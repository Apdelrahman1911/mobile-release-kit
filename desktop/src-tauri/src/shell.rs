use std::{sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}}, time::Duration};
use serde_json::Value;
use tauri::{Emitter, Manager, State, Webview, WebviewUrl, WebviewWindowBuilder};
use tokio::sync::{watch, oneshot, Mutex as AsyncMutex};
use crate::{
    asset_commands::{self, AssetError, CommandError, Reason},
    asset_session::{AssetStatus, DocumentBinding, NativeResponse, OriginalWork},
    bridge::{AppInfo, DesktopBridge, Project},
    edit_commands, edit_owner::EditOwner, edit_protocol::ConfigEditStatus,
    github_workflow_edit_protocol::WorkflowEditStatus,
    metadata_text_commands, metadata_text_edit_protocol::{self as metadata_text_wire, MetadataTextEditStatus},
    release_version_edit_commands, release_version_edit_protocol::{self as release_version_wire, ReleaseVersionEditStatus},
    github_connection_protocol::{self as github_connection_wire, Status as GitHubConnectionStatus, Reason as GitHubConnectionReason},
    github_connection_session,
    error::BridgeError,
};

#[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "development-runtime", target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
#[path = "session_gtk_qualification.rs"]
pub(crate) mod qualification;
#[cfg(any(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64", feature = "macos-installed-observation", not(feature = "macos-installed-installer")))), all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "windows-installed-observation", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "windows-runtime-publisher"), not(feature = "macos-installed-installer"), target_os = "windows", target_arch = "x86_64", target_env = "msvc")))]
#[cfg_attr(target_os = "linux", path = "installed_shell_observation.rs")]
#[cfg_attr(target_os = "macos", path = "installed_shell_observation_macos.rs")]
#[cfg_attr(target_os = "windows", path = "installed_shell_observation_windows.rs")]
pub(crate) mod installed_observation;
// Only the installed Linux observer sees these calls. Ordinary builds retain
// the same typed IPC and original document owners, with no qualification token.
macro_rules! installed_command_request {
    ($state:expr, $kind:ident, $value:expr) => {
        #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
        if let Some(q) = &$state.observation { q.commands_request(installed_observation::commands::Command::$kind, $value); }
    };
}
macro_rules! installed_command_result {
    ($state:expr, $kind:ident, $value:expr) => {
        #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
        if let Some(q) = &$state.observation { q.commands_result(installed_observation::commands::Command::$kind, $value); }
    };
}
macro_rules! fixture_command {
    ($state:expr, $kind:ident, $observed:ident, $error:expr) => {
        #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "development-runtime", target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
        let $observed = match &$state.fixture {
            Some(context) => Some(context.command(qualification::Command::$kind).map_err(|_| $error)?),
            None => None,
        };
    };
}
macro_rules! fixture_result {
    ($observed:ident, $method:ident, $result:expr) => {
        #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "development-runtime", target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
        if let Some(observed) = $observed { observed.$method($result); }
    };
}
macro_rules! gtk_fixture {
    ($call:expr, $kind:ident, $detail:expr) => {
        #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "development-runtime", target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
        $call.fixture_event(qualification::EventKind::$kind, $detail);
    };
}
macro_rules! installed_session_command {
    ($state:expr, $kind:ident, $observed:ident) => {
        #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
        let $observed = $state.observation.clone();
        #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
        if let Some(q) = &$observed { q.session_request(installed_observation::SessionCommand::$kind); }
    };
}
macro_rules! installed_session_result {
    ($observed:ident, Prepare, $result:expr) => {
        #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
        if let Some(q) = &$observed { q.session_prepare_result($result); }
    };
    ($observed:ident, $kind:ident, $result:expr) => {
        #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
        if let Some(q) = &$observed { q.session_result(installed_observation::SessionCommand::$kind,$result); }
    };
}
macro_rules! installed_session_input {
    ($observed:ident, $method:ident, $($arg:expr),+) => {
        #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
        if let Some(q) = &$observed { q.$method($($arg),+); }
    };
}

const MAIN_WINDOW: &str = "main";
const QUIT_MENU_ID: &str = "mrk-file-quit";
const EDIT_EVENT: &str = "config-edit-state";
const WORKFLOW_EDIT_EVENT: &str = "github-workflow-edit-status";
const ASSET_EVENT: &str = "asset-session-state";

struct ShellState {
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "development-runtime", target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    fixture: Option<Arc<qualification::Qualification>>,
    #[cfg(any(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64", feature = "macos-installed-observation", not(feature = "macos-installed-installer")))), all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "windows-installed-observation", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "windows-runtime-publisher"), not(feature = "macos-installed-installer"), target_os = "windows", target_arch = "x86_64", target_env = "msvc")))]
    observation: Option<Arc<installed_observation::Observation>>,
    bridge: Arc<DesktopBridge>, document: DocumentBinding,
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))] picker: Arc<AtomicBool>,
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))] closing: AtomicBool,
    exit_ready: AtomicBool,
    relay_stop: watch::Sender<bool>,
    relay: AsyncMutex<RelayBook>,
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))] exit_observer: Mutex<Option<tauri::async_runtime::JoinHandle<()>>>,
}
struct RelayBook { handle: Option<tauri::async_runtime::JoinHandle<()>>, settled: bool }

pub(crate) fn diagnostic(line: &'static [u8]) {
    use std::io::Write;
    // Fixed status only. A closed diagnostic channel must not panic, change
    // admission, or substitute for the original query/cleanup result.
    let _ = std::io::stderr().write_all(line);
}

#[tauri::command]
async fn app_info(state: State<'_, ShellState>) -> Result<AppInfo, BridgeError> {
    diagnostic(b"MRKDBG_DESKTOP_BOOTSTRAP=app-info-enter\n");
    fixture_command!(state, AppInfo, observed, BridgeError::new("sg1_fixture_refused", "This fixture does not admit that action."));
    let info = state.bridge.app_info(&state.document).await;
    diagnostic(if info.runtime.state == "available" && info.capabilities.is_some() {
        b"MRK_DESKTOP_CAPABILITIES=available\n"
    } else { b"MRK_DESKTOP_CAPABILITIES=unavailable\n" });
    #[cfg(any(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64", feature = "macos-installed-observation", not(feature = "macos-installed-installer")))), all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "windows-installed-observation", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "windows-runtime-publisher"), not(feature = "macos-installed-installer"), target_os = "windows", target_arch = "x86_64", target_env = "msvc")))]
    if let Some(q) = &state.observation { q.app_info(&info); }
    let result = Ok(info);
    fixture_result!(observed, info, &result);
    result
}
#[tauri::command]
async fn catalog(state: State<'_, ShellState>) -> Result<Value, BridgeError> {
    diagnostic(b"MRKDBG_DESKTOP_BOOTSTRAP=catalog-enter\n");
    fixture_command!(state, Catalog, observed, BridgeError::new("sg1_fixture_refused", "This fixture does not admit that action."));
    let result = state.bridge.catalog(&state.document).await;
    diagnostic(if result.is_ok() { b"MRK_DESKTOP_CATALOGUE=returned\n" } else { b"MRK_DESKTOP_CATALOGUE=refused\n" });
    #[cfg(any(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64", feature = "macos-installed-observation", not(feature = "macos-installed-installer")))), all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "windows-installed-observation", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "windows-runtime-publisher"), not(feature = "macos-installed-installer"), target_os = "windows", target_arch = "x86_64", target_env = "msvc")))]
    if let Some(q) = &state.observation { q.catalog(&result); }
    fixture_result!(observed, value, &result);
    result
}
#[tauri::command]
async fn environment_requirements(webview: Webview, request: tauri::ipc::Request<'_>, state: State<'_, ShellState>) -> Result<crate::environment::Requirements, BridgeError> {
    fixture_command!(state, Forbidden, observed, BridgeError::new("sg1_fixture_refused", "This fixture does not admit that action."));
    edit_window(&webview)?;
    let body = request_body(&request)?;
    let args = crate::environment::request(body)?;
    not_closing(&state)?;
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64", feature = "macos-installed-observation", not(feature = "macos-installed-installer")))))]
    if let Some(q) = &state.observation { q.requirements_request(body); }
    let result = state.bridge.environment_requirements(&state.document, args).await;
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64", feature = "macos-installed-observation", not(feature = "macos-installed-installer")))))]
    if let Some(q) = &state.observation { q.requirements(&result); }
    result
}
#[tauri::command]
async fn start_environment_diagnostics(webview: Webview, request: tauri::ipc::Request<'_>, state: State<'_, ShellState>) -> Result<crate::environment_diagnostics_protocol::Status, BridgeError> {
    fixture_command!(state, Forbidden, observed, BridgeError::new("sg1_fixture_refused", "This fixture does not admit that action."));
    edit_window(&webview)?;
    let value = request_body(&request)?;
    let args = crate::environment_diagnostics_protocol::start(value)?;
    installed_command_request!(state, ToolsStart, value);
    let result = state.document.start_environment_diagnostics(args);
    installed_command_result!(state, ToolsStart, &result);
    result
}
#[tauri::command]
async fn environment_diagnostics_status(webview: Webview, request: tauri::ipc::Request<'_>, state: State<'_, ShellState>) -> Result<crate::environment_diagnostics_protocol::Status, BridgeError> {
    fixture_command!(state, EnvironmentStatus, observed, BridgeError::new("sg1_fixture_refused", "This fixture does not admit that action."));
    edit_window(&webview)?; crate::environment_diagnostics_protocol::status_request(request_body(&request)?)?;
    let result = state.document.environment_diagnostics_status();
    fixture_result!(observed, environment_status_returned, &result);
    result
}
#[tauri::command]
async fn cancel_environment_diagnostics(webview: Webview, request: tauri::ipc::Request<'_>, state: State<'_, ShellState>) -> Result<crate::environment_diagnostics_protocol::Status, BridgeError> {
    fixture_command!(state, Forbidden, observed, BridgeError::new("sg1_fixture_refused", "This fixture does not admit that action."));
    edit_window(&webview)?;
    let value = request_body(&request)?;
    let args = crate::environment_diagnostics_protocol::cancel(value)?;
    installed_command_request!(state, ToolsCancel, value);
    let result = state.document.cancel_environment_diagnostics(args);
    installed_command_result!(state, ToolsCancel, &result);
    result
}
#[tauri::command]
async fn prepare_offline_preflight(webview: Webview, request: tauri::ipc::Request<'_>, state: State<'_, ShellState>) -> Result<crate::offline_preflight_protocol::Status, BridgeError> {
    fixture_command!(state, Forbidden, observed, BridgeError::new("sg1_fixture_refused", "This fixture does not admit that action."));
    edit_window(&webview).map_err(|_| crate::offline_preflight_protocol::invalid())?;
    let value = preflight_request_body(request.body())?;
    let args = crate::offline_preflight_protocol::prepare(&value)?;
    installed_command_request!(state, OfflinePrepare, &value);
    let result = state.document.prepare_offline_preflight(args);
    installed_command_result!(state, OfflinePrepare, &result);
    result
}
#[tauri::command]
async fn start_offline_preflight(webview: Webview, request: tauri::ipc::Request<'_>, state: State<'_, ShellState>) -> Result<crate::offline_preflight_protocol::Status, BridgeError> {
    fixture_command!(state, Forbidden, observed, BridgeError::new("sg1_fixture_refused", "This fixture does not admit that action."));
    edit_window(&webview).map_err(|_| crate::offline_preflight_protocol::invalid())?;
    let value = preflight_request_body(request.body())?;
    let args = crate::offline_preflight_protocol::start(&value)?;
    installed_command_request!(state, OfflineStart, &value);
    let result = state.document.start_offline_preflight(args);
    installed_command_result!(state, OfflineStart, &result);
    result
}
#[tauri::command]
async fn offline_preflight_status(webview: Webview, request: tauri::ipc::Request<'_>, state: State<'_, ShellState>) -> Result<crate::offline_preflight_protocol::Status, BridgeError> {
    fixture_command!(state, Forbidden, observed, BridgeError::new("sg1_fixture_refused", "This fixture does not admit that action."));
    edit_window(&webview).map_err(|_| crate::offline_preflight_protocol::invalid())?;
    let value = preflight_request_body(request.body())?;
    crate::offline_preflight_protocol::status_request(&value)?;
    state.document.offline_preflight_status()
}
#[tauri::command]
async fn cancel_offline_preflight(webview: Webview, request: tauri::ipc::Request<'_>, state: State<'_, ShellState>) -> Result<crate::offline_preflight_protocol::Status, BridgeError> {
    fixture_command!(state, Forbidden, observed, BridgeError::new("sg1_fixture_refused", "This fixture does not admit that action."));
    edit_window(&webview).map_err(|_| crate::offline_preflight_protocol::invalid())?;
    let value = preflight_request_body(request.body())?;
    let args = crate::offline_preflight_protocol::cancel(&value)?;
    installed_command_request!(state, OfflineCancel, &value);
    let result = state.document.cancel_offline_preflight(args);
    installed_command_result!(state, OfflineCancel, &result);
    result
}
#[tauri::command]
async fn prepare_android_build(webview: Webview, request: tauri::ipc::Request<'_>, state: State<'_, ShellState>) -> Result<crate::android_build_protocol::Status, BridgeError> {
    fixture_command!(state, Forbidden, observed, BridgeError::new("sg1_fixture_refused", "This fixture does not admit that action."));
    edit_window(&webview).map_err(|_| crate::android_build_protocol::invalid())?;
    let value = android_build_request_body(request.body())?;
    state.document.prepare_android_build(crate::android_build_protocol::prepare(&value)?)
}
#[tauri::command]
async fn start_android_build(webview: Webview, request: tauri::ipc::Request<'_>, state: State<'_, ShellState>) -> Result<crate::android_build_protocol::Status, BridgeError> {
    fixture_command!(state, Forbidden, observed, BridgeError::new("sg1_fixture_refused", "This fixture does not admit that action."));
    edit_window(&webview).map_err(|_| crate::android_build_protocol::invalid())?;
    let value = android_build_request_body(request.body())?;
    state.document.start_android_build(crate::android_build_protocol::start(&value)?)
}
#[tauri::command]
async fn android_build_status(webview: Webview, request: tauri::ipc::Request<'_>, state: State<'_, ShellState>) -> Result<crate::android_build_protocol::Status, BridgeError> {
    fixture_command!(state, Forbidden, observed, BridgeError::new("sg1_fixture_refused", "This fixture does not admit that action."));
    edit_window(&webview).map_err(|_| crate::android_build_protocol::invalid())?;
    let value = android_build_request_body(request.body())?;
    crate::android_build_protocol::status_request(&value)?;
    state.document.android_build_status()
}
#[tauri::command]
async fn cancel_android_build(webview: Webview, request: tauri::ipc::Request<'_>, state: State<'_, ShellState>) -> Result<crate::android_build_protocol::Status, BridgeError> {
    fixture_command!(state, Forbidden, observed, BridgeError::new("sg1_fixture_refused", "This fixture does not admit that action."));
    edit_window(&webview).map_err(|_| crate::android_build_protocol::invalid())?;
    let value = android_build_request_body(request.body())?;
    state.document.cancel_android_build(crate::android_build_protocol::cancel(&value)?)
}
#[tauri::command]
async fn artifact_evidence_choose(webview: Webview, app: tauri::AppHandle, request: tauri::ipc::Request<'_>, state: State<'_, ShellState>) -> Result<crate::candidate_evidence_protocol::Status, BridgeError> {
    fixture_command!(state, Forbidden, observed, BridgeError::new("sg1_fixture_refused", "This fixture does not admit that action."));
    edit_window(&webview)?; let body = request_body(&request)?; crate::candidate_evidence_protocol::empty_request(body)?;
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    if let Some(q) = &state.observation { q.evidence_choose_request(body); }
    let result = state.document.artifact_evidence_choose(app);
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    if let Some(q) = &state.observation { q.evidence_choose_result(&result); }
    result
}
#[tauri::command]
async fn artifact_evidence_status(webview: Webview, request: tauri::ipc::Request<'_>, state: State<'_, ShellState>) -> Result<crate::candidate_evidence_protocol::Status, BridgeError> {
    fixture_command!(state, Forbidden, observed, BridgeError::new("sg1_fixture_refused", "This fixture does not admit that action."));
    edit_window(&webview)?; let body = request_body(&request)?; crate::candidate_evidence_protocol::empty_request(body)?;
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    if let Some(q) = &state.observation { q.evidence_status_request(body); }
    let result = state.document.artifact_evidence_status();
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    if let Some(q) = &state.observation { q.evidence_status_result(&result); }
    result
}
#[tauri::command]
async fn artifact_evidence_observe(webview: Webview, request: tauri::ipc::Request<'_>, state: State<'_, ShellState>) -> Result<crate::candidate_evidence_protocol::Status, BridgeError> {
    fixture_command!(state, Forbidden, observed, BridgeError::new("sg1_fixture_refused", "This fixture does not admit that action."));
    edit_window(&webview)?; let body = request_body(&request)?; let args = crate::candidate_evidence_protocol::observe_request(body)?;
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    if let Some(q) = &state.observation { q.evidence_observe_request(body); }
    let result = state.document.artifact_evidence_observe(args);
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    if let Some(q) = &state.observation { q.evidence_observe_result(&result); }
    result
}
#[tauri::command]
async fn artifact_evidence_cancel(webview: Webview, request: tauri::ipc::Request<'_>, state: State<'_, ShellState>) -> Result<crate::candidate_evidence_protocol::Status, BridgeError> {
    fixture_command!(state, Forbidden, observed, BridgeError::new("sg1_fixture_refused", "This fixture does not admit that action."));
    edit_window(&webview)?; let args = crate::candidate_evidence_protocol::cancel_request(request_body(&request)?)?;
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    if let Some(q) = &state.observation { q.unexpected(); } // This case uses the real chooser's Cancel widget, not STOP IPC.
    state.document.artifact_evidence_cancel(args)
}
#[tauri::command(rename_all = "camelCase")]
async fn project_snapshot(project_id: String, state: State<'_, ShellState>) -> Result<Value, BridgeError> {
    fixture_command!(state, Forbidden, observed, BridgeError::new("sg1_fixture_refused", "This fixture does not admit that action."));
    #[cfg(any(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64", feature = "macos-installed-observation", not(feature = "macos-installed-installer")))), all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "windows-installed-observation", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "windows-runtime-publisher"), not(feature = "macos-installed-installer"), target_os = "windows", target_arch = "x86_64", target_env = "msvc")))]
    let observed_project = {
        if let Some(q) = &state.observation { q.snapshot_request(&project_id); }
        project_id.clone()
    };
    let result = state.bridge.project_snapshot(&state.document, project_id).await;
    #[cfg(any(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64", feature = "macos-installed-observation", not(feature = "macos-installed-installer")))), all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "windows-installed-observation", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "windows-runtime-publisher"), not(feature = "macos-installed-installer"), target_os = "windows", target_arch = "x86_64", target_env = "msvc")))]
    if let Some(q) = &state.observation { q.snapshot(&observed_project, &result); }
    result
}
#[tauri::command]
async fn validate_config(draft: Value, state: State<'_, ShellState>) -> Result<Value, BridgeError> {
    fixture_command!(state, Forbidden, observed, BridgeError::new("sg1_fixture_refused", "This fixture does not admit that action."));
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    if let Some(q) = &state.observation { q.unexpected(); }
    #[cfg(any(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "macos-installed-observation", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer"), target_os = "macos", target_arch = "aarch64"), all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "windows-installed-observation", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "windows-runtime-publisher"), not(feature = "macos-installed-installer"), target_os = "windows", target_arch = "x86_64", target_env = "msvc")))]
    if let Some(q) = &state.observation { q.validate_request(&draft); }
    let result = state.bridge.validate_config(&state.document, draft).await;
    #[cfg(any(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "macos-installed-observation", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer"), target_os = "macos", target_arch = "aarch64"), all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "windows-installed-observation", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "windows-runtime-publisher"), not(feature = "macos-installed-installer"), target_os = "windows", target_arch = "x86_64", target_env = "msvc")))]
    if let Some(q) = &state.observation { q.validation(&result); }
    result
}
#[tauri::command]
async fn suggest_config(hints: Value, state: State<'_, ShellState>) -> Result<Value, BridgeError> {
    fixture_command!(state, Forbidden, observed, BridgeError::new("sg1_fixture_refused", "This fixture does not admit that action."));
    #[cfg(any(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64", feature = "macos-installed-observation", not(feature = "macos-installed-installer")))), all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "windows-installed-observation", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "windows-runtime-publisher"), not(feature = "macos-installed-installer"), target_os = "windows", target_arch = "x86_64", target_env = "msvc")))]
    if let Some(q) = &state.observation { q.suggest_request(&hints); }
    let result = state.bridge.suggest_config(&state.document, hints).await;
    #[cfg(any(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64", feature = "macos-installed-observation", not(feature = "macos-installed-installer")))), all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "windows-installed-observation", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "windows-runtime-publisher"), not(feature = "macos-installed-installer"), target_os = "windows", target_arch = "x86_64", target_env = "msvc")))]
    if let Some(q) = &state.observation { q.suggestion(&result); }
    result
}
#[tauri::command]
async fn preview_config(base: Value, draft: Value, state: State<'_, ShellState>) -> Result<Value, BridgeError> {
    fixture_command!(state, Forbidden, observed, BridgeError::new("sg1_fixture_refused", "This fixture does not admit that action."));
    #[cfg(any(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64", feature = "macos-installed-observation", not(feature = "macos-installed-installer")))), all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "windows-installed-observation", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "windows-runtime-publisher"), not(feature = "macos-installed-installer"), target_os = "windows", target_arch = "x86_64", target_env = "msvc")))]
    if let Some(q) = &state.observation { q.preview_request(&base,&draft); }
    let result = state.bridge.preview_config(&state.document, base, draft).await;
    #[cfg(any(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64", feature = "macos-installed-observation", not(feature = "macos-installed-installer")))), all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "windows-installed-observation", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "windows-runtime-publisher"), not(feature = "macos-installed-installer"), target_os = "windows", target_arch = "x86_64", target_env = "msvc")))]
    if let Some(q) = &state.observation { q.preview_result(&result); }
    result
}
#[tauri::command]
async fn propose_github_setup(request: tauri::ipc::Request<'_>, state: State<'_, ShellState>) -> Result<Value, BridgeError> {
    fixture_command!(state, Forbidden, observed, BridgeError::new("sg1_fixture_refused", "This fixture does not admit that action."));
    let body = request_body(&request)?;
    let input = crate::github_commands::proposal(body)?;
    not_closing(&state)?;
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64", feature = "macos-installed-observation", not(feature = "macos-installed-installer")))))]
    if let Some(q) = &state.observation { q.github_request(body); }
    let result = state.bridge.propose_github_setup(&state.document, input).await;
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64", feature = "macos-installed-observation", not(feature = "macos-installed-installer")))))]
    if let Some(q) = &state.observation { q.github_proposal(&result); }
    result
}

fn edit_window(webview: &Webview) -> Result<&str, BridgeError> {
    if webview.label() != MAIN_WINDOW { return Err(BridgeError::invalid()); }
    Ok(webview.label())
}
fn request_body<'a>(request: &'a tauri::ipc::Request<'_>) -> Result<&'a Value, BridgeError> {
    match request.body() {
        tauri::ipc::InvokeBody::Json(value) => Ok(value),
        tauri::ipc::InvokeBody::Raw(_) => Err(BridgeError::invalid()),
    }
}
fn preflight_request_body(body: &tauri::ipc::InvokeBody) -> Result<Value, BridgeError> {
    match body {
        // Original length and duplicate-aware parsing precede all DTO copying.
        tauri::ipc::InvokeBody::Raw(bytes) => crate::offline_preflight_protocol::raw_request(bytes),
        tauri::ipc::InvokeBody::Json(_) => Err(crate::offline_preflight_protocol::invalid()),
    }
}
fn android_build_request_body(body: &tauri::ipc::InvokeBody) -> Result<Value, BridgeError> {
    match body {
        // Preserve the original IPC byte limit and duplicate keys; a Tauri
        // Json value has already lost that evidence and is not admitted here.
        tauri::ipc::InvokeBody::Raw(bytes) => crate::android_build_protocol::raw_request(bytes),
        tauri::ipc::InvokeBody::Json(_) => Err(crate::android_build_protocol::invalid()),
    }
}
#[cfg(test)]
#[path = "offline_preflight_shell_tests.rs"]
mod offline_preflight_shell_tests;
#[cfg(test)]
#[path = "android_build_shell_tests.rs"]
mod android_build_shell_tests;
fn not_closing(state: &ShellState) -> Result<(), BridgeError> {
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    { return state.document.not_quitting(); }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
    if state.closing.load(Ordering::SeqCst) {
        return Err(BridgeError::new("quit_pending", "Finish or cancel the quit confirmation before starting another action."));
    }
    state.bridge.preflight.ensure_idle()?;
    state.bridge.android_build.ensure_idle()?;
    Ok(())
    }
}

// Async Tauri entrypoints enter the application runtime, but admission itself
// is synchronous. No invoke future owns the registered operation's lifetime.
// No renderer-receipt acknowledgment is claimed or required.
#[tauri::command]
async fn open_config_edit(webview: Webview, request: tauri::ipc::Request<'_>, state: State<'_, ShellState>) -> Result<ConfigEditStatus, BridgeError> {
    fixture_command!(state, Forbidden, observed, BridgeError::new("sg1_fixture_refused", "This fixture does not admit that action."));
    let window = edit_window(&webview)?;
    let args = edit_commands::open(request_body(&request)?)?;
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64", feature = "macos-installed-observation", not(feature = "macos-installed-installer")))))]
    if let Some(q) = &state.observation { q.open_request(&args.project_id); }
    // The same real document gate checks quit and retires saved consent/STOP
    // before checking idle. An outer idle-only gate would skip retirement.
    let result = state.document.configuration_edit_admit(|bridge| bridge.open_config_edit(window, args.project_id));
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64", feature = "macos-installed-observation", not(feature = "macos-installed-installer")))))]
    if let Some(q) = &state.observation { q.open_result(&result, &state.bridge.edits); }
    result
}
#[tauri::command]
async fn prepare_config_edit(webview: Webview, request: tauri::ipc::Request<'_>, state: State<'_, ShellState>) -> Result<ConfigEditStatus, BridgeError> {
    fixture_command!(state, Forbidden, observed, BridgeError::new("sg1_fixture_refused", "This fixture does not admit that action."));
    let window = edit_window(&webview)?;
    let args = edit_commands::prepare(request_body(&request)?)?;
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64", feature = "macos-installed-observation", not(feature = "macos-installed-installer")))))]
    if let Some(q) = &state.observation { q.prepare_request(&args); }
    let result = state.document.configuration_edit_admit(|bridge| bridge.edits.prepare(window, args));
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64", feature = "macos-installed-observation", not(feature = "macos-installed-installer")))))]
    if let Some(q) = &state.observation { q.prepare_result(&result, &state.bridge.edits); }
    result
}
#[tauri::command]
async fn apply_config_edit(webview: Webview, request: tauri::ipc::Request<'_>, state: State<'_, ShellState>) -> Result<ConfigEditStatus, BridgeError> {
    fixture_command!(state, Forbidden, observed, BridgeError::new("sg1_fixture_refused", "This fixture does not admit that action."));
    let window = edit_window(&webview)?;
    let args = edit_commands::apply(request_body(&request)?)?;
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64", feature = "macos-installed-observation", not(feature = "macos-installed-installer")))))]
    if let Some(q) = &state.observation { q.apply_request(&args.session_id, &args.plan_token); }
    let result = state.document.configuration_edit_admit(|bridge| bridge.edits.apply(window, &args.session_id, &args.plan_token));
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64", feature = "macos-installed-observation", not(feature = "macos-installed-installer")))))]
    if let Some(q) = &state.observation { q.apply_result(&result, &state.bridge.edits); }
    result
}
#[tauri::command]
async fn close_config_edit(webview: Webview, request: tauri::ipc::Request<'_>, state: State<'_, ShellState>) -> Result<ConfigEditStatus, BridgeError> {
    fixture_command!(state, Forbidden, observed, BridgeError::new("sg1_fixture_refused", "This fixture does not admit that action."));
    let window = edit_window(&webview)?;
    let args = edit_commands::close(request_body(&request)?)?;
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64", feature = "macos-installed-observation", not(feature = "macos-installed-installer")))))]
    if let Some(q) = &state.observation { q.close_request(); }
    // The original document may stop during quit. Document loss already sends
    // STOP from native lifecycle handling; later renderers have status only.
    state.bridge.edits.close(window, &args.session_id)
}
#[tauri::command]
async fn config_edit_status(webview: Webview, request: tauri::ipc::Request<'_>, state: State<'_, ShellState>) -> Result<ConfigEditStatus, BridgeError> {
    fixture_command!(state, EditStatus, observed, BridgeError::new("sg1_fixture_refused", "This fixture does not admit that action."));
    let result = async {
        edit_window(&webview)?;
        edit_commands::status(request_body(&request)?)?;
        state.bridge.edits.status()
    }.await;
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64", feature = "macos-installed-observation", not(feature = "macos-installed-installer")))))]
    if let (Some(q), Ok(status)) = (&state.observation, &result) { q.edit_status(status, &state.bridge.edits); }
    fixture_result!(observed, edit, &result);
    result
}

#[tauri::command]
async fn github_workflow_edit_open(webview: Webview, request: tauri::ipc::Request<'_>, state: State<'_, ShellState>) -> Result<WorkflowEditStatus, BridgeError> {
    fixture_command!(state, Forbidden, observed, BridgeError::new("sg1_fixture_refused", "This fixture does not admit that action."));
    let window = edit_window(&webview)?;
    let args = edit_commands::open(request_body(&request)?)?;
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    if let Some(q) = &state.observation { q.workflow_open_request(&args.project_id); }
    let result = state.bridge.open_workflow_edit(&state.document, window, args.project_id);
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    if let Some(q) = &state.observation { q.workflow_open_result(&result, &state.bridge.edits); }
    result
}
#[tauri::command]
async fn github_workflow_edit_prepare(webview: Webview, request: tauri::ipc::Request<'_>, state: State<'_, ShellState>) -> Result<WorkflowEditStatus, BridgeError> {
    fixture_command!(state, Forbidden, observed, BridgeError::new("sg1_fixture_refused", "This fixture does not admit that action."));
    let window = edit_window(&webview)?;
    let args = edit_commands::workflow_prepare(request_body(&request)?)?;
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    if let Some(q) = &state.observation { q.workflow_prepare_request(&args); }
    let result = state.bridge.prepare_workflow_edit(&state.document, window, args);
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    if let Some(q) = &state.observation { q.workflow_prepare_result(&result, &state.bridge.edits); }
    result
}
#[tauri::command]
async fn github_workflow_edit_apply(webview: Webview, request: tauri::ipc::Request<'_>, state: State<'_, ShellState>) -> Result<WorkflowEditStatus, BridgeError> {
    fixture_command!(state, Forbidden, observed, BridgeError::new("sg1_fixture_refused", "This fixture does not admit that action."));
    let window = edit_window(&webview)?;
    let args = edit_commands::apply(request_body(&request)?)?;
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    if let Some(q) = &state.observation { q.workflow_apply_request(&args.session_id, &args.plan_token); }
    let result = state.bridge.apply_workflow_edit(&state.document, window, &args.session_id, &args.plan_token);
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    if let Some(q) = &state.observation { q.workflow_apply_result(&result, &state.bridge.edits); }
    result
}
#[tauri::command]
async fn github_workflow_edit_close(webview: Webview, request: tauri::ipc::Request<'_>, state: State<'_, ShellState>) -> Result<WorkflowEditStatus, BridgeError> {
    fixture_command!(state, Forbidden, observed, BridgeError::new("sg1_fixture_refused", "This fixture does not admit that action."));
    let window = edit_window(&webview)?;
    let args = edit_commands::close(request_body(&request)?)?;
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    if let Some(q) = &state.observation { q.workflow_close_request(); }
    // STOP remains available to the original document during quit; loss has
    // already stopped this same owner. No new root lookup/claim is involved.
    state.bridge.edits.close_workflow(window, &args.session_id)
}
#[tauri::command]
async fn github_workflow_edit_status(webview: Webview, request: tauri::ipc::Request<'_>, state: State<'_, ShellState>) -> Result<WorkflowEditStatus, BridgeError> {
    fixture_command!(state, Forbidden, observed, BridgeError::new("sg1_fixture_refused", "This fixture does not admit that action."));
    edit_window(&webview)?;
    edit_commands::status(request_body(&request)?)?;
    let result = state.bridge.edits.workflow_status();
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    if let (Some(q), Ok(status)) = (&state.observation, &result) { q.workflow_status(status, &state.bridge.edits); }
    result
}

#[tauri::command]
async fn release_version_observe(webview: Webview, request: tauri::ipc::Request<'_>, state: State<'_, ShellState>) -> Result<crate::release_version_protocol::Observation, BridgeError> {
    fixture_command!(state, Forbidden, observed, BridgeError::new("sg1_fixture_refused", "This fixture does not admit that action."));
    edit_window(&webview).map_err(crate::release_version_protocol::public_error)?;
    let body = request_body(&request).map_err(crate::release_version_protocol::public_error)?;
    let args = crate::release_version_protocol::request(body)?;
    not_closing(&state).map_err(crate::release_version_protocol::public_error)?;
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    if let Some(q) = &state.observation { q.release_version_request(body); }
    let result = state.bridge.observe_release_version(&state.document, args).await;
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    if let Some(q) = &state.observation { q.release_version(&result); }
    result
}
#[tauri::command]
async fn metadata_text_observe(webview: Webview, request: tauri::ipc::Request<'_>, state: State<'_, ShellState>) -> Result<metadata_text_wire::Observation, BridgeError> {
    fixture_command!(state, Forbidden, observed, BridgeError::new("sg1_fixture_refused", "This fixture does not admit that action."));
    edit_window(&webview)?;
    let body = request_body(&request)?;
    let args = metadata_text_commands::open(body)?;
    not_closing(&state)?;
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    if let Some(q) = &state.observation { q.metadata_request(body); }
    let result = state.bridge.observe_metadata_text(&state.document, args).await;
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    if let Some(q) = &state.observation { q.metadata_observation(&result); }
    result
}
#[tauri::command]
async fn metadata_text_validate(webview: Webview, request: tauri::ipc::Request<'_>, state: State<'_, ShellState>) -> Result<metadata_text_wire::ValidationResult, BridgeError> {
    fixture_command!(state, Forbidden, observed, BridgeError::new("sg1_fixture_refused", "This fixture does not admit that action."));
    edit_window(&webview)?;
    let body = request_body(&request)?;
    let args = metadata_text_commands::validate(body)?;
    not_closing(&state)?;
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    if let Some(q) = &state.observation { q.metadata_validation_request(body); }
    let result = state.bridge.validate_metadata_text(&state.document, args).await;
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    if let Some(q) = &state.observation { q.metadata_validation(&result); }
    result
}
#[tauri::command]
async fn metadata_text_edit_open(webview: Webview, request: tauri::ipc::Request<'_>, state: State<'_, ShellState>) -> Result<MetadataTextEditStatus, BridgeError> {
    fixture_command!(state, Forbidden, observed, BridgeError::new("sg1_fixture_refused", "This fixture does not admit that action."));
    let window = edit_window(&webview)?;
    let args = metadata_text_commands::open(request_body(&request)?)?;
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    if let Some(q) = &state.observation { q.metadata_open_request(&args); }
    let result = state.bridge.open_metadata_text_edit(&state.document, window, args);
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    if let Some(q) = &state.observation { q.metadata_open_result(&result, &state.bridge.edits); }
    result
}
#[tauri::command]
async fn metadata_text_edit_prepare(webview: Webview, request: tauri::ipc::Request<'_>, state: State<'_, ShellState>) -> Result<MetadataTextEditStatus, BridgeError> {
    fixture_command!(state, Forbidden, observed, BridgeError::new("sg1_fixture_refused", "This fixture does not admit that action."));
    let window = edit_window(&webview)?;
    let args = metadata_text_commands::prepare(request_body(&request)?)?;
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    if let Some(q) = &state.observation { q.metadata_prepare_request(&args); }
    let result = state.bridge.prepare_metadata_text_edit(&state.document, window, args);
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    if let Some(q) = &state.observation { q.metadata_prepare_result(&result, &state.bridge.edits); }
    result
}
#[tauri::command]
async fn metadata_text_edit_apply(webview: Webview, request: tauri::ipc::Request<'_>, state: State<'_, ShellState>) -> Result<MetadataTextEditStatus, BridgeError> {
    fixture_command!(state, Forbidden, observed, BridgeError::new("sg1_fixture_refused", "This fixture does not admit that action."));
    let window = edit_window(&webview)?;
    let args = edit_commands::apply(request_body(&request)?)?;
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    if let Some(q) = &state.observation { q.metadata_apply_request(&args.session_id, &args.plan_token); }
    let result = state.bridge.apply_metadata_text_edit(&state.document, window, &args.session_id, &args.plan_token);
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    if let Some(q) = &state.observation { q.metadata_apply_result(&result, &state.bridge.edits); }
    result
}
#[tauri::command]
async fn metadata_text_edit_close(webview: Webview, request: tauri::ipc::Request<'_>, state: State<'_, ShellState>) -> Result<MetadataTextEditStatus, BridgeError> {
    fixture_command!(state, Forbidden, observed, BridgeError::new("sg1_fixture_refused", "This fixture does not admit that action."));
    let window = edit_window(&webview)?;
    let args = edit_commands::close(request_body(&request)?)?;
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    if let Some(q) = &state.observation { q.metadata_close_request(&args.session_id); }
    // Original STOP remains available during quit without a new root lookup.
    let result = state.bridge.edits.close_metadata_text(window, &args.session_id);
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    if let Some(q) = &state.observation { q.metadata_close_result(&result, &state.bridge.edits); }
    result
}
#[tauri::command]
async fn metadata_text_edit_status(webview: Webview, request: tauri::ipc::Request<'_>, state: State<'_, ShellState>) -> Result<MetadataTextEditStatus, BridgeError> {
    fixture_command!(state, Forbidden, observed, BridgeError::new("sg1_fixture_refused", "This fixture does not admit that action."));
    edit_window(&webview)?;
    edit_commands::status(request_body(&request)?)?;
    let result = state.bridge.edits.metadata_text_status();
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    if let (Some(q), Ok(status)) = (&state.observation, &result) { q.metadata_edit_status(status, &state.bridge.edits); }
    result
}

#[tauri::command]
async fn release_version_edit_open(webview: Webview, request: tauri::ipc::Request<'_>, state: State<'_, ShellState>) -> Result<ReleaseVersionEditStatus, BridgeError> {
    fixture_command!(state, Forbidden, observed, BridgeError::new("sg1_fixture_refused", "This fixture does not admit that action."));
    let window = edit_window(&webview)?;
    let args = release_version_edit_commands::open(request_body(&request)?)?;
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    if let Some(q) = &state.observation { q.version_open_request(&args); }
    let result = state.bridge.open_release_version_edit(&state.document, window, args);
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    if let Some(q) = &state.observation { q.version_open_result(&result, &state.bridge.edits); }
    result
}
#[tauri::command]
async fn release_version_edit_prepare(webview: Webview, request: tauri::ipc::Request<'_>, state: State<'_, ShellState>) -> Result<ReleaseVersionEditStatus, BridgeError> {
    fixture_command!(state, Forbidden, observed, BridgeError::new("sg1_fixture_refused", "This fixture does not admit that action."));
    let window = edit_window(&webview)?;
    let result = request_body(&request).and_then(release_version_edit_commands::prepare)
        .and_then(|args| {
        #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
        if let Some(q) = &state.observation { q.version_prepare_request(&args); }
        state.bridge.prepare_release_version_edit(&state.document, window, args)
    });
    if result.is_err() { state.bridge.edits.retire_release_version_request(window); }
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    if let Some(q) = &state.observation { q.version_prepare_result(&result, &state.bridge.edits); }
    result
}
#[tauri::command]
async fn release_version_edit_apply(webview: Webview, request: tauri::ipc::Request<'_>, state: State<'_, ShellState>) -> Result<ReleaseVersionEditStatus, BridgeError> {
    fixture_command!(state, Forbidden, observed, BridgeError::new("sg1_fixture_refused", "This fixture does not admit that action."));
    let window = edit_window(&webview)?;
    let result = request_body(&request).and_then(edit_commands::apply)
        .and_then(|args| {
        #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
        if let Some(q) = &state.observation { q.version_apply_request(&args.session_id, &args.plan_token); }
        state.bridge.apply_release_version_edit(&state.document, window, &args.session_id, &args.plan_token)
    });
    if result.is_err() { state.bridge.edits.retire_release_version_request(window); }
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    if let Some(q) = &state.observation { q.version_apply_result(&result, &state.bridge.edits); }
    result
}
#[tauri::command]
async fn release_version_edit_close(webview: Webview, request: tauri::ipc::Request<'_>, state: State<'_, ShellState>) -> Result<ReleaseVersionEditStatus, BridgeError> {
    fixture_command!(state, Forbidden, observed, BridgeError::new("sg1_fixture_refused", "This fixture does not admit that action."));
    let window = edit_window(&webview)?;
    let args = edit_commands::close(request_body(&request)?)?;
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    if let Some(q) = &state.observation { q.version_close_request(&args.session_id); }
    // Original STOP stays available during quit without another root lookup.
    let result = state.bridge.edits.close_release_version(window, &args.session_id);
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    if let Some(q) = &state.observation { q.version_close_result(&result, &state.bridge.edits); }
    result
}
#[tauri::command]
async fn release_version_edit_status(webview: Webview, request: tauri::ipc::Request<'_>, state: State<'_, ShellState>) -> Result<ReleaseVersionEditStatus, BridgeError> {
    fixture_command!(state, Forbidden, observed, BridgeError::new("sg1_fixture_refused", "This fixture does not admit that action."));
    edit_window(&webview)?;
    edit_commands::status(request_body(&request)?)?;
    let result = state.bridge.edits.release_version_status();
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    if let (Some(q), Ok(status)) = (&state.observation, &result) { q.version_edit_status(status, &state.bridge.edits); }
    result
}

fn github_connection_body<'a>(webview: &Webview, request: &'a tauri::ipc::Request<'_>) -> Result<&'a Value, BridgeError> {
    if webview.label() != MAIN_WINDOW { return Err(github_connection_session::refused(GitHubConnectionReason::InvalidInput)); }
    request_body(request).map_err(|_| github_connection_session::refused(GitHubConnectionReason::InvalidInput))
}
#[tauri::command]
async fn github_connection_status(webview: Webview, request: tauri::ipc::Request<'_>, state: State<'_, ShellState>) -> Result<GitHubConnectionStatus, BridgeError> {
    fixture_command!(state, Forbidden, observed, github_connection_session::refused(GitHubConnectionReason::Unqualified));
    let body = github_connection_body(&webview, &request)?;
    github_connection_wire::decode_command_value("github_connection_status", body)
        .map_err(|_| github_connection_session::refused(GitHubConnectionReason::InvalidInput))?;
    let result = Ok(state.document.github_connection_status());
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    if let Some(q) = &state.observation { q.github_result(installed_observation::github::Command::Status, &result); }
    result
}
#[tauri::command]
async fn github_connection_connect_token(webview: Webview, request: tauri::ipc::Request<'_>, state: State<'_, ShellState>) -> Result<GitHubConnectionStatus, BridgeError> {
    fixture_command!(state, Forbidden, observed, github_connection_session::refused(GitHubConnectionReason::Unqualified));
    // No await before native synchronous registration. Qualification/admission
    // is checked by that SAME document gate before its decoder copies a token.
    let result = state.document.github_connection_connect_token(github_connection_body(&webview, &request)?);
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    if let Some(q) = &state.observation { q.github_result(installed_observation::github::Command::Connect, &result); }
    result
}
#[tauri::command]
async fn github_connection_refresh(webview: Webview, request: tauri::ipc::Request<'_>, state: State<'_, ShellState>) -> Result<GitHubConnectionStatus, BridgeError> {
    fixture_command!(state, Forbidden, observed, github_connection_session::refused(GitHubConnectionReason::Unqualified));
    let result = state.document.github_connection_refresh(github_connection_body(&webview, &request)?);
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    if let Some(q) = &state.observation { q.github_result(installed_observation::github::Command::Refresh, &result); }
    result
}
#[tauri::command]
async fn github_connection_disconnect(webview: Webview, request: tauri::ipc::Request<'_>, state: State<'_, ShellState>) -> Result<GitHubConnectionStatus, BridgeError> {
    fixture_command!(state, Forbidden, observed, github_connection_session::refused(GitHubConnectionReason::Unqualified));
    let result = state.document.github_connection_disconnect(github_connection_body(&webview, &request)?);
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    if let Some(q) = &state.observation { q.github_result(installed_observation::github::Command::Disconnect, &result); }
    result
}

fn asset_window(webview: &Webview) -> Result<(), AssetError> {
    if webview.label() == MAIN_WINDOW { Ok(()) } else { Err(AssetError::invalid()) }
}
fn asset_body<'a>(request: &'a tauri::ipc::Request<'_>) -> Result<&'a Value, AssetError> {
    match request.body() { tauri::ipc::InvokeBody::Json(value) => Ok(value), tauri::ipc::InvokeBody::Raw(_) => Err(AssetError::invalid()) }
}

#[tauri::command]
async fn vault_status(webview: Webview, request: tauri::ipc::Request<'_>, state: State<'_, ShellState>) -> Result<AssetStatus, AssetError> {
    fixture_command!(state, AssetStatus, observed, AssetError::new(Reason::Unqualified));
    installed_session_command!(state, Status, session_observed);
    let result = async {
        asset_window(&webview)?; asset_commands::status(asset_body(&request)?)?; Ok(state.document.status())
    }.await;
    fixture_result!(observed, asset, &result);
    installed_session_result!(session_observed, Status, &result);
    result
}
#[tauri::command]
async fn vault_open(webview: Webview, request: tauri::ipc::Request<'_>, state: State<'_, ShellState>) -> Result<AssetStatus, AssetError> {
    fixture_command!(state, Open, observed, AssetError::new(Reason::Unqualified));
    installed_session_command!(state, Open, session_observed);
    let result = async {
        asset_window(&webview)?; asset_commands::open(asset_body(&request)?)?; state.document.open_session()
    }.await;
    fixture_result!(observed, asset, &result);
    installed_session_result!(session_observed, Open, &result);
    result
}
#[tauri::command]
async fn asset_context(webview: Webview, request: tauri::ipc::Request<'_>, state: State<'_, ShellState>) -> Result<AssetStatus, AssetError> {
    fixture_command!(state, Context, observed, AssetError::new(Reason::Unqualified));
    installed_session_command!(state, Context, session_observed);
    let result = async {
        asset_window(&webview)?; let args = asset_commands::context(asset_body(&request)?)?;
        installed_session_input!(session_observed,session_context_input,&args);
        state.document.context(args)
    }.await;
    fixture_result!(observed, asset, &result);
    installed_session_result!(session_observed, Context, &result);
    result
}
#[tauri::command]
async fn asset_choose(webview: Webview, app: tauri::AppHandle, request: tauri::ipc::Request<'_>, state: State<'_, ShellState>) -> Result<AssetStatus, AssetError> {
    fixture_command!(state, Choose, observed, AssetError::new(Reason::Unqualified));
    installed_session_command!(state, Choose, session_observed);
    let result = async {
        asset_window(&webview)?; let args = asset_commands::choose(asset_body(&request)?)?;
        installed_session_input!(session_observed,session_choose_input,&args);
        state.document.choose(app, args)
    }.await;
    fixture_result!(observed, asset, &result);
    installed_session_result!(session_observed, Choose, &result);
    result
}
#[tauri::command]
async fn credential_prepare(webview: Webview, request: tauri::ipc::Request<'_>, state: State<'_, ShellState>) -> Result<AssetStatus, CommandError> {
    fixture_command!(state, Forbidden, observed, CommandError::from(AssetError::new(Reason::Unqualified)));
    installed_session_command!(state, Prepare, session_observed);
    let result = async {
        asset_window(&webview)?; let args = asset_commands::prepare(asset_body(&request)?)?;
        installed_session_input!(session_observed,session_prepare_input,&args);
        let id = state.document.prepare(args)?;
        let document = state.document.clone(); drop(state); drop(request);
        // This waiter owns neither Fields nor an original operation handle.
        // Keep request-drop-before-await; Tauri may still retain its admitted
        // IPC body, so this is not a prompt physical-erasure claim.
        document.prepared(id).await
    }.await;
    installed_session_result!(session_observed, Prepare, &result); result
}
#[tauri::command]
async fn vault_prepare_delete(webview: Webview, request: tauri::ipc::Request<'_>, state: State<'_, ShellState>) -> Result<AssetStatus, AssetError> {
    fixture_command!(state, Forbidden, observed, AssetError::new(Reason::Unqualified));
    installed_session_command!(state, Delete, session_observed);
    let result=async { asset_window(&webview)?; let args = asset_commands::delete(asset_body(&request)?)?; state.document.prepare_delete(args) }.await;
    installed_session_result!(session_observed, Delete, &result); result
}
#[tauri::command]
async fn vault_commit(webview: Webview, request: tauri::ipc::Request<'_>, state: State<'_, ShellState>) -> Result<AssetStatus, AssetError> {
    fixture_command!(state, Forbidden, observed, AssetError::new(Reason::Unqualified));
    installed_session_command!(state, Commit, session_observed);
    let result=async { asset_window(&webview)?; let token = asset_commands::preview_token(asset_body(&request)?)?;
        installed_session_input!(session_observed,session_confirmation_input,token,false); state.document.commit(token) }.await;
    installed_session_result!(session_observed, Commit, &result); result
}
#[tauri::command]
async fn vault_bind(webview: Webview, request: tauri::ipc::Request<'_>, state: State<'_, ShellState>) -> Result<AssetStatus, AssetError> {
    fixture_command!(state, Forbidden, observed, AssetError::new(Reason::Unqualified));
    installed_session_command!(state, Bind, session_observed);
    let result=async { asset_window(&webview)?; let token = asset_commands::preview_token(asset_body(&request)?)?;
        installed_session_input!(session_observed,session_confirmation_input,token,true); state.document.bind(token) }.await;
    installed_session_result!(session_observed, Bind, &result); result
}
#[tauri::command]
async fn vault_discard(webview: Webview, request: tauri::ipc::Request<'_>, state: State<'_, ShellState>) -> Result<AssetStatus, AssetError> {
    fixture_command!(state, Forbidden, observed, AssetError::new(Reason::Unqualified));
    installed_session_command!(state, Discard, session_observed);
    let result=async { asset_window(&webview)?; let id = asset_commands::discard(asset_body(&request)?)?; state.document.discard(id) }.await;
    installed_session_result!(session_observed, Discard, &result); result
}
#[tauri::command]
async fn vault_lock(webview: Webview, request: tauri::ipc::Request<'_>, state: State<'_, ShellState>) -> Result<AssetStatus, AssetError> {
    fixture_command!(state, Forbidden, observed, AssetError::new(Reason::Unqualified));
    installed_session_command!(state, Lock, session_observed);
    let result=async { asset_window(&webview)?; asset_commands::lock(asset_body(&request)?)?; state.document.lock_session() }.await;
    installed_session_result!(session_observed, Lock, &result); result
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
struct PickerGuard { flag: Arc<AtomicBool>, document: Option<DocumentBinding> }
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
impl Drop for PickerGuard { fn drop(&mut self) { if let Some(document) = &self.document { document.compatibility_picker_end(); } self.flag.store(false, Ordering::SeqCst); } }
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
#[tauri::command]
async fn choose_project(state: State<'_, ShellState>) -> Result<Option<Project>, BridgeError> {
    not_closing(&state)?;
    if state.bridge.supervisor.stopping() || state.bridge.edits.stopping() { return Err(BridgeError::shutdown()); }
    if state.picker.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).is_err() {
        return Err(BridgeError::new("busy", "A native project picker is already open."));
    }
    let mut guard = PickerGuard { flag: state.picker.clone(), document: None };
    state.document.compatibility_picker_begin()?;
    guard.document = Some(state.document.clone());
    not_closing(&state)?;
    let document = state.document.clone();
    // A renderer going away cannot abandon the Rust picker/selection owner.
    tauri::async_runtime::spawn(async move {
        let _guard = guard;
        match rfd::AsyncFileDialog::new().set_title("Choose a mobile project folder").pick_folder().await {
            None => Ok(None),
            Some(folder) => document.compatibility_picker_publish(folder.path().to_path_buf()).map(Some),
        }
    }).await.map_err(|_| BridgeError::new("picker_failed", "The native project picker did not settle normally."))?
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
#[tauri::command]
async fn choose_project(webview: Webview, app: tauri::AppHandle, request: tauri::ipc::Request<'_>, state: State<'_, ShellState>) -> Result<Option<Project>, AssetError> {
    fixture_command!(state, Project, observed, AssetError::new(Reason::Unqualified));
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "macos-installed-observation",
        not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer"),
        target_os = "macos", target_arch = "aarch64"))]
    let mut selection = None;
    let result = async {
        asset_window(&webview)?; asset_commands::status(asset_body(&request)?)?;
        let id = state.document.choose_project(app)?;
        // Only an observer of the retained original operation; no path or native
        // handle belongs to this invoke future, even if the renderer disappears.
        #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "macos-installed-observation",
            not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer"),
            target_os = "macos", target_arch = "aarch64"))]
        { state.document.installed_macos_project_result(id, &mut selection).await }
        #[cfg(not(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "macos-installed-observation",
            not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer"),
            target_os = "macos", target_arch = "aarch64")))]
        { state.document.project_result(id).await }
    }.await;
    fixture_result!(observed, project, &result);
    #[cfg(any(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "windows-installed-observation", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "windows-runtime-publisher"), not(feature = "macos-installed-installer"), target_os = "windows", target_arch = "x86_64", target_env = "msvc")))]
    if let Some(q) = &state.observation { q.project_result(&result); }
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "macos-installed-observation",
        not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer"),
        target_os = "macos", target_arch = "aarch64"))]
    // The original result released its document guard before this Record
    // callback. Never look up a possibly replaced slot from the observer.
    if let Some(q) = &state.observation { q.project_result(&result, selection.as_ref()); }
    result
}

#[tauri::command]
async fn choose_project_path(webview: Webview, app: tauri::AppHandle, request: tauri::ipc::Request<'_>, state: State<'_, ShellState>) -> Result<Option<asset_commands::ProjectPathResult>, BridgeError> {
    fixture_command!(state, Forbidden, observed, asset_commands::project_path_error(Reason::Unqualified));
    let result: Result<Option<asset_commands::ProjectPathResult>, AssetError> = async {
        asset_window(&webview)?;
        let args = asset_commands::choose_project_path(asset_body(&request)?)?;
        #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
        if let Some(q) = &state.observation { q.path_request(&args); }
        let owner = state.document.choose_project_path(app, args)?;
        state.document.project_path_result(owner).await
    }.await;
    let result = result.map_err(|error| asset_commands::project_path_error(error.reason));
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    if let Some(q) = &state.observation { q.path_result(&result); }
    result
}

fn trusted_document(url: &tauri::Url) -> bool {
    // Tauri special-cases App("index.html") to the base app URL. Accept its
    // native empty/root-path normalization, not arbitrary same-origin assets.
    let origin = if cfg!(windows) {
        url.scheme() == "http" && url.host_str() == Some("tauri.localhost")
    } else {
        url.scheme() == "tauri" && url.host_str() == Some("localhost")
    };
    origin && url.username().is_empty() && url.password().is_none() && url.port().is_none()
        && url.query().is_none() && url.fragment().is_none() && matches!(url.path(), "" | "/")
}

struct PreflightRelayGuard { document: DocumentBinding, closed: bool }
impl Drop for PreflightRelayGuard {
    fn drop(&mut self) { if !self.closed { self.document.offline_preflight_relay_lost(); } }
}
struct AndroidBuildRelayGuard { document: DocumentBinding, closed: bool }
impl Drop for AndroidBuildRelayGuard {
    fn drop(&mut self) { if !self.closed { self.document.android_build_relay_lost(); } }
}
#[deny(unused_variables, unused_assignments)]
fn start_relay(app: tauri::AppHandle, edits: EditOwner, document: DocumentBinding, mut stop: watch::Receiver<bool>) -> (tauri::async_runtime::JoinHandle<()>, oneshot::Sender<()>) {
    let mut revisions = edits.subscribe();
    let mut assets = document.subscribe();
    let mut diagnostics = document.environment_diagnostics_subscribe();
    let mut preflight = document.offline_preflight_subscribe();
    let preflight_guard = PreflightRelayGuard { document: document.clone(), closed: false }; // Before spawn/unpolled task loss.
    let mut android_build = document.android_build_subscribe();
    let android_build_guard = AndroidBuildRelayGuard { document: document.clone(), closed: false }; // Before spawn/unpolled task loss.
    let (start, enter) = oneshot::channel();
    let handle = tauri::async_runtime::spawn(async move {
        let mut preflight_guard = preflight_guard;
        let mut android_build_guard = android_build_guard;
        if enter.await.is_err() { return; }
        let mut metadata_revision = None;
        let mut release_version_revision = None;
        let mut diagnostics_revision = None;
        let mut preflight_revision = None;
        let mut preflight_relay_failed = false;
        let mut android_build_revision = None;
        let mut android_build_relay_failed = false;
        loop {
            if *stop.borrow() { preflight_guard.closed = true; android_build_guard.closed = true; return; }
            // status() releases its native locks before any renderer callback.
            // Events are best effort: the UI subscribes then fetches status and
            // orders both by native revision, never by arrival time.
            if let Ok(status) = edits.status() {
                #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64", feature = "macos-installed-observation", not(feature = "macos-installed-installer")))))]
                if let Some(q) = app.try_state::<Arc<installed_observation::Observation>>() { q.edit_status(&status, &edits); }
                let _ = app.emit_to(MAIN_WINDOW, EDIT_EVENT, &status);
            }
            #[cfg(any(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64", feature = "macos-installed-observation", not(feature = "macos-installed-installer")))), all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "windows-installed-observation", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "windows-runtime-publisher"), not(feature = "macos-installed-installer"), target_os = "windows", target_arch = "x86_64", target_env = "msvc")))]
            if let Some(q) = app.try_state::<Arc<installed_observation::Observation>>() { q.tick(&app); }
            if let Ok(status) = edits.workflow_status() {
                #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
                if let Some(q) = app.try_state::<Arc<installed_observation::Observation>>() { q.workflow_status(&status, &edits); }
                let _ = app.emit_to(MAIN_WINDOW, WORKFLOW_EDIT_EVENT, &status);
            }
            // Public before/after text can be large. Emit metadata only when
            // original owner state changes, not on each 100ms observer tick.
            // Clients subscribe first, fetch status, and count down from that
            // receipt. Native deadlines still belong to the original owner.
            let revision = *revisions.borrow();
            if metadata_revision != Some(revision) {
                if let Ok(status) = edits.metadata_text_status() {
                    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
                    if let Some(q) = app.try_state::<Arc<installed_observation::Observation>>() { q.metadata_edit_status(&status, &edits); }
                    metadata_revision = Some(status.status_revision);
                    let _ = app.emit_to(MAIN_WINDOW, metadata_text_wire::EVENT, &status);
                }
            }
            if release_version_revision != Some(revision) {
                if let Ok(status) = edits.release_version_status() {
                    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
                    if let Some(q) = app.try_state::<Arc<installed_observation::Observation>>() { q.version_edit_status(&status, &edits); }
                    release_version_revision = Some(status.status_revision);
                    let _ = app.emit_to(MAIN_WINDOW, release_version_wire::EVENT, &status);
                }
            }
            let status = document.status();
            let _ = app.emit_to(MAIN_WINDOW, ASSET_EVENT, &status);
            let status = document.github_connection_status();
            #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
            if let Some(q) = app.try_state::<Arc<installed_observation::Observation>>() { q.github_status(&status); q.github_relay(&app).await; }
            let _ = app.emit_to(MAIN_WINDOW, github_connection_wire::EVENT, &status);
            if let Ok(status) = document.environment_diagnostics_status() {
                if diagnostics_revision != Some(status.status_revision) {
                    diagnostics_revision = Some(status.status_revision);
                    let _ = app.emit_to(MAIN_WINDOW, crate::environment_diagnostics_protocol::EVENT, &status);
                }
            }
            if !preflight_relay_failed {
                if let Ok(status) = document.offline_preflight_status() {
                    if preflight_revision != Some(status.status_revision) {
                        preflight_revision = Some(status.status_revision);
                        if app.emit_to(MAIN_WINDOW, crate::offline_preflight_protocol::EVENT, &status).is_err() {
                            preflight_relay_failed = true; document.offline_preflight_relay_lost();
                        }
                    }
                }
            }
            if !android_build_relay_failed {
                match document.android_build_status() {
                    Ok(status) => {
                        if android_build_revision != Some(status.status_revision) {
                            android_build_revision = Some(status.status_revision);
                            if app.emit_to(MAIN_WINDOW, crate::android_build_protocol::EVENT, &status).is_err() {
                                android_build_relay_failed = true; document.android_build_relay_lost();
                            }
                        }
                    },
                    Err(_) => { android_build_relay_failed = true; document.android_build_relay_lost(); },
                }
            }
            tokio::select! {
                biased;
                result = stop.changed() => { if result.is_err() { return; } if *stop.borrow() { preflight_guard.closed = true; android_build_guard.closed = true; return; } },
                result = revisions.changed() => { if result.is_err() { return; } },
                result = assets.changed() => { if result.is_err() { return; } },
                result = diagnostics.changed() => { if result.is_err() { return; } },
                result = preflight.changed() => { if result.is_err() { return; } },
                result = android_build.changed() => { if result.is_err() { return; } },
                // Observation only: status checks fixed original endpoints and
                // already-ended joins. It launches no operation or new clock.
                _ = tokio::time::sleep(Duration::from_millis(100)) => {},
            }
        }
    });
    (handle, start)
}

async fn settle_relay(app: &tauri::AppHandle) -> bool {
    let state = app.state::<ShellState>(); state.relay_stop.send_replace(true);
    let mut book = state.relay.lock().await;
    if book.settled { return true; }
    // Await only a BORROW of the original retained handle. An observer's loss
    // cannot detach it. Even Err positively joins this data-only relay; it does
    // not change the independently established native/core result.
    let Some(handle) = book.handle.as_mut() else { return false; };
    let joined = handle.await;
    #[cfg(any(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64", feature = "macos-installed-observation", not(feature = "macos-installed-installer")))), all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "windows-installed-observation", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "windows-runtime-publisher"), not(feature = "macos-installed-installer"), target_os = "windows", target_arch = "x86_64", target_env = "msvc")))]
    if let Some(q) = &state.observation { q.relay_joined(joined.is_ok()); }
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "development-runtime", target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    if let Some(context) = &state.fixture { context.relay_joined(joined.is_ok()); }
    #[cfg(not(all(test, debug_assertions, feature = "desktop-shell", feature = "development-runtime", target_os = "linux", target_arch = "x86_64", target_env = "gnu")))]
    let _ = joined;
    book.handle.take(); book.settled = true; true
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn start_exit_observer(app: tauri::AppHandle, document: DocumentBinding) -> (tauri::async_runtime::JoinHandle<()>, oneshot::Sender<()>) {
    let (start, enter) = oneshot::channel();
    let handle = tauri::async_runtime::spawn(async move {
        if enter.await.is_err() { return; }
        loop {
            // One fixed app-level exit observer. can_exit only observes the
            // already-ended original quit coordinator; it starts no dialog or
            // business operation. Windows extends this SAME finality path with
            // retained original-STA controller/browser/UDF cleanup below.
            if document.can_exit() {
                #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
                if let Some(q) = app.try_state::<Arc<installed_observation::Observation>>() {
                    if !q.github_exit(&app).await || !document.can_exit() { return; }
                }
                if !settle_relay(&app).await || !document.can_exit() { return; }
                #[cfg(all(target_os = "windows", target_arch = "x86_64", target_env = "msvc"))]
                if !owned_windows::settle_for_exit(&app, &document).await || !document.can_exit() { return; }
                #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "development-runtime", target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
                if let Some(context) = &app.state::<ShellState>().fixture {
                    if context.seal().await.is_err() { context.refuse(); return; }
                }
                app.state::<ShellState>().exit_ready.store(true, Ordering::SeqCst);
                app.exit(0); return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    });
    (handle, start)
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn request_shutdown(app: &tauri::AppHandle) { app.state::<ShellState>().document.request_quit(app.clone()); }

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn request_shutdown(app: &tauri::AppHandle) {
    let state = app.state::<ShellState>();
    // The native picker has no safe cancellation primitive. Keep its original
    // window/event-loop owner until the user selects or cancels it.
    if state.picker.load(Ordering::SeqCst) { return; }
    if state.closing.swap(true, Ordering::SeqCst) { return; }
    if state.picker.load(Ordering::SeqCst) {
        state.closing.store(false, Ordering::SeqCst);
        return;
    }
    if !state.document.compatibility_quit_begin() {
        state.closing.store(false, Ordering::SeqCst); return;
    }
    let bridge = state.bridge.clone();
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        // Unconditional native confirmation protects all in-memory drafts.
        // Cancel stops nothing; an accepted Apply may already have committed.
        let choice = rfd::AsyncMessageDialog::new()
            .set_title("Quit and discard unsaved drafts?")
            .set_description("Unsaved in-memory changes will be lost. Choose Cancel to keep working, or OK to stop owned operations and wait for cleanup before quitting. A save already accepted may still complete; quitting does not undo committed files.")
            .set_buttons(rfd::MessageButtons::OkCancel)
            .set_level(rfd::MessageLevel::Warning)
            .show().await;
        if !matches!(choice, rfd::MessageDialogResult::Ok) {
            app.state::<ShellState>().document.compatibility_quit_result(false);
            app.state::<ShellState>().closing.store(false, Ordering::SeqCst);
            return;
        }
        app.state::<ShellState>().document.compatibility_quit_result(true);
        // No short circuit can skip another original owner's shutdown.
        let (passive, edit, diagnostics, preflight, android_build) = tokio::join!(bridge.supervisor.shutdown(), bridge.edits.shutdown(), bridge.diagnostics.shutdown(), bridge.preflight.shutdown(), bridge.android_build.shutdown());
        if passive.is_ok() && edit.is_ok() && diagnostics.is_ok() && preflight.is_ok() && android_build.is_ok()
            && bridge.supervisor.can_exit() && bridge.edits.can_exit() && bridge.diagnostics.can_exit() && bridge.preflight.can_exit() && bridge.android_build.can_exit() {
            if !settle_relay(&app).await { return; }
            if !(bridge.supervisor.can_exit() && bridge.edits.can_exit() && bridge.diagnostics.can_exit() && bridge.preflight.can_exit() && bridge.android_build.can_exit()) { return; }
            app.state::<ShellState>().exit_ready.store(true, Ordering::SeqCst);
            app.exit(0);
        } else {
            let _ = rfd::AsyncMessageDialog::new().set_title("Operation cleanup is unconfirmed")
                .set_description("Original operation owners remain retained and new work is disabled. Keep this window open until cleanup settles. Closing again only rechecks existing owners; it does not repeat or undo an operation.")
                .set_level(rfd::MessageLevel::Error).show().await;
            app.state::<ShellState>().closing.store(false, Ordering::SeqCst);
        }
    });
}

#[derive(Clone, Copy)]
pub(crate) enum DialogChoice { File(crate::credential_format::FileKind), Project, ProjectPath(asset_commands::ProjectPathField), EvidenceFolder, Quit }

#[cfg(target_os = "linux")]
fn requires_recent_files_suppression(choice: DialogChoice) -> bool {
    matches!(choice, DialogChoice::File(_) | DialogChoice::Project | DialogChoice::EvidenceFolder | DialogChoice::ProjectPath(_))
}

#[cfg(not(any(target_os = "linux", all(target_os = "macos", target_arch = "aarch64"), all(target_os = "windows", target_arch = "x86_64", target_env = "msvc"))))]
pub(crate) async fn run_owned_dialog(_: &tauri::AppHandle, owner: &Arc<OriginalWork>, _: DialogChoice, _: Option<std::path::PathBuf>) -> Result<Option<std::path::PathBuf>, Reason> {
    owner.gui.not_created(Reason::UnsupportedPlatform); Err(Reason::UnsupportedPlatform)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[path = "shell_macos_dialog.rs"]
mod owned_macos;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) use owned_macos::run_owned_dialog;

#[cfg(all(target_os = "windows", target_arch = "x86_64", target_env = "msvc"))]
#[path = "shell_windows.rs"]
mod owned_windows;
#[cfg(all(target_os = "windows", target_arch = "x86_64", target_env = "msvc"))]
pub(crate) use owned_windows::run_owned_dialog;

#[cfg(target_os = "linux")]
pub(crate) use owned_gtk::run_owned_dialog;

#[cfg(target_os = "linux")]
mod owned_gtk {
    use super::*;
    use std::{cell::RefCell, path::PathBuf, sync::Weak};
    use gtk::prelude::*;
    use crate::{asset_session::GuiCall, credential_format::FileKind};

    // Exactly one actual native object book on the existing GTK main thread.
    // This is resource ownership, not another document/authority registry.
    thread_local! { static DIALOG: RefCell<Option<NativeDialog>> = const { RefCell::new(None) }; }
    enum Object { File(gtk::FileChooserDialog), Message(gtk::MessageDialog) }
    struct NativeDialog {
        id: u32, object: Object, filter: Option<gtk::FileFilter>,
        response: Option<gtk::glib::SignalHandlerId>, destroy: Option<gtk::glib::SignalHandlerId>,
        #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
        observation: Option<(Weak<installed_observation::Observation>, Weak<GuiCall>)>,
        #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "development-runtime", target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
        topology: Option<topology::DialogMetadata>,
    }
    impl Object {
        fn close(&self) { match self { Self::File(dialog) => dialog.close(), Self::Message(dialog) => dialog.close() } }
        fn show(&self) { match self { Self::File(dialog) => dialog.show(), Self::Message(dialog) => dialog.show() } }
    }

    fn destroyed(weak: &Weak<GuiCall>) {
        let Some(call) = weak.upgrade() else { return; };
        gtk_fixture!(call, DestroyEnter, 1);
        let unexpected = if let Some(mut facts) = call.facts() {
            let unexpected = !facts.response && call.owner().is_some_and(|owner| !owner.stopped());
            facts.destroyed = true; facts.showing = false; unexpected
        } else { true };
        if unexpected { call.failed(Reason::SourceRefused); }
        gtk_fixture!(call, DestroyLeave, 1);
        call.changed();
    }
    fn native_path(dialog: &gtk::FileChooserDialog, _call: &GuiCall) -> Result<PathBuf, Reason> {
        // Exactly one accepted-response filename() call. Before any additional
        // application path copy, enforce native byte/component bounds. Neither
        // this hint nor its basename is ever returned as an asset DTO.
        gtk_fixture!(_call, Filename, 1);
        let path = dialog.filename().ok_or(Reason::SourceRefused)?;
        crate::asset_source::path_hint(&path)?; Ok(path)
    }
    fn not_created(call: &Arc<GuiCall>, reason: Reason) { call.not_created(reason); call.failed(reason); }

    fn construct(app: tauri::AppHandle, call: Arc<GuiCall>, choice: DialogChoice, initial_folder: Option<PathBuf>) {
        if !gtk::is_initialized_main_thread() { not_created(&call, Reason::Unqualified); return; }
        #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
        let observation = app.try_state::<Arc<installed_observation::Observation>>().map(|q| Arc::downgrade(q.inner()));
        gtk_fixture!(call, ConstructEnter, match choice { DialogChoice::Project => 1,
            DialogChoice::File(FileKind::AndroidKeystore) => 2, DialogChoice::Quit => 3, _ => 4 });
        let Some(owner) = call.owner() else { not_created(&call, Reason::CleanupUnknown); return; };
        if owner.interrupted() { not_created(&call, Reason::UserCancelled); return; }
        if DIALOG.with(|book| book.borrow().is_some()) { not_created(&call, Reason::Busy); return; }
        let Some(window) = app.get_webview_window(MAIN_WINDOW) else { not_created(&call, Reason::DocumentLost); return; };
        let parent = match window.gtk_window() { Ok(parent) => parent, Err(_) => { not_created(&call, Reason::Unqualified); return; } };
        if let Some(mut facts) = call.facts() { facts.constructing = true; } else { call.failed(Reason::CleanupUnknown); return; }
        if requires_recent_files_suppression(choice) {
            let Some(settings) = gtk::Settings::default() else { not_created(&call, Reason::Unqualified); return; };
            settings.set_gtk_recent_files_enabled(false);
            if settings.is_gtk_recent_files_enabled() { not_created(&call, Reason::Unqualified); return; }
        }
        if owner.interrupted() { not_created(&call, Reason::UserCancelled); return; }
        let object = match choice {
            DialogChoice::File(kind) => {
                let title = match kind { FileKind::AndroidKeystore => "Choose an Android JKS keystore", FileKind::AndroidFirebase => "Choose Android Firebase JSON" };
                Object::File(gtk::FileChooserDialog::with_buttons(Some(title), Some(&parent), gtk::FileChooserAction::Open,
                    &[("Cancel", gtk::ResponseType::Cancel), ("Select", gtk::ResponseType::Accept)]))
            }
            DialogChoice::Project => Object::File(gtk::FileChooserDialog::with_buttons(Some("Choose a mobile project folder"), Some(&parent), gtk::FileChooserAction::SelectFolder,
                &[("Cancel", gtk::ResponseType::Cancel), ("Select", gtk::ResponseType::Accept)])),
            DialogChoice::ProjectPath(field) => {
                let title = match field {
                    asset_commands::ProjectPathField::VersionSource => "Choose an existing version source inside the project",
                    asset_commands::ProjectPathField::IosProject => "Choose an existing Xcode project directory",
                    asset_commands::ProjectPathField::IosWorkspace => "Choose an existing Xcode workspace directory",
                    asset_commands::ProjectPathField::MetadataRoot => "Choose an existing metadata directory inside the project",
                };
                let action = if field.directory() { gtk::FileChooserAction::SelectFolder } else { gtk::FileChooserAction::Open };
                Object::File(gtk::FileChooserDialog::with_buttons(Some(title), Some(&parent), action,
                    &[("Cancel", gtk::ResponseType::Cancel), ("Select", gtk::ResponseType::Accept)]))
            }
            DialogChoice::EvidenceFolder => Object::File(gtk::FileChooserDialog::with_buttons(Some("Choose a candidate evidence folder"), Some(&parent), gtk::FileChooserAction::SelectFolder,
                &[("Cancel", gtk::ResponseType::Cancel), ("Select evidence folder", gtk::ResponseType::Accept)])),
            DialogChoice::Quit => Object::Message(gtk::MessageDialog::new(Some(&parent), gtk::DialogFlags::MODAL, gtk::MessageType::Question, gtk::ButtonsType::OkCancel,
                "Unsaved in-memory changes will be lost. Choose Cancel to keep working, or OK to stop owned operations and wait for cleanup before quitting. A save already accepted may still complete; quitting does not undo committed files.")),
        };
        // Adopt the late returned object BEFORE any STOP check/configuration.
        // A cancellation during its constructor cannot lose its destruction
        // obligation. No callback captures a strong dialog or application cycle.
        DIALOG.with(|book| *book.borrow_mut() = Some(NativeDialog { id: owner.id, object, filter: None, response: None, destroy: None,
            #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
            observation: observation.as_ref().map(|q| (q.clone(), Arc::downgrade(&call))),
            #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "development-runtime", target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
            topology: None,
        }));
        if let Some(mut facts) = call.facts() { facts.created = true; facts.constructing = false; }
        #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
        if let Some(q) = observation.as_ref().and_then(Weak::upgrade) {
            if matches!(choice, DialogChoice::Project) { q.project_created(owner.id); }
            else if matches!(choice, DialogChoice::EvidenceFolder) { q.evidence_created(owner.id); }
            else if let DialogChoice::ProjectPath(field) = choice { q.path_created(owner.id,field); }
            else if let DialogChoice::File(kind) = choice { q.session_file_created(owner.id,kind); }
            else { q.native_created(owner.id, matches!(choice, DialogChoice::Quit)); }
        }
        gtk_fixture!(call, Adopted, 1);
        DIALOG.with(|book| {
            let mut book = book.borrow_mut();
            let Some(entry) = book.as_mut().filter(|entry| entry.id == owner.id) else { call.failed(Reason::CleanupUnknown); return; };
            let response_call = Arc::downgrade(&call); let destroy_call = Arc::downgrade(&call);
            match &entry.object {
                Object::File(dialog) => {
                    dialog.set_local_only(true); dialog.set_select_multiple(false); dialog.set_create_folders(false);
                    dialog.set_modal(true); dialog.set_destroy_with_parent(true);
                    // Private native hint from the captured registration, never
                    // a renderer path/current value or a fallback to recents.
                    // Failure still retains this already-adopted GUI original.
                    if let Some(folder) = initial_folder.as_deref() {
                        if !dialog.set_current_folder(folder) { call.failed(Reason::SourceRefused); }
                    }
                    if let DialogChoice::File(kind) = choice {
                        let filter = gtk::FileFilter::new();
                        match kind {
                            FileKind::AndroidKeystore => {
                                filter.set_name(Some("JKS keystore (.jks, .keystore)"));
                                for pattern in ["*.jks", "*.JKS", "*.keystore", "*.KEYSTORE"] { filter.add_pattern(pattern); }
                            }
                            FileKind::AndroidFirebase => {
                                filter.set_name(Some("Android Firebase JSON (.json)"));
                                for pattern in ["*.json", "*.JSON"] { filter.add_pattern(pattern); }
                            }
                        }
                        dialog.add_filter(filter.clone()); dialog.set_filter(&filter); entry.filter = Some(filter);
                    }
                    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
                    let (response_observation, destroy_observation, observed_id) = (observation.clone(), observation.clone(), owner.id);
                    entry.response = Some(dialog.connect_response(move |dialog, response| {
                        let Some(call) = response_call.upgrade() else { return; };
                        #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
                        let (observed_accept, observed_cancel, observed_delete) = (response == gtk::ResponseType::Accept,
                            response == gtk::ResponseType::Cancel, response == gtk::ResponseType::DeleteEvent);
                        gtk_fixture!(call, ResponseEnter, match response { gtk::ResponseType::Accept => 1,
                            gtk::ResponseType::Cancel => 2, gtk::ResponseType::DeleteEvent => 3, _ => 4 });
                        // Latch the actual response/endpoint under the real
                        // admission lock BEFORE calling filename(), without
                        // holding that lock over any GTK API.
                        let response = match response {
                            gtk::ResponseType::Accept => NativeResponse::Accept,
                            gtk::ResponseType::Cancel | gtk::ResponseType::DeleteEvent => NativeResponse::Decline,
                            _ => NativeResponse::Other,
                        };
                        let read_one_path = call.begin_response(response, false);
                        if read_one_path == Some(true) {
                            let path = native_path(dialog, &call);
                            #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
                            if let Some(q) = response_observation.as_ref().and_then(Weak::upgrade) {
                                match choice {
                                    DialogChoice::Project => q.project_filename(observed_id, path.as_ref().ok().map(PathBuf::as_path)),
                                    DialogChoice::EvidenceFolder => q.evidence_filename(observed_id, path.as_ref().ok().map(PathBuf::as_path)),
                                    DialogChoice::ProjectPath(field) => q.path_filename(observed_id,field,path.as_ref().ok().map(PathBuf::as_path)),
                                    DialogChoice::File(_) => q.session_file_filename(observed_id,path.as_ref().ok().map(PathBuf::as_path)),
                                    _ => q.unexpected(),
                                }
                            }
                            call.selected_path(path);
                        }
                        #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
                        if let Some(q) = response_observation.as_ref().and_then(Weak::upgrade) {
                            let (accepted, cancelled, disposal) = call.facts().map_or((false, false, false), |facts| {
                                let path_choice = matches!(choice,DialogChoice::ProjectPath(_));
                                let response = facts.response && (if path_choice { facts.accepted != facts.declined } else { !facts.declined })
                                    && !facts.destroyed && !facts.released && facts.refusal.is_none();
                                (observed_accept && read_one_path == Some(true) && response && facts.accepted && facts.selected.is_some() && !facts.close_ack,
                                 observed_cancel && read_one_path == Some(false) && response && !facts.accepted && (!path_choice || facts.declined)
                                    && facts.selected.is_none() && !facts.close_ack,
                                 observed_delete && read_one_path.is_none() && response && facts.close_ack)
                            });
                            match choice {
                                DialogChoice::Project => q.project_response(observed_id, accepted, cancelled, disposal),
                                DialogChoice::EvidenceFolder => q.evidence_response(observed_id, accepted, cancelled, disposal),
                                DialogChoice::ProjectPath(_) => q.path_response(observed_id,accepted,cancelled,disposal),
                                DialogChoice::File(_) => q.session_file_response(observed_id,accepted,cancelled,disposal),
                                _ => q.unexpected(),
                            }
                        }
                        gtk_fixture!(call, ResponseLeave, 1);
                    }));
                    entry.destroy = Some(dialog.connect_destroy(move |_| {
                        destroyed(&destroy_call);
                        #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
                        if let Some(q) = destroy_observation.as_ref().and_then(Weak::upgrade) {
                            let seen = destroy_call.upgrade().is_some_and(|call| call.facts().is_some_and(|facts|
                                installed_observation::file_destroyed(&facts, matches!(choice, DialogChoice::ProjectPath(_)))));
                            q.native_destroyed(observed_id, seen);
                        }
                    }));
                }
                Object::Message(dialog) => {
                    dialog.set_title("Quit and discard unsaved drafts?"); dialog.set_destroy_with_parent(true);
                    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
                    let (response_observation, destroy_observation, observed_id) = (observation.clone(), observation.clone(), owner.id);
                    entry.response = Some(dialog.connect_response(move |_, response| {
                        if let Some(call) = response_call.upgrade() {
                            #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
                            let (observed_ok, observed_cancel, observed_delete) = (response == gtk::ResponseType::Ok,
                                response == gtk::ResponseType::Cancel, response == gtk::ResponseType::DeleteEvent);
                            gtk_fixture!(call, ResponseEnter, match response { gtk::ResponseType::Ok => 1,
                                gtk::ResponseType::Cancel => 2, gtk::ResponseType::DeleteEvent => 3, _ => 4 });
                            let response = match response {
                                gtk::ResponseType::Ok => NativeResponse::Accept,
                                gtk::ResponseType::Cancel | gtk::ResponseType::DeleteEvent => NativeResponse::Decline,
                                _ => NativeResponse::Other,
                            };
                            let _read_one_path = call.begin_response(response, true);
                            #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
                            if let Some(q) = response_observation.as_ref().and_then(Weak::upgrade) {
                                // begin_response returns filename-read permission,
                                // NOT consent. A first Quit decision returns false;
                                // acceptance is in the original call's facts.
                                let (accepted, declined, disposal) = call.facts().map_or((false, false, false), |facts| {
                                    let response = facts.response && facts.accepted != facts.declined && !facts.destroyed && !facts.released
                                        && facts.refusal.is_none() && facts.selected.is_none();
                                    (observed_ok && _read_one_path == Some(false) && response && facts.accepted && !facts.close_ack,
                                     observed_cancel && _read_one_path == Some(false) && response && facts.declined && !facts.close_ack,
                                     observed_delete && _read_one_path.is_none() && response && facts.close_ack)
                                });
                                q.native_response(observed_id, accepted, declined, disposal);
                            }
                            gtk_fixture!(call, ResponseLeave, 1);
                        }
                    }));
                    entry.destroy = Some(dialog.connect_destroy(move |_| {
                        destroyed(&destroy_call);
                        #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
                        if let Some(q) = destroy_observation.as_ref().and_then(Weak::upgrade) {
                            let seen = destroy_call.upgrade().is_some_and(|call| call.facts().is_some_and(|facts|
                                facts.destroyed && facts.response && facts.accepted != facts.declined && facts.refusal.is_none()));
                            q.native_destroyed(observed_id, seen);
                        }
                    }));
                }
            }
        });
        #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "development-runtime", target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
        topology::tag(parent.upcast_ref(), &call);
        if owner.interrupted() { call.changed(); return; }
        if let Some(mut facts) = call.facts() { facts.showing = true; }
        DIALOG.with(|book| { if let Some(entry) = book.borrow().as_ref().filter(|entry| entry.id == owner.id) { entry.object.show(); } });
        gtk_fixture!(call, Show, 1);
        call.presented(); call.changed();
    }

    fn close_after_response(call: Arc<GuiCall>, id: u32) {
        if !gtk::is_initialized_main_thread() { call.failed(Reason::CleanupUnknown); return; }
        gtk_fixture!(call, CloseEnter, 1);
        // Entry into this non-main-origin queued closure is the response-unwind
        // barrier. close() itself is only a request, NEVER destruction proof.
        let destroyed = call.facts().is_some_and(|facts| facts.destroyed);
        if !destroyed {
            DIALOG.with(|book| {
                if let Some(entry) = book.borrow().as_ref().filter(|entry| entry.id == id) { entry.object.close(); }
                else { call.failed(Reason::CleanupUnknown); }
            });
        }
        if let Some(mut facts) = call.facts() { facts.close_ack = true; }
        gtk_fixture!(call, CloseAck, 1);
        gtk_fixture!(call, CloseLeave, 1);
        call.changed();
    }
    fn release_after_destroy(call: Arc<GuiCall>, id: u32) {
        if !gtk::is_initialized_main_thread() { call.failed(Reason::CleanupUnknown); return; }
        gtk_fixture!(call, ReleaseEnter, 1);
        if !call.facts().is_some_and(|facts| facts.destroyed && facts.close_ack) { call.failed(Reason::CleanupUnknown); return; }
        let original = DIALOG.with(|book| {
            let mut book = book.borrow_mut();
            if book.as_ref().is_some_and(|entry| entry.id == id) { book.take() } else { None }
        });
        let Some(mut original) = original else { call.failed(Reason::CleanupUnknown); return; };
        #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
        let observation = original.observation.as_ref().and_then(|(q, _)| q.upgrade());
        // This queued entry is the full genuine GTK destruction-unwind barrier.
        // gtk_widget_destroy runs GObject disposal, which disconnects all handlers.
        // Retire only the saved IDs; do not disconnect or query the inert widget.
        original.response = None;
        original.destroy = None;
        gtk_fixture!(call, HandlersDetached, 1);
        #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "development-runtime", target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
        let had_topology = original.topology.is_some();
        drop(original); // Original dialog/filter refs, on their thread.
        #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "development-runtime", target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
        topology::retire(&call, id, had_topology);
        if let Some(mut facts) = call.facts() { facts.released = true; }
        #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
        if let Some(q) = observation {
            let seen = call.facts().is_some_and(|facts| facts.destroyed && facts.close_ack && facts.released)
                && DIALOG.with(|book| book.borrow().is_none());
            q.native_released(id, seen);
        }
        gtk_fixture!(call, Released, u32::from(DIALOG.with(|book| book.borrow().is_none())));
        gtk_fixture!(call, ReleaseLeave, 1);
        call.changed();
    }

    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    fn observed_folder_dialog(app: &tauri::AppHandle, q: &Arc<installed_observation::Observation>, evidence: bool) -> Result<Option<(u32, gtk::FileChooserDialog)>, ()> {
        if !gtk::is_initialized_main_thread() { return Err(()); }
        let original = DIALOG.with(|book| {
            let book = book.try_borrow().map_err(|_| ())?;
            let Some(entry) = book.as_ref() else { return Ok(None); };
            let Object::File(dialog) = &entry.object else { return Err(()); };
            let (context, call) = entry.observation.as_ref().ok_or(())?;
            Ok(Some((entry.id, dialog.clone(), context.clone(), call.clone())))
        })?;
        let Some((id, dialog, context, call)) = original else { return Ok(None); };
        if !context.upgrade().is_some_and(|actual| Arc::ptr_eq(&actual, q)) { return Err(()); }
        let call = call.upgrade().ok_or(())?; let owner = call.owner().ok_or(())?;
        if owner.id != id || !Arc::ptr_eq(&owner.gui, &call) || owner.interrupted()
            || !call.facts().is_some_and(|facts| facts.created && facts.showing && !facts.constructing
                && !facts.not_created && !facts.response && !facts.destroyed && !facts.released && facts.refusal.is_none()) { return Err(()); }
        let main = app.get_webview_window(MAIN_WINDOW).ok_or(())?;
        let parent: gtk::Window = main.gtk_window().map_err(|_| ())?.upcast();
        let title = if evidence { "Choose a candidate evidence folder" } else { "Choose a mobile project folder" };
        if dialog.title().as_deref() != Some(title) || !dialog.is_visible() || !dialog.is_modal()
            || dialog.transient_for().as_ref() != Some(&parent)
            || dialog.property::<gtk::FileChooserAction>("action") != gtk::FileChooserAction::SelectFolder
            || !dialog.property::<bool>("local-only") || dialog.property::<bool>("select-multiple") || dialog.property::<bool>("create-folders")
            || gtk::Settings::default().is_none_or(|settings| settings.is_gtk_recent_files_enabled()) { return Err(()); }
        // Temporary refs to the actual retained original, released in this
        // main-thread callback. No test-side GTK/source owner is installed.
        Ok(Some((id, dialog)))
    }

    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    pub(super) fn select_observed_folder(app: &tauri::AppHandle, q: &Arc<installed_observation::Observation>, evidence: bool) -> Result<bool, ()> {
        let Some((id, dialog)) = observed_folder_dialog(app, q, evidence)? else { return Ok(false); };
        let path = (if evidence { q.evidence_path() } else { q.project_path() }).ok_or(())?;
        if evidence { q.evidence_selection(id)?; } else { q.project_selection(id)?; }
        // Navigate once into the exact accessible target. Selecting a row in
        // its protected, nonenumerable parent is not a selection receipt.
        // Never read filename here: the admitted response owns that sole read.
        if !dialog.set_current_folder(path) { return Err(()); }
        Ok(true)
    }

    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    pub(super) fn activate_observed_folder(app: &tauri::AppHandle, q: &Arc<installed_observation::Observation>, select: bool, evidence: bool) -> Result<bool, ()> {
        let Some((id, dialog)) = observed_folder_dialog(app, q, evidence)? else { return Ok(false); };
        if select {
            let path = (if evidence { q.evidence_path() } else { q.project_path() }).ok_or(())?;
            // A setter return or one relay tick is not asynchronous readiness.
            // Wait within the original clock, without another setter or click.
            if dialog.current_folder().as_deref() != Some(path) { return Ok(false); }
        }
        let response = if select { gtk::ResponseType::Accept } else { gtk::ResponseType::Cancel };
        let button = dialog.widget_for_response(response).ok_or(())?.downcast::<gtk::Button>().map_err(|_| ())?;
        if !button.is_visible() || dialog.response_for_widget(&button) != response
            || button.label().as_deref() != Some(if select { if evidence { "Select evidence folder" } else { "Select" } } else { "Cancel" }) { return Err(()); }
        if !button.is_sensitive() { return Ok(false); }
        if evidence { q.evidence_activation(id, select)?; } else { q.project_activation(id, select)?; }
        // GtkDialog's original clicked handler produces the response. Neither
        // response() nor the admission begin_response() is called by this seam.
        button.emit_clicked(); Ok(true)
    }


    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    fn observed_path_dialog(app: &tauri::AppHandle, q: &Arc<installed_observation::Observation>, index: u8) -> Result<Option<(u32,gtk::FileChooserDialog)>,()> {
        use installed_observation::PathRejection as R;
        if !gtk::is_initialized_main_thread() { q.path_failed(R::GtkThread); return Err(()); }
        let original = DIALOG.with(|book| {
            let book = book.try_borrow().map_err(|_| R::GtkDialogBook)?;
            let Some(entry) = book.as_ref() else { return Ok(None); };
            let Object::File(dialog) = &entry.object else { return Err(R::GtkDialogOriginal); };
            let (context,call) = entry.observation.as_ref().ok_or(R::GtkDialogOriginal)?;
            Ok(Some((entry.id,dialog.clone(),context.clone(),call.clone())))
        });
        // Only a closed reason crosses the DIALOG borrow; release it before
        // taking the observation's Record, as in the session-file observer.
        let original = match original {
            Ok(original) => original,
            Err(reason) => { q.path_failed(reason); return Err(()); },
        };
        let Some((id,dialog,context,call)) = original else { q.path_wait(installed_observation::PathWait::DialogAbsent); return Ok(None); };
        if !context.upgrade().is_some_and(|actual| Arc::ptr_eq(&actual,q)) { q.path_failed(R::GtkDialogOriginal); return Err(()); }
        let Some(call) = call.upgrade() else { q.path_failed(R::GtkDialogOriginal); return Err(()); };
        let Some(owner) = call.owner() else { q.path_failed(R::GtkOwnerBinding); return Err(()); };
        if owner.id != id || !Arc::ptr_eq(&owner.gui,&call) { q.path_failed(R::GtkOwnerBinding); return Err(()); }
        if owner.interrupted() { q.path_failed(R::GtkOwnerInterrupted); return Err(()); }
        let original_facts = call.facts().is_some_and(|f| f.created && f.showing && !f.constructing && !f.not_created
            && !f.response && !f.destroyed && !f.released && f.refusal.is_none());
        if !original_facts { q.path_failed(R::GtkOwnerFacts); return Err(()); }
        let (field,initial) = q.path_dialog(id,index)?;
        let title = match field {
            asset_commands::ProjectPathField::VersionSource => "Choose an existing version source inside the project",
            asset_commands::ProjectPathField::IosProject => "Choose an existing Xcode project directory",
            asset_commands::ProjectPathField::IosWorkspace => "Choose an existing Xcode workspace directory",
            asset_commands::ProjectPathField::MetadataRoot => "Choose an existing metadata directory inside the project",
        };
        let Some(main) = app.get_webview_window(MAIN_WINDOW) else { q.path_failed(R::GtkDialogProperties); return Err(()); };
        let parent: gtk::Window = match main.gtk_window() {
            Ok(window) => window.upcast(),
            Err(_) => { q.path_failed(R::GtkDialogProperties); return Err(()); },
        };
        if dialog.title().as_deref() != Some(title) || !dialog.is_visible() || !dialog.is_modal()
            || dialog.transient_for().as_ref() != Some(&parent) || !dialog.property::<bool>("destroy-with-parent")
            || dialog.property::<gtk::FileChooserAction>("action") != (if field.directory() { gtk::FileChooserAction::SelectFolder } else { gtk::FileChooserAction::Open })
            || !dialog.property::<bool>("local-only") || dialog.property::<bool>("select-multiple") || dialog.property::<bool>("create-folders")
            || gtk::Settings::default().is_none_or(|settings| settings.is_gtk_recent_files_enabled()) { q.path_failed(R::GtkDialogProperties); return Err(()); }
        if initial {
            let Some(folder) = dialog.current_folder() else { q.path_wait(installed_observation::PathWait::InitialFolderAbsent); return Ok(None); };
            if Some(folder.as_path()) != q.project_path() { q.path_failed(R::GtkInitialFolder); return Err(()); }
        }
        Ok(Some((id,dialog)))
    }
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    pub(super) fn select_observed_path(app: &tauri::AppHandle, q: &Arc<installed_observation::Observation>, index: u8) -> Result<bool,()> {
        use installed_observation::PathRejection as R;
        let Some((id,dialog)) = observed_path_dialog(app,q,index)? else { return Ok(false); };
        let Some(path) = q.path_target(index) else { q.path_failed(R::GtkTarget); return Err(()); };
        q.path_selection(id,index)?;
        if !dialog.set_filename(path) { q.path_failed(R::GtkSelectionSetter); return Err(()); }
        Ok(true)
    }
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    pub(super) fn activate_observed_path(app: &tauri::AppHandle, q: &Arc<installed_observation::Observation>, index: u8) -> Result<bool,()> {
        use installed_observation::PathRejection as R;
        use installed_observation::PathWait as W;
        let Some((id,dialog)) = observed_path_dialog(app,q,index)? else { return Ok(false); };
        let target = q.path_target(index);
        let select = target.is_some();
        if let Some(path) = target {
            // Observer-only readiness, not a filename transfer or identity proof.
            // A setter return or sensitive button can precede GTK's selection.
            let Some(file) = dialog.file() else { q.path_wait(W::SelectionAbsent); return Ok(false); };
            if !file.equal(&gtk::gio::File::for_path(&path)) { q.path_wait(W::SelectionDifferent); return Ok(false); }
        }
        let response = if select { gtk::ResponseType::Accept } else { gtk::ResponseType::Cancel };
        let button = match dialog.widget_for_response(response).and_then(|widget| widget.downcast::<gtk::Button>().ok()) {
            Some(button) => button,
            None => { q.path_failed(R::GtkResponseWidget); return Err(()); },
        };
        if !button.is_visible() || dialog.response_for_widget(&button) != response
            || button.label().as_deref() != Some(if select { "Select" } else { "Cancel" }) { q.path_failed(R::GtkActionWidget); return Err(()); }
        if !button.is_sensitive() { q.path_wait(W::ResponseInsensitive); return Ok(false); }
        q.path_activation(id,index)?;
        button.emit_clicked(); Ok(true)
    }

    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    fn observed_session_file(app: &tauri::AppHandle, q: &Arc<installed_observation::Observation>, index: u8, activating: bool) -> Result<Option<(u32, gtk::FileChooserDialog, bool)>, ()> {
        use installed_observation::{SessionRejection as R, SessionWait as W};
        if !gtk::is_initialized_main_thread() { q.session_file_failed(R::GtkThread); return Err(()); }
        let original = DIALOG.with(|book| {
            let book = book.try_borrow().map_err(|_| R::GtkDialogBook)?;
            let Some(entry) = book.as_ref() else { return Ok(None); };
            let Object::File(dialog) = &entry.object else { return Err(R::GtkDialogOriginal); };
            let (context, call) = entry.observation.as_ref().ok_or(R::GtkDialogOriginal)?;
            Ok(Some((entry.id, dialog.clone(), context.clone(), call.clone())))
        });
        // Only closed DATA crosses the DIALOG borrow; record after it is gone.
        let original = match original {
            Ok(original) => original,
            Err(reason) => { q.session_file_failed(reason); return Err(()); },
        };
        let Some((id, dialog, context, call)) = original else {
            q.session_file_wait(index, activating, W::GtkDialogAbsent); return Ok(None);
        };
        if !context.upgrade().is_some_and(|actual| Arc::ptr_eq(&actual, q)) { q.session_file_failed(R::GtkDialogOriginal); return Err(()); }
        let Some(call) = call.upgrade() else { q.session_file_failed(R::GtkDialogOriginal); return Err(()); };
        let Some(owner) = call.owner() else { q.session_file_failed(R::GtkOwnerBinding); return Err(()); };
        if owner.id != id || !Arc::ptr_eq(&owner.gui, &call) { q.session_file_failed(R::GtkOwnerBinding); return Err(()); }
        if owner.interrupted() { q.session_file_failed(R::GtkOwnerInterrupted); return Err(()); }
        let original_facts = call.facts().is_some_and(|facts| facts.created && facts.showing && !facts.constructing
            && !facts.not_created && !facts.response && !facts.destroyed && !facts.released && facts.refusal.is_none());
        if !original_facts { q.session_file_failed(R::GtkOwnerFacts); return Err(()); }
        let (kind, select) = q.session_file_dialog(id, index)?;
        let title = match kind {
            "android-keystore" => "Choose an Android JKS keystore",
            "android-firebase" => "Choose Android Firebase JSON",
            _ => { q.session_file_failed(R::GtkDialogProperties); return Err(()); },
        };
        let Some(main) = app.get_webview_window(MAIN_WINDOW) else { q.session_file_failed(R::GtkDialogProperties); return Err(()); };
        let parent: gtk::Window = match main.gtk_window() {
            Ok(window) => window.upcast(),
            Err(_) => { q.session_file_failed(R::GtkDialogProperties); return Err(()); },
        };
        if dialog.title().as_deref() != Some(title) || !dialog.is_visible() || !dialog.is_modal()
            || dialog.transient_for().as_ref() != Some(&parent) || !dialog.property::<bool>("destroy-with-parent")
            || dialog.property::<gtk::FileChooserAction>("action") != gtk::FileChooserAction::Open
            || !dialog.property::<bool>("local-only") || dialog.property::<bool>("select-multiple") || dialog.property::<bool>("create-folders")
            || gtk::Settings::default().is_none_or(|settings| settings.is_gtk_recent_files_enabled()) { q.session_file_failed(R::GtkDialogProperties); return Err(()); }
        Ok(Some((id, dialog, select)))
    }

    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    pub(super) fn select_observed_session_file(app: &tauri::AppHandle, q: &Arc<installed_observation::Observation>, index: u8) -> Result<bool, ()> {
        use installed_observation::SessionRejection as R;
        let Some((id, dialog, select)) = observed_session_file(app, q, index, false)? else { return Ok(false); };
        if !select { q.session_file_failed(R::GtkSelectionState); return Err(()); }
        let Some(path) = q.session_file_target(index) else { q.session_file_failed(R::GtkSelectionState); return Err(()); };
        q.session_file_selection(id, index)?;
        // One setter on the real chooser, not a selection receipt. Its actual
        // accepted callback alone performs the original filename() transfer.
        if !dialog.set_filename(&path) { q.session_file_failed(R::GtkSelectionSetter); return Err(()); }
        Ok(true)
    }

    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    pub(super) fn activate_observed_session_file(app: &tauri::AppHandle, q: &Arc<installed_observation::Observation>, index: u8) -> Result<bool, ()> {
        use installed_observation::{SessionRejection as R, SessionWait as W};
        let Some((id, dialog, select)) = observed_session_file(app, q, index, true)? else { return Ok(false); };
        if select {
            let Some(path) = q.session_file_target(index) else { q.session_file_failed(R::GtkSelectionState); return Err(()); };
            // Observe only readiness on the original chooser. The accepted
            // production callback still owns the sole native_path transfer.
            let Some(file) = dialog.file() else {
                q.session_file_wait(index, true, W::GtkSelectionAbsent); return Ok(false);
            };
            if !file.equal(&gtk::gio::File::for_path(&path)) {
                q.session_file_wait(index, true, W::GtkSelectionDifferent); return Ok(false);
            }
        }
        let response = if select { gtk::ResponseType::Accept } else { gtk::ResponseType::Cancel };
        let button = match dialog.widget_for_response(response).and_then(|widget| widget.downcast::<gtk::Button>().ok()) {
            Some(button) => button,
            None => { q.session_file_failed(R::GtkResponseWidget); return Err(()); },
        };
        if !button.is_visible() || dialog.response_for_widget(&button) != response
            || button.label().as_deref() != Some(if select { "Select" } else { "Cancel" }) { q.session_file_failed(R::GtkActionWidget); return Err(()); }
        if !button.is_sensitive() { q.session_file_wait(index, true, W::GtkActionInsensitive); return Ok(false); }
        q.session_file_activation(id, index)?;
        // The existing GtkDialog handler emits the response. No direct
        // response/begin_response call or second filename read is permitted.
        button.emit_clicked(); Ok(true)
    }

    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    pub(super) fn activate_observed_quit(app: &tauri::AppHandle, q: &Arc<installed_observation::Observation>) -> Result<bool, ()> {
        if !gtk::is_initialized_main_thread() { return Err(()); }
        let original = DIALOG.with(|book| {
            let book = book.try_borrow().map_err(|_| ())?;
            let Some(entry) = book.as_ref() else { return Ok(None); };
            let Object::Message(dialog) = &entry.object else { return Err(()); };
            let (context, call) = entry.observation.as_ref().ok_or(())?;
            // Local refs to the already-owned original only. No GTK getter,
            // action, callback or observation lock under the object-book borrow.
            Ok(Some((entry.id, dialog.clone(), context.clone(), call.clone())))
        })?;
        let Some((id, dialog, context, call)) = original else { return Ok(false); };
        if !context.upgrade().is_some_and(|actual| Arc::ptr_eq(&actual, q)) { return Err(()); }
        let call = call.upgrade().ok_or(())?;
        let owner = call.owner().ok_or(())?;
        if owner.id != id || !Arc::ptr_eq(&owner.gui, &call) || owner.interrupted()
            || !call.facts().is_some_and(|facts| facts.created && facts.showing && !facts.constructing
                && !facts.not_created && !facts.response && !facts.destroyed && !facts.released && facts.refusal.is_none()) { return Err(()); }
        let main = app.get_webview_window(MAIN_WINDOW).ok_or(())?;
        let parent: gtk::Window = main.gtk_window().map_err(|_| ())?.upcast();
        if dialog.title().as_deref() != Some("Quit and discard unsaved drafts?")
            || !dialog.is_visible() || !dialog.is_modal()
            || dialog.transient_for().as_ref() != Some(&parent) { return Err(()); }
        let response = if q.quit_selects_ok(id)? { gtk::ResponseType::Ok } else { gtk::ResponseType::Cancel };
        let button = dialog.widget_for_response(response).ok_or(())?.downcast::<gtk::Button>().map_err(|_| ())?;
        if !button.is_visible() || !button.is_sensitive() || dialog.response_for_widget(&button) != response { return Err(()); }
        q.native_activation(id)?;
        // Activate the actual selected action widget. GtkDialog's original clicked
        // handler emits the response; never call response/begin_response here.
        button.emit_clicked();
        // These temporary GTK refs leave before the queued native close/release
        // continuation can run on this thread. Nothing is stored in the test.
        Ok(true)
    }

    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "development-runtime", target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    pub(super) mod topology {
        use super::*;
        use crate::shell::qualification::{Qualification, TopologyTags};
        type Check<T> = Result<T, &'static str>;
        fn need(ok: bool, reason: &'static str) -> Check<()> { if ok { Ok(()) } else { Err(reason) } }

        // Weak registrations only. Retired is a scalar tombstone, never a new
        // acquisition opportunity. No extra retained strong Gtk/Atk owner.
        struct MainMetadata {
            window: gtk::glib::WeakRef<gtk::Window>, accessible: gtk::glib::WeakRef<gtk::atk::Object>,
            context: Weak<Qualification>, id: String,
        }
        enum MainBook { Empty, Bound(MainMetadata), Retired }
        thread_local! { static MAIN: RefCell<MainBook> = const { RefCell::new(MainBook::Empty) }; }
        pub(super) struct DialogMetadata {
            accessible: gtk::glib::WeakRef<gtk::atk::Object>, call: Weak<GuiCall>,
            context: Weak<Qualification>, tags: TopologyTags,
        }

        // These data-only witnesses have no constructor outside this actual
        // original-object observer. Q cannot supply loose IDs/true in lieu of it.
        pub(in crate::shell) struct Tagged(TopologyTags);
        impl Tagged { pub(in crate::shell) fn into_tags(self) -> TopologyTags { self.0 } }
        pub(in crate::shell) struct Checked { tags: TopologyTags, at_ns: u64 }
        impl Checked { pub(in crate::shell) fn into_parts(self) -> (TopologyTags, u64) { (self.tags, self.at_ns) } }
        pub(in crate::shell) struct Retired { operation: u32, main_retired: bool }
        impl Retired { pub(in crate::shell) fn into_parts(self) -> (u32, bool) { (self.operation, self.main_retired) } }

        fn window(object: &Object) -> gtk::Window {
            match object { Object::File(d) => d.clone().upcast(), Object::Message(d) => d.clone().upcast() }
        }
        fn same_window(object: &Object, original: &gtk::Window) -> bool {
            match object { Object::File(d) => d.upcast_ref::<gtk::Window>() == original,
                Object::Message(d) => d.upcast_ref::<gtk::Window>() == original }
        }
        fn live(call: &Arc<GuiCall>, q: &Arc<Qualification>, n: u32, showing: bool) -> Check<()> {
            need(gtk::is_initialized_main_thread(), "sg1_topology_thread")?;
            let owner = call.owner().ok_or("sg1_topology_original_work")?;
            need(owner.id == n && Arc::ptr_eq(&owner.gui, call) && !owner.interrupted()
                && call.fixture_context().is_some_and(|actual| Arc::ptr_eq(&actual, q)), "sg1_topology_original_context")?;
            let facts = call.facts().ok_or("sg1_topology_facts")?;
            need(facts.created && !facts.constructing && facts.showing == showing && !facts.not_created
                && !facts.response && !facts.destroyed && !facts.released && !facts.close_queued
                && facts.refusal.is_none(), "sg1_topology_live_original")
        }
        fn id_is(accessible: &gtk::atk::Object, expected: Option<&str>) -> Check<()> {
            let property = accessible.find_property("accessible-id").ok_or("sg1_accessible_id_missing")?;
            let flags = property.flags();
            need(property.value_type() == gtk::glib::Type::STRING
                && flags.contains(gtk::glib::ParamFlags::READABLE | gtk::glib::ParamFlags::WRITABLE)
                && !flags.contains(gtk::glib::ParamFlags::CONSTRUCT_ONLY), "sg1_accessible_id_property")?;
            let value = accessible.property_value("accessible-id");
            let actual = value.get::<Option<&str>>().map_err(|_| "sg1_accessible_id_type")?;
            // Initial foreign IDs remain untouched; do not retain/copy their
            // arbitrary text. Exact readback bounds all subsequent scalar IDs.
            need(match expected { None => actual.is_none_or(str::is_empty),
                Some(id) => id.len() <= 80 && id.is_ascii() && actual == Some(id) }, "sg1_accessible_id_changed")
        }
        fn original_main(q: &Arc<Qualification>, tags: &TopologyTags, first: bool) -> Check<Option<(gtk::Window, gtk::atk::Object)>> {
            MAIN.with(|book| {
                let book = book.try_borrow().map_err(|_| "sg1_topology_main_borrow")?;
                match &*book {
                    MainBook::Empty if first => Ok(None),
                    MainBook::Bound(main) if !first => {
                        need(main.id == tags.main_id() && main.context.upgrade().is_some_and(|actual| Arc::ptr_eq(&actual, q)), "sg1_topology_main_context")?;
                        Ok(Some((main.window.upgrade().ok_or("sg1_topology_main_lost")?,
                            main.accessible.upgrade().ok_or("sg1_topology_main_accessible_lost")?)))
                    },
                    _ => Err("sg1_topology_main_reused"),
                }
            }) // Only local ref acquisition here; no GTK property/getter API under this borrow.
        }

        pub(super) fn tag(parent: &gtk::Window, call: &Arc<GuiCall>) {
            let Some(q) = call.fixture_context() else { return; }; // Ordinary run is untouched.
            let result: Check<Tagged> = (|| {
                let n = call.owner().ok_or("sg1_topology_original_work")?.id;
                live(call, &q, n, false)?;
                let tags = q.topology_begin(n)?;
                let observed = {
                    // Exactly one short local clone of the already-owned
                    // dialog lets ALL GTK property/getter calls run without
                    // DIALOG's RefCell borrow (notify callbacks can reenter).
                    let dialog = DIALOG.with(|book| {
                        let book = book.try_borrow().map_err(|_| "sg1_topology_dialog_borrow")?;
                        let entry = book.as_ref().filter(|e| e.id == n && e.topology.is_none()).ok_or("sg1_topology_dialog_original")?;
                        Ok::<_, &'static str>(window(&entry.object))
                    })?;
                    let prior = original_main(&q, &tags, n == 1)?;
                    let main_accessible = parent.accessible().ok_or("sg1_topology_main_accessible")?;
                    let dialog_accessible = dialog.accessible().ok_or("sg1_topology_dialog_accessible")?;
                    let transient = dialog.transient_for().ok_or("sg1_topology_no_transient")?;
                    need(transient == *parent && dialog != *parent && main_accessible != dialog_accessible, "sg1_topology_native_originals")?;
                    if let Some((original, accessible)) = &prior {
                        need(original == parent && accessible == &main_accessible, "sg1_topology_main_substituted")?;
                    }
                    id_is(&main_accessible, if n == 1 { None } else { Some(tags.main_id()) })?;
                    id_is(&dialog_accessible, None)?; // Check BOTH initial values before either write.
                    if n == 1 { main_accessible.set_property("accessible-id", tags.main_id()); }
                    dialog_accessible.set_property("accessible-id", tags.dialog_id());
                    id_is(&main_accessible, Some(tags.main_id()))?; id_is(&dialog_accessible, Some(tags.dialog_id()))?;
                    live(call, &q, n, false)?;
                    let metadata = DialogMetadata { accessible: dialog_accessible.downgrade(), call: Arc::downgrade(call),
                        context: Arc::downgrade(&q), tags: tags.clone() };
                    DIALOG.with(|book| {
                        let mut book = book.try_borrow_mut().map_err(|_| "sg1_topology_dialog_borrow")?;
                        let entry = book.as_mut().filter(|e| e.id == n && e.topology.is_none()).ok_or("sg1_topology_dialog_changed")?;
                        need(same_window(&entry.object, &dialog), "sg1_topology_dialog_substituted")?;
                        entry.topology = Some(metadata); Ok::<_, &'static str>(())
                    })?;
                    if n == 1 {
                        let metadata = MainMetadata { window: parent.downgrade(), accessible: main_accessible.downgrade(),
                            context: Arc::downgrade(&q), id: tags.main_id().to_owned() };
                        MAIN.with(|book| {
                            let mut book = book.try_borrow_mut().map_err(|_| "sg1_topology_main_borrow")?;
                            need(matches!(&*book, MainBook::Empty), "sg1_topology_main_reused")?;
                            *book = MainBook::Bound(metadata); Ok::<_, &'static str>(())
                        })?;
                    }
                    Tagged(tags)
                }; // Actually drop dialog clone, accessibles, transient and all upgraded refs BEFORE event.
                Ok(observed)
            })();
            if result.and_then(|observed| q.topology_tagged(observed)).is_err() { q.refuse(); }
            // A partial tag is NOT rolled back/retried. Real constructor,
            // response/STOP and disposal continue through their original paths.
        }

        pub(in crate::shell) fn inspect(weak: Weak<Qualification>, n: u32) {
            let Some(q) = weak.upgrade() else { return; };
            let result: Check<Checked> = (|| {
                q.topology_check_ready(n)?;
                let observed = {
                    let (dialog, original_accessible, call, context, tags) = DIALOG.with(|book| {
                        let book = book.try_borrow().map_err(|_| "sg1_topology_dialog_borrow")?;
                        let entry = book.as_ref().filter(|e| e.id == n).ok_or("sg1_topology_dialog_original")?;
                        let metadata = entry.topology.as_ref().ok_or("sg1_topology_untagged")?;
                        Ok::<_, &'static str>((window(&entry.object), metadata.accessible.upgrade().ok_or("sg1_topology_accessible_lost")?,
                            metadata.call.upgrade().ok_or("sg1_topology_call_lost")?, metadata.context.upgrade().ok_or("sg1_topology_context_lost")?,
                            metadata.tags.clone()))
                    })?;
                    need(tags.operation() == n && Arc::ptr_eq(&context, &q), "sg1_topology_check_context")?;
                    live(&call, &q, n, true)?;
                    let (main, original_main_accessible) = original_main(&q, &tags, false)?.ok_or("sg1_topology_main_missing")?;
                    let main_accessible = main.accessible().ok_or("sg1_topology_main_accessible")?;
                    let dialog_accessible = dialog.accessible().ok_or("sg1_topology_dialog_accessible")?;
                    let transient = dialog.transient_for().ok_or("sg1_topology_no_transient")?;
                    need(transient == main && dialog != main && main_accessible != dialog_accessible
                        && main_accessible == original_main_accessible && dialog_accessible == original_accessible, "sg1_topology_check_originals")?;
                    id_is(&main_accessible, Some(tags.main_id()))?; id_is(&dialog_accessible, Some(tags.dialog_id()))?;
                    live(&call, &q, n, true)?;
                    Checked { tags, at_ns: q.topology_clock()? }
                }; // No extra Gtk/Atk wrapper, Value or weak registration survives to completion publication.
                Ok(observed)
            })();
            if result.and_then(|observed| q.topology_checked(observed)).is_err() { q.refuse(); }
            // Successful completion publication is the final memory operation;
            // it is not a response-unwind/destroy/coordinator-join substitute.
        }

        pub(super) fn retire(call: &Arc<GuiCall>, n: u32, had_metadata: bool) {
            // Caller has ALREADY dropped the actual original NativeDialog,
            // including its weak accessible/call/context metadata, off-borrow.
            let Some(q) = call.fixture_context() else { return; };
            if !had_metadata || q.topology_retire_ready(n).is_err() { q.refuse(); }
            let result: Check<Retired> = (|| {
                need(gtk::is_initialized_main_thread(), "sg1_topology_retire_thread")?;
                let clear = n == 5 || q.topology_failed();
                let (removed, main_retired) = MAIN.with(|book| {
                    let mut book = book.try_borrow_mut().map_err(|_| "sg1_topology_main_borrow")?;
                    match &*book {
                        MainBook::Bound(main) => need(main.context.upgrade().is_some_and(|actual| Arc::ptr_eq(&actual, &q)), "sg1_topology_retire_context")?,
                        MainBook::Empty if q.topology_failed() => {},
                        _ => return Err("sg1_topology_retire_repeated"),
                    }
                    if clear {
                        let removed = match std::mem::replace(&mut *book, MainBook::Retired) { MainBook::Bound(main) => Some(main), _ => None };
                        Ok((removed, true))
                    } else { Ok((None, false)) }
                })?;
                drop(removed); // Really g_weak_ref_clear BOTH extracted main refs BEFORE Retired, not merely TLS=None.
                need(had_metadata, "sg1_topology_retire_untagged")?;
                Ok(Retired { operation: n, main_retired })
            })();
            if result.and_then(|observed| q.topology_retired(observed)).is_err() { q.refuse(); }
        }
    }

    pub(crate) async fn run_owned_dialog(app: &tauri::AppHandle, owner: &Arc<OriginalWork>, choice: DialogChoice, initial_folder: Option<PathBuf>) -> Result<Option<PathBuf>, Reason> {
        let call = owner.gui.clone();
        // Exactly this new purpose needs a native registration folder. Existing
        // File/Project/Evidence/Quit callers must continue to pass None.
        let folder_admitted = match (choice, initial_folder.as_deref()) {
            (DialogChoice::ProjectPath(_), Some(path)) => path.to_str().is_some() && crate::asset_source::path_hint(path).is_ok(),
            (DialogChoice::ProjectPath(_), None) | (_, Some(_)) => false,
            (_, None) => true,
        };
        if !folder_admitted { not_created(&call, Reason::SourceRefused); return Err(Reason::SourceRefused); }
        // Tauri run_on_main_thread is inline for a main-thread caller. Checking
        // here AND at both dispatch points is required for actual unwind proof.
        if gtk::is_initialized_main_thread() || !gtk::is_initialized() {
            not_created(&call, Reason::Unqualified); return Err(Reason::Unqualified);
        }
        let window = match app.get_webview_window(MAIN_WINDOW) {
            Some(window) => window, None => { not_created(&call, Reason::DocumentLost); return Err(Reason::DocumentLost); }
        };
        {
            let Some(mut facts) = call.facts() else { call.failed(Reason::CleanupUnknown); return Err(Reason::CleanupUnknown); };
            if facts.dispatched || facts.created { return Err(Reason::CleanupUnknown); }
            facts.dispatched = true;
        }
        gtk_fixture!(call, ConstructDispatch, 1);
        let construct_call = call.clone(); let construct_app = app.clone();
        if window.run_on_main_thread(move || construct(construct_app, construct_call, choice, initial_folder)).is_err() {
            // Scheduling failure is not positive not-created evidence. Keep the
            // original acquisition facts and coordinator, with no fallback.
            call.failed(Reason::CleanupUnknown);
        }
        loop {
            let (close, release, outcome) = {
                let Some(mut facts) = call.facts() else { call.failed(Reason::CleanupUnknown); return Err(Reason::CleanupUnknown); };
                let outcome = if facts.not_created { Some(Err(facts.refusal.unwrap_or(Reason::SourceRefused))) }
                    else if facts.destroyed && facts.released && facts.close_ack {
                        if matches!(choice, DialogChoice::Quit) { Some(Ok(None)) }
                        else if let Some(reason) = facts.refusal { Some(Err(reason)) }
                        else if matches!(choice, DialogChoice::ProjectPath(_)) && facts.declined && !facts.accepted { Some(Ok(None)) }
                        else if !facts.accepted || owner.interrupted() { Some(Err(Reason::UserCancelled)) }
                        else { Some(facts.selected.take().map(Some).ok_or(Reason::SourceRefused)) }
                    } else { None };
                let close = facts.created && (facts.response || facts.destroyed || owner.interrupted()) && !facts.close_queued;
                if close { facts.close_queued = true; }
                let release = facts.destroyed && facts.close_ack && !facts.release_queued;
                if release { facts.release_queued = true; }
                (close, release, outcome)
            };
            if let Some(outcome) = outcome { return outcome; }
            if close {
                if gtk::is_initialized_main_thread() { call.failed(Reason::CleanupUnknown); }
                else {
                    let call = call.clone(); let failure = call.clone(); let id = owner.id;
                    gtk_fixture!(call, CloseDispatch, 1);
                    if window.run_on_main_thread(move || close_after_response(call, id)).is_err() { failure.failed(Reason::CleanupUnknown); }
                }
            }
            if release {
                if gtk::is_initialized_main_thread() { call.failed(Reason::CleanupUnknown); }
                else {
                    let call = call.clone(); let failure = call.clone(); let id = owner.id;
                    gtk_fixture!(call, ReleaseDispatch, 1);
                    if window.run_on_main_thread(move || release_after_destroy(call, id)).is_err() { failure.failed(Reason::CleanupUnknown); }
                }
            }
            tokio::select! {
                _ = call.wake.notified() => {},
                _ = tokio::time::sleep(Duration::from_millis(25)) => {},
            }
        }
    }
}

#[derive(Debug)]
pub struct InitializationFailed;

pub fn run() -> Result<(), InitializationFailed> {
    // Installer is the only privileged entry. Do not even construct a native
    // window/document/project picker in a root or incompatible Mac process.
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    if mrk_macos_installed_native::real_user().is_err() { return Err(InitializationFailed); }
    run_builder(builder()).map(|_| ())
}

fn builder() -> tauri::Builder<tauri::Wry> {
    let builder = tauri::Builder::default();
    #[cfg(all(target_os = "windows", target_arch = "x86_64", target_env = "msvc"))]
    let windows_startup = owned_windows::startup();
    #[cfg(all(target_os = "windows", target_arch = "x86_64", target_env = "msvc"))]
    let builder = {
        // The same original is captured before any WebView exists; the protocol
        // cannot depend on a manager lookup during runtime construction.
        let original = windows_startup.clone();
        builder.register_asynchronous_uri_scheme_protocol(owned_windows::SCHEME, move |context, request, responder| {
            original.protocol(context.webview_label(), request, responder);
        })
    };
    #[cfg(target_os = "macos")]
    let builder = builder.on_web_content_process_terminate(|webview| {
        if webview.label() == MAIN_WINDOW {
            if let Some(state) = webview.try_state::<ShellState>() { state.document.lost(); }
        }
    });
    builder
        .menu(|app| {
            use tauri::menu::{Menu, MenuItem, Submenu};
            // A custom action, never the predefined Quit item: the existing
            // main-window CloseRequested path alone owns confirmation/cleanup.
            let quit = MenuItem::with_id(app, QUIT_MENU_ID, "Quit", true, Some("CmdOrCtrl+Q"))?;
            let file = Submenu::with_items(app, "File", true, &[&quit])?;
            Menu::with_items(app, &[&file])
        })
        .on_menu_event(|app, event| {
            if event.id().as_ref() != QUIT_MENU_ID { return; }
            if let Some(main) = app.get_webview_window(MAIN_WINDOW) {
                if main.label() == MAIN_WINDOW { let _ = main.close(); }
            }
        })
        .setup(move |app| {
            diagnostic(b"MRKDBG_DESKTOP_BOOTSTRAP=setup-enter\n");
            let resources = app.path().resource_dir()?;
            #[cfg(any(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64", feature = "macos-installed-observation", not(feature = "macos-installed-installer")))), all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "windows-installed-observation", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "windows-runtime-publisher"), not(feature = "macos-installed-installer"), target_os = "windows", target_arch = "x86_64", target_env = "msvc")))]
            let observation = app.try_state::<Arc<installed_observation::Observation>>().map(|q| q.inner().clone());
            #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
            let bridge = Arc::new(match &observation { Some(q) => q.build_bridge(resources)?, None => DesktopBridge::new(resources) });
            #[cfg(not(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu")))]
            let bridge = Arc::new(DesktopBridge::new(resources));
            #[cfg(any(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64", feature = "macos-installed-observation", not(feature = "macos-installed-installer")))), all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "windows-installed-observation", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "windows-runtime-publisher"), not(feature = "macos-installed-installer"), target_os = "windows", target_arch = "x86_64", target_env = "msvc")))]
            if let Some(q) = &observation { q.attach(&bridge.supervisor)?; }
            #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "development-runtime", target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
            let fixture = app.try_state::<Arc<qualification::Qualification>>().map(|q| q.inner().clone());
            #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "development-runtime", target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
            let document = if let Some(context) = &fixture {
                let state = app.state::<Mutex<Option<qualification::FixtureAdmission>>>();
                let permit = state.lock().map_err(|_| "SG1 permit lock poisoned")?.take().ok_or("SG1 permit missing")?;
                let document = DocumentBinding::for_fixture(bridge.clone(), permit)?;
                context.attach(bridge.clone())?; document
            } else { DocumentBinding::new(bridge.clone()) };
            #[cfg(not(all(test, debug_assertions, feature = "desktop-shell", feature = "development-runtime", target_os = "linux", target_arch = "x86_64", target_env = "gnu")))]
            let document = DocumentBinding::new(bridge.clone());
            #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
            if let Some(q) = &observation { q.attach_session(&document)?; q.attach_commands(&document)?; }
            let (relay_stop, stop_receiver) = watch::channel(false);
            app.manage(ShellState {
                #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "development-runtime", target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
                fixture: fixture.clone(),
                #[cfg(any(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64", feature = "macos-installed-observation", not(feature = "macos-installed-installer")))), all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "windows-installed-observation", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "windows-runtime-publisher"), not(feature = "macos-installed-installer"), target_os = "windows", target_arch = "x86_64", target_env = "msvc")))]
                observation: observation.clone(),
                bridge: bridge.clone(), document: document.clone(),
                #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))] picker: Arc::new(AtomicBool::new(false)),
                #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))] closing: AtomicBool::new(false),
                exit_ready: AtomicBool::new(false), relay_stop, relay: AsyncMutex::new(RelayBook { handle: None, settled: false }),
                #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))] exit_observer: Mutex::new(None),
            });
            #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "development-runtime", target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
            let navigation_fixture = fixture.clone();
            #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "development-runtime", target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
            let page_fixture = fixture.clone();
            #[cfg(any(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64", feature = "macos-installed-observation", not(feature = "macos-installed-installer")))), all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "windows-installed-observation", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "windows-runtime-publisher"), not(feature = "macos-installed-installer"), target_os = "windows", target_arch = "x86_64", target_env = "msvc")))]
            let page_observation = observation.clone();
            #[cfg(any(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64", feature = "macos-installed-observation", not(feature = "macos-installed-installer")))), all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "windows-installed-observation", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "windows-runtime-publisher"), not(feature = "macos-installed-installer"), target_os = "windows", target_arch = "x86_64", target_env = "msvc")))]
            let navigation_observation = observation.clone();
            #[cfg(not(all(target_os = "windows", target_arch = "x86_64", target_env = "msvc")))]
            let navigation = document.clone();
            #[cfg(not(all(target_os = "windows", target_arch = "x86_64", target_env = "msvc")))]
            let page = document.clone();
            #[cfg(all(target_os = "windows", target_arch = "x86_64", target_env = "msvc"))]
            let startup = windows_startup.clone();
            #[cfg(all(target_os = "windows", target_arch = "x86_64", target_env = "msvc"))]
            {
                startup.bind(document.clone())?;
                if !app.manage(startup.clone()) {
                    startup.unknown();
                    return Err("The original Windows startup could not be registered.".into());
                }
            }
            #[cfg(all(target_os = "windows", target_arch = "x86_64", target_env = "msvc"))]
            let navigation_windows = startup.clone();
            #[cfg(all(target_os = "windows", target_arch = "x86_64", target_env = "msvc"))]
            let page_windows = startup.clone();
            #[cfg(all(target_os = "windows", target_arch = "x86_64", target_env = "msvc"))]
            let initial_url = WebviewUrl::External(tauri::Url::parse(owned_windows::REQUEST_URI)?);
            #[cfg(not(all(target_os = "windows", target_arch = "x86_64", target_env = "msvc")))]
            let initial_url = WebviewUrl::App("index.html".into());
            let window = WebviewWindowBuilder::new(app, MAIN_WINDOW, initial_url)
                .title("Mobile Release Kit").inner_size(1280.0, 840.0).min_inner_size(920.0, 640.0)
                .on_navigation(move |url| {
                    let _trusted = trusted_document(url);
                    #[cfg(all(target_os = "windows", target_arch = "x86_64", target_env = "msvc"))]
                    let route = navigation_windows.navigation(url);
                    #[cfg(all(target_os = "windows", target_arch = "x86_64", target_env = "msvc"))]
                    let allowed = route != owned_windows::EventRoute::Rejected;
                    #[cfg(all(target_os = "windows", target_arch = "x86_64", target_env = "msvc"))]
                    let _observed = (route != owned_windows::EventRoute::Controlled,
                        _trusted && route != owned_windows::EventRoute::Rejected);
                    #[cfg(not(all(target_os = "windows", target_arch = "x86_64", target_env = "msvc")))]
                    let _observed = (true, _trusted);
                    #[cfg(not(all(target_os = "windows", target_arch = "x86_64", target_env = "msvc")))]
                    let allowed = navigation.navigation(_trusted);
                    #[cfg(any(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64", feature = "macos-installed-observation", not(feature = "macos-installed-installer")))), all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "windows-installed-observation", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "windows-runtime-publisher"), not(feature = "macos-installed-installer"), target_os = "windows", target_arch = "x86_64", target_env = "msvc")))]
                    if let Some(q) = &navigation_observation {
                        if _observed.0 { q.navigation(_observed.1, allowed); }
                    }
                    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "development-runtime", target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
                    if let Some(q) = &navigation_fixture { q.lifecycle(qualification::EventKind::Navigation, u32::from(_trusted && allowed)); }
                    allowed
                })
                .on_page_load(move |_webview, payload| {
                    let trusted = trusted_document(payload.url());
                    #[cfg(all(target_os = "windows", target_arch = "x86_64", target_env = "msvc"))]
                    let route = page_windows.page(&payload);
                    #[cfg(all(target_os = "windows", target_arch = "x86_64", target_env = "msvc"))]
                    let trusted = trusted && route != owned_windows::EventRoute::Rejected;
                    #[cfg(all(target_os = "windows", target_arch = "x86_64", target_env = "msvc"))]
                    let _observe = route != owned_windows::EventRoute::Controlled;
                    #[cfg(not(all(target_os = "windows", target_arch = "x86_64", target_env = "msvc")))]
                    let _observe = true;
                    #[cfg(target_os = "macos")]
                    if matches!(payload.event(), tauri::webview::PageLoadEvent::Started) {
                        // Wry's actual WK didCommitNavigation callback proves
                        // the delegate (including the selected termination
                        // hook) exists. build() Ok alone does not prove that.
                        page.hook_installed();
                    }
                    #[cfg(not(all(target_os = "windows", target_arch = "x86_64", target_env = "msvc")))]
                    page.observe(|lifetime| match payload.event() {
                        tauri::webview::PageLoadEvent::Started => lifetime.started(trusted),
                        tauri::webview::PageLoadEvent::Finished => lifetime.finished(trusted),
                    });
                    // Diagnostic-only, after the original transition and
                    // outside observe's document lock. Never disclose a URL.
                    diagnostic(match (payload.event(), trusted) {
                        (tauri::webview::PageLoadEvent::Started, true) => b"MRKDBG_DESKTOP_BOOTSTRAP=page-start-trusted\n",
                        (tauri::webview::PageLoadEvent::Started, false) => b"MRKDBG_DESKTOP_BOOTSTRAP=page-start-untrusted\n",
                        (tauri::webview::PageLoadEvent::Finished, true) => b"MRKDBG_DESKTOP_BOOTSTRAP=page-finish-trusted\n",
                        (tauri::webview::PageLoadEvent::Finished, false) => b"MRKDBG_DESKTOP_BOOTSTRAP=page-finish-untrusted\n",
                    });
                    #[cfg(any(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64", feature = "macos-installed-observation", not(feature = "macos-installed-installer")))), all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "windows-installed-observation", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "windows-runtime-publisher"), not(feature = "macos-installed-installer"), target_os = "windows", target_arch = "x86_64", target_env = "msvc")))]
                    if let Some(q) = &page_observation {
                        if _observe {
                            q.page_load(trusted, matches!(payload.event(), tauri::webview::PageLoadEvent::Finished));
                        }
                    }
                    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "development-runtime", target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
                    if let Some(q) = &page_fixture { q.lifecycle(match payload.event() {
                        tauri::webview::PageLoadEvent::Started => qualification::EventKind::LoadStarted,
                        tauri::webview::PageLoadEvent::Finished => qualification::EventKind::LoadFinished,
                    }, u32::from(trusted)); }
                })
                .on_new_window(|_, _| tauri::webview::NewWindowResponse::Deny);
            #[cfg(all(target_os = "windows", target_arch = "x86_64", target_env = "msvc"))]
            let window = window.data_directory(startup.user_data()?.to_path_buf())
                // Fixed normal profile: no caller/config browser arguments or
                // extensions, and no Wry default SmartScreen-disable switch.
                .additional_browser_args("").browser_extensions_enabled(false);
            #[cfg(all(target_os = "windows", target_arch = "x86_64", target_env = "msvc"))]
            owned_windows::before_webview(&startup)?;
            let window = window.build()?;
            #[cfg(all(target_os = "windows", target_arch = "x86_64", target_env = "msvc"))]
            owned_windows::install(&window, startup);
            #[cfg(target_os = "linux")]
            {
                use webkit2gtk::WebViewExt;
                let install = document.clone();
                #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "development-runtime", target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
                let install_fixture = fixture.clone();
                // This may run inline, so hold no lifetime/owner lock across
                // with_webview. Outer Ok only means the callback was scheduled.
                if window.with_webview(move |platform| {
                    let terminated = install.clone();
                    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "development-runtime", target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
                    let terminated_fixture = install_fixture.clone();
                    let _signal_id = platform.inner().connect_web_process_terminated(move |_, reason| {
                        terminated.lost();
                        diagnostic(b"MRKDBG_DESKTOP_BOOTSTRAP=content-terminated\n");
                        diagnostic(match reason {
                            webkit2gtk::WebProcessTerminationReason::Crashed => b"MRKDBG_DESKTOP_BOOTSTRAP=content-reason-crashed\n",
                            webkit2gtk::WebProcessTerminationReason::ExceededMemoryLimit => b"MRKDBG_DESKTOP_BOOTSTRAP=content-reason-exceeded-memory-limit\n",
                            webkit2gtk::WebProcessTerminationReason::TerminatedByApi => b"MRKDBG_DESKTOP_BOOTSTRAP=content-reason-terminated-by-api\n",
                            _ => b"MRKDBG_DESKTOP_BOOTSTRAP=content-reason-unknown\n",
                        });
                        #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "development-runtime", target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
                        if let Some(q) = &terminated_fixture { q.lifecycle(qualification::EventKind::DocumentLost, 0); }
                    });
                    // GLib retains the handler with the original webview. All
                    // termination reasons invalidate; the ID is not a lease.
                    install.hook_installed();
                    diagnostic(b"MRKDBG_DESKTOP_BOOTSTRAP=hook-installed\n");
                    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "development-runtime", target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
                    if let Some(q) = &install_fixture { q.lifecycle(qualification::EventKind::HookInstalled, 1); }
                }).is_err() { document.lost(); }
            }
            #[cfg(not(any(target_os = "linux", all(target_os = "windows", target_arch = "x86_64", target_env = "msvc"))))]
            { let _ = window; }
            let state = app.state::<ShellState>();
            // Setup is synchronous and these fresh slots cannot be contended.
            // Both observer bodies wait behind barriers until their ORIGINAL
            // handles have been stored in the application, not an invoke.
            let mut book = state.relay.try_lock().map_err(|_| "The original event relay could not be retained.")?;
            let (handle, start) = start_relay(app.handle().clone(), bridge.edits.clone(), document.clone(), stop_receiver);
            book.handle = Some(handle); drop(book);
            let _ = start.send(());
            #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
            {
                let mut book = state.exit_observer.lock().map_err(|_| "The original exit observer could not be retained.")?;
                let (handle, start) = start_exit_observer(app.handle().clone(), document);
                *book = Some(handle); drop(book);
                let _ = start.send(());
            }
            #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "development-runtime", target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
            if let Some(context) = &fixture { context.start(app.handle().clone())?; }
            Ok(())
        })
        .invoke_handler(|invoke: tauri::ipc::Invoke<tauri::Wry>| {
            #[cfg(all(target_os = "windows", target_arch = "x86_64", target_env = "msvc"))]
            {
                let webview = invoke.message.webview_ref();
                let allowed = webview.label() == MAIN_WINDOW
                    && webview.try_state::<Arc<owned_windows::Startup>>().is_some_and(|startup| startup.first_party_phase())
                    && webview.url().is_ok_and(|url| trusted_document(&url));
                if !allowed {
                    // Additional first-party refusal only: current URL is not
                    // historical request-origin proof, and this generated
                    // handler does not intercept supplier listen/unlisten IPC.
                    invoke.resolver.reject(BridgeError::new("startup_document_unavailable",
                        "The original packaged application document is not available."));
                    return true;
                }
            }
            let handler: fn(tauri::ipc::Invoke<tauri::Wry>) -> bool =
                tauri::generate_handler![
            app_info, choose_project, choose_project_path, project_snapshot, catalog, environment_requirements, release_version_observe,
            artifact_evidence_choose, artifact_evidence_status, artifact_evidence_observe, artifact_evidence_cancel,
            start_environment_diagnostics, environment_diagnostics_status, cancel_environment_diagnostics,
            prepare_offline_preflight, start_offline_preflight, offline_preflight_status, cancel_offline_preflight,
            prepare_android_build, start_android_build, android_build_status, cancel_android_build,
            validate_config, suggest_config, preview_config,
            propose_github_setup,
            open_config_edit, prepare_config_edit, apply_config_edit, close_config_edit, config_edit_status,
            github_workflow_edit_open, github_workflow_edit_prepare, github_workflow_edit_apply,
            github_workflow_edit_close, github_workflow_edit_status,
            metadata_text_observe, metadata_text_validate, metadata_text_edit_open, metadata_text_edit_prepare,
            metadata_text_edit_apply, metadata_text_edit_close, metadata_text_edit_status,
            release_version_edit_open, release_version_edit_prepare, release_version_edit_apply,
            release_version_edit_close, release_version_edit_status,
            github_connection_status, github_connection_connect_token, github_connection_refresh, github_connection_disconnect,
            vault_status, vault_open, asset_context, asset_choose, credential_prepare,
            vault_prepare_delete, vault_commit, vault_bind, vault_discard, vault_lock,
            ];
            handler(invoke)
        })
        .on_window_event(|window, event| {
            if window.label() != MAIN_WINDOW { return; }
            #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "macos-installed-observation", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer"), target_os = "macos", target_arch = "aarch64"))]
            if !matches!(event, tauri::WindowEvent::Destroyed | tauri::WindowEvent::CloseRequested { .. }) {
                // Tauri supplies its captured ORIGINAL Window here. The label
                // only routes; missing pre-setup observer state remains inert.
                if let Some(state) = window.try_state::<ShellState>() {
                    if let Some(q) = &state.observation { q.observe_original_window(window); }
                }
            }
            if let tauri::WindowEvent::Destroyed = event {
                #[cfg(all(target_os = "windows", target_arch = "x86_64", target_env = "msvc"))]
                if let Some(startup) = window.try_state::<Arc<owned_windows::Startup>>() { startup.destroyed(); }
                if let Some(state) = window.try_state::<ShellState>() {
                    state.document.lost();
                    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "development-runtime", target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
                    if let Some(q) = &state.fixture { q.lifecycle(qualification::EventKind::DocumentLost, 0); }
                }
            }
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                let state = window.state::<ShellState>();
                if state.exit_ready.load(Ordering::SeqCst) { return; }
                api.prevent_close();
                #[cfg(any(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64", feature = "macos-installed-observation", not(feature = "macos-installed-installer")))), all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "windows-installed-observation", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "windows-runtime-publisher"), not(feature = "macos-installed-installer"), target_os = "windows", target_arch = "x86_64", target_env = "msvc")))]
                if let Some(q) = &state.observation { q.close_prevented(); }
                #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "development-runtime", target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
                if let Some(q) = &state.fixture { if !q.close_prevented() { return; } }
                request_shutdown(window.app_handle());
            }
        })
}

#[cfg(any(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64", feature = "macos-installed-observation", not(feature = "macos-installed-installer")))), all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "windows-installed-observation", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "windows-runtime-publisher"), not(feature = "macos-installed-installer"), target_os = "windows", target_arch = "x86_64", target_env = "msvc")))]
type LoopReturn = i32;
#[cfg(not(any(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64", feature = "macos-installed-observation", not(feature = "macos-installed-installer")))), all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "windows-installed-observation", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "windows-runtime-publisher"), not(feature = "macos-installed-installer"), target_os = "windows", target_arch = "x86_64", target_env = "msvc"))))]
type LoopReturn = ();

fn run_builder(builder: tauri::Builder<tauri::Wry>) -> Result<LoopReturn, InitializationFailed> {
    let context = tauri::generate_context!();
    #[cfg(target_os = "windows")]
    if !context.config().app.windows.is_empty()
        || !crate::runtime::RuntimeConfig::packaged(std::path::PathBuf::new()).project_selection_profile_available() {
        diagnostic(b"The Windows shell requires its packaged normal profile and explicit pre-WebView admission.\n");
        return Err(InitializationFailed);
    }
    #[cfg(all(target_os = "windows", target_arch = "x86_64", target_env = "msvc"))]
    owned_windows::prepare()?;
    let application = builder.build(context);
    let application = match application {
        Ok(application) => application,
        Err(_) => {
            #[cfg(all(target_os = "windows", target_arch = "x86_64", target_env = "msvc"))]
            owned_windows::build_failed();
            diagnostic(b"The native desktop application could not initialize.\n"); return Err(InitializationFailed);
        }
    };
    let callback = |app: &tauri::AppHandle, event: tauri::RunEvent| {
        #[cfg(any(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64", feature = "macos-installed-observation", not(feature = "macos-installed-installer")))), all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "windows-installed-observation", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "windows-runtime-publisher"), not(feature = "macos-installed-installer"), target_os = "windows", target_arch = "x86_64", target_env = "msvc")))]
        if matches!(event, tauri::RunEvent::Exit) {
            let state = app.state::<ShellState>();
            if let Some(q) = &state.observation { q.actual_exit(state.exit_ready.load(Ordering::SeqCst), &state.document, &state.bridge.edits); }
        }
        #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "development-runtime", target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
        if matches!(event, tauri::RunEvent::Exit) {
            let state = app.state::<ShellState>();
            if let Some(q) = &state.fixture { q.actual_exit(state.exit_ready.load(Ordering::SeqCst)); }
        }
        if let tauri::RunEvent::ExitRequested { api, .. } = event {
            let state = app.state::<ShellState>();
            if state.exit_ready.load(Ordering::SeqCst) { return; }
            api.prevent_exit();
            #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "development-runtime", target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
            if let Some(q) = &state.fixture { q.refuse(); return; }
            request_shutdown(app);
        }
    };
    // Same event callback and original shutdown owner in either case. App::run
    // exits the process itself; only this test needs control after the actual
    // loop cleanup to join/inspect its retained original and report evidence.
    #[cfg(any(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64", feature = "macos-installed-observation", not(feature = "macos-installed-installer")))), all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "windows-installed-observation", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "windows-runtime-publisher"), not(feature = "macos-installed-installer"), target_os = "windows", target_arch = "x86_64", target_env = "msvc")))]
    { Ok(application.run_return(callback)) }
    #[cfg(not(any(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64", feature = "macos-installed-observation", not(feature = "macos-installed-installer")))), all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "windows-installed-observation", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "windows-runtime-publisher"), not(feature = "macos-installed-installer"), target_os = "windows", target_arch = "x86_64", target_env = "msvc"))))]
    { application.run(callback); Ok(()) }
}
