use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use serde_json::Value;
use tauri::{Manager, State, WebviewUrl, WebviewWindowBuilder};
use crate::{bridge::{AppInfo, DesktopBridge, Project}, error::BridgeError};

struct ShellState { bridge: Arc<DesktopBridge>, picker: Arc<AtomicBool>, closing: AtomicBool }

#[tauri::command]
async fn app_info(state: State<'_, ShellState>) -> AppInfo { state.bridge.app_info().await }
#[tauri::command]
async fn catalog(state: State<'_, ShellState>) -> Result<Value, BridgeError> { state.bridge.catalog().await }
#[tauri::command(rename_all = "camelCase")]
async fn project_snapshot(project_id: String, state: State<'_, ShellState>) -> Result<Value, BridgeError> {
    state.bridge.project_snapshot(project_id).await
}
#[tauri::command]
async fn validate_config(draft: Value, state: State<'_, ShellState>) -> Result<Value, BridgeError> { state.bridge.validate_config(draft).await }
#[tauri::command]
async fn suggest_config(hints: Value, state: State<'_, ShellState>) -> Result<Value, BridgeError> { state.bridge.suggest_config(hints).await }
#[tauri::command]
async fn preview_config(base: Value, draft: Value, state: State<'_, ShellState>) -> Result<Value, BridgeError> { state.bridge.preview_config(base, draft).await }

struct PickerGuard(Arc<AtomicBool>);
impl Drop for PickerGuard { fn drop(&mut self) { self.0.store(false, Ordering::SeqCst); } }
#[tauri::command]
async fn choose_project(state: State<'_, ShellState>) -> Result<Option<Project>, BridgeError> {
    if state.closing.load(Ordering::SeqCst) {
        return Err(BridgeError::new("quit_pending", "Finish or cancel the quit confirmation before selecting another project."));
    }
    if state.bridge.supervisor.stopping() { return Err(BridgeError::shutdown()); }
    if state.picker.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).is_err() {
        return Err(BridgeError::new("busy", "A native project picker is already open."));
    }
    let guard = PickerGuard(state.picker.clone());
    if state.closing.load(Ordering::SeqCst) {
        return Err(BridgeError::new("quit_pending", "Finish or cancel the quit confirmation before selecting another project."));
    }
    let bridge = state.bridge.clone();
    // A renderer going away cannot abandon the Rust picker/selection owner.
    tauri::async_runtime::spawn(async move {
        let _guard = guard;
        match rfd::AsyncFileDialog::new().set_title("Choose a mobile project folder").pick_folder().await {
            None => Ok(None),
            Some(folder) => bridge.register_picked_project(folder.path().to_path_buf()).map(Some),
        }
    }).await.map_err(|_| BridgeError::new("picker_failed", "The native project picker did not settle normally."))?
}

fn allowed_navigation(url: &tauri::Url) -> bool {
    url.username().is_empty() && url.password().is_none() && url.port().is_none()
        && ((url.scheme() == "tauri" && url.host_str() == Some("localhost"))
            || (url.scheme() == "http" && url.host_str() == Some("tauri.localhost")))
}

fn request_shutdown(app: &tauri::AppHandle) {
    let state = app.state::<ShellState>();
    // A native picker has no safe cancellation primitive in this foundation.
    // Keep its window/event-loop owner until the user selects or cancels it.
    if state.picker.load(Ordering::SeqCst) { return; }
    if state.closing.swap(true, Ordering::SeqCst) { return; }
    if state.picker.load(Ordering::SeqCst) {
        state.closing.store(false, Ordering::SeqCst);
        return;
    }
    let bridge = state.bridge.clone();
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        // Foundation drafts exist only in renderer memory. Confirm natively
        // before stopping any owner; a beforeunload hint is not sufficient.
        let choice = rfd::AsyncMessageDialog::new()
            .set_title("Quit and discard in-memory drafts?")
            .set_description("This foundation does not save configuration drafts. Closing the application discards all in-memory project drafts. Choose Cancel to keep editing, or OK to stop owned queries and quit.")
            .set_buttons(rfd::MessageButtons::OkCancel)
            .set_level(rfd::MessageLevel::Warning)
            .show().await;
        if !matches!(choice, rfd::MessageDialogResult::Ok) {
            app.state::<ShellState>().closing.store(false, Ordering::SeqCst);
            return;
        }
        match bridge.supervisor.shutdown().await {
            Ok(()) => app.exit(0),
            Err(_) => {
                let _ = rfd::AsyncMessageDialog::new().set_title("Query cleanup is unconfirmed")
                    .set_description("The original query owner is retained and further queries are disabled. This window remains open because safe shutdown has not been confirmed.")
                    .set_level(rfd::MessageLevel::Error).show().await;
            }
        }
    });
}

pub fn run() {
    let application = tauri::Builder::default()
        .setup(|app| {
            let resources = app.path().resource_dir()?;
            app.manage(ShellState { bridge: Arc::new(DesktopBridge::new(resources)), picker: Arc::new(AtomicBool::new(false)), closing: AtomicBool::new(false) });
            WebviewWindowBuilder::new(app, "main", WebviewUrl::App("index.html".into()))
                .title("Mobile Release Kit").inner_size(1280.0, 840.0).min_inner_size(920.0, 640.0)
                .on_navigation(allowed_navigation)
                .on_new_window(|_, _| tauri::webview::NewWindowResponse::Deny)
                .build()?;
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![app_info, choose_project, project_snapshot, catalog, validate_config, suggest_config, preview_config])
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                let state = window.state::<ShellState>();
                if state.picker.load(Ordering::SeqCst) { api.prevent_close(); return; }
                if state.bridge.supervisor.stopping() && state.bridge.supervisor.can_exit() { return; }
                api.prevent_close();
                request_shutdown(window.app_handle());
            }
        })
        .build(tauri::generate_context!());
    let application = match application {
        Ok(application) => application,
        Err(_) => { eprintln!("The native desktop foundation could not initialize."); return; }
    };
    application.run(|app, event| {
        if let tauri::RunEvent::ExitRequested { api, .. } = event {
            let state = app.state::<ShellState>();
            if state.picker.load(Ordering::SeqCst) { api.prevent_exit(); return; }
            if state.bridge.supervisor.stopping() && state.bridge.supervisor.can_exit() { return; }
            api.prevent_exit();
            request_shutdown(app);
        }
    });
}
