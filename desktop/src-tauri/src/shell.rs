use std::sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}};
use serde_json::Value;
use tauri::{Emitter, Manager, State, Webview, WebviewUrl, WebviewWindowBuilder};
use tokio::sync::watch;
use crate::{
    bridge::{AppInfo, DesktopBridge, Project},
    document_lifetime::{DocumentAction, DocumentLifetime},
    edit_commands, edit_owner::EditOwner, edit_protocol::ConfigEditStatus,
    error::BridgeError,
};

const MAIN_WINDOW: &str = "main";
const EDIT_EVENT: &str = "config-edit-state";

/// Startup observations feed the edit registry synchronously. The registry,
/// not this mutex or a renderer token, linearizes invalidation with admission.
#[derive(Clone)]
struct DocumentBinding { lifetime: Arc<Mutex<DocumentLifetime>>, edits: EditOwner }
impl DocumentBinding {
    fn new(edits: EditOwner) -> Self { Self { lifetime: Arc::new(Mutex::new(DocumentLifetime::default())), edits } }
    fn apply(&self, lifetime: &mut DocumentLifetime, action: DocumentAction) {
        match action {
            DocumentAction::Bind => {
                if self.edits.initial_document(MAIN_WINDOW).is_err() {
                    lifetime.invalidate();
                    self.edits.document_lost(MAIN_WINDOW);
                }
            }
            DocumentAction::Lost => self.edits.document_lost(MAIN_WINDOW),
            DocumentAction::None => {},
        }
    }
    fn observe(&self, event: impl FnOnce(&mut DocumentLifetime) -> DocumentAction) {
        match self.lifetime.lock() {
            Ok(mut lifetime) => {
                let action = event(&mut lifetime);
                self.apply(&mut lifetime, action);
            }
            Err(_) => self.edits.document_lost(MAIN_WINDOW),
        }
    }
    fn navigation(&self, trusted: bool) -> bool {
        match self.lifetime.lock() {
            Ok(mut lifetime) => {
                let (allowed, action) = lifetime.navigation(trusted);
                self.apply(&mut lifetime, action);
                allowed
            }
            Err(_) => { self.edits.document_lost(MAIN_WINDOW); false }
        }
    }
    fn lost(&self) { self.observe(DocumentLifetime::invalidate); }
    fn hook_installed(&self) { self.observe(DocumentLifetime::crash_hook_installed); }
}

struct ShellState {
    bridge: Arc<DesktopBridge>, document: DocumentBinding,
    picker: Arc<AtomicBool>, closing: AtomicBool, exit_ready: AtomicBool,
    relay_stop: watch::Sender<bool>,
    relay: Mutex<Option<tauri::async_runtime::JoinHandle<()>>>,
}

#[tauri::command]
async fn app_info(state: State<'_, ShellState>) -> Result<AppInfo, BridgeError> { Ok(state.bridge.app_info().await) }
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
fn not_closing(state: &ShellState) -> Result<(), BridgeError> {
    if state.closing.load(Ordering::SeqCst) {
        return Err(BridgeError::new("quit_pending", "Finish or cancel the quit confirmation before starting another action."));
    }
    Ok(())
}

// Async Tauri entrypoints enter the application runtime, but admission itself
// is synchronous. No invoke future owns the registered operation's lifetime.
// No renderer-receipt acknowledgment is claimed or required.
#[tauri::command]
async fn open_config_edit(webview: Webview, request: tauri::ipc::Request<'_>, state: State<'_, ShellState>) -> Result<ConfigEditStatus, BridgeError> {
    let window = edit_window(&webview)?;
    let args = edit_commands::open(request_body(&request)?)?;
    not_closing(&state)?;
    state.bridge.open_config_edit(window, args.project_id)
}
#[tauri::command]
async fn prepare_config_edit(webview: Webview, request: tauri::ipc::Request<'_>, state: State<'_, ShellState>) -> Result<ConfigEditStatus, BridgeError> {
    let window = edit_window(&webview)?;
    let args = edit_commands::prepare(request_body(&request)?)?;
    not_closing(&state)?;
    state.bridge.edits.prepare(window, args)
}
#[tauri::command]
async fn apply_config_edit(webview: Webview, request: tauri::ipc::Request<'_>, state: State<'_, ShellState>) -> Result<ConfigEditStatus, BridgeError> {
    let window = edit_window(&webview)?;
    let args = edit_commands::apply(request_body(&request)?)?;
    not_closing(&state)?;
    state.bridge.edits.apply(window, &args.session_id, &args.plan_token)
}
#[tauri::command]
async fn close_config_edit(webview: Webview, request: tauri::ipc::Request<'_>, state: State<'_, ShellState>) -> Result<ConfigEditStatus, BridgeError> {
    let window = edit_window(&webview)?;
    let args = edit_commands::close(request_body(&request)?)?;
    // The original document may stop during quit. Document loss already sends
    // STOP from native lifecycle handling; later renderers have status only.
    state.bridge.edits.close(window, &args.session_id)
}
#[tauri::command]
async fn config_edit_status(webview: Webview, request: tauri::ipc::Request<'_>, state: State<'_, ShellState>) -> Result<ConfigEditStatus, BridgeError> {
    edit_window(&webview)?;
    edit_commands::status(request_body(&request)?)?;
    state.bridge.edits.status()
}

struct PickerGuard(Arc<AtomicBool>);
impl Drop for PickerGuard { fn drop(&mut self) { self.0.store(false, Ordering::SeqCst); } }
#[tauri::command]
async fn choose_project(state: State<'_, ShellState>) -> Result<Option<Project>, BridgeError> {
    not_closing(&state)?;
    if state.bridge.supervisor.stopping() || state.bridge.edits.stopping() { return Err(BridgeError::shutdown()); }
    if state.picker.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).is_err() {
        return Err(BridgeError::new("busy", "A native project picker is already open."));
    }
    let guard = PickerGuard(state.picker.clone());
    not_closing(&state)?;
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

fn start_relay(app: tauri::AppHandle, edits: EditOwner, mut stop: watch::Receiver<bool>) -> tauri::async_runtime::JoinHandle<()> {
    let mut revisions = edits.subscribe();
    tauri::async_runtime::spawn(async move {
        loop {
            if *stop.borrow() { return; }
            // status() releases its native locks before any renderer callback.
            // Events are best effort: the UI subscribes then fetches status and
            // orders both by native revision, never by arrival time.
            if let Ok(status) = edits.status() { let _ = app.emit_to(MAIN_WINDOW, EDIT_EVENT, &status); }
            tokio::select! {
                biased;
                result = stop.changed() => { if result.is_err() || *stop.borrow() { return; } },
                result = revisions.changed() => { if result.is_err() { return; } },
            }
        }
    })
}

async fn settle_relay(app: &tauri::AppHandle) {
    let handle = {
        let state = app.state::<ShellState>();
        state.relay_stop.send_replace(true);
        // No user callback or await holds this slot's short lock. Even an
        // errored Join result positively settles this data-only observer task;
        // it cannot change the independently established core/child result.
        let mut slot = state.relay.lock().unwrap_or_else(|error| error.into_inner());
        slot.take()
    };
    if let Some(handle) = handle { let _ = handle.await; }
}

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
            app.state::<ShellState>().closing.store(false, Ordering::SeqCst);
            return;
        }
        // Request both owners' shutdown and await both results. A failure in
        // one must not skip stopping/settling the other's original resources.
        let (passive, edit) = tokio::join!(bridge.supervisor.shutdown(), bridge.edits.shutdown());
        if passive.is_ok() && edit.is_ok() && bridge.supervisor.can_exit() && bridge.edits.can_exit() {
            settle_relay(&app).await;
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

pub fn run() {
    let builder = tauri::Builder::default();
    #[cfg(target_os = "macos")]
    let builder = builder.on_web_content_process_terminate(|webview| {
        if webview.label() == MAIN_WINDOW {
            if let Some(state) = webview.try_state::<ShellState>() { state.document.lost(); }
        }
    });
    let application = builder
        .setup(|app| {
            let resources = app.path().resource_dir()?;
            let bridge = Arc::new(DesktopBridge::new(resources));
            let document = DocumentBinding::new(bridge.edits.clone());
            let (relay_stop, stop_receiver) = watch::channel(false);
            app.manage(ShellState {
                bridge: bridge.clone(), document: document.clone(), picker: Arc::new(AtomicBool::new(false)),
                closing: AtomicBool::new(false), exit_ready: AtomicBool::new(false), relay_stop, relay: Mutex::new(None),
            });
            let navigation = document.clone();
            let page = document.clone();
            let window = WebviewWindowBuilder::new(app, MAIN_WINDOW, WebviewUrl::App("index.html".into()))
                .title("Mobile Release Kit").inner_size(1280.0, 840.0).min_inner_size(920.0, 640.0)
                .on_navigation(move |url| navigation.navigation(trusted_document(url)))
                .on_page_load(move |_, payload| {
                    let trusted = trusted_document(payload.url());
                    #[cfg(target_os = "macos")]
                    if matches!(payload.event(), tauri::webview::PageLoadEvent::Started) {
                        // Wry's actual WK didCommitNavigation callback proves
                        // the delegate (including the selected termination
                        // hook) exists. build() Ok alone does not prove that.
                        page.hook_installed();
                    }
                    page.observe(|lifetime| match payload.event() {
                        tauri::webview::PageLoadEvent::Started => lifetime.started(trusted),
                        tauri::webview::PageLoadEvent::Finished => lifetime.finished(trusted),
                    });
                })
                .on_new_window(|_, _| tauri::webview::NewWindowResponse::Deny)
                .build()?;
            #[cfg(target_os = "linux")]
            {
                use webkit2gtk::WebViewExt;
                let install = document.clone();
                // This may run inline, so hold no lifetime/owner lock across
                // with_webview. Outer Ok only means the callback was scheduled.
                if window.with_webview(move |platform| {
                    let terminated = install.clone();
                    let _signal_id = platform.inner().connect_web_process_terminated(move |_, _| terminated.lost());
                    // GLib retains the handler with the original webview. All
                    // termination reasons invalidate; the ID is not a lease.
                    install.hook_installed();
                }).is_err() { document.lost(); }
            }
            #[cfg(not(target_os = "linux"))]
            { let _ = window; /* Windows has no qualified crash/filesystem backend: never bind editing. */ }
            let handle = start_relay(app.handle().clone(), bridge.edits.clone(), stop_receiver);
            let state = app.state::<ShellState>();
            *state.relay.lock().unwrap_or_else(|error| error.into_inner()) = Some(handle);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            app_info, choose_project, project_snapshot, catalog, validate_config, suggest_config, preview_config,
            open_config_edit, prepare_config_edit, apply_config_edit, close_config_edit, config_edit_status,
        ])
        .on_window_event(|window, event| {
            if window.label() != MAIN_WINDOW { return; }
            if let tauri::WindowEvent::Destroyed = event {
                if let Some(state) = window.try_state::<ShellState>() { state.document.lost(); }
            }
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                let state = window.state::<ShellState>();
                if state.exit_ready.load(Ordering::SeqCst) { return; }
                api.prevent_close();
                request_shutdown(window.app_handle());
            }
        })
        .build(tauri::generate_context!());
    let application = match application {
        Ok(application) => application,
        Err(_) => { eprintln!("The native desktop application could not initialize."); return; }
    };
    application.run(|app, event| {
        if let tauri::RunEvent::ExitRequested { api, .. } = event {
            let state = app.state::<ShellState>();
            if state.exit_ready.load(Ordering::SeqCst) { return; }
            api.prevent_exit();
            request_shutdown(app);
        }
    });
}
