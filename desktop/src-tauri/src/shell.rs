use std::{sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}}, time::Duration};
use serde_json::Value;
use tauri::{Emitter, Manager, State, Webview, WebviewUrl, WebviewWindowBuilder};
use tokio::sync::{watch, oneshot, Mutex as AsyncMutex};
use crate::{
    asset_commands::{self, AssetError, CommandError, Reason},
    asset_session::{AssetStatus, DocumentBinding, NativeResponse, OriginalWork},
    bridge::{AppInfo, DesktopBridge, Project},
    edit_commands, edit_owner::EditOwner, edit_protocol::ConfigEditStatus,
    error::BridgeError,
};

const MAIN_WINDOW: &str = "main";
const EDIT_EVENT: &str = "config-edit-state";
const ASSET_EVENT: &str = "asset-session-state";

struct ShellState {
    bridge: Arc<DesktopBridge>, document: DocumentBinding,
    #[cfg(not(target_os = "linux"))] picker: Arc<AtomicBool>,
    #[cfg(not(target_os = "linux"))] closing: AtomicBool,
    exit_ready: AtomicBool,
    relay_stop: watch::Sender<bool>,
    relay: AsyncMutex<RelayBook>,
    #[cfg(target_os = "linux")] exit_observer: Mutex<Option<tauri::async_runtime::JoinHandle<()>>>,
}
struct RelayBook { handle: Option<tauri::async_runtime::JoinHandle<()>>, settled: bool }

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
#[tauri::command]
async fn propose_github_setup(request: tauri::ipc::Request<'_>, state: State<'_, ShellState>) -> Result<Value, BridgeError> {
    let input = crate::github_commands::proposal(request_body(&request)?)?;
    not_closing(&state)?;
    state.bridge.propose_github_setup(input).await
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
fn not_closing(state: &ShellState) -> Result<(), BridgeError> {
    #[cfg(target_os = "linux")]
    { return state.document.not_quitting(); }
    #[cfg(not(target_os = "linux"))]
    {
    if state.closing.load(Ordering::SeqCst) {
        return Err(BridgeError::new("quit_pending", "Finish or cancel the quit confirmation before starting another action."));
    }
    Ok(())
    }
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

fn asset_window(webview: &Webview) -> Result<(), AssetError> {
    if webview.label() == MAIN_WINDOW { Ok(()) } else { Err(AssetError::invalid()) }
}
fn asset_body<'a>(request: &'a tauri::ipc::Request<'_>) -> Result<&'a Value, AssetError> {
    match request.body() { tauri::ipc::InvokeBody::Json(value) => Ok(value), tauri::ipc::InvokeBody::Raw(_) => Err(AssetError::invalid()) }
}

#[tauri::command]
async fn vault_status(webview: Webview, request: tauri::ipc::Request<'_>, state: State<'_, ShellState>) -> Result<AssetStatus, AssetError> {
    asset_window(&webview)?; asset_commands::status(asset_body(&request)?)?; Ok(state.document.status())
}
#[tauri::command]
async fn vault_open(webview: Webview, request: tauri::ipc::Request<'_>, state: State<'_, ShellState>) -> Result<AssetStatus, AssetError> {
    asset_window(&webview)?; asset_commands::open(asset_body(&request)?)?; state.document.open_session()
}
#[tauri::command]
async fn asset_context(webview: Webview, request: tauri::ipc::Request<'_>, state: State<'_, ShellState>) -> Result<AssetStatus, AssetError> {
    asset_window(&webview)?; let args = asset_commands::context(asset_body(&request)?)?; state.document.context(args)
}
#[tauri::command]
async fn asset_choose(webview: Webview, app: tauri::AppHandle, request: tauri::ipc::Request<'_>, state: State<'_, ShellState>) -> Result<AssetStatus, AssetError> {
    asset_window(&webview)?; let args = asset_commands::choose(asset_body(&request)?)?; state.document.choose(app, args)
}
#[tauri::command]
async fn credential_prepare(webview: Webview, request: tauri::ipc::Request<'_>, state: State<'_, ShellState>) -> Result<AssetStatus, CommandError> {
    asset_window(&webview)?; let args = asset_commands::prepare(asset_body(&request)?)?;
    let id = state.document.prepare(args)?;
    let document = state.document.clone(); drop(state); drop(request);
    // This waiter owns neither Fields nor an original operation handle. Tauri
    // may still retain its admitted IPC body; no prompt physical-erasure claim.
    document.prepared(id).await
}
#[tauri::command]
async fn vault_prepare_delete(webview: Webview, request: tauri::ipc::Request<'_>, state: State<'_, ShellState>) -> Result<AssetStatus, AssetError> {
    asset_window(&webview)?; let args = asset_commands::delete(asset_body(&request)?)?; state.document.prepare_delete(args)
}
#[tauri::command]
async fn vault_commit(webview: Webview, request: tauri::ipc::Request<'_>, state: State<'_, ShellState>) -> Result<AssetStatus, AssetError> {
    asset_window(&webview)?; let token = asset_commands::preview_token(asset_body(&request)?)?; state.document.commit(token)
}
#[tauri::command]
async fn vault_bind(webview: Webview, request: tauri::ipc::Request<'_>, state: State<'_, ShellState>) -> Result<AssetStatus, AssetError> {
    asset_window(&webview)?; let token = asset_commands::preview_token(asset_body(&request)?)?; state.document.bind(token)
}
#[tauri::command]
async fn vault_discard(webview: Webview, request: tauri::ipc::Request<'_>, state: State<'_, ShellState>) -> Result<AssetStatus, AssetError> {
    asset_window(&webview)?; let id = asset_commands::discard(asset_body(&request)?)?; state.document.discard(id)
}
#[tauri::command]
async fn vault_lock(webview: Webview, request: tauri::ipc::Request<'_>, state: State<'_, ShellState>) -> Result<AssetStatus, AssetError> {
    asset_window(&webview)?; asset_commands::lock(asset_body(&request)?)?; state.document.lock_session()
}

#[cfg(not(target_os = "linux"))]
struct PickerGuard(Arc<AtomicBool>);
#[cfg(not(target_os = "linux"))]
impl Drop for PickerGuard { fn drop(&mut self) { self.0.store(false, Ordering::SeqCst); } }
#[cfg(not(target_os = "linux"))]
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

#[cfg(target_os = "linux")]
#[tauri::command]
async fn choose_project(webview: Webview, app: tauri::AppHandle, request: tauri::ipc::Request<'_>, state: State<'_, ShellState>) -> Result<Option<Project>, AssetError> {
    asset_window(&webview)?; asset_commands::status(asset_body(&request)?)?;
    let id = state.document.choose_project(app)?;
    // Only an observer of the retained original operation; no path or native
    // handle belongs to this invoke future, even if the renderer disappears.
    state.document.project_result(id).await
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

fn start_relay(app: tauri::AppHandle, edits: EditOwner, document: DocumentBinding, mut stop: watch::Receiver<bool>) -> (tauri::async_runtime::JoinHandle<()>, oneshot::Sender<()>) {
    let mut revisions = edits.subscribe();
    let mut assets = document.subscribe();
    let (start, enter) = oneshot::channel();
    let handle = tauri::async_runtime::spawn(async move {
        if enter.await.is_err() { return; }
        loop {
            if *stop.borrow() { return; }
            // status() releases its native locks before any renderer callback.
            // Events are best effort: the UI subscribes then fetches status and
            // orders both by native revision, never by arrival time.
            if let Ok(status) = edits.status() { let _ = app.emit_to(MAIN_WINDOW, EDIT_EVENT, &status); }
            let status = document.status();
            let _ = app.emit_to(MAIN_WINDOW, ASSET_EVENT, &status);
            tokio::select! {
                biased;
                result = stop.changed() => { if result.is_err() || *stop.borrow() { return; } },
                result = revisions.changed() => { if result.is_err() { return; } },
                result = assets.changed() => { if result.is_err() { return; } },
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
    let _ = handle.await;
    book.handle.take(); book.settled = true; true
}

#[cfg(target_os = "linux")]
fn start_exit_observer(app: tauri::AppHandle, document: DocumentBinding) -> (tauri::async_runtime::JoinHandle<()>, oneshot::Sender<()>) {
    let (start, enter) = oneshot::channel();
    let handle = tauri::async_runtime::spawn(async move {
        if enter.await.is_err() { return; }
        loop {
            // One fixed, app-level data-only observer. No native dialog, IO,
            // query, assignment publication, retry or deadline renewal here.
            // can_exit polls only an already-ended original quit coordinator.
            if document.can_exit() {
                if !settle_relay(&app).await || !document.can_exit() { return; }
                app.state::<ShellState>().exit_ready.store(true, Ordering::SeqCst);
                app.exit(0); return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    });
    (handle, start)
}

#[cfg(target_os = "linux")]
fn request_shutdown(app: &tauri::AppHandle) { app.state::<ShellState>().document.request_quit(app.clone()); }

#[cfg(not(target_os = "linux"))]
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
            if !settle_relay(&app).await { return; }
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
pub(crate) enum DialogChoice { File(crate::credential_format::FileKind), Project, Quit }

#[cfg(not(target_os = "linux"))]
pub(crate) async fn run_owned_dialog(_: &tauri::AppHandle, owner: &Arc<OriginalWork>, _: DialogChoice) -> Result<Option<std::path::PathBuf>, Reason> {
    owner.gui.not_created(Reason::UnsupportedPlatform); Err(Reason::UnsupportedPlatform)
}

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
    }
    impl Object {
        fn close(&self) { match self { Self::File(dialog) => dialog.close(), Self::Message(dialog) => dialog.close() } }
        fn show(&self) { match self { Self::File(dialog) => dialog.show(), Self::Message(dialog) => dialog.show() } }
        fn disconnect(&self, handler: gtk::glib::SignalHandlerId) {
            match self { Self::File(dialog) => dialog.disconnect(handler), Self::Message(dialog) => dialog.disconnect(handler) }
        }
    }

    fn destroyed(weak: &Weak<GuiCall>) {
        let Some(call) = weak.upgrade() else { return; };
        let unexpected = if let Some(mut facts) = call.facts() {
            let unexpected = !facts.response && call.owner().is_some_and(|owner| !owner.stopped());
            facts.destroyed = true; facts.showing = false; unexpected
        } else { true };
        if unexpected { call.failed(Reason::SourceRefused); }
        call.changed();
    }
    fn native_path(dialog: &gtk::FileChooserDialog) -> Result<PathBuf, Reason> {
        // Exactly one accepted-response filename() call. Before any additional
        // application path copy, enforce native byte/component bounds. Neither
        // this hint nor its basename is ever returned as an asset DTO.
        let path = dialog.filename().ok_or(Reason::SourceRefused)?;
        crate::asset_source::path_hint(&path)?; Ok(path)
    }
    fn not_created(call: &Arc<GuiCall>, reason: Reason) { call.not_created(reason); call.failed(reason); }

    fn construct(app: tauri::AppHandle, call: Arc<GuiCall>, choice: DialogChoice) {
        if !gtk::is_initialized_main_thread() { not_created(&call, Reason::Unqualified); return; }
        let Some(owner) = call.owner() else { not_created(&call, Reason::CleanupUnknown); return; };
        if owner.interrupted() { not_created(&call, Reason::UserCancelled); return; }
        if DIALOG.with(|book| book.borrow().is_some()) { not_created(&call, Reason::Busy); return; }
        let Some(window) = app.get_webview_window(MAIN_WINDOW) else { not_created(&call, Reason::DocumentLost); return; };
        let parent = match window.gtk_window() { Ok(parent) => parent, Err(_) => { not_created(&call, Reason::Unqualified); return; } };
        if let Some(mut facts) = call.facts() { facts.constructing = true; } else { call.failed(Reason::CleanupUnknown); return; }
        if matches!(choice, DialogChoice::File(_)) {
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
            DialogChoice::Quit => Object::Message(gtk::MessageDialog::new(Some(&parent), gtk::DialogFlags::MODAL, gtk::MessageType::Question, gtk::ButtonsType::OkCancel,
                "Unsaved in-memory changes will be lost. Choose Cancel to keep working, or OK to stop owned operations and wait for cleanup before quitting. A save already accepted may still complete; quitting does not undo committed files.")),
        };
        // Adopt the late returned object BEFORE any STOP check/configuration.
        // A cancellation during its constructor cannot lose its destruction
        // obligation. No callback captures a strong dialog or application cycle.
        DIALOG.with(|book| *book.borrow_mut() = Some(NativeDialog { id: owner.id, object, filter: None, response: None, destroy: None }));
        if let Some(mut facts) = call.facts() { facts.created = true; facts.constructing = false; }
        DIALOG.with(|book| {
            let mut book = book.borrow_mut();
            let Some(entry) = book.as_mut().filter(|entry| entry.id == owner.id) else { call.failed(Reason::CleanupUnknown); return; };
            let response_call = Arc::downgrade(&call); let destroy_call = Arc::downgrade(&call);
            match &entry.object {
                Object::File(dialog) => {
                    dialog.set_local_only(true); dialog.set_select_multiple(false); dialog.set_create_folders(false);
                    dialog.set_modal(true); dialog.set_destroy_with_parent(true);
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
                    entry.response = Some(dialog.connect_response(move |dialog, response| {
                        let Some(call) = response_call.upgrade() else { return; };
                        // Latch the actual response/endpoint under the real
                        // admission lock BEFORE calling filename(), without
                        // holding that lock over any GTK API.
                        let response = match response {
                            gtk::ResponseType::Accept => NativeResponse::Accept,
                            gtk::ResponseType::Cancel | gtk::ResponseType::DeleteEvent => NativeResponse::Decline,
                            _ => NativeResponse::Other,
                        };
                        if call.begin_response(response, false) == Some(true) { call.selected_path(native_path(dialog)); }
                    }));
                    entry.destroy = Some(dialog.connect_destroy(move |_| destroyed(&destroy_call)));
                }
                Object::Message(dialog) => {
                    dialog.set_title("Quit and discard unsaved drafts?"); dialog.set_destroy_with_parent(true);
                    entry.response = Some(dialog.connect_response(move |_, response| {
                        if let Some(call) = response_call.upgrade() {
                            let response = match response {
                                gtk::ResponseType::Ok => NativeResponse::Accept,
                                gtk::ResponseType::Cancel | gtk::ResponseType::DeleteEvent => NativeResponse::Decline,
                                _ => NativeResponse::Other,
                            };
                            let _ = call.begin_response(response, true);
                        }
                    }));
                    entry.destroy = Some(dialog.connect_destroy(move |_| destroyed(&destroy_call)));
                }
            }
        });
        if owner.interrupted() { call.changed(); return; }
        if let Some(mut facts) = call.facts() { facts.showing = true; }
        DIALOG.with(|book| { if let Some(entry) = book.borrow().as_ref().filter(|entry| entry.id == owner.id) { entry.object.show(); } });
        call.presented(); call.changed();
    }

    fn close_after_response(call: Arc<GuiCall>, id: u32) {
        if !gtk::is_initialized_main_thread() { call.failed(Reason::CleanupUnknown); return; }
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
        call.changed();
    }
    fn release_after_destroy(call: Arc<GuiCall>, id: u32) {
        if !gtk::is_initialized_main_thread() { call.failed(Reason::CleanupUnknown); return; }
        if !call.facts().is_some_and(|facts| facts.destroyed && facts.close_ack) { call.failed(Reason::CleanupUnknown); return; }
        let original = DIALOG.with(|book| {
            let mut book = book.borrow_mut();
            if book.as_ref().is_some_and(|entry| entry.id == id) { book.take() } else { None }
        });
        let Some(mut original) = original else { call.failed(Reason::CleanupUnknown); return; };
        if let Some(handler) = original.response.take() { original.object.disconnect(handler); }
        if let Some(handler) = original.destroy.take() { original.object.disconnect(handler); }
        drop(original); // Original dialog/filter/handler refs, on their thread.
        if let Some(mut facts) = call.facts() { facts.released = true; }
        call.changed();
    }

    pub(crate) async fn run_owned_dialog(app: &tauri::AppHandle, owner: &Arc<OriginalWork>, choice: DialogChoice) -> Result<Option<PathBuf>, Reason> {
        let call = owner.gui.clone();
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
        let construct_call = call.clone(); let construct_app = app.clone();
        if window.run_on_main_thread(move || construct(construct_app, construct_call, choice)).is_err() {
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
                    if window.run_on_main_thread(move || close_after_response(call, id)).is_err() { failure.failed(Reason::CleanupUnknown); }
                }
            }
            if release {
                if gtk::is_initialized_main_thread() { call.failed(Reason::CleanupUnknown); }
                else {
                    let call = call.clone(); let failure = call.clone(); let id = owner.id;
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
            let document = DocumentBinding::new(bridge.clone());
            let (relay_stop, stop_receiver) = watch::channel(false);
            app.manage(ShellState {
                bridge: bridge.clone(), document: document.clone(),
                #[cfg(not(target_os = "linux"))] picker: Arc::new(AtomicBool::new(false)),
                #[cfg(not(target_os = "linux"))] closing: AtomicBool::new(false),
                exit_ready: AtomicBool::new(false), relay_stop, relay: AsyncMutex::new(RelayBook { handle: None, settled: false }),
                #[cfg(target_os = "linux")] exit_observer: Mutex::new(None),
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
            let state = app.state::<ShellState>();
            // Setup is synchronous and these fresh slots cannot be contended.
            // Both observer bodies wait behind barriers until their ORIGINAL
            // handles have been stored in the application, not an invoke.
            let mut book = state.relay.try_lock().map_err(|_| "The original event relay could not be retained.")?;
            let (handle, start) = start_relay(app.handle().clone(), bridge.edits.clone(), document.clone(), stop_receiver);
            book.handle = Some(handle); drop(book);
            let _ = start.send(());
            #[cfg(target_os = "linux")]
            {
                let mut book = state.exit_observer.lock().map_err(|_| "The original exit observer could not be retained.")?;
                let (handle, start) = start_exit_observer(app.handle().clone(), document);
                *book = Some(handle); drop(book);
                let _ = start.send(());
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            app_info, choose_project, project_snapshot, catalog, validate_config, suggest_config, preview_config,
            propose_github_setup,
            open_config_edit, prepare_config_edit, apply_config_edit, close_config_edit, config_edit_status,
            vault_status, vault_open, asset_context, asset_choose, credential_prepare,
            vault_prepare_delete, vault_commit, vault_bind, vault_discard, vault_lock,
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
