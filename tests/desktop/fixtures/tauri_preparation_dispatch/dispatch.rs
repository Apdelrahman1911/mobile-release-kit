//! Actual Tauri IPC/macro/runtime with the current handler and request gates.
//! Only the final Document port is replaced; no native owner is constructed.
#![allow(dead_code)]
use serde::Serialize;
use serde_json::{json, Value};
use std::sync::{atomic::{AtomicBool, AtomicUsize, Ordering}, Arc, Mutex};
use tauri::State;
type Webview = tauri::Webview<tauri::test::MockRuntime>;
const MAIN_WINDOW: &str = "main";

#[derive(Debug, Serialize)]
struct BridgeError { code: &'static str }
impl BridgeError {
    fn new(code: &'static str, _: &str) -> Self { Self { code } }
    fn invalid() -> Self { Self { code: "invalid_request" } }
}
// The production fixture macro is inert in the ordinary build. This harness
// supplies no observation profile or route and exercises the unchanged body.
macro_rules! fixture_command { ($($argument:tt)*) => {}; }

mod installation {
    use super::*;
    pub(crate) type PreparationStatus = Value;
    /* ORIGINAL_CONFIRMATION_AND_REQUEST */
}

#[derive(Default)]
struct DocumentPort {
    calls: AtomicUsize,
    runtime_observed: AtomicBool,
    thread: Mutex<Option<std::thread::ThreadId>>,
    refusal: bool,
}
impl DocumentPort {
    fn prepare_installation_quit(&self, confirmation: &str) -> Result<Value, BridgeError> {
        assert_eq!(confirmation, installation::PREPARE_QUIT_CONFIRMATION);
        self.calls.fetch_add(1, Ordering::SeqCst);
        *self.thread.lock().unwrap() = Some(std::thread::current().id());
        // The same fallible API used before Saved's original publication.
        // Never create/enter a runtime here to make an invalid route succeed.
        let _executor = tokio::runtime::Handle::try_current()
            .map_err(|_| BridgeError::new("macos_maintenance_unavailable", ""))?;
        self.runtime_observed.store(true, Ordering::SeqCst);
        if self.refusal { return Err(BridgeError::new("original_admission_refused", "")); }
        Ok(json!({"fixture": "document-port-returned"}))
    }
}
struct ShellState { document: Arc<DocumentPort> }
/* ORIGINAL_WINDOW_AND_BODY_GATES */
/* ORIGINAL_PREPARATION_COMMAND */
/* LEGACY_SYNCHRONOUS_COMMAND */

fn app(port: Arc<DocumentPort>) -> tauri::App<tauri::test::MockRuntime> {
    tauri::test::mock_builder()
        .manage(ShellState { document: port })
        .invoke_handler(tauri::generate_handler![prepare_installation_quit, legacy_prepare_installation_quit])
        .build(tauri::test::mock_context(tauri::test::noop_assets())).unwrap()
}
fn invoke(app: &tauri::App<tauri::test::MockRuntime>, label: &str, command: &str,
          body: tauri::ipc::InvokeBody) -> Result<Value, Value> {
    assert!(tokio::runtime::Handle::try_current().is_err(), "invoke originates outside Tokio");
    let window = tauri::WebviewWindowBuilder::new(app, label, Default::default()).build().unwrap();
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    window.as_ref().clone().on_message(tauri::webview::InvokeRequest {
        cmd: command.into(), callback: tauri::ipc::CallbackFn(0), error: tauri::ipc::CallbackFn(1),
        url: "tauri://localhost".parse().unwrap(), body, headers: Default::default(),
        invoke_key: tauri::test::INVOKE_KEY.to_string(),
    }, Box::new(move |_, _, response, _, _| { sender.send(response).unwrap(); }));
    let response = receiver.recv_timeout(std::time::Duration::from_secs(5)).expect("one bounded original response");
    assert!(tokio::runtime::Handle::try_current().is_err(), "no runtime context leaked to the callback thread");
    match response {
        tauri::ipc::InvokeResponse::Ok(value) => Ok(value.deserialize().unwrap()),
        tauri::ipc::InvokeResponse::Err(tauri::ipc::InvokeError(value)) => Err(value),
    }
}
fn confirmed() -> tauri::ipc::InvokeBody {
    tauri::ipc::InvokeBody::Json(json!({"confirmation": installation::PREPARE_QUIT_CONFIRMATION}))
}

#[test]
fn old_sync_dispatch_has_no_current_runtime_before_original_publication() {
    let port = Arc::new(DocumentPort::default()); let app = app(port.clone());
    let original_thread = std::thread::current().id();
    assert_eq!(invoke(&app, MAIN_WINDOW, "legacy_prepare_installation_quit", confirmed()).unwrap_err()["code"], "macos_maintenance_unavailable");
    assert_eq!(port.calls.load(Ordering::SeqCst), 1);
    assert!(!port.runtime_observed.load(Ordering::SeqCst));
    assert_eq!(*port.thread.lock().unwrap(), Some(original_thread));
}
#[test]
fn current_handler_runs_once_on_the_tauri_owned_runtime() {
    let port = Arc::new(DocumentPort::default()); let app = app(port.clone());
    let original_thread = std::thread::current().id();
    assert_eq!(invoke(&app, MAIN_WINDOW, "prepare_installation_quit", confirmed()).unwrap()["fixture"], "document-port-returned");
    assert_eq!(port.calls.load(Ordering::SeqCst), 1);
    assert!(port.runtime_observed.load(Ordering::SeqCst));
    assert_ne!(*port.thread.lock().unwrap(), Some(original_thread));
}
#[test]
fn wrong_original_window_never_reaches_document() {
    let port = Arc::new(DocumentPort::default()); let app = app(port.clone());
    assert_eq!(invoke(&app, "other", "prepare_installation_quit", confirmed()).unwrap_err()["code"], "invalid_request");
    assert_eq!(port.calls.load(Ordering::SeqCst), 0);
}
#[test]
fn malformed_confirmation_and_raw_body_never_reach_document() {
    for body in [tauri::ipc::InvokeBody::Raw(Vec::new()),
                 tauri::ipc::InvokeBody::Json(json!({})),
                 tauri::ipc::InvokeBody::Json(json!({"confirmation":"yes"})),
                 tauri::ipc::InvokeBody::Json(json!({"confirmation":installation::PREPARE_QUIT_CONFIRMATION,"path":"/unplanned"}))] {
        let port = Arc::new(DocumentPort::default()); let app = app(port.clone());
        assert_eq!(invoke(&app, MAIN_WINDOW, "prepare_installation_quit", body).unwrap_err()["code"], "invalid_request");
        assert_eq!(port.calls.load(Ordering::SeqCst), 0);
    }
}
#[test]
fn original_document_refusal_is_returned_without_retry() {
    let port = Arc::new(DocumentPort { refusal:true, ..Default::default() }); let app = app(port.clone());
    assert_eq!(invoke(&app, MAIN_WINDOW, "prepare_installation_quit", confirmed()).unwrap_err()["code"], "original_admission_refused");
    assert_eq!(port.calls.load(Ordering::SeqCst), 1);
    assert!(port.runtime_observed.load(Ordering::SeqCst));
}
