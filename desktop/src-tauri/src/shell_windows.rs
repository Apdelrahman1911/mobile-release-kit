//! Windows normal document and two owned native dialogs. Native COM/Win32
//! calls stay in the private platform crate; this crate forbids unsafe code.
use super::*;
use std::{cell::RefCell, path::PathBuf, rc::Rc};
use crate::asset_session::GuiCall;
use mrk_windows_installed_native::ui as native;

const BLANK: &str = "about:blank";
const PACKAGED: &str = "http://tauri.localhost/";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StartupPhase { Blank, PackagedRequested, Lost }
#[derive(Debug)]
struct StartupOrder {
    phase: StartupPhase,
    blank_navigation: bool,
    blank_started: bool,
    blank_finished: bool,
    hook: bool,
}
impl Default for StartupOrder {
    fn default() -> Self {
        Self { phase: StartupPhase::Blank, blank_navigation: false,
            blank_started: false, blank_finished: false, hook: false }
    }
}
impl StartupOrder {
    fn fail(&mut self) { self.phase = StartupPhase::Lost; }
    fn navigation(&mut self, blank: bool) -> Option<bool> {
        match self.phase {
            StartupPhase::Lost => Some(false),
            StartupPhase::Blank if blank && !self.blank_navigation && !self.blank_finished => {
                self.blank_navigation = true; Some(true)
            }
            StartupPhase::Blank => { self.fail(); Some(false) }
            StartupPhase::PackagedRequested if blank => { self.fail(); Some(false) }
            StartupPhase::PackagedRequested => None, // Existing DocumentLifetime owns this load.
        }
    }
    fn page(&mut self, blank: bool, finished: bool) -> bool {
        match self.phase {
            StartupPhase::Lost => true,
            StartupPhase::Blank if blank => {
                if finished {
                    if !self.blank_started || self.blank_finished { self.fail(); }
                    else { self.blank_finished = true; }
                } else if self.blank_started { self.fail(); }
                else { self.blank_started = true; }
                true
            }
            StartupPhase::Blank => { self.fail(); true }
            StartupPhase::PackagedRequested if blank => { self.fail(); true }
            StartupPhase::PackagedRequested => false,
        }
    }
    fn installed(&mut self) -> bool {
        if self.phase != StartupPhase::Blank || self.hook { self.fail(); false }
        else { self.hook = true; true }
    }
    fn claim_navigation(&mut self) -> bool {
        if self.phase == StartupPhase::Blank && self.blank_started && self.blank_finished && self.hook {
            self.phase = StartupPhase::PackagedRequested; true
        } else { false }
    }
}

pub(super) struct Startup {
    document: DocumentBinding,
    order: Mutex<StartupOrder>,
    user_data: PathBuf,
}
impl Startup {
    pub(super) fn user_data(&self) -> &std::path::Path { &self.user_data }
    fn lost(&self) {
        if let Ok(mut order) = self.order.lock() { order.fail(); }
        self.document.lost();
    }
    pub(super) fn navigation(&self, url: &tauri::Url) -> bool {
        let decision = match self.order.lock() {
            Ok(mut order) => order.navigation(url.as_str() == BLANK),
            Err(_) => { self.document.lost(); return false; }
        };
        match decision {
            Some(false) => { self.document.lost(); false }
            Some(true) => true, // Inert original blank only; no document authority.
            None => self.document.navigation(trusted_document(url)),
        }
    }
    pub(super) fn page(&self, webview: &tauri::WebviewWindow, payload: &tauri::webview::PageLoadPayload<'_>) {
        let (consumed, lost) = match self.order.lock() {
            Ok(mut order) => {
                let consumed = order.page(payload.url().as_str() == BLANK,
                    matches!(payload.event(), tauri::webview::PageLoadEvent::Finished));
                (consumed, order.phase == StartupPhase::Lost)
            }
            Err(_) => { self.document.lost(); return; }
        };
        if lost { self.document.lost(); return; }
        if !consumed {
            let trusted = trusted_document(payload.url());
            self.document.observe(|lifetime| match payload.event() {
                tauri::webview::PageLoadEvent::Started => lifetime.started(trusted),
                tauri::webview::PageLoadEvent::Finished => lifetime.finished(trusted),
            });
        }
        self.navigate_once(webview);
    }
    fn navigate_once(&self, webview: &tauri::WebviewWindow) {
        let claimed = match self.order.lock() {
            Ok(mut order) => order.claim_navigation(),
            Err(_) => { self.document.lost(); false }
        };
        if !claimed { return; }
        // The claim is spent before dispatch. A failed/late navigation never
        // retries, substitutes a cached Finished, or rearms DocumentLifetime.
        match tauri::Url::parse(PACKAGED) {
            Ok(url) if webview.navigate(url).is_ok() => {},
            _ => self.lost(),
        }
    }
}

struct Session { original: native::ShellSession, user_data: Option<PathBuf> }
struct OriginalDialog {
    id: u32, original: Rc<native::Dialog>, call: std::sync::Weak<GuiCall>,
}
thread_local! {
    static SESSION: RefCell<Option<Box<Session>>> = const { RefCell::new(None) };
    static DIALOG: RefCell<Option<OriginalDialog>> = const { RefCell::new(None) };
}

/// Called by run_builder before Tauri can construct any implicit/explicit view.
/// Even an Err leaves the original partial book registered, never Result<Self>.
pub(super) fn prepare() -> Result<(), InitializationFailed> {
    SESSION.with(|slot| {
        let mut slot = slot.try_borrow_mut().map_err(|_| InitializationFailed)?;
        if slot.is_some() { return Err(InitializationFailed); }
        *slot = Some(Box::new(Session { original: native::ShellSession::new(), user_data: None }));
        let original = slot.as_mut().ok_or(InitializationFailed)?;
        match original.original.prepare() {
            Ok(path) => { original.user_data = Some(path); Ok(()) },
            Err(error) => {
                startup_refusal(error);
                // No WebView creation was permitted. Only this fresh scope and
                // same inspector's actual known originals are eligible to settle.
                let end = std::time::Instant::now() + Duration::from_secs(2);
                if original.original.begin_close(end).is_err() || original.original.settle() != Ok(true) {
                    diagnostic(b"MRK_WINDOWS_SHELL=initial-cleanup-unconfirmed\n");
                }
                Err(InitializationFailed)
            }
        }
    })
}
fn startup_refusal(error: native::UiError) {
    diagnostic(match error {
        native::UiError::OrdinaryContext => b"Mobile Release Kit requires an ordinary, non-elevated Windows account.\n",
        native::UiError::InteractiveDesktop => b"Mobile Release Kit requires the current interactive Windows desktop.\n",
        native::UiError::ManagedRuntimeUnavailable => b"A supported system-managed Microsoft Edge WebView2 Evergreen runtime is required. No downloader or per-user fallback was started.\n",
        native::UiError::RuntimeOverrides => b"WebView2 browser, data, argument, or channel overrides are not supported. No system policy was changed.\n",
        native::UiError::UserDataParent => b"A private local application-data directory could not be admitted. Shared profiles are not used.\n",
        _ => b"The original Windows application could not initialize safely; its unresolved resources are retained.\n",
    });
}
pub(super) fn startup(document: DocumentBinding) -> Result<Arc<Startup>, native::UiError> {
    let user_data = SESSION.with(|slot| slot.try_borrow().map_err(|_| native::UiError::State)?
        .as_ref().and_then(|session| session.user_data.clone()).ok_or(native::UiError::State))?;
    Ok(Arc::new(Startup { document, order: Mutex::new(StartupOrder::default()), user_data }))
}
pub(super) fn before_webview() -> Result<(), native::UiError> {
    SESSION.with(|slot| slot.try_borrow_mut().map_err(|_| native::UiError::State)?
        .as_mut().ok_or(native::UiError::State)?.original.before_webview())
}
pub(super) fn install(window: &tauri::WebviewWindow, startup: Arc<Startup>) {
    let callback = startup.clone(); let original_window = window.clone();
    if window.with_webview(move |platform| {
        let lost = callback.clone();
        let installed = SESSION.with(|slot| slot.try_borrow_mut().map_err(|_| native::UiError::State)?
            .as_mut().ok_or(native::UiError::State)?.original.install(platform.controller(), platform.environment(),
                Box::new(move || lost.lost())));
        let ordered = installed.is_ok() && callback.order.lock().is_ok_and(|mut order| order.installed());
        if !ordered { callback.lost(); return; }
        callback.document.hook_installed();
        diagnostic(b"MRKDBG_DESKTOP_BOOTSTRAP=hook-installed\n");
        callback.navigate_once(&original_window);
    }).is_err() { startup.lost(); }
}
pub(super) fn build_failed() {
    // Wry may have created a browser before a later build/with_webview failure.
    // No successful controller/environment ownership means no deletion or
    // fabricated settlement. Keep the original profile/book, report failure.
    SESSION.with(|slot| {
        if let Ok(mut slot) = slot.try_borrow_mut() {
            if let Some(session) = slot.as_mut() {
                if session.original.finish_failed_setup(std::time::Instant::now() + Duration::from_secs(2)) == Ok(true) {
                    diagnostic(b"MRK_WINDOWS_SHELL=pre-construction-cleanup-confirmed\n"); return;
                }
            }
        }
        diagnostic(b"MRK_WINDOWS_SHELL=construction-finality-unconfirmed\n");
    });
}

type NativeReturn = Result<(), native::UiError>;
async fn original_dispatch(app: &tauri::AppHandle, done: impl FnOnce() -> NativeReturn + Send + 'static,
    document: &DocumentBinding, end: tokio::time::Instant) -> bool {
    if tokio::time::Instant::now() >= end {
        document.lost(); diagnostic(b"MRK_WINDOWS_SHELL=original-close-deadline-unconfirmed\n"); return false;
    }
    let (returned, mut joined) = oneshot::channel();
    if app.run_on_main_thread(move || { let result = done(); let _ = returned.send(result); }).is_err() {
        document.lost(); std::future::pending::<()>().await;
    }
    tokio::select! {
        result = &mut joined => match result {
            Ok(Ok(())) if tokio::time::Instant::now() < end => true,
            _ => { document.lost(); false },
        },
        _ = tokio::time::sleep_until(end) => {
            document.lost(); diagnostic(b"MRK_WINDOWS_SHELL=original-close-deadline-unconfirmed\n");
            // Keep the original receiver/dispatch reachable, not a detached
            // timeout future which a late success could turn into readiness.
            std::future::pending::<()>().await; let _ = joined; false
        }
    }
}
/// Extends the EXISTING application exit observer; no parallel cleanup owner.
pub(super) async fn settle_for_exit(app: &tauri::AppHandle, document: &DocumentBinding) -> bool {
    // Core/GUI/relay settlement spent part of the SAME accepted Quit budget.
    // An absent or expired original endpoint never authorizes a renewed scope.
    let Some(original_end) = document.exit_cleanup_end() else { document.lost(); return false; };
    let end = tokio::time::Instant::from_std(original_end);
    if !original_dispatch(app, move || SESSION.with(|slot| slot.try_borrow_mut().map_err(|_| native::UiError::CleanupUnknown)?
        .as_mut().ok_or(native::UiError::State)?.original.begin_close(original_end)), document, end).await { return false; }
    loop {
        if tokio::time::Instant::now() >= end { document.lost(); return false; }
        let (returned, mut joined) = oneshot::channel();
        if app.run_on_main_thread(move || {
            let result = SESSION.with(|slot| slot.try_borrow_mut().map_err(|_| native::UiError::CleanupUnknown)?
                .as_mut().ok_or(native::UiError::State)?.original.settle());
            let _ = returned.send(result);
        }).is_err() { document.lost(); std::future::pending::<()>().await; }
        tokio::select! {
            result = &mut joined => match result {
                Ok(Ok(true)) if tokio::time::Instant::now() < end => return true,
                Ok(Ok(false)) => {},
                _ => { document.lost(); diagnostic(b"MRK_WINDOWS_SHELL=original-cleanup-unconfirmed\n"); return false; }
            },
            _ = tokio::time::sleep_until(end) => {
                document.lost(); diagnostic(b"MRK_WINDOWS_SHELL=original-cleanup-deadline-unconfirmed\n");
                std::future::pending::<()>().await; let _ = joined;
            }
        }
        if tokio::time::Instant::now() >= end { document.lost(); return false; }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

fn native_event(call: &Arc<GuiCall>, event: native::DialogEvent, quit: bool) {
    match event {
        native::DialogEvent::Created => {
            if let Some(mut facts) = call.facts() { facts.created = true; facts.constructing = false; }
            else { call.failed(Reason::CleanupUnknown); }
        }
        native::DialogEvent::ShowEntered => {
            if let Some(mut facts) = call.facts() { facts.showing = true; }
            else { call.failed(Reason::CleanupUnknown); }
        }
        native::DialogEvent::Presented => call.presented(),
        native::DialogEvent::Response(response) => {
            let response = match response { native::DialogResponse::Accept => NativeResponse::Accept, native::DialogResponse::Decline => NativeResponse::Decline };
            if call.begin_response(response, quit).is_none() { call.failed(Reason::DocumentLost); }
        }
        native::DialogEvent::ShowReturned => {
            if let Some(mut facts) = call.facts() { facts.showing = false; facts.constructing = false; }
            else { call.failed(Reason::CleanupUnknown); }
        }
        native::DialogEvent::Releasing => {
            if let Some(mut facts) = call.facts() {
                // The actual modal call is no longer entered; this is the
                // original native adapter's one close/release transition.
                facts.close_queued = true; facts.release_queued = true;
            } else { call.failed(Reason::CleanupUnknown); }
        }
        // Actual original COM unadvising/releases, TaskDialog destroyed callback,
        // Show return, fixed-message retirement and helper destruction precede it.
        native::DialogEvent::Settled => {
            if let Some(mut facts) = call.facts() {
                facts.showing = false; facts.constructing = false;
                if facts.created { facts.destroyed = true; facts.close_ack = true; facts.released = true; }
            } else { call.failed(Reason::CleanupUnknown); }
        }
        native::DialogEvent::Unknown => call.failed(Reason::CleanupUnknown),
    }
    call.changed();
}
fn show(call: Arc<GuiCall>, control: Arc<native::DialogControl>, kind: native::DialogKind) -> Result<Option<PathBuf>, Reason> {
    let Some(owner) = call.owner() else { call.not_created(Reason::DocumentLost); return Err(Reason::DocumentLost); };
    if owner.interrupted() { call.not_created(Reason::UserCancelled); return Err(Reason::UserCancelled); }
    let parent = match SESSION.with(|slot| slot.try_borrow().map_err(|_| native::UiError::State)?
        .as_ref().ok_or(native::UiError::State)?.original.dialog_parent(kind)) {
        Ok(parent) => parent,
        Err(_) => { call.not_created(Reason::SourceRefused); return Err(Reason::SourceRefused); }
    };
    let events = call.clone();
    let original = Rc::new(native::Dialog::new(kind, control, Box::new(move |event| native_event(&events, event, kind == native::DialogKind::Quit))));
    let reserved = DIALOG.with(|slot| {
        let mut slot = slot.try_borrow_mut().map_err(|_| Reason::CleanupUnknown)?;
        if slot.is_some() { return Err(Reason::Busy); }
        *slot = Some(OriginalDialog { id: owner.id, original: original.clone(), call: Arc::downgrade(&call) }); Ok(())
    });
    if let Err(reason) = reserved {
        if let Some(mut facts) = call.facts() { facts.constructing = false; }
        call.not_created(reason); return Err(reason);
    }
    // No TLS RefCell or mutable Rust object borrow across the modal loop. The
    // retained original remains reachable for actual STA cancellation/observation.
    let returned = original.run(parent);
    if !original.settled() {
        call.failed(Reason::CleanupUnknown); return Err(Reason::CleanupUnknown);
    }
    if !original.created() { call.not_created(if owner.interrupted() { Reason::UserCancelled } else { Reason::SourceRefused }); }
    let result = match returned {
        Ok(result) => {
            if let Some(path) = result.selected { call.selected_path(Ok(path)); }
            let mut facts = call.facts().ok_or(Reason::CleanupUnknown)?;
            if let Some(reason) = facts.refusal { Err(reason) }
            else if owner.interrupted() && kind != native::DialogKind::Quit { Err(Reason::UserCancelled) }
            else if kind == native::DialogKind::Quit || !facts.accepted { Ok(None) }
            else { facts.selected.take().map(Some).ok_or(Reason::SourceRefused) }
        }
        Err(error) => { let reason = if error == native::UiError::CleanupUnknown { Reason::CleanupUnknown } else { Reason::SourceRefused };
            call.failed(reason); Err(reason) }
    };
    DIALOG.with(|slot| {
        let mut slot = slot.try_borrow_mut().map_err(|_| Reason::CleanupUnknown)?;
        if !slot.as_ref().is_some_and(|entry| entry.id == owner.id && Rc::ptr_eq(&entry.original, &original)) { return Err(Reason::CleanupUnknown); }
        *slot = None; Ok(())
    })?;
    result
}
pub(crate) async fn run_owned_dialog(app: &tauri::AppHandle, owner: &Arc<OriginalWork>, choice: DialogChoice,
    initial_folder: Option<PathBuf>) -> Result<Option<PathBuf>, Reason> {
    let kind = match (choice, initial_folder) {
        (DialogChoice::Project, None) => native::DialogKind::Project,
        (DialogChoice::Quit, None) => native::DialogKind::Quit,
        _ => { owner.gui.not_created(Reason::UnsupportedPlatform); return Err(Reason::UnsupportedPlatform); }
    };
    let call = owner.gui.clone();
    {
        let mut facts = call.facts().ok_or(Reason::CleanupUnknown)?;
        if facts.dispatched || facts.created { return Err(Reason::CleanupUnknown); }
        facts.dispatched = true; facts.constructing = true;
    }
    let control = Arc::new(native::DialogControl::new());
    let creating = call.clone(); let closing = control.clone(); let (done, mut joined) = oneshot::channel();
    if app.run_on_main_thread(move || { let result = show(creating, closing, kind); let _ = done.send(result); }).is_err() {
        call.failed(Reason::CleanupUnknown); std::future::pending::<()>().await;
    }
    loop {
        if owner.interrupted() && control.request_stop().is_err() {
            call.failed(Reason::CleanupUnknown); std::future::pending::<()>().await;
        }
        tokio::select! {
            result = &mut joined => {
                let result = match result { Ok(result) => result, Err(_) => { call.failed(Reason::CleanupUnknown); Err(Reason::CleanupUnknown) } };
                if result == Err(Reason::CleanupUnknown) || !call.settled() {
                    call.failed(Reason::CleanupUnknown); std::future::pending::<()>().await;
                }
                return result;
            },
            _ = tokio::time::sleep(Duration::from_millis(25)) => {},
        }
    }
}

#[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "windows-installed-observation",
    not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "windows-runtime-publisher"),
    not(feature = "macos-installed-installer")))]
pub(super) mod observation {
    use super::*;
    pub(crate) use native::{DialogAction, DialogKind, DialogObservation, DialogResponse};
    pub(crate) struct ObservedDialog {
        pub(crate) id: u32,
        pub(crate) native: DialogObservation,
        pub(crate) action_allowed: bool,
        // Retain the same original response/join facts after the native TLS slot
        // retires. This read-only witness grants no GUI action or finality.
        pub(crate) call: Arc<GuiCall>,
    }
    fn original() -> Result<Option<(u32, Rc<native::Dialog>, Arc<GuiCall>, Arc<OriginalWork>)>, native::UiError> {
        let selected = DIALOG.with(|slot| {
            let slot = slot.try_borrow().map_err(|_| native::UiError::State)?;
            let Some(entry) = slot.as_ref() else { return Ok(None); };
            let call = entry.call.upgrade().ok_or(native::UiError::State)?;
            let owner = call.owner().ok_or(native::UiError::State)?;
            if owner.id != entry.id || !Arc::ptr_eq(&owner.gui, &call) { return Err(native::UiError::State); }
            Ok(Some((entry.id, entry.original.clone(), call, owner)))
        })?;
        Ok(selected)
    }
    fn allowed(call: &GuiCall, owner: &OriginalWork) -> Result<bool, native::UiError> {
        let facts = call.facts().ok_or(native::UiError::CleanupUnknown)?;
        Ok(!owner.interrupted() && facts.dispatched && facts.created && facts.showing && !facts.constructing
            && !facts.not_created && facts.refusal.is_none() && !facts.response && !facts.close_queued
            && !facts.destroyed && !facts.close_ack && !facts.release_queued && !facts.released)
    }
    pub(crate) fn observed_dialog() -> Result<Option<ObservedDialog>, native::UiError> {
        let Some((id, original, call, owner)) = original()? else { return Ok(None); };
        let action_allowed = allowed(&call, &owner)?;
        let native = original.installed_observation()?;
        Ok(Some(ObservedDialog { id, native, action_allowed, call }))
    }
    pub(crate) fn observe_dialog_action(id: u32, action: DialogAction<'_>) -> Result<bool, native::UiError> {
        let Some((actual, original, call, owner)) = original()? else { return Err(native::UiError::State); };
        if actual != id || !allowed(&call, &owner)? || owner.interrupted() { return Err(native::UiError::State); }
        // No DIALOG/GuiFacts borrow held across reentrant native button/folder
        // calls. The original Show/event/release path is the sole result owner.
        original.installed_action(action)
    }
    pub(crate) fn session_final() -> Result<bool, native::UiError> {
        if DIALOG.with(|slot| slot.try_borrow().map(|slot| slot.is_some()).map_err(|_| native::UiError::State))? {
            return Ok(false);
        }
        SESSION.with(|slot| slot.try_borrow().map_err(|_| native::UiError::State)?
            .as_ref().ok_or(native::UiError::State)?.original.observed_finality())
    }
}

#[cfg(test)]
mod tests {
    use super::{StartupOrder, StartupPhase};
    #[test]
    fn original_blank_and_actual_hook_both_precede_one_packaged_navigation() {
        for hook_first in [false, true] {
            let mut order = StartupOrder::default();
            if hook_first { assert!(order.installed()); }
            assert_eq!(order.navigation(true), Some(true));
            assert!(order.page(true, false));
            assert!(!order.claim_navigation());
            assert!(order.page(true, true));
            if !hook_first { assert!(!order.claim_navigation()); assert!(order.installed()); }
            assert!(order.claim_navigation());
            assert!(!order.claim_navigation());
            assert_eq!(order.navigation(false), None);
            assert!(!order.page(false, false));
            assert!(!order.page(false, true));
        }
    }
    #[test]
    fn startup_never_admits_unordered_repeat_or_replacement_blank() {
        for scenario in 0..5 {
            let mut order = StartupOrder::default();
            match scenario {
                0 => { order.page(true, true); },
                1 => { order.navigation(true); order.navigation(true); },
                2 => { order.page(true, false); order.page(true, false); },
                3 => { order.navigation(false); },
                _ => { order.installed(); order.page(true, false); order.page(true, true);
                    assert!(order.claim_navigation()); order.page(true, true); },
            }
            assert_eq!(order.phase, StartupPhase::Lost);
            assert!(!order.installed());
            assert!(!order.claim_navigation());
            assert_eq!(order.navigation(false), Some(false));
        }
    }
}
