//! Windows normal document and two owned native dialogs. Native COM/Win32
//! calls stay in the private platform crate; this crate forbids unsafe code.
use super::*;
use std::{cell::RefCell, path::PathBuf, rc::Rc};
use crate::asset_session::GuiCall;
use mrk_windows_installed_native::ui as native;

pub(super) use crate::windows_startup::{EventRoute, REQUEST_URI, SCHEME};
use crate::windows_startup::{DOCUMENT_URI, PACKAGED_URI, ReplyKind, StartupOrder};
use std::sync::OnceLock;
use crate::windows_startup::diagnostic::{Event, NativeError, NativeMark, Stage, UrlClass};
use mrk_windows_installed_native::ui_startup_data::{Loss, NativeMark as NativeSignal};

type StartupBook = StartupOrder<tauri::WebviewWindow, tauri::UriSchemeResponder>;
pub(super) struct Startup {
    document: OnceLock<DocumentBinding>,
    order: Mutex<StartupBook>,
    user_data: OnceLock<PathBuf>,
    thread: std::thread::ThreadId,
    publication: native::StartupPublication,
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "windows-installed-observation", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "windows-runtime-publisher"), not(feature = "macos-installed-installer")))]
    observer_diagnostic: OnceLock<Arc<mrk_windows_installed_native::ObserverDiagnostic>>,
}
#[derive(Clone, Copy)]
enum Entered { Callback, Reply(ReplyKind), Navigation, WindowRelease }
struct OriginalCall<'a> { startup: &'a Startup, kind: Entered, returned: bool }
impl<'a> OriginalCall<'a> {
    fn new(startup: &'a Startup, kind: Entered) -> Self {
        if matches!(kind, Entered::Callback) { startup.with_order(|book| book.callback_entered()); }
        let call = Self { startup, kind, returned: false };
        // Register the existing call guard before new diagnostic bookkeeping
        // or USER32 effects. Window release has already retired the channel.
        match kind {
            Entered::Reply(kind) => startup.with_order(|book| book.note(Event::ReplyEnter, u8::from(kind == ReplyKind::Refused))),
            Entered::Navigation => startup.with_order(|book| book.note(Event::NavigateEnter, 0)),
            Entered::Callback | Entered::WindowRelease => {},
        }
        if matches!(kind, Entered::Reply(_) | Entered::Navigation) { startup.publish(); }
        call
    }
    fn returned(mut self, succeeded: bool) {
        self.startup.with_order(|book| match self.kind {
            Entered::Callback => book.callback_returned(),
            Entered::Reply(kind) => book.reply_returned(kind),
            Entered::Navigation => book.navigation_returned(succeeded),
            Entered::WindowRelease => book.window_release_returned(),
        });
        self.returned = true; self.startup.publish();
    }
}
impl Drop for OriginalCall<'_> {
    fn drop(&mut self) { if !self.returned {
        let (event, detail) = match self.kind {
            Entered::Callback => (Event::CallbackAbandoned, 0),
            Entered::Reply(kind) => (Event::ReplyAbandoned, u8::from(kind == ReplyKind::Refused)),
            Entered::Navigation => (Event::NavigateAbandoned, 0),
            Entered::WindowRelease => (Event::WindowReleaseAbandoned, 0),
        };
        // Preserve the original loss/property behavior. Do not add append I/O
        // to an abandoned call's Drop or use unwinding as a journal publisher.
        self.startup.with_order(|book| book.refuse(event, detail, true));
        self.startup.publish_property();
    } }
}
impl Startup {
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "windows-installed-observation", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "windows-runtime-publisher"), not(feature = "macos-installed-installer")))]
    pub(super) fn bind_observer_diagnostic(&self, diagnostic: Option<Arc<mrk_windows_installed_native::ObserverDiagnostic>>) {
        if let Some(diagnostic) = diagnostic {
            if let Err(diagnostic) = self.observer_diagnostic.set(diagnostic) { diagnostic.unavailable(); }
        }
    }
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "windows-installed-observation", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "windows-runtime-publisher"), not(feature = "macos-installed-installer")))]
    fn observer_word(&self, word: u64) {
        if let Some(diagnostic) = self.observer_diagnostic.get() {
            diagnostic.startup(word, &|| self.diagnostic_end().is_some());
        }
    }
    fn with_order<T>(&self, action: impl FnOnce(&mut StartupBook) -> T) -> T {
        let (value, lost) = {
            let mut book = match self.order.lock() {
                Ok(book) => book,
                Err(poisoned) => { let mut book = poisoned.into_inner(); book.refuse(Event::Poisoned, 0, true); book }
            };
            let value = action(&mut book);
            (value, book.is_lost())
        };
        // No startup lock is held while invalidating the original document.
        if lost { if let Some(document) = self.document.get() { document.lost(); } }
        value
    }
    // All book mutation/invalidation remains in with_order. There is deliberately
    // NO automatic publication there: native error taps must be record-only
    // until the existing fail/on_loss has invalidated the document.
    fn diagnostic_end(&self) -> Option<Option<std::time::Instant>> {
        if std::thread::current().id() != self.thread { return None; }
        let end = self.document.get()?.exit_cleanup_end();
        if end.is_some_and(|end| std::time::Instant::now() >= end) { self.publication.seal(); return None; }
        Some(end)
    }
    fn publish(&self) {
        let word = self.publish_property();
        #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "windows-installed-observation", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "windows-runtime-publisher"), not(feature = "macos-installed-installer")))]
        if let Some(word) = word { self.observer_word(word); }
        let _ = word;
    }
    fn publish_property(&self) -> Option<u64> {
        if self.diagnostic_end().is_none() { return None; }
        match self.with_order(|book| book.diagnostic().encode()) {
            // The borrowed checkpoint refreshes the ORIGINAL endpoint before
            // each property effect; it creates no endpoint, owner or retry.
            Some(word) => { self.publication.publish(word, &|| self.diagnostic_end().is_some()); Some(word) },
            None => { self.publication.seal(); None },
        }
    }
    fn bind_publication(&self, window: &tauri::WebviewWindow) {
        if self.diagnostic_end().is_none() { self.publication.seal(); return; }
        let Some(word) = self.with_order(|book| book.diagnostic().encode()) else { self.publication.seal(); return; };
        // Same actual already-built main argument, not discovery by title.
        if self.diagnostic_end().is_none() { self.publication.seal(); return; }
        match window.hwnd() {
            Ok(hwnd) => self.publication.bind(hwnd.0 as usize, word, &|| self.diagnostic_end().is_some()),
            Err(_) => self.publication.seal(),
        }
        #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "windows-installed-observation", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "windows-runtime-publisher"), not(feature = "macos-installed-installer")))]
        self.observer_word(word); // Only after original registration/adoption and property binding.
    }
    fn refuse(&self, event: Event, detail: u8, unknown: bool) {
        self.with_order(|book| book.refuse(event, detail, unknown));
        self.publish(); // Only AFTER original document invalidation, never a drive().
    }
    pub(super) fn lost(&self) { self.refuse(Event::ExternalLoss, 0, false); }
    pub(super) fn unknown(&self) { self.refuse(Event::ExternalUnknown, 0, true); }
    pub(super) fn destroyed(&self) {
        self.publication.seal(); self.refuse(Event::Destroyed, 0, false);
    }
    // Boundary codes: bind1, pre-WebView2, install3, protocol4, navigation5,
    // page6, drive7, accepted-Quit8, actual-hook9. These are fixed DATA only.
    fn on_thread(&self, boundary: u8) -> bool {
        if std::thread::current().id() == self.thread { true }
        else { self.refuse(Event::WrongThread, boundary, true); false }
    }
    fn native_mark(&self, mark: NativeSignal) {
        // Same schema source, separately compiled nominal types. Transfer only
        // checked fixed codes, never a native pointer or an error Display string.
        let Some(stage) = Stage::from_code(mark.stage as u8) else { self.publication.seal(); return; };
        let error = match mark.error {
            None => None,
            Some(error) => match NativeError::from_code(error as u8) {
                Some(error) => Some(error), None => { self.publication.seal(); return; }
            },
        };
        self.with_order(|book| book.native_mark(NativeMark { stage, part: mark.part, error }));
        // Errors are record-only until fail/on_loss (or the glue's existing
        // loss on early install Err). No native publication before adoption.
        if mark.error.is_none() && stage as u8 >= Stage::Adopted as u8 { self.publish(); }
    }
    fn native_loss(&self, reason: Loss) {
        let event = match reason {
            Loss::Stop => { self.with_order(|book| book.close_notified()); self.publish(); return; },
            Loss::Operation => Event::NativeLoss, Loss::ProcessFailed => Event::ProcessFailed,
            Loss::BrowserExited => Event::BrowserExited, Loss::CallbackUnknown => Event::NativeCallbackUnknown,
        };
        self.refuse(event, 0, false);
    }
    pub(super) fn bind(self: &Arc<Self>, document: DocumentBinding) -> Result<(), native::UiError> {
        if !self.on_thread(1) { document.lost(); return Err(native::UiError::State); }
        if self.document.set(document).is_err() { self.refuse(Event::ContextRefused, 1, true); return Err(native::UiError::State); }
        let path = SESSION.with(|slot| {
            let mut slot = slot.try_borrow_mut().map_err(|_| {
                self.with_order(|book| book.note(Event::SessionBorrowRefused, 1)); native::UiError::State
            })?;
            let session = slot.as_mut().ok_or_else(|| {
                self.with_order(|book| book.note(Event::SessionRefused, 1)); native::UiError::State
            })?;
            if session.startup.is_some() {
                self.with_order(|book| book.note(Event::SessionRefused, 17)); return Err(native::UiError::State);
            }
            let path = session.user_data.clone().ok_or_else(|| {
                self.with_order(|book| book.note(Event::SessionRefused, 33)); native::UiError::State
            })?;
            session.startup = Some(self.clone()); Ok(path)
        });
        let path = match path { Ok(path) => path, Err(error) => { self.unknown(); return Err(error); } };
        if self.user_data.set(path).is_err() { self.refuse(Event::ContextRefused, 2, true); return Err(native::UiError::State); }
        if !self.with_order(|book| book.bind_context()) { self.unknown(); return Err(native::UiError::State); }
        Ok(())
    }
    pub(super) fn user_data(&self) -> Result<&std::path::Path, native::UiError> {
        self.user_data.get().map(PathBuf::as_path).ok_or(native::UiError::State)
    }
    fn observe_stop(&self) -> bool {
        let Some(document) = self.document.get() else { self.refuse(Event::DocumentMissing, 0, true); return false; };
        if let Some(end) = document.exit_cleanup_end() {
            if std::time::Instant::now() >= end { self.publication.seal(); }
            self.with_order(|book| book.stop());
            if std::time::Instant::now() >= end {
                self.publication.seal(); self.refuse(Event::EndpointRefused, 0, true); return false;
            }
        }
        true
    }
    fn native_available(&self) -> bool {
        // Reentrant native loss/install/close callbacks may hold SESSION. Never
        // call a responder on that stack; the existing outer callback/exit owner
        // will resume this same book after the native borrow has unwound.
        let present = SESSION.with(|slot| match slot.try_borrow_mut() {
            Err(_) => None,
            Ok(slot) => {
                let original = slot.as_ref().and_then(|session| session.startup.as_ref());
                let present = original.is_some_and(|original| std::ptr::eq(original.as_ref(), self));
                Some((present, if original.is_some() { 23 } else { 7 }))
            },
        });
        if let Some((false, detail)) = present { self.refuse(Event::SessionRefused, detail, true); }
        present.is_some_and(|(present, _)| present)
    }
    fn response(kind: ReplyKind) -> tauri::http::Response<&'static [u8]> {
        use tauri::http::{header, HeaderValue, Response, StatusCode};
        let body: &'static [u8] = if kind == ReplyKind::Controlled {
            b"<!doctype html><html><head><meta charset=\"utf-8\"><title>Mobile Release Kit</title></head><body></body></html>"
        } else { b"" };
        let mut response = Response::new(body);
        *response.status_mut() = if kind == ReplyKind::Controlled { StatusCode::OK } else { StatusCode::BAD_REQUEST };
        let headers = response.headers_mut();
        headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/html; charset=utf-8"));
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        headers.insert(header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static("default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"));
        headers.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
        response
    }
    fn drive(&self) {
        if !self.on_thread(7) || !self.native_available() { return; }
        loop {
            if !self.observe_stop() { return; }
            if let Some(reply) = self.with_order(|book| book.take_reply()) {
                let call = OriginalCall::new(self, Entered::Reply(reply.kind));
                // Same creation thread: Wry executes the original response /
                // native-deferral closure inline. No locks, SESSION borrow or
                // detached task is held/started here. Its public return does
                // NOT expose GetDeferral/SetResponse/Complete HRESULT success.
                reply.original.respond(Self::response(reply.kind));
                call.returned(true);
                continue;
            }
            if !self.observe_stop() { return; }
            let Some(window) = self.with_order(|book| book.claim_navigation()) else { return; };
            let call = OriginalCall::new(self, Entered::Navigation);
            let succeeded = tauri::Url::parse(PACKAGED_URI).ok().is_some_and(|url| window.navigate(url).is_ok());
            drop(window); // Actual temporary original reference, outside the book lock.
            call.returned(succeeded);
        }
    }
    pub(super) fn protocol(&self, label: &str, request: tauri::http::Request<Vec<u8>>, responder: tauri::UriSchemeResponder) {
        let call = OriginalCall::new(self, Entered::Callback);
        let detail = u8::from(std::thread::current().id() != self.thread)
            | (u8::from(label != MAIN_WINDOW) << 1) | (u8::from(request.method() != tauri::http::Method::GET) << 2)
            | (u8::from(request.uri().to_string() != REQUEST_URI) << 3) | (u8::from(!request.body().is_empty()) << 4);
        self.with_order(|book| book.note(Event::Protocol, detail));
        let on_thread = self.on_thread(4);
        let exact = detail == 0;
        self.with_order(|book| book.request_observed(exact, detail, responder));
        // A wrong-thread responder stays in the original Unknown book; never
        // use Wry's off-thread hidden dispatch as an invented owned endpoint.
        if on_thread { self.drive(); }
        call.returned(true);
    }
    pub(super) fn navigation(&self, url: &tauri::Url) -> EventRoute {
        let call = OriginalCall::new(self, Entered::Callback);
        let controlled = url.as_str() == DOCUMENT_URI; let packaged = trusted_document(url);
        let class = UrlClass::of(controlled, packaged, url.as_str() == "about:blank");
        self.with_order(|book| book.note(Event::Navigation, class as u8));
        let mut route = if self.on_thread(5) && self.observe_stop() {
            self.with_order(|book| book.navigation_observed(controlled, packaged, class))
        } else { EventRoute::Rejected };
        if route == EventRoute::Packaged && !self.document.get().is_some_and(|document| document.navigation(trusted_document(url))) {
            self.refuse(Event::PackagedDocumentRefused, 0, false); route = EventRoute::Rejected;
        }
        self.drive();
        if self.with_order(|book| book.is_lost()) { route = EventRoute::Rejected; }
        call.returned(true); route
    }
    pub(super) fn page(&self, payload: &tauri::webview::PageLoadPayload<'_>) -> EventRoute {
        let call = OriginalCall::new(self, Entered::Callback);
        let controlled = payload.url().as_str() == DOCUMENT_URI; let packaged = trusted_document(payload.url());
        let finished = matches!(payload.event(), tauri::webview::PageLoadEvent::Finished);
        let class = UrlClass::of(controlled, packaged, payload.url().as_str() == "about:blank");
        self.with_order(|book| book.note(if finished { Event::Finished } else { Event::Started }, class as u8));
        let mut route = if self.on_thread(6) && self.observe_stop() {
            self.with_order(|book| book.page_observed(controlled, packaged, finished, class))
        } else { EventRoute::Rejected };
        if route == EventRoute::Packaged {
            if let Some(document) = self.document.get() {
                document.observe(|lifetime| match payload.event() {
                    tauri::webview::PageLoadEvent::Started => lifetime.started(trusted_document(payload.url())),
                    tauri::webview::PageLoadEvent::Finished => lifetime.finished(trusted_document(payload.url())),
                });
            } else { self.refuse(Event::DocumentMissing, 0, true); }
        }
        self.drive();
        if self.with_order(|book| book.is_lost()) { route = EventRoute::Rejected; }
        call.returned(true); route
    }
    pub(super) fn first_party_phase(&self) -> bool { self.with_order(|book| book.first_party_phase()) }
    fn finality(&self) -> bool { self.with_order(|book| book.finality()) }
    fn close_for_exit(&self, original_end: std::time::Instant) -> NativeReturn {
        let admitted = std::thread::current().id() == self.thread
            && self.document.get().is_some_and(|document| document.exit_cleanup_end() == Some(original_end))
            && std::time::Instant::now() < original_end;
        if !admitted {
            // Seal BEFORE any refusal can reach publication, including an
            // invalid supplied endpoint while the document's endpoint is live.
            self.publication.seal();
            let _ = self.on_thread(8); // Keep the original thread refusal, then original close refusal.
            self.refuse(Event::EndpointRefused, 0, true);
            return Err(native::UiError::CleanupUnknown);
        }
        self.with_order(|book| book.stop());
        self.drive();
        self.publication.retire(&|| self.diagnostic_end() == Some(Some(original_end))); // At most once, before clone release.
        if let Some(window) = self.with_order(|book| book.take_window_for_close()) {
            let call = OriginalCall::new(self, Entered::WindowRelease);
            drop(window); // Break the original app-manager cycle on the same STA.
            call.returned(true);
        }
        if self.finality() && std::time::Instant::now() < original_end { Ok(()) }
        else { Err(native::UiError::CleanupUnknown) }
    }
}

struct Session { original: native::ShellSession, user_data: Option<PathBuf>, startup: Option<Arc<Startup>> }
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
        *slot = Some(Box::new(Session { original: native::ShellSession::new(), user_data: None, startup: None }));
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
pub(super) fn startup() -> Arc<Startup> {
    Arc::new(Startup { document: OnceLock::new(), order: Mutex::new(StartupBook::default()),
        #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "windows-installed-observation", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "windows-runtime-publisher"), not(feature = "macos-installed-installer")))]
        observer_diagnostic: OnceLock::new(),
        user_data: OnceLock::new(), thread: std::thread::current().id(), publication: native::StartupPublication::default() })
}
pub(super) fn before_webview(startup: &Startup) -> Result<(), native::UiError> {
    if !startup.on_thread(2) { return Err(native::UiError::State); }
    SESSION.with(|slot| {
        let mut slot = slot.try_borrow_mut().map_err(|_| {
            startup.with_order(|book| book.note(Event::SessionBorrowRefused, 2)); native::UiError::State
        })?;
        let session = slot.as_mut().ok_or_else(|| {
            startup.with_order(|book| book.note(Event::SessionRefused, 2)); native::UiError::State
        })?;
        if !session.startup.as_ref().is_some_and(|original| std::ptr::eq(original.as_ref(), startup)) {
            startup.with_order(|book| book.note(Event::SessionRefused, 18)); return Err(native::UiError::State);
        }
        session.original.before_webview()
    })?;
    if startup.with_order(|book| book.construction_started()) { Ok(()) } else { Err(native::UiError::State) }
}
pub(super) fn install(window: &tauri::WebviewWindow, startup: Arc<Startup>) {
    if !startup.on_thread(3) { return; }
    let registered = startup.with_order(|book| { book.note(Event::Window, 0); book.register_window(window.clone()) });
    startup.bind_publication(window); // Also reports a first rejection BEFORE registration.
    if registered.is_err() { drop(registered); return; }
    if !startup.with_order(|book| book.queue_hook()) { startup.publish(); return; }
    startup.publish();
    let callback = startup.clone();
    let scheduled = window.with_webview(move |platform| {
        let call = OriginalCall::new(&callback, Entered::Callback);
        if !callback.on_thread(9) || !callback.with_order(|book| book.enter_hook()) { call.returned(true); return; }
        callback.publish();
        let lost = callback.clone();
        let installed = SESSION.with(|slot| {
            let mut slot = slot.try_borrow_mut().map_err(|_| {
                callback.with_order(|book| book.note(Event::SessionBorrowRefused, 9)); native::UiError::State
            })?;
            let session = slot.as_mut().ok_or_else(|| {
                callback.with_order(|book| book.note(Event::SessionRefused, 9)); native::UiError::State
            })?;
            session.original.install(platform.controller(), platform.environment(),
                Box::new(move |reason| lost.native_loss(reason)), &|mark| callback.native_mark(mark))
        });
        if installed.is_ok() { callback.with_order(|book| book.note(Event::NativeReturn, 0)); }
        if installed.is_ok() && callback.with_order(|book| book.accepts_hook_return()) {
            if let Some(document) = callback.document.get() {
                document.hook_installed();
                if callback.with_order(|book| book.hook_installed()) { diagnostic(b"MRKDBG_DESKTOP_BOOTSTRAP=hook-installed\n"); }
            } else { callback.refuse(Event::DocumentMissing, 0, true); }
        } else { callback.refuse(Event::HookReturnRefused, 0, false); }
        // SESSION has ended. All failure publication follows the SAME original
        // on_loss/document invalidation (including early native install Err).
        callback.publish(); callback.drive(); call.returned(true);
    });
    if scheduled.is_err() { startup.refuse(Event::HookDispatchRefused, 0, true); }
    else { startup.with_order(|book| book.note(Event::HookDispatch, 0)); startup.publish(); }
}
pub(super) fn build_failed() {
    // Wry may have created a browser before a later build/with_webview failure.
    // No successful controller/environment ownership means no deletion or
    // fabricated settlement. Keep the original profile/book, report failure.
    let startup = SESSION.with(|slot| slot.try_borrow().ok()
        .and_then(|slot| slot.as_ref().and_then(|session| session.startup.clone())));
    if let Some(startup) = startup { startup.with_order(|book| book.construction_failed()); }
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
    let Some(startup) = app.try_state::<Arc<Startup>>().map(|state| state.inner().clone()) else {
        document.lost(); return false;
    };
    let end = tokio::time::Instant::from_std(original_end);
    let closing = startup.clone();
    if !original_dispatch(app, move || {
        closing.close_for_exit(original_end)?;
        SESSION.with(|slot| {
            let mut slot = slot.try_borrow_mut().map_err(|_| native::UiError::CleanupUnknown)?;
            let session = slot.as_mut().ok_or(native::UiError::State)?;
            if !session.startup.as_ref().is_some_and(|original| Arc::ptr_eq(original, &closing)) {
                return Err(native::UiError::CleanupUnknown);
            }
            session.original.begin_close(original_end)
        })?;
        closing.close_for_exit(original_end)
    }, document, end).await { return false; }
    loop {
        if tokio::time::Instant::now() >= end { document.lost(); return false; }
        let (returned, mut joined) = oneshot::channel();
        let settling = startup.clone();
        if app.run_on_main_thread(move || {
            let result: Result<bool, native::UiError> = (|| {
                settling.close_for_exit(original_end)?;
                let native_final = SESSION.with(|slot| slot.try_borrow_mut().map_err(|_| native::UiError::CleanupUnknown)?
                    .as_mut().ok_or(native::UiError::State)?.original.settle())?;
                settling.close_for_exit(original_end)?;
                Ok(native_final && settling.finality())
            })();
            let _ = returned.send(result);
        }).is_err() { document.lost(); std::future::pending::<()>().await; }
        tokio::select! {
            result = &mut joined => match result {
                Ok(Ok(true)) if tokio::time::Instant::now() < end && startup.finality() => return true,
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
        #[cfg(feature = "windows-installed-observation")]
        native::DialogEvent::ObservationTurn => return, // Never a GUI fact/change notification.
    }
    call.changed();
}
fn show(call: Arc<GuiCall>, control: Arc<native::DialogControl>, kind: native::DialogKind,
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "windows-installed-observation",
        not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "windows-runtime-publisher"),
        not(feature = "macos-installed-installer")))]
    observation: Option<(Arc<super::installed_observation::Observation>, tauri::AppHandle)>,
) -> Result<Option<PathBuf>, Reason> {
    let Some(owner) = call.owner() else { call.not_created(Reason::DocumentLost); return Err(Reason::DocumentLost); };
    if owner.interrupted() { call.not_created(Reason::UserCancelled); return Err(Reason::UserCancelled); }
    let parent = match SESSION.with(|slot| slot.try_borrow().map_err(|_| native::UiError::State)?
        .as_ref().ok_or(native::UiError::State)?.original.dialog_parent(kind)) {
        Ok(parent) => parent,
        Err(_) => { call.not_created(Reason::SourceRefused); return Err(Reason::SourceRefused); }
    };
    let events = call.clone();
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "windows-installed-observation",
        not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "windows-runtime-publisher"),
        not(feature = "macos-installed-installer")))]
    let id = owner.id;
    let original = Rc::new(native::Dialog::new(kind, control, Box::new(move |event| {
        #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "windows-installed-observation",
            not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "windows-runtime-publisher"),
            not(feature = "macos-installed-installer")))]
        if event == native::DialogEvent::ObservationTurn {
            if let Some((q, app)) = &observation { q.modal_turn(app, id, kind, &events); }
            return;
        }
        native_event(&events, event, kind == native::DialogKind::Quit);
    })));
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
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "windows-installed-observation",
        not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "windows-runtime-publisher"),
        not(feature = "macos-installed-installer")))]
    let observation = app.try_state::<Arc<super::installed_observation::Observation>>().map(|q| (q.inner().clone(), app.clone()));
    let creating = call.clone(); let closing = control.clone(); let (done, mut joined) = oneshot::channel();
    if app.run_on_main_thread(move || {
        let result = show(creating, closing, kind,
            #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "windows-installed-observation",
                not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "windows-runtime-publisher"),
                not(feature = "macos-installed-installer")))]
            observation,
        );
        let _ = done.send(result);
    }).is_err() {
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
        let startup = SESSION.with(|slot| slot.try_borrow().map_err(|_| native::UiError::State)?
            .as_ref().and_then(|session| session.startup.clone()).ok_or(native::UiError::State))?;
        if !startup.finality() { return Ok(false); }
        let native_final = SESSION.with(|slot| slot.try_borrow().map_err(|_| native::UiError::State)?
            .as_ref().ok_or(native::UiError::State)?.original.observed_finality())?;
        Ok(native_final && startup.finality())
    }
}
