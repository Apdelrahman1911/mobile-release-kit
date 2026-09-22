//! Native project/Quit panel adapter for the existing OriginalWork, not rfd's
//! compatibility future. The actual panel and completion live on the main loop.
use super::*;
use std::{cell::RefCell, path::PathBuf};
use crate::asset_session::{GuiCall, GuiFacts};
use mrk_macos_installed_native::{self as native, Panel, PanelKind, PanelResponse, PanelState};

type NativeResult = Result<(), ()>;
type DialogOutcome = Result<Option<PathBuf>, Reason>;
struct OriginalPanel {
    id: u32, panel: Option<Panel>,
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "macos-installed-observation", feature = "custom-protocol",
        not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer")))]
    observed_call: std::sync::Weak<GuiCall>,
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "macos-installed-observation", feature = "custom-protocol",
        not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer")))]
    open_release: Option<Arc<observation::OpenRelease>>,
}
thread_local! { static PANEL: RefCell<Option<OriginalPanel>> = const { RefCell::new(None) }; }

#[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "macos-installed-observation", feature = "custom-protocol",
    not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer")))]
pub(super) mod observation {
    use super::*;
    use std::{sync::atomic::{AtomicU8, Ordering}, time::Instant};
    pub(crate) use native::PanelAction;

    #[derive(Clone, Copy)]
    pub(crate) enum ObservationError {
        WrongThread, BookBorrow, OriginalCall, OriginalOwner, OriginalBinding,
        MissingFacts, MissingPanel, Ineligible, NativeObservation,
        NativeAction(Option<native::PanelActionDiagnostic>),
        OpenBinding(native::AxDiagnostic), OpenCustody,
    }
    impl ObservationError {
        pub(crate) fn reason(self) -> &'static str { match self {
            Self::WrongThread => "adapter-wrong-thread", Self::BookBorrow => "adapter-book-borrow",
            Self::OriginalCall => "adapter-original-call", Self::OriginalOwner => "adapter-original-owner",
            Self::OriginalBinding => "adapter-original-binding", Self::MissingFacts => "adapter-missing-facts",
            Self::MissingPanel => "adapter-missing-panel", Self::Ineligible => "adapter-ineligible",
            Self::NativeObservation => "adapter-native-observation", Self::NativeAction(_) => "adapter-native-action",
            Self::OpenBinding(_) => "native-ax-binding", Self::OpenCustody => "native-ax-custody",
        }}
        pub(crate) fn action_diagnostic(self) -> Option<native::PanelActionDiagnostic> {
            match self { Self::NativeAction(diagnostic) => diagnostic, _ => None }
        }
        pub(crate) fn binding_diagnostic(self) -> Option<native::AxDiagnostic> {
            match self { Self::OpenBinding(diagnostic) => Some(diagnostic), _ => None }
        }
    }
    pub(crate) struct ObservedPanel {
        pub(crate) id: u32,
        pub(crate) native: native::PanelObservation,
        /// Read-only sample, not an action permit or a settlement receipt.
        pub(crate) action_allowed: bool,
    }
    fn original(entry: &OriginalPanel) -> Result<(Arc<GuiCall>, Arc<OriginalWork>), ObservationError> {
        let call = entry.observed_call.upgrade().ok_or(ObservationError::OriginalCall)?;
        let owner = call.owner().ok_or(ObservationError::OriginalOwner)?;
        if owner.id != entry.id || !Arc::ptr_eq(&owner.gui, &call) { return Err(ObservationError::OriginalBinding); }
        Ok((call, owner))
    }
    fn allowed(call: &GuiCall, owner: &OriginalWork) -> Result<bool, ObservationError> {
        let facts = call.facts().ok_or(ObservationError::MissingFacts)?;
        Ok(!owner.interrupted() && facts.dispatched && facts.created && facts.showing && !facts.constructing
            && !facts.not_created && facts.refusal.is_none() && !facts.response && !facts.close_queued
            && !facts.destroyed && !facts.close_ack && !facts.release_queued && !facts.released)
    }
    #[repr(u8)]
    #[derive(Clone, Copy)]
    enum OpenPhase { Prepared, Entered, Returned, Retired, Unknown }
    pub(crate) struct OpenRelease(AtomicU8);
    impl OpenRelease {
        fn new() -> Self { Self(AtomicU8::new(OpenPhase::Prepared as u8)) }
        fn advance(&self, from: OpenPhase, to: OpenPhase) -> bool {
            self.0.compare_exchange(from as u8, to as u8, Ordering::SeqCst, Ordering::SeqCst).is_ok()
        }
        pub(super) fn release_ready(&self) -> bool { self.0.load(Ordering::SeqCst) == OpenPhase::Retired as u8 }
        fn enter(&self) -> bool { self.advance(OpenPhase::Prepared, OpenPhase::Entered) }
        fn no_entry(&self, custody: bool) -> bool {
            self.advance(OpenPhase::Prepared, if custody { OpenPhase::Retired } else { OpenPhase::Unknown }) && custody
        }
        fn returned(&self, cleanup: bool, custody: bool) -> bool {
            if !self.advance(OpenPhase::Entered, OpenPhase::Returned) { return false; }
            self.advance(OpenPhase::Returned, if cleanup && custody { OpenPhase::Retired } else { OpenPhase::Unknown })
                && cleanup && custody
        }
    }
    pub(crate) struct PreparedOpenInput {
        pub(crate) id: u32, identity: native::OpenIdentity,
        call: Arc<GuiCall>, owner: Arc<OriginalWork>, release: Arc<OpenRelease>,
    }
    impl PreparedOpenInput {
        /// Called only inside the scoped AX admission; never touches PANEL or
        /// AppKit. The Record caller releases its guard before any AX IPC.
        pub(crate) fn admitted(&self, after_press: bool) -> Option<bool> {
            let owner = self.call.owner()?;
            if owner.id != self.id || !Arc::ptr_eq(&owner, &self.owner) || !Arc::ptr_eq(&owner.gui, &self.call) { return None; }
            if after_press {
                // An early REAL callback/close must not be mistaken for a
                // failed pre-action gate. Poisoned custody still stays unknown.
                let _facts = self.call.facts()?; Some(true)
            } else { allowed(&self.call, &owner).ok() }
        }
        pub(crate) fn stopped(&self) -> bool { self.owner.stopped() }
        pub(crate) fn enter(&self) -> bool { self.release.enter() }
        pub(crate) fn press(&self, end: Instant, admit: impl FnMut(bool) -> Option<bool>) -> native::AxInputReturn {
            native::installed_accessibility_press(&self.identity, end, admit)
        }
        pub(crate) fn no_entry(&self, custody: bool) -> bool { self.release.no_entry(custody) }
        pub(crate) fn returned(&self, result: &native::AxInputReturn, matching: bool) -> bool {
            self.release.returned(result.report.is_some_and(|r| r.cleanup_returned),
                matching && result.custody_known && result.report.is_some_and(|r| r.diagnostic.error != "custody"))
        }
    }
    pub(crate) fn prepare_open_input(id: u32) -> Result<PreparedOpenInput, ObservationError> {
        if !native::main_thread() { return Err(ObservationError::WrongThread); }
        PANEL.with(|book| {
            let mut book = book.try_borrow_mut().map_err(|_| ObservationError::BookBorrow)?;
            let entry = book.as_mut().filter(|entry| entry.id == id).ok_or(ObservationError::OriginalBinding)?;
            if entry.open_release.is_some() { return Err(ObservationError::OpenCustody); }
            let (call, owner) = original(entry)?;
            if !allowed(&call, &owner)? || owner.interrupted() { return Err(ObservationError::Ineligible); }
            let identity = entry.panel.as_mut().ok_or(ObservationError::MissingPanel)?
                .installed_open_identity().map_err(ObservationError::OpenBinding)?;
            let release = Arc::new(OpenRelease::new());
            entry.open_release = Some(release.clone());
            Ok(PreparedOpenInput { id, identity, call, owner, release })
        })
    }
    pub(crate) fn open_release_data_check() -> bool {
        // Inert state-machine DATA: no original owner, panel or callback exists.
        for custody in [false, true] {
            let no_entry = OpenRelease::new();
            if no_entry.release_ready() || no_entry.no_entry(custody) != custody
                || no_entry.release_ready() != custody || no_entry.enter() || no_entry.no_entry(true) { return false; }
            for cleanup in [false, true] {
                let entered = OpenRelease::new();
                if !entered.enter() || entered.enter() || entered.release_ready() { return false; }
                if entered.returned(cleanup, custody) != (cleanup && custody)
                    || entered.release_ready() != (cleanup && custody) || entered.returned(true, true)
                    || entered.no_entry(true) { return false; }
            }
        }
        true
    }
    pub(crate) fn observed_panel() -> Result<Option<ObservedPanel>, ObservationError> {
        if !native::main_thread() { return Err(ObservationError::WrongThread); }
        PANEL.with(|book| {
            let mut book = book.try_borrow_mut().map_err(|_| ObservationError::BookBorrow)?;
            let Some(entry) = book.as_mut() else { return Ok(None); };
            let (call, owner) = original(entry)?;
            let action_allowed = allowed(&call, &owner)?;
            let native = entry.panel.as_mut().ok_or(ObservationError::MissingPanel)?
                .installed_observation().map_err(|_| ObservationError::NativeObservation)?;
            Ok(Some(ObservedPanel { id: entry.id, native, action_allowed }))
        })
    }
    pub(crate) fn observe_panel_action(id: u32, action: PanelAction<'_>) -> Result<bool, ObservationError> {
        if !native::main_thread() { return Err(ObservationError::WrongThread); }
        PANEL.with(|book| {
            let mut book = book.try_borrow_mut().map_err(|_| ObservationError::BookBorrow)?;
            let entry = book.as_mut().filter(|entry| entry.id == id).ok_or(ObservationError::OriginalBinding)?;
            let (call, owner) = original(entry)?;
            if !allowed(&call, &owner)? || owner.interrupted() { return Err(ObservationError::Ineligible); }
            // No GuiFacts lock across AppKit. The same native completion and
            // production tick retain response admission/close/release custody.
            let mut diagnostic = None;
            let returned = entry.panel.as_mut().ok_or(ObservationError::MissingPanel)?
                .installed_action(action, &mut diagnostic);
            // Only this original error carries its DATA; no later panel query,
            // successful/not-ready action, or old slot can supply diagnostics.
            returned.map_err(|_| ObservationError::NativeAction(diagnostic))
        })
    }
}

// Retained by the original coordinating task, independent of GuiCall's first
// user-facing refusal. A later known return cannot erase cleanup uncertainty.
#[derive(Default)]
struct DispatchState { cleanup_unknown: bool }
impl DispatchState {
    fn observe(&mut self, result: NativeResult) { self.cleanup_unknown |= result.is_err(); }
    fn can_continue(&self) -> bool { !self.cleanup_unknown }
    fn outcome(&mut self, facts: Option<&mut GuiFacts>, quit: bool, interrupted: bool) -> Option<DialogOutcome> {
        if !self.can_continue() { return None; } // Gate BEFORE any outcome/path consumption.
        let Some(facts) = facts else { self.observe(Err(())); return None; };
        if facts.refusal == Some(Reason::CleanupUnknown) { self.observe(Err(())); return None; }
        if facts.not_created { Some(Err(facts.refusal.unwrap_or(Reason::SourceRefused))) }
        else if facts.destroyed && facts.released && facts.close_ack && !facts.constructing {
            if let Some(reason) = facts.refusal { Some(Err(reason)) }
            else if quit || !facts.accepted { Some(Ok(None)) }
            else if interrupted { Some(Err(Reason::UserCancelled)) }
            else { Some(facts.selected.take().map(Some).ok_or(Reason::SourceRefused)) }
        } else { None }
    }
}
fn response_kind(response: PanelResponse) -> NativeResponse {
    match response { PanelResponse::Accept => NativeResponse::Accept,
        PanelResponse::Decline => NativeResponse::Decline, PanelResponse::Other => NativeResponse::Other }
}
fn uncertain(call: &Arc<GuiCall>) -> NativeResult { call.failed(Reason::CleanupUnknown); Err(()) }

fn construct(call: &Arc<GuiCall>, choice: PanelKind) -> NativeResult {
    let Some(owner) = call.owner() else { call.not_created(Reason::DocumentLost); return Ok(()); };
    if !native::main_thread() || owner.interrupted() { call.not_created(Reason::UserCancelled); return Ok(()); }
    if let Some(mut facts) = call.facts() { facts.constructing = true; } else { return uncertain(call); }
    let reserved = PANEL.with(|book| {
        let Ok(mut book) = book.try_borrow_mut() else { return Err(Reason::Busy); };
        if book.is_some() { return Err(Reason::Busy); }
        let panel = Panel::reserve().map_err(|_| Reason::SourceRefused)?;
        // Store the exact original before constructing/presenting any panel.
        *book = Some(OriginalPanel { id: owner.id, panel: Some(panel),
            #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "macos-installed-observation", feature = "custom-protocol",
                not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer")))]
            observed_call: Arc::downgrade(call),
            #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "macos-installed-observation", feature = "custom-protocol",
                not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer")))]
            open_release: None,
        }); Ok(())
    });
    if let Err(reason) = reserved {
        if let Some(mut facts) = call.facts() { facts.constructing = false; } else { return uncertain(call); }
        call.not_created(reason); return Ok(());
    }
    if let Some(mut facts) = call.facts() { facts.created = true; } else { return uncertain(call); }
    if owner.interrupted() {
        if let Some(mut facts) = call.facts() { facts.constructing = false; } else { return uncertain(call); }
        call.failed(Reason::UserCancelled); return Ok(());
    }
    let started = PANEL.with(|book| {
        let mut book = book.try_borrow_mut().map_err(|_| Reason::CleanupUnknown)?;
        let panel = book.as_mut().filter(|entry| entry.id == owner.id).and_then(|entry| entry.panel.as_mut()).ok_or(Reason::CleanupUnknown)?;
        panel.start(choice).map_err(|error| if error.kind() == std::io::ErrorKind::PermissionDenied {
            // Native start observed an unavailable/occupied parent before any
            // NSWindow/NSAlert construction. The reserved cell still closes.
            Reason::SourceRefused
        } else { Reason::CleanupUnknown })
    });
    if let Some(mut facts) = call.facts() { facts.constructing = false; facts.showing = started.is_ok(); }
    else { return uncertain(call); }
    match started {
        Ok(()) => call.presented(),
        Err(Reason::CleanupUnknown) => return uncertain(call),
        Err(reason) => call.failed(reason),
    }
    call.changed(); Ok(())
}

fn tick(call: &Arc<GuiCall>, id: u32, quit: bool) -> NativeResult {
    if !native::main_thread() { return uncertain(call); }
    let result = PANEL.with(|book| -> NativeResult {
        let mut book = book.try_borrow_mut().map_err(|_| ())?;
        let released = {
            let entry = book.as_mut().filter(|entry| entry.id == id).ok_or(())?;
            let panel = entry.panel.as_mut().ok_or(())?;
            match panel.poll() {
                Ok(PanelState::Responded { response, path }) => {
                    let first = call.facts().ok_or(())?.response == false;
                    if first {
                        #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "macos-installed-observation", feature = "custom-protocol",
                            not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer")))]
                        call.record_installed_native_response(id, response_kind(response), path.as_deref())?;
                        let admitted = call.begin_response(response_kind(response), quit);
                        if admitted == Some(true) && !quit {
                            call.selected_path(path.ok_or(Reason::SourceRefused).and_then(|path| {
                                crate::asset_source::path_hint(&path)?; Ok(path)
                            }));
                        }
                    }
                }
                Ok(PanelState::Closed) => {
                    let mut facts = call.facts().ok_or(())?;
                    facts.destroyed = true; facts.showing = false; facts.close_ack = true;
                }
                Ok(PanelState::Showing) => {}
                Err(_) => return Err(()), // No close/release native work after uncertainty.
            }
            let close = {
                let mut facts = call.facts().ok_or(())?;
                // A known pre-presentation refusal still owns its reserved native cell.
                let needed = !facts.close_queued && (facts.response || facts.refusal.is_some()
                    || call.owner().is_none_or(|owner| owner.interrupted()));
                if needed { facts.close_queued = true; } needed
            };
            if close { panel.close_once().map_err(|_| ())?; }
            let release = {
                let mut facts = call.facts().ok_or(())?;
                let ready = facts.destroyed && facts.close_ack && !facts.release_queued;
                // The original may poll/respond/close during AX IPC, but must
                // retain its exact panel/parent until actual AX retirement.
                #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "macos-installed-observation", feature = "custom-protocol",
                    not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer")))]
                let ready = ready && entry.open_release.as_ref().is_none_or(|barrier| barrier.release_ready());
                if ready { facts.release_queued = true; } ready
            };
            if !release { false } else {
                let original = entry.panel.take().ok_or(())?;
                match original.release() {
                    Ok(()) => true,
                    Err(original) => { entry.panel = Some(original); return Err(()); }
                }
            }
        };
        if released {
            // Remove only after actual native completion/dismissal and release,
            // not a callback flag, a dropped invoke, or Drop itself.
            *book = None;
            call.facts().ok_or(())?.released = true;
        }
        Ok(())
    });
    if result.is_err() { return uncertain(call); }
    call.changed(); result
}

pub(crate) async fn run_owned_dialog(app: &tauri::AppHandle, owner: &Arc<OriginalWork>, choice: DialogChoice,
    initial_folder: Option<PathBuf>) -> DialogOutcome {
    let call = owner.gui.clone();
    let kind = match (choice, initial_folder) {
        (DialogChoice::Project, None) => PanelKind::Project,
        (DialogChoice::Quit, None) => PanelKind::Quit,
        _ => { call.not_created(Reason::UnsupportedPlatform); return Err(Reason::UnsupportedPlatform); }
    };
    if native::main_thread() { call.not_created(Reason::Unqualified); return Err(Reason::Unqualified); }
    {
        let Some(mut facts) = call.facts() else { return Err(Reason::CleanupUnknown); };
        if facts.dispatched || facts.created { return Err(Reason::CleanupUnknown); }
        facts.dispatched = true;
    }
    let mut dispatch = DispatchState::default();
    // The original coordinator retains each completion receiver and its native
    // outcome. A failed dispatch/join keeps that original without another tick.
    let (done, joined) = oneshot::channel(); let creating = call.clone();
    if app.run_on_main_thread(move || { let result = construct(&creating, kind); let _ = done.send(result); }).is_err() {
        dispatch.observe(uncertain(&call)); std::future::pending::<()>().await;
    }
    dispatch.observe(match joined.await { Ok(result) => result, Err(_) => uncertain(&call) });
    loop {
        if !dispatch.can_continue() { std::future::pending::<()>().await; }
        let outcome = {
            let mut facts = call.facts();
            dispatch.outcome(facts.as_deref_mut(), matches!(choice, DialogChoice::Quit), owner.interrupted())
        };
        // A failed facts observation also vetoes outcome and the next dispatch.
        if !dispatch.can_continue() { call.failed(Reason::CleanupUnknown); std::future::pending::<()>().await; }
        if let Some(outcome) = outcome { return outcome; }
        let (done, joined) = oneshot::channel(); let observing = call.clone(); let id = owner.id;
        if app.run_on_main_thread(move || { let result = tick(&observing, id, matches!(choice, DialogChoice::Quit)); let _ = done.send(result); }).is_err() {
            dispatch.observe(uncertain(&call)); std::future::pending::<()>().await;
        }
        dispatch.observe(match joined.await { Ok(result) => result, Err(_) => uncertain(&call) });
        if dispatch.can_continue() { tokio::time::sleep(Duration::from_millis(25)).await; }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_unknown_blocks_dispatch_and_outcome_despite_first_user_refusal() {
        for reason in [Reason::SourceRefused, Reason::UserCancelled] {
            // Inert projection DATA only. No panel, callback, original owner or
            // permission is constructed by this classifier regression.
            let mut facts = GuiFacts { dispatched: true, constructing: false, created: true,
                showing: false, response: true, accepted: false, declined: false, accepted_at: None,
                destroyed: true, released: true, not_created: false, close_queued: true, close_ack: true,
                release_queued: true, selected: None, refusal: Some(reason) };
            let mut dispatch = DispatchState::default();
            assert!(dispatch.outcome(Some(&mut facts), true, false).is_some());
            dispatch.observe(Err(()));
            assert!(!dispatch.can_continue());
            assert!(dispatch.outcome(Some(&mut facts), true, false).is_none());
            dispatch.observe(Ok(())); // A later known return cannot restore admission.
            facts.not_created = true; // Nor can an otherwise-final projection.
            assert!(!dispatch.can_continue());
            assert!(dispatch.outcome(Some(&mut facts), true, false).is_none());
            assert_eq!(facts.refusal, Some(reason)); // No global first-reason semantics change.
        }
    }
    #[test]
    fn response_mapping_preserves_other_and_missing_facts_poison_dispatch() {
        assert!(response_kind(PanelResponse::Accept) == NativeResponse::Accept);
        assert!(response_kind(PanelResponse::Decline) == NativeResponse::Decline);
        assert!(response_kind(PanelResponse::Other) == NativeResponse::Other);
        let mut dispatch = DispatchState::default();
        assert!(dispatch.outcome(None, true, false).is_none());
        assert!(!dispatch.can_continue());
    }
}
