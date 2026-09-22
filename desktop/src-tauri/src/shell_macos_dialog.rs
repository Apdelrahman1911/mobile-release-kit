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
    use std::{cell::Cell, sync::atomic::{AtomicU16, Ordering}, time::Instant};
    pub(crate) use native::PanelAction;

    #[derive(Clone, Copy)]
    pub(crate) enum ObservationError {
        WrongThread, BookBorrow, OriginalCall, OriginalOwner, OriginalBinding,
        MissingFacts, MissingPanel, Ineligible, NativeObservation,
        NativeAction(Option<native::PanelActionDiagnostic>),
        OpenBinding(native::OpenDiagnostic), OpenCustody,
    }
    impl ObservationError {
        pub(crate) fn reason(self) -> &'static str { match self {
            Self::WrongThread => "adapter-wrong-thread", Self::BookBorrow => "adapter-book-borrow",
            Self::OriginalCall => "adapter-original-call", Self::OriginalOwner => "adapter-original-owner",
            Self::OriginalBinding => "adapter-original-binding", Self::MissingFacts => "adapter-missing-facts",
            Self::MissingPanel => "adapter-missing-panel", Self::Ineligible => "adapter-ineligible",
            Self::NativeObservation => "adapter-native-observation", Self::NativeAction(_) => "adapter-native-action",
            Self::OpenBinding(_) => "native-default-binding", Self::OpenCustody => "native-default-custody",
        }}
        pub(crate) fn action_diagnostic(self) -> Option<native::PanelActionDiagnostic> {
            match self { Self::NativeAction(diagnostic) => diagnostic, _ => None }
        }
        pub(crate) fn binding_diagnostic(self) -> Option<native::OpenDiagnostic> {
            match self { Self::OpenBinding(diagnostic) => Some(diagnostic), _ => None }
        }
    }
    pub(crate) struct ObservedPanel {
        pub(crate) id: u32,
        pub(crate) native: native::PanelObservation,
        /// Read-only sample, not an action permit or a settlement receipt.
        pub(crate) action_allowed: bool,
    }
    pub(super) fn original(entry: &OriginalPanel) -> Result<(Arc<GuiCall>, Arc<OriginalWork>), ObservationError> {
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
    enum OpenPhase { Prepared, Requested, Queued, Entered, Returned, Joined, Retired, Unknown }
    const OPEN_PHASE: u16 = 7;
    const OPEN_EXPIRED: u16 = 1 << 9;
    impl OpenPhase {
        fn event(self) -> u16 { match self {
            Self::Prepared | Self::Unknown => 0, _ => 1 << (self as u16 + 2),
        }}
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) struct OpenProgress {
        pub(crate) state: &'static str, pub(crate) requested: bool, pub(crate) dispatched: bool,
        pub(crate) entered: bool, pub(crate) returned: bool, pub(crate) joined: bool,
        pub(crate) retired: bool, pub(crate) expired: bool,
    }
    pub(crate) struct OpenRelease { progress: AtomicU16 }
    impl OpenRelease {
        fn new() -> Self { Self { progress: AtomicU16::new(OpenPhase::Prepared as u16) } }
        fn transition(&self, from: OpenPhase, to: OpenPhase, actual_body_event: bool) -> bool {
            let previous = self.progress.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |bits| {
                let admitted = bits & OPEN_PHASE == from as u16;
                let phase = if admitted { to } else { OpenPhase::Unknown };
                // Real wrapper entry/return is history even after custody became
                // Unknown. Failed requests/joins never invent those events.
                Some((bits & !OPEN_PHASE) | phase as u16
                    | if admitted || actual_body_event { to.event() } else { 0 })
            }).unwrap_or_else(|bits| bits);
            previous & OPEN_PHASE == from as u16
        }
        fn advance(&self, from: OpenPhase, to: OpenPhase) -> bool {
            self.transition(from, to, false)
        }
        pub(crate) fn snapshot(&self) -> OpenProgress {
            let bits = self.progress.load(Ordering::SeqCst);
            let event = |phase: OpenPhase| bits & phase.event() != 0;
            OpenProgress { state: ["prepared", "requested", "queued", "entered", "returned", "joined", "retired", "unknown"]
                [(bits & OPEN_PHASE) as usize], requested: event(OpenPhase::Requested), dispatched: event(OpenPhase::Queued),
                entered: event(OpenPhase::Entered), returned: event(OpenPhase::Returned), joined: event(OpenPhase::Joined),
                retired: event(OpenPhase::Retired), expired: bits & OPEN_EXPIRED != 0 }
        }
        pub(super) fn release_ready(&self) -> bool { self.snapshot().state == "retired" }
        fn state(&self) -> &'static str { self.snapshot().state }
        fn unknown(&self) { self.progress.fetch_or(OpenPhase::Unknown as u16, Ordering::SeqCst); }
        fn expire(&self) { self.progress.fetch_or(OPEN_EXPIRED, Ordering::SeqCst); }
        fn expired(&self) -> bool { self.snapshot().expired }
        fn no_entry(&self, custody: bool) -> bool {
            if !custody { self.unknown(); return false; }
            match self.state() {
                "prepared" => self.advance(OpenPhase::Prepared, OpenPhase::Retired),
                "requested" => self.advance(OpenPhase::Requested, OpenPhase::Retired),
                _ => { self.unknown(); false },
            }
        }
    }
    fn original_admitted(id: u32, call: &Arc<GuiCall>, original: &Arc<OriginalWork>, after_confirm: bool) -> Option<bool> {
        let owner = call.owner()?;
        if owner.id != id || !Arc::ptr_eq(&owner, original) || !Arc::ptr_eq(&owner.gui, call) { return None; }
        if after_confirm { let _facts = call.facts()?; Some(true) }
        else { allowed(call, &owner).ok() }
    }
    pub(crate) struct PreparedOpenInput {
        pub(crate) id: u32, identity: native::OpenIdentity,
        call: Arc<GuiCall>, owner: Arc<OriginalWork>, release: Arc<OpenRelease>,
    }
    impl PreparedOpenInput {
        pub(crate) fn admitted(&self, after: bool) -> Option<bool> {
            original_admitted(self.id, &self.call, &self.owner, after)
        }
        pub(crate) fn token(&self) -> OpenAction {
            OpenAction { id: self.id, identity: self.identity, call: self.call.clone(), owner: self.owner.clone(), release: self.release.clone() }
        }
        pub(crate) fn no_entry(&self, custody: bool) -> bool { self.release.no_entry(custody) }
        pub(crate) fn progress_handle(&self) -> Arc<OpenRelease> { self.release.clone() }
    }
    /// Owned scalar identity/custody only; the original native panel stays TLS.
    #[derive(Clone)]
    pub(crate) struct OpenAction {
        pub(crate) id: u32, identity: native::OpenIdentity,
        call: Arc<GuiCall>, owner: Arc<OriginalWork>, release: Arc<OpenRelease>,
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) struct OpenActionBody { pub(crate) native: Option<native::OpenInputReturn>, pub(crate) admitted: Option<bool> }
    impl OpenActionBody {
        pub(crate) fn no_native(admitted: Option<bool>) -> Self { Self { native: None, admitted } }
        pub(crate) fn custody_known(self) -> bool {
            self.admitted.is_some() && self.native.is_none_or(|n| n.custody_known)
        }
        pub(crate) fn succeeded(self) -> bool {
            self.admitted == Some(true) && self.native.is_some_and(|n|
                n.entered && n.custody_known && n.report.is_some_and(native::OpenReport::succeeded))
        }
    }
    thread_local! { static OPEN_BODY: Cell<Option<u32>> = const { Cell::new(None) }; }
    struct OpenBodyGuard { id: u32, release: Arc<OpenRelease> }
    impl OpenBodyGuard {
        fn enter(token: &OpenAction) -> Option<Self> {
            OPEN_BODY.with(|cell| {
                if cell.get().is_some() { token.unknown(); return None; }
                cell.set(Some(token.id)); Some(Self { id: token.id, release: token.release.clone() })
            })
        }
    }
    impl Drop for OpenBodyGuard {
        fn drop(&mut self) {
            OPEN_BODY.with(|cell| {
                if cell.get() != Some(self.id) { self.release.unknown(); }
                else { cell.set(None); }
            });
        }
    }
    pub(super) fn body_busy(id: u32) -> Result<bool, ()> {
        OPEN_BODY.with(|cell| match cell.get() { None => Ok(false), Some(original) if original == id => Ok(true), _ => Err(()) })
    }
    impl OpenAction {
        pub(crate) fn same(&self, other: &Self) -> bool {
            self.id == other.id && self.identity == other.identity && Arc::ptr_eq(&self.call, &other.call)
                && Arc::ptr_eq(&self.owner, &other.owner) && Arc::ptr_eq(&self.release, &other.release)
        }
        pub(crate) fn state(&self) -> &'static str { self.release.state() }
        pub(crate) fn progress(&self) -> OpenProgress { self.release.snapshot() }
        pub(crate) fn same_progress(&self, progress: &Arc<OpenRelease>) -> bool { Arc::ptr_eq(&self.release, progress) }
        pub(crate) fn request(&self) -> bool { self.release.advance(OpenPhase::Prepared, OpenPhase::Requested) }
        pub(crate) fn queue(&self) -> bool { self.release.advance(OpenPhase::Requested, OpenPhase::Queued) }
        pub(crate) fn enter(&self) -> bool { self.release.transition(OpenPhase::Queued, OpenPhase::Entered, true) }
        pub(crate) fn returned(&self) -> bool { self.release.transition(OpenPhase::Entered, OpenPhase::Returned, true) }
        pub(crate) fn joined(&self) -> bool { self.release.advance(OpenPhase::Returned, OpenPhase::Joined) }
        pub(crate) fn retire(&self) -> bool { self.release.advance(OpenPhase::Joined, OpenPhase::Retired) }
        pub(crate) fn unknown(&self) { self.release.unknown(); }
        pub(crate) fn expire(&self) { self.release.expire(); }
        pub(crate) fn expired(&self) -> bool { self.release.expired() }
        pub(crate) fn stopped(&self) -> bool { self.owner.stopped() }
        pub(crate) fn admitted(&self, after: bool) -> Option<bool> {
            original_admitted(self.id, &self.call, &self.owner, after)
        }
        pub(crate) fn run(&self, end: Instant, mut admit: impl FnMut(bool) -> Option<bool>) -> OpenActionBody {
            if !native::main_thread() || self.state() != "entered" { return OpenActionBody::no_native(None); }
            if self.expired() || Instant::now() >= end { return OpenActionBody::no_native(Some(false)); }
            let before = admit(false);
            if before != Some(true) || self.stopped() || self.expired() || Instant::now() >= end {
                return OpenActionBody::no_native(before.map(|_| false));
            }
            let Some(_body) = OpenBodyGuard::enter(self) else { return OpenActionBody::no_native(None); };
            PANEL.with(|book| {
                let Ok(mut book) = book.try_borrow_mut() else { return OpenActionBody::no_native(None); };
                let Some(entry) = book.as_mut().filter(|e| e.id == self.id) else { return OpenActionBody::no_native(None); };
                let Ok((call, owner)) = original(entry) else { return OpenActionBody::no_native(None); };
                if !Arc::ptr_eq(&call, &self.call) || !Arc::ptr_eq(&owner, &self.owner)
                    || !entry.open_release.as_ref().is_some_and(|r| Arc::ptr_eq(r, &self.release)) {
                    return OpenActionBody::no_native(None);
                }
                let before = admit(false);
                if before != Some(true) || self.state() != "entered" || self.stopped() || self.expired() || Instant::now() >= end {
                    return OpenActionBody::no_native(before.map(|_| false));
                }
                let Some(panel) = entry.panel.as_mut() else { return OpenActionBody::no_native(None); };
                // No Record/GuiFacts/owner lock survives either admission into
                // this synchronous AppKit call. Relay independently observes E.
                let returned = panel.installed_panel_confirm(&self.identity, end, |after| {
                    let allowed = admit(after);
                    if self.state() != "entered" { return None; }
                    allowed.map(|yes| yes && (after || !self.expired() && !self.stopped() && Instant::now() < end))
                });
                let after = admit(true);
                OpenActionBody { native: Some(returned), admitted: if returned.custody_known { after } else { None } }
            }) // PANEL and main-only body guard drop before wrapper publication.
        }
    }
    pub(crate) fn prepare_open_input(id: u32, returned: &mut Option<native::IdentityBindingReturn>) -> Result<PreparedOpenInput, ObservationError> {
        *returned = None;
        if !native::main_thread() { return Err(ObservationError::WrongThread); }
        PANEL.with(|book| {
            let mut book = book.try_borrow_mut().map_err(|_| ObservationError::BookBorrow)?;
            let entry = book.as_mut().filter(|entry| entry.id == id).ok_or(ObservationError::OriginalBinding)?;
            if entry.open_release.is_some() { return Err(ObservationError::OpenCustody); }
            let (call, owner) = original(entry)?;
            if !allowed(&call, &owner)? || owner.interrupted() { return Err(ObservationError::Ineligible); }
            let identity = entry.panel.as_mut().ok_or(ObservationError::MissingPanel)?
                .installed_open_identity(returned).map_err(ObservationError::OpenBinding)?;
            let release = Arc::new(OpenRelease::new());
            entry.open_release = Some(release.clone());
            Ok(PreparedOpenInput { id, identity, call, owner, release })
        })
    }
    pub(crate) fn open_release_data_check() -> bool {
        // Same state transitions as the real lifecycle, inert original-free DATA.
        for custody in [false, true] {
            let p = OpenRelease::new();
            if p.release_ready() || p.no_entry(custody) != custody || p.release_ready() != custody { return false; }
            let s = p.snapshot();
            if s.requested || s.dispatched || s.entered || s.returned || s.joined || s.retired != custody { return false; }
        }
        for expire_at in 0..=6 {
            let p = OpenRelease::new();
            let stages = [OpenPhase::Prepared, OpenPhase::Requested, OpenPhase::Queued, OpenPhase::Entered,
                OpenPhase::Returned, OpenPhase::Joined, OpenPhase::Retired];
            for i in 0..6 {
                if i == expire_at { p.expire(); }
                if p.release_ready() || !p.advance(stages[i], stages[i+1]) { return false; }
            }
            if !p.release_ready() || p.expired() != (expire_at < 6) { return false; }
            let mut saved = p.snapshot(); saved.state = "unknown";
            p.unknown();
            if p.snapshot() != saved { return false; } // Unknown preserves actual retirement history.
            if p.release_ready() || p.advance(OpenPhase::Joined, OpenPhase::Retired) || p.no_entry(true) { return false; }
        }
        let queued = OpenRelease::new();
        if !queued.advance(OpenPhase::Prepared, OpenPhase::Requested)
            || !queued.advance(OpenPhase::Requested, OpenPhase::Queued) { return false; }
        queued.unknown(); queued.expire();
        // The real wrapper may enter/return after a dispatch error made custody
        // Unknown. These facts persist; native admission and join stay refused.
        if queued.transition(OpenPhase::Queued, OpenPhase::Entered, true)
            || queued.transition(OpenPhase::Entered, OpenPhase::Returned, true)
            || queued.advance(OpenPhase::Returned, OpenPhase::Joined) || queued.release_ready() { return false; }
        if queued.snapshot() != (OpenProgress { state: "unknown", requested: true, dispatched: true,
            entered: true, returned: true, joined: false, retired: false, expired: true }) { return false; }
        let p = OpenRelease::new(); p.unknown();
        !p.advance(OpenPhase::Prepared, OpenPhase::Requested) && !p.release_ready()
    }
    pub(crate) fn observed_panel() -> Result<Option<ObservedPanel>, ObservationError> {
        if !native::main_thread() { return Err(ObservationError::WrongThread); }
        PANEL.with(|book| {
            let mut book = book.try_borrow_mut().map_err(|_| ObservationError::BookBorrow)?;
            let Some(entry) = book.as_mut() else { return Ok(None); };
            let (call, owner) = original(entry)?;
            if entry.open_release.as_ref().is_some_and(|r| !r.release_ready()) { return Err(ObservationError::Ineligible); }
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
            if entry.open_release.as_ref().is_some_and(|r| !r.release_ready())
                || !allowed(&call, &owner)? || owner.interrupted() { return Err(ObservationError::Ineligible); }
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

fn construct(call: &Arc<GuiCall>, choice: PanelKind,
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "macos-installed-observation", feature = "custom-protocol",
        not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer")))]
    observer: Option<&super::installed_observation::Observation>,
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "macos-installed-observation", feature = "custom-protocol",
        not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer")))]
    identity_return: &mut Option<(u32, native::IdentityStartReturn)>,
) -> NativeResult {
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
        let entry = book.as_mut().filter(|entry| entry.id == owner.id).ok_or(Reason::CleanupUnknown)?;
        #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "macos-installed-observation", feature = "custom-protocol",
            not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer")))]
        let arm = observer.filter(|q| q.open_identity_scope(owner.id, choice));
        #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "macos-installed-observation", feature = "custom-protocol",
            not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer")))]
        if let Some(q) = arm {
            let (bound_call, bound_owner) = observation::original(entry).map_err(|_| Reason::CleanupUnknown)?;
            if !Arc::ptr_eq(&bound_call, call) || !Arc::ptr_eq(&bound_owner, &owner)
                || bound_owner.interrupted() || !q.timely() { return Err(Reason::CleanupUnknown); }
        }
        let panel = entry.panel.as_mut().ok_or(Reason::CleanupUnknown)?;
        #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "macos-installed-observation", feature = "custom-protocol",
            not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer")))]
        if arm.is_some() { panel.installed_arm_open_identity().map_err(|_| Reason::CleanupUnknown)?; }
        // Keep the original PANEL borrow, but no Record/GuiFacts guard, across
        // this SAME start. There is no per-getter observer callback in AppKit.
        let returned = panel.start(choice);
        #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "macos-installed-observation", feature = "custom-protocol",
            not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer")))]
        if arm.is_some() { *identity_return = panel.take_installed_identity_start_return().map(|data| (owner.id, data)); }
        returned.map_err(|error| if error.kind() == std::io::ErrorKind::PermissionDenied {
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
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "macos-installed-observation", feature = "custom-protocol",
        not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer")))]
    match observation::body_busy(id) { Ok(true) => return Ok(()), Ok(false) => {}, Err(()) => return uncertain(call) }
    let result = PANEL.with(|book| -> NativeResult {
        let mut book = book.try_borrow_mut().map_err(|_| ())?;
        let released = {
            let entry = book.as_mut().filter(|entry| entry.id == id).ok_or(())?;
            #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "macos-installed-observation", feature = "custom-protocol",
                not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer")))]
            if entry.open_release.as_ref().is_some_and(|r| !r.release_ready()) { return Ok(()); }
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
                // The whole original poll/close path is gated above; release
                // independently requires actual body/receipt retirement too.
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
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "macos-installed-observation", feature = "custom-protocol",
        not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer")))]
    let observer = app.try_state::<Arc<super::installed_observation::Observation>>().map(|q| q.inner().clone());
    if app.run_on_main_thread(move || {
        #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "macos-installed-observation", feature = "custom-protocol",
            not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer")))]
        let mut identity_return = None;
        let result = construct(&creating, kind,
            #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "macos-installed-observation", feature = "custom-protocol",
                not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer")))]
            observer.as_deref(),
            #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "macos-installed-observation", feature = "custom-protocol",
                not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer")))]
            &mut identity_return,
        );
        #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "macos-installed-observation", feature = "custom-protocol",
            not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer")))]
        if let (Some(q), Some((id, data))) = (observer.as_ref(), identity_return) {
            // Original construct has returned and PANEL/GuiFacts guards are
            // gone. Publish only its saved scalar DATA, before the same send.
            q.identity_start_returned(id, data);
        }
        let _ = done.send(result);
    }).is_err() {
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
