//! The actual Windows controlled-document book, independent of native APIs.
//! Generic slots contain the original window/responder in production. Tests
//! exercise this same book; no scalar transition certifies native completion.

// The identical pure schema source is included here so cfg(test) contracts
// exercise it in the actual headless/observer crate, not in a dependency built
// without cfg(test). Only integer codes cross the private native boundary.
#[path = "../../native/windows-installed-native/src/ui_startup_data.rs"]
pub(crate) mod diagnostic;
use diagnostic::{Event, NativeMark, UrlClass, Word};

pub(crate) const SCHEME: &str = "mrk-startup";
pub(crate) const REQUEST_URI: &str = "mrk-startup://localhost/";
pub(crate) const DOCUMENT_URI: &str = "http://mrk-startup.localhost/";
pub(crate) const PACKAGED_URI: &str = "http://tauri.localhost/";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EventRoute { Controlled, Packaged, Rejected }
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReplyKind { Controlled, Refused }
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase { Controlled, Packaged, Lost }

pub(crate) struct Reply<R> { pub(crate) kind: ReplyKind, pub(crate) original: R }
pub(crate) struct StartupOrder<W, R> {
    phase: Phase,
    diagnostic: Word,
    context: bool,
    construction: bool,
    navigation: bool,
    requested: bool,
    registered: bool,
    hook_queued: bool,
    hook_entered: bool,
    hook: bool,
    positive_reply: bool,
    reply_returned: bool,
    started: bool,
    finished: bool,
    packaged_claimed: bool,
    navigation_entered: bool,
    stopping: bool,
    unknown: bool,
    callbacks: u32,
    replies: Option<ReplyKind>,
    window: Option<W>,
    pending: Option<R>,
    // Only a valid original is intentionally delayed. Invalid/reentrant or
    // wrong-thread requests retain their actual responders until same-STA
    // refusal is possible; they never replace the original or gain authority.
    refused: Vec<R>,
    window_release_entered: bool,
    window_released: bool,
}
impl<W, R> Default for StartupOrder<W, R> {
    fn default() -> Self {
        Self { phase: Phase::Controlled, diagnostic: Word::default(), context: false, construction: false,
            navigation: false, requested: false, registered: false, hook_queued: false, hook_entered: false,
            hook: false, positive_reply: false, reply_returned: false, started: false,
            finished: false, packaged_claimed: false, navigation_entered: false,
            stopping: false, unknown: false, callbacks: 0, replies: None, window: None,
            pending: None, refused: Vec::new(), window_release_entered: false, window_released: false }
    }
}
impl<W, R> StartupOrder<W, R> {
    fn conditions(&self) -> u32 {
        [self.context, self.construction, self.navigation, self.requested, self.registered,
            self.hook_queued, self.hook_entered, self.hook, self.positive_reply, self.reply_returned,
            self.started, self.finished, self.packaged_claimed, self.navigation_entered, self.stopping, self.unknown,
            self.callbacks != 0, self.replies == Some(ReplyKind::Controlled), self.replies == Some(ReplyKind::Refused),
            self.window.is_some(), self.pending.is_some(), !self.refused.is_empty(), self.window_release_entered,
            self.window_released, self.phase == Phase::Packaged, self.phase == Phase::Lost]
            .iter().enumerate().fold(0u32, |mask, (bit, value)| mask | (u32::from(*value) << bit))
    }
    pub(crate) fn diagnostic(&self) -> Word { self.diagnostic.snapshot(self.conditions()) }
    pub(crate) fn note(&mut self, event: Event, detail: u8) { self.diagnostic.record(self.conditions(), event, detail); }
    // Record-only: native returned failures must still deliver the ORIGINAL
    // loss/invalidation before any USER32 publication. This method has no I/O.
    pub(crate) fn native_mark(&mut self, mark: NativeMark) { self.diagnostic.native(self.conditions(), mark); }
    pub(crate) fn refuse(&mut self, event: Event, detail: u8, unknown: bool) {
        self.note(event, detail); if unknown { self.unknown = true; } self.phase = Phase::Lost;
    }
    pub(crate) fn lost(&mut self) { self.refuse(Event::ExternalLoss, 0, false); }
    pub(crate) fn unknown(&mut self) { self.refuse(Event::ExternalUnknown, 0, true); }
    pub(crate) fn is_lost(&self) -> bool { self.phase == Phase::Lost }
    pub(crate) fn stop(&mut self) { self.note(Event::Stop, 0); self.stopping = true; self.phase = Phase::Lost; }
    // The existing native close deliberately notifies loss. Record that normal
    // boundary without inventing a refusal or changing its old loss authority.
    pub(crate) fn close_notified(&mut self) { self.note(Event::Stop, 0); self.phase = Phase::Lost; }
    fn active(&self) -> bool { self.phase == Phase::Controlled && !self.stopping && !self.unknown }
    pub(crate) fn bind_context(&mut self) -> bool {
        if !self.active() || self.context { self.refuse(Event::ContextRefused, 0, true); false }
        else { self.context = true; self.note(Event::Context, 0); true }
    }
    pub(crate) fn construction_started(&mut self) -> bool {
        if !self.active() || !self.context || self.construction { self.refuse(Event::ConstructionRefused, 0, true); false }
        else { self.construction = true; self.note(Event::Construction, 0); true }
    }
    pub(crate) fn construction_failed(&mut self) { self.refuse(Event::ConstructionFailed, 0, self.construction); }
    pub(crate) fn register_window(&mut self, original: W) -> Result<(), W> {
        if !self.active() || !self.context || !self.construction || self.registered {
            self.refuse(Event::RegistrationRefused, 0, true); Err(original)
        } else {
            self.window = Some(original); self.registered = true; self.note(Event::Registered, 0); Ok(())
        }
    }
    pub(crate) fn queue_hook(&mut self) -> bool {
        if !self.active() || !self.registered || self.hook_queued || self.hook_entered || self.hook {
            self.refuse(Event::HookQueueRefused, 0, true); false
        } else { self.hook_queued = true; self.note(Event::HookQueued, 0); true }
    }
    pub(crate) fn enter_hook(&mut self) -> bool {
        // Freeze refusal DATA before the original queue/entry consumption.
        // This exact admission complement changes no guard or transition below.
        if !self.hook_queued || self.hook_entered || !self.active() || !self.registered || self.hook {
            self.note(Event::HookEntryRefused, 0);
        }
        if !self.hook_queued { self.refuse(Event::HookEntryRefused, 0, true); return false; }
        self.hook_queued = false;
        if self.hook_entered { self.refuse(Event::HookEntryRefused, 0, true); return false; }
        self.hook_entered = true;
        let accepted = self.active() && self.registered && !self.hook;
        // Diagnostic only; the original false-return branch did not itself
        // change Lost/Unknown. Keep that authority decision unchanged.
        self.note(if accepted { Event::HookEntered } else { Event::HookEntryRefused }, 0); accepted
    }
    pub(crate) fn accepts_hook_return(&self) -> bool {
        self.active() && self.registered && self.hook_entered && !self.hook_queued && !self.hook
    }
    pub(crate) fn hook_installed(&mut self) -> bool {
        if !self.accepts_hook_return() { self.refuse(Event::HookReturnRefused, 0, false); false }
        else { self.hook = true; self.note(Event::HookAccepted, 0); true }
    }
    pub(crate) fn callback_entered(&mut self) {
        match self.callbacks.checked_add(1) { Some(count) => self.callbacks = count,
            None => self.refuse(Event::CallbackCounterRefused, 0, true) }
    }
    pub(crate) fn callback_returned(&mut self) {
        match self.callbacks.checked_sub(1) { Some(count) => self.callbacks = count,
            None => self.refuse(Event::CallbackCounterRefused, 1, true) }
    }
    pub(crate) fn request(&mut self, exact: bool, original: R) { self.request_observed(exact, if exact { 0 } else { 8 }, original); }
    pub(crate) fn request_observed(&mut self, exact: bool, detail: u8, original: R) {
        self.note(Event::Protocol, detail);
        if exact && self.active() && self.context && self.construction && !self.requested {
            self.requested = true; self.pending = Some(original);
        } else { self.refuse(Event::ProtocolRefused, detail, false); self.refused.push(original); }
    }
    pub(crate) fn navigation(&mut self, controlled: bool, packaged: bool) -> EventRoute {
        self.navigation_observed(controlled, packaged, UrlClass::of(controlled, packaged, false))
    }
    pub(crate) fn navigation_observed(&mut self, controlled: bool, packaged: bool, class: UrlClass) -> EventRoute {
        self.note(Event::Navigation, class as u8);
        match self.phase {
            Phase::Controlled if self.active() && self.construction && controlled && !packaged && !self.navigation => {
                // Native NavigationStarting may precede manager registration.
                // This is NOT Wry ContentLoading/PageLoadEvent::Started.
                self.navigation = true; EventRoute::Controlled
            }
            Phase::Packaged if packaged && !controlled && !self.stopping && !self.unknown => EventRoute::Packaged,
            _ => { self.refuse(Event::NavigationRefused, class as u8, false); EventRoute::Rejected }
        }
    }
    pub(crate) fn page(&mut self, controlled: bool, packaged: bool, finished: bool) -> EventRoute {
        self.page_observed(controlled, packaged, finished, UrlClass::of(controlled, packaged, false))
    }
    pub(crate) fn page_observed(&mut self, controlled: bool, packaged: bool, finished: bool, class: UrlClass) -> EventRoute {
        self.note(if finished { Event::Finished } else { Event::Started }, class as u8);
        let failure = if finished { Event::FinishedRefused } else { Event::StartedRefused };
        if self.phase == Phase::Packaged && packaged && !controlled && !self.stopping && !self.unknown { return EventRoute::Packaged; }
        if !self.active() || !controlled || packaged || !self.registered || !self.hook || !self.positive_reply {
            self.refuse(failure, class as u8, false); return EventRoute::Rejected;
        }
        if finished {
            if !self.started || self.finished { self.refuse(failure, class as u8, false); return EventRoute::Rejected; }
            self.finished = true;
        } else {
            if self.started || self.finished { self.refuse(failure, class as u8, false); return EventRoute::Rejected; }
            self.started = true;
        }
        EventRoute::Controlled
    }
    pub(crate) fn take_reply(&mut self) -> Option<Reply<R>> {
        // Reentrant page/request callbacks may record facts, but do not nest a
        // second responder call inside the original response/navigation call.
        if self.replies.is_some() || self.navigation_entered { return None; }
        let (kind, original) = if !self.active() {
            let original = self.pending.take().or_else(|| self.refused.pop())?;
            (ReplyKind::Refused, original)
        } else {
            if !self.context || !self.navigation || !self.registered || !self.hook || !self.requested || self.positive_reply { return None; }
            let original = match self.pending.take() { Some(original) => original,
                None => { self.refuse(Event::ReplySlotRefused, 0, true); return None; } };
            self.positive_reply = true; (ReplyKind::Controlled, original)
        };
        self.replies = Some(kind); // The actual original/kind is taken before native entry.
        self.note(Event::ReplyClaim, u8::from(kind == ReplyKind::Refused));
        Some(Reply { kind, original })
    }
    pub(crate) fn reply_returned(&mut self, kind: ReplyKind) {
        if self.replies != Some(kind) { self.refuse(Event::ReplyReturnRefused, u8::from(kind == ReplyKind::Refused), true); return; }
        // The matching original reply is still present in the refusal projection.
        if kind == ReplyKind::Controlled && (!self.positive_reply || self.reply_returned) {
            self.note(Event::ReplyReturnRefused, 0);
        }
        self.replies = None;
        if kind == ReplyKind::Controlled {
            if !self.positive_reply || self.reply_returned { self.refuse(Event::ReplyReturnRefused, 0, true); }
            else { self.reply_returned = true; }
        }
        self.note(Event::ReplyReturn, u8::from(kind == ReplyKind::Refused));
    }
    pub(crate) fn claim_navigation(&mut self) -> Option<W> where W: Clone {
        if !self.active() || !self.reply_returned || !self.started || !self.finished
            || self.replies.is_some() || self.hook_queued || self.packaged_claimed { return None; }
        let Some(original) = self.window.as_ref() else { self.refuse(Event::NavigateSlotRefused, 0, true); return None; };
        let original = original.clone();
        self.packaged_claimed = true; self.navigation_entered = true; self.phase = Phase::Packaged;
        self.note(Event::PackagedClaim, 0); Some(original)
    }
    pub(crate) fn navigation_returned(&mut self, succeeded: bool) {
        if !self.navigation_entered { self.refuse(Event::NavigateReturnRefused, 0, true); return; }
        // Preserve the refusing entered original before its unchanged completion.
        if !succeeded { self.note(Event::NavigateReturnRefused, 0); }
        self.navigation_entered = false;
        if !succeeded { self.refuse(Event::NavigateReturnRefused, 0, false); }
        else { self.note(Event::NavigateReturn, 0); }
    }
    pub(crate) fn first_party_phase(&self) -> bool {
        // Additional dispatch refusal only. Ordinary post-loss status/recovery
        // still belongs to the existing command-specific DocumentBinding gates.
        self.packaged_claimed && !self.unknown
    }
    fn calls_settled(&self) -> bool { self.callbacks == 0 && self.replies.is_none() && !self.navigation_entered && !self.hook_queued }
    pub(crate) fn take_window_for_close(&mut self) -> Option<W> {
        if !self.stopping || self.unknown || !self.calls_settled() || self.pending.is_some()
            || !self.refused.is_empty() || self.window_release_entered || self.window_released { return None; }
        let Some(original) = self.window.take() else { self.refuse(Event::WindowReleaseRefused, 0, true); return None; };
        self.window_release_entered = true; Some(original)
    }
    pub(crate) fn window_release_returned(&mut self) {
        if !self.window_release_entered || self.window.is_some() || self.window_released { self.refuse(Event::WindowReleaseRefused, 1, true); }
        else { self.window_release_entered = false; self.window_released = true; }
    }
    pub(crate) fn finality(&self) -> bool {
        self.stopping && !self.unknown && self.registered && self.window_released
            && !self.window_release_entered && self.window.is_none() && self.pending.is_none()
            && self.refused.is_empty() && self.calls_settled()
    }
}

#[cfg(test)]
mod tests {

    fn diagnostic_contract(case: u8) {
        use super::diagnostic::{NativeError, Stage};
        let mut book = StartupOrder::<(), ()>::default(); assert!(book.bind_context()); assert!(book.construction_started());
        match case {
            0 => {
                diagnostic::scalar_contract();
                assert_eq!(book.page_observed(false, false, false, UrlClass::Blank), EventRoute::Rejected);
                let first = book.diagnostic(); assert_eq!(first.event, Event::StartedRefused); assert_eq!(first.detail, 3);
                assert_eq!(first.conditions & ((1 << 4) | (1 << 7)), 0);
                assert!(book.register_window(()).is_err()); book.stop(); book.unknown();
                let after = book.diagnostic(); assert_eq!((after.event, after.conditions, after.detail), (first.event, first.conditions, 3));
                assert_eq!(after.live, 7);
            },
            1 => {
                book.request_observed(false, 2 | 4 | 8 | 16, ()); let first = book.diagnostic();
                assert_eq!(first.event, Event::ProtocolRefused); assert_eq!(first.detail, 30);
                assert_eq!(book.take_reply().unwrap().kind, ReplyKind::Refused); book.reply_returned(ReplyKind::Refused);
                assert_eq!(book.diagnostic().conditions, first.conditions); assert!(book.is_lost());
            },
            2 => {
                book.native_mark(NativeMark { stage: Stage::ParentIdentity, part: 0, error: Some(NativeError::Ordinary) });
                assert!(!book.is_lost()); // Record-only cannot replace the real native loss notification.
                book.lost(); let first = book.diagnostic(); assert_eq!(first.event, Event::NativeRefused);
                assert_eq!(first.stage, Stage::ParentIdentity); assert_eq!(first.detail, 1);
                book.native_mark(NativeMark { stage: Stage::Complete, part: 0, error: None }); assert_eq!(book.diagnostic(), first);
                for detail in 0..=36 {
                    let mut audited = constructing(); assert!(audited.register_window("original").is_ok());
                    assert!(audited.queue_hook()); audited.callback_entered(); assert!(audited.enter_hook());
                    audited.native_mark(NativeMark { stage: Stage::Prerequisites, part: 0, error: None });
                    let before = audited.conditions(); assert_eq!(before, 0x90053);
                    let mark = NativeMark { stage: Stage::WatchOverrideAudit, part: detail, error: Some(NativeError::Overrides) };
                    audited.native_mark(mark); let first = audited.diagnostic();
                    assert_eq!(first, Word { conditions: before, event: Event::NativeRefused, detail,
                        stage: Stage::WatchOverrideAudit, first_refusal: true, live: 0, seen: 0 });
                    assert_eq!(Word::decode(first.encode().unwrap()), Some(first));
                    assert_eq!(audited.conditions(), before); assert!(!audited.is_lost() && !audited.unknown);
                    assert!(audited.accepts_hook_return()); // The diagnostic did not decide loss or installation.
                    audited.native_mark(NativeMark { stage: Stage::Prerequisites, part: 0, error: Some(NativeError::Overrides) });
                    assert_eq!(audited.diagnostic(), first); assert!(!audited.is_lost());
                    audited.lost(); assert!(audited.is_lost()); assert!(!audited.hook_installed());
                    assert_eq!(audited.diagnostic(), Word { live: 1, ..first }); audited.callback_returned();
                    audited.request_observed(false, 8, 7);
                    assert_eq!(audited.navigation_observed(false, false, UrlClass::Blank), EventRoute::Rejected);
                    assert_eq!(audited.page_observed(false, false, true, UrlClass::Blank), EventRoute::Rejected);
                    assert_eq!(audited.diagnostic(), Word { live: 1, seen: 11, ..first });
                    assert!(!audited.first_party_phase()); assert!(!audited.finality());
                    audited.stop(); audited.unknown(); assert_eq!(audited.diagnostic(), Word { live: 7, seen: 11, ..first });
                    let mut earlier = constructing(); earlier.refuse(Event::WrongThread, 4, true);
                    let winner = earlier.diagnostic(); earlier.native_mark(mark); earlier.lost();
                    assert_eq!(earlier.diagnostic(), winner);
                    earlier.note(Event::Protocol, 0); assert_eq!(earlier.diagnostic(), Word { seen: 1, ..winner });
                }
            },
            _ => {
                let glue = include_str!("shell_windows.rs");
                let native = include_str!("../../native/windows-installed-native/src/ui.rs");
                let tap = glue.split("fn native_mark(").nth(1).unwrap().split("fn native_loss(").next().unwrap();
                assert!(tap.contains("mark.error.is_none()") && tap.contains("Stage::Adopted"));
                let ordered = native.split("// Record the actual returned error BEFORE fail/on_loss.").nth(1).unwrap();
                assert!(ordered.find("record(NativeMark").unwrap() < ordered.find("self.fail(error)").unwrap());
                for (signature, guard) in [
                    ("pub fn inspect(&mut self) -> UiResult<PrerequisiteFacts> {", "if self.begun || self.final_attempted || self.unknown"),
                    ("pub fn recheck(&mut self) -> UiResult<()> {", "if self.facts.is_none() || self.final_attempted || self.unknown"),
                ] {
                    let entry = native.split(signature).nth(1).unwrap();
                    assert!(entry.strip_prefix("\n        self.overrides.refusal.reset();\n        ").unwrap().starts_with(guard));
                }
                let watch = native.split("fn install_inner(&mut self, prerequisites:").nth(1).unwrap()
                    .split("self.stage(Stage::Controller, record);").next().unwrap();
                assert_eq!(watch.matches("prerequisites.recheck()").count(), 1);
                assert!(watch.contains(r#"self.stage(Stage::Prerequisites, record);
        let recheck = prerequisites.recheck();
        let refusal = prerequisites.overrides.refusal.returned(recheck.as_ref().err().map(|error| error.diagnostic()));
        if recheck == Err(UiError::RuntimeOverrides) {
            if let Some(refusal) = refusal { self.install_stage.set((Stage::WatchOverrideAudit, refusal.code())); }
        }
        recheck?;"#));
                assert_eq!(watch.matches("self.stage(").count(), 2);
                assert_eq!(watch.matches("self.install_stage.set(").count(), 1);
                assert!(!watch.contains("record(") && !watch.contains("publication") && !watch.contains("publish("));
                assert_eq!(native.matches(".refusal.reset()").count(), 3);
                assert_eq!(native.matches(".refusal.note(").count(), 3);
                assert_eq!(native.matches(".refusal.returned(").count(), 1);
                assert!(native.contains(r#"const OVERRIDE_KEYS: &[(&str, bool)] = &[
    ("SOFTWARE\\Policies\\Microsoft\\Edge\\WebView2", false),
    ("SOFTWARE\\Microsoft\\Edge\\WebView2", false),
    ("SOFTWARE\\Microsoft\\EdgeUpdate\\Clients", true),
    ("SOFTWARE\\Microsoft\\EdgeWebView", true),
];"#));
                let audit = native.split("fn absent(&mut self, root:").nth(1).unwrap().split("fn settled(&self)").next().unwrap();
                assert!(audit.contains(r#"if self.unknown || self.originals.len() >= 96 { return Err(UiError::CleanupUnknown); }
        self.originals.push(ManuallyDrop::new(Box::pin(RegistryOriginal {
            name: name.to_vec(), value: UnsafeCell::new(null_mut()), entered: false, returned: false, close_entered: false, settled: false })));
        let original = self.originals.last_mut().ok_or(UiError::State)?;
        let original = unsafe { original.as_mut().get_unchecked_mut() };
        original.entered = true;
        let result = unsafe { R::RegOpenKeyExW(root, original.name.as_ptr(), 0, R::KEY_QUERY_VALUE | view, original.value.get()) };
        if result == F::ERROR_IO_PENDING { self.unknown = true; return Err(UiError::CleanupUnknown); }
        original.returned = true;
        let handle = unsafe { *original.value.get() };"#));
                assert!(audit.contains(r#"if result == F::ERROR_FILE_NOT_FOUND || result == F::ERROR_PATH_NOT_FOUND {
            if !handle.is_null() { self.unknown = true; return Err(UiError::CleanupUnknown); }
            original.settled = true; return Ok(());
        }"#));
                assert!(audit.contains(r#"if result == F::ERROR_SUCCESS && !handle.is_null() {
            original.close_entered = true;
            if unsafe { R::RegCloseKey(handle) } != F::ERROR_SUCCESS { self.unknown = true; return Err(UiError::CleanupUnknown); }
            original.settled = true;
            self.refusal.note(OverrideRefusal::registry(probe, OverrideOpen::Present));
            return Err(UiError::RuntimeOverrides);
        }"#));
                assert!(audit.contains(r#"if !handle.is_null() { self.unknown = true; return Err(UiError::CleanupUnknown); }
        original.settled = true;
        self.refusal.note(OverrideRefusal::registry(probe, if result == F::ERROR_SUCCESS {
            OverrideOpen::SuccessNull
        } else { OverrideOpen::OtherStatusNull }));
        Err(UiError::RuntimeOverrides)"#));
                assert_eq!(audit.matches("R::RegOpenKeyExW(").count(), 1); assert_eq!(audit.matches("R::RegCloseKey(").count(), 1);
                assert_eq!(audit.matches(".refusal.note(").count(), 2);
                let drop_audit = native.split("impl Drop for RegistryAudit {").nth(1).unwrap().split("fn overrides_absent(").next().unwrap();
                assert!(drop_audit.contains("if original.settled { unsafe { ManuallyDrop::drop(original); } }"));
                assert!(!drop_audit.contains("RegCloseKey"));
                let overrides = native.split("fn overrides_absent(").nth(1).unwrap().split("// Mutable-user-parent").next().unwrap();
                assert!(overrides.starts_with("audit: &mut RegistryAudit) -> UiResult<()> {\n    audit.refusal.reset();"));
                assert!(overrides.contains(r#"for (name, _) in std::env::vars_os() {
        let units: Vec<u16> = name.encode_wide().collect();
        let prefix: Vec<u16> = "WEBVIEW2_".encode_utf16().collect();
        if units.len() >= prefix.len() && units[..prefix.len()].iter().zip(&prefix)
            .all(|(left, right)| *left == *right || *left >= b'a' as u16 && *left <= b'z' as u16 && *left - 32 == *right) {
            audit.refusal.note(Some(OverrideRefusal::ENVIRONMENT));
            return Err(UiError::RuntimeOverrides);
        }
    }"#));
                assert!(overrides.contains(r#"for (key_index, (key, user_only)) in OVERRIDE_KEYS.iter().enumerate() {
        for (hive_index, root) in [R::HKEY_CURRENT_USER, R::HKEY_LOCAL_MACHINE].iter().copied().enumerate() {
            if *user_only && root != R::HKEY_CURRENT_USER { continue; }
            for (view_index, view) in [R::KEY_WOW64_32KEY, R::KEY_WOW64_64KEY].iter().copied().enumerate() {
                let probe = OverrideProbe::from_parts(key_index, hive_index, view_index);
                audit.absent(root, &wide(key), view, probe)?;
            }
        }
    }"#));
                assert_eq!(overrides.matches("std::env::vars_os()").count(), 1); assert_eq!(overrides.matches("audit.absent(").count(), 1);
                assert!(!overrides.contains("originals.len()"));
                let close = glue.split("fn close_for_exit(").nth(1).unwrap().split("struct Session").next().unwrap();
                assert!(close.find("self.publication.seal()").unwrap() < close.find("self.on_thread(8)").unwrap());
                assert!(close.find("self.publication.retire(").unwrap() < close.find("book.take_window_for_close()").unwrap());
                assert!(close.contains("self.diagnostic_end() == Some(Some(original_end))"));
                let publisher = native.split("impl StartupPublication {").nth(1).unwrap().split("pub(crate) fn startup_property(").next().unwrap();
                for (begin, end, operation) in [
                    ("fn identity(", "fn get(", "W::GetWindowThreadProcessId"),
                    ("fn get(", "fn set(", "W::GetPropW"),
                    ("fn set(", "pub fn bind(", "W::SetPropW"),
                    ("pub fn retire(", "// The integer", "W::RemovePropW"),
                ] {
                    let body = publisher.split(begin).nth(1).unwrap().split(end).next().unwrap();
                    assert!(body.find("self.admitted(permitted)").unwrap() < body.find(operation).unwrap());
                }
                let order = glue.split("fn with_order<T>(").nth(1).unwrap().split("fn diagnostic_end(").next().unwrap();
                assert!(!order.contains("self.publish("));
                let installed = glue.split("let installed = SESSION.with(").nth(1).unwrap().split("let scheduled").next().unwrap();
                assert!(installed.find("callback.refuse(Event::HookReturnRefused").unwrap()
                    < installed.find("callback.publish(); callback.drive()").unwrap());
                assert!(glue.contains("self.publication.publish(word, &|| self.diagnostic_end().is_some())"));
                let destroyed = glue.split("fn destroyed(").nth(1).unwrap().split("fn on_thread(").next().unwrap();
                assert!(destroyed.find("publication.seal()").unwrap() < destroyed.find("self.refuse(").unwrap());
                let mut stopping = StartupOrder::<(), ()>::default(); stopping.stop(); stopping.close_notified();
                assert_eq!(stopping.diagnostic().event, Event::Stop); assert!(!stopping.diagnostic().first_refusal);
                assert!(stopping.is_lost()); assert_eq!(stopping.diagnostic().live, 5);
                assert!(native.contains("self.callbacks()?.lost(Loss::Stop)"));
                book.refuse(Event::WrongThread, 4, true); let first = book.diagnostic();
                book.refuse(Event::ReplyAbandoned, 1, true); book.stop();
                assert_eq!(book.diagnostic().event, Event::WrongThread); assert_eq!(book.diagnostic().conditions, first.conditions);
                assert!(book.diagnostic().encode().is_some()); assert!(!book.finality());
            }
        }
    }
    use super::*;
    type Book = StartupOrder<&'static str, u8>;
    fn constructing() -> Book {
        let mut book = Book::default();
        assert!(book.bind_context()); assert!(book.construction_started()); book
    }
    fn installed(book: &mut Book) {
        assert!(book.queue_hook()); book.callback_entered(); assert!(book.enter_hook());
        assert!(book.accepts_hook_return()); assert!(book.hook_installed()); book.callback_returned();
    }
    fn reply_ready() -> Book {
        let mut book = constructing();
        assert_eq!(book.navigation(true, false), EventRoute::Controlled);
        book.request(true, 7); assert!(book.register_window("original").is_ok()); installed(&mut book); book
    }
    #[test]
    fn controlled_reply_requires_original_registration_and_actual_hook() {
        diagnostic_contract(0);
        for early_request in [false, true] {
            for early_navigation in [false, true] {
                let mut book = constructing();
                if early_request { book.request(true, 7); }
                if early_navigation { assert_eq!(book.navigation(true, false), EventRoute::Controlled); }
                assert!(book.take_reply().is_none());
                assert!(book.register_window("original").is_ok());
                assert!(book.take_reply().is_none());
                assert!(book.queue_hook()); assert!(book.take_reply().is_none());
                book.callback_entered(); assert!(book.enter_hook());
                assert!(book.take_reply().is_none()); // Scheduling/entry is not returned installation.
                assert!(book.hook_installed()); book.callback_returned();
                if !early_request { assert!(book.take_reply().is_none()); book.request(true, 7); }
                if !early_navigation {
                    assert!(book.take_reply().is_none());
                    assert_eq!(book.navigation(true, false), EventRoute::Controlled);
                }
                let reply = book.take_reply().unwrap();
                assert_eq!((reply.kind, reply.original), (ReplyKind::Controlled, 7));
                assert!(book.take_reply().is_none()); assert!(!book.first_party_phase());
                assert!(!book.diagnostic().first_refusal);
            }
        }
        let mut duplicate = reply_ready();
        assert_eq!(duplicate.register_window("replacement"), Err("replacement"));
        assert_eq!(duplicate.window, Some("original"));
        assert_eq!(duplicate.take_reply().unwrap().kind, ReplyKind::Refused);
        assert!(!duplicate.first_party_phase()); assert!(duplicate.claim_navigation().is_none());
        let mut not_entered = constructing(); assert!(not_entered.register_window("original").is_ok());
        assert!(!not_entered.accepts_hook_return());
        // Defensive duplicate-entry guard still consumes only the original queue.
        let mut repeated = constructing(); assert!(repeated.register_window("original").is_ok());
        assert!(repeated.queue_hook()); repeated.hook_entered = true;
        let before = repeated.conditions(); assert_eq!(before & ((1 << 5) | (1 << 6)), (1 << 5) | (1 << 6));
        assert!(!repeated.enter_hook()); let first = repeated.diagnostic();
        assert_eq!(first.conditions, before); assert_eq!(first.event, Event::HookEntryRefused);
        assert!(first.first_refusal); assert_eq!(first.detail, 0); assert_eq!(first.live, 3);
        assert!(!repeated.hook_queued && repeated.hook_entered && repeated.unknown && repeated.is_lost());
        repeated.stop(); let later = repeated.diagnostic();
        assert_eq!((later.event, later.detail, later.stage, later.conditions), (first.event, first.detail, first.stage, first.conditions));
        assert!(later.first_refusal); assert_eq!(later.live, 7);
        assert_eq!(SCHEME, "mrk-startup");
        assert_ne!(REQUEST_URI, DOCUMENT_URI); assert_ne!(DOCUMENT_URI, PACKAGED_URI);
    }
    #[test]
    fn real_reply_return_and_ordered_events_precede_one_packaged_navigation() {
        diagnostic_contract(1);
        for reentrant in [false, true] {
            let mut book = reply_ready(); book.callback_entered();
            let reply = book.take_reply().unwrap();
            if !reentrant { book.reply_returned(reply.kind); }
            assert!(book.claim_navigation().is_none());
            assert_eq!(book.page(true, false, false), EventRoute::Controlled);
            assert!(book.claim_navigation().is_none());
            assert_eq!(book.page(true, false, true), EventRoute::Controlled);
            if reentrant {
                assert!(book.claim_navigation().is_none()); book.reply_returned(reply.kind);
            }
            assert_eq!(book.claim_navigation(), Some("original"));
            assert!(book.claim_navigation().is_none());
            assert_eq!(book.navigation(false, true), EventRoute::Packaged);
            assert_eq!(book.page(false, true, false), EventRoute::Packaged);
            assert_eq!(book.page(false, true, true), EventRoute::Packaged);
            book.navigation_returned(true); book.callback_returned();
            assert!(!book.diagnostic().first_refusal); assert_eq!(book.diagnostic().event, Event::NavigateReturn);
            assert!(book.first_party_phase()); assert!(!book.finality());
        }
        // Seed each defensive contradiction in the actual matching Controlled book.
        for duplicate_return in [false, true] {
            let mut bad = reply_ready(); let reply = bad.take_reply().unwrap();
            if duplicate_return { bad.reply_returned = true; } else { bad.positive_reply = false; }
            let before = bad.conditions(); assert_ne!(before & (1 << 17), 0);
            assert!(!bad.diagnostic().first_refusal); bad.reply_returned(reply.kind);
            let first = bad.diagnostic(); assert_eq!(first.conditions, before);
            assert_eq!(first.event, Event::ReplyReturnRefused); assert_eq!(first.detail, 0);
            assert!(first.first_refusal); assert_eq!(first.live, 3);
            assert!(bad.replies.is_none() && bad.unknown && bad.is_lost());
            assert_eq!(bad.conditions() & (1 << 17), 0); assert_eq!(bad.reply_returned, duplicate_return);
            bad.stop(); bad.reply_returned(ReplyKind::Refused); let later = bad.diagnostic();
            assert_eq!((later.event, later.detail, later.stage, later.conditions), (first.event, first.detail, first.stage, first.conditions));
            assert!(later.first_refusal); assert_eq!(later.live, 7);
        }
        let mut failed = reply_ready(); let reply = failed.take_reply().unwrap();
        failed.reply_returned(reply.kind); failed.page(true, false, false); failed.page(true, false, true);
        assert!(failed.claim_navigation().is_some());
        let before = failed.conditions(); assert_ne!(before & (1 << 13), 0);
        assert!(!failed.diagnostic().first_refusal); failed.navigation_returned(false);
        let first = failed.diagnostic(); assert_eq!(first.conditions, before);
        assert_eq!(first.event, Event::NavigateReturnRefused); assert_eq!(first.detail, 0);
        assert!(first.first_refusal); assert_eq!(first.live, 1);
        assert!(!failed.navigation_entered && !failed.unknown); assert_eq!(failed.conditions() & (1 << 13), 0);
        assert!(failed.is_lost()); assert!(failed.claim_navigation().is_none());
        assert!(failed.first_party_phase()); // Existing command gates still own post-loss status/recovery.
        failed.stop(); failed.unknown(); let later = failed.diagnostic();
        assert_eq!((later.event, later.detail, later.stage, later.conditions), (first.event, first.detail, first.stage, first.conditions));
        assert!(later.first_refusal); assert_eq!(later.live, 7);
    }
    #[test]
    fn late_blank_replacement_or_unordered_callbacks_cannot_rearm() {
        diagnostic_contract(2);
        for case in 0..9 {
            let mut book = reply_ready();
            match case {
                0 => { assert_eq!(book.page(true, false, false), EventRoute::Rejected); }
                1 => { book.take_reply(); assert_eq!(book.page(true, false, true), EventRoute::Rejected); }
                2 => { book.take_reply(); book.page(true, false, false); assert_eq!(book.page(true, false, false), EventRoute::Rejected); }
                3 => { assert_eq!(book.navigation(true, false), EventRoute::Rejected); }
                4 => { assert_eq!(book.navigation(false, false), EventRoute::Rejected); }
                5 => { book.request(false, 9); }
                6 => { book.request(true, 9); }
                7 => { book.unknown(); }
                _ => {
                    let reply = book.take_reply().unwrap(); book.reply_returned(reply.kind);
                    book.page(true, false, false); book.page(true, false, true); book.claim_navigation();
                    book.navigation_returned(true);
                    assert_eq!(book.page(true, false, true), EventRoute::Rejected);
                }
            }
            assert!(book.is_lost()); assert!(!book.hook_installed());
            assert!(book.claim_navigation().is_none());
            assert_eq!(book.navigation(false, true), EventRoute::Rejected);
            assert_eq!(book.page(false, true, true), EventRoute::Rejected);
        }
        let mut book = reply_ready(); book.request(true, 9);
        let original = book.take_reply().unwrap();
        assert_eq!((original.kind, original.original), (ReplyKind::Refused, 7));
        book.reply_returned(original.kind);
        let duplicate = book.take_reply().unwrap(); assert_eq!((duplicate.kind, duplicate.original), (ReplyKind::Refused, 9));
    }
    #[test]
    fn original_reply_and_window_custody_gate_shutdown_finality() {
        diagnostic_contract(3);
        let mut book = reply_ready(); book.callback_entered(); book.stop();
        assert!(!book.first_party_phase()); assert!(book.claim_navigation().is_none());
        assert!(book.take_window_for_close().is_none());
        let reply = book.take_reply().unwrap(); assert_eq!(reply.kind, ReplyKind::Refused);
        assert!(!book.finality()); assert!(book.take_window_for_close().is_none());
        book.reply_returned(reply.kind); assert!(book.take_window_for_close().is_none());
        book.callback_returned(); let original = book.take_window_for_close().unwrap();
        assert_eq!(original, "original"); assert!(!book.finality());
        // Production calls this only after dropping that original on the STA.
        book.window_release_returned(); assert!(book.finality());
        book.callback_entered(); book.request(false, 9); assert!(!book.finality());
        let late = book.take_reply().unwrap(); book.reply_returned(late.kind);
        book.callback_returned(); assert!(book.finality()); assert!(!book.first_party_phase());
        for case in 0..6 {
            let mut unknown = reply_ready();
            match case {
                0 => { unknown.callback_entered(); unknown.unknown(); }
                1 => { unknown.take_reply(); unknown.unknown(); }
                2 => { unknown.callbacks = u32::MAX; unknown.callback_entered(); }
                3 => { unknown.window_release_returned(); }
                4 => { unknown.construction_failed(); }
                _ => { unknown.take_reply(); unknown.reply_returned(ReplyKind::Refused); }
            }
            unknown.stop();
            assert!(unknown.take_window_for_close().is_none()); assert!(!unknown.finality());
            assert!(unknown.claim_navigation().is_none()); assert!(!unknown.bind_context());
        }
        let mut queued = constructing(); assert!(queued.register_window("original").is_ok());
        assert!(queued.queue_hook()); queued.stop();
        assert!(queued.take_window_for_close().is_none()); assert!(!queued.finality());
        queued.callback_entered();
        assert_eq!(queued.diagnostic().event, Event::Stop); assert!(!queued.diagnostic().first_refusal);
        let before = queued.conditions(); assert_eq!(before & ((1 << 5) | (1 << 6)), 1 << 5);
        assert!(!queued.enter_hook()); let first = queued.diagnostic();
        assert_eq!(first.conditions, before); assert_eq!(first.event, Event::HookEntryRefused);
        assert!(first.first_refusal); assert_eq!(first.detail, 0); assert_eq!(first.live, 5);
        assert!(!queued.hook_queued && queued.hook_entered && !queued.unknown && queued.is_lost());
        assert!(queued.take_window_for_close().is_none()); queued.callback_returned();
        assert_eq!(queued.take_window_for_close(), Some("original"));
        queued.window_release_returned(); assert!(queued.finality());
        let later = queued.diagnostic();
        assert_eq!((later.event, later.detail, later.stage, later.conditions), (first.event, first.detail, first.stage, first.conditions));
        assert!(later.first_refusal); assert_eq!(later.live, 5);
    }
}
