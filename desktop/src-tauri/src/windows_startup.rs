//! The actual Windows controlled-document book, independent of native APIs.
//! Generic slots contain the original window/responder in production. Tests
//! exercise this same book; no scalar transition certifies native completion.

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
        Self { phase: Phase::Controlled, context: false, construction: false,
            navigation: false, requested: false, registered: false, hook_queued: false, hook_entered: false,
            hook: false, positive_reply: false, reply_returned: false, started: false,
            finished: false, packaged_claimed: false, navigation_entered: false,
            stopping: false, unknown: false, callbacks: 0, replies: None, window: None,
            pending: None, refused: Vec::new(), window_release_entered: false, window_released: false }
    }
}
impl<W, R> StartupOrder<W, R> {
    pub(crate) fn lost(&mut self) { self.phase = Phase::Lost; }
    pub(crate) fn unknown(&mut self) { self.unknown = true; self.lost(); }
    pub(crate) fn is_lost(&self) -> bool { self.phase == Phase::Lost }
    pub(crate) fn stop(&mut self) { self.stopping = true; self.lost(); }
    fn active(&self) -> bool { self.phase == Phase::Controlled && !self.stopping && !self.unknown }
    pub(crate) fn bind_context(&mut self) -> bool {
        if !self.active() || self.context { self.unknown(); false }
        else { self.context = true; true }
    }
    pub(crate) fn construction_started(&mut self) -> bool {
        if !self.active() || !self.context || self.construction { self.unknown(); false }
        else { self.construction = true; true }
    }
    pub(crate) fn construction_failed(&mut self) {
        if self.construction { self.unknown(); } else { self.lost(); }
    }
    pub(crate) fn register_window(&mut self, original: W) -> Result<(), W> {
        if !self.active() || !self.context || !self.construction || self.registered {
            self.unknown(); Err(original)
        } else {
            self.window = Some(original); self.registered = true; Ok(())
        }
    }
    pub(crate) fn queue_hook(&mut self) -> bool {
        if !self.active() || !self.registered || self.hook_queued || self.hook_entered || self.hook {
            self.unknown(); false
        } else { self.hook_queued = true; true }
    }
    pub(crate) fn enter_hook(&mut self) -> bool {
        if !self.hook_queued { self.unknown(); return false; }
        self.hook_queued = false;
        if self.hook_entered { self.unknown(); return false; }
        self.hook_entered = true;
        self.active() && self.registered && !self.hook
    }
    pub(crate) fn accepts_hook_return(&self) -> bool {
        self.active() && self.registered && self.hook_entered && !self.hook_queued && !self.hook
    }
    pub(crate) fn hook_installed(&mut self) -> bool {
        if !self.accepts_hook_return() { self.lost(); false }
        else { self.hook = true; true }
    }
    pub(crate) fn callback_entered(&mut self) {
        match self.callbacks.checked_add(1) {
            Some(count) => self.callbacks = count,
            None => self.unknown(),
        }
    }
    pub(crate) fn callback_returned(&mut self) {
        match self.callbacks.checked_sub(1) {
            Some(count) => self.callbacks = count,
            None => self.unknown(),
        }
    }
    pub(crate) fn request(&mut self, exact: bool, original: R) {
        if exact && self.active() && self.context && self.construction && !self.requested {
            self.requested = true; self.pending = Some(original);
        } else { self.lost(); self.refused.push(original); }
    }
    pub(crate) fn navigation(&mut self, controlled: bool, packaged: bool) -> EventRoute {
        match self.phase {
            Phase::Controlled if self.active() && self.construction && controlled && !packaged && !self.navigation => {
                // Native NavigationStarting may precede manager registration.
                // This is NOT Wry ContentLoading/PageLoadEvent::Started.
                self.navigation = true; EventRoute::Controlled
            }
            Phase::Packaged if packaged && !controlled && !self.stopping && !self.unknown => EventRoute::Packaged,
            _ => { self.lost(); EventRoute::Rejected }
        }
    }
    pub(crate) fn page(&mut self, controlled: bool, packaged: bool, finished: bool) -> EventRoute {
        if self.phase == Phase::Packaged && packaged && !controlled && !self.stopping && !self.unknown {
            return EventRoute::Packaged;
        }
        if !self.active() || !controlled || packaged || !self.registered || !self.hook || !self.positive_reply {
            self.lost(); return EventRoute::Rejected;
        }
        if finished {
            if !self.started || self.finished { self.lost(); return EventRoute::Rejected; }
            self.finished = true;
        } else {
            if self.started || self.finished { self.lost(); return EventRoute::Rejected; }
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
            if !self.context || !self.navigation || !self.registered || !self.hook
                || !self.requested || self.positive_reply { return None; }
            let original = match self.pending.take() {
                Some(original) => original,
                None => { self.unknown(); return None; }
            };
            self.positive_reply = true;
            (ReplyKind::Controlled, original)
        };
        self.replies = Some(kind); // The actual original/kind is taken before native entry.
        Some(Reply { kind, original })
    }
    pub(crate) fn reply_returned(&mut self, kind: ReplyKind) {
        if self.replies != Some(kind) { self.unknown(); return; }
        self.replies = None;
        if kind == ReplyKind::Controlled {
            if !self.positive_reply || self.reply_returned { self.unknown(); }
            else { self.reply_returned = true; }
        }
    }
    pub(crate) fn claim_navigation(&mut self) -> Option<W> where W: Clone {
        if !self.active() || !self.reply_returned || !self.started || !self.finished
            || self.replies.is_some() || self.hook_queued || self.packaged_claimed { return None; }
        let Some(original) = self.window.as_ref() else { self.unknown(); return None; };
        let original = original.clone();
        self.packaged_claimed = true; self.navigation_entered = true; self.phase = Phase::Packaged;
        Some(original)
    }
    pub(crate) fn navigation_returned(&mut self, succeeded: bool) {
        if !self.navigation_entered { self.unknown(); return; }
        self.navigation_entered = false;
        if !succeeded { self.lost(); }
    }
    pub(crate) fn first_party_phase(&self) -> bool {
        // Additional dispatch refusal only. Ordinary post-loss status/recovery
        // still belongs to the existing command-specific DocumentBinding gates.
        self.packaged_claimed && !self.unknown
    }
    fn calls_settled(&self) -> bool {
        self.callbacks == 0 && self.replies.is_none() && !self.navigation_entered && !self.hook_queued
    }
    pub(crate) fn take_window_for_close(&mut self) -> Option<W> {
        if !self.stopping || self.unknown || !self.calls_settled() || self.pending.is_some()
            || !self.refused.is_empty() || self.window_release_entered || self.window_released { return None; }
        let Some(original) = self.window.take() else { self.unknown(); return None; };
        self.window_release_entered = true;
        Some(original)
    }
    pub(crate) fn window_release_returned(&mut self) {
        if !self.window_release_entered || self.window.is_some() || self.window_released { self.unknown(); }
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
            }
        }
        let mut duplicate = reply_ready();
        assert_eq!(duplicate.register_window("replacement"), Err("replacement"));
        assert_eq!(duplicate.window, Some("original"));
        assert_eq!(duplicate.take_reply().unwrap().kind, ReplyKind::Refused);
        assert!(!duplicate.first_party_phase()); assert!(duplicate.claim_navigation().is_none());
        let mut not_entered = constructing(); assert!(not_entered.register_window("original").is_ok());
        assert!(!not_entered.accepts_hook_return());
        assert_eq!(SCHEME, "mrk-startup");
        assert_ne!(REQUEST_URI, DOCUMENT_URI); assert_ne!(DOCUMENT_URI, PACKAGED_URI);
    }
    #[test]
    fn real_reply_return_and_ordered_events_precede_one_packaged_navigation() {
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
            assert!(book.first_party_phase()); assert!(!book.finality());
        }
        let mut failed = reply_ready(); let reply = failed.take_reply().unwrap();
        failed.reply_returned(reply.kind); failed.page(true, false, false); failed.page(true, false, true);
        assert!(failed.claim_navigation().is_some()); failed.navigation_returned(false);
        assert!(failed.is_lost()); assert!(failed.claim_navigation().is_none());
        assert!(failed.first_party_phase()); // Existing command gates still own post-loss status/recovery.
    }
    #[test]
    fn late_blank_replacement_or_unordered_callbacks_cannot_rearm() {
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
        queued.callback_entered(); assert!(!queued.enter_hook());
        assert!(queued.take_window_for_close().is_none()); queued.callback_returned();
        assert_eq!(queued.take_window_for_close(), Some("original"));
        queued.window_release_returned(); assert!(queued.finality());
    }
}
