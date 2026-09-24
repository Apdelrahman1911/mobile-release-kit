//! Closed startup diagnostic DATA. No word is readiness, identity or finality.
//! Shared by the ordinary producer, original owner, and actual-book scalar tests.
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
macro_rules! codes {
    ($name:ident { $($variant:ident = $code:literal => $label:literal),+ $(,)? }) => {
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        #[repr(u8)]
        pub enum $name { $($variant = $code),+ }
        impl $name {
            pub const fn from_code(code: u8) -> Option<Self> { match code { $($code => Some(Self::$variant),)+ _ => None } }
            pub const fn label(self) -> &'static str { match self { $(Self::$variant => $label),+ } }
        }
    };
}
codes!(Event {
    New=0=>"new", Context=1=>"context", Construction=2=>"construction", Window=3=>"window-returned",
    Registered=4=>"registered", HookQueued=5=>"hook-queued", HookDispatch=6=>"hook-dispatch-returned",
    HookEntered=7=>"hook-entered", NativeEnter=8=>"native-entered", NativeReturn=9=>"native-returned",
    HookAccepted=10=>"hook-accepted", Protocol=11=>"protocol", Navigation=12=>"navigation",
    Started=13=>"started", Finished=14=>"finished", ReplyClaim=15=>"reply-claim", ReplyEnter=16=>"reply-entered",
    ReplyReturn=17=>"reply-returned", PackagedClaim=18=>"packaged-claim", NavigateEnter=19=>"navigate-entered",
    NavigateReturn=20=>"navigate-returned", Stop=21=>"stop",
    ContextRefused=22=>"context-refused", ConstructionRefused=23=>"construction-refused",
    ConstructionFailed=24=>"construction-failed", RegistrationRefused=25=>"registration-refused",
    HookQueueRefused=26=>"hook-queue-refused", HookDispatchRefused=27=>"hook-dispatch-refused",
    HookEntryRefused=28=>"hook-entry-refused", NativeRefused=29=>"native-refused", HookReturnRefused=30=>"hook-return-refused",
    ProtocolRefused=31=>"protocol-refused", NavigationRefused=32=>"navigation-refused",
    StartedRefused=33=>"started-refused", FinishedRefused=34=>"finished-refused",
    ReplySlotRefused=35=>"reply-slot-refused", ReplyReturnRefused=36=>"reply-return-refused",
    NavigateSlotRefused=37=>"navigate-slot-refused", NavigateReturnRefused=38=>"navigate-return-refused",
    CallbackCounterRefused=39=>"callback-counter-refused", WrongThread=40=>"wrong-thread",
    SessionRefused=41=>"session-refused", SessionBorrowRefused=42=>"session-borrow-refused",
    DocumentMissing=43=>"document-missing", Poisoned=44=>"order-poisoned",
    CallbackAbandoned=45=>"callback-abandoned", ReplyAbandoned=46=>"reply-abandoned",
    NavigateAbandoned=47=>"navigate-abandoned", WindowReleaseAbandoned=48=>"window-release-abandoned",
    NativeLoss=49=>"native-loss", EndpointRefused=50=>"endpoint-refused",
    WindowReleaseRefused=51=>"window-release-refused", ExternalLoss=52=>"external-loss",
    ExternalUnknown=53=>"external-unknown", ProcessFailed=54=>"process-failed",
    BrowserExited=55=>"browser-exited", NativeCallbackUnknown=56=>"native-callback-unknown",
    PackagedDocumentRefused=57=>"packaged-document-refused", Destroyed=58=>"destroyed"
});
codes!(Stage {
    None=0=>"none", Session=1=>"session-admission", SessionState=2=>"session-state", Profile=3=>"profile-path",
    Watch=4=>"watch-admission", Adopted=5=>"watch-adopted", Sta=6=>"sta", Prerequisites=7=>"prerequisites-recheck",
    Controller=8=>"controller-slot", CoreOutput=9=>"core-output", Core=10=>"core-webview2",
    ParentOutput=11=>"parent-output", Parent=12=>"parent-window", ParentPresent=13=>"parent-present",
    ParentIdentity=14=>"parent-thread", ParentProcess=15=>"parent-process", Environment=16=>"environment-slot",
    Environment5Output=17=>"environment5-output", Environment5=18=>"environment5",
    Environment7Output=19=>"environment7-output", Environment7=20=>"environment7",
    Version=21=>"version-call", VersionText=22=>"version-text", VersionMatch=23=>"version-match",
    FolderEnvironment=24=>"folder-environment", Folder=25=>"folder-call", FolderText=26=>"folder-text",
    FolderMatch=27=>"folder-match", FailedHandler=28=>"failed-handler", ExitedHandler=29=>"exited-handler",
    BrowserOutput=30=>"browser-pid-output", BrowserCore=31=>"browser-core", BrowserPid=32=>"browser-pid",
    BrowserPidCheck=33=>"browser-pid-check", BrowserLost=34=>"browser-lost", ProcessOpen=35=>"process-open",
    ProcessHandle=36=>"process-handle", ProcessIdentity=37=>"process-identity", InitialWait=38=>"initial-wait",
    ImageQuery=39=>"image-query", ImageLength=40=>"image-nonempty", ImageFit=41=>"image-length",
    ImageText=42=>"image-text", ImageMatch=43=>"image-match", ProtectedImage=44=>"protected-image",
    ProtectedMatch=45=>"protected-image-match", FailedCore=46=>"failed-core", FailedHandlerSlot=47=>"failed-handler-slot",
    FailedRegistration=48=>"failed-registration", ExitedEnvironment=49=>"exited-environment",
    ExitedHandlerSlot=50=>"exited-handler-slot", ExitedRegistration=51=>"exited-registration",
    FinalWait=52=>"final-wait", CallbackState=53=>"callback-lost", CallbackUnknown=54=>"callback-unknown", Complete=55=>"complete", BrowserBind=56=>"browser-pid-bind"
});
impl Stage {
    // Slot part0 is the original Option presence; part1 is that SAME
    // ComOriginal::get/released check. Other stages have only part0.
    fn part_valid(self, part: u8) -> bool {
        part == 0 || part == 1 && matches!(self, Self::Controller | Self::Environment | Self::FolderEnvironment |
            Self::BrowserCore | Self::FailedCore | Self::FailedHandlerSlot | Self::ExitedEnvironment | Self::ExitedHandlerSlot)
    }
}
codes!(NativeError {
    Ordinary=1=>"ordinary-context", Interactive=2=>"interactive-desktop", Runtime=3=>"managed-webview2",
    Overrides=4=>"webview2-overrides", Data=5=>"private-user-data-parent", Native=6=>"native-failure",
    Unknown=7=>"cleanup-unknown", State=8=>"original-state"
});
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Loss { Operation, Stop, ProcessFailed, BrowserExited, CallbackUnknown }
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
// NativeEnter detail is part. NativeRefused detail is (part << 4) | the
// original UiError code1..8; unassigned combinations are invalid DATA.
pub struct NativeMark { pub stage: Stage, pub part: u8, pub error: Option<NativeError> }
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum UrlClass { Controlled=1, Packaged=2, Blank=3, Other=4, Conflict=5 }
impl UrlClass {
    pub fn of(controlled: bool, packaged: bool, blank: bool) -> Self {
        match (controlled, packaged) { (true, false) => Self::Controlled, (false, true) => Self::Packaged,
            (true, true) => Self::Conflict, _ if blank => Self::Blank, _ => Self::Other }
    }
}
impl Event {
    pub fn refused(self) -> bool { self as u8 >= 22 }
    fn detail_valid(self, detail: u8, stage: Stage) -> bool { match self {
        Self::Protocol | Self::ProtocolRefused => detail <= 31,
        Self::Navigation | Self::NavigationRefused | Self::Started | Self::StartedRefused |
        Self::Finished | Self::FinishedRefused => (1..=5).contains(&detail),
        Self::NativeEnter => stage.part_valid(detail),
        Self::NativeRefused => stage.part_valid(detail >> 4) && NativeError::from_code(detail & 15).is_some(),
        Self::ContextRefused => detail <= 2,
        Self::CallbackCounterRefused | Self::WindowReleaseRefused => detail <= 1,
        Self::ReplyClaim | Self::ReplyEnter | Self::ReplyReturn | Self::ReplyReturnRefused | Self::ReplyAbandoned => detail <= 1,
        Self::WrongThread | Self::SessionBorrowRefused => (1..=9).contains(&detail),
        // Session detail low nibble is the calling boundary; high bits are
        // missing0, mismatched/already-bound1, missing prepared user-data2.
        Self::SessionRefused => (1..=9).contains(&(detail & 15)) && detail >> 4 <= 2,
        _ => detail == 0,
    } }
    fn seen(self) -> u8 { match self { Self::Protocol | Self::ProtocolRefused => 1,
        Self::Navigation | Self::NavigationRefused => 2, Self::Started | Self::StartedRefused => 4,
        Self::Finished | Self::FinishedRefused => 8, _ => 0 } }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Word {
    pub conditions: u32, pub event: Event, pub detail: u8, pub stage: Stage,
    pub first_refusal: bool, pub live: u8, pub seen: u8,
}
impl Default for Word {
    fn default() -> Self { Self { conditions: 0, event: Event::New, detail: 0, stage: Stage::None,
        first_refusal: false, live: 0, seen: 0 } }
}
impl Word {
    pub fn record(&mut self, conditions: u32, event: Event, detail: u8) {
        self.seen |= event.seen();
        if !self.first_refusal { self.conditions = conditions; self.event = event; self.detail = detail;
            self.first_refusal = event.refused(); }
    }
    pub fn native(&mut self, conditions: u32, mark: NativeMark) {
        if !self.first_refusal { self.stage = mark.stage; }
        let detail = if mark.stage.part_valid(mark.part) {
            mark.error.map_or(mark.part, |error| (mark.part << 4) | error as u8)
        } else { u8::MAX }; // Invalid closed metadata cannot truncate into a valid word.
        self.record(conditions, if mark.error.is_some() { Event::NativeRefused } else { Event::NativeEnter }, detail);
    }
    pub fn snapshot(mut self, conditions: u32) -> Self {
        if !self.first_refusal { self.conditions = conditions; }
        self.live = (((conditions >> 25) & 1) | (((conditions >> 15) & 1) << 1) | (((conditions >> 14) & 1) << 2)) as u8;
        self
    }
    pub fn encode(self) -> Option<u64> {
        if self.conditions >= (1 << 26) || self.live > 7 || self.seen > 15
            || self.first_refusal != self.event.refused() || !self.event.detail_valid(self.detail, self.stage) { return None; }
        Some(0x51u64 << 56 | self.conditions as u64 | (self.event as u64) << 26 | (self.detail as u64) << 32
            | (self.stage as u64) << 38 | (u64::from(self.first_refusal)) << 44 | (self.live as u64) << 45 | (self.seen as u64) << 48)
    }
    pub fn decode(raw: u64) -> Option<Self> {
        if raw >> 56 != 0x51 || (raw >> 52) & 15 != 0 { return None; }
        let value = Self { conditions: (raw & ((1 << 26) - 1)) as u32,
            event: Event::from_code(((raw >> 26) & 63) as u8)?, detail: ((raw >> 32) & 63) as u8,
            stage: Stage::from_code(((raw >> 38) & 63) as u8)?, first_refusal: raw & (1 << 44) != 0,
            live: ((raw >> 45) & 7) as u8, seen: ((raw >> 48) & 15) as u8 };
        (value.encode() == Some(raw)).then_some(value)
    }
}
/// Scalar publication lifecycle, shared with its real USER32 adapter. It owns
/// neither a HWND nor the integer-as-HANDLE payload. No Drop/native operation.
#[derive(Default)]
pub struct PublicationOrder { state: AtomicU8, last: AtomicU64 }
impl PublicationOrder {
    const NEW: u8 = 0; const ENTERED: u8 = 1; const LIVE: u8 = 2; const DISABLED: u8 = 3; const RETIRED: u8 = 4;
    pub fn bind(&self) -> bool { self.state.compare_exchange(Self::NEW, Self::ENTERED, Ordering::SeqCst, Ordering::SeqCst).is_ok() }
    pub fn begin(&self, word: u64) -> Option<u64> {
        if Word::decode(word).is_none() { self.seal(); return None; }
        if self.last.load(Ordering::SeqCst) == word { return None; }
        self.state.compare_exchange(Self::LIVE, Self::ENTERED, Ordering::SeqCst, Ordering::SeqCst).ok()?;
        Some(self.last.load(Ordering::SeqCst))
    }
    pub fn entered(&self) -> bool { self.state.load(Ordering::SeqCst) == Self::ENTERED }
    pub fn returned(&self, word: u64, success: bool) {
        if success { self.last.store(word, Ordering::SeqCst); }
        let _ = self.state.compare_exchange(Self::ENTERED, if success { Self::LIVE } else { Self::DISABLED }, Ordering::SeqCst, Ordering::SeqCst);
    }
    pub fn seal(&self) { self.state.store(Self::RETIRED, Ordering::SeqCst); }
    pub fn retire(&self) -> Option<u64> {
        (self.state.swap(Self::RETIRED, Ordering::SeqCst) == Self::LIVE).then(|| self.last.load(Ordering::SeqCst))
    }
}
#[cfg(test)]
pub fn scalar_contract() {
    let initial = Word::default(); let raw = initial.encode().unwrap(); assert!(raw != 0 && raw < i64::MAX as u64);
    assert_eq!(Word::decode(raw), Some(initial));
    for bit in 52..56 { assert_eq!(Word::decode(raw | 1 << bit), None); }
    assert_eq!(Word::decode(0), None); assert_eq!(Word::decode(raw | 63 << 26), None);
    assert_eq!(Word::decode(raw | 63 << 38), None);
    for code in 0..64 { if let Some(event) = Event::from_code(code) {
        for detail in 0..64 { let value = Word { event, detail, first_refusal: event.refused(), ..initial };
            assert_eq!(value.encode().is_some(), event.detail_valid(detail, Stage::None));
            if let Some(word) = value.encode() { assert_eq!(Word::decode(word), Some(value)); }
        }
    } }
    for code in 0..64 { if let Some(stage) = Stage::from_code(code) {
        for part in 0..4 { let mut value = initial;
            value.native(0, NativeMark { stage, part, error: Some(NativeError::State) });
            assert_eq!(value.encode().is_some(), stage.part_valid(part));
            if let Some(raw) = value.encode() { assert_eq!(Word::decode(raw), Some(value)); }
        }
    } }
    let mut first = initial; first.native(17, NativeMark { stage: Stage::FolderMatch, part: 0, error: Some(NativeError::Data) });
    first.native(99, NativeMark { stage: Stage::Complete, part: 0, error: None }); first.record(99, Event::Stop, 0);
    let after = first.snapshot((1 << 25) | (1 << 15) | (1 << 14));
    assert_eq!((after.conditions, after.event, after.stage, after.detail), (17, Event::NativeRefused, Stage::FolderMatch, 5));
    assert_eq!(after.live, 7);
    for value in [Word { conditions: 1 << 26, ..initial }, Word { live: 8, ..initial },
        Word { seen: 16, ..initial }, Word { first_refusal: true, ..initial },
        Word { event: Event::NativeRefused, first_refusal: true, detail: 15, ..initial }] { assert!(value.encode().is_none()); }
    let mut slot = initial;
    slot.native(7, NativeMark { stage: Stage::Controller, part: 1, error: Some(NativeError::State) });
    assert_eq!(slot.detail, 24); assert_eq!(Word::decode(slot.encode().unwrap()), Some(slot));
    assert!(Word { stage: Stage::Parent, ..slot }.encode().is_none());
    let order = PublicationOrder::default(); assert_eq!(order.begin(raw), None);
    assert!(order.bind()); assert!(!order.bind()); order.returned(raw, true);
    assert_eq!(order.begin(raw), None); let next = after.encode().unwrap(); assert_eq!(order.begin(next), Some(raw));
    order.returned(next, false); assert_eq!(order.begin(next), None); assert!(!order.bind()); assert_eq!(order.retire(), None);
    let order = PublicationOrder::default(); assert!(order.bind()); order.returned(raw, true);
    assert_eq!(order.retire(), Some(raw)); assert_eq!(order.retire(), None); assert_eq!(order.begin(next), None);
    let order = PublicationOrder::default(); order.seal(); assert!(!order.bind()); assert_eq!(order.begin(raw), None);
    let order = PublicationOrder::default(); assert!(order.bind()); order.returned(raw, true);
    assert_eq!(order.begin(0), None); assert_eq!(order.begin(next), None); assert_eq!(order.retire(), None);
    let order = PublicationOrder::default(); assert!(order.bind()); order.seal(); order.returned(raw, true);
    assert!(!order.entered()); assert_eq!(order.retire(), None); assert_eq!(order.begin(next), None);
}
