//! Closed qualification-only DATA and the append attempt's finite ordering.
//! No native API, paths, handles, SIDs, arbitrary text, clock or application owner.
use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use crate::ui_startup_data::{Event as StartupEvent, Word};

pub const RECORD_LIMIT: usize = 512;
pub const RECORDS: u8 = 64;
pub const BYTE_LIMIT: usize = 32 * 1024;
pub const IDENTITY_ENV: &str = "MRK_WINDOWS_NORMAL_UI_DIAGNOSTIC_IDENTITY";
pub const SUFFIX: &str = "observer-diagnostic.private.jsonl";
pub const EXECUTION_MS: u64 = 90_000;
pub const DIAGNOSTIC_MS: u64 = 110_000;

/// Clock samples are caller-owned DATA. This never samples/renews a clock.
pub fn window_sample(entry: u64, end: u64, now: u64, instant_live: bool, latched: &AtomicBool) -> bool {
    latched.fetch_or(now < entry || now >= end || !instant_live, Ordering::SeqCst);
    !latched.load(Ordering::SeqCst)
}
#[derive(Default)]
pub struct InventoryOrder { attempted: bool, failure: bool }
impl InventoryOrder {
    pub fn attempted(&mut self) { self.attempted = true; }
    pub fn failure(&self) -> bool { self.failure }
    pub fn select_failure(&mut self, child_final: bool, never_started: bool) -> bool {
        if !child_final || !never_started || self.attempted || self.failure { return false; }
        self.failure = true; true
    }
}
#[derive(Clone, Copy, Default)]
pub struct ChildFinality {
    pub returned: bool, pub created: bool, pub signaled: bool, pub exit_observed: bool,
    pub process_closed: bool, pub thread_closed: bool, pub unknown: bool,
}
impl ChildFinality {
    pub fn admitted(self) -> bool { self.returned && self.created && self.signaled && self.exit_observed
        && self.process_closed && self.thread_closed && !self.unknown }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AppendPhase { Inspect, Write, InspectWritten, Close }
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AppendReturn { Complete, Refused, Unresolved }
/// Only this journal's one attempt. The native caller already retains its
/// original and all buffers, and MUST park with them on Unresolved. A Close
/// refusal is unresolved; an operation Unknown never permits even a close.
pub fn append_once(mut call: impl FnMut(AppendPhase) -> AppendReturn) -> AppendReturn {
    let mut outcome = AppendReturn::Complete;
    for phase in [AppendPhase::Inspect, AppendPhase::Write, AppendPhase::InspectWritten] {
        outcome = call(phase);
        match outcome { AppendReturn::Complete => (), AppendReturn::Refused => break,
            AppendReturn::Unresolved => return AppendReturn::Unresolved }
    }
    if call(AppendPhase::Close) != AppendReturn::Complete { AppendReturn::Unresolved } else { outcome }
}
pub fn next_bytes(previous: usize, record: usize) -> Option<usize> {
    if !(1..=RECORD_LIMIT).contains(&record) { return None; }
    previous.checked_add(record).filter(|next| *next <= BYTE_LIMIT)
}

macro_rules! codes {
    ($name:ident { $($variant:ident = $code:literal),+ $(,)? }) => {
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        #[repr(u8)]
        pub enum $name { $($variant = $code),+ }
        impl $name {
            pub const fn from_code(value: u8) -> Option<Self> {
                match value { $($code => Some(Self::$variant),)+ _ => None }
            }
        }
    };
}
codes!(Step {
    Bootstrap=1, Environment=2, ReadEnvironment=3, Dashboard=4, ChooseCancel=5, CancelProject=6,
    CancelSettled=7, ReadCancelled=8, ChooseProject=9, SetFolder=10, AcceptProject=11, ProjectSettled=12,
    Snapshot=13, Settings=14, Suggest=15, Suggestion=16, Adopt=17, Hydrated=18, EditDraft=19, Edited=20,
    Validate=21, Validated=22, Preview=23, Previewed=24, MutateFixture=25, ReturnDashboard=26,
    Refresh=27, Refreshed=28, ReturnSettings=29, Preserved=30, ArmHold=31, HeldRefresh=32, Held=33,
    ChoosePending=34, PickerPending=35, Reload=36, Lost=37, CloseCancel=38, QuitCancel=39,
    QuitCancelled=40, Close=41, QuitConfirm=42, Exit=43,
});
codes!(Refusal {
    Record=1, Deadline=2, Attach=3, Navigation=4, PageLoad=5, AppInfo=6, Catalog=7,
    ProjectResult=8, SnapshotRequest=9, Snapshot=10, SuggestRequest=11, Suggestion=12,
    ValidateRequest=13, Validation=14, PreviewRequest=15, PreviewResult=16,
    ClosePrevented=17, Tick=18, DocumentSample=19, NativeStep=20, Dom=21,
    RelayJoined=22, ActualExit=23, Finish=24, MainReturn=25,
});
codes!(PendingKind { None=0, Dom=1, Native=2, Close=3, Reload=4 });

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Snapshot {
    pub step: Step, pub pending: PendingKind, pub pending_step: Option<Step>,
    pub dispatch: u16, pub flags: u16,
}
impl Default for Snapshot {
    fn default() -> Self { Self { step: Step::Bootstrap, pending: PendingKind::None,
        pending_step: None, dispatch: 0, flags: 0 } }
}
impl Snapshot {
    pub fn encode(self) -> Option<u64> {
        let valid = match self.pending {
            PendingKind::None | PendingKind::Reload => self.pending_step.is_none() && self.dispatch == 0,
            PendingKind::Dom => self.pending_step.is_some() && (1..=200).contains(&self.dispatch),
            PendingKind::Native | PendingKind::Close => self.pending_step.is_some() && self.dispatch == 0,
        };
        valid.then_some(self.step as u64 | (self.pending as u64) << 6
            | u64::from(self.pending_step.map_or(0, |step| step as u8)) << 9
            | u64::from(self.dispatch) << 15 | u64::from(self.flags) << 23)
    }
    pub fn decode(raw: u64) -> Option<Self> {
        if raw >> 39 != 0 { return None; }
        let pending = ((raw >> 9) & 63) as u8;
        let value = Self { step: Step::from_code((raw & 63) as u8)?,
            pending: PendingKind::from_code(((raw >> 6) & 7) as u8)?,
            pending_step: if pending == 0 { None } else { Some(Step::from_code(pending)?) },
            dispatch: ((raw >> 15) & 255) as u16, flags: ((raw >> 23) & 65535) as u16 };
        (value.encode() == Some(raw)).then_some(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Event { MainAdmitted, Step(Step), Startup(StartupEvent), StartupRefusal, ObserverRefusal, BuilderReturned }
impl Event {
    // The only publication keys: 1 + 43 + 8 + 2 + 1 = 55. No heartbeat.
    fn key(self) -> Option<u8> { Some(match self {
        Self::MainAdmitted => 0, Self::Step(step) => step as u8,
        Self::Startup(event) => 44 + match event {
            StartupEvent::Context => 0, StartupEvent::Window => 1, StartupEvent::Registered => 2,
            StartupEvent::HookAccepted => 3, StartupEvent::ReplyReturn => 4, StartupEvent::NavigateReturn => 5,
            StartupEvent::Finished => 6, StartupEvent::Stop => 7, _ => return None,
        },
        Self::StartupRefusal => 52, Self::ObserverRefusal => 53, Self::BuilderReturned => 54,
    }) }
    fn code(self) -> u8 { match self { Self::MainAdmitted => 1, Self::Step(_) => 2,
        Self::Startup(_) => 3, Self::StartupRefusal => 4, Self::ObserverRefusal => 5, Self::BuilderReturned => 6 } }
}

/// Scalar first refusal and last copied observation, independent of Record's
/// mutex. Fail may be called with that mutex held; it never tries to acquire it.
#[derive(Default)]
pub struct Latch { first: AtomicU8, snapshot: AtomicU64 }
impl Latch {
    pub fn refuse(&self, reason: Refusal) { let _ = self.first.compare_exchange(0, reason as u8, Ordering::SeqCst, Ordering::SeqCst); }
    pub fn first(&self) -> Option<Refusal> { Refusal::from_code(self.first.load(Ordering::SeqCst)) }
    pub fn observe(&self, value: Snapshot) {
        if let Some(word) = value.encode() { self.snapshot.store(word, Ordering::SeqCst); }
    }
    pub fn snapshot(&self) -> Snapshot { Snapshot::decode(self.snapshot.load(Ordering::SeqCst)).unwrap_or_default() }
}

#[derive(Default)]
pub struct JournalOrder {
    busy: AtomicBool, disabled: AtomicBool, incomplete: AtomicBool, seen: AtomicU64, count: AtomicU8,
}
pub struct Permit<'a> { owner: &'a JournalOrder, sequence: u8, event: Event }
impl Drop for Permit<'_> { fn drop(&mut self) { self.owner.busy.store(false, Ordering::SeqCst); } }
impl JournalOrder {
    pub fn unavailable(&self) { self.incomplete.store(true, Ordering::SeqCst); }
    pub fn disable(&self) { self.disabled.store(true, Ordering::SeqCst); self.unavailable(); }
    pub fn begin(&self, event: Event) -> Option<Permit<'_>> {
        let key = event.key()?;
        if self.disabled.load(Ordering::SeqCst) { return None; }
        // Claim even a busy/reentrant event. Later callbacks cannot retry that
        // missed publication or relabel a later snapshot as its first boundary.
        let mask = 1u64 << key;
        if self.seen.fetch_or(mask, Ordering::SeqCst) & mask != 0 { return None; }
        if self.busy.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).is_err() {
            self.unavailable(); return None;
        }
        let sequence = self.count.load(Ordering::SeqCst);
        let permit = Permit { owner: self, sequence: sequence.saturating_add(1), event };
        if self.disabled.load(Ordering::SeqCst) { return None; }
        if sequence >= RECORDS { self.disable(); return None; }
        // Claim before I/O: a short/unknown write can never replay this record.
        self.count.store(sequence + 1, Ordering::SeqCst);
        Some(permit)
    }
}
impl Permit<'_> {
    pub fn record(&self, output: &mut impl Write, snapshot: Snapshot,
        startup: Option<u64>, refusal: Option<Refusal>) -> io::Result<()> {
        let event = self.event;
        let invalid = || io::Error::from(io::ErrorKind::InvalidData);
        if snapshot.encode().is_none() || event.key().is_none()
            || matches!(event, Event::Step(step) if step != snapshot.step)
            || startup.is_some_and(|word| Word::decode(word).is_none())
            || matches!(event, Event::Startup(_) | Event::StartupRefusal) && startup.is_none()
            || matches!(event, Event::ObserverRefusal) && refusal.is_none() { return Err(invalid()); }
        if let Some(word) = startup.and_then(Word::decode) {
            if matches!(event, Event::StartupRefusal) && !word.first_refusal
                || matches!(event, Event::Startup(selected) if word.event != selected || word.first_refusal) { return Err(invalid()); }
        }
        write!(output, "{{\"schema\":1,\"sequence\":{},\"event\":{},\"step\":{},\"pending\":{},\"pendingStep\":{},\"dispatch\":{},\"flags\":{},\"startup\":",
            self.sequence, event.code(), snapshot.step as u8, snapshot.pending as u8,
            snapshot.pending_step.map_or(0, |step| step as u8), snapshot.dispatch, snapshot.flags)?;
        match startup { Some(word) => write!(output, "{word}")?, None => output.write_all(b"null")? }
        write!(output, ",\"refusal\":{},\"coverageIncomplete\":{}}}\n", refusal.map_or(0, |reason| reason as u8),
            self.owner.incomplete.load(Ordering::SeqCst))
    }
}

/// Formatting is bounded before any native entry, including malformed input.
/// This buffer contains DATA only and has no handle or automatic I/O in Drop.
pub struct Frame { raw: [u8; RECORD_LIMIT], used: usize }
impl Default for Frame { fn default() -> Self { Self { raw: [0; RECORD_LIMIT], used: 0 } } }
impl Frame { pub fn bytes(&self) -> &[u8] { &self.raw[..self.used] } }
impl Write for Frame {
    fn write(&mut self, raw: &[u8]) -> io::Result<usize> {
        let Some(end) = self.used.checked_add(raw.len()).filter(|end| *end <= RECORD_LIMIT) else {
            return Err(io::ErrorKind::WriteZero.into());
        };
        self.raw[self.used..end].copy_from_slice(raw); self.used = end; Ok(raw.len())
    }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}

/// A validated historical row, not a current application state or finality fact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Row {
    pub sequence: u8, pub event: Event, pub snapshot: Snapshot, pub startup: Option<u64>,
    pub refusal: Option<Refusal>, pub coverage_incomplete: bool,
}
struct Fields<'a>(&'a [u8]);
impl Fields<'_> {
    fn take(&mut self, fixed: &[u8]) -> Option<()> { self.0 = self.0.strip_prefix(fixed)?; Some(()) }
    fn number(&mut self) -> Option<u64> {
        let length = self.0.iter().take_while(|byte| byte.is_ascii_digit()).count();
        if length == 0 || length > 20 || length > 1 && self.0[0] == b'0' { return None; }
        let mut value = 0u64;
        for byte in &self.0[..length] { value = value.checked_mul(10)?.checked_add(u64::from(*byte - b'0'))?; }
        self.0 = &self.0[length..]; Some(value)
    }
    fn byte(&mut self) -> Option<u8> { self.number()?.try_into().ok() }
    fn boolean(&mut self) -> Option<bool> {
        if self.0.starts_with(b"true") { self.take(b"true")?; Some(true) }
        else { self.take(b"false")?; Some(false) }
    }
}
impl Row {
    pub fn decode(raw: &[u8]) -> Option<Self> {
        if raw.len() > RECORD_LIMIT { return None; }
        // Exact emitter grammar: fixed keys/order, canonical decimal/boolean,
        // one LF, no duplicate/unknown key, whitespace, escaping or arbitrary text.
        let mut input = Fields(raw);
        input.take(b"{\"schema\":1,\"sequence\":")?; let sequence = input.byte()?;
        if !(1..=RECORDS).contains(&sequence) { return None; }
        input.take(b",\"event\":")?; let code = input.byte()?;
        input.take(b",\"step\":")?; let step = Step::from_code(input.byte()?)?;
        input.take(b",\"pending\":")?; let pending = PendingKind::from_code(input.byte()?)?;
        input.take(b",\"pendingStep\":")?; let pending_step = input.byte()?;
        let pending_step = if pending_step == 0 { None } else { Some(Step::from_code(pending_step)?) };
        input.take(b",\"dispatch\":")?; let dispatch = input.number()?.try_into().ok()?;
        input.take(b",\"flags\":")?; let flags = input.number()?.try_into().ok()?;
        let snapshot = Snapshot { step, pending, pending_step, dispatch, flags }; snapshot.encode()?;
        input.take(b",\"startup\":")?;
        let startup = if input.0.starts_with(b"null") { input.take(b"null")?; None } else { Some(input.number()?) };
        let word = match startup { Some(raw) => Some(Word::decode(raw)?), None => None };
        input.take(b",\"refusal\":")?; let refusal = input.byte()?;
        let refusal = if refusal == 0 { None } else { Some(Refusal::from_code(refusal)?) };
        input.take(b",\"coverageIncomplete\":")?; let coverage_incomplete = input.boolean()?;
        input.take(b"}\n")?; if !input.0.is_empty() { return None; }
        let event = match code {
            1 => Event::MainAdmitted, 2 => Event::Step(step),
            3 => { let word = word?; if word.first_refusal { return None; } Event::Startup(word.event) },
            4 => { if !word?.first_refusal { return None; } Event::StartupRefusal },
            5 => { refusal?; Event::ObserverRefusal }, 6 => Event::BuilderReturned, _ => return None,
        };
        event.key()?;
        Some(Self { sequence, event, snapshot, startup, refusal, coverage_incomplete })
    }
    pub fn write_json(self, output: &mut impl Write) -> io::Result<()> {
        let snapshot = self.snapshot;
        write!(output, "{{\"sequence\":{},\"event\":{},\"step\":{},\"pending\":{},\"pendingStep\":{},\"dispatch\":{},\"flags\":{},\"startup\":",
            self.sequence, self.event.code(), snapshot.step as u8, snapshot.pending as u8,
            snapshot.pending_step.map_or(0, |value| value as u8), snapshot.dispatch, snapshot.flags)?;
        match self.startup { Some(word) => write!(output, "{word}")?, None => output.write_all(b"null")? }
        write!(output, ",\"refusal\":{},\"coverageIncomplete\":{}}}", self.refusal.map_or(0, |value| value as u8), self.coverage_incomplete)
    }
}

/// Closed reasons: 0 observed prefix, 1 no capture, 2 empty, 3 partial tail,
/// 4 invalid record/order, 5 bounds, 6 emitter reported incomplete coverage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Projection {
    pub bytes: u32, pub records: u8, pub reason: u8,
    pub last: Option<Row>, pub observer_refusal: Option<Row>, pub startup_refusal: Option<Row>,
}
impl Default for Projection {
    fn default() -> Self { Self { bytes: 0, records: 0, reason: 1, last: None, observer_refusal: None, startup_refusal: None } }
}
impl Projection {
    pub fn decode(raw: &[u8]) -> Self {
        let mut value = Self::default();
        if raw.len() > BYTE_LIMIT { value.reason = 5; return value; }
        value.bytes = raw.len() as u32;
        if raw.is_empty() { value.reason = 2; return value; }
        value.reason = 0; let mut seen = 0u64;
        for line in raw.split_inclusive(|byte| *byte == b'\n') {
            if value.records >= RECORDS || line.len() > RECORD_LIMIT { value.reason = 5; break; }
            if !line.ends_with(b"\n") { value.reason = 3; break; }
            let Some(row) = Row::decode(line) else { value.reason = 4; break; };
            let key = row.event.key().expect("decoded finite event"); let mask = 1u64 << key;
            if row.sequence != value.records + 1 || seen & mask != 0
                || value.observer_refusal.is_some_and(|first| first.refusal != row.refusal) {
                value.reason = 4; break;
            }
            seen |= mask; value.records += 1; value.last = Some(row);
            if row.refusal.is_some() && value.observer_refusal.is_none() { value.observer_refusal = Some(row); }
            if row.startup.and_then(Word::decode).is_some_and(|word| word.first_refusal) && value.startup_refusal.is_none() {
                value.startup_refusal = Some(row);
            }
            if row.coverage_incomplete { value.reason = 6; }
        }
        value
    }
    pub fn write_json(self, output: &mut impl Write) -> io::Result<()> {
        // Even reason0 is only a fully parsed historical prefix, never proof
        // that no later publication was lost or the application is still here.
        write!(output, "{{\"bytes\":{},\"records\":{},\"reason\":{},\"last\":", self.bytes, self.records, self.reason)?;
        match self.last { Some(row) => row.write_json(output)?, None => output.write_all(b"null")? }
        output.write_all(b",\"observerRefusal\":")?;
        match self.observer_refusal { Some(row) => row.write_json(output)?, None => output.write_all(b"null")? }
        output.write_all(b",\"startupRefusal\":")?;
        match self.startup_refusal { Some(row) => row.write_json(output)?, None => output.write_all(b"null")? }
        output.write_all(b"}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const ROW: &str = "{\"schema\":1,\"sequence\":1,\"event\":1,\"step\":1,\"pending\":0,\"pendingStep\":0,\"dispatch\":0,\"flags\":0,\"startup\":null,\"refusal\":0,\"coverageIncomplete\":false}\n";
    #[test]
    fn independent_rows_are_strict_and_partial_tails_remain_incomplete() {
        let row = Row::decode(ROW.as_bytes()).unwrap();
        assert_eq!((row.sequence, row.event, row.snapshot), (1, Event::MainAdmitted, Snapshot::default()));
        assert_eq!((Projection::decode(ROW.as_bytes()).records, Projection::decode(ROW.as_bytes()).reason), (1, 0));
        for (from, to) in [("\"schema\":1", "\"schema\":true"), ("\"sequence\":1", "\"sequence\":01"),
            ("\"event\":1", "\"event\":7"), ("\"step\":1", "\"step\":44"), ("\"flags\":0", "\"flags\":65536"),
            ("\"flags\":0", "\"flags\":-1"), ("\"pending\":0", "\"pending\":1"), ("\"refusal\":0", "\"refusal\":26"),
            ("\"startup\":null", "\"startup\":18446744073709551616"), ("\"startup\":null", "\"startup\":1"),
            ("\"schema\":1", "\"schema\":1,\"schema\":1"), ("}\n", ",\"path\":\"private\"}\n"),
            ("}\n", "}\r\n")] {
            let bad = ROW.replace(from, to); assert!(Row::decode(bad.as_bytes()).is_none(), "{bad}");
            assert_eq!(Projection::decode(bad.as_bytes()).reason, 4);
        }
        let partial = format!("{ROW}{{\"schema\":"); let projected = Projection::decode(partial.as_bytes());
        assert_eq!((projected.records, projected.reason, projected.bytes), (1, 3, partial.len() as u32));
        assert_eq!(projected.last, Some(row));
        assert_eq!(Projection::decode(&ROW.as_bytes()[..ROW.len()-1]).reason, 3);
        assert_eq!(Projection::decode(b"").reason, 2);
        assert_eq!(Projection::decode(&vec![b'x'; BYTE_LIMIT + 1]).reason, 5);
        assert_eq!(Projection::decode(&vec![b'x'; RECORD_LIMIT + 1]).reason, 5);
    }
    #[test]
    fn prefix_order_first_refusal_and_projection_are_not_success_claims() {
        let first = ROW.replace("\"refusal\":0", "\"refusal\":2");
        let next = first.replace("\"sequence\":1", "\"sequence\":2").replace("\"event\":1", "\"event\":2");
        let raw = format!("{first}{next}"); let projection = Projection::decode(raw.as_bytes());
        assert_eq!((projection.reason, projection.records), (0, 2));
        assert_eq!(projection.observer_refusal.unwrap().sequence, 1);
        for bad in [format!("{first}{first}"), next.clone(), format!("{first}{}", next.replace("\"refusal\":2", "\"refusal\":3"))] {
            assert_eq!(Projection::decode(bad.as_bytes()).reason, 4);
        }
        let gap = raw.replace("\"coverageIncomplete\":false", "\"coverageIncomplete\":true");
        assert_eq!(Projection::decode(gap.as_bytes()).reason, 6);
        let mut output = Vec::new(); projection.write_json(&mut output).unwrap();
        assert!(output.len() < 2048);
        let text = std::str::from_utf8(&output).unwrap();
        for forbidden in ["path", "Sid", "handle", "ready", "passed", "verified", "currentPhase"] { assert!(!text.contains(forbidden)); }
    }
    #[test]
    fn original_90_and_prebound_110_samples_latch_independently() {
        let execution = AtomicBool::new(false); let diagnostic = AtomicBool::new(false);
        let entry = 700u64; let normal_end = entry + EXECUTION_MS; let read_end = entry + DIAGNOSTIC_MS;
        assert!(window_sample(entry, normal_end, normal_end - 1, true, &execution));
        assert!(!window_sample(entry, normal_end, normal_end, true, &execution));
        assert!(!window_sample(entry, normal_end, entry, true, &execution));
        assert!(window_sample(entry, read_end, entry + 100_000, true, &diagnostic));
        assert!(window_sample(entry, read_end, read_end - 1, true, &diagnostic));
        assert!(!window_sample(entry, read_end, read_end, true, &diagnostic));
        assert!(!window_sample(entry, read_end, entry, true, &diagnostic));
        assert!(!window_sample(entry, read_end, entry - 1, true, &AtomicBool::new(false)));
        assert!(!window_sample(entry, read_end, entry, false, &AtomicBool::new(false)));
        assert!(u64::MAX.checked_add(DIAGNOSTIC_MS).is_none());
    }
    #[test]
    fn known_finality_and_never_started_inventory_are_both_required_once() {
        let good = ChildFinality { returned: true, created: true, signaled: true, exit_observed: true,
            process_closed: true, thread_closed: true, unknown: false };
        assert!(good.admitted());
        for bad in [ChildFinality { returned: false, ..good }, ChildFinality { created: false, ..good },
            ChildFinality { signaled: false, ..good }, ChildFinality { exit_observed: false, ..good },
            ChildFinality { process_closed: false, ..good }, ChildFinality { thread_closed: false, ..good },
            ChildFinality { unknown: true, ..good }] {
            assert!(!bad.admitted()); assert!(!InventoryOrder::default().select_failure(bad.admitted(), true));
        }
        let mut used = InventoryOrder::default(); used.attempted(); assert!(!used.select_failure(true, true));
        assert!(!InventoryOrder::default().select_failure(true, false));
        let mut fresh = InventoryOrder::default(); assert!(fresh.select_failure(true, true));
        assert!(fresh.failure()); assert!(!fresh.select_failure(true, true)); fresh.attempted();
        assert!(fresh.failure()); assert!(!fresh.select_failure(true, false));
    }
    #[test]
    fn snapshots_are_closed_and_round_trip() {
        for step in 1..=43 { for pending in [PendingKind::None, PendingKind::Dom, PendingKind::Native, PendingKind::Close, PendingKind::Reload] {
            let snapshot = Snapshot { step: Step::from_code(step).unwrap(), pending,
                pending_step: matches!(pending, PendingKind::Dom | PendingKind::Native | PendingKind::Close).then_some(Step::Exit),
                dispatch: if pending == PendingKind::Dom { 200 } else { 0 }, flags: u16::MAX };
            assert_eq!(Snapshot::decode(snapshot.encode().unwrap()), Some(snapshot));
        } }
        assert!(Snapshot::decode(u64::MAX).is_none());
        assert!((0..=255).filter_map(Step::from_code).count() == 43);
        assert!((0..=255).filter_map(Refusal::from_code).count() == 25);
        assert!(Snapshot { pending: PendingKind::Dom, ..Snapshot::default() }.encode().is_none());
    }
    #[test]
    fn first_refusal_never_locks_or_changes_the_snapshot() {
        let latch = Latch::default(); let snapshot = Snapshot { step: Step::SetFolder, ..Snapshot::default() };
        latch.observe(snapshot); latch.refuse(Refusal::NativeStep); latch.refuse(Refusal::Deadline);
        assert_eq!(latch.first(), Some(Refusal::NativeStep)); assert_eq!(latch.snapshot(), snapshot);
    }
    #[test]
    fn reentry_duplicate_and_failure_cannot_replay() {
        let order = JournalOrder::default(); let first = order.begin(Event::MainAdmitted).unwrap();
        assert!(order.begin(Event::Step(Step::Bootstrap)).is_none()); drop(first);
        assert!(order.begin(Event::MainAdmitted).is_none());
        assert!(order.begin(Event::Step(Step::Bootstrap)).is_none()); // No retry of the busy first boundary.
        let refusal = order.begin(Event::ObserverRefusal).unwrap(); let mut raw = Vec::new();
        refusal.record(&mut raw, Snapshot::default(), None, Some(Refusal::Deadline)).unwrap();
        assert!(std::str::from_utf8(&raw).unwrap().contains("\"coverageIncomplete\":true"));
        order.disable(); drop(refusal); assert!(order.begin(Event::BuilderReturned).is_none());
    }
    #[test]
    fn all_distinct_records_fit_unchanged_bounds() {
        let order = JournalOrder::default(); let mut events = vec![Event::MainAdmitted];
        events.extend((1..=43).map(|code| Event::Step(Step::from_code(code).unwrap())));
        events.extend([StartupEvent::Context, StartupEvent::Window, StartupEvent::Registered,
            StartupEvent::HookAccepted, StartupEvent::ReplyReturn, StartupEvent::NavigateReturn,
            StartupEvent::Finished, StartupEvent::Stop].map(Event::Startup));
        events.extend([Event::StartupRefusal, Event::ObserverRefusal, Event::BuilderReturned]);
        assert_eq!(events.len(), 55); let mut total = 0;
        for event in events {
            let mut word = Word::default();
            if let Event::Startup(event) = event { word.event = event; if event == StartupEvent::Finished { word.detail = 2; } }
            if event == Event::StartupRefusal { word.event = StartupEvent::ExternalUnknown; word.first_refusal = true; }
            let snapshot = Snapshot { step: if let Event::Step(step) = event { step } else { Step::Exit },
                pending: PendingKind::Dom, pending_step: Some(Step::Exit), dispatch: 200, flags: u16::MAX };
            let permit = order.begin(event).unwrap(); let mut raw = Frame::default();
            permit.record(&mut raw, snapshot, Some(word.encode().unwrap()), Some(Refusal::MainReturn)).unwrap();
            assert!(raw.bytes().len() <= RECORD_LIMIT); total += raw.bytes().len();
        }
        assert!(total <= BYTE_LIMIT); assert_eq!(order.count.load(Ordering::SeqCst), 55);
    }
    #[test]
    fn invalid_scalar_records_are_not_formatted() {
        let order = JournalOrder::default();
        assert!(order.begin(Event::MainAdmitted).unwrap().record(&mut Vec::new(), Snapshot::default(), Some(1), None).is_err());
        assert!(order.begin(Event::ObserverRefusal).unwrap().record(&mut Vec::new(), Snapshot::default(), None, None).is_err());
        assert!(order.begin(Event::Step(Step::Exit)).unwrap().record(&mut Vec::new(), Snapshot::default(), None, None).is_err());
        let mut frame = Frame::default(); frame.write_all(&[b'x'; RECORD_LIMIT]).unwrap();
        assert!(frame.write_all(b"x").is_err()); assert_eq!(frame.bytes().len(), RECORD_LIMIT);
    }
    #[test]
    fn one_attempt_known_short_unknown_close_and_late_refusals() {
        use AppendPhase::*; use AppendReturn::*;
        let phases = [Inspect, Write, InspectWritten, Close];
        let mut calls = Vec::new();
        assert_eq!(append_once(|phase| { calls.push(phase); Complete }), Complete);
        assert_eq!(calls, phases);
        // Short Write and an expired per-effect checkpoint both have a known
        // Refused return. Neither permits another write/poststate, but both
        // permit one late close of the same original. Unknown permits neither.
        for (position, failure) in phases.into_iter().enumerate() {
            for answer in [Refused, Unresolved] {
                let mut calls = Vec::new();
                let observed = append_once(|phase| { calls.push(phase); if phase == failure { answer } else { Complete } });
                let expected = if answer == Unresolved || failure == Close { Unresolved } else { Refused };
                assert_eq!(observed, expected);
                let mut wanted = phases[..=position].to_vec();
                if answer == Refused && failure != Close { wanted.push(Close); }
                assert_eq!(calls, wanted);
                assert!(calls.iter().filter(|phase| **phase == Write).count() <= 1);
                assert!(calls.iter().filter(|phase| **phase == Close).count() <= 1);
            }
        }
        for size in [0, RECORD_LIMIT + 1, usize::MAX] { assert_eq!(next_bytes(0, size), None); }
        assert_eq!(next_bytes(BYTE_LIMIT - RECORD_LIMIT, RECORD_LIMIT), Some(BYTE_LIMIT));
        assert_eq!(next_bytes(BYTE_LIMIT, 1), None); assert_eq!(next_bytes(usize::MAX, 1), None);
        let order = JournalOrder::default(); order.count.store(RECORDS, Ordering::SeqCst);
        assert!(order.begin(Event::MainAdmitted).is_none());
        assert!(order.disabled.load(Ordering::SeqCst));
    }
}
