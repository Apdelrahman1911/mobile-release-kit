//! Qualification-only original owner for closed headless libtest variants.
//! Compiled only by cfg(test); no product capability or general launcher.
//! The fullwalk seam stays closed until separate publication/precheck review.
//! This same libtest thread owns every synchronous borrower. In particular, a
//! blocked CreateProcessWithLogonW is NOT detached, timed out, or freed. Hosted
//! step expiry is containment/Unknown, never an original-return/close receipt.
use super::*;
use super::qualification_fixture::{self as fixture, Admission, AggregateClock, Wire};
pub(super) use super::qualification_result::*;
use std::path::Path;
use std::time::{Duration, Instant};
use windows_sys::Win32::NetworkManagement::NetManagement as NM;
use windows_sys::Win32::Security::Cryptography as BC;

pub(super) const CHILD: &str = "hosted_tests::hosted_native_read_only_contract";
const OWNER: &str = "ordinary_owner::hosted_ordinary_original_handle_contract";
const REQUEST: &str = "ordinary-request.txt";
const RESULT: &str = "native-result.json";
const OWNER_RESULT: &str = "ordinary-owner-result.private.json";
const NATIVE_SECONDS: u64 = 90;
const SETTLE_MS: u32 = 10_000;

#[cfg(feature = "desktop-ui")]
#[path = "ordinary_owner_ui.rs"]
mod normal_ui;
#[cfg(feature = "desktop-ui")]
pub(super) fn ui_local_sid(sid: &[u8]) -> bool { local_account_sid(sid) }

// Each fixed prerequisite profile has its separate review/dispatch gates.
// The legacy synthetic receipt and actual-producer observation are distinct;
// neither a request digest nor producer pre-close bytes replace original gates.
// Source wiring alone authorizes no execution, consumer enablement or success.
pub(super) const FULLWALK_PREREQUISITES_REVIEWED: bool = true;
#[derive(Clone, Copy, Eq, PartialEq)]
enum OwnerVariant { Ordinary, Fullwalk, Passive }
impl OwnerVariant {
    fn owner(self) -> &'static str { match self { Self::Ordinary => OWNER, Self::Fullwalk => FULLWALK_OWNER, Self::Passive => PASSIVE_OWNER } }
    fn child(self) -> &'static str { match self { Self::Ordinary => CHILD, Self::Fullwalk => FULLWALK_CHILD, Self::Passive => PASSIVE_CHILD } }
    fn request(self) -> &'static str { match self { Self::Ordinary => REQUEST, Self::Fullwalk => FULLWALK_REQUEST, Self::Passive => PASSIVE_REQUEST } }
    fn output(self) -> &'static str { match self { Self::Ordinary => "ordinary-output", Self::Fullwalk => FULLWALK_OUTPUT, Self::Passive => PASSIVE_OUTPUT } }
    fn result(self) -> &'static str { match self { Self::Ordinary => RESULT, Self::Fullwalk => FULLWALK_RESULT, Self::Passive => PASSIVE_RESULT } }
    fn intent(self) -> &'static str {
        match self { Self::Ordinary => "ordinary-owner-intent.private.json", Self::Fullwalk => "fullwalk-owner-intent.private.json", Self::Passive => "passive-owner-intent.private.json" }
    }
    fn owner_result(self) -> &'static str {
        match self { Self::Ordinary => OWNER_RESULT, Self::Fullwalk => "fullwalk-owner-result.private.json", Self::Passive => "passive-owner-result.private.json" }
    }
    fn command(self, path: &str) -> String {
        match self { Self::Ordinary => command(path), Self::Fullwalk => fullwalk_command(path), Self::Passive => passive_command(path) }
    }
}

// One shared, absorbing next-effect gate. Callers supply elapsed time from the
// original owner clock, including after synchronous observations return. This
// does not cancel a borrower or prohibit settling an already-owned original.
pub(super) fn next_effect(elapsed: Duration, deadline_latched: &mut bool) -> Result<()> {
    *deadline_latched |= elapsed >= Duration::from_secs(NATIVE_SECONDS);
    need(!*deadline_latched)
}
fn owner_effect(start: Instant, latched: &mut bool, aggregate: &mut Option<AggregateClock>) -> Result<()> {
    let local = next_effect(start.elapsed(), latched);
    let batch = match aggregate.as_mut() { Some(clock) => clock.sample(false).map(|_| ()), None => Ok(()) };
    local?; batch
}
fn owner_effect_traced(start: Instant, latched: &mut bool, aggregate: &mut Option<AggregateClock>, trace: &mut InputTrace) -> Result<()> {
    let original = owner_effect(start, latched, aggregate);
    trace.prerequisite_clock(*latched);
    trace.prerequisite_result(PrerequisiteCheck::T01, original)
}
fn prerequisite_process_decision<T>(trace: &mut InputTrace, check: PrerequisiteCheck, original: Result<T>,
    before: (bool, bool), facts: &ProcessFacts, native: Option<PrerequisiteNative>) -> Result<T> {
    // State/bounds guards rejected before the native-answer classifier. They
    // cannot borrow even an adjacent returned scalar as their cause.
    if let Err(error) = &original {
        let cause = if matches!(error, Error::State | Error::Bounds) { None } else { native };
        trace.prerequisite_fault(check, *error, cause, None);
    }
    else if !before.1 && facts.unknown { trace.prerequisite_fault(check, Error::Unknown, native, None); }
    else if !before.0 && facts.failed { trace.prerequisite_fault(check, Error::Unsafe, native, None); }
    original
}
fn batch_return(facts: &mut ProcessFacts, aggregate: &mut Option<AggregateClock>) {
    if aggregate.as_mut().is_some_and(|clock| clock.sample(false).is_err()) { facts.failed = true; }
}
fn command(path: &str) -> String { format!("\"{path}\" {CHILD} {}", FLAGS.join(" ")) }
fn command_digest(path: &str) -> Result<String> {
    command_digest_traced(path, &mut InputTrace::default())
}
fn command_digest_traced(path: &str, trace: &mut InputTrace) -> Result<String> {
    let text = command(path);
    trace.need(text.encode_utf16().count() <= 1023, InputCheck::CommandUnits)?;
    digest_traced(&text.encode_utf16().flat_map(u16::to_le_bytes).collect::<Vec<_>>(), trace)
}

// The actual native driver and existing nine inert methods use these SAME
// absorbing decisions. Synthetic records cannot call any native function.
#[derive(Clone, Debug)]
pub(super) struct ProcessFacts {
    pub claimed: bool, pub returned: bool, pub created: bool,
    pub failed: bool, pub unknown: bool, pub signaled: bool,
    pub exit: Option<u32>, pub terminated: bool,
    pub process: SlotState, pub thread: SlotState,
}
impl ProcessFacts {
    pub fn new() -> Self {
        Self { claimed: false, returned: false, created: false, failed: false,
            unknown: false, signaled: false, exit: None, terminated: false,
            process: SlotState::Reserved, thread: SlotState::Reserved }
    }
    pub fn begin(&mut self) -> Result<()> {
        if self.claimed { return Err(Error::State); }
        self.claimed = true; self.process = SlotState::Acquiring; self.thread = SlotState::Acquiring; Ok(())
    }
    pub fn creation(&mut self, ok: bool, error: u32, outputs: (usize, usize, u32, u32), late: bool) -> Result<()> {
        if !self.claimed || self.returned { return Err(Error::State); }
        self.returned = true; self.failed |= late;
        let (process, thread, pid, tid) = outputs;
        let valid = |h| h != 0 && h != usize::MAX;
        if ok && valid(process) && valid(thread) && process != thread && pid != 0 && tid != 0 && pid != tid {
            self.created = true; self.process = SlotState::Owned; self.thread = SlotState::Owned;
            return if late { Err(Error::Unsafe) } else { Ok(()) };
        }
        self.failed = true;
        if !ok && error != 0 && error != F::ERROR_IO_PENDING && outputs == (0, 0, 0, 0) {
            self.process = SlotState::NoHandle; self.thread = SlotState::NoHandle;
            Err(Error::Unavailable)
        } else {
            self.unknown = true; self.process = SlotState::Unknown; self.thread = SlotState::Unknown;
            Err(Error::Unknown)
        }
    }
    pub fn wait(&mut self, returned: u32, late: bool) -> Result<()> {
        if !self.created || self.signaled { return Err(Error::State); }
        self.failed |= late;
        if returned == F::WAIT_OBJECT_0 { self.signaled = true; return Ok(()); }
        self.failed = true;
        if returned != F::WAIT_TIMEOUT { self.unknown = true; }
        Err(if self.unknown { Error::Unknown } else { Error::Unsafe })
    }
    pub fn exited(&mut self, ok: bool, code: u32) -> Result<()> {
        if !self.signaled || self.exit.is_some() { return Err(Error::State); }
        if !ok { self.failed = true; self.unknown = true; return Err(Error::Unknown); }
        self.exit = Some(code); self.failed |= code != 0;
        Ok(())
    }
    pub fn begin_terminate(&mut self) -> Result<()> {
        if !self.created || self.signaled || self.terminated { return Err(Error::State); }
        self.terminated = true; self.failed = true; Ok(())
    }
    pub fn begin_close(&mut self, thread: bool) -> Result<()> {
        if !self.signaled { return Err(Error::State); }
        let state = if thread { &mut self.thread } else { &mut self.process };
        if *state != SlotState::Owned { return Err(Error::State); }
        *state = SlotState::Closing; Ok(())
    }
    pub fn closed(&mut self, thread: bool, ok: bool) -> Result<()> {
        let state = if thread { &mut self.thread } else { &mut self.process };
        if *state != SlotState::Closing { return Err(Error::State); }
        *state = if ok { SlotState::Closed } else { SlotState::Unknown };
        self.failed |= !ok; self.unknown |= !ok;
        if ok { Ok(()) } else { Err(Error::Unknown) }
    }
    pub fn passed(&self) -> bool {
        self.claimed && self.returned && self.created && self.signaled && self.exit == Some(0)
            && !self.failed && !self.unknown && !self.terminated
            && self.process == SlotState::Closed && self.thread == SlotState::Closed
    }
}
pub(super) fn fresh_account(absent: u32, pointer_null: bool, added: u32, sid: &[u8], groups: &[Vec<u8>]) -> bool {
    absent == NM::NERR_UserNotFound && pointer_null && added == 0
        && local_account_sid(sid) && groups == [builtin(545)]
}
fn local_account_sid(sid: &[u8]) -> bool {
    sid.len() == 28 && sid[..8] == [1, 5, 0, 0, 0, 0, 0, 5] && sid[8..12] == 21u32.to_le_bytes()
}


#[derive(Clone, Eq, PartialEq)]
pub(super) struct AclImage { owner: Vec<u8>, group: Vec<u8>, control: u16, revision: u8, aces: Vec<Vec<u8>> }
impl AclImage {
    pub(super) fn parse_traced(raw: &[u8], trace: &mut InputTrace) -> Result<Self> {
        trace.prerequisite_scope(PrerequisiteCheck::G01, |trace| {
            trace.observed(Self::parse(raw), InputCheck::AclLayout)
        })
    }
    fn parse(raw: &[u8]) -> Result<Self> {
        need(raw.len() >= 20 && raw.len() <= BUFFER && raw[0] == 1 && raw[1] == 0)?;
        let control = decode::u16_at(raw, 2)?;
        need(control & (S::SE_SELF_RELATIVE | S::SE_DACL_PRESENT) == (S::SE_SELF_RELATIVE | S::SE_DACL_PRESENT)
            && decode::u32_at(raw, 12)? == 0)?;
        let principal = |at| -> Result<Vec<u8>> {
            let offset = decode::u32_at(raw, at)? as usize;
            need(offset >= 20 && offset % 4 == 0)?;
            Ok(security::sid_at(raw, offset, raw.len())?.bytes().to_vec())
        };
        let owner = principal(4)?; let group = principal(8)?;
        let at = decode::u32_at(raw, 16)? as usize;
        need(at >= 20 && at % 4 == 0)?;
        let head = decode::span(raw, at, 8)?;
        let size = decode::u16_at(head, 2)? as usize;
        let count = decode::u16_at(head, 4)? as usize;
        need(matches!(head[0], 2 | 4) && head[1] == 0 && decode::u16_at(head, 6)? == 0
            && size >= 8 && count <= 1024 && size % 4 == 0)?;
        decode::span(raw, at, size)?;
        let mut aces = Vec::new(); let mut cursor = at + 8;
        for _ in 0..count {
            let header = decode::span(raw, cursor, 4)?;
            let length = decode::u16_at(header, 2)? as usize;
            need(matches!(header[0], 0 | 1) && header[1] & !0x1f == 0 && length >= 16 && length % 4 == 0
                && cursor + length <= at + size)?;
            let sid = security::sid_at(raw, cursor + 8, cursor + length)?;
            need(sid.bytes().len() + 8 == length)?;
            aces.push(decode::span(raw, cursor, length)?.to_vec()); cursor += length;
        }
        // Do not reinterpret unknown ACEs, null DACLs or leftover nonzero data.
        need(raw[cursor..at + size].iter().all(|byte| *byte == 0))?;
        Ok(Self { owner, group, control, revision: head[0], aces })
    }
    pub(super) fn base(&self, parent: &[u8], account: &[u8], directory: bool, trace: &mut InputTrace) -> Result<()> {
        trace.prerequisite_scope(PrerequisiteCheck::G01, |trace| {
            trace.need([system_sid(), builtin(544), parent.to_vec()].contains(&self.owner)
                && self.owner != account, InputCheck::AclOwner)?;
            trace.need(self.group != account, InputCheck::AclGroup)?;
            for ace in &self.aces {
                let sid = &ace[8..];
                trace.need(sid != account, InputCheck::AclAccount)?;
                let mut mask = trace.observed(decode::u32_at(ace, 4), InputCheck::AclLayout)?;
                for (generic, rights) in [(F::GENERIC_ALL, FS::FILE_ALL_ACCESS),
                    (F::GENERIC_READ, FS::FILE_GENERIC_READ), (F::GENERIC_WRITE, FS::FILE_GENERIC_WRITE),
                    (F::GENERIC_EXECUTE, FS::FILE_GENERIC_EXECUTE)] {
                    if mask & generic != 0 { mask = (mask & !generic) | rights; }
                }
                trace.need(mask & !FS::FILE_ALL_ACCESS == 0, InputCheck::AclMask)?;
                // Exact OWNER RIGHTS (S-1-3-4) applies to the already qualified
                // concrete owner above. Preserve the original ACE; no SID rewrite,
                // CREATOR OWNER/prefix trust, new grant or production-policy change.
                const OWNER_RIGHTS: &[u8] = &[1, 1, 0, 0, 0, 0, 0, 3, 4, 0, 0, 0];
                if ace[0] == 1 || ace[1] as u32 & S::INHERIT_ONLY_ACE != 0
                    || sid == parent || sid == system_sid() || sid == builtin(544) || sid == OWNER_RIGHTS { continue; }
                // Only the already task-owned tree is changed. Other principals may
                // read/traverse, but may not mutate/replace these exact originals.
                let mut mutation = FS::DELETE | FS::FILE_DELETE_CHILD | FS::WRITE_DAC | FS::WRITE_OWNER
                    | FS::FILE_WRITE_DATA | FS::FILE_APPEND_DATA | FS::FILE_WRITE_EA | FS::FILE_WRITE_ATTRIBUTES;
                if !directory { mutation |= FS::FILE_WRITE_DATA; }
                trace.need(mask & mutation == 0, InputCheck::AclMutation)?;
            }
            Ok(())
        })
    }
    pub(super) fn dacl_control(&self) -> (u16, u16) {
        // Only the original protection bit belongs in this absolute input.
        // Descriptor control bits are not SECURITY_INFORMATION operation flags.
        (S::SE_DACL_PROTECTED, self.control & S::SE_DACL_PROTECTED)
    }
    pub(super) fn add(&self, sid: &[u8], mask: u32, trace: &mut InputTrace) -> Result<(Self, Box<Aligned>)> {
        trace.prerequisite_scope(PrerequisiteCheck::G01, |trace| {
            let size = 8 + self.aces.iter().map(Vec::len).sum::<usize>() + 8 + sid.len();
            trace.need(size <= BUFFER && size <= u16::MAX as usize && self.aces.len() < 1024, InputCheck::AclCapacity)?;
            let mut expected = self.clone();
            let mut ace = vec![0, 0];
            ace.extend_from_slice(&((8 + sid.len()) as u16).to_le_bytes());
            ace.extend_from_slice(&mask.to_le_bytes()); ace.extend_from_slice(sid);
            // One explicit non-inheriting ACE; retain every original ACE byte/order.
            let insertion = expected.aces.iter().position(|a| a[1] as u32 & S::INHERITED_ACE != 0).unwrap_or(expected.aces.len());
            expected.aces.insert(insertion, ace);
            let mut acl = Box::new(Aligned([0; BUFFER]));
            acl.0[0] = expected.revision; acl.0[2..4].copy_from_slice(&(size as u16).to_le_bytes());
            acl.0[4..6].copy_from_slice(&(expected.aces.len() as u16).to_le_bytes());
            let mut at = 8;
            for ace in &expected.aces { acl.0[at..at + ace.len()].copy_from_slice(ace); at += ace.len(); }
            Ok((expected, acl))
        })
    }
    pub(super) fn readback(&self, before: &Stamp, after: &Stamp, raw_before: &[u8], raw_after: &[u8],
        trace: &mut InputTrace) -> Result<()> {
        trace.prerequisite_scope(PrerequisiteCheck::G01, |trace| {
            trace.need(acl_stamp(before, after), InputCheck::AclStamp)?;
            let actual = Self::parse_traced(raw_after, trace)?;
            trace.control(self.control, actual.control)?;
            trace.need(self.owner == actual.owner, InputCheck::AclOwnerEqual)?;
            trace.need(self.group == actual.group, InputCheck::AclGroupEqual)?;
            trace.need(self.revision == actual.revision, InputCheck::AclRevision)?;
            trace.need(self.aces == actual.aces, InputCheck::AclAces)?;
            trace.need(raw_before != raw_after, InputCheck::AclChanged)
        })
    }
}
fn grant(file: &mut OriginalFile, role: &str, parent: &[u8], account: &[u8], mask: u32,
    start: Instant, deadline_latched: &mut bool, aggregate: &mut Option<AggregateClock>, trace: &mut InputTrace) -> Result<String> {
    trace.prerequisite_scope(PrerequisiteCheck::G02, |trace| {
        let timely = owner_effect_traced(start, deadline_latched, aggregate, trace);
        trace.observed(timely, InputCheck::AclDeadline)?;
        let before = file.stamp_traced(trace)?;
        let timely = owner_effect_traced(start, deadline_latched, aggregate, trace);
        trace.observed(timely, InputCheck::AclDeadline)?;
        let raw_before = file.descriptor_traced(trace)?;
        let timely = owner_effect_traced(start, deadline_latched, aggregate, trace);
        trace.observed(timely, InputCheck::AclDeadline)?;
        let image = AclImage::parse_traced(&raw_before, trace)?; image.base(parent, account, file.directory, trace)?;
        let (expected, acl) = image.add(account, mask, trace)?;
        let mut descriptor = Box::new(S::SECURITY_DESCRIPTOR::default());
        // These existing Boolean observations do not query/fabricate last error.
        let initialized = unsafe { S::InitializeSecurityDescriptor((&mut *descriptor as *mut S::SECURITY_DESCRIPTOR).cast(), 1) };
        if initialized == 0 {
            trace.record(InputCheck::AclInitialize, None);
            trace.prerequisite_fault(PrerequisiteCheck::G02, Error::Unsafe,
                PrerequisiteNative::boolean(PrerequisiteApi::InitializeSecurityDescriptor, PrerequisiteSelector::None, initialized, None),
                Some(PrerequisiteDetail::Input(InputCheck::AclInitialize)));
        }
        trace.need(initialized != 0, InputCheck::AclInitialize)?;
        let dacl = unsafe { S::SetSecurityDescriptorDacl((&mut *descriptor as *mut S::SECURITY_DESCRIPTOR).cast(),
            1, acl.0.as_ptr().cast(), 0) };
        if dacl == 0 {
            trace.record(InputCheck::AclDacl, None);
            trace.prerequisite_fault(PrerequisiteCheck::G02, Error::Unsafe,
                PrerequisiteNative::boolean(PrerequisiteApi::SetSecurityDescriptorDacl, PrerequisiteSelector::None, dacl, None),
                Some(PrerequisiteDetail::Input(InputCheck::AclDacl)));
        }
        trace.need(dacl != 0, InputCheck::AclDacl)?;
        // Mutate only owned descriptor DATA; the original object setter stays below.
        let (control_interest, control_value) = image.dacl_control();
        let control = unsafe { S::SetSecurityDescriptorControl(
            (&mut *descriptor as *mut S::SECURITY_DESCRIPTOR).cast(), control_interest, control_value) };
        if control == 0 {
            trace.record(InputCheck::AclControlInput, None);
            trace.prerequisite_fault(PrerequisiteCheck::G02, Error::Unsafe,
                PrerequisiteNative::boolean(PrerequisiteApi::SetSecurityDescriptorControl, PrerequisiteSelector::None, control, None),
                Some(PrerequisiteDetail::Input(InputCheck::AclControlInput)));
        }
        trace.need(control != 0, InputCheck::AclControlInput)?;
        let b = file.body();
        if b.state != SlotState::Owned || b.active { return trace.observed(Err(Error::State), InputCheck::AclSetState); }
        let timely = owner_effect_traced(start, deadline_latched, aggregate, trace);
        trace.observed(timely, InputCheck::AclDeadline)?;
        b.active = true;
        // Same original only. No SetNamedSecurityInfo/SetSecurityInfo propagation,
        // recursion, owner/group/SACL replacement, inheritable ACE or broad trustee.
        let ok = unsafe { S::SetKernelObjectSecurity(b.handle, S::DACL_SECURITY_INFORMATION,
            (&mut *descriptor as *mut S::SECURITY_DESCRIPTOR).cast()) };
        b.error = if ok != 0 { 0 } else { unsafe { F::GetLastError() } };
        if ok == 0 { trace.record(InputCheck::AclSetReturned, Some(InputStatus::Win32(b.error))); }
        b.active = ok == 0 && (b.error == 0 || b.error == F::ERROR_IO_PENDING);
        if ok == 0 {
            trace.prerequisite_fault(PrerequisiteCheck::G02, if b.active { Error::Unknown } else { Error::Unsafe },
                PrerequisiteNative::boolean(PrerequisiteApi::SetKernelObjectSecurity, PrerequisiteSelector::None, ok, Some(b.error)),
                Some(PrerequisiteDetail::Input(InputCheck::AclSetReturned)));
        }
        if b.active {
            b.state = SlotState::Unknown;
            diagnostic_with_fault("original-acl-operation", None, true, trace.first);
            loop { std::thread::park(); std::hint::black_box((&mut *b, &descriptor, &acl, &*trace)); }
        }
        need(ok != 0)?;
        let timely = owner_effect_traced(start, deadline_latched, aggregate, trace);
        trace.observed(timely, InputCheck::AclDeadline)?;
        let after = file.stamp_traced(trace)?;
        let timely = owner_effect_traced(start, deadline_latched, aggregate, trace);
        trace.observed(timely, InputCheck::AclDeadline)?;
        let raw_after = file.descriptor_traced(trace)?;
        expected.readback(&before, &after, &raw_before, &raw_after, trace)?;
        let timely = owner_effect_traced(start, deadline_latched, aggregate, trace);
        trace.observed(timely, InputCheck::AclDeadline)?;
        Ok(format!("{{\"role\":\"{role}\",\"mask\":{mask},\"before\":{},\"after\":{},\"securityBefore\":\"{}\",\"securityAfter\":\"{}\",\"singleExplicitNoninheritingAce\":true}}",
            before.json(), after.json(), digest_traced(&raw_before, trace)?, digest_traced(&raw_after, trace)?))
    })
}

// NetAPI allocation outputs remain original objects until their explicit single
// NetApiBufferFree. A status/pointer/size contradiction is retained, not adopted.
struct NetBuffer {
    pointer: *mut u8, status: u32, bytes: u32, entries: u32, total: u32,
    release_attempted: bool, released: bool, release_status: u32,
}
impl NetBuffer {
    fn new() -> Self { Self { pointer: null_mut(), status: u32::MAX, bytes: 0, entries: 0, total: 0,
        release_attempted: false, released: false, release_status: u32::MAX } }
    fn range(&self, pointer: *const u8, size: usize) -> Result<&[u8]> { self.range_traced(pointer, size, &mut InputTrace::default()) }
    fn range_traced(&self, pointer: *const u8, size: usize, trace: &mut InputTrace) -> Result<&[u8]> {
        trace.prerequisite_scope(PrerequisiteCheck::N01, |trace| {
            let start = self.pointer as usize; let selected = pointer as usize;
            need(!self.pointer.is_null() && selected >= start && size <= self.bytes as usize
                && selected.checked_add(size).is_some_and(|end| start.checked_add(self.bytes as usize).is_some_and(|limit| end <= limit)))?;
            Ok(unsafe { std::slice::from_raw_parts(pointer, size) })
        })
    }
    fn sized(&mut self) -> Result<()> { self.sized_traced(&mut InputTrace::default()) }
    fn sized_traced(&mut self, trace: &mut InputTrace) -> Result<()> {
        trace.prerequisite_scope(PrerequisiteCheck::N01, |trace| {
            if self.status != 0 || self.pointer.is_null() { return Err(Error::Unknown); }
            let result = unsafe { NM::NetApiBufferSize(self.pointer.cast(), &mut self.bytes) };
            if result != 0 || self.bytes == 0 || self.bytes as usize > BUFFER {
                trace.prerequisite_fault(PrerequisiteCheck::N01, Error::Unknown,
                    PrerequisiteNative::net(PrerequisiteApi::NetApiBufferSize, PrerequisiteSelector::None, result), None);
                return Err(Error::Unknown);
            }
            Ok(())
        })
    }
    fn string(&self, pointer: *const u16, maximum: usize) -> Result<Vec<u16>> { self.string_traced(pointer, maximum, &mut InputTrace::default()) }
    fn string_traced(&self, pointer: *const u16, maximum: usize, trace: &mut InputTrace) -> Result<Vec<u16>> {
        trace.prerequisite_scope(PrerequisiteCheck::N01, |trace| {
            let mut value = Vec::new();
            for i in 0..=maximum {
                let raw = self.range_traced((pointer as usize).checked_add(i * 2).ok_or(Error::Bounds)? as *const u8, 2, trace)?;
                let unit = u16::from_le_bytes([raw[0], raw[1]]);
                if unit == 0 { return Ok(value); }
                value.push(unit);
            }
            Err(Error::Bounds)
        })
    }
    fn sid(&self, pointer: S::PSID) -> Result<Vec<u8>> { self.sid_traced(pointer, &mut InputTrace::default()) }
    fn sid_traced(&self, pointer: S::PSID, trace: &mut InputTrace) -> Result<Vec<u8>> {
        trace.prerequisite_scope(PrerequisiteCheck::N01, |trace| {
            let head = self.range_traced(pointer.cast(), 8, trace)?;
            need(head[0] == 1 && head[1] <= 15)?;
            let raw = self.range_traced(pointer.cast(), 8 + head[1] as usize * 4, trace)?;
            Ok(security::sid_at(raw, 0, raw.len())?.bytes().to_vec())
        })
    }
    fn free(&mut self) -> Result<()> { self.free_traced(&mut InputTrace::default()) }
    fn free_traced(&mut self, trace: &mut InputTrace) -> Result<()> {
        trace.prerequisite_scope(PrerequisiteCheck::N02, |trace| {
            if self.release_attempted { return Err(Error::State); }
            self.release_attempted = true;
            if self.pointer.is_null() {
                self.released = self.status == NM::NERR_UserNotFound || self.status == 0 && self.entries == 0;
                return if self.released { Ok(()) } else { Err(Error::Unknown) };
            }
            if self.status != 0 { return Err(Error::Unknown); }
            self.release_status = unsafe { NM::NetApiBufferFree(self.pointer.cast()) };
            self.released = self.release_status == 0;
            if !self.released {
                trace.prerequisite_fault(PrerequisiteCheck::N02, Error::Unknown,
                    PrerequisiteNative::net(PrerequisiteApi::NetApiBufferFree, PrerequisiteSelector::None, self.release_status), None);
            }
            if self.released { Ok(()) } else { Err(Error::Unknown) }
        })
    }
}
struct Account {
    name: Vec<u16>, password: Box<[u16; 65]>, users: Vec<u16>, sid: Vec<u8>,
    absent: u32, absent_pointer_null: bool, add: u32, group_add: bool, attempted: bool,
    delete_attempted: bool, delete_status: u32, removed: bool,
    queries: Vec<Box<NetBuffer>>,
}
impl Account {
    fn new() -> Result<Self> { Self::new_traced(&mut InputTrace::default()) }
    fn new_traced(trace: &mut InputTrace) -> Result<Self> {
        trace.prerequisite_scope(PrerequisiteCheck::N03, |trace| {
            let mut sid = builtin(545); let mut name_buffer = [0u16; 256]; let mut domain = [0u16; 256];
            let mut name_units = 256; let mut domain_units = 256; let mut usage = 0;
            let ok = unsafe { S::LookupAccountSidW(null(), sid.as_mut_ptr().cast(), name_buffer.as_mut_ptr(),
                &mut name_units, domain.as_mut_ptr(), &mut domain_units, &mut usage) };
            let lookup_error = if ok == 0 && trace.prerequisite.is_some() { unsafe { F::GetLastError() } } else { 0 };
            if ok == 0 {
                trace.prerequisite_fault(PrerequisiteCheck::N03, Error::Unsafe,
                    PrerequisiteNative::boolean(PrerequisiteApi::LookupAccountSidW, PrerequisiteSelector::None, ok, Some(lookup_error)), None);
            }
            need(ok != 0 && usage == S::SidTypeAlias && name_units > 0 && name_units < 256
                && domain_units < 256 && String::from_utf16(&domain[..domain_units as usize]).map_err(|_| Error::Unsafe)? == "BUILTIN")?;
            let users = name_buffer[..name_units as usize].iter().copied().chain(std::iter::once(0)).collect();
            // Resolve the well-known Users alias BEFORE any password exists.
            let mut random = [0u8; 68];
            let random_status = unsafe { BC::BCryptGenRandom(null_mut(), random.as_mut_ptr(), random.len() as u32,
                BC::BCRYPT_USE_SYSTEM_PREFERRED_RNG) };
            if random_status != 0 {
                for byte in &mut random { unsafe { std::ptr::write_volatile(byte, 0); } }
                std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
                trace.prerequisite_fault(PrerequisiteCheck::N03, Error::Unavailable,
                    PrerequisiteNative::nt(PrerequisiteApi::BCryptGenRandom, PrerequisiteSelector::None, random_status), None);
                return Err(Error::Unavailable);
            }
            let name = wide(&format!("mrk{}", hex(&random[..8])));
            let mut password = Box::new([0u16; 65]);
            password[..4].copy_from_slice(&[b'A' as u16, b'a' as u16, b'7' as u16, b'!' as u16]);
            let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!_";
            for (slot, byte) in password[4..64].iter_mut().zip(&random[8..]) { *slot = alphabet[(*byte & 63) as usize] as u16; }
            for byte in &mut random { unsafe { std::ptr::write_volatile(byte, 0); } }
            std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
            Ok(Self { name, password, users, sid: Vec::new(), absent: u32::MAX, absent_pointer_null: false,
                add: u32::MAX, group_add: false, attempted: false, delete_attempted: false,
                delete_status: u32::MAX, removed: false, queries: Vec::with_capacity(8) })
        })
    }
    fn zero(&mut self) {
        for unit in self.password.iter_mut() { unsafe { std::ptr::write_volatile(unit, 0); } }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
    fn query(&mut self) -> Result<Option<Vec<u8>>> { self.query_traced(&mut InputTrace::default()) }
    fn query_traced(&mut self, trace: &mut InputTrace) -> Result<Option<Vec<u8>>> {
        trace.prerequisite_scope(PrerequisiteCheck::N04, |trace| {
            need(self.queries.len() < 8)?;
            let first_query = self.queries.is_empty();
            self.queries.push(Box::new(NetBuffer::new()));
            let q = self.queries.last_mut().ok_or(Error::State)?;
            q.status = unsafe { NM::NetUserGetInfo(null(), self.name.as_ptr(), 23, &mut q.pointer) };
            if q.status == NM::NERR_UserNotFound && q.pointer.is_null() {
                if first_query { self.absent = q.status; self.absent_pointer_null = q.pointer.is_null(); }
                q.free_traced(trace)?; return Ok(None);
            }
            if q.status != 0 {
                trace.prerequisite_fault(PrerequisiteCheck::N04, Error::Unknown,
                    PrerequisiteNative::net(PrerequisiteApi::NetUserGetInfo, PrerequisiteSelector::UserInfo23, q.status), None);
            }
            let observed = (|| -> Result<Vec<u8>> {
                q.sized_traced(trace)?;
                q.range_traced(q.pointer, size_of::<NM::USER_INFO_23>(), trace)?;
                let info = unsafe { std::ptr::read_unaligned(q.pointer.cast::<NM::USER_INFO_23>()) };
                need(q.string_traced(info.usri23_name, 20, trace)? == self.name[..self.name.len() - 1]
                    && info.usri23_flags == (NM::UF_SCRIPT | NM::UF_NORMAL_ACCOUNT))?;
                q.sid_traced(info.usri23_user_sid, trace)
            })();
            let observed = trace.prerequisite_result(PrerequisiteCheck::N04, observed);
            let freed = q.free_traced(trace);
            if freed.is_err() { return Err(Error::Unknown); }
            observed.map(Some)
        })
    }
    fn groups(&mut self) -> Result<Vec<Vec<u8>>> { self.groups_traced(&mut InputTrace::default()) }
    fn groups_traced(&mut self, trace: &mut InputTrace) -> Result<Vec<Vec<u8>>> {
        trace.prerequisite_scope(PrerequisiteCheck::N05, |trace| {
            need(self.queries.len() < 8)?;
            self.queries.push(Box::new(NetBuffer::new()));
            let q = self.queries.last_mut().ok_or(Error::State)?;
            q.status = unsafe { NM::NetUserGetLocalGroups(null(), self.name.as_ptr(), 0, NM::LG_INCLUDE_INDIRECT,
                &mut q.pointer, BUFFER as u32, &mut q.entries, &mut q.total) };
            let observed = (|| -> Result<Vec<Vec<u8>>> {
                if q.status != 0 || q.entries != q.total {
                    trace.prerequisite_fault(PrerequisiteCheck::N05, Error::Unknown,
                        PrerequisiteNative::net(PrerequisiteApi::NetUserGetLocalGroups, PrerequisiteSelector::LocalGroups0, q.status), None);
                    return Err(Error::Unknown);
                }
                need(q.entries <= 1)?;
                if q.entries == 0 {
                    if !q.pointer.is_null() { return Err(Error::Unknown); }
                    return Ok(Vec::new());
                }
                q.sized_traced(trace)?; q.range_traced(q.pointer, size_of::<NM::LOCALGROUP_USERS_INFO_0>(), trace)?;
                let info = unsafe { std::ptr::read_unaligned(q.pointer.cast::<NM::LOCALGROUP_USERS_INFO_0>()) };
                need(q.string_traced(info.lgrui0_name, 256, trace)? == self.users[..self.users.len() - 1])?;
                Ok(vec![builtin(545)])
            })();
            let observed = trace.prerequisite_result(PrerequisiteCheck::N05, observed);
            let freed = q.free_traced(trace);
            if freed.is_err() { return Err(Error::Unknown); }
            observed
        })
    }
    fn create(&mut self, parent: &[u8], start: Instant, deadline_latched: &mut bool, aggregate: &mut Option<AggregateClock>) -> Result<()> { self.create_traced(parent, start, deadline_latched, aggregate, &mut InputTrace::default()) }
    fn create_traced(&mut self, parent: &[u8], start: Instant, deadline_latched: &mut bool, aggregate: &mut Option<AggregateClock>, trace: &mut InputTrace) -> Result<()> {
        trace.prerequisite_scope(PrerequisiteCheck::N06, |trace| {
            if self.attempted { return Err(Error::State); }
            owner_effect_traced(start, deadline_latched, aggregate, trace)?;
            self.attempted = true; // Caller already registered durable private intent.
            need(self.query_traced(trace)?.is_none())?;
            owner_effect_traced(start, deadline_latched, aggregate, trace)?;
            let mut information = NM::USER_INFO_1::default();
            information.usri1_name = self.name.as_mut_ptr(); information.usri1_password = self.password.as_mut_ptr();
            information.usri1_priv = NM::USER_PRIV_USER;
            information.usri1_flags = NM::UF_SCRIPT | NM::UF_NORMAL_ACCOUNT;
            let mut parameter = 0u32;
            owner_effect_traced(start, deadline_latched, aggregate, trace)?;
            self.add = unsafe { NM::NetUserAdd(null(), 1, (&information as *const NM::USER_INFO_1).cast(), &mut parameter) };
            // Any creation error/ambiguity retains intent; never delete an account
            // selected merely by this name, reuse a collision, or retry creation.
            if self.add != 0 {
                trace.prerequisite_fault(PrerequisiteCheck::N06, Error::Unknown,
                    PrerequisiteNative::net(PrerequisiteApi::NetUserAdd, PrerequisiteSelector::UserAdd1, self.add), None);
                return Err(Error::Unknown);
            }
            owner_effect_traced(start, deadline_latched, aggregate, trace)?;
            self.sid = self.query_traced(trace)?.ok_or(Error::Unknown)?;
            owner_effect_traced(start, deadline_latched, aggregate, trace)?;
            // A local creation cannot adopt an alias of the parent's identity or a
            // foreign/malformed SID before changing membership or granting rights.
            if !local_account_sid(&self.sid) || !local_account_sid(parent)
                || self.sid[..24] != parent[..24] || self.sid == parent {
                return Err(Error::Unknown);
            }
            if self.groups_traced(trace)?.is_empty() {
                let member = NM::LOCALGROUP_MEMBERS_INFO_0 { lgrmi0_sid: self.sid.as_mut_ptr().cast() };
                owner_effect_traced(start, deadline_latched, aggregate, trace)?;
                self.group_add = true;
                let status = unsafe { NM::NetLocalGroupAddMembers(null(), self.users.as_ptr(), 0,
                    (&member as *const NM::LOCALGROUP_MEMBERS_INFO_0).cast(), 1) };
                if status != 0 {
                    trace.prerequisite_fault(PrerequisiteCheck::N06, Error::Unknown,
                        PrerequisiteNative::net(PrerequisiteApi::NetLocalGroupAddMembers, PrerequisiteSelector::GroupAdd0, status), None);
                    return Err(Error::Unknown);
                }
                owner_effect_traced(start, deadline_latched, aggregate, trace)?;
            }
            let groups = self.groups_traced(trace)?;
            owner_effect_traced(start, deadline_latched, aggregate, trace)?;
            need(fresh_account(self.absent, self.absent_pointer_null, self.add, &self.sid, &groups))?;
            owner_effect_traced(start, deadline_latched, aggregate, trace)
        })
    }
    fn retire(&mut self, start: Instant, deadline_latched: &mut bool, aggregate: &mut Option<AggregateClock>) -> Result<()> { self.retire_traced(start, deadline_latched, aggregate, &mut InputTrace::default()) }
    fn retire_traced(&mut self, start: Instant, deadline_latched: &mut bool, aggregate: &mut Option<AggregateClock>, trace: &mut InputTrace) -> Result<()> {
        trace.prerequisite_scope(PrerequisiteCheck::N07, |trace| {
            owner_effect_traced(start, deadline_latched, aggregate, trace)?;
            need(self.attempted && self.add == 0 && !self.delete_attempted && !self.removed && !self.sid.is_empty()
                && self.password.iter().all(|unit| *unit == 0))?;
            // No name-only cleanup: immediately reobserve the actual returned SID.
            need(self.query_traced(trace)?.as_deref() == Some(self.sid.as_slice()) && self.groups_traced(trace)? == [builtin(545)])?;
            owner_effect_traced(start, deadline_latched, aggregate, trace)?;
            self.delete_attempted = true; // Irreversible intent, not a success receipt.
            self.delete_status = unsafe { NM::NetUserDel(null(), self.name.as_ptr()) };
            if self.delete_status != 0 {
                trace.prerequisite_fault(PrerequisiteCheck::N07, Error::Unknown,
                    PrerequisiteNative::net(PrerequisiteApi::NetUserDel, PrerequisiteSelector::None, self.delete_status), None);
                return Err(Error::Unknown);
            }
            owner_effect_traced(start, deadline_latched, aggregate, trace)?;
            if self.query_traced(trace)?.is_some() { return Err(Error::Unknown); }
            self.removed = true;
            owner_effect_traced(start, deadline_latched, aggregate, trace)
        })
    }
}
impl Drop for Account {
    fn drop(&mut self) { self.zero(); } // Only owned memory, never OS/account cleanup.
}

#[derive(Clone)]
pub(super) struct Binding {
    source: String, tree: String, run: String, artifact: String,
    bytes: usize, sha: String, command_sha: String, identity: String,
}
impl Binding {
    pub fn parse(raw: &[u8]) -> Result<Self> {
        Self::parse_traced(raw, &mut InputTrace::default())
    }
    fn parse_traced(raw: &[u8], trace: &mut InputTrace) -> Result<Self> {
        trace.need(raw.len() <= LIMIT && raw.is_ascii() && raw.ends_with(b"\n") && !raw.contains(&b'\r'), InputCheck::RequestEnvelope)?;
        let text = trace.observed(std::str::from_utf8(raw).map_err(|_| Error::Unsafe), InputCheck::RequestUtf8)?;
        let lines: Vec<_> = text.lines().collect();
        trace.need(lines.len() == 10, InputCheck::RequestLines)?;
        trace.need(lines[0] == "MRK_WINDOWS_ORDINARY_REQUEST_V1", InputCheck::RequestHeader)?;
        let mut values = Vec::new();
        for (line, key) in lines[1..].iter().zip([
            "sourceSha", "sourceTree", "runId", "attempt", "artifact", "artifactBytes", "artifactSha256", "commandSha256", "artifactIdentity",
        ]) {
            let (name, value) = trace.observed(line.split_once('=').ok_or(Error::Unsafe), InputCheck::RequestKey)?;
            trace.need(name == key, InputCheck::RequestKey)?;
            trace.need(!value.is_empty(), InputCheck::RequestValue)?; values.push(value);
        }
        trace.need(is_hex(values[0], 40) && values[0] != "0".repeat(40) && is_hex(values[1], 40)
            && values[1] != "0".repeat(40) && decimal(values[2]) && values[3] == "1"
            && is_hex(values[6], 64) && is_hex(values[7], 64) && decimal(values[5]), InputCheck::RequestValues)?;
        trace.observed(fixed_path(values[4]), InputCheck::RequestArtifactPath)?;
        let bytes = trace.observed(values[5].parse().map_err(|_| Error::Unsafe), InputCheck::RequestBytes)?;
        trace.need(bytes > 0 && bytes <= 128 << 20, InputCheck::RequestBytesRange)?;
        let identity: Vec<_> = values[8].split(':').collect();
        trace.need(identity.len() == 6 && is_hex(identity[1], 32) && identity[1] != "0".repeat(32)
            && decimal(identity[0]) && identity[0].parse::<u64>().is_ok()
            && identity[2..5].iter().all(|value| decimal(value) && value.parse::<i64>().is_ok())
            && decimal(identity[5]) && identity[5].parse::<u32>().is_ok(), InputCheck::RequestIdentity)?;
        Ok(Self { source: values[0].to_owned(), tree: values[1].to_owned(), run: values[2].to_owned(),
            artifact: values[4].to_owned(), bytes, sha: values[6].to_owned(), command_sha: values[7].to_owned(),
            identity: values[8].to_owned() })
    }
    pub fn matches(&self, stamp: &Stamp) -> bool {
        stamp.wire() == self.identity && stamp.size == self.bytes as i64 && stamp.links == 1
    }
    fn compiled(&self) -> Result<()> {
        self.compiled_traced(&mut InputTrace::default())
    }
    fn compiled_traced(&self, trace: &mut InputTrace) -> Result<()> {
        let source = trace.observed(super::hosted_tests::hosted_source(), InputCheck::BindingSourceAvailable)?;
        trace.need(source == self.source, InputCheck::BindingSource)?;
        trace.need(option_env!("MRK_WINDOWS_SOURCE_TREE") == Some(self.tree.as_str()), InputCheck::BindingTree)?;
        trace.need(option_env!("GITHUB_RUN_ID") == Some(self.run.as_str()), InputCheck::BindingRun)?;
        trace.need(std::env::var("GITHUB_RUN_ID").as_deref() == Ok(self.run.as_str()), InputCheck::BindingRuntimeRun)?;
        trace.need(std::env::var("MRK_WINDOWS_SOURCE_TREE").as_deref() == Ok(self.tree.as_str()), InputCheck::BindingRuntimeTree)
    }
    fn result(&self, sid_sha: &str) -> String {
        // The caller is ONLY the already-settled, exact-count positive branch.
        // File closure is gated by that original child's observed exit zero,
        // never asserted inside the bytes which precede their own close.
        format!("{{\"schemaVersion\":1,\"sourceSha\":\"{}\",\"sourceTree\":\"{}\",\"runId\":\"{}\",\"attempt\":1,\"artifactBytes\":{},\"artifactSha256\":\"{}\",\"commandSha256\":\"{}\",\"accountSidSha256\":\"{}\",\"test\":\"{CHILD}\",\"native\":{{\"context\":\"ordinary-admitted\",\"contextContracts\":1,\"admitted\":1,\"refused\":0,\"rootContracts\":1,\"rootNotExecuted\":0,\"primaryOriginals\":1,\"absentThreadReceipts\":6,\"closedOriginals\":2,\"unknown\":0,\"bookSettled\":true}},\"resultFile\":{{\"createNew\":true,\"writeCalls\":1,\"closeGate\":\"original-child-exit-zero-required\"}}}}\n",
            self.source, self.tree, self.run, self.bytes, self.sha, self.command_sha, sid_sha)
    }
}

pub(super) fn write_native_result(actual_user: &[u8]) -> Result<()> {
    let get = |name| std::env::var(name).map_err(|_| Error::State);
    let artifact = std::env::current_exe().map_err(|_| Error::Unavailable)?;
    let image = artifact.to_str().ok_or(Error::Unsafe)?;
    fixed_path(image)?; args_are(CHILD, &artifact)?;
    let raw = format!("MRK_WINDOWS_ORDINARY_REQUEST_V1\nsourceSha={}\nsourceTree={}\nrunId={}\nattempt=1\nartifact={}\nartifactBytes={}\nartifactSha256={}\ncommandSha256={}\nartifactIdentity={}\n",
        get("GITHUB_SHA")?, get("MRK_WINDOWS_SOURCE_TREE")?, get("GITHUB_RUN_ID")?, image,
        get("MRK_WINDOWS_NATIVE_ARTIFACT_BYTES")?, get("MRK_WINDOWS_NATIVE_ARTIFACT_SHA256")?,
        get("MRK_WINDOWS_NATIVE_COMMAND_SHA256")?, get("MRK_WINDOWS_NATIVE_ARTIFACT_IDENTITY")?);
    let binding = Binding::parse(raw.as_bytes())?; binding.compiled()?;
    need(command_digest(image)? == binding.command_sha)?;
    let account = unhex(&get("MRK_WINDOWS_ORDINARY_SID")?)?;
    let parent = unhex(&get("MRK_WINDOWS_PARENT_SID")?)?;
    need(account == actual_user && account != parent && account != system_sid() && account != builtin(544))?;
    let output = fixed_path(&get("MRK_WINDOWS_ORDINARY_OUTPUT")?)?;
    need(std::env::current_dir().map_err(|_| Error::Unavailable)? == output
        && output.file_name().and_then(|s| s.to_str()) == Some("ordinary-output"))?;
    let mut file = OriginalFile::new(&artifact, false)?;
    let observation = (|| -> Result<()> {
        file.open(FS::FILE_GENERIC_READ, false, null())?; file.named(&artifact)?;
        need(binding.matches(&file.stamp()?))?;
        let raw = file.read(128 << 20)?;
        need(raw.len() == binding.bytes && digest(&raw)? == binding.sha)
    })();
    if matches!(observation, Err(Error::Unknown)) {
        loop { std::thread::park(); std::hint::black_box(&mut file); }
    }
    let closed = file.close();
    if closed.is_err() {
        loop { std::thread::park(); std::hint::black_box(&mut file); }
    }
    observation?;
    let value = binding.result(&digest(actual_user)?);
    need(value.len() <= LIMIT)?;
    let (acl, mut descriptor) = child_security(&parent, &account)?;
    let attributes = S::SECURITY_ATTRIBUTES { nLength: size_of::<S::SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: (&mut *descriptor as *mut S::SECURITY_DESCRIPTOR).cast(), bInheritHandle: 0 };
    // Unknown parks inside write_one: this same stack still owns the complete
    // security inputs and child original; it never leaks then exits as "settled".
    let result = write_one(&output.join(RESULT), value.as_bytes(), LIMIT, &attributes);
    std::hint::black_box((&acl, &descriptor, &attributes));
    result
}

struct Launch {
    domain: [u16; 2], application: Vec<u16>, command: Vec<u16>, environment: Vec<u16>, directory: Vec<u16>,
    logon_flags: u32,
    startup: T::STARTUPINFOW, outputs: T::PROCESS_INFORMATION,
    return_recorded: bool, returned: i32, error: u32, first_wait: u32,
    settle_wait: u32, first_wait_error: u32, settle_wait_error: u32, exit_output: u32, exit_return: i32,
    exit_error: u32, terminate_return: i32, terminate_error: u32,
    process_close: i32, process_close_error: u32, thread_close: i32, thread_close_error: u32,
    facts: ProcessFacts, _pin: PhantomPinned,
}
impl Launch {
    fn new(variant: OwnerVariant, binding: &Binding, fullwalk_request: Option<&str>,
        output: &Path, account: &Account, parent: &[u8]) -> Result<Pin<Box<Self>>> { Self::new_traced(variant, binding, fullwalk_request, output, account, parent, &mut InputTrace::default()) }
    fn new_traced(variant: OwnerVariant, binding: &Binding, fullwalk_request: Option<&str>,
        output: &Path, account: &Account, parent: &[u8], trace: &mut InputTrace) -> Result<Pin<Box<Self>>> {
        trace.prerequisite_scope(PrerequisiteCheck::D01, |trace| {
            let output = output.to_str().ok_or(Error::Unsafe)?;
            let system_root = std::env::var("SystemRoot").map_err(|_| Error::State)?;
            fixed_path_traced(&system_root, trace)?;
            let mut windows = [0u16; 32768];
            let count = unsafe { SI::GetSystemWindowsDirectoryW(windows.as_mut_ptr(), windows.len() as u32) };
            let windows_error = if count == 0 && trace.prerequisite.is_some() { unsafe { F::GetLastError() } } else { 0 };
            if count == 0 {
                trace.prerequisite_fault(PrerequisiteCheck::D01, Error::Unsafe,
                    PrerequisiteNative::count(PrerequisiteApi::GetSystemWindowsDirectoryW, count, windows_error), None);
            }
            need(count > 0 && (count as usize) < windows.len()
                && String::from_utf16(&windows[..count as usize]).map_err(|_| Error::Unsafe)? == system_root)?;
            let mut environment = vec![
                ("GITHUB_ACTIONS", "true".to_owned()), ("GITHUB_RUN_ATTEMPT", "1".to_owned()),
                ("GITHUB_RUN_ID", binding.run.clone()), ("GITHUB_SHA", binding.source.clone()),
                ("ImageOS", "win25-vs2026".to_owned()), ("MRK_DESKTOP_HOSTED_CHECKS", "windows-installed-native-v1".to_owned()),
                ("MRK_WINDOWS_NATIVE_ARTIFACT_BYTES", binding.bytes.to_string()),
                ("MRK_WINDOWS_NATIVE_ARTIFACT_SHA256", binding.sha.clone()),
                ("MRK_WINDOWS_NATIVE_ARTIFACT_IDENTITY", binding.identity.clone()),
                ("MRK_WINDOWS_NATIVE_COMMAND_SHA256", binding.command_sha.clone()),
                ("MRK_WINDOWS_ORDINARY_OUTPUT", output.to_owned()), ("MRK_WINDOWS_ORDINARY_SID", hex(&account.sid)),
                ("MRK_WINDOWS_PARENT_SID", hex(parent)), ("MRK_WINDOWS_SOURCE_TREE", binding.tree.clone()),
                ("PATH", format!("{system_root}\\System32;{system_root}")), ("RUNNER_ARCH", "X64".to_owned()),
                ("RUNNER_ENVIRONMENT", "github-hosted".to_owned()), ("RUNNER_OS", "Windows".to_owned()),
                ("SystemRoot", system_root.clone()), ("TEMP", output.to_owned()), ("TMP", output.to_owned()),
                ("WINDIR", system_root),
            ];
            match (variant, fullwalk_request) {
                (OwnerVariant::Ordinary, None) => (), // Ordinary environment stays byte-for-byte unchanged.
                (OwnerVariant::Fullwalk | OwnerVariant::Passive, Some(request)) => {
                    need(request.len() <= LIMIT && request.is_ascii())?;
                    environment.retain(|(name, _)| !matches!(*name,
                        "MRK_WINDOWS_NATIVE_ARTIFACT_BYTES" | "MRK_WINDOWS_NATIVE_ARTIFACT_SHA256"
                        | "MRK_WINDOWS_NATIVE_ARTIFACT_IDENTITY" | "MRK_WINDOWS_NATIVE_COMMAND_SHA256"
                        | "MRK_WINDOWS_ORDINARY_OUTPUT"));
                    if variant == OwnerVariant::Passive {
                        environment.extend([
                            ("MRK_WINDOWS_PASSIVE_REQUEST", request.to_owned()),
                            ("MRK_WINDOWS_PASSIVE_ARTIFACT_IDENTITY", binding.identity.clone()),
                            ("MRK_WINDOWS_PASSIVE_OUTPUT", output.to_owned()),
                            ("PYTHONHOME", output.to_owned()), ("PYTHONPATH", output.to_owned()),
                            ("PYTHONSTARTUP", format!("{output}\\never-present.py")), ("HOME", output.to_owned()),
                        ]);
                        // Only this task-owned, fresh test process receives inert
                        // wrong ambient values. No Windows directory/file changes.
                        for (name, value) in &mut environment {
                            if matches!(*name, "PATH" | "SystemRoot" | "WINDIR") { *value = output.to_owned(); }
                        }
                    } else {
                        environment.extend([
                            ("MRK_WINDOWS_FULLWALK_REQUEST", request.to_owned()),
                            ("MRK_WINDOWS_FULLWALK_ARTIFACT_IDENTITY", binding.identity.clone()),
                            ("MRK_WINDOWS_FULLWALK_OUTPUT", output.to_owned()),
                        ]);
                    }
                },
                _ => return Err(Error::State),
            }
            environment.sort_by_key(|(name, _)| name.to_ascii_uppercase());
            let environment: Vec<u16> = environment.iter().flat_map(|(name, value)| wide(&format!("{name}={value}")))
                .chain(std::iter::once(0)).collect();
            let command = variant.command(&binding.artifact);
            need(environment.len() <= 8192 && command.encode_utf16().count() <= 1023)?;
            let mut startup = T::STARTUPINFOW::default(); startup.cb = size_of::<T::STARTUPINFOW>() as u32;
            // lpDesktop=null explicitly inherits the actual desktop/station. Their
            // access is NOT precomputed, granted, or inferred from headlessness.
            // All flags/std handles remain zero: no profile, shell or redirection.
            Ok(Box::pin(Self { domain: [b'.' as u16, 0], application: wide(&binding.artifact), command: wide(&command), logon_flags: 0,
                environment, directory: wide(output), startup, outputs: T::PROCESS_INFORMATION::default(),
                return_recorded: false, returned: 0, error: 0, first_wait: u32::MAX,
                settle_wait: u32::MAX, first_wait_error: 0, settle_wait_error: 0, exit_output: 0,
                exit_return: 0, exit_error: 0, terminate_return: 0, terminate_error: 0,
                process_close: 0, process_close_error: 0, thread_close: 0, thread_close_error: 0,
                facts: ProcessFacts::new(), _pin: PhantomPinned }))
        })
    }
    fn enter(self: Pin<&mut Self>, account: &mut Account, start: Instant, deadline_latched: &mut bool, aggregate: &mut Option<AggregateClock>) -> Result<()> { self.enter_traced(account, start, deadline_latched, aggregate, &mut InputTrace::default()) }
    fn enter_traced(self: Pin<&mut Self>, account: &mut Account, start: Instant, deadline_latched: &mut bool, aggregate: &mut Option<AggregateClock>, trace: &mut InputTrace) -> Result<()> {
        trace.prerequisite_scope(PrerequisiteCheck::D03, |trace| {
            let this = unsafe { self.get_unchecked_mut() };
            owner_effect_traced(start, deadline_latched, aggregate, trace)?;
            if let Some(clock) = aggregate.as_mut() { clock.sample(true)?; }
            this.facts.begin()?;
            // Every UTF-16 input, full STARTUPINFO, complete initialized PI and
            // return/error destinations are owned/stable BEFORE this sole entry.
            this.returned = unsafe { T::CreateProcessWithLogonW(account.name.as_ptr(), this.domain.as_ptr(),
                account.password.as_ptr(), this.logon_flags, this.application.as_ptr(), this.command.as_mut_ptr(),
                T::CREATE_UNICODE_ENVIRONMENT, this.environment.as_ptr().cast(), this.directory.as_ptr(),
                &this.startup, &mut this.outputs) };
            this.error = if this.returned == 0 { unsafe { F::GetLastError() } } else { 0 };
            this.return_recorded = true;
            // No allocation, formatting, new call or ownership adoption intervened.
            account.zero(); // Only now has its original plaintext borrower returned.
            let creation = this.facts.creation(this.returned != 0, this.error,
                (this.outputs.hProcess as usize, this.outputs.hThread as usize,
                    this.outputs.dwProcessId, this.outputs.dwThreadId),
                start.elapsed() >= Duration::from_secs(NATIVE_SECONDS));
            // The password-zeroing window above is untouched. Preserve this raw
            // creation decision before the original clock can fail independently.
            let creation = trace.prerequisite_native_result(PrerequisiteCheck::D03, creation,
                PrerequisiteNative::boolean(PrerequisiteApi::CreateProcessWithLogonW, PrerequisiteSelector::None, this.returned, Some(this.error)), None);
            let timely = owner_effect_traced(start, deadline_latched, aggregate, trace);
            if timely.is_err() { this.facts.failed = true; }
            creation?; timely
        })
    }
    fn finish(self: Pin<&mut Self>, start: Instant, aggregate: &mut Option<AggregateClock>) { self.finish_traced(start, aggregate, &mut InputTrace::default()) }
    fn finish_traced(self: Pin<&mut Self>, start: Instant, aggregate: &mut Option<AggregateClock>, trace: &mut InputTrace) {
        let this = unsafe { self.get_unchecked_mut() };
        if !this.return_recorded || !this.facts.created { return; }
        batch_return(&mut this.facts, aggregate);
        if !this.facts.failed {
            let remaining = Duration::from_secs(NATIVE_SECONDS).saturating_sub(start.elapsed());
            if remaining.is_zero() {
                this.facts.failed = true;
                trace.prerequisite_fault(PrerequisiteCheck::D04, Error::Unsafe, None, None);
            }
            else {
                this.first_wait = unsafe { T::WaitForSingleObject(this.outputs.hProcess,
                    remaining.as_millis().min(u128::from(u32::MAX - 1)) as u32) };
                this.first_wait_error = if this.first_wait == F::WAIT_FAILED { unsafe { F::GetLastError() } } else { 0 };
                let before = (this.facts.failed, this.facts.unknown);
                let original = this.facts.wait(this.first_wait, start.elapsed() >= Duration::from_secs(NATIVE_SECONDS));
                let _ = prerequisite_process_decision(trace, PrerequisiteCheck::D04, original, before, &this.facts,
                    PrerequisiteNative::wait(PrerequisiteSelector::FirstWait, this.first_wait, this.first_wait_error));
                batch_return(&mut this.facts, aggregate);
            }
        }
        if !this.facts.signaled && {
            let before = (this.facts.failed, this.facts.unknown);
            let original = this.facts.begin_terminate();
            prerequisite_process_decision(trace, PrerequisiteCheck::D04, original, before, &this.facts, None).is_ok()
        } {
            this.terminate_return = unsafe { T::TerminateProcess(this.outputs.hProcess, 125) };
            this.terminate_error = if this.terminate_return == 0 { unsafe { F::GetLastError() } } else { 0 };
            if this.terminate_return == 0 {
                this.facts.unknown = true;
                trace.prerequisite_fault(PrerequisiteCheck::D04, Error::Unknown,
                    PrerequisiteNative::boolean(PrerequisiteApi::TerminateProcess, PrerequisiteSelector::None,
                        this.terminate_return, Some(this.terminate_error)), None);
            }
            batch_return(&mut this.facts, aggregate);
            // Termination is asynchronous. Even its success is not finality.
            this.settle_wait = unsafe { T::WaitForSingleObject(this.outputs.hProcess, SETTLE_MS) };
            this.settle_wait_error = if this.settle_wait == F::WAIT_FAILED { unsafe { F::GetLastError() } } else { 0 };
            let before = (this.facts.failed, this.facts.unknown);
            let original = this.facts.wait(this.settle_wait, true);
            let _ = prerequisite_process_decision(trace, PrerequisiteCheck::D04, original, before, &this.facts,
                PrerequisiteNative::wait(PrerequisiteSelector::SettleWait, this.settle_wait, this.settle_wait_error));
            batch_return(&mut this.facts, aggregate);
        }
        if !this.facts.signaled {
            this.facts.unknown = true;
            trace.prerequisite_fault(PrerequisiteCheck::D04, Error::Unknown, None, None);
            return;
        }
        this.exit_return = unsafe { T::GetExitCodeProcess(this.outputs.hProcess, &mut this.exit_output) };
        this.exit_error = if this.exit_return == 0 { unsafe { F::GetLastError() } } else { 0 };
        let before = (this.facts.failed, this.facts.unknown);
        let original = this.facts.exited(this.exit_return != 0, this.exit_output);
        let native = if this.exit_return == 0 {
            PrerequisiteNative::boolean(PrerequisiteApi::GetExitCodeProcess, PrerequisiteSelector::None, this.exit_return, Some(this.exit_error))
        } else { PrerequisiteNative::exit(this.exit_output) };
        let _ = prerequisite_process_decision(trace, PrerequisiteCheck::D05, original, before, &this.facts, native);
        batch_return(&mut this.facts, aggregate);
        // Every borrower has returned before either once-only original close.
        if prerequisite_result!(trace, D05, this.facts.begin_close(true)).is_ok() {
            this.thread_close = unsafe { F::CloseHandle(this.outputs.hThread) };
            this.thread_close_error = if this.thread_close == 0 { unsafe { F::GetLastError() } } else { 0 };
            let before = (this.facts.failed, this.facts.unknown);
            let original = this.facts.closed(true, this.thread_close != 0);
            let _ = prerequisite_process_decision(trace, PrerequisiteCheck::D05, original, before, &this.facts,
                PrerequisiteNative::boolean(PrerequisiteApi::CloseHandle, PrerequisiteSelector::ThreadClose,
                    this.thread_close, Some(this.thread_close_error)));
            batch_return(&mut this.facts, aggregate);
        }
        if prerequisite_result!(trace, D05, this.facts.begin_close(false)).is_ok() {
            this.process_close = unsafe { F::CloseHandle(this.outputs.hProcess) };
            this.process_close_error = if this.process_close == 0 { unsafe { F::GetLastError() } } else { 0 };
            let before = (this.facts.failed, this.facts.unknown);
            let original = this.facts.closed(false, this.process_close != 0);
            let _ = prerequisite_process_decision(trace, PrerequisiteCheck::D05, original, before, &this.facts,
                PrerequisiteNative::boolean(PrerequisiteApi::CloseHandle, PrerequisiteSelector::ProcessClose,
                    this.process_close, Some(this.process_close_error)));
            batch_return(&mut this.facts, aggregate);
        }
    }
}

fn parent_user(book: &mut NativeBook) -> Result<Vec<u8>> { parent_user_traced(book, &mut InputTrace::default()) }
fn parent_user_traced(book: &mut NativeBook, trace: &mut InputTrace) -> Result<Vec<u8>> {
    trace.prerequisite_scope(PrerequisiteCheck::D06, |trace| {
        let index = book.process_token.ok_or(Error::State)?;
        let complete = book.prerequisite_observe(trace, PrerequisiteCheck::NB10, |book| book.token(index, S::TokenUser))?;
        let raw = complete.bytes(complete.count()?)?;
        need(raw.len() >= size_of::<S::TOKEN_USER>())?;
        let pointer = decode::u64_at(raw, offset_of!(S::TOKEN_USER, User) + offset_of!(S::SID_AND_ATTRIBUTES, Sid))? as usize;
        let offset = pointer.checked_sub(raw.as_ptr() as usize).ok_or(Error::Unsafe)?;
        need(offset >= size_of::<S::TOKEN_USER>())?;
        let sid = security::sid_at(raw, offset, raw.len())?.bytes().to_vec();
        need(sid.len() == 28 && sid != system_sid() && sid != builtin(544))?;
        Ok(sid)
    })
}
fn diagnostic(stage: &'static str, launch: Option<&Launch>, unknown: bool) {
    diagnostic_with_fault(stage, launch, unknown, None);
}
fn diagnostic_with_fault(stage: &'static str, launch: Option<&Launch>, unknown: bool, fault: Option<InputFault>) {
    let facts = launch.map(|value| (value.return_recorded, value.error, value.facts.exit,
        [value.first_wait, value.first_wait_error, value.settle_wait, value.settle_wait_error,
            value.exit_error, value.terminate_error, value.process_close_error, value.thread_close_error]));
    diagnostic_data(stage, facts, unknown, fault);
}

#[test]
#[ignore = "one original-handle ordinary-account owner on its fixed disposable Windows hosted job"]
fn hosted_ordinary_original_handle_contract() -> Result<()> {
    let entry_tick = unsafe { SI::GetTickCount64() }; // FIRST entry observation, never intent-publication time.
    run_owner(OwnerVariant::Ordinary, entry_tick)
}

#[test]
#[ignore = "closed seam: separately reviewed protected publication and headless-app precheck required"]
fn hosted_protected_version_fullwalk_contract() -> Result<()> {
    let entry_tick = unsafe { SI::GetTickCount64() };
    run_owner(OwnerVariant::Fullwalk, entry_tick)
}

#[test]
#[ignore = "fixed reviewed installed-passive scope and fresh normal publication required"]
fn hosted_installed_passive_original_handle_contract() -> Result<()> {
    let entry_tick = unsafe { SI::GetTickCount64() };
    run_owner(OwnerVariant::Passive, entry_tick)
}

#[cfg(feature = "desktop-ui")]
#[test]
#[ignore = "fixed fresh-account normal UI prerequisite owner; separate original-exit finalizer required"]
fn hosted_normal_ui_prerequisite_original_handle_contract() -> Result<()> {
    let tick = unsafe { SI::GetTickCount64() };
    normal_ui::run(UiRole::Prerequisite, tick)
}
#[cfg(feature = "desktop-ui")]
#[test]
#[ignore = "fixed normal uninstrumented binary; original native UI smoke driver only"]
fn hosted_normal_ui_smoke_original_handle_contract() -> Result<()> {
    let tick = unsafe { SI::GetTickCount64() };
    normal_ui::run(UiRole::NormalSmoke, tick)
}
#[cfg(feature = "desktop-ui")]
#[test]
#[ignore = "fixed genuine Project/draft GUI case; reviewed ordinary owner only"]
fn hosted_normal_ui_project_original_handle_contract() -> Result<()> {
    let tick = unsafe { SI::GetTickCount64() };
    normal_ui::run(UiRole::ProjectDraft, tick)
}
#[cfg(feature = "desktop-ui")]
#[test]
#[ignore = "fixed genuine Quit/passive-owner GUI case; reviewed ordinary owner only"]
fn hosted_normal_ui_quit_original_handle_contract() -> Result<()> {
    let tick = unsafe { SI::GetTickCount64() };
    normal_ui::run(UiRole::QuitPassive, tick)
}
#[cfg(feature = "desktop-ui")]
#[test]
#[ignore = "fixed original document-loss GUI case; reviewed ordinary owner only"]
fn hosted_normal_ui_document_original_handle_contract() -> Result<()> {
    let tick = unsafe { SI::GetTickCount64() };
    normal_ui::run(UiRole::DocumentLoss, tick)
}

fn run_owner(variant: OwnerVariant, entry_tick: u64) -> Result<()> {
    let start = Instant::now();
    let mut deadline_latched = false;
    let batch = matches!(std::env::var("MRK_DESKTOP_DISPATCH_SCOPE").as_deref(),
        Ok(fixture::DISPATCH) | Ok(fixture::PRODUCTION_DISPATCH));
    // Before NativeBook observation, original inputs, account, ACL or launch.
    need(variant != OwnerVariant::Fullwalk || FULLWALK_PREREQUISITES_REVIEWED)?;
    need(!batch || FULLWALK_PREREQUISITES_REVIEWED)?;
    need(variant != OwnerVariant::Fullwalk || batch)?;
    if variant == OwnerVariant::Passive {
        fixture::profile()?;
        // Separate, closed, single-owner90s aggregate. Do not reset a two-owner
        // fullwalk envelope or reuse its old supplier/producer success receipts.
        need(!batch && std::env::var("MRK_DESKTOP_DISPATCH_SCOPE").as_deref() == Ok("windows-installed-passive")
            && std::env::var("GITHUB_REF").as_deref() == Ok("refs/heads/verify/desktop-windows-installed-passive")
            && std::env::var("GITHUB_EVENT_NAME").as_deref() == Ok("workflow_dispatch")
            && std::env::var("MRK_WINDOWS_PASSIVE_PUBLICATION_STEP_OUTCOME").as_deref() == Ok("success")
            && std::env::var("MRK_WINDOWS_PASSIVE_PUBLICATION_FINALIZE_STEP_OUTCOME").as_deref() == Ok("success"))?;
    }
    if batch {
        fixture::profile()?;
        for key in ["MRK_WINDOWS_PUBLISHER_STEP_OUTCOME", "MRK_WINDOWS_FIXTURE_FINALIZE_STEP_OUTCOME"] { fixture::outcome(key)?; }
    }
    let mut aggregate = if batch && variant == OwnerVariant::Ordinary {
        Some(AggregateClock::new(entry_tick, entry_tick, false)?)
    } else { None };
    super::hosted_tests::hosted_source()?;
    let root_text = std::env::var("MRK_DESKTOP_CI_ROOT").map_err(|_| Error::State)?;
    let root = fixed_path(&root_text)?;
    let temp = fixed_path(&std::env::var("RUNNER_TEMP").map_err(|_| Error::State)?)?;
    let run = std::env::var("GITHUB_RUN_ID").map_err(|_| Error::State)?;
    need(decimal(&run) && root == temp.join(format!("mrk-windows-installed-native-{run}-1"))
        && std::env::current_dir().map_err(|_| Error::Unavailable)? == root)?;
    let image = std::env::current_exe().map_err(|_| Error::Unavailable)?;
    args_are(variant.owner(), &image)?;
    let basename = image.file_name().and_then(|s| s.to_str()).ok_or(Error::Unsafe)?;
    let hash = basename.strip_prefix("mrk_windows_installed_native-").and_then(|s| s.strip_suffix(".exe")).ok_or(Error::Unsafe)?;
    need(is_hex(hash, 16) && image.parent() == Some(root.join("target/x86_64-pc-windows-msvc/debug/deps").as_path()))?;
    let mut files = Vec::with_capacity(40);
    let mut book = NativeBook::new();
    let mut parent_settlement_attempted = false; let mut parent_settled = false;
    let mut account: Option<Account> = None; let mut launch: Option<Pin<Box<Launch>>> = None;
    let mut transitions = Vec::with_capacity(7); let mut binding = None;
    let mut fullwalk_binding = None; let mut fullwalk_entries = None; let mut request_sha = String::new();
    let mut prerequisites: Option<Admission> = None;
    let mut ordinary_invocation: Option<Wire> = None; let mut intent_raw = Vec::new();
    let mut result_sha = String::new(); let mut sid_sha = String::new();
    let mut input_trace = InputTrace::default();
    let mut stage = "parent-context";
    let mut observation = (|| -> Result<()> {
        need(matches!(book.observe_user_once(), Err(Error::Unsafe)))?;
        owner_effect(start, &mut deadline_latched, &mut aggregate)?;
        let index = book.process_token.ok_or(Error::State)?;
        super::hosted_tests::actual_elevated_primary_refusal(&mut book, index)?;
        let parent = parent_user(&mut book)?;
        owner_effect(start, &mut deadline_latched, &mut aggregate)?;
        stage = "original-inputs";
        // Pin all actual ancestors against reparse/rename, but change ACLs ONLY
        // at/below this freshly owned root, never RUNNER_TEMP or an OS directory.
        let mut ancestors: Vec<_> = root.ancestors().map(Path::to_path_buf).collect();
        ancestors.reverse();
        input_trace.at(InputRole::Ancestor, None);
        input_trace.need(ancestors.len() <= if batch { 19 } else { 24 }, InputCheck::AncestorCount)?;
        let mut root_index = 0;
        for path in &ancestors {
            let access = FS::FILE_READ_ATTRIBUTES | FS::READ_CONTROL
                | if path == &root { FS::WRITE_DAC } else { 0 };
            input_trace.at(InputRole::Ancestor, Some(files.len() as u8));
            let index = owned_file_traced(&mut files, path, true, access, &mut input_trace)?;
            if path == &root { root_index = index; }
            owner_effect(start, &mut deadline_latched, &mut aggregate)?;
        }
        input_trace.at(InputRole::Request, Some(files.len() as u8));
        let request = owned_file_traced(&mut files, &root.join(variant.request()), false, FS::FILE_GENERIC_READ, &mut input_trace)?;
        let data = files[request].read_traced(LIMIT, &mut input_trace)?;
        owner_effect(start, &mut deadline_latched, &mut aggregate)?;
        let fullwalk = match variant {
            OwnerVariant::Ordinary => None,
            OwnerVariant::Fullwalk => Some(FullwalkRequest::parse_traced(&data, &mut input_trace)?),
            OwnerVariant::Passive => Some(FullwalkRequest::parse_passive(&data, &mut input_trace)?),
        };
        let selected = match fullwalk.as_ref() {
            None => Binding::parse_traced(&data, &mut input_trace)?,
            Some(request) => Binding { source: request.source.clone(), tree: request.tree.clone(), run: request.run.clone(),
                artifact: request.app.path.clone(), bytes: request.app.bytes, sha: request.app.sha.clone(),
                command_sha: request.app.command_sha.clone(), identity: request.app.identity.clone() },
        };
        input_trace.at(InputRole::Binding, Some(request as u8));
        selected.compiled_traced(&mut input_trace)?;
        input_trace.need(selected.run == run, InputCheck::BindingRun)?;
        if batch { request_sha = digest_traced(&data, &mut input_trace)?; }
        if let Some(fullwalk) = &fullwalk {
            input_trace.observed(fullwalk.at_root(&root), InputCheck::BindingImage)?;
            input_trace.need(image.to_str() == Some(fullwalk.owner.path.as_str())
                && Path::new(&selected.artifact) != image, InputCheck::BindingImage)?;
            request_sha = digest_traced(&data, &mut input_trace)?;
        } else {
            input_trace.need(Path::new(&selected.artifact) == image, InputCheck::BindingImage)?;
        }
        input_trace.at(InputRole::Command, Some(request as u8));
        if let Some(fullwalk) = &fullwalk {
            fullwalk.check_commands(&mut input_trace)?;
        } else {
            let command_sha = command_digest_traced(&selected.artifact, &mut input_trace)?;
            input_trace.need(command_sha == selected.command_sha, InputCheck::CommandDigest)?;
        }
        let mut directories = vec![(root_index, "root".to_owned())];
        for (name, path) in fixed_directories(&root) {
            input_trace.at(InputRole::Directory, Some(files.len() as u8));
            let index = owned_file_traced(&mut files, &path, true,
                FS::FILE_READ_ATTRIBUTES | FS::READ_CONTROL | FS::WRITE_DAC, &mut input_trace)?;
            directories.push((index, name.to_owned()));
            owner_effect(start, &mut deadline_latched, &mut aggregate)?;
        }
        input_trace.at(InputRole::Artifact, Some(files.len() as u8));
        let artifact_path = if variant == OwnerVariant::Ordinary { image.as_path() } else { Path::new(&selected.artifact) };
        let artifact = owned_file_traced(&mut files, artifact_path, false, FS::FILE_GENERIC_READ | FS::WRITE_DAC, &mut input_trace)?;
        let artifact_before = files[artifact].stamp_traced(&mut input_trace)?;
        input_trace.need(selected.matches(&artifact_before), InputCheck::ArtifactIdentity)?;
        let bytes = match variant {
            OwnerVariant::Ordinary => files[artifact].read_traced(128 << 20, &mut input_trace)?,
            OwnerVariant::Fullwalk | OwnerVariant::Passive => files[artifact].read_app_traced(&mut input_trace)?,
        };
        owner_effect(start, &mut deadline_latched, &mut aggregate)?;
        input_trace.need(bytes.len() == selected.bytes, InputCheck::ArtifactBytes)?;
        let artifact_sha = match variant {
            OwnerVariant::Ordinary => digest_traced(&bytes, &mut input_trace)?,
            OwnerVariant::Fullwalk | OwnerVariant::Passive => digest_app_traced(&bytes, &mut input_trace)?,
        };
        input_trace.need(artifact_sha == selected.sha, InputCheck::ArtifactDigest)?;
        // Hash/read does not authorize adoption of another artifact or discard
        // original ChangeTime. The exact preflight identity must still match.
        let artifact_stable = files[artifact].stamp_traced(&mut input_trace)?;
        input_trace.need(artifact_stable == artifact_before, InputCheck::ArtifactStable)?;
        owner_effect(start, &mut deadline_latched, &mut aggregate)?;
        let mut companion_originals = Vec::with_capacity(13);
        if let Some(fullwalk) = &fullwalk {
            // Distinct standalone owner original: no child substitution, copy,
            // second compile or ACL mutation of the owner's executable here.
            input_trace.at(InputRole::Artifact, Some(files.len() as u8));
            let owned = owned_file_traced(&mut files, &image, false, FS::FILE_GENERIC_READ, &mut input_trace)?;
            let before = files[owned].stamp_traced(&mut input_trace)?;
            input_trace.need(fullwalk.owner.matches(&before)
                && (before.volume, before.id) != (artifact_before.volume, artifact_before.id), InputCheck::ArtifactIdentity)?;
            let raw = files[owned].read_traced(128 << 20, &mut input_trace)?;
            input_trace.need(raw.len() == fullwalk.owner.bytes, InputCheck::ArtifactBytes)?;
            let hash = digest_traced(&raw, &mut input_trace)?;
            input_trace.need(hash == fullwalk.owner.sha, InputCheck::ArtifactDigest)?;
            let stable = files[owned].stamp_traced(&mut input_trace)?;
            input_trace.need(stable == before, InputCheck::ArtifactStable)?;
            companion_originals.push((owned, before));
            // Original compiler messages stay separately retained and hash-bound.
            // Argv digests are the original compile-record DATA bound by request;
            // this owner never compiles, manufactures or reinterprets that record.
            for (name, expected_bytes, expected_sha) in [
                ("compile-messages.jsonl", fullwalk.owner.messages_bytes, &fullwalk.owner.messages_sha),
                ("app-compile-messages.jsonl", fullwalk.app.messages_bytes, &fullwalk.app.messages_sha),
            ] {
                input_trace.at(InputRole::Binding, Some(files.len() as u8));
                let owned = owned_file_traced(&mut files, &root.join(name), false, FS::FILE_GENERIC_READ, &mut input_trace)?;
                let before = files[owned].stamp_traced(&mut input_trace)?;
                let raw = files[owned].read_traced(16 << 20, &mut input_trace)?;
                input_trace.need(raw.len() == expected_bytes, InputCheck::ArtifactBytes)?;
                let hash = digest_traced(&raw, &mut input_trace)?;
                input_trace.need(hash == *expected_sha, InputCheck::ArtifactDigest)?;
                let stable = files[owned].stamp_traced(&mut input_trace)?;
                input_trace.need(stable == before, InputCheck::ArtifactStable)?;
                companion_originals.push((owned, before));
                owner_effect(start, &mut deadline_latched, &mut aggregate)?;
            }
            if variant == OwnerVariant::Passive {
                // Fresh publisher/setup comparison DATA only. The candidate
                // still owes actual complete native payload/loader admission;
                // neither this file nor its digest can grant runtime custody.
                input_trace.at(InputRole::Binding, Some(files.len() as u8));
                let owned = owned_file_traced(&mut files, &root.join("passive-publication.private.json"), false,
                    FS::FILE_GENERIC_READ, &mut input_trace)?;
                let before = files[owned].stamp_traced(&mut input_trace)?;
                let raw = files[owned].read_traced(OWNER_LIMIT, &mut input_trace)?;
                input_trace.need(raw.len() == fullwalk.publication_bytes, InputCheck::ArtifactBytes)?;
                let digest = digest_traced(&raw, &mut input_trace)?;
                input_trace.need(digest == fullwalk.publication_sha, InputCheck::ArtifactDigest)?;
                let after = files[owned].stamp_traced(&mut input_trace)?;
                input_trace.need(after == before, InputCheck::ArtifactStable)?;
                companion_originals.push((owned, before));
                owner_effect(start, &mut deadline_latched, &mut aggregate)?;
            } else {
                let admission = fixture::admit(fullwalk, &root, &mut files, &mut input_trace,
                    start.checked_add(Duration::from_secs(NATIVE_SECONDS)).ok_or(Error::Bounds)?)?;
                let mut clock = AggregateClock::new(admission.origin, entry_tick, true)?;
                need(clock.deadline == admission.deadline && entry_tick >= admission.ordinary_prewrite)?;
                clock.observe(unsafe { SI::GetTickCount64() }, fixture::SECOND_FLOOR_MS)?;
                companion_originals.extend(admission.originals.iter().cloned());
                aggregate = Some(clock); prerequisites = Some(admission);
            }
        } else if batch {
            let mut invocation = fixture::invocation(&selected.source, &selected.tree, &selected.run,
                selected.bytes, &selected.sha, &selected.identity, &selected.command_sha, &request_sha, entry_tick)?;
            invocation.put("profile", fixture::active_profile()?);
            ordinary_invocation = Some(invocation);
        }
        stage = "account-intent";
        owner_effect(start, &mut deadline_latched, &mut aggregate)?;
        account = Some(Account::new()?);
        let current = account.as_mut().ok_or(Error::State)?;
        let name = String::from_utf16(&current.name[..current.name.len() - 1]).map_err(|_| Error::Unsafe)?;
        let intent_role = match variant {
            OwnerVariant::Ordinary => "fixedNativeChildOnly", OwnerVariant::Fullwalk => "fixedFullwalkChildOnly",
            OwnerVariant::Passive => "fixedInstalledPassiveChildOnly",
        };
        let batch_intent = match (variant, ordinary_invocation.as_ref(), prerequisites.as_ref(), aggregate.as_ref()) {
            (OwnerVariant::Ordinary, Some(invocation), None, Some(_)) =>
                format!(",\"fullwalkBatch\":{}", fixture::invocation_json(invocation)?),
            (OwnerVariant::Fullwalk, None, Some(admission), Some(clock)) =>
                format!(",\"fullwalkBatch\":{}", admission.batch_json(clock)?),
            (OwnerVariant::Ordinary | OwnerVariant::Passive, None, None, None) => String::new(),
            _ => return Err(Error::State),
        };
        let intent = format!("{{\"schemaVersion\":1,\"sourceSha\":\"{}\",\"runId\":\"{}\",\"attempt\":1,\"accountName\":\"{name}\",\"freshAccountIntent\":true,\"{intent_role}\":true{batch_intent}}}\n",
            selected.source, selected.run);
        if batch { intent_raw = intent.as_bytes().to_vec(); }
        owner_effect(start, &mut deadline_latched, &mut aggregate)?;
        write_one(&root.join(variant.intent()), intent.as_bytes(), LIMIT, null())?;
        owner_effect(start, &mut deadline_latched, &mut aggregate)?;
        stage = "fresh-account";
        current.create(&parent, start, &mut deadline_latched, &mut aggregate)?;
        need(current.sid != parent)?;
        owner_effect(start, &mut deadline_latched, &mut aggregate)?;
        sid_sha = digest(&current.sid)?;
        stage = "exact-acl";
        input_trace.at(InputRole::Output, Some(files.len() as u8));
        let output = root.join(variant.output());
        let output_name = wide(input_trace.observed(output.to_str().ok_or(Error::Unsafe), InputCheck::PathText)?);
        // CreateDirectoryW is exclusive. Collision/error never adopts output.
        input_trace.observed(owner_effect(start, &mut deadline_latched, &mut aggregate), InputCheck::AclDeadline)?;
        let created = unsafe { FS::CreateDirectoryW(output_name.as_ptr(), null()) };
        let creation_error = if created != 0 { 0 } else { unsafe { F::GetLastError() } };
        if created == 0 {
            input_trace.record(InputCheck::OutputCreate, Some(InputStatus::Win32(creation_error)));
            if creation_error == 0 || creation_error == F::ERROR_IO_PENDING {
                // Keep the original directory call's name/first cause on this stack.
                diagnostic_with_fault("output-original-create", None, true, input_trace.first);
                loop { std::thread::park(); std::hint::black_box((&output_name, &input_trace)); }
            }
            return Err(if creation_error == F::ERROR_ALREADY_EXISTS { Error::Unsafe } else { Error::Unavailable });
        }
        input_trace.observed(owner_effect(start, &mut deadline_latched, &mut aggregate), InputCheck::AclDeadline)?;
        let output_index = owned_file_traced(&mut files, &output, true,
            FS::FILE_READ_ATTRIBUTES | FS::READ_CONTROL | FS::WRITE_DAC, &mut input_trace)?;
        for ((index, role), acl_role) in directories.into_iter().zip([
            InputRole::AclRoot, InputRole::AclTarget, InputRole::AclTriple, InputRole::AclDebug, InputRole::AclDeps]) {
            input_trace.at(acl_role, Some(index as u8));
            transitions.push(grant(&mut files[index], &role, &parent, &current.sid, FS::FILE_TRAVERSE,
                start, &mut deadline_latched, &mut aggregate, &mut input_trace)?);
        }
        input_trace.at(InputRole::AclArtifact, Some(artifact as u8));
        transitions.push(grant(&mut files[artifact], "artifact", &parent, &current.sid,
            FS::FILE_GENERIC_READ | FS::FILE_GENERIC_EXECUTE, start, &mut deadline_latched, &mut aggregate, &mut input_trace)?);
        let artifact_after = files[artifact].stamp_traced(&mut input_trace)?;
        input_trace.at(InputRole::AclOutput, Some(output_index as u8));
        transitions.push(grant(&mut files[output_index], variant.output(), &parent, &current.sid,
            FS::FILE_ADD_FILE | FS::FILE_TRAVERSE | FS::FILE_READ_ATTRIBUTES | FS::SYNCHRONIZE,
            start, &mut deadline_latched, &mut aggregate, &mut input_trace)?);
        input_trace.need(transitions.len() == 7, InputCheck::AclTransitions)?;
        // This exact caller still has its original elevated primary, and no
        // impersonation. Close its NativeBook explicitly before original create.
        input_trace.at(InputRole::Parent, None);
        input_trace.observed(super::hosted_tests::actual_elevated_primary_refusal(&mut book, index), InputCheck::ParentPrimary)?;
        let parent_after = input_trace.observed(parent_user(&mut book), InputCheck::ParentUser)?;
        input_trace.need(parent_after == parent, InputCheck::ParentIdentity)?;
        parent_settlement_attempted = true;
        parent_settled = book.settle_once() == CloseOutcome::Settled && book.settled();
        input_trace.need(parent_settled, InputCheck::ParentSettlement)?;
        stage = "preowned-create";
        let mut child = selected.clone(); child.identity = artifact_after.wire();
        let fullwalk_request = if fullwalk.is_some() { Some(std::str::from_utf8(&data).map_err(|_| Error::Unsafe)?) } else { None };
        launch = Some(Launch::new(variant, &child, fullwalk_request, &output, current, &parent)?);
        owner_effect(start, &mut deadline_latched, &mut aggregate)?;
        let original = launch.as_mut().ok_or(Error::State)?;
        let created = original.as_mut().enter(current, start, &mut deadline_latched, &mut aggregate);
        original.as_mut().finish(start, &mut aggregate); // Always settle a definitely owned pair.
        created?;
        need(original.facts.passed())?;
        owner_effect(start, &mut deadline_latched, &mut aggregate)?;
        stage = "closed-native-result";
        let result = owned_file(&mut files, &output.join(variant.result()), false, FS::FILE_GENERIC_READ)?;
        let raw = files[result].read(LIMIT)?;
        owner_effect(start, &mut deadline_latched, &mut aggregate)?;
        input_trace.need(files.len() == ancestors.len() + match variant {
            OwnerVariant::Ordinary => 8, OwnerVariant::Fullwalk => 21, OwnerVariant::Passive => 12 }, InputCheck::FileCount)?;
        if let Some(fullwalk) = &fullwalk {
            fullwalk_entries = Some(if variant == OwnerVariant::Passive {
                fullwalk.accept_passive_result(&raw, &request_sha, &sid_sha)?
            } else { fullwalk.accept_result(&raw, &request_sha, &sid_sha)? });
        } else { need(raw == selected.result(&sid_sha).as_bytes())?; }
        result_sha = digest(&raw)?;
        need(files[artifact].stamp()? == artifact_after)?;
        for (owned, before) in companion_originals {
            need(files[owned].stamp()? == before)?;
            owner_effect(start, &mut deadline_latched, &mut aggregate)?;
        }
        owner_effect(start, &mut deadline_latched, &mut aggregate)?;
        fullwalk_binding = fullwalk;
        binding = Some(selected);
        Ok(())
    })();
    // No early ?/panic/Drop-as-close may skip this original settlement.
    if let Some(current) = account.as_mut() { current.zero(); }
    if !parent_settlement_attempted {
        parent_settlement_attempted = true;
        parent_settled = book.settle_once() == CloseOutcome::Settled && book.settled();
    }
    let process_unknown = launch.as_ref().is_some_and(|value|
        value.facts.unknown || value.facts.created && !value.facts.signaled);
    if process_unknown || !parent_settled || matches!(observation, Err(Error::Unknown)) {
        diagnostic_with_fault(stage, launch.as_deref(), true, input_trace.first);
        // Original worker/inputs/output slots stay reachable; no detached
        // borrower, account deletion, file cleanup or late-success promotion.
        loop { std::thread::park(); std::hint::black_box((&mut launch, &mut account, &mut book, &mut files)); }
    }
    let files_settled = close_files(&mut files);
    if !files_settled {
        diagnostic_with_fault("original-file-close", launch.as_deref(), true, input_trace.first);
        loop { std::thread::park(); std::hint::black_box((&mut launch, &mut account, &mut book, &mut files)); }
    }
    if owner_effect(start, &mut deadline_latched, &mut aggregate).is_err() { observation = Err(Error::Unsafe); }
    if observation.is_err() {
        diagnostic_with_fault(stage, launch.as_deref(), false, input_trace.first);
        return observation;
    }
    let current = account.as_mut().ok_or(Error::State)?;
    // Only after original child wait/exit/handle closes, result read/close and
    // every native input original settlement; failure/Unknown retains account.
    let retired = current.retire(start, &mut deadline_latched, &mut aggregate);
    if matches!(retired, Err(Error::Unknown)) {
        diagnostic("account-original-retirement", launch.as_deref(), true);
        loop { std::thread::park(); std::hint::black_box((&mut launch, &mut account, &mut book, &mut files)); }
    }
    retired?;
    let current = account.as_ref().ok_or(Error::State)?;
    owner_effect(start, &mut deadline_latched, &mut aggregate)?;
    need(current.removed && launch.as_ref().is_some_and(|value| value.facts.passed())
        && files.iter().all(OriginalFile::is_closed))?;
    let selected = binding.ok_or(Error::State)?;
    let original = launch.as_ref().ok_or(Error::State)?;
    let owner_test = variant.owner(); let child_test = variant.child();
    let protected_fullwalk = variant == OwnerVariant::Fullwalk;
    let mut extra = match (variant, fullwalk_binding.as_ref()) {
        (OwnerVariant::Ordinary, None) => String::new(),
        (OwnerVariant::Fullwalk | OwnerVariant::Passive, Some(fullwalk)) => format!(",\"requestSha256\":\"{}\",\"ownerArtifactBytes\":{},\"ownerArtifactSha256\":\"{}\",\"ownerCommandSha256\":\"{}\",\"fullwalkEntries\":{}",
            request_sha, fullwalk.owner.bytes, fullwalk.owner.sha, fullwalk.owner.command_sha,
            fullwalk_entries.ok_or(Error::State)?),
        _ => return Err(Error::State),
    };
    if variant == OwnerVariant::Passive { extra.push_str(",\"installedPassive\":true,\"ownerAggregateSeconds\":90,\"poisonedParentEnvironment\":true"); }
    if let Some(clock) = aggregate.as_mut() {
        // PRE-WRITE fact only. The original writer/close and the same two clocks
        // must still pass below before this foreground owner can exit zero.
        let prewrite = clock.sample(false)?;
        let base = match (variant, ordinary_invocation.as_ref(), prerequisites.as_ref()) {
            (OwnerVariant::Ordinary, Some(invocation), None) => fixture::invocation_json(invocation)?,
            (OwnerVariant::Fullwalk, None, Some(admission)) => admission.batch_json(clock)?,
            _ => return Err(Error::State),
        };
        let prefix = base.strip_suffix('}').ok_or(Error::State)?;
        let intent_sha = digest(&intent_raw)?;
        let detail = if variant == OwnerVariant::Ordinary {
            format!(",\"ordinaryIntentBytes\":{},\"ordinaryIntentSha256\":\"{intent_sha}\"", intent_raw.len())
        } else {
            format!(",\"ownerIntentBytes\":{},\"ownerIntentSha256\":\"{intent_sha}\",\"prelaunchTickMs\":{}",
                intent_raw.len(), clock.prelaunch.ok_or(Error::State)?)
        };
        extra.push_str(&format!(",\"aggregate\":{prefix}{detail},\"resultPrewriteTickMs\":{prewrite}}}"));
    }
    let record = format!("{{\"schemaVersion\":1,\"sourceSha\":\"{}\",\"sourceTree\":\"{}\",\"runId\":\"{}\",\"attempt\":1,\"artifactBytes\":{},\"artifactSha256\":\"{}\",\"commandSha256\":\"{}\",\"accountSidSha256\":\"{}\",\"ownerTest\":\"{owner_test}\",\"childTest\":\"{child_test}\",\"createCalls\":1,\"createReturn\":{},\"createError\":null,\"firstWait\":{},\"exitReturn\":{},\"originalExitCode\":{},\"terminateCalls\":0,\"processCloseReturn\":{},\"threadCloseReturn\":{},\"deadlineLatched\":false,\"unknown\":false,\"parentBookSettled\":true,\"inputOriginals\":{},\"inputOriginalsClosed\":{},\"freshAccountVerified\":true,\"onlyUsersMembership\":true,\"accountRemovedAfterSettlement\":true,\"nativeResultSha256\":\"{}\",\"aclTransitions\":[{}],\"ownerResult\":{{\"createNew\":true,\"writeCalls\":1,\"closeGate\":\"original-owner-exit-zero-required\"}},\"managedSourceMappingAuthenticated\":false,\"managedOrdinaryStartAuthorized\":false,\"protectedFullwalk\":{protected_fullwalk},\"productionEnabled\":false{extra}}}\n",
        selected.source, selected.tree, selected.run, selected.bytes, selected.sha, selected.command_sha, sid_sha,
        original.returned, original.first_wait, original.exit_return, original.exit_output,
        original.process_close, original.thread_close, files.len(), files.len(), result_sha, transitions.join(","));
    need(record.len() <= OWNER_LIMIT)?;
    owner_effect(start, &mut deadline_latched, &mut aggregate)?;
    write_one(&root.join(variant.owner_result()), record.as_bytes(), OWNER_LIMIT, null())?;
    // Even a late complete record is not admissible: original owner exit zero
    // is a separate mandatory gate, after its own write and original close.
    owner_effect(start, &mut deadline_latched, &mut aggregate)
}
