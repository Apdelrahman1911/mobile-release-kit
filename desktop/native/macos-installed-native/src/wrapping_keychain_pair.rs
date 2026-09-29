//! Qualification-only fixed creator/reader record custody. No process launch,
//! configurable transport, credential getter, Keychain mutation, or Drop cleanup.
//! Fixed private bytes stay local; reports contain closed scalar observations.
use super::{qualification::{Case, CaseReturn, OwnerFixturePin, PeerLookup, Refused},
    native_frame_bytes, AddEffect, Admission, Checkpoint, Context, Custody, Facts,
    Outcome, RawResult, ReferenceObservation};
use std::{any::Any, cell::Cell, ffi::c_void, fmt::{self, Write as FmtWrite},
    io::{self, Write as IoWrite}, marker::PhantomData, mem::{size_of, ManuallyDrop},
    panic::{catch_unwind, AssertUnwindSafe}, ptr::NonNull,
    sync::atomic::{AtomicBool, AtomicPtr, Ordering}, time::{Duration, Instant}};

const CONTROL_ABI: u32 = 0x51500101;
const CONTROL_BYTES: usize = 1912;
const STEPS: usize = 132; // Initialize + publish + <=128 polls + finish.
pub(super) const POLLS: usize = 128;
pub(super) const POLL_INTERVAL: Duration = Duration::from_millis(350);
const PUBLIC_OUTPUT_LIMIT: usize = 128 * 1024;
const READER_SECONDS: u64 = 10;
const READER_CHARGE_LIMIT: usize = 512 * 1024;

fn u16_at(b: &[u8], at: usize) -> u16 { u16::from_le_bytes([b[at], b[at+1]]) }
fn u32_at(b: &[u8], at: usize) -> u32 { u32::from_le_bytes(b[at..at+4].try_into().unwrap()) }
fn u64_at(b: &[u8], at: usize) -> u64 { u64::from_le_bytes(b[at..at+8].try_into().unwrap()) }
fn prefix(b: &[u8], magic: &[u8; 8], kind: u16, bytes: usize) -> bool {
    b.len() == bytes && &b[..8] == magic && u16_at(b, 8) == 1 && u16_at(b, 10) == kind
        && b[12..16] == [0; 4] && b[16..32] != [0; 16]
}
fn request_valid(b: &[u8; 64]) -> bool {
    prefix(b, b"MRKQPR01", 2, 64) && u64_at(b, 32) <= u32::MAX as u64
        && u64_at(b, 40) != 0 && u32_at(b, 48) != 0 && b[56..64] == [0; 8]
}
pub(super) struct Ready { pub(super) token: [u8; 16], pub(super) pin: OwnerFixturePin, pub(super) context: Context }
fn ready_value(b: &[u8; 128], request: &[u8; 64]) -> Option<Ready> {
    if !request_valid(request) || !prefix(b, b"MRKQPD01", 1, 128) || b[16..32] != request[16..32]
        || u32_at(b, 32) != 1 || u32_at(b, 36) != 56 || u64_at(b, 40) > u32::MAX as u64
        || u64_at(b, 48) == 0 || u32_at(b, 56) != 0o040700 || u32_at(b, 60) != u32_at(request, 48)
        || u32_at(b, 64) != u32_at(request, 52) || b[68..72] != [0; 4] || b[72..88] == [0; 16]
        || b[120..128] != [0; 8] { return None; }
    Some(Ready { token: b[72..88].try_into().ok()?, pin: OwnerFixturePin { device: u64_at(b, 40),
        inode: u64_at(b, 48), mode: u32_at(b, 56), uid: u32_at(b, 60), gid: u32_at(b, 64) },
        context: Context::new(b[88..104].try_into().ok()?, b[104..120].try_into().ok()?).ok()? })
}
fn encode_ready(request: &[u8; 64], token: &[u8; 16], pin: &OwnerFixturePin, context: &Context) -> Option<[u8; 128]> {
    let mut b = [0; 128];
    b[..8].copy_from_slice(b"MRKQPD01"); b[8..10].copy_from_slice(&1u16.to_le_bytes());
    b[10..12].copy_from_slice(&1u16.to_le_bytes()); b[16..32].copy_from_slice(&request[16..32]);
    b[32..36].copy_from_slice(&1u32.to_le_bytes()); b[36..40].copy_from_slice(&56u32.to_le_bytes());
    b[40..48].copy_from_slice(&pin.device.to_le_bytes()); b[48..56].copy_from_slice(&pin.inode.to_le_bytes());
    b[56..60].copy_from_slice(&pin.mode.to_le_bytes()); b[60..64].copy_from_slice(&pin.uid.to_le_bytes());
    b[64..68].copy_from_slice(&pin.gid.to_le_bytes()); b[72..88].copy_from_slice(token);
    b[88..104].copy_from_slice(&context.vault); b[104..120].copy_from_slice(&context.generation);
    ready_value(&b, request).map(|_| b)
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct RawControl { header: [i64; 32], fds: [[i64; 26]; 6], acl: [i64; 21], native: [i64; 9], io: [i64; 9], roster: [i64; 12] }
const _: () = assert!(size_of::<RawControl>() == CONTROL_BYTES);
impl RawControl {
    fn valid(&self, role: u32, acl_bytes: usize) -> bool {
        let h = &self.header;
        if h[..3] != [1, CONTROL_BYTES as i64, role as i64] || !(0..=4).contains(&h[3])
            || [4,5,6,7,8,9,10,11,12,13,14,15,16,17,26,27,28].iter().any(|i| !(0..=1).contains(&h[*i]))
            || h[8] != 1 || h[25] != acl_bytes as i64 || h[29..] != [0; 3]
            || h[20] < 0 || h[20] > 136 || !(0..=POLLS as i64).contains(&h[21]) || h[22] != h[21]
            || h[15] > h[14] || h[16] != h[14] || h[17] > h[15] || h[10] != h[17]
            || h[13] > h[27] || (h[5] | h[6] | h[7]) != 0 && h[4] != 1 { return false; }
        for r in &self.fds {
            if [0,1,2,3,5,6,9,10,13,14,17,18,19,22,23].iter().any(|i| !(0..=1).contains(&r[*i]))
                || r[0] != r[1] || r[2] > r[1] || r[3] > r[2] || r[6] > r[5] || r[5] > r[3]
                || r[10] > r[9] || r[9] > r[3] || r[14] > r[13] || r[13] > r[10]
                || r[17] > r[3] || r[18] > r[17] || r[19] > r[18] || r[22] > r[6] || r[23] > r[22]
                || r[18] == 1 && r[19] != i64::from(r[20] == 0)
                || r[0] == 0 && *r != [0; 26] { return false; }
        }
        let a = &self.acl; let n = &self.native; let io = &self.io; let d = &self.roster;
        if a.iter().any(|v| *v < 0) || a[0] > 400 || a[1] > a[0] || a[0] - a[1] > 1 || a[2] > a[1]
            || a[3] > 128 * a[0] || a[5] > a[4] || a[6] > a[5] || a[7] > a[6] || a[8] > a[7]
            || a[10] > a[9] || a[11] > a[10] || a[12] > a[11] || a[13] > a[12] || a[14] > a[13]
            || a[16] > a[15] || a[17] > a[16] || a[18] > a[17] || a[19] > a[18] || a[20] > a[19]
            || n[0] < 0 || n[0] > 300000 || n[1] > n[0] || n[0] - n[1] > 1
            || io[0] < 0 || io[0] > 8192 || io[1] > io[0] || io[0] - io[1] > 1
            || !(0..=6).contains(&io[2]) || !(0..=6).contains(&io[6])
            || d[..3].iter().any(|v| !(0..=1).contains(v)) || d[1] > d[0] || d[2] > d[1]
            || d[4] != d[2] || d[5] < d[6] || d[7] < d[8] || d[9] > d[6]
            || d[5] > 136 || d[7] > 952 || !(0..=1).contains(&d[10]) { return false; }
        true
    }
    fn extends(&self, old: &Self) -> bool {
        if old.header[0] == 0 { return true; }
        if [3,4,5,6,7,9,10,11,12,13,14,15,16,17,20,21,22,26,27,28].iter()
            .any(|i| self.header[*i] < old.header[*i]) { return false; }
        for (now, before) in self.fds.iter().zip(&old.fds) {
            if [0,1,2,3,5,6,9,10,13,14,17,18,19,22,23].iter().any(|i| now[*i] < before[*i]) { return false; }
            for (returned, start, end) in [(2,4,5),(6,7,9),(10,11,13),(14,15,17),(18,20,22),(23,24,26)] {
                if before[returned] == 1 && now[start..end] != before[start..end] { return false; }
            }
        }
        if self.acl.iter().zip(&old.acl).any(|(now, before)| now < before) { return false; }
        for (now, before) in [(&self.native, &old.native), (&self.io, &old.io)] {
            if now[0] < before[0] || now[1] < before[1] || before[6] != 0 && now[6..9] != before[6..9] { return false; }
        }
        true
    }
    fn settled(&self) -> bool {
        let a = &self.acl; let d = &self.roster;
        self.header[13] == 1 && self.header[27] == 1 && self.header[5] == 0
            && self.fds.iter().all(|r| r[1] == r[2] && r[3] == r[19] && r[17] == r[18]
                && r[5] == r[6] && r[9] == r[10] && r[13] == r[14] && r[22] == r[23])
            && a[0] == a[1] && a[4] == a[5] && a[6] == a[7] && a[7] == a[8]
            && a[9] == a[10] && a[11] == a[12] && a[12] == a[13] && a[13] == a[14]
            && a[15] == a[16] && a[17] == a[18] && a[18] == a[19] && a[19] == a[20]
            && self.native[0] == self.native[1] && self.io[0] == self.io[1]
            && d[0] == d[1] && d[5] == d[6] && d[7] == d[8]
    }
}
type PairAdmission = extern "C" fn(*mut c_void, u32) -> u32;
unsafe extern "C" {
    fn mrk_wrapping_pair_abi() -> u32;
    fn mrk_wrapping_pair_frame_bytes() -> usize;
    fn mrk_wrapping_pair_acl_frame_bytes() -> usize;
    fn mrk_wrapping_pair_new(role: u32) -> *mut c_void;
    fn mrk_wrapping_pair_step(frame: *mut c_void, action: u32, input: *const u8, input_bytes: usize,
        output: *mut u8, output_bytes: usize, admission: PairAdmission, context: *mut c_void,
        result: *mut RawControl, result_bytes: usize) -> u32;
    fn mrk_wrapping_pair_free(frame: *mut c_void) -> u32;
}
pub(super) fn native_control_charge() -> Option<(usize, usize)> {
    // Constants/sizeof only. The caller charges both originals BEFORE allocation.
    let (abi, book, acl) = unsafe { (mrk_wrapping_pair_abi(), mrk_wrapping_pair_frame_bytes(), mrk_wrapping_pair_acl_frame_bytes()) };
    (abi == CONTROL_ABI && (1..=4096).contains(&book) && (1..=65536).contains(&acl)).then_some((book, acl))
}
struct Bridge<'a, F> { admission: &'a mut F, panic: Option<Box<dyn Any + Send>>, malformed: bool }
extern "C" fn control_admission<F: FnMut(Checkpoint) -> Admission>(context: *mut c_void, checkpoint: u32) -> u32 {
    if context.is_null() { return Admission::Unknown.raw(); }
    // SAFETY: original synchronous step owns this exact bridge until C clears it.
    let bridge = unsafe { &mut *context.cast::<Bridge<'_, F>>() };
    if bridge.panic.is_some() || bridge.malformed { return Admission::Unknown.raw(); }
    let Some(checkpoint) = Checkpoint::from_raw(checkpoint) else { bridge.malformed = true; return Admission::Unknown.raw(); };
    match catch_unwind(AssertUnwindSafe(|| (bridge.admission)(checkpoint))) {
        Ok(value) => value.raw(), Err(payload) => { bridge.panic = Some(payload); Admission::Unknown.raw() }
    }
}
pub(super) struct ControlBook {
    pointer: Option<NonNull<c_void>>, role: u32, book_bytes: usize, acl_bytes: usize,
    raw: RawControl, previous: RawControl, calls: [[u32; 5]; STEPS], count: usize,
    allocation: [u32; 3], free: [u32; 3], finish_spent: bool, blocked: bool, uncertain: bool,
    request: [u8; 64], ready: [u8; 128], request_admitted: bool, ready_admitted: bool,
    _not_sync: PhantomData<Cell<()>>, panic: Option<Box<dyn Any + Send>>,
}
// No Drop: unknown original pointers remain reachable and are never reclosed.
impl ControlBook {
    pub(super) fn empty() -> Self {
        Self { pointer: None, role: 0, book_bytes: 0, acl_bytes: 0, raw: RawControl::default(), previous: RawControl::default(),
            calls: [[0; 5]; STEPS], count: 0, allocation: [0; 3], free: [0; 3], finish_spent: false, blocked: false, uncertain: false,
            request: [0; 64], ready: [0; 128], request_admitted: false, ready_admitted: false, _not_sync: PhantomData, panic: None }
    }
    pub(super) fn reserve(&mut self, role: u32, book_bytes: usize, acl_bytes: usize) -> bool {
        if self.allocation[0] != 0 || !matches!(role, 1 | 2) || !(1..=4096).contains(&book_bytes)
            || !(1..=65536).contains(&acl_bytes) { return false; }
        self.role = role; self.book_bytes = book_bytes; self.acl_bytes = acl_bytes; self.allocation[0] = 1;
        self.pointer = NonNull::new(unsafe { mrk_wrapping_pair_new(role) });
        self.allocation[1] = 1; self.allocation[2] = u32::from(self.pointer.is_some()); self.pointer.is_some()
    }
    fn step<F: FnMut(Checkpoint) -> Admission>(&mut self, action: u32, input: Option<&[u8]>, output: Option<&mut [u8]>, admission: &mut F) -> u32 {
        if self.uncertain || self.pointer.is_none() || self.count >= STEPS || self.free[0] != 0
            || self.blocked && action != 5 || self.panic.is_some() { return 0; }
        let index = self.count; self.count += 1; self.calls[index] = [action, 1, 0, 0, 0];
        let (ip, il) = input.map_or((std::ptr::null(), 0), |v| (v.as_ptr(), v.len()));
        let (op, ol) = output.map_or((std::ptr::null_mut(), 0), |v| (v.as_mut_ptr(), v.len()));
        let mut bridge = Bridge { admission, panic: None, malformed: false };
        self.previous = self.raw; self.raw = RawControl::default();
        let actual = unsafe { mrk_wrapping_pair_step(self.pointer.unwrap().as_ptr(), action, ip, il, op, ol,
            control_admission::<F>, (&mut bridge as *mut Bridge<'_, F>).cast(), &mut self.raw, CONTROL_BYTES) };
        self.calls[index][2] = 1; self.calls[index][3] = actual; self.panic = bridge.panic;
        let valid = self.raw.valid(self.role, self.acl_bytes) && self.raw.extends(&self.previous)
            && !bridge.malformed && self.panic.is_none() && actual <= 2 && (actual != 2 || action == 4);
        self.calls[index][4] = u32::from(valid);
        // An unauthenticated original is NOT a known returned refusal. Retain
        // every original and forbid ANY later native entry, including cleanup.
        // A later valid-looking receipt can never clear this uncertainty.
        if !valid || self.raw.header[5] != 0 || self.raw.header[7] != 0 { self.uncertain = true; }
        if !valid || actual == 0 || self.raw.header[4..8] != [0; 4] { self.blocked = true; }
        if valid && !self.blocked { actual } else { 0 }
    }
    pub(super) fn initialize<F: FnMut(Checkpoint) -> Admission>(&mut self, admission: &mut F) -> bool {
        if self.count != 0 { return false; }
        let mut output = [0; 64];
        let actual = self.step(1, None, Some(&mut output), admission);
        self.request = output; self.request_admitted = actual == 1 && request_valid(&self.request);
        if !self.request_admitted { self.blocked = true; } self.request_admitted
    }
    pub(super) fn publish_ready<F: FnMut(Checkpoint) -> Admission>(&mut self, token: &[u8; 16], pin: &OwnerFixturePin,
        context: &Context, admission: &mut F) -> bool {
        if self.role != 1 || !self.request_admitted || self.ready_admitted { return false; }
        let Some(bytes) = encode_ready(&self.request, token, pin, context) else { self.blocked = true; return false; };
        self.ready = bytes;
        self.ready_admitted = self.step(2, Some(&bytes), None, admission) == 1;
        self.ready_admitted
    }
    fn read_ready<F: FnMut(Checkpoint) -> Admission>(&mut self, admission: &mut F) -> Option<Ready> {
        if self.role != 2 || !self.request_admitted || self.ready_admitted { return None; }
        let mut bytes = [0; 128]; let actual = self.step(3, None, Some(&mut bytes), admission); self.ready = bytes;
        let ready = (actual == 1).then(|| ready_value(&self.ready, &self.request)).flatten();
        self.ready_admitted = ready.is_some(); if !self.ready_admitted { self.blocked = true; } ready
    }
    pub(super) fn poll<F: FnMut(Checkpoint) -> Admission>(&mut self, admission: &mut F) -> u32 {
        if self.role != 1 || !self.ready_admitted { return 0; } self.step(4, None, None, admission)
    }
    pub(super) fn finish<F: FnMut(Checkpoint) -> Admission>(&mut self, admission: &mut F) -> bool {
        if self.uncertain || self.finish_spent || self.pointer.is_none() { return false; }
        self.finish_spent = true;
        let _actual = self.step(5, None, None, admission);
        if self.uncertain || !self.raw.valid(self.role, self.acl_bytes) || !self.raw.settled() || self.panic.is_some()
            || self.calls[..self.count].iter().any(|r| r[2] != 1 || r[4] != 1) { return false; }
        self.free[0] = 1;
        self.free[2] = unsafe { mrk_wrapping_pair_free(self.pointer.unwrap().as_ptr()) };
        self.free[1] = 1;
        if self.free[2] == 1 { self.pointer = None; } else { self.blocked = true; }
        self.complete()
    }
    pub(super) fn complete(&self) -> bool {
        let h = &self.raw.header; let a = &self.raw.acl; let d = &self.raw.roster;
        let actual_controls = self.raw.fds.iter().enumerate().all(|(i, row)| {
            let used = self.role == 1 || !matches!(i, 2 | 4);
            let mut expected = [0i64; 26];
            if used {
                expected[..4].fill(1); expected[17..20].fill(1);
                if matches!(i, 1 | 3 | 4) { expected[5] = 1; expected[6] = 1;
                    expected[7] = if i == 1 { 64 } else if i == 3 { 128 } else { 48 };
                    expected[22] = 1; expected[23] = 1; }
                if i == 2 { expected[9] = 1; expected[10] = 1; expected[11] = 128; expected[13] = 1; expected[14] = 1; }
            }
            row == &expected
        });
        !self.uncertain && !self.blocked && actual_controls && a[0] > 0 && a[0] == a[2]
            && self.raw.native[0] > 0 && self.raw.native[3] == 1 && self.raw.native[6..9] == [0; 3]
            && self.raw.io[0] > 0 && self.raw.io[3] == 1 && self.raw.io[6..9] == [0; 3]
            && d[..5] == [1, 1, 1, 0, 1] && d[5] == h[20] && d[9] == h[20] && d[10..12] == [0, 0]
            && h[9] == 1 && h[26..29] == [1, 1, 1]
            && !self.blocked && self.request_admitted && self.ready_admitted && self.pointer.is_none()
            && self.allocation == [1, 1, 1] && self.free == [1, 1, 1] && self.raw.valid(self.role, self.acl_bytes)
            && self.raw.settled() && self.raw.header[4..8] == [0; 4] && self.raw.header[3] == 4
            && if self.role == 1 { self.raw.header[10] == 1 && self.raw.header[12] == 1 }
                else { self.raw.header[11] == 1 && self.raw.header[10] == 0 && self.raw.header[12] == 0 }
    }
    pub(super) fn report(&self, out: &mut impl FmtWrite) -> fmt::Result {
        write!(out, "{{\"role\":{},\"bookBytes\":{},\"aclFrameBytes\":{},\"blocked\":{},\"uncertain\":{},\"complete\":{},\"retained\":{},\"callbackPanic\":{},\"allocation\":",
            self.role, self.book_bytes, self.acl_bytes, self.blocked, self.uncertain, self.complete(), self.pointer.is_some(), self.panic.is_some())?;
        numbers(out, &self.allocation.map(i64::from))?; out.write_str(",\"free\":")?; numbers(out, &self.free.map(i64::from))?;
        out.write_str(",\"steps\":[")?;
        for (i, row) in self.calls[..self.count].iter().enumerate() {
            if i != 0 { out.write_char(',')?; } numbers(out, &row.map(i64::from))?;
        }
        out.write_str("],\"header\":")?; numbers(out, &self.raw.header)?; out.write_str(",\"fds\":[")?;
        for (i, row) in self.raw.fds.iter().enumerate() { if i != 0 { out.write_char(',')?; } numbers(out, row)?; }
        for (key, row) in [("acl", self.raw.acl.as_slice()), ("native", self.raw.native.as_slice()),
            ("io", self.raw.io.as_slice()), ("roster", self.raw.roster.as_slice())] {
            write!(out, "{}\"{}\":", if key == "acl" { "]," } else { "," }, key)?; numbers(out, row)?;
        }
        out.write_char('}')
    }
}

pub(super) fn peer_settled(row: &CaseReturn) -> bool {
    let f = row.facts();
    f.native_run_returned() && f.verified_native_run_receipt() && f.custody() == Custody::Settled
        && !f.callback_panicked() && !f.native_exception() && !f.stopped() && f.ordinary_user_admitted()
        && row.selection().verified() && row.selection().account_selected() && row.selection().fixture_selected()
        && row.selection().root_identity_matched() && row.selection().callbacks_cleared()
        && !row.selection().selector_boundary_returned() && row.selection().helper_counts() == Some((0, 0, 0))
}
pub(super) fn creator_lookup_ready(row: &CaseReturn) -> bool {
    let f = row.facts();
    row.case() == Case::CreatorControlLookup && peer_settled(row) && f.outcome() == Outcome::Candidate
        && f.add_effect() == AddEffect::NotEntered && f.original_item_verified() && f.namespace_verified()
        && f.observed_keychain_status().is_some_and(|s| s & 1 == 1) && row.scoped_value_present()
        && exact_lookup(f, 0)
}
fn exact_lookup(f: &Facts, status: i32) -> bool {
    f.security_calls().is_some_and(|calls| {
        let mut item = calls.iter().filter(|row| matches!(row.phase, 10 | 11));
        item.next().is_some_and(|r| r.phase == 11 && r.entered == 1 && r.returned == 1 && r.status == status) && item.next().is_none()
    })
}
fn reader_denied(row: &CaseReturn) -> bool {
    let f = row.facts();
    row.case() == Case::OtherExecutableLookup && peer_settled(row) && exact_lookup(f, -25308)
        && f.outcome() == Outcome::InteractionRequired && f.add_effect() == AddEffect::NotEntered
        && f.observed_keychain_status().is_some_and(|s| s & 1 == 1) && f.namespace_verified()
        && f.first_refusal_phase() == Some(11) && f.raw.key_bytes == 0 && !row.scoped_value_present()
        && row.comparison().is_none() && f.adapter_frame_retired() && row.retained_native_frame_bytes() == 0
}
pub(super) fn peer_report(out: &mut impl FmtWrite, row: &CaseReturn) -> fmt::Result {
    let f = row.facts(); let s = row.selection();
    write!(out, "{{\"nativeReturned\":{},\"verified\":{},\"retainedNativeBytes\":{},\"frameRetired\":{},\"scopedValuePresent\":{},\"selection\":",
        f.native_run_returned(), f.verified_native_run_receipt(), row.retained_native_frame_bytes(), f.adapter_frame_retired(), row.scoped_value_present())?;
    numbers(out, &[s.verified().into(),s.account_selected().into(),s.fixture_selected().into(),s.root_identity_matched().into(),
        s.selector_boundary_returned().into(),s.callbacks_cleared().into()])?;
    out.write_str(",\"comparison\":")?;
    if let Some(c) = row.comparison() {
        numbers(out, &[c.callback_returned.into(),c.bytes_equal.into(),c.whole_frame_charge_transferred.into(),
            c.native_frame_bytes as i64,c.consume_returned_and_frame_retired.into()])?;
    } else { out.write_str("null")?; }
    out.write_str(",\"raw\":")?; native_result(out, &f.raw)?; out.write_char('}')
}

struct ReaderClock { cutoff: Option<Instant>, late: bool, poisoned: bool, checks: u64 }
impl ReaderClock {
    fn new(entry: Instant) -> Self { Self { cutoff: entry.checked_add(Duration::from_secs(READER_SECONDS)), late: false, poisoned: false, checks: 0 } }
    fn admit(&mut self) -> Admission {
        self.checks += 1;
        if self.cutoff.is_none_or(|cutoff| Instant::now() >= cutoff) { self.late = true; }
        if self.poisoned { Admission::Unknown } else if self.late { Admission::Cutoff } else { Admission::Continue }
    }
}
struct Reader {
    clock: ReaderClock, controls: ControlBook, peer: Option<PeerLookup>, original: Option<CaseReturn>, refused: Option<Refused>,
    charged: usize, adapter_bytes: usize, registered: bool, run_entered: bool, run_returned: bool, completed: bool,
    output: String, report_built: bool, write_entered: bool, flush_entered: bool,
    write_original: Option<io::Result<()>>, flush_original: Option<io::Result<()>>,
    panic: Option<Box<dyn Any + Send>>, report_panic: Option<Box<dyn Any + Send>>,
}
impl Reader {
    fn empty(entry: Instant) -> Self { Self { clock: ReaderClock::new(entry), controls: ControlBook::empty(), peer: None, original: None, refused: None,
        charged: 0, adapter_bytes: 0, registered: false, run_entered: false, run_returned: false, completed: false,
        output: String::new(), report_built: false, write_entered: false, flush_entered: false, write_original: None,
        flush_original: None, panic: None, report_panic: None } }
    fn run(&mut self) -> bool {
        if self.clock.admit() != Admission::Continue || self.output.try_reserve_exact(PUBLIC_OUTPUT_LIMIT).is_err() { return false; }
        let Some((book, acl)) = native_control_charge() else { return false; };
        let Some(adapter) = native_frame_bytes() else { return false; }; self.adapter_bytes = adapter;
        let Some(charge) = [size_of::<ManuallyDrop<Self>>(), book, acl, adapter, self.output.capacity(), 65536].into_iter()
            .try_fold(0usize, usize::checked_add) else { return false; }; self.charged = charge;
        if charge > READER_CHARGE_LIMIT || self.clock.admit() != Admission::Continue { return false; }
        self.registered = true;
        if !self.controls.reserve(2, book, acl) { return false; }
        let clock = &mut self.clock;
        if !self.controls.initialize(&mut |_| clock.admit()) { return false; }
        let Some(ready) = self.controls.read_ready(&mut |_| clock.admit()) else { return false; };
        if clock.admit() != Admission::Continue { return false; }
        match PeerLookup::reader(ready.token, ready.context, ready.pin) {
            Ok(peer) => self.peer = Some(peer), Err(refused) => { self.refused = Some(refused); return false; }
        }
        let Some(peer) = self.peer.as_mut() else { return false; };
        // One lookup, no candidate route even on unexpected success. Retain the
        // entire actual return before inspecting it; no Missing repair or retry.
        match unsafe { peer.run(&mut |_, _| clock.admit()) } {
            Ok(actual) => self.original = Some(actual), Err(refused) => { self.refused = Some(refused); return false; }
        }
        self.original.as_ref().is_some_and(reader_denied) && clock.admit() == Admission::Continue
    }
    fn finish_controls(&mut self) -> bool {
        let clock = &mut self.clock;
        self.controls.finish(&mut |_| clock.admit()) && clock.admit() == Admission::Continue
    }
    fn build_report(&mut self) -> fmt::Result {
        self.output.clear(); let out = &mut Bounded { value: &mut self.output };
        write!(out, "MRK_WRAPPING_PEER_RESULT={{\"schemaVersion\":1,\"scope\":\"wrapping-other-executable-reader\",\"provisional\":true,\"outerFinalityRequired\":true,\"cutoffSeconds\":10,\"adapterInvocationBound\":1,\"runEntered\":{},\"runReturned\":{},\"completed\":{},\"originalSlotRetained\":true,\"registered\":{},\"chargedBytes\":{},\"chargeLimit\":{},\"adapterFrameBytes\":{},\"deadlineObserved\":{},\"poisoned\":{},\"clockChecks\":{},\"callbackOrCallerPanic\":{},\"lookupStarted\":{},\"lookupRefused\":{},\"denialAccepted\":{},\"controls\":",
            self.run_entered,self.run_returned,self.completed,self.registered,self.charged,READER_CHARGE_LIMIT,self.adapter_bytes,
            self.clock.late,self.clock.poisoned,self.clock.checks,self.panic.is_some() || self.original.as_ref().is_some_and(|r| r.facts().callback_panicked()),
            self.peer.as_ref().is_some_and(PeerLookup::started),self.refused.is_some(),self.original.as_ref().is_some_and(reader_denied))?;
        self.controls.report(out)?; out.write_str(",\"lookup\":")?;
        if let Some(row) = &self.original { peer_report(out, row)?; } else { out.write_str("null")?; }
        out.write_str(",\"globalWindowSurveillance\":false,\"shippingIdentityQualified\":false}\n")
    }
    fn write_report(&mut self) {
        let mut stdout = io::stdout().lock(); self.write_entered = true;
        let fallback = b"MRK_WRAPPING_PEER_RESULT={\"schemaVersion\":1,\"scope\":\"wrapping-other-executable-reader\",\"provisional\":true,\"outerFinalityRequired\":true,\"reportUnavailable\":true}\n";
        let bytes = if self.report_built { self.output.as_bytes() } else { fallback };
        self.write_original = Some(IoWrite::write_all(&mut stdout, bytes));
        if matches!(self.write_original.as_ref(), Some(Ok(()))) {
            self.flush_entered = true; self.flush_original = Some(IoWrite::flush(&mut stdout));
        }
    }
}
struct Bounded<'a> { value: &'a mut String }
impl FmtWrite for Bounded<'_> {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        let end = self.value.len().checked_add(text.len()).ok_or(fmt::Error)?;
        if end > PUBLIC_OUTPUT_LIMIT || end > self.value.capacity() { return Err(fmt::Error); }
        self.value.push_str(text); Ok(())
    }
}
/// Only the source-fixed qualification example calls this entry. Its very first
/// action starts the original10s clock; there is no general input or CLI.
pub fn reader_entry() {
    let entry = Instant::now();
    static CLAIMED: AtomicBool = AtomicBool::new(false);
    #[used]
    static ORIGINAL: AtomicPtr<ManuallyDrop<Reader>> = AtomicPtr::new(std::ptr::null_mut());
    assert!(!CLAIMED.swap(true, Ordering::AcqRel), "private reader is single-use");
    let pointer = Box::into_raw(Box::new(ManuallyDrop::new(Reader::empty(entry))));
    ORIGINAL.store(pointer, Ordering::Release);
    let reader = unsafe { &mut **pointer }; reader.run_entered = true;
    match catch_unwind(AssertUnwindSafe(|| reader.run())) {
        Ok(ok) => { reader.run_returned = true; reader.completed = ok; },
        Err(payload) => { reader.panic = Some(payload); reader.clock.poisoned = true; }
    }
    // Known control originals get their one independent close pass on failure;
    // unknowns are retained. This never repairs/edits/deletes the native fixture.
    match catch_unwind(AssertUnwindSafe(|| reader.finish_controls())) {
        Ok(settled) => reader.completed &= settled,
        Err(payload) => { reader.report_panic = Some(payload); reader.completed = false; reader.clock.poisoned = true; }
    }
    if reader.report_panic.is_none() {
        match catch_unwind(AssertUnwindSafe(|| { reader.report_built = reader.build_report().is_ok(); reader.write_report(); })) {
            Ok(()) => {}, Err(payload) => { reader.report_panic = Some(payload); reader.clock.poisoned = true; }
        }
    }
    let complete = reader.completed && reader.run_returned && reader.panic.is_none() && reader.report_panic.is_none()
        && reader.report_built && reader.write_entered && reader.flush_entered
        && matches!(reader.write_original.as_ref(), Some(Ok(()))) && matches!(reader.flush_original.as_ref(), Some(Ok(())))
        && reader.clock.admit() == Admission::Continue;
    assert!(complete, "private reader incomplete; retained original");
}

pub(super) fn numbers(out: &mut impl FmtWrite, values: &[i64]) -> fmt::Result {
    out.write_char('[')?;
    for (i, value) in values.iter().enumerate() {
        if i != 0 { out.write_char(',')?; }
        write!(out, "{value}")?;
    }
    out.write_char(']')
}
pub(super) fn references(out: &mut impl FmtWrite, rows: &[ReferenceObservation]) -> fmt::Result {
    out.write_char('[')?;
    for (i, row) in rows.iter().enumerate() {
        if i != 0 { out.write_char(',')?; }
        numbers(out, &[row.reserved.into(), row.call_entered.into(), row.call_returned.into(),
            row.nonnull_returned.into(), row.release_entered.into(), row.release_returned.into()])?;
    }
    out.write_char(']')
}
pub(super) fn native_result(out: &mut impl FmtWrite, raw: &RawResult) -> fmt::Result {
    out.write_str("{\"header\":")?;
    numbers(out, &[raw.version.into(), raw.operation.into(), raw.outcome.into(), raw.effect.into(), raw.phase.into(),
        raw.failure_phase.into(), raw.flags.into(), raw.account_errno.into(), raw.keychain_status.into(),
        raw.slot_count.into(), raw.call_count.into(), raw.key_bytes.into(), raw.run_returned.into(),
        raw.directory_count.into(), raw.descriptor_count.into(), raw.namespace_entered.into(),
        raw.namespace_returned.into(), raw.namespace_passed.into()])?;
    out.write_str(",\"references\":")?;
    references(out, &raw.references[..(raw.slot_count as usize).min(raw.references.len())])?;
    out.write_str(",\"calls\":[")?;
    for (i, row) in raw.calls.iter().take(raw.call_count as usize).enumerate() {
        if i != 0 { out.write_char(',')?; }
        numbers(out, &[row.phase.into(), row.entered.into(), row.returned.into(), row.status.into()])?;
    }
    out.write_str("],\"descriptors\":[")?;
    for (i, row) in raw.descriptors.iter().take(raw.descriptor_count as usize).enumerate() {
        if i != 0 { out.write_char(',')?; }
        numbers(out, &[row.reserved.into(), row.open_entered.into(), row.open_returned.into(),
            row.acquired.into(), row.open_errno.into(), row.close_entered.into(), row.close_returned.into(),
            row.closed.into(), row.close_result.into(), row.close_errno.into()])?;
    }
    let a = &raw.acl;
    out.write_str("],\"acl\":")?;
    numbers(out, &[a.snapshots_entered.into(), a.snapshots_returned.into(), a.snapshots_admitted.into(), a.entries.into(),
        a.filesec_init_entered.into(), a.filesec_init_returned.into(), a.filesec_acquired.into(),
        a.filesec_free_entered.into(), a.filesec_free_returned.into(), a.acl_export_entered.into(),
        a.acl_export_returned.into(), a.acl_acquired.into(), a.acl_free_entered.into(), a.acl_free_returned.into(),
        a.acl_freed.into(), a.qualifier_entered.into(), a.qualifier_returned.into(), a.qualifier_acquired.into(),
        a.qualifier_free_entered.into(), a.qualifier_free_returned.into(), a.qualifier_freed.into()])?;
    let n = &raw.native;
    out.write_str(",\"native\":")?;
    numbers(out, &[n.entered.into(), n.returned.into(), n.last_call.into(), n.last_returned.into(),
        n.last_result.into(), n.last_errno.into(), n.failure_call.into(), n.failure_result.into(), n.failure_errno.into()])?;
    out.write_char('}')
}
