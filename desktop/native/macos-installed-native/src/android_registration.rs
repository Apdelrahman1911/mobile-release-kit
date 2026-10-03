//! Fixed, authenticated Mac Android registration transport.
//!
//! The native callbacks below can only move bounded DATA through Ingress. They
//! never receive the publisher, filesystem callback, descriptor or native ACL/
//! lease book. Original Rust workers own all payload work. Status is comparison
//! DATA; the service coordinator must observe the actual same-original join.
//! No alternate peer, runtime service name, reverse callback or command exists.
use std::{
    ffi::{c_int, c_void},
    mem::ManuallyDrop,
    ptr::NonNull,
    sync::{Arc, Mutex, OnceLock, TryLockError, atomic::{AtomicBool, AtomicU64, Ordering}},
    time::Instant,
};
use crate::vault_helper_wire::{uptime, ClockBridge};
use crate::android_service_prepare as prepare;
use crate::android_service_client_data::{self as client_data,ClientData,DataOwner};

pub const FRAME_BYTES: usize = 65_536;
pub const ENVELOPE_BYTES: usize = 32;
pub const CONTENT_BYTES: usize = FRAME_BYTES - ENVELOPE_BYTES;
pub const STATUS_BYTES: usize = 256;
pub const TERMINAL_BYTES: usize = STATUS_BYTES - 80;
pub const WORK_NS: u64 = 300_000_000_000;
pub const HARD_NS: u64 = 310_000_000_000;
pub const CLEANUP_NS: u64 = 10_000_000_000;
const MAGIC: &[u8; 8] = b"MRKAX01\0";
const STATUS_MAGIC: &[u8; 8] = b"MRKAXS01";
// Raw nanoseconds share one atomic failure/finality word. More than73 years
// of uninterrupted uptime is explicitly unavailable, never wrapped/rebased.
const FIRST_MASK: u64 = (1_u64 << 61) - 1;
const UNKNOWN_BIT: u64 = 1_u64 << 61;
const CLOCK_UNKNOWN_BIT: u64 = 1_u64 << 62;
const TERMINAL_BIT: u64 = 1_u64 << 63;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure { Unavailable, Bounds, Binding, Sequence, Busy, Stopped, Native, Unknown }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bounds { pub origin: u64, pub work: u64, pub hard: u64 }
impl Bounds {
    pub fn valid(self) -> bool {
        self.origin != 0 && self.hard <= FIRST_MASK
            && self.work.checked_sub(self.origin) == Some(WORK_NS)
            && self.hard.checked_sub(self.origin) == Some(HARD_NS)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrozenFailure { pub first: Option<u64>, pub cleanup: Option<u64>, pub unknown: bool }

/// One bounded, independently runnable first-F/STOP mailbox. Failure publication
/// takes no Registry, Document, native-book or ingress lock. Failure/Unknown and
/// finality freeze share ONE atomic word: a callback cannot pass a separate
/// terminal flag then overwrite the immutable terminal result.
pub struct Signal { bounds: OnceLock<Bounds>, state: AtomicU64 }
impl Signal {
    pub fn reserved() -> Self { Self { bounds: OnceLock::new(), state: AtomicU64::new(0) } }
    fn arm_at(&self, bounds: Bounds, now: u64) -> Result<(), Failure> {
        if !bounds.valid() || now < bounds.origin || now >= bounds.work
            || self.bounds.set(bounds).is_err()
        {
            self.unknown_clock(); return Err(Failure::Unknown);
        }
        if self.first().is_some_and(|first| first < bounds.origin || first > now)
            || self.state.load(Ordering::SeqCst) & TERMINAL_BIT != 0
        {
            self.unknown_clock(); return Err(Failure::Unknown);
        }
        Ok(())
    }
    pub fn arm(&self, bounds: Bounds) -> Result<(), Failure> {
        self.arm_at(bounds, uptime().ok_or_else(|| { self.unknown_clock(); Failure::Unknown })?)
    }
    fn update(&self, first: Option<u64>, flags: u64) {
        let mut old = self.state.load(Ordering::SeqCst);
        loop {
            if old & TERMINAL_BIT != 0 { return; }
            let present = old & FIRST_MASK;
            let earliest = match first {
                Some(first) if present == 0 => first,
                Some(first) => present.min(first),
                None => present,
            };
            let next = (old & !FIRST_MASK) | earliest | flags;
            match self.state.compare_exchange_weak(old, next, Ordering::SeqCst, Ordering::SeqCst) {
                Ok(_) => return, Err(actual) => old = actual,
            }
        }
    }
    fn unknown_clock(&self) { self.update(None, UNKNOWN_BIT | CLOCK_UNKNOWN_BIT); }
    /// Absorbing invalid-clock state, with no invented accepted failure timestamp.
    pub fn clock_unknown(&self) { self.unknown_clock(); }
    /// Trusted local/native observation only. Deserialized time must pass
    /// accept_remote first. Zero/out-of-range/pre-origin is UNKNOWN clock.
    pub fn failure_at(&self, first: u64, unknown: bool) {
        if first == 0 || first > FIRST_MASK || self.bounds().is_some_and(|bounds| first < bounds.origin) {
            self.unknown_clock(); return;
        }
        self.update(Some(first), if unknown { UNKNOWN_BIT } else { 0 });
    }
    pub fn failure_now(&self, unknown: bool) { self.failure_at(uptime().unwrap_or(0), unknown); }
    pub fn local_failure(&self, clock: &ClockBridge, event: Instant, unknown: bool) {
        self.failure_at(clock.earlier_endpoint(event).unwrap_or(0), unknown);
    }
    pub fn first(&self) -> Option<u64> {
        let first = self.state.load(Ordering::SeqCst) & FIRST_MASK;
        (first != 0).then_some(first)
    }
    pub fn unknown(&self) -> bool { self.state.load(Ordering::SeqCst) & UNKNOWN_BIT != 0 }
    pub fn bounds(&self) -> Option<Bounds> { self.bounds.get().copied() }
    fn snapshot_word(&self, word: u64) -> FrozenFailure {
        let first = word & FIRST_MASK;
        let first = (first != 0).then_some(first);
        let cleanup = self.bounds().and_then(|bounds| {
            if word & CLOCK_UNKNOWN_BIT != 0 { return None; }
            match first {
                Some(first) if first >= bounds.origin => Some(first.checked_add(CLEANUP_NS)?.min(bounds.hard)),
                Some(_) => None, None => Some(bounds.hard),
            }
        });
        FrozenFailure { first, cleanup, unknown: word & UNKNOWN_BIT != 0 }
    }
    pub fn snapshot(&self) -> FrozenFailure { self.snapshot_word(self.state.load(Ordering::SeqCst)) }
    pub fn cleanup(&self) -> Option<u64> { self.snapshot().cleanup }
    /// Validate comparison DATA against this exact original clock. A peer
    /// cannot select/extend W/H or import future/pre-origin F. Missing cleanup
    /// is accepted only with explicit peer Unknown, never as a renewed clock.
    fn accept_remote(&self, first: Option<u64>, cleanup: Option<u64>, unknown: bool, now: u64) -> bool {
        let Some(bounds) = self.bounds() else { self.unknown_clock(); return false; };
        let valid = now >= bounds.origin && now <= FIRST_MASK
            && first.is_none_or(|first| first >= bounds.origin && first <= now)
            && match cleanup {
                Some(actual) => first.map_or(Some(bounds.hard), |first| first.checked_add(CLEANUP_NS).map(|end| end.min(bounds.hard))) == Some(actual),
                None => unknown,
            };
        if !valid { self.failure_at(now, true); return false; }
        if let Some(first) = first { self.failure_at(first, unknown); }
        else if unknown { self.failure_at(now, true); }
        true
    }
    pub fn admitted_at(&self, cleanup: bool, now: u64) -> bool {
        let Some(bounds) = self.bounds() else { return false; };
        if now < bounds.origin || now > FIRST_MASK { self.unknown_clock(); return false; }
        let word = self.state.load(Ordering::SeqCst);
        if word & (CLOCK_UNKNOWN_BIT | TERMINAL_BIT) != 0 { return false; }
        if !cleanup && now >= bounds.work { self.failure_at(bounds.work, false); }
        if cleanup { self.cleanup().is_some_and(|end| now < end) }
        else { !self.unknown() && self.first().is_none() && now < bounds.work }
    }
    pub fn admitted(&self, cleanup: bool) -> bool {
        match uptime() { Some(now) => self.admitted_at(cleanup, now), None => { self.unknown_clock(); false } }
    }
    /// Service coordinator ONLY after its actual original worker join. DATA
    /// freeze is the stop/result linearization point, not a lease/join proof.
    fn freeze(&self) -> FrozenFailure {
        let before = self.state.fetch_or(TERMINAL_BIT, Ordering::SeqCst);
        self.snapshot_word(before | TERMINAL_BIT)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verb { Push, Status, Stop }
pub struct Envelope<'a> { pub nonce: [u8; 16], pub sequence: u32, pub verb: Verb, pub content: &'a [u8] }
impl<'a> Envelope<'a> {
    pub fn decode(raw: &'a [u8]) -> Result<Self, Failure> {
        if !(ENVELOPE_BYTES..=FRAME_BYTES).contains(&raw.len()) || &raw[..8] != MAGIC
            || raw[29..32] != [0; 3] { return Err(Failure::Bounds); }
        let nonce = raw[8..24].try_into().map_err(|_| Failure::Bounds)?;
        if nonce == [0; 16] { return Err(Failure::Binding); }
        let sequence = u32::from_be_bytes(raw[24..28].try_into().map_err(|_| Failure::Bounds)?);
        let content = &raw[ENVELOPE_BYTES..];
        let verb = match raw[28] {
            0 if sequence != 0 && sequence != u32::MAX && !content.is_empty() => Verb::Push,
            1 if sequence == 0 && content.is_empty() => Verb::Status,
            2 if sequence == 0 && content.len() == 8 => Verb::Stop,
            _ => return Err(Failure::Sequence),
        };
        Ok(Self { nonce, sequence, verb, content })
    }
    pub fn encode(nonce: [u8; 16], sequence: u32, verb: Verb, content: &[u8]) -> Result<Vec<u8>, Failure> {
        if content.len() > CONTENT_BYTES { return Err(Failure::Bounds); }
        let mut out = vec![0; ENVELOPE_BYTES + content.len()];
        out[..8].copy_from_slice(MAGIC); out[8..24].copy_from_slice(&nonce);
        out[24..28].copy_from_slice(&sequence.to_be_bytes());
        out[28] = match verb { Verb::Push => 0, Verb::Status => 1, Verb::Stop => 2 };
        out[ENVELOPE_BYTES..].copy_from_slice(content);
        Envelope::decode(&out)?;
        Ok(out)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum Phase { Reserved = 0, Active = 1, InputClosed = 2, Complete = 3, Refused = 4, Busy = 5, Unknown = 6 }
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Status {
    pub phase: Phase, pub account: u32, pub nonce: [u8; 16],
    pub enqueued: u32, pub processed: u32, pub payload_bytes: u64,
    pub first: Option<u64>, pub cleanup: Option<u64>, pub unknown: bool,
    pub terminal: Vec<u8>,
}
impl Status {
    pub fn decode(raw: &[u8; STATUS_BYTES]) -> Option<Self> {
        if &raw[..8] != STATUS_MAGIC { return None; }
        let u32at = |at: usize| u32::from_be_bytes([raw[at], raw[at+1], raw[at+2], raw[at+3]]);
        let u64at = |at: usize| u64::from_be_bytes([raw[at], raw[at+1], raw[at+2], raw[at+3], raw[at+4], raw[at+5], raw[at+6], raw[at+7]]);
        let phase = match u32at(8) { 0 => Phase::Reserved, 1 => Phase::Active, 2 => Phase::InputClosed,
            3 => Phase::Complete, 4 => Phase::Refused, 5 => Phase::Busy, 6 => Phase::Unknown, _ => return None };
        let account = u32at(12);
        let nonce = raw[16..32].try_into().ok()?;
        let enqueued = u32at(32); let processed = u32at(36);
        let first = u64at(48); let cleanup = u64at(56); let unknown = u32at(64);
        let length = usize::try_from(u32at(68)).ok()?;
        if unknown > 1 || length > TERMINAL_BYTES || raw[72..80] != [0; 8]
            || raw[80+length..].iter().any(|byte| *byte != 0) || processed > enqueued
            || enqueued == u32::MAX || enqueued - processed > 1
            || matches!(phase, Phase::Active | Phase::InputClosed | Phase::Complete | Phase::Refused)
                && (account == 0 || account == u32::MAX || nonce == [0; 16])
            || phase == Phase::Complete && (unknown != 0 || first != 0 || length == 0)
            || !matches!(phase, Phase::Complete | Phase::Refused | Phase::Unknown) && length != 0 {
            return None;
        }
        Some(Self { phase, account, nonce, enqueued, processed, payload_bytes: u64at(40),
            first: (first != 0).then_some(first), cleanup: (cleanup != 0).then_some(cleanup),
            unknown: unknown == 1, terminal: raw[80..80+length].to_vec() })
    }
    fn encode(&self) -> [u8; STATUS_BYTES] {
        let mut out = [0; STATUS_BYTES]; out[..8].copy_from_slice(STATUS_MAGIC);
        out[8..12].copy_from_slice(&(self.phase as u32).to_be_bytes());
        out[12..16].copy_from_slice(&self.account.to_be_bytes()); out[16..32].copy_from_slice(&self.nonce);
        out[32..36].copy_from_slice(&self.enqueued.to_be_bytes()); out[36..40].copy_from_slice(&self.processed.to_be_bytes());
        out[40..48].copy_from_slice(&self.payload_bytes.to_be_bytes());
        out[48..56].copy_from_slice(&self.first.unwrap_or(0).to_be_bytes());
        out[56..64].copy_from_slice(&self.cleanup.unwrap_or(0).to_be_bytes());
        out[64..68].copy_from_slice(&u32::from(self.unknown).to_be_bytes());
        if self.terminal.len() <= TERMINAL_BYTES {
            out[68..72].copy_from_slice(&(self.terminal.len() as u32).to_be_bytes());
            out[80..80+self.terminal.len()].copy_from_slice(&self.terminal);
        }
        out
    }
}

struct Flow {
    queued: Option<Vec<u8>>, pending: Option<u32>, enqueued: u32, processed: u32,
    payload_bytes: u64, phase: Phase, terminal: Vec<u8>,
}
/// DATA-only fixed one-slot service queue. Its private identity binds a taken
/// frame to this original slot; equality of nonce/sequence never substitutes.
pub struct Ingress {
    identity: Arc<()>, binding: OnceLock<(u32, [u8; 16])>, flow: Mutex<Flow>,
    closed: AtomicBool, terminal: AtomicBool, signal: Arc<Signal>,
}
pub struct Packet {
    identity: Arc<()>, sequence: u32, account: u32, nonce: [u8; 16], content: Vec<u8>,
}
impl Packet {
    pub fn account(&self) -> u32 { self.account }
    pub fn nonce(&self) -> [u8; 16] { self.nonce }
    pub fn sequence(&self) -> u32 { self.sequence }
    pub fn content(&self) -> &[u8] { &self.content }
}
impl Ingress {
    #[cfg(feature = "android-registration-helper")]
    pub(crate) fn service_high_water() -> Option<usize> {
        #[repr(C)] struct ArcCell<T> { counts: [usize; 2], data: T }
        std::mem::size_of::<ArcCell<Self>>().checked_add(std::mem::size_of::<ArcCell<Signal>>())?
            .checked_add(std::mem::size_of::<ArcCell<()>>())?
            .checked_add(2 * CONTENT_BYTES)?.checked_add(2 * TERMINAL_BYTES)?.checked_add(STATUS_BYTES)
    }
    pub fn new() -> Self {
        Self { identity: Arc::new(()), binding: OnceLock::new(),
            flow: Mutex::new(Flow { queued: None, pending: None, enqueued: 0, processed: 0,
                payload_bytes: 0, phase: Phase::Reserved, terminal: Vec::new() }),
            closed: AtomicBool::new(false), terminal: AtomicBool::new(false),
            signal: Arc::new(Signal::reserved()) }
    }
    pub fn signal(&self) -> &Arc<Signal> { &self.signal }
    pub fn bound_account(&self) -> Option<u32> { self.binding.get().map(|binding| binding.0) }
    pub fn bound_nonce(&self) -> Option<[u8; 16]> { self.binding.get().map(|binding| binding.1) }
    /// Service prepare only, before original worker GO. Status/Stop can then
    /// address genuine prepared custody even when no Hello has entered.
    pub(crate) fn prepare_binding(&self, account: u32, nonce: [u8; 16], bounds: Bounds, now: u64) -> bool {
        if account == 0 || account == u32::MAX || !prepare::nonce_valid(&nonce)
            || self.closed.load(Ordering::SeqCst) || self.binding.get().is_some()
            || self.binding.set((account, nonce)).is_err() {
            self.signal.failure_at(now, true); return false;
        }
        self.signal.arm_at(bounds, now).is_ok()
    }
    pub fn take(&self) -> Result<Option<Packet>, Failure> {
        let mut flow = self.flow.try_lock().map_err(|error| match error {
            TryLockError::WouldBlock => Failure::Busy,
            TryLockError::Poisoned(_) => { self.signal.failure_now(true); Failure::Unknown }
        })?;
        let Some(content) = flow.queued.take() else { return Ok(None); };
        let (account, nonce) = *self.binding.get().ok_or(Failure::Unknown)?;
        let sequence = flow.pending.ok_or(Failure::Unknown)?;
        Ok(Some(Packet { identity: self.identity.clone(), sequence, account, nonce, content }))
    }
    /// The actual worker calls this only after the corresponding original
    /// effect returned. It is queue ACK DATA, never a finality/publication grant.
    pub fn acknowledge(&self, packet: Packet, payload_bytes: u64) -> Result<(), Failure> {
        if !Arc::ptr_eq(&self.identity, &packet.identity) {
            self.signal.failure_now(true); return Err(Failure::Unknown);
        }
        let sequence = packet.sequence;
        // Retire the original DATA slot BEFORE exposing its ACK to the client.
        drop(packet);
        let mut flow = self.flow.lock().map_err(|_| { self.signal.failure_now(true); Failure::Unknown })?;
        if flow.pending != Some(sequence) || flow.queued.is_some() || flow.processed.checked_add(1) != Some(sequence)
            || payload_bytes < flow.payload_bytes {
            self.signal.failure_now(true); return Err(Failure::Unknown);
        }
        flow.pending = None; flow.processed = sequence; flow.payload_bytes = payload_bytes;
        Ok(())
    }
    pub fn seal(&self) -> Result<(), Failure> {
        let mut flow = self.flow.lock().map_err(|_| { self.signal.failure_now(true); Failure::Unknown })?;
        self.closed.store(true, Ordering::SeqCst); // Irreversible, even on refusal.
        if flow.pending.is_some() || flow.queued.is_some() {
            self.signal.failure_now(true); return Err(Failure::Unknown);
        }
        if !self.terminal.load(Ordering::SeqCst) { flow.phase = Phase::InputClosed; }
        Ok(())
    }
    /// Failure cleanup retires DATA only, never acknowledges a failed native
    /// effect. A packet already handed to the original worker must be returned
    /// by that same owner; a queue-empty Boolean cannot substitute.
    pub fn retire_failed_input(&self, packet: Option<Packet>) -> bool {
        self.closed.store(true, Ordering::SeqCst);
        let mut flow = match self.flow.lock() {
            Ok(flow) => flow,
            Err(_) => { self.signal.failure_now(true); return false; }
        };
        if let Some(packet) = packet {
            if !Arc::ptr_eq(&self.identity, &packet.identity) || flow.pending != Some(packet.sequence)
                || flow.queued.is_some() {
                self.signal.failure_now(true); return false;
            }
            drop(packet);
            flow.pending = None;
        } else if flow.queued.is_some() {
            // This original queue entry never left service DATA custody.
            drop(flow.queued.take()); flow.pending = None;
        } else if flow.pending.is_some() {
            self.signal.failure_now(true); return false;
        }
        if !self.terminal.load(Ordering::SeqCst) { flow.phase = Phase::InputClosed; }
        true
    }
    pub fn stop_new_input(&self) { self.closed.store(true, Ordering::SeqCst); }
    pub fn input_settled(&self) -> bool {
        self.closed.load(Ordering::SeqCst) && self.flow.try_lock()
            .is_ok_and(|flow| flow.pending.is_none() && flow.queued.is_none())
    }
    /// H only: no payload/native-book access is possible here. The caller must
    /// already have observed the genuine original Rust worker join; this method
    /// cannot prove that obligation. The terminal is never rewritten.
    pub fn publish_joined_terminal(&self, result: &[u8], success: bool, known: bool) -> Result<(), Failure> {
        if result.is_empty() || result.len() > TERMINAL_BYTES || !self.input_settled()
            || self.terminal.load(Ordering::SeqCst) {
            self.signal.failure_now(true); return Err(Failure::Unknown);
        }
        let mut flow = self.flow.lock().map_err(|_| { self.signal.failure_now(true); Failure::Unknown })?;
        if self.terminal.load(Ordering::SeqCst) || flow.pending.is_some() || flow.queued.is_some() {
            self.signal.failure_now(true); return Err(Failure::Unknown);
        }
        let frozen = self.signal.freeze();
        let positive = success && known && !frozen.unknown && frozen.first.is_none();
        flow.phase = if positive { Phase::Complete } else if known && !frozen.unknown { Phase::Refused } else { Phase::Unknown };
        flow.terminal.extend_from_slice(result);
        self.terminal.store(true, Ordering::SeqCst);
        Ok(())
    }
    fn snapshot(&self) -> Status {
        let (account, nonce) = self.binding.get().copied().unwrap_or((0, [0; 16]));
        match self.flow.try_lock() {
            Ok(flow) => Status { phase: if self.signal.unknown() && !self.terminal.load(Ordering::SeqCst) { Phase::Unknown } else { flow.phase },
                account, nonce, enqueued: flow.enqueued, processed: flow.processed, payload_bytes: flow.payload_bytes,
                first: self.signal.first(), cleanup: self.signal.cleanup(), unknown: self.signal.unknown(), terminal: flow.terminal.clone() },
            Err(error) => {
                let poisoned = matches!(error, TryLockError::Poisoned(_));
                if poisoned { self.signal.failure_now(true); }
                Status { phase: if poisoned { Phase::Unknown } else { Phase::Busy }, account, nonce,
                    enqueued: 0, processed: 0, payload_bytes: 0,
                    first: self.signal.first(), cleanup: self.signal.cleanup(), unknown: self.signal.unknown(), terminal: Vec::new() }
            }
        }
    }
    pub(crate) fn exchange(&self, account: u32, raw: &[u8], now: u64) -> [u8; STATUS_BYTES] {
        let input = match Envelope::decode(raw) {
            Ok(input) if account != 0 && account != u32::MAX => input,
            _ => { self.signal.failure_at(now, false); return self.snapshot().encode(); }
        };
        // First payload never binds/rearms a prepared original.
        if self.binding.get() != Some(&(account, input.nonce)) {
            self.signal.failure_at(now, false); return self.snapshot().encode();
        }
        if self.terminal.load(Ordering::SeqCst) {
            return self.snapshot().encode(); // Same binding, immutable old terminal.
        }
        if input.verb == Verb::Stop {
            let first = u64::from_be_bytes(input.content.try_into().unwrap_or([0; 8]));
            if first == 0 || first > now || self.signal.bounds().is_none_or(|bound| first < bound.origin) {
                self.signal.failure_at(now, true);
            } else { self.signal.failure_at(first, false); }
            return self.snapshot().encode();
        }
        if input.verb == Verb::Status { return self.snapshot().encode(); }
        if self.closed.load(Ordering::SeqCst) || !self.signal.admitted_at(false, now) {
            self.signal.failure_at(now, false); return self.snapshot().encode();
        }
        let mut flow = match self.flow.try_lock() {
            Ok(flow) => flow,
            Err(_) => {
                // Failure reaches the independent mailbox before any contended
                // queue/status projection. Do not wait or queue another frame.
                self.signal.failure_at(now, true); return self.snapshot().encode();
            }
        };
        if self.closed.load(Ordering::SeqCst) || flow.pending.is_some() || flow.queued.is_some()
            || flow.enqueued.checked_add(1).filter(|next| *next != u32::MAX) != Some(input.sequence) {
            self.signal.failure_at(now, false);
        } else {
            flow.queued = Some(input.content.to_vec()); flow.pending = Some(input.sequence);
            flow.enqueued = input.sequence; flow.phase = Phase::Active;
        }
        drop(flow);
        self.snapshot().encode()
    }
}

// SAFETY: C owns only bounded DATA pointers for the duration of the synchronous
// callback. Its permanent context is a retained Ingress, not any payload owner.
unsafe extern "C" fn exchange_callback(context: *const c_void, account: u32,
    bytes: *const u8, length: usize, now: u64, out: *mut u8) -> c_int {
    if context.is_null() || bytes.is_null() || out.is_null() || length > FRAME_BYTES { return 0; }
    let ingress = unsafe { &*context.cast::<Ingress>() };
    let raw = unsafe { std::slice::from_raw_parts(bytes, length) };
    let status = ingress.exchange(account, raw, now);
    unsafe { std::ptr::copy_nonoverlapping(status.as_ptr(), out, STATUS_BYTES); }
    1
}
unsafe extern "C" fn admit_callback(context: *const c_void, cleanup: u32) -> u32 {
    if context.is_null() || cleanup > 1 { return 0; }
    let signal = unsafe { &*context.cast::<Signal>() };
    u32::from(signal.admitted(cleanup == 1))
}
unsafe extern "C" fn signal_callback(context: *const c_void, first: u64, unknown: u32) {
    if context.is_null() { return; }
    let signal = unsafe { &*context.cast::<Signal>() };
    signal.failure_at(first, unknown != 0);
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(crate) struct NativeFacts {
    pub(crate) version: u32, pub(crate) entered: u32, pub(crate) native_call: u32, pub(crate) returned: u32, pub(crate) unknown: u32,
    pub(crate) slots: [u32; 8], pub(crate) calls: u32, pub(crate) returns: u32, pub(crate) first_call: u32, pub(crate) first_code: i32,
    pub(crate) callbacks: u32, pub(crate) callback_returns: u32, pub(crate) peer: u32, pub(crate) reserved: u32,
}
impl NativeFacts {
    pub(crate) fn valid(&self) -> bool {
        self.version == 1 && [self.entered, self.native_call, self.returned, self.unknown].iter().all(|value| *value <= 1)
            && self.slots.iter().all(|state| *state <= 5) && self.returns <= self.calls && self.calls - self.returns <= 1
            && self.callback_returns <= self.callbacks && self.callbacks - self.callback_returns <= 1
            && self.first_call <= self.calls && self.reserved == 0
    }
    pub(crate) fn quiescent(&self) -> bool {
        self.valid() && self.unknown == 0 && self.native_call == 0
            && self.calls == self.returns && self.callbacks == self.callback_returns
    }
    pub(crate) fn settled(&self) -> bool { self.quiescent() && self.slots.iter().all(|state| matches!(*state, 0 | 4)) }
}
unsafe extern "C" {
    fn mrk_android_identity_available() -> c_int;
    pub(crate) fn mrk_android_client_bytes() -> usize;
    fn mrk_android_client_new(context: *const c_void,
        notify: unsafe extern "C" fn(*const c_void, u64, u32),
        admit: unsafe extern "C" fn(*const c_void, u32) -> u32,
        data: *const client_data::Api) -> *mut c_void;
    pub(crate) fn mrk_android_client_begin(book: *mut c_void) -> c_int;
    pub(crate) fn mrk_android_client_exchange(book: *mut c_void, input: *const u8, count: usize, cleanup: u32, output: *mut u8) -> c_int;
    pub(crate) fn mrk_android_client_prepare(book: *mut c_void, input: *const u8, output: *mut u8) -> c_int;
    pub(crate) fn mrk_android_client_facts(book: *mut c_void, out: *mut NativeFacts) -> c_int;
    pub(crate) fn mrk_android_client_release_one(book: *mut c_void, slot: u32) -> c_int;
    pub(crate) fn mrk_android_client_retire(book: *mut c_void) -> c_int;
}

/// Native connection originals, owned by the SAME pre-registered IPC worker.
/// new() is inert. No automatic destructor closes a connection or releases a
/// callback context. Unknown stays retained by the enclosing original owner.
pub struct ClientBook {
    pointer: Option<NonNull<c_void>>, signal: ManuallyDrop<Arc<Signal>>,
    facts: NativeFacts, started: bool, retired: bool, poisoned: bool, in_call: bool, bytes: usize, account: u32,
    prepare: Option<prepare::ClientAttempt>, prepare_last: u64, data: Option<DataOwner>,
}
unsafe impl Send for ClientBook {}
impl ClientBook {
    pub fn new(signal: Arc<Signal>) -> Self {
        Self { pointer: None, signal: ManuallyDrop::new(signal), facts: NativeFacts { version: 1, ..NativeFacts::default() },
            started: false, retired: false, poisoned: false, in_call: false, bytes: 0, account: 0,
            prepare: None, prepare_last: 0, data: None }
    }
    pub fn identity_available() -> bool { unsafe { mrk_android_identity_available() == 1 } }
    fn ptr(&self) -> *mut c_void { self.pointer.map_or(std::ptr::null_mut(), NonNull::as_ptr) }
    fn refresh(&mut self) -> bool {
        let mut next = NativeFacts::default();
        if self.pointer.is_none() || unsafe { mrk_android_client_facts(self.ptr(), &mut next) } != 1
            || !next.valid() || next.calls < self.facts.calls || next.returns < self.facts.returns
            || next.callbacks < self.facts.callbacks || next.callback_returns < self.facts.callback_returns {
            self.poisoned = true; self.signal.failure_now(true); return false;
        }
        self.facts = next;
        if next.unknown != 0 { self.signal.failure_now(true); }
        true
    }
    pub fn begin(&mut self) -> Result<(), Failure> {
        if self.started || self.retired || self.pointer.is_some() { return Err(Failure::Unknown); }
        self.started = true;
        if Self::allocation_requirements().admitted_upper_bound().is_err() {
            self.signal.failure_now(false); return Err(Failure::Unavailable);
        }
        if !self.signal.admitted(false) { return Err(Failure::Stopped); }
        self.account = crate::real_user().map_err(|_| { self.signal.failure_now(false); Failure::Unavailable })?;
        if !self.signal.admitted(false) { return Err(Failure::Stopped); }
        if !Self::identity_available() { self.signal.failure_now(false); return Err(Failure::Unavailable); }
        self.in_call = true;
        let size = unsafe { mrk_android_client_bytes() };
        if !(1..=16_384).contains(&size) { self.in_call = false; self.poisoned = true; self.signal.failure_now(true); return Err(Failure::Bounds); }
        self.data = Some(DataOwner::new(ClientData::registration(Arc::clone(&self.signal))));
        let context = self.data.as_ref().map_or(std::ptr::null(), DataOwner::pointer);
        self.pointer = NonNull::new(unsafe { mrk_android_client_new(context, client_data::notify, client_data::admit, &client_data::API) });
        self.in_call = false;
        if self.pointer.is_none() { self.signal.failure_now(false); return Err(Failure::Native); }
        self.bytes = size;
        self.in_call = true; let outcome = unsafe { mrk_android_client_begin(self.ptr()) }; self.in_call = false;
        if !self.refresh() || outcome != 1 || !self.facts.quiescent() {
            self.signal.failure_now(self.poisoned); return Err(Failure::Native);
        }
        if !self.signal.admitted(false) { return Err(Failure::Stopped); }
        Ok(())
    }
    pub fn allocation_requirements() -> crate::android_service_budget::ClientRequirements {
        crate::android_service_budget::client_requirements()
    }
    pub fn prepare_custody(&self) -> prepare::PeerCustody {
        self.prepare.as_ref().map_or(prepare::PeerCustody::PrepareNotEntered, prepare::ClientAttempt::state)
    }
    pub fn prepared_nonce(&self) -> Option<[u8; 16]> {
        self.prepare.as_ref().and_then(prepare::ClientAttempt::nonce)
    }
    pub fn peer_nonentry_known(&self) -> bool {
        self.prepare.as_ref().is_none_or(prepare::ClientAttempt::peer_nonentry_known)
    }
    fn request_available(&self, cleanup: bool) -> bool {
        loop {
            let Some(data) = self.data.as_ref() else { return false; };
            if data.idle_known() { return self.signal.admitted(cleanup); }
            if data.uncertain() || !self.signal.admitted(cleanup) { return false; }
            // DATA-only waiting on this same original worker/clock; no second
            // native pool/proxy/connection/arena is created while backing lives.
            std::thread::park_timeout(std::time::Duration::from_millis(2));
        }
    }
    /// One original native prepare call (or an identical Pending observation).
    /// The same registered pthread/connection/Signal survives every failure.
    pub fn prepare(&mut self) -> Result<prepare::Reply, Failure> {
        if !self.started || self.retired || self.poisoned || self.in_call || !self.facts.quiescent()
            || !self.signal.admitted(false) { return Err(Failure::Stopped); }
        if !self.request_available(false) { return Err(Failure::Stopped); }
        let bounds = self.signal.bounds().ok_or(Failure::Unknown)?;
        let request = prepare::Request { bounds: prepare::Bounds { role: prepare::Role::Registration,
            origin: bounds.origin, work: bounds.work, hard: bounds.hard } };
        let input = request.encode().ok_or(Failure::Bounds)?;
        if self.prepare.is_none() { self.prepare = prepare::ClientAttempt::new(request); }
        let attempt = self.prepare.as_mut().ok_or(Failure::Unknown)?;
        if attempt.request() != request || !attempt.enter_native() { return Err(Failure::Binding); }
        // Possible server entry is already latched before entering Objective-C.
        let mut raw = [0; prepare::BYTES]; self.in_call = true;
        let returned = unsafe { mrk_android_client_prepare(self.ptr(), input.as_ptr(), raw.as_mut_ptr()) };
        self.in_call = false;
        let reply = if self.refresh() && returned == 1 && self.facts.quiescent() && self.facts.peer == 0 {
            prepare::Reply::decode(&raw)
        } else { None };
        let observed = uptime();
        let valid = match (reply, observed) {
            (Some(value), Some(now)) if value.bounds == request.bounds
                && value.bounds.accepts_observation(value.first, now, self.prepare_last) => {
                    self.prepare_last = now;
                    self.signal.accept_remote(value.first, value.bounds.cleanup(value.first), value.unknown, now)
                },
            _ => false,
        };
        if !valid {
            if let Some(attempt) = self.prepare.as_mut() { attempt.lost_reply(); }
            self.signal.failure_now(true); return Err(Failure::Unknown);
        }
        let reply = reply.ok_or(Failure::Unknown)?;
        if !self.prepare.as_mut().is_some_and(|attempt| attempt.accept_authenticated(reply)) {
            self.signal.failure_now(true); return Err(Failure::Unknown);
        }
        if !self.signal.admitted(false) { return Err(Failure::Stopped); }
        Ok(reply)
    }
    pub fn exchange(&mut self, input: &[u8], cleanup: bool) -> Result<Status, Failure> {
        let decoded = Envelope::decode(input)?;
        if cleanup && decoded.verb == Verb::Push { return Err(Failure::Bounds); }
        if self.prepared_nonce() != Some(decoded.nonce) || self.peer_nonentry_known()
            || decoded.verb == Verb::Push && self.prepare_custody() != prepare::PeerCustody::Ready {
            return Err(Failure::Binding);
        }
        if !self.started || self.retired || self.poisoned || self.in_call || !self.facts.quiescent()
            || !self.signal.admitted(cleanup) { return Err(Failure::Stopped); }
        if !self.request_available(cleanup) { return Err(Failure::Stopped); }
        let mut out = [0; STATUS_BYTES];
        self.in_call = true;
        let returned = unsafe { mrk_android_client_exchange(self.ptr(), input.as_ptr(), input.len(), u32::from(cleanup), out.as_mut_ptr()) };
        self.in_call = false;
        if !self.refresh() || returned != 1 || !self.facts.quiescent() || self.facts.peer != 0 {
            self.signal.failure_now(true); return Err(Failure::Unknown);
        }
        let status = Status::decode(&out).ok_or_else(|| { self.signal.failure_now(true); Failure::Unknown })?;
        let envelope = Envelope::decode(input)?;
        if status.nonce != envelope.nonce || status.account != self.account {
            self.signal.failure_now(true); return Err(Failure::Binding);
        }
        let now = uptime().ok_or_else(|| { self.signal.unknown_clock(); Failure::Unknown })?;
        if !self.signal.accept_remote(status.first, status.cleanup, status.unknown, now) {
            return Err(Failure::Unknown);
        }
        if !self.signal.admitted(cleanup) { return Err(Failure::Stopped); }
        Ok(status)
    }
    /// One explicit release attempt per known object; independent known releases
    /// continue after a sibling error. No invalidate-as-finality shortcut.
    pub fn release(&mut self) -> bool {
        if self.retired { return self.settled(); }
        if self.in_call || self.poisoned { self.signal.failure_now(true); return false; }
        if self.facts.entered != 0 && !self.signal.admitted(true) { return false; }
        if self.pointer.is_none() {
            if self.data.as_mut().is_some_and(|data| !data.settle()) { return false; }
            self.data = None; self.retired = true;
            // Native allocator never entered/returned None, or its original
            // retire already returned. DATA exclusivity is independently actual.
            unsafe { ManuallyDrop::drop(&mut self.signal); }
            return true;
        }
        if !self.refresh() { return false; }
        // Actual acquisition order for a call is pool3, NSData5, proxy4.
        // Cleanup after a partial exchange must use that same dependency order,
        // not numeric slot order. Unused reservations7/6 carry no native object.
        for slot in [7, 6, 4, 5, 3, 2, 1, 0] {
            if self.facts.slots[slot] != 2 { continue; }
            if !self.signal.admitted(true) { return false; }
            self.in_call = true;
            let returned = unsafe { mrk_android_client_release_one(self.ptr(), slot as u32) };
            self.in_call = false;
            if !self.refresh() { return false; }
            if returned != 1 { self.signal.failure_now(true); }
        }
        if !self.facts.settled() || !self.request_available(true) { return false; }
        self.in_call = true;
        let retired = unsafe { mrk_android_client_retire(self.ptr()) };
        self.in_call = false;
        if retired != 1 { self.poisoned = true; self.signal.failure_now(true); return false; }
        self.pointer = None; self.bytes = 0;
        if !self.signal.admitted(true) || self.data.as_mut().is_none_or(|data| !data.settle()) { return false; }
        self.data = None; self.retired = true;
        // Only actual native return PLUS same-DATA exclusivity ends this owner.
        unsafe { ManuallyDrop::drop(&mut self.signal); }
        true
    }
    pub fn settled(&self) -> bool { self.retired && self.pointer.is_none() && self.data.is_none()
        && !self.in_call && !self.poisoned && self.facts.settled() }
    pub fn retained_bytes(&self) -> Option<usize> {
        if self.settled() { Some(0) } else if !self.started { Some(0) } else { None }
    }
}

#[cfg(feature = "android-registration-helper")]
pub use crate::android_service_resident::{ServiceBook,ServiceControl,ServiceRegistry,ServiceDomain,ServiceRole};

#[cfg(test)]
mod tests {
    use super::*;
    fn bounds() -> Bounds { Bounds { origin: 10, work: 10 + WORK_NS, hard: 10 + HARD_NS } }
    #[test]
    fn earliest_failure_precedes_later_stop_and_cleanup_never_renews() {
        let signal = Signal::reserved(); signal.arm_at(bounds(), 20).unwrap();
        signal.failure_at(100, false); signal.failure_at(1_000, false);
        assert_eq!(signal.first(), Some(100)); assert_eq!(signal.cleanup(), Some(100 + CLEANUP_NS));
        signal.failure_at(80, true); assert_eq!(signal.cleanup(), Some(80 + CLEANUP_NS));
        assert!(!signal.admitted_at(false, 200)); assert!(signal.admitted_at(true, 200));
        assert!(!signal.admitted_at(true, 80 + CLEANUP_NS));
        signal.freeze(); signal.failure_at(60, false); assert_eq!(signal.first(), Some(80));
    }
    #[test]
    fn exact_envelope_bound_includes_outer_header() {
        let nonce = [1; 16];
        assert_eq!(Envelope::encode(nonce, 1, Verb::Push, &vec![1; CONTENT_BYTES]).unwrap().len(), FRAME_BYTES);
        assert!(Envelope::encode(nonce, 1, Verb::Push, &vec![1; CONTENT_BYTES + 1]).is_err());
        for (sequence, verb, data) in [(0, Verb::Push, b"x".as_slice()), (1, Verb::Status, b"".as_slice()),
            (0, Verb::Stop, b"x".as_slice()), (u32::MAX, Verb::Push, b"x".as_slice())] {
            assert!(Envelope::encode(nonce, sequence, verb, data).is_err());
        }
    }
    #[test]
    fn one_slot_ack_is_not_worker_or_lease_finality_and_seal_is_irreversible() {
        let ingress = Ingress::new(); assert!(ingress.prepare_binding(501, prepare::nonce_for_counter(1).unwrap(), bounds(), 20));
        let first = Envelope::encode(prepare::nonce_for_counter(1).unwrap(), 1, Verb::Push, b"metadata").unwrap();
        let status = Status::decode(&ingress.exchange(501, &first, 30)).unwrap();
        assert_eq!((status.enqueued, status.processed), (1, 0));
        let packet = ingress.take().unwrap().unwrap();
        assert!(ingress.take().unwrap().is_none());
        ingress.acknowledge(packet, 0).unwrap();
        ingress.seal().unwrap(); assert!(ingress.input_settled());
        let late = Envelope::encode(prepare::nonce_for_counter(1).unwrap(), 2, Verb::Push, b"late").unwrap();
        ingress.exchange(501, &late, 40);
        assert_eq!(ingress.signal.first(), Some(40)); assert!(ingress.take().unwrap().is_none());
        assert_ne!(ingress.snapshot().phase, Phase::Complete);
    }
    #[test]
    fn prepared_status_and_stop_exist_before_hello_without_rebinding() {
        let ingress=Ingress::new();let nonce=prepare::nonce_for_counter(7).unwrap();
        assert!(ingress.prepare_binding(501,nonce,bounds(),20));
        let status=Envelope::encode(nonce,0,Verb::Status,&[]).unwrap();
        let observed=Status::decode(&ingress.exchange(501,&status,21)).unwrap();
        assert_eq!((observed.account,observed.nonce,observed.enqueued),(501,nonce,0));
        let stop=Envelope::encode(nonce,0,Verb::Stop,&22u64.to_be_bytes()).unwrap();
        ingress.exchange(501,&stop,23);
        assert_eq!(ingress.signal().first(),Some(22));
        assert!(ingress.take().unwrap().is_none());
        let push=Envelope::encode(nonce,1,Verb::Push,b"never enters").unwrap();
        ingress.exchange(501,&push,24);assert!(ingress.take().unwrap().is_none());
        assert_eq!(ingress.signal().bounds(),Some(bounds()));
        assert!(!ingress.prepare_binding(501,prepare::nonce_for_counter(8).unwrap(),bounds(),25));
        assert_eq!(ingress.bound_nonce(),Some(nonce));
    }
    #[test]
    fn first_stop_mailbox_progresses_while_queue_is_contended() {
        let ingress = Ingress::new(); assert!(ingress.prepare_binding(501, prepare::nonce_for_counter(1).unwrap(), bounds(), 20));
        let first = Envelope::encode(prepare::nonce_for_counter(1).unwrap(), 1, Verb::Push, b"start").unwrap();
        ingress.exchange(501, &first, 30);
        let _held = ingress.flow.lock().unwrap();
        let stop = Envelope::encode(prepare::nonce_for_counter(1).unwrap(), 0, Verb::Stop, &40u64.to_be_bytes()).unwrap();
        ingress.exchange(501, &stop, 50);
        assert_eq!(ingress.signal.first(), Some(40));
        assert_eq!(ingress.signal.cleanup(), Some(40 + CLEANUP_NS));
    }
}
