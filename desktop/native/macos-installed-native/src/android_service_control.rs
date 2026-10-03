//! Resident connection DATA: no descriptor/native object or worker handle.
//! Final allocation credit belongs to the real supervisor AFTER actual joins
//! and exclusive ownership of the containing connection DATA.
#![forbid(unsafe_code)]
use std::sync::{OnceLock, atomic::{AtomicBool, AtomicU64, Ordering}};
use crate::android_service_prepare::{Bounds, Request, Phase, MAX_RAW, CLEANUP_NS, nonce_for_counter};

pub const LIVE_CONTEXTS: usize = 8;
pub const CONTROL_LIMIT: usize = 64 * 1024 * 1024;
const INITIAL_CEILING_NS: u64 = 3_020_000_000_000;
const UNKNOWN: u64 = 1_u64 << 61;
const CLOCK_UNKNOWN: u64 = 1_u64 << 62;

/// Service-process-local nonreuse. No reset/decrement/wrap API exists.
pub struct NonceCounter(AtomicU64);
impl NonceCounter {
    pub fn new() -> Self { Self(AtomicU64::new(0)) }
    pub fn reserve(&self) -> Option<(u64, [u8; 16])> {
        let old = self.0.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |at| at.checked_add(1)).ok()?;
        let number = old.checked_add(1)?;
        Some((number, nonce_for_counter(number)?))
    }
}

/// The single protected-payload reservation is comparison DATA only. Releasing
/// it is private supervisor work, not proof that originals have ended.
pub struct PayloadReservation(AtomicU64);
impl PayloadReservation {
    pub fn new() -> Self { Self(AtomicU64::new(0)) }
    fn claim(&self, number: u64) -> bool {
        number != 0 && self.0.compare_exchange(0, number, Ordering::SeqCst, Ordering::SeqCst).is_ok()
    }
    pub(super) fn release_settled(&self, number: u64) -> bool {
        number != 0 && self.0.compare_exchange(number, 0, Ordering::SeqCst, Ordering::SeqCst).is_ok()
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision { FirstPending, Existing(Phase), BindingRefused }
/// Mutated under the connection's bounded DATA lock, never a native/book lock.
/// First Busy/Refused remains immutable even when another payload later ends.
pub struct FirstPrepare {
    request: Option<Request>, phase: Phase, admitted: bool,
}
impl FirstPrepare {
    pub fn new() -> Self { Self { request: None, phase: Phase::Unknown, admitted: false } }
    pub fn request(&self) -> Option<Request> { self.request }
    pub fn phase(&self) -> Phase { self.phase }
    pub fn admitted(&self) -> bool { self.admitted }
    pub fn decide(&mut self, request: Request, number: u64, admission_open: bool,
        reservation: &PayloadReservation) -> Decision {
        if let Some(existing) = self.request {
            return if existing == request { Decision::Existing(self.phase) } else { Decision::BindingRefused };
        }
        if !request.bounds.valid() || number == 0 { return Decision::BindingRefused; }
        self.request = Some(request);
        if !admission_open { self.phase = Phase::Refused; return Decision::Existing(self.phase); }
        if !reservation.claim(number) { self.phase = Phase::Busy; return Decision::Existing(self.phase); }
        self.admitted = true; self.phase = Phase::Pending; Decision::FirstPending
    }
    /// Only the supervisor after original handles/barrier custody is published.
    pub fn ready(&mut self) -> bool {
        if !self.admitted || self.phase != Phase::Pending { return false; }
        self.phase = Phase::Ready; true
    }
    pub fn unknown(&mut self) {
        // An immutable NoEntry is never turned into a queued owner.
        if self.admitted { self.phase = Phase::Unknown; }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WindowData {
    pub acceptance: u64, pub ceiling: u64, pub retirement: Option<u64>,
    pub first: Option<u64>, pub unknown: bool, pub clock_unknown: bool,
}
impl WindowData {
    pub fn cutoff(self) -> Option<u64> {
        if self.clock_unknown || self.acceptance == 0 || self.ceiling > MAX_RAW
            || self.ceiling <= self.acceptance { return None; }
        let mut end = self.ceiling;
        for first in [self.retirement, self.first].into_iter().flatten() {
            if first < self.acceptance || first > MAX_RAW { return None; }
            end = end.min(first.checked_add(CLEANUP_NS)?);
        }
        Some(end)
    }
    pub fn admits(self, now: u64, cleanup: bool) -> bool {
        now >= self.acceptance && now <= MAX_RAW && self.cutoff().is_some_and(|end| now < end)
            && (cleanup || !self.unknown && self.retirement.is_none() && self.first.is_none())
    }
}
/// Not an Arc itself: every asynchronous producer must retain the SAME
/// containing ConnectionData Arc. A naked independently retained clock Arc
/// would invalidate the supervisor's final-after-exclusivity proof.
pub struct ControlWindow {
    acceptance: u64, initial_ceiling: u64, prepared: OnceLock<Bounds>,
    state: AtomicU64, retirement: AtomicU64, closed: AtomicBool,
}
impl ControlWindow {
    pub fn new(acceptance: u64) -> Option<Self> {
        let initial_ceiling = acceptance.checked_add(INITIAL_CEILING_NS)?;
        if acceptance == 0 || initial_ceiling > MAX_RAW { return None; }
        Some(Self { acceptance, initial_ceiling, prepared: OnceLock::new(), state: AtomicU64::new(0),
            retirement: AtomicU64::new(0), closed: AtomicBool::new(false) })
    }
    pub fn prepared(&self) -> Option<Bounds> { self.prepared.get().copied() }
    pub fn route_expiry(&self) -> u64 {
        self.prepared.get().map_or(self.acceptance + CLEANUP_NS, |bounds| bounds.hard)
    }
    pub fn bind(&self, bounds: Bounds, now: u64) -> bool {
        if !bounds.work_admitted(now) || now < self.acceptance
            || now >= self.acceptance + CLEANUP_NS || self.closed.load(Ordering::SeqCst)
            || !self.snapshot().admits(now, false) || self.prepared.get().is_some()
            || bounds.hard.checked_add(CLEANUP_NS).is_none() { return false; }
        if self.prepared.set(bounds).is_err() { return false; }
        // A concurrent original expiry/failure cannot be erased by binding.
        !self.closed.load(Ordering::SeqCst) && self.snapshot().admits(now, false)
    }
    fn update_failure(&self, first: Option<u64>, flags: u64) {
        let mut old = self.state.load(Ordering::SeqCst);
        loop {
            let present = old & MAX_RAW;
            let earliest = match first { None => present, Some(at) if present == 0 => at,
                Some(at) => at.min(present) };
            let next = (old & !MAX_RAW) | earliest | flags;
            match self.state.compare_exchange_weak(old, next, Ordering::SeqCst, Ordering::SeqCst) {
                Ok(_) => return, Err(current) => old = current,
            }
        }
    }
    pub fn clock_unknown(&self) {
        self.update_failure(None, UNKNOWN | CLOCK_UNKNOWN); self.closed.store(true, Ordering::SeqCst);
    }
    /// Actual native observation, before contended status/book projection.
    pub fn failure_at(&self, first: u64, unknown: bool) {
        if first < self.acceptance || first > MAX_RAW { self.clock_unknown(); return; }
        self.update_failure(Some(first), if unknown { UNKNOWN } else { 0 });
        self.closed.store(true, Ordering::SeqCst);
    }
    pub fn retire_at(&self, first: u64) {
        if first < self.acceptance || first > MAX_RAW { self.clock_unknown(); return; }
        let mut old = self.retirement.load(Ordering::SeqCst);
        loop {
            if old != 0 && old <= first { break; }
            match self.retirement.compare_exchange_weak(old, first, Ordering::SeqCst, Ordering::SeqCst) {
                Ok(_) => break, Err(current) => old = current,
            }
        }
        self.closed.store(true, Ordering::SeqCst);
    }
    pub fn watch(&self, now: u64) {
        if now < self.acceptance || now > MAX_RAW { self.clock_unknown(); return; }
        let expiry = self.route_expiry();
        if now >= expiry { self.retire_at(expiry); }
    }
    pub fn work_open(&self, now: u64) -> bool {
        self.watch(now);
        !self.closed.load(Ordering::SeqCst) && self.snapshot().admits(now, false)
    }
    pub fn snapshot(&self) -> WindowData {
        let state = self.state.load(Ordering::SeqCst);
        let first = state & MAX_RAW;
        let retirement = self.retirement.load(Ordering::SeqCst);
        let ceiling = self.prepared.get().and_then(|bounds| bounds.hard.checked_add(CLEANUP_NS))
            .map_or(self.initial_ceiling, |end| end.min(self.initial_ceiling));
        WindowData { acceptance: self.acceptance, ceiling,
            retirement: (retirement != 0).then_some(retirement), first: (first != 0).then_some(first),
            unknown: state & UNKNOWN != 0, clock_unknown: state & CLOCK_UNKNOWN != 0 }
    }
    /// Consume ONLY after Arc::try_unwrap on the containing domain and the
    /// original native returns/required joins. This snapshot cannot race an
    /// independently retained ControlWindow Arc because none is exported.
    pub fn into_final(self) -> WindowData { self.snapshot() }
}

/// Fixed original-call proof summary. Each normal return contributes to the
/// maximum, so a later earlier CF/R invalidates ALL affected entered originals
/// without an unbounded per-reply log. Native object slots remain separately
/// charged until their actual ownership is ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CallSummary {
    entered: u64, returned: u64, pending: Option<u64>,
    earliest: Option<u64>, latest: Option<u64>, last: u64, unknown: bool,
}
impl CallSummary {
    pub fn new() -> Self {
        Self { entered: 0, returned: 0, pending: None, earliest: None,
            latest: None, last: 0, unknown: false }
    }
    pub fn enter(&mut self, window: &ControlWindow, now: u64, cleanup: bool) -> Option<u64> {
        window.watch(now);
        if self.pending.is_some() || now < self.last || !window.snapshot().admits(now, cleanup)
            || self.unknown && !cleanup {
            window.failure_at(now, true); self.unknown = true; return None;
        }
        let Some(ticket) = self.entered.checked_add(1) else {
            window.failure_at(now, true); self.unknown = true; return None;
        };
        self.entered = ticket; self.pending = Some(ticket); self.last = now;
        self.earliest = Some(self.earliest.map_or(now, |old| old.min(now))); Some(ticket)
    }
    pub fn returned(&mut self, window: &ControlWindow, ticket: u64, now: u64, normal: bool) -> bool {
        window.watch(now);
        if self.pending != Some(ticket) || now < self.last {
            self.unknown = true; window.failure_at(now, true); return false;
        }
        self.pending = None; self.last = now;
        self.latest = Some(self.latest.map_or(now, |old| old.max(now)));
        if normal {
            match self.returned.checked_add(1) {
                Some(value) => self.returned = value,
                None => { self.unknown = true; window.failure_at(now, true); return false; }
            }
        }
        if !normal || !window.snapshot().admits(now, true) {
            self.unknown = true; window.failure_at(now, true); return false;
        }
        true
    }
    pub fn known_with(&self, final_window: WindowData) -> bool {
        !self.unknown && !final_window.unknown && self.pending.is_none() && self.entered == self.returned
            && self.earliest.is_none_or(|first| first >= final_window.acceptance)
            && self.latest.is_none_or(|last| final_window.cutoff().is_some_and(|end| last < end))
            && final_window.cutoff().is_some()
    }
    pub fn in_call(&self) -> bool { self.pending.is_some() }
    pub fn uncertain(&self) -> bool { self.unknown }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::android_service_prepare::Role;
    fn request(role: Role, origin: u64) -> Request {
        Request { bounds: Bounds { role, origin, work: origin + role.work_ns(),
            hard: origin + role.hard_ns() } }
    }
    #[test]
    fn first_busy_and_refused_never_turn_into_a_queued_owner() {
        let gate = PayloadReservation::new();
        let input = request(Role::Catalog, 100);
        let mut owner = FirstPrepare::new();
        assert_eq!(owner.decide(input, 1, true, &gate), Decision::FirstPending);
        let mut busy = FirstPrepare::new();
        assert_eq!(busy.decide(input, 2, true, &gate), Decision::Existing(Phase::Busy));
        assert!(gate.release_settled(1));
        assert_eq!(busy.decide(input, 2, true, &gate), Decision::Existing(Phase::Busy));
        assert!(!busy.ready());
        assert_eq!(busy.decide(request(Role::Start, 100), 2, true, &gate), Decision::BindingRefused);
        let mut refused = FirstPrepare::new();
        assert_eq!(refused.decide(input, 3, false, &gate), Decision::Existing(Phase::Refused));
        assert_eq!(refused.decide(input, 3, true, &gate), Decision::Existing(Phase::Refused));
        let mut fresh = FirstPrepare::new();
        assert_eq!(fresh.decide(input, 4, true, &gate), Decision::FirstPending);
        assert!(fresh.ready()); fresh.unknown();
        assert_eq!(fresh.decide(input, 4, true, &gate), Decision::Existing(Phase::Unknown));
    }
    #[test]
    fn nonce_counter_exhaustion_does_not_wrap_or_reuse_after_refusal() {
        let counter = NonceCounter::new();
        for number in 1..=20 { assert_eq!(counter.reserve().unwrap().0, number); }
        let exhausted = NonceCounter(AtomicU64::new(u64::MAX - 1));
        assert_eq!(exhausted.reserve().unwrap().0, u64::MAX);
        assert!(exhausted.reserve().is_none()); assert!(exhausted.reserve().is_none());
    }
    #[test]
    fn original_acceptance_retirement_and_first_failure_only_narrow() {
        let a = 1_000;
        let window = ControlWindow::new(a).unwrap();
        assert_eq!(window.snapshot().cutoff(), Some(a + INITIAL_CEILING_NS));
        assert!(window.bind(request(Role::Catalog, a - 1).bounds, a + 1));
        let fixed = window.snapshot().ceiling;
        assert_eq!(fixed, a - 1 + Role::Catalog.hard_ns() + CLEANUP_NS);
        assert!(!window.bind(request(Role::Start, a).bounds, a + 2));
        window.retire_at(a + 100); window.retire_at(a + 200);
        window.failure_at(a + 50, false);
        assert_eq!(window.snapshot().cutoff(), Some(a + 50 + CLEANUP_NS));
        window.failure_at(a + 75, true);
        assert!(window.snapshot().unknown);
        assert_eq!(window.snapshot().cutoff(), Some(a + 50 + CLEANUP_NS));
        assert_eq!(window.snapshot().ceiling, fixed);
    }
    #[test]
    fn provisional_expiry_cannot_be_repaired_by_late_prepare() {
        let a = 100;
        let window = ControlWindow::new(a).unwrap();
        window.watch(a + CLEANUP_NS);
        assert!(!window.bind(request(Role::Catalog, a).bounds, a + CLEANUP_NS));
        assert_eq!(window.snapshot().retirement, Some(a + CLEANUP_NS));
        assert_eq!(window.snapshot().cutoff(), Some(a + CLEANUP_NS * 2));
        assert!(ControlWindow::new(MAX_RAW).is_none());
        window.failure_at(a - 1, false); assert!(window.snapshot().cutoff().is_none());
    }
    #[test]
    fn delayed_earlier_failure_reconciles_previously_returned_originals() {
        let window = ControlWindow::new(100).unwrap();
        let mut calls = CallSummary::new();
        let ticket = calls.enter(&window, 101, false).unwrap();
        assert!(calls.returned(&window, ticket, 12_000_000_101, true));
        assert!(calls.known_with(window.snapshot()));
        // The last still-retained DATA producer delivers this original sample.
        window.failure_at(102, false);
        let final_data = window.into_final();
        assert!(!calls.known_with(final_data));
    }
    #[test]
    fn late_or_ambiguous_native_return_never_becomes_credit() {
        let window = ControlWindow::new(100).unwrap();
        window.retire_at(101);
        let mut calls = CallSummary::new();
        let ticket = calls.enter(&window, 102, true).unwrap();
        assert!(!calls.returned(&window, ticket, 101 + CLEANUP_NS, true));
        assert!(!calls.known_with(window.into_final()));
        let window = ControlWindow::new(100).unwrap();
        let mut calls = CallSummary::new();
        let first = calls.enter(&window, 101, false).unwrap();
        assert!(!calls.returned(&window, first, 102, false));
        let independent = calls.enter(&window, 103, true).unwrap();
        assert!(calls.returned(&window, independent, 104, true));
        assert!(!calls.known_with(window.into_final()));
    }
}
