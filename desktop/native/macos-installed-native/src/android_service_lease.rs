//! One original no-copy backing lease. All state is bounded DATA; no native
//! object, descriptor, handle, queue, or callback authority is stored here.
//! A documented backing relinquishment is one fact, not a callback-join proof.
#![forbid(unsafe_code)]
use std::sync::atomic::{AtomicU64, Ordering};
const TICKET: u64 = (1_u64 << 56) - 1;
const BORROW_END: u64 = 1_u64 << 56;
const NATIVE_RETURN: u64 = 1_u64 << 57;
const BACKING_END: u64 = 1_u64 << 58;
const UNKNOWN: u64 = 1_u64 << 59;
const ALL: u64 = BORROW_END | NATIVE_RETURN | BACKING_END;

pub(crate) struct BackingLease(AtomicU64);
impl BackingLease {
    pub(crate) fn reserved() -> Self { Self(AtomicU64::new(0)) }
    /// Neither a live nor an uncertain old backing can allocate a second lease.
    pub(crate) fn claim(&self) -> Option<u64> {
        let mut old = self.0.load(Ordering::SeqCst);
        loop {
            if old & UNKNOWN != 0 || old != 0 && old & ALL != ALL { return None; }
            let previous = old & TICKET;
            let Some(next) = previous.checked_add(1).filter(|next| *next <= TICKET) else {
                self.unknown(); return None;
            };
            match self.0.compare_exchange_weak(old, next, Ordering::SeqCst, Ordering::SeqCst) {
                Ok(_) => return Some(next), Err(actual) => old = actual,
            }
        }
    }
    pub(crate) fn active(&self,ticket:u64)->bool {
        ticket!=0 && ticket<=TICKET && self.0.load(Ordering::SeqCst)==ticket
    }
    fn mark(&self, ticket: u64, flag: u64) -> bool {
        let mut old = self.0.load(Ordering::SeqCst);
        loop {
            if ticket == 0 || ticket > TICKET || old & TICKET != ticket {
                self.unknown(); return false;
            }
            match self.0.compare_exchange_weak(old, old | flag, Ordering::SeqCst, Ordering::SeqCst) {
                Ok(_) => return true, Err(actual) => old = actual,
            }
        }
    }
    pub(crate) fn backing_relinquished(&self, ticket: u64) -> bool { self.mark(ticket, BACKING_END) }
    pub(crate) fn original_returns(&self, ticket: u64, known: bool) -> bool {
        self.mark(ticket, if known { NATIVE_RETURN } else { UNKNOWN })
    }
    pub(crate) fn borrow_ended(&self, ticket: u64) -> bool { self.mark(ticket, BORROW_END) }
    pub(crate) fn unknown(&self) { self.0.fetch_or(UNKNOWN, Ordering::SeqCst); }
    pub(crate) fn is_unknown(&self) -> bool { self.0.load(Ordering::SeqCst) & UNKNOWN != 0 }
    pub(crate) fn original_borrow_settled(&self) -> bool {
        let state = self.0.load(Ordering::SeqCst);
        state == 0 || state & UNKNOWN == 0 && state & (BORROW_END | NATIVE_RETURN) == (BORROW_END | NATIVE_RETURN)
    }
    pub(crate) fn idle_known(&self) -> bool {
        let state = self.0.load(Ordering::SeqCst);
        state == 0 || state & UNKNOWN == 0 && state & ALL == ALL
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn backing_retained_after_native_return_prevents_a_second_arena() {
        let lease = BackingLease::reserved(); let first = lease.claim().unwrap();
        assert!(lease.original_returns(first, true)); assert!(lease.borrow_ended(first));
        assert!(!lease.idle_known()); assert!(lease.claim().is_none());
        assert!(lease.backing_relinquished(first)); assert!(lease.idle_known());
        let second = lease.claim().unwrap(); assert_ne!(first, second);
        // A stale callback can never credit this new original lease.
        assert!(!lease.backing_relinquished(first)); assert!(lease.is_unknown());
        assert!(!lease.idle_known()); assert!(lease.claim().is_none());
    }
    #[test]
    fn nil_exception_or_ambiguous_consuming_return_keeps_charge_after_deallocation() {
        let lease = BackingLease::reserved(); let first = lease.claim().unwrap();
        assert!(lease.original_returns(first, false));
        assert!(lease.backing_relinquished(first)); assert!(lease.borrow_ended(first));
        assert!(lease.is_unknown()); assert!(!lease.idle_known()); assert!(lease.claim().is_none());
        let lease = BackingLease(AtomicU64::new(TICKET | ALL));
        assert!(lease.claim().is_none()); assert!(lease.is_unknown());
    }
    #[test]
    fn deallocator_alone_is_neither_original_release_nor_response_borrow_end() {
        let lease = BackingLease::reserved(); let first = lease.claim().unwrap();
        assert!(lease.backing_relinquished(first)); assert!(!lease.idle_known());
        assert!(lease.original_returns(first, true)); assert!(!lease.idle_known());
        assert!(lease.borrow_ended(first)); assert!(lease.idle_known());
    }
}
