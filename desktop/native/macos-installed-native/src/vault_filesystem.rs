//! Original storage ACL snapshot custody. This book must be retained outside the
//! worker, just like its borrowed filesystem descriptors. No Keychain, filesystem
//! write, path lookup, provider, clock owner, or credential capability is added.
use std::{cell::Cell, ffi::{c_int, c_void}, marker::PhantomData,
    os::fd::{AsRawFd, BorrowedFd}, ptr::NonNull, time::Instant};

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Expected {
    pub device: u64, pub inode: u64,
    pub mode: u32, pub owner: u32, pub group: u32, pub flags: u32,
}
#[derive(Clone, Copy)]
pub enum Policy { Ancestors, Empty }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure { Refused, Native, Bounds, Stopped, Unknown }

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Facts {
    version: u32, phase: u32, outcome: u32, resource: [u32; 3],
    entries: u32, qualifiers: u32, qualifiers_closed: u32,
    first_phase: u32, first_return: i32, first_errno: i32,
}
impl Facts {
    fn valid(self) -> bool {
        self.version == 1 && self.phase <= 15 && self.outcome <= 4
            && self.resource.iter().all(|state| *state <= 5)
            && self.entries <= 129 && self.qualifiers <= self.entries
            && self.qualifiers_closed <= self.qualifiers && self.first_errno >= 0
            && if self.first_phase == 0 {
                self.outcome <= 1 && self.first_return == 0 && self.first_errno == 0
                    && (self.outcome != 1 || self.phase == 15 && self.entries == self.qualifiers
                        && self.qualifiers == self.qualifiers_closed)
            } else { (1..=18).contains(&self.first_phase) && self.outcome >= 2 }
    }
    fn settled(self) -> bool { self.resource.iter().all(|state| matches!(*state, 0 | 4)) }
    fn owned(self) -> bool { self.resource.contains(&2) }
    fn uncertain(self) -> bool { self.resource.iter().any(|state| matches!(*state, 1 | 3 | 5)) }
    fn problem(self) -> Option<Failure> {
        match self.outcome {
            2 => Some(Failure::Refused), 3 if self.uncertain() => Some(Failure::Unknown),
            3 => Some(Failure::Native), 4 => Some(Failure::Bounds), _ => None,
        }
    }
}

unsafe extern "C" {
    fn mrk_vault_acl_frame_bytes() -> usize;
    fn mrk_vault_acl_frame_new() -> *mut c_void;
    fn mrk_vault_acl_facts_read(frame: *mut c_void, facts: *mut Facts) -> c_int;
    fn mrk_vault_acl_begin(frame: *mut c_void, expected: *const Expected, empty: u32) -> c_int;
    fn mrk_vault_acl_step(frame: *mut c_void, fd: c_int) -> c_int;
    fn mrk_vault_acl_cleanup_step(frame: *mut c_void) -> c_int;
    fn mrk_vault_acl_frame_retire(frame: *mut c_void) -> c_int;
    #[cfg(test)]
    fn mrk_vault_acl_policy_data_contract() -> u32;
}

/// Owns the actual native frame and any outstanding filesec/ACL/qualifier
/// originals. A failed free remains unknown even after the borrowed FD closes.
/// There is deliberately no Drop cleanup or retry; the containing original owner
/// must call release and retain an uncertain book. Losing it is not finality.
pub struct SnapshotBook {
    frame: Option<NonNull<c_void>>, bytes: usize, facts: Facts,
    started: bool, retired: bool, in_call: bool, poisoned: bool,
    first: Option<(Failure, Instant)>, _not_sync: PhantomData<Cell<()>>,
}
// SAFETY: exclusive Rust access surrounds each synchronous C step. Native keeps
// no thread-affine object/callback; no move overlaps a native borrow. !Sync.
unsafe impl Send for SnapshotBook {}
impl SnapshotBook {
    /// Allocates only the adapter frame, before worker entry. Charge its exact
    /// bytes then; this is not an invented bound on libc allocator overhead.
    pub fn new() -> Self {
        // SAFETY: fixed sizeof query and zeroed allocation, no descriptor or SDK query.
        let size = unsafe { mrk_vault_acl_frame_bytes() };
        let frame = if (1..=16384).contains(&size) { NonNull::new(unsafe { mrk_vault_acl_frame_new() }) } else { None };
        let bytes = if frame.is_some() { size } else { 0 };
        Self { frame, bytes, facts: Facts { version: 1, ..Facts::default() }, started: false,
            retired: false, in_call: false, poisoned: false, first: None, _not_sync: PhantomData }
    }
    pub fn not_started(&self) -> bool { !self.started && !self.retired && !self.in_call && !self.poisoned && self.first.is_none() }
    pub fn quiescent(&self) -> bool { !self.in_call && !self.poisoned && self.facts.settled() }
    pub fn settled(&self) -> bool { self.retired && self.frame.is_none() && self.quiescent() }
    /// Exact adapter-frame allocation only. It does not measure opaque
    /// filesec/ACL/qualifier heap storage. A containing byte census must remain
    /// unknown while !quiescent(), rather than treating those originals as zero.
    pub fn retained_frame_bytes(&self) -> usize { self.bytes }
    pub fn first_failure(&self) -> Option<(Failure, Instant)> { self.first }
    fn pointer(&self) -> *mut c_void { self.frame.map_or(std::ptr::null_mut(), NonNull::as_ptr) }
    fn fail(&mut self, problem: Failure) -> Failure {
        if self.first.is_none() { self.first=Some((problem, Instant::now())); }
        problem
    }
    fn refresh(&mut self, returned: c_int) -> Result<(), Failure> {
        let mut facts=Facts::default();
        // SAFETY: the same original frame and a distinct fixed writable result.
        let read = if returned == 1 { unsafe { mrk_vault_acl_facts_read(self.pointer(), &mut facts) } } else { 0 };
        if read != 1 || !facts.valid() {
            self.poisoned=true; return Err(self.fail(Failure::Unknown));
        }
        self.facts=facts;
        if let Some(problem)=facts.problem() { return Err(self.fail(problem)); }
        Ok(())
    }
    fn checkpoint(&mut self, stop: &mut dyn FnMut() -> bool) -> Result<(), Failure> {
        if stop() { Err(self.fail(Failure::Stopped)) } else { Ok(()) }
    }
    pub fn observe(&mut self, fd: BorrowedFd<'_>, expected: Expected, policy: Policy,
        stop: &mut dyn FnMut() -> bool) -> Result<(), Failure> {
        if let Some((problem,_))=self.first { return Err(problem); }
        if self.retired || !self.quiescent() { return Err(self.fail(Failure::Unknown)); }
        self.checkpoint(stop)?;
        if self.frame.is_none() { return Err(self.fail(Failure::Bounds)); }
        self.started=true; self.in_call=true;
        // SAFETY: one stable original frame; fixed copy-only expected metadata.
        let returned=unsafe { mrk_vault_acl_begin(self.pointer(), &expected, u32::from(matches!(policy,Policy::Empty))) };
        self.in_call=false; self.refresh(returned)?;
        while self.facts.outcome == 0 {
            self.checkpoint(stop)?; self.in_call=true;
            // SAFETY: same live borrowed original FD throughout this synchronous
            // call. No descriptor acquisition, close or callback is delegated.
            let returned=unsafe { mrk_vault_acl_step(self.pointer(), fd.as_raw_fd()) };
            self.in_call=false;
            self.refresh(returned)?; // Latch actual refusal BEFORE STOP or cleanup.
            self.checkpoint(stop)?;
        }
        while self.facts.owned() {
            self.checkpoint(stop)?; self.in_call=true;
            // SAFETY: consumes one retained original reference, once.
            let returned=unsafe { mrk_vault_acl_cleanup_step(self.pointer()) };
            self.in_call=false; self.refresh(returned)?; self.checkpoint(stop)?;
        }
        if self.facts.outcome != 1 || !self.quiescent() { return Err(self.fail(Failure::Unknown)); }
        Ok(())
    }
    /// The callback sees the first actual failure timestamp before every cleanup
    /// entry. Its containing StoreBook combines that with the ORIGINAL owner
    /// endpoint; the adapter never starts or renews a phase timer.
    pub fn release(&mut self, expired: &mut dyn FnMut(Option<(Failure, Instant)>) -> bool) -> bool {
        if self.retired { return self.settled(); }
        if self.in_call || self.poisoned { self.fail(Failure::Unknown); return false; }
        while self.facts.owned() {
            if expired(self.first) { self.fail(Failure::Stopped); return false; }
            self.in_call=true;
            // SAFETY: one positive original; the C ledger skips Unknown frees
            // while allowing other independent owned references to retire.
            let returned=unsafe { mrk_vault_acl_cleanup_step(self.pointer()) };
            self.in_call=false;
            let _ = self.refresh(returned);
            if self.poisoned { return false; }
            if expired(self.first) { self.fail(Failure::Stopped); return false; }
        }
        if !self.facts.settled() { self.fail(Failure::Unknown); return false; }
        if self.frame.is_some() {
            if expired(self.first) { self.fail(Failure::Stopped); return false; }
            self.in_call=true;
            // SAFETY: frame retirement requires positively settled original
            // references; actual return precedes removing the charge/capability.
            let retired=unsafe { mrk_vault_acl_frame_retire(self.pointer()) };
            self.in_call=false;
            if retired != 1 { self.poisoned=true; self.fail(Failure::Unknown); return false; }
            self.frame=None; self.bytes=0;
            if expired(self.first) { self.fail(Failure::Stopped); }
        }
        self.retired=true; self.settled()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn storage_acl_policy_never_grants_mutation_via_an_allow_ace() {
        // Header constants and the SAME C predicate, not guessed ABI bit values.
        // This only checks DATA policy; no filesystem/provider API is entered.
        assert_eq!(unsafe { mrk_vault_acl_policy_data_contract() },15);
    }
    #[test]
    fn incomplete_or_unknown_native_custody_cannot_become_a_settled_snapshot() {
        let complete=Facts { version:1, phase:15, outcome:1, resource:[4,4,4],
            entries:2, qualifiers:2, qualifiers_closed:2, ..Facts::default() };
        assert!(complete.valid() && complete.settled());
        for state in [1,2,3,5] { let mut facts=complete; facts.resource[1]=state; assert!(!facts.settled()); }
        let mut facts=complete; facts.qualifiers_closed=1; assert!(!facts.valid());
        facts=complete; facts.entries=130; assert!(!facts.valid());
        facts=complete; facts.first_phase=13; assert!(!facts.valid());
        facts.outcome=3; facts.resource[2]=5; assert!(facts.valid() && facts.uncertain());
        assert_eq!(facts.problem(),Some(Failure::Unknown));
    }
}
