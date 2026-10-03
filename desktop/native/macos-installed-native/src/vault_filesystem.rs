//! Original storage ACL snapshot custody. This book must be retained outside the
//! worker, just like its borrowed filesystem descriptors. No Keychain, filesystem
//! write, provider, clock owner, or credential capability is added.
//! The separate fixed-buffer readlink adapter observes one supplied parent/name
//! without following the link or allocating a pathname/target buffer.
use std::{cell::Cell, ffi::{c_int, c_void}, marker::PhantomData,
    os::fd::{AsRawFd, BorrowedFd}, ptr::NonNull, time::Instant};

/// First-party supplied C bookkeeping only. Matching C sizeof assertions bind
/// these pre-entry ceilings; opaque system ACL/filesec storage is OUTSIDE this
/// typed-owned byte claim, not zero and not proof of settled native custody.
pub const SNAPSHOT_FRAME_BYTES:usize=1024;
pub const LEASE_WRITER_FRAME_BYTES:usize=1024;
pub const LINK_TARGET_BYTES:usize=513;

fn link_length(count:usize)->Option<usize>{(count>0 && count<LINK_TARGET_BYTES).then_some(count)}
/// One original parent-relative readlink. A full output could be truncated and
/// therefore refuses, even if its prefix happens to match an expected target.
pub fn readlink_component(fd:BorrowedFd<'_>,name:&str,output:&mut[u8;LINK_TARGET_BYTES])->std::io::Result<usize>{
    if name.is_empty() || name.len()>255 || matches!(name,"."|"..")
        || name.as_bytes().iter().any(|b|matches!(*b,0|b'/')){
        return Err(std::io::ErrorKind::InvalidInput.into());
    }
    let mut component=[0_u8;256];component[..name.len()].copy_from_slice(name.as_bytes());
    // SAFETY: live borrowed original directory; bounded NUL-terminated component;
    // the supplied writable array lives for the entire ordinary POSIX call.
    let count=unsafe{nix::libc::readlinkat(fd.as_raw_fd(),component.as_ptr().cast(),
        output.as_mut_ptr().cast(),output.len())};
    if count<0{return Err(std::io::Error::last_os_error());}
    link_length(count as usize).ok_or_else(||std::io::ErrorKind::InvalidData.into())
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Expected {
    pub device: u64, pub inode: u64,
    pub mode: u32, pub owner: u32, pub group: u32, pub flags: u32,
}
#[derive(Clone, Copy)]
pub enum Policy {
    Ancestors,
    Empty,
    /// A protected root-owned registration lease only, never tools/runtime.
    /// The containing native connection/current-user owner must authenticate
    /// uid+principal; these expected DATA fields do not authenticate a peer.
    /// Native membership is independently compared and synthesized UID UUIDs
    /// are refused. No caller-provided or renderer UID is new authority here.
    LeaseUser { uid: u32, principal: [u8; 16] },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure { Refused, Native, Bounds, Stopped, Unknown }

/// Work may wait for a reversible application predicate. Cleanup must not wait:
/// it imports the original first failure and checks the original H/F cutoff.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObservePhase { Work, Cleanup }

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Facts {
    version: u32, phase: u32, outcome: u32, resource: [u32; 3],
    entries: u32, qualifiers: u32, qualifiers_closed: u32,
    first_phase: u32, first_return: i32, first_errno: i32,
}
impl Facts {
    fn valid(self) -> bool {
        self.version == 1 && (self.phase <= 15 || (19..=23).contains(&self.phase)) && self.outcome <= 4
            && self.resource.iter().all(|state| *state <= 5)
            && self.entries <= 129 && self.qualifiers <= self.entries
            && self.qualifiers_closed <= self.qualifiers && self.first_errno >= 0
            && if self.first_phase == 0 {
                self.outcome <= 1 && self.first_return == 0 && self.first_errno == 0
                    && (self.outcome != 1 || self.phase == 15 && self.entries == self.qualifiers
                        && self.qualifiers == self.qualifiers_closed)
            } else { (1..=23).contains(&self.first_phase) && self.outcome >= 2 }
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
    fn mrk_vault_acl_begin_lease_user(frame: *mut c_void, expected: *const Expected,
        uid: u32, principal: *const u8) -> c_int;
    fn mrk_vault_acl_step(frame: *mut c_void, fd: c_int) -> c_int;
    fn mrk_vault_acl_cleanup_step(frame: *mut c_void) -> c_int;
    fn mrk_vault_acl_frame_retire(frame: *mut c_void) -> c_int;
    #[cfg(test)]
    fn mrk_vault_acl_policy_data_contract() -> u32;
    #[cfg(test)]
    fn mrk_vault_acl_lease_policy_data_contract() -> u32;
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
        let frame = if (1..=SNAPSHOT_FRAME_BYTES).contains(&size) { NonNull::new(unsafe { mrk_vault_acl_frame_new() }) } else { None };
        let bytes = if frame.is_some() { size } else { 0 };
        Self { frame, bytes, facts: Facts { version: 1, ..Facts::default() }, started: false,
            retired: false, in_call: false, poisoned: false, first: None, _not_sync: PhantomData }
    }
    pub fn not_started(&self) -> bool { !self.started && !self.retired && !self.in_call && !self.poisoned && self.first.is_none() }
    pub fn quiescent(&self) -> bool { !self.in_call && !self.poisoned && self.facts.settled() }
    pub fn settled(&self) -> bool { self.retired && self.frame.is_none() && self.quiescent() }
    /// Exact first-party adapter frame only, not opaque filesec/ACL/qualifier
    /// heap storage. Original native lifetime/return/Unknown obligations remain
    /// independent: this byte count is never a settlement or release receipt.
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
    fn observe_checkpoint(&mut self, phase: ObservePhase,
        gate: &mut dyn FnMut(ObservePhase, Option<(Failure, Instant)>) -> bool) -> Result<(), Failure> {
        if gate(phase, self.first) { Err(self.fail(Failure::Stopped)) } else { Ok(()) }
    }
    fn after_work_checkpoint(&mut self,
        gate: &mut dyn FnMut(ObservePhase, Option<(Failure, Instant)>) -> bool) -> Result<(), Failure> {
        let phase=if self.facts.outcome==0 { ObservePhase::Work } else { ObservePhase::Cleanup };
        self.observe_checkpoint(phase,gate)
    }
    /// Compatibility policy: the same Boolean predicate still runs at each
    /// original checkpoint. Registration uses the phase-aware entry below.
    pub fn observe(&mut self, fd: BorrowedFd<'_>, expected: Expected, policy: Policy,
        stop: &mut dyn FnMut() -> bool) -> Result<(), Failure> {
        self.observe_phased(fd,expected,policy,&mut |_,_| stop())
    }
    /// Callbacks run BETWEEN synchronous C entries, with in_call=false. Work
    /// may wait outside application/barrier/watch guards. Cleanup must not wait
    /// on a conditional publisher or treat pending alone as STOP; it receives
    /// the original native first failure before the next consuming entry.
    pub fn observe_phased(&mut self, fd: BorrowedFd<'_>, expected: Expected, policy: Policy,
        gate: &mut dyn FnMut(ObservePhase, Option<(Failure, Instant)>) -> bool) -> Result<(), Failure> {
        if let Some((problem,_))=self.first { return Err(problem); }
        if self.retired || !self.quiescent() { return Err(self.fail(Failure::Unknown)); }
        self.observe_checkpoint(ObservePhase::Work,gate)?;
        if self.frame.is_none() { return Err(self.fail(Failure::Bounds)); }
        self.started=true; self.in_call=true;
        // SAFETY: one stable original frame; fixed copy-only expected metadata.
        let returned=match policy {
            Policy::Ancestors => unsafe { mrk_vault_acl_begin(self.pointer(), &expected, 0) },
            Policy::Empty => unsafe { mrk_vault_acl_begin(self.pointer(), &expected, 1) },
            Policy::LeaseUser { uid, principal } => unsafe {
                mrk_vault_acl_begin_lease_user(self.pointer(), &expected, uid, principal.as_ptr())
            },
        };
        self.in_call=false; self.refresh(returned)?;
        while self.facts.outcome == 0 {
            self.observe_checkpoint(ObservePhase::Work,gate)?; self.in_call=true;
            // SAFETY: same live borrowed original FD throughout this synchronous
            // call. No descriptor acquisition, close or callback is delegated.
            let returned=unsafe { mrk_vault_acl_step(self.pointer(), fd.as_raw_fd()) };
            self.in_call=false;
            self.refresh(returned)?; // Latch actual refusal BEFORE STOP or cleanup.
            self.after_work_checkpoint(gate)?;
        }
        while self.facts.owned() {
            self.observe_checkpoint(ObservePhase::Cleanup,gate)?; self.in_call=true;
            // SAFETY: consumes one retained original reference, once.
            let returned=unsafe { mrk_vault_acl_cleanup_step(self.pointer()) };
            self.in_call=false; self.refresh(returned)?; self.observe_checkpoint(ObservePhase::Cleanup,gate)?;
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
    fn last_work_return_cannot_wait_before_cleanup_or_replace_the_native_failure() {
        // SAME production checkpoint; no filesystem/native entry. The last
        // successful work return switches to the nonwaiting cleanup predicate.
        let mut book=SnapshotBook { frame:None, bytes:0,
            facts:Facts { version:1,phase:15,outcome:1,resource:[2,2,0],..Facts::default() },
            started:true,retired:false,in_call:false,poisoned:false,first:None,_not_sync:PhantomData };
        let mut phases=Vec::new();
        book.after_work_checkpoint(&mut |phase,failure| {
            phases.push(phase);assert!(failure.is_none());false
        }).unwrap();
        assert_eq!(phases,[ObservePhase::Cleanup]);
        book.facts.outcome=0;
        book.after_work_checkpoint(&mut |phase,_| { phases.push(phase);false }).unwrap();
        assert_eq!(phases,[ObservePhase::Cleanup,ObservePhase::Work]);
        let original=Instant::now();book.first=Some((Failure::Native,original));book.facts.outcome=3;
        assert_eq!(book.after_work_checkpoint(&mut |phase,failure| {
            assert_eq!(phase,ObservePhase::Cleanup);
            assert_eq!(failure,Some((Failure::Native,original)));true
        }),Err(Failure::Stopped));
        assert_eq!(book.first_failure(),Some((Failure::Native,original)));
    }
    #[test]
    fn storage_acl_policy_never_grants_mutation_via_an_allow_ace() {
        // Header constants and the SAME C predicate, not guessed ABI bit values.
        // This only checks DATA policy; no filesystem/provider API is entered.
        assert_eq!(unsafe { mrk_vault_acl_policy_data_contract() },15);
    }
    #[test]
    fn lease_acl_requires_exact_flags_rights_and_nonsynthesized_user_principal() {
        // The same C predicate checks every single bit of each public32-bit
        // ACL/ACE flag and rights field, entry count, principal and header.
        // No membership or filesystem API runs in this DATA-only contract.
        assert_eq!(unsafe { mrk_vault_acl_lease_policy_data_contract() },31);
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



/// Fixed new-lease ACL mutation boundary. This does NOT change SnapshotBook or
/// permit mutations on runtime/payload files. Only the containing authenticated
/// helper's original new EX-held lease may enter; no renderer pathname or ACL
/// byte stream is accepted here.
pub mod lease_writer {
    use super::{Expected, Failure};
    use std::{cell::Cell, ffi::{c_int, c_void}, marker::PhantomData,
        os::fd::{AsRawFd, BorrowedFd}, ptr::NonNull, time::Instant};

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct FreshExpected {
        pub identity: Expected,
        pub links: u64, pub bytes: u64,
        pub modified_seconds: i64, pub modified_nanoseconds: i64,
        pub changed_seconds: i64, pub changed_nanoseconds: i64,
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Mutation { NotEntered, Entered, Applied, Unknown }
    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct WriterFacts {
        version: u32, phase: u32, outcome: u32, resource: u32, effect: u32, post_observed: u32,
        first_phase: u32,
        first_return: i32, first_errno: i32, free_return: i32, free_errno: i32,
        changed_seconds: i64, changed_nanoseconds: i64,
    }
    impl WriterFacts {
        fn valid(self) -> bool {
            self.version == 1 && self.phase <= 11 && self.outcome <= 3 && self.resource <= 5
                && self.effect <= 3 && self.post_observed <= 1 && self.first_errno >= 0 && self.free_errno >= 0
                && (self.post_observed == 0 || self.effect == 2 && self.phase == 11
                    && (0..1_000_000_000).contains(&self.changed_nanoseconds))
                && (self.effect != 3 || self.outcome >= 2)
                && (self.resource != 5 || self.outcome >= 2)
                && (self.free_return != 0 || self.free_errno == 0)
                && if self.first_phase == 0 {
                    self.outcome <= 1 && self.first_return == 0 && self.first_errno == 0
                        && (self.outcome != 1 || self.phase == 11 && self.effect == 2 && self.post_observed == 1)
                } else { (1..=12).contains(&self.first_phase) && self.outcome >= 2 }
        }
        fn resource_settled(self) -> bool { matches!(self.resource, 0 | 4) }
        fn unknown(self) -> bool { matches!(self.resource, 1 | 3 | 5) || self.effect == 3 }
        fn problem(self) -> Option<Failure> {
            if self.unknown() { return Some(Failure::Unknown); }
            match self.outcome { 2 => Some(Failure::Refused), 3 => Some(Failure::Native), _ => None }
        }
        fn mutation(self) -> Mutation {
            match self.effect { 0 => Mutation::NotEntered, 1 => Mutation::Entered,
                2 => Mutation::Applied, _ => Mutation::Unknown }
        }
    }
    unsafe extern "C" {
        fn mrk_android_lease_principal(uid: u32, out: *mut u8) -> c_int;
        fn mrk_android_lease_acl_write_frame_bytes() -> usize;
        fn mrk_android_lease_acl_write_frame_new() -> *mut c_void;
        fn mrk_android_lease_acl_write_facts_read(frame: *mut c_void, out: *mut WriterFacts) -> c_int;
        fn mrk_android_lease_acl_write_begin(frame: *mut c_void, fd: c_int,
            expected: *const FreshExpected, uid: u32, principal: *const u8) -> c_int;
        fn mrk_android_lease_acl_write_step(frame: *mut c_void, fd: c_int) -> c_int;
        fn mrk_android_lease_acl_write_cleanup(frame: *mut c_void) -> c_int;
        fn mrk_android_lease_acl_write_retire(frame: *mut c_void) -> c_int;
        #[cfg(test)]
        fn mrk_android_lease_acl_writer_data_contract() -> u32;
    }

    /// Holds the actual native allocation and one ACL original across STOP,
    /// refusal and cleanup. No Drop cleanup/retry. Containing original owner must
    /// retain an uncertain book and settle it BEFORE its last EX lease close.
    pub struct LeaseWriterBook {
        frame: Option<NonNull<c_void>>, bytes: usize, facts: WriterFacts,
        entered: bool, in_call: bool, poisoned: bool, retired: bool,
        first: Option<(Failure, Instant)>, _not_sync: PhantomData<Cell<()>>,
    }
    // SAFETY: exclusive Rust access encloses each synchronous native step; C
    // retains no thread-affine object or callback. Moves cannot overlap a borrow.
    unsafe impl Send for LeaseWriterBook {}
    impl LeaseWriterBook {
        /// Inert. Even native frame allocation waits for the SAME registered
        /// worker to enter after GO, outside Document/Registry locks.
        pub fn new() -> Self {
            Self { frame: None, bytes: 0, facts: WriterFacts { version: 1, ..WriterFacts::default() },
                entered: false, in_call: false, poisoned: false, retired: false,
                first: None, _not_sync: PhantomData }
        }
        pub fn not_started(&self) -> bool { !self.entered && !self.in_call && !self.retired && self.first.is_none() }
        pub fn first_failure(&self) -> Option<(Failure, Instant)> { self.first }
        pub fn mutation(&self) -> Mutation {
            if self.poisoned || self.in_call { Mutation::Unknown } else { self.facts.mutation() }
        }
        /// Exact first-party adapter frame only, NOT opaque ACL allocator usage.
        /// Native originals remain separately owed until native_settled().
        pub fn retained_frame_bytes(&self) -> usize { self.bytes }
        pub fn native_settled(&self) -> bool {
            self.retired && self.frame.is_none() && !self.in_call && !self.poisoned && self.facts.resource_settled()
        }
        /// Separate cleanup diagnostic, never overwritten by the primary error.
        pub fn cleanup_failure(&self) -> Option<(i32, i32)> {
            (self.facts.resource == 5).then_some((self.facts.free_return, self.facts.free_errno))
        }
        /// Post-setter ctime DATA only. Full original readback,0400 sealing,
        /// exact lease ACL/header verification and persistence remain owed.
        pub fn post_changed_data(&self) -> Option<(i64, i64)> {
            (self.facts.post_observed == 1 && !self.poisoned && !self.in_call)
                .then_some((self.facts.changed_seconds, self.facts.changed_nanoseconds))
        }
        fn pointer(&self) -> *mut c_void { self.frame.map_or(std::ptr::null_mut(), NonNull::as_ptr) }
        fn fail(&mut self, failure: Failure) -> Failure {
            if self.first.is_none() { self.first = Some((failure, Instant::now())); }
            self.first.expect("original failure was recorded").0
        }
        fn checkpoint(&mut self, stopped: &mut dyn FnMut(Option<(Failure, Instant)>) -> bool) -> Result<(), Failure> {
            if stopped(self.first) { self.fail(Failure::Stopped); }
            match self.first { Some((failure, _)) => Err(failure), None => Ok(()) }
        }
        fn refresh(&mut self, returned: c_int) -> Result<(), Failure> {
            let mut facts = WriterFacts::default();
            // SAFETY: same retained native frame and distinct fixed result.
            let read = if returned == 1 { unsafe { mrk_android_lease_acl_write_facts_read(self.pointer(), &mut facts) } } else { 0 };
            if read != 1 || !facts.valid() {
                self.poisoned = true; return Err(self.fail(Failure::Unknown));
            }
            self.facts = facts;
            match facts.problem() { Some(problem) => Err(self.fail(problem)), None => Ok(()) }
        }

        /// Install only the closed native-selected-account read ACE on the
        /// containing helper's NEW root:wheel0600/60-byte original lease.
        /// Caller owns original EX, authenticated connection EUID/principal,
        /// empty-ACL protected ancestry and complete header/creation proof.
        /// A returned Ok means the setter/post-fstat returned, NOT that native
        /// custody settled, lease persisted, publication succeeded or finality.
        pub fn apply(&mut self, fd: BorrowedFd<'_>, expected: FreshExpected, uid: u32,
            principal: [u8; 16], stopped: &mut dyn FnMut(Option<(Failure, Instant)>) -> bool) -> Result<(), Failure>
        {
            if !self.not_started() { return Err(self.fail(Failure::Unknown)); }
            self.entered = true;
            self.checkpoint(stopped)?;
            self.in_call = true;
            // SAFETY: fixed sizeof query; no object/descriptor acquired.
            let size = unsafe { mrk_android_lease_acl_write_frame_bytes() };
            self.in_call = false;
            if !(1..=super::LEASE_WRITER_FRAME_BYTES).contains(&size) { return Err(self.fail(Failure::Bounds)); }
            self.checkpoint(stopped)?;
            self.in_call = true;
            // SAFETY: one new bounded zeroed frame, retained before STOP checks.
            let frame = unsafe { mrk_android_lease_acl_write_frame_new() };
            self.in_call = false;
            self.frame = NonNull::new(frame);
            self.bytes = if self.frame.is_some() { size } else { 0 };
            if self.frame.is_none() { return Err(self.fail(Failure::Bounds)); }
            self.checkpoint(stopped)?;
            self.in_call = true;
            // SAFETY: stable original frame; live borrowed original FD; fixed
            // expected metadata and principal cells live throughout this call.
            let returned = unsafe { mrk_android_lease_acl_write_begin(self.pointer(), fd.as_raw_fd(),
                &expected, uid, principal.as_ptr()) };
            self.in_call = false;
            let _ = self.refresh(returned);
            self.checkpoint(stopped)?;
            while self.facts.outcome == 0 {
                self.in_call = true;
                // SAFETY: same original frame and FD, one fixed native step.
                let returned = unsafe { mrk_android_lease_acl_write_step(self.pointer(), fd.as_raw_fd()) };
                self.in_call = false;
                let _ = self.refresh(returned); // Actual F precedes STOP.
                self.checkpoint(stopped)?;
            }
            if self.facts.outcome != 1 || self.facts.mutation() != Mutation::Applied {
                return Err(self.fail(Failure::Unknown));
            }
            Ok(())
        }

        /// Consume the one positively owned ACL original once; collect its
        /// actual cleanup error separately; never retry Unknown. The deadline
        /// callback uses the containing owner's original min(H,F+10), not a
        /// timer started by this adapter. Resource settlement is NOT proof of
        /// no metadata effect: mutation()==Unknown remains Unknown.
        pub fn release(&mut self, expired: &mut dyn FnMut(Option<(Failure, Instant)>) -> bool) -> bool {
            if self.retired { return self.native_settled(); }
            if self.in_call || self.poisoned { self.fail(Failure::Unknown); return false; }
            if self.facts.resource == 2 {
                if expired(self.first) { self.fail(Failure::Stopped); return false; }
                self.in_call = true;
                // SAFETY: consumes only the one positively retained ACL.
                let returned = unsafe { mrk_android_lease_acl_write_cleanup(self.pointer()) };
                self.in_call = false;
                let _ = self.refresh(returned);
                if self.poisoned { return false; }
                if expired(self.first) { self.fail(Failure::Stopped); return false; }
            }
            if !self.facts.resource_settled() { self.fail(Failure::Unknown); return false; }
            if self.frame.is_some() {
                if expired(self.first) { self.fail(Failure::Stopped); return false; }
                self.in_call = true;
                // SAFETY: all native references positively settled; one
                // consuming frame retirement. A lost/invalid return poisons it.
                let returned = unsafe { mrk_android_lease_acl_write_retire(self.pointer()) };
                self.in_call = false;
                if returned != 1 { self.poisoned = true; self.fail(Failure::Unknown); return false; }
                self.frame = None; self.bytes = 0;
                if expired(self.first) { self.fail(Failure::Stopped); }
            }
            self.retired = true;
            self.native_settled()
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        fn applied() -> WriterFacts {
            WriterFacts { version: 1, phase: 11, outcome: 1, resource: 2, effect: 2,
                post_observed: 1, changed_seconds: 3, changed_nanoseconds: 4, ..WriterFacts::default() }
        }
        #[test]
        fn exact_writer_policy_is_same_native_read_only_ace_and_new_lease_shape() {
            // Pure C DATA helper only: no allocator, file, account or setter.
            assert_eq!(unsafe { mrk_android_lease_acl_writer_data_contract() }, 31);
        }
        #[test]
        fn applied_metadata_does_not_imply_native_settlement_and_cleanup_errors_remain_distinct() {
            let mut facts = applied();
            assert!(facts.valid() && !facts.resource_settled());
            facts.resource = 4;
            assert!(facts.valid() && facts.resource_settled());
            facts.resource = 5; facts.outcome = 3; facts.first_phase = 9;
            facts.first_return = -1; facts.first_errno = 5;
            facts.free_return = -1; facts.free_errno = 22;
            assert!(facts.valid() && !facts.resource_settled());
            let mut book = LeaseWriterBook::new(); book.facts = facts;
            assert_eq!(book.cleanup_failure(), Some((-1, 22)));
            assert_eq!(book.facts.first_errno, 5);
            assert!(!book.native_settled());
            book.facts.resource = 4; book.facts.effect = 3; book.facts.post_observed = 0;
            assert!(book.facts.valid() && book.facts.resource_settled());
            assert_eq!(book.mutation(), Mutation::Unknown);
        }
        #[test]
        fn inert_writer_records_original_failure_before_later_stop_without_new_clock() {
            let mut book = LeaseWriterBook::new();
            assert!(book.not_started() && book.frame.is_none() && book.bytes == 0);
            book.fail(Failure::Native);
            let first = book.first_failure();
            let mut seen = None;
            assert_eq!(book.checkpoint(&mut |value| { seen = value; true }), Err(Failure::Native));
            assert_eq!(seen, first);
            assert_eq!(book.first_failure(), first);
            assert!(!book.not_started() && !book.native_settled());
        }
        #[test]
        fn invalid_native_facts_cannot_create_applied_or_settled_authority() {
            for which in 0..7 {
                let mut facts = applied();
                match which {
                    0 => facts.version = 2,
                    1 => facts.effect = 0,
                    2 => facts.post_observed = 0,
                    3 => facts.phase = 10,
                    4 => facts.changed_nanoseconds = 1_000_000_000,
                    5 => facts.resource = 6,
                    _ => facts.first_phase = 9,
                }
                assert!(!facts.valid(), "field {which}");
            }
        }
    }
    /// Actual native membership observation, not renderer/serialized identity.
    /// Caller gates this synchronous call on its original W/F/H and invokes
    /// only after the genuine connecting EUID is available.
    pub fn principal(uid: u32) -> Result<[u8; 16], Failure> {
        let mut out = [0; 16];
        if uid == 0 || uid == u32::MAX { return Err(Failure::Refused); }
        // SAFETY: one fixed16-byte result; no pointer or native resource retained.
        if unsafe { mrk_android_lease_principal(uid, out.as_mut_ptr()) } != 1 || out == [0; 16] {
            return Err(Failure::Refused);
        }
        Ok(out)
    }

}

#[cfg(test)]
mod supplied_frame_data_tests{
    use super::*;
    #[test]
    fn full_link_buffer_never_counts_as_a_complete_target(){
        assert_eq!(link_length(0),None);assert_eq!(link_length(512),Some(512));
        assert_eq!(link_length(513),None);assert_eq!(link_length(514),None);
    }
}
