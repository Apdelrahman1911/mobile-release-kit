//! One explicit Darwin flock attempt on a borrowed ORIGINAL Android lease.
//!
//! This is a small native-call ledger, NOT a descriptor/transaction owner. The
//! containing publisher, catalog, recovery or Start owner retains the same
//! original FD, authenticates its parent/name/APFS/header/principal/ACL, and
//! preserves the approved EX-last-close or whole-use SH lifetime. A successful
//! call alone does not admit content or establish resource finality.
//!
//! LockAttempt provides no pathname, open, close, unlock, conversion, clone,
//! fork, retry, child, callback worker or Drop cleanup. Its synchronous borrow
//! does not move custody. The separate GuardedClose shim below is the sole
//! reviewed final consuming close; every entry has same-clock pre-admission.
use std::{cell::Cell, marker::PhantomData, os::fd::{AsRawFd, BorrowedFd}, time::Instant};
use nix::{errno::Errno, fcntl::{fcntl, FcntlArg}, libc, sys::stat::{fstat, FileStat}};

/// Closed call roles. "Fresh" means the containing original owner exclusively
/// created and authenticated its new empty0600 leaf; this enum is not proof of
/// creation, account authentication or authority to write its final header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode { FreshExclusive, RecoveryExclusive, Shared }
impl Mode {
    fn native_flags(self) -> i32 {
        libc::LOCK_NB | if matches!(self, Self::Shared) { libc::LOCK_SH } else { libc::LOCK_EX }
    }
    fn access_mode(self) -> i32 {
        if matches!(self, Self::FreshExclusive) { libc::O_RDWR } else { libc::O_RDONLY }
    }
}

/// Full immutable original fstat DATA, without atime (ordinary reads may update
/// it). FreshExclusive checks an empty0600 leaf before finalization; the other
/// roles check the fixed finalized0400/60-byte lease. Native ACL/ancestry/header
/// and EUID/principal checks remain separate mandatory original observations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Expected {
    pub device: u64, pub inode: u64, pub mode: u32, pub owner: u32, pub group: u32,
    pub links: u64, pub bytes: u64, pub flags: u32,
    pub modified_seconds: i64, pub modified_nanoseconds: u32,
    pub changed_seconds: i64, pub changed_nanoseconds: u32,
}
impl Expected {
    fn observed(value: &FileStat) -> Option<Self> {
        Some(Self {
            device: u64::try_from(value.st_dev).ok()?, inode: value.st_ino,
            mode: u32::from(value.st_mode), owner: value.st_uid, group: value.st_gid,
            links: u64::from(value.st_nlink), bytes: u64::try_from(value.st_size).ok()?,
            flags: value.st_flags,
            modified_seconds: value.st_mtime,
            modified_nanoseconds: u32::try_from(value.st_mtime_nsec).ok()?,
            changed_seconds: value.st_ctime,
            changed_nanoseconds: u32::try_from(value.st_ctime_nsec).ok()?,
        })
    }
    fn shape(self, mode: Mode) -> bool {
        let (permissions, bytes) = if matches!(mode, Mode::FreshExclusive) {
            (0o100600, 0)
        } else { (0o100400, 60) };
        self.device != 0 && self.inode != 0 && self.mode == permissions
            && self.owner == 0 && self.group == 0 && self.links == 1 && self.bytes == bytes
            && self.flags == 0 && self.modified_nanoseconds < 1_000_000_000
            && self.changed_nanoseconds < 1_000_000_000
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure { Refused, Busy, Native, Stopped, Reused, Unknown }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step { InitialStat, DescriptorFlags, AccessFlags, Acquire, FinalStat }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeFailure { pub step: Step, pub returned: i32, pub errno: i32 }

/// Returned syscall state only. Held remains Held on late STOP, metadata
/// mismatch or later observation failure: the containing owner must still
/// retain the ORIGINAL lease and all dependent exclusions. Unknown never
/// becomes Held through a replacement attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LockState { NotAttempted, Calling, Held(Mode), Busy, Unknown }

/// Inert, fixed-size and !Sync. Reserve it with the containing original owner
/// before GO; call acquire only from that owner's same entered worker. No
/// framework, descriptor, heap allocation or native query occurs in new().
pub struct LockAttempt {
    entered: bool,
    in_native: bool,
    state: LockState,
    first: Option<(Failure, Instant)>,
    native_failure: Option<NativeFailure>,
    _not_sync: PhantomData<Cell<()>>,
}
impl LockAttempt {
    pub fn new() -> Self {
        Self { entered: false, in_native: false, state: LockState::NotAttempted,
            first: None, native_failure: None, _not_sync: PhantomData }
    }
    pub fn not_started(&self) -> bool { !self.entered && !self.in_native && self.first.is_none() }
    pub fn lock_state(&self) -> LockState { self.state }
    pub fn first_failure(&self) -> Option<(Failure, Instant)> { self.first }
    pub fn native_failure(&self) -> Option<NativeFailure> { self.native_failure }
    /// No result from this book is a descriptor close/finality observation.
    pub fn call_in_progress(&self) -> bool { self.in_native }
    fn fail_at(&mut self, failure: Failure, at: Instant) -> Failure {
        if self.first.is_none() { self.first = Some((failure, at)); }
        self.first.expect("failure was recorded").0
    }
    fn fail(&mut self, failure: Failure) -> Failure { self.fail_at(failure, Instant::now()) }
    fn begin(&mut self) -> Result<(), Failure> {
        if self.entered || self.in_native || self.first.is_some() {
            return Err(self.fail(Failure::Reused));
        }
        // Even pre-call refusal/STOP consumes this attempt. No same-book retry.
        self.entered = true;
        Ok(())
    }
    fn checkpoint(&mut self, stopped: &mut dyn FnMut(Option<(Failure, Instant)>) -> bool) -> Result<(), Failure> {
        // The caller sees the original native failure before projecting its
        // earliest-F cleanup deadline. This adapter owns no phase clock.
        if stopped(self.first) { self.fail(Failure::Stopped); }
        match self.first { Some((failure, _)) => Err(failure), None => Ok(()) }
    }
    fn native_error(&mut self, step: Step, errno: Errno) -> Failure {
        let at = Instant::now();
        if self.native_failure.is_none() {
            self.native_failure = Some(NativeFailure { step, returned: -1, errno: errno as i32 });
        }
        self.fail_at(Failure::Native, at)
    }
    fn record_lock_return(&mut self, mode: Mode, returned: i32, errno: i32, at: Instant) {
        // Only a direct successful native return establishes Held. No receipt,
        // metadata predicate, timeout or retry can fabricate that observation.
        if self.state != LockState::Calling || !self.in_native {
            self.state = LockState::Unknown;
            self.fail_at(Failure::Unknown, at);
            return;
        }
        self.in_native = false;
        match (returned, errno) {
            (0, 0) => self.state = LockState::Held(mode),
            (-1, value) if value == libc::EWOULDBLOCK => {
                self.state = LockState::Busy;
                self.native_failure = Some(NativeFailure { step: Step::Acquire, returned, errno });
                self.fail_at(Failure::Busy, at);
            }
            _ => {
                // EINTR/error/invalid return is never retried, converted or
                // described as proof that the kernel released the original.
                self.state = LockState::Unknown;
                self.native_failure = Some(NativeFailure { step: Step::Acquire, returned, errno });
                self.fail_at(Failure::Unknown, at);
            }
        }
    }
    fn stat_matches(&mut self, fd: BorrowedFd<'_>, expected: Expected, step: Step) -> Result<(), Failure> {
        self.in_native = true;
        let observed = fstat(fd);
        self.in_native = false;
        match observed {
            Ok(value) if Expected::observed(&value) == Some(expected) => Ok(()),
            Ok(_) => Err(self.fail(Failure::Refused)),
            Err(errno) => Err(self.native_error(step, errno)),
        }
    }

    pub fn acquire(&mut self, fd: BorrowedFd<'_>, expected: Expected, mode: Mode,
        stopped: &mut dyn FnMut(Option<(Failure, Instant)>) -> bool) -> Result<(), Failure>
    {
        self.begin()?;
        self.checkpoint(stopped)?;
        if !expected.shape(mode) { return Err(self.fail(Failure::Refused)); }
        let _ = self.stat_matches(fd, expected, Step::InitialStat);
        self.checkpoint(stopped)?;

        self.in_native = true;
        let descriptor_flags = fcntl(fd, FcntlArg::F_GETFD);
        self.in_native = false;
        match descriptor_flags {
            Ok(value) if value & libc::FD_CLOEXEC == libc::FD_CLOEXEC => {}
            Ok(_) => { self.fail(Failure::Refused); }
            Err(errno) => { self.native_error(Step::DescriptorFlags, errno); }
        }
        self.checkpoint(stopped)?;
        self.in_native = true;
        let access_flags = fcntl(fd, FcntlArg::F_GETFL);
        self.in_native = false;
        match access_flags {
            Ok(value) if value & libc::O_ACCMODE == mode.access_mode()
                && value & libc::O_NONBLOCK == libc::O_NONBLOCK => {}
            Ok(_) => { self.fail(Failure::Refused); }
            Err(errno) => { self.native_error(Step::AccessFlags, errno); }
        }
        self.checkpoint(stopped)?;

        self.state = LockState::Calling;
        self.in_native = true;
        // SAFETY: one live borrowed original FD, closed role-derived native
        // flags, synchronous nonblocking call. No pointer, descriptor transfer,
        // duplication, unlock or destructor-controlled flock wrapper is used.
        let returned = unsafe { libc::flock(fd.as_raw_fd(), mode.native_flags()) };
        // Capture the errno immediately, before clock/callback/native work.
        let errno = if returned == -1 { Errno::last() as i32 } else { 0 };
        self.record_lock_return(mode, returned, errno, Instant::now());
        self.checkpoint(stopped)?; // Preserve a late-acquired original as Held.
        let _ = self.stat_matches(fd, expected, Step::FinalStat);
        self.checkpoint(stopped)?;
        if self.state != LockState::Held(mode) { return Err(self.fail(Failure::Unknown)); }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn expected(mode: Mode) -> Expected {
        Expected { device: 7, inode: 42,
            mode: if matches!(mode, Mode::FreshExclusive) { 0o100600 } else { 0o100400 },
            owner: 0, group: 0, links: 1, bytes: if matches!(mode, Mode::FreshExclusive) { 0 } else { 60 },
            flags: 0, modified_seconds: 1, modified_nanoseconds: 2, changed_seconds: 3, changed_nanoseconds: 4 }
    }
    fn calling() -> LockAttempt {
        let mut value = LockAttempt::new();
        value.begin().unwrap();
        value.state = LockState::Calling;
        value.in_native = true;
        value
    }
    fn fixed_roles_shapes_and_nonblocking_flags_data() {
        for mode in [Mode::FreshExclusive, Mode::RecoveryExclusive, Mode::Shared] {
            assert!(expected(mode).shape(mode));
            assert_ne!(mode.native_flags() & libc::LOCK_NB, 0);
            assert_eq!(mode.native_flags() & libc::LOCK_UN, 0);
            assert_ne!(mode.native_flags() & if mode == Mode::Shared { libc::LOCK_SH } else { libc::LOCK_EX }, 0);
            for field in 0..10 {
                let mut bad = expected(mode);
                match field {
                    0 => bad.owner = 501,
                    1 => bad.group = 80,
                    2 => bad.mode ^= 0o020,
                    3 => bad.links = 2,
                    4 => bad.bytes += 1,
                    5 => bad.flags = 1,
                    6 => bad.device = 0,
                    7 => bad.inode = 0,
                    8 => bad.modified_nanoseconds = 1_000_000_000,
                    _ => bad.changed_nanoseconds = 1_000_000_000,
                }
                assert!(!bad.shape(mode), "role {mode:?} field {field}");
            }
        }
        assert!(!expected(Mode::FreshExclusive).shape(Mode::Shared));
        assert!(!expected(Mode::Shared).shape(Mode::FreshExclusive));
    }
    fn native_return_unknown_and_contention_do_not_claim_success_data() {
        let at = Instant::now();
        for (returned, errno) in [(-1, libc::EINTR), (-1, libc::EBADF), (-1, 0), (1, 0), (0, libc::EIO)] {
            let mut value = calling();
            value.record_lock_return(Mode::Shared, returned, errno, at);
            assert_eq!(value.lock_state(), LockState::Unknown);
            assert_eq!(value.first_failure(), Some((Failure::Unknown, at)));
            assert!(!value.call_in_progress());
            assert!(value.begin().is_err());
            assert_eq!(value.lock_state(), LockState::Unknown);
        }
        let mut busy = calling();
        busy.record_lock_return(Mode::RecoveryExclusive, -1, libc::EWOULDBLOCK, at);
        assert_eq!(busy.lock_state(), LockState::Busy);
        assert_eq!(busy.first_failure(), Some((Failure::Busy, at)));
        assert!(busy.begin().is_err());
        assert_eq!(busy.lock_state(), LockState::Busy);
    }
    fn actual_failure_precedes_stop_and_late_acquisition_remains_held_data() {
        let at = Instant::now();
        let mut bad = calling();
        bad.record_lock_return(Mode::Shared, -1, libc::EWOULDBLOCK, at);
        let mut observed = None;
        assert_eq!(bad.checkpoint(&mut |first| { observed = first; true }), Err(Failure::Busy));
        assert_eq!(observed, Some((Failure::Busy, at)));
        assert_eq!(bad.first_failure(), Some((Failure::Busy, at)));
        let mut late = calling();
        late.record_lock_return(Mode::FreshExclusive, 0, 0, at);
        assert_eq!(late.checkpoint(&mut |_| true), Err(Failure::Stopped));
        assert_eq!(late.lock_state(), LockState::Held(Mode::FreshExclusive));
        assert!(!late.call_in_progress());
        assert!(late.begin().is_err()); // Cannot convert/retry the held original.
        assert_eq!(late.lock_state(), LockState::Held(Mode::FreshExclusive));
    }
    fn inert_constructor_and_preentry_refusal_are_one_use_data() {
        let mut value = LockAttempt::new();
        assert!(value.not_started());
        assert_eq!(value.lock_state(), LockState::NotAttempted);
        value.begin().unwrap();
        assert_eq!(value.checkpoint(&mut |_| true), Err(Failure::Stopped));
        assert_eq!(value.lock_state(), LockState::NotAttempted);
        assert!(!value.call_in_progress() && !value.not_started());
        assert!(value.begin().is_err());
        assert_eq!(value.first_failure().unwrap().0, Failure::Stopped);
        let mut impossible = LockAttempt::new();
        impossible.record_lock_return(Mode::Shared, 0, 0, Instant::now());
        assert_eq!(impossible.lock_state(), LockState::Unknown);
        assert_eq!(impossible.first_failure().unwrap().0, Failure::Unknown);
    }
    #[test]
    fn fixed_roles_shapes_and_nonblocking_flags() { fixed_roles_shapes_and_nonblocking_flags_data(); }
    #[test]
    fn native_return_unknown_and_contention_do_not_claim_success() { native_return_unknown_and_contention_do_not_claim_success_data(); }
    #[test]
    fn actual_failure_precedes_stop_and_late_acquisition_remains_held() { actual_failure_precedes_stop_and_late_acquisition_remains_held_data(); }
    #[test]
    fn inert_constructor_and_preentry_refusal_are_one_use() { inert_constructor_and_preentry_refusal_are_one_use_data(); }

    pub(super) fn all_data() {
        fixed_roles_shapes_and_nonblocking_flags_data();
        native_return_unknown_and_contention_do_not_claim_success_data();
        actual_failure_precedes_stop_and_late_acquisition_remains_held_data();
        inert_constructor_and_preentry_refusal_are_one_use_data();
    }
}

/// Explicit nonshipping harness bridge. Pure ledger/DATA cases only; no file,
/// flock, native account/ACL/provider call, original acquisition or execution.
#[cfg(test)]
pub fn assert_android_lease_lock_policy_data_contract() { tests::all_data(); consuming_close_tests::all_data(); }


/// Closed scalar admission from the SAME original owner. The cutoff is already
/// min(original hard, earliest known failure + original grace), never receipt-now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CloseAdmission {
    pub origin: u64, pub hard: u64, pub previous: u64, pub cutoff: u64,
}
const CLOSE_MAX_RAW: u64 = (1_u64 << 61) - 1;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CloseRefusal { Bounds, Clock, Deadline }
impl CloseAdmission {
    fn valid(self) -> bool {
        self.origin != 0 && self.origin < self.hard && self.hard <= CLOSE_MAX_RAW
            && self.previous >= self.origin && self.previous <= CLOSE_MAX_RAW
            && self.cutoff > self.origin && self.cutoff <= self.hard
    }
    fn clock_sample(self, value: u64) -> bool {
        self.valid() && value >= self.previous && value >= self.origin && value <= CLOSE_MAX_RAW
    }
    /// Pure DATA rule also used by the actual native shim; no synthetic sample
    /// can invoke that shim or construct a GuardedClose with descriptor custody.
    pub fn refusal(self, before: Option<u64>) -> Option<CloseRefusal> {
        if !self.valid() { return Some(CloseRefusal::Bounds); }
        let Some(before) = before else { return Some(CloseRefusal::Clock); };
        if !self.clock_sample(before) { return Some(CloseRefusal::Clock); }
        if self.previous >= self.cutoff || before >= self.cutoff { return Some(CloseRefusal::Deadline); }
        None
    }
}

/// Scalar view ONLY. No returned0/errno0 is fabricated for a refused entry; a
/// call which never returns has no CloseData and remains in its original join.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CloseData {
    NotEntered { before: Option<u64>, refusal: CloseRefusal },
    Returned { before: u64, returned: i32, errno: i32, after: Option<u64> },
}
impl CloseData {
    pub fn entered(self) -> bool { matches!(self, Self::Returned { .. }) }
    pub fn returned_success(self) -> bool {
        matches!(self, Self::Returned { returned: 0, errno: 0, .. })
    }
    pub fn close_errno(self) -> Option<i32> {
        match self {
            Self::Returned { returned, errno, .. } if (returned, errno) != (0, 0) => Some(errno),
            _ => None,
        }
    }
    /// Actual valid same-clock sample, not an accepted timestamp invented for
    /// a missing/regressing/invalid clock. Late native return may still have a
    /// valid failure time; timely finality is a separate, stricter fact.
    pub fn observation(self, admission: CloseAdmission) -> Option<u64> {
        match self {
            Self::NotEntered { before: Some(before), refusal: CloseRefusal::Deadline }
                if admission.refusal(Some(before)) == Some(CloseRefusal::Deadline) => Some(before),
            Self::Returned { before, after: Some(after), .. }
                if admission.refusal(Some(before)).is_none()
                    && after >= before && after <= CLOSE_MAX_RAW => Some(after),
            _ => None,
        }
    }
    /// Independent first-F may narrow the already original cutoff after the
    /// return. It cannot extend it. Returned success alone is never settlement.
    pub fn timely_success(self, admission: CloseAdmission, independent_cutoff: Option<u64>) -> bool {
        self.returned_success() && self.observation(admission).is_some_and(|after|
            independent_cutoff.is_some_and(|cutoff| after < cutoff.min(admission.cutoff)))
    }
}

/// One-use moved original result. A positively non-entered FD remains HERE in
/// non-dropping opaque custody. No FD getter, Debug/Clone, retry, reconstruction,
/// release or Drop close is exposed. The containing original owner retains this
/// object even on Unknown. Entered failures do NOT recreate known-open custody.
pub struct GuardedClose {
    data: CloseData,
    _not_entered: Option<std::mem::ManuallyDrop<std::os::fd::OwnedFd>>,
}
impl GuardedClose { pub fn data(&self) -> CloseData { self.data } }

/// The only consuming original close entrypoint. Every dependent read/native/
/// parent original and matching owner join must be settled before the caller
/// moves this exact FD. Mandatory same-clock pre-admission occurs INSIDE this
/// shim; a previous close's after-time is not admission for this call.
pub fn consume_original(fd: std::os::fd::OwnedFd, admission: CloseAdmission) -> GuardedClose {
    use std::{mem::ManuallyDrop, os::fd::IntoRawFd};
    // Install non-dropping custody BEFORE even the pre-admission clock call.
    let original = ManuallyDrop::new(fd);
    let before = crate::vault_helper_wire::uptime();
    if let Some(refusal) = admission.refusal(before) {
        return GuardedClose { data: CloseData::NotEntered { before, refusal }, _not_entered: Some(original) };
    }
    // Only the admitted branch converts/consumes. No panic-producing unwrap or
    // numeric retry is needed; the None branch is explicitly non-entered above.
    let Some(before) = before else {
        return GuardedClose { data: CloseData::NotEntered { before: None, refusal: CloseRefusal::Clock },
            _not_entered: Some(original) };
    };
    let raw = ManuallyDrop::into_inner(original).into_raw_fd();
    // SAFETY: consumes the moved original exactly once. EINTR/EBADF/late return
    // is terminal uncertainty, never permission to reconstruct or retry raw.
    let returned = unsafe { libc::close(raw) };
    let errno = if returned == -1 { Errno::last() as i32 } else { 0 };
    let after = crate::vault_helper_wire::uptime();
    GuardedClose { data: CloseData::Returned { before, returned, errno, after }, _not_entered: None }
}

#[cfg(test)]
mod consuming_close_tests {
    use super::*;
    fn admission() -> CloseAdmission { CloseAdmission { origin: 100, hard: 500, previous: 200, cutoff: 400 } }
    fn pre_admission_never_uses_the_previous_return_as_current_time_data() {
        let gate = admission();
        assert_eq!(gate.refusal(Some(399)), None);
        // Previous200 is still admissible, but the scheduler delayed this NEXT
        // actual entry until the exact cutoff; it must not consume any FD.
        for before in [400, 401, 500] {
            assert_eq!(gate.refusal(Some(before)), Some(CloseRefusal::Deadline));
        }
        for before in [None, Some(0), Some(99), Some(199), Some(CLOSE_MAX_RAW + 1)] {
            assert_eq!(gate.refusal(before), Some(CloseRefusal::Clock));
        }
        assert_eq!(CloseAdmission { cutoff: 199, ..gate }.refusal(Some(200)), Some(CloseRefusal::Deadline));
        for bad in [CloseAdmission { origin: 0, ..gate }, CloseAdmission { hard: 100, ..gate },
            CloseAdmission { cutoff: 501, ..gate }, CloseAdmission { cutoff: 100, ..gate },
            CloseAdmission { previous: 99, ..gate }, CloseAdmission { hard: CLOSE_MAX_RAW + 1, ..gate }] {
            assert_eq!(bad.refusal(Some(300)), Some(CloseRefusal::Bounds));
        }
    }
    fn non_entry_return_success_and_finality_are_distinct_data() {
        let gate = admission();
        let refused = CloseData::NotEntered { before: Some(400), refusal: CloseRefusal::Deadline };
        assert!(!refused.entered());
        assert_eq!(u32::from(refused.entered()), 0); // production attempt accounting
        assert!(!refused.returned_success());
        assert_eq!(refused.close_errno(), None);
        assert_eq!(refused.observation(gate), Some(400));
        assert!(!refused.timely_success(gate, Some(500)));
        let ok = CloseData::Returned { before: 250, returned: 0, errno: 0, after: Some(300) };
        assert!(ok.entered() && ok.returned_success() && ok.timely_success(gate, Some(400)));
        assert!(ok.timely_success(gate, Some(301)));
        // An earlier actual F can only CONTRACT original min(H,F+10).
        assert!(!ok.timely_success(gate, Some(300)));
        assert!(!ok.timely_success(gate, None));
        for after in [Some(400), Some(401)] {
            let late = CloseData::Returned { before: 250, returned: 0, errno: 0, after };
            assert!(late.entered() && late.returned_success());
            assert!(!late.timely_success(gate, Some(500))); // no cutoff renewal
            assert_eq!(late.observation(gate), after);
        }
        for after in [None, Some(0), Some(249), Some(CLOSE_MAX_RAW + 1)] {
            let bad = CloseData::Returned { before: 250, returned: 0, errno: 0, after };
            assert_eq!(bad.observation(gate), None);
            assert!(!bad.timely_success(gate, Some(400)));
        }
        for (returned, errno) in [(-1, libc::EINTR), (-1, libc::EBADF), (-1, 0), (1, 0), (0, libc::EIO)] {
            let failed = CloseData::Returned { before: 250, returned, errno, after: Some(300) };
            assert!(failed.entered()); assert!(!failed.returned_success());
            assert_eq!(failed.close_errno(), Some(errno));
            assert_eq!(failed.observation(gate), Some(300));
            assert!(!failed.timely_success(gate, Some(400)));
        }
        let bad_clock = CloseData::NotEntered { before: Some(199), refusal: CloseRefusal::Clock };
        assert_eq!(bad_clock.observation(gate), None);
        assert_eq!(u32::from(bad_clock.entered()), 0);
    }
    #[test]
    fn pre_admission_never_uses_the_previous_return_as_current_time() {
        pre_admission_never_uses_the_previous_return_as_current_time_data();
    }
    #[test]
    fn non_entry_return_success_and_finality_are_distinct() {
        non_entry_return_success_and_finality_are_distinct_data();
    }
    pub(super) fn all_data() {
        pre_admission_never_uses_the_previous_return_as_current_time_data();
        non_entry_return_success_and_finality_are_distinct_data();
    }
}
