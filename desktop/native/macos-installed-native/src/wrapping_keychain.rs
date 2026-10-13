//! Unwired explicit-login-Keychain primitive, not an operation owner or permit.
//!
//! Provider entry is confined to two owner-bound, nonshipping helper mains.
//! Shared Desktop/Tokio/OriginalWork is NOT process isolation and cannot activate
//! it. The existing owner retains each helper's actual return through STOP/cutoff.
//! Security calls are synchronous and have no timeout-as-cancel contract here.
//!
//! The first profile admits only the native ordinary user's existing explicit
//! login.keychain-db. It never discovers a default/search-list store, unlocks,
//! creates a login Keychain, repairs a missing item or retries an add. The private
//! helper guard saves/disables/restores its own process-local interaction Boolean
//! for each operation; every final result requires its actual restoration. This
//! is not a per-query UIFail guarantee, a thread-local guard or a shipping API.
//!
//! Returned immutable CFData is never mutated. Exactly32 checked bytes are
//! copied into one stable private native cell. Every CF/ACL original and retained
//! no-follow descriptor must actually settle before a candidate is obtainable. Wipe covers our cell,
//! not OS/provider copies, compiler temporaries or swap. The retained candidate's
//! charge includes its whole native frame, not just the32 logical secret bytes.
//!
//! Add requires the existing durable initialization reservation and generated
//! key. A duplicate is terminal. AddEffect survives refusal, late return and
//! cleanup uncertainty; neither a timeout nor Missing grants another add.
//! Retained APFS ancestry and five paired leaf/complete ACL checkpoints exclude
//! foreign mutation authority under the trusted OS/current ordinary-user profile.
//! Every ACL allow is considered applicable regardless of flags; only exact root
//! or current USER UUIDs may allow mutation. Ordinary home deny-delete is allowed.
//! These are bounded checks, not hostile same-user swapback or provider-FD inode
//! attestation: GetPath supplies spelling only. Database mutation may replace an
//! inode between checkpoints; no cross-checkpoint content/stat equality is required.
//!
//! Header authentication, key charge and all publication/finality gates remain
//! application obligations. Session Lock must not lock the user's Keychain.

// Both the explicit target cfg and build.rs's checked C-side handshake must
// agree. In particular PROFILE/debug info cannot stand in for debug_assertions.
#[cfg(any(
    all(mrk_wrapping_keychain_qualification,
        not(all(feature = "installed-observation", debug_assertions, mrk_wrapping_keychain_qualification_native))),
    all(mrk_wrapping_keychain_qualification_native, not(mrk_wrapping_keychain_qualification))
))]
compile_error!("wrapping qualification requires matching explicit cfg, native build, installed-observation and debug assertions");

#[cfg(all(mrk_wrapping_keychain_qualification, mrk_wrapping_keychain_qualification_native,
    feature = "installed-observation", debug_assertions))]
#[path = "wrapping_keychain_qualification.rs"]
pub mod qualification;

#[cfg(all(mrk_wrapping_keychain_qualification, mrk_wrapping_keychain_qualification_native,
    feature = "installed-observation", debug_assertions))]
#[path = "wrapping_keychain_pair.rs"]
pub mod private_pair;

#[cfg(all(mrk_wrapping_keychain_qualification, mrk_wrapping_keychain_qualification_native,
    feature = "installed-observation", debug_assertions))]
#[path = "wrapping_keychain_fixture.rs"]
pub mod private_fixture;

use std::any::Any;
use std::cell::Cell;
use std::ffi::c_void;
use std::marker::PhantomData;
use std::mem::size_of;
use std::panic::{catch_unwind, resume_unwind, AssertUnwindSafe};
use std::ptr::NonNull;
use std::time::Instant;

#[path = "wrapping_keychain_transport.rs"]
pub mod transport;

pub const KEY_BYTES: usize = 32;
pub const MAX_CF_REFERENCES: usize = 24;
pub const MAX_SECURITY_CALLS: usize = 12;
pub const MAX_NATIVE_FRAME_BYTES: usize = 65_536;
pub const MAX_DESCRIPTORS: usize = 72;
pub const MAX_PATH_COMPONENTS: u32 = 64;
pub const NAMESPACE_CHECKPOINTS: u32 = 5;
pub const MAX_ACL_SNAPSHOTS: u32 = 400;
pub const MAX_ACL_ENTRIES: u32 = 128;
pub const MAX_NATIVE_CALLS: u32 = 300_000;

const KNOWN: u32 = 1;
const UNKNOWN: u32 = 2;
const STOP: u32 = 4;
const ITEM_VERIFIED: u32 = 8;
const KEY_READY: u32 = 16;
const USER_ADMITTED: u32 = 32;
const STATUS_OBSERVED: u32 = 64;
const KEY_WIPED: u32 = 128;
const NATIVE_EXCEPTION: u32 = 256;
const CALLBACK_UNKNOWN: u32 = 512;
const NAMESPACE_VERIFIED: u32 = 1024;
const FLAG_MASK: u32 = 2047;
const ERR_SEC_DUPLICATE_ITEM: i32 = -25299; // Public OSStatus; the sibling uses errSecDuplicateItem.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operation { AddOnly, Lookup }
impl Operation { fn raw(self) -> u32 { match self { Self::AddOnly => 1, Self::Lookup => 2 } } }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Pending, Added, Candidate, Missing, Duplicate, Locked, InteractionRequired,
    AuthenticationFailed, UserCanceled, Unavailable, Unsupported, InvalidInput,
    InvalidResult, Allocation, Stopped, CustodyUnknown, NativeFailure, NativeException,
}
impl Outcome {
    fn from_raw(raw: u32) -> Self {
        match raw {
            0 => Self::Pending, 1 => Self::Added, 2 => Self::Candidate, 3 => Self::Missing,
            4 => Self::Duplicate, 5 => Self::Locked, 6 => Self::InteractionRequired,
            7 => Self::AuthenticationFailed, 8 => Self::UserCanceled, 9 => Self::Unavailable,
            10 => Self::Unsupported, 11 => Self::InvalidInput, 12 => Self::InvalidResult,
            13 => Self::Allocation, 14 => Self::Stopped, 15 => Self::CustodyUnknown,
            16 => Self::NativeFailure, 17 => Self::NativeException, _ => Self::InvalidResult,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddEffect { NotEntered, Added, Duplicate, MayHaveAdded }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Custody { InFlight, Settled, Unknown }

/// The owner supplies its ORIGINAL cutoff/state. No clock is started here.
/// Cutoff revokes later calls and delivery, but permits original-only releases.
/// Explicit Unknown retains native custody and starts no further release. A
/// returned failed descriptor close does not itself skip independent originals;
/// each remaining close still requires this owner's BeforeRelease admission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admission { Continue, Cutoff, Unknown }
impl Admission {
    fn raw(self) -> u32 { match self { Self::Continue => 1, Self::Cutoff => 2, Self::Unknown => 3 } }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Checkpoint { BeforeCall, AfterCall, BeforeRelease, BeforeDelivery }
impl Checkpoint {
    fn from_raw(raw: u32) -> Option<Self> {
        match raw { 0 => Some(Self::BeforeCall), 1 => Some(Self::AfterCall),
            2 => Some(Self::BeforeRelease), 3 => Some(Self::BeforeDelivery), _ => None }
    }
}

/// Fixed validated identity, not a free-form account/service/Keychain selector.
pub struct Context { vault: [u8; 16], generation: [u8; 16] }
impl Context {
    pub fn new(vault: [u8; 16], generation: [u8; 16]) -> Result<Self, Outcome> {
        if vault == [0; 16] || generation == [0; 16] || vault == generation {
            return Err(Outcome::InvalidInput);
        }
        Ok(Self { vault, generation })
    }
}

/// Nonsecret actual reference observations. All fields are checked0/1.
/// A reserved or null-result slot is never counted as a CFRelease.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReferenceObservation {
    pub reserved: u32,
    pub call_entered: u32,
    pub call_returned: u32,
    pub nonnull_returned: u32,
    pub release_entered: u32,
    pub release_returned: u32,
}
/// Security phase numbers:4 open,5 path,6 status,8 current trusted application,
/// 9 access,10 add,11 lookup,12 copied item parent. status is an actual OSStatus
/// ONLY when returned==1; zero in an unfinished row is not a success.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CallObservation {
    pub phase: u32,
    pub entered: u32,
    pub returned: u32,
    pub status: i32,
}
/// One original descriptor slot, never a numeric-handle ownership API.
/// Unentered/null ownership, actual open return, consuming close entry, actual
/// close result and successful settlement are distinct. errno is saved on return.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DescriptorObservation {
    pub reserved: u32,
    pub open_entered: u32,
    pub open_returned: u32,
    pub acquired: u32,
    pub open_errno: i32,
    pub close_entered: u32,
    pub close_returned: u32,
    pub closed: u32,
    pub close_result: i32,
    pub close_errno: i32,
}
impl DescriptorObservation {
    fn valid(&self, known: bool) -> bool {
        self.reserved == 1 && self.open_entered <= 1 && self.open_returned <= self.open_entered
            && self.acquired <= self.open_returned && self.close_entered <= self.acquired
            && self.close_returned <= self.close_entered && self.closed <= self.close_returned
            && (self.open_returned != 0 || self.open_errno == 0)
            && (self.close_returned != 0 || (self.close_result == 0 && self.close_errno == 0))
            && (self.close_returned == 0 || self.closed == u32::from(self.close_result == 0))
            && (!known || (self.open_entered == self.open_returned && self.acquired == self.closed
                && self.close_entered == self.close_returned))
    }
}
/// Bounded cumulative observations of the one reusable ACL working cell. A count
/// is incremented only at the corresponding actual entry/return. Unknown cells
/// keep their original allocations; no replacement/free retry is inferred.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AclObservation {
    pub snapshots_entered: u32,
    pub snapshots_returned: u32,
    pub snapshots_admitted: u32,
    pub entries: u32,
    pub filesec_init_entered: u32,
    pub filesec_init_returned: u32,
    pub filesec_acquired: u32,
    pub filesec_free_entered: u32,
    pub filesec_free_returned: u32,
    pub acl_export_entered: u32,
    pub acl_export_returned: u32,
    pub acl_acquired: u32,
    pub acl_free_entered: u32,
    pub acl_free_returned: u32,
    pub acl_freed: u32,
    pub qualifier_entered: u32,
    pub qualifier_returned: u32,
    pub qualifier_acquired: u32,
    pub qualifier_free_entered: u32,
    pub qualifier_free_returned: u32,
    pub qualifier_freed: u32,
}
impl AclObservation {
    fn valid(&self, known: bool) -> bool {
        fn stream(calls: [u32; 5], freed: u32, bound: u32, known: bool) -> bool {
            let [entered, returned, acquired, free_entered, free_returned] = calls;
            entered <= bound && returned <= entered && entered - returned <= 1
                && acquired <= returned && free_entered <= acquired && free_returned <= free_entered
                && freed <= free_returned && acquired - freed <= 1
                && (!known || (entered == returned && acquired == freed && free_entered == free_returned
                    && free_returned == freed))
        }
        self.snapshots_entered <= MAX_ACL_SNAPSHOTS && self.snapshots_returned <= self.snapshots_entered
            && self.snapshots_entered - self.snapshots_returned <= 1
            && self.snapshots_admitted <= self.snapshots_returned
            && self.snapshots_admitted <= self.filesec_free_returned
            && self.entries <= self.snapshots_entered * MAX_ACL_ENTRIES
            && stream([self.filesec_init_entered, self.filesec_init_returned, self.filesec_acquired,
                self.filesec_free_entered, self.filesec_free_returned],
                self.filesec_free_returned, self.snapshots_entered, known)
            && stream([self.acl_export_entered, self.acl_export_returned, self.acl_acquired,
                self.acl_free_entered, self.acl_free_returned], self.acl_freed, self.snapshots_entered, known)
            && stream([self.qualifier_entered, self.qualifier_returned, self.qualifier_acquired,
                self.qualifier_free_entered, self.qualifier_free_returned], self.qualifier_freed, self.entries, known)
            && (!known || self.snapshots_entered == self.snapshots_returned)
    }
}
/// Last nonowning/ACL API call and first refusal, not an unbounded history.
/// Codes:1 lstat(root),2 fstatat,3 fstat,4 fstatfs,5/6 root/current USER UUID;
/// 7 filesec_init,8 fstatx,9/10/11 owner/group/mode,12 ACL presence,13 ACL export,
/// 14 acl_valid,15 entry,16 tag,17 rights mask,18 qualifier,19 qualifier free,
/// 20 ACL free,21 filesec_free. For7/18 last_result is actual nonnull0/1; for21
/// it is0 only after the void call returned. Otherwise it is the actual scalar.
/// No paths, UUIDs, secret bytes, pointers or numeric descriptor handles escape.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NativeCallObservation {
    pub entered: u32,
    pub returned: u32,
    pub last_call: u32,
    pub last_returned: u32,
    pub last_result: i32,
    pub last_errno: i32,
    pub failure_call: u32,
    pub failure_result: i32,
    pub failure_errno: i32,
}
impl NativeCallObservation {
    fn valid(&self, known: bool) -> bool {
        if self.entered == 0 { return *self == Self::default(); }
        self.entered <= MAX_NATIVE_CALLS && self.returned <= self.entered && self.entered - self.returned <= 1
            && (1..=21).contains(&self.last_call) && self.last_returned <= 1
            && self.last_returned == u32::from(self.entered == self.returned)
            && (self.last_returned != 0 || (self.last_result == 0 && self.last_errno == 0))
            && (self.failure_call == 0 && self.failure_result == 0 && self.failure_errno == 0
                || (1..=21).contains(&self.failure_call))
            && (!known || self.entered == self.returned)
    }
}
const _: () = assert!(size_of::<DescriptorObservation>() == 40);
const _: () = assert!(size_of::<AclObservation>() == 84);
const _: () = assert!(size_of::<NativeCallObservation>() == 36);


/// Finite, nonsecret original process-policy observations. Getter validity is
/// separate from its byte; zero status is meaningful only after actual return.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct InteractionCallObservation {
    pub entered: u32, pub returned: u32, pub refused: u32, pub exception: u32,
    pub status: i32, pub value: u32, pub value_valid: u32,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProcessInteractionObservation {
    pub version: u32, pub kind: u32, pub role: u32, pub entered: u32, pub scope_admitted: u32,
    pub original_valid: u32, pub original_value: u32, pub installed: u32, pub restore_due: u32, pub restored: u32,
    pub failed: u32, pub first_failure: u32, pub finished: u32, pub callback_refused: u32, pub cleanup_refused: u32,
    pub namespace_entered: u32, pub namespace_returned: u32, pub namespace_completed: u32,
    pub calls: [InteractionCallObservation; 5],
}
const _: () = assert!(size_of::<InteractionCallObservation>() == 28);
const _: () = assert!(size_of::<ProcessInteractionObservation>() == 212);
impl ProcessInteractionObservation {
    fn valid(&self, final_return: bool) -> bool {
        // SAFETY: pure finite-data validation in the SAME shared scalar header;
        // no process activation, SDK, clock, provider, reference or filesystem.
        unsafe { mrk_wrapping_policy_validate(self, u32::from(final_return)) == 1 }
    }
    pub fn complete(&self) -> bool {
        unsafe { mrk_wrapping_policy_complete(self, 0) == 1 }
    }
    fn namespace_complete(&self) -> bool {
        unsafe { mrk_wrapping_policy_complete(self, 1) == 1 }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RawResult {
    version: u32, operation: u32, outcome: u32, effect: u32, phase: u32, failure_phase: u32, flags: u32,
    account_errno: i32,
    keychain_status: u32, slot_count: u32, call_count: u32, key_bytes: u32, run_returned: u32,
    references: [ReferenceObservation; MAX_CF_REFERENCES],
    calls: [CallObservation; MAX_SECURITY_CALLS],
    directory_count: u32, descriptor_count: u32, namespace_entered: u32, namespace_returned: u32, namespace_passed: u32,
    descriptors: [DescriptorObservation; MAX_DESCRIPTORS],
    acl: AclObservation,
    native: NativeCallObservation,
    policy: ProcessInteractionObservation,
}
const _: () = assert!(size_of::<RawResult>() == 4052);
impl RawResult {
    fn empty(operation: Operation, outcome: u32) -> Self {
        Self { version: 3, operation: operation.raw(), outcome, effect: 0, phase: 1,
            failure_phase: if outcome == 0 { 0 } else { 1 }, flags: KNOWN | KEY_WIPED,
            account_errno: 0, keychain_status: 0, slot_count: 0, call_count: 0,
            key_bytes: 0, run_returned: 0, references: [ReferenceObservation::default(); MAX_CF_REFERENCES],
            calls: [CallObservation::default(); MAX_SECURITY_CALLS],
            directory_count: 0, descriptor_count: 0, namespace_entered: 0, namespace_returned: 0, namespace_passed: 0,
            descriptors: [DescriptorObservation::default(); MAX_DESCRIPTORS],
            acl: AclObservation::default(), native: NativeCallObservation::default(),
            policy: ProcessInteractionObservation::default() }
    }
    fn valid(&self, final_return: bool) -> bool {
        if self.version != 3 || !matches!(self.operation, 1 | 2) || self.outcome > 17
            || self.effect > 3 || self.phase == 0 || self.phase > 21 || self.failure_phase > 21
            || self.flags & !FLAG_MASK != 0 || self.flags & (KNOWN | UNKNOWN) == (KNOWN | UNKNOWN)
            || self.slot_count as usize > MAX_CF_REFERENCES || self.call_count as usize > MAX_SECURITY_CALLS
            || !matches!(self.key_bytes, 0 | 32) || self.run_returned > 1
            || (final_return && (self.run_returned != 1 || self.outcome == 0 || self.flags & (KNOWN | UNKNOWN) == 0)) { return false; }
        let known = self.flags & KNOWN != 0;
        if !self.policy.valid(final_return && self.policy.kind != 0)
            || (self.run_returned == 1 && (self.policy.kind != 1 || (known && !self.policy.complete())))
            || (self.flags & KEY_READY != 0 && !self.policy.complete()) { return false; }
        if self.directory_count > MAX_PATH_COMPONENTS || self.descriptor_count as usize > MAX_DESCRIPTORS
            || (self.directory_count == 0 && (self.descriptor_count != 0 || self.namespace_entered != 0))
            || (self.directory_count != 0 && self.descriptor_count != self.directory_count + NAMESPACE_CHECKPOINTS)
            || self.namespace_entered > NAMESPACE_CHECKPOINTS || self.namespace_returned > self.namespace_entered
            || self.namespace_entered - self.namespace_returned > 1 || self.namespace_passed > self.namespace_returned
            || self.namespace_returned - self.namespace_passed > 1
            || (self.flags & NAMESPACE_VERIFIED != 0) != (self.namespace_passed == NAMESPACE_CHECKPOINTS)
            || !self.acl.valid(known) || !self.native.valid(known) { return false; }
        for (i, descriptor) in self.descriptors.iter().enumerate() {
            if i >= self.descriptor_count as usize {
                if *descriptor != DescriptorObservation::default() { return false; }
            } else if !descriptor.valid(known) { return false; }
        }
        if known && self.namespace_entered != self.namespace_returned { return false; }
        if self.flags & NAMESPACE_VERIFIED != 0 {
            // Construction plus five checkpoints each observe every directory;
            // each checkpoint also acquires one distinct, completely checked leaf.
            let snapshots = (NAMESPACE_CHECKPOINTS + 1) * self.directory_count + NAMESPACE_CHECKPOINTS;
            if self.flags & USER_ADMITTED == 0 || self.acl.snapshots_entered != snapshots
                || self.acl.snapshots_admitted != snapshots
                || self.descriptors[..self.descriptor_count as usize].iter().any(|r| r.acquired != 1) { return false; }
        }
        for (i, r) in self.references.iter().enumerate() {
            if i >= self.slot_count as usize {
                if *r != ReferenceObservation::default() { return false; }
                continue;
            }
            if r.reserved != 1 || r.call_entered > 1 || r.call_returned > r.call_entered
                || r.nonnull_returned > r.call_returned || r.release_entered > r.nonnull_returned
                || r.release_returned > r.release_entered { return false; }
            if self.flags & KNOWN != 0 && (r.call_entered != r.call_returned
                || r.nonnull_returned != r.release_returned) { return false; }
        }
        let mut add = None;
        let mut phases = [false; 17];
        for (i, call) in self.calls.iter().enumerate() {
            if i >= self.call_count as usize {
                if *call != CallObservation::default() { return false; }
                continue;
            }
            if !matches!(call.phase, 4 | 5 | 6 | 8 | 9 | 10 | 11 | 12) || call.entered != 1
                || call.returned > 1 || (call.returned == 0 && call.status != 0)
                || (self.flags & KNOWN != 0 && call.returned != 1) { return false; }
            if phases[call.phase as usize] || (self.operation == 1 && call.phase == 11)
                || (self.operation == 2 && matches!(call.phase, 8 | 9 | 10)) { return false; }
            phases[call.phase as usize] = true;
            if call.phase == 10 {
                if add.is_some() { return false; }
                add = Some(call);
            }
        }
        if self.operation == 2 && (self.effect != 0 || add.is_some()) { return false; }
        if self.operation == 1 {
            match (self.effect, add) {
                (0, None) => {},
                (1, Some(call)) if call.returned == 1 && call.status == 0 => {},
                (2, Some(call)) if call.returned == 1 && call.status == ERR_SEC_DUPLICATE_ITEM => {},
                (3, Some(_)) => {},
                _ => return false,
            }
        }
        if self.flags & KNOWN != 0 && self.flags & (NATIVE_EXCEPTION | CALLBACK_UNKNOWN) != 0 { return false; }
        if self.flags & KEY_READY != 0 && (self.operation != 2 || self.outcome != 2 || self.key_bytes != 32
            || self.flags & (KNOWN | ITEM_VERIFIED | NAMESPACE_VERIFIED) != (KNOWN | ITEM_VERIFIED | NAMESPACE_VERIFIED)
            || self.flags & (UNKNOWN | STOP | KEY_WIPED) != 0) { return false; }
        if self.flags & KEY_WIPED != 0 && self.key_bytes != 0 { return false; }
        true
    }
}

/// Bounded nonsecret actual facts, never a native-child join or publish permit.
/// Malformed ABI output is withheld, not normalized into a successful receipt.
pub struct Facts {
    raw: RawResult, operation: Operation, verified: bool, ffi_returned: bool,
    callback_panicked: bool, frame_retired: bool,
}
impl Facts {
    pub fn outcome(&self) -> Outcome {
        if self.verified { Outcome::from_raw(self.raw.outcome) } else { Outcome::InvalidResult }
    }
    pub fn add_effect(&self) -> AddEffect {
        if !self.verified {
            // The requested operation is Rust-owned, never an untrusted result field.
            return if self.operation == Operation::Lookup { AddEffect::NotEntered } else { AddEffect::MayHaveAdded };
        }
        match self.raw.effect { 0 => AddEffect::NotEntered, 1 => AddEffect::Added,
            2 => AddEffect::Duplicate, _ => AddEffect::MayHaveAdded }
    }
    pub fn custody(&self) -> Custody {
        if !self.verified || self.raw.flags & UNKNOWN != 0 { Custody::Unknown }
        else if self.raw.flags & KNOWN != 0 { Custody::Settled } else { Custody::InFlight }
    }
    pub fn stopped(&self) -> bool { self.raw.flags & STOP != 0 }
    pub fn original_item_verified(&self) -> bool { self.verified && self.raw.flags & ITEM_VERIFIED != 0 }
    pub fn namespace_verified(&self) -> bool { self.verified && self.raw.flags & NAMESPACE_VERIFIED != 0 }
    pub fn namespace_checkpoints_passed(&self) -> Option<u32> { self.verified.then_some(self.raw.namespace_passed) }
    pub fn ordinary_user_admitted(&self) -> bool { self.verified && self.raw.flags & USER_ADMITTED != 0 }
    pub fn observed_keychain_status(&self) -> Option<u32> {
        (self.verified && self.raw.flags & STATUS_OBSERVED != 0).then_some(self.raw.keychain_status)
    }
    pub fn account_errno(&self) -> Option<i32> { self.verified.then_some(self.raw.account_errno) }
    pub fn phase(&self) -> Option<u32> { self.verified.then_some(self.raw.phase) }
    pub fn first_refusal_phase(&self) -> Option<u32> {
        (self.verified && self.raw.failure_phase != 0).then_some(self.raw.failure_phase)
    }
    pub fn references(&self) -> Option<&[ReferenceObservation]> {
        if self.verified { Some(&self.raw.references[..self.raw.slot_count as usize]) } else { None }
    }
    pub fn security_calls(&self) -> Option<&[CallObservation]> {
        if self.verified { Some(&self.raw.calls[..self.raw.call_count as usize]) } else { None }
    }
    pub fn descriptors(&self) -> Option<&[DescriptorObservation]> {
        if self.verified { Some(&self.raw.descriptors[..self.raw.descriptor_count as usize]) } else { None }
    }
    pub fn acl_observation(&self) -> Option<&AclObservation> { self.verified.then_some(&self.raw.acl) }
    pub fn native_call_observation(&self) -> Option<&NativeCallObservation> { self.verified.then_some(&self.raw.native) }
    /// Rust actually received the original FFI return, even if its ABI was refused.
    /// This is not a trusted provider receipt, cleanup, worker join or finality.
    pub fn native_run_returned(&self) -> bool { self.ffi_returned }
    pub fn verified_native_run_receipt(&self) -> bool { self.verified && self.raw.run_returned == 1 }
    pub fn callback_panicked(&self) -> bool { self.callback_panicked }
    pub fn process_interaction(&self) -> Option<&ProcessInteractionObservation> {
        self.verified.then_some(&self.raw.policy)
    }
    pub fn process_interaction_restored(&self) -> bool { self.verified && self.raw.policy.complete() }
    pub fn native_exception(&self) -> bool { self.raw.flags & NATIVE_EXCEPTION != 0 }
    /// This concerns only the adapter's native frame, not provider/global state.
    pub fn adapter_frame_retired(&self) -> bool { self.frame_retired }
    fn accepted(&self, outcome: Outcome) -> bool {
        self.verified && !self.callback_panicked && self.native_run_returned() && self.verified_native_run_receipt()
            && self.custody() == Custody::Settled && !self.stopped() && self.process_interaction_restored()
            && self.original_item_verified() && self.namespace_verified() && self.outcome() == outcome
    }
}

unsafe extern "C" {
    fn mrk_wrapping_frame_bytes() -> usize;
    fn mrk_wrapping_frame_new() -> *mut c_void;
    fn mrk_wrapping_policy_validate(policy: *const ProcessInteractionObservation, final_return: u32) -> u32;
    fn mrk_wrapping_policy_complete(policy: *const ProcessInteractionObservation, namespace_only: u32) -> u32;
    fn mrk_wrapping_retain_unknown(frame: *mut c_void);
    fn mrk_wrapping_consume(frame: *mut c_void,
        consume: extern "C" fn(*mut c_void, *const u8, usize) -> u32, context: *mut c_void) -> u32;
    fn mrk_wrapping_frame_retire(frame: *mut c_void) -> u32;
}

/// Reserve this exact adapter allocation in the EXISTING owner before entry.
/// This is not a bound on SDK/provider-internal allocations made before return.
pub fn native_frame_bytes() -> Option<usize> {
    // SAFETY: returns only the sibling's compile-time sizeof, with no allocation.
    let bytes = unsafe { mrk_wrapping_frame_bytes() };
    (bytes != 0 && bytes <= MAX_NATIVE_FRAME_BYTES).then_some(bytes)
}

struct Frame { pointer: Option<NonNull<c_void>>, bytes: usize, retain: bool, _not_sync: PhantomData<Cell<()>> }
// SAFETY: a frame moves only before or after a synchronous native borrow. Rust
// gives exclusive access, there is no retained callback, and uncertain frames
// are never accessed/released on another thread. This type is deliberately !Sync.
unsafe impl Send for Frame {}
impl Frame {
    fn new() -> Option<Self> {
        let bytes = native_frame_bytes()?;
        // SAFETY: zeroed adapter-owned storage only; no Security query/effect.
        let pointer = NonNull::new(unsafe { mrk_wrapping_frame_new() })?;
        Some(Self { pointer: Some(pointer), bytes, retain: false, _not_sync: PhantomData })
    }
    fn pointer(&self) -> *mut c_void { self.pointer.map_or(std::ptr::null_mut(), NonNull::as_ptr) }
    fn retain_unknown(&mut self) {
        if !self.retain {
            // SAFETY: same live original after its synchronous call returned.
            // This only latches retention, clears callbacks and wipes safe copies.
            unsafe { mrk_wrapping_retain_unknown(self.pointer()) };
            self.retain = true;
        }
    }
    fn retire(&mut self) -> bool {
        if self.retain || self.pointer.is_none() { return false; }
        // SAFETY: same original, no active borrow. Native retires only positively
        // settled CF/ACL/FD custody, and wipes its own allocation before the actual free.
        let returned = unsafe { mrk_wrapping_frame_retire(self.pointer()) };
        if returned == 1 { self.pointer = None; true }
        else { self.retain = true; false } // No retry, not an allocation refund.
    }
}
impl Drop for Frame {
    fn drop(&mut self) {
        if self.pointer.is_some() && !self.retain { let _ = self.retire(); }
        // Unknown storage remains allocated. Losing Rust bookkeeping is a memory
        // safety fallback, NOT original-owner reachability, join or finality.
    }
}

struct AdmissionBridge<'a, F> {
    admission: &'a mut F,
    operation: Operation,
    panic: Option<Box<dyn Any + Send>>,
    malformed: bool,
}
extern "C" fn admission_bridge<F: FnMut(Checkpoint, &Facts) -> Admission>(
    context: *mut c_void, raw: *const RawResult, checkpoint: u32,
) -> u32 {
    if context.is_null() || raw.is_null() { return Admission::Unknown.raw(); }
    // SAFETY: exclusive fixed bridge and bounded snapshot live for the whole
    // synchronous native call; the sibling clears both pointers before returning.
    let bridge = unsafe { &mut *context.cast::<AdmissionBridge<'_, F>>() };
    if bridge.panic.is_some() || bridge.malformed { return Admission::Unknown.raw(); }
    let result = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: sibling passes a complete aligned read-only ABI snapshot; no
        // native mutation overlaps this synchronous callback.
        let raw = unsafe { *raw };
        let Some(checkpoint) = Checkpoint::from_raw(checkpoint) else {
            bridge.malformed = true; return Admission::Unknown;
        };
        if raw.operation != bridge.operation.raw() || !raw.valid(false) {
            bridge.malformed = true; return Admission::Unknown;
        }
        let facts = Facts { raw, operation: bridge.operation, verified: true, ffi_returned: false,
            callback_panicked: false, frame_retired: false };
        (bridge.admission)(checkpoint, &facts)
    }));
    match result {
        Ok(admission) => admission.raw(),
        // Do not drop an arbitrary panic payload across C. The actual Rust result
        // retains it after native return; no panic message/private data is logged.
        Err(payload) => { bridge.panic = Some(payload); Admission::Unknown.raw() },
    }
}


/// Original child cutoff copied before borrowing the forward owner. There is no
/// duration/new-clock constructor and no transported parent15/90s endpoint here.
/// This context survives in the actual return, separate from any forward panic.
pub struct CleanupAdmission {
    cutoff: Option<Instant>,
    #[cfg(feature = "vault-helper")]
    transported: bool,
    seen: u32,
    checks: u32,
    expired: bool,
    uncertain: bool,
    panic: Option<Box<dyn Any + Send>>,
}
impl CleanupAdmission {
    pub(super) fn from_original_cutoff(cutoff: Option<Instant>) -> Self {
        Self { cutoff, #[cfg(feature = "vault-helper")] transported: false,
            seen: 0, checks: 0, expired: false, uncertain: cutoff.is_none(), panic: None }
    }
    #[cfg(feature = "vault-helper")]
    pub(crate) fn from_helper_control() -> Self {
        Self { cutoff: None, transported: true, seen: 0, checks: 0,
            expired: false, uncertain: false, panic: None }
    }
    fn admit_current(&mut self, slot: u32) -> Admission {
        #[cfg(feature = "vault-helper")]
        if self.transported {
            if !matches!(slot, 3 | 4) || self.seen & (1 << slot) != 0
                || slot == 4 && self.seen & (1 << 3) == 0 {
                self.uncertain = true; return Admission::Unknown;
            }
            self.seen |= 1 << slot; self.checks += 1;
            if self.uncertain || self.panic.is_some() { return Admission::Unknown; }
            // Independent of the forward closure/panic/Facts. The fixed native
            // cell owns the first actual failure and earlier STOP contraction.
            let result = crate::vault_helper::cleanup_admission();
            match result {
                Admission::Unknown => self.uncertain = true,
                Admission::Cutoff => self.expired = true,
                Admission::Continue => {},
            }
            return if self.uncertain { Admission::Unknown }
                else if self.expired { Admission::Cutoff } else { Admission::Continue };
        }
        self.admit_at(slot, Instant::now())
    }
    fn admit_at(&mut self, slot: u32, now: Instant) -> Admission {
        if !matches!(slot, 3 | 4) || self.seen & (1 << slot) != 0
            || slot == 4 && self.seen & (1 << 3) == 0 {
            self.uncertain = true; return Admission::Unknown;
        }
        self.seen |= 1 << slot; self.checks += 1;
        if self.uncertain || self.panic.is_some() { return Admission::Unknown; }
        if self.cutoff.is_none_or(|cutoff| now >= cutoff) { self.expired = true; }
        if self.expired { Admission::Cutoff } else { Admission::Continue }
    }
    fn failed(&self) -> bool { self.expired || self.uncertain || self.panic.is_some() }
}
type NativeCleanupAdmission = extern "C" fn(*mut c_void, u32) -> u32;
extern "C" fn cleanup_admission_bridge(context: *mut c_void, slot: u32) -> u32 {
    if context.is_null() { return Admission::Unknown.raw(); }
    // SAFETY: native borrows this fixed context only for its own prearmed slots3/4,
    // synchronously, and clears it before return. It never accesses forward Facts.
    let original = unsafe { &mut *context.cast::<CleanupAdmission>() };
    if original.uncertain || original.panic.is_some() { return Admission::Unknown.raw(); }
    let returned = catch_unwind(AssertUnwindSafe(|| original.admit_current(slot)));
    match returned {
        Ok(admission) => admission.raw(),
        // Only a failure of this fixed clock/book leg can reach here. Retain its
        // own payload in the actual return; never inspect/drop forward payloads
        // or unwind/drop arbitrary Rust data across C.
        Err(payload) => { original.uncertain = true; original.panic = Some(payload); Admission::Unknown.raw() }
    }
}

/// Holds the actual outcome and any uncertain original frame. Keep this result
/// in OriginalWork through actual worker/coordinator joins. Neither take_value
/// nor positive adapter cleanup is authority to publish an authenticated vault.
pub struct NativeResult<T> {
    facts: Facts,
    value: Option<T>,
    retained: Option<Frame>,
    value_native_bytes: usize,
    // Declared after retained: its Rust-only destructor cannot strand a frame
    // by unwinding before the frame's non-retrying retention/drop handling.
    callback_panic: Option<Box<dyn Any + Send>>,
    cleanup: CleanupAdmission,
}
impl<T> NativeResult<T> {
    pub fn facts(&self) -> &Facts { &self.facts }
    pub fn take_value(&mut self) -> Option<T> {
        if self.facts.verified && self.facts.custody() == Custody::Settled && !self.facts.stopped()
            && !self.facts.callback_panicked && self.facts.process_interaction_restored()
            && self.callback_panic.is_none() && !self.cleanup.failed() {
            let value = self.value.take();
            if value.is_some() { self.value_native_bytes = 0; } // Charge transfers with the value; no refund.
            value
        } else { None }
    }
    /// Actual adapter allocation retained here, not SDK allocator capacity.
    pub fn retained_native_frame_bytes(&self) -> usize {
        self.retained.as_ref().map_or(0, |frame| frame.bytes)
            + if self.value.is_some() { self.value_native_bytes } else { 0 }
    }
    /// Adapter descriptor/frame only: not opaque caller panic payloads or SDK
    /// allocation capacity. Unknown custody never authorizes any charge refund.
    pub fn adapter_retained_bytes(&self) -> usize { size_of::<Self>() + self.retained_native_frame_bytes() }
}

struct Returned {
    facts: Facts,
    frame: Option<Frame>,
    panic: Option<Box<dyn Any + Send>>,
    cleanup: CleanupAdmission,
}
type NativeAdmission = extern "C" fn(*mut c_void, *const RawResult, u32) -> u32;
fn run_using<F: FnMut(Checkpoint, &Facts) -> Admission>(
    operation: Operation, admission: &mut F, mut cleanup: CleanupAdmission,
    invoke: impl FnOnce(*mut c_void, NativeAdmission, *mut c_void, NativeCleanupAdmission, *mut c_void, &mut RawResult) -> bool,
) -> Returned {
    let Some(mut frame) = Frame::new() else {
        return Returned { facts: Facts { raw: RawResult::empty(operation, 13), operation, verified: true,
            ffi_returned: false, callback_panicked: false, frame_retired: false }, frame: None, panic: None, cleanup };
    };
    let mut raw = RawResult::empty(operation, 0);
    let mut bridge = AdmissionBridge { admission, operation, panic: None, malformed: false };
    // One exclusively owned stable frame, bounded ABI result and original
    // admission bridge live through the ENTIRE call. The private invoker may
    // select only the compiled native entry; it is not a user callback or owner.
    let returned_shape = invoke(frame.pointer(), admission_bridge::<F>,
        (&mut bridge as *mut AdmissionBridge<'_, F>).cast(), cleanup_admission_bridge,
        (&mut cleanup as *mut CleanupAdmission).cast(), &mut raw);
    let verified = returned_shape && raw.operation == operation.raw() && raw.valid(false) && !bridge.malformed;
    let callback_panicked = bridge.panic.is_some() || cleanup.panic.is_some();
    let facts = Facts { raw, operation, verified, ffi_returned: true, callback_panicked, frame_retired: false };
    if !verified || callback_panicked || facts.custody() != Custody::Settled {
        frame.retain_unknown();
    }
    Returned { facts, frame: Some(frame), panic: bridge.panic, cleanup }
}
fn finish_without_key<T>(mut returned: Returned, value: Option<T>) -> NativeResult<T> {
    let mut value = value;
    if let Some(frame) = returned.frame.as_mut() {
        if returned.facts.custody() == Custody::Settled && !returned.facts.callback_panicked {
            if frame.retire() { returned.facts.frame_retired = true; returned.frame = None; }
            else { returned.facts.verified = false; value = None; }
        } else { value = None; }
    }
    NativeResult { facts: returned.facts, value, retained: returned.frame, value_native_bytes: 0, callback_panic: returned.panic, cleanup: returned.cleanup }
}

/// Shipping entry remains unavailable. A shared application worker is not the
/// process isolation required by the inspected classic-Keychain interaction API.
/// No provider call, callback, copy of key material or helper activation occurs.
pub fn add_only<F: FnMut(Checkpoint, &Facts) -> Admission>(
    context: &Context, key: &[u8; KEY_BYTES], admission: &mut F,
) -> NativeResult<()> {
    let _ = (context, key, admission);
    unavailable_in_application(Operation::AddOnly)
}

/// Shipping lookup remains unavailable, just like add_only. The candidate type
/// remains available for existing aliases, not as a shipping activation path.
pub fn lookup<F: FnMut(Checkpoint, &Facts) -> Admission>(
    context: &Context, admission: &mut F,
) -> NativeResult<WrappingKeyCandidate> {
    let _ = (context, admission);
    unavailable_in_application(Operation::Lookup)
}
fn unavailable_in_application<T>(operation: Operation) -> NativeResult<T> {
    finish_without_key(Returned {
        facts: Facts { raw: RawResult::empty(operation, 10), operation, verified: true,
            ffi_returned: false, callback_panicked: false, frame_retired: false },
        frame: None, panic: None, cleanup: CleanupAdmission::from_original_cutoff(None),
    }, None)
}
fn finish_lookup(mut returned: Returned) -> NativeResult<WrappingKeyCandidate> {
    if returned.facts.accepted(Outcome::Candidate) && returned.facts.raw.flags & KEY_READY != 0 {
        if let Some(frame) = returned.frame.take() {
            let value_native_bytes = frame.bytes;
            return NativeResult { facts: returned.facts, value: Some(WrappingKeyCandidate { frame }),
                retained: None, value_native_bytes, callback_panic: returned.panic, cleanup: returned.cleanup };
        }
    }
    finish_without_key(returned, None)
}

/// Only the exact lookup can construct this opaque consumed32-byte candidate.
/// No Clone/Debug/serde, raw field, raw getter or asynchronous borrow exists.
pub struct WrappingKeyCandidate { frame: Frame }
impl WrappingKeyCandidate {
    pub fn retained_bytes(&self) -> usize { size_of::<Self>() + self.frame.bytes }
    /// Synchronous header authentication, not availability or a charge refund.
    /// The private cell wipes on success, ordinary drop or callback unwinding.
    pub fn consume<R>(self, authenticate: impl FnOnce(&[u8; KEY_BYTES]) -> R) -> R {
        self.consume_with(authenticate)
    }
    fn consume_with<F: FnOnce(&[u8; KEY_BYTES]) -> R, R>(mut self, authenticate: F) -> R {
        struct Consumption<F, R> {
            callback: Option<F>,
            result: Option<Result<R, Box<dyn Any + Send>>>,
            malformed: bool,
        }
        extern "C" fn consume_bridge<F: FnOnce(&[u8; KEY_BYTES]) -> R, R>(
            context: *mut c_void, key: *const u8, bytes: usize,
        ) -> u32 {
            if context.is_null() { return 0; }
            // SAFETY: one fixed exclusive bridge lives through this native call.
            let state = unsafe { &mut *context.cast::<Consumption<F, R>>() };
            if state.result.is_some() || state.malformed || key.is_null() || bytes != KEY_BYTES {
                state.malformed = true; return 0;
            }
            let Some(callback) = state.callback.take() else { state.malformed = true; return 0; };
            state.result = Some(catch_unwind(AssertUnwindSafe(|| {
                // SAFETY: native grants only this synchronous view of its private
                // stable32-byte cell after all CF/ACL/FD custody actually settled.
                let key = unsafe { &*key.cast::<[u8; KEY_BYTES]>() };
                callback(key)
            })));
            1
        }
        let mut state = Consumption { callback: Some(authenticate), result: None, malformed: false };
        // SAFETY: this unique candidate owns the settled live native frame. The
        // sibling spends the key before the single callback, retains no pointer
        // to this bridge, and wipes the cell immediately after actual return.
        let returned = unsafe { mrk_wrapping_consume(self.frame.pointer(), consume_bridge::<F, R>,
            (&mut state as *mut Consumption<F, R>).cast()) };
        let retired = self.frame.retire();
        drop(self); // No retry on refusal; retire BEFORE returning or resuming a panic.
        assert!(retired && returned == 1 && !state.malformed, "invalid consumed wrapping-key ABI");
        match state.result {
            Some(Ok(value)) => value,
            Some(Err(payload)) => resume_unwind(payload),
            None => panic!("missing consumed wrapping-key callback"),
        }
    }
}

#[cfg(test)]
mod policy_contract_tests {
    use super::*;

    fn settled_policy() -> ProcessInteractionObservation {
        let call = |value| InteractionCallObservation { entered: 1, returned: 1, refused: 0, exception: 0,
            status: 0, value, value_valid: 1 };
        ProcessInteractionObservation {
            version: 1, kind: 1, role: 1, entered: 1, scope_admitted: 1,
            original_valid: 1, original_value: 1, installed: 1, restore_due: 1, restored: 1,
            finished: 1, calls: [call(1), call(0), call(0), call(1), call(1)],
            ..ProcessInteractionObservation::default()
        }
    }

    #[test]
    fn policy_failure_preserves_effect_and_blocks_known_candidate() {
        // Shared native DATA validator, not a second implementation of its rules.
        let mut policy = settled_policy();
        assert!(policy.valid(true) && policy.complete());
        policy.calls[3].status = -1; policy.failed = 1; policy.first_failure = 4;
        // Matching observation is real data but cannot erase a failed setter.
        assert!(policy.valid(true) && policy.restored == 1 && !policy.complete());
        let mut raw = RawResult::empty(Operation::AddOnly, 15);
        raw.policy = policy; raw.run_returned = 1; raw.phase = 16;
        raw.flags = UNKNOWN | KEY_WIPED; raw.effect = 1;
        raw.call_count = 1; raw.calls[0] = CallObservation { phase: 10, entered: 1, returned: 1, status: 0 };
        assert!(raw.valid(true));
        let facts = Facts { raw, operation: Operation::AddOnly, verified: true, ffi_returned: true,
            callback_panicked: false, frame_retired: false };
        assert_eq!(facts.add_effect(), AddEffect::Added);
        assert_eq!(facts.custody(), Custody::Unknown);
        assert!(!facts.process_interaction_restored());
        raw.flags = KNOWN | KEY_WIPED;
        assert!(!raw.valid(true)); // Resource flags cannot invent policy finality.
        raw.policy = settled_policy(); assert!(raw.valid(true));
        raw.version = 2; assert!(!raw.valid(true)); // Old ABI is not policy evidence.
        let mut unfinished = settled_policy();
        unfinished.finished = 0; assert!(!unfinished.complete());
        unfinished.calls[4].returned = 0; assert!(!unfinished.valid(true));
    }

    #[test]
    fn cleanup_uses_original_endpoint_and_spends_only_two_slots() {
        let cutoff = Instant::now();
        let before = cutoff.checked_sub(std::time::Duration::from_millis(1)).unwrap();
        let mut live = CleanupAdmission::from_original_cutoff(Some(cutoff));
        assert_eq!(live.admit_at(3, before), Admission::Continue);
        assert_eq!(live.admit_at(4, cutoff), Admission::Cutoff); // Equality is expired.
        assert!(live.failed());
        assert_eq!(live.admit_at(4, before), Admission::Unknown); // No retry/clock rewind.
        let mut order = CleanupAdmission::from_original_cutoff(Some(cutoff));
        assert_eq!(order.admit_at(4, before), Admission::Unknown);
        let mut wrong_slot = CleanupAdmission::from_original_cutoff(Some(cutoff));
        assert_eq!(wrong_slot.admit_at(2, before), Admission::Unknown);
        let mut missing = CleanupAdmission::from_original_cutoff(None);
        assert_eq!(cleanup_admission_bridge((&mut missing as *mut CleanupAdmission).cast(), 3), Admission::Unknown.raw());
    }

    #[test]
    fn cleanup_bridge_does_not_reenter_or_drop_poisoned_forward_callback() {
        use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};
        struct Payload(Arc<AtomicUsize>);
        impl Drop for Payload { fn drop(&mut self) { self.0.fetch_add(1, Ordering::SeqCst); } }
        let drops = Arc::new(AtomicUsize::new(0));
        let held = drops.clone();
        let mut callback = move |_: Checkpoint, _: &Facts| -> Admission { std::panic::panic_any(Payload(held.clone())) };
        let mut forward = AdmissionBridge { admission: &mut callback, operation: Operation::Lookup, panic: None, malformed: false };
        let raw = RawResult::empty(Operation::Lookup, 0);
        fn forward_call<F: FnMut(Checkpoint, &Facts) -> Admission>(bridge: &mut AdmissionBridge<'_, F>, raw: &RawResult) -> u32 {
            admission_bridge::<F>((bridge as *mut AdmissionBridge<'_, F>).cast(), raw, 0)
        }
        assert_eq!(forward_call(&mut forward, &raw), Admission::Unknown.raw());
        assert!(forward.panic.is_some()); assert_eq!(drops.load(Ordering::SeqCst), 0);
        // This deadline belongs to this small DATA-only test, not a native child.
        let cutoff = Instant::now().checked_add(std::time::Duration::from_secs(10));
        let mut cleanup = CleanupAdmission::from_original_cutoff(cutoff);
        let independent = (&mut cleanup as *mut CleanupAdmission).cast();
        assert_eq!(cleanup_admission_bridge(independent, 3), Admission::Continue.raw());
        assert_eq!(cleanup_admission_bridge(independent, 4), Admission::Continue.raw());
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        assert_eq!(forward_call(&mut forward, &raw), Admission::Unknown.raw());
        drop(forward);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn application_entries_do_not_invoke_provider_or_admission() {
        let context = Context::new([1; 16], [2; 16]).unwrap();
        let mut never = |_: Checkpoint, _: &Facts| -> Admission { panic!("application callback must remain unentered") };
        let mut add = add_only(&context, &[3; KEY_BYTES], &mut never);
        assert_eq!(add.facts().outcome(), Outcome::Unsupported);
        assert_eq!(add.facts().add_effect(), AddEffect::NotEntered);
        assert!(!add.facts().native_run_returned() && add.take_value().is_none());
        assert_eq!(add.retained_native_frame_bytes(), 0);
        let mut read = lookup(&context, &mut never);
        assert_eq!(read.facts().outcome(), Outcome::Unsupported);
        assert!(!read.facts().native_run_returned() && read.take_value().is_none());
        assert_eq!(read.retained_native_frame_bytes(), 0);
    }
}

// Separate fixed helper graph only. These are not public ordinary-app APIs.
#[cfg(feature="vault-helper")]
unsafe extern "C" {
    fn mrk_wrapping_run(frame:*mut c_void,operation:u32,vault:*const u8,generation:*const u8,key:*const u8,
        admission:NativeAdmission,context:*mut c_void,cleanup:NativeCleanupAdmission,cleanup_context:*mut c_void,out:*mut RawResult);
}
#[cfg(feature="vault-helper")]
pub(crate) fn helper_add<F:FnMut(Checkpoint,&Facts)->Admission>(context:&Context,key:&[u8;KEY_BYTES],admission:&mut F)->NativeResult<()> {
    let returned=run_using(Operation::AddOnly,admission,CleanupAdmission::from_helper_control(),
        |frame,admission,bridge,cleanup,cleanup_bridge,out|{
            // SAFETY: one registered native frame and both original synchronous
            //bridges; the fixed helper role is also checked by native main/pid.
            unsafe{mrk_wrapping_run(frame,1,context.vault.as_ptr(),context.generation.as_ptr(),key.as_ptr(),
                admission,bridge,cleanup,cleanup_bridge,out);}true
        });
    let value=returned.facts.accepted(Outcome::Added).then_some(());
    finish_without_key(returned,value)
}
#[cfg(feature="vault-helper")]
pub(crate) fn helper_lookup<F:FnMut(Checkpoint,&Facts)->Admission>(context:&Context,admission:&mut F)->NativeResult<WrappingKeyCandidate> {
    let returned=run_using(Operation::Lookup,admission,CleanupAdmission::from_helper_control(),
        |frame,admission,bridge,cleanup,cleanup_bridge,out|{
            unsafe{mrk_wrapping_run(frame,2,context.vault.as_ptr(),context.generation.as_ptr(),std::ptr::null(),
                admission,bridge,cleanup,cleanup_bridge,out);}true
        });
    finish_lookup(returned)
}
