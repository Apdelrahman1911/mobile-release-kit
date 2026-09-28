//! Fixed, nonshipping qualification dispatcher, NOT a worker, owner or permit.
//!
//! Run only inside the existing OriginalWork/native-child ownership path with
//! its original cutoff and precharged frame. This leaf starts no clock/thread,
//! provisions nothing, changes no fixture, and performs no teardown or retry.
//! The independent execution packet must bind this exact14-call roster, the
//! native binary, owner, fixture provisioning and every external setup/action.
//!
//! The roster is a bounded common-logic cohort, not a complete qualification
//! claim. Unforced failed-close/exception/ACL-incomplete behavior, optional
//! second-executable creator negatives, before-item STOP and remaining native
//! bound observations remain OWED unless separately evidenced. Unavailable or
//! unexecuted obligations are never passes, and the16-call bound is not an
//! extension grant. Any successor roster requires review before execution.
//!
//! Source labels deliberately separate production-selector, helper-shape and
//! synthetic-provider evidence. No case qualifies login-Keychain mutation or
//! atomic provider-to-FD identity. No fault model is installed here.
//!
//! STOP and post-item changes come only from separately admitted ORIGINAL-owner
//! actions with retained real returns. The admission closure is not permission
//! to hide a fixture mutation. An Unknown/panic/unsettled return latches halt;
//! the caller retains the entire CaseReturn and original custody. Never infer
//! fixture retirement from Drop, this dispatcher, a timeout or process exit.

use super::{
    Admission, AddEffect, Checkpoint, Context, Custody, Facts, NativeAdmission, NativeResult,
    Operation, Outcome, RawResult, Returned, WrappingKeyCandidate, KEY_BYTES,
    Frame, KNOWN, KEY_WIPED, USER_ADMITTED, finish_lookup, finish_without_key, run_using,
};
use std::any::Any;
use std::cell::Cell;
use std::ffi::c_void;
use std::marker::PhantomData;
use std::mem::size_of;
use std::panic::{catch_unwind, AssertUnwindSafe};

pub const MAX_ADAPTER_INVOCATIONS: usize = 16;
pub const HELPER_SHAPE_CHECKS: u32 = 20;
pub const HELPER_CF_ORIGINALS: u32 = 12;
const SELECTOR: u32 = 1;
const FIXTURE: u32 = 2;
const HELPERS: u32 = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvidenceKind { ProductionSelectorOnly, HelperShapeOnly, SyntheticProviderOnly }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Case {
    Selector, HelperShapes, AddBaseline, LookupBaseline, DuplicateBaseline, MissingOther,
    DenyDeleteAndReadonlyAllow, ForeignUserMutationAllow, ForeignGroupInheritOnlyMutationAllow,
    PosixForeignWrite, SymlinkLeaf, PostAddNamespaceRefusal, LockedPrivateFixture, StopAfterAdd,
}
pub const CALL_ROSTER: [Case; 14] = [
    Case::Selector, Case::HelperShapes, Case::AddBaseline, Case::LookupBaseline,
    Case::DuplicateBaseline, Case::MissingOther, Case::DenyDeleteAndReadonlyAllow,
    Case::ForeignUserMutationAllow, Case::ForeignGroupInheritOnlyMutationAllow,
    Case::PosixForeignWrite, Case::SymlinkLeaf, Case::PostAddNamespaceRefusal,
    Case::LockedPrivateFixture, Case::StopAfterAdd,
];
const _: () = assert!(CALL_ROSTER.len() <= MAX_ADAPTER_INVOCATIONS);
impl Case {
    pub fn evidence(self) -> EvidenceKind {
        match self { Self::Selector => EvidenceKind::ProductionSelectorOnly,
            Self::HelperShapes => EvidenceKind::HelperShapeOnly, _ => EvidenceKind::SyntheticProviderOnly }
    }
    pub fn operation(self) -> Operation {
        match self { Self::AddBaseline | Self::DuplicateBaseline | Self::PostAddNamespaceRefusal | Self::StopAfterAdd =>
            Operation::AddOnly, _ => Operation::Lookup }
    }
    fn mode(self) -> u32 { match self { Self::Selector => SELECTOR, Self::HelperShapes => HELPERS, _ => FIXTURE } }
    fn context_index(self) -> usize {
        match self { Self::MissingOther => 1, Self::PostAddNamespaceRefusal => 2, Self::StopAfterAdd => 3, _ => 0 }
    }
}

/// Actual retained root identity from the existing fixture owner, never a path
/// selector or a claim made by this harness. dev_t is encoded as its public
/// uint32 bit representation; mode includes S_IFDIR and must be exactly0700.
pub struct OwnerFixturePin {
    pub device: u64, pub inode: u64, pub mode: u32, pub uid: u32, pub gid: u32,
}
#[repr(C)]
struct FixtureInput {
    version: u32, bytes: u32,
    root_device: u64, root_inode: u64,
    root_mode: u32, root_uid: u32, root_gid: u32, reserved: u32,
    token: [u8; 16],
}
const _: () = assert!(size_of::<FixtureInput>() == 56);
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Observation {
    version: u32, mode: u32, configured: u32, run_returned: u32,
    account_selected: u32, fixture_selected: u32, root_identity_matched: u32, selector_boundary_returned: u32,
    callbacks_cleared: u32, helpers_entered: u32, helpers_returned: u32, helper_matches: u32,
}
const _: () = assert!(size_of::<Observation>() == 48);
impl Observation {
    fn valid(&self, raw: &RawResult, mode: u32) -> bool {
        if self.version != 1 || self.mode != mode || self.configured != 1
            || self.run_returned != 1 || raw.run_returned != 1 || raw.phase != 16 || self.callbacks_cleared != 1
            || self.account_selected > 1 || self.fixture_selected > self.account_selected
            || self.root_identity_matched > self.fixture_selected || self.selector_boundary_returned > self.account_selected
            || self.helpers_entered > HELPER_SHAPE_CHECKS || self.helpers_returned > self.helpers_entered
            || self.helpers_entered - self.helpers_returned > 1
            || self.helper_matches & !((1u32 << self.helpers_returned) - 1) != 0 { return false; }
        if mode != HELPERS && (self.helpers_entered != 0 || self.helpers_returned != 0 || self.helper_matches != 0) {
            return false;
        }
        if mode == FIXTURE {
            return self.selector_boundary_returned == 0 && raw.valid(true);
        }
        // Both readonly selector and helper-shape routes stop above filesystem
        // admission. Helpers may own CF values, but neither may open/search a
        // Keychain, acquire a descriptor/ACL, call membership or deliver a key.
        if self.fixture_selected != 0 || self.root_identity_matched != 0
            || raw.call_count != 0 || raw.directory_count != 0 || raw.descriptor_count != 0
            || raw.namespace_entered != 0 || raw.native.entered != 0 || raw.acl.snapshots_entered != 0
            || raw.key_bytes != 0 || raw.effect != 0 { return false; }
        if mode == HELPERS {
            return self.selector_boundary_returned == 0 && raw.valid(true);
        }
        if mode != SELECTOR || raw.slot_count != 0 { return false; }
        if raw.outcome != 0 { return raw.valid(true); } // Actual refused/stopped/unknown facts, not probe success.
        raw.valid(false) && self.selector_boundary_returned == 1 && self.account_selected == 1
            && raw.flags == (KNOWN | KEY_WIPED | USER_ADMITTED) && raw.failure_phase == 0 && raw.account_errno == 0
    }
    fn complete_helpers(&self) -> bool {
        self.helpers_entered == HELPER_SHAPE_CHECKS && self.helpers_returned == HELPER_SHAPE_CHECKS
            && self.helper_matches == (1u32 << HELPER_SHAPE_CHECKS) - 1
    }
}

unsafe extern "C" {
    fn mrk_wrapping_qualification_abi() -> u32;
    fn mrk_wrapping_qualification_run(frame: *mut c_void, mode: u32, fixture: *const FixtureInput,
        operation: u32, vault: *const u8, generation: *const u8, key: *const u8,
        admission: NativeAdmission, bridge: *mut c_void, raw: *mut RawResult, observation: *mut Observation);
}

/// Scalar, nonsecret extra observations. A true root match is just an observed
/// identity comparison; only the original Facts establish full ACL/namespace
/// checks. No path, principal UUID, password, key or panic payload is exposed.
pub struct SelectionFacts { raw: Observation, verified: bool }
impl SelectionFacts {
    pub fn verified(&self) -> bool { self.verified }
    pub fn account_selected(&self) -> bool { self.verified && self.raw.account_selected == 1 }
    pub fn fixture_selected(&self) -> bool { self.verified && self.raw.fixture_selected == 1 }
    pub fn root_identity_matched(&self) -> bool { self.verified && self.raw.root_identity_matched == 1 }
    pub fn selector_boundary_returned(&self) -> bool { self.verified && self.raw.selector_boundary_returned == 1 }
    pub fn callbacks_cleared(&self) -> bool { self.verified && self.raw.callbacks_cleared == 1 }
    pub fn helper_counts(&self) -> Option<(u32, u32, u32)> {
        self.verified.then_some((self.raw.helpers_entered, self.raw.helpers_returned, self.raw.helper_matches.count_ones()))
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refused {
    InvalidBinding, NativeAbiMismatch, WrongCaseOrInput, PendingOriginal, Halted,
    NoCandidate, ConsumptionAlreadySpent, ConsumptionUncertain, ChargeMismatch, NotSettled,
}
enum Original {
    Data(NativeResult<()>), Add(NativeResult<()>), Lookup(NativeResult<WrappingKeyCandidate>),
}
impl Original {
    fn facts(&self) -> &Facts {
        match self { Self::Data(r) | Self::Add(r) => r.facts(), Self::Lookup(r) => r.facts() }
    }
    fn native_bytes(&self) -> usize {
        match self { Self::Data(r) | Self::Add(r) => r.retained_native_frame_bytes(),
            Self::Lookup(r) => r.retained_native_frame_bytes() }
    }
}
#[derive(Clone, Copy, Debug)]
pub struct Comparison {
    pub callback_returned: bool, pub bytes_equal: bool,
    pub whole_frame_charge_transferred: bool, pub native_frame_bytes: usize,
    pub consume_returned_and_frame_retired: bool,
}

/// Retain this entire original under the existing owner through actual joins.
/// This wrapper reports adapter facts only; it never deletes a fixture or
/// returns a permit to another work item. No Clone/Debug/serialization exists.
pub struct CaseReturn {
    original: Original,
    case: Case,
    token: [u8; 16],
    selection: SelectionFacts,
    comparison: Option<Comparison>,
    consumption_started: bool,
    unresolved_consumption_charge: usize,
    consumption_retained: Option<Frame>,
    // Last: an opaque Rust panic destructor cannot run before original custody.
    consumption_panic: Option<Box<dyn Any + Send>>,
}
impl CaseReturn {
    pub fn case(&self) -> Case { self.case }
    pub fn evidence(&self) -> EvidenceKind { self.case.evidence() }
    pub fn facts(&self) -> &Facts { self.original.facts() }
    pub fn selection(&self) -> &SelectionFacts { &self.selection }
    pub fn comparison(&self) -> Option<Comparison> { self.comparison }
    pub fn retained_native_frame_bytes(&self) -> usize {
        self.original.native_bytes() + self.unresolved_consumption_charge
            + self.consumption_retained.as_ref().map_or(0, |frame| frame.bytes)
    }
    pub fn adapter_retained_bytes(&self) -> usize { size_of::<Self>() + self.retained_native_frame_bytes() }
    /// Scoped only to this case's actual data/selector or successful add value.
    /// This is never a claim that the roster, provider or product is qualified.
    pub fn scoped_value_present(&self) -> bool {
        match &self.original { Original::Data(r) | Original::Add(r) => r.value.is_some(),
            Original::Lookup(r) => r.value.is_some() }
    }
    /// # Safety
    /// The original owner must freshly admit THIS consumption under its original
    /// cutoff and retain the complete frame charge through return. expected is
    /// its charged, generated disposable32-byte key, not a real credential.
    /// This method neither grants admission nor refunds caller/OS allocations.
    pub unsafe fn compare_candidate(&mut self, expected: &[u8; KEY_BYTES]) -> Result<Comparison, Refused> {
        if self.consumption_started { return Err(Refused::ConsumptionAlreadySpent); }
        let Original::Lookup(result) = &mut self.original else { return Err(Refused::NoCandidate); };
        let bytes = result.retained_native_frame_bytes();
        let Some(mut candidate) = result.take_value() else { return Err(Refused::NoCandidate); };
        self.consumption_started = true;
        self.unresolved_consumption_charge = bytes; // Charge transfers BEFORE synchronous consumption.
        let transferred = bytes != 0 && result.retained_native_frame_bytes() == 0
            && candidate.retained_bytes() == size_of::<WrappingKeyCandidate>() + bytes;
        if !transferred {
            // Never drop/refund a frame after a malformed charge transfer.
            candidate.frame.retain_unknown();
            self.consumption_retained = Some(candidate.frame);
            self.unresolved_consumption_charge = 0; // Same original frame, now explicitly retained here.
            return Err(Refused::ChargeMismatch);
        }
        let mut callback_returned = false;
        let actual = catch_unwind(AssertUnwindSafe(|| candidate.consume(|value| {
            let equal = value == expected; // Synthetic comparison stays private.
            callback_returned = true;
            equal
        })));
        match actual {
            Ok(bytes_equal) => {
                // The shared candidate primitive returns only AFTER its actual
                // consume return, wipe and original frame retirement; no copied
                // implementation or Drop-based settlement is substituted here.
                let observation = Comparison { callback_returned, bytes_equal,
                    whole_frame_charge_transferred: transferred, native_frame_bytes: bytes,
                    consume_returned_and_frame_retired: true };
                self.unresolved_consumption_charge = 0;
                self.comparison = Some(observation);
                Ok(observation)
            }
            Err(payload) => {
                // Keep even an overconservative full charge on uncertainty.
                // The private panic is retained, not printed or retried.
                self.consumption_panic = Some(payload);
                Err(Refused::ConsumptionUncertain)
            }
        }
    }
}

pub struct Harness {
    token: [u8; 16],
    contexts: [Context; 4],
    fixture: Option<FixtureInput>,
    next: usize,
    pending: Option<Case>,
    halted: bool,
    _not_sync: PhantomData<Cell<()>>,
}
impl Harness {
    /// # Safety
    /// One instance only for this independently reviewed original-owner cohort.
    /// token is nonzero, generated and unique to the one task-owned fixture.
    /// contexts are distinct owner-reserved identities in order baseline,
    /// missing (never added), post-add refusal and terminal STOP. Creating a new
    /// instance is not a retry/extra budget, fresh cutoff or execution grant.
    pub unsafe fn new(token: [u8; 16], contexts: [Context; 4]) -> Result<Self, Refused> {
        if token == [0; 16] { return Err(Refused::InvalidBinding); }
        for left in 0..contexts.len() {
            for right in 0..left {
                if contexts[left].vault == contexts[right].vault && contexts[left].generation == contexts[right].generation {
                    return Err(Refused::InvalidBinding);
                }
            }
        }
        // SAFETY: a linked constant ABI marker only; no allocation/provider call.
        if unsafe { mrk_wrapping_qualification_abi() } != 0x514b0101 { return Err(Refused::NativeAbiMismatch); }
        Ok(Self { token, contexts, fixture: None, next: 0, pending: None, halted: false, _not_sync: PhantomData })
    }
    /// # Safety
    /// Provisioning has separate prior approval and ACTUAL known completion.
    /// The original owner holds the exact0700/current-native-user root named
    /// native_home/Library/Keychains/mrk-wrapping-qualification-<token32hex>,
    /// with fixed synthetic.keychain-db. It retains that namespace original
    /// and its pin through operations and actual admitted retirement.
    /// No ordinary user's default/login/search list may have been modified.
    pub unsafe fn bind_fixture(&mut self, pin: OwnerFixturePin) -> Result<(), Refused> {
        if self.halted { return Err(Refused::Halted); }
        if self.pending.is_some() || self.next != 2 || self.fixture.is_some() { return Err(Refused::WrongCaseOrInput); }
        if pin.device > u32::MAX as u64 || pin.inode == 0 || pin.uid == 0 || pin.mode != 0o040700 {
            return Err(Refused::InvalidBinding);
        }
        self.fixture = Some(FixtureInput { version: 1, bytes: size_of::<FixtureInput>() as u32,
            root_device: pin.device, root_inode: pin.inode, root_mode: pin.mode,
            root_uid: pin.uid, root_gid: pin.gid, reserved: 0, token: self.token });
        Ok(())
    }
    pub fn invocations_started(&self) -> usize { self.next }
    pub fn halted(&self) -> bool { self.halted }

    /// # Safety
    /// Each invocation is separately admitted/registered by the EXISTING owner,
    /// which reserves the full native frame and generated key charge and uses
    /// the ORIGINAL cutoff. Actual fixture setup, post-item mutation and STOP
    /// actions have distinct reviewed admissions/real returns retained by that
    /// owner. This method injects none of them and does not authorize them.
    pub unsafe fn run_next<F: FnMut(Checkpoint, &Facts) -> Admission>(
        &mut self, case: Case, key: Option<&[u8; KEY_BYTES]>, admission: &mut F,
    ) -> Result<CaseReturn, Refused> {
        if self.halted { return Err(Refused::Halted); }
        if self.pending.is_some() { return Err(Refused::PendingOriginal); }
        if self.next >= CALL_ROSTER.len() || self.next >= MAX_ADAPTER_INVOCATIONS || CALL_ROSTER[self.next] != case
            || (case.operation() == Operation::AddOnly) != key.is_some()
            || (case.mode() == FIXTURE && self.fixture.is_none()) { return Err(Refused::WrongCaseOrInput); }
        self.next += 1; self.pending = Some(case); // Spend this fixed call before native entry.
        let mut observation = Observation::default();
        let operation = case.operation();
        let context = &self.contexts[case.context_index()];
        let fixture = if case.mode() == FIXTURE {
            self.fixture.as_ref().map_or(std::ptr::null(), |pin| pin as *const FixtureInput)
        } else { std::ptr::null() };
        let returned: Returned = run_using(operation, admission, |frame, callback, bridge, raw| {
            // SAFETY: one exact-sized frame/input/bridge/output; the binding and
            // borrows remain live through the ENTIRE synchronous common entry.
            unsafe {
                mrk_wrapping_qualification_run(frame, case.mode(), fixture, operation.raw(),
                    context.vault.as_ptr(), context.generation.as_ptr(), key.map_or(std::ptr::null(), |key| key.as_ptr()),
                    callback, bridge, raw, &mut observation);
            }
            observation.valid(raw, case.mode())
        });
        let mut selection = SelectionFacts { raw: observation, verified: returned.facts.verified && returned.facts.ffi_returned };
        let original = match case {
            Case::Selector | Case::HelperShapes => {
                let complete = returned.facts.verified && returned.facts.ffi_returned
                    && returned.facts.custody() == Custody::Settled && !returned.facts.stopped()
                    && !returned.facts.callback_panicked()
                    && if case == Case::Selector {
                        observation.selector_boundary_returned == 1 && returned.facts.outcome() == Outcome::Pending
                    } else {
                        observation.complete_helpers() && returned.facts.raw.slot_count == HELPER_CF_ORIGINALS
                            && returned.facts.outcome() == Outcome::InvalidResult
                    };
                Original::Data(finish_without_key(returned, complete.then_some(())))
            }
            _ if operation == Operation::AddOnly => {
                let value = returned.facts.accepted(Outcome::Added).then_some(());
                Original::Add(finish_without_key(returned, value))
            }
            _ => Original::Lookup(finish_lookup(returned)),
        };
        selection.verified &= original.facts().verified_native_run_receipt();
        if !original.facts().native_run_returned() || !original.facts().verified_native_run_receipt()
            || original.facts().custody() != Custody::Settled || original.facts().stopped() || original.facts().callback_panicked() {
            self.halted = true;
        }
        Ok(CaseReturn { original, case, token: self.token, selection, comparison: None,
            consumption_started: false, unresolved_consumption_charge: 0, consumption_retained: None, consumption_panic: None })
    }

    /// # Safety
    /// The actual original worker/coordinator joins and next-work admission are
    /// the caller's existing owner obligations. This verifies only positively
    /// settled adapter custody/no outstanding candidate, NOT those joins or
    /// permission to alter/retire the fixture. Keep the returned original.
    pub unsafe fn acknowledge_adapter_return(&mut self, actual: &CaseReturn) -> Result<(), Refused> {
        if self.pending != Some(actual.case) || actual.token != self.token { return Err(Refused::WrongCaseOrInput); }
        if self.halted { return Err(Refused::Halted); }
        if !actual.facts().native_run_returned() || !actual.facts().verified_native_run_receipt()
            || actual.facts().custody() != Custody::Settled || actual.facts().stopped()
            || actual.facts().callback_panicked() || actual.consumption_panic.is_some()
            || actual.retained_native_frame_bytes() != 0
            || !(actual.facts().adapter_frame_retired()
                || actual.comparison.is_some_and(|r| r.consume_returned_and_frame_retired)) {
            self.halted = true; return Err(Refused::NotSettled);
        }
        self.pending = None;
        Ok(())
    }
}

/// These are expectations for independent result review, never substituted
/// actual facts. Added/MayHaveAdded after a refused postcheck or STOP must remain
/// visible even when the case has no successful value and the cohort halts.
pub fn expected_terminal_add_effect(case: Case) -> Option<AddEffect> {
    match case { Case::PostAddNamespaceRefusal | Case::StopAfterAdd => Some(AddEffect::Added), _ => None }
}
