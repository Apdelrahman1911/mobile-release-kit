//! One fixed native-test fixture/caller, compiled only by the checked K1 cfg.
//!
//! No worker, reusable executor, user pathname or ambient runtime enable switch.
//! The test's original entry establishes ONE cutoff before allocation/selection;
//! every adapter case, separately registered mutation and cleanup uses that same
//! cutoff. The existing Aqua run_owned remains the longer enclosing owner.
//! A provisional native report alone never supplies that process's finality.
//!
//! The fixed17 fixture actions surround the unchanged14-case K1 roster. Every
//! actual return remains in the original caller, including failure/panic. No
//! automatic Drop cleanup, renewed clock, retry or uncertain-fixture deletion.
//! Two fixed variants change only the last case; each has its own original
//! invocation and never shares/restarts a stopped Harness.
//! Caller-owned frame/material charges exclude unbounded SDK-internal allocator
//! capacity and opaque panic allocations, which are retained as unknown on error.

use super::{
    qualification::{Case, CaseReturn, Harness, OwnerFixturePin, PeerLookup, Refused, CALL_ROSTER},
    private_pair::{self, ControlBook},
    native_frame_bytes, AddEffect, Admission, Checkpoint, Context, Custody, Facts, Operation,
    Outcome, RawResult, ReferenceObservation, KEY_BYTES, KNOWN, UNKNOWN,
};
use std::{
    any::Any, ffi::c_void, fmt::{self, Write as FmtWrite},
    io::{self, Write as IoWrite}, marker::PhantomData, cell::{Cell, RefCell},
    mem::{size_of, ManuallyDrop}, panic::{catch_unwind, AssertUnwindSafe},
    ptr::NonNull, sync::atomic::{compiler_fence, AtomicBool, AtomicPtr, Ordering}, time::{Duration, Instant},
};

const ACTIONS: usize = 17;
const CALLS: usize = 1024;
const REFS: usize = 10;
const SELECTIONS: usize = 4;
const MEMBERS: u32 = 64;
const NATIVE_RESULT_BYTES: usize = 29384;
const FIXTURE_FRAME_LIMIT: usize = 196608;
const PUBLIC_OUTPUT_LIMIT: usize = 128 * 1024;
const CALLER_OWNED_CHARGE_LIMIT: usize = 2 * 1024 * 1024;
const COHORT_SECONDS: u64 = 45; // The workflow's original run_owned uses90, never a per-case timeout.
const _: () = assert!(CALL_ROSTER.len() == 14);
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Action {
    Entropy = 1, Create, DenyRead, RestoreDeny, ForeignUser, RestoreUser,
    ForeignGroup, RestoreGroup, Posix, RestorePosix, Symlink, RestoreSymlink,
    PostAdd, RestorePostAdd, Lock, Unlock, Retire,
}
impl Action { fn raw(self) -> u32 { self as u32 } }

#[repr(C)]
#[derive(Clone, Copy, Default, PartialEq, Eq)]
struct Call { kind: u32, entered: u32, returned: u32, actual_errno: i32, result: i64 }
#[repr(C)]
#[derive(Clone, Copy, Default, PartialEq, Eq)]
struct ActionObservation { kind: u32, entered: u32, returned: u32, completed: u32, first_call: u32, end_call: u32 }
#[repr(C)]
#[derive(Clone, Copy, Default, PartialEq, Eq)]
struct Selection {
    entered: u32, returned: u32, search_typed: u32, default_kind: u32, count: u32,
    members_entered: u32, members_returned: u32, members_typed: u32,
    paths_entered: u32, paths_returned: u32, identities_admitted: u32,
    comparisons_entered: u32, comparisons_returned: u32, unchanged: u32, fixture_absent: u32,
}
#[repr(C)]
#[derive(Clone, Copy)]
struct RawFixture {
    version: u32, bytes: u32, action_count: u32, call_count: u32, ref_count: u32,
    failed: u32, unknown: u32, stopped: u32, exception: u32, callbacks_cleared: u32,
    material_generated: u32, root_created: u32, root_removed: u32, create_effect: u32,
    provider_deleted: u32, sync_entered: u32, sync_returned: u32, sync_absent_empty: u32, finalized: u32, reserved: u32,
    actions: [ActionObservation; ACTIONS],
    calls: [Call; CALLS],
    references: [ReferenceObservation; REFS],
    selections: [Selection; SELECTIONS],
    namespace: RawResult,
}
const _: () = assert!(size_of::<Call>() == 24 && size_of::<ActionObservation>() == 24 && size_of::<Selection>() == 60);
const _: () = assert!(size_of::<RawFixture>() == NATIVE_RESULT_BYTES);
impl RawFixture {
    fn empty() -> Self {
        Self {
            version: 0, bytes: 0, action_count: 0, call_count: 0, ref_count: 0,
            failed: 0, unknown: 0, stopped: 0, exception: 0, callbacks_cleared: 0,
            material_generated: 0, root_created: 0, root_removed: 0, create_effect: 0,
            provider_deleted: 0, sync_entered: 0, sync_returned: 0, sync_absent_empty: 0, finalized: 0, reserved: 0,
            actions: [ActionObservation::default(); ACTIONS], calls: [Call::default(); CALLS],
            references: [ReferenceObservation::default(); REFS], selections: [Selection::default(); SELECTIONS],
            namespace: RawResult::empty(Operation::Lookup, 0),
        }
    }
    fn prefix_valid(&self) -> bool {
        self.version == 1 && self.bytes as usize == NATIVE_RESULT_BYTES && self.reserved == 0
            && (1..=ACTIONS as u32).contains(&self.action_count)
            && self.call_count as usize <= CALLS && self.ref_count as usize <= REFS
            && self.create_effect <= 2
            && [self.failed, self.unknown, self.stopped, self.exception, self.callbacks_cleared,
                self.material_generated, self.root_created, self.root_removed, self.provider_deleted,
                self.sync_entered, self.sync_returned, self.sync_absent_empty, self.finalized].iter().all(|v| *v <= 1)
            && self.sync_returned <= self.sync_entered && self.sync_absent_empty <= self.sync_returned
            && self.root_removed <= self.root_created && self.provider_deleted <= u32::from(self.create_effect == 1)
            && ((self.unknown | self.stopped | self.exception) == 0 || self.failed == 1)
            && self.namespace.valid(false)
    }
    fn valid(&self, final_return: bool) -> bool {
        if !self.prefix_valid() || final_return && self.callbacks_cleared != 1 { return false; }
        let mut previous_end = 0;
        for (i, row) in self.actions.iter().enumerate() {
            if i >= self.action_count as usize {
                if *row != ActionObservation::default() { return false; }
                continue;
            }
            if row.kind != i as u32 + 1 || row.entered != 1 || row.returned > 1 || row.completed > row.returned
                || row.first_call != previous_end
                || (row.returned == 0 && (row.end_call != 0 || i + 1 != self.action_count as usize))
                || (row.returned == 1 && !(row.first_call..=self.call_count).contains(&row.end_call))
                || (i + 1 < self.action_count as usize && row.completed != 1)
                || final_return && row.returned != 1 { return false; }
            if row.returned == 1 { previous_end = row.end_call; }
        }
        if final_return && previous_end != self.call_count { return false; }
        for (i, row) in self.calls.iter().enumerate() {
            if i >= self.call_count as usize {
                if *row != Call::default() { return false; }
            } else if !(1..=47).contains(&row.kind) || row.entered != 1 || row.returned > 1
                || row.returned == 0 && (row.result != 0 || row.actual_errno != 0 || i + 1 != self.call_count as usize)
                || final_return && self.unknown == 0 && row.returned != 1 { return false; }
        }
        for (i, row) in self.references.iter().enumerate() {
            if i >= self.ref_count as usize {
                if *row != ReferenceObservation::default() { return false; }
            } else if row.reserved != 1 || row.call_entered > 1 || row.call_returned > row.call_entered
                || row.nonnull_returned > row.call_returned || row.release_entered > row.nonnull_returned
                || row.release_returned > row.release_entered { return false; }
        }
        for row in &self.selections {
            if row.entered > 1 || row.returned > row.entered || row.search_typed > row.entered || row.default_kind > 2
                || row.count > MEMBERS || row.members_entered > row.count
                || row.members_returned > row.members_entered || row.members_entered - row.members_returned > 1
                || row.members_typed > row.members_returned || row.paths_entered > row.count + 1
                || row.paths_returned > row.paths_entered || row.paths_entered - row.paths_returned > 1
                || row.identities_admitted > row.paths_returned || row.comparisons_entered > MEMBERS + 1
                || row.comparisons_returned > row.comparisons_entered || row.comparisons_entered - row.comparisons_returned > 1
                || row.unchanged > row.returned || row.fixture_absent > row.returned { return false; }
            if row.returned == 1 && (row.search_typed != 1 || row.default_kind == 0 || row.fixture_absent != 1
                || row.members_entered != row.count || row.members_returned != row.count || row.members_typed != row.count
                || row.paths_entered != row.count + u32::from(row.default_kind == 2)
                || row.paths_returned != row.paths_entered || row.identities_admitted != row.paths_entered) { return false; }
        }
        if self.finalized != 0 {
            if self.failed != 0 || self.unknown != 0 || self.stopped != 0 || self.exception != 0
                || self.action_count as usize != ACTIONS || self.material_generated != 1
                || self.root_created != 1 || self.root_removed != 1 || self.create_effect != 1 || self.provider_deleted != 1
                || self.sync_entered != 1 || self.sync_returned != 1 || self.sync_absent_empty != 1
                || self.ref_count as usize != REFS || self.namespace.flags & (KNOWN | UNKNOWN) != KNOWN
                || self.actions.iter().any(|row| row.completed != 1)
                || self.references.iter().any(|row| row.call_entered != row.call_returned
                    || row.nonnull_returned != row.release_returned || row.release_entered != row.release_returned)
                || self.selections.iter().any(|row| row.returned != 1 || row.fixture_absent != 1)
                || self.selections[1..].iter().any(|row| row.unchanged != 1) { return false; }
        }
        true
    }
    fn extends(&self, before: &Self) -> bool {
        if !before.valid(true) || !self.valid(true) || before.failed != 0
            || self.action_count != before.action_count + 1 || self.call_count < before.call_count
            || self.ref_count < before.ref_count
            || self.actions[..before.action_count as usize] != before.actions[..before.action_count as usize]
            || self.calls[..before.call_count as usize] != before.calls[..before.call_count as usize]
            || self.namespace.native.entered < before.namespace.native.entered
            || self.namespace.acl.snapshots_entered < before.namespace.acl.snapshots_entered { return false; }
        for (now, old) in self.references.iter().zip(&before.references).take(before.ref_count as usize) {
            if now.reserved != old.reserved || now.call_entered != old.call_entered
                || now.call_returned != old.call_returned || now.nonnull_returned != old.nonnull_returned
                || now.release_entered < old.release_entered || now.release_returned < old.release_returned { return false; }
        }
        for (now, old) in self.selections.iter().zip(&before.selections) {
            if old.entered != 0 && now != old { return false; }
        }
        true
    }
    fn all_fixture_effects_observed(&self) -> bool {
        if !self.valid(true) || self.finalized != 1 { return false; }
        let count = |kind, result| self.calls[..self.call_count as usize].iter()
            .filter(|row| row.kind == kind && row.returned == 1 && row.result == result).count();
        // This cohort must actually exercise all three absent-ACL restorations.
        // Present-ACL setters cannot stand in for the corrected Darwin route.
        if count(47, 0) != 3 || count(29, 0) != 3 || count(16, 0) != 6 || count(17, 0) != 6
            || count(28, 0) != 3 { return false; }
        // Actual fixed API entries/returns, not an assertion-derived fixture.
        if count(1, 0) != 4 || count(4, 0) != 1 || count(5, 0) != 4 || count(11, 0) != 1
            || count(13, 0) != 1 || count(14, 0) != 1 || count(15, 1) != 6 || count(20, 1) != 3
            || count(31, 0) != 6 || count(32, 0) != 4 || count(33, 0) != 2
            || count(34, 0) != 1 || count(37, 0) != 1 || count(38, 0) != 1
            || count(39, 0) != 1 || count(42, 0) != 1 || count(43, 0) != 1 { return false; }
        let mut default_calls = self.calls[..self.call_count as usize].iter().filter(|row| row.kind == 6);
        let slots = [(0usize, 1usize), (3, 4), (5, 6), (8, 9)];
        for (i, (search, default)) in slots.into_iter().enumerate() {
            let row = &self.selections[i];
            let Some(default_call) = default_calls.next() else { return false; };
            if self.references[search].nonnull_returned != 1
                || self.references[default].nonnull_returned != u32::from(row.default_kind == 2)
                || default_call.returned != 1
                || default_call.result != if row.default_kind == 2 { 0 } else { -25307 } { return false; }
        }
        let mut sync_calls = self.calls[..self.call_count as usize].iter().filter(|row| row.kind == 40);
        let Some(sync) = sync_calls.next() else { return false; };
        default_calls.next().is_none() && self.references[2].nonnull_returned == 1 && sync_calls.next().is_none()
            && sync.returned == 1 && sync.result == i64::from(self.references[7].nonnull_returned)
            && self.calls[..self.call_count as usize].iter().filter(|row| row.kind == 41).count()
                == self.references[7].nonnull_returned as usize
            && self.calls[..self.call_count as usize].iter().filter(|row| row.kind == 41)
                .all(|row| row.returned == 1 && row.result == 0)
    }
}
#[repr(C)]
#[derive(Default)]
struct Binding {
    version: u32, bytes: u32, root_device: u64, root_inode: u64,
    root_mode: u32, root_uid: u32, root_gid: u32, reserved: u32, token: [u8; 16],
}
const _: () = assert!(size_of::<Binding>() == 56);
type NativeAdmission = extern "C" fn(*mut c_void, *const RawFixture, u32) -> u32;
unsafe extern "C" {
    fn mrk_wrapping_fixture_frame_bytes() -> usize;
    fn mrk_wrapping_fixture_abi() -> u32;
    fn mrk_wrapping_fixture_new() -> *mut c_void;
    fn mrk_wrapping_fixture_run(frame: *mut c_void, action: u32, admission: NativeAdmission,
        context: *mut c_void, out: *mut RawFixture);
    fn mrk_wrapping_fixture_material(frame: *mut c_void, token: *mut u8, key: *mut u8, ids: *mut u8) -> u32;
    fn mrk_wrapping_fixture_binding(frame: *mut c_void, out: *mut Binding) -> u32;
    fn mrk_wrapping_fixture_free(frame: *mut c_void) -> u32;
}
struct Fixture {
    pointer: Option<NonNull<c_void>>, bytes: usize, next: u32, blocked: bool,
    allocation_entered: bool, allocation_returned: bool, allocation_nonnull: bool, free_spent: bool, free_returned: bool, free_result: u32,
    _not_sync: PhantomData<Cell<()>>,
}
// No Drop: even a known call/assertion/timeout is not fixture retirement.
impl Fixture {
    fn empty() -> Self {
        Self { pointer: None, bytes: 0, next: 1, blocked: false, allocation_entered: false, allocation_returned: false, allocation_nonnull: false,
            free_spent: false, free_returned: false, free_result: 0, _not_sync: PhantomData }
    }
    fn reserve(&mut self, charged_bytes: usize) -> bool {
        if self.pointer.is_some() || charged_bytes == 0 || charged_bytes > FIXTURE_FRAME_LIMIT { return false; }
        self.bytes = charged_bytes; self.allocation_entered = true;
        // SAFETY: one precharged fixed native allocation, no filesystem/provider call.
        self.pointer = NonNull::new(unsafe { mrk_wrapping_fixture_new() });
        self.allocation_returned = true; self.allocation_nonnull = self.pointer.is_some();
        self.pointer.is_some()
    }
    fn pointer(&self) -> *mut c_void { self.pointer.map_or(std::ptr::null_mut(), NonNull::as_ptr) }
    fn run<F: FnMut(Checkpoint) -> Admission>(&mut self, action: Action, admission: &mut F) -> Option<FixtureReturn> {
        if self.pointer.is_none() || self.blocked || self.next != action.raw() || self.next > ACTIONS as u32 { return None; }
        self.next += 1; // Spend the fixed action before entry, never as a retry.
        let mut raw = RawFixture::empty();
        let mut bridge = Bridge { admission, action, panic: None, malformed: false };
        // SAFETY: unique retained native frame, stable bridge/output for the
        // entire synchronous call. Native clears both callback pointers on return.
        unsafe { mrk_wrapping_fixture_run(self.pointer(), action.raw(), fixture_admission::<F>,
            (&mut bridge as *mut Bridge<'_, F>).cast(), &mut raw); }
        let verified = raw.valid(true) && raw.action_count == action.raw() && !bridge.malformed;
        if !verified || bridge.panic.is_some() || raw.failed != 0 || raw.unknown != 0 || raw.stopped != 0 { self.blocked = true; }
        Some(FixtureReturn { raw, action, verified, ffi_returned: true, callback_panic: bridge.panic })
    }
    fn retire_allocation(&mut self) -> bool {
        if self.pointer.is_none() || self.blocked || self.free_spent || self.next != ACTIONS as u32 + 1 { return false; }
        self.free_spent = true;
        // SAFETY: all17 actual action returns were checked by the retained
        // original caller; native independently checks actual CF/ACL/FD retirement.
        let returned = unsafe { mrk_wrapping_fixture_free(self.pointer()) };
        self.free_result = returned; self.free_returned = true; // Keep the actual scalar before interpretation.
        if returned == 1 { self.pointer = None; true } else { self.blocked = true; false }
    }
}
struct FixtureReturn {
    raw: RawFixture, action: Action, verified: bool, ffi_returned: bool,
    callback_panic: Option<Box<dyn Any + Send>>,
}
impl FixtureReturn {
    fn completed(&self) -> bool {
        self.ffi_returned && self.verified && self.callback_panic.is_none() && self.raw.failed == 0
            && self.raw.unknown == 0 && self.raw.stopped == 0
            && self.raw.actions[self.action.raw() as usize - 1].completed == 1
    }
}
struct Bridge<'a, F> {
    admission: &'a mut F, action: Action, panic: Option<Box<dyn Any + Send>>, malformed: bool,
}
extern "C" fn fixture_admission<F: FnMut(Checkpoint) -> Admission>(
    context: *mut c_void, raw: *const RawFixture, checkpoint: u32,
) -> u32 {
    if context.is_null() || raw.is_null() { return Admission::Unknown.raw(); }
    // SAFETY: exact bridge/result borrows retained by Fixture::run; no concurrent access.
    let bridge = unsafe { &mut *context.cast::<Bridge<'_, F>>() };
    if bridge.panic.is_some() || bridge.malformed { return Admission::Unknown.raw(); }
    let returned = catch_unwind(AssertUnwindSafe(|| {
        let raw = unsafe { &*raw };
        let Some(checkpoint) = Checkpoint::from_raw(checkpoint) else {
            bridge.malformed = true; return Admission::Unknown;
        };
        if !raw.prefix_valid() || raw.action_count != bridge.action.raw() || raw.callbacks_cleared != 0 {
            bridge.malformed = true; return Admission::Unknown;
        }
        (bridge.admission)(checkpoint)
    }));
    match returned {
        Ok(admission) => admission.raw(),
        Err(payload) => { bridge.panic = Some(payload); Admission::Unknown.raw() }
    }
}

// One original clock, established by the test before all allocation or native
// work. Intentional terminal STOP revokes forward work. It is NOT cleanup
// permission: the fixed Retire action was registered before the cohort and is
// reachable only after separately proving every original adapter frame settled.
struct Clock {
    cutoff: Option<Instant>, stop_requested: bool, deadline_observed: bool, poisoned: bool,
    checks: u64, forward_admissions: u64, retirement_admissions: u64,
}
impl Clock {
    fn new(entry: Instant) -> Self {
        Self { cutoff: entry.checked_add(Duration::from_secs(COHORT_SECONDS)), stop_requested: false,
            deadline_observed: false, poisoned: false, checks: 0, forward_admissions: 0, retirement_admissions: 0 }
    }
    fn live(&mut self) -> bool {
        self.checks += 1;
        if self.cutoff.is_none_or(|cutoff| Instant::now() >= cutoff) { self.deadline_observed = true; }
        !self.poisoned && !self.deadline_observed
    }
    fn admit(&mut self, original_retirement: bool) -> Admission {
        if self.poisoned { return Admission::Unknown; }
        if !self.live() || self.stop_requested && !original_retirement { return Admission::Cutoff; }
        if original_retirement { self.retirement_admissions += 1; } else { self.forward_admissions += 1; }
        Admission::Continue
    }
    fn request_terminal_stop(&mut self) -> bool {
        if self.stop_requested || self.admit(false) != Admission::Continue { return false; }
        self.stop_requested = true;
        true // Actual one-way original-caller state transition, NOT an OSStatus.
    }
}
#[derive(Default)]
struct Material { token: [u8; 16], key: [u8; KEY_BYTES], ids: [[u8; 32]; 4] }
#[derive(Clone, Copy, Default)]
struct ScalarReturn { entered: bool, returned: bool, actual: u32 }
#[derive(Clone, Copy, Default)]
struct OriginalAction {
    registered: bool, entered: bool, returned: bool, completed: bool,
    checkpoint: u32, phase: u32, add_returned: bool, add_status: i32, add_effect: u32,
}
impl OriginalAction {
    fn observe_add(&mut self, checkpoint: Checkpoint, facts: &Facts) -> bool {
        if !self.registered || self.entered || checkpoint != Checkpoint::AfterCall || facts.phase() != Some(10)
            || facts.add_effect() != AddEffect::Added { return false; }
        let Some(calls) = facts.security_calls() else { return false; };
        let mut adds = calls.iter().filter(|call| call.phase == 10);
        let Some(add) = adds.next() else { return false; };
        if adds.next().is_some() || add.entered != 1 || add.returned != 1 || add.status != 0 { return false; }
        self.entered = true; self.checkpoint = 1; self.phase = 10;
        self.add_returned = true; self.add_status = add.status; self.add_effect = 1;
        true
    }
    fn observe_before_item(&mut self, checkpoint: Checkpoint, facts: &Facts, phase: u32) -> bool {
        if !self.registered || self.entered || checkpoint != Checkpoint::BeforeCall
            || !matches!(phase, 10 | 11) || facts.phase() != Some(phase)
            || facts.add_effect() != AddEffect::NotEntered || !no_item_call(facts) { return false; }
        // Real callback observations. No item was entered or returned; zero is
        // the NotEntered effect, not an invented successful OSStatus.
        self.entered = true; self.checkpoint = 0; self.phase = phase;
        self.add_returned = false; self.add_status = 0; self.add_effect = 0;
        true
    }
    fn complete_for(&self, case: Case) -> bool {
        if let Some(phase) = case.before_item_phase() {
            self.registered && self.entered && self.returned && self.completed
                && self.checkpoint == 0 && self.phase == phase
                && !self.add_returned && self.add_status == 0 && self.add_effect == 0
        } else { case == Case::StopAfterAdd && self.complete() }
    }
    fn complete(&self) -> bool {
        self.registered && self.entered && self.returned && self.completed
            && self.checkpoint == 1 && self.phase == 10 && self.add_returned && self.add_status == 0 && self.add_effect == 1
    }
}
fn fixture_action(fixture: &mut Fixture, originals: &mut Vec<FixtureReturn>, clock: &mut Clock,
    action: Action, original_retirement: bool) -> bool {
    if originals.len() + 1 != action.raw() as usize || originals.len() >= ACTIONS
        || originals.capacity() < ACTIONS || clock.admit(original_retirement) != Admission::Continue { return false; }
    let mut admission = |_checkpoint| clock.admit(original_retirement);
    let Some(actual) = fixture.run(action, &mut admission) else { return false; };
    originals.push(actual); // Original retained BEFORE checking its contents.
    originals.last().is_some_and(FixtureReturn::completed)
        && (originals.len() == 1 || originals[originals.len() - 1].raw.extends(&originals[originals.len() - 2].raw))
        && clock.live()
}
fn item_call(facts: &Facts, phase: u32, status: i32) -> bool {
    facts.security_calls().is_some_and(|calls| {
        let mut matches = calls.iter().filter(|row| row.phase == phase);
        matches.next().is_some_and(|row| row.entered == 1 && row.returned == 1 && row.status == status)
            && matches.next().is_none()
    })
}
fn no_item_call(facts: &Facts) -> bool {
    facts.security_calls().is_some_and(|calls| calls.iter().all(|row| !matches!(row.phase, 10 | 11)))
}
fn expected_case(actual: &CaseReturn) -> bool {
    let facts = actual.facts(); let selection = actual.selection();
    if !facts.native_run_returned() || !facts.verified_native_run_receipt() || facts.custody() != Custody::Settled
        || facts.callback_panicked() || facts.native_exception() || !facts.ordinary_user_admitted()
        || !selection.verified() || !selection.account_selected() || !selection.callbacks_cleared() { return false; }
    let case = actual.case();
    if !case.terminal_stop() && facts.stopped() { return false; }
    if !matches!(case, Case::Selector | Case::HelperShapes) && !selection.fixture_selected() { return false; }
    match case {
        Case::Selector => facts.outcome() == Outcome::Pending && selection.selector_boundary_returned()
            && !selection.fixture_selected() && no_item_call(facts) && actual.scoped_value_present(),
        Case::HelperShapes => facts.outcome() == Outcome::InvalidResult && actual.scoped_value_present()
            && selection.helper_counts() == Some((20, 20, 20)) && no_item_call(facts)
            && facts.references().is_some_and(|rows| rows.len() == 12 && rows.iter().all(|row|
                row.reserved == 1 && row.call_entered == 1 && row.call_returned == 1
                    && row.nonnull_returned == 1 && row.release_entered == 1 && row.release_returned == 1)),
        Case::AddBaseline => facts.outcome() == Outcome::Added && facts.add_effect() == AddEffect::Added
            && actual.scoped_value_present() && facts.original_item_verified() && facts.namespace_verified()
            && selection.root_identity_matched() && item_call(facts, 10, 0),
        Case::LookupBaseline | Case::DenyDeleteAndReadonlyAllow =>
            facts.outcome() == Outcome::Candidate && facts.add_effect() == AddEffect::NotEntered
                && actual.scoped_value_present() && facts.original_item_verified() && facts.namespace_verified()
                && selection.root_identity_matched() && item_call(facts, 11, 0),
        Case::DuplicateBaseline => facts.outcome() == Outcome::Duplicate && facts.add_effect() == AddEffect::Duplicate
            && !actual.scoped_value_present() && item_call(facts, 10, -25299) && selection.root_identity_matched(),
        Case::MissingOther => facts.outcome() == Outcome::Missing && facts.add_effect() == AddEffect::NotEntered
            && !actual.scoped_value_present() && item_call(facts, 11, -25300) && selection.root_identity_matched(),
        Case::ForeignUserMutationAllow | Case::ForeignGroupInheritOnlyMutationAllow =>
            facts.outcome() == Outcome::Unsupported && facts.add_effect() == AddEffect::NotEntered
                && !actual.scoped_value_present() && no_item_call(facts) && selection.root_identity_matched()
                && facts.first_refusal_phase() == Some(19)
                && facts.acl_observation().is_some_and(|acl| acl.snapshots_entered > acl.snapshots_admitted
                    && acl.snapshots_entered == acl.snapshots_returned && acl.entries > 0),
        Case::PosixForeignWrite | Case::SymlinkLeaf =>
            facts.outcome() == Outcome::Unsupported && facts.add_effect() == AddEffect::NotEntered
                && !actual.scoped_value_present() && no_item_call(facts) && facts.first_refusal_phase() == Some(18),
        Case::PostAddNamespaceRefusal => facts.outcome() == Outcome::Unsupported && facts.add_effect() == AddEffect::Added
            && !actual.scoped_value_present() && item_call(facts, 10, 0)
            && facts.namespace_checkpoints_passed() == Some(3) && facts.first_refusal_phase() == Some(18),
        Case::LockedPrivateFixture => facts.outcome() == Outcome::Locked && facts.add_effect() == AddEffect::NotEntered
            && !actual.scoped_value_present() && no_item_call(facts)
            && facts.observed_keychain_status().is_some_and(|status| status & 1 == 0),
        Case::StopAfterAdd => facts.outcome() == Outcome::Stopped && facts.stopped()
            && facts.add_effect() == AddEffect::Added && !actual.scoped_value_present()
            && item_call(facts, 10, 0) && facts.namespace_checkpoints_passed() == Some(3),
        Case::CreatorControlLookup => private_pair::creator_lookup_ready(actual),
        Case::OtherExecutableLookup => false, // Only the separate reader admits that fixed result.
        Case::StopBeforeAdd | Case::StopBeforeLookup => facts.outcome() == Outcome::Stopped && facts.stopped()
            && facts.add_effect() == AddEffect::NotEntered && !actual.scoped_value_present()
            && no_item_call(facts) && selection.root_identity_matched()
            && facts.first_refusal_phase() == case.before_item_phase()
            && facts.namespace_checkpoints_passed() == Some(3),
    }
}
fn adapter_settled(actual: &CaseReturn) -> bool {
    actual.facts().native_run_returned() && actual.facts().verified_native_run_receipt()
        && actual.facts().custody() == Custody::Settled && !actual.facts().callback_panicked()
        && actual.retained_native_frame_bytes() == 0
        && (actual.facts().adapter_frame_retired()
            || actual.comparison().is_some_and(|row| row.consume_returned_and_frame_retired))
}
struct Cohort {
    clock: Clock, fixture: Fixture, fixtures: Vec<FixtureReturn>, cases: Vec<CaseReturn>, harness: Option<Harness>,
    material: Material, binding: Binding, material_return: ScalarReturn, binding_return: ScalarReturn,
    native_abi: u32, fixture_bytes: usize, adapter_bytes: usize, charged_bytes: usize,
    registered: bool, post_add: OriginalAction, stop: OriginalAction, retirement_admitted: bool,
    terminal: Case, pair_enabled: bool, controls: ControlBook, control_bytes: usize, control_acl_bytes: usize,
    peer: Option<PeerLookup>, positive: Option<CaseReturn>, positive_accepted: bool,
    positive_refused: Option<Refused>, barrier_completed: bool, waits: usize,
    expected: [bool; 14], acknowledged: [bool; 14], comparison_refusals: [Option<Refused>; 14],
    harness_refusal: Option<Refused>, material_wiped: bool, stage: u32, run_entered: bool, run_returned: bool,
    cohort_completed: bool, output: RefCell<String>, report_built: bool, report_written: ScalarReturn, report_flushed: ScalarReturn,
    report_write_original: Option<io::Result<()>>, report_flush_original: Option<io::Result<()>>,
    // Last, and held for the entire process lifetime: never invoke an opaque
    // panic destructor while native/adapter/fixture originals may be unsettled.
    panic: Option<Box<dyn Any + Send>>, report_panic: Option<Box<dyn Any + Send>>,
}
impl Cohort {
    fn empty(entry: Instant) -> Self {
        Self { clock: Clock::new(entry), fixture: Fixture::empty(), fixtures: Vec::new(), cases: Vec::new(), harness: None,
            material: Material::default(), binding: Binding::default(), material_return: ScalarReturn::default(),
            binding_return: ScalarReturn::default(), native_abi: 0, fixture_bytes: 0, adapter_bytes: 0, charged_bytes: 0,
            registered: false, post_add: OriginalAction::default(), stop: OriginalAction::default(), retirement_admitted: false,
            terminal: Case::StopAfterAdd, pair_enabled: false, controls: ControlBook::empty(), control_bytes: 0, control_acl_bytes: 0,
            peer: None, positive: None, positive_accepted: false, positive_refused: None, barrier_completed: false, waits: 0,
            expected: [false; 14], acknowledged: [false; 14], comparison_refusals: [None; 14],
            harness_refusal: None, material_wiped: false, stage: 0, run_entered: false, run_returned: false,
            cohort_completed: false, output: RefCell::new(String::new()), report_built: false,
            report_written: ScalarReturn::default(), report_flushed: ScalarReturn::default(), report_write_original: None, report_flush_original: None, panic: None, report_panic: None }
    }
    fn prepare(&mut self) -> bool {
        self.stage = 1;
        if self.clock.admit(false) != Admission::Continue
            || self.fixtures.try_reserve_exact(ACTIONS).is_err() || self.cases.try_reserve_exact(14).is_err()
            || self.output.get_mut().try_reserve_exact(PUBLIC_OUTPUT_LIMIT).is_err() { return false; }
        // Constant ABI/sizeof queries only. No provider/selector/filesystem call.
        self.native_abi = unsafe { mrk_wrapping_fixture_abi() };
        self.fixture_bytes = unsafe { mrk_wrapping_fixture_frame_bytes() };
        let Some(adapter_bytes) = native_frame_bytes() else { return false; };
        self.adapter_bytes = adapter_bytes;
        if self.pair_enabled {
            let Some((book, acl)) = private_pair::native_control_charge() else { return false; };
            self.control_bytes = book; self.control_acl_bytes = acl;
        }
        if self.native_abi != 0x51460101 || self.fixture_bytes == 0 || self.fixture_bytes > FIXTURE_FRAME_LIMIT
            || self.fixtures.capacity() < ACTIONS || self.cases.capacity() < 14
            || self.output.get_mut().capacity() < PUBLIC_OUTPUT_LIMIT { return false; }
        // Full original Vec capacities, all14 complete adapter frame charges,
        // one fixture frame, output capacity and a conservative source-owned
        // working-cell allowance are reserved before the first native action.
        // This is NOT a compiler-stack/SDK/panic/process resident-memory bound.
        let parts = [
            size_of::<ManuallyDrop<Self>>(), self.fixtures.capacity() * size_of::<FixtureReturn>(),
            self.cases.capacity() * size_of::<CaseReturn>(), self.output.get_mut().capacity(),
            self.fixture_bytes, (14 + usize::from(self.pair_enabled)) * adapter_bytes, 196608,
            self.control_bytes, self.control_acl_bytes,
        ];
        let Some(charged) = parts.into_iter().try_fold(0usize, usize::checked_add) else { return false; };
        self.charged_bytes = charged;
        if charged > CALLER_OWNED_CHARGE_LIMIT || self.clock.admit(false) != Admission::Continue { return false; }
        self.registered = true;
        self.post_add.registered = true; self.stop.registered = true; // Distinct original-owner actions, before GO.
        if !self.fixture.reserve(self.fixture_bytes) || !self.clock.live() { return false; }
        if self.pair_enabled {
            if self.clock.admit(false) != Admission::Continue
                || !self.controls.reserve(1, self.control_bytes, self.control_acl_bytes) { return false; }
            let clock = &mut self.clock;
            if !self.controls.initialize(&mut |_| clock.admit(false)) { return false; }
        }
        self.clock.live()
    }
    fn action(&mut self, action: Action, retirement: bool) -> bool {
        self.stage = 100 + action.raw();
        self.registered && (!retirement || self.retirement_admitted)
            && fixture_action(&mut self.fixture, &mut self.fixtures, &mut self.clock, action, retirement)
    }
    fn initialize_harness(&mut self) -> bool {
        if self.clock.admit(false) != Admission::Continue { return false; }
        self.material_return.entered = true;
        // SAFETY: exactly sized precharged owner buffers, one original frame;
        // entropy completed. Password is never copied across this private FFI.
        let actual = unsafe { mrk_wrapping_fixture_material(self.fixture.pointer(),
            self.material.token.as_mut_ptr(), self.material.key.as_mut_ptr(), self.material.ids.as_mut_ptr().cast()) };
        self.material_return.actual = actual; self.material_return.returned = true;
        if actual != 1 || self.clock.admit(false) != Admission::Continue { return false; }
        fn context(bytes: &[u8; 32]) -> Option<Context> {
            let mut vault = [0; 16]; let mut generation = [0; 16];
            vault.copy_from_slice(&bytes[..16]); generation.copy_from_slice(&bytes[16..]);
            Context::new(vault, generation).ok()
        }
        let [Some(a), Some(b), Some(c), Some(d)] = self.material.ids.each_ref().map(context) else { return false; };
        // SAFETY: one fixed registered original cohort, genuine generated
        // identities, full charges, unchanged original cutoff; no retry.
        let original = unsafe { match self.terminal {
            Case::StopAfterAdd => Harness::new(self.material.token, [a, b, c, d]),
            Case::StopBeforeAdd => Harness::new_stop_before_add(self.material.token, [a, b, c, d]),
            Case::StopBeforeLookup => Harness::new_stop_before_lookup(self.material.token, [a, b, c, d]),
            _ => return false,
        } };
        match original {
            Ok(harness) => self.harness = Some(harness),
            Err(refused) => { self.harness_refusal = Some(refused); return false; }
        }
        true
    }
    fn bind(&mut self) -> bool {
        if self.clock.admit(false) != Admission::Continue { return false; }
        self.binding_return.entered = true;
        // SAFETY: fixed precharged out cell; genuine completed Create action.
        let actual = unsafe { mrk_wrapping_fixture_binding(self.fixture.pointer(), &mut self.binding) };
        self.binding_return.actual = actual; self.binding_return.returned = true;
        let b = &self.binding;
        if actual != 1 || b.version != 1 || b.bytes as usize != size_of::<Binding>() || b.reserved != 0
            || b.token != self.material.token || self.clock.admit(false) != Admission::Continue { return false; }
        let Some(harness) = self.harness.as_mut() else { return false; };
        // SAFETY: actual Create/root/selection observations retained above.
        // This pin is never updated for later deliberate fixture mutations.
        match unsafe { harness.bind_fixture(OwnerFixturePin { device: b.root_device, inode: b.root_inode,
            mode: b.root_mode, uid: b.root_uid, gid: b.root_gid }) } {
            Ok(()) => true,
            Err(refused) => { self.harness_refusal = Some(refused); false }
        }
    }
    fn case(&mut self, case: Case) -> bool {
        let index = self.cases.len();
        self.stage = 200 + index as u32;
        let expected = CALL_ROSTER.get(index).copied().map(|value|
            if value == Case::StopAfterAdd { self.terminal } else { value });
        if !self.registered || index >= CALL_ROSTER.len() || expected != Some(case)
            || self.cases.capacity() < 14 || self.clock.admit(false) != Admission::Continue { return false; }
        let Some(harness) = self.harness.as_mut() else { return false; };
        let clock = &mut self.clock; let fixture = &mut self.fixture; let fixtures = &mut self.fixtures;
        let post_add = &mut self.post_add; let stop = &mut self.stop;
        let mut admission = |checkpoint: Checkpoint, facts: &Facts| {
            let current = clock.admit(false);
            if current != Admission::Continue { return current; }
            if let Some(phase) = case.before_item_phase() {
                if checkpoint == Checkpoint::BeforeCall && facts.phase() == Some(phase) {
                    if !stop.observe_before_item(checkpoint, facts, phase) { clock.poisoned = true; return Admission::Unknown; }
                    let changed = clock.request_terminal_stop();
                    stop.returned = true; stop.completed = changed;
                    return if changed { Admission::Cutoff } else { Admission::Unknown };
                }
            }
            if checkpoint == Checkpoint::AfterCall && facts.phase() == Some(10) && facts.add_effect() == AddEffect::Added {
                if case == Case::PostAddNamespaceRefusal {
                    if !post_add.observe_add(checkpoint, facts) { clock.poisoned = true; return Admission::Unknown; }
                    // This is the separately PRE-registered original-owner
                    // mutation, not a fabricated callback status or fault hook.
                    // Its complete actual return enters the owner Vec first.
                    let completed = fixture_action(fixture, fixtures, clock, Action::PostAdd, false);
                    post_add.returned = fixtures.last().is_some_and(|row| row.action == Action::PostAdd && row.ffi_returned);
                    post_add.completed = completed;
                    if !completed { clock.poisoned = true; return Admission::Unknown; }
                } else if case == Case::StopAfterAdd {
                    if !stop.observe_add(checkpoint, facts) { clock.poisoned = true; return Admission::Unknown; }
                    let changed = clock.request_terminal_stop();
                    stop.returned = true; stop.completed = changed;
                    return if changed { Admission::Cutoff } else { Admission::Unknown };
                }
            }
            clock.admit(false)
        };
        let key = (case.operation() == Operation::AddOnly).then_some(&self.material.key);
        // SAFETY: exact fixed roster, precharged full adapter frame, native
        // originals retained in this same caller; every callback uses its ONE
        // cutoff. Explicit post-add and STOP action registrations are above.
        let actual = unsafe { harness.run_next(case, key, &mut admission) };
        match actual {
            Ok(original) => self.cases.push(original), // BEFORE result checks/consumption.
            Err(refused) => { self.harness_refusal = Some(refused); return false; }
        }
        if !self.clock.live() || !expected_case(&self.cases[index]) { return false; }
        if matches!(case, Case::LookupBaseline | Case::DenyDeleteAndReadonlyAllow) {
            if self.cases[index].retained_native_frame_bytes() != self.adapter_bytes
                || self.clock.admit(false) != Admission::Continue { return false; }
            // SAFETY: fresh original-cutoff admission immediately above, whole
            // frame charge retained through the actual synchronous comparison.
            let actual = unsafe { self.cases[index].compare_candidate(&self.material.key) };
            match actual {
                Ok(row) if row.callback_returned && row.bytes_equal && row.whole_frame_charge_transferred
                    && row.native_frame_bytes == self.adapter_bytes && row.consume_returned_and_frame_retired => {},
                Ok(_) => return false,
                Err(refused) => { self.comparison_refusals[index] = Some(refused); return false; }
            }
        }
        if !self.clock.live() || !adapter_settled(&self.cases[index])
            || case == Case::PostAddNamespaceRefusal && !self.post_add.complete()
            || case.terminal_stop() && !self.stop.complete_for(case) { return false; }
        self.expected[index] = true;
        if case.terminal_stop() {
            // Terminal STOP intentionally leaves the harness halted/pending.
            // No acknowledge, next call, restarted instance or implicit permit.
            return self.clock.stop_requested && self.harness.as_ref().is_some_and(Harness::halted);
        }
        if self.clock.admit(false) != Admission::Continue { return false; }
        let Some(harness) = self.harness.as_mut() else { return false; };
        // SAFETY: actual original synchronous return and candidate settlement
        // already observed; this is not fixture-retirement or outer finality.
        match unsafe { harness.acknowledge_adapter_return(&self.cases[index]) } {
            Ok(()) => { self.acknowledged[index] = true; true },
            Err(refused) => { self.harness_refusal = Some(refused); false }
        }
    }
    fn creator_barrier(&mut self) -> bool {
        self.stage = 250;
        if !self.pair_enabled || self.terminal != Case::StopAfterAdd || self.barrier_completed
            || self.cases.len() != 13 || self.fixtures.len() != 16 || self.peer.is_some()
            || self.clock.admit(false) != Admission::Continue { return false; }
        let b = &self.binding;
        let pin = || OwnerFixturePin { device: b.root_device, inode: b.root_inode,
            mode: b.root_mode, uid: b.root_uid, gid: b.root_gid };
        let ids = self.material.ids[0];
        let Ok(context) = Context::new(ids[..16].try_into().unwrap(), ids[16..].try_into().unwrap()) else { return false; };
        match PeerLookup::creator(self.material.token, context, pin()) {
            Ok(peer) => self.peer = Some(peer), Err(refused) => { self.positive_refused = Some(refused); return false; }
        }
        let clock = &mut self.clock;
        if clock.admit(false) != Admission::Continue { return false; }
        match unsafe { self.peer.as_mut().unwrap().run(&mut |_, _| clock.admit(false)) } {
            Ok(actual) => self.positive = Some(actual), // Retain before inspection/consumption.
            Err(refused) => { self.positive_refused = Some(refused); return false; }
        }
        let original = self.positive.as_mut().unwrap();
        if !clock.live() || !private_pair::creator_lookup_ready(original)
            || original.retained_native_frame_bytes() != self.adapter_bytes
            || clock.admit(false) != Admission::Continue { return false; }
        match unsafe { original.compare_candidate(&self.material.key) } {
            Ok(c) if c.callback_returned && c.bytes_equal && c.whole_frame_charge_transferred
                && c.native_frame_bytes == self.adapter_bytes && c.consume_returned_and_frame_retired => {},
            Ok(_) => return false, Err(refused) => { self.positive_refused = Some(refused); return false; }
        }
        if !adapter_settled(original) || clock.admit(false) != Admission::Continue { return false; }
        self.positive_accepted = true;
        let Ok(context) = Context::new(ids[..16].try_into().unwrap(), ids[16..].try_into().unwrap()) else { return false; };
        if !self.controls.publish_ready(&self.material.token, &pin(), &context, &mut |_| clock.admit(false)) { return false; }
        let mut acknowledged = false;
        for _ in 0..private_pair::POLLS {
            if clock.admit(false) != Admission::Continue { return false; }
            match self.controls.poll(&mut |_| clock.admit(false)) {
                1 => { acknowledged = true; break; },
                2 => {}, _ => return false,
            }
            if clock.admit(false) != Admission::Continue { return false; }
            self.waits += 1;
            std::thread::sleep(private_pair::POLL_INTERVAL); // No worker, retry, or renewed clock.
        }
        if !acknowledged || clock.admit(false) != Admission::Continue
            || !self.controls.finish(&mut |_| clock.admit(false)) || !clock.live() { return false; }
        self.barrier_completed = true;
        true // Only now is the original terminal case reachable; Retire stays separate.
    }
    fn finish_failed_pair_controls(&mut self) {
        if self.pair_enabled && !self.controls.complete() {
            let clock = &mut self.clock;
            let _settled = self.controls.finish(&mut |_| clock.admit(false));
            // Failure remains absorbing. No acknowledgement, terminal item, or
            // native fixture retirement is acquired from a control close.
        }
    }
    fn run(&mut self) -> bool {
        if !self.prepare() || !self.action(Action::Entropy, false) || !self.initialize_harness()
            || !self.case(Case::Selector) || !self.case(Case::HelperShapes)
            || !self.action(Action::Create, false) || !self.bind() { return false; }
        let terminal = self.terminal;
        for original_case in CALL_ROSTER.into_iter().skip(2) {
            let case = if original_case == Case::StopAfterAdd { terminal } else { original_case };
            let before = match case {
                Case::DenyDeleteAndReadonlyAllow => Some(Action::DenyRead),
                Case::ForeignUserMutationAllow => Some(Action::ForeignUser),
                Case::ForeignGroupInheritOnlyMutationAllow => Some(Action::ForeignGroup),
                Case::PosixForeignWrite => Some(Action::Posix), Case::SymlinkLeaf => Some(Action::Symlink),
                Case::LockedPrivateFixture => Some(Action::Lock),
                Case::StopAfterAdd | Case::StopBeforeAdd | Case::StopBeforeLookup => Some(Action::Unlock), _ => None,
            };
            if before.is_some_and(|action| !self.action(action, false)) { return false; }
            if self.pair_enabled && case == Case::StopAfterAdd && !self.creator_barrier() { return false; }
            if !self.case(case) { return false; }
            let restore = match case {
                Case::DenyDeleteAndReadonlyAllow => Some(Action::RestoreDeny),
                Case::ForeignUserMutationAllow => Some(Action::RestoreUser),
                Case::ForeignGroupInheritOnlyMutationAllow => Some(Action::RestoreGroup),
                Case::PosixForeignWrite => Some(Action::RestorePosix), Case::SymlinkLeaf => Some(Action::RestoreSymlink),
                Case::PostAddNamespaceRefusal => Some(Action::RestorePostAdd), _ => None,
            };
            if restore.is_some_and(|action| !self.action(action, false)) { return false; }
        }
        if self.pair_enabled && (!self.barrier_completed || !self.positive_accepted || !self.controls.complete()
            || !self.positive.as_ref().is_some_and(adapter_settled) || !self.peer.as_ref().is_some_and(PeerLookup::started)) { return false; }
        if self.cases.len() != 14 || self.fixtures.len() != 16 || !self.expected.iter().all(|v| *v)
            || !self.acknowledged[..13].iter().all(|v| *v) || self.acknowledged[13]
            || !self.cases.iter().all(adapter_settled) || !self.post_add.complete() || !self.stop.complete_for(self.terminal)
            || !self.harness.as_ref().is_some_and(|h| h.invocations_started() == 14 && h.halted())
            || !self.clock.stop_requested || self.clock.admit(true) != Admission::Continue { return false; }
        // A distinct fresh admission of the originally registered last action,
        // AFTER positive settlement of every original. STOP itself grants none.
        self.retirement_admitted = true;
        if !self.action(Action::Retire, true)
            || !self.fixtures.last().is_some_and(|row| row.raw.all_fixture_effects_observed())
            || self.clock.admit(true) != Admission::Continue || !self.fixture.retire_allocation() { return false; }
        fn wipe(bytes: &mut [u8]) {
            for byte in bytes { unsafe { std::ptr::write_volatile(byte, 0) }; }
            compiler_fence(Ordering::SeqCst);
        }
        wipe(&mut self.material.key); wipe(&mut self.material.token);
        for pair in &mut self.material.ids { wipe(pair); }
        wipe(&mut self.binding.token);
        self.material_wiped = true; // Only these owned copies, never all compiler/provider copies.
        self.stage = 300;
        self.clock.live()
    }
}

// Every string emitted below is a source-fixed public label. No formatting of
// native paths, CF values, principal identities, key/password bytes, pointers,
// handle numbers, panic payloads or arbitrary error messages is permitted.
struct Bounded<'a> { value: &'a mut String }
impl FmtWrite for Bounded<'_> {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        let Some(end) = self.value.len().checked_add(text.len()) else { return Err(fmt::Error); };
        if end > PUBLIC_OUTPUT_LIMIT || end > self.value.capacity() { return Err(fmt::Error); }
        self.value.push_str(text);
        Ok(())
    }
}
fn numbers(out: &mut Bounded<'_>, values: &[i64]) -> fmt::Result { private_pair::numbers(out, values) }
fn references(out: &mut Bounded<'_>, rows: &[ReferenceObservation]) -> fmt::Result { private_pair::references(out, rows) }
fn native_result(out: &mut Bounded<'_>, raw: &RawResult) -> fmt::Result { private_pair::native_result(out, raw) }
fn original_action(out: &mut Bounded<'_>, row: &OriginalAction) -> fmt::Result {
    numbers(out, &[row.registered.into(), row.entered.into(), row.returned.into(), row.completed.into(),
        row.checkpoint.into(), row.phase.into(), row.add_returned.into(), row.add_status.into(), row.add_effect.into()])
}
fn case_name(case: Case) -> &'static str {
    match case {
        Case::Selector => "Selector", Case::HelperShapes => "HelperShapes", Case::AddBaseline => "AddBaseline",
        Case::LookupBaseline => "LookupBaseline", Case::DuplicateBaseline => "DuplicateBaseline",
        Case::MissingOther => "MissingOther", Case::DenyDeleteAndReadonlyAllow => "DenyDeleteAndReadonlyAllow",
        Case::ForeignUserMutationAllow => "ForeignUserMutationAllow",
        Case::ForeignGroupInheritOnlyMutationAllow => "ForeignGroupInheritOnlyMutationAllow",
        Case::PosixForeignWrite => "PosixForeignWrite", Case::SymlinkLeaf => "SymlinkLeaf",
        Case::PostAddNamespaceRefusal => "PostAddNamespaceRefusal",
        Case::LockedPrivateFixture => "LockedPrivateFixture", Case::StopAfterAdd => "StopAfterAdd",
        Case::StopBeforeAdd => "StopBeforeAdd", Case::StopBeforeLookup => "StopBeforeLookup",
        Case::CreatorControlLookup => "CreatorControlLookup", Case::OtherExecutableLookup => "OtherExecutableLookup",
    }
}
impl Cohort {
    fn report_scope(&self) -> &'static str {
        if self.pair_enabled { return "wrapping-private-creator-pair"; }
        match self.terminal {
            Case::StopBeforeAdd => "wrapping-private-stop-before-add",
            Case::StopBeforeLookup => "wrapping-private-stop-before-lookup",
            _ => "wrapping-private-common-cohort",
        }
    }
    fn build_report(&self) -> fmt::Result {
        let mut buffer = self.output.borrow_mut();
        buffer.clear();
        let out = &mut Bounded { value: &mut buffer };
        write!(out, "MRK_WRAPPING_PRIVATE_RESULT={{\"schemaVersion\":1,\"scope\":\"{}\",", self.report_scope())?;
        out.write_str("\"provisional\":true,\"outerFinalityRequired\":true,\"shippingBinaryQualified\":false,")?;
        out.write_str("\"distributionQualified\":false,\"perQueryUIFailQualified\":false,")?;
        write!(out, "\"cutoffSeconds\":{},\"adapterInvocationBound\":{},\"fixtureActionBound\":17,", COHORT_SECONDS, if self.pair_enabled { 15 } else { 14 })?;
        write!(out, "\"caller\":{{\"runEntered\":{},\"runReturned\":{},\"completed\":{},\"originalSlotRetained\":true,",
            self.run_entered, self.run_returned, self.cohort_completed)?;
        write!(out, "\"registered\":{},\"chargedBytes\":{},\"chargeLimit\":{},\"nativeAbi\":{},\"fixtureFrameBytes\":{},\"adapterFrameBytes\":{},",
            self.registered, self.charged_bytes, CALLER_OWNED_CHARGE_LIMIT, self.native_abi, self.fixture_bytes, self.adapter_bytes)?;
        write!(out, "\"retirementAdmitted\":{},\"stopRequested\":{},\"deadlineObserved\":{},\"poisoned\":{},\"stage\":{},\"callbackOrCallerPanic\":{},",
            self.retirement_admitted, self.clock.stop_requested, self.clock.deadline_observed, self.clock.poisoned,
            self.stage, self.panic.is_some() || self.fixtures.iter().any(|row| row.callback_panic.is_some())
                || self.cases.iter().any(|row| row.facts().callback_panicked()))?;
        write!(out, "\"clockChecks\":{},\"forwardAdmissions\":{},\"retirementAdmissions\":{},\"harnessRefused\":{},\"materialWiped\":{},",
            self.clock.checks, self.clock.forward_admissions, self.clock.retirement_admissions,
            self.harness_refusal.is_some(), self.material_wiped)?;
        if self.terminal.before_item_phase().is_some() || self.pair_enabled {
            write!(out, "\"terminalHarnessHalted\":{},\"terminalHarnessInvocations\":{},",
                self.harness.as_ref().is_some_and(Harness::halted),
                self.harness.as_ref().map_or(0, Harness::invocations_started))?;
        }
        out.write_str("\"materialGetter\":")?;
        numbers(out, &[self.material_return.entered.into(), self.material_return.returned.into(), self.material_return.actual.into()])?;
        out.write_str(",\"bindingGetter\":")?;
        numbers(out, &[self.binding_return.entered.into(), self.binding_return.returned.into(), self.binding_return.actual.into()])?;
        out.write_str(",\"fixtureAllocation\":")?;
        numbers(out, &[self.fixture.allocation_entered.into(), self.fixture.allocation_returned.into(),
            self.fixture.allocation_nonnull.into(), self.fixture.free_spent.into(), self.fixture.free_returned.into(),
            self.fixture.free_result.into()])?;
        out.write_str("},\"originalActions\":{\"postAdd\":")?;
        original_action(out, &self.post_add)?;
        out.write_str(",\"terminalStop\":")?;
        original_action(out, &self.stop)?;
        out.write_str("},\"fixtureReturns\":[")?;
        for (i, row) in self.fixtures.iter().enumerate() {
            if i != 0 { out.write_char(',')?; }
            numbers(out, &[row.action.raw().into(), row.ffi_returned.into(), row.verified.into(), row.completed().into(),
                row.callback_panic.is_some().into(), row.raw.failed.into(), row.raw.unknown.into(), row.raw.stopped.into()])?;
        }
        out.write_str("],\"fixture\":")?;
        if let Some(original) = self.fixtures.last() {
            let raw = &original.raw;
            write!(out, "{{\"verified\":{},\"header\":", original.verified)?;
            numbers(out, &[raw.version.into(), raw.bytes.into(), raw.action_count.into(), raw.call_count.into(),
                raw.ref_count.into(), raw.failed.into(), raw.unknown.into(), raw.stopped.into(), raw.exception.into(),
                raw.callbacks_cleared.into(), raw.material_generated.into(), raw.root_created.into(), raw.root_removed.into(),
                raw.create_effect.into(), raw.provider_deleted.into(), raw.sync_entered.into(), raw.sync_returned.into(),
                raw.sync_absent_empty.into(), raw.finalized.into(), raw.reserved.into()])?;
            out.write_str(",\"actions\":[")?;
            for (i, row) in raw.actions.iter().take(raw.action_count as usize).enumerate() {
                if i != 0 { out.write_char(',')?; }
                numbers(out, &[row.kind.into(), row.entered.into(), row.returned.into(), row.completed.into(),
                    row.first_call.into(), row.end_call.into()])?;
            }
            out.write_str("],\"calls\":[")?;
            for (i, row) in raw.calls.iter().take(raw.call_count as usize).enumerate() {
                if i != 0 { out.write_char(',')?; }
                numbers(out, &[row.kind.into(), row.entered.into(), row.returned.into(), row.actual_errno.into(), row.result])?;
            }
            out.write_str("],\"references\":")?;
            references(out, &raw.references[..(raw.ref_count as usize).min(REFS)])?;
            out.write_str(",\"selections\":[")?;
            for (i, row) in raw.selections.iter().enumerate() {
                if i != 0 { out.write_char(',')?; }
                numbers(out, &[row.entered.into(), row.returned.into(), row.search_typed.into(), row.default_kind.into(), row.count.into(),
                    row.members_entered.into(), row.members_returned.into(), row.members_typed.into(),
                    row.paths_entered.into(), row.paths_returned.into(), row.identities_admitted.into(),
                    row.comparisons_entered.into(), row.comparisons_returned.into(), row.unchanged.into(), row.fixture_absent.into()])?;
            }
            out.write_str("],\"namespace\":")?;
            native_result(out, &raw.namespace)?;
            out.write_char('}')?;
        } else { out.write_str("null")?; }
        out.write_str(",\"cases\":[")?;
        for (i, row) in self.cases.iter().enumerate() {
            if i != 0 { out.write_char(',')?; }
            let facts = row.facts(); let selection = row.selection();
            let evidence = match row.case() { Case::Selector => "production-selector-only",
                Case::HelperShapes => "helper-shape-only", _ => "synthetic-provider-only" };
            write!(out, "{{\"ordinal\":{},\"case\":\"{}\",\"evidence\":\"{}\",\"expected\":{},\"acknowledged\":{},",
                i + 1, case_name(row.case()), evidence, self.expected[i], self.acknowledged[i])?;
            write!(out, "\"nativeReturned\":{},\"verified\":{},\"settled\":{},\"retainedNativeBytes\":{},\"frameRetired\":{},\"scopedValuePresent\":{},\"comparisonRefused\":{},",
                facts.native_run_returned(), facts.verified_native_run_receipt(), adapter_settled(row),
                row.retained_native_frame_bytes(), facts.adapter_frame_retired(), row.scoped_value_present(),
                self.comparison_refusals[i].is_some())?;
            out.write_str("\"selection\":")?;
            numbers(out, &[selection.verified().into(), selection.account_selected().into(), selection.fixture_selected().into(),
                selection.root_identity_matched().into(), selection.selector_boundary_returned().into(), selection.callbacks_cleared().into()])?;
            out.write_str(",\"helperCounts\":")?;
            if let Some((entered, returned, matches)) = selection.helper_counts() {
                numbers(out, &[entered.into(), returned.into(), matches.into()])?;
            } else { out.write_str("null")?; }
            out.write_str(",\"comparison\":")?;
            if let Some(c) = row.comparison() {
                numbers(out, &[c.callback_returned.into(), c.bytes_equal.into(), c.whole_frame_charge_transferred.into(),
                    c.native_frame_bytes as i64, c.consume_returned_and_frame_retired.into()])?;
            } else { out.write_str("null")?; }
            out.write_str(",\"raw\":")?;
            native_result(out, &facts.raw)?;
            out.write_char('}')?;
        }
        out.write_char(']')?;
        if self.pair_enabled {
            write!(out, ",\"pair\":{{\"positiveAccepted\":{},\"comparisonRefused\":{},\"barrierCompleted\":{},\"totalAdapterCalls\":{},\"waits\":{},\"controls\":",
                self.positive_accepted, self.positive_refused.is_some(), self.barrier_completed,
                self.harness.as_ref().map_or(0, Harness::invocations_started) + usize::from(self.peer.as_ref().is_some_and(PeerLookup::started)), self.waits)?;
            self.controls.report(out)?; out.write_str(",\"positive\":")?;
            if let Some(row) = &self.positive { private_pair::peer_report(out, row)?; } else { out.write_str("null")?; }
            out.write_char('}')?;
        }
        out.write_str(",\"owed\":[\"native-exception\",\"returned-failed-close\",\"incomplete-acl\",")?;
        out.write_str("\"unforced-native-bounds\",\"before-item-stop\",\"second-executable-creator\",")?;
        out.write_str("\"uifail-no-prompt-denial\"],\"atomicProviderFdAttestation\":false}\n")
    }
    fn write_report(&mut self) {
        // Keep the actual I/O Result originals as well as scalar observations.
        // A report's provisional 'completed' is not its write/flush result;
        // actual outer process return and strict receipt validation remain due.
        let buffer = self.output.borrow();
        let fallback: &[u8] = match self.terminal {
            Case::StopBeforeAdd => b"MRK_WRAPPING_PRIVATE_RESULT={\"schemaVersion\":1,\"scope\":\"wrapping-private-stop-before-add\",\"provisional\":true,\"outerFinalityRequired\":true,\"reportUnavailable\":true}\n",
            Case::StopBeforeLookup => b"MRK_WRAPPING_PRIVATE_RESULT={\"schemaVersion\":1,\"scope\":\"wrapping-private-stop-before-lookup\",\"provisional\":true,\"outerFinalityRequired\":true,\"reportUnavailable\":true}\n",
            _ => b"MRK_WRAPPING_PRIVATE_RESULT={\"schemaVersion\":1,\"scope\":\"wrapping-private-common-cohort\",\"provisional\":true,\"outerFinalityRequired\":true,\"reportUnavailable\":true}\n",
        };
        let fallback = if self.pair_enabled {
            b"MRK_WRAPPING_PRIVATE_RESULT={\"schemaVersion\":1,\"scope\":\"wrapping-private-creator-pair\",\"provisional\":true,\"outerFinalityRequired\":true,\"reportUnavailable\":true}\n".as_slice()
        } else { fallback };
        let bytes = if self.report_built { buffer.as_bytes() } else { fallback };
        let mut stdout = io::stdout().lock();
        self.report_written.entered = true;
        self.report_write_original = Some(IoWrite::write_all(&mut stdout, bytes));
        self.report_written.returned = true;
        self.report_written.actual = u32::from(matches!(self.report_write_original.as_ref(), Some(Ok(()))));
        if self.report_written.actual == 1 {
            self.report_flushed.entered = true;
            self.report_flush_original = Some(IoWrite::flush(&mut stdout));
            self.report_flushed.returned = true;
            self.report_flushed.actual = u32::from(matches!(self.report_flush_original.as_ref(), Some(Ok(()))));
        }
    }
}

// This single slot is a process-lifetime address of THIS original libtest
// caller, not a reusable registry/executor or another work owner. No thread,
// task, path, clock or permission is acquired from it and no getter is exposed.
// It keeps failed/panicked originals reachable after the test thread returns;
// an outer timeout/process exit still cannot authorize fixture deletion.
fn run_registered_cohort(entry: Instant, terminal: Case) { run_registered_variant(entry, terminal, false); }
fn run_registered_variant(entry: Instant, terminal: Case, pair_enabled: bool) {
    static CLAIMED: AtomicBool = AtomicBool::new(false);
    #[used]
    static ORIGINAL: AtomicPtr<ManuallyDrop<Cohort>> = AtomicPtr::new(std::ptr::null_mut());
    assert!(!CLAIMED.swap(true, Ordering::AcqRel), "private cohort is single-use");
    let mut original = Cohort::empty(entry);
    original.terminal = terminal; // A source-fixed test entry, never ambient input.
    original.pair_enabled = pair_enabled;
    let pointer = Box::into_raw(Box::new(ManuallyDrop::new(original)));
    ORIGINAL.store(pointer, Ordering::Release);
    // SAFETY: CLAIMED permits one caller only; no other code reads this private
    // slot. The allocation remains reachable and is never implicitly dropped.
    let cohort = unsafe { &mut **pointer };
    cohort.run_entered = true;
    match catch_unwind(AssertUnwindSafe(|| cohort.run())) {
        Ok(completed) => { cohort.run_returned = true; cohort.cohort_completed = completed; },
        Err(payload) => { cohort.panic = Some(payload); cohort.clock.poisoned = true; },
    }
    match catch_unwind(AssertUnwindSafe(|| cohort.finish_failed_pair_controls())) {
        Ok(()) => {}, Err(payload) => { cohort.report_panic = Some(payload); cohort.clock.poisoned = true; }
    }
    if cohort.report_panic.is_some() { assert!(false, "private pair control cleanup uncertain; original retained"); }
    match catch_unwind(AssertUnwindSafe(|| {
        cohort.report_built = cohort.build_report().is_ok();
        cohort.write_report();
    })) {
        Ok(()) => {},
        Err(payload) => { cohort.report_panic = Some(payload); cohort.clock.poisoned = true; },
    }
    // Assert only AFTER preserving originals/reporting. A slow/failed write,
    // callback panic, late cutoff or incomplete retirement cannot produce an
    // exit0 test, even if a provisional line was written before the failure.
    let complete = cohort.cohort_completed && cohort.run_returned && cohort.panic.is_none()
        && cohort.report_panic.is_none() && cohort.report_built
        && cohort.report_written.returned && cohort.report_written.actual == 1
        && cohort.report_flushed.returned && cohort.report_flushed.actual == 1 && cohort.clock.live();
    assert!(complete, "private cohort incomplete; retain originals and fixture");
}

#[test]
fn private_keychain_cohort() {
    let entry = Instant::now(); // FIRST action: ONE cutoff covers every later step.
    run_registered_cohort(entry, Case::StopAfterAdd);
}
#[test]
fn private_keychain_stop_before_add() {
    let entry = Instant::now(); // Its separately registered original, not a reset.
    run_registered_cohort(entry, Case::StopBeforeAdd);
}
#[test]
fn private_keychain_stop_before_lookup() {
    let entry = Instant::now(); // Its separately registered original, not a reset.
    run_registered_cohort(entry, Case::StopBeforeLookup);
}

#[test]
fn private_keychain_creator_pair() {
    let entry = Instant::now(); // FIRST action: same original45s covers peer wait and retirement.
    run_registered_variant(entry, Case::StopAfterAdd, true);
}
