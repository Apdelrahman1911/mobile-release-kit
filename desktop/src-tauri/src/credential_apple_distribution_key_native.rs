//! Native-only pending-key custody on the ORIGINAL Asset/vault work.
//!
//! The Apple SavedSession owns the generator/verifier/transport/journal and
//! opaque permits. This leaf only borrows the same vault and current context.
//! No pending key can be selected through ordinary Prepare/assessment/Bind.
//! Parent v3/clock hooks are required before compiling/enabling this path.
use super::*;
use crate::{
    credential_setup::KeyReference,
    saved_command_owner::{AppleKeySavePermit, AppleKeyUseJoined},
};
use std::sync::Weak;

#[path = "credential_apple_distribution_key_store.rs"]
pub(in crate::asset_session) mod key_store;
pub(crate) use key_store::AppleDistributionKeyDestination;
#[path="credential_apple_p12_native.rs"]
pub(in crate::asset_session) mod p12;
pub(crate) use p12::AppleP12Destination;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Purpose {
    Prepare,
    Use,
    P12,
}
impl Purpose {
    fn operation(self) -> Operation {
        match self {
            Self::Prepare => Operation::PrepareAppleDistributionKey,
            Self::Use => Operation::UseAppleDistributionKey,
            Self::P12 => Operation::AssembleAppleP12,
        }
    }
}

fn same_reference(a: StoredRef, b: StoredRef) -> bool {
    a.identity == b.identity
        && a.record == b.record
        && a.revision == b.revision
        && a.original == b.original
}

/// Existing Arc backing only. This is not another Store/source/lifetime or an
/// authorization that a descriptor/reference can reconstruct.
struct VaultOriginal {
    owner: Weak<OriginalWork>,
    document: Weak<Inner>,
    session_identity: Arc<()>,
    context: Arc<NativeContext>,
    key: Arc<crypto::VaultKey>,
    store: Arc<Mutex<store::StoreBook>>,
    clock: Arc<crate::saved_command_owner::AppleProvisioningClock>,
    roster: ProjectRoster,
    purpose: Purpose,
}
impl VaultOriginal {
    fn capture(
        document: &DocumentBinding,
        state: &DocumentState,
        owner: &Arc<OriginalWork>,
        roster: ProjectRoster,
        purpose: Purpose,
    ) -> Result<Arc<Self>, Reason> {
        if !document.native_qualified() || !document.persistence_qualified() {
            return Err(Reason::Unqualified);
        }
        let context = state.context.as_ref().ok_or(Reason::ContextStale)?;
        let session = state.vault.as_ref().ok_or(Reason::VaultKeyMissing)?;
        let slot = state.slot.as_ref().ok_or(Reason::ContextStale)?;
        let key = session.key.as_ref().ok_or(Reason::VaultKeyMissing)?;
        // This MUST be the clock attached by the SAME real Apple SavedSession,
        // never an Asset default deadline or a copied status timestamp.
        let clock = owner.apple_profile_clock.get().ok_or(Reason::Unqualified)?;
        if context.execution_mode != commands::ExecutionMode::Local
            || context.platform != Platform::Ios
            || context.stage != Stage::Candidate
            || context.purpose != commands::Purpose::Provisioning
            || !session.writable()
            || session.identity != Some(key.identity())
            || !Arc::ptr_eq(&slot.owner, owner)
            || slot.operation != purpose.operation()
            || slot.target.is_some()
            || slot.reason != Reason::None
            || slot.cleanup_end.is_some()
            || owner.interrupted()
            || !clock.original_matches(owner)
            || clock.interrupted()
            || clock.completed()
            || roster.generation != context.registry_generation
            // The existing full SourceBook vault-exclusion probe supports
            // 32 projects. Do not mint a key source which it cannot recheck.
            || roster.roots.len() > 32
            || roster.roots.capacity() > 32
            || !roster.roots.contains(&context.project)
            || !document
                .context_matches(state, context)
                .map_err(|e| e.reason)?
            || !Arc::ptr_eq(&active_key(owner)?, key)
            || !Arc::ptr_eq(&native_store(owner)?, &session.store)
        {
            return Err(Reason::ContextStale);
        }
        let original = Self {
            owner: Arc::downgrade(owner),
            document: Arc::downgrade(&document.inner),
            session_identity: document.inner.session_identity.clone(),
            context: context.clone(),
            key: key.clone(),
            store: session.store.clone(),
            clock: clock.clone(),
            roster,
            purpose,
        };
        if !original.current_data(state, session, owner, false) {
            return Err(Reason::ContextStale);
        }
        Ok(Arc::new(original))
    }

    fn same_owner(&self, owner: &Arc<OriginalWork>) -> bool {
        self.owner
            .upgrade()
            .is_some_and(|original| Arc::ptr_eq(&original, owner))
            && owner
                .apple_profile_clock
                .get()
                .is_some_and(|clock| Arc::ptr_eq(clock, &self.clock))
    }

    /// Memory-only same-original check. Physical Store/roster IO remains in
    /// the original Child below and runs outside Document/host/service locks.
    fn current_data(
        &self,
        state: &DocumentState,
        session: &Session,
        owner: &Arc<OriginalWork>,
        mutating: bool,
    ) -> bool {
        state
            .slot
            .as_ref()
            .is_some_and(|slot| self.current_data_in_slot(state, session, slot, owner, mutating))
    }

    // Publication temporarily takes the actual Slot out of DocumentState.
    // Check that exact original argument, not a missing state.slot or a new
    // renderer-shaped replacement.
    fn current_data_in_slot(
        &self,
        state: &DocumentState,
        session: &Session,
        slot: &Slot,
        owner: &Arc<OriginalWork>,
        mutating: bool,
    ) -> bool {
        self.same_owner(owner)
            && !owner.interrupted()
            && !state.session
            && !state.stopping
            && !state.unknown
            && !state.exhausted
            && !state.retiring
            && !state.quit_pending
            && !state.lock_pending
            && state.lifetime.original_bound()
            && !session.revoked
            && !session.read_only
            && (session.state == State::Unlocked
                || mutating && matches!(self.purpose,Purpose::Prepare|Purpose::P12) && session.state == State::Mutating)
            && session.identity == Some(self.key.identity())
            && Arc::ptr_eq(&session.store, &self.store)
            && session
                .key
                .as_ref()
                .is_some_and(|key| Arc::ptr_eq(key, &self.key))
            && session.registry_generation == self.context.registry_generation
            && slot.vault.generation == Some(self.roster.generation)
            && state
                .context
                .as_ref()
                .is_some_and(|context| Arc::ptr_eq(context, &self.context))
            && Arc::ptr_eq(&slot.owner, owner)
            && slot.operation == self.purpose.operation()
            && slot.target.is_none()
            && slot.reason == Reason::None
            && slot.cleanup_end.is_none()
            && slot
                .context
                .as_ref()
                .is_some_and(|context| Arc::ptr_eq(context, &self.context))
    }

    fn current(
        &self,
        document: &DocumentBinding,
        state: &DocumentState,
        owner: &Arc<OriginalWork>,
        mutating: bool,
    ) -> bool {
        Weak::ptr_eq(&self.document, &Arc::downgrade(&document.inner))
            && Arc::ptr_eq(&self.session_identity, &document.inner.session_identity)
            && state
                .vault
                .as_ref()
                .is_some_and(|session| self.current_data(state, session, owner, mutating))
            && document
                .context_matches(state, &self.context)
                .unwrap_or(false)
    }

    fn recheck_store(
        &self,
        owner: &Arc<OriginalWork>,
        book: &mut store::StoreBook,
    ) -> Result<(), Reason> {
        if !self.same_owner(owner)
            || owner.interrupted()
            || !Arc::ptr_eq(&active_key(owner)?, &self.key)
            || !Arc::ptr_eq(&native_store(owner)?, &self.store)
        {
            return Err(Reason::SourceChanged);
        }
        check_exclusions(owner, book, &self.roster)?;
        if owner.interrupted() {
            return Err(Reason::UserCancelled);
        }
        Ok(())
    }

    /// The only interruption-tolerant checkpoint in this leaf. The opaque
    /// SAME-parent permit, not a boolean/status/error, proves that its one
    /// predeclared generated candidate is returned and may still be preserved.
    /// The parent also keeps a sticky veto for EVERY excluded later failure.
    fn save_current(&self, owner: &Arc<OriginalWork>, permit: &AppleKeySavePermit) -> bool {
        self.purpose == Purpose::Prepare
            && self.same_owner(owner)
            && self.clock.original_matches(owner)
            && !self.clock.completed()
            && permit.save_current(owner)
            && permit.save_deadline(owner).is_some_and(|end| {
                Instant::now() < end.min(self.clock.cleanup_end()).min(self.clock.hard_end())
            })
    }

    fn save_current_data_in_slot(
        &self,
        state: &DocumentState,
        session: &Session,
        slot: &Slot,
        owner: &Arc<OriginalWork>,
        permit: &AppleKeySavePermit,
        mutating: bool,
    ) -> bool {
        self.save_current(owner, permit)
            && self.key_scope_data_in_slot(state, session, slot, owner, mutating)
    }

    // Current document/lease half shared by the fixed save and by automatic
    // release deferral. Neither this half nor the predeclared parent slot is
    // a generated-output/save permit on its own.
    fn key_scope_data_in_slot(
        &self,
        state: &DocumentState,
        session: &Session,
        slot: &Slot,
        owner: &Arc<OriginalWork>,
        mutating: bool,
    ) -> bool {
        self.purpose == Purpose::Prepare
            && self.same_owner(owner)
            && save_scope_data(state, session, slot, owner, mutating)
            && session.identity == Some(self.key.identity())
            && Arc::ptr_eq(&session.store, &self.store)
            && session
                .key
                .as_ref()
                .is_some_and(|key| Arc::ptr_eq(key, &self.key))
            && session.registry_generation == self.context.registry_generation
            && slot.vault.generation == Some(self.roster.generation)
            && state
                .context
                .as_ref()
                .is_some_and(|context| Arc::ptr_eq(context, &self.context))
            && slot
                .context
                .as_ref()
                .is_some_and(|context| Arc::ptr_eq(context, &self.context))
            && self.context_identity_current()
    }

    fn save_current_document(
        &self,
        document: &DocumentBinding,
        state: &DocumentState,
        owner: &Arc<OriginalWork>,
        permit: &AppleKeySavePermit,
        mutating: bool,
    ) -> bool {
        Weak::ptr_eq(&self.document, &Arc::downgrade(&document.inner))
            && Arc::ptr_eq(&self.session_identity, &document.inner.session_identity)
            && state.vault.as_ref().is_some_and(|session| {
                state.slot.as_ref().is_some_and(|slot| {
                    self.save_current_data_in_slot(state, session, slot, owner, permit, mutating)
                })
            })
    }

    fn context_identity_current(&self) -> bool {
        let Some(document) = self.document.upgrade() else {
            return false;
        };
        Arc::ptr_eq(&document.session_identity, &self.session_identity)
            && document.bridge.registry_generation() == self.context.registry_generation
            && document
                .bridge
                .native_generation()
                .is_ok_and(|generation| generation == self.roster.generation)
            && document
                .bridge
                .native_project(&self.context.project_id)
                .is_ok_and(|(generation, root)| {
                    generation == self.context.registry_generation
                        && root.identity == self.context.project.identity
                        && root.path == self.context.project.path
                })
    }

    /// Uses the SAME actual SourceBook and StoreBook probes. Ordinary callers
    /// keep check_exclusions/owner.interrupted unchanged; no new source is
    /// adopted and an explicit revoke/source loss is never excused by STOP.
    fn recheck_store_for_save(
        &self,
        owner: &Arc<OriginalWork>,
        book: &mut store::StoreBook,
        permit: &AppleKeySavePermit,
    ) -> Result<(), Reason> {
        if !self.save_current(owner, permit)
            || !Arc::ptr_eq(&active_key(owner)?, &self.key)
            || !Arc::ptr_eq(&native_store(owner)?, &self.store)
        {
            return Err(Reason::SourceChanged);
        }
        let root = book
            .recheck_root(&mut || !self.save_current(owner, permit))
            .map_err(problem)?
            .registered();
        {
            let mut source = owner.source.lock().map_err(|_| Reason::CleanupUnknown)?;
            asset_source::probe_vault_exclusion(
                &mut source,
                Some(&root),
                &self.roster.roots,
                &mut || !self.save_current(owner, permit),
            )?;
        }
        if !self.save_current(owner, permit) {
            return Err(Reason::ContextStale);
        }
        Ok(())
    }

    fn save_cleanup_expired(&self) -> bool {
        // Cleanup of already-entered file operations is independently owed.
        // A revoked save permit cannot suppress these original close attempts;
        // neither can it extend the SAME parent's first-F/hard cutoff.
        !cleanup_window_open(
            self.clock.completed(),
            self.clock.cleanup_end(),
            self.clock.hard_end(),
            Instant::now(),
        )
    }

    fn fail(&self, owner: &Arc<OriginalWork>, reason: Reason, at: Instant) {
        // Same original minimum-F clock, even if another memory guard is busy.
        // No callback from this clock is allowed to borrow Document/Store.
        self.clock.observe_failure_at(reason, at);
        if let Ok(mut work) = owner.vault.try_lock() {
            work.fail(reason, at);
        }
        owner.signal_stop();
    }

    fn own_retained_bytes(&self) -> Option<usize> {
        let mut bytes = std::mem::size_of::<Self>().checked_add(
            self.roster
                .roots
                .capacity()
                .checked_mul(std::mem::size_of::<asset_source::RegisteredRoot>())?,
        )?;
        for root in &self.roster.roots {
            bytes = bytes.checked_add(root.path.capacity())?;
        }
        Some(bytes)
    }
}

// Only the time comparison of the SAME retained clock. This cannot mint a
// parent proof or revive a failed/consumed private-disposal attempt.
fn cleanup_window_open(completed: bool, cleanup: Instant, hard: Instant, now: Instant) -> bool {
    !completed && now < cleanup.min(hard)
}

fn preservation_reason(reason: Reason) -> bool {
    matches!(
        reason,
        Reason::None | Reason::UserCancelled | Reason::Shutdown | Reason::Deadline
    )
}

/// This predicate is only the state half of save_current_data_in_slot. Passing
/// it never mints a permit or original joins, and ordinary cancellation paths
/// do not call it. Kept separate for inert original-Slot regression coverage.
fn save_scope_data(
    state: &DocumentState,
    session: &Session,
    slot: &Slot,
    owner: &Arc<OriginalWork>,
    mutating: bool,
) -> bool {
    !state.session
        && !state.unknown
        && !state.exhausted
        && !state.retiring
        && !state.lock_pending
        && state.lifetime.original_bound()
        && !session.revoked
        && !session.read_only
        && (session.state == State::Unlocked || mutating && session.state == State::Mutating)
        && preservation_reason(session.reason)
        && Arc::ptr_eq(&slot.owner, owner)
        && slot.operation == Operation::PrepareAppleDistributionKey
        && slot.target.is_none()
        && preservation_reason(slot.reason)
        && slot.phase != super::super::Phase::Unknown
        && slot.settlement != Settlement::Unknown
        && slot.source != SourceState::Unknown
}

/// This is ONLY the automatic release fence. Explicit revoke_all/Lock never
/// calls it. The actual Apple parent was retained on this original before GO;
/// an operation enum or a matching numeric ID cannot manufacture that parent.
pub(in crate::asset_session) fn defer_automatic_release(
    state: &DocumentState,
    slot: &Slot,
    parent: &crate::saved_command_owner::AppleKeySession,
) -> bool {
    if !parent.preservation_pending(&slot.owner) {
        return false;
    }
    let Some(session) = &state.vault else {
        return false;
    };
    let Ok(work) = slot.owner.vault.try_lock() else {
        return false;
    };
    let Some(held) = work.apple_distribution_key.destination() else {
        return false;
    };
    !work.release
        && !work.release_claimed
        && work.original_join.is_none()
        && work.failed_child_join.is_none()
        && work
            .first
            .is_none_or(|(reason, _)| preservation_reason(reason))
        && held.preservation_unfailed()
        && Arc::ptr_eq(parent.clock(), &held.original.clock)
        && work
            .store
            .as_ref()
            .is_some_and(|store| Arc::ptr_eq(store, &held.original.store))
        && work
            .key
            .as_ref()
            .is_some_and(|key| Arc::ptr_eq(key, &held.original.key))
        && held
            .original
            .key_scope_data_in_slot(state, session, slot, &slot.owner, true)
}

pub(in crate::asset_session) fn automatic_release_deferred(
    state: &DocumentState,
    slot: &Slot,
) -> bool {
    slot.operation == Operation::PrepareAppleDistributionKey
        && slot
            .owner
            .apple_key_parent()
            .is_some_and(|parent| defer_automatic_release(state, slot, &parent))
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum InventoryPoint {
    Initial,
    BeforePending,
}
impl InventoryPoint {
    fn index(self) -> usize {
        match self {
            Self::Initial => 0,
            Self::BeforePending => 1,
        }
    }
}
#[derive(Clone, Copy, Default)]
struct InventoryCheck {
    entered: bool,
    returned: bool,
    succeeded: bool,
}
#[derive(Clone, Copy)]
struct InventoryRow {
    kind: Kind,
    reference: StoredRef,
}

/// Complete previously authenticated inventory, not a refreshed/adopted
/// census. The SAME Asset parent retains this before any Check child; the
/// destination shares it after Initial and before Pending is durable.
pub(crate) struct AppleDistributionKeyInventory {
    original: Arc<VaultOriginal>,
    rows: Vec<InventoryRow>,
    witnesses: Vec<store::ReadWitness>,
    checks: Mutex<[InventoryCheck; 2]>,
}
impl AppleDistributionKeyInventory {
    pub(in crate::asset_session) fn capture(
        document: &DocumentBinding,
        state: &DocumentState,
        owner: &Arc<OriginalWork>,
        roster: ProjectRoster,
    ) -> Result<Arc<Self>, Reason> {
        let original = VaultOriginal::capture(document, state, owner, roster, Purpose::Prepare)?;
        let session = state.vault.as_ref().ok_or(Reason::VaultKeyMissing)?;
        if !complete_session_inventory(session) {
            return Err(Reason::SourceChanged);
        }
        let mut rows = Vec::new();
        let mut witnesses = Vec::new();
        rows.try_reserve_exact(session.rows.len())
            .map_err(|_| Reason::Capacity)?;
        witnesses
            .try_reserve_exact(session.rows.len())
            .map_err(|_| Reason::Capacity)?;
        if rows.capacity() > store::DESCRIPTOR_COUNT
            || witnesses.capacity() > store::DESCRIPTOR_COUNT
        {
            return Err(Reason::Capacity);
        }
        for row in &session.rows {
            let reference = row.reference(original.key.identity());
            rows.push(InventoryRow {
                kind: row.authenticated.descriptor.kind,
                reference,
            });
            witnesses.push(reference.original);
        }
        Ok(Arc::new(Self {
            original,
            rows,
            witnesses,
            checks: Mutex::new([InventoryCheck::default(); 2]),
        }))
    }

    pub(in crate::asset_session) fn current(
        &self,
        document: &DocumentBinding,
        state: &DocumentState,
        owner: &Arc<OriginalWork>,
    ) -> bool {
        self.original.current(document, state, owner, false)
            && state
                .vault
                .as_ref()
                .is_some_and(|session| self.matches_session(session))
    }
    fn matches_session(&self, session: &Session) -> bool {
        inventory_rows_match(&self.rows, self.original.key.identity(), session)
    }
    pub(crate) fn checked(&self, owner: &Arc<OriginalWork>, point: InventoryPoint) -> bool {
        self.original.same_owner(owner)
            && self.checks.try_lock().is_ok_and(|checks| {
                let check = checks[point.index()];
                check.entered && check.returned && check.succeeded
            })
    }
    pub(crate) fn generation_empty(&self, owner: &Arc<OriginalWork>) -> bool {
        self.checked(owner, InventoryPoint::Initial)
            && !self
                .rows
                .iter()
                .any(|row| row.kind == Kind::AppleDistributionKey)
    }
    /// Bounded presentation DATA only. Callers must separately require the
    /// actual joined Initial check; these counts never authorize generation.
    pub(crate) fn counts(&self) -> (usize, usize) {
        (
            self.rows.len(),
            self.rows
                .iter()
                .filter(|row| row.kind == Kind::AppleDistributionKey)
                .count(),
        )
    }
    pub(crate) fn own_retained_bytes(&self) -> Option<usize> {
        std::mem::size_of::<Self>()
            .checked_add(2 * std::mem::size_of::<usize>())?
            .checked_add(self.original.own_retained_bytes()?)?
            .checked_add(2 * std::mem::size_of::<usize>())?
            .checked_add(
                self.rows
                    .capacity()
                    .checked_mul(std::mem::size_of::<InventoryRow>())?,
            )?
            .checked_add(
                self.witnesses
                    .capacity()
                    .checked_mul(std::mem::size_of::<store::ReadWitness>())?,
            )
    }
    pub(in crate::asset_session) fn context(&self) -> &Arc<NativeContext> {
        &self.original.context
    }
    pub(in crate::asset_session) fn key(&self) -> &Arc<crypto::VaultKey> {
        &self.original.key
    }
    pub(in crate::asset_session) fn store(&self) -> &Arc<Mutex<store::StoreBook>> {
        &self.original.store
    }
}

fn complete_session_inventory(session: &Session) -> bool {
    session.rows.len() <= store::DESCRIPTOR_COUNT
        && session.inventory.len() == session.rows.len()
        && session.rows.iter().enumerate().all(|(index, row)| {
            !row.mutation_pending
                && !session.rows[..index]
                    .iter()
                    .any(|prior| prior.authenticated.record == row.authenticated.record)
                && session
                    .inventory
                    .iter()
                    .filter(|record| **record == row.authenticated.record)
                    .count()
                    == 1
        })
}

fn inventory_rows_match(
    rows: &[InventoryRow],
    identity: format::Identity,
    session: &Session,
) -> bool {
    complete_session_inventory(session)
        && rows.len() == session.rows.len()
        && rows.iter().all(|captured| {
            session.rows.iter().any(|row| {
                captured.kind == row.authenticated.descriptor.kind
                    && same_reference(captured.reference, row.reference(identity))
            })
        })
}

pub(in crate::asset_session) fn execute_inventory(
    owner: &Arc<OriginalWork>,
    book: &mut store::StoreBook,
    inventory: &Arc<AppleDistributionKeyInventory>,
    point: InventoryPoint,
) -> Result<ChildResult, Reason> {
    if !inventory.original.same_owner(owner) {
        return Err(Reason::ContextStale);
    }
    {
        let mut checks = inventory
            .checks
            .lock()
            .map_err(|_| Reason::CleanupUnknown)?;
        let index = point.index();
        if checks[index].entered || index != 0 && !checks[0].succeeded {
            return Err(Reason::ContextStale);
        }
        checks[index].entered = true;
    }
    inventory.original.recheck_store(owner, book)?;
    book.recheck_apple_key_inventory(&inventory.witnesses, None, &mut || owner.interrupted())
        .map_err(problem)?;
    inventory.original.recheck_store(owner, book)?;
    Ok(ChildResult::Checked)
}

#[cfg(feature = "desktop-shell")]
pub(in crate::asset_session) async fn check_inventory(
    document: &DocumentBinding,
    owner: &Arc<OriginalWork>,
    inventory: &Arc<AppleDistributionKeyInventory>,
    point: InventoryPoint,
) -> Result<(), Reason> {
    {
        let state = document.lock();
        if !inventory.current(document, &state, owner) {
            return Err(Reason::ContextStale);
        }
        if allowance(&state, owner)? < crypto::CONTROL_BYTES {
            return Err(Reason::Capacity);
        }
    }
    let returned = native(
        document,
        owner,
        Child::CheckAppleDistributionKeyInventory(inventory.clone(), point),
    )
    .await;
    let current = {
        let state = document.lock();
        inventory.current(document, &state, owner)
            && owner
                .child
                .try_lock()
                .is_ok_and(|child| child.handle.is_none() && child.receipt == JoinReceipt::Returned)
    };
    let mut checks = inventory
        .checks
        .try_lock()
        .map_err(|_| Reason::CleanupUnknown)?;
    let check = &mut checks[point.index()];
    if check.returned {
        return Err(Reason::CleanupUnknown);
    }
    check.returned = true;
    match returned {
        Ok(ChildResult::Checked) if check.entered && current => {
            check.succeeded = true;
            Ok(())
        }
        Err(reason) => Err(reason),
        _ => Err(Reason::ContextStale),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum LoadPhase {
    Reserved,
    Reading,
    Loaded,
    Failed,
}
struct LoadProgress {
    phase: LoadPhase,
    payload: Option<Arc<Payload>>,
    first: Option<(Reason, Instant)>,
    joined: Option<AppleKeyUseJoined>,
}

/// Fresh exact record loan for a separate, explicitly admitted certificate
/// operation. An imported backup has a NEW reference and gets this same full
/// read/verification path, never an old keySaved/issuance permission.
pub(crate) struct AppleDistributionKeyLoan {
    original: Arc<VaultOriginal>,
    reference: StoredRef,
    allowance: usize,
    progress: Mutex<LoadProgress>,
}
impl AppleDistributionKeyLoan {
    pub(in crate::asset_session) fn reserve(
        document: &DocumentBinding,
        state: &DocumentState,
        owner: &Arc<OriginalWork>,
        expected: &KeyReference,
        roster: ProjectRoster,
    ) -> Result<Arc<Self>, Reason> {
        let original = VaultOriginal::capture(document, state, owner, roster, Purpose::Use)?;
        let (identity, record, revision) = expected.parts().map_err(|_| Reason::InvalidRequest)?;
        if original.key.identity() != identity {
            return Err(Reason::SourceChanged);
        }
        let session = state.vault.as_ref().ok_or(Reason::VaultKeyMissing)?;
        let row = session
            .rows
            .iter()
            .find(|row| {
                !row.mutation_pending
                    && row.authenticated.record == record
                    && row.authenticated.revision == revision
                    && row.authenticated.descriptor.kind == Kind::AppleDistributionKey
            })
            .ok_or(Reason::SourceChanged)?;
        let reference = row.reference(identity);
        Ok(Arc::new(Self {
            original,
            reference,
            allowance: crypto::APPLE_KEY_CRYPTO_BYTES,
            progress: Mutex::new(LoadProgress {
                phase: LoadPhase::Reserved,
                payload: None,
                first: None,
                joined: None,
            }),
        }))
    }

    pub(crate) fn reference(&self) -> KeyReference {
        KeyReference::native(
            self.reference.identity,
            self.reference.record,
            self.reference.revision,
        )
    }

    pub(in crate::asset_session) fn current(
        &self,
        document: &DocumentBinding,
        state: &DocumentState,
        owner: &Arc<OriginalWork>,
    ) -> bool {
        self.original.current(document, state, owner, self.original.purpose==Purpose::P12)
            && state.vault.as_ref().is_some_and(|session| {
                session.rows.iter().any(|row| {
                    !row.mutation_pending
                        && row.authenticated.descriptor.kind == Kind::AppleDistributionKey
                        && same_reference(row.reference(self.reference.identity), self.reference)
                })
            })
            && self.progress.try_lock().is_ok_and(|p| {
                p.phase == LoadPhase::Loaded
                    && p.first.is_none()
                    && p.joined.is_none()
                    && p.payload.as_ref().is_some_and(|payload| {
                        payload.kind == Kind::AppleDistributionKey
                            && !payload.usable_source()
                            && payload.material.is_none()
                    })
            })
    }

    /// Fixed existing private material writer only. No caller-controlled field
    /// name, generic bytes getter, renderer scalar, ordinary Bind or public CSR.
    pub(in crate::asset_session) fn private_parts<'a>(
        &self,
        owner: &Arc<OriginalWork>,
        payload: &'a Arc<Payload>,
    ) -> Result<[(&'static str, &'a [u8]); 3], Reason> {
        if !self.original.same_owner(owner) || owner.interrupted() {
            return Err(Reason::ContextStale);
        }
        if !owner
            .child
            .try_lock()
            .is_ok_and(|book| book.handle.is_none() && book.receipt == JoinReceipt::Returned)
        {
            return Err(Reason::CleanupUnknown);
        }
        let progress = self
            .progress
            .try_lock()
            .map_err(|_| Reason::CleanupUnknown)?;
        if progress.phase != LoadPhase::Loaded
            || progress.first.is_some()
            || progress.joined.is_some()
        {
            return Err(Reason::SourceChanged);
        }
        if !progress
            .payload
            .as_ref()
            .is_some_and(|held| Arc::ptr_eq(held, payload))
        {
            return Err(Reason::SourceChanged);
        }
        let fields = payload.fields.as_ref().ok_or(Reason::SourceRefused)?;
        let value = |name| {
            fields
                .borrow_value(name)
                .filter(|value| !value.is_empty() && value.len() <= 4096)
                .map(str::as_bytes)
                .ok_or(Reason::SourceRefused)
        };
        Ok([
            ("apple-key-pkcs8-base64", value("privateKeyPkcs8Base64")?),
            ("apple-key-csr", value("csrPem")?),
            ("apple-key-spki-base64", value("publicKeySpkiBase64")?),
        ])
    }

    pub(in crate::asset_session) fn payload(&self) -> Result<Option<Arc<Payload>>, Reason> {
        // Actual native census/fixed SelectedStoreMaterial only, never an
        // assignment. Its stored-only Payload stays unusable_source=false.
        // Contention is UNKNOWN, not an empty payload/memory refund.
        Ok(self
            .progress
            .try_lock()
            .map_err(|_| Reason::CleanupUnknown)?
            .payload
            .clone())
    }

    pub(crate) fn recheck(&self, owner: &Arc<OriginalWork>) -> Result<(), Reason> {
        let mut book = self
            .original
            .store
            .lock()
            .map_err(|_| Reason::CleanupUnknown)?;
        self.original.recheck_store(owner, &mut book)?;
        book.recheck_record(&self.reference.original, &mut || owner.interrupted())
            .map_err(problem)?;
        if owner.interrupted() {
            return Err(Reason::UserCancelled);
        }
        Ok(())
    }

    /// The actual parent must ALSO have the genuine bundled verifier result,
    /// current context/physical witness and original joins. This method only
    /// prevents a public result being substituted for this exact stored key.
    pub(crate) fn matches_public_material(
        &self,
        owner: &Arc<OriginalWork>,
        csr: &[u8],
        spki: &[u8],
    ) -> bool {
        self.original.same_owner(owner)
            && !owner.interrupted()
            && self.progress.try_lock().is_ok_and(|p| {
                p.phase == LoadPhase::Loaded
                    && p.first.is_none()
                    && p.joined.is_none()
                    && p.payload
                        .as_ref()
                        .and_then(|p| p.fields.as_ref())
                        .is_some_and(|fields| {
                            commands::apple_distribution_key_public_matches(fields, csr, spki)
                        })
            })
    }

    /// Still requires this original loaded loan and the separate genuine
    /// verifier/joins. A hash alone never adopts a restored NEW reference.
    pub(crate) fn matches_recovery_frame(&self, owner: &Arc<OriginalWork>, bytes:u32, sha256:&str) -> bool {
        self.original.same_owner(owner) && !owner.interrupted()
            && self.progress.try_lock().is_ok_and(|p| p.phase == LoadPhase::Loaded && p.first.is_none()
                && p.joined.is_none() && p.payload.as_ref().and_then(|p|p.fields.as_ref())
                    .is_some_and(|fields|commands::apple_distribution_key_frame_matches(fields,bytes,sha256)))
    }

    pub(crate) fn accept_joined(
        &self,
        owner: &Arc<OriginalWork>,
        proof: AppleKeyUseJoined,
    ) -> Result<(), Reason> {
        let mut p = self.progress.lock().map_err(|_| Reason::CleanupUnknown)?;
        if p.joined.is_some() {
            return Err(Reason::VaultInterrupted);
        }
        p.joined = Some(proof); // Retain first, including later currentness/clock failure.
        if !self.original.same_owner(owner)
            || !p
                .joined
                .as_ref()
                .is_some_and(|proof| proof.matches(self, owner))
        {
            let at = Instant::now();
            p.first.get_or_insert((Reason::CleanupUnknown, at));
            p.phase = LoadPhase::Failed;
            self.original.fail(owner, Reason::CleanupUnknown, at);
            return Err(Reason::CleanupUnknown);
        }
        Ok(())
    }

    /// Equal-only binding used by actual parent proof construction/retirement.
    /// Does not imply verification, native joins or current public-key proof.
    pub(crate) fn original_binding(
        &self,
        owner: &Arc<OriginalWork>,
        reference: &KeyReference,
    ) -> bool {
        self.original.same_owner(owner)
            && reference.parts().is_ok_and(|parts| {
                parts
                    == (
                        self.reference.identity,
                        self.reference.record,
                        self.reference.revision,
                    )
            })
    }

    fn parent_retirement_ready(&self, owner: &Arc<OriginalWork>) -> bool {
        self.progress.try_lock().is_ok_and(|p| {
            p.joined
                .as_ref()
                .is_some_and(|proof| proof.retirement_ready(self, owner))
        })
    }

    fn dispose_private(&self, owner: &Arc<OriginalWork>) -> bool {
        let Ok(mut p) = self.progress.try_lock() else {
            return false;
        };
        if !p
            .joined
            .as_mut()
            .is_some_and(|proof| proof.try_retire_used(self, owner))
        {
            return false;
        }
        // Keep the actual consumed proof and original private loan if its
        // return was late. A parent token being consumed does not erase the
        // original cutoff or allow a second disposal attempt.
        if self.original.save_cleanup_expired() {
            let at = Instant::now();
            p.first.get_or_insert((Reason::Deadline, at));
            p.phase = LoadPhase::Failed;
            self.original.fail(owner, Reason::Deadline, at);
            return false;
        }
        // The genuine proof covers all original private writers/readers and
        // same SavedSession jobs. Merely dropping a token is never that proof.
        p.payload = None;
        p.joined = None;
        true
    }

    fn own_retained_bytes(&self) -> Option<usize> {
        let p = self.progress.try_lock().ok()?;
        let mut bytes = std::mem::size_of::<Self>()
            .checked_add(2 * std::mem::size_of::<usize>())?
            .checked_add(
                self.original
                    .own_retained_bytes()?
                    .checked_add(2 * std::mem::size_of::<usize>())?,
            )?;
        if let Some(proof) = &p.joined {
            bytes = bytes.checked_add(
                proof
                    .own_retained_bytes()?
                    .checked_sub(std::mem::size_of::<AppleKeyUseJoined>())?,
            )?;
        }
        // Actual payload/context/key/store/clock backing is visited by the
        // existing Arc-deduplicating census, NOT replaced by this fixed quote.
        Some(bytes)
    }
}

pub(in crate::asset_session) struct LoadRequest {
    loan: Arc<AppleDistributionKeyLoan>,
}
impl LoadRequest {
    pub(in crate::asset_session) fn new(loan: &Arc<AppleDistributionKeyLoan>) -> Self {
        Self { loan: loan.clone() }
    }
}

/// Fixed native child gate for this retained key lane. The ordinary lookup
/// gate continues to refuse ANY retained key work. Each caller performs the
/// SAME document's actual census immediately before this original dispatch;
/// this hook only binds its already charged request to the original key/book.
pub(in crate::asset_session) fn child_admitted(owner: &OriginalWork, child: &Child) -> bool {
    let original = match child {
        Child::CheckAppleDistributionKeyInventory(inventory, _) => &inventory.original,
        Child::LoadAppleDistributionKey(request) => &request.loan.original,
        Child::SaveAppleDistributionKey(request) => request.original(),
        Child::SaveAppleP12(request)=>request.original(),
        _ => return false,
    };
    let Some(held_owner) = original
        .owner
        .upgrade()
        .filter(|same| std::ptr::eq(same.as_ref(), owner))
    else {
        return false;
    };
    if !owner
        .keyring
        .try_lock()
        .is_ok_and(|book| !book.memory_held())
    {
        return false;
    }
    let Ok(work) = owner.vault.try_lock() else {
        return false;
    };
    if work.release
        || work.release_claimed
        || work.failed_child_join.is_some()
        || work
            .store
            .as_ref()
            .is_none_or(|store| !Arc::ptr_eq(store, &original.store))
        || work
            .key
            .as_ref()
            .is_none_or(|key| !Arc::ptr_eq(key, &original.key))
    {
        return false;
    }
    match child {
        Child::CheckAppleDistributionKeyInventory(inventory, point) => {
            !owner.interrupted()
                && work.first.is_none()
                && inventory
                    .checks
                    .try_lock()
                    .is_ok_and(|checks| !checks[point.index()].entered)
        }
        Child::LoadAppleDistributionKey(request) => {
            !owner.interrupted()
                && work.first.is_none()
                && work
                    .apple_distribution_key
                    .loan()
                    .is_some_and(|same| Arc::ptr_eq(same, &request.loan))
                && request.loan.progress.try_lock().is_ok_and(|p| {
                    p.phase == LoadPhase::Reserved && p.first.is_none() && p.payload.is_none()
                })
        }
        Child::SaveAppleP12(request)=> !owner.interrupted() && work.first.is_none() && request.admitted(&held_owner),
        Child::SaveAppleDistributionKey(request) => {
            work.first
                .is_none_or(|(reason, _)| preservation_reason(reason))
                && request.admitted(&held_owner)
        }
        _ => false,
    }
}

/// An actual private load is never a generic selected/assessed/Bind record.
/// Its parent still owes the bundled verifier and all private material joins.
pub(in crate::asset_session) fn load_publication(
    state: &DocumentState,
    session: &Session,
    slot: &Slot,
    work: &super::Work,
    generation: u32,
) -> bool {
    let Some(loan) = work.apple_distribution_key.loan() else {
        return false;
    };
    matches!(slot.operation,Operation::UseAppleDistributionKey|Operation::AssembleAppleP12)
        && generation == loan.original.roster.generation
        && loan
            .original
            .current_data_in_slot(state, session, slot, &slot.owner, false)
        && loan.original.context_identity_current()
        && returned_controls(&slot.owner, false)
        && loan.progress.try_lock().is_ok_and(|p| {
            p.phase == LoadPhase::Loaded
                && p.first.is_none()
                && p.payload.is_some()
                && p.joined.is_none()
        })
}

pub(in crate::asset_session) fn execute_load(
    owner: &Arc<OriginalWork>,
    book: &mut store::StoreBook,
    request: LoadRequest,
) -> Result<ChildResult, Reason> {
    let loan = request.loan;
    let result = (|| {
        loan.original.recheck_store(owner, book)?;
        let mut p = loan.progress.lock().map_err(|_| Reason::CleanupUnknown)?;
        if p.phase != LoadPhase::Reserved
            || p.payload.is_some()
            || p.first.is_some()
            || p.joined.is_some()
        {
            return Err(Reason::VaultInterrupted);
        }
        p.phase = LoadPhase::Reading; // One attempt, before original read entry.
        let read = book
            .read_apple_key_record(&loan.reference.original, loan.allowance, &mut || {
                owner.interrupted()
            })
            .map_err(problem)?;
        let (bytes, witness, complete) = read.into_parts();
        if !complete || witness != loan.reference.original {
            return Err(Reason::SourceChanged);
        }
        let opened = loan
            .original
            .key
            .open_record(bytes, loan.allowance)
            .map_err(crypto_problem)?;
        if opened.record != loan.reference.record
            || opened.revision != loan.reference.revision
            || opened.descriptor.kind != Kind::AppleDistributionKey
            || opened.descriptor.label.is_some()
            || opened.descriptor.has_file()
            || opened.descriptor.presence() != [true; 3]
            || opened.file.is_some()
        {
            return Err(Reason::VaultCorrupt);
        }
        p.payload = Some(Arc::new(Payload {
            kind: Kind::AppleDistributionKey,
            material: None,
            fields: Some(opened.fields),
        }));
        // The actual owned decrypted fields survive every later recheck failure
        // in this same loan; no replacement loan is made on uncertainty.
        if p.payload
            .as_ref()
            .is_none_or(|payload| payload.bytes() > loan.allowance || payload.usable_source())
        {
            return Err(Reason::Capacity);
        }
        loan.original.recheck_store(owner, book)?;
        book.recheck_record(&loan.reference.original, &mut || owner.interrupted())
            .map_err(problem)?;
        if owner.interrupted() {
            return Err(Reason::UserCancelled);
        }
        p.phase = LoadPhase::Loaded;
        Ok(ChildResult::AppleDistributionKeyLoaded)
    })();
    if let Err(reason) = result {
        let at = Instant::now();
        if let Ok(mut p) = loan.progress.lock() {
            p.first.get_or_insert((reason, at));
            p.phase = LoadPhase::Failed;
        }
        loan.original.fail(owner, reason, at);
    }
    result
}

#[cfg(feature = "desktop-shell")]
pub(in crate::asset_session) async fn run_load(
    document: &DocumentBinding,
    owner: &Arc<OriginalWork>,
    request: LoadRequest,
) -> Result<super::super::Staged, Reason> {
    let loan = request.loan.clone();
    {
        let state = document.lock();
        current_gate(document, &state, owner)?;
        if !loan.original.current(document, &state, owner, false)
            || allowance(&state, owner)? < loan.allowance
        {
            return Err(Reason::ContextStale);
        }
        if !owner.vault.try_lock().is_ok_and(|work| {
            work.first.is_none()
                && !work.release
                && work
                    .apple_distribution_key
                    .loan()
                    .is_some_and(|held| Arc::ptr_eq(held, &loan))
        }) {
            return Err(Reason::VaultInterrupted);
        }
    }
    let returned = native(document, owner, Child::LoadAppleDistributionKey(request)).await?;
    let state = document.lock();
    current_gate(document, &state, owner)?;
    if !loan.current(document, &state, owner) {
        return Err(Reason::ContextStale);
    }
    match returned {
        ChildResult::AppleDistributionKeyLoaded => Ok(super::super::Staged::Vault(
            Staged::AppleDistributionKeyLoaded {
                generation: loan.original.roster.generation,
            },
        )),
        _ => Err(Reason::CleanupUnknown),
    }
}

enum Holding {
    Prepare(Arc<AppleDistributionKeyDestination>),
    Use(Arc<AppleDistributionKeyLoan>),
    P12(Arc<AppleP12Destination>),
}
#[derive(Default)]
pub(in crate::asset_session) struct Work {
    inner: Option<Holding>,
}
impl Work {
    pub(in crate::asset_session) fn attach_destination(
        &mut self,
        value: Arc<AppleDistributionKeyDestination>,
    ) -> Result<(), Reason> {
        if self.inner.is_some() {
            return Err(Reason::Busy);
        }
        self.inner = Some(Holding::Prepare(value));
        Ok(())
    }
    pub(in crate::asset_session) fn attach_loan(
        &mut self,
        value: Arc<AppleDistributionKeyLoan>,
    ) -> Result<(), Reason> {
        if self.inner.is_some() {
            return Err(Reason::Busy);
        }
        self.inner = Some(Holding::Use(value));
        Ok(())
    }
    pub(in crate::asset_session) fn attach_p12(&mut self,value:Arc<AppleP12Destination>)->Result<(),Reason> {
        if !self.loan().is_some_and(|loan|value.same_source(loan)) || !matches!(self.inner,Some(Holding::Use(_))) { return Err(Reason::SourceChanged); }
        self.inner=Some(Holding::P12(value)); Ok(())
    }
    pub(in crate::asset_session) fn p12_destination(&self)->Option<&Arc<AppleP12Destination>> { match self.inner.as_ref()? {Holding::P12(value)=>Some(value),_=>None} }
    pub(in crate::asset_session) fn destination(
        &self,
    ) -> Option<&Arc<AppleDistributionKeyDestination>> {
        match self.inner.as_ref()? {
            Holding::Prepare(value) => Some(value),
            Holding::Use(_) | Holding::P12(_) => None,
        }
    }
    pub(in crate::asset_session) fn loan(&self) -> Option<&Arc<AppleDistributionKeyLoan>> {
        match self.inner.as_ref()? {
            Holding::Use(value) => Some(value),
            Holding::P12(value)=>Some(&value.loan),
            Holding::Prepare(_) => None,
        }
    }
    fn original(&self) -> Option<&VaultOriginal> {
        match self.inner.as_ref()? {
            Holding::Prepare(value) => Some(&value.original),
            Holding::Use(value) => Some(&value.original),
            Holding::P12(value)=>Some(&value.loan.original),
        }
    }
    pub(in crate::asset_session) fn empty(&self) -> bool {
        self.inner.is_none()
    }
    pub(in crate::asset_session) fn blocks_reuse(&self) -> bool {
        !self.empty()
    }
    pub(in crate::asset_session) fn retained_bytes(&self) -> Option<usize> {
        match &self.inner {
            None => Some(0),
            Some(Holding::Prepare(value)) => value.retained_bytes(),
            Some(Holding::Use(value)) => value.own_retained_bytes(),
            Some(Holding::P12(value))=>value.own_retained_bytes(),
        }
    }
    fn parent_ready(&self, owner: &Arc<OriginalWork>) -> bool {
        match &self.inner {
            None => true,
            Some(Holding::Prepare(value)) => value.parent_retirement_ready(owner),
            Some(Holding::Use(value)) => value.parent_retirement_ready(owner),
            Some(Holding::P12(value))=>value.parent_retirement_ready(owner),
        }
    }
    fn allows_unstarted_child(&self) -> bool {
        self.destination()
            .is_some_and(|held| held.allows_unstarted_child())
    }
    pub(in crate::asset_session) fn take_for_retirement(&mut self) -> Self {
        let ready = self
            .original()
            .and_then(|o| o.owner.upgrade())
            .is_some_and(|owner| self.parent_ready(&owner));
        if ready {
            Self {
                inner: self.inner.take(),
            }
        } else {
            Self::default()
        }
    }
    pub(in crate::asset_session) fn dispose_private(&mut self) -> bool {
        let Some(original) = self.original() else {
            return true;
        };
        let Some(owner) = original.owner.upgrade() else {
            return false;
        };
        if !original_cleanup_joins(&owner, original, self.allows_unstarted_child())
            || !self.parent_ready(&owner)
        {
            return false;
        }
        let disposed = match self.inner.as_ref() {
            Some(Holding::Prepare(value)) => value.dispose_private(&owner),
            Some(Holding::Use(value)) => value.dispose_private(&owner),
            Some(Holding::P12(value))=>value.dispose_private(&owner),
            None => true,
        };
        if !disposed {
            return false;
        }
        if original.save_cleanup_expired() {
            original.fail(&owner, Reason::Deadline, Instant::now());
            return false;
        }
        self.inner = None; // Off-lock actual custody disposal, never Drop-as-proof.
        true
    }

    // Actual existing census uses these borrowed originals and its seen-Arc
    // sets; no private scalar values or owned material copy is returned.
    pub(in crate::asset_session) fn context(&self) -> Option<&Arc<NativeContext>> {
        Some(&self.original()?.context)
    }
    pub(in crate::asset_session) fn key(&self) -> Option<&Arc<crypto::VaultKey>> {
        Some(&self.original()?.key)
    }
    pub(in crate::asset_session) fn store(&self) -> Option<&Arc<Mutex<store::StoreBook>>> {
        Some(&self.original()?.store)
    }
    pub(in crate::asset_session) fn payload(&self) -> Result<Option<Arc<Payload>>, Reason> {
        self.loan().map_or(Ok(None), |loan| loan.payload())
    }
}

fn known_cleanup_failure(first: Option<(Reason, Instant)>) -> bool {
    first.is_none_or(|(reason, _)| {
        matches!(
            reason,
            Reason::UserCancelled
                | Reason::Shutdown
                | Reason::DocumentLost
                | Reason::ContextStale
                | Reason::Deadline
                | Reason::ReviewExpired
                | Reason::Closed
                | Reason::Unqualified
                | Reason::UnsupportedPlatform
                | Reason::UnsupportedFilesystem
                | Reason::UnsupportedFormat
                | Reason::InvalidRequest
                | Reason::Busy
                | Reason::SourceRefused
                | Reason::SourceChanged
                | Reason::MaterialLimit
                | Reason::ParserLimit
                | Reason::ProjectOverlap
                | Reason::ExclusionUnconfirmed
                | Reason::Capacity
                | Reason::VaultUninitialized
                | Reason::VaultKeyMissing
                | Reason::VaultKeyringLocked
                | Reason::VaultKeyringDenied
                | Reason::VaultKeyringUnavailable
                | Reason::VaultProviderUnsupported
                | Reason::VaultInterrupted
        )
    })
}
fn returned_controls(owner: &OriginalWork, unstarted: bool) -> bool {
    owner.control_resources_settled()
        && owner
            .coordinator
            .try_lock()
            .is_ok_and(|b| b.handle.is_none() && b.receipt == JoinReceipt::Returned)
        && owner.child.try_lock().is_ok_and(|b| {
            b.handle.is_none()
                && (b.receipt == JoinReceipt::Returned
                    || unstarted && b.receipt == JoinReceipt::New)
        })
}
fn original_cleanup_joins(owner: &OriginalWork, original: &VaultOriginal, unstarted: bool) -> bool {
    !original.save_cleanup_expired()
        && returned_controls(owner, unstarted)
        && owner.vault.try_lock().is_ok_and(|work| {
            matches!(work.original_join, None | Some(JoinReceipt::Returned))
                && work.failed_child_join.is_none()
                && known_cleanup_failure(work.first)
                && work
                    .store
                    .as_ref()
                    .is_some_and(|held| Arc::ptr_eq(held, &original.store))
                && original.store.try_lock().is_ok_and(|book| {
                    if work.release {
                        work.release_claimed && work.release_end.is_some() && book.settled()
                    } else {
                        !work.release_claimed
                            && book.problem().is_none()
                            && book.lease_held()
                            && book.operation_quiescent()
                    }
                })
        })
}

pub(in crate::asset_session) fn retirement_ready(owner: &Arc<OriginalWork>) -> bool {
    if !owner.retired.load(Ordering::SeqCst) {
        return false;
    }
    // Do not hold Work while a predicate attempts to re-borrow that same book.
    let held = match owner.vault.try_lock() {
        Ok(work) => match &work.apple_distribution_key.inner {
            Some(Holding::Prepare(value)) => Holding::Prepare(value.clone()),
            Some(Holding::Use(value)) => Holding::Use(value.clone()),
            Some(Holding::P12(value))=>Holding::P12(value.clone()),
            None => return false,
        },
        Err(_) => return false,
    };
    let original = match &held {
        Holding::Prepare(value) => &value.original,
        Holding::Use(value) => &value.original,
        Holding::P12(value)=>&value.loan.original,
    };
    let unstarted = match &held {
        Holding::Prepare(value) => value.allows_unstarted_child(),
        Holding::Use(_) | Holding::P12(_) => false,
    };
    original_cleanup_joins(owner, original, unstarted)
        && match held {
            Holding::Prepare(value) => value.parent_retirement_ready(owner),
            Holding::Use(value) => value.parent_retirement_ready(owner),
            Holding::P12(value)=>value.parent_retirement_ready(owner),
        }
}

pub(in crate::asset_session) fn retirement_deferred(slot: &Slot) -> bool {
    if !matches!(
        slot.operation,
        Operation::PrepareAppleDistributionKey | Operation::UseAppleDistributionKey | Operation::AssembleAppleP12
    ) {
        return false;
    }
    let retained = slot
        .owner
        .vault
        .try_lock()
        .map_or(true, |work| work.apple_distribution_key.blocks_reuse());
    retained && !retirement_ready(&slot.owner)
}

/// Report-only cleanup exception AFTER the actual parent has finished all
/// work-capable jobs and supplied its one saved/never-generated/use proof.
/// This does not dispose data, permit a store mutation, clear Unknown or claim
/// a still-running Asset coordinator joined. A claimed Release must really
/// have returned closed; before Release only original known quiescence fits.
pub(in crate::asset_session) fn known_cleanup_report(owner: &Arc<OriginalWork>) -> bool {
    let Ok(work) = owner.vault.try_lock() else {
        return false;
    };
    let holding = &work.apple_distribution_key;
    let Some(original) = holding.original() else {
        return false;
    };
    known_cleanup_failure(work.first)
        && !original.save_cleanup_expired()
        && original.same_owner(owner)
        && matches!(work.original_join, None | Some(JoinReceipt::Returned))
        && work.failed_child_join.is_none()
        && owner.child.try_lock().is_ok_and(|child| {
            child.handle.is_none()
                && (child.receipt == JoinReceipt::Returned
                    || holding.allows_unstarted_child() && child.receipt == JoinReceipt::New)
        })
        && original.store.try_lock().is_ok_and(|book| {
            if work.release_claimed {
                book.settled()
            } else {
                book.problem().is_none() && book.lease_held() && book.operation_quiescent()
            }
        })
        && holding.parent_ready(owner)
}

/// Same cleanup-only release continuation used by the vault. The parent proof
/// covers all work-capable jobs; it must not depend on this future Store close
/// or Asset private-empty (that would create a disposal/finality cycle).
pub(in crate::asset_session) fn release_retained_private_ready(
    state: &DocumentState,
    slot: &Slot,
) -> bool {
    if !matches!(
        slot.operation,
        Operation::PrepareAppleDistributionKey | Operation::UseAppleDistributionKey | Operation::AssembleAppleP12
    ) || slot.target.is_some()
    {
        return false;
    }
    let Some(session) = &state.vault else {
        return false;
    };
    let Ok(work) = slot.owner.vault.try_lock() else {
        return false;
    };
    let holding = &work.apple_distribution_key;
    let Some(original) = holding.original() else {
        return false;
    };
    session.revoked
        && !original.save_cleanup_expired()
        && work.release
        && !work.release_claimed
        && work.release_end.is_some()
        && work.original_join.is_none()
        && work.failed_child_join.is_none()
        && known_cleanup_failure(work.first)
        && returned_controls(&slot.owner, holding.allows_unstarted_child())
        && original.same_owner(&slot.owner)
        && session.identity == Some(original.key.identity())
        && Arc::ptr_eq(&session.store, &original.store)
        && work
            .store
            .as_ref()
            .is_some_and(|store| Arc::ptr_eq(store, &original.store))
        && session
            .key
            .as_ref()
            .is_some_and(|key| Arc::ptr_eq(key, &original.key))
        && work
            .key
            .as_ref()
            .is_some_and(|key| Arc::ptr_eq(key, &original.key))
        && slot
            .context
            .as_ref()
            .is_some_and(|context| Arc::ptr_eq(context, &original.context))
        && original
            .store
            .try_lock()
            .is_ok_and(|book| book.operation_quiescent())
        && holding.parent_ready(&slot.owner)
}

/// Only metadata from this exact already-joined operation may remain while
/// the SAME StoreBook release continuation runs. No Mutated row, private
/// candidate or unproved save is consumed or re-published by this exception.
pub(in crate::asset_session) fn cleanup_staged_allowed(slot: &Slot, retained_ready: bool) -> bool {
    if slot.staged.is_none() {
        return true;
    }
    retained_ready
        && matches!(
            slot.operation,
            Operation::PrepareAppleDistributionKey | Operation::UseAppleDistributionKey | Operation::AssembleAppleP12
        )
        && match slot.staged.as_ref() {
            Some(super::super::Staged::Refused(_))
            | Some(super::super::Staged::Committed { bind: None }) => true,
            Some(super::super::Staged::Vault(Staged::AppleDistributionKeyLoaded {
                generation,
            })) => {
                slot.operation == Operation::UseAppleDistributionKey
                    && slot.vault.generation == Some(*generation)
            }
            _ => false,
        }
}

#[cfg(all(test, debug_assertions))]
mod tests {
    use super::*;
    fn id(byte: u8) -> format::Id {
        format::Id::from_bytes([byte; 16]).unwrap()
    }
    fn reference() -> StoredRef {
        let revision = format::Revision::new(id(4), 1).unwrap();
        StoredRef {
            identity: format::Identity::new(id(1), id(2)).unwrap(),
            record: id(3),
            revision,
            original: store::ReadWitness::lifecycle_data(id(3), revision),
        }
    }
    pub(super) fn state_data(operation: Operation) -> (DocumentState, Arc<OriginalWork>) {
        let mut state = super::super::tests::loan_state();
        let owner = OriginalWork::new(71, false, Weak::new());
        let session = state.vault.as_ref().unwrap();
        attach(&owner, session, true, false)
            .unwrap_or_else(|_| panic!("inert original association"));
        let mut slot = Slot::new(owner.clone(), operation, state.context.clone(), None, None);
        slot.vault.lease = Some(session.store.clone());
        slot.vault.generation = Some(session.registry_generation);
        state.slot = Some(slot);
        (state, owner)
    }
    pub(super) fn row_data(record: u8, kind: Kind) -> Descriptor {
        let record = id(record);
        let revision = format::Revision::new(id(70), 1).unwrap();
        Descriptor {
            authenticated: crypto::AuthenticatedDescriptor {
                record,
                revision,
                descriptor: format::Descriptor::new(
                    kind,
                    None,
                    if kind == Kind::AppleDistributionKey {
                        vec![true; 3]
                    } else {
                        vec![true]
                    },
                    false,
                )
                .unwrap(),
            },
            original: store::ReadWitness::lifecycle_data(record, revision),
            mutation_pending: false,
        }
    }
    #[test]
    fn complete_key_inventory_refuses_missing_duplicate_or_pending_unrelated_rows() {
        let (mut state, _) = state_data(Operation::PrepareAppleDistributionKey);
        let session = state.vault.as_mut().unwrap();
        session.rows.clear();
        session.inventory.clear();
        session.rows.push(row_data(8, Kind::ProjectReadToken));
        assert!(!complete_session_inventory(session));
        session.inventory.push(id(8));
        assert!(complete_session_inventory(session));
        let identity = session.identity.unwrap();
        let captured = [InventoryRow {
            kind: Kind::ProjectReadToken,
            reference: session.rows[0].reference(identity),
        }];
        assert!(inventory_rows_match(&captured, identity, session));
        session.rows[0].mutation_pending = true;
        assert!(!complete_session_inventory(session));
        session.rows[0].mutation_pending = false;
        session.rows[0].original =
            store::ReadWitness::lifecycle_data(id(9), session.rows[0].authenticated.revision);
        assert!(!inventory_rows_match(&captured, identity, session));
        session.rows[0] = row_data(8, Kind::ProjectReadToken);
        session.rows.push(row_data(8, Kind::ProjectReadToken));
        session.inventory.push(id(8));
        assert!(!complete_session_inventory(session));
        session.rows[1] = row_data(10, Kind::AppleDistributionKey);
        session.inventory[1] = id(10);
        assert!(complete_session_inventory(session));
        assert!(!inventory_rows_match(&captured, identity, session));
        // Counts/plain descriptors never construct the original checked
        // Inventory or a no-existing-key/Pending acknowledgement.
    }
    #[test]
    fn key_save_state_half_keeps_cancel_but_refuses_explicit_revoke_loss_and_same_ids() {
        let (mut state, owner) = state_data(Operation::PrepareAppleDistributionKey);
        state
            .slot
            .as_mut()
            .unwrap()
            .stop(Reason::UserCancelled, Instant::now());
        let scope = |state: &DocumentState, owner: &Arc<OriginalWork>| {
            save_scope_data(
                state,
                state.vault.as_ref().unwrap(),
                state.slot.as_ref().unwrap(),
                owner,
                false,
            )
        };
        assert!(scope(&state, &owner)); // Only DATA: NO opaque permit or join is fabricated.
        assert!(!scope(
            &state,
            &OriginalWork::new(owner.id, false, Weak::new())
        ));
        state.stopping = true;
        state.quit_pending = true;
        assert!(scope(&state, &owner)); // Full predicate still requires actual parent clock/mask.
        state.lock_pending = true;
        assert!(!scope(&state, &owner));
        state.lock_pending = false;
        state.unknown = true;
        assert!(!scope(&state, &owner));
        state.unknown = false;
        state.vault.as_mut().unwrap().read_only = true;
        assert!(!scope(&state, &owner));
        state.vault.as_mut().unwrap().read_only = false;
        state.slot.as_mut().unwrap().reason = Reason::SourceChanged;
        assert!(!scope(&state, &owner));
        state.slot.as_mut().unwrap().reason = Reason::UserCancelled;
        super::super::revoke_all(&mut state);
        assert!(state.vault.as_ref().unwrap().revoked);
        assert!(!scope(&state, &owner));
    }
    #[test]
    fn automatic_stop_still_revokes_ordinary_or_unbound_key_operations() {
        for operation in [
            Operation::Prepare,
            Operation::Commit,
            Operation::UseAppleDistributionKey,
            Operation::PrepareAppleDistributionKey,
        ] {
            let (mut state, owner) = state_data(operation);
            let at = Instant::now();
            state.slot.as_mut().unwrap().stop(Reason::UserCancelled, at);
            assert!(super::super::observe_stop(&mut state, at));
            assert!(state.vault.as_ref().unwrap().revoked);
            assert!(owner.vault.try_lock().unwrap().release);
            // An operation enum/ID alone has no predeclared SAME-parent save
            // slot, even for key preparation. No native call was entered.
        }
    }
    #[test]
    fn cleanup_metadata_never_grants_a_missing_parent_or_republishes_new_record_data() {
        for operation in [
            Operation::PrepareAppleDistributionKey,
            Operation::UseAppleDistributionKey,
        ] {
            let (mut state, _) = state_data(operation);
            let slot = state.slot.as_mut().unwrap();
            let at = Instant::now();
            slot.stop(Reason::UserCancelled, at);
            slot.staged = Some(super::super::super::Staged::Refused(Reason::UserCancelled));
            assert!(!cleanup_staged_allowed(slot, false));
            assert!(cleanup_staged_allowed(slot, true)); // Metadata conjunct only.
            assert_eq!(slot.reason, Reason::UserCancelled);
            assert!(matches!(
                slot.staged,
                Some(super::super::super::Staged::Refused(Reason::UserCancelled))
            )); // The actual staged value was not taken or disposed.
            slot.staged = Some(super::super::super::Staged::Committed { bind: None });
            assert!(!cleanup_staged_allowed(slot, false));
            assert!(cleanup_staged_allowed(slot, true));
            let generation = slot.vault.generation.unwrap();
            slot.staged = Some(super::super::super::Staged::Vault(
                Staged::AppleDistributionKeyLoaded { generation },
            ));
            assert_eq!(
                cleanup_staged_allowed(slot, true),
                operation == Operation::UseAppleDistributionKey
            );
            slot.staged = Some(super::super::super::Staged::Vault(
                Staged::AppleDistributionKeyLoaded {
                    generation: generation + 1,
                },
            ));
            assert!(!cleanup_staged_allowed(slot, true));
            slot.staged = Some(super::super::super::Staged::Vault(Staged::Mutated {
                record: id(9),
                row: Some(row_data(9, Kind::AppleDistributionKey)),
                generation,
            }));
            assert!(!cleanup_staged_allowed(slot, true));
        }
        let (mut ordinary, _) = state_data(Operation::Commit);
        let slot = ordinary.slot.as_mut().unwrap();
        slot.staged = Some(super::super::super::Staged::Refused(Reason::UserCancelled));
        assert!(!cleanup_staged_allowed(slot, true));
        // No test constructs a SavedSession proof, returned native handle or
        // private key. The real retained_ready gate independently requires all.
    }
    #[test]
    fn original_cleanup_window_never_renews_after_a_late_disposal_return() {
        let admitted = Instant::now();
        let hard = admitted + std::time::Duration::from_secs(20);
        let first_cleanup = admitted + std::time::Duration::from_secs(3);
        assert!(cleanup_window_open(false, first_cleanup, hard, admitted));
        assert!(!cleanup_window_open(
            false,
            first_cleanup,
            hard,
            first_cleanup
        ));
        assert!(!cleanup_window_open(false, first_cleanup, hard, hard));
        assert!(!cleanup_window_open(
            false,
            hard + std::time::Duration::from_secs(2),
            hard,
            hard
        ));
        assert!(!cleanup_window_open(true, first_cleanup, hard, admitted));
        // The same comparison is used before original joins/disposal and after
        // the actual one-use proof returns. No new deadline is constructed.
    }
    #[test]
    fn stored_key_comparison_keeps_full_revision_and_physical_witness() {
        // Deliberately zero-mode witness DATA, not file/key/custody authority.
        let original = reference();
        assert!(same_reference(original, original));
        let mut changed = original;
        changed.identity = format::Identity::new(id(1), id(5)).unwrap();
        assert!(!same_reference(original, changed));
        changed = original;
        changed.revision = format::Revision::new(id(6), 1).unwrap();
        assert!(!same_reference(original, changed));
        changed = original;
        changed.original = store::ReadWitness::lifecycle_data(id(7), original.revision);
        assert!(!same_reference(original, changed));
    }
    #[test]
    fn unknown_or_corrupt_storage_never_becomes_known_cleanup_by_cancellation() {
        let at = Instant::now();
        assert!(known_cleanup_failure(Some((Reason::UserCancelled, at))));
        assert!(known_cleanup_failure(Some((Reason::SourceRefused, at))));
        for reason in [
            Reason::CleanupUnknown,
            Reason::VaultCorrupt,
            Reason::VaultDurabilityUnknown,
        ] {
            assert!(!known_cleanup_failure(Some((reason, at))));
        }
        // These are only one conjunct. No test constructs a native parent
        // token or upgrades a pending/failed producer to a joined original.
    }
    #[test]
    fn an_empty_work_has_no_disposal_or_key_loan_capability() {
        let mut work = Work::default();
        assert!(work.empty() && !work.blocks_reuse());
        assert!(work.destination().is_none() && work.loan().is_none());
        assert_eq!(work.retained_bytes(), Some(0));
        assert!(work.take_for_retirement().empty());
        assert!(work
            .payload()
            .unwrap_or_else(|_| panic!("empty DATA"))
            .is_none());
    }
}
