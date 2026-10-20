//! Exact selected P8 custody for the existing Apple key operation.
//! The complete authenticated vault inventory is checked by the existing
//! fixed native child; this source neither enumerates files nor creates keys.
use super::distribution_key::{AppleDistributionKeyInventory, InventoryPoint};
use super::*;
use crate::{credential_setup::KeyReference, saved_command_owner::AppleKeySession};
use std::sync::{OnceLock, Weak};

#[path = "credential_apple_certificate_source.rs"]
pub(in crate::asset_session) mod certificate;

pub(crate) struct AppleKeySources {
    p8: BoundLoan,
    roster: ProjectRoster,
    owner: OnceLock<Weak<OriginalWork>>,
    inventory: OnceLock<Arc<AppleDistributionKeyInventory>>,
    certificate: Option<certificate::CertificateSource>,
}
impl AppleKeySources {
    pub(in crate::asset_session) fn capture(
        document: &DocumentBinding,
        state: &DocumentState,
        native: &Arc<NativeContext>,
        key: &RecordKey,
        payload: &Arc<Payload>,
        selected_key: Option<&RecordKey>,
    ) -> Result<Arc<Self>, Reason> {
        if !document.native_qualified()
            || !document.persistence_qualified()
            || native.purpose != Purpose::Provisioning
            || native.platform != Platform::Ios
            || native.stage != Stage::Candidate
            || native.execution_mode != commands::ExecutionMode::Local
        {
            return Err(Reason::Unqualified);
        }
        let session = state.vault.as_ref().ok_or(Reason::VaultKeyMissing)?;
        let mut matching = session.bound.iter().flatten().filter(|loan| {
            loan.payload.kind == Kind::AscP8
                && Arc::ptr_eq(&loan.context, native)
                && Arc::ptr_eq(&loan.payload, payload)
                && loan.reference.matches(key)
                && loan.current(state, session)
        });
        let loan = matching.next().ok_or(Reason::SourceRefused)?;
        if matching.next().is_some() {
            return Err(Reason::SourceChanged);
        }
        let roster = document
            .inner
            .bridge
            .native_roster()
            .map_err(|error| error.reason)?;
        if roster.generation != native.registry_generation
            || roster.roots.len() > 32
            || roster.roots.capacity() > 32
            || !roster.roots.contains(&native.project)
        {
            return Err(Reason::ContextStale);
        }
        let certificate = selected_key.map(|key| certificate::CertificateSource::capture(state, key, loan)).transpose()?;
        Ok(Arc::new(Self {
            p8: BoundLoan {
                context: loan.context.clone(),
                payload: loan.payload.clone(),
                reference: loan.reference,
                store: loan.store.clone(),
                key: loan.key.clone(),
            },
            roster,
            owner: OnceLock::new(),
            inventory: OnceLock::new(),
            certificate,
        }))
    }
    pub(in crate::asset_session) fn native(&self) -> &Arc<NativeContext> {
        &self.p8.context
    }
    pub(in crate::asset_session) fn roster(&self) -> &ProjectRoster {
        &self.roster
    }
    pub(in crate::asset_session) fn loan(&self) -> &BoundLoan {
        &self.p8
    }
    pub(crate) fn reference(&self) -> KeyReference {
        let source = self.p8.reference;
        KeyReference::native(source.identity, source.record, source.revision)
    }
    pub(in crate::asset_session) fn owner(&self) -> Option<Arc<OriginalWork>> {
        self.owner.get().and_then(Weak::upgrade)
    }
    pub(in crate::asset_session) fn same_owner(&self, owner: &Arc<OriginalWork>) -> bool {
        self.owner().is_some_and(|same| Arc::ptr_eq(&same, owner))
    }
    pub(in crate::asset_session) fn same_selection(&self, other: &Self) -> bool {
        let left = self.p8.reference;
        let right = other.p8.reference;
        Arc::ptr_eq(&self.p8.context, &other.p8.context)
            && Arc::ptr_eq(&self.p8.payload, &other.p8.payload)
            && Arc::ptr_eq(&self.p8.key, &other.p8.key)
            && Arc::ptr_eq(&self.p8.store, &other.p8.store)
            && left.identity == right.identity
            && left.record == right.record
            && left.revision == right.revision
            && left.original == right.original
            && match (&self.certificate, &other.certificate) { (None,None)=>true,(Some(a),Some(b))=>a.same(b),_=>false }
            && self.roster.generation == other.roster.generation
            && self.roster.roots == other.roster.roots
    }
    pub(in crate::asset_session) fn current(
        &self,
        document: &DocumentBinding,
        state: &DocumentState,
    ) -> bool {
        state
            .vault
            .as_ref()
            .is_some_and(|session| self.p8.current(state, session))
            && self.certificate.as_ref().is_none_or(|source| source.current(self, document, state))
            && document.inner.bridge.registry_generation() == self.roster.generation
            && document
                .context_matches(state, &self.p8.context)
                .unwrap_or(false)
    }
    /// Fixed cancelled-key preservation only. Ordinary assignment availability
    /// may be withdrawn by STOP; it is NOT a substitute for the retained full
    /// source/key/Store/row/context checks below or the parent's opaque cutoff.
    pub(in crate::asset_session) fn preservation_current(
        &self,
        document: &DocumentBinding,
        state: &DocumentState,
        owner: &Arc<OriginalWork>,
        parent: &AppleKeySession,
    ) -> bool {
        let Some(session) = &state.vault else {
            return false;
        };
        self.same_owner(owner)
            && parent.preservation_pending(owner)
            && !state.session
            && state.lifetime.original_bound()
            && !state.lost_observed
            && !state.unknown
            && !state.exhausted
            && !state.lock_pending
            && !state.compatibility_picker_pending
            && !state.retiring
            && !session.revoked
            && !session.read_only
            && matches!(session.state, State::Unlocked | State::Mutating)
            && Arc::ptr_eq(&session.store, &self.p8.store)
            && session
                .key
                .as_ref()
                .is_some_and(|key| Arc::ptr_eq(key, &self.p8.key))
            && session.identity == Some(self.p8.reference.identity)
            && self.p8.key.identity() == self.p8.reference.identity
            && state
                .context
                .as_ref()
                .is_some_and(|context| Arc::ptr_eq(context, &self.p8.context))
            && self.p8.payload.usable_source()
            && session.registry_generation == self.roster.generation
            && session.rows.iter().any(|row| {
                !row.mutation_pending
                    && row.authenticated.descriptor.kind == Kind::AscP8
                    && row.authenticated.record == self.p8.reference.record
                    && row.authenticated.revision == self.p8.reference.revision
                    && row.original == self.p8.reference.original
            })
            && state.slot.as_ref().is_some_and(|slot| {
                Arc::ptr_eq(&slot.owner, owner)
                    && slot.operation == Operation::PrepareAppleDistributionKey
                    && slot.target.is_none()
                    && slot
                        .context
                        .as_ref()
                        .is_some_and(|context| Arc::ptr_eq(context, &self.p8.context))
                    && slot.settlement != Settlement::Unknown
                    && slot.phase != Phase::Unknown
            })
            && document.inner.bridge.registry_generation() == self.roster.generation
            && document
                .inner
                .bridge
                .native_project(&self.p8.context.project_id)
                .is_ok_and(|(generation, root)| {
                    generation == self.roster.generation && root == self.p8.context.project
                })
    }
    pub(in crate::asset_session) fn bind_inventory(
        &self,
        owner: &Arc<OriginalWork>,
        inventory: Arc<AppleDistributionKeyInventory>,
    ) -> Result<(), Reason> {
        if !self.same_owner(owner)
            || !Arc::ptr_eq(inventory.context(), &self.p8.context)
            || !Arc::ptr_eq(inventory.key(), &self.p8.key)
            || !Arc::ptr_eq(inventory.store(), &self.p8.store)
        {
            return Err(Reason::SourceChanged);
        }
        self.inventory
            .set(inventory)
            .map_err(|_| Reason::ContextStale)
    }
    pub(in crate::asset_session) fn inventory(
        &self,
    ) -> Option<&Arc<AppleDistributionKeyInventory>> {
        self.inventory.get()
    }
    pub(in crate::asset_session) fn checked(
        &self,
        owner: &Arc<OriginalWork>,
        point: InventoryPoint,
    ) -> bool {
        self.same_owner(owner)
            && self
                .inventory
                .get()
                .is_some_and(|inventory| inventory.checked(owner, point))
    }
    pub(crate) fn own_retained_bytes(&self) -> Option<usize> {
        let mut bytes = std::mem::size_of::<Self>()
            .checked_add(2 * std::mem::size_of::<usize>())?
            .checked_add(
                self.roster
                    .roots
                    .capacity()
                    .checked_mul(std::mem::size_of::<asset_source::RegisteredRoot>())?,
            )?;
        for root in &self.roster.roots {
            bytes = bytes.checked_add(root.path.capacity())?;
        }
        if self.certificate.is_some() {
            bytes=bytes.checked_add(certificate::CertificateSource::weak_backing_bytes()?)?;
        }
        // The existing Arc-deduplicating census visits the Inventory/BoundLoan
        // context/key/store backing separately (also held by a destination).
        Some(bytes)
    }
}

pub(in crate::asset_session) fn attach(
    state: &DocumentState,
    owner: &Arc<OriginalWork>,
    sources: &Arc<AppleKeySources>,
) -> Result<(), Reason> {
    let session = state.vault.as_ref().ok_or(Reason::VaultKeyMissing)?;
    if !session.writable()
        || owner.interrupted()
        || !Arc::ptr_eq(&session.store, &sources.p8.store)
        || session
            .key
            .as_ref()
            .is_none_or(|key| !Arc::ptr_eq(key, &sources.p8.key))
    {
        return Err(Reason::SourceChanged);
    }
    super::attach(owner, session, true, false).map_err(|error| error.reason)?;
    sources
        .owner
        .set(Arc::downgrade(owner))
        .map_err(|_| Reason::ContextStale)
}

/// Only a genuinely never-installed/never-entered Asset original uses this
/// path. It owns no new filesystem acquisition and cannot close by dropping a
/// Store Arc; the original book must already be positively quiescent.
pub(in crate::asset_session) fn retire_unentered(owner: &Arc<OriginalWork>) -> bool {
    let Ok(mut work) = owner.vault.try_lock() else {
        return false;
    };
    if work.outcome.is_some()
        || work.release_claimed
        || work.original_join.is_some()
        || work.failed_child_join.is_some()
        || work.apple_distribution_key.blocks_reuse()
        || work.store.as_ref().is_some_and(|store| {
            !store.try_lock().is_ok_and(|book| {
                book.not_started() || book.settled() || book.operation_quiescent()
            })
        })
    {
        return false;
    }
    work.key.take();
    work.store.take();
    work.apple_clock.take();
    true
}
