//! Fixed NEW-only sink for an Apple pending private key, on the same vault
//! Child/StoreBook as ordinary storage and backup restore. This is deliberately
//! not a general reserved-kind writer. The SAME Apple parent owns all permits.
use super::*;
use crate::saved_command_owner::{
    AppleKeyNeverGeneratedJoined, AppleKeyPendingAck, AppleKeySavePermit,
};
use std::sync::OnceLock;

const KNOWN_NEW: store::StorageOutcome = store::StorageOutcome {
    effect: store::Effect::KnownApplied,
    durability: store::Durability::Confirmed,
    cleanup: store::Cleanup::Known,
};
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Reserved,
    Pending,
    SaveClaimed,
    Storing,
    Readback,
    Stored,
    Published,
    Failed,
}
struct Progress {
    phase: Phase,
    first: Option<(Reason, Instant)>,
    reserved: crypto::ReservedAppleDistributionKey,
    pending: Option<AppleKeyPendingAck>,
    permit: Option<AppleKeySavePermit>,
    never_generated: Option<AppleKeyNeverGeneratedJoined>,
    cipher: Option<crypto::SealedRecord>,
    intent: Option<[u8; format::INTENT_BYTES]>,
    outcome: Option<store::StorageOutcome>,
    saved: Option<StoredRef>,
}
impl Progress {
    fn enter(&mut self, expected: Phase, next: Phase) -> Result<(), Reason> {
        if self.phase != expected || self.first.is_some() || self.never_generated.is_some() {
            return Err(Reason::VaultInterrupted);
        }
        self.phase = next;
        Ok(())
    }
    fn fail(&mut self, reason: Reason, at: Instant) {
        self.first.get_or_insert((reason, at));
        self.phase = Phase::Failed;
    }
    fn saved(&self) -> bool {
        self.first.is_none()
            && self.outcome == Some(KNOWN_NEW)
            && self.saved.is_some()
            && self.cipher.is_none()
            && matches!(self.phase, Phase::Stored | Phase::Published)
    }
    fn save_unattempted(&self) -> bool {
        !self.reserved.attempted()
            && self.permit.is_none()
            && self.cipher.is_none()
            && self.intent.is_none()
            && self.outcome.is_none()
            && self.saved.is_none()
            && matches!(self.phase, Phase::Reserved | Phase::Pending | Phase::Failed)
    }
}

pub(crate) struct AppleDistributionKeyDestination {
    pub(super) original: Arc<VaultOriginal>,
    inventory: Arc<AppleDistributionKeyInventory>,
    identity: format::Identity,
    record: format::Id,
    revision: format::Revision,
    allowance: usize,
    published: OnceLock<StoredRef>,
    failed: AtomicBool,
    never_generated_accepted: AtomicBool,
    progress: Mutex<Progress>,
}
impl AppleDistributionKeyDestination {
    pub(in crate::asset_session) fn reserve(
        document: &DocumentBinding,
        state: &mut DocumentState,
        owner: &Arc<OriginalWork>,
        inventory: Arc<AppleDistributionKeyInventory>,
        allowance: usize,
    ) -> Result<Arc<Self>, Reason> {
        if allowance != crypto::APPLE_KEY_CRYPTO_BYTES {
            return Err(Reason::Capacity);
        }
        // Initial is already an actual returned Check on this original. The
        // second BeforePending check must happen AFTER this nonsecret identity
        // reservation and immediately before the parent's journal/ACK; do not
        // consume that freshness slot early here.
        if !inventory.current(document, state, owner) || !inventory.generation_empty(owner) {
            return Err(Reason::SourceChanged);
        }
        let original = inventory.original.clone();
        let session = state.vault.as_mut().ok_or(Reason::VaultKeyMissing)?;
        if session.rows.len() >= store::DESCRIPTOR_COUNT
            || session.inventory.len() >= store::DESCRIPTOR_COUNT
        {
            return Err(Reason::Capacity);
        }
        // Same native census must admit this live backing before construction.
        // Reserve final publication capacity before the generator can run.
        session
            .rows
            .try_reserve_exact(1)
            .map_err(|_| Reason::Capacity)?;
        session
            .inventory
            .try_reserve_exact(1)
            .map_err(|_| Reason::Capacity)?;
        let reserved =
            crypto::ReservedAppleDistributionKey::reserve(&original.key, &session.inventory)
                .map_err(crypto_problem)?;
        let (identity, record, revision) = reserved.descriptor();
        Ok(Arc::new(Self {
            original,
            inventory,
            identity,
            record,
            revision,
            allowance,
            published: OnceLock::new(),
            failed: AtomicBool::new(false),
            never_generated_accepted: AtomicBool::new(false),
            progress: Mutex::new(Progress {
                phase: Phase::Reserved,
                first: None,
                reserved,
                pending: None,
                permit: None,
                never_generated: None,
                cipher: None,
                intent: None,
                outcome: None,
                saved: None,
            }),
        }))
    }
    pub(crate) fn descriptor(&self) -> KeyReference {
        KeyReference::native(self.identity, self.record, self.revision)
    }

    pub(crate) fn inventory(&self) -> &Arc<AppleDistributionKeyInventory> {
        &self.inventory
    }

    pub(super) fn preservation_unfailed(&self) -> bool {
        !self.failed.load(Ordering::SeqCst)
    }

    /// Immutable, equal-only parent binding. No progress/Doc/Store lock and no
    /// callback into a permit while the parent is constructing/checking it.
    pub(crate) fn original_binding(
        &self,
        owner: &Arc<OriginalWork>,
        reference: &KeyReference,
    ) -> bool {
        self.original.same_owner(owner)
            && reference
                .parts()
                .is_ok_and(|parts| parts == (self.identity, self.record, self.revision))
    }

    pub(crate) fn recheck(&self, owner: &Arc<OriginalWork>) -> Result<(), Reason> {
        if self.failed.load(Ordering::SeqCst) {
            return Err(Reason::VaultInterrupted);
        }
        let mut book = self
            .original
            .store
            .lock()
            .map_err(|_| Reason::CleanupUnknown)?;
        self.original.recheck_store(owner, &mut book)?;
        book.recheck_apple_key_inventory(&self.inventory.witnesses, None, &mut || {
            owner.interrupted()
        })
        .map_err(problem)
    }
    fn fail(&self, owner: &Arc<OriginalWork>, reason: Reason, at: Instant) {
        self.failed.store(true, Ordering::SeqCst);
        self.original.fail(owner, reason, at);
    }
    pub(crate) fn record_pending(
        &self,
        owner: &Arc<OriginalWork>,
        ack: AppleKeyPendingAck,
    ) -> Result<(), Reason> {
        let mut p = self.progress.lock().map_err(|_| Reason::CleanupUnknown)?;
        if p.pending.is_some() || p.never_generated.is_some() || p.phase != Phase::Reserved {
            return Err(Reason::VaultInterrupted);
        }
        p.pending = Some(ack); // Original durable CAS acknowledgement, retained before checks.
        if !self.original.same_owner(owner)
            || owner.interrupted()
            || !self.inventory.checked(owner, InventoryPoint::BeforePending)
            || !p
                .pending
                .as_ref()
                .is_some_and(|ack| ack.matches(self, owner))
        {
            let at = Instant::now();
            p.fail(Reason::ContextStale, at);
            self.fail(owner, Reason::ContextStale, at);
            return Err(Reason::ContextStale);
        }
        p.enter(Phase::Reserved, Phase::Pending)
    }
    pub(in crate::asset_session) fn claim_save(
        self: &Arc<Self>,
        owner: &Arc<OriginalWork>,
        permit: AppleKeySavePermit,
    ) -> Result<SaveRequest, Reason> {
        let mut p = self.progress.lock().map_err(|_| Reason::CleanupUnknown)?;
        if p.permit.is_some() || p.never_generated.is_some() || p.phase != Phase::Pending {
            return Err(Reason::VaultInterrupted);
        }
        p.permit = Some(permit); // Retained candidate/reader proof even on later failure.
        if !self.original.same_owner(owner)
            || !self.inventory.checked(owner, InventoryPoint::BeforePending)
            || !p.permit.as_ref().is_some_and(|permit| {
                permit.matches(self, owner) && self.original.save_current(owner, permit)
            })
            || !p
                .pending
                .as_ref()
                .is_some_and(|ack| ack.matches(self, owner))
        {
            let at = Instant::now();
            p.fail(Reason::ContextStale, at);
            self.fail(owner, Reason::ContextStale, at);
            return Err(Reason::ContextStale);
        }
        p.enter(Phase::Pending, Phase::SaveClaimed)?;
        Ok(SaveRequest {
            destination: self.clone(),
        })
    }

    /// Save-not-entered is NOT proof that a private key was never generated.
    /// Only the parent's actual positively unclaimed generator/no-private-input
    /// and all-originals-joined proof can take this empty-custody cleanup path.
    pub(crate) fn accept_never_generated(
        &self,
        owner: &Arc<OriginalWork>,
        proof: AppleKeyNeverGeneratedJoined,
    ) -> Result<(), Reason> {
        let mut p = self.progress.lock().map_err(|_| Reason::CleanupUnknown)?;
        if p.never_generated.is_some() {
            return Err(Reason::VaultInterrupted);
        }
        p.never_generated = Some(proof);
        if !self.original.same_owner(owner)
            || self.published.get().is_some()
            || !p.save_unattempted()
            || !p
                .never_generated
                .as_ref()
                .is_some_and(|proof| proof.matches(self, owner))
        {
            let at = Instant::now();
            p.fail(Reason::CleanupUnknown, at);
            self.fail(owner, Reason::CleanupUnknown, at);
            return Err(Reason::CleanupUnknown);
        }
        self.never_generated_accepted.store(true, Ordering::SeqCst);
        Ok(())
    }
    pub(crate) fn never_generated_candidate_binding(
        &self,
        owner: &Arc<OriginalWork>,
        reference: &KeyReference,
    ) -> bool {
        self.original.same_owner(owner)
            && !self.never_generated_accepted.load(Ordering::SeqCst)
            && self.published.get().is_none()
            && reference
                .parts()
                .is_ok_and(|parts| parts == (self.identity, self.record, self.revision))
    }
    pub(crate) fn never_generated_binding(
        &self,
        owner: &Arc<OriginalWork>,
        reference: &KeyReference,
    ) -> bool {
        self.original.same_owner(owner)
            && self.never_generated_accepted.load(Ordering::SeqCst)
            && self.published.get().is_none()
            && reference
                .parts()
                .is_ok_and(|parts| parts == (self.identity, self.record, self.revision))
    }
    pub(crate) fn retirement_binding(
        &self,
        owner: &Arc<OriginalWork>,
        reference: &KeyReference,
    ) -> bool {
        self.original.same_owner(owner)
            && !self.failed.load(Ordering::SeqCst)
            && reference
                .parts()
                .is_ok_and(|parts| parts == (self.identity, self.record, self.revision))
            && self.published.get().is_some_and(|saved| {
                saved.identity == self.identity
                    && saved.record == self.record
                    && saved.revision == self.revision
            })
    }
    pub(crate) fn saved_reference_data(&self) -> Option<KeyReference> {
        self.progress
            .try_lock()
            .ok()?
            .saved()
            .then(|| self.descriptor())
    }
    /// Only the actual memory publication after NEW/full readback and original
    /// Asset joins can expose this reference to the parent's keySaved CAS.
    /// A merely stored/read-back record is deliberately not sufficient.
    pub(crate) fn published_reference_data(
        &self,
        owner: &Arc<OriginalWork>,
    ) -> Option<KeyReference> {
        if !self.original.same_owner(owner) || self.failed.load(Ordering::SeqCst) {
            return None;
        }
        let p = self.progress.try_lock().ok()?;
        (p.phase == Phase::Published
            && p.saved()
            && p.saved
                .zip(self.published.get().copied())
                .is_some_and(|(saved, published)| same_reference(saved, published)))
        .then(|| self.descriptor())
    }
    pub(super) fn parent_retirement_ready(&self, owner: &Arc<OriginalWork>) -> bool {
        self.progress.try_lock().is_ok_and(|p| {
            if self.never_generated_accepted.load(Ordering::SeqCst) {
                p.save_unattempted()
                    && p.never_generated
                        .as_ref()
                        .is_some_and(|proof| proof.retirement_ready(self, owner))
            } else {
                p.phase == Phase::Published
                    && p.saved()
                    && p.permit
                        .as_ref()
                        .is_some_and(|permit| permit.retirement_ready(self, owner))
            }
        })
    }
    pub(super) fn dispose_private(&self, owner: &Arc<OriginalWork>) -> bool {
        let Ok(mut p) = self.progress.try_lock() else {
            return false;
        };
        let disposed = if self.never_generated_accepted.load(Ordering::SeqCst) {
            p.save_unattempted()
                && p.never_generated
                    .as_mut()
                    .is_some_and(|proof| proof.try_retire_never_generated(self, owner))
        } else {
            p.phase == Phase::Published
                && p.saved()
                && p.permit
                    .as_mut()
                    .is_some_and(|permit| permit.try_retire_saved(self, owner))
        };
        if !disposed {
            return false;
        }
        // Preserve the consumed original proof/outcome on a late return; it
        // cannot be reissued or converted to successful clock retirement.
        if self.original.save_cleanup_expired() {
            let at = Instant::now();
            p.fail(Reason::Deadline, at);
            self.fail(owner, Reason::Deadline, at);
            return false;
        }
        p.permit = None;
        p.pending = None;
        p.never_generated = None;
        true
    }
    pub(super) fn allows_unstarted_child(&self) -> bool {
        self.never_generated_accepted.load(Ordering::SeqCst)
    }
    pub(crate) fn retained_bytes(&self) -> Option<usize> {
        let p = self.progress.try_lock().ok()?;
        let mut bytes = std::mem::size_of::<Self>()
            .checked_add(2 * std::mem::size_of::<usize>())?
            .checked_add(
                // The destination shares the actual captured inventory; its
                // original Arc/roster is included here exactly once. The outer
                // census may deduplicate this SAME inventory against parent.
                self.inventory.own_retained_bytes()?,
            )?;
        if let Some(ack) = &p.pending {
            bytes = bytes.checked_add(
                ack.own_retained_bytes()?
                    .checked_sub(std::mem::size_of::<AppleKeyPendingAck>())?,
            )?;
        }
        if let Some(permit) = &p.permit {
            bytes = bytes.checked_add(
                permit
                    .own_retained_bytes()?
                    .checked_sub(std::mem::size_of::<AppleKeySavePermit>())?,
            )?;
        }
        if let Some(proof) = &p.never_generated {
            bytes = bytes.checked_add(
                proof
                    .own_retained_bytes()?
                    .checked_sub(std::mem::size_of::<AppleKeyNeverGeneratedJoined>())?,
            )?;
        }
        if let Some(cipher) = &p.cipher {
            bytes = bytes.checked_add(
                cipher
                    .retained_bytes()
                    .ok()?
                    .checked_sub(std::mem::size_of::<crypto::SealedRecord>())?,
            )?;
        }
        Some(bytes)
    }
}

pub(in crate::asset_session) struct SaveRequest {
    destination: Arc<AppleDistributionKeyDestination>,
}
impl SaveRequest {
    /// Used only by the original Child's fixed key-save arm. In particular,
    /// true is not a generic cleanup_child exemption for other operations.
    pub(in crate::asset_session) fn admitted(&self, owner: &Arc<OriginalWork>) -> bool {
        let held = &self.destination;
        !held.failed.load(Ordering::SeqCst)
            && held
                .progress
                .try_lock()
                .is_ok_and(|p| p.phase == Phase::SaveClaimed && save_checked(held, owner, &p))
    }
    pub(super) fn original(&self) -> &Arc<VaultOriginal> {
        &self.destination.original
    }
}

fn save_checked(
    held: &AppleDistributionKeyDestination,
    owner: &Arc<OriginalWork>,
    progress: &Progress,
) -> bool {
    !held.failed.load(Ordering::SeqCst)
        && progress.first.is_none()
        && progress.never_generated.is_none()
        && held.inventory.checked(owner, InventoryPoint::BeforePending)
        && progress
            .pending
            .as_ref()
            .is_some_and(|ack| ack.matches(held, owner))
        && progress.permit.as_ref().is_some_and(|permit| {
            permit.matches(held, owner) && held.original.save_current(owner, permit)
        })
}

fn recheck_for_save(
    held: &AppleDistributionKeyDestination,
    owner: &Arc<OriginalWork>,
    book: &mut store::StoreBook,
    progress: &Progress,
    added: Option<&store::ReadWitness>,
) -> Result<(), Reason> {
    if !save_checked(held, owner, progress) {
        return Err(Reason::ContextStale);
    }
    let permit = progress.permit.as_ref().ok_or(Reason::VaultInterrupted)?;
    held.original.recheck_store_for_save(owner, book, permit)?;
    book.recheck_apple_key_inventory(&held.inventory.witnesses, added, &mut || {
        !held.original.save_current(owner, permit)
    })
    .map_err(problem)?;
    if !save_checked(held, owner, progress) {
        return Err(Reason::ContextStale);
    }
    Ok(())
}

/// Runs ONLY inside the existing original Child with its StoreBook already
/// borrowed. No Document/service/native-registry lock is acquired here.
pub(in crate::asset_session) fn execute(
    owner: &Arc<OriginalWork>,
    book: &mut store::StoreBook,
    request: SaveRequest,
) -> Result<ChildResult, Reason> {
    let held = request.destination;
    let result = (|| {
        let mut p = held.progress.lock().map_err(|_| Reason::CleanupUnknown)?;
        p.enter(Phase::SaveClaimed, Phase::Storing)?;
        recheck_for_save(&held, owner, book, &p, None)?;
        let key = active_key(owner)?;
        if key.identity() != held.identity || !Arc::ptr_eq(&key, &held.original.key) {
            return Err(Reason::SourceChanged);
        }
        let sealed = {
            let Progress {
                reserved, permit, ..
            } = &mut *p;
            permit
                .as_mut()
                .ok_or(Reason::VaultInterrupted)?
                .seal_key(reserved, &key, held.allowance, owner)
                .map_err(crypto_problem)?
        };
        p.cipher = Some(sealed); // Retain exact candidate before fallible postchecks.
        let cipher = p.cipher.as_ref().ok_or(Reason::VaultCorrupt)?;
        if cipher.revision() != held.revision {
            return Err(Reason::VaultCorrupt);
        }
        let length = cipher.bytes().len();
        p.intent = Some(
            key.seal_intent(format::Mutation::New, held.record, None, Some(cipher))
                .map_err(crypto_problem)?,
        );
        recheck_for_save(&held, owner, book, &p, None)?;
        if book.problem().is_some()
            || !book.operation_quiescent()
            || !save_checked(&held, owner, &p)
        {
            return Err(Reason::VaultInterrupted);
        }
        let effect = book.mutate(
            p.intent.as_ref().ok_or(Reason::VaultCorrupt)?,
            Some(p.cipher.as_ref().ok_or(Reason::VaultCorrupt)?.bytes()),
            None,
            &mut || !save_checked(&held, owner, &p),
            &mut || held.original.save_cleanup_expired(),
        );
        p.outcome = book.storage_outcome();
        remember(owner, book, true)?; // Only THIS entered New, before any failure/readback.
        effect.map_err(problem)?;
        if p.outcome != Some(KNOWN_NEW) {
            return Err(Reason::VaultDurabilityUnknown);
        }
        p.cipher = None; // Actual confirmed durability, not a command return/ACK.
        p.enter(Phase::Storing, Phase::Readback)?;
        if length
            .checked_add(crypto::CONTROL_BYTES)
            .is_none_or(|n| n > held.allowance)
        {
            return Err(Reason::Capacity);
        }
        let read = book
            .read_new_apple_key_record(
                held.record,
                held.revision,
                length,
                held.allowance,
                &mut || !save_checked(&held, owner, &p),
            )
            .map_err(problem)?;
        let (bytes, witness, complete) = read.into_parts();
        if !complete
            || bytes.len() != length
            || bytes
                .capacity()
                .checked_add(crypto::CONTROL_BYTES)
                .is_none_or(|n| n > held.allowance)
        {
            return Err(Reason::VaultCorrupt);
        }
        let opened = key
            .open_record(bytes, held.allowance)
            .map_err(crypto_problem)?;
        if !p.reserved.matches_record(&key, &opened)
            || !p
                .permit
                .as_mut()
                .is_some_and(|permit| permit.matches_authenticated_readback(&opened, owner))
        {
            return Err(Reason::VaultCorrupt);
        }
        // SAME complete old roster plus this ONE authenticated NEW witness.
        // This does not replace any prior witness or silently adopt a row
        // which appeared during generation, even an unrelated kind.
        recheck_for_save(&held, owner, book, &p, Some(&witness))?;
        if !save_checked(&held, owner, &p) || !Arc::ptr_eq(&key, &active_key(owner)?) {
            return Err(Reason::ContextStale);
        }
        let row = Descriptor {
            authenticated: crypto::AuthenticatedDescriptor {
                record: opened.record,
                revision: opened.revision,
                descriptor: opened.descriptor,
            },
            original: witness,
            mutation_pending: false,
        };
        drop((opened.fields, opened.file)); // Actual zeroizing full readback, candidate stays retained.
        p.saved = Some(row.reference(key.identity()));
        p.enter(Phase::Readback, Phase::Stored)?;
        Ok(ChildResult::Mutated {
            record: held.record,
            row: Some(row),
        })
    })();
    if let Err(reason) = result {
        let at = Instant::now();
        if let Ok(mut p) = held.progress.lock() {
            p.fail(reason, at);
        }
        held.fail(owner, reason, at);
    }
    result
}

#[cfg(feature = "desktop-shell")]
pub(in crate::asset_session) async fn run(
    document: &DocumentBinding,
    owner: &Arc<OriginalWork>,
    request: SaveRequest,
) -> Result<super::super::super::Staged, Reason> {
    let held = request.destination.clone();
    {
        let mut state = document.lock();
        let p = held
            .progress
            .try_lock()
            .map_err(|_| Reason::CleanupUnknown)?;
        if p.phase != Phase::SaveClaimed
            || !save_checked(&held, owner, &p)
            || !p.permit.as_ref().is_some_and(|permit| {
                held.original
                    .save_current_document(document, &state, owner, permit, false)
            })
            || state
                .vault
                .as_ref()
                .is_none_or(|session| !held.inventory.matches_session(session))
        {
            return Err(Reason::ContextStale);
        }
        // Release the progress borrow before the existing census visits the
        // retained destination. No inverse Doc→Progress→census→Progress lock.
        drop(p);
        if allowance(&state, owner)? < held.allowance {
            return Err(Reason::Capacity);
        }
        let mut work = owner.vault.try_lock().map_err(|_| Reason::CleanupUnknown)?;
        if work
            .first
            .is_some_and(|(reason, _)| !preservation_reason(reason))
            || work.release
            || work.outcome.is_some()
            || work
                .apple_distribution_key
                .destination()
                .is_none_or(|value| !Arc::ptr_eq(value, &held))
        {
            return Err(Reason::VaultInterrupted);
        }
        let pending = store::StorageOutcome {
            effect: store::Effect::NotStarted,
            durability: store::Durability::NotRun,
            cleanup: store::Cleanup::Pending,
        };
        work.outcome = Some(pending);
        let session = state.vault.as_mut().ok_or(Reason::Closed)?;
        session.state = State::Mutating;
        // Never erase the original cancellation while preserving its key.
        let slot = state.slot.as_mut().ok_or(Reason::Closed)?;
        if slot.cleanup_end.is_none() {
            slot.phase = super::super::super::Phase::Mutating;
        }
        slot.vault.outcome = Some(pending);
    }
    let returned = native(document, owner, Child::SaveAppleDistributionKey(request)).await?;
    {
        let state = document.lock();
        let p = held
            .progress
            .try_lock()
            .map_err(|_| Reason::CleanupUnknown)?;
        if p.phase != Phase::Stored
            || !p.saved()
            || !save_checked(&held, owner, &p)
            || !p.permit.as_ref().is_some_and(|permit| {
                held.original
                    .save_current_document(document, &state, owner, permit, true)
            })
            || state
                .vault
                .as_ref()
                .is_none_or(|session| !held.inventory.matches_session(session))
        {
            return Err(Reason::ContextStale);
        }
    }
    match returned {
        ChildResult::Mutated { record, row } => {
            Ok(super::super::super::Staged::Vault(Staged::Mutated {
                record,
                row,
                generation: held.original.roster.generation,
            }))
        }
        _ => Err(Reason::CleanupUnknown),
    }
}

pub(in crate::asset_session) fn new_publication(
    work: &super::super::Work,
    state: &DocumentState,
    session: &Session,
    slot: &Slot,
    record: format::Id,
    row: Option<&Descriptor>,
) -> bool {
    let (Some(held), Some(row)) = (work.apple_distribution_key.destination(), row) else {
        return false;
    };
    if record != held.record
        || row.authenticated.record != held.record
        || row.authenticated.revision != held.revision
        || row.authenticated.descriptor.kind != Kind::AppleDistributionKey
        || row.authenticated.descriptor.label.is_some()
        || row.authenticated.descriptor.has_file()
        || row.authenticated.descriptor.presence() != [true; 3]
        || row.mutation_pending
        || session.inventory.contains(&record)
        || session.rows.len() >= store::DESCRIPTOR_COUNT
        || session.rows.len() >= session.rows.capacity()
        || session.inventory.len() >= session.inventory.capacity()
        || !held.inventory.matches_session(session)
        || held.failed.load(Ordering::SeqCst)
    {
        return false;
    }
    held.progress.try_lock().is_ok_and(|p| {
        save_checked(held, &slot.owner, &p)
            && p.permit.as_ref().is_some_and(|permit| {
                held.original.save_current_data_in_slot(
                    state,
                    session,
                    slot,
                    &slot.owner,
                    permit,
                    true,
                )
            })
            && p.saved()
            && p.phase == Phase::Stored
            && p.saved
                .is_some_and(|saved| same_reference(saved, row.reference(held.identity)))
    })
}

/// Used by the outer original reconciler as well as the fixed vault publisher.
/// In particular a stopped coordinator still needs its REAL returned child,
/// source/control closures and same healthy StoreBook; STOP is not finality.
pub(in crate::asset_session) fn publication_ready(
    state: &DocumentState,
    slot: &Slot,
    staged: &super::super::super::Staged,
) -> bool {
    let super::super::super::Staged::Vault(Staged::Mutated {
        record,
        row,
        generation,
    }) = staged
    else {
        return false;
    };
    let Some(session) = &state.vault else {
        return false;
    };
    if slot.operation != Operation::PrepareAppleDistributionKey
        || slot.vault.generation != Some(*generation)
        || !returned_controls(&slot.owner, false)
        || !slot.owner.retired.load(Ordering::SeqCst)
    {
        return false;
    }
    let Ok(work) = slot.owner.vault.try_lock() else {
        return false;
    };
    let Some(held) = work.apple_distribution_key.destination() else {
        return false;
    };
    !work.release
        && !work.release_claimed
        && work
            .first
            .is_none_or(|(reason, _)| preservation_reason(reason))
        && matches!(work.original_join, None | Some(JoinReceipt::Returned))
        && work.failed_child_join.is_none()
        && work.outcome == Some(KNOWN_NEW)
        && work
            .store
            .as_ref()
            .is_some_and(|store| Arc::ptr_eq(store, &held.original.store))
        && held.original.store.try_lock().is_ok_and(|book| {
            book.problem().is_none() && book.lease_held() && book.operation_quiescent()
        })
        && new_publication(&work, state, session, slot, *record, row.as_ref())
}

/// Fixed key-only memory transition. It never calls the generic publisher
/// which clears cancellation and labels an ordinary mutation Idle/Known.
pub(in crate::asset_session) fn publish(
    state: &mut DocumentState,
    slot: &mut Slot,
    staged: Staged,
) {
    let staged = super::super::super::Staged::Vault(staged);
    if !publication_ready(state, slot, &staged) {
        slot.staged = Some(staged);
        slot.error = Some(AssetError::new(Reason::SourceChanged).into());
        slot.stop(Reason::SourceChanged, Instant::now());
        return;
    }
    let super::super::super::Staged::Vault(Staged::Mutated {
        record,
        row: Some(row),
        generation,
    }) = staged
    else {
        unreachable!("validated fixed key publication");
    };
    let result_record = row.key(); // The same bounded ordinary record-token DATA.
    let session = state.vault.as_mut().expect("validated original key vault");
    append_key_row_data(session, slot, record, row, generation, result_record);
    // Publish the parent's reference marker AFTER the real row transition.
    // A concurrent late veto can retain a durable row without keySaved/CSR,
    // but can never make a marker precede the original row publication.
    let published = slot
        .owner
        .vault
        .try_lock()
        .map_err(|_| Reason::CleanupUnknown)
        .and_then(|work| mark_published(&work, &slot.owner));
    if let Err(reason) = published {
        slot.error = Some(AssetError::new(reason).into());
        slot.stop(reason, Instant::now());
        if let Ok(work) = slot.owner.vault.try_lock() {
            if let Some(held) = work.apple_distribution_key.destination() {
                held.fail(&slot.owner, reason, Instant::now());
            }
        }
    }
}

// DATA transition only, called after the actual fixed publication checks.
// Capacity and absence were reserved/rechecked; no existing row is removed.
fn append_key_row_data(
    session: &mut Session,
    slot: &mut Slot,
    record: format::Id,
    row: Descriptor,
    generation: u32,
    result_record: RecordKey,
) {
    session.inventory.push(record);
    session.rows.push(row);
    session.state = State::Unlocked;
    session.registry_generation = generation;
    slot.result_record = Some(result_record);
    slot.assessment = None;
    slot.assessment_context_revision = None;
    slot.preview = None;
    slot.selection = None;
    slot.review_end = None;
    slot.phase =
        if slot.cleanup_end.is_some() || slot.reason != Reason::None || slot.owner.stopped() {
            super::super::super::Phase::Stopping
        } else {
            super::super::super::Phase::Mutating
        };
    slot.settlement = Settlement::Pending;
    slot.discard = false;
    // session.reason, original error/STOP/first-F and endpoint are preserved.
    // The separate parent keySaved+finalCAS+NativeUse and private disposal are
    // still owed; neither this row nor the UI can invent those receipts.
}

pub(in crate::asset_session) fn mark_published(
    work: &super::super::Work,
    owner: &Arc<OriginalWork>,
) -> Result<(), Reason> {
    let held = work
        .apple_distribution_key
        .destination()
        .ok_or(Reason::VaultInterrupted)?;
    let mut p = held
        .progress
        .try_lock()
        .map_err(|_| Reason::CleanupUnknown)?;
    if !p.saved() || !save_checked(held, owner, &p) {
        return Err(Reason::VaultInterrupted);
    }
    held.published
        .set(p.saved.ok_or(Reason::VaultCorrupt)?)
        .map_err(|_| Reason::VaultInterrupted)?;
    p.enter(Phase::Stored, Phase::Published)
}

#[cfg(all(test, debug_assertions))]
mod tests {
    use super::*;
    fn progress() -> (Progress, Arc<crypto::VaultKey>) {
        let id = |b| format::Id::from_bytes([b; 16]).unwrap();
        let key = Arc::new(crypto::lifecycle_data_key(
            format::Identity::new(id(11), id(12)).unwrap(),
        ));
        // Only random reference IDs; the vault key is existing synthetic DATA.
        let reserved = crypto::ReservedAppleDistributionKey::reserve(&key, &[]).unwrap();
        (
            Progress {
                phase: Phase::Reserved,
                first: None,
                reserved,
                pending: None,
                permit: None,
                never_generated: None,
                cipher: None,
                intent: None,
                outcome: None,
                saved: None,
            },
            key,
        )
    }
    #[test]
    fn no_save_is_not_a_never_generated_or_disposal_proof() {
        let (mut p, key) = progress();
        assert!(p.save_unattempted() && p.never_generated.is_none());
        p.phase = Phase::Pending;
        assert!(p.save_unattempted() && p.never_generated.is_none());
        let fields = commands::own_fields(
            Kind::ProjectReadToken,
            &serde_json::json!({"token":"inert-not-a-key"}),
        )
        .unwrap_or_else(|_| panic!("fixed scalar DATA"));
        assert!(p
            .reserved
            .seal_fields(&key, &fields, crypto::APPLE_KEY_CRYPTO_BYTES)
            .is_err());
        assert!(!p.save_unattempted()); // Even a refused seal attempt cannot be replayed.
    }
    #[test]
    fn known_new_alone_does_not_become_readback_publication_or_key_saved() {
        let (mut p, _key) = progress();
        p.phase = Phase::Storing;
        p.outcome = Some(KNOWN_NEW);
        assert!(!p.saved());
        let (identity, record, revision) = p.reserved.descriptor();
        p.saved = Some(StoredRef {
            identity,
            record,
            revision,
            original: store::ReadWitness::lifecycle_data(record, revision),
        });
        p.phase = Phase::Readback;
        assert!(!p.saved());
        p.phase = Phase::Stored;
        assert!(p.saved()); // Comparison DATA only; still no original parent permit.
        assert!(p.permit.is_none() && p.pending.is_none());
        p.outcome = Some(store::StorageOutcome {
            effect: store::Effect::KnownApplied,
            durability: store::Durability::Unknown,
            cleanup: store::Cleanup::Known,
        });
        assert!(!p.saved());
    }
    #[test]
    fn first_failure_and_reserved_identity_survive_cancel_and_never_rearm() {
        let (mut p, _key) = progress();
        let at = Instant::now();
        let reference = p.reserved.descriptor();
        p.fail(Reason::VaultDurabilityUnknown, at);
        p.fail(
            Reason::UserCancelled,
            at + std::time::Duration::from_millis(1),
        );
        assert_eq!(p.first, Some((Reason::VaultDurabilityUnknown, at)));
        assert!(p.enter(Phase::Failed, Phase::Pending).is_err());
        assert!(p.reserved.descriptor() == reference && !p.saved());
    }
    #[test]
    fn appended_key_data_keeps_original_cancel_and_never_labels_key_saved_or_idle() {
        use super::super::tests::{row_data, state_data};
        for cancelled in [false, true] {
            let (mut state, owner) = state_data(Operation::PrepareAppleDistributionKey);
            let mut slot = state.slot.take().unwrap();
            let session = state.vault.as_mut().unwrap();
            session.rows.clear();
            session.inventory.clear();
            let old = row_data(30, Kind::ProjectReadToken);
            let old_reference = old.reference(session.identity.unwrap());
            session.inventory.push(old.authenticated.record);
            session.rows.push(old);
            let row = row_data(31, Kind::AppleDistributionKey);
            let record = row.authenticated.record;
            let key = row.key();
            if cancelled {
                slot.stop(Reason::UserCancelled, Instant::now());
                session.reason = Reason::UserCancelled;
            }
            let original_end = slot.cleanup_end;
            let generation = session.registry_generation;
            // Exercise ONLY the final DATA append. No native Session, permit,
            // generated bytes or real producer receipt is manufactured here.
            append_key_row_data(session, &mut slot, record, row, generation, key);
            assert!(same_reference(
                old_reference,
                session.rows[0].reference(session.identity.unwrap())
            ));
            assert!(session.inventory.len() == 2 && session.rows.len() == 2);
            assert!(slot
                .result_record
                .as_ref()
                .is_some_and(|key| key.id.0 == record.token()));
            assert!(slot.settlement == Settlement::Pending && !slot.discard);
            assert!(
                slot.phase
                    == if cancelled {
                        super::super::super::super::Phase::Stopping
                    } else {
                        super::super::super::super::Phase::Mutating
                    }
            );
            assert_eq!(slot.cleanup_end, original_end);
            assert!(
                slot.reason
                    == if cancelled {
                        Reason::UserCancelled
                    } else {
                        Reason::None
                    }
            );
            assert!(
                session.reason
                    == if cancelled {
                        Reason::UserCancelled
                    } else {
                        Reason::None
                    }
            );
            assert!(
                slot.assessment.is_none() && slot.preview.is_none() && slot.selection.is_none()
            );
            assert!(owner.coordinator.try_lock().unwrap().receipt == JoinReceipt::New);
            assert!(owner
                .vault
                .try_lock()
                .unwrap()
                .apple_distribution_key
                .empty());
        }
    }
    #[test]
    fn stopped_new_row_data_cannot_cross_outer_publication_without_original_permit_and_joins() {
        use super::super::tests::{row_data, state_data};
        let (mut state, _) = state_data(Operation::PrepareAppleDistributionKey);
        let mut slot = state.slot.take().unwrap();
        slot.stop(Reason::UserCancelled, Instant::now());
        let row = row_data(31, Kind::AppleDistributionKey);
        let staged = super::super::super::super::Staged::Vault(Staged::Mutated {
            record: row.authenticated.record,
            row: Some(row),
            generation: slot.vault.generation.unwrap(),
        });
        assert!(!publication_ready(&state, &slot, &staged));
        // Even a copied known Store outcome cannot supply native joins or a
        // same-parent saved-output permit.
        slot.owner.vault.try_lock().unwrap().outcome = Some(KNOWN_NEW);
        assert!(!publication_ready(&state, &slot, &staged));
    }
}
