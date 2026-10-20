//! Fixed P12 destination on the SAME stored-key loan and original vault work.
//! This child reuses the original inventory, key, StoreBook, clock and joins;
//! it is not a generic writer or a certificate-policy/binding constructor.
use super::*;
use crate::saved_command_owner::{AppleP12NoSaveJoined, AppleP12PendingAck, AppleP12SavePermit};
use std::sync::OnceLock;

#[path = "credential_apple_p12_store.rs"]
pub(in crate::asset_session) mod p12_store;

impl AppleDistributionKeyLoan {
    pub(in crate::asset_session) fn reserve_p12(
        document: &DocumentBinding,
        state: &DocumentState,
        owner: &Arc<OriginalWork>,
        expected: &KeyReference,
        roster: ProjectRoster,
    ) -> Result<Arc<Self>, Reason> {
        let original = VaultOriginal::capture(document, state, owner, roster, Purpose::P12)?;
        let (identity, record, revision) = expected.parts().map_err(|_| Reason::InvalidRequest)?;
        if original.key.identity() != identity {
            return Err(Reason::SourceChanged);
        }
        let session = state.vault.as_ref().ok_or(Reason::VaultKeyMissing)?;
        if !complete_session_inventory(session) {
            return Err(Reason::SourceChanged);
        }
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
        Ok(Arc::new(Self {
            original,
            reference: row.reference(identity),
            allowance: crypto::APPLE_KEY_CRYPTO_BYTES,
            progress: Mutex::new(LoadProgress {
                phase: LoadPhase::Reserved,
                payload: None,
                first: None,
                joined: None,
            }),
        }))
    }
}
impl AppleDistributionKeyInventory {
    /// Capture the SAME fresh loaded key original. No second SourceBook walk,
    /// regenerated root identity or descriptor-only key authorization.
    pub(in crate::asset_session) fn capture_p12(
        document: &DocumentBinding,
        state: &DocumentState,
        owner: &Arc<OriginalWork>,
        loan: &Arc<AppleDistributionKeyLoan>,
    ) -> Result<Arc<Self>, Reason> {
        if loan.original.purpose != Purpose::P12 || !loan.current(document, state, owner) {
            return Err(Reason::SourceChanged);
        }
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
            let reference = row.reference(loan.reference.identity);
            rows.push(InventoryRow {
                kind: row.authenticated.descriptor.kind,
                reference,
            });
            witnesses.push(reference.original);
        }
        Ok(Arc::new(Self {
            original: loan.original.clone(),
            rows,
            witnesses,
            checks: Mutex::new([InventoryCheck::default(); 2]),
        }))
    }
}

const KNOWN_NEW: store::StorageOutcome = store::StorageOutcome {
    effect: store::Effect::KnownApplied,
    durability: store::Durability::Confirmed,
    cleanup: store::Cleanup::Known,
};

/// Only the selected P8 of this exact P12 save may remain current across its
/// own Unlocked -> Mutating transition. Ordinary writable/BoundLoan checks
/// are unchanged; no other operation, record, revision or key is admitted.
pub(in crate::asset_session) fn owns_current_source(
    state: &DocumentState,
    session: &Session,
    owner: &Arc<OriginalWork>,
    source: &BoundLoan,
) -> bool {
    let Some(slot) = &state.slot else {
        return false;
    };
    if slot.operation != Operation::AssembleAppleP12
        || !Arc::ptr_eq(&slot.owner, owner)
        || slot.target.is_some()
        || slot.cleanup_end.is_some()
        || slot.reason != Reason::None
        || source.payload.kind != Kind::AscP8
        || !matches!(session.state, State::Unlocked | State::Mutating)
        || session.read_only
        || session.revoked
        || owner.interrupted()
    {
        return false;
    }
    let Ok(work) = owner.vault.try_lock() else {
        return false;
    };
    let Some(destination) = work.apple_distribution_key.p12_destination() else {
        return false;
    };
    let original = &destination.loan.original;
    destination.original_binding(owner, &destination.descriptor())
        && !destination.failed.load(Ordering::SeqCst)
        && work.first.is_none()
        && !work.release
        && destination.identity == source.reference.identity
        && destination.revision.counter == 1
        && Arc::ptr_eq(&original.context, &source.context)
        && Arc::ptr_eq(&original.key, &source.key)
        && Arc::ptr_eq(&original.store, &source.store)
        && owner.apple_p12_source_matches_p8(source)
        && (!session.inventory.contains(&destination.record)
            || destination.published.get().is_some_and(|saved| {
                session.rows.iter().any(|row| {
                    !row.mutation_pending
                        && same_reference(*saved, row.reference(destination.identity))
                })
            }))
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Reserved,
    Pending,
    Claimed,
    Writing,
    Reading,
    Stored,
    Published,
    Failed,
}
struct Progress {
    phase: Phase,
    first: Option<(Reason, Instant)>,
    reserved: crypto::ReservedAppleP12,
    pending: Option<AppleP12PendingAck>,
    permit: Option<AppleP12SavePermit>,
    no_save: Option<AppleP12NoSaveJoined>,
    password: Option<Arc<commands::AppleP12Password>>,
    cipher: Option<crypto::SealedRecord>,
    intent: Option<[u8; format::INTENT_BYTES]>,
    outcome: Option<store::StorageOutcome>,
    saved: Option<StoredRef>,
}
impl Progress {
    fn enter(&mut self, from: Phase, to: Phase) -> Result<(), Reason> {
        if self.phase != from || self.first.is_some() || self.no_save.is_some() {
            return Err(Reason::VaultInterrupted);
        }
        self.phase = to;
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
    fn never_saved(&self) -> bool {
        !self.reserved.attempted()
            && self.permit.is_none()
            && self.cipher.is_none()
            && self.intent.is_none()
            && self.outcome.is_none()
            && self.saved.is_none()
            && matches!(self.phase, Phase::Reserved | Phase::Pending | Phase::Failed)
    }
}
pub(crate) struct AppleP12Destination {
    pub(super) loan: Arc<AppleDistributionKeyLoan>,
    inventory: Arc<AppleDistributionKeyInventory>,
    identity: format::Identity,
    record: format::Id,
    revision: format::Revision,
    published: OnceLock<StoredRef>,
    no_save_accepted: AtomicBool,
    failed: AtomicBool,
    progress: Mutex<Progress>,
}
impl AppleP12Destination {
    pub(in crate::asset_session) fn reserve(
        document: &DocumentBinding,
        state: &mut DocumentState,
        owner: &Arc<OriginalWork>,
        loan: Arc<AppleDistributionKeyLoan>,
        inventory: Arc<AppleDistributionKeyInventory>,
    ) -> Result<Arc<Self>, Reason> {
        if loan.original.purpose != Purpose::P12
            || !loan.current(document, state, owner)
            || !Arc::ptr_eq(&loan.original, &inventory.original)
            || !inventory.current(document, state, owner)
            || !inventory.checked(owner, InventoryPoint::Initial)
        {
            return Err(Reason::SourceChanged);
        }
        let session = state.vault.as_mut().ok_or(Reason::VaultKeyMissing)?;
        if session.rows.len() >= store::DESCRIPTOR_COUNT {
            return Err(Reason::Capacity);
        }
        session
            .rows
            .try_reserve_exact(1)
            .map_err(|_| Reason::Capacity)?;
        session
            .inventory
            .try_reserve_exact(1)
            .map_err(|_| Reason::Capacity)?;
        let reserved = crypto::ReservedAppleP12::reserve(&loan.original.key, &session.inventory)
            .map_err(crypto_problem)?;
        let (identity, record, revision) = reserved.descriptor();
        let password = Arc::new(commands::AppleP12Password::generate().map_err(crypto_problem)?);
        Ok(Arc::new(Self {
            loan,
            inventory,
            identity,
            record,
            revision,
            published: OnceLock::new(),
            no_save_accepted: AtomicBool::new(false),
            failed: AtomicBool::new(false),
            progress: Mutex::new(Progress {
                phase: Phase::Reserved,
                first: None,
                reserved,
                pending: None,
                permit: None,
                no_save: None,
                password: Some(password),
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
    pub(crate) fn source_reference(&self) -> KeyReference {
        self.loan.reference()
    }
    pub(crate) fn original_binding(
        &self,
        owner: &Arc<OriginalWork>,
        reference: &KeyReference,
    ) -> bool {
        self.loan.original.same_owner(owner)
            && reference
                .parts()
                .is_ok_and(|parts| parts == (self.identity, self.record, self.revision))
    }
    pub(crate) fn same_source(&self, loan: &Arc<AppleDistributionKeyLoan>) -> bool {
        Arc::ptr_eq(&self.loan, loan)
    }
    /// The parent retains only this same opaque password original. There is
    /// no scalar getter; its sole writer and fixed seal/readback methods stay
    /// inside their existing private owners.
    pub(crate) fn password_original(
        &self,
        owner: &Arc<OriginalWork>,
    ) -> Result<Arc<commands::AppleP12Password>, Reason> {
        let p = self
            .progress
            .try_lock()
            .map_err(|_| Reason::CleanupUnknown)?;
        if !self.loan.original.same_owner(owner)
            || owner.interrupted()
            || self.failed.load(Ordering::SeqCst)
            || p.phase != Phase::Reserved
            || p.first.is_some()
        {
            return Err(Reason::ContextStale);
        }
        p.password.as_ref().cloned().ok_or(Reason::SourceChanged)
    }
    pub(in crate::asset_session) fn inventory(&self) -> &Arc<AppleDistributionKeyInventory> {
        &self.inventory
    }
    #[cfg(all(
        feature = "desktop-shell",
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64")
    ))]
    pub(crate) fn write_password(
        &self,
        owner: &Arc<OriginalWork>,
        writer: &mut crate::saved_command_owner::PrivateAppleP12Input,
    ) -> Result<(), BridgeError> {
        let p = self
            .progress
            .try_lock()
            .map_err(|_| BridgeError::cleanup_unknown())?;
        if !self.loan.original.same_owner(owner)
            || owner.interrupted()
            || self.failed.load(Ordering::SeqCst)
            || !matches!(p.phase, Phase::Reserved | Phase::Pending)
        {
            return Err(BridgeError::protocol());
        }
        p.password
            .as_ref()
            .ok_or_else(BridgeError::protocol)?
            .write_to(writer)
    }
    pub(crate) fn record_pending(
        &self,
        owner: &Arc<OriginalWork>,
        ack: AppleP12PendingAck,
    ) -> Result<(), Reason> {
        let mut p = self.progress.lock().map_err(|_| Reason::CleanupUnknown)?;
        if p.phase != Phase::Reserved || p.pending.is_some() || p.no_save.is_some() {
            return Err(Reason::VaultInterrupted);
        }
        p.pending = Some(ack);
        if owner.interrupted()
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
    pub(in crate::asset_session) fn claim(
        self: &Arc<Self>,
        owner: &Arc<OriginalWork>,
        permit: AppleP12SavePermit,
    ) -> Result<p12_store::SaveRequest, Reason> {
        let mut p = self.progress.lock().map_err(|_| Reason::CleanupUnknown)?;
        if p.phase != Phase::Pending || p.permit.is_some() || p.no_save.is_some() {
            return Err(Reason::VaultInterrupted);
        }
        p.permit = Some(permit); // Keep the genuine producer/receive proof BEFORE later errors.
        if !self.save_current(owner, &p) {
            let at = Instant::now();
            p.fail(Reason::ContextStale, at);
            self.fail(owner, Reason::ContextStale, at);
            return Err(Reason::ContextStale);
        }
        p.enter(Phase::Pending, Phase::Claimed)?;
        Ok(p12_store::SaveRequest {
            destination: self.clone(),
        })
    }
    fn save_current(&self, owner: &Arc<OriginalWork>, p: &Progress) -> bool {
        !self.failed.load(Ordering::SeqCst)
            && p.first.is_none()
            && p.no_save.is_none()
            && !owner.interrupted()
            && self.loan.original.same_owner(owner)
            && !self.loan.original.clock.interrupted()
            && !self.loan.original.clock.completed()
            && Instant::now() < self.loan.original.clock.work_end()
            && self.inventory.checked(owner, InventoryPoint::BeforePending)
            && p.password.is_some()
            && p.pending
                .as_ref()
                .is_some_and(|ack| ack.matches(self, owner))
            && p.permit
                .as_ref()
                .is_some_and(|permit| permit.matches(self, owner) && permit.save_current(owner))
    }
    fn fail(&self, owner: &Arc<OriginalWork>, reason: Reason, at: Instant) {
        self.failed.store(true, Ordering::SeqCst);
        self.loan.original.fail(owner, reason, at);
    }
    pub(crate) fn accept_no_save(
        &self,
        owner: &Arc<OriginalWork>,
        proof: AppleP12NoSaveJoined,
    ) -> Result<(), Reason> {
        let mut p = self.progress.lock().map_err(|_| Reason::CleanupUnknown)?;
        if p.no_save.is_some() {
            return Err(Reason::VaultInterrupted);
        }
        p.no_save = Some(proof);
        if !self.loan.original.same_owner(owner)
            || self.published.get().is_some()
            || !p.never_saved()
            || !p
                .no_save
                .as_ref()
                .is_some_and(|proof| proof.matches(self, owner))
        {
            let at = Instant::now();
            p.fail(Reason::CleanupUnknown, at);
            self.fail(owner, Reason::CleanupUnknown, at);
            return Err(Reason::CleanupUnknown);
        }
        self.no_save_accepted.store(true, Ordering::SeqCst);
        Ok(())
    }
    pub(crate) fn no_save_candidate(
        &self,
        owner: &Arc<OriginalWork>,
        reference: &KeyReference,
    ) -> bool {
        self.original_binding(owner, reference)
            && self.published.get().is_none()
            && !self.no_save_accepted.load(Ordering::SeqCst)
    }
    pub(crate) fn no_save_binding(
        &self,
        owner: &Arc<OriginalWork>,
        reference: &KeyReference,
    ) -> bool {
        self.original_binding(owner, reference)
            && self.published.get().is_none()
            && self.no_save_accepted.load(Ordering::SeqCst)
    }
    pub(crate) fn retirement_binding(
        &self,
        owner: &Arc<OriginalWork>,
        reference: &KeyReference,
    ) -> bool {
        self.original_binding(owner, reference)
            && !self.failed.load(Ordering::SeqCst)
            && self.published.get().is_some_and(|saved| {
                saved.identity == self.identity
                    && saved.record == self.record
                    && saved.revision == self.revision
            })
    }
    pub(crate) fn published_reference_data(
        &self,
        owner: &Arc<OriginalWork>,
    ) -> Option<KeyReference> {
        if !self.retirement_binding(owner, &self.descriptor()) {
            return None;
        }
        let p = self.progress.try_lock().ok()?;
        (p.saved()
            && p.phase == Phase::Published
            && p.saved
                .zip(self.published.get().copied())
                .is_some_and(|(saved, published)| same_reference(saved, published)))
        .then(|| self.descriptor())
    }
    pub(super) fn parent_retirement_ready(&self, owner: &Arc<OriginalWork>) -> bool {
        self.loan.parent_retirement_ready(owner)
            && self.progress.try_lock().is_ok_and(|p| {
                if self.no_save_accepted.load(Ordering::SeqCst) {
                    p.never_saved()
                        && p.no_save
                            .as_ref()
                            .is_some_and(|proof| proof.retirement_ready(self, owner))
                } else {
                    p.saved()
                        && p.phase == Phase::Published
                        && p.permit
                            .as_ref()
                            .is_some_and(|permit| permit.retirement_ready(self, owner))
                }
            })
    }
    pub(super) fn dispose_private(&self, owner: &Arc<OriginalWork>) -> bool {
        // Existing Work calls this only after original Store/controls/release
        // joins. These TRY parent proofs do not wait for this future disposal.
        if !self.loan.parent_retirement_ready(owner) {
            return false;
        }
        let Ok(mut p) = self.progress.try_lock() else {
            return false;
        };
        let drained = if self.no_save_accepted.load(Ordering::SeqCst) {
            p.never_saved()
                && p.no_save
                    .as_mut()
                    .is_some_and(|proof| proof.try_retire_refused(self, owner))
        } else {
            p.saved()
                && p.phase == Phase::Published
                && p.permit
                    .as_mut()
                    .is_some_and(|permit| permit.try_retire_saved(self, owner))
        };
        if !drained
            || self.loan.original.save_cleanup_expired()
            || !self.loan.dispose_private(owner)
        {
            return false;
        }
        p.password = None;
        p.pending = None;
        p.permit = None;
        p.no_save = None;
        true
    }
    pub(crate) fn own_retained_bytes(&self) -> Option<usize> {
        let p = self.progress.try_lock().ok()?;
        let mut bytes = std::mem::size_of::<Self>()
            .checked_add(2 * std::mem::size_of::<usize>())?
            .checked_add(self.loan.own_retained_bytes()?)?
            .checked_add(self.inventory.own_retained_bytes()?)?;
        // The same Original/roster is charged above by both fixed wrappers;
        // conservative overcount, never an admission credit. Payload/key and
        // receive buffers are visited by their actual owning census separately.
        if let Some(password) = &p.password {
            bytes = bytes
                .checked_add(password.retained_bytes()?)?
                .checked_add(2 * std::mem::size_of::<usize>())?;
        }
        if let Some(cipher) = &p.cipher {
            bytes = bytes.checked_add(
                cipher
                    .retained_bytes()
                    .ok()?
                    .checked_sub(std::mem::size_of::<crypto::SealedRecord>())?,
            )?;
        }
        if let Some(ack) = &p.pending {
            bytes = bytes.checked_add(
                ack.own_retained_bytes()?
                    .checked_sub(std::mem::size_of::<AppleP12PendingAck>())?,
            )?;
        }
        if let Some(permit) = &p.permit {
            bytes = bytes.checked_add(
                permit
                    .own_retained_bytes()?
                    .checked_sub(std::mem::size_of::<AppleP12SavePermit>())?,
            )?;
        }
        if let Some(proof) = &p.no_save {
            bytes = bytes.checked_add(
                proof
                    .own_retained_bytes()?
                    .checked_sub(std::mem::size_of::<AppleP12NoSaveJoined>())?,
            )?;
        }
        Some(bytes)
    }
}

#[cfg(all(test, debug_assertions))]
mod tests {
    use super::*;
    #[test]
    fn p12_derived_no_save_predicate_never_launders_an_attempted_store() {
        let key = Arc::new(crypto::lifecycle_data_key(
            format::Identity::new(
                format::Id::from_bytes([41; 16]).unwrap(),
                format::Id::from_bytes([42; 16]).unwrap(),
            )
            .unwrap(),
        ));
        let mut p = Progress {
            phase: Phase::Pending,
            first: None,
            reserved: crypto::ReservedAppleP12::reserve(&key, &[]).unwrap(),
            pending: None,
            permit: None,
            no_save: None,
            password: None,
            cipher: None,
            intent: None,
            outcome: None,
            saved: None,
        };
        assert!(p.never_saved());
        p.fail(Reason::UserCancelled, Instant::now());
        assert!(p.never_saved());
        for phase in [
            Phase::Claimed,
            Phase::Writing,
            Phase::Reading,
            Phase::Stored,
            Phase::Published,
        ] {
            p.phase = phase;
            assert!(!p.never_saved());
        }
        p.phase = Phase::Failed;
        p.outcome = Some(KNOWN_NEW);
        assert!(!p.never_saved());
        p.outcome = Some(store::StorageOutcome {
            effect: store::Effect::Unknown,
            durability: store::Durability::Unknown,
            cleanup: store::Cleanup::Unknown,
        });
        assert!(!p.never_saved());
        p.outcome = None;
        p.intent = Some([0; format::INTENT_BYTES]);
        assert!(!p.never_saved());
        // No NativeJoined/SavePermit/NoSave proof is made by this DATA test.
    }
}
