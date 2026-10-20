//! The fixed NEW-only profile sink on the existing vault OriginalWork.
//! Provider/worker receipts cannot construct this owner or authorize a file
//! write. The parent supplies original, non-serializable reserve/save permits.
use super::*;
use crate::saved_command_owner::{
    AppleProfileNoSaveJoined, AppleProfilePendingAck, AppleProfileSavePermit,
};
use std::sync::OnceLock;

const ARC_CELLS: usize = 2 * std::mem::size_of::<usize>();
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
    reserved: crypto::ReservedAppleProfile,
    pending: Option<AppleProfilePendingAck>,
    permit: Option<AppleProfileSavePermit>,
    no_save: Option<AppleProfileNoSaveJoined>,
    cipher: Option<crypto::SealedRecord>,
    intent: Option<[u8; format::INTENT_BYTES]>,
    outcome: Option<store::StorageOutcome>,
    saved: Option<StoredRef>,
}
impl Progress {
    fn enter(&mut self, expected: Phase, next: Phase) -> Result<(), Reason> {
        if self.first.is_some() || self.no_save.is_some() || self.phase != expected {
            return Err(Reason::VaultInterrupted);
        }
        self.phase = next;
        Ok(())
    }
    fn fail(&mut self, reason: Reason, at: Instant) {
        if self.first.is_none() {
            self.first = Some((reason, at));
        }
        self.phase = Phase::Failed;
    }
    fn no_save_unattempted(&self) -> bool {
        !self.reserved.attempted()
            && self.permit.is_none()
            && self.cipher.is_none()
            && self.intent.is_none()
            && self.outcome.is_none()
            && self.saved.is_none()
            && matches!(self.phase, Phase::Reserved | Phase::Pending | Phase::Failed)
    }
    fn saved(&self) -> bool {
        self.first.is_none()
            && self.outcome == Some(KNOWN_NEW)
            && self.saved.is_some()
            && self.cipher.is_none()
            && matches!(self.phase, Phase::Stored | Phase::Published)
    }
}

/// Retained in original vault Work before provider GO and moved, never cloned
/// as a replacement owner, into its original off-lock Retirement. The source
/// payload/key/store/context Arcs retain authenticated original custody.
pub(crate) struct AppleProfileDestination {
    owner: Weak<OriginalWork>,
    source: Arc<AppleP12Loan>,
    identity: format::Identity,
    record: format::Id,
    revision: format::Revision,
    roster: ProjectRoster,
    allowance: usize,
    published: OnceLock<StoredRef>,
    failed: AtomicBool,
    no_save_accepted: AtomicBool,
    progress: Mutex<Progress>,
}

impl AppleProfileDestination {
    /// Native-only preparation under the actual Document guard. The original
    /// parent has already attached the SAME key/store/clock and owns the slot.
    /// No file/provider write occurs here; the subsequent durable journal ACK
    /// reserves this exact full identity before any provider mutation.
    pub(in crate::asset_session) fn reserve(
        document: &DocumentBinding,
        state: &mut DocumentState,
        owner: &Arc<OriginalWork>,
        source: Arc<AppleP12Loan>,
        roster: ProjectRoster,
        allowance: usize,
    ) -> Result<Arc<Self>, Reason> {
        let slot = state.slot.as_ref().ok_or(Reason::ContextStale)?;
        if !Arc::ptr_eq(&slot.owner, owner)
            || slot.operation != Operation::AppleProfileSetup
            || slot.target.is_some()
            || slot.reason != Reason::None
            || slot.cleanup_end.is_some()
            || owner.interrupted()
            || !source.current(document, state, None)
            || roster.generation != source.original.context.registry_generation
            || roster.roots.len() > 64
            || !roster.roots.contains(&source.original.context.project)
            || allowance != crypto::APPLE_PROFILE_CRYPTO_BYTES
        {
            return Err(Reason::ContextStale);
        }
        let session = state.vault.as_mut().ok_or(Reason::VaultKeyMissing)?;
        if !session.writable()
            || session.rows.len() >= store::DESCRIPTOR_COUNT
            || session.inventory.len() >= store::DESCRIPTOR_COUNT
            || !Arc::ptr_eq(&active_key(owner)?, &source.original.key)
            || !Arc::ptr_eq(&native_store(owner)?, &source.original.store)
        {
            return Err(Reason::VaultInterrupted);
        }
        // Reserve actual publication capacity before external work. A later
        // source change still refuses; spare capacity is not a ready verdict.
        session
            .rows
            .try_reserve_exact(1)
            .map_err(|_| Reason::Capacity)?;
        session
            .inventory
            .try_reserve_exact(1)
            .map_err(|_| Reason::Capacity)?;
        let reserved =
            crypto::ReservedAppleProfile::reserve(&source.original.key, &session.inventory)
                .map_err(crypto_problem)?;
        let (identity, record, revision) = reserved.descriptor();
        Ok(Arc::new(Self {
            owner: Arc::downgrade(owner),
            source,
            identity,
            record,
            revision,
            roster,
            allowance,
            published: OnceLock::new(),
            failed: AtomicBool::new(false),
            no_save_accepted: AtomicBool::new(false),
            progress: Mutex::new(Progress {
                phase: Phase::Reserved,
                first: None,
                reserved,
                pending: None,
                permit: None,
                no_save: None,
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
        self.source.reference()
    }

    /// SAME pre-GO native writer/finite job, outside Document/Service locks.
    /// The destination already retains the complete genuine registered roster;
    /// no renderer path, fresh Store owner or new read worker can enter here.
    pub(crate) fn recheck_source(&self, owner: &Arc<OriginalWork>) -> Result<(), Reason> {
        if !self.same_owner(owner) || self.failed.load(Ordering::SeqCst) || owner.interrupted() {
            return Err(Reason::ContextStale);
        }
        let mut book = self
            .source
            .original
            .store
            .lock()
            .map_err(|_| Reason::CleanupUnknown)?;
        self.source.recheck_store(owner, &mut book, &self.roster)
    }

    /// Non-relocking fixed comparison for the original permit's final private
    /// drain. OnceLock is set at genuine native saved publication, never from
    /// a request/Terminal. Parent still proves ALL its actual joins/final CAS.
    pub(crate) fn retirement_binding(
        &self,
        owner: &Arc<OriginalWork>,
        reference: &KeyReference,
    ) -> bool {
        self.same_owner(owner)
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

    /// Comparison before accepting an original no-save closure witness. It
    /// does not prove that a save never entered: only the parent's actual fixed
    /// slot and genuine all-jobs join can supply that proof.
    pub(crate) fn no_save_candidate_binding(
        &self,
        owner: &Arc<OriginalWork>,
        reference: &KeyReference,
    ) -> bool {
        self.same_owner(owner)
            && !self.no_save_accepted.load(Ordering::SeqCst)
            && self.published.get().is_none()
            && reference
                .parts()
                .is_ok_and(|parts| parts == (self.identity, self.record, self.revision))
    }

    /// Non-relocking cleanup-only binding, usable after the exact witness was
    /// retained and independently checked. Failure/STOP is not cleared.
    pub(crate) fn no_save_binding(
        &self,
        owner: &Arc<OriginalWork>,
        reference: &KeyReference,
    ) -> bool {
        self.same_owner(owner)
            && self.no_save_accepted.load(Ordering::SeqCst)
            && self.published.get().is_none()
            && reference
                .parts()
                .is_ok_and(|parts| parts == (self.identity, self.record, self.revision))
    }

    /// A known refused operation may release private references only after the
    /// actual SavedSession all-jobs/NativeUse cut and a proven never-entered
    /// fixed vault-save slot. Remote journal Pending is not converted to no-send.
    pub(crate) fn accept_no_save(
        &self,
        owner: &Arc<OriginalWork>,
        witness: AppleProfileNoSaveJoined,
    ) -> Result<(), Reason> {
        let mut state = self.progress.lock().map_err(|_| Reason::CleanupUnknown)?;
        if state.no_save.is_some() {
            return Err(Reason::VaultInterrupted);
        }
        state.no_save = Some(witness); // Retain even a later refusal/unknown.
        if !self.same_owner(owner)
            || self.published.get().is_some()
            || !state.no_save_unattempted()
            || !state
                .no_save
                .as_ref()
                .is_some_and(|proof| proof.matches(self, owner))
        {
            let at = Instant::now();
            state.fail(Reason::CleanupUnknown, at);
            self.fail(owner, Reason::CleanupUnknown, at);
            return Err(Reason::CleanupUnknown);
        }
        self.no_save_accepted.store(true, Ordering::SeqCst);
        Ok(())
    }

    fn fail(&self, owner: &Arc<OriginalWork>, reason: Reason, at: Instant) {
        self.failed.store(true, Ordering::SeqCst);
        if let Ok(mut work) = owner.vault.try_lock() {
            work.fail(reason, at);
        }
        owner.signal_stop();
    }

    fn same_owner(&self, owner: &Arc<OriginalWork>) -> bool {
        self.owner
            .upgrade()
            .is_some_and(|original| Arc::ptr_eq(&original, owner))
    }

    /// Retain the actual reserve-job ACK, not a copied journal row or success
    /// flag. Reuse/download has its own GET-only save intent through this same
    /// gate; it never claims a POST was sent.
    pub(crate) fn record_pending(
        &self,
        owner: &Arc<OriginalWork>,
        ack: AppleProfilePendingAck,
    ) -> Result<(), Reason> {
        let mut state = self.progress.lock().map_err(|_| Reason::CleanupUnknown)?;
        if state.pending.is_some() || state.no_save.is_some() || state.phase != Phase::Reserved {
            return Err(Reason::VaultInterrupted);
        }
        state.pending = Some(ack); // Retain before any later currentness failure.
        if !self.same_owner(owner)
            || owner.interrupted()
            || !state
                .pending
                .as_ref()
                .is_some_and(|ack| ack.matches(self, owner))
        {
            let at = Instant::now();
            state.fail(Reason::ContextStale, at);
            self.fail(owner, Reason::ContextStale, at);
            return Err(Reason::ContextStale);
        }
        state.enter(Phase::Reserved, Phase::Pending)
    }

    /// Called at the existing parent's finite pre-FINISH save-job handoff.
    /// The actual profile receiver/consumer joins are checked by this opaque
    /// permit, never inferred from a Terminal or the source's return code.
    pub(in crate::asset_session) fn claim_save(
        self: &Arc<Self>,
        owner: &Arc<OriginalWork>,
        permit: AppleProfileSavePermit,
    ) -> Result<SaveRequest, Reason> {
        let mut state = self.progress.lock().map_err(|_| Reason::CleanupUnknown)?;
        if state.permit.is_some() || state.no_save.is_some() || state.phase != Phase::Pending {
            return Err(Reason::VaultInterrupted);
        }
        state.permit = Some(permit);
        if !self.same_owner(owner)
            || owner.interrupted()
            || !state
                .pending
                .as_ref()
                .is_some_and(|ack| ack.matches(self, owner))
        {
            let at = Instant::now();
            state.fail(Reason::ContextStale, at);
            self.fail(owner, Reason::ContextStale, at);
            return Err(Reason::ContextStale);
        }
        state.enter(Phase::Pending, Phase::SaveClaimed)?;
        Ok(SaveRequest {
            destination: self.clone(),
        })
    }

    pub(in crate::asset_session) fn census_source(&self) -> &Arc<AppleP12Loan> {
        &self.source
    }

    /// Token-owned bytes only. Shared source payload/context/key/store and
    /// SavedSession/receive/journal backing remain on their actual deduplicated
    /// censuses; this never replaces those originals with an estimated quote.
    pub(crate) fn retained_bytes(&self) -> Option<usize> {
        let state = self.progress.try_lock().ok()?;
        let mut bytes = std::mem::size_of::<Self>()
            .checked_add(ARC_CELLS)?
            .checked_add(
                self.roster
                    .roots
                    .capacity()
                    .checked_mul(std::mem::size_of::<asset_source::RegisteredRoot>())?,
            )?;
        for root in &self.roster.roots {
            bytes = bytes.checked_add(root.path.capacity())?;
        }
        if let Some(ack) = &state.pending {
            bytes = bytes.checked_add(
                ack.own_retained_bytes()?
                    .checked_sub(std::mem::size_of::<AppleProfilePendingAck>())?,
            )?;
        }
        if let Some(permit) = &state.permit {
            bytes = bytes.checked_add(
                permit
                    .own_retained_bytes()?
                    .checked_sub(std::mem::size_of::<AppleProfileSavePermit>())?,
            )?;
        }
        if let Some(proof) = &state.no_save {
            bytes = bytes.checked_add(
                proof
                    .own_retained_bytes()?
                    .checked_sub(std::mem::size_of::<AppleProfileNoSaveJoined>())?,
            )?;
        }
        if let Some(cipher) = &state.cipher {
            bytes = bytes.checked_add(
                cipher
                    .retained_bytes()
                    .ok()?
                    .checked_sub(std::mem::size_of::<crypto::SealedRecord>())?,
            )?;
        }
        Some(bytes)
    }

    /// Comparison DATA for the original final journal job. This reports only
    /// authenticated local readback, NOT assignment, overall native finality,
    /// successful provider publication or a transferable save permission.
    fn parent_retirement_ready(&self, owner: &Arc<OriginalWork>, state: &Progress) -> bool {
        if self.no_save_accepted.load(Ordering::SeqCst) {
            state.no_save_unattempted()
                && state
                    .no_save
                    .as_ref()
                    .is_some_and(|proof| proof.retirement_ready(self, owner))
        } else {
            state.phase == Phase::Published
                && state.saved()
                && state
                    .permit
                    .as_ref()
                    .is_some_and(|permit| permit.retirement_ready(self, owner))
        }
    }

    pub(crate) fn saved_reference_data(&self) -> Option<KeyReference> {
        let state = self.progress.try_lock().ok()?;
        if !state.saved() {
            return None;
        }
        Some(self.descriptor())
    }
}

pub(in crate::asset_session) struct SaveRequest {
    destination: Arc<AppleProfileDestination>,
}

/// This predicate is part of the original BoundLoan's common currentness gate,
/// and permits ONLY this operation's own Unlocked→Mutating transition. It does
/// not widen ordinary writable(), assignment scope, or any other active owner.
pub(in crate::asset_session) fn owns_current_source(
    state: &DocumentState,
    session: &Session,
    owner: &Arc<OriginalWork>,
    loan: &BoundLoan,
) -> bool {
    let Some(slot) = &state.slot else {
        return false;
    };
    if slot.operation != Operation::AppleProfileSetup
        || !Arc::ptr_eq(&slot.owner, owner)
        || slot.target.is_some()
        || slot.cleanup_end.is_some()
        || slot.reason != Reason::None
        || !matches!(loan.payload.kind, Kind::AscP8 | Kind::AppleP12)
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
    let Some(destination) = work.apple_profile.inner.as_ref() else {
        return false;
    };
    destination.same_owner(owner)
        && !destination.failed.load(Ordering::SeqCst)
        && work.first.is_none()
        && !work.release
        && destination.identity == loan.reference.identity
        && destination.revision.counter == 1
        && (!session.inventory.contains(&destination.record)
            || destination.published.get().is_some_and(|saved| {
                session.rows.iter().any(|row| {
                    same_reference(*saved, row.reference(destination.identity))
                        && !row.mutation_pending
                })
            }))
        && Arc::ptr_eq(&destination.source.original.context, &loan.context)
        && Arc::ptr_eq(&destination.source.original.key, &loan.key)
        && Arc::ptr_eq(&destination.source.original.store, &loan.store)
        && (loan.payload.kind == Kind::AscP8
            || same_reference(destination.source.original.reference, loan.reference)
                && Arc::ptr_eq(&destination.source.original.payload, &loan.payload))
}

/// Existing vault Child execution owns the StoreBook lock and actual worker.
/// Nothing in this function acquires a Document/native registry lock.
pub(in crate::asset_session) fn execute(
    owner: &Arc<OriginalWork>,
    book: &mut store::StoreBook,
    request: SaveRequest,
) -> Result<ChildResult, Reason> {
    let destination = &request.destination;
    let result = (|| {
        if !destination.same_owner(owner) || owner.interrupted() {
            return Err(Reason::ContextStale);
        }
        let key = active_key(owner)?;
        if !Arc::ptr_eq(&key, &destination.source.original.key)
            || key.identity() != destination.identity
        {
            return Err(Reason::SourceChanged);
        }
        destination
            .source
            .recheck_store(owner, book, &destination.roster)?;
        let mut state = destination
            .progress
            .lock()
            .map_err(|_| Reason::CleanupUnknown)?;
        state.enter(Phase::SaveClaimed, Phase::Storing)?;
        if !state
            .pending
            .as_ref()
            .is_some_and(|ack| ack.matches(destination, owner))
        {
            return Err(Reason::ContextStale);
        }
        let sealed = {
            let Progress {
                reserved, permit, ..
            } = &mut *state;
            permit
                .as_mut()
                .ok_or(Reason::VaultInterrupted)?
                .seal_profile(reserved, &key, destination.allowance, owner)
                .map_err(crypto_problem)?
        };
        state.cipher = Some(sealed); // Keep original on every subsequent failure.
        let cipher = state.cipher.as_ref().ok_or(Reason::VaultCorrupt)?;
        if cipher.revision() != destination.revision {
            return Err(Reason::VaultCorrupt);
        }
        let length = cipher.bytes().len();
        state.intent = Some(
            key.seal_intent(
                format::Mutation::New,
                destination.record,
                None,
                Some(cipher),
            )
            .map_err(crypto_problem)?,
        );
        // This successful original read also proves StoreBook.begin may enter
        // the following exclusive mutation. No intervening Book operation can
        // leave a previous mutation outcome masquerading as this attempt.
        destination
            .source
            .recheck_store(owner, book, &destination.roster)?;
        if book.problem().is_some() || !book.operation_quiescent() || owner.interrupted() {
            return Err(Reason::VaultInterrupted);
        }
        let effect = book.mutate(
            state.intent.as_ref().ok_or(Reason::VaultCorrupt)?,
            Some(state.cipher.as_ref().ok_or(Reason::VaultCorrupt)?.bytes()),
            None,
            &mut || owner.interrupted(),
            &mut || cleanup_expired(owner),
        );
        state.outcome = book.storage_outcome(); // THIS original call, before any return.
        remember(owner, book, true)?;
        effect.map_err(problem)?;
        if state.outcome != Some(KNOWN_NEW) {
            return Err(Reason::VaultDurabilityUnknown);
        }
        // Only a genuinely known durable New permits this memory retirement.
        // The raw receive backing, ACK, reserved identity and failure fence all
        // remain retained. Unknown never frees/reuses the crypto allowance.
        state.cipher = None;
        state.enter(Phase::Storing, Phase::Readback)?;
        if length
            .checked_add(crypto::CONTROL_BYTES)
            .is_none_or(|n| n > destination.allowance)
        {
            return Err(Reason::Capacity);
        }
        let original = book
            .read_record(destination.record, true, &mut || owner.interrupted())
            .map_err(problem)?;
        let (bytes, witness, complete) = original.into_parts();
        if !complete
            || bytes.len() != length
            || bytes
                .capacity()
                .checked_add(crypto::CONTROL_BYTES)
                .is_none_or(|n| n > destination.allowance)
        {
            return Err(Reason::VaultCorrupt);
        }
        let opened = key
            .open_record(bytes, destination.allowance)
            .map_err(crypto_problem)?;
        if opened.record != destination.record
            || opened.revision != destination.revision
            || opened.descriptor.kind != Kind::AppleProfile
            || !state
                .permit
                .as_mut()
                .is_some_and(|permit| permit.matches_authenticated_readback(&opened, owner))
        {
            return Err(Reason::VaultCorrupt);
        }
        destination
            .source
            .recheck_store(owner, book, &destination.roster)?;
        book.recheck_record(&witness, &mut || owner.interrupted())
            .map_err(problem)?;
        if owner.interrupted() || !Arc::ptr_eq(&key, &active_key(owner)?) {
            return Err(Reason::UserCancelled);
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
        drop((opened.fields, opened.file)); // Actual zeroizing full-readback retirement.
        state.saved = Some(row.reference(key.identity()));
        state.enter(Phase::Readback, Phase::Stored)?;
        Ok(ChildResult::Mutated {
            record: destination.record,
            row: Some(row),
        })
    })();
    if let Err(reason) = result {
        // This is off Document. Preserve both original explanations and first
        // failure; the parent's SAME Apple clock receives it, never a new timer.
        let now = Instant::now();
        if let Ok(mut progress) = destination.progress.lock() {
            progress.fail(reason, now);
        }
        destination.fail(owner, reason, now);
    }
    result
}

#[cfg(feature = "desktop-shell")]
pub(in crate::asset_session) async fn run(
    document: &DocumentBinding,
    owner: &Arc<OriginalWork>,
    request: SaveRequest,
) -> Result<super::super::super::Staged, Reason> {
    let destination = request.destination.clone();
    {
        let mut state = document.lock();
        current_gate(document, &state, owner)?;
        if !destination.source.current(document, &state, Some(owner)) {
            return Err(Reason::ContextStale);
        }
        // Use the original live census, not the illustrative profile quote.
        if allowance(&state, owner)? < destination.allowance {
            return Err(Reason::Capacity);
        }
        let session = state.vault.as_mut().ok_or(Reason::Closed)?;
        if !session.writable() {
            return Err(Reason::VaultInterrupted);
        }
        let mut work = owner.vault.try_lock().map_err(|_| Reason::CleanupUnknown)?;
        if work.first.is_some()
            || work.release
            || work.outcome.is_some()
            || work
                .apple_profile
                .inner
                .as_ref()
                .is_none_or(|held| !Arc::ptr_eq(held, &destination))
        {
            return Err(Reason::VaultInterrupted);
        }
        let pending = store::StorageOutcome {
            effect: store::Effect::NotStarted,
            durability: store::Durability::NotRun,
            cleanup: store::Cleanup::Pending,
        };
        work.outcome = Some(pending);
        session.state = State::Mutating;
        session.reason = Reason::None;
        let slot = state.slot.as_mut().ok_or(Reason::Closed)?;
        slot.phase = super::super::super::Phase::Mutating;
        slot.vault.outcome = Some(pending);
    }
    let returned = native(document, owner, Child::SaveAppleProfile(request)).await?;
    {
        let state = document.lock();
        current_gate(document, &state, owner)?;
        if !destination.source.current(document, &state, Some(owner)) {
            return Err(Reason::ContextStale);
        }
    }
    match returned {
        ChildResult::Mutated { record, row } => {
            Ok(super::super::super::Staged::Vault(Staged::Mutated {
                record,
                row,
                generation: destination.roster.generation,
            }))
        }
        _ => Err(Reason::CleanupUnknown),
    }
}

#[derive(Default)]
pub(in crate::asset_session) struct Work {
    inner: Option<Arc<AppleProfileDestination>>,
}
impl Work {
    pub(in crate::asset_session) fn attach(
        &mut self,
        destination: Arc<AppleProfileDestination>,
    ) -> Result<(), Reason> {
        if self.inner.is_some() {
            return Err(Reason::Busy);
        }
        self.inner = Some(destination);
        Ok(())
    }
    pub(in crate::asset_session) fn destination(&self) -> Option<&Arc<AppleProfileDestination>> {
        self.inner.as_ref()
    }
    pub(in crate::asset_session) fn empty(&self) -> bool {
        self.inner.is_none()
    }
    pub(in crate::asset_session) fn blocks_reuse(&self) -> bool {
        !self.empty()
    }
    pub(in crate::asset_session) fn retained_bytes(&self) -> Option<usize> {
        self.inner
            .as_ref()
            .map_or(Some(0), |held| held.retained_bytes())
    }
    pub(in crate::asset_session) fn take_for_retirement(&mut self) -> Self {
        // Parent must first prove genuine original joins and accepted saved
        // publication. This check cannot upgrade an unknown/failed original.
        if !self.inner.as_ref().is_some_and(|held| {
            let Some(owner) = held.owner.upgrade() else {
                return false;
            };
            held.progress
                .try_lock()
                .is_ok_and(|state| held.parent_retirement_ready(&owner, &state))
        }) {
            return Self::default();
        }
        Self {
            inner: self.inner.take(),
        }
    }
    pub(in crate::asset_session) fn dispose_private(&mut self) -> bool {
        let Some(held) = self.inner.as_ref() else {
            return true;
        };
        let Some(owner) = held.owner.upgrade() else {
            return false;
        };
        let no_save = held.no_save_accepted.load(Ordering::SeqCst);
        if !owner
            .vault
            .try_lock()
            .is_ok_and(|work| original_cleanup_joins(&owner, held, &work))
        {
            return false;
        }
        let Ok(mut state) = held.progress.try_lock() else {
            return false;
        };
        let drained = if no_save {
            state.no_save_unattempted()
                && state
                    .no_save
                    .as_mut()
                    .is_some_and(|proof| proof.try_retire_refused(held, &owner))
        } else {
            state.phase == Phase::Published
                && state.saved()
                && state
                    .permit
                    .as_mut()
                    .is_some_and(|permit| permit.try_retire_saved(held, &owner))
        };
        if !drained {
            return false;
        }
        // Parent has positively drained the SAME receive backing after every
        // actual job/consumer join. Drop private source/permit Arcs OFF Doc only.
        state.permit = None;
        state.pending = None;
        state.no_save = None;
        drop(state);
        self.inner = None;
        true
    }
}

fn returned_controls(owner: &OriginalWork, no_save: bool) -> bool {
    owner.control_resources_settled()
        && owner
            .coordinator
            .try_lock()
            .is_ok_and(|book| book.handle.is_none() && book.receipt == JoinReceipt::Returned)
        && owner.child.try_lock().is_ok_and(|book| {
            book.handle.is_none()
                && (book.receipt == JoinReceipt::Returned
                    || no_save && book.receipt == JoinReceipt::New)
        })
}

fn prior_joins_known(work: &super::super::Work) -> bool {
    matches!(work.original_join, None | Some(JoinReceipt::Returned))
        && work.failed_child_join.is_none()
}

fn cleanup_failure_known(first: Option<(Reason, Instant)>, no_save: bool) -> bool {
    let Some((reason, _)) = first else {
        return true;
    };
    match reason {
        Reason::UserCancelled
        | Reason::Shutdown
        | Reason::DocumentLost
        | Reason::ContextStale
        | Reason::Deadline
        | Reason::ReviewExpired => true,
        // The actual no-save witness must independently establish this known
        // refusal and all its jobs. These reasons alone grant nothing.
        Reason::Closed
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
        | Reason::VaultInterrupted => no_save,
        _ => false, // Unknown/corruption/durability is never a late-known STOP.
    }
}

fn original_cleanup_joins(
    owner: &OriginalWork,
    held: &AppleProfileDestination,
    work: &super::super::Work,
) -> bool {
    let no_save = held.no_save_accepted.load(Ordering::SeqCst);
    returned_controls(owner, no_save)
        && prior_joins_known(work)
        && cleanup_failure_known(work.first, no_save)
        && work.store.as_ref().is_some_and(|storage| {
            Arc::ptr_eq(storage, &held.source.original.store)
                && storage.try_lock().is_ok_and(|book| {
                    if work.release {
                        // Release is intent, not closure. Require the original
                        // one-use release and its actual closed native handles.
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

/// Cleanup-only exception to the existing release continuation's empty-key /
/// empty-context prerequisite. The same original profile source remains held
/// while that continuation closes its Store; no read, save or retry is allowed.
/// Called before start_cleanup takes Work/coordinator locks. Parent proof is
/// TRY-only and covers all jobs capable of work, not this future release.
pub(in crate::asset_session) fn release_retained_private_ready(
    state: &DocumentState,
    slot: &Slot,
) -> bool {
    if slot.operation != Operation::AppleProfileSetup || slot.target.is_some() {
        return false;
    }
    let Some(session) = &state.vault else {
        return false;
    };
    let Ok(work) = slot.owner.vault.try_lock() else {
        return false;
    };
    let Some(held) = &work.apple_profile.inner else {
        return false;
    };
    let no_save = held.no_save_accepted.load(Ordering::SeqCst);
    session.revoked
        && work.release
        && !work.release_claimed
        && work.release_end.is_some()
        && work.original_join.is_none()
        && work.failed_child_join.is_none()
        && cleanup_failure_known(work.first, no_save)
        && returned_controls(&slot.owner, no_save)
        && held.same_owner(&slot.owner)
        && session.identity == Some(held.identity)
        && Arc::ptr_eq(&session.store, &held.source.original.store)
        && work
            .store
            .as_ref()
            .is_some_and(|store| Arc::ptr_eq(store, &session.store))
        && session
            .key
            .as_ref()
            .is_some_and(|key| Arc::ptr_eq(key, &held.source.original.key))
        && work
            .key
            .as_ref()
            .is_some_and(|key| Arc::ptr_eq(key, &held.source.original.key))
        && slot
            .context
            .as_ref()
            .is_some_and(|context| Arc::ptr_eq(context, &held.source.original.context))
        && session
            .store
            .try_lock()
            .is_ok_and(|book| book.operation_quiescent())
        && held
            .progress
            .try_lock()
            .is_ok_and(|progress| held.parent_retirement_ready(&slot.owner, &progress))
}

pub(in crate::asset_session) fn new_publication(
    work: &super::super::Work,
    state: &DocumentState,
    session: &Session,
    slot: &Slot,
    record: format::Id,
    row: Option<&Descriptor>,
) -> bool {
    let (Some(held), Some(row)) = (&work.apple_profile.inner, row) else {
        return false;
    };
    if !held.source.original.current_original(state, session)
        || slot.operation != Operation::AppleProfileSetup
        || slot.target.is_some()
        || record != held.record
        || session.identity != Some(held.identity)
        || row.authenticated.record != held.record
        || row.authenticated.revision != held.revision
        || row.authenticated.descriptor.kind != Kind::AppleProfile
        || row.mutation_pending
        || session.inventory.contains(&record)
        || session.rows.len() >= store::DESCRIPTOR_COUNT
        || held.failed.load(Ordering::SeqCst)
        || !held.same_owner(&slot.owner)
        || slot
            .context
            .as_ref()
            .is_none_or(|context| !Arc::ptr_eq(context, &held.source.original.context))
        || session
            .key
            .as_ref()
            .is_none_or(|key| !Arc::ptr_eq(key, &held.source.original.key))
        || !Arc::ptr_eq(&session.store, &held.source.original.store)
    {
        return false;
    }
    held.progress.try_lock().is_ok_and(|state| {
        state.saved()
            && state.phase == Phase::Stored
            && state
                .saved
                .is_some_and(|saved| same_reference(saved, row.reference(held.identity)))
    })
}

pub(in crate::asset_session) fn mark_published(work: &super::super::Work) -> Result<(), Reason> {
    let held = work
        .apple_profile
        .inner
        .as_ref()
        .ok_or(Reason::VaultInterrupted)?;
    let mut state = held
        .progress
        .try_lock()
        .map_err(|_| Reason::CleanupUnknown)?;
    if !state.saved() {
        return Err(Reason::VaultInterrupted);
    }
    let saved = state.saved.ok_or(Reason::VaultCorrupt)?;
    held.published
        .set(saved)
        .map_err(|_| Reason::VaultInterrupted)?;
    state.enter(Phase::Stored, Phase::Published)
}

pub(in crate::asset_session) fn retirement_ready(owner: &Arc<OriginalWork>) -> bool {
    if !owner.retired.load(Ordering::SeqCst) {
        return false;
    }
    let Ok(work) = owner.vault.try_lock() else {
        return false;
    };
    work.apple_profile.inner.as_ref().is_some_and(|held| {
        original_cleanup_joins(owner, held, &work)
            && held
                .progress
                .try_lock()
                .is_ok_and(|state| held.parent_retirement_ready(owner, &state))
    })
}

#[cfg(all(test, debug_assertions))]
mod tests {
    use super::*;

    fn fixture() -> (
        DocumentState,
        Arc<OriginalWork>,
        Arc<AppleProfileDestination>,
    ) {
        // Reuse the actual vault's inert stored-loan fixture. These are memory
        // predicate tests, not file/crypto/provisioning/child-join receipts.
        let mut state = super::super::super::tests::loan_state();
        let old = state.context.as_ref().unwrap();
        state.context = Some(Arc::new(NativeContext {
            execution_mode: commands::ExecutionMode::Local,
            revision: old.revision,
            project_id: old.project_id.clone(),
            project: old.project.clone(),
            registry_generation: old.registry_generation,
            draft: old.draft.clone(),
            platform: Platform::Ios,
            stage: Stage::Candidate,
            purpose: Purpose::Provisioning,
        }));
        super::super::super::tests::publish_loan_data(&mut state, Kind::AppleP12, 3);
        let session = state.vault.as_ref().unwrap();
        let loan = session.bound.iter().flatten().next().unwrap();
        let source = Arc::new(AppleP12Loan {
            original: *super::super::super::tests::same_backing_loan(loan),
            document: Weak::new(),
            session_identity: Arc::new(()),
            expected_certificate: [0x11; 32],
            p12_digest: [0x22; 32],
        });
        let owner = OriginalWork::new(99, false, Weak::new());
        attach(&owner, session, true, false).ok().unwrap();
        let reserved = crypto::ReservedAppleProfile::reserve(&source.original.key, &[]).unwrap();
        let (identity, record, revision) = reserved.descriptor();
        let context = source.original.context.clone();
        let destination = Arc::new(AppleProfileDestination {
            owner: Arc::downgrade(&owner),
            source,
            identity,
            record,
            revision,
            roster: ProjectRoster {
                generation: context.registry_generation,
                roots: vec![context.project.clone()],
            },
            allowance: crypto::APPLE_PROFILE_CRYPTO_BYTES,
            published: OnceLock::new(),
            failed: AtomicBool::new(false),
            no_save_accepted: AtomicBool::new(false),
            progress: Mutex::new(Progress {
                phase: Phase::Reserved,
                first: None,
                reserved,
                pending: None,
                permit: None,
                no_save: None,
                cipher: None,
                intent: None,
                outcome: None,
                saved: None,
            }),
        });
        let mut slot = Slot::new(
            owner.clone(),
            Operation::AppleProfileSetup,
            Some(context),
            None,
            None,
        );
        slot.vault.lease = Some(session.store.clone());
        slot.vault.generation = Some(session.registry_generation);
        owner
            .vault
            .lock()
            .unwrap()
            .apple_profile
            .attach(destination.clone())
            .unwrap();
        state.slot = Some(slot);
        (state, owner, destination)
    }

    #[test]
    fn self_mutation_exception_keeps_original_loan_checks_and_excludes_other_owners() {
        let (mut state, owner, destination) = fixture();
        let loan = &destination.source.original;
        assert!(loan.current(&state, state.vault.as_ref().unwrap()));
        state.vault.as_mut().unwrap().state = State::Mutating;
        assert!(!loan.current(&state, state.vault.as_ref().unwrap()));
        assert!(loan.current_for_apple_profile(&state, state.vault.as_ref().unwrap(), &owner));
        state.slot.as_mut().unwrap().operation = Operation::Commit;
        assert!(!loan.current_for_apple_profile(&state, state.vault.as_ref().unwrap(), &owner));
        state.slot.as_mut().unwrap().operation = Operation::AppleProfileSetup;
        let foreign = OriginalWork::new(owner.id, false, Weak::new());
        assert!(!loan.current_for_apple_profile(&state, state.vault.as_ref().unwrap(), &foreign));
        let revision = state.vault.as_ref().unwrap().rows[0].authenticated.revision;
        state.vault.as_mut().unwrap().rows[0].authenticated.revision = format::Revision::new(
            format::Id::from_bytes([0xee; 16]).unwrap(),
            revision.counter,
        )
        .unwrap();
        assert!(!loan.current_for_apple_profile(&state, state.vault.as_ref().unwrap(), &owner));
        state.vault.as_mut().unwrap().rows[0].authenticated.revision = revision;
        state.vault.as_mut().unwrap().state = State::Unlocked;
        assert!(loan.current_for_apple_profile(&state, state.vault.as_ref().unwrap(), &owner));
        assert!(loan.current(&state, state.vault.as_ref().unwrap()));
    }

    #[test]
    fn known_storage_effect_alone_cannot_retire_unknown_original_or_rearm_save() {
        let (_state, owner, destination) = fixture();
        let at = Instant::now();
        {
            let mut progress = destination.progress.lock().unwrap();
            progress.phase = Phase::Storing;
            progress.outcome = Some(KNOWN_NEW);
            // No full authenticated readback, publication or original permit.
            assert!(!progress.saved());
            progress.fail(Reason::CleanupUnknown, at);
            progress.fail(
                Reason::UserCancelled,
                at + std::time::Duration::from_secs(1),
            );
            assert_eq!(progress.first, Some((Reason::CleanupUnknown, at)));
            assert!(!progress.saved());
            assert!(progress.enter(Phase::Failed, Phase::Pending).is_err());
        }
        assert!(destination.saved_reference_data().is_none());
        assert!(!retirement_ready(&owner));
        let mut work = owner.vault.lock().unwrap();
        assert!(work.apple_profile.take_for_retirement().empty());
        assert!(Arc::ptr_eq(
            work.apple_profile.destination().unwrap(),
            &destination
        ));
        // Retained work and key/source are not erased by a terminal-like DATA
        // outcome, a normal error, or an attempted second transition.
        assert!(work.apple_profile.blocks_reuse());
        assert!(work.key.is_some());
        // Cleanup predicates, not synthetic joins or permission: a known late
        // STOP is distinct from unknown, and a retained successful original
        // continuation receipt is not the same as a failed original.
        assert!(cleanup_failure_known(Some((Reason::Shutdown, at)), false));
        assert!(!cleanup_failure_known(
            Some((Reason::SourceRefused, at)),
            false
        ));
        assert!(!cleanup_failure_known(
            Some((Reason::CleanupUnknown, at)),
            true
        ));
        assert!(!cleanup_failure_known(
            Some((Reason::VaultDurabilityUnknown, at)),
            false
        ));
        work.original_join = Some(JoinReceipt::Returned);
        assert!(prior_joins_known(&work));
        work.original_join = Some(JoinReceipt::Failed);
        assert!(!prior_joins_known(&work));
        work.original_join = Some(JoinReceipt::Returned);
        work.failed_child_join = Some(JoinReceipt::Failed);
        assert!(!prior_joins_known(&work));
    }

    #[test]
    fn no_save_requires_unattempted_original_even_after_known_refusal() {
        let (_state, _owner, destination) = fixture();
        let mut progress = destination.progress.lock().unwrap();
        assert!(progress.no_save_unattempted());
        progress.fail(Reason::SourceRefused, Instant::now());
        assert!(progress.no_save_unattempted());
        // This is still only a prerequisite, never a parent no-save witness.
        assert!(!destination.no_save_accepted.load(Ordering::SeqCst));

        for phase in [Phase::SaveClaimed, Phase::Storing] {
            let (_state, _owner, destination) = fixture();
            let mut progress = destination.progress.lock().unwrap();
            progress.phase = phase;
            assert!(!progress.no_save_unattempted());
        }

        let (_state, _owner, destination) = fixture();
        let mut progress = destination.progress.lock().unwrap();
        progress.fail(Reason::UserCancelled, Instant::now());
        progress.outcome = Some(KNOWN_NEW);
        assert!(!progress.no_save_unattempted());

        let (_state, _owner, destination) = fixture();
        let mut progress = destination.progress.lock().unwrap();
        // A refused empty-profile attempt returns before any cipher/key use,
        // but permanently spends this actual original reservation.
        assert!(progress
            .reserved
            .seal_profile(
                &destination.source.original.key,
                &[],
                crypto::APPLE_PROFILE_CRYPTO_BYTES
            )
            .is_err());
        progress.fail(Reason::UserCancelled, Instant::now());
        assert!(!progress.no_save_unattempted());
    }
}
