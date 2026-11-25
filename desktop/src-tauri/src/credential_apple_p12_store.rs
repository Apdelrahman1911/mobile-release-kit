//! The fixed P12-only NEW/None child. It never replaces a stored key/P12,
//! promotes a descriptor/hash to a loan, or retries a previous Store outcome.
use super::*;

pub(in crate::asset_session) struct SaveRequest {
    pub(super) destination: Arc<AppleP12Destination>,
}
impl SaveRequest {
    pub(in crate::asset_session) fn admitted(&self, owner: &Arc<OriginalWork>) -> bool {
        self.destination
            .progress
            .try_lock()
            .is_ok_and(|p| p.phase == Phase::Claimed && self.destination.save_current(owner, &p))
    }
    pub(in crate::asset_session::vault::distribution_key) fn original(
        &self,
    ) -> &Arc<VaultOriginal> {
        &self.destination.loan.original
    }
}
fn current_slot(
    held: &AppleP12Destination,
    state: &DocumentState,
    session: &Session,
    slot: &Slot,
    mutating: bool,
) -> bool {
    slot.operation == Operation::AssembleAppleP12
        && held
            .loan
            .original
            .current_data_in_slot(state, session, slot, &slot.owner, mutating)
        && held.inventory.matches_session(session)
        && held.loan.progress.try_lock().is_ok_and(|p| {
            p.phase == LoadPhase::Loaded
                && p.first.is_none()
                && p.joined.is_none()
                && p.payload.is_some()
        })
}
fn recheck(
    held: &AppleP12Destination,
    owner: &Arc<OriginalWork>,
    book: &mut store::StoreBook,
    p: &Progress,
    added: Option<&store::ReadWitness>,
) -> Result<(), Reason> {
    if !held.save_current(owner, p) {
        return Err(Reason::VaultInterrupted);
    }
    held.loan.original.recheck_store(owner, book)?;
    book.recheck_apple_key_inventory(&held.inventory.witnesses, added, &mut || {
        !held.save_current(owner, p)
    })
    .map_err(problem)?;
    if !held.save_current(owner, p) {
        return Err(Reason::VaultInterrupted);
    }
    Ok(())
}

pub(in crate::asset_session) fn execute(
    owner: &Arc<OriginalWork>,
    book: &mut store::StoreBook,
    request: SaveRequest,
) -> Result<ChildResult, Reason> {
    let held = request.destination;
    let result = (|| {
        let mut p = held.progress.lock().map_err(|_| Reason::CleanupUnknown)?;
        p.enter(Phase::Claimed, Phase::Writing)?;
        recheck(&held, owner, book, &p, None)?;
        let key = active_key(owner)?;
        if key.identity() != held.identity || !Arc::ptr_eq(&key, &held.loan.original.key) {
            return Err(Reason::SourceChanged);
        }
        let password = p.password.as_ref().ok_or(Reason::SourceChanged)?.clone();
        let sealed = {
            let Progress {
                reserved, permit, ..
            } = &mut *p;
            permit
                .as_mut()
                .ok_or(Reason::VaultInterrupted)?
                .seal_p12(
                    reserved,
                    &key,
                    &password,
                    crypto::APPLE_P12_CRYPTO_BYTES,
                    owner,
                )
                .map_err(crypto_problem)?
        };
        p.cipher = Some(sealed); // Retain before any postcheck or interrupt.
        let cipher = p.cipher.as_ref().ok_or(Reason::VaultCorrupt)?;
        if cipher.revision() != held.revision {
            return Err(Reason::VaultCorrupt);
        }
        let length = cipher.bytes().len();
        p.intent = Some(
            key.seal_intent(format::Mutation::New, held.record, None, Some(cipher))
                .map_err(crypto_problem)?,
        );
        recheck(&held, owner, book, &p, None)?;
        if book.problem().is_some() || !book.operation_quiescent() {
            return Err(Reason::VaultInterrupted);
        }
        let effect = book.mutate(
            p.intent.as_ref().ok_or(Reason::VaultCorrupt)?,
            Some(p.cipher.as_ref().ok_or(Reason::VaultCorrupt)?.bytes()),
            None,
            &mut || !held.save_current(owner, &p),
            &mut || held.loan.original.save_cleanup_expired(),
        );
        p.outcome = book.storage_outcome();
        remember(owner, book, true)?; // This actual entered NEW, before EVERY later error.
        effect.map_err(problem)?;
        if p.outcome != Some(KNOWN_NEW) {
            return Err(Reason::VaultDurabilityUnknown);
        }
        p.cipher = None; // Only this KnownApplied+Confirmed+Known releases ciphertext.
        p.enter(Phase::Writing, Phase::Reading)?;
        // Fixed expected NEW revision+length gate BEFORE body allocation; not
        // ordinary read_record followed by a late size check.
        let read = book
            .read_new_apple_p12_record(
                held.record,
                held.revision,
                length,
                crypto::APPLE_P12_CRYPTO_BYTES,
                &mut || !held.save_current(owner, &p),
            )
            .map_err(problem)?;
        let (bytes, witness, complete) = read.into_parts();
        if !complete
            || bytes.len() != length
            || bytes
                .capacity()
                .checked_add(crypto::CONTROL_BYTES)
                .is_none_or(|total| total > crypto::APPLE_P12_CRYPTO_BYTES)
        {
            return Err(Reason::VaultCorrupt);
        }
        let opened = key
            .open_record(bytes, crypto::APPLE_P12_CRYPTO_BYTES)
            .map_err(crypto_problem)?;
        if !p.reserved.matches_record(&key, &opened)
            || !p.permit.as_mut().is_some_and(|permit| {
                permit.matches_authenticated_readback(&opened, &password, owner)
            })
        {
            return Err(Reason::VaultCorrupt);
        }
        recheck(&held, owner, book, &p, Some(&witness))?;
        let row = Descriptor {
            authenticated: crypto::AuthenticatedDescriptor {
                record: opened.record,
                revision: opened.revision,
                descriptor: opened.descriptor,
            },
            original: witness,
            mutation_pending: false,
        };
        drop((opened.fields, opened.file)); // Actual zeroizing AEAD readback, raw receive stays.
        p.saved = Some(row.reference(held.identity));
        p.enter(Phase::Reading, Phase::Stored)?;
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
) -> Result<crate::asset_session::Staged, Reason> {
    let held = request.destination.clone();
    {
        let mut state = document.lock();
        let p = held
            .progress
            .try_lock()
            .map_err(|_| Reason::CleanupUnknown)?;
        let session = state.vault.as_ref().ok_or(Reason::VaultKeyMissing)?;
        let slot = state.slot.as_ref().ok_or(Reason::ContextStale)?;
        if p.phase != Phase::Claimed
            || !held.save_current(owner, &p)
            || !current_slot(&held, &state, session, slot, false)
            || !document
                .context_matches(&state, &held.loan.original.context)
                .unwrap_or(false)
        {
            return Err(Reason::ContextStale);
        }
        drop(p); // Actual census may visit Progress; never re-lock it here.
        if allowance(&state, owner)? < crypto::APPLE_P12_CRYPTO_BYTES {
            return Err(Reason::Capacity);
        }
        let mut work = owner.vault.try_lock().map_err(|_| Reason::CleanupUnknown)?;
        if work.first.is_some()
            || work.release
            || work.outcome.is_some()
            || work
                .apple_distribution_key
                .p12_destination()
                .is_none_or(|same| !Arc::ptr_eq(same, &held))
        {
            return Err(Reason::VaultInterrupted);
        }
        let pending = store::StorageOutcome {
            effect: store::Effect::NotStarted,
            durability: store::Durability::NotRun,
            cleanup: store::Cleanup::Pending,
        };
        work.outcome = Some(pending);
        state.vault.as_mut().ok_or(Reason::Closed)?.state = State::Mutating;
        let slot = state.slot.as_mut().ok_or(Reason::Closed)?;
        slot.phase = crate::asset_session::Phase::Mutating;
        slot.vault.outcome = Some(pending);
    }
    let returned = native(document, owner, Child::SaveAppleP12(request)).await?;
    {
        let state = document.lock();
        let session = state.vault.as_ref().ok_or(Reason::VaultKeyMissing)?;
        let slot = state.slot.as_ref().ok_or(Reason::ContextStale)?;
        let p = held
            .progress
            .try_lock()
            .map_err(|_| Reason::CleanupUnknown)?;
        if !p.saved()
            || !held.save_current(owner, &p)
            || !current_slot(&held, &state, session, slot, true)
            || !document
                .context_matches(&state, &held.loan.original.context)
                .unwrap_or(false)
        {
            return Err(Reason::ContextStale);
        }
    }
    match returned {
        ChildResult::Mutated { record, row } => {
            Ok(crate::asset_session::Staged::Vault(Staged::Mutated {
                record,
                row,
                generation: held.loan.original.roster.generation,
            }))
        }
        _ => Err(Reason::CleanupUnknown),
    }
}

fn publication_ready(
    state: &DocumentState,
    slot: &Slot,
    staged: &crate::asset_session::Staged,
) -> bool {
    let crate::asset_session::Staged::Vault(Staged::Mutated {
        record,
        row: Some(row),
        generation,
    }) = staged
    else {
        return false;
    };
    let Some(session) = &state.vault else {
        return false;
    };
    if slot.operation != Operation::AssembleAppleP12
        || slot.vault.generation != Some(*generation)
        || !returned_controls(&slot.owner, false)
        || !slot.owner.retired.load(Ordering::SeqCst)
    {
        return false;
    }
    let Ok(work) = slot.owner.vault.try_lock() else {
        return false;
    };
    let Some(held) = work.apple_distribution_key.p12_destination() else {
        return false;
    };
    if work.release
        || work.release_claimed
        || work.first.is_some()
        || work.failed_child_join.is_some()
        || !matches!(work.original_join, None | Some(JoinReceipt::Returned))
        || work.outcome != Some(KNOWN_NEW)
        || *record != held.record
        || row.authenticated.record != held.record
        || row.authenticated.revision != held.revision
        || row.authenticated.descriptor.kind != Kind::AppleP12
        || row.authenticated.descriptor.label.is_some()
        || !row.authenticated.descriptor.has_file()
        || row.authenticated.descriptor.presence() != [true]
        || row.mutation_pending
        || session.inventory.contains(record)
        || session.rows.len() >= store::DESCRIPTOR_COUNT
        || session.rows.len() >= session.rows.capacity()
        || session.inventory.len() >= session.inventory.capacity()
        || !current_slot(held, state, session, slot, true)
        || work
            .store
            .as_ref()
            .is_none_or(|same| !Arc::ptr_eq(same, &held.loan.original.store))
        || !held.loan.original.context_identity_current()
        || !held.loan.original.store.try_lock().is_ok_and(|book| {
            book.problem().is_none() && book.lease_held() && book.operation_quiescent()
        })
    {
        return false;
    }
    held.progress.try_lock().is_ok_and(|p| {
        p.saved()
            && p.phase == Phase::Stored
            && held.save_current(&slot.owner, &p)
            && p.saved
                .is_some_and(|saved| same_reference(saved, row.reference(held.identity)))
    })
}
pub(in crate::asset_session) fn publish(
    state: &mut DocumentState,
    slot: &mut Slot,
    staged: Staged,
) {
    let staged = crate::asset_session::Staged::Vault(staged);
    if !publication_ready(state, slot, &staged) {
        slot.staged = Some(staged);
        slot.error = Some(AssetError::new(Reason::SourceChanged).into());
        slot.stop(Reason::SourceChanged, Instant::now());
        return;
    }
    let crate::asset_session::Staged::Vault(Staged::Mutated {
        record,
        row: Some(row),
        generation,
    }) = staged
    else {
        unreachable!("fixed P12 publication checked");
    };
    let key = row.key();
    let session = state.vault.as_mut().expect("checked P12 vault");
    session.inventory.push(record);
    session.rows.push(row);
    session.state = State::Unlocked;
    session.registry_generation = generation;
    slot.result_record = Some(key);
    slot.assessment = None;
    slot.assessment_context_revision = None;
    slot.preview = None;
    slot.selection = None;
    slot.review_end = None;
    slot.phase = crate::asset_session::Phase::Mutating;
    slot.settlement = Settlement::Pending;
    slot.discard = false;
    // Only AFTER actual row publication; remaining journal/finality/private
    // drain are not implied by saved-unassigned reference DATA.
    let result = (|| {
        let work = slot
            .owner
            .vault
            .try_lock()
            .map_err(|_| Reason::CleanupUnknown)?;
        let held = work
            .apple_distribution_key
            .p12_destination()
            .ok_or(Reason::VaultInterrupted)?;
        let mut p = held
            .progress
            .try_lock()
            .map_err(|_| Reason::CleanupUnknown)?;
        if !p.saved() || !held.save_current(&slot.owner, &p) {
            return Err(Reason::VaultInterrupted);
        }
        held.published
            .set(p.saved.ok_or(Reason::VaultCorrupt)?)
            .map_err(|_| Reason::VaultInterrupted)?;
        p.enter(Phase::Stored, Phase::Published)
    })();
    if let Err(reason) = result {
        slot.error = Some(AssetError::new(reason).into());
        slot.stop(reason, Instant::now());
    }
}
