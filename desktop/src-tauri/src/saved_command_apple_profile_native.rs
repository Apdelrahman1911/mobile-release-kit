//! Profile-only phases on the existing Apple journal job roster and writer.
//! All provider/CMS/reader originals precede save; all save/readback originals
//! precede final CAS. No vault operation can start after the roster is sealed.
use super::super::super::apple_signing as signing;
use super::*;
use crate::apple_provisioning_journal::{
    ProfileJournalAck, ProfileOriginalReservation, ProfileProvider, ProfileSaveState, ProfileUpdate,
};

pub(super) async fn event_reply(
    inner: &Arc<Inner>,
    owner: &Arc<Session>,
    sequence: u32,
    event: apple_wire::EventData,
) -> Result<(Vec<u8>, bool), BridgeError> {
    let apple_wire::EventData::Profile(event) = event else {
        return Err(apple_wire::invalid());
    };
    if let apple_wire::ProfileEvent::Identity(input) = event {
        if sequence != 1 {
            return Err(apple_wire::invalid());
        }
        return signing::identity_ack(owner, input).map(|reply| (reply, false));
    }
    if sequence == 2 && matches!(&event, apple_wire::ProfileEvent::Pending { .. }) {
        // Same original native vault child, OFF journal/Document/Edit locks.
        // The retained P8/P12 ReadWitnesses, not their hashes, are rechecked
        // immediately before reserving the account-wide pending intent.
        owner
            .apple
            .input()?
            .check_profile_before_pending()
            .await
            .map_err(|error| local_error(owner, error))?;
    }
    let (selected, update, previous) = {
        let jobs = owner.apple.native.lock().await;
        match event {
            apple_wire::ProfileEvent::Pending { intent, update } if sequence == 2 => {
                signing::current_identity(owner, &intent)?;
                (
                    Call::ProfileReserve(intent, update.clone()),
                    update,
                    owner.apple.request_binding()?.revision,
                )
            }
            apple_wire::ProfileEvent::Attempt(update) if (3..=4).contains(&sequence) => {
                let ack = jobs.last_profile_ack().ok_or_else(apple_wire::invalid)?;
                (
                    Call::ProfileRecord(ack.revision, ack.original.clone(), update.clone()),
                    update,
                    ack.revision,
                )
            }
            _ => return Err(apple_wire::invalid()),
        }
    };
    let mut jobs = owner.apple.native.lock().await;
    call(inner, owner, &mut jobs, sequence as usize - 1, selected).await?;
    let ack = jobs.last_profile_ack().ok_or_else(apple_wire::invalid)?;
    if sequence == 2 {
        signing::pending_ack(owner, ack)?;
    }
    let binding = owner.apple.request_binding()?;
    let bytes = apple_wire::profile_journal_ack(binding.as_ref(), ack, &update, previous)?;
    // Only final bounded audit ACKs have no provider successor. A sparse201
    // response ACK permits GET and must still pass currentness before writing.
    let audit = match &update.provider {
        ProfileProvider::Creation(record) => !matches!(
            (record.status, record.reason),
            (
                AttemptStatus::Running
                    | AttemptStatus::CancellationRequested
                    | AttemptStatus::RecoveryRequired,
                AttemptReason::ReadbackRequired
            )
        ),
        ProfileProvider::DownloadPending => false,
        _ => true,
    };
    Ok((bytes, audit))
}

fn can_save(inner: &Inner, owner: &Session, ack: &ProfileJournalAck) -> bool {
    if ack.row.update.save != ProfileSaveState::NotEntered
        || ack.row.update.cancel_requested
        || ack.row.update.download.is_none()
        || owner
            .apple_profile
            .get()
            .is_none_or(|profile| !profile.work_current())
    {
        return false;
    }
    let registry = inner.lock();
    original_session(&registry, owner) && registry.active.as_ref().is_some_and(|active|
        active.first_stop.is_none() && !active.context_invalidated && !active.unknown
        && active.projection.outcome == Some(Outcome::Complete)
        && matches!(&active.projection.result, Some(Terminal::AppleProvisioning(terminal))
            if terminal.result.as_ref().and_then(apple_wire::ResultData::profile)
                .is_some_and(|result| result.decision == apple_wire::ProfileDecision::DownloadReturned)))
}

async fn save_before_finish(inner: &Arc<Inner>, owner: &Arc<Session>) -> Result<(), BridgeError> {
    let mode = owner.apple.input()?.context().mode;
    if !mode.profile_save() {
        signing::dispatch_save(owner, None)?;
        if signing::join_asset(owner).await?.is_some() {
            return Err(BridgeError::cleanup_unknown());
        }
        return Ok(());
    }
    let candidate = {
        let jobs = owner.apple.native.lock().await;
        jobs.last_profile_ack()
            .is_some_and(|ack| can_save(inner, owner, ack))
    };
    if candidate {
        // The fixed source-check child has its own retained original handle.
        // A known refusal closes the unused save slot below; an unknown child
        // can never produce a no-save disposal witness.
        if let Err(error) = owner.apple.input()?.check_profile_before_save().await {
            let error = local_error(owner, error);
            if error.code == "cleanup_unknown" {
                return Err(error);
            }
        }
    }
    let arm = {
        let jobs = owner.apple.native.lock().await;
        jobs.last_profile_ack()
            .filter(|ack| can_save(inner, owner, ack))
            .map(|ack| {
                let mut update = ack.row.update.clone();
                update.sequence += 1;
                update.save = ProfileSaveState::Armed;
                (ack.revision, ack.original.clone(), update)
            })
    };
    let mut dispatched = false;
    if let Some((revision, original, update)) = arm {
        let mut jobs = owner.apple.native.lock().await;
        let armed = call(
            inner,
            owner,
            &mut jobs,
            PROFILE_ARM,
            Call::ProfileRecord(revision, original, update),
        )
        .await;
        if armed.is_ok()
            && owner
                .apple_profile
                .get()
                .is_some_and(|profile| profile.work_current())
        {
            let ack = jobs.last_profile_ack().ok_or_else(apple_wire::invalid)?;
            signing::dispatch_save(owner, Some(ack))?;
            dispatched = true;
        } else if owner.resource_unknown.load(Ordering::SeqCst) {
            return Err(BridgeError::cleanup_unknown());
        }
        // Known refusal after the durable arm preserves Armed/Pending. It
        // never rolls back a reservation or treats a missing file as no effect.
    }
    if !dispatched {
        signing::dispatch_save(owner, None)?;
    }
    let saved = signing::join_asset(owner).await?;
    if dispatched {
        let reference = saved.ok_or_else(BridgeError::cleanup_unknown)?;
        let mut jobs = owner.apple.native.lock().await;
        let ack = jobs.last_profile_ack().ok_or_else(apple_wire::invalid)?;
        if ack.row.update.save != ProfileSaveState::Armed
            || reference != ack.original.intent().destination
        {
            return Err(BridgeError::cleanup_unknown());
        }
        let revision = ack.revision;
        let original = ack.original.clone();
        let mut update = ack.row.update.clone();
        update.sequence += 1;
        update.save = ProfileSaveState::ReadBack;
        update.saved_reference = Some(reference);
        // Late native STOP after a true Published/readback remains a failed
        // operation, but the durable local fact and cleanup may still finish.
        update.cancel_requested |= owner
            .apple_profile
            .get()
            .is_some_and(|profile| profile.clock().failure().is_some());
        call(
            inner,
            owner,
            &mut jobs,
            PROFILE_SAVED,
            Call::ProfileRecord(revision, original, update),
        )
        .await?;
    } else if saved.is_some() {
        return Err(BridgeError::cleanup_unknown());
    }
    Ok(())
}

pub(super) async fn finish(inner: &Arc<Inner>, owner: &Arc<Session>) -> bool {
    // Read the SAME originals; no argument with a worker success bit can enter
    // this branch. Runtime return, stdout EOF/trailer and both CMS closures are
    // still mandatory even when provider reconciliation remains unknown.
    {
        let book = owner.resources.lock().await;
        if !worker_joined(inner, owner, &book) {
            return false;
        }
    }
    {
        let jobs = owner.apple.native.lock().await;
        if jobs.sealed || !jobs.pre_joined() {
            return false;
        }
    }
    if signing::producer_joined(owner).is_err() {
        return false;
    }
    if save_before_finish(inner, owner).await.is_err() {
        return false;
    }
    let mut jobs = owner.apple.native.lock().await;
    let (lease, original) = {
        let Ok(held) = jobs.hold.try_lock() else {
            return false;
        };
        if let (Some(lease), Some(journal)) = (&held.lease, &held.journal) {
            if !journal.is_for(lease.store(), lease.native_use()) {
                return false;
            }
        } else if held.lease.is_some() || held.journal.is_some() {
            return false;
        }
        (
            held.lease.clone(),
            held.journal
                .as_ref()
                .and_then(|journal| journal.retained_profile_reservation().cloned()),
        )
    };
    let Some(lease) = lease else {
        jobs.sealed = true;
        jobs.complete =
            jobs.slots.iter().all(Slot::known) && !owner.resource_unknown.load(Ordering::SeqCst);
        return jobs.complete;
    };
    if let Some(original) = original {
        let healthy = jobs.hold.try_lock().is_ok_and(|held| {
            held.journal
                .as_ref()
                .is_some_and(|journal| journal.failure().is_none())
        });
        if let Some(ack) = jobs.last_profile_ack().filter(|_| healthy) {
            if !Arc::ptr_eq(&original, &ack.original)
                || ack.row.native_settlement != NativeSettlement::Pending
            {
                return false;
            }
            let revision = ack.revision;
            let joined =
                match signing::native_joined(owner, lease.native_use().clone(), original.clone()) {
                    Ok(joined) => joined,
                    Err(_) => return false,
                };
            if call(
                inner,
                owner,
                &mut jobs,
                PROFILE_FINISH,
                Call::ProfileFinish(revision, original, joined),
            )
            .await
            .is_err()
                && owner.resource_unknown.load(Ordering::SeqCst)
            {
                return false;
            }
        }
        // Lost reserve/write ACK remains Pending. Never guess its revision.
    }
    if !jobs.slots[..PROFILE_RETIRE].iter().all(Slot::known)
        || owner.resource_unknown.load(Ordering::SeqCst)
    {
        return false;
    }
    jobs.sealed = true;
    let joined = AppleProvisioningAllJobsJoined {
        native_use: lease.native_use().clone(),
    };
    if call(
        inner,
        owner,
        &mut jobs,
        PROFILE_RETIRE,
        Call::Retire(joined),
    )
    .await
    .is_err()
    {
        return false;
    }
    jobs.complete = jobs.slots[PROFILE_RETIRE].known()
        && matches!(
            jobs.slots[PROFILE_RETIRE].returned.as_ref(),
            Some(Ok(Value::Retired))
        )
        && !owner.resource_unknown.load(Ordering::SeqCst);
    jobs.complete
}
