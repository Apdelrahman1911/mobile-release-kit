//! Local-key phases on the existing eleven-slot Apple job roster and sole
//! stdin writer. The raw body is already held by the original stdout reader
//! before an output event reaches this code. No key bytes enter journal JSON.
use super::super::super::apple_key as key;
use super::*;
use crate::apple_provisioning_journal::{
    KeyDisposition, KeyGeneration, KeyJournalAck, KeyPrepareUpdate, ProfileSaveState,
};

fn key_end(owner: &Session) -> Result<Instant, BridgeError> {
    owner
        .apple_key
        .get()
        .and_then(|key| key.clock().key_preservation_end())
        .ok_or_else(BridgeError::cleanup_unknown)
}
fn terminal_received(inner: &Inner, owner: &Session) -> bool {
    let registry = inner.lock();
    original_session(&registry, owner)
        && registry
            .active
            .as_ref()
            .is_some_and(|active| active.terminal)
}
fn abandon_pending(owner: &Session, sequence: u32) -> Result<(), BridgeError> {
    let mut route = owner
        .apple
        .route
        .try_lock()
        .map_err(|_| BridgeError::cleanup_unknown())?;
    if sequence != 1
        || route.failed
        || route.completed != 0
        || route.ack_writing
        || route.ack_entered[0]
        || !*owner.stop.borrow()
    {
        return Err(BridgeError::cleanup_unknown());
    }
    // Consumes provisional event DATA only. NeverGenerated still requires the
    // actual worker/EOF/joins and the original ACK-write-never-entered slot.
    route.completed = 1;
    Ok(())
}

async fn event_reply(
    inner: &Arc<Inner>,
    owner: &Arc<Session>,
    sequence: u32,
    event: apple_wire::KeyEvent,
) -> Result<(Vec<u8>, bool), BridgeError> {
    match event {
        apple_wire::KeyEvent::Pending { intent, update } if sequence == 1 => {
            owner
                .apple
                .input()?
                .check_key_before_pending()
                .await
                .map_err(|e| local_error(owner, e))?;
            key::current_pending(owner, &intent)?;
            let previous = owner.apple.request_binding()?.revision.0;
            let mut jobs = owner.apple.native.lock().await;
            call(inner, owner, &mut jobs, 1, Call::KeyReserve(intent, update)).await?;
            let ack = jobs.last_key_ack().ok_or_else(apple_wire::invalid)?;
            key::pending_ack(owner, ack)?;
            let binding = owner.apple.request_binding()?;
            Ok((
                apple_wire::key_pending_ack(binding.as_ref(), ack, previous)?,
                false,
            ))
        }
        apple_wire::KeyEvent::Output(output) if sequence == 2 => {
            key::output_custody(owner, &output)?;
            let parent = owner.apple_key.get().ok_or_else(apple_wire::invalid)?;
            owner
                .apple
                .input()?
                .key_preservation_current(parent)
                .map_err(|e| local_error(owner, e))?;
            let mut jobs = owner.apple.native.lock().await;
            let ack = jobs.last_key_ack().ok_or_else(apple_wire::invalid)?;
            if ack.row.update.sequence != 1 || ack.row.update.generation != KeyGeneration::Armed {
                return Err(apple_wire::invalid());
            }
            let previous = ack.revision;
            let reservation = ack.original.clone();
            let update = KeyPrepareUpdate {
                sequence: 2,
                generation: KeyGeneration::Returned,
                output: Some(output.clone()),
                save: ProfileSaveState::Armed,
                saved_reference: None,
                disposition: KeyDisposition::Running,
                cancel_requested: parent.clock().failure().is_some(),
            };
            call(
                inner,
                owner,
                &mut jobs,
                2,
                Call::KeyRecord(previous, reservation, update),
            )
            .await?;
            let ack = jobs.last_key_ack().ok_or_else(apple_wire::invalid)?;
            owner
                .apple
                .input()?
                .key_preservation_current(parent)
                .map_err(|e| local_error(owner, e))?;
            let binding = owner.apple.request_binding()?;
            Ok((
                apple_wire::key_retained_ack(binding.as_ref(), ack, &output, previous.0)?,
                true,
            ))
        }
        _ => Err(apple_wire::invalid()),
    }
}

/// No second writer or channel. A key-only STOP byte leaves this SAME input
/// open for one body-custody ACK. It never means GO, receipt, EOF or save.
pub(super) async fn write_phases(
    inner: &Arc<Inner>,
    owner: &Arc<Session>,
    writer: &mut ChildStdin,
) -> Result<(), BridgeError> {
    if owner.apple.input()?.context().mode != apple_wire::Mode::KeyPrepare {
        return Err(apple_wire::invalid());
    }
    let parent = owner.apple_key.get().ok_or_else(apple_wire::invalid)?;
    let mut stop_sent = false;
    loop {
        let wake = owner.apple.changed.notified();
        let original_wake = owner.wake.notified();
        if terminal_received(inner, owner) {
            return Ok(());
        }
        let now = Instant::now();
        if now >= owner.clocks.work && !*owner.stop.borrow() {
            inner.stop(owner, Reason::TimedOut);
        }
        let cleanup = parent.clock().cleanup_end();
        if now >= cleanup || owner.resource_unknown.load(Ordering::SeqCst) {
            return Err(BridgeError::cleanup_unknown());
        }
        if *owner.stop.borrow() && !stop_sent {
            // Enter once before polling. Every partial/failed marker is
            // unknown, never retried and never confused with an ACK.
            stop_sent = true;
            let marker = [apple_wire::KEY_STOP];
            let write = writer.write_all(&marker);
            tokio::pin!(write);
            let written = loop {
                let changed = owner.apple.changed.notified();
                let end = parent.clock().cleanup_end();
                if Instant::now() >= end || owner.resource_unknown.load(Ordering::SeqCst) {
                    break false;
                }
                tokio::select! { biased;
                    result = &mut write => break result.is_ok(),
                    _ = changed => {},
                    _ = tokio::time::sleep_until(end.into()) => {},
                }
            };
            if !written {
                return Err(BridgeError::cleanup_unknown());
            }
        }
        let event = {
            let mut route = owner
                .apple
                .route
                .try_lock()
                .map_err(|_| BridgeError::cleanup_unknown())?;
            if route.failed {
                return Err(apple_wire::invalid());
            }
            route.pending.take()
        };
        let Some(event) = event else {
            let mut stop = owner.stop.subscribe();
            tokio::select! { biased;
                _ = wake => {},
                // Terminal publication wakes the original Session, not only
                // the phase router. It must still close this writer after a
                // previously sent STOP (no second marker/ACK or extra wait).
                _ = original_wake => {},
                _ = stop.changed(), if !stop_sent => {},
                _ = tokio::time::sleep_until(if stop_sent { cleanup } else { owner.clocks.work }.into()) => {},
            }
            continue;
        };
        let apple_wire::EventData::Key(event_data) = event.data else {
            return Err(apple_wire::invalid());
        };
        if event.sequence == 1 && *owner.stop.borrow() {
            abandon_pending(owner, event.sequence)?;
            continue;
        }
        let output = match &event_data {
            apple_wire::KeyEvent::Output(value) => Some(value.clone()),
            _ => None,
        };
        let reply = event_reply(inner, owner, event.sequence, event_data).await;
        let (bytes, custody) = match reply {
            Ok(value) => value,
            Err(error)
                if event.sequence == 1
                    && error.code != "cleanup_unknown"
                    && !owner.resource_unknown.load(Ordering::SeqCst) =>
            {
                local_error(owner, error);
                abandon_pending(owner, event.sequence)?;
                continue;
            }
            Err(error) => return Err(error),
        };
        let end = if custody {
            owner
                .apple
                .input()?
                .key_preservation_current(parent)
                .map_err(|e| local_error(owner, e))?;
            key_end(owner)?
        } else {
            if *owner.stop.borrow() {
                abandon_pending(owner, event.sequence)?;
                continue;
            }
            work_clear(owner).map_err(|e| local_error(owner, e))?;
            owner.clocks.work
        };
        {
            let mut route = owner
                .apple
                .route
                .try_lock()
                .map_err(|_| BridgeError::cleanup_unknown())?;
            let index = usize::try_from(event.sequence).map_err(|_| apple_wire::invalid())? - 1;
            if route.failed
                || route.completed.checked_add(1) != Some(event.sequence)
                || route.ack_writing
                || route.ack_entered[index]
            {
                return Err(apple_wire::invalid());
            }
            route.ack_writing = true;
            route.ack_entered[index] = true;
        }
        if custody {
            key::begin_custody_write(owner, output.as_ref().ok_or_else(apple_wire::invalid)?)?;
        } else {
            key::begin_pending_write(owner)?;
        }
        let mut stop = owner.stop.subscribe();
        let written = if custody {
            // Keep polling the SAME irreversible write. A later earlier-F or
            // excluded failure shortens/refuses its original deadline; never
            // drop this future merely to start another write or repeat bytes.
            let write = writer.write_all(&bytes);
            tokio::pin!(write);
            loop {
                let changed = owner.apple.changed.notified();
                if Instant::now() >= owner.clocks.work && parent.clock().failure().is_none() {
                    inner.stop(owner, Reason::TimedOut);
                }
                let Ok(end) = key_end(owner) else {
                    break false;
                };
                tokio::select! { biased;
                    result = &mut write => break result.is_ok(),
                    _ = stop.changed() => {},
                    _ = changed => {},
                    _ = tokio::time::sleep_until(end.into()) => {},
                }
            }
        } else {
            tokio::select! { biased;
                result = writer.write_all(&bytes) => result.is_ok(),
                _ = stop.changed() => false,
                _ = tokio::time::sleep_until(end.into()) => false,
            }
        };
        let returned = if custody {
            key::end_custody_write(
                owner,
                output.as_ref().ok_or_else(apple_wire::invalid)?,
                written,
            )
        } else {
            key::end_pending_write(owner, written)
        };
        {
            let mut route = owner
                .apple
                .route
                .try_lock()
                .map_err(|_| BridgeError::cleanup_unknown())?;
            route.ack_writing = false;
            if !written || returned.is_err() {
                route.failed = true;
            } else {
                route.completed = if event.sequence == 1 && route.key_not_generated.is_some() {
                    2
                } else {
                    event.sequence
                };
            }
        }
        if !written || returned.is_err() {
            return Err(BridgeError::cleanup_unknown());
        }
    }
}

fn cancelled(owner: &Session) -> bool {
    owner
        .apple_key
        .get()
        .and_then(|key| key.clock().failure())
        .is_some_and(|(reason, _)| {
            matches!(
                reason,
                crate::asset_commands::Reason::UserCancelled
                    | crate::asset_commands::Reason::Shutdown
                    | crate::asset_commands::Reason::Deadline
            )
        })
}
async fn save_before_finish(inner: &Arc<Inner>, owner: &Arc<Session>) -> Result<(), BridgeError> {
    let mode = owner.apple.input()?.context().mode;
    let parent = owner.apple_key.get().ok_or_else(apple_wire::invalid)?;
    let generated = parent.has_returned_output();
    if generated {
        owner
            .apple
            .input()?
            .key_preservation_current(parent)
            .map_err(|e| local_error(owner, e))?;
        let jobs = owner.apple.native.lock().await;
        let ack = jobs
            .last_key_ack()
            .ok_or_else(BridgeError::cleanup_unknown)?;
        key::dispatch_save(owner, Some(ack))?;
    } else {
        key::dispatch_save(owner, None)?;
    }
    let saved = key::join_asset(owner).await?;
    if generated {
        let reference = saved.ok_or_else(BridgeError::cleanup_unknown)?;
        owner
            .apple
            .input()?
            .key_preservation_current(parent)
            .map_err(|e| local_error(owner, e))?;
        let mut jobs = owner.apple.native.lock().await;
        let ack = jobs
            .last_key_ack()
            .ok_or_else(BridgeError::cleanup_unknown)?;
        if mode != apple_wire::Mode::KeyPrepare
            || ack.row.update.save != ProfileSaveState::Armed
            || reference != ack.original.intent().destination
        {
            return Err(BridgeError::cleanup_unknown());
        }
        let (revision, reservation) = (ack.revision, ack.original.clone());
        let mut update = ack.row.update.clone();
        update.sequence += 1;
        update.save = ProfileSaveState::ReadBack;
        update.saved_reference = Some(reference);
        update.cancel_requested |= cancelled(owner);
        update.disposition = if update.cancel_requested {
            KeyDisposition::Cancelled
        } else {
            KeyDisposition::Prepared
        };
        call(
            inner,
            owner,
            &mut jobs,
            PROFILE_SAVED,
            Call::KeyRecord(revision, reservation, update),
        )
        .await?;
        owner
            .apple
            .input()?
            .key_preservation_current(parent)
            .map_err(|e| local_error(owner, e))?;
    } else if saved.is_some() {
        return Err(BridgeError::cleanup_unknown());
    } else if mode == apple_wire::Mode::KeyPrepare {
        let mut jobs = owner.apple.native.lock().await;
        let update = jobs
            .last_key_ack()
            .filter(|ack| ack.row.update.generation == KeyGeneration::Armed)
            .map(|ack| {
                let mut update = ack.row.update.clone();
                update.sequence += 1;
                update.generation = KeyGeneration::NotEntered;
                update.cancel_requested |= cancelled(owner);
                update.disposition = if update.cancel_requested {
                    KeyDisposition::Cancelled
                } else {
                    KeyDisposition::Failed
                };
                (ack.revision, ack.original.clone(), update)
            });
        if let Some((revision, reservation, update)) = update {
            // dispatch_save(None) already demanded the actual never-entered
            // generator cut, and join_asset demanded the original return.
            call(
                inner,
                owner,
                &mut jobs,
                AUDIT,
                Call::KeyRecord(revision, reservation, update),
            )
            .await?;
        }
    }
    Ok(())
}

pub(super) async fn finish(inner: &Arc<Inner>, owner: &Arc<Session>) -> bool {
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
    let no_generation = match owner.apple.route.try_lock() {
        Ok(route) => route.key_not_generated.clone(),
        Err(_) => return false,
    };
    if key::producer_joined(owner, no_generation.as_ref()).is_err()
        || save_before_finish(inner, owner).await.is_err()
    {
        return false;
    }
    let mut jobs = owner.apple.native.lock().await;
    let (lease, reservation) = {
        let Ok(hold) = jobs.hold.try_lock() else {
            return false;
        };
        if let (Some(lease), Some(journal)) = (&hold.lease, &hold.journal) {
            if !journal.is_for(lease.store(), lease.native_use()) {
                return false;
            }
        } else if hold.lease.is_some() || hold.journal.is_some() {
            return false;
        }
        (
            hold.lease.clone(),
            hold.journal
                .as_ref()
                .and_then(|journal| journal.retained_key_reservation().cloned()),
        )
    };
    let Some(lease) = lease else {
        jobs.sealed = true;
        jobs.complete =
            jobs.slots.iter().all(Slot::known) && !owner.resource_unknown.load(Ordering::SeqCst);
        return jobs.complete;
    };
    if let Some(reservation) = reservation {
        let healthy = jobs.hold.try_lock().is_ok_and(|hold| {
            hold.journal
                .as_ref()
                .is_some_and(|journal| journal.failure().is_none())
        });
        if let Some(ack) = jobs.last_key_ack().filter(|_| healthy) {
            if !Arc::ptr_eq(&ack.original, &reservation)
                || ack.row.native_settlement != NativeSettlement::Pending
            {
                return false;
            }
            let revision = ack.revision;
            let joined =
                match key::native_joined(owner, lease.native_use().clone(), reservation.clone()) {
                    Ok(value) => value,
                    Err(_) => return false,
                };
            if call(
                inner,
                owner,
                &mut jobs,
                PROFILE_FINISH,
                Call::KeyFinish(revision, reservation, joined),
            )
            .await
            .is_err()
                && owner.resource_unknown.load(Ordering::SeqCst)
            {
                return false;
            }
        }
        // A lost ACK does not restore a revision/reservation or allow retry.
        // Its Pending row remains. Only real known jobs can close local use.
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
