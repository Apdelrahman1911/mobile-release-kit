//! P12 phases of the SAME eleven-job Apple roster and original stdin task.
//! A local Pending precedes assembly; raw custody is not a save ACK. The
//! optional NEW job starts only after the real worker and all its IO join.
use super::super::super::apple_key::{self as key, certificate, p12};
use super::*;
use crate::apple_provisioning_journal::{
    P12Assembly, P12Disposition, P12SaveUpdate, ProfileSaveState,
};

fn terminal_received(inner: &Inner, owner: &Session) -> bool {
    let registry = inner.lock();
    original_session(&registry, owner)
        && registry
            .active
            .as_ref()
            .is_some_and(|active| active.terminal)
}
fn digest(value: &str) -> Result<[u8; 32], BridgeError> {
    let mut result = [0; 32];
    if value.len() != 64 {
        return Err(apple_wire::invalid());
    }
    for (out, pair) in result.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        let n = |b: u8| match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            _ => None,
        };
        *out = n(pair[0])
            .zip(n(pair[1]))
            .map(|(a, b)| a * 16 + b)
            .ok_or_else(apple_wire::invalid)?;
    }
    Ok(result)
}
async fn event_reply(
    inner: &Arc<Inner>,
    owner: &Arc<Session>,
    phase: u32,
    event: apple_wire::EventData,
) -> Result<
    (
        Vec<u8>,
        Option<crate::apple_provisioning_journal::P12OutputMetadata>,
        bool,
    ),
    BridgeError,
> {
    match event {
        apple_wire::EventData::Certificate(apple_wire::CertificateEvent::Key(value)) => {
            Ok((certificate::key_ack(owner, phase, value)?, None, false))
        }
        apple_wire::EventData::Certificate(apple_wire::CertificateEvent::Identities(value)) => {
            Ok((
                certificate::identities_ack(owner, phase, value)?,
                None,
                false,
            ))
        }
        apple_wire::EventData::Certificate(apple_wire::CertificateEvent::Policy {
            input,
            payload_sha256,
        }) => Ok((
            certificate::policy_ack(owner, phase, input, payload_sha256)?,
            None,
            false,
        )),
        apple_wire::EventData::P12(apple_wire::P12Event::Pending { intent, update })
            if phase == 4 =>
        {
            owner
                .apple
                .input()?
                .check_p12_before_pending()
                .await
                .map_err(|e| local_error(owner, e))?;
            p12::current_pending(owner, &intent)?;
            let binding = owner.apple.request_binding()?;
            let previous = binding.revision;
            let mut jobs = owner.apple.native.lock().await;
            call(
                inner,
                owner,
                &mut jobs,
                1,
                Call::P12Reserve(intent, update.clone()),
            )
            .await?;
            let ack = jobs.last_p12_ack().ok_or_else(apple_wire::invalid)?;
            p12::pending_ack(owner, ack)?;
            Ok((
                apple_wire::p12_journal_ack(&binding, phase, ack, &update, previous)?,
                None,
                true,
            ))
        }
        apple_wire::EventData::P12(apple_wire::P12Event::Output(output)) if phase == 5 => {
            p12::output_custody(owner, &output)?;
            let binding = owner.apple.request_binding()?;
            Ok((
                apple_wire::p12_custody_ack(&binding, phase, &output)?,
                Some(output),
                false,
            ))
        }
        _ => Err(apple_wire::invalid()), // No issuer Pending/Attempt or observed ACK.
    }
}

pub(super) async fn write_phases(
    inner: &Arc<Inner>,
    owner: &Arc<Session>,
    writer: &mut ChildStdin,
) -> Result<(), BridgeError> {
    if !owner.apple.input()?.context().mode.p12() {
        return Err(apple_wire::invalid());
    }
    loop {
        let wake = owner.apple.changed.notified();
        let original_wake = owner.wake.notified();
        if terminal_received(inner, owner) {
            return Ok(());
        }
        if Instant::now() >= owner.clocks.work && !*owner.stop.borrow() {
            inner.stop(owner, Reason::TimedOut);
        }
        if owner.resource_unknown.load(Ordering::SeqCst) {
            return Err(BridgeError::cleanup_unknown());
        }
        if *owner.stop.borrow() {
            return Ok(());
        } // Existing outer writer closes; no tail/GO.
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
            tokio::select! {biased;_ = wake=>{},_ = original_wake=>{},_ = stop.changed()=>{},
            _ = tokio::time::sleep_until(owner.clocks.work.into())=>{},}
            continue;
        };
        work_clear(owner).map_err(|e| local_error(owner, e))?;
        let (bytes, output, pending) =
            event_reply(inner, owner, event.sequence, event.data).await?;
        work_clear(owner).map_err(|e| local_error(owner, e))?;
        let index = usize::try_from(event.sequence).map_err(|_| apple_wire::invalid())? - 1;
        {
            let mut route = owner
                .apple
                .route
                .try_lock()
                .map_err(|_| BridgeError::cleanup_unknown())?;
            if route.failed
                || route.completed.checked_add(1) != Some(event.sequence)
                || route.ack_writing
                || route.ack_entered.get(index) != Some(&false)
            {
                return Err(apple_wire::invalid());
            }
            route.ack_writing = true;
            route.ack_entered[index] = true;
        }
        if pending {
            key::begin_pending_write(owner)?;
        }
        if let Some(output) = &output {
            p12::begin_custody_write(owner, output)?;
        }
        // Same pinned write helper, but stopped=false is mandatory in this
        // GET/local branch. An early failure can shorten, never renew it.
        let written = certificate::write_ack(owner, writer, &bytes, false).await;
        let returned = if pending {
            key::end_pending_write(owner, written)
        } else if let Some(output) = &output {
            p12::end_custody_write(owner, output, written)
        } else if written {
            Ok(())
        } else {
            Err(BridgeError::cleanup_unknown())
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
                route.completed =
                    if route.p12_observed.is_some() && route.received == event.sequence + 1 {
                        route.received
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
        .and_then(|p| p.clock().failure())
        .is_some_and(|(reason, _)| {
            matches!(
                reason,
                crate::asset_commands::Reason::UserCancelled
                    | crate::asset_commands::Reason::Shutdown
                    | crate::asset_commands::Reason::Deadline
            )
        })
}
async fn save_before_finish(
    inner: &Arc<Inner>,
    owner: &Arc<Session>,
    positive: bool,
) -> Result<(), BridgeError> {
    let should_save = positive && owner.apple.input()?.context().mode == apple_wire::Mode::P12Save;
    if should_save {
        p12::post_worker_save_clear(inner, owner).map_err(|e| local_error(owner, e))?;
        let output = p12::output(owner)
            .ok_or_else(BridgeError::cleanup_unknown)?
            .clone();
        let mut jobs = owner.apple.native.lock().await;
        let ack = jobs
            .last_p12_ack()
            .ok_or_else(BridgeError::cleanup_unknown)?;
        if ack.row.update.sequence != 1
            || ack.row.update.assembly != P12Assembly::Armed
            || ack.row.update.save != ProfileSaveState::NotEntered
        {
            return Err(apple_wire::invalid());
        }
        let (previous, original) = (ack.revision, ack.original.clone());
        let update = P12SaveUpdate {
            sequence: 2,
            assembly: P12Assembly::Returned,
            output: Some(output),
            save: ProfileSaveState::Armed,
            saved_reference: None,
            disposition: P12Disposition::Running,
            cancel_requested: false,
        };
        call(
            inner,
            owner,
            &mut jobs,
            PROFILE_ARM,
            Call::P12Record(previous, original, update),
        )
        .await?;
        // Once Armed, any failed/ambiguous save dispatch remains fenced. It
        // cannot fall back to the known-never-save path below.
        p12::post_worker_save_clear(inner, owner).map_err(|e| local_error(owner, e))?;
        p12::dispatch_save(
            inner,
            owner,
            Some(
                jobs.last_p12_ack()
                    .ok_or_else(BridgeError::cleanup_unknown)?,
            ),
        )?;
    } else {
        p12::dispatch_save(inner, owner, None)?;
    }
    let saved = key::join_asset(owner).await?; // Actual child+coordinator and NEW publication.
    let mut jobs = owner.apple.native.lock().await;
    if should_save {
        let reference = saved.ok_or_else(BridgeError::cleanup_unknown)?;
        let ack = jobs
            .last_p12_ack()
            .ok_or_else(BridgeError::cleanup_unknown)?;
        if reference != ack.original.intent().destination
            || ack.row.update.save != ProfileSaveState::Armed
        {
            return Err(BridgeError::cleanup_unknown());
        }
        let (previous, original) = (ack.revision, ack.original.clone());
        let mut update = ack.row.update.clone();
        update.sequence += 1;
        update.save = ProfileSaveState::ReadBack;
        update.saved_reference = Some(reference);
        update.disposition = P12Disposition::SavedUnassigned;
        update.cancel_requested |= cancelled(owner);
        // Receipt audit of actual NEW/full readback, not permission for any
        // new effect after STOP. Lost ACK preserves the Armed row and bytes.
        call(
            inner,
            owner,
            &mut jobs,
            PROFILE_SAVED,
            Call::P12Record(previous, original, update),
        )
        .await?;
    } else {
        if saved.is_some() {
            return Err(BridgeError::cleanup_unknown());
        }
        let next = jobs.last_p12_ack().map(|ack| {
            let mut update = ack.row.update.clone();
            update.sequence += 1;
            update.output = p12::output(owner).cloned();
            update.assembly = if update.output.is_some() {
                P12Assembly::Returned
            } else {
                P12Assembly::NoOutputRetained
            };
            update.disposition = P12Disposition::Refused;
            update.cancel_requested |= cancelled(owner);
            (ack.revision, ack.original.clone(), update)
        });
        if let Some((previous, original, update)) = next {
            // NoOutputRetained is not a claim the assembler never executed.
            // It is the joined, fixed save-slot-never-entered refusal only.
            call(
                inner,
                owner,
                &mut jobs,
                AUDIT,
                Call::P12Record(previous, original, update),
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
    let result = {
        let registry = inner.lock();
        registry
            .active
            .as_ref()
            .filter(|active| {
                original_session(&registry, owner)
                    && !active.unknown
                    && active.first_stop.is_none()
                    && active.projection.outcome == Some(Outcome::Complete)
            })
            .and_then(|active| match &active.projection.result {
                Some(Terminal::AppleProvisioning(terminal)) => terminal
                    .result
                    .as_ref()
                    .and_then(apple_wire::ResultData::p12)
                    .cloned(),
                _ => None,
            })
    };
    if key::producer_joined(owner, None).is_err() || p12::producer_joined(owner).is_err() {
        return false;
    }
    let mut positive = result
        .as_ref()
        .is_some_and(apple_wire::P12Result::positive_identity);
    if positive {
        let checked = match owner.apple.input() {
            Ok(input) => input.check_p12_after_worker().await,
            Err(error) => Err(error),
        };
        if let Err(error) = checked {
            local_error(owner, error);
            positive = false;
        }
    }
    if positive {
        if let Some(reused) = result.as_ref().and_then(|result| result.reused.as_ref()) {
            let checked = (|| {
                owner.apple.input()?.p12_reused_current(
                    &reused.source_p12,
                    &digest(&reused.certificate_sha256)?,
                    &digest(&reused.p12_sha256)?,
                )
            })();
            if let Err(error) = checked {
                local_error(owner, error);
                positive = false;
            }
        }
    }
    if positive {
        if let Err(error) = certificate::producer_joined_p12(owner, result.as_ref()) {
            local_error(owner, error);
            positive = false;
        }
    }
    if owner.resource_unknown.load(Ordering::SeqCst)
        || save_before_finish(inner, owner, positive).await.is_err()
    {
        return false;
    }
    let mut jobs = owner.apple.native.lock().await;
    let (lease, reservation) = {
        let Ok(hold) = jobs.hold.try_lock() else {
            return false;
        };
        match (&hold.lease, &hold.journal) {
            (Some(lease), Some(journal)) if journal.is_for(lease.store(), lease.native_use()) => (
                Some(lease.clone()),
                journal.retained_p12_reservation().cloned(),
            ),
            (None, None) => (None, None),
            _ => return false,
        }
    };
    let Some(lease) = lease else {
        jobs.sealed = true;
        jobs.complete =
            jobs.slots.iter().all(Slot::known) && !owner.resource_unknown.load(Ordering::SeqCst);
        return jobs.complete;
    };
    if let Some(original) = reservation {
        let healthy = jobs
            .hold
            .try_lock()
            .is_ok_and(|hold| hold.journal.as_ref().is_some_and(|j| j.failure().is_none()));
        if let Some(ack) = jobs.last_p12_ack().filter(|_| healthy) {
            if !Arc::ptr_eq(&ack.original, &original)
                || ack.row.native_settlement != NativeSettlement::Pending
            {
                return false;
            }
            let revision = ack.revision;
            let Ok(joined) =
                p12::native_joined(owner, lease.native_use().clone(), original.clone())
            else {
                return false;
            };
            if call(
                inner,
                owner,
                &mut jobs,
                PROFILE_FINISH,
                Call::P12Finish(revision, original, joined),
            )
            .await
            .is_err()
                && owner.resource_unknown.load(Ordering::SeqCst)
            {
                return false;
            }
        }
    }
    if !jobs.slots[..PROFILE_RETIRE].iter().all(Slot::known)
        || owner.resource_unknown.load(Ordering::SeqCst)
    {
        return false;
    }
    jobs.sealed = true;
    if call(
        inner,
        owner,
        &mut jobs,
        PROFILE_RETIRE,
        Call::Retire(AppleProvisioningAllJobsJoined {
            native_use: lease.native_use().clone(),
        }),
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
