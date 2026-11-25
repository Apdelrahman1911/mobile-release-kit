//! Certificate-only phases of the original eleven-job roster and stdin
//! writer. No key-generation, save slot, transport, task or clock is created.
use super::*;
use super::super::super::apple_key::{self as key, certificate};
use crate::apple_provisioning_journal::CertificateJournalAck;

fn terminal_received(inner: &Inner, owner: &Session) -> bool {
    let registry = inner.lock();
    original_session(&registry, owner) && registry.active.as_ref().is_some_and(|active| active.terminal)
}
fn pending_entered(owner: &Session) -> bool {
    owner.apple.route.try_lock().is_ok_and(|route| !route.failed && route.certificate_pending
        .and_then(|step| route.ack_entered.get(step as usize - 1)).copied() == Some(true))
}

async fn event_reply(inner: &Arc<Inner>, owner: &Arc<Session>, phase: u32, event: apple_wire::CertificateEvent)
    -> Result<(Vec<u8>, bool), BridgeError> {
    match event {
        apple_wire::CertificateEvent::Key(value) => Ok((certificate::key_ack(owner, phase, value)?, false)),
        apple_wire::CertificateEvent::Identities(value) => Ok((certificate::identities_ack(owner, phase, value)?, false)),
        apple_wire::CertificateEvent::Policy { input, payload_sha256 } =>
            Ok((certificate::policy_ack(owner, phase, input, payload_sha256)?, false)),
        apple_wire::CertificateEvent::Pending { intent, update } => {
            owner.apple.input()?.check_certificate_before_pending().await.map_err(|error| local_error(owner,error))?;
            certificate::current_pending(owner, &intent)?;
            let binding = owner.apple.request_binding()?;
            let previous = binding.revision;
            let mut jobs = owner.apple.native.lock().await;
            call(inner, owner, &mut jobs, 1, Call::CertificateReserve(intent, update.clone())).await?;
            let ack = jobs.last_certificate_ack().ok_or_else(apple_wire::invalid)?;
            certificate::pending_ack(owner, ack)?;
            Ok((apple_wire::certificate_journal_ack(&binding, phase, "certificate-pending", ack, &update, previous, false)?, false))
        },
        apple_wire::CertificateEvent::Attempt(update) => {
            if !pending_entered(owner) { return Err(apple_wire::invalid()); }
            let mut jobs = owner.apple.native.lock().await;
            let ack = jobs.last_certificate_ack().ok_or_else(apple_wire::invalid)?;
            let (previous, original) = (ack.revision, ack.original.clone());
            let index = usize::try_from(update.sequence).map_err(|_| apple_wire::invalid())?;
            if !(2..=3).contains(&index) { return Err(apple_wire::invalid()); }
            call(inner, owner, &mut jobs, index, Call::CertificateRecord(previous, original, update.clone())).await?;
            let ack = jobs.last_certificate_ack().ok_or_else(apple_wire::invalid)?;
            // A certificate audit ACK is not a continuation grant. Its closed
            // stopped bit is latched by Python before any next work checkpoint.
            let stopped = *owner.stop.borrow() || work_clear(owner).is_err();
            let binding = owner.apple.request_binding()?;
            Ok((apple_wire::certificate_journal_ack(&binding, phase, "certificate-attempt", ack, &update, previous, stopped)?, true))
        },
        apple_wire::CertificateEvent::Observed(_) => Err(apple_wire::invalid()),
    }
}

/// The SAME writer may receive an already-armed receipt audit after STOP. No
/// identity, new Pending or GO may pass this tail; its original F/W/H shrinks.
pub(super) async fn write_phases(inner: &Arc<Inner>, owner: &Arc<Session>, writer: &mut ChildStdin)
    -> Result<(), BridgeError> {
    if !owner.apple.input()?.context().mode.certificate() { return Err(apple_wire::invalid()); }
    loop {
        let wake = owner.apple.changed.notified();
        let original_wake = owner.wake.notified();
        if terminal_received(inner, owner) { return Ok(()); }
        let now = Instant::now();
        if now >= owner.clocks.work && !*owner.stop.borrow() { inner.stop(owner, Reason::TimedOut); }
        let end = journal_cutoff(owner);
        if !audit_clear(owner,end) { return Err(BridgeError::cleanup_unknown()); }
        let event = {
            let mut route = owner.apple.route.try_lock().map_err(|_| BridgeError::cleanup_unknown())?;
            if route.failed { return Err(apple_wire::invalid()); }
            route.pending.take()
        };
        let Some(event) = event else {
            if *owner.stop.borrow() && !pending_entered(owner) { return Ok(()); }
            let mut stop = owner.stop.subscribe();
            let watch_stop = !*stop.borrow();
            tokio::select! { biased;
                _ = wake => {}, _ = original_wake => {},
                _ = stop.changed(), if watch_stop => {},
                _ = tokio::time::sleep_until(end.into()) => {},
            }
            continue;
        };
        let apple_wire::EventData::Certificate(data) = event.data else { return Err(apple_wire::invalid()); };
        let audit = matches!(&data, apple_wire::CertificateEvent::Attempt(_));
        if *owner.stop.borrow() && (!audit || !pending_entered(owner)) { return Ok(()); }
        if !audit { work_clear(owner).map_err(|error| local_error(owner,error))?; }
        let (mut bytes, audit) = event_reply(inner,owner,event.sequence,data).await?;
        // If STOP arrived after constructing an audit ACK, replace only this
        // not-yet-entered buffer's stopped=false with true through the SAME
        // closed serializer, never editing bytes after the first write poll.
        let stopped = if audit {
            let stopped = *owner.stop.borrow() || work_clear(owner).is_err();
            if stopped {
                let jobs = owner.apple.native.lock().await;
                let ack: &CertificateJournalAck = jobs.last_certificate_ack().ok_or_else(apple_wire::invalid)?;
                let binding = owner.apple.request_binding()?;
                let previous = Revision(ack.revision.0.checked_sub(1).ok_or_else(apple_wire::invalid)?);
                bytes = apple_wire::certificate_journal_ack(&binding, event.sequence, "certificate-attempt", ack, &ack.row.update, previous, true)?;
            }
            stopped
        } else { work_clear(owner).map_err(|error| local_error(owner,error))?; false };
        let index = usize::try_from(event.sequence).map_err(|_| apple_wire::invalid())? - 1;
        {
            let mut route = owner.apple.route.try_lock().map_err(|_| BridgeError::cleanup_unknown())?;
            if route.failed || route.completed.checked_add(1) != Some(event.sequence) || route.ack_writing
                || route.ack_entered.get(index) != Some(&false) { return Err(apple_wire::invalid()); }
            route.ack_writing = true; route.ack_entered[index] = true;
        }
        // Same pinned original write, including STOP-after-first-write and
        // an earlier cutoff discovered while an audit ACK is partially sent.
        // This never grants later work or turns partial writes into receipts.
        let written = certificate::write_ack(owner, writer, &bytes, stopped).await;
        {
            let mut route = owner.apple.route.try_lock().map_err(|_| BridgeError::cleanup_unknown())?;
            route.ack_writing = false;
            if !written { route.failed = true; }
            else { route.completed = if route.certificate_observed.is_some() && route.received == event.sequence + 1
                { route.received } else { event.sequence }; }
        }
        if !written { return Err(BridgeError::cleanup_unknown()); }
    }
}

pub(super) async fn finish(inner: &Arc<Inner>, owner: &Arc<Session>) -> bool {
    { let book = owner.resources.lock().await; if !worker_joined(inner,owner,&book) { return false; } }
    { let jobs = owner.apple.native.lock().await; if jobs.sealed || !jobs.pre_joined() { return false; } }
    let result = {
        let registry = inner.lock();
        registry.active.as_ref().filter(|active| original_session(&registry,owner)
            && !active.unknown && active.first_stop.is_none() && active.projection.outcome == Some(Outcome::Complete))
            .and_then(|active| match &active.projection.result {
                Some(Terminal::AppleProvisioning(terminal)) => terminal.result.as_ref().and_then(apple_wire::ResultData::certificate).cloned(),
                _ => None,
            })
    };
    if key::producer_joined(owner,None).is_err() { return false; }
    if let Err(error) = certificate::producer_joined(owner,result.as_ref()) {
        // A late known STOP/source refusal can withdraw the provisional
        // association, not strand an otherwise joined read-only key loan.
        // Keep the original first failure; no binding/success is published.
        // Unknown still retains everything and cannot use this cleanup cut.
        local_error(owner,error);
        if owner.resource_unknown.load(Ordering::SeqCst) { return false; }
    }
    if key::dispatch_save(owner,None).is_err() { return false; }
    if !matches!(key::join_asset(owner).await, Ok(None)) { return false; }
    let mut jobs = owner.apple.native.lock().await;
    let (lease, reservation) = {
        let Ok(hold) = jobs.hold.try_lock() else { return false; };
        match (&hold.lease,&hold.journal) {
            (Some(lease),Some(journal)) if journal.is_for(lease.store(),lease.native_use()) =>
                (Some(lease.clone()),journal.retained_certificate_reservation().cloned()),
            (None,None) => (None,None), _ => return false,
        }
    };
    let Some(lease) = lease else { jobs.sealed=true; jobs.complete=jobs.slots.iter().all(Slot::known); return jobs.complete; };
    if let Some(original) = reservation {
        // Exact reserve ACK but no Pending write was ever entered. Only this
        // original successful worker/IO join permits a bounded no-send audit.
        let no_ack = owner.apple.route.try_lock().is_ok_and(|route| route.certificate_pending
            .and_then(|step| route.ack_entered.get(step as usize - 1)).copied() == Some(false));
        let cancelled = {
            let registry = inner.lock();
            registry.active.as_ref().is_some_and(|active| original_session(&registry, owner)
                && matches!(active.projection.reason, Reason::Cancelled | Reason::DocumentLost | Reason::Shutdown))
        };
        let no_send = jobs.last_certificate_ack().filter(|ack| no_ack && ack.row.update.sequence == 1).map(|ack| {
            let mut update = ack.row.update.clone(); update.sequence+=1;
            update.record.status=if cancelled { AttemptStatus::Cancelled } else { AttemptStatus::Failed };
            update.record.reason=if cancelled { AttemptReason::CancelledBeforeSend } else { AttemptReason::AuthorizationChanged };
            update.record.possible_send=false; update.record.cancel_requested|=cancelled;
            (ack.revision,update)
        });
        if let Some((revision,update)) = no_send {
            if call(inner,owner,&mut jobs,AUDIT,Call::CertificateRecord(revision,original.clone(),update)).await.is_err()
                && owner.resource_unknown.load(Ordering::SeqCst) { return false; }
        }
        let healthy = jobs.hold.try_lock().is_ok_and(|hold| hold.journal.as_ref().is_some_and(|journal| journal.failure().is_none()));
        if let Some(ack) = jobs.last_certificate_ack().filter(|_| healthy) {
            if !Arc::ptr_eq(&ack.original,&original) || ack.row.native_settlement != NativeSettlement::Pending { return false; }
            let revision=ack.revision;
            let Ok(joined) = certificate::native_joined(owner,lease.native_use().clone(),original.clone()) else { return false; };
            if call(inner,owner,&mut jobs,PROFILE_FINISH,Call::CertificateFinish(revision,original,joined)).await.is_err()
                && owner.resource_unknown.load(Ordering::SeqCst) { return false; }
        }
        // Lost durable ACK never reconstructs its revision or adopts the row.
        // Pending remains even after all genuinely known local jobs settle.
    }
    if !jobs.slots[..PROFILE_RETIRE].iter().all(Slot::known) || owner.resource_unknown.load(Ordering::SeqCst) { return false; }
    jobs.sealed=true;
    let joined=AppleProvisioningAllJobsJoined { native_use:lease.native_use().clone() };
    if call(inner,owner,&mut jobs,PROFILE_RETIRE,Call::Retire(joined)).await.is_err() { return false; }
    jobs.complete=jobs.slots[PROFILE_RETIRE].known()
        && matches!(jobs.slots[PROFILE_RETIRE].returned.as_ref(),Some(Ok(Value::Retired)))
        && !owner.resource_unknown.load(Ordering::SeqCst);
    jobs.complete
}
