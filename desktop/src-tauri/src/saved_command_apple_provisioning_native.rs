//! Closed native journal phases of the SAME SavedCommand Session. No process
//! runner, runtime, filesystem service, retry queue or public finality factory.
//! Blocking Store calls only borrow its original NativeUse, OFF all Document,
//! Edit, Host.control and ApplicationService guards. STOP lives in Session and
//! never waits for the private journal job lock.
use super::*;
use crate::{
    apple_provisioning_journal::{
        AccountSnapshot, AppleProvisioningJournal, AttemptReason, AttemptStatus, AttemptUpdate,
        BundleRegistrationIntent, JournalAck, NativeSettlement,
    },
    application_service_host::NativeStateLease,
    application_state_store::{Cleanup, Durability, Effect, Revision, StateError},
    service_protocol::{hex, Error as StateCode},
};
use mrk_macos_installed_native::vault_helper_wire::ClockBridge;

const INITIAL: usize = 0;
const AUDIT: usize = 4;
const FINISH: usize = 5;
const RETIRE: usize = 6;
const JOBS: usize = 7;
const STATE_CALL: Duration = Duration::from_secs(60);

#[derive(Default)]
struct Hold {
    lease: Option<Arc<NativeStateLease>>,
    journal: Option<AppleProvisioningJournal>,
}
enum Value {
    Account(AccountSnapshot),
    Written(JournalAck),
    Retired,
}
enum Call {
    Initialize,
    Reserve(BundleRegistrationIntent, AttemptUpdate),
    Record(Revision, Arc<OriginalReservation>, AttemptUpdate),
    Finish(
        Revision,
        Arc<OriginalReservation>,
        AppleProvisioningNativeJoined,
    ),
    Retire(AppleProvisioningAllJobsJoined),
}
#[derive(Default)]
struct Slot {
    started: bool,
    task: Option<JoinHandle<Result<Value, BridgeError>>>,
    returned: Option<Result<Value, BridgeError>>,
    joined: bool,
    join_error: Option<tokio::task::JoinError>,
}
impl Slot {
    fn known(&self) -> bool {
        if !self.started {
            self.task.is_none()
                && self.returned.is_none()
                && !self.joined
                && self.join_error.is_none()
        } else {
            self.task.is_none()
                && self.returned.is_some()
                && self.joined
                && self.join_error.is_none()
        }
    }
    fn ack(&self) -> Option<&JournalAck> {
        match self.returned.as_ref() {
            Some(Ok(Value::Written(ack))) => Some(ack),
            _ => None,
        }
    }
}

pub(super) struct Jobs {
    hold: Arc<Mutex<Hold>>,
    slots: [Slot; JOBS],
    sealed: bool,
    complete: bool,
}
impl Jobs {
    pub(super) fn new() -> Self {
        Self {
            hold: Arc::new(Mutex::new(Hold::default())),
            slots: std::array::from_fn(|_| Slot::default()),
            sealed: false,
            complete: false,
        }
    }
    fn last_ack(&self) -> Option<&JournalAck> {
        self.slots[1..=FINISH].iter().rev().find_map(Slot::ack)
    }
    fn pre_joined(&self) -> bool {
        self.slots[..AUDIT].iter().all(Slot::known)
    }
    fn journal_joined(&self) -> bool {
        self.slots[..RETIRE].iter().all(Slot::known)
    }
}

fn state_error(owner: &Session, error: StateError) -> BridgeError {
    let unknown = error.cleanup == Cleanup::Unknown
        || error.durability == Durability::Unknown
        || error.effect == Effect::Unknown
        || error.code == StateCode::StateUnknown;
    owner.observe_failure_at(
        if unknown {
            Reason::CleanupUnknown
        } else {
            Reason::JournalUnavailable
        },
        Instant::now(),
        unknown,
    );
    if unknown {
        BridgeError::cleanup_unknown()
    } else {
        BridgeError::new("apple_provisioning_journal_unavailable", "The original local provisioning journal refused this operation. Preserve its state and review recovery.")
    }
}
fn local_error(owner: &Session, error: BridgeError) -> BridgeError {
    let unknown = error.code == "cleanup_unknown";
    owner.observe_failure_at(
        if unknown {
            Reason::CleanupUnknown
        } else {
            Reason::ContextChanged
        },
        Instant::now(),
        unknown,
    );
    error
}
pub(super) fn work_clear(owner: &Session) -> Result<(), BridgeError> {
    if owner.resource_unknown.load(Ordering::SeqCst) {
        return Err(BridgeError::cleanup_unknown());
    }
    let now = Instant::now();
    if *owner.stop.borrow() || now >= owner.clocks.work {
        return Err(BridgeError::new(
            "apple_provisioning_stopped",
            "Bundle-ID provisioning is stopping.",
        ));
    }
    let intent = owner
        .apple
        .intent
        .as_ref()
        .ok_or_else(apple_wire::invalid)?;
    if let Some(review) = &intent.review {
        if now >= review.expires
            || !review.used.load(Ordering::SeqCst)
            || !review.input.same_selection(&intent.input)
        {
            return Err(apple_wire::invalid());
        }
    }
    intent.input.current()
}
fn audit_clear(owner: &Session, end: Instant) -> bool {
    !owner.resource_unknown.load(Ordering::SeqCst)
        && Instant::now() < end
        && Instant::now() < *owner.native_audit_cutoff.borrow()
}
fn call_end(owner: &Session) -> Result<Instant, BridgeError> {
    let now = Instant::now();
    let end = now
        .checked_add(STATE_CALL)
        .ok_or_else(apple_wire::invalid)?
        .min(owner.clocks.work)
        .min(*owner.native_audit_cutoff.borrow());
    if !audit_clear(owner, end) {
        return Err(BridgeError::cleanup_unknown());
    }
    Ok(end)
}

/// The original handle is installed BEFORE GO. An entered call is never
/// aborted, timed out by dropping its future, replaced or retried. The existing
/// join_with_clock keeps the owner/watchdog runnable and retains a late job.
async fn call(
    inner: &Arc<Inner>,
    owner: &Arc<Session>,
    jobs: &mut Jobs,
    index: usize,
    selected: Call,
) -> Result<(), BridgeError> {
    let role_ok = matches!(
        (&selected, index),
        (Call::Initialize, INITIAL)
            | (Call::Reserve(_, _), 1)
            | (Call::Record(_, _, _), 2..=AUDIT)
            | (Call::Finish(_, _, _), FINISH)
            | (Call::Retire(_), RETIRE)
    );
    if !role_ok || index >= JOBS || jobs.slots[index].started || (jobs.sealed && index != RETIRE) {
        return Err(local_error(owner, apple_wire::invalid()));
    }
    let end = call_end(owner)?;
    // New effects require currentness; an already-armed audit uses only the
    // original immutable reservation and cannot authorize a provider call.
    if matches!(&selected, Call::Initialize | Call::Reserve(_, _)) {
        work_clear(owner).map_err(|error| local_error(owner, error))?;
    }
    let input = owner.apple.input()?.clone();
    let held = jobs.hold.clone();
    let original = owner.clone();
    let (release, enter) = oneshot::channel();
    let slot = &mut jobs.slots[index];
    slot.started = true;
    slot.task = Some(tokio::task::spawn_blocking(move || {
        enter
            .blocking_recv()
            .map_err(|_| local_error(&original, apple_wire::invalid()))?;
        if !audit_clear(&original, end) {
            return Err(local_error(&original, BridgeError::cleanup_unknown()));
        }
        if matches!(&selected, Call::Initialize | Call::Reserve(_, _)) {
            work_clear(&original).map_err(|error| local_error(&original, error))?;
        }
        // This mutex is ONLY the finite operation's journal backing. Neither
        // STOP nor a Document/Host status path takes it. The slot's actual
        // JoinHandle, not this mutex or returned JSON, decides join finality.
        let mut held = held
            .lock()
            .map_err(|_| local_error(&original, BridgeError::cleanup_unknown()))?;
        let result = match selected {
            Call::Initialize => {
                if held.lease.is_some() || held.journal.is_some() {
                    return Err(local_error(&original, apple_wire::invalid()));
                }
                let lease = Arc::new(
                    input
                        .ready()
                        .begin_use()
                        .map_err(|error| state_error(&original, error))?,
                );
                // Preserve the SAME lease before entering ANY journal read,
                // including refusal, panic or a lost initialization result.
                held.lease = Some(lease.clone());
                // Start's explicit consent covers this local journal setup.
                // Reuse the fixed same-owner upgrade INSIDE this retained IO
                // job; status/Prepare never upgrades or contacts Apple.
                lease.store().enable_apple_provisioning(lease.native_use())
                    .map_err(|error| state_error(&original, error))?;
                held.journal = Some(AppleProvisioningJournal::new(
                    lease.store().clone(),
                    lease.native_use().clone(),
                ));
                held.journal
                    .as_mut()
                    .ok_or_else(apple_wire::invalid)?
                    .inspect_account(input.account())
                    .map(Value::Account)
            }
            Call::Reserve(intent, update) => {
                let binding = original.apple.request_binding()?;
                held.journal
                    .as_mut()
                    .ok_or_else(apple_wire::invalid)?
                    .reserve(binding.revision, intent, update)
                    .map(Value::Written)
            }
            Call::Record(revision, reservation, update) => held
                .journal
                .as_mut()
                .ok_or_else(apple_wire::invalid)?
                .record_attempt(revision, &reservation, update)
                .map(Value::Written),
            Call::Finish(revision, reservation, joined) => held
                .journal
                .as_mut()
                .ok_or_else(apple_wire::invalid)?
                .finish_native(revision, &reservation, &joined)
                .map(Value::Written),
            Call::Retire(joined) => {
                let lease = held.lease.as_ref().ok_or_else(apple_wire::invalid)?;
                if !joined.matches(lease.native_use()) {
                    return Err(local_error(&original, apple_wire::invalid()));
                }
                lease
                    .store()
                    .retire_native_use(lease.native_use())
                    .map(|()| Value::Retired)
            }
        };
        // Capture the actual first failed return before any subsequent clock
        // check. Do not wrap/erase StateError effect/durability/cleanup facts.
        let result = result.map_err(|error| state_error(&original, error));
        drop(held); // No native currentness callback while holding journal IO.
        if !audit_clear(&original, end) {
            original.observe_failure_at(Reason::TimedOut, end, true);
        }
        // Retain a genuine returned ACK for original cleanup even if a later
        // currentness check vetoes its publication. Never convert it to send
        // permission merely because the CAS itself succeeded.
        result
    }));
    let _ = release.send(());
    let result = {
        // This per-call endpoint is also observed while the original syscall
        // is blocked, not merely at its eventual return. Keep awaiting the
        // SAME original join future after F; never drop/abort/retry the job.
        let joining = join_with_clock(&mut slot.task, inner, owner);
        tokio::pin!(joining);
        let mut expired = false;
        loop {
            tokio::select! { biased;
                _ = tokio::time::sleep_until(end.into()), if !expired => {
                    expired = true;
                    owner.observe_failure_at(Reason::TimedOut, end, true);
                    inner.unknown(owner);
                },
                result = &mut joining => break result,
            }
        }
    };
    match result {
        Ok(value) => {
            slot.joined = true;
            slot.returned = Some(value);
            slot.task.take();
        }
        Err(error) => {
            slot.join_error = Some(error);
            owner.resource_unknown.store(true, Ordering::SeqCst);
            inner.unknown(owner);
            return Err(BridgeError::cleanup_unknown());
        }
    }
    if !audit_clear(owner, end) {
        return Err(BridgeError::cleanup_unknown());
    }
    match slot.returned.as_ref() {
        Some(Ok(_)) => Ok(()),
        Some(Err(error)) => Err(error.clone()),
        None => Err(BridgeError::cleanup_unknown()),
    }
}

pub(super) async fn initialize(
    inner: &Arc<Inner>,
    owner: &Arc<Session>,
) -> Result<(), BridgeError> {
    work_clear(owner).map_err(|error| local_error(owner, error))?;
    let mut jobs = owner.apple.native.lock().await;
    call(inner, owner, &mut jobs, INITIAL, Call::Initialize).await?;
    drop(jobs);
    work_clear(owner).map_err(|error| local_error(owner, error))
}
pub(super) fn request(
    owner: &Session,
    profile: apple_wire::Profile,
    runtime: &VerifiedRuntime,
) -> Result<Vec<u8>, BridgeError> {
    work_clear(owner).map_err(|error| local_error(owner, error))?;
    let input = owner.apple.input()?;
    let scope = input.scope(
        &owner.id,
        &owner.generation,
        owner
            .apple
            .intent
            .as_ref()
            .and_then(|intent| intent.review.as_ref())
            .map(|review| review.observed_at.clone()),
    )?;
    let jobs = owner
        .apple
        .native
        .try_lock()
        .map_err(|_| BridgeError::cleanup_unknown())?;
    if !jobs.pre_joined() || jobs.sealed {
        return Err(apple_wire::invalid());
    }
    let Some(Ok(Value::Account(account))) = jobs.slots[INITIAL].returned.as_ref() else {
        return Err(apple_wire::invalid());
    };
    let prior = if input.context().mode == apple_wire::Mode::Reconcile {
        let reference = input
            .context()
            .reference
            .as_ref()
            .ok_or_else(apple_wire::invalid)?;
        Some(
            account
                .rows
                .iter()
                .find(|row| {
                    row.intent.provenance.operation_id.as_str() == reference.operation_id
                        && row.intent.provenance.owner_generation.as_str()
                            == reference.owner_generation
                })
                .ok_or_else(apple_wire::invalid)?,
        )
    } else {
        None
    };
    let clock = ClockBridge::capture().ok_or_else(apple_wire::invalid)?;
    let mut nonce = [0u8; 16];
    getrandom::fill(&mut nonce).map_err(|_| apple_wire::invalid())?;
    let encoded = apple_wire::request(
        &owner.id,
        &owner.generation,
        input.context(),
        profile,
        &owner.project,
        &runtime.cwd,
        &input.material().provisioning_context_data()?,
        clock
            .endpoint(owner.clocks.work)
            .ok_or_else(apple_wire::invalid)?,
        clock
            .endpoint(owner.clocks.finality)
            .ok_or_else(apple_wire::invalid)?,
        hex(&nonce),
        scope,
        account,
        prior,
    )?;
    let mut binding = owner
        .apple
        .binding
        .try_lock()
        .map_err(|_| BridgeError::cleanup_unknown())?;
    if binding.is_some() {
        return Err(apple_wire::invalid());
    }
    *binding = Some(encoded.binding);
    Ok(encoded.bytes)
}

fn audit_only(update: &AttemptUpdate) -> bool {
    // The response-publication ACK is NOT merely a log acknowledgment: the
    // fixed worker may make its one readback GET afterward. Never issue that
    // ACK after native STOP/currentness loss. Truly final audit records have
    // no remaining provider step in the fixed worker.
    !matches!(
        (update.record.status, update.record.reason),
        (
            AttemptStatus::Running | AttemptStatus::CancellationRequested,
            AttemptReason::ReadbackRequired
        ) | (
            AttemptStatus::RecoveryRequired,
            AttemptReason::ReadbackRequired
        )
    )
}
pub(super) async fn write_phases(
    inner: &Arc<Inner>,
    owner: &Arc<Session>,
    writer: &mut ChildStdin,
) -> Result<(), BridgeError> {
    if owner.apple.input()?.context().mode != apple_wire::Mode::Register {
        return Ok(());
    }
    loop {
        let wake = owner.apple.changed.notified();
        let event = {
            let mut route = owner
                .apple
                .route
                .lock()
                .map_err(|_| BridgeError::cleanup_unknown())?;
            if route.failed {
                return Err(apple_wire::invalid());
            }
            route.pending.take()
        };
        let Some(event) = event else {
            if *owner.stop.borrow() {
                return Ok(());
            }
            let mut stop = owner.stop.subscribe();
            tokio::select! { biased; _ = stop.changed() => return Ok(()), _ = wake => {},
            _ = tokio::time::sleep_until(owner.clocks.work.into()) => return Ok(()) }
            continue;
        };
        let (selected, update, previous) = {
            let jobs = owner.apple.native.lock().await;
            match event.data {
                apple_wire::EventData::Pending { intent, update } if event.sequence == 1 => (
                    Call::Reserve(intent, update.clone()),
                    update,
                    owner.apple.request_binding()?.revision,
                ),
                apple_wire::EventData::Attempt(update)
                    if (2..=apple_wire::MAX_EVENTS).contains(&event.sequence) =>
                {
                    let ack = jobs.last_ack().ok_or_else(apple_wire::invalid)?;
                    (
                        Call::Record(ack.revision, ack.original.clone(), update.clone()),
                        update,
                        ack.revision,
                    )
                }
                _ => return Err(apple_wire::invalid()),
            }
        };
        let index = usize::try_from(event.sequence).map_err(|_| apple_wire::invalid())?;
        let bytes = {
            let mut jobs = owner.apple.native.lock().await;
            call(inner, owner, &mut jobs, index, selected).await?;
            let ack = jobs.slots[index].ack().ok_or_else(apple_wire::invalid)?;
            let binding = owner.apple.request_binding()?;
            apple_wire::journal_ack(binding.as_ref(), ack, &update, previous)?
        };
        let current = work_clear(owner);
        let allow_audit = current.is_err()
            && audit_only(&update)
            && !owner.resource_unknown.load(Ordering::SeqCst)
            && Instant::now() < *owner.native_audit_cutoff.borrow();
        if let Err(error) = current {
            local_error(owner, error);
            if !allow_audit {
                return Ok(());
            }
        }
        {
            let mut route = owner
                .apple
                .route
                .lock()
                .map_err(|_| BridgeError::cleanup_unknown())?;
            if route.failed
                || route.completed.checked_add(1) != Some(event.sequence)
                || route.ack_writing
                || route.ack_entered[index - 1]
            {
                return Err(apple_wire::invalid());
            }
            // Irreversible BEFORE first poll of write_all. Partial/lost ACKs
            // cannot be reclassified as a proved no-send path later.
            route.ack_writing = true;
            route.ack_entered[index - 1] = true;
        }
        let mut stop = owner.stop.subscribe();
        let end = owner.clocks.work.min(*owner.native_audit_cutoff.borrow());
        // A normal terminal also requests pipe STOP, and may arrive as soon as
        // the worker consumes this ACK. Prefer an ALREADY returned write over
        // that same-round-trip notification. An already observed cancellation
        // still refuses before the first write poll; partial/lost writes stay
        // entered and cannot acquire no-send proof.
        let written = if *stop.borrow() && !allow_audit {
            false
        } else {
            tokio::select! { biased;
                result = writer.write_all(&bytes) => result.is_ok(),
                _ = stop.changed(), if !allow_audit => false,
                _ = tokio::time::sleep_until(end.into()) => false,
            }
        };
        {
            let mut route = owner
                .apple
                .route
                .lock()
                .map_err(|_| BridgeError::cleanup_unknown())?;
            route.ack_writing = false;
            if !written {
                route.failed = true;
            } else {
                route.completed = event.sequence;
            }
        }
        if !written {
            return Err(local_error(owner, BridgeError::protocol()));
        }
    }
}

pub(super) fn pre_final_jobs(owner: &Session) -> bool {
    owner
        .apple
        .native
        .try_lock()
        .is_ok_and(|jobs| jobs.pre_joined())
}
fn worker_joined(inner: &Inner, owner: &Session, book: &Resources) -> bool {
    let Ok(startup) = owner.startup.try_lock() else {
        return false;
    };
    let runtime = store::installed_final(book);
    let io_joined = book.writer.is_none()
        && book.stdout.is_none()
        && book.stderr.is_none()
        && !book.write_failed
        && !book.out_failed
        && !book.err_failed
        && book.write_end.is_some()
        && book.out_end.is_some()
        && book.err_end.is_some();
    let startup_joined = book.inspection.is_none()
        && book.acquisition.is_none()
        && !book.inspection_failed
        && !book.acquisition_failed
        && !startup.failed;
    let child = if !startup.attempted {
        !startup.returned
            && startup.child.is_none()
            && book.child.is_none()
            && book.waited.is_none()
            && !book.wait_failed
    } else {
        let registry = inner.lock();
        startup.returned
            && startup.child.is_none()
            && book.acquisition_joined
            && book.inspection_joined
            && book.waited.as_ref().is_some_and(ExitStatus::success)
            && !book.wait_failed
            && book
                .write_end
                .as_ref()
                .is_some_and(|end| end.sent && end.closed && !end.failed)
            && book.out_end.as_ref().is_some_and(|end| {
                end.closed && end.eof && end.protocol_settled_for(&owner.context)
            })
            && book
                .err_end
                .as_ref()
                .is_some_and(|end| end.closed && end.eof && !end.failed && end.frames == 0)
            && original_session(&registry, owner)
            && registry.active.as_ref().is_some_and(|active| {
                active.accepted
                    && active.terminal
                    && matches!(&active.projection.result,
                    Some(Terminal::AppleProvisioning(terminal)) if terminal.lifetime.settled())
            })
    };
    runtime
        && io_joined
        && startup_joined
        && child
        && owner.driver_joined.load(Ordering::SeqCst)
        && !owner.driver_failed.load(Ordering::SeqCst)
        && owner
            .driver_return
            .lock()
            .is_ok_and(|returned| matches!(returned.as_ref(), Some(Ok(()))))
        && owner
            .manager_return
            .lock()
            .is_ok_and(|returned| matches!(returned.as_ref(), Some(Ok(()))))
        && !owner.manager_failed.load(Ordering::SeqCst)
        && !owner.resource_unknown.load(Ordering::SeqCst)
}

pub(super) async fn finish_after_manager(inner: &Arc<Inner>, owner: &Arc<Session>) -> bool {
    // A lost writer/driver cannot abandon an already entered journal job.
    // Join its SAME retained handle before deciding whether any new cleanup
    // effect is permitted. This does not repair the failed outer owner.
    {
        let mut jobs = owner.apple.native.lock().await;
        for slot in &mut jobs.slots[..AUDIT] {
            if slot.task.is_some() && !slot.joined && slot.join_error.is_none() {
                match join_with_clock(&mut slot.task, inner, owner).await {
                    Ok(value) => {
                        slot.joined = true;
                        slot.returned = Some(value);
                        slot.task.take();
                    }
                    Err(error) => {
                        slot.join_error = Some(error);
                        owner.resource_unknown.store(true, Ordering::SeqCst);
                        inner.unknown(owner);
                    }
                }
            }
        }
    }
    // Caller is the original final observer AFTER its genuine manager join.
    // Re-read originals, not an argument containing a caller's success bool.
    let worker = {
        let book = owner.resources.lock().await;
        worker_joined(inner, owner, &book)
    };
    let mut jobs = owner.apple.native.lock().await;
    if jobs.sealed || !jobs.pre_joined() || !worker {
        return false;
    }
    let (lease, reservation) = {
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
                .and_then(|journal| journal.retained_reservation().cloned()),
        )
    };
    let Some(lease) = lease else {
        // Original Start never entered initialization; no NativeUse existed.
        jobs.sealed = true;
        jobs.complete = jobs.journal_joined();
        return jobs.complete;
    };
    if let Some(original) = reservation {
        // At most one post-worker no-send audit, and ONLY if the first ACK's
        // write was NEVER entered. Actual known worker joins alone cannot say
        // whether a sent request was accepted. Restored rows have no original.
        let never_ack = owner
            .apple
            .route
            .lock()
            .is_ok_and(|route| !route.ack_entered[0]);
        if never_ack {
            let cancelled = {
                let registry = inner.lock();
                registry.active.as_ref().is_some_and(|active| {
                    original_session(&registry, owner)
                        && matches!(
                            active.projection.reason,
                            Reason::Cancelled | Reason::DocumentLost | Reason::Shutdown
                        )
                })
            };
            let update = jobs
                .last_ack()
                .filter(|ack| {
                    ack.row.attempt.sequence == 1
                        && ack.row.attempt.record.status == AttemptStatus::Running
                        && ack.row.attempt.record.reason == AttemptReason::ReadbackRequired
                })
                .map(|ack| {
                    let mut update = ack.row.attempt.clone();
                    update.sequence += 1;
                    update.record.status = if cancelled {
                        AttemptStatus::Cancelled
                    } else {
                        AttemptStatus::Failed
                    };
                    update.record.reason = if cancelled {
                        AttemptReason::CancelledBeforeSend
                    } else {
                        AttemptReason::AuthorizationChanged
                    };
                    update.record.cancel_requested |= cancelled;
                    update.record.possible_send = false;
                    (ack.revision, update)
                });
            if let Some((revision, update)) = update {
                let result = call(
                    inner,
                    owner,
                    &mut jobs,
                    AUDIT,
                    Call::Record(revision, original.clone(), update),
                )
                .await;
                if result.is_err() && owner.resource_unknown.load(Ordering::SeqCst) {
                    return false;
                }
            }
        }
        let journal_healthy = jobs.hold.try_lock().is_ok_and(|held| {
            held.journal
                .as_ref()
                .is_some_and(|journal| journal.failure().is_none())
        });
        if let Some(ack) = jobs.last_ack().filter(|_| journal_healthy) {
            if !Arc::ptr_eq(&ack.original, &original)
                || ack.row.native_settlement != NativeSettlement::Pending
            {
                return false;
            }
            let revision = ack.revision;
            // This private fact excludes the final CAS itself and the later
            // observer/watchdog/material-retirement edges. Those cannot form
            // a circular prerequisite for the final CAS which precedes them.
            let joined = AppleProvisioningNativeJoined {
                native_use: lease.native_use().clone(),
                reservation: original.clone(),
            };
            let result = call(
                inner,
                owner,
                &mut jobs,
                FINISH,
                Call::Finish(revision, original, joined),
            )
            .await;
            if result.is_err() && owner.resource_unknown.load(Ordering::SeqCst) {
                return false;
            }
        }
        // Lost reserve ACK: keep the account row Pending. Even after actual
        // jobs joined, do not guess its namespace revision or retry/adopt it.
    }
    if !jobs.journal_joined() || owner.resource_unknown.load(Ordering::SeqCst) {
        return false;
    }
    jobs.sealed = true;
    let all_jobs = AppleProvisioningAllJobsJoined {
        native_use: lease.native_use().clone(),
    };
    // The receipt covers journal writers THROUGH final CAS, not this new
    // retirement syscall. Retain/join its separate original slot before the
    // final observer may return; a late/lost retirement remains Unknown/Busy.
    if call(inner, owner, &mut jobs, RETIRE, Call::Retire(all_jobs))
        .await
        .is_err()
    {
        return false;
    }
    jobs.complete = jobs.slots[RETIRE].known()
        && matches!(
            jobs.slots[RETIRE].returned.as_ref(),
            Some(Ok(Value::Retired))
        )
        && !owner.resource_unknown.load(Ordering::SeqCst);
    jobs.complete
}
pub(super) fn complete(owner: &Session) -> bool {
    owner
        .apple
        .native
        .try_lock()
        .is_ok_and(|jobs| jobs.complete && jobs.sealed && jobs.slots.iter().all(Slot::known))
}
