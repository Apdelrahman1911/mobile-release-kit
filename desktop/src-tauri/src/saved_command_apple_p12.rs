//! The fixed P12 save/derived-output facet of the SAME AppleKeySession.
//! No additional Session, clock, process, journal, task or byte getter is
//! introduced. These capabilities are constructed only by the original
//! native job/pipe path below; serialized review/results cannot create them.
use super::*;
use crate::{
    apple_provisioning_journal::{
        P12Assembly, P12Disposition, P12JournalAck, P12OriginalReservation, P12OutputMetadata,
        P12SaveIntent,
    },
    asset_commands::AppleP12Password,
    asset_session::AppleP12Destination,
};

#[path = "saved_command_apple_p12_private.rs"]
mod private;

pub(super) struct State {
    destination: OnceLock<Weak<AppleP12Destination>>,
    password: OnceLock<Weak<AppleP12Password>>,
    receive: Option<Arc<private::ReceiveBook>>,
    reservation: OnceLock<Arc<P12OriginalReservation>>,
    output: OnceLock<P12OutputMetadata>,
    password_entered: AtomicBool,
    password_returned: AtomicBool,
    no_save_joined: AtomicBool,
}
impl State {
    pub(super) fn reserve(mode: wire::Mode) -> Result<Option<Self>, BridgeError> {
        if !mode.p12() {
            return Ok(None);
        }
        Ok(Some(Self {
            destination: OnceLock::new(),
            password: OnceLock::new(),
            receive: if mode == wire::Mode::P12Save {
                Some(private::ReceiveBook::reserved()?)
            } else {
                None
            },
            reservation: OnceLock::new(),
            output: OnceLock::new(),
            password_entered: AtomicBool::new(false),
            password_returned: AtomicBool::new(false),
            no_save_joined: AtomicBool::new(false),
        }))
    }
}
fn state(parent: &AppleKeySession) -> Result<&State, BridgeError> {
    parent.p12.as_ref().ok_or_else(invalid)
}
pub(super) fn backing_bytes(mode: wire::Mode) -> Option<usize> {
    if !mode.p12() {
        return Some(0);
    }
    std::mem::size_of::<State>()
        .checked_add(if mode == wire::Mode::P12Save {
            private::ReceiveBook::retained_bytes()?
        } else {
            0
        })?
        .checked_add(std::mem::size_of::<AppleP12PendingAck>())?
        .checked_add(std::mem::size_of::<AppleP12SavePermit>())?
        .checked_add(std::mem::size_of::<AppleP12NoSaveJoined>())?
        .checked_add(std::mem::size_of::<AppleP12NativeJoined>())?
        .checked_add(64 + 4 * 64)
}
impl AppleKeySession {
    /// Mode DATA only. Admission and every use still compare the actual
    /// original parent/input/loan; this accessor cannot mint a permit.
    pub(crate) fn p12_mode(&self) -> Option<wire::Mode> {
        self.mode.p12().then_some(self.mode)
    }
    pub(crate) fn attach_p12_destination(
        &self,
        original: &Arc<OriginalWork>,
        destination: &Arc<AppleP12Destination>,
    ) -> Result<(), BridgeError> {
        let data = state(self)?;
        if self.mode != wire::Mode::P12Save
            || !self.same_asset(original)
            || self.phase() != Some(SavePhase::Waiting)
            || self.clock.interrupted()
            || data.destination.get().is_some()
            || data.password.get().is_some()
            || !self
                .loan
                .get()
                .and_then(Weak::upgrade)
                .is_some_and(|loan| destination.same_source(&loan))
        {
            return Err(invalid());
        }
        let password = destination
            .password_original(original)
            .map_err(|_| asset_error())?;
        data.destination
            .set(Arc::downgrade(destination))
            .map_err(|_| invalid())?;
        data.password
            .set(Arc::downgrade(&password))
            .map_err(|_| invalid())
    }
    pub(crate) fn p12_destination_data(&self) -> Result<Option<KeyReference>, BridgeError> {
        if !self.mode.p12() || self.phase() != Some(SavePhase::Waiting) {
            return Err(invalid());
        }
        if self.mode != wire::Mode::P12Save {
            return Ok(None);
        }
        state(self)?
            .destination
            .get()
            .and_then(Weak::upgrade)
            .map(|value| Some(value.descriptor()))
            .ok_or_else(invalid)
    }
    pub(crate) fn p12_before_pending_returned(
        &self,
        original: &Arc<OriginalWork>,
    ) -> Result<(), BridgeError> {
        if self.mode != wire::Mode::P12Save
            || !self.same_asset(original)
            || self.clock.interrupted()
            || !self.source_returned.load(Ordering::SeqCst)
            || !original.apple_p12_before_pending_checked(self)
            || self.before_pending_returned.swap(true, Ordering::SeqCst)
        {
            return Err(invalid());
        }
        Ok(())
    }
}
fn same_destination(
    parent: &AppleKeySession,
    original: &Arc<OriginalWork>,
    destination: &AppleP12Destination,
) -> bool {
    parent.same_asset(original)
        && state(parent).is_ok_and(|data| {
            data.destination
                .get()
                .and_then(Weak::upgrade)
                .is_some_and(|same| std::ptr::eq(same.as_ref(), destination))
        })
}
fn same_password(parent: &AppleKeySession, password: &Arc<AppleP12Password>) -> bool {
    state(parent).is_ok_and(|data| {
        data.password
            .get()
            .and_then(Weak::upgrade)
            .is_some_and(|same| Arc::ptr_eq(&same, password))
    })
}
fn source_binding(
    parent: &Arc<AppleKeySession>,
    original: &Arc<OriginalWork>,
    request: &Arc<wire::RequestBinding>,
    output: &P12OutputMetadata,
) -> bool {
    let Some(loan) = parent.loan.get().and_then(Weak::upgrade) else {
        return false;
    };
    // Fixed child comparison to the actual final same-worker holder. This is
    // never used for cleanup, which cannot renew a certificate or save.
    certificate::confirms_p12(
        parent,
        original,
        &loan,
        request,
        &output.certificate_sha256,
        &output.public_key_sha256,
    )
}
fn save_sources_current(
    parent: &Arc<AppleKeySession>,
    original: &Arc<OriginalWork>,
    request: &Arc<wire::RequestBinding>,
    output: &P12OutputMetadata,
) -> bool {
    parent.mode == wire::Mode::P12Save
        && parent.same_asset(original)
        && parent.same_binding(request)
        && !parent.clock.interrupted()
        && !parent.clock.completed()
        && Instant::now() < parent.clock.work_end()
        && parent.worker_joined.load(Ordering::SeqCst)
        && !parent.all_jobs_joined.load(Ordering::SeqCst)
        && !parent.private_drained.load(Ordering::SeqCst)
        && state(parent).is_ok_and(|data| {
            data.password_returned.load(Ordering::SeqCst)
                && !data.no_save_joined.load(Ordering::SeqCst)
                && data.output.get() == Some(output)
                && data
                    .receive
                    .as_ref()
                    .is_some_and(|receive| receive.returned_matches(output))
        })
        && parent
            .owner()
            .is_ok_and(|owner| !owner.resource_unknown.load(Ordering::SeqCst))
        && source_binding(parent, original, request, output)
}
fn save_current(
    parent: &Arc<AppleKeySession>,
    original: &Arc<OriginalWork>,
    request: &Arc<wire::RequestBinding>,
    output: &P12OutputMetadata,
) -> bool {
    matches!(
        parent.phase(),
        Some(SavePhase::Claimed | SavePhase::ReturnedSaved)
    ) && save_sources_current(parent, original, request, output)
}

/// Normal Terminal closes the already-finished worker input using owner.stop.
/// That signal is NOT a cancellation receipt. This checks the actual original
/// dispatch state instead; it is only one conjunct, never native save authority.
fn normal_terminal_for_save(inner: &Inner, owner: &Session, output: &P12OutputMetadata) -> bool {
    if inner.domain != SavedCommandDomain::AppleProvisioning
        || !matches!(&owner.context, Context::AppleProvisioning(context) if context.mode == wire::Mode::P12Save)
        || inner.poisoned.load(Ordering::SeqCst)
        || owner.resource_unknown.load(Ordering::SeqCst)
        || !owner
            .native_failure
            .try_lock()
            .is_ok_and(|first| first.is_none())
        || Instant::now() >= owner.clocks.work
        || !owner
            .apple_key
            .get()
            .is_some_and(|parent| !parent.clock.interrupted() && !parent.clock.completed())
    {
        return false;
    }
    let registry = inner.lock();
    original_session(&registry, owner)
        && !registry.disabled
        && !registry.exhausted
        && !registry.stopping
        && !registry.document_lost
        && registry.active.as_ref().is_some_and(|active| {
            active.accepted
                && active.terminal
                && !active.unknown
                && !active.work_expired
                && !active.context_invalidated
                && !active.final_join_seen
                && active.first_stop.is_none()
                && active.projection.phase == Phase::Stopping
                && active.projection.reason == Reason::None
                && active.projection.outcome == Some(Outcome::Complete)
                && matches!(&active.projection.result,
                    Some(Terminal::AppleProvisioning(terminal))
                        if terminal.settled()
                            && terminal.outcome == wire::Outcome::Complete
                            && terminal.reason == wire::Reason::None
                            && terminal.result.as_ref().and_then(wire::ResultData::p12)
                                .is_some_and(|result| result.decision == wire::P12Decision::Assembled
                                    && result.positive_identity()
                                    && result.output.as_ref() == Some(output)))
        })
}

/// Fixed post-worker P12-save admission, used before/inside the save-armed CAS
/// and at the original one-use dispatch. The ordinary pre-worker work_clear is
/// unchanged. No first failure, timeout or lost currentness is waived here.
pub(in crate::saved_command_owner) fn post_worker_save_clear(
    inner: &Inner,
    owner: &Arc<Session>,
) -> Result<(), BridgeError> {
    let parent = original(owner)?;
    let data = state(parent)?;
    let output = data.output.get().ok_or_else(invalid)?;
    if !normal_terminal_for_save(inner, owner, output) {
        return Err(invalid());
    }
    let asset = parent
        .original
        .get()
        .and_then(Weak::upgrade)
        .ok_or_else(invalid)?;
    let request = parent.binding.get().ok_or_else(invalid)?;
    // This repeats the consumed review/current Document checks OFF Registry,
    // private journal, vault and dispatch locks. It cannot renew the review.
    owner.apple.p12_save_current()?;
    if parent.phase() != Some(SavePhase::Waiting)
        || !parent.source_returned.load(Ordering::SeqCst)
        || !parent.before_pending_returned.load(Ordering::SeqCst)
        || !parent.pending_ack_returned.load(Ordering::SeqCst)
        || !save_sources_current(parent, &asset, request, output)
        || !normal_terminal_for_save(inner, owner, output)
    {
        return Err(invalid());
    }
    Ok(())
}

pub(crate) struct AppleP12PendingAck {
    parent: Arc<AppleKeySession>,
    request: Arc<wire::RequestBinding>,
    reservation: Arc<P12OriginalReservation>,
}
impl AppleP12PendingAck {
    pub(crate) fn matches(
        &self,
        destination: &AppleP12Destination,
        original: &Arc<OriginalWork>,
    ) -> bool {
        let intent = self.reservation.intent();
        same_destination(&self.parent, original, destination)
            && self.parent.same_binding(&self.request)
            && self.parent.before_pending_returned.load(Ordering::SeqCst)
            && intent.destination == destination.descriptor()
            && intent.source_key == destination.source_reference()
            && intent.context == self.request.scope.provisioning
            && intent.request_binding_sha256 == self.request.certificate_digest()
            && self.request.scope.p12.as_ref().is_some_and(|scope| {
                scope.destination.as_ref() == Some(&intent.destination)
                    && scope.source_key == intent.source_key
                    && scope.source_p8 == intent.source_p8
            })
            && state(&self.parent).is_ok_and(|data| {
                data.reservation
                    .get()
                    .is_some_and(|same| Arc::ptr_eq(same, &self.reservation))
            })
    }
    pub(crate) fn own_retained_bytes(&self) -> Option<usize> {
        Some(std::mem::size_of::<Self>())
    }
}

/// Save authority only after original process/IO/runtime/driver joins and the
/// distinct local save-armed CAS. STOP does not authorize a preservation save:
/// the source key is already durable. It may only enable known cleanup later.
pub(crate) struct AppleP12SavePermit {
    parent: Arc<AppleKeySession>,
    request: Arc<wire::RequestBinding>,
    reservation: Arc<P12OriginalReservation>,
    output: P12OutputMetadata,
    seal_entered: bool,
    readback: bool,
    disposed: bool,
}
impl AppleP12SavePermit {
    fn binding(&self, original: &Arc<OriginalWork>) -> bool {
        self.parent.same_asset(original)
            && self.parent.same_binding(&self.request)
            && self.parent.worker_joined.load(Ordering::SeqCst)
            && self
                .parent
                .owner()
                .is_ok_and(|owner| !owner.resource_unknown.load(Ordering::SeqCst))
            && state(&self.parent).is_ok_and(|data| {
                data.output.get() == Some(&self.output)
                    && data
                        .reservation
                        .get()
                        .is_some_and(|same| Arc::ptr_eq(same, &self.reservation))
            })
    }
    pub(crate) fn save_current(&self, original: &Arc<OriginalWork>) -> bool {
        !self.disposed
            && self.binding(original)
            && save_current(&self.parent, original, &self.request, &self.output)
    }
    pub(crate) fn matches(
        &self,
        destination: &AppleP12Destination,
        original: &Arc<OriginalWork>,
    ) -> bool {
        self.save_current(original)
            && same_destination(&self.parent, original, destination)
            && self.reservation.intent().destination == destination.descriptor()
            && self.reservation.intent().source_key == destination.source_reference()
    }
    pub(crate) fn seal_p12(
        &mut self,
        reserved: &mut crate::vault_crypto::ReservedAppleP12,
        key: &crate::vault_crypto::VaultKey,
        password: &Arc<AppleP12Password>,
        allowance: usize,
        original: &Arc<OriginalWork>,
    ) -> Result<crate::vault_crypto::SealedRecord, crate::vault_crypto::Error> {
        use crate::vault_crypto::Error;
        if self.seal_entered || self.disposed {
            return Err(Error::Authentication);
        }
        self.seal_entered = true;
        let (identity, record, revision) = reserved.descriptor();
        if !self.save_current(original)
            || !same_password(&self.parent, password)
            || KeyReference::native(identity, record, revision)
                != self.reservation.intent().destination
        {
            return Err(Error::Authentication);
        }
        state(&self.parent)
            .map_err(|_| Error::Authentication)?
            .receive
            .as_ref()
            .ok_or(Error::Authentication)?
            .seal_p12(reserved, key, password, allowance, &self.output)
    }
    pub(crate) fn matches_authenticated_readback(
        &mut self,
        record: &crate::vault_crypto::AuthenticatedRecord,
        password: &Arc<AppleP12Password>,
        original: &Arc<OriginalWork>,
    ) -> bool {
        if !self.seal_entered
            || self.readback
            || !self.save_current(original)
            || !same_password(&self.parent, password)
            || !self
                .reservation
                .intent()
                .destination
                .parts()
                .is_ok_and(|(_, id, rev)| id == record.record && rev == record.revision)
            || !state(&self.parent).is_ok_and(|data| {
                data.receive
                    .as_ref()
                    .is_some_and(|receive| receive.matches_readback(record, password, &self.output))
            })
        {
            return false;
        }
        self.readback = true;
        true
    }
    pub(crate) fn retirement_ready(
        &self,
        destination: &AppleP12Destination,
        original: &Arc<OriginalWork>,
    ) -> bool {
        !self.disposed
            && self.seal_entered
            && self.readback
            && self.binding(original)
            && self.parent.cleanup_ready(original)
            && same_destination(&self.parent, original, destination)
            && destination.retirement_binding(original, &self.reservation.intent().destination)
            && !state(&self.parent).is_ok_and(|data| data.no_save_joined.load(Ordering::SeqCst))
    }
    pub(crate) fn try_retire_saved(
        &mut self,
        destination: &AppleP12Destination,
        original: &Arc<OriginalWork>,
    ) -> bool {
        if !self.retirement_ready(destination, original)
            || !state(&self.parent).is_ok_and(|data| {
                data.receive
                    .as_ref()
                    .is_some_and(|receive| receive.drain_saved(&self.output))
            })
        {
            return false;
        }
        self.disposed = true;
        true // same source loan/Asset retirement still follows
    }
    pub(crate) fn own_retained_bytes(&self) -> Option<usize> {
        std::mem::size_of::<Self>()
            .checked_add(self.output.frame_sha256.capacity())?
            .checked_add(self.output.p12_sha256.capacity())?
            .checked_add(self.output.certificate_sha256.capacity())?
            .checked_add(self.output.public_key_sha256.capacity())
    }
}

pub(crate) struct AppleP12NoSaveJoined {
    parent: Arc<AppleKeySession>,
    destination: KeyReference,
    disposed: bool,
}
impl AppleP12NoSaveJoined {
    fn binding(&self, original: &Arc<OriginalWork>) -> bool {
        !self.disposed
            && self.parent.cleanup_ready(original)
            && self.parent.phase() == Some(SavePhase::ReturnedRefused)
            && state(&self.parent).is_ok_and(|data| {
                data.no_save_joined.load(Ordering::SeqCst)
                    && data
                        .receive
                        .as_ref()
                        .is_some_and(|receive| match data.output.get() {
                            Some(output) => receive.returned_matches(output),
                            None => receive.no_body_returned(),
                        })
            })
    }
    pub(crate) fn matches(
        &self,
        destination: &AppleP12Destination,
        original: &Arc<OriginalWork>,
    ) -> bool {
        self.binding(original)
            && same_destination(&self.parent, original, destination)
            && destination.no_save_candidate(original, &self.destination)
    }
    pub(crate) fn retirement_ready(
        &self,
        destination: &AppleP12Destination,
        original: &Arc<OriginalWork>,
    ) -> bool {
        self.binding(original)
            && same_destination(&self.parent, original, destination)
            && destination.no_save_binding(original, &self.destination)
    }
    pub(crate) fn try_retire_refused(
        &mut self,
        destination: &AppleP12Destination,
        original: &Arc<OriginalWork>,
    ) -> bool {
        if !self.retirement_ready(destination, original)
            || !state(&self.parent).is_ok_and(|data| {
                data.receive
                    .as_ref()
                    .is_some_and(|receive| receive.drain_no_save(data.output.get()))
            })
        {
            return false;
        }
        self.disposed = true;
        true
    }
    pub(crate) fn own_retained_bytes(&self) -> Option<usize> {
        std::mem::size_of::<Self>()
            .checked_add(self.destination.vault_id.capacity())?
            .checked_add(self.destination.generation_id.capacity())?
            .checked_add(self.destination.record_id.capacity())?
            .checked_add(self.destination.revision_id.capacity())
    }
}
pub(crate) struct AppleP12NativeJoined {
    native_use: Arc<NativeUse>,
    reservation: Arc<P12OriginalReservation>,
}
impl AppleP12NativeJoined {
    pub(crate) fn matches(
        &self,
        native_use: &Arc<NativeUse>,
        reservation: &Arc<P12OriginalReservation>,
    ) -> bool {
        Arc::ptr_eq(&self.native_use, native_use) && Arc::ptr_eq(&self.reservation, reservation)
    }
}

pub(super) fn bind_request(
    owner: &Session,
    binding: &Arc<wire::RequestBinding>,
    bytes: &[u8],
) -> Result<(), BridgeError> {
    let parent = original(owner)?;
    if !parent.mode.p12() || parent.mode != binding.context.mode {
        return Err(invalid());
    }
    if let Some(receive) = &state(parent)?.receive {
        receive.bind_request(bytes)?;
    }
    Ok(())
}
pub(in crate::saved_command_owner) async fn read_output<T: AsyncRead + Unpin + OriginalClose>(
    inner: Arc<Inner>,
    owner: Arc<Session>,
    slot: Arc<AsyncMutex<Pipe<T>>>,
    guard: Guard,
) -> ReadEnd {
    let receive = owner
        .apple_key
        .get()
        .and_then(|parent| parent.p12.as_ref())
        .and_then(|data| data.receive.clone());
    let Some(receive) = receive else {
        inner.unknown(&owner);
        return ReadEnd {
            frames: 0,
            eof: false,
            closed: false,
            failed: true,
            decoder_settled: false,
        };
    };
    private::read(inner, owner, slot, receive, guard).await
}
pub(in crate::saved_command_owner) fn current_pending(
    owner: &Session,
    intent: &P12SaveIntent,
) -> Result<(), BridgeError> {
    let parent = original(owner)?;
    let request = parent.binding.get().ok_or_else(invalid)?;
    if parent.mode != wire::Mode::P12Save
        || parent.clock.interrupted()
        || parent.phase() != Some(SavePhase::Waiting)
        || !parent.source_returned.load(Ordering::SeqCst)
        || !parent.before_pending_returned.load(Ordering::SeqCst)
        || !state(parent)?.password_returned.load(Ordering::SeqCst)
        || intent.context != request.scope.provisioning
        || intent.request_binding_sha256 != request.certificate_digest()
        || !request.scope.p12.as_ref().is_some_and(|scope| {
            scope.source_key == intent.source_key
                && scope.source_p8 == intent.source_p8
                && scope.destination.as_ref() == Some(&intent.destination)
        })
    {
        return Err(invalid());
    }
    owner.apple.input()?.current()
}
pub(in crate::saved_command_owner) fn pending_ack(
    owner: &Arc<Session>,
    ack: &P12JournalAck,
) -> Result<(), BridgeError> {
    current_pending(owner, ack.original.intent())?;
    if ack.row.update.sequence != 1
        || ack.row.update.assembly != P12Assembly::Armed
        || ack.row.update.save != ProfileSaveState::NotEntered
        || ack.row.update.cancel_requested
        || ack.row.native_settlement != NativeSettlement::Pending
    {
        return Err(invalid());
    }
    let parent = original(owner)?.clone();
    let asset = parent
        .original
        .get()
        .and_then(Weak::upgrade)
        .ok_or_else(invalid)?;
    let data = state(&parent)?;
    data.reservation
        .set(ack.original.clone())
        .map_err(|_| invalid())?;
    let destination = data
        .destination
        .get()
        .and_then(Weak::upgrade)
        .ok_or_else(invalid)?;
    destination
        .record_pending(
            &asset,
            AppleP12PendingAck {
                request: parent.binding.get().ok_or_else(invalid)?.clone(),
                parent: parent.clone(),
                reservation: ack.original.clone(),
            },
        )
        .map_err(|_| asset_error())
}
pub(in crate::saved_command_owner) fn output_custody(
    owner: &Session,
    output: &P12OutputMetadata,
) -> Result<(), BridgeError> {
    let parent = original(owner)?;
    let data = state(parent)?;
    if !parent.pending_ack_returned.load(Ordering::SeqCst)
        || !data
            .receive
            .as_ref()
            .is_some_and(|r| r.custody_matches(output))
        || !data
            .reservation
            .get()
            .is_some_and(|r| output.valid(r.intent()))
    {
        return Err(invalid());
    }
    data.output.set(output.clone()).map_err(|_| invalid())
}
pub(in crate::saved_command_owner) fn begin_custody_write(
    owner: &Session,
    output: &P12OutputMetadata,
) -> Result<(), BridgeError> {
    let parent = original(owner)?;
    let data = state(parent)?;
    if data.output.get() != Some(output) || parent.clock.interrupted() {
        return Err(invalid());
    }
    data.receive.as_ref().ok_or_else(invalid)?.begin_ack(output)
}
pub(in crate::saved_command_owner) fn end_custody_write(
    owner: &Session,
    output: &P12OutputMetadata,
    written: bool,
) -> Result<(), BridgeError> {
    if !state(original(owner)?)?
        .receive
        .as_ref()
        .is_some_and(|r| r.end_ack(output, written))
    {
        return Err(BridgeError::cleanup_unknown());
    }
    Ok(())
}

/// Only the native finish path after genuine original worker/IO/driver/runtime
/// joins may close the no-save slot. An ACK/frame/STOP cannot call this path.
#[cfg(all(
    target_os = "macos",
    target_pointer_width = "64",
    any(target_arch = "aarch64", target_arch = "x86_64")
))]
pub(in crate::saved_command_owner) fn producer_joined(
    owner: &Arc<Session>,
) -> Result<(), BridgeError> {
    let parent = original(owner)?;
    let data = state(parent)?;
    if !parent.worker_joined.load(Ordering::SeqCst)
        || owner.resource_unknown.load(Ordering::SeqCst)
        || !matches!(
            parent.phase(),
            Some(SavePhase::Waiting | SavePhase::NotCreated)
        )
    {
        return Err(BridgeError::cleanup_unknown());
    }
    if parent.mode == wire::Mode::P12Save {
        let receive = data.receive.as_ref().ok_or_else(invalid)?;
        let known = match data.output.get() {
            Some(output) => receive.returned_matches(output),
            None => receive.no_body_returned(),
        };
        if !known {
            return Err(BridgeError::cleanup_unknown());
        }
    }
    Ok(())
}
#[cfg(all(
    target_os = "macos",
    target_pointer_width = "64",
    any(target_arch = "aarch64", target_arch = "x86_64")
))]
pub(in crate::saved_command_owner) fn dispatch_save(
    inner: &Inner,
    owner: &Arc<Session>,
    ack: Option<&P12JournalAck>,
) -> Result<(), BridgeError> {
    let parent = original(owner)?.clone();
    let data = state(&parent)?;
    producer_joined(owner)?;
    let permit = if let Some(ack) = ack {
        post_worker_save_clear(inner, owner)?;
        let output = ack.row.update.output.as_ref().ok_or_else(invalid)?;
        let asset = parent
            .original
            .get()
            .and_then(Weak::upgrade)
            .ok_or_else(invalid)?;
        let request = parent.binding.get().ok_or_else(invalid)?.clone();
        if parent.mode != wire::Mode::P12Save
            || parent.clock.interrupted()
            || ack.row.update.assembly != P12Assembly::Returned
            || ack.row.update.save != ProfileSaveState::Armed
            || ack.row.native_settlement != NativeSettlement::Pending
            || data.output.get() != Some(output)
            || !data
                .reservation
                .get()
                .is_some_and(|same| Arc::ptr_eq(same, &ack.original))
            || !source_binding(&parent, &asset, &request, output)
        {
            return Err(invalid());
        }
        Some(AppleKeySaveCommand::P12(AppleP12SavePermit {
            parent: parent.clone(),
            request,
            reservation: ack.original.clone(),
            output: output.clone(),
            seal_entered: false,
            readback: false,
            disposed: false,
        }))
    } else {
        None
    };
    let mut slot = parent
        .dispatch
        .try_lock()
        .map_err(|_| BridgeError::cleanup_unknown())?;
    let saving = permit.is_some();
    // A real STOP between the above admission and this one-use claim still
    // vetoes a new save. A normal Terminal's pipe signal never clears F.
    if saving && (parent.clock.interrupted() || parent.clock.completed()) {
        return Err(invalid());
    }
    if parent.phase() == Some(SavePhase::NotCreated) {
        if saving || parent.original.get().is_some() || slot.is_some() {
            return Err(BridgeError::cleanup_unknown());
        }
        data.no_save_joined.store(true, Ordering::SeqCst);
        return Ok(());
    }
    parent.transition(
        SavePhase::Waiting,
        if saving {
            SavePhase::Claimed
        } else {
            SavePhase::ClosedNotRun
        },
    )?;
    if !saving {
        data.no_save_joined.store(true, Ordering::SeqCst);
    }
    let sender = slot.take().ok_or_else(BridgeError::cleanup_unknown)?;
    if sender.send(permit).is_err() && saving {
        return Err(BridgeError::cleanup_unknown());
    }
    Ok(())
}
#[cfg(all(
    target_os = "macos",
    target_pointer_width = "64",
    any(target_arch = "aarch64", target_arch = "x86_64")
))]
pub(in crate::saved_command_owner) fn native_joined(
    owner: &Arc<Session>,
    native_use: Arc<NativeUse>,
    reservation: Arc<P12OriginalReservation>,
) -> Result<AppleP12NativeJoined, BridgeError> {
    let parent = original(owner)?;
    let data = state(parent)?;
    if !parent.worker_joined.load(Ordering::SeqCst)
        || owner.resource_unknown.load(Ordering::SeqCst)
        || !matches!(
            parent.phase(),
            Some(SavePhase::ReturnedSaved | SavePhase::ReturnedRefused)
        )
        || !data
            .reservation
            .get()
            .is_some_and(|same| Arc::ptr_eq(same, &reservation))
        || reservation.intent().context != owner.apple.request_binding()?.scope.provisioning
        || parent.phase() == Some(SavePhase::ReturnedRefused)
            && !data.no_save_joined.load(Ordering::SeqCst)
    {
        return Err(BridgeError::cleanup_unknown());
    }
    Ok(AppleP12NativeJoined {
        native_use,
        reservation,
    })
}

/// Called from the original finish_private after ALL native jobs/NativeUse
/// returned. It prepares proofs only; common Asset retirement must still
/// prove Store close, original release/coordinator joins and source empty.
#[cfg(all(
    target_os = "macos",
    target_pointer_width = "64",
    any(target_arch = "aarch64", target_arch = "x86_64")
))]
pub(super) fn prepare_private_finish(
    parent: &Arc<AppleKeySession>,
    asset: &Arc<OriginalWork>,
) -> Result<(), BridgeError> {
    let data = state(parent)?;
    if !parent.cleanup_ready(asset) {
        return Err(BridgeError::cleanup_unknown());
    }
    if let Some(loan) = parent.loan.get().and_then(Weak::upgrade) {
        loan.accept_joined(
            asset,
            AppleKeyUseJoined {
                parent: parent.clone(),
                reference: loan.reference(),
                disposed: false,
            },
        )
        .map_err(|_| asset_error())?;
    } else if data.destination.get().is_some() || parent.phase() != Some(SavePhase::ReturnedRefused)
    {
        return Err(BridgeError::cleanup_unknown());
    }
    if let Some(destination) = data.destination.get().and_then(Weak::upgrade) {
        if parent.phase() == Some(SavePhase::ReturnedRefused) {
            destination
                .accept_no_save(
                    asset,
                    AppleP12NoSaveJoined {
                        parent: parent.clone(),
                        destination: destination.descriptor(),
                        disposed: false,
                    },
                )
                .map_err(|_| asset_error())?;
        } else if parent.phase() != Some(SavePhase::ReturnedSaved) {
            return Err(BridgeError::cleanup_unknown());
        }
    } else if parent.mode == wire::Mode::P12Save {
        if !data.no_save_joined.load(Ordering::SeqCst)
            || parent.phase() != Some(SavePhase::ReturnedRefused)
            || !data
                .receive
                .as_ref()
                .is_some_and(|r| r.drain_no_save(data.output.get()))
        {
            return Err(BridgeError::cleanup_unknown());
        }
    }
    Ok(())
}

/// Pre-Asset refusal only after the real native worker/no-work roster joins.
/// The absence of an Asset by itself is not a receiver/drain proof.
pub(super) fn finish_without_asset(parent: &AppleKeySession) -> bool {
    parent.phase() == Some(SavePhase::NotCreated)
        && parent.original.get().is_none()
        && parent.worker_joined.load(Ordering::SeqCst)
        && parent.all_jobs_joined.load(Ordering::SeqCst)
        && state(parent).is_ok_and(|data| {
            data.no_save_joined.load(Ordering::SeqCst)
                && data.destination.get().is_none()
                && data.password.get().is_none()
                && data.reservation.get().is_none()
                && data.output.get().is_none()
                && data
                    .receive
                    .as_ref()
                    .is_none_or(|receive| receive.drain_no_save(None))
        })
}

/// Only the caller AFTER the actual original Asset/source retirement uses
/// this pre-Load refusal cut. No private Loan or destination was published;
/// an absent/expired Weak that once existed does not satisfy it.
pub(super) fn finish_unloaded_after_asset(parent: &AppleKeySession) -> bool {
    parent.mode.p12()
        && parent.phase() == Some(SavePhase::ReturnedRefused)
        && parent.original.get().is_some()
        && parent.loan.get().is_none()
        && parent.worker_joined.load(Ordering::SeqCst)
        && parent.all_jobs_joined.load(Ordering::SeqCst)
        && state(parent).is_ok_and(|data| {
            data.no_save_joined.load(Ordering::SeqCst)
                && data.destination.get().is_none()
                && data.password.get().is_none()
                && data.reservation.get().is_none()
                && data.output.get().is_none()
                && data
                    .receive
                    .as_ref()
                    .is_none_or(|receive| receive.drained())
        })
}

pub(in crate::saved_command_owner) fn output(owner: &Session) -> Option<&P12OutputMetadata> {
    owner.apple_key.get()?.p12.as_ref()?.output.get()
}

#[cfg(all(
    feature = "desktop-shell",
    target_os = "macos",
    target_pointer_width = "64",
    any(target_arch = "aarch64", target_arch = "x86_64")
))]
#[path = "saved_command_apple_p12_input.rs"]
mod input;
#[cfg(all(
    feature = "desktop-shell",
    target_os = "macos",
    target_pointer_width = "64",
    any(target_arch = "aarch64", target_arch = "x86_64")
))]
pub(in crate::saved_command_owner) use input::write_material;
#[cfg(all(
    feature = "desktop-shell",
    target_os = "macos",
    target_pointer_width = "64",
    any(target_arch = "aarch64", target_arch = "x86_64")
))]
pub(crate) use input::PrivateAppleP12Input;

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn session() -> (
        SavedCommandOwner,
        Arc<Session>,
        P12OutputMetadata,
        wire::Terminal,
    ) {
        let context = wire::prepare(&json!({
            "projectId":"fixture","draftRevision":1,"baselineGeneration":1,
            "savedConfig":{"bytes":20,"sha256":"a".repeat(64)},
            "savedVersion":{"source":"version.properties","bytes":20,"sha256":"b".repeat(64),"name":"1.2.3","build":1},
            "credentialContextRevision":1,"recordId":"c".repeat(32),"recordRevision":1,
            "keyRecordId":"d".repeat(32),"keyRecordRevision":1,
            "p12RecordId":null,"p12RecordRevision":null,
            "executionMode":"local","platform":"ios","mode":"p12-save",
            "reference":{"operationId":"e".repeat(32),"ownerGeneration":"f".repeat(32)},
            "newApplication":false,"displayName":"Synthetic P12 setup"
        })).unwrap().context;
        let output = P12OutputMetadata {
            frame_bytes: 88,
            frame_sha256: "1".repeat(64),
            p12_bytes: 4,
            p12_sha256: "2".repeat(64),
            certificate_sha256: "3".repeat(64),
            public_key_sha256: "4".repeat(64),
        };
        let terminal = serde_json::from_value(json!({
            "schemaVersion":1,"context":context,"outcome":"complete","reason":"none",
            "result":{"schemaVersion":1,"scope":"local-ios-p12-setup","mode":"p12-save",
                "decision":"assembled","reason":"producer-returned","certificateId":"ABC123",
                "certificateSha256":output.certificate_sha256,"publicKeySha256":output.public_key_sha256,
                "output":output,"reused":null,"p12Saved":false,"profileSaved":false,
                "credentialReady":false,"revocationChecked":false},
            "lifetime":{"complete":true,"fatal":false,"contained":true,"commandDispatched":true,
                "commands":15,"profileCalls":1,"inputClosed":true,"handlersRestored":true,
                "invocationClosed":true,"stopObserved":"none"}
        })).unwrap();
        let application = SavedCommandOwner::apple_provisioning(RuntimeConfig::packaged(
            std::path::PathBuf::from("/unopened-p12-terminal-test-runtime"),
        ));
        let (application, original) = crate::saved_command_owner::tests::active_with_context(
            application,
            Context::AppleProvisioning(context),
        );
        super::super::initialize(&original).unwrap();
        (application, original, output, terminal)
    }

    #[test]
    fn original_normal_terminal_pipe_stop_is_not_failure_and_never_substitutes_for_save_joins() {
        for reason in [
            Reason::Cancelled,
            Reason::ContextChanged,
            Reason::TimedOut,
            Reason::Shutdown,
            Reason::CleanupUnknown,
        ] {
            for before_terminal in [false, true] {
                // Real original reducer/clock, but NO process, key, receiver
                // return, journal, certificate holder or positive native join.
                let (application, original, output, terminal) = session();
                let admitted = original.clocks.admitted;
                let first = admitted + Duration::from_secs(1);
                let later = admitted + Duration::from_secs(3);
                application.inner.accept_at(
                    &original,
                    Frame::AppleProvisioning(wire::Frame::Accepted),
                    admitted,
                );
                assert!(!normal_terminal_for_save(
                    &application.inner,
                    &original,
                    &output
                ));
                if before_terminal {
                    let mut registry = application.inner.lock();
                    application
                        .inner
                        .stop_locked(&mut registry, &original, reason, first);
                }
                // This is the actual dispatch that sets owner.stop to close
                // input. Do not imitate that event by editing the stop flag.
                application.inner.accept_at(
                    &original,
                    Frame::AppleProvisioning(wire::Frame::Terminal(terminal)),
                    admitted + Duration::from_secs(2),
                );
                assert!(*original.stop.borrow());
                assert_eq!(
                    normal_terminal_for_save(&application.inner, &original, &output),
                    !before_terminal
                );
                assert!(post_worker_save_clear(&application.inner, &original).is_err());
                let parent = original.apple_key.get().unwrap();
                assert!(!parent.worker_joined.load(Ordering::SeqCst));
                assert!(parent.loan.get().is_none() && parent.binding.get().is_none());
                assert!(parent.phase() == Some(SavePhase::Unattached));
                if !before_terminal {
                    assert!(parent.clock.failure().is_none());
                    assert!(application
                        .inner
                        .lock()
                        .active
                        .as_ref()
                        .unwrap()
                        .first_stop
                        .is_none());
                    assert_eq!(*original.native_audit_cutoff.borrow(), original.clocks.work);
                    let mut registry = application.inner.lock();
                    application
                        .inner
                        .stop_locked(&mut registry, &original, reason, first);
                }
                {
                    let mut registry = application.inner.lock();
                    application.inner.stop_locked(
                        &mut registry,
                        &original,
                        Reason::Shutdown,
                        later,
                    );
                    assert_eq!(registry.active.as_ref().unwrap().first_stop, Some(first));
                }
                assert!(!normal_terminal_for_save(
                    &application.inner,
                    &original,
                    &output
                ));
                assert!(post_worker_save_clear(&application.inner, &original).is_err());
                assert_eq!(parent.clock.failure().map(|(_, at)| at), Some(first));
                assert_eq!(parent.clock.cleanup_end(), first + SETTLEMENT);
                assert!(
                    !parent.clock.completed() && !parent.private_drained.load(Ordering::SeqCst)
                );
            }
        }
    }
}
