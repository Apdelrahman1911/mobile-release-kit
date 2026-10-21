//! Profile facts of the SAME SavedCommand Apple Session. A journal row cannot
//! construct these capabilities; no constructor is exported to a codec, IPC
//! caller, restored reservation or test fixture.
use std::sync::Arc;

use crate::{
    apple_provisioning_journal::ProfileOriginalReservation, application_state_store::NativeUse,
};

/// The original worker/provider/CMS/private receive consumers AND the fixed
/// vault save/readback jobs have returned and joined. This fact deliberately
/// excludes the final journal CAS and subsequent native-use retirement job.
/// Those remain on the SAME original parent's finite roster.
pub(crate) struct AppleProfileNativeJoined {
    native_use: Arc<NativeUse>,
    reservation: Arc<ProfileOriginalReservation>,
}

impl AppleProfileNativeJoined {
    pub(crate) fn matches(
        &self,
        native_use: &Arc<NativeUse>,
        reservation: &Arc<ProfileOriginalReservation>,
    ) -> bool {
        Arc::ptr_eq(&self.native_use, native_use) && Arc::ptr_eq(&self.reservation, reservation)
    }
}

use super::*;
use crate::{
    apple_provisioning_journal::{ProfileJournalAck, ProfileSaveState, ProfileUpdate},
    apple_provisioning_protocol as wire,
    asset_commands::Reason as AssetReason,
    asset_session::{AppleProfileDestination, OriginalWork},
    credential_setup::KeyReference,
};
use std::sync::{OnceLock, Weak};

#[path = "saved_command_apple_profile_clock.rs"]
mod clock;
pub(crate) use clock::AppleProvisioningClock;
#[path = "saved_command_apple_profile_private.rs"]
mod private;

/// The finite save slot is retained BEFORE the Asset coordinator is admitted.
/// A failed send of a permit is still Claimed: it cannot become a no-save fact.
#[derive(Clone, Copy, PartialEq, Eq)]
enum SavePhase {
    NotCreated,
    Unattached,
    Waiting,
    Claimed,
    ClosedNotRun,
    ReturnedSaved,
    ReturnedRefused,
}
struct AssetSlot {
    original: Option<Weak<OriginalWork>>,
    destination: Option<Weak<AppleProfileDestination>>,
    dispatch: Option<oneshot::Sender<Option<AppleProfileSavePermit>>>,
    phase: SavePhase,
}

/// SAME SavedSession backing. Only original Start constructs this, before
/// attaching/reserving the Asset destination. No parsed row can reconstruct it.
pub(crate) struct AppleProfileSession {
    owner: Weak<Session>,
    clock: Arc<AppleProvisioningClock>,
    receive: Arc<private::ReceiveBook>,
    asset: Mutex<AssetSlot>,
    identity: Mutex<Option<wire::IdentityComparison>>,
    save_mode: bool,
    source_returned: AtomicBool,
    worker_joined: AtomicBool,
    all_jobs_joined: AtomicBool,
    private_drained: AtomicBool,
    saved_reference: OnceLock<KeyReference>,
}
#[derive(Default)]
pub(super) struct State {
    original: OnceLock<Arc<AppleProfileSession>>,
}
impl State {
    pub(super) fn get(&self) -> Option<&Arc<AppleProfileSession>> {
        self.original.get()
    }
}

pub(super) fn initialize(owner: &Arc<Session>) -> Result<(), BridgeError> {
    let Context::AppleProvisioning(context) = &owner.context else {
        return Ok(());
    };
    if !context.mode.profile() {
        return Ok(());
    }
    let original = Arc::new(AppleProfileSession {
        owner: Arc::downgrade(owner),
        clock: AppleProvisioningClock::for_session(owner)?,
        receive: private::ReceiveBook::reserved(context.mode.profile_save())?,
        asset: Mutex::new(AssetSlot {
            original: None,
            destination: None,
            dispatch: None,
            phase: SavePhase::Unattached,
        }),
        identity: Mutex::new(None),
        save_mode: context.mode.profile_save(),
        source_returned: AtomicBool::new(false),
        worker_joined: AtomicBool::new(false),
        all_jobs_joined: AtomicBool::new(false),
        private_drained: AtomicBool::new(false),
        saved_reference: OnceLock::new(),
    });
    owner
        .apple_profile
        .original
        .set(original)
        .map_err(|_| wire::invalid())
}

/// Fixed profile-only backing quoted before the SAME Session is allocated.
/// Shared RequestBinding/journal/Source objects are charged by their original
/// books, not recursively by the token Arcs below.
pub(super) fn backing_bytes() -> Option<usize> {
    std::mem::size_of::<AppleProfileSession>()
        .checked_add(2 * std::mem::size_of::<usize>())?
        .checked_add(std::mem::size_of::<AppleProvisioningClock>())?
        .checked_add(2 * std::mem::size_of::<usize>())?
        .checked_add(private::ReceiveBook::retained_bytes()?)?
        .checked_add(std::mem::size_of::<wire::IdentityComparison>())?
        .checked_add(4 * 64)?
        .checked_add(std::mem::size_of::<AppleProfilePendingAck>())?
        .checked_add(std::mem::size_of::<AppleProfileSavePermit>())?
        .checked_add(std::mem::size_of::<AppleProfileNoSaveJoined>())?
        .checked_add(2 * 4 * 32)
}

fn original(owner: &Session) -> Result<&Arc<AppleProfileSession>, BridgeError> {
    owner.apple_profile.get().ok_or_else(wire::invalid)
}
fn digest(value: &str) -> Result<[u8; 32], BridgeError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(wire::invalid());
    }
    let mut result = [0; 32];
    for (out, pair) in result.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        let digit = |b: u8| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
        *out = digit(pair[0]) * 16 + digit(pair[1]);
    }
    Ok(result)
}
fn asset_error() -> BridgeError {
    BridgeError::new("apple_provisioning_credentials", "The original signing input or encrypted profile save is unavailable. Keep the existing setup and review recovery.")
}
fn failure_reason(reason: Reason) -> AssetReason {
    match reason {
        Reason::Cancelled => AssetReason::UserCancelled,
        Reason::DocumentLost => AssetReason::DocumentLost,
        Reason::Shutdown => AssetReason::Shutdown,
        Reason::TimedOut => AssetReason::Deadline,
        Reason::CleanupUnknown => AssetReason::CleanupUnknown,
        _ => AssetReason::ContextStale,
    }
}
pub(super) fn stopped(owner: &Session, reason: Reason, at: Instant) {
    if let Some(profile) = owner.apple_profile.get() {
        profile.clock.latch(failure_reason(reason), at);
    }
}

impl AppleProfileSession {
    pub(crate) fn admission_failed(
        &self,
        input: &crate::asset_session::AppleProvisioningDocumentInput,
        unknown: bool,
        at: Instant,
    ) {
        let Ok(owner) = self.owner() else {
            return;
        };
        if !owner
            .apple
            .input()
            .is_ok_and(|same| std::ptr::eq(same.as_ref(), input))
        {
            owner.resource_unknown.store(true, Ordering::SeqCst);
            return;
        }
        let reason = if unknown {
            AssetReason::CleanupUnknown
        } else {
            AssetReason::ContextStale
        };
        if self
            .asset
            .try_lock()
            .is_ok_and(|slot| slot.phase == SavePhase::Unattached && slot.original.is_none())
        {
            let _ = self.decline_before_asset(reason, at);
        } else {
            self.clock.observe_failure_at(reason, at);
        }
    }
    pub(crate) fn decline_before_asset(
        &self,
        reason: AssetReason,
        at: Instant,
    ) -> Result<(), BridgeError> {
        let mut slot = self
            .asset
            .try_lock()
            .map_err(|_| BridgeError::cleanup_unknown())?;
        if slot.phase != SavePhase::Unattached || slot.original.is_some() || slot.dispatch.is_some()
        {
            return Err(BridgeError::cleanup_unknown());
        }
        slot.phase = SavePhase::NotCreated;
        self.clock.latch(reason, at);
        #[cfg(all(
            target_os = "macos",
            target_pointer_width = "64",
            any(target_arch = "aarch64", target_arch = "x86_64")
        ))]
        self.clock.observe_failure_at(reason, at);
        self.owner()?.apple.changed.notify_waiters();
        Ok(())
    }
    /// Post-provider save checks use original first-F, not the ordinary pipe
    /// STOP sent after every normal Terminal to finish the existing writer.
    pub(crate) fn work_current(&self) -> bool {
        !self.clock.interrupted()
            && self.owner().is_ok_and(|owner| {
                !owner.resource_unknown.load(Ordering::SeqCst)
                    && owner
                        .apple
                        .input()
                        .is_ok_and(|input| input.current().is_ok())
            })
    }
    pub(crate) fn clock(&self) -> &Arc<AppleProvisioningClock> {
        &self.clock
    }
    fn owner(&self) -> Result<Arc<Session>, BridgeError> {
        let owner = self.owner.upgrade().ok_or_else(wire::invalid)?;
        if owner
            .apple_profile
            .get()
            .is_none_or(|same| !std::ptr::eq(same.as_ref(), self))
        {
            return Err(wire::invalid());
        }
        Ok(owner)
    }
    pub(in crate::saved_command_owner) fn same_asset(&self, original: &Arc<OriginalWork>) -> bool {
        self.clock.original_matches(original)
            && self.asset.try_lock().is_ok_and(|slot| {
                slot.original
                    .as_ref()
                    .and_then(Weak::upgrade)
                    .is_some_and(|same| Arc::ptr_eq(&same, original))
            })
    }
    fn destination(
        &self,
        original: &Arc<OriginalWork>,
        destination: &AppleProfileDestination,
    ) -> bool {
        self.same_asset(original)
            && self.asset.try_lock().is_ok_and(|slot| {
                slot.destination
                    .as_ref()
                    .and_then(Weak::upgrade)
                    .is_some_and(|same| std::ptr::eq(same.as_ref(), destination))
            })
    }
    /// Native-only attachment, after the SAME retained Session but before either
    /// original GO. The existing Asset coordinator owns the receiving end.
    pub(crate) fn attach(
        &self,
        original: &Arc<OriginalWork>,
        dispatch: oneshot::Sender<Option<AppleProfileSavePermit>>,
    ) -> Result<(), BridgeError> {
        let owner = self.owner()?;
        let mut slot = self
            .asset
            .try_lock()
            .map_err(|_| BridgeError::cleanup_unknown())?;
        if slot.phase != SavePhase::Unattached || slot.original.is_some() || slot.dispatch.is_some()
        {
            return Err(wire::invalid());
        }
        self.clock.bind_original(&owner, original)?;
        slot.original = Some(Arc::downgrade(original));
        slot.dispatch = Some(dispatch);
        slot.phase = SavePhase::Waiting;
        Ok(())
    }
    pub(crate) fn attach_destination(
        &self,
        original: &Arc<OriginalWork>,
        destination: &Arc<AppleProfileDestination>,
    ) -> Result<(), BridgeError> {
        if !self.same_asset(original) {
            return Err(wire::invalid());
        }
        let mut slot = self
            .asset
            .try_lock()
            .map_err(|_| BridgeError::cleanup_unknown())?;
        if !self.save_mode || slot.phase != SavePhase::Waiting || slot.destination.is_some() {
            return Err(wire::invalid());
        }
        slot.destination = Some(Arc::downgrade(destination));
        Ok(())
    }
    pub(crate) fn destination_data(&self) -> Result<Option<KeyReference>, BridgeError> {
        let slot = self
            .asset
            .try_lock()
            .map_err(|_| BridgeError::cleanup_unknown())?;
        match slot.phase {
            SavePhase::Waiting if !self.save_mode => Ok(None),
            SavePhase::Waiting => Ok(Some(
                slot.destination
                    .as_ref()
                    .and_then(Weak::upgrade)
                    .ok_or_else(wire::invalid)?
                    .descriptor(),
            )),
            _ => Err(wire::invalid()),
        }
    }
    /// Called only after the original Asset source-check child returned and
    /// its native currentness was rechecked. This is not a public producer flag.
    pub(in crate::saved_command_owner) fn note_source_returned(
        &self,
        original: &Arc<OriginalWork>,
    ) -> Result<(), BridgeError> {
        if !self.same_asset(original)
            || self.clock.interrupted()
            || self.source_returned.swap(true, Ordering::SeqCst)
        {
            return Err(wire::invalid());
        }
        let owner = self.owner()?;
        owner.apple.changed.notify_waiters();
        Ok(())
    }
    pub(crate) fn source_check_returned(
        &self,
        original: &Arc<OriginalWork>,
    ) -> Result<(), BridgeError> {
        // The actual Asset child exposes a fixed proof predicate, not a bool.
        if !original.apple_profile_source_checked(self) {
            return Err(wire::invalid());
        }
        self.note_source_returned(original)
    }
    fn cleanup_ready(&self, original: &Arc<OriginalWork>) -> bool {
        self.same_asset(original)
            && self.worker_joined.load(Ordering::SeqCst)
            && self.all_jobs_joined.load(Ordering::SeqCst)
            && self
                .owner()
                .is_ok_and(|owner| !owner.resource_unknown.load(Ordering::SeqCst))
    }
    pub(crate) fn no_more_work(&self, original: &Arc<OriginalWork>) -> bool {
        self.cleanup_ready(original)
    }
    pub(crate) fn own_retained_bytes(&self) -> Option<usize> {
        std::mem::size_of::<Self>()
            .checked_add(2 * std::mem::size_of::<usize>())?
            .checked_add(self.clock.retained_bytes())?
            .checked_add(private::ReceiveBook::retained_bytes()?)
    }
}

/// Durable ACK tied to the exact live reservation. It does not itself grant
/// vault save: the private receiver and actual child joins are still pending.
pub(crate) struct AppleProfilePendingAck {
    parent: Arc<AppleProfileSession>,
    binding: Arc<wire::RequestBinding>,
    reservation: Arc<ProfileOriginalReservation>,
}
impl AppleProfilePendingAck {
    pub(crate) fn matches(
        &self,
        destination: &AppleProfileDestination,
        original: &Arc<OriginalWork>,
    ) -> bool {
        self.parent.destination(original, destination)
            && self.reservation.intent().source_key == destination.source_reference()
            && self.reservation.intent().destination == destination.descriptor()
            && self.binding.scope.signing.as_ref().is_some_and(|scope| {
                scope.source_key == destination.source_reference()
                    && scope.destination.as_ref() == Some(&destination.descriptor())
            })
            && self.parent.owner().is_ok_and(|owner| {
                owner
                    .apple
                    .request_binding()
                    .is_ok_and(|b| Arc::ptr_eq(&b, &self.binding))
            })
    }
    pub(crate) fn own_retained_bytes(&self) -> Option<usize> {
        Some(std::mem::size_of::<Self>())
    }
}

/// Issued at the post-worker, pre-final-CAS slot only after durable SaveArmed.
/// The sole file borrow can enter only the fixed NEW AppleProfile codec.
pub(crate) struct AppleProfileSavePermit {
    parent: Arc<AppleProfileSession>,
    binding: Arc<wire::RequestBinding>,
    reservation: Arc<ProfileOriginalReservation>,
    header: private::Header,
    seal_entered: bool,
    readback: bool,
    disposed: bool,
}
impl AppleProfileSavePermit {
    fn binding(&self, original: &Arc<OriginalWork>) -> bool {
        self.parent.same_asset(original)
            && self.parent.worker_joined.load(Ordering::SeqCst)
            && self.parent.owner().is_ok_and(|owner| {
                !owner.resource_unknown.load(Ordering::SeqCst)
                    && owner
                        .apple
                        .request_binding()
                        .is_ok_and(|binding| Arc::ptr_eq(&binding, &self.binding))
            })
    }
    pub(crate) fn seal_profile(
        &mut self,
        reserved: &mut crate::vault_crypto::ReservedAppleProfile,
        key: &crate::vault_crypto::VaultKey,
        allowance: usize,
        original: &Arc<OriginalWork>,
    ) -> Result<crate::vault_crypto::SealedRecord, crate::vault_crypto::Error> {
        use crate::vault_crypto::Error;
        if self.seal_entered || self.disposed {
            return Err(Error::Authentication);
        }
        self.seal_entered = true; // A refusal cannot reacquire the same save slot.
        if !self.binding(original) || self.parent.clock.interrupted() {
            return Err(Error::Authentication);
        }
        let (identity, record, revision) = reserved.descriptor();
        if KeyReference::native(identity, record, revision) != self.reservation.intent().destination
        {
            return Err(Error::Authentication);
        }
        self.parent
            .receive
            .seal_profile(reserved, key, allowance, self.header)
    }
    pub(crate) fn matches_authenticated_readback(
        &mut self,
        record: &crate::vault_crypto::AuthenticatedRecord,
        original: &Arc<OriginalWork>,
    ) -> bool {
        if !self.seal_entered
            || self.readback
            || self.disposed
            || !self.binding(original)
            || self.parent.clock.interrupted()
        {
            return false;
        }
        let reference = &self.reservation.intent().destination;
        if !reference.parts().is_ok_and(|(_, selected, revision)| {
            selected == record.record && revision == record.revision
        }) || !self.parent.receive.matches_readback(record, self.header)
        {
            return false;
        }
        self.readback = true;
        true
    }
    pub(crate) fn retirement_ready(
        &self,
        destination: &AppleProfileDestination,
        original: &Arc<OriginalWork>,
    ) -> bool {
        // Cleanup-only: a known late STOP never turns a true Published save
        // into permanent private retention. Failure/status is not cleared.
        self.seal_entered
            && self.readback
            && !self.disposed
            && self.binding(original)
            && self.parent.cleanup_ready(original)
            && self.parent.destination(original, destination)
            && destination.retirement_binding(original, &self.reservation.intent().destination)
    }
    pub(crate) fn try_retire_saved(
        &mut self,
        destination: &AppleProfileDestination,
        original: &Arc<OriginalWork>,
    ) -> bool {
        if !self.retirement_ready(destination, original) || !self.parent.receive.drain(false) {
            return false;
        }
        self.disposed = true;
        self.parent.private_drained.store(true, Ordering::SeqCst);
        true
    }
    pub(crate) fn own_retained_bytes(&self) -> Option<usize> {
        Some(std::mem::size_of::<Self>())
    }
}

/// A known closed save slot that was NEVER claimed. Issued only after original
/// worker/source/receive, final CAS and NativeUse retirement actually joined.
/// Provider Pending/Unknown is preserved; this only disposes the local empty
/// destination. It cannot be used after a seal, save claim or unknown handoff.
pub(crate) struct AppleProfileNoSaveJoined {
    parent: Arc<AppleProfileSession>,
    destination: KeyReference,
    disposed: bool,
}
impl AppleProfileNoSaveJoined {
    pub(crate) fn matches(
        &self,
        destination: &AppleProfileDestination,
        original: &Arc<OriginalWork>,
    ) -> bool {
        !self.disposed
            && self.parent.cleanup_ready(original)
            && self.parent.destination(original, destination)
            && self
                .parent
                .asset
                .try_lock()
                .is_ok_and(|slot| slot.phase == SavePhase::ReturnedRefused)
            && destination.no_save_candidate_binding(original, &self.destination)
    }
    pub(crate) fn retirement_ready(
        &self,
        destination: &AppleProfileDestination,
        original: &Arc<OriginalWork>,
    ) -> bool {
        !self.disposed
            && self.parent.cleanup_ready(original)
            && self.parent.destination(original, destination)
            && self
                .parent
                .asset
                .try_lock()
                .is_ok_and(|slot| slot.phase == SavePhase::ReturnedRefused)
            && destination.no_save_binding(original, &self.destination)
    }
    pub(crate) fn try_retire_refused(
        &mut self,
        destination: &AppleProfileDestination,
        original: &Arc<OriginalWork>,
    ) -> bool {
        if !self.retirement_ready(destination, original) || !self.parent.receive.drain(true) {
            return false;
        }
        self.disposed = true;
        self.parent.private_drained.store(true, Ordering::SeqCst);
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

pub(super) async fn read_output<T: AsyncRead + Unpin + OriginalClose>(
    inner: Arc<Inner>,
    owner: Arc<Session>,
    slot: Arc<AsyncMutex<Pipe<T>>>,
    guard: Guard,
) -> ReadEnd {
    let Some(profile) = owner.apple_profile.get().cloned() else {
        inner.unknown(&owner);
        return ReadEnd {
            frames: 0,
            eof: false,
            closed: false,
            failed: true,
            decoder_settled: false,
        };
    };
    private::read(inner, owner, slot, profile.receive.clone(), guard).await
}

pub(super) fn bind_request(owner: &Session, bytes: &[u8]) -> Result<(), BridgeError> {
    match owner.apple_profile.get() {
        Some(profile) => profile.receive.bind_request(bytes),
        None => Ok(()),
    }
}

pub(super) async fn wait_source(
    inner: &Arc<Inner>,
    owner: &Arc<Session>,
) -> Result<(), BridgeError> {
    let Some(profile) = owner.apple_profile.get() else {
        return Ok(());
    };
    loop {
        let changed = owner.apple.changed.notified();
        if profile.source_returned.load(Ordering::SeqCst) {
            return Ok(());
        }
        if profile.clock.interrupted() || *owner.stop.borrow() {
            return Err(asset_error());
        }
        let mut stop = owner.stop.subscribe();
        tokio::select! { biased;
            _ = stop.changed() => return Err(asset_error()),
            _ = tokio::time::sleep_until(owner.clocks.work.into()) => {
                #[cfg(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
                owner.observe_failure_at(Reason::TimedOut, owner.clocks.work, false);
                owner.wake.notify_waiters(); return Err(asset_error());
            },
            _ = changed => {},
        }
    }
}

/// Same private writer's one identity reply, before any Pending. The parser
/// only emits public comparison facts; all loan/clock currentness is retained.
#[cfg(all(
    target_os = "macos",
    target_pointer_width = "64",
    any(target_arch = "aarch64", target_arch = "x86_64")
))]
pub(super) fn identity_ack(
    owner: &Arc<Session>,
    input: wire::IdentityInput,
) -> Result<Vec<u8>, BridgeError> {
    let profile = original(owner)?;
    owner.apple.input()?.current()?;
    let binding = owner.apple.request_binding()?;
    let comparison = wire::IdentityComparison::inspect(
        &binding,
        &input,
        std::time::SystemTime::now(),
        &mut || profile.clock.interrupted() || owner.resource_unknown.load(Ordering::SeqCst),
    )?;
    owner.apple.input()?.current()?;
    let reply = comparison.reply(&binding)?;
    let mut retained = profile
        .identity
        .try_lock()
        .map_err(|_| BridgeError::cleanup_unknown())?;
    if retained.is_some() {
        return Err(wire::invalid());
    }
    *retained = Some(comparison);
    Ok(reply)
}

pub(super) fn current_identity(
    owner: &Session,
    intent: &crate::apple_provisioning_journal::ProfileSetupIntent,
) -> Result<(), BridgeError> {
    let profile = original(owner)?;
    let binding = owner.apple.request_binding()?;
    if !profile.source_returned.load(Ordering::SeqCst)
        || profile.clock.interrupted()
        || !profile.identity.try_lock().is_ok_and(|comparison| {
            comparison
                .as_ref()
                .is_some_and(|proof| proof.matches(&binding, &intent.certificate))
        })
    {
        return Err(wire::invalid());
    }
    owner.apple.input()?.current()
}

pub(super) fn pending_ack(
    owner: &Arc<Session>,
    ack: &ProfileJournalAck,
) -> Result<(), BridgeError> {
    current_identity(owner, ack.original.intent())?;
    if ack.row.update.sequence != 1
        || ack.row.update.save != ProfileSaveState::NotEntered
        || ack.row.native_settlement != crate::apple_provisioning_journal::NativeSettlement::Pending
    {
        return Err(wire::invalid());
    }
    let profile = original(owner)?.clone();
    let (asset, destination) = {
        let slot = profile
            .asset
            .try_lock()
            .map_err(|_| BridgeError::cleanup_unknown())?;
        if slot.phase != SavePhase::Waiting {
            return Err(wire::invalid());
        }
        (
            slot.original
                .as_ref()
                .and_then(Weak::upgrade)
                .ok_or_else(wire::invalid)?,
            slot.destination
                .as_ref()
                .and_then(Weak::upgrade)
                .ok_or_else(wire::invalid)?,
        )
    };
    let permit = AppleProfilePendingAck {
        parent: profile,
        binding: owner.apple.request_binding()?,
        reservation: ack.original.clone(),
    };
    destination
        .record_pending(&asset, permit)
        .map_err(|_| asset_error())
}

/// Caller is the same final observer after actual worker/source/reader/driver/
/// manager joins. It never accepts a child supplied 'closed' boolean here.
#[cfg(all(
    target_os = "macos",
    target_pointer_width = "64",
    any(target_arch = "aarch64", target_arch = "x86_64")
))]
pub(super) fn producer_joined(owner: &Arc<Session>) -> Result<(), BridgeError> {
    let profile = original(owner)?;
    if profile.worker_joined.swap(true, Ordering::SeqCst) {
        return Err(wire::invalid());
    }
    Ok(())
}

#[cfg(all(
    target_os = "macos",
    target_pointer_width = "64",
    any(target_arch = "aarch64", target_arch = "x86_64")
))]
pub(super) fn dispatch_save(
    owner: &Arc<Session>,
    ack: Option<&ProfileJournalAck>,
) -> Result<(), BridgeError> {
    let profile = original(owner)?.clone();
    if !profile.worker_joined.load(Ordering::SeqCst) {
        return Err(wire::invalid());
    }
    let permit = if let Some(ack) = ack {
        current_identity(owner, ack.original.intent())?;
        let download = ack.row.update.download.as_ref().ok_or_else(wire::invalid)?;
        let digest: [u8; 32] = digest(&download.sha256)?;
        if ack.row.update.save != ProfileSaveState::Armed
            || ack.row.update.cancel_requested
            || !profile
                .receive
                .returned_matches(download.bytes as usize, &digest)
        {
            return Err(wire::invalid());
        }
        Some(AppleProfileSavePermit {
            parent: profile.clone(),
            binding: owner.apple.request_binding()?,
            reservation: ack.original.clone(),
            header: private::Header {
                length: download.bytes as usize,
                sha256: digest,
            },
            seal_entered: false,
            readback: false,
            disposed: false,
        })
    } else {
        None
    };
    let mut slot = profile
        .asset
        .try_lock()
        .map_err(|_| BridgeError::cleanup_unknown())?;
    if slot.phase == SavePhase::NotCreated {
        return if permit.is_none() {
            Ok(())
        } else {
            Err(wire::invalid())
        };
    }
    if slot.phase != SavePhase::Waiting {
        return Err(wire::invalid());
    }
    let dispatch = slot.dispatch.take().ok_or_else(wire::invalid)?;
    let saving = permit.is_some();
    slot.phase = if saving {
        SavePhase::Claimed
    } else {
        SavePhase::ClosedNotRun
    };
    // Irreversible before send. Lost receiver after Some(permit) is not NoSave.
    if dispatch.send(permit).is_err() && saving {
        return Err(BridgeError::cleanup_unknown());
    }
    Ok(())
}

#[cfg(all(
    target_os = "macos",
    target_pointer_width = "64",
    any(target_arch = "aarch64", target_arch = "x86_64")
))]
pub(super) async fn join_asset(owner: &Arc<Session>) -> Result<Option<KeyReference>, BridgeError> {
    let profile = original(owner)?;
    let asset = {
        let slot = profile
            .asset
            .try_lock()
            .map_err(|_| BridgeError::cleanup_unknown())?;
        if slot.phase == SavePhase::NotCreated {
            return Ok(None);
        }
        slot.original
            .as_ref()
            .and_then(Weak::upgrade)
            .ok_or_else(wire::invalid)?
    };
    // This observes/reaps the EXISTING Asset coordinator/child. No task or new
    // work is created; its normal publication still requires the original joins.
    let result = owner.apple.input()?.join_profile_asset(&asset).await?;
    let mut slot = profile
        .asset
        .try_lock()
        .map_err(|_| BridgeError::cleanup_unknown())?;
    slot.phase = match (slot.phase, result.as_ref()) {
        (SavePhase::Claimed, Some(_)) => SavePhase::ReturnedSaved,
        (SavePhase::ClosedNotRun, None) => SavePhase::ReturnedRefused,
        _ => return Err(BridgeError::cleanup_unknown()),
    };
    if let Some(reference) = &result {
        profile
            .saved_reference
            .set(reference.clone())
            .map_err(|_| BridgeError::cleanup_unknown())?;
    }
    Ok(result)
}

/// Historical saved-record DATA only, after the actual private drain and
/// complete native-use retirement. It cannot be used as a current vault loan.
pub(super) fn saved_reference(owner: &Session) -> Option<KeyReference> {
    let profile = owner.apple_profile.get()?;
    if !profile.all_jobs_joined.load(Ordering::SeqCst)
        || !profile.private_drained.load(Ordering::SeqCst)
        || !profile.clock.completed()
        || owner.resource_unknown.load(Ordering::SeqCst)
    {
        return None;
    }
    profile.saved_reference.get().cloned()
}

#[cfg(all(
    target_os = "macos",
    target_pointer_width = "64",
    any(target_arch = "aarch64", target_arch = "x86_64")
))]
pub(super) async fn finish_private(owner: &Arc<Session>) -> bool {
    let Ok(profile) = original(owner) else {
        return false;
    };
    // Only called after native::complete rechecked the actual final-CAS and
    // token-retire job. This flag cannot be set by a receipt/row/status caller.
    if !super::apple_provisioning::native_complete(owner)
        || !profile.worker_joined.load(Ordering::SeqCst)
        || owner.resource_unknown.load(Ordering::SeqCst)
    {
        return false;
    }
    profile.all_jobs_joined.store(true, Ordering::SeqCst);
    let detached = {
        let Ok(slot) = profile.asset.try_lock() else {
            return false;
        };
        if slot.phase == SavePhase::NotCreated {
            None
        } else {
            let Some(asset) = slot.original.as_ref().and_then(Weak::upgrade) else {
                return false;
            };
            Some((
                asset,
                slot.destination.as_ref().and_then(Weak::upgrade),
                slot.phase,
            ))
        }
    };
    if let Some((asset, destination, phase)) = detached {
        if phase == SavePhase::ReturnedRefused {
            if let Some(destination) = &destination {
                let proof = AppleProfileNoSaveJoined {
                    parent: profile.clone(),
                    destination: destination.descriptor(),
                    disposed: false,
                };
                if destination.accept_no_save(&asset, proof).is_err() {
                    return false;
                }
            } else if !profile.receive.drain(true) {
                return false;
            } else {
                profile.private_drained.store(true, Ordering::SeqCst);
            }
        } else if phase != SavePhase::ReturnedSaved {
            return false;
        }
        if owner.apple.input().is_err()
            || owner
                .apple
                .input()
                .unwrap()
                .retire_profile_asset(&asset)
                .await
                .is_err()
        {
            return false;
        }
    } else {
        if !profile.receive.drain(true) {
            return false;
        }
        profile.private_drained.store(true, Ordering::SeqCst);
    }
    profile.private_drained.load(Ordering::SeqCst) && profile.clock.mark_completed(owner)
}

#[cfg(all(
    target_os = "macos",
    target_pointer_width = "64",
    any(target_arch = "aarch64", target_arch = "x86_64")
))]
pub(super) fn native_joined(
    owner: &Arc<Session>,
    native_use: Arc<NativeUse>,
    reservation: Arc<ProfileOriginalReservation>,
) -> Result<AppleProfileNativeJoined, BridgeError> {
    let profile = original(owner)?;
    let phase = profile
        .asset
        .try_lock()
        .map_err(|_| BridgeError::cleanup_unknown())?
        .phase;
    if !profile.worker_joined.load(Ordering::SeqCst)
        || owner.resource_unknown.load(Ordering::SeqCst)
        || !matches!(
            phase,
            SavePhase::NotCreated | SavePhase::ReturnedSaved | SavePhase::ReturnedRefused
        )
        || reservation.intent().context != owner.apple.request_binding()?.scope.provisioning
    {
        return Err(BridgeError::cleanup_unknown());
    }
    Ok(AppleProfileNativeJoined {
        native_use,
        reservation,
    })
}
