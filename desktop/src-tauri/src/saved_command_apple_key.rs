//! Local Apple key custody on the SAME SavedCommand Apple Session.
//!
//! No parsed row, public hash, zero-byte output or cancellation creates one of
//! these capabilities. In particular, a generated key is not a profile: an
//! unused vault save slot is NOT permission to dispose of generated output.
use super::*;
use crate::{
    apple_provisioning_journal::{
        CertificateOriginalReservation, KeyDisposition, KeyGeneration, KeyJournalAck,
        KeyOriginalReservation, KeyOutputMetadata, NativeSettlement, ProfileSaveState,
    },
    apple_provisioning_protocol as wire,
    application_state_store::NativeUse,
    asset_commands::Reason as AssetReason,
    asset_session::{AppleDistributionKeyDestination, AppleDistributionKeyLoan, OriginalWork},
    credential_setup::KeyReference,
    service_protocol::hex,
};
use std::sync::{atomic::AtomicU8, OnceLock, Weak};

#[path = "saved_command_apple_key_private.rs"]
mod private;
#[path = "saved_command_apple_certificate.rs"]
pub(in crate::saved_command_owner) mod certificate;
pub(crate) use certificate::AppleDistributionCertificateBinding;
#[path="saved_command_apple_p12.rs"]
pub(in crate::saved_command_owner) mod p12;
pub(crate) use p12::{AppleP12PendingAck,AppleP12SavePermit,AppleP12NoSaveJoined,AppleP12NativeJoined};
#[cfg(all(feature="desktop-shell",target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64")))]
pub(crate) use p12::PrivateAppleP12Input;
/// Closed variants on the original one-use Asset save slot. Never a second writer.
pub(crate) enum AppleKeySaveCommand { Key(AppleKeySavePermit), P12(AppleP12SavePermit) }

/// Pre-final-CAS fact. The final journal CAS and NativeUse retirement are
/// deliberately later original jobs, and are not claimed by this token.
pub(crate) struct AppleKeyNativeJoined {
    native_use: Arc<NativeUse>,
    reservation: Arc<KeyOriginalReservation>,
}
impl AppleKeyNativeJoined {
    pub(crate) fn matches(
        &self,
        native_use: &Arc<NativeUse>,
        reservation: &Arc<KeyOriginalReservation>,
    ) -> bool {
        Arc::ptr_eq(&self.native_use, native_use) && Arc::ptr_eq(&self.reservation, reservation)
    }
}

/// Separate certificate-operation fact. The local generator cannot create it
/// and a keySaved row cannot substitute for the fresh stored-key loan.
pub(crate) struct AppleCertificateNativeJoined {
    native_use: Arc<NativeUse>,
    reservation: Arc<CertificateOriginalReservation>,
}
impl AppleCertificateNativeJoined {
    pub(crate) fn matches(
        &self,
        native_use: &Arc<NativeUse>,
        reservation: &Arc<CertificateOriginalReservation>,
    ) -> bool {
        Arc::ptr_eq(&self.native_use, native_use) && Arc::ptr_eq(&self.reservation, reservation)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum SavePhase {
    Unattached,
    NotCreated,
    Waiting,
    Claimed,
    ClosedNotRun,
    ReturnedSaved,
    ReturnedRefused,
}

/// Retained before any Asset destination or generator is admitted. This is a
/// facet of the existing SavedSession, not a task, clock, process or vault.
pub(crate) struct AppleKeySession {
    owner: Weak<Session>,
    clock: Arc<super::apple_signing::AppleProvisioningClock>,
    mode: wire::Mode,
    certificate: Option<certificate::State>,
    p12: Option<p12::State>,
    original: OnceLock<Weak<OriginalWork>>,
    destination: OnceLock<Weak<AppleDistributionKeyDestination>>,
    loan: OnceLock<Weak<AppleDistributionKeyLoan>>,
    binding: OnceLock<Arc<wire::RequestBinding>>,
    receive: Option<Arc<private::ReceiveBook>>,
    dispatch: Mutex<Option<oneshot::Sender<Option<AppleKeySaveCommand>>>>,
    phase: AtomicU8,
    source_returned: AtomicBool,
    before_pending_returned: AtomicBool,
    pending_ack_entered: AtomicBool,
    pending_ack_returned: AtomicBool,
    worker_joined: AtomicBool,
    generator_never_entered: AtomicBool,
    all_jobs_joined: AtomicBool,
    private_drained: AtomicBool,
    output: OnceLock<KeyOutputMetadata>,
    saved_reference: OnceLock<KeyReference>,
}

#[derive(Default)]
pub(super) struct State {
    original: OnceLock<Arc<AppleKeySession>>,
}
impl State {
    pub(super) fn get(&self) -> Option<&Arc<AppleKeySession>> {
        self.original.get()
    }
}

fn invalid() -> BridgeError {
    wire::invalid()
}
fn asset_error() -> BridgeError {
    BridgeError::new("apple_provisioning_credentials", "The selected encrypted key store is unavailable. Keep the previous setup and review recovery.")
}
fn original(owner: &Session) -> Result<&Arc<AppleKeySession>, BridgeError> {
    owner.apple_key.get().ok_or_else(invalid)
}

pub(super) fn initialize(owner: &Arc<Session>) -> Result<(), BridgeError> {
    let Context::AppleProvisioning(context) = &owner.context else {
        return Ok(());
    };
    if !context.mode.key() {
        return Ok(());
    }
    // Local generation is the only mode with a generated-private receive
    // body. Fresh stored-key operations use their original material loan.
    let receive = if context.mode == wire::Mode::KeyPrepare {
        Some(private::ReceiveBook::reserved()?)
    } else {
        None
    };
    let value = Arc::new(AppleKeySession {
        owner: Arc::downgrade(owner),
        clock: super::apple_signing::AppleProvisioningClock::for_session(owner)?,
        mode: context.mode,
        certificate: (context.mode.certificate() || context.mode.p12()).then(certificate::State::default),
        p12: p12::State::reserve(context.mode)?,
        original: OnceLock::new(),
        destination: OnceLock::new(),
        loan: OnceLock::new(),
        binding: OnceLock::new(),
        receive,
        dispatch: Mutex::new(None),
        phase: AtomicU8::new(SavePhase::Unattached as u8),
        source_returned: AtomicBool::new(false),
        before_pending_returned: AtomicBool::new(false),
        pending_ack_entered: AtomicBool::new(false),
        pending_ack_returned: AtomicBool::new(false),
        worker_joined: AtomicBool::new(false),
        generator_never_entered: AtomicBool::new(false),
        all_jobs_joined: AtomicBool::new(false),
        private_drained: AtomicBool::new(false),
        output: OnceLock::new(),
        saved_reference: OnceLock::new(),
    });
    owner.apple_key.original.set(value).map_err(|_| invalid())
}

pub(super) fn backing_bytes(mode: wire::Mode) -> Option<usize> {
    if !mode.key() {
        return Some(0);
    }
    std::mem::size_of::<AppleKeySession>()
        .checked_add(2 * std::mem::size_of::<usize>())?
        .checked_add(std::mem::size_of::<
            super::apple_signing::AppleProvisioningClock,
        >())?
        .checked_add(2 * std::mem::size_of::<usize>())?
        .checked_add(if mode == wire::Mode::KeyPrepare {
            private::ReceiveBook::retained_bytes()?
        } else {
            0
        })?
        .checked_add(std::mem::size_of::<AppleKeyPendingAck>())?
        .checked_add(std::mem::size_of::<AppleKeySavePermit>())?
        .checked_add(std::mem::size_of::<AppleKeyNeverGeneratedJoined>())?
        .checked_add(std::mem::size_of::<AppleKeyUseJoined>())?
        .checked_add(2 * (4 * 32) + 3 * 64)?
        .checked_add(if mode.certificate() || mode.p12() { certificate::backing_bytes()? } else { 0 })?
        .checked_add(p12::backing_bytes(mode)?)
}

pub(super) fn stopped(owner: &Session, reason: Reason, at: Instant) {
    if let Some(key) = owner.apple_key.get() {
        let reason = match reason {
            Reason::Cancelled => AssetReason::UserCancelled,
            Reason::Shutdown => AssetReason::Shutdown,
            Reason::TimedOut => AssetReason::Deadline,
            Reason::DocumentLost => AssetReason::DocumentLost,
            Reason::CleanupUnknown => AssetReason::CleanupUnknown,
            _ => AssetReason::ContextStale,
        };
        // EVERY excluded later failure is latched, even when the first failure
        // was an allowed cancellation. The first reason/time are not cleared.
        key.clock.latch(reason, at);
    }
}

impl AppleKeySession {
    fn owner(&self) -> Result<Arc<Session>, BridgeError> {
        let owner = self.owner.upgrade().ok_or_else(invalid)?;
        if owner
            .apple_key
            .get()
            .is_none_or(|same| !std::ptr::eq(same.as_ref(), self))
        {
            return Err(invalid());
        }
        Ok(owner)
    }
    fn phase(&self) -> Option<SavePhase> {
        match self.phase.load(Ordering::SeqCst) {
            n if n == SavePhase::Unattached as u8 => Some(SavePhase::Unattached),
            n if n == SavePhase::NotCreated as u8 => Some(SavePhase::NotCreated),
            n if n == SavePhase::Waiting as u8 => Some(SavePhase::Waiting),
            n if n == SavePhase::Claimed as u8 => Some(SavePhase::Claimed),
            n if n == SavePhase::ClosedNotRun as u8 => Some(SavePhase::ClosedNotRun),
            n if n == SavePhase::ReturnedSaved as u8 => Some(SavePhase::ReturnedSaved),
            n if n == SavePhase::ReturnedRefused as u8 => Some(SavePhase::ReturnedRefused),
            _ => None,
        }
    }
    fn transition(&self, from: SavePhase, to: SavePhase) -> Result<(), BridgeError> {
        self.phase
            .compare_exchange(from as u8, to as u8, Ordering::SeqCst, Ordering::SeqCst)
            .map(|_| ())
            .map_err(|_| BridgeError::cleanup_unknown())
    }
    fn same_asset(&self, original: &Arc<OriginalWork>) -> bool {
        self.clock.original_matches(original)
            && self
                .original
                .get()
                .and_then(Weak::upgrade)
                .is_some_and(|same| Arc::ptr_eq(&same, original))
    }
    fn destination_matches(
        &self,
        original: &Arc<OriginalWork>,
        destination: &AppleDistributionKeyDestination,
    ) -> bool {
        self.same_asset(original)
            && self
                .destination
                .get()
                .and_then(Weak::upgrade)
                .is_some_and(|same| std::ptr::eq(same.as_ref(), destination))
    }
    fn same_binding(&self, binding: &Arc<wire::RequestBinding>) -> bool {
        self.binding
            .get()
            .is_some_and(|same| Arc::ptr_eq(same, binding))
    }
    pub(crate) fn clock(&self) -> &Arc<super::apple_signing::AppleProvisioningClock> {
        &self.clock
    }

    pub(crate) fn decline_before_asset(
        &self,
        reason: AssetReason,
        at: Instant,
    ) -> Result<(), BridgeError> {
        if self.original.get().is_some()
            || self.destination.get().is_some()
            || !self.dispatch.try_lock().is_ok_and(|slot| slot.is_none())
        {
            return Err(BridgeError::cleanup_unknown());
        }
        self.transition(SavePhase::Unattached, SavePhase::NotCreated)?;
        self.clock.observe_failure_at(reason, at);
        self.owner()?.apple.changed.notify_waiters();
        Ok(())
    }
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
        if self.phase() == Some(SavePhase::Unattached) && self.original.get().is_none() {
            let _ = self.decline_before_asset(reason, at);
        } else {
            self.clock.observe_failure_at(reason, at);
        }
    }

    /// Same Asset original and one predeclared save slot, before either GO.
    pub(crate) fn attach(
        &self,
        original: &Arc<OriginalWork>,
        dispatch: oneshot::Sender<Option<AppleKeySaveCommand>>,
    ) -> Result<(), BridgeError> {
        let owner = self.owner()?;
        let mut slot = self
            .dispatch
            .try_lock()
            .map_err(|_| BridgeError::cleanup_unknown())?;
        if self.phase() != Some(SavePhase::Unattached)
            || slot.is_some()
            || self.original.get().is_some()
        {
            return Err(invalid());
        }
        self.clock.bind_original(&owner, original)?;
        self.original
            .set(Arc::downgrade(original))
            .map_err(|_| invalid())?;
        *slot = Some(dispatch);
        self.transition(SavePhase::Unattached, SavePhase::Waiting)
    }
    pub(crate) fn attach_destination(
        &self,
        original: &Arc<OriginalWork>,
        destination: &Arc<AppleDistributionKeyDestination>,
    ) -> Result<(), BridgeError> {
        if self.mode != wire::Mode::KeyPrepare
            || !self.same_asset(original)
            || self.phase() != Some(SavePhase::Waiting)
            || self.clock.interrupted()
        {
            return Err(invalid());
        }
        self.destination
            .set(Arc::downgrade(destination))
            .map_err(|_| invalid())
    }
    pub(crate) fn attach_loan(
        &self,
        original: &Arc<OriginalWork>,
        loan: &Arc<AppleDistributionKeyLoan>,
    ) -> Result<(), BridgeError> {
        if matches!(self.mode, wire::Mode::KeyReview | wire::Mode::KeyPrepare)
            || !self.same_asset(original)
            || self.phase() != Some(SavePhase::Waiting)
            || self.clock.interrupted()
        {
            return Err(invalid());
        }
        self.loan.set(Arc::downgrade(loan)).map_err(|_| invalid())
    }
    pub(crate) fn destination_data(&self) -> Result<Option<KeyReference>, BridgeError> {
        if self.phase() != Some(SavePhase::Waiting) {
            return Err(invalid());
        }
        if self.mode != wire::Mode::KeyPrepare {
            return Ok(None);
        }
        self.destination
            .get()
            .and_then(Weak::upgrade)
            .map(|d| Some(d.descriptor()))
            .ok_or_else(invalid)
    }
    pub(crate) fn source_check_returned(
        &self,
        original: &Arc<OriginalWork>,
    ) -> Result<(), BridgeError> {
        // Fixed actual Asset source/inventory Child+Returned proof. The
        // method below is supplied by the same native parent, not a DTO.
        if !self.same_asset(original)
            || self.clock.interrupted()
            || !original.apple_key_source_checked(self)
            || self.source_returned.swap(true, Ordering::SeqCst)
        {
            return Err(invalid());
        }
        self.owner()?.apple.changed.notify_waiters();
        Ok(())
    }
    pub(crate) fn before_pending_check_returned(
        &self,
        original: &Arc<OriginalWork>,
    ) -> Result<(), BridgeError> {
        if self.mode != wire::Mode::KeyPrepare
            || !self.same_asset(original)
            || !self.source_returned.load(Ordering::SeqCst)
            || self.clock.interrupted()
            || !original.apple_key_before_pending_checked(self)
            || self.before_pending_returned.swap(true, Ordering::SeqCst)
        {
            return Err(invalid());
        }
        Ok(())
    }

    /// Automatic STOP-release deferral ONLY, before the vault is marked
    /// revoked. Called under the vault/Document books: no callback, IO, Doc,
    /// Work, Store, destination-progress or source reborrow is made here.
    /// Explicit lock/revoke/context/source loss is never bypassed by this.
    pub(crate) fn preservation_pending(&self, original: &Arc<OriginalWork>) -> bool {
        self.mode == wire::Mode::KeyPrepare
            && self.same_asset(original)
            && self.destination.get().is_some()
            && !self.all_jobs_joined.load(Ordering::SeqCst)
            && !self.private_drained.load(Ordering::SeqCst)
            && self.clock.key_preservation_end().is_some()
            && matches!(
                self.phase(),
                Some(
                    SavePhase::Waiting
                        | SavePhase::Claimed
                        | SavePhase::ReturnedSaved
                        | SavePhase::ClosedNotRun
                        | SavePhase::ReturnedRefused
                )
            )
            && self
                .owner()
                .is_ok_and(|owner| !owner.resource_unknown.load(Ordering::SeqCst))
    }
    fn save_end(&self, original: &Arc<OriginalWork>) -> Option<Instant> {
        if self.mode != wire::Mode::KeyPrepare
            || !self.same_asset(original)
            || !self.source_returned.load(Ordering::SeqCst)
            || !self.before_pending_returned.load(Ordering::SeqCst)
            || !self.worker_joined.load(Ordering::SeqCst)
            || self.all_jobs_joined.load(Ordering::SeqCst)
            || self.private_drained.load(Ordering::SeqCst)
            || self.generator_never_entered.load(Ordering::SeqCst)
            || !matches!(
                self.phase(),
                Some(SavePhase::Claimed | SavePhase::ReturnedSaved)
            )
            || !self
                .owner()
                .is_ok_and(|owner| !owner.resource_unknown.load(Ordering::SeqCst))
        {
            return None;
        }
        self.clock.key_preservation_end()
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
    pub(in crate::saved_command_owner) fn has_returned_output(&self) -> bool {
        self.output.get().is_some()
    }
    pub(crate) fn own_retained_bytes(&self) -> Option<usize> {
        backing_bytes(self.mode)
    }
}

pub(crate) struct AppleKeyPendingAck {
    parent: Arc<AppleKeySession>,
    binding: Arc<wire::RequestBinding>,
    reservation: Arc<KeyOriginalReservation>,
}
impl AppleKeyPendingAck {
    pub(crate) fn matches(
        &self,
        destination: &AppleDistributionKeyDestination,
        original: &Arc<OriginalWork>,
    ) -> bool {
        self.parent.destination_matches(original, destination)
            && self.parent.before_pending_returned.load(Ordering::SeqCst)
            && self.parent.same_binding(&self.binding)
            && self.reservation.intent().destination == destination.descriptor()
            && self.binding.scope.key.as_ref().is_some_and(|scope| {
                scope.destination.as_ref() == Some(&destination.descriptor())
                    && scope.source_p8 == self.reservation.intent().source_p8
            })
            && self.reservation.intent().context == self.binding.scope.provisioning
    }
    pub(crate) fn own_retained_bytes(&self) -> Option<usize> {
        Some(std::mem::size_of::<Self>())
    }
}

/// Issued only after original producer/IO/runtime joins, with the exact output
/// retained and durably save-armed. A late permitted stop changes disposition,
/// not these joins or the one-use private preservation slot.
pub(crate) struct AppleKeySavePermit {
    parent: Arc<AppleKeySession>,
    binding: Arc<wire::RequestBinding>,
    reservation: Arc<KeyOriginalReservation>,
    output: KeyOutputMetadata,
    seal_entered: bool,
    readback: bool,
    disposed: bool,
}
impl AppleKeySavePermit {
    fn binding(&self, original: &Arc<OriginalWork>) -> bool {
        self.parent.same_asset(original)
            && self.parent.same_binding(&self.binding)
            && self.parent.worker_joined.load(Ordering::SeqCst)
            && self.parent.output.get() == Some(&self.output)
            && self
                .parent
                .owner()
                .is_ok_and(|owner| !owner.resource_unknown.load(Ordering::SeqCst))
    }
    pub(crate) fn save_deadline(&self, original: &Arc<OriginalWork>) -> Option<Instant> {
        if self.disposed || !self.binding(original) {
            return None;
        }
        self.parent.save_end(original)
    }
    pub(crate) fn save_current(&self, original: &Arc<OriginalWork>) -> bool {
        self.save_deadline(original).is_some()
    }
    pub(crate) fn matches(
        &self,
        destination: &AppleDistributionKeyDestination,
        original: &Arc<OriginalWork>,
    ) -> bool {
        self.save_current(original)
            && self.parent.destination_matches(original, destination)
            && self.reservation.intent().destination == destination.descriptor()
    }
    pub(crate) fn seal_key(
        &mut self,
        reserved: &mut crate::vault_crypto::ReservedAppleDistributionKey,
        key: &crate::vault_crypto::VaultKey,
        allowance: usize,
        original: &Arc<OriginalWork>,
    ) -> Result<crate::vault_crypto::SealedRecord, crate::vault_crypto::Error> {
        use crate::vault_crypto::Error;
        if self.seal_entered || self.disposed {
            return Err(Error::Authentication);
        }
        self.seal_entered = true; // even a refused claim cannot repeat.
        if !self.save_current(original) {
            return Err(Error::Authentication);
        }
        let (identity, record, revision) = reserved.descriptor();
        if KeyReference::native(identity, record, revision) != self.reservation.intent().destination
        {
            return Err(Error::Authentication);
        }
        self.parent
            .receive
            .as_ref()
            .ok_or(Error::Authentication)?
            .seal_key(reserved, key, allowance, &self.output)
    }
    pub(crate) fn matches_authenticated_readback(
        &mut self,
        record: &crate::vault_crypto::AuthenticatedRecord,
        original: &Arc<OriginalWork>,
    ) -> bool {
        if !self.seal_entered
            || self.readback
            || !self.save_current(original)
            || !self.reservation.intent().destination.parts().is_ok_and(
                |(_, selected, revision)| selected == record.record && revision == record.revision,
            )
            || !self
                .parent
                .receive
                .as_ref()
                .is_some_and(|receive| receive.matches_readback(record, &self.output))
        {
            return false;
        }
        self.readback = true;
        true
    }
    pub(crate) fn retirement_ready(
        &self,
        destination: &AppleDistributionKeyDestination,
        original: &Arc<OriginalWork>,
    ) -> bool {
        // Cleanup only. A known late STOP does not undo a Published NEW or
        // clear failure. Actual Store Release must independently return.
        !self.disposed
            && self.seal_entered
            && self.readback
            && self.binding(original)
            && self.parent.cleanup_ready(original)
            && self.parent.destination_matches(original, destination)
            && destination.retirement_binding(original, &self.reservation.intent().destination)
    }
    pub(crate) fn try_retire_saved(
        &mut self,
        destination: &AppleDistributionKeyDestination,
        original: &Arc<OriginalWork>,
    ) -> bool {
        if !self.retirement_ready(destination, original)
            || !self
                .parent
                .receive
                .as_ref()
                .is_some_and(|receive| receive.drain_saved(&self.output))
        {
            return false;
        }
        self.disposed = true;
        self.parent.private_drained.store(true, Ordering::SeqCst);
        true
    }
    pub(crate) fn own_retained_bytes(&self) -> Option<usize> {
        std::mem::size_of::<Self>()
            .checked_add(self.output.frame_sha256.capacity())?
            .checked_add(self.output.csr_sha256.capacity())?
            .checked_add(self.output.public_key_sha256.capacity())
    }
}

/// Local keySaved DATA can be exposed only after full original settlement.
/// It is deliberately not a fresh key loan or a public CSR/POST capability.
pub(crate) struct AppleKeySavedAck {
    parent: Weak<AppleKeySession>,
    reservation: Arc<KeyOriginalReservation>,
    output: KeyOutputMetadata,
}
impl AppleKeySavedAck {
    pub(crate) fn matches(&self, reference: &KeyReference) -> bool {
        self.parent.upgrade().is_some_and(|parent| {
            parent.all_jobs_joined.load(Ordering::SeqCst)
                && parent.private_drained.load(Ordering::SeqCst)
                && parent.clock.completed()
                && parent.saved_reference.get() == Some(reference)
                && parent.output.get() == Some(&self.output)
                && *reference == self.reservation.intent().destination
        })
    }
}

/// Stronger than ProfileNoSave: generated/partial/missing-after-GO key output
/// can NEVER use this token. Only original positively never-entered generation
/// plus every later journal/native-use join may close the empty destination.
pub(crate) struct AppleKeyNeverGeneratedJoined {
    parent: Arc<AppleKeySession>,
    destination: KeyReference,
    disposed: bool,
}
impl AppleKeyNeverGeneratedJoined {
    fn binding(&self, original: &Arc<OriginalWork>) -> bool {
        !self.disposed
            && self.parent.cleanup_ready(original)
            && self.parent.generator_never_entered.load(Ordering::SeqCst)
            && self.parent.phase() == Some(SavePhase::ReturnedRefused)
            && self.parent.output.get().is_none()
            && self
                .parent
                .receive
                .as_ref()
                .is_some_and(|receive| receive.no_body_returned())
    }
    pub(crate) fn matches(
        &self,
        destination: &AppleDistributionKeyDestination,
        original: &Arc<OriginalWork>,
    ) -> bool {
        self.binding(original)
            && self.parent.destination_matches(original, destination)
            && destination.never_generated_candidate_binding(original, &self.destination)
    }
    pub(crate) fn retirement_ready(
        &self,
        destination: &AppleDistributionKeyDestination,
        original: &Arc<OriginalWork>,
    ) -> bool {
        self.binding(original)
            && self.parent.destination_matches(original, destination)
            && destination.never_generated_binding(original, &self.destination)
    }
    pub(crate) fn try_retire_never_generated(
        &mut self,
        destination: &AppleDistributionKeyDestination,
        original: &Arc<OriginalWork>,
    ) -> bool {
        if !self.retirement_ready(destination, original)
            || !self
                .parent
                .receive
                .as_ref()
                .is_some_and(|receive| receive.drain_never_generated())
        {
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

/// Retires only a freshly loaded stored-key loan. This cannot close generated
/// output or stand in for a generator/save/pending-key result.
pub(crate) struct AppleKeyUseJoined {
    parent: Arc<AppleKeySession>,
    reference: KeyReference,
    disposed: bool,
}
impl AppleKeyUseJoined {
    pub(crate) fn matches(
        &self,
        loan: &AppleDistributionKeyLoan,
        original: &Arc<OriginalWork>,
    ) -> bool {
        !self.disposed
            && !matches!(
                self.parent.mode,
                wire::Mode::KeyReview | wire::Mode::KeyPrepare
            )
            && self.parent.cleanup_ready(original)
            && self
                .parent
                .loan
                .get()
                .and_then(Weak::upgrade)
                .is_some_and(|same| std::ptr::eq(same.as_ref(), loan))
            && loan.original_binding(original, &self.reference)
    }
    pub(crate) fn retirement_ready(
        &self,
        loan: &AppleDistributionKeyLoan,
        original: &Arc<OriginalWork>,
    ) -> bool {
        self.matches(loan, original)
    }
    pub(crate) fn try_retire_used(
        &mut self,
        loan: &AppleDistributionKeyLoan,
        original: &Arc<OriginalWork>,
    ) -> bool {
        if !self.retirement_ready(loan, original) {
            return false;
        }
        self.disposed = true;
        self.parent.private_drained.store(true, Ordering::SeqCst);
        true
    }
    pub(crate) fn own_retained_bytes(&self) -> Option<usize> {
        std::mem::size_of::<Self>()
            .checked_add(self.reference.vault_id.capacity())?
            .checked_add(self.reference.generation_id.capacity())?
            .checked_add(self.reference.record_id.capacity())?
            .checked_add(self.reference.revision_id.capacity())
    }
}

pub(super) fn bind_request(
    owner: &Session,
    binding: &Arc<wire::RequestBinding>,
    bytes: &[u8],
) -> Result<(), BridgeError> {
    let Some(key) = owner.apple_key.get() else {
        return Ok(());
    };
    if key.mode != binding.context.mode || key.binding.get().is_some() {
        return Err(invalid());
    }
    if let Some(receive) = &key.receive {
        receive.bind_request(bytes)?;
    }
    if key.mode.p12() { p12::bind_request(owner,binding,bytes)?; }
    key.binding.set(binding.clone()).map_err(|_| invalid())
}

pub(super) async fn read_output<T: AsyncRead + Unpin + OriginalClose>(
    inner: Arc<Inner>,
    owner: Arc<Session>,
    slot: Arc<AsyncMutex<Pipe<T>>>,
    guard: Guard,
) -> ReadEnd {
    let receive = owner.apple_key.get().and_then(|key| key.receive.clone());
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

pub(super) async fn wait_source(owner: &Arc<Session>) -> Result<(), BridgeError> {
    let Some(key) = owner.apple_key.get() else {
        return Ok(());
    };
    loop {
        let changed = owner.apple.changed.notified();
        if key.source_returned.load(Ordering::SeqCst) {
            return Ok(());
        }
        if key.clock.interrupted() || *owner.stop.borrow() {
            return Err(asset_error());
        }
        let mut stop = owner.stop.subscribe();
        tokio::select! { biased;
            _ = stop.changed() => return Err(asset_error()),
            _ = tokio::time::sleep_until(owner.clocks.work.into()) => return Err(asset_error()),
            _ = changed => {},
        }
    }
}

pub(super) fn current_pending(
    owner: &Session,
    intent: &crate::apple_provisioning_journal::KeyPrepareIntent,
) -> Result<(), BridgeError> {
    let key = original(owner)?;
    if key.mode != wire::Mode::KeyPrepare
        || !key.source_returned.load(Ordering::SeqCst)
        || !key.before_pending_returned.load(Ordering::SeqCst)
        || key.clock.interrupted()
        || key.phase() != Some(SavePhase::Waiting)
    {
        return Err(invalid());
    }
    let binding = key.binding.get().ok_or_else(invalid)?;
    if intent.context != binding.scope.provisioning
        || !binding.scope.key.as_ref().is_some_and(|scope| {
            scope.source_p8 == intent.source_p8
                && scope.destination.as_ref() == Some(&intent.destination)
        })
    {
        return Err(invalid());
    }
    // This call is made outside Doc/Work/Store. It is never used by a permit
    // predicate under the native sink's locks.
    owner.apple.input()?.current()
}

pub(super) fn pending_ack(owner: &Arc<Session>, ack: &KeyJournalAck) -> Result<(), BridgeError> {
    current_pending(owner, ack.original.intent())?;
    if ack.row.update.sequence != 1
        || ack.row.update.generation != KeyGeneration::Armed
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
    let destination = parent
        .destination
        .get()
        .and_then(Weak::upgrade)
        .ok_or_else(invalid)?;
    let proof = AppleKeyPendingAck {
        binding: parent.binding.get().ok_or_else(invalid)?.clone(),
        parent,
        reservation: ack.original.clone(),
    };
    destination
        .record_pending(&asset, proof)
        .map_err(|_| asset_error())
}

/// Called by the sole original writer immediately before its first pending
/// ACK write. A partial/lost write cannot be reinterpreted as never entered.
pub(super) fn begin_pending_write(owner: &Session) -> Result<(), BridgeError> {
    let key = original(owner)?;
    if key.clock.interrupted() || key.pending_ack_entered.swap(true, Ordering::SeqCst) {
        return Err(invalid());
    }
    Ok(())
}
pub(super) fn end_pending_write(owner: &Session, written: bool) -> Result<(), BridgeError> {
    let key = original(owner)?;
    if !written
        || !key.pending_ack_entered.load(Ordering::SeqCst)
        || key.pending_ack_returned.swap(true, Ordering::SeqCst)
    {
        return Err(BridgeError::cleanup_unknown());
    }
    Ok(())
}
pub(super) fn output_custody(
    owner: &Session,
    output: &KeyOutputMetadata,
) -> Result<(), BridgeError> {
    let key = original(owner)?;
    if !key.pending_ack_returned.load(Ordering::SeqCst)
        || !key
            .receive
            .as_ref()
            .is_some_and(|receive| receive.custody_matches(output))
    {
        return Err(invalid());
    }
    key.output.set(output.clone()).map_err(|_| invalid())
}
pub(super) fn begin_custody_write(
    owner: &Session,
    output: &KeyOutputMetadata,
) -> Result<(), BridgeError> {
    let key = original(owner)?;
    if key.output.get() != Some(output) || key.clock.key_preservation_end().is_none() {
        return Err(invalid());
    }
    key.receive.as_ref().ok_or_else(invalid)?.begin_ack(output)
}
pub(super) fn end_custody_write(
    owner: &Session,
    output: &KeyOutputMetadata,
    written: bool,
) -> Result<(), BridgeError> {
    if !original(owner)?
        .receive
        .as_ref()
        .is_some_and(|receive| receive.end_ack(output, written))
    {
        return Err(BridgeError::cleanup_unknown());
    }
    Ok(())
}

/// Private caller is native::finish AFTER re-reading actual worker, runtime,
/// writer/readers, driver/manager and startup joins. Receipt DATA alone cannot
/// invoke this method or set the native generator cut.
#[cfg(all(
    target_os = "macos",
    target_pointer_width = "64",
    any(target_arch = "aarch64", target_arch = "x86_64")
))]
pub(super) fn producer_joined(
    owner: &Arc<Session>,
    no_generation: Option<&wire::KeyNotGenerated>,
) -> Result<(), BridgeError> {
    let key = original(owner)?;
    if key.worker_joined.swap(true, Ordering::SeqCst) {
        return Err(invalid());
    }
    if key.mode != wire::Mode::KeyPrepare {
        return Ok(());
    }
    let no_ack_entered = !key.pending_ack_entered.load(Ordering::SeqCst)
        && !key.pending_ack_returned.load(Ordering::SeqCst);
    let receipt = no_generation.is_some_and(|receipt| {
        (6..=7).contains(&receipt.commands) && (!receipt.before_command || receipt.commands == 6)
    });
    if (no_ack_entered || receipt)
        && key.output.get().is_none()
        && key
            .receive
            .as_ref()
            .is_some_and(|receive| receive.no_body_returned())
    {
        key.generator_never_entered.store(true, Ordering::SeqCst);
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
    ack: Option<&KeyJournalAck>,
) -> Result<(), BridgeError> {
    let key = original(owner)?.clone();
    if !key.worker_joined.load(Ordering::SeqCst) {
        return Err(invalid());
    }
    let permit = if let Some(ack) = ack {
        let output = ack.row.update.output.as_ref().ok_or_else(invalid)?;
        if key.mode != wire::Mode::KeyPrepare
            || ack.row.update.generation != KeyGeneration::Returned
            || ack.row.update.save != ProfileSaveState::Armed
            || ack.row.native_settlement != NativeSettlement::Pending
            || key.clock.key_preservation_end().is_none()
            || key.generator_never_entered.load(Ordering::SeqCst)
            || key.output.get() != Some(output)
            || !key
                .receive
                .as_ref()
                .is_some_and(|receive| receive.returned_matches(output))
        {
            return Err(invalid());
        }
        Some(AppleKeySavePermit {
            parent: key.clone(),
            binding: key.binding.get().ok_or_else(invalid)?.clone(),
            reservation: ack.original.clone(),
            output: output.clone(),
            seal_entered: false,
            readback: false,
            disposed: false,
        })
    } else {
        if key.mode == wire::Mode::KeyPrepare && !key.generator_never_entered.load(Ordering::SeqCst)
        {
            return Err(BridgeError::cleanup_unknown());
        }
        None
    };
    if key.phase() == Some(SavePhase::NotCreated) {
        return if permit.is_none() {
            Ok(())
        } else {
            Err(invalid())
        };
    }
    let mut slot = key
        .dispatch
        .try_lock()
        .map_err(|_| BridgeError::cleanup_unknown())?;
    let saving = permit.is_some();
    key.transition(
        SavePhase::Waiting,
        if saving {
            SavePhase::Claimed
        } else {
            SavePhase::ClosedNotRun
        },
    )?;
    let send = slot.take().ok_or_else(BridgeError::cleanup_unknown)?;
    if send.send(permit.map(AppleKeySaveCommand::Key)).is_err() && saving {
        return Err(BridgeError::cleanup_unknown());
    }
    // A refused Initial/BeforePending child may already have returned before
    // a never-generated close is sent. A closed channel is NOT a join: the
    // next join_asset still checks the SAME child/coordinator/source books.
    // Any attempted permit delivery stays unknown instead.
    Ok(())
}

#[cfg(all(
    target_os = "macos",
    target_pointer_width = "64",
    any(target_arch = "aarch64", target_arch = "x86_64")
))]
pub(super) async fn join_asset(owner: &Arc<Session>) -> Result<Option<KeyReference>, BridgeError> {
    let key = original(owner)?;
    if key.phase() == Some(SavePhase::NotCreated) {
        return Ok(None);
    }
    let asset = key
        .original
        .get()
        .and_then(Weak::upgrade)
        .ok_or_else(invalid)?;
    let saved = owner.apple.input()?.join_key_asset(&asset).await?;
    match (key.phase(), saved.as_ref()) {
        (Some(SavePhase::Claimed), Some(reference)) => {
            key.transition(SavePhase::Claimed, SavePhase::ReturnedSaved)?;
            key.saved_reference
                .set(reference.clone())
                .map_err(|_| BridgeError::cleanup_unknown())?;
        }
        (Some(SavePhase::ClosedNotRun), None) => {
            key.transition(SavePhase::ClosedNotRun, SavePhase::ReturnedRefused)?
        }
        _ => return Err(BridgeError::cleanup_unknown()),
    }
    Ok(saved)
}

#[cfg(all(
    target_os = "macos",
    target_pointer_width = "64",
    any(target_arch = "aarch64", target_arch = "x86_64")
))]
pub(super) fn native_joined(
    owner: &Arc<Session>,
    native_use: Arc<NativeUse>,
    reservation: Arc<KeyOriginalReservation>,
) -> Result<AppleKeyNativeJoined, BridgeError> {
    let key = original(owner)?;
    if !key.worker_joined.load(Ordering::SeqCst)
        || owner.resource_unknown.load(Ordering::SeqCst)
        || !matches!(
            key.phase(),
            Some(SavePhase::NotCreated | SavePhase::ReturnedSaved | SavePhase::ReturnedRefused)
        )
        || reservation.intent().context != owner.apple.request_binding()?.scope.provisioning
        || key.phase() != Some(SavePhase::ReturnedSaved)
            && !key.generator_never_entered.load(Ordering::SeqCst)
    {
        return Err(BridgeError::cleanup_unknown());
    }
    Ok(AppleKeyNativeJoined {
        native_use,
        reservation,
    })
}

pub(super) fn saved_reference(owner: &Session) -> Option<KeyReference> {
    let key = owner.apple_key.get()?;
    (key.all_jobs_joined.load(Ordering::SeqCst)
        && key.private_drained.load(Ordering::SeqCst)
        && key.clock.completed()
        && !owner.resource_unknown.load(Ordering::SeqCst))
    .then(|| key.saved_reference.get().cloned())
    .flatten()
}

#[cfg(all(
    target_os = "macos",
    target_pointer_width = "64",
    any(target_arch = "aarch64", target_arch = "x86_64")
))]
pub(super) async fn finish_private(owner: &Arc<Session>) -> bool {
    let Ok(key) = original(owner) else {
        return false;
    };
    if !super::apple_provisioning::native_complete(owner)
        || !key.worker_joined.load(Ordering::SeqCst)
        || owner.resource_unknown.load(Ordering::SeqCst)
    {
        return false;
    }
    // Does not await future Asset private-empty/Release. The same Asset uses
    // this cut to enter its original cleanup continuation; its actual return
    // is still required before the receiver/loan can be drained below.
    key.all_jobs_joined.store(true, Ordering::SeqCst);
    let Some(asset) = key.original.get().and_then(Weak::upgrade) else {
        if key.phase() != Some(SavePhase::NotCreated) {
            return false;
        }
        if key.mode.p12() && !p12::finish_without_asset(key) { return false; }
        if key.receive.as_ref().is_some_and(|receive| {
            !key.generator_never_entered.load(Ordering::SeqCst) || !receive.drain_never_generated()
        }) {
            return false;
        }
        key.private_drained.store(true, Ordering::SeqCst);
        return key.clock.mark_completed(owner);
    };
    if key.mode.p12() {
        if p12::prepare_private_finish(key,&asset).is_err() { return false; }
    } else if key.phase() == Some(SavePhase::ReturnedRefused) {
        if let Some(destination) = key.destination.get().and_then(Weak::upgrade) {
            if !key.generator_never_entered.load(Ordering::SeqCst) {
                return false;
            }
            let proof = AppleKeyNeverGeneratedJoined {
                parent: key.clone(),
                destination: destination.descriptor(),
                disposed: false,
            };
            if destination.accept_never_generated(&asset, proof).is_err() {
                return false;
            }
        } else if let Some(loan) = key.loan.get().and_then(Weak::upgrade) {
            let proof = AppleKeyUseJoined {
                parent: key.clone(),
                reference: loan.reference(),
                disposed: false,
            };
            if loan.accept_joined(&asset, proof).is_err() {
                return false;
            }
        } else if key.mode == wire::Mode::KeyReview || key.mode.certificate() {
            // Inventory-only operation has no generated/loaded private body.
            // Its original source/store still closes in retire_key_asset.
            key.private_drained.store(true, Ordering::SeqCst);
        } else if key.mode == wire::Mode::KeyPrepare
            && key.generator_never_entered.load(Ordering::SeqCst)
            && key
                .receive
                .as_ref()
                .is_some_and(|receive| receive.drain_never_generated())
        {
            // An actual Initial/source refusal can precede destination
            // reservation. The ACK-never-entered/producer/EOF cut above is
            // still required; absent destination alone grants no disposal.
            key.private_drained.store(true, Ordering::SeqCst);
        } else {
            return false;
        }
    } else if key.phase() != Some(SavePhase::ReturnedSaved) {
        return false;
    }
    let Ok(input) = owner.apple.input() else {
        return false;
    };
    if input.retire_key_asset(&asset).await.is_err() {
        return false;
    }
    if key.mode.p12() && !key.private_drained.load(Ordering::SeqCst)
        && p12::finish_unloaded_after_asset(key) {
        key.private_drained.store(true, Ordering::SeqCst);
    }
    key.private_drained.load(Ordering::SeqCst) && key.clock.mark_completed(owner)
}

#[cfg(test)]
#[path = "saved_command_apple_key_tests.rs"]
mod tests;
