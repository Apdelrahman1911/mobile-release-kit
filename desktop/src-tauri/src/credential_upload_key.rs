//! One explicit Android upload-key operation in the EXISTING vault owner.
//!
//! The saved-command child owns keytool and its original leased toolchain.
//! This child owns the durable pre-GO reservation, the fixed New/None vault
//! mutation and FULL authenticated readback. Neither a preference, a returned
//! process nor a public fingerprint supplies assignment or generation rights.
use super::*;
use crate::{
    android_upload_key_protocol as wire,
    application_state_store::PrivateStateDirectory,
    saved_command_owner::{SavedCommandOwner, UploadKeyPreparation, UploadKeyRun},
};
use std::sync::atomic::AtomicU8;
use std::sync::{OnceLock, Weak};

// Source/portable checks do not qualify private native generation. Entry and
// status must use this SAME fixed predicate, never installed-vault alone.
const NATIVE_UPLOAD_KEY_QUALIFIED: bool = false;
#[path = "credential_upload_key_controls.rs"]
pub(crate) mod controls;
#[path = "credential_upload_key_cancellation.rs"]
pub(in crate::asset_session) mod cancellation;
pub(crate) use cancellation::UploadKeyCancellationDisposal;
#[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "macos-installed-observation", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer"), target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
#[path = "credential_upload_key_observation.rs"]
pub(crate) mod observation;
// The generated container is fixed and small. Reserving the entire remaining
// vault allowance before the real inspector returns would spuriously deny a
// normal measured native graph. This smaller, source-derived workspace grants
// no native/record authority and never enlarges the ordinary vault limits.
const CRYPTO_WORK_BYTES: usize = 1024 * 1024;
const _: () = assert!(
    crypto::CONTROL_BYTES
        + format::RECORD_OVERHEAD
        + format::DESCRIPTOR_LIMIT
        + 8
        + format::SCALAR_LIMIT
        + wire::JKS_LIMIT
        <= CRYPTO_WORK_BYTES
);
pub(crate) fn available(document: &DocumentBinding) -> bool {
    cfg!(all(
        feature = "desktop-shell",
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64")
    )) && NATIVE_UPLOAD_KEY_QUALIFIED
        && document.native_qualified()
        && document.persistence_qualified()
}

// Reuse the EXISTING installed-inspector partition. This full native code
// reservation is distinct from vault/private storage credit; it never enlarges
// the 64/96MiB vault caps or replaces the measured census required before GO.
fn inspection_fits(retained: usize, reservation: usize) -> bool {
    reservation == crate::macos_install_record::CONTROL_LIMIT
        && retained <= store::RESIDENT_BYTES
        && retained
            .checked_add(reservation)
            .is_some_and(|total| crate::macos_install_record::installed_control_fits(total, 1))
}

/// The one tuple minted at outer admission. OriginalWork retains this exact
/// Arc before GO. Generic status/GUI/cleanup must never create another clock.
struct FailureClock {
    first: Option<Instant>,
    cleanup: Option<Instant>,
    // A native-projected failure/cutoff already belongs to the native
    // original. Do not echo its inverse-mapped Instant as a new local STOP.
    native_first: Option<Instant>,
    native_cleanup: Option<Instant>,
}
pub(crate) struct UploadKeyClock {
    admitted: Instant,
    work: Instant,
    hard: Instant,
    failed: AtomicBool,
    failure: Mutex<FailureClock>,
    completed: AtomicBool,
}
impl UploadKeyClock {
    fn new(admitted: Instant) -> Self {
        Self {
            admitted,
            work: admitted + Duration::from_secs(wire::WORK_SECONDS),
            hard: admitted + Duration::from_secs(wire::FINALITY_SECONDS),
            failed: AtomicBool::new(false),
            failure: Mutex::new(FailureClock {
                first: None,
                cleanup: None,
                native_first: None,
                native_cleanup: None,
            }),
            completed: AtomicBool::new(false),
        }
    }
    pub(crate) fn bounds(&self) -> (Instant, Instant, Instant) {
        (self.admitted, self.work, self.hard)
    }
    pub(crate) fn work_end(&self) -> Instant {
        self.work
    }
    pub(crate) fn endpoint(&self) -> Option<Instant> {
        (!self.completed.load(Ordering::SeqCst)).then_some(self.work)
    }
    pub(crate) fn cleanup_end(&self, first: Instant) -> Instant {
        let proposed = (first + Duration::from_secs(wire::FINALITY_SECONDS - wire::WORK_SECONDS))
            .min(self.hard);
        self.cleanup_cutoff()
            .map_or(proposed, |original| original.min(proposed))
    }
    pub(crate) fn cleanup_cutoff(&self) -> Option<Instant> {
        // Poison cannot manufacture either a fresh interval or a missing
        // native first-F. The original admission is an already-expired cap.
        self.failure
            .lock()
            .map_or(Some(self.admitted), |failure| failure.cleanup)
    }
    pub(crate) fn observe_failure(&self, at: Instant) -> Instant {
        self.failed.store(true, Ordering::SeqCst);
        // Only this generation clock contracts for a later-delivered earlier
        // original native Instant. Existing Work.fail reason/receipt semantics
        // and every other operation's clock remain unchanged.
        if let Ok(mut failure) = self.failure.lock() {
            failure.first = Some(failure.first.map_or(at, |old| old.min(at)));
            let end = (at + Duration::from_secs(wire::FINALITY_SECONDS - wire::WORK_SECONDS))
                .min(self.hard);
            failure.cleanup = Some(failure.cleanup.map_or(end, |old| old.min(end)));
        }
        self.cleanup_end(at)
    }
    fn observe_native_cleanup(&self, first: Option<Instant>, end: Instant) {
        self.failed.store(true, Ordering::SeqCst);
        if let Ok(mut failure) = self.failure.lock() {
            let mut end = end.min(self.hard);
            if let Some(first) = first {
                failure.first = Some(failure.first.map_or(first, |old| old.min(first)));
                failure.native_first =
                    Some(failure.native_first.map_or(first, |old| old.min(first)));
                end = end
                    .min(first + Duration::from_secs(wire::FINALITY_SECONDS - wire::WORK_SECONDS));
            }
            // A native Unknown may have an original expiry but no first-F.
            // Keep that absence, not end/now disguised as an observation.
            failure.native_cleanup = Some(failure.native_cleanup.map_or(end, |old| old.min(end)));
            failure.cleanup = Some(failure.cleanup.map_or(end, |old| old.min(end)));
        }
    }
    fn native_already_knows(&self, first: Instant) -> bool {
        self.failure.lock().is_ok_and(|failure| {
            failure.native_first.is_some_and(|native| native <= first)
                || failure.native_first.is_none() && failure.native_cleanup.is_some()
        })
    }
    pub(crate) fn failure_at(&self) -> Option<Instant> {
        self.failure.lock().ok().and_then(|failure| failure.first)
    }
}

/// Root calls only for an OriginalWork carrying this fixed generation clock.
/// Safe while the Doc is held: no SavedOwner lock, IO, callback or new worker.
pub(in crate::asset_session) fn parent_stop(
    owner: &OriginalWork,
    reason: Reason,
    at: Instant,
) -> Option<Instant> {
    let clock = owner.upload_key_clock.get()?;
    // Only actual off-lock disposal can complete this operation. Its original
    // tuple remains recorded, but a later independent vault-lease close does
    // not revive an expired generation budget or become a second generation.
    clock.endpoint()?;
    let mut end = clock.observe_failure(at);
    // A caller may already hold the ordinary Work lock. The shared clock and
    // Slot keep the original failure even then; never recursively lock Work.
    if let Ok(mut work) = owner.vault.try_lock() {
        work.fail(reason, at);
        if let Some((_, first)) = work.first {
            end = end.min(clock.observe_failure(first));
        }
    }
    owner.signal_stop();
    Some(end)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ProgressPhase {
    Admitted,
    Reserving,
    Reserved,
    Starting,
    Running,
    Candidate,
    Storing,
    Stored,
    Recording,
    Recorded,
    Published,
    Failed,
}
struct Progress {
    phase: ProgressPhase,
    first: Option<(Reason, Instant)>,
    outcome: Option<store::StorageOutcome>,
    saved: Option<StoredRef>,
    certificate: Option<[u8; 32]>,
    journal_revision: Option<u64>,
    authenticated_new: Option<cancellation::AuthenticatedNew>,
}
impl Progress {
    fn new() -> Self {
        Self {
            phase: ProgressPhase::Admitted,
            first: None,
            outcome: None,
            saved: None,
            certificate: None,
            journal_revision: None,
            authenticated_new: None,
        }
    }
    fn enter(&mut self, expected: ProgressPhase, next: ProgressPhase) -> Result<(), Reason> {
        if self.first.is_some() || self.phase != expected {
            return Err(Reason::VaultInterrupted);
        }
        self.phase = next;
        Ok(())
    }
    fn fail(&mut self, reason: Reason, at: Instant) {
        if self.first.is_none() {
            self.first = Some((reason, at));
        }
        self.phase = ProgressPhase::Failed;
    }
    fn saved_effect_known(&self) -> bool {
        self.first.is_none()
            && self.outcome
                == Some(store::StorageOutcome {
                    effect: store::Effect::KnownApplied,
                    durability: store::Durability::Confirmed,
                    cleanup: store::Cleanup::Known,
                })
            && self.saved.is_some()
            && self.certificate.is_some()
    }
    fn published(&self) -> bool {
        self.phase == ProgressPhase::Published
            && self.saved_effect_known()
            && self.journal_revision.is_some()
    }
}

// There is no strong OriginalWork/Session cycle. Every private holding is
// retained by the SAME Work before a producer is released. Native preparation
// itself holds only a Weak of its eventual saved-command Session.
struct Holding {
    owner: Weak<OriginalWork>,
    document: Weak<Inner>,
    context: Arc<NativeContext>,
    key: Weak<crypto::VaultKey>,
    store: Weak<Mutex<store::StoreBook>>,
    native: SavedCommandOwner,
    preparation: Arc<UploadKeyPreparation>,
    service: Arc<ApplicationService>,
    setup: Arc<controls::PreparedSetup>,
    native_use: OnceLock<crate::application_service_host::NativeStateLease>,
    native_use_retired: AtomicBool,
    observed: NativeObservation,
    preference_revision: u64,
    roster: ProjectRoster,
    allowance: usize,
    inspection_reservation: usize,
    clock: Arc<UploadKeyClock>,
    progress: Mutex<Progress>,
    reservation: OnceLock<Arc<persistence::DurableGenerationReservation>>,
    secrets: OnceLock<Arc<commands::UploadKeySecrets>>,
    gate: OnceLock<Arc<UploadKeyGoGate>>,
    run: OnceLock<Arc<UploadKeyRun>>,
    cancellation: cancellation::CancellationState,
}
impl Holding {
    fn progress(&self) -> Result<std::sync::MutexGuard<'_, Progress>, Reason> {
        self.progress.lock().map_err(|_| Reason::CleanupUnknown)
    }
    fn native_settled(&self) -> bool {
        self.run.get().is_none_or(|run| run.native_settled())
    }
    fn retained_bytes(&self) -> Option<usize> {
        const ARC_CELLS: usize = 2 * std::mem::size_of::<usize>();
        let mut bytes = std::mem::size_of::<Self>().checked_add(ARC_CELLS)?;
        bytes = bytes.checked_add(self.preparation.retained_bytes()?)?
            .checked_add(controls::retained_use_bytes(self)?)?;
        for text in [
            &self.observed.project.project_id,
            &self.observed.project.canonical_root,
            &self.observed.identity,
        ] {
            bytes = bytes.checked_add(text.capacity())?;
        }
        bytes = bytes
            .checked_add(self.observed.expected.as_ref().map_or(0, String::capacity))?
            .checked_add(
                self.observed
                    .records
                    .capacity()
                    .checked_mul(std::mem::size_of::<RecordFact>())?,
            )?
            .checked_add(
                self.roster
                    .roots
                    .capacity()
                    .checked_mul(std::mem::size_of::<asset_source::RegisteredRoot>())?,
            )?;
        for root in &self.roster.roots {
            bytes = bytes.checked_add(root.path.capacity())?;
        }
        // Generation admission refuses ALL existing Android rows. Do not
        // silently omit their dynamic reference backing from this census.
        if !self.observed.records.is_empty() {
            return None;
        }
        if let Some(reservation) = self.reservation.get() {
            bytes = bytes
                .checked_add(reservation.retained_bytes()?)?
                .checked_add(ARC_CELLS)?;
        }
        if let Some(secrets) = self.secrets.get() {
            bytes = bytes
                .checked_add(secrets.retained_bytes()?)?
                .checked_add(ARC_CELLS)?;
        }
        if let Some(gate) = self.gate.get() {
            bytes = bytes
                .checked_add(std::mem::size_of_val(&**gate))?
                .checked_add(ARC_CELLS)?;
        }
        // Only the not-yet-started producer uses its constructor quote. Once
        // the Run exists its SAME native inspector must publish the actual
        // quiescent charge before private GO; while inspection is live the
        // census is unavailable, not a guessed fixed/zero amount.
        let native = match self.run.get() {
            Some(run) => run
                .retained_bytes()?
                .checked_add(std::mem::size_of::<UploadKeyRun>())?
                .checked_add(ARC_CELLS)?,
            _ => crate::saved_command_owner::upload_key_document_backing_bytes()?,
        };
        bytes.checked_add(native)
    }
    fn fail(&self, reason: Reason, at: Instant) {
        self.clock.observe_failure(at);
        if let Ok(mut progress) = self.progress.lock() {
            progress.fail(reason, at);
        }
        let mut original = (reason, at);
        if let Some(owner) = self.owner.upgrade() {
            if let Ok(mut work) = owner.vault.lock() {
                work.fail(reason, at);
                // StoreBook can have observed the failure before this caller.
                // Preserve that original explanation, and contract ONLY the
                // generation clock rather than rewriting ordinary Work.fail.
                if let Some(first) = work.first {
                    original = first;
                }
            }
            self.clock.observe_failure(original.1);
            owner.signal_stop();
        }
        // Called only OFF Doc/Work/Progress/native-registry locks. The native
        // child may synchronously forward this same first failure to the gate.
        let first = self.clock.failure_at().unwrap_or(original.1);
        if !self.clock.native_already_knows(first) {
            if let Some(run) = self.run.get() {
                run.failed_at(original.0, first);
            }
        }
    }
}

/// Charged in actual vault Work AND its existing off-lock Retired holding.
/// Native quiescence is deliberately not private disposal/slot reuse.
#[derive(Default)]
pub(in crate::asset_session) struct Work {
    inner: Option<Arc<Holding>>,
    disposal: Option<UploadKeyDisposal>,
    cancelled: Option<cancellation::CancellationRetirement>,
}
impl Work {
    pub(in crate::asset_session) fn empty(&self) -> bool {
        self.inner.is_none()
    }
    pub(in crate::asset_session) fn blocks_reuse(&self) -> bool {
        !self.empty()
    }
    pub(in crate::asset_session) fn native_settled(&self) -> bool {
        self.inner.as_ref().is_none_or(|held| held.native_settled())
    }
    pub(in crate::asset_session) fn retained_bytes(&self) -> Option<usize> {
        self.inner
            .as_ref()
            .map_or(Some(0), |held| held.retained_bytes())
    }
    pub(in crate::asset_session) fn recovery_required(&self) -> bool {
        self.inner.as_ref().is_some_and(|held| {
            held.progress.try_lock().map_or(true, |p| {
                p.phase == ProgressPhase::Failed
                    || held.clock.failed.load(Ordering::SeqCst)
                    || held.run.get().is_some_and(|run| run.cleanup_unknown())
            })
        })
    }
}

fn same_reference(left: StoredRef, right: StoredRef) -> bool {
    left.identity == right.identity
        && left.record == right.record
        && left.revision == right.revision
        && left.original == right.original
}
fn original_joins(owner: &OriginalWork, work: &super::super::Work) -> bool {
    owner.control_resources_settled()
        && owner
            .coordinator
            .try_lock()
            .is_ok_and(|book| book.handle.is_none() && book.receipt == JoinReceipt::Returned)
        && owner
            .child
            .try_lock()
            .is_ok_and(|book| book.handle.is_none() && book.receipt == JoinReceipt::Returned)
        && work.original_join.is_none()
        && work.failed_child_join.is_none()
}
fn digest(text: &str) -> Option<[u8; 32]> {
    fn nibble(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            _ => None,
        }
    }
    if text.len() != 64 {
        return None;
    }
    let mut result = [0; 32];
    for (out, bytes) in result.iter_mut().zip(text.as_bytes().chunks_exact(2)) {
        *out = nibble(bytes[0])? * 16 + nibble(bytes[1])?;
    }
    Some(result)
}

/// Volatile native-only provenance, NOT a persisted expected fingerprint. This
/// survives ordinary working-ref retirement, but not replacing the original
/// unlocked VaultKey/session. It never supplies assessment or a BoundLoan.
pub(in crate::asset_session) struct UploadKeyObservation {
    reference: StoredRef,
    identity: [u8; 32],
    certificate: [u8; 32],
    key: Weak<crypto::VaultKey>,
    store: Weak<Mutex<store::StoreBook>>,
}
pub(in crate::asset_session) fn certificate_for(
    session: &Session,
    row: &Descriptor,
    identity: &str,
) -> Option<[u8; 32]> {
    let evidence = session.upload_key_observation.as_ref()?;
    let key = evidence.key.upgrade()?;
    let storage = evidence.store.upgrade()?;
    if !session.writable()
        || row.mutation_pending
        || row.authenticated.descriptor.kind != Kind::AndroidKeystore
        || session.identity != Some(evidence.reference.identity)
        || key.identity() != evidence.reference.identity
        || digest(identity) != Some(evidence.identity)
        || !Arc::ptr_eq(&session.store, &storage)
        || session
            .key
            .as_ref()
            .is_none_or(|current| !Arc::ptr_eq(current, &key))
        || !same_reference(
            evidence.reference,
            row.reference(evidence.reference.identity),
        )
    {
        return None;
    }
    Some(evidence.certificate)
}

/// Extra New-only predicate in the existing post-join vault publisher. The
/// ordinary replace/delete/Bind arms do not accept this generated result.
pub(in crate::asset_session) fn new_publication(
    work: &super::super::Work,
    session: &Session,
    slot: &Slot,
    record: format::Id,
    row: Option<&Descriptor>,
) -> bool {
    let Some(held) = &work.upload_key.inner else {
        return false;
    };
    let Some(row) = row else {
        return false;
    };
    let context = held.preparation.context();
    let Some(reservation) = held.reservation.get() else {
        return false;
    };
    original_joins(&slot.owner, work)
        && !slot.owner.stopped()
        && !held.clock.failed.load(Ordering::SeqCst)
        && slot.operation == Operation::GenerateUploadKey
        && slot.target.is_none()
        && slot
            .context
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, &held.context))
        && session.identity == Some(context.vault)
        && record == context.record
        && !session
            .rows
            .iter()
            .any(|previous| previous.authenticated.record == record)
        && !session.inventory.contains(&record)
        && session.rows.len() < store::DESCRIPTOR_COUNT
        && session.rows.len() < session.rows.capacity()
        && session.inventory.len() < session.inventory.capacity()
        && !row.mutation_pending
        && row.authenticated.descriptor.kind == Kind::AndroidKeystore
        && row.authenticated.record == record
        && row.authenticated.revision.counter == 1
        && work.key.as_ref().is_some_and(|key| {
            key.identity() == context.vault
                && session
                    .key
                    .as_ref()
                    .is_some_and(|current| Arc::ptr_eq(key, current))
        })
        && held
            .run
            .get()
            .is_some_and(|run| run.native_settled() && !run.cleanup_unknown())
        && held
            .gate
            .get()
            .is_some_and(|gate| gate.once.load(Ordering::SeqCst) == 2)
        && held.progress.try_lock().is_ok_and(|p| {
            p.phase == ProgressPhase::Recorded
                && p.saved_effect_known()
                && p.journal_revision == reservation.store_revision().checked_add(1)
                && p.saved
                    .is_some_and(|saved| same_reference(saved, row.reference(context.vault)))
        })
}

/// Called only after new_publication and the parent's native registry/context
/// rematch, BEFORE publishing the row. No fallible IO/assignment occurs here.
pub(in crate::asset_session) fn publish_observation(
    work: &super::super::Work,
    session: &Session,
    slot: &Slot,
    record: format::Id,
    row: &Descriptor,
) -> Result<UploadKeyObservation, Reason> {
    if !new_publication(work, session, slot, record, Some(row)) {
        return Err(Reason::SourceChanged);
    }
    let held = work
        .upload_key
        .inner
        .as_ref()
        .ok_or(Reason::VaultInterrupted)?;
    let mut progress = held.progress()?;
    let observation = UploadKeyObservation {
        reference: progress.saved.ok_or(Reason::VaultCorrupt)?,
        identity: digest(&held.observed.identity).ok_or(Reason::VaultCorrupt)?,
        certificate: progress.certificate.ok_or(Reason::VaultCorrupt)?,
        key: held.key.clone(),
        store: held.store.clone(),
    };
    progress.enter(ProgressPhase::Recorded, ProgressPhase::Published)?;
    Ok(observation)
}

/// Sole fixed permission to clear the native private result after actual
/// NEW/readback/journal/publication and original joins. No constructor, serde,
/// Clone or boolean/public result can create this permission.
pub(crate) struct UploadKeyDisposal {
    preparation: Arc<UploadKeyPreparation>,
    consumed: bool,
}
impl UploadKeyDisposal {
    pub(crate) fn matches(&self, preparation: &Arc<UploadKeyPreparation>) -> bool {
        !self.consumed
            && Arc::ptr_eq(&self.preparation, preparation)
            && self.preparation.same_original(preparation)
    }
    pub(crate) fn consume(
        &mut self,
        preparation: &Arc<UploadKeyPreparation>,
    ) -> Result<(), Reason> {
        let matches = self.matches(preparation);
        self.consumed = true;
        if matches {
            Ok(())
        } else {
            Err(Reason::CleanupUnknown)
        }
    }
}

/// Run BEFORE taking vault::Work. Failed prior originals cannot be repaired by
/// a later cleanup-only receipt; generic STOP/Idle does not grant disposal.
pub(in crate::asset_session) fn retirement_ready(owner: &Arc<OriginalWork>) -> bool {
    if !owner.retired.load(Ordering::SeqCst) {
        return false;
    }
    let Ok(work) = owner.vault.try_lock() else {
        return false;
    };
    let Some(held) = &work.upload_key.inner else {
        return true;
    };
    original_joins(owner, &work)
        && !owner.stopped()
        && !held.clock.failed.load(Ordering::SeqCst)
        && work.first.is_none()
        && !work.release
        && work.settled()
        && Arc::strong_count(held) == 1
        && held.native_settled()
        && held.run.get().is_some_and(|run| !run.cleanup_unknown())
        && held.progress.try_lock().is_ok_and(|p| p.published())
}
impl Work {
    /// Parent uses only after retirement_ready plus its accepted publication
    /// marker, and moves this charged holding into the SAME original Retirement.
    pub(in crate::asset_session) fn take_for_retirement(&mut self) -> Self {
        let Some(held) = &self.inner else {
            return Self::default();
        };
        if self.disposal.is_some()
            || held.clock.failed.load(Ordering::SeqCst)
            || !held.progress.try_lock().is_ok_and(|p| p.published())
        {
            return Self::default();
        }
        let disposal = UploadKeyDisposal {
            preparation: held.preparation.clone(),
            consumed: false,
        };
        Self {
            inner: self.inner.take(),
            disposal: Some(disposal),
            cancelled: None,
        }
    }
    /// Concrete memory disposal OFF the Document lock, while the existing
    /// retirement mutex still retains/counts this Work. On any failure keep
    /// originals/proof and return false; never credit scheduled Drop as empty.
    pub(in crate::asset_session) fn dispose_private(&mut self) -> bool {
        if self.cancelled.is_some() { return self.dispose_cancelled(); }
        let Some(held) = &self.inner else {
            return true;
        };
        let Some(run) = held.run.get() else {
            return false;
        };
        // The handoff did not end the original source/coordinator obligations.
        // Recheck their actual joins before clearing the retained private
        // native result; no status bit or record_saved receipt can do this.
        let Some(owner) = held.owner.upgrade() else {
            return false;
        };
        if !owner
            .upload_key_clock
            .get()
            .is_some_and(|clock| Arc::ptr_eq(clock, &held.clock))
            || !owner.vault.try_lock().is_ok_and(|work| {
                original_joins(&owner, &work) && work.first.is_none() && !work.release
            })
            || owner.stopped()
            || held.clock.failed.load(Ordering::SeqCst)
            || !held.progress.try_lock().is_ok_and(|p| p.published())
        {
            return false;
        }
        #[cfg(not(all(
            feature = "desktop-shell",
            target_os = "macos",
            target_pointer_width = "64",
            any(target_arch = "aarch64", target_arch = "x86_64")
        )))]
        {
            let _ = run;
            return false;
        }
        #[cfg(all(
            feature = "desktop-shell",
            target_os = "macos",
            target_pointer_width = "64",
            any(target_arch = "aarch64", target_arch = "x86_64")
        ))]
        {
            if !run.private_disposed() {
                let Some(proof) = self.disposal.take() else {
                    return false;
                };
                if run.dispose_private(proof).is_err() {
                    return false;
                }
            }
            if !run.private_disposed() {
                return false;
            }
            // This is after actual private disposal AND every original job,
            // including final journal readback/publication. No token-first cycle.
            if !controls::retire_use(held) { return false; }
#[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "macos-installed-observation", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer"), target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
            if observation::disposed(held).is_err(){return false;}
            let clock = held.clock.clone();
            self.inner = None; // Actual zeroizing private Fields/candidate holding dropped first.
                               // Only the same-original publication + all-join disposal proof can
                               // reach here. Generic Idle, record_saved, STOP and set_endpoint cannot
                               // retire a live deadline. Immutable admission/failure facts remain.
            clock.completed.store(true, Ordering::SeqCst);
            true
        }
    }
}

/// The real successful reference-store reservation, the exact native
/// preparation and the current original vault all have to meet at this gate.
/// None of those can be reconstructed from renderer/status-shaped DATA.
pub(crate) struct UploadKeyGoGate {
    held: Weak<Holding>,
    owner: Weak<OriginalWork>,
    document: Weak<Inner>,
    context: Arc<NativeContext>,
    preparation: Arc<UploadKeyPreparation>,
    key: Weak<crypto::VaultKey>,
    store: Weak<Mutex<store::StoreBook>>,
    state: Arc<PrivateStateDirectory>,
    reservation: Arc<persistence::DurableGenerationReservation>,
    secrets: Arc<commands::UploadKeySecrets>,
    clock: Arc<UploadKeyClock>,
    once: AtomicU8,
}
impl UploadKeyGoGate {
    pub(crate) fn preparation(&self) -> &Arc<UploadKeyPreparation> {
        &self.preparation
    }
    pub(crate) fn secrets(&self) -> &Arc<commands::UploadKeySecrets> {
        &self.secrets
    }
    pub(crate) fn original_bounds(&self) -> (Instant, Instant, Instant) {
        self.clock.bounds()
    }
    /// MEMORY ONLY: native start may already hold its registry/document locks.
    pub(crate) fn matches(
        &self,
        preparation: &Arc<UploadKeyPreparation>,
        context: &wire::UploadKeyContext,
    ) -> bool {
        Arc::ptr_eq(&self.preparation, preparation)
            && self.preparation.same_original(preparation)
            && self.preparation.context() == context
            && self.context.revision != 0
            && !self.clock.failed.load(Ordering::SeqCst)
            && self.owner.upgrade().is_some_and(|owner| {
                !owner.stopped()
                    && owner
                        .upload_key_clock
                        .get()
                        .is_some_and(|clock| Arc::ptr_eq(clock, &self.clock))
            })
    }
    pub(crate) fn matches_original(&self, original: &OriginalWork) -> bool {
        self.owner
            .upgrade()
            .is_some_and(|owner| std::ptr::eq(&*owner, original))
            && original
                .upload_key_clock
                .get()
                .is_some_and(|clock| Arc::ptr_eq(clock, &self.clock))
    }
    /// Native caller holds no Doc/Work lock. Do not call back into its registry
    /// here: this preserves the original first Instant without a lock cycle.
    pub(crate) fn failed_at(&self, reason: Reason, at: Instant) {
        self.native_cleanup_at(reason, Some(at), self.clock.cleanup_end(at));
    }
    /// SAME native control projection, including a possible cutoff without a
    /// known first-F. This never remaps time or calls back into native STOP.
    /// May run under the original native Registry/Document: only try-lock the
    /// optional explanatory books; the clock and STOP latch independently.
    pub(crate) fn native_cleanup_at(&self, reason: Reason, first: Option<Instant>, end: Instant) {
        self.clock.observe_native_cleanup(first, end);
        if let Some(held) = self.held.upgrade() {
            if let Ok(mut p) = held.progress.try_lock() {
                if let Some(first) = first {
                    p.fail(reason, first);
                } else {
                    p.phase = ProgressPhase::Failed;
                }
            }
        }
        if let Some(owner) = self.owner.upgrade() {
            if let Ok(mut work) = owner.vault.try_lock() {
                if let Some(first) = first {
                    work.fail(reason, first);
                }
                if let Some((_, first)) = work.first {
                    self.clock.observe_failure(first);
                }
            }
            owner.signal_stop();
        }
    }
    #[cfg(all(
        feature = "desktop-shell",
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64")
    ))]
    pub(crate) fn ready_for_go(
        self: &Arc<Self>,
        context: &wire::UploadKeyContext,
    ) -> Result<PreparedGenerationGo, Reason> {
        // Spend BEFORE any IO: a conflict, lost READY or uncertain GO does not
        // mint a replacement token or fresh operation ID.
        self.once
            .compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst)
            .map_err(|_| Reason::VaultInterrupted)?;
        let checked = (|| {
            let owner = self.owner.upgrade().ok_or(Reason::DocumentLost)?;
            if !self.matches(&self.preparation, context)
                || owner.interrupted()
                || Instant::now() >= self.clock.work
                || !self.preparation.current()
            {
                return Err(Reason::ContextStale);
            }
            // ORIGINAL shared-state IO in the original native writer, outside
            // every document/native-registry lock. No detached gate task.
            let retained = self.held.upgrade().ok_or(Reason::VaultInterrupted)?;
            controls::check_use(&retained)?;
            self.reservation
                .current(&self.state)
                .map_err(|error| preference_error(error).reason)?;
            let document = DocumentBinding {
                inner: self.document.upgrade().ok_or(Reason::DocumentLost)?,
            };
            let state = document.lock();
            let held = self.held.upgrade().ok_or(Reason::VaultInterrupted)?;
            rematch(&document, &state, &owner, &held, false)?;
            let edit = document
                .inner
                .bridge
                .edits
                .saved_registration_guard(&document.inner.session_identity)
                .map_err(|_| Reason::ContextStale)?;
            document
                .recheck_upload_key_saved_input(&state, self.preparation.saved(), &edit)
                .map_err(|_| Reason::ContextStale)?;
            // Private GO is downstream of the actual original inspector. Its
            // frozen native/tool charge participates in the EXISTING full
            // document census; the pre-start constructor quote is insufficient.
            // No book/Doc lock is held by the native atomic charge accessor.
            let live = lookup_memory::upload_key_live_bytes(
                &document.inner,
                &state,
                &owner,
                self.preparation.tools(),
            )
            .map_err(|_| Reason::Capacity)?
            .checked_add(installation_memory::additional_document_bytes(
                &document, &state,
            )?)
            .ok_or(Reason::Capacity)?;
            if live > store::RESIDENT_BYTES
                || live
                    .checked_add(held.allowance)
                    .is_none_or(|n| n > store::WORKING_BYTES)
            {
                return Err(Reason::Capacity);
            }
            // The actual document guard is dropped BEFORE private writer IO.
            drop(edit);
            drop(state);
            if !self.preparation.current() || owner.interrupted() {
                return Err(Reason::ContextStale);
            }
#[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "macos-installed-observation", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer"), target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
            observation::checkpoint(&held,observation::Cut::BeforeGo)?;
            Ok(PreparedGenerationGo {
                gate: self.clone(),
                consumed: false,
            })
        })();
        if let Err(reason) = checked {
            self.failed_at(reason, Instant::now());
        }
        checked
    }
}

/// Fixed native entry called only for the explicit confirmed-new-application
/// command. No password/path/tool/context digest arrives from the renderer.
#[cfg(all(
    feature = "desktop-shell",
    target_os = "macos",
    target_pointer_width = "64",
    any(target_arch = "aarch64", target_arch = "x86_64"),
    not(feature = "macos-android-registration-helper")
))]
impl DocumentBinding {
    pub(crate) fn generate_confirmed_new_upload_key(
        &self,
        service: Arc<ApplicationService>,
        native: &SavedCommandOwner,
        tools: Arc<crate::saved_command_owner::UploadKeyToolLoan>,
        context_revision: u32,
        native_availability: wire::Availability,
        consent: controls::Consent,
    ) -> Result<AssetStatus, AssetError> {
        if !consent.qualified(self) || native_availability != wire::Availability::Available {
            return Err(AssetError::new(Reason::Unqualified));
        }
        self.reconcile();
        let context = {
            let mut state = self.lock();
            self.expire(&mut state, Instant::now());
            self.durable_gate(&state, true)?;
            idle(&state)?;
            consent.current(self, &state)?;
            if !consent.service_matches(&service) { return Err(AssetError::new(Reason::ContextStale)); }
            let context = state
                .context
                .as_ref()
                .filter(|context| {
                    context.revision == context_revision && context.platform == Platform::Android
                })
                .ok_or_else(|| AssetError::new(Reason::ContextStale))?
                .clone();
            if !self.context_matches(&state, &context)? {
                return Err(AssetError::new(Reason::ContextStale));
            }
            context
        };
        // Private SAME-ready native binding, not a renderer/project-ID lookup.
        // First journal IO belongs to the retained coordinator NativeStateLease.
        let known = consent.project_binding();
        let (observed, saved, key, storage, roster) = {
            let mut state = self.lock();
            self.expire(&mut state, Instant::now());
            self.durable_gate(&state, true)?;
            idle(&state)?;
            if !state
                .context
                .as_ref()
                .is_some_and(|current| Arc::ptr_eq(current, &context))
            {
                return Err(AssetError::new(Reason::ContextStale));
            }
            let observed =
                self.credential_observation_for_binding(&state, known, Role::AndroidUpload)?;
            let edit = self
                .inner
                .bridge
                .edits
                .saved_registration_guard(&self.inner.session_identity)
                .map_err(|_| AssetError::new(Reason::ContextStale))?;
            let saved = self
                .upload_key_saved_input(&state, &context, &edit)
                .map_err(|_| AssetError::new(Reason::ContextStale))?;
            drop(edit);
            let session = state.vault.as_ref().ok_or_else(AssetError::invalid)?;
            let key = session
                .key
                .as_ref()
                .ok_or_else(|| AssetError::new(Reason::VaultKeyMissing))?
                .clone();
            let storage = session.store.clone();
            let roster = self.vault_roster(&mut state)?;
            (observed, saved, key, storage, roster)
        };
        // Explicit setup's reference-only observation is not authority. The
        // actual reservation re-reads/CAS-checks it under NativeUse before RNG.
        let preference = consent.preference();
        let plan = observed
            .with_continuity(Continuity::NewApplicationConfirmed, |value| {
                setup::classify(value, preference.preference.as_ref())
            })
            .map_err(data_error)?;
        if plan != Plan::OfferGeneration {
            return Err(AssetError::new(if plan == Plan::RecoveryRequired {
                Reason::VaultInterrupted
            } else {
                Reason::SourceRefused
            }));
        }
        let (record, allowance) = {
            let mut state = self.lock();
            self.expire(&mut state, Instant::now());
            self.durable_gate(&state, true)?;
            idle(&state)?;
            if state.revision != observed.revision
                || roster.generation != context.registry_generation
                || !state
                    .context
                    .as_ref()
                    .is_some_and(|current| Arc::ptr_eq(current, &context))
                || !self.context_matches(&state, &context)?
            {
                return Err(AssetError::new(Reason::ContextStale));
            }
            let session = state.vault.as_ref().ok_or_else(AssetError::invalid)?;
            if !Arc::ptr_eq(&storage, &session.store)
                || session
                    .key
                    .as_ref()
                    .is_none_or(|current| !Arc::ptr_eq(current, &key))
                || session
                    .rows
                    .iter()
                    .any(|row| row.authenticated.descriptor.kind == Kind::AndroidKeystore)
            {
                return Err(AssetError::new(Reason::SourceChanged));
            }
            // Quote all prior original owners plus the concrete native future
            // BEFORE Prepared/Work/control/private buffer construction. The
            // final pending-slot census repeats with actual retained objects.
            let live = lookup_memory::retained_document_bytes(&self.inner, &state)
                .map_err(|_| AssetError::new(Reason::Capacity))?
                .checked_add(
                    lookup_memory::upload_key_catalogue_bytes(&tools)
                        .map_err(|_| AssetError::new(Reason::Capacity))?,
                )
                .ok_or_else(|| AssetError::new(Reason::Capacity))?
                .checked_add(
                    installation_memory::additional_document_bytes(self, &state)
                        .map_err(AssetError::new)?,
                )
                .ok_or_else(|| AssetError::new(Reason::Capacity))?;
            let future = crate::saved_command_owner::upload_key_document_backing_bytes()
                .and_then(|n| {
                    saved
                        .retained_bytes()
                        .and_then(|saved| n.checked_add(saved))
                })
                .and_then(|n| {
                    n.checked_add(
                        std::mem::size_of::<OriginalWork>()
                            + std::mem::size_of::<Slot>()
                            + std::mem::size_of::<Holding>()
                            + std::mem::size_of::<UploadKeyGoGate>()
                            + std::mem::size_of::<UploadKeyClock>(),
                    )
                })
                // Whole-slot journal decode/encode plus bounded scalar/ID and
                // roster constructor backing, not a renewed work allowance.
                .and_then(|n| n.checked_add(2 * 1024 * 1024 + 34 * asset_source::PATH_LIMIT))
                .ok_or_else(|| AssetError::new(Reason::Capacity))?;
            let charged = live
                .checked_add(future)
                .ok_or_else(|| AssetError::new(Reason::Capacity))?;
            if !inspection_fits(charged, crate::macos_install_record::CONTROL_LIMIT) {
                return Err(AssetError::new(Reason::Capacity));
            }
            if charged
                .checked_add(CRYPTO_WORK_BYTES)
                .is_none_or(|n| n > store::WORKING_BYTES)
            {
                return Err(AssetError::new(Reason::Capacity));
            }
            let record = key
                .new_record_id(&session.inventory)
                .map_err(|error| AssetError::new(crypto_problem(error)))?;
            (record, CRYPTO_WORK_BYTES)
        };
        let native_context = wire::UploadKeyContext {
            project_id: observed.project.project_id.clone(),
            runtime_project_id: context.project_id.clone(),
            config_bytes: saved.config_bytes(),
            config_sha256: saved.config_sha256().to_owned(),
            draft_sha256: saved.draft_sha256().to_owned(),
            app_identity_sha256: observed.identity.clone(),
            observation_revision: observed.revision,
            vault: key.identity(),
            record,
        };
        let preparation = native
            .prepare_upload_key(
                native_context,
                context.registry_generation,
                context.project.clone(),
                native_availability,
                tools,
                saved,
            )
            .map_err(|_| AssetError::new(Reason::ContextStale))?;
        if !preparation.current()
            || preparation.inspection_reservation_bytes()
                != crate::macos_install_record::CONTROL_LIMIT
        {
            return Err(AssetError::new(Reason::ContextStale));
        }
        let mut state = self.lock();
        self.expire(&mut state, Instant::now());
        self.durable_upload_key_preparation_gate(&state, &preparation)?;
        idle(&state)?;
        if state.revision != observed.revision
            || !state
                .context
                .as_ref()
                .is_some_and(|current| Arc::ptr_eq(current, &context))
            || !self.context_matches(&state, &context)?
        {
            return Err(AssetError::new(Reason::ContextStale));
        }
        let edit = self
            .inner
            .bridge
            .edits
            .saved_registration_guard(&self.inner.session_identity)
            .map_err(|_| AssetError::new(Reason::ContextStale))?;
        self.recheck_upload_key_saved_input(&state, preparation.saved(), &edit)
            .map_err(|_| AssetError::new(Reason::ContextStale))?;
        drop(edit);
        let session = state.vault.as_mut().ok_or_else(AssetError::invalid)?;
        if !Arc::ptr_eq(&session.store, &storage)
            || session
                .key
                .as_ref()
                .is_none_or(|current| !Arc::ptr_eq(current, &key))
            || session
                .rows
                .iter()
                .any(|row| row.authenticated.descriptor.kind == Kind::AndroidKeystore)
            || session.inventory.contains(&record)
        {
            return Err(AssetError::new(Reason::SourceChanged));
        }
        session
            .rows
            .try_reserve_exact(store::DESCRIPTOR_COUNT.saturating_sub(session.rows.len()))
            .map_err(|_| AssetError::new(Reason::Capacity))?;
        session
            .inventory
            .try_reserve_exact(store::DESCRIPTOR_COUNT.saturating_sub(session.inventory.len()))
            .map_err(|_| AssetError::new(Reason::Capacity))?;
        if session.rows.capacity() > store::DESCRIPTOR_COUNT
            || session.inventory.capacity() > store::DESCRIPTOR_COUNT
        {
            return Err(AssetError::new(Reason::Capacity));
        }
        let clock = Arc::new(UploadKeyClock::new(Instant::now()));
        let mut slot = self.vault_owner(
            &mut state,
            Operation::GenerateUploadKey,
            Some(context.clone()),
            None,
            None,
            true,
        )?;
        slot.kind = Some(Kind::AndroidKeystore);
        slot.vault.generation = Some(roster.generation);
        slot.owner
            .upload_key_clock
            .set(clock.clone())
            .map_err(|_| AssetError::new(Reason::CleanupUnknown))?;
        let inspection_reservation = preparation.inspection_reservation_bytes();
        let held = Arc::new(Holding {
            owner: Arc::downgrade(&slot.owner),
            document: Arc::downgrade(&self.inner),
            context,
            key: Arc::downgrade(&key),
            store: Arc::downgrade(&storage),
            native: native.clone(),
            preparation,
            service,
            setup: consent.preparation().clone(),
            native_use: OnceLock::new(),
            native_use_retired: AtomicBool::new(false),
            observed,
            preference_revision: preference.store_revision,
            roster,
            allowance,
            inspection_reservation,
            clock,
            progress: Mutex::new(Progress::new()),
            reservation: OnceLock::new(),
            secrets: OnceLock::new(),
            gate: OnceLock::new(),
            run: OnceLock::new(),
            cancellation: Default::default(),
        });
        slot.owner
            .vault
            .lock()
            .map_err(|_| AssetError::new(Reason::CleanupUnknown))?
            .upload_key = Work {
            inner: Some(held.clone()),
            disposal: None,
            cancelled: None,
        };
        let live = lookup_memory::pending_slot_bytes(&state, &slot)
            .map_err(|_| AssetError::new(Reason::Capacity))?
            .checked_add(
                lookup_memory::upload_key_catalogue_bytes(held.preparation.tools())
                    .map_err(|_| AssetError::new(Reason::Capacity))?,
            )
            .ok_or_else(|| AssetError::new(Reason::Capacity))?
            .checked_add(
                installation_memory::additional_document_bytes(self, &state)
                    .map_err(AssetError::new)?,
            )
            .ok_or_else(|| AssetError::new(Reason::Capacity))?;
        if !inspection_fits(live, held.inspection_reservation)
            || live
                .checked_add(allowance)
                .is_none_or(|n| n > store::WORKING_BYTES)
        {
            return Err(AssetError::new(Reason::Capacity));
        }
        let start = self.install(
            &mut state,
            slot,
            crate::asset_session::Job::Vault(super::super::Job::GenerateUploadKey(Request {
                held,
            })),
        )?;
        let status = self.snapshot(&state);
        drop(state);
        let _ = start.send(());
        Ok(status)
    }
}

/// NonClone and retained by the original fixed writer before consumption or
/// send. The absence of a sent acknowledgement never permits a second GO.
pub(crate) struct PreparedGenerationGo {
    gate: Arc<UploadKeyGoGate>,
    consumed: bool,
}
impl PreparedGenerationGo {
    pub(crate) fn consume_for_writer(
        &mut self,
        preparation: &Arc<UploadKeyPreparation>,
        context: &wire::UploadKeyContext,
    ) -> Result<(), Reason> {
        if self.consumed {
            return Err(Reason::VaultInterrupted);
        }
        self.consumed = true;
        if !self.gate.matches(preparation, context)
            || Instant::now() >= self.gate.clock.work
            || self
                .gate
                .once
                .compare_exchange(1, 2, Ordering::SeqCst, Ordering::SeqCst)
                .is_err()
            || self
                .gate
                .owner
                .upgrade()
                .is_none_or(|owner| owner.interrupted())
        {
            return Err(Reason::ContextStale);
        }
        Ok(())
    }
}

#[cfg(feature = "desktop-shell")]
fn rematch(
    document: &DocumentBinding,
    state: &DocumentState,
    owner: &Arc<OriginalWork>,
    held: &Arc<Holding>,
    mutating: bool,
) -> Result<(), Reason> {
    current_gate(document, state, owner)?;
    controls::current_prepared(document, state, &held.setup).map_err(|error| error.reason)?;
    let slot = state.slot.as_ref().ok_or(Reason::ContextStale)?;
    let session = state.vault.as_ref().ok_or(Reason::Closed)?;
    let key = held.key.upgrade().ok_or(Reason::VaultKeyMissing)?;
    let storage = held.store.upgrade().ok_or(Reason::Closed)?;
    let work = owner.vault.try_lock().map_err(|_| Reason::CleanupUnknown)?;
    if slot.operation != Operation::GenerateUploadKey
        || slot.target.is_some()
        || slot.reason != Reason::None
        || slot.cleanup_end.is_some()
        || slot.vault.generation != Some(held.roster.generation)
        || !state
            .context
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, &held.context))
        || !slot
            .context
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, &held.context))
        || !document
            .context_matches(state, &held.context)
            .map_err(|error| error.reason)?
        || session.registry_generation != held.roster.generation
        || session.identity != Some(held.preparation.context().vault)
        || session.revoked
        || session.read_only
        || session.state
            != if mutating {
                State::Mutating
            } else {
                State::Unlocked
            }
        || !Arc::ptr_eq(&session.store, &storage)
        || session
            .key
            .as_ref()
            .is_none_or(|current| !Arc::ptr_eq(current, &key))
        || work.release
        || work.first.is_some()
        || work
            .store
            .as_ref()
            .is_none_or(|current| !Arc::ptr_eq(current, &storage))
        || work
            .key
            .as_ref()
            .is_none_or(|current| !Arc::ptr_eq(current, &key))
        || work
            .upload_key
            .inner
            .as_ref()
            .is_none_or(|current| !Arc::ptr_eq(current, held))
        || session
            .rows
            .iter()
            .any(|row| row.authenticated.descriptor.kind == Kind::AndroidKeystore)
        || session
            .inventory
            .contains(&held.preparation.context().record)
    {
        return Err(Reason::SourceChanged);
    }
    Ok(())
}

pub(in crate::asset_session) struct Request {
    held: Arc<Holding>,
}
pub(in crate::asset_session) struct SaveRequest {
    held: Arc<Holding>,
}

/// The ONLY allocation exception for this already-rostered private holding.
/// It admits its own fixed New child, not Load/Mutate or a second generation.
pub(in crate::asset_session) fn child_admitted(
    owner: &OriginalWork,
    request: &SaveRequest,
) -> bool {
    if owner.interrupted()
        || owner.installation.is_some()
        || !owner.retired.load(Ordering::SeqCst)
        || request
            .held
            .owner
            .upgrade()
            .is_none_or(|current| !std::ptr::eq(&*current, owner))
        || !owner
            .keyring
            .try_lock()
            .is_ok_and(|book| !book.memory_held())
        || !owner
            .source
            .try_lock()
            .is_ok_and(|source| source.not_started())
    {
        return false;
    }
    let Ok(work) = owner.vault.try_lock() else {
        return false;
    };
    work.first.is_none()
        && !work.release
        && work
            .upload_key
            .inner
            .as_ref()
            .is_some_and(|held| Arc::ptr_eq(held, &request.held))
        && work.outcome
            == Some(store::StorageOutcome {
                effect: store::Effect::NotStarted,
                durability: store::Durability::NotRun,
                cleanup: store::Cleanup::Pending,
            })
        && request.held.progress.try_lock().is_ok_and(|p| {
            p.phase == ProgressPhase::Candidate
                && p.first.is_none()
                && p.outcome.is_none()
                && p.saved.is_none()
        })
        && request
            .held
            .gate
            .get()
            .is_some_and(|gate| gate.once.load(Ordering::SeqCst) == 2)
        && request
            .held
            .run
            .get()
            .is_some_and(|run| run.native_settled() && !run.cleanup_unknown())
}

/// Called by the closed original Child::GenerateUploadKey arm while it holds
/// the SAME StoreBook used by normal encrypted-vault operations.
pub(in crate::asset_session) fn execute(
    owner: &Arc<OriginalWork>,
    book: &mut store::StoreBook,
    request: SaveRequest,
) -> Result<ChildResult, Reason> {
    #[cfg(not(all(
        feature = "desktop-shell",
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64")
    )))]
    {
        let _ = (owner, book, request);
        return Err(Reason::Unqualified);
    }
    #[cfg(all(
        feature = "desktop-shell",
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64")
    ))]
    {
        let held = &request.held;
        let result = (|| {
            if held
                .owner
                .upgrade()
                .is_none_or(|current| !Arc::ptr_eq(&current, owner))
                || owner.interrupted()
            {
                return Err(Reason::UserCancelled);
            }
            held.progress()?
                .enter(ProgressPhase::Candidate, ProgressPhase::Storing)?;
            let run = held.run.get().ok_or(Reason::VaultInterrupted)?;
            let key = active_key(owner)?;
            let context = held.preparation.context();
            if !run.native_settled()
                || run.cleanup_unknown()
                || key.identity() != context.vault
                || held
                    .key
                    .upgrade()
                    .is_none_or(|current| !Arc::ptr_eq(&current, &key))
            {
                return Err(Reason::SourceChanged);
            }
            check_exclusions(owner, book, &held.roster)?;
            // Candidate stays inside the SAME native Session. This fixed method
            // seals once, never exports raw JKS/password bytes or replaces a key.
            let candidate = run
                .seal_new(&key, context.record, held.allowance, owner)
                .map_err(crypto_problem)?;
            let revision = candidate.revision();
            if revision.counter != 1 {
                return Err(Reason::VaultCorrupt);
            }
            let exact_length = candidate.bytes().len();
            let intent = key
                .seal_intent(
                    format::Mutation::New,
                    context.record,
                    None,
                    Some(&candidate),
                )
                .map_err(crypto_problem)?;
            if owner.interrupted() {
                return Err(Reason::UserCancelled);
            }
            let effect = book.mutate(
                &intent,
                Some(candidate.bytes()),
                None,
                &mut || owner.interrupted(),
                &mut || cleanup_expired(owner),
            );
            // Preserve THIS actual mutation outcome before any effect/readback
            // error returns. Pre-seal/capture failure must never replay an older
            // StoreBook outcome into this original operation.
            let outcome = book.storage_outcome();
            remember(owner, book, true)?;
            held.progress()?.outcome = outcome;
            effect.map_err(problem)?;
            if outcome
                != Some(store::StorageOutcome {
                    effect: store::Effect::KnownApplied,
                    durability: store::Durability::Confirmed,
                    cleanup: store::Cleanup::Known,
                })
            {
                return Err(Reason::VaultDurabilityUnknown);
            }
            drop(candidate); // Bound ciphertext/plaintext overlap before readback.
            if exact_length
                .checked_add(crypto::CONTROL_BYTES)
                .is_none_or(|n| n > held.allowance)
            {
                return Err(Reason::Capacity);
            }
            let actual = book
                .read_record(context.record, true, &mut || owner.interrupted())
                .map_err(problem)?;
            let (bytes, witness, complete) = actual.into_parts();
            if !complete
                || bytes.len() != exact_length
                || bytes
                    .capacity()
                    .checked_add(crypto::CONTROL_BYTES)
                    .is_none_or(|n| n > held.allowance)
            {
                return Err(Reason::VaultCorrupt);
            }
            let opened = key
                .open_record(bytes, held.allowance)
                .map_err(crypto_problem)?;
            if opened.record != context.record
                || opened.revision != revision
                || !run.matches_authenticated_readback(&opened)
            {
                return Err(Reason::VaultCorrupt);
            }
            // This is observed from that original generated leaf only AFTER the
            // full JKS and every private Field matched authenticated readback.
            let certificate = run
                .observed_certificate_sha256()
                .ok_or(Reason::VaultCorrupt)?;
            book.recheck_root(&mut || owner.interrupted())
                .map_err(problem)?;
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
            // The private fields/file from opened are dropped/zeroized here. The
            // original candidate remains retained across all later uncertainty.
            drop((opened.fields, opened.file));
            let mut progress = held.progress()?;
            progress.saved = Some(row.reference(key.identity()));
            progress.certificate = Some(certificate);
            progress.enter(ProgressPhase::Storing, ProgressPhase::Stored)?;
            progress.authenticated_new = Some(cancellation::AuthenticatedNew::capture(
                held, row.reference(key.identity()), certificate));
            Ok(ChildResult::Mutated {
                record: context.record,
                row: Some(row),
            })
        })();
        if let Err(reason) = result {
            held.fail(reason, Instant::now());
        }
        result
    }
}

#[cfg(all(
    feature = "desktop-shell",
    target_os = "macos",
    target_pointer_width = "64",
    any(target_arch = "aarch64", target_arch = "x86_64")
))]
async fn run_inner(
    document: &DocumentBinding,
    owner: &Arc<OriginalWork>,
    request: Request,
) -> Result<crate::asset_session::Staged, Reason> {
    let held = &request.held;
    {
        let state = document.lock();
        rematch(document, &state, owner, held, false)?;
    }
#[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "macos-installed-observation", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer"), target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
    observation::bind(held)?;
    controls::begin_use(held)?; // SAME original coordinator, before any journal/private work.
    controls::check_use(held)?;
    held.progress()?
        .enter(ProgressPhase::Admitted, ProgressPhase::Reserving)?;
    let context = held.preparation.context();
    let intent = setup::GenerationIntent {
        operation_id: held.preparation.operation_id().to_owned(),
        vault_id: context.vault.vault.token(),
        generation_id: context.vault.generation.token(),
        record_id: context.record.token(),
        identity_sha256: held.observed.identity.clone(),
        observation_revision: held.observed.revision,
    };
    let reservation = held
        .observed
        .with_continuity(Continuity::NewApplicationConfirmed, |observed| {
            persistence::reserve_generation(
                held.service.state_directory(),
                held.preference_revision,
                &held.observed.project,
                Role::AndroidUpload,
                intent,
                observed,
            )
        })
        .map_err(|error| preference_error(error).reason)?;
    // Original durable intent is rooted BEFORE password generation, keytool,
    // or fallible post-reservation checks. Restart/rerun cannot erase it.
    held.reservation
        .set(Arc::new(reservation))
        .map_err(|_| Reason::VaultInterrupted)?;
    held.progress()?
        .enter(ProgressPhase::Reserving, ProgressPhase::Reserved)?;
    {
        let state = document.lock();
        rematch(document, &state, owner, held, false)?;
    }
    held.secrets
        .set(Arc::new(
            commands::UploadKeySecrets::generate().map_err(crypto_problem)?,
        ))
        .map_err(|_| Reason::VaultInterrupted)?;
    let gate = Arc::new(UploadKeyGoGate {
        held: Arc::downgrade(held),
        owner: Arc::downgrade(owner),
        document: Arc::downgrade(&document.inner),
        context: held.context.clone(),
        preparation: held.preparation.clone(),
        key: held.key.clone(),
        store: held.store.clone(),
        state: held.service.state_directory().clone(),
        reservation: held
            .reservation
            .get()
            .ok_or(Reason::VaultInterrupted)?
            .clone(),
        secrets: held.secrets.get().ok_or(Reason::VaultInterrupted)?.clone(),
        clock: held.clock.clone(),
        once: AtomicU8::new(0),
    });
    held.gate
        .set(gate.clone())
        .map_err(|_| Reason::VaultInterrupted)?;
    held.progress()?
        .enter(ProgressPhase::Reserved, ProgressPhase::Starting)?;
    // Same SavedCommandOwner, original tool loan and original tuple. The
    // closed same-parent admission hook must NOT bypass unrelated Asset work.
    let admitted = held
        .native
        .start_upload_key(
            held.preparation.clone(),
            gate,
            Some((
                held.context.registry_generation,
                held.context.project.clone(),
            )),
            wire::Availability::Available,
        )
        .map_err(|_| Reason::VaultInterrupted)?;
    let run = admitted.run.ok_or(Reason::VaultInterrupted)?;
    held.run
        .set(Arc::new(run))
        .map_err(|_| Reason::VaultInterrupted)?;
    held.progress()?
        .enter(ProgressPhase::Starting, ProgressPhase::Running)?;
    admitted.release.release(); // Only AFTER the parent retains the exact Run.
    let run = held.run.get().ok_or(Reason::VaultInterrupted)?;
    wait_candidate(owner, held, run).await?;
    if !run.native_settled() || run.cleanup_unknown() {
        return Err(Reason::CleanupUnknown);
    }
    held.progress()?
        .enter(ProgressPhase::Running, ProgressPhase::Candidate)?;
    {
        let mut state = document.lock();
        rematch(document, &state, owner, held, false)?;
        let live = lookup_memory::upload_key_live_bytes(
            &document.inner,
            &state,
            owner,
            held.preparation.tools(),
        )
        .map_err(|_| Reason::Capacity)?
        .checked_add(installation_memory::additional_document_bytes(
            document, &state,
        )?)
        .ok_or(Reason::Capacity)?;
        if live > store::RESIDENT_BYTES
            || live
                .checked_add(held.allowance)
                .is_none_or(|n| n > store::WORKING_BYTES)
        {
            return Err(Reason::Capacity);
        }
        let mut work = owner.vault.try_lock().map_err(|_| Reason::CleanupUnknown)?;
        if work.outcome.is_some() {
            return Err(Reason::VaultInterrupted);
        }
        let slot = state.slot.as_mut().ok_or(Reason::ContextStale)?;
        if slot.vault.outcome.is_some() {
            return Err(Reason::VaultInterrupted);
        }
        let outcome = store::StorageOutcome {
            effect: store::Effect::NotStarted,
            durability: store::Durability::NotRun,
            cleanup: store::Cleanup::Pending,
        };
        work.outcome = Some(outcome);
        slot.vault.outcome = Some(outcome);
        slot.phase = Phase::Mutating;
        state.vault.as_mut().ok_or(Reason::Closed)?.state = State::Mutating;
    }
    let result = native(
        document,
        owner,
        Child::GenerateUploadKey(SaveRequest { held: held.clone() }),
    )
    .await?;
    let (record, row) = match result {
        ChildResult::Mutated {
            record,
            row: Some(row),
        } => (record, row),
        _ => return Err(Reason::CleanupUnknown),
    };
    // The original storage child and all native generator C/A/W/tool/tail
    // joins precede record_saved. Coordinator publication still follows later.
    if !run.native_settled()
        || run.cleanup_unknown()
        || !owner
            .child
            .try_lock()
            .is_ok_and(|book| book.handle.is_none() && book.receipt == JoinReceipt::Returned)
    {
        return Err(Reason::CleanupUnknown);
    }
    {
        let state = document.lock();
        rematch(document, &state, owner, held, true)?;
    }
#[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "macos-installed-observation", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer"), target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
    { observation::stored(held)?; observation::checkpoint(held,observation::Cut::AfterNew)?; }
    let (reference, certificate) = {
        let mut p = held.progress()?;
        p.enter(ProgressPhase::Stored, ProgressPhase::Recording)?;
        (
            p.saved.ok_or(Reason::VaultCorrupt)?,
            p.certificate.ok_or(Reason::VaultCorrupt)?,
        )
    };
    let reservation = held.reservation.get().ok_or(Reason::VaultInterrupted)?;
    let saved = SavedAssignment {
        reference: KeyReference::native(reference.identity, reference.record, reference.revision),
        identity_sha256: held.observed.identity.clone(),
        certificate_sha256: Some(crate::service_protocol::hex(&certificate)),
        operation_id: reservation.operation_id().to_owned(),
    };
    controls::check_use(held)?;
    let revision = persistence::record_saved(
        held.service.state_directory(),
        reservation.store_revision(),
        &held.observed.project,
        Role::AndroidUpload,
        saved,
    )
    .map_err(|error| preference_error(error).reason)?;
    {
        let mut p = held.progress()?;
        p.journal_revision = Some(revision);
        p.enter(ProgressPhase::Recording, ProgressPhase::Recorded)?;
    }
    {
        let state = document.lock();
        rematch(document, &state, owner, held, true)?;
    }
    Ok(crate::asset_session::Staged::Vault(
        super::super::Staged::Mutated {
            record,
            row: Some(row),
            generation: held.roster.generation,
        },
    ))
}

#[cfg(all(
    feature = "desktop-shell",
    target_os = "macos",
    target_pointer_width = "64",
    any(target_arch = "aarch64", target_arch = "x86_64")
))]
async fn wait_candidate(
    owner: &Arc<OriginalWork>,
    held: &Arc<Holding>,
    run: &Arc<UploadKeyRun>,
) -> Result<(), Reason> {
    let candidate = run.wait_candidate();
    tokio::pin!(candidate);
    let mut forwarded: Option<Instant> = None;
    loop {
        let wake = owner.wake.notified();
        if owner.interrupted() || held.clock.failed.load(Ordering::SeqCst) {
            let retained = owner.vault.try_lock().ok().and_then(|work| work.first);
            if let Some((_, at)) = retained {
                held.clock.observe_failure(at);
            }
            // A native Unknown cutoff without F is already a stopped original;
            // do not manufacture/echo a local event at status-observation time.
            let first = held.clock.failure_at().or_else(|| {
                if held.clock.failed.load(Ordering::SeqCst) {
                    None
                } else {
                    Some(if Instant::now() >= held.clock.work {
                        held.clock.work
                    } else {
                        Instant::now()
                    })
                }
            });
            if let Some(at) = first {
                let reason = retained.map_or(
                    if at >= held.clock.work {
                        Reason::Deadline
                    } else {
                        Reason::UserCancelled
                    },
                    |(reason, _)| reason,
                );
                if forwarded.is_none_or(|old| at < old) {
                    held.clock.observe_failure(at);
                    // Original native F/cutoff is already carried by its own
                    // ControlData. Only a new earlier parent failure crosses
                    // back; never re-invert a remote timestamp as local STOP.
                    if !held.clock.native_already_knows(at) {
                        run.failed_at(reason, at);
                    }
                    forwarded = Some(at);
                }
            }
        }
        let end = held.clock.cleanup_cutoff().unwrap_or(held.clock.work);
        if Instant::now() >= end {
            if held.clock.failed.load(Ordering::SeqCst) {
                return Err(Reason::CleanupUnknown);
            }
            held.clock.observe_failure(held.clock.work);
            owner.signal_stop();
            continue;
        }
        tokio::select! {
            result = &mut candidate => return result.map_err(|_| if run.cleanup_unknown() { Reason::CleanupUnknown } else { Reason::VaultInterrupted }),
            _ = wake => {},
            _ = tokio::time::sleep_until(end.into()) => {},
        }
    }
}

#[cfg(feature = "desktop-shell")]
pub(in crate::asset_session) async fn run(
    document: &DocumentBinding,
    owner: &Arc<OriginalWork>,
    request: Request,
) -> Result<crate::asset_session::Staged, Reason> {
    #[cfg(all(
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64")
    ))]
    {
        let held = request.held.clone();
        let result = run_inner(document, owner, request).await;
        if let Err(reason) = result {
            held.fail(reason, Instant::now());
        }
        result
    }
    #[cfg(not(all(
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64")
    )))]
    {
        let _ = (document, owner, request);
        Err(Reason::Unqualified)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn id(byte: u8) -> format::Id {
        format::Id::from_bytes([byte; 16]).unwrap()
    }
    fn row() -> Descriptor {
        let record = id(3);
        let revision = format::Revision::new(id(4), 1).unwrap();
        Descriptor {
            authenticated: crypto::AuthenticatedDescriptor {
                record,
                revision,
                descriptor: format::Descriptor::new(
                    Kind::AndroidKeystore,
                    None,
                    vec![true; 3],
                    true,
                )
                .unwrap(),
            },
            original: store::ReadWitness::lifecycle_data(record, revision),
            mutation_pending: false,
        }
    }
    fn session() -> Session {
        // Real types/codec DATA only. No native vault opened, no generated key,
        // process, private file, account, toolchain or native join is entered.
        let identity = format::Identity::new(id(1), id(2)).unwrap();
        let mut session = Session::new(Arc::new(Mutex::new(store::StoreBook::new())), 7);
        session.identity = Some(identity);
        session.key = Some(Arc::new(crypto::lifecycle_data_key(identity)));
        session.state = State::Unlocked;
        session.rows.push(row());
        session
    }
    fn observation_data(session: &Session) -> UploadKeyObservation {
        UploadKeyObservation {
            reference: session.rows[0].reference(session.identity.unwrap()),
            identity: [6; 32],
            certificate: [7; 32],
            key: Arc::downgrade(session.key.as_ref().unwrap()),
            store: Arc::downgrade(&session.store),
        }
    }

    #[test]
    fn one_original_clock_contracts_earlier_delayed_failure_without_renewal_or_reason_replacement()
    {
        let start = Instant::now();
        let clock = UploadKeyClock::new(start);
        assert_eq!(
            clock.bounds(),
            (
                start,
                start + Duration::from_secs(180),
                start + Duration::from_secs(190)
            )
        );
        let mut ordinary = super::super::super::Work::default();
        ordinary.fail(Reason::UserCancelled, start + Duration::from_secs(30));
        assert_eq!(
            clock.observe_failure(start + Duration::from_secs(30)),
            start + Duration::from_secs(40)
        );
        ordinary.fail(Reason::VaultInterrupted, start + Duration::from_secs(20));
        assert_eq!(
            clock.observe_failure(start + Duration::from_secs(20)),
            start + Duration::from_secs(30)
        );
        assert_eq!(
            clock.observe_failure(start + Duration::from_secs(100)),
            start + Duration::from_secs(30)
        );
        assert_eq!(
            ordinary.first,
            Some((Reason::UserCancelled, start + Duration::from_secs(30)))
        );
        assert_eq!(clock.bounds().1, start + Duration::from_secs(180));
        let late = UploadKeyClock::new(start);
        assert_eq!(
            late.observe_failure(start + Duration::from_secs(185)),
            start + Duration::from_secs(190)
        );
    }

    #[test]
    fn native_inverse_cutoff_contracts_without_echo_or_fabricated_first_failure() {
        let start = Instant::now();
        let clock = UploadKeyClock::new(start);
        clock.observe_failure(start + Duration::from_secs(60));
        let first = start + Duration::from_secs(40);
        let cutoff = first + Duration::from_secs(7);
        clock.observe_native_cleanup(Some(first), cutoff);
        assert_eq!(clock.failure_at(), Some(first));
        assert_eq!(clock.cleanup_end(start + Duration::from_secs(70)), cutoff);
        assert!(clock.native_already_knows(first));
        assert!(clock.native_already_knows(first + Duration::from_secs(1)));
        assert!(!clock.native_already_knows(first - Duration::from_secs(1)));
        clock.observe_native_cleanup(
            Some(first + Duration::from_secs(10)),
            cutoff + Duration::from_secs(20),
        );
        assert_eq!(clock.cleanup_cutoff(), Some(cutoff));
        assert_eq!(
            clock.bounds(),
            (
                start,
                start + Duration::from_secs(180),
                start + Duration::from_secs(190)
            )
        );
        let unknown = UploadKeyClock::new(start);
        unknown.observe_native_cleanup(None, start);
        assert_eq!(unknown.failure_at(), None);
        assert_eq!(unknown.cleanup_cutoff(), Some(start));
        assert!(unknown.failed.load(Ordering::SeqCst));
        assert!(unknown.native_already_knows(start + Duration::from_secs(1)));
    }

    #[test]
    fn actual_original_stop_and_store_cleanup_use_earliest_clock_not_cached_release_end() {
        let start = Instant::now() - Duration::from_secs(100);
        let owner = OriginalWork::new(77, false, Weak::new());
        let clock = Arc::new(UploadKeyClock::new(start));
        assert!(owner.upload_key_clock.set(clock.clone()).is_ok());
        owner.set_endpoint(None);
        owner.set_endpoint(Some(start + Duration::from_secs(1000)));
        assert_eq!(owner.endpoint(), Some(start + Duration::from_secs(180)));
        let first = start + Duration::from_secs(30);
        owner
            .vault
            .lock()
            .unwrap()
            .fail(Reason::VaultCorrupt, first);
        let mut slot = Slot::new(
            owner.clone(),
            Operation::GenerateUploadKey,
            None,
            None,
            None,
        );
        slot.stop(Reason::UserCancelled, start + Duration::from_secs(50));
        assert_eq!(slot.cleanup_end, Some(first + Duration::from_secs(10)));
        assert_eq!(
            owner.vault.lock().unwrap().first,
            Some((Reason::VaultCorrupt, first))
        );
        // Synthetic bookkeeping cut after a release has already cached its
        // later endpoint. The real store callback still uses the stricter cap.
        owner.vault.lock().unwrap().release_end = Some(Instant::now() + Duration::from_secs(100));
        clock.observe_native_cleanup(
            Some(start + Duration::from_secs(20)),
            start + Duration::from_secs(25),
        );
        assert!(cleanup_expired(&owner));
        assert_eq!(clock.failure_at(), Some(start + Duration::from_secs(20)));
        assert_eq!(
            owner.vault.lock().unwrap().first,
            Some((Reason::VaultCorrupt, first))
        );
    }

    #[test]
    fn readback_record_saved_and_failed_publication_never_grant_private_disposal() {
        let start = Instant::now();
        let clock = UploadKeyClock::new(start);
        let mut p = Progress::new();
        p.phase = ProgressPhase::Stored;
        p.outcome = Some(store::StorageOutcome {
            effect: store::Effect::KnownApplied,
            durability: store::Durability::Confirmed,
            cleanup: store::Cleanup::Known,
        });
        p.saved = Some(row().reference(format::Identity::new(id(1), id(2)).unwrap()));
        assert!(!p.saved_effect_known()); // Descriptor/readback without observed original leaf.
        p.certificate = Some([7; 32]);
        p.journal_revision = Some(2);
        p.phase = ProgressPhase::Recorded;
        assert!(p.saved_effect_known());
        assert!(!p.published()); // record_saved is not publication.
        p.phase = ProgressPhase::Published;
        assert!(p.published()); // Pure predicate DATA, not an original join/disposal permission.
        p.fail(Reason::ContextStale, start + Duration::from_secs(1));
        assert!(!p.published());
        assert_eq!(clock.endpoint(), Some(start + Duration::from_secs(180)));
    }

    #[test]
    fn actual_retirement_of_marker_only_or_empty_data_cannot_erase_live_generation_clock() {
        let mut state = super::super::super::tests::loan_state();
        let start = Instant::now() - Duration::from_secs(200);
        let owner = OriginalWork::new(78, false, Weak::new());
        let clock = Arc::new(UploadKeyClock::new(start));
        assert!(owner.upload_key_clock.set(clock.clone()).is_ok());
        // Existing synthetic original receipt DATA only, no private candidate,
        // tool/key generation, source IO, actual producer or grant constructor.
        owner.coordinator.lock().unwrap().receipt = JoinReceipt::Returned;
        owner.child.try_lock().unwrap().receipt = JoinReceipt::Returned;
        let mut slot = Slot::new(
            owner.clone(),
            Operation::GenerateUploadKey,
            state.context.clone(),
            None,
            None,
        );
        slot.vault.upload_key_new_published = true; // A marker alone is deliberately insufficient.
        let retired = take_retirement(&mut state, &mut slot);
        assert!(!retired.upload_key.blocks_reuse());
        assert!(owner
            .retain_retirement(Retirement {
                vault: retired,
                ..Retirement::default()
            })
            .is_ok());
        assert!(owner.release_retirement());
        assert_eq!(owner.endpoint(), Some(start + Duration::from_secs(180)));
        assert!(owner.interrupted());
        assert!(!clock.completed.load(Ordering::SeqCst));
        assert!(!NATIVE_UPLOAD_KEY_QUALIFIED);
    }

    #[test]
    fn failure_never_reopens_reservation_or_recording_and_first_reason_survives_cleanup() {
        let mut progress = Progress::new();
        let at = Instant::now();
        progress
            .enter(ProgressPhase::Admitted, ProgressPhase::Reserving)
            .unwrap();
        progress.fail(Reason::VaultDurabilityUnknown, at);
        progress.fail(Reason::CleanupUnknown, at + Duration::from_secs(1));
        assert!(progress
            .enter(ProgressPhase::Admitted, ProgressPhase::Reserving)
            .is_err());
        assert!(progress
            .enter(ProgressPhase::Stored, ProgressPhase::Recording)
            .is_err());
        assert_eq!(progress.first, Some((Reason::VaultDurabilityUnknown, at)));
        assert!(progress.saved.is_none() && progress.journal_revision.is_none());
    }

    #[test]
    fn volatile_observation_requires_full_current_reference_not_expected_hash_or_counter() {
        let mut session = session();
        let app = "06".repeat(32);
        assert!(certificate_for(&session, &session.rows[0], &app).is_none());
        session.upload_key_observation = Some(observation_data(&session));
        assert_eq!(
            certificate_for(&session, &session.rows[0], &app),
            Some([7; 32])
        );
        assert!(certificate_for(&session, &session.rows[0], &"08".repeat(32)).is_none());
        let mut alias = row();
        alias.authenticated.revision = format::Revision::new(id(9), 1).unwrap();
        assert!(certificate_for(&session, &alias, &app).is_none());
        alias = row();
        alias.original =
            store::ReadWitness::lifecycle_data(id(3), format::Revision::new(id(10), 1).unwrap());
        assert!(certificate_for(&session, &alias, &app).is_none());
    }

    #[test]
    fn replacing_vault_key_or_book_never_restores_observed_signer_from_preference() {
        let mut session = session();
        let app = "06".repeat(32);
        session.upload_key_observation = Some(observation_data(&session));
        let original_key = session.key.take().unwrap();
        session.key = Some(Arc::new(crypto::lifecycle_data_key(
            session.identity.unwrap(),
        )));
        assert!(certificate_for(&session, &session.rows[0], &app).is_none());
        session.key = Some(original_key);
        assert!(certificate_for(&session, &session.rows[0], &app).is_some());
        let _original_store = std::mem::replace(
            &mut session.store,
            Arc::new(Mutex::new(store::StoreBook::new())),
        );
        assert!(certificate_for(&session, &session.rows[0], &app).is_none());
        assert!(!NATIVE_UPLOAD_KEY_QUALIFIED);
    }

    #[test]
    fn full_inspection_partition_is_separate_and_never_private_vault_credit() {
        let reserve = crate::macos_install_record::CONTROL_LIMIT;
        let backing = 48 * 1024 * 1024;
        assert!(reserve > store::WORKING_BYTES);
        assert!(inspection_fits(backing, reserve));
        assert!(!inspection_fits(backing + 1, reserve));
        assert!(!inspection_fits(0, reserve - 1));
        assert!(!inspection_fits(usize::MAX, reserve));
        assert!(!inspection_fits(store::RESIDENT_BYTES + 1, reserve));
    }
}
