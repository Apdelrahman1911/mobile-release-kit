//! Cleanup of an explicitly cancelled ORIGINAL upload-key operation.
//!
//! No successful publication predicate is relaxed. A known unsent private GO
//! or a fully authenticated, durable NEW may release memory after all original
//! cleanup; the persisted intent/key remains and generation is never rearmed.
use super::*;
use crate::saved_command_owner::UploadKeyCancelledNative;

#[derive(Default)]
pub(super) struct CancellationState {
    attempted: AtomicBool,
    failed: AtomicBool,
    disposition: Mutex<Option<CancelDisposition>>,
    retire_claimed: AtomicBool,
}

/// Captured only at the real full NEW/readback/private-fields/witness checks,
/// before the storage child returns. Descriptor/outcome DATA cannot create it.
pub(super) struct AuthenticatedNew {
    original: Weak<OriginalWork>,
    preparation: Weak<UploadKeyPreparation>,
    reference: StoredRef,
    certificate: [u8; 32],
}
impl AuthenticatedNew {
    pub(super) fn capture(held: &Holding, reference: StoredRef, certificate: [u8; 32]) -> Self {
        Self {
            original: held.owner.clone(),
            preparation: Arc::downgrade(&held.preparation),
            reference,
            certificate,
        }
    }
    fn matches(&self, held: &Holding, progress: &Progress) -> bool {
        Weak::ptr_eq(&self.original, &held.owner)
            && self
                .preparation
                .upgrade()
                .is_some_and(|same| Arc::ptr_eq(&same, &held.preparation))
            && readback_matches(self.reference, self.certificate, progress)
            && self.reference.identity == held.preparation.context().vault
            && self.reference.record == held.preparation.context().record
            && self.reference.revision.counter == 1
    }
}

fn readback_matches(reference: StoredRef, certificate: [u8; 32], progress: &Progress) -> bool {
    progress
        .saved
        .is_some_and(|saved| same_reference(saved, reference))
        && progress.certificate == Some(certificate)
        && progress.outcome == Some(known_new())
}

fn known_new() -> store::StorageOutcome {
    store::StorageOutcome {
        effect: store::Effect::KnownApplied,
        durability: store::Durability::Confirmed,
        cleanup: store::Cleanup::Known,
    }
}
#[derive(Clone, Copy)]
enum Kind {
    NoGo,
    DurableNew(StoredRef),
}
impl Kind {
    fn native_target(self) -> Option<(format::Identity, format::Id, format::Revision)> {
        match self {
            Self::NoGo => None,
            Self::DurableNew(reference) => {
                Some((reference.identity, reference.record, reference.revision))
            }
        }
    }
}

struct CancelDisposition {
    original: Weak<OriginalWork>,
    preparation: Arc<UploadKeyPreparation>,
    clock: Arc<UploadKeyClock>,
    native: UploadKeyCancelledNative,
    kind: Kind,
    journal_revision: u64,
}
impl CancelDisposition {
    fn retained_matches(&self, held: &Holding) -> bool {
        Arc::ptr_eq(&self.preparation, &held.preparation)
            && Arc::ptr_eq(&self.clock, &held.clock)
            && Weak::ptr_eq(&self.original, &held.owner)
            && held.progress.try_lock().is_ok_and(|progress| {
                let Some(reservation) = held.reservation.get() else {
                    return false;
                };
                self.journal_revision
                    == progress
                        .journal_revision
                        .unwrap_or(reservation.store_revision())
                    && match (self.kind, kind(held, &progress)) {
                        (Kind::NoGo, Some(Kind::NoGo)) => true,
                        (Kind::DurableNew(expected), Some(Kind::DurableNew(actual))) => {
                            same_reference(expected, actual)
                        }
                        _ => false,
                    }
            })
    }
}

/// The native child retains this exact one-use proof BEFORE clearing anything.
/// It is separate from UploadKeyDisposal and never authorizes Publish/Bind.
pub(crate) struct UploadKeyCancellationDisposal {
    disposition: CancelDisposition,
    consumed: bool,
}
impl UploadKeyCancellationDisposal {
    pub(crate) fn matches(
        &self,
        run: &UploadKeyRun,
        preparation: &Arc<UploadKeyPreparation>,
    ) -> bool {
        !self.consumed
            && Arc::ptr_eq(&self.disposition.preparation, preparation)
            && self.disposition.native.matches(run, preparation)
            && self.disposition.original.upgrade().is_some_and(|owner| {
                owner.vault.try_lock().is_ok_and(|work| {
                    cancellation_origin(&owner, &self.disposition.clock, work.first, Instant::now())
                        && all_joins(&owner, &work)
                        && store_closed(&work)
                })
            })
    }
    pub(crate) fn consume(
        &mut self,
        preparation: &Arc<UploadKeyPreparation>,
    ) -> Result<(), Reason> {
        let valid = !self.consumed && Arc::ptr_eq(&self.disposition.preparation, preparation);
        self.consumed = true;
        if valid {
            Ok(())
        } else {
            Err(Reason::CleanupUnknown)
        }
    }
    pub(crate) fn consumed_for(
        &self,
        parent: &OriginalWork,
        preparation: &Arc<UploadKeyPreparation>,
    ) -> bool {
        self.consumed
            && Arc::ptr_eq(&self.disposition.preparation, preparation)
            && self
                .disposition
                .original
                .upgrade()
                .is_some_and(|owner| std::ptr::eq(&*owner, parent))
            && parent
                .upload_key_clock
                .get()
                .is_some_and(|clock| Arc::ptr_eq(clock, &self.disposition.clock))
    }
}

pub(super) struct CancellationRetirement {
    proof: Option<UploadKeyCancellationDisposal>,
    failed: bool,
    stopped_write: Option<controls::recovery::StoppedWrite>,
}

// Caller already has Work when used by report/retirement. Never re-lock it.
fn cancellation_origin(
    owner: &OriginalWork,
    clock: &Arc<UploadKeyClock>,
    first: Option<(Reason, Instant)>,
    now: Instant,
) -> bool {
    owner.stopped()
        && matches!(first, Some((Reason::UserCancelled, _)))
        && owner
            .upload_key_clock
            .get()
            .is_some_and(|same| Arc::ptr_eq(same, clock))
        && clock.failed.load(Ordering::SeqCst)
        && !clock.completed.load(Ordering::SeqCst)
        && clock.failure_at().is_some()
        && clock.cleanup_cutoff().is_some_and(|end| now < end)
}
fn prior_joins_known(work: &super::super::super::Work) -> bool {
    matches!(work.original_join, None | Some(JoinReceipt::Returned))
        && work.failed_child_join.is_none()
}
fn all_joins(owner: &OriginalWork, work: &super::super::super::Work) -> bool {
    owner.control_resources_settled()
        && prior_joins_known(work)
        && owner
            .coordinator
            .try_lock()
            .is_ok_and(|book| book.handle.is_none() && book.receipt == JoinReceipt::Returned)
        && owner
            .child
            .try_lock()
            .is_ok_and(|book| book.handle.is_none() && book.receipt == JoinReceipt::Returned)
}
fn store_closed(work: &super::super::super::Work) -> bool {
    work.release
        && work.release_claimed
        && work.release_end.is_some()
        && work
            .store
            .as_ref()
            .is_some_and(|storage| storage.try_lock().is_ok_and(|book| book.settled()))
}
fn same_store(held: &Holding, work: &super::super::super::Work) -> bool {
    held.store.upgrade().is_some_and(|original| {
        work.store
            .as_ref()
            .is_some_and(|store| Arc::ptr_eq(store, &original))
    })
}

impl UploadKeyGoGate {
    /// Only immutable/try-borrowed metadata. Native pre-close callers already
    /// hold Resources/Registry; this must never acquire Doc, IO or native locks.
    pub(crate) fn cancelled_origin(&self, preparation: &Arc<UploadKeyPreparation>) -> bool {
        if !Arc::ptr_eq(&self.preparation, preparation) {
            return false;
        }
        self.owner.upgrade().is_some_and(|owner| {
            self.matches_original(&owner)
                && owner.vault.try_lock().is_ok_and(|work| {
                    cancellation_origin(&owner, &self.clock, work.first, Instant::now())
                })
        })
    }
    pub(crate) fn cancelled_no_go_origin(&self, preparation: &Arc<UploadKeyPreparation>) -> bool {
        self.cancelled_origin(preparation)
            && self.held.upgrade().is_some_and(|held| {
                held.reservation.get().is_some()
                    && held.progress.try_lock().is_ok_and(|progress| {
                        progress.outcome.is_none()
                            && progress.saved.is_none()
                            && progress.authenticated_new.is_none()
                            && progress.certificate.is_none()
                            && progress.journal_revision.is_none()
                    })
            })
    }
    pub(crate) fn cancelled_no_go_failure(
        &self,
        preparation: &Arc<UploadKeyPreparation>,
    ) -> Option<Instant> {
        if !self.cancelled_no_go_origin(preparation) {
            return None;
        }
        self.clock.failure_at()
    }
}

fn kind(held: &Holding, progress: &Progress) -> Option<Kind> {
    let run = held.run.get()?; // An absent/uncertain admission is NOT no-GO proof.
    if let Some(saved) = &progress.authenticated_new {
        if saved.matches(held, progress)
            && run.cancelled_saved_settled(
                saved.reference.identity,
                saved.reference.record,
                saved.reference.revision,
            )
        {
            return Some(Kind::DurableNew(saved.reference));
        }
        return None;
    }
    (progress.outcome.is_none()
        && progress.saved.is_none()
        && progress.certificate.is_none()
        && progress.journal_revision.is_none()
        && run.cancelled_no_go_settled())
    .then_some(Kind::NoGo)
}

fn report_child_known(
    kind: Kind,
    release_claimed: bool,
    outcome: Option<store::StorageOutcome>,
    receipt: JoinReceipt,
    has_handle: bool,
) -> bool {
    !has_handle
        && (receipt == JoinReceipt::Returned
            || receipt == JoinReceipt::New
                && matches!(kind, Kind::NoGo)
                && !release_claimed
                && outcome.is_none())
}

/// Report-only pending-cleanup distinction. It never clears existing Unknown,
/// returns Idle or grants disposal. Actual intent/readback proof follows only
/// after the original Release child and its real Store close.
pub(in crate::asset_session) fn report_recovery(work: &super::super::super::Work) -> bool {
    if !work.upload_key.recovery_required() {
        return false;
    }
    let Some(held) = &work.upload_key.inner else {
        return false;
    };
    let Some(owner) = held.owner.upgrade() else {
        return true;
    };
    let Some(kind) = held
        .progress
        .try_lock()
        .ok()
        .and_then(|progress| kind(held, &progress))
    else {
        return true;
    };
    let pending = !held.cancellation.failed.load(Ordering::SeqCst)
        && cancellation_origin(&owner, &held.clock, work.first, Instant::now())
        && prior_joins_known(work)
        && same_store(held, work)
        && owner
            .coordinator
            .try_lock()
            .is_ok_and(|book| book.receipt != JoinReceipt::Failed)
        && owner.child.try_lock().is_ok_and(|book| {
            // NoGO can return before any Asset store child. New is the
            // original not-started receipt, never a fabricated join; the
            // later Release and final disposal still require Returned.
            report_child_known(
                kind,
                work.release_claimed,
                work.outcome,
                book.receipt,
                book.handle.is_some(),
            )
        })
        && work.store.as_ref().is_some_and(|storage| {
            storage.try_lock().is_ok_and(|book| {
                matches!(book.problem(), None | Some(store::Problem::Interrupted))
                    && if work.release_claimed {
                        book.settled()
                    } else {
                        book.operation_quiescent()
                    }
            })
        });
    !pending
}

/// SAME coordinator, OFF Doc/Work/native locks, after its actual release child.
/// No replay, mutation, new producer, filesystem adoption or new clock occurs.
#[cfg(feature = "desktop-shell")]
pub(in crate::asset_session) fn prepare_after_release(
    document: &DocumentBinding,
    owner: &Arc<OriginalWork>,
) {
    #[cfg(all(
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64")
    ))]
    {
        let held = {
            let Ok(work) = owner.vault.try_lock() else {
                return;
            };
            let Some(held) = &work.upload_key.inner else {
                return;
            };
            if !matches!(work.first, Some((Reason::UserCancelled, _))) {
                return;
            }
            held.clone()
        };
        if held.cancellation.attempted.swap(true, Ordering::SeqCst) {
            return;
        }
        let admitted_cleanup = {
            let state = document.lock();
            !state.unknown
                && state.slot.as_ref().is_some_and(|slot| {
                    slot.operation == Operation::GenerateUploadKey
                        && Arc::ptr_eq(&slot.owner, owner)
                })
        }; // Only metadata; drop the original Doc guard before all state IO.
        let result = if admitted_cleanup {
            prepare(owner, &held)
        } else {
            Err(Reason::CleanupUnknown)
        };
        match result {
            Ok(proof) => match held.cancellation.disposition.try_lock() {
                Ok(mut slot) if slot.is_none() => *slot = Some(proof),
                _ => {
                    held.cancellation.failed.store(true, Ordering::SeqCst);
                }
            },
            Err(_) => {
                held.cancellation.failed.store(true, Ordering::SeqCst);
            }
        }
        // A failed check becomes genuinely Unknown; never undo the original
        // UserCancelled explanation or its first cleanup timestamp.
        report(document, owner);
    }
    #[cfg(not(all(
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64")
    )))]
    {
        let _ = (document, owner);
    }
}

#[cfg(all(
    feature = "desktop-shell",
    target_os = "macos",
    target_pointer_width = "64",
    any(target_arch = "aarch64", target_arch = "x86_64")
))]
fn prepare(owner: &Arc<OriginalWork>, held: &Arc<Holding>) -> Result<CancelDisposition, Reason> {
    {
        let work = owner.vault.try_lock().map_err(|_| Reason::CleanupUnknown)?;
        if !cancellation_origin(owner, &held.clock, work.first, Instant::now())
            || !prior_joins_known(&work)
            || !store_closed(&work)
            || !same_store(held, &work)
            || !owner
                .child
                .try_lock()
                .is_ok_and(|book| book.handle.is_none() && book.receipt == JoinReceipt::Returned)
        {
            return Err(Reason::CleanupUnknown);
        }
    }
    let (kind, journal_revision, certificate) = {
        let progress = held
            .progress
            .try_lock()
            .map_err(|_| Reason::CleanupUnknown)?;
        (
            kind(held, &progress).ok_or(Reason::CleanupUnknown)?,
            progress.journal_revision,
            progress.certificate,
        )
    };
    let run = held.run.get().ok_or(Reason::CleanupUnknown)?;
    let native = run
        .cancelled_original(owner, kind.native_target())
        .map_err(|_| Reason::CleanupUnknown)?;
    let lease = held.native_use.get().ok_or(Reason::CleanupUnknown)?;
    if held.native_use_retired.load(Ordering::SeqCst) {
        return Err(Reason::CleanupUnknown);
    }
    lease
        .store()
        .check_native_use(lease.native_use())
        .map_err(|_| Reason::CleanupUnknown)?;
    let reservation = held.reservation.get().ok_or(Reason::CleanupUnknown)?;
    let revision = match (kind, journal_revision) {
        (_, None) => {
            reservation
                .current(held.service.state_directory())
                .map_err(|_| Reason::CleanupUnknown)?;
            reservation.store_revision()
        }
        (Kind::DurableNew(reference), Some(revision))
            if Some(revision) == reservation.store_revision().checked_add(1) =>
        {
            let current = persistence::observe(
                held.service.state_directory(),
                &held.observed.project,
                Role::AndroidUpload,
            )
            .map_err(|_| Reason::CleanupUnknown)?;
            let expected = SavedAssignment {
                reference: KeyReference::native(
                    reference.identity,
                    reference.record,
                    reference.revision,
                ),
                identity_sha256: held.observed.identity.clone(),
                certificate_sha256: Some(crate::service_protocol::hex(
                    &certificate.ok_or(Reason::CleanupUnknown)?,
                )),
                operation_id: reservation.operation_id().to_owned(),
            };
            if current.store_revision != revision
                || current.preference != Some(setup::Preference::RecordSaved(expected))
            {
                return Err(Reason::CleanupUnknown);
            }
            revision
        }
        _ => return Err(Reason::CleanupUnknown),
    };
    // These real Store reads may block. Recheck the ORIGINAL cleanup endpoint
    // after return; a late response never supplies a fresh cleanup interval.
    if !owner.vault.try_lock().is_ok_and(|work| {
        cancellation_origin(owner, &held.clock, work.first, Instant::now()) && store_closed(&work)
    }) {
        return Err(Reason::CleanupUnknown);
    }
    Ok(CancelDisposition {
        original: held.owner.clone(),
        preparation: held.preparation.clone(),
        clock: held.clock.clone(),
        native,
        kind,
        journal_revision: revision,
    })
}

pub(in crate::asset_session) fn retirement_ready(state: &DocumentState, slot: &Slot) -> bool {
    if state.unknown
        || slot.operation != Operation::GenerateUploadKey
        || slot.reason != Reason::UserCancelled
        || !slot.owner.retired.load(Ordering::SeqCst)
    {
        return false;
    }
    let Ok(work) = slot.owner.vault.try_lock() else {
        return false;
    };
    let Some(held) = &work.upload_key.inner else {
        return false;
    };
    cancellation_origin(&slot.owner, &held.clock, work.first, Instant::now())
        && all_joins(&slot.owner, &work)
        && store_closed(&work)
        && same_store(held, &work)
        && Arc::strong_count(held) == 1
        && !held.cancellation.failed.load(Ordering::SeqCst)
        && held.cancellation.disposition.try_lock().is_ok_and(|proof| {
            proof.as_ref().is_some_and(|proof| {
                proof.retained_matches(held)
                    && proof
                        .original
                        .upgrade()
                        .is_some_and(|original| Arc::ptr_eq(&original, &slot.owner))
                    && held
                        .run
                        .get()
                        .is_some_and(|run| proof.native.matches(run, &held.preparation))
            })
        })
}

impl Work {
    pub(in crate::asset_session) fn take_cancelled_retirement(&mut self) -> Self {
        let Some(held) = &self.inner else {
            return Self::default();
        };
        if self.disposal.is_some()
            || self.cancelled.is_some()
            || held.cancellation.failed.load(Ordering::SeqCst)
        {
            return Self::default();
        }
        let proof = {
            let Ok(mut proof) = held.cancellation.disposition.try_lock() else {
                return Self::default();
            };
            let Some(disposition) = proof.take() else {
                return Self::default();
            };
            UploadKeyCancellationDisposal {
                disposition,
                consumed: false,
            }
        };
        let stopped_write = matches!(proof.disposition.kind, Kind::NoGo).then(controls::recovery::StoppedWrite::default);
        Self {
            inner: self.inner.take(),
            disposal: None,
            cancelled: Some(CancellationRetirement {
                proof: Some(proof),
                failed: false,
                stopped_write,
            }),
        }
    }

    pub(super) fn dispose_cancelled(&mut self) -> bool {
        let Some(held) = &self.inner else {
            return false;
        };
        let Some(retirement) = self.cancelled.as_mut() else {
            return false;
        };
        if retirement.failed {
            return false;
        }
        let result = dispose(held, retirement);
        if !result {
            retirement.failed = true;
            return false;
        }
#[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "macos-installed-observation", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer"), target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
        observation::cancelled_disposed(held, retirement.stopped_write.as_ref().and_then(controls::recovery::StoppedWrite::installed_revision));
        let clock = held.clock.clone();
        self.inner = None; // Actual private Fields/retained native run dropped, not scheduled.
        self.cancelled = None;
        clock.completed.store(true, Ordering::SeqCst); // First reason/F/failed remain unchanged.
        true
    }
}

fn dispose(held: &Holding, retirement: &mut CancellationRetirement) -> bool {
    #[cfg(not(all(
        feature = "desktop-shell",
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64")
    )))]
    {
        let _ = (held, retirement);
        false
    }
    #[cfg(all(
        feature = "desktop-shell",
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64")
    ))]
    {
        let Some(owner) = held.owner.upgrade() else {
            return false;
        };
        let Some(run) = held.run.get() else {
            return false;
        };
        if !owner.vault.try_lock().is_ok_and(|work| {
            cancellation_origin(&owner, &held.clock, work.first, Instant::now())
                && all_joins(&owner, &work)
                && store_closed(&work)
                && same_store(held, &work)
        }) {
            return false;
        }
        if !run.cancelled_private_disposed(&owner, &held.preparation) {
            let Some(proof) = retirement.proof.take() else {
                return false;
            };
            if run.dispose_cancelled(proof).is_err() {
                return false;
            }
        }
        if !run.cancelled_private_disposed(&owner, &held.preparation) {
            return false;
        }
        if let Some(write) = &mut retirement.stopped_write {
            if !controls::recovery::persist_stopped(held, write) { return false; }
        }
        retire_use_cancelled(held, &owner)
    }
}

#[cfg(all(feature="desktop-shell", target_os="macos", target_pointer_width="64", any(target_arch="aarch64",target_arch="x86_64")))]
pub(super) fn disposed_cleanup_window(held: &Holding) -> Option<Instant> {
    let owner=held.owner.upgrade()?;
    if held.native_use_retired.load(Ordering::SeqCst)
        || !held.run.get()?.cancelled_private_disposed(&owner,&held.preparation)
        || !owner.vault.try_lock().is_ok_and(|work| cancellation_origin(&owner,&held.clock,work.first,Instant::now())
            && all_joins(&owner,&work) && store_closed(&work) && same_store(held,&work)) { return None; }
    held.clock.cleanup_cutoff()
}

#[cfg(all(
    feature = "desktop-shell",
    target_os = "macos",
    target_pointer_width = "64",
    any(target_arch = "aarch64", target_arch = "x86_64")
))]
fn retire_use_cancelled(held: &Holding, owner: &OriginalWork) -> bool {
    // Positive controls::retire_use correctly refuses cancellation. This is a
    // different cleanup-only callsite AFTER this original's actual disposal.
    if !owner
        .vault
        .try_lock()
        .is_ok_and(|work| cancellation_origin(owner, &held.clock, work.first, Instant::now()))
    {
        return false;
    }
    if !held.native_use_retired.load(Ordering::SeqCst) {
        if held
            .cancellation
            .retire_claimed
            .swap(true, Ordering::SeqCst)
        {
            return false;
        }
        let Some(lease) = held.native_use.get() else {
            return false;
        };
        if lease.store().retire_native_use(lease.native_use()).is_err() {
            return false;
        }
        held.native_use_retired.store(true, Ordering::SeqCst); // Preserve real return even if late.
    }
    owner.vault.try_lock().is_ok_and(|work| {
        cancellation_origin(owner, &held.clock, work.first, Instant::now())
            && all_joins(owner, &work)
            && store_closed(&work)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn original() -> (Arc<OriginalWork>, Arc<UploadKeyClock>, Instant) {
        let owner = OriginalWork::new(1, false, Weak::new());
        let now = Instant::now();
        let clock = Arc::new(UploadKeyClock::new(now));
        assert!(owner.upload_key_clock.set(clock.clone()).is_ok());
        owner.signal_stop();
        clock.observe_failure(now);
        (owner, clock, now)
    }
    #[test]
    fn cancelled_origin_uses_same_original_and_cleanup_not_success_window() {
        let (owner, clock, now) = original();
        assert!(cancellation_origin(
            &owner,
            &clock,
            Some((Reason::UserCancelled, now)),
            now
        ));
        assert!(!cancellation_origin(
            &owner,
            &clock,
            Some((Reason::Deadline, now)),
            now
        ));
        assert!(!cancellation_origin(&owner, &clock, None, now));
        let replacement = Arc::new(UploadKeyClock::new(now));
        replacement.observe_failure(now);
        assert!(!cancellation_origin(
            &owner,
            &replacement,
            Some((Reason::UserCancelled, now)),
            now
        ));
        assert!(!clock.completed.load(Ordering::SeqCst));
    }
    #[test]
    fn late_native_use_return_cannot_complete_or_renew_cancelled_clock() {
        let (owner, clock, now) = original();
        let first = Some((Reason::UserCancelled, now));
        let end = clock.cleanup_cutoff().unwrap();
        let actual_retired_token = AtomicBool::new(true); // DATA about an already returned cleanup, not a receipt factory.
        assert!(!cancellation_origin(&owner, &clock, first, end));
        assert!(actual_retired_token.load(Ordering::SeqCst));
        assert!(!clock.completed.load(Ordering::SeqCst));
        assert_eq!(clock.failure_at(), Some(now));
        assert_eq!(clock.endpoint(), Some(clock.work_end()));
    }
    #[test]
    fn earlier_original_failure_contracts_cancelled_cleanup() {
        let (owner, clock, now) = original();
        clock.observe_native_cleanup(
            Some(now - Duration::from_secs(2)),
            now + Duration::from_secs(8),
        );
        assert!(!cancellation_origin(
            &owner,
            &clock,
            Some((Reason::UserCancelled, now)),
            now + Duration::from_secs(8)
        ));
        assert_eq!(clock.failure_at(), Some(now - Duration::from_secs(2)));
    }
    #[test]
    fn cancelled_current_join_cannot_rehabilitate_prior_failed_original() {
        let mut work = super::super::super::super::Work::default();
        assert!(prior_joins_known(&work));
        work.original_join = Some(JoinReceipt::Returned);
        assert!(prior_joins_known(&work));
        work.original_join = Some(JoinReceipt::Failed);
        assert!(!prior_joins_known(&work));
        work.original_join = None;
        work.failed_child_join = Some(JoinReceipt::Failed);
        assert!(!prior_joins_known(&work));
    }
    #[test]
    fn inert_original_and_empty_store_never_grant_cancelled_disposal() {
        let (owner, _, _) = original();
        let work = owner.vault.try_lock().unwrap();
        assert!(!all_joins(&owner, &work));
        assert!(!store_closed(&work));
        let mut empty = Work::default();
        assert!(!empty.dispose_cancelled());
        assert!(empty.take_cancelled_retirement().empty());
    }
    #[test]
    fn cancelled_native_use_claim_is_one_attempt_even_without_a_return() {
        let state = CancellationState::default();
        assert!(!state.retire_claimed.swap(true, Ordering::SeqCst));
        assert!(state.retire_claimed.swap(true, Ordering::SeqCst));
        assert!(state.disposition.try_lock().unwrap().is_none());
    }
    #[test]
    fn only_no_go_before_release_can_report_a_not_started_store_child() {
        assert!(report_child_known(
            Kind::NoGo,
            false,
            None,
            JoinReceipt::New,
            false,
        ));
        let saved = Kind::DurableNew(reference());
        for (kind, claimed, outcome) in [
            (Kind::NoGo, true, None),
            (Kind::NoGo, false, Some(known_new())),
            (saved, false, None),
            (saved, true, Some(known_new())),
        ] {
            assert!(!report_child_known(
                kind,
                claimed,
                outcome,
                JoinReceipt::New,
                false,
            ));
        }
        for kind in [Kind::NoGo, saved] {
            assert!(report_child_known(
                kind,
                true,
                Some(known_new()),
                JoinReceipt::Returned,
                false,
            ));
            for receipt in [JoinReceipt::Pending, JoinReceipt::Failed] {
                assert!(!report_child_known(kind, false, None, receipt, false));
            }
            for receipt in [JoinReceipt::New, JoinReceipt::Returned] {
                assert!(!report_child_known(kind, false, None, receipt, true));
            }
        }
        // This predicate is used only by report, never all_joins/disposal.
    }
    fn reference() -> StoredRef {
        let id = |byte| format::Id::from_bytes([byte; 16]).unwrap();
        let identity = format::Identity::new(id(1), id(2)).unwrap();
        let record = id(3);
        let revision = format::Revision::new(id(4), 1).unwrap();
        StoredRef {
            identity,
            record,
            revision,
            original: store::ReadWitness::lifecycle_data(record, revision),
        }
    }
    #[test]
    fn cleanup_requires_full_saved_reference_not_counter_or_fingerprint_alone() {
        let reference = reference();
        let certificate = [5; 32];
        let mut progress = Progress::new();
        progress.saved = Some(reference);
        progress.certificate = Some(certificate);
        progress.outcome = Some(known_new());
        assert!(readback_matches(reference, certificate, &progress));
        let mut alias = reference;
        alias.revision =
            format::Revision::new(format::Id::from_bytes([6; 16]).unwrap(), 1).unwrap();
        assert!(!readback_matches(alias, certificate, &progress));
        progress.certificate = None;
        assert!(!readback_matches(reference, certificate, &progress));
        // This comparison helper still cannot create the separate actual
        // AuthenticatedNew or native finality proof.
        assert!(progress.authenticated_new.is_none());
    }
    #[test]
    fn unknown_write_or_readback_cannot_become_a_durable_new_cleanup() {
        let reference = reference();
        let certificate = [5; 32];
        let mut progress = Progress::new();
        progress.saved = Some(reference);
        progress.certificate = Some(certificate);
        assert!(!readback_matches(reference, certificate, &progress));
        progress.outcome = Some(store::StorageOutcome {
            effect: store::Effect::KnownApplied,
            durability: store::Durability::Unknown,
            cleanup: store::Cleanup::Known,
        });
        assert!(!readback_matches(reference, certificate, &progress));
        progress.outcome = Some(known_new());
        progress.saved = None;
        assert!(!readback_matches(reference, certificate, &progress));
    }
}
