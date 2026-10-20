//! Selected-folder provenance for missing-only acquisition. The SourceSlots
//! original reads/closes on the existing saved inspection worker, not in Doc.
use super::*;

// Current Known, one prepared intent, and the already-bounded retained-session
// walk. This is an inline reference census, not additional owner capacity.
const PICKER_REFERENCES: usize = 3 * (MAX_RETAINED_SESSIONS + 2);
pub(super) struct PickerOriginals {
    entries: [Option<Arc<crate::asset_session::OriginalWork>>; PICKER_REFERENCES],
    used: usize,
}
impl PickerOriginals {
    pub(super) fn new() -> Self {
        Self {
            entries: std::array::from_fn(|_| None),
            used: 0,
        }
    }
    pub(super) fn record(
        &mut self,
        originals: &[Option<Arc<crate::asset_session::OriginalWork>>; 3],
    ) -> Option<()> {
        for original in originals.iter().flatten() {
            if self.iter().any(|old| Arc::ptr_eq(old, original)) {
                continue;
            }
            if self.used == self.entries.len() {
                return None;
            }
            self.entries[self.used] = Some(original.clone());
            self.used += 1;
        }
        Some(())
    }
    pub(super) fn iter(&self) -> impl Iterator<Item = &Arc<crate::asset_session::OriginalWork>> {
        self.entries[..self.used].iter().flatten()
    }
}

pub(super) fn future_bytes(known: &Known) -> Option<usize> {
    if known.catalog.empty().is_none() {
        return Some(FUTURE_PUBLIC_BYTES);
    }
    #[cfg(all(
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64"),
        not(feature = "macos-android-registration-helper")
    ))]
    {
        let profile = wire::Profile::current()?.android();
        let source =
            crate::installed_runtime::AndroidRegistrationSourceSlots::acquisition_reservation(
                profile,
            )?;
        // Previous inspected books remain charged in T. New source workspace
        // exists only BEFORE the later manifest/CA/cache/child phase; every
        // source record/close/metadata byte remains held and charged throughout.
        let future = FUTURE_PUBLIC_BYTES.checked_add(source.acquisition_retained_bytes()?)?;
        (source.bytes() <= future && future <= PUBLIC_WORK_LIMIT).then_some(future)
    }
    #[cfg(not(all(
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64"),
        not(feature = "macos-android-registration-helper")
    )))]
    None
}

// Classification only; the SAME original failure timestamp and unknown latch
// stay with Session. Cleanup's generic normalization cannot replace first F.
#[cfg(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),
    not(feature = "macos-android-registration-helper")))]
fn source_failure_reason(failure: AdmissionFailure) -> Option<wire::Reason> {
    match failure {
        AdmissionFailure::Inventory => Some(wire::Reason::ExistingToolsIncompatible),
        AdmissionFailure::Ownership | AdmissionFailure::Native => Some(wire::Reason::ExistingToolsUnreadable),
        AdmissionFailure::Identity => Some(wire::Reason::Stale),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),
        not(feature = "macos-android-registration-helper")))]
    #[test]
    fn source_diagnostic_keeps_original_first_failure_through_generic_cleanup_normalization() {
        for (failure, reason) in [(AdmissionFailure::Inventory, wire::Reason::ExistingToolsIncompatible),
            (AdmissionFailure::Ownership, wire::Reason::ExistingToolsUnreadable), (AdmissionFailure::Native, wire::Reason::ExistingToolsUnreadable),
            (AdmissionFailure::Identity, wire::Reason::Stale)] {
            assert_eq!(source_failure_reason(failure), Some(reason));
            let context = wire::prepare(&json!({"projectId":"inert-source","draftRevision":0,"baselineGeneration":1,
                "savedConfig":{"bytes":2,"sha256":"a".repeat(64)},"action":"inspect","review":null})).unwrap();
            let application = SavedCommandOwner::tool_acquisition(RuntimeConfig::packaged("/unopened-source-diagnostic".into()));
            let (_application, owner) = crate::saved_command_owner::tests::active_with_context(application, Context::ToolAcquisition(context));
            let at = owner.clocks.admitted;
            owner.observe_failure_at(Reason::from_tools(reason), at, false);
            owner.publish_native_failure(Some((failure, at)));
            assert_eq!(*owner.native_failure.lock().unwrap(), Some((Reason::from_tools(reason), at)));
            assert!(*owner.stop.borrow());
            assert!(!original_joined(&owner)); // Inert owner: no finality or native source was supplied.
        }
        for failure in [AdmissionFailure::Stopped, AdmissionFailure::Deadline, AdmissionFailure::Unknown] {
            assert_eq!(source_failure_reason(failure), None);
        }
    }
    #[test]
    fn picker_census_keeps_current_and_replaced_originals_and_deduplicates_shared_arcs() {
        // Existing genuinely unentered originals. No selected/closed/receipt
        // bit is supplied; the later Document owner traversal must refuse them.
        let old = crate::asset_session::OriginalWork::artifact_unentered_original_data();
        let shared = crate::asset_session::OriginalWork::artifact_unentered_original_data();
        let replacement = crate::asset_session::OriginalWork::artifact_unentered_original_data();
        let old_weak = Arc::downgrade(&old);
        let mut census = PickerOriginals::new();
        let before = [Some(old), Some(shared.clone()), None];
        let current = [Some(replacement.clone()), Some(shared.clone()), None];
        census.record(&current).unwrap();
        census.record(&before).unwrap();
        census.record(&current).unwrap();
        assert_eq!(census.iter().count(), 3);
        assert!(census
            .iter()
            .any(|original| Arc::ptr_eq(original, &replacement)));
        assert_eq!(
            census
                .iter()
                .filter(|original| Arc::ptr_eq(original, &shared))
                .count(),
            1
        );
        drop(before);
        let old = old_weak.upgrade().unwrap();
        assert!(census.iter().any(|original| Arc::ptr_eq(original, &old)));
        assert!(census
            .iter()
            .all(|original| !original.android_source_selected_settled()));
        let mut full = PickerOriginals::new();
        full.used = full.entries.len(); // Capacity DATA only, no native result.
        assert!(full.record(&[Some(old), None, None]).is_none());
    }
}

#[cfg(all(
    target_os = "macos",
    target_pointer_width = "64",
    any(target_arch = "aarch64", target_arch = "x86_64"),
    not(feature = "macos-android-registration-helper")
))]
#[derive(Clone)]
pub(crate) struct SourceGate {
    inner: Weak<Inner>,
    owner: Weak<Session>,
}

#[cfg(all(
    target_os = "macos",
    target_pointer_width = "64",
    any(target_arch = "aarch64", target_arch = "x86_64"),
    not(feature = "macos-android-registration-helper")
))]
impl SourceGate {
    pub(super) fn new(inner: &Arc<Inner>, owner: &Arc<Session>) -> Self {
        Self {
            inner: Arc::downgrade(inner),
            owner: Arc::downgrade(owner),
        }
    }
    pub(crate) fn source_work(&self) -> Result<(), AdmissionFailure> {
        let owner = self.owner.upgrade().ok_or(AdmissionFailure::Unknown)?;
        let inner = self.inner.upgrade().ok_or(AdmissionFailure::Unknown)?;
        if owner.resource_unknown.load(Ordering::SeqCst) {
            return Err(AdmissionFailure::Unknown);
        }
        if let Some((failure, _)) = self.source_first() {
            return Err(failure);
        }
        if Instant::now() >= owner.clocks.work {
            return Err(AdmissionFailure::Deadline);
        }
        if *owner.stop.borrow() {
            return Err(AdmissionFailure::Stopped);
        }
        if !native::context_current(&inner, &owner) {
            return Err(AdmissionFailure::Identity);
        }
        Ok(())
    }
    pub(crate) fn source_first(&self) -> Option<(AdmissionFailure, Instant)> {
        let owner = self.owner.upgrade()?;
        let first = match owner.native_failure.try_lock() {
            Ok(first) => first.map(|(reason, at)| {
                (
                    match reason {
                        Reason::TimedOut => AdmissionFailure::Deadline,
                        Reason::CleanupUnknown => AdmissionFailure::Unknown,
                        _ => AdmissionFailure::Stopped,
                    },
                    at,
                )
            }),
            Err(_) => Some((AdmissionFailure::Unknown, owner.clocks.admitted)),
        };
        first
    }
    pub(crate) fn source_note(&self, failure: AdmissionFailure, at: Instant) {
        if let Some(owner) = self.owner.upgrade() {
            // Preserve this SAME original source failure/F before generic
            // cleanup normalizes it. A denied/wrong tree is never "missing".
            let reason = source_failure_reason(failure);
            if let Some(reason) = reason { owner.observe_failure_at(Reason::from_tools(reason), at, false); }
            owner.publish_native_failure(Some((failure, at)));
        }
    }
    pub(crate) fn source_cleanup_expired(
        &self,
        first: Option<(AdmissionFailure, Instant)>,
    ) -> bool {
        // Normal input shutdown sets STOP even on success. Cleanup uses the
        // SAME original first-failure endpoint, not STOP as closure authority.
        self.owner
            .upgrade()
            .is_none_or(|owner| owner.native_cleanup_expired(first))
    }
}
