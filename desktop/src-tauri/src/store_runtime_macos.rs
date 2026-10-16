//! A Store dependency loan over the existing installed Book/slot lifecycle.
//! No process, credential, release confirmation or Store authority is created.
use super::*;
use crate::macos_store_runtime as layout;

const ORIGINALS: [&str; 6] = ["store", layout::RUBY, layout::BUNDLE, layout::BUNDLE_ENTRY, layout::CA, layout::TOOLING];
pub(super) fn retained(path: &str) -> bool {
    ORIGINALS.iter().any(|selected| *selected == path || selected.strip_prefix(path).is_some_and(|tail| tail.starts_with('/')))
}
pub(super) struct Originals {
    indices: [Option<usize>; ORIGINALS.len()],
    end: Instant,
    stop: watch::Receiver<bool>,
}
impl Originals {
    fn new(end: Instant, stop: watch::Receiver<bool>) -> Self { Self { indices:[None; ORIGINALS.len()], end, stop } }
    pub(super) fn observed(&mut self, path: &str, index: usize) -> Result<()> {
        if let Some(slot) = ORIGINALS.iter().position(|name| *name == path) {
            if self.indices[slot].replace(index).is_some() { return Err(AdmissionFailure::Inventory); }
        }
        Ok(())
    }
    pub(super) fn complete(&self) -> bool { self.indices.iter().all(Option::is_some) }
    fn check(&self, book: &Book) -> Result<()> {
        book.point(self.end, &self.stop)?;
        if !self.complete() || !book.inspected || !book.prepared || !book.admission_custody_ready() {
            return Err(AdmissionFailure::AlreadyUsed);
        }
        for index in self.indices {
            let index = index.ok_or(AdmissionFailure::Inventory)?;
            if book.records.get(index).is_none_or(|record| record.state != State::Owned || record.fd.is_none()) {
                return Err(AdmissionFailure::Unknown);
            }
        }
        // Includes the held Python/core, installation ancestry and every Store
        // ancestor. Closed sibling files remain under this root-protected tree.
        for (index, record) in book.records.iter().enumerate() {
            if record.state == State::Owned { book.check_name(index, self.end, &self.stop)?; }
        }
        book.point(self.end, &self.stop)
    }
}

/// The contained passive slots are private: they cannot be extracted as a
/// cross-domain capability. Their original inspection/transfer/cleanup is reused.
pub(crate) struct StoreRuntimeSlots { inner: PassiveRuntimeSlots }
impl StoreRuntimeSlots {
    pub(crate) fn new() -> Self { Self { inner: PassiveRuntimeSlots::new() } }
    pub(crate) fn never_started(&self) -> bool {
        self.inner.never_started() && self.inner.inspection.as_ref().is_some_and(|book| book.store.is_none())
    }
    pub(crate) fn arm_acl_once(&mut self, end: Instant, stop: &watch::Receiver<bool>) -> Result<()> {
        if !self.never_started() { return Err(AdmissionFailure::AlreadyUsed); }
        self.inner.inspection.as_mut().ok_or(AdmissionFailure::Unknown)?.store = Some(Originals::new(end, stop.clone()));
        self.inner.arm_acl_once(end, stop)
    }
    pub(crate) fn inspect_once(&mut self, profile: runtime::PassiveInstalledProfile) -> std::result::Result<VerifiedRuntime, BridgeError> {
        let originals = self.inner.inspection.as_ref().and_then(|book| book.store.as_ref()).ok_or_else(BridgeError::cleanup_unknown)?;
        let (end, stop) = (originals.end, originals.stop.clone());
        self.inner.inspect_once(profile, end, &stop)
    }
    pub(crate) fn transfer_once(&mut self) -> Result<()> { self.inner.transfer_once() }
    pub(crate) fn retained_bytes(&self) -> Option<usize> { self.inner.retained_bytes() }
    pub(crate) fn retained_original_count(&self) -> Option<usize> { self.inner.retained_original_count() }
    pub(crate) fn first_failure(&self) -> Option<(AdmissionFailure, Instant)> { self.inner.first_failure() }
    pub(crate) fn no_child_effect(&self) -> bool { self.inner.no_child_effect() }
    pub(crate) fn mark_interrupted(&mut self) { self.inner.mark_interrupted(); }
    pub(crate) fn settle_originals(&mut self, expired: &mut dyn FnMut(Option<(AdmissionFailure, Instant)>) -> bool) -> CloseOutcome {
        self.inner.settle_originals(expired)
    }
    pub(crate) fn settled(&self) -> bool { self.inner.settled() }
    pub(crate) fn prepare_loan(&mut self, publish: &mut dyn FnMut(Option<(AdmissionFailure, Instant)>)) -> Result<StoreRuntimeLoan<'_>> {
        let capability = self.inner.capability()?;
        let original = capability.original.store.as_ref().ok_or(AdmissionFailure::Inventory)?;
        let (end, stop) = (original.end, original.stop.clone());
        capability.prepare_once_observed(end, &stop, publish)?;
        let result = capability.original.store.as_ref().ok_or(AdmissionFailure::Inventory)?.check(&capability.original)
            .and_then(|_| capability.claim_once());
        if let Err(failure) = result { capability.original.note_acl(failure, Instant::now()); }
        publish(capability.original.first_failure());
        result?;
        Ok(StoreRuntimeLoan { capability })
    }
}

/// Borrowed only after real original inspection, prepare and one-use claim.
/// Its borrow prevents consuming slot settlement while a caller uses these
/// fixed paths. A caller still owns its actual child/journal/credential policy.
pub(crate) struct StoreRuntimeLoan<'a> { capability: &'a mut PassiveInstalledRuntime }
impl StoreRuntimeLoan<'_> {
    pub(crate) fn check_before_or_after_use(&self) -> Result<()> {
        let result = self.capability.original.store.as_ref().ok_or(AdmissionFailure::Inventory)?
            .check(&self.capability.original);
        if let Err(failure) = result { self.capability.original.note_acl(failure, Instant::now()); }
        result
    }
    pub(crate) fn ruby(&self) -> PathBuf { self.capability.selection.cwd.join(layout::RUBY) }
    pub(crate) fn bundle_entry(&self) -> PathBuf { self.capability.selection.cwd.join(layout::BUNDLE_ENTRY) }
    pub(crate) fn tooling(&self) -> PathBuf { self.capability.selection.cwd.join(layout::TOOLING) }
    pub(crate) fn ca(&self) -> PathBuf { self.capability.selection.cwd.join(layout::CA) }
    pub(crate) fn python_runtime(&self) -> &VerifiedRuntime { &self.capability.selection }
    pub(crate) fn record_closed_spawn_gate(&mut self) { self.capability.record_closed_spawn_gate(); }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn store_slots_do_not_lend_uninspected_or_settled_sources() {
        let mut slots = StoreRuntimeSlots::new();
        assert!(slots.never_started() && slots.no_child_effect());
        assert!(slots.prepare_loan(&mut |_| {}).is_err());
        assert!(slots.transfer_once().is_err());
        assert_eq!(slots.settle_originals(&mut |_| false), CloseOutcome::Settled);
        assert!(slots.settled() && !slots.never_started());
        assert!(slots.prepare_loan(&mut |_| {}).is_err());
        assert_eq!(slots.settle_originals(&mut |_| false), CloseOutcome::Unknown);
        assert!(retained("store") && retained("store/bin") && retained(layout::RUBY));
        assert!(!retained("store2") && !retained("store/bin/gem") && !retained("store/lib/other"));
        let (_sender, stop) = watch::channel(false);
        let mut original = Originals::new(Instant::now(), stop);
        assert!(!original.complete());
        assert!(original.check(&Book::new()).is_err()); // No native allocation/open.
        for (index, path) in ORIGINALS.iter().enumerate() { original.observed(path, index).unwrap(); }
        assert!(original.complete());
        assert!(original.observed(layout::RUBY, 99).is_err());
        assert!(original.check(&Book::new()).is_err()); // IDs cannot fabricate originals.
    }
}
