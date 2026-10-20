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
    fn check(&self,book:&Book)->Result<()>{self.check_with(book,&mut ||book.point(self.end,&self.stop))}
    fn check_for_settlement(&self,book:&Book,expired:&mut dyn FnMut(Option<(AdmissionFailure,Instant)>)->bool)->Result<()>{
        self.check_with(book,&mut ||settlement_point(book,expired))
    }
    fn check_with(&self, book: &Book, point:&mut dyn FnMut()->Result<()>) -> Result<()> {
        point()?;
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
            if record.state == State::Owned { book.check_name_with(index, point)?; }
        }
        point()
    }
}

// Cleanup uses the same Session's earlier F+10/H latch, not the work STOP
// flag (which is also set after an ordinary successful terminal).
fn settlement_point(book:&Book,expired:&mut dyn FnMut(Option<(AdmissionFailure,Instant)>)->bool)->Result<()> {
    if expired(book.first_failure()) { Err(AdmissionFailure::Deadline) } else { Ok(()) }
}

/// The contained passive slots are private: they cannot be extracted as a
/// cross-domain capability. Their original inspection/transfer/cleanup is reused.
pub(crate) struct StoreRuntimeSlots { inner: PassiveRuntimeSlots, post_claimed: bool }
impl StoreRuntimeSlots {
    pub(crate) fn new() -> Self { Self { inner: PassiveRuntimeSlots::new(), post_claimed: false } }
    pub(crate) fn never_started(&self) -> bool {
        !self.post_claimed && self.inner.never_started() && self.inner.inspection.as_ref().is_some_and(|book| book.store.is_none())
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
    pub(crate) fn inspect_apple_provisioning_once(&mut self,profile:runtime::AppleProvisioningInstalledProfile)->std::result::Result<VerifiedRuntime,BridgeError>{self.inspect_selected(profile.selection()?)}
    pub(crate) fn inspect_preflight_once(&mut self,profile:runtime::LocalStorePreflightInstalledProfile)->std::result::Result<VerifiedRuntime,BridgeError>{self.inspect_selected(profile.selection()?)}
    pub(crate) fn inspect_prepare_once(&mut self,profile:runtime::LocalStorePrepareInstalledProfile)->std::result::Result<VerifiedRuntime,BridgeError>{self.inspect_selected(profile.selection()?)}
    pub(crate) fn inspect_reconcile_once(&mut self,profile:runtime::LocalStoreReconcileInstalledProfile)->std::result::Result<VerifiedRuntime,BridgeError>{self.inspect_selected(profile.selection()?)}
    pub(crate) fn inspect_execute_once(&mut self,profile:runtime::LocalStoreExecuteInstalledProfile)->std::result::Result<VerifiedRuntime,BridgeError>{self.inspect_selected(profile.selection()?)}
    fn inspect_selected(&mut self,selected:VerifiedRuntime)->std::result::Result<VerifiedRuntime,BridgeError>{
        if self.inner.settlement || self.inner.selection.is_some() || self.inner.acquisition.is_some()
            || !self.inner.inspection.as_ref().is_some_and(Book::inspection_ready) { return Err(BridgeError::cleanup_unknown()); }
        let originals = self.inner.inspection.as_ref().and_then(|book| book.store.as_ref()).ok_or_else(BridgeError::cleanup_unknown)?;
        let (end, stop) = (originals.end, originals.stop.clone());
        self.inner.selection = Some(selected);
        let selection = self.inner.selection.as_ref().ok_or_else(BridgeError::cleanup_unknown)?;
        let book = self.inner.inspection.as_mut().ok_or_else(BridgeError::cleanup_unknown)?;
        book.inspect(selection, end, &stop).map_err(|_| BridgeError::unavailable("The installed Store runtime failed original custody inspection."))?;
        Ok(VerifiedRuntime { python: selection.python.clone(), bootstrap: selection.bootstrap.clone(), core: selection.core.clone(), cwd: selection.cwd.clone() })
    }
    // Called by the same saved owner only after its original child/IO joins.
    // A failed check never consumes safe settlement or creates another claim.
    pub(crate) fn check_claimed_before_settlement(&mut self,expired:&mut dyn FnMut(Option<(AdmissionFailure,Instant)>)->bool) -> Result<()> {
        if self.post_claimed { return Err(AdmissionFailure::AlreadyUsed); }
        self.post_claimed = true;
        let capability = self.inner.capability()?;
        let result = if !capability.claimed || capability.no_effect { Err(AdmissionFailure::AlreadyUsed) }
            else { capability.original.store.as_ref().ok_or(AdmissionFailure::Inventory)?.check_for_settlement(&capability.original,expired) };
        if let Err(failure) = result { capability.original.note_acl(failure, Instant::now()); }
        result
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
        if self.post_claimed { return Err(AdmissionFailure::AlreadyUsed); }
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
    fn store_cleanup_points_ignore_work_stop_but_keep_original_expiry_and_failures() {
        let book=Book::new(); let (_sender,stop)=watch::channel(true);
        assert!(book.point(Instant::now()+std::time::Duration::from_secs(10),&stop).is_err());
        let mut samples=0;
        let mut cleanup=|first| { assert_eq!(first,None); samples+=1; false };
        settlement_point(&book,&mut cleanup).unwrap();
        settlement_point(&book,&mut cleanup).unwrap();
        assert_eq!(samples,2); assert!(*stop.borrow());
        let original=Originals::new(Instant::now()+std::time::Duration::from_secs(10),stop.clone());
        let mut calls=0;
        assert_eq!(original.check_for_settlement(&book,&mut |_|{calls+=1;false}),Err(AdmissionFailure::AlreadyUsed));
        assert_eq!(calls,1); // Actual wrapper passed cleanup point, then refused missing originals.
        assert_eq!(original.check_for_settlement(&book,&mut |_|true),Err(AdmissionFailure::Deadline));
        assert_eq!(settlement_point(&book,&mut |_|true),Err(AdmissionFailure::Deadline));
        let at=Instant::now(); book.note_acl(AdmissionFailure::Identity,at);
        let mut seen=None;
        assert_eq!(settlement_point(&book,&mut |first|{seen=first;true}),Err(AdmissionFailure::Deadline));
        assert_eq!(seen,Some((AdmissionFailure::Identity,at)));
        // No fake descriptors/originals or claimed positive native settlement.
    }
    #[test]
    fn store_slots_do_not_lend_uninspected_or_settled_sources() {
        let mut slots = StoreRuntimeSlots::new();
        assert!(slots.check_claimed_before_settlement(&mut |_|false).is_err());
        assert!(slots.check_claimed_before_settlement(&mut |_|false).is_err());
        assert!(!slots.never_started());
        assert!(slots.prepare_loan(&mut |_| {}).is_err());
        assert_eq!(slots.settle_originals(&mut |_| false), CloseOutcome::Settled);
        assert!(slots.check_claimed_before_settlement(&mut |_|false).is_err());
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
