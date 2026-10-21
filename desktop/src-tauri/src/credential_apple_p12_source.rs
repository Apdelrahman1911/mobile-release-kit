//! Optional ONE selected, genuinely bound P12 beside the same P8/stored-key
//! source. Unrelated P12 rows are not a blocker and are never decrypted here.
//! References only select a current BoundLoan; they cannot construct one.
use super::*;
fn same_reference(a: StoredRef, b: StoredRef) -> bool {
    a.identity == b.identity
        && a.record == b.record
        && a.revision == b.revision
        && a.original == b.original
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::asset_session) enum CheckPoint {
    BeforeWork,
    AfterWorker,
}
impl CheckPoint {
    fn index(self) -> usize {
        match self {
            Self::BeforeWork => 0,
            Self::AfterWorker => 1,
        }
    }
}
#[derive(Default)]
struct Check {
    entered: bool,
    returned: bool,
    failed: bool,
}
pub(super) struct P12Source {
    selected: Mutex<Option<Arc<AppleP12Loan>>>,
    // Fixed comparison survives a completed review without retaining private bytes.
    selection: Option<(StoredRef, Weak<Payload>)>,
    checks: [Mutex<Check>; 2],
}
impl P12Source {
    fn census_selected(&self) -> Result<Option<Arc<AppleP12Loan>>, Reason> {
        self.selected.try_lock().map(|selected| selected.clone()).map_err(|_| Reason::CleanupUnknown)
    }

    pub(super) fn capture(
        document: &DocumentBinding,
        state: &DocumentState,
        p8: &BoundLoan,
        key: &KeyReference,
        selected: Option<&KeyReference>,
    ) -> Result<Self, Reason> {
        let selected = if let Some(reference) = selected {
            // Existing normal Load/Assess/Bind and saved expected certificate
            // remain mandatory. This call does not synthesize or replace Bind.
            let loan = AppleP12Loan::capture(document, state)?;
            if loan.reference() != *reference
                || reference == key
                || reference.vault_id != key.vault_id
                || reference.generation_id != key.generation_id
                || !Arc::ptr_eq(&loan.census_loan().context, &p8.context)
                || !Arc::ptr_eq(&loan.census_loan().store, &p8.store)
                || !Arc::ptr_eq(&loan.census_loan().key, &p8.key)
                || loan.reference().record_id == p8.reference.record.token()
            {
                return Err(Reason::SourceChanged);
            }
            Some(loan)
        } else {
            None
        };
        let selection = selected.as_ref().map(|loan| {
            (
                loan.census_loan().reference,
                Arc::downgrade(&loan.census_loan().payload),
            )
        });
        Ok(Self {
            selected: Mutex::new(selected),
            selection,
            checks: std::array::from_fn(|_| Mutex::new(Check::default())),
        })
    }
    pub(super) fn same(&self, other: &Self) -> bool {
        match (&self.selection, &other.selection) {
            (None, None) => true,
            (Some((a, pa)), Some((b, pb))) => same_reference(*a, *b) && Weak::ptr_eq(pa, pb),
            _ => false,
        }
    }
    pub(super) fn current(&self, document: &DocumentBinding, state: &DocumentState) -> bool {
        self.selected
            .try_lock()
            .is_ok_and(|selected| match (&self.selection, &*selected) {
                (None, None) => true,
                (Some((reference, payload)), Some(loan)) => {
                    same_reference(*reference, loan.census_loan().reference)
                        && Weak::ptr_eq(payload, &Arc::downgrade(&loan.census_loan().payload))
                        && loan.current(document, state, None)
                }
                _ => false,
            })
    }
    // Called only after the actual same-owner Store/control/coordinator joins,
    // not as a Drop/STOP callback. A retained review keeps comparison data only.
    pub(super) fn retire_private(&self) -> bool {
        let Ok(mut selected) = self.selected.try_lock() else {
            return false;
        };
        selected.take();
        true
    }
    pub(super) fn own_retained_bytes(&self) -> usize {
        // Existing census separately visits the selected BoundLoan and its
        // actual key/context/payload/Store Arcs; this is only fixed cells.
        std::mem::size_of::<Self>()
            + self.selection.as_ref().map_or(0, |_| {
                std::mem::size_of::<Payload>() + 2 * std::mem::size_of::<usize>()
            })
    }
}
impl AppleKeySources {
    pub(in crate::asset_session) fn p12_matches_p8(&self, source: &BoundLoan) -> bool {
        self.p12.is_some()
            && same_reference(self.p8.reference, source.reference)
            && Arc::ptr_eq(&self.p8.payload, &source.payload)
            && Arc::ptr_eq(&self.p8.context, &source.context)
            && Arc::ptr_eq(&self.p8.key, &source.key)
            && Arc::ptr_eq(&self.p8.store, &source.store)
    }
    /// Lossless census only: a failed TRY lock must never become an absent
    /// selected P12. The ordinary producer accessor below is unchanged.
    pub(in crate::asset_session) fn selected_p12_census(&self) -> Result<Option<Arc<AppleP12Loan>>, Reason> {
        self.p12.as_ref().map(P12Source::census_selected).transpose().map(Option::flatten)
    }
    pub(in crate::asset_session) fn selected_p12(&self) -> Option<Arc<AppleP12Loan>> {
        self.p12.as_ref()?.selected.try_lock().ok()?.clone()
    }
    pub(in crate::asset_session) fn selected_p12_expected(&self) -> bool {
        self.p12
            .as_ref()
            .is_some_and(|source| source.selection.is_some())
    }
    pub(in crate::asset_session) fn retire_p12_private(&self) -> bool {
        self.p12.as_ref().is_none_or(P12Source::retire_private)
    }
    pub(in crate::asset_session) fn p12_checked(
        &self,
        owner: &Arc<OriginalWork>,
        point: CheckPoint,
    ) -> bool {
        self.same_owner(owner)
            && self.p12.as_ref().is_some_and(|p12| {
                p12.checks[point.index()]
                    .try_lock()
                    .is_ok_and(|check| check.entered && check.returned && !check.failed)
            })
    }
    pub(in crate::asset_session) fn selected_p12_parts<'a>(
        &self,
        selected: &'a Arc<AppleP12Loan>,
    ) -> Result<[(&'static str, &'a [u8]); 2], Reason> {
        let original = self.owner().ok_or(Reason::CleanupUnknown)?;
        if !self.p12_checked(&original, CheckPoint::BeforeWork) {
            return Err(Reason::SourceChanged);
        }
        if !self
            .selected_p12()
            .is_some_and(|same| Arc::ptr_eq(&same, selected))
        {
            return Err(Reason::SourceChanged);
        }
        selected.private_parts()
    }
    /// Reuse publication requires the real current selected assignment; a
    /// complete child/frame/hash/journal row is insufficient on its own.
    pub(in crate::asset_session) fn reused_assignment_current(
        &self,
        document: &DocumentBinding,
        state: &DocumentState,
        owner: &Arc<OriginalWork>,
        reference: &KeyReference,
        leaf: &[u8; 32],
        p12: &[u8; 32],
    ) -> bool {
        self.same_owner(owner)
            && self.current(document, state)
            && self.p12_checked(owner, CheckPoint::BeforeWork)
            && self.p12_checked(owner, CheckPoint::AfterWorker)
            && self.selected_p12().is_some_and(|loan| {
                loan.reference() == *reference
                    && loan.expected_certificate_sha256() == *leaf
                    && loan.p12_sha256() == *p12
                    && loan.current(document, state, None)
            })
    }
}

#[cfg(test)]
mod census_tests {
    use super::*;

    #[test]
    fn selected_p12_census_distinguishes_real_none_contention_and_poison() {
        let source = P12Source { selected: Mutex::new(None), selection: None,
            checks: std::array::from_fn(|_| Mutex::new(Check::default())) };
        assert!(source.census_selected().unwrap().is_none());
        let held = source.selected.lock().unwrap();
        assert!(matches!(source.census_selected(), Err(Reason::CleanupUnknown)));
        drop(held);
        assert!(source.census_selected().unwrap().is_none());
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _held = source.selected.lock().unwrap();
            panic!("inert P12 census lock poison");
        }));
        assert!(matches!(source.census_selected(), Err(Reason::CleanupUnknown)));
        // A poisoned private slot is not an observed retired absence.
        assert!(!source.retire_private());
    }
}

pub(in crate::asset_session) fn child_admitted(
    owner: &OriginalWork,
    sources: &Arc<AppleKeySources>,
    point: CheckPoint,
) -> bool {
    let Some(original) = sources.owner() else {
        return false;
    };
    std::ptr::eq(owner, original.as_ref())
        && !owner.interrupted()
        && sources.p12.as_ref().is_some_and(|p12| {
            p12.checks[point.index()]
                .try_lock()
                .is_ok_and(|check| !check.entered && !check.returned && !check.failed)
        })
        && sources.certificate_loan().is_some()
        && owner.vault.try_lock().is_ok_and(|work| {
            work.first.is_none()
                && !work.release
                && work
                    .key
                    .as_ref()
                    .is_some_and(|key| Arc::ptr_eq(key, &sources.p8.key))
                && work
                    .store
                    .as_ref()
                    .is_some_and(|store| Arc::ptr_eq(store, &sources.p8.store))
        })
}

/// This is an arm of the original vault Child, not a new worker/Store reader.
pub(in crate::asset_session) fn execute(
    owner: &Arc<OriginalWork>,
    book: &mut store::StoreBook,
    sources: &Arc<AppleKeySources>,
    point: CheckPoint,
) -> Result<ChildResult, Reason> {
    let p12 = sources.p12.as_ref().ok_or(Reason::SourceRefused)?;
    {
        let mut check = p12.checks[point.index()]
            .try_lock()
            .map_err(|_| Reason::CleanupUnknown)?;
        if !sources.same_owner(owner)
            || owner.interrupted()
            || check.entered
            || check.returned
            || check.failed
        {
            return Err(Reason::ContextStale);
        }
        check.entered = true;
    }
    let result = (|| {
        check_exclusions(owner, book, &sources.roster)?;
        if !Arc::ptr_eq(&active_key(owner)?, &sources.p8.key) {
            return Err(Reason::SourceChanged);
        }
        book.recheck_record(&sources.p8.reference.original, &mut || owner.interrupted())
            .map_err(problem)?;
        // The selected stored key's complete witness, not an identity rebuilt
        // from a reported hash. The same native Load already authenticated it.
        let witness = sources
            .certificate_read_witness()
            .ok_or(Reason::SourceRefused)?;
        book.recheck_record(witness, &mut || owner.interrupted())
            .map_err(problem)?;
        let selected = sources.selected_p12();
        if p12.selection.is_some() && selected.is_none() {
            return Err(Reason::SourceChanged);
        }
        if let Some(selected) = selected {
            selected.recheck_store(owner, book, &sources.roster)?;
        }
        if owner.interrupted() {
            return Err(Reason::UserCancelled);
        }
        Ok(ChildResult::Checked)
    })();
    if result.is_err() {
        p12.checks[point.index()]
            .try_lock()
            .map_err(|_| Reason::CleanupUnknown)?
            .failed = true;
    }
    result
}

#[cfg(feature = "desktop-shell")]
pub(in crate::asset_session) async fn check(
    document: &DocumentBinding,
    owner: &Arc<OriginalWork>,
    sources: &Arc<AppleKeySources>,
    point: CheckPoint,
) -> Result<(), Reason> {
    {
        let state = document.lock();
        if !sources.same_owner(owner) || !sources.current(document, &state) {
            return Err(Reason::ContextStale);
        }
    }
    let result = native(
        document,
        owner,
        Child::CheckAppleP12Sources(sources.clone(), point),
    )
    .await?;
    let state = document.lock();
    if !sources.current(document, &state)
        || !matches!(result, ChildResult::Checked)
        || !owner
            .child
            .try_lock()
            .is_ok_and(|book| book.handle.is_none() && book.receipt == JoinReceipt::Returned)
    {
        return Err(Reason::CleanupUnknown);
    }
    let p12 = sources.p12.as_ref().ok_or(Reason::SourceRefused)?;
    let mut check = p12.checks[point.index()]
        .try_lock()
        .map_err(|_| Reason::CleanupUnknown)?;
    if !check.entered || check.returned || check.failed {
        return Err(Reason::CleanupUnknown);
    }
    check.returned = true;
    Ok(())
}
