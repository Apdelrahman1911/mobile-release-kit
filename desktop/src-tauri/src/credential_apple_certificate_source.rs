//! Fresh selected stored-key facet of the existing P8 source. No new store,
//! process, path getter, assignment or imported key authority is introduced.
use super::*;
use super::super::distribution_key::{self, AppleDistributionKeyLoan};

#[derive(Clone, Copy)]
pub(in crate::asset_session) enum CheckPoint { Initial, BeforePending }
impl CheckPoint { fn index(self) -> usize { match self { Self::Initial => 0, Self::BeforePending => 1 } } }
#[derive(Default)]
struct Checked { entered: bool, returned: bool, failed: bool }
pub(super) struct CertificateSource {
    reference: StoredRef,
    // A completed private Review retains this source for comparison only.
    // The original vault Work, not that Review, owns the loaded loan/fields.
    loan: OnceLock<Weak<AppleDistributionKeyLoan>>,
    payload: OnceLock<Weak<Payload>>,
    checks: [Mutex<Checked>; 2],
}
impl CertificateSource {
    pub(super) fn weak_backing_bytes() -> Option<usize> {
        // Weak keeps the allocation (not its dropped private fields) alive.
        // Reserve these two fixed tombstones even while the original Work
        // separately charges its live loan/payload. No heap-size guess/refund.
        std::mem::size_of::<AppleDistributionKeyLoan>()
            .checked_add(std::mem::size_of::<Payload>())?
            .checked_add(4 * std::mem::size_of::<usize>())
    }
    pub(super) fn capture(state: &DocumentState, expected: &RecordKey, p8: &BoundLoan) -> Result<Self, Reason> {
        let session = state.vault.as_ref().ok_or(Reason::VaultKeyMissing)?;
        let mut rows = session.rows.iter().filter(|row|
            !row.mutation_pending && row.authenticated.descriptor.kind == Kind::AppleDistributionKey
                && row.reference(p8.reference.identity).matches(expected));
        let row = rows.next().ok_or(Reason::SourceChanged)?;
        let reference = row.reference(p8.reference.identity);
        if rows.next().is_some() || reference.record == p8.reference.record { return Err(Reason::SourceChanged); }
        Ok(Self { reference, loan: OnceLock::new(), payload: OnceLock::new(), checks: std::array::from_fn(|_| Mutex::new(Checked::default())) })
    }
    pub(super) fn same(&self, other: &Self) -> bool {
        self.reference.identity == other.reference.identity && self.reference.record == other.reference.record
            && self.reference.revision == other.reference.revision && self.reference.original == other.reference.original
    }
    pub(super) fn current(&self, sources: &AppleKeySources, document: &DocumentBinding, state: &DocumentState) -> bool {
        state.vault.as_ref().is_some_and(|session| session.rows.iter().any(|row|
            !row.mutation_pending && row.authenticated.descriptor.kind == Kind::AppleDistributionKey
                && row.authenticated.record == self.reference.record && row.authenticated.revision == self.reference.revision
                && row.original == self.reference.original))
            && match (self.loan.get().and_then(Weak::upgrade), self.payload.get()) {
                (Some(loan), Some(payload)) => payload.upgrade().is_some()
                    && sources.owner().is_some_and(|owner| loan.current(document, state, &owner)),
                (loan, None) => (self.loan.get().is_none() || loan.is_some())
                    && self.checks[0].try_lock().is_ok_and(|check| !check.entered && !check.returned && !check.failed),
                _ => false,
            }
    }
}
impl AppleKeySources {
    pub(in crate::asset_session) fn selected_certificate_key(&self) -> Option<KeyReference> {
        let reference = self.certificate.as_ref()?.reference;
        Some(KeyReference::native(reference.identity, reference.record, reference.revision))
    }
    pub(in crate::asset_session) fn certificate_read_witness(&self) -> Option<&store::ReadWitness> { Some(&self.certificate.as_ref()?.reference.original) }
    pub(in crate::asset_session) fn certificate_loan(&self) -> Option<Arc<AppleDistributionKeyLoan>> {
        self.certificate.as_ref()?.loan.get()?.upgrade()
    }
    pub(in crate::asset_session) fn certificate_payload(&self) -> Option<Arc<Payload>> {
        self.certificate.as_ref()?.payload.get()?.upgrade()
    }
    pub(in crate::asset_session) fn attach_certificate_loan(&self, document: &DocumentBinding, state: &DocumentState, owner: &Arc<OriginalWork>) -> Result<(), Reason> {
        let certificate = self.certificate.as_ref().ok_or(Reason::SourceRefused)?;
        if !self.same_owner(owner) || !self.current(document, state) || certificate.loan.get().is_some() { return Err(Reason::SourceChanged); }
        let expected = self.selected_certificate_key().ok_or(Reason::SourceRefused)?;
        let roster=ProjectRoster { generation:self.roster.generation, roots:self.roster.roots.clone() };
        let loan=if owner.apple_key_parent().is_some_and(|parent|parent.p12_mode()==Some(crate::apple_provisioning_protocol::Mode::P12Save)) {
            AppleDistributionKeyLoan::reserve_p12(document,state,owner,&expected,roster)?
        } else { AppleDistributionKeyLoan::reserve(document,state,owner,&expected,roster)? };
        // reserve is zero-IO. The existing Work retains the exact original
        // BEFORE weak publication, parent attachment, or the first Load.
        owner.vault.try_lock().map_err(|_| Reason::CleanupUnknown)?.attach_apple_distribution_key_loan(loan.clone())?;
        certificate.loan.set(Arc::downgrade(&loan)).map_err(|_| Reason::CleanupUnknown)?;
        owner.apple_key_parent().ok_or(Reason::CleanupUnknown)?.attach_loan(owner, &loan).map_err(|_| Reason::CleanupUnknown)
    }
    pub(in crate::asset_session) fn certificate_checked(&self, owner: &Arc<OriginalWork>, point: CheckPoint) -> bool {
        self.same_owner(owner) && self.certificate.as_ref().is_some_and(|source|
            source.payload.get().and_then(Weak::upgrade).is_some()
                && source.checks[point.index()].try_lock().is_ok_and(|check| check.entered && check.returned && !check.failed))
    }
    pub(in crate::asset_session) fn certificate_parts<'a>(&self, payload: &'a Arc<Payload>) -> Result<[(&'static str, &'a [u8]); 3], Reason> {
        let owner = self.owner().ok_or(Reason::CleanupUnknown)?;
        let source = self.certificate.as_ref().ok_or(Reason::SourceRefused)?;
        if !self.certificate_checked(&owner, CheckPoint::Initial)
            || !source.payload.get().is_some_and(|held| Weak::ptr_eq(held, &Arc::downgrade(payload))) {
            return Err(Reason::SourceChanged);
        }
        source.loan.get().and_then(Weak::upgrade).ok_or(Reason::SourceRefused)?.private_parts(&owner, payload)
    }
}

pub(in crate::asset_session) fn child_admitted(owner: &OriginalWork, sources: &Arc<AppleKeySources>, point: CheckPoint) -> bool {
    let Some(original) = sources.owner() else { return false; };
    let Some(source) = &sources.certificate else { return false; };
    std::ptr::eq(owner, original.as_ref()) && !owner.interrupted()
        && source.payload.get().and_then(Weak::upgrade).is_some()
        && source.loan.get().and_then(Weak::upgrade).is_some()
        && source.checks[point.index()].try_lock().is_ok_and(|check| !check.entered && !check.returned && !check.failed)
        && owner.vault.try_lock().is_ok_and(|work| work.first.is_none() && !work.release
            && work.key.as_ref().is_some_and(|key| Arc::ptr_eq(key, &sources.p8.key))
            && work.store.as_ref().is_some_and(|store| Arc::ptr_eq(store, &sources.p8.store)))
}

/// Executed only by the existing original vault Child, with its held StoreBook.
pub(in crate::asset_session) fn execute(owner: &Arc<OriginalWork>, book: &mut store::StoreBook,
    sources: &Arc<AppleKeySources>, point: CheckPoint) -> Result<ChildResult, Reason> {
    let source = sources.certificate.as_ref().ok_or(Reason::SourceRefused)?;
    {
        let mut check = source.checks[point.index()].try_lock().map_err(|_| Reason::CleanupUnknown)?;
        if !sources.same_owner(owner) || check.entered || check.returned || check.failed || owner.interrupted() { return Err(Reason::ContextStale); }
        check.entered = true;
    }
    let result = (|| {
        check_exclusions(owner, book, &sources.roster)?;
        if active_key(owner)?.identity() != source.reference.identity || source.payload.get().and_then(Weak::upgrade).is_none() { return Err(Reason::SourceChanged); }
        for witness in [&sources.p8.reference.original, &source.reference.original] {
            book.recheck_record(witness, &mut || owner.interrupted()).map_err(problem)?;
        }
        if owner.interrupted() { return Err(Reason::UserCancelled); }
        Ok(ChildResult::Checked)
    })();
    if result.is_err() {
        source.checks[point.index()].try_lock().map_err(|_| Reason::CleanupUnknown)?.failed = true;
    }
    result
}

#[cfg(feature = "desktop-shell")]
pub(in crate::asset_session) async fn load(document: &DocumentBinding, owner: &Arc<OriginalWork>, sources: &Arc<AppleKeySources>) -> Result<(), Reason> {
    let source = sources.certificate.as_ref().ok_or(Reason::SourceRefused)?;
    let loan = source.loan.get().and_then(Weak::upgrade).ok_or(Reason::SourceRefused)?;
    let request = distribution_key::LoadRequest::new(&loan);
    let staged = distribution_key::run_load(document, owner, request).await?;
    if !matches!(staged, crate::asset_session::Staged::Vault(super::super::Staged::AppleDistributionKeyLoaded { .. })) { return Err(Reason::CleanupUnknown); }
    // Returned DATA is not a new assignment; the original loan retains its
    // private fields and read witness until the parent actual use-joined cut.
    let payload = loan.payload()?.ok_or(Reason::SourceChanged)?;
    source.payload.set(Arc::downgrade(&payload)).map_err(|_| Reason::CleanupUnknown)?;
    drop(payload);
    check(document, owner, sources, CheckPoint::Initial).await
}

#[cfg(feature = "desktop-shell")]
pub(in crate::asset_session) async fn check(document: &DocumentBinding, owner: &Arc<OriginalWork>, sources: &Arc<AppleKeySources>, point: CheckPoint) -> Result<(), Reason> {
    {
        let state = document.lock();
        if !sources.current(document, &state) || !sources.same_owner(owner) { return Err(Reason::ContextStale); }
    }
    let result = native(document, owner, Child::CheckAppleCertificateSources(sources.clone(), point)).await?;
    let state = document.lock();
    if !sources.current(document, &state) || !matches!(result, ChildResult::Checked)
        || !owner.child.try_lock().is_ok_and(|book| book.handle.is_none() && book.receipt == JoinReceipt::Returned) { return Err(Reason::CleanupUnknown); }
    let source = sources.certificate.as_ref().ok_or(Reason::SourceRefused)?;
    let mut check = source.checks[point.index()].try_lock().map_err(|_| Reason::CleanupUnknown)?;
    if !check.entered || check.returned || check.failed { return Err(Reason::CleanupUnknown); }
    check.returned = true;
    Ok(())
}

#[cfg(all(test, debug_assertions))]
mod tests {
    use super::*;

    #[test]
    fn retained_certificate_review_source_does_not_pin_the_original_private_payload() {
        let id=|byte| format::Id::from_bytes([byte;16]).unwrap();
        let revision=format::Revision::new(id(4),1).unwrap();
        let source=Arc::new(CertificateSource {
            reference:StoredRef { identity:format::Identity::new(id(1),id(2)).unwrap(),
                record:id(3),revision,original:store::ReadWitness::lifecycle_data(id(3),revision) },
            loan:OnceLock::new(),payload:OnceLock::new(),
            checks:std::array::from_fn(|_|Mutex::new(Checked::default())),
        });
        // Reference-lifetime DATA, not a loaded key, native join or a permit.
        // The production loan retains this strong role through Unknown and
        // releases it only in its unchanged actual UseJoined disposal path.
        let original=Arc::new(Payload { kind:Kind::AppleDistributionKey,material:None,fields:None });
        let observed=Arc::downgrade(&original);
        source.payload.set(Arc::downgrade(&original)).ok().unwrap();
        let retained_review=source.clone();
        let writer=source.payload.get().and_then(Weak::upgrade).unwrap();
        assert!(Arc::ptr_eq(&writer,&original));
        drop(source);
        // A returned writer alone is not native retirement. Unknown still
        // leaves the actual original holder alive rather than recreating it.
        drop(writer);
        assert!(observed.upgrade().is_some());
        let partial_writer=retained_review.payload.get().and_then(Weak::upgrade).unwrap();
        drop(original);
        assert!(observed.upgrade().is_some());
        // The same writer borrow spans header/body and is not dropped when a
        // write future is cancelled. Its actual return drops that last Arc.
        drop(partial_writer);
        assert!(observed.upgrade().is_none());
        assert!(retained_review.payload.get().and_then(Weak::upgrade).is_none());
        assert!(retained_review.loan.get().is_none());
        assert!(CertificateSource::weak_backing_bytes().unwrap()
            >=std::mem::size_of::<Payload>()+std::mem::size_of::<AppleDistributionKeyLoan>()+4*std::mem::size_of::<usize>());
    }
}
