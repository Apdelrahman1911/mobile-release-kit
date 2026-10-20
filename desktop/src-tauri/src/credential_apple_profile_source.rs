//! The selected P8 and P12 keep their original native ReadWitnesses. Each
//! fixed check uses the existing vault child; a captured digest is not a
//! substitute for rechecking the actual held StoreBook.
use super::*;
use std::sync::{OnceLock, Weak};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::asset_session) enum CheckPoint {
    Initial,
    BeforePending,
    BeforeSave,
}
impl CheckPoint {
    fn index(self) -> usize {
        match self {
            Self::Initial => 0,
            Self::BeforePending => 1,
            Self::BeforeSave => 2,
        }
    }
}
#[derive(Clone, Copy, Default)]
struct Check {
    entered: bool,
    returned: bool,
    succeeded: bool,
}

pub(crate) struct AppleProfileSources {
    p8: BoundLoan,
    p12: Arc<AppleP12Loan>,
    roster: ProjectRoster,
    owner: OnceLock<Weak<OriginalWork>>,
    checks: Mutex<[Check; 3]>,
}
impl AppleProfileSources {
    pub(in crate::asset_session) fn capture(
        document: &DocumentBinding,
        state: &DocumentState,
        native: &Arc<NativeContext>,
        key: &RecordKey,
        payload: &Arc<Payload>,
    ) -> Result<Arc<Self>, Reason> {
        let p12 = AppleP12Loan::capture(document, state)?;
        let session = state.vault.as_ref().ok_or(Reason::VaultKeyMissing)?;
        let mut matching = session.bound.iter().flatten().filter(|loan| {
            loan.payload.kind == Kind::AscP8
                && Arc::ptr_eq(&loan.context, native)
                && Arc::ptr_eq(&loan.payload, payload)
                && loan.reference.matches(key)
                && loan.current(state, session)
        });
        let loan = matching.next().ok_or(Reason::SourceRefused)?;
        if matching.next().is_some()
            || !Arc::ptr_eq(&loan.context, &p12.census_loan().context)
            || !Arc::ptr_eq(&loan.store, &p12.census_loan().store)
            || !Arc::ptr_eq(&loan.key, &p12.census_loan().key)
        {
            return Err(Reason::SourceChanged);
        }
        let roster = document
            .inner
            .bridge
            .native_roster()
            .map_err(|e| e.reason)?;
        if roster.generation != native.registry_generation
            || roster.roots.len() > 64
            || !roster.roots.contains(&native.project)
        {
            return Err(Reason::ContextStale);
        }
        Ok(Arc::new(Self {
            p8: BoundLoan {
                context: loan.context.clone(),
                payload: loan.payload.clone(),
                reference: loan.reference,
                store: loan.store.clone(),
                key: loan.key.clone(),
            },
            p12,
            roster,
            owner: OnceLock::new(),
            checks: Mutex::new([Check::default(); 3]),
        }))
    }
    pub(in crate::asset_session) fn p12(&self) -> &Arc<AppleP12Loan> {
        &self.p12
    }
    pub(in crate::asset_session) fn roster(&self) -> &ProjectRoster {
        &self.roster
    }
    pub(in crate::asset_session) fn native(&self) -> &Arc<NativeContext> {
        &self.p8.context
    }
    pub(in crate::asset_session) fn loans(&self) -> [&BoundLoan; 2] {
        [&self.p8, self.p12.census_loan()]
    }
    pub(in crate::asset_session) fn bind(&self, owner: &Arc<OriginalWork>) -> Result<(), Reason> {
        if owner.interrupted()
            || !Arc::ptr_eq(&active_key(owner)?, &self.p8.key)
            || !Arc::ptr_eq(&native_store(owner)?, &self.p8.store)
        {
            return Err(Reason::SourceChanged);
        }
        self.owner
            .set(Arc::downgrade(owner))
            .map_err(|_| Reason::ContextStale)
    }
    pub(in crate::asset_session) fn same_owner(&self, owner: &Arc<OriginalWork>) -> bool {
        self.owner
            .get()
            .and_then(Weak::upgrade)
            .is_some_and(|same| Arc::ptr_eq(&same, owner))
    }
    pub(in crate::asset_session) fn owner(&self) -> Option<Arc<OriginalWork>> {
        self.owner.get().and_then(Weak::upgrade)
    }
    pub(in crate::asset_session) fn no_child_entered(&self) -> bool {
        self.checks
            .try_lock()
            .is_ok_and(|checks| checks.iter().all(|check| !check.entered))
    }
    pub(in crate::asset_session) fn same_selection(&self, other: &Self) -> bool {
        let left = self.p8.reference;
        let right = other.p8.reference;
        Arc::ptr_eq(&self.p8.context, &other.p8.context)
            && Arc::ptr_eq(&self.p8.payload, &other.p8.payload)
            && Arc::ptr_eq(&self.p8.key, &other.p8.key)
            && Arc::ptr_eq(&self.p8.store, &other.p8.store)
            && left.identity == right.identity
            && left.record == right.record
            && left.revision == right.revision
            && left.original == right.original
            && self.p12.reference() == other.p12.reference()
            && self.p12.p12_sha256() == other.p12.p12_sha256()
            && self.p12.expected_certificate_sha256() == other.p12.expected_certificate_sha256()
            && Arc::ptr_eq(
                &self.p12.census_loan().payload,
                &other.p12.census_loan().payload,
            )
            && self.roster.generation == other.roster.generation
            && self.roster.roots == other.roster.roots
    }
    pub(in crate::asset_session) fn current(
        &self,
        document: &DocumentBinding,
        state: &DocumentState,
    ) -> bool {
        let Some(session) = state.vault.as_ref() else {
            return false;
        };
        // A read-only review does not create a destination or mutate the vault.
        // The saving mode's one current-source exception is bound to the SAME
        // fixed destination, not to an arbitrary busy original or a flag.
        let original = self.owner.get().and_then(Weak::upgrade);
        let mutation = original.as_ref().filter(|owner| {
            state.slot.as_ref().is_some_and(|slot| {
                Arc::ptr_eq(&slot.owner, owner) && slot.operation == Operation::AppleProfileSetup
            }) && session.state == State::Mutating
        });
        let p8 = match mutation {
            Some(owner) => self.p8.current_for_apple_profile(state, session, owner),
            None => self.p8.current(state, session),
        };
        p8 && self.p12.current(document, state, mutation)
            && document.inner.bridge.registry_generation() == self.roster.generation
    }
    pub(in crate::asset_session) fn initially_checked(&self, owner: &Arc<OriginalWork>) -> bool {
        self.same_owner(owner)
            && self
                .checks
                .try_lock()
                .is_ok_and(|checks| checks[0].entered && checks[0].returned && checks[0].succeeded)
    }
    pub(crate) fn own_retained_bytes(&self) -> Option<usize> {
        let mut bytes = std::mem::size_of::<Self>()
            .checked_add(2 * std::mem::size_of::<usize>())?
            .checked_add(self.p12.own_retained_bytes())?
            .checked_add(
                self.roster
                    .roots
                    .capacity()
                    .checked_mul(std::mem::size_of::<asset_source::RegisteredRoot>())?,
            )?;
        for root in &self.roster.roots {
            bytes = bytes.checked_add(root.path.capacity())?;
        }
        Some(bytes)
    }
}

pub(in crate::asset_session) fn attach(
    state: &DocumentState,
    owner: &Arc<OriginalWork>,
    sources: &Arc<AppleProfileSources>,
) -> Result<(), Reason> {
    let session = state.vault.as_ref().ok_or(Reason::VaultKeyMissing)?;
    if !session.writable()
        || !Arc::ptr_eq(&session.store, &sources.p8.store)
        || session
            .key
            .as_ref()
            .is_none_or(|key| !Arc::ptr_eq(key, &sources.p8.key))
    {
        return Err(Reason::SourceChanged);
    }
    super::attach(owner, session, true, false).map_err(|error| error.reason)?;
    sources.bind(owner)
}

/// Only the caller's actual never-installed/no-child original reaches this
/// fixed path. No native handle was obtained here: the Document retains the
/// existing StoreBook lease, which must still be positively quiescent/closed.
pub(in crate::asset_session) fn retire_unentered(owner: &Arc<OriginalWork>) -> bool {
    let Ok(mut work) = owner.vault.try_lock() else {
        return false;
    };
    if work.outcome.is_some()
        || work.release_claimed
        || work.original_join.is_some()
        || work.failed_child_join.is_some()
        || work.apple_profile.blocks_reuse()
        || work.store.as_ref().is_some_and(|store| {
            !store.try_lock().is_ok_and(|book| {
                book.not_started() || book.settled() || book.operation_quiescent()
            })
        })
    {
        return false;
    }
    work.key.take();
    work.store.take();
    work.apple_clock.take();
    true
}

/// Not a callback or a generic record reader: the one original native child
/// can only check the two already-selected stored records and complete roster.
pub(super) fn execute(
    owner: &Arc<OriginalWork>,
    book: &mut store::StoreBook,
    sources: &Arc<AppleProfileSources>,
    point: CheckPoint,
) -> Result<ChildResult, Reason> {
    if !sources.same_owner(owner) {
        return Err(Reason::ContextStale);
    }
    {
        let mut checks = sources.checks.lock().map_err(|_| Reason::CleanupUnknown)?;
        let index = point.index();
        if checks[index].entered || index != 0 && !checks[0].succeeded {
            return Err(Reason::ContextStale);
        }
        checks[index].entered = true;
    }
    if owner.interrupted()
        || !Arc::ptr_eq(&active_key(owner)?, &sources.p8.key)
        || !Arc::ptr_eq(&native_store(owner)?, &sources.p8.store)
    {
        return Err(Reason::SourceChanged);
    }
    check_exclusions(owner, book, &sources.roster)?;
    book.recheck_record(&sources.p8.reference.original, &mut || owner.interrupted())
        .map_err(problem)?;
    sources.p12.recheck_store(owner, book, &sources.roster)?;
    if owner.interrupted() {
        return Err(Reason::UserCancelled);
    }
    Ok(ChildResult::Checked)
}

#[cfg(feature = "desktop-shell")]
pub(in crate::asset_session) async fn check(
    document: &DocumentBinding,
    owner: &Arc<OriginalWork>,
    sources: &Arc<AppleProfileSources>,
    point: CheckPoint,
) -> Result<(), Reason> {
    {
        let state = document.lock();
        if !sources.same_owner(owner)
            || !sources.current(document, &state)
            || state.slot.as_ref().is_none_or(|slot| {
                !Arc::ptr_eq(&slot.owner, owner) || slot.operation != Operation::AppleProfileSetup
            })
        {
            return Err(Reason::ContextStale);
        }
    }
    let result = native(
        document,
        owner,
        Child::CheckAppleProfile(sources.clone(), point),
    )
    .await;
    let mut checks = sources
        .checks
        .try_lock()
        .map_err(|_| Reason::CleanupUnknown)?;
    let check = &mut checks[point.index()];
    if check.returned {
        return Err(Reason::CleanupUnknown);
    }
    check.returned = true;
    match result {
        Ok(ChildResult::Checked) if check.entered => {
            check.succeeded = true;
            Ok(())
        }
        Err(reason) => Err(reason),
        _ => Err(Reason::CleanupUnknown),
    }
}
