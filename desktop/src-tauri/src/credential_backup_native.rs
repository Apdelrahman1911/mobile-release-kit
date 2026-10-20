//! Fixed portable-backup facets of the EXISTING asset_session_vault owner.
//!
//! Root integrates this child into OriginalWork/Child/Job and the exact census;
//! it is not a second worker, arbitrary-path command or source of authorization.
//! Neither a successful codec nor the return below is worker/coordinator join,
//! delivered export, native capture qualification, assessment or assignment.
//!
//! The macOS two-destination child is a concrete, one-use native sink. Its
//! successful body is still not delivery: the parent rematches current vault
//! context only after original joins, and retains output through every failure.
//! No public route/qualification is enabled by these internal adapters.
use super::*;
use crypto::backup;
#[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "macos-installed-observation", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer"), target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
#[path = "credential_upload_key_backup_observation.rs"]
pub(in crate::asset_session) mod installed;

const ARC_BYTES: usize = 2 * std::mem::size_of::<usize>();
// Future SourceBook/roster/control allocations are not present in the initial
// live census. Reserve them before native read/crypto allocation, independently
// of the existing parser arena and actual retained payload/output charges.
const NATIVE_CONTROL_BYTES: usize = 1024 * 1024;

impl OriginalWork {
    /// One-way early failure notification from the fixed backup-pair child.
    /// Called with NO vault::Work/document lock held. Keep the actual first
    /// observation time before independent closes; later cleanup failures never
    /// replace it. This grants neither output/finality nor a new cleanup clock.
    pub(crate) fn credential_backup_failed(&self, reason: Reason) {
        let at = Instant::now();
        if let Ok(mut work) = self.vault.lock() { work.fail(reason, at); }
        self.signal_stop();
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase { Reserved, Running, PendingPrivateSink, ExportCandidate, StoredNew, Failed }

enum Content {
    Export { reference: StoredRef, output: Option<backup::ExportedBackup>,
        #[cfg(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
        destination: Option<asset_source::BackupDestinations>,
    },
    #[cfg(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
    ImportNew { identity: format::Identity, record: format::Id, sources: asset_source::BackupSources },
}
impl Content {
    fn export(reference: StoredRef, output: Option<backup::ExportedBackup>) -> Self {
        Self::Export { reference, output,
            #[cfg(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
            destination: None,
        }
    }
    fn export_destination_bytes(&self) -> Option<usize> {
        #[cfg(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
        if let Self::Export { destination, .. } = self {
            return destination.as_ref().map_or(Some(0), asset_source::BackupDestinations::retained_bytes);
        }
        Some(0)
    }
    fn disposal_ready(&self) -> bool {
        #[cfg(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
        if let Self::Export { destination, .. } = self {
            return destination.as_ref().is_none_or(asset_source::BackupDestinations::disposal_ready);
        }
        true
    }
}

struct Custody {
    owner_id: u32,
    content: Content,
    phase: Phase,
    first: Option<Reason>,
    saved: Option<StoredRef>,
    outcome: Option<store::StorageOutcome>,
}
impl Custody {
    fn retained_bytes(&self) -> Option<usize> {
        let content = match &self.content {
            Content::Export { output, .. } => output.as_ref().map_or(Some(0), backup::ExportedBackup::retained_bytes)?
                .checked_add(self.content.export_destination_bytes()?)?,
            #[cfg(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
            Content::ImportNew { sources, .. } => sources.retained_bytes()?,
        };
        // Conservative inline double-counting is intentional; never refund a
        // plaintext/transition allocation because it moved through a worker.
        std::mem::size_of::<Mutex<Self>>().checked_add(ARC_BYTES)?.checked_add(content)
    }
    fn native_settled(&self) -> bool {
        if self.phase == Phase::Running { return false; }
        match &self.content {
            Content::Export { .. } => {
                #[cfg(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
                if let Content::Export { destination, .. } = &self.content {
                    return destination.as_ref().is_none_or(asset_source::BackupDestinations::native_settled);
                }
                true
            },
            #[cfg(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
            Content::ImportNew { sources, .. } => sources.native_settled(),
        }
    }
    fn fail(&mut self, reason: Reason) {
        if self.first.is_none() { self.first = Some(reason); }
        self.phase = Phase::Failed;
    }
}

/// One optional private holding in vault::Work. The original owns this Arc
/// before GO; a panic poisons/retains it, never replaces it with empty state.
#[derive(Default)]
pub(super) struct Work { inner: Option<Arc<Mutex<Custody>>> }
impl Work {
    pub(super) fn empty(&self) -> bool { self.inner.is_none() }
    pub(super) fn retained_bytes(&self) -> Option<usize> {
        self.inner.as_ref().map_or(Some(0), |value| value.try_lock().ok()?.retained_bytes())
    }
    /// This belongs in native settlement, NOT in the slot-reuse decision.
    /// A pending private sink has no running producer but still owns output.
    pub(super) fn native_settled(&self) -> bool {
        self.inner.as_ref().is_none_or(|value| value.try_lock().is_ok_and(|value| value.native_settled()))
    }
    pub(super) fn blocks_reuse(&self) -> bool { self.inner.is_some() }
    pub(super) fn recovery_required(&self) -> bool {
        self.inner.as_ref().is_some_and(|inner| inner.try_lock().map_or(true, |custody|
            custody.phase == Phase::Failed && (!custody.native_settled() || !custody.content.disposal_ready()
                || custody.outcome.is_some_and(|outcome| outcome.effect == store::Effect::Unknown
                    || outcome.durability == store::Durability::Unknown || outcome.cleanup == store::Cleanup::Unknown))))
    }
    pub(super) fn pending_private_sink(&self) -> bool {
        self.inner.as_ref().is_some_and(|value| value.try_lock().is_ok_and(|value|
            value.phase == Phase::PendingPrivateSink && value.first.is_none()
                && matches!(&value.content, Content::Export { output: Some(_), .. })))
    }
}

/// Created by the locked, native document preparation below; no serialized
/// budget/context or result-shaped message constructs this original request.
pub(in crate::asset_session) struct Request {
    owner_id: u32,
    identity: format::Identity,
    roster: ProjectRoster,
    budget: Budget,
    kind: RequestKind,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum RequestKind {
    Export,
    #[cfg(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
    ImportNew,
}
impl Request {
    pub(super) fn mutation(&self) -> bool {
        match self.kind {
            RequestKind::Export => false,
            #[cfg(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
            RequestKind::ImportNew => true,
        }
    }
}

/// The sole exception to this original's pending-private-data allocation
/// fence. Its already-retained, one-use closed Request may enter its own child;
/// unrelated Tokens/Load/Mutate work cannot borrow that permission.
pub(super) fn child_admitted(owner: &OriginalWork, request: &Request) -> bool {
    if owner.id != request.owner_id || owner.interrupted() || owner.installation.is_some()
        || !owner.retired.load(Ordering::SeqCst)
        || !owner.keyring.try_lock().is_ok_and(|book| !book.memory_held())
        || !owner.source.try_lock().is_ok_and(|source| source.not_started()) { return false; }
    let Ok(work) = owner.vault.try_lock() else { return false; };
    if work.first.is_some() || work.release || work.store.is_none()
        || work.key.as_ref().is_none_or(|key| key.identity() != request.identity) { return false; }
    work.backup.inner.as_ref().is_some_and(|inner| inner.try_lock().is_ok_and(|custody| {
        if custody.owner_id != owner.id || custody.phase != Phase::Reserved || custody.first.is_some() { return false; }
        match (&custody.content, request.kind) {
            (Content::Export { reference, output: None, .. }, RequestKind::Export) =>
                reference.identity == request.identity && work.outcome.is_none(),
            #[cfg(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
            (Content::ImportNew { identity, sources, .. }, RequestKind::ImportNew) =>
                *identity == request.identity && sources.not_started() && work.outcome == Some(store::StorageOutcome {
                    effect: store::Effect::NotStarted, durability: store::Durability::NotRun, cleanup: store::Cleanup::Pending }),
            _ => false,
        }
    }))
}

#[derive(Clone, Copy)]
struct Budget { resident: usize, working: usize }
impl Budget {
    fn from_live(live: usize, prospective: usize) -> Result<Self, Reason> {
        let live = live.checked_add(prospective).and_then(|n| n.checked_add(NATIVE_CONTROL_BYTES))
            .ok_or(Reason::Capacity)?;
        let resident = store::RESIDENT_BYTES.checked_sub(live).ok_or(Reason::Capacity)?;
        let working = store::WORKING_BYTES.checked_sub(live)
            .and_then(|n| n.checked_sub(8 * 1024 * 1024)).ok_or(Reason::Capacity)?;
        Ok(Self { resident, working })
    }
    fn transfer(self) -> usize { self.resident.min(self.working) }
    fn before_record_read(self, length: usize) -> Result<(), Reason> {
        if length.checked_add(crypto::CONTROL_BYTES).is_none_or(|n| n > self.working) {
            return Err(Reason::Capacity);
        }
        Ok(())
    }
    fn export_allowance(self, opened: usize) -> Result<usize, Reason> {
        // Codec allowance includes its fixed control/descriptor scratch. The
        // output itself must fit the free resident row BEFORE allocation.
        self.working.checked_sub(opened).map(|remaining| remaining.min(self.resident))
            .ok_or(Reason::Capacity)
    }
}

fn same_reference(left: StoredRef, right: StoredRef) -> bool {
    left.identity == right.identity && left.record == right.record
        && left.revision == right.revision && left.original == right.original
}

fn opened_bytes(record: &crypto::AuthenticatedRecord) -> Result<usize, Reason> {
    std::mem::size_of::<crypto::AuthenticatedRecord>()
        .checked_add(record.descriptor.retained_bytes().map_err(|_| Reason::Capacity)?)
        .and_then(|n| record.fields.retained_bytes().and_then(|fields| n.checked_add(fields)))
        .and_then(|n| record.file.as_ref().map_or(Some(0), |file| file.retained_bytes().ok()).and_then(|file| n.checked_add(file)))
        .ok_or(Reason::Capacity)
}

fn original(owner: &Arc<OriginalWork>, request: &Request) -> Result<Arc<Mutex<Custody>>, Reason> {
    if owner.id != request.owner_id || owner.interrupted() { return Err(Reason::UserCancelled); }
    let work = owner.vault.lock().map_err(|_| Reason::CleanupUnknown)?;
    if work.release || work.first.is_some() || work.key.as_ref().is_none_or(|key| key.identity() != request.identity) {
        return Err(Reason::VaultInterrupted);
    }
    work.backup.inner.clone().ok_or(Reason::SourceRefused)
}

/// Called ONLY by the closed Child::Backup arm while it holds the SAME native
/// StoreBook as existing vault operations. No new store/path/key is acquired.
pub(super) fn execute(owner: &Arc<OriginalWork>, book: &mut store::StoreBook, request: Request)
    -> Result<ChildResult, Reason> {
    let original = original(owner, &request)?;
    let mut custody = original.lock().map_err(|_| Reason::CleanupUnknown)?;
    if custody.owner_id != owner.id || custody.phase != Phase::Reserved || custody.first.is_some() {
        return Err(Reason::VaultInterrupted);
    }
    let matches = match (&custody.content, request.kind) {
        (Content::Export { reference, output: None, .. }, RequestKind::Export) => reference.identity == request.identity,
        #[cfg(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
        (Content::ImportNew { identity, .. }, RequestKind::ImportNew) => *identity == request.identity,
        _ => false,
    };
    if !matches { return Err(Reason::SourceChanged); }
    custody.phase = Phase::Running;
    let result = match request.kind {
        RequestKind::Export => export_current(owner, book, &mut custody, &request),
        #[cfg(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
        RequestKind::ImportNew => import_new(owner, book, &mut custody, &request),
    };
    if let Err(reason) = result {
        // The output/destination holding remains on this SAME original. Close
        // every independent destination even when authentication/postcheck
        // failed before publication; never turn that failure into regeneration.
        owner.credential_backup_failed(reason);
        #[cfg(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
        if let Content::Export { destination: Some(destination), .. } = &mut custody.content {
            if !destination.abort(owner, reason) { custody.fail(Reason::CleanupUnknown); return Err(Reason::CleanupUnknown); }
        }
        custody.fail(reason);
    }
    result
}

#[cfg(not(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"))))]
fn export_current(_: &Arc<OriginalWork>, _: &mut store::StoreBook, _: &mut Custody, _: &Request) -> Result<ChildResult, Reason> {
    // No native private sink on this platform. Do not create an undeliverable
    // recovery code/key simply because the portable codec compiled.
    Err(Reason::Unqualified)
}
#[cfg(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
fn export_current(owner: &Arc<OriginalWork>, book: &mut store::StoreBook, custody: &mut Custody, request: &Request)
    -> Result<ChildResult, Reason> {
    let reference = match &custody.content {
        Content::Export { reference, output: None, destination: Some(destination) } if destination.not_started() => *reference,
        _ => return Err(Reason::Unqualified),
    };
    let key = active_key(owner)?;
    if key.identity() != reference.identity { return Err(Reason::SourceChanged); }
    check_exclusions(owner, book, &request.roster)?;
    let roots = exclusion_roots(owner, book, &request.roster)?;
    let Content::Export { destination: Some(destination), .. } = &mut custody.content else { return Err(Reason::Unqualified); };
    // Both actual parent chains and empty no-clobber file originals are
    // retained/admitted BEFORE random recovery-key or encrypted-output creation.
    destination.admit(&roots, NATIVE_CONTROL_BYTES, owner)?;
    drop(roots);
    // Authenticate the small original descriptor and obtain a bounded payload
    // quote BEFORE StoreBook allocates a complete encrypted record.
    let small = book.read_record(reference.record, false, &mut || owner.interrupted()).map_err(problem)?;
    let (bytes, witness, complete) = small.into_parts();
    if complete || witness != reference.original { return Err(Reason::SourceChanged); }
    let prefix = format::RecordPrefix::parse(bytes.get(..format::RECORD_PREFIX_BYTES).ok_or(Reason::VaultCorrupt)?, key.identity())
        .map_err(|_| Reason::VaultCorrupt)?;
    let quoted = prefix.total_length().map_err(|_| Reason::Capacity)?;
    request.budget.before_record_read(quoted)?;
    let authenticated = key.open_descriptor(&bytes, request.budget.working).map_err(crypto_problem)?;
    let row = Descriptor { authenticated, original: witness, mutation_pending: false };
    match_descriptor(&row, reference, &key)?;
    drop((row, bytes));
    let record = book.read_record(reference.record, true, &mut || owner.interrupted()).map_err(problem)?;
    let (bytes, witness, complete) = record.into_parts();
    if !complete || witness != reference.original || bytes.len() != quoted { return Err(Reason::SourceChanged); }
    request.budget.before_record_read(bytes.capacity())?;
    let opened = key.open_record(bytes, request.budget.working).map_err(crypto_problem)?;
    if opened.record != reference.record || opened.revision != reference.revision { return Err(Reason::SourceChanged); }
    let allowance = request.budget.export_allowance(opened_bytes(&opened)?)?;
    let output = backup::export(&opened.descriptor, &opened.fields, opened.file.as_ref().map(crypto::StoredBytes::bytes), allowance)
        .map_err(crypto_problem)?;
    // The holding is already locked and retained by OriginalWork. Publish the
    // private output here BEFORE any fallible postcheck or interruption poll.
    match &mut custody.content {
        Content::Export { output: held, .. } => *held = Some(output),
        #[cfg(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
        _ => unreachable!("validated fixed export custody"),
    }
    drop(opened);
    if custody.retained_bytes().is_none_or(|bytes| bytes > request.budget.resident) { return Err(Reason::Capacity); }
    // Recheck the actual record/root originals, not a result hash or row count.
    // The coordinator additionally rematches the native registry generation.
    book.recheck_root(&mut || owner.interrupted()).map_err(problem)?;
    book.recheck_record(&reference.original, &mut || owner.interrupted()).map_err(problem)?;
    if owner.interrupted() || !Arc::ptr_eq(&key, &active_key(owner)?) { return Err(Reason::UserCancelled); }
    let Content::Export { output: Some(output), destination: Some(destination), .. } = &mut custody.content
        else { return Err(Reason::CleanupUnknown); };
    output.publish_to(destination, owner)?; // BORROW, never move output away.
    book.recheck_root(&mut || owner.interrupted()).map_err(problem)?;
    book.recheck_record(&reference.original, &mut || owner.interrupted()).map_err(problem)?;
    if owner.interrupted() || !Arc::ptr_eq(&key, &active_key(owner)?) || !destination.candidate_ready(owner) {
        return Err(Reason::SourceChanged);
    }
    custody.phase = Phase::ExportCandidate;
    Ok(ChildResult::BackupPublished) // Parent joins/rematch still required.
}

#[cfg(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
fn exclusion_roots(owner: &Arc<OriginalWork>, book: &mut store::StoreBook, roster: &ProjectRoster)
    -> Result<Vec<asset_source::RegisteredRoot>, Reason> {
    let root = book.recheck_root(&mut || owner.interrupted()).map_err(problem)?.registered();
    if roster.roots.len() > 32 || roster.roots.iter().any(|root| root.path.capacity() > asset_source::PATH_LIMIT)
        || root.path.capacity() > asset_source::PATH_LIMIT { return Err(Reason::Capacity); }
    let mut exclusions = Vec::new();
    exclusions.try_reserve_exact(roster.roots.len() + 1).map_err(|_| Reason::Capacity)?;
    if exclusions.capacity() > 33 { return Err(Reason::Capacity); }
    for project in &roster.roots { exclusions.push(project.clone()); }
    exclusions.push(root);
    Ok(exclusions)
}

#[cfg(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
fn import_new(owner: &Arc<OriginalWork>, book: &mut store::StoreBook, custody: &mut Custody, request: &Request)
    -> Result<ChildResult, Reason> {
    let key = active_key(owner)?;
    let Content::ImportNew { identity, record, sources } = &mut custody.content else { return Err(Reason::SourceChanged); };
    if key.identity() != *identity { return Err(Reason::SourceChanged); }
    let record = *record; // Already reserved in this SAME Work before GO.
    let exclusions = exclusion_roots(owner, book, &request.roster)?;
    sources.capture(&exclusions, request.budget.transfer(), owner)?;
    sources.authenticate(request.budget.transfer(), &mut || owner.interrupted())?;
    let retained = sources.retained_bytes().ok_or(Reason::Capacity)?;
    if retained > request.budget.resident { return Err(Reason::Capacity); }
    let allowance = request.budget.working.checked_sub(retained).ok_or(Reason::Capacity)?;
    let candidate = sources.seal_new(&key, record, allowance, &mut || owner.interrupted())?;
    if candidate.revision().counter != 1 { return Err(Reason::VaultCorrupt); }
    let revision = candidate.revision();
    let exact_length = candidate.bytes().len();
    let intent = key.seal_intent(format::Mutation::New, record, None, Some(&candidate)).map_err(crypto_problem)?;
    // Actual ordinary exclusion owner, distinct from the retained input pair's
    // one-shot SourceBook. New/None is fixed here, never selected by a DTO.
    check_exclusions(owner, book, &request.roster)?;
    let effect = book.mutate(&intent, Some(candidate.bytes()), None,
        &mut || owner.interrupted(), &mut || cleanup_expired(owner));
    custody.outcome = book.storage_outcome();
    remember(owner, book, true)?; // Before effect/readback failure can return.
    effect.map_err(problem)?;
    if custody.outcome != Some(store::StorageOutcome { effect: store::Effect::KnownApplied,
        durability: store::Durability::Confirmed, cleanup: store::Cleanup::Known }) {
        return Err(Reason::VaultDurabilityUnknown);
    }
    drop(candidate); // Retained restored input remains charged; no cipher/readback overlap.
    if exact_length.checked_add(crypto::CONTROL_BYTES).is_none_or(|bytes| bytes > allowance) {
        return Err(Reason::Capacity);
    }
    let actual = book.read_record(record, true, &mut || owner.interrupted()).map_err(problem)?;
    let (bytes, witness, complete) = actual.into_parts();
    if !complete || bytes.len() != exact_length
        || bytes.capacity().checked_add(crypto::CONTROL_BYTES).is_none_or(|bytes| bytes > allowance) {
        return Err(Reason::VaultCorrupt);
    }
    let opened = key.open_record(bytes, allowance).map_err(crypto_problem)?;
    if opened.record != record || opened.revision != revision
        || !sources.matches_authenticated_readback(&opened) { return Err(Reason::VaultCorrupt); }
    book.recheck_root(&mut || owner.interrupted()).map_err(problem)?;
    book.recheck_record(&witness, &mut || owner.interrupted()).map_err(problem)?;
    if owner.interrupted() || !Arc::ptr_eq(&key, &active_key(owner)?) { return Err(Reason::UserCancelled); }
    let row = Descriptor { authenticated: crypto::AuthenticatedDescriptor {
        record: opened.record, revision: opened.revision, descriptor: opened.descriptor,
    }, original: witness, mutation_pending: false };
    drop((opened.fields, opened.file));
    custody.saved = Some(row.reference(key.identity()));
    custody.phase = Phase::StoredNew;
    Ok(ChildResult::Mutated { record, row: Some(row) })
}

#[cfg(all(test, debug_assertions, target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
#[path = "credential_backup_component_macos.rs"]
mod component_tests;

/// Before child GO, compare the exact retained unentered import, not a caller
/// preference or result-shaped mutation outcome. Linux has no such content.
pub(super) fn reserved_import(work: &Work, owner_id: u32, identity: format::Identity) -> bool {
    work.inner.as_ref().is_some_and(|inner| inner.try_lock().is_ok_and(|custody| {
        if custody.owner_id != owner_id || custody.phase != Phase::Reserved || custody.first.is_some()
            || custody.saved.is_some() || custody.outcome.is_some() { return false; }
        match &custody.content {
            #[cfg(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
            Content::ImportNew { identity: retained, sources, .. } => *retained == identity && sources.not_started(),
            _ => { let _ = identity; false },
        }
    }))
}

/// A saved descriptor is publishable only for the exact retained import. This
/// supplements, NEVER replaces, actual original joins/current gates/outcome.
pub(super) fn new_publication(work: &Work, identity: format::Identity, record: format::Id, row: &Descriptor) -> bool {
    work.inner.as_ref().is_some_and(|inner| inner.try_lock().is_ok_and(|custody|
        custody.phase == Phase::StoredNew && custody.first.is_none()
            && imported_record(&custody, identity, record)
            && custody.outcome == Some(store::StorageOutcome { effect: store::Effect::KnownApplied,
                durability: store::Durability::Confirmed, cleanup: store::Cleanup::Known })
            && row.authenticated.record == record && row.authenticated.revision.counter == 1
            && custody.saved.is_some_and(|saved| same_reference(saved, row.reference(identity)))))
}

fn imported_record(custody: &Custody, identity: format::Identity, record: format::Id) -> bool {
    match &custody.content {
        #[cfg(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
        Content::ImportNew { identity: held_identity, record: held_record, sources } =>
            *held_identity == identity && *held_record == record && sources.native_settled(),
        _ => { let _ = (identity, record); false },
    }
}

/// Exact current-vault rematch for the parent's post-join PendingPrivateSink
/// projection. Output existence/phase alone does not pass this check. Even a
/// true return remains UNDELIVERED and grants no destination or file write.
pub(super) fn pending_publication(work: &super::Work, session: &Session) -> bool {
    if !session.writable()
        || work.store.as_ref().is_none_or(|store| !Arc::ptr_eq(store, &session.store))
        || work.key.as_ref().is_none_or(|key| session.key.as_ref().is_none_or(|current| !Arc::ptr_eq(key, current))) {
        return false;
    }
    work.backup.inner.as_ref().is_some_and(|inner| inner.try_lock().is_ok_and(|custody| {
        let Content::Export { reference, output: Some(_), .. } = &custody.content else { return false; };
        custody.phase == Phase::PendingPrivateSink && custody.first.is_none()
            && session.identity == Some(reference.identity)
            && session.rows.iter().any(|row| !row.mutation_pending
                && same_reference(*reference, row.reference(reference.identity)))
    }))
}

/// Parent-only post-join projection of the SAME concrete two-file original.
/// No receipt DTO constructs this: both native writes, exclusive renames,
/// durability and original closes remain retained inside the destination book.
pub(super) fn delivered_publication(owner: &Arc<OriginalWork>, work: &super::Work, session: &Session) -> bool {
    if !owner.control_resources_settled()
        || !owner.coordinator.try_lock().is_ok_and(|book| book.handle.is_none() && book.receipt == JoinReceipt::Returned)
        || !owner.child.try_lock().is_ok_and(|book| book.handle.is_none() && book.receipt == JoinReceipt::Returned)
        || work.original_join.is_some() || work.failed_child_join.is_some()
        || !session.writable() || work.release || work.first.is_some() || work.outcome.is_some()
        || work.store.as_ref().is_none_or(|store| !Arc::ptr_eq(store, &session.store))
        || work.key.as_ref().is_none_or(|key| session.key.as_ref().is_none_or(|current| !Arc::ptr_eq(key, current))) {
        return false;
    }
    #[cfg(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
    return work.backup.inner.as_ref().is_some_and(|inner| inner.try_lock().is_ok_and(|custody| {
        let Content::Export { reference, output: Some(_), destination: Some(destination) } = &custody.content
            else { return false; };
        custody.owner_id == owner.id && custody.phase == Phase::ExportCandidate && custody.first.is_none()
            && custody.saved.is_none() && custody.outcome.is_none() && destination.candidate_ready(owner)
            && session.identity == Some(reference.identity)
            && session.rows.iter().any(|row| !row.mutation_pending
                && same_reference(*reference, row.reference(reference.identity)))
    }));
    #[cfg(not(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"))))]
    false // Portable phase/hash/codec DATA can never constitute a private sink.
}

/// A returned child body or pending-sink status is NOT disposal authority. Root
/// invokes this only for an explicit undelivered discard or after the parent's
/// accepted New publication, then moves this Work into its existing Retired
/// holding and counts it until the original off-lock drain has returned.
pub(super) fn retirement_ready(owner: &Arc<OriginalWork>) -> bool {
    if !owner.control_resources_settled() || !owner.retired.load(Ordering::SeqCst)
        || !owner.coordinator.try_lock().is_ok_and(|book| book.handle.is_none() && book.receipt == JoinReceipt::Returned)
        || !owner.child.try_lock().is_ok_and(|book| book.handle.is_none() && book.receipt == JoinReceipt::Returned) {
        return false;
    }
    let Ok(work) = owner.vault.try_lock() else { return false; };
    // A successful cleanup-only continuation must not rehabilitate the first
    // coordinator/child failure that the existing vault owner preserved.
    if !work.settled() || work.original_join.is_some_and(|receipt| receipt != JoinReceipt::Returned)
        || work.failed_child_join.is_some() { return false; }
    let Some(inner) = &work.backup.inner else { return true; };
    if Arc::strong_count(inner) != 1 { return false; }
    inner.try_lock().is_ok_and(|custody| custody.native_settled() && custody.content.disposal_ready()
        && matches!(custody.phase, Phase::Reserved | Phase::PendingPrivateSink | Phase::ExportCandidate | Phase::StoredNew | Phase::Failed)
        && custody.outcome.is_none_or(|outcome| !matches!(outcome.effect, store::Effect::Unknown)
            && !matches!(outcome.durability, store::Durability::Unknown)
            && outcome.cleanup == store::Cleanup::Known))
}

#[cfg(feature = "desktop-shell")]
fn preparation_gate(document: &DocumentBinding, state: &DocumentState, slot: &Slot) -> Result<(), AssetError> {
    document.durable_gate(state, true)?;
    let session = state.vault.as_ref().ok_or_else(AssetError::invalid)?;
    let context = slot.context.as_ref().ok_or_else(|| AssetError::new(Reason::ContextStale))?;
    if !document.context_matches(state, context)? || !state.context.as_ref().is_some_and(|current| Arc::ptr_eq(current, context))
        || context.registry_generation != session.registry_generation || slot.vault.generation != Some(session.registry_generation)
        || slot.owner.interrupted() || slot.reason != Reason::None || slot.cleanup_end.is_some() || !owns(slot, session) {
        return Err(AssetError::new(Reason::ContextStale));
    }
    let work = slot.owner.vault.try_lock().map_err(|_| AssetError::new(Reason::CleanupUnknown))?;
    if !work.backup.empty() || work.first.is_some() || work.release
        || work.store.as_ref().is_none_or(|store| !Arc::ptr_eq(store, &session.store))
        || work.key.as_ref().is_none_or(|key| session.key.as_ref().is_none_or(|current| !Arc::ptr_eq(current, key))) {
        return Err(AssetError::new(Reason::SourceChanged));
    }
    Ok(())
}

#[cfg(feature = "desktop-shell")]
fn retain_request(document: &DocumentBinding, state: &mut DocumentState, slot: &Slot, content: Content,
    kind: RequestKind) -> Result<Request, AssetError> {
    preparation_gate(document, state, slot)?;
    let identity = state.vault.as_ref().and_then(|session| session.identity).ok_or_else(AssetError::invalid)?;
    let roster = document.vault_roster(state)?;
    if slot.vault.generation != Some(roster.generation) { return Err(AssetError::new(Reason::ContextStale)); }
    let custody = Custody { owner_id: slot.owner.id, content, phase: Phase::Reserved, first: None, saved: None, outcome: None };
    let prospective = custody.retained_bytes().ok_or_else(|| AssetError::new(Reason::Capacity))?;
    let live = lookup_memory::pending_slot_bytes(state, slot).map_err(|_| AssetError::new(Reason::Capacity))?
        .checked_add(installation_memory::additional_document_bytes(document, state).map_err(AssetError::new)?)
        .ok_or_else(|| AssetError::new(Reason::Capacity))?;
    // Older lookup census accounts this containing GitHub allocation only
    // with retained loans/history. Preserve its real quiescent overhead too.
    let live = if !state.github.setup_has_material() && !state.github.history_has_retained_data() {
        live.checked_add(state.github.retained_heap_bytes_if_quiescent().ok_or_else(|| AssetError::new(Reason::Capacity))?)
            .ok_or_else(|| AssetError::new(Reason::Capacity))?
    } else { live };
    let budget = Budget::from_live(live, prospective).map_err(AssetError::new)?;
    let mut work = slot.owner.vault.try_lock().map_err(|_| AssetError::new(Reason::CleanupUnknown))?;
    if !work.backup.empty() { return Err(AssetError::new(Reason::Busy)); }
    work.backup.inner = Some(Arc::new(Mutex::new(custody)));
    Ok(Request { owner_id: slot.owner.id, identity, roster, budget, kind })
}

/// Native parent calls after its explicit export action and retained original
/// slot preparation. Absence of a concrete private sink MUST gate the route
/// before this point; creating an undeliverable candidate is not activation.
#[cfg(feature = "desktop-shell")]
pub(super) fn prepare_export(document: &DocumentBinding, state: &mut DocumentState, slot: &Slot, reference: StoredRef)
    -> Result<Request, AssetError> {
    if slot.operation != Operation::PrepareBackupExport { return Err(AssetError::invalid()); }
    let session = state.vault.as_ref().ok_or_else(AssetError::invalid)?;
    let row = session.rows.iter().find(|row| !row.mutation_pending && row.authenticated.record == reference.record)
        .ok_or_else(|| AssetError::new(Reason::SourceChanged))?;
    if session.identity != Some(reference.identity) || !same_reference(row.reference(reference.identity), reference) {
        return Err(AssetError::new(Reason::SourceChanged));
    }
    retain_request(document, state, slot, Content::export(reference, None), RequestKind::Export)
}

/// Only the sealed two-original native selector can construct this concrete
/// destination. Retain it and quote the same original's census BEFORE child GO.
#[cfg(all(feature = "desktop-shell", target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
pub(super) fn prepare_export_to(document: &DocumentBinding, state: &mut DocumentState, slot: &Slot,
    reference: StoredRef, destination: asset_source::BackupDestinations) -> Result<Request, AssetError> {
    if slot.operation != Operation::PrepareBackupExport || !destination.not_started()
        || !slot.owner.credential_backup_destination_scope() {
        return Err(AssetError::invalid());
    }
    let session = state.vault.as_ref().ok_or_else(AssetError::invalid)?;
    if session.identity != Some(reference.identity) || !slot.vault.reference.is_some_and(|held| same_reference(held, reference))
        || !session.rows.iter().any(|row| !row.mutation_pending && same_reference(row.reference(reference.identity), reference)) {
        return Err(AssetError::new(Reason::SourceChanged));
    }
    retain_request(document, state, slot, Content::Export { reference, output: None, destination: Some(destination) }, RequestKind::Export)
}

/// Native parent supplies the pair from its two ORIGINAL private picker phases
/// while retaining both selector originals. There is deliberately no public
/// paths/bytes/code adapter or constructed selector/finality token here.
#[cfg(all(feature = "desktop-shell", target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
pub(super) fn prepare_import(document: &DocumentBinding, state: &mut DocumentState, slot: &Slot, sources: asset_source::BackupSources)
    -> Result<Request, AssetError> {
    if slot.operation != Operation::ImportBackup || slot.target.is_some() || !sources.not_started() {
        return Err(AssetError::invalid());
    }
    preparation_gate(document, state, slot)?;
    let session = state.vault.as_mut().ok_or_else(AssetError::invalid)?;
    if session.rows.len() >= store::DESCRIPTOR_COUNT { return Err(AssetError::new(Reason::Capacity)); }
    // Reserve the parent's existing publication cells BEFORE any source read
    // or durable effect. The later authenticated New publication cannot grow
    // an unquoted row/inventory allocation, including after a delayed readback.
    session.rows.try_reserve_exact(store::DESCRIPTOR_COUNT - session.rows.len())
        .map_err(|_| AssetError::new(Reason::Capacity))?;
    session.inventory.try_reserve_exact(store::DESCRIPTOR_COUNT.saturating_sub(session.inventory.len()))
        .map_err(|_| AssetError::new(Reason::Capacity))?;
    if session.rows.capacity() > store::DESCRIPTOR_COUNT || session.inventory.capacity() > store::DESCRIPTOR_COUNT {
        return Err(AssetError::new(Reason::Capacity));
    }
    let key = session.key.as_ref().ok_or_else(|| AssetError::new(Reason::VaultKeyMissing))?;
    let identity = key.identity();
    let record = key.new_record_id(&session.inventory).map_err(|error| AssetError::new(crypto_problem(error)))?;
    retain_request(document, state, slot, Content::ImportNew { identity, record, sources }, RequestKind::ImportNew)
}

/// Runs only through the parent's SAME retained native child/receipt path.
#[cfg(feature = "desktop-shell")]
pub(super) async fn run(document: &DocumentBinding, owner: &Arc<OriginalWork>, request: Request) -> Result<super::super::Staged, Reason> {
    let mutation = request.mutation();
    let generation = request.roster.generation;
    {
        let mut state = document.lock();
        current_gate(document, &state, owner)?;
        let operation = state.slot.as_ref().map(|slot| slot.operation);
        let expected = if mutation { Operation::ImportBackup } else { Operation::PrepareBackupExport };
        if operation != Some(expected) { return Err(Reason::SourceChanged); }
        // The original request is already retained. Mark this one New intent
        // before its actual child GO, after native selection/preparation and
        // while holding the genuine current document gate. No second install.
        if mutation { begin_backup_import(&mut state, owner)?; }
    }
    let result = native(document, owner, Child::Backup(request)).await?;
    let state = document.lock(); current_gate(document, &state, owner)?;
    match result {
        ChildResult::BackupPrepared if !mutation => Ok(super::super::Staged::Vault(Staged::BackupPending { generation })),
        ChildResult::BackupPublished if !mutation => Ok(super::super::Staged::Vault(Staged::BackupDelivered { generation })),
        ChildResult::Mutated { record, row: Some(row) } if mutation =>
            Ok(super::super::Staged::Vault(Staged::Mutated { record, row: Some(row), generation })),
        _ => Err(Reason::CleanupUnknown),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asset_commands::{self as commands, Kind};

    fn id(byte: u8) -> format::Id { format::Id::from_bytes([byte; 16]).unwrap() }
    fn reference() -> StoredRef {
        let identity = format::Identity::new(id(1), id(2)).unwrap();
        let revision = format::Revision::new(id(4), 1).unwrap();
        StoredRef { identity, record: id(3), revision, original: store::ReadWitness::lifecycle_data(id(3), revision) }
    }
    fn synthetic_output() -> backup::ExportedBackup {
        let fields = commands::own_fields(Kind::AndroidKeystore, &serde_json::json!({
            "storePassword":"synthetic-only", "keyAlias":"synthetic", "keyPassword":"synthetic-only"
        })).ok().unwrap();
        let descriptor = format::Descriptor::new(Kind::AndroidKeystore, None, vec![true; 3], true).unwrap();
        backup::export(&descriptor, &fields, Some(b"NOT-A-REAL-KEY"), format::WORKING_BYTES).unwrap()
    }
    fn held(output: Option<backup::ExportedBackup>, phase: Phase) -> Work {
        Work { inner: Some(Arc::new(Mutex::new(Custody { owner_id: 7,
            content: Content::export(reference(), output), phase,
            first: None, saved: None, outcome: None }))) }
    }
    fn owner_data(phase: Phase) -> (DocumentState, Arc<OriginalWork>) {
        // Inert native-book DATA only. No worker, descriptor, picker, account,
        // process or native close is entered by this fixture constructor.
        let owner = OriginalWork::artifact_unentered_original_data();
        owner.set_endpoint(None);
        let holding = held(Some(synthetic_output()), phase);
        holding.inner.as_ref().unwrap().lock().unwrap().owner_id = owner.id;
        owner.vault.lock().unwrap().backup = holding;
        let mut state = crate::asset_session::tests::empty_state();
        state.session = false;
        let mut slot = Slot::new(owner.clone(), Operation::PrepareBackupExport, None, None, None);
        slot.phase = crate::asset_session::Phase::Selected;
        state.slot = Some(slot);
        (state, owner)
    }
    fn live(state: &DocumentState, owner: &Arc<OriginalWork>) -> usize {
        let source = owner.source.lock().unwrap();
        let retirement = owner.retirement.lock().unwrap();
        lookup_memory::live_bytes(state, owner, &source, &retirement).unwrap()
    }
    fn joined_data(owner: &Arc<OriginalWork>) {
        // Predicate DATA only, not a producer/finality fixture. The production
        // path still obtains these from original retained handle joins.
        owner.coordinator.lock().unwrap().receipt = JoinReceipt::Returned;
        owner.child.try_lock().unwrap().receipt = JoinReceipt::Returned;
    }

    #[test]
    fn full_random_revision_and_original_witness_are_not_counter_aliases() {
        let original = reference();
        assert!(same_reference(original, original));
        for changed in [
            StoredRef { identity: format::Identity::new(id(1), id(9)).unwrap(), ..original },
            StoredRef { record: id(5), ..original },
            StoredRef { revision: format::Revision::new(id(6), 1).unwrap(), ..original },
            StoredRef { revision: format::Revision::new(id(4), 2).unwrap(), ..original },
            StoredRef { original: store::ReadWitness::lifecycle_data(id(5), original.revision), ..original },
        ] { assert!(!same_reference(original, changed)); }
    }

    #[test]
    fn pending_or_failed_private_output_is_still_charged_and_blocks_reuse() {
        let work = held(Some(synthetic_output()), Phase::PendingPrivateSink);
        let bytes = work.retained_bytes().unwrap();
        assert!(work.native_settled() && work.blocks_reuse() && work.pending_private_sink());
        // Actual pure custody transition only, NOT a forged native postcheck
        // receipt. Failure retains the exact output rather than recomputing it.
        work.inner.as_ref().unwrap().lock().unwrap().fail(Reason::SourceChanged);
        assert!(work.native_settled() && work.blocks_reuse() && !work.pending_private_sink());
        assert_eq!(work.retained_bytes(), Some(bytes));
        assert!(matches!(&work.inner.as_ref().unwrap().lock().unwrap().content, Content::Export { output: Some(_), .. }));
    }

    #[test]
    fn running_producer_and_pending_sink_are_different_not_disposal_receipts() {
        let work = held(None, Phase::Running);
        assert!(!work.native_settled() && work.blocks_reuse());
        work.inner.as_ref().unwrap().lock().unwrap().phase = Phase::PendingPrivateSink;
        assert!(work.native_settled() && work.blocks_reuse());
        assert!(!work.pending_private_sink()); // No output even if phase DATA lies.
        let row = Descriptor { authenticated: crypto::AuthenticatedDescriptor { record: id(3), revision: reference().revision,
            descriptor: format::Descriptor::new(Kind::GoogleWif, None, vec![false; 2], false).unwrap() },
            original: reference().original, mutation_pending: false };
        assert!(!new_publication(&work, reference().identity, id(3), &row));
        // Result-shaped phase/effect DATA still cannot turn the EXPORT content
        // into a New-only import or authorize publishing a new vault record.
        {
            let mut custody = work.inner.as_ref().unwrap().lock().unwrap();
            custody.phase = Phase::StoredNew;
            custody.saved = Some(reference());
            custody.outcome = Some(store::StorageOutcome { effect: store::Effect::KnownApplied,
                durability: store::Durability::Confirmed, cleanup: store::Cleanup::Known });
        }
        assert!(!new_publication(&work, reference().identity, id(3), &row));
    }

    #[test]
    fn allocation_quotes_refuse_before_full_record_or_output_allocation() {
        assert!(Budget::from_live(store::RESIDENT_BYTES, 1).is_err());
        assert!(Budget::from_live(usize::MAX, 1).is_err());
        let quote = Budget { resident: 1024, working: crypto::CONTROL_BYTES + 2048 };
        assert!(quote.before_record_read(2048).is_ok());
        assert!(quote.before_record_read(2049).is_err());
        assert!(quote.before_record_read(usize::MAX).is_err());
        assert_eq!(quote.export_allowance(0).unwrap(), 1024);
        assert!(quote.export_allowance(usize::MAX).is_err());
    }

    #[test]
    fn original_capture_failure_latches_once_without_renewal_or_native_receipt() {
        // Existing inert constructor: no producer/native call has entered.
        let owner = OriginalWork::artifact_unentered_original_data();
        let deadline = owner.endpoint();
        owner.credential_backup_failed(Reason::SourceChanged);
        let first = owner.vault.lock().unwrap().first;
        assert!(first.is_some_and(|(reason, _)| reason == Reason::SourceChanged));
        assert!(owner.stopped());
        owner.credential_backup_failed(Reason::CleanupUnknown);
        assert!(owner.vault.lock().unwrap().first == first);
        assert_eq!(owner.endpoint(), deadline);
        assert!(owner.coordinator.lock().unwrap().receipt == JoinReceipt::New);
        assert!(owner.child.try_lock().unwrap().receipt == JoinReceipt::New);
        assert!(!retirement_ready(&owner));
    }

    #[test]
    fn original_sink_timestamp_and_cleanup_ceiling_are_not_restarted() {
        // Timestamp/cancellation DATA only, no native snapshot or file opens.
        let owner = OriginalWork::artifact_unentered_original_data();
        let deadline = owner.endpoint();
        let at = Instant::now().checked_sub(Duration::from_millis(1)).unwrap();
        owner.credential_backup_sink_failed_at(Reason::SourceChanged, at);
        assert!(owner.vault.lock().unwrap().first == Some((Reason::SourceChanged, at)));
        owner.credential_backup_sink_failed_at(Reason::CleanupUnknown, Instant::now());
        assert!(owner.vault.lock().unwrap().first == Some((Reason::SourceChanged, at)));
        assert_eq!(owner.endpoint(), deadline);
        assert!(owner.stopped());
        *owner.cleanup_end.lock().unwrap() = Some(at);
        assert!(owner.credential_backup_sink_cleanup_expired());
        assert!(owner.coordinator.lock().unwrap().receipt == JoinReceipt::New);
    }

    #[test]
    fn candidate_phase_output_and_join_data_without_concrete_sink_never_deliver() {
        // The current-reference and join DATA here deliberately looks suitable;
        // it still cannot manufacture the absent original two-file private sink.
        let (_, owner) = owner_data(Phase::ExportCandidate);
        joined_data(&owner);
        let identity = reference().identity;
        let storage = Arc::new(Mutex::new(store::StoreBook::new()));
        let key = Arc::new(crypto::lifecycle_data_key(identity));
        let mut session = Session::new(storage.clone(), 1);
        session.state = State::Unlocked; session.identity = Some(identity); session.key = Some(key.clone());
        session.rows.push(Descriptor { authenticated: crypto::AuthenticatedDescriptor {
            record: reference().record, revision: reference().revision,
            descriptor: format::Descriptor::new(Kind::AndroidKeystore, None, vec![true; 3], true).unwrap(),
        }, original: reference().original, mutation_pending: false });
        let mut work = owner.vault.lock().unwrap(); work.store = Some(storage); work.key = Some(key);
        assert!(!delivered_publication(&owner, &work, &session));
        assert!(work.backup.native_settled() && work.backup.blocks_reuse());
        assert!(!work.backup.pending_private_sink());
    }

    #[test]
    fn parent_census_retains_same_backup_across_off_lock_holding_and_restore() {
        let (mut state, owner) = owner_data(Phase::PendingPrivateSink);
        let (bytes, original) = {
            let work = owner.vault.lock().unwrap();
            (work.backup_retained_bytes().unwrap(), Arc::downgrade(work.backup.inner.as_ref().unwrap()))
        };
        let occupied = live(&state, &owner);
        assert!(bytes > 0 && super::super::backup_pending(&state));
        joined_data(&owner);
        let mut slot = state.slot.take().unwrap();
        slot.discard = true; // A generic STOP/discard flag is not this consent.
        let refused = super::super::take_retirement(&mut state, &mut slot);
        assert!(refused.backup.empty() && owner.vault.lock().unwrap().backup_blocks_reuse());
        super::super::request_backup_discard(&mut slot);
        let retired = super::super::take_retirement(&mut state, &mut slot);
        assert!(!retired.empty() && retired.backup.retained_bytes() == Some(bytes));
        assert!(owner.vault.lock().unwrap().backup.empty());
        assert!(owner.retain_retirement(crate::asset_session::Retirement {
            vault: retired, ..Default::default()
        }).is_ok());
        state.slot = Some(slot);
        assert_eq!(live(&state, &owner), occupied); // A move is not memory credit.
        let mut slot = state.slot.take().unwrap();
        let retired = {
            let mut holding = owner.retirement.lock().unwrap();
            std::mem::take(&mut holding.vault)
        };
        owner.retired.store(true, Ordering::SeqCst);
        super::super::restore_retirement(&mut state, &mut slot, retired);
        state.slot = Some(slot);
        assert_eq!(live(&state, &owner), occupied);
        assert_eq!(Arc::as_ptr(owner.vault.lock().unwrap().backup.inner.as_ref().unwrap()), original.as_ptr());
        let mut slot = state.slot.take().unwrap();
        let retired = super::super::take_retirement(&mut state, &mut slot);
        assert!(owner.retain_retirement(crate::asset_session::Retirement {
            vault: retired, ..Default::default()
        }).is_ok());
        state.slot = Some(slot);
        assert_eq!(live(&state, &owner), occupied);
        assert!(owner.release_retirement()); // Actual off-lock private DATA drop.
        assert!(original.upgrade().is_none());
        assert_eq!(live(&state, &owner), occupied - bytes);
    }

    #[test]
    fn explicit_discard_cannot_dispose_failed_join_or_unknown_original_outcome() {
        let (mut state, owner) = owner_data(Phase::Failed);
        joined_data(&owner);
        let mut slot = state.slot.take().unwrap();
        super::super::request_backup_discard(&mut slot);
        let bytes = owner.vault.lock().unwrap().backup_retained_bytes();
        owner.child.try_lock().unwrap().receipt = JoinReceipt::Failed;
        assert!(!retirement_ready(&owner));
        assert!(super::super::take_retirement(&mut state, &mut slot).backup.empty());
        owner.child.try_lock().unwrap().receipt = JoinReceipt::Returned;
        for outcome in [
            store::StorageOutcome { effect: store::Effect::Unknown, durability: store::Durability::Confirmed, cleanup: store::Cleanup::Known },
            store::StorageOutcome { effect: store::Effect::KnownApplied, durability: store::Durability::Unknown, cleanup: store::Cleanup::Known },
            store::StorageOutcome { effect: store::Effect::KnownApplied, durability: store::Durability::Confirmed, cleanup: store::Cleanup::Unknown },
            store::StorageOutcome { effect: store::Effect::NotStarted, durability: store::Durability::NotRun, cleanup: store::Cleanup::Pending },
        ] {
            owner.vault.lock().unwrap().backup.inner.as_ref().unwrap().lock().unwrap().outcome = Some(outcome);
            assert!(!retirement_ready(&owner));
            assert!(super::super::take_retirement(&mut state, &mut slot).backup.empty());
            assert_eq!(owner.vault.lock().unwrap().backup_retained_bytes(), bytes);
        }
    }

    #[test]
    fn quiescent_private_custody_is_not_an_empty_session_or_exit() {
        for phase in [Phase::PendingPrivateSink, Phase::Failed] {
            let (mut state, owner) = owner_data(phase);
            state.session = true; state.lock_pending = true;
            joined_data(&owner);
            if phase == Phase::Failed {
                owner.vault.lock().unwrap().backup.inner.as_ref().unwrap().lock().unwrap().outcome = Some(store::StorageOutcome {
                    effect: store::Effect::Unknown, durability: store::Durability::Unknown, cleanup: store::Cleanup::Known });
            }
            assert!(owner.resources_settled()); // Producer predicate DATA, not secret disposal.
            assert!(!crate::asset_session::slot_private_data_empty(state.slot.as_ref().unwrap()));
            assert!(!crate::asset_session::session_data_empty(&state));
            assert!(!crate::asset_session::assets_can_exit_locked(&state));
            assert!(!crate::asset_session::complete_empty_session_lock(&mut state));
            assert!(state.session && state.lock_pending);
            let mut slot = state.slot.take().unwrap();
            slot.stop(Reason::Shutdown, Instant::now()); // Generic STOP does not grant private disposal.
            let refused = super::super::take_retirement(&mut state, &mut slot);
            assert!(refused.backup.empty());
            super::super::request_backup_discard(&mut slot);
            let retired = super::super::take_retirement(&mut state, &mut slot);
            if phase == Phase::Failed {
                assert!(retired.backup.empty()); state.slot = Some(slot);
                assert!(!crate::asset_session::session_data_empty(&state));
                assert!(!crate::asset_session::complete_empty_session_lock(&mut state));
                continue; // Unknown effects keep the SAME private holding.
            }
            assert!(!retired.backup.empty());
            let original = Arc::downgrade(retired.backup.inner.as_ref().unwrap());
            assert!(owner.retain_retirement(crate::asset_session::Retirement { vault: retired, ..Default::default() }).is_ok());
            state.slot = Some(slot);
            assert!(owner.vault.lock().unwrap().backup.empty());
            assert!(!crate::asset_session::slot_private_data_empty(state.slot.as_ref().unwrap()));
            assert!(!crate::asset_session::session_data_empty(&state));
            assert!(!crate::asset_session::assets_can_exit_locked(&state));
            assert!(original.upgrade().is_some());
            assert!(owner.release_retirement()); // Actual off-lock private DATA drain, not a flag-only refund.
            assert!(original.upgrade().is_none());
            assert!(crate::asset_session::slot_private_data_empty(state.slot.as_ref().unwrap()));
            assert!(crate::asset_session::session_data_empty(&state));
            assert!(crate::asset_session::assets_can_exit_locked(&state));
            assert!(crate::asset_session::complete_empty_session_lock(&mut state));
            assert!(!state.session && !state.lock_pending);
            let work = owner.vault.lock().unwrap();
            assert!(!crate::asset_session::slot_private_data_empty(state.slot.as_ref().unwrap()));
            drop(work);
            let retirement = owner.retirement.lock().unwrap();
            assert!(!crate::asset_session::slot_private_data_empty(state.slot.as_ref().unwrap()));
            drop(retirement);
        }
    }

    #[test]
    fn successful_cleanup_cannot_rehabilitate_a_retained_failed_original_join() {
        for (coordinator, child) in [
            (Some(JoinReceipt::Failed), None), (Some(JoinReceipt::New), None),
            (Some(JoinReceipt::Pending), None), (Some(JoinReceipt::Returned), Some(JoinReceipt::Failed)),
        ] {
            let (mut state, owner) = owner_data(Phase::Failed);
            joined_data(&owner); // Current cleanup Returned DATA only.
            {
                let mut work = owner.vault.lock().unwrap();
                work.original_join = coordinator; work.failed_child_join = child;
            }
            assert!(owner.resources_settled()); // Native quiescence stays separate.
            assert!(!retirement_ready(&owner));
            let mut slot = state.slot.take().unwrap();
            super::super::request_backup_discard(&mut slot);
            assert!(super::super::take_retirement(&mut state, &mut slot).backup.empty());
            assert!(owner.vault.lock().unwrap().backup_blocks_reuse());
        }
        let (_, owner) = owner_data(Phase::PendingPrivateSink); joined_data(&owner);
        owner.vault.lock().unwrap().original_join = Some(JoinReceipt::Returned);
        assert!(retirement_ready(&owner)); // Preserved *normal* original is not a failure.
    }

    #[test]
    fn retained_request_exception_never_admits_other_work_or_reuses_output() {
        let (state, owner) = owner_data(Phase::Reserved);
        {
            let mut work = owner.vault.lock().unwrap();
            work.store = Some(Arc::new(Mutex::new(store::StoreBook::new())));
            work.key = Some(Arc::new(crypto::lifecycle_data_key(reference().identity)));
            let mut custody = work.backup.inner.as_ref().unwrap().lock().unwrap();
            // Reserved export has not allocated output yet. This constructor's
            // synthetic output is disposed here only for admission DATA tests.
            custody.content = Content::export(reference(), None);
        }
        let mut request = Request { owner_id: owner.id, identity: reference().identity,
            roster: ProjectRoster { generation: 1, roots: Vec::new() },
            budget: Budget { resident: 1024, working: 2048 }, kind: RequestKind::Export };
        assert!(!owner.lookup_allocations_allowed());
        assert!(super::super::backup_pending(&state));
        assert!(!crate::asset_session::child_allocation_admitted(&owner, &ChildJob::Tokens));
        assert!(child_admitted(&owner, &request)); // DATA gate, not an entered child.
        request.owner_id += 1; assert!(!child_admitted(&owner, &request)); request.owner_id = owner.id;
        assert!(!reserved_import(&owner.vault.lock().unwrap().backup, owner.id, request.identity));
        for phase in [Phase::Running, Phase::PendingPrivateSink, Phase::ExportCandidate, Phase::StoredNew, Phase::Failed] {
            owner.vault.lock().unwrap().backup.inner.as_ref().unwrap().lock().unwrap().phase = phase;
            assert!(!child_admitted(&owner, &request));
        }
        assert!(!owner.lookup_allocations_allowed());
        assert!(crate::asset_session::idle(&state).is_err());
    }

    #[cfg(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
    #[test]
    fn unentered_import_never_copies_a_different_store_outcome() {
        // Actual parent dispatch, but the wrong original ID refuses before
        // any native file acquisition or mutation. The inert StoreBook has
        // no outcome; it must not replace this original's initial New intent.
        let owner = OriginalWork::artifact_unentered_original_data();
        owner.set_endpoint(None);
        let initial = store::StorageOutcome { effect: store::Effect::NotStarted,
            durability: store::Durability::NotRun, cleanup: store::Cleanup::Pending };
        {
            let mut work = owner.vault.lock().unwrap();
            work.store = Some(Arc::new(Mutex::new(store::StoreBook::new())));
            work.key = Some(Arc::new(crypto::lifecycle_data_key(reference().identity)));
            work.outcome = Some(initial);
            work.backup.inner = Some(Arc::new(Mutex::new(Custody { owner_id: owner.id,
                content: Content::ImportNew { identity: reference().identity, record: id(8),
                    sources: asset_source::BackupSources::new([
                        "/private/synthetic-backup.mrkbackup".into(),
                        "/private/synthetic-recovery.mrkcode".into(),
                    ]).unwrap() }, phase: Phase::Reserved, first: None, saved: None, outcome: None })));
        }
        let request = Request { owner_id: owner.id + 1, identity: reference().identity,
            roster: ProjectRoster { generation: 1, roots: Vec::new() },
            budget: Budget { resident: 1024, working: 2048 }, kind: RequestKind::ImportNew };
        assert!(matches!(super::super::execute(&owner, Child::Backup(request)), Err(Reason::UserCancelled)));
        let work = owner.vault.lock().unwrap();
        assert!(work.outcome == Some(initial));
        assert!(work.store.as_ref().unwrap().lock().unwrap().storage_outcome().is_none());
        assert!(work.backup.native_settled() && work.backup.blocks_reuse());
    }

    #[cfg(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
    #[test]
    fn unknown_import_custody_cannot_be_an_empty_session_after_cleanup() {
        let (mut state, owner) = owner_data(Phase::Failed);
        state.session = true; state.lock_pending = true;
        state.slot.as_mut().unwrap().operation = Operation::ImportBackup;
        joined_data(&owner);
        {
            // Input paths and unknown outcome DATA only; no actual filesystem,
            // encrypted import or store mutation is entered by this fixture.
            let mut work = owner.vault.lock().unwrap();
            work.original_join = Some(JoinReceipt::Returned);
            let mut custody = work.backup.inner.as_ref().unwrap().lock().unwrap();
            custody.content = Content::ImportNew { identity: reference().identity, record: id(8),
                sources: asset_source::BackupSources::new(["/private/synthetic-backup.mrkbackup".into(),
                    "/private/synthetic-recovery.mrkcode".into()]).unwrap() };
            custody.outcome = Some(store::StorageOutcome { effect: store::Effect::Unknown,
                durability: store::Durability::Unknown, cleanup: store::Cleanup::Known });
        }
        assert!(owner.resources_settled());
        assert!(!crate::asset_session::slot_private_data_empty(state.slot.as_ref().unwrap()));
        assert!(!crate::asset_session::session_data_empty(&state));
        assert!(!crate::asset_session::assets_can_exit_locked(&state));
        assert!(!crate::asset_session::complete_empty_session_lock(&mut state));
        let mut slot = state.slot.take().unwrap();
        super::super::request_backup_discard(&mut slot);
        assert!(super::super::take_retirement(&mut state, &mut slot).backup.empty());
        assert!(owner.vault.lock().unwrap().backup_blocks_reuse());
    }

    #[cfg(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
    #[test]
    fn closed_pair_with_unknown_or_unsynced_publication_stays_on_original_across_discard() {
        for unsynced in [false, true] {
            let (mut state, owner) = owner_data(Phase::Failed);
            joined_data(&owner); // Prior DATA predicate checks, no native/test worker.
            {
                let work = owner.vault.lock().unwrap();
                let mut custody = work.backup.inner.as_ref().unwrap().lock().unwrap();
                let Content::Export { destination, .. } = &mut custody.content else { unreachable!() };
                *destination = Some(if unsynced {
                    asset_source::BackupDestinations::unsynced_publication_predicate_data(&owner)
                } else { asset_source::BackupDestinations::unknown_effect_predicate_data(&owner) });
            }
            let bytes = owner.vault.lock().unwrap().backup_retained_bytes();
            assert!(owner.resources_settled());
            assert!(owner.vault.lock().unwrap().backup.recovery_required());
            assert!(!retirement_ready(&owner));
            let mut slot = state.slot.take().unwrap();
            super::super::request_backup_discard(&mut slot);
            assert!(super::super::take_retirement(&mut state, &mut slot).backup.empty());
            assert_eq!(owner.vault.lock().unwrap().backup_retained_bytes(), bytes);
            assert!(!crate::asset_session::slot_private_data_empty(&slot));
        }
    }
}
