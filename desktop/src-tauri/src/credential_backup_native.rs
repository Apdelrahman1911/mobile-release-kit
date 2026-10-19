//! Fixed portable-backup facets of the EXISTING asset_session_vault owner.
//!
//! Root integrates this child into OriginalWork/Child/Job and the exact census;
//! it is not a second worker, arbitrary-path command or source of authorization.
//! Neither a successful codec nor the return below is worker/coordinator join,
//! delivered export, native capture qualification, assessment or assignment.
//!
//! No concrete two-destination private sink exists yet. Production export
//! routes therefore stay unavailable: this facet can retain an encrypted
//! candidate, but has no byte getter, callback, delivered receipt or sink grant.
use super::*;
use crypto::backup;

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
enum Phase { Reserved, Running, PendingPrivateSink, StoredNew, Failed }

enum Content {
    Export { reference: StoredRef, output: Option<backup::ExportedBackup> },
    #[cfg(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
    ImportNew { identity: format::Identity, record: format::Id, sources: asset_source::BackupSources },
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
            Content::Export { output, .. } => output.as_ref().map_or(Some(0), backup::ExportedBackup::retained_bytes)?,
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
            Content::Export { .. } => true,
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
    pub(super) fn pending_private_sink(&self) -> bool {
        self.inner.as_ref().is_some_and(|value| value.try_lock().is_ok_and(|value|
            value.phase == Phase::PendingPrivateSink && value.first.is_none()
                && matches!(&value.content, Content::Export { output: Some(_), .. })))
    }
}

/// Created by the locked, native document preparation below; no serialized
/// budget/context or result-shaped message constructs this original request.
pub(super) struct Request {
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
        (Content::Export { reference, output: None }, RequestKind::Export) => reference.identity == request.identity,
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
    if let Err(reason) = result { custody.fail(reason); }
    result
}

fn export_current(owner: &Arc<OriginalWork>, book: &mut store::StoreBook, custody: &mut Custody, request: &Request)
    -> Result<ChildResult, Reason> {
    let reference = match &custody.content {
        Content::Export { reference, output: None } => *reference, _ => return Err(Reason::SourceChanged),
    };
    let key = active_key(owner)?;
    if key.identity() != reference.identity { return Err(Reason::SourceChanged); }
    check_exclusions(owner, book, &request.roster)?;
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
    if owner.interrupted() { return Err(Reason::UserCancelled); }
    custody.phase = Phase::PendingPrivateSink;
    Ok(ChildResult::BackupPrepared)
}

#[cfg(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
fn import_new(owner: &Arc<OriginalWork>, book: &mut store::StoreBook, custody: &mut Custody, request: &Request)
    -> Result<ChildResult, Reason> {
    let key = active_key(owner)?;
    let Content::ImportNew { identity, record, sources } = &mut custody.content else { return Err(Reason::SourceChanged); };
    if key.identity() != *identity { return Err(Reason::SourceChanged); }
    let record = *record; // Already reserved in this SAME Work before GO.
    let root = book.recheck_root(&mut || owner.interrupted()).map_err(problem)?.registered();
    if request.roster.roots.len() > 32 || request.roster.roots.iter().any(|root| root.path.capacity() > asset_source::PATH_LIMIT)
        || root.path.capacity() > asset_source::PATH_LIMIT { return Err(Reason::Capacity); }
    let mut exclusions = Vec::new();
    exclusions.try_reserve_exact(request.roster.roots.len() + 1).map_err(|_| Reason::Capacity)?;
    if exclusions.capacity() > 33 { return Err(Reason::Capacity); }
    for project in &request.roster.roots { exclusions.push(project.clone()); }
    exclusions.push(root);
    sources.capture(&exclusions, request.budget.transfer(), owner)?;
    sources.authenticate(request.budget.transfer(), &mut || owner.interrupted())?;
    let retained = sources.retained_bytes().ok_or(Reason::Capacity)?;
    if retained > request.budget.resident { return Err(Reason::Capacity); }
    let allowance = request.budget.working.checked_sub(retained).ok_or(Reason::Capacity)?;
    let candidate = sources.seal_new(&key, record, allowance, &mut || owner.interrupted())?;
    if candidate.revision().counter != 1 { return Err(Reason::VaultCorrupt); }
    let revision = candidate.revision();
    let intent = key.seal_intent(format::Mutation::New, record, None, Some(&candidate)).map_err(crypto_problem)?;
    // Actual ordinary exclusion owner, distinct from the retained input pair's
    // one-shot SourceBook. New/None is fixed here, never selected by a DTO.
    check_exclusions(owner, book, &request.roster)?;
    let effect = book.mutate(&intent, Some(candidate.bytes()), None,
        &mut || owner.interrupted(), &mut || cleanup_expired(owner));
    custody.outcome = book.storage_outcome();
    remember(owner, book, true)?; // Before effect/readback failure can return.
    effect.map_err(problem)?;
    drop(candidate); // Release ciphertext BEFORE bounded descriptor readback.
    let row = descriptor(book, &key, record, allowance, owner)?;
    if row.authenticated.record != record || row.authenticated.revision != revision
        || row.authenticated.descriptor.kind != sources.kind()? { return Err(Reason::VaultCorrupt); }
    book.recheck_record(&row.original, &mut || owner.interrupted()).map_err(problem)?;
    if owner.interrupted() { return Err(Reason::UserCancelled); }
    custody.saved = Some(row.reference(key.identity()));
    custody.phase = Phase::StoredNew;
    Ok(ChildResult::Mutated { record, row: Some(row) })
}

/// A saved descriptor is publishable only for the exact retained import. This
/// predicate supplements, NEVER replaces, the parent's actual original joins,
/// current document/vault/registry gate and KnownApplied+durable+cleanup checks.
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
        let Content::Export { reference, output: Some(_) } = &custody.content else { return false; };
        custody.phase == Phase::PendingPrivateSink && custody.first.is_none()
            && session.identity == Some(reference.identity)
            && session.rows.iter().any(|row| !row.mutation_pending
                && same_reference(*reference, row.reference(reference.identity)))
    }))
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
    if !work.settled() { return false; }
    let Some(inner) = &work.backup.inner else { return true; };
    if Arc::strong_count(inner) != 1 { return false; }
    inner.try_lock().is_ok_and(|custody| custody.native_settled()
        && matches!(custody.phase, Phase::Reserved | Phase::PendingPrivateSink | Phase::StoredNew | Phase::Failed)
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
    let live = lookup_memory::pending_slot_bytes(state, slot).map_err(|_| AssetError::new(Reason::Capacity))?;
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
    retain_request(document, state, slot, Content::Export { reference, output: None }, RequestKind::Export)
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
        let state = document.lock();
        current_gate(document, &state, owner)?;
        let operation = state.slot.as_ref().map(|slot| slot.operation);
        let expected = if mutation { Operation::ImportBackup } else { Operation::PrepareBackupExport };
        if operation != Some(expected) { return Err(Reason::SourceChanged); }
    }
    let result = native(document, owner, Child::Backup(request)).await?;
    let state = document.lock(); current_gate(document, &state, owner)?;
    match result {
        ChildResult::BackupPrepared if !mutation => Ok(super::super::Staged::Vault(Staged::BackupPending { generation })),
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
            content: Content::Export { reference: reference(), output }, phase,
            first: None, saved: None, outcome: None }))) }
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
}
