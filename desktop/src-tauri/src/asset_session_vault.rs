//! Finite durable data in the existing document/slot/original-child lifecycle.
//! This is not a second owner. The native store is the same retained original
//! book from inspection until explicit release; keys never become IPC DATA.
use super::*;
use crate::{vault_crypto as crypto, vault_format as format, vault_store as store};

// Compiler/codec tests and a same-UID service are not native qualification.
const DURABLE_QUALIFIED: bool = false;

pub(crate) struct KeyringInitializationAdmission { identity: format::Identity }
impl KeyringInitializationAdmission {
    pub(crate) fn into_identity(self) -> format::Identity { self.identity }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum State { Uninitialized, Locked, Unlocked, Initializing, Mutating, Interrupted, Unknown }
impl State {
    fn name(self) -> &'static str { match self {
        Self::Uninitialized => "uninitialized", Self::Locked => "locked", Self::Unlocked => "unlocked",
        Self::Initializing => "initializing", Self::Mutating => "mutating", Self::Interrupted => "interrupted", Self::Unknown => "unknown",
    } }
}

#[derive(Clone, Copy)]
pub(super) struct StoredRef {
    identity: format::Identity, record: format::Id, revision: format::Revision, original: store::ReadWitness,
}
impl StoredRef {
    fn key(self) -> RecordKey { RecordKey { id: Token(self.record.token()), revision: self.revision.counter } }
    fn matches(self, key: &RecordKey) -> bool { self.revision.counter == key.revision && self.record.token() == key.id.0 }
}
pub(super) struct StoredMaterial { pub(super) bytes: crypto::StoredBytes, reference: StoredRef }
struct Descriptor { authenticated: crypto::AuthenticatedDescriptor, original: store::ReadWitness, mutation_pending: bool }
impl Descriptor {
    fn key(&self) -> RecordKey { RecordKey { id: Token(self.authenticated.record.token()), revision: self.authenticated.revision.counter } }
    fn matches(&self, key: &RecordKey) -> bool { self.authenticated.record.token() == key.id.0 && self.authenticated.revision.counter == key.revision }
    fn reference(&self, identity: format::Identity) -> StoredRef {
        StoredRef { identity, record: self.authenticated.record, revision: self.authenticated.revision, original: self.original }
    }
}
pub(super) struct Session {
    store: Arc<Mutex<store::StoreBook>>, root: Option<store::RootWitness>, header: Option<[u8; format::HEADER_BYTES]>,
    identity: Option<format::Identity>, key: Option<Arc<crypto::VaultKey>>, rows: Vec<Descriptor>, inventory: Vec<format::Id>,
    state: State, reason: Reason, revoked: bool, read_only: bool, registry_generation: u32, release_end: Option<Instant>,
}
impl Session {
    fn new(store: Arc<Mutex<store::StoreBook>>, generation: u32) -> Self {
        Self { store, root: None, header: None, identity: None, key: None, rows: Vec::new(), inventory: Vec::new(),
            state: State::Unknown, reason: Reason::None, revoked: false, read_only: false, registry_generation: generation, release_end: None }
    }
    fn writable(&self) -> bool { !self.revoked && !self.read_only && self.state == State::Unlocked && self.key.is_some() }
    fn row(&self, key: &RecordKey) -> Option<&Descriptor> { self.rows.iter().find(|row| row.matches(key)) }
    pub(super) fn data_bytes(&self) -> Option<usize> {
        let mut total = std::mem::size_of::<Self>().checked_add(self.rows.capacity().checked_mul(std::mem::size_of::<Descriptor>())?)?
            .checked_add(self.inventory.capacity().checked_mul(std::mem::size_of::<format::Id>())?)?;
        for row in &self.rows { total = total.checked_add(row.authenticated.descriptor.retained_bytes().ok()?)?; }
        if let Some(root) = &self.root { total = total.checked_add(root.retained_bytes()?)?; }
        Some(total)
    }
    pub(super) fn store(&self) -> &Arc<Mutex<store::StoreBook>> { &self.store }
    pub(super) fn key(&self) -> Option<&Arc<crypto::VaultKey>> { self.key.as_ref() }
}

#[derive(Default)]
pub(super) struct Work {
    store: Option<Arc<Mutex<store::StoreBook>>>, key: Option<Arc<crypto::VaultKey>>, outcome: Option<store::StorageOutcome>,
    first: Option<(Reason, Instant)>, release: bool, release_end: Option<Instant>, release_claimed: bool,
    // The exact first coordinator receipt survives the one cleanup-only
    // continuation. That continuation reuses this OriginalWork/child slot; it
    // cannot turn failure/STOP into a second work attempt or a renewed lease.
    original_join: Option<JoinReceipt>, failed_child_join: Option<JoinReceipt>,
}

#[derive(Default)]
pub(super) struct Retired {
    pub(super) session: Option<Session>, pub(super) keys: [Option<Arc<crypto::VaultKey>>; 2],
    pub(super) loaded: Option<Arc<Payload>>, label: Option<String>, rows: Vec<Descriptor>,
}
impl Retired {
    pub(super) fn empty(&self) -> bool {
        self.session.is_none() && self.keys.iter().all(Option::is_none) && self.loaded.is_none() && self.label.is_none() && self.rows.capacity() == 0
    }
    pub(super) fn data_bytes(&self) -> Option<usize> {
        std::mem::size_of::<Self>().checked_add(self.label.as_ref().map_or(0, String::capacity))?.checked_add(rows_bytes(&self.rows)?)
    }
}
impl Work {
    pub(super) fn store_ref(&self) -> Option<&Arc<Mutex<store::StoreBook>>> { self.store.as_ref() }
    pub(super) fn key_ref(&self) -> Option<&Arc<crypto::VaultKey>> { self.key.as_ref() }
    pub(super) fn settled(&self) -> bool {
        self.store.as_ref().is_none_or(|store| store.try_lock().is_ok_and(|book| book.not_started() || book.settled() || !self.release && book.operation_quiescent()))
    }
    fn store(&self) -> Result<Arc<Mutex<store::StoreBook>>, Reason> { self.store.clone().ok_or(Reason::VaultCorrupt) }
    fn key(&self) -> Result<Arc<crypto::VaultKey>, Reason> { self.key.clone().ok_or(Reason::VaultKeyMissing) }
    fn fail(&mut self, reason: Reason, at: Instant) { if self.first.is_none() { self.first = Some((reason, at)); } }
}
#[derive(Default)]
pub(super) struct SlotData {
    pub(super) label: Option<String>, pub(super) loaded: Option<Arc<Payload>>, reference: Option<StoredRef>,
    initialize: Option<format::Identity>, generation: Option<u32>, pub(super) lease: Option<Arc<Mutex<store::StoreBook>>>,
    outcome: Option<store::StorageOutcome>,
}

pub(super) fn mode(state: &DocumentState) -> bool { state.vault.is_some() }
pub(super) fn writable(state: &DocumentState) -> bool { state.vault.as_ref().is_some_and(Session::writable) }
pub(super) fn context_gate(state: &DocumentState, generation: u32) -> Result<(), AssetError> {
    if let Some(vault) = &state.vault {
        if !vault.writable() { return Err(AssetError::new(vault.reason_for_access())); }
        if vault.registry_generation != generation { return Err(AssetError::new(Reason::ExclusionUnconfirmed)); }
    }
    Ok(())
}
impl Session {
    fn reason_for_access(&self) -> Reason {
        if self.reason != Reason::None { self.reason } else if self.revoked { Reason::Closed }
        else if self.key.is_none() { Reason::VaultKeyringLocked } else { Reason::VaultInterrupted }
    }
}
pub(super) fn physical_root(state: &DocumentState) -> Option<asset_source::RegisteredRoot> {
    state.vault.as_ref().and_then(|vault| vault.root.as_ref()).map(store::RootWitness::registered)
}
pub(super) fn projection(state: &DocumentState) -> Option<PersistenceStatus> {
    state.vault.as_ref().map(|vault| PersistenceStatus { state: if vault.revoked && !matches!(vault.state, State::Interrupted | State::Unknown) { "locked" } else { vault.state.name() }, reason: vault.reason,
        key_access: if vault.revoked || vault.key.is_none() { "locked" }
            else if vault.state == State::Interrupted && vault.read_only { "read-only" }
            else if matches!(vault.state, State::Unlocked | State::Mutating) && !vault.read_only { "read-write" }
            else { "locked" } })
}
pub(super) fn outcome(slot: &Slot) -> Option<StorageStatus> {
    slot.vault.outcome.map(|outcome| StorageStatus {
        effect: match outcome.effect { store::Effect::NotStarted => "not-started", store::Effect::KnownNone => "known-none", store::Effect::KnownApplied => "known-applied", store::Effect::Unknown => "unknown" },
        durability: match outcome.durability { store::Durability::NotRun => "not-run", store::Durability::Confirmed => "confirmed", store::Durability::Unknown => "unknown" },
        cleanup: match outcome.cleanup { store::Cleanup::Pending => "pending", store::Cleanup::Known => "known", store::Cleanup::Unknown => "unknown" },
    })
}
pub(super) fn summaries(state: &DocumentState) -> Vec<RecordStatus> {
    let Some(vault) = &state.vault else { return Vec::new(); };
    if vault.revoked || vault.key.is_none() || !matches!(vault.state, State::Unlocked | State::Mutating | State::Interrupted) { return Vec::new(); }
    vault.rows.iter().map(|row| {
        let key = row.key();
        let assigned = vault.writable() && state.assignments.iter().any(|assignment| assignment.record_id == key.id && assignment.record_revision == key.revision
            && assignment.availability == AssignmentAvailability::Available);
        let assessed = vault.writable() && record_assessed(state, &key);
        RecordStatus { record_id: key.id, revision: key.revision, kind: row.authenticated.descriptor.kind,
            availability: if row.mutation_pending { "mutation-pending" } else if assigned { "assigned" } else { "unassigned" },
            storage: "encrypted", label: row.authenticated.descriptor.label.clone(), payload_state: if assessed { "assessed" } else { "not-checked" } }
    }).collect()
}

pub(super) fn authority_visible(state: &DocumentState) -> bool {
    state.vault.as_ref().is_none_or(Session::writable)
}

fn rows_bytes(rows: &Vec<Descriptor>) -> Option<usize> {
    let mut total = rows.capacity().checked_mul(std::mem::size_of::<Descriptor>())?;
    for row in rows { total = total.checked_add(row.authenticated.descriptor.retained_bytes().ok()?)?; }
    Some(total)
}

impl Staged {
    pub(super) fn retained_bytes(&self) -> Option<usize> {
        let dynamic = match self {
            Self::Opened { observation, .. } => observation.records.capacity().checked_mul(std::mem::size_of::<format::Id>())?
                .checked_add(observation.root.as_ref().map_or(Some(0), store::RootWitness::retained_bytes)?)?,
            Self::Prepared { root, tokens, .. } => root.retained_bytes()?.checked_add(token_bytes(tokens)?)?,
            Self::Unlocked { rows, .. } => rows_bytes(rows)?,
            Self::DeletedPreview { tokens, .. } => token_bytes(tokens)?,
            Self::Mutated { row, .. } => row.as_ref().map_or(Some(0), |row| row.authenticated.descriptor.retained_bytes().ok())?,
            Self::Released => 0,
        };
        std::mem::size_of::<Self>().checked_add(dynamic)
    }
}
fn token_bytes(tokens: &TokenBatch) -> Option<usize> {
    tokens.selection.0.capacity().checked_add(tokens.record.0.capacity())?
        .checked_add(tokens.preview.0.capacity())?.checked_add(tokens.bind.0.capacity())
}

/// Memory-only publication after the original coordinator/child/SDK joins.
/// The caller temporarily removed its slot; compare that exact original rather
/// than trying to recover authority through a status projection/current number.
pub(super) fn publish(document: &DocumentBinding, state: &mut DocumentState, slot: &mut Slot, staged: Staged) {
    let valid = (|| -> Result<(), Reason> {
        if state.stopping || state.unknown || state.lock_pending || state.quit_pending || !state.lifetime.original_bound()
            || slot.cleanup_end.is_some() || slot.reason != Reason::None || slot.owner.interrupted() {
            return Err(Reason::UserCancelled);
        }
        let session = state.vault.as_ref().ok_or(Reason::Closed)?;
        let work = slot.owner.vault.try_lock().map_err(|_| Reason::CleanupUnknown)?;
        if session.revoked || work.first.is_some() || work.release
            || work.store.as_ref().is_none_or(|original| !Arc::ptr_eq(original, &session.store)) {
            return Err(Reason::VaultInterrupted);
        }
        let generation = slot.vault.generation.ok_or(Reason::ExclusionUnconfirmed)?;
        if document.inner.bridge.native_generation().map_err(|error| error.reason)? != generation { return Err(Reason::ExclusionUnconfirmed); }
        match &staged {
            Staged::Opened { observation, generation: checked } => {
                if slot.operation != Operation::OpenVault || *checked != generation || !session.rows.is_empty() || session.key.is_some()
                    || observation.records.len() > store::DESCRIPTOR_COUNT { return Err(Reason::VaultCorrupt); }
                header_identity(observation)?;
            },
            Staged::Prepared { identity, tokens, generation: checked, .. } => {
                if slot.operation != Operation::PrepareInitialize || *checked != generation || session.state != State::Uninitialized
                    || session.key.is_some() || !tokens_distinct(tokens) || slot.vault.initialize.is_some()
                    || session.identity.is_some() || identity.vault == identity.generation { return Err(Reason::VaultCorrupt); }
            },
            Staged::Unlocked { rows, initialized_header } => {
                let key = work.key.as_ref().ok_or(Reason::VaultKeyMissing)?;
                if !session.rows.is_empty() || session.key.is_some() || rows.len() > store::DESCRIPTOR_COUNT { return Err(Reason::VaultCorrupt); }
                if let Some(header) = initialized_header {
                    if slot.operation != Operation::Initialize || session.state != State::Initializing || !rows.is_empty()
                        || session.identity.is_some() || session.header.is_some() { return Err(Reason::VaultCorrupt); }
                    format::Header::parse(header, key.identity()).map_err(|_| Reason::VaultCorrupt)?;
                    if work.outcome != Some(store::StorageOutcome { effect: store::Effect::KnownApplied,
                        durability: store::Durability::Confirmed, cleanup: store::Cleanup::Known }) { return Err(Reason::VaultDurabilityUnknown); }
                } else if slot.operation != Operation::Unlock || !matches!(session.state, State::Locked | State::Interrupted)
                    || session.identity != Some(key.identity()) || session.header.is_none()
                    || rows.len() != session.inventory.len() || rows.iter().enumerate().any(|(index, row)|
                        !session.inventory.contains(&row.authenticated.record) || rows[index + 1..].iter().any(|other| other.authenticated.record == row.authenticated.record)) {
                    return Err(Reason::VaultCorrupt);
                }
            },
            Staged::DeletedPreview { reference, tokens } => {
                if slot.operation != Operation::PrepareDelete || !session.writable() || !tokens_distinct(tokens)
                    || session.identity != Some(reference.identity) || slot.target.as_ref().is_none_or(|target| !reference.matches(target))
                    || session.row(&reference.key()).is_none_or(|row| !row.mutation_pending || row.original != reference.original
                        || row.authenticated.revision != reference.revision) { return Err(Reason::SourceChanged); }
            },
            Staged::Mutated { record, row, generation: checked } => {
                if slot.operation != Operation::Commit || *checked != generation || session.state != State::Mutating || session.read_only
                    || session.key.is_none() || work.outcome != Some(store::StorageOutcome { effect: store::Effect::KnownApplied,
                        durability: store::Durability::Confirmed, cleanup: store::Cleanup::Known }) { return Err(Reason::VaultDurabilityUnknown); }
                let previous = session.rows.iter().find(|value| value.authenticated.record == *record);
                match (previous, row) {
                    (None, Some(row)) if row.authenticated.record == *record && row.authenticated.revision.counter == 1
                        && session.rows.len() < store::DESCRIPTOR_COUNT && slot.target.is_none() => {},
                    (Some(previous), Some(row)) if row.authenticated.record == *record && previous.mutation_pending
                        && previous.authenticated.revision.counter.checked_add(1) == Some(row.authenticated.revision.counter)
                        && previous.authenticated.revision.random != row.authenticated.revision.random
                        && slot.target.as_ref().is_some_and(|target| previous.matches(target)) => {},
                    (Some(previous), None) if previous.mutation_pending && slot.target.as_ref().is_some_and(|target| previous.matches(target)) => {},
                    _ => return Err(Reason::SourceChanged),
                }
            },
            Staged::Released => return Err(Reason::UserCancelled), // Cleanup cannot publish work authority.
        }
        Ok(())
    })();
    if let Err(reason) = valid {
        slot.staged = Some(super::Staged::Vault(staged)); slot.error = Some(AssetError::new(reason).into());
        slot.stop(reason, Instant::now()); return;
    }
    let session = state.vault.as_mut().expect("validated retained vault");
    match staged {
        Staged::Opened { observation, generation } => {
            session.identity = header_identity(&observation).ok().flatten();
            session.state = match observation.state { store::Inspection::Uninitialized => State::Uninitialized, store::Inspection::Locked => State::Locked,
                store::Inspection::Interrupted => State::Interrupted, store::Inspection::Corrupt => State::Unknown };
            session.reason = match observation.state { store::Inspection::Uninitialized => Reason::VaultUninitialized, store::Inspection::Locked => Reason::None,
                store::Inspection::Interrupted => Reason::VaultInterrupted, store::Inspection::Corrupt => Reason::VaultCorrupt };
            session.read_only = observation.state == store::Inspection::Interrupted;
            session.root = observation.root; session.header = observation.header; session.inventory = observation.records; session.registry_generation = generation;
            slot.phase = Phase::Idle; slot.settlement = Settlement::Known; slot.review_end = None;
        },
        Staged::Prepared { root, identity, tokens, generation } => {
            session.root = Some(root); session.registry_generation = generation; slot.vault.initialize = Some(identity);
            offer_preview(state, slot, Preview { token: tokens.preview, action: Action::Initialize, bind_token: None,
                record: None, subject: PreviewSubject::Vault { change: InitializeChange::Initialize } });
            slot.settlement = Settlement::Known;
        },
        Staged::Unlocked { rows, initialized_header } => {
            let owner = slot.owner.clone();
            let Ok(mut work) = owner.vault.try_lock() else {
                slot.staged = Some(super::Staged::Vault(Staged::Unlocked { rows, initialized_header }));
                slot.stop(Reason::CleanupUnknown, Instant::now()); return;
            };
            // Take the already-authenticated opaque key from its charged original
            // custody. No byte getter, new lookup or renderer-provided key exists.
            let Some(key) = work.key.take() else { slot.stop(Reason::VaultKeyMissing, Instant::now()); return; };
            if let Some(header) = initialized_header { session.identity = Some(key.identity()); session.header = Some(header); session.state = State::Unlocked; session.read_only = false; }
            if session.state != State::Interrupted { session.state = State::Unlocked; session.reason = Reason::None; }
            else { session.read_only = true; session.reason = Reason::VaultInterrupted; }
            session.key = Some(key); session.rows = rows;
            session.registry_generation = slot.vault.generation.expect("validated generation");
            slot.phase = Phase::Idle; slot.settlement = Settlement::Known; slot.review_end = None;
        },
        Staged::DeletedPreview { reference, tokens } => {
            slot.vault.reference = Some(reference);
            let key = reference.key();
            let kind = session.row(&key).expect("validated descriptor").authenticated.descriptor.kind;
            offer_preview(state, slot, Preview { token: tokens.preview, action: Action::Delete, bind_token: None, record: Some(key.clone()),
                subject: PreviewSubject::new(kind, SubjectChange::Delete, Some(&key)) });
            slot.settlement = Settlement::Known;
        },
        Staged::Mutated { record, row, generation } => {
            publish_saved_revision(session, slot, record, row, generation);
        },
        Staged::Released => unreachable!("cleanup has no publication authority"),
    }
}
// Bounded memory transition only, called after publish's actual native,
// identity/generation, effect, durability and finality checks above.
fn publish_saved_revision(session: &mut Session, slot: &mut Slot, record: format::Id, row: Option<Descriptor>, generation: u32) {
    if let Some(index) = session.rows.iter().position(|value| value.authenticated.record == record) { session.rows.remove(index); }
    session.inventory.retain(|value| *value != record);
    if let Some(row) = row { session.inventory.push(record); slot.result_record = Some(row.key()); session.rows.push(row); }
    session.state = State::Unlocked; session.reason = Reason::None; session.registry_generation = generation;
    // Save authenticates the descriptor only. A separate explicit load,
    // payload authentication/core assessment and Bind review is required.
    slot.assessment = None; slot.assessment_context_revision = None; slot.preview = None; slot.selection = None;
    slot.phase = Phase::Idle; slot.settlement = Settlement::Known; slot.discard = true; slot.review_end = None;
}
pub(super) fn target(state: &DocumentState, reference: Option<commands::RecordRef<'_>>, kind: Kind) -> Result<Option<RecordKey>, AssetError> {
    let vault = state.vault.as_ref().ok_or_else(AssetError::invalid)?;
    let Some(reference) = reference else {
        if vault.rows.len() >= store::DESCRIPTOR_COUNT { return Err(AssetError::new(Reason::Capacity)); }
        return Ok(None);
    };
    let key = own_record(reference)?;
    if !vault.row(&key).is_some_and(|row| row.authenticated.descriptor.kind == kind && !row.mutation_pending) { return Err(AssetError::invalid()); }
    Ok(Some(key))
}
pub(super) fn has_record(state: &DocumentState, key: &RecordKey, kind: Kind) -> bool {
    state.vault.as_ref().and_then(|vault| vault.row(key)).is_some_and(|row| row.authenticated.descriptor.kind == kind)
}
pub(super) fn pending(state: &DocumentState, key: &RecordKey) -> bool {
    state.vault.as_ref().and_then(|vault| vault.row(key)).is_some_and(|row| row.mutation_pending)
}
pub(super) fn usable(state: &DocumentState, slot: &Slot, key: &RecordKey, kind: Kind) -> bool {
    writable(state) && state.vault.as_ref().and_then(|vault| vault.row(key)).is_some_and(|row| !row.mutation_pending && row.authenticated.descriptor.kind == kind)
        && slot.vault.reference.is_some_and(|reference| reference.matches(key))
        && slot.vault.loaded.as_ref().is_some_and(|payload| payload.kind == kind && payload.usable_source())
}
pub(super) fn revoke(state: &mut DocumentState, key: &RecordKey) {
    if let Some(row) = state.vault.as_mut().and_then(|vault| vault.rows.iter_mut().find(|row| row.matches(key))) { row.mutation_pending = true; }
}
fn owns(slot: &Slot, session: &Session) -> bool {
    slot.vault.lease.as_ref().is_some_and(|store| Arc::ptr_eq(store, &session.store))
}
pub(super) fn completed_context_receipt(state: &DocumentState) -> bool {
    let Some(session) = &state.vault else { return false; };
    let Some(slot) = &state.slot else { return false; };
    if state.unknown || state.stopping || state.lock_pending || state.quit_pending || state.retiring || state.exhausted
        || !state.lifetime.original_bound() || !session.writable() || !owns(slot, session)
        || slot.phase != Phase::Idle || slot.settlement != Settlement::Known || slot.reason != Reason::None
        || slot.cleanup_end.is_some() || slot.error.is_some() || slot.owner.interrupted() || !slot.owner.resources_settled()
        || slot.candidate.is_some() || slot.staged.is_some() || slot.retired_payload.is_some() || slot.vault.loaded.is_some() {
        return false;
    }
    // The current context can retire DATA from this completed receipt, not
    // cancel its healthy vault lease. Failed/late/merely-body-ended work never
    // supplies this exemption; its original STOP and cleanup clocks still win.
    slot.owner.coordinator.try_lock().is_ok_and(|book| book.receipt == JoinReceipt::Returned && book.handle.is_none())
        && slot.owner.child.try_lock().is_ok_and(|book| matches!(book.receipt, JoinReceipt::New | JoinReceipt::Returned) && book.handle.is_none())
        && slot.owner.cleanup_end.try_lock().is_ok_and(|end| end.is_none())
        && slot.owner.vault.try_lock().is_ok_and(|work| work.first.is_none() && !work.release && work.release_end.is_none() && work.key.is_none()
            && work.store.as_ref().is_some_and(|store| Arc::ptr_eq(store, &session.store)))
}
fn request_release(state: &mut DocumentState, at: Instant) -> bool {
    let Some(session) = &mut state.vault else { return false; };
    let affected = state.slot.as_ref().filter(|slot| owns(slot, session));
    release_lease(session, affected, at)
}
fn release_lease(session: &mut Session, affected: Option<&Slot>, at: Instant) -> bool {
    let mut end = affected.map_or(at + CLEANUP, |slot| slot.cleanup_end.unwrap_or_else(|| first_cleanup_end(at, slot.owner.endpoint(), slot.review_end)));
    // A native failure can predate this later coordinator/status observer.
    if let Ok(book) = session.store.try_lock() { if let Some(first) = book.problem_at() { end = end.min(first + CLEANUP); } }
    let changed = !session.revoked || session.release_end.is_none_or(|old| end < old);
    session.revoked = true; session.release_end = Some(session.release_end.map_or(end, |old| old.min(end)));
    if let Some(slot) = affected {
        if let Ok(mut work) = slot.owner.vault.try_lock() {
            work.release = true;
            work.release_end = Some(work.release_end.map_or(end, |old| old.min(end)));
        }
    }
    changed
}
pub(super) fn revoke_all(state: &mut DocumentState) { request_release(state, Instant::now()); }
pub(super) fn observe_stop(state: &mut DocumentState, now: Instant) -> bool {
    let affected = state.vault.as_ref().is_some_and(|session| state.slot.as_ref().is_some_and(|slot|
        owns(slot, session) && (slot.cleanup_end.is_some() || slot.owner.stopped())));
    if affected || state.unknown || state.stopping || state.lock_pending || !state.lifetime.original_bound() { request_release(state, now) } else { false }
}
pub(super) fn observe_detached_stop(state: &mut DocumentState, slot: &Slot, now: Instant) {
    // Reconciliation temporarily takes the SAME original slot out of state.
    // Reattach its clock before releasing the document gate; status projection
    // or a failed join never substitutes an unrelated observer-now deadline.
    let Some(session) = &mut state.vault else { return; };
    let affected = owns(slot, session);
    if affected && (slot.cleanup_end.is_some() || slot.owner.stopped()) || state.unknown || state.stopping
        || state.lock_pending || !state.lifetime.original_bound() {
        release_lease(session, affected.then_some(slot), now);
    }
}
pub(super) fn release_pending(state: &DocumentState) -> bool { state.vault.as_ref().is_some_and(|session| session.revoked) }
pub(super) fn operation_attached(slot: &Slot) -> bool {
    slot.vault.lease.is_some()
}
fn unrelated_retired(session: &Session, slot: &Slot) -> bool {
    !owns(slot, session) && slot.owner.resources_settled()
        && (slot.phase == Phase::Idle || slot.phase == Phase::Unknown && slot.settlement == Settlement::LateKnown)
}
pub(super) fn late_cleanup_install(state: &DocumentState, slot: &Slot) -> bool {
    let Some(session) = &state.vault else { return false; };
    let Some(end) = session.release_end else { return false; };
    if !state.unknown || !session.revoked || slot.operation != Operation::Lock || !owns(slot, session)
        || !slot.owner.stopped() || slot.cleanup_end != Some(end)
        || !state.slot.as_ref().is_some_and(|old| old.phase == Phase::Unknown && old.settlement == Settlement::LateKnown
            && unrelated_retired(session, old)) { return false; }
    slot.owner.vault.try_lock().is_ok_and(|work| work.release && work.release_claimed && work.release_end == Some(end)
        && work.key.is_none() && work.store.as_ref().is_some_and(|store| Arc::ptr_eq(store, &session.store)))
}
pub(super) fn preserve_operation(slot: &Slot) -> bool {
    slot.vault.lease.is_some() && matches!(slot.operation, Operation::Initialize | Operation::Commit)
}
pub(super) fn controls_released(owner: &OriginalWork) -> bool {
    owner.control_resources_settled() && owner.retired.load(Ordering::SeqCst)
        && owner.keyring.try_lock().is_ok_and(|book| book.allocations_released())
}
pub(super) fn retirement_ready(state: &DocumentState, slot: &Slot) -> bool {
    release_pending(state) && operation_attached(slot) && controls_released(&slot.owner)
}
pub(super) fn take_retirement(state: &mut DocumentState, slot: &mut Slot) -> Retired {
    let closing = release_pending(state);
    let mut retired = Retired { loaded: slot.vault.loaded.take(), label: slot.vault.label.take(), ..Retired::default() };
    slot.vault.reference = None;
    if let Ok(mut work) = slot.owner.vault.try_lock() { retired.keys[0] = work.key.take(); }
    if closing {
        if let Some(session) = &mut state.vault {
            retired.keys[1] = session.key.take(); retired.rows = std::mem::take(&mut session.rows);
        }
        let settled = state.vault.as_ref().is_some_and(|session| session.store.try_lock().is_ok_and(|book| book.not_started() || book.settled()));
        if settled { retired.session = state.vault.take(); }
    }
    retired
}
pub(super) fn restore_retirement(state: &mut DocumentState, slot: &mut Slot, mut retired: Retired) {
    slot.vault.loaded = retired.loaded.take(); slot.vault.label = retired.label.take();
    if let Some(session) = retired.session.take() { state.vault = Some(session); }
    if let Some(session) = &mut state.vault {
        if !retired.rows.is_empty() { session.rows = std::mem::take(&mut retired.rows); }
        if retired.keys[1].is_some() { session.key = retired.keys[1].take(); }
    }
    if retired.keys[0].is_some() {
        // All original executions were joined before this retirement attempt.
        // Preserve opaque key custody even after a poisoned bookkeeping mutex;
        // the caller records Unknown, never treats this recovery as authority.
        let mut work = match slot.owner.vault.lock() { Ok(work) => work, Err(error) => error.into_inner() };
        work.key = retired.keys[0].take();
    }
}
pub(super) fn initialize_preview_valid(state: &DocumentState, slot: &Slot, preview: &Preview) -> bool {
    matches!(preview.subject, PreviewSubject::Vault { change: InitializeChange::Initialize }) && preview.action == Action::Initialize
        && slot.operation == Operation::PrepareInitialize && slot.vault.initialize.is_some() && preview.record.is_none() && preview.bind_token.is_none()
        && state.vault.as_ref().is_some_and(|vault| vault.state == State::Uninitialized && !vault.revoked && vault.key.is_none())
}
pub(super) fn problem(problem: store::Problem) -> Reason { match problem {
    store::Problem::Busy => Reason::Busy, store::Problem::Bounds => Reason::Capacity,
    store::Problem::UnsupportedFilesystem => Reason::UnsupportedFilesystem,
    store::Problem::Interrupted => Reason::VaultInterrupted, store::Problem::CleanupUnknown => Reason::CleanupUnknown,
    store::Problem::DurabilityUnknown => Reason::VaultDurabilityUnknown, store::Problem::Stopped => Reason::UserCancelled,
    store::Problem::Identity | store::Problem::UnsupportedEntry => Reason::ExclusionUnconfirmed,
    store::Problem::State | store::Problem::Native | store::Problem::Corrupt => Reason::VaultCorrupt,
} }
fn crypto_problem(error: crypto::Error) -> Reason {
    match error { crypto::Error::Bounds => Reason::Capacity, crypto::Error::Random => Reason::SourceRefused, _ => Reason::VaultCorrupt }
}
fn header_identity(observation: &store::Observation) -> Result<Option<format::Identity>, Reason> {
    match (&observation.reservation, &observation.header) {
        (Some(reservation), Some(header)) => {
            let identity = format::Identity::parse_reservation(reservation).map_err(|_| Reason::VaultCorrupt)?;
            format::Header::parse(header, identity).map_err(|_| Reason::VaultCorrupt)?; Ok(Some(identity))
        },
        (None, None) if observation.state == store::Inspection::Uninitialized => Ok(None),
        (_, None) if observation.state == store::Inspection::Interrupted => Ok(None),
        _ => Err(Reason::VaultCorrupt),
    }
}

fn attach(owner: &Arc<OriginalWork>, session: &Session, key: bool, release: bool) -> Result<(), AssetError> {
    let mut work = owner.vault.lock().map_err(|_| AssetError::new(Reason::CleanupUnknown))?;
    if work.store.is_some() { return Err(AssetError::new(Reason::CleanupUnknown)); }
    work.store = Some(session.store.clone()); work.key = if key { session.key.clone() } else { None }; work.release = release; Ok(())
}

#[cfg(feature = "desktop-shell")]
pub(super) fn attach_asset_slot(state: &DocumentState, slot: &mut Slot) -> Result<(), AssetError> {
    if matches!(slot.operation, Operation::ChooseProject | Operation::ChooseProjectPath | Operation::ChooseEvidenceFolder | Operation::InspectEvidence) {
        return Ok(());
    }
    if let Some(session) = &state.vault {
        let attached = slot.owner.vault.try_lock().map_err(|_| AssetError::new(Reason::CleanupUnknown))?.store.is_some();
        if !attached { attach(&slot.owner, session, false, false)?; }
        else if slot.owner.vault.try_lock().map_err(|_| AssetError::new(Reason::CleanupUnknown))?.store.as_ref()
            .is_none_or(|store| !Arc::ptr_eq(store, &session.store)) { return Err(AssetError::new(Reason::CleanupUnknown)); }
        slot.vault.lease = Some(session.store.clone());
        if slot.vault.generation.is_none() { slot.vault.generation = Some(session.registry_generation); }
    }
    Ok(())
}

pub(super) fn registered_generation(state: &mut DocumentState, generation: u32) {
    if let Some(session) = &mut state.vault { session.registry_generation = generation; }
}

pub(super) enum Child {
    Open { location: store::Location, roster: ProjectRoster },
    PrepareInitialize { proposed: format::Identity, root: Option<asset_source::RegisteredRoot>, roster: ProjectRoster },
    Reserve { identity: format::Identity, roster: ProjectRoster },
    PublishHeader([u8; format::HEADER_BYTES]),
    List { records: Vec<format::Id>, roster: ProjectRoster, allowance: usize },
    Load { reference: StoredRef, roster: ProjectRoster, allowance: usize },
    ReviewDelete { reference: StoredRef, roster: ProjectRoster, allowance: usize },
    Mutate { operation: format::Mutation, record: format::Id, expected: Option<StoredRef>, payload: Option<Arc<Payload>>, label: Option<String>, roster: ProjectRoster, allowance: usize },
    Check { reference: StoredRef, roster: ProjectRoster },
    Release,
}
impl Child {
    pub(super) fn large(&self) -> bool { matches!(self, Self::List { .. } | Self::Load { .. } | Self::ReviewDelete { .. } | Self::Mutate { .. }) }
    pub(super) fn cleanup(&self) -> bool { matches!(self, Self::Release) }
}
pub(super) enum ChildResult {
    Opened(store::Observation), Prepared { root: store::RootWitness, identity: format::Identity, tokens: TokenBatch },
    Reserved(format::Identity), Header, Listed(Vec<Descriptor>), Loaded { payload: Arc<Payload>, reference: StoredRef },
    Delete { reference: StoredRef, tokens: TokenBatch }, Mutated { record: format::Id, row: Option<Descriptor> }, Checked, Released,
}
pub(super) enum Staged {
    Opened { observation: store::Observation, generation: u32 },
    Prepared { root: store::RootWitness, identity: format::Identity, tokens: TokenBatch, generation: u32 },
    Unlocked { rows: Vec<Descriptor>, initialized_header: Option<[u8; format::HEADER_BYTES]> },
    DeletedPreview { reference: StoredRef, tokens: TokenBatch },
    Mutated { record: format::Id, row: Option<Descriptor>, generation: u32 }, Released,
}
#[cfg(feature = "desktop-shell")]
pub(super) enum Job {
    Open { location: store::Location, roster: ProjectRoster },
    PrepareInitialize { root: Option<asset_source::RegisteredRoot>, roster: ProjectRoster },
    Initialize { identity: format::Identity, roster: ProjectRoster },
    Unlock { identity: format::Identity, header: [u8; format::HEADER_BYTES], records: Vec<format::Id>, roster: ProjectRoster },
    Load { reference: StoredRef, roster: ProjectRoster, context: Arc<NativeContext>, allowance: usize },
    Delete { reference: StoredRef, roster: ProjectRoster, allowance: usize },
    Mutate { operation: format::Mutation, record: format::Id, expected: Option<StoredRef>, payload: Option<Arc<Payload>>, label: Option<String>, roster: ProjectRoster, allowance: usize },
    Bind { reference: StoredRef, roster: ProjectRoster, assignment: Assignment }, Release,
}

pub(super) fn cleanup_expired(owner: &OriginalWork) -> bool {
    let end = owner.vault.try_lock().ok().and_then(|work| work.release_end)
        .or_else(|| owner.cleanup_end.lock().ok().and_then(|end| *end)).or_else(|| owner.endpoint());
    end.is_none_or(|end| Instant::now() >= end)
}
fn native_store(owner: &Arc<OriginalWork>) -> Result<Arc<Mutex<store::StoreBook>>, Reason> {
    owner.vault.lock().map_err(|_| Reason::CleanupUnknown)?.store()
}
fn active_key(owner: &Arc<OriginalWork>) -> Result<Arc<crypto::VaultKey>, Reason> {
    owner.vault.lock().map_err(|_| Reason::CleanupUnknown)?.key()
}
fn exclusions(owner: &Arc<OriginalWork>, root: Option<&asset_source::RegisteredRoot>, roster: &ProjectRoster) -> Result<asset_source::VaultAbsentExclusion, Reason> {
    let mut source = owner.source.lock().map_err(|_| Reason::CleanupUnknown)?;
    asset_source::probe_vault_exclusion(&mut source, root, &roster.roots, &mut || owner.interrupted())
}
fn check_exclusions(owner: &Arc<OriginalWork>, book: &mut store::StoreBook, roster: &ProjectRoster) -> Result<(), Reason> {
    let root = book.recheck_root(&mut || owner.interrupted()).map_err(problem)?.registered();
    exclusions(owner, Some(&root), roster)?; Ok(())
}
fn remember(owner: &Arc<OriginalWork>, book: &store::StoreBook, mutation: bool) -> Result<(), Reason> {
    let mut work = owner.vault.lock().map_err(|_| Reason::CleanupUnknown)?;
    if mutation { work.outcome = book.storage_outcome(); }
    if let Some(error) = book.problem() { work.fail(problem(error), book.problem_at().unwrap_or_else(Instant::now)); }
    Ok(())
}
fn descriptor(book: &mut store::StoreBook, key: &crypto::VaultKey, record: format::Id, allowance: usize, owner: &OriginalWork) -> Result<Descriptor, Reason> {
    let original = book.read_record(record, false, &mut || owner.interrupted()).map_err(problem)?;
    let (bytes, original, complete) = original.into_parts();
    if complete { return Err(Reason::VaultCorrupt); }
    let authenticated = key.open_descriptor(&bytes, allowance).map_err(crypto_problem)?;
    if authenticated.record != record { return Err(Reason::VaultCorrupt); }
    Ok(Descriptor { authenticated, original, mutation_pending: false })
}
fn match_descriptor(row: &Descriptor, reference: StoredRef, key: &crypto::VaultKey) -> Result<(), Reason> {
    if reference.identity != key.identity() || row.authenticated.record != reference.record
        || row.authenticated.revision != reference.revision || row.original != reference.original { return Err(Reason::SourceChanged); }
    Ok(())
}
fn initial_outcome(book: &store::StoreBook, ready: bool) -> store::StorageOutcome {
    let (reservation, header) = book.initialization_durability();
    let ((reservation_entered, _), (header_entered, _)) = book.initialization_effects();
    store::StorageOutcome {
        effect: if header { store::Effect::KnownApplied } else if reservation_entered || header_entered { store::Effect::Unknown } else { store::Effect::NotStarted },
        durability: if header { store::Durability::Confirmed } else if reservation || reservation_entered || header_entered { store::Durability::Unknown } else { store::Durability::NotRun },
        cleanup: if ready && book.operation_quiescent() { store::Cleanup::Known } else { store::Cleanup::Pending },
    }
}

pub(super) fn execute(owner: &Arc<OriginalWork>, child: Child) -> Result<ChildResult, Reason> {
    let storage = native_store(owner)?;
    let mut book = storage.lock().map_err(|_| Reason::CleanupUnknown)?;
    let mutation = matches!(child, Child::Mutate { .. });
    let initialization = matches!(child, Child::Reserve { .. } | Child::PublishHeader(_));
    let result = (|| match child {
        Child::Open { location, roster } => {
            let observation = book.inspect(location, &mut || owner.interrupted()).map_err(problem)?;
            let root = observation.root.as_ref().map(store::RootWitness::registered);
            exclusions(owner, root.as_ref(), &roster)?;
            header_identity(&observation)?;
            Ok(ChildResult::Opened(observation))
        },
        Child::PrepareInitialize { proposed, root, roster } => {
            // Only a fresh, already-retired uninitialized preview enters here.
            // This clears no failure, reservation, key or partial effect.
            book.cancel_initialize_preview();
            let proof = exclusions(owner, root.as_ref(), &roster)?;
            let root = book.prepare_initialize(proposed, &proof, &mut || owner.interrupted()).map_err(problem)?;
            let tokens = random_tokens(&mut || owner.interrupted())?;
            Ok(ChildResult::Prepared { root, identity: proposed, tokens })
        },
        Child::Reserve { identity, roster } => {
            check_exclusions(owner, &mut book, &roster)?;
            let actual = book.reserve_prepared_identity(&mut || owner.interrupted()).map_err(problem)?;
            if actual != identity { return Err(Reason::VaultCorrupt); }
            Ok(ChildResult::Reserved(actual))
        },
        Child::PublishHeader(header) => {
            book.publish_header(&header, &mut || owner.interrupted()).map_err(problem)?;
            Ok(ChildResult::Header)
        },
        Child::List { records, roster, allowance } => {
            if records.len() > store::DESCRIPTOR_COUNT { return Err(Reason::Capacity); }
            check_exclusions(owner, &mut book, &roster)?;
            let key = active_key(owner)?;
            let mut rows = Vec::new(); rows.try_reserve_exact(records.len()).map_err(|_| Reason::Capacity)?;
            let mut occupied = rows.capacity().checked_mul(std::mem::size_of::<Descriptor>()).ok_or(Reason::Capacity)?;
            for record in records {
                if owner.interrupted() { return Err(Reason::UserCancelled); }
                let row = descriptor(&mut book, &key, record, allowance.checked_sub(occupied).ok_or(Reason::Capacity)?, owner)?;
                if rows.iter().any(|row: &Descriptor| row.authenticated.record == record) { return Err(Reason::VaultCorrupt); }
                occupied = occupied.checked_add(row.authenticated.descriptor.retained_bytes().map_err(|_| Reason::Capacity)?).ok_or(Reason::Capacity)?;
                if occupied > store::RESIDENT_BYTES || occupied > allowance { return Err(Reason::Capacity); }
                rows.push(row);
            }
            Ok(ChildResult::Listed(rows))
        },
        Child::Load { reference, roster, allowance } => {
            check_exclusions(owner, &mut book, &roster)?;
            let key = active_key(owner)?;
            if key.identity() != reference.identity { return Err(Reason::VaultCorrupt); }
            let original = book.read_record(reference.record, true, &mut || owner.interrupted()).map_err(problem)?;
            let (bytes, witness, complete) = original.into_parts();
            if !complete || witness != reference.original { return Err(Reason::SourceChanged); }
            let opened = key.open_record(bytes, allowance).map_err(crypto_problem)?;
            if opened.record != reference.record || opened.revision != reference.revision { return Err(Reason::SourceChanged); }
            let kind = opened.descriptor.kind;
            let material = if let Some(bytes) = opened.file {
                let file = kind.file().ok_or(Reason::VaultCorrupt)?;
                let observation = credential_format::inspect(file, bytes.bytes(), &mut || owner.interrupted()).map_err(|_| Reason::UserCancelled)?;
                Some(Arc::new(Material { origin: MaterialOrigin::Stored(StoredMaterial { bytes, reference }), observation }))
            } else { None };
            let payload = Arc::new(Payload { kind, material, fields: Some(opened.fields) });
            if payload.bytes() > store::RESIDENT_BYTES || payload.bytes() > allowance { return Err(Reason::Capacity); }
            Ok(ChildResult::Loaded { payload, reference })
        },
        Child::ReviewDelete { reference, roster, allowance } => {
            check_exclusions(owner, &mut book, &roster)?;
            let key = active_key(owner)?;
            let row = descriptor(&mut book, &key, reference.record, allowance, owner)?;
            match_descriptor(&row, reference, &key)?;
            Ok(ChildResult::Delete { reference, tokens: random_tokens(&mut || owner.interrupted())? })
        },
        Child::Mutate { operation, record, expected, payload, label, roster, allowance } => {
            let key = active_key(owner)?;
            if expected.is_some_and(|reference| reference.record != record || reference.identity != key.identity()) { return Err(Reason::SourceChanged); }
            let candidate = if let Some(payload) = &payload {
                let fields = payload.fields.as_ref().ok_or(Reason::VaultCorrupt)?;
                let descriptor = format::Descriptor::new(payload.kind, label, fields.vault_presence(), payload.material.is_some()).map_err(|_| Reason::VaultCorrupt)?;
                Some(key.seal_record(record, expected.map(|reference| reference.revision), &descriptor, fields,
                    payload.material.as_ref().map(|material| material.bytes()), allowance).map_err(crypto_problem)?)
            } else { None };
            let intent = key.seal_intent(operation, record, expected.map(|reference| reference.revision), candidate.as_ref()).map_err(crypto_problem)?;
            // Do the complete physical roster probe after sealing, as close to
            // native publication admission as possible. Registry generation is
            // checked again before the memory-only result can be published.
            check_exclusions(owner, &mut book, &roster)?;
            let effect = book.mutate(&intent, candidate.as_ref().map(crypto::SealedRecord::bytes), expected.as_ref().map(|reference| &reference.original),
                &mut || owner.interrupted(), &mut || cleanup_expired(owner));
            remember(owner, &book, true)?;
            effect.map_err(problem)?;
            let revision = candidate.as_ref().map(crypto::SealedRecord::revision);
            // Release ciphertext backing BEFORE bounded descriptor readback.
            drop(candidate);
            let row = if let Some(revision) = revision {
                let row = descriptor(&mut book, &key, record, allowance, owner)?;
                if row.authenticated.revision != revision { return Err(Reason::VaultCorrupt); }
                Some(row)
            } else { None };
            Ok(ChildResult::Mutated { record, row })
        },
        Child::Check { reference, roster } => {
            check_exclusions(owner, &mut book, &roster)?;
            if active_key(owner)?.identity() != reference.identity { return Err(Reason::VaultCorrupt); }
            book.recheck_record(&reference.original, &mut || owner.interrupted()).map_err(problem)?;
            Ok(ChildResult::Checked)
        },
        Child::Release => {
            let settled = book.release(&mut || cleanup_expired(owner));
            let mut work = owner.vault.lock().map_err(|_| Reason::CleanupUnknown)?;
            if let Some(outcome) = &mut work.outcome {
                if outcome.cleanup == store::Cleanup::Pending { outcome.cleanup = if settled { store::Cleanup::Known } else { store::Cleanup::Unknown }; }
            }
            if !settled { return Err(Reason::CleanupUnknown); }
            Ok(ChildResult::Released)
        },
    })();
    remember(owner, &book, mutation)?;
    if initialization {
        owner.vault.lock().map_err(|_| Reason::CleanupUnknown)?.outcome = Some(initial_outcome(&book, result.is_ok()));
    }
    if let Err(reason) = &result {
        owner.vault.lock().map_err(|_| Reason::CleanupUnknown)?.fail(*reason, book.problem_at().unwrap_or_else(Instant::now));
    }
    result
}

fn allowance(state: &DocumentState, owner: &Arc<OriginalWork>) -> Result<usize, Reason> {
    let source = owner.source.try_lock().map_err(|_| Reason::CleanupUnknown)?;
    let retirement = owner.retirement.try_lock().map_err(|_| Reason::CleanupUnknown)?;
    let live = lookup_memory::live_bytes(state, owner, &source, &retirement).map_err(|_| Reason::Capacity)?;
    if live > store::RESIDENT_BYTES { return Err(Reason::Capacity); }
    // Existing bounded parser arena plus scalar/request/control scratch; crypto
    // additionally charges its actual buffer capacity and fixed control row.
    store::WORKING_BYTES.checked_sub(live).and_then(|bytes| bytes.checked_sub(8 * 1024 * 1024)).ok_or(Reason::Capacity)
}
fn pending_allowance(state: &DocumentState, slot: &Slot) -> Result<usize, Reason> {
    let live = lookup_memory::pending_slot_bytes(state, slot).map_err(|_| Reason::Capacity)?;
    if live > store::RESIDENT_BYTES { return Err(Reason::Capacity); }
    store::WORKING_BYTES.checked_sub(live).and_then(|bytes| bytes.checked_sub(8 * 1024 * 1024)).ok_or(Reason::Capacity)
}
fn current_gate(document: &DocumentBinding, state: &DocumentState, owner: &Arc<OriginalWork>) -> Result<(), Reason> {
    if state.stopping || state.unknown || state.lock_pending || state.quit_pending || state.retiring || !state.lifetime.original_bound()
        || owner.interrupted() || !state.slot.as_ref().is_some_and(|slot| Arc::ptr_eq(&slot.owner, owner) && slot.cleanup_end.is_none()) {
        return Err(Reason::UserCancelled);
    }
    let generation = state.slot.as_ref().and_then(|slot| slot.vault.generation).ok_or(Reason::ExclusionUnconfirmed)?;
    if document.inner.bridge.native_generation().map_err(|error| error.reason)? != generation { return Err(Reason::ExclusionUnconfirmed); }
    Ok(())
}
pub(super) fn report(document: &DocumentBinding, owner: &Arc<OriginalWork>) {
    let Some((first, outcome)) = owner.vault.try_lock().ok().map(|work| (work.first, work.outcome)) else { return; };
    let mut state = document.lock();
    let mut changed = false;
    if let Some(slot) = state.slot.as_mut().filter(|slot| Arc::ptr_eq(&slot.owner, owner)) {
        if slot.vault.outcome != outcome { slot.vault.outcome = outcome; changed = true; }
        let Some((reason, at)) = first else { if changed { document.bump(&mut state); } return; };
        slot.error = Some(AssetError::new(reason).into()); slot.stop(reason, at);
        let operation = slot.operation;
        if let Some(vault) = &mut state.vault {
            vault.reason = reason;
            if matches!(operation, Operation::Initialize | Operation::Commit) { vault.state = State::Interrupted; vault.read_only = true; }
            if reason == Reason::CleanupUnknown { vault.state = State::Unknown; vault.revoked = true; state.unknown = true; }
        }
        invalidate_all(&mut state); document.bump(&mut state);
    }
}

#[cfg(feature = "desktop-shell")]
async fn native(document: &DocumentBinding, owner: &Arc<OriginalWork>, work: Child) -> Result<ChildResult, Reason> {
    let result = child(owner, ChildJob::Vault(work)).await;
    report(document, owner); // The backend's first observed failure clock wins.
    match result {
        Ok(ChildEnd::Vault(value)) => Ok(value), Ok(ChildEnd::Refused(reason)) | Err(reason) => Err(reason),
        _ => Err(Reason::CleanupUnknown),
    }
}
#[cfg(feature = "desktop-shell")]
fn provider_problem(problem: crate::vault_keyring_linux::Problem) -> Reason {
    use crate::vault_keyring_linux::Problem;
    match problem {
        Problem::Interrupted => Reason::UserCancelled, Problem::Capacity => Reason::Capacity,
        Problem::CleanupUnknown => Reason::CleanupUnknown, Problem::Locked => Reason::VaultKeyringLocked,
        Problem::MissingKey => Reason::VaultKeyMissing,
        Problem::Denied => Reason::VaultKeyringDenied,
        Problem::UnsupportedProvider => Reason::VaultProviderUnsupported,
        _ => Reason::VaultKeyringUnavailable,
    }
}

#[cfg(feature = "desktop-shell")]
impl DocumentBinding {
    fn retain_authenticated_vault_key(&self, owner: &Arc<OriginalWork>, identity: format::Identity, header: &[u8; format::HEADER_BYTES]) -> Result<(), Reason> {
        let mut state = self.lock(); self.expire(&mut state, Instant::now()); current_gate(self, &state, owner)?;
        let child = owner.child.try_lock().map_err(|_| Reason::CleanupUnknown)?;
        if child.handle.is_some() || !matches!(child.receipt, JoinReceipt::New | JoinReceipt::Returned)
            || !owner.retired.load(Ordering::SeqCst) { return Err(Reason::CleanupUnknown); }
        let mut work = owner.vault.try_lock().map_err(|_| Reason::CleanupUnknown)?;
        if work.key.is_some() || work.first.is_some() { return Err(Reason::VaultCorrupt); }
        let mut book = owner.keyring.try_lock().map_err(|_| Reason::CleanupUnknown)?;
        if !book.resources_settled() || !book.memory_held() { return Err(Reason::CleanupUnknown); }
        // Consume under the STILL-HELD wire charge. Even an authentication
        // failure zeroizes the candidate; no byte getter/IPC key exists.
        let key = book.consume_settled_key(|candidate| crypto::VaultKey::authenticate_candidate(candidate, identity, header))
            .map_err(provider_problem)?.map_err(crypto_problem)?;
        work.key = Some(Arc::new(key)); // OriginalWork custody precedes refund.
        drop((book, work, child, state));
        // Same coordinator, positively settled SDK originals, no other task
        // can allocate under this current slot. The key is already in its exact
        // census; this is phase disposal, not document publication/finality.
        let mut book = owner.keyring.lock().map_err(|_| Reason::CleanupUnknown)?;
        if !book.dispose_settled_storage() || !book.allocations_released() { return Err(Reason::CleanupUnknown); }
        Ok(())
    }
    fn initialize_admission(&self, owner: &Arc<OriginalWork>, identity: format::Identity) -> Result<KeyringInitializationAdmission, Reason> {
        let mut state = self.lock(); self.expire(&mut state, Instant::now()); current_gate(self, &state, owner)?;
        let slot = state.slot.as_mut().ok_or(Reason::VaultCorrupt)?;
        if slot.operation != Operation::Initialize || slot.vault.initialize != Some(identity) { return Err(Reason::VaultCorrupt); }
        let child = owner.child.try_lock().map_err(|_| Reason::CleanupUnknown)?;
        if child.receipt != JoinReceipt::Returned || child.handle.is_some() { return Err(Reason::CleanupUnknown); }
        // Child returned exactly the reserved identity; this private field is
        // spent once, while the original provider gets one consuming token.
        spend_initialization(slot, identity)
    }
    fn vault_work_allowance(&self, owner: &Arc<OriginalWork>) -> Result<usize, Reason> {
        let state = self.lock(); current_gate(self, &state, owner)?; allowance(&state, owner)
    }
}

#[cfg(all(test, debug_assertions))]
mod tests {
    // Deterministic in-memory DATA models only. No bridge/document constructor,
    // SDK/provider, native file, process, worker, join or store call is run.
    // They prove predicates/custody/projection, NOT native qualification.
    use super::*;
    use serde_json::{json, Value};

    fn id(byte: u8) -> format::Id { format::Id::from_bytes([byte; 16]).unwrap() }
    fn identity() -> format::Identity { format::Identity::new(id(1), id(2)).unwrap() }
    fn token(byte: char) -> Token { Token(byte.to_string().repeat(32)) }
    fn descriptor_data(record: u8, revision: u32) -> Descriptor {
        let record = id(record); let revision = format::Revision::new(id(201), revision).unwrap();
        Descriptor {
            authenticated: crypto::AuthenticatedDescriptor { record, revision,
                descriptor: format::Descriptor::new(Kind::GoogleWif, Some("Public label".into()), vec![false, false], false).unwrap() },
            original: store::ReadWitness::lifecycle_data(record, revision), mutation_pending: false,
        }
    }
    fn context_data() -> Arc<NativeContext> {
        Arc::new(NativeContext { revision: 1, project_id: "data-project".into(),
            project: asset_source::RegisteredRoot { path: "/inert/project".into(),
                identity: asset_source::ProjectIdentity::Posix(asset_source::DirectoryIdentity::synthetic_evidence_identity()) },
            registry_generation: 7, draft: Vec::new(), platform: Platform::Android, stage: Stage::Candidate, purpose: Purpose::Store })
    }
    fn model(operation: Operation, attached: bool) -> (DocumentState, Arc<OriginalWork>) {
        let mut state = super::super::tests::empty_state();
        state.session = false;
        state.lifetime.crash_hook_installed(); state.lifetime.started(true); state.lifetime.finished(true);
        let mut session = Session::new(Arc::new(Mutex::new(store::StoreBook::new())), 7);
        session.identity = Some(identity()); session.state = State::Unlocked;
        session.key = Some(Arc::new(crypto::lifecycle_data_key(identity())));
        let owner = OriginalWork::new(9, false, Weak::new()); owner.set_endpoint(None);
        let mut slot = Slot::new(owner.clone(), operation, None, None, None); slot.phase = Phase::Idle;
        if attached {
            attach(&owner, &session, true, false).ok().expect("DATA store association");
            slot.vault.lease = Some(session.store.clone()); slot.vault.generation = Some(7);
        }
        state.vault = Some(session); state.slot = Some(slot); (state, owner)
    }
    fn live(state: &DocumentState, owner: &Arc<OriginalWork>) -> usize {
        let source = owner.source.lock().unwrap(); let retirement = owner.retirement.lock().unwrap();
        lookup_memory::live_bytes(state, owner, &source, &retirement).unwrap()
    }
    fn completed_model(operation: Operation) -> (DocumentState, Arc<OriginalWork>) {
        let (mut state, owner) = model(operation, true);
        // DATA facts for the exact context predicate, not an executed/native
        // receipt. The production publisher requires all the original joins.
        owner.coordinator.lock().unwrap().receipt = JoinReceipt::Returned;
        owner.ended.store(true, Ordering::SeqCst);
        owner.vault.lock().unwrap().key = None;
        state.slot.as_mut().unwrap().settlement = Settlement::Known;
        (state, owner)
    }

    #[test]
    fn completed_unlock_context_and_commit_retirement_preserve_the_healthy_lease_not_old_authority() {
        for operation in [Operation::Unlock, Operation::Initialize, Operation::Commit] {
            let (mut state, owner) = completed_model(operation);
            let key = state.vault.as_ref().unwrap().key.clone().unwrap();
            let original_store = state.vault.as_ref().unwrap().store.clone();
            let context = context_data(); state.context = Some(context.clone());
            let record = RecordKey { id: token('a'), revision: 1 };
            state.assignments.push(Assignment { kind: Kind::GoogleWif, record_id: record.id.clone(), record_revision: 1,
                context_revision: 1, availability: AssignmentAvailability::Available });
            let outcome = store::StorageOutcome { effect: store::Effect::KnownApplied, durability: store::Durability::Confirmed, cleanup: store::Cleanup::Known };
            if operation == Operation::Commit {
                let slot = state.slot.as_mut().unwrap(); slot.context = Some(context.clone());
                slot.selection = Some(token('b')); slot.assessment_context_revision = Some(1); slot.review_end = Some(Instant::now() + REVIEW);
                slot.preview = Some(Preview { token: token('c'), action: Action::Bind, bind_token: None, record: Some(record.clone()),
                    subject: PreviewSubject::new(Kind::GoogleWif, SubjectChange::Assign, Some(&record)) });
                slot.vault.outcome = Some(outcome);
            }
            assert!(completed_context_receipt(&state));
            // This is the SAME bounded transition called by context(), before
            // its new context publication and registered off-lock DATA drop.
            let retired = retire_context_authority(&mut state, Instant::now());
            assert_eq!(retired.is_some(), operation == Operation::Commit);
            if let Some(retired) = &retired { assert!(Arc::ptr_eq(retired, &context)); }
            let mut next = context_data(); Arc::get_mut(&mut next).unwrap().revision = 2;
            state.context = Some(next);
            assert!(!observe_stop(&mut state, Instant::now()));
            let slot = state.slot.take().unwrap();
            // Reconcile's stale-context predicate has no old binding left,
            // and its temporarily-detached stop observer must not revoke it.
            assert!(slot.context.is_none());
            observe_detached_stop(&mut state, &slot, Instant::now());
            assert!(slot.phase == Phase::Idle && slot.settlement == Settlement::Known && slot.operation == operation);
            assert_eq!(slot.reason, Reason::None); assert!(slot.cleanup_end.is_none());
            assert!(slot.selection.is_none() && slot.preview.is_none() && slot.assessment_context_revision.is_none() && slot.review_end.is_none());
            if operation == Operation::Commit { assert!(slot.vault.outcome == Some(outcome)); }
            state.slot = Some(slot); drop(retired);
            assert!(state.vault.as_ref().unwrap().writable());
            assert!(Arc::ptr_eq(state.vault.as_ref().unwrap().key.as_ref().unwrap(), &key));
            assert!(Arc::ptr_eq(state.vault.as_ref().unwrap().store(), &original_store));
            assert!(!owner.stopped() && owner.cleanup_end.lock().unwrap().is_none());
            assert!(state.assignments.iter().all(|assignment| assignment.availability == AssignmentAvailability::Unavailable));
            let status = serde_json::to_value(DocumentBinding::status_data(&state, false)).unwrap();
            assert_eq!(status["context"]["revision"], 2); assert_eq!(status["persistence"]["keyAccess"], "read-write");
            assert_eq!(status["operation"]["assessment"], Value::Null);
        }
    }

    #[test]
    fn context_retirement_never_exempts_active_unjoined_failed_unknown_or_other_originals() {
        let at = Instant::now();
        for case in 0..12 {
            let (mut state, owner) = completed_model(Operation::Unlock);
            match case {
                0 => state.slot.as_mut().unwrap().phase = Phase::Assessing,
                1 => owner.coordinator.lock().unwrap().receipt = JoinReceipt::New,
                2 => owner.coordinator.lock().unwrap().receipt = JoinReceipt::Failed,
                3 => owner.child.try_lock().unwrap().receipt = JoinReceipt::Failed,
                4 => { state.unknown = true; state.slot.as_mut().unwrap().phase = Phase::Unknown; state.slot.as_mut().unwrap().settlement = Settlement::LateKnown; },
                5 => state.slot.as_mut().unwrap().stop(Reason::VaultCorrupt, at),
                6 => state.slot.as_mut().unwrap().vault.lease = Some(Arc::new(Mutex::new(store::StoreBook::new()))),
                7 => owner.vault.lock().unwrap().store = Some(Arc::new(Mutex::new(store::StoreBook::new()))),
                8 => owner.vault.lock().unwrap().release_end = Some(at + CLEANUP),
                9 => *owner.cleanup_end.lock().unwrap() = Some(at + CLEANUP),
                10 => owner.vault.lock().unwrap().fail(Reason::VaultCorrupt, at),
                11 => state.slot.as_mut().unwrap().retired_payload = Some(Arc::new(Payload { kind: Kind::GoogleWif, material: None, fields: None })),
                _ => unreachable!(),
            }
            assert!(!completed_context_receipt(&state), "invalid DATA case {case}");
            assert!(retire_context_authority(&mut state, at + Duration::from_secs(1)).is_none());
            assert!(owner.stopped() && state.slot.as_ref().unwrap().cleanup_end.is_some());
            if case == 5 {
                assert_eq!(state.slot.as_ref().unwrap().reason, Reason::VaultCorrupt);
                assert_eq!(state.slot.as_ref().unwrap().cleanup_end, Some(at + CLEANUP));
            }
            if matches!(case, 5 | 9) { assert_eq!(*owner.cleanup_end.lock().unwrap(), Some(at + CLEANUP)); }
            if case == 8 { assert_eq!(owner.vault.lock().unwrap().release_end, Some(at + CLEANUP)); }
            if case == 10 { assert_eq!(owner.vault.lock().unwrap().first, Some((Reason::VaultCorrupt, at))); }
            if case == 4 { assert!(state.unknown && state.slot.as_ref().unwrap().phase == Phase::Unknown); }
        }
    }

    #[test]
    fn affected_stop_revokes_without_waiting_for_worker_and_only_contracts_first_cutoff() {
        let at = Instant::now();
        let (mut state, owner) = model(Operation::Prepare, true);
        owner.set_endpoint(Some(at + WORK));
        state.slot.as_mut().unwrap().stop(Reason::UserCancelled, at + Duration::from_secs(3));
        let holding = owner.vault.lock().unwrap();
        assert!(observe_stop(&mut state, at + Duration::from_secs(8)));
        let lease = state.vault.as_ref().unwrap();
        assert!(lease.revoked && !lease.writable());
        assert_eq!(lease.release_end, Some(at + Duration::from_secs(3) + CLEANUP));
        assert!(!holding.release); // Revocation does not wait for this custody lock.
        drop(holding);
        assert!(!observe_stop(&mut state, at + WORK));
        assert!(owner.vault.lock().unwrap().release);
        // A late-delivered native failure at an earlier timestamp contracts
        // both clocks. Neither a later lock nor observer receives a new lease.
        state.slot.as_mut().unwrap().stop(Reason::VaultCorrupt, at);
        observe_stop(&mut state, at + WORK + CLEANUP);
        assert_eq!(state.slot.as_ref().unwrap().cleanup_end, Some(at + CLEANUP));
        assert_eq!(*owner.cleanup_end.lock().unwrap(), Some(at + CLEANUP));
        assert_eq!(state.vault.as_ref().unwrap().release_end, Some(at + CLEANUP));
        assert_eq!(owner.vault.lock().unwrap().release_end, Some(at + CLEANUP));
        request_release(&mut state, at + WORK * 2);
        assert_eq!(state.vault.as_ref().unwrap().release_end, Some(at + CLEANUP));
        assert_eq!(state.slot.as_ref().unwrap().reason, Reason::UserCancelled);
    }

    #[test]
    fn unrelated_operation_stop_never_owns_a_healthy_vault_lease_clock() {
        let at = Instant::now();
        for operation in [Operation::ChooseProject, Operation::ChooseProjectPath, Operation::ChooseEvidenceFolder, Operation::InspectEvidence] {
            let (mut state, owner) = model(operation, false);
            state.slot.as_mut().unwrap().stop(Reason::UserCancelled, at);
            assert!(!observe_stop(&mut state, at + WORK));
            assert!(state.vault.as_ref().unwrap().writable());
            assert!(state.vault.as_ref().unwrap().release_end.is_none());
            request_release(&mut state, at + WORK);
            assert_eq!(state.vault.as_ref().unwrap().release_end, Some(at + WORK + CLEANUP));
            assert_eq!(state.slot.as_ref().unwrap().cleanup_end, Some(at + CLEANUP));
            assert!(owner.vault.lock().unwrap().store.is_none());
        }
        // Same numeric operation ID is not ownership of another StoreBook.
        let (mut state, owner) = model(Operation::Prepare, true);
        state.slot.as_mut().unwrap().vault.lease = Some(Arc::new(Mutex::new(store::StoreBook::new())));
        state.slot.as_mut().unwrap().stop(Reason::UserCancelled, at);
        assert!(!observe_stop(&mut state, at + WORK));
        assert!(!owner.vault.lock().unwrap().release && state.vault.as_ref().unwrap().writable());
    }

    #[test]
    fn detached_reconciliation_retains_affected_original_cutoff_not_observer_time() {
        let at = Instant::now(); let (mut state, owner) = model(Operation::Unlock, true);
        let mut slot = state.slot.take().unwrap();
        slot.stop(Reason::CleanupUnknown, at); state.unknown = true;
        request_release(&mut state, at + WORK); // Status has no currently inserted slot.
        assert_eq!(state.vault.as_ref().unwrap().release_end, Some(at + WORK + CLEANUP));
        observe_detached_stop(&mut state, &slot, at + WORK);
        assert_eq!(state.vault.as_ref().unwrap().release_end, Some(at + CLEANUP));
        assert_eq!(owner.vault.lock().unwrap().release_end, Some(at + CLEANUP));
        assert!(owner.vault.lock().unwrap().release && state.unknown);
    }

    #[test]
    fn cleanup_claim_and_failed_child_receipt_are_one_shot_without_new_work_authority() {
        let (mut state, owner) = model(Operation::Commit, true);
        assert_eq!(claim_release(&owner), Err(Reason::CleanupUnknown));
        assert!(!release_child_admitted(&owner));
        let at = Instant::now(); state.slot.as_mut().unwrap().stop(Reason::VaultCorrupt, at);
        observe_stop(&mut state, at);
        owner.vault.lock().unwrap().fail(Reason::VaultCorrupt, at);
        assert_eq!(claim_release(&owner), Ok(true));
        assert!(release_child_admitted(&owner));
        assert_eq!(claim_release(&owner), Ok(false));
        assert!(retain_failed_child_for_release(&owner));
        assert!(!retain_failed_child_for_release(&owner));
        let work = owner.vault.lock().unwrap();
        assert!(work.failed_child_join == Some(JoinReceipt::Failed));
        assert!(work.original_join.is_none()); // No coordinator was run/joined.
        assert_eq!(work.first, Some((Reason::VaultCorrupt, at)));
        assert_eq!(work.release_end, Some(at + CLEANUP));
        assert!(owner.stopped() && !state.vault.as_ref().unwrap().writable());
    }

    #[test]
    fn unrelated_late_known_cleanup_requires_original_settlement_and_original_vault_cutoff() {
        let at = Instant::now();
        let (mut state, old) = model(Operation::ChooseProjectPath, false);
        state.slot.as_mut().unwrap().stop(Reason::CleanupUnknown, at);
        state.slot.as_mut().unwrap().phase = Phase::Unknown;
        state.slot.as_mut().unwrap().settlement = Settlement::LateKnown;
        state.unknown = true; request_release(&mut state, at + Duration::from_secs(2));
        let end = state.vault.as_ref().unwrap().release_end.unwrap();
        let owner = OriginalWork::new(10, false, Weak::new()); owner.set_endpoint(None);
        let session = state.vault.as_ref().unwrap();
        attach(&owner, session, false, true).ok().unwrap();
        {
            let mut work = owner.vault.lock().unwrap(); work.release_end = Some(end); work.release_claimed = true;
        }
        let mut slot = Slot::new(owner.clone(), Operation::Lock, None, None, None);
        slot.vault.lease = Some(session.store.clone()); slot.stop(Reason::UserCancelled, end - CLEANUP);
        old.ended.store(true, Ordering::SeqCst);
        assert!(!late_cleanup_install(&state, &slot)); // Body-ended alone is not joined.
        // DATA receipts test only the exact predicate, no real task is asserted.
        old.coordinator.lock().unwrap().receipt = JoinReceipt::Returned;
        assert!(late_cleanup_install(&state, &slot));
        state.slot.as_mut().unwrap().settlement = Settlement::Unknown;
        assert!(!late_cleanup_install(&state, &slot));
        state.slot.as_mut().unwrap().settlement = Settlement::LateKnown;
        old.child.try_lock().unwrap().receipt = JoinReceipt::Pending;
        assert!(!late_cleanup_install(&state, &slot));
        old.child.try_lock().unwrap().receipt = JoinReceipt::New;
        *old.keyring.lock().unwrap() = crate::vault_keyring_linux::LookupBook::constructor_refusal_data();
        assert!(!late_cleanup_install(&state, &slot)); // Native-none still retains charged backing.
        assert!(old.keyring.lock().unwrap().dispose_settled_storage());
        assert!(late_cleanup_install(&state, &slot));
        owner.vault.lock().unwrap().release_claimed = false;
        assert!(!late_cleanup_install(&state, &slot));
        owner.vault.lock().unwrap().release_claimed = true;
        slot.cleanup_end = Some(end + CLEANUP);
        assert!(!late_cleanup_install(&state, &slot));
        slot.cleanup_end = Some(end); slot.operation = Operation::Prepare;
        assert!(!late_cleanup_install(&state, &slot));
        assert!(state.unknown && state.slot.as_ref().unwrap().phase == Phase::Unknown);
        assert_eq!(state.slot.as_ref().unwrap().reason, Reason::CleanupUnknown);
        assert_eq!(state.slot.as_ref().unwrap().cleanup_end, Some(at + CLEANUP));
        assert_eq!(state.vault.as_ref().unwrap().release_end, Some(at + Duration::from_secs(2) + CLEANUP));
    }

    #[test]
    fn initialization_data_token_is_exact_same_identity_and_spent_once() {
        let (mut state, _) = model(Operation::Initialize, true);
        let slot = state.slot.as_mut().unwrap(); slot.vault.initialize = Some(identity());
        let other = format::Identity::new(id(1), id(3)).unwrap();
        assert!(spend_initialization(slot, other).is_err());
        assert!(slot.vault.initialize == Some(identity()));
        let consumed = spend_initialization(slot, identity()).unwrap();
        assert!(consumed.into_identity() == identity() && slot.vault.initialize.is_none());
        assert!(spend_initialization(slot, identity()).is_err());
        slot.vault.initialize = Some(identity()); slot.operation = Operation::PrepareInitialize;
        assert!(spend_initialization(slot, identity()).is_err());
        assert!(slot.vault.initialize == Some(identity()));
    }

    #[test]
    fn encrypted_save_publishes_descriptor_only_and_requires_separate_assessment_and_bind() {
        let (mut state, _) = model(Operation::Commit, true);
        state.context = Some(context_data());
        let row = descriptor_data(3, 1); let key = row.key();
        let slot = state.slot.as_mut().unwrap();
        slot.phase = Phase::Mutating; slot.selection = Some(token('b')); slot.assessment_context_revision = Some(1);
        slot.review_end = Some(Instant::now() + REVIEW);
        slot.preview = Some(Preview { token: token('c'), action: Action::Save, bind_token: Some(token('d')), record: None,
            subject: PreviewSubject::new(Kind::GoogleWif, SubjectChange::New, None) });
        let session = state.vault.as_mut().unwrap(); session.state = State::Mutating;
        // Only the shared memory transition is under test. No native effect,
        // original join or authenticated filesystem receipt is manufactured.
        publish_saved_revision(session, slot, id(3), Some(row), 7);
        assert!(slot.phase == Phase::Idle && slot.settlement == Settlement::Known && slot.discard);
        assert!(slot.preview.is_none() && slot.selection.is_none() && slot.assessment.is_none());
        assert!(slot.assessment_context_revision.is_none() && slot.review_end.is_none());
        assert!(slot.result_record.as_ref() == Some(&key));
        assert!(state.assignments.is_empty() && !record_assessed(&state, &key));
        let rows = summaries(&state); assert_eq!(rows.len(), 1);
        assert_eq!((rows[0].storage, rows[0].availability, rows[0].payload_state), ("encrypted", "unassigned", "not-checked"));
        assert!(!usable(&state, state.slot.as_ref().unwrap(), &key, Kind::GoogleWif));
    }

    #[test]
    fn encrypted_projection_redacts_locked_read_only_and_mutating_authority() {
        let (mut state, _) = model(Operation::Prepare, true);
        state.context = Some(context_data());
        let row = descriptor_data(3, 1); let key = row.key();
        state.vault.as_mut().unwrap().rows = vec![row, descriptor_data(4, 1)];
        state.assignments.push(Assignment { kind: Kind::GoogleWif, record_id: key.id, record_revision: key.revision,
            context_revision: 1, availability: AssignmentAvailability::Available });
        let unlocked = serde_json::to_value(DocumentBinding::status_data(&state, false)).unwrap();
        assert_eq!(unlocked["records"][0]["availability"], "assigned");
        assert_eq!(unlocked["records"][0]["payloadState"], "assessed");
        for (phase, read_only, access, visible) in [
            (State::Locked, false, "locked", false), (State::Uninitialized, false, "locked", false),
            (State::Initializing, false, "locked", false), (State::Unknown, false, "locked", false),
            (State::Interrupted, true, "read-only", true), (State::Mutating, false, "read-write", true),
        ] {
            let session = state.vault.as_mut().unwrap(); session.state = phase; session.read_only = read_only;
            session.rows[0].mutation_pending = phase == State::Mutating;
            assert!(!authority_visible(&state));
            let status = serde_json::to_value(DocumentBinding::status_data(&state, false)).unwrap();
            assert_eq!(status["persistence"]["keyAccess"], access);
            assert_eq!(status["context"], Value::Null); assert_eq!(status["assignments"], json!([]));
            for key in ["selectionToken", "assessment", "preview"] { assert_eq!(status["operation"][key], Value::Null); }
            assert_eq!(status["records"].as_array().unwrap().len(), if visible { 2 } else { 0 });
            if visible {
                assert_eq!(status["records"][0]["availability"], if phase == State::Mutating { "mutation-pending" } else { "unassigned" });
                assert_eq!(status["records"][1]["availability"], "unassigned");
                assert_eq!(status["records"][0]["payloadState"], "not-checked");
            }
        }
        state.vault.as_mut().unwrap().state = State::Unlocked; state.vault.as_mut().unwrap().read_only = false;
        request_release(&mut state, Instant::now());
        let status = serde_json::to_value(DocumentBinding::status_data(&state, false)).unwrap();
        assert_eq!(status["persistence"]["state"], "locked"); assert_eq!(status["persistence"]["keyAccess"], "locked");
        assert_eq!(status["records"], json!([])); assert!(!authority_visible(&state));
    }

    #[test]
    fn key_and_loaded_payload_census_tracks_actual_shared_backing_through_retirement() {
        let (mut state, owner) = model(Operation::Prepare, true);
        let baseline = live(&state, &owner);
        let same_key = state.vault.as_ref().unwrap().key.clone().unwrap();
        owner.vault.lock().unwrap().key = None;
        assert_eq!(live(&state, &owner), baseline); // Session still owns same backing.
        owner.vault.lock().unwrap().key = Some(same_key.clone());
        assert_eq!(live(&state, &owner), baseline);
        let another_key = Arc::new(crypto::lifecycle_data_key(identity()));
        let extra = another_key.retained_bytes() + 2 * std::mem::size_of::<usize>();
        owner.vault.lock().unwrap().key = Some(another_key);
        assert_eq!(live(&state, &owner), baseline + extra);
        owner.vault.lock().unwrap().key = Some(same_key);
        let fields = commands::own_fields(Kind::GoogleWif, &json!({"provider":"public-test-value","serviceAccount":null})).ok().unwrap();
        let payload = Arc::new(Payload { kind: Kind::GoogleWif, material: None, fields: Some(fields) });
        state.slot.as_mut().unwrap().vault.loaded = Some(payload.clone());
        let loaded = live(&state, &owner); assert!(loaded > baseline);
        {
            let mut retirement = owner.retirement.lock().unwrap();
            retirement.vault.loaded = Some(payload);
            owner.retired.store(false, Ordering::SeqCst);
        }
        assert_eq!(live(&state, &owner), loaded); // Duplicate Arc spends no new charge.
        state.slot.as_mut().unwrap().vault.loaded = None;
        assert_eq!(live(&state, &owner), loaded); // Retired data is STILL live.
        assert!(owner.release_retirement());
        assert_eq!(live(&state, &owner), baseline);
    }

    #[test]
    fn failed_retirement_restores_exact_key_and_loaded_custody_without_unlocking() {
        let (mut state, owner) = model(Operation::Commit, true);
        let key = state.vault.as_ref().unwrap().key.clone().unwrap();
        let payload = Arc::new(Payload { kind: Kind::GoogleWif, material: None, fields: None });
        state.slot.as_mut().unwrap().vault.loaded = Some(payload.clone());
        state.slot.as_mut().unwrap().vault.label = Some("public DATA".into());
        request_release(&mut state, Instant::now());
        let cutoff = state.vault.as_ref().unwrap().release_end;
        let mut slot = state.slot.take().unwrap();
        let retired = take_retirement(&mut state, &mut slot);
        assert!(state.vault.is_none() && slot.vault.loaded.is_none());
        assert!(!retired.empty() && owner.vault.lock().unwrap().key.is_none());
        restore_retirement(&mut state, &mut slot, retired);
        assert!(Arc::ptr_eq(state.vault.as_ref().unwrap().key.as_ref().unwrap(), &key));
        assert!(Arc::ptr_eq(owner.vault.lock().unwrap().key.as_ref().unwrap(), &key));
        assert!(Arc::ptr_eq(slot.vault.loaded.as_ref().unwrap(), &payload));
        assert_eq!(state.vault.as_ref().unwrap().release_end, cutoff);
        assert!(!state.vault.as_ref().unwrap().writable());
        assert_eq!(slot.vault.label.as_deref(), Some("public DATA"));
    }

    #[test]
    fn closed_status_keeps_bounded_storage_facts_but_no_work_authority() {
        let (mut state, _) = model(Operation::Commit, true);
        state.vault = None; state.session = false;
        let record = RecordKey { id: token('a'), revision: 1 };
        state.records.push(Record { key: record.clone(), payload: Arc::new(Payload { kind: Kind::GoogleWif, material: None, fields: None }), mutation_pending: false });
        state.assignments.push(Assignment { kind: Kind::GoogleWif, record_id: record.id.clone(), record_revision: 1, context_revision: 1, availability: AssignmentAvailability::Available });
        let slot = state.slot.as_mut().unwrap();
        slot.selection = Some(token('b'));
        slot.preview = Some(Preview { token: token('c'), action: Action::Bind, bind_token: None, record: Some(record.clone()),
            subject: PreviewSubject::new(Kind::GoogleWif, SubjectChange::Assign, Some(&record)) });
        slot.vault.outcome = Some(store::StorageOutcome { effect: store::Effect::KnownApplied, durability: store::Durability::Unknown, cleanup: store::Cleanup::Pending });
        let value = serde_json::to_value(DocumentBinding::status_data(&state, false)).unwrap();
        assert_eq!(value["schemaVersion"], 2); assert_eq!(value["mode"], "closed");
        for key in ["context", "persistence"] { assert_eq!(value[key], Value::Null); }
        for key in ["records", "assignments"] { assert_eq!(value[key], json!([])); }
        for key in ["selectionToken", "assessment", "preview"] { assert_eq!(value["operation"][key], Value::Null); }
        assert_eq!(value["operation"]["operation"], "commit");
        assert_eq!(value["operation"]["storageOutcome"], json!({"effect":"known-applied","durability":"unknown","cleanup":"pending"}));
        assert!(!DURABLE_QUALIFIED);
    }
}

#[cfg(feature = "desktop-shell")]
pub(super) async fn run(document: &DocumentBinding, owner: &Arc<OriginalWork>, job: Job) -> super::Staged {
    let result = run_inner(document, owner, job).await;
    match result {
        Ok(result) => result,
        Err(reason) => {
            if let Ok(mut work) = owner.vault.lock() { work.fail(reason, Instant::now()); }
            report(document, owner); super::Staged::Refused(reason)
        },
    }
}

fn claim_release(owner: &OriginalWork) -> Result<bool, Reason> {
    let mut work = owner.vault.lock().map_err(|_| Reason::CleanupUnknown)?;
    if !work.release || work.release_end.is_none() || work.store.is_none() { return Err(Reason::CleanupUnknown); }
    if work.release_claimed { return Ok(false); }
    work.release_claimed = true; Ok(true)
}
fn spend_initialization(slot: &mut Slot, identity: format::Identity) -> Result<KeyringInitializationAdmission, Reason> {
    if slot.operation != Operation::Initialize || slot.vault.initialize != Some(identity) { return Err(Reason::VaultCorrupt); }
    slot.vault.initialize = None;
    Ok(KeyringInitializationAdmission { identity })
}
pub(super) fn release_child_admitted(owner: &OriginalWork) -> bool {
    owner.vault.try_lock().is_ok_and(|work| work.release && work.release_claimed && work.store.is_some() && work.release_end.is_some())
}
pub(super) fn retain_failed_child_for_release(owner: &OriginalWork) -> bool {
    let Ok(mut work) = owner.vault.try_lock() else { return false; };
    if !work.release || !work.release_claimed || work.failed_child_join.is_some() { return false; }
    work.failed_child_join = Some(JoinReceipt::Failed); true
}

pub(super) fn take_empty_session(state: &mut DocumentState) -> Option<Session> {
    if state.slot.is_some() || !state.vault.as_ref().is_some_and(|session| session.revoked
        && session.store.try_lock().is_ok_and(|book| book.not_started() || book.settled())) { return None; }
    state.vault.take()
}

/// The same running coordinator independently closes its known store originals
/// after first STOP/failure. No key/payload work, new timeout or rollback is
/// admitted; a failed SDK/source path does not suppress this independent close.
#[cfg(feature = "desktop-shell")]
pub(super) async fn after_job(document: &DocumentBinding, owner: &Arc<OriginalWork>, staged: &super::Staged) {
    let pending = {
        let mut state = document.lock();
        let Some(slot) = state.slot.as_mut().filter(|slot| Arc::ptr_eq(&slot.owner, owner) && operation_attached(slot)) else { return; };
        if let super::Staged::Refused(reason) = staged { if slot.cleanup_end.is_none() { slot.stop(*reason, Instant::now()); } }
        observe_stop(&mut state, Instant::now());
        let pending = release_pending(&state);
        if pending { document.bump(&mut state); }
        pending
    };
    if !pending { return; }
    match claim_release(owner) {
        Ok(true) => { let _ = native(document, owner, Child::Release).await; },
        Ok(false) => {},
        Err(reason) => {
            if let Ok(mut work) = owner.vault.lock() { work.fail(reason, Instant::now()); }
            report(document, owner);
        },
    }
}

#[cfg(feature = "desktop-shell")]
pub(super) fn start_cleanup(document: &DocumentBinding, state: &mut DocumentState) -> Result<Option<oneshot::Sender<()>>, AssetError> {
    let Some(session) = &state.vault else { return Ok(None); };
    if !session.revoked { return Ok(None); }
    let end = session.release_end.ok_or_else(|| AssetError::new(Reason::CleanupUnknown))?;
    if state.retiring { return Ok(None); }
    // A healthy document lease can outlive an unrelated project/evidence
    // operation. That retired operation is never relabelled or granted a new
    // deadline; a first explicit lease revocation uses this same single slot.
    let attached = state.slot.as_ref().is_some_and(|slot| owns(slot, session));
    if !attached {
        if state.slot.as_ref().is_some_and(|slot| !unrelated_retired(session, slot)) { return Ok(None); }
        let storage = session.store.clone(); let generation = session.registry_generation;
        let id = document.next_operation(state)?;
        let owner = OriginalWork::new(id, false, Arc::downgrade(&document.inner));
        {
            let mut work = owner.vault.lock().map_err(|_| AssetError::new(Reason::CleanupUnknown))?;
            work.store = Some(storage.clone()); work.release = true; work.release_end = Some(end);
            work.release_claimed = true;
        }
        let mut slot = Slot::new(owner, Operation::Lock, None, None, None);
        slot.vault.lease = Some(storage); slot.vault.generation = Some(generation);
        slot.stop(Reason::UserCancelled, end - CLEANUP); // Original lease-revocation clock, never spawn time.
        let start = document.install(state, slot, super::Job::Vault(Job::Release))?;
        return Ok(Some(start));
    }
    let slot = state.slot.as_mut().ok_or_else(AssetError::invalid)?;
    if !controls_released(&slot.owner) || slot.candidate.is_some() || slot.staged.is_some() || slot.retired_payload.is_some()
        || slot.vault.loaded.is_some() || slot.context.is_some() { return Ok(None); }
    let mut work = slot.owner.vault.try_lock().map_err(|_| AssetError::new(Reason::CleanupUnknown))?;
    if work.release_claimed { return Ok(None); }
    if work.key.is_some() || state.vault.as_ref().is_some_and(|session| session.key.is_some() || !session.rows.is_empty()) {
        return Ok(None);
    }
    let mut coordinator = slot.owner.coordinator.try_lock().map_err(|_| AssetError::new(Reason::CleanupUnknown))?;
    if coordinator.handle.is_some() || !matches!(coordinator.receipt, JoinReceipt::Returned | JoinReceipt::Failed) || work.original_join.is_some() {
        return Err(AssetError::new(Reason::CleanupUnknown));
    }
    // Atomically spend the one continuation while retaining the actual original
    // receipt. No earlier native book, STOP, failure or review clock is reset.
    work.original_join = Some(coordinator.receipt); work.release = true; work.release_claimed = true;
    work.release_end = Some(work.release_end.map_or(end, |old| old.min(end)));
    let owner = slot.owner.clone();
    owner.ended.store(false, Ordering::SeqCst);
    coordinator.receipt = JoinReceipt::Pending;
    let (start, enter) = oneshot::channel();
    let worker = owner.clone(); let binding = document.clone(); let marker = CoordinatorEnd(owner.clone());
    coordinator.handle = Some(tauri::async_runtime::spawn(async move {
        let _marker = marker;
        if enter.await.is_err() {
            if let Ok(mut work) = worker.vault.lock() { work.fail(Reason::CleanupUnknown, Instant::now()); }
            report(&binding, &worker); return;
        }
        // Original store handle custody exists before GO. Release never opens,
        // recreates, decrypts or adopts anything, even when the document is gone.
        let result = native(&binding, &worker, Child::Release).await;
        if let Err(reason) = result {
            if let Ok(mut work) = worker.vault.lock() { work.fail(reason, Instant::now()); }
            report(&binding, &worker);
        }
    }));
    drop((coordinator, work));
    slot.phase = if state.unknown { Phase::Unknown } else { Phase::Stopping };
    slot.settlement = if state.unknown { Settlement::Unknown } else { Settlement::Pending };
    document.bump(state); Ok(Some(start))
}
#[cfg(feature = "desktop-shell")]
async fn run_inner(document: &DocumentBinding, owner: &Arc<OriginalWork>, job: Job) -> Result<super::Staged, Reason> {
    use crate::vault_keyring_linux::LookupInput;
    match job {
        Job::Open { location, roster } => {
            let generation = roster.generation;
            match native(document, owner, Child::Open { location, roster }).await? {
                ChildResult::Opened(observation) => Ok(super::Staged::Vault(Staged::Opened { observation, generation })), _ => Err(Reason::CleanupUnknown),
            }
        },
        Job::PrepareInitialize { root, roster } => {
            let generation = roster.generation;
            let proposed = crypto::new_identity().map_err(crypto_problem)?;
            match native(document, owner, Child::PrepareInitialize { proposed, root, roster }).await? {
                ChildResult::Prepared { root, identity, tokens } => Ok(super::Staged::Vault(Staged::Prepared { root, identity, tokens, generation })), _ => Err(Reason::CleanupUnknown),
            }
        },
        Job::Initialize { identity, roster } => {
            match native(document, owner, Child::Reserve { identity, roster }).await? {
                ChildResult::Reserved(actual) if actual == identity => {}, _ => return Err(Reason::VaultCorrupt),
            }
            let admission = document.initialize_admission(owner, identity)?;
            let proposal = crypto::InitializationKey::generate(identity).map_err(crypto_problem)?;
            let header = *proposal.header();
            document.phase(owner, Phase::Assessing)?;
            let input = LookupInput::initialize(admission, proposal).map_err(provider_problem)?;
            document.drive_keyring_lookup(owner, input).await.map_err(provider_problem)?;
            document.retain_authenticated_vault_key(owner, identity, &header)?;
            document.phase(owner, Phase::Mutating)?;
            match native(document, owner, Child::PublishHeader(header)).await? { ChildResult::Header => {}, _ => return Err(Reason::CleanupUnknown) }
            Ok(super::Staged::Vault(Staged::Unlocked { rows: Vec::new(), initialized_header: Some(header) }))
        },
        Job::Unlock { identity, header, records, roster } => {
            document.phase(owner, Phase::Assessing)?;
            let input = LookupInput::unlock(identity).map_err(provider_problem)?;
            document.drive_keyring_lookup(owner, input).await.map_err(provider_problem)?;
            document.retain_authenticated_vault_key(owner, identity, &header)?;
            let allowance = document.vault_work_allowance(owner)?;
            match native(document, owner, Child::List { records, roster, allowance }).await? {
                ChildResult::Listed(rows) => Ok(super::Staged::Vault(Staged::Unlocked { rows, initialized_header: None })), _ => Err(Reason::CleanupUnknown),
            }
        },
        Job::Load { reference, roster, context, allowance } => {
            let (payload, reference) = match native(document, owner, Child::Load { reference, roster, allowance }).await? {
                ChildResult::Loaded { payload, reference } => (payload, reference), _ => return Err(Reason::CleanupUnknown),
            };
            {
                let mut state = document.lock(); current_gate(document, &state, owner)?;
                let slot = state.slot.as_mut().ok_or(Reason::CleanupUnknown)?;
                slot.vault.reference = Some(reference); slot.vault.loaded = Some(payload.clone());
                slot.kind = Some(payload.kind); slot.source = if payload.material.is_some() { SourceState::Captured } else { SourceState::NotRun };
            }
            Ok(super::prepare_job(document, owner, payload, context).await)
        },
        Job::Delete { reference, roster, allowance } => {
            match native(document, owner, Child::ReviewDelete { reference, roster, allowance }).await? {
                ChildResult::Delete { reference, tokens } => Ok(super::Staged::Vault(Staged::DeletedPreview { reference, tokens })), _ => Err(Reason::CleanupUnknown),
            }
        },
        Job::Mutate { operation, record, expected, payload, label, roster, allowance } => {
            let generation = roster.generation;
            match native(document, owner, Child::Mutate { operation, record, expected, payload, label, roster, allowance }).await? {
                ChildResult::Mutated { record, row } => Ok(super::Staged::Vault(Staged::Mutated { record, row, generation })), _ => Err(Reason::CleanupUnknown),
            }
        },
        Job::Bind { reference, roster, assignment } => {
            match native(document, owner, Child::Check { reference, roster }).await? { ChildResult::Checked => Ok(super::Staged::Bound(assignment)), _ => Err(Reason::CleanupUnknown) }
        },
        Job::Release => match native(document, owner, Child::Release).await? {
            ChildResult::Released => Ok(super::Staged::Vault(Staged::Released)), _ => Err(Reason::CleanupUnknown),
        },
    }
}

#[cfg(feature = "desktop-shell")]
impl DocumentBinding {
    fn durable_gate(&self, state: &DocumentState, write: bool) -> Result<(), AssetError> {
        self.gate(state, false)?;
        if !DURABLE_QUALIFIED { return Err(AssetError::new(Reason::Unqualified)); }
        if state.session { return Err(AssetError::new(Reason::Busy)); }
        if write && !writable(state) { return Err(AssetError::new(state.vault.as_ref().map_or(Reason::Closed, Session::reason_for_access))); }
        Ok(())
    }
    fn vault_roster(&self, state: &mut DocumentState) -> Result<ProjectRoster, AssetError> {
        self.registry_result(state, self.inner.bridge.native_roster(), None)
    }
    fn vault_owner(&self, state: &mut DocumentState, operation: Operation, context: Option<Arc<NativeContext>>, target: Option<RecordKey>, review: Option<Instant>, key: bool)
        -> Result<Slot, AssetError> {
        let id = self.next_operation(state)?; let owner = OriginalWork::new(id, false, Arc::downgrade(&self.inner));
        let session = state.vault.as_ref().ok_or_else(|| AssetError::new(Reason::Closed))?;
        attach(&owner, session, key, false)?;
        let mut slot = Slot::new(owner, operation, context, target, review);
        slot.vault.generation = Some(session.registry_generation); slot.vault.lease = Some(session.store.clone()); Ok(slot)
    }
    pub(crate) fn open_encrypted(&self, application_data: &std::path::Path) -> Result<AssetStatus, AssetError> {
        self.reconcile(); let mut state = self.lock(); self.expire(&mut state, Instant::now()); self.durable_gate(&state, false)?; idle(&state)?;
        if state.vault.is_some() { return Ok(self.snapshot(&state)); }
        let location = store::Location::application_data(application_data).map_err(|error| AssetError::new(problem(error)))?;
        let roster = self.vault_roster(&mut state)?;
        let original = Arc::new(Mutex::new(store::StoreBook::new()));
        state.vault = Some(Session::new(original, roster.generation));
        let slot = self.vault_owner(&mut state, Operation::OpenVault, None, None, None, false)?;
        let start = self.install(&mut state, slot, super::Job::Vault(Job::Open { location, roster }))?;
        let status = self.snapshot(&state); drop(state); let _ = start.send(()); Ok(status)
    }
    pub(crate) fn prepare_vault_initialize(&self) -> Result<AssetStatus, AssetError> {
        self.reconcile(); let mut state = self.lock(); self.expire(&mut state, Instant::now()); self.durable_gate(&state, false)?; idle(&state)?;
        let session = state.vault.as_ref().filter(|session| session.state == State::Uninitialized && !session.revoked && session.key.is_none())
            .ok_or_else(|| AssetError::new(Reason::VaultInterrupted))?;
        let root = session.root.as_ref().map(store::RootWitness::registered);
        let roster = self.vault_roster(&mut state)?;
        let mut slot = self.vault_owner(&mut state, Operation::PrepareInitialize, None, None, Some(Instant::now() + REVIEW), false)?;
        slot.vault.generation = Some(roster.generation);
        let start = self.install(&mut state, slot, super::Job::Vault(Job::PrepareInitialize { root, roster }))?;
        let status = self.snapshot(&state); drop(state); let _ = start.send(()); Ok(status)
    }
    pub(crate) fn unlock_vault(&self) -> Result<AssetStatus, AssetError> {
        self.reconcile(); let mut state = self.lock(); self.expire(&mut state, Instant::now()); self.durable_gate(&state, false)?; idle(&state)?;
        let session = state.vault.as_ref().filter(|session| !session.revoked).ok_or_else(|| AssetError::new(Reason::Closed))?;
        if session.key.is_some() && matches!(session.state, State::Unlocked | State::Interrupted) { return Ok(self.snapshot(&state)); }
        if !matches!(session.state, State::Locked | State::Interrupted) { return Err(AssetError::new(session.reason_for_access())); }
        let identity = session.identity.ok_or_else(|| AssetError::new(Reason::VaultCorrupt))?;
        let header = session.header.ok_or_else(|| AssetError::new(Reason::VaultCorrupt))?;
        let records = session.inventory.clone();
        let roster = self.vault_roster(&mut state)?;
        let mut slot = self.vault_owner(&mut state, Operation::Unlock, None, None, None, false)?;
        slot.vault.generation = Some(roster.generation);
        let start = self.install(&mut state, slot, super::Job::Vault(Job::Unlock { identity, header, records, roster }))?;
        let status = self.snapshot(&state); drop(state); let _ = start.send(()); Ok(status)
    }
    pub(super) fn prepare_stored_vault(&self, state: &mut DocumentState, key: RecordKey, context: Arc<NativeContext>) -> Result<(u32, oneshot::Sender<()>), AssetError> {
        self.durable_gate(state, true)?; idle(state)?;
        let session = state.vault.as_ref().ok_or_else(AssetError::invalid)?;
        let row = session.row(&key).filter(|row| !row.mutation_pending).ok_or_else(AssetError::invalid)?;
        let reference = row.reference(session.identity.ok_or_else(AssetError::invalid)?); let kind = row.authenticated.descriptor.kind;
        let roster = self.vault_roster(state)?;
        if roster.generation != context.registry_generation { return Err(AssetError::new(Reason::ContextStale)); }
        let mut slot = self.vault_owner(state, Operation::Prepare, Some(context.clone()), Some(key), Some(Instant::now() + REVIEW), true)?;
        slot.kind = Some(kind); slot.vault.reference = Some(reference); slot.vault.generation = Some(roster.generation);
        let id = slot.owner.id;
        let available = pending_allowance(state, &slot).map_err(AssetError::new)?;
        let start = self.install(state, slot, super::Job::Vault(Job::Load { reference, roster, context, allowance: available }))?;
        // Caller opens GO only after releasing the actual document gate.
        Ok((id, start))
    }
    pub(super) fn prepare_vault_delete(&self, reference: commands::RecordRef<'_>) -> Result<AssetStatus, AssetError> {
        self.reconcile(); let mut state = self.lock(); self.expire(&mut state, Instant::now()); self.durable_gate(&state, true)?; idle(&state)?;
        let key = own_record(reference)?;
        let session = state.vault.as_ref().ok_or_else(AssetError::invalid)?;
        let row = session.row(&key).filter(|row| !row.mutation_pending).ok_or_else(AssetError::invalid)?;
        let reference = row.reference(session.identity.ok_or_else(AssetError::invalid)?); let kind = row.authenticated.descriptor.kind;
        let roster = self.vault_roster(&mut state)?;
        let mut slot = self.vault_owner(&mut state, Operation::PrepareDelete, None, Some(key.clone()), Some(Instant::now() + REVIEW), true)?;
        slot.kind = Some(kind); slot.vault.reference = Some(reference); slot.vault.generation = Some(roster.generation);
        let available = pending_allowance(&state, &slot).map_err(AssetError::new)?;
        revoke_record(&mut state, &key);
        let start = self.install(&mut state, slot, super::Job::Vault(Job::Delete { reference, roster, allowance: available }))?;
        let status = self.snapshot(&state); drop(state); let _ = start.send(()); Ok(status)
    }
    pub(super) fn commit_vault(&self, token: &str) -> Result<AssetStatus, AssetError> {
        self.reconcile(); let mut state = self.lock(); self.expire(&mut state, Instant::now()); self.durable_gate(&state, false)?;
        let preview = self.consume_preview(&mut state, token, false)?;
        let decision = (|| -> Result<(Slot, Job), AssetError> {
            let roster = self.vault_roster(&mut state)?;
            if preview.action == Action::Initialize {
                let old = state.slot.as_ref().ok_or_else(AssetError::invalid)?;
                let identity = old.vault.initialize.ok_or_else(AssetError::invalid)?;
                let review = old.review_end;
                if state.vault.as_ref().is_none_or(|session| session.state != State::Uninitialized || session.revoked || session.key.is_some()) { return Err(AssetError::invalid()); }
                let mut slot = self.vault_owner(&mut state, Operation::Initialize, None, None, review, false)?;
                slot.phase = Phase::Mutating; slot.vault.initialize = Some(identity); slot.vault.generation = Some(roster.generation);
                slot.owner.vault.lock().map_err(|_| AssetError::new(Reason::CleanupUnknown))?.outcome = Some(store::StorageOutcome {
                    effect: store::Effect::NotStarted, durability: store::Durability::NotRun, cleanup: store::Cleanup::Pending });
                slot.vault.outcome = Some(store::StorageOutcome { effect: store::Effect::NotStarted,
                    durability: store::Durability::NotRun, cleanup: store::Cleanup::Pending });
                return Ok((slot, Job::Initialize { identity, roster }));
            }
            self.durable_gate(&state, true)?;
            {
                // Reserve the bounded publication cells before any native
                // effect. Final publication cannot allocate an uncharged row.
                let session = state.vault.as_mut().ok_or_else(AssetError::invalid)?;
                session.rows.try_reserve_exact(store::DESCRIPTOR_COUNT.saturating_sub(session.rows.len())).map_err(|_| AssetError::new(Reason::Capacity))?;
                session.inventory.try_reserve_exact(store::DESCRIPTOR_COUNT.saturating_sub(session.inventory.len())).map_err(|_| AssetError::new(Reason::Capacity))?;
            }
            let old = state.slot.as_ref().ok_or_else(AssetError::invalid)?;
            let kind = old.kind.ok_or_else(AssetError::invalid)?;
            let session = state.vault.as_ref().ok_or_else(AssetError::invalid)?;
            let identity = session.identity.ok_or_else(AssetError::invalid)?;
            let (operation, record, expected, payload) = match preview.action {
                Action::Save => {
                    let context = old.context.as_ref().ok_or_else(|| AssetError::new(Reason::ContextStale))?;
                    if !self.context_matches(&state, context)? || context.registry_generation != roster.generation { return Err(AssetError::new(Reason::ContextStale)); }
                    let candidate = old.candidate.as_ref().filter(|candidate| candidate.payload.kind == kind && candidate.payload.usable_source())
                        .ok_or_else(|| AssetError::new(Reason::SourceRefused))?;
                    if !old.assessment.as_ref().is_some_and(SafeAssessment::permits) { return Err(AssetError::new(Reason::SourceRefused)); }
                    if let Some(key) = &candidate.existing {
                        let row = session.row(key).filter(|row| row.mutation_pending && row.authenticated.descriptor.kind == kind).ok_or_else(AssetError::invalid)?;
                        let expected = row.reference(identity);
                        (format::Mutation::Replace, expected.record, Some(expected), Some(candidate.payload.clone()))
                    } else {
                        if session.rows.len() >= store::DESCRIPTOR_COUNT { return Err(AssetError::new(Reason::Capacity)); }
                        let record = format::Id::from_token(&candidate.record_id.0).map_err(|_| AssetError::new(Reason::SourceRefused))?;
                        if session.rows.iter().any(|row| row.authenticated.record == record) || [identity.vault, identity.generation].contains(&record) { return Err(AssetError::new(Reason::SourceRefused)); }
                        (format::Mutation::New, record, None, Some(candidate.payload.clone()))
                    }
                },
                Action::Delete => {
                    let reference = old.vault.reference.ok_or_else(AssetError::invalid)?;
                    if preview.record.as_ref().is_none_or(|key| !reference.matches(key)) || !session.row(&reference.key()).is_some_and(|row| row.mutation_pending) { return Err(AssetError::invalid()); }
                    (format::Mutation::Delete, reference.record, Some(reference), None)
                },
                Action::Initialize | Action::Bind => return Err(AssetError::invalid()),
            };
            let context = old.context.clone(); let target = old.target.clone(); let review = old.review_end; let label = old.vault.label.clone();
            let mut slot = self.vault_owner(&mut state, Operation::Commit, context, target, review, true)?;
            slot.kind = Some(kind); slot.phase = Phase::Mutating; slot.vault.generation = Some(roster.generation);
            let available = pending_allowance(&state, &slot).map_err(AssetError::new)?;
            slot.owner.vault.lock().map_err(|_| AssetError::new(Reason::CleanupUnknown))?.outcome = Some(store::StorageOutcome {
                effect: store::Effect::NotStarted, durability: store::Durability::NotRun, cleanup: store::Cleanup::Pending });
            slot.vault.outcome = Some(store::StorageOutcome { effect: store::Effect::NotStarted,
                durability: store::Durability::NotRun, cleanup: store::Cleanup::Pending });
            Ok((slot, Job::Mutate { operation, record, expected, payload, label, roster, allowance: available }))
        })();
        let (slot, job) = match decision { Ok(decision) => decision, Err(error) => return Err(self.refuse_consumed(&mut state, error)) };
        if let Some(key) = slot.target.as_ref() { revoke_record(&mut state, key); }
        let initializing = slot.operation == Operation::Initialize;
        let start = self.install(&mut state, slot, super::Job::Vault(job))?;
        if let Some(session) = &mut state.vault { session.state = if initializing { State::Initializing } else { State::Mutating }; session.reason = Reason::None; }
        let status = self.snapshot(&state); drop(state); let _ = start.send(()); Ok(status)
    }
    pub(super) fn bind_vault(&self, token: &str) -> Result<AssetStatus, AssetError> {
        self.reconcile(); let mut state = self.lock(); self.expire(&mut state, Instant::now()); self.durable_gate(&state, true)?;
        let preview = self.consume_preview(&mut state, token, true)?;
        let decision = (|| -> Result<(Slot, Job), AssetError> {
            let roster = self.vault_roster(&mut state)?;
            let old = state.slot.as_ref().ok_or_else(AssetError::invalid)?;
            let context = old.context.as_ref().ok_or_else(|| AssetError::new(Reason::ContextStale))?;
            if !self.context_matches(&state, context)? || context.registry_generation != roster.generation { return Err(AssetError::new(Reason::ContextStale)); }
            let key = preview.record.as_ref().ok_or_else(AssetError::invalid)?;
            let kind = old.kind.ok_or_else(AssetError::invalid)?;
            if !usable(&state, old, key, kind) || !old.assessment.as_ref().is_some_and(SafeAssessment::permits) { return Err(AssetError::new(Reason::SourceRefused)); }
            if state.assignments.len() >= 8 && !state.assignments.iter().any(|assignment| assignment.kind == kind) { return Err(AssetError::new(Reason::Capacity)); }
            let reference = old.vault.reference.ok_or_else(AssetError::invalid)?;
            let loaded = old.vault.loaded.clone(); let assessment = old.assessment.clone(); let review = old.review_end;
            let assignment = Assignment { kind, record_id: key.id.clone(), record_revision: key.revision, context_revision: context.revision, availability: AssignmentAvailability::Available };
            let context = context.clone(); let key = key.clone();
            let mut slot = self.vault_owner(&mut state, Operation::Bind, Some(context), Some(key), review, true)?;
            slot.kind = Some(kind); slot.phase = Phase::Mutating; slot.assessment = assessment;
            slot.vault = SlotData { loaded, reference: Some(reference), generation: Some(roster.generation), ..SlotData::default() };
            Ok((slot, Job::Bind { reference, roster, assignment }))
        })();
        let (slot, job) = match decision { Ok(decision) => decision, Err(error) => return Err(self.refuse_consumed(&mut state, error)) };
        for assignment in &mut state.assignments { if Some(assignment.kind) == slot.kind { assignment.availability = AssignmentAvailability::Unavailable; } }
        let start = self.install(&mut state, slot, super::Job::Vault(job))?;
        let status = self.snapshot(&state); drop(state); let _ = start.send(()); Ok(status)
    }
}
