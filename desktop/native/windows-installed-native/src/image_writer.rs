//! Bounded, opt-in Windows PROJECT image primitives; not an installer or transaction.
//! Acquisition claims never change. Current edges, accepted effects, namespace
//! finality and handle retirement are separate, original-book-bound facts.
//! No callback/STOP runs between native return, scalar capture and effect latch.
//! No worker, DLL loader, ACL setter, READY, error rollback or recovery API exists.
//! A healthy predeclared inverse is not authority to resume a failed transaction.
//! Keep the whole owner reachable through every frame and unresolved finality.
//! This slice retains32 single-object passes and all original native/heap limits.
//! SOURCE acceptance does not qualify NTFS behavior or open the image backend gate.
use super::{
    boolean, decode, project, Aligned, CloseOutcome, DirectoryEntry, Error, FileIdentity,
    FileKind, Held, Kind, Metadata, NativeBook, Original, Phase, Result, Returned,
    SlotState, BUFFER, MAX_ENTRIES, MAX_FILES, MAX_FILE_BYTES, MAX_LIVE, MAX_RECORDS,
    MAX_TOTAL_BYTES, NAME_UNITS,
};
use std::cell::{Cell, UnsafeCell};
use std::marker::PhantomPinned;
use std::mem::{offset_of, size_of, ManuallyDrop};
use std::pin::Pin;
use std::ptr::{null, null_mut};
use std::sync::Arc;
use windows_sys::Wdk::{Foundation::OBJECT_ATTRIBUTES, Storage::FileSystem as N};
use windows_sys::Win32::{Foundation as F, Security as S, Storage::FileSystem as FS};
use windows_sys::Win32::System::{IO, WindowsProgramming as WP};

#[path = "image_writer_namespace.rs"]
mod namespace;

const R: u32 = FS::SYNCHRONIZE | FS::READ_CONTROL | FS::FILE_READ_ATTRIBUTES;
const DI: u32 = R | FS::FILE_LIST_DIRECTORY | FS::FILE_TRAVERSE;
const FR: u32 = R | FS::FILE_READ_DATA;
const DW: u32 = DI | FS::FILE_GENERIC_WRITE;
const FW: u32 = FR | FS::FILE_GENERIC_WRITE | FS::DELETE;
const MAX_PLAN_ROWS: usize = MAX_LIVE - 10; // primary + transient token + eight finality reservations
const MAX_PASSES: u16 = 32;
const PASS_ENTRIES: usize = 128;
const PASS_BYTES: u64 = 8 * 1024 * 1024;
const IMAGE_ENTRIES: usize = MAX_PASSES as usize * PASS_ENTRIES;
const IMAGE_BYTES: u64 = MAX_PASSES as u64 * PASS_BYTES;
const USER_CHECKS: u16 = 2048;
const EFFECTS: usize = 8192;
const HEAP_BYTES: usize = 16 * 1024 * 1024;
const SECURITY_BYTES: usize = 8192;
const MAX_ACES: usize = 128;
// Charged BEFORE native helper entry. Includes complete metadata/token arenas,
// decoder allocations, two descriptor copies and the returned bounded DATA chunk.
const HELPER_RESERVE: usize = 16 * BUFFER + 4 * NAME_UNITS * size_of::<u16>();

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ImageRole {
    ExistingDirectory,
    MutationParent,
    Config,
    IgnoreFile,
    UnchangedImage,
    ReplaceTarget,
    PrivateDirectory,
    ControlFile,
    StagedImage,
    StagedDirectory,
}
impl ImageRole {
    fn directory(self) -> bool {
        matches!(self, Self::ExistingDirectory | Self::MutationParent
            | Self::PrivateDirectory | Self::StagedDirectory)
    }
    fn create(self) -> bool {
        matches!(self, Self::PrivateDirectory | Self::ControlFile
            | Self::StagedImage | Self::StagedDirectory)
    }
    fn access(self) -> u32 {
        match self {
            Self::ExistingDirectory => DI,
            Self::MutationParent => DW,
            Self::Config | Self::IgnoreFile | Self::UnchangedImage => FR,
            Self::ReplaceTarget | Self::ControlFile => FW,
            Self::PrivateDirectory => DW | FS::DELETE,
            Self::StagedImage => FW | FS::WRITE_DAC | FS::WRITE_OWNER,
            Self::StagedDirectory => DW | FS::DELETE | FS::WRITE_DAC | FS::WRITE_OWNER,
        }
    }
    fn mutation_parent(self) -> bool {
        matches!(self, Self::MutationParent | Self::PrivateDirectory | Self::StagedDirectory)
    }
    fn movable(self) -> bool {
        matches!(self, Self::ReplaceTarget | Self::PrivateDirectory | Self::ControlFile
            | Self::StagedImage | Self::StagedDirectory)
    }
    fn content_writer(self) -> bool { matches!(self, Self::ControlFile | Self::StagedImage) }
    fn fence(self) -> bool {
        self.mutation_parent() || matches!(self, Self::ReplaceTarget | Self::ControlFile | Self::StagedImage)
    }
}

/// Parent 0 is the selected project root; parent n is the n-th planned child.
/// Parents must precede children. The constructor copies only admitted names;
/// callers cannot append roles/paths or upgrade an already acquired original.
#[derive(Clone, Debug)]
pub struct PlannedChild {
    pub parent: u16,
    pub name: String,
    pub role: ImageRole,
}

/// Opaque book-bound key, never a HANDLE, access mask or reopened pathname.
pub struct ImageKey { book: Arc<()>, row: usize }
pub struct PassKey { book: Arc<()>, row: usize, generation: u16 }

/// Endpoints refer to the same root-relative indexes as PlannedChild.
#[derive(Clone, Debug)]
pub struct PlannedEdge { pub parent: u16, pub name: String }
#[derive(Clone, Debug)]
pub struct PlannedMove { pub source: u16, pub from: PlannedEdge, pub to: PlannedEdge }
#[derive(Clone, Debug)]
pub struct PlannedDelete { pub source: u16, pub at: PlannedEdge }
pub struct MoveKey { book: Arc<()>, step: usize }
pub struct DeleteKey { book: Arc<()>, step: usize }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MoveObservation {
    pub step: u16,
    pub entered: bool,
    pub accepted: bool,
    pub finalized: bool,
    pub epoch: Option<u64>,
    pub change_before: Option<i64>,
    pub change_after: Option<i64>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeletionObservation {
    pub step: u16,
    pub entered: bool,
    pub disposition_accepted: bool,
    pub close_attempted: bool,
    pub handle_retired: bool,
    pub deleted: bool,
    pub disposition_epoch: Option<u64>,
    pub retired_epoch: Option<u64>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MoveReceipt {
    pub step: u16,
    pub identity: FileIdentity,
    pub epoch: u64,
    pub change_before: i64,
    pub change_after: i64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeletionReceipt { pub step: u16, pub identity: FileIdentity, pub epoch: u64 }

// This is the only image-name value accepted by the private NativeBook seam.
// No caller-supplied canonical string, native selector or HANDLE is exported.
pub(super) struct CurrentName<'a> {
    book: &'a Arc<()>,
    slot: usize,
    row: usize,
    epoch: u64,
    namespace: &'a namespace::Namespace,
}
impl CurrentName<'_> {
    pub(super) fn canonical_for(&self, book: &Arc<()>, slot: usize) -> Result<&str> {
        if !Arc::ptr_eq(book, self.book) || slot != self.slot || !self.namespace.original_is(self.row, slot) { return Err(Error::State); }
        self.namespace.name(self.row, self.epoch).map_err(namespace_error)
    }
}
struct RosterEvidence {
    row: usize,
    generation: u16,
    epoch: u64,
    after: Snapshot,
    entries: Vec<DirectoryEntry>, // all non-dot records, not selected-only DATA
}
struct PendingMove {
    step: usize,
    before: Snapshot,
    prepared: Option<namespace::PreparedMove>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EffectKind { ExistingOpen, ExclusiveCreate, Write, Read, FullFence, SecurityQuery, RosterRestart, RosterContinue, Rename, Disposition }
#[derive(Clone, Copy, Debug)]
pub enum NativeReturn { Nt(i32), Boolean { value: i32, error: u32 } }
#[derive(Clone, Copy, Debug)]
pub struct EffectObservation {
    pub kind: EffectKind,
    pub row: u16,
    pub entered: bool,
    pub returned: Option<NativeReturn>,
    pub iosb_status: Option<i32>,
    pub information: Option<u64>,
    pub adopted: bool,
    pub latched: bool, // accepted namespace effect, not durable finality
    pub complete: bool,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PassKind { Read, Roster }
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PassReceipt {
    pub generation: u16,
    pub kind: PassKind,
    pub identity: FileIdentity,
    pub bytes: u64,
    pub entries: u32,
}
#[derive(Clone, Copy, Debug)]
pub struct CostObservation {
    pub native_live: usize,
    pub native_records: usize,
    pub native_file_records: usize,
    pub cumulative_entries: usize,
    pub cumulative_read_bytes: u64,
    pub cumulative_written_bytes: u64,
    pub user_checks: u16,
    pub passes_started: u16,
    pub effects_entered: usize,
    pub retained_heap_bytes: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Descriptor { raw: Vec<u8> }
#[derive(Clone, Debug, Eq, PartialEq)]
struct Snapshot { metadata: Metadata, security: Descriptor }
// Borrow the exact proved state; an index retains the existing roster Snapshot
// without cloning its descriptor or starting a fresh fence baseline.
#[derive(Clone, Copy)]
enum FenceExpected<'a> { SourceAfter(&'a Snapshot), Roster(usize) }
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WriteState { NotWriter, Open, Finished }
struct Row {
    role: ImageRole,
    parent: Option<usize>,
    name: String,
    // Immutable acquisition facts. Separate Namespace owns all current edges.
    attempted: bool,
    original: Option<Original>,
    acquisition: Option<Snapshot>,
    current: Option<Snapshot>,
    written: u64,
    write_state: WriteState,
}
struct Pass {
    row: usize,
    generation: u16,
    kind: PassKind,
    before: Snapshot,
    epoch: u64,
    entries: Vec<DirectoryEntry>,
    bytes: u64,
    names: Vec<String>,
    entry_count: usize,
    seen_edges: u64,
    first_batch: bool,
}
#[derive(Clone, Copy)]
enum ImageCall {
    Open { row: usize, slot: usize, create: bool, epoch: Option<namespace::Epoch> },
    Write { row: usize, count: usize },
    Read { row: usize, count: usize },
    Fence { row: usize },
    Security { row: usize },
    Roster { row: usize, restart: bool },
    Rename { row: usize, step: usize },
    Disposition { row: usize, step: usize, epoch: namespace::Epoch },
}
impl ImageCall {
    fn row(self) -> usize {
        match self {
            Self::Open { row, .. } | Self::Write { row, .. } | Self::Read { row, .. }
                | Self::Fence { row } | Self::Security { row } | Self::Roster { row, .. }
                | Self::Rename { row, .. } | Self::Disposition { row, .. } => row,
        }
    }
    fn kind(self) -> EffectKind {
        match self {
            Self::Open { create: false, .. } => EffectKind::ExistingOpen,
            Self::Open { create: true, .. } => EffectKind::ExclusiveCreate,
            Self::Write { .. } => EffectKind::Write,
            Self::Read { .. } => EffectKind::Read,
            Self::Fence { .. } => EffectKind::FullFence,
            Self::Security { .. } => EffectKind::SecurityQuery,
            Self::Roster { restart: true, .. } => EffectKind::RosterRestart,
            Self::Roster { restart: false, .. } => EffectKind::RosterContinue,
            Self::Rename { .. } => EffectKind::Rename,
            Self::Disposition { .. } => EffectKind::Disposition,
        }
    }
}
struct Frame {
    call: ImageCall,
    effect: usize,
    phase: Cell<Phase>,
    returned: Cell<Option<Returned>>,
    handle: F::HANDLE,
    output_handle: *mut F::HANDLE,
    input: Vec<u16>,
    unicode: F::UNICODE_STRING,
    attributes: OBJECT_ATTRIBUTES,
    access: u32,
    directory: bool,
    offset: i64,
    information_length: u32,
    bytes: UnsafeCell<Aligned>,
    count: UnsafeCell<u32>,
    iosb: UnsafeCell<IO::IO_STATUS_BLOCK>,
    _pin: PhantomPinned,
}
impl Frame { fn buffer(&self) -> *mut u8 { self.bytes.get().cast() } }
struct Completed { frame: Pin<Box<Frame>> }
impl Completed {
    fn returned(&self) -> Result<Returned> { self.frame.returned.get().ok_or(Error::Unknown) }
    fn bytes(&self, count: usize) -> Result<&[u8]> {
        if self.frame.phase.get() != Phase::Complete || count > BUFFER { return Err(Error::Unknown); }
        // SAFETY: only definite completion constructs Completed; no outstanding
        // native writer can address this still-pinned initialized allocation.
        Ok(unsafe { std::slice::from_raw_parts(self.frame.buffer(), count) })
    }
    fn io_count(&self) -> Result<usize> {
        if self.frame.phase.get() != Phase::Complete { return Err(Error::Unknown); }
        // SAFETY: used only on corroborated STATUS_SUCCESS, never pending/EOF.
        let count = unsafe { (*self.frame.iosb.get()).Information };
        if count > BUFFER { return Err(Error::Unknown); }
        Ok(count)
    }
}

/// Own exactly ONE NativeBook, its original token/slots/counters and this extension
/// frame. It is never lent out. Every NativeBook call is excluded while the image
/// frame is present. UNKNOWN cannot be cured by a new pass or a fresh book here.
pub struct ImagePrimitives {
    native: NativeBook,
    drive: String,
    device: Option<String>,
    rows: Vec<Row>,
    root: usize,
    namespace: namespace::Namespace,
    move_observations: Vec<MoveObservation>,
    deletion_observations: Vec<DeletionObservation>,
    pending_move: Option<PendingMove>,
    pending_deletion: Option<usize>,
    roster_evidence: Vec<RosterEvidence>,
    latest_roster: [u16; MAX_PLAN_ROWS],
    close_requested: [bool; MAX_RECORDS],
    begun: bool,
    failed: Option<Error>,
    final_attempted: bool,
    active: Option<Held<Frame>>,
    pass: Option<Pass>,
    passes: u16,
    user_checks: u16,
    written_bytes: u64,
    effects: Vec<EffectObservation>,
    receipts: Vec<PassReceipt>,
}
// SAFETY: the whole exclusive owner moves; raw values never escape. Windows
// handles are process-wide, all IO storage is pinned, and &mut self serializes
// native entry. This is intentionally NOT Sync. Context is freshly observed.
unsafe impl Send for ImagePrimitives {}

impl ImagePrimitives {
    /// Pure bounded SOURCE interface; no filesystem/token call in this constructor.
    pub fn prepare(project_path: &str, children: &[PlannedChild]) -> Result<Self> {
        Self::prepare_lifecycle(project_path, children, &[], &[])
    }
    /// All acquisition, move, inverse and deletion roles/edges freeze before entry.
    /// This is not a transaction schedule and has no recovery/rollback authority.
    pub fn prepare_lifecycle(project_path: &str, children: &[PlannedChild],
        planned_moves: &[PlannedMove], planned_deletes: &[PlannedDelete]) -> Result<Self> {
        if children.len() > MAX_PLAN_ROWS || planned_moves.len() > namespace::MAX_MOVES
            || planned_deletes.len() > namespace::MAX_DELETES { return Err(Error::Bounds); }
        let (drive, components) = project::spelling(project_path)?;
        if !drive.is_ascii() || components.iter().any(|part| !part.is_ascii())
            || children.iter().any(|child| child.name.len() > 255 || !child.name.is_ascii() || !decode::component(&child.name)) {
            return Err(Error::Unsafe);
        }
        let count = components.len().checked_add(1).and_then(|n| n.checked_add(children.len())).ok_or(Error::Bounds)?;
        if count > MAX_PLAN_ROWS || count > namespace::MAX_ROWS
            || count + 1 + 2 * USER_CHECKS as usize + 24 > MAX_RECORDS { return Err(Error::Bounds); }
        let root = components.len();
        let mut rows = Vec::new();
        rows.try_reserve_exact(count).map_err(|_| Error::Bounds)?;
        rows.push(new_row(ImageRole::ExistingDirectory, None, String::new()));
        for (index, name) in components.into_iter().enumerate() {
            let role = if index + 1 == root { ImageRole::MutationParent } else { ImageRole::ExistingDirectory };
            rows.push(new_row(role, Some(index), name));
        }
        for (index, child) in children.iter().enumerate() {
            if child.parent as usize > index { return Err(Error::State); }
            let parent = root + child.parent as usize;
            if !rows[parent].role.directory() || child.role.create() && !rows[parent].role.mutation_parent() {
                return Err(Error::State);
            }
            if rows.iter().any(|row| row.parent == Some(parent) && row.name.eq_ignore_ascii_case(&child.name)) {
                return Err(Error::Unsafe);
            }
            rows.push(new_row(child.role, Some(parent), child.name.clone()));
        }
        if rows.iter().filter(|row| !row.role.directory()).count() > MAX_FILES { return Err(Error::Bounds); }
        let nodes: Vec<_> = rows.iter().enumerate().map(|(row, facts)| namespace::Node {
            parent: facts.parent, name: facts.name.clone(), directory: facts.role.directory(),
            mutation_parent: row >= root && facts.role.mutation_parent(),
            movable: row > root && facts.role.movable(),
        }).collect();
        let edge = |input: &PlannedEdge| -> Result<namespace::Edge> {
            let parent = root.checked_add(input.parent as usize).ok_or(Error::Bounds)?;
            if parent >= rows.len() || !rows[parent].role.mutation_parent()
                || input.name.len() > 255 || !input.name.is_ascii() || !decode::component(&input.name) { return Err(Error::Unsafe); }
            Ok(namespace::Edge { parent, name: input.name.clone() })
        };
        let source = |input: u16| -> Result<usize> {
            let row = root.checked_add(input as usize).ok_or(Error::Bounds)?;
            if row <= root || row >= rows.len() || !rows[row].role.movable() { return Err(Error::Unsafe); }
            Ok(row)
        };
        let mut moves = Vec::new();
        moves.try_reserve_exact(planned_moves.len()).map_err(|_| Error::Bounds)?;
        for plan in planned_moves {
            let row = source(plan.source)?;
            let movement = namespace::Move { row, from: edge(&plan.from)?, to: edge(&plan.to)? };
            if rows[row].role == ImageRole::ReplaceTarget {
                let original = namespace::Edge { parent: rows[row].parent.ok_or(Error::State)?, name: rows[row].name.clone() };
                // An existing target only enters a private old-N backup, or a
                // separately declared inverse returns THAT original to its edge.
                if !((movement.from == original && backup_edge(&rows, &movement.to))
                    || (movement.to == original && backup_edge(&rows, &movement.from))) { return Err(Error::Unsafe); }
            }
            moves.push(movement);
        }
        let mut deletes = Vec::new();
        deletes.try_reserve_exact(planned_deletes.len()).map_err(|_| Error::Bounds)?;
        for plan in planned_deletes {
            let row = source(plan.source)?;
            let deletion = namespace::Delete { row, edge: edge(&plan.at)? };
            let original = namespace::Edge { parent: rows[row].parent.ok_or(Error::State)?, name: rows[row].name.clone() };
            if rows[row].role == ImageRole::ReplaceTarget
                && (deletion.edge == original || !backup_edge(&rows, &deletion.edge)) {
                return Err(Error::Unsafe);
            }
            deletes.push(deletion);
        }
        let namespace = namespace::Namespace::new(&nodes, &moves, &deletes, NAME_UNITS).map_err(namespace_error)?;
        let mut move_observations = Vec::new();
        move_observations.try_reserve_exact(moves.len()).map_err(|_| Error::Bounds)?;
        for step in 0..moves.len() {
            move_observations.push(MoveObservation { step: step as u16, entered: false, accepted: false,
                finalized: false, epoch: None, change_before: None, change_after: None });
        }
        let mut deletion_observations = Vec::new();
        deletion_observations.try_reserve_exact(deletes.len()).map_err(|_| Error::Bounds)?;
        for step in 0..deletes.len() {
            deletion_observations.push(DeletionObservation { step: step as u16, entered: false,
                disposition_accepted: false, close_attempted: false, handle_retired: false,
                deleted: false, disposition_epoch: None, retired_epoch: None });
        }
        let mut native = NativeBook::new();
        // Only retained record storage is reserved. Default/native48 is unchanged.
        native.slots.try_reserve_exact(count + 1 + 2 * USER_CHECKS as usize + 24).map_err(|_| Error::Bounds)?;
        let mut effects = Vec::new();
        effects.try_reserve_exact(EFFECTS).map_err(|_| Error::Bounds)?;
        let mut receipts = Vec::new();
        receipts.try_reserve_exact(MAX_PASSES as usize).map_err(|_| Error::Bounds)?;
        let mut roster_evidence = Vec::new();
        roster_evidence.try_reserve_exact(MAX_PASSES as usize).map_err(|_| Error::Bounds)?;
        let owner = Self { native, drive, device: None, rows, root, namespace,
            move_observations, deletion_observations, pending_move: None, pending_deletion: None,
            roster_evidence, latest_roster: [0; MAX_PLAN_ROWS], close_requested: [false; MAX_RECORDS],
            begun: false, failed: None, final_attempted: false, active: None, pass: None,
            passes: 0, user_checks: 0, written_bytes: 0, effects, receipts };
        owner.budget(HELPER_RESERVE)?;
        Ok(owner)
    }

    /// Index 0 is the selected project root, then exactly the admitted children.
    pub fn key(&self, index: u16) -> Result<ImageKey> {
        let row = self.root.checked_add(index as usize).ok_or(Error::Bounds)?;
        self.rows.get(row).ok_or(Error::State)?;
        Ok(ImageKey { book: Arc::clone(&self.native.identity), row })
    }
    pub fn move_key(&self, step: u16) -> Result<MoveKey> {
        self.namespace.move_plan(step as usize).map_err(namespace_error)?;
        Ok(MoveKey { book: Arc::clone(&self.native.identity), step: step as usize })
    }
    pub fn delete_key(&self, step: u16) -> Result<DeleteKey> {
        self.namespace.delete_plan(step as usize).map_err(namespace_error)?;
        Ok(DeleteKey { book: Arc::clone(&self.native.identity), step: step as usize })
    }
    pub fn move_observations(&self) -> &[MoveObservation] { &self.move_observations }
    pub fn deletion_observations(&self) -> &[DeletionObservation] { &self.deletion_observations }
    pub fn namespace_epoch(&self) -> u64 { self.namespace.epoch() }
    /// Neither this fact nor HANDLE settlement is transaction success.
    pub fn accepted_effects_finalized(&self) -> bool {
        self.active.is_none() && !self.is_unknown()
            && self.move_observations.iter().all(|fact| !fact.accepted || fact.finalized)
            && self.deletion_observations.iter().all(|fact| !fact.disposition_accepted || fact.deleted)
    }
    fn move_step(&self, key: &MoveKey) -> Result<usize> {
        if !Arc::ptr_eq(&key.book, &self.native.identity) { return Err(Error::State); }
        self.namespace.move_plan(key.step).map_err(namespace_error)?;
        Ok(key.step)
    }
    fn delete_step(&self, key: &DeleteKey) -> Result<usize> {
        if !Arc::ptr_eq(&key.book, &self.native.identity) { return Err(Error::State); }
        self.namespace.delete_plan(key.step).map_err(namespace_error)?;
        Ok(key.step)
    }
    fn mutation_idle(&self) -> Result<()> {
        self.idle()?;
        if self.pending_move.is_some() || self.pending_deletion.is_some() { return Err(Error::State); }
        Ok(())
    }
    fn delete_pending(&self, row: usize) -> bool {
        self.deletion_observations.iter().enumerate().any(|(step, fact)|
            fact.disposition_accepted && !fact.deleted
                && self.namespace.delete_plan(step).is_ok_and(|plan| plan.row == row))
    }
    fn owned(&self, row: usize) -> Result<()> {
        if self.native.state(self.original(row)?)? != SlotState::Owned || self.delete_pending(row) {
            return Err(Error::State);
        }
        Ok(())
    }
    fn live_rows(&self) -> u64 {
        self.rows.iter().enumerate().fold(0, |bits, (row, facts)| {
            if facts.original.as_ref().is_some_and(|key|
                !matches!(self.native.state(key), Ok(SlotState::NoHandle | SlotState::Closed))) {
                bits | (1u64 << row)
            } else { bits }
        })
    }
    fn protected_rows(&self) -> u64 {
        // An unfinished cursor is not a completed observation. Conservatively
        // keep its entire declared graph and token context until owner settlement.
        let mut needed = if self.pass.is_some() { (1u64 << self.rows.len()) - 1 } else { 0 };
        if let Some(pending) = &self.pending_move {
            if let Ok(plan) = self.namespace.move_plan(pending.step) {
                needed |= (1u64 << plan.row) | (1u64 << plan.from.parent) | (1u64 << plan.to.parent);
            }
        }
        if let Some(step) = self.pending_deletion {
            if let Ok(plan) = self.namespace.delete_plan(step) {
                needed |= 1u64 << plan.edge.parent; // CURRENT declared parent, not Slot.parent
                if !self.deletion_observations[step].handle_retired { needed |= 1u64 << plan.row; }
            }
        }
        self.namespace.dependency_closure(needed)
    }

    pub fn effects(&self) -> &[EffectObservation] { &self.effects }
    pub fn pass_receipts(&self) -> &[PassReceipt] { &self.receipts }
    pub fn first_failure(&self) -> Option<Error> { self.failed }
    pub fn is_unknown(&self) -> bool { self.native.is_unknown() || self.active.is_some() }
    pub fn settled(&self) -> bool { self.final_attempted && self.active.is_none() && self.native.settled() }
    pub fn costs(&self) -> Result<CostObservation> {
        Ok(CostObservation {
            native_live: self.native.slots.iter().filter(|slot| !matches!(slot.state, SlotState::NoHandle | SlotState::Closed)).count(),
            native_records: self.native.slots.len(),
            native_file_records: self.native.slots.iter().filter(|slot| slot.kind == Kind::File).count(),
            cumulative_entries: self.native.entries,
            cumulative_read_bytes: self.native.bytes_read,
            cumulative_written_bytes: self.written_bytes,
            user_checks: self.user_checks,
            passes_started: self.passes,
            effects_entered: self.effects.iter().filter(|effect| effect.entered).count(),
            retained_heap_bytes: self.heap_bytes().ok_or(Error::Bounds)?,
        })
    }
    pub fn acquisition_identity(&self, key: &ImageKey) -> Result<FileIdentity> {
        Ok(self.rows[self.row(key)?].acquisition.as_ref().ok_or(Error::State)?.metadata.identity)
    }

    fn row(&self, key: &ImageKey) -> Result<usize> {
        if !Arc::ptr_eq(&self.native.identity, &key.book) { return Err(Error::State); }
        self.rows.get(key.row).ok_or(Error::State)?;
        Ok(key.row)
    }
    fn original(&self, row: usize) -> Result<&Original> {
        self.rows.get(row).and_then(|row| row.original.as_ref()).ok_or(Error::State)
    }
    fn usable(&self) -> Result<()> {
        if self.is_unknown() { return Err(Error::Unknown); }
        if self.failed.is_some() || self.final_attempted { return Err(Error::State); }
        self.native.clear()
    }
    fn idle(&self) -> Result<()> {
        self.usable()?;
        if self.pass.is_some() { return Err(Error::State); }
        Ok(())
    }
    fn record<T>(&mut self, result: Result<T>) -> Result<T> {
        if let Err(error) = &result {
            if self.failed.is_none() { self.failed = Some(*error); }
            if *error == Error::Unknown { self.native.mark_interrupted(); }
        }
        result
    }
    fn unknown<T>(&mut self) -> Result<T> {
        self.native.mark_interrupted();
        if self.failed.is_none() { self.failed = Some(Error::Unknown); }
        Err(Error::Unknown)
    }
    fn heap_bytes(&self) -> Option<usize> {
        let mut count = size_of::<Self>().checked_add(self.native.public_image_retained_heap_bytes()?)?
            .checked_add(self.namespace.heap_bytes()?)?
            .checked_add(self.drive.capacity())?
            .checked_add(self.device.as_ref().map_or(0, String::capacity))?
            .checked_add(self.rows.capacity().checked_mul(size_of::<Row>())?)?
            .checked_add(self.effects.capacity().checked_mul(size_of::<EffectObservation>())?)?
            .checked_add(self.receipts.capacity().checked_mul(size_of::<PassReceipt>())?)?
            .checked_add(self.move_observations.capacity().checked_mul(size_of::<MoveObservation>())?)?
            .checked_add(self.deletion_observations.capacity().checked_mul(size_of::<DeletionObservation>())?)?
            .checked_add(self.roster_evidence.capacity().checked_mul(size_of::<RosterEvidence>())?)?;
        for row in &self.rows {
            count = count.checked_add(row.name.capacity())?;
            for snapshot in [&row.acquisition, &row.current].into_iter().flatten() {
                count = count.checked_add(snapshot.security.raw.capacity())?;
            }
        }
        for proof in &self.roster_evidence {
            count = count.checked_add(proof.after.security.raw.capacity())?
                .checked_add(entry_heap(&proof.entries)?)?;
        }
        if let Some(pass) = &self.pass {
            count = count.checked_add(pass.before.security.raw.capacity())?
                .checked_add(pass.names.capacity().checked_mul(size_of::<String>())?)?
                .checked_add(entry_heap(&pass.entries)?)?;
            for name in &pass.names { count = count.checked_add(name.capacity())?; }
        }
        if let Some(pending) = &self.pending_move {
            count = count.checked_add(pending.before.security.raw.capacity())?;
            if let Some(prepared) = &pending.prepared { count = count.checked_add(prepared.heap_bytes()?)?; }
        }
        if let Some(frame) = &self.active {
            count = count.checked_add(size_of::<Frame>())?
                .checked_add(frame.input.capacity().checked_mul(size_of::<u16>())?)?;
        }
        Some(count)
    }
    fn budget(&self, extra: usize) -> Result<()> {
        if self.heap_bytes().and_then(|n| n.checked_add(extra)).is_none_or(|n| n > HEAP_BYTES) {
            Err(Error::Bounds)
        } else { Ok(()) }
    }
    fn check_user(&mut self) -> Result<()> {
        self.usable()?;
        if self.user_checks >= USER_CHECKS { return Err(Error::Bounds); }
        self.budget(HELPER_RESERVE)?;
        self.user_checks += 1; // two absent-thread originals charged before entry
        self.native.recheck_user()?;
        self.budget(0)
    }

    pub fn begin_once(&mut self) -> Result<()> {
        let result = self.begin_inner();
        self.record(result)
    }
    fn begin_inner(&mut self) -> Result<()> {
        self.mutation_idle()?;
        if self.begun || !self.native.never_started() { return Err(Error::State); }
        self.budget(HELPER_RESERVE)?;
        self.begun = true;
        self.user_checks = 1;
        self.native.observe_user_once()?;
        self.device = Some(self.native.mapping(&self.drive)?);
        self.namespace.bind_volume(self.device.as_deref().ok_or(Error::State)?).map_err(namespace_error)?;
        self.budget(HELPER_RESERVE)?;
        for row in 0..=self.root { self.acquire_row(row)?; }
        self.check_user()
    }

    pub fn acquire_once(&mut self, key: &ImageKey) -> Result<()> {
        let result = self.acquire_inner(key);
        self.record(result)
    }
    fn acquire_inner(&mut self, key: &ImageKey) -> Result<()> {
        self.mutation_idle()?;
        if !self.begun { return Err(Error::State); }
        let row = self.row(key)?;
        self.check_user()?;
        self.acquire_row(row)?;
        self.check_user()
    }
    fn acquire_row(&mut self, row: usize) -> Result<()> {
        self.mutation_idle()?;
        if self.rows[row].attempted { return Err(Error::State); }
        let role = self.rows[row].role;
        let parent = self.rows[row].parent;
        if self.namespace.parent(row).map_err(namespace_error)? != parent
            || self.namespace.leaf(row).map_err(namespace_error)? != self.rows[row].name {
            return Err(Error::State);
        }
        if let Some(parent) = parent { self.check_current(parent)?; }
        self.budget(HELPER_RESERVE)?;
        // Same original parent, but a moved directory's descendants now resolve
        // through the separate CURRENT graph. No Slot acquisition field changes.
        let canonical = self.namespace.claim_acquisition(row).map_err(namespace_error)?;
        let epoch = if role.create() { Some(self.namespace.next_epoch().map_err(namespace_error)?) } else { None };
        let parent_slot = parent.map(|parent| self.original(parent).map(|key| key.index)).transpose()?;
        let name = if parent.is_none() { canonical.clone() } else { self.rows[row].name.clone() };
        self.rows[row].attempted = true;
        let original = self.native.reserve(if role.directory() { Kind::Directory } else { Kind::File }, parent_slot, &name, canonical)?;
        let slot = original.index;
        self.rows[row].original = Some(original); // BEFORE original OS acquisition
        self.namespace.bind_original(row, slot).map_err(namespace_error)?;
        self.call(ImageCall::Open { row, slot, create: role.create(), epoch }, 0, &[])?;
        self.native.noninherited(slot)?;
        let snapshot = self.snapshot(row)?;
        if role.create() && !role.directory() && snapshot.metadata.size != 0 { return Err(Error::Unsafe); }
        for (other, prior) in self.rows.iter().enumerate() {
            if other != row && prior.acquisition.as_ref().is_some_and(|prior| prior.metadata.identity == snapshot.metadata.identity) {
                return Err(Error::Unsafe);
            }
        }
        if let Some(parent) = parent {
            let identity = self.rows[parent].acquisition.as_ref().ok_or(Error::State)?.metadata.identity;
            if identity.volume_serial != snapshot.metadata.identity.volume_serial { return Err(Error::Unsafe); }
        }
        self.rows[row].acquisition = Some(snapshot.clone());
        self.rows[row].current = Some(snapshot);
        if let Some(parent) = parent { self.check_current(parent)?; }
        self.budget(0)
    }

    fn snapshot(&mut self, row: usize) -> Result<Snapshot> {
        self.usable()?;
        self.owned(row)?; // in particular, never query a delete-pending original
        self.budget(HELPER_RESERVE)?;
        let slot = self.original(row)?.index;
        let book = Arc::clone(&self.native.identity);
        let original = Original { book: Arc::clone(&book), index: slot };
        self.native.local_ntfs(&original)?;
        let name = CurrentName { book: &book, slot, row, epoch: self.namespace.epoch(), namespace: &self.namespace };
        let metadata = self.native.image_current_metadata(&original, &name)?;
        self.native.no_alternate_streams(&original)?;
        let complete = self.call(ImageCall::Security { row }, 0, &[])?;
        // SAFETY: successful synchronous BOOL query was corroborated and bounded.
        let count = unsafe { *complete.frame.count.get() } as usize;
        let security = descriptor(complete.bytes(count)?)?;
        Ok(Snapshot { metadata, security })
    }
    fn check_current(&mut self, row: usize) -> Result<()> {
        let actual = self.snapshot(row)?;
        let prior = self.rows[row].current.as_ref().ok_or(Error::State)?;
        if !same_identity_security(prior, &actual)
            || !self.rows[row].role.directory() && prior != &actual { return Err(Error::Unsafe); }
        Ok(())
    }

    /// Append exactly one bounded owned chunk to a NEW control/staging original.
    /// No existing target content, truncation, seek-back or retry is exposed.
    /// A short write is recorded/charged but poisons this lease, never retried.
    pub fn write_chunk(&mut self, key: &ImageKey, bytes: &[u8]) -> Result<()> {
        let result = self.write_inner(key, bytes);
        self.record(result)
    }
    fn write_inner(&mut self, key: &ImageKey, bytes: &[u8]) -> Result<()> {
        self.mutation_idle()?;
        let row = self.row(key)?;
        if bytes.is_empty() || bytes.len() > BUFFER { return Err(Error::Bounds); }
        if !self.rows[row].role.content_writer() || self.rows[row].write_state != WriteState::Open {
            return Err(Error::State);
        }
        self.check_user()?;
        self.check_current(row)?;
        let offset = self.rows[row].written;
        if offset.checked_add(bytes.len() as u64).is_none_or(|n| n > PASS_BYTES)
            || self.written_bytes.checked_add(bytes.len() as u64).is_none_or(|n| n > IMAGE_BYTES) {
            return Err(Error::Bounds);
        }
        let complete = self.call(ImageCall::Write { row, count: bytes.len() }, offset, bytes)?;
        let actual = complete.io_count()?;
        // Latch actual bytes before semantic checks, a clock/STOP, or ABI return.
        self.rows[row].written = offset.checked_add(actual as u64).ok_or(Error::Bounds)?;
        self.written_bytes = self.written_bytes.checked_add(actual as u64).ok_or(Error::Bounds)?;
        if actual != bytes.len() { return Err(Error::Unavailable); }
        let after = self.snapshot(row)?;
        let prior = self.rows[row].current.as_ref().ok_or(Error::State)?;
        if !same_identity_security(prior, &after) || after.metadata.size != self.rows[row].written {
            return Err(Error::Unsafe);
        }
        self.rows[row].current = Some(after);
        self.check_user()
    }

    /// Full flags=0 file fence on the SAME newly written handle. This ends the
    /// write stream, not a transaction: a later full read pass must still compare
    /// every byte/digest with the retained input, and stage ACL work is absent.
    pub fn finish_write_once(&mut self, key: &ImageKey) -> Result<()> {
        let result = self.finish_write_inner(key);
        self.record(result)
    }
    fn finish_write_inner(&mut self, key: &ImageKey) -> Result<()> {
        self.mutation_idle()?;
        let row = self.row(key)?;
        if !self.rows[row].role.content_writer() || self.rows[row].write_state != WriteState::Open {
            return Err(Error::State);
        }
        self.check_user()?;
        self.check_current(row)?;
        self.call(ImageCall::Fence { row }, 0, &[])?;
        let after = self.snapshot(row)?;
        let prior = self.rows[row].current.as_ref().ok_or(Error::State)?;
        if !same_identity_security(prior, &after) || after.metadata.size != self.rows[row].written {
            return Err(Error::Unsafe);
        }
        self.rows[row].current = Some(after);
        self.rows[row].write_state = WriteState::Finished;
        self.check_user()
    }

    /// Exact full file/directory primitive, never DATA_ONLY/NO_SYNC or a file-only
    /// substitute for a refused directory fence. Access intent was fixed at open.
    pub fn full_fence(&mut self, key: &ImageKey) -> Result<()> {
        let result = self.fence_inner(key);
        self.record(result)
    }
    fn fence_inner(&mut self, key: &ImageKey) -> Result<()> {
        self.idle()?;
        let row = self.row(key)?;
        if !self.rows[row].role.fence() || self.rows[row].write_state == WriteState::Open {
            return Err(Error::State);
        }
        self.check_user()?;
        self.check_current(row)?;
        let before = self.snapshot(row)?;
        self.call(ImageCall::Fence { row }, 0, &[])?;
        if before != self.snapshot(row)? { return Err(Error::Unsafe); }
        self.check_user()
    }

    pub fn begin_read_pass(&mut self, key: &ImageKey) -> Result<PassKey> {
        let result = self.begin_pass(key, PassKind::Read);
        self.record(result)
    }
    pub fn begin_roster_pass(&mut self, key: &ImageKey) -> Result<PassKey> {
        let result = self.begin_pass(key, PassKind::Roster);
        self.record(result)
    }
    fn begin_pass(&mut self, key: &ImageKey, kind: PassKind) -> Result<PassKey> {
        self.idle()?;
        let row = self.row(key)?;
        if self.rows[row].role.directory() != (kind == PassKind::Roster)
            || self.rows[row].write_state == WriteState::Open { return Err(Error::State); }
        if self.passes >= MAX_PASSES { return Err(Error::Bounds); }
        self.check_user()?;
        self.budget(HELPER_RESERVE)?;
        self.passes += 1; // charged before the first boundary observation
        self.check_current(row)?;
        let before = self.snapshot(row)?;
        if kind == PassKind::Read && before.metadata.size > PASS_BYTES { return Err(Error::Bounds); }
        let mut names = Vec::new();
        names.try_reserve_exact(PASS_ENTRIES).map_err(|_| Error::Bounds)?;
        let mut entries = Vec::new();
        entries.try_reserve_exact(PASS_ENTRIES).map_err(|_| Error::Bounds)?;
        self.pass = Some(Pass { row, generation: self.passes, kind, before, epoch: self.namespace.epoch(),
            entries, bytes: 0, names, entry_count: 0, seen_edges: 0, first_batch: true });
        self.check_user()?;
        Ok(PassKey { book: Arc::clone(&self.native.identity), row, generation: self.passes })
    }
    fn pass_row(&self, key: &PassKey, kind: PassKind) -> Result<usize> {
        self.usable()?;
        let pass = self.pass.as_ref().ok_or(Error::State)?;
        if !Arc::ptr_eq(&key.book, &self.native.identity) || pass.row != key.row
            || pass.generation != key.generation || pass.kind != kind || pass.epoch != self.namespace.epoch() { return Err(Error::State); }
        Ok(pass.row)
    }

    /// Explicit offsets on the SAME synchronous original, including an actual
    /// EOF query. None means metadata/owner/group/DACL/name POST also completed.
    /// Failed/abandoned passes cannot begin another generation or reset counters.
    pub fn read_next(&mut self, key: &PassKey) -> Result<Option<Vec<u8>>> {
        let result = self.read_inner(key);
        self.record(result)
    }
    fn read_inner(&mut self, key: &PassKey) -> Result<Option<Vec<u8>>> {
        let row = self.pass_row(key, PassKind::Read)?;
        self.check_user()?;
        let pass = self.pass.as_ref().ok_or(Error::State)?;
        let offset = pass.bytes;
        let expected = pass.before.metadata.size;
        let slot = self.original(row)?.index;
        let prior = self.native.slot(slot)?.read_bytes;
        if self.native.bytes_read > MAX_TOTAL_BYTES || prior > MAX_FILE_BYTES
            || self.native.bytes_read > IMAGE_BYTES || offset > PASS_BYTES { return Err(Error::Bounds); }
        let remaining = (MAX_TOTAL_BYTES - self.native.bytes_read)
            .min(MAX_FILE_BYTES - prior).min(IMAGE_BYTES - self.native.bytes_read)
            .min(PASS_BYTES - offset).min(expected.saturating_sub(offset));
        // One extra byte distinguishes exact-limit EOF from newly grown content.
        // Excess is charged but never offered to the caller or another generation.
        let request = BUFFER.min(remaining.min(BUFFER as u64 - 1) as usize + 1);
        let complete = self.call(ImageCall::Read { row, count: request }, offset, &[])?;
        let count = if matches!(complete.returned()?, Returned::Nt(F::STATUS_END_OF_FILE)) {
            0 // definite NT EOF never authorizes reading an unwritten IOSB
        } else { complete.io_count()? };
        self.native.bytes_read = self.native.bytes_read.checked_add(count as u64).ok_or(Error::Bounds)?;
        self.native.slot_mut(slot)?.read_bytes = prior.checked_add(count as u64).ok_or(Error::Bounds)?;
        self.pass.as_mut().ok_or(Error::State)?.bytes = offset.checked_add(count as u64).ok_or(Error::Bounds)?;
        if self.native.bytes_read > MAX_TOTAL_BYTES || self.native.bytes_read > IMAGE_BYTES
            || self.native.slot(slot)?.read_bytes > MAX_FILE_BYTES
            || self.pass.as_ref().ok_or(Error::State)?.bytes > PASS_BYTES { return Err(Error::Bounds); }
        if offset.checked_add(count as u64).is_none_or(|n| n > expected) { return Err(Error::Unsafe); }
        if count == 0 {
            if offset != expected { return Err(Error::Unsafe); }
            self.end_pass()?;
            return Ok(None);
        }
        self.budget(HELPER_RESERVE)?;
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(count).map_err(|_| Error::Bounds)?;
        bytes.extend_from_slice(complete.bytes(count)?);
        self.check_user()?;
        Ok(Some(bytes))
    }

    /// Drains one original restart/continuation cursor to real NO_MORE_FILES.
    /// Each accepted batch and dot record consumes the unchanged NativeBook entry
    /// budget; duplicates and selected edge/full-ID mismatches poison the lease.
    pub fn roster_next(&mut self, key: &PassKey) -> Result<Option<Vec<DirectoryEntry>>> {
        let result = self.roster_inner(key);
        self.record(result)
    }
    fn roster_inner(&mut self, key: &PassKey) -> Result<Option<Vec<DirectoryEntry>>> {
        let row = self.pass_row(key, PassKind::Roster)?;
        self.check_user()?;
        if self.native.entries > MAX_ENTRIES || self.native.entries > IMAGE_ENTRIES { return Err(Error::Bounds); }
        let restart = self.pass.as_ref().ok_or(Error::State)?.first_batch;
        self.pass.as_mut().ok_or(Error::State)?.first_batch = false;
        let complete = self.call(ImageCall::Roster { row, restart }, 0, &[])?;
        if matches!(complete.returned()?, Returned::Boolean(0, F::ERROR_NO_MORE_FILES)) {
            let pass = self.pass.as_ref().ok_or(Error::State)?;
            for (index, child) in self.rows.iter().enumerate() {
                if self.namespace.parent(index).map_err(namespace_error)? == Some(row)
                    && !self.delete_pending(index) && child.original.as_ref().is_some_and(|key|
                    self.native.state(key) == Ok(SlotState::Owned)) && pass.seen_edges & (1u64 << index) == 0 {
                    return Err(Error::Unsafe);
                }
            }
            self.end_pass()?;
            return Ok(None);
        }
        self.budget(HELPER_RESERVE)?;
        let entries = decode::Observed::new(super::Refusal::none()).directory(complete.bytes(BUFFER)?)?;
        self.native.entries = self.native.entries.checked_add(entries.len()).ok_or(Error::Bounds)?;
        let pass = self.pass.as_mut().ok_or(Error::State)?;
        pass.entry_count = pass.entry_count.checked_add(entries.len()).ok_or(Error::Bounds)?;
        if pass.entry_count > PASS_ENTRIES || self.native.entries > MAX_ENTRIES
            || self.native.entries > IMAGE_ENTRIES { return Err(Error::Bounds); }
        let volume = pass.before.metadata.identity.volume_serial;
        for entry in &entries {
            if !entry.name.is_ascii() || pass.names.iter().any(|name| name.eq_ignore_ascii_case(&entry.name)) {
                return Err(Error::Unsafe);
            }
            pass.names.push(entry.name.clone());
            if entry.name == "." || entry.name == ".." {
                let expected = if entry.name == "." { row } else { self.namespace.parent(row).map_err(namespace_error)?.unwrap_or(row) };
                let facts = self.rows[expected].acquisition.as_ref().ok_or(Error::State)?;
                if entry.kind != FileKind::Directory || entry.file_id != facts.metadata.identity.file_id
                    || volume != facts.metadata.identity.volume_serial { return Err(Error::Unsafe); }
                continue;
            }
            for (index, child) in self.rows.iter().enumerate() {
                let Some(facts) = child.current.as_ref() else { continue };
                let parent = self.namespace.parent(index).map_err(namespace_error)?;
                let name = self.namespace.leaf(index).map_err(namespace_error)?;
                let same_id = facts.metadata.identity.volume_serial == volume && facts.metadata.identity.file_id == entry.file_id;
                let owned = child.original.as_ref().is_some_and(|key| self.native.state(key) == Ok(SlotState::Owned));
                // Reject a retained full ID under ANY undeclared alias, even if
                // its original has retired. A same-parent rename is accepted
                // only at its now-current exact endpoint.
                if same_id && (parent != Some(row) || name != entry.name) { return Err(Error::Unsafe); }
                if parent == Some(row) && name.eq_ignore_ascii_case(&entry.name) && (owned || same_id) {
                    if name != entry.name || !same_id || entry.kind != facts.metadata.kind
                        || entry.attributes != facts.metadata.attributes { return Err(Error::Unsafe); }
                    pass.seen_edges |= 1u64 << index;
                }
            }
            pass.entries.push(entry.clone()); // pre-reserved bounded full roster
        }
        self.budget(0)?;
        self.check_user()?;
        Ok(Some(entries))
    }
    fn end_pass(&mut self) -> Result<()> {
        let row = self.pass.as_ref().ok_or(Error::State)?.row;
        let after = self.snapshot(row)?;
        let pass = self.pass.as_ref().ok_or(Error::State)?;
        if after != pass.before || pass.epoch != self.namespace.epoch() { return Err(Error::Unsafe); }
        self.check_user()?;
        self.budget(HELPER_RESERVE)?;
        let pass = self.pass.as_ref().ok_or(Error::State)?;
        let receipt = PassReceipt { generation: pass.generation, kind: pass.kind,
            identity: pass.before.metadata.identity, bytes: pass.bytes,
            entries: u32::try_from(pass.entry_count).map_err(|_| Error::Bounds)? };
        if self.receipts.len() >= MAX_PASSES as usize || self.roster_evidence.len() >= MAX_PASSES as usize {
            return Err(Error::Bounds);
        }
        let pass = self.pass.take().ok_or(Error::State)?;
        self.receipts.push(receipt);
        if pass.kind == PassKind::Roster {
            self.latest_roster[row] = pass.generation;
            self.roster_evidence.push(RosterEvidence { row, generation: pass.generation,
                epoch: pass.epoch, after, entries: pass.entries });
        }
        self.budget(0)
    }

    // Only this owner's completed EOF+POST record is authority. Public receipts
    // and booleans are descriptive; callers cannot synthesize or refresh proof.
    fn roster_index(&self, key: &PassKey, parent: usize) -> Result<usize> {
        if parent >= self.rows.len() || !Arc::ptr_eq(&key.book, &self.native.identity) || key.row != parent
            || self.latest_roster[parent] != key.generation { return Err(Error::State); }
        let index = self.roster_evidence.iter().position(|proof|
            proof.row == parent && proof.generation == key.generation).ok_or(Error::State)?;
        if self.roster_evidence[index].epoch != self.namespace.epoch() { return Err(Error::State); }
        Ok(index)
    }
    fn prove_roster(&mut self, key: &PassKey, parent: usize) -> Result<usize> {
        let index = self.roster_index(key, parent)?;
        self.owned(parent)?;
        let actual = self.snapshot(parent)?;
        if self.roster_evidence[index].after != actual
            || actual.metadata.identity != self.rows[parent].acquisition.as_ref().ok_or(Error::State)?.metadata.identity {
            return Err(Error::Unsafe);
        }
        Ok(index)
    }

    /// Attempt exactly one declared same-original rename. An Ok result means
    /// only accepted native rename and same-original post-observation, NOT finality.
    /// Supply the opaque key of a completed destination-parent absence pass.
    pub fn rename_once(&mut self, key: &MoveKey, destination: &PassKey) -> Result<()> {
        let result = self.rename_inner(key, destination);
        self.record(result)
    }
    fn rename_inner(&mut self, key: &MoveKey, destination: &PassKey) -> Result<()> {
        self.mutation_idle()?;
        let step = self.move_step(key)?;
        let plan = self.namespace.move_plan(step).map_err(namespace_error)?.clone();
        for row in [plan.row, plan.from.parent, plan.to.parent] {
            self.owned(row)?;
            if self.rows[row].write_state == WriteState::Open { return Err(Error::State); }
        }
        if !self.rows[plan.row].role.movable()
            || !self.rows[plan.from.parent].role.mutation_parent()
            || !self.rows[plan.to.parent].role.mutation_parent() { return Err(Error::State); }
        self.check_user()?;
        self.check_current(plan.row)?;
        self.check_current(plan.from.parent)?;
        if plan.to.parent != plan.from.parent { self.check_current(plan.to.parent)?; }
        let before = self.snapshot(plan.row)?;
        for parent in [plan.from.parent, plan.to.parent] {
            if self.rows[parent].acquisition.as_ref().ok_or(Error::State)?.metadata.identity.volume_serial
                != before.metadata.identity.volume_serial { return Err(Error::Unsafe); }
        }
        let proof = self.prove_roster(destination, plan.to.parent)?;
        let allowed = if plan.from.parent == plan.to.parent { Some(&plan.from) } else { None };
        endpoint_absent(&self.roster_evidence[proof], &plan.to, before.metadata.identity, allowed)?;
        let prepared = self.namespace.prepare_move(step).map_err(namespace_error)?;
        self.pending_move = Some(PendingMove { step, before, prepared: Some(prepared) });
        // Prepared edge/name replacements, old/new descendant claims, BEFORE
        // snapshot and actual SDK/input capacities all count before native entry.
        if let Err(error) = self.budget(HELPER_RESERVE + size_of::<Frame>()) {
            self.pending_move = None;
            return Err(error);
        }
        let result = self.call(ImageCall::Rename { row: plan.row, step }, 0, &[]);
        if let Err(error) = result {
            if error != Error::Unknown && self.active.is_none() && !self.move_observations[step].accepted {
                self.pending_move = None; // entered historical claims remain forever
            }
            return Err(error);
        }
        // The accepted edge was ALREADY latched by finish, before this fallible
        // metadata/security/type/name observation or the caller's STOP boundary.
        let after = self.snapshot(plan.row)?;
        let pending = self.pending_move.as_ref().ok_or(Error::State)?;
        if !same_after_rename(&pending.before, &after) { return Err(Error::Unsafe); }
        self.move_observations[step].change_after = Some(after.metadata.change);
        self.rows[plan.row].current = Some(after);
        self.check_user()
    }

    /// Requires fresh complete CURRENT-epoch old-absence/new-presence passes.
    /// Same-parent moves may use the same completed pass key for both endpoints.
    pub fn finish_move(&mut self, key: &MoveKey, old_parent: &PassKey, new_parent: &PassKey) -> Result<MoveReceipt> {
        let result = self.finish_move_inner(key, old_parent, new_parent);
        self.record(result)
    }
    fn finish_move_inner(&mut self, key: &MoveKey, old_parent: &PassKey, new_parent: &PassKey) -> Result<MoveReceipt> {
        self.idle()?;
        let step = self.move_step(key)?;
        let pending = self.pending_move.as_ref().ok_or(Error::State)?;
        if pending.step != step || pending.prepared.is_some() || !self.move_observations[step].accepted
            || self.move_observations[step].finalized { return Err(Error::State); }
        let plan = self.namespace.move_plan(step).map_err(namespace_error)?.clone();
        self.check_user()?;
        let after = self.snapshot(plan.row)?;
        if !same_after_rename(&self.pending_move.as_ref().ok_or(Error::State)?.before, &after)
            || self.rows[plan.row].current.as_ref() != Some(&after) { return Err(Error::Unsafe); }
        let old = self.prove_roster(old_parent, plan.from.parent)?;
        let new = self.prove_roster(new_parent, plan.to.parent)?;
        endpoint_absent(&self.roster_evidence[old], &plan.from, after.metadata.identity,
            if plan.from.parent == plan.to.parent { Some(&plan.to) } else { None })?;
        endpoint_present(&self.roster_evidence[new], &plan.to, &after)?;
        // Each exact original is fenced once here, using flags=0. Neither a
        // successful rename nor a file-only fence substitutes for a parent fence.
        self.fence_retained(plan.row, FenceExpected::SourceAfter(&after))?;
        self.fence_retained(plan.from.parent, FenceExpected::Roster(old))?;
        if plan.to.parent != plan.from.parent {
            self.fence_retained(plan.to.parent, FenceExpected::Roster(new))?;
        }
        self.check_user()?;
        let fact = self.move_observations[step];
        let receipt = MoveReceipt { step: step as u16, identity: after.metadata.identity,
            epoch: self.namespace.epoch(), change_before: fact.change_before.ok_or(Error::State)?,
            change_after: fact.change_after.ok_or(Error::State)? };
        self.namespace.finish_move(step).map_err(namespace_error)?;
        self.move_observations[step].finalized = true;
        self.pending_move = None;
        Ok(receipt)
    }

    /// Ordinary FileDispositionInformation(TRUE), exactly once at a frozen
    /// CURRENT edge. Directory disposal additionally needs full empty EOF+POST.
    /// Accepted disposition is deliberately not a namespace-deleted receipt.
    pub fn dispose_once(&mut self, key: &DeleteKey, empty: Option<&PassKey>) -> Result<()> {
        let result = self.dispose_inner(key, empty);
        self.record(result)
    }
    fn dispose_inner(&mut self, key: &DeleteKey, empty: Option<&PassKey>) -> Result<()> {
        self.mutation_idle()?;
        let step = self.delete_step(key)?;
        let plan = self.namespace.delete_plan(step).map_err(namespace_error)?.clone();
        self.owned(plan.row)?;
        self.owned(plan.edge.parent)?;
        if self.rows[plan.row].write_state == WriteState::Open || !self.rows[plan.row].role.movable()
            || !self.rows[plan.edge.parent].role.mutation_parent() { return Err(Error::State); }
        self.check_user()?;
        self.check_current(plan.row)?;
        self.check_current(plan.edge.parent)?;
        if self.rows[plan.row].role.directory() {
            if self.namespace.has_live_dependency(plan.row, self.live_rows()) { return Err(Error::State); }
            let proof = self.prove_roster(empty.ok_or(Error::State)?, plan.row)?;
            if !self.roster_evidence[proof].entries.is_empty() { return Err(Error::Unsafe); }
        } else if empty.is_some() { return Err(Error::State); }
        // Consumes the one declaration before entry; a preparation error still
        // poisons the lease, never offers a disposition retry.
        let epoch = self.namespace.enter_delete(step).map_err(namespace_error)?;
        self.pending_deletion = Some(step);
        let result = self.call(ImageCall::Disposition { row: plan.row, step, epoch }, 0, &[]);
        if let Err(error) = result {
            if error != Error::Unknown && self.active.is_none() && !self.deletion_observations[step].disposition_accepted {
                self.pending_deletion = None;
            }
            return Err(error);
        }
        // No normal metadata call to a delete-pending source. Only its original
        // consuming close, followed by parent absence/fence, remains meaningful.
        self.check_user()
    }

    /// Consumes an ALREADY accepted disposition's original handle once. It does
    /// not revive forward mutation after a first error. The parent remains held
    /// even when this positive retirement cannot be followed by finality proof.
    pub fn close_disposed_once(&mut self, key: &DeleteKey) -> Result<()> {
        let result = self.close_disposed_inner(key);
        self.record(result)
    }
    fn close_disposed_inner(&mut self, key: &DeleteKey) -> Result<()> {
        if self.active.is_some() || self.native.active.is_some() { return self.unknown(); }
        if self.final_attempted || self.pass.is_some() { return Err(Error::State); }
        let step = self.delete_step(key)?;
        if self.pending_deletion != Some(step) || !self.deletion_observations[step].disposition_accepted
            || self.deletion_observations[step].close_attempted { return Err(Error::State); }
        let plan = self.namespace.delete_plan(step).map_err(namespace_error)?;
        let row = plan.row;
        let index = self.original(row)?.index;
        if self.native.slot(index)?.state != SlotState::Owned
            || self.namespace.has_live_dependency(row, self.live_rows())
            || !self.native_children_retired(index) { return Err(Error::State); }
        let epoch = self.namespace.next_epoch().map_err(namespace_error)?;
        self.budget(HELPER_RESERVE)?;
        self.deletion_observations[step].close_attempted = true;
        self.close_index_once(index)?;
        // The sole NativeBook consuming close has positively completed. Latch
        // retirement and epoch BEFORE any query, STOP or fallible postcondition.
        self.deletion_observations[step].handle_retired = true;
        self.namespace.latch_epoch(epoch);
        self.deletion_observations[step].retired_epoch = Some(self.namespace.epoch());
        Ok(())
    }

    pub fn finish_deletion(&mut self, key: &DeleteKey, parent: &PassKey) -> Result<DeletionReceipt> {
        let result = self.finish_deletion_inner(key, parent);
        self.record(result)
    }
    fn finish_deletion_inner(&mut self, key: &DeleteKey, parent: &PassKey) -> Result<DeletionReceipt> {
        self.idle()?;
        let step = self.delete_step(key)?;
        let fact = self.deletion_observations[step];
        if self.pending_deletion != Some(step) || !fact.disposition_accepted || !fact.handle_retired
            || !fact.close_attempted || fact.deleted { return Err(Error::State); }
        let plan = self.namespace.delete_plan(step).map_err(namespace_error)?.clone();
        let identity = self.rows[plan.row].acquisition.as_ref().ok_or(Error::State)?.metadata.identity;
        if self.native.state(self.original(plan.row)?)? != SlotState::Closed { return Err(Error::State); }
        self.check_user()?;
        let proof = self.prove_roster(parent, plan.edge.parent)?;
        // No alias exception for deletion: the name AND the entire full ID must
        // be absent in the retained CURRENT deletion parent, not acquisition parent.
        endpoint_absent(&self.roster_evidence[proof], &plan.edge, identity, None)?;
        self.fence_retained(plan.edge.parent, FenceExpected::Roster(proof))?;
        self.check_user()?;
        self.deletion_observations[step].deleted = true;
        self.pending_deletion = None;
        Ok(DeletionReceipt { step: step as u16, identity, epoch: self.namespace.epoch() })
    }

    fn check_fence_snapshot(&self, row: usize, expected: FenceExpected<'_>, observed: &Snapshot) -> Result<()> {
        let expected = match expected {
            FenceExpected::SourceAfter(after) => after,
            FenceExpected::Roster(index) => {
                let proof = self.roster_evidence.get(index).ok_or(Error::State)?;
                if proof.row != row || proof.epoch != self.namespace.epoch()
                    || self.latest_roster.get(row).copied() != Some(proof.generation) { return Err(Error::State); }
                &proof.after // the SAME immutable Snapshot already proved by prove_roster
            },
        };
        if expected != observed { Err(Error::Unsafe) } else { Ok(()) }
    }
    fn fence_retained(&mut self, row: usize, expected: FenceExpected<'_>) -> Result<()> {
        self.owned(row)?;
        if !self.rows[row].role.fence() || self.rows[row].write_state == WriteState::Open { return Err(Error::State); }
        self.check_current(row)?;
        let before = self.snapshot(row)?;
        self.check_fence_snapshot(row, expected, &before)?;
        self.call(ImageCall::Fence { row }, 0, &[])?;
        let after = self.snapshot(row)?;
        self.check_fence_snapshot(row, expected, &after)
    }

    /// Known independent HANDLE retirement, never deletion or namespace success.
    /// All acquisition and every declared move-parent dependency remains in force.
    pub fn close_once(&mut self, key: &ImageKey) -> Result<()> {
        let result = self.close_inner(key);
        self.record(result)
    }
    fn close_inner(&mut self, key: &ImageKey) -> Result<()> {
        if self.active.is_some() || self.native.active.is_some() { return self.unknown(); }
        if self.final_attempted || self.pass.is_some() { return Err(Error::State); }
        let row = self.row(key)?;
        let index = self.original(row)?.index;
        if self.protected_rows() & (1u64 << row) != 0
            || self.namespace.has_live_dependency(row, self.live_rows())
            || !self.native_children_retired(index) { return Err(Error::State); }
        self.budget(HELPER_RESERVE)?;
        self.close_index_once(index)
    }
    fn native_children_retired(&self, index: usize) -> bool {
        !self.native.slots.iter().any(|slot| slot.parent == Some(index)
            && !matches!(slot.state, SlotState::NoHandle | SlotState::Closed))
    }
    // Still exactly one original NativeBook close implementation. This extension
    // supplies stronger eligibility and one-use DATA, never an unchecked HANDLE.
    fn close_index_once(&mut self, index: usize) -> Result<()> {
        if index >= MAX_RECORDS || !known_close_candidate(self.native.slot(index)?.state, self.close_requested[index]) { return Err(Error::State); }
        self.close_requested[index] = true;
        self.native.close_index(index)
    }
    fn mapped_row(&self, index: usize) -> Option<usize> {
        self.rows.iter().position(|row| row.original.as_ref().is_some_and(|key| key.index == index))
    }
    fn retire_index(&mut self, index: usize, protected: u64) {
        if self.active.is_some() || self.native.active.is_some() || index >= MAX_RECORDS
            || self.close_requested[index] || !self.native_children_retired(index) { return; }
        let state = match self.native.slot(index) { Ok(slot) => slot.state, Err(error) => {
            if self.failed.is_none() { self.failed = Some(error); }
            return;
        }};
        if !known_close_candidate(state, self.close_requested[index]) { return; }
        if let Some(row) = self.mapped_row(index) {
            if protected & (1u64 << row) != 0 || self.namespace.has_live_dependency(row, self.live_rows()) { return; }
        }
        let result = self.close_index_once(index);
        let _ = self.record(result); // original first failure never changes
    }

    /// One final sweep under the caller's existing absolute finalization deadline.
    /// A repeat is observation only. Settled means HANDLE retirement, not deletion
    /// or move finality, transaction completion, rollback or OS-teardown success.
    pub fn retire_handles_once(&mut self) -> CloseOutcome {
        if self.final_attempted { return if self.settled() { CloseOutcome::Settled } else { CloseOutcome::Unknown }; }
        self.final_attempted = true;
        self.native.retiring = true;
        if self.pass.is_some() && self.failed.is_none() { self.failed = Some(Error::State); }
        if self.active.is_some() || self.native.active.is_some() {
            self.native.mark_interrupted();
            if self.failed.is_none() { self.failed = Some(Error::Unknown); }
            return CloseOutcome::Unknown; // absolutely no close through either frame
        }
        if let Err(error) = self.budget(HELPER_RESERVE) {
            if self.failed.is_none() { self.failed = Some(error); }
            self.native.mark_interrupted();
            return CloseOutcome::Unknown;
        }
        let protected = self.protected_rows();
        let primary = self.native.process_token;
        // Include EVERY non-row slot, including interrupted/failed user-check
        // token acquisitions. Child slots outside the image graph settle first.
        for index in (0..self.native.slots.len()).rev() {
            if self.mapped_row(index).is_none() && Some(index) != primary {
                self.retire_index(index, protected);
            }
        }
        // Frozen reverse UNION topology, not reverse acquisition order. The sole
        // native close guard also keeps every immutable Slot.parent dependency.
        for ordinal in 0..self.rows.len() {
            let row = self.namespace.retirement()[ordinal];
            if let Some(index) = self.rows[row].original.as_ref().map(|key| key.index) {
                self.retire_index(index, protected);
            }
        }
        // Non-row ancestors can become eligible after image children. This can
        // never re-enter a close: close_requested and native state are absorbing.
        for index in (0..self.native.slots.len()).rev() {
            if self.mapped_row(index).is_none() && Some(index) != primary {
                self.retire_index(index, protected);
            }
        }
        if let Some(index) = primary {
            let needs_context = self.pass.is_some() || self.pending_move.is_some() || self.pending_deletion.is_some()
                || self.active.is_some() || self.native.active.is_some()
                || self.native.slots.iter().enumerate().any(|(other, slot)| other != index
                    && !matches!(slot.state, SlotState::NoHandle | SlotState::Closed));
            if !needs_context { self.retire_index(index, protected); }
        }
        if self.native.slots.iter().any(|slot| !matches!(slot.state, SlotState::NoHandle | SlotState::Closed))
            || self.pass.is_some() || self.pending_move.is_some() || self.pending_deletion.is_some() {
            self.native.mark_interrupted();
            if self.failed.is_none() { self.failed = Some(Error::State); }
        }
        if self.settled() { CloseOutcome::Settled } else { CloseOutcome::Unknown }
    }

    fn frame(&self) -> Result<&Frame> {
        self.active.as_ref().map(|frame| frame.as_ref().get_ref()).ok_or(Error::Unknown)
    }
    fn complete(&mut self) -> Result<Completed> {
        self.frame()?.phase.set(Phase::Complete);
        let effect = self.frame()?.effect;
        self.effects[effect].complete = true;
        let frame = self.active.take().ok_or(Error::Unknown)?;
        Ok(Completed { frame: ManuallyDrop::into_inner(frame) })
    }

    fn call(&mut self, call: ImageCall, offset: u64, input: &[u8]) -> Result<Completed> {
        self.usable()?;
        if self.effects.len() >= EFFECTS || input.len() > BUFFER || offset > i64::MAX as u64 {
            return Err(Error::Bounds);
        }
        self.budget(HELPER_RESERVE + size_of::<Frame>())?;
        let row = call.row();
        let role = self.rows.get(row).ok_or(Error::State)?.role;
        let index = self.original(row)?.index;
        let effect = self.effects.len();
        let mut frame = Box::pin(Frame { call, effect, phase: Cell::new(Phase::Prepared),
            returned: Cell::new(None), handle: null_mut(), output_handle: null_mut(),
            input: Vec::new(), unicode: F::UNICODE_STRING::default(),
            attributes: OBJECT_ATTRIBUTES::default(), access: role.access(),
            directory: role.directory(), offset: offset as i64, information_length: 0,
            bytes: UnsafeCell::new(Aligned([0; BUFFER])), count: UnsafeCell::new(u32::MAX),
            iosb: UnsafeCell::new(IO::IO_STATUS_BLOCK {
                Anonymous: IO::IO_STATUS_BLOCK_0 { Status: F::STATUS_PENDING }, Information: usize::MAX,
            }), _pin: PhantomPinned });
        // SAFETY: only initialize fields of a fresh, pinned, unentered frame.
        // The input allocation and object attributes will not subsequently move.
        let setup = unsafe { frame.as_mut().get_unchecked_mut() };
        if let ImageCall::Open { slot, create, .. } = call {
            if slot != index || create != role.create() { return Err(Error::State); }
            let original = self.native.slot(slot)?;
            if original.state != SlotState::Reserved { return Err(Error::State); }
            setup.output_handle = original.output.get();
            setup.input = original.name.clone();
            setup.unicode.Length = u16::try_from((setup.input.len() - 1) * 2).map_err(|_| Error::Bounds)?;
            setup.unicode.MaximumLength = u16::try_from(setup.input.len() * 2).map_err(|_| Error::Bounds)?;
            setup.unicode.Buffer = setup.input.as_mut_ptr();
            setup.attributes.Length = size_of::<OBJECT_ATTRIBUTES>() as u32;
            setup.attributes.RootDirectory = original.parent.map(|parent| self.native.handle(parent)).transpose()?.unwrap_or(null_mut());
            setup.attributes.ObjectName = &setup.unicode;
            setup.attributes.Attributes = F::OBJ_DONT_REPARSE;
        } else {
            setup.handle = self.native.handle(index)?;
        }
        if let ImageCall::Write { count, .. } = call {
            if count != input.len() || count == 0 || count > BUFFER || !role.content_writer() { return Err(Error::State); }
            // SAFETY: fresh initialized storage, bounded copy, no native borrower.
            unsafe { (&mut (*setup.bytes.get()).0)[..count].copy_from_slice(input); }
        } else if !input.is_empty() { return Err(Error::State); }
        match call {
            ImageCall::Rename { row, step } => {
                let plan = self.namespace.move_plan(step).map_err(namespace_error)?;
                let pending = self.pending_move.as_ref().ok_or(Error::State)?;
                if plan.row != row || pending.step != step || pending.prepared.as_ref().is_none_or(|plan| plan.step() != step)
                    || !role.movable() || self.namespace.edge(row).map_err(namespace_error)? != Some(&plan.from) {
                    return Err(Error::State);
                }
                let destination = self.native.handle(self.original(plan.to.parent)?.index)?;
                setup.input = plan.to.name.encode_utf16().collect();
                let name_bytes = setup.input.len().checked_mul(size_of::<u16>()).ok_or(Error::Bounds)?;
                let name_at = offset_of!(N::FILE_RENAME_INFORMATION, FileName);
                let root_at = offset_of!(N::FILE_RENAME_INFORMATION, RootDirectory);
                let length_at = offset_of!(N::FILE_RENAME_INFORMATION, FileNameLength);
                let length = name_at.checked_add(name_bytes).ok_or(Error::Bounds)?.max(size_of::<N::FILE_RENAME_INFORMATION>());
                if name_bytes == 0 || length > BUFFER || name_bytes > u32::MAX as usize { return Err(Error::Bounds); }
                setup.information_length = u32::try_from(length).map_err(|_| Error::Bounds)?;
                // SAFETY: fresh initialized aligned frame bytes, not yet entered.
                // SDK offsets select the locked native layout. The entire union/
                // BOOLEAN and all padding remain zero: ReplaceIfExists=FALSE,
                // no Ex/POSIX/replace flags. RootDirectory is the SAME original.
                let bytes = unsafe { &mut (*setup.bytes.get()).0 };
                bytes[root_at..root_at + size_of::<F::HANDLE>()].copy_from_slice(&(destination as usize).to_ne_bytes());
                bytes[length_at..length_at + size_of::<u32>()].copy_from_slice(&(name_bytes as u32).to_ne_bytes());
                for (ordinal, unit) in setup.input.iter().enumerate() {
                    let at = name_at + ordinal * size_of::<u16>();
                    bytes[at..at + size_of::<u16>()].copy_from_slice(&unit.to_ne_bytes());
                }
            },
            ImageCall::Disposition { row, step, .. } => {
                let plan = self.namespace.delete_plan(step).map_err(namespace_error)?;
                if plan.row != row || self.pending_deletion != Some(step)
                    || self.namespace.edge(row).map_err(namespace_error)? != Some(&plan.edge) || !role.movable() {
                    return Err(Error::State);
                }
                let length = size_of::<N::FILE_DISPOSITION_INFORMATION>();
                let at = offset_of!(N::FILE_DISPOSITION_INFORMATION, DeleteFile);
                if length > BUFFER || at >= length { return Err(Error::Bounds); }
                setup.information_length = u32::try_from(length).map_err(|_| Error::Bounds)?;
                // SAFETY: fresh, pinned, unentered ordinary disposition buffer.
                unsafe { (&mut (*setup.bytes.get()).0)[at] = 1; } // BOOLEAN TRUE
            },
            _ => {},
        }
        self.effects.push(EffectObservation { kind: call.kind(),
            row: u16::try_from(row).map_err(|_| Error::Bounds)?, entered: false,
            returned: None, iosb_status: None, information: None, adopted: false, latched: false, complete: false });
        self.active = Some(ManuallyDrop::new(frame));
        // Actual capacities and original slot allocation are charged while still
        // Prepared. A pre-entry budget refusal releases only this unentered frame.
        if let Err(error) = self.budget(HELPER_RESERVE) {
            self.complete()?;
            return Err(error);
        }
        let admission = match call {
            ImageCall::Rename { step, .. } => {
                match self.pending_move.as_mut().filter(|pending| pending.step == step)
                    .and_then(|pending| pending.prepared.as_mut()) {
                    Some(prepared) => self.namespace.enter_move(prepared).map_err(namespace_error),
                    None => Err(Error::State),
                }
            },
            _ => Ok(()),
        };
        if let Err(error) = admission {
            self.complete()?; // only an UNENTERED frame; no native borrower
            return Err(error);
        }
        if let ImageCall::Open { slot, .. } = call {
            self.native.slot_mut(slot)?.state = SlotState::Acquiring;
        }
        match call {
            ImageCall::Rename { step, .. } => {
                self.move_observations[step].entered = true;
                self.move_observations[step].change_before = self.pending_move.as_ref().map(|pending| pending.before.metadata.change);
            },
            ImageCall::Disposition { step, .. } => self.deletion_observations[step].entered = true,
            _ => {},
        }
        self.native.started = true;
        self.frame()?.phase.set(Phase::Entered);
        self.effects[effect].entered = true;
        let frame = self.frame()?;
        // SAFETY: all original handles, input names/bytes, output cell, offset and
        // IOSB are retained and pinned before entry. Synchronous mode, no APC,
        // callback, event, borrowed Python buffer or arbitrary native selector.
        let returned = unsafe {
            match frame.call {
                ImageCall::Open { create, .. } => Returned::Nt(N::NtCreateFile(
                    frame.output_handle, frame.access, &frame.attributes, frame.iosb.get(),
                    null(), 0, FS::FILE_SHARE_READ, if create { N::FILE_CREATE } else { N::FILE_OPEN },
                    N::FILE_SYNCHRONOUS_IO_NONALERT | if frame.directory { N::FILE_DIRECTORY_FILE } else { N::FILE_NON_DIRECTORY_FILE },
                    null(), 0)),
                ImageCall::Write { count, .. } => Returned::Nt(N::NtWriteFile(
                    frame.handle, null_mut(), None, null(), frame.iosb.get(),
                    frame.buffer().cast(), count as u32, &frame.offset, null())),
                ImageCall::Read { count, .. } => Returned::Nt(N::NtReadFile(
                    frame.handle, null_mut(), None, null(), frame.iosb.get(),
                    frame.buffer().cast(), count as u32, &frame.offset, null())),
                ImageCall::Rename { .. } => Returned::Nt(N::NtSetInformationFile(
                    frame.handle, frame.iosb.get(), frame.buffer().cast(), frame.information_length, N::FileRenameInformation)),
                ImageCall::Disposition { .. } => Returned::Nt(N::NtSetInformationFile(
                    frame.handle, frame.iosb.get(), frame.buffer().cast(), frame.information_length, N::FileDispositionInformation)),
                ImageCall::Fence { .. } => Returned::Nt(N::NtFlushBuffersFileEx(
                    frame.handle, 0, null(), 0, frame.iosb.get())),
                ImageCall::Security { .. } => boolean(S::GetKernelObjectSecurity(
                    frame.handle, S::OWNER_SECURITY_INFORMATION | S::GROUP_SECURITY_INFORMATION | S::DACL_SECURITY_INFORMATION,
                    frame.buffer().cast(), SECURITY_BYTES as u32, frame.count.get())),
                ImageCall::Roster { restart, .. } => boolean(FS::GetFileInformationByHandleEx(
                    frame.handle, if restart { FS::FileIdExtdDirectoryRestartInfo } else { FS::FileIdExtdDirectoryInfo },
                    frame.buffer().cast(), BUFFER as u32)),
            }
        };
        frame.returned.set(Some(returned)); // first action after immediate scalar/error capture
        frame.phase.set(Phase::Returned);
        self.effects[effect].returned = Some(match returned {
            Returned::Nt(status) => NativeReturn::Nt(status),
            Returned::Boolean(value, error) => NativeReturn::Boolean { value, error },
            _ => return self.unknown(),
        });
        self.finish(call, returned)
    }

    fn finish(&mut self, call: ImageCall, returned: Returned) -> Result<Completed> {
        if self.frame()?.phase.get() != Phase::Returned { return self.unknown(); }
        let effect = self.frame()?.effect;
        // Pending, informational and warning returns retain the EXACT entered
        // frame/IOSB/input/output cell. Do not read any output to guess completion.
        match returned {
            Returned::Nt(status) if status != F::STATUS_SUCCESS && (status as u32 >> 30) != 3 => return self.unknown(),
            Returned::Boolean(0, F::ERROR_IO_PENDING) => return self.unknown(),
            _ => {},
        }
        if let ImageCall::Open { slot, create, epoch, .. } = call {
            let status = match returned { Returned::Nt(status) => status, _ => return self.unknown() };
            if self.native.slot(slot)?.state != SlotState::Acquiring { return self.unknown(); }
            // SAFETY: only definite NT completion reaches the original output.
            let handle = unsafe { *self.native.slot(slot)?.output.get() };
            if status != F::STATUS_SUCCESS {
                if !handle.is_null() { return self.unknown(); }
                self.native.slot_mut(slot)?.state = SlotState::NoHandle;
                self.complete()?;
                return Err(Error::Unavailable);
            }
            let frame = self.frame()?;
            // SAFETY: SUCCESS authorizes IOSB inspection, but contradictions
            // still retain the frame and never become an ordinary close receipt.
            let (io, information) = unsafe { ((*frame.iosb.get()).Anonymous.Status, (*frame.iosb.get()).Information) };
            self.effects[effect].iosb_status = Some(io);
            self.effects[effect].information = Some(information as u64);
            if !super::valid_handle(handle) || io != F::STATUS_SUCCESS
                || information != acquisition_information(create)
                || self.native.duplicate_live(slot, handle) { return self.unknown(); }
            // FILE_CREATE has its OWN FILE_CREATED adoption; never route it into
            // NativeBook's FILE_OPENED-only completion helper.
            let adopted = self.native.slot_mut(slot)?;
            adopted.state = SlotState::Owned;
            self.effects[effect].adopted = true;
            if let Some(epoch) = epoch {
                self.namespace.latch_epoch(epoch); // FILE_CREATED invalidates every old receipt
                self.effects[effect].latched = true;
            }
            return self.complete();
        }
        match (call, returned) {
            (ImageCall::Rename { step, .. }, Returned::Nt(F::STATUS_SUCCESS)) => {
                self.corroborate_io(effect, Some(0))?;
                // Only the exact serialized pre-entry plan can reach this point.
                // This is completion corroboration, not a fallible metadata/STOP
                // postcheck. All names/edges/claims were allocated before entry.
                let prepared = match self.pending_move.as_mut().filter(|pending| pending.step == step)
                    .and_then(|pending| pending.prepared.take()) {
                    Some(prepared) => prepared,
                    None => return self.unknown(),
                };
                self.namespace.latch_move(prepared); // no allocation/Result/check inside latch
                self.move_observations[step].accepted = true;
                self.move_observations[step].epoch = Some(self.namespace.epoch());
                self.effects[effect].latched = true;
                self.complete()
            },
            (ImageCall::Disposition { step, epoch, .. }, Returned::Nt(F::STATUS_SUCCESS)) => {
                self.corroborate_io(effect, Some(0))?;
                self.namespace.latch_epoch(epoch);
                self.deletion_observations[step].disposition_accepted = true;
                self.deletion_observations[step].disposition_epoch = Some(self.namespace.epoch());
                self.effects[effect].latched = true;
                self.complete()
            },
            (ImageCall::Rename { .. } | ImageCall::Disposition { .. }, Returned::Nt(_)) => {
                self.complete()?;
                Err(Error::Unavailable)
            },
            (ImageCall::Read { .. }, Returned::Nt(F::STATUS_END_OF_FILE)) => self.complete(),
            (ImageCall::Read { count, .. } | ImageCall::Write { count, .. }, Returned::Nt(F::STATUS_SUCCESS)) => {
                self.corroborate_io(effect, Some(count))?;
                self.complete()
            },
            (ImageCall::Fence { .. }, Returned::Nt(F::STATUS_SUCCESS)) => {
                self.corroborate_io(effect, Some(0))?;
                self.complete()
            },
            (ImageCall::Read { .. } | ImageCall::Write { .. } | ImageCall::Fence { .. }, Returned::Nt(_)) => {
                self.complete()?;
                Err(Error::Unavailable)
            },
            (ImageCall::Security { .. }, Returned::Boolean(value, _)) if value != 0 => {
                // SAFETY: definite synchronous query returned TRUE. Insufficient
                // buffer never reaches here and never triggers a size/retry query.
                let count = unsafe { *self.frame()?.count.get() } as usize;
                self.effects[effect].information = Some(count as u64);
                if count == 0 || count > SECURITY_BYTES { return self.unknown(); }
                self.complete()
            },
            (ImageCall::Roster { .. }, Returned::Boolean(value, _)) if value != 0 => self.complete(),
            (ImageCall::Roster { .. }, Returned::Boolean(0, F::ERROR_NO_MORE_FILES)) => self.complete(),
            (ImageCall::Security { .. } | ImageCall::Roster { .. }, Returned::Boolean(0, _)) => {
                self.complete()?;
                Err(Error::Unavailable)
            },
            _ => self.unknown(),
        }
    }
    fn corroborate_io(&mut self, effect: usize, maximum: Option<usize>) -> Result<()> {
        let frame = self.frame()?;
        // SAFETY: called only for definite synchronous STATUS_SUCCESS.
        let (io, information) = unsafe { ((*frame.iosb.get()).Anonymous.Status, (*frame.iosb.get()).Information) };
        self.effects[effect].iosb_status = Some(io);
        self.effects[effect].information = Some(information as u64);
        if io != F::STATUS_SUCCESS || maximum.is_some_and(|count| information > count) { return self.unknown(); }
        Ok(())
    }
}
impl Drop for ImagePrimitives {
    fn drop(&mut self) {
        // No native release, cancellation, retry, delete or success synthesis.
        // Normally completed frames were already consumed. Retain any unresolved
        // image frame; NativeBook retains its acquired/uncertain slots likewise.
        // This memory-safety fallback is NOT proof the owner remained reachable.
        if let Some(frame) = self.active.as_mut() {
            if frame.phase.get() == Phase::Complete {
                // SAFETY: no outstanding native writer or earlier manual drop.
                unsafe { ManuallyDrop::drop(frame); }
            }
        }
    }
}

fn new_row(role: ImageRole, parent: Option<usize>, name: String) -> Row {
    Row { role, parent, name,
        attempted: false, original: None, acquisition: None, current: None,
        written: 0, write_state: if role.content_writer() { WriteState::Open } else { WriteState::NotWriter } }
}
fn known_close_candidate(state: SlotState, requested: bool) -> bool {
    !requested && matches!(state, SlotState::Reserved | SlotState::Owned)
}
fn namespace_error(error: namespace::Fault) -> Error {
    match error { namespace::Fault::Bounds => Error::Bounds, namespace::Fault::State => Error::State,
        namespace::Fault::Unsafe => Error::Unsafe }
}
fn backup_edge(rows: &[Row], edge: &namespace::Edge) -> bool {
    rows.get(edge.parent).is_some_and(|row| row.role == ImageRole::PrivateDirectory)
        && edge.name.strip_prefix("old-").is_some_and(|suffix|
            !suffix.is_empty() && suffix.len() <= 2 && (suffix == "0" || !suffix.starts_with('0'))
                && suffix.bytes().all(|byte| byte.is_ascii_digit())
                && suffix.parse::<u16>().is_ok_and(|index| index < namespace::MAX_MOVES as u16))
}
fn entry_heap(entries: &Vec<DirectoryEntry>) -> Option<usize> {
    let mut bytes = entries.capacity().checked_mul(size_of::<DirectoryEntry>())?;
    for entry in entries { bytes = bytes.checked_add(entry.name.capacity())?; }
    Some(bytes)
}
fn same_after_rename(before: &Snapshot, after: &Snapshot) -> bool {
    same_identity_security(before, after) && before.metadata.size == after.metadata.size
        && before.metadata.allocation_size == after.metadata.allocation_size
        && before.metadata.write == after.metadata.write
    // Only change-time may differ, and both values are kept in the move ledger.
}
fn endpoint_absent(proof: &RosterEvidence, edge: &namespace::Edge,
    identity: FileIdentity, allowed: Option<&namespace::Edge>) -> Result<()> {
    if proof.row != edge.parent || proof.after.metadata.identity.volume_serial != identity.volume_serial {
        return Err(Error::State);
    }
    for entry in &proof.entries {
        if entry.name.eq_ignore_ascii_case(&edge.name) { return Err(Error::Unsafe); }
        if entry.file_id == identity.file_id
            && !allowed.is_some_and(|other| other.parent == proof.row && other.name == entry.name) {
            return Err(Error::Unsafe);
        }
    }
    Ok(())
}
fn endpoint_present(proof: &RosterEvidence, edge: &namespace::Edge, original: &Snapshot) -> Result<()> {
    if proof.row != edge.parent || proof.after.metadata.identity.volume_serial != original.metadata.identity.volume_serial {
        return Err(Error::State);
    }
    let mut found = false;
    for entry in &proof.entries {
        let same_id = entry.file_id == original.metadata.identity.file_id;
        if entry.name.eq_ignore_ascii_case(&edge.name) || same_id {
            if found || entry.name != edge.name || !same_id || entry.kind != original.metadata.kind
                || entry.attributes != original.metadata.attributes { return Err(Error::Unsafe); }
            found = true;
        }
    }
    if found { Ok(()) } else { Err(Error::Unsafe) }
}

fn same_identity_security(before: &Snapshot, after: &Snapshot) -> bool {
    before.metadata.identity == after.metadata.identity
        && before.metadata.kind == after.metadata.kind
        && before.metadata.attributes == after.metadata.attributes
        && before.metadata.creation == after.metadata.creation
        && before.metadata.links == after.metadata.links
        && before.security == after.security
}

// Lossless bounded QUERY admission only. No reserialization, SID trust rewrite,
// mask expansion, ACE reordering, descriptor synthesis or security equivalence
// claim. Future create/replace security must preserve/derive these complete facts
// and actually exercise SetKernelObjectSecurity on ONLY a new staging original.
fn descriptor(raw: &[u8]) -> Result<Descriptor> {
    // Self-relative SECURITY_DESCRIPTOR header: revision, reserved, control,
    // owner/group/SACL/DACL offsets. Keep all admitted layout and padding bytes.
    if raw.len() < 20 || raw.len() > SECURITY_BYTES || raw[0] != 1 || raw[1] != 0 {
        return Err(Error::Unsafe);
    }
    let control = decode::u16_at(raw, 2)?;
    // OWNER_DEFAULTED, GROUP_DEFAULTED, DACL_PRESENT/DEFAULTED,
    // DACL_AUTO_INHERIT_REQ/AUTO_INHERITED/PROTECTED, SELF_RELATIVE only.
    const ALLOWED_CONTROL: u16 = 0x0001 | 0x0002 | 0x0004 | 0x0008 | 0x0100 | 0x0400 | 0x1000 | 0x8000;
    if control & !ALLOWED_CONTROL != 0 || control & 0x8004 != 0x8004 || decode::u32_at(raw, 12)? != 0 {
        return Err(Error::Unsafe);
    }
    let owner = decode::u32_at(raw, 4)? as usize;
    let group = decode::u32_at(raw, 8)? as usize;
    let dacl = decode::u32_at(raw, 16)? as usize;
    for offset in [owner, group, dacl] {
        if offset < 20 || offset % 4 != 0 || offset >= raw.len() { return Err(Error::Unsafe); }
    }
    let owner_end = sid_end(raw, owner)?;
    let group_end = sid_end(raw, group)?;
    if overlaps((owner, owner_end), (group, group_end)) && (owner, owner_end) != (group, group_end) {
        return Err(Error::Unsafe);
    }
    let header = decode::span(raw, dacl, 8)?;
    if header[0] != 2 || header[1] != 0 || decode::u16_at(header, 6)? != 0 { return Err(Error::Unsafe); }
    let acl_size = decode::u16_at(header, 2)? as usize;
    let ace_count = decode::u16_at(header, 4)? as usize;
    let acl_end = dacl.checked_add(acl_size).ok_or(Error::Bounds)?;
    if acl_size < 8 || acl_size % 4 != 0 || acl_end > raw.len() || ace_count > MAX_ACES
        || overlaps((dacl, acl_end), (owner, owner_end)) || overlaps((dacl, acl_end), (group, group_end)) {
        return Err(Error::Unsafe);
    }
    let mut at = dacl + 8;
    for _ in 0..ace_count {
        let head = decode::span(raw, at, 8)?;
        let flags = head[1];
        if !matches!(head[0], 0 | 1) || flags & !0x1f != 0
            || flags & 0x0c != 0 && flags & 0x03 == 0 { return Err(Error::Unsafe); }
        let size = decode::u16_at(head, 2)? as usize;
        let end = at.checked_add(size).ok_or(Error::Bounds)?;
        if size < 16 || size % 4 != 0 || end > acl_end || sid_end(raw, at + 8)? != end {
            return Err(Error::Unsafe);
        }
        let mask = decode::u32_at(head, 4)?;
        if mask & !(FS::FILE_ALL_ACCESS | F::GENERIC_READ | F::GENERIC_WRITE | F::GENERIC_EXECUTE | F::GENERIC_ALL) != 0 {
            return Err(Error::Unsafe);
        }
        at = end;
    }
    // Preserve ACL free space and all descriptor layout bytes, not merely the
    // effective access mask. The bounded original byte string is the comparison.
    if at > acl_end { return Err(Error::Unsafe); }
    let mut retained = Vec::new();
    retained.try_reserve_exact(raw.len()).map_err(|_| Error::Bounds)?;
    retained.extend_from_slice(raw);
    Ok(Descriptor { raw: retained })
}
fn sid_end(raw: &[u8], at: usize) -> Result<usize> {
    let head = decode::span(raw, at, 8)?;
    if head[0] != 1 || head[1] > 15 { return Err(Error::Unsafe); }
    let count = 8 + 4 * head[1] as usize;
    decode::span(raw, at, count)?;
    at.checked_add(count).ok_or(Error::Bounds)
}
fn overlaps(a: (usize, usize), b: (usize, usize)) -> bool { a.0 < b.1 && b.0 < a.1 }

fn acquisition_information(create: bool) -> usize {
    if create { WP::FILE_CREATED as usize } else { WP::FILE_OPENED as usize }
}

#[cfg(test)]
#[path = "image_writer_tests.rs"]
mod tests;
