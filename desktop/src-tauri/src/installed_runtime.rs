//! Original-descriptor inspection of the one protected Linux installation.
//!
//! This is NOT executable runtime qualification. In particular, a compiled
//! manifest, equal hashes, and retained descriptors cannot prove the external
//! fresh-inode installer / immutable published-version / interpreter-loader
//! contracts. The fixed passive selector still requires those independently
//! established contracts; other production execution profiles remain closed.
//!
//! The Android retained path keeps the SAME originals until its saved-command
//! owner's actual inspection/acquisition/child/IO/native-settlement joins. Legacy
//! inspection-only transfer remains DATA, never executable runtime authority.
#![cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
#![forbid(unsafe_code)]

use std::{
    collections::BTreeSet,
    mem::{ManuallyDrop, MaybeUninit},
    os::fd::{AsFd, BorrowedFd, OwnedFd},
    time::Instant,
    sync::{Arc, atomic::{AtomicUsize, Ordering}},
};
use mrk_linux_mount_observation as mount;
use rustix::{fs::{self, FileType, Mode, OFlags, RawDir, ResolveFlags, Stat}, io::Errno};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::watch;
use crate::{protocol::{strict_json, PROTOCOL},
    runtime::{safe_payload_path, COMPILED_TARGET, CORE_VERSION, GITHUB_CA_LIMIT, REQUIRED_RUNTIME_RESOURCES}};

const TARGET: &str = "x86_64-unknown-linux-gnu";
const MANIFEST_ANCHOR: Option<&str> = option_env!("MRK_BUNDLED_RUNTIME_MANIFEST_SHA256");
const PROTOCOL_ANCHOR: Option<&str> = option_env!("MRK_BUNDLED_PROTOCOL_SHA256");
pub(crate) const MANIFEST_LIMIT: usize = 1024 * 1024;
const MOUNTINFO_LIMIT: usize = 1024 * 1024;
const STATUS_LIMIT: usize = 64 * 1024;
const MAP_LIMIT: usize = 4096;
const OS_RELEASE_LIMIT: usize = 64 * 1024;
const FILE_LIMIT: u64 = 512 * 1024 * 1024;
const TOTAL_LIMIT: u64 = 1024 * 1024 * 1024;
const FILE_COUNT: usize = 2048;
pub(crate) const ENTRY_COUNT: usize = 8192;
pub(crate) const TREE_DEPTH: usize = 16;
const RECORD_COUNT: usize = ENTRY_COUNT + 64;
const LIVE_COUNT: usize = 48;
const BLOCK_SIZE: usize = 64 * 1024;
const PREFIX_COUNT: usize = 7;
const RETAINED_COUNT: usize = PREFIX_COUNT + 2;
// Initial namespace inodes from Linux v6.8 proc_ns.h and the exact reviewed
// Ubuntu Azure 6.17.0-1022.22 nsfs.h. Not portable namespace detection.
pub(crate) const INITIAL_USER_INODE: u64 = 0xefff_fffd;
pub(crate) const INITIAL_PID_INODE: u64 = 0xefff_fffc;

type AdmissionResult<T> = Result<T, AdmissionFailure>;

/// Bounded, path-free reasons. None is authority to fall back or elevate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AdmissionFailure {
    UnsupportedPlatform, MissingCompileAnchor, Stopped, Deadline,
    NativeUnavailable, NativeDenied, Namespace, Mount, Ownership,
    ExtendedAttributes, IdentityChanged, Manifest, Inventory, Bounds,
    AlreadyUsed, Interrupted, CloseUncertain, LedgerInvariant,
    TransferUnavailable, DestinationOccupied,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase { New, Inspecting, InspectedOnly, PassivePreparing, PassivePrepared, Retained, Auditing, Refused, Settling, Settled, Unknown }

#[must_use]
#[derive(Debug)]
pub(crate) enum InspectionOutcome {
    InspectedOnly,
    Refused(AdmissionFailure),
    Unknown,
}

#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CloseOutcome { Settled, Unknown }

/// Reporting only. No selected paths, handles, numeric descriptors or authority.
#[derive(Debug)]
pub(crate) struct CustodyObservation {
    phase: Phase,
    records: usize,
    live_originals: usize,
    pending_acquisitions: usize,
    positive_closes: usize,
    uncertain_closes: usize,
    failure: Option<AdmissionFailure>,
}

impl CustodyObservation {
    pub(crate) fn phase(&self) -> &'static str {
        match self.phase {
            Phase::New => "new", Phase::Inspecting => "inspecting",
            Phase::PassivePreparing => "passivePreparing", Phase::PassivePrepared => "passivePrepared",
            Phase::InspectedOnly => "inspectedOnly", Phase::Retained => "retained", Phase::Auditing => "auditing", Phase::Refused => "refused",
            Phase::Settling => "settling", Phase::Settled => "settled", Phase::Unknown => "unknown",
        }
    }
    pub(crate) fn records(&self) -> usize { self.records }
    pub(crate) fn live_originals(&self) -> usize { self.live_originals }
    pub(crate) fn pending_acquisitions(&self) -> usize { self.pending_acquisitions }
    pub(crate) fn positive_closes(&self) -> usize { self.positive_closes }
    pub(crate) fn uncertain_closes(&self) -> usize { self.uncertain_closes }
    pub(crate) fn failure(&self) -> Option<AdmissionFailure> { self.failure }
}

/// Evidence of this one actual move only; not registration or qualification.
#[must_use]
pub(crate) struct TransferReceipt { original_records: usize, retained_originals: usize }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SlotId(usize);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Purpose {
    ProtectedAncestor(u8), ProcRoot, ProcDirectory, ProcControl,
    InitialUserNamespace, InitialPidNamespace, MountNamespace, OsDirectory, OsIdentity, Alias,
    Manifest, InventoryDirectory, Payload,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Acquisition { Attempted, Original, NoHandle }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CloseReceipt { Unattempted, Attempted, Positive, Unknown }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Operation {
    Idle, Kernel, Credentials, Inventory,
    Acquire(SlotId), Metadata(SlotId), Mount(SlotId), Attributes(SlotId),
    Read(SlotId), Hash(SlotId), Directory(SlotId), Close(SlotId),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Identity {
    pub(crate) device: u64, pub(crate) inode: u64, pub(crate) mode: u32, pub(crate) uid: u32, pub(crate) gid: u32, links: u64,
    size: i64, mtime: i64, mtime_nsec: u64, ctime: i64, ctime_nsec: u64,
}

impl Identity {
    pub(crate) fn of(stat: &Stat) -> Self {
        Self { device: stat.st_dev, inode: stat.st_ino, mode: stat.st_mode,
            uid: stat.st_uid, gid: stat.st_gid, links: stat.st_nlink, size: stat.st_size,
            mtime: stat.st_mtime, mtime_nsec: stat.st_mtime_nsec,
            ctime: stat.st_ctime, ctime_nsec: stat.st_ctime_nsec }
    }
    fn device_pair(self) -> AdmissionResult<(u32, u32)> {
        Ok((u32::try_from(nix::sys::stat::major(self.device)).map_err(|_| AdmissionFailure::Mount)?,
            u32::try_from(nix::sys::stat::minor(self.device)).map_err(|_| AdmissionFailure::Mount)?))
    }
}

// Unused preallocated capacity has no record and no acquisition. Records are
// appended once, before open, and NEVER reused (including known no-handle errors).
struct FdRecord {
    sequence: SlotId,
    purpose: Purpose,
    acquisition: Acquisition,
    original: Option<ManuallyDrop<OwnedFd>>,
    identity: Option<Identity>,
    close: CloseReceipt,
    parent: Option<(SlotId, String)>,
    digest: Option<String>,
    charged: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Credentials { uid: u32, gid: u32, pid: u32, tid: u32 }

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Manifest {
    schema_version: u32, protocol: u32, core_version: String, target: String,
    core_sha256: String, protocol_sha256: String, inventory_sha256: String,
    files: Vec<PayloadFile>,
}

// The publisher hashes compact, sorted-key JSON in this exact field order.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PayloadFile { pub(crate) path: String, pub(crate) sha256: String, pub(crate) size: u64 }

pub(crate) struct Inventory { pub(crate) files: Vec<PayloadFile>, pub(crate) directories: BTreeSet<String> }

struct TreeEntry { component: String, inode: u64, kind: FileType }

struct DirectoryFrame {
    original: SlotId,
    relative: String,
    depth: usize,
    entries: Vec<TreeEntry>,
    next: usize,
    enumerated: bool,
    dot_seen: bool,
    dotdot_seen: bool,
}

struct Work {
    block: Vec<u8>,
    directory_buffer: Vec<MaybeUninit<u8>>,
    data: Vec<u8>,
    attribute_buffer: [u8; 1],
    hash: Sha256,
    reader: Option<SlotId>,
    read_bytes: u64,
    read_eof: bool,
    last_digest: Option<[u8; 32]>,
    directory: Option<SlotId>,
}

struct RuntimeWork {
    walk: Vec<DirectoryFrame>,
    inventory: Option<Inventory>,
    actual_names: BTreeSet<String>,
    actual_folded: BTreeSet<String>,
    tree_entries: usize,
    files_verified: usize,
    directories_verified: usize,
    saw_manifest: bool,
}

/// Keep this same object registered through actual worker/child/IO joins and
/// explicit original settlement. It is deliberately not Clone or Serialize.
///
/// There is NO implicit-close Drop implementation: ManuallyDrop prevents an
/// unobserved or repeated close on unwind. Accidentally dropping an unsettled
/// book leaks originals and is an integration bug, NEVER a completion path.
#[must_use]
pub(crate) struct OriginalDescriptorBook {
    phase: Phase,
    operation: Operation,
    interrupted_at: Option<Operation>,
    failure: Option<AdmissionFailure>,
    settlement_started: bool,
    interrupted: bool,
    unknown: bool,
    records: Vec<FdRecord>,
    budget: Option<Arc<AndroidDescriptorBudget>>,
    control_slots: usize,
    control_rounds: usize,
    entry_observations: usize,
    root: Option<SlotId>,
    mount_namespace: Option<SlotId>,
    hash_left: [u64; 2],
    audit_started: bool,
    checkpoints: usize,
    original_stop: Option<watch::Receiver<bool>>,
    namespaces: [Option<SlotId>; 2],
    root_mount: Option<mount::MountObservation>,
    proc_mount: Option<mount::MountObservation>,
    credentials: Option<Credentials>,
    work: Work,
}

/// Runtime-specific inventory/selection; the reusable book owns only original
/// descriptors and protected native checks, never a caller-selected policy.
#[must_use]
pub(crate) struct InstalledRuntimeCustody {
    book: OriginalDescriptorBook,
    ancestors: [Option<SlotId>; PREFIX_COUNT],
    transferred: bool,
    retain_android: bool,
    work: RuntimeWork,
}

impl OriginalDescriptorBook {
    /// Pure allocation/initialization only; acquires no OS resource.
    pub(crate) fn new() -> Self {
        Self {
            phase: Phase::New, operation: Operation::Idle, interrupted_at: None,
            failure: None, settlement_started: false, interrupted: false,
            unknown: false,
            records: Vec::with_capacity(RECORD_COUNT), budget: None, control_slots: 0, control_rounds: 0, entry_observations: 0,
            root: None, mount_namespace: None, hash_left: [TOTAL_LIMIT + MANIFEST_LIMIT as u64; 2],
            audit_started: false, checkpoints: 0, original_stop: None,
            namespaces: [None; 2], root_mount: None, proc_mount: None, credentials: None,
            work: Work {
                block: vec![0; BLOCK_SIZE], directory_buffer: vec![MaybeUninit::uninit(); BLOCK_SIZE],
                data: Vec::with_capacity(MANIFEST_LIMIT.max(MOUNTINFO_LIMIT)), attribute_buffer: [0],
                hash: Sha256::new(), reader: None, read_bytes: 0, read_eof: false, last_digest: None,
                directory: None,
            },
        }
    }

    pub(crate) fn observation(&self) -> CustodyObservation {
        CustodyObservation {
            phase: self.phase, records: self.records.len(),
            live_originals: self.records.iter().filter(|r| r.original.is_some()).count(),
            pending_acquisitions: self.records.iter().filter(|r| r.acquisition == Acquisition::Attempted).count(),
            positive_closes: self.records.iter().filter(|r| r.close == CloseReceipt::Positive).count(),
            uncertain_closes: self.records.iter().filter(|r| matches!(r.close, CloseReceipt::Attempted | CloseReceipt::Unknown)).count(),
            failure: self.failure,
        }
    }

    /// Call only on an actual failed/lost ORIGINAL worker return, not elapsed
    /// time alone while that worker still borrows this book. Lost RawDir/hash
    /// progress is never resumed. Independent original settlement is still due.
    pub(crate) fn mark_interrupted(&mut self) {
        if self.interrupted_at.is_none() { self.interrupted_at = Some(self.operation); }
        self.interrupted = true;
        self.unknown = true;
        self.settlement_started = true;
        self.failure.get_or_insert(AdmissionFailure::Interrupted);
        self.phase = Phase::Unknown;
    }

    /// Retire each still-known original before its ONE consuming close. A
    /// later pass may close only an original that has never been attempted.
    /// EINTR/EBADF and a missing close return are unknown, not retry permission.
    pub(crate) fn settle_originals(&mut self) -> CloseOutcome {
        self.settlement_started = true; // Absorbing: even empty/positive settlement disables transfer.
        if matches!(self.phase, Phase::Inspecting | Phase::PassivePreparing) { self.mark_interrupted(); }
        if !self.unknown { self.phase = Phase::Settling; }
        for index in (0..self.records.len()).rev() {
            let _ = self.close_one(SlotId(index)); // Continue every independent known original.
        }
        let incomplete = self.records.iter().any(|r| {
            r.original.is_some() || r.acquisition == Acquisition::Attempted
                || matches!(r.close, CloseReceipt::Attempted | CloseReceipt::Unknown)
                || (r.acquisition == Acquisition::Original && r.close != CloseReceipt::Positive)
        });
        if self.unknown || self.interrupted || incomplete {
            self.unknown = true;
            self.phase = Phase::Unknown;
            CloseOutcome::Unknown
        } else {
            self.operation = Operation::Idle;
            self.phase = Phase::Settled;
            CloseOutcome::Settled
        }
    }

    fn refuse_and_settle(&mut self, failure: AdmissionFailure) -> InspectionOutcome {
        self.failure.get_or_insert(failure);
        // This path has a real normal inspection return. It is not a lost
        // native return; per-record Attempted states still independently matter.
        if !self.unknown {
            self.phase = Phase::Refused;
            self.operation = Operation::Idle;
        }
        match self.settle_originals() {
            CloseOutcome::Settled => InspectionOutcome::Refused(failure),
            CloseOutcome::Unknown => InspectionOutcome::Unknown,
        }
    }

    fn begin(&mut self, operation: Operation, end: Instant, stop: &watch::Receiver<bool>) -> AdmissionResult<()> {
        if !matches!(self.phase, Phase::Inspecting | Phase::PassivePreparing | Phase::Retained | Phase::Auditing)
            || self.unknown || self.interrupted || self.settlement_started {
            return Err(AdmissionFailure::LedgerInvariant);
        }
        if self.phase == Phase::Auditing {
            // Narrow original cleanup borrow ignores cooperative STOP, not W/F.
            let end = self.budget.as_ref().ok_or(AdmissionFailure::LedgerInvariant)?.audit_end(end)?;
            if Instant::now() >= end { return Err(AdmissionFailure::Deadline); }
        } else { checkpoint(end, stop)?; }
        if self.budget.is_some() {
            self.checkpoints = self.checkpoints.checked_add(1).ok_or(AdmissionFailure::Bounds)?;
            if self.checkpoints > 2_000_000 { return Err(AdmissionFailure::Bounds); }
        }
        self.operation = operation;
        Ok(())
    }

    fn arm(&mut self, purpose: Purpose) -> AdmissionResult<SlotId> {
        if self.records.len() >= RECORD_COUNT
            || self.budget.is_none() && self.records.iter().filter(|r| r.original.is_some()).count() >= LIVE_COUNT {
            return Err(AdmissionFailure::Bounds);
        }
        let control = matches!(purpose, Purpose::ProcRoot | Purpose::ProcDirectory | Purpose::ProcControl
            | Purpose::InitialUserNamespace | Purpose::InitialPidNamespace | Purpose::MountNamespace);
        let charged = if let Some(budget) = &self.budget {
            if control {
                if self.control_slots >= ANDROID_CONTROL_SLOTS { return Err(AdmissionFailure::Bounds); }
                self.control_slots += 1; false // Reserved before either book can open.
            } else { budget.claim()?; true }
        } else { false };
        let sequence = SlotId(self.records.len());
        // Capacity for ALL records was allocated before the first acquisition.
        self.records.push(FdRecord { sequence, purpose, acquisition: Acquisition::Attempted,
            original: None, identity: None, close: CloseReceipt::Unattempted, parent: None, digest: None, charged });
        self.operation = Operation::Acquire(sequence);
        Ok(sequence)
    }

    fn receive_open(&mut self, slot: SlotId, result: Result<OwnedFd, Errno>) -> AdmissionResult<SlotId> {
        // No fallible operation, allocation or callback between a returned
        // original and its installation in the already-armed permanent slot.
        match result {
            Ok(original) => {
                self.records[slot.0].original = Some(ManuallyDrop::new(original));
                self.records[slot.0].acquisition = Acquisition::Original;
                self.operation = Operation::Idle;
                Ok(slot)
            }
            Err(error) => {
                self.records[slot.0].acquisition = Acquisition::NoHandle;
                if self.records[slot.0].charged {
                    if let Some(budget) = &self.budget { budget.release(); }
                    self.records[slot.0].charged = false;
                }
                self.operation = Operation::Idle;
                Err(native_error(error))
            }
        }
    }

    fn close_one(&mut self, slot: SlotId) -> CloseOutcome {
        let Some(record) = self.records.get_mut(slot.0) else {
            self.unknown = true;
            return CloseOutcome::Unknown;
        };
        if record.acquisition == Acquisition::NoHandle {
            if record.original.is_none() && record.close == CloseReceipt::Unattempted {
                return CloseOutcome::Settled;
            }
            self.unknown = true;
            return CloseOutcome::Unknown;
        }
        if record.acquisition == Acquisition::Attempted {
            self.unknown = true; // No returned original AND no actual no-handle receipt.
            return CloseOutcome::Unknown;
        }
        match record.close {
            CloseReceipt::Positive if record.original.is_none() => return CloseOutcome::Settled,
            CloseReceipt::Unattempted => {}
            _ => { self.unknown = true; return CloseOutcome::Unknown; }
        }
        record.close = CloseReceipt::Attempted;
        self.operation = Operation::Close(slot);
        let Some(original) = record.original.take() else {
            record.close = CloseReceipt::Unknown;
            self.unknown = true;
            return CloseOutcome::Unknown;
        };
        // The slot is retired first. nix consumes OwnedFd via IntoRawFd and
        // reports close(2); its error cannot cause OwnedFd::drop or a retry.
        let result = nix::unistd::close(ManuallyDrop::into_inner(original));
        match result {
            Ok(()) => {
                record.close = CloseReceipt::Positive;
                if record.charged {
                    if let Some(budget) = &self.budget { budget.release(); }
                    record.charged = false;
                }
                self.operation = Operation::Idle;
                CloseOutcome::Settled
            }
            Err(_) => {
                record.close = CloseReceipt::Unknown;
                self.unknown = true;
                self.failure.get_or_insert(AdmissionFailure::CloseUncertain);
                CloseOutcome::Unknown
            }
        }
    }

    // Successful per-file/control closes are EXPECTED during inspection. They
    // are not global settlement and do not disable the final one-time move.
    fn close_finished(&mut self, slot: SlotId) -> AdmissionResult<()> {
        match self.close_one(slot) {
            CloseOutcome::Settled => Ok(()),
            CloseOutcome::Unknown => Err(AdmissionFailure::CloseUncertain),
        }
    }

    fn live_binding(&self, slot: SlotId, purpose: Purpose) -> bool {
        self.records.get(slot.0).is_some_and(|r| r.sequence == slot && r.purpose == purpose
            && r.acquisition == Acquisition::Original && r.original.is_some()
            && r.identity.is_some() && r.close == CloseReceipt::Unattempted)
    }

}

impl InstalledRuntimeCustody {
    /// Pure book allocation; legacy inspection still retains only its original nine witnesses.
    pub(crate) fn new() -> Self {
        Self { book: OriginalDescriptorBook::new(), ancestors: [None; PREFIX_COUNT], transferred: false,
            retain_android: false, work: RuntimeWork {
                walk: Vec::with_capacity(TREE_DEPTH + 1), inventory: None,
                actual_names: BTreeSet::new(), actual_folded: BTreeSet::new(), tree_entries: 0,
                files_verified: 0, directories_verified: 0, saw_manifest: false,
            } }
    }
    pub(crate) fn observation(&self) -> CustodyObservation { self.book.observation() }
    pub(crate) fn mark_interrupted(&mut self) { self.book.mark_interrupted(); }
    pub(crate) fn settle_originals(&mut self) -> CloseOutcome { self.book.settle_originals() }
    /// Synchronous work for the existing sole retained blocking inspection.
    /// No replacement clock, watcher, task, controller or restart is created.
    pub(crate) fn inspect_once(&mut self, end: Instant, stop: &watch::Receiver<bool>) -> InspectionOutcome {
        self.inspect_with_profile(None, end, stop)
    }
    fn inspect_with_profile(&mut self, profile: Option<&crate::runtime::PassiveInstalledProfile>,
        end: Instant, stop: &watch::Receiver<bool>) -> InspectionOutcome {
        if self.retain_android || self.book.phase != Phase::New || self.book.settlement_started || self.book.interrupted || self.transferred {
            if matches!(self.book.phase, Phase::Inspecting | Phase::PassivePreparing) { self.mark_interrupted(); }
            return self.book.refuse_and_settle(AdmissionFailure::AlreadyUsed);
        }
        self.book.phase = Phase::Inspecting;
        let result = (|| {
            if let Some(profile) = profile { self.book.inspect_passive_platform(profile, end, stop)?; }
            self.inspect_inner(end, stop)
        })();
        match result {
            Ok(()) => {
                self.book.operation = Operation::Idle;
                self.book.phase = Phase::InspectedOnly;
                InspectionOutcome::InspectedOnly
            }
            Err(failure) => self.book.refuse_and_settle(failure),
        }
    }

    fn retained_bindings_present(&self) -> bool {
        self.ancestors.iter().enumerate().all(|(index, slot)| {
            slot.is_some_and(|id| self.book.live_binding(id, Purpose::ProtectedAncestor(index as u8)))
        }) && self.book.namespaces[0].is_some_and(|id| self.book.live_binding(id, Purpose::InitialUserNamespace))
            && self.book.namespaces[1].is_some_and(|id| self.book.live_binding(id, Purpose::InitialPidNamespace))
    }

    fn retained_originals_ready(&self) -> bool {
        !self.book.settlement_started && !self.book.interrupted && !self.book.unknown
            && self.book.failure.is_none() && self.book.operation == Operation::Idle
            && self.retained_bindings_present()
            && self.book.records.iter().filter(|r| r.original.is_some()).count() == RETAINED_COUNT
            && self.book.records.iter().all(|r| r.acquisition == Acquisition::Original
                && match r.close {
                    CloseReceipt::Unattempted => r.original.is_some(),
                    CloseReceipt::Positive => r.original.is_none(),
                    CloseReceipt::Attempted | CloseReceipt::Unknown => false,
                })
    }
    fn inspected_originals_ready(&self) -> bool {
        self.book.phase == Phase::InspectedOnly && self.retained_originals_ready()
    }
    fn transfer_ready(&self) -> bool { !self.transferred && self.inspected_originals_ready() }
    fn start_passive_preparation(&mut self) -> AdmissionResult<()> {
        if !self.transferred || self.retain_android || self.book.budget.is_some() || !self.inspected_originals_ready() {
            return Err(AdmissionFailure::TransferUnavailable);
        }
        // One-shot, passive-only native borrow. Neither Android's budget nor
        // its Retained/audit state can substitute for this actual transition.
        self.book.phase = Phase::PassivePreparing;
        Ok(())
    }
}

/// Move the whole original ledger, once. No syscall, await, allocation, callback
/// or executable result is involved. The caller still owes actual registration,
/// original join and the existing serialized STOP/deadline race.
pub(crate) fn transfer_original(
    source: &mut Option<InstalledRuntimeCustody>,
    destination: &mut Option<InstalledRuntimeCustody>,
) -> AdmissionResult<TransferReceipt> {
    if destination.is_some() { return Err(AdmissionFailure::DestinationOccupied); }
    let Some(book) = source.as_ref() else { return Err(AdmissionFailure::TransferUnavailable); };
    if !book.transfer_ready() { return Err(AdmissionFailure::TransferUnavailable); }
    let receipt = TransferReceipt { original_records: book.book.records.len(), retained_originals: RETAINED_COUNT };
    let Some(mut original) = source.take() else { return Err(AdmissionFailure::TransferUnavailable); };
    original.transferred = true;
    *destination = Some(original);
    Ok(receipt)
}

/// One passive Owner's registered slots, not a second owner/controller. The
/// original inspection and acquisition workers borrow this SAME storage.
/// Profiles and path data are prepared before the serialized whole-ledger move.
pub(crate) struct PassiveRuntimeSlots {
    inspection: Option<InstalledRuntimeCustody>,
    profile: Option<crate::runtime::PassiveInstalledProfile>,
    selection: Option<crate::runtime::VerifiedRuntime>,
    acquisition: Option<PassiveInstalledRuntime>,
    inspection_started: bool,
    settlement_started: bool,
}

/// Domain-local capability, never cloned/serialized or returned by a worker.
/// Construction requires selected profile DATA AND the same inspected originals.
/// The test candidate cannot construct this private-field type from DATA alone.
pub(crate) struct PassiveInstalledRuntime {
    original: InstalledRuntimeCustody,
    profile: crate::runtime::PassiveInstalledProfile,
    selection: crate::runtime::VerifiedRuntime,
    claimed: bool,
    refused_before_effect: bool,
}

impl PassiveInstalledRuntime {
    fn ready(&self) -> bool {
        self.original.transferred && self.original.book.phase == Phase::PassivePrepared && self.original.retained_originals_ready()
            && !self.claimed && !self.refused_before_effect
    }
    /// The real acquisition worker borrows the transferred original ledger.
    /// Returned paths remain DATA; only this SAME borrowed capability can claim.
    pub(crate) fn prepare_once(&mut self, end: Instant, stop: &watch::Receiver<bool>) -> AdmissionResult<&crate::runtime::VerifiedRuntime> {
        if self.claimed || self.refused_before_effect { return Err(AdmissionFailure::TransferUnavailable); }
        self.original.start_passive_preparation()?;
        let result = (|| {
            self.original.book.inspect_passive_platform(&self.profile, end, stop)?;
            self.original.book.check_launch_thread(end, stop)?; // Actual current worker, not the inspector's TID.
            self.original.book.check_names(end, stop)?;
            self.original.book.begin(Operation::Idle, end, stop)?; // Original STOP/deadline after all native work.
            if !self.original.retained_originals_ready() { return Err(AdmissionFailure::LedgerInvariant); }
            Ok(())
        })();
        match result {
            Ok(()) => {
                // Only the actual complete native body return can prepare a claim.
                self.original.book.phase = Phase::PassivePrepared;
                Ok(&self.selection)
            }
            Err(failure) => {
                // Normal refusal is not interruption. Keep every partial in
                // this registered ledger until the original worker has joined.
                self.original.book.refuse(failure);
                Err(failure)
            }
        }
    }
    pub(crate) fn claim_once(&mut self) -> AdmissionResult<()> {
        if !self.ready() { return Err(AdmissionFailure::TransferUnavailable); }
        self.claimed = true;
        Ok(())
    }
    /// Called ONLY by the unconditional unsupported-profile spawn refusal, not an OS
    /// spawn-error mapper. This records no creation effect, never pipe closes.
    #[cfg(not(all(not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), any(test, feature = "desktop-shell"))))]
    pub(crate) fn record_closed_spawn_gate(&mut self) {
        self.refused_before_effect = true;
    }
}

impl PassiveRuntimeSlots {
    pub(crate) fn new() -> Self {
        Self { inspection: Some(InstalledRuntimeCustody::new()), profile: None, selection: None,
            acquisition: None, inspection_started: false, settlement_started: false }
    }
    pub(crate) fn never_started(&self) -> bool {
        !self.inspection_started && !self.settlement_started && self.profile.is_none() && self.selection.is_none()
            && self.acquisition.is_none() && self.inspection.as_ref().is_some_and(|original|
                original.book.phase == Phase::New && original.book.records.is_empty()
                && !original.book.unknown && !original.book.interrupted && !original.book.settlement_started)
    }
    pub(crate) fn inspect_once(&mut self, profile: crate::runtime::PassiveInstalledProfile,
        end: Instant, stop: &watch::Receiver<bool>) -> Result<crate::runtime::VerifiedRuntime, crate::error::BridgeError> {
        use crate::error::BridgeError;
        if !self.never_started() { return Err(BridgeError::cleanup_unknown()); }
        self.selection = Some(profile.selection()?);
        self.profile = Some(profile);
        self.inspection_started = true;
        let Some(profile) = self.profile.as_ref() else { return Err(BridgeError::cleanup_unknown()); };
        let Some(original) = self.inspection.as_mut() else { return Err(BridgeError::cleanup_unknown()); };
        match original.inspect_with_profile(Some(profile), end, stop) {
            InspectionOutcome::InspectedOnly => {
                let Some(data) = self.selection.as_ref() else { return Err(BridgeError::cleanup_unknown()); };
                Ok(crate::runtime::VerifiedRuntime { python: data.python.clone(), bootstrap: data.bootstrap.clone(),
                    core: data.core.clone(), cwd: data.cwd.clone() }) // DATA only; originals never leave these slots.
            }
            InspectionOutcome::Refused(_) => Err(BridgeError::unavailable("The passive installed runtime failed original-custody inspection.")),
            InspectionOutcome::Unknown => Err(BridgeError::cleanup_unknown()),
        }
    }
    pub(crate) fn transfer_once(&mut self) -> AdmissionResult<()> {
        if self.acquisition.is_some() { return Err(AdmissionFailure::DestinationOccupied); }
        if !self.inspection_started || self.settlement_started || self.profile.is_none() || self.selection.is_none()
            || !self.inspection.as_ref().is_some_and(InstalledRuntimeCustody::transfer_ready) {
            return Err(AdmissionFailure::TransferUnavailable);
        }
        // All fallible checks precede the actual source take. These two values
        // own no native resources; a failed precondition cannot discard custody.
        let profile = self.profile.take().ok_or(AdmissionFailure::LedgerInvariant)?;
        let selection = self.selection.take().ok_or(AdmissionFailure::LedgerInvariant)?;
        let Some(mut original) = self.inspection.take() else {
            self.profile = Some(profile); self.selection = Some(selection);
            return Err(AdmissionFailure::LedgerInvariant);
        };
        original.transferred = true;
        self.acquisition = Some(PassiveInstalledRuntime { original, profile, selection,
            claimed: false, refused_before_effect: false });
        Ok(()) // No syscall, allocation, await or fallible work after the actual take.
    }
    pub(crate) fn capability(&mut self) -> AdmissionResult<&mut PassiveInstalledRuntime> {
        if self.settlement_started { return Err(AdmissionFailure::TransferUnavailable); }
        self.acquisition.as_mut().ok_or(AdmissionFailure::TransferUnavailable)
    }
    pub(crate) fn no_child_effect(&self) -> bool {
        match (&self.inspection, &self.acquisition) {
            (Some(_), None) => true,
            (None, Some(runtime)) => !runtime.claimed || runtime.refused_before_effect,
            _ => false,
        }
    }
    pub(crate) fn mark_interrupted(&mut self) {
        if let Some(original) = &mut self.inspection { original.mark_interrupted(); }
        if let Some(runtime) = &mut self.acquisition { runtime.original.mark_interrupted(); }
    }
    pub(crate) fn settle_originals(&mut self) -> CloseOutcome {
        if self.settlement_started { return CloseOutcome::Unknown; }
        self.settlement_started = true;
        let mut count = 0; let mut positive = true;
        if let Some(original) = &mut self.inspection { count += 1; positive &= original.settle_originals() == CloseOutcome::Settled; }
        if let Some(runtime) = &mut self.acquisition { count += 1; positive &= runtime.original.settle_originals() == CloseOutcome::Settled; }
        if count == 1 && positive && self.settled() { CloseOutcome::Settled } else { CloseOutcome::Unknown }
    }
    pub(crate) fn settled(&self) -> bool {
        self.settlement_started && match (&self.inspection, &self.acquisition) {
            (Some(original), None) => original.settled(),
            (None, Some(runtime)) => runtime.original.settled(),
            _ => false,
        }
    }
    /// Read-only test observation, not a capability or a substitute join/close.
    #[cfg(all(test, not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher")))]
    pub(crate) fn claimed_observation(&self) -> Option<CustodyObservation> {
        match (&self.inspection, &self.acquisition) {
            (None, Some(runtime)) if runtime.original.transferred && runtime.claimed && !runtime.refused_before_effect =>
                Some(runtime.original.observation()),
            _ => None,
        }
    }
    /// Read-only native-fixture DATA for normal refusal/unchosen-claim closure.
    /// This neither moves originals nor creates a receipt/capability.
    #[cfg(all(test, not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher")))]
    pub(crate) fn fixture_observation(&self) -> Option<CustodyObservation> {
        match (&self.inspection, &self.acquisition) {
            (Some(original), None) => Some(original.observation()),
            (None, Some(runtime)) => Some(runtime.original.observation()),
            _ => None,
        }
    }
}

fn checkpoint(end: Instant, stop: &watch::Receiver<bool>) -> AdmissionResult<()> {
    if *stop.borrow() || stop.has_changed().is_err() { return Err(AdmissionFailure::Stopped); }
    if Instant::now() >= end { return Err(AdmissionFailure::Deadline); }
    Ok(())
}

fn native_error(error: Errno) -> AdmissionFailure {
    match error {
        Errno::ACCESS | Errno::PERM => AdmissionFailure::NativeDenied,
        _ => AdmissionFailure::NativeUnavailable,
    }
}

fn mount_error(error: mount::ObservationError) -> AdmissionFailure {
    match error {
        mount::ObservationError::Denied => AdmissionFailure::NativeDenied,
        mount::ObservationError::Inconsistent => AdmissionFailure::IdentityChanged,
        mount::ObservationError::Unsupported | mount::ObservationError::System => AdmissionFailure::Mount,
    }
}

fn fd_at(records: &[FdRecord], slot: SlotId) -> AdmissionResult<BorrowedFd<'_>> {
    let record = records.get(slot.0).ok_or(AdmissionFailure::LedgerInvariant)?;
    if record.sequence != slot || record.acquisition != Acquisition::Original || record.close != CloseReceipt::Unattempted {
        return Err(AdmissionFailure::LedgerInvariant);
    }
    record.original.as_ref().map(|original| original.as_fd()).ok_or(AdmissionFailure::LedgerInvariant)
}

fn ordinary_flags(directory: bool) -> OFlags {
    let flags = OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC | OFlags::NOFOLLOW;
    if directory { flags | OFlags::DIRECTORY } else { flags }
}

fn beneath_same_mount() -> ResolveFlags {
    ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_XDEV
}

fn single_component(name: &str) -> bool {
    !name.contains('/') && safe_payload_path(name)
}

pub(crate) fn ordinary_identity(identity: Identity, kind: FileType) -> bool {
    let forbidden = Mode::WGRP | Mode::WOTH | Mode::SUID | Mode::SGID | Mode::SVTX;
    FileType::from_raw_mode(identity.mode) == kind && identity.inode != 0
        && identity.links != 0 && identity.size >= 0
        && identity.mtime_nsec < 1_000_000_000 && identity.ctime_nsec < 1_000_000_000
        && !Mode::from_raw_mode(identity.mode).intersects(forbidden)
        && (kind != FileType::RegularFile || identity.links == 1)
}

pub(crate) fn protected_identity(identity: Identity, kind: FileType, size: Option<u64>) -> bool {
    ordinary_identity(identity, kind) && identity.uid == 0 && identity.gid == 0
        && size.is_none_or(|expected| u64::try_from(identity.size).ok() == Some(expected))
}

pub(crate) fn known_mount_attributes(attributes: u64) -> bool {
    attributes & !mount::KNOWN_ATTRIBUTES == 0 && attributes & mount::ID_MAPPED == 0
        && attributes & (mount::NO_ATIME | mount::STRICT_ATIME) != (mount::NO_ATIME | mount::STRICT_ATIME)
}

pub(crate) fn protected_mount(observation: mount::MountObservation) -> bool {
    matches!(observation.filesystem_magic(), mount::EXT4_MAGIC | mount::XFS_MAGIC)
        && known_mount_attributes(observation.attributes()) && observation.attributes() & mount::NO_EXEC == 0
}

impl OriginalDescriptorBook {
    fn acquire_root(&mut self, end: Instant, stop: &watch::Receiver<bool>) -> AdmissionResult<SlotId> {
        self.begin(Operation::Idle, end, stop)?;
        let slot = self.arm(Purpose::ProtectedAncestor(0))?;
        let result = fs::open("/", ordinary_flags(true), Mode::empty());
        let slot = self.receive_open(slot, result)?;
        self.root = Some(slot);
        Ok(slot)
    }

    fn acquire_child(&mut self, parent: SlotId, component: &str, directory: bool, purpose: Purpose,
        end: Instant, stop: &watch::Receiver<bool>) -> AdmissionResult<SlotId> {
        self.acquire_relative(parent, component, ordinary_flags(directory), beneath_same_mount(), purpose, end, stop)
    }

    fn acquire_relative(&mut self, parent: SlotId, component: &str, flags: OFlags, resolve: ResolveFlags,
        purpose: Purpose, end: Instant, stop: &watch::Receiver<bool>) -> AdmissionResult<SlotId> {
        self.begin(Operation::Idle, end, stop)?;
        if !(if self.budget.is_some() { tool_component(component) } else { single_component(component) }) { return Err(AdmissionFailure::Inventory); }
        let _ = fd_at(&self.records, parent)?;
        let slot = self.arm(purpose)?;
        self.records[slot.0].parent = Some((parent, component.to_owned()));
        let result = fs::openat2(fd_at(&self.records, parent)?, component, flags, Mode::empty(), resolve);
        self.receive_open(slot, result)
    }

    fn snapshot(&mut self, slot: SlotId, end: Instant, stop: &watch::Receiver<bool>) -> AdmissionResult<Identity> {
        self.begin(Operation::Metadata(slot), end, stop)?;
        let result = fs::fstat(fd_at(&self.records, slot)?);
        self.operation = Operation::Idle;
        let identity = Identity::of(&result.map_err(native_error)?);
        let record = self.records.get_mut(slot.0).ok_or(AdmissionFailure::LedgerInvariant)?;
        match record.identity {
            Some(original) if original != identity => return Err(AdmissionFailure::IdentityChanged),
            None => record.identity = Some(identity),
            _ => {}
        }
        Ok(identity)
    }

    fn filesystem_magic(&mut self, slot: SlotId, end: Instant, stop: &watch::Receiver<bool>) -> AdmissionResult<u64> {
        self.begin(Operation::Mount(slot), end, stop)?;
        let result = fs::fstatfs(fd_at(&self.records, slot)?);
        self.operation = Operation::Idle;
        Ok(result.map_err(native_error)?.f_type as u64)
    }

    fn mounted_original(&mut self, slot: SlotId, identity: Identity,
        end: Instant, stop: &watch::Receiver<bool>) -> AdmissionResult<mount::MountObservation> {
        let magic = self.filesystem_magic(slot, end, stop)?;
        self.begin(Operation::Mount(slot), end, stop)?;
        let result = mount::observe_mount(fd_at(&self.records, slot)?);
        self.operation = Operation::Idle;
        let observed = result.map_err(mount_error)?;
        if observed.device() != identity.device_pair()? || observed.filesystem_magic() != magic {
            return Err(AdmissionFailure::Mount);
        }
        Ok(observed)
    }

    fn absent_attribute(&mut self, slot: SlotId, name: &'static str,
        end: Instant, stop: &watch::Receiver<bool>) -> AdmissionResult<()> {
        self.begin(Operation::Attributes(slot), end, stop)?;
        let result = fs::fgetxattr(fd_at(&self.records, slot)?, name, &mut self.work.attribute_buffer[..]);
        self.operation = Operation::Idle;
        // A one-byte initialized buffer is enough: ANY present value, including
        // an empty one or ERANGE, refuses. ENOTSUP/EPERM are not absence.
        match result { Err(Errno::NODATA) => Ok(()), _ => Err(AdmissionFailure::ExtendedAttributes) }
    }

    fn inspect_protected(&mut self, slot: SlotId, kind: FileType, size: Option<u64>,
        end: Instant, stop: &watch::Receiver<bool>) -> AdmissionResult<mount::MountObservation> {
        let before = self.snapshot(slot, end, stop)?;
        if !protected_identity(before, kind, size) { return Err(AdmissionFailure::Ownership); }
        self.absent_attribute(slot, "system.posix_acl_access", end, stop)?;
        if kind == FileType::Directory {
            self.absent_attribute(slot, "system.posix_acl_default", end, stop)?;
        } else {
            self.absent_attribute(slot, "security.capability", end, stop)?;
        }
        let observed = self.mounted_original(slot, before, end, stop)?;
        if !protected_mount(observed) { return Err(AdmissionFailure::Mount); }
        match self.root_mount {
            Some(root) if root != observed => return Err(AdmissionFailure::Mount),
            None if self.records[slot.0].purpose != Purpose::ProtectedAncestor(0) => return Err(AdmissionFailure::LedgerInvariant),
            _ => {}
        }
        self.snapshot(slot, end, stop)?;
        Ok(observed)
    }

    fn inspect_proc_object(&mut self, slot: SlotId, kind: FileType,
        end: Instant, stop: &watch::Receiver<bool>) -> AdmissionResult<mount::MountObservation> {
        let before = self.snapshot(slot, end, stop)?;
        if !ordinary_identity(before, kind) { return Err(AdmissionFailure::Namespace); }
        let observed = self.mounted_original(slot, before, end, stop)?;
        if observed.filesystem_magic() != mount::PROC_MAGIC || !known_mount_attributes(observed.attributes()) {
            return Err(AdmissionFailure::Namespace);
        }
        match self.proc_mount {
            Some(proc_mount) if proc_mount != observed => return Err(AdmissionFailure::Namespace),
            None if self.records[slot.0].purpose != Purpose::ProcRoot => return Err(AdmissionFailure::LedgerInvariant),
            _ => {}
        }
        // Proc controls are genuine kernel-generated entries, not protected
        // payloads. Their per-task ownership is intentionally NOT forced to 0.
        // NO_XDEV/no-symlink component opens forbid bind-file substitutions.
        self.snapshot(slot, end, stop)?;
        Ok(observed)
    }

    fn inspect_namespace(&mut self, slot: SlotId, expected_inode: u64,
        end: Instant, stop: &watch::Receiver<bool>) -> AdmissionResult<()> {
        let identity = self.snapshot(slot, end, stop)?;
        if !ordinary_identity(identity, FileType::RegularFile) || identity.inode != expected_inode
            || self.filesystem_magic(slot, end, stop)? != mount::NAMESPACE_MAGIC {
            return Err(AdmissionFailure::Namespace);
        }
        self.snapshot(slot, end, stop)?;
        Ok(())
    }

    /// Read this original to a real EOF; progress/buffers/hash stay in the book.
    /// Proc st_size is normally zero and is NOT mistaken for its content size.
    fn read_original(&mut self, slot: SlotId, expected_size: Option<u64>, limit: u64, capture: bool,
        end: Instant, stop: &watch::Receiver<bool>) -> AdmissionResult<[u8; 32]> {
        self.begin(Operation::Read(slot), end, stop)?;
        let before = self.records.get(slot.0).and_then(|record| record.identity).ok_or(AdmissionFailure::LedgerInvariant)?;
        if FileType::from_raw_mode(before.mode) != FileType::RegularFile
            || expected_size.is_some_and(|size| size > limit || u64::try_from(before.size).ok() != Some(size))
            || (capture && limit > self.work.data.capacity() as u64) {
            return Err(AdmissionFailure::Bounds);
        }
        if self.budget.is_some() && matches!(self.records[slot.0].purpose, Purpose::Manifest | Purpose::Payload) {
            let bytes = expected_size.ok_or(AdmissionFailure::Bounds)?;
            let pass = usize::from(self.phase == Phase::Auditing);
            self.hash_left[pass] = self.hash_left[pass].checked_sub(bytes).ok_or(AdmissionFailure::Bounds)?;
        }
        self.work.reader = Some(slot);
        self.work.read_bytes = 0;
        self.work.read_eof = false;
        self.work.last_digest = None;
        self.work.hash = Sha256::new();
        self.work.data.clear();
        loop {
            self.begin(Operation::Read(slot), end, stop)?;
            let result = if self.budget.is_some() && expected_size.is_some() {
                // Two precharged passes on this SAME original; no reopen/seek adoption.
                rustix::io::pread(fd_at(&self.records, slot)?, &mut self.work.block[..], self.work.read_bytes)
            } else { rustix::io::read(fd_at(&self.records, slot)?, &mut self.work.block[..]) };
            let length = result.map_err(native_error)?;
            if length == 0 { self.work.read_eof = true; break; }
            self.work.read_bytes = self.work.read_bytes.checked_add(length as u64).ok_or(AdmissionFailure::Bounds)?;
            if self.work.read_bytes > limit || expected_size.is_some_and(|size| self.work.read_bytes > size) {
                return Err(AdmissionFailure::Bounds);
            }
            self.operation = Operation::Hash(slot);
            self.work.hash.update(&self.work.block[..length]);
            if capture { self.work.data.extend_from_slice(&self.work.block[..length]); }
        }
        self.snapshot(slot, end, stop)?;
        if expected_size.is_some_and(|size| self.work.read_bytes != size) { return Err(AdmissionFailure::IdentityChanged); }
        self.begin(Operation::Hash(slot), end, stop)?;
        let digest: [u8; 32] = self.work.hash.finalize_reset().into();
        self.work.last_digest = Some(digest);
        self.work.reader = None;
        self.operation = Operation::Idle;
        Ok(digest)
    }

    fn read_proc_control(&mut self, parent: SlotId, component: &'static str, limit: usize,
        end: Instant, stop: &watch::Receiver<bool>) -> AdmissionResult<()> {
        let slot = self.acquire_child(parent, component, false, Purpose::ProcControl, end, stop)?;
        self.inspect_proc_object(slot, FileType::RegularFile, end, stop)?;
        self.read_original(slot, None, limit as u64, true, end, stop)?;
        self.inspect_proc_object(slot, FileType::RegularFile, end, stop)?;
        self.close_finished(slot)
    }

    fn current_credentials(&mut self, end: Instant, stop: &watch::Receiver<bool>) -> AdmissionResult<Credentials> {
        self.begin(Operation::Credentials, end, stop)?;
        let uid = rustix::process::getuid().as_raw();
        self.begin(Operation::Credentials, end, stop)?;
        let euid = rustix::process::geteuid().as_raw();
        self.begin(Operation::Credentials, end, stop)?;
        let gid = rustix::process::getgid().as_raw();
        self.begin(Operation::Credentials, end, stop)?;
        let egid = rustix::process::getegid().as_raw();
        self.begin(Operation::Credentials, end, stop)?;
        let pid = rustix::process::getpid().as_raw_pid();
        self.begin(Operation::Credentials, end, stop)?;
        let tid = rustix::thread::gettid().as_raw_pid();
        self.begin(Operation::Credentials, end, stop)?;
        let capabilities = rustix::thread::capabilities(None).map_err(native_error)?;
        self.operation = Operation::Idle;
        if uid == 0 || euid == 0 || uid != euid || gid != egid
            || !capabilities.effective.is_empty() || !capabilities.permitted.is_empty()
            || !capabilities.inheritable.is_empty() {
            return Err(AdmissionFailure::Namespace);
        }
        Ok(Credentials { uid, gid, pid: u32::try_from(pid).map_err(|_| AdmissionFailure::Namespace)?,
            tid: u32::try_from(tid).map_err(|_| AdmissionFailure::Namespace)? })
    }

    fn inspect_kernel(&mut self, end: Instant, stop: &watch::Receiver<bool>) -> AdmissionResult<()> {
        self.begin(Operation::Kernel, end, stop)?;
        if self.budget.is_some() && rustix::process::getrlimit(rustix::process::Resource::Nofile)
            .current.is_some_and(|limit| limit < 8192) { return Err(AdmissionFailure::Bounds); }
        let actual = rustix::system::uname();
        self.operation = Operation::Idle;
        if !supported_kernel(actual.sysname().to_bytes(), actual.machine().to_bytes(), actual.release().to_bytes()) {
            return Err(AdmissionFailure::UnsupportedPlatform);
        }
        Ok(())
    }

    fn inspect_passive_platform(&mut self, profile: &crate::runtime::PassiveInstalledProfile,
        end: Instant, stop: &watch::Receiver<bool>) -> AdmissionResult<()> {
        self.begin(Operation::Kernel, end, stop)?;
        let actual = rustix::system::uname();
        self.operation = Operation::Idle;
        if !profile.accepts_platform(actual.sysname().to_bytes(), actual.machine().to_bytes(), actual.release().to_bytes()) {
            return Err(AdmissionFailure::UnsupportedPlatform);
        }
        Ok(()) // Narrow passive candidate only; the shared GA6.8/Azure ABI rule is unchanged.
    }

    fn inspect_namespace_controls(&mut self, root: SlotId, credentials: Credentials,
        end: Instant, stop: &watch::Receiver<bool>) -> AdmissionResult<()> {
        if self.budget.is_some() {
            if self.control_rounds >= 3 { return Err(AdmissionFailure::Bounds); }
            self.control_rounds += 1;
        }
        let retaining = self.namespaces[0].is_none();
        // The ONLY ordinary mount crossing: fixed '/' -> fixed genuine '/proc'.
        let proc_root = self.acquire_relative(root, "proc", ordinary_flags(true),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
            Purpose::ProcRoot, end, stop)?;
        self.proc_mount = Some(self.inspect_proc_object(proc_root, FileType::Directory, end, stop)?);
        let pid_name = credentials.pid.to_string();
        let tid_name = credentials.tid.to_string();
        let process = self.acquire_child(proc_root, &pid_name, true, Purpose::ProcDirectory, end, stop)?;
        self.inspect_proc_object(process, FileType::Directory, end, stop)?;
        let task = self.acquire_child(process, "task", true, Purpose::ProcDirectory, end, stop)?;
        self.inspect_proc_object(task, FileType::Directory, end, stop)?;
        let thread = self.acquire_child(task, &tid_name, true, Purpose::ProcDirectory, end, stop)?;
        self.inspect_proc_object(thread, FileType::Directory, end, stop)?;
        let ns = self.acquire_child(thread, "ns", true, Purpose::ProcDirectory, end, stop)?;
        self.inspect_proc_object(ns, FileType::Directory, end, stop)?;

        // Only these fixed user/pid endpoints and the Android mnt endpoint
        // below follow kernel magic links, under this pinned genuine numeric
        // current-thread proc ns directory. No payload gets this exception.
        let namespace_flags = OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC;
        let user_ns = self.acquire_relative(ns, "user", namespace_flags, ResolveFlags::empty(),
            Purpose::InitialUserNamespace, end, stop)?;
        self.inspect_namespace(user_ns, INITIAL_USER_INODE, end, stop)?;
        if retaining { self.namespaces[0] = Some(user_ns); }
        let pid_ns = self.acquire_relative(ns, "pid", namespace_flags, ResolveFlags::empty(),
            Purpose::InitialPidNamespace, end, stop)?;
        self.inspect_namespace(pid_ns, INITIAL_PID_INODE, end, stop)?;
        if retaining { self.namespaces[1] = Some(pid_ns); }

        self.read_proc_control(thread, "uid_map", MAP_LIMIT, end, stop)?;
        initial_id_map(&self.work.data)?;
        self.read_proc_control(thread, "gid_map", MAP_LIMIT, end, stop)?;
        initial_id_map(&self.work.data)?;
        self.read_proc_control(thread, "status", STATUS_LIMIT, end, stop)?;
        inspect_status(&self.work.data, credentials)?;
        self.read_proc_control(thread, "mountinfo", MOUNTINFO_LIMIT, end, stop)?;
        let current_root = parse_root_mount(&self.work.data)?;

        // Initial PID namespace evidence above makes fixed 1 the actual global
        // init. This is a read-only namespace witness, NEVER process discovery,
        // a controller, a child receipt or permission to signal anything.
        let initial = self.acquire_child(proc_root, "1", true, Purpose::ProcDirectory, end, stop)?;
        self.inspect_proc_object(initial, FileType::Directory, end, stop)?;
        self.read_proc_control(initial, "mountinfo", MOUNTINFO_LIMIT, end, stop)?;
        let initial_root = parse_root_mount(&self.work.data)?;
        let root_mount = self.root_mount.ok_or(AdmissionFailure::LedgerInvariant)?;
        let original_root = RootMount { old_id: root_mount.old_id(), device: root_mount.device(), magic: root_mount.filesystem_magic() };
        if current_root != initial_root || current_root != original_root { return Err(AdmissionFailure::Namespace); }

        if self.budget.is_some() {
            // Bind the actual numeric current-thread mount namespace, retaining
            // the first original through launch and final audit. PID1 ns/mnt is
            // ptrace-gated and is NOT an accessible ordinary-user witness.
            // Continuity and equal root mounts do not authenticate an initial/
            // host mount namespace; that remains external OS qualification.
            let current = self.acquire_relative(ns, "mnt", namespace_flags, ResolveFlags::empty(), Purpose::MountNamespace, end, stop)?;
            let identity = self.snapshot(current, end, stop)?;
            self.inspect_namespace(current, identity.inode, end, stop)?;
            if let Some(original) = self.mount_namespace {
                if self.snapshot(original, end, stop)? != identity { return Err(AdmissionFailure::Namespace); }
                self.inspect_namespace(original, identity.inode, end, stop)?;
                self.close_finished(current)?; // Never substitute for the retained original.
            } else { self.mount_namespace = Some(current); }
        }
        if !retaining { self.close_finished(pid_ns)?; self.close_finished(user_ns)?; }
        for slot in [initial, ns, thread, task, process, proc_root] {
            self.inspect_proc_object(slot, FileType::Directory, end, stop)?;
            self.close_finished(slot)?;
        }
        // Keep BOTH actual initial-namespace handles along with the seven
        // ancestor/version bindings; every temporary proc original is settled.
        Ok(())
    }

    fn inspect_os_release(&mut self, root: SlotId, end: Instant, stop: &watch::Receiver<bool>) -> AdmissionResult<()> {
        // Never /etc/os-release (usually a symlink), PATH, distro environment,
        // project location, relocated archive or administrator-elevation helper.
        let usr = self.acquire_child(root, "usr", true, Purpose::OsDirectory, end, stop)?;
        self.inspect_protected(usr, FileType::Directory, None, end, stop)?;
        let lib = self.acquire_child(usr, "lib", true, Purpose::OsDirectory, end, stop)?;
        self.inspect_protected(lib, FileType::Directory, None, end, stop)?;
        let release = self.acquire_child(lib, "os-release", false, Purpose::OsIdentity, end, stop)?;
        self.inspect_protected(release, FileType::RegularFile, None, end, stop)?;
        let size = self.records[release.0].identity.ok_or(AdmissionFailure::LedgerInvariant)?.size;
        let size = u64::try_from(size).map_err(|_| AdmissionFailure::Bounds)?;
        self.read_original(release, Some(size), OS_RELEASE_LIMIT as u64, true, end, stop)?;
        ubuntu_2404(&self.work.data)?;
        self.inspect_protected(release, FileType::RegularFile, Some(size), end, stop)?;
        self.close_finished(release)?;
        self.inspect_protected(lib, FileType::Directory, None, end, stop)?;
        self.close_finished(lib)?;
        self.inspect_protected(usr, FileType::Directory, None, end, stop)?;
        self.close_finished(usr)
    }

}

impl InstalledRuntimeCustody {
    fn inspect_inner(&mut self, end: Instant, stop: &watch::Receiver<bool>) -> AdmissionResult<()> {
        self.book.begin(Operation::Inventory, end, stop)?;
        if COMPILED_TARGET != TARGET { return Err(AdmissionFailure::UnsupportedPlatform); }
        let manifest_anchor = MANIFEST_ANCHOR.filter(|value| sha(value)).ok_or(AdmissionFailure::MissingCompileAnchor)?;
        let protocol_anchor = PROTOCOL_ANCHOR.filter(|value| sha(value)).ok_or(AdmissionFailure::MissingCompileAnchor)?;
        self.book.inspect_kernel(end, stop)?;
        let credentials = self.book.current_credentials(end, stop)?;
        self.book.credentials = Some(credentials);
        let root = self.book.acquire_root(end, stop)?;
        self.book.root_mount = Some(self.book.inspect_protected(root, FileType::Directory, None, end, stop)?);
        self.ancestors[0] = Some(root);
        self.book.inspect_namespace_controls(root, credentials, end, stop)?;
        self.book.inspect_os_release(root, end, stop)?;

        let mut parent = root;
        for (index, component) in ["var", "lib", "mobile-release-kit", "versions", TARGET, manifest_anchor].into_iter().enumerate() {
            let slot = self.book.acquire_child(parent, component, true, Purpose::ProtectedAncestor((index + 1) as u8), end, stop)?;
            self.book.inspect_protected(slot, FileType::Directory, None, end, stop)?;
            self.ancestors[index + 1] = Some(slot);
            parent = slot;
        }
        let version = parent;
        let manifest_slot = self.book.acquire_child(version, "manifest.json", false, Purpose::Manifest, end, stop)?;
        self.book.inspect_protected(manifest_slot, FileType::RegularFile, None, end, stop)?;
        let manifest_size = self.book.records[manifest_slot.0].identity.ok_or(AdmissionFailure::LedgerInvariant)?.size;
        let manifest_size = u64::try_from(manifest_size).map_err(|_| AdmissionFailure::Bounds)?;
        let digest = self.book.read_original(manifest_slot, Some(manifest_size), MANIFEST_LIMIT as u64, true, end, stop)?;
        self.book.begin(Operation::Inventory, end, stop)?;
        if hex(&digest) != manifest_anchor { return Err(AdmissionFailure::Manifest); }
        self.work.inventory = Some(parse_inventory(&self.book.work.data, protocol_anchor)?);
        self.book.inspect_protected(manifest_slot, FileType::RegularFile, Some(manifest_size), end, stop)?;
        self.walk_inventory(version, manifest_slot, end, stop)?;
        self.book.inspect_protected(manifest_slot, FileType::RegularFile, Some(manifest_size), end, stop)?;
        if self.retain_android { self.book.records[manifest_slot.0].digest = Some(manifest_anchor.to_owned()); }
        else { self.book.close_finished(manifest_slot)?; }

        for index in 0..PREFIX_COUNT {
            let slot = self.ancestors[index].ok_or(AdmissionFailure::LedgerInvariant)?;
            self.book.inspect_protected(slot, FileType::Directory, None, end, stop)?;
        }
        for (index, inode) in [INITIAL_USER_INODE, INITIAL_PID_INODE].into_iter().enumerate() {
            self.book.inspect_namespace(self.book.namespaces[index].ok_or(AdmissionFailure::LedgerInvariant)?, inode, end, stop)?;
        }
        if self.book.current_credentials(end, stop)? != credentials || !self.retained_bindings_present()
            || !self.retain_android && self.book.records.iter().filter(|r| r.original.is_some()).count() != RETAINED_COUNT
            || self.book.records.iter().any(|r| r.acquisition != Acquisition::Original
                || matches!(r.close, CloseReceipt::Attempted | CloseReceipt::Unknown)) {
            return Err(AdmissionFailure::LedgerInvariant);
        }
        self.book.begin(Operation::Idle, end, stop)?;
        Ok(())
    }
}

impl InstalledRuntimeCustody {
    fn enumerate_directory(&mut self, frame_index: usize, manifest: SlotId,
        end: Instant, stop: &watch::Receiver<bool>) -> AdmissionResult<()> {
        let slot = self.work.walk.get(frame_index).ok_or(AdmissionFailure::LedgerInvariant)?.original;
        self.book.begin(Operation::Directory(slot), end, stop)?;
        let directory_identity = self.book.records[slot.0].identity.ok_or(AdmissionFailure::LedgerInvariant)?;
        let manifest_identity = self.book.records[manifest.0].identity.ok_or(AdmissionFailure::LedgerInvariant)?;
        self.book.work.directory = Some(slot);
        {
            let original = fd_at(&self.book.records, slot)?;
            // RawDir owns ONLY this BorrowedFd and borrows the original book's
            // buffer. No dup/Dir/fdopendir/owned iterator/implicit-close owner.
            // The cursor itself is local: if lost, the book can ONLY settle,
            // never resume from a discarded getdents buffer and claim success.
            let mut entries = RawDir::new(original, &mut self.book.work.directory_buffer[..]);
            loop {
                checkpoint(end, stop)?;
                self.book.operation = Operation::Directory(slot);
                let Some(entry) = entries.next() else { break; };
                let entry = entry.map_err(native_error)?;
                let component = entry.file_name().to_str().map_err(|_| AdmissionFailure::Inventory)?;
                let kind = entry.file_type();
                let inode = entry.ino();
                let frame = &mut self.work.walk[frame_index];
                if component == "." {
                    if frame.dot_seen || kind != FileType::Directory || inode != directory_identity.inode {
                        return Err(AdmissionFailure::Inventory);
                    }
                    frame.dot_seen = true;
                    continue;
                }
                if component == ".." {
                    if frame.dotdot_seen || kind != FileType::Directory || inode == 0 {
                        return Err(AdmissionFailure::Inventory);
                    }
                    frame.dotdot_seen = true;
                    continue;
                }
                self.work.tree_entries = self.work.tree_entries.checked_add(1).ok_or(AdmissionFailure::Bounds)?;
                if self.work.tree_entries > ENTRY_COUNT || inode == 0 || !single_component(component)
                    || !matches!(kind, FileType::Directory | FileType::RegularFile) {
                    return Err(AdmissionFailure::Inventory);
                }
                let relative = if frame.relative.is_empty() { component.to_owned() }
                    else { format!("{}/{}", frame.relative, component) };
                if !safe_payload_path(&relative) { return Err(AdmissionFailure::Inventory); }
                let inventory = self.work.inventory.as_ref().ok_or(AdmissionFailure::LedgerInvariant)?;
                if relative == "manifest.json" {
                    if kind != FileType::RegularFile || self.work.saw_manifest
                        || inode != manifest_identity.inode || directory_identity.device != manifest_identity.device {
                        return Err(AdmissionFailure::Inventory);
                    }
                    self.work.saw_manifest = true;
                } else if kind == FileType::Directory {
                    if !inventory.directories.contains(&relative) { return Err(AdmissionFailure::Inventory); }
                } else if inventory.files.binary_search_by(|file| file.path.as_str().cmp(&relative)).is_err() {
                    return Err(AdmissionFailure::Inventory);
                }
                if !self.work.actual_names.insert(relative.clone())
                    || !self.work.actual_folded.insert(relative.to_ascii_lowercase()) {
                    return Err(AdmissionFailure::Inventory);
                }
                frame.entries.push(TreeEntry { component: component.to_owned(), inode, kind });
            }
        }
        let frame = &mut self.work.walk[frame_index];
        if !frame.dot_seen || !frame.dotdot_seen { return Err(AdmissionFailure::Inventory); }
        frame.enumerated = true;
        self.book.work.directory = None;
        self.book.snapshot(slot, end, stop)?;
        self.book.operation = Operation::Idle;
        Ok(())
    }

    fn walk_inventory(&mut self, version: SlotId, manifest: SlotId,
        end: Instant, stop: &watch::Receiver<bool>) -> AdmissionResult<()> {
        self.work.walk.push(DirectoryFrame { original: version, relative: String::new(), depth: 0,
            entries: Vec::new(), next: 0, enumerated: false, dot_seen: false, dotdot_seen: false });
        while !self.work.walk.is_empty() {
            self.book.begin(Operation::Inventory, end, stop)?;
            let index = self.work.walk.len() - 1;
            if !self.work.walk[index].enumerated { self.enumerate_directory(index, manifest, end, stop)?; }
            let frame = &mut self.work.walk[index];
            if frame.next == frame.entries.len() {
                let slot = frame.original;
                self.book.inspect_protected(slot, FileType::Directory, None, end, stop)?;
                if slot != version && !self.retain_android { self.book.close_finished(slot)?; }
                self.work.directories_verified += 1;
                self.work.walk.pop();
                continue;
            }
            let entry = &frame.entries[frame.next];
            // Only bounded names/data are copied. No descriptor is duplicated;
            // originals, parent bindings and the actual cursor remain in book.
            let component = entry.component.clone();
            let inode = entry.inode;
            let kind = entry.kind;
            let parent = frame.original;
            let depth = frame.depth + 1;
            let relative = if frame.relative.is_empty() { component.clone() }
                else { format!("{}/{}", frame.relative, component) };
            frame.next += 1;
            if depth > TREE_DEPTH { return Err(AdmissionFailure::Bounds); }
            if relative == "manifest.json" { continue; } // Only the already-open ROOT manifest.
            if kind == FileType::Directory {
                let slot = self.book.acquire_child(parent, &component, true, Purpose::InventoryDirectory, end, stop)?;
                self.book.inspect_protected(slot, FileType::Directory, None, end, stop)?;
                if self.book.records[slot.0].identity.is_none_or(|identity| identity.inode != inode) {
                    return Err(AdmissionFailure::IdentityChanged);
                }
                if self.work.walk.len() >= TREE_DEPTH + 1 { return Err(AdmissionFailure::Bounds); }
                self.work.walk.push(DirectoryFrame { original: slot, relative, depth,
                    entries: Vec::new(), next: 0, enumerated: false, dot_seen: false, dotdot_seen: false });
            } else {
                let inventory = self.work.inventory.as_ref().ok_or(AdmissionFailure::LedgerInvariant)?;
                let file_index = inventory.files.binary_search_by(|file| file.path.as_str().cmp(&relative))
                    .map_err(|_| AdmissionFailure::Inventory)?;
                let expected_size = inventory.files[file_index].size;
                let expected_hash = inventory.files[file_index].sha256.clone();
                let slot = self.book.acquire_child(parent, &component, false, Purpose::Payload, end, stop)?;
                self.book.inspect_protected(slot, FileType::RegularFile, Some(expected_size), end, stop)?;
                if self.book.records[slot.0].identity.is_none_or(|identity| identity.inode != inode) {
                    return Err(AdmissionFailure::IdentityChanged);
                }
                let android_bootstrap = self.retain_android && relative == "android_build_bootstrap.py";
                let digest = self.book.read_original(slot, Some(expected_size), if android_bootstrap { 64 * 1024 } else { FILE_LIMIT }, android_bootstrap, end, stop)?;
                if hex(&digest) != expected_hash || android_bootstrap
                    && self.book.work.data.as_slice() != include_bytes!("../../android_build_bootstrap.py") {
                    return Err(AdmissionFailure::Manifest);
                }
                if self.retain_android && relative == "python/bin/python3"
                    && self.book.records[slot.0].identity.is_none_or(|identity| identity.mode & 0o111 == 0) {
                    return Err(AdmissionFailure::Manifest);
                }
                self.book.inspect_protected(slot, FileType::RegularFile, Some(expected_size), end, stop)?;
                if self.retain_android { self.book.records[slot.0].digest = Some(expected_hash); }
                else { self.book.close_finished(slot)?; }
                self.work.files_verified += 1;
            }
        }
        let inventory = self.work.inventory.as_ref().ok_or(AdmissionFailure::LedgerInvariant)?;
        if !self.work.saw_manifest || self.work.files_verified != inventory.files.len()
            || self.work.directories_verified != inventory.directories.len() + 1
            || self.work.actual_names.len() != inventory.files.len() + inventory.directories.len() + 1
            || !inventory.files.iter().all(|file| self.work.actual_names.contains(&file.path))
            || !inventory.directories.iter().all(|directory| self.work.actual_names.contains(directory)) {
            return Err(AdmissionFailure::Inventory);
        }
        self.book.operation = Operation::Idle;
        Ok(())
    }
}


// The only second consumer of these private primitives is the fixed Android
// tool book. Two books precharge 64 kernel-control slots EACH; every other live
// original (including ancestry and aliases) competes below the SAME 4096 cap.
const ANDROID_CONTROL_SLOTS: usize = 64;
pub(crate) struct AndroidDescriptorBudget {
    live: AtomicUsize,
    // Original Session-owned cutoff, initialized at W and only tightened by
    // its serialized first F. No replacement clock, watcher or timer task.
    audit_cutoff: watch::Receiver<Instant>,
}
impl AndroidDescriptorBudget {
    pub(crate) fn new(audit_cutoff: watch::Receiver<Instant>) -> Self {
        Self { live: AtomicUsize::new(2 * ANDROID_CONTROL_SLOTS), audit_cutoff }
    }
    fn audit_end(&self, end: Instant) -> AdmissionResult<Instant> {
        if self.audit_cutoff.has_changed().is_err() { return Err(AdmissionFailure::Interrupted); }
        Ok(end.min(*self.audit_cutoff.borrow()))
    }
    fn claim(&self) -> AdmissionResult<()> {
        self.live.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| (n < 4096).then_some(n + 1))
            .map(|_| ()).map_err(|_| AdmissionFailure::Bounds)
    }
    fn release(&self) { self.live.fetch_sub(1, Ordering::SeqCst); }
}
pub(crate) struct ProtectedEntry { pub(crate) name: String, pub(crate) inode: u64, pub(crate) kind: FileType }
impl OriginalDescriptorBook {
    pub(crate) fn new_android(budget: Arc<AndroidDescriptorBudget>) -> Self {
        let mut book = Self::new(); book.budget = Some(budget); book
    }
    pub(crate) fn identity(&self, slot: SlotId) -> AdmissionResult<Identity> {
        let _ = fd_at(&self.records, slot)?;
        self.records[slot.0].identity.ok_or(AdmissionFailure::LedgerInvariant)
    }
    pub(crate) fn ready(&self) -> bool {
        self.phase == Phase::Retained && !self.unknown && !self.interrupted && !self.settlement_started
            && !self.audit_started && self.failure.is_none() && self.operation == Operation::Idle
    }
    pub(crate) fn settled(&self) -> bool { self.phase == Phase::Settled && !self.unknown && !self.interrupted }
    pub(crate) fn remember(&mut self, failure: AdmissionFailure) { self.failure.get_or_insert(failure); }
    pub(crate) fn refuse(&mut self, failure: AdmissionFailure) {
        self.remember(failure);
        if !self.unknown { self.phase = Phase::Refused; self.operation = Operation::Idle; }
    }
    pub(crate) fn start_android(&mut self, end: Instant, stop: &watch::Receiver<bool>) -> AdmissionResult<SlotId> {
        if self.phase != Phase::New || self.budget.is_none() { return Err(AdmissionFailure::AlreadyUsed); }
        self.phase = Phase::Inspecting; self.original_stop = Some(stop.clone());
        self.inspect_kernel(end, stop)?;
        let credentials = self.current_credentials(end, stop)?; self.credentials = Some(credentials);
        let root = self.acquire_root(end, stop)?;
        self.root_mount = Some(self.inspect_protected(root, FileType::Directory, None, end, stop)?);
        self.inspect_namespace_controls(root, credentials, end, stop)?;
        self.inspect_os_release(root, end, stop)?;
        Ok(root)
    }
    pub(crate) fn finish_retained(&mut self) -> AdmissionResult<()> {
        if self.phase != Phase::Inspecting || self.budget.is_none() || self.failure.is_some() || self.unknown
            || self.settlement_started || self.records.iter().any(|r| r.acquisition == Acquisition::Attempted
                || matches!(r.close, CloseReceipt::Attempted | CloseReceipt::Unknown)
                || r.original.is_some() && r.identity.is_none()) { return Err(AdmissionFailure::LedgerInvariant); }
        self.phase = Phase::Retained; self.operation = Operation::Idle; Ok(())
    }
    pub(crate) fn directory(&mut self, parent: SlotId, name: &str, end: Instant, stop: &watch::Receiver<bool>) -> AdmissionResult<SlotId> {
        let slot = self.acquire_child(parent, name, true, Purpose::InventoryDirectory, end, stop)?;
        self.inspect_protected(slot, FileType::Directory, None, end, stop)?; Ok(slot)
    }
    pub(crate) fn manifest(&mut self, parent: SlotId, name: &str, expected: &str, end: Instant,
        stop: &watch::Receiver<bool>) -> AdmissionResult<(SlotId, Vec<u8>)> {
        let slot = self.acquire_child(parent, name, false, Purpose::Manifest, end, stop)?;
        self.inspect_protected(slot, FileType::RegularFile, None, end, stop)?;
        let size = u64::try_from(self.identity(slot)?.size).map_err(|_| AdmissionFailure::Bounds)?;
        if size == 0 { return Err(AdmissionFailure::Manifest); }
        if hex(&self.read_original(slot, Some(size), MANIFEST_LIMIT as u64, true, end, stop)?) != expected {
            return Err(AdmissionFailure::Manifest);
        }
        self.records[slot.0].digest = Some(expected.to_owned());
        self.inspect_protected(slot, FileType::RegularFile, Some(size), end, stop)?;
        Ok((slot, self.work.data.clone()))
    }
    pub(crate) fn payload(&mut self, parent: SlotId, name: &str, size: u64, mode: u32, expected: &str,
        end: Instant, stop: &watch::Receiver<bool>) -> AdmissionResult<SlotId> {
        let slot = self.acquire_child(parent, name, false, Purpose::Payload, end, stop)?;
        self.inspect_protected(slot, FileType::RegularFile, Some(size), end, stop)?;
        if self.identity(slot)?.mode & 0o7777 != mode
            || hex(&self.read_original(slot, Some(size), FILE_LIMIT, false, end, stop)?) != expected {
            return Err(AdmissionFailure::Manifest);
        }
        self.records[slot.0].digest = Some(expected.to_owned());
        self.inspect_protected(slot, FileType::RegularFile, Some(size), end, stop)?; Ok(slot)
    }
    pub(crate) fn entries(&mut self, slot: SlotId, end: Instant, stop: &watch::Receiver<bool>) -> AdmissionResult<Vec<ProtectedEntry>> {
        self.begin(Operation::Directory(slot), end, stop)?;
        let identity = self.identity(slot)?;
        let mut result = Vec::new(); let (mut dot, mut dotdot) = (false, false);
        {
            let mut entries = RawDir::new(fd_at(&self.records, slot)?, &mut self.work.directory_buffer[..]);
            loop {
                checkpoint(end, stop)?;
                let Some(entry) = entries.next() else { break; };
                let entry = entry.map_err(native_error)?;
                let name = entry.file_name().to_str().map_err(|_| AdmissionFailure::Inventory)?;
                let kind = entry.file_type(); let inode = entry.ino();
                if name == "." {
                    if dot || kind != FileType::Directory || inode != identity.inode { return Err(AdmissionFailure::Inventory); }
                    dot = true; continue;
                }
                if name == ".." {
                    if dotdot || kind != FileType::Directory || inode == 0 { return Err(AdmissionFailure::Inventory); }
                    dotdot = true; continue;
                }
                if self.entry_observations >= ENTRY_COUNT { return Err(AdmissionFailure::Bounds); }
                self.entry_observations += 1;
                if inode == 0 || !tool_component(name)
                    || !matches!(kind, FileType::Directory | FileType::RegularFile) { return Err(AdmissionFailure::Inventory); }
                result.push(ProtectedEntry { name: name.to_owned(), inode, kind });
            }
        }
        if !dot || !dotdot { return Err(AdmissionFailure::Inventory); }
        self.inspect_protected(slot, FileType::Directory, None, end, stop)?;
        self.operation = Operation::Idle; Ok(result)
    }
    fn named_original(&mut self, slot: SlotId, end: Instant, stop: &watch::Receiver<bool>) -> AdmissionResult<()> {
        let parent = self.records[slot.0].parent.clone();
        if let Some((parent, name)) = parent {
            self.begin(Operation::Metadata(slot), end, stop)?;
            let actual = fs::statat(fd_at(&self.records, parent)?, name.as_str(), fs::AtFlags::SYMLINK_NOFOLLOW).map_err(native_error)?;
            if Some(Identity::of(&actual)) != self.records[slot.0].identity { return Err(AdmissionFailure::IdentityChanged); }
        }
        self.operation = Operation::Idle; Ok(())
    }
    pub(crate) fn check_names(&mut self, end: Instant, stop: &watch::Receiver<bool>) -> AdmissionResult<()> {
        for index in 0..self.records.len() {
            if self.records[index].original.is_none() { continue; }
            let slot = SlotId(index);
            match self.records[index].purpose {
                Purpose::InitialUserNamespace => { self.inspect_namespace(slot, INITIAL_USER_INODE, end, stop)?; continue; }
                Purpose::InitialPidNamespace => { self.inspect_namespace(slot, INITIAL_PID_INODE, end, stop)?; continue; }
                Purpose::MountNamespace => { let inode = self.identity(slot)?.inode; self.inspect_namespace(slot, inode, end, stop)?; continue; }
                Purpose::Alias => { self.alias_snapshot(slot, end, stop)?; }
                _ => {
                    let identity = self.identity(slot)?;
                    let kind = FileType::from_raw_mode(identity.mode);
                    let size = if kind == FileType::RegularFile { Some(u64::try_from(identity.size).map_err(|_| AdmissionFailure::Bounds)?) } else { None };
                    self.inspect_protected(slot, kind, size, end, stop)?;
                }
            }
            self.named_original(slot, end, stop)?;
        }
        Ok(())
    }
    pub(crate) fn check_launch_thread(&mut self, end: Instant, stop: &watch::Receiver<bool>) -> AdmissionResult<()> {
        self.inspect_kernel(end, stop)?;
        let original = self.credentials.ok_or(AdmissionFailure::LedgerInvariant)?;
        let current = self.current_credentials(end, stop)?;
        if (current.uid, current.gid, current.pid) != (original.uid, original.gid, original.pid) {
            return Err(AdmissionFailure::Namespace);
        }
        self.inspect_namespace_controls(self.root.ok_or(AdmissionFailure::LedgerInvariant)?, current, end, stop)?;
        if self.current_credentials(end, stop)? != current { return Err(AdmissionFailure::Namespace); }
        Ok(())
    }
    pub(crate) fn audit_once(&mut self, end: Instant) -> AdmissionResult<()> {
        if !self.ready() || self.audit_started { return Err(AdmissionFailure::AlreadyUsed); }
        self.audit_started = true; self.phase = Phase::Auditing;
        let stop = self.original_stop.clone().ok_or(AdmissionFailure::LedgerInvariant)?;
        self.check_launch_thread(end, &stop)?;
        self.check_names(end, &stop)?;
        for index in 0..self.records.len() {
            let Some(expected) = self.records[index].digest.clone() else { continue; };
            let slot = SlotId(index);
            let size = u64::try_from(self.identity(slot)?.size).map_err(|_| AdmissionFailure::Bounds)?;
            if hex(&self.read_original(slot, Some(size), FILE_LIMIT, false, end, &stop)?) != expected {
                return Err(AdmissionFailure::IdentityChanged);
            }
        }
        self.check_names(end, &stop)
    }
    fn alias_snapshot(&mut self, slot: SlotId, end: Instant, stop: &watch::Receiver<bool>) -> AdmissionResult<()> {
        let identity = self.snapshot(slot, end, stop)?;
        if FileType::from_raw_mode(identity.mode) != FileType::Symlink || identity.uid != 0 || identity.gid != 0
            || identity.links != 1 || identity.size <= 0 || identity.size > 512 { return Err(AdmissionFailure::Ownership); }
        // Linux symlink mode/ACLs do not confer target access. Never execute or
        // follow this descriptor; the exact canonical target is checked separately.
        let mounted = self.mounted_original(slot, identity, end, stop)?;
        if Some(mounted) != self.root_mount || !protected_mount(mounted) { return Err(AdmissionFailure::Mount); }
        Ok(())
    }
    pub(crate) fn alias(&mut self, parent: SlotId, name: &str, end: Instant, stop: &watch::Receiver<bool>) -> AdmissionResult<SlotId> {
        let slot = self.acquire_relative(parent, name, OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            beneath_same_mount(), Purpose::Alias, end, stop)?;
        self.alias_snapshot(slot, end, stop)?; Ok(slot)
    }
    pub(crate) fn check_alias(&mut self, slot: SlotId, target: &str, canonical: SlotId,
        end: Instant, stop: &watch::Receiver<bool>) -> AdmissionResult<()> {
        self.alias_snapshot(slot, end, stop)?;
        let destination = self.identity(canonical)?;
        if !matches!(FileType::from_raw_mode(destination.mode), FileType::Directory | FileType::RegularFile) {
            return Err(AdmissionFailure::Inventory);
        }
        self.begin(Operation::Read(slot), end, stop)?;
        let mut bytes = [0u8; 513];
        let length = fs::readlinkat_raw(fd_at(&self.records, slot)?, "", &mut bytes[..]).map_err(native_error)?;
        if length != target.len() || &bytes[..length] != target.as_bytes() { return Err(AdmissionFailure::IdentityChanged); }
        self.alias_snapshot(slot, end, stop)?;
        self.named_original(slot, end, stop)
    }
}
// Android distribution names have a wider, still closed ASCII alphabet than
// the portable runtime publisher. Only the Android book may use that alphabet.
fn tool_component(name: &str) -> bool {
    !name.is_empty() && name.len() <= 255 && name != "." && name != ".." && !name.ends_with('.')
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b"_+@.,=-".contains(&b))
}
impl InstalledRuntimeCustody {
    pub(crate) fn new_android(budget: Arc<AndroidDescriptorBudget>) -> Self {
        let mut runtime = Self::new(); runtime.book = OriginalDescriptorBook::new_android(budget); runtime.retain_android = true; runtime
    }
    pub(crate) fn retain_android_once(&mut self, end: Instant, stop: &watch::Receiver<bool>) -> AdmissionResult<()> {
        if !self.retain_android || self.book.phase != Phase::New || self.transferred { return Err(AdmissionFailure::AlreadyUsed); }
        self.book.phase = Phase::Inspecting; self.book.original_stop = Some(stop.clone());
        let result = self.inspect_inner(end, stop).and_then(|_| self.book.finish_retained());
        if let Err(failure) = result { self.book.refuse(failure); }
        result // Partials remain in this registered book until its original settlement worker.
    }
    pub(crate) fn android_data(&self) -> AdmissionResult<crate::runtime::VerifiedRuntime> {
        if !self.retain_android || !self.book.ready() || !self.retained_bindings_present() { return Err(AdmissionFailure::TransferUnavailable); }
        let anchor = MANIFEST_ANCHOR.filter(|value| sha(value)).ok_or(AdmissionFailure::MissingCompileAnchor)?;
        let cwd = std::path::PathBuf::from("/var/lib/mobile-release-kit/versions").join(TARGET).join(anchor);
        Ok(crate::runtime::VerifiedRuntime { python: cwd.join("python/bin/python3"), bootstrap: cwd.join("android_build_bootstrap.py"),
            core: cwd.join("core.zip"), cwd })
    }
    pub(crate) fn check_before_spawn(&mut self, end: Instant, stop: &watch::Receiver<bool>) -> AdmissionResult<()> {
        let _ = self.android_data()?;
        self.book.check_names(end, stop)?; self.book.check_launch_thread(end, stop)
    }
    pub(crate) fn check_after_use(&mut self, end: Instant) -> AdmissionResult<()> { self.book.audit_once(end) }
    pub(crate) fn settled(&self) -> bool { self.book.settled() }
}

// All helpers below are pure bounded data validation, NOT alternate admission,
// resource constructors, close receipts, installed paths or native test hooks.
pub(crate) fn sha(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(DIGITS[usize::from(byte >> 4)] as char);
        result.push(DIGITS[usize::from(byte & 15)] as char);
    }
    result
}

fn digest(bytes: &[u8]) -> String { hex(&Sha256::digest(bytes)) }

pub(crate) fn parse_inventory(bytes: &[u8], protocol_anchor: &str) -> AdmissionResult<Inventory> {
    if bytes.len() > MANIFEST_LIMIT || !sha(protocol_anchor) { return Err(AdmissionFailure::Manifest); }
    let manifest: Manifest = serde_json::from_value(strict_json(bytes).map_err(|_| AdmissionFailure::Manifest)?)
        .map_err(|_| AdmissionFailure::Manifest)?;
    validate_inventory(manifest, protocol_anchor)
}

fn validate_inventory(manifest: Manifest, protocol_anchor: &str) -> AdmissionResult<Inventory> {
    if manifest.schema_version != 1 || manifest.protocol != PROTOCOL || manifest.core_version != CORE_VERSION
        || manifest.target != TARGET || manifest.target != COMPILED_TARGET || manifest.protocol_sha256 != protocol_anchor
        || !sha(&manifest.core_sha256) || !sha(&manifest.inventory_sha256)
        || manifest.files.is_empty() || manifest.files.len() > FILE_COUNT {
        return Err(AdmissionFailure::Manifest);
    }
    let encoded_inventory = serde_json::to_vec(&manifest.files).map_err(|_| AdmissionFailure::Manifest)?;
    if encoded_inventory.len() > MANIFEST_LIMIT || digest(&encoded_inventory) != manifest.inventory_sha256 {
        return Err(AdmissionFailure::Manifest);
    }
    let mut names = BTreeSet::new();
    let mut directories = BTreeSet::new();
    let mut previous: Option<&str> = None;
    let mut total = 0u64;
    for file in &manifest.files {
        if !safe_payload_path(&file.path) || file.path == "manifest.json" || !sha(&file.sha256)
            || file.size > FILE_LIMIT
            || file.path == "github-ca.pem" && (file.size == 0 || file.size > GITHUB_CA_LIMIT)
            || previous.is_some_and(|name| name >= file.path.as_str())
            || !names.insert(file.path.clone()) {
            return Err(AdmissionFailure::Manifest);
        }
        total = total.checked_add(file.size).ok_or(AdmissionFailure::Bounds)?;
        if total > TOTAL_LIMIT { return Err(AdmissionFailure::Bounds); }
        if file.path == "core.zip" && file.sha256 != manifest.core_sha256 { return Err(AdmissionFailure::Manifest); }
        previous = Some(&file.path);
        let mut relative = file.path.as_str();
        while let Some((parent, _)) = relative.rsplit_once('/') {
            directories.insert(parent.to_owned());
            if directories.len() + manifest.files.len() + 1 > ENTRY_COUNT { return Err(AdmissionFailure::Bounds); }
            relative = parent;
        }
    }
    for required in REQUIRED_RUNTIME_RESOURCES {
        if !names.contains(required) { return Err(AdmissionFailure::Manifest); }
    }
    let mut folded = BTreeSet::new();
    folded.insert("manifest.json".to_owned());
    for name in names.iter().chain(directories.iter()) {
        // Reject directory/file conflicts AND case aliases at ANY inventory
        // level, not just case-folded final payload leaves.
        if !folded.insert(name.to_ascii_lowercase()) { return Err(AdmissionFailure::Manifest); }
    }
    Ok(Inventory { files: manifest.files, directories })
}

pub(crate) fn supported_kernel(sysname: &[u8], machine: &[u8], release: &[u8]) -> bool {
    if sysname != b"Linux" || machine != b"x86_64" { return false; }
    // Exactly one source-reviewed Azure ABI, plus the existing GA 6.8 rule.
    // This name check is NOT boot provenance or runtime qualification. All
    // native observations and consumer gates remain independently required.
    if release == b"6.17.0-1022-azure" { return true; }
    let Some(abi) = release.strip_prefix(b"6.8.0-").and_then(|value| value.strip_suffix(b"-generic")) else { return false; };
    !abi.is_empty() && abi.len() <= 10 && abi[0] != b'0' && abi.iter().all(u8::is_ascii_digit)
}

fn numeric<const N: usize>(value: &str) -> AdmissionResult<[u64; N]> {
    let mut result = [0; N];
    let mut fields = value.split_ascii_whitespace();
    for destination in &mut result {
        let field = fields.next().ok_or(AdmissionFailure::Namespace)?;
        if field.is_empty() || !field.bytes().all(|byte| byte.is_ascii_digit()) { return Err(AdmissionFailure::Namespace); }
        *destination = field.parse().map_err(|_| AdmissionFailure::Namespace)?;
    }
    if fields.next().is_some() { return Err(AdmissionFailure::Namespace); }
    Ok(result)
}

pub(crate) fn initial_id_map(bytes: &[u8]) -> AdmissionResult<()> {
    if bytes.len() > MAP_LIMIT { return Err(AdmissionFailure::Bounds); }
    let text = std::str::from_utf8(bytes).map_err(|_| AdmissionFailure::Namespace)?;
    if numeric::<3>(text)? != [0, 0, 4_294_967_295] { return Err(AdmissionFailure::Namespace); }
    Ok(())
}

fn single_field<T>(slot: &mut Option<T>, value: T) -> AdmissionResult<()> {
    if slot.is_some() { return Err(AdmissionFailure::Namespace); }
    *slot = Some(value);
    Ok(())
}

fn capability_value(value: &str) -> AdmissionResult<u64> {
    let value = value.trim_matches(|character: char| character.is_ascii_whitespace());
    if value.len() != 16 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) { return Err(AdmissionFailure::Namespace); }
    u64::from_str_radix(value, 16).map_err(|_| AdmissionFailure::Namespace)
}

fn inspect_status(bytes: &[u8], actual: Credentials) -> AdmissionResult<()> {
    if bytes.len() > STATUS_LIMIT { return Err(AdmissionFailure::Bounds); }
    let text = std::str::from_utf8(bytes).map_err(|_| AdmissionFailure::Namespace)?;
    if text.contains('\0') || !text.ends_with('\n') { return Err(AdmissionFailure::Namespace); }
    let (mut uid, mut gid, mut pid, mut tgid, mut nspid, mut nstgid) = (None, None, None, None, None, None);
    let (mut effective, mut permitted, mut inheritable, mut ambient) = (None, None, None, None);
    for line in text.lines() {
        let (key, value) = line.split_once(':').ok_or(AdmissionFailure::Namespace)?;
        match key {
            "Uid" => single_field(&mut uid, numeric::<4>(value)?)?,
            "Gid" => single_field(&mut gid, numeric::<4>(value)?)?,
            "Pid" => single_field(&mut pid, numeric::<1>(value)?[0])?,
            "Tgid" => single_field(&mut tgid, numeric::<1>(value)?[0])?,
            "NSpid" => single_field(&mut nspid, numeric::<1>(value)?[0])?,
            "NStgid" => single_field(&mut nstgid, numeric::<1>(value)?[0])?,
            "CapEff" => single_field(&mut effective, capability_value(value)?)?,
            "CapPrm" => single_field(&mut permitted, capability_value(value)?)?,
            "CapInh" => single_field(&mut inheritable, capability_value(value)?)?,
            "CapAmb" => single_field(&mut ambient, capability_value(value)?)?,
            // The inherited bounding SET may be nonzero in an ordinary process;
            // it is not an actually effective/permitted/inheritable capability.
            "CapBnd" => { capability_value(value)?; }
            _ => {}
        }
    }
    if uid != Some([u64::from(actual.uid); 4]) || gid != Some([u64::from(actual.gid); 4])
        || pid != Some(u64::from(actual.tid)) || tgid != Some(u64::from(actual.pid))
        || nspid != pid || nstgid != tgid
        || effective != Some(0) || permitted != Some(0) || inheritable != Some(0) || ambient != Some(0) {
        return Err(AdmissionFailure::Namespace);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RootMount { pub(crate) old_id: u32, pub(crate) device: (u32, u32), pub(crate) magic: u64 }

fn mount_number(value: &str) -> AdmissionResult<u32> {
    let number = numeric::<1>(value)?[0];
    u32::try_from(number).map_err(|_| AdmissionFailure::Namespace)
}

// Validate kernel mountinfo's ONLY four escaped path characters. In particular
// '\057' cannot conceal an alternative spelling of '/'. Never unescape and
// then treat an ambiguous/relative name as evidence of the original root.
fn mount_path(path: &str) -> bool {
    if !path.starts_with('/') { return false; }
    let bytes = path.as_bytes();
    let mut position = 0;
    while position < bytes.len() {
        match bytes[position] {
            b'\\' => {
                let Some(escape) = bytes.get(position + 1..position + 4) else { return false; };
                if !matches!(escape, b"040" | b"011" | b"012" | b"134") { return false; }
                position += 4;
            }
            byte if byte.is_ascii_control() || byte.is_ascii_whitespace() => return false,
            _ => position += 1,
        }
    }
    true
}

pub(crate) fn parse_root_mount(bytes: &[u8]) -> AdmissionResult<RootMount> {
    if bytes.len() > MOUNTINFO_LIMIT { return Err(AdmissionFailure::Bounds); }
    let text = std::str::from_utf8(bytes).map_err(|_| AdmissionFailure::Namespace)?;
    if text.contains('\0') || !text.ends_with('\n') { return Err(AdmissionFailure::Namespace); }
    let mut root = None;
    let mut ids = BTreeSet::new();
    for (index, line) in text.lines().enumerate() {
        if index >= ENTRY_COUNT { return Err(AdmissionFailure::Bounds); }
        if line.is_empty() || line.bytes().any(|byte| byte.is_ascii_control()) { return Err(AdmissionFailure::Namespace); }
        let fields: Vec<&str> = line.split(' ').collect();
        if fields.iter().any(|field| field.is_empty()) { return Err(AdmissionFailure::Namespace); }
        let separator = fields.iter().position(|field| *field == "-").ok_or(AdmissionFailure::Namespace)?;
        if separator < 6 || fields.len() != separator + 4 { return Err(AdmissionFailure::Namespace); }
        let id = mount_number(fields[0])?;
        let parent = mount_number(fields[1])?;
        let (major, minor) = fields[2].split_once(':').ok_or(AdmissionFailure::Namespace)?;
        let device = (mount_number(major)?, mount_number(minor)?);
        if id == 0 || parent == 0 || !ids.insert(id) || !mount_path(fields[3]) || !mount_path(fields[4]) {
            return Err(AdmissionFailure::Namespace);
        }
        let mut optional_tags = 0u8;
        for field in &fields[6..separator] {
            let (tag, number) = match field.split_once(':') {
                Some((tag, number)) => (tag, Some(mount_number(number)?)),
                None => (*field, None),
            };
            let bit = match (tag, number) {
                ("shared", Some(number)) if number != 0 => 1,
                ("master", Some(number)) if number != 0 => 2,
                ("propagate_from", Some(number)) if number != 0 => 4,
                ("unbindable", None) => 8,
                _ => return Err(AdmissionFailure::Namespace),
            };
            if optional_tags & bit != 0 { return Err(AdmissionFailure::Namespace); }
            optional_tags |= bit;
        }
        // mountinfo's first per-mount option is exactly ro or rw. No option
        // string (including an absent IDMAP marker) replaces real statmount.
        if !matches!(fields[5].split(',').next(), Some("ro" | "rw")) {
            return Err(AdmissionFailure::Namespace);
        }
        if fields[4] != "/" { continue; }
        if fields[3] != "/" || root.is_some() { return Err(AdmissionFailure::Namespace); }
        let magic = match fields[separator + 1] {
            "ext4" => mount::EXT4_MAGIC, "xfs" => mount::XFS_MAGIC,
            _ => return Err(AdmissionFailure::Mount),
        };
        root = Some(RootMount { old_id: id, device, magic });
    }
    root.ok_or(AdmissionFailure::Namespace)
}

fn release_value(value: &str) -> AdmissionResult<&str> {
    if value.starts_with('"') || value.starts_with('\'') {
        let quote = value.as_bytes()[0] as char;
        if value.len() < 2 || !value.ends_with(quote) { return Err(AdmissionFailure::UnsupportedPlatform); }
        let inner = &value[1..value.len() - 1];
        if inner.chars().any(|character| matches!(character, '"' | '\'' | '\\')) { return Err(AdmissionFailure::UnsupportedPlatform); }
        Ok(inner)
    } else if value.is_empty() || value.chars().any(|character| character.is_whitespace() || matches!(character, '"' | '\'' | '\\')) {
        Err(AdmissionFailure::UnsupportedPlatform)
    } else { Ok(value) }
}

pub(crate) fn ubuntu_2404(bytes: &[u8]) -> AdmissionResult<()> {
    if bytes.len() > OS_RELEASE_LIMIT { return Err(AdmissionFailure::Bounds); }
    let text = std::str::from_utf8(bytes).map_err(|_| AdmissionFailure::UnsupportedPlatform)?;
    if text.contains('\0') { return Err(AdmissionFailure::UnsupportedPlatform); }
    let mut keys = BTreeSet::new();
    let (mut id, mut version) = (None, None);
    for (index, line) in text.lines().enumerate() {
        if index >= 1024 { return Err(AdmissionFailure::Bounds); }
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') { continue; }
        let (key, value) = line.split_once('=').ok_or(AdmissionFailure::UnsupportedPlatform)?;
        if key.is_empty() || !key.bytes().all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
            || !keys.insert(key) { return Err(AdmissionFailure::UnsupportedPlatform); }
        match key {
            "ID" => id = Some(release_value(value)?),
            "VERSION_ID" => version = Some(release_value(value)?),
            _ => {}
        }
    }
    if id != Some("ubuntu") || version != Some("24.04") { return Err(AdmissionFailure::UnsupportedPlatform); }
    Ok(())
}

#[cfg(test)]
mod pure_tests {
    use super::*;

    // This entire roster is DATA/memory-only. No installed-object observation,
    // native descriptor, proc read, runtime, process, fixture installer or
    // executable capability is used or fabricated. Empty/pending books below
    // cannot make a syscall even when testing original-settlement refusal.
    #[test]
    fn digest_and_component_policy_are_exact() {
        assert!(sha(&"a".repeat(64)));
        assert!(!sha(&"A".repeat(64)));
        assert!(!sha(&"g".repeat(64)));
        assert!(!sha(&"a".repeat(63)));
        assert_eq!(digest(b""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        for name in ["opt", TARGET, "manifest.json", "123"] { assert!(single_component(name)); }
        for name in ["", ".", "..", "a/b", "a\\b", "CON", "bad."] { assert!(!single_component(name)); }
    }

    fn ordinary_file() -> Identity {
        Identity { device: 1, inode: 2, mode: FileType::RegularFile.as_raw_mode() | 0o644,
            uid: 0, gid: 0, links: 1, size: 10, mtime: 1, mtime_nsec: 2, ctime: 3, ctime_nsec: 4 }
    }

    #[test]
    fn protected_metadata_refuses_mutability_aliases_and_special_files() {
        let base = ordinary_file();
        assert!(protected_identity(base, FileType::RegularFile, Some(10)));
        assert!(!protected_identity(base, FileType::RegularFile, Some(11)));
        for bit in [0o020, 0o002, 0o4000, 0o2000, 0o1000] {
            assert!(!protected_identity(Identity { mode: base.mode | bit, ..base }, FileType::RegularFile, Some(10)));
        }
        assert!(!protected_identity(Identity { uid: 1000, ..base }, FileType::RegularFile, None));
        assert!(!protected_identity(Identity { gid: 1000, ..base }, FileType::RegularFile, None));
        assert!(!protected_identity(Identity { links: 2, ..base }, FileType::RegularFile, None));
        assert!(!protected_identity(Identity { size: -1, ..base }, FileType::RegularFile, None));
        for kind in [FileType::Symlink, FileType::Fifo, FileType::Socket, FileType::CharacterDevice, FileType::BlockDevice] {
            assert!(!protected_identity(Identity { mode: kind.as_raw_mode() | 0o644, ..base }, FileType::RegularFile, None));
        }
    }

    #[test]
    fn mount_attributes_reject_idmap_unknown_and_conflicting_atime() {
        assert!(known_mount_attributes(0));
        assert!(known_mount_attributes(mount::NO_ATIME));
        assert!(known_mount_attributes(mount::STRICT_ATIME));
        assert!(!known_mount_attributes(mount::ID_MAPPED));
        assert!(!known_mount_attributes(mount::NO_ATIME | mount::STRICT_ATIME));
        assert!(!known_mount_attributes(1u64 << 63));
    }

    #[test]
    fn kernel_scope_is_reviewed_ubuntu() {
        assert!(supported_kernel(b"Linux", b"x86_64", b"6.8.0-91-generic"));
        assert!(supported_kernel(b"Linux", b"x86_64", b"6.17.0-1022-azure"));
        for release in [b"6.8.0-generic".as_slice(), b"6.8.0-0-generic", b"6.8.0-91-lowlatency",
            b"6.8.0-91-generic-custom", b"6.11.0-29-generic", b"6.8.0-+91-generic",
            b"6.17.0-1021-azure", b"6.17.0-1023-azure", b"6.17.0-1022-generic",
            b"6.17.0-1022-azure-custom", b"6.17.0-01022-azure"] {
            assert!(!supported_kernel(b"Linux", b"x86_64", release));
        }
        assert!(!supported_kernel(b"Linux", b"aarch64", b"6.8.0-91-generic"));
        assert!(!supported_kernel(b"FreeBSD", b"x86_64", b"6.8.0-91-generic"));
        assert!(!supported_kernel(b"Linux", b"aarch64", b"6.17.0-1022-azure"));
        assert!(!supported_kernel(b"FreeBSD", b"x86_64", b"6.17.0-1022-azure"));
    }

    #[test]
    fn initial_maps_require_one_full_initial_mapping() {
        assert_eq!(initial_id_map(b"         0          0 4294967295\n"), Ok(()));
        for value in [b"0 1000 1\n".as_slice(), b"0 0 4294967294\n", b"0 0 4294967295\n1 1 1\n", b"+0 0 4294967295\n"] {
            assert!(initial_id_map(value).is_err());
        }
    }

    fn status_bytes() -> &'static str {
        "Name:\tinspection-test\nTgid:\t123\nPid:\t124\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\nNStgid:\t123\nNSpid:\t124\nCapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapBnd:\t000001ffffffffff\nCapAmb:\t0000000000000000\n"
    }

    #[test]
    fn status_requires_actual_thread_saved_ids_and_zero_caps() {
        let actual = Credentials { uid: 1000, gid: 1000, pid: 123, tid: 124 };
        assert_eq!(inspect_status(status_bytes().as_bytes(), actual), Ok(()));
        for changed in [
            status_bytes().replace("1000\t1000\t1000\t1000", "1000\t1000\t0\t1000"),
            status_bytes().replace("NSpid:\t124", "NSpid:\t124\t2"),
            status_bytes().replace("Pid:\t124", "Pid:\t125"),
            status_bytes().replace("CapEff:\t0000000000000000", "CapEff:\t0000000000000001"),
            status_bytes().replace("CapAmb:\t0000000000000000", "CapAmb:\t0000000000000001"),
            format!("{}Uid:\t1000\t1000\t1000\t1000\n", status_bytes()),
        ] { assert!(inspect_status(changed.as_bytes(), actual).is_err()); }
    }

    #[test]
    fn mountinfo_requires_one_unambiguous_full_root() {
        let text = "29 1 8:2 / / rw,relatime shared:1 - ext4 /dev/sda2 rw\n30 29 0:22 / /proc rw,nosuid,nodev,noexec - proc proc rw\n";
        let expected = RootMount { old_id: 29, device: (8, 2), magic: mount::EXT4_MAGIC };
        assert_eq!(parse_root_mount(text.as_bytes()), Ok(expected));
        assert_ne!(parse_root_mount(text.replace("29 1", "31 1").as_bytes()), Ok(expected));
        for changed in [
            text.replace("8:2 / /", "8:2 /subroot /"),
            text.replace("8:2 / /", "8:2 / \\057"),
            text.replace("shared:1", "unrecognized:1"),
            text.replace("shared:1", "shared:1 shared:2"),
            text.replace(" - ext4 ", " - overlay "),
            text.replace("29 1", "29\t1"),
            format!("{text}31 1 8:2 / / rw - ext4 /dev/sda2 rw\n"),
        ] { assert!(parse_root_mount(changed.as_bytes()).is_err()); }
    }

    #[test]
    fn os_identity_requires_exact_distribution_and_version() {
        assert_eq!(ubuntu_2404(b"NAME=Ubuntu\nID=ubuntu\nVERSION_ID=\"24.04\"\n"), Ok(()));
        for value in [b"ID=ubuntu\nVERSION_ID=22.04\n".as_slice(), b"ID=debian\nVERSION_ID=24.04\n",
            b"ID=ubuntu\nID=ubuntu\nVERSION_ID=24.04\n", b"ID=ubuntu\nVERSION_ID=\"24.04\n",
            b"ID=ubuntu\nVERSION_ID=\"24\\.04\"\n"] {
            assert!(ubuntu_2404(value).is_err());
        }
    }

    fn inventory_fixture() -> Manifest {
        let files = REQUIRED_RUNTIME_RESOURCES
            .into_iter().map(|path| PayloadFile { path: path.to_owned(), sha256: "a".repeat(64), size: 1 }).collect();
        let mut result = Manifest { schema_version: 1, protocol: PROTOCOL, core_version: CORE_VERSION.to_owned(),
            target: TARGET.to_owned(), core_sha256: "a".repeat(64), protocol_sha256: "b".repeat(64),
            inventory_sha256: String::new(), files };
        rehash_inventory(&mut result);
        result
    }

    fn rehash_inventory(manifest: &mut Manifest) {
        match serde_json::to_vec(&manifest.files) {
            Ok(bytes) => manifest.inventory_sha256 = digest(&bytes),
            Err(_) => panic!("pure inventory fixture could not be encoded"),
        }
    }

    #[test]
    fn inventory_requires_roster_order_digest_and_no_case_or_tree_aliases() {
        let protocol = "b".repeat(64);
        assert!(validate_inventory(inventory_fixture(), &protocol).is_ok());
        for required in REQUIRED_RUNTIME_RESOURCES {
            let mut missing = inventory_fixture();
            missing.files.retain(|file| file.path != required);
            rehash_inventory(&mut missing);
            assert!(validate_inventory(missing, &protocol).is_err(), "{required}");
        }
        for (size, accepted) in [(0, false), (GITHUB_CA_LIMIT, true), (GITHUB_CA_LIMIT + 1, false)] {
            let mut ca_bound = inventory_fixture();
            let Some(ca) = ca_bound.files.iter_mut().find(|file| file.path == "github-ca.pem") else {
                panic!("pure inventory fixture omitted the fixed CA");
            };
            ca.size = size;
            rehash_inventory(&mut ca_bound);
            assert_eq!(validate_inventory(ca_bound, &protocol).is_ok(), accepted);
        }
        let mut reordered = inventory_fixture();
        reordered.files.swap(0, 1);
        rehash_inventory(&mut reordered);
        assert!(validate_inventory(reordered, &protocol).is_err());
        let mut bad_core = inventory_fixture();
        bad_core.core_sha256 = "c".repeat(64);
        assert!(validate_inventory(bad_core, &protocol).is_err());
        let mut bad_digest = inventory_fixture();
        bad_digest.inventory_sha256 = "c".repeat(64);
        assert!(validate_inventory(bad_digest, &protocol).is_err());
        for extra in ["PYTHON/data", "python", "MANIFEST.JSON", "../outside"] {
            let mut aliased = inventory_fixture();
            aliased.files.push(PayloadFile { path: extra.to_owned(), sha256: "a".repeat(64), size: 1 });
            aliased.files.sort_by(|a, b| a.path.cmp(&b.path));
            rehash_inventory(&mut aliased);
            assert!(validate_inventory(aliased, &protocol).is_err());
        }
        let mut too_large = inventory_fixture();
        too_large.files[0].size = FILE_LIMIT + 1;
        rehash_inventory(&mut too_large);
        assert!(validate_inventory(too_large, &protocol).is_err());
    }

    #[test]
    fn android_budget_precharges_controls_and_tracks_original_cutoff() {
        let start = Instant::now(); let work = start + std::time::Duration::from_secs(3000);
        let (cutoff, receiver) = watch::channel(work);
        let budget = AndroidDescriptorBudget::new(receiver);
        assert_eq!(budget.live.load(Ordering::SeqCst), 128);
        for _ in 128..4096 { assert_eq!(budget.claim(), Ok(())); }
        assert_eq!(budget.claim(), Err(AdmissionFailure::Bounds));
        assert_eq!(budget.live.load(Ordering::SeqCst), 4096);
        budget.release(); assert_eq!(budget.claim(), Ok(()));
        assert_eq!(budget.audit_end(work), Ok(work));
        let earlier = start + std::time::Duration::from_secs(11);
        cutoff.send_replace(earlier); // The SAME receiver sees a newly earlier F+10.
        assert_eq!(budget.audit_end(work), Ok(earlier));
        assert_eq!(budget.audit_end(start), Ok(start)); // Never renew a supplied earlier bound.
        drop(cutoff); assert_eq!(budget.audit_end(work), Err(AdmissionFailure::Interrupted));
    }

    #[test]
    fn empty_android_book_is_not_runtime_authority_and_refusal_preserves_unknown() {
        let (_cutoff, receiver) = watch::channel(Instant::now());
        let mut runtime = InstalledRuntimeCustody::new_android(Arc::new(AndroidDescriptorBudget::new(receiver)));
        assert!(runtime.android_data().is_err() && InstalledRuntimeCustody::new().android_data().is_err());
        assert!(!runtime.book.ready() && !runtime.settled());
        assert_eq!(runtime.observation().records(), 0);
        runtime.mark_interrupted(); runtime.book.refuse(AdmissionFailure::Manifest);
        assert_eq!(runtime.observation().phase(), "unknown");
        assert_eq!(runtime.observation().failure(), Some(AdmissionFailure::Interrupted));
        assert!(runtime.android_data().is_err() && !runtime.transfer_ready());
        assert_eq!(runtime.observation().live_originals(), 0);
    }

    #[test]
    fn unreturned_android_acquisition_remains_unknown_charged_and_not_retried() {
        let (_cutoff, receiver) = watch::channel(Instant::now());
        let budget = Arc::new(AndroidDescriptorBudget::new(receiver));
        let mut book = OriginalDescriptorBook::new_android(budget.clone());
        // Actual pre-effect registration only: intentionally NO open/receive,
        // no fake FD, no positive close and no OS effect to retry.
        let slot = book.arm(Purpose::Payload).unwrap();
        assert_eq!(book.observation().pending_acquisitions(), 1);
        assert_eq!(budget.live.load(Ordering::SeqCst), 129);
        for _ in 0..2 {
            assert_eq!(book.settle_originals(), CloseOutcome::Unknown);
            assert_eq!(book.records[slot.0].acquisition, Acquisition::Attempted);
            assert_eq!(book.records[slot.0].close, CloseReceipt::Unattempted);
            assert!(book.records[slot.0].charged && book.records[slot.0].original.is_none());
            assert_eq!(budget.live.load(Ordering::SeqCst), 129);
        }
        assert!(!book.ready() && !book.settled());
    }

    #[test]
    fn uninspected_or_occupied_transfer_keeps_original_slots() {
        // Pure new() allocates a book with ZERO native acquisitions. These are
        // rejection tests only; no fake FD or synthetic inspected capability.
        let mut source = Some(InstalledRuntimeCustody::new());
        let mut destination = None;
        assert!(matches!(transfer_original(&mut source, &mut destination), Err(AdmissionFailure::TransferUnavailable)));
        assert!(source.is_some() && destination.is_none());
        destination = Some(InstalledRuntimeCustody::new());
        assert!(matches!(transfer_original(&mut source, &mut destination), Err(AdmissionFailure::DestinationOccupied)));
        assert!(source.is_some() && destination.is_some());
        if let Some(original) = source.as_mut() {
            original.mark_interrupted();
            assert_eq!(original.observation().phase(), "unknown");
            assert_eq!(original.observation().live_originals(), 0);
            assert!(original.book.settlement_started && original.book.interrupted && !original.transfer_ready());
        } else { panic!("rejected transfer consumed its original source"); }
    }

    #[test]
    fn empty_passive_slots_cannot_transfer_or_expose_a_capability() {
        // No release profile is fabricated. These are the actual empty slots,
        // with no inspection/open/FD/child; even their empty settlement cannot
        // create execution authority or witness a native close.
        let mut slots = PassiveRuntimeSlots::new();
        let original = slots.inspection.as_ref().map(std::ptr::from_ref);
        assert!(slots.never_started() && !slots.settled());
        assert!(matches!(slots.transfer_once(), Err(AdmissionFailure::TransferUnavailable)));
        assert!(slots.capability().is_err());
        assert_eq!(slots.inspection.as_ref().map(std::ptr::from_ref), original);
        assert!(slots.acquisition.is_none() && slots.profile.is_none() && slots.selection.is_none());
        assert_eq!(slots.inspection.as_ref().unwrap().observation().records(), 0);
        assert_eq!(slots.settle_originals(), CloseOutcome::Settled); // ZERO originals: no close syscall.
        assert!(!slots.never_started() && slots.settled() && slots.capability().is_err());
        assert!(matches!(slots.transfer_once(), Err(AdmissionFailure::TransferUnavailable)));
        assert_eq!(slots.inspection.as_ref().map(std::ptr::from_ref), original);
        assert_eq!(slots.settle_originals(), CloseOutcome::Unknown); // No second settlement worker/attempt.
    }

    #[test]
    fn interrupted_empty_passive_slots_preserve_the_original_and_unknown() {
        let mut slots = PassiveRuntimeSlots::new();
        let original = slots.inspection.as_ref().map(std::ptr::from_ref);
        slots.mark_interrupted(); // Negative zero-resource state only, not a synthetic positive worker return.
        assert!(!slots.never_started() && !slots.settled());
        assert!(matches!(slots.transfer_once(), Err(AdmissionFailure::TransferUnavailable)));
        assert!(slots.capability().is_err());
        assert_eq!(slots.settle_originals(), CloseOutcome::Unknown);
        assert!(!slots.settled());
        assert_eq!(slots.inspection.as_ref().map(std::ptr::from_ref), original);
        let observed = slots.inspection.as_ref().unwrap().observation();
        assert_eq!(observed.phase(), "unknown");
        assert_eq!(observed.records(), 0);
        assert_eq!(observed.live_originals(), 0);
        assert_eq!(observed.positive_closes(), 0);
        assert!(slots.acquisition.is_none());
    }
    #[test]
    fn passive_preparation_refuses_uninspected_settled_and_interrupted_originals() {
        // Actual empty storage only: no manufactured profile, transfer or FD.
        let mut original = InstalledRuntimeCustody::new();
        assert_eq!(original.start_passive_preparation(), Err(AdmissionFailure::TransferUnavailable));
        assert_eq!(original.observation().phase(), "new");
        assert_eq!(original.settle_originals(), CloseOutcome::Settled); // No close syscall.
        assert_eq!(original.start_passive_preparation(), Err(AdmissionFailure::TransferUnavailable));
        assert_eq!(original.observation().phase(), "settled");
        let mut interrupted = InstalledRuntimeCustody::new();
        interrupted.mark_interrupted();
        assert_eq!(interrupted.start_passive_preparation(), Err(AdmissionFailure::TransferUnavailable));
        assert_eq!(interrupted.settle_originals(), CloseOutcome::Unknown);
        for original in [&original, &interrupted] {
            assert_eq!(original.observation().records(), 0);
            assert_eq!(original.observation().positive_closes(), 0);
            assert!(!original.inspected_originals_ready());
        }
    }
    #[test]
    fn unreturned_passive_preparation_cannot_become_positive_settlement() {
        let mut book = OriginalDescriptorBook::new();
        // Negative pending bookkeeping ONLY, not a successful native return or
        // executable capability. An unfinished preparation is absorbing Unknown.
        book.phase = Phase::PassivePreparing;
        assert_eq!(book.settle_originals(), CloseOutcome::Unknown);
        book.refuse(AdmissionFailure::Stopped);
        assert_eq!(book.observation().phase(), "unknown");
        assert_eq!(book.observation().failure(), Some(AdmissionFailure::Interrupted));
        assert!(book.interrupted && book.unknown && book.settlement_started);
        assert_eq!(book.observation().records(), 0);
        assert_eq!(book.observation().positive_closes(), 0);
    }
}

// Read-only platform observations, not a qualified runtime or a test bypass of
// the consumer gates. Hosted execution is separately reviewed and explicitly
// selected; the existing pure and publisher-helper rosters do not include it.
#[cfg(test)]
mod platform_native_tests {
    use super::*;

    #[test]
    #[ignore = "reviewed disposable Ubuntu nonroot platform observation only"]
    fn nonroot_exact_ubuntu_platform() {
        assert!(matches!(std::env::var("MRK_UBUNTU_PUBLICATION_NATIVE").as_deref(), Ok("1")));
        assert!(matches!(std::env::var("GITHUB_ACTIONS").as_deref(), Ok("true")));
        assert!(matches!(std::env::var("RUNNER_ENVIRONMENT").as_deref(), Ok("github-hosted")));
        assert_ne!(rustix::process::getuid().as_raw(), 0);
        assert_ne!(rustix::process::getgid().as_raw(), 0);

        let (_sender, stop) = watch::channel(false);
        let end = Instant::now() + std::time::Duration::from_secs(20);
        let mut book = OriginalDescriptorBook::new();
        book.phase = Phase::Inspecting;
        let mut phase = "kernel";
        let result = (|| -> AdmissionResult<()> {
            book.inspect_kernel(end, &stop)?;
            phase = "credentials";
            let credentials = book.current_credentials(end, &stop)?;
            book.credentials = Some(credentials);
            phase = "protected-root";
            let root = book.acquire_root(end, &stop)?;
            book.root_mount = Some(book.inspect_protected(root, FileType::Directory, None, end, &stop)?);
            phase = "namespace-controls";
            book.inspect_namespace_controls(root, credentials, end, &stop)?;
            phase = "os-release";
            book.inspect_os_release(root, end, &stop)?;
            phase = "protected-var";
            let var = book.acquire_child(root, "var", true, Purpose::OsDirectory, end, &stop)?;
            book.inspect_protected(var, FileType::Directory, None, end, &stop)?;
            phase = "protected-var-lib";
            let lib = book.acquire_child(var, "lib", true, Purpose::OsDirectory, end, &stop)?;
            book.inspect_protected(lib, FileType::Directory, None, end, &stop)?;
            book.inspect_protected(var, FileType::Directory, None, end, &stop)?;
            book.inspect_protected(root, FileType::Directory, None, end, &stop)?;
            phase = "credential-recheck";
            if book.current_credentials(end, &stop)? != credentials { return Err(AdmissionFailure::Namespace); }
            checkpoint(end, &stop)
        })();
        match result {
            Ok(()) => {
                // This is the actual normal body return, not an interrupted
                // Inspecting state. Never clear a preexisting unknown latch.
                if !book.unknown {
                    book.operation = Operation::Idle;
                    book.phase = Phase::InspectedOnly;
                }
                let _ = book.settle_originals();
            }
            Err(failure) => { let _ = book.refuse_and_settle(failure); }
        }
        let observed = book.observation();
        assert_eq!(result, Ok(()), "nonroot platform phase: {phase}; settlement: {observed:?}");
        assert_eq!(observed.phase(), "settled", "nonroot platform original settlement");
        assert_eq!((observed.live_originals(), observed.pending_acquisitions(), observed.uncertain_closes()), (0, 0, 0));
        assert!(observed.records() > 0 && observed.positive_closes() > 0);
    }
}
