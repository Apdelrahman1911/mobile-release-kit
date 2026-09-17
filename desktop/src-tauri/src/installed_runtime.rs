//! Original-descriptor inspection of the one protected Linux installation.
//!
//! This is NOT executable runtime qualification. In particular, a compiled
//! manifest, equal hashes, and retained descriptors cannot prove the external
//! fresh-inode installer / immutable published-version / interpreter-loader
//! contracts. Both existing production launch refusals remain necessary.
//!
//! Future integration must register this actual book in the original owner's
//! Resources BEFORE retained blocking inspection starts. It must observe that
//! original worker's join and serialize the existing STOP/deadline admission
//! race before transferring the book. Neither a receipt nor two Option slots
//! prove that registration. Worker replies carry bounded observations only.
#![cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
#![forbid(unsafe_code)]

use std::{
    collections::BTreeSet,
    mem::{ManuallyDrop, MaybeUninit},
    os::fd::{AsFd, BorrowedFd, OwnedFd},
    time::Instant,
};
use mrk_linux_mount_observation as mount;
use rustix::{fs::{self, FileType, Mode, OFlags, RawDir, ResolveFlags, Stat}, io::Errno};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::watch;
use crate::{protocol::{strict_json, PROTOCOL}, runtime::{safe_payload_path, COMPILED_TARGET, CORE_VERSION}};

const TARGET: &str = "x86_64-unknown-linux-gnu";
const MANIFEST_ANCHOR: Option<&str> = option_env!("MRK_BUNDLED_RUNTIME_MANIFEST_SHA256");
const PROTOCOL_ANCHOR: Option<&str> = option_env!("MRK_BUNDLED_PROTOCOL_SHA256");
const MANIFEST_LIMIT: usize = 1024 * 1024;
const MOUNTINFO_LIMIT: usize = 1024 * 1024;
const STATUS_LIMIT: usize = 64 * 1024;
const MAP_LIMIT: usize = 4096;
const OS_RELEASE_LIMIT: usize = 64 * 1024;
const FILE_LIMIT: u64 = 512 * 1024 * 1024;
const TOTAL_LIMIT: u64 = 1024 * 1024 * 1024;
const FILE_COUNT: usize = 2048;
const ENTRY_COUNT: usize = 8192;
const TREE_DEPTH: usize = 16;
const RECORD_COUNT: usize = ENTRY_COUNT + 64;
const LIVE_COUNT: usize = 48;
const BLOCK_SIZE: usize = 64 * 1024;
const PREFIX_COUNT: usize = 6;
const RETAINED_COUNT: usize = PREFIX_COUNT + 2;
// Initial namespace inodes from include/linux/proc_ns.h at Linux v6.8.
// These are deliberately version-bound, not portable namespace detection.
const INITIAL_USER_INODE: u64 = 0xefff_fffd;
const INITIAL_PID_INODE: u64 = 0xefff_fffc;

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
enum Phase { New, Inspecting, InspectedOnly, Refused, Settling, Settled, Unknown }

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
            Phase::InspectedOnly => "inspectedOnly", Phase::Refused => "refused",
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
struct SlotId(usize);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Purpose {
    ProtectedAncestor(u8), ProcRoot, ProcDirectory, ProcControl,
    InitialUserNamespace, InitialPidNamespace, OsDirectory, OsIdentity,
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
struct Identity {
    device: u64, inode: u64, mode: u32, uid: u32, gid: u32, links: u64,
    size: i64, mtime: i64, mtime_nsec: u64, ctime: i64, ctime_nsec: u64,
}

impl Identity {
    fn of(stat: &Stat) -> Self {
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
struct PayloadFile { path: String, sha256: String, size: u64 }

struct Inventory { files: Vec<PayloadFile>, directories: BTreeSet<String> }

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
pub(crate) struct InstalledRuntimeCustody {
    phase: Phase,
    operation: Operation,
    interrupted_at: Option<Operation>,
    failure: Option<AdmissionFailure>,
    settlement_started: bool,
    interrupted: bool,
    unknown: bool,
    transferred: bool,
    records: Vec<FdRecord>,
    ancestors: [Option<SlotId>; PREFIX_COUNT],
    namespaces: [Option<SlotId>; 2],
    root_mount: Option<mount::MountObservation>,
    proc_mount: Option<mount::MountObservation>,
    credentials: Option<Credentials>,
    work: Work,
}

impl InstalledRuntimeCustody {
    /// Pure allocation/initialization only; acquires no OS resource.
    pub(crate) fn new() -> Self {
        Self {
            phase: Phase::New, operation: Operation::Idle, interrupted_at: None,
            failure: None, settlement_started: false, interrupted: false,
            unknown: false, transferred: false,
            records: Vec::with_capacity(RECORD_COUNT), ancestors: [None; PREFIX_COUNT],
            namespaces: [None; 2], root_mount: None, proc_mount: None, credentials: None,
            work: Work {
                block: vec![0; BLOCK_SIZE], directory_buffer: vec![MaybeUninit::uninit(); BLOCK_SIZE],
                data: Vec::with_capacity(MANIFEST_LIMIT.max(MOUNTINFO_LIMIT)), attribute_buffer: [0],
                hash: Sha256::new(), reader: None, read_bytes: 0, read_eof: false, last_digest: None,
                directory: None, walk: Vec::with_capacity(TREE_DEPTH + 1), inventory: None,
                actual_names: BTreeSet::new(), actual_folded: BTreeSet::new(), tree_entries: 0,
                files_verified: 0, directories_verified: 0, saw_manifest: false,
            },
        }
    }

    /// Synchronous work for the existing sole retained blocking inspection.
    /// No replacement clock, watcher, task, controller or restart is created.
    pub(crate) fn inspect_once(&mut self, end: Instant, stop: &watch::Receiver<bool>) -> InspectionOutcome {
        if self.phase != Phase::New || self.settlement_started || self.interrupted || self.transferred {
            if self.phase == Phase::Inspecting { self.mark_interrupted(); }
            return self.refuse_and_settle(AdmissionFailure::AlreadyUsed);
        }
        self.phase = Phase::Inspecting;
        match self.inspect_inner(end, stop) {
            Ok(()) => {
                self.operation = Operation::Idle;
                self.phase = Phase::InspectedOnly;
                InspectionOutcome::InspectedOnly
            }
            Err(failure) => self.refuse_and_settle(failure),
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
        if self.phase == Phase::Inspecting { self.mark_interrupted(); }
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
        if self.phase != Phase::Inspecting || self.unknown || self.interrupted || self.settlement_started {
            return Err(AdmissionFailure::LedgerInvariant);
        }
        checkpoint(end, stop)?;
        self.operation = operation;
        Ok(())
    }

    fn arm(&mut self, purpose: Purpose) -> AdmissionResult<SlotId> {
        if self.records.len() >= RECORD_COUNT
            || self.records.iter().filter(|r| r.original.is_some()).count() >= LIVE_COUNT {
            return Err(AdmissionFailure::Bounds);
        }
        let sequence = SlotId(self.records.len());
        // Capacity for ALL records was allocated before the first acquisition.
        self.records.push(FdRecord { sequence, purpose, acquisition: Acquisition::Attempted,
            original: None, identity: None, close: CloseReceipt::Unattempted });
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

    fn retained_bindings_present(&self) -> bool {
        self.ancestors.iter().enumerate().all(|(index, slot)| {
            slot.is_some_and(|id| self.live_binding(id, Purpose::ProtectedAncestor(index as u8)))
        }) && self.namespaces[0].is_some_and(|id| self.live_binding(id, Purpose::InitialUserNamespace))
            && self.namespaces[1].is_some_and(|id| self.live_binding(id, Purpose::InitialPidNamespace))
    }

    fn transfer_ready(&self) -> bool {
        self.phase == Phase::InspectedOnly && !self.settlement_started && !self.interrupted
            && !self.unknown && !self.transferred && self.operation == Operation::Idle
            && self.retained_bindings_present()
            && self.records.iter().filter(|r| r.original.is_some()).count() == RETAINED_COUNT
            && self.records.iter().all(|r| r.acquisition == Acquisition::Original
                && match r.close {
                    CloseReceipt::Unattempted => r.original.is_some(),
                    CloseReceipt::Positive => r.original.is_none(),
                    CloseReceipt::Attempted | CloseReceipt::Unknown => false,
                })
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
    let receipt = TransferReceipt { original_records: book.records.len(), retained_originals: RETAINED_COUNT };
    let Some(mut original) = source.take() else { return Err(AdmissionFailure::TransferUnavailable); };
    original.transferred = true;
    *destination = Some(original);
    Ok(receipt)
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

fn ordinary_identity(identity: Identity, kind: FileType) -> bool {
    let forbidden = Mode::WGRP | Mode::WOTH | Mode::SUID | Mode::SGID | Mode::SVTX;
    FileType::from_raw_mode(identity.mode) == kind && identity.inode != 0
        && identity.links != 0 && identity.size >= 0
        && identity.mtime_nsec < 1_000_000_000 && identity.ctime_nsec < 1_000_000_000
        && !Mode::from_raw_mode(identity.mode).intersects(forbidden)
        && (kind != FileType::RegularFile || identity.links == 1)
}

fn protected_identity(identity: Identity, kind: FileType, size: Option<u64>) -> bool {
    ordinary_identity(identity, kind) && identity.uid == 0 && identity.gid == 0
        && size.is_none_or(|expected| u64::try_from(identity.size).ok() == Some(expected))
}

fn known_mount_attributes(attributes: u64) -> bool {
    attributes & !mount::KNOWN_ATTRIBUTES == 0 && attributes & mount::ID_MAPPED == 0
        && attributes & (mount::NO_ATIME | mount::STRICT_ATIME) != (mount::NO_ATIME | mount::STRICT_ATIME)
}

fn protected_mount(observation: mount::MountObservation) -> bool {
    matches!(observation.filesystem_magic(), mount::EXT4_MAGIC | mount::XFS_MAGIC)
        && known_mount_attributes(observation.attributes()) && observation.attributes() & mount::NO_EXEC == 0
}

impl InstalledRuntimeCustody {
    fn acquire_root(&mut self, end: Instant, stop: &watch::Receiver<bool>) -> AdmissionResult<SlotId> {
        self.begin(Operation::Idle, end, stop)?;
        let slot = self.arm(Purpose::ProtectedAncestor(0))?;
        let result = fs::open("/", ordinary_flags(true), Mode::empty());
        self.receive_open(slot, result)
    }

    fn acquire_child(&mut self, parent: SlotId, component: &str, directory: bool, purpose: Purpose,
        end: Instant, stop: &watch::Receiver<bool>) -> AdmissionResult<SlotId> {
        self.acquire_relative(parent, component, ordinary_flags(directory), beneath_same_mount(), purpose, end, stop)
    }

    fn acquire_relative(&mut self, parent: SlotId, component: &str, flags: OFlags, resolve: ResolveFlags,
        purpose: Purpose, end: Instant, stop: &watch::Receiver<bool>) -> AdmissionResult<SlotId> {
        self.begin(Operation::Idle, end, stop)?;
        if !single_component(component) { return Err(AdmissionFailure::Inventory); }
        let _ = fd_at(&self.records, parent)?;
        let slot = self.arm(purpose)?;
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
        self.work.reader = Some(slot);
        self.work.read_bytes = 0;
        self.work.read_eof = false;
        self.work.last_digest = None;
        self.work.hash = Sha256::new();
        self.work.data.clear();
        loop {
            self.begin(Operation::Read(slot), end, stop)?;
            let result = rustix::io::read(fd_at(&self.records, slot)?, &mut self.work.block[..]);
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
        let actual = rustix::system::uname();
        self.operation = Operation::Idle;
        if !supported_kernel(actual.sysname().to_bytes(), actual.machine().to_bytes(), actual.release().to_bytes()) {
            return Err(AdmissionFailure::UnsupportedPlatform);
        }
        Ok(())
    }

    fn inspect_namespace_controls(&mut self, root: SlotId, credentials: Credentials,
        end: Instant, stop: &watch::Receiver<bool>) -> AdmissionResult<()> {
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

        // These two fixed kernel endpoints are the ONLY followed magic links.
        // The parent is the pinned genuine numeric current-thread proc ns dir.
        // No payload path is permitted this exception or selected by an input.
        let namespace_flags = OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC;
        let user_ns = self.acquire_relative(ns, "user", namespace_flags, ResolveFlags::empty(),
            Purpose::InitialUserNamespace, end, stop)?;
        self.inspect_namespace(user_ns, INITIAL_USER_INODE, end, stop)?;
        self.namespaces[0] = Some(user_ns);
        let pid_ns = self.acquire_relative(ns, "pid", namespace_flags, ResolveFlags::empty(),
            Purpose::InitialPidNamespace, end, stop)?;
        self.inspect_namespace(pid_ns, INITIAL_PID_INODE, end, stop)?;
        self.namespaces[1] = Some(pid_ns);

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

        for slot in [initial, ns, thread, task, process, proc_root] {
            self.inspect_proc_object(slot, FileType::Directory, end, stop)?;
            self.close_finished(slot)?;
        }
        // Keep BOTH actual initial-namespace handles along with the six
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

    fn inspect_inner(&mut self, end: Instant, stop: &watch::Receiver<bool>) -> AdmissionResult<()> {
        self.begin(Operation::Inventory, end, stop)?;
        if COMPILED_TARGET != TARGET { return Err(AdmissionFailure::UnsupportedPlatform); }
        let manifest_anchor = MANIFEST_ANCHOR.filter(|value| sha(value)).ok_or(AdmissionFailure::MissingCompileAnchor)?;
        let protocol_anchor = PROTOCOL_ANCHOR.filter(|value| sha(value)).ok_or(AdmissionFailure::MissingCompileAnchor)?;
        self.inspect_kernel(end, stop)?;
        let credentials = self.current_credentials(end, stop)?;
        self.credentials = Some(credentials);
        let root = self.acquire_root(end, stop)?;
        self.root_mount = Some(self.inspect_protected(root, FileType::Directory, None, end, stop)?);
        self.ancestors[0] = Some(root);
        self.inspect_namespace_controls(root, credentials, end, stop)?;
        self.inspect_os_release(root, end, stop)?;

        let mut parent = root;
        for (index, component) in ["opt", "mobile-release-kit", "versions", TARGET, manifest_anchor].into_iter().enumerate() {
            let slot = self.acquire_child(parent, component, true, Purpose::ProtectedAncestor((index + 1) as u8), end, stop)?;
            self.inspect_protected(slot, FileType::Directory, None, end, stop)?;
            self.ancestors[index + 1] = Some(slot);
            parent = slot;
        }
        let version = parent;
        let manifest_slot = self.acquire_child(version, "manifest.json", false, Purpose::Manifest, end, stop)?;
        self.inspect_protected(manifest_slot, FileType::RegularFile, None, end, stop)?;
        let manifest_size = self.records[manifest_slot.0].identity.ok_or(AdmissionFailure::LedgerInvariant)?.size;
        let manifest_size = u64::try_from(manifest_size).map_err(|_| AdmissionFailure::Bounds)?;
        let digest = self.read_original(manifest_slot, Some(manifest_size), MANIFEST_LIMIT as u64, true, end, stop)?;
        self.begin(Operation::Inventory, end, stop)?;
        if hex(&digest) != manifest_anchor { return Err(AdmissionFailure::Manifest); }
        self.work.inventory = Some(parse_inventory(&self.work.data, protocol_anchor)?);
        self.inspect_protected(manifest_slot, FileType::RegularFile, Some(manifest_size), end, stop)?;
        self.walk_inventory(version, manifest_slot, end, stop)?;
        self.inspect_protected(manifest_slot, FileType::RegularFile, Some(manifest_size), end, stop)?;
        self.close_finished(manifest_slot)?;

        for index in 0..PREFIX_COUNT {
            let slot = self.ancestors[index].ok_or(AdmissionFailure::LedgerInvariant)?;
            self.inspect_protected(slot, FileType::Directory, None, end, stop)?;
        }
        for (index, inode) in [INITIAL_USER_INODE, INITIAL_PID_INODE].into_iter().enumerate() {
            self.inspect_namespace(self.namespaces[index].ok_or(AdmissionFailure::LedgerInvariant)?, inode, end, stop)?;
        }
        if self.current_credentials(end, stop)? != credentials || !self.retained_bindings_present()
            || self.records.iter().filter(|r| r.original.is_some()).count() != RETAINED_COUNT
            || self.records.iter().any(|r| r.acquisition != Acquisition::Original
                || matches!(r.close, CloseReceipt::Attempted | CloseReceipt::Unknown)) {
            return Err(AdmissionFailure::LedgerInvariant);
        }
        self.begin(Operation::Idle, end, stop)?;
        Ok(())
    }
}

impl InstalledRuntimeCustody {
    fn enumerate_directory(&mut self, frame_index: usize, manifest: SlotId,
        end: Instant, stop: &watch::Receiver<bool>) -> AdmissionResult<()> {
        let slot = self.work.walk.get(frame_index).ok_or(AdmissionFailure::LedgerInvariant)?.original;
        self.begin(Operation::Directory(slot), end, stop)?;
        let directory_identity = self.records[slot.0].identity.ok_or(AdmissionFailure::LedgerInvariant)?;
        let manifest_identity = self.records[manifest.0].identity.ok_or(AdmissionFailure::LedgerInvariant)?;
        self.work.directory = Some(slot);
        {
            let original = fd_at(&self.records, slot)?;
            // RawDir owns ONLY this BorrowedFd and borrows the original book's
            // buffer. No dup/Dir/fdopendir/owned iterator/implicit-close owner.
            // The cursor itself is local: if lost, the book can ONLY settle,
            // never resume from a discarded getdents buffer and claim success.
            let mut entries = RawDir::new(original, &mut self.work.directory_buffer[..]);
            loop {
                checkpoint(end, stop)?;
                self.operation = Operation::Directory(slot);
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
        self.work.directory = None;
        self.snapshot(slot, end, stop)?;
        self.operation = Operation::Idle;
        Ok(())
    }

    fn walk_inventory(&mut self, version: SlotId, manifest: SlotId,
        end: Instant, stop: &watch::Receiver<bool>) -> AdmissionResult<()> {
        self.work.walk.push(DirectoryFrame { original: version, relative: String::new(), depth: 0,
            entries: Vec::new(), next: 0, enumerated: false, dot_seen: false, dotdot_seen: false });
        while !self.work.walk.is_empty() {
            self.begin(Operation::Inventory, end, stop)?;
            let index = self.work.walk.len() - 1;
            if !self.work.walk[index].enumerated { self.enumerate_directory(index, manifest, end, stop)?; }
            let frame = &mut self.work.walk[index];
            if frame.next == frame.entries.len() {
                let slot = frame.original;
                self.inspect_protected(slot, FileType::Directory, None, end, stop)?;
                if slot != version { self.close_finished(slot)?; }
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
                let slot = self.acquire_child(parent, &component, true, Purpose::InventoryDirectory, end, stop)?;
                self.inspect_protected(slot, FileType::Directory, None, end, stop)?;
                if self.records[slot.0].identity.is_none_or(|identity| identity.inode != inode) {
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
                let slot = self.acquire_child(parent, &component, false, Purpose::Payload, end, stop)?;
                self.inspect_protected(slot, FileType::RegularFile, Some(expected_size), end, stop)?;
                if self.records[slot.0].identity.is_none_or(|identity| identity.inode != inode) {
                    return Err(AdmissionFailure::IdentityChanged);
                }
                let digest = self.read_original(slot, Some(expected_size), FILE_LIMIT, false, end, stop)?;
                if hex(&digest) != expected_hash { return Err(AdmissionFailure::Manifest); }
                self.inspect_protected(slot, FileType::RegularFile, Some(expected_size), end, stop)?;
                self.close_finished(slot)?;
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
        self.operation = Operation::Idle;
        Ok(())
    }
}

// All helpers below are pure bounded data validation, NOT alternate admission,
// resource constructors, close receipts, installed paths or native test hooks.
fn sha(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(DIGITS[usize::from(byte >> 4)] as char);
        result.push(DIGITS[usize::from(byte & 15)] as char);
    }
    result
}

fn digest(bytes: &[u8]) -> String { hex(&Sha256::digest(bytes)) }

fn parse_inventory(bytes: &[u8], protocol_anchor: &str) -> AdmissionResult<Inventory> {
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
            || file.size > FILE_LIMIT || previous.is_some_and(|name| name >= file.path.as_str())
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
    for required in ["python/bin/python3", "core.zip", "engine_bootstrap.py", "config_edit_bootstrap.py"] {
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

fn supported_kernel(sysname: &[u8], machine: &[u8], release: &[u8]) -> bool {
    if sysname != b"Linux" || machine != b"x86_64" { return false; }
    // Ubuntu's GA 6.8 ABI naming, not a >=6.8 or HWE/custom-kernel fallback.
    // This name check is NOT a kernel provenance/qualification claim.
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

fn initial_id_map(bytes: &[u8]) -> AdmissionResult<()> {
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
struct RootMount { old_id: u32, device: (u32, u32), magic: u64 }

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

fn parse_root_mount(bytes: &[u8]) -> AdmissionResult<RootMount> {
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

fn ubuntu_2404(bytes: &[u8]) -> AdmissionResult<()> {
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

    // This entire roster is data-only. No inspect_once/settle_originals,
    // native adapter, descriptor, proc path, system clock, runtime, process,
    // fixture installer or executable capability is used or fabricated.
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
    fn kernel_scope_is_exact_ga_68() {
        assert!(supported_kernel(b"Linux", b"x86_64", b"6.8.0-91-generic"));
        for release in [b"6.8.0-generic".as_slice(), b"6.8.0-0-generic", b"6.8.0-91-lowlatency",
            b"6.8.0-91-generic-custom", b"6.11.0-29-generic", b"6.8.0-+91-generic"] {
            assert!(!supported_kernel(b"Linux", b"x86_64", release));
        }
        assert!(!supported_kernel(b"Linux", b"aarch64", b"6.8.0-91-generic"));
        assert!(!supported_kernel(b"FreeBSD", b"x86_64", b"6.8.0-91-generic"));
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
        let files = ["config_edit_bootstrap.py", "core.zip", "engine_bootstrap.py", "python/bin/python3"]
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
        let mut missing = inventory_fixture();
        missing.files.remove(0);
        rehash_inventory(&mut missing);
        assert!(validate_inventory(missing, &protocol).is_err());
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
            assert!(original.settlement_started && original.interrupted && !original.transfer_ready());
        } else { panic!("rejected transfer consumed its original source"); }
    }
}
