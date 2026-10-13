//! Original macOS APFS fd custody for the fixed application-private vault directory.
//! This book is retained outside the blocking worker by OriginalWork. There is
//! no Drop-based close receipt, path-suffix cleanup, automatic repair or retry.
use super::*;
use std::{cell::RefCell, ffi::OsStr, mem::ManuallyDrop, os::{fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd}, unix::ffi::OsStrExt}, path::{Path, PathBuf}, time::{Duration, Instant}};
use nix::{errno::Errno, fcntl::{self, AtFlags, FlockArg, OFlag as OFlags}, mount::MntFlags,
    sys::{stat::{self, FileStat as Stat, Mode, SFlag}, statfs}, unistd::{self, UnlinkatFlags, Whence}};
use mrk_macos_installed_native::{self as darwin, vault_filesystem::{SnapshotBook, Expected as AclExpected, Policy as AclPolicy, Failure as AclFailure}};
use sha2::{Digest, Sha256};

const APPLICATION: &[u8] = b"dev.mobile-release-kit.desktop";
const VAULT: &[u8] = b"credential-vault-v1";
const COMPONENTS: usize = 128;
const ORIGINALS: usize = COMPONENTS + 8;
const BLOCK: usize = 64 * 1024;
const FAILURE_CLEANUP: Duration = Duration::from_secs(2);

fn check(stop: &mut dyn FnMut() -> bool) -> Result<()> { if stop() { Err(Problem::Stopped) } else { Ok(()) } }
fn native(error: Errno) -> Problem { if error == Errno::EWOULDBLOCK { Problem::Busy } else { Problem::Native } }
fn native_io(error: std::io::Error) -> Problem { if error.kind() == std::io::ErrorKind::WouldBlock { Problem::Busy } else { Problem::Native } }
fn acl_problem(error: AclFailure) -> Problem { match error {
    AclFailure::Refused => Problem::Identity, AclFailure::Native => Problem::Native, AclFailure::Bounds => Problem::Bounds,
    AclFailure::Stopped => Problem::Stopped, AclFailure::Unknown => Problem::CleanupUnknown,
} }
fn admitted_filesystem(name: &str, flags: MntFlags) -> bool {
    name == "apfs" && flags.contains(MntFlags::MNT_LOCAL)
        && !flags.intersects(MntFlags::MNT_UNION | MntFlags::MNT_AUTOMOUNTED | MntFlags::MNT_IGNORE_OWNERSHIP)
}
fn namespace_fold(name: &[u8]) -> Result<Vec<u8>> {
    // The vault's format uses only ASCII names. Non-ASCII/unknown normalization
    // is a refusal, not a text-normalized authority or a debris deletion.
    need(!name.is_empty() && name.len() <= 255 && name.is_ascii()
        && !name.contains(&0) && !name.contains(&b'/') && name != b"." && name != b"..",Problem::UnsupportedEntry)?;
    Ok(name.to_ascii_lowercase())
}
fn directory_entry(buffer: &[u8], at: usize) -> Result<(u64,u8,&[u8],usize)> {
    let fixed=buffer.get(at..at.checked_add(11).ok_or(Problem::Bounds)?).ok_or(Problem::Corrupt)?;
    let inode=u64::from_ne_bytes(fixed[..8].try_into().map_err(|_| Problem::Corrupt)?);
    let length=usize::from(u16::from_ne_bytes(fixed[9..11].try_into().map_err(|_| Problem::Corrupt)?));
    need(inode != 0 && (1..=255).contains(&length),Problem::Corrupt)?;
    let next=at.checked_add(11).and_then(|value| value.checked_add(length)).ok_or(Problem::Bounds)?;
    let name=buffer.get(at+11..next).ok_or(Problem::Corrupt)?;
    namespace_fold(name)?; Ok((inode,fixed[8],name,next))
}
fn need(condition: bool, problem: Problem) -> Result<()> { if condition { Ok(()) } else { Err(problem) } }
fn first_failure_expired(first: Option<Instant>, now: Instant) -> bool {
    first.is_some_and(|at| at.checked_add(FAILURE_CLEANUP).is_none_or(|end| now >= end))
}
fn cleanup_expired_at(first: Option<Instant>, original: &mut dyn FnMut() -> bool) -> bool {
    // The original owner can shorten this deadline further. Neither a later
    // observer nor a successful cleanup step receives a fresh allowance.
    original() || first_failure_expired(first, Instant::now())
}

/// Rust's application-local-data resolution supplies this; no IPC command takes
/// a pathname. Only the final app directory and fixed vault child may be made.
pub(crate) struct Location { path: PathBuf, components: Vec<Vec<u8>> }
impl Location {
    pub(crate) fn application_data(path: &Path) -> Result<Self> {
        let raw = path.as_os_str().as_bytes();
        need(raw.len() <= 4096 - VAULT.len() - 1 && raw.first() == Some(&b'/') && !raw.contains(&0), Problem::Identity)?;
        let mut components = Vec::new();
        for name in raw[1..].split(|byte| *byte == b'/') {
            need(!name.is_empty() && name.len() <= 255 && name != b"." && name != b".." && components.len() < COMPONENTS - 2, Problem::Identity)?;
            components.push(name.to_vec());
        }
        need(components.len() >= 2 && components.last().is_some_and(|name| name.as_slice() == APPLICATION), Problem::Identity)?;
        components.push(VAULT.to_vec());
        Ok(Self { path: path.join(OsStr::from_bytes(VAULT)), components })
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct DirectoryKey { dev: u64, ino: u64, mode: u32, uid: u32, gid: u32, flags: u32 }
impl DirectoryKey {
    fn of(stat: &Stat) -> Result<Self> {
        need(stat.st_ino != 0, Problem::Identity)?;
        Ok(Self { dev: u64::try_from(stat.st_dev).map_err(|_| Problem::Identity)?,
            ino: stat.st_ino, mode: u32::from(stat.st_mode), uid: stat.st_uid, gid: stat.st_gid, flags: stat.st_flags })
    }
    fn acl_expected(self) -> AclExpected { AclExpected { device:self.dev, inode:self.ino, mode:self.mode, owner:self.uid, group:self.gid, flags:self.flags } }
    fn same_object(self, other: Self) -> bool { self.dev == other.dev && self.ino == other.ino }
    fn directory(self, uid: u32, private: bool) -> bool {
        self.mode & u32::from(SFlag::S_IFMT.bits()) == u32::from(SFlag::S_IFDIR.bits())
            && if private { self.uid == uid && self.mode & 0o7777 == 0o700 && self.flags == 0 }
            else { [0, uid].contains(&self.uid) && self.mode & 0o022 == 0 }
    }
}
fn exclude_project_ancestors(ancestors: impl Iterator<Item = DirectoryKey>,
    projects: &[crate::asset_source::DirectoryIdentity], stop: &mut dyn FnMut() -> bool) -> Result<()> {
    check(stop)?;
    for ancestor in ancestors {
        let held = crate::asset_source::DirectoryIdentity::vault_original(
            ancestor.dev, ancestor.ino, ancestor.mode, ancestor.uid, ancestor.gid);
        for project in projects {
            check(stop)?;
            need(!held.same_object(*project), Problem::Identity)?;
        }
    }
    check(stop)
}
#[derive(Clone, Copy, PartialEq, Eq)]
struct FileKey { common: DirectoryKey, links: u64, bytes: u64, mtime: (i64, i64), ctime: (i64, i64) }
impl FileKey {
    fn of(stat: &Stat, uid: u32) -> Result<Self> {
        need(stat.st_mode & SFlag::S_IFMT.bits() == SFlag::S_IFREG.bits() && stat.st_uid == uid
            && stat.st_mode & 0o7777 == 0o600 && stat.st_nlink == 1 && stat.st_flags == 0, Problem::Identity)?;
        need((0..1_000_000_000).contains(&stat.st_mtime_nsec) && (0..1_000_000_000).contains(&stat.st_ctime_nsec), Problem::Identity)?;
        Ok(Self { common: DirectoryKey::of(stat)?, links: u64::from(stat.st_nlink),
            bytes: u64::try_from(stat.st_size).map_err(|_| Problem::Identity)?,
            mtime: (stat.st_mtime,stat.st_mtime_nsec), ctime: (stat.st_ctime,stat.st_ctime_nsec) })
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum OriginalState { Reserved, Entered, Owned, NoHandle, Closing, Closed, Unknown }
struct Original {
    fd: Option<ManuallyDrop<OwnedFd>>, state: OriginalState, parent: Option<usize>, name: Vec<u8>,
    directory: Option<DirectoryKey>, private: bool, exclusive: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Work { Inspect, PrepareInitialize, ReserveIdentity, PublishHeader, ReadRecord, RecheckRoot, RecheckRecord, Mutate }
#[cfg(all(test,debug_assertions))]
#[derive(Clone,Copy,PartialEq,Eq)]
enum StorageFault { AfterAclAllocation, BeforeEffect, AfterEffect, AfterSync, BeforeClear, AfterClear }

/// Only this operation's three possible original leaves. The indexes are armed
/// before their native open, so a late STOP/failed worker cannot lose custody.
struct MutationFiles {
    prefix: format::IntentPrefix, expected: Option<ReadWitness>,
    target: Option<usize>, candidate: Option<usize>, intent: Option<usize>,
    candidate_ready: Option<FileKey>, intent_ready: Option<FileKey>,
    candidate_removed: bool, candidate_cleanup_sync: bool, intent_removed: bool, effect_returned: Option<bool>, effect_verified: bool,
}

/// Non-owning metadata from actual held directory originals, never a reusable
/// fd or authority to reopen a source file. Later registry checks need fresh
/// original comparisons in both directions, not a path-prefix test.
#[derive(Clone)]
pub(crate) struct RootWitness { path: PathBuf, root: DirectoryKey, ancestry: Vec<DirectoryKey> }
impl RootWitness {
    pub(crate) fn retained_bytes(&self) -> Option<usize> {
        std::mem::size_of::<Self>().checked_add(self.path.capacity())?
            .checked_add(self.ancestry.capacity().checked_mul(std::mem::size_of::<DirectoryKey>())?)
    }
    pub(crate) fn registered(&self) -> crate::asset_source::RegisteredRoot {
        crate::asset_source::RegisteredRoot { path: self.path.clone(), identity: crate::asset_source::ProjectIdentity::Posix(
            crate::asset_source::DirectoryIdentity::vault_original(self.root.dev, self.root.ino, self.root.mode, self.root.uid, self.root.gid)) }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReadWitness { root: DirectoryKey, file: FileKey, record: Id, revision: format::Revision }
#[cfg(all(test, debug_assertions))]
impl ReadWitness {
    /// Inert projection/census DATA only: no file, descriptor or storage owner
    /// is acquired. Zero modes deliberately do not describe admissible files.
    pub(crate) fn lifecycle_data(record: Id, revision: format::Revision) -> Self {
        let root = DirectoryKey { dev: 0, ino: 0, mode: 0, uid: 0, gid: 0, flags: 0 };
        let file = FileKey { common: root, links: 0, bytes: 0, mtime: (0, 0), ctime: (0, 0) };
        Self { root, file, record, revision }
    }
}
pub(crate) struct ReadOriginal { bytes: Vec<u8>, witness: ReadWitness, complete: bool }
impl ReadOriginal {
    pub(crate) fn bytes(&self) -> &[u8] { &self.bytes }
    pub(crate) fn complete(&self) -> bool { self.complete }
    pub(crate) fn into_parts(self) -> (Vec<u8>, ReadWitness, bool) { (self.bytes, self.witness, self.complete) }
}
pub(crate) struct Observation {
    pub(crate) state: Inspection, pub(crate) reservation: Option<[u8; format::RESERVATION_BYTES]>,
    pub(crate) header: Option<[u8; format::HEADER_BYTES]>, pub(crate) records: Vec<Id>, pub(crate) root: Option<RootWitness>,
}

pub(crate) struct StoreBook {
    #[cfg(all(test,debug_assertions))]
    fault: Option<StorageFault>,
    acl: RefCell<SnapshotBook>, originals: Vec<Original>, location: Option<Location>, uid: Option<u32>, root: Option<usize>, lock: Option<usize>,
    retained: usize, consumed: u64, started: bool, retired: bool, close_failed: bool, lock_held: bool,
    prepared: Option<format::Identity>, reserved: Option<format::Identity>,
    reservation_sync: bool, header_sync: bool,
    reservation_entered: bool, reservation_applied: bool, header_entered: bool, header_applied: bool,
    reservation_original: Option<FileKey>, header_original: Option<FileKey>,
    first: Option<Problem>, first_at: Option<Instant>, in_flight: Option<Work>, mutation: Option<MutationProgress>, mutation_files: Option<MutationFiles>,
}
impl StoreBook {
    pub(crate) fn new() -> Self {
        Self {
            #[cfg(all(test,debug_assertions))]
            fault: None,
            acl: RefCell::new(SnapshotBook::new()), originals: Vec::new(), location: None, uid: None, root: None, lock: None, retained: 0, consumed: 0,
            started: false, retired: false, close_failed: false, lock_held: false,
            prepared: None, reserved: None, reservation_sync: false, header_sync: false,
            reservation_entered: false, reservation_applied: false, header_entered: false, header_applied: false,
            reservation_original: None, header_original: None, first: None, first_at: None, in_flight: None,
            mutation: None, mutation_files: None }
    }
    pub(crate) fn not_started(&self) -> bool { !self.started && self.originals.is_empty() && self.first.is_none() && self.in_flight.is_none()
        && self.acl.try_borrow().is_ok_and(|book| book.not_started()) }
    pub(crate) fn settled(&self) -> bool {
        self.retired && !self.close_failed && self.acl.try_borrow().is_ok_and(|book| book.settled()) && self.originals.iter().all(|original|
            original.fd.is_none() && matches!(original.state, OriginalState::Closed | OriginalState::NoHandle))
    }
    pub(crate) fn lease_held(&self) -> bool { self.started && !self.retired && !self.close_failed
        && self.acl.try_borrow().is_ok_and(|book| book.quiescent()) && self.root.is_some() && self.lock_held }
    fn first_observed(&self) -> Option<(Problem,Instant)> {
        let native = self.acl.try_borrow().ok().and_then(|book| book.first_failure()).map(|(problem,at)| (acl_problem(problem),at));
        match (self.first.zip(self.first_at),native) {
            (Some(original),Some(native)) => Some(if native.1 < original.1 { native } else { original }),
            (original,native) => original.or(native),
        }
    }
    pub(crate) fn problem(&self) -> Option<Problem> { self.first_observed().map(|value| value.0) }
    pub(crate) fn problem_at(&self) -> Option<Instant> { self.first_observed().map(|value| value.1) }
    /// ((reservation create entered, returned original), (header create
    /// entered, returned original)). An applied create can contain incomplete
    /// bytes; only the separate successful directory-sync facts mean durable
    /// controls. None of these facts grants initialization/key use after STOP.
    pub(crate) fn initialization_effects(&self) -> ((bool, bool), (bool, bool)) {
        ((self.reservation_entered, self.reservation_applied), (self.header_entered, self.header_applied))
    }
    pub(crate) fn initialization_durability(&self) -> (bool, bool) { (self.reservation_sync, self.header_sync) }
    /// Per-operation quiescence is not retirement of the retained document
    /// root/lock lease, and neither projection erases the operation's failure.
    pub(crate) fn operation_quiescent(&self) -> bool {
        self.in_flight.is_none() && !self.close_failed && self.acl.try_borrow().is_ok_and(|book| book.quiescent()) && self.retained <= self.originals.len()
            && self.originals[..self.retained].iter().all(|original| match original.state {
                OriginalState::Owned => original.fd.is_some(),
                OriginalState::Closed | OriginalState::NoHandle => original.fd.is_none(),
                _ => false,
            })
            && self.originals[self.retained..].iter().all(|original| original.fd.is_none()
                && matches!(original.state, OriginalState::Closed | OriginalState::NoHandle))
    }
    pub(crate) fn storage_outcome(&self) -> Option<StorageOutcome> { self.mutation.as_ref().map(|progress| progress.outcome) }
    pub(crate) fn retained_bytes(&self) -> Option<usize> {
        let acl = self.acl.try_borrow().ok()?;
        // The adapter frame is measured, but opaque filesec/ACL/qualifier
        // allocations are not. Pending/unknown native originals have no complete
        // byte census: return None, never a frame-only total or a zero refund.
        if !acl.quiescent() { return None; }
        let mut count = std::mem::size_of::<Self>().checked_add(self.originals.capacity().checked_mul(std::mem::size_of::<Original>())?)?;
        for original in &self.originals { count = count.checked_add(original.name.capacity())?; }
        if let Some(location) = &self.location {
            count = count.checked_add(location.path.capacity())?
                .checked_add(location.components.capacity().checked_mul(std::mem::size_of::<Vec<u8>>())?)?;
            for name in &location.components { count = count.checked_add(name.capacity())?; }
        }
        count = count.checked_add(acl.retained_frame_bytes())?;
        Some(count)
    }
    fn fail(&mut self, problem: Problem) {
        // Native snapshot refusals are observed before cleanup begins. Preserve
        // that actual first timestamp, not this later wrapper-return time.
        if let Some((first,at)) = self.first_observed() { self.first=Some(first); self.first_at=Some(at); }
        if self.first.is_none() { self.first = Some(problem); self.first_at = Some(Instant::now()); }
        if let Some(progress) = &mut self.mutation {
            if problem == Problem::Stopped { progress.stop(); } else { progress.fail(problem); }
        }
    }
    #[cfg(all(test,debug_assertions))]
    fn inject(&mut self, at: StorageFault) -> Result<()> {
        if self.fault == Some(at) { self.fault=None; Err(if at == StorageFault::BeforeClear { Problem::Native } else { Problem::Stopped }) }
        else { Ok(()) }
    }
    fn begin(&mut self, work: Work) -> Result<()> {
        if let Some(problem) = self.first { return Err(problem); }
        if self.retired || !self.operation_quiescent()
            || self.mutation.as_ref().is_some_and(|progress| !progress.success()) {
            self.fail(Problem::State); return Err(Problem::State);
        }
        self.in_flight = Some(work); Ok(())
    }
    fn finish<T>(&mut self, result: Result<T>, stop: &mut dyn FnMut() -> bool) -> Result<T> {
        if let Err(problem) = &result { self.fail(*problem); }
        if stop() { self.fail(Problem::Stopped); }
        self.in_flight = None;
        match self.first { Some(problem) => Err(problem), None => result }
    }
    fn work<T>(&mut self, work: Work, stop: &mut dyn FnMut() -> bool,
        run: impl FnOnce(&mut Self, &mut dyn FnMut() -> bool) -> Result<T>) -> Result<T> {
        self.begin(work)?;
        let result = check(stop).and_then(|()| run(self, stop));
        // A panic never reaches finish: the still-armed book cannot be reused.
        self.finish(result, stop)
    }
    fn uid(&self) -> Result<u32> { self.uid.ok_or(Problem::State) }
    fn fd(&self, index: usize) -> Result<BorrowedFd<'_>> {
        self.originals.get(index).filter(|o| o.state == OriginalState::Owned).and_then(|o| o.fd.as_ref())
            .map(|fd| fd.as_fd()).ok_or(Problem::CleanupUnknown)
    }
    fn arm(&mut self, parent: Option<usize>, name: &[u8], private: bool) -> Result<usize> {
        need(!self.close_failed && !self.retired && self.originals.len() < ORIGINALS, Problem::State)?;
        need(name == b"/" && parent.is_none() || parent.is_some() && !name.is_empty() && name.len() <= 255
            && !name.contains(&b'/') && !name.contains(&0), Problem::Identity)?;
        self.originals.try_reserve(1).map_err(|_| Problem::Bounds)?;
        let index = self.originals.len();
        self.originals.push(Original { fd: None, state: OriginalState::Reserved, parent, name: name.to_vec(), directory: None, private, exclusive: false });
        Ok(index)
    }
    fn open(&mut self, parent: Option<usize>, name: &[u8], flags: OFlags, private: bool, stop: &mut dyn FnMut() -> bool) -> Result<usize> {
        check(stop)?;
        if let Some(parent) = parent { self.fd(parent)?; }
        let index = self.arm(parent, name, private)?;
        self.open_armed(index, flags, stop)?;
        Ok(index)
    }
    fn open_armed(&mut self, index: usize, flags: OFlags, stop: &mut dyn FnMut() -> bool) -> Result<()> {
        check(stop)?;
        let original = self.originals.get(index).ok_or(Problem::State)?;
        need(original.state == OriginalState::Reserved && original.fd.is_none(), Problem::State)?;
        let (parent, name) = (original.parent, original.name.clone());
        if let Some(parent) = parent { self.fd(parent)?; }
        let mode = if flags.contains(OFlags::O_CREAT) { Mode::from_bits_truncate(0o600) } else { Mode::empty() };
        self.originals[index].exclusive = flags.contains(OFlags::O_CREAT | OFlags::O_EXCL);
        let reservation = self.originals[index].exclusive && parent == self.root && name == format::RESERVATION_NAME.as_bytes();
        let header = self.originals[index].exclusive && parent == self.root && name == format::HEADER_NAME.as_bytes();
        if reservation { self.reservation_entered = true; }
        if header { self.header_entered = true; }
        self.originals[index].state = OriginalState::Entered;
        let returned = match parent {
            Some(parent) => fcntl::openat(self.fd(parent)?, OsStr::from_bytes(&name), flags, mode),
            None => fcntl::open("/", flags, mode),
        };
        // Every returned original is retained before checking STOP or metadata.
        match returned {
            Ok(fd) => {
                self.originals[index].fd = Some(ManuallyDrop::new(fd)); self.originals[index].state = OriginalState::Owned;
                if reservation { self.reservation_applied = true; }
                if header { self.header_applied = true; }
            },
            Err(error) => { self.originals[index].state = OriginalState::NoHandle; return Err(native(error)); },
        }
        check(stop)
    }
    fn named(&self, parent: usize, name: &[u8], stop: &mut dyn FnMut() -> bool) -> Result<Option<Stat>> {
        check(stop)?;
        let result = stat::fstatat(self.fd(parent)?, OsStr::from_bytes(name), AtFlags::AT_SYMLINK_NOFOLLOW);
        let result = match result { Ok(value) => Some(value), Err(Errno::ENOENT) => None, Err(error) => return Err(native(error)) };
        check(stop)?; Ok(result)
    }
    fn stat(&self, index: usize, stop: &mut dyn FnMut() -> bool) -> Result<Stat> {
        check(stop)?; let returned = stat::fstat(self.fd(index)?).map_err(native)?; check(stop)?; Ok(returned)
    }
    fn filesystem(&self, index: usize, stop: &mut dyn FnMut() -> bool) -> Result<()> {
        check(stop)?; let observed = statfs::fstatfs(self.fd(index)?).map_err(native)?; check(stop)?;
        need(admitted_filesystem(observed.filesystem_type_name(), observed.flags()), Problem::UnsupportedFilesystem)
    }
    fn acl_check(&self, index: usize, stat: &Stat, policy: AclPolicy, stop: &mut dyn FnMut() -> bool) -> Result<()> {
        let expected = DirectoryKey::of(stat)?.acl_expected();
        #[cfg(all(test,debug_assertions))]
        if self.fault == Some(StorageFault::AfterAclAllocation) {
            // The existing snapshot's third checkpoint follows the actual first
            // filesec allocation. Stop there, without inventing a native receipt.
            let mut points = 0;
            return self.acl.try_borrow_mut().map_err(|_| Problem::CleanupUnknown)?
                .observe(self.fd(index)?, expected, policy, &mut || {
                    points += 1; points == 3 || stop()
                }).map_err(acl_problem);
        }
        self.acl.try_borrow_mut().map_err(|_| Problem::CleanupUnknown)?
            .observe(self.fd(index)?, expected, policy, stop).map_err(acl_problem)
    }
    fn private_leaf(&self, index: usize, stop: &mut dyn FnMut() -> bool) -> Result<FileKey> {
        self.filesystem(index,stop)?;
        let before=self.stat(index,stop)?; let key=FileKey::of(&before,self.uid()?)?;
        self.acl_check(index,&before,AclPolicy::Empty,stop)?;
        check(stop)?; darwin::no_xattrs(self.fd(index)?).map_err(native_io)?; check(stop)?;
        need(FileKey::of(&self.stat(index,stop)?,self.uid()?)? == key,Problem::Identity)?;
        Ok(key)
    }
    fn directory(&mut self, parent: Option<usize>, name: &[u8], private: bool, stop: &mut dyn FnMut() -> bool) -> Result<usize> {
        let before = match parent { Some(parent) => self.named(parent, name, stop)?.ok_or(Problem::Identity)?,
            None => { check(stop)?; let value = stat::lstat(Path::new("/")).map_err(native)?; check(stop)?; value } };
        let expected = DirectoryKey::of(&before)?; need(expected.directory(self.uid()?, private), Problem::Identity)?;
        let index = self.open(parent, name, read_flags(true), private, stop)?;
        self.filesystem(index, stop)?;
        let held=self.stat(index,stop)?;
        need(DirectoryKey::of(&held)? == expected, Problem::Identity)?;
        self.acl_check(index,&held,if private { AclPolicy::Empty } else { AclPolicy::Ancestors },stop)?;
        if private { check(stop)?; darwin::no_xattrs(self.fd(index)?).map_err(native_io)?; check(stop)?; }
        need(DirectoryKey::of(&self.stat(index,stop)?)? == expected,Problem::Identity)?;
        let after = match parent { Some(parent) => self.named(parent, name, stop)?.ok_or(Problem::Identity)?,
            None => { check(stop)?; let value = stat::lstat(Path::new("/")).map_err(native)?; check(stop)?; value } };
        need(DirectoryKey::of(&after)? == expected, Problem::Identity)?;
        self.originals[index].directory = Some(expected); Ok(index)
    }
    fn check_roots(&self, stop: &mut dyn FnMut() -> bool) -> Result<()> {
        need(!self.close_failed && !self.retired, Problem::CleanupUnknown)?;
        for (index, original) in self.originals.iter().enumerate().take(self.retained) {
            let Some(expected) = original.directory else { continue; };
            need(expected.directory(self.uid()?, original.private), Problem::Identity)?;
            self.filesystem(index, stop)?;
            let held=self.stat(index,stop)?;
            need(DirectoryKey::of(&held)? == expected, Problem::Identity)?;
            self.acl_check(index,&held,if original.private { AclPolicy::Empty } else { AclPolicy::Ancestors },stop)?;
            if original.private { check(stop)?; darwin::no_xattrs(self.fd(index)?).map_err(native_io)?; check(stop)?; }
            need(DirectoryKey::of(&self.stat(index,stop)?)? == expected,Problem::Identity)?;
            let after = match original.parent {
                Some(parent) => self.named(parent, &original.name, stop)?.ok_or(Problem::Identity)?,
                None => { check(stop)?; let value = stat::lstat(Path::new("/")).map_err(native)?; check(stop)?; value },
            };
            need(DirectoryKey::of(&after)? == expected, Problem::Identity)?;
        }
        if let Some(lock) = self.lock {
            let root = self.root.ok_or(Problem::State)?;
            let held = self.private_leaf(lock,stop)?;
            let named = FileKey::of(&self.named(root, format::LOCK_NAME.as_bytes(), stop)?.ok_or(Problem::Identity)?, self.uid()?)?;
            need(self.lock_held && held == named && held.bytes == 0, Problem::Identity)?;
        }
        Ok(())
    }
    #[allow(deprecated)] // Retain/close the same original; no separate RAII flock owner.
    fn lock(&mut self, create: bool, stop: &mut dyn FnMut() -> bool) -> Result<()> {
        need(self.lock.is_none() && !self.lock_held, Problem::State)?;
        let root = self.root.ok_or(Problem::State)?;
        let existing = self.named(root, format::LOCK_NAME.as_bytes(), stop)?;
        let flags = read_flags(false) | OFlags::O_RDWR;
        let flags = if existing.is_none() && create { flags | OFlags::O_CREAT | OFlags::O_EXCL } else { flags };
        need(existing.is_some() || create, Problem::Corrupt)?;
        if let Some(stat) = &existing { need(FileKey::of(stat, self.uid()?)?.bytes == 0, Problem::Identity)?; }
        let index = self.open(Some(root), format::LOCK_NAME.as_bytes(), flags, false, stop)?;
        let held = self.private_leaf(index,stop)?;
        let named = FileKey::of(&self.named(root, format::LOCK_NAME.as_bytes(), stop)?.ok_or(Problem::Identity)?, self.uid()?)?;
        need(held == named && held.bytes == 0 && existing.as_ref().is_none_or(|before| FileKey::of(before, self.uid.unwrap_or(0)).is_ok_and(|before| before == held)), Problem::Identity)?;
        check(stop)?;
        let returned = fcntl::flock(self.fd(index)?.as_raw_fd(), FlockArg::LockExclusiveNonblock);
        // Failure/WOULDBLOCK owns this fd but never claims an acquired lock.
        returned.map_err(native)?; self.lock = Some(index); self.lock_held = true;
        self.retained = self.originals.len(); check(stop)?; Ok(())
    }
    pub(crate) fn inspect(&mut self, location: Location, stop: &mut dyn FnMut() -> bool) -> Result<Observation> {
        self.work(Work::Inspect, stop, |book, stop| book.inspect_inner(location, stop))
    }
    fn inspect_inner(&mut self, location: Location, stop: &mut dyn FnMut() -> bool) -> Result<Observation> {
        need(!self.started && self.originals.is_empty() && !self.retired, Problem::State)?;
        check(stop)?; let uid=darwin::real_user().map_err(native_io)?; check(stop)?;
        self.started = true; self.uid = Some(uid); self.location = Some(location);
        let root = self.directory(None, b"/", false, stop)?;
        let count = self.location.as_ref().ok_or(Problem::State)?.components.len();
        let mut parent = root;
        for at in 0..count {
            let name = self.location.as_ref().ok_or(Problem::State)?.components[at].clone();
            if self.named(parent, &name, stop)?.is_none() {
                need(at >= count - 2, Problem::Identity)?;
                self.retained = self.originals.len(); self.check_roots(stop)?;
                return Ok(Observation { state: Inspection::Uninitialized, reservation: None, header: None, records: Vec::new(), root: None });
            }
            parent = self.directory(Some(parent), &name, at == count - 1, stop)?;
        }
        self.root = Some(parent); self.retained = self.originals.len();
        let inventory = self.inventory(stop)?;
        if inventory.names.is_empty() {
            self.check_roots(stop)?;
            return Ok(Observation { state: Inspection::Uninitialized, reservation: None, header: None, records: Vec::new(), root: Some(self.witness()?) });
        }
        self.lock(false, stop)?;
        self.observe_locked(stop)
    }
    fn witness(&self) -> Result<RootWitness> {
        let root = self.root.and_then(|index| self.originals.get(index)).and_then(|original| original.directory).ok_or(Problem::State)?;
        let location = self.location.as_ref().ok_or(Problem::State)?;
        Ok(RootWitness { path: location.path.clone(), root,
            ancestry: self.originals.iter().take(self.retained).filter_map(|original| original.directory).collect() })
    }
    fn inventory(&mut self, stop: &mut dyn FnMut() -> bool) -> Result<Inventory> {
        let root=self.root.ok_or(Problem::State)?;
        need(self.originals.len() == self.retained,Problem::State)?;
        self.check_roots(stop)?;
        let before=self.stat(root,stop)?; let root_key=DirectoryKey::of(&before)?;
        check(stop)?; need(unistd::lseek(self.fd(root)?,0,Whence::SeekSet).map_err(native)? == 0,Problem::Identity)?; check(stop)?;
        let mut buffer=[0u8;BLOCK]; let mut inventory=Inventory::new();
        let mut folded=BTreeSet::new(); let mut physical=BTreeSet::new();
        let mut observed=Vec::new(); observed.try_reserve_exact(ENTRY_COUNT).map_err(|_| Problem::Bounds)?;
        loop {
            check(stop)?;
            let used=darwin::directory_block(self.fd(root)?,&mut buffer).map_err(native_io)?;
            check(stop)?;
            if used == 0 { break; } // Actual complete original-cursor EOF; no dot-entry fiction.
            let mut at=0;
            while at < used {
                let (inode,kind,name,next)=directory_entry(&buffer[..used],at)?;
                at=next; check(stop)?;
                need(kind == 8,Problem::UnsupportedEntry)?; // Public Darwin DT_REG.
                let lower=namespace_fold(name)?;
                need(folded.insert(lower) && inventory.names.len() < ENTRY_COUNT,Problem::Bounds)?;
                let expected=FileKey::of(&self.named(root,name,stop)?.ok_or(Problem::Identity)?,self.uid()?)?;
                need(expected.common.ino == inode && expected.common.dev == root_key.dev
                    && physical.insert((expected.common.dev,expected.common.ino)),Problem::Identity)?;
                let index=self.open(Some(root),name,read_flags(false),false,stop)?;
                need(self.private_leaf(index,stop)? == expected,Problem::Identity)?;
                need(FileKey::of(&self.named(root,name,stop)?.ok_or(Problem::Identity)?,self.uid()?)? == expected,Problem::Identity)?;
                self.close(index)?; self.discard_closed_leaves()?;
                inventory.add(name,expected.bytes,true)?;
                observed.push((name.to_vec(),expected));
            }
        }
        // No leaf metadata drift may hide behind an unchanged directory mtime.
        for (name,expected) in &observed {
            need(FileKey::of(&self.named(root,name,stop)?.ok_or(Problem::Identity)?,self.uid()?)? == *expected,Problem::Identity)?;
        }
        let after=self.stat(root,stop)?;
        need(root_key == DirectoryKey::of(&after)? && before.st_mtime == after.st_mtime
            && before.st_mtime_nsec == after.st_mtime_nsec && before.st_ctime == after.st_ctime
            && before.st_ctime_nsec == after.st_ctime_nsec,Problem::Identity)?;
        self.check_roots(stop)?; Ok(inventory)
    }
    fn read_leaf(&mut self, name: &[u8], length: usize, full: bool, stop: &mut dyn FnMut() -> bool) -> Result<(Vec<u8>, FileKey)> {
        need(self.originals.len() == self.retained, Problem::State)?;
        self.check_roots(stop)?;
        let root = self.root.ok_or(Problem::State)?;
        let before = FileKey::of(&self.named(root, name, stop)?.ok_or(Problem::Identity)?, self.uid()?)?;
        need(length <= format::RECORD_LIMIT && if full { before.bytes == length as u64 } else { before.bytes >= length as u64 }, Problem::Bounds)?;
        let index = self.open(Some(root), name, read_flags(false), false, stop)?;
        let bytes = self.read_held(index, name, before, length, full, stop)?;
        self.close(index)?; self.discard_closed_leaves()?; self.check_roots(stop)?;
        need(FileKey::of(&self.named(root, name, stop)?.ok_or(Problem::Identity)?, self.uid()?)? == before, Problem::Identity)?;
        Ok((bytes, before))
    }
    fn read_held(&self, index: usize, name: &[u8], before: FileKey, length: usize, full: bool,
        stop: &mut dyn FnMut() -> bool) -> Result<Vec<u8>> {
        let root = self.root.ok_or(Problem::State)?;
        need(length <= format::RECORD_LIMIT && if full { before.bytes == length as u64 } else { before.bytes >= length as u64 }, Problem::Bounds)?;
        need(self.private_leaf(index,stop)? == before, Problem::Identity)?;
        check(stop)?; need(unistd::lseek(self.fd(index)?, 0, Whence::SeekSet).map_err(native)? == 0, Problem::Identity)?; check(stop)?;
        let mut bytes = Vec::new(); bytes.try_reserve_exact(length).map_err(|_| Problem::Bounds)?; bytes.resize(length, 0);
        let mut read = 0;
        while read < length {
            check(stop)?; let end = (read + BLOCK).min(length);
            let got = unistd::read(self.fd(index)?, &mut bytes[read..end]).map_err(native)?;
            need(got > 0 && got <= end - read, Problem::Identity)?; read += got; check(stop)?;
        }
        if full { let mut extra = [0; 1]; check(stop)?; let count = unistd::read(self.fd(index)?, &mut extra).map_err(native)?; check(stop)?; need(count == 0, Problem::Identity)?; }
        need(FileKey::of(&self.stat(index, stop)?, self.uid()?)? == before
            && FileKey::of(&self.named(root, name, stop)?.ok_or(Problem::Identity)?, self.uid()?)? == before, Problem::Identity)?;
        self.check_roots(stop)?;
        Ok(bytes)
    }
    fn observe_locked(&mut self, stop: &mut dyn FnMut() -> bool) -> Result<Observation> {
        need(self.lease_held(), Problem::State)?;
        let inventory = self.inventory(stop)?; let mut state = inventory.inspection();
        let reservation: Option<[u8; format::RESERVATION_BYTES]> = if inventory.reservation && !inventory.malformed {
            let (bytes, original) = self.read_leaf(format::RESERVATION_NAME.as_bytes(), 48, true, stop)?;
            self.reservation_original = Some(original);
            Some(bytes.try_into().map_err(|_| Problem::Corrupt)?)
        } else { None };
        let header: Option<[u8; format::HEADER_BYTES]> = if inventory.header && !inventory.malformed {
            let (bytes, original) = self.read_leaf(format::HEADER_NAME.as_bytes(), 104, true, stop)?;
            self.header_original = Some(original);
            Some(bytes.try_into().map_err(|_| Problem::Corrupt)?)
        } else { None };
        if let Some(reservation) = &reservation {
            match format::Identity::parse_reservation(reservation) {
                Ok(identity) => {
                    self.reserved = Some(identity);
                    if header.as_ref().is_some_and(|bytes| format::Header::parse(bytes, identity).is_err()) { state = Inspection::Corrupt; }
                },
                Err(_) => { state = Inspection::Corrupt; },
            }
        }
        self.check_roots(stop)?;
        Ok(Observation { state, reservation, header, records: inventory.records, root: Some(self.witness()?) })
    }
    /// Preview-side setup makes only the two fixed app-owned private directories
    /// and original lock. It does NOT create a reservation or call the keyring.
    pub(crate) fn prepare_initialize(&mut self, proposed: format::Identity, exclusion: &crate::asset_source::VaultAbsentExclusion,
        stop: &mut dyn FnMut() -> bool) -> Result<RootWitness> {
        self.work(Work::PrepareInitialize, stop, |book, stop| book.prepare_initialize_inner(proposed, exclusion, stop))
    }
    fn prepare_initialize_inner(&mut self, proposed: format::Identity, exclusion: &crate::asset_source::VaultAbsentExclusion,
        stop: &mut dyn FnMut() -> bool) -> Result<RootWitness> {
        need(self.started && !self.retired && self.prepared.is_none() && self.reserved.is_none(), Problem::State)?;
        self.check_roots(stop)?;
        // The owner supplies a fresh complete registered-project probe and
        // serializes its generation. Compare that proof with these ACTUAL
        // held ancestors before either missing private edge can be created.
        // Existing-vault probes already cover the opposite ancestor direction.
        exclude_project_ancestors(self.originals.iter().take(self.retained).filter_map(|original| original.directory),
            exclusion.roots(), stop)?;
        let count = self.location.as_ref().ok_or(Problem::State)?.components.len();
        // Directory originals are one root plus each completed component.
        let mut present = self.originals.iter().filter(|o| o.directory.is_some()).count().checked_sub(1).ok_or(Problem::State)?;
        let mut parent = self.originals.iter().enumerate().rev().find(|(_, o)| o.directory.is_some()).map(|(i, _)| i).ok_or(Problem::State)?;
        while present < count {
            need(present >= count - 2, Problem::Identity)?;
            let name = self.location.as_ref().ok_or(Problem::State)?.components[present].clone();
            need(self.named(parent, &name, stop)?.is_none(), Problem::Identity)?;
            check(stop)?;
            stat::mkdirat(self.fd(parent)?, OsStr::from_bytes(&name), Mode::from_bits_truncate(0o700)).map_err(native)?;
            // A failure/STOP is never permission to adopt an existing directory
            // on retry; this book stays tied to the first actual attempt.
            check(stop)?;
            let child = self.directory(Some(parent), &name, present == count - 1, stop)?;
            self.sync(parent, stop)?; parent = child; present += 1;
            self.retained = self.originals.len();
        }
        self.root = Some(parent); self.retained = self.originals.len();
        if self.lock.is_none() { self.lock(true, stop)?; }
        let inventory = self.inventory(stop)?;
        need(inventory.inspection() == Inspection::Uninitialized && inventory.names.len() == 1 && inventory.lock, Problem::Interrupted)?;
        self.sync(parent, stop)?; self.check_roots(stop)?;
        self.prepared = Some(proposed); self.witness()
    }
    pub(crate) fn cancel_initialize_preview(&mut self) {
        self.prepared = None;
        if self.in_flight.is_some() { self.fail(Problem::State); }
        // This never clears a prior error, adopts a partial setup or renews work.
    }
    /// Consume the exact preview identity before any key creation. A durable or
    /// uncertain reservation is never overwritten/retried as an empty vault.
    pub(crate) fn reserve_prepared_identity(&mut self, stop: &mut dyn FnMut() -> bool) -> Result<format::Identity> {
        self.work(Work::ReserveIdentity, stop, Self::reserve_prepared_identity_inner)
    }
    fn reserve_prepared_identity_inner(&mut self, stop: &mut dyn FnMut() -> bool) -> Result<format::Identity> {
        need(self.lease_held() && self.reserved.is_none(), Problem::State)?;
        let proposed = self.prepared.take().ok_or(Problem::State)?;
        let inventory = self.inventory(stop)?;
        need(inventory.inspection() == Inspection::Uninitialized && inventory.names.len() == 1 && inventory.lock, Problem::Interrupted)?;
        let bytes = proposed.reservation();
        // Publish the fixed reservation exclusively. Any later failure retains
        // it as pending; no cleanup path removes or rebinds this identity.
        self.reserved = Some(proposed);
        let original = self.write_control(format::RESERVATION_NAME.as_bytes(), &bytes, stop)?;
        self.reservation_original = Some(original);
        self.sync_initialization(false, stop)?;
        check(stop)?; Ok(proposed)
    }
    pub(crate) fn publish_header(&mut self, bytes: &[u8; format::HEADER_BYTES], stop: &mut dyn FnMut() -> bool) -> Result<()> {
        self.work(Work::PublishHeader, stop, |book, stop| book.publish_header_inner(bytes, stop))
    }
    fn publish_header_inner(&mut self, bytes: &[u8; format::HEADER_BYTES], stop: &mut dyn FnMut() -> bool) -> Result<()> {
        need(self.lease_held() && self.reservation_sync && !self.header_sync, Problem::State)?;
        let identity = self.reserved.ok_or(Problem::State)?;
        format::Header::parse(bytes, identity).map_err(|_| Problem::Corrupt)?;
        self.check_roots(stop)?;
        let (reservation, original) = self.read_leaf(format::RESERVATION_NAME.as_bytes(), 48, true, stop)?;
        need(reservation == identity.reservation() && Some(original) == self.reservation_original, Problem::Identity)?;
        let inventory = self.inventory(stop)?;
        need(inventory.names.len() == 2 && inventory.lock && inventory.reservation && !inventory.header
            && !inventory.debris && !inventory.intent && !inventory.malformed, Problem::Interrupted)?;
        // The private crypto caller must already have authenticated the actual
        // provider's returned wrapping key against these exact header bytes.
        let original = self.write_control(format::HEADER_NAME.as_bytes(), bytes, stop)?;
        self.header_original = Some(original);
        self.sync_initialization(true, stop)?;
        check(stop)
    }
    pub(crate) fn read_record(&mut self, record: Id, complete: bool, stop: &mut dyn FnMut() -> bool) -> Result<ReadOriginal> {
        self.work(Work::ReadRecord, stop, |book, stop| book.read_record_inner(record, complete, stop))
    }
    fn read_record_inner(&mut self, record: Id, complete: bool, stop: &mut dyn FnMut() -> bool) -> Result<ReadOriginal> {
        need(self.lease_held(), Problem::State)?;
        self.check_controls(stop)?;
        let identity = self.reserved.ok_or(Problem::State)?; let name = record.record_name();
        let (prefix, original) = self.read_leaf(name.as_bytes(), format::RECORD_PREFIX_BYTES, false, stop)?;
        let prefix = format::RecordPrefix::parse(&prefix, identity).map_err(|_| Problem::Corrupt)?;
        need(prefix.record == record && prefix.total_length().map_err(|_| Problem::Bounds)? as u64 == original.bytes, Problem::Corrupt)?;
        let length = if complete { prefix.total_length().map_err(|_| Problem::Bounds)? } else { 232 + prefix.descriptor_length };
        let (bytes, current) = self.read_leaf(name.as_bytes(), length, complete, stop)?;
        need(current == original && bytes.get(..168) == Some(prefix.bytes().as_slice()), Problem::Identity)?;
        let root = self.root.and_then(|index| self.originals[index].directory).ok_or(Problem::State)?;
        Ok(ReadOriginal { bytes, witness: ReadWitness { root, file: original, record, revision: prefix.revision }, complete })
    }
    pub(crate) fn recheck_root(&mut self, stop: &mut dyn FnMut() -> bool) -> Result<RootWitness> {
        self.work(Work::RecheckRoot, stop, |book, stop| { book.check_roots(stop)?; book.witness() })
    }
    pub(crate) fn recheck_record(&mut self, expected: &ReadWitness, stop: &mut dyn FnMut() -> bool) -> Result<()> {
        self.work(Work::RecheckRecord, stop, |book, stop| {
            let current = book.read_record_inner(expected.record, false, stop)?;
            need(current.witness == *expected, Problem::Identity)
        })
    }
    fn check_controls(&mut self, stop: &mut dyn FnMut() -> bool) -> Result<()> {
        let identity = self.reserved.ok_or(Problem::State)?;
        let (reservation, original) = self.read_leaf(format::RESERVATION_NAME.as_bytes(), format::RESERVATION_BYTES, true, stop)?;
        need(Some(original) == self.reservation_original && reservation == identity.reservation(), Problem::Identity)?;
        let (header, original) = self.read_leaf(format::HEADER_NAME.as_bytes(), format::HEADER_BYTES, true, stop)?;
        need(Some(original) == self.header_original, Problem::Identity)?;
        format::Header::parse(&header, identity).map_err(|_| Problem::Corrupt)?;
        Ok(())
    }
    fn check_control_names(&self, stop: &mut dyn FnMut() -> bool) -> Result<()> {
        self.check_roots(stop)?;
        let root = self.root.ok_or(Problem::State)?;
        for (name, original) in [(format::RESERVATION_NAME, self.reservation_original), (format::HEADER_NAME, self.header_original)] {
            let original = original.ok_or(Problem::State)?;
            need(FileKey::of(&self.named(root, name.as_bytes(), stop)?.ok_or(Problem::Identity)?, self.uid()?)? == original, Problem::Identity)?;
        }
        Ok(())
    }
    /// Authenticated bytes are supplied only by the private crypto/owner lane.
    /// This backend proves framing, exact original/revision and native effects;
    /// it never treats a renderer body or a digest as AEAD authentication.
    pub(crate) fn mutate(&mut self, intent: &[u8; format::INTENT_BYTES], candidate: Option<&[u8]>, expected: Option<&ReadWitness>,
        work_stop: &mut dyn FnMut() -> bool, cleanup_expired: &mut dyn FnMut() -> bool) -> Result<StorageOutcome> {
        self.begin(Work::Mutate)?;
        // The previous original owner keeps its own copied outcome. Do not
        // expose a previous success as this admitted call's early failure.
        self.mutation = None; self.mutation_files = None;
        let result = check(work_stop).and_then(|()| self.mutate_inner(intent, candidate, expected, work_stop));
        if let Err(problem) = result { self.fail(problem); }
        if work_stop() { self.fail(Problem::Stopped); }
        let first_at = self.first_at;
        let cleanup = self.cleanup_mutation(&mut || cleanup_expired_at(first_at, cleanup_expired));
        if let Err(problem) = cleanup { self.fail(problem); }
        // Always attempt independent known leaf closes before inspecting native
        // quiescence. An empty FD range cannot settle a pending ACL allocation.
        let leaves_known = self.close_operation_leaves(cleanup_expired);
        let native_quiescent = self.acl.try_borrow().is_ok_and(|book| book.quiescent());
        let originals_known = leaves_known && native_quiescent;
        if let Some(progress) = &mut self.mutation {
            progress.cleanup_returned(mutation_cleanup_known(cleanup.is_ok(), leaves_known, native_quiescent));
        }
        if !originals_known { self.fail(Problem::CleanupUnknown); }
        if work_stop() { self.fail(Problem::Stopped); }
        self.in_flight = None;
        if let Some(problem) = self.first { return Err(problem); }
        if !self.mutation.as_ref().is_some_and(MutationProgress::success) {
            self.fail(Problem::CleanupUnknown); return Err(Problem::CleanupUnknown);
        }
        Ok(self.mutation.as_ref().ok_or(Problem::State)?.outcome)
    }
    fn progress(&mut self) -> Result<&mut MutationProgress> { self.mutation.as_mut().ok_or(Problem::State) }
    fn mutation_files(&self) -> Result<&MutationFiles> { self.mutation_files.as_ref().ok_or(Problem::State) }
    fn mutation_files_mut(&mut self) -> Result<&mut MutationFiles> { self.mutation_files.as_mut().ok_or(Problem::State) }
    fn mutate_inner(&mut self, intent: &[u8; format::INTENT_BYTES], candidate: Option<&[u8]>, expected: Option<&ReadWitness>,
        stop: &mut dyn FnMut() -> bool) -> Result<()> {
        need(self.lease_held() && self.originals.len() == self.retained && self.prepared.is_none(), Problem::State)?;
        let identity = self.reserved.ok_or(Problem::State)?;
        let (prefix, _, _) = format::IntentPrefix::parse_frame(intent, identity).map_err(|_| Problem::Corrupt)?;
        self.mutation = Some(MutationProgress::new(prefix.operation));
        self.mutation_files = Some(MutationFiles { prefix, expected: expected.copied(), target: None, candidate: None, intent: None,
            candidate_ready: None, intent_ready: None, candidate_removed: false, candidate_cleanup_sync: false,
            intent_removed: false, effect_returned: None, effect_verified: false });
        mutation_input(self.mutation_files()?, candidate, stop)?;
        let inventory = self.inventory(stop)?;
        inventory.candidate_budget(candidate.map_or(0, <[u8]>::len))?;
        let files = self.mutation_files()?;
        need(if files.prefix.operation == Mutation::New {
            inventory.records.len() < DESCRIPTOR_COUNT && !inventory.records.contains(&files.prefix.record)
        } else { inventory.records.contains(&files.prefix.record) }, Problem::State)?;
        self.check_controls(stop)?;
        self.hold_mutation_target(stop)?;
        if let Some(bytes) = candidate {
            let name = self.mutation_files()?.prefix.fence.candidate_name();
            let index = self.arm_mutation_leaf(name.as_bytes(), false, stop)?;
            self.mutation_files_mut()?.candidate = Some(index);
            self.open_armed(index, write_flags(), stop)?;
            let original = self.write_held(index, bytes, stop)?;
            self.mutation_files_mut()?.candidate_ready = Some(original);
        }
        self.check_control_names(stop)?;
        self.progress()?.begin_intent()?;
        let index = self.arm_mutation_leaf(format::INTENT_NAME.as_bytes(), false, stop)?;
        self.mutation_files_mut()?.intent = Some(index);
        self.open_armed(index, write_flags(), stop)?;
        let original = self.write_held(index, intent, stop)?;
        self.mutation_files_mut()?.intent_ready = Some(original);
        check(stop)?;
        let root = self.root.ok_or(Problem::State)?;
        let returned = darwin::sync(self.fd(root)?, false);
        if returned.is_ok() { self.progress()?.intent_durable_returned()?; }
        returned.map_err(|_| Problem::DurabilityUnknown)?;
        check(stop)?;
        self.target_unchanged(stop)?;
        self.check_control_names(stop)?;
        let (operation, name, candidate_name, index, ready) = {
            let files = self.mutation_files()?;
            (files.prefix.operation, files.prefix.record.record_name(), files.prefix.fence.candidate_name(), files.candidate, files.candidate_ready)
        };
        if operation != Mutation::Delete { self.check_owned_leaf(index.ok_or(Problem::State)?, candidate_name.as_bytes(), ready, stop)?; }
        let (intent_index, intent_ready) = { let files = self.mutation_files()?; (files.intent, files.intent_ready) };
        self.check_owned_leaf(intent_index.ok_or(Problem::State)?, format::INTENT_NAME.as_bytes(), intent_ready, stop)?;
        check(stop)?;
        #[cfg(all(test,debug_assertions))]
        self.inject(StorageFault::BeforeEffect)?;
        self.progress()?.enter_effect()?;
        let returned = match operation {
            // The existing native single-name RENAME_EXCL primitive admits files
            // too; there is no overwrite-capable fallback for a new record.
            Mutation::New => darwin::publish_directory(self.fd(root)?, &candidate_name, self.fd(root)?, &name).map_err(native_io),
            Mutation::Replace => fcntl::renameat(self.fd(root)?, OsStr::from_bytes(candidate_name.as_bytes()),
                self.fd(root)?, OsStr::from_bytes(name.as_bytes())).map_err(native),
            Mutation::Delete => unistd::unlinkat(self.fd(root)?, OsStr::from_bytes(name.as_bytes()), UnlinkatFlags::NoRemoveDir).map_err(native),
        };
        self.mutation_files_mut()?.effect_returned = Some(returned.is_ok());
        if returned.is_ok() { self.progress()?.applied_returned()?; }
        returned?;
        // A known applied effect is not known durable. Arm that distinction
        // before STOP can prevent entering the one directory sync.
        self.progress()?.enter_effect_sync()?;
        #[cfg(all(test,debug_assertions))]
        self.inject(StorageFault::AfterEffect)?;
        check(stop)?;
        let returned = darwin::sync(self.fd(root)?, false);
        self.progress()?.effect_sync_returned(returned.is_ok())?;
        returned.map_err(|_| Problem::DurabilityUnknown)?;
        #[cfg(all(test,debug_assertions))]
        self.inject(StorageFault::AfterSync)?;
        check(stop)
    }
    fn arm_mutation_leaf(&mut self, name: &[u8], existing: bool, stop: &mut dyn FnMut() -> bool) -> Result<usize> {
        self.check_roots(stop)?;
        let root = self.root.ok_or(Problem::State)?;
        need(self.named(root, name, stop)?.is_some() == existing, Problem::Identity)?;
        self.arm(Some(root), name, false)
    }
    fn hold_mutation_target(&mut self, stop: &mut dyn FnMut() -> bool) -> Result<()> {
        let (record, expected) = { let files = self.mutation_files()?; (files.prefix.record, files.expected) };
        let name = record.record_name();
        if let Some(expected) = expected {
            let root_key = self.root.and_then(|index| self.originals[index].directory).ok_or(Problem::State)?;
            need(root_key == expected.root, Problem::Identity)?;
            let index = self.arm_mutation_leaf(name.as_bytes(), true, stop)?;
            self.mutation_files_mut()?.target = Some(index);
            self.open_armed(index, read_flags(false), stop)?;
        }
        self.target_unchanged(stop)
    }
    fn target_unchanged(&self, stop: &mut dyn FnMut() -> bool) -> Result<()> {
        self.check_roots(stop)?;
        let files = self.mutation_files()?;
        let root = self.root.ok_or(Problem::State)?;
        let name = files.prefix.record.record_name();
        if let Some(expected) = files.expected {
            need(self.originals[root].directory == Some(expected.root), Problem::Identity)?;
            let index = files.target.ok_or(Problem::Identity)?;
            let raw = self.read_held(index, name.as_bytes(), expected.file, format::RECORD_PREFIX_BYTES, false, stop)?;
            let prefix = format::RecordPrefix::parse(&raw, files.prefix.identity).map_err(|_| Problem::Corrupt)?;
            need(prefix.record == expected.record && prefix.revision == expected.revision
                && prefix.total_length().map_err(|_| Problem::Bounds)? as u64 == expected.file.bytes, Problem::Identity)
        } else { need(self.named(root, name.as_bytes(), stop)?.is_none(), Problem::Identity) }
    }
    fn check_owned_leaf(&self, index: usize, name: &[u8], expected: Option<FileKey>, stop: &mut dyn FnMut() -> bool) -> Result<FileKey> {
        self.check_roots(stop)?;
        let root = self.root.ok_or(Problem::State)?;
        let original = self.originals.get(index).ok_or(Problem::State)?;
        need(original.exclusive && original.parent == Some(root) && original.name == name, Problem::Identity)?;
        let held = self.private_leaf(index,stop)?;
        let named = FileKey::of(&self.named(root, name, stop)?.ok_or(Problem::Identity)?, self.uid()?)?;
        need(held == named && expected.is_none_or(|expected| held == expected), Problem::Identity)?;
        Ok(held)
    }
    fn write_held(&self, index: usize, bytes: &[u8], stop: &mut dyn FnMut() -> bool) -> Result<FileKey> {
        need(!bytes.is_empty() && bytes.len() <= format::RECORD_LIMIT, Problem::Bounds)?;
        let name = &self.originals.get(index).ok_or(Problem::State)?.name;
        let fresh = self.check_owned_leaf(index, name, None, stop)?;
        need(fresh.bytes == 0, Problem::Identity)?;
        let mut offset = 0;
        while offset < bytes.len() {
            check(stop)?; let end = (offset + BLOCK).min(bytes.len());
            let count = unistd::write(self.fd(index)?, &bytes[offset..end]).map_err(native)?;
            need(count > 0 && count <= end - offset, Problem::Native)?; offset += count; check(stop)?;
        }
        self.sync(index, stop)?;
        let after = self.check_owned_leaf(index, name, None, stop)?;
        need(after.common == fresh.common && after.bytes == bytes.len() as u64, Problem::Identity)?;
        check(stop)?; need(unistd::lseek(self.fd(index)?, 0, Whence::SeekSet).map_err(native)? == 0, Problem::Identity)?; check(stop)?;
        let mut buffer = [0u8; BLOCK]; let mut offset = 0;
        while offset < bytes.len() {
            check(stop)?; let wanted = (bytes.len() - offset).min(buffer.len());
            let count = unistd::read(self.fd(index)?, &mut buffer[..wanted]).map_err(native)?;
            need(count > 0 && count <= wanted && buffer[..count] == bytes[offset..offset + count], Problem::Identity)?;
            offset += count; check(stop)?;
        }
        check(stop)?; let extra = unistd::read(self.fd(index)?, &mut buffer[..1]).map_err(native)?; check(stop)?;
        need(extra == 0 && self.check_owned_leaf(index, name, Some(after), stop)? == after, Problem::Identity)?;
        Ok(after)
    }
    fn verify_applied(&mut self, stop: &mut dyn FnMut() -> bool) -> Result<()> {
        self.check_control_names(stop)?;
        let root = self.root.ok_or(Problem::State)?;
        let files = self.mutation_files()?;
        need(files.effect_returned == Some(true), Problem::State)?;
        let name = files.prefix.record.record_name();
        if files.prefix.operation == Mutation::Delete {
            need(self.named(root, name.as_bytes(), stop)?.is_none(), Problem::Identity)?;
        } else {
            let index = files.candidate.ok_or(Problem::State)?;
            let expected = files.candidate_ready.ok_or(Problem::State)?;
            let held = self.private_leaf(index,stop)?;
            need(held.common == expected.common && held.bytes == expected.bytes && held.mtime == expected.mtime
                && FileKey::of(&self.named(root, name.as_bytes(), stop)?.ok_or(Problem::Identity)?, self.uid()?)? == held
                && self.named(root, files.prefix.fence.candidate_name().as_bytes(), stop)?.is_none(), Problem::Identity)?;
        }
        if let Some(expected) = files.expected {
            let old = self.stat(files.target.ok_or(Problem::State)?, stop)?;
            need(DirectoryKey::of(&old)? == expected.file.common && old.st_nlink == 0 && old.st_size >= 0
                && old.st_size as u64 == expected.file.bytes && old.st_mtime == expected.file.mtime.0
                && i64::try_from(old.st_mtime_nsec).ok() == Some(expected.file.mtime.1), Problem::Identity)?;
        }
        self.check_roots(stop)?;
        self.mutation_files_mut()?.effect_verified = true; Ok(())
    }
    fn cleanup_mutation(&mut self, expired: &mut dyn FnMut() -> bool) -> Result<()> {
        let Some(progress) = &self.mutation else { return Ok(()); };
        let effect = progress.outcome.effect; let durability = progress.outcome.durability;
        if effect == Effect::KnownApplied {
            // Unconfirmed durability keeps the intent. No rollback or retry.
            if durability != Durability::Confirmed { return Ok(()); }
            self.verify_applied(expired)?;
            return self.clear_intent(expired);
        }
        let files = self.mutation_files()?;
        if files.candidate.is_none() && files.intent.is_none() && files.effect_returned.is_none()
            && self.mutation.as_ref().is_some_and(|progress| progress.fence == Fence::Absent) {
            return Ok(()); // No candidate/fence/effect call was entered.
        }
        self.target_unchanged(expired)?;
        self.cleanup_candidate(expired)?;
        self.target_unchanged(expired)?;
        self.progress()?.no_effect_proved(&NoEffectProof { target_original_unchanged: true, candidate_cleanup_known: true })?;
        self.clear_intent(expired)
    }
    fn cleanup_candidate(&mut self, expired: &mut dyn FnMut() -> bool) -> Result<()> {
        let (index, name, ready, removed) = { let files = self.mutation_files()?;
            (files.candidate, files.prefix.fence.candidate_name(), files.candidate_ready, files.candidate_removed) };
        need(!removed, Problem::State)?;
        let root = self.root.ok_or(Problem::State)?;
        let Some(index) = index else { return Ok(()); };
        if self.no_original(index)? {
            need(self.named(root, name.as_bytes(), expired)?.is_none(), Problem::CleanupUnknown)?;
            return Ok(());
        }
        self.check_owned_leaf(index, name.as_bytes(), ready, expired)?;
        check(expired)?;
        let returned = unistd::unlinkat(self.fd(root)?, OsStr::from_bytes(name.as_bytes()), UnlinkatFlags::NoRemoveDir);
        if returned.is_ok() { self.mutation_files_mut()?.candidate_removed = true; }
        returned.map_err(native)?;
        check(expired)?;
        let returned = darwin::sync(self.fd(root)?, false);
        if returned.is_ok() { self.mutation_files_mut()?.candidate_cleanup_sync = true; }
        returned.map_err(|_| Problem::DurabilityUnknown)?;
        check(expired)?;
        need(self.named(root, name.as_bytes(), expired)?.is_none(), Problem::CleanupUnknown)?;
        self.check_roots(expired)
    }
    fn no_original(&self, index: usize) -> Result<bool> {
        let original = self.originals.get(index).ok_or(Problem::State)?;
        match original.state {
            OriginalState::Reserved | OriginalState::NoHandle if original.fd.is_none() => Ok(true),
            OriginalState::Owned if original.fd.is_some() => Ok(false),
            _ => Err(Problem::CleanupUnknown),
        }
    }
    fn clear_intent(&mut self, expired: &mut dyn FnMut() -> bool) -> Result<()> {
        if self.mutation.as_ref().is_some_and(|progress| progress.fence == Fence::Absent) { return Ok(()); }
        let (index, ready, removed) = { let files = self.mutation_files()?; (files.intent, files.intent_ready, files.intent_removed) };
        need(!removed, Problem::State)?;
        let root = self.root.ok_or(Problem::State)?;
        let absent = match index { Some(index) => self.no_original(index)?, None => true };
        if absent {
            self.check_roots(expired)?;
            need(self.named(root, format::INTENT_NAME.as_bytes(), expired)?.is_none(), Problem::CleanupUnknown)?;
            check(expired)?;
            let returned = darwin::sync(self.fd(root)?, false);
            returned.map_err(|_| Problem::DurabilityUnknown)?;
            check(expired)?;
            need(self.named(root, format::INTENT_NAME.as_bytes(), expired)?.is_none(), Problem::CleanupUnknown)?;
            self.progress()?.absent_intent_proved(&AbsentIntentProof { no_intent_original: true,
                current_absence_confirmed: true, directory_sync_confirmed: true })?;
            return self.check_roots(expired);
        }
        self.check_owned_leaf(index.ok_or(Problem::State)?, format::INTENT_NAME.as_bytes(), ready, expired)?;
        check(expired)?;
        #[cfg(all(test,debug_assertions))]
        self.inject(StorageFault::BeforeClear)?;
        self.progress()?.enter_clear(true)?;
        let returned = unistd::unlinkat(self.fd(root)?, OsStr::from_bytes(format::INTENT_NAME.as_bytes()), UnlinkatFlags::NoRemoveDir);
        if returned.is_ok() { self.mutation_files_mut()?.intent_removed = true; }
        returned.map_err(native)?;
        #[cfg(all(test,debug_assertions))]
        self.inject(StorageFault::AfterClear)?;
        check(expired)?;
        let returned = darwin::sync(self.fd(root)?, false);
        self.progress()?.clear_sync_returned(returned.is_ok())?;
        returned.map_err(|_| Problem::DurabilityUnknown)?;
        check(expired)?;
        need(self.named(root, format::INTENT_NAME.as_bytes(), expired)?.is_none(), Problem::CleanupUnknown)?;
        self.check_roots(expired)
    }
    fn close_operation_leaves(&mut self, expired: &mut dyn FnMut() -> bool) -> bool {
        if self.retained > self.originals.len() { self.close_failed = true; return false; }
        let mut known = true;
        for index in (self.retained..self.originals.len()).rev() {
            if matches!(self.originals[index].state, OriginalState::Reserved | OriginalState::NoHandle | OriginalState::Closed)
                && self.originals[index].fd.is_none() {
                if let Err(problem) = self.close(index) { self.fail(problem); known = false; }
                continue;
            }
            if cleanup_expired_at(self.first_at, expired) { self.fail(Problem::Stopped); known = false; continue; }
            if let Err(problem) = self.close(index) { self.fail(problem); known = false; }
            if cleanup_expired_at(self.first_at, expired) { self.fail(Problem::Stopped); known = false; }
        }
        if known && self.discard_closed_leaves().is_err() { known = false; }
        known
    }
    fn sync(&self, index: usize, stop: &mut dyn FnMut() -> bool) -> Result<()> {
        check(stop)?;
        let file=self.originals.get(index).ok_or(Problem::State)?.directory.is_none();
        darwin::sync(self.fd(index)?,file).map_err(native_io)?;
        check(stop)
    }
    fn sync_initialization(&mut self, header: bool, stop: &mut dyn FnMut() -> bool) -> Result<()> {
        check(stop)?;
        let returned = darwin::sync(self.fd(self.root.ok_or(Problem::State)?)?, false);
        // Record the actual directory-sync return before a late STOP. These
        // durability facts never authorize a second work call after failure.
        if returned.is_ok() { if header { self.header_sync = true; } else { self.reservation_sync = true; } }
        returned.map_err(|_| Problem::DurabilityUnknown)?;
        check(stop)
    }
    fn write_control(&mut self, name: &[u8], bytes: &[u8], stop: &mut dyn FnMut() -> bool) -> Result<FileKey> {
        let expected = match Name::parse(name)? {
            Name::Reservation => format::RESERVATION_BYTES, Name::Header => format::HEADER_BYTES,
            _ => return Err(Problem::State),
        };
        need(bytes.len() == expected && self.originals.len() == self.retained, Problem::State)?;
        self.check_roots(stop)?; let root = self.root.ok_or(Problem::State)?;
        need(self.named(root, name, stop)?.is_none(), Problem::Identity)?;
        let index = self.open(Some(root), name, write_flags(), false, stop)?;
        let after = self.write_held(index, bytes, stop)?;
        self.close(index)?; self.discard_closed_leaves()?; self.check_roots(stop)?;
        need(FileKey::of(&self.named(root, name, stop)?.ok_or(Problem::Identity)?, self.uid()?)? == after, Problem::Identity)?;
        Ok(after)
    }
    fn close(&mut self, index: usize) -> Result<()> {
        let original = self.originals.get_mut(index).ok_or(Problem::State)?;
        match original.state {
            OriginalState::Reserved => { original.state = OriginalState::NoHandle; return Ok(()); },
            OriginalState::NoHandle | OriginalState::Closed => return Ok(()),
            OriginalState::Owned => {},
            _ => { self.close_failed = true; return Err(Problem::CleanupUnknown); },
        }
        let consumed = match self.consumed.checked_add(1) { Some(value) => value, None => { self.close_failed = true; return Err(Problem::Bounds); } };
        original.state = OriginalState::Closing;
        let Some(fd) = original.fd.take() else { original.state = OriginalState::Unknown; self.close_failed = true; return Err(Problem::CleanupUnknown); };
        let returned = nix::unistd::close(ManuallyDrop::into_inner(fd));
        self.consumed = consumed;
        if returned.is_err() { original.state = OriginalState::Unknown; self.close_failed = true; return Err(Problem::CleanupUnknown); }
        original.state = OriginalState::Closed; Ok(())
    }
    fn discard_closed_leaves(&mut self) -> Result<()> {
        need(!self.close_failed && self.retained <= self.originals.len() && self.originals[self.retained..].iter().all(|original|
            original.fd.is_none() && matches!(original.state, OriginalState::Closed | OriginalState::NoHandle)), Problem::CleanupUnknown)?;
        self.originals.truncate(self.retained); Ok(())
    }
    /// Close each original at most once; one failure does not skip other known
    /// independent originals. The caller supplies its existing cleanup endpoint.
    /// Expired cleanup retains ownership, not an inferred close receipt.
    pub(crate) fn release(&mut self, expired: &mut dyn FnMut() -> bool) -> bool {
        if self.retired { return self.settled(); }
        self.prepared = None;
        if self.in_flight.is_some() { self.fail(Problem::CleanupUnknown); }
        let first=self.first_observed().map(|value| value.1);
        let native_settled=self.acl.get_mut().release(&mut |native_first| {
            let native_first=native_first.map(|value| value.1);
            let earliest=match (first,native_first) { (Some(a),Some(b)) => Some(a.min(b)), (a,b) => a.or(b) };
            cleanup_expired_at(earliest,expired)
        });
        if !native_settled { self.fail(Problem::CleanupUnknown); }
        else if self.problem().is_some() { self.fail(self.problem().unwrap_or(Problem::CleanupUnknown)); }
        // Even after a native ACL free failed, close every other known original
        // FD while its ORIGINAL cleanup endpoint remains. FD close cannot settle ACL uncertainty.
        for index in (0..self.originals.len()).rev() {
            if matches!(self.originals[index].state, OriginalState::Reserved | OriginalState::NoHandle | OriginalState::Closed)
                && self.originals[index].fd.is_none() {
                if let Err(problem) = self.close(index) { self.fail(problem); }
                continue;
            }
            if cleanup_expired_at(self.first_at, expired) { self.fail(Problem::Stopped); continue; }
            if let Err(problem) = self.close(index) { self.fail(problem); }
            // A late endpoint is a failure, not permission to forget an actual
            // positive consuming close. Unclosed originals remain in the book.
            if cleanup_expired_at(self.first_at, expired) { self.fail(Problem::Stopped); }
        }
        self.retired = true;
        if self.settled() { self.lock_held = false; }
        self.settled()
    }
}

// A successfully reusable native frame may remain allocated. Quiescence, not
// frame retirement, proves that no filesec/ACL/qualifier original is pending.
fn mutation_cleanup_known(cleanup_complete: bool, leaves_known: bool, native_quiescent: bool) -> bool {
    cleanup_complete && leaves_known && native_quiescent
}

fn mutation_input(files: &MutationFiles, candidate: Option<&[u8]>, stop: &mut dyn FnMut() -> bool) -> Result<()> {
    check(stop)?;
    let prefix = &files.prefix;
    need(files.expected.map(|expected| expected.revision) == prefix.expected
        && files.expected.is_none_or(|expected| expected.record == prefix.record), Problem::Identity)?;
    if prefix.operation == Mutation::Delete { return need(candidate.is_none(), Problem::Identity); }
    let candidate = candidate.ok_or(Problem::Identity)?;
    need(candidate.len() == prefix.candidate_length && candidate.len() <= format::RECORD_LIMIT, Problem::Bounds)?;
    let record = format::RecordPrefix::parse(candidate.get(..format::RECORD_PREFIX_BYTES).ok_or(Problem::Corrupt)?, prefix.identity)
        .map_err(|_| Problem::Corrupt)?;
    need(record.record == prefix.record && Some(record.revision) == prefix.proposed
        && record.total_length().map_err(|_| Problem::Bounds)? == candidate.len(), Problem::Identity)?;
    let mut digest = Sha256::new();
    for block in candidate.chunks(BLOCK) { check(stop)?; digest.update(block); }
    need(<[u8; 32]>::from(digest.finalize()) == prefix.candidate_digest, Problem::Identity)?;
    check(stop)
}

fn read_flags(directory: bool) -> OFlags {
    let flags = OFlags::O_RDONLY | OFlags::O_CLOEXEC | OFlags::O_NOFOLLOW | OFlags::O_NONBLOCK;
    if directory { flags | OFlags::O_DIRECTORY } else { flags }
}
fn write_flags() -> OFlags { OFlags::O_RDWR | OFlags::O_CREAT | OFlags::O_EXCL | OFlags::O_CLOEXEC | OFlags::O_NOFOLLOW | OFlags::O_NONBLOCK }


#[cfg(all(test,debug_assertions))]
mod tests {
    use super::*;
    fn id(byte:u8) -> Id { Id::from_bytes([byte;16]).unwrap() }
    fn identity() -> format::Identity { format::Identity::new(id(1),id(2)).unwrap() }
    fn record(revision:format::Revision) -> Vec<u8> {
        let prefix=format::RecordPrefix::new(identity(),id(3),revision,1,8,[[10;24],[11;24],[12;24]]).unwrap();
        let mut bytes=vec![0;prefix.total_length().unwrap()];
        bytes[..format::RECORD_PREFIX_BYTES].copy_from_slice(prefix.bytes()); bytes
    }
    fn intent(operation:Mutation, fence:u8, expected:Option<format::Revision>, proposed:Option<format::Revision>,
        candidate:Option<&[u8]>) -> [u8;format::INTENT_BYTES] {
        let digest=candidate.map_or([0;32],|bytes| Sha256::digest(bytes).into());
        let prefix=format::IntentPrefix::new(identity(),operation,id(fence),id(3),expected,proposed,digest,candidate.map_or(0,<[u8]>::len)).unwrap();
        let mut bytes=[0;format::INTENT_BYTES]; bytes[..format::INTENT_PREFIX_BYTES].copy_from_slice(prefix.bytes()); bytes
    }
    #[test]
    fn apfs_policy_and_fixed_namespace_refuse_ambiguous_census_data() {
        assert!(admitted_filesystem("apfs",MntFlags::MNT_LOCAL));
        for flags in [MntFlags::empty(),MntFlags::MNT_LOCAL|MntFlags::MNT_UNION,
            MntFlags::MNT_LOCAL|MntFlags::MNT_AUTOMOUNTED,MntFlags::MNT_LOCAL|MntFlags::MNT_IGNORE_OWNERSHIP] {
            assert!(!admitted_filesystem("apfs",flags));
        }
        assert!(!admitted_filesystem("hfs",MntFlags::MNT_LOCAL));
        let mut names=BTreeSet::new();
        assert!(names.insert(namespace_fold(b"vault-lock").unwrap()));
        assert!(!names.insert(namespace_fold(b"VAULT-LOCK").unwrap()));
        for name in [b"".as_slice(),b".",b"..",b"a/b",b"a\0b",b"\xc3\xa9"] { assert!(namespace_fold(name).is_err()); }
        let mut entry=7u64.to_ne_bytes().to_vec(); entry.push(8); entry.extend_from_slice(&10u16.to_ne_bytes()); entry.extend_from_slice(b"vault-lock");
        assert!(matches!(directory_entry(&entry,0),Ok((7,8,b"vault-lock",21))));
        for length in 0..entry.len() { assert!(directory_entry(&entry[..length],0).is_err()); }
        assert!(directory_entry(&entry,usize::MAX).is_err());
    }
    #[test]
    fn missing_vault_proof_checks_every_original_ancestor_without_path_text() {
        let ancestor=DirectoryKey { dev:3,ino:5,mode:0o40700,uid:501,gid:20,flags:0 };
        let project=crate::asset_source::DirectoryIdentity::vault_original(3,5,0o40755,502,20);
        assert_eq!(exclude_project_ancestors([ancestor].into_iter(),&[project],&mut || false),Err(Problem::Identity));
        assert!(exclude_project_ancestors([DirectoryKey { dev:4,..ancestor }].into_iter(),&[project],&mut || false).is_ok());
        assert_eq!(exclude_project_ancestors([ancestor].into_iter(),&[],&mut || true),Err(Problem::Stopped));
    }
    #[test]
    fn mutation_cleanup_projection_requires_native_quiescence_even_without_leaf_fds() {
        for (cleanup, leaves, quiescent, expected) in [
            (true, true, false, Cleanup::Unknown), // Pending/unknown native original.
            (true, false, true, Cleanup::Unknown), // Independent FD close failed.
            (false, true, true, Cleanup::Unknown), // Original mutation cleanup failed.
            (true, true, true, Cleanup::Known), // Reusable allocated frame is fine.
        ] {
            let mut progress = MutationProgress::new(Mutation::New);
            progress.stop(); // Early failure: no candidate, intent or effect.
            assert!(progress.fence == Fence::Absent);
            progress.cleanup_returned(mutation_cleanup_known(cleanup, leaves, quiescent));
            assert_eq!(progress.outcome.effect, Effect::NotStarted);
            assert_eq!(progress.outcome.cleanup, expected);
            assert!(!progress.success()); // Cleanup never clears the first STOP.
        }
    }
    #[test]
    fn mac_book_first_failure_and_native_frame_charge_are_not_finality() {
        let mut book=StoreBook::new();
        let before=book.retained_bytes().unwrap(); assert!(before >= std::mem::size_of::<StoreBook>());
        assert!(book.operation_quiescent() && book.not_started() && !book.settled());
        book.fail(Problem::Native); let first=book.problem_at().unwrap();
        book.fail(Problem::Stopped); assert_eq!(book.problem_at(),Some(first)); assert_eq!(book.problem(),Some(Problem::Native));
        assert!(!first_failure_expired(Some(first),first+FAILURE_CLEANUP-Duration::from_nanos(1)));
        assert!(first_failure_expired(Some(first),first+FAILURE_CLEANUP));
        assert!(book.reserve_prepared_identity(&mut || panic!("failure must refuse before work")).is_err());
        assert!(book.release(&mut || false)); assert!(book.settled());
        assert!(book.retained_bytes().unwrap() <= before); assert_eq!(book.problem_at(),Some(first));
    }

    // Explicitly ignored, credential-free APFS integration fixture. Root's
    // reviewed native owner supplies a NEW EMPTY private directory, selects this
    // one test, retains its process/join evidence and cleans only that tree.
    // No automatic system-temp search, Keychain access, process launch, Store
    // mutation, permission repair or recursive deletion exists here.
    #[test]
    #[ignore = "requires reviewed ordinary macOS26 ARM64 private APFS fixture owner"]
    fn native_apfs_storage_lifecycle() {
        let fixture=PathBuf::from(std::env::var_os("MRK_MACOS_VAULT_FIXTURE_ROOT").expect("explicit private fixture required"));
        let end=Instant::now()+Duration::from_secs(30); let cleanup_end=end+FAILURE_CLEANUP;
        let mut stop=|| Instant::now() >= end; let mut cleanup=|| Instant::now() >= cleanup_end;
        let application=fixture.join(OsStr::from_bytes(APPLICATION));
        let mut owner=StoreBook::new();
        let empty=owner.inspect(Location::application_data(&application).unwrap(),&mut stop).unwrap();
        assert!(empty.state == Inspection::Uninitialized && empty.root.is_none());
        let root=owner.originals.iter().enumerate().rev().find(|(_,original)| original.directory.is_some()).unwrap().0;
        let root_key=owner.originals[root].directory.unwrap();
        assert!(root_key.directory(owner.uid().unwrap(),true));
        let mut buffer=[0u8;BLOCK];
        assert_eq!(unistd::lseek(owner.fd(root).unwrap(),0,Whence::SeekSet).unwrap(),0);
        assert_eq!(darwin::directory_block(owner.fd(root).unwrap(),&mut buffer).unwrap(),0);

        // STOP after actual filesec allocation keeps original native custody;
        // same-endpoint cleanup retires it without consuming the borrowed FD.
        let mut acl=SnapshotBook::new(); let mut points=0;
        assert_eq!(acl.observe(owner.fd(root).unwrap(),root_key.acl_expected(),AclPolicy::Empty,
            &mut || { points+=1; points==3 || stop() }),Err(AclFailure::Stopped));
        assert!(!acl.quiescent()); let first=acl.first_failure().unwrap().1;
        assert!(acl.release(&mut |observed| {
            assert_eq!(observed.unwrap().1,first); cleanup_expired_at(Some(first),&mut cleanup)
        }));
        assert!(acl.settled()); assert!(stat::fstat(owner.fd(root).unwrap()).is_ok());

        for (name,fault) in [("normal",None),("early-acl-stop",Some(StorageFault::AfterAclAllocation)),
            ("before-effect",Some(StorageFault::BeforeEffect)),
            ("after-effect",Some(StorageFault::AfterEffect)),("after-sync",Some(StorageFault::AfterSync)),
            ("before-clear",Some(StorageFault::BeforeClear)),("after-clear",Some(StorageFault::AfterClear)),
            ("reserved",None),("debris",None),("stale",None)] {
            owner.check_roots(&mut stop).unwrap();
            assert!(owner.named(root,name.as_bytes(),&mut stop).unwrap().is_none());
            stat::mkdirat(owner.fd(root).unwrap(),name,Mode::from_bits_truncate(0o700)).unwrap();
            let app=fixture.join(name).join(OsStr::from_bytes(APPLICATION));
            let mut book=StoreBook::new();
            let initial=book.inspect(Location::application_data(&app).unwrap(),&mut stop).unwrap();
            assert!(initial.state == Inspection::Uninitialized && initial.root.is_none());
            let mut source=crate::asset_source::SourceBook::new();
            let absent=crate::asset_source::probe_vault_exclusion(&mut source,None,&[],&mut stop).unwrap();
            assert!(source.settled());
            let witness=book.prepare_initialize(identity(),&absent,&mut stop).unwrap();
            let registered=witness.registered();
            // Both exact and reciprocal overlap are actual original probes.
            let mut overlap=crate::asset_source::SourceBook::new();
            assert!(matches!(crate::asset_source::probe_vault_exclusion(&mut overlap,Some(&registered),
                std::slice::from_ref(&registered),&mut stop),Err(crate::asset_commands::Reason::ProjectOverlap)));
            assert!(overlap.settled());
            assert!(book.reserve_prepared_identity(&mut stop).unwrap() == identity());
            if name == "reserved" {
                assert!(book.release(&mut cleanup));
                let mut restarted=StoreBook::new();
                let found=restarted.inspect(Location::application_data(&app).unwrap(),&mut stop).unwrap();
                assert!(found.state == Inspection::Interrupted && found.reservation.is_some() && found.header.is_none());
                assert!(restarted.release(&mut cleanup)); continue;
            }
            let mut header=[0;format::HEADER_BYTES]; header[..64].copy_from_slice(&identity().header_prefix());
            // Deliberate framing-only buffers. These are NOT authenticated vault
            // bytes, a provider result, production credentials or a ready UI.
            book.publish_header(&header,&mut stop).unwrap();
            let mut other=StoreBook::new();
            assert!(matches!(other.inspect(Location::application_data(&app).unwrap(),&mut stop),Err(Problem::Busy)));
            assert!(other.release(&mut cleanup)); assert!(book.lease_held());
            let revision=format::Revision::new(id(4),1).unwrap();
            let candidate=record(revision);
            let new=intent(Mutation::New,6,None,Some(revision),Some(&candidate));
            if name == "debris" {
                let at=book.open(Some(book.root.unwrap()),b"unknown-owned-fixture",write_flags(),false,&mut stop).unwrap();
                book.write_held(at,b"inert-fixture",&mut stop).unwrap();
                book.close(at).unwrap(); book.discard_closed_leaves().unwrap();
                assert!(book.mutate(&new,Some(&candidate),None,&mut stop,&mut cleanup).is_err());
                assert!(book.named(book.root.unwrap(),b"unknown-owned-fixture",&mut cleanup).unwrap().is_some());
                assert!(book.release(&mut cleanup)); continue;
            }
            assert!(book.acl.borrow().quiescent() && book.retained_bytes().is_some());
            book.fault=fault;
            let result=book.mutate(&new,Some(&candidate),None,&mut stop,&mut cleanup);
            if fault == Some(StorageFault::AfterAclAllocation) {
                assert!(matches!(result,Err(Problem::Stopped)));
                assert_eq!(book.storage_outcome().unwrap(),StorageOutcome {
                    effect:Effect::NotStarted,durability:Durability::NotRun,cleanup:Cleanup::Unknown });
                assert!(book.mutation.as_ref().unwrap().fence == Fence::Absent);
                let files=book.mutation_files.as_ref().unwrap();
                assert!(files.candidate.is_none() && files.intent.is_none() && files.effect_returned.is_none());
                assert_eq!(book.originals.len(),book.retained); // No leaf close could settle the ACL original.
                let (reason,first)=book.acl.borrow().first_failure().unwrap();
                assert_eq!(reason,AclFailure::Stopped);
                assert!(!book.acl.borrow().quiescent() && !book.operation_quiescent());
                assert!(book.retained_bytes().is_none()); // Opaque native allocation is not zero bytes.
                assert_eq!(book.problem_at(),Some(first));
                assert!(book.release(&mut cleanup)); // Actual original settlement, under the same endpoint.
                assert!(book.settled() && book.retained_bytes().is_some());
                assert_eq!(book.problem_at(),Some(first));
                assert_eq!(book.storage_outcome().unwrap().cleanup,Cleanup::Unknown); // No retrospective pass.
                continue;
            }
            if let Some(fault)=fault {
                assert!(result.is_err()); let outcome=book.storage_outcome().unwrap();
                assert_eq!(outcome.effect,if fault == StorageFault::BeforeEffect { Effect::KnownNone } else { Effect::KnownApplied });
                assert!(!book.mutation.as_ref().unwrap().success());
                assert_eq!(outcome.durability,match fault {
                    StorageFault::BeforeEffect => Durability::NotRun,
                    StorageFault::AfterEffect => Durability::Unknown,
                    _ => Durability::Confirmed,
                });
                assert_eq!(outcome.cleanup,if matches!(fault,StorageFault::BeforeClear|StorageFault::AfterClear) {
                    Cleanup::Unknown
                } else { Cleanup::Known });
                let intent_exists=book.named(book.root.unwrap(),format::INTENT_NAME.as_bytes(),&mut cleanup).unwrap().is_some();
                assert_eq!(intent_exists,matches!(fault,StorageFault::AfterEffect|StorageFault::BeforeClear));
                assert!(book.release(&mut cleanup)); continue;
            }
            assert_eq!(result.unwrap(),StorageOutcome { effect:Effect::KnownApplied,durability:Durability::Confirmed,cleanup:Cleanup::Known });
            let (actual,expected,complete)=book.read_record(id(3),true,&mut stop).unwrap().into_parts();
            assert!(complete && actual == candidate); book.recheck_record(&expected,&mut stop).unwrap();
            let next_revision=format::Revision::new(id(5),2).unwrap(); let replacement=record(next_revision);
            let replace=intent(Mutation::Replace,7,Some(revision),Some(next_revision),Some(&replacement));
            book.mutate(&replace,Some(&replacement),Some(&expected),&mut stop,&mut cleanup).unwrap();
            if name == "stale" {
                assert!(book.mutate(&replace,Some(&replacement),Some(&expected),&mut stop,&mut cleanup).is_err());
                assert!(book.named(book.root.unwrap(),format::INTENT_NAME.as_bytes(),&mut cleanup).unwrap().is_none());
                assert!(book.release(&mut cleanup)); continue;
            }
            let (actual,current,complete)=book.read_record(id(3),true,&mut stop).unwrap().into_parts();
            assert!(complete && actual == replacement);
            let delete=intent(Mutation::Delete,8,Some(next_revision),None,None);
            book.mutate(&delete,None,Some(&current),&mut stop,&mut cleanup).unwrap();
            let observed=book.observe_locked(&mut stop).unwrap();
            assert!(observed.records.is_empty() && observed.state == Inspection::Locked);
            assert!(book.release(&mut cleanup)); assert!(book.settled());
        }
        assert!(owner.release(&mut cleanup)); assert!(owner.settled());
        // Synthetic outputs remain only for the original native owner's
        // postcondition/evidence collection and identity-bound task cleanup.
    }
}
