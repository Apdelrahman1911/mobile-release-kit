//! Original Linux fd custody for the fixed application-private vault directory.
//! This book is retained outside the blocking worker by OriginalWork. There is
//! no Drop-based close receipt, path-suffix cleanup, automatic repair or retry.
use super::*;
use std::{ffi::OsStr, mem::{ManuallyDrop, MaybeUninit}, os::{fd::{AsFd, BorrowedFd, OwnedFd}, unix::ffi::OsStrExt}, path::{Path, PathBuf}, time::{Duration, Instant}};
use rustix::{fs::{self, AtFlags, FileType, FlockOperation, Mode, OFlags, RawDir, RenameFlags, Stat}, io::{self, Errno}};
use sha2::{Digest, Sha256};

const APPLICATION: &[u8] = b"dev.mobile-release-kit.desktop";
const VAULT: &[u8] = b"credential-vault-v1";
const COMPONENTS: usize = 128;
const ORIGINALS: usize = COMPONENTS + 8;
const BLOCK: usize = 64 * 1024;
const FAILURE_CLEANUP: Duration = Duration::from_secs(2);

fn check(stop: &mut dyn FnMut() -> bool) -> Result<()> { if stop() { Err(Problem::Stopped) } else { Ok(()) } }
fn native(error: Errno) -> Problem { if error == Errno::WOULDBLOCK { Problem::Busy } else { Problem::Native } }
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
struct DirectoryKey { dev: u64, ino: u64, mode: u32, uid: u32, gid: u32 }
impl DirectoryKey {
    fn of(stat: &Stat) -> Self { Self { dev: stat.st_dev, ino: stat.st_ino, mode: stat.st_mode, uid: stat.st_uid, gid: stat.st_gid } }
    fn same_object(self, other: Self) -> bool { self.dev == other.dev && self.ino == other.ino }
    fn directory(self, uid: u32, private: bool) -> bool {
        FileType::from_raw_mode(self.mode) == FileType::Directory
            && if private { self.uid == uid && self.mode & 0o7777 == 0o700 }
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
        need(FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile && stat.st_uid == uid
            && stat.st_mode & 0o7777 == 0o600 && stat.st_nlink == 1 && stat.st_size >= 0, Problem::Identity)?;
        // rustix's Linux-raw Stat uses unsigned nanoseconds, unlike libc's
        // FileStat. Reject unrepresentable/invalid values instead of casting.
        let modified = i64::try_from(stat.st_mtime_nsec).map_err(|_| Problem::Identity)?;
        let changed = i64::try_from(stat.st_ctime_nsec).map_err(|_| Problem::Identity)?;
        need((0..1_000_000_000).contains(&modified) && (0..1_000_000_000).contains(&changed), Problem::Identity)?;
        Ok(Self { common: DirectoryKey::of(stat), links: stat.st_nlink, bytes: stat.st_size as u64,
            mtime: (stat.st_mtime, modified), ctime: (stat.st_ctime, changed) })
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
        let root = DirectoryKey { dev: 0, ino: 0, mode: 0, uid: 0, gid: 0 };
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
    originals: Vec<Original>, location: Option<Location>, uid: Option<u32>, root: Option<usize>, lock: Option<usize>,
    retained: usize, consumed: u64, started: bool, retired: bool, close_failed: bool, lock_held: bool,
    prepared: Option<format::Identity>, reserved: Option<format::Identity>,
    reservation_sync: bool, header_sync: bool,
    reservation_entered: bool, reservation_applied: bool, header_entered: bool, header_applied: bool,
    reservation_original: Option<FileKey>, header_original: Option<FileKey>,
    first: Option<Problem>, first_at: Option<Instant>, in_flight: Option<Work>, mutation: Option<MutationProgress>, mutation_files: Option<MutationFiles>,
}
impl StoreBook {
    pub(crate) fn new() -> Self {
        Self { originals: Vec::new(), location: None, uid: None, root: None, lock: None, retained: 0, consumed: 0,
            started: false, retired: false, close_failed: false, lock_held: false,
            prepared: None, reserved: None, reservation_sync: false, header_sync: false,
            reservation_entered: false, reservation_applied: false, header_entered: false, header_applied: false,
            reservation_original: None, header_original: None, first: None, first_at: None, in_flight: None,
            mutation: None, mutation_files: None }
    }
    pub(crate) fn not_started(&self) -> bool { !self.started && self.originals.is_empty() && self.first.is_none() && self.in_flight.is_none() }
    pub(crate) fn settled(&self) -> bool {
        self.retired && !self.close_failed && self.originals.iter().all(|original|
            original.fd.is_none() && matches!(original.state, OriginalState::Closed | OriginalState::NoHandle))
    }
    pub(crate) fn lease_held(&self) -> bool { self.started && !self.retired && !self.close_failed && self.root.is_some() && self.lock_held }
    pub(crate) fn problem(&self) -> Option<Problem> { self.first }
    pub(crate) fn problem_at(&self) -> Option<Instant> { self.first_at }
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
        self.in_flight.is_none() && !self.close_failed && self.retained <= self.originals.len()
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
        let mut count = std::mem::size_of::<Self>().checked_add(self.originals.capacity().checked_mul(std::mem::size_of::<Original>())?)?;
        for original in &self.originals { count = count.checked_add(original.name.capacity())?; }
        if let Some(location) = &self.location {
            count = count.checked_add(location.path.capacity())?
                .checked_add(location.components.capacity().checked_mul(std::mem::size_of::<Vec<u8>>())?)?;
            for name in &location.components { count = count.checked_add(name.capacity())?; }
        }
        Some(count)
    }
    fn fail(&mut self, problem: Problem) {
        if self.first.is_none() { self.first = Some(problem); self.first_at = Some(Instant::now()); }
        if let Some(progress) = &mut self.mutation {
            if problem == Problem::Stopped { progress.stop(); } else { progress.fail(problem); }
        }
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
        let mode = if flags.contains(OFlags::CREATE) { Mode::from_raw_mode(0o600) } else { Mode::empty() };
        self.originals[index].exclusive = flags.contains(OFlags::CREATE | OFlags::EXCL);
        let reservation = self.originals[index].exclusive && parent == self.root && name == format::RESERVATION_NAME.as_bytes();
        let header = self.originals[index].exclusive && parent == self.root && name == format::HEADER_NAME.as_bytes();
        if reservation { self.reservation_entered = true; }
        if header { self.header_entered = true; }
        self.originals[index].state = OriginalState::Entered;
        let returned = match parent {
            Some(parent) => fs::openat(self.fd(parent)?, OsStr::from_bytes(&name), flags, mode),
            None => fs::open("/", flags, mode),
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
        let result = fs::statat(self.fd(parent)?, OsStr::from_bytes(name), AtFlags::SYMLINK_NOFOLLOW);
        let result = match result { Ok(value) => Some(value), Err(Errno::NOENT) => None, Err(error) => return Err(native(error)) };
        check(stop)?; Ok(result)
    }
    fn stat(&self, index: usize, stop: &mut dyn FnMut() -> bool) -> Result<Stat> {
        check(stop)?; let returned = fs::fstat(self.fd(index)?).map_err(native)?; check(stop)?; Ok(returned)
    }
    fn ext_family(&self, index: usize, stop: &mut dyn FnMut() -> bool) -> Result<()> {
        check(stop)?; let observed = fs::fstatfs(self.fd(index)?).map_err(native)?; check(stop)?;
        need(observed.f_type as u64 == 0xef53, Problem::UnsupportedFilesystem)
    }
    fn directory(&mut self, parent: Option<usize>, name: &[u8], private: bool, stop: &mut dyn FnMut() -> bool) -> Result<usize> {
        let before = match parent { Some(parent) => self.named(parent, name, stop)?.ok_or(Problem::Identity)?,
            None => { check(stop)?; let value = fs::stat("/").map_err(native)?; check(stop)?; value } };
        let expected = DirectoryKey::of(&before); need(expected.directory(self.uid()?, private), Problem::Identity)?;
        let index = self.open(parent, name, read_flags(true), private, stop)?;
        self.ext_family(index, stop)?;
        need(DirectoryKey::of(&self.stat(index, stop)?) == expected, Problem::Identity)?;
        let after = match parent { Some(parent) => self.named(parent, name, stop)?.ok_or(Problem::Identity)?,
            None => { check(stop)?; let value = fs::stat("/").map_err(native)?; check(stop)?; value } };
        need(DirectoryKey::of(&after) == expected, Problem::Identity)?;
        self.originals[index].directory = Some(expected); Ok(index)
    }
    fn check_roots(&self, stop: &mut dyn FnMut() -> bool) -> Result<()> {
        need(!self.close_failed && !self.retired, Problem::CleanupUnknown)?;
        for (index, original) in self.originals.iter().enumerate().take(self.retained) {
            let Some(expected) = original.directory else { continue; };
            need(expected.directory(self.uid()?, original.private), Problem::Identity)?;
            self.ext_family(index, stop)?;
            need(DirectoryKey::of(&self.stat(index, stop)?) == expected, Problem::Identity)?;
            let after = match original.parent {
                Some(parent) => self.named(parent, &original.name, stop)?.ok_or(Problem::Identity)?,
                None => { check(stop)?; let value = fs::stat("/").map_err(native)?; check(stop)?; value },
            };
            need(DirectoryKey::of(&after) == expected, Problem::Identity)?;
        }
        if let Some(lock) = self.lock {
            let root = self.root.ok_or(Problem::State)?;
            let held = FileKey::of(&self.stat(lock, stop)?, self.uid()?)?;
            let named = FileKey::of(&self.named(root, format::LOCK_NAME.as_bytes(), stop)?.ok_or(Problem::Identity)?, self.uid()?)?;
            need(self.lock_held && held == named && held.bytes == 0, Problem::Identity)?;
        }
        Ok(())
    }
    fn lock(&mut self, create: bool, stop: &mut dyn FnMut() -> bool) -> Result<()> {
        need(self.lock.is_none() && !self.lock_held, Problem::State)?;
        let root = self.root.ok_or(Problem::State)?;
        let existing = self.named(root, format::LOCK_NAME.as_bytes(), stop)?;
        let flags = read_flags(false) | OFlags::RDWR;
        let flags = if existing.is_none() && create { flags | OFlags::CREATE | OFlags::EXCL } else { flags };
        need(existing.is_some() || create, Problem::Corrupt)?;
        if let Some(stat) = &existing { need(FileKey::of(stat, self.uid()?)?.bytes == 0, Problem::Identity)?; }
        let index = self.open(Some(root), format::LOCK_NAME.as_bytes(), flags, false, stop)?;
        let held = FileKey::of(&self.stat(index, stop)?, self.uid()?)?;
        let named = FileKey::of(&self.named(root, format::LOCK_NAME.as_bytes(), stop)?.ok_or(Problem::Identity)?, self.uid()?)?;
        need(held == named && held.bytes == 0 && existing.as_ref().is_none_or(|before| FileKey::of(before, self.uid.unwrap_or(0)).is_ok_and(|before| before == held)), Problem::Identity)?;
        check(stop)?;
        let returned = fs::flock(self.fd(index)?, FlockOperation::NonBlockingLockExclusive);
        // Failure/WOULDBLOCK owns this fd but never claims an acquired lock.
        returned.map_err(native)?; self.lock = Some(index); self.lock_held = true;
        self.retained = self.originals.len(); check(stop)?; Ok(())
    }
    pub(crate) fn inspect(&mut self, location: Location, stop: &mut dyn FnMut() -> bool) -> Result<Observation> {
        self.work(Work::Inspect, stop, |book, stop| book.inspect_inner(location, stop))
    }
    fn inspect_inner(&mut self, location: Location, stop: &mut dyn FnMut() -> bool) -> Result<Observation> {
        need(!self.started && self.originals.is_empty() && !self.retired, Problem::State)?;
        check(stop)?; let uid = rustix::process::getuid().as_raw(); let effective = rustix::process::geteuid().as_raw(); check(stop)?;
        need(uid != 0 && uid == effective, Problem::Identity)?;
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
    fn inventory(&self, stop: &mut dyn FnMut() -> bool) -> Result<Inventory> {
        let root = self.root.ok_or(Problem::State)?;
        self.check_roots(stop)?;
        let before = self.stat(root, stop)?;
        check(stop)?; need(fs::seek(self.fd(root)?, fs::SeekFrom::Start(0)).map_err(native)? == 0, Problem::Identity)?; check(stop)?;
        let mut buffer = [MaybeUninit::<u8>::uninit(); 8192];
        let mut directory = RawDir::new(self.fd(root)?, &mut buffer[..]);
        let mut inventory = Inventory::new(); let mut dots = [false; 2];
        loop {
            check(stop)?;
            let entry = match directory.next() { Some(entry) => entry.map_err(native)?, None => break };
            check(stop)?;
            let name = entry.file_name().to_bytes();
            if name == b"." || name == b".." {
                let at = usize::from(name == b"..");
                need(!dots[at] && entry.file_type() == FileType::Directory && entry.ino() != 0, Problem::Identity)?;
                if at == 0 { need(entry.ino() == before.st_ino, Problem::Identity)?; }
                dots[at] = true; continue;
            }
            need(entry.file_type() == FileType::RegularFile, Problem::UnsupportedEntry)?;
            let stat = self.named(root, name, stop)?.ok_or(Problem::Identity)?;
            let key = FileKey::of(&stat, self.uid()?)?;
            need(key.common.ino == entry.ino() && key.common.dev == before.st_dev, Problem::Identity)?;
            inventory.add(name, key.bytes, true)?;
        }
        drop(directory);
        let after = self.stat(root, stop)?;
        need(dots == [true; 2] && DirectoryKey::of(&before) == DirectoryKey::of(&after)
            && before.st_mtime == after.st_mtime && before.st_mtime_nsec == after.st_mtime_nsec
            && before.st_ctime == after.st_ctime && before.st_ctime_nsec == after.st_ctime_nsec, Problem::Identity)?;
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
        need(FileKey::of(&self.stat(index, stop)?, self.uid()?)? == before, Problem::Identity)?;
        check(stop)?; need(fs::seek(self.fd(index)?, fs::SeekFrom::Start(0)).map_err(native)? == 0, Problem::Identity)?; check(stop)?;
        let mut bytes = Vec::new(); bytes.try_reserve_exact(length).map_err(|_| Problem::Bounds)?; bytes.resize(length, 0);
        let mut read = 0;
        while read < length {
            check(stop)?; let end = (read + BLOCK).min(length);
            let got = io::read(self.fd(index)?, &mut bytes[read..end]).map_err(native)?;
            need(got > 0 && got <= end - read, Problem::Identity)?; read += got; check(stop)?;
        }
        if full { let mut extra = [0; 1]; check(stop)?; let count = io::read(self.fd(index)?, &mut extra).map_err(native)?; check(stop)?; need(count == 0, Problem::Identity)?; }
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
            fs::mkdirat(self.fd(parent)?, OsStr::from_bytes(&name), Mode::from_raw_mode(0o700)).map_err(native)?;
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
        let originals_known = self.close_operation_leaves(cleanup_expired);
        if let Some(progress) = &mut self.mutation { progress.cleanup_returned(cleanup.is_ok() && originals_known); }
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
        let returned = fs::fsync(self.fd(root)?);
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
        self.progress()?.enter_effect()?;
        let returned = match operation {
            Mutation::New => fs::renameat_with(self.fd(root)?, OsStr::from_bytes(candidate_name.as_bytes()), self.fd(root)?,
                OsStr::from_bytes(name.as_bytes()), RenameFlags::NOREPLACE),
            Mutation::Replace => fs::renameat(self.fd(root)?, OsStr::from_bytes(candidate_name.as_bytes()), self.fd(root)?, OsStr::from_bytes(name.as_bytes())),
            Mutation::Delete => fs::unlinkat(self.fd(root)?, OsStr::from_bytes(name.as_bytes()), AtFlags::empty()),
        };
        self.mutation_files_mut()?.effect_returned = Some(returned.is_ok());
        if returned.is_ok() { self.progress()?.applied_returned()?; }
        returned.map_err(native)?;
        // A known applied effect is not known durable. Arm that distinction
        // before STOP can prevent entering the one directory sync.
        self.progress()?.enter_effect_sync()?;
        check(stop)?;
        let returned = fs::fsync(self.fd(root)?);
        self.progress()?.effect_sync_returned(returned.is_ok())?;
        returned.map_err(|_| Problem::DurabilityUnknown)?;
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
        let held = FileKey::of(&self.stat(index, stop)?, self.uid()?)?;
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
            let count = io::write(self.fd(index)?, &bytes[offset..end]).map_err(native)?;
            need(count > 0 && count <= end - offset, Problem::Native)?; offset += count; check(stop)?;
        }
        self.sync(index, stop)?;
        let after = self.check_owned_leaf(index, name, None, stop)?;
        need(after.common == fresh.common && after.bytes == bytes.len() as u64, Problem::Identity)?;
        check(stop)?; need(fs::seek(self.fd(index)?, fs::SeekFrom::Start(0)).map_err(native)? == 0, Problem::Identity)?; check(stop)?;
        let mut buffer = [0u8; BLOCK]; let mut offset = 0;
        while offset < bytes.len() {
            check(stop)?; let wanted = (bytes.len() - offset).min(buffer.len());
            let count = io::read(self.fd(index)?, &mut buffer[..wanted]).map_err(native)?;
            need(count > 0 && count <= wanted && buffer[..count] == bytes[offset..offset + count], Problem::Identity)?;
            offset += count; check(stop)?;
        }
        check(stop)?; let extra = io::read(self.fd(index)?, &mut buffer[..1]).map_err(native)?; check(stop)?;
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
            let held = FileKey::of(&self.stat(index, stop)?, self.uid()?)?;
            need(held.common == expected.common && held.bytes == expected.bytes && held.mtime == expected.mtime
                && FileKey::of(&self.named(root, name.as_bytes(), stop)?.ok_or(Problem::Identity)?, self.uid()?)? == held
                && self.named(root, files.prefix.fence.candidate_name().as_bytes(), stop)?.is_none(), Problem::Identity)?;
        }
        if let Some(expected) = files.expected {
            let old = self.stat(files.target.ok_or(Problem::State)?, stop)?;
            need(DirectoryKey::of(&old) == expected.file.common && old.st_nlink == 0 && old.st_size >= 0
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
        let returned = fs::unlinkat(self.fd(root)?, OsStr::from_bytes(name.as_bytes()), AtFlags::empty());
        if returned.is_ok() { self.mutation_files_mut()?.candidate_removed = true; }
        returned.map_err(native)?;
        check(expired)?;
        let returned = fs::fsync(self.fd(root)?);
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
            let returned = fs::fsync(self.fd(root)?);
            returned.map_err(|_| Problem::DurabilityUnknown)?;
            check(expired)?;
            need(self.named(root, format::INTENT_NAME.as_bytes(), expired)?.is_none(), Problem::CleanupUnknown)?;
            self.progress()?.absent_intent_proved(&AbsentIntentProof { no_intent_original: true,
                current_absence_confirmed: true, directory_sync_confirmed: true })?;
            return self.check_roots(expired);
        }
        self.check_owned_leaf(index.ok_or(Problem::State)?, format::INTENT_NAME.as_bytes(), ready, expired)?;
        check(expired)?;
        self.progress()?.enter_clear(true)?;
        let returned = fs::unlinkat(self.fd(root)?, OsStr::from_bytes(format::INTENT_NAME.as_bytes()), AtFlags::empty());
        if returned.is_ok() { self.mutation_files_mut()?.intent_removed = true; }
        returned.map_err(native)?;
        check(expired)?;
        let returned = fs::fsync(self.fd(root)?);
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
        check(stop)?; fs::fsync(self.fd(index)?).map_err(native)?; check(stop)
    }
    fn sync_initialization(&mut self, header: bool, stop: &mut dyn FnMut() -> bool) -> Result<()> {
        check(stop)?;
        let returned = fs::fsync(self.fd(self.root.ok_or(Problem::State)?)?);
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
    let flags = OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK;
    if directory { flags | OFlags::DIRECTORY } else { flags }
}
fn write_flags() -> OFlags { OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK }

#[cfg(test)]
mod tests {
    use super::*;
    fn id(byte: u8) -> Id { Id::from_bytes([byte; 16]).unwrap() }
    fn mutation_fixture(operation: Mutation) -> (MutationFiles, Option<Vec<u8>>) {
        let identity = format::Identity::new(id(1), id(2)).unwrap();
        let expected = (operation != Mutation::New).then(|| format::Revision::new(id(4), 1).unwrap());
        let proposed = (operation != Mutation::Delete).then(|| format::Revision::new(id(5), if operation == Mutation::New { 1 } else { 2 }).unwrap());
        let candidate = proposed.map(|revision| {
            let prefix = format::RecordPrefix::new(identity, id(3), revision, 1, 8, [[10; 24], [11; 24], [12; 24]]).unwrap();
            let mut body = vec![0; prefix.total_length().unwrap()]; body[..format::RECORD_PREFIX_BYTES].copy_from_slice(prefix.bytes()); body
        });
        let digest = candidate.as_ref().map_or([0; 32], |body| Sha256::digest(body).into());
        let prefix = format::IntentPrefix::new(identity, operation, id(6), id(3), expected, proposed,
            digest, candidate.as_ref().map_or(0, Vec::len)).unwrap();
        let root = DirectoryKey { dev: 1, ino: 2, mode: 0o40700, uid: 1000, gid: 1000 };
        let file = FileKey { common: DirectoryKey { ino: 3, mode: 0o100600, ..root }, links: 1, bytes: 257, mtime: (1, 0), ctime: (1, 0) };
        let files = MutationFiles { prefix, expected: expected.map(|revision| ReadWitness { root, file, record: id(3), revision }),
            target: None, candidate: None, intent: None, candidate_ready: None, intent_ready: None,
            candidate_removed: false, candidate_cleanup_sync: false, intent_removed: false, effect_returned: None, effect_verified: false };
        // Synthetic framing only: no native original or AEAD authentication is
        // claimed for these deliberately inert records/witnesses.
        (files, candidate)
    }

    #[test]
    fn private_mutation_matches_complete_ciphertext_record_and_exact_revision() {
        for operation in [Mutation::New, Mutation::Replace, Mutation::Delete] {
            let (mut files, candidate) = mutation_fixture(operation);
            assert!(mutation_input(&files, candidate.as_deref(), &mut || false).is_ok());
            if let Some(mut body) = candidate {
                let original = body[200]; body[200] ^= 1;
                assert!(mutation_input(&files, Some(&body), &mut || false).is_err());
                body[200] = original;
                body[48] ^= 0x10;
                files.prefix.candidate_digest = Sha256::digest(&body).into();
                // A matching whole-body digest is not permission to publish a
                // different record/revision under the intent's selected name.
                assert!(mutation_input(&files, Some(&body), &mut || false).is_err());
            } else {
                assert!(mutation_input(&files, Some(&[0; 257]), &mut || false).is_err());
            }
        }
        let (mut files, candidate) = mutation_fixture(Mutation::Replace);
        files.expected.as_mut().unwrap().revision.counter = 2;
        assert!(mutation_input(&files, candidate.as_deref(), &mut || false).is_err());
        let (files, mut candidate) = mutation_fixture(Mutation::New);
        candidate.as_mut().unwrap().pop();
        assert!(mutation_input(&files, candidate.as_deref(), &mut || false).is_err());
    }

    #[test]
    fn mutation_validation_observes_original_stop_before_io_or_large_hash() {
        let (files, candidate) = mutation_fixture(Mutation::New);
        let mut points = 0;
        assert_eq!(mutation_input(&files, candidate.as_deref(), &mut || { points += 1; points == 2 }), Err(Problem::Stopped));
        assert_eq!(points, 2);
    }

    #[test]
    fn first_failure_and_abandoned_phase_refuse_every_successor_without_work() {
        let mut book = StoreBook::new();
        assert_eq!(book.work::<()>(Work::PrepareInitialize, &mut || false, |_, _| Err(Problem::Native)), Err(Problem::Native));
        assert_eq!(book.problem(), Some(Problem::Native));
        let mut forbidden = || panic!("a failed book must not reach any successor work callback");
        let location = Location::application_data(Path::new("/home/example/.local/share/dev.mobile-release-kit.desktop")).unwrap();
        assert!(matches!(book.inspect(location, &mut forbidden), Err(Problem::Native)));
        // A synthetic project identity is not a native exclusion proof. Test
        // the same mandatory guard without manufacturing VaultAbsentExclusion.
        assert!(matches!(book.work::<()>(Work::PrepareInitialize, &mut forbidden,
            |_, _| panic!("prepare-initialize work must not be reached")), Err(Problem::Native)));
        assert!(matches!(book.reserve_prepared_identity(&mut forbidden), Err(Problem::Native)));
        assert_eq!(book.publish_header(&[0; 104], &mut forbidden), Err(Problem::Native));
        assert!(matches!(book.read_record(id(3), true, &mut forbidden), Err(Problem::Native)));
        assert!(matches!(book.recheck_root(&mut forbidden), Err(Problem::Native)));
        let (files, _) = mutation_fixture(Mutation::Replace);
        assert_eq!(book.recheck_record(files.expected.as_ref().unwrap(), &mut forbidden), Err(Problem::Native));
        assert_eq!(book.mutate(&[0; 200], None, None, &mut forbidden, &mut || panic!("mutation was not admitted")), Err(Problem::Native));
        book.cancel_initialize_preview(); assert_eq!(book.problem(), Some(Problem::Native));
        let mut abandoned = StoreBook::new(); abandoned.begin(Work::PrepareInitialize).unwrap();
        assert_eq!(abandoned.begin(Work::PrepareInitialize), Err(Problem::State));
        assert_eq!(abandoned.problem(), Some(Problem::State));
        assert!(abandoned.in_flight.is_some());
    }

    #[test]
    fn late_stop_preserves_recorded_durability_but_never_renews_the_book() {
        let mut book = StoreBook::new(); book.begin(Work::PublishHeader).unwrap();
        // Already-returned DATA facts; this does not simulate native fsync.
        book.reservation_entered = true; book.reservation_applied = true;
        book.header_entered = true; book.header_applied = true;
        book.reservation_sync = true; book.header_sync = true;
        assert_eq!(book.finish(Ok(()), &mut || true), Err(Problem::Stopped));
        assert_eq!(book.initialization_effects(), ((true, true), (true, true)));
        assert_eq!(book.initialization_durability(), (true, true));
        assert_eq!(book.problem(), Some(Problem::Stopped));
        assert!(matches!(book.read_record(id(3), false, &mut || panic!("late STOP is sticky")), Err(Problem::Stopped)));
        assert!(book.release(&mut || true)); // No originals existed to close.
        assert!(book.settled()); assert_eq!(book.problem(), Some(Problem::Stopped));
    }

    #[test]
    fn incomplete_initialization_is_not_inferred_unstarted_from_missing_sync() {
        let mut book = StoreBook::new();
        assert_eq!(book.initialization_effects(), ((false, false), (false, false)));
        // Inert entered/returned DATA states, not native persistence receipts.
        book.reservation_entered = true;
        assert_eq!(book.initialization_effects(), ((true, false), (false, false)));
        book.reservation_applied = true; book.header_entered = true;
        book.fail(Problem::Native);
        assert_eq!(book.initialization_effects(), ((true, true), (true, false)));
        assert_eq!(book.initialization_durability(), (false, false));
        assert!(book.release(&mut || true));
        assert_eq!(book.initialization_effects(), ((true, true), (true, false)));
    }

    #[test]
    fn first_failure_clock_is_sticky_and_never_renews_original_cleanup() {
        let mut book = StoreBook::new();
        assert_eq!(book.problem_at(), None);
        book.fail(Problem::Native);
        let first = book.problem_at().unwrap();
        assert!(!first_failure_expired(Some(first), first + FAILURE_CLEANUP - Duration::from_nanos(1)));
        assert!(first_failure_expired(Some(first), first + FAILURE_CLEANUP));
        book.fail(Problem::Stopped);
        assert_eq!(book.problem(), Some(Problem::Native)); assert_eq!(book.problem_at(), Some(first));
        assert!(cleanup_expired_at(Some(first), &mut || true)); // Earlier owner endpoint wins.
        assert!(cleanup_expired_at(Some(first - FAILURE_CLEANUP), &mut || false)); // Stale WORK cannot extend it.
        assert!(book.release(&mut || true)); // No native originals in this DATA case.
        assert_eq!(book.problem_at(), Some(first));
    }

    #[test]
    fn absent_vault_exclusion_compares_physical_ancestors_before_creation() {
        let ancestor = DirectoryKey { dev: 3, ino: 5, mode: 0o40700, uid: 1000, gid: 1000 };
        let project = crate::asset_source::DirectoryIdentity::vault_original(3, 5, 0o40755, 2000, 2000);
        // Physical equality refuses even if cached ownership/mode differ. A
        // same-inode number on another device is not the same directory.
        assert_eq!(exclude_project_ancestors([ancestor].into_iter(), &[project], &mut || false), Err(Problem::Identity));
        assert_eq!(exclude_project_ancestors([DirectoryKey { dev: 4, ..ancestor }].into_iter(), &[project], &mut || false), Ok(()));
        assert_eq!(exclude_project_ancestors([ancestor].into_iter(), &[], &mut || true), Err(Problem::Stopped));
        // Only the actual SourceBook producer can mint the typed public proof;
        // these inert predicate fixtures do not perform native registration.
    }

    #[test]
    fn no_original_proof_cannot_adopt_entered_owned_or_unknown_slots() {
        let mut book = StoreBook::new(); let index = book.arm(None, b"/", false).unwrap();
        assert_eq!(book.no_original(index), Ok(true));
        for state in [OriginalState::Entered, OriginalState::Owned, OriginalState::Unknown, OriginalState::Closing, OriginalState::Closed] {
            book.originals[index].state = state;
            assert_eq!(book.no_original(index), Err(Problem::CleanupUnknown));
        }
        book.originals[index].state = OriginalState::NoHandle;
        assert_eq!(book.no_original(index), Ok(true));
        assert!(book.release(&mut || true)); assert_eq!(book.consumed, 0);
    }

    #[test]
    fn quiescent_originals_are_not_retirement_or_permission_to_reuse_failure() {
        let mut book = StoreBook::new(); assert!(book.operation_quiescent()); assert!(!book.settled());
        let index = book.arm(None, b"/", false).unwrap();
        assert!(!book.operation_quiescent());
        // No native open was entered: settling a reserved slot makes no close
        // syscall and never fabricates a retained root/lock lease.
        book.close(index).unwrap(); assert!(book.operation_quiescent()); assert!(!book.lease_held());
        book.fail(Problem::Stopped);
        assert_eq!(book.begin(Work::Inspect), Err(Problem::Stopped));
        assert!(book.release(&mut || true)); assert!(book.settled());
        assert_eq!(book.problem(), Some(Problem::Stopped));
    }

    #[test]
    fn next_admitted_mutation_cannot_borrow_previous_success_outcome() {
        let mut progress = MutationProgress::new(Mutation::New);
        progress.begin_intent().unwrap(); progress.intent_durable_returned().unwrap();
        progress.enter_effect().unwrap(); progress.applied_returned().unwrap(); progress.enter_effect_sync().unwrap();
        progress.effect_sync_returned(true).unwrap(); progress.enter_clear(true).unwrap(); progress.clear_sync_returned(true).unwrap();
        progress.cleanup_returned(true); assert!(progress.success());
        let mut book = StoreBook::new(); book.mutation = Some(progress);
        let old = book.storage_outcome().unwrap();
        // This new call has no native lease, so it refuses before any IO. The
        // old original owner keeps `old`; it is not this call's storage result.
        assert_eq!(book.mutate(&[0; 200], None, None, &mut || false, &mut || true), Err(Problem::State));
        assert!(book.storage_outcome().is_none());
        assert_eq!(old.effect, Effect::KnownApplied);
    }
    #[test]
    fn location_only_accepts_native_application_data_and_fixed_vault_child() {
        assert!(Location::application_data(Path::new("/home/example/.local/share/dev.mobile-release-kit.desktop")).is_ok());
        for path in ["relative/dev.mobile-release-kit.desktop", "/dev.mobile-release-kit.desktop", "/home/example/elsewhere",
            "/home//dev.mobile-release-kit.desktop", "/home/../dev.mobile-release-kit.desktop", "/home/./dev.mobile-release-kit.desktop",
            "/home/dev.mobile-release-kit.desktop/", "/home/\0/dev.mobile-release-kit.desktop"] {
            assert!(Location::application_data(Path::new(path)).is_err());
        }
    }
    #[test]
    fn original_book_never_calls_unstarted_pending_or_unknown_a_lease_or_close() {
        let mut book = StoreBook::new(); assert!(book.not_started()); assert!(!book.settled()); assert!(!book.lease_held());
        book.started = true; book.originals.push(Original { fd: None, state: OriginalState::Entered, parent: None, name: b"/".to_vec(), directory: None, private: false, exclusive: false });
        assert!(!book.settled()); assert!(!book.lease_held());
        book.retired = true; assert!(!book.settled());
        book.originals[0].state = OriginalState::Unknown; assert!(!book.settled());
        // These are inert DATA states, not a native open/close test.
        book.originals[0].state = OriginalState::NoHandle; assert!(book.settled());
        book.close_failed = true; assert!(!book.settled());
    }
}
