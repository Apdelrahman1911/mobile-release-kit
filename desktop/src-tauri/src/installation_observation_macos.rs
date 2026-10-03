//! Read-only fixed installation correspondence, subordinate to DocumentBinding's
//! original blocking child. No launch capability, maintenance or alternate path.
use super::*;
use crate::{installation::{CheckReason as Problem, Matching},
    macos_install_paths as paths, macos_install_record::{self as data, Inventory, InventoryIndex}};
use std::mem::size_of;
type InspectResult<T> = std::result::Result<T, Problem>;
pub(crate) const CONTROL_RESERVE: usize = 16 * 1024 * 1024;
const RECORDS: usize = 8256;
const NATIVE_FRAME_LIMIT: usize = 16384;

fn problem(failure: AdmissionFailure, content: Problem) -> Problem {
    match failure {
        AdmissionFailure::Stopped => Problem::Cancelled,
        AdmissionFailure::Deadline => Problem::Deadline,
        AdmissionFailure::Bounds => Problem::Bounds,
        AdmissionFailure::Native => Problem::Native,
        AdmissionFailure::Ownership => Problem::Protection,
        AdmissionFailure::Inventory => content,
        AdmissionFailure::Identity | AdmissionFailure::AlreadyUsed | AdmissionFailure::Unknown => Problem::CleanupUnknown,
    }
}
pub(crate) fn native_problem(failure: AdmissionFailure) -> Problem { problem(failure, Problem::PayloadMismatch) }

pub(crate) struct InstallationSlots {
    book: Option<Book>, entered: bool, native_settled: bool, storage_disposed: bool,
    // Original positive returns, never substitute for a child/coordinator join.
    files: u32, bytes: u64,
}
impl InstallationSlots {
    pub(crate) fn new() -> Self {
        Self { book: Some(Book::new()), entered: false, native_settled: false, storage_disposed: false, files: 0, bytes: 0 }
    }
    #[cfg(not(feature = "macos-android-registration-helper"))]
    pub(crate) fn new_registered(gate: crate::saved_command_owner::AndroidRegistrationWorkGate) -> Self {
        // Same inert installation inspector, now subordinate to the caller's
        // original registration clock/cohort. No entry or observation here.
        let mut book = Book::new(); book.registration_gate = Some(gate);
        Self { book: Some(book), entered: false, native_settled: false, storage_disposed: false, files: 0, bytes: 0 }
    }
    pub(crate) fn settled(&self) -> bool {
        (!self.entered && self.book.as_ref().is_some_and(Book::never_started))
            || (self.entered && self.native_settled && self.storage_disposed && self.book.is_none())
    }
    pub(crate) fn storage_released(&self) -> bool { self.settled() }
    pub(crate) fn settlement_facts(&self) -> (bool, bool) { (self.native_settled, self.storage_disposed) }
    pub(crate) fn observed_settled(&self) -> bool {
        self.entered && self.native_settled && self.storage_disposed && self.book.is_none()
    }
    pub(crate) fn control_bytes(&self) -> Option<usize> {
        let heap = match &self.book { Some(book) => book.retained_heap_bytes()?, None if self.storage_disposed => 0, _ => return None };
        size_of::<Self>().checked_add(heap)
    }
    fn note_native(&self, publish: &mut dyn FnMut(Problem, Instant)) {
        if let Some((failure, at)) = self.book.as_ref().and_then(Book::first_failure) {
            publish(native_problem(failure), at);
        }
    }
    fn reject<T>(&self, why: Problem, at: Instant, publish: &mut dyn FnMut(Problem, Instant)) -> InspectResult<T> {
        self.note_native(publish); publish(why, at); Err(why)
    }
    fn attempt<T>(&mut self, content: Problem, publish: &mut dyn FnMut(Problem, Instant),
        call: impl FnOnce(&mut Book) -> Result<T>) -> InspectResult<T> {
        let Some(book) = self.book.as_mut() else { return self.reject(Problem::CleanupUnknown, Instant::now(), publish); };
        let returned = call(book);
        let at = Instant::now(); // Before a containing-owner/Document mutex or join.
        self.note_native(publish);
        match returned {
            Ok(value) => {
                // Every successful native return is quiescent. Check actual
                // retained capacities before permitting its next successor.
                match self.control_bytes() {
                    Some(bytes) if bytes <= CONTROL_RESERVE => Ok(value),
                    Some(_) => self.reject(Problem::Bounds, at, publish),
                    None => self.reject(Problem::CleanupUnknown, at, publish),
                }
            },
            Err(failure) => self.reject(problem(failure, content), at, publish),
        }
    }
    fn check(&self, end: Instant, stop: &watch::Receiver<bool>, publish: &mut dyn FnMut(Problem, Instant)) -> InspectResult<()> {
        let returned = checkpoint(end, stop);
        let at = Instant::now();
        match returned { Ok(()) => Ok(()), Err(failure) => self.reject(native_problem(failure), at, publish) }
    }
    fn directory_identity(&self, index: usize) -> InspectResult<data::DirectoryIdentity> {
        let id = self.book.as_ref().and_then(|book| book.records.get(index)).and_then(|r| r.identity)
            .ok_or(Problem::CleanupUnknown)?;
        let stable = data::DirectoryIdentity { device: i64::from(id.dev), inode: id.ino,
            mode: u32::from(id.mode), uid: id.uid, gid: id.gid, flags: id.flags };
        stable.valid().then_some(stable).ok_or(Problem::Protection)
    }
    fn protected(&mut self, index: usize, mode: u16, end: Instant, stop: &watch::Receiver<bool>,
        publish: &mut dyn FnMut(Problem, Instant)) -> InspectResult<()> {
        self.attempt(Problem::PayloadMismatch, publish, |book| {
            checkpoint(end, stop)?;
            let id = book.records.get(index).and_then(|r| r.identity).ok_or(AdmissionFailure::Identity)?;
            if id.uid != 0 || id.gid != 0 || id.mode & 0o7777 != mode || id.flags != 0 { return Err(AdmissionFailure::Ownership); }
            native::no_xattrs(book.fd(index)?.as_fd()).map_err(native_error)?;
            book.check_name(index, end, stop)
        })
    }
    fn open(&mut self, parent: Option<usize>, name: &str, directory: bool, end: Instant, stop: &watch::Receiver<bool>,
        publish: &mut dyn FnMut(Problem, Instant)) -> InspectResult<usize> {
        self.attempt(Problem::PayloadMismatch, publish, |book| book.open(parent, name, directory, end, stop))
    }
    fn close(&mut self, index: usize, end: Instant, stop: &watch::Receiver<bool>,
        publish: &mut dyn FnMut(Problem, Instant)) -> InspectResult<()> {
        self.check(end, stop, publish)?;
        self.attempt(Problem::PayloadMismatch, publish, |book| {
            if book.close(index) { Ok(()) } else { Err(AdmissionFailure::Unknown) }
        })?;
        self.check(end, stop, publish)
    }
    // Missing is an observed negative, not a guess from Book::open's Native.
    // Hold/recheck the exact protected parent and repeat only the fixed no-follow
    // observation. The bounded recheck cannot renew work or cleanup.
    fn require_present(&mut self, parent: usize, name: &str, missing: Problem, end: Instant,
        stop: &watch::Receiver<bool>, publish: &mut dyn FnMut(Problem, Instant)) -> InspectResult<()> {
        self.check(end, stop, publish)?;
        self.attempt(Problem::PayloadMismatch, publish, |book| book.check_name(parent, end, stop))?;
        let observed = match self.book.as_ref().and_then(|book| book.fd(parent).ok()) {
            Some(fd) => stat::fstatat(fd, name, AtFlags::AT_SYMLINK_NOFOLLOW),
            None => return self.reject(Problem::CleanupUnknown, Instant::now(), publish),
        };
        let first_at = Instant::now();
        match observed {
            Ok(_) => Ok(()),
            Err(nix::errno::Errno::ENOENT) => {
                let recheck_end = end.min(first_at + std::time::Duration::from_secs(2));
                // ENOENT becomes "missing" only after this bounded confirmation.
                // A stop/error breaks the confirmation immediately; never use
                // cleanup permission to issue another inspection. Either outcome
                // contracts cleanup from the ORIGINAL negative-return instant.
                let confirmed = (|| -> InspectResult<()> {
                    self.attempt(Problem::PayloadMismatch, publish, |book| book.check_name(parent, recheck_end, stop))?;
                    self.check(recheck_end, stop, publish)?;
                    let repeated = match self.book.as_ref().and_then(|book| book.fd(parent).ok()) {
                        Some(fd) => stat::fstatat(fd, name, AtFlags::AT_SYMLINK_NOFOLLOW),
                        None => return self.reject(Problem::CleanupUnknown, Instant::now(), publish),
                    };
                    let repeated_at = Instant::now();
                    if !matches!(repeated, Err(nix::errno::Errno::ENOENT)) {
                        return self.reject(Problem::CleanupUnknown, repeated_at, publish);
                    }
                    self.attempt(Problem::PayloadMismatch, publish, |book| book.check_name(parent, recheck_end, stop))
                })();
                self.reject(if confirmed.is_ok() { missing } else { Problem::CleanupUnknown }, first_at, publish)
            },
            Err(_) => self.reject(Problem::Native, first_at, publish),
        }
    }
    fn read_record(&mut self, parent: usize, name: &str, limit: usize, end: Instant,
        stop: &watch::Receiver<bool>, publish: &mut dyn FnMut(Problem, Instant)) -> InspectResult<Vec<u8>> {
        self.require_present(parent, name, Problem::Incomplete, end, stop, publish)?;
        let index = self.open(Some(parent), name, false, end, stop, publish)?;
        self.protected(index, 0o444, end, stop, publish)?;
        let size = self.book.as_ref().and_then(|book| book.records[index].identity)
            .and_then(|id| u64::try_from(id.size).ok()).filter(|size| *size > 0 && *size <= limit as u64);
        let Some(size) = size else { return self.reject(Problem::Bounds, Instant::now(), publish); };
        let (_, bytes) = self.attempt(Problem::RecordMismatch, publish, |book| book.read(index, size, true, end, stop))?;
        self.close(index, end, stop, publish)?;
        Ok(bytes)
    }
    fn roster(&mut self, parent: usize, limit: usize, end: Instant, stop: &watch::Receiver<bool>,
        publish: &mut dyn FnMut(Problem, Instant)) -> InspectResult<BTreeMap<String, (u64, u8)>> {
        let mut local = BTreeMap::new(); let mut buffer = [0u8; 65536];
        loop {
            self.check(end, stop, publish)?;
            let used = self.attempt(Problem::PayloadMismatch, publish, |book|
                native::directory_block(book.fd(parent)?.as_fd(), &mut buffer).map_err(native_error))?;
            if used == 0 { break; }
            let mut offset = 0;
            while offset < used {
                if used - offset < 11 { return self.reject(Problem::PayloadMismatch, Instant::now(), publish); }
                // Eleven available bytes above prove this fixed array read.
                let inode = u64::from_ne_bytes([buffer[offset], buffer[offset+1], buffer[offset+2], buffer[offset+3],
                    buffer[offset+4], buffer[offset+5], buffer[offset+6], buffer[offset+7]]);
                let kind = buffer[offset+8];
                let length = usize::from(u16::from_ne_bytes([buffer[offset+9],buffer[offset+10]]));
                let Some(next) = offset.checked_add(11 + length).filter(|n| *n <= used) else {
                    return self.reject(Problem::PayloadMismatch, Instant::now(), publish);
                };
                let name = match std::str::from_utf8(&buffer[offset+11..next]) {
                    Ok(name) => name, Err(_) => return self.reject(Problem::PayloadMismatch, Instant::now(), publish),
                };
                offset = next;
                if name == "." || name == ".." { continue; }
                if !matches!(kind, nix::libc::DT_DIR | nix::libc::DT_REG) || inode == 0
                    || !name.is_ascii() || name.contains('/')
                    || !(name == paths::APP_NAME || runtime::safe_payload_path(name)) {
                    return self.reject(Problem::PayloadMismatch, Instant::now(), publish);
                }
                if local.len() >= limit || local.insert(name.to_owned(), (inode, kind)).is_some() {
                    return self.reject(Problem::Bounds, Instant::now(), publish);
                }
            }
        }
        self.attempt(Problem::PayloadMismatch, publish, |book| book.check_name(parent, end, stop))?;
        Ok(local)
    }
    fn match_fixed_roster(&mut self, parent: usize, names: &[&str], optional_stage: Option<&str>, end: Instant,
        stop: &watch::Receiver<bool>, publish: &mut dyn FnMut(Problem, Instant)) -> InspectResult<()> {
        let roster = self.roster(parent, names.len() + usize::from(optional_stage.is_some()), end, stop, publish)?;
        let expected = names.iter().all(|name| roster.contains_key(*name))
            && roster.keys().all(|name| names.contains(&name.as_str()) || optional_stage == Some(name.as_str()));
        if !expected { return self.reject(Problem::PayloadMismatch, Instant::now(), publish); }
        if let Some(name) = optional_stage.filter(|name| roster.contains_key(*name)) {
            self.check(end, stop, publish)?;
            let before = self.attempt(Problem::PayloadMismatch, publish, |book|
                stat::fstatat(book.fd(parent)?, name, AtFlags::AT_SYMLINK_NOFOLLOW).map_err(native_error))?;
            if before.st_mode != (SFlag::S_IFDIR.bits() | 0o700) || before.st_uid != 0 || before.st_gid != 0
                || before.st_flags != 0 || roster[name] != (before.st_ino, nix::libc::DT_DIR) {
                return self.reject(Problem::Protection, Instant::now(), publish);
            }
            self.attempt(Problem::PayloadMismatch, publish, |book| book.check_name(parent, end, stop))?;
            let after = self.attempt(Problem::PayloadMismatch, publish, |book|
                stat::fstatat(book.fd(parent)?, name, AtFlags::AT_SYMLINK_NOFOLLOW).map_err(native_error))?;
            if Identity::of(&before) != Identity::of(&after) {
                return self.reject(Problem::CleanupUnknown, Instant::now(), publish);
            }
            // The root-only staging directory is metadata-only. Never open it.
        }
        Ok(())
    }
    fn walk(&mut self, parent: usize, prefix: &str, index: &InventoryIndex<'_>, observed: &mut BTreeSet<String>,
        depth: usize, end: Instant, stop: &watch::Receiver<bool>, publish: &mut dyn FnMut(Problem, Instant),
        read_returned: &mut dyn FnMut(u32, u64)) -> InspectResult<()> {
        if depth > 16 { return self.reject(Problem::Bounds, Instant::now(), publish); }
        let expected = index.files.keys().chain(index.directories.iter()).filter(|path|
            immediate_child(prefix, path)).count();
        if expected > data::FILE_LIMIT * 2 { return self.reject(Problem::Bounds, Instant::now(), publish); }
        // Bounds follow the inventory's immediate roster, not a per-depth4096
        // allocation. Extra names cannot accumulate at every retained ancestor.
        let roster = self.roster(parent, expected, end, stop, publish)?;
        if roster.len() != expected { return self.reject(Problem::PayloadMismatch, Instant::now(), publish); }
        for (name, (inode, kind)) in roster {
            self.check(end, stop, publish)?;
            let path = format!("{prefix}/{name}");
            let directory = index.directories.contains(&path);
            if !directory && !index.files.contains_key(&path) || path.len() > 1024
                || observed.len() >= data::FILE_LIMIT * 2 || !observed.insert(path.clone()) {
                return self.reject(Problem::PayloadMismatch, Instant::now(), publish);
            }
            if kind != if directory { nix::libc::DT_DIR } else { nix::libc::DT_REG } {
                return self.reject(Problem::PayloadMismatch, Instant::now(), publish);
            }
            let item = self.open(Some(parent), &name, directory, end, stop, publish)?;
            if self.book.as_ref().and_then(|book| book.records[item].identity).is_none_or(|id| id.ino != inode) {
                return self.reject(Problem::CleanupUnknown, Instant::now(), publish);
            }
            let executable = index.files.get(&path).is_some_and(|entry| entry.executable);
            self.protected(item, if directory || executable { 0o555 } else { 0o444 }, end, stop, publish)?;
            if directory { self.walk(item, &path, index, observed, depth+1, end, stop, publish, read_returned)?; }
            else {
                let Some(entry) = index.files.get(&path) else { return self.reject(Problem::PayloadMismatch, Instant::now(), publish); };
                let hash = self.attempt(Problem::PayloadMismatch, publish, |book| book.read(item, entry.size, false, end, stop))?.0;
                if hash != entry.sha256 { return self.reject(Problem::PayloadMismatch, Instant::now(), publish); }
                let Some(files) = self.files.checked_add(1).filter(|n| *n <= data::FILE_LIMIT as u32) else {
                    return self.reject(Problem::Bounds, Instant::now(), publish);
                };
                let Some(bytes) = self.bytes.checked_add(entry.size).filter(|n| *n <= data::PAYLOAD_LIMIT) else {
                    return self.reject(Problem::Bounds, Instant::now(), publish);
                };
                self.files = files; self.bytes = bytes;
                // Read-only scalar progress, and the sole permitted test pause
                // hook: this original child, after a real successful full read.
                read_returned(self.files, self.bytes);
                self.check(end, stop, publish)?;
            }
            self.close(item, end, stop, publish)?;
        }
        self.attempt(Problem::PayloadMismatch, publish, |book| book.check_name(parent, end, stop))
    }
    fn inspect(&mut self, end: Instant, stop: &watch::Receiver<bool>, publish: &mut dyn FnMut(Problem, Instant),
        read_returned: &mut dyn FnMut(u32, u64)) -> InspectResult<Matching> {
        self.check(end, stop, publish)?;
        if !crate::installation::NORMAL_MAC_PROFILE { return self.reject(Problem::UnavailableProfile, Instant::now(), publish); }
        let user = native::real_user(); let user_at = Instant::now();
        if user.is_err() { return self.reject(Problem::Protection, user_at, publish); }
        self.check(end, stop, publish)?;
        let executable = std::env::current_exe(); let executable_at = Instant::now();
        if executable.as_ref().is_err() { return self.reject(Problem::Native, executable_at, publish); }
        if executable.as_deref().ok() != Some(Path::new(paths::PAYLOAD_EXECUTABLE)) {
            return self.reject(Problem::WrongLocation, executable_at, publish);
        }
        self.attempt(Problem::PayloadMismatch, publish, |book| book.arm_acl_once(end, stop))?;
        self.attempt(Problem::PayloadMismatch, publish, |book| {
            if !book.inspection_ready() { return Err(AdmissionFailure::AlreadyUsed); }
            book.records.try_reserve_exact(RECORDS).map_err(|_| AdmissionFailure::Bounds)?;
            book.started = true; Ok(())
        })?;
        let root = self.open(None, "/", true, end, stop, publish)?;
        let library = self.open(Some(root), "Library", true, end, stop, publish)?;
        let support = self.open(Some(library), "Application Support", true, end, stop, publish)?;
        self.require_present(support, "MobileReleaseKit", Problem::Missing, end, stop, publish)?;
        let install = self.open(Some(support), "MobileReleaseKit", true, end, stop, publish)?;
        self.protected(install, 0o755, end, stop, publish)?;
        self.require_present(install, paths::MAINTENANCE_GATE_NAME, Problem::Incomplete, end, stop, publish)?;
        {
            let gate_data = self.read_record(install, paths::MAINTENANCE_GATE_NAME, paths::MAINTENANCE_GATE_BYTES.len(), end, stop, publish)?;
            if gate_data != paths::MAINTENANCE_GATE_BYTES { return self.reject(Problem::RecordMismatch, Instant::now(), publish); }
        }
        self.require_present(install, "versions", Problem::Incomplete, end, stop, publish)?;
        let versions = self.open(Some(install), "versions", true, end, stop, publish)?;
        self.protected(versions, 0o755, end, stop, publish)?;
        self.require_present(versions, paths::RELEASE, Problem::Incomplete, end, stop, publish)?;
        let release = self.open(Some(versions), paths::RELEASE, true, end, stop, publish)?;
        self.protected(release, 0o755, end, stop, publish)?;
        let descriptor = self.read_record(release, data::RECORD_NAME, data::RECORD_LIMIT, end, stop, publish)?;
        let inventory_bytes = self.read_record(release, data::INVENTORY_NAME, data::INVENTORY_LIMIT, end, stop, publish)?;
        let install_root = match self.directory_identity(install) {
            Ok(value) => value, Err(why) => return self.reject(why, Instant::now(), publish),
        };
        let release_directory = match self.directory_identity(release) {
            Ok(value) => value, Err(why) => return self.reject(why, Instant::now(), publish),
        };
        let source = option_env!("MRK_MACOS_INSTALL_SOURCE_COMMIT").unwrap_or("");
        let manifest = option_env!("MRK_BUNDLED_RUNTIME_MANIFEST_SHA256").unwrap_or("");
        let expected = data::Expected { kind: data::Kind::Ordinary, source_commit: source, runtime_manifest: manifest,
            install_root, release_directory };
        let record = match data::Record::parse_data(&descriptor, &inventory_bytes, &expected) {
            Ok(record) => record, Err(_) => return self.reject(Problem::RecordMismatch, Instant::now(), publish),
        };
        self.check(end, stop, publish)?;
        let inventory = match Inventory::parse(&inventory_bytes, manifest) {
            Ok(inventory) => inventory, Err(_) => return self.reject(Problem::RecordMismatch, Instant::now(), publish),
        };
        let index = match inventory.index() { Ok(index) => index, Err(_) => return self.reject(Problem::RecordMismatch, Instant::now(), publish) };
        // No opaque current native allocation receives zero credit. This native
        // snapshot is quiescent here; every live/native frame must be accountable.
        let Some(native_bytes) = self.control_bytes() else { return self.reject(Problem::CleanupUnknown, Instant::now(), publish); };
        let planned = control_bound(&descriptor, &inventory_bytes, &inventory, &index, native_bytes);
        if planned.is_none_or(|bytes| bytes > CONTROL_RESERVE) { return self.reject(Problem::Bounds, Instant::now(), publish); }
        // Prove a required absence before checking a complete roster; an absent
        // app/runtime is incomplete, not an unexplained generic mismatch.
        self.require_present(install, paths::APP_NAME, Problem::Incomplete, end, stop, publish)?;
        self.require_present(release, "runtime", Problem::Incomplete, end, stop, publish)?;
        self.match_fixed_roster(install, &[paths::APP_NAME, "versions", paths::MAINTENANCE_GATE_NAME], Some(&format!(".install-{}", record.instance())), end, stop, publish)?;
        self.match_fixed_roster(versions, &[paths::RELEASE], None, end, stop, publish)?;
        self.match_fixed_roster(release, &["runtime", data::INVENTORY_NAME, data::RECORD_NAME], None, end, stop, publish)?;
        let app = self.open(Some(install), paths::APP_NAME, true, end, stop, publish)?;
        self.protected(app, 0o555, end, stop, publish)?;
        let runtime = self.open(Some(release), "runtime", true, end, stop, publish)?;
        self.protected(runtime, 0o555, end, stop, publish)?;
        let mut observed = BTreeSet::from(["app".to_owned(), "runtime".to_owned()]);
        self.walk(app, "app", &index, &mut observed, 0, end, stop, publish, read_returned)?;
        self.walk(runtime, "runtime", &index, &mut observed, 0, end, stop, publish, read_returned)?;
        if observed.len() != index.files.len() + index.directories.len() || self.files as usize != index.files.len()
            || self.bytes != index.payload_bytes { return self.reject(Problem::PayloadMismatch, Instant::now(), publish); }
        let Some(book) = self.book.as_ref() else { return self.reject(Problem::CleanupUnknown, Instant::now(), publish); };
        let count = book.records.len();
        for original in 0..count {
            if self.book.as_ref().is_some_and(|book| book.records[original].state == State::Owned) {
                self.attempt(Problem::PayloadMismatch, publish, |book| book.check_name(original, end, stop))?;
            }
        }
        self.check(end, stop, publish)?;
        match Matching::checked(self.files as usize, self.bytes) {
            Some(result) => Ok(result), None => self.reject(Problem::Bounds, Instant::now(), publish),
        }
    }
    pub(crate) fn run(&mut self, end: Instant, stop: &watch::Receiver<bool>, publish: &mut dyn FnMut(Problem, Instant),
        cleanup_expired: &mut dyn FnMut(Option<(AdmissionFailure, Instant)>) -> bool,
        read_returned: &mut dyn FnMut(u32, u64)) -> InspectResult<Matching> {
        if self.entered || !self.book.as_ref().is_some_and(Book::never_started) {
            return self.reject(Problem::CleanupUnknown, Instant::now(), publish);
        }
        self.entered = true;
        let result = self.inspect(end, stop, publish, read_returned);
        let at = Instant::now();
        if let Err(why) = result { self.note_native(publish); publish(why, at); }
        // Stop means no more inspection, not permission to skip independently
        // allowed original cleanup. There is no second worker or new interval.
        let cleaned = self.book.as_mut().is_some_and(|book| book.settle(cleanup_expired) == CloseOutcome::Settled && book.settled());
        self.note_native(publish);
        self.native_settled = cleaned;
        if cleaned {
            // Only already-closed DATA leaves the original. Drop is explicitly
            // not a native settle operation; its real return precedes credit.
            let closed = self.book.take();
            drop(closed);
            self.storage_disposed = true;
        } else { publish(Problem::CleanupUnknown, Instant::now()); }
        if !self.settled() { return Err(Problem::CleanupUnknown); }
        // An original refusal has already set STOP. Do not replace that
        // diagnosis with a later checkpoint's generic Cancelled.
        if result.is_ok() { self.check(end, stop, publish)?; }
        result
    }
}

fn immediate_child(parent: &str, path: &str) -> bool {
    path.strip_prefix(parent).and_then(|rest| rest.strip_prefix('/'))
        .is_some_and(|name| !name.is_empty() && !name.contains('/'))
}

// Conservative complete backing bound: existing strict JSON is node/depth
// bounded while parsing, and only <=1MiB DATA is collected. The parser arena is
// gone before the indexed walk. Reserve 4MiB for its transient nodes/control,
// native frame <=16KiB, Book's entire8256-cell ledger, bounded recursion/blocks,
// copied/indexed String backing, directory/observed nodes and streamed rosters.
// Exact current capacities are checked too; opaque live SDK memory is Unknown.
fn control_bound(descriptor: &Vec<u8>, raw: &Vec<u8>, inventory: &Inventory, index: &InventoryIndex<'_>, native_bytes: usize) -> Option<usize> {
    let mut bytes = (4usize * 1024 * 1024).checked_add(NATIVE_FRAME_LIMIT)?
        .checked_add(17usize.checked_mul(65536)?)? // Bounded retained walk frames.
        .checked_add(128 * 1024)? // Read block, fixed rosters and control/signal DATA.
        .checked_add(RECORDS.checked_mul(size_of::<Record>())?)?
        .checked_add(native_bytes)?.checked_add(descriptor.capacity())?.checked_add(raw.capacity())?
        .checked_add(inventory.files.capacity().checked_mul(size_of::<data::Entry>())?)?;
    for entry in &inventory.files { bytes = bytes.checked_add(entry.path.capacity())?.checked_add(entry.sha256.capacity())?; }
    for path in index.files.keys().chain(index.directories.iter()) {
        // Original index + observed path + transient constructed path,
        // historical Book names and at most one full immediate roster per path.
        // The extra2048 charges worst-case512-byte unknown short names plus
        // BTree/String/node/control overhead before their mismatch is rejected.
        bytes = bytes.checked_add(path.capacity().checked_mul(4)?)?.checked_add(2048)?;
    }
    Some(bytes)
}

#[cfg(test)]
#[test]
fn installation_roster_uses_fixed_app_name_and_global_inventory_bound() {
    assert!(!runtime::safe_payload_path(paths::APP_NAME));
    assert!(paths::APP_NAME == "Mobile Release Kit.app");
    let paths = ["app/Contents", "app/Contents/Info.plist", "app/Contents/MacOS",
        data::APP_BINARY, "runtime/python", "runtime/python/bin"];
    assert_eq!(paths.iter().filter(|path| immediate_child("app", path)).count(), 1);
    assert_eq!(paths.iter().filter(|path| immediate_child("app/Contents", path)).count(), 2);
    assert!(!immediate_child("app", "application/Contents"));
    assert!(!immediate_child("app", "app/"));
    assert!(!immediate_child("app/Contents", "app/Contents/MacOS/nested"));
}
