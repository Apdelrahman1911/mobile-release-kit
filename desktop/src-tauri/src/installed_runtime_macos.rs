//! Original Darwin installed-runtime inspection and one-use launch slots.
//! These slots plug into Supervisor/EditOwner; they are not another runner.
//! Protected one-shot installation and original writer finality are separate
//! prerequisites. Hashes or retained descriptors never make writable data safe.
#![forbid(unsafe_code)]
use std::{collections::{BTreeMap, BTreeSet}, os::{fd::{AsFd, OwnedFd}, unix::ffi::OsStrExt}, path::{Path, PathBuf}, time::Instant};
use nix::{fcntl::{self, AtFlags, OFlag}, mount::MntFlags, sys::{stat::{self, FileStat, Mode, SFlag}, statfs}, unistd};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::watch;
use mrk_macos_installed_native as native;
use crate::{error::BridgeError, protocol::{strict_json, PROTOCOL}, runtime::{self, VerifiedRuntime}};

pub(crate) use crate::macos_install_paths::{APP, PROTOCOL_SHA, runtime_root};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AdmissionFailure { Stopped, Deadline, Bounds, Native, Ownership, Inventory, Identity, AlreadyUsed, Unknown }
type Result<T> = std::result::Result<T, AdmissionFailure>;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CloseOutcome { Settled, Unknown }
#[derive(Clone, Copy, PartialEq, Eq)]
enum State { Reserved, Acquiring, Owned, NoHandle, Closing, Closed, Unknown }
#[derive(Clone, Copy, PartialEq, Eq)]
struct Identity { dev: i32, ino: u64, mode: u16, uid: u32, gid: u32, links: u16, size: i64,
    mtime: i64, mtime_ns: i64, ctime: i64, ctime_ns: i64 }
impl Identity {
    fn of(s: &FileStat) -> Self { Self { dev: s.st_dev, ino: s.st_ino, mode: s.st_mode, uid: s.st_uid, gid: s.st_gid,
        links: s.st_nlink, size: s.st_size, mtime: s.st_mtime, mtime_ns: s.st_mtime_nsec, ctime: s.st_ctime, ctime_ns: s.st_ctime_nsec } }
}
struct Record { state: State, fd: Option<OwnedFd>, parent: Option<usize>, name: String, identity: Option<Identity> }
struct Book { records: Vec<Record>, started: bool, inspected: bool, prepared: bool, unknown: bool, closed: bool }
fn native_error<T>(_: T) -> AdmissionFailure { AdmissionFailure::Native }
fn checkpoint(end: Instant, stop: &watch::Receiver<bool>) -> Result<()> {
    if *stop.borrow() || stop.has_changed().is_err() { return Err(AdmissionFailure::Stopped); }
    if Instant::now() >= end { return Err(AdmissionFailure::Deadline); } Ok(())
}
fn digest(bytes: &[u8]) -> String { Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect() }
fn sha(value: &str) -> bool { value.len() == 64 && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) }
fn metadata(s: &FileStat, directory: bool) -> Result<Identity> {
    let kind = if directory { SFlag::S_IFDIR } else { SFlag::S_IFREG };
    if s.st_mode & SFlag::S_IFMT.bits() != kind.bits() || s.st_uid != 0 || s.st_mode & 0o7022 != 0
        || (!directory && s.st_nlink != 1) { return Err(AdmissionFailure::Ownership); }
    Ok(Identity::of(s))
}
impl Book {
    fn new() -> Self { Self { records: Vec::new(), started: false, inspected: false, prepared: false, unknown: false, closed: false } }
    fn fd(&self, index: usize) -> Result<&OwnedFd> { self.records.get(index).and_then(|r| r.fd.as_ref()).ok_or(AdmissionFailure::Unknown) }
    fn reserve(&mut self, parent: Option<usize>, name: &str) -> Result<usize> {
        if self.records.len() >= 8256 || self.records.iter().filter(|r| r.fd.is_some()).count() >= 48 { return Err(AdmissionFailure::Bounds); }
        let i = self.records.len(); self.records.push(Record { state: State::Reserved, fd: None, parent, name: name.into(), identity: None }); Ok(i)
    }
    fn filesystem(&self, index: usize) -> Result<()> {
        let fd = self.fd(index)?;
        let fs = statfs::fstatfs(fd).map_err(native_error)?;
        if fs.filesystem_type_name() != "apfs" || !fs.flags().contains(MntFlags::MNT_LOCAL)
            || fs.flags().intersects(MntFlags::MNT_UNION | MntFlags::MNT_AUTOMOUNTED | MntFlags::MNT_IGNORE_OWNERSHIP) {
            return Err(AdmissionFailure::Ownership);
        }
        native::empty_acl(fd.as_fd()).map_err(native_error)
    }
    fn open(&mut self, parent: Option<usize>, name: &str, directory: bool, end: Instant, stop: &watch::Receiver<bool>) -> Result<usize> {
        checkpoint(end, stop)?;
        let index = self.reserve(parent, name)?;
        let before = if let Some(parent) = parent {
            stat::fstatat(self.fd(parent)?, name, AtFlags::AT_SYMLINK_NOFOLLOW)
        } else { stat::lstat(Path::new("/")) }.map_err(native_error)?;
        checkpoint(end, stop)?;
        let identity = metadata(&before, directory)?;
        self.records[index].state = State::Acquiring;
        let flags = OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC
            | if directory { OFlag::O_DIRECTORY } else { OFlag::empty() };
        let opened = if let Some(parent) = parent { fcntl::openat(self.fd(parent)?, name, flags, Mode::empty()) }
            else { fcntl::open(Path::new("/"), flags, Mode::empty()) };
        match opened {
            Ok(fd) => { self.records[index].fd = Some(fd); self.records[index].state = State::Owned; }
            Err(_) => { self.records[index].state = State::NoHandle; return Err(AdmissionFailure::Native); }
        }
        checkpoint(end, stop)?;
        self.filesystem(index)?;
        let after = stat::fstat(self.fd(index)?).map_err(native_error)?;
        if metadata(&after, directory)? != identity { return Err(AdmissionFailure::Identity); }
        self.records[index].identity = Some(identity);
        self.check_name(index, end, stop)?; Ok(index)
    }
    fn check_name(&self, index: usize, end: Instant, stop: &watch::Receiver<bool>) -> Result<()> {
        checkpoint(end, stop)?;
        let record = &self.records[index]; let identity = record.identity.ok_or(AdmissionFailure::Identity)?;
        let actual = stat::fstat(self.fd(index)?).map_err(native_error)?;
        let named = if let Some(parent) = record.parent {
            stat::fstatat(self.fd(parent)?, record.name.as_str(), AtFlags::AT_SYMLINK_NOFOLLOW)
        } else { stat::lstat(Path::new("/")) }.map_err(native_error)?;
        if Identity::of(&actual) != identity || Identity::of(&named) != identity { return Err(AdmissionFailure::Identity); }
        self.filesystem(index)?; checkpoint(end, stop)
    }
    fn chain(&mut self, path: &Path, end: Instant, stop: &watch::Receiver<bool>) -> Result<usize> {
        let bytes = path.as_os_str().as_bytes();
        if bytes.first() != Some(&b'/') || bytes.len() > 4096 { return Err(AdmissionFailure::Bounds); }
        let mut parent = self.open(None, "/", true, end, stop)?;
        for name in bytes[1..].split(|b| *b == b'/') {
            if name.is_empty() || name == b"." || name == b".." { return Err(AdmissionFailure::Bounds); }
            let name = std::str::from_utf8(name).map_err(native_error)?;
            parent = self.open(Some(parent), name, true, end, stop)?;
        }
        Ok(parent)
    }
    fn read(&self, index: usize, size: u64, collect: bool, end: Instant, stop: &watch::Receiver<bool>) -> Result<(String, Vec<u8>)> {
        if size > 512 * 1024 * 1024 || (collect && size > 1024 * 1024) { return Err(AdmissionFailure::Bounds); }
        let fd = self.fd(index)?; native::no_xattrs(fd.as_fd()).map_err(native_error)?;
        if self.records[index].identity.is_none_or(|id| id.size < 0 || id.size as u64 != size) { return Err(AdmissionFailure::Inventory); }
        let mut hash = Sha256::new(); let mut bytes = Vec::new(); let mut count = 0u64; let mut block = [0u8; 65536];
        loop {
            checkpoint(end, stop)?;
            let n = unistd::read(fd, &mut block).map_err(native_error)?;
            if n == 0 { break; }
            count = count.checked_add(n as u64).ok_or(AdmissionFailure::Bounds)?;
            if count > size { return Err(AdmissionFailure::Inventory); }
            hash.update(&block[..n]); if collect { bytes.extend_from_slice(&block[..n]); }
        }
        if count != size { return Err(AdmissionFailure::Inventory); }
        self.check_name(index, end, stop)?;
        Ok((hash.finalize().iter().map(|b| format!("{b:02x}")).collect(), bytes))
    }
    fn close(&mut self, index: usize) -> bool {
        let record = &mut self.records[index];
        match record.state {
            State::Reserved => record.state = State::NoHandle,
            State::Owned => {
                record.state = State::Closing;
                match record.fd.take().map(unistd::close) {
                    Some(Ok(())) => record.state = State::Closed,
                    _ => { record.state = State::Unknown; self.unknown = true; }
                }
            }
            State::NoHandle | State::Closed => {}
            _ => self.unknown = true,
        }
        !self.unknown
    }
    fn walk(&mut self, parent: usize, relative: &str, files: &BTreeMap<String, PayloadFile>, directories: &BTreeSet<String>,
        observed: &mut BTreeSet<String>, selection: &VerifiedRuntime, depth: usize, end: Instant, stop: &watch::Receiver<bool>) -> Result<()> {
        if depth > 16 { return Err(AdmissionFailure::Bounds); }
        let mut buffer = [0u8; 65536]; let mut local = BTreeSet::new();
        loop {
            checkpoint(end, stop)?;
            let used = native::directory_block(self.fd(parent)?.as_fd(), &mut buffer).map_err(native_error)?;
            if used == 0 { break; }
            let mut offset = 0;
            while offset < used {
                if used - offset < 11 { return Err(AdmissionFailure::Inventory); }
                let inode = u64::from_ne_bytes(buffer[offset..offset+8].try_into().map_err(native_error)?);
                let length = usize::from(u16::from_ne_bytes([buffer[offset+9],buffer[offset+10]]));
                let next = offset.checked_add(11+length).filter(|n| *n <= used).ok_or(AdmissionFailure::Inventory)?;
                let name = std::str::from_utf8(&buffer[offset+11..next]).map_err(native_error)?.to_owned(); offset = next;
                if name == "." || name == ".." { continue; }
                if !runtime::safe_payload_path(&name) || name.contains('/') || inode == 0 || !local.insert(name.clone()) { return Err(AdmissionFailure::Inventory); }
                let path = if relative.is_empty() { name.clone() } else { format!("{relative}/{name}") };
                if path == "manifest.json" { continue; }
                if observed.len() >= 8192 || !observed.insert(path.clone()) { return Err(AdmissionFailure::Bounds); }
                let directory = directories.contains(&path);
                if !directory && !files.contains_key(&path) { return Err(AdmissionFailure::Inventory); }
                let index = self.open(Some(parent), &name, directory, end, stop)?;
                let id = self.records[index].identity.ok_or(AdmissionFailure::Identity)?;
                if id.ino != inode || id.gid != 0 || id.mode & 0o7777 != if directory || path == "python/bin/python3" { 0o555 } else { 0o444 } {
                    return Err(AdmissionFailure::Ownership);
                }
                native::no_xattrs(self.fd(index)?.as_fd()).map_err(native_error)?;
                if directory { self.walk(index, &path, files, directories, observed, selection, depth+1, end, stop)?; }
                else {
                    let expected = files.get(&path).ok_or(AdmissionFailure::Inventory)?;
                    if self.read(index, expected.size, false, end, stop)?.0 != expected.sha256 { return Err(AdmissionFailure::Inventory); }
                }
                // Original records survive every close. Keep the launch roots
                // and their ancestors; other inspected payloads need no live fd
                // because verified root ownership/ACL ancestry forbids mutation.
                let absolute = selection.cwd.join(&path);
                let retain = [&selection.python, &selection.core, &selection.bootstrap].iter().any(|p| p.starts_with(&absolute));
                if !retain && !self.close(index) { return Err(AdmissionFailure::Unknown); }
            }
        }
        self.check_name(parent, end, stop)
    }
    fn inspect(&mut self, selection: &VerifiedRuntime, end: Instant, stop: &watch::Receiver<bool>) -> Result<()> {
        if self.started { return Err(AdmissionFailure::AlreadyUsed); }
        self.records.try_reserve_exact(8256).map_err(native_error)?; self.started = true;
        checkpoint(end, stop)?; native::real_user().map_err(native_error)?; checkpoint(end, stop)?;
        // A user-writable drag-copy or checkout app cannot select this runtime.
        let executable = Path::new(APP).join("Contents/MacOS/mobile-release-kit-desktop");
        if std::env::current_exe().map_err(native_error)? != executable { return Err(AdmissionFailure::Ownership); }
        let app_parent = self.chain(executable.parent().ok_or(AdmissionFailure::Bounds)?, end, stop)?;
        let binary = self.open(Some(app_parent), "mobile-release-kit-desktop", false, end, stop)?;
        let id = self.records[binary].identity.ok_or(AdmissionFailure::Identity)?;
        if id.gid != 0 || id.mode & 0o7777 != 0o555 { return Err(AdmissionFailure::Ownership); }
        native::no_xattrs(self.fd(binary)?.as_fd()).map_err(native_error)?;
        if selection.cwd != runtime_root() { return Err(AdmissionFailure::Inventory); }
        let root = self.chain(&selection.cwd, end, stop)?;
        let id = self.records[root].identity.ok_or(AdmissionFailure::Identity)?;
        if id.gid != 0 || id.mode & 0o7777 != 0o555 { return Err(AdmissionFailure::Ownership); }
        native::no_xattrs(self.fd(root)?.as_fd()).map_err(native_error)?;
        let manifest = self.open(Some(root), "manifest.json", false, end, stop)?;
        let id = self.records[manifest].identity.ok_or(AdmissionFailure::Identity)?;
        if id.gid != 0 || id.mode & 0o7777 != 0o444 { return Err(AdmissionFailure::Ownership); }
        let size = u64::try_from(self.records[manifest].identity.ok_or(AdmissionFailure::Identity)?.size).map_err(native_error)?;
        let (hash, bytes) = self.read(manifest, size, true, end, stop)?;
        if Some(hash.as_str()) != option_env!("MRK_BUNDLED_RUNTIME_MANIFEST_SHA256") { return Err(AdmissionFailure::Inventory); }
        let manifest: Manifest = serde_json::from_value(strict_json(&bytes).map_err(native_error)?).map_err(native_error)?;
        if manifest.schema_version != 1 || manifest.protocol != PROTOCOL || manifest.core_version != runtime::CORE_VERSION
            || manifest.target != "aarch64-apple-darwin" || manifest.protocol_sha256 != PROTOCOL_SHA
            || option_env!("MRK_BUNDLED_PROTOCOL_SHA256") != Some(PROTOCOL_SHA)
            || manifest.files.is_empty() || manifest.files.len() > 2048
            || digest(&serde_json::to_vec(&manifest.files).map_err(native_error)?) != manifest.inventory_sha256 { return Err(AdmissionFailure::Inventory); }
        let mut files = BTreeMap::new(); let mut directories = BTreeSet::new(); let mut folded = BTreeSet::new(); let mut total = 0u64;
        let mut previous = String::new();
        for file in manifest.files {
            if !runtime::safe_payload_path(&file.path) || !file.path.is_ascii() || file.path == "manifest.json" || !sha(&file.sha256)
                || file.path <= previous || file.size > 512*1024*1024 { return Err(AdmissionFailure::Inventory); }
            total = total.checked_add(file.size).ok_or(AdmissionFailure::Bounds)?;
            if total > 1024*1024*1024 || (file.path == "core.zip" && file.sha256 != manifest.core_sha256) { return Err(AdmissionFailure::Inventory); }
            previous = file.path.clone(); let mut name = file.path.as_str();
            while let Some((parent, _)) = name.rsplit_once('/') { directories.insert(parent.to_owned()); name = parent; }
            files.insert(file.path.clone(), file);
        }
        for required in runtime::REQUIRED_RUNTIME_RESOURCES { if !files.contains_key(required) { return Err(AdmissionFailure::Inventory); } }
        for name in files.keys().chain(directories.iter()) {
            if !folded.insert(name.to_ascii_lowercase()) { return Err(AdmissionFailure::Inventory); }
        }
        let mut observed = BTreeSet::new(); self.walk(root, "", &files, &directories, &mut observed, selection, 0, end, stop)?;
        if observed.len() != files.len() + directories.len() { return Err(AdmissionFailure::Inventory); }
        checkpoint(end, stop)?; self.inspected = true; Ok(())
    }
    fn prepare(&mut self, end: Instant, stop: &watch::Receiver<bool>) -> Result<()> {
        if !self.inspected || self.prepared || self.closed || self.unknown { return Err(AdmissionFailure::AlreadyUsed); }
        checkpoint(end, stop)?; native::real_user().map_err(native_error)?;
        for (index, record) in self.records.iter().enumerate() {
            if record.state == State::Owned { self.check_name(index, end, stop)?; }
        }
        checkpoint(end, stop)?; self.prepared = true; Ok(())
    }
    fn settle(&mut self) -> CloseOutcome {
        if self.closed { return CloseOutcome::Unknown; }
        for index in (0..self.records.len()).rev() { self.close(index); }
        self.closed = true; if self.settled() { CloseOutcome::Settled } else { CloseOutcome::Unknown }
    }
    fn settled(&self) -> bool { self.closed && !self.unknown && self.records.iter().all(|r|
        r.fd.is_none() && matches!(r.state, State::NoHandle | State::Closed)) }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Manifest { schema_version: u32, protocol: u32, core_version: String, target: String, core_sha256: String,
    protocol_sha256: String, inventory_sha256: String, files: Vec<PayloadFile> }
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PayloadFile { path: String, sha256: String, size: u64 }

// Two distinct sealed input types and slot types; no passive→edit conversion.
// The whole registered Book is moved only by the existing owner's transfer.
macro_rules! slots {
    ($slots:ident, $capability:ident, $profile:ty) => {
        pub(crate) struct $slots { inspection: Option<Book>, acquisition: Option<$capability>, selection: Option<VerifiedRuntime>, settlement: bool }
        pub(crate) struct $capability { original: Book, selection: VerifiedRuntime, claimed: bool, no_effect: bool }
        impl $capability {
            pub(crate) fn prepare_once(&mut self, end: Instant, stop: &watch::Receiver<bool>) -> Result<&VerifiedRuntime> {
                if self.claimed { return Err(AdmissionFailure::AlreadyUsed); }
                self.original.prepare(end, stop)?; Ok(&self.selection)
            }
            pub(crate) fn claim_once(&mut self) -> Result<()> {
                if self.claimed || !self.original.prepared || self.original.unknown || self.original.closed { return Err(AdmissionFailure::AlreadyUsed); }
                self.claimed = true; Ok(())
            }
            pub(crate) fn record_closed_spawn_gate(&mut self) { self.no_effect = true; }
        }
        impl $slots {
            pub(crate) fn new() -> Self { Self { inspection: Some(Book::new()), acquisition: None, selection: None, settlement: false } }
            pub(crate) fn never_started(&self) -> bool { !self.settlement && self.selection.is_none() && self.acquisition.is_none()
                && self.inspection.as_ref().is_some_and(|b| !b.started && b.records.is_empty() && !b.unknown) }
            pub(crate) fn inspect_once(&mut self, profile: $profile, end: Instant, stop: &watch::Receiver<bool>) -> std::result::Result<VerifiedRuntime, BridgeError> {
                if !self.never_started() { return Err(BridgeError::cleanup_unknown()); }
                self.selection = Some(profile.selection()?);
                let selection = self.selection.as_ref().ok_or_else(BridgeError::cleanup_unknown)?;
                let book = self.inspection.as_mut().ok_or_else(BridgeError::cleanup_unknown)?;
                book.inspect(selection, end, stop).map_err(|_| BridgeError::unavailable("The installed Mac runtime failed original custody inspection."))?;
                Ok(VerifiedRuntime { python: selection.python.clone(), bootstrap: selection.bootstrap.clone(), core: selection.core.clone(), cwd: selection.cwd.clone() })
            }
            pub(crate) fn transfer_once(&mut self) -> Result<()> {
                if self.settlement || self.acquisition.is_some() || self.selection.is_none()
                    || !self.inspection.as_ref().is_some_and(|b| b.inspected && !b.unknown && !b.closed) { return Err(AdmissionFailure::AlreadyUsed); }
                let selection = self.selection.take().ok_or(AdmissionFailure::Unknown)?;
                let original = match self.inspection.take() { Some(b) => b, None => { self.selection = Some(selection); return Err(AdmissionFailure::Unknown); } };
                self.acquisition = Some($capability { original, selection, claimed: false, no_effect: false }); Ok(())
            }
            pub(crate) fn capability(&mut self) -> Result<&mut $capability> {
                if self.settlement { return Err(AdmissionFailure::AlreadyUsed); } self.acquisition.as_mut().ok_or(AdmissionFailure::AlreadyUsed)
            }
            pub(crate) fn no_child_effect(&self) -> bool { match (&self.inspection, &self.acquisition) {
                (Some(_), None) => true, (None, Some(c)) => !c.claimed || c.no_effect, _ => false } }
            pub(crate) fn mark_interrupted(&mut self) {
                if let Some(b) = &mut self.inspection { b.unknown = true; }
                if let Some(c) = &mut self.acquisition { c.original.unknown = true; }
            }
            pub(crate) fn settle_originals(&mut self) -> CloseOutcome {
                if self.settlement { return CloseOutcome::Unknown; } self.settlement = true;
                match (&mut self.inspection, &mut self.acquisition) {
                    (Some(b), None) => b.settle(), (None, Some(c)) => c.original.settle(), _ => CloseOutcome::Unknown }
            }
            pub(crate) fn settled(&self) -> bool { self.settlement && match (&self.inspection, &self.acquisition) {
                (Some(b), None) => b.settled(), (None, Some(c)) => c.original.settled(), _ => false } }
        }
    }
}
slots!(PassiveRuntimeSlots, PassiveInstalledRuntime, runtime::PassiveInstalledProfile);
slots!(ConfigurationRuntimeSlots, ConfigurationInstalledRuntime, runtime::ConfigurationInstalledProfile);
slots!(IOSArchiveRuntimeSlots, IOSArchiveInstalledRuntime, runtime::IOSArchiveInstalledProfile);

// The iOS owner lends its original, first-failure-shortened cleanup endpoint.
// STOP is expected during final settlement, not permission to renew a clock.
fn ios_audit_point(end: Instant, original: &watch::Receiver<Instant>) -> Result<()> {
    if original.has_changed().is_err() || Instant::now() >= end.min(*original.borrow()) {
        return Err(AdmissionFailure::Deadline);
    }
    Ok(())
}
impl Book {
    fn ios_check_after_use(&self, end: Instant, original: &watch::Receiver<Instant>) -> Result<()> {
        if !self.inspected || self.closed || self.unknown { return Err(AdmissionFailure::Unknown); }
        for (index, record) in self.records.iter().enumerate() {
            ios_audit_point(end, original)?;
            if record.state != State::Owned { continue; }
            let expected = record.identity.ok_or(AdmissionFailure::Identity)?;
            let actual = stat::fstat(self.fd(index)?).map_err(native_error)?;
            ios_audit_point(end, original)?;
            let named = if let Some(parent) = record.parent {
                stat::fstatat(self.fd(parent)?, record.name.as_str(), AtFlags::AT_SYMLINK_NOFOLLOW)
            } else { stat::lstat(Path::new("/")) }.map_err(native_error)?;
            if Identity::of(&actual) != expected || Identity::of(&named) != expected { return Err(AdmissionFailure::Identity); }
            ios_audit_point(end, original)?;
            self.filesystem(index)?;
            ios_audit_point(end, original)?;
        }
        Ok(())
    }
}
impl IOSArchiveRuntimeSlots {
    pub(crate) fn ios_check_after_use(&self, end: Instant, original: &watch::Receiver<Instant>) -> Result<()> {
        if self.settlement { return Err(AdmissionFailure::AlreadyUsed); }
        match (&self.inspection, &self.acquisition) {
            (None, Some(capability)) if capability.claimed => capability.original.ios_check_after_use(end, original),
            _ => Err(AdmissionFailure::AlreadyUsed),
        }
    }
}

struct IOSXcodeAlias { parent: usize, identity: Identity, target: PathBuf }
/// Distinct tool originals, reusing only Book's finite no-follow descriptor,
/// metadata and one-attempt close primitives. No runtime/tool interchange.
pub(crate) struct IOSXcodeSlots {
    original: Book, alias: Option<IOSXcodeAlias>, developer: Option<usize>, executable: Option<usize>,
    sdk: Option<usize>, developer_path: Option<PathBuf>, sdk_path: Option<PathBuf>,
    signing: Option<[usize; 3]>, recovery_security: Option<usize>, audit: watch::Receiver<Instant>, prepared: bool,
}
impl IOSXcodeSlots {
    pub(crate) fn new(audit: watch::Receiver<Instant>) -> Self {
        Self { original: Book::new(), alias: None, developer: None, executable: None, sdk: None,
            developer_path: None, sdk_path: None, signing: None, recovery_security: None, audit, prepared: false }
    }
    pub(crate) fn inspect_once(&mut self, end: Instant, stop: &watch::Receiver<bool>) -> Result<()> {
        self.inspect_selected(end, stop, false)
    }
    pub(crate) fn inspect_signed_once(&mut self, end: Instant, stop: &watch::Receiver<bool>) -> Result<()> {
        self.inspect_selected(end, stop, true)
    }
    pub(crate) fn inspect_recovery_once(&mut self, end: Instant, stop: &watch::Receiver<bool>) -> Result<()> {
        if self.original.started { return Err(AdmissionFailure::AlreadyUsed); }
        self.original.records.try_reserve_exact(8).map_err(native_error)?;
        self.original.started = true;
        checkpoint(end, stop)?;
        native::real_user().map_err(native_error)?;
        // Recovery has no Xcode/config/material prerequisite. Retain only its
        // one fixed Security original in the same audited tool book.
        let bin = self.original.chain(Path::new("/usr/bin"), end, stop)?;
        self.recovery_security = Some(self.original.open(Some(bin), "security", false, end, stop)?);
        self.original.inspected = true;
        let _ = self.recovery_binding_data()?;
        self.check_current(end, stop)
    }
    fn inspect_selected(&mut self, end: Instant, stop: &watch::Receiver<bool>, signed: bool) -> Result<()> {
        use crate::ios_toolchain::{APPLICATIONS, SDK_COMPONENTS, STANDARD_APP, sibling_target};
        if self.original.started { return Err(AdmissionFailure::AlreadyUsed); }
        self.original.records.try_reserve_exact(32).map_err(native_error)?;
        self.original.started = true;
        checkpoint(end, stop)?;
        native::real_user().map_err(native_error)?;
        let applications = self.original.chain(Path::new(APPLICATIONS), end, stop)?;
        checkpoint(end, stop)?;
        let named = stat::fstatat(self.original.fd(applications)?, STANDARD_APP, AtFlags::AT_SYMLINK_NOFOLLOW).map_err(native_error)?;
        let app = if named.st_mode & SFlag::S_IFMT.bits() == SFlag::S_IFLNK.bits() {
            if named.st_uid != 0 || named.st_nlink != 1 || !(1..=1024).contains(&named.st_size) {
                return Err(AdmissionFailure::Ownership);
            }
            checkpoint(end, stop)?;
            let target = fcntl::readlinkat(self.original.fd(applications)?, STANDARD_APP).map_err(native_error)?;
            let target = PathBuf::from(target);
            let name = sibling_target(target.to_str().ok_or(AdmissionFailure::Bounds)?).ok_or(AdmissionFailure::Inventory)?.to_owned();
            self.alias = Some(IOSXcodeAlias { parent: applications, identity: Identity::of(&named), target });
            self.check_alias(end, stop)?;
            name
        } else { STANDARD_APP.to_owned() };
        // open() refuses a second alias and every symlink below this sibling.
        let mut parent = applications;
        for name in [app.as_str(), "Contents", "Developer"] {
            parent = self.original.open(Some(parent), name, true, end, stop)?;
        }
        self.developer = Some(parent);
        self.developer_path = Some(Path::new(APPLICATIONS).join(&app).join("Contents/Developer"));
        let mut tool = parent;
        for name in ["usr", "bin"] { tool = self.original.open(Some(tool), name, true, end, stop)?; }
        self.executable = Some(self.original.open(Some(tool), "xcodebuild", false, end, stop)?);
        let mut sdk = parent;
        let mut path = self.developer_path.clone().ok_or(AdmissionFailure::Unknown)?;
        for name in SDK_COMPONENTS {
            sdk = self.original.open(Some(sdk), name, true, end, stop)?;
            path.push(name);
        }
        self.sdk = Some(sdk); self.sdk_path = Some(path);
        if signed {
            // These fixed account/validator tools belong to the same retained
            // book and its pre/post audits/consuming closes. No PATH search or
            // second tools owner is introduced for the signed extension.
            let bin = self.original.chain(Path::new("/usr/bin"), end, stop)?;
            let security = self.original.open(Some(bin), "security", false, end, stop)?;
            let codesign = self.original.open(Some(bin), "codesign", false, end, stop)?;
            let openssl = self.original.open(Some(bin), "openssl", false, end, stop)?;
            self.signing = Some([security, codesign, openssl]);
        }
        self.original.inspected = true;
        let _ = self.binding_data()?;
        if signed { let _ = self.signing_binding_data()?; }
        self.check_current(end, stop)?;
        Ok(())
    }
    fn check_alias(&self, end: Instant, stop: &watch::Receiver<bool>) -> Result<()> {
        let Some(alias) = &self.alias else { return Ok(()); };
        checkpoint(end, stop)?;
        let named = stat::fstatat(self.original.fd(alias.parent)?, crate::ios_toolchain::STANDARD_APP,
            AtFlags::AT_SYMLINK_NOFOLLOW).map_err(native_error)?;
        if Identity::of(&named) != alias.identity { return Err(AdmissionFailure::Identity); }
        checkpoint(end, stop)?;
        let target = fcntl::readlinkat(self.original.fd(alias.parent)?, crate::ios_toolchain::STANDARD_APP).map_err(native_error)?;
        if PathBuf::from(target) != alias.target { return Err(AdmissionFailure::Identity); }
        checkpoint(end, stop)
    }
    pub(crate) fn check_before_spawn(&mut self, end: Instant, stop: &watch::Receiver<bool>) -> Result<()> {
        if !self.original.inspected || self.original.closed || self.original.unknown || self.prepared { return Err(AdmissionFailure::AlreadyUsed); }
        self.check_current(end, stop)?;
        self.prepared = true;
        Ok(())
    }
    fn check_current(&self, end: Instant, stop: &watch::Receiver<bool>) -> Result<()> {
        self.check_alias(end, stop)?;
        for index in 0..self.original.records.len() { self.original.check_name(index, end, stop)?; }
        checkpoint(end, stop)
    }
    pub(crate) fn binding_data(&self) -> Result<crate::ios_archive_protocol::ToolchainBinding> {
        use crate::ios_archive_protocol::{RootIdentity, ToolchainBinding};
        if !self.original.inspected || self.original.closed || self.original.unknown { return Err(AdmissionFailure::Unknown); }
        let identity = |index: Option<usize>| -> Result<Identity> {
            self.original.records.get(index.ok_or(AdmissionFailure::Unknown)?).and_then(|r| r.identity).ok_or(AdmissionFailure::Identity)
        };
        let root = |id: Identity| RootIdentity { device: id.dev.to_string(), inode: id.ino.to_string(),
            mode: u32::from(id.mode), uid: id.uid, gid: id.gid };
        let developer = identity(self.developer)?; let sdk = identity(self.sdk)?;
        ToolchainBinding::new_data(self.developer_path.as_ref().ok_or(AdmissionFailure::Unknown)?, root(developer),
            self.tool_data(self.executable)?, self.sdk_path.as_ref().ok_or(AdmissionFailure::Unknown)?, root(sdk))
            .map_err(|_| AdmissionFailure::Inventory)
    }
    fn tool_data(&self, index: Option<usize>) -> Result<crate::ios_archive_protocol::ToolIdentity> {
        use crate::ios_archive_protocol::ToolIdentity;
        let tool = self.original.records.get(index.ok_or(AdmissionFailure::Unknown)?)
            .and_then(|record| record.identity).ok_or(AdmissionFailure::Identity)?;
        let nanos = |seconds: i64, remainder: i64| -> Result<String> {
            if !(0..1_000_000_000).contains(&remainder) { return Err(AdmissionFailure::Identity); }
            seconds.checked_mul(1_000_000_000).and_then(|s| s.checked_add(remainder)).filter(|n| *n >= 0)
                .map(|n| n.to_string()).ok_or(AdmissionFailure::Identity)
        };
        Ok(ToolIdentity { device: tool.dev.to_string(), inode: tool.ino.to_string(), mode: u32::from(tool.mode),
            uid: tool.uid, gid: tool.gid, links: u32::from(tool.links), size: u64::try_from(tool.size).map_err(native_error)?,
            mtime_ns: nanos(tool.mtime, tool.mtime_ns)?, ctime_ns: nanos(tool.ctime, tool.ctime_ns)? })
    }
    pub(crate) fn signing_binding_data(&self) -> Result<crate::ios_archive_protocol::SigningToolBindings> {
        if !self.original.inspected || self.original.closed || self.original.unknown { return Err(AdmissionFailure::Unknown); }
        let [security, codesign, openssl] = self.signing.ok_or(AdmissionFailure::Inventory)?;
        crate::ios_archive_protocol::SigningToolBindings::new_data(self.tool_data(Some(security))?,
            self.tool_data(Some(codesign))?, self.tool_data(Some(openssl))?).map_err(|_| AdmissionFailure::Inventory)
    }
    pub(crate) fn recovery_binding_data(&self) -> Result<crate::ios_archive_protocol::ToolIdentity> {
        if !self.original.inspected || self.original.closed || self.original.unknown
            || self.signing.is_some() || self.developer.is_some() || self.sdk.is_some() || self.executable.is_some() {
            return Err(AdmissionFailure::Inventory);
        }
        self.tool_data(self.recovery_security)
    }
    pub(crate) fn check_after_use(&self, end: Instant) -> Result<()> {
        self.original.ios_check_after_use(end, &self.audit)?;
        if let Some(alias) = &self.alias {
            ios_audit_point(end, &self.audit)?;
            let actual = stat::fstatat(self.original.fd(alias.parent)?, crate::ios_toolchain::STANDARD_APP,
                AtFlags::AT_SYMLINK_NOFOLLOW).map_err(native_error)?;
            if Identity::of(&actual) != alias.identity { return Err(AdmissionFailure::Identity); }
            ios_audit_point(end, &self.audit)?;
            let target = fcntl::readlinkat(self.original.fd(alias.parent)?, crate::ios_toolchain::STANDARD_APP).map_err(native_error)?;
            if PathBuf::from(target) != alias.target { return Err(AdmissionFailure::Identity); }
            ios_audit_point(end, &self.audit)?;
        }
        Ok(())
    }
    pub(crate) fn mark_interrupted(&mut self) { self.original.unknown = true; }
    pub(crate) fn settle_originals(&mut self) -> CloseOutcome { self.original.settle() }
    pub(crate) fn settled(&self) -> bool { self.original.settled() }
}
