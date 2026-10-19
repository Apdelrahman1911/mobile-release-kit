//! Small ordinary-user store for project/credential REFERENCES, never secrets.
//!
//! One held directory and flock coordinate cooperating application hosts. The
//! closed namespaces have a durable creation reservation; missing state is not
//! an empty journal. Each replacement has a separate durable intent fence.
//! A crash/uncertain sync leaves that fence for explicit recovery, not retry.
//! This is not protection from a compromised account or hostile same-UID ABA.
use crate::service_protocol::Error;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs::File, io::{Read, Write}, path::{Component, Path, PathBuf}, sync::{Mutex, MutexGuard}};

pub(crate) const DIRECTORY: &str = "service-v1";
const PARENT_RESERVATION: &str = "service-v1.reservation";
pub(crate) const MAX_BYTES: usize = 1024 * 1024;
/// Closed native metadata, not a renderer DTO or filesystem admission. Keeping
/// this store independent of Desktop source owners preserves the client-only
/// installed CLI graph. The host supplies it only from its genuine source probe.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ApplicationDirectoryIdentity {
    pub(crate) device: u64, pub(crate) inode: u64, pub(crate) mode: u32,
    pub(crate) uid: u32, pub(crate) gid: u32,
}
pub(crate) type ApplicationDirectoryExpectation = (ApplicationDirectoryIdentity, Option<ApplicationDirectoryIdentity>);
const HEADER: usize = 52;
const MAGIC: &[u8; 8] = b"MRKST001";
const RESERVATION: &[u8] = b"MRK application references v1\nprojects\ncredential-references\nversion-allocations\n";
const RESERVATION_V2: &[u8] = b"MRK application references v2\nprojects\ncredential-references\nversion-allocations\napple-provisioning\n";
const APPLE_UPGRADE_INTENT: &str = "apple-provisioning.upgrade-intent";
const RESERVATION_V2_CANDIDATE: &str = ".reservation-v2.next";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Namespace { Projects, CredentialReferences, VersionAllocations, AppleProvisioning }
impl Namespace {
    fn file(self) -> &'static str { match self { Self::Projects => "projects.state", Self::CredentialReferences => "credential-references.state", Self::VersionAllocations => "version-allocations.state", Self::AppleProvisioning => "apple-provisioning.state" } }
    fn candidate(self) -> &'static str { match self { Self::Projects => ".projects.next", Self::CredentialReferences => ".credential-references.next", Self::VersionAllocations => ".version-allocations.next", Self::AppleProvisioning => ".apple-provisioning.next" } }
    fn intent(self) -> &'static str { match self { Self::Projects => "projects.intent", Self::CredentialReferences => "credential-references.intent", Self::VersionAllocations => "version-allocations.intent", Self::AppleProvisioning => "apple-provisioning.intent" } }
    fn tag(self) -> u8 { match self { Self::Projects => 1, Self::CredentialReferences => 2, Self::VersionAllocations => 3, Self::AppleProvisioning => 4 } }
}
// Ordinary first initialization deliberately remains exactly v1/old3.
const NAMESPACES: [Namespace; 3] = [Namespace::Projects, Namespace::CredentialReferences, Namespace::VersionAllocations];
const NAMESPACES_V2: [Namespace; 4] = [Namespace::Projects, Namespace::CredentialReferences, Namespace::VersionAllocations, Namespace::AppleProvisioning];
#[derive(Clone, Copy, PartialEq, Eq)]
enum StoreVersion { V1, V2 }
impl StoreVersion {
    fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes == RESERVATION { Ok(Self::V1) }
        else if bytes == RESERVATION_V2 { Ok(Self::V2) }
        else { Err(Error::RecoveryRequired.into()) }
    }
    fn namespaces(self) -> &'static [Namespace] {
        match self { Self::V1 => &NAMESPACES, Self::V2 => &NAMESPACES_V2 }
    }
    fn supports(self, namespace: Namespace) -> bool {
        self == Self::V2 || namespace != Namespace::AppleProvisioning
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Revision(pub(crate) u64);
pub(crate) struct Snapshot { pub(crate) revision: Revision, pub(crate) bytes: Vec<u8> }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Effect { None, Applied, Unknown }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Durability { NotApplicable, Confirmed, Unknown }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Cleanup { Known, Unknown }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct StateError {
    pub(crate) code: Error,
    pub(crate) effect: Effect,
    pub(crate) durability: Durability,
    pub(crate) cleanup: Cleanup,
}
impl StateError {
    fn refused(code: Error) -> Self { Self { code, effect: Effect::None, durability: Durability::NotApplicable, cleanup: Cleanup::Known } }
    fn unknown(effect: Effect) -> Self { Self { code: Error::StateUnknown, effect, durability: Durability::Unknown, cleanup: Cleanup::Unknown } }
}
impl From<Error> for StateError { fn from(code: Error) -> Self { Self::refused(code) } }
type Result<T> = std::result::Result<T, StateError>;

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod native {
    use super::*;
    use nix::{errno::Errno, fcntl::{self, AtFlags, FlockArg, OFlag}, sys::stat::{self, Mode, SFlag}, unistd};
    use std::{ffi::OsString, os::{fd::{AsRawFd, OwnedFd}, unix::ffi::OsStrExt}};
    use zeroize::Zeroizing;
    use std::time::Instant;

    fn checkpoint(deadline: Option<Instant>) -> Result<()> {
        if deadline.is_some_and(|cutoff| Instant::now() >= cutoff) { Err(Error::Expired.into()) } else { Ok(()) }
    }
    fn application_identity(key: FileKey) -> ApplicationDirectoryIdentity {
        ApplicationDirectoryIdentity { device: key.device, inode: key.inode, mode: key.mode, uid: key.uid, gid: key.gid }
    }

    #[cfg(test)]
    thread_local! {
        static READ_CLOSE_UNKNOWN: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
        static CREATE_PRE_SYNC_REFUSAL: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    }

    pub(crate) fn uid() -> u32 {
        #[cfg(target_os = "linux")]
        { rustix::process::geteuid().as_raw() }
        #[cfg(target_os = "macos")]
        { nix::unistd::geteuid().as_raw() }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) struct FileKey {
        pub(crate) device: u64, pub(crate) inode: u64, pub(crate) mode: u32,
        pub(crate) uid: u32, pub(crate) gid: u32, pub(crate) links: u64,
        pub(crate) size: u64, modified: (i64, i64), changed: (i64, i64),
    }
    impl FileKey {
        fn of(s: &stat::FileStat) -> Self {
            Self { device: s.st_dev as u64, inode: s.st_ino as u64, mode: s.st_mode as u32, uid: s.st_uid,
                gid: s.st_gid, links: s.st_nlink as u64, size: s.st_size as u64,
                modified: (s.st_mtime, s.st_mtime_nsec), changed: (s.st_ctime, s.st_ctime_nsec) }
        }
        pub(crate) fn same_object(self, other: Self) -> bool {
            (self.device, self.inode, self.mode, self.uid, self.gid, self.links)
                == (other.device, other.inode, other.mode, other.uid, other.gid, other.links)
        }
        fn same_directory(self, other: Self) -> bool {
            // Adding a child legitimately changes a directory's link count.
            // That metadata is not an original-directory identity component.
            (self.device, self.inode, self.mode, self.uid, self.gid)
                == (other.device, other.inode, other.mode, other.uid, other.gid)
        }
        fn directory(self, private: bool) -> bool {
            SFlag::from_bits_truncate(self.mode as _) == SFlag::S_IFDIR
                && if private { self.uid == uid() && self.mode & 0o7777 == 0o700 }
                else { [0, uid()].contains(&self.uid) && self.mode & 0o022 == 0 }
        }
        pub(crate) fn private_regular(self, limit: usize) -> bool {
            SFlag::from_bits_truncate(self.mode as _) == SFlag::S_IFREG && self.uid == uid()
                && self.mode & 0o7777 == 0o600 && self.links == 1 && self.size <= limit as u64
        }
        pub(crate) fn private_socket(self) -> bool {
            SFlag::from_bits_truncate(self.mode as _) == SFlag::S_IFSOCK && self.uid == uid()
                && self.mode & 0o7777 == 0o600 && self.links == 1
        }
    }
    fn io_error(_: impl Sized) -> StateError { Error::RecoveryRequired.into() }
    pub(crate) fn key(file: &File) -> Result<FileKey> { stat::fstat(file).map(|s| FileKey::of(&s)).map_err(io_error) }
    pub(crate) fn named(dir: &File, name: &str) -> Result<Option<FileKey>> {
        match stat::fstatat(dir, name, AtFlags::AT_SYMLINK_NOFOLLOW) {
            Ok(s) => Ok(Some(FileKey::of(&s))), Err(Errno::ENOENT) => Ok(None), Err(e) => Err(io_error(e)),
        }
    }
    pub(crate) fn close(file: File) -> Result<()> {
        // close consumes/retire the descriptor before its one native attempt.
        unistd::close(file).map_err(|_| StateError::unknown(Effect::None))
    }
    pub(crate) fn sync(dir: &File) -> Result<()> { unistd::fsync(dir).map_err(|_| StateError::unknown(Effect::Unknown)) }
    pub(crate) fn read_private(dir: &File, name: &str, limit: usize, expected: Option<FileKey>) -> Result<(FileKey, Vec<u8>)> {
        let fd = fcntl::openat(dir, name, OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK, Mode::empty())
            .map_err(io_error)?;
        let mut file = File::from(fd);
        let result = (|| {
            let original = key(&file)?;
            if !original.private_regular(limit) || expected.is_some_and(|e| e != original)
                || named(dir, name)? != Some(original) { return Err(Error::Conflict.into()); }
            // Bound from fstat BEFORE allocating/reading. A malicious extension
            // can consume only limit+1, and the final stat comparison rejects it.
            // The descriptor namespace also uses this bounded reader. Keep
            // capability bytes protected through every post-read check AND
            // the original close, not only once returned to its caller.
            let mut bytes = Zeroizing::new(Vec::with_capacity(original.size as usize));
            (&mut file).take(limit as u64 + 1).read_to_end(&mut bytes).map_err(io_error)?;
            if bytes.len() > limit || bytes.len() as u64 != original.size || key(&file)? != original
                || named(dir, name)? != Some(original) { return Err(Error::Conflict.into()); }
            Ok((original, bytes))
        })();
        let closed = close(file);
        #[cfg(test)]
        let closed = if READ_CLOSE_UNKNOWN.with(|cut| cut.replace(false)) {
            // The real original close still ran once. Only its reported
            // result is faulted; no test leaks or closes a reused descriptor.
            Err(StateError::unknown(Effect::None))
        } else { closed };
        closed?;
        result.map(|(key, mut bytes)| (key, std::mem::take(&mut *bytes)))
    }
    pub(crate) fn create_private(dir: &File, name: &str, bytes: &[u8]) -> Result<FileKey> {
        let fd = fcntl::openat(dir, name, OFlag::O_WRONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW | OFlag::O_CREAT | OFlag::O_EXCL,
            Mode::from_bits_truncate(0o600)).map_err(io_error)?;
        let mut file = File::from(fd);
        let result = (|| {
            let original = key(&file)?;
            if !original.private_regular(0) || named(dir, name)? != Some(original) { return Err(Error::Conflict.into()); }
            #[cfg(test)]
            if CREATE_PRE_SYNC_REFUSAL.with(|cut| cut.replace(false)) {
                // The real exclusive empty file exists, but no write/fsync
                // has occurred. The original close below still runs once.
                return Err(Error::Conflict.into());
            }
            file.write_all(bytes).map_err(|_| StateError::unknown(Effect::None))?;
            sync(&file)?;
            let written = key(&file)?;
            if !original.same_object(written) || written.size != bytes.len() as u64
                || named(dir, name)? != Some(written) { return Err(Error::Conflict.into()); }
            Ok(written)
        })();
        close(file)?;
        result
    }
    pub(crate) fn remove_original(dir: &File, name: &str, original: FileKey) -> Result<()> {
        if named(dir, name)? != Some(original) { return Err(Error::Conflict.into()); }
        unistd::unlinkat(dir, name, unistd::UnlinkatFlags::NoRemoveDir).map_err(|_| StateError::unknown(Effect::Unknown))
    }

    struct Edge { file: File, name: OsString, original: FileKey }
    pub(crate) struct Directory { path: PathBuf, edges: Vec<Edge>, parent_reservation: Option<FileKey> }
    impl Directory {
        fn acquire(app_data: &Path, create: bool, excluded_projects: &[(u64, u64)],
            expected: Option<ApplicationDirectoryExpectation>, deadline: Option<Instant>) -> Result<(Self, bool)> {
            let text = app_data.as_os_str().as_bytes();
            if excluded_projects.len() > crate::service_protocol::PROJECT_LIMIT
                || excluded_projects.iter().any(|(_, inode)| *inode == 0)
                || text.len() > 3500 || !app_data.is_absolute() || text.windows(2).any(|v| v == b"//") || text.ends_with(b"/")
                || text.split(|b| *b == b'/').any(|part| part == b"." || part == b"..")
                || app_data.components().any(|v| !matches!(v, Component::RootDir | Component::Normal(_)))
                || app_data.file_name().and_then(|v| v.to_str()) != Some("dev.mobile-release-kit.desktop") {
                return Err(Error::InvalidRequest.into());
            }
            let names: Vec<_> = app_data.components().filter_map(|c| match c { Component::Normal(n) => Some(n.to_owned()), _ => None }).collect();
            if names.len() < 2 || names.len() > 96 { return Err(Error::InvalidRequest.into()); }
            checkpoint(deadline)?;
            let root = File::from(fcntl::open("/", OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW, Mode::empty()).map_err(io_error)?);
            let root_key = match key(&root) { Ok(key) => key, Err(error) => { close(root)?; return Err(error); } };
            if !root_key.directory(false) || excluded_projects.contains(&(root_key.device, root_key.inode)) {
                close(root)?; return Err(Error::Conflict.into());
            }
            let mut this = Self { path: app_data.join(DIRECTORY), edges: vec![Edge { file: root, name: OsString::from("/"), original: root_key }], parent_reservation: None };
            let mut created_any = false;
            let result = (|| {
                for (index, name) in names.iter().enumerate() {
                    checkpoint(deadline)?;
                    let parent = &this.edges.last().ok_or_else(|| StateError::from(Error::StateUnknown))?.file;
                    let flags = OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW;
                    let expected_leaf = if index + 1 == names.len() { expected } else { None };
                    if let Some((expected_parent, _)) = expected_leaf {
                        if application_identity(key(parent)?) != expected_parent { return Err(Error::Conflict.into()); }
                    }
                    // Inspect an existing leaf before any create attempt. All
                    // SAME held parents were physically excluded when opened;
                    // an absent app-data leaf is the sole path component we
                    // may create. Path spelling does not decide exclusion.
                    let fd = match fcntl::openat(parent, name.as_os_str(), flags, Mode::empty()) {
                        Ok(fd) => {
                            if expected_leaf.is_some_and(|(_, leaf)| leaf.is_none()) {
                                close(File::from(fd))?; return Err(Error::Conflict.into());
                            }
                            fd
                        }
                        Err(Errno::ENOENT) if create && index + 1 == names.len() => {
                            if expected_leaf.is_some_and(|(_, leaf)| leaf.is_some()) { return Err(Error::Conflict.into()); }
                            checkpoint(deadline)?;
                            match stat::mkdirat(parent, name.as_os_str(), Mode::from_bits_truncate(0o700)) {
                                Ok(()) => { created_any = true; sync(parent)?; },
                                Err(Errno::EEXIST) if expected_leaf.is_none() => {},
                                Err(Errno::EEXIST) => return Err(Error::Conflict.into()),
                                Err(e) => return Err(io_error(e)),
                            }
                            fcntl::openat(parent, name.as_os_str(), flags, Mode::empty()).map_err(io_error)?
                        }
                        Err(e) => return Err(if !create && e == Errno::ENOENT { Error::Unavailable.into() } else { io_error(e) }),
                    };
                    let file = File::from(fd);
                    let original = match key(&file) { Ok(key) => key, Err(error) => { close(file)?; return Err(error); } };
                    if !original.directory(false) || excluded_projects.contains(&(original.device, original.inode))
                        || expected_leaf.and_then(|(_, leaf)| leaf).is_some_and(|expected| application_identity(original) != expected) {
                        close(file)?; return Err(Error::Conflict.into());
                    }
                    this.edges.push(Edge { file, name: name.clone(), original });
                }
                let parent_index = this.edges.len().checked_sub(1).ok_or_else(|| StateError::from(Error::StateUnknown))?;
                let parent = &this.edges[parent_index].file;
                checkpoint(deadline)?;
                // The marker is outside the child: deletion/replacement of the
                // entire child cannot masquerade as first use with empty state.
                let child = named(parent, DIRECTORY)?;
                let marker = named(parent, PARENT_RESERVATION)?;
                let created = match (child, marker) {
                    (None, None) if create => {
                        checkpoint(deadline)?;
                        stat::mkdirat(parent, DIRECTORY, Mode::from_bits_truncate(0o700)).map_err(io_error)?;
                        created_any = true;
                        sync(parent)?; true
                    }
                    (None, None) => return Err(Error::Unavailable.into()),
                    (Some(_), Some(_)) => false,
                    _ => return Err(Error::RecoveryRequired.into()),
                };
                let fd: OwnedFd = fcntl::openat(parent, DIRECTORY, OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW, Mode::empty()).map_err(io_error)?;
                let file = File::from(fd);
                let original = match key(&file) { Ok(key) => key, Err(error) => { close(file)?; return Err(error); } };
                if !original.directory(true) || excluded_projects.contains(&(original.device, original.inode)) {
                    close(file)?; return Err(Error::Conflict.into());
                }
                // Retain this same child before a deadline, marker/read or
                // sync can fail. The outer close then attempts EVERY original.
                this.edges.push(Edge { file, name: OsString::from(DIRECTORY), original });
                let parent = &this.edges[parent_index].file;
                let mut binding = b"MRK service root v1\n".to_vec();
                binding.extend(original.device.to_be_bytes()); binding.extend(original.inode.to_be_bytes());
                let (reservation_key, reservation_bytes) = if created {
                    checkpoint(deadline)?;
                    let created_key = create_private(parent, PARENT_RESERVATION, &binding)?;
                    sync(parent)?; (created_key, binding.clone())
                } else { read_private(parent, PARENT_RESERVATION, binding.len(), marker)? };
                if reservation_bytes != binding { return Err(Error::Conflict.into()); }
                this.parent_reservation = Some(reservation_key);
                this.check()?;
                Ok(created)
            })();
            match result {
                Ok(created) => Ok((this, created)),
                Err(mut error) => {
                    if created_any && error.effect == Effect::None {
                        error.effect = Effect::Applied;
                        // Earlier mkdir syncs do not establish durability of
                        // a later marker created before its own first fsync.
                        if error.durability == Durability::NotApplicable { error.durability = Durability::Unknown; }
                    }
                    if let Err(mut cleanup) = this.close() {
                        cleanup.effect = error.effect; return Err(cleanup);
                    }
                    Err(error)
                }
            }
        }
        pub(crate) fn for_client(app_data: &Path) -> Result<Self> { Self::acquire(app_data, false, &[], None, None).map(|v| v.0) }
        pub(crate) fn file(&self) -> Result<&File> { self.edges.last().map(|e| &e.file).ok_or_else(|| Error::Unavailable.into()) }
        pub(crate) fn path(&self) -> &Path { &self.path }
        pub(crate) fn check(&self) -> Result<()> {
            for (i, edge) in self.edges.iter().enumerate() {
                if !edge.original.same_directory(key(&edge.file)?) { return Err(Error::Conflict.into()); }
                if i > 0 {
                    let current = stat::fstatat(&self.edges[i - 1].file, edge.name.as_os_str(), AtFlags::AT_SYMLINK_NOFOLLOW).map_err(io_error)?;
                    if !edge.original.same_directory(FileKey::of(&current)) { return Err(Error::Conflict.into()); }
                }
            }
            let parent = self.edges.get(self.edges.len().checked_sub(2).ok_or_else(|| StateError::from(Error::StateUnknown))?).ok_or_else(|| StateError::from(Error::StateUnknown))?;
            if named(&parent.file, PARENT_RESERVATION)? != self.parent_reservation { return Err(Error::Conflict.into()); }
            Ok(())
        }
        fn contains_ancestor(&self, device: u64, inode: u64) -> bool { self.edges.iter().any(|e| e.original.device == device && e.original.inode == inode) }
        fn application_root(&self) -> Result<(PathBuf, ApplicationDirectoryIdentity)> {
            let original = self.edges.get(self.edges.len().checked_sub(2).ok_or_else(|| StateError::from(Error::StateUnknown))?)
                .ok_or_else(|| StateError::from(Error::StateUnknown))?.original;
            Ok((self.path.parent().ok_or_else(|| StateError::from(Error::StateUnknown))?.to_owned(), application_identity(original)))
        }
        pub(crate) fn close(mut self) -> Result<()> {
            let mut failed = false;
            while let Some(edge) = self.edges.pop() { failed |= close(edge.file).is_err(); }
            if failed { Err(StateError::unknown(Effect::None)) } else { Ok(()) }
        }
    }

    struct Book {
        directory: Option<Directory>, lock: Option<File>, lock_key: FileKey,
        reservation: FileKey, version: StoreVersion, originals: BTreeMap<Namespace, FileKey>, poisoned: bool, endpoint_active: bool,
        native_use: Option<std::sync::Arc<()>>,
        #[cfg(test)] cut_after_rename: bool,
    }
    impl Book {
        fn directory(&self) -> Result<&Directory> { self.directory.as_ref().ok_or_else(|| Error::Unavailable.into()) }
        fn check(&self) -> Result<()> {
            if self.poisoned { return Err(Error::RecoveryRequired.into()); }
            let directory = self.directory()?;
            directory.check()?;
            let lock = self.lock.as_ref().ok_or_else(|| StateError::from(Error::Unavailable))?;
            if key(lock)? != self.lock_key || named(directory.file()?, "owner.lock")? != Some(self.lock_key)
                || named(directory.file()?, "reservation")? != Some(self.reservation) { return Err(Error::Conflict.into()); }
            Ok(())
        }
    }

    pub(crate) struct PrivateStateDirectory { book: Mutex<Book> }
    pub(crate) struct IpcDirectory<'a> { book: MutexGuard<'a, Book> }
    impl IpcDirectory<'_> {
        pub(crate) fn directory(&self) -> Result<&Directory> { self.book.directory() }
    }
    impl PrivateStateDirectory {
        pub(crate) fn open(app_data: &Path) -> Result<Self> {
            Self::open_excluding_projects(app_data, &[])
        }
        /// Native project identities only, supplied by the real registry.
        /// The original directory acquisition excludes every opened ancestor
        /// before descending or creating private state; this is not a claim
        /// about a project that is itself below this directory through aliases.
        pub(crate) fn open_excluding_projects(app_data: &Path, excluded_projects: &[(u64, u64)]) -> Result<Self> {
            Self::open_checked(app_data, excluded_projects, None, None)
        }
        /// The only native host startup route: genuine full-roster source
        /// exclusion, then SAME directory owner with expected presence/identity.
        pub(crate) fn open_after_exclusion(app_data: &Path, excluded_projects: &[(u64, u64)],
            expected: ApplicationDirectoryExpectation, deadline: Instant) -> Result<Self> {
            Self::open_checked(app_data, excluded_projects, Some(expected), Some(deadline))
        }
        fn open_checked(app_data: &Path, excluded_projects: &[(u64, u64)],
            expected: Option<ApplicationDirectoryExpectation>, deadline: Option<Instant>) -> Result<Self> {
            let (directory, created) = Directory::acquire(app_data, true, excluded_projects, expected, deadline)?;
            let result = (|| {
                checkpoint(deadline)?;
                let flags = OFlag::O_RDWR | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK
                    | if created { OFlag::O_CREAT | OFlag::O_EXCL } else { OFlag::empty() };
                let file = File::from(fcntl::openat(directory.file()?, "owner.lock", flags, Mode::from_bits_truncate(0o600)).map_err(io_error)?);
                let lock_key = match key(&file) { Ok(key) => key, Err(error) => { close(file)?; return Err(error); } };
                if !lock_key.private_regular(0) || named(directory.file()?, "owner.lock")? != Some(lock_key) { close(file)?; return Err(Error::Conflict.into()); }
                // Raw flock is used only on this owned file. Closing that same
                // original is the sole release; there is no PID-based owner.
                #[allow(deprecated)]
                if let Err(error) = fcntl::flock(file.as_raw_fd(), FlockArg::LockExclusiveNonblock) {
                    close(file)?;
                    return Err(if error == Errno::EWOULDBLOCK { Error::Busy.into() } else { io_error(error) });
                }
                let load = (|| {
                    if created {
                        checkpoint(deadline)?;
                        sync(&file)?;
                        create_private(directory.file()?, "reservation", RESERVATION)?;
                        sync(directory.file()?)?;
                        for namespace in NAMESPACES {
                            checkpoint(deadline)?;
                            create_private(directory.file()?, namespace.file(), &encode(namespace, Revision(0), &[])?)?;
                        }
                        sync(directory.file()?)?;
                    }
                    let dir = directory.file()?;
                    // A mixed/unfinished upgrade is never an empty namespace
                    // or permission to repair it during ordinary startup.
                    if named(dir, APPLE_UPGRADE_INTENT)?.is_some() || named(dir, RESERVATION_V2_CANDIDATE)?.is_some() {
                        return Err(Error::RecoveryRequired.into());
                    }
                    let (reservation, contents) = read_private(dir, "reservation", RESERVATION_V2.len(), None)?;
                    let version = StoreVersion::parse(&contents)?;
                    if version == StoreVersion::V1 {
                        for name in [Namespace::AppleProvisioning.file(), Namespace::AppleProvisioning.candidate(), Namespace::AppleProvisioning.intent()] {
                            if named(dir, name)?.is_some() { return Err(Error::RecoveryRequired.into()); }
                        }
                    }
                    let mut originals = BTreeMap::new();
                    for &namespace in version.namespaces() {
                        checkpoint(deadline)?;
                        if named(directory.file()?, namespace.candidate())?.is_some() || named(directory.file()?, namespace.intent())?.is_some() {
                            return Err(Error::RecoveryRequired.into());
                        }
                        let (key, raw) = read_private(directory.file()?, namespace.file(), MAX_BYTES + HEADER, None)?;
                        decode(namespace, &raw)?;
                        originals.insert(namespace, key);
                    }
                    Ok((reservation, version, originals))
                })();
                match load { Ok((reservation, version, originals)) => Ok((file, lock_key, reservation, version, originals)), Err(error) => { close(file)?; Err(error) } }
            })();
            match result {
                Ok((lock, lock_key, reservation, version, originals)) => Ok(Self { book: Mutex::new(Book { directory: Some(directory), lock: Some(lock), lock_key,
                    reservation, version, originals, poisoned: false, endpoint_active: false, native_use: None, #[cfg(test)] cut_after_rename: false }) }),
                Err(mut error) => {
                    if created && error.effect == Effect::None {
                        error.effect = Effect::Applied;
                        // owner.lock or a later initial namespace may have
                        // been created before its sync. Do not equate original
                        // descriptor closure with durable complete creation.
                        if error.durability == Durability::NotApplicable { error.durability = Durability::Unknown; }
                    }
                    if let Err(mut cleanup) = directory.close() { cleanup.effect = error.effect; return Err(cleanup); }
                    Err(error)
                }
            }
        }
        fn lock(&self) -> Result<MutexGuard<'_, Book>> { self.book.lock().map_err(|_| StateError::unknown(Effect::Unknown)) }
        pub(crate) fn ipc_directory(&self) -> Result<IpcDirectory<'_>> {
            let book = self.lock()?; book.check()?; Ok(IpcDirectory { book })
        }
        pub(crate) fn begin_endpoint(&self) -> Result<()> {
            let mut book = self.lock()?; book.check()?;
            if book.endpoint_active { return Err(Error::Busy.into()); }
            book.endpoint_active = true; Ok(())
        }
        pub(crate) fn endpoint_settled(&self, known: bool) -> Result<()> {
            let mut book = self.lock()?;
            if !book.endpoint_active { return Err(Error::Conflict.into()); }
            if known { book.endpoint_active = false; Ok(()) }
            else { book.poisoned = true; Err(StateError::unknown(Effect::None)) }
        }
        pub(crate) fn excludes_project(&self, device: u64, inode: u64) -> Result<()> {
            let book = self.lock()?; book.check()?;
            if book.directory()?.contains_ancestor(device, inode) { Err(Error::Conflict.into()) } else { Ok(()) }
        }
        /// Full metadata from the actual held app-data edge, never stat(path).
        pub(crate) fn native_application_root(&self) -> Result<(PathBuf, ApplicationDirectoryIdentity)> {
            let book = self.lock()?; book.check()?; book.directory()?.application_root()
        }
        pub(crate) fn check_application_exclusion(&self, expected: ApplicationDirectoryExpectation) -> Result<()> {
            let book = self.lock()?; book.check()?;
            let directory = book.directory()?;
            let (_, actual) = directory.application_root()?;
            let parent = directory.edges.get(directory.edges.len().checked_sub(3).ok_or_else(|| StateError::from(Error::StateUnknown))?)
                .ok_or_else(|| StateError::from(Error::StateUnknown))?;
            if expected != (application_identity(parent.original), Some(actual)) {
                return Err(Error::Conflict.into());
            }
            Ok(())
        }
        pub(crate) fn read(&self, namespace: Namespace) -> Result<Snapshot> {
            let mut book = self.lock()?;
            if let Err(error) = book.check() { book.poisoned = true; return Err(error); }
            // Unsupported optional namespace is not corrupt old3 custody.
            if !book.version.supports(namespace) { return Err(Error::Unavailable.into()); }
            let result = (|| {
                let expected = *book.originals.get(&namespace).ok_or_else(|| StateError::from(Error::RecoveryRequired))?;
                let (_, raw) = read_private(book.directory()?.file()?, namespace.file(), MAX_BYTES + HEADER, Some(expected))?;
                decode(namespace, &raw)
            })();
            if result.is_err() { book.poisoned = true; }
            result
        }
        pub(crate) fn replace(&self, namespace: Namespace, expected: Revision, bytes: &[u8]) -> Result<Snapshot> {
            if bytes.len() > MAX_BYTES { return Err(Error::InvalidRequest.into()); }
            let mut book = self.lock()?;
            if let Err(error) = book.check() { book.poisoned = true; return Err(error); }
            if !book.version.supports(namespace) { return Err(Error::Unavailable.into()); }
            let preflight = (|| {
                let original = *book.originals.get(&namespace).ok_or_else(|| StateError::from(Error::RecoveryRequired))?;
                let (_, raw) = read_private(book.directory()?.file()?, namespace.file(), MAX_BYTES + HEADER, Some(original))?;
                Ok((original, decode(namespace, &raw)?))
            })();
            let (original, current) = match preflight {
                Ok(value) => value,
                Err(error) => { book.poisoned = true; return Err(error); }
            };
            // A real stale expected revision is a non-mutating CAS refusal,
            // unlike an unconfirmed original read/close or corrupt custody.
            if current.revision != expected { return Err(Error::Conflict.into()); }
            let revision = Revision(expected.0.checked_add(1).ok_or_else(|| StateError::from(Error::StateUnknown))?);
            let next = encode(namespace, revision, bytes)?;
            let mut effect = Effect::None;
            let result = (|| {
                let dir = book.directory()?.file()?;
                if named(dir, namespace.intent())?.is_some() || named(dir, namespace.candidate())?.is_some() {
                    return Err(Error::RecoveryRequired.into());
                }
                // The fence survives candidate rename and failed directory sync.
                let intent = create_private(dir, namespace.intent(), &next[..HEADER])?;
                sync(dir)?;
                let candidate = create_private(dir, namespace.candidate(), &next)?;
                sync(dir)?;
                book.check()?;
                if named(dir, namespace.file())? != Some(original) || named(dir, namespace.candidate())? != Some(candidate) {
                    return Err(Error::Conflict.into());
                }
                effect = Effect::Unknown;
                fcntl::renameat(dir, namespace.candidate(), dir, namespace.file()).map_err(|_| StateError::unknown(effect))?;
                effect = Effect::Applied;
                #[cfg(test)]
                if book.cut_after_rename { return Err(StateError::unknown(effect)); }
                sync(dir)?;
                let (published, actual) = read_private(dir, namespace.file(), MAX_BYTES + HEADER, None)?;
                if !published.same_object(candidate) || actual != next { return Err(StateError::unknown(effect)); }
                remove_original(dir, namespace.intent(), intent)?;
                sync(dir)?;
                Ok(published)
            })();
            match result {
                Ok(published) => { book.originals.insert(namespace, published); Ok(Snapshot { revision, bytes: bytes.to_vec() }) }
                Err(mut error) => {
                    // Never report failed-no-effect after rename, nor silently
                    // retry a namespace that acquired a possibly durable fence.
                    book.poisoned = true;
                    error.effect = effect;
                    if effect != Effect::None { error.code = Error::StateUnknown; error.durability = Durability::Unknown; }
                    Err(error)
                }
            }
        }
        pub(crate) fn close(&self) -> Result<()> {
            let mut book = self.lock()?;
            if book.endpoint_active || book.native_use.is_some() { return Err(Error::Busy.into()); }
            book.poisoned = true;
            let mut unknown = false;
            if let Some(lock) = book.lock.take() { unknown |= close(lock).is_err(); }
            if let Some(directory) = book.directory.take() { unknown |= directory.close().is_err(); }
            if unknown { Err(StateError::unknown(Effect::None)) } else { Ok(()) }
        }
    }

    // Extend this SAME private owner; no second directory/flock or visibility
    // escape for caller-selected filesystem names is introduced.
    include!("application_state_store_native_use.rs");
    include!("application_state_store_apple_upgrade.rs");

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::os::unix::fs::{symlink, PermissionsExt};
        pub(crate) struct Fixture { root: PathBuf, pub(crate) app: PathBuf }
        impl Fixture {
            pub(crate) fn new() -> Self {
                let root = std::env::current_dir().unwrap().join(format!(".service-test-{}", crate::service_protocol::Id::random().unwrap().as_str()));
                std::fs::create_dir(&root).unwrap();
                std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
                Self { app: root.join("dev.mobile-release-kit.desktop"), root }
            }
            pub(crate) fn short() -> Self {
                // Real sockaddr_un limits apply to these transport tests. This
                // fresh private synthetic root is owned/removed by this test,
                // never a preexisting runtime, vault, cache or project.
                let home = PathBuf::from(std::env::var_os("HOME").unwrap());
                let id = crate::service_protocol::Id::random().unwrap();
                let root = home.join(format!(".mrks-{}", &id.as_str()[..16]));
                std::fs::create_dir(&root).unwrap();
                std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
                Self { app: root.join("dev.mobile-release-kit.desktop"), root }
            }
        }
        impl Drop for Fixture {
            fn drop(&mut self) { std::fs::remove_dir_all(&self.root).unwrap(); }
        }
        fn held_directory_identity(path: &Path) -> ApplicationDirectoryIdentity {
            let file = File::open(path).unwrap(); let id = application_identity(key(&file).unwrap());
            close(file).unwrap(); id
        }
        #[test]
        fn native_store_expected_presence_and_identity_refuse_before_service_writes() {
            // Exercise the actual Directory owner. These observed input facts
            // are NOT fabricated SourceBook proofs or APFS qualification.
            let f = Fixture::short(); let parent = held_directory_identity(f.app.parent().unwrap());
            std::fs::create_dir(&f.app).unwrap();
            std::fs::set_permissions(&f.app, std::fs::Permissions::from_mode(0o700)).unwrap();
            let original = held_directory_identity(&f.app);
            let acquire = |expected| Directory::acquire(&f.app, true, &[], Some((parent, expected)), None);
            let error = acquire(None).err().unwrap();
            assert_eq!((error.code, error.effect, error.cleanup), (Error::Conflict, Effect::None, Cleanup::Known));
            assert_eq!(std::fs::read_dir(&f.app).unwrap().count(), 0);

            let retained = f.app.with_file_name("retained-application-directory");
            std::fs::rename(&f.app, &retained).unwrap();
            assert_eq!(acquire(Some(original)).err().unwrap().code, Error::Conflict);
            assert!(!f.app.exists());
            std::fs::create_dir(&f.app).unwrap();
            std::fs::set_permissions(&f.app, std::fs::Permissions::from_mode(0o700)).unwrap();
            assert_eq!(acquire(Some(original)).err().unwrap().code, Error::Conflict);
            assert_eq!(std::fs::read_dir(&f.app).unwrap().count(), 0);
            std::fs::remove_dir(&f.app).unwrap(); // This fixture's own empty replacement only.
            symlink(&retained, &f.app).unwrap();
            assert!(acquire(Some(original)).is_err());
            assert_eq!(std::fs::read_dir(&retained).unwrap().count(), 0);
        }
        #[test]
        fn native_store_expected_parent_deadline_and_forward_roster_are_checked_before_creation() {
            let f = Fixture::short(); let location = f.app.parent().unwrap().join("location");
            std::fs::create_dir(&location).unwrap();
            std::fs::set_permissions(&location, std::fs::Permissions::from_mode(0o700)).unwrap();
            let parent = held_directory_identity(&location);
            let app = location.join("dev.mobile-release-kit.desktop");
            assert_eq!(Directory::acquire(&app, true, &[], Some((parent, None)), Some(Instant::now())).err().unwrap().code, Error::Expired);
            assert!(!app.exists());
            assert_eq!(Directory::acquire(&app, true, &[(parent.device, parent.inode)], Some((parent, None)), None).err().unwrap().code, Error::Conflict);
            assert!(!app.exists());
            std::fs::rename(&location, location.with_file_name("retained-location")).unwrap();
            std::fs::create_dir(&location).unwrap();
            std::fs::set_permissions(&location, std::fs::Permissions::from_mode(0o700)).unwrap();
            assert_eq!(Directory::acquire(&app, true, &[], Some((parent, None)), None).err().unwrap().code, Error::Conflict);
            assert!(!app.exists());

            // Ordinary same-owner success, separate from source qualification.
            let current_parent = held_directory_identity(&location);
            let store = PrivateStateDirectory::open_checked(&app, &[], Some((current_parent, None)), None).unwrap();
            let (path, identity) = store.native_application_root().unwrap();
            assert_eq!(identity, held_directory_identity(&app));
            assert_eq!(path, app); store.close().unwrap();

            // A genuine exclusive marker creation followed by an ordinary
            // refusal before fsync is NOT known durable merely because the
            // preceding application/service mkdirs were already synced.
            let partial = Fixture::short(); let parent = held_directory_identity(partial.app.parent().unwrap());
            CREATE_PRE_SYNC_REFUSAL.with(|cut| cut.set(true));
            let error = Directory::acquire(&partial.app, true, &[], Some((parent, None)), None).err().unwrap();
            assert!(!CREATE_PRE_SYNC_REFUSAL.with(|cut| cut.get()));
            assert_eq!((error.code, error.effect, error.durability, error.cleanup),
                (Error::Conflict, Effect::Applied, Durability::Unknown, Cleanup::Known));
            assert!(std::fs::read(partial.app.join(PARENT_RESERVATION)).unwrap().is_empty());
            assert_eq!(std::fs::read_dir(partial.app.join(DIRECTORY)).unwrap().count(), 0);
        }
        #[test]
        fn all_namespaces_persist_cas_and_exclusive_host() {
            let f = Fixture::new();
            let store = PrivateStateDirectory::open(&f.app).unwrap();
            assert_eq!(PrivateStateDirectory::open(&f.app).err().unwrap().code, Error::Busy);
            assert_eq!(store.read(Namespace::Projects).unwrap().revision, Revision(0));
            let first = store.replace(Namespace::Projects, Revision(0), b"project reference").unwrap();
            assert_eq!(first.revision, Revision(1));
            assert_eq!(store.replace(Namespace::Projects, Revision(0), b"stale").err().unwrap().code, Error::Conflict);
            store.replace(Namespace::CredentialReferences, Revision(0), b"vault revision reference").unwrap();
            store.replace(Namespace::VersionAllocations, Revision(0), b"candidate reservation reference").unwrap();
            store.close().unwrap();
            let reopened = PrivateStateDirectory::open(&f.app).unwrap();
            assert_eq!(reopened.read(Namespace::Projects).unwrap().bytes, b"project reference");
            assert_eq!(reopened.read(Namespace::CredentialReferences).unwrap().bytes, b"vault revision reference");
            assert_eq!(reopened.read(Namespace::VersionAllocations).unwrap().bytes, b"candidate reservation reference");
            reopened.close().unwrap();
        }
        #[test]
        fn missing_namespace_is_not_empty_even_at_first_revision() {
            let f = Fixture::new();
            let store = PrivateStateDirectory::open(&f.app).unwrap(); store.close().unwrap();
            std::fs::remove_file(f.app.join(DIRECTORY).join("credential-references.state")).unwrap();
            assert!(PrivateStateDirectory::open(&f.app).is_err());
            assert!(!f.app.join(DIRECTORY).join("credential-references.state").exists());
        }
        #[test]
        fn missing_or_replaced_entire_directory_does_not_initialize_empty() {
            let f = Fixture::new(); let store = PrivateStateDirectory::open(&f.app).unwrap(); store.close().unwrap();
            std::fs::rename(f.app.join(DIRECTORY), f.app.join("preserved-original")).unwrap();
            assert_eq!(PrivateStateDirectory::open(&f.app).err().unwrap().code, Error::RecoveryRequired);
            assert!(!f.app.join(DIRECTORY).exists());
            std::fs::create_dir(f.app.join(DIRECTORY)).unwrap();
            std::fs::set_permissions(f.app.join(DIRECTORY), std::fs::Permissions::from_mode(0o700)).unwrap();
            assert_eq!(PrivateStateDirectory::open(&f.app).err().unwrap().code, Error::Conflict);
            assert!(!f.app.join(DIRECTORY).join("projects.state").exists());
        }
        #[test]
        fn same_bytes_replacement_and_symlink_are_conflicts() {
            let f = Fixture::new();
            let store = PrivateStateDirectory::open(&f.app).unwrap();
            let path = f.app.join(DIRECTORY).join("projects.state");
            let contents = std::fs::read(&path).unwrap();
            std::fs::rename(&path, path.with_extension("old")).unwrap();
            std::fs::write(&path, contents).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            assert_eq!(store.read(Namespace::Projects).err().unwrap().code, Error::Conflict);
            store.close().unwrap();
            std::fs::remove_file(&path).unwrap();
            symlink(path.with_extension("old"), &path).unwrap();
            assert!(PrivateStateDirectory::open(&f.app).is_err());
        }
        #[test]
        fn interruption_after_rename_retains_fence_and_blocks_restart() {
            let f = Fixture::new();
            let store = PrivateStateDirectory::open(&f.app).unwrap();
            store.book.lock().unwrap().cut_after_rename = true;
            let error = store.replace(Namespace::Projects, Revision(0), b"not a completion claim").err().unwrap();
            assert_eq!((error.effect, error.durability), (Effect::Applied, Durability::Unknown));
            assert!(store.read(Namespace::Projects).is_err());
            store.close().unwrap();
            assert!(f.app.join(DIRECTORY).join("projects.intent").exists());
            assert_eq!(PrivateStateDirectory::open(&f.app).err().unwrap().code, Error::RecoveryRequired);
        }
        #[test]
        fn oversized_input_does_not_create_intent() {
            let f = Fixture::new();
            let store = PrivateStateDirectory::open(&f.app).unwrap();
            assert_eq!(store.replace(Namespace::Projects, Revision(0), &vec![0; MAX_BYTES + 1]).err().unwrap().code, Error::InvalidRequest);
            assert!(!f.app.join(DIRECTORY).join("projects.intent").exists());
            store.close().unwrap();
        }
        #[test]
        fn unconfirmed_preflight_read_close_poisoned_without_creating_intent() {
            let f = Fixture::new();
            let store = PrivateStateDirectory::open(&f.app).unwrap();
            READ_CLOSE_UNKNOWN.with(|cut| cut.set(true));
            let error = store.replace(Namespace::Projects, Revision(0), b"must not publish").err().unwrap();
            assert_eq!((error.code, error.effect, error.cleanup), (Error::StateUnknown, Effect::None, Cleanup::Unknown));
            assert!(store.book.lock().unwrap().poisoned);
            assert!(!f.app.join(DIRECTORY).join("projects.intent").exists());
            assert!(!f.app.join(DIRECTORY).join(".projects.next").exists());
            assert_eq!(store.replace(Namespace::Projects, Revision(0), b"not retryable").err().unwrap().code, Error::RecoveryRequired);
            // This closes the remaining directory/lock; it does not erase the
            // earlier retained read-close error or invent its finality.
            store.close().unwrap();
        }
        #[test]
        fn changed_preflight_original_poisoned_instead_of_reusing_book() {
            let f = Fixture::new();
            let store = PrivateStateDirectory::open(&f.app).unwrap();
            let path = f.app.join(DIRECTORY).join("projects.state");
            std::fs::write(&path, b"corrupt private reference state").unwrap();
            assert_eq!(store.replace(Namespace::Projects, Revision(0), b"must not publish").err().unwrap().code, Error::Conflict);
            assert!(store.book.lock().unwrap().poisoned);
            assert_eq!(store.read(Namespace::CredentialReferences).err().unwrap().code, Error::RecoveryRequired);
            store.close().unwrap();
        }
    }
    #[cfg(test)] pub(crate) use tests::Fixture;
}

fn digest(namespace: Namespace, revision: Revision, bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(MAGIC); hash.update([namespace.tag()]); hash.update(revision.0.to_be_bytes()); hash.update(bytes);
    hash.finalize().into()
}
fn encode(namespace: Namespace, revision: Revision, bytes: &[u8]) -> Result<Vec<u8>> {
    if bytes.len() > MAX_BYTES { return Err(Error::InvalidRequest.into()); }
    let mut raw = Vec::with_capacity(HEADER + bytes.len());
    raw.extend(MAGIC); raw.extend(revision.0.to_be_bytes()); raw.extend((bytes.len() as u32).to_be_bytes());
    raw.extend(digest(namespace, revision, bytes)); raw.extend(bytes);
    Ok(raw)
}
fn decode(namespace: Namespace, raw: &[u8]) -> Result<Snapshot> {
    if raw.len() < HEADER || raw.len() > HEADER + MAX_BYTES || &raw[..8] != MAGIC { return Err(Error::RecoveryRequired.into()); }
    let revision = Revision(u64::from_be_bytes(raw[8..16].try_into().map_err(|_| StateError::from(Error::RecoveryRequired))?));
    let size = u32::from_be_bytes(raw[16..20].try_into().map_err(|_| StateError::from(Error::RecoveryRequired))?) as usize;
    if size != raw.len() - HEADER || raw[20..HEADER] != digest(namespace, revision, &raw[HEADER..]) { return Err(Error::RecoveryRequired.into()); }
    Ok(Snapshot { revision, bytes: raw[HEADER..].to_vec() })
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) use native::{create_private, named, read_private, remove_original, sync, uid, Directory, FileKey, NativeUse, PrivateStateDirectory};
#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
pub(crate) use native::Fixture;
