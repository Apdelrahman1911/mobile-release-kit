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
const HEADER: usize = 52;
const MAGIC: &[u8; 8] = b"MRKST001";
const RESERVATION: &[u8] = b"MRK application references v1\nprojects\ncredential-references\nversion-allocations\n";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Namespace { Projects, CredentialReferences, VersionAllocations }
impl Namespace {
    fn file(self) -> &'static str { match self { Self::Projects => "projects.state", Self::CredentialReferences => "credential-references.state", Self::VersionAllocations => "version-allocations.state" } }
    fn candidate(self) -> &'static str { match self { Self::Projects => ".projects.next", Self::CredentialReferences => ".credential-references.next", Self::VersionAllocations => ".version-allocations.next" } }
    fn intent(self) -> &'static str { match self { Self::Projects => "projects.intent", Self::CredentialReferences => "credential-references.intent", Self::VersionAllocations => "version-allocations.intent" } }
    fn tag(self) -> u8 { match self { Self::Projects => 1, Self::CredentialReferences => 2, Self::VersionAllocations => 3 } }
}
const NAMESPACES: [Namespace; 3] = [Namespace::Projects, Namespace::CredentialReferences, Namespace::VersionAllocations];

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

    #[cfg(test)]
    thread_local! { static READ_CLOSE_UNKNOWN: std::cell::Cell<bool> = const { std::cell::Cell::new(false) }; }

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
        fn acquire(app_data: &Path, create: bool) -> Result<(Self, bool)> {
            let text = app_data.as_os_str().as_bytes();
            if text.len() > 3500 || !app_data.is_absolute() || text.windows(2).any(|v| v == b"//") || text.ends_with(b"/")
                || text.split(|b| *b == b'/').any(|part| part == b"." || part == b"..")
                || app_data.components().any(|v| !matches!(v, Component::RootDir | Component::Normal(_)))
                || app_data.file_name().and_then(|v| v.to_str()) != Some("dev.mobile-release-kit.desktop") {
                return Err(Error::InvalidRequest.into());
            }
            let names: Vec<_> = app_data.components().filter_map(|c| match c { Component::Normal(n) => Some(n.to_owned()), _ => None }).collect();
            if names.len() < 2 || names.len() > 96 { return Err(Error::InvalidRequest.into()); }
            let root = File::from(fcntl::open("/", OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW, Mode::empty()).map_err(io_error)?);
            let root_key = key(&root)?;
            if !root_key.directory(false) { close(root)?; return Err(Error::Conflict.into()); }
            let mut this = Self { path: app_data.join(DIRECTORY), edges: vec![Edge { file: root, name: OsString::from("/"), original: root_key }], parent_reservation: None };
            let result = (|| {
                for (index, name) in names.iter().enumerate() {
                    let parent = &this.edges.last().ok_or_else(|| StateError::from(Error::StateUnknown))?.file;
                    if create && index + 1 == names.len() {
                        match stat::mkdirat(parent, name.as_os_str(), Mode::from_bits_truncate(0o700)) {
                            Ok(()) => sync(parent)?, Err(Errno::EEXIST) => {}, Err(e) => return Err(io_error(e)),
                        }
                    }
                    let fd = fcntl::openat(parent, name.as_os_str(), OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW, Mode::empty())
                        .map_err(|e| if !create && e == Errno::ENOENT { Error::Unavailable.into() } else { io_error(e) })?;
                    let file = File::from(fd);
                    let original = key(&file)?;
                    if !original.directory(false) { close(file)?; return Err(Error::Conflict.into()); }
                    this.edges.push(Edge { file, name: name.clone(), original });
                }
                let parent = &this.edges.last().ok_or_else(|| StateError::from(Error::StateUnknown))?.file;
                // The marker is outside the child: deletion/replacement of the
                // entire child cannot masquerade as first use with empty state.
                let child = named(parent, DIRECTORY)?;
                let marker = named(parent, PARENT_RESERVATION)?;
                let created = match (child, marker) {
                    (None, None) if create => {
                        stat::mkdirat(parent, DIRECTORY, Mode::from_bits_truncate(0o700)).map_err(io_error)?;
                        sync(parent)?; true
                    }
                    (None, None) => return Err(Error::Unavailable.into()),
                    (Some(_), Some(_)) => false,
                    _ => return Err(Error::RecoveryRequired.into()),
                };
                let fd: OwnedFd = fcntl::openat(parent, DIRECTORY, OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW, Mode::empty()).map_err(io_error)?;
                let file = File::from(fd);
                let original = key(&file)?;
                if !original.directory(true) { close(file)?; return Err(Error::Conflict.into()); }
                let mut binding = b"MRK service root v1\n".to_vec();
                binding.extend(original.device.to_be_bytes()); binding.extend(original.inode.to_be_bytes());
                let (reservation_key, reservation_bytes) = if created {
                    let created_key = create_private(parent, PARENT_RESERVATION, &binding)?;
                    sync(parent)?; (created_key, binding.clone())
                } else { read_private(parent, PARENT_RESERVATION, binding.len(), marker)? };
                if reservation_bytes != binding { close(file)?; return Err(Error::Conflict.into()); }
                this.parent_reservation = Some(reservation_key);
                this.edges.push(Edge { file, name: OsString::from(DIRECTORY), original });
                this.check()?;
                Ok(created)
            })();
            match result { Ok(created) => Ok((this, created)), Err(error) => { this.close()?; Err(error) } }
        }
        pub(crate) fn for_client(app_data: &Path) -> Result<Self> { Self::acquire(app_data, false).map(|v| v.0) }
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
        pub(crate) fn close(mut self) -> Result<()> {
            let mut failed = false;
            while let Some(edge) = self.edges.pop() { failed |= close(edge.file).is_err(); }
            if failed { Err(StateError::unknown(Effect::None)) } else { Ok(()) }
        }
    }

    struct Book {
        directory: Option<Directory>, lock: Option<File>, lock_key: FileKey,
        reservation: FileKey, originals: BTreeMap<Namespace, FileKey>, poisoned: bool, endpoint_active: bool,
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
            let (directory, created) = Directory::acquire(app_data, true)?;
            let result = (|| {
                let flags = OFlag::O_RDWR | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK
                    | if created { OFlag::O_CREAT | OFlag::O_EXCL } else { OFlag::empty() };
                let file = File::from(fcntl::openat(directory.file()?, "owner.lock", flags, Mode::from_bits_truncate(0o600)).map_err(io_error)?);
                let lock_key = key(&file)?;
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
                        sync(&file)?;
                        create_private(directory.file()?, "reservation", RESERVATION)?;
                        sync(directory.file()?)?;
                        for namespace in NAMESPACES {
                            create_private(directory.file()?, namespace.file(), &encode(namespace, Revision(0), &[])?)?;
                        }
                        sync(directory.file()?)?;
                    }
                    let (reservation, contents) = read_private(directory.file()?, "reservation", RESERVATION.len(), None)?;
                    if contents != RESERVATION { return Err(Error::RecoveryRequired.into()); }
                    let mut originals = BTreeMap::new();
                    for namespace in NAMESPACES {
                        if named(directory.file()?, namespace.candidate())?.is_some() || named(directory.file()?, namespace.intent())?.is_some() {
                            return Err(Error::RecoveryRequired.into());
                        }
                        let (key, raw) = read_private(directory.file()?, namespace.file(), MAX_BYTES + HEADER, None)?;
                        decode(namespace, &raw)?;
                        originals.insert(namespace, key);
                    }
                    Ok((reservation, originals))
                })();
                match load { Ok((reservation, originals)) => Ok((file, lock_key, reservation, originals)), Err(error) => { close(file)?; Err(error) } }
            })();
            match result {
                Ok((lock, lock_key, reservation, originals)) => Ok(Self { book: Mutex::new(Book { directory: Some(directory), lock: Some(lock), lock_key,
                    reservation, originals, poisoned: false, endpoint_active: false, #[cfg(test)] cut_after_rename: false }) }),
                Err(error) => { directory.close()?; Err(error) }
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
        pub(crate) fn read(&self, namespace: Namespace) -> Result<Snapshot> {
            let mut book = self.lock()?;
            let result = (|| {
                book.check()?;
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
            let preflight = (|| {
                book.check()?;
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
            if book.endpoint_active { return Err(Error::Busy.into()); }
            book.poisoned = true;
            let mut unknown = false;
            if let Some(lock) = book.lock.take() { unknown |= close(lock).is_err(); }
            if let Some(directory) = book.directory.take() { unknown |= directory.close().is_err(); }
            if unknown { Err(StateError::unknown(Effect::None)) } else { Ok(()) }
        }
    }

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
pub(crate) use native::{create_private, named, read_private, remove_original, sync, uid, Directory, FileKey, PrivateStateDirectory};
#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
pub(crate) use native::Fixture;
