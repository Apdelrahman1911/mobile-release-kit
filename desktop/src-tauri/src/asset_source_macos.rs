//! Darwin project-directory observation only, held by the existing OriginalWork.
//! Not runtime custody, a snapshot/Save lease, or an asset/P2/evidence capability.
//! Each acquisition is recorded before open; the SAME originals are retained
//! outside the blocking worker until every one-use close and its actual join.
#![forbid(unsafe_code)]

use super::*;
use std::{ffi::OsStr, os::{fd::OwnedFd, unix::ffi::OsStrExt}};
use nix::{fcntl::{self, AtFlags, OFlag}, mount::MntFlags,
    sys::{stat::{self, FileStat, Mode, SFlag}, statfs}, unistd};

#[derive(Clone, Copy, PartialEq, Eq)]
enum OriginalState { Reserved, Acquiring, Owned, NoHandle, Closing, Closed, Unknown }
struct Descriptor {
    state: OriginalState, fd: Option<OwnedFd>, parent: Option<usize>,
    name: Vec<u8>, identity: Option<DirectoryIdentity>,
}

pub(crate) struct SourceBook { slots: Vec<Descriptor>, begun: bool, terminal: bool }
impl SourceBook {
    pub(crate) fn new() -> Self { Self { slots: Vec::new(), begun: false, terminal: false } }
    pub(crate) fn not_started(&self) -> bool { !self.begun && self.slots.is_empty() }
    pub(crate) fn settled(&self) -> bool {
        self.terminal && self.slots.iter().all(|slot|
            matches!(slot.state, OriginalState::Closed | OriginalState::NoHandle) && slot.fd.is_none())
    }
    fn begin(&mut self, capacity: usize) -> Result<(), Reason> {
        if !self.not_started() || self.terminal { return Err(Reason::CleanupUnknown); }
        if capacity == 0 || capacity > COMPONENT_LIMIT || capacity > DESCRIPTOR_LIMIT { return Err(Reason::Capacity); }
        self.slots.try_reserve_exact(capacity).map_err(|_| Reason::Capacity)?;
        self.begun = true; Ok(())
    }
    fn reserve(&mut self, parent: Option<usize>, name: &[u8]) -> Result<usize, Reason> {
        if !self.begun || self.terminal || self.slots.len() >= self.slots.capacity()
            || self.slots.len() >= COMPONENT_LIMIT { return Err(Reason::Capacity); }
        let mut owned_name = Vec::new(); owned_name.try_reserve_exact(name.len()).map_err(|_| Reason::Capacity)?;
        owned_name.extend_from_slice(name);
        let index = self.slots.len();
        self.slots.push(Descriptor { state: OriginalState::Reserved, fd: None, parent, name: owned_name, identity: None });
        Ok(index)
    }
    fn fd(&self, index: usize) -> Result<&OwnedFd, Reason> {
        self.slots.get(index).and_then(|slot| slot.fd.as_ref()).ok_or(Reason::CleanupUnknown)
    }
    fn adopt(&mut self, index: usize, result: nix::Result<OwnedFd>) -> Result<(), Reason> {
        match result {
            Ok(fd) => {
                self.slots[index].fd = Some(fd); self.slots[index].state = OriginalState::Owned; Ok(())
            }
            Err(_) => { self.slots[index].state = OriginalState::NoHandle; Err(Reason::SourceRefused) }
        }
    }
    fn root(&mut self, stop: &mut dyn FnMut() -> bool) -> Result<usize, Reason> {
        checkpoint(stop)?;
        let index = self.reserve(None, b"/")?;
        let before = stat::lstat(Path::new("/")).map_err(|_| Reason::SourceRefused)?;
        checkpoint(stop)?;
        let expected = directory_identity(&before)?;
        self.slots[index].state = OriginalState::Acquiring;
        let opened = fcntl::open(Path::new("/"), directory_flags(), Mode::empty());
        self.adopt(index, opened)?; // Adopt the actual result even after late STOP.
        checkpoint(stop)?;
        filesystem(self.fd(index)?, stop)?;
        let actual = stat::fstat(self.fd(index)?).map_err(|_| Reason::SourceRefused)?;
        checkpoint(stop)?;
        let named = stat::lstat(Path::new("/")).map_err(|_| Reason::SourceRefused)?;
        checkpoint(stop)?;
        if directory_identity(&actual)? != expected || directory_identity(&named)? != expected { return Err(Reason::SourceChanged); }
        self.slots[index].identity = Some(expected); Ok(index)
    }
    fn child(&mut self, parent: usize, name: &[u8], stop: &mut dyn FnMut() -> bool) -> Result<usize, Reason> {
        checkpoint(stop)?;
        let index = self.reserve(Some(parent), name)?;
        let before = stat::fstatat(self.fd(parent)?, OsStr::from_bytes(name), AtFlags::AT_SYMLINK_NOFOLLOW)
            .map_err(|_| Reason::SourceRefused)?;
        checkpoint(stop)?;
        let expected = directory_identity(&before)?;
        self.slots[index].state = OriginalState::Acquiring;
        let opened = fcntl::openat(self.fd(parent)?, OsStr::from_bytes(name), directory_flags(), Mode::empty());
        self.adopt(index, opened)?;
        checkpoint(stop)?;
        filesystem(self.fd(index)?, stop)?;
        let actual = stat::fstat(self.fd(index)?).map_err(|_| Reason::SourceRefused)?;
        checkpoint(stop)?;
        let named = stat::fstatat(self.fd(parent)?, OsStr::from_bytes(name), AtFlags::AT_SYMLINK_NOFOLLOW)
            .map_err(|_| Reason::SourceRefused)?;
        checkpoint(stop)?;
        if directory_identity(&actual)? != expected || directory_identity(&named)? != expected { return Err(Reason::SourceChanged); }
        self.slots[index].identity = Some(expected); Ok(index)
    }
    fn terminal_check(&self, stop: &mut dyn FnMut() -> bool) -> Result<(), Reason> {
        for (index, slot) in self.slots.iter().enumerate().rev() {
            checkpoint(stop)?;
            let expected = slot.identity.ok_or(Reason::SourceChanged)?;
            filesystem(self.fd(index)?, stop)?;
            let actual = stat::fstat(self.fd(index)?).map_err(|_| Reason::SourceChanged)?;
            checkpoint(stop)?;
            if directory_identity(&actual)? != expected { return Err(Reason::SourceChanged); }
            let named = if let Some(parent) = slot.parent {
                stat::fstatat(self.fd(parent)?, OsStr::from_bytes(&slot.name), AtFlags::AT_SYMLINK_NOFOLLOW)
            } else { stat::lstat(Path::new("/")) }.map_err(|_| Reason::SourceChanged)?;
            checkpoint(stop)?;
            if directory_identity(&named)? != expected { return Err(Reason::SourceChanged); }
        }
        Ok(())
    }
    fn close_all(&mut self) -> bool {
        // Do not stop at an independent close failure and never retry EINTR.
        // Acquiring/Closing/Unknown is absorbing, not permission to reconstruct
        // a numeric descriptor, run replacement cleanup, or drop-as-settlement.
        let mut known = true;
        for slot in self.slots.iter_mut().rev() {
            match slot.state {
                OriginalState::Reserved => { slot.state = OriginalState::NoHandle; }
                OriginalState::NoHandle | OriginalState::Closed => {}
                OriginalState::Owned => {
                    slot.state = OriginalState::Closing;
                    match slot.fd.take() {
                        Some(fd) => match unistd::close(fd) {
                            Ok(()) => { slot.state = OriginalState::Closed; }
                            Err(_) => { slot.state = OriginalState::Unknown; known = false; }
                        },
                        None => { slot.state = OriginalState::Unknown; known = false; }
                    }
                }
                OriginalState::Acquiring | OriginalState::Closing | OriginalState::Unknown => { known = false; }
            }
        }
        self.terminal = true;
        known && self.settled()
    }
    fn finish(&mut self, result: Result<ProjectProbe, Reason>, stop: &mut dyn FnMut() -> bool) -> Result<ProjectProbe, Reason> {
        let result = result.and_then(|probe| { self.terminal_check(stop)?; Ok(probe) });
        // The enclosing original task owns the finite cleanup clock. These
        // closes settle the original acquisitions even after STOP/deadline.
        if !self.close_all() { return Err(Reason::CleanupUnknown); }
        checkpoint(stop)?; result
    }
}

fn checkpoint(stop: &mut dyn FnMut() -> bool) -> Result<(), Reason> {
    if stop() { Err(Reason::UserCancelled) } else { Ok(()) }
}
fn directory_flags() -> OFlag {
    OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_DIRECTORY | OFlag::O_NONBLOCK
}
fn directory_identity(stat: &FileStat) -> Result<DirectoryIdentity, Reason> {
    if stat.st_mode & SFlag::S_IFMT.bits() != SFlag::S_IFDIR.bits() { return Err(Reason::SourceRefused); }
    Ok(DirectoryIdentity { dev: u64::try_from(stat.st_dev).map_err(|_| Reason::SourceRefused)?,
        ino: stat.st_ino, mode: u32::from(stat.st_mode), uid: stat.st_uid, gid: stat.st_gid })
}
fn admitted_filesystem(name: &str, flags: MntFlags) -> bool {
    name == "apfs" && flags.contains(MntFlags::MNT_LOCAL)
        && !flags.intersects(MntFlags::MNT_UNION | MntFlags::MNT_AUTOMOUNTED | MntFlags::MNT_IGNORE_OWNERSHIP)
}
fn filesystem(fd: &OwnedFd, stop: &mut dyn FnMut() -> bool) -> Result<(), Reason> {
    checkpoint(stop)?;
    let observed = statfs::fstatfs(fd).map_err(|_| Reason::UnsupportedFilesystem)?;
    checkpoint(stop)?;
    if !admitted_filesystem(observed.filesystem_type_name(), observed.flags()) { return Err(Reason::UnsupportedFilesystem); }
    // APFS System/Data firmlink traversal can cross device IDs. Each actual
    // descriptor must satisfy this local policy; do not impose Linux xdev or
    // path-text aliases, and never canonicalize an arbitrary symlink to pass.
    Ok(())
}
fn parts(path: &Path) -> Result<Vec<&[u8]>, Reason> {
    let bytes = path.as_os_str().as_bytes();
    if bytes.is_empty() || bytes.len() > PATH_LIMIT || bytes[0] != b'/' || bytes.contains(&0)
        || path.to_str().is_none() { return Err(Reason::SourceRefused); }
    let mut components = Vec::new(); components.try_reserve_exact(COMPONENT_LIMIT - 1).map_err(|_| Reason::Capacity)?;
    if bytes == b"/" { return Ok(components); }
    for name in bytes[1..].split(|byte| *byte == b'/') {
        if name.is_empty() || name == b"." || name == b".." || name.len() > 255 || components.len() >= COMPONENT_LIMIT - 1 {
            return Err(Reason::SourceRefused);
        }
        components.push(name);
    }
    Ok(components)
}
pub(crate) fn path_hint(path: &Path) -> Result<(), Reason> { parts(path).map(|_| ()) }

pub(crate) fn probe_project(book: &mut SourceBook, path: PathBuf, origins: &[Arc<OriginWitness>],
    stop: &mut dyn FnMut() -> bool) -> Result<ProjectProbe, Reason> {
    // This platform has no credential session/exclusion backend. A nonempty
    // origin roster must refuse, not silently omit its exclusion obligations.
    if !origins.is_empty() { return Err(Reason::UnsupportedPlatform); }
    let components = parts(&path)?;
    book.begin(components.len() + 1)?;
    let result = (|| {
        let mut leaf = book.root(stop)?;
        for name in components { leaf = book.child(leaf, name, stop)?; }
        let identity = book.slots[leaf].identity.ok_or(Reason::SourceRefused)?;
        Ok(ProjectProbe { path: path.clone(), identity })
    })();
    book.finish(result, stop)
}

// No Mac credential capture, descendant-path (P2) or suffix-based capability.
pub(crate) fn suffix(_: FileKind, _: &Path) -> Result<(), Reason> { Err(Reason::UnsupportedPlatform) }
pub(crate) fn capture(_: &mut SourceBook, _: PathBuf, _: &[RegisteredRoot], _: FileKind,
    _: &mut dyn FnMut() -> bool) -> Result<CapturedSource, Reason> { Err(Reason::UnsupportedPlatform) }
pub(crate) fn probe_project_path(_: &mut SourceBook, _: &RegisteredRoot, _: PathBuf, _: ProjectPathField,
    _: &mut dyn FnMut() -> bool) -> Result<ProjectPathProbe, Reason> { Err(Reason::UnsupportedPlatform) }

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn project_spellings_are_bounded_without_canonicalization() {
        assert!(parts(Path::new("/Users/owner/project")).is_ok());
        assert!(parts(Path::new("/System/Volumes/Data/Users/owner/project")).is_ok());
        for path in ["", "relative", "//Users", "/Users/", "/Users/./project", "/Users/../project", "/nul\0project"] {
            assert!(parts(Path::new(path)).is_err());
        }
        assert!(parts(Path::new(&format!("/{}", "a".repeat(256)))).is_err());
        assert!(parts(Path::new(&format!("/{}", vec!["a"; COMPONENT_LIMIT].join("/")))).is_err());
    }
    #[test]
    fn only_local_ownership_aware_apfs_is_admitted() {
        assert!(admitted_filesystem("apfs", MntFlags::MNT_LOCAL));
        assert!(admitted_filesystem("apfs", MntFlags::MNT_LOCAL | MntFlags::MNT_RDONLY));
        for name in ["hfs", "nfs", "smbfs", "webdav", "autofs", "APFS", ""] {
            assert!(!admitted_filesystem(name, MntFlags::MNT_LOCAL));
        }
        assert!(!admitted_filesystem("apfs", MntFlags::empty()));
        for flag in [MntFlags::MNT_UNION, MntFlags::MNT_AUTOMOUNTED, MntFlags::MNT_IGNORE_OWNERSHIP] {
            assert!(!admitted_filesystem("apfs", MntFlags::MNT_LOCAL | flag));
        }
    }
    #[test]
    fn original_book_never_reuses_or_relabels_unknown_acquisitions() {
        let mut book = SourceBook::new();
        assert!(book.not_started()); assert!(!book.settled());
        book.begin(1).unwrap();
        let index = book.reserve(None, b"/").unwrap();
        assert!(!book.not_started()); assert!(!book.settled());
        book.slots[index].state = OriginalState::Acquiring; // DATA only; no native descriptor exists.
        assert!(!book.close_all()); assert!(!book.settled());
        assert!(!book.close_all()); assert!(book.begin(1).is_err());
        book.slots[index].state = OriginalState::Unknown;
        assert!(!book.close_all()); assert!(!book.settled());
    }
}
