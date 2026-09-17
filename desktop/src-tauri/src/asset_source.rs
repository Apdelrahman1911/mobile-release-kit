//! Original, read-only Linux credential custody. No pathname is renderer authority.
//! The operation retains SourceBook outside its worker. A panic/uncertain close
//! therefore cannot erase its original acquisition facts or authorize a retry.
use std::{path::{Path, PathBuf}, sync::Arc};
use crate::{asset_commands::Reason, credential_format::FileKind};

pub(crate) const PATH_LIMIT: usize = 4096;
const COMPONENT_LIMIT: usize = 128;
pub(crate) const DESCRIPTOR_LIMIT: usize = 512;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct DirectoryIdentity { dev: u64, ino: u64, mode: u32, uid: u32, gid: u32 }
impl DirectoryIdentity {
    pub(crate) fn same_object(self, other: Self) -> bool { self.dev == other.dev && self.ino == other.ino }
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "development-runtime", target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    pub(crate) fn fixture_value(self) -> serde_json::Value {
        serde_json::json!({"device":self.dev.to_string(),"inode":self.ino.to_string(),"mode":self.mode,"owner":self.uid})
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
struct FileIdentity { common: DirectoryIdentity, nlink: u64, size: u64, mtime: (i64, i64), ctime: (i64, i64) }
#[derive(Clone)]
pub(crate) struct RegisteredRoot { pub(crate) path: PathBuf, pub(crate) identity: DirectoryIdentity }

// Native-only metadata hint. Not serialized, hashed into an ID, or a capability
// to recapture bytes. Every later registration probe must match fresh originals.
pub(crate) struct OriginWitness { path: PathBuf, ancestry: Vec<DirectoryIdentity>, leaf: FileIdentity }
pub(crate) struct CapturedSource { pub(crate) bytes: Vec<u8>, pub(crate) origin: Arc<OriginWitness> }
pub(crate) struct ProjectProbe { path: PathBuf, identity: DirectoryIdentity }
impl ProjectProbe {
    pub(crate) fn path(&self) -> &Path { &self.path }
    pub(crate) fn identity(&self) -> DirectoryIdentity { self.identity }
}

pub(crate) fn material_limit(kind: FileKind) -> usize {
    match kind { FileKind::AndroidKeystore => 32 * 1024 * 1024, FileKind::AndroidFirebase => 4 * 1024 * 1024 }
}
fn private_file(mode: u32) -> bool { mode & 0o077 == 0 }
fn roster_limit(counts: impl IntoIterator<Item = usize>, leaf: usize) -> Result<usize, Reason> {
    let mut total = 1usize.checked_add(leaf).ok_or(Reason::Capacity)?;
    for count in counts { total = total.checked_add(count).ok_or(Reason::Capacity)?; }
    if total > DESCRIPTOR_LIMIT { return Err(Reason::Capacity); } Ok(total)
}

#[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
mod linux {
    use super::*;
    use std::{os::{fd::OwnedFd, unix::ffi::OsStrExt}, ffi::OsStr};
    use nix::{fcntl::{self, AtFlags, OFlag}, sys::{stat::{self, FileStat, Mode, SFlag}, statfs}, unistd};

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum OriginalState { Reserved, Acquiring, Owned, NoHandle, Closing, Closed, Unknown }
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Identity { Directory(DirectoryIdentity), File(FileIdentity) }
    // Observation only. These cells neither own descriptors nor influence the
    // production custody state. Fixed counters are recorded at the real calls.
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "development-runtime"))]
    #[derive(Default)]
    struct FixtureTrace { sequence: std::cell::Cell<u32>, failed: std::cell::Cell<bool>, reads: std::cell::Cell<u32>, eof: std::cell::Cell<Option<(u32, usize)>> }
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "development-runtime"))]
    impl FixtureTrace {
        fn next(&self) -> u32 {
            let next = self.sequence.get().checked_add(1).filter(|n| *n <= 8192);
            match next { Some(n) => { self.sequence.set(n); n }, None => { self.failed.set(true); 0 } }
        }
    }
    macro_rules! fixture_mark {
        ($book:expr, $index:expr, $event:expr) => {
            #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "development-runtime"))]
            { $book.slots[$index].trace[$event].set($book.trace.next()); }
        };
    }
    struct Descriptor {
        state: OriginalState, fd: Option<OwnedFd>, parent: Option<usize>, name: Vec<u8>, identity: Option<Identity>,
        #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "development-runtime"))]
        trace: [std::cell::Cell<u32>; 7],
    }
    struct LeafProbe { parent: usize, name: Vec<u8>, identity: FileIdentity }

    pub(crate) struct SourceBook {
        slots: Vec<Descriptor>, probes: Vec<LeafProbe>, begun: bool, terminal: bool,
        #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "development-runtime"))]
        trace: FixtureTrace,
    }
    impl SourceBook {
        pub(crate) fn new() -> Self { Self { slots: Vec::new(), probes: Vec::new(), begun: false, terminal: false,
            #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "development-runtime"))]
            trace: FixtureTrace::default(),
        } }
        pub(crate) fn settled(&self) -> bool {
            self.terminal && self.slots.iter().all(|slot| matches!(slot.state, OriginalState::Closed | OriginalState::NoHandle) && slot.fd.is_none())
        }
        pub(crate) fn not_started(&self) -> bool { !self.begun && self.slots.is_empty() }
        fn begin(&mut self, capacity: usize, probes: usize) -> Result<(), Reason> {
            if self.begun || !self.slots.is_empty() { return Err(Reason::CleanupUnknown); }
            if capacity > DESCRIPTOR_LIMIT || probes > 32 { return Err(Reason::Capacity); }
            self.slots.try_reserve_exact(capacity).map_err(|_| Reason::Capacity)?;
            self.probes.try_reserve_exact(probes).map_err(|_| Reason::Capacity)?;
            self.begun = true; Ok(())
        }
        fn reserve(&mut self, parent: Option<usize>, name: &[u8]) -> Result<usize, Reason> {
            if self.slots.len() >= self.slots.capacity() || self.slots.len() >= DESCRIPTOR_LIMIT { return Err(Reason::Capacity); }
            let name = copy_bytes(name)?;
            let index = self.slots.len();
            self.slots.push(Descriptor { state: OriginalState::Reserved, fd: None, parent, name, identity: None,
                #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "development-runtime"))]
                trace: std::array::from_fn(|_| std::cell::Cell::new(0)),
            });
            fixture_mark!(self, index, 0);
            Ok(index)
        }
        fn fd(&self, index: usize) -> Result<&OwnedFd, Reason> { self.slots.get(index).and_then(|slot| slot.fd.as_ref()).ok_or(Reason::CleanupUnknown) }
        fn directory(&self, index: usize) -> Result<DirectoryIdentity, Reason> {
            match self.slots.get(index).and_then(|slot| slot.identity) { Some(Identity::Directory(id)) => Ok(id), _ => Err(Reason::SourceRefused) }
        }
        fn adopt(&mut self, index: usize, result: nix::Result<OwnedFd>) -> Result<(), Reason> {
            match result {
                Ok(fd) => { self.slots[index].fd = Some(fd); self.slots[index].state = OriginalState::Owned;
                    fixture_mark!(self, index, 2); Ok(()) }
                Err(_) => { self.slots[index].state = OriginalState::NoHandle; Err(Reason::SourceRefused) }
            }
        }
        fn root(&mut self, stop: &mut dyn FnMut() -> bool) -> Result<usize, Reason> {
            checkpoint(stop)?;
            let index = self.reserve(None, b"/")?;
            let before = stat::stat(Path::new("/")).map_err(|_| Reason::SourceRefused)?;
            checkpoint(stop)?;
            let before = directory_identity(&before)?;
            self.slots[index].state = OriginalState::Acquiring;
            fixture_mark!(self, index, 1);
            let result = fcntl::open(Path::new("/"), directory_flags(), Mode::empty());
            self.adopt(index, result)?; // Adopt before observing late STOP.
            checkpoint(stop)?;
            filesystem(self.fd(index)?, stop)?;
            let opened = stat::fstat(self.fd(index)?).map_err(|_| Reason::SourceRefused)?;
            checkpoint(stop)?;
            let after = stat::stat(Path::new("/")).map_err(|_| Reason::SourceRefused)?;
            checkpoint(stop)?;
            if before != directory_identity(&opened)? || before != directory_identity(&after)? { return Err(Reason::SourceChanged); }
            self.slots[index].identity = Some(Identity::Directory(before));
            fixture_mark!(self, index, 3); Ok(index)
        }
        fn child(&mut self, parent: usize, name: &[u8], file: bool, stop: &mut dyn FnMut() -> bool) -> Result<usize, Reason> {
            checkpoint(stop)?;
            let index = self.reserve(Some(parent), name)?;
            let before = stat::fstatat(self.fd(parent)?, OsStr::from_bytes(name), AtFlags::AT_SYMLINK_NOFOLLOW).map_err(|_| Reason::SourceRefused)?;
            checkpoint(stop)?;
            let expected = if file { Identity::File(file_identity(&before)?) } else { Identity::Directory(directory_identity(&before)?) };
            if file && !private_file(before.st_mode) { return Err(Reason::SourceRefused); }
            self.slots[index].state = OriginalState::Acquiring;
            fixture_mark!(self, index, 1);
            let flags = if file { OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK } else { directory_flags() };
            let result = fcntl::openat(self.fd(parent)?, OsStr::from_bytes(name), flags, Mode::empty());
            self.adopt(index, result)?;
            checkpoint(stop)?;
            filesystem(self.fd(index)?, stop)?;
            let opened = stat::fstat(self.fd(index)?).map_err(|_| Reason::SourceRefused)?;
            checkpoint(stop)?;
            let after = stat::fstatat(self.fd(parent)?, OsStr::from_bytes(name), AtFlags::AT_SYMLINK_NOFOLLOW).map_err(|_| Reason::SourceRefused)?;
            checkpoint(stop)?;
            if identity(&opened, file)? != expected || identity(&after, file)? != expected { return Err(Reason::SourceChanged); }
            self.slots[index].identity = Some(expected);
            fixture_mark!(self, index, 3); Ok(index)
        }
        fn chain(&mut self, components: &[&[u8]], stop: &mut dyn FnMut() -> bool) -> Result<Vec<usize>, Reason> {
            let mut indices = Vec::new(); indices.try_reserve_exact(components.len() + 1).map_err(|_| Reason::Capacity)?;
            indices.push(0);
            let mut parent = 0;
            for component in components { parent = self.child(parent, component, false, stop)?; indices.push(parent); }
            Ok(indices)
        }
        fn terminal_check(&self, stop: &mut dyn FnMut() -> bool) -> Result<(), Reason> {
            for probe in self.probes.iter().rev() {
                checkpoint(stop)?;
                let metadata = stat::fstatat(self.fd(probe.parent)?, OsStr::from_bytes(&probe.name), AtFlags::AT_SYMLINK_NOFOLLOW).map_err(|_| Reason::SourceChanged)?;
                checkpoint(stop)?;
                if file_identity(&metadata)? != probe.identity { return Err(Reason::SourceChanged); }
            }
            for (index, slot) in self.slots.iter().enumerate().rev() {
                checkpoint(stop)?;
                let expected = slot.identity.ok_or(Reason::SourceChanged)?;
                filesystem(self.fd(index)?, stop)?;
                let metadata = stat::fstat(self.fd(index)?).map_err(|_| Reason::SourceChanged)?;
                checkpoint(stop)?;
                let file = matches!(expected, Identity::File(_));
                if identity(&metadata, file)? != expected { return Err(Reason::SourceChanged); }
                let entry = if let Some(parent) = slot.parent {
                    stat::fstatat(self.fd(parent)?, OsStr::from_bytes(&slot.name), AtFlags::AT_SYMLINK_NOFOLLOW)
                } else { stat::stat(Path::new("/")) }.map_err(|_| Reason::SourceChanged)?;
                checkpoint(stop)?;
                if identity(&entry, file)? != expected { return Err(Reason::SourceChanged); }
                fixture_mark!(self, index, 4);
            }
            Ok(())
        }
        fn close_all(&mut self) -> bool {
            let mut known = true;
            for slot in self.slots.iter_mut().rev() {
                match slot.state {
                    OriginalState::Reserved => { slot.state = OriginalState::NoHandle; }
                    OriginalState::NoHandle | OriginalState::Closed => {},
                    OriginalState::Owned => {
                        // Retire the stored OwnedFd before the consuming call.
                        // Never retry even EINTR or reconstruct a numeric fd.
                        slot.state = OriginalState::Closing;
                        #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "development-runtime"))]
                        slot.trace[5].set(self.trace.next());
                        match slot.fd.take() {
                            Some(fd) => match unistd::close(fd) {
                                Ok(()) => {
                                    slot.state = OriginalState::Closed;
                                    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "development-runtime"))]
                                    slot.trace[6].set(self.trace.next());
                                },
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
        fn finish<T>(&mut self, result: Result<T, Reason>, stop: &mut dyn FnMut() -> bool) -> Result<T, Reason> {
            let result = result.and_then(|value| { self.terminal_check(stop)?; Ok(value) });
            // Independent original closes run despite another close's failure.
            if !self.close_all() { return Err(Reason::CleanupUnknown); }
            checkpoint(stop)?; result
        }
        #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "development-runtime"))]
        pub(crate) fn fixture_facts(&self) -> Option<serde_json::Value> {
            // Read closed observations only. No fd/path is reopened, duplicated
            // or returned; FileBook counts never stand in for these originals.
            if self.trace.failed.get() { return None; }
            if self.not_started() {
                return (!self.terminal && self.trace.sequence.get() == 0 && self.trace.reads.get() == 0 && self.trace.eof.get().is_none())
                    .then(|| serde_json::json!({"notStarted":true,"originals":[],"reads":0,"eof":null}));
            }
            if !self.settled() || !self.probes.is_empty() || self.slots.len() > 40 { return None; }
            let mut originals = Vec::new();
            let mut previous_close = u32::MAX;
            for (index, slot) in self.slots.iter().enumerate() {
                let order: [u32; 7] = std::array::from_fn(|i| slot.trace[i].get());
                if slot.state != OriginalState::Closed || slot.fd.is_some() || order[0] == 0
                    || !order.windows(2).all(|pair| pair[0] < pair[1]) || order[6] >= previous_close { return None; }
                previous_close = order[5]; // Reverse, nonoverlapping consuming close attempts.
                let (common, size) = match slot.identity? {
                    Identity::Directory(id) => (id, None), Identity::File(id) => (id.common, Some(id.size)),
                };
                if slot.parent.is_some_and(|parent| parent >= index) { return None; }
                originals.push(serde_json::json!({"slot":index,"parent":slot.parent,"identity":common.fixture_value(),"size":size,"order":order}));
            }
            let eof = self.trace.eof.get().map(|(ordinal, bytes)| serde_json::json!({"ordinal":ordinal,"bytes":bytes}));
            Some(serde_json::json!({"notStarted":false,"originals":originals,"reads":self.trace.reads.get(),"eof":eof}))
        }
    }
    fn copy_bytes(bytes: &[u8]) -> Result<Vec<u8>, Reason> {
        let mut result = Vec::new(); result.try_reserve_exact(bytes.len()).map_err(|_| Reason::Capacity)?;
        result.extend_from_slice(bytes); Ok(result)
    }
    fn checkpoint(stop: &mut dyn FnMut() -> bool) -> Result<(), Reason> { if stop() { Err(Reason::UserCancelled) } else { Ok(()) } }
    fn directory_flags() -> OFlag { OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_DIRECTORY }
    fn common(stat: &FileStat) -> DirectoryIdentity { DirectoryIdentity { dev: stat.st_dev, ino: stat.st_ino, mode: stat.st_mode, uid: stat.st_uid, gid: stat.st_gid } }
    fn directory_identity(stat: &FileStat) -> Result<DirectoryIdentity, Reason> {
        if stat.st_mode & SFlag::S_IFMT.bits() != SFlag::S_IFDIR.bits() { return Err(Reason::SourceRefused); } Ok(common(stat))
    }
    fn file_identity(stat: &FileStat) -> Result<FileIdentity, Reason> {
        if stat.st_mode & SFlag::S_IFMT.bits() != SFlag::S_IFREG.bits() { return Err(Reason::SourceRefused); }
        Ok(FileIdentity { common: common(stat), nlink: stat.st_nlink, size: u64::try_from(stat.st_size).map_err(|_| Reason::SourceRefused)?,
            mtime: (stat.st_mtime, stat.st_mtime_nsec), ctime: (stat.st_ctime, stat.st_ctime_nsec) })
    }
    fn identity(stat: &FileStat, file: bool) -> Result<Identity, Reason> {
        if file { file_identity(stat).map(Identity::File) } else { directory_identity(stat).map(Identity::Directory) }
    }
    fn filesystem(fd: &OwnedFd, stop: &mut dyn FnMut() -> bool) -> Result<(), Reason> {
        checkpoint(stop)?;
        let observed = statfs::fstatfs(fd).map_err(|_| Reason::UnsupportedFilesystem)?;
        checkpoint(stop)?;
        if observed.filesystem_type() != statfs::EXT4_SUPER_MAGIC { return Err(Reason::UnsupportedFilesystem); } Ok(())
    }
    fn parts(path: &Path) -> Result<Vec<&[u8]>, Reason> {
        let bytes = path.as_os_str().as_bytes();
        if bytes.is_empty() || bytes.len() > PATH_LIMIT || bytes[0] != b'/' || bytes.contains(&0) { return Err(Reason::SourceRefused); }
        let mut components = Vec::new(); components.try_reserve_exact(COMPONENT_LIMIT - 1).map_err(|_| Reason::Capacity)?;
        if bytes == b"/" { return Ok(components); }
        for component in bytes[1..].split(|byte| *byte == b'/') {
            if component.is_empty() || component == b"." || component == b".." || components.len() >= COMPONENT_LIMIT - 1 { return Err(Reason::SourceRefused); }
            components.push(component);
        }
        Ok(components)
    }
    pub(crate) fn path_hint(path: &Path) -> Result<(), Reason> { parts(path).map(|_| ()) }
    pub(crate) fn suffix(kind: FileKind, path: &Path) -> Result<(), Reason> {
        let names = parts(path)?;
        let leaf = names.last().ok_or(Reason::SourceRefused)?;
        let suffix = leaf.rsplit(|byte| *byte == b'.').next().ok_or(Reason::SourceRefused)?;
        let matches = match kind {
            FileKind::AndroidKeystore => suffix.eq_ignore_ascii_case(b"jks") || suffix.eq_ignore_ascii_case(b"keystore"),
            FileKind::AndroidFirebase => suffix.eq_ignore_ascii_case(b"json"),
        };
        if !matches || !leaf.contains(&b'.') { return Err(Reason::UnsupportedFormat); } Ok(())
    }
    pub(crate) fn capture(book: &mut SourceBook, path: PathBuf, roots: &[RegisteredRoot], kind: FileKind, stop: &mut dyn FnMut() -> bool) -> Result<CapturedSource, Reason> {
        suffix(kind, &path)?;
        if roots.len() > 64 { return Err(Reason::Capacity); }
        let source = parts(&path)?;
        let (leaf_name, parents) = source.split_last().ok_or(Reason::SourceRefused)?;
        let mut root_parts = Vec::new(); root_parts.try_reserve_exact(roots.len()).map_err(|_| Reason::Capacity)?;
        for root in roots { root_parts.push(parts(&root.path)?); }
        let capacity = roster_limit(root_parts.iter().map(Vec::len).chain(std::iter::once(parents.len())), 1)?;
        book.begin(capacity, 0)?;
        let result = (|| {
            book.root(stop)?;
            let mut root_ids = Vec::new(); root_ids.try_reserve_exact(roots.len()).map_err(|_| Reason::Capacity)?;
            for (root, components) in roots.iter().zip(&root_parts) {
                let chain = book.chain(components, stop)?;
                let id = book.directory(*chain.last().ok_or(Reason::SourceRefused)?)?;
                if id != root.identity { return Err(Reason::SourceChanged); } root_ids.push(id);
            }
            let ancestry_indices = book.chain(parents, stop)?;
            let mut ancestry = Vec::new(); ancestry.try_reserve_exact(ancestry_indices.len()).map_err(|_| Reason::Capacity)?;
            for index in &ancestry_indices {
                let id = book.directory(*index)?;
                if root_ids.iter().any(|root| id.same_object(*root)) { return Err(Reason::ProjectOverlap); }
                ancestry.push(id);
            }
            let parent = *ancestry_indices.last().ok_or(Reason::SourceRefused)?;
            let leaf = book.child(parent, leaf_name, true, stop)?;
            let file = match book.slots[leaf].identity { Some(Identity::File(file)) => file, _ => return Err(Reason::SourceRefused) };
            let size = usize::try_from(file.size).map_err(|_| Reason::MaterialLimit)?;
            if size == 0 || size > material_limit(kind) { return Err(Reason::MaterialLimit); }
            let capacity = size.checked_add(1).ok_or(Reason::MaterialLimit)?;
            let mut bytes = Vec::new(); bytes.try_reserve_exact(capacity).map_err(|_| Reason::Capacity)?; bytes.resize(capacity, 0);
            let mut used = 0usize;
            loop {
                checkpoint(stop)?;
                let end = capacity.min(used.saturating_add(1024 * 1024));
                let read = unistd::read(book.fd(leaf)?, &mut bytes[used..end]).map_err(|_| Reason::SourceRefused)?;
                #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "development-runtime"))]
                {
                    let reads = book.trace.reads.get().checked_add(1).filter(|n| *n <= 4096);
                    match reads { Some(n) => book.trace.reads.set(n), None => book.trace.failed.set(true) }
                    if read == 0 {
                        if book.trace.eof.get().is_some() { book.trace.failed.set(true); }
                        book.trace.eof.set(Some((book.trace.next(), used)));
                    }
                }
                checkpoint(stop)?;
                if read == 0 { if used != size { return Err(Reason::SourceChanged); } break; }
                used = used.checked_add(read).ok_or(Reason::SourceChanged)?;
                if used > size { return Err(Reason::SourceChanged); }
            }
            bytes.truncate(size); // Capacity still charges size+1; no whole-file clone.
            Ok(CapturedSource { bytes, origin: Arc::new(OriginWitness { path: path.clone(), ancestry, leaf: file }) })
        })();
        book.finish(result, stop)
    }
    pub(crate) fn probe_project(book: &mut SourceBook, path: PathBuf, origins: &[Arc<OriginWitness>], stop: &mut dyn FnMut() -> bool) -> Result<ProjectProbe, Reason> {
        if origins.len() > 32 || path.to_str().is_none() { return Err(Reason::SourceRefused); }
        let project_parts = parts(&path)?;
        let mut origin_parts = Vec::new(); origin_parts.try_reserve_exact(origins.len()).map_err(|_| Reason::Capacity)?;
        for origin in origins { origin_parts.push(parts(&origin.path)?); }
        let capacity = roster_limit(std::iter::once(project_parts.len()).chain(origin_parts.iter().map(|parts| parts.len().saturating_sub(1))), 0)?;
        book.begin(capacity, origins.len())?;
        let result = (|| {
            book.root(stop)?;
            let project_chain = book.chain(&project_parts, stop)?;
            let project = book.directory(*project_chain.last().ok_or(Reason::SourceRefused)?)?;
            for (origin, components) in origins.iter().zip(&origin_parts) {
                let (leaf_name, parents) = components.split_last().ok_or(Reason::SourceRefused)?;
                let chain = book.chain(parents, stop)?;
                if chain.len() != origin.ancestry.len() { return Err(Reason::ExclusionUnconfirmed); }
                for (index, expected) in chain.iter().zip(&origin.ancestry) {
                    let current = book.directory(*index)?;
                    if current != *expected { return Err(Reason::ExclusionUnconfirmed); }
                    if current.same_object(project) { return Err(Reason::ProjectOverlap); }
                }
                let parent = *chain.last().ok_or(Reason::SourceRefused)?;
                checkpoint(stop)?;
                // Metadata through the fresh original parent ONLY. No source
                // leaf open/read/hash and no recapture of its retained snapshot.
                let metadata = stat::fstatat(book.fd(parent)?, OsStr::from_bytes(leaf_name), AtFlags::AT_SYMLINK_NOFOLLOW).map_err(|_| Reason::ExclusionUnconfirmed)?;
                checkpoint(stop)?;
                if file_identity(&metadata)? != origin.leaf { return Err(Reason::ExclusionUnconfirmed); }
                book.probes.push(LeafProbe { parent, name: copy_bytes(leaf_name)?, identity: origin.leaf });
            }
            Ok(ProjectProbe { path: path.clone(), identity: project })
        })();
        book.finish(result, stop)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn native_spelling_subset_is_byte_exact_without_resolving_anything() {
            for bad in ["relative/a.jks", "/tmp//a.jks", "/tmp/./a.jks", "/tmp/../a.jks", "/tmp/a.jks/", "/tmp/a\0.jks"] { assert!(parts(Path::new(bad)).is_err()); }
            assert!(parts(Path::new("/")).is_ok());
            assert!(suffix(FileKind::AndroidKeystore, Path::new("/fictional/STORE.JKS")).is_ok());
            assert!(suffix(FileKind::AndroidKeystore, Path::new("/fictional/store.p12")).is_err());
            assert!(suffix(FileKind::AndroidFirebase, Path::new("/fictional/google-services.JSON")).is_ok());
        }
        #[test]
        fn unconfirmed_originals_are_not_relabelled_as_known_settlement() {
            let mut book = SourceBook::new();
            assert!(book.not_started()); assert!(!book.settled());
            assert!(book.begin(1, 0).is_ok());
            let index = book.reserve(None, b"/"); assert!(index.is_ok());
            book.slots[0].state = OriginalState::Acquiring;
            book.terminal = true;
            assert!(!book.settled()); // No fake fd, native open, or close is run.
            book.slots[0].state = OriginalState::Unknown;
            assert!(!book.settled());
        }
    }
}
#[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
pub(crate) use linux::{SourceBook, capture, probe_project, suffix, path_hint};

#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu")))]
mod unsupported {
    use super::*;
    pub(crate) struct SourceBook;
    impl SourceBook { pub(crate) fn new() -> Self { Self } pub(crate) fn settled(&self) -> bool { true } pub(crate) fn not_started(&self) -> bool { true } }
    pub(crate) fn suffix(_: FileKind, _: &Path) -> Result<(), Reason> { Err(Reason::UnsupportedPlatform) }
    pub(crate) fn path_hint(_: &Path) -> Result<(), Reason> { Err(Reason::UnsupportedPlatform) }
    pub(crate) fn capture(_: &mut SourceBook, _: PathBuf, _: &[RegisteredRoot], _: FileKind, _: &mut dyn FnMut() -> bool) -> Result<CapturedSource, Reason> { Err(Reason::UnsupportedPlatform) }
    pub(crate) fn probe_project(_: &mut SourceBook, _: PathBuf, _: &[Arc<OriginWitness>], _: &mut dyn FnMut() -> bool) -> Result<ProjectProbe, Reason> { Err(Reason::UnsupportedPlatform) }
}
#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu")))]
pub(crate) use unsupported::{SourceBook, capture, probe_project, suffix, path_hint};

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn permission_rule_is_not_owner_or_single_link_policy() {
        assert!(private_file(0o100400)); assert!(private_file(0o100600)); assert!(private_file(0o100700));
        assert!(!private_file(0o100640)); assert!(!private_file(0o100604));
        let identity = DirectoryIdentity { dev: 1, ino: 2, mode: 0o100600, uid: 9876, gid: 4321 };
        let file = FileIdentity { common: identity, nlink: 9, size: 12, mtime: (1, 2), ctime: (3, 4) };
        assert!(private_file(file.common.mode)); assert!(file.nlink > 1);
    }
    #[test]
    fn physical_directory_identity_ignores_sibling_timestamp_and_link_churn() {
        let a = DirectoryIdentity { dev: 1, ino: 2, mode: 0o40755, uid: 1, gid: 1 };
        let mut b = a; assert!(a == b); b.ino = 3; assert!(!a.same_object(b));
        b = a; b.mode = 0o40700; assert!(a.same_object(b)); assert!(a != b);
    }
    #[test]
    fn complete_roster_is_refused_before_any_open_when_over_capacity() {
        assert!(roster_limit([510], 1).is_ok()); assert!(roster_limit([511], 1).is_err());
        assert!(roster_limit([127; 32], 0).is_err());
    }
}
