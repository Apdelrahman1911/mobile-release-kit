//! Original read-only source custody. Linux credentials and the Mac/Windows
//! project-only probes are separate; no pathname is renderer authority.
//! The operation retains SourceBook outside its worker. A panic/uncertain close
//! therefore cannot erase its original acquisition facts or authorize a retry.
use std::{path::{Path, PathBuf}, sync::Arc};
use crate::{asset_commands::{ProjectPathField, Reason}, credential_format::FileKind};

pub(crate) const PATH_LIMIT: usize = 4096;
const COMPONENT_LIMIT: usize = 128;
pub(crate) const DESCRIPTOR_LIMIT: usize = 512;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct DirectoryIdentity { dev: u64, ino: u64, mode: u32, uid: u32, gid: u32 }
impl DirectoryIdentity {
    #[cfg(test)]
    pub(crate) fn synthetic_evidence_identity() -> Self {
        // Predicate DATA only: no path is opened and no native proof is issued.
        Self { dev: 1, ino: 2, mode: 0o40700, uid: 123, gid: 123 }
    }
    pub(crate) fn same_object(self, other: Self) -> bool { self.dev == other.dev && self.ino == other.ino }
    pub(crate) fn preflight_identity(self) -> crate::offline_preflight_protocol::RootIdentity {
        // Projection of the actual registered native directory, never a path
        // hint, evidence test identity or descriptor/cleanup permission.
        crate::offline_preflight_protocol::RootIdentity {
            device: self.dev.to_string(), inode: self.ino.to_string(), mode: self.mode, uid: self.uid, gid: self.gid,
        }
    }
    pub(crate) fn evidence_identity(self) -> crate::candidate_evidence_protocol::RootIdentity {
        crate::candidate_evidence_protocol::RootIdentity {
            device: self.dev.to_string(), inode: self.ino.to_string(), mode: self.mode, uid: self.uid, gid: self.gid,
        }
    }
    pub(crate) fn workflow_identity(self) -> crate::github_workflow_edit_protocol::RegisteredIdentity {
        // This closed private authority DTO is not the test-only projection.
        // Preserve full st_mode and both ownership fields, with lossless u64s.
        crate::github_workflow_edit_protocol::RegisteredIdentity {
            device: self.dev.to_string(), inode: self.ino.to_string(), mode: self.mode, uid: self.uid, gid: self.gid,
        }
    }
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "development-runtime", target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    pub(crate) fn fixture_value(self) -> serde_json::Value {
        serde_json::json!({"device":self.dev.to_string(),"inode":self.ino.to_string(),"mode":self.mode,"owner":self.uid})
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
struct FileIdentity { common: DirectoryIdentity, nlink: u64, size: u64, mtime: (i64, i64), ctime: (i64, i64) }
/// A completed native selection, not a continuing directory lease or write
/// authority. Windows keeps its full native ID; it never invents POSIX facts.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProjectIdentity {
    Posix(DirectoryIdentity),
    Windows { volume: u64, file_id: [u8; 16] },
}
impl ProjectIdentity {
    pub(crate) fn posix(self) -> Result<DirectoryIdentity, Reason> {
        match self { Self::Posix(identity) => Ok(identity), Self::Windows { .. } => Err(Reason::UnsupportedPlatform) }
    }
}
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct RegisteredRoot { pub(crate) path: PathBuf, pub(crate) identity: ProjectIdentity }

/// Test-only registration from an actually held fixture directory. This is not
/// a ProjectProbe or a picker/asset qualification, and no synthetic identity is
/// accepted. The caller retains this original directory through native joins.
#[cfg(all(test, debug_assertions, feature = "development-runtime", not(feature = "desktop-shell"),
    any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64"))))]
pub(crate) fn offline_fixture_root(held: &std::fs::File, path: &Path) -> Result<RegisteredRoot, Reason> {
    use std::os::unix::fs::MetadataExt;
    let actual = held.metadata().map_err(|_| Reason::SourceRefused)?;
    let named = std::fs::symlink_metadata(path).map_err(|_| Reason::SourceRefused)?;
    if !path.is_absolute() || !actual.is_dir() || !named.is_dir() || actual.uid() == 0 || actual.mode() & 0o7777 != 0o700
        || (actual.dev(), actual.ino(), actual.mode(), actual.uid(), actual.gid())
            != (named.dev(), named.ino(), named.mode(), named.uid(), named.gid()) {
        return Err(Reason::SourceRefused);
    }
    Ok(RegisteredRoot { path: path.to_path_buf(), identity: ProjectIdentity::Posix(DirectoryIdentity {
        dev: actual.dev(), ino: actual.ino(), mode: actual.mode(), uid: actual.uid(), gid: actual.gid(),
    }) })
}

// Native-only metadata hint. Not serialized, hashed into an ID, or a capability
// to recapture bytes. Every later registration probe must match fresh originals.
pub(crate) struct OriginWitness { path: PathBuf, ancestry: Vec<DirectoryIdentity>, leaf: FileIdentity }
pub(crate) struct CapturedSource { pub(crate) bytes: Vec<u8>, pub(crate) origin: Arc<OriginWitness> }
#[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
impl OriginWitness {
    // Pure retained DATA accounting; this neither reopens nor qualifies a path.
    pub(crate) fn retained_bytes(&self) -> Option<usize> {
        std::mem::size_of::<Self>().checked_add(self.path.capacity())?
            .checked_add(self.ancestry.capacity().checked_mul(std::mem::size_of::<DirectoryIdentity>())?)
    }
}
#[cfg(all(test, target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
impl CapturedSource {
    pub(crate) fn memory_data(bytes: Vec<u8>) -> Self {
        // Inert census DATA, not source-custody/identity or native test evidence.
        let common = DirectoryIdentity { dev: 1, ino: 2, mode: 0o100600, uid: 123, gid: 123 };
        Self { bytes, origin: Arc::new(OriginWitness { path: "/inert/census".into(), ancestry: Vec::new(),
            leaf: FileIdentity { common, nlink: 1, size: 0, mtime: (0, 0), ctime: (0, 0) } }) }
    }
}
pub(crate) struct ProjectProbe { path: PathBuf, identity: ProjectIdentity }
impl ProjectProbe {
    pub(crate) fn path(&self) -> &Path { &self.path }
    pub(crate) fn identity(&self) -> ProjectIdentity { self.identity }
}
// Metadata-only, point-in-time descendant proof. No native absolute path,
// payload, source witness or reusable file/write authority reaches the DTO.
pub(crate) struct ProjectPathProbe { relative_path: String }
impl ProjectPathProbe { pub(crate) fn into_relative_path(self) -> String { self.relative_path } }

#[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"),
    not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
#[derive(Default)]
pub(crate) struct InstalledCaptureCheckpoint {
    reached: std::sync::atomic::AtomicBool, released: std::sync::atomic::AtomicBool,
}
#[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"),
    not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
impl InstalledCaptureCheckpoint {
    pub(crate) fn reached(&self) -> bool { self.reached.load(std::sync::atomic::Ordering::SeqCst) }
    pub(crate) fn release(&self) -> bool { !self.released.swap(true, std::sync::atomic::Ordering::SeqCst) }
    fn wait(&self, stop: &mut dyn FnMut() -> bool) {
        self.reached.store(true, std::sync::atomic::Ordering::SeqCst);
        while !self.released.load(std::sync::atomic::Ordering::SeqCst) && !stop() {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }
}
#[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"),
    not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct InstalledSourceFacts {
    pub(crate) begun: bool, pub(crate) originals: usize, pub(crate) closes: usize, pub(crate) no_handle: usize,
    pub(crate) reads: u32, pub(crate) eof: bool, pub(crate) bytes: usize,
    pub(crate) terminal_checked: bool, pub(crate) terminal_matched: bool, pub(crate) settled: bool,
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
        #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher")))]
        installed: InstalledSourceFacts,
        #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher")))]
        installed_checkpoint: Option<Arc<InstalledCaptureCheckpoint>>,
    }
    impl SourceBook {
        pub(crate) fn new() -> Self { Self { slots: Vec::new(), probes: Vec::new(), begun: false, terminal: false,
            #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "development-runtime"))]
            trace: FixtureTrace::default(),
            #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher")))]
            installed: InstalledSourceFacts::default(),
            #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher")))]
            installed_checkpoint: None,
        } }
        #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher")))]
        pub(crate) fn installed_checkpoint(&mut self, checkpoint: Arc<InstalledCaptureCheckpoint>) -> bool {
            if self.begun || self.installed_checkpoint.is_some() { return false; }
            self.installed_checkpoint = Some(checkpoint); true
        }
        #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher")))]
        pub(crate) fn installed_facts(&self) -> InstalledSourceFacts {
            // Closed states are written only by the one consuming close. A
            // failed/no-handle acquisition is distinct, never counted a close.
            InstalledSourceFacts { begun: self.begun, originals: self.slots.len(),
                closes: self.slots.iter().filter(|slot| slot.state == OriginalState::Closed && slot.fd.is_none()).count(),
                no_handle: self.slots.iter().filter(|slot| slot.state == OriginalState::NoHandle && slot.fd.is_none()).count(),
                settled: self.not_started() || self.settled(), ..self.installed }
        }
        pub(crate) fn settled(&self) -> bool {
            self.terminal && self.slots.iter().all(|slot| matches!(slot.state, OriginalState::Closed | OriginalState::NoHandle) && slot.fd.is_none())
        }
        pub(crate) fn not_started(&self) -> bool { !self.begun && self.slots.is_empty() }
        // Heap backing only; the census separately includes this fixed book,
        // mutex and Arc cells. settled()/not_started() NEVER imply zero capacity.
        pub(crate) fn retained_bytes(&self) -> Option<usize> {
            let slots = self.slots.capacity().checked_mul(std::mem::size_of::<Descriptor>())?;
            let probes = self.probes.capacity().checked_mul(std::mem::size_of::<LeafProbe>())?;
            let mut bytes = slots.checked_add(probes)?;
            for slot in &self.slots { bytes = bytes.checked_add(slot.name.capacity())?; }
            for probe in &self.probes { bytes = bytes.checked_add(probe.name.capacity())?; }
            Some(bytes)
        }
        #[cfg(test)]
        pub(crate) fn unstarted_backing_data() -> Self {
            // Model the capacity retained if the second reservation refuses.
            // No original descriptor, native call or settlement is fabricated.
            let mut book = Self::new(); book.slots.try_reserve_exact(4).unwrap(); book
        }
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
            let result = result.and_then(|value| {
                let terminal = self.terminal_check(stop);
                #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher")))]
                { self.installed.terminal_checked = true; self.installed.terminal_matched = terminal.is_ok(); }
                terminal?; Ok(value)
            });
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
        for root in roots { root.identity.posix()?; root_parts.push(parts(&root.path)?); }
        let capacity = roster_limit(root_parts.iter().map(Vec::len).chain(std::iter::once(parents.len())), 1)?;
        book.begin(capacity, 0)?;
        let result = (|| {
            book.root(stop)?;
            let mut root_ids = Vec::new(); root_ids.try_reserve_exact(roots.len()).map_err(|_| Reason::Capacity)?;
            for (root, components) in roots.iter().zip(&root_parts) {
                let chain = book.chain(components, stop)?;
                let id = book.directory(*chain.last().ok_or(Reason::SourceRefused)?)?;
                if ProjectIdentity::Posix(id) != root.identity { return Err(Reason::SourceChanged); } root_ids.push(id);
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
                #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher")))]
                {
                    book.installed.reads = book.installed.reads.checked_add(1).ok_or(Reason::Capacity)?;
                    if read == 0 { book.installed.eof = true; book.installed.bytes = used; }
                }
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
            #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher")))]
            if let Some(checkpoint) = &book.installed_checkpoint {
                // After this ORIGINAL EOF, before its terminal identity check.
                // Receipt/relay loss cannot prevent STOP releasing the borrower.
                checkpoint.wait(stop);
            }
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
            Ok(ProjectProbe { path: path.clone(), identity: ProjectIdentity::Posix(project) })
        })();
        book.finish(result, stop)
    }

    struct ProjectPathSpelling<'a> { components: Vec<&'a [u8]>, root_depth: usize, relative_path: String }
    fn project_path_spelling<'a>(root: &Path, path: &'a Path, field: ProjectPathField) -> Result<ProjectPathSpelling<'a>, Reason> {
        // Compare exact admitted component bytes BEFORE any SourceBook effect.
        // Path::components/strip_prefix/canonicalize would normalize spellings
        // this route must refuse. In particular /project2 is not /project.
        let root_parts = parts(root)?;
        let components = parts(path)?;
        if root.to_str().is_none() || path.to_str().is_none() || components.len() <= root_parts.len()
            || !components.starts_with(&root_parts) { return Err(Reason::SourceRefused); }
        let start = root.as_os_str().as_bytes().len() + usize::from(!root_parts.is_empty());
        let relative = std::str::from_utf8(&path.as_os_str().as_bytes()[start..]).map_err(|_| Reason::SourceRefused)?;
        if !crate::release_version_protocol::relative_display_path(relative)
            || !field.accepts_basename(relative.rsplit('/').next().ok_or(Reason::SourceRefused)?) { return Err(Reason::SourceRefused); }
        let relative_path = crate::asset_commands::copy_text(relative).map_err(|error| error.reason)?;
        Ok(ProjectPathSpelling { components, root_depth: root_parts.len(), relative_path })
    }
    fn project_path_file_leaf(file: FileIdentity, parent: DirectoryIdentity) -> bool {
        file.common.mode & SFlag::S_IFMT.bits() == SFlag::S_IFREG.bits()
            && file.nlink == 1 && file.common.dev == parent.dev
    }
    pub(crate) fn probe_project_path(book: &mut SourceBook, root: &RegisteredRoot, path: PathBuf, field: ProjectPathField,
        stop: &mut dyn FnMut() -> bool) -> Result<ProjectPathProbe, Reason> {
        let root_identity = root.identity.posix()?;
        let spelling = project_path_spelling(&root.path, &path, field)?;
        let file = !field.directory();
        let capacity = roster_limit([spelling.components.len() - usize::from(file)], 0)?;
        book.begin(capacity, usize::from(file))?;
        let result = (|| {
            book.root(stop)?;
            let root_chain = book.chain(&spelling.components[..spelling.root_depth], stop)?;
            let mut parent = *root_chain.last().ok_or(Reason::SourceRefused)?;
            if book.directory(parent)? != root_identity { return Err(Reason::SourceChanged); }
            let (leaf, parents) = spelling.components[spelling.root_depth..].split_last().ok_or(Reason::SourceRefused)?;
            // Descendants continue from the SAME checked registered-root
            // descriptor, never a second pathname traversal or fresh parent.
            for name in parents { parent = book.child(parent, name, false, stop)?; }
            if field.directory() {
                book.child(parent, leaf, false, stop)?;
            } else {
                let name = copy_bytes(leaf)?;
                let parent_identity = book.directory(parent)?;
                checkpoint(stop)?;
                // No child(..., true), open/read/hash, extension requirement or
                // credential private_file change. Only no-follow leaf metadata.
                let metadata = stat::fstatat(book.fd(parent)?, OsStr::from_bytes(leaf), AtFlags::AT_SYMLINK_NOFOLLOW).map_err(|_| Reason::SourceRefused)?;
                checkpoint(stop)?;
                let identity = file_identity(&metadata)?;
                if !project_path_file_leaf(identity, parent_identity) { return Err(Reason::SourceRefused); }
                book.probes.push(LeafProbe { parent, name, identity });
            }
            Ok(ProjectPathProbe { relative_path: spelling.relative_path })
        })();
        // Includes the original no-follow leaf probe and directory checks,
        // then every original consuming close, even after refusal/STOP.
        book.finish(result, stop)
    }

    #[cfg(test)]
    pub(crate) fn assert_project_path_source_contracts() {
        // Pure spelling, policy and custody-model contracts only. No stat,
        // descriptor, real filesystem proof or native qualification is created.
        let root = Path::new("/inert/project");
        for (path, field, relative) in [
            ("/inert/project/VERSION", ProjectPathField::VersionSource, "VERSION"),
            ("/inert/project/config/release.json", ProjectPathField::VersionSource, "config/release.json"),
            ("/inert/project/ios/App.xcodeproj", ProjectPathField::IosProject, "ios/App.xcodeproj"),
            ("/inert/project/ios/App.xcworkspace", ProjectPathField::IosWorkspace, "ios/App.xcworkspace"),
            ("/inert/project/metadata/en-US", ProjectPathField::MetadataRoot, "metadata/en-US"),
        ] {
            let spelling = project_path_spelling(root, Path::new(path), field).expect("contained spelling");
            assert_eq!(spelling.relative_path, relative); assert_eq!(spelling.root_depth, 2);
            assert_eq!(spelling.components[spelling.root_depth..].join(&b'/'), relative.as_bytes());
        }
        assert_eq!(project_path_spelling(Path::new("/"), Path::new("/release/VERSION"), ProjectPathField::VersionSource)
            .expect("root descendant").relative_path, "release/VERSION");
        assert_eq!(project_path_spelling(Path::new("/inert/prøject"), Path::new("/inert/prøject/versión"), ProjectPathField::VersionSource)
            .expect("exact UTF-8").relative_path, "versión");
        for path in ["/inert/project", "/inert/project2/VERSION", "/inert/other/VERSION", "/VERSION", "relative/VERSION",
            "/inert/project//VERSION", "/inert/project/./VERSION", "/inert/project/../VERSION", "/inert/project/VERSION/",
            "/inert/project/.hidden", "/inert/project/PrIvAtE/VERSION", "/inert/project/secrets/VERSION",
            "/inert/project/dir/a\0b", "/inert/project/dir/a\nb", "/inert/project/dir/name ", "/inert/project/dir/name.",
            "/inert/project/dir/NUL.txt", "/inert/project/dir/a\\b", "/inert/project/dir/a:b"] {
            assert!(project_path_spelling(root, Path::new(path), ProjectPathField::VersionSource).is_err());
        }
        for bad_root in ["relative", "/inert//project", "/inert/./project", "/inert/project/"] {
            assert!(project_path_spelling(Path::new(bad_root), Path::new("/inert/project/VERSION"), ProjectPathField::VersionSource).is_err());
        }
        assert!(project_path_spelling(root, Path::new(OsStr::from_bytes(b"/inert/project/bad\xff")), ProjectPathField::VersionSource).is_err());
        assert!(project_path_spelling(Path::new(OsStr::from_bytes(b"/inert/pr\xffject")),
            Path::new(OsStr::from_bytes(b"/inert/pr\xffject/VERSION")), ProjectPathField::VersionSource).is_err());
        let twelve = format!("/inert/project/{}", vec!["a"; 12].join("/"));
        assert!(project_path_spelling(root, Path::new(&twelve), ProjectPathField::MetadataRoot).is_ok());
        assert!(project_path_spelling(root, Path::new(&format!("{twelve}/a")), ProjectPathField::MetadataRoot).is_err());
        let exactly_512 = format!("{}/{}/c", "a".repeat(255), "b".repeat(254));
        assert!(project_path_spelling(root, Path::new(&format!("/inert/project/{exactly_512}")), ProjectPathField::VersionSource).is_ok());
        assert!(project_path_spelling(root, Path::new(&format!("/inert/project/{exactly_512}d")), ProjectPathField::VersionSource).is_err());
        assert!(project_path_spelling(root, Path::new(&format!("/inert/project/{}", "é".repeat(128))), ProjectPathField::VersionSource).is_err());
        assert!(project_path_spelling(root, Path::new(&format!("/inert/project/{}", "a".repeat(PATH_LIMIT))), ProjectPathField::VersionSource).is_err());
        for (field, path) in [(ProjectPathField::IosProject, "/inert/project/App.XCODEPROJ"),
            (ProjectPathField::IosWorkspace, "/inert/project/App.xcodeproj"),
            (ProjectPathField::IosProject, "/inert/project/App.xcodeproj/child")] {
            assert!(project_path_spelling(root, Path::new(path), field).is_err());
        }

        let parent = DirectoryIdentity { dev: 1, ino: 2, mode: 0o40755, uid: 123, gid: 456 };
        let file = FileIdentity { common: DirectoryIdentity { ino: 3, mode: 0o100644, ..parent }, nlink: 1, size: 0, mtime: (1, 2), ctime: (3, 4) };
        assert!(project_path_file_leaf(file, parent));
        assert!(!private_file(file.common.mode)); // Version metadata is not a weakening of credential capture.
        for nlink in [0, 2, u64::MAX] { assert!(!project_path_file_leaf(FileIdentity { nlink, ..file }, parent)); }
        assert!(!project_path_file_leaf(FileIdentity { common: DirectoryIdentity { dev: 2, ..file.common }, ..file }, parent));
        for mode in [0o040755, 0o120777, 0o010600, 0o020600, 0o060600, 0o140600] {
            assert!(!project_path_file_leaf(FileIdentity { common: DirectoryIdentity { mode, ..file.common }, ..file }, parent));
        }
        assert!(project_path_file_leaf(FileIdentity { size: u64::MAX, ..file }, parent)); // No invented content/size policy.
        for changed in [FileIdentity { nlink: 2, ..file }, FileIdentity { size: 1, ..file },
            FileIdentity { mtime: (2, 2), ..file }, FileIdentity { ctime: (3, 5), ..file },
            FileIdentity { common: DirectoryIdentity { ino: 4, ..file.common }, ..file }] { assert!(changed != file); }
        for changed in [DirectoryIdentity { dev: 2, ..parent }, DirectoryIdentity { ino: 3, ..parent },
            DirectoryIdentity { mode: 0o40700, ..parent }, DirectoryIdentity { uid: 456, ..parent },
            DirectoryIdentity { gid: 123, ..parent }] { assert!(changed != parent); }

        // The real probe rejects these before even SourceBook::begin. A
        // permanently-STOPped callback additionally forbids any native effect
        // if that lexical barrier regresses; this test never issues a syscall.
        let registered = RegisteredRoot { path: root.to_path_buf(), identity: ProjectIdentity::Posix(parent) };
        for (path, field) in [("/inert/outside/VERSION", ProjectPathField::VersionSource),
            ("/inert/project2/VERSION", ProjectPathField::VersionSource), ("/inert/project", ProjectPathField::MetadataRoot),
            ("/inert/project/App.XCODEPROJ", ProjectPathField::IosProject)] {
            let mut book = SourceBook::new();
            let result = probe_project_path(&mut book, &registered, PathBuf::from(path), field, &mut || true);
            assert!(matches!(result, Err(Reason::SourceRefused))); assert!(book.not_started() && !book.settled());
        }
        let mut book = SourceBook::new(); book.begin(1, 1).expect("bounded model reservation");
        book.reserve(None, b"/").expect("model slot"); book.slots[0].state = OriginalState::Acquiring; book.terminal = true;
        assert!(!book.settled()); book.slots[0].state = OriginalState::Unknown; assert!(!book.settled());
        // A spent/uncertain close is never retried or changed to a known receipt.
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn lookup_source_charge_includes_refused_and_closed_retained_names() {
            let mut book = SourceBook::unstarted_backing_data();
            assert!(book.not_started() && !book.settled());
            let cells = book.slots.capacity() * std::mem::size_of::<Descriptor>();
            assert_eq!(book.retained_bytes(), Some(cells)); assert!(cells > 0);
            book.begin(4, 1).unwrap(); book.reserve(None, b"/inert").unwrap();
            let common = DirectoryIdentity { dev: 1, ino: 2, mode: 0o100600, uid: 123, gid: 123 };
            let mut name = Vec::with_capacity(91); name.extend_from_slice(b"data"); name.clear();
            book.probes.push(LeafProbe { parent: 0, name,
                identity: FileIdentity { common, nlink: 1, size: 0, mtime: (0, 0), ctime: (0, 0) } });
            let retained = book.slots.capacity() * std::mem::size_of::<Descriptor>()
                + book.probes.capacity() * std::mem::size_of::<LeafProbe>()
                + book.slots[0].name.capacity() + book.probes[0].name.capacity();
            // Closed/NoHandle are in-memory predicate inputs, NOT close receipts.
            book.slots[0].state = OriginalState::NoHandle; book.terminal = true;
            assert!(book.settled()); assert_eq!(book.retained_bytes(), Some(retained));
            assert!(book.retained_bytes().unwrap() > cells);
            book.slots.clear(); book.probes.clear();
            assert!(book.retained_bytes().unwrap() >= cells); // Vec capacity remains.
        }
        #[test]
        fn project_path_containment_type_and_original_custody_are_conservative() { assert_project_path_source_contracts(); }
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
pub(crate) use linux::{SourceBook, capture, probe_project, probe_project_path, suffix, path_hint};
#[cfg(all(test, target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
pub(crate) use linux::assert_project_path_source_contracts;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[path = "asset_source_macos.rs"]
mod macos;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) use macos::{SourceBook, capture, probe_project, probe_project_path, suffix, path_hint};

#[cfg(all(target_os = "windows", target_arch = "x86_64", target_env = "msvc"))]
#[path = "asset_source_windows.rs"]
mod windows;
#[cfg(all(target_os = "windows", target_arch = "x86_64", target_env = "msvc"))]
pub(crate) use windows::{SourceBook, capture, probe_project, probe_project_path, suffix, path_hint};

#[cfg(not(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64"),
    all(target_os = "windows", target_arch = "x86_64", target_env = "msvc"))))]
mod unsupported {
    use super::*;
    pub(crate) struct SourceBook;
    impl SourceBook { pub(crate) fn new() -> Self { Self } pub(crate) fn settled(&self) -> bool { true } pub(crate) fn not_started(&self) -> bool { true } }
    pub(crate) fn suffix(_: FileKind, _: &Path) -> Result<(), Reason> { Err(Reason::UnsupportedPlatform) }
    pub(crate) fn path_hint(_: &Path) -> Result<(), Reason> { Err(Reason::UnsupportedPlatform) }
    pub(crate) fn capture(_: &mut SourceBook, _: PathBuf, _: &[RegisteredRoot], _: FileKind, _: &mut dyn FnMut() -> bool) -> Result<CapturedSource, Reason> { Err(Reason::UnsupportedPlatform) }
    pub(crate) fn probe_project(_: &mut SourceBook, _: PathBuf, _: &[Arc<OriginWitness>], _: &mut dyn FnMut() -> bool) -> Result<ProjectProbe, Reason> { Err(Reason::UnsupportedPlatform) }
    pub(crate) fn probe_project_path(_: &mut SourceBook, _: &RegisteredRoot, _: PathBuf, _: ProjectPathField, _: &mut dyn FnMut() -> bool) -> Result<ProjectPathProbe, Reason> { Err(Reason::UnsupportedPlatform) }
}
#[cfg(not(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64"),
    all(target_os = "windows", target_arch = "x86_64", target_env = "msvc"))))]
pub(crate) use unsupported::{SourceBook, capture, probe_project, probe_project_path, suffix, path_hint};

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
    #[test]
    fn workflow_registration_compares_full_native_facts_path_and_generation() {
        use crate::edit_owner::WorkflowRegistration;
        let identity = DirectoryIdentity { dev:u64::MAX,ino:u64::MAX,mode:0o40750,uid:u32::MAX,gid:u32::MAX-1 };
        let wire = identity.workflow_identity();
        assert_eq!(wire.device,u64::MAX.to_string()); assert_eq!(wire.inode,u64::MAX.to_string());
        assert_eq!((wire.mode,wire.uid,wire.gid),(0o40750,u32::MAX,u32::MAX-1));
        let original = WorkflowRegistration { generation:7,root:RegisteredRoot { path:PathBuf::from("/inert/project"),identity: ProjectIdentity::Posix(identity) } };
        assert!(original == original.clone());
        for altered in [DirectoryIdentity { dev:1,..identity },DirectoryIdentity { ino:1,..identity },
            DirectoryIdentity { mode:0o40700,..identity },DirectoryIdentity { uid:1,..identity },DirectoryIdentity { gid:1,..identity }] {
            let mut changed = original.clone(); changed.root.identity = ProjectIdentity::Posix(altered); assert!(original != changed);
        }
        let mut changed = original.clone(); changed.root.path = PathBuf::from("/inert/other"); assert!(original != changed);
        let mut changed = original.clone(); changed.generation += 1; assert!(original != changed);
        // Value comparisons only: no stat/open, filesystem or registration.
    }
    #[test]
    fn windows_project_ids_preserve_all_bits_and_cannot_project_posix_authority() {
        let original = ProjectIdentity::Windows { volume: u64::MAX, file_id: [0xff; 16] };
        assert!(original.posix().is_err());
        for byte in 0..16 {
            let mut changed = [0xff; 16]; changed[byte] = 0xfe;
            assert!(original != ProjectIdentity::Windows { volume: u64::MAX, file_id: changed });
        }
        assert!(original != ProjectIdentity::Windows { volume: u64::MAX - 1, file_id: [0xff; 16] });
        let posix = DirectoryIdentity::synthetic_evidence_identity();
        assert!(ProjectIdentity::Posix(posix).posix().is_ok_and(|actual| actual == posix));
        assert!(original != ProjectIdentity::Posix(posix));
        let mut root = RegisteredRoot { path: PathBuf::from(if cfg!(windows) { r"C:\inert-project" } else { "/inert-project" }),
            identity: ProjectIdentity::Posix(posix) };
        assert!(crate::candidate_evidence_protocol::params(&root).is_ok());
        root.identity = original;
        assert!(crate::candidate_evidence_protocol::params(&root).is_err());
    }
}
