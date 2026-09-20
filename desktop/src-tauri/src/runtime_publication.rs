//! Fixed Ubuntu package publication, NOT executable-runtime qualification.
//!
//! A single synchronous invocation owns these originals. There are no children,
//! tasks, caller paths, retries, rollback, cleanup traversal or consumer permits.
//! In particular, root never enters the nonroot consumer's admission ledger.
#![forbid(unsafe_code)]

#[cfg(any(feature = "desktop-shell", feature = "development-runtime"))]
compile_error!("ubuntu-runtime-publisher is a separate headless build, without desktop-shell or development-runtime");

use std::{
    collections::BTreeSet,
    fmt,
    mem::{ManuallyDrop, MaybeUninit},
    os::fd::{AsFd, BorrowedFd, OwnedFd},
    time::{Duration, Instant},
};
use mrk_linux_mount_observation as mount;
use rustix::{fs::{self, AtFlags, FileType, Mode, OFlags, RawDir, RenameFlags, ResolveFlags, Stat}, io::{self, Errno}};
use sha2::{Digest, Sha256};
use crate::{installed_runtime::{self as policy, Identity, Inventory, RootMount,
    ENTRY_COUNT, INITIAL_PID_INODE, INITIAL_USER_INODE, MANIFEST_LIMIT, TREE_DEPTH},
    runtime::{safe_payload_path, COMPILED_TARGET}};

const TARGET: &str = "x86_64-unknown-linux-gnu";
const BLOCK: usize = 64 * 1024;
const LIVE_LIMIT: usize = 48;
// Paired source/destination construction, one destination readback traversal,
// and fixed prefix/proc/manifest originals. Completed slots are never reused.
const RECORD_LIMIT: usize = 3 * ENTRY_COUNT + 128;
const OPERATION: Duration = Duration::from_secs(180);
const MAP_LIMIT: usize = 4096;
const STATUS_LIMIT: usize = 64 * 1024;
const MOUNTINFO_LIMIT: usize = 1024 * 1024;

/// Bounded diagnostics only. A failure can leave a stage OR a published version.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublicationError { Invocation, Profile, Identity, Inventory, Bounds, Native, Collision, Close, Deadline }
impl fmt::Display for PublicationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Invocation => "the publisher takes no arguments",
            Self::Profile => "the fixed release or administrator platform is unsupported",
            Self::Identity => "an original namespace, identity or permission differs",
            Self::Inventory => "the exact source or destination inventory differs",
            Self::Bounds => "a fixed publication bound was exceeded",
            Self::Native => "a required native operation failed",
            Self::Collision => "a staging or published name already exists",
            Self::Close => "an original close or acquisition is unconfirmed",
            Self::Deadline => "the original publication endpoint expired",
        })
    }
}
impl std::error::Error for PublicationError {}
type Result<T> = std::result::Result<T, PublicationError>;
type Slot = usize;

fn native(error: Errno) -> PublicationError {
    if error == Errno::EXIST { PublicationError::Collision } else { PublicationError::Native }
}
fn require(condition: bool, error: PublicationError) -> Result<()> { if condition { Ok(()) } else { Err(error) } }
fn component(name: &str) -> bool { !name.contains('/') && safe_payload_path(name) }
fn read_flags(directory: bool) -> OFlags {
    let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
    if directory { flags | OFlags::DIRECTORY } else { flags }
}
fn write_flags() -> OFlags { OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC }
fn beneath() -> ResolveFlags { ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_XDEV }
fn payload_mode(name: &str) -> u32 { if name == "python/bin/python3" { 0o555 } else { 0o444 } }

struct Release<'a> { manifest: &'a str, protocol: &'a str }
impl<'a> Release<'a> {
    fn checked(target: &str, manifest: Option<&'a str>, protocol: Option<&'a str>) -> Result<Self> {
        require(target == TARGET, PublicationError::Profile)?;
        Ok(Self { manifest: manifest.filter(|s| policy::sha(s)).ok_or(PublicationError::Profile)?,
            protocol: protocol.filter(|s| policy::sha(s)).ok_or(PublicationError::Profile)? })
    }
}

struct Original { fd: Option<ManuallyDrop<OwnedFd>>, writer: bool }
struct Originals {
    rows: Vec<Original>, pending: Option<Slot>, live: usize, writers: usize, close_failed: bool,
    #[cfg(test)] fail_close: Option<Slot>,
    #[cfg(test)] closes: Vec<Slot>,
}
impl Originals {
    fn new() -> Self {
        Self { rows: Vec::with_capacity(RECORD_LIMIT), pending: None, live: 0, writers: 0, close_failed: false,
            #[cfg(test)] fail_close: None, #[cfg(test)] closes: Vec::new() }
    }
    fn arm(&mut self, writer: bool) -> Result<Slot> {
        require(self.pending.is_none() && !self.close_failed, PublicationError::Close)?;
        require(self.live < LIVE_LIMIT && self.rows.len() < RECORD_LIMIT, PublicationError::Bounds)?;
        let slot = self.rows.len();
        self.rows.push(Original { fd: None, writer });
        self.pending = Some(slot);
        Ok(slot)
    }
    fn receive(&mut self, slot: Slot, result: std::result::Result<OwnedFd, Errno>) -> Result<Slot> {
        // arm() made this exact slot immediately before the synchronous open.
        // Store the returned original before any fallible work or another call.
        match result {
            Ok(fd) => {
                self.rows[slot].fd = Some(ManuallyDrop::new(fd));
                self.live += 1;
                if self.rows[slot].writer { self.writers += 1; }
                self.pending = None;
                Ok(slot)
            }
            Err(error) => { self.pending = None; Err(native(error)) }
        }
    }
    fn fd(&self, slot: Slot) -> Result<BorrowedFd<'_>> {
        self.rows.get(slot).and_then(|row| row.fd.as_ref()).map(|fd| fd.as_fd()).ok_or(PublicationError::Close)
    }
    fn open(&mut self, parent: Option<Slot>, name: &str, flags: OFlags, resolve: ResolveFlags) -> Result<Slot> {
        require(if parent.is_some() { component(name) } else { name == "/" }, PublicationError::Identity)?;
        let writer = flags.intersects(OFlags::WRONLY | OFlags::RDWR);
        let slot = self.arm(writer)?;
        let mode = if flags.contains(OFlags::CREATE) { Mode::from_raw_mode(0o600) } else { Mode::empty() };
        let result = match parent {
            Some(parent) => fs::openat2(self.fd(parent)?, name, flags, mode, resolve),
            None => fs::open("/", flags, mode),
        };
        self.receive(slot, result)
    }
    fn close(&mut self, slot: Slot) -> Result<()> {
        let Some(row) = self.rows.get_mut(slot) else { self.close_failed = true; return Err(PublicationError::Close); };
        let Some(fd) = row.fd.take() else { self.close_failed = true; return Err(PublicationError::Close); };
        self.live -= 1;
        if row.writer { self.writers -= 1; }
        // Retire before the one consuming call. Never close a copied integer or
        // rely on OwnedFd::drop; the slot remains empty even when close fails.
        let result = nix::unistd::close(ManuallyDrop::into_inner(fd));
        // Tests may lose the receipt AFTER the real consuming call. That is
        // deterministic bookkeeping coverage, never an observed OS close fault.
        #[cfg(test)]
        let injected = { self.closes.push(slot); if self.fail_close == Some(slot) { self.fail_close = None; true } else { false } };
        #[cfg(not(test))]
        let injected = false;
        if result.is_err() || injected { self.close_failed = true; return Err(PublicationError::Close); }
        Ok(())
    }
    fn before_publication(&self) -> Result<()> {
        require(self.pending.is_none() && !self.close_failed && self.writers == 0, PublicationError::Close)
    }
    fn settle(&mut self) -> Result<()> {
        for slot in (0..self.rows.len()).rev() {
            if self.rows[slot].fd.is_some() { let _ = self.close(slot); }
        }
        require(self.pending.is_none() && !self.close_failed && self.live == 0 && self.writers == 0, PublicationError::Close)
    }
}

// Publisher-created entries legitimately alter destination/prefix parent times
// and link counts. Their binding uses this structural key. Source directories
// and stable file reads additionally retain/recheck the full Identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DirectoryKey { device: u64, inode: u64, mode: u32, uid: u32, gid: u32 }
impl DirectoryKey {
    fn of(stat: &Stat) -> Self { Self { device: stat.st_dev, inode: stat.st_ino, mode: stat.st_mode, uid: stat.st_uid, gid: stat.st_gid } }
    fn with_mode(self, mode: u32) -> Self { Self { mode: (self.mode & !0o7777) | mode, ..self } }
}
struct Binding { slot: Slot, parent: Option<Slot>, name: String, key: DirectoryKey }
struct Entry { name: String, relative: String, inode: u64, kind: FileType }

struct Publisher {
    originals: Originals, end: Instant, root_mount: Option<mount::MountObservation>, retained: Vec<Binding>,
    #[cfg(test)] fail_sync: Option<Slot>,
    #[cfg(test)] renames: usize,
}
impl Publisher {
    fn new() -> Self {
        Self { originals: Originals::new(), end: Instant::now() + OPERATION, root_mount: None, retained: Vec::with_capacity(16),
            #[cfg(test)] fail_sync: None, #[cfg(test)] renames: 0 }
    }
    fn tick(&self) -> Result<()> { require(Instant::now() < self.end, PublicationError::Deadline) }
    fn open(&mut self, parent: Option<Slot>, name: &str, flags: OFlags, resolve: ResolveFlags) -> Result<Slot> {
        self.tick()?;
        let slot = self.originals.open(parent, name, flags, resolve)?;
        self.tick()?;
        Ok(slot)
    }
    fn stat(&self, slot: Slot) -> Result<Stat> {
        self.tick()?;
        let value = fs::fstat(self.originals.fd(slot)?).map_err(native)?;
        self.tick()?;
        Ok(value)
    }
    fn unchanged(&self, slot: Slot, before: Identity) -> Result<()> {
        require(before == Identity::of(&self.stat(slot)?), PublicationError::Identity)
    }
    fn named(&self, parent: Slot, name: &str) -> Result<Option<Stat>> {
        self.tick()?;
        require(component(name), PublicationError::Identity)?;
        let result = fs::statat(self.originals.fd(parent)?, name, AtFlags::SYMLINK_NOFOLLOW);
        self.tick()?;
        match result { Ok(stat) => Ok(Some(stat)), Err(Errno::NOENT) => Ok(None), Err(error) => Err(native(error)) }
    }
    fn absent(&self, parent: Slot, name: &str) -> Result<()> {
        require(self.named(parent, name)?.is_none(), PublicationError::Collision)
    }
    fn attribute_absent(&self, slot: Slot, name: &str) -> Result<()> {
        self.tick()?;
        let mut byte = [0_u8; 1];
        let result = fs::fgetxattr(self.originals.fd(slot)?, name, &mut byte[..]);
        self.tick()?;
        require(matches!(result, Err(Errno::NODATA)), PublicationError::Identity)
    }
    fn protected(&self, slot: Slot, kind: FileType, size: Option<u64>) -> Result<Stat> {
        let before = self.stat(slot)?;
        require(policy::protected_identity(Identity::of(&before), kind, size), PublicationError::Identity)?;
        self.attribute_absent(slot, "system.posix_acl_access")?;
        self.attribute_absent(slot, if kind == FileType::Directory { "system.posix_acl_default" } else { "security.capability" })?;
        self.tick()?;
        let observed = mount::observe_mount(self.originals.fd(slot)?).map_err(|_| PublicationError::Profile)?;
        require(policy::protected_mount(observed) && self.root_mount.is_none_or(|root| root == observed), PublicationError::Profile)?;
        require(Identity::of(&before) == Identity::of(&self.stat(slot)?), PublicationError::Identity)?;
        Ok(before)
    }
    fn binding(&self, slot: Slot, parent: Option<Slot>, name: &str) -> Result<Binding> {
        let stat = self.protected(slot, FileType::Directory, None)?;
        let binding = Binding { slot, parent, name: name.to_owned(), key: DirectoryKey::of(&stat) };
        self.check_binding(&binding)?;
        Ok(binding)
    }
    fn check_binding(&self, binding: &Binding) -> Result<()> {
        let actual = self.protected(binding.slot, FileType::Directory, None)?;
        require(DirectoryKey::of(&actual) == binding.key, PublicationError::Identity)?;
        if let Some(parent) = binding.parent {
            let named = self.named(parent, &binding.name)?.ok_or(PublicationError::Identity)?;
            require(DirectoryKey::of(&named) == binding.key, PublicationError::Identity)?;
        }
        Ok(())
    }
    fn check_retained(&self) -> Result<()> { for binding in &self.retained { self.check_binding(binding)?; } Ok(()) }
    fn keep_child(&mut self, parent: Slot, name: &str) -> Result<Slot> {
        let slot = self.open(Some(parent), name, read_flags(true), beneath())?;
        let binding = self.binding(slot, Some(parent), name)?;
        require(self.retained.len() < 16, PublicationError::Bounds)?;
        self.retained.push(binding);
        Ok(slot)
    }
    fn sync(&mut self, slot: Slot) -> Result<()> {
        self.tick()?;
        // Test-only refusal at the call boundary, not an observed OS fsync fault.
        #[cfg(test)]
        if self.fail_sync == Some(slot) { self.fail_sync = None; return Err(PublicationError::Native); }
        fs::fsync(self.originals.fd(slot)?).map_err(native)?;
        self.tick()
    }
    fn directory_mode(&mut self, binding: &mut Binding, mode: u32) -> Result<()> {
        self.check_binding(binding)?;
        self.tick()?;
        fs::fchmod(self.originals.fd(binding.slot)?, Mode::from_raw_mode(mode)).map_err(native)?;
        binding.key = binding.key.with_mode(mode); // Expected own mode transition, never adoption.
        self.check_binding(binding)?;
        self.sync(binding.slot)
    }
    fn new_directory(&mut self, parent: Slot, name: &str) -> Result<Binding> {
        require(component(name), PublicationError::Identity)?;
        self.tick()?;
        fs::mkdirat(self.originals.fd(parent)?, name, Mode::from_raw_mode(0o700)).map_err(native)?;
        let named = self.named(parent, name)?.ok_or(PublicationError::Identity)?;
        let slot = self.open(Some(parent), name, read_flags(true), beneath())?;
        let binding = self.binding(slot, Some(parent), name)?;
        require(binding.key == DirectoryKey::of(&named) && binding.key.mode & 0o7777 == 0o700, PublicationError::Identity)?;
        self.sync(parent)?;
        Ok(binding)
    }
    fn prefix(&mut self, parent: Slot, name: &str) -> Result<Slot> {
        if self.named(parent, name)?.is_some() { return self.keep_child(parent, name); }
        let mut binding = self.new_directory(parent, name)?;
        self.directory_mode(&mut binding, 0o755)?;
        let slot = binding.slot;
        require(self.retained.len() < 16, PublicationError::Bounds)?;
        self.retained.push(binding);
        Ok(slot)
    }
    fn read_bytes(&self, slot: Slot, limit: usize, size: Option<u64>) -> Result<Vec<u8>> {
        let before = Identity::of(&self.stat(slot)?);
        let mut bytes = Vec::new();
        let mut buffer = [0_u8; BLOCK];
        loop {
            self.tick()?;
            let count = io::read(self.originals.fd(slot)?, &mut buffer).map_err(native)?;
            require(count <= limit.saturating_sub(bytes.len()), PublicationError::Bounds)?;
            if count == 0 { break; }
            bytes.extend_from_slice(&buffer[..count]);
        }
        require(size.is_none_or(|size| bytes.len() as u64 == size), PublicationError::Inventory)?;
        self.unchanged(slot, before)?;
        Ok(bytes)
    }
    fn proc_object(&self, slot: Slot, kind: FileType, expected: Option<mount::MountObservation>) -> Result<mount::MountObservation> {
        let before = self.stat(slot)?;
        require(policy::ordinary_identity(Identity::of(&before), kind), PublicationError::Profile)?;
        self.tick()?;
        let observed = mount::observe_mount(self.originals.fd(slot)?).map_err(|_| PublicationError::Profile)?;
        require(observed.filesystem_magic() == mount::PROC_MAGIC && policy::known_mount_attributes(observed.attributes())
            && expected.is_none_or(|mount| mount == observed), PublicationError::Profile)?;
        require(Identity::of(&before) == Identity::of(&self.stat(slot)?), PublicationError::Identity)?;
        Ok(observed)
    }
    fn proc_child(&mut self, parent: Slot, name: &str, proc_mount: mount::MountObservation) -> Result<Slot> {
        let slot = self.open(Some(parent), name, read_flags(true), beneath())?;
        self.proc_object(slot, FileType::Directory, Some(proc_mount))?;
        Ok(slot)
    }
    fn proc_read(&mut self, parent: Slot, name: &str, limit: usize, proc_mount: mount::MountObservation) -> Result<Vec<u8>> {
        let slot = self.open(Some(parent), name, read_flags(false), beneath())?;
        self.proc_object(slot, FileType::RegularFile, Some(proc_mount))?;
        let bytes = self.read_bytes(slot, limit, None)?;
        self.proc_object(slot, FileType::RegularFile, Some(proc_mount))?;
        self.originals.close(slot)?;
        Ok(bytes)
    }
    fn namespace(&mut self, parent: Slot, name: &str, inode: u64) -> Result<()> {
        // The only magic-link exceptions: fixed endpoints under this already
        // observed genuine numeric current-thread proc namespace directory.
        let slot = self.open(Some(parent), name, OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC, ResolveFlags::empty())?;
        let stat = self.stat(slot)?;
        self.tick()?;
        let filesystem = fs::fstatfs(self.originals.fd(slot)?).map_err(native)?;
        require(policy::ordinary_identity(Identity::of(&stat), FileType::RegularFile) && stat.st_ino == inode
            && filesystem.f_type as u64 == mount::NAMESPACE_MAGIC, PublicationError::Profile)?;
        require(Identity::of(&stat) == Identity::of(&self.stat(slot)?), PublicationError::Identity)?;
        // Both originals remain in this invocation until final settlement.
        Ok(())
    }
    fn admin_context(&mut self, root: Slot) -> Result<()> {
        admin_ids()?;
        self.tick()?;
        let actual = rustix::system::uname();
        require(policy::supported_kernel(actual.sysname().to_bytes(), actual.machine().to_bytes(), actual.release().to_bytes()), PublicationError::Profile)?;
        let pid = u32::try_from(rustix::process::getpid().as_raw_pid()).map_err(|_| PublicationError::Profile)?;
        let tid = u32::try_from(rustix::thread::gettid().as_raw_pid()).map_err(|_| PublicationError::Profile)?;
        let proc_root = self.open(Some(root), "proc", read_flags(true),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS)?;
        let proc_mount = self.proc_object(proc_root, FileType::Directory, None)?;
        let process = self.proc_child(proc_root, &pid.to_string(), proc_mount)?;
        let task = self.proc_child(process, "task", proc_mount)?;
        let thread = self.proc_child(task, &tid.to_string(), proc_mount)?;
        let ns = self.proc_child(thread, "ns", proc_mount)?;
        self.namespace(ns, "user", INITIAL_USER_INODE)?;
        self.namespace(ns, "pid", INITIAL_PID_INODE)?;
        for map in ["uid_map", "gid_map"] {
            policy::initial_id_map(&self.proc_read(thread, map, MAP_LIMIT, proc_mount)?).map_err(|_| PublicationError::Profile)?;
        }
        root_status(&self.proc_read(thread, "status", STATUS_LIMIT, proc_mount)?, pid, tid)?;
        let current = policy::parse_root_mount(&self.proc_read(thread, "mountinfo", MOUNTINFO_LIMIT, proc_mount)?).map_err(|_| PublicationError::Profile)?;
        let initial = self.proc_child(proc_root, "1", proc_mount)?; // Read-only global-init witness, never process discovery/signalling.
        let initial_root = policy::parse_root_mount(&self.proc_read(initial, "mountinfo", MOUNTINFO_LIMIT, proc_mount)?).map_err(|_| PublicationError::Profile)?;
        let observed = self.root_mount.ok_or(PublicationError::Profile)?;
        require(current == initial_root && current == (RootMount { old_id: observed.old_id(), device: observed.device(), magic: observed.filesystem_magic() }), PublicationError::Profile)?;
        for slot in [initial, ns, thread, task, process, proc_root] { self.originals.close(slot)?; }
        // As in the consumer policy, equal root mounts are NOT provenance of an
        // initial mount namespace. The admitted OS execution context supplies it.
        admin_ids()?;
        self.tick()
    }
}

fn admin_ids() -> Result<()> {
    require(rustix::process::getuid().as_raw() == 0 && rustix::process::geteuid().as_raw() == 0
        && rustix::process::getgid().as_raw() == 0 && rustix::process::getegid().as_raw() == 0, PublicationError::Profile)
}

fn root_status(bytes: &[u8], pid: u32, tid: u32) -> Result<()> {
    require(bytes.len() <= STATUS_LIMIT && bytes.ends_with(b"\n") && !bytes.contains(&0), PublicationError::Profile)?;
    let text = std::str::from_utf8(bytes).map_err(|_| PublicationError::Profile)?;
    let mut seen = BTreeSet::new();
    for line in text.lines() {
        let (key, value) = line.split_once(':').ok_or(PublicationError::Profile)?;
        let expected: &[u32] = match key {
            "Uid" | "Gid" => &[0, 0, 0, 0],
            "Pid" | "NSpid" => std::slice::from_ref(&tid),
            "Tgid" | "NStgid" => std::slice::from_ref(&pid),
            _ => continue, // Root's real capabilities are not the nonroot consumer's zero-cap policy.
        };
        require(seen.insert(key), PublicationError::Profile)?;
        let mut fields = value.split_ascii_whitespace();
        for number in expected {
            let field = fields.next().ok_or(PublicationError::Profile)?;
            require(!field.is_empty() && field.bytes().all(|byte| byte.is_ascii_digit())
                && field.parse::<u32>().ok() == Some(*number), PublicationError::Profile)?;
        }
        require(fields.next().is_none(), PublicationError::Profile)?;
    }
    require(seen.len() == 6 && pid != 0 && tid != 0, PublicationError::Profile)
}

impl Publisher {
    fn write_all(&self, slot: Slot, bytes: &[u8]) -> Result<()> {
        let mut written = 0;
        while written < bytes.len() {
            self.tick()?;
            let count = io::write(self.originals.fd(slot)?, &bytes[written..]).map_err(native)?;
            require(count != 0 && count <= bytes.len() - written, PublicationError::Native)?;
            written += count;
        }
        self.tick()
    }
    fn copy_bytes(&mut self, source: Slot, destination: Slot, size: u64, digest: &str, mode: u32) -> Result<()> {
        require(size <= 512 * 1024 * 1024 && policy::sha(digest) && matches!(mode, 0o444 | 0o555), PublicationError::Bounds)?;
        let source_before = self.stat(source)?;
        let destination_before = self.stat(destination)?;
        require(policy::ordinary_identity(Identity::of(&source_before), FileType::RegularFile)
            && source_before.st_size >= 0 && source_before.st_size as u64 == size
            && policy::ordinary_identity(Identity::of(&destination_before), FileType::RegularFile)
            && destination_before.st_size == 0 && destination_before.st_mode & 0o7777 == 0o600
            && (source_before.st_dev, source_before.st_ino) != (destination_before.st_dev, destination_before.st_ino)
            && self.originals.rows.get(destination).is_some_and(|row| row.writer && row.fd.is_some()), PublicationError::Identity)?;
        let mut hash = Sha256::new();
        let mut total = 0_u64;
        let mut buffer = [0_u8; BLOCK];
        loop {
            self.tick()?;
            let count = io::read(self.originals.fd(source)?, &mut buffer).map_err(native)?;
            if count == 0 { break; }
            total = total.checked_add(count as u64).ok_or(PublicationError::Bounds)?;
            require(total <= size, PublicationError::Inventory)?;
            self.write_all(destination, &buffer[..count])?;
            hash.update(&buffer[..count]);
        }
        require(total == size && policy::hex(&hash.finalize()) == digest, PublicationError::Inventory)?;
        self.unchanged(source, Identity::of(&source_before))?;
        self.tick()?;
        fs::fchmod(self.originals.fd(destination)?, Mode::from_raw_mode(mode)).map_err(native)?;
        self.sync(destination)?;
        let after = self.stat(destination)?;
        require(DirectoryKey::of(&after) == DirectoryKey::of(&destination_before).with_mode(mode)
            && after.st_nlink == 1 && after.st_size >= 0 && after.st_size as u64 == size, PublicationError::Identity)?;
        self.originals.close(destination)?;
        self.originals.close(source)?;
        // This destination writer is consumed before successful return. Its
        // write hash is NOT the independent readback performed by verify_tree().
        Ok(())
    }
    fn verify_bytes(&self, slot: Slot, size: u64, digest: &str) -> Result<()> {
        require(size <= 512 * 1024 * 1024 && policy::sha(digest), PublicationError::Bounds)?;
        let before = self.stat(slot)?;
        require(policy::ordinary_identity(Identity::of(&before), FileType::RegularFile)
            && before.st_size >= 0 && before.st_size as u64 == size, PublicationError::Identity)?;
        let mut buffer = [0_u8; BLOCK];
        let mut total = 0_u64;
        let mut hash = Sha256::new();
        loop {
            self.tick()?;
            let count = io::read(self.originals.fd(slot)?, &mut buffer).map_err(native)?;
            if count == 0 { break; }
            total = total.checked_add(count as u64).ok_or(PublicationError::Bounds)?;
            require(total <= size, PublicationError::Inventory)?;
            hash.update(&buffer[..count]);
        }
        require(total == size && policy::hex(&hash.finalize()) == digest, PublicationError::Inventory)?;
        self.unchanged(slot, Identity::of(&before))
    }
    fn scan(&self, directory: Slot, relative: &str, inventory: &Inventory, seen: &mut BTreeSet<String>) -> Result<Vec<Entry>> {
        let before = self.stat(directory)?;
        require(policy::ordinary_identity(Identity::of(&before), FileType::Directory), PublicationError::Identity)?;
        let mut buffer = [MaybeUninit::<u8>::uninit(); BLOCK];
        let mut original = RawDir::new(self.originals.fd(directory)?, &mut buffer[..]);
        let mut entries = Vec::new();
        let (mut dot, mut dotdot) = (false, false);
        loop {
            self.tick()?;
            let Some(entry) = original.next() else { break; };
            let entry = entry.map_err(native)?;
            let name = entry.file_name().to_str().map_err(|_| PublicationError::Inventory)?;
            let kind = entry.file_type();
            let inode = entry.ino();
            if name == "." {
                require(!dot && kind == FileType::Directory && inode == before.st_ino, PublicationError::Identity)?;
                dot = true; continue;
            }
            if name == ".." {
                require(!dotdot && kind == FileType::Directory && inode != 0, PublicationError::Identity)?;
                dotdot = true; continue;
            }
            require(seen.len() < ENTRY_COUNT && component(name) && inode != 0, PublicationError::Bounds)?;
            let next = if relative.is_empty() { name.to_owned() } else { format!("{relative}/{name}") };
            require(safe_payload_path(&next), PublicationError::Inventory)?;
            let expected = if next == "manifest.json" { FileType::RegularFile }
                else if inventory.directories.contains(&next) { FileType::Directory }
                else if inventory.files.binary_search_by(|file| file.path.as_str().cmp(&next)).is_ok() { FileType::RegularFile }
                else { return Err(PublicationError::Inventory); };
            require(kind == expected && seen.insert(next.clone()), PublicationError::Inventory)?;
            // Charge names before queueing even an as-yet unvisited directory.
            entries.push(Entry { name: name.to_owned(), relative: next, inode, kind });
        }
        require(dot && dotdot && Identity::of(&before) == Identity::of(&self.stat(directory)?), PublicationError::Identity)?;
        Ok(entries)
    }
    fn copy_tree(&mut self, source: Slot, destination: Slot, relative: &str, depth: usize,
        inventory: &Inventory, release: &Release<'_>, manifest_size: u64, seen: &mut BTreeSet<String>) -> Result<()> {
        require(depth < TREE_DEPTH, PublicationError::Bounds)?;
        let source_before = Identity::of(&self.protected(source, FileType::Directory, None)?);
        let entries = self.scan(source, relative, inventory, seen)?;
        for entry in entries {
            if entry.kind == FileType::Directory {
                let child = self.open(Some(source), &entry.name, read_flags(true), beneath())?;
                let source_binding = self.binding(child, Some(source), &entry.name)?;
                require(source_binding.key.inode == entry.inode, PublicationError::Identity)?;
                let mut target = self.new_directory(destination, &entry.name)?;
                self.copy_tree(child, target.slot, &entry.relative, depth + 1, inventory, release, manifest_size, seen)?;
                self.check_binding(&source_binding)?;
                self.directory_mode(&mut target, 0o555)?;
                self.originals.close(child)?;
                self.originals.close(target.slot)?;
            } else {
                let (size, digest) = file_expected(inventory, &entry.relative, release, manifest_size)?;
                let child = self.open(Some(source), &entry.name, read_flags(false), beneath())?;
                let before = self.protected(child, FileType::RegularFile, Some(size))?;
                require(before.st_ino == entry.inode, PublicationError::Identity)?;
                let target = self.open(Some(destination), &entry.name, write_flags(), beneath())?;
                let fresh = self.protected(target, FileType::RegularFile, Some(0))?;
                require(fresh.st_mode & 0o7777 == 0o600, PublicationError::Identity)?;
                self.copy_bytes(child, target, size, digest, payload_mode(&entry.relative))?;
                let named_source = self.named(source, &entry.name)?.ok_or(PublicationError::Identity)?;
                require(Identity::of(&named_source) == Identity::of(&before), PublicationError::Identity)?;
                let named_target = self.named(destination, &entry.name)?.ok_or(PublicationError::Identity)?;
                require(DirectoryKey::of(&named_target) == DirectoryKey::of(&fresh).with_mode(payload_mode(&entry.relative))
                    && named_target.st_nlink == 1 && named_target.st_size >= 0 && named_target.st_size as u64 == size, PublicationError::Identity)?;
            }
        }
        self.protected(source, FileType::Directory, None)?;
        // We never mutate source directories. An entry added, removed or
        // replaced after scan must not disappear behind a structural-only key.
        self.unchanged(source, source_before)?;
        self.sync(destination)
    }
    fn verify_tree(&mut self, directory: Slot, relative: &str, depth: usize, inventory: &Inventory,
        release: &Release<'_>, manifest_size: u64, seen: &mut BTreeSet<String>) -> Result<()> {
        require(depth < TREE_DEPTH, PublicationError::Bounds)?;
        let before = self.protected(directory, FileType::Directory, None)?;
        require(before.st_mode & 0o7777 == if relative.is_empty() { 0o700 } else { 0o555 }, PublicationError::Identity)?;
        let entries = self.scan(directory, relative, inventory, seen)?;
        for entry in entries {
            let child = self.open(Some(directory), &entry.name, read_flags(entry.kind == FileType::Directory), beneath())?;
            if entry.kind == FileType::Directory {
                let binding = self.binding(child, Some(directory), &entry.name)?;
                require(binding.key.inode == entry.inode, PublicationError::Identity)?;
                self.verify_tree(child, &entry.relative, depth + 1, inventory, release, manifest_size, seen)?;
                self.check_binding(&binding)?;
            } else {
                let (size, digest) = file_expected(inventory, &entry.relative, release, manifest_size)?;
                let actual = self.protected(child, FileType::RegularFile, Some(size))?;
                require(actual.st_ino == entry.inode && actual.st_mode & 0o7777 == payload_mode(&entry.relative), PublicationError::Identity)?;
                self.verify_bytes(child, size, digest)?;
                let named = self.named(directory, &entry.name)?.ok_or(PublicationError::Identity)?;
                require(Identity::of(&actual) == Identity::of(&named)
                    && Identity::of(&actual) == Identity::of(&self.protected(child, FileType::RegularFile, Some(size))?), PublicationError::Identity)?;
            }
            self.originals.close(child)?;
        }
        require(Identity::of(&before) == Identity::of(&self.protected(directory, FileType::Directory, None)?), PublicationError::Identity)
    }
    fn commit_directory(&mut self, parent: Slot, stage: Slot, stage_name: &str, final_name: &str) -> Result<()> {
        self.originals.before_publication()?;
        require(component(stage_name) && component(final_name), PublicationError::Identity)?;
        self.sync(stage)?;
        self.tick()?;
        #[cfg(test)] { self.renames += 1; }
        // Exactly one native no-replace operation. ENOENT preflights never
        // authorize plain rename, repair, exchange or a retry on another path.
        fs::renameat_with(self.originals.fd(parent)?, stage_name, self.originals.fd(parent)?, final_name, RenameFlags::NOREPLACE).map_err(native)?;
        // Failure here may leave a published name. Never remove or retry it.
        self.sync(parent)
    }
    // The same original read-only admission is used by publication and its
    // narrowly opted-in hosted platform observation. No source/output selection
    // or filesystem mutation has occurred when this method returns.
    fn root_context(&mut self) -> Result<(Slot, Slot)> {
        admin_ids()?;
        let root = self.open(None, "/", read_flags(true), ResolveFlags::empty())?;
        self.protected(root, FileType::Directory, None)?;
        self.tick()?;
        self.root_mount = Some(mount::observe_mount(self.originals.fd(root)?).map_err(|_| PublicationError::Profile)?);
        let root_binding = self.binding(root, None, "/")?;
        self.retained.push(root_binding);
        self.admin_context(root)?;
        let usr = self.keep_child(root, "usr")?;
        let lib = self.keep_child(usr, "lib")?;
        let os_release = self.open(Some(lib), "os-release", read_flags(false), beneath())?;
        let os_stat = self.protected(os_release, FileType::RegularFile, None)?;
        let os_size = u64::try_from(os_stat.st_size).map_err(|_| PublicationError::Bounds)?;
        policy::ubuntu_2404(&self.read_bytes(os_release, STATUS_LIMIT, Some(os_size))?).map_err(|_| PublicationError::Profile)?;
        self.originals.close(os_release)?;
        Ok((root, lib))
    }
    fn run(&mut self, release: &Release<'_>) -> Result<()> {
        let (root, lib) = self.root_context()?;
        let mut source = lib;
        for name in ["mobile-release-kit", "runtime-input", TARGET, release.manifest] { source = self.keep_child(source, name)?; }
        let manifest = self.open(Some(source), "manifest.json", read_flags(false), beneath())?;
        let manifest_stat = self.protected(manifest, FileType::RegularFile, None)?;
        let manifest_size = u64::try_from(manifest_stat.st_size).map_err(|_| PublicationError::Bounds)?;
        let bytes = self.read_bytes(manifest, MANIFEST_LIMIT, Some(manifest_size))?;
        require(policy::hex(&Sha256::digest(&bytes)) == release.manifest, PublicationError::Inventory)?;
        let inventory = policy::parse_inventory(&bytes, release.protocol).map_err(|_| PublicationError::Inventory)?;
        require(inventory.files.iter().any(|file| file.path == "python/bin/python3" && file.size != 0), PublicationError::Inventory)?;
        self.originals.close(manifest)?;

        // Only this fixed headless invocation changes its creation mask. It does
        // not fix permissions/ownership of an existing source or published inode.
        self.tick()?;
        rustix::process::umask(Mode::from_raw_mode(0o077));
        let mut parent = self.keep_child(root, "opt")?;
        for name in ["mobile-release-kit", "versions", TARGET] { parent = self.prefix(parent, name)?; }
        let stage_name = format!(".publish-{}", release.manifest);
        self.absent(parent, release.manifest)?;
        self.absent(parent, &stage_name)?;
        let mut stage = self.new_directory(parent, &stage_name)?;
        let mut source_names = BTreeSet::new();
        self.copy_tree(source, stage.slot, "", 0, &inventory, release, manifest_size, &mut source_names)?;
        complete_names(&inventory, &source_names)?;
        self.originals.before_publication()?; // In particular, every data writer has positively returned close.
        let mut destination_names = BTreeSet::new();
        self.verify_tree(stage.slot, "", 0, &inventory, release, manifest_size, &mut destination_names)?;
        complete_names(&inventory, &destination_names)?;
        self.check_retained()?;
        self.directory_mode(&mut stage, 0o555)?;
        admin_ids()?;
        self.check_retained()?;
        self.commit_directory(parent, stage.slot, &stage_name, release.manifest)?;
        stage.name = release.manifest.to_owned(); // Expected successful rename of this SAME original directory.
        self.check_binding(&stage)?;
        self.check_retained()?;
        admin_ids()?;
        self.tick()
    }
}

fn file_expected<'a>(inventory: &'a Inventory, name: &str, release: &'a Release<'_>, manifest_size: u64) -> Result<(u64, &'a str)> {
    if name == "manifest.json" { return Ok((manifest_size, release.manifest)); }
    let index = inventory.files.binary_search_by(|file| file.path.as_str().cmp(name)).map_err(|_| PublicationError::Inventory)?;
    let file = &inventory.files[index];
    Ok((file.size, &file.sha256))
}
fn complete_names(inventory: &Inventory, seen: &BTreeSet<String>) -> Result<()> {
    require(seen.len() == inventory.files.len() + inventory.directories.len() + 1 && seen.contains("manifest.json")
        && inventory.files.iter().all(|file| seen.contains(&file.path))
        && inventory.directories.iter().all(|name| seen.contains(name)), PublicationError::Inventory)
}

/// Sole production entry. It selects no external arguments, environment paths,
/// source build, qualified profile, application owner or executable payload.
pub fn publish_fixed() -> Result<()> {
    require(std::env::args_os().count() == 1, PublicationError::Invocation)?;
    let release = Release::checked(COMPILED_TARGET, option_env!("MRK_BUNDLED_RUNTIME_MANIFEST_SHA256"),
        option_env!("MRK_BUNDLED_PROTOCOL_SHA256"))?;
    let mut publisher = Publisher::new();
    let result = publisher.run(&release);
    // Also runs after any refusal/partial copy/post-rename error. Never traversal
    // cleanup: settle just these returned originals, once, even after expiry.
    publisher.originals.settle()?;
    result?;
    publisher.tick()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::installed_runtime::PayloadFile;
    use std::{ffi::OsStr, sync::atomic::{AtomicU64, Ordering}};

    #[test]
    fn release_inputs_are_fixed_and_lowercase() {
        let manifest = "a".repeat(64);
        let protocol = "b".repeat(64);
        assert!(Release::checked(TARGET, Some(&manifest), Some(&protocol)).is_ok());
        assert!(Release::checked("aarch64-unknown-linux-gnu", Some(&manifest), Some(&protocol)).is_err());
        assert!(Release::checked(TARGET, None, Some(&protocol)).is_err());
        assert!(Release::checked(TARGET, Some(&manifest), None).is_err());
        assert!(Release::checked(TARGET, Some(&manifest.to_uppercase()), Some(&protocol)).is_err());
        assert!(Release::checked(TARGET, Some(&manifest), Some(&protocol[..63])).is_err());
    }

    #[test]
    fn root_status_requires_all_initial_root_ids() {
        let status = "Name:\tpublisher-test\nTgid:\t123\nPid:\t124\nUid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\nNStgid:\t123\nNSpid:\t124\nCapEff:\t0000000000000001\n";
        assert_eq!(root_status(status.as_bytes(), 123, 124), Ok(()));
        for key in ["Uid", "Gid"] {
            for index in 0..4 {
                let mut ids = ["0"; 4];
                ids[index] = "1000";
                let changed = status.replace(&format!("{key}:\t0\t0\t0\t0"), &format!("{key}:\t{}", ids.join("\t")));
                assert_eq!(root_status(changed.as_bytes(), 123, 124), Err(PublicationError::Profile));
            }
        }
        for changed in [
            status.replace("NSpid:\t124", "NSpid:\t124\t2"),
            status.replace("NStgid:\t123", "NStgid:\t123\t1"),
            status.replace("Pid:\t124", "Pid:\t125"),
            status.replace("Tgid:\t123", "Tgid:\t125"),
            status.replace("Gid:\t0\t0\t0\t0\n", ""),
            format!("{status}Uid:\t0\t0\t0\t0\n"),
            format!("{status}\0\n"),
        ] { assert_eq!(root_status(changed.as_bytes(), 123, 124), Err(PublicationError::Profile)); }
        assert_eq!(root_status(status.trim_end().as_bytes(), 123, 124), Err(PublicationError::Profile));
        assert_eq!(root_status(status.as_bytes(), 0, 124), Err(PublicationError::Profile));
    }

    #[test]
    fn complete_membership_requires_exact_manifest_roster() {
        let inventory = Inventory {
            files: vec![PayloadFile { path: "data/one".to_owned(), sha256: "a".repeat(64), size: 1 }],
            directories: BTreeSet::from(["data".to_owned()]),
        };
        let names = BTreeSet::from(["manifest.json".to_owned(), "data".to_owned(), "data/one".to_owned()]);
        assert_eq!(complete_names(&inventory, &names), Ok(()));
        for name in &names {
            let mut missing = names.clone();
            missing.remove(name);
            assert_eq!(complete_names(&inventory, &missing), Err(PublicationError::Inventory));
        }
        let mut extra = names.clone();
        extra.insert("unlisted".to_owned());
        assert_eq!(complete_names(&inventory, &extra), Err(PublicationError::Inventory));
        extra.remove("unlisted");
        extra.remove("data/one");
        extra.insert("data/two".to_owned());
        assert_eq!(complete_names(&inventory, &extra), Err(PublicationError::Inventory));
    }

    // Explicitly ignored nonroot helper fixtures, NOT installed-profile or root
    // publication tests. The original hosted command owner must opt in and set
    // TMPDIR to its private disposable case directory. There is no production
    // path, identity or platform override. Only low-level FD helpers run here.
    // Each case creates one exclusive tiny subtree; all are intentionally kept
    // for separately owned inspection/removal. No Drop/exit is a close receipt.
    fn fixture() -> Result<(Publisher, Slot)> {
        require(std::env::var_os("MRK_RUNTIME_PUBLICATION_HELPER_TESTS").as_deref() == Some(OsStr::new("1")), PublicationError::Profile)?;
        require(rustix::process::getuid().as_raw() != 0 && rustix::process::geteuid().as_raw() != 0
            && rustix::process::getgid().as_raw() != 0 && rustix::process::getegid().as_raw() != 0, PublicationError::Profile)?;
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("mrk-runtime-publish-test-{}-{sequence}", rustix::process::getpid().as_raw_pid()));
        fs::mkdirat(fs::CWD, &path, Mode::from_raw_mode(0o700)).map_err(native)?;
        let mut publisher = Publisher::new();
        let armed = publisher.originals.arm(false)?;
        let opened = fs::open(&path, read_flags(true), Mode::empty());
        let root = publisher.originals.receive(armed, opened)?;
        require(publisher.stat(root)?.st_mode & 0o7777 == 0o700, PublicationError::Identity)?;
        Ok((publisher, root))
    }
    fn fixture_directory(publisher: &mut Publisher, parent: Slot, name: &str) -> Result<Slot> {
        fs::mkdirat(publisher.originals.fd(parent)?, name, Mode::from_raw_mode(0o700)).map_err(native)?;
        publisher.open(Some(parent), name, read_flags(true), beneath())
    }
    fn fixture_file(publisher: &mut Publisher, parent: Slot, name: &str, bytes: &[u8]) -> Result<()> {
        let writer = publisher.open(Some(parent), name, write_flags(), beneath())?;
        publisher.write_all(writer, bytes)?;
        publisher.sync(writer)?;
        publisher.originals.close(writer)
    }
    fn named_identity(publisher: &Publisher, parent: Slot, name: &str) -> Result<Identity> {
        Ok(Identity::of(&publisher.named(parent, name)?.ok_or(PublicationError::Identity)?))
    }

    #[test]
    #[ignore = "separately admitted nonroot original-FD filesystem fixture"]
    fn helper_fresh_copy_has_independent_inode_and_bytes() -> Result<()> {
        let (mut publisher, root) = fixture()?;
        let bytes = b"original";
        let digest = policy::hex(&Sha256::digest(bytes));
        let source_writer = publisher.open(Some(root), "source", write_flags(), beneath())?;
        publisher.write_all(source_writer, bytes)?;
        fs::fchmod(publisher.originals.fd(source_writer)?, Mode::from_raw_mode(0o444)).map_err(native)?;
        publisher.sync(source_writer)?;
        let source = publisher.open(Some(root), "source", read_flags(false), beneath())?;
        let destination = publisher.open(Some(root), "destination", write_flags(), beneath())?;
        let before_source = publisher.stat(source)?;
        let before_destination = publisher.stat(destination)?;
        assert_ne!((before_source.st_dev, before_source.st_ino), (before_destination.st_dev, before_destination.st_ino));
        publisher.copy_bytes(source, destination, bytes.len() as u64, &digest, 0o444)?;
        assert!(publisher.originals.fd(source).is_err() && publisher.originals.fd(destination).is_err());

        // A pre-chmod source writer still works, but only against its source
        // inode. This must not alter the freshly copied destination bytes.
        fs::seek(publisher.originals.fd(source_writer)?, fs::SeekFrom::Start(0)).map_err(native)?;
        publisher.write_all(source_writer, b"tampered")?;
        publisher.sync(source_writer)?;
        publisher.originals.close(source_writer)?;
        publisher.originals.before_publication()?;
        let changed = publisher.open(Some(root), "source", read_flags(false), beneath())?;
        publisher.verify_bytes(changed, bytes.len() as u64, &policy::hex(&Sha256::digest(b"tampered")))?;
        publisher.originals.close(changed)?;
        let readback = publisher.open(Some(root), "destination", read_flags(false), beneath())?;
        assert_eq!(publisher.stat(readback)?.st_mode & 0o7777, 0o444);
        publisher.verify_bytes(readback, bytes.len() as u64, &digest)?;
        publisher.originals.close(readback)?;
        publisher.originals.settle()
    }

    #[test]
    #[ignore = "separately admitted nonroot original-FD filesystem fixture"]
    fn helper_source_size_digest_and_readback_refuse() -> Result<()> {
        let (mut publisher, root) = fixture()?;
        let bytes = b"payload";
        let digest = policy::hex(&Sha256::digest(bytes));
        fixture_file(&mut publisher, root, "source", bytes)?;
        for (name, size) in [("short-source", bytes.len() as u64 + 1), ("trailing-source", bytes.len() as u64 - 1)] {
            let source = publisher.open(Some(root), "source", read_flags(false), beneath())?;
            let destination = publisher.open(Some(root), name, write_flags(), beneath())?;
            assert_eq!(publisher.copy_bytes(source, destination, size, &digest, 0o444), Err(PublicationError::Identity));
            publisher.originals.close(destination)?;
            publisher.originals.close(source)?;
        }
        let source = publisher.open(Some(root), "source", read_flags(false), beneath())?;
        let destination = publisher.open(Some(root), "wrong-digest", write_flags(), beneath())?;
        assert_eq!(publisher.copy_bytes(source, destination, bytes.len() as u64, &"0".repeat(64), 0o444), Err(PublicationError::Inventory));
        publisher.originals.close(destination)?;
        publisher.originals.close(source)?;

        let source = publisher.open(Some(root), "source", read_flags(false), beneath())?;
        let destination = publisher.open(Some(root), "readback", write_flags(), beneath())?;
        publisher.copy_bytes(source, destination, bytes.len() as u64, &digest, 0o444)?;
        publisher.originals.before_publication()?;
        let good = publisher.open(Some(root), "readback", read_flags(false), beneath())?;
        publisher.verify_bytes(good, bytes.len() as u64, &digest)?;
        // Deliberate mutation of this test-owned inode, never a production repair.
        fs::fchmod(publisher.originals.fd(good)?, Mode::from_raw_mode(0o600)).map_err(native)?;
        publisher.originals.close(good)?;
        let writer = publisher.open(Some(root), "readback", OFlags::WRONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC, beneath())?;
        publisher.write_all(writer, b"damaged")?;
        fs::fchmod(publisher.originals.fd(writer)?, Mode::from_raw_mode(0o444)).map_err(native)?;
        publisher.sync(writer)?;
        publisher.originals.close(writer)?;
        let bad = publisher.open(Some(root), "readback", read_flags(false), beneath())?;
        assert_eq!(publisher.verify_bytes(bad, bytes.len() as u64, &digest), Err(PublicationError::Inventory));
        publisher.originals.close(bad)?;
        publisher.originals.settle()
    }

    #[test]
    #[ignore = "separately admitted nonroot original-FD filesystem fixture"]
    fn helper_noreplace_preserves_existing_names() -> Result<()> {
        let (mut publisher, root) = fixture()?;
        let stage = fixture_directory(&mut publisher, root, "stage")?;
        let existing = fixture_directory(&mut publisher, root, "final")?;
        fixture_file(&mut publisher, existing, "marker", b"retained")?;
        let stage_identity = named_identity(&publisher, root, "stage")?;
        let final_identity = named_identity(&publisher, root, "final")?;
        assert_eq!(fixture_directory(&mut publisher, root, "stage"), Err(PublicationError::Collision));
        assert_eq!(publisher.commit_directory(root, stage, "stage", "final"), Err(PublicationError::Collision));
        assert_eq!(publisher.renames, 1);
        assert_eq!(named_identity(&publisher, root, "stage")?, stage_identity);
        assert_eq!(named_identity(&publisher, root, "final")?, final_identity);
        let marker = publisher.open(Some(existing), "marker", read_flags(false), beneath())?;
        publisher.verify_bytes(marker, 8, &policy::hex(&Sha256::digest(b"retained")))?;
        publisher.originals.close(marker)?;
        publisher.originals.settle()
    }

    #[test]
    #[ignore = "separately admitted nonroot original-FD filesystem fixture"]
    fn helper_lost_close_receipt_blocks_publication() -> Result<()> {
        let (mut publisher, root) = fixture()?;
        let stage = fixture_directory(&mut publisher, root, "stage")?;
        let identity = named_identity(&publisher, root, "stage")?;
        let writer = publisher.open(Some(root), "writer", write_flags(), beneath())?;
        publisher.write_all(writer, b"x")?;
        publisher.originals.fail_close = Some(writer);
        assert_eq!(publisher.originals.close(writer), Err(PublicationError::Close));
        assert!(publisher.originals.fd(writer).is_err());
        assert_eq!(publisher.commit_directory(root, stage, "stage", "final"), Err(PublicationError::Close));
        assert_eq!(publisher.renames, 0);
        assert_eq!(named_identity(&publisher, root, "stage")?, identity);
        assert!(publisher.named(root, "final")?.is_none());
        assert_eq!(publisher.originals.closes.iter().filter(|slot| **slot == writer).count(), 1);
        assert_eq!(publisher.originals.settle(), Err(PublicationError::Close));
        assert_eq!(publisher.originals.live, 0);
        assert!(publisher.originals.rows.iter().all(|row| row.fd.is_none()));
        assert_eq!(publisher.originals.closes.iter().filter(|slot| **slot == writer).count(), 1);
        Ok(())
    }

    #[test]
    #[ignore = "separately admitted nonroot original-FD filesystem fixture"]
    fn helper_stage_sync_failure_prevents_rename() -> Result<()> {
        let (mut publisher, root) = fixture()?;
        let stage = fixture_directory(&mut publisher, root, "stage")?;
        let identity = named_identity(&publisher, root, "stage")?;
        publisher.fail_sync = Some(stage);
        assert_eq!(publisher.commit_directory(root, stage, "stage", "final"), Err(PublicationError::Native));
        assert_eq!(publisher.renames, 0);
        assert_eq!(named_identity(&publisher, root, "stage")?, identity);
        assert!(publisher.named(root, "final")?.is_none());
        publisher.originals.settle()
    }

    #[test]
    #[ignore = "separately admitted nonroot original-FD filesystem fixture"]
    fn helper_parent_sync_failure_preserves_published_name() -> Result<()> {
        let (mut publisher, root) = fixture()?;
        let stage = fixture_directory(&mut publisher, root, "stage")?;
        let key = DirectoryKey::of(&publisher.stat(stage)?);
        publisher.fail_sync = Some(root);
        assert_eq!(publisher.commit_directory(root, stage, "stage", "final"), Err(PublicationError::Native));
        assert_eq!(publisher.renames, 1);
        assert!(publisher.named(root, "stage")?.is_none());
        assert_eq!(DirectoryKey::of(&publisher.named(root, "final")?.ok_or(PublicationError::Identity)?), key);
        assert_eq!(DirectoryKey::of(&publisher.stat(stage)?), key);
        publisher.originals.settle()
    }

    #[test]
    #[ignore = "separately admitted nonroot original-FD filesystem fixture"]
    fn helper_extra_destination_member_is_rejected() -> Result<()> {
        let (mut publisher, root) = fixture()?;
        let stage = fixture_directory(&mut publisher, root, "stage")?;
        fixture_file(&mut publisher, stage, "manifest.json", b"{}")?;
        fixture_file(&mut publisher, stage, "payload", b"x")?;
        fixture_file(&mut publisher, stage, "extra", b"x")?;
        let inventory = Inventory {
            files: vec![PayloadFile { path: "payload".to_owned(), sha256: policy::hex(&Sha256::digest(b"x")), size: 1 }],
            directories: BTreeSet::new(),
        };
        let mut seen = BTreeSet::new();
        assert!(matches!(publisher.scan(stage, "", &inventory, &mut seen), Err(PublicationError::Inventory)));
        publisher.originals.settle()
    }

    #[test]
    #[ignore = "separately admitted nonroot original-FD filesystem fixture"]
    fn helper_source_directory_drift_is_rejected() -> Result<()> {
        let (mut publisher, root) = fixture()?;
        let source = fixture_directory(&mut publisher, root, "source")?;
        fixture_file(&mut publisher, source, "manifest.json", b"{}")?;
        let before = publisher.stat(source)?;
        let inventory = Inventory { files: Vec::new(), directories: BTreeSet::new() };
        let mut seen = BTreeSet::new();
        assert_eq!(publisher.scan(source, "", &inventory, &mut seen)?.len(), 1);
        complete_names(&inventory, &seen)?;
        // Mutation AFTER the accepted scan. A subdirectory changes the link
        // count too, without depending on timestamp tick granularity.
        let _late = fixture_directory(&mut publisher, source, "unlisted-after-scan")?;
        assert_eq!(DirectoryKey::of(&publisher.stat(source)?), DirectoryKey::of(&before));
        assert_eq!(publisher.unchanged(source, Identity::of(&before)), Err(PublicationError::Identity));
        publisher.originals.settle()
    }
}

// Separate from the eleven ordinary helper cases: this observes genuine
// administrator platform admission and must never run on the shared VPS.
#[cfg(test)]
mod platform_native_tests {
    use super::*;

    #[test]
    #[ignore = "reviewed disposable Ubuntu root platform observation only"]
    fn root_exact_ubuntu_platform() {
        assert!(matches!(std::env::var("MRK_UBUNTU_PUBLICATION_NATIVE").as_deref(), Ok("1")));
        assert!(matches!(std::env::var("GITHUB_ACTIONS").as_deref(), Ok("true")));
        assert!(matches!(std::env::var("RUNNER_ENVIRONMENT").as_deref(), Ok("github-hosted")));
        assert_eq!(admin_ids(), Ok(())); // No original descriptor exists yet.

        let mut publisher = Publisher::new();
        let mut phase = "root-context";
        let result = (|| -> Result<()> {
            let (root, _) = publisher.root_context()?;
            phase = "protected-opt";
            publisher.keep_child(root, "opt")?;
            phase = "retained-recheck";
            publisher.check_retained()?;
            admin_ids()?;
            publisher.tick()
        })();
        // No assertion can bypass the one ordinary settlement after the real
        // synchronous body returned. Failure never enters publication.
        let settled = publisher.originals.settle();
        assert_eq!((result, settled), (Ok(()), Ok(())), "root platform phase: {phase}");
    }
}
