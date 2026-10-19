//! Finite original descriptor/ACL book for public tool sources and their cache.
//! Only the fixed saved owner calls this on registered blocking workers. There
//! is no Drop cleanup, arbitrary path publisher, recursive repair or restart join.
use crate::{
    asset_source::{self, RegisteredRoot},
    tool_acquisition_protocol as wire,
};
use mrk_macos_installed_native::{
    self as native,
    vault_filesystem::{Expected, Failure, Policy, SnapshotBook},
};
use nix::{
    errno::Errno,
    fcntl::{self, AtFlags, FlockArg, OFlag},
    mount::MntFlags,
    sys::{
        stat::{self, FileStat, Mode, SFlag},
        statfs,
    },
    unistd::{self, Whence},
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    mem::ManuallyDrop,
    os::{
        fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd},
        unix::ffi::OsStrExt,
    },
    path::{Path, PathBuf},
    time::Instant,
};

pub(super) const FD_LIMIT: usize = 384;
const BLOCK: usize = 64 * 1024;
type Result<T> = std::result::Result<T, wire::Reason>;
fn need(value: bool, reason: wire::Reason) -> Result<()> {
    if value {
        Ok(())
    } else {
        Err(reason)
    }
}
fn point(stop: &mut dyn FnMut() -> bool) -> Result<()> {
    need(!stop(), wire::Reason::Cancelled)
}
fn io(_: impl std::fmt::Debug) -> wire::Reason {
    wire::Reason::CacheConflict
}
fn acl_failure(value: Failure) -> wire::Reason {
    match value {
        Failure::Stopped => wire::Reason::Cancelled,
        Failure::Unknown => wire::Reason::CleanupUnknown,
        Failure::Bounds => wire::Reason::Limit,
        _ => wire::Reason::CacheConflict,
    }
}
fn source_failure(value: crate::asset_commands::Reason) -> wire::Reason {
    use crate::asset_commands::Reason as R;
    match value {
        R::UserCancelled => wire::Reason::Cancelled,
        R::Deadline => wire::Reason::TimedOut,
        R::CleanupUnknown => wire::Reason::CleanupUnknown,
        R::Capacity | R::MaterialLimit => wire::Reason::Limit,
        R::SourceChanged | R::ExclusionUnconfirmed => wire::Reason::Stale,
        R::UnsupportedPlatform => wire::Reason::Unsupported,
        _ => wire::Reason::CacheConflict,
    }
}
fn expected_directory(fields: asset_source::ApplicationDirectoryFields) -> wire::DirectoryIdentity {
    wire::DirectoryIdentity {
        device: fields.0.to_string(),
        inode: fields.1.to_string(),
        mode: fields.2,
        uid: fields.3,
        gid: fields.4,
    }
}
fn existing_expectation(
    value: (
        asset_source::ApplicationDirectoryFields,
        Option<asset_source::ApplicationDirectoryFields>,
    ),
) -> Result<(wire::DirectoryIdentity, wire::DirectoryIdentity)> {
    // Fresh installation without app-data is deliberately unavailable in this
    // first native slice. ENOENT is not authority to initialize another service.
    let existing = value.1.ok_or(wire::Reason::Unsupported)?;
    Ok((expected_directory(value.0), expected_directory(existing)))
}
fn hash(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn flags(directory: bool) -> OFlag {
    OFlag::O_RDONLY
        | OFlag::O_CLOEXEC
        | OFlag::O_NOFOLLOW
        | OFlag::O_NONBLOCK
        | if directory {
            OFlag::O_DIRECTORY
        } else {
            OFlag::empty()
        }
}
fn directory(value: &FileStat) -> Result<wire::DirectoryIdentity> {
    need(
        value.st_mode & SFlag::S_IFMT.bits() == SFlag::S_IFDIR.bits() && value.st_ino != 0,
        wire::Reason::Stale,
    )?;
    Ok(wire::DirectoryIdentity {
        device: u64::try_from(value.st_dev).map_err(io)?.to_string(),
        inode: value.st_ino.to_string(),
        mode: u32::from(value.st_mode),
        uid: value.st_uid,
        gid: value.st_gid,
    })
}
fn file(value: &FileStat) -> Result<wire::FileIdentity> {
    need(
        value.st_mode & SFlag::S_IFMT.bits() == SFlag::S_IFREG.bits()
            && value.st_ino != 0
            && value.st_size >= 0
            && value.st_size <= 512 * 1024
            && value.st_nlink > 0
            && (0..1_000_000_000).contains(&value.st_mtime_nsec)
            && (0..1_000_000_000).contains(&value.st_ctime_nsec),
        wire::Reason::Stale,
    )?;
    Ok(wire::FileIdentity {
        device: u64::try_from(value.st_dev).map_err(io)?.to_string(),
        inode: value.st_ino.to_string(),
        mode: u32::from(value.st_mode),
        uid: value.st_uid,
        gid: value.st_gid,
        links: u32::from(value.st_nlink),
        bytes: u32::try_from(value.st_size).map_err(io)?,
        mtime_ns: (i128::from(value.st_mtime) * 1_000_000_000 + i128::from(value.st_mtime_nsec))
            .to_string(),
        ctime_ns: (i128::from(value.st_ctime) * 1_000_000_000 + i128::from(value.st_ctime_nsec))
            .to_string(),
    })
}

/// Supplied by the native app-local-data resolver; never deserialized from IPC.
#[derive(Clone)]
pub(super) struct Location {
    application: PathBuf,
    cache: PathBuf,
}
impl Location {
    pub(super) fn application_data(path: &Path) -> Result<Self> {
        need(
            wire::native_path(path).is_some()
                && path
                    .file_name()
                    .is_some_and(|n| n == "dev.mobile-release-kit.desktop")
                && path.as_os_str().len() < 4000,
            wire::Reason::Input,
        )?;
        Ok(Self {
            application: path.to_path_buf(),
            cache: path.join("tool-cache-v1"),
        })
    }
    pub(super) fn retained_bytes(&self) -> Option<usize> {
        std::mem::size_of::<Self>()
            .checked_add(self.application.capacity())?
            .checked_add(self.cache.capacity())
    }
}
#[derive(Clone)]
pub(super) struct Witness {
    base: wire::DirectoryIdentity,
    archives: wire::DirectoryIdentity,
    origins: wire::DirectoryIdentity,
}
pub(super) fn same_witness(a: &Witness, b: &Witness) -> bool {
    a.base == b.base && a.archives == b.archives && a.origins == b.origins
}
#[derive(Clone)]
pub(super) struct Origin {
    pub(super) operation: String,
    pub(super) intent_sha256: String,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    Reserved,
    Entered,
    Owned,
    NoHandle,
    Closing,
    Closed,
    Unknown,
}
struct Original {
    state: State,
    fd: Option<ManuallyDrop<OwnedFd>>,
    parent: Option<usize>,
    name: String,
    directory: Option<wire::DirectoryIdentity>,
    file: Option<wire::FileIdentity>,
    private: bool,
}
struct Source {
    root: usize,
    footprint: wire::Footprint,
    dirs: BTreeMap<String, usize>,
    files: Vec<(usize, wire::File)>,
    missing: Vec<(usize, String)>,
}
struct Cache {
    location: Location,
    base: usize,
    archives: usize,
    origins: usize,
    lock: usize,
    witness: Witness,
    known: Vec<Origin>,
    operation: String,
    intent: Vec<u8>,
    intent_sha256: String,
    control: Vec<(usize, Vec<u8>)>,
    pending: Option<usize>,
    settled: Option<usize>,
}
struct Application {
    root: RegisteredRoot,
    parent: usize,
    leaf: usize,
    post_checked: bool,
}
pub(super) struct Book {
    originals: Vec<Original>,
    acl: Option<RefCell<SnapshotBook>>,
    source: Option<Source>,
    // The SAME actual SourceBook is retained before the physical full-roster
    // probe. A failed/unknown source close cannot be erased by a later cache.
    application_source: Option<asset_source::SourceBook>,
    application_exclusion: Option<asset_source::ApplicationDirectoryExclusion>,
    application: Option<Application>,
    cache: Option<Cache>,
    entered: bool,
    retired: bool,
    unknown: bool,
    in_flight: bool,
    first: Option<(wire::Reason, Instant)>,
    uid: Option<u32>,
    settled_intent: bool,
}
impl Book {
    pub(super) fn new() -> Self {
        Self {
            originals: Vec::new(),
            acl: None,
            source: None,
            application_source: None,
            application_exclusion: None,
            application: None,
            cache: None,
            entered: false,
            retired: false,
            unknown: false,
            in_flight: false,
            first: None,
            uid: None,
            settled_intent: false,
        }
    }
    pub(super) fn first(&self) -> Option<(wire::Reason, Instant)> {
        let acl = self
            .acl
            .as_ref()
            .and_then(|a| a.try_borrow().ok())
            .and_then(|a| a.first_failure())
            .map(|(e, at)| (acl_failure(e), at));
        match (self.first, acl) {
            (Some(a), Some(b)) => Some(if a.1 <= b.1 { a } else { b }),
            (a, b) => a.or(b),
        }
    }
    pub(super) fn note(&mut self, reason: wire::Reason) {
        if self.first.is_none() {
            self.first = Some((reason, Instant::now()));
        }
        if reason == wire::Reason::CleanupUnknown {
            self.unknown = true;
        }
    }
    pub(super) fn interrupted(&mut self) {
        self.unknown = true;
        self.note(wire::Reason::CleanupUnknown);
    }
    fn fd(&self, index: usize) -> Result<BorrowedFd<'_>> {
        self.originals
            .get(index)
            .filter(|r| r.state == State::Owned)
            .and_then(|r| r.fd.as_ref())
            .map(|fd| fd.as_fd())
            .ok_or(wire::Reason::CleanupUnknown)
    }
    pub(super) fn arm(&mut self, stop: &mut dyn FnMut() -> bool) -> Result<()> {
        need(
            !self.entered && !self.retired && self.acl.is_none(),
            wire::Reason::AlreadyUsed,
        )?;
        point(stop)?;
        self.entered = true;
        self.acl = Some(RefCell::new(SnapshotBook::new()));
        need(
            self.acl
                .as_ref()
                .is_some_and(|a| a.borrow().retained_frame_bytes() > 0 && a.borrow().quiescent()),
            wire::Reason::Limit,
        )?;
        point(stop)?;
        self.uid = Some(native::real_user().map_err(io)?);
        point(stop)
    }
    fn named(
        &self,
        parent: usize,
        name: &str,
        stop: &mut dyn FnMut() -> bool,
    ) -> Result<Option<FileStat>> {
        point(stop)?;
        let value = stat::fstatat(self.fd(parent)?, name, AtFlags::AT_SYMLINK_NOFOLLOW);
        point(stop)?;
        match value {
            Ok(value) => Ok(Some(value)),
            Err(Errno::ENOENT) => Ok(None),
            Err(error) => Err(io(error)),
        }
    }
    fn stat(&self, index: usize, stop: &mut dyn FnMut() -> bool) -> Result<FileStat> {
        point(stop)?;
        let v = stat::fstat(self.fd(index)?).map_err(io)?;
        point(stop)?;
        Ok(v)
    }
    fn audit(
        &self,
        index: usize,
        value: &FileStat,
        private: bool,
        stop: &mut dyn FnMut() -> bool,
    ) -> Result<()> {
        point(stop)?;
        let fs = statfs::fstatfs(self.fd(index)?).map_err(io)?;
        point(stop)?;
        need(
            fs.filesystem_type_name() == "apfs"
                && fs.flags().contains(MntFlags::MNT_LOCAL)
                && !fs.flags().intersects(
                    MntFlags::MNT_UNION
                        | MntFlags::MNT_AUTOMOUNTED
                        | MntFlags::MNT_IGNORE_OWNERSHIP,
                ),
            wire::Reason::Unsupported,
        )?;
        let expected = Expected {
            device: u64::try_from(value.st_dev).map_err(io)?,
            inode: value.st_ino,
            mode: u32::from(value.st_mode),
            owner: value.st_uid,
            group: value.st_gid,
            flags: value.st_flags,
        };
        self.acl
            .as_ref()
            .ok_or(wire::Reason::CleanupUnknown)?
            .try_borrow_mut()
            .map_err(|_| wire::Reason::CleanupUnknown)?
            .observe(
                self.fd(index)?,
                expected,
                if private {
                    Policy::Empty
                } else {
                    Policy::Ancestors
                },
                stop,
            )
            .map_err(acl_failure)?;
        if private {
            point(stop)?;
            native::no_xattrs(self.fd(index)?).map_err(io)?;
            point(stop)?;
        }
        Ok(())
    }
    fn open(
        &mut self,
        parent: Option<usize>,
        name: &str,
        open_flags: OFlag,
        private: bool,
        stop: &mut dyn FnMut() -> bool,
    ) -> Result<usize> {
        point(stop)?;
        need(
            !self.retired && !self.unknown && self.originals.len() < FD_LIMIT,
            wire::Reason::Limit,
        )?;
        need(
            (parent.is_none() && name == "/")
                || (parent.is_some()
                    && !name.is_empty()
                    && name.len() <= 255
                    && !name.contains('/')
                    && !name.contains('\0')
                    && !matches!(name, "." | "..")),
            wire::Reason::Input,
        )?;
        self.originals
            .try_reserve(1)
            .map_err(|_| wire::Reason::Limit)?;
        let index = self.originals.len();
        self.originals.push(Original {
            state: State::Reserved,
            fd: None,
            parent,
            name: name.into(),
            directory: None,
            file: None,
            private,
        });
        self.originals[index].state = State::Entered;
        let mode = if open_flags.contains(OFlag::O_CREAT) {
            Mode::from_bits_truncate(0o600)
        } else {
            Mode::empty()
        };
        let result = match parent {
            Some(p) => fcntl::openat(self.fd(p)?, name, open_flags, mode),
            None => fcntl::open("/", open_flags, mode),
        };
        match result {
            Ok(fd) => {
                self.originals[index].fd = Some(ManuallyDrop::new(fd));
                self.originals[index].state = State::Owned;
            }
            Err(error) => {
                self.originals[index].state = State::NoHandle;
                return Err(io(error));
            }
        }
        point(stop)?;
        Ok(index)
    }
    fn directory(
        &mut self,
        parent: Option<usize>,
        name: &str,
        private: bool,
        stop: &mut dyn FnMut() -> bool,
    ) -> Result<usize> {
        let before = match parent {
            Some(p) => self.named(p, name, stop)?.ok_or(wire::Reason::Stale)?,
            None => {
                point(stop)?;
                stat::lstat("/").map_err(io)?
            }
        };
        let expected = directory(&before)?;
        let uid = self.uid.ok_or(wire::Reason::CleanupUnknown)?;
        need(
            if private {
                expected.uid == uid && expected.mode & 0o7777 == 0o700 && before.st_flags == 0
            } else {
                [0, uid].contains(&expected.uid) && expected.mode & 0o022 == 0
            },
            wire::Reason::CacheConflict,
        )?;
        let index = self.open(parent, name, flags(true), private, stop)?;
        let held = self.stat(index, stop)?;
        need(directory(&held)? == expected, wire::Reason::Stale)?;
        self.audit(index, &held, private, stop)?;
        self.originals[index].directory = Some(expected);
        self.check_named(index, stop)?;
        Ok(index)
    }
    fn path(&mut self, path: &Path, stop: &mut dyn FnMut() -> bool) -> Result<usize> {
        let text = wire::native_path(path).ok_or(wire::Reason::Input)?;
        let mut parent = self.directory(None, "/", false, stop)?;
        if text != "/" {
            for name in text[1..].split('/') {
                parent = self.directory(Some(parent), name, false, stop)?;
            }
        }
        Ok(parent)
    }
    fn make_directory(
        &mut self,
        parent: usize,
        name: &str,
        stop: &mut dyn FnMut() -> bool,
    ) -> Result<usize> {
        need(
            self.named(parent, name, stop)?.is_none(),
            wire::Reason::CacheConflict,
        )?;
        point(stop)?;
        self.in_flight = true;
        let result = stat::mkdirat(self.fd(parent)?, name, Mode::from_bits_truncate(0o700));
        self.in_flight = false;
        result.map_err(io)?;
        // Namespace exists now. Every later interruption leaves it intact.
        let index = self.directory(Some(parent), name, true, stop)?;
        self.sync(parent, stop)?;
        Ok(index)
    }
    fn check_named(&self, index: usize, stop: &mut dyn FnMut() -> bool) -> Result<()> {
        let record = self
            .originals
            .get(index)
            .ok_or(wire::Reason::CleanupUnknown)?;
        let held = self.stat(index, stop)?;
        let named = match record.parent {
            Some(parent) => self
                .named(parent, &record.name, stop)?
                .ok_or(wire::Reason::Stale)?,
            None => {
                point(stop)?;
                stat::lstat("/").map_err(io)?
            }
        };
        if let Some(id) = &record.directory {
            need(
                directory(&held)? == *id && directory(&named)? == *id,
                wire::Reason::Stale,
            )?;
        }
        if let Some(id) = &record.file {
            need(
                file(&held)? == *id && file(&named)? == *id,
                wire::Reason::Stale,
            )?;
        }
        need(
            held.st_flags == named.st_flags && (!record.private || held.st_flags == 0),
            wire::Reason::Stale,
        )?;
        self.audit(index, &held, record.private, stop)?;
        Ok(())
    }
    fn read(&self, index: usize, limit: usize, stop: &mut dyn FnMut() -> bool) -> Result<Vec<u8>> {
        let before = file(&self.stat(index, stop)?)?;
        need(before.bytes as usize <= limit, wire::Reason::Limit)?;
        point(stop)?;
        need(
            unistd::lseek(self.fd(index)?, 0, Whence::SeekSet).map_err(io)? == 0,
            wire::Reason::Stale,
        )?;
        point(stop)?;
        let mut result = Vec::new();
        result
            .try_reserve_exact(before.bytes as usize)
            .map_err(|_| wire::Reason::Limit)?;
        let mut buffer = [0u8; BLOCK];
        loop {
            point(stop)?;
            let count = unistd::read(self.fd(index)?, &mut buffer).map_err(io)?;
            point(stop)?;
            if count == 0 {
                break;
            }
            need(
                result
                    .len()
                    .checked_add(count)
                    .is_some_and(|n| n <= before.bytes as usize),
                wire::Reason::Stale,
            )?;
            result.extend_from_slice(&buffer[..count]);
        }
        need(
            result.len() == before.bytes as usize && file(&self.stat(index, stop)?)? == before,
            wire::Reason::Stale,
        )?;
        Ok(result)
    }
    fn open_file(
        &mut self,
        parent: usize,
        name: &str,
        private: bool,
        stop: &mut dyn FnMut() -> bool,
    ) -> Result<usize> {
        let before = self.named(parent, name, stop)?.ok_or(wire::Reason::Stale)?;
        let expected = file(&before)?;
        if private {
            need(
                expected.mode & 0o7777 == 0o600
                    && expected.uid == self.uid.unwrap_or(0)
                    && expected.links == 1
                    && before.st_flags == 0,
                wire::Reason::CacheConflict,
            )?;
        }
        let index = self.open(Some(parent), name, flags(false), private, stop)?;
        self.originals[index].file = Some(expected);
        self.check_named(index, stop)?;
        Ok(index)
    }
    pub(super) fn capture_sources(
        &mut self,
        root: &RegisteredRoot,
        expected: &wire::Footprint,
        stop: &mut dyn FnMut() -> bool,
    ) -> Result<()> {
        need(
            self.source.is_none() && expected.valid(),
            wire::Reason::Input,
        )?;
        let root_index = self.path(&root.path, stop)?;
        let id = root.identity.posix().map_err(io)?.preflight_identity();
        let captured = self.originals[root_index]
            .directory
            .as_ref()
            .ok_or(wire::Reason::Stale)?;
        need(
            (
                captured.device.as_str(),
                captured.inode.as_str(),
                captured.mode,
                captured.uid,
                captured.gid,
            ) == (
                id.device.as_str(),
                id.inode.as_str(),
                id.mode,
                id.uid,
                id.gid,
            ),
            wire::Reason::Stale,
        )?;
        self.source = Some(Source {
            root: root_index,
            footprint: expected.clone(),
            dirs: BTreeMap::new(),
            files: Vec::new(),
            missing: Vec::new(),
        });
        for row in &expected.directories {
            let (parent, name) = self.source_parent(&row.relative)?;
            let index = self.directory(Some(parent), name, false, stop)?;
            need(
                self.originals[index].directory.as_ref() == Some(&row.identity),
                wire::Reason::Stale,
            )?;
            self.source
                .as_mut()
                .ok_or(wire::Reason::CleanupUnknown)?
                .dirs
                .insert(row.relative.clone(), index);
        }
        for row in &expected.files {
            let (parent, name) = self.source_parent(&row.relative)?;
            let index = self.open_file(parent, name, false, stop)?;
            need(
                self.originals[index].file.as_ref() == Some(&row.identity)
                    && hash(&self.read(index, 512 * 1024, stop)?) == row.sha256,
                wire::Reason::Stale,
            )?;
            self.source
                .as_mut()
                .ok_or(wire::Reason::CleanupUnknown)?
                .files
                .push((index, row.clone()));
        }
        for name in &expected.missing {
            let (parent, leaf) = self.source_parent(name)?;
            let leaf = leaf.to_owned();
            need(
                self.named(parent, &leaf, stop)?.is_none(),
                wire::Reason::Stale,
            )?;
            self.source
                .as_mut()
                .ok_or(wire::Reason::CleanupUnknown)?
                .missing
                .push((parent, leaf));
        }
        self.check_sources(stop)
    }
    fn source_parent<'a>(&self, relative: &'a str) -> Result<(usize, &'a str)> {
        let source = self.source.as_ref().ok_or(wire::Reason::CleanupUnknown)?;
        match relative.rsplit_once('/') {
            Some((parent, name)) => source
                .dirs
                .get(parent)
                .copied()
                .map(|p| (p, name))
                .ok_or(wire::Reason::Stale),
            None => Ok((source.root, relative)),
        }
    }
    pub(super) fn check_sources(&self, stop: &mut dyn FnMut() -> bool) -> Result<()> {
        if let Some(source) = &self.source {
            for (index, record) in self.originals.iter().enumerate() {
                if record.directory.is_some() && record.state == State::Owned {
                    self.check_named(index, stop)?;
                }
            }
            for (index, expected) in &source.files {
                self.check_named(*index, stop)?;
                need(
                    hash(&self.read(*index, 512 * 1024, stop)?) == expected.sha256,
                    wire::Reason::Stale,
                )?;
            }
            for (parent, name) in &source.missing {
                need(
                    self.named(*parent, name, stop)?.is_none(),
                    wire::Reason::Stale,
                )?;
            }
        }
        point(stop)
    }
    fn names(
        &self,
        index: usize,
        limit: usize,
        stop: &mut dyn FnMut() -> bool,
    ) -> Result<BTreeSet<String>> {
        point(stop)?;
        need(
            unistd::lseek(self.fd(index)?, 0, Whence::SeekSet).map_err(io)? == 0,
            wire::Reason::CacheConflict,
        )?;
        point(stop)?;
        let mut names = BTreeSet::new();
        let mut buffer = [0u8; BLOCK];
        loop {
            point(stop)?;
            let used = native::directory_block(self.fd(index)?, &mut buffer).map_err(io)?;
            point(stop)?;
            if used == 0 {
                break;
            }
            need(used <= buffer.len(), wire::Reason::Limit)?;
            let mut at = 0;
            while at < used {
                need(used - at >= 11, wire::Reason::CacheConflict)?;
                let len = usize::from(u16::from_ne_bytes([buffer[at + 9], buffer[at + 10]]));
                let end = at
                    .checked_add(11 + len)
                    .filter(|end| *end <= used)
                    .ok_or(wire::Reason::Limit)?;
                let inode = u64::from_ne_bytes(buffer[at..at + 8].try_into().map_err(io)?);
                let kind = buffer[at + 8];
                need(
                    inode != 0 && matches!(kind, nix::libc::DT_REG | nix::libc::DT_DIR),
                    wire::Reason::CacheConflict,
                )?;
                let name = std::str::from_utf8(&buffer[at + 11..end]).map_err(io)?;
                at = end;
                if matches!(name, "." | "..") {
                    continue;
                }
                need(
                    !name.is_empty()
                        && name.len() <= 255
                        && name.is_ascii()
                        && !name.contains('/')
                        && !name.contains('\0')
                        && names.len() < limit
                        && names.insert(name.into()),
                    wire::Reason::CacheConflict,
                )?;
                let named = self.named(index, name, stop)?.ok_or(wire::Reason::Stale)?;
                need(
                    named.st_ino == inode
                        && named.st_mode & SFlag::S_IFMT.bits()
                            == if kind == nix::libc::DT_DIR {
                                SFlag::S_IFDIR.bits()
                            } else {
                                SFlag::S_IFREG.bits()
                            },
                    wire::Reason::Stale,
                )?;
            }
        }
        Ok(names)
    }
    fn sync(&self, index: usize, stop: &mut dyn FnMut() -> bool) -> Result<()> {
        point(stop)?;
        unistd::fsync(self.fd(index)?).map_err(io)?;
        point(stop)
    }
    fn write_new(
        &mut self,
        parent: usize,
        name: &str,
        bytes: &[u8],
        stop: &mut dyn FnMut() -> bool,
    ) -> Result<usize> {
        need(
            bytes.len() > 0
                && bytes.len() <= wire::CONTROL_LIMIT
                && self.named(parent, name, stop)?.is_none(),
            wire::Reason::CacheConflict,
        )?;
        let index = self.open(
            Some(parent),
            name,
            flags(false) | OFlag::O_RDWR | OFlag::O_CREAT | OFlag::O_EXCL,
            true,
            stop,
        )?;
        let mut at = 0;
        while at < bytes.len() {
            point(stop)?;
            self.in_flight = true;
            let result = unistd::write(self.fd(index)?, &bytes[at..]);
            self.in_flight = false;
            let count = result.map_err(io)?;
            need(
                count > 0 && count <= bytes.len() - at,
                wire::Reason::CacheConflict,
            )?;
            at += count;
            point(stop)?;
        }
        self.sync(index, stop)?;
        self.sync(parent, stop)?;
        let id = file(&self.stat(index, stop)?)?;
        need(
            id.mode & 0o7777 == 0o600 && id.uid == self.uid.unwrap_or(0) && id.links == 1,
            wire::Reason::CacheConflict,
        )?;
        self.originals[index].file = Some(id);
        self.check_named(index, stop)?;
        need(
            self.read(index, wire::CONTROL_LIMIT, stop)? == bytes,
            wire::Reason::CacheConflict,
        )?;
        Ok(index)
    }
    #[allow(deprecated)] // Same original descriptor; no independent RAII flock owner.
    pub(super) fn prepare_cache(
        &mut self,
        location: Location,
        projects: &[RegisteredRoot],
        previous: Option<&Witness>,
        known: &[Origin],
        operation: &str,
        intent: Vec<u8>,
        current: &mut dyn FnMut() -> bool,
        stop: &mut dyn FnMut() -> bool,
    ) -> Result<()> {
        need(
            self.cache.is_none()
                && self.application_source.is_none()
                && self.application_exclusion.is_none()
                && self.application.is_none()
                && projects.len() <= 64
                && crate::edit_protocol::token(operation)
                && intent.len() <= wire::CONTROL_LIMIT
                && known.len() < 32,
            wire::Reason::Input,
        )?;
        self.check_sources(stop)?;
        self.application_source = Some(asset_source::SourceBook::new());
        let proof = asset_source::probe_application_directory_exclusion(
            self.application_source
                .as_mut()
                .ok_or(wire::Reason::CleanupUnknown)?,
            &location.application,
            projects,
            stop,
        )
        .map_err(source_failure)?;
        self.application_exclusion = Some(proof);
        need(
            self.application_source
                .as_ref()
                .is_some_and(|b| b.settled()),
            wire::Reason::CleanupUnknown,
        )?;
        let (expected_parent, expected_app) = existing_expectation(
            self.application_exclusion
                .as_ref()
                .ok_or(wire::Reason::CleanupUnknown)?
                .store_expectation(&location.application, projects)
                .map_err(source_failure)?,
        )?;
        let parent = self.path(
            location.application.parent().ok_or(wire::Reason::Input)?,
            stop,
        )?;
        need(
            self.originals[parent].directory.as_ref() == Some(&expected_parent),
            wire::Reason::Stale,
        )?;
        let name = location
            .application
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or(wire::Reason::Input)?;
        // Match the actual no-follow edge against original Expected Existing,
        // not a second pathname snapshot or a successful resolver lookup.
        need(
            self.named(parent, name, stop)?
                .as_ref()
                .map(directory)
                .transpose()?
                == Some(expected_app.clone()),
            wire::Reason::Stale,
        )?;
        let app = self.directory(Some(parent), name, false, stop)?;
        need(
            self.originals[app].directory.as_ref() == Some(&expected_app),
            wire::Reason::Stale,
        )?;
        let actual = self.stat(app, stop)?;
        self.application = Some(Application {
            root: RegisteredRoot {
                path: location.application.clone(),
                identity: asset_source::ProjectIdentity::Posix(
                    asset_source::DirectoryIdentity::vault_original(
                        u64::try_from(actual.st_dev).map_err(io)?,
                        actual.st_ino,
                        u32::from(actual.st_mode),
                        actual.st_uid,
                        actual.st_gid,
                    ),
                ),
            },
            parent,
            leaf: app,
            post_checked: false,
        });
        self.check_application(stop)?;
        let existing = self.named(app, "tool-cache-v1", stop)?;
        // An existing path without this process's actual positive predecessor
        // is a restart/recovery fence, even if no target/job currently exists.
        need(
            existing.is_some() == previous.is_some(),
            wire::Reason::RecoveryRequired,
        )?;
        // Full original parent chain is rematched immediately BEFORE the
        // first possible namespace effect, not merely after the download.
        self.check_application(stop)?;
        need(current(), wire::Reason::Stale)?;
        let base = if existing.is_some() {
            self.directory(Some(app), "tool-cache-v1", true, stop)?
        } else {
            self.make_directory(app, "tool-cache-v1", stop)?
        };
        let new = previous.is_none();
        if !new {
            need(
                self.names(base, 3, stop)?
                    == [".lease", "archives", "origins"]
                        .into_iter()
                        .map(String::from)
                        .collect(),
                wire::Reason::CacheConflict,
            )?;
        }
        let archives = if new {
            self.make_directory(base, "archives", stop)?
        } else {
            self.directory(Some(base), "archives", true, stop)?
        };
        let origins = if new {
            self.make_directory(base, "origins", stop)?
        } else {
            self.directory(Some(base), "origins", true, stop)?
        };
        let lock = if new {
            let index = self.open(
                Some(base),
                ".lease",
                flags(false) | OFlag::O_RDWR | OFlag::O_CREAT | OFlag::O_EXCL,
                true,
                stop,
            )?;
            self.originals[index].file = Some(file(&self.stat(index, stop)?)?);
            self.sync(index, stop)?;
            self.sync(base, stop)?;
            index
        } else {
            self.open_file(base, ".lease", true, stop)?
        };
        need(
            self.originals[lock].file.as_ref().is_some_and(|id| {
                id.bytes == 0
                    && id.mode & 0o7777 == 0o600
                    && id.links == 1
                    && id.uid == self.uid.unwrap_or(0)
            }),
            wire::Reason::CacheConflict,
        )?;
        self.check_named(lock, stop)?;
        point(stop)?;
        self.in_flight = true;
        let result = fcntl::flock(self.fd(lock)?.as_raw_fd(), FlockArg::LockExclusiveNonblock);
        self.in_flight = false;
        result.map_err(io)?;
        point(stop)?;
        let witness = Witness {
            base: self.originals[base]
                .directory
                .clone()
                .ok_or(wire::Reason::CleanupUnknown)?,
            archives: self.originals[archives]
                .directory
                .clone()
                .ok_or(wire::Reason::CleanupUnknown)?,
            origins: self.originals[origins]
                .directory
                .clone()
                .ok_or(wire::Reason::CleanupUnknown)?,
        };
        if let Some(prior) = previous {
            need(
                witness.base == prior.base
                    && witness.archives == prior.archives
                    && witness.origins == prior.origins,
                wire::Reason::Stale,
            )?;
        }
        self.cache = Some(Cache {
            location,
            base,
            archives,
            origins,
            lock,
            witness,
            known: known.to_vec(),
            operation: operation.into(),
            intent_sha256: hash(&intent),
            intent,
            control: Vec::new(),
            pending: None,
            settled: None,
        });
        let expected: BTreeSet<String> = known
            .iter()
            .flat_map(|o| {
                [
                    format!("pending-{}.json", o.operation),
                    format!("settled-{}.json", o.operation),
                ]
            })
            .collect();
        need(
            expected.len() == known.len() * 2 && self.names(origins, 64, stop)? == expected,
            wire::Reason::RecoveryRequired,
        )?;
        let jobs = self.names(archives, 32, stop)?;
        need(
            jobs.iter().all(|job| {
                known
                    .iter()
                    .any(|o| job == &format!("tool-{}", o.operation))
            }),
            wire::Reason::RecoveryRequired,
        )?;
        for origin in known {
            need(
                crate::edit_protocol::token(&origin.operation)
                    && wire::sha(&origin.intent_sha256)
                    && origin.operation != operation,
                wire::Reason::Input,
            )?;
            for phase in ["pending", "settled"] {
                let index = self.open_file(
                    origins,
                    &format!("{phase}-{}.json", origin.operation),
                    true,
                    stop,
                )?;
                let bytes = self.read(index, wire::CONTROL_LIMIT, stop)?;
                if phase == "pending" {
                    need(
                        hash(&bytes) == origin.intent_sha256,
                        wire::Reason::RecoveryRequired,
                    )?;
                } else {
                    need(
                        bytes == settled_bytes(&origin.operation, &origin.intent_sha256)?,
                        wire::Reason::RecoveryRequired,
                    )?;
                }
                self.cache
                    .as_mut()
                    .ok_or(wire::Reason::CleanupUnknown)?
                    .control
                    .push((index, bytes));
            }
        }
        self.check_sources(stop)?;
        need(current(), wire::Reason::Stale)?;
        let bytes = self
            .cache
            .as_ref()
            .ok_or(wire::Reason::CleanupUnknown)?
            .intent
            .clone();
        let pending =
            self.write_new(origins, &format!("pending-{operation}.json"), &bytes, stop)?;
        self.cache
            .as_mut()
            .ok_or(wire::Reason::CleanupUnknown)?
            .pending = Some(pending);
        self.check_before_use(stop)
    }
    pub(super) fn check_before_use(&self, stop: &mut dyn FnMut() -> bool) -> Result<()> {
        need(
            !self.retired && !self.unknown && !self.in_flight,
            wire::Reason::CleanupUnknown,
        )?;
        self.check_sources(stop)?;
        self.check_application(stop)?;
        if let Some(cache) = &self.cache {
            for index in [cache.base, cache.archives, cache.origins, cache.lock] {
                self.check_named(index, stop)?;
            }
            for (index, expected) in &cache.control {
                self.check_named(*index, stop)?;
                need(
                    self.read(*index, wire::CONTROL_LIMIT, stop)? == *expected,
                    wire::Reason::Stale,
                )?;
            }
            let pending = cache.pending.ok_or(wire::Reason::RecoveryRequired)?;
            self.check_named(pending, stop)?;
            need(
                self.read(pending, wire::CONTROL_LIMIT, stop)? == cache.intent,
                wire::Reason::Stale,
            )?;
            let mut expected: BTreeSet<_> = cache
                .known
                .iter()
                .flat_map(|o| {
                    [
                        format!("pending-{}.json", o.operation),
                        format!("settled-{}.json", o.operation),
                    ]
                })
                .collect();
            expected.insert(format!("pending-{}.json", cache.operation));
            if cache.settled.is_some() {
                expected.insert(format!("settled-{}.json", cache.operation));
            }
            need(
                self.names(cache.origins, 64, stop)? == expected,
                wire::Reason::RecoveryRequired,
            )?;
            need(
                self.names(cache.archives, 32, stop)?.iter().all(|job| {
                    job == &format!("tool-{}", cache.operation)
                        || cache
                            .known
                            .iter()
                            .any(|o| job == &format!("tool-{}", o.operation))
                }),
                wire::Reason::RecoveryRequired,
            )?;
        }
        point(stop)
    }
    fn check_application(&self, stop: &mut dyn FnMut() -> bool) -> Result<()> {
        need(
            self.application_source
                .as_ref()
                .is_none_or(|b| b.not_started() || b.settled()),
            wire::Reason::CleanupUnknown,
        )?;
        if let Some(application) = &self.application {
            need(
                self.application_exclusion.is_some(),
                wire::Reason::CleanupUnknown,
            )?;
            // All forward edges of the same cache/project chains, including
            // root and app-data parent, remain original no-follow descriptors.
            for (index, original) in self.originals.iter().enumerate() {
                if original.directory.is_some() && original.state == State::Owned {
                    self.check_named(index, stop)?;
                }
            }
            for index in [application.parent, application.leaf] {
                self.check_named(index, stop)?;
            }
            let actual = directory(&self.stat(application.leaf, stop)?)?;
            let expected = application
                .root
                .identity
                .posix()
                .map_err(source_failure)?
                .preflight_identity();
            need(
                (
                    actual.device,
                    actual.inode,
                    actual.mode,
                    actual.uid,
                    actual.gid,
                ) == (
                    expected.device,
                    expected.inode,
                    expected.mode,
                    expected.uid,
                    expected.gid,
                ),
                wire::Reason::Stale,
            )?;
        }
        point(stop)
    }
    /// Called in the actual cache tail, after namespace writes and original
    /// consumer/runtime joins, before the SAME descriptors are closed.
    pub(super) fn post_application(&mut self, stop: &mut dyn FnMut() -> bool) -> Result<()> {
        self.check_application(stop)?;
        if let Some(application) = &mut self.application {
            application.post_checked = true;
        }
        Ok(())
    }
    /// Point-in-time native observation only, not a continuing directory lease.
    /// An independent fresh project-picker SourceBook must rematch this root.
    pub(super) fn application_root(&self) -> Result<Option<RegisteredRoot>> {
        need(self.settled(), wire::Reason::CleanupUnknown)?;
        match &self.application {
            Some(application) if application.post_checked => Ok(Some(application.root.clone())),
            Some(_) => Err(wire::Reason::Stale),
            None => Ok(None),
        }
    }
    pub(super) fn cache_data(
        &self,
        generation: u64,
        context_sha: &str,
        reference_sha: &str,
        projection_sha: &str,
    ) -> Result<Value> {
        let cache = self.cache.as_ref().ok_or(wire::Reason::RecoveryRequired)?;
        let source = self.source.as_ref().ok_or(wire::Reason::Stale)?;
        need(
            cache.pending.is_some() && !self.retired && !self.unknown,
            wire::Reason::RecoveryRequired,
        )?;
        let intent_base64 = crate::metadata_images_edit_protocol::base64(&cache.intent)
            .map_err(|_| wire::Reason::InputLimit)?;
        Ok(
            json!({"root":cache.location.cache.join("archives"),"rootIdentity":cache.witness.archives,"generation":generation,
            "contextSha256":context_sha,"referenceSha256":reference_sha,"projectionSha256":projection_sha,"missing":wire::COMPONENTS,"compatible":[],
            "intentBase64":intent_base64,"origins":cache.known.iter().map(|o|json!({"operationId":o.operation,"intentSha256":o.intent_sha256})).collect::<Vec<_>>(),
            "footprint":source.footprint}),
        )
    }
    /// Called only after the parent's actual child/IO/driver/runtime joins. The
    /// resulting JSON never reconstructs those joins after restart.
    pub(super) fn record_settled(&mut self, stop: &mut dyn FnMut() -> bool) -> Result<()> {
        self.check_before_use(stop)?;
        if self.cache.is_none() {
            return Ok(());
        }
        let cache = self.cache.as_ref().ok_or(wire::Reason::CleanupUnknown)?;
        need(cache.settled.is_none(), wire::Reason::AlreadyUsed)?;
        let (parent, name, bytes) = (
            cache.origins,
            format!("settled-{}.json", cache.operation),
            settled_bytes(&cache.operation, &cache.intent_sha256)?,
        );
        let index = self.write_new(parent, &name, &bytes, stop)?;
        self.cache
            .as_mut()
            .ok_or(wire::Reason::CleanupUnknown)?
            .settled = Some(index);
        self.settled_intent = true;
        self.check_before_use(stop)
    }
    pub(super) fn origin(&self) -> Option<(Origin, Witness)> {
        if !self.settled() || !self.settled_intent {
            return None;
        }
        let cache = self.cache.as_ref()?;
        Some((
            Origin {
                operation: cache.operation.clone(),
                intent_sha256: cache.intent_sha256.clone(),
            },
            cache.witness.clone(),
        ))
    }
    pub(super) fn settled(&self) -> bool {
        self.retired
            && !self.unknown
            && !self.in_flight
            && self
                .application_source
                .as_ref()
                .is_none_or(|b| b.not_started() || b.settled())
            && self
                .acl
                .as_ref()
                .is_none_or(|a| a.try_borrow().is_ok_and(|a| a.settled()))
            && self
                .originals
                .iter()
                .all(|o| o.fd.is_none() && matches!(o.state, State::Closed | State::NoHandle))
    }
    fn close(&mut self, index: usize) -> bool {
        let original = &mut self.originals[index];
        match original.state {
            State::Reserved => {
                original.state = State::NoHandle;
                return true;
            }
            State::NoHandle | State::Closed => return original.fd.is_none(),
            State::Owned => {}
            _ => {
                self.unknown = true;
                return false;
            }
        }
        original.state = State::Closing;
        let Some(fd) = original.fd.take() else {
            self.unknown = true;
            original.state = State::Unknown;
            return false;
        };
        let returned = unistd::close(ManuallyDrop::into_inner(fd));
        if returned.is_err() {
            original.state = State::Unknown;
            self.unknown = true;
            false
        } else {
            original.state = State::Closed;
            true
        }
    }
    pub(super) fn release(&mut self, expired: &mut dyn FnMut() -> bool) -> bool {
        if self.retired {
            return self.settled();
        }
        if self.in_flight {
            self.interrupted();
        }
        if self
            .application_source
            .as_ref()
            .is_some_and(|b| !b.not_started() && !b.settled())
        {
            // The original source worker already attempted its own closes.
            // Never adopt numeric descriptors or create a replacement book.
            self.interrupted();
        }
        if let Some(acl) = &mut self.acl {
            if !acl.get_mut().release(&mut |_| expired()) {
                self.unknown = true;
            }
        }
        for index in (0..self.originals.len()).rev() {
            if expired() {
                self.unknown = true;
                break;
            }
            if !self.close(index) {
                self.unknown = true;
            }
        }
        self.retired = true;
        self.settled()
    }
    pub(super) fn retained_bytes(&self) -> Option<usize> {
        if self.unknown || self.in_flight {
            return None;
        }
        let mut bytes = std::mem::size_of::<Self>().checked_add(
            self.originals
                .capacity()
                .checked_mul(std::mem::size_of::<Original>())?,
        )?;
        for o in &self.originals {
            bytes = bytes.checked_add(o.name.capacity())?;
            if let Some(d) = &o.directory {
                bytes = bytes
                    .checked_add(d.device.capacity())?
                    .checked_add(d.inode.capacity())?;
            }
            if let Some(f) = &o.file {
                for s in [&f.device, &f.inode, &f.mtime_ns, &f.ctime_ns] {
                    bytes = bytes.checked_add(s.capacity())?;
                }
            }
        }
        if let Some(acl) = &self.acl {
            let acl = acl.try_borrow().ok()?;
            if !acl.quiescent() {
                return None;
            }
            bytes = bytes.checked_add(acl.retained_frame_bytes())?;
        }
        if let Some(source) = &self.application_source {
            if !source.not_started() && !source.settled() {
                return None;
            }
            bytes = bytes
                .checked_add(std::mem::size_of::<asset_source::SourceBook>())?
                .checked_add(source.retained_bytes()?)?;
        }
        if let Some(proof) = &self.application_exclusion {
            bytes = bytes.checked_add(proof.retained_bytes()?)?;
        }
        if let Some(application) = &self.application {
            bytes = bytes
                .checked_add(std::mem::size_of::<Application>())?
                .checked_add(application.root.path.capacity())?;
        }
        // Source/cache controls are closed finite DATA, charged in addition to
        // actual original FD/ACL frame cells. No opaque SDK heap-size claim.
        if let Some(s) = &self.source {
            bytes = bytes
                .checked_add(s.footprint.retained_bytes()?)?
                .checked_add(
                    s.files
                        .capacity()
                        .checked_mul(std::mem::size_of::<(usize, wire::File)>())?,
                )?
                .checked_add(
                    s.missing
                        .capacity()
                        .checked_mul(std::mem::size_of::<(usize, String)>())?,
                )?;
            for (_, f) in &s.files {
                for v in [
                    &f.relative,
                    &f.sha256,
                    &f.identity.device,
                    &f.identity.inode,
                    &f.identity.mtime_ns,
                    &f.identity.ctime_ns,
                ] {
                    bytes = bytes.checked_add(v.capacity())?;
                }
            }
            for (_, name) in &s.missing {
                bytes = bytes.checked_add(name.capacity())?;
            }
            // BTreeMap node allocations are not exposed; this finite helper
            // reserve is additive, not reported as an exact native allocation.
            bytes = bytes.checked_add(132 * 1024)?;
        }
        if let Some(c) = &self.cache {
            bytes = bytes
                .checked_add(c.location.retained_bytes()?)?
                .checked_add(c.operation.capacity())?
                .checked_add(c.intent.capacity())?
                .checked_add(c.intent_sha256.capacity())?
                .checked_add(
                    c.known
                        .capacity()
                        .checked_mul(std::mem::size_of::<Origin>())?,
                )?
                .checked_add(
                    c.control
                        .capacity()
                        .checked_mul(std::mem::size_of::<(usize, Vec<u8>)>())?,
                )?;
            for o in &c.known {
                bytes = bytes
                    .checked_add(o.operation.capacity())?
                    .checked_add(o.intent_sha256.capacity())?;
            }
            for (_, raw) in &c.control {
                bytes = bytes.checked_add(raw.capacity())?;
            }
            for d in [&c.witness.base, &c.witness.archives, &c.witness.origins] {
                bytes = bytes
                    .checked_add(d.device.capacity())?
                    .checked_add(d.inode.capacity())?;
            }
        }
        Some(bytes)
    }
}
fn settled_bytes(operation: &str, intent: &str) -> Result<Vec<u8>> {
    crate::edit_protocol::bounded(
        &json!({"schemaVersion":1,"operationId":operation,
    "intentSha256":intent,"state":"producer-settled"}),
        wire::CONTROL_LIMIT,
    )
    .map_err(io)
}

#[cfg(test)]
mod tests {
    // Mac target DATA only: no SnapshotBook is armed and no FD/path is opened.
    use super::*;
    #[test]
    fn unentered_cache_close_never_mints_a_producer_origin() {
        let mut original = Book::new();
        assert!(!original.settled());
        assert!(original.application_root().is_err());
        assert!(original.release(&mut || false));
        assert!(original.origin().is_none());
        assert!(original.application_root().unwrap().is_none());
        assert!(original.release(&mut || false));
        assert!(original.origin().is_none());
    }
    #[test]
    fn unknown_survives_empty_cache_and_cannot_become_an_absence_retry() {
        let mut original = Book::new();
        original.interrupted();
        assert!(!original.release(&mut || false));
        assert!(!original.settled());
        assert!(original.origin().is_none());
        assert!(original.application_root().is_err());
        assert!(original.retained_bytes().is_none());
        assert_eq!(original.first().unwrap().0, wire::Reason::CleanupUnknown);
    }
    #[test]
    fn missing_application_is_unavailable_and_existing_fields_are_lossless() {
        let parent = (17, 29, 0o40755, 501, 20);
        let leaf = (17, u64::MAX, 0o40700, 501, 21);
        assert_eq!(
            existing_expectation((parent, None)).err(),
            Some(wire::Reason::Unsupported)
        );
        let (actual_parent, actual_leaf) = existing_expectation((parent, Some(leaf))).unwrap();
        assert_eq!(actual_parent, expected_directory(parent));
        assert_eq!(actual_leaf, expected_directory(leaf));
        for changed in [
            (18, leaf.1, leaf.2, leaf.3, leaf.4),
            (leaf.0, 30, leaf.2, leaf.3, leaf.4),
            (leaf.0, leaf.1, 0o40755, leaf.3, leaf.4),
            (leaf.0, leaf.1, leaf.2, 502, leaf.4),
            (leaf.0, leaf.1, leaf.2, leaf.3, 22),
        ] {
            assert_ne!(actual_leaf, expected_directory(changed));
        }
    }
}
