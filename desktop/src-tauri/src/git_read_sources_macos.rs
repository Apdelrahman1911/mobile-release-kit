//! GitRead-only child of asset_source_macos. The existing SourceBook, Account
//! and SnapshotBook retain all real calls/FDs until their enclosing Supervisor
//! inspection/acquisition/settlement originals return. No new IO executor.
use super::*;
use crate::git_read_protocol as wire;
use mrk_macos_installed_native::{
    local_account::Account,
    vault_filesystem::{Expected, Failure, Policy, SnapshotBook},
};
use sha2::{Digest, Sha256};
use std::time::Instant;
use zeroize::Zeroizing;

const SOURCE_LIMIT: usize = 128;
pub(crate) struct GitReadSources {
    book: SourceBook,
    account: Account,
    acl: Option<SnapshotBook>,
    acl_entered: bool,
    started: bool,
    finished: bool,
    close_failed: bool,
    first: Option<Reason>,
    native: Option<wire::Native>,
    git: Option<usize>,
    indices: [Option<usize>; 4],
    flags: git_source_flags::Snapshots<SOURCE_LIMIT>,
}
impl Drop for GitReadSources {
    fn drop(&mut self) {
        // Defensive retention only, never a successful closure or retry route.
        if !self.book.settled() {
            let book = std::mem::replace(&mut self.book, SourceBook::new());
            std::mem::forget(book);
        }
    }
}
impl GitReadSources {
    pub(crate) fn new() -> Self {
        Self {
            book: SourceBook::new(),
            account: Account::new(),
            acl: None,
            acl_entered: false,
            started: false,
            finished: false,
            close_failed: false,
            first: None,
            native: None,
            git: None,
            indices: [None; 4],
            flags: git_source_flags::Snapshots::new(),
        }
    }
    pub(crate) fn not_started(&self) -> bool {
        !self.started && !self.finished && !self.acl_entered && self.acl.is_none() && self.book.not_started()
    }
    pub(crate) fn working_bytes() -> Option<usize> {
        SOURCE_LIMIT
            .checked_mul(std::mem::size_of::<Descriptor>() + 255)?
            .checked_add(std::mem::size_of::<Self>() + 65536 + 3 * PATH_LIMIT + 4096)?
            .checked_add(mrk_macos_installed_native::vault_filesystem::SNAPSHOT_FRAME_BYTES)
    }
    pub(crate) fn first_failure(&self) -> Option<(Failure, Instant)> {
        self.acl.as_ref().and_then(SnapshotBook::first_failure)
    }
    pub(crate) fn mark_interrupted(&mut self) {
        self.first.get_or_insert(Reason::CleanupUnknown);
        self.close_failed = true;
    }
    fn remember<T>(&mut self, result: Result<T, Reason>) -> Result<T, Reason> {
        if let Err(reason) = &result {
            self.first.get_or_insert(*reason);
        }
        result
    }
    fn file(
        &mut self,
        parent: usize,
        name: &[u8],
        uid: u32,
        maximum: u64,
        executable: bool,
        stop: &mut dyn FnMut() -> bool,
    ) -> Result<usize, Reason> {
        checkpoint(stop)?;
        let index = self.book.reserve(Some(parent), name)?;
        let before = stat::fstatat(self.book.fd(parent)?, OsStr::from_bytes(name), AtFlags::AT_SYMLINK_NOFOLLOW)
            .map_err(|_| Reason::SourceRefused)?;
        checkpoint(stop)?;
        let expected = file_identity(&before)?;
        if expected.common.uid != uid
            || expected.nlink != 1
            || expected.common.mode & 0o7022 != 0
            || expected.size > maximum
            || executable && (expected.size == 0 || expected.common.mode & 0o111 == 0)
            || !git_source_flags::permits(before.st_flags, uid,
                if executable { git_source_flags::Kind::SystemGit } else { git_source_flags::Kind::RepositoryFile })
        {
            return Err(Reason::SourceRefused);
        }
        self.book.slots[index].state = OriginalState::Acquiring;
        let opened = fcntl::openat(
            self.book.fd(parent)?,
            OsStr::from_bytes(name),
            OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK,
            Mode::empty(),
        );
        self.book.adopt(index, opened)?;
        checkpoint(stop)?;
        filesystem(self.book.fd(index)?, stop)?;
        let held = stat::fstat(self.book.fd(index)?).map_err(|_| Reason::SourceChanged)?;
        checkpoint(stop)?;
        let named = stat::fstatat(self.book.fd(parent)?, OsStr::from_bytes(name), AtFlags::AT_SYMLINK_NOFOLLOW)
            .map_err(|_| Reason::SourceChanged)?;
        checkpoint(stop)?;
        if file_identity(&held)? != expected || file_identity(&named)? != expected
            || held.st_flags != before.st_flags || named.st_flags != before.st_flags {
            return Err(Reason::SourceChanged);
        }
        self.flags.observe(index, held.st_flags, named.st_flags, uid,
            if executable { git_source_flags::Kind::SystemGit } else { git_source_flags::Kind::RepositoryFile })?;
        self.book.slots[index].identity = Some(Identity::File(expected));
        Ok(index)
    }
    fn snapshot(&self, index: usize, maximum: u64, stop: &mut dyn FnMut() -> bool) -> Result<wire::Snapshot, Reason> {
        checkpoint(stop)?;
        let expected = match self.book.slots[index].identity {
            Some(Identity::File(value)) => value,
            _ => return Err(Reason::SourceChanged),
        };
        if expected.size > maximum {
            return Err(Reason::Capacity);
        }
        let held = stat::fstat(self.book.fd(index)?).map_err(|_| Reason::SourceChanged)?;
        checkpoint(stop)?;
        if file_identity(&held)? != expected {
            return Err(Reason::SourceChanged);
        }
        let nanos = |v: (i64, i64)| -> Result<i64, Reason> {
            if !(0..1_000_000_000).contains(&v.1) {
                return Err(Reason::SourceRefused);
            }
            v.0.checked_mul(1_000_000_000)
                .and_then(|s| s.checked_add(v.1))
                .ok_or(Reason::SourceRefused)
        };
        unistd::lseek(self.book.fd(index)?, 0, unistd::Whence::SeekSet).map_err(|_| Reason::SourceRefused)?;
        let mut buffer = Zeroizing::new([0u8; 32768]);
        let mut hash = Sha256::new();
        let mut count = 0u64;
        loop {
            checkpoint(stop)?;
            let count_now = unistd::read(self.book.fd(index)?, &mut buffer[..]).map_err(|_| Reason::SourceRefused)?;
            checkpoint(stop)?;
            if count_now == 0 {
                break;
            }
            count = count.checked_add(count_now as u64).ok_or(Reason::Capacity)?;
            if count > expected.size {
                return Err(Reason::SourceChanged);
            }
            hash.update(&buffer[..count_now]);
        }
        let after = stat::fstat(self.book.fd(index)?).map_err(|_| Reason::SourceChanged)?;
        checkpoint(stop)?;
        if count != expected.size || file_identity(&after)? != expected {
            return Err(Reason::SourceChanged);
        }
        Ok(wire::Snapshot {
            identity: (
                expected.common.dev,
                expected.common.ino,
                expected.common.mode,
                expected.common.uid,
                expected.common.gid,
                expected.nlink,
                expected.size,
                nanos(expected.mtime)?,
                nanos(expected.ctime)?,
            ),
            sha256: hash.finalize().iter().map(|b| format!("{b:02x}")).collect(),
        })
    }
    pub(crate) fn inspect(&mut self, root: &RegisteredRoot, runtime_live: usize, stop: &mut dyn FnMut() -> bool) -> Result<(), Reason> {
        if !self.not_started() {
            return Err(Reason::CleanupUnknown);
        }
        self.started = true;
        let result = (|| {
            checkpoint(stop)?;
            self.account.acquire().map_err(|_| Reason::SourceRefused)?;
            checkpoint(stop)?;
            let (_, uid, gid) = self.account.selected().map_err(|_| Reason::SourceRefused)?;
            let project_parts = parts(&root.path)?;
            let tool_parts = parts(Path::new(wire::TOOL_PATH))?;
            let parent_parts = &tool_parts[..tool_parts.len() - 1];
            let capacity = roster_limit([project_parts.len(), parent_parts.len()], 8 + source_extra(&project_parts))?;
            if capacity > SOURCE_LIMIT
                || capacity
                    .checked_add(runtime_live)
                    .and_then(|n| n.checked_add(32))
                    .is_none_or(|n| n > 256)
            {
                return Err(Reason::Capacity);
            }
            self.book.begin(capacity, 0, 1)?;
            self.acl_entered = true;
            self.acl = Some(SnapshotBook::new());
            self.book.root(stop)?;
            self.book.anchor_private(stop)?;
            let (project_chain, _) = self.book.chain(&project_parts, true, stop)?;
            let project = *project_chain.last().ok_or(Reason::SourceRefused)?;
            if self.book.directory(project)? != root.identity.posix()? {
                return Err(Reason::SourceChanged);
            }
            let git = self.book.child(project, b".git", false, stop)?;
            self.git = Some(git);
            let objects = self.book.child(git, b"objects", false, stop)?;
            let (tool_chain, _) = self.book.chain(parent_parts, false, stop)?;
            // This fixed provider is not nominated through a user-writable
            // executable prefix. Held and named identities are rechecked by
            // post_inner; the Python worker freezes and verifies the same tool.
            for index in &tool_chain {
                let directory = self.book.directory(*index)?;
                if directory.uid != 0 || directory.mode & 0o7022 != 0 {
                    return Err(Reason::SourceRefused);
                }
            }
            let tool_parent = *tool_chain.last().ok_or(Reason::SourceRefused)?;
            let tool = self.file(tool_parent, b"git", 0, wire::TOOL_LIMIT, true, stop)?;
            self.indices[0] = Some(tool);
            let head = self.file(git, b"HEAD", uid, 2048, false, stop)?;
            self.indices[1] = Some(head);
            let config = self.file(git, b"config", uid, 65536, false, stop)?;
            self.indices[2] = Some(config);
            checkpoint(stop)?;
            match stat::fstatat(self.book.fd(git)?, "index", AtFlags::AT_SYMLINK_NOFOLLOW) {
                Err(nix::errno::Errno::ENOENT) => {}
                Ok(_) => {
                    self.indices[3] = Some(self.file(git, b"index", uid, wire::INDEX_LIMIT, false, stop)?);
                }
                Err(_) => return Err(Reason::SourceRefused),
            }
            let directory = |index| -> Result<wire::DirectoryIdentity, Reason> {
                let d = self.book.directory(index)?;
                Ok((d.dev, d.ino, d.mode, d.uid, d.gid))
            };
            let native = wire::Native {
                uid,
                gid,
                root: root.path.to_str().ok_or(Reason::SourceRefused)?.into(),
                directories: wire::Directories {
                    root: directory(project)?,
                    git: directory(git)?,
                    objects: directory(objects)?,
                },
                tool: self.snapshot(tool, wire::TOOL_LIMIT, stop)?,
                files: wire::Files {
                    head: self.snapshot(head, 2048, stop)?,
                    config: self.snapshot(config, 65536, stop)?,
                    index: self.indices[3].map(|i| self.snapshot(i, wire::INDEX_LIMIT, stop)).transpose()?,
                },
            };
            if !native.valid() {
                return Err(Reason::SourceRefused);
            }
            self.native = Some(native);
            self.post_inner(stop)
        })();
        self.remember(result)
    }
    fn post_inner(&mut self, stop: &mut dyn FnMut() -> bool) -> Result<(), Reason> {
        let (_, uid, _) = self.account.selected().map_err(|_| Reason::SourceChanged)?;
        for index in 0..self.book.slots.len() {
            checkpoint(stop)?;
            let slot = &self.book.slots[index];
            let expected = slot.identity.ok_or(Reason::SourceChanged)?;
            let file = matches!(expected, Identity::File(_));
            let fd = self.book.fd(index)?;
            filesystem(fd, stop)?;
            let held = stat::fstat(fd).map_err(|_| Reason::SourceChanged)?;
            checkpoint(stop)?;
            let named = if let Some(parent) = slot.parent {
                stat::fstatat(self.book.fd(parent)?, OsStr::from_bytes(&slot.name), AtFlags::AT_SYMLINK_NOFOLLOW)
            } else {
                stat::lstat(Path::new("/"))
            }
            .map_err(|_| Reason::SourceChanged)?;
            checkpoint(stop)?;
            if identity(&held, file)? != expected
                || identity(&named, file)? != expected
                || held.st_uid != 0 && held.st_uid != uid
            {
                return Err(Reason::SourceChanged);
            }
            self.flags.observe(index, held.st_flags, named.st_flags, held.st_uid,
                if Some(index) == self.indices[0] { git_source_flags::Kind::SystemGit }
                else if file { git_source_flags::Kind::RepositoryFile }
                else { git_source_flags::Kind::Directory })?;
            // Existing protected temporary ancestors may be sticky; no other
            // group/other writable directory can nominate a Git executable.
            if held.st_mode & 0o7022 != 0 && !(slot.role == PhysicalRole::Tmp && held.st_mode & 0o1000 != 0) {
                return Err(Reason::SourceRefused);
            }
            let actual = common(&held)?;
            self.acl
                .as_mut()
                .ok_or(Reason::CleanupUnknown)?
                .observe(
                    fd.as_fd(),
                    Expected {
                        device: actual.dev,
                        inode: actual.ino,
                        mode: actual.mode,
                        owner: actual.uid,
                        group: actual.gid,
                        flags: held.st_flags,
                    },
                    if file { Policy::Empty } else { Policy::Ancestors },
                    stop,
                )
                .map_err(|failure| {
                    if failure == Failure::Unknown {
                        Reason::CleanupUnknown
                    } else {
                        Reason::SourceRefused
                    }
                })?;
            checkpoint(stop)?;
        }
        for alias in &self.book.aliases {
            self.book.check_alias(alias, stop)?;
        }
        let original = self.native.as_ref().ok_or(Reason::SourceChanged)?;
        for (index, expected, maximum) in [
            (self.indices[0], Some(&original.tool), wire::TOOL_LIMIT),
            (self.indices[1], Some(&original.files.head), 2048),
            (self.indices[2], Some(&original.files.config), 65536),
            (self.indices[3], original.files.index.as_ref(), wire::INDEX_LIMIT),
        ] {
            match (index, expected) {
                (Some(index), Some(expected)) if self.snapshot(index, maximum, stop)? == *expected => {}
                (None, None) => {
                    checkpoint(stop)?;
                    if !matches!(
                        stat::fstatat(
                            self.book.fd(self.git.ok_or(Reason::SourceChanged)?)?,
                            "index",
                            AtFlags::AT_SYMLINK_NOFOLLOW
                        ),
                        Err(nix::errno::Errno::ENOENT)
                    ) {
                        return Err(Reason::SourceChanged);
                    }
                    checkpoint(stop)?;
                }
                _ => return Err(Reason::SourceChanged),
            }
        }
        Ok(())
    }
    pub(crate) fn post(&mut self, stop: &mut dyn FnMut() -> bool) -> Result<(), Reason> {
        if self.finished || self.first.is_some() {
            return Err(Reason::SourceChanged);
        }
        let result = self.post_inner(stop);
        self.remember(result)
    }
    pub(crate) fn native_snapshot(&self) -> Result<&wire::Native, Reason> {
        if self.finished || self.first.is_some() {
            return Err(Reason::SourceChanged);
        }
        self.native.as_ref().ok_or(Reason::SourceRefused)
    }
    pub(crate) fn close(&mut self, expired: &mut dyn FnMut(Option<(Failure, Instant)>) -> bool) -> Result<(), Reason> {
        if self.finished {
            return if self.settled() { Ok(()) } else { Err(Reason::CleanupUnknown) };
        }
        self.finished = true;
        self.close_failed = true;
        if !self.account.call_settled() || self.first == Some(Reason::CleanupUnknown) || self.acl_entered && self.acl.is_none() {
            return Err(Reason::CleanupUnknown);
        }
        if let Some(acl) = self.acl.as_mut() {
            if !acl.release(expired) || !acl.settled() {
                return Err(Reason::CleanupUnknown);
            }
        }
        if expired(self.first_failure()) || !self.book.close_all() || expired(self.first_failure()) {
            return Err(Reason::CleanupUnknown);
        }
        self.close_failed = false;
        Ok(())
    }
    pub(crate) fn settled(&self) -> bool {
        self.finished
            && !self.close_failed
            && self.account.call_settled()
            && self.book.settled()
            && (!self.acl_entered || self.acl.as_ref().is_some_and(SnapshotBook::settled))
    }
}
