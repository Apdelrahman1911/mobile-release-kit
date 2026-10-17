//! Fixed setup child's source census and confined-link walk. Private and not
//! registered until the sole Parent/copier route is complete. No publication,
//! source execution, mode repair or arbitrary source nomination occurs here.
#![cfg(all(
    target_os = "macos",
    target_pointer_width = "64",
    any(target_arch = "aarch64", target_arch = "x86_64")
))]
use super::{
    macos_xcode_copy::{self as copy, Failure, Identity, Result, Work},
    macos_xcode_setup as profile,
};
use crate as native;
use nix::{libc, mount::MntFlags, sys::statfs};
use sha2::{Digest, Sha256};
use std::{
    collections::VecDeque,
    ffi::{CStr, CString},
    os::fd::{AsRawFd, BorrowedFd},
    time::Instant,
};

#[derive(Clone, Copy)]
enum SourceRole {
    Payload,
    Applications,
}

#[derive(Clone, Copy)]
enum Slot {
    Vacant,
    Acquiring,
    Owned(libc::c_int),
    Closed,
    Unknown,
}
/// The ONE copier's fixed FD table. Every native open reserves first, observes
/// its returned FD before any fallible point, and consumes once. Unknown close
/// stays charged/fatal. No OwnedFd Drop, duplicate or reusable unknown slot.
pub(crate) struct CopierFiles {
    slots: [Slot; profile::COPIER_ORIGINAL_LIMIT],
    unknown: bool,
    cleanup: Instant,
    first: Option<Instant>,
    inherited: usize,
    cleaning: bool,
}
impl CopierFiles {
    pub(crate) fn new(
        original_cleanup: Instant,
        actual_inherited_originals: usize,
    ) -> Result<Self> {
        if actual_inherited_originals > profile::COPIER_ORIGINAL_LIMIT {
            return Err(Failure::Bounds);
        }
        Ok(Self {
            slots: [Slot::Vacant; profile::COPIER_ORIGINAL_LIMIT],
            unknown: false,
            cleanup: original_cleanup,
            first: None,
            inherited: actual_inherited_originals,
            cleaning: false,
        })
    }
    pub(crate) fn note_failure(&mut self) {
        self.fail_at(Instant::now());
    }
    pub(crate) fn fail_at(&mut self, at: Instant) {
        self.first = Some(self.first.map_or(at, |old| old.min(at)));
    }
    pub(crate) fn first_failure(&self) -> Option<Instant> {
        self.first
    }
    fn cleanup_end(&self) -> Instant {
        self.first
            .and_then(|at| at.checked_add(std::time::Duration::from_secs(120)))
            .map_or(self.cleanup, |end| end.min(self.cleanup))
    }
    fn reserve(&mut self) -> Result<usize> {
        if self.unknown {
            return Err(Failure::Close);
        }
        if self.first.is_some() && !self.cleaning {
            return Err(Failure::Binding);
        }
        if self.cleaning && Instant::now() >= self.cleanup_end() {
            return Err(Failure::Deadline);
        }
        if self
            .live()
            .checked_add(self.inherited)
            .is_none_or(|n| n >= profile::COPIER_ORIGINAL_LIMIT)
        {
            return Err(Failure::Bounds);
        }
        let index = self
            .slots
            .iter()
            .position(|s| matches!(s, Slot::Vacant | Slot::Closed))
            .ok_or(Failure::Bounds)?;
        self.slots[index] = Slot::Acquiring;
        Ok(index)
    }
    pub(crate) fn live(&self) -> usize {
        self.slots
            .iter()
            .filter(|s| !matches!(s, Slot::Vacant | Slot::Closed))
            .count()
    }
    pub(crate) fn fd(&self, index: usize) -> Result<BorrowedFd<'_>> {
        match self.slots.get(index) {
            Some(Slot::Owned(fd)) => Ok(unsafe { BorrowedFd::borrow_raw(*fd) }),
            _ => Err(Failure::Binding),
        }
    }
    pub(crate) fn open_source(
        &mut self,
        parent: BorrowedFd<'_>,
        name: &CStr,
        expected: Identity,
        work: &Work,
    ) -> Result<usize> {
        let result = self.open_source_inner(parent, name, expected, work, SourceRole::Payload);
        if result.is_err() {
            self.note_failure();
        }
        result
    }
    /// The caller lends its already admitted root original. This closed route
    /// cannot select another name, and grants no payload or managed authority.
    pub(crate) fn open_applications(
        &mut self,
        root: BorrowedFd<'_>,
        expected: Identity,
        work: &Work,
    ) -> Result<usize> {
        let result = self.open_source_inner(
            root, c"Applications", expected, work, SourceRole::Applications,
        );
        if result.is_err() {
            self.note_failure();
        }
        result
    }
    fn open_source_inner(
        &mut self,
        parent: BorrowedFd<'_>,
        name: &CStr,
        expected: Identity,
        work: &Work,
        role: SourceRole,
    ) -> Result<usize> {
        work.point()?;
        if !profile::component(name.to_bytes()) {
            return Err(Failure::Bounds);
        }
        let kind = match role {
            SourceRole::Payload => expected.source_kind()?,
            SourceRole::Applications => {
                if name != c"Applications" {
                    return Err(Failure::Binding);
                }
                expected.applications_directory()?;
                profile::Kind::Directory
            }
        };
        let flags = libc::O_RDONLY
            | libc::O_CLOEXEC
            | libc::O_NONBLOCK
            // Darwin O_SYMLINK opens the link itself. Adding O_NOFOLLOW
            // instead makes vn_authorize_open_existing reject it with ELOOP.
            | match kind {
                profile::Kind::Directory => libc::O_DIRECTORY | libc::O_NOFOLLOW,
                profile::Kind::Symlink => libc::O_SYMLINK,
                profile::Kind::Regular => libc::O_NOFOLLOW,
            };
        let slot = self.reserve()?;
        let fd = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
        self.slots[slot] = if fd < 0 {
            Slot::Closed
        } else {
            Slot::Owned(fd)
        };
        if fd < 0 {
            return Err(Failure::Read);
        }
        work.point()?;
        let original = self.fd(slot)?;
        copy::exact(original, parent, name, expected, work)?;
        copy::empty_acl(original, work)?;
        let fs = statfs::fstatfs(original).map_err(|_| Failure::Metadata)?;
        work.point()?;
        if fs.filesystem_type_name() != "apfs"
            || !fs.flags().contains(MntFlags::MNT_LOCAL)
            || fs.flags().intersects(
                MntFlags::MNT_UNION | MntFlags::MNT_AUTOMOUNTED | MntFlags::MNT_IGNORE_OWNERSHIP,
            )
        {
            return Err(Failure::Access);
        }
        copy::exact(original, parent, name, expected, work)?;
        Ok(slot)
    }
    fn open_reserved_root(
        &mut self,
        parent: BorrowedFd<'_>,
        expected: Identity,
        work: &Work,
    ) -> Result<usize> {
        work.point()?;
        copy::private_stage(expected)?;
        let slot = self.reserve()?;
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                c"Xcode.app".as_ptr(),
                libc::O_RDONLY
                    | libc::O_DIRECTORY
                    | libc::O_NOFOLLOW
                    | libc::O_CLOEXEC
                    | libc::O_NONBLOCK,
            )
        };
        self.slots[slot] = if fd < 0 {
            Slot::Closed
        } else {
            Slot::Owned(fd)
        };
        if fd < 0 {
            return Err(Failure::Read);
        }
        work.point()?;
        copy::exact(self.fd(slot)?, parent, c"Xcode.app", expected, work)?;
        copy::empty_acl(self.fd(slot)?, work)?;
        Ok(slot)
    }
    /// Only the fixed child's private stage. Exclusive creation never reuses
    /// a present node. Even an open/POST failure leaves the created namespace
    /// retained for Parent's authenticated pending cleanup, not an eager unlink.
    fn create_output(
        &mut self,
        parent: BorrowedFd<'_>,
        name: &CStr,
        kind: profile::Kind,
        target: Option<&[u8]>,
        work: &Work,
    ) -> Result<(usize, Identity)> {
        let result = (|| -> Result<(usize, Identity)> {
            work.point()?;
            if unsafe { libc::geteuid() } != 0
                || unsafe { libc::getuid() } != 0
                || !profile::component(name.to_bytes())
            {
                return Err(Failure::Access);
            }
            let link_target = if kind == profile::Kind::Symlink {
                Some(
                    CString::new(
                        target
                            .filter(|v| profile::relative_link_shape(v))
                            .ok_or(Failure::Links)?,
                    )
                    .map_err(|_| Failure::Links)?,
                )
            } else {
                None
            };
            let slot = self.reserve()?;
            let fd = match kind {
                profile::Kind::Regular => unsafe {
                    libc::openat(
                        parent.as_raw_fd(),
                        name.as_ptr(),
                        libc::O_RDWR
                            | libc::O_CREAT
                            | libc::O_EXCL
                            | libc::O_CLOEXEC
                            | libc::O_NOFOLLOW,
                        0o600,
                    )
                },
                profile::Kind::Directory => {
                    if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
                        self.slots[slot] = Slot::Closed;
                        return Err(Failure::Write);
                    }
                    unsafe {
                        libc::openat(
                            parent.as_raw_fd(),
                            name.as_ptr(),
                            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                        )
                    }
                }
                profile::Kind::Symlink => {
                    let target = link_target.as_ref().ok_or(Failure::Links)?;
                    if unsafe {
                        libc::symlinkat(target.as_ptr(), parent.as_raw_fd(), name.as_ptr())
                    } != 0
                    {
                        self.slots[slot] = Slot::Closed;
                        return Err(Failure::Write);
                    }
                    unsafe {
                        libc::openat(
                            parent.as_raw_fd(),
                            name.as_ptr(),
                            libc::O_RDONLY | libc::O_SYMLINK | libc::O_CLOEXEC | libc::O_NONBLOCK,
                        )
                    }
                }
            };
            self.slots[slot] = if fd < 0 {
                Slot::Closed
            } else {
                Slot::Owned(fd)
            };
            if fd < 0 {
                return Err(Failure::Write);
            }
            let original = self.fd(slot)?;
            let id = copy::fstat(original, work)?;
            copy::exact(original, parent, name, id, work)?;
            copy::empty_acl(original, work)?;
            Ok((slot, id))
        })();
        if result.is_err() {
            self.note_failure();
        }
        result
    }
    fn open_output(
        &mut self,
        parent: BorrowedFd<'_>,
        name: &CStr,
        source: Identity,
        expected: Identity,
        work: &Work,
    ) -> Result<usize> {
        let result = (|| -> Result<usize> {
            work.point()?;
            copy::sealed_output(source, expected)?;
            if !profile::component(name.to_bytes()) {
                return Err(Failure::Bounds);
            }
            let kind = source.source_kind()?;
            let slot = self.reserve()?;
            let fd = unsafe {
                libc::openat(
                    parent.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY
                        | libc::O_CLOEXEC
                        | libc::O_NONBLOCK
                        | match kind {
                            profile::Kind::Directory => libc::O_DIRECTORY | libc::O_NOFOLLOW,
                            profile::Kind::Symlink => libc::O_SYMLINK,
                            profile::Kind::Regular => libc::O_NOFOLLOW,
                        },
                )
            };
            self.slots[slot] = if fd < 0 {
                Slot::Closed
            } else {
                Slot::Owned(fd)
            };
            if fd < 0 {
                return Err(Failure::Read);
            }
            copy::exact(self.fd(slot)?, parent, name, expected, work)?;
            copy::empty_acl(self.fd(slot)?, work)?;
            Ok(slot)
        })();
        if result.is_err() {
            self.note_failure();
        }
        result
    }
    /// One fixed bounded control original; no general filesystem reader API.
    pub(crate) fn read_attempt(
        &mut self,
        namespace: BorrowedFd<'_>,
        expected: Identity,
        expected_bytes: usize,
        work: &Work,
    ) -> Result<Vec<u8>> {
        work.point()?;
        if self.cleaning || expected.retiring_kind()? != profile::Kind::Regular {
            return Err(Failure::Binding);
        }
        let slot = self.reserve()?;
        let fd = unsafe {
            libc::openat(
                namespace.as_raw_fd(),
                c"attempt.json".as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        self.slots[slot] = if fd < 0 {
            Slot::Closed
        } else {
            Slot::Owned(fd)
        };
        if fd < 0 {
            return Err(Failure::Read);
        }
        work.point()?;
        copy::exact(self.fd(slot)?, namespace, c"attempt.json", expected, work)?;
        copy::empty_acl(self.fd(slot)?, work)?;
        let mut bytes = [0u8; 4097];
        let n = unsafe { libc::pread(fd, bytes.as_mut_ptr().cast(), bytes.len(), 0) };
        work.point()?;
        if n <= 0 || n > 4096 || n as usize != expected_bytes {
            return Err(Failure::Bounds);
        }
        copy::exact(self.fd(slot)?, namespace, c"attempt.json", expected, work)?;
        self.close(slot)?;
        Ok(bytes[..n as usize].to_vec())
    }
    /// The same actual table changes to one-way fixed-pending cleanup only
    /// after every earlier tracked original has positively closed. No unknown
    /// slot is reusable and the original first-failure cleanup cutoff survives.
    fn cleanup_mode(&mut self, parent: libc::pid_t) -> Result<Work> {
        if self.unknown || self.live() != 0 || self.cleaning {
            return Err(Failure::Close);
        }
        let work = Work {
            end: self.cleanup_end(),
            parent,
        };
        work.point()?;
        self.cleaning = true;
        Ok(work)
    }
    fn open_retiring(
        &mut self,
        parent: BorrowedFd<'_>,
        name: &CStr,
        expected: Identity,
        work: &Work,
    ) -> Result<usize> {
        if !self.cleaning {
            return Err(Failure::Binding);
        }
        work.point()?;
        let kind = expected.retiring_kind()?;
        if !profile::component(name.to_bytes()) {
            return Err(Failure::Bounds);
        }
        let slot = self.reserve()?;
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY
                    | libc::O_CLOEXEC
                    | libc::O_NONBLOCK
                    | match kind {
                        profile::Kind::Directory => libc::O_DIRECTORY | libc::O_NOFOLLOW,
                        profile::Kind::Symlink => libc::O_SYMLINK,
                        profile::Kind::Regular => libc::O_NOFOLLOW,
                    },
            )
        };
        self.slots[slot] = if fd < 0 {
            Slot::Closed
        } else {
            Slot::Owned(fd)
        };
        if fd < 0 {
            return Err(Failure::Read);
        }
        work.point()?;
        copy::exact(self.fd(slot)?, parent, name, expected, work)?;
        copy::empty_acl(self.fd(slot)?, work)?;
        Ok(slot)
    }
    /// This is deliberately NOT an arbitrary tree remover. The authenticated
    /// caller lends the original private pending wrapper and durable stage ID;
    /// the only root name this routine can unlink is its Xcode.app child.
    pub(crate) fn retire_pending(
        &mut self,
        pending: BorrowedFd<'_>,
        pending_id: Identity,
        device: u64,
        inode: u64,
        parent_pid: libc::pid_t,
    ) -> Result<()> {
        let work = self.cleanup_mode(parent_pid)?;
        copy::private_stage(pending_id)?;
        if copy::fstat(pending, &work)? != pending_id {
            return Err(Failure::Binding);
        }
        let mut missing = std::mem::MaybeUninit::<libc::stat>::uninit();
        let present = unsafe {
            libc::fstatat(
                pending.as_raw_fd(),
                c"Xcode.app".as_ptr(),
                missing.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if present != 0 {
            if std::io::Error::last_os_error().raw_os_error() != Some(libc::ENOENT) {
                return Err(Failure::Read);
            }
            work.point()?;
            let mut budget = NameBudget { live: 0 };
            let rows = names(pending, pending_id, &mut budget, &work)?;
            let empty = rows.is_empty();
            budget.release(&rows);
            if !empty {
                return Err(Failure::Binding);
            }
            return work.point();
        }
        let root = copy::named(pending, c"Xcode.app", &work)?;
        if root.device() as u64 != device
            || root.inode() != inode
            || root.retiring_kind()? != profile::Kind::Directory
        {
            return Err(Failure::Binding);
        }
        let mut budget = NameBudget { live: 0 };
        let mut entries = 0u64;
        let result = self.retire_walk(
            pending,
            c"Xcode.app",
            root,
            0,
            9,
            &mut entries,
            &mut budget,
            &work,
        );
        if result.is_err() {
            self.note_failure();
        }
        let closed = self.close_all();
        result?;
        if !closed || budget.live != 0 {
            return Err(Failure::Close);
        }
        let after = copy::fstat(pending, &work)?;
        if !pending_id.same_owned_directory(after) {
            return Err(Failure::Binding);
        }
        let rows = names(pending, after, &mut budget, &work)?;
        let empty = rows.is_empty();
        budget.release(&rows);
        if !empty {
            return Err(Failure::Binding);
        }
        native::sync(pending, false).map_err(|_| Failure::Sync)?;
        work.point()
    }
    fn retire_walk(
        &mut self,
        parent: BorrowedFd<'_>,
        name: &CStr,
        expected: Identity,
        depth: usize,
        path_bytes: usize,
        entries: &mut u64,
        budget: &mut NameBudget,
        work: &Work,
    ) -> Result<()> {
        work.point()?;
        *entries = entries.checked_add(1).ok_or(Failure::Bounds)?;
        if *entries > profile::ENTRY_LIMIT
            || depth > profile::DEPTH_LIMIT
            || path_bytes > profile::PATH_LIMIT
        {
            return Err(Failure::Bounds);
        }
        let kind = expected.retiring_kind()?;
        let slot = self.open_retiring(parent, name, expected, work)?;
        let raw = self.fd(slot)?.as_raw_fd();
        let original = unsafe { BorrowedFd::borrow_raw(raw) };
        let mut current = expected;
        if kind == profile::Kind::Directory {
            let rows = names(original, current, budget, work)?;
            let traversed = (|| -> Result<()> {
                for row in &rows {
                    copy::exact(original, parent, name, current, work)?;
                    let child = copy::named(original, row.cstr()?, work)?;
                    let child_kind = child.retiring_kind()?;
                    let listed_kind = match child_kind {
                        profile::Kind::Directory => libc::DT_DIR,
                        profile::Kind::Regular => libc::DT_REG,
                        profile::Kind::Symlink => libc::DT_LNK,
                    };
                    if row.inode != child.inode()
                        || row.kind != listed_kind
                        || child.device() != expected.device()
                    {
                        return Err(Failure::Binding);
                    }
                    self.retire_walk(
                        original,
                        row.cstr()?,
                        child,
                        depth + 1,
                        path_bytes
                            .checked_add(1 + row.key().len())
                            .ok_or(Failure::Bounds)?,
                        entries,
                        budget,
                        work,
                    )?;
                    let changed = copy::fstat(original, work)?;
                    if !current.same_owned_directory(changed) {
                        return Err(Failure::Binding);
                    }
                    current = changed;
                }
                let remaining = names(original, current, budget, work)?;
                let empty = remaining.is_empty();
                budget.release(&remaining);
                if !empty {
                    return Err(Failure::Binding);
                }
                Ok(())
            })();
            budget.release(&rows);
            traversed?;
        }
        copy::exact(original, parent, name, current, work)?;
        copy::empty_acl(original, work)?;
        work.point()?;
        let removed = unsafe {
            libc::unlinkat(
                parent.as_raw_fd(),
                name.as_ptr(),
                if kind == profile::Kind::Directory {
                    libc::AT_REMOVEDIR
                } else {
                    0
                },
            )
        };
        if removed != 0 {
            return Err(Failure::Write);
        }
        work.point()?;
        // Recheck absence without following any former leaf, then consume the
        // still-held inode independently. No close error is treated as success.
        let mut absent = std::mem::MaybeUninit::<libc::stat>::uninit();
        let r = unsafe {
            libc::fstatat(
                parent.as_raw_fd(),
                name.as_ptr(),
                absent.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if r == 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::ENOENT) {
            return Err(Failure::Binding);
        }
        let retired = copy::fstat(original, work)?;
        if !current.same_retired_inode(retired) {
            return Err(Failure::Binding);
        }
        self.close(slot)?;
        work.point()
    }
    pub(crate) fn close(&mut self, index: usize) -> Result<()> {
        // Consuming cleanup uses the original F, not expired W/getppid. Losing
        // Parent revokes forward work but does not invent an uncloseable FD.
        if Instant::now() >= self.cleanup_end() {
            self.note_failure();
            self.unknown = true;
            return Err(Failure::Close);
        }
        match self.slots.get(index).copied() {
            Some(Slot::Owned(fd)) => {
                self.slots[index] = Slot::Unknown;
                let result = unsafe { libc::close(fd) }; // EXACTLY one attempt.
                if result == 0 {
                    self.slots[index] = Slot::Closed;
                } else {
                    self.note_failure();
                    self.unknown = true;
                }
                if result != 0 || Instant::now() >= self.cleanup_end() {
                    self.note_failure();
                    self.unknown = true;
                    return Err(Failure::Close);
                }
                Ok(())
            }
            Some(Slot::Vacant | Slot::Closed) => Ok(()),
            _ => {
                self.note_failure();
                self.unknown = true;
                Err(Failure::Close)
            }
        }
    }
    pub(crate) fn close_all(&mut self) -> bool {
        let mut known = true;
        for index in (0..self.slots.len()).rev() {
            if self.close(index).is_err() {
                known = false;
            }
        }
        known && !self.unknown && self.live() == 0
    }
}

#[derive(Clone)]
struct Entry {
    name: [u8; 256],
    length: u16,
    inode: u64,
    kind: u8,
}
impl Entry {
    fn key(&self) -> &[u8] {
        &self.name[..usize::from(self.length)]
    }
    fn cstr(&self) -> Result<&CStr> {
        CStr::from_bytes_with_nul(&self.name[..usize::from(self.length) + 1])
            .map_err(|_| Failure::Bounds)
    }
    fn matches(&self, identity: Identity) -> Result<()> {
        let kind = match identity.source_kind()? {
            profile::Kind::Directory => libc::DT_DIR,
            profile::Kind::Regular => libc::DT_REG,
            profile::Kind::Symlink => libc::DT_LNK,
        };
        if self.inode != identity.inode() || self.kind != kind {
            return Err(Failure::Binding);
        }
        Ok(())
    }
}
/// The actual simultaneous vector capacities, not total path string bytes.
struct NameBudget {
    live: usize,
}
impl NameBudget {
    fn grow(&mut self, entries: &mut Vec<Entry>) -> Result<()> {
        if entries.len() < entries.capacity() {
            return Ok(());
        }
        let wanted = entries.capacity().max(16).min(1024);
        let bytes = wanted
            .checked_mul(std::mem::size_of::<Entry>())
            .ok_or(Failure::Bounds)?;
        if !profile::name_control_fit(self.live as u64, bytes as u64) {
            return Err(Failure::Bounds);
        }
        let old = entries.capacity();
        entries
            .try_reserve_exact(wanted)
            .map_err(|_| Failure::Bounds)?;
        let actual = (entries.capacity() - old)
            .checked_mul(std::mem::size_of::<Entry>())
            .ok_or(Failure::Bounds)?;
        // Allocator over-reserve must still fit, not silently use quoted lower
        // capacity; no next native call/entry insertion before checking it.
        self.live = self.live.checked_add(actual).ok_or(Failure::Bounds)?;
        if self.live > profile::NAME_CONTROL_LIMIT as usize {
            return Err(Failure::Bounds);
        }
        Ok(())
    }
    fn release(&mut self, entries: &Vec<Entry>) {
        self.live -= entries.capacity() * std::mem::size_of::<Entry>();
    }
}
fn names(
    fd: BorrowedFd<'_>,
    expected: Identity,
    budget: &mut NameBudget,
    work: &Work,
) -> Result<Vec<Entry>> {
    let mut rows = Vec::new();
    let observed = (|| -> Result<()> {
        work.point()?;
        if unsafe { libc::lseek(fd.as_raw_fd(), 0, libc::SEEK_SET) } != 0 {
            return Err(Failure::Read);
        }
        let mut block = [0u8; 65536];
        loop {
            work.point()?;
            let used = native::directory_block(fd, &mut block).map_err(|_| Failure::Read)?;
            work.point()?;
            if copy::fstat(fd, work)? != expected {
                return Err(Failure::Binding);
            }
            if used == 0 {
                break;
            }
            let mut at = 0;
            while at < used {
                if used - at < 11 {
                    return Err(Failure::Metadata);
                }
                let inode = u64::from_ne_bytes(
                    block[at..at + 8]
                        .try_into()
                        .map_err(|_| Failure::Metadata)?,
                );
                let kind = block[at + 8];
                let length = usize::from(u16::from_ne_bytes(
                    block[at + 9..at + 11]
                        .try_into()
                        .map_err(|_| Failure::Metadata)?,
                ));
                let end = at
                    .checked_add(11 + length)
                    .filter(|n| *n <= used)
                    .ok_or(Failure::Bounds)?;
                let value = &block[at + 11..end];
                at = end;
                if value == b"." || value == b".." {
                    continue;
                }
                if !profile::component(value)
                    || inode == 0
                    || !matches!(kind, libc::DT_DIR | libc::DT_REG | libc::DT_LNK)
                {
                    return Err(Failure::Kind);
                }
                if rows.len() >= profile::ENTRY_LIMIT as usize {
                    return Err(Failure::Bounds);
                }
                budget.grow(&mut rows)?;
                let mut name = [0; 256];
                name[..length].copy_from_slice(value);
                rows.push(Entry {
                    name,
                    length: length as u16,
                    inode,
                    kind,
                });
            }
        }
        rows.sort_unstable_by(|a, b| a.key().cmp(b.key()));
        work.point()?;
        if rows.windows(2).any(|p| p[0].key() == p[1].key()) {
            return Err(Failure::Binding);
        }
        Ok(())
    })();
    if let Err(failure) = observed {
        budget.release(&rows);
        return Err(failure);
    }
    Ok(rows)
}
fn link(parent: BorrowedFd<'_>, name: &CStr, identity: Identity, work: &Work) -> Result<Vec<u8>> {
    work.point()?;
    let mut target = [0u8; profile::LINK_LIMIT + 1];
    let count = unsafe {
        libc::readlinkat(
            parent.as_raw_fd(),
            name.as_ptr(),
            target.as_mut_ptr().cast(),
            target.len(),
        )
    };
    work.point()?;
    if count <= 0
        || count as usize > profile::LINK_LIMIT
        || copy::named(parent, name, work)? != identity
    {
        return Err(Failure::Links);
    }
    if !profile::relative_link_shape(&target[..count as usize]) {
        return Err(Failure::Links);
    }
    Ok(target[..count as usize].to_vec())
}

/// Original physical walk plus ordered link resolution. Parent/tree source
/// nominations and Apple signature are external REQUIRED admission, not granted
/// by this census. One final digest folds all original stat fields/names/links;
/// bytes are independently read back by the copy phase, never assumed from stat.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Census {
    pub(crate) quote: profile::CopyQuote,
    pub(crate) digest: [u8; 32],
}
pub(crate) struct SealedCopy {
    pub(crate) slot: usize,
    pub(crate) identity: Identity,
    pub(crate) digest: [u8; 32],
}
pub(crate) struct SourceTree<'a> {
    root: BorrowedFd<'a>,
    root_identity: Identity,
    root_parent: BorrowedFd<'a>,
    root_name: &'a CStr,
    work: &'a Work,
    copy_started: bool,
    protected: bool,
}
impl<'a> SourceTree<'a> {
    pub(crate) fn original(
        root: BorrowedFd<'a>,
        parent: BorrowedFd<'a>,
        name: &'a CStr,
        identity: Identity,
        work: &'a Work,
    ) -> Result<Self> {
        if identity.source_kind()? != profile::Kind::Directory {
            return Err(Failure::Kind);
        }
        copy::exact(root, parent, name, identity, work)?;
        copy::empty_acl(root, work)?;
        Ok(Self {
            root,
            root_identity: identity,
            root_parent: parent,
            root_name: name,
            work,
            copy_started: false,
            protected: false,
        })
    }
    /// Same bounded physical reader, additionally enforcing exact sealed modes
    /// on EVERY actual node. No copy or normalization is available on this view.
    pub(crate) fn protected(mut self) -> Result<Self> {
        self.root_identity.protected_kind()?;
        self.protected = true;
        Ok(self)
    }
    fn root_post(&self) -> Result<()> {
        copy::exact(
            self.root,
            self.root_parent,
            self.root_name,
            self.root_identity,
            self.work,
        )
    }
    fn confined_link(
        &self,
        files: &mut CopierFiles,
        parent_parts: &[Vec<u8>],
        target: &[u8],
    ) -> Result<()> {
        let mut pending: VecDeque<Vec<u8>> = parent_parts.iter().cloned().collect();
        pending.extend(target.split(|b| *b == b'/').map(|p| p.to_vec()));
        let mut stack: Vec<(usize, Identity, Vec<u8>)> = Vec::new();
        let mut links = 0;
        let observed = (|| -> Result<()> {
            while let Some(part) = pending.pop_front() {
                self.work.point()?;
                if pending.iter().map(|p| p.len() + 1).sum::<usize>()
                    + stack.iter().map(|r| r.2.len() + 1).sum::<usize>()
                    + part.len()
                    > profile::PATH_LIMIT
                {
                    return Err(Failure::Bounds);
                }
                if part == b"." {
                    continue;
                }
                if part == b".." {
                    let (slot, id, component) = stack.last().ok_or(Failure::Links)?;
                    let parent = if stack.len() == 1 {
                        self.root
                    } else {
                        files.fd(stack[stack.len() - 2].0)?
                    };
                    let component =
                        CString::new(component.as_slice()).map_err(|_| Failure::Links)?;
                    copy::exact(files.fd(*slot)?, parent, &component, *id, self.work)?;
                    // Keep the slot in stack until close returns; a refused
                    // original remains available for independent final cleanup.
                    files.close(*slot)?;
                    stack.pop();
                    continue;
                }
                if !profile::component(&part) {
                    return Err(Failure::Links);
                }
                let name = CString::new(part.clone()).map_err(|_| Failure::Links)?;
                let parent = match stack.last() {
                    Some((slot, _, _)) => files.fd(*slot)?,
                    None => self.root,
                };
                let id = copy::named(parent, &name, self.work)?;
                if id.device() != self.root_identity.device() {
                    return Err(Failure::Binding);
                }
                match id.source_kind()? {
                    profile::Kind::Symlink => {
                        links += 1;
                        if links > 40 {
                            return Err(Failure::Links);
                        }
                        let next = link(parent, &name, id, self.work)?;
                        for item in next.split(|b| *b == b'/').rev() {
                            pending.push_front(item.to_vec());
                        }
                    }
                    profile::Kind::Directory => {
                        if stack.len() >= profile::DEPTH_LIMIT {
                            return Err(Failure::Bounds);
                        }
                        // Parent FD is borrowed from this same fixed table;
                        // copy its raw number before the mutable reserve/open.
                        let raw = parent.as_raw_fd();
                        let slot = files.open_source(
                            unsafe { BorrowedFd::borrow_raw(raw) },
                            &name,
                            id,
                            self.work,
                        )?;
                        stack.push((slot, id, part));
                    }
                    profile::Kind::Regular => {
                        if !pending.is_empty() {
                            return Err(Failure::Kind);
                        }
                    }
                }
            }
            // All directory ancestors retained for this resolver, compared
            // deepest-first BEFORE original closes, including alias/.. routes.
            for (offset, (slot, id, name)) in stack.iter().enumerate().rev() {
                let parent = if offset == 0 {
                    self.root
                } else {
                    files.fd(stack[offset - 1].0)?
                };
                let name = CString::new(name.as_slice()).map_err(|_| Failure::Links)?;
                copy::exact(files.fd(*slot)?, parent, &name, *id, self.work)?;
            }
            self.root_post()
        })();
        if observed.is_err() {
            files.note_failure();
        }
        let mut known = true;
        for (slot, _, _) in stack.into_iter().rev() {
            if files.close(slot).is_err() {
                known = false;
            }
        }
        if !known {
            return Err(Failure::Close);
        }
        observed
    }
    pub(crate) fn census(&self, files: &mut CopierFiles, allocation_unit: u64) -> Result<Census> {
        if files.unknown || files.first.is_some() {
            return Err(Failure::Binding);
        }
        let original_live = files.live();
        let result = self.census_inner(files, allocation_unit, original_live);
        if result.is_err() {
            files.note_failure();
        }
        result
    }
    fn census_inner(
        &self,
        files: &mut CopierFiles,
        allocation_unit: u64,
        original_live: usize,
    ) -> Result<Census> {
        let mut quote = profile::CopyQuote::new(allocation_unit).map_err(|_| Failure::Bounds)?;
        let mut digest = Sha256::new();
        digest.update(b"mrk-xcode-original-census/1\0");
        let mut budget = NameBudget { live: 0 };
        let mut parts = Vec::new();
        self.root_post()?;
        self.walk(
            self.root,
            self.root_parent,
            self.root_name,
            self.root_identity,
            &mut parts,
            files,
            &mut budget,
            &mut quote,
            &mut digest,
        )?;
        self.root_post()?;
        if budget.live != 0 || files.live() != original_live {
            return Err(Failure::Bounds);
        }
        Ok(Census {
            quote,
            digest: digest.finalize().into(),
        })
    }
    fn walk(
        &self,
        fd: BorrowedFd<'_>,
        parent: BorrowedFd<'_>,
        name: &CStr,
        id: Identity,
        parts: &mut Vec<Vec<u8>>,
        files: &mut CopierFiles,
        budget: &mut NameBudget,
        quote: &mut profile::CopyQuote,
        digest: &mut Sha256,
    ) -> Result<()> {
        let result = self.walk_inner(fd, parent, name, id, parts, files, budget, quote, digest);
        if result.is_err() {
            files.note_failure();
        }
        result
    }
    fn walk_inner(
        &self,
        fd: BorrowedFd<'_>,
        parent: BorrowedFd<'_>,
        name: &CStr,
        id: Identity,
        parts: &mut Vec<Vec<u8>>,
        files: &mut CopierFiles,
        budget: &mut NameBudget,
        quote: &mut profile::CopyQuote,
        digest: &mut Sha256,
    ) -> Result<()> {
        self.work.point()?;
        if id.device() != self.root_identity.device() {
            return Err(Failure::Binding);
        }
        let kind = if self.protected {
            id.protected_kind()?
        } else {
            id.source_kind()?
        };
        let bytes = copy::quote_visible_attributes(fd, parent, name, id, self.work)?;
        let path_bytes = parts.iter().map(|s| s.len() + 1).sum::<usize>().max(1);
        quote
            .add(profile::NodeSize {
                kind,
                data_bytes: id.logical_bytes()?,
                attribute_bytes: bytes,
                depth: parts.len(),
                path_bytes,
            })
            .map_err(|_| Failure::Bounds)?;
        digest.update((parts.len() as u32).to_be_bytes());
        for part in parts.iter() {
            digest.update((part.len() as u16).to_be_bytes());
            digest.update(part);
        }
        id.fold(digest);
        digest.update(bytes.to_be_bytes());
        match kind {
            profile::Kind::Regular => (),
            profile::Kind::Symlink => {
                let value = link(parent, name, id, self.work)?;
                digest.update((value.len() as u16).to_be_bytes());
                digest.update(&value);
                let parent_parts = &parts[..parts.len().checked_sub(1).ok_or(Failure::Links)?];
                self.confined_link(files, parent_parts, &value)?;
            }
            profile::Kind::Directory => {
                let rows = names(fd, id, budget, self.work)?;
                let observed = (|| -> Result<()> {
                    for row in &rows {
                        self.work.point()?;
                        if parts.len() >= profile::DEPTH_LIMIT
                            || path_bytes + row.key().len() + 1 > profile::PATH_LIMIT
                        {
                            return Err(Failure::Bounds);
                        }
                        let named = copy::named(fd, row.cstr()?, self.work)?;
                        row.matches(named)?;
                        let slot = files.open_source(fd, row.cstr()?, named, self.work)?;
                        parts.push(row.key().to_vec());
                        // All originals are still present; raw borrow cannot
                        // outlive this synchronous call or its positive close.
                        let raw = files.fd(slot)?.as_raw_fd();
                        let child = self.walk(
                            unsafe { BorrowedFd::borrow_raw(raw) },
                            fd,
                            row.cstr()?,
                            named,
                            parts,
                            files,
                            budget,
                            quote,
                            digest,
                        );
                        parts.pop();
                        let closed = files.close(slot);
                        if closed.is_err() {
                            return Err(Failure::Close);
                        }
                        child?;
                    }
                    copy::exact(fd, parent, name, id, self.work)
                })();
                budget.release(&rows);
                observed?;
            }
        }
        copy::exact(fd, parent, name, id, self.work)
    }
    /// Caller has already admitted signed source/ancestors and the original
    /// private pending wrapper and recorded empty Xcode.app original. Payload
    /// content starts only after a fresh full census and real free-space check.
    /// Result is provisional until Apple POST, all original closes and Parent.
    pub(crate) fn copy_to(
        &mut self,
        files: &mut CopierFiles,
        stage: BorrowedFd<'_>,
        stage_identity: Identity,
        recorded_device: u64,
        recorded_inode: u64,
        admitted: &Census,
    ) -> Result<SealedCopy> {
        if self.copy_started || self.protected {
            return Err(Failure::Binding);
        }
        self.copy_started = true;
        let original_live = files.live();
        let result = (|| -> Result<SealedCopy> {
            self.work.point()?;
            copy::private_stage(stage_identity)?;
            if copy::fstat(stage, self.work)? != stage_identity {
                return Err(Failure::Binding);
            }
            if self.census(files, admitted.quote.allocation_unit())? != *admitted {
                return Err(Failure::Binding);
            }
            let disk = statfs::fstatfs(stage).map_err(|_| Failure::Metadata)?;
            self.work.point()?;
            if disk.filesystem_type_name() != "apfs"
                || !disk.flags().contains(MntFlags::MNT_LOCAL)
                || disk.flags().intersects(
                    MntFlags::MNT_UNION
                        | MntFlags::MNT_AUTOMOUNTED
                        | MntFlags::MNT_IGNORE_OWNERSHIP,
                )
            {
                return Err(Failure::Access);
            }
            if u64::from(disk.block_size()) != admitted.quote.allocation_unit() {
                return Err(Failure::Bounds);
            }
            let available = disk
                .blocks_available()
                .checked_mul(u64::from(disk.block_size()))
                .ok_or(Failure::Bounds)?;
            admitted
                .quote
                .admit_space(available)
                .map_err(|_| Failure::Bounds)?;
            if copy::fstat(stage, self.work)? != stage_identity {
                return Err(Failure::Binding);
            }
            let created = copy::named(stage, c"Xcode.app", self.work)?;
            copy::private_stage(created)?;
            if created.device() as u64 != recorded_device || created.inode() != recorded_inode {
                return Err(Failure::Binding);
            }
            // Open the pre-reserved root without creating/replacing it. Mode
            // 0700 is intentionally private, not a source/public tree claim.
            let slot = files.open_reserved_root(stage, created, self.work)?;
            let mut empty_budget = NameBudget { live: 0 };
            let rows = names(files.fd(slot)?, created, &mut empty_budget, self.work)?;
            let empty = rows.is_empty();
            empty_budget.release(&rows);
            if !empty {
                return Err(Failure::Binding);
            }
            let output_raw = files.fd(slot)?.as_raw_fd();
            let output = unsafe { BorrowedFd::borrow_raw(output_raw) };
            let mut budget = NameBudget { live: 0 };
            let mut parts = Vec::new();
            let mut source_quote = profile::CopyQuote::new(admitted.quote.allocation_unit())
                .map_err(|_| Failure::Bounds)?;
            let mut digest = Sha256::new();
            digest.update(b"mrk-xcode-sealed-copy/1\0");
            let sealed = self.copy_walk(
                self.root,
                self.root_parent,
                self.root_name,
                self.root_identity,
                output,
                stage,
                c"Xcode.app",
                created,
                files,
                &mut budget,
                &mut parts,
                &mut source_quote,
                &mut digest,
            )?;
            if source_quote != admitted.quote
                || budget.live != 0
                || files.live() != original_live + 1
            {
                return Err(Failure::Binding);
            }
            let first: [u8; 32] = digest.finalize().into();
            if self.census(files, admitted.quote.allocation_unit())? != *admitted {
                return Err(Failure::Binding);
            }
            let mut final_digest = Sha256::new();
            final_digest.update(b"mrk-xcode-sealed-copy/1\0");
            self.verify_walk(
                self.root,
                self.root_parent,
                self.root_name,
                self.root_identity,
                output,
                stage,
                c"Xcode.app",
                sealed,
                files,
                &mut budget,
                &mut parts,
                &mut final_digest,
            )?;
            let second: [u8; 32] = final_digest.finalize().into();
            if first != second || budget.live != 0 || files.live() != original_live + 1 {
                return Err(Failure::Binding);
            }
            if self.census(files, admitted.quote.allocation_unit())? != *admitted {
                return Err(Failure::Binding);
            }
            copy::exact(output, stage, c"Xcode.app", sealed, self.work)?;
            native::sync(stage, false).map_err(|_| Failure::Sync)?;
            self.work.point()?;
            Ok(SealedCopy {
                slot,
                identity: sealed,
                digest: second,
            })
        })();
        if result.is_err() {
            files.note_failure();
        }
        result
    }
    fn fold_output(parts: &[Vec<u8>], id: Identity, digest: &mut Sha256) {
        digest.update((parts.len() as u32).to_be_bytes());
        for part in parts {
            digest.update((part.len() as u16).to_be_bytes());
            digest.update(part);
        }
        id.fold(digest);
    }
    fn copy_walk(
        &self,
        source: BorrowedFd<'_>,
        source_parent: BorrowedFd<'_>,
        source_name: &CStr,
        source_id: Identity,
        output: BorrowedFd<'_>,
        output_parent: BorrowedFd<'_>,
        output_name: &CStr,
        created: Identity,
        files: &mut CopierFiles,
        budget: &mut NameBudget,
        parts: &mut Vec<Vec<u8>>,
        quote: &mut profile::CopyQuote,
        digest: &mut Sha256,
    ) -> Result<Identity> {
        let result = (|| -> Result<Identity> {
            self.work.point()?;
            if source_id.device() != self.root_identity.device() {
                return Err(Failure::Binding);
            }
            let kind = source_id.source_kind()?;
            let attrs = copy::quote_visible_attributes(
                source,
                source_parent,
                source_name,
                source_id,
                self.work,
            )?;
            let path_bytes = parts.iter().map(|p| p.len() + 1).sum::<usize>().max(1);
            quote
                .add(profile::NodeSize {
                    kind,
                    data_bytes: source_id.logical_bytes()?,
                    attribute_bytes: attrs,
                    depth: parts.len(),
                    path_bytes,
                })
                .map_err(|_| Failure::Bounds)?;
            let sealed = match kind {
                profile::Kind::Regular => {
                    if source_name != output_name {
                        return Err(Failure::Binding);
                    }
                    let mut pair = copy::RegularPair::admit(
                        source,
                        source_parent,
                        output,
                        output_parent,
                        source_name,
                        source_id,
                        self.work,
                    )?;
                    pair.copy_data_once()?;
                    pair.verify_data_once()?;
                    pair.copy_verify_attributes_once(attrs)?;
                    pair.seal_once()?
                }
                profile::Kind::Symlink => {
                    if source_name != output_name {
                        return Err(Failure::Binding);
                    }
                    copy::verify_new_symlink(
                        source,
                        source_parent,
                        output,
                        output_parent,
                        source_name,
                        source_id,
                        self.work,
                    )?
                }
                profile::Kind::Directory => {
                    let mut pair = copy::DirectoryPair::created(
                        source,
                        source_parent,
                        output,
                        output_parent,
                        source_name,
                        output_name,
                        source_id,
                        created,
                        self.work,
                    )?;
                    let rows = names(source, source_id, budget, self.work)?;
                    let observed = (|| -> Result<()> {
                        for row in &rows {
                            self.work.point()?;
                            if parts.len() >= profile::DEPTH_LIMIT
                                || path_bytes + row.key().len() + 1 > profile::PATH_LIMIT
                            {
                                return Err(Failure::Bounds);
                            }
                            let name = row.cstr()?;
                            let id = copy::named(source, name, self.work)?;
                            row.matches(id)?;
                            let source_slot = files.open_source(source, name, id, self.work)?;
                            let mut output_slot = None;
                            let copied = (|| -> Result<()> {
                                let target = if id.source_kind()? == profile::Kind::Symlink {
                                    Some(link(source, name, id, self.work)?)
                                } else {
                                    None
                                };
                                let (slot, created) = files.create_output(
                                    output,
                                    name,
                                    id.source_kind()?,
                                    target.as_deref(),
                                    self.work,
                                )?;
                                output_slot = Some(slot);
                                let left = files.fd(source_slot)?.as_raw_fd();
                                let right = files.fd(slot)?.as_raw_fd();
                                parts.push(row.key().to_vec());
                                let copied = self.copy_walk(
                                    unsafe { BorrowedFd::borrow_raw(left) },
                                    source,
                                    name,
                                    id,
                                    unsafe { BorrowedFd::borrow_raw(right) },
                                    output,
                                    name,
                                    created,
                                    files,
                                    budget,
                                    parts,
                                    quote,
                                    digest,
                                );
                                parts.pop();
                                copied.map(|_| ())
                            })();
                            if copied.is_err() {
                                files.note_failure();
                            }
                            let output_closed =
                                output_slot.map_or(Ok(()), |slot| files.close(slot));
                            let source_closed = files.close(source_slot);
                            if output_closed.is_err() || source_closed.is_err() {
                                return Err(Failure::Close);
                            }
                            copied?;
                        }
                        copy::exact(source, source_parent, source_name, source_id, self.work)
                    })();
                    budget.release(&rows);
                    observed?;
                    pair.finish_once(attrs)?
                }
            };
            copy::sealed_output(source_id, sealed)?;
            copy::exact(source, source_parent, source_name, source_id, self.work)?;
            copy::exact(output, output_parent, output_name, sealed, self.work)?;
            Self::fold_output(parts, sealed, digest);
            Ok(sealed)
        })();
        if result.is_err() {
            files.note_failure();
        }
        result
    }
    fn verify_walk(
        &self,
        source: BorrowedFd<'_>,
        source_parent: BorrowedFd<'_>,
        source_name: &CStr,
        source_id: Identity,
        output: BorrowedFd<'_>,
        output_parent: BorrowedFd<'_>,
        output_name: &CStr,
        output_id: Identity,
        files: &mut CopierFiles,
        budget: &mut NameBudget,
        parts: &mut Vec<Vec<u8>>,
        digest: &mut Sha256,
    ) -> Result<()> {
        let result = (|| -> Result<()> {
            self.work.point()?;
            if source_id.device() != self.root_identity.device() {
                return Err(Failure::Binding);
            }
            let attrs = copy::quote_visible_attributes(
                source,
                source_parent,
                source_name,
                source_id,
                self.work,
            )?;
            copy::verify_sealed_pair(
                source,
                source_parent,
                source_name,
                source_id,
                output,
                output_parent,
                output_name,
                output_id,
                attrs,
                self.work,
            )?;
            if source_id.source_kind()? == profile::Kind::Directory {
                let left = names(source, source_id, budget, self.work)?;
                let observed = (|| -> Result<()> {
                    let right = names(output, output_id, budget, self.work)?;
                    let observed = (|| -> Result<()> {
                        if left.len() != right.len()
                            || left
                                .iter()
                                .zip(&right)
                                .any(|(a, b)| a.key() != b.key() || a.kind != b.kind)
                        {
                            return Err(Failure::Binding);
                        }
                        for (row, output_row) in left.iter().zip(&right) {
                            if parts.len() >= profile::DEPTH_LIMIT
                                || parts.iter().map(|p| p.len() + 1).sum::<usize>()
                                    + row.key().len()
                                    + 1
                                    > profile::PATH_LIMIT
                            {
                                return Err(Failure::Bounds);
                            }
                            let name = row.cstr()?;
                            let id = copy::named(source, name, self.work)?;
                            row.matches(id)?;
                            let out_id = copy::named(output, name, self.work)?;
                            output_row.matches(out_id)?;
                            let source_slot = files.open_source(source, name, id, self.work)?;
                            let mut output_slot = None;
                            let checked = (|| -> Result<()> {
                                let slot =
                                    files.open_output(output, name, id, out_id, self.work)?;
                                output_slot = Some(slot);
                                let l = files.fd(source_slot)?.as_raw_fd();
                                let r = files.fd(slot)?.as_raw_fd();
                                parts.push(row.key().to_vec());
                                let checked = self.verify_walk(
                                    unsafe { BorrowedFd::borrow_raw(l) },
                                    source,
                                    name,
                                    id,
                                    unsafe { BorrowedFd::borrow_raw(r) },
                                    output,
                                    name,
                                    out_id,
                                    files,
                                    budget,
                                    parts,
                                    digest,
                                );
                                parts.pop();
                                checked
                            })();
                            if checked.is_err() {
                                files.note_failure();
                            }
                            let oc = output_slot.map_or(Ok(()), |slot| files.close(slot));
                            let sc = files.close(source_slot);
                            if oc.is_err() || sc.is_err() {
                                return Err(Failure::Close);
                            }
                            checked?;
                        }
                        Ok(())
                    })();
                    budget.release(&right);
                    observed
                })();
                budget.release(&left);
                observed?;
            }
            copy::exact(source, source_parent, source_name, source_id, self.work)?;
            copy::exact(output, output_parent, output_name, output_id, self.work)?;
            Self::fold_output(parts, output_id, digest);
            Ok(())
        })();
        if result.is_err() {
            files.note_failure();
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        os::{
            fd::{AsFd, OwnedFd},
            unix::fs::{symlink, PermissionsExt},
        },
    };
    fn error(failure: Failure) -> std::io::Error {
        std::io::Error::other(format!("{failure:?}"))
    }
    // Genuine tiny APFS originals, no Apple signature, Installer, privilege,
    // source execution or final-copy authority is mocked or inferred here.
    #[test]
    fn source_census_accounts_for_originals_links_and_same_size_file_drift() {
        let root = std::env::temp_dir().join(format!(
            "mrk-xcode-census-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&root).unwrap();
        let end = Instant::now() + std::time::Duration::from_secs(30);
        let work = Work {
            end,
            parent: unsafe { libc::getppid() },
        };
        let mut files = CopierFiles::new(end + std::time::Duration::from_secs(5), 2).unwrap();
        let mut inputs: Vec<OwnedFd> = Vec::new();
        let observed = (|| -> std::result::Result<(Census, Census), Box<dyn std::error::Error>> {
            let app = root.join("Xcode.app");
            fs::create_dir_all(app.join("Versions/A"))?;
            for p in [&app, &app.join("Versions"), &app.join("Versions/A")] {
                fs::set_permissions(p, fs::Permissions::from_mode(0o755))?;
            }
            fs::write(app.join("Versions/A/tool"), b"old")?;
            fs::set_permissions(
                app.join("Versions/A/tool"),
                fs::Permissions::from_mode(0o644),
            )?;
            symlink("A", app.join("Versions/Current"))?;
            inputs.push(fs::File::open(&root)?.into());
            inputs.push(fs::File::open(&app)?.into());
            let name = c"Xcode.app";
            let id = copy::fstat(inputs[1].as_fd(), &work).map_err(error)?;
            let tree = SourceTree::original(inputs[1].as_fd(), inputs[0].as_fd(), name, id, &work)
                .map_err(error)?;
            let first = tree.census(&mut files, 4096).map_err(error)?;
            fs::write(app.join("Versions/A/tool"), b"new")?;
            fs::File::open(app.join("Versions/A/tool"))?
                .set_modified(std::time::SystemTime::now() + std::time::Duration::from_secs(1))?;
            let second = tree.census(&mut files, 4096).map_err(error)?;
            Ok((first, second))
        })();
        if observed.is_err() {
            files.note_failure();
        }
        let children_closed = files.close_all();
        let mut inputs_closed = true;
        for fd in inputs.into_iter().rev() {
            inputs_closed &= nix::unistd::close(fd).is_ok();
        }
        let cleanup = fs::remove_dir_all(&root);
        assert!(
            children_closed && inputs_closed,
            "original close unconfirmed"
        );
        assert!(cleanup.is_ok(), "temporary tree cleanup failed");
        let (first, second) = observed.expect("actual bounded source census");
        assert_eq!(first.quote.entries(), 5);
        assert_eq!(first.quote.logical_bytes(), 4);
        assert_eq!(first.quote, second.quote);
        assert_ne!(first.digest, second.digest);
    }
    #[test]
    fn source_census_rejects_ordered_alias_escape_and_leaves_no_output() {
        let root = std::env::temp_dir().join(format!(
            "mrk-xcode-escape-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&root).unwrap();
        let end = Instant::now() + std::time::Duration::from_secs(30);
        let work = Work {
            end,
            parent: unsafe { libc::getppid() },
        };
        let mut files = CopierFiles::new(end + std::time::Duration::from_secs(5), 2).unwrap();
        let mut inputs: Vec<OwnedFd> = Vec::new();
        let observed = (|| -> std::result::Result<Result<Census>, Box<dyn std::error::Error>> {
            let app = root.join("Xcode.app");
            fs::create_dir_all(app.join("Versions/A"))?;
            for p in [&app, &app.join("Versions"), &app.join("Versions/A")] {
                fs::set_permissions(p, fs::Permissions::from_mode(0o755))?;
            }
            symlink("A", app.join("Versions/Current"))?;
            symlink("Versions/Current/../../../outside", app.join("bad"))?;
            inputs.push(fs::File::open(&root)?.into());
            inputs.push(fs::File::open(&app)?.into());
            let id = copy::fstat(inputs[1].as_fd(), &work).map_err(error)?;
            let tree = SourceTree::original(
                inputs[1].as_fd(),
                inputs[0].as_fd(),
                c"Xcode.app",
                id,
                &work,
            )
            .map_err(error)?;
            Ok(tree.census(&mut files, 4096))
        })();
        if !matches!(&observed, Ok(Ok(_))) {
            files.note_failure();
        }
        let children_closed = files.close_all();
        let mut inputs_closed = true;
        for fd in inputs.into_iter().rev() {
            inputs_closed &= nix::unistd::close(fd).is_ok();
        }
        let exact_names = fs::read_dir(&root).and_then(|rows| {
            rows.map(|r| r.map(|e| e.file_name()))
                .collect::<std::io::Result<Vec<_>>>()
        });
        let cleanup = fs::remove_dir_all(&root);
        assert!(
            children_closed && inputs_closed,
            "original close unconfirmed"
        );
        assert!(cleanup.is_ok(), "temporary tree cleanup failed");
        assert_eq!(
            exact_names.unwrap(),
            vec![std::ffi::OsString::from("Xcode.app")]
        );
        assert!(matches!(observed, Ok(Err(Failure::Links))), "{observed:?}");
    }
}
