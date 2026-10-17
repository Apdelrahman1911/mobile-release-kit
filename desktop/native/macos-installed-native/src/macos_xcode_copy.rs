//! Fixed setup copier primitives. Not an application API or a path-based copier.
//!
//! Only the separate setup child may borrow its actual tracked originals here.
//! The Parent/child admission, full census, xattrs, Apple verification and sole
//! Parent publication are separate required joins. This file is not registered
//! or callable in any product target until those joins exist.
#![cfg(all(
    target_os = "macos",
    target_pointer_width = "64",
    any(target_arch = "aarch64", target_arch = "x86_64")
))]

use super::macos_xcode_setup as profile;
use crate as native;
use nix::libc;
use std::{
    ffi::CStr,
    os::fd::{AsRawFd, BorrowedFd},
    time::Instant,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Failure {
    Deadline,
    Parent,
    Metadata,
    Binding,
    Kind,
    Access,
    Bounds,
    Read,
    Write,
    Sync,
    NativeObject,
    Attributes,
    Close,
    Links,
}
pub(crate) type Result<T> = std::result::Result<T, Failure>;

/// Copied from the genuine Parent's original absolute endpoint by the private
/// authenticated child handoff, never derived from a fresh duration here.
pub(crate) struct Work {
    pub(crate) end: Instant,
    pub(crate) parent: libc::pid_t,
}
impl Work {
    pub(crate) fn point(&self) -> Result<()> {
        if Instant::now() >= self.end {
            return Err(Failure::Deadline);
        }
        if self.parent <= 1 || unsafe { libc::getppid() } != self.parent {
            return Err(Failure::Parent);
        }
        Ok(())
    }
}

/// Whole original stat binding: timestamps and flags are not normalized away.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Identity {
    dev: libc::dev_t,
    ino: libc::ino_t,
    mode: libc::mode_t,
    links: libc::nlink_t,
    uid: libc::uid_t,
    gid: libc::gid_t,
    size: libc::off_t,
    flags: u32,
    mtime: libc::time_t,
    mtime_ns: libc::c_long,
    ctime: libc::time_t,
    ctime_ns: libc::c_long,
}
impl Identity {
    pub(crate) fn of(s: &libc::stat) -> Self {
        Self {
            dev: s.st_dev,
            ino: s.st_ino,
            mode: s.st_mode,
            links: s.st_nlink,
            uid: s.st_uid,
            gid: s.st_gid,
            size: s.st_size,
            flags: s.st_flags,
            mtime: s.st_mtime,
            mtime_ns: s.st_mtime_nsec,
            ctime: s.st_ctime,
            ctime_ns: s.st_ctime_nsec,
        }
    }
    fn source_regular(&self) -> Result<u32> {
        if self.dev < 0
            || self.ino == 0
            || self.size < 0
            || self.size as u64 > profile::FILE_LIMIT
            || !(0..1_000_000_000).contains(&self.mtime_ns)
            || !(0..1_000_000_000).contains(&self.ctime_ns)
        {
            return Err(Failure::Metadata);
        }
        // UF_COMPRESSED changes physical storage only; ordinary pread exposes
        // the logical bytes. Do not paste its hidden encoding onto a new file.
        if self.flags & !libc::UF_COMPRESSED != 0 {
            return Err(Failure::Metadata);
        }
        profile::copied_mode(
            profile::Kind::Regular,
            u32::from(self.mode),
            u64::from(self.links),
        )
        .map_err(|_| Failure::Access)?
        .ok_or(Failure::Kind)
    }
    pub(crate) fn source_kind(&self) -> Result<profile::Kind> {
        if self.dev < 0
            || self.ino == 0
            || self.size < 0
            || self.links == 0
            || !(0..1_000_000_000).contains(&self.mtime_ns)
            || !(0..1_000_000_000).contains(&self.ctime_ns)
        {
            return Err(Failure::Metadata);
        }
        let kind = match self.mode & libc::S_IFMT {
            libc::S_IFREG => {
                self.source_regular()?;
                profile::Kind::Regular
            }
            libc::S_IFDIR => {
                if self.flags != 0 {
                    return Err(Failure::Metadata);
                }
                profile::Kind::Directory
            }
            libc::S_IFLNK => {
                if self.flags != 0 || !(1..=profile::LINK_LIMIT as i64).contains(&self.size) {
                    return Err(Failure::Metadata);
                }
                profile::Kind::Symlink
            }
            _ => return Err(Failure::Kind),
        };
        profile::copied_mode(kind, u32::from(self.mode), u64::from(self.links))
            .map_err(|_| Failure::Access)?;
        Ok(kind)
    }
    /// Only actual private output inodes qualify for fixed-stage retirement.
    /// Private unfinished 0600/0700 modes are not public source admission.
    pub(crate) fn retiring_kind(self) -> Result<profile::Kind> {
        if self.dev <= 0
            || self.ino == 0
            || self.uid != 0
            || self.gid != 0
            || self.flags != 0
            || self.size < 0
            || self.mode & 0o7000 != 0
        {
            return Err(Failure::Access);
        }
        match self.mode & libc::S_IFMT {
            libc::S_IFDIR if matches!(self.mode & 0o777, 0o700 | 0o555) => {
                Ok(profile::Kind::Directory)
            }
            libc::S_IFREG
                if self.links == 1
                    && matches!(self.mode & 0o777, 0o600 | 0o444 | 0o555)
                    && self.size as u64 <= profile::FILE_LIMIT =>
            {
                Ok(profile::Kind::Regular)
            }
            libc::S_IFLNK
                if self.links == 1
                    && profile::copied_mode(
                        profile::Kind::Symlink,
                        u32::from(self.mode),
                        u64::from(self.links),
                    )
                    .is_ok()
                    && (1..=profile::LINK_LIMIT as i64).contains(&self.size) =>
            {
                Ok(profile::Kind::Symlink)
            }
            _ => Err(Failure::Kind),
        }
    }
    /// Current managed payload must match actual sealed-output metadata;
    /// unfinished private modes are never admitted as a prepared toolchain.
    pub(crate) fn protected_kind(self) -> Result<profile::Kind> {
        let kind = self.retiring_kind()?;
        let expected = profile::copied_mode(kind, u32::from(self.mode), u64::from(self.links))
            .map_err(|_| Failure::Access)?;
        if expected.is_some_and(|mode| mode != u32::from(self.mode & 0o7777)) {
            return Err(Failure::Access);
        }
        Ok(kind)
    }
    pub(crate) fn same_owned_directory(self, other: Self) -> bool {
        self.mode & libc::S_IFMT == libc::S_IFDIR && self.same_retired_inode(other)
    }
    pub(crate) fn same_retired_inode(self, other: Self) -> bool {
        self.dev == other.dev
            && self.ino == other.ino
            && self.mode == other.mode
            && self.uid == other.uid
            && self.gid == other.gid
            && self.flags == other.flags
    }
    pub(crate) fn device(self) -> libc::dev_t {
        self.dev
    }
    pub(crate) fn inode(self) -> libc::ino_t {
        self.ino
    }
    pub(crate) fn logical_bytes(self) -> Result<u64> {
        Ok(if self.source_kind()? == profile::Kind::Directory {
            0
        } else {
            self.size as u64
        })
    }
    pub(crate) fn fold(self, digest: &mut sha2::Sha256) {
        use sha2::Digest;
        // Typed fixed-width original stat fields, never native struct padding.
        digest.update(self.dev.to_be_bytes());
        digest.update(self.ino.to_be_bytes());
        digest.update(self.mode.to_be_bytes());
        digest.update(self.links.to_be_bytes());
        digest.update(self.uid.to_be_bytes());
        digest.update(self.gid.to_be_bytes());
        digest.update(self.size.to_be_bytes());
        digest.update(self.flags.to_be_bytes());
        digest.update(self.mtime.to_be_bytes());
        digest.update(self.mtime_ns.to_be_bytes());
        digest.update(self.ctime.to_be_bytes());
        digest.update(self.ctime_ns.to_be_bytes());
    }
    fn output_regular(&self, source: Self) -> Result<()> {
        if self.dev < 0
            || self.ino == 0
            || self.uid != 0
            || self.gid != 0
            || self.links != 1
            || self.mode != libc::S_IFREG | 0o600
            || self.size != 0
            || self.flags != 0
            || self.dev == source.dev && self.ino == source.ino
        {
            return Err(Failure::Metadata);
        }
        Ok(())
    }
    /// Only the private exclusive output's data/timestamps may change here.
    fn same_output_object(self, next: Self) -> bool {
        (
            self.dev, self.ino, self.mode, self.links, self.uid, self.gid, self.flags,
        ) == (
            next.dev, next.ino, next.mode, next.links, next.uid, next.gid, next.flags,
        )
    }
}

pub(crate) fn fstat(fd: BorrowedFd<'_>, work: &Work) -> Result<Identity> {
    work.point()?;
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(fd.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
        return Err(Failure::Metadata);
    }
    work.point()?;
    Ok(Identity::of(&unsafe { stat.assume_init() }))
}
pub(crate) fn named(parent: BorrowedFd<'_>, name: &CStr, work: &Work) -> Result<Identity> {
    if !profile::component(name.to_bytes()) {
        return Err(Failure::Bounds);
    }
    work.point()?;
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(Failure::Metadata);
    }
    work.point()?;
    Ok(Identity::of(&unsafe { stat.assume_init() }))
}
pub(crate) fn exact(
    fd: BorrowedFd<'_>,
    parent: BorrowedFd<'_>,
    name: &CStr,
    expected: Identity,
    work: &Work,
) -> Result<()> {
    if fstat(fd, work)? != expected || named(parent, name, work)? != expected {
        return Err(Failure::Binding);
    }
    Ok(())
}
pub(crate) fn empty_acl(fd: BorrowedFd<'_>, work: &Work) -> Result<()> {
    work.point()?;
    // A filesec/ACL failure, including failed native free, is not invented
    // positive closure. The child retains fatal state and cannot complete.
    native::empty_acl(fd).map_err(|_| Failure::NativeObject)?;
    work.point()
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Ready,
    Copying,
    Copied,
    Verifying,
    Verified,
    Attributes,
    AttributesVerified,
    Sealing,
    Sealed,
}

/// Capture an actual readable original before the caller debits its census.
/// The caller still owns its pre-open slot and every ancestor/named join.
pub(crate) fn observe_source_regular(
    fd: BorrowedFd<'_>,
    parent: BorrowedFd<'_>,
    name: &CStr,
    work: &Work,
) -> Result<Identity> {
    let original = fstat(fd, work)?;
    original.source_regular()?;
    exact(fd, parent, name, original, work)?;
    empty_acl(fd, work)?;
    exact(fd, parent, name, original, work)?;
    Ok(original)
}

/// One same-name source/output pair. Both descriptors were acquired and remain
/// retained by the actual child owner; no dup, open, hidden Drop or FD close is
/// performed here. Source comparison includes every original metadata field.
/// Output must be a NEW private0600 regular file, never an existing destination.
pub(crate) struct RegularPair<'a> {
    source: BorrowedFd<'a>,
    source_parent: BorrowedFd<'a>,
    output: BorrowedFd<'a>,
    output_parent: BorrowedFd<'a>,
    name: &'a CStr,
    source_identity: Identity,
    output_identity: Identity,
    mode: u32,
    phase: Phase,
    work: &'a Work,
}
impl<'a> RegularPair<'a> {
    pub(crate) fn admit(
        source: BorrowedFd<'a>,
        source_parent: BorrowedFd<'a>,
        output: BorrowedFd<'a>,
        output_parent: BorrowedFd<'a>,
        name: &'a CStr,
        expected_source: Identity,
        work: &'a Work,
    ) -> Result<Self> {
        let mode = expected_source.source_regular()?;
        exact(source, source_parent, name, expected_source, work)?;
        empty_acl(source, work)?;
        exact(source, source_parent, name, expected_source, work)?;
        let output_identity = fstat(output, work)?;
        output_identity.output_regular(expected_source)?;
        exact(output, output_parent, name, output_identity, work)?;
        empty_acl(output, work)?;
        exact(output, output_parent, name, output_identity, work)?;
        Ok(Self {
            source,
            source_parent,
            output,
            output_parent,
            name,
            source_identity: expected_source,
            output_identity,
            mode,
            phase: Phase::Ready,
            work,
        })
    }
    fn source_post(&self, work: &Work) -> Result<()> {
        exact(
            self.source,
            self.source_parent,
            self.name,
            self.source_identity,
            work,
        )
    }
    fn output_post(&self, expected_size: u64, work: &Work) -> Result<()> {
        let actual = fstat(self.output, work)?;
        if !self.output_identity.same_output_object(actual)
            || actual.size < 0
            || actual.size as u64 != expected_size
            || named(self.output_parent, self.name, work)? != actual
        {
            return Err(Failure::Binding);
        }
        Ok(())
    }
    /// Bounded logical stream, not opaque copyfile(XATTR) allocation or clone.
    /// On any failure the one-use state remains consumed; no retry or refund.
    pub(crate) fn copy_data_once(&mut self) -> Result<()> {
        if self.phase != Phase::Ready {
            return Err(Failure::Binding);
        }
        self.phase = Phase::Copying;
        let work = self.work;
        self.source_post(work)?;
        self.output_post(0, work)?;
        let mut buffer = [0u8; 65536];
        let size = self.source_identity.size as u64;
        let mut offset = 0u64;
        while offset < size {
            work.point()?;
            let wanted = usize::try_from((size - offset).min(buffer.len() as u64))
                .map_err(|_| Failure::Bounds)?;
            let got = unsafe {
                libc::pread(
                    self.source.as_raw_fd(),
                    buffer.as_mut_ptr().cast(),
                    wanted,
                    offset as libc::off_t,
                )
            };
            if got <= 0 || got as usize > wanted {
                return Err(Failure::Read);
            }
            work.point()?;
            let mut written = 0usize;
            while written < got as usize {
                work.point()?;
                let n = unsafe {
                    libc::pwrite(
                        self.output.as_raw_fd(),
                        buffer[written..got as usize].as_ptr().cast(),
                        got as usize - written,
                        (offset + written as u64) as libc::off_t,
                    )
                };
                if n <= 0 || n as usize > got as usize - written {
                    return Err(Failure::Write);
                }
                written += n as usize;
                work.point()?;
            }
            offset += got as u64;
            self.source_post(work)?;
            self.output_post(offset, work)?;
        }
        work.point()?;
        if unsafe {
            libc::pread(
                self.source.as_raw_fd(),
                buffer.as_mut_ptr().cast(),
                1,
                size as libc::off_t,
            )
        } != 0
        {
            return Err(Failure::Read);
        }
        self.source_post(work)?;
        self.output_post(size, work)?;
        self.phase = Phase::Copied;
        // Data only: no completeness claim before exact attrs, normalization,
        // source census, final Apple check and the child's consuming closes.
        Ok(())
    }
    pub(crate) fn verify_data_once(&mut self) -> Result<()> {
        if self.phase != Phase::Copied {
            return Err(Failure::Binding);
        }
        self.phase = Phase::Verifying;
        let work = self.work;
        self.source_post(work)?;
        let size = self.source_identity.size as u64;
        self.output_post(size, work)?;
        let (mut left, mut right) = ([0u8; 65536], [0u8; 65536]);
        let mut offset = 0u64;
        while offset < size {
            let wanted = (size - offset).min(left.len() as u64) as usize;
            for (fd, buffer) in [(self.source, &mut left), (self.output, &mut right)] {
                let mut read = 0usize;
                while read < wanted {
                    work.point()?;
                    let n = unsafe {
                        libc::pread(
                            fd.as_raw_fd(),
                            buffer[read..wanted].as_mut_ptr().cast(),
                            wanted - read,
                            (offset + read as u64) as libc::off_t,
                        )
                    };
                    if n <= 0 || n as usize > wanted - read {
                        return Err(Failure::Read);
                    }
                    read += n as usize;
                    work.point()?;
                }
            }
            if left[..wanted] != right[..wanted] {
                return Err(Failure::Binding);
            }
            offset += wanted as u64;
            self.source_post(work)?;
            self.output_post(size, work)?;
        }
        self.source_post(work)?;
        self.output_post(size, work)?;
        self.phase = Phase::Verified;
        Ok(())
    }
    pub(crate) fn copied_mode(&self) -> u32 {
        self.mode
    }
}

// Fixed per-node workspace. Its four1MiB byte buffers plus two bounded index
// tables are included in the copier's pre-effect owned-memory quote (24MiB).
// No size-only native result is ever used to allocate a later mutable value.
const ATTRIBUTE_WORK_BYTES: usize = 24 * 1024 * 1024;
struct Names {
    bytes: Vec<u8>,
    ranges: Vec<(usize, usize)>,
}
fn buffer() -> Result<Vec<u8>> {
    let mut value = Vec::new();
    value
        .try_reserve_exact(profile::ATTRIBUTE_LIMIT as usize)
        .map_err(|_| Failure::Bounds)?;
    value.resize(profile::ATTRIBUTE_LIMIT as usize, 0);
    Ok(value)
}
fn attribute_name(name: &[u8]) -> bool {
    // Security/ACL-bearing attributes are unsupported rather than copied as
    // public data. Compression storage is hidden by flags0; if exposed, refuse.
    !name.is_empty()
        && name.len() <= 127
        && !name.contains(&0)
        && !name.starts_with(b"com.apple.system.")
        && !matches!(
            name,
            b"com.apple.macl" | b"com.apple.rootless" | b"com.apple.decmpfs"
        )
}
impl Names {
    fn read(fd: BorrowedFd<'_>, work: &Work) -> Result<Self> {
        let mut bytes = buffer()?;
        work.point()?;
        let used =
            unsafe { libc::flistxattr(fd.as_raw_fd(), bytes.as_mut_ptr().cast(), bytes.len(), 0) };
        work.point()?;
        if used < 0 || used as usize > bytes.len() {
            return Err(Failure::Attributes);
        }
        bytes.truncate(used as usize);
        let count = bytes.iter().filter(|b| **b == 0).count();
        if count > profile::ATTRIBUTE_LIMIT as usize / 2 {
            return Err(Failure::Bounds);
        }
        let mut ranges = Vec::new();
        // Actual cell count is known before the sole index allocation. No
        // geometric-growth optimism or per-name realloc loop.
        ranges
            .try_reserve_exact(count)
            .map_err(|_| Failure::Bounds)?;
        let mut start = 0;
        while start < bytes.len() {
            work.point()?;
            let length = bytes[start..]
                .iter()
                .position(|b| *b == 0)
                .ok_or(Failure::Attributes)?;
            if !attribute_name(&bytes[start..start + length]) {
                return Err(Failure::Attributes);
            }
            // Nonempty names consume at least2bytes. Reserve actual index cells
            // before insertion; buffers+both worst-case indices stay below24MiB.
            if ranges.len() >= profile::ATTRIBUTE_LIMIT as usize / 2 {
                return Err(Failure::Bounds);
            }
            ranges.push((start, start + length + 1));
            start += length + 1;
        }
        ranges.sort_unstable_by(|a, b| bytes[a.0..a.1].cmp(&bytes[b.0..b.1]));
        work.point()?;
        if ranges
            .windows(2)
            .any(|w| bytes[w[0].0..w[0].1] == bytes[w[1].0..w[1].1])
        {
            return Err(Failure::Attributes);
        }
        Ok(Self { bytes, ranges })
    }
    fn key(&self, index: usize) -> Result<&CStr> {
        let (start, end) = *self.ranges.get(index).ok_or(Failure::Bounds)?;
        CStr::from_bytes_with_nul(&self.bytes[start..end]).map_err(|_| Failure::Attributes)
    }
    fn equal(&self, other: &Self) -> bool {
        self.ranges.len() == other.ranges.len()
            && self
                .ranges
                .iter()
                .zip(&other.ranges)
                .all(|(a, b)| self.bytes[a.0..a.1] == other.bytes[b.0..b.1])
    }
    fn quoted_bytes(&self, fd: BorrowedFd<'_>, work: &Work) -> Result<u64> {
        let mut total = self.bytes.len() as u64;
        for index in 0..self.ranges.len() {
            work.point()?;
            let size = unsafe {
                libc::fgetxattr(
                    fd.as_raw_fd(),
                    self.key(index)?.as_ptr(),
                    std::ptr::null_mut(),
                    0,
                    0,
                    0,
                )
            };
            work.point()?;
            if size < 0 {
                return Err(Failure::Attributes);
            }
            total = total
                .checked_add(size as u64)
                .filter(|n| *n <= profile::ATTRIBUTE_LIMIT)
                .ok_or(Failure::Bounds)?;
        }
        Ok(total)
    }
}
fn attribute(fd: BorrowedFd<'_>, name: &CStr, value: &mut [u8], work: &Work) -> Result<usize> {
    work.point()?;
    let size = unsafe {
        libc::fgetxattr(
            fd.as_raw_fd(),
            name.as_ptr(),
            value.as_mut_ptr().cast(),
            value.len(),
            0,
            0,
        )
    };
    work.point()?;
    if size < 0 || size as usize > value.len() {
        return Err(Failure::Attributes);
    }
    Ok(size as usize)
}

/// The actual census uses this before debiting CopyQuote/creating output. It is
/// no allocation allowance derived from a caller-selected path or xattr size.
pub(crate) fn quote_visible_attributes(
    fd: BorrowedFd<'_>,
    parent: BorrowedFd<'_>,
    name: &CStr,
    expected: Identity,
    work: &Work,
) -> Result<u64> {
    let kind = expected.source_kind()?;
    exact(fd, parent, name, expected, work)?;
    empty_acl(fd, work)?;
    let names = Names::read(fd, work)?;
    // No path-based symlink attribute copy. First generation admits links only
    // when the actual O_SYMLINK original has no visible attrs; never omit attrs.
    if kind == profile::Kind::Symlink && !names.ranges.is_empty() {
        return Err(Failure::Attributes);
    }
    let bytes = names.quoted_bytes(fd, work)?;
    exact(fd, parent, name, expected, work)?;
    Ok(bytes)
}
fn output_current(
    fd: BorrowedFd<'_>,
    parent: BorrowedFd<'_>,
    name: &CStr,
    expected: Identity,
    work: &Work,
) -> Result<()> {
    let actual = fstat(fd, work)?;
    if !expected.same_output_object(actual) || actual.size != expected.size {
        return Err(Failure::Binding);
    }
    exact(fd, parent, name, actual, work)
}
// Exact same primitive for one completed regular node or a directory AFTER its
// children have finished. No arbitrary callback, path nomination or quota mode.
fn transfer_attributes(
    source: BorrowedFd<'_>,
    source_parent: BorrowedFd<'_>,
    source_name: &CStr,
    source_identity: Identity,
    output: BorrowedFd<'_>,
    output_parent: BorrowedFd<'_>,
    output_name: &CStr,
    output_identity: Identity,
    quoted_bytes: u64,
    work: &Work,
) -> Result<()> {
    if quoted_bytes > profile::ATTRIBUTE_LIMIT {
        return Err(Failure::Bounds);
    }
    exact(source, source_parent, source_name, source_identity, work)?;
    output_current(output, output_parent, output_name, output_identity, work)?;
    let names = Names::read(source, work)?;
    if names.quoted_bytes(source, work)? != quoted_bytes {
        return Err(Failure::Binding);
    }
    if !Names::read(output, work)?.ranges.is_empty() {
        return Err(Failure::Attributes);
    }
    let mut left = buffer()?;
    let mut right = buffer()?;
    let mut actual_bytes = names.bytes.len() as u64;
    for index in 0..names.ranges.len() {
        let key = names.key(index)?;
        let size = attribute(source, key, &mut left, work)?;
        actual_bytes = actual_bytes
            .checked_add(size as u64)
            .filter(|n| *n <= quoted_bytes)
            .ok_or(Failure::Bounds)?;
        exact(source, source_parent, source_name, source_identity, work)?;
        work.point()?;
        // Exclusive target has no attrs; never erase or overwrite an
        // unexpected attribute, including platform-added security metadata.
        if unsafe {
            libc::fsetxattr(
                output.as_raw_fd(),
                key.as_ptr(),
                left.as_ptr().cast(),
                size,
                0,
                libc::XATTR_CREATE,
            )
        } != 0
        {
            return Err(Failure::Attributes);
        }
        work.point()?;
        let read = attribute(output, key, &mut right, work)?;
        if read != size || left[..size] != right[..size] {
            return Err(Failure::Binding);
        }
        exact(source, source_parent, source_name, source_identity, work)?;
        output_current(output, output_parent, output_name, output_identity, work)?;
    }
    if actual_bytes != quoted_bytes {
        return Err(Failure::Binding);
    }
    let source_after = Names::read(source, work)?;
    if !names.equal(&source_after) {
        return Err(Failure::Binding);
    }
    drop(source_after);
    let output_after = Names::read(output, work)?;
    if !names.equal(&output_after) {
        return Err(Failure::Binding);
    }
    drop(output_after);
    // A complete second value comparison, after roster equality. No
    // successful per-attribute write substitutes for final source readback.
    for index in 0..names.ranges.len() {
        let key = names.key(index)?;
        let a = attribute(source, key, &mut left, work)?;
        let b = attribute(output, key, &mut right, work)?;
        if a != b || left[..a] != right[..b] {
            return Err(Failure::Binding);
        }
    }
    exact(source, source_parent, source_name, source_identity, work)?;
    output_current(output, output_parent, output_name, output_identity, work)?;
    Ok(())
}
impl RegularPair<'_> {
    pub(crate) fn attribute_work_bytes() -> usize {
        ATTRIBUTE_WORK_BYTES
    }
    pub(crate) fn copy_verify_attributes_once(&mut self, quoted_bytes: u64) -> Result<()> {
        if self.phase != Phase::Verified || quoted_bytes > profile::ATTRIBUTE_LIMIT {
            return Err(Failure::Binding);
        }
        self.phase = Phase::Attributes;
        let work = self.work;
        self.source_post(work)?;
        self.output_post(self.source_identity.size as u64, work)?;
        transfer_attributes(
            self.source,
            self.source_parent,
            self.name,
            self.source_identity,
            self.output,
            self.output_parent,
            self.name,
            fstat(self.output, work)?,
            quoted_bytes,
            work,
        )?;
        self.source_post(work)?;
        self.output_post(self.source_identity.size as u64, work)?;
        self.phase = Phase::AttributesVerified;
        Ok(())
    }
    /// Returns only this completed node's current stat. Parent publication still
    /// requires whole-tree readback, Apple POST and independent child closures.
    pub(crate) fn seal_once(&mut self) -> Result<Identity> {
        if self.phase != Phase::AttributesVerified {
            return Err(Failure::Binding);
        }
        self.phase = Phase::Sealing;
        let work = self.work;
        self.source_post(work)?;
        self.output_post(self.source_identity.size as u64, work)?;
        work.point()?;
        if unsafe { libc::fchmod(self.output.as_raw_fd(), self.mode as libc::mode_t) } != 0 {
            return Err(Failure::Write);
        }
        work.point()?;
        let sealed = fstat(self.output, work)?;
        if sealed.mode != libc::S_IFREG | self.mode as libc::mode_t {
            return Err(Failure::Metadata);
        }
        let mut expected = self.output_identity;
        expected.mode = sealed.mode;
        if !expected.same_output_object(sealed) || sealed.size != self.source_identity.size {
            return Err(Failure::Binding);
        }
        exact(self.output, self.output_parent, self.name, sealed, work)?;
        empty_acl(self.output, work)?;
        native::sync(self.output, true).map_err(|_| Failure::Sync)?;
        work.point()?;
        exact(self.output, self.output_parent, self.name, sealed, work)?;
        self.source_post(work)?;
        self.phase = Phase::Sealed;
        Ok(sealed)
    }
}

/// Created private directory, retained from its actual mkdir/open by the same
/// copier table. Finishing is called only after its child loop has independently
/// returned/closed. No present/existing directory may be adopted as output.
pub(crate) struct DirectoryPair<'a> {
    source: BorrowedFd<'a>,
    source_parent: BorrowedFd<'a>,
    output: BorrowedFd<'a>,
    output_parent: BorrowedFd<'a>,
    source_name: &'a CStr,
    output_name: &'a CStr,
    source_identity: Identity,
    created: Identity,
    finished: bool,
    work: &'a Work,
}
impl<'a> DirectoryPair<'a> {
    pub(crate) fn created(
        source: BorrowedFd<'a>,
        source_parent: BorrowedFd<'a>,
        output: BorrowedFd<'a>,
        output_parent: BorrowedFd<'a>,
        source_name: &'a CStr,
        output_name: &'a CStr,
        source_identity: Identity,
        created: Identity,
        work: &'a Work,
    ) -> Result<Self> {
        if source_identity.source_kind()? != profile::Kind::Directory
            || created.dev < 0
            || created.ino == 0
            || created.mode != libc::S_IFDIR | 0o700
            || created.uid != 0
            || created.gid != 0
            || created.flags != 0
            || created.links == 0
            || created.dev == source_identity.dev && created.ino == source_identity.ino
        {
            return Err(Failure::Metadata);
        }
        exact(source, source_parent, source_name, source_identity, work)?;
        exact(output, output_parent, output_name, created, work)?;
        empty_acl(source, work)?;
        empty_acl(output, work)?;
        // The actual exclusive empty directory is checked before child effects.
        let mut block = [0u8; 65536];
        work.point()?;
        if unsafe { libc::lseek(output.as_raw_fd(), 0, libc::SEEK_SET) } != 0 {
            return Err(Failure::Read);
        }
        let used = native::directory_block(output, &mut block).map_err(|_| Failure::Read)?;
        work.point()?;
        if used != 0 {
            return Err(Failure::Binding);
        }
        exact(output, output_parent, output_name, created, work)?;
        Ok(Self {
            source,
            source_parent,
            output,
            output_parent,
            source_name,
            output_name,
            source_identity,
            created,
            finished: false,
            work,
        })
    }
    pub(crate) fn finish_once(&mut self, quoted_attributes: u64) -> Result<Identity> {
        if self.finished {
            return Err(Failure::Binding);
        }
        self.finished = true;
        let work = self.work;
        work.point()?;
        exact(
            self.source,
            self.source_parent,
            self.source_name,
            self.source_identity,
            work,
        )?;
        let before = fstat(self.output, work)?;
        // Child creation legitimately changed nlink/size/timestamps. All other
        // fields remain those of this actual exclusive private directory.
        if (
            before.dev,
            before.ino,
            before.mode,
            before.uid,
            before.gid,
            before.flags,
        ) != (
            self.created.dev,
            self.created.ino,
            self.created.mode,
            self.created.uid,
            self.created.gid,
            self.created.flags,
        ) || before.links == 0
            || before.size < 0
        {
            return Err(Failure::Binding);
        }
        exact(
            self.output,
            self.output_parent,
            self.output_name,
            before,
            work,
        )?;
        transfer_attributes(
            self.source,
            self.source_parent,
            self.source_name,
            self.source_identity,
            self.output,
            self.output_parent,
            self.output_name,
            before,
            quoted_attributes,
            work,
        )?;
        work.point()?;
        if unsafe { libc::fchmod(self.output.as_raw_fd(), 0o555) } != 0 {
            return Err(Failure::Write);
        }
        work.point()?;
        let sealed = fstat(self.output, work)?;
        let mut expected = before;
        expected.mode = libc::S_IFDIR | 0o555;
        if !expected.same_output_object(sealed) || sealed.size != before.size {
            return Err(Failure::Binding);
        }
        exact(
            self.output,
            self.output_parent,
            self.output_name,
            sealed,
            work,
        )?;
        empty_acl(self.output, work)?;
        native::sync(self.output, false).map_err(|_| Failure::Sync)?;
        work.point()?;
        exact(
            self.output,
            self.output_parent,
            self.output_name,
            sealed,
            work,
        )?;
        exact(
            self.source,
            self.source_parent,
            self.source_name,
            self.source_identity,
            work,
        )?;
        Ok(sealed)
    }
}

/// Only verifies one freshly created link; the caller owns its exclusive
/// symlinkat and both actual O_SYMLINK originals. Link bytes are never followed
/// here. Source census's ordered confinement is still a required earlier cut.
pub(crate) fn verify_new_symlink(
    source: BorrowedFd<'_>,
    source_parent: BorrowedFd<'_>,
    output: BorrowedFd<'_>,
    output_parent: BorrowedFd<'_>,
    name: &CStr,
    source_identity: Identity,
    work: &Work,
) -> Result<Identity> {
    if source_identity.source_kind()? != profile::Kind::Symlink {
        return Err(Failure::Kind);
    }
    exact(source, source_parent, name, source_identity, work)?;
    empty_acl(source, work)?;
    let target = fstat(output, work)?;
    if target.mode & libc::S_IFMT != libc::S_IFLNK
        || target.mode & 0o7000 != 0
        || target.uid != 0
        || target.gid != 0
        || target.links != 1
        || target.flags != 0
        || target.size != source_identity.size
        || target.dev < 0
        || target.ino == 0
        || target.dev == source_identity.dev && target.ino == source_identity.ino
    {
        return Err(Failure::Metadata);
    }
    exact(output, output_parent, name, target, work)?;
    empty_acl(output, work)?;
    if !Names::read(source, work)?.ranges.is_empty()
        || !Names::read(output, work)?.ranges.is_empty()
    {
        return Err(Failure::Attributes);
    }
    let mut left = [0u8; profile::LINK_LIMIT + 1];
    let mut right = [0u8; profile::LINK_LIMIT + 1];
    for (parent, buffer) in [(source_parent, &mut left), (output_parent, &mut right)] {
        work.point()?;
        let got = unsafe {
            libc::readlinkat(
                parent.as_raw_fd(),
                name.as_ptr(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
            )
        };
        work.point()?;
        if got != source_identity.size as isize {
            return Err(Failure::Links);
        }
    }
    let size = source_identity.size as usize;
    if left[..size] != right[..size] || !profile::relative_link_shape(&left[..size]) {
        return Err(Failure::Links);
    }
    exact(source, source_parent, name, source_identity, work)?;
    exact(output, output_parent, name, target, work)?;
    // The enclosing directory's actual fsync seals link creation; no invented
    // successful fsync(O_SYMLINK) and no root chmod/follow of its referent.
    Ok(target)
}

/// One actual sealed output node, not an inferred copy based on its path. The
/// whole second walk compares these identities with the ordered first walk.
pub(crate) fn sealed_output(source: Identity, target: Identity) -> Result<()> {
    let kind = source.source_kind()?;
    let mode = profile::copied_mode(kind, u32::from(source.mode), u64::from(source.links))
        .map_err(|_| Failure::Access)?;
    if target.dev < 0
        || target.ino == 0
        || target.uid != 0
        || target.gid != 0
        || target.flags != 0
        || target.mode & libc::S_IFMT != source.mode & libc::S_IFMT
        || target.mode & 0o7000 != 0
        || target.dev == source.dev && target.ino == source.ino
        || kind != profile::Kind::Directory && (target.links != 1 || target.size != source.size)
        || kind == profile::Kind::Directory && (target.links == 0 || target.size < 0)
        || mode.is_some_and(|mode| u32::from(target.mode & 0o7777) != mode)
        || !(0..1_000_000_000).contains(&target.mtime_ns)
        || !(0..1_000_000_000).contains(&target.ctime_ns)
    {
        return Err(Failure::Metadata);
    }
    Ok(())
}

/// Read-only second-pass pair check; source and output identities stay bound
/// throughout each actual byte/attribute comparison. It neither repairs nor
/// adopts a new output on failure. Directory child roster is owned by tree.
pub(crate) fn verify_sealed_pair(
    source: BorrowedFd<'_>,
    source_parent: BorrowedFd<'_>,
    source_name: &CStr,
    source_id: Identity,
    output: BorrowedFd<'_>,
    output_parent: BorrowedFd<'_>,
    output_name: &CStr,
    output_id: Identity,
    quoted_attributes: u64,
    work: &Work,
) -> Result<()> {
    sealed_output(source_id, output_id)?;
    let point = || -> Result<()> {
        exact(source, source_parent, source_name, source_id, work)?;
        exact(output, output_parent, output_name, output_id, work)
    };
    point()?;
    empty_acl(source, work)?;
    empty_acl(output, work)?;
    let kind = source_id.source_kind()?;
    if kind == profile::Kind::Regular {
        let (mut left, mut right) = ([0u8; 65536], [0u8; 65536]);
        let mut offset = 0;
        while offset < source_id.size as u64 {
            let wanted = ((source_id.size as u64) - offset).min(left.len() as u64) as usize;
            for (fd, buffer) in [(source, &mut left), (output, &mut right)] {
                let mut used = 0;
                while used < wanted {
                    work.point()?;
                    let n = unsafe {
                        libc::pread(
                            fd.as_raw_fd(),
                            buffer[used..wanted].as_mut_ptr().cast(),
                            wanted - used,
                            (offset + used as u64) as libc::off_t,
                        )
                    };
                    work.point()?;
                    if n <= 0 || n as usize > wanted - used {
                        return Err(Failure::Read);
                    }
                    used += n as usize;
                }
            }
            if left[..wanted] != right[..wanted] {
                return Err(Failure::Binding);
            }
            offset += wanted as u64;
            point()?;
        }
        for fd in [source, output] {
            work.point()?;
            let n =
                unsafe { libc::pread(fd.as_raw_fd(), left.as_mut_ptr().cast(), 1, source_id.size) };
            work.point()?;
            if n != 0 {
                return Err(Failure::Read);
            }
        }
    } else if kind == profile::Kind::Symlink {
        let (mut left, mut right) = (
            [0u8; profile::LINK_LIMIT + 1],
            [0u8; profile::LINK_LIMIT + 1],
        );
        for (parent, name, buffer) in [
            (source_parent, source_name, &mut left),
            (output_parent, output_name, &mut right),
        ] {
            work.point()?;
            let n = unsafe {
                libc::readlinkat(
                    parent.as_raw_fd(),
                    name.as_ptr(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                )
            };
            work.point()?;
            if n != source_id.size as isize {
                return Err(Failure::Links);
            }
        }
        if left[..source_id.size as usize] != right[..source_id.size as usize] {
            return Err(Failure::Links);
        }
    }
    let source_names = Names::read(source, work)?;
    if !source_names.equal(&Names::read(output, work)?)
        || source_names.quoted_bytes(source, work)? != quoted_attributes
        || kind == profile::Kind::Symlink && !source_names.ranges.is_empty()
    {
        return Err(Failure::Attributes);
    }
    let (mut left, mut right) = (buffer()?, buffer()?);
    for index in 0..source_names.ranges.len() {
        point()?;
        let key = source_names.key(index)?;
        let l = attribute(source, key, &mut left, work)?;
        let r = attribute(output, key, &mut right, work)?;
        if l != r || left[..l] != right[..r] {
            return Err(Failure::Attributes);
        }
        point()?;
    }
    // Roster and actual sizes are reread after values; no mutable list adopted.
    if !source_names.equal(&Names::read(source, work)?) {
        return Err(Failure::Attributes);
    }
    if !source_names.equal(&Names::read(output, work)?) {
        return Err(Failure::Attributes);
    }
    point()
}

/// Fixed Parent-reserved private wrapper, not an arbitrary writable directory.
/// Full protected ancestry/name and sole EX lock remain the caller's originals.
pub(crate) fn private_stage(id: Identity) -> Result<()> {
    if id.mode != libc::S_IFDIR | 0o700
        || id.uid != 0
        || id.gid != 0
        || id.flags != 0
        || id.ino == 0
        || id.dev < 0
        || id.links == 0
    {
        return Err(Failure::Access);
    }
    Ok(())
}
