//! A single read-only mount query, not installed-runtime qualification.
//!
//! Reviewed ABIs: Ubuntu 24.04 x86_64 GNU / GA Linux 6.8 and the exact Ubuntu
//! Azure 6.17.0-1022.22 source. This is not native/product qualification. This crate
//! neither selects paths nor acquires/closes descriptors, changes namespaces,
//! raises privilege, retries unsupported syscalls, or launches a process.
//! Its caller retains the borrowed original descriptor and the deadline owner.
#![cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
#![deny(unsafe_code, unsafe_op_in_unsafe_fn)]

use std::{mem::{offset_of, size_of, MaybeUninit}, os::fd::BorrowedFd};
use linux_raw_sys::general as uapi;
use rustix::fs::{self, AtFlags, Statx, StatxFlags};

pub const ID_MAPPED: u64 = uapi::MOUNT_ATTR_IDMAP as u64;
pub const NO_EXEC: u64 = uapi::MOUNT_ATTR_NOEXEC as u64;
pub const NO_ATIME: u64 = uapi::MOUNT_ATTR_NOATIME as u64;
pub const STRICT_ATIME: u64 = uapi::MOUNT_ATTR_STRICTATIME as u64;
pub const KNOWN_ATTRIBUTES: u64 = (uapi::MOUNT_ATTR_RDONLY | uapi::MOUNT_ATTR_NOSUID
    | uapi::MOUNT_ATTR_NODEV | uapi::MOUNT_ATTR_NOEXEC | uapi::MOUNT_ATTR_NOATIME | uapi::MOUNT_ATTR_STRICTATIME
    | uapi::MOUNT_ATTR_NODIRATIME | uapi::MOUNT_ATTR_IDMAP | uapi::MOUNT_ATTR_NOSYMFOLLOW) as u64;
pub const EXT4_MAGIC: u64 = uapi::EXT4_SUPER_MAGIC as u64;
pub const XFS_MAGIC: u64 = uapi::XFS_SUPER_MAGIC as u64;
pub const PROC_MAGIC: u64 = uapi::PROC_SUPER_MAGIC as u64;
pub const NAMESPACE_MAGIC: u64 = uapi::NSFS_MAGIC as u64;

const REQUEST_MASK: u64 = (uapi::STATMOUNT_SB_BASIC | uapi::STATMOUNT_MNT_BASIC) as u64;
const UNIQUE_MASK: u32 = uapi::STATX_MNT_ID_UNIQUE;
const HEADER_SIZE: usize = 512;

// The pinned binding includes newer fields in what was reserved space in 6.8.
// Only the version-0 request extent and the fixed basic output fields are used.
const _: () = {
    assert!(uapi::MNT_ID_REQ_SIZE_VER0 == 24);
    assert!(size_of::<uapi::mnt_id_req>() >= 24);
    assert!(offset_of!(uapi::mnt_id_req, size) == 0);
    assert!(offset_of!(uapi::mnt_id_req, spare) == 4);
    assert!(offset_of!(uapi::mnt_id_req, mnt_id) == 8);
    assert!(offset_of!(uapi::mnt_id_req, param) == 16);
    assert!(size_of::<uapi::statmount>() == HEADER_SIZE);
    assert!(offset_of!(uapi::statmount, size) == 0);
    assert!(offset_of!(uapi::statmount, mask) == 8);
    assert!(offset_of!(uapi::statmount, sb_dev_major) == 16);
    assert!(offset_of!(uapi::statmount, sb_dev_minor) == 20);
    assert!(offset_of!(uapi::statmount, sb_magic) == 24);
    assert!(offset_of!(uapi::statmount, mnt_id) == 40);
    assert!(offset_of!(uapi::statmount, mnt_id_old) == 56);
    assert!(offset_of!(uapi::statmount, mnt_attr) == 64);
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObservationError { Unsupported, Denied, Inconsistent, System }

/// Plain observed metadata. Not a descriptor, namespace or runtime authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MountObservation {
    unique_id: u64, old_id: u32, device_major: u32, device_minor: u32,
    filesystem_magic: u64, attributes: u64,
}
impl MountObservation {
    pub fn unique_id(&self) -> u64 { self.unique_id }
    pub fn old_id(&self) -> u32 { self.old_id }
    pub fn device(&self) -> (u32, u32) { (self.device_major, self.device_minor) }
    pub fn filesystem_magic(&self) -> u64 { self.filesystem_magic }
    pub fn attributes(&self) -> u64 { self.attributes }
}

fn error(errno: Option<i32>) -> ObservationError {
    match errno {
        Some(libc::ENOSYS | libc::EINVAL | libc::EOPNOTSUPP) => ObservationError::Unsupported,
        Some(libc::EPERM | libc::EACCES) => ObservationError::Denied,
        _ => ObservationError::System,
    }
}

fn original_stat(fd: BorrowedFd<'_>) -> Result<Statx, ObservationError> {
    let mask = StatxFlags::BASIC_STATS | StatxFlags::from_bits_retain(UNIQUE_MASK);
    let stat = fs::statx(fd, "", AtFlags::EMPTY_PATH | AtFlags::SYMLINK_NOFOLLOW | AtFlags::NO_AUTOMOUNT, mask)
        .map_err(|e| error(Some(e.raw_os_error())))?;
    if stat.stx_mask & mask.bits() != mask.bits() || stat.stx_mnt_id == 0 {
        return Err(ObservationError::Unsupported);
    }
    Ok(stat)
}

fn same_original(a: &Statx, b: &Statx) -> bool {
    a.stx_mnt_id == b.stx_mnt_id && a.stx_dev_major == b.stx_dev_major && a.stx_dev_minor == b.stx_dev_minor
        && a.stx_ino == b.stx_ino && a.stx_mode == b.stx_mode && a.stx_uid == b.stx_uid && a.stx_gid == b.stx_gid
        && a.stx_nlink == b.stx_nlink && a.stx_size == b.stx_size
        && a.stx_mtime.tv_sec == b.stx_mtime.tv_sec && a.stx_mtime.tv_nsec == b.stx_mtime.tv_nsec
        && a.stx_ctime.tv_sec == b.stx_ctime.tv_sec && a.stx_ctime.tv_nsec == b.stx_ctime.tv_nsec
}

fn accept_header(header: &uapi::statmount, original: &Statx) -> Result<MountObservation, ObservationError> {
    if header.size as usize != HEADER_SIZE || header.mask != REQUEST_MASK
        || header.mnt_id == 0 || header.mnt_id_old == 0 || header.mnt_id != original.stx_mnt_id
        || header.sb_dev_major != original.stx_dev_major || header.sb_dev_minor != original.stx_dev_minor {
        return Err(ObservationError::Inconsistent);
    }
    Ok(MountObservation { unique_id: header.mnt_id, old_id: header.mnt_id_old,
        device_major: header.sb_dev_major, device_minor: header.sb_dev_minor,
        filesystem_magic: header.sb_magic, attributes: header.mnt_attr })
}

/// Observe only this borrowed original's mount in the calling thread's namespace.
/// Missing masks, syscall/LSM denial and unsupported kernels never get a fallback.
pub fn observe_mount(fd: BorrowedFd<'_>) -> Result<MountObservation, ObservationError> {
    let before = original_stat(fd)?;
    let result = query_basic(before.stx_mnt_id)?;
    let observed = accept_header(&result, &before)?;
    let after = original_stat(fd)?;
    if !same_original(&before, &after) { return Err(ObservationError::Inconsistent); }
    Ok(observed)
}

// The only explicitly permitted unsafe boundary in this crate. The application
// crate remains unsafe_code=forbid. No descriptor integers or caller buffers
// enter here. No strings/offset arrays are requested, dereferenced or returned.
#[allow(unsafe_code)]
fn query_basic(unique_mount_id: u64) -> Result<uapi::statmount, ObservationError> {
    let request = uapi::mnt_id_req { size: uapi::MNT_ID_REQ_SIZE_VER0, spare: 0,
        mnt_id: unique_mount_id, param: REQUEST_MASK, mnt_ns_id: 0 };
    let mut result = MaybeUninit::<uapi::statmount>::zeroed();
    // SAFETY: the pinned x86_64 UAPI assertions above bind both extents. The
    // kernel may read exactly the initialized version-0 request, and may write
    // no more than HEADER_SIZE bytes to a properly aligned live output. The
    // entire output is initialized first; its type contains only integer and
    // zero-length-array UAPI fields, for which every bit pattern is valid.
    // Published target-specific __NR_statmount is used, never a guessed number.
    let returned = unsafe { libc::syscall(libc::c_long::from(uapi::__NR_statmount),
        &request as *const uapi::mnt_id_req, result.as_mut_ptr(), HEADER_SIZE, 0u32) };
    if returned == -1 { return Err(error(std::io::Error::last_os_error().raw_os_error())); }
    if returned != 0 { return Err(ObservationError::Inconsistent); }
    // SAFETY: all bytes were initialized before the call; no UAPI field has an
    // invalid Rust bit pattern. accept_header checks actual coverage and IDs.
    Ok(unsafe { result.assume_init() })
}

#[cfg(test)]
mod pure_tests {
    use super::*;

    #[test]
    fn errno_refuses_missing_or_denied_observation() {
        assert_eq!(error(Some(libc::ENOSYS)), ObservationError::Unsupported);
        assert_eq!(error(Some(libc::EINVAL)), ObservationError::Unsupported);
        assert_eq!(error(Some(libc::EPERM)), ObservationError::Denied);
        assert_eq!(error(None), ObservationError::System);
    }

    #[test]
    fn published_idmap_bit_is_separate_from_other_mount_attributes() {
        assert_ne!(ID_MAPPED, 0);
        assert_eq!(ID_MAPPED & KNOWN_ATTRIBUTES, ID_MAPPED);
        assert_eq!(ID_MAPPED & NO_EXEC, 0);
        assert_eq!(KNOWN_ATTRIBUTES & uapi::MOUNT_ATTR__ATIME as u64, NO_ATIME | STRICT_ATIME);
        assert_ne!(EXT4_MAGIC, XFS_MAGIC);
        assert_ne!(PROC_MAGIC, NAMESPACE_MAGIC);
    }
}
