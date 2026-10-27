//! Bounded volume metadata from the caller's held original. No path lookup,
//! descriptor ownership, stored-record migration or installation authority.
use std::{io, os::fd::{AsRawFd, BorrowedFd}};

fn returned(code: i32, bytes: [u8; 16]) -> io::Result<[u8; 16]> {
    if code != 0 { return Err(io::Error::from_raw_os_error(code)); }
    if bytes == [0; 16] { return Err(io::ErrorKind::InvalidData.into()); }
    Ok(bytes)
}

/// The caller must retain its named/held identity and mount checks. A UUID
/// alone does not identify a file or authorize accepting a legacy record.
pub fn volume_uuid(fd: BorrowedFd<'_>) -> io::Result<[u8; 16]> {
    unsafe extern "C" { fn mrk_filesystem_uuid_v1(fd: i32, bytes: *mut u8) -> i32; }
    let mut bytes = [0; 16];
    // SAFETY: one live borrowed descriptor and exactly sixteen writable bytes.
    // The shim retains no pointer, allocation or descriptor and never closes it.
    let code = unsafe { mrk_filesystem_uuid_v1(fd.as_raw_fd(), bytes.as_mut_ptr()) };
    returned(code, bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs::{self, File}, os::fd::AsFd};
    #[test]
    fn malformed_or_failed_uuid_is_not_a_persistent_identity() {
        assert!(returned(0, [0; 16]).is_err());
        assert!(returned(nix::libc::ENOTSUP, [7; 16]).is_err());
        assert_eq!(returned(0, [7; 16]).unwrap(), [7; 16]);
    }
    #[test]
    fn original_volume_uuid_is_stable_and_descriptor_remains_owned() {
        let root = std::env::temp_dir().join(format!("mrk-volume-uuid-{}", std::process::id()));
        fs::create_dir(&root).unwrap();
        let child = root.join("child"); fs::create_dir(&child).unwrap();
        let parent = File::open(&root).unwrap(); let nested = File::open(&child).unwrap();
        let first = volume_uuid(parent.as_fd()).unwrap();
        assert_eq!(first, volume_uuid(parent.as_fd()).unwrap());
        assert_eq!(first, volume_uuid(nested.as_fd()).unwrap());
        assert!(parent.metadata().unwrap().is_dir());
        assert!(nested.metadata().unwrap().is_dir());
        let (reader, writer) = nix::unistd::pipe().unwrap();
        assert!(volume_uuid(reader.as_fd()).is_err());
        assert_eq!(nix::unistd::write(&writer, b"x").unwrap(), 1);
        let mut byte = [0]; assert_eq!(nix::unistd::read(&reader, &mut byte).unwrap(), 1);
        assert_eq!(byte, [b'x']);
        drop(nested); drop(parent); fs::remove_dir(child).unwrap(); fs::remove_dir(root).unwrap();
    }
}
