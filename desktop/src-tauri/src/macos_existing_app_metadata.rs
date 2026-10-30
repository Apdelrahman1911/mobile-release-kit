//! Opaque existing-app metadata DATA, never file-access or installation authority.
//! Only the native installer enrolls this after authenticating a recorded app
//! original. Incoming app roots and every child retain zero-attribute checks.
use sha2::{Digest, Sha256};

pub const MACL_BYTES_LIMIT: usize = 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SnapshotData {
    length: u16,
    digest: [u8; 32],
}

impl SnapshotData {
    // Empty means the native original had no attributes, never an empty tag.
    // The native reader separately requires the exact one-name roster.
    pub fn from_observed_bytes_data(bytes: &[u8]) -> Option<Self> {
        if bytes.len() > MACL_BYTES_LIMIT { return None; }
        Some(Self { length: bytes.len() as u16, digest: Sha256::digest(bytes).into() })
    }

    // A reopened original must conserve its first snapshot, not adopt a new
    // permission tag or derive a replacement expectation from persisted DATA.
    pub fn conserve_data(prior: Option<Self>, observed: Self) -> Option<Self> {
        match prior { Some(first) if first != observed => None, Some(first) => Some(first), None => Some(observed) }
    }
}

// SAME inert bodies run in libtest and the existing compiled observer cut.
// No filesystem calls, grants, installation or native admission occurs here.
pub fn assert_existing_app_metadata_bounds() {
    let empty = SnapshotData::from_observed_bytes_data(&[]).unwrap();
    let tag = SnapshotData::from_observed_bytes_data(&[7; 72]).unwrap();
    assert_ne!(empty, tag);
    for length in [1, 72, MACL_BYTES_LIMIT] {
        assert!(SnapshotData::from_observed_bytes_data(&vec![7; length]).is_some());
    }
    assert!(SnapshotData::from_observed_bytes_data(&vec![7; MACL_BYTES_LIMIT + 1]).is_none());
}

pub fn assert_existing_app_metadata_conservation() {
    let empty = SnapshotData::from_observed_bytes_data(&[]).unwrap();
    let first = SnapshotData::from_observed_bytes_data(&[7; 72]).unwrap();
    let changed = SnapshotData::from_observed_bytes_data(&[8; 72]).unwrap();
    let resized = SnapshotData::from_observed_bytes_data(&[7; 73]).unwrap();
    assert_eq!(SnapshotData::conserve_data(None, first), Some(first));
    assert_eq!(SnapshotData::conserve_data(Some(first), first), Some(first));
    for observed in [empty, changed, resized] {
        assert_eq!(SnapshotData::conserve_data(Some(first), observed), None);
        assert_eq!(SnapshotData::conserve_data(Some(observed), first), None);
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn existing_app_metadata_is_bounded_opaque_data() { super::assert_existing_app_metadata_bounds(); }
    #[test]
    fn existing_app_metadata_never_adopts_changed_permissions() { super::assert_existing_app_metadata_conservation(); }
}
