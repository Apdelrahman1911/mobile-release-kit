//! Fixed Windows package producer, not consumer/runtime qualification.
//!
//! This process-lifetime singleton is the ACTUAL original owner, not a receipt.
//! It is registered before the first native call and cannot be replaced. A panic
//! poisons the Mutex but leaves that owner and every unresolved pinned arena in
//! the static. No async task, worker, sink lock or destructor supplies finality.
#![forbid(unsafe_code)]

use std::{collections::BTreeSet, sync::{Mutex, OnceLock}};
use mrk_windows_installed_native::{CloseOutcome, Publication, PUBLICATION_PAYLOADS};
use sha2::{Digest, Sha256};
use crate::runtime::windows_version::{Inventory, VersionSpec, MANIFEST_BYTES, TARGET};

static OWNER: OnceLock<Mutex<Publication>> = OnceLock::new();
const MANIFEST: usize = 7;
const FILE_LIMIT: u64 = 512 * 1024 * 1024;
const TOTAL_READ_LIMIT: u64 = 1024 * 1024 * 1024;

/// Failure never promises that the destination name is absent or unreadable.
/// In particular Windows traverse bypass can expose already sealed child bytes
/// before the final version-root consumer-admission grant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicationError {
    Invocation,
    Profile,
    AlreadyStarted,
    OwnerUnavailable,
    /// The original fixed target-D creation returned ERROR_ALREADY_EXISTS;
    /// no output was created/exposed and the original owner actually settled.
    OccupiedTargetSettled,
    Failed { possibly_exposed: bool, originals_unknown: bool },
}
type Checked<T> = Result<T, ()>;
fn require(value: bool) -> Checked<()> { if value { Ok(()) } else { Err(()) } }
fn no_arguments(count: usize) -> bool { count == 1 }
fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes { result.push(DIGITS[(byte >> 4) as usize] as char); result.push(DIGITS[(byte & 15) as usize] as char); }
    result
}

struct Expected { sizes: [u64; 47], hashes: [String; 47] }
impl Expected {
    fn decode(spec: &VersionSpec, bytes: &[u8]) -> Checked<Self> {
        // The existing VersionSpec hashes before JSON and retains Q/core/target,
        // exact supplier hashes, inventory serialization, strict path/case and
        // schema checks. This helper does not implement a second manifest policy.
        let inventory = spec.decode(bytes).map_err(|_| ())?;
        require(spec.components() == ["Mobile Release Kit", "versions", TARGET, spec.manifest_sha256()])?;
        Self::roster(&inventory, bytes.len() as u64, spec.manifest_sha256())
    }
    fn roster(inventory: &Inventory, manifest_size: u64, manifest_hash: &str) -> Checked<Self> {
        require(manifest_size > 0 && manifest_size <= MANIFEST_BYTES
            && inventory.manifest.files.len() + 1 == PUBLICATION_PAYLOADS.len()
            && inventory.directories == BTreeSet::from(["python".to_owned()]))?;
        let actual: BTreeSet<&str> = inventory.manifest.files.iter().map(|row| row.path.as_str())
            .chain(std::iter::once("manifest.json")).collect();
        let expected: BTreeSet<&str> = PUBLICATION_PAYLOADS.into_iter().collect();
        require(actual == expected && actual.len() == PUBLICATION_PAYLOADS.len())?;
        let mut sizes = [0; 47];
        let mut hashes = std::array::from_fn(|_| String::new());
        for (i, path) in PUBLICATION_PAYLOADS.iter().enumerate() {
            if i == MANIFEST {
                require(*path == "manifest.json")?;
                sizes[i] = manifest_size; hashes[i] = manifest_hash.to_owned();
            } else {
                let row = inventory.file(path).ok_or(())?;
                sizes[i] = row.size; hashes[i] = row.sha256.clone();
            }
        }
        require(sizes.iter().all(|n| *n <= FILE_LIMIT))?;
        let bytes = sizes.iter().try_fold(0u64, |total, size| total.checked_add(*size).ok_or(()))?;
        require(bytes.checked_mul(2).is_some_and(|total| total <= TOTAL_READ_LIMIT)
            && inventory.payload_bytes.checked_add(manifest_size) == Some(bytes))?;
        Ok(Self { sizes, hashes })
    }
    fn verify(&self, index: usize, count: u64, hasher: Sha256) -> Checked<()> {
        require(self.sizes.get(index) == Some(&count)
            && self.hashes.get(index).is_some_and(|expected| *expected == hex(&hasher.finalize())))
    }
}

fn produce(owner: &mut Publication, spec: &VersionSpec) -> Checked<()> {
    let manifest = owner.admit_once().map_err(|_| ())?;
    let expected = Expected::decode(spec, &manifest)?;
    owner.create_once(expected.sizes).map_err(|_| ())?;
    for index in 0..PUBLICATION_PAYLOADS.len() {
        owner.start_copy(index).map_err(|_| ())?;
        let mut count = 0u64;
        let mut hasher = Sha256::new();
        loop {
            let bytes = owner.copy_next().map_err(|_| ())?;
            if bytes.is_empty() { break; } // native original EOF, not a length guess
            count = count.checked_add(bytes.len() as u64).ok_or(())?;
            require(count <= expected.sizes[index])?; hasher.update(&bytes);
        }
        expected.verify(index, count, hasher)?;
        // No readback can replace a failed flush or actual writer CloseHandle.
        owner.finish_copy().map_err(|_| ())?;
        let mut count = 0u64;
        let mut hasher = Sha256::new();
        loop {
            let bytes = owner.readback_next().map_err(|_| ())?;
            if bytes.is_empty() { break; }
            count = count.checked_add(bytes.len() as u64).ok_or(())?;
            require(count <= expected.sizes[index])?; hasher.update(&bytes);
        }
        expected.verify(index, count, hasher)?;
        owner.finish_readback().map_err(|_| ())?;
    }
    owner.seal_once().map_err(|_| ())?;
    require(owner.published_and_settled())
}

/// No arguments, environment paths, current directory, self-executable lookup,
/// MSI property or renderer input can select source/destination/target/anchors.
pub fn publish_fixed() -> Result<(), PublicationError> {
    if !no_arguments(std::env::args_os().take(2).count()) { return Err(PublicationError::Invocation); }
    let spec = VersionSpec::compiled().map_err(|_| PublicationError::Profile)?;
    let owner = Publication::new(spec.manifest_sha256()).map_err(|_| PublicationError::Profile)?;
    OWNER.set(Mutex::new(owner)).map_err(|_| PublicationError::AlreadyStarted)?;
    // No native effect has preceded OWNER.set. A rejected second call cannot
    // replace, retry, repair or settle the original owner behind this static.
    let mut original = OWNER.get().ok_or(PublicationError::OwnerUnavailable)?
        .lock().map_err(|_| PublicationError::OwnerUnavailable)?;
    if produce(&mut original, &spec).is_ok() && original.published_and_settled() { return Ok(()); }
    let possibly_exposed = original.possibly_exposed();
    let settlement = original.fail_and_settle_once();
    if settlement == CloseOutcome::Settled && original.occupied_target_and_settled() {
        return Err(PublicationError::OccupiedTargetSettled);
    }
    let originals_unknown = settlement == CloseOutcome::Unknown;
    Err(PublicationError::Failed { possibly_exposed, originals_unknown })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::{Manifest, PayloadFile, CORE_VERSION};

    // Roster-only DATA, deliberately not a supplier/manifest/native admission
    // fixture. Real production always calls VersionSpec::decode BEFORE roster.
    fn roster_fixture() -> Inventory {
        let files: Vec<_> = PUBLICATION_PAYLOADS.iter().filter(|p| **p != "manifest.json")
            .map(|p| PayloadFile { path: (*p).to_owned(), size: 1, sha256: hex(&Sha256::digest(b"x")) }).collect();
        Inventory { payload_bytes: files.len() as u64, directories: BTreeSet::from(["python".to_owned()]),
            manifest: Manifest { schema_version: 1, protocol: crate::protocol::PROTOCOL,
                core_version: CORE_VERSION.to_owned(), target: TARGET.to_owned(), core_sha256: "a".repeat(64),
                protocol_sha256: "b".repeat(64), inventory_sha256: "c".repeat(64), files } }
    }
    #[test]
    fn no_argument_entry_and_literal_release_shape() {
        assert!(no_arguments(1)); assert!(!no_arguments(0)); assert!(!no_arguments(2));
        assert_eq!(TARGET, "x86_64-pc-windows-msvc");
        assert_eq!(PUBLICATION_PAYLOADS[MANIFEST], "manifest.json");
        assert_eq!(PUBLICATION_PAYLOADS.iter().filter(|p| p.starts_with("python/")).count(), 38);
        assert_eq!(PUBLICATION_PAYLOADS.iter().filter(|p| p.ends_with("_bootstrap.py")).count(), 6);
    }
    #[test]
    fn roster_refuses_extras_omissions_case_aliases_and_extra_directories() {
        let digest = "d".repeat(64);
        assert!(Expected::roster(&roster_fixture(), 1, &digest).is_ok());
        for missing in 0..46 {
            let mut inventory = roster_fixture(); inventory.manifest.files.remove(missing);
            assert!(Expected::roster(&inventory, 1, &digest).is_err());
        }
        let mut extra = roster_fixture();
        extra.manifest.files.push(PayloadFile { path: "extra".to_owned(), size: 0, sha256: digest.clone() });
        assert!(Expected::roster(&extra, 1, &digest).is_err());
        let mut alias = roster_fixture(); alias.manifest.files[0].path.make_ascii_uppercase();
        assert!(Expected::roster(&alias, 1, &digest).is_err());
        let mut directory = roster_fixture(); directory.directories.insert("empty".to_owned());
        assert!(Expected::roster(&directory, 1, &digest).is_err());
    }
    #[test]
    fn pair_read_budget_and_exact_digest_cannot_be_replaced_by_size() -> Checked<()> {
        let mut inventory = roster_fixture();
        let expected = Expected::roster(&inventory, 1, &"d".repeat(64))?;
        let mut hash = Sha256::new(); hash.update(b"x"); expected.verify(0, 1, hash)?;
        let mut wrong = Sha256::new(); wrong.update(b"y"); assert!(expected.verify(0, 1, wrong).is_err());
        let mut short = Sha256::new(); short.update(b"x"); assert!(expected.verify(0, 0, short).is_err());
        inventory.payload_bytes += FILE_LIMIT - 1; inventory.manifest.files[0].size = FILE_LIMIT;
        assert!(Expected::roster(&inventory, 1, &"d".repeat(64)).is_err());
        Ok(())
    }
}
