//! Fixed Windows package producer, not consumer/runtime qualification.
//!
//! This process-lifetime singleton is the ACTUAL original owner, not a receipt.
//! It is registered before the first native call and cannot be replaced. A panic
//! poisons the Mutex but leaves that owner and every unresolved pinned arena in
//! the static. No async task, worker, sink lock or destructor supplies finality.
#![forbid(unsafe_code)]

use std::{collections::BTreeSet, sync::{Mutex, OnceLock}};
use mrk_windows_installed_native::{CloseOutcome, Error as NativeError, Publication, PublicationFrameObservation, PublicationAdmissionObservation, PUBLICATION_PAYLOADS};
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
    Failed { cause: PublicationFailure, possibly_exposed: bool, originals_unknown: bool, frame: Option<PublicationFrameObservation>, admission: Option<PublicationAdmissionObservation> },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FailurePhase {
    Admit, Decode, Create, StartCopy, CopyNext, CopyCount, CopySize, CopyVerify, FinishCopy,
    ReadbackNext, ReadbackCount, ReadbackSize, ReadbackVerify, FinishReadback, Seal, FinalPostcondition,
}
impl FailurePhase {
    fn label(self) -> &'static str {
        match self {
            Self::Admit => "admit", Self::Decode => "decode", Self::Create => "create",
            Self::StartCopy => "start-copy", Self::CopyNext => "copy-next", Self::CopyCount => "copy-count",
            Self::CopySize => "copy-size", Self::CopyVerify => "copy-verify", Self::FinishCopy => "finish-copy",
            Self::ReadbackNext => "readback-next", Self::ReadbackCount => "readback-count",
            Self::ReadbackSize => "readback-size", Self::ReadbackVerify => "readback-verify",
            Self::FinishReadback => "finish-readback", Self::Seal => "seal", Self::FinalPostcondition => "final-postcondition",
        }
    }
}
/// Closed DATA from the first returning operation, never a native owner or receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicationFailure { phase: FailurePhase, ordinal: Option<usize>, native: Option<NativeError> }
impl PublicationFailure {
    fn native(phase: FailurePhase, ordinal: Option<usize>, error: NativeError) -> Self {
        Self { phase, ordinal, native: Some(error) }
    }
    fn policy(phase: FailurePhase, ordinal: Option<usize>) -> Self { Self { phase, ordinal, native: None } }
    fn admission_observation_allowed(self) -> bool {
        self.phase == FailurePhase::Admit && self.native == Some(NativeError::Unsafe)
    }
    fn class(self) -> &'static str {
        match self.native {
            None => "policy", Some(NativeError::Unavailable) => "unavailable", Some(NativeError::Unsafe) => "unsafe",
            Some(NativeError::Bounds) => "bounds", Some(NativeError::State) => "state", Some(NativeError::Unknown) => "unknown",
        }
    }
}
impl PublicationError {
    /// One bounded ASCII failure line; no owner/native reads or arbitrary error formatting.
    /// Pre-owner errors (including AlreadyStarted) assert no exposure or finality facts.
    pub fn diagnostic_line(self) -> Option<String> {
        let observed = |value| if value { "true" } else { "false" };
        let (phase, class, ordinal, exposed, unknown) = match self {
            Self::Invocation => ("invocation", "unobserved", None, "unobserved", "unobserved"),
            Self::Profile => ("profile", "unobserved", None, "unobserved", "unobserved"),
            Self::AlreadyStarted => ("already-started", "unobserved", None, "unobserved", "unobserved"),
            Self::OwnerUnavailable => ("owner-unavailable", "unobserved", None, "unobserved", "unobserved"),
            Self::OccupiedTargetSettled => return None, // Expected exit2 remains silent.
            Self::Failed { cause, possibly_exposed, originals_unknown, .. } =>
                (cause.phase.label(), cause.class(), cause.ordinal, observed(possibly_exposed), observed(originals_unknown)),
        };
        let mut line = String::with_capacity(192);
        line.push_str("MRK_WINDOWS_RUNTIME_PUBLISH_FAILURE_V1=phase="); line.push_str(phase);
        line.push_str(";class="); line.push_str(class); line.push_str(";ordinal=");
        if let Some(index) = ordinal.filter(|index| *index < 47) {
            if index >= 10 { line.push(char::from(b'0' + (index / 10) as u8)); }
            line.push(char::from(b'0' + (index % 10) as u8));
        } else { line.push_str("none"); }
        line.push_str(";possiblyExposed="); line.push_str(exposed);
        line.push_str(";originalsUnknown="); line.push_str(unknown); line.push('\n');
        if line.len() <= 256 { Some(line) } else { None }
    }
    pub fn admission_diagnostic_line(self) -> Option<String> {
        match self {
            Self::Failed { cause, admission: Some(admission), .. }
                if cause.admission_observation_allowed() => admission.diagnostic_line(),
            _ => None,
        }
    }
    pub fn frame_diagnostic_line(self) -> Option<String> {
        match self {
            Self::Failed { cause, frame: Some(frame), .. }
                if cause.phase == FailurePhase::Admit && cause.native == Some(NativeError::Unknown) => frame.diagnostic_line(),
            _ => None,
        }
    }
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

fn produce(owner: &mut Publication, spec: &VersionSpec) -> Result<(), PublicationFailure> {
    let manifest = owner.admit_once().map_err(|error| PublicationFailure::native(FailurePhase::Admit, None, error))?;
    let expected = Expected::decode(spec, &manifest).map_err(|_| PublicationFailure::policy(FailurePhase::Decode, None))?;
    owner.create_once(expected.sizes).map_err(|error| PublicationFailure::native(FailurePhase::Create, None, error))?;
    for index in 0..PUBLICATION_PAYLOADS.len() {
        let ordinal = Some(index);
        owner.start_copy(index).map_err(|error| PublicationFailure::native(FailurePhase::StartCopy, ordinal, error))?;
        let mut count = 0u64;
        let mut hasher = Sha256::new();
        loop {
            let bytes = owner.copy_next().map_err(|error| PublicationFailure::native(FailurePhase::CopyNext, ordinal, error))?;
            if bytes.is_empty() { break; } // native original EOF, not a length guess
            count = count.checked_add(bytes.len() as u64).ok_or_else(|| PublicationFailure::policy(FailurePhase::CopyCount, ordinal))?;
            require(count <= expected.sizes[index]).map_err(|_| PublicationFailure::policy(FailurePhase::CopySize, ordinal))?;
            hasher.update(&bytes);
        }
        expected.verify(index, count, hasher).map_err(|_| PublicationFailure::policy(FailurePhase::CopyVerify, ordinal))?;
        // No readback can replace a failed flush or actual writer CloseHandle.
        owner.finish_copy().map_err(|error| PublicationFailure::native(FailurePhase::FinishCopy, ordinal, error))?;
        let mut count = 0u64;
        let mut hasher = Sha256::new();
        loop {
            let bytes = owner.readback_next().map_err(|error| PublicationFailure::native(FailurePhase::ReadbackNext, ordinal, error))?;
            if bytes.is_empty() { break; }
            count = count.checked_add(bytes.len() as u64).ok_or_else(|| PublicationFailure::policy(FailurePhase::ReadbackCount, ordinal))?;
            require(count <= expected.sizes[index]).map_err(|_| PublicationFailure::policy(FailurePhase::ReadbackSize, ordinal))?;
            hasher.update(&bytes);
        }
        expected.verify(index, count, hasher).map_err(|_| PublicationFailure::policy(FailurePhase::ReadbackVerify, ordinal))?;
        owner.finish_readback().map_err(|error| PublicationFailure::native(FailurePhase::FinishReadback, ordinal, error))?;
    }
    owner.seal_once().map_err(|error| PublicationFailure::native(FailurePhase::Seal, None, error))?;
    require(owner.published_and_settled()).map_err(|_| PublicationFailure::policy(FailurePhase::FinalPostcondition, None))
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
    // Keep BOTH original deadline-sensitive postconditions and their short-circuit.
    // A later finality/settlement observation cannot replace produce's first cause.
    let cause = match produce(&mut original, &spec) {
        Ok(()) if original.published_and_settled() => return Ok(()),
        Ok(()) => PublicationFailure::policy(FailurePhase::FinalPostcondition, None),
        Err(first) => first,
    };
    let frame = if cause.phase == FailurePhase::Admit && cause.native == Some(NativeError::Unknown) {
        Some(original.retained_frame_observation())
    } else { None };
    let admission = if cause.admission_observation_allowed() {
        original.retained_admission_observation()
    } else { None };
    let possibly_exposed = original.possibly_exposed();
    let settlement = original.fail_and_settle_once();
    if settlement == CloseOutcome::Settled && original.occupied_target_and_settled() {
        return Err(PublicationError::OccupiedTargetSettled);
    }
    let originals_unknown = settlement == CloseOutcome::Unknown;
    Err(PublicationError::Failed { cause, possibly_exposed, originals_unknown, frame, admission })
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
        // Reuse this already-selected policy test; do not create a filtered-out test.
        for (error, phase) in [(PublicationError::Invocation, "invocation"), (PublicationError::Profile, "profile"),
            (PublicationError::AlreadyStarted, "already-started"), (PublicationError::OwnerUnavailable, "owner-unavailable")] {
            assert_eq!(error.diagnostic_line(), Some(format!("MRK_WINDOWS_RUNTIME_PUBLISH_FAILURE_V1=phase={phase};class=unobserved;ordinal=none;possiblyExposed=unobserved;originalsUnknown=unobserved\n")));
            assert!(error.admission_diagnostic_line().is_none());
        }
        assert_eq!(PublicationError::OccupiedTargetSettled.diagnostic_line(), None);
        assert_eq!(PublicationError::OccupiedTargetSettled.admission_diagnostic_line(), None);
        for (phase, label) in [(FailurePhase::Admit, "admit"), (FailurePhase::Decode, "decode"), (FailurePhase::Create, "create"),
            (FailurePhase::StartCopy, "start-copy"), (FailurePhase::CopyNext, "copy-next"), (FailurePhase::CopyCount, "copy-count"),
            (FailurePhase::CopySize, "copy-size"), (FailurePhase::CopyVerify, "copy-verify"), (FailurePhase::FinishCopy, "finish-copy"),
            (FailurePhase::ReadbackNext, "readback-next"), (FailurePhase::ReadbackCount, "readback-count"), (FailurePhase::ReadbackSize, "readback-size"),
            (FailurePhase::ReadbackVerify, "readback-verify"), (FailurePhase::FinishReadback, "finish-readback"),
            (FailurePhase::Seal, "seal"), (FailurePhase::FinalPostcondition, "final-postcondition")] {
            let error = PublicationError::Failed { cause: PublicationFailure::policy(phase, None), possibly_exposed: false, originals_unknown: true, frame: None, admission: None };
            assert_eq!(error.diagnostic_line(), Some(format!("MRK_WINDOWS_RUNTIME_PUBLISH_FAILURE_V1=phase={label};class=policy;ordinal=none;possiblyExposed=false;originalsUnknown=true\n")));
            assert!(!PublicationFailure::policy(phase, None).admission_observation_allowed());
            // The same closed gate controls both the owner snapshot and formatter.
            // No public factory fabricates native diagnostic values for this crate.
            for native in [NativeError::Unavailable, NativeError::Unsafe, NativeError::Bounds, NativeError::State, NativeError::Unknown] {
                let cause = PublicationFailure::native(phase, None, native);
                assert_eq!(cause.admission_observation_allowed(), phase == FailurePhase::Admit && native == NativeError::Unsafe);
                let absent = PublicationError::Failed { cause, possibly_exposed: false, originals_unknown: true, frame: None, admission: None };
                assert!(absent.admission_diagnostic_line().is_none());
            }
        }
        for (native, class) in [(NativeError::Unavailable, "unavailable"), (NativeError::Unsafe, "unsafe"),
            (NativeError::Bounds, "bounds"), (NativeError::State, "state"), (NativeError::Unknown, "unknown")] {
            let error = PublicationError::Failed { cause: PublicationFailure::native(FailurePhase::CopyNext, Some(46), native), possibly_exposed: true, originals_unknown: false, frame: None, admission: None };
            assert_eq!(error.diagnostic_line(), Some(format!("MRK_WINDOWS_RUNTIME_PUBLISH_FAILURE_V1=phase=copy-next;class={class};ordinal=46;possiblyExposed=true;originalsUnknown=false\n")));
        }
        for (ordinal, encoded) in [(None, "none"), (Some(0), "0"), (Some(9), "9"), (Some(10), "10"),
            (Some(46), "46"), (Some(47), "none"), (Some(usize::MAX), "none")] {
            let error = PublicationError::Failed { cause: PublicationFailure::policy(FailurePhase::CopyCount, ordinal), possibly_exposed: true, originals_unknown: true, frame: None, admission: None };
            let line = error.diagnostic_line().unwrap();
            assert_eq!(line, format!("MRK_WINDOWS_RUNTIME_PUBLISH_FAILURE_V1=phase=copy-count;class=policy;ordinal={encoded};possiblyExposed=true;originalsUnknown=true\n"));
            assert!(line.is_ascii() && line.len() <= 256 && line.bytes().filter(|b| *b == b'\n').count() == 1);
        }
        // Creating/copying this empty DATA owner enters no native call. The
        // FRAME companion is allowed only for first Admit/Unknown, never another cause.
        let frame = Publication::new(&"d".repeat(64)).unwrap().retained_frame_observation();
        for (phase, native, allowed) in [(FailurePhase::Admit, NativeError::Unknown, true),
            (FailurePhase::Admit, NativeError::Unsafe, false), (FailurePhase::Create, NativeError::Unknown, false)] {
            let error = PublicationError::Failed { cause: PublicationFailure::native(phase, None, native),
                possibly_exposed: false, originals_unknown: true, frame: Some(frame), admission: None };
            assert_eq!(error.frame_diagnostic_line().is_some(), allowed);
            assert!(error.admission_diagnostic_line().is_none());
            if allowed {
                let line = error.frame_diagnostic_line().unwrap();
                assert_eq!(line, "MRK_WINDOWS_RUNTIME_PUBLISH_FRAME_V2=qcall=none;qphase=none;qret=none;qrefusal=none;mcall=none;mphase=none;mret=none;mcount=none\n");
                assert!(error.diagnostic_line().unwrap().len() + line.len() <= 512);
            }
        }
        for error in [PublicationError::Invocation, PublicationError::Profile, PublicationError::AlreadyStarted,
            PublicationError::OwnerUnavailable, PublicationError::OccupiedTargetSettled,
            PublicationError::Failed { cause: PublicationFailure::native(FailurePhase::Admit, None, NativeError::Unknown),
                possibly_exposed: false, originals_unknown: true, frame: None, admission: None }] {
            assert!(error.frame_diagnostic_line().is_none());
            assert!(error.admission_diagnostic_line().is_none());
        }
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
