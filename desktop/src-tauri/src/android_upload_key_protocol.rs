//! Fixed generation comparison/transport DATA. No process, credential or lease
//! authority is minted here. In particular a binary terminal is NOT finality.
use crate::error::BridgeError;
#[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"))))]
use crate::vault_format::{Id, Identity};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fmt;

pub(crate) const PROTOCOL: &str = "mrk-android-upload-key/1";
pub(crate) const WORK_SECONDS: u64 = 180;
pub(crate) const FINALITY_SECONDS: u64 = 190;
pub(crate) const REQUEST_LIMIT: usize = 16 * 1024;
pub(crate) const JKS_LIMIT: usize = 64 * 1024;
pub(crate) const CERTIFICATE_LIMIT: usize = 16 * 1024;
pub(crate) const PRIVATE_BACKING_LIMIT: usize = 96 * 1024;
pub(crate) const PASSWORD_LENGTH: usize = 64;
pub(crate) const READY_MAGIC: &[u8] = b"MRK-UK-READY/1\0";
pub(crate) const GO_MAGIC: &[u8] = b"MRK-UK-GO/1\0";
pub(crate) const END_MAGIC: &[u8] = b"MRK-UK-END/1\0";
pub(crate) const READY_LENGTH: usize = READY_MAGIC.len() + 32 + 32 + 32;
pub(crate) const GO_LENGTH: usize = GO_MAGIC.len() + 32 + PASSWORD_LENGTH * 2;
pub(crate) const END_HEADER_LENGTH: usize = END_MAGIC.len() + 32 + 32 + 1 + 4 + 4;
pub(crate) const RESPONSE_LIMIT: usize =
    READY_LENGTH + END_HEADER_LENGTH + JKS_LIMIT + CERTIFICATE_LIMIT;
const _: () = assert!(RESPONSE_LIMIT <= PRIVATE_BACKING_LIMIT);

// Existing nonsecret installed-inspector partition, never extra vault credit.
pub(crate) const INSPECTION_RESERVE: usize = crate::macos_install_record::CONTROL_LIMIT;
// Generation alone uses the existing bounded typed M2 parser with this cap.
// It preserves the common validator and can refuse a larger catalogue layout.
pub(crate) const TOOL_PARSE_RESERVE: usize = 16 * 1024 * 1024;

/// App-owned M2 inspection peak, computed against the actual private native
/// row types by its sole caller. No caller-sized credit or native grant.
pub(crate) fn tool_inspection_peak(
    original_cell: usize,
    alias_cell: usize,
    frame: usize,
) -> Option<usize> {
    use crate::android_toolchain_macos_policy as policy;
    let originals = policy::ENTRY_LIMIT.checked_add(256)?;
    // Original ledger Vec growth + basename backing, alias originals; the
    // insertion-only BTree debits use the same conservative256B node allowance
    // as the existing installed-code planner. The seen+expected full-path sets
    // dominate the walk's disjoint recursive basename sets (<=ENTRY_LIMIT).
    let bytes = originals
        .checked_mul(2)?
        .checked_mul(original_cell)?
        .checked_add(originals.checked_mul(255)?)?
        .checked_add(
            policy::ALIAS_COUNT
                .checked_mul(2)?
                .checked_mul(alias_cell.checked_add(255 + 512)?)?,
        )?
        .checked_add(TOOL_PARSE_RESERVE)?
        .checked_add(
            policy::FILE_COUNT
                .checked_add(policy::ALIAS_COUNT)?
                .checked_mul(256)?,
        )?
        .checked_add(policy::ENTRY_LIMIT.checked_mul(2 * (512 + 256))?)?
        .checked_add(policy::MANIFEST_LIMIT.checked_mul(2)?)?
        .checked_add(policy::PROVIDER_LIMIT.checked_mul(2)?)?
        .checked_add(policy::RECORD_LIMIT.checked_mul(2)?)?
        .checked_add(policy::NATIVE_WORK_BYTES)?
        .checked_add(17 * 65536 + 128 * 1024)?
        .checked_add(frame)?;
    (original_cell > 0 && alias_cell > 0 && frame > 0 && bytes <= INSPECTION_RESERVE)
        .then_some(bytes)
}

pub(crate) fn measured_native_charge(fixed: usize, measured: usize) -> Option<usize> {
    // Zero is the original atomic's unpublished/in-progress sentinel, not a
    // settled empty book. Over-limit observations cannot make a new GO valid.
    (measured > 0 && measured <= INSPECTION_RESERVE)
        .then_some(measured)
        .and_then(|bytes| fixed.checked_add(bytes))
}

pub(crate) fn inspection_peak_fits(retained: usize, growing: usize) -> bool {
    measured_native_charge(retained, growing).is_some_and(|sum| sum <= INSPECTION_RESERVE)
}

pub(crate) fn invalid() -> BridgeError {
    BridgeError::new("android_upload_key_invalid", "The new upload-key request no longer matches this project. Review it again; do not repeat an uncertain generation.")
}
pub(crate) fn unavailable() -> BridgeError {
    BridgeError::new("android_upload_key_unavailable", "Create a new upload key only with this project's unlocked credential storage and supported protected JDK.")
}
pub(crate) fn id(value: &str) -> bool {
    // Exactly Id::from_token's syntax, without an unsupported vault backend.
    value.len() == 32
        && value.bytes().any(|b| b != b'0')
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub(crate) fn sha(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Native comparison data only. There is intentionally no Deserialize route;
/// the parent retains the genuine saved config/root/AssetContext originals.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct UploadKeyContext {
    pub(crate) project_id: String,
    pub(crate) runtime_project_id: String,
    pub(crate) config_bytes: u32,
    pub(crate) config_sha256: String,
    pub(crate) draft_sha256: String,
    pub(crate) app_identity_sha256: String,
    pub(crate) observation_revision: u32,
    #[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"))))]
    pub(crate) vault: Identity,
    #[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"))))]
    pub(crate) record: Id,
}
impl fmt::Debug for UploadKeyContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("UploadKeyContext(private native binding)")
    }
}
#[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"))))]
impl UploadKeyContext {
    pub(crate) fn valid(&self) -> bool {
        id(&self.project_id)
            && crate::protocol::valid_id(&self.runtime_project_id)
            && (1..=512 * 1024).contains(&self.config_bytes)
            && sha(&self.config_sha256)
            && sha(&self.draft_sha256)
            && sha(&self.app_identity_sha256)
            && self.observation_revision != 0
            && self.vault.vault != self.vault.generation
            && self.record != self.vault.vault
            && self.record != self.vault.generation
    }
    pub(crate) fn digest(&self) -> Result<String, BridgeError> {
        if !self.valid() {
            return Err(invalid());
        }
        let mut hash = Sha256::new();
        hash.update(b"mrk-upload-key-context/1\0");
        for text in [
            &self.project_id,
            &self.runtime_project_id,
            &self.config_sha256,
            &self.draft_sha256,
            &self.app_identity_sha256,
        ] {
            hash.update((text.len() as u32).to_be_bytes());
            hash.update(text.as_bytes());
        }
        hash.update(self.config_bytes.to_be_bytes());
        hash.update(self.observation_revision.to_be_bytes());
        hash.update(self.vault.vault.bytes());
        hash.update(self.vault.generation.bytes());
        hash.update(self.record.bytes());
        Ok(format!("{:x}", hash.finalize()))
    }
}
#[cfg(not(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))))]
impl UploadKeyContext {
    pub(crate) fn valid(&self) -> bool {
        false
    }
    pub(crate) fn digest(&self) -> Result<String, BridgeError> {
        Err(invalid())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Profile {
    MacArm64,
    MacX64,
}
impl Profile {
    pub(crate) fn current() -> Option<Self> {
        #[cfg(all(
            target_os = "macos",
            target_pointer_width = "64",
            target_arch = "aarch64",
            not(feature = "macos-android-registration-helper")
        ))]
        {
            return Some(Self::MacArm64);
        }
        #[cfg(all(
            target_os = "macos",
            target_pointer_width = "64",
            target_arch = "x86_64",
            not(feature = "macos-android-registration-helper")
        ))]
        {
            return Some(Self::MacX64);
        }
        #[allow(unreachable_code)]
        None
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Availability {
    Available,
    Busy,
    Shutdown,
    CleanupUnknown,
    DocumentLost,
    UnsupportedPlatform,
    RuntimeUnqualified,
    ToolchainUnqualified,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Phase {
    AwaitingConsent,
    Starting,
    Running,
    Stopping,
    Terminal,
    Unknown,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Outcome {
    Complete,
    Refused,
    Cancelled,
    TimedOut,
    Failed,
    Unknown,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Reason {
    None,
    Refused,
    Cancelled,
    TimedOut,
    CleanupUnknown,
    StaleIntent,
    NativeFailure,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CoreStatus {
    Ok,
    Refused,
    Cancelled,
    TimedOut,
    CleanupUnknown,
}
impl CoreStatus {
    fn parse(value: u8) -> Result<Self, BridgeError> {
        match value {
            0 => Ok(Self::Ok),
            1 => Ok(Self::Refused),
            2 => Ok(Self::Cancelled),
            3 => Ok(Self::TimedOut),
            4 => Ok(Self::CleanupUnknown),
            _ => Err(invalid()),
        }
    }
    pub(crate) fn outcome(self) -> Outcome {
        match self {
            Self::Ok => Outcome::Complete,
            Self::Refused => Outcome::Refused,
            Self::Cancelled => Outcome::Cancelled,
            Self::TimedOut => Outcome::TimedOut,
            Self::CleanupUnknown => Outcome::Unknown,
        }
    }
    pub(crate) fn reason(self) -> Reason {
        match self {
            Self::Ok => Reason::None,
            Self::Refused => Reason::Refused,
            Self::Cancelled => Reason::Cancelled,
            Self::TimedOut => Reason::TimedOut,
            Self::CleanupUnknown => Reason::CleanupUnknown,
        }
    }
}
#[derive(Clone)]
pub(crate) struct Terminal {
    pub(crate) status: CoreStatus,
}
impl Terminal {
    pub(crate) fn settled(&self) -> bool {
        self.status != CoreStatus::CleanupUnknown
    }
}
pub(crate) enum Frame {
    Accepted,
    Terminal(Terminal),
}

/// Private original-owner status for the outer vault coordinator. It is not
/// a new UI operation endpoint nor permission to fetch candidate bytes.
pub(crate) struct Status {
    pub(crate) revision: u32,
    pub(crate) availability: Availability,
    pub(crate) current: Option<Run>,
}
pub(crate) struct Run {
    pub(crate) operation_id: String,
    pub(crate) owner_generation: String,
    pub(crate) phase: Phase,
    pub(crate) outcome: Option<Outcome>,
    pub(crate) reason: Reason,
}

#[derive(Clone, Copy)]
pub(crate) struct EndHeader {
    pub(crate) status: CoreStatus,
    pub(crate) jks: usize,
    pub(crate) certificate: usize,
}
pub(crate) fn check_ready(
    raw: &[u8],
    operation: &str,
    generation: &str,
    digest: &[u8; 32],
) -> bool {
    let start = READY_MAGIC.len();
    id(operation)
        && id(generation)
        && raw.len() == READY_LENGTH
        && raw.starts_with(READY_MAGIC)
        && raw[start..start + 32] == *operation.as_bytes()
        && raw[start + 32..start + 64] == *generation.as_bytes()
        && raw[start + 64..] == digest[..]
}
pub(crate) fn end_header(
    raw: &[u8],
    operation: &str,
    generation: &str,
) -> Result<EndHeader, BridgeError> {
    let start = END_MAGIC.len();
    if !id(operation)
        || !id(generation)
        || raw.len() != END_HEADER_LENGTH
        || !raw.starts_with(END_MAGIC)
        || raw[start..start + 32] != *operation.as_bytes()
        || raw[start + 32..start + 64] != *generation.as_bytes()
    {
        return Err(invalid());
    }
    let status = CoreStatus::parse(raw[start + 64])?;
    let jks = u32::from_be_bytes(
        raw[start + 65..start + 69]
            .try_into()
            .map_err(|_| invalid())?,
    ) as usize;
    let certificate = u32::from_be_bytes(
        raw[start + 69..start + 73]
            .try_into()
            .map_err(|_| invalid())?,
    ) as usize;
    if if status == CoreStatus::Ok {
        !(32 < jks && jks <= JKS_LIMIT && 0 < certificate && certificate <= CERTIFICATE_LIMIT)
    } else {
        jks != 0 || certificate != 0
    } {
        return Err(invalid());
    }
    Ok(EndHeader {
        status,
        jks,
        certificate,
    })
}

/// Only fixed-format consistency, never imported-key trust or finality. The
/// helper already verifies password-dependent integrity; the native retained
/// candidate compares this same JKS/DER with full authenticated vault readback.
pub(crate) fn generated_container(jks: &[u8], certificate: &[u8]) -> bool {
    fn take<'a>(raw: &mut &'a [u8], count: usize) -> Option<&'a [u8]> {
        if count > raw.len() {
            return None;
        }
        let (result, rest) = raw.split_at(count);
        *raw = rest;
        Some(result)
    }
    fn u32be(raw: &mut &[u8]) -> Option<usize> {
        Some(u32::from_be_bytes(take(raw, 4)?.try_into().ok()?) as usize)
    }
    fn check(jks: &[u8], cert: &[u8]) -> Option<()> {
        if !(32 < jks.len()
            && jks.len() <= JKS_LIMIT
            && 0 < cert.len()
            && cert.len() <= CERTIFICATE_LIMIT)
        {
            return None;
        }
        let mut raw = &jks[..jks.len() - 20];
        if u32be(&mut raw)? != 0xfeedfeed
            || u32be(&mut raw)? != 2
            || u32be(&mut raw)? != 1
            || u32be(&mut raw)? != 1
            || take(&mut raw, 8)? != b"\0\x06upload"
        {
            return None;
        }
        if i64::from_be_bytes(take(&mut raw, 8)?.try_into().ok()?) <= 0 {
            return None;
        }
        let encrypted = u32be(&mut raw)?;
        if !(32..=JKS_LIMIT - 64).contains(&encrypted)
            || take(&mut raw, encrypted)?.first() != Some(&0x30)
            || u32be(&mut raw)? != 1
            || take(&mut raw, 7)? != b"\0\x05X.509"
        {
            return None;
        }
        let size = u32be(&mut raw)?;
        if size != cert.len()
            || cert.first() != Some(&0x30)
            || take(&mut raw, size)? != cert
            || !raw.is_empty()
        {
            return None;
        }
        Some(())
    }
    check(jks, certificate).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unpublished_over_limit_or_overflowed_measurement_is_unavailable() {
        assert_eq!(measured_native_charge(73, 0), None);
        assert_eq!(measured_native_charge(73, INSPECTION_RESERVE + 1), None);
        assert_eq!(measured_native_charge(usize::MAX, 1), None);
        assert_eq!(measured_native_charge(73, 1), Some(74));
        assert_eq!(
            measured_native_charge(73, INSPECTION_RESERVE),
            Some(73 + INSPECTION_RESERVE)
        );
        assert!(!inspection_peak_fits(1, INSPECTION_RESERVE));
        assert!(inspection_peak_fits(1, INSPECTION_RESERVE - 1));
        assert!(!inspection_peak_fits(usize::MAX, 1));
    }

    #[test]
    fn bounded_tool_peak_rejects_bad_target_sizes_before_inspection() {
        // Cell sizes are DATA here, not native qualification. Production uses
        // only its actual private Original/Alias layouts and native frame.
        assert!(tool_inspection_peak(128, 128, 16_384).is_some());
        for (original, alias, frame) in [
            (0, 128, 16_384),
            (128, 0, 16_384),
            (128, 128, 0),
            (usize::MAX, 128, 16_384),
            (128, usize::MAX, 16_384),
            (128, 128, usize::MAX),
        ] {
            assert!(tool_inspection_peak(original, alias, frame).is_none());
        }
    }

    fn header(status: u8, jks: u32, cert: u32) -> Vec<u8> {
        let mut raw = END_MAGIC.to_vec();
        raw.extend_from_slice(b"11111111111111111111111111111111");
        raw.extend_from_slice(b"22222222222222222222222222222222");
        raw.push(status);
        raw.extend_from_slice(&jks.to_be_bytes());
        raw.extend_from_slice(&cert.to_be_bytes());
        raw
    }
    #[test]
    fn private_header_is_exact_and_bounded() {
        let raw = header(0, 1024, 2048);
        assert!(end_header(&raw, &"1".repeat(32), &"2".repeat(32)).is_ok());
        for bad in [
            header(0, 0, 1),
            header(0, 65537, 1),
            header(0, 33, 16385),
            header(1, 33, 1),
            header(5, 0, 0),
        ] {
            assert!(end_header(&bad, &"1".repeat(32), &"2".repeat(32)).is_err());
        }
        assert!(end_header(&raw[..raw.len() - 1], &"1".repeat(32), &"2".repeat(32)).is_err());
        assert!(end_header(&raw, &"3".repeat(32), &"2".repeat(32)).is_err());
    }
    #[test]
    fn ready_binds_original_and_request_not_just_lengths() {
        let mut raw = READY_MAGIC.to_vec();
        raw.extend_from_slice("1".repeat(32).as_bytes());
        raw.extend_from_slice("2".repeat(32).as_bytes());
        raw.extend_from_slice(&[4; 32]);
        assert!(check_ready(
            &raw,
            &"1".repeat(32),
            &"2".repeat(32),
            &[4; 32]
        ));
        assert!(!check_ready(
            &raw,
            &"1".repeat(32),
            &"2".repeat(32),
            &[5; 32]
        ));
        raw.push(0);
        assert!(!check_ready(
            &raw,
            &"1".repeat(32),
            &"2".repeat(32),
            &[4; 32]
        ));
    }
    #[test]
    fn no_zero_alias_id_or_private_json_parser() {
        assert!(!id(&"0".repeat(32)));
        assert!(!id(&"A".repeat(32)));
        assert!(!id("fixture"));
        assert!(id(&"1".repeat(32)));
        assert!(generated_container(&[0; 33], &[0x30]).eq(&false));
        #[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"))))]
        for value in [
            "".to_owned(),
            "0".repeat(32),
            "1".repeat(31),
            "1".repeat(33),
            "A".repeat(32),
            "g".repeat(32),
            "é".repeat(16),
            "\0".repeat(32),
            "00000000000000000000000000000001".to_owned(),
            "10000000000000000000000000000000".to_owned(),
            "0123456789abcdef0123456789abcdef".to_owned(),
        ] {
            assert_eq!(id(&value), Id::from_token(&value).is_ok());
        }
    }

    #[cfg(not(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))))]
    #[test]
    fn unsupported_target_refuses_context_digest_and_request_before_admission() {
        // Predicate DATA only: even otherwise valid comparison fields cannot
        // authorize a request without this target's existing vault backend.
        let context = UploadKeyContext {
            project_id: "1".repeat(32),
            runtime_project_id: "project-1".to_owned(),
            config_bytes: 73,
            config_sha256: "a".repeat(64),
            draft_sha256: "b".repeat(64),
            app_identity_sha256: "c".repeat(64),
            observation_revision: 1,
        };
        let path = std::path::PathBuf::from(if cfg!(windows) {
            r"C:\unopened-upload-key-fixture"
        } else {
            "/unopened-upload-key-fixture"
        });
        let root = crate::asset_source::RegisteredRoot {
            path: path.clone(),
            identity: crate::asset_source::ProjectIdentity::Posix(
                crate::asset_source::DirectoryIdentity::synthetic_evidence_identity(),
            ),
        };
        let tool = NativeTool {
            path: path.join("bin").join("keytool"),
            identity: [1, 2, 0o100755, 0, 0, 1, 4096, 0, 0],
            sha256: "d".repeat(64),
            uid: 123,
            gid: 123,
        };
        assert!(tool.valid());
        assert!(root.identity.posix().is_ok());
        assert_eq!(Profile::current(), None);
        assert!(!context.valid());
        assert_eq!(context.digest().unwrap_err().code, "android_upload_key_invalid");
        let error = request(
            &"2".repeat(32),
            &"3".repeat(32),
            &context,
            &root,
            &tool,
            1,
            10_000_000_001,
        )
        .unwrap_err();
        assert_eq!(error.code, "android_upload_key_invalid");
    }
}

/// Comparison DATA captured from the actual retained protected keytool file,
/// after the existing complete M2 inventory/hash/native-file inspection.
/// No parser/renderer constructor or alternate path/search is supplied.
#[derive(Clone)]
pub(crate) struct NativeTool {
    pub(crate) path: std::path::PathBuf,
    pub(crate) identity: [i64; 9],
    pub(crate) sha256: String,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
}
impl NativeTool {
    pub(crate) fn retained_bytes(&self) -> Option<usize> {
        std::mem::size_of::<Self>()
            .checked_add(self.path.capacity())?
            .checked_add(self.sha256.capacity())
    }
    fn valid(&self) -> bool {
        self.uid > 0
            && self.uid < u32::MAX
            && self.path.is_absolute()
            && self.path.file_name().is_some_and(|n| n == "keytool")
            && self
                .path
                .parent()
                .and_then(std::path::Path::file_name)
                .is_some_and(|n| n == "bin")
            && self
                .path
                .to_str()
                .is_some_and(|p| p.len() <= 4096 && !p.chars().any(char::is_control))
            && self.identity[..7].iter().all(|n| *n >= 0)
            && self.identity[0] > 0
            && self.identity[1] > 0
            && self.identity[2] & 0o170000 == 0o100000
            && self.identity[2] & 0o111 != 0
            && self.identity[2] & 0o7022 == 0
            && matches!(self.identity[3], 0)
            && self.identity[5] == 1
            && (1..=256 * 1024 * 1024).contains(&self.identity[6])
            && sha(&self.sha256)
    }
}
pub(crate) fn request(
    operation: &str,
    generation: &str,
    context: &UploadKeyContext,
    root: &crate::asset_source::RegisteredRoot,
    tool: &NativeTool,
    work: u64,
    hard: u64,
) -> Result<Vec<u8>, BridgeError> {
    if !id(operation)
        || !id(generation)
        || !context.valid()
        || !tool.valid()
        || work == 0
        || hard > i64::MAX as u64
        || hard.checked_sub(work) != Some(10_000_000_000)
    {
        return Err(invalid());
    }
    let root_id = root
        .identity
        .posix()
        .map_err(|_| invalid())?
        .preflight_identity();
    let device = root_id.device.parse::<u64>().map_err(|_| invalid())?;
    let inode = root_id.inode.parse::<u64>().map_err(|_| invalid())?;
    if device == 0 || inode == 0 {
        return Err(invalid());
    }
    let mut raw=serde_json::to_vec(&serde_json::json!({
        "protocol":PROTOCOL,"id":operation,"generation":generation,"contextSha256":context.digest()?,
        "native":{"uid":tool.uid,"gid":tool.gid,"executable":tool.path,
            "tool":{"identity":tool.identity,"sha256":tool.sha256},
            "saved":{"root":root.path,"identity":[device,inode,u64::from(root_id.mode),u64::from(root_id.uid),u64::from(root_id.gid)],
                "configBytes":context.config_bytes,"configSha256":context.config_sha256,
                "draftSha256":context.draft_sha256,"appIdentitySha256":context.app_identity_sha256}},
        "clock":{"workEndNs":work,"hardEndNs":hard}
    })).map_err(|_|invalid())?;
    raw.push(b'\n');
    if raw.len() > REQUEST_LIMIT {
        return Err(invalid());
    }
    Ok(raw)
}
