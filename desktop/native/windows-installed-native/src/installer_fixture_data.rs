//! Fixed nonshipping compile DATA and eligibility for five retained-shell cases.
//! No filesystem mutation, process launch, native owner or success receipt here.
//! Enabled only by the explicit installer-protected-fixture feature.
use super::{Result, Error, AcquisitionByteCounts, InstallerRuntimeMode};
fn need(value: bool) -> Result<()> { if value { Ok(()) } else { Err(Error::Unsafe) } }
use super::installer_input_data::{InputLayout, INPUTS, TARGET, digest_name, expected_sizes};
// Already locked/used by the actual prerequisite owner; this has no native call.
use sha2::{Digest, Sha256};
fn digest(raw: &[u8]) -> Result<String> { Ok(format!("{:x}", Sha256::digest(raw))) }
use std::path::PathBuf;

const PROFILE_HEADER: &str = "MRK_WINDOWS_RETAINED_SHELL_FIXTURE_PROFILE_SET_V1";
const ROSTER_HEADER: &str = "MRK_WINDOWS_RETAINED_SHELL_FIXTURE_ROSTER_V1";
const PROFILES: &[u8] = include_bytes!(env!("MRK_WINDOWS_RETAINED_FIXTURE_PROFILES"));
const ROSTER: &[u8] = include_bytes!(env!("MRK_WINDOWS_RETAINED_FIXTURE_ROSTER"));
pub const INSTALLER_FIXTURE_LIMIT: u64 = 128 * 1024 * 1024;
pub const INSTALLER_FIXTURE_PROFILE: &str = "windows-installer-retained-shell-v1";
const PROFILE_NAMES: [&str; 5] = ["fresh", "reuse", "stop-copy", "wrong-caller", "bad-manifest"];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InstallerFixtureCase { Fresh, Reuse, StopCopy, WrongCaller, BadManifest }
impl InstallerFixtureCase {
    pub const ALL: [Self; 5] = [Self::Fresh, Self::Reuse, Self::StopCopy, Self::WrongCaller, Self::BadManifest];
    pub fn index(self) -> usize { match self { Self::Fresh=>0, Self::Reuse=>1, Self::StopCopy=>2, Self::WrongCaller=>3, Self::BadManifest=>4 } }
    pub fn label(self) -> &'static str { PROFILE_NAMES[self.index()] }
    pub fn app_test(self) -> &'static str { match self {
        Self::Fresh=>"windows_installer_controller::retained_fixture::owned_fresh",
        Self::Reuse=>"windows_installer_controller::retained_fixture::owned_reuse",
        Self::StopCopy=>"windows_installer_controller::retained_fixture::owned_stop_copy",
        Self::WrongCaller=>"windows_installer_controller::retained_fixture::owned_wrong_caller",
        Self::BadManifest=>"windows_installer_controller::retained_fixture::owned_bad_manifest",
    } }
}

pub struct InstallerFixtureInputs {
    pub source_commit: &'static str,
    pub manifest: &'static str,
    pub protocol: &'static str,
    pub core_version: &'static str,
    pub helper: &'static str,
    pub image: &'static str,
    pub sizes: [u64; INPUTS],
    pub hashes: [&'static str; INPUTS],
    pub profile: &'static [u8],
    case: InstallerFixtureCase,
}
impl InstallerFixtureInputs {
    pub fn source_leaf(&self) -> String { format!("MRK Installer Fixture {}", self.image) }
    pub fn case(&self) -> InstallerFixtureCase { self.case }
    pub(super) fn layout(&self) -> Result<InputLayout> {
        InputLayout::new(self.manifest, self.helper, self.image).ok_or(Error::State)
    }
}
fn number(value: &str) -> Result<u64> {
    need(!value.is_empty() && value.bytes().all(|b| b.is_ascii_digit())
        && (value == "0" || !value.starts_with('0')))?;
    value.parse().map_err(|_| Error::Bounds)
}
fn field<'a>(line: Option<&'a str>, key: &str) -> Result<&'a str> {
    line.and_then(|line| line.strip_prefix(key)).ok_or(Error::Unsafe)
}

/// Validates the whole finite set before returning one selected immutable row.
/// A profile hash/image is DATA only; actual InputAcquisition must still admit
/// protected originals and the existing core authenticates/decode its manifest.
pub fn installer_fixture_inputs(case: InstallerFixtureCase) -> Result<InstallerFixtureInputs> {
    need(!PROFILES.is_empty() && PROFILES.len() <= 5 * 8193 + PROFILE_HEADER.len() + 1
        && !ROSTER.is_empty() && ROSTER.len() <= 32768
        && PROFILES.is_ascii() && ROSTER.is_ascii()
        && !PROFILES.contains(&0) && !ROSTER.contains(&0))?;
    need(digest(PROFILES)? == env!("MRK_WINDOWS_RETAINED_FIXTURE_PROFILES_SHA256")
        && digest(ROSTER)? == env!("MRK_WINDOWS_RETAINED_FIXTURE_ROSTER_SHA256"))?;
    let profiles_text = std::str::from_utf8(PROFILES).map_err(|_| Error::Unsafe)?;
    let roster_text = std::str::from_utf8(ROSTER).map_err(|_| Error::Unsafe)?;
    need(profiles_text.ends_with('\n') && roster_text.ends_with('\n'))?;
    let profiles: Vec<_> = profiles_text.lines().collect();
    need(profiles.len() == 6 && profiles[0] == PROFILE_HEADER)?;
    let mut lines = roster_text.lines();
    need(lines.next() == Some(ROSTER_HEADER))?;
    need(field(lines.next(), "profilesSha256=")? == env!("MRK_WINDOWS_RETAINED_FIXTURE_PROFILES_SHA256"))?;
    let source_commit = field(lines.next(), "sourceCommit=")?;
    let target = field(lines.next(), "target=")?;
    let manifest = field(lines.next(), "runtimeManifestSha256=")?;
    let protocol = field(lines.next(), "protocolSha256=")?;
    let core_version = field(lines.next(), "coreVersion=")?;
    let helper = field(lines.next(), "publisherSha256=")?;
    need(source_commit.len() == 40 && source_commit.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && source_commit == env!("GITHUB_SHA") && target == TARGET
        && digest_name(manifest) && digest_name(protocol) && digest_name(helper)
        && manifest == env!("MRK_BUNDLED_RUNTIME_MANIFEST_SHA256")
        && protocol == env!("MRK_BUNDLED_PROTOCOL_SHA256")
        && !core_version.is_empty() && core_version.len() <= 64)?;
    let mut result = Vec::with_capacity(5);
    let mut images = std::collections::BTreeSet::new();
    let mut shells = std::collections::BTreeSet::new();
    for selected in InstallerFixtureCase::ALL {
        need(field(lines.next(), "case=")? == selected.label())?;
        let image = field(lines.next(), "image=")?;
        let profile = profiles[selected.index() + 1].as_bytes();
        need(!profile.is_empty() && profile.len() <= 8192 && digest(profile)? == image
            && images.insert(image))?;
        let mut sizes = [0u64; INPUTS]; let mut hashes = [""; INPUTS];
        for ordinal in 0..INPUTS {
            let parts: Vec<_> = lines.next().ok_or(Error::Unsafe)?.split('\t').collect();
            need(parts.len() == 3 && number(parts[0])? == ordinal as u64 && digest_name(parts[2]))?;
            sizes[ordinal] = number(parts[1])?; hashes[ordinal] = parts[2];
        }
        need(expected_sizes(&sizes).is_some_and(|n| n <= INSTALLER_FIXTURE_LIMIT)
            && hashes[7] == manifest && hashes[47] == helper && shells.insert(hashes[48]))?;
        let row = InstallerFixtureInputs { source_commit, manifest, protocol, core_version, helper,
            image, sizes, hashes, profile, case: selected };
        if let Some(first) = result.first() {
            let first: &InstallerFixtureInputs = first;
            need((0..INPUTS).filter(|i| ![48, 52, 53].contains(i))
                .all(|i| first.sizes[i] == row.sizes[i] && first.hashes[i] == row.hashes[i]))?;
        }
        result.push(row);
    }
    need(lines.next().is_none())?;
    Ok(result.swap_remove(case.index()))
}

/// Eligibility strings identify this finite test route, not native authority.
/// Root still owns original-process admission, compile/source binding and finality.
pub fn installer_fixture_eligibility(case: InstallerFixtureCase) -> Result<PathBuf> {
    installer_fixture_process(case.app_test())
}
pub(super) fn installer_fixture_process(test: &'static str) -> Result<PathBuf> {
    fixed_fixture_process(test, "windows-installer-retained-shell")
}
#[cfg(feature = "installer-selection-fixture")]
pub(super) fn selection_fixture_process(test: &'static str) -> Result<PathBuf> {
    fixed_fixture_process(test, "windows-installer-selection")
}
fn fixed_fixture_process(test: &'static str, dispatch: &'static str) -> Result<PathBuf> {
    need(matches!(dispatch, "windows-installer-retained-shell" | "windows-installer-selection"))?;
    for (name, expected) in [
        ("MRK_DESKTOP_HOSTED_CHECKS", "windows-installed-native-v1"),
        ("MRK_DESKTOP_DISPATCH_SCOPE", dispatch),
        ("GITHUB_EVENT_NAME", "workflow_dispatch"),
        ("GITHUB_JOB", "windows-installed-native"),
        ("GITHUB_REF", "refs/heads/verify/desktop-windows-installer-retained-shell"),
        ("GITHUB_ACTIONS", "true"), ("RUNNER_ENVIRONMENT", "github-hosted"),
        ("RUNNER_OS", "Windows"), ("RUNNER_ARCH", "X64"), ("ImageOS", "win25-vs2026"),
        ("GITHUB_RUN_ATTEMPT", "1"), ("GITHUB_SHA", env!("GITHUB_SHA")),
        ("GITHUB_WORKFLOW_SHA", env!("GITHUB_SHA")), ("MRK_DESKTOP_EXPECTED_SHA", env!("GITHUB_SHA")),
    ] { need(std::env::var(name).as_deref() == Ok(expected))?; }
    let run = std::env::var("GITHUB_RUN_ID").map_err(|_| Error::State)?;
    need(!run.is_empty() && run.len() <= 20 && !run.starts_with('0') && run.bytes().all(|b| b.is_ascii_digit()))?;
    let temp = PathBuf::from(std::env::var_os("RUNNER_TEMP").ok_or(Error::State)?);
    let root = PathBuf::from(std::env::var_os("MRK_DESKTOP_CI_ROOT").ok_or(Error::State)?);
    need(root == temp.join(format!("mrk-windows-installed-native-{run}-1"))
        && std::env::current_dir().map_err(|_| Error::Unavailable)? == root)?;
    let image = std::env::current_exe().map_err(|_| Error::Unavailable)?;
    let args: Vec<_> = std::env::args_os().collect();
    let expected = [test, "--exact", "--ignored", "--nocapture", "--test-threads=1"];
    need(args.len() == 6 && PathBuf::from(&args[0]) == image
        && args[1..].iter().zip(expected).all(|(a, b)| a == b))?;
    Ok(root)
}

/// DATA snapshots of actual retained owner storage. They are not constructors,
/// permission/cleanup capabilities, current filesystem facts or finality receipts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InstallerFixtureAcquisitionObservation {
    pub original_books_settled: bool,
    pub complete_rows: usize,
    pub controls_read_bytes: u64,
    pub byte_counts: AcquisitionByteCounts,
    pub partial_ordinal: Option<usize>,
    pub partial_writer_closed: bool,
    pub activation_started: bool,
    pub activation_settled: bool,
    pub activation_completed: bool,
    pub activation_cleanup_errors: usize,
    pub roles_mask: u8,
    pub transition_mask: u8,
    pub controls_mask: u8,
    pub public_roles_mask: u8,
    pub unexpected_control: bool,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InstallerFixturePublicationObservation {
    pub mode: Option<InstallerRuntimeMode>,
    pub originals_settled: bool,
    pub published: bool,
    pub reused: bool,
    pub creations: usize,
    pub target_intent: bool,
    pub directory_controls: usize,
    pub copied_rows: usize,
    pub sealed_rows: usize,
    pub has_transfer: bool,
    pub readonly_rows: usize,
    pub readonly_current: bool,
    pub exposure_attempted: bool,
}
