//! Fixed packaged runtime selection. No production PATH, environment, source, or
//! failed-launch fallback. Verification runs in an owned blocking task, not UI IO.
use std::{collections::BTreeSet, fs::{self, File, Metadata}, io::Read, path::{Component, Path, PathBuf}, time::Instant};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use crate::{error::BridgeError, protocol::{strict_json, PROTOCOL}};

pub const CORE_VERSION: &str = "0.3.0";
pub const COMPILED_TARGET: &str = env!("MRK_COMPILED_TARGET");
const MANIFEST_ANCHOR: Option<&str> = option_env!("MRK_BUNDLED_RUNTIME_MANIFEST_SHA256");
const PROTOCOL_ANCHOR: Option<&str> = option_env!("MRK_BUNDLED_PROTOCOL_SHA256");
const MANIFEST_LIMIT: u64 = 1024 * 1024;
pub(crate) const GITHUB_CA_LIMIT: u64 = 512 * 1024;
// Separate from the session gate and the passive development feature. A CA
// inventory hash is not native socket/TLS, runtime-custody or host qualification.
pub(crate) const GITHUB_TLS_PROFILE_QUALIFIED: bool = false;
const FILE_LIMIT: u64 = 512 * 1024 * 1024;
const TOTAL_LIMIT: u64 = 1024 * 1024 * 1024;
// Seven JSON nodes per payload entry; leave room under strict_json's 20k
// budget. Publisher preparation uses this same portable inventory ceiling.
const FILE_COUNT: usize = 2048;
const ENTRY_COUNT: usize = 8192;
const TREE_DEPTH: usize = 16;
#[cfg(windows)]
const PYTHON_RESOURCE: &str = "python/python.exe";
#[cfg(not(windows))]
const PYTHON_RESOURCE: &str = "python/bin/python3";

// Canonical fixed inventory shared by packaging and installed-data validation.
// Presence is not runtime, TLS, XML, or native-custody qualification.
pub(crate) const REQUIRED_RUNTIME_RESOURCES: [&str; 9] = [
    "android_build_bootstrap.py", "config_edit_bootstrap.py", "core.zip",
    "engine_bootstrap.py", "environment_bootstrap.py", "github-ca.pem",
    "github_connection_bootstrap.py", "offline_preflight_bootstrap.py", PYTHON_RESOURCE,
];

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeStatus { pub state: &'static str, pub reason: Option<String>, pub mode: &'static str }

#[derive(Clone)]
pub struct RuntimeConfig { bundle_root: PathBuf,
    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    passive_installed: PassiveInstalledSelection,
    #[cfg(all(test, debug_assertions, feature = "development-runtime", not(feature = "desktop-shell"),
        any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64"))))]
    environment_fixture_core: Option<PathBuf>,
}

#[derive(Debug)]
pub struct VerifiedRuntime { pub python: PathBuf, pub bootstrap: PathBuf, pub core: PathBuf, pub cwd: PathBuf }

// Selection DATA only, never executable custody. Only the fixed Linux shell
// and its feature-off native tests can select the independently admitted A.
#[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
#[derive(Clone, Copy)]
enum PassiveInstalledSelection {
    Closed,
    #[cfg(all(not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), any(test, feature = "desktop-shell")))]
    CandidateA,
}

// The fixed selector supplies A DATA, not custody or loader qualification.
// Every request still owes original inspection, transfer and the final claim.
#[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
pub(crate) struct PassiveInstalledProfile { _private: () }

#[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
impl PassiveInstalledProfile {
    // A 35507734308/1. A new release/profile requires a separate source review.
    const TARGET: &'static str = "x86_64-unknown-linux-gnu";
    const MANIFEST: &'static str = "e3375ff140d69df54b2445f756711e0245d397ba6ded76e8559732ec2e4e3801";
    const PROTOCOL: &'static str = "860d1cee0072730a487ac8e632206c69e3ba676cab849b144a61755c4b84e41e";
    fn bindings_match(target: &str, manifest: Option<&str>, protocol: Option<&str>) -> bool {
        target == Self::TARGET && manifest == Some(Self::MANIFEST) && protocol == Some(Self::PROTOCOL)
    }
    pub(crate) fn selection(&self) -> Result<VerifiedRuntime, BridgeError> {
        if !Self::bindings_match(COMPILED_TARGET, MANIFEST_ANCHOR, PROTOCOL_ANCHOR) { return Err(unavailable()); }
        let cwd = PathBuf::from("/var/lib/mobile-release-kit/versions").join(Self::TARGET).join(Self::MANIFEST);
        Ok(VerifiedRuntime { python: cwd.join("python/bin/python3"), bootstrap: cwd.join("engine_bootstrap.py"),
            core: cwd.join("core.zip"), cwd })
    }
    pub(crate) fn accepts_platform(&self, sysname: &[u8], machine: &[u8], release: &[u8]) -> bool {
        sysname == b"Linux" && machine == b"x86_64" && release == b"6.17.0-1022-azure"
    }
}

// Separate configuration-only selection DATA. A passive candidate/profile is
// not edit authority, and the feature-off native passive fixture cannot mint
// this value. The original EditOwner still owes custody and a one-use claim.
#[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
pub(crate) struct ConfigurationInstalledProfile { _private: () }

#[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
impl ConfigurationInstalledProfile {
    fn bindings_match(target: &str, manifest: Option<&str>, protocol: Option<&str>) -> bool {
        // Same independently admitted A, not a new supplier/loader profile.
        PassiveInstalledProfile::bindings_match(target, manifest, protocol)
    }
    pub(crate) fn selection(&self) -> Result<VerifiedRuntime, BridgeError> {
        if !Self::bindings_match(COMPILED_TARGET, MANIFEST_ANCHOR, PROTOCOL_ANCHOR) { return Err(unavailable()); }
        let cwd = PathBuf::from("/var/lib/mobile-release-kit/versions")
            .join(PassiveInstalledProfile::TARGET).join(PassiveInstalledProfile::MANIFEST);
        Ok(VerifiedRuntime { python: cwd.join("python/bin/python3"), bootstrap: cwd.join("config_edit_bootstrap.py"),
            core: cwd.join("core.zip"), cwd })
    }
    pub(crate) fn accepts_platform(&self, sysname: &[u8], machine: &[u8], release: &[u8]) -> bool {
        sysname == b"Linux" && machine == b"x86_64" && release == b"6.17.0-1022-azure"
    }
}

/// Packaging inspection is NOT admission to execution or a native-custody proof.
pub struct BundleInspection { pub files: usize, pub target: String }

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Manifest {
    schema_version: u32, protocol: u32, core_version: String, target: String,
    core_sha256: String, protocol_sha256: String, inventory_sha256: String,
    files: Vec<PayloadFile>,
}

// Field order is intentional: compact serde JSON == Python sorted-key JSON.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PayloadFile { path: String, sha256: String, size: u64 }

fn unavailable() -> BridgeError { BridgeError::unavailable("The packaged runtime is absent, incompatible, or fails its trusted inventory.") }
fn installed_passive_method(name: &str) -> bool {
    matches!(name, "capabilities" | "catalog" | "project.snapshot" | "config.validate" | "config.suggest" | "config.preview"
        | "environment.requirements" | "github.setup.propose" | "release.version.observe"
        | "metadata.text.observe" | "metadata.text.validate" | "artifacts.candidate.observe")
}
fn deadline(end: Instant) -> Result<(), BridgeError> { if Instant::now() >= end { Err(BridgeError::timeout()) } else { Ok(()) } }
fn digest(bytes: &[u8]) -> String { hex(&Sha256::digest(bytes)) }
fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes { output.push(HEX[usize::from(byte >> 4)] as char); output.push(HEX[usize::from(byte & 15)] as char); }
    output
}
fn sha(value: &str) -> bool { value.len() == 64 && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) }

pub fn safe_payload_path(path: &str) -> bool {
    if path.is_empty() || path.len() > 512 || !path.is_ascii() { return false; }
    let mut depth = 0;
    for part in path.split('/') {
        depth += 1;
        if depth > TREE_DEPTH || part.is_empty() || part == "." || part == ".." || part.ends_with('.')
            || !part.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-+".contains(&b)) { return false; }
        let stem = part.split('.').next().unwrap_or("").to_ascii_uppercase();
        if ["CON", "PRN", "AUX", "NUL"].contains(&stem.as_str())
            || (stem.len() == 4 && (stem.starts_with("COM") || stem.starts_with("LPT"))
                && matches!(stem.as_bytes().get(3), Some(b'1'..=b'9'))) { return false; }
    }
    true
}

fn ordinary(metadata: &Metadata) -> bool {
    if metadata.file_type().is_symlink() { return false; }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 { return false; } // FILE_ATTRIBUTE_REPARSE_POINT
    }
    true
}

fn anchored_path(path: &Path) -> Result<(), BridgeError> {
    if !path.is_absolute() { return Err(unavailable()); }
    let mut current = PathBuf::new();
    for component in path.components() {
        match component {
            Component::ParentDir | Component::CurDir => return Err(unavailable()),
            // A Windows drive prefix alone (C:) is drive-relative. Do not
            // inspect it until the following root component makes C:\\.
            Component::Prefix(_) => { current.push(component.as_os_str()); continue; }
            _ => current.push(component.as_os_str()),
        }
        let metadata = fs::symlink_metadata(&current).map_err(|_| unavailable())?;
        if !ordinary(&metadata) { return Err(unavailable()); }
    }
    Ok(())
}

fn same_metadata(first: &Metadata, second: &Metadata) -> bool {
    if !ordinary(second) || first.len() != second.len() || first.modified().ok() != second.modified().ok() { return false; }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if first.dev() != second.dev() || first.ino() != second.ino() || first.mode() != second.mode() { return false; }
    }
    true
}

fn read_checked(path: &Path, limit: u64, end: Instant) -> Result<Vec<u8>, BridgeError> {
    deadline(end)?;
    anchored_path(path)?;
    let before = fs::symlink_metadata(path).map_err(|_| unavailable())?;
    if !before.is_file() || before.len() > limit { return Err(unavailable()); }
    let mut file = File::open(path).map_err(|_| unavailable())?;
    let opened = file.metadata().map_err(|_| unavailable())?;
    if !opened.is_file() || !same_metadata(&before, &opened) { return Err(unavailable()); }
    let mut result = Vec::new();
    let mut block = [0u8; 32 * 1024];
    loop {
        deadline(end)?;
        let length = file.read(&mut block).map_err(|_| unavailable())?;
        if length == 0 { break; }
        if (result.len() as u64).saturating_add(length as u64) > limit { return Err(unavailable()); }
        result.extend_from_slice(&block[..length]);
    }
    let after = file.metadata().map_err(|_| unavailable())?;
    let named_after = fs::symlink_metadata(path).map_err(|_| unavailable())?;
    if !same_metadata(&opened, &after) || !same_metadata(&opened, &named_after) || after.len() != result.len() as u64 { return Err(unavailable()); }
    Ok(result)
}

fn hash_checked(path: &Path, expected_size: u64, end: Instant) -> Result<String, BridgeError> {
    deadline(end)?;
    anchored_path(path)?;
    let before = fs::symlink_metadata(path).map_err(|_| unavailable())?;
    if !before.is_file() || before.len() != expected_size { return Err(unavailable()); }
    let mut file = File::open(path).map_err(|_| unavailable())?;
    let opened = file.metadata().map_err(|_| unavailable())?;
    if !same_metadata(&before, &opened) { return Err(unavailable()); }
    let mut hash = Sha256::new();
    let mut count = 0u64;
    let mut block = [0u8; 64 * 1024];
    loop {
        deadline(end)?;
        let length = file.read(&mut block).map_err(|_| unavailable())?;
        if length == 0 { break; }
        count = count.checked_add(length as u64).ok_or_else(unavailable)?;
        if count > expected_size { return Err(unavailable()); }
        hash.update(&block[..length]);
    }
    let after = file.metadata().map_err(|_| unavailable())?;
    let named_after = fs::symlink_metadata(path).map_err(|_| unavailable())?;
    if count != expected_size || !same_metadata(&opened, &after) || !same_metadata(&opened, &named_after) { return Err(unavailable()); }
    Ok(hex(&hash.finalize()))
}

fn exact_inventory(root: &Path, expected: &BTreeSet<String>, end: Instant) -> Result<(), BridgeError> {
    let mut directories = BTreeSet::new();
    for item in expected {
        let mut parent = Path::new(item).parent();
        while let Some(path) = parent {
            if path.as_os_str().is_empty() { break; }
            directories.insert(path.to_str().ok_or_else(unavailable)?.replace('\\', "/"));
            parent = path.parent();
        }
    }
    let mut pending = vec![(PathBuf::new(), 0usize)];
    let mut observed = BTreeSet::new();
    let mut entries = 0usize;
    while let Some((relative, depth)) = pending.pop() {
        deadline(end)?;
        if depth > TREE_DEPTH { return Err(unavailable()); }
        let directory = root.join(&relative);
        anchored_path(&directory)?;
        for entry in fs::read_dir(&directory).map_err(|_| unavailable())? {
            deadline(end)?;
            entries += 1;
            if entries > ENTRY_COUNT { return Err(unavailable()); }
            let entry = entry.map_err(|_| unavailable())?;
            let filename = entry.file_name();
            if !filename.to_str().is_some_and(safe_payload_path) { return Err(unavailable()); }
            let next = relative.join(filename);
            let name = next.to_str().ok_or_else(unavailable)?.replace('\\', "/");
            if !safe_payload_path(&name) { return Err(unavailable()); }
            let metadata = fs::symlink_metadata(root.join(&next)).map_err(|_| unavailable())?;
            if !ordinary(&metadata) { return Err(unavailable()); }
            if metadata.is_dir() {
                if !directories.contains(&name) { return Err(unavailable()); }
                pending.push((next, depth + 1));
            } else if metadata.is_file() {
                if name == "manifest.json" { continue; }
                if !expected.contains(&name) || !observed.insert(name) { return Err(unavailable()); }
            } else { return Err(unavailable()); }
        }
    }
    if &observed != expected { return Err(unavailable()); }
    Ok(())
}

impl RuntimeConfig {
    pub fn packaged(resource_dir: PathBuf) -> Self { Self { bundle_root: resource_dir.join("runtime"),
        #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
        passive_installed: {
            #[cfg(all(feature = "desktop-shell", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher")))]
            { PassiveInstalledSelection::CandidateA }
            #[cfg(not(all(feature = "desktop-shell", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"))))]
            { PassiveInstalledSelection::Closed }
        },
        #[cfg(all(test, debug_assertions, feature = "development-runtime", not(feature = "desktop-shell"),
            any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64"))))]
        environment_fixture_core: None,
    } }
    /// Fixed no-argument candidate DATA. No environment/path/permit can select
    /// it. Feature-off packaged configurations remain Closed.
    #[cfg(all(test, target_os = "linux", target_arch = "x86_64", target_env = "gnu",
        not(feature = "development-runtime"), not(feature = "desktop-shell"), not(feature = "ubuntu-runtime-publisher")))]
    pub(crate) fn installed_passive_candidate_a() -> Self {
        let mut config = Self::packaged(PathBuf::new());
        config.passive_installed = PassiveInstalledSelection::CandidateA;
        config
    }
    #[cfg(all(test, debug_assertions, feature = "development-runtime", not(feature = "desktop-shell"),
        any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64"))))]
    pub(crate) fn select_environment_fixture_zip(&mut self, selection: &crate::environment_diagnostics_owner::EnvironmentRuntimeSelection) {
        self.environment_fixture_core = Some(selection.core().to_path_buf());
    }
    pub fn mode(&self) -> &'static str {
        #[cfg(all(feature = "development-runtime", debug_assertions))]
        { "development" }
        #[cfg(not(all(feature = "development-runtime", debug_assertions)))]
        { "bundled" }
    }
    /// Availability DATA for the UI, using the same installed method allowlist
    /// as admission. This is not permission to skip per-request inspection.
    pub(crate) fn passive_method_available(&self, name: &str) -> bool {
        #[cfg(all(feature = "development-runtime", debug_assertions))]
        { let _ = name; true }
        #[cfg(all(not(all(feature = "development-runtime", debug_assertions)), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
        { installed_passive_method(name) && self.passive_installed_profile().is_ok() }
        #[cfg(all(not(all(feature = "development-runtime", debug_assertions)), not(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))))]
        { let _ = name; false }
    }
    /// Fixed selection DATA for the project-only picker, not an asset session
    /// qualification or a substitute for its original document/lifecycle gate.
    /// Even the feature-off passive candidate cannot select this shell route.
    pub(crate) fn project_selection_profile_available(&self) -> bool {
        #[cfg(all(feature = "desktop-shell", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"),
            target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
        { self.passive_installed_profile().is_ok() }
        #[cfg(not(all(feature = "desktop-shell", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"),
            target_os = "linux", target_arch = "x86_64", target_env = "gnu")))]
        { false }
    }
    pub fn resolve(&self, end: Instant) -> Result<VerifiedRuntime, BridgeError> {
        #[cfg(all(feature = "development-runtime", debug_assertions))]
        { self.development(end) }
        #[cfg(not(all(feature = "development-runtime", debug_assertions)))]
        {
            let _ = end;
            Err(BridgeError::unavailable("Packaged execution is disabled until an immutable, nonblocking runtime-custody backend is qualified. A manifest digest alone cannot enable it."))
        }
    }
    /// The sole passive installed inspection seam. The caller already owns the
    /// registered original slots and blocking worker; this never returns custody.
    /// All other packaged profiles refuse before descriptor inspection.
    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    pub(crate) fn resolve_passive_installed(&self, method: crate::protocol::Method, originals: &mut crate::installed_runtime::PassiveRuntimeSlots,
        end: Instant, stop: &tokio::sync::watch::Receiver<bool>) -> Result<VerifiedRuntime, BridgeError> {
        let profile = self.passive_installed_profile()?;
        if !installed_passive_method(method.name()) {
            return Err(BridgeError::unavailable("This installed desktop profile supports only capabilities, catalog, project.snapshot, config.validate, config.suggest, config.preview, environment.requirements, github.setup.propose, release.version.observe, metadata.text.observe, metadata.text.validate and artifacts.candidate.observe."));
        }
        originals.inspect_once(profile, end, stop)
    }
    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    fn passive_installed_profile(&self) -> Result<PassiveInstalledProfile, BridgeError> {
        match self.passive_installed {
            PassiveInstalledSelection::Closed => Err(BridgeError::unavailable("The passive installed-runtime release and custody profile are not qualified.")),
            #[cfg(all(not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), any(test, feature = "desktop-shell")))]
            PassiveInstalledSelection::CandidateA => {
                if !PassiveInstalledProfile::bindings_match(COMPILED_TARGET, MANIFEST_ANCHOR, PROTOCOL_ANCHOR) { return Err(unavailable()); }
                Ok(PassiveInstalledProfile { _private: () })
            }
        }
    }
    /// Availability and original-owner admission use this SAME sealed selector.
    /// No caller path, environment flag, domain argument or passive test permit.
    pub(crate) fn configuration_edit_profile_available(&self) -> bool {
        #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
        { self.configuration_installed_profile().is_ok() }
        #[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu")))]
        { false }
    }
    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    fn configuration_installed_profile(&self) -> Result<ConfigurationInstalledProfile, BridgeError> {
        #[cfg(all(feature = "desktop-shell", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher")))]
        if ConfigurationInstalledProfile::bindings_match(COMPILED_TARGET, MANIFEST_ANCHOR, PROTOCOL_ANCHOR) {
            return Ok(ConfigurationInstalledProfile { _private: () });
        }
        Err(BridgeError::unavailable("The configuration installed-runtime release and custody profile are not qualified."))
    }
    /// Only the original configuration owner's registered worker may borrow
    /// these slots. The result is path DATA; it cannot spawn or carry custody.
    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    pub(crate) fn resolve_configuration_installed(&self, originals: &mut crate::installed_runtime::ConfigurationRuntimeSlots,
        end: Instant, stop: &tokio::sync::watch::Receiver<bool>) -> Result<VerifiedRuntime, BridgeError> {
        let profile = self.configuration_installed_profile()?; // Refuse other builds before inspection.
        originals.inspect_once(profile, end, stop)
    }
    /// Separate fixed entry point for the finite configuration owner. Never
    /// dispatch stateful work through the passive engine or its supervisor.
    pub fn resolve_edit(&self, end: Instant) -> Result<VerifiedRuntime, BridgeError> {
        #[cfg(all(feature = "development-runtime", debug_assertions))]
        {
            let mut runtime = self.development(end)?;
            let bootstrap = runtime.cwd.join("config_edit_bootstrap.py");
            anchored_path(&bootstrap)?;
            if !fs::metadata(&bootstrap).map_err(|_| unavailable())?.is_file() { return Err(unavailable()); }
            deadline(end)?;
            runtime.bootstrap = bootstrap;
            Ok(runtime)
        }
        #[cfg(not(all(feature = "development-runtime", debug_assertions)))]
        {
            let _ = end;
            Err(BridgeError::unavailable("Packaged configuration editing is disabled until its runtime custody and native owner are qualified."))
        }
    }
    /// Fixed diagnostics bootstrap, never the passive engine or edit protocol.
    /// These source/metadata checks do not qualify the neutral cwd, installed
    /// runtime custody, external tool policy or actual native document owner.
    pub(crate) fn resolve_environment_diagnostics(&self, end: Instant) -> Result<VerifiedRuntime, BridgeError> {
        #[cfg(all(feature = "development-runtime", debug_assertions))]
        {
            let mut runtime = self.development(end)?;
            #[cfg(all(test, debug_assertions, not(feature = "desktop-shell"),
                any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64"))))]
            if let Some(core) = &self.environment_fixture_core {
                // Closed R3 selection only; no change to passive/edit/Store
                // resolution and no mutable process-wide environment override.
                anchored_path(core)?;
                if !fs::metadata(core).map_err(|_| unavailable())?.is_file() || core.extension().is_none_or(|s| s != "zip") { return Err(unavailable()); }
                runtime.core = core.clone();
            }
            let bootstrap = runtime.cwd.join("environment_bootstrap.py");
            const BOOTSTRAP: &[u8] = include_bytes!("../../environment_bootstrap.py");
            if read_checked(&bootstrap, BOOTSTRAP.len() as u64, end)?.as_slice() != BOOTSTRAP { return Err(unavailable()); }
            deadline(end)?;
            runtime.bootstrap = bootstrap;
            Ok(runtime)
        }
        #[cfg(not(all(feature = "development-runtime", debug_assertions)))]
        {
            let _ = end;
            Err(BridgeError::unavailable("Packaged build-tool diagnostics remain disabled until their fixed runtime, native owner and neutral cwd are qualified."))
        }
    }
    /// Separate fixed saved-preflight bootstrap. The owner has its own closed
    /// native/runtime qualification flags; another domain's permit is unusable.
    pub(crate) fn resolve_offline_preflight(&self, end: Instant) -> Result<VerifiedRuntime, BridgeError> {
        #[cfg(all(feature = "development-runtime", debug_assertions))]
        {
            let mut runtime = self.development(end)?;
            let bootstrap = runtime.cwd.join("offline_preflight_bootstrap.py");
            const BOOTSTRAP: &[u8] = include_bytes!("../../offline_preflight_bootstrap.py");
            if read_checked(&bootstrap, BOOTSTRAP.len() as u64, end)?.as_slice() != BOOTSTRAP { return Err(unavailable()); }
            deadline(end)?;
            runtime.bootstrap = bootstrap;
            Ok(runtime)
        }
        #[cfg(not(all(feature = "development-runtime", debug_assertions)))]
        {
            let _ = end;
            Err(BridgeError::unavailable("Saved offline checks remain disabled until their original native owner, runtime custody and neutral cwd are qualified."))
        }
    }
    /// Android has its own fixed entry and owner qualification; an offline
    /// permit or successful path/hash inspection cannot authorize this domain.
    /// VerifiedRuntime is selection DATA, not immutable tool/runtime custody.
    pub(crate) fn resolve_android_build(&self, end: Instant) -> Result<VerifiedRuntime, BridgeError> {
        #[cfg(all(feature = "development-runtime", debug_assertions,
            target_os = "linux", target_env = "gnu", target_arch = "x86_64"))]
        {
            let mut runtime = self.development(end)?;
            let bootstrap = runtime.cwd.join("android_build_bootstrap.py");
            const BOOTSTRAP: &[u8] = include_bytes!("../../android_build_bootstrap.py");
            if read_checked(&bootstrap, BOOTSTRAP.len() as u64, end)?.as_slice() != BOOTSTRAP { return Err(unavailable()); }
            deadline(end)?;
            runtime.bootstrap = bootstrap;
            Ok(runtime)
        }
        #[cfg(not(all(feature = "development-runtime", debug_assertions,
            target_os = "linux", target_env = "gnu", target_arch = "x86_64")))]
        {
            let _ = end;
            Err(BridgeError::unavailable("Android builds remain disabled until their original native owner, protected toolchain and runtime custody are qualified for this platform."))
        }
    }
    /// Private profile, not another ambient development entry. The closed gate
    /// precedes even inspection. The latent branch additionally binds every
    /// selected path/CA byte to the existing explicit compiled manifest anchor;
    /// that inventory alone is never native/TLS or immutable custody authority.
    pub(crate) fn resolve_github_readonly(&self, end: Instant) -> Result<VerifiedRuntime, BridgeError> {
        if !GITHUB_TLS_PROFILE_QUALIFIED {
            return Err(BridgeError::unavailable("The GitHub read-only runtime and TLS profile are not qualified."));
        }
        #[cfg(all(feature = "development-runtime", debug_assertions, target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
        {
            deadline(end)?;
            // Still the same original retained blocking inspection/deadline.
            // No adjacent hash is inferred and no separate CA trust input exists.
            self.inspect_bundle_for_packaging(end)?;
            let python = self.bundle_root.join(PYTHON_RESOURCE);
            let core = self.bundle_root.join("core.zip");
            let selected = |name: &str| std::env::var_os(name).map(PathBuf::from).ok_or_else(unavailable);
            if selected("MRK_DESKTOP_DEV_PYTHON")? != python || selected("MRK_DESKTOP_DEV_CORE")? != core {
                return Err(BridgeError::unavailable("The GitHub development paths are not the fixed inventoried runtime profile."));
            }
            let bootstrap = self.bundle_root.join("github_connection_bootstrap.py");
            // The helper derives github-ca.pem only from this fixed sibling
            // directory. Never a CA argument, project cwd or environment path.
            deadline(end)?;
            Ok(VerifiedRuntime { python, core, bootstrap, cwd: self.bundle_root.clone() })
        }
        #[cfg(not(all(feature = "development-runtime", debug_assertions, target_os = "linux", target_arch = "x86_64", target_env = "gnu")))]
        {
            let _ = end;
            Err(BridgeError::unavailable("The GitHub read-only profile is not qualified for this runtime target."))
        }
    }
    /// Closed no-network hosted fixture only. The selection is minted privately
    /// after admitted Inputs and fixed Case files, never from an env enable.
    /// This remains the original retained inspection with its original endpoint;
    /// byte/roster checks are not TLS qualification or immutable runtime custody.
    #[cfg(all(test, debug_assertions, feature = "development-runtime", target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    pub(crate) fn resolve_github_fixture(&self, end: Instant,
        selection: &crate::supervisor::GitHubFixtureRuntime) -> Result<VerifiedRuntime, BridgeError> {
        fn fixture_inventory(core: &Path, expected: &BTreeSet<String>, end: Instant) -> Result<(), BridgeError> {
            exact_inventory(core, expected, end)?;
            // Packaged inventories exempt their root manifest. This fixed
            // fixture has no manifest or other fifth file/import route.
            match fs::symlink_metadata(core.join("manifest.json")) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {},
                _ => return Err(unavailable()),
            }
            deadline(end)
        }

        deadline(end)?;
        let (python, python_size, python_sha256) = selection.python_binding();
        let case = selection.case_bytes();
        if python_size == 0 || python_size > FILE_LIMIT || !sha(python_sha256)
            || case.is_empty() || case.len() > 16 * 1024 { return Err(unavailable()); }
        let mut runtime = self.development(end)?;
        if runtime.python.as_path() != python || runtime.core.as_path() != selection.core()
            || !fs::metadata(&runtime.core).map_err(|_| unavailable())?.is_dir() { return Err(unavailable()); }

        // Every G1 Case has exactly this source package. The passive member is
        // retained only for mixed-profile admission under the same Supervisor.
        let files: [(&str, &[u8]); 4] = [
            ("mobile_release/__init__.py", include_bytes!("../tests/fixtures/passive_core/__init__.py")),
            ("mobile_release/_desktop_engine.py", include_bytes!("../tests/fixtures/passive_core/_desktop_engine.py")),
            ("mobile_release/_desktop_github_engine.py", include_bytes!("../tests/fixtures/github_core/_desktop_github_engine.py")),
            ("mobile_release/case.json", case),
        ];
        let expected = files.iter().map(|(name, _)| (*name).to_owned()).collect::<BTreeSet<_>>();
        fixture_inventory(&runtime.core, &expected, end)?;
        if hash_checked(&runtime.python, python_size, end)? != python_sha256 { return Err(unavailable()); }
        for (name, bytes) in files {
            if read_checked(&runtime.core.join(name), bytes.len() as u64, end)?.as_slice() != bytes {
                return Err(unavailable());
            }
        }
        // Always the actual checkout's fixed bootstrap, not a selected path or
        // callback. No CA, TLS, live engine import or network permission follows.
        let bootstrap = runtime.cwd.join("github_connection_bootstrap.py");
        const BOOTSTRAP: &[u8] = include_bytes!("../../github_connection_bootstrap.py");
        if read_checked(&bootstrap, BOOTSTRAP.len() as u64, end)?.as_slice() != BOOTSTRAP { return Err(unavailable()); }
        fixture_inventory(&runtime.core, &expected, end)?;
        deadline(end)?;
        runtime.bootstrap = bootstrap;
        Ok(runtime)
    }
    /// Separate finite TLS fixture, never a production gate or an env-selected
    /// bootstrap. This is still the owner's original blocking inspection and
    /// endpoint. The private selection was minted against the compile-anchored
    /// source/runtime/CA/namespace manifest, not a version string or fake core.
    #[cfg(all(test, debug_assertions, feature = "development-runtime", target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    pub(crate) fn resolve_github_tls_fixture(&self, end: Instant,
        selection: &crate::supervisor::GitHubTlsRuntime) -> Result<VerifiedRuntime, BridgeError> {
        fn closed_inventory(root: &Path, names: &BTreeSet<String>, end: Instant) -> Result<(), BridgeError> {
            exact_inventory(root, names, end)?;
            // Unlike packaged payloads, neither TLS source nor its private
            // two-file bootstrap directory has an exempt root manifest.
            match fs::symlink_metadata(root.join("manifest.json")) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {},
                _ => return Err(unavailable()),
            }
            deadline(end)
        }
        deadline(end)?;
        let mut runtime = self.development(end)?;
        if runtime.python.as_path() != selection.python() || runtime.core.as_path() != selection.core()
            || selection.files().is_empty() || selection.files().len() > FILE_COUNT {
            return Err(unavailable());
        }
        // Includes the genuine source/ZIP, stdlib/import inputs, _ssl/_socket,
        // mapped loader/libssl/libcrypto, fixed peer/namespace and all six PEMs.
        // No TLS import, certificate generation or subprocess occurs here.
        let mut total = 0u64;
        closed_inventory(selection.source(), selection.source_files(), end)?;
        for item in selection.files() {
            let (path, size, expected) = item.parts();
            if size > FILE_LIMIT || !sha(expected) { return Err(unavailable()); }
            total = total.checked_add(size).ok_or_else(unavailable)?;
            if total > TOTAL_LIMIT || hash_checked(path, size, end)? != expected { return Err(unavailable()); }
        }
        // Source mode and ZIP mode share the exact genuine implementation. The
        // ZIP's admitted bytes are independently bound above, not rebuilt here.
        let sources: [(&str, &[u8]); 4] = [
            ("mobile_release/__init__.py", include_bytes!("../../../src/mobile_release/__init__.py")),
            ("mobile_release/api/__init__.py", include_bytes!("../../../src/mobile_release/api/__init__.py")),
            ("mobile_release/_desktop_github_engine.py", include_bytes!("../../../src/mobile_release/_desktop_github_engine.py")),
            ("mobile_release/_github_connection_transport.py", include_bytes!("../../../src/mobile_release/_github_connection_transport.py")),
        ];
        for (name, bytes) in sources {
            if read_checked(&selection.source().join(name), bytes.len() as u64, end)?.as_slice() != bytes { return Err(unavailable()); }
        }
        let bootstrap = selection.bootstrap();
        let cwd = bootstrap.parent().ok_or_else(unavailable)?;
        if !bootstrap.file_name().is_some_and(|name| name == "github_connection_bootstrap.py")
            || selection.trust().is_empty() || selection.trust().len() as u64 > GITHUB_CA_LIMIT { return Err(unavailable()); }
        const BOOTSTRAP: &[u8] = include_bytes!("../../github_connection_bootstrap.py");
        let private_files = ["github_connection_bootstrap.py".to_owned(), "github-ca.pem".to_owned()]
            .into_iter().collect::<BTreeSet<_>>();
        closed_inventory(cwd, &private_files, end)?;
        if read_checked(bootstrap, BOOTSTRAP.len() as u64, end)?.as_slice() != BOOTSTRAP
            || read_checked(&cwd.join("github-ca.pem"), GITHUB_CA_LIMIT, end)?.as_slice() != selection.trust() {
            return Err(unavailable());
        }
        closed_inventory(selection.source(), selection.source_files(), end)?;
        closed_inventory(cwd, &private_files, end)?;
        deadline(end)?;
        // The live factory derives its only trust input from this exact private
        // bootstrap's sibling. Never from the checkout cwd, an argv CA or URL.
        runtime.bootstrap = bootstrap.to_path_buf();
        runtime.cwd = cwd.to_path_buf();
        Ok(runtime)
    }
    /// Unqualified preparation helper only; no application command calls this,
    /// and its result intentionally contains no executable/bootstrap/core paths.
    pub fn inspect_bundle_for_packaging(&self, end: Instant) -> Result<BundleInspection, BridgeError> {
        let manifest_anchor = MANIFEST_ANCHOR.filter(|value| sha(value)).ok_or_else(unavailable)?;
        let protocol_anchor = PROTOCOL_ANCHOR.filter(|value| sha(value)).ok_or_else(unavailable)?;
        let bytes = read_checked(&self.bundle_root.join("manifest.json"), MANIFEST_LIMIT, end)?;
        if digest(&bytes) != manifest_anchor { return Err(unavailable()); }
        let manifest: Manifest = serde_json::from_value(strict_json(&bytes).map_err(|_| unavailable())?).map_err(|_| unavailable())?;
        if manifest.schema_version != 1 || manifest.protocol != PROTOCOL || manifest.core_version != CORE_VERSION
            || manifest.target != COMPILED_TARGET || manifest.protocol_sha256 != protocol_anchor
            || !sha(&manifest.core_sha256) || !sha(&manifest.inventory_sha256)
            || manifest.files.is_empty() || manifest.files.len() > FILE_COUNT { return Err(unavailable()); }
        let inventory = serde_json::to_vec(&manifest.files).map_err(|_| unavailable())?;
        if digest(&inventory) != manifest.inventory_sha256 { return Err(unavailable()); }
        let mut files = BTreeSet::new();
        let mut folded = BTreeSet::new();
        let mut previous: Option<&str> = None;
        let mut total = 0u64;
        for item in &manifest.files {
            if !safe_payload_path(&item.path) || item.path == "manifest.json" || !sha(&item.sha256)
                || item.size > FILE_LIMIT
                || item.path == "github-ca.pem" && (item.size == 0 || item.size > GITHUB_CA_LIMIT)
                || previous.is_some_and(|value| value >= item.path.as_str())
                || !files.insert(item.path.clone()) || !folded.insert(item.path.to_ascii_lowercase()) { return Err(unavailable()); }
            total = total.checked_add(item.size).ok_or_else(unavailable)?;
            if total > TOTAL_LIMIT { return Err(unavailable()); }
            previous = Some(&item.path);
            if item.path == "core.zip" && item.sha256 != manifest.core_sha256 { return Err(unavailable()); }
        }
        for required in REQUIRED_RUNTIME_RESOURCES {
            if !files.contains(required) { return Err(unavailable()); }
        }
        exact_inventory(&self.bundle_root, &files, end)?;
        for item in &manifest.files {
            if hash_checked(&self.bundle_root.join(&item.path), item.size, end)? != item.sha256 { return Err(unavailable()); }
        }
        // Check the selected names and complete inventory again after hashing.
        exact_inventory(&self.bundle_root, &files, end)?;
        Ok(BundleInspection { files: manifest.files.len(), target: manifest.target })
    }

    #[cfg(all(feature = "development-runtime", debug_assertions))]
    fn development(&self, end: Instant) -> Result<VerifiedRuntime, BridgeError> {
        fn selected(name: &str) -> Result<PathBuf, BridgeError> {
            let value = std::env::var_os(name).ok_or_else(|| BridgeError::unavailable("Explicit development Python/core paths are not configured."))?;
            let path = PathBuf::from(value);
            anchored_path(&path)?;
            Ok(path)
        }
        deadline(end)?;
        let python = selected("MRK_DESKTOP_DEV_PYTHON")?;
        let core = selected("MRK_DESKTOP_DEV_CORE")?;
        let bootstrap = Path::new(env!("CARGO_MANIFEST_DIR")).parent().ok_or_else(unavailable)?.join("engine_bootstrap.py");
        anchored_path(&bootstrap)?;
        if !fs::metadata(&python).map_err(|_| unavailable())?.is_file()
            || !fs::metadata(&bootstrap).map_err(|_| unavailable())?.is_file() { return Err(unavailable()); }
        let core_metadata = fs::metadata(&core).map_err(|_| unavailable())?;
        if !core_metadata.is_dir() && !(core_metadata.is_file() && core.extension().is_some_and(|extension| extension == "zip")) { return Err(unavailable()); }
        Ok(VerifiedRuntime { python, core, cwd: bootstrap.parent().ok_or_else(unavailable)?.to_path_buf(), bootstrap })
    }
}

#[cfg(all(test, target_os = "linux", target_arch = "x86_64", target_env = "gnu", feature = "desktop-shell",
    not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher")))]
pub(crate) fn assert_packaged_shell_allowlist_contract() {
    let runtime = RuntimeConfig::packaged(PathBuf::from("/inert-shell-path-must-not-be-opened"));
    assert!(matches!(runtime.passive_installed, PassiveInstalledSelection::CandidateA));
    let bindings = PassiveInstalledProfile::bindings_match(COMPILED_TARGET, MANIFEST_ANCHOR, PROTOCOL_ANCHOR);
    assert_eq!(runtime.project_selection_profile_available(), bindings);
    assert_eq!(runtime.configuration_edit_profile_available(), bindings);
    for name in ["capabilities", "catalog", "project.snapshot", "config.validate", "config.suggest", "config.preview",
        "environment.requirements", "github.setup.propose", "release.version.observe", "metadata.text.observe", "metadata.text.validate", "artifacts.candidate.observe"] {
        assert_eq!(runtime.passive_method_available(name), bindings);
    }
    for name in ["credentials.assess", "config.save", "metadata.text.prepare",
        "metadata.text.apply", "unknown"] {
        assert!(!runtime.passive_method_available(name));
    }
    let mut originals = crate::installed_runtime::PassiveRuntimeSlots::new();
    let (_sender, stop) = tokio::sync::watch::channel(false);
    assert!(runtime.resolve_passive_installed(crate::protocol::Method::AssessCredentials, &mut originals, Instant::now(), &stop).is_err());
    assert!(originals.never_started());
    assert!(runtime.resolve(Instant::now()).is_err());
    assert!(runtime.resolve_edit(Instant::now()).is_err());
}

#[cfg(all(test, target_os = "linux", target_arch = "x86_64", target_env = "gnu", feature = "desktop-shell",
    not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher")))]
pub(crate) fn assert_installed_configuration_profile_contract() {
    tests::configuration_candidate_bindings_are_exactly_a_not_an_arbitrary_anchor();
    tests::installed_configuration_data_is_fixed_and_stopped_inspection_owes_original_settlement();
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn installed_allowlist_is_exactly_the_read_only_project_draft_guidance_and_saved_services() {
        for name in ["capabilities", "catalog", "project.snapshot", "config.validate", "config.suggest", "config.preview",
            "environment.requirements", "github.setup.propose", "release.version.observe", "metadata.text.observe", "metadata.text.validate", "artifacts.candidate.observe"] {
            assert!(installed_passive_method(name));
        }
        for name in ["", "unknown", "config.save", "config.apply", "config.initialize", "metadata.text.prepare",
            "metadata.text.apply", "credentials.assess", "artifacts.candidate.observe ", "Artifacts.Candidate.Observe",
            "project.snapshot ", "Config.Validate", "environment.requirements ", "GitHub.Setup.Propose",
            "Release.Version.Observe", "metadata.text.observe ", "Metadata.Text.Validate"] {
            assert!(!installed_passive_method(name));
        }
    }
    #[test]
    fn payload_names_are_portable_and_unambiguous() {
        assert_eq!(REQUIRED_RUNTIME_RESOURCES, [
            "android_build_bootstrap.py", "config_edit_bootstrap.py", "core.zip",
            "engine_bootstrap.py", "environment_bootstrap.py", "github-ca.pem",
            "github_connection_bootstrap.py", "offline_preflight_bootstrap.py", PYTHON_RESOURCE,
        ]);
        for name in REQUIRED_RUNTIME_RESOURCES { assert!(safe_payload_path(name)); }
        assert!(safe_payload_path("python/lib/libstdc++.so.6"));
        for name in ["", "/core.zip", "../core.zip", "a/./b", "a//b", "a\\b", "a:b", "NUL.txt", "com1", "LPT9.log", "trailing.", "x ", "é.py"] { assert!(!safe_payload_path(name)); }
    }
    #[cfg(not(all(feature = "development-runtime", debug_assertions)))]
    #[test]
    fn production_gate_does_not_open_even_a_missing_bundle() {
        let runtime = RuntimeConfig::packaged(PathBuf::from("/this-path-must-not-be-opened"));
        assert_eq!(runtime.resolve(Instant::now() + std::time::Duration::from_secs(1)).err().map(|error| error.code), Some("runtime_unavailable".into()));
    }
    #[test]
    fn github_profile_gate_refuses_before_inventory_or_development_selection() {
        assert!(!GITHUB_TLS_PROFILE_QUALIFIED);
        let runtime = RuntimeConfig::packaged(PathBuf::from("/inert-github-path-must-not-be-opened"));
        let error = runtime.resolve_github_readonly(Instant::now()).unwrap_err();
        assert_eq!(error.code, "runtime_unavailable");
        assert_eq!(error.message, "The GitHub read-only runtime and TLS profile are not qualified.");
    }
    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu",
        not(all(feature = "desktop-shell", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher")))))]
    #[test]
    fn passive_installed_profile_refuses_an_inert_bundle_before_inspection() {
        // A pathname is DATA only: no channel, task, descriptor or profile.
        // The owner seam calls this exact gate before any inspection effect.
        let runtime = RuntimeConfig::packaged(PathBuf::from("/inert-passive-path-must-not-be-opened"));
        assert!(!runtime.project_selection_profile_available());
        let error = runtime.passive_installed_profile().err().unwrap();
        assert_eq!(error.code, "runtime_unavailable");
        assert_eq!(error.message, "The passive installed-runtime release and custody profile are not qualified.");
    }
    #[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu", feature = "desktop-shell",
        not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"))))]
    #[test]
    fn installed_configuration_selector_is_closed_outside_the_normal_linux_shell() {
        let runtime = RuntimeConfig::packaged(PathBuf::from("/inert-config-path-must-not-be-opened"));
        assert!(!runtime.configuration_edit_profile_available());
        #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
        {
            let mut slots = crate::installed_runtime::ConfigurationRuntimeSlots::new();
            let (_sender, stop) = tokio::sync::watch::channel(false);
            assert!(runtime.resolve_configuration_installed(&mut slots, Instant::now(), &stop).is_err());
            assert!(slots.never_started() && !slots.settled()); // Selector refusal before ANY inspection.
            assert!(slots.capability().is_err());
        }
    }
    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    #[test]
    fn configuration_candidate_bindings_data_contract() { configuration_candidate_bindings_are_exactly_a_not_an_arbitrary_anchor(); }
    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    pub(super) fn configuration_candidate_bindings_are_exactly_a_not_an_arbitrary_anchor() {
        let (target, manifest, protocol) = (PassiveInstalledProfile::TARGET, PassiveInstalledProfile::MANIFEST, PassiveInstalledProfile::PROTOCOL);
        assert!(ConfigurationInstalledProfile::bindings_match(target, Some(manifest), Some(protocol)));
        let wrong = "0".repeat(64);
        for (target, manifest, protocol) in [
            ("aarch64-unknown-linux-gnu", Some(manifest), Some(protocol)), (target, None, Some(protocol)),
            (target, Some(manifest), None), (target, Some(wrong.as_str()), Some(protocol)), (target, Some(manifest), Some(wrong.as_str())),
        ] { assert!(!ConfigurationInstalledProfile::bindings_match(target, manifest, protocol)); }
    }
    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu", feature = "desktop-shell",
        not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher")))]
    #[test]
    fn installed_configuration_profile_contract_is_inert() { assert_installed_configuration_profile_contract(); }
    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu", feature = "desktop-shell",
        not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher")))]
    pub(super) fn installed_configuration_data_is_fixed_and_stopped_inspection_owes_original_settlement() {
        // Even in the selected shell this test performs NO uname/open/close or
        // child work: sticky STOP refuses before the first native checkpoint.
        let runtime = RuntimeConfig::packaged(PathBuf::from("/inert-config-data-only"));
        let profile = runtime.configuration_installed_profile();
        assert_eq!(runtime.configuration_edit_profile_available(), profile.is_ok());
        assert_eq!(profile.is_ok(), ConfigurationInstalledProfile::bindings_match(COMPILED_TARGET, MANIFEST_ANCHOR, PROTOCOL_ANCHOR));
        if let Ok(profile) = profile {
            let data = profile.selection().unwrap();
            let root = PathBuf::from("/var/lib/mobile-release-kit/versions").join(PassiveInstalledProfile::TARGET).join(PassiveInstalledProfile::MANIFEST);
            assert_eq!(data.python, root.join("python/bin/python3"));
            assert_eq!(data.bootstrap, root.join("config_edit_bootstrap.py"));
            assert_eq!(data.core, root.join("core.zip")); assert_eq!(data.cwd, root);
            assert!(profile.accepts_platform(b"Linux", b"x86_64", b"6.17.0-1022-azure"));
            for release in [b"6.8.0-91-generic".as_slice(), b"6.17.0-1021-azure", b"6.17.0-1022-azure-custom"] {
                assert!(!profile.accepts_platform(b"Linux", b"x86_64", release));
            }
            assert!(!profile.accepts_platform(b"Linux", b"aarch64", b"6.17.0-1022-azure"));
            assert!(!profile.accepts_platform(b"FreeBSD", b"x86_64", b"6.17.0-1022-azure"));
            let mut slots = crate::installed_runtime::ConfigurationRuntimeSlots::new();
            let (_sender, stop) = tokio::sync::watch::channel(true);
            assert!(runtime.resolve_configuration_installed(&mut slots, Instant::now() + std::time::Duration::from_secs(1), &stop).is_err());
            assert!(!slots.never_started() && !slots.settled() && slots.no_child_effect());
            assert!(slots.transfer_once().is_err() && slots.capability().is_err());
            assert_eq!(slots.settle_originals(), crate::installed_runtime::CloseOutcome::Settled); // Empty; not a native close witness.
            assert!(slots.settled() && slots.capability().is_err());
        }
        assert!(runtime.resolve(Instant::now()).is_err());
        assert!(runtime.resolve_edit(Instant::now()).is_err());
    }
    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    #[test]
    fn passive_candidate_bindings_are_exact_data_not_digest_shape() {
        let (target, manifest, protocol) = (PassiveInstalledProfile::TARGET, PassiveInstalledProfile::MANIFEST, PassiveInstalledProfile::PROTOCOL);
        assert!(PassiveInstalledProfile::bindings_match(target, Some(manifest), Some(protocol)));
        let different = "0".repeat(64);
        for (target, manifest, protocol) in [
            ("aarch64-unknown-linux-gnu", Some(manifest), Some(protocol)),
            (target, None, Some(protocol)), (target, Some(manifest), None),
            (target, Some(different.as_str()), Some(protocol)), (target, Some(manifest), Some(different.as_str())),
        ] { assert!(!PassiveInstalledProfile::bindings_match(target, manifest, protocol)); }
    }
    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu", feature = "desktop-shell",
        not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher")))]
    #[test]
    fn packaged_shell_selects_only_fixed_passive_data_without_opening_other_methods() {
        assert_packaged_shell_allowlist_contract();
    }
    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu",
        not(feature = "development-runtime"), not(feature = "desktop-shell"), not(feature = "ubuntu-runtime-publisher")))]
    #[test]
    fn passive_candidate_selects_only_fixed_data_and_never_opens_path_launch() {
        // No native inspection or capability is performed/fabricated here.
        let candidate = RuntimeConfig::installed_passive_candidate_a();
        assert!(matches!(candidate.passive_installed, PassiveInstalledSelection::CandidateA));
        assert!(!candidate.project_selection_profile_available());
        assert!(!candidate.configuration_edit_profile_available());
        let packaged = RuntimeConfig::packaged(PathBuf::from("/inert-passive-candidate-path"));
        assert!(matches!(packaged.passive_installed, PassiveInstalledSelection::Closed));
        assert!(packaged.passive_installed_profile().is_err());
        assert!(candidate.resolve(Instant::now()).is_err());
        assert!(candidate.resolve_edit(Instant::now()).is_err());
        let mut configuration = crate::installed_runtime::ConfigurationRuntimeSlots::new();
        let mut originals = crate::installed_runtime::PassiveRuntimeSlots::new();
        let (_sender, stop) = tokio::sync::watch::channel(false);
        assert!(candidate.resolve_configuration_installed(&mut configuration, Instant::now(), &stop).is_err());
        assert!(configuration.never_started()); // Passive candidate never acquires configuration authority.
        assert!(candidate.resolve_passive_installed(crate::protocol::Method::AssessCredentials, &mut originals, Instant::now(), &stop).is_err());
        assert!(originals.never_started()); // An unselected method cannot begin inspection.
        let profile = candidate.passive_installed_profile();
        assert_eq!(profile.is_ok(), PassiveInstalledProfile::bindings_match(COMPILED_TARGET, MANIFEST_ANCHOR, PROTOCOL_ANCHOR));
        if let Ok(profile) = profile {
            let data = profile.selection().unwrap();
            let root = PathBuf::from("/var/lib/mobile-release-kit/versions").join(PassiveInstalledProfile::TARGET).join(PassiveInstalledProfile::MANIFEST);
            assert_eq!(data.cwd, root);
            assert_eq!(data.python, root.join("python/bin/python3"));
            assert_eq!(data.bootstrap, root.join("engine_bootstrap.py"));
            assert_eq!(data.core, root.join("core.zip"));
            assert!(profile.accepts_platform(b"Linux", b"x86_64", b"6.17.0-1022-azure"));
            for release in [b"6.8.0-91-generic".as_slice(), b"6.17.0-1021-azure", b"6.17.0-1022-azure-custom"] {
                assert!(!profile.accepts_platform(b"Linux", b"x86_64", release));
            }
            assert!(!profile.accepts_platform(b"Linux", b"aarch64", b"6.17.0-1022-azure"));
            assert!(!profile.accepts_platform(b"FreeBSD", b"x86_64", b"6.17.0-1022-azure"));
        }
    }
}
