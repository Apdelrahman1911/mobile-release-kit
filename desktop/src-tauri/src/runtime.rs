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
    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    installed_session: InstalledSessionSelection,
    #[cfg(all(test, debug_assertions, feature = "development-runtime", not(feature = "desktop-shell"),
        any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64"))))]
    environment_fixture_core: Option<PathBuf>,
}

#[derive(Debug)]
pub struct VerifiedRuntime { pub python: PathBuf, pub bootstrap: PathBuf, pub core: PathBuf, pub cwd: PathBuf }

// Explicit compile inputs bind the successor staged payload. Neither a nearby
// manifest nor environment data at app launch can select or qualify a release.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn macos_bindings() -> bool {
    COMPILED_TARGET == "aarch64-apple-darwin" && MANIFEST_ANCHOR.is_some_and(sha)
        && PROTOCOL_ANCHOR == Some(crate::installed_runtime::PROTOCOL_SHA)
        && cfg!(all(feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"),
            not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer")))
}
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) struct PassiveInstalledProfile { _private: () }
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) struct ConfigurationInstalledProfile { _private: () }
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl PassiveInstalledProfile {
    pub(crate) fn selection(&self) -> Result<VerifiedRuntime, BridgeError> {
        if !macos_bindings() { return Err(unavailable()); }
        let cwd = crate::installed_runtime::runtime_root();
        Ok(VerifiedRuntime { python: cwd.join("python/bin/python3"), bootstrap: cwd.join("engine_bootstrap.py"), core: cwd.join("core.zip"), cwd })
    }
}
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl ConfigurationInstalledProfile {
    pub(crate) fn selection(&self) -> Result<VerifiedRuntime, BridgeError> {
        if !macos_bindings() { return Err(unavailable()); }
        let cwd = crate::installed_runtime::runtime_root();
        Ok(VerifiedRuntime { python: cwd.join("python/bin/python3"), bootstrap: cwd.join("config_edit_bootstrap.py"), core: cwd.join("core.zip"), cwd })
    }
}
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn macos_installed_environment(command: &mut tokio::process::Command) -> std::io::Result<()> {
    let uid = mrk_macos_installed_native::real_user()?;
    command.env("__CF_USER_TEXT_ENCODING", format!("0x{uid:X}:0:0"));
    Ok(())
}

// Selection DATA only, never executable custody. Only the fixed Linux shell
// and its feature-off native tests can select the independently admitted A.
#[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
#[derive(Clone, Copy)]
enum PassiveInstalledSelection {
    Closed,
    #[cfg(all(not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), any(test, feature = "desktop-shell")))]
    CandidateA,
}

// Separate, initially CLOSED four-kind session selection. A working project
// picker or the twelve-method passive profile does not grant collection/R1.
// Activation of the normal constructor requires genuine installed-session
// qualification and a separately reviewed activation change.
pub(crate) const INSTALLED_SESSION_INPUTS_QUALIFIED: bool = false;

#[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
struct InstalledSessionOriginal {
    supervisor_claimed: std::sync::atomic::AtomicBool,
    document: std::sync::Mutex<Option<std::sync::Weak<()>>>,
    enabled: std::sync::atomic::AtomicBool,
}
#[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
#[derive(Clone)]
struct InstalledSessionSelection {
    original: std::sync::Arc<InstalledSessionOriginal>,
    supervisor: bool,
}
#[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
impl InstalledSessionSelection {
    fn new() -> Self {
        use std::sync::{Arc, Mutex, atomic::AtomicBool};
        Self { original: Arc::new(InstalledSessionOriginal {
            supervisor_claimed: AtomicBool::new(false), document: Mutex::new(None),
            enabled: AtomicBool::new(INSTALLED_SESSION_INPUTS_QUALIFIED),
        }), supervisor: false }
    }
    fn claim_supervisor(&mut self) {
        // RuntimeConfig clones share this ONE claim. Inspection copies of the
        // already-bound original remain usable, but a second Supervisor::new
        // never inherits its session admission.
        self.supervisor = !self.original.supervisor_claimed.swap(true, std::sync::atomic::Ordering::SeqCst);
    }
    fn bind_document(&self, identity: &std::sync::Arc<()>) {
        if !self.supervisor { return; }
        let Ok(mut document) = self.original.document.lock() else { return; };
        // Even a dead original leaves its Weak tombstone: no later document
        // can rebind this Supervisor or reuse its one-use qualification.
        if document.is_none() { *document = Some(std::sync::Arc::downgrade(identity)); }
    }
    fn matches(&self, identity: Option<&std::sync::Arc<()>>) -> bool {
        if !self.supervisor || !self.original.enabled.load(std::sync::atomic::Ordering::SeqCst) { return false; }
        let Ok(document) = self.original.document.lock() else { return false; };
        document.as_ref().and_then(std::sync::Weak::upgrade)
            .is_some_and(|original| identity.is_none_or(|identity| std::sync::Arc::ptr_eq(&original, identity)))
    }
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol",
        not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher")))]
    fn admit_once(&self, identity: &std::sync::Arc<()>) -> Result<(), BridgeError> {
        if !self.supervisor || INSTALLED_SESSION_INPUTS_QUALIFIED { return Err(unavailable()); }
        let document = self.original.document.lock().map_err(|_| unavailable())?;
        if !document.as_ref().and_then(std::sync::Weak::upgrade)
            .is_some_and(|original| std::sync::Arc::ptr_eq(&original, identity)) { return Err(unavailable()); }
        self.original.enabled.compare_exchange(false, true, std::sync::atomic::Ordering::SeqCst,
            std::sync::atomic::Ordering::SeqCst).map_err(|_| unavailable())?;
        Ok(())
    }
}

#[cfg(all(test, target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
pub(crate) fn assert_installed_session_selection_contract() {
    use std::sync::{Arc, atomic::Ordering};
    // Pure shared-selection bookkeeping only. No installed runtime is opened.
    let mut first = InstalledSessionSelection::new();
    let mut other = first.clone();
    first.claim_supervisor(); other.claim_supervisor();
    let original = Arc::new(()); let replacement = Arc::new(());
    other.bind_document(&replacement); first.bind_document(&original);
    first.bind_document(&replacement);
    first.original.enabled.store(false, Ordering::SeqCst);
    assert!(!first.matches(Some(&original)) && !other.matches(Some(&replacement)));
    first.original.enabled.store(true, Ordering::SeqCst);
    assert!(first.matches(Some(&original)) && first.clone().matches(Some(&original)));
    assert!(!first.matches(Some(&replacement)) && !other.matches(None));
    let mut second_supervisor = first.clone(); second_supervisor.claim_supervisor();
    assert!(!second_supervisor.matches(Some(&original)));
    drop(original); first.bind_document(&replacement);
    assert!(!first.matches(None)); // Dead original remains a non-rebindable tombstone.
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

// The same authenticated A contains the existing workflow bootstrap/core, but
// Configuration or passive selection is NOT authority for this edit domain.
// Only the normal installed workflow selector below can mint this profile.
#[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
pub(crate) struct GitHubWorkflowInstalledProfile { _private: () }

#[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
impl GitHubWorkflowInstalledProfile {
    fn bindings_match(target: &str, manifest: Option<&str>, protocol: Option<&str>) -> bool {
        PassiveInstalledProfile::bindings_match(target, manifest, protocol) // Fixed DATA only.
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
pub(crate) struct Manifest {
    pub(crate) schema_version: u32, pub(crate) protocol: u32, pub(crate) core_version: String, pub(crate) target: String,
    pub(crate) core_sha256: String, pub(crate) protocol_sha256: String, pub(crate) inventory_sha256: String,
    pub(crate) files: Vec<PayloadFile>,
}

// Field order is intentional: compact serde JSON == Python sorted-key JSON.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PayloadFile { pub(crate) path: String, pub(crate) sha256: String, pub(crate) size: u64 }

fn unavailable() -> BridgeError { BridgeError::unavailable("The packaged runtime is absent, incompatible, or fails its trusted inventory.") }
// Scope DATA, not a release/custody permit. Keep the Mac draft-only surface
// separate: selecting a real project must not inherit Linux C/P2 services.
fn macos_installed_passive_method(name: &str) -> bool {
    matches!(name, "capabilities" | "catalog" | "project.snapshot" | "config.validate" | "config.suggest" | "config.preview"
        | "environment.requirements" | "github.setup.propose")
}
fn linux_installed_passive_method(name: &str) -> bool {
    macos_installed_passive_method(name) || matches!(name,
        "release.version.observe" | "metadata.text.observe" | "metadata.text.validate" | "artifacts.candidate.observe")
}
fn installed_passive_method(name: &str) -> bool {
    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    { linux_installed_passive_method(name) }
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    { macos_installed_passive_method(name) }
    #[cfg(not(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),
        all(target_os = "macos", target_arch = "aarch64"))))]
    { let _ = name; false }
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
        #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
        installed_session: InstalledSessionSelection::new(),
        #[cfg(all(test, debug_assertions, feature = "development-runtime", not(feature = "desktop-shell"),
            any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64"))))]
        environment_fixture_core: None,
    } }
    pub(crate) fn claim_original_supervisor(&mut self) {
        #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
        self.installed_session.claim_supervisor();
    }
    pub(crate) fn bind_original_session_document(&self, identity: &std::sync::Arc<()>) {
        #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
        self.installed_session.bind_document(identity);
        #[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu")))]
        let _ = identity;
    }
    fn installed_session_profile(&self, identity: Option<&std::sync::Arc<()>>) -> bool {
        #[cfg(all(feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"),
            not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
        { self.passive_installed_profile().is_ok() && self.installed_session.matches(identity) }
        #[cfg(not(all(feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"),
            not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu")))]
        { let _ = identity; false }
    }
    pub(crate) fn installed_session_available(&self, identity: &std::sync::Arc<()>) -> bool {
        self.installed_session_profile(Some(identity))
    }
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol",
        not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"),
        target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    pub(crate) fn admit_installed_session_once(&self, identity: &std::sync::Arc<()>) -> Result<(), BridgeError> {
        self.passive_installed_profile()?;
        self.installed_session.admit_once(identity)
    }
    fn installed_method_available(&self, name: &str) -> bool {
        installed_passive_method(name) || name == "credentials.assess" && self.installed_session_profile(None)
    }
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
        { self.installed_method_available(name) && self.passive_installed_profile().is_ok() }
        #[cfg(all(not(all(feature = "development-runtime", debug_assertions)), target_os = "macos", target_arch = "aarch64"))]
        { installed_passive_method(name) && self.passive_installed_profile().is_ok() }
        #[cfg(all(not(all(feature = "development-runtime", debug_assertions)), not(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64")))))]
        { let _ = name; false }
    }
    /// Fixed selection DATA for the project-only picker, not an asset session
    /// qualification or a substitute for its original document/lifecycle gate.
    /// Even the feature-off passive candidate cannot select this shell route.
    pub(crate) fn project_selection_profile_available(&self) -> bool {
        #[cfg(all(feature = "desktop-shell", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"),
            target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
        { self.passive_installed_profile().is_ok() }
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        { self.passive_installed_profile().is_ok() }
        #[cfg(not(any(all(feature = "desktop-shell", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"),
            target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64"))))]
        { false }
    }
    /// Separate P2 selection DATA. A project-only Mac profile is never a
    /// descendant-path picker permit; keep the existing Linux selection exact.
    pub(crate) fn project_path_selection_profile_available(&self) -> bool {
        #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
        { self.project_selection_profile_available() }
        #[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu")))]
        { false }
    }
    /// Separate C picker DATA. The native method intersection is checked again
    /// by DocumentBinding; neither a Mac project nor an asset fixture grants C.
    pub(crate) fn evidence_selection_profile_available(&self) -> bool {
        #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
        { self.project_selection_profile_available() }
        #[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu")))]
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
        if !self.installed_method_available(method.name()) {
            return Err(BridgeError::unavailable("This installed desktop method is outside the selected passive/session profile."));
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
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn passive_installed_profile(&self) -> Result<PassiveInstalledProfile, BridgeError> {
        if macos_bindings() { Ok(PassiveInstalledProfile { _private: () }) } else { Err(unavailable()) }
    }
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    pub(crate) fn resolve_passive_installed(&self, method: crate::protocol::Method, originals: &mut crate::installed_runtime::PassiveRuntimeSlots,
        end: Instant, stop: &tokio::sync::watch::Receiver<bool>) -> Result<VerifiedRuntime, BridgeError> {
        let profile = self.passive_installed_profile()?;
        if !installed_passive_method(method.name()) { return Err(BridgeError::unavailable("This Mac installed profile supports only the eight passive project/draft/guidance methods.")); }
        originals.inspect_once(profile, end, stop)
    }
    /// Availability and original-owner admission use this SAME sealed selector.
    /// No caller path, environment flag, domain argument or passive test permit.
    pub(crate) fn configuration_edit_profile_available(&self) -> bool {
        #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
        { self.configuration_installed_profile().is_ok() }
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        { self.configuration_installed_profile().is_ok() }
        #[cfg(not(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64"))))]
        { false }
    }
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn configuration_installed_profile(&self) -> Result<ConfigurationInstalledProfile, BridgeError> {
        if macos_bindings() { Ok(ConfigurationInstalledProfile { _private: () }) } else { Err(unavailable()) }
    }
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    pub(crate) fn resolve_configuration_installed(&self, originals: &mut crate::installed_runtime::ConfigurationRuntimeSlots,
        end: Instant, stop: &tokio::sync::watch::Receiver<bool>) -> Result<VerifiedRuntime, BridgeError> {
        originals.inspect_once(self.configuration_installed_profile()?, end, stop)
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
    /// SAME sealed workflow selector for capability and original-owner admission.
    /// Neither another edit profile nor a feature-off native test can select it.
    pub(crate) fn github_workflow_edit_profile_available(&self) -> bool {
        #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
        { self.github_workflow_installed_profile().is_ok() }
        #[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu")))]
        { false }
    }
    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    fn github_workflow_installed_profile(&self) -> Result<GitHubWorkflowInstalledProfile, BridgeError> {
        #[cfg(all(feature = "desktop-shell", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher")))]
        if GitHubWorkflowInstalledProfile::bindings_match(COMPILED_TARGET, MANIFEST_ANCHOR, PROTOCOL_ANCHOR) {
            return Ok(GitHubWorkflowInstalledProfile { _private: () });
        }
        Err(BridgeError::unavailable("The GitHub workflow installed-runtime release and custody profile are not qualified."))
    }
    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    pub(crate) fn resolve_github_workflow_installed(&self, originals: &mut crate::installed_runtime::GitHubWorkflowRuntimeSlots,
        end: Instant, stop: &tokio::sync::watch::Receiver<bool>) -> Result<VerifiedRuntime, BridgeError> {
        // The registered original worker borrows its domain-bound slots. The
        // returned paths are DATA; they cannot carry the ledger or spawn.
        originals.inspect_once(self.github_workflow_installed_profile()?, end, stop)
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
    assert_eq!(runtime.github_workflow_edit_profile_available(), bindings);
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

#[cfg(all(test, target_os = "linux", target_arch = "x86_64", target_env = "gnu", feature = "desktop-shell",
    not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher")))]
pub(crate) fn assert_installed_workflow_profile_contract() {
    tests::workflow_candidate_bindings_are_exactly_a_not_an_arbitrary_anchor();
    tests::installed_workflow_data_is_fixed_and_stopped_inspection_owes_original_settlement();
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn installed_allowlist_is_exactly_the_read_only_project_draft_guidance_and_saved_services() {
        for name in ["capabilities", "catalog", "project.snapshot", "config.validate", "config.suggest", "config.preview",
            "environment.requirements", "github.setup.propose", "release.version.observe", "metadata.text.observe", "metadata.text.validate", "artifacts.candidate.observe"] {
            assert!(linux_installed_passive_method(name));
        }
        for name in ["", "unknown", "config.save", "config.apply", "config.initialize", "metadata.text.prepare",
            "metadata.text.apply", "credentials.assess", "artifacts.candidate.observe ", "Artifacts.Candidate.Observe",
            "project.snapshot ", "Config.Validate", "environment.requirements ", "GitHub.Setup.Propose",
            "Release.Version.Observe", "metadata.text.observe ", "Metadata.Text.Validate"] {
            assert!(!linux_installed_passive_method(name));
        }
    }
    #[test]
    fn macos_installed_allowlist_is_only_the_eight_passive_draft_methods() {
        for name in ["capabilities", "catalog", "project.snapshot", "config.validate", "config.suggest", "config.preview",
            "environment.requirements", "github.setup.propose"] {
            assert!(macos_installed_passive_method(name));
        }
        for name in ["", "unknown", "config.save", "config.apply", "config.initialize", "credentials.assess",
            "release.version.observe", "metadata.text.observe", "metadata.text.validate", "metadata.text.prepare",
            "metadata.text.apply", "artifacts.candidate.observe", "environment.diagnostics", "github.connection.refresh",
            "project.snapshot ", "Config.Validate", "environment.requirements ", "GitHub.Setup.Propose"] {
            assert!(!macos_installed_passive_method(name));
        }
    }
    #[cfg(target_os = "macos")]
    #[test]
    fn macos_project_scope_does_not_grant_path_or_evidence_pickers() {
        let runtime = RuntimeConfig::packaged(PathBuf::from("/inert-mac-profile-data-only"));
        assert!(!runtime.project_path_selection_profile_available());
        assert!(!runtime.evidence_selection_profile_available());
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
    #[cfg(not(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu", feature = "desktop-shell",
        not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher")),
        all(target_os = "macos", target_arch = "aarch64", feature = "desktop-shell", feature = "custom-protocol",
            not(feature = "development-runtime"), not(feature = "macos-installed-installer"), not(feature = "ubuntu-runtime-publisher")))))]
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
    #[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu", feature = "desktop-shell",
        not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"))))]
    #[test]
    fn installed_workflow_selector_is_closed_outside_the_normal_linux_shell() {
        let runtime = RuntimeConfig::packaged(PathBuf::from("/inert-workflow-path-must-not-be-opened"));
        assert!(!runtime.github_workflow_edit_profile_available());
        #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
        {
            let mut slots = crate::installed_runtime::GitHubWorkflowRuntimeSlots::new();
            let (_sender, stop) = tokio::sync::watch::channel(false);
            assert!(runtime.resolve_github_workflow_installed(&mut slots, Instant::now(), &stop).is_err());
            assert!(slots.never_started() && !slots.settled() && slots.capability().is_err());
        }
    }
    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    #[test]
    fn workflow_candidate_bindings_data_contract() { workflow_candidate_bindings_are_exactly_a_not_an_arbitrary_anchor(); }
    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    pub(super) fn workflow_candidate_bindings_are_exactly_a_not_an_arbitrary_anchor() {
        let (target, manifest, protocol) = (PassiveInstalledProfile::TARGET, PassiveInstalledProfile::MANIFEST, PassiveInstalledProfile::PROTOCOL);
        assert!(GitHubWorkflowInstalledProfile::bindings_match(target, Some(manifest), Some(protocol)));
        let wrong = "0".repeat(64);
        for (target, manifest, protocol) in [
            ("aarch64-unknown-linux-gnu", Some(manifest), Some(protocol)), (target, None, Some(protocol)),
            (target, Some(manifest), None), (target, Some(wrong.as_str()), Some(protocol)), (target, Some(manifest), Some(wrong.as_str())),
        ] { assert!(!GitHubWorkflowInstalledProfile::bindings_match(target, manifest, protocol)); }
    }
    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu", feature = "desktop-shell",
        not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher")))]
    #[test]
    fn installed_workflow_profile_contract_is_inert() { assert_installed_workflow_profile_contract(); }
    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu", feature = "desktop-shell",
        not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher")))]
    pub(super) fn installed_workflow_data_is_fixed_and_stopped_inspection_owes_original_settlement() {
        let runtime = RuntimeConfig::packaged(PathBuf::from("/inert-workflow-data-only"));
        let profile = runtime.github_workflow_installed_profile();
        assert_eq!(runtime.github_workflow_edit_profile_available(), profile.is_ok());
        assert_eq!(profile.is_ok(), GitHubWorkflowInstalledProfile::bindings_match(COMPILED_TARGET, MANIFEST_ANCHOR, PROTOCOL_ANCHOR));
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
            let mut slots = crate::installed_runtime::GitHubWorkflowRuntimeSlots::new();
            let (_sender, stop) = tokio::sync::watch::channel(true);
            // Sticky STOP precedes uname/open: this is empty DATA bookkeeping,
            // never an executed runtime, transferred ledger or native witness.
            assert!(runtime.resolve_github_workflow_installed(&mut slots, Instant::now() + std::time::Duration::from_secs(1), &stop).is_err());
            assert!(!slots.never_started() && !slots.settled() && slots.no_child_effect());
            assert!(slots.transfer_once().is_err() && slots.capability().is_err());
            assert_eq!(slots.settle_originals(), crate::installed_runtime::CloseOutcome::Settled);
            assert!(slots.settled() && slots.capability().is_err());
        }
        assert!(runtime.resolve(Instant::now()).is_err());
        assert!(runtime.resolve_edit(Instant::now()).is_err());
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

// Windows version selection/inspection DATA. No owner, command, availability or
// native-success flag is produced here. Pure helpers are testable on Linux too.
#[cfg(any(test, all(target_os = "windows", target_arch = "x86_64", target_env = "msvc")))]
pub(crate) mod windows_version {
    use super::*;
    use std::collections::BTreeMap;

    pub(crate) const TARGET: &str = "x86_64-pc-windows-msvc";
    pub(crate) const SELECTED: [&str; 3] = ["python/python.exe", "engine_bootstrap.py", "core.zip"];
    pub(crate) const BLOCK_SIZE: usize = 64 * 1024;
    pub(crate) const MANIFEST_BYTES: u64 = MANIFEST_LIMIT;

    // Official CPython 3.14.7 embed-amd64's entire unchanged 37-member roster,
    // including unused images/catalog. Source: accepted Windows payload preparer
    // e49c459629f6453166ffdd504dc33f8d6607e78c62178aa03556a5f763f7f775.
    // A roster match is DATA, not loaded-image, distribution or launch approval.
    const SUPPLIER: [(&str, u64, &str); 37] = [
        ("LICENSE.txt", 35407, "935cf13e19f8c31b497d20b05d73623431a226b230c3599bc30fa3348979bc68"),
        ("_asyncio.pyd", 78048, "f9594a2a4f45570dbfdf1f3471194ae7b27dc117c54b9af6bc22df9c93830f8b"),
        ("_bz2.pyd", 88288, "b938073c85cf6b9fe80556d7899ed1901e5e60b7adea2832442376239fb36b36"),
        ("_ctypes.pyd", 142560, "408cc4e7a22ffa418ca52f5e13fe9268a3c50a2bc9de02b0530b555ef591bc5a"),
        ("_decimal.pyd", 291552, "bc3a61685825ae37a4cd2b2b87fa27af12e01575c4f920788ea806e6781a2c79"),
        ("_elementtree.pyd", 138976, "d8a17f9c831e313b440e19e0d26e6c0e7ed830ff1f657887cbc26664d6ef4973"),
        ("_hashlib.pyd", 69344, "5933ef5eda7c0bca0b3874a6e2c5f13b91b8f2cfc29bc46160df3212a1dbee79"),
        ("_lzma.pyd", 160992, "d2abf8db7fb0cf6285663b177991691a41b37e215c3d71fd087a98d8ec1bee63"),
        ("_multiprocessing.pyd", 38624, "cea83c9bf3131d079c20066b626f67ab33021b476777be2d7be26d1fa5e4eb66"),
        ("_overlapped.pyd", 58080, "1d7028683e6ec50c159139238f90a6c8431ece139a4764900ca11c941ba05d46"),
        ("_queue.pyd", 36576, "2fd8668f52b34d0e71ae48784bd2e7d35e5d99df6f641edb0fc279235a187c8e"),
        ("_remote_debugging.pyd", 93408, "32b58c85e29ecc2378eddfe367745998fdb131e1ab6bb84d54e16f33806b584c"),
        ("_socket.pyd", 87776, "02265dd0d0287f3ffd287ea5d8e3c918a5a056e8ef2c4529857f5e84ec9e2519"),
        ("_sqlite3.pyd", 132832, "ec9694e5929747e93e05bc32427d24350dc4de5074b61a37bc961c3048794a67"),
        ("_ssl.pyd", 190688, "4cfb154c7cc525d57020c0e64f2dd876a78b46cd38419446392478de6b7b13b8"),
        ("_uuid.pyd", 28384, "fbfd7fe8583b346ba20b174b2510c0830237f5092bdf9fc26da9d6b25b018385"),
        ("_wmi.pyd", 40160, "b6fd41f079da0c0054829855360e88b8b762f5c42bb474c2fa02eae367839ad2"),
        ("_zoneinfo.pyd", 51936, "07469c7fc221663e423a2e6023a5b2ead3b10d0b40eb297887f4447a1ff1b2a3"),
        ("_zstd.pyd", 503520, "33c6eca99470c3eb9d776b617c550ad41b002a668336f062a9ab7be677a7409a"),
        ("libcrypto-3.dll", 6242552, "53c529145339fb042a3dcd3a09c2d7753204f8b4fc79d99e0d31e69a33985958"),
        ("libffi-8.dll", 39696, "eff52743773eb550fcc6ce3efc37c85724502233b6b002a35496d828bd7b280a"),
        ("libssl-3.dll", 1329912, "b17a87979862d19241edc4318f967e24c3ec356ed6c2368f561179fab2311001"),
        ("libtommath.dll", 95456, "bf18448a56de62e56adb5a50040c08648f0bcf556217de90eca283490ee8c0c3"),
        ("pyexpat.pyd", 222944, "e34347c4e11b2ecc57df2ce1627ba7f98fd076e9df59951e9034f5aa8e95a2fc"),
        ("python.cat", 600973, "bd98c1a5acc6dc6850425221a755506571eac182cb0aa85f2f45a9a077a3c71b"),
        ("python.exe", 106208, "4942b86a6597e5aee0128daa00050ed79bc21f6e709a78eb19cbfeb0c2f39ac9"),
        ("python3.dll", 73952, "6c45910e7c82617ca6360820de861699cc99f9efee434df290aa4c6e38f39886"),
        ("python314._pth", 80, "2ed7ccda80e9e28ab5877902a9a325586c8a7b7b3e6731d944565bee082e216c"),
        ("python314.dll", 6785760, "0f9857ffdfe010fe6b99328d58c2e3c7472ce75f336bf9c2ad9bd5bca3bce700"),
        ("python314.zip", 4138882, "5a7a66daf1a2c2e3c8d7a4a0d095685ec301efc3ef28cc2419e3041bf5729b65"),
        ("pythonw.exe", 104672, "c197268f7e7cf2848b8c1ae59bbd0e0c14defe668a2d365302137ea929b47769"),
        ("select.pyd", 33504, "722328e7fad8048057fc966474ba73966d2ceebaa32e7344cce09640ab4dc9bd"),
        ("sqlite3.dll", 1584864, "d3e60dd22e62c9fbdb64b31b1b8c48782e1d4958d04d0bf830cffd31ace3275f"),
        ("unicodedata.pyd", 759008, "280b09bd97b598d18c0ed9542dc18ed35fa57a16e84f8e65fd9c6e96516c28d6"),
        ("vcruntime140.dll", 178616, "d1f4225df2cd877dbf130d5668a021dce3f94118455ff5ec952061c30afc9ce7"),
        ("vcruntime140_1.dll", 50112, "a7146c08f89fe5b04541ab507cdb59ff7b44534d4ba3c668a426c6450a03434e"),
        ("winsound.pyd", 32992, "6a27340660de89d5da59445a77ac6b08d471e373304ce7294c198238f09f2dc2"),
    ];

    pub(crate) fn passive_method(name: &str) -> bool {
        matches!(name, "capabilities" | "catalog" | "project.snapshot"
            | "config.validate" | "config.suggest" | "config.preview")
    }

    #[derive(Debug)]
    pub(crate) struct VersionSpec { manifest_sha256: String, protocol_sha256: String }
    impl VersionSpec {
        pub(crate) fn compiled() -> Result<Self, BridgeError> {
            Self::bindings(COMPILED_TARGET, MANIFEST_ANCHOR, PROTOCOL_ANCHOR)
        }
        fn bindings(target: &str, manifest: Option<&str>, protocol: Option<&str>) -> Result<Self, BridgeError> {
            if target != TARGET { return Err(unavailable()); }
            Ok(Self {
                manifest_sha256: manifest.filter(|s| sha(s)).ok_or_else(unavailable)?.to_owned(),
                protocol_sha256: protocol.filter(|s| sha(s)).ok_or_else(unavailable)?.to_owned(),
            })
        }
        pub(crate) fn components(&self) -> [&str; 4] {
            ["Mobile Release Kit", "versions", TARGET, &self.manifest_sha256]
        }
        pub(crate) fn manifest_sha256(&self) -> &str { &self.manifest_sha256 }
        pub(crate) fn decode(&self, bytes: &[u8]) -> Result<Inventory, BridgeError> {
            // No JSON is interpreted until its exact compile-bound bytes match.
            if bytes.is_empty() || bytes.len() as u64 > MANIFEST_LIMIT
                || digest(bytes) != self.manifest_sha256 { return Err(unavailable()); }
            let manifest: Manifest = serde_json::from_value(strict_json(bytes).map_err(|_| unavailable())?)
                .map_err(|_| unavailable())?;
            if manifest.schema_version != 1 || manifest.protocol != PROTOCOL || manifest.core_version != CORE_VERSION
                || manifest.target != TARGET || manifest.protocol_sha256 != self.protocol_sha256
                || !sha(&manifest.core_sha256) || !sha(&manifest.inventory_sha256)
                || manifest.files.is_empty() || manifest.files.len() >= FILE_COUNT { return Err(unavailable()); }
            // NativeBook's 2048 file attempts and 1GiB reads include manifest.json.
            if digest(&serde_json::to_vec(&manifest.files).map_err(|_| unavailable())?) != manifest.inventory_sha256 {
                return Err(unavailable());
            }
            let mut nodes = BTreeMap::new();
            insert_node(&mut nodes, "manifest.json", InventoryKind::File)?;
            let mut directories = BTreeSet::new();
            let mut previous: Option<&str> = None;
            let mut payload_bytes = 0u64;
            for item in &manifest.files {
                if !safe_payload_path(&item.path) || item.path.split('/').any(|part| part.len() > 255)
                    || item.path == "manifest.json" || !sha(&item.sha256) || item.size > FILE_LIMIT
                    || item.path == "github-ca.pem" && (item.size == 0 || item.size > GITHUB_CA_LIMIT)
                    || previous.is_some_and(|p| p >= item.path.as_str()) { return Err(unavailable()); }
                previous = Some(&item.path);
                insert_node(&mut nodes, &item.path, InventoryKind::File)?;
                let mut child = item.path.as_str();
                while let Some((parent, _)) = child.rsplit_once('/') {
                    insert_node(&mut nodes, parent, InventoryKind::Directory)?;
                    directories.insert(parent.to_owned()); child = parent;
                }
                payload_bytes = payload_bytes.checked_add(item.size).ok_or_else(unavailable)?;
                if payload_bytes > TOTAL_LIMIT - bytes.len() as u64 { return Err(unavailable()); }
                if item.path == "core.zip" && item.sha256 != manifest.core_sha256 { return Err(unavailable()); }
            }
            // Derived directories, not undeclared empty folders; actual native
            // entry accounting also includes prefix and . / .. observations.
            if nodes.len() > ENTRY_COUNT { return Err(unavailable()); }
            for required in REQUIRED_RUNTIME_RESOURCES {
                let required = if required == PYTHON_RESOURCE { SELECTED[0] } else { required };
                if find_file(&manifest.files, required).is_none() { return Err(unavailable()); }
            }
            for (name, size, hash) in SUPPLIER {
                let file = find_file(&manifest.files, &format!("python/{name}")).ok_or_else(unavailable)?;
                if file.size != size || file.sha256 != hash { return Err(unavailable()); }
            }
            Ok(Inventory { manifest, directories, payload_bytes })
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) enum InventoryKind { File, Directory }
    fn insert_node(nodes: &mut BTreeMap<String, (String, InventoryKind)>, path: &str, kind: InventoryKind)
        -> Result<(), BridgeError> {
        let folded = path.to_ascii_lowercase();
        if let Some((existing, prior_kind)) = nodes.get(&folded) {
            if existing != path || *prior_kind != InventoryKind::Directory || kind != InventoryKind::Directory {
                return Err(unavailable());
            }
        } else { nodes.insert(folded, (path.to_owned(), kind)); }
        Ok(())
    }
    fn find_file<'a>(files: &'a [PayloadFile], path: &str) -> Option<&'a PayloadFile> {
        files.binary_search_by(|file| file.path.as_str().cmp(path)).ok().and_then(|index| files.get(index))
    }
    #[derive(Debug)]
    pub(crate) struct Inventory {
        pub(crate) manifest: Manifest,
        pub(crate) directories: BTreeSet<String>,
        pub(crate) payload_bytes: u64,
    }
    impl Inventory {
        pub(crate) fn file(&self, path: &str) -> Option<&PayloadFile> { find_file(&self.manifest.files, path) }
        pub(crate) fn progress(&self) -> InventoryProgress {
            let mut remaining = BTreeMap::new();
            remaining.insert("manifest.json".to_owned(), InventoryKind::File);
            for file in &self.manifest.files { remaining.insert(file.path.clone(), InventoryKind::File); }
            for path in &self.directories { remaining.insert(path.clone(), InventoryKind::Directory); }
            InventoryProgress { remaining }
        }
    }
    /// Exact observed-name accounting, not a hash receipt or native-success mock.
    pub(crate) struct InventoryProgress { remaining: BTreeMap<String, InventoryKind> }
    impl InventoryProgress {
        pub(crate) fn observe(&mut self, path: &str, kind: InventoryKind) -> Result<(), BridgeError> {
            if self.remaining.get(path) != Some(&kind) { return Err(unavailable()); }
            self.remaining.remove(path); Ok(())
        }
        pub(crate) fn complete(&self) -> bool { self.remaining.is_empty() }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use serde_json::{json, Value};
        fn fixture() -> Value {
            let mut files: Vec<PayloadFile> = SUPPLIER.iter().map(|(name, size, hash)| PayloadFile {
                path: format!("python/{name}"), size: *size, sha256: (*hash).to_owned(),
            }).collect();
            for required in REQUIRED_RUNTIME_RESOURCES {
                if required != PYTHON_RESOURCE {
                    files.push(PayloadFile { path: required.to_owned(), size: 1, sha256: "a".repeat(64) });
                }
            }
            files.sort_by(|a, b| a.path.cmp(&b.path));
            json!({"schemaVersion":1,"protocol":PROTOCOL,"coreVersion":CORE_VERSION,"target":TARGET,
                "coreSha256":"a".repeat(64),"protocolSha256":"b".repeat(64),
                "inventorySha256":digest(&serde_json::to_vec(&files).unwrap()),"files":files})
        }
        fn encode(value: &mut Value) -> Vec<u8> {
            let files = value["files"].as_array_mut().unwrap();
            files.sort_by(|a, b| a["path"].as_str().cmp(&b["path"].as_str()));
            let inventory = serde_json::to_vec(files).unwrap();
            value["inventorySha256"] = json!(digest(&inventory));
            serde_json::to_vec(value).unwrap()
        }
        fn spec(bytes: &[u8]) -> VersionSpec {
            VersionSpec::bindings(TARGET, Some(&digest(bytes)), Some(&"b".repeat(64))).unwrap()
        }
        fn parse(value: &mut Value) -> Result<Inventory, BridgeError> {
            let bytes = encode(value); spec(&bytes).decode(&bytes)
        }
        fn row(path: &str, size: u64) -> Value { json!({"path":path,"size":size,"sha256":"a".repeat(64)}) }

        #[test]
        fn windows_manifest_and_observed_inventory_are_exact() {
            let inventory = parse(&mut fixture()).unwrap();
            assert_eq!(inventory.manifest.files.len(), 45);
            assert_eq!(inventory.directories, BTreeSet::from(["python".to_owned()]));
            let mut progress = inventory.progress();
            assert!(!progress.complete());
            assert!(progress.observe("extra", InventoryKind::File).is_err());
            assert!(progress.observe("python", InventoryKind::File).is_err());
            progress.observe("manifest.json", InventoryKind::File).unwrap();
            assert!(progress.observe("manifest.json", InventoryKind::File).is_err());
            for file in &inventory.manifest.files { progress.observe(&file.path, InventoryKind::File).unwrap(); }
            assert!(!progress.complete());
            progress.observe("python", InventoryKind::Directory).unwrap();
            assert!(progress.complete());
        }
        #[test]
        fn windows_manifest_anchors_schema_and_inventory_are_bound_before_use() {
            let valid = encode(&mut fixture());
            let bound = spec(&valid);
            assert!(bound.decode(&valid[..valid.len()-1]).is_err());
            for (key, value) in [("schemaVersion", json!(2)), ("protocol", json!(2)),
                ("coreVersion", json!("9.9.9")), ("target", json!("x86_64-unknown-linux-gnu")),
                ("protocolSha256", json!("c".repeat(64))), ("coreSha256", json!("c".repeat(64))),
                ("extra", json!(true))] {
                let mut value_map = fixture(); value_map[key] = value;
                assert!(parse(&mut value_map).is_err(), "{key}");
            }
            let mut invalid = fixture(); invalid["inventorySha256"] = json!("0".repeat(64));
            let bytes = serde_json::to_vec(&invalid).unwrap();
            assert!(spec(&bytes).decode(&bytes).is_err());
            let duplicate = format!("{{\"schemaVersion\":1,{}", String::from_utf8(valid.clone()).unwrap().get(1..).unwrap()).into_bytes();
            assert!(spec(&duplicate).decode(&duplicate).is_err());
            let uppercase = "A".repeat(64);
            for anchor in [None, Some(""), Some(uppercase.as_str()), Some("../version")] {
                assert!(VersionSpec::bindings(TARGET, anchor, Some(&"b".repeat(64))).is_err());
            }
            assert!(VersionSpec::bindings("x86_64-unknown-linux-gnu", Some(&digest(&valid)), Some(&"b".repeat(64))).is_err());
        }
        #[test]
        fn windows_manifest_rejects_case_aliases_and_file_directory_conflicts() {
            for paths in [vec!["Python/extra"], vec!["core.zip/child"], vec!["manifest.json/child"],
                vec!["foo", "foo/child"], vec!["Foo/a", "foo/b"], vec!["NUL.txt"], vec!["a//b"],
                vec!["../file"], vec!["a."], vec!["x:stream"], vec!["a\\b"]] {
                let mut value = fixture();
                for path in paths { value["files"].as_array_mut().unwrap().push(row(path, 1)); }
                assert!(parse(&mut value).is_err());
            }
            for path in ["x".repeat(256), ["x"; 17].join("/")] {
                let mut value = fixture(); value["files"].as_array_mut().unwrap().push(row(&path, 1));
                assert!(parse(&mut value).is_err());
            }
        }
        #[test]
        fn windows_manifest_preserves_every_supplier_member_and_hash() {
            for (name, _, _) in SUPPLIER {
                let path = format!("python/{name}");
                let mut absent = fixture(); absent["files"].as_array_mut().unwrap().retain(|file| file["path"] != path);
                assert!(parse(&mut absent).is_err(), "omitted {name}");
            }
            for path in ["python/python314._pth", "python/python.cat", "python/_remote_debugging.pyd"] {
                let mut changed = fixture();
                let file = changed["files"].as_array_mut().unwrap().iter_mut().find(|file| file["path"] == path).unwrap();
                file["sha256"] = json!("0".repeat(64));
                assert!(parse(&mut changed).is_err());
            }
        }
        #[test]
        fn windows_manifest_budgets_include_manifest_not_only_payload() {
            let mut value = fixture();
            while value["files"].as_array().unwrap().len() < FILE_COUNT - 1 {
                let index = value["files"].as_array().unwrap().len();
                value["files"].as_array_mut().unwrap().push(row(&format!("extra-{index:04}"), 0));
            }
            assert!(parse(&mut value).is_ok());
            value["files"].as_array_mut().unwrap().push(row("extra-final", 0));
            assert!(parse(&mut value).is_err());
            let mut oversized = fixture();
            oversized["files"].as_array_mut().unwrap().extend([row("large-a", FILE_LIMIT), row("large-b", FILE_LIMIT)]);
            assert!(parse(&mut oversized).is_err());
            let huge = vec![b' '; MANIFEST_LIMIT as usize + 1];
            assert!(spec(&huge).decode(&huge).is_err());
        }
        #[test]
        fn windows_six_method_data_does_not_enable_any_production_profile() {
            for method in ["capabilities", "catalog", "project.snapshot", "config.validate", "config.suggest", "config.preview"] {
                assert!(passive_method(method));
            }
            for method in ["", "project.snapshot ", "Config.Validate", "config.save", "credentials.assess",
                "environment.requirements", "github.setup.propose", "release.version.observe", "metadata.text.observe",
                "metadata.text.validate", "artifacts.candidate.observe", "environment.diagnostics", "android.build"] {
                assert!(!passive_method(method));
            }
            #[cfg(all(target_os = "windows", target_arch = "x86_64", target_env = "msvc", not(feature = "development-runtime")))]
            {
                let runtime = RuntimeConfig::packaged(PathBuf::from("Z:\\inert-not-opened"));
                assert!(!runtime.project_selection_profile_available());
                assert!(!runtime.configuration_edit_profile_available());
                assert!(!runtime.passive_method_available("capabilities"));
                assert!(runtime.resolve(Instant::now()).is_err());
            }
        }
    }
}
