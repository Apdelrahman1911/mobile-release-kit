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
const GITHUB_CA_LIMIT: u64 = 512 * 1024;
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

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeStatus { pub state: &'static str, pub reason: Option<String>, pub mode: &'static str }

#[derive(Clone)]
pub struct RuntimeConfig { bundle_root: PathBuf }

#[derive(Debug)]
pub struct VerifiedRuntime { pub python: PathBuf, pub bootstrap: PathBuf, pub core: PathBuf, pub cwd: PathBuf }

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
    pub fn packaged(resource_dir: PathBuf) -> Self { Self { bundle_root: resource_dir.join("runtime") } }
    pub fn mode(&self) -> &'static str {
        #[cfg(all(feature = "development-runtime", debug_assertions))]
        { "development" }
        #[cfg(not(all(feature = "development-runtime", debug_assertions)))]
        { "bundled" }
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
        for required in [PYTHON_RESOURCE, "engine_bootstrap.py", "config_edit_bootstrap.py",
            "github_connection_bootstrap.py", "github-ca.pem", "core.zip"] {
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn payload_names_are_portable_and_unambiguous() {
        for name in ["core.zip", "engine_bootstrap.py", "github_connection_bootstrap.py", "github-ca.pem",
            "python/bin/python3", "python/lib/libstdc++.so.6"] { assert!(safe_payload_path(name)); }
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
}
