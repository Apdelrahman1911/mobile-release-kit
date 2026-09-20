//! One compiled protected Android instance. Profile/manifest DATA is not a
//! qualification permit. No discovery, installer, environment fallback or tools
//! are run here; the saved-command owner retains the actual original book.
use std::{collections::BTreeSet, path::PathBuf};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use crate::protocol::strict_json;

const PROFILE: &str = "android-local-linux-gnu-x86_64-v1";
const TARGET: &str = "linux-gnu-x86_64";
const PREFIX: &str = "/opt/mobile-release-kit/android/";
const MANIFEST: &str = "android-toolchain.json";
const MANIFEST_LIMIT: usize = 1024 * 1024;
const FILE_LIMIT: u64 = 512 * 1024 * 1024;
const TOTAL_LIMIT: u64 = 1024 * 1024 * 1024;
const BUNDLETOOL_SHA256: &str = "a099cfa1543f55593bc2ed16a70a7c67fe54b1747bb7301f37fdfd6d91028e29";
const BUNDLETOOL_MAX_BYTES: u64 = 32_520_401;
const INSTANCE: Option<&str> = option_env!("MRK_ANDROID_TOOL_INSTANCE");
const MANIFEST_ANCHOR: Option<&str> = option_env!("MRK_ANDROID_TOOL_MANIFEST_SHA256");
const OS_ANCHOR: Option<&str> = option_env!("MRK_ANDROID_OS_CONTRACT_SHA256");
// Intentionally ABSENT. Only a separately reviewed exact executable OS closure
// (Python AND JDK/SDK/Gradle shell/helpers/loaders and aliases) may populate it.
// A digest-shaped manifest field, Ubuntu name or claimed coverage is not that
// external authentication/immutable-namespace/native qualification evidence.
const OS_CONTRACT_BYTES: Option<&[u8]> = None;

#[derive(Clone)]
pub(crate) struct AndroidToolchainProfile {
    instance: String, root: PathBuf, manifest_sha256: String, os: OsContract,
}

impl AndroidToolchainProfile {
    pub(crate) fn compiled() -> Option<Self> {
        if !cfg!(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu")) { return None; }
        let instance = INSTANCE.filter(|v| instance_name(v))?;
        let manifest = MANIFEST_ANCHOR.filter(|v| sha(v))?;
        let os = parse_os_contract(OS_CONTRACT_BYTES?, OS_ANCHOR?)?;
        Some(Self { instance: instance.into(), root: PathBuf::from(PREFIX).join(instance),
            manifest_sha256: manifest.into(), os })
    }
}
#[derive(Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct FileSpec { path: String, size: u64, sha256: String, mode: u32 }
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Alias { path: String, target: String, canonical: String }
#[derive(Clone)]
struct OsContract { id: String, sha256: String, files: Vec<FileSpec>, aliases: Vec<Alias> }
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ContractData { schema_version: u32, id: String, closure: String, files: Vec<FileSpec>, aliases: Vec<Alias> }
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Versions { jdk_vendor: String, jdk_version: String, gradle_version: String, agp_version: String,
    sdk_platform: String, sdk_platform_revision: String, sdk_build_tools_version: String }
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Distribution { url: String, sha256: String }
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Bundletool { version: String, sha256: String }
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Roles { java: String, javac: String, gradle: String, bundletool: String, sdk: String }
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OsProfile { id: String, inventory_sha256: String, shell: String, executable_directory: String,
    helpers: Vec<String>, files: Vec<FileSpec> }
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ManifestData { schema_version: u32, profile: String, target: String, instance: String, launch_contract: String,
    versions: Versions, gradle_distribution: Distribution, bundletool: Bundletool, roles: Roles,
    files: Vec<FileSpec>, os_profile: OsProfile }
struct Inventory { data: ManifestData, directories: BTreeSet<String> }
fn sha(v: &str) -> bool { v.len() == 64 && v.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) }
fn digest(bytes: &[u8]) -> String { Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect() }
fn component(v: &str) -> bool {
    !v.is_empty() && v.len() <= 255 && !matches!(v, "." | "..") && !v.ends_with('.')
        && v.bytes().all(|b| b.is_ascii_alphanumeric() || b"_+@.,=-".contains(&b))
}
fn instance_name(v: &str) -> bool {
    !v.is_empty() && v.len() <= 64 && (v.as_bytes()[0].is_ascii_lowercase() || v.as_bytes()[0].is_ascii_digit())
        && v.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_-".contains(&b))
}
fn label(v: &str, version: bool) -> bool {
    !v.is_empty() && v.len() <= (if version { 64 } else { 128 })
        && (if version { v.as_bytes()[0].is_ascii_digit() } else { v.as_bytes()[0].is_ascii_alphanumeric() })
        && v.bytes().all(|b| b.is_ascii_alphanumeric() || b"_.+-".contains(&b))
}
fn path(v: &str, absolute: bool) -> bool {
    if v.is_empty() || v.len() > 512 || v.starts_with('/') != absolute { return false; }
    let parts: Vec<_> = v[usize::from(absolute)..].split('/').collect();
    parts.len() <= 16 && parts.iter().all(|v| component(v))
}
fn native_path(v: &str) -> bool {
    path(v, true) && (v.starts_with("/usr/bin/") || v.starts_with("/usr/lib/") || v.starts_with("/usr/lib64/")
        || v.starts_with("/etc/ld.so.conf.d/") || matches!(v, "/etc/ld.so.cache" | "/etc/ld.so.conf"))
}
fn files_valid(files: &[FileSpec], native: bool) -> bool {
    !files.is_empty() && files.len() <= (if native { 128 } else { 2048 })
        && files.windows(2).all(|p| p[0].path < p[1].path)
        && files.iter().all(|f| f.size <= FILE_LIMIT && sha(&f.sha256) && f.mode <= 0o777 && f.mode & 0o022 == 0
            && if native { native_path(&f.path) } else { path(&f.path, false)
                && f.path.split_once('/').is_some_and(|(first, _)| matches!(first, "jdk" | "gradle" | "sdk" | "bundletool")) })
        && directories(files, native).is_some()
}
fn directories(files: &[FileSpec], native: bool) -> Option<BTreeSet<String>> {
    let mut dirs = BTreeSet::new(); let names: BTreeSet<_> = files.iter().map(|f| f.path.clone()).collect();
    let mut folded = BTreeSet::new();
    for f in files {
        if !folded.insert(f.path.to_ascii_lowercase()) { return None; }
        let mut name = f.path.as_str();
        while let Some((parent, _)) = name.rsplit_once('/') {
            if parent.is_empty() { break; } dirs.insert(parent.to_owned()); name = parent;
        }
    }
    if !native { folded.insert(MANIFEST.into()); }
    for d in &dirs { if names.contains(d) || !folded.insert(d.to_ascii_lowercase()) { return None; } }
    (folded.len() <= 8192).then_some(dirs)
}
fn alias_destination(alias: &Alias) -> Option<String> {
    if !path(&alias.path, true) || !path(&alias.canonical, true) || alias.target.is_empty() || alias.target.len() > 512 { return None; }
    let parent = alias.path.rsplit_once('/')?.0;
    let mut parts: Vec<&str> = if alias.target.starts_with('/') { Vec::new() }
        else { parent.split('/').filter(|v| !v.is_empty()).collect() };
    let target = alias.target.strip_prefix('/').unwrap_or(&alias.target);
    for part in target.split('/') {
        match part { ".." => { parts.pop()?; }, "." => {}, _ if component(part) => parts.push(part), _ => return None }
        if parts.len() > 16 { return None; }
    }
    Some(format!("/{}", parts.join("/"))) // Lexical DATA only; never follows a link.
}
fn parse_os_contract(raw: &[u8], anchor: &str) -> Option<OsContract> {
    if raw.is_empty() || raw.len() > MANIFEST_LIMIT || !sha(anchor) || digest(raw) != anchor { return None; }
    let d: ContractData = serde_json::from_value(strict_json(raw).ok()?).ok()?;
    if d.schema_version != 1 || d.closure != "python-jdk-sdk-gradle-shell-loader-v1" || !label(&d.id, false)
        || !files_valid(&d.files, true) || d.aliases.len() > 128 { return None; }
    let mut total = 0u64;
    for f in &d.files { total = total.checked_add(f.size)?; if total > TOTAL_LIMIT { return None; } }
    let mut targets = directories(&d.files, true)?;
    targets.extend(d.files.iter().map(|f| f.path.clone()));
    let folded_targets: BTreeSet<_> = targets.iter().map(|name| name.to_ascii_lowercase()).collect();
    let mut names = BTreeSet::new();
    for a in &d.aliases {
        if !names.insert(a.path.to_ascii_lowercase()) || folded_targets.contains(&a.path.to_ascii_lowercase())
            || !targets.contains(&a.canonical) || !a.canonical.starts_with("/usr/")
            || !matches!(a.path.as_str(), "/bin" | "/lib" | "/lib64") && !a.path.starts_with("/usr/")
            || alias_destination(a).as_deref() != Some(a.canonical.as_str()) { return None; }
    }
    Some(OsContract { id: d.id, sha256: anchor.into(), files: d.files, aliases: d.aliases })
}
fn parse_manifest(raw: &[u8], profile: &AndroidToolchainProfile) -> Option<Inventory> {
    if raw.is_empty() || raw.len() > MANIFEST_LIMIT || digest(raw) != profile.manifest_sha256 { return None; }
    let d: ManifestData = serde_json::from_value(strict_json(raw).ok()?).ok()?;
    if d.schema_version != 1 || d.profile != PROFILE || d.target != TARGET || d.instance != profile.instance
        || d.launch_contract != "gradle-posix-private-jvm-v1" || !label(&d.versions.jdk_vendor, false)
        || [&d.versions.jdk_version, &d.versions.gradle_version, &d.versions.agp_version,
            &d.versions.sdk_platform_revision, &d.versions.sdk_build_tools_version].iter().any(|v| !label(v, true)) { return None; }
    let platform = d.versions.sdk_platform.strip_prefix("android-")?;
    if platform.is_empty() || platform.len() > 3 || platform.starts_with('0') || !platform.bytes().all(|b| b.is_ascii_digit()) { return None; }
    if !["services.gradle.org", "downloads.gradle.org"].iter().any(|host|
        d.gradle_distribution.url == format!("https://{host}/distributions/gradle-{}-bin.zip", d.versions.gradle_version))
        || !sha(&d.gradle_distribution.sha256) || d.bundletool.version != "1.18.3" || d.bundletool.sha256 != BUNDLETOOL_SHA256
        || d.roles.java != "jdk/bin/java" || d.roles.javac != "jdk/bin/javac" || d.roles.gradle != "gradle/bin/gradle"
        || d.roles.bundletool != "bundletool/bundletool.jar" || d.roles.sdk != "sdk" || !files_valid(&d.files, false) { return None; }
    for role in [&d.roles.java, &d.roles.javac, &d.roles.gradle, &d.roles.bundletool] {
        let f = d.files.iter().find(|f| &f.path == role)?;
        if f.size == 0 || role != &d.roles.bundletool && f.mode & 0o111 == 0 { return None; }
        if role == &d.roles.bundletool && (f.sha256 != BUNDLETOOL_SHA256 || f.size > BUNDLETOOL_MAX_BYTES) { return None; }
    }
    let os = &d.os_profile;
    if !d.files.iter().any(|f| f.path.starts_with("sdk/")) || os.id != profile.os.id || os.inventory_sha256 != profile.os.sha256
        || os.files != profile.os.files || !files_valid(&os.files, true) || os.shell != "/usr/bin/dash" || os.executable_directory != "/usr/bin"
        || os.helpers.is_empty() || os.helpers.len() > 128 || !os.helpers.iter().all(|h| component(h))
        || !os.helpers.windows(2).all(|p| p[0] < p[1])
        || !["sed", "uname", "xargs"].iter().all(|name| os.helpers.iter().any(|h| h.as_str() == *name)) { return None; }
    for command in std::iter::once(os.shell.clone()).chain(os.helpers.iter().map(|h| format!("/usr/bin/{h}"))) {
        if !os.files.iter().any(|f| f.path == command && f.size > 0 && f.mode & 0o111 != 0) { return None; }
    }
    let mut total = 0u64;
    for f in d.files.iter().chain(os.files.iter()) { total = total.checked_add(f.size)?; if total > TOTAL_LIMIT { return None; } }
    let directories = directories(&d.files, false)?;
    Some(Inventory { data: d, directories })
}

#[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
pub(crate) use native::AndroidToolchainCustody;
#[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
mod native {
    use super::*;
    use std::{collections::BTreeMap, sync::Arc, time::Instant};
    use tokio::sync::watch;
    use rustix::fs::FileType;
    use crate::{android_build_protocol::{RootIdentity, ToolchainBinding},
        installed_runtime::{AdmissionFailure as Failure, AndroidDescriptorBudget, CloseOutcome, OriginalDescriptorBook, SlotId}};
    type Result<T> = std::result::Result<T, Failure>;
    struct BoundAlias { slot: SlotId, canonical: SlotId, target: String }
    pub(crate) struct AndroidToolchainCustody {
        profile: AndroidToolchainProfile, originals: OriginalDescriptorBook, root: Option<SlotId>,
        inventory: Option<Inventory>, aliases: Vec<BoundAlias>, inspected: bool, attempted: bool,
        stop: Option<watch::Receiver<bool>>,
    }
    impl AndroidToolchainCustody {
        pub(crate) fn new(profile: AndroidToolchainProfile, budget: Arc<AndroidDescriptorBudget>) -> Self {
            Self { profile, originals: OriginalDescriptorBook::new_android(budget), root: None, inventory: None,
                aliases: Vec::with_capacity(128), inspected: false, attempted: false, stop: None }
        }
        pub(crate) fn inspect_once(&mut self, end: Instant, stop: &watch::Receiver<bool>) -> Result<()> {
            if self.attempted { return Err(Failure::AlreadyUsed); }
            self.attempted = true; self.stop = Some(stop.clone());
            let result = self.inspect_inner(end, stop);
            if let Err(failure) = result { self.originals.refuse(failure); }
            result
        }
        fn inspect_inner(&mut self, end: Instant, stop: &watch::Receiver<bool>) -> Result<()> {
            let system = self.originals.start_android(end, stop)?;
            let mut root = system;
            for part in ["opt", "mobile-release-kit", "android", self.profile.instance.as_str()] {
                root = self.originals.directory(root, part, end, stop)?;
            }
            self.root = Some(root);
            let (manifest, bytes) = self.originals.manifest(root, MANIFEST, &self.profile.manifest_sha256, end, stop)?;
            self.inventory = Some(parse_manifest(&bytes, &self.profile).ok_or(Failure::Manifest)?);
            let inventory = self.inventory.as_ref().ok_or(Failure::LedgerInvariant)?;
            let mut pending = vec![(root, String::new())]; let mut seen = BTreeSet::new();
            while let Some((directory, relative)) = pending.pop() {
                for entry in self.originals.entries(directory, end, stop)? {
                    let name = if relative.is_empty() { entry.name.clone() } else { format!("{relative}/{}", entry.name) };
                    if !seen.insert(name.clone()) || seen.len() > 8192 { return Err(Failure::Inventory); }
                    let opened = if name == MANIFEST {
                        if entry.kind != FileType::RegularFile { return Err(Failure::Inventory); } manifest
                    } else if entry.kind == FileType::Directory {
                        if !inventory.directories.contains(&name) { return Err(Failure::Inventory); }
                        let slot = self.originals.directory(directory, &entry.name, end, stop)?;
                        pending.push((slot, name)); slot
                    } else {
                        let index = inventory.data.files.binary_search_by(|f| f.path.as_str().cmp(name.as_str())).map_err(|_| Failure::Inventory)?;
                        let f = &inventory.data.files[index];
                        self.originals.payload(directory, &entry.name, f.size, f.mode, &f.sha256, end, stop)?
                    };
                    if self.originals.identity(opened)?.inode != entry.inode { return Err(Failure::IdentityChanged); }
                }
            }
            if !seen.contains(MANIFEST) || seen.len() != inventory.data.files.len() + inventory.directories.len() + 1
                || !inventory.data.files.iter().all(|f| seen.contains(&f.path)) { return Err(Failure::Inventory); }
            let mut canonical = BTreeMap::from([("/".to_owned(), system)]);
            for f in &inventory.data.os_profile.files {
                let (parent, name) = f.path.rsplit_once('/').ok_or(Failure::Manifest)?;
                let parent = os_directory(&mut self.originals, &mut canonical, system, parent, end, stop)?;
                let slot = self.originals.payload(parent, name, f.size, f.mode, &f.sha256, end, stop)?;
                if canonical.insert(f.path.clone(), slot).is_some() { return Err(Failure::Inventory); }
            }
            for alias in &self.profile.os.aliases {
                let destination = *canonical.get(&alias.canonical).ok_or(Failure::Manifest)?;
                let (parent, name) = alias.path.rsplit_once('/').ok_or(Failure::Manifest)?;
                let parent = os_directory(&mut self.originals, &mut canonical, system, if parent.is_empty() { "/" } else { parent }, end, stop)?;
                let slot = self.originals.alias(parent, name, end, stop)?;
                self.aliases.push(BoundAlias { slot, canonical: destination, target: alias.target.clone() });
                self.originals.check_alias(slot, &alias.target, destination, end, stop)?;
            }
            self.originals.check_names(end, stop)?;
            self.originals.finish_retained()?; self.inspected = true; Ok(())
        }
        pub(crate) fn binding_data(&self) -> Result<ToolchainBinding> {
            if !self.inspected || !self.originals.ready() { return Err(Failure::TransferUnavailable); }
            let identity = self.originals.identity(self.root.ok_or(Failure::LedgerInvariant)?)?;
            ToolchainBinding::new_data(&self.profile.root, RootIdentity { device: identity.device.to_string(),
                inode: identity.inode.to_string(), mode: identity.mode, uid: identity.uid, gid: identity.gid },
                &self.profile.manifest_sha256).map_err(|_| Failure::Manifest)
        }
        pub(crate) fn check_before_spawn(&mut self, end: Instant, stop: &watch::Receiver<bool>) -> Result<()> {
            let _ = self.binding_data()?;
            self.originals.check_names(end, stop)?;
            self.originals.check_launch_thread(end, stop)?;
            for alias in &self.aliases { self.originals.check_alias(alias.slot, &alias.target, alias.canonical, end, stop)?; }
            Ok(())
        }
        pub(crate) fn check_after_use(&mut self, end: Instant) -> Result<()> {
            self.originals.audit_once(end)?;
            let stop = self.stop.clone().ok_or(Failure::LedgerInvariant)?;
            for alias in &self.aliases { self.originals.check_alias(alias.slot, &alias.target, alias.canonical, end, &stop)?; }
            Ok(())
        }
        pub(crate) fn mark_interrupted(&mut self) { self.originals.mark_interrupted(); }
        pub(crate) fn settle_originals(&mut self) -> CloseOutcome { self.originals.settle_originals() }
        pub(crate) fn settled(&self) -> bool { self.originals.settled() }
    }
    fn os_directory(book: &mut OriginalDescriptorBook, paths: &mut BTreeMap<String, SlotId>, root: SlotId,
        path: &str, end: Instant, stop: &watch::Receiver<bool>) -> Result<SlotId> {
        if path == "/" { return Ok(root); }
        let mut parent = root; let mut name = String::new();
        for component in path.strip_prefix('/').ok_or(Failure::Manifest)?.split('/') {
            name.push('/'); name.push_str(component);
            parent = if let Some(slot) = paths.get(&name) {
                if FileType::from_raw_mode(book.identity(*slot)?.mode) != FileType::Directory { return Err(Failure::Inventory); } *slot
            } else { let slot = book.directory(parent, component, end, stop)?; paths.insert(name.clone(), slot); slot };
        }
        Ok(parent)
    }
}

#[cfg(test)]
mod pure_tests {
    use super::*;
    use serde_json::{json, Value};

    // Invented JSON specs only. These are NOT an installed tuple, authenticated
    // OS closure, native book/Ready fixture or permission to execute anything.
    fn os_data() -> Value {
        let files = ["dash","sed","uname","xargs"].map(|name| json!({
            "path":format!("/usr/bin/{name}"),"size":1,"sha256":"a".repeat(64),"mode":493}));
        json!({"schemaVersion":1,"id":"inert-os-data","closure":"python-jdk-sdk-gradle-shell-loader-v1",
            "files":files,
            "aliases":[{"path":"/bin","target":"usr/bin","canonical":"/usr/bin"}]})
    }
    fn manifest_data() -> Value {
        let os = os_data(); let os_hash = digest(&serde_json::to_vec(&os).unwrap());
        let files = ["bundletool/bundletool.jar","gradle/bin/gradle","jdk/bin/java","jdk/bin/javac","sdk/licenses/inert"]
            .map(|path| json!({"path":path,"size":1,"mode":493,
                "sha256":if path == "bundletool/bundletool.jar" { BUNDLETOOL_SHA256.to_owned() } else { "a".repeat(64) }}));
        json!({"schemaVersion":1,"profile":PROFILE,"target":TARGET,"instance":"inert-data-only",
            "launchContract":"gradle-posix-private-jvm-v1",
            "versions":{"jdkVendor":"inert","jdkVersion":"1","gradleVersion":"1","agpVersion":"1",
                "sdkPlatform":"android-1","sdkPlatformRevision":"1","sdkBuildToolsVersion":"1"},
            "gradleDistribution":{"url":"https://services.gradle.org/distributions/gradle-1-bin.zip","sha256":"a".repeat(64)},
            "bundletool":{"version":"1.18.3","sha256":BUNDLETOOL_SHA256},
            "roles":{"java":"jdk/bin/java","javac":"jdk/bin/javac","gradle":"gradle/bin/gradle",
                "bundletool":"bundletool/bundletool.jar","sdk":"sdk"},
            "files":files,
            "osProfile":{"id":"inert-os-data","inventorySha256":os_hash,"shell":"/usr/bin/dash",
                "executableDirectory":"/usr/bin","helpers":["sed","uname","xargs"],"files":os["files"]}})
    }
    fn profile(raw: &[u8]) -> AndroidToolchainProfile {
        let os = serde_json::to_vec(&os_data()).unwrap();
        AndroidToolchainProfile { instance: "inert-data-only".into(), root: PathBuf::from(PREFIX).join("inert-data-only"),
            manifest_sha256: digest(raw), os: parse_os_contract(&os, &digest(&os)).unwrap() }
    }
    fn manifest_valid(value: &Value) -> bool {
        let raw = serde_json::to_vec(value).unwrap(); parse_manifest(&raw, &profile(&raw)).is_some()
    }
    fn os_valid(value: &Value) -> bool {
        let raw = serde_json::to_vec(value).unwrap(); parse_os_contract(&raw, &digest(&raw)).is_some()
    }
    #[test]
    fn absent_compiled_profile_and_whole_manifest_binding_are_not_authority() {
        assert!(OS_CONTRACT_BYTES.is_none() && AndroidToolchainProfile::compiled().is_none());
        let raw = serde_json::to_vec(&manifest_data()).unwrap(); let profile = profile(&raw);
        let parsed = parse_manifest(&raw, &profile).unwrap();
        assert_eq!(parsed.data.files.len(), 5);
        assert_eq!(profile.root, PathBuf::from("/opt/mobile-release-kit/android/inert-data-only"));
        let mut changed = raw.clone(); changed.push(b' ');
        assert!(parse_manifest(&changed, &profile).is_none()); // Equal JSON is not equal anchored bytes.
        let mut unknown = manifest_data(); unknown["allowFallback"] = json!(true);
        assert!(!manifest_valid(&unknown));
        let duplicate = String::from_utf8(raw).unwrap().replacen("\"schemaVersion\":1", "\"schemaVersion\":1,\"schemaVersion\":1", 1).into_bytes();
        assert!(parse_manifest(&duplicate, &self::profile(&duplicate)).is_none());
    }
    #[test]
    fn manifest_requires_fixed_roles_contract_helpers_and_compiled_os_files() {
        assert!(manifest_valid(&manifest_data()));
        for role in ["java", "javac", "gradle", "bundletool", "sdk"] {
            let mut value = manifest_data(); value["roles"].as_object_mut().unwrap().remove(role);
            assert!(!manifest_valid(&value), "missing role {role}");
        }
        for file in ["jdk/bin/java", "jdk/bin/javac", "gradle/bin/gradle", "bundletool/bundletool.jar", "sdk/licenses/inert"] {
            let mut value = manifest_data(); value["files"].as_array_mut().unwrap().retain(|f| f["path"] != file);
            assert!(!manifest_valid(&value), "missing file {file}");
        }
        for (pointer, replacement) in [
            ("/instance", json!("another-instance")), ("/launchContract", json!("shell-fallback")),
            ("/versions/gradleVersion", json!("2")), ("/versions/sdkPlatform", json!("android-01")),
            ("/gradleDistribution/url", json!("https://untrusted.invalid/gradle-1-bin.zip")),
            ("/bundletool/sha256", json!("b".repeat(64))), ("/roles/java", json!("/usr/bin/java")),
            ("/osProfile/id", json!("another-os")), ("/osProfile/inventorySha256", json!("b".repeat(64))),
            ("/osProfile/files/0/sha256", json!("b".repeat(64))), ("/osProfile/helpers", json!(["sed","uname"])),
            ("/osProfile/helpers", json!(["uname","sed","xargs"])), ("/files/2/mode", json!(420)),
        ] {
            let mut value = manifest_data(); *value.pointer_mut(pointer).unwrap() = replacement;
            assert!(!manifest_valid(&value), "{pointer}");
        }
    }
    #[test]
    fn inventories_refuse_fixed_byte_file_entry_mode_and_path_bounds() {
        for (pointer, replacement) in [
            ("/files/0/size", json!(BUNDLETOOL_MAX_BYTES + 1)), ("/files/2/size", json!(FILE_LIMIT + 1)),
            ("/files/2/mode", json!(0o775)), ("/files/2/mode", json!(0o4755)),
        ] {
            let mut value = manifest_data(); *value.pointer_mut(pointer).unwrap() = replacement;
            assert!(!manifest_valid(&value), "{pointer}");
        }
        let mut over_total = manifest_data();
        over_total["files"][2]["size"] = json!(FILE_LIMIT); over_total["files"][3]["size"] = json!(FILE_LIMIT);
        assert!(!manifest_valid(&over_total));
        let mut over_os = os_data();
        for f in over_os["files"].as_array_mut().unwrap() { f["size"] = json!(FILE_LIMIT); }
        assert!(!os_valid(&over_os));
        let spec = |path| FileSpec { path, size: 1, sha256: "a".repeat(64), mode: 0o644 };
        for path in ["sdk/../outside".into(), "sdk/file.".into(), format!("sdk/{}", "a".repeat(512)),
            format!("sdk/{}file", "a/".repeat(16)), "jdk/bin/Java".into(), "jdk/bin".into()] {
            let mut files: Vec<FileSpec> = serde_json::from_value(manifest_data()["files"].clone()).unwrap();
            files.push(spec(path)); files.sort_by(|a, b| a.path.cmp(&b.path));
            assert!(!files_valid(&files, false));
        }
        let files: Vec<_> = (0..2048).map(|n| spec(format!("sdk/file-{n:04}"))).collect();
        assert!(files_valid(&files, false));
        let mut too_many = files.clone(); too_many.push(spec("sdk/file-2048".into()));
        assert!(!files_valid(&too_many, false));
        let entries: Vec<_> = (0..2048).map(|n| spec(format!("sdk/d{n:04}/a/b/file"))).collect();
        assert!(!files_valid(&entries, false)); // 8194 files/derived directories/manifest entries.
        let native: Vec<_> = (0..129).map(|n| spec(format!("/usr/lib/inert-{n:03}"))).collect();
        assert!(files_valid(&native[..128], true) && !files_valid(&native, true));
        let oversized = vec![b' '; MANIFEST_LIMIT + 1];
        assert!(parse_manifest(&oversized, &profile(&oversized)).is_none());
    }
    #[test]
    fn os_alias_contract_requires_exact_retained_canonical_destinations() {
        assert!(os_valid(&os_data()));
        for (pointer, replacement) in [
            ("/aliases/0/path", json!("/tmp/bin")),
            ("/aliases/0/target", json!("usr/lib")), ("/aliases/0/target", json!("../../usr/bin")),
            ("/aliases/0/canonical", json!("/usr/unlisted")), ("/closure", json!("jdk-only")),
        ] {
            let mut value = os_data(); *value.pointer_mut(pointer).unwrap() = replacement;
            assert!(!os_valid(&value), "{pointer}");
        }
        let mut duplicate = os_data(); let alias = duplicate["aliases"][0].clone();
        duplicate["aliases"].as_array_mut().unwrap().push(alias); assert!(!os_valid(&duplicate));
        let mut collision = os_data(); collision["aliases"][0]["path"] = json!("/usr/BIN");
        collision["aliases"][0]["target"] = json!("bin"); assert!(!os_valid(&collision));
        let raw = serde_json::to_vec(&os_data()).unwrap();
        assert!(parse_os_contract(&raw, &"b".repeat(64)).is_none());
    }
}
