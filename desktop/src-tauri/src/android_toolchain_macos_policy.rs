//! Closed macOS ARM64 Android tool-registration DATA policy.
//! No object parsed here grants native custody, registration or execution.
use std::collections::{BTreeMap, BTreeSet};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use crate::{android_build_protocol::{MacToolchainSelection, MAC_TOOLCHAIN_PROFILE},
    protocol::{strict_android_tool_manifest_json, strict_json}};

pub(crate) const MANIFEST: &str = "android-toolchain.json";
pub(crate) const RECORD: &str = "registration.json";
pub(crate) const PROVIDER: &str = "os-provider.json";
pub(crate) const AAPT2: &str = "gradle/native/aapt2/aapt2";
pub(crate) const FILE_LIMIT: u64 = 512 * 1024 * 1024;
pub(crate) const TOTAL_LIMIT: u64 = 1024 * 1024 * 1024;
pub(crate) const ENTRY_LIMIT: usize = 32_768;
pub(crate) const FILE_COUNT: usize = 16_384;
pub(crate) const ALIAS_COUNT: usize = 128;
pub(crate) const MANIFEST_LIMIT: usize = 4 * 1024 * 1024;
pub(crate) const PROVIDER_LIMIT: usize = 64 * 1024;
pub(crate) const RECORD_LIMIT: usize = 4096;
pub(crate) const OS_FILES: [&str; 8] = ["/System/Library/CoreServices/SystemVersion.plist", "/bin/sh",
    "/usr/bin/basename", "/usr/bin/dirname", "/usr/bin/sed", "/usr/bin/tr", "/usr/bin/uname", "/usr/bin/xargs"];
pub(crate) const OS_ROOTS: [&str; 2] = ["/System/Library", "/usr/lib"];
pub(crate) const OS_PROFILE: &str = "macos26-arm64-sealed-system-v1";
const BUNDLETOOL_SHA: &str = "a099cfa1543f55593bc2ed16a70a7c67fe54b1747bb7301f37fdfd6d91028e29";
const BUNDLETOOL_BYTES: u64 = 32_520_401;

pub(crate) fn digest(raw: &[u8]) -> String { Sha256::digest(raw).iter().map(|b| format!("{b:02x}")).collect() }
fn sha(v: &str) -> bool { v.len() == 64 && v.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) }
pub(crate) fn component(v: &str) -> bool {
    !v.is_empty() && v.len() <= 255 && !matches!(v, "." | "..") && !v.ends_with('.') && !v.ends_with(' ')
        && v.bytes().all(|b| b.is_ascii_alphanumeric() || b"_+@.,= -".contains(&b))
}
pub(crate) fn relative(v: &str) -> bool {
    !v.is_empty() && v.len() <= 512 && v.split('/').count() <= 16 && v.split('/').all(component)
}
fn label(v: &str, version: bool) -> bool {
    !v.is_empty() && v.len() <= (if version { 64 } else { 128 })
        && v.bytes().next().is_some_and(|b| if version { b.is_ascii_digit() } else { b.is_ascii_alphanumeric() })
        && v.bytes().all(|b| b.is_ascii_alphanumeric() || b"_.+-".contains(&b))
}
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct FileSpec { pub(crate) path: String, pub(crate) size: u64, pub(crate) sha256: String, pub(crate) mode: u32 }
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Alias { pub(crate) path: String, pub(crate) target: String, pub(crate) canonical: String }
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Roles { pub(crate) java: String, pub(crate) javac: String, pub(crate) gradle: String, pub(crate) bundletool: String, pub(crate) sdk: String }
impl Roles {
    pub(crate) fn java_home(&self) -> Option<&str> {
        let home = self.java.strip_suffix("/bin/java")?;
        let parts: Vec<_> = home.split('/').collect();
        (parts.len() == 4 && parts[0] == "jdk" && component(parts[1]) && parts[1].ends_with(".jdk")
            && parts[1].len() > 4 && parts[2..] == ["Contents", "Home"]).then_some(home)
    }
    fn valid(&self) -> bool {
        self.java_home().is_some_and(|home| self.javac == format!("{home}/bin/javac"))
            && self.gradle == "gradle/bin/gradle" && self.bundletool == "bundletool/bundletool.jar" && self.sdk == "sdk"
    }
    pub(crate) fn launch(&self) -> Vec<String> {
        let mut out = vec![self.java.clone(), self.javac.clone(), self.gradle.clone(), self.bundletool.clone(), AAPT2.into()];
        if let Some(home) = self.java_home() { out.extend([format!("{home}/bin/jarsigner"), format!("{home}/bin/keytool")]); }
        out
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Versions {
    pub(crate) jdk_vendor: String, pub(crate) jdk_version: String, pub(crate) gradle_version: String, pub(crate) agp_version: String,
    pub(crate) sdk_platform: String, pub(crate) sdk_platform_revision: String, pub(crate) sdk_build_tools_version: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Distribution { pub(crate) url: String, pub(crate) sha256: String }
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Bundletool { version: String, sha256: String }
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Manifest {
    schema_version: u32, profile: String, target: String, instance: String, launch_contract: String,
    pub(crate) versions: Versions, pub(crate) gradle_distribution: Distribution, bundletool: Bundletool,
    pub(crate) roles: Roles, pub(crate) files: Vec<FileSpec>, pub(crate) aliases: Vec<Alias>, os_provider_sha256: String,
}
pub(crate) struct Inventory { pub(crate) data: Manifest, pub(crate) directories: BTreeSet<String> }
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Registration {
    schema_version: u32, profile: String, target: String, pub(crate) instance: String, pub(crate) owner_uid: u32,
    pub(crate) inventory_sha256: String, pub(crate) os_provider_sha256: String, license_acknowledged: bool,
}
impl Registration {
    pub(crate) fn parse(raw: &[u8], account: u32, instance: &str) -> Option<Self> {
        if raw.is_empty() || raw.len() > RECORD_LIMIT || account == 0 || account == u32::MAX { return None; }
        let value: Self = serde_json::from_value(strict_json(raw).ok()?).ok()?;
        (value.schema_version == 1 && value.profile == MAC_TOOLCHAIN_PROFILE && value.target == "macos-arm64"
            && value.instance == instance && instance.len() == 32 && instance.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && value.owner_uid == account && sha(&value.inventory_sha256) && sha(&value.os_provider_sha256)
            && value.license_acknowledged).then_some(value)
    }
    pub(crate) fn matches(&self, selected: &MacToolchainSelection) -> bool {
        selected.valid() && self.instance == selected.instance && self.owner_uid == selected.owner_uid
            && self.inventory_sha256 == selected.inventory_sha256 && self.os_provider_sha256 == selected.os_provider_sha256
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Provider {
    schema_version: u32, profile: String, target: String, shell: String, executable_path: Vec<String>, roots: Vec<String>,
    pub(crate) files: Vec<FileSpec>,
}
impl Provider {
    pub(crate) fn parse(raw: &[u8], selected: &MacToolchainSelection) -> Option<Self> {
        if raw.is_empty() || raw.len() > PROVIDER_LIMIT || digest(raw) != selected.os_provider_sha256 { return None; }
        let value: Self = serde_json::from_value(strict_json(raw).ok()?).ok()?;
        if value.schema_version != 1 || value.profile != OS_PROFILE || value.target != "macos-arm64" || value.shell != "/bin/sh"
            || value.executable_path != ["/usr/bin", "/bin"] || value.roots != OS_ROOTS
            || value.files.len() != OS_FILES.len() { return None; }
        for (file, expected) in value.files.iter().zip(OS_FILES) {
            if file.path != expected || file.size == 0 || file.size > FILE_LIMIT || !sha(&file.sha256)
                || !(if expected.ends_with(".plist") { matches!(file.mode, 0o444 | 0o644) } else { matches!(file.mode, 0o555 | 0o755) }) { return None; }
        }
        Some(value)
    }
}
// Lexical alias resolution only. Native reads the original link; never follow
// it during inventory. Targets must be regular members of the same JDK bundle.
pub(crate) fn alias_target(alias: &Alias) -> Option<String> {
    if !relative(&alias.path) || !relative(&alias.canonical) || alias.target.is_empty() || alias.target.len() > 512
        || alias.target.starts_with('/') || !alias.path.starts_with("jdk/") || !alias.canonical.starts_with("jdk/") { return None; }
    let mut parts: Vec<_> = alias.path.split('/').collect(); parts.pop()?;
    for part in alias.target.split('/') {
        match part {
            ".." => { parts.pop()?; },
            "." => {},
            _ if component(part) => parts.push(part),
            _ => return None,
        }
    }
    let out = parts.join("/");
    (out == alias.canonical && alias.path.split('/').take(2).eq(out.split('/').take(2))).then_some(out)
}
pub(crate) fn parse_manifest(raw: &[u8], selected: &MacToolchainSelection) -> Option<Inventory> {
    if !selected.valid() || raw.is_empty() || raw.len() > MANIFEST_LIMIT || digest(raw) != selected.inventory_sha256 { return None; }
    let value: Manifest = serde_json::from_value(strict_android_tool_manifest_json(raw).ok()?).ok()?;
    if value.schema_version != 1 || value.profile != MAC_TOOLCHAIN_PROFILE || value.target != "macos-arm64"
        || value.instance != selected.instance || value.os_provider_sha256 != selected.os_provider_sha256
        || value.launch_contract != "gradle-macos-private-jvm-arm64-v1" || !value.roles.valid()
        || value.files.is_empty() || value.files.len() > FILE_COUNT || value.aliases.len() > ALIAS_COUNT { return None; }
    let v = &value.versions;
    if !label(&v.jdk_vendor, false) || !v.jdk_version.starts_with("17.") || !label(&v.jdk_version, true)
        || ![&v.gradle_version, &v.agp_version, &v.sdk_platform_revision, &v.sdk_build_tools_version].into_iter().all(|s| label(s, true))
        || !v.sdk_platform.strip_prefix("android-").is_some_and(|n| !n.is_empty() && n.len() <= 3 && !n.starts_with('0') && n.bytes().all(|b| b.is_ascii_digit()))
        || !["services.gradle.org", "downloads.gradle.org"].into_iter().any(|host|
            value.gradle_distribution.url == format!("https://{host}/distributions/gradle-{}-bin.zip", v.gradle_version))
        || !sha(&value.gradle_distribution.sha256) || value.bundletool.version != "1.18.3" || value.bundletool.sha256 != BUNDLETOOL_SHA { return None; }
    if !value.files.windows(2).all(|p| p[0].path < p[1].path) || !value.aliases.windows(2).all(|p| p[0].path < p[1].path) { return None; }
    let mut names = BTreeSet::new(); let mut directories = BTreeSet::new(); let mut total = 0u64;
    let mut exact = BTreeMap::new();
    for file in &value.files {
        if !relative(&file.path) || !file.path.split_once('/').is_some_and(|(p,_)| matches!(p,"jdk"|"gradle"|"sdk"|"bundletool"))
            || !sha(&file.sha256) || !matches!(file.mode,0o444|0o555) || file.size > FILE_LIMIT
            || !names.insert(file.path.to_ascii_lowercase()) { return None; }
        total = total.checked_add(file.size)?; if total > TOTAL_LIMIT { return None; }
        exact.insert(file.path.as_str(), file);
    }
    for alias in &value.aliases {
        if alias_target(alias).is_none() || !exact.contains_key(alias.canonical.as_str())
            || !names.insert(alias.path.to_ascii_lowercase()) { return None; }
    }
    for path in value.files.iter().map(|f| &f.path).chain(value.aliases.iter().map(|a| &a.path)) {
        let mut part = path.as_str();
        while let Some((parent,_)) = part.rsplit_once('/') { directories.insert(parent.to_owned()); part = parent; }
    }
    for dir in &directories { if !names.insert(dir.to_ascii_lowercase()) { return None; } }
    if names.len() + 3 > ENTRY_LIMIT { return None; }
    for name in [MANIFEST,RECORD,PROVIDER] { if !names.insert(name.into()) { return None; } }
    let required = value.roles.launch();
    if required.iter().filter(|name| name.as_str() != value.roles.bundletool.as_str())
        .any(|name| exact.get(name.as_str()).is_none_or(|f| f.mode != 0o555 || f.size == 0))
        || exact.get(AAPT2).is_none_or(|f| f.mode != 0o555 || f.size == 0) { return None; }
    let jar = exact.get(value.roles.bundletool.as_str())?;
    if jar.sha256 != BUNDLETOOL_SHA || jar.size == 0 || jar.size > BUNDLETOOL_BYTES || jar.mode != 0o444
        || !value.files.iter().any(|f| f.path.starts_with("sdk/")) { return None; }
    // No second bundle may supply unselected JDK/native files.
    let bundle = value.roles.java.split('/').take(2).collect::<Vec<_>>().join("/") + "/";
    if value.files.iter().any(|f| f.path.starts_with("jdk/") && !f.path.starts_with(&bundle))
        || value.aliases.iter().any(|a| !a.path.starts_with(&bundle) || !a.canonical.starts_with(&bundle)) { return None; }
    Some(Inventory { data: value, directories })
}

/// Architecture selection is a file-data predicate, not execution/Rosetta.
/// Only ARM64 or universal files containing a complete ARM64 slice may launch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct MachSlice { pub(crate) offset: u64, pub(crate) size: u64 }
pub(crate) fn arm64_slice(prefix: &[u8], size: u64) -> Option<MachSlice> {
    const ARM64: u32 = 0x0100000c;
    const X64: u32 = 0x01000007;
    if size < 32 || prefix.len() < 8 { return None; }
    let le = |at: usize| prefix.get(at..at+4).and_then(|s| s.try_into().ok()).map(u32::from_le_bytes);
    let be = |at: usize| prefix.get(at..at+4).and_then(|s| s.try_into().ok()).map(u32::from_be_bytes);
    if prefix.starts_with(&[0xcf,0xfa,0xed,0xfe]) {
        return (le(4)? == ARM64).then_some(MachSlice { offset:0, size });
    }
    // Mach universal 32/64 tables, big-endian; swapped/legacy variants refuse.
    let wide = match be(0)? { 0xcafebabe => false, 0xcafebabf => true, _ => return None };
    let count = usize::try_from(be(4)?).ok()?; if !(1..=4).contains(&count) { return None; }
    let width = if wide { 32 } else { 20 }; let table_end = 8 + count*width;
    if prefix.len() < table_end { return None; }
    let mut selected = None; let mut ranges = Vec::new(); let mut seen = BTreeSet::new();
    for index in 0..count {
        let at = 8 + index*width; let cpu = be(at)?;
        if !matches!(cpu, ARM64|X64) || !seen.insert(cpu) { return None; }
        let u64be = |at:usize| prefix.get(at..at+8).and_then(|s|s.try_into().ok()).map(u64::from_be_bytes);
        let (offset, length, align) = if wide { (u64be(at+8)?, u64be(at+16)?, be(at+24)?) }
            else { (u64::from(be(at+8)?), u64::from(be(at+12)?), be(at+16)?) };
        let end = offset.checked_add(length)?;
        if wide && be(at+28)? != 0 || align > 20 || offset % (1u64 << align) != 0 || offset < table_end as u64
            || length < 32 || end > size
            || ranges.iter().any(|(start, previous_end)| offset < *previous_end && *start < end) { return None; }
        ranges.push((offset, end));
        if cpu == ARM64 { selected = Some(MachSlice { offset, size:length }); }
    }
    selected
}
#[derive(Debug)]
pub(crate) struct MachCommands { pub(crate) loads: Vec<String>, pub(crate) rpaths: Vec<String> }
/// Parse the selected original ARM64 header/load-command bytes (not the file's
/// first arbitrary text block). Loader paths remain subject to native resolution.
pub(crate) fn macho_commands(raw: &[u8], slice: MachSlice) -> Option<MachCommands> {
    if raw.len() < 32 || !raw.starts_with(&[0xcf,0xfa,0xed,0xfe]) { return None; }
    let le = |at:usize| raw.get(at..at+4).and_then(|s|s.try_into().ok()).map(u32::from_le_bytes);
    if le(4)? != 0x0100000c || !matches!(le(12)?, 2|6|8) { return None; }
    let count = usize::try_from(le(16)?).ok()?; let bytes = usize::try_from(le(20)?).ok()?;
    if count > 1024 || bytes > 256*1024 || bytes.checked_add(32)? > raw.len() || (bytes+32) as u64 > slice.size { return None; }
    let end = bytes + 32; let mut at = 32; let mut loads = Vec::new(); let mut rpaths = Vec::new();
    for _ in 0..count {
        let command = le(at)?; let length = usize::try_from(le(at+4)?).ok()?;
        if length < 8 || length % 8 != 0 || at.checked_add(length)? > end { return None; }
        if matches!(command,0x0c|0x20|0x80000018|0x8000001f|0x80000023|0x8000001c|0x0e) {
            let minimum = if command == 0x8000001c || command == 0x0e { 12 } else { 24 };
            if length < minimum { return None; }
            let offset = usize::try_from(le(at+8)?).ok()?;
            if offset < minimum || offset >= length { return None; }
            let string = &raw[at+offset..at+length];
            let nul = string.iter().position(|b| *b == 0)?;
            let text = std::str::from_utf8(&string[..nul]).ok()?;
            if text.is_empty() || text.len() > 512 || text.chars().any(|c| c.is_control() || c == '\\' || c == ':') { return None; }
            if command == 0x8000001c { rpaths.push(text.into()); }
            else if command == 0x0e { if text != "/usr/lib/dyld" { return None; } }
            else { loads.push(text.into()); }
        }
        // Runtime environment declarations cannot introduce native provider paths.
        if command == 0x27 { return None; } // LC_DYLD_ENVIRONMENT
        at += length;
    }
    (at == end).then_some(MachCommands { loads, rpaths })
}

/// Sealed-system references are a separate admitted provider, never ambient PATH.
pub(crate) fn system_load(value: &str) -> bool {
    (value.starts_with("/usr/lib/") || value.starts_with("/System/Library/")) && relative(&value[1..])
}
fn resolve(base: &str, tail: &str) -> Option<String> {
    let mut parts: Vec<_> = base.split('/').filter(|p| !p.is_empty()).collect();
    for part in tail.split('/') {
        match part { ".." => { parts.pop()?; }, "." => {}, _ if component(part) => parts.push(part), _ => return None }
    }
    let value = parts.join("/"); relative(&value).then_some(value)
}
/// Every declared loader search root must itself be protected. A missing member
/// under an admitted immutable root is harmless; a writable/unknown search root
/// cannot be ignored merely because another candidate happens to exist.
pub(crate) fn local_loads(path: &str, commands: &MachCommands, inventory: &Inventory) -> bool {
    let parent = path.rsplit_once('/').map_or("", |(p,_)| p);
    let jdk_bundle = inventory.data.roles.java.split('/').take(2).collect::<Vec<_>>().join("/") + "/";
    let executable_parent = if path.starts_with(&jdk_bundle) {
        // Every permitted JDK launcher lives in this same Contents/Home/bin.
        inventory.data.roles.java.rsplit_once('/').map(|(p,_)| p)
    } else if inventory.data.roles.launch().iter().any(|p| p == path) { Some(parent) } else { None };
    let token = |value: &str| -> Option<String> {
        if value == "@loader_path" { return Some(parent.into()); }
        if let Some(tail) = value.strip_prefix("@loader_path/") { return resolve(parent,tail); }
        if value == "@executable_path" { return executable_parent.map(str::to_owned); }
        if let Some(tail) = value.strip_prefix("@executable_path/") { return resolve(executable_parent?,tail); }
        None
    };
    let mut search = Vec::new();
    for value in &commands.rpaths {
        if OS_ROOTS.contains(&value.as_str()) || system_load(value) { search.push((true, value[1..].to_owned())); }
        else if let Some(path) = token(value) { search.push((false,path)); }
        else { return false; }
    }
    for load in &commands.loads {
        if system_load(load) { continue; }
        let mut candidates = BTreeSet::new();
        if let Some(tail) = load.strip_prefix("@rpath/") {
            for (system, root) in &search {
                let Some(path) = resolve(root,tail) else { return false; };
                if *system {
                    if !system_load(&("/".to_owned()+&path)) { return false; }
                    // The immutable native OS provider is admitted separately.
                    candidates.insert("/".to_owned()+&path);
                } else {
                    let canonical = inventory.data.aliases.iter().find(|a| a.path == path).map_or(path.as_str(), |a|a.canonical.as_str());
                    if inventory.data.files.iter().any(|f| f.path == canonical) { candidates.insert(canonical.to_owned()); }
                }
            }
        } else {
            let Some(path) = token(load) else { return false; };
            let canonical = inventory.data.aliases.iter().find(|a| a.path == path).map_or(path.as_str(), |a|a.canonical.as_str());
            if inventory.data.files.iter().any(|f| f.path == canonical) { candidates.insert(canonical.to_owned()); }
        }
        // Refuse ambiguous provider selection instead of inventing dyld facts.
        if candidates.len() != 1 { return false; }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};
    fn fixture() -> (MacToolchainSelection, Value) {
        let selected = MacToolchainSelection { instance:"a".repeat(32), owner_uid:501, catalog_generation:1,
            record_sha256:"b".repeat(64), inventory_sha256:"c".repeat(64), os_provider_sha256:"d".repeat(64) };
        let home = "jdk/Test.jdk/Contents/Home";
        let mut entries: Vec<Value> = ["java","javac","jarsigner","keytool"].iter().map(|name|
            json!({"path":format!("{home}/bin/{name}"),"mode":0o555,"size":1,"sha256":"e".repeat(64)})).collect();
        entries.extend([
            json!({"path":"gradle/bin/gradle","mode":0o555,"size":1,"sha256":"e".repeat(64)}),
            json!({"path":AAPT2,"mode":0o555,"size":1,"sha256":"e".repeat(64)}),
            json!({"path":"sdk/platforms/android-35/android.jar","mode":0o444,"size":1,"sha256":"e".repeat(64)}),
            json!({"path":format!("{home}/lib/jli/libjli.dylib"),"mode":0o444,"size":1,"sha256":"e".repeat(64)}),
            json!({"path":"bundletool/bundletool.jar","mode":0o444,"size":BUNDLETOOL_BYTES,"sha256":BUNDLETOOL_SHA}),
        ]);
        entries.sort_by(|a,b| a["path"].as_str().cmp(&b["path"].as_str()));
        let value = json!({"schemaVersion":1,"profile":MAC_TOOLCHAIN_PROFILE,"target":"macos-arm64","instance":selected.instance,
            "launchContract":"gradle-macos-private-jvm-arm64-v1",
            "versions":{"jdkVendor":"test","jdkVersion":"17.0.1","gradleVersion":"8.14.5","agpVersion":"8.9.2",
                "sdkPlatform":"android-35","sdkPlatformRevision":"2","sdkBuildToolsVersion":"35.0.0"},
            "gradleDistribution":{"url":"https://services.gradle.org/distributions/gradle-8.14.5-bin.zip","sha256":"e".repeat(64)},
            "bundletool":{"version":"1.18.3","sha256":BUNDLETOOL_SHA},
            "roles":{"java":format!("{home}/bin/java"),"javac":format!("{home}/bin/javac"),"gradle":"gradle/bin/gradle",
                "bundletool":"bundletool/bundletool.jar","sdk":"sdk"},
            "files":entries,"aliases":[],"osProviderSha256":selected.os_provider_sha256});
        (selected,value)
    }
    fn inventory(selected:&mut MacToolchainSelection, value:&Value) -> Option<Inventory> {
        let raw=serde_json::to_vec(value).unwrap();selected.inventory_sha256=digest(&raw);parse_manifest(&raw,selected)
    }
    pub(super) fn closed_mac_roles_membership_and_selected_hashes_are_required_data() {
        let (mut selected,value)=fixture();
        assert!(inventory(&mut selected,&value).is_some()); // DATA predicate only.
        let raw=serde_json::to_vec(&value).unwrap();let mut foreign=selected.clone();foreign.inventory_sha256="f".repeat(64);
        assert!(parse_manifest(&raw,&foreign).is_none());
        for (field,replacement) in [("profile",json!("android-registered-linux-x64-v1")),
            ("target",json!("linux-x64")),("instance",json!("f".repeat(32))),("launchContract",json!("anything"))] {
            let mut changed=value.clone();changed[field]=replacement;assert!(inventory(&mut selected,&changed).is_none(),"{field}");
        }
        let mut changed=value.clone();changed["roles"]["java"]=json!("jdk/bin/java");
        assert!(inventory(&mut selected,&changed).is_none());
        let mut changed=value.clone();changed["files"].as_array_mut().unwrap().retain(|file|
            file["path"]!="jdk/Test.jdk/Contents/Home/bin/keytool");
        assert!(inventory(&mut selected,&changed).is_none());
        for path in ["jdk/Test.jdk/Contents/Home/bin/JAVA","gradle/bin"] {
            let mut changed=value.clone();let entries=changed["files"].as_array_mut().unwrap();
            entries.push(json!({"path":path,"mode":0o444,"size":1,"sha256":"e".repeat(64)}));
            entries.sort_by(|a,b|a["path"].as_str().cmp(&b["path"].as_str()));
            assert!(inventory(&mut selected,&changed).is_none(),"{path}");
        }
    }
    pub(super) fn aliases_cannot_escape_change_bundles_or_point_to_another_alias_data() {
        let alias=Alias {path:"jdk/Test.jdk/Contents/Home/lib/jli/link.dylib".into(),target:"libjli.dylib".into(),
            canonical:"jdk/Test.jdk/Contents/Home/lib/jli/libjli.dylib".into()};
        assert_eq!(alias_target(&alias),Some(alias.canonical.clone()));
        for target in ["/usr/lib/libjli.dylib","../../../../../../tmp/file","../../../../../Other.jdk/file",""] {
            assert!(alias_target(&Alias {target:target.into(),..alias.clone()}).is_none());
        }
        let (mut selected,mut value)=fixture();
        value["aliases"]=json!([{"path":alias.path,"target":alias.target,"canonical":alias.canonical}]);
        assert!(inventory(&mut selected,&value).is_some());
        value["aliases"][0]["canonical"]=json!("jdk/Test.jdk/Contents/Home/lib/jli/second.dylib");
        value["aliases"][0]["target"]=json!("second.dylib");
        assert!(inventory(&mut selected,&value).is_none());
    }
    pub(super) fn registration_and_os_provider_are_closed_and_account_bound_data() {
        let (mut selected,_)=fixture();
        let record=json!({"schemaVersion":1,"profile":MAC_TOOLCHAIN_PROFILE,"target":"macos-arm64","instance":selected.instance,
            "ownerUid":501,"inventorySha256":selected.inventory_sha256,"osProviderSha256":selected.os_provider_sha256,"licenseAcknowledged":true});
        let bytes=serde_json::to_vec(&record).unwrap();
        assert!(Registration::parse(&bytes,501,&selected.instance).unwrap().matches(&selected));
        assert!(Registration::parse(&bytes,502,&selected.instance).is_none());
        let mut denied=record;denied["licenseAcknowledged"]=json!(false);
        assert!(Registration::parse(&serde_json::to_vec(&denied).unwrap(),501,&selected.instance).is_none());
        let provider=json!({"schemaVersion":1,"profile":OS_PROFILE,"target":"macos-arm64","shell":"/bin/sh",
            "executablePath":["/usr/bin","/bin"],"roots":OS_ROOTS,"files":OS_FILES.iter().map(|path|
                json!({"path":path,"size":1,"sha256":"e".repeat(64),"mode":if path.ends_with(".plist"){0o644}else{0o755}})).collect::<Vec<_>>()});
        let bytes=serde_json::to_vec(&provider).unwrap();selected.os_provider_sha256=digest(&bytes);
        assert!(Provider::parse(&bytes,&selected).is_some());
        let mut borrowed=provider;borrowed["executablePath"]=json!(["/usr/local/bin","/usr/bin","/bin"]);
        let bytes=serde_json::to_vec(&borrowed).unwrap();selected.os_provider_sha256=digest(&bytes);
        assert!(Provider::parse(&bytes,&selected).is_none());
    }
    fn word(raw:&mut [u8], at:usize, n:u32, big:bool) {
        raw[at..at+4].copy_from_slice(&if big {n.to_be_bytes()}else{n.to_le_bytes()});
    }
    pub(super) fn universal_architecture_table_may_be_unsorted_but_never_overlapping_or_intel_only_data() {
        let mut fat=vec![0u8;48];word(&mut fat,0,0xcafebabe,true);word(&mut fat,4,2,true);
        for (at,cpu,offset) in [(8,0x0100000c,256),(28,0x01000007,64)] {
            word(&mut fat,at,cpu,true);word(&mut fat,at+8,offset,true);word(&mut fat,at+12,32,true);word(&mut fat,at+16,3,true);
        }
        assert_eq!(arm64_slice(&fat,512),Some(MachSlice {offset:256,size:32}));
        word(&mut fat,36,264,true);assert!(arm64_slice(&fat,512).is_none());
        word(&mut fat,4,1,true);word(&mut fat,8,0x01000007,true);assert!(arm64_slice(&fat,512).is_none());
        let mut thin=vec![0;32];word(&mut thin,0,0xfeedfacf,false);word(&mut thin,4,0x0100000c,false);
        assert!(arm64_slice(&thin,32).is_some());word(&mut thin,4,0x01000007,false);assert!(arm64_slice(&thin,32).is_none());
    }
    pub(super) fn lazy_load_paths_are_parsed_and_loader_environment_commands_refused_data() {
        let path=b"/usr/lib/libSystem.B.dylib";
        let length=(24+path.len()+1+7)&!7;let mut raw=vec![0;32+length];
        word(&mut raw,0,0xfeedfacf,false);word(&mut raw,4,0x0100000c,false);word(&mut raw,12,2,false);
        word(&mut raw,16,1,false);word(&mut raw,20,length as u32,false);
        word(&mut raw,32,0x20,false);word(&mut raw,36,length as u32,false);word(&mut raw,40,24,false);
        raw[56..56+path.len()].copy_from_slice(path);
        let slice=MachSlice {offset:0,size:raw.len() as u64};
        assert_eq!(macho_commands(&raw,slice).unwrap().loads,vec![String::from_utf8(path.to_vec()).unwrap()]);
        word(&mut raw,32,0x27,false);assert!(macho_commands(&raw,slice).is_none());
    }
    pub(super) fn dyld_search_never_ignores_unprotected_roots_or_assumes_inherited_rpaths_data() {
        let (mut selected,value)=fixture();let inventory=inventory(&mut selected,&value).unwrap();
        let binary=inventory.data.roles.java.as_str();
        let mut commands=MachCommands {loads:vec!["@rpath/libjli.dylib".into()],rpaths:vec!["@loader_path/../lib/jli".into()]};
        assert!(local_loads(binary,&commands,&inventory));
        commands.rpaths.insert(0,"@loader_path/missing".into());assert!(local_loads(binary,&commands,&inventory));
        commands.rpaths.insert(0,"/tmp/unprotected".into());assert!(!local_loads(binary,&commands,&inventory));
        commands.rpaths.clear();assert!(!local_loads(binary,&commands,&inventory));
        commands.loads=vec!["@loader_path/../lib/jli/libjli.dylib".into()];assert!(local_loads(binary,&commands,&inventory));
        commands.loads=vec!["/usr/local/lib/libjli.dylib".into()];assert!(!local_loads(binary,&commands,&inventory));
    }
    #[test]
    fn closed_mac_roles_membership_and_selected_hashes_are_required() { closed_mac_roles_membership_and_selected_hashes_are_required_data(); }

    #[test]
    fn aliases_cannot_escape_change_bundles_or_point_to_another_alias() { aliases_cannot_escape_change_bundles_or_point_to_another_alias_data(); }

    #[test]
    fn registration_and_os_provider_are_closed_and_account_bound() { registration_and_os_provider_are_closed_and_account_bound_data(); }

    #[test]
    fn universal_architecture_table_may_be_unsorted_but_never_overlapping_or_intel_only() { universal_architecture_table_may_be_unsorted_but_never_overlapping_or_intel_only_data(); }

    #[test]
    fn lazy_load_paths_are_parsed_and_loader_environment_commands_refused() { lazy_load_paths_are_parsed_and_loader_environment_commands_refused_data(); }

    #[test]
    fn dyld_search_never_ignores_unprotected_roots_or_assumes_inherited_rpaths() { dyld_search_never_ignores_unprotected_roots_or_assumes_inherited_rpaths_data(); }

}

// Explicit harness=false DATA bridge; ordinary libtest wrappers use these same
// inert bodies. No native custody, task, Prepare/Start or qualification is granted.
#[cfg(test)]
pub(crate) fn assert_macos_toolchain_policy_data_contract() {
    tests::closed_mac_roles_membership_and_selected_hashes_are_required_data();
    tests::aliases_cannot_escape_change_bundles_or_point_to_another_alias_data();
    tests::registration_and_os_provider_are_closed_and_account_bound_data();
    tests::universal_architecture_table_may_be_unsorted_but_never_overlapping_or_intel_only_data();
    tests::lazy_load_paths_are_parsed_and_loader_environment_commands_refused_data();
    tests::dyld_search_never_ignores_unprotected_roots_or_assumes_inherited_rpaths_data();
}
