//! Closed installation DATA. Parsing/matching is not native observation,
//! signature trust, writer finality, execution authority or permission to modify.
use std::collections::{BTreeMap, BTreeSet};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use crate::{macos_install_paths as paths, protocol::strict_json, runtime::safe_payload_path};

pub const INVENTORY_NAME: &str = "install-inventory.json";
pub const RECORD_NAME: &str = "installation-v1.json";
pub const INVENTORY_LIMIT: usize = 1024 * 1024;
pub const RECORD_LIMIT: usize = 8192;
pub const PAYLOAD_LIMIT: u64 = 512 * 1024 * 1024;
pub const FILE_LIMIT: usize = 2048;
pub const ANDROID_HELPER: &str = "app/Contents/Helpers/mrk-android-register";
pub const ANDROID_SERVICE_PLIST: &str = "app/Contents/Library/LaunchDaemons/dev.mobile-release-kit.desktop.android-register.plist";
type Result<T> = std::result::Result<T, &'static str>;
fn check(ok: bool, reason: &'static str) -> Result<()> { if ok { Ok(()) } else { Err(reason) } }
fn hex(value: &str, bytes: usize) -> bool {
    value.len() == bytes && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn digest(bytes: &[u8]) -> String { format!("{:x}", Sha256::digest(bytes)) }

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Kind { Ordinary, Fixture }
impl Kind {
    pub fn package_identifier(self) -> &'static str {
        match self { Self::Ordinary => paths::PACKAGE_ID, Self::Fixture => paths::FIXTURE_PACKAGE_ID }
    }
}

/// Stable inode identity, NOT a snapshot of a mutable directory's contents.
/// Native callers independently retain full original/name observations, ACL,
/// mount, xattr and current roster checks. Directory times/size/links are not
/// generation identity: creating these very records changes them.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DirectoryIdentity {
    pub device: i64, pub inode: u64, pub mode: u32, pub uid: u32, pub gid: u32, pub flags: u32,
}
impl DirectoryIdentity {
    pub fn valid(self) -> bool {
        self.device > 0 && self.inode > 0 && self.mode == 0o040755 && self.uid == 0 && self.gid == 0 && self.flags == 0
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Inventory { pub schema_version: u32, pub release: String, pub runtime_manifest_sha256: String, pub files: Vec<Entry> }
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry { pub path: String, pub sha256: String, pub size: u64, pub executable: bool }
pub struct InventoryIndex<'a> {
    pub files: BTreeMap<String, &'a Entry>, pub directories: BTreeSet<String>, pub payload_bytes: u64,
}
impl Inventory {
    pub fn parse(bytes: &[u8], runtime_manifest: &str) -> Result<Self> {
        check(!bytes.is_empty() && bytes.len() <= INVENTORY_LIMIT, "inventory-size")?;
        let inventory: Self = serde_json::from_value(strict_json(bytes).map_err(|_| "inventory-json")?)
            .map_err(|_| "inventory-shape")?;
        check(inventory.schema_version == 1 && inventory.release == paths::RELEASE
            && !inventory.files.is_empty() && inventory.files.len() <= FILE_LIMIT
            && hex(runtime_manifest, 64) && inventory.runtime_manifest_sha256 == runtime_manifest, "inventory-binding")?;
        Ok(inventory)
    }
    pub fn index(&self) -> Result<InventoryIndex<'_>> {
        let mut files = BTreeMap::new();
        let mut directories = BTreeSet::from(["app".to_owned(), "runtime".to_owned()]);
        let mut total = 0u64; let mut previous = "";
        for item in &self.files {
            check(item.path.is_ascii() && safe_payload_path(&item.path) && item.path.len() <= 1024
                && item.path.split('/').count() <= 17
                && (item.path.starts_with("app/Contents/") || item.path.starts_with("runtime/"))
                && item.path.as_str() > previous && hex(&item.sha256, 64), "inventory-path")?;
            check(item.executable == matches!(item.path.as_str(),
                "app/Contents/MacOS/mobile-release-kit-desktop" | "app/Contents/Helpers/mrk-vault-keychain" | ANDROID_HELPER | "runtime/python/bin/python3"),
                "inventory-executable-scope")?;
            total = total.checked_add(item.size).ok_or("inventory-bound")?;
            check(total <= PAYLOAD_LIMIT, "inventory-bound")?;
            previous = &item.path; files.insert(item.path.clone(), item);
            let mut path = item.path.as_str();
            while let Some((parent, _)) = path.rsplit_once('/') { directories.insert(parent.to_owned()); path = parent; }
        }
        check(directories.len() <= FILE_LIMIT && files.contains_key("app/Contents/MacOS/mobile-release-kit-desktop")
            && files.contains_key("app/Contents/Info.plist") && files.contains_key("app/Contents/Helpers/mrk-vault-keychain")
            && files.contains_key("runtime/python/bin/python3")
            && files.get("runtime/manifest.json").is_some_and(|f| f.sha256 == self.runtime_manifest_sha256), "inventory-required")?;
        // Optional only as a complete fixed pair. Absent keeps the existing
        // engineering package unavailable; presence is DATA completeness, not
        // signature trust, service approval, peer Ready or execution authority.
        check(files.contains_key(ANDROID_HELPER) == files.contains_key(ANDROID_SERVICE_PLIST), "inventory-android-service-pair")?;
        let mut folded = BTreeSet::new();
        for name in files.keys().chain(directories.iter()) {
            check(folded.insert(name.to_ascii_lowercase()), "inventory-collision")?;
        }
        Ok(InventoryIndex { files, directories, payload_bytes: total })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InventoryBinding { pub name: String, pub bytes: u64, pub sha256: String }
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Record {
    schema_version: u32, basis: String, phase: String, kind: Kind, instance: String,
    package_identifier: String, package_version: String, bundle_identifier: String,
    release: String, source_commit: String, protocol_sha256: String, runtime_manifest_sha256: String,
    inventory: InventoryBinding, policy: String, install_root: DirectoryIdentity, release_directory: DirectoryIdentity,
}

/// Expected caller DATA is independently selected, never filled from a record
/// in order to make that same record match. Native provenance stays with caller.
#[derive(Clone, Copy)]
pub struct Expected<'a> {
    pub kind: Kind, pub source_commit: &'a str, pub runtime_manifest: &'a str,
    pub install_root: DirectoryIdentity, pub release_directory: DirectoryIdentity,
}
impl Record {
    pub fn encode(instance: &str, inventory: &[u8], expected: &Expected<'_>) -> Result<Vec<u8>> {
        let record = Self { schema_version: 1, basis: "protected-recorded-installation-inventory".into(),
            phase: "inventory-recorded".into(), kind: expected.kind, instance: instance.into(),
            package_identifier: expected.kind.package_identifier().into(), package_version: paths::PACKAGE_VERSION.into(),
            bundle_identifier: paths::BUNDLE_ID.into(), release: paths::RELEASE.into(),
            source_commit: expected.source_commit.into(), protocol_sha256: paths::PROTOCOL_SHA.into(),
            runtime_manifest_sha256: expected.runtime_manifest.into(),
            inventory: InventoryBinding { name: INVENTORY_NAME.into(), bytes: inventory.len() as u64, sha256: digest(inventory) },
            policy: "fixed-root-wheel-readonly-v1".into(), install_root: expected.install_root,
            release_directory: expected.release_directory };
        let mut bytes = serde_json::to_vec(&record).map_err(|_| "installation-record-shape")?;
        bytes.push(b'\n');
        Self::parse_data(&bytes, inventory, expected)?;
        Ok(bytes)
    }
    pub fn parse_data(bytes: &[u8], inventory: &[u8], expected: &Expected<'_>) -> Result<Self> {
        check(!bytes.is_empty() && bytes.len() <= RECORD_LIMIT, "installation-record-size")?;
        let record: Self = serde_json::from_value(strict_json(bytes).map_err(|_| "installation-record-json")?)
            .map_err(|_| "installation-record-shape")?;
        check(hex(expected.source_commit, 40) && hex(expected.runtime_manifest, 64)
            && expected.install_root.valid() && expected.release_directory.valid(), "installation-record-expected")?;
        check(record.schema_version == 1 && record.basis == "protected-recorded-installation-inventory"
            && record.phase == "inventory-recorded" && record.kind == expected.kind
            && hex(&record.instance, 32) && record.instance.bytes().any(|b| b != b'0')
            && record.package_identifier == expected.kind.package_identifier() && record.package_version == paths::PACKAGE_VERSION
            && record.bundle_identifier == paths::BUNDLE_ID && record.release == paths::RELEASE
            && record.source_commit == expected.source_commit && record.protocol_sha256 == paths::PROTOCOL_SHA
            && record.runtime_manifest_sha256 == expected.runtime_manifest && record.policy == "fixed-root-wheel-readonly-v1"
            && record.install_root == expected.install_root && record.release_directory == expected.release_directory,
            "installation-record-binding")?;
        check(!inventory.is_empty() && inventory.len() <= INVENTORY_LIMIT && record.inventory.name == INVENTORY_NAME
            && record.inventory.bytes == inventory.len() as u64 && record.inventory.sha256 == digest(inventory),
            "installation-record-inventory")?;
        let parsed = Inventory::parse(inventory, expected.runtime_manifest)?;
        let indexed = parsed.index()?;
        check(indexed.payload_bytes.checked_add(inventory.len() as u64).and_then(|n| n.checked_add(RECORD_LIMIT as u64))
            .is_some_and(|n| n <= PAYLOAD_LIMIT), "installation-record-total-bound")?;
        Ok(record)
    }
    pub fn instance(&self) -> &str { &self.instance }
}

/// Finite returned-effect accounting, not an owner or syscall receipt. The
/// Installer invokes these transitions only from its real original returns.
#[derive(Clone, Copy, Default, Debug)]
pub struct Progress {
    entered: bool, recorded: bool, attempted_files: u32, opened_files: u32,
    planned_bytes: u64, written_bytes: u64,
}
impl Progress {
    pub fn begin(&mut self, bytes: u64) -> Result<()> {
        check(!self.entered && bytes > 0 && bytes <= (INVENTORY_LIMIT + RECORD_LIMIT) as u64, "installation-metadata-plan")?;
        self.entered = true; self.planned_bytes = bytes; Ok(())
    }
    pub fn attempted(&mut self) -> Result<()> {
        check(self.entered && !self.recorded && self.attempted_files < 2, "installation-metadata-attempt")?;
        self.attempted_files += 1; Ok(())
    }
    pub fn opened(&mut self) -> Result<()> {
        check(self.entered && !self.recorded && self.opened_files < self.attempted_files, "installation-metadata-open")?;
        self.opened_files += 1; Ok(())
    }
    pub fn wrote(&mut self, bytes: usize) -> Result<()> {
        check(self.entered && !self.recorded && self.opened_files > 0 && bytes > 0, "installation-metadata-write")?;
        let total = self.written_bytes.checked_add(bytes as u64).ok_or("installation-metadata-write")?;
        check(total <= self.planned_bytes, "installation-metadata-write")?;
        self.written_bytes = total; Ok(())
    }
    pub fn record(&mut self, readers_writers_and_parent_settled: bool) -> Result<()> {
        check(self.entered && !self.recorded && self.attempted_files == 2 && self.opened_files == 2
            && self.written_bytes == self.planned_bytes && readers_writers_and_parent_settled, "installation-metadata-unsettled")?;
        self.recorded = true; Ok(())
    }
    pub fn snapshot(&self, writers_settled: bool) -> serde_json::Value {
        serde_json::json!({"state": if self.recorded { "recorded" } else if self.entered { "incomplete" } else { "not-attempted" },
            "attemptedFiles":self.attempted_files,"openedFiles":self.opened_files,
            "plannedBytes":self.planned_bytes,"writtenBytes":self.written_bytes,"writersSettled":writers_settled})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn inventory() -> Vec<u8> {
        let rows = ["app/Contents/Helpers/mrk-vault-keychain", "app/Contents/Info.plist",
            "app/Contents/MacOS/mobile-release-kit-desktop", "runtime/manifest.json", "runtime/python/bin/python3"]
            .into_iter().map(|path| json!({"path":path,"sha256": if path == "runtime/manifest.json" { "c".repeat(64) } else { "b".repeat(64) },
                "size":1,"executable":matches!(path,"app/Contents/Helpers/mrk-vault-keychain"|"app/Contents/MacOS/mobile-release-kit-desktop"|"runtime/python/bin/python3")}))
            .collect::<Vec<_>>();
        serde_json::to_vec(&json!({"schemaVersion":1,"release":paths::RELEASE,"runtimeManifestSha256":"c".repeat(64),"files":rows})).unwrap()
    }
    fn identity(inode: u64) -> DirectoryIdentity { DirectoryIdentity { device:1,inode,mode:0o040755,uid:0,gid:0,flags:0 } }
    fn expected<'a>(source: &'a str, manifest: &'a str) -> Expected<'a> {
        Expected { kind:Kind::Ordinary,source_commit:source,runtime_manifest:manifest,install_root:identity(11),release_directory:identity(12) }
    }
    fn closed_record_tuple_inventory_and_nonfinality_data() {
        let source = "a".repeat(40); let manifest = "c".repeat(64); let input = inventory();
        let expected = expected(&source, &manifest);
        let bytes = Record::encode(&"d".repeat(32), &input, &expected).unwrap();
        let record = Record::parse_data(&bytes, &input, &expected).unwrap();
        assert_eq!(record.instance(), "d".repeat(32));
        assert_eq!(record.phase, "inventory-recorded");
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(value.get("originalsSettled").is_none() && value.get("installed").is_none());
        for (field, bad) in [("sourceCommit",json!("e".repeat(40))),("kind",json!("fixture")),
            ("phase",json!("installed")),("instance",json!("0".repeat(32))),("release",json!("another")),
            ("runtimeManifestSha256",json!("e".repeat(64))),("extra",json!(true))] {
            let mut changed=value.clone();changed[field]=bad;
            assert!(Record::parse_data(&serde_json::to_vec(&changed).unwrap(),&input,&expected).is_err(), "{field}");
        }
        let duplicate = String::from_utf8(bytes.clone()).unwrap().replacen("{","{\"schemaVersion\":1,",1);
        assert!(Record::parse_data(duplicate.as_bytes(),&input,&expected).is_err());
        let mut changed=input.clone();changed.push(b' ');
        assert!(Record::parse_data(&bytes,&changed,&expected).is_err());
        assert!(Record::parse_data(&vec![b' ';RECORD_LIMIT+1],&input,&expected).is_err());
        assert!(Record::encode(&"d".repeat(32),&input,&Expected { source_commit:"",..expected }).is_err());
    }
    fn full_inventory_and_stable_directory_identity_data() {
        let source="a".repeat(40);let manifest="c".repeat(64);let input=inventory();let expected=expected(&source,&manifest);
        let bytes=Record::encode(&"d".repeat(32),&input,&expected).unwrap();
        let parsed=Inventory::parse(&input,&manifest).unwrap();assert_eq!(parsed.index().unwrap().files.len(),5);
        for field in ["mtime","ctime","size","links"] {
            let mut changed:serde_json::Value=serde_json::from_slice(&bytes).unwrap();
            changed["installRoot"][field]=json!(1);
            assert!(Record::parse_data(&serde_json::to_vec(&changed).unwrap(),&input,&expected).is_err());
        }
        for bad in [DirectoryIdentity { inode:99,..identity(11) },DirectoryIdentity { uid:501,..identity(11) },
            DirectoryIdentity { mode:0o040777,..identity(11) },DirectoryIdentity { flags:1,..identity(11) }] {
            assert!(Record::parse_data(&bytes,&input,&Expected { install_root:bad,..expected }).is_err());
        }
        for field in ["path","executable","size"] {
            let mut value:serde_json::Value=serde_json::from_slice(&input).unwrap();
            value["files"][0][field]=match field { "path"=>json!("runtime/../bad"),"size"=>json!(u64::MAX),_=>json!(false) };
            let changed=serde_json::to_vec(&value).unwrap();
            assert!(Record::encode(&"d".repeat(32),&changed,&expected).is_err());
        }
    }
    fn progress_preserves_partial_native_returns_and_never_mints_finality_data() {
        let mut progress=Progress::default();
        assert_eq!(progress.snapshot(true)["state"],"not-attempted");
        assert!(progress.attempted().is_err());
        progress.begin(12).unwrap();progress.attempted().unwrap();progress.opened().unwrap();progress.wrote(5).unwrap();
        progress.attempted().unwrap(); // Exclusive second open can fail; don't mark it opened.
        assert_eq!(progress.snapshot(true)["state"],"incomplete");
        assert_eq!(progress.snapshot(true)["openedFiles"],1);
        assert_eq!(progress.snapshot(true)["writtenBytes"],5);
        assert!(progress.record(true).is_err() && progress.attempted().is_err());
        progress.opened().unwrap();progress.wrote(7).unwrap();
        assert!(progress.record(false).is_err()); // Real readback/close/persistence is separately required.
        progress.record(true).unwrap();
        assert_eq!(progress.snapshot(true)["state"],"recorded");
        assert!(progress.begin(1).is_err() && progress.wrote(1).is_err() && progress.record(true).is_err());
        assert!(progress.snapshot(true).get("originalsSettled").is_none());
    }
    fn android_service_inventory_pair_and_executable_scope_data() {
        let manifest="c".repeat(64);
        let original:serde_json::Value=serde_json::from_slice(&inventory()).unwrap();
        // The original five-file unavailable package remains a valid DATA
        // inventory; it cannot acquire service authority by this parse.
        assert!(Inventory::parse(&inventory(),&manifest).unwrap().index().is_ok());
        for (helper,plist,helper_executable,plist_executable,accepted) in [
            (true,true,true,false,true), (true,false,true,false,false),
            (false,true,true,false,false), (true,true,false,false,false),
            (true,true,true,true,false),
        ] {
            let mut changed=original.clone();let rows=changed["files"].as_array_mut().unwrap();
            for (include,path,executable) in [(helper,ANDROID_HELPER,helper_executable),(plist,ANDROID_SERVICE_PLIST,plist_executable)] {
                if include { rows.push(json!({"path":path,"sha256":"b".repeat(64),"size":1,"executable":executable})); }
            }
            rows.sort_by(|a,b|a["path"].as_str().cmp(&b["path"].as_str()));
            let bytes=serde_json::to_vec(&changed).unwrap();
            assert_eq!(Inventory::parse(&bytes,&manifest).unwrap().index().is_ok(),accepted);
        }
    }
    #[test] fn closed_record_tuple_inventory_and_nonfinality() { closed_record_tuple_inventory_and_nonfinality_data(); }
    #[test] fn full_inventory_and_stable_directory_identity() { full_inventory_and_stable_directory_identity_data(); }
    #[test] fn progress_preserves_partial_native_returns_and_never_mints_finality() { progress_preserves_partial_native_returns_and_never_mints_finality_data(); }
    #[test] fn android_service_inventory_pair_and_executable_scope() { android_service_inventory_pair_and_executable_scope_data(); }
    pub(super) fn all() {
        closed_record_tuple_inventory_and_nonfinality_data();
        full_inventory_and_stable_directory_identity_data();
        progress_preserves_partial_native_returns_and_never_mints_finality_data();
        android_service_inventory_pair_and_executable_scope_data();
    }
}
/// Shared inert bodies for the already selected normal-profile observer route.
#[cfg(test)]
pub(crate) fn assert_installation_record_data_contract() { tests::all(); }
