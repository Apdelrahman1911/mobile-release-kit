//! Closed installation DATA. Parsing/matching is not native observation,
//! signature trust, writer finality, execution authority or permission to modify.
use std::collections::{BTreeMap, BTreeSet};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use crate::{macos_install_maintenance::ReleaseData, macos_install_paths as paths,
    protocol::strict_json, runtime::safe_payload_path};

pub const INVENTORY_NAME: &str = "install-inventory.json";
pub const RECORD_NAME: &str = "installation-v1.json";
pub const INVENTORY_LIMIT: usize = 1024 * 1024;
pub const RECORD_LIMIT: usize = 8192;
pub const PAYLOAD_LIMIT: u64 = 512 * 1024 * 1024;
pub const FILE_LIMIT: usize = 2048;
pub const ENTRY_BINARY: &str = paths::ENTRY_INVENTORY_PATH;
pub const APP_BINARY: &str = paths::PAYLOAD_INVENTORY_PATH;
pub const VAULT_HELPER: &str = paths::VAULT_HELPER_INVENTORY_PATH;
pub const ANDROID_HELPER: &str = paths::ANDROID_HELPER_INVENTORY_PATH;
pub const REMOVER: &str = paths::REMOVER_INVENTORY_PATH;
pub const ANDROID_SERVICE_PLIST: &str = paths::ANDROID_SERVICE_INVENTORY_PATH;
pub const DESKTOP_IMAGE: &str = paths::DESKTOP_IMAGE_INVENTORY_PATH;
pub const RESIDENT_IMAGE: &str = paths::RESIDENT_IMAGE_INVENTORY_PATH;
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
/// Selected only by the trusted compile/build caller, never serialized in Kind,
/// read from an inventory, or inferred from a missing image.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CodeLayout { OrdinaryImage, ObserverExecutable }
impl InventoryIndex<'_> {
    pub(crate) fn require_layout(&self, layout: CodeLayout) -> Result<()> {
        check(self.files.contains_key(ANDROID_HELPER) && self.files.contains_key(ANDROID_SERVICE_PLIST)
            && self.files.contains_key(RESIDENT_IMAGE)
            && self.files.contains_key(DESKTOP_IMAGE) == (layout == CodeLayout::OrdinaryImage),
            "inventory-code-layout")
    }
}
impl Inventory {
    pub fn parse(bytes: &[u8], runtime_manifest: &str) -> Result<Self> {
        Self::parse_for_release(bytes, runtime_manifest, paths::RELEASE)
    }
    /// The original observer supplies a producer-selected generation, never the
    /// release/runtime strings learned from the inventory being checked. The
    /// ordinary compatibility entry remains bound to the compiled release.
    pub fn parse_for_release(bytes: &[u8], runtime_manifest: &str, release: &str) -> Result<Self> {
        check(!bytes.is_empty() && bytes.len() <= INVENTORY_LIMIT, "inventory-size")?;
        check(!release.is_empty() && release.len() <= 128 && release != "." && release != ".."
            && release.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"-_.".contains(&b)), "inventory-expected-release")?;
        let value = strict_json(bytes).map_err(|_| "inventory-json")?;
        check(value.is_object() && value.get("files").and_then(serde_json::Value::as_array)
            .is_some_and(|items| items.iter().all(serde_json::Value::is_object)), "inventory-shape")?;
        let inventory: Self = serde_json::from_value(value)
            .map_err(|_| "inventory-shape")?;
        check(inventory.schema_version == 1 && inventory.release == release
            && !inventory.files.is_empty() && inventory.files.len() <= FILE_LIMIT - 3
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
                ENTRY_BINARY | APP_BINARY | VAULT_HELPER | ANDROID_HELPER | REMOVER | DESKTOP_IMAGE | RESIDENT_IMAGE | "runtime/python/bin/python3"),
                "inventory-executable-scope")?;
            total = total.checked_add(item.size).ok_or("inventory-bound")?;
            check(total <= PAYLOAD_LIMIT, "inventory-bound")?;
            previous = &item.path; files.insert(item.path.clone(), item);
            let mut path = item.path.as_str();
            while let Some((parent, _)) = path.rsplit_once('/') { directories.insert(parent.to_owned()); path = parent; }
        }
        check(directories.len() <= FILE_LIMIT && files.contains_key(ENTRY_BINARY) && files.contains_key(APP_BINARY)
            && files.contains_key("app/Contents/Info.plist") && files.contains_key(paths::PAYLOAD_INFO_INVENTORY_PATH)
            && files.contains_key(VAULT_HELPER)
            && files.contains_key("runtime/python/bin/python3")
            && files.get("runtime/manifest.json").is_some_and(|f| f.sha256 == self.runtime_manifest_sha256), "inventory-required")?;
        // Common structural DATA accepts only the complete resident group;
        // desktop implies resident. This is not an ordinary/observer selector.
        // Real admission separately invokes require_layout from its source role.
        check(files.contains_key(ANDROID_HELPER) == files.contains_key(ANDROID_SERVICE_PLIST)
            && files.contains_key(ANDROID_HELPER) == files.contains_key(RESIDENT_IMAGE)
            && (!files.contains_key(DESKTOP_IMAGE) || files.contains_key(RESIDENT_IMAGE)),
            "inventory-android-service-pair")?;
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
        Self::parse_bound_data(bytes, inventory, expected, paths::PACKAGE_VERSION, paths::RELEASE, paths::PROTOCOL_SHA)
    }
    /// Historical DATA remains inventory-recorded, not an old completion
    /// receipt. The caller independently selected this exact release tuple and
    /// retains its current root/generation originals and signature observation.
    pub fn parse_for_release_data(bytes: &[u8], inventory: &[u8], expected: &Expected<'_>, release: &ReleaseData) -> Result<Self> {
        let binding = release.binding_data();
        check(expected.source_commit == binding.source_commit && expected.runtime_manifest == binding.runtime_manifest_sha256
            && binding.package_identifier == paths::PACKAGE_ID
            && binding.bundle_identifier == paths::BUNDLE_ID && digest(inventory) == binding.inventory_sha256,
            "installation-record-selected-release")?;
        Self::parse_bound_data(bytes, inventory, expected, binding.package_version, binding.release, binding.protocol_sha256)
    }
    fn parse_bound_data(bytes: &[u8], inventory: &[u8], expected: &Expected<'_>, package_version: &str,
        release: &str, protocol_sha256: &str) -> Result<Self> {
        check(!bytes.is_empty() && bytes.len() <= RECORD_LIMIT, "installation-record-size")?;
        let value = strict_json(bytes).map_err(|_| "installation-record-json")?;
        check(value.is_object() && ["inventory", "installRoot", "releaseDirectory"].iter()
            .all(|name| value.get(*name).is_some_and(serde_json::Value::is_object)), "installation-record-shape")?;
        let record: Self = serde_json::from_value(value)
            .map_err(|_| "installation-record-shape")?;
        check(hex(expected.source_commit, 40) && hex(expected.runtime_manifest, 64)
            && expected.install_root.valid() && expected.release_directory.valid(), "installation-record-expected")?;
        check(record.schema_version == 1 && record.basis == "protected-recorded-installation-inventory"
            && record.phase == "inventory-recorded" && record.kind == expected.kind
            && hex(&record.instance, 32) && record.instance.bytes().any(|b| b != b'0')
            && record.package_identifier == expected.kind.package_identifier() && record.package_version == package_version
            && record.bundle_identifier == paths::BUNDLE_ID && record.release == release
            && record.source_commit == expected.source_commit && record.protocol_sha256 == protocol_sha256
            && record.runtime_manifest_sha256 == expected.runtime_manifest && record.policy == "fixed-root-wheel-readonly-v1"
            && record.install_root == expected.install_root && record.release_directory == expected.release_directory,
            "installation-record-binding")?;
        check(!inventory.is_empty() && inventory.len() <= INVENTORY_LIMIT && record.inventory.name == INVENTORY_NAME
            && record.inventory.bytes == inventory.len() as u64 && record.inventory.sha256 == digest(inventory),
            "installation-record-inventory")?;
        let parsed = Inventory::parse_for_release(inventory, expected.runtime_manifest, release)?;
        let indexed = parsed.index()?;
        check(indexed.payload_bytes.checked_add(inventory.len() as u64).and_then(|n| n.checked_add(RECORD_LIMIT as u64))
            .and_then(|n| n.checked_add(paths::MAINTENANCE_GATE_BYTES.len() as u64))
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
        let mut paths = [ENTRY_BINARY, APP_BINARY, VAULT_HELPER, "app/Contents/Info.plist",
            paths::PAYLOAD_INFO_INVENTORY_PATH, "runtime/manifest.json", "runtime/python/bin/python3"];
        paths.sort();
        let rows = paths
            .into_iter().map(|path| json!({"path":path,"sha256": if path == "runtime/manifest.json" { "c".repeat(64) } else { "b".repeat(64) },
                "size":1,"executable":matches!(path,ENTRY_BINARY|APP_BINARY|VAULT_HELPER|"runtime/python/bin/python3")}))
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
        let parsed=Inventory::parse(&input,&manifest).unwrap();assert_eq!(parsed.index().unwrap().files.len(),7);
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
        // A historical inventory must match an independently selected release,
        // not the current compile default or strings learned from that record.
        use crate::macos_install_maintenance::{MaintenanceTargetData, ReleaseSetData};
        let mut raw_inventory:serde_json::Value=serde_json::from_slice(&input).unwrap();
        raw_inventory["release"]=json!("macos26-arm64-data-2");
        let historical_inventory=serde_json::to_vec(&raw_inventory).unwrap();
        let selection=ReleaseSetData::parse_for_target_data(&serde_json::to_vec(&json!({"schemaVersion":2,
            "current":{"profile":"fixed-macos26-arm64-maintenance-v2","packageIdentifier":paths::PACKAGE_ID,
                "bundleIdentifier":paths::BUNDLE_ID,"packageVersion":"0.2.0","release":"macos26-arm64-data-2",
                "sourceCommit":source,"protocolSha256":paths::PROTOCOL_SHA,"runtimeManifestSha256":manifest,
                "inventorySha256":digest(&historical_inventory),"signingPolicySha256":"b".repeat(64),"packageSha256":"d".repeat(64)},
            "acceptedPredecessors":[]})).unwrap(),MaintenanceTargetData::Arm64).unwrap();
        let mut record:serde_json::Value=serde_json::from_slice(&bytes).unwrap();
        record["release"]=raw_inventory["release"].clone(); record["packageVersion"]=json!("0.2.0");
        record["inventory"]["bytes"]=json!(historical_inventory.len());
        record["inventory"]["sha256"]=json!(digest(&historical_inventory));
        let historical_record=serde_json::to_vec(&record).unwrap();
        assert!(Record::parse_for_release_data(&historical_record,&historical_inventory,&expected,selection.current_data()).is_ok());
        assert!(Record::parse_data(&historical_record,&historical_inventory,&expected).is_err());
        assert!(Inventory::parse(&historical_inventory,&manifest).is_err());
        assert!(Record::parse_for_release_data(&historical_record,&historical_inventory,
            &Expected { kind:Kind::Fixture,..expected },selection.current_data()).is_err());
        let mut changed=historical_inventory.clone(); changed.push(b' ');
        assert!(Record::parse_for_release_data(&historical_record,&changed,&expected,selection.current_data()).is_err());
        let positional=|value:&serde_json::Value, keys:&[&str]| serde_json::Value::Array(keys.iter().map(|key|value[*key].clone()).collect());
        for (name,keys) in [("inventory",&["name","bytes","sha256"][..]),
            ("installRoot",&["device","inode","mode","uid","gid","flags"][..]),
            ("releaseDirectory",&["device","inode","mode","uid","gid","flags"][..])] {
            let mut changed=record.clone(); changed[name]=positional(&record[name],keys);
            assert!(Record::parse_for_release_data(&serde_json::to_vec(&changed).unwrap(),&historical_inventory,&expected,selection.current_data()).is_err());
        }
        let mut changed=raw_inventory.clone();
        changed["files"][0]=positional(&raw_inventory["files"][0],&["path","sha256","size","executable"]);
        assert!(Inventory::parse_for_release(&serde_json::to_vec(&changed).unwrap(),&manifest,"macos26-arm64-data-2").is_err());
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
        // Minimal inventory stays nonauthorizing DATA; neither runtime role
        // can use missing images as a fallback.
        let base=Inventory::parse(&inventory(),&manifest).unwrap();
        let index=base.index().unwrap();
        assert!(index.require_layout(CodeLayout::OrdinaryImage).is_err());
        assert!(index.require_layout(CodeLayout::ObserverExecutable).is_err());
        for (helper,plist,resident,desktop,code,accepted) in [
            (true,true,true,false,true,true), (true,true,true,true,true,true),
            (true,false,true,false,true,false), (false,true,true,false,true,false),
            (true,true,false,false,true,false), (false,false,true,false,true,false),
            (false,false,false,true,true,false), (true,true,false,true,true,false),
            (true,true,true,false,false,false), (true,true,true,true,false,false),
        ] {
            let mut changed=original.clone();let rows=changed["files"].as_array_mut().unwrap();
            for (include,path,executable) in [
                (helper,ANDROID_HELPER,code),(plist,ANDROID_SERVICE_PLIST,false),
                (resident,RESIDENT_IMAGE,code),(desktop,DESKTOP_IMAGE,code),
            ] {
                if include { rows.push(json!({"path":path,"sha256":"b".repeat(64),"size":1,"executable":executable})); }
            }
            rows.sort_by(|a,b|a["path"].as_str().cmp(&b["path"].as_str()));
            let bytes=serde_json::to_vec(&changed).unwrap();
            let parsed=Inventory::parse(&bytes,&manifest).unwrap();
            assert_eq!(parsed.index().is_ok(),accepted);
            if accepted {
                let index=parsed.index().unwrap();
                assert_eq!(index.require_layout(CodeLayout::OrdinaryImage).is_ok(),desktop);
                assert_eq!(index.require_layout(CodeLayout::ObserverExecutable).is_ok(),!desktop);
                let mut wrong=changed.clone();
                let plist=wrong["files"].as_array_mut().unwrap().iter_mut()
                    .find(|row|row["path"]==ANDROID_SERVICE_PLIST).unwrap();
                plist["executable"]=json!(true);
                assert!(Inventory::parse(&serde_json::to_vec(&wrong).unwrap(),&manifest).unwrap().index().is_err());
                let mut wrong=changed.clone();
                wrong["files"].as_array_mut().unwrap().push(json!({"path":
                    "app/Contents/Helpers/MobileReleaseKitPayload.app/Contents/Frameworks/plugin.dylib",
                    "sha256":"b".repeat(64),"size":1,"executable":true}));
                wrong["files"].as_array_mut().unwrap().sort_by(|a,b|a["path"].as_str().cmp(&b["path"].as_str()));
                assert!(Inventory::parse(&serde_json::to_vec(&wrong).unwrap(),&manifest).unwrap().index().is_err());
            }
        }
        // Historical authenticated inventories remain parseable. Only this
        // new fixed executable joins the closed list; current-role admission
        // must separately require its genuine signed original.
        for (path,executable,accepted) in [(REMOVER,true,true),(REMOVER,false,false),
            ("app/Contents/Helpers/MobileReleaseKitPayload.app/Contents/Helpers/mrk-macos-remove-other",true,false)] {
            let mut changed=original.clone();let rows=changed["files"].as_array_mut().unwrap();
            rows.push(json!({"path":path,"sha256":"b".repeat(64),"size":1,"executable":executable}));
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
