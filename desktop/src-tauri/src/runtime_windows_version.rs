#[cfg(any(test, all(target_os = "windows", target_arch = "x86_64", target_env = "msvc")))]
pub(crate) mod windows_version {
    use super::*;
    use std::collections::BTreeMap;

    pub(crate) const TARGET: &str = "x86_64-pc-windows-msvc";
    pub(crate) const SELECTED: [&str; 3] = ["python/python.exe", "engine_bootstrap.py", "core.zip"];
    pub(crate) const BLOCK_SIZE: usize = 64 * 1024;
    pub(crate) const MANIFEST_BYTES: u64 = MANIFEST_LIMIT;
    // Complete current Windows base input. Resource presence does not enable a method.
    const CURRENT_WINDOWS_REQUIRED_RUNTIME_RESOURCES: [&str; 27] = [
        "android_build_bootstrap.py",
        "android_upload_key_bootstrap.py",
        "artifact_inspection_bootstrap.py",
        "config_edit_bootstrap.py",
        "core.zip",
        "engine_bootstrap.py",
        "environment_bootstrap.py",
        "git_local_bootstrap.py",
        "git_push_bootstrap.py",
        "git_push_helper_bootstrap.py",
        "git_read_bootstrap.py",
        "git_remote_bootstrap.py",
        "git_remote_helper_bootstrap.py",
        "github-ca.pem",
        "github_auth_bootstrap.py",
        "github_connection_bootstrap.py",
        "github_device_bootstrap.py",
        "github_history_bootstrap.py",
        "github_preflight_bootstrap.py",
        "github_release_bootstrap.py",
        "github_setup_bootstrap.py",
        "ios_archive_bootstrap.py",
        "local_release_history_bootstrap.py",
        "offline_preflight_bootstrap.py",
        "project_recovery_bootstrap.py",
        "tool_acquisition_bootstrap.py",
        PYTHON_RESOURCE,
    ];

    /// Pure selection DATA. A five-method qualification candidate is never
    /// silently promoted into the normal window's six-method capability set.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) enum Selection { Closed, HeadlessCandidate, Normal }
    impl Selection {
        pub(crate) fn permits(self, name: &str) -> bool {
            match self {
                Self::Closed => false,
                Self::HeadlessCandidate => installed_candidate_method(name),
                Self::Normal => passive_method(name),
            }
        }
        // Derived selection DATA only. RuntimeConfig supplies its actual live
        // original-session match; native per-request inspection remains mandatory.
        pub(crate) fn permits_with_original_session(self, name: &str, original_session: bool) -> bool {
            self.permits(name) || self == Self::Normal && name == "credentials.assess" && original_session
        }
    }

    // CPython dynload_win.c passes512 wchar_t to GetModuleFileNameW and
    // PathCchCombineEx. Count the complete path, a possible \\?\ expansion,
    // and NUL BEFORE any creation; native8192-unit bounds are not sufficient.
    fn python_path_units_fit(units: usize) -> bool {
        units.checked_add(4).and_then(|n| n.checked_add(1)).is_some_and(|n| n <= 512)
    }
    pub(crate) fn python_path_fits(path: &str) -> bool {
        !path.contains('\0') && path.encode_utf16().try_fold(0usize, |n, _| n.checked_add(1))
            .is_some_and(python_path_units_fit)
    }
    pub(crate) struct LaunchLayout { pub(crate) root: String, pub(crate) python: String }
    pub(crate) fn launch_layout(program_files: &str, spec: &VersionSpec) -> Result<LaunchLayout, BridgeError> {
        if !python_path_fits(program_files) { return Err(unavailable()); }
        let mut root = program_files.to_owned();
        for component in spec.components() { root.push('\\'); root.push_str(component); }
        let prefix = format!("{root}\\python");
        let python = format!("{prefix}\\python.exe");
        let paths = [&python, &format!("{prefix}\\python314.dll"), &format!("{prefix}\\python3.dll"),
            &prefix, &format!("{prefix}\\DLLs\\python3.dll")];
        if paths.iter().any(|p| !python_path_fits(p)) { return Err(unavailable()); }
        Ok(LaunchLayout { root, python })
    }

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

    #[cfg(test)]
    mod loader_path_tests {
        use super::*;
        #[test]
        fn windows_session_assessment_needs_normal_selection_and_the_original_binding() {
            // Selection and original-book DATA only: no Windows/native entry,
            // runtime verification, synthetic identity or qualification receipt.
            #[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),
                all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")),
                all(target_os = "windows", target_arch = "x86_64", target_env = "msvc")))]
            #[cfg(not(feature="windows-runtime-publisher"))]
            assert_installed_session_selection_contract();
            for selection in [Selection::Closed, Selection::HeadlessCandidate, Selection::Normal] {
                for original_session in [false, true] {
                    assert_eq!(selection.permits_with_original_session("credentials.assess", original_session),
                        selection == Selection::Normal && original_session);
                    for name in ["capabilities", "catalog", "project.snapshot", "config.validate", "config.suggest", "config.preview"] {
                        assert_eq!(selection.permits_with_original_session(name, original_session), selection.permits(name));
                    }
                    for name in ["credentials", "credentials.assess.extra", "github.release", "store.release", ""] {
                        assert!(!selection.permits_with_original_session(name, original_session));
                    }
                }
            }
        }
        #[test]
        fn windows_python_capacity_counts_utf16_nul_and_verbatim_prefix_before_creation() {
            assert!(python_path_fits(&"a".repeat(507)));
            assert!(!python_path_fits(&"a".repeat(508)));
            assert!(python_path_fits(&("a".repeat(505) + "\u{1f680}")));
            assert!(!python_path_fits(&("a".repeat(506) + "\u{1f680}")));
            assert!(!python_path_fits("C:\\Python\0ignored"));
            assert!(!python_path_units_fit(usize::MAX));
            assert!(!python_path_units_fit(usize::MAX - 3));
            for method in ["capabilities", "catalog", "config.validate", "config.suggest", "config.preview"] {
                assert!(installed_candidate_method(method));
            }
            for method in ["project.snapshot", "config.save", "environment.requirements", "github.setup.propose", "android.build", "catalog "] {
                assert!(!installed_candidate_method(method));
            }
        }
        #[test]
        fn windows_complete_layout_binds_the_longest_python_dlls_fallback() {
            let spec = VersionSpec::bindings(TARGET, Some(&"a".repeat(64)), Some(&"b".repeat(64))).unwrap();
            let suffix = format!("\\{}\\python\\DLLs\\python3.dll", spec.components().join("\\"));
            let remaining = 507 - suffix.encode_utf16().count();
            let base = format!("C:\\{}", "a".repeat(remaining - 3));
            assert!(launch_layout(&base, &spec).is_ok());
            assert!(launch_layout(&(base + "a"), &spec).is_err());
        }
    }

    pub(crate) fn passive_method(name: &str) -> bool {
        matches!(name, "capabilities" | "catalog" | "project.snapshot"
            | "config.validate" | "config.suggest" | "config.preview")
    }
    pub(crate) fn installed_candidate_method(name: &str) -> bool {
        passive_method(name) && name != "project.snapshot"
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
            let manifest: Manifest = serde_json::from_value(manifest_json(bytes).map_err(|_| unavailable())?)
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
            for required in CURRENT_WINDOWS_REQUIRED_RUNTIME_RESOURCES {
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
        /// This producing profile is narrower than arbitrary inspected DATA.
        /// Both pyvenv.cfg sites, .local/manifests, extra _pth/site inputs and
        /// prefix/DLLs must be absent under the protected complete inventory.
        pub(crate) fn passive_loader_inventory(&self) -> Result<(), BridgeError> {
            let root = [
                "android_build_bootstrap.py",
                "android_upload_key_bootstrap.py",
                "artifact_inspection_bootstrap.py",
                "config_edit_bootstrap.py",
                "core.zip",
                "engine_bootstrap.py",
                "environment_bootstrap.py",
                "git_local_bootstrap.py",
                "git_push_bootstrap.py",
                "git_push_helper_bootstrap.py",
                "git_read_bootstrap.py",
                "git_remote_bootstrap.py",
                "git_remote_helper_bootstrap.py",
                "github-ca.pem",
                "github_auth_bootstrap.py",
                "github_connection_bootstrap.py",
                "github_device_bootstrap.py",
                "github_history_bootstrap.py",
                "github_preflight_bootstrap.py",
                "github_release_bootstrap.py",
                "github_setup_bootstrap.py",
                "ios_archive_bootstrap.py",
                "local_release_history_bootstrap.py",
                "offline_preflight_bootstrap.py",
                "project_recovery_bootstrap.py",
                "tool_acquisition_bootstrap.py",
            ];
            if self.directories != BTreeSet::from(["python".to_owned()])
                || self.manifest.files.len() != root.len() + SUPPLIER.len() + 1
                || self.manifest.files.iter().any(|file| {
                    if let Some(name) = file.path.strip_prefix("python/") {
                        name != "MRK-EMBEDDED-NOTICES.txt" && !SUPPLIER.iter().any(|(allowed, _, _)| name == *allowed)
                    } else { !root.contains(&file.path.as_str()) }
                }) { return Err(unavailable()); }
            Ok(())
        }
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
            for required in CURRENT_WINDOWS_REQUIRED_RUNTIME_RESOURCES {
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
        fn windows_passive_inventory_excludes_all_additional_startup_inputs() {
            assert!(parse(&mut fixture()).unwrap().passive_loader_inventory().is_err()); // Required notice absent.
            let mut value = fixture();
            value["files"].as_array_mut().unwrap().push(row("python/MRK-EMBEDDED-NOTICES.txt", 1));
            assert!(parse(&mut value).unwrap().passive_loader_inventory().is_ok());
            for extra in ["pyvenv.cfg", "python/pyvenv.cfg", "python/python._pth", "python/python.exe.local",
                "python/python.exe.manifest", "python/DLLs/python3.dll", "python/sitecustomize.py", "python/extra.pth"] {
                let mut changed = value.clone();
                changed["files"].as_array_mut().unwrap().push(row(extra, 1));
                assert!(parse(&mut changed).unwrap().passive_loader_inventory().is_err());
            }
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
            // The scope predicate is DATA; only the separate compiled normal
            // selector admits six methods. Preserve the five-method candidate.
            for method in ["capabilities", "catalog", "project.snapshot", "config.validate", "config.suggest", "config.preview"] {
                assert!(passive_method(method));
                assert!(Selection::Normal.permits(method));
                assert_eq!(Selection::HeadlessCandidate.permits(method), method != "project.snapshot");
                assert!(!Selection::Closed.permits(method));
            }
            for method in ["", "project.snapshot ", "Config.Validate", "config.save", "credentials.assess",
                "environment.requirements", "github.setup.propose", "release.version.observe", "metadata.text.observe",
                "metadata.text.validate", "artifacts.candidate.observe", "release.evidence.observe", "environment.diagnostics", "android.build"] {
                assert!(!passive_method(method));
                assert!(!Selection::Normal.permits(method));
                assert!(!Selection::HeadlessCandidate.permits(method));
            }
            #[cfg(all(target_os = "windows", target_arch = "x86_64", target_env = "msvc",
                not(feature = "development-runtime"), not(feature = "desktop-shell"), not(feature = "windows-runtime-publisher")))]
            {
                let runtime = RuntimeConfig::packaged(PathBuf::from("Z:\\inert-not-opened"));
                assert!(!runtime.project_selection_profile_available());
                assert!(!runtime.configuration_edit_profile_available());
                assert!(!runtime.passive_method_available("capabilities"));
                assert!(runtime.resolve(Instant::now()).is_err());
            }
        }
        #[cfg(all(target_os = "windows", target_arch = "x86_64", target_env = "msvc",
            feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"),
            not(feature = "ubuntu-runtime-publisher"), not(feature = "windows-runtime-publisher"),
            not(feature = "macos-installed-installer")))]
        #[test]
        fn windows_normal_availability_uses_the_original_owner_selector_without_write_authority() {
            let runtime = RuntimeConfig::packaged(PathBuf::from("Z:\\inert-never-opened"));
            let available = runtime.passive_installed_profile().is_ok();
            assert_eq!(runtime.windows_passive, Selection::Normal);
            assert_eq!(runtime.project_selection_profile_available(), available);
            for method in ["capabilities", "catalog", "project.snapshot", "config.validate", "config.suggest", "config.preview"] {
                assert_eq!(runtime.passive_method_available(method), available);
            }
            for method in ["config.save", "credentials.assess", "environment.requirements", "github.setup.propose",
                "artifacts.candidate.observe", "release.evidence.observe", "android.build"] { assert!(!runtime.passive_method_available(method)); }
            assert!(!runtime.configuration_edit_profile_available());
            assert!(!runtime.project_path_selection_profile_available());
            assert!(!runtime.android_source_selection_profile_available());
            assert!(!runtime.evidence_selection_profile_available());
            assert!(runtime.resolve(Instant::now()).is_err());
        }
    }
}
