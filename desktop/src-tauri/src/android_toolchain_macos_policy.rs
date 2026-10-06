//! Closed paired macOS Android registration DATA; native role graphs remain ARM64-only.
//! No object parsed here grants native custody, registration or execution.
use std::collections::{BTreeMap, BTreeSet};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use crate::{android_build_protocol::{MacToolchainSelection, Profile, MAC_TOOLCHAIN_PROFILE, MAC_X64_TOOLCHAIN_PROFILE},
    protocol::{strict_android_tool_manifest_json, strict_json}};

pub(crate) const MANIFEST: &str = "android-toolchain.json";
pub(crate) const RECORD: &str = "registration.json";
pub(crate) const PROVIDER: &str = "os-provider.json";
pub(crate) const AAPT2: &str = "gradle/native/aapt2/aapt2";
pub(crate) const FILE_LIMIT: u64 = 512 * 1024 * 1024;
// Shared pre-reservation for one native header/command parse + local resolution.
// <=256KiB raw commands; disjoint stored strings <=256KiB, <=2048 Vec slots;
// <=1024 roots/candidates of <=512B, geometric Vec and insertion-only BTree
// backing plus path resolution scratch fit below3MiB. This is not a new pool.
pub(crate) const NATIVE_WORK_BYTES: usize = 3 * 1024 * 1024;
pub(crate) use crate::android_native_macos_profile::{android_target_elf, gradle_foreign_launcher};
pub(crate) const TOTAL_LIMIT: u64 = 1024 * 1024 * 1024;
pub(crate) const ENTRY_LIMIT: usize = 32_768;
pub(crate) const FILE_COUNT: usize = 16_384;
pub(crate) const ALIAS_COUNT: usize = 128;
pub(crate) const MANIFEST_LIMIT: usize = 4 * 1024 * 1024;
pub(crate) const PROVIDER_LIMIT: usize = 64 * 1024;
pub(crate) const RECORD_LIMIT: usize = 4096;
pub(crate) const OS_FILES: [&str; 11] = ["/System/Library/CoreServices/SystemVersion.plist", "/bin/bash", "/bin/ls", "/bin/sh",
    "/usr/bin/basename", "/usr/bin/dirname", "/usr/bin/expr", "/usr/bin/sed", "/usr/bin/tr", "/usr/bin/uname", "/usr/bin/xargs"];
pub(crate) const OS_ROOTS: [&str; 2] = ["/System/Library", "/usr/lib"];
pub(crate) const OS_PROFILE: &str = "macos26-arm64-sealed-system-v1";
pub(crate) const INTEL_OS_PROFILE: &str = "macos26-x86_64-sealed-system-v1";

// Explicit DATA selection only. No host detection, provider admission or native grant.
#[derive(Clone, Copy)]
struct MacFields {
    toolchain: &'static str, target: &'static str, launch: &'static str, os: &'static str,
}
fn mac_fields(profile: Profile) -> Option<MacFields> {
    match profile {
        Profile::MacArm64 => Some(MacFields { toolchain: MAC_TOOLCHAIN_PROFILE, target: "macos-arm64",
            launch: "gradle-macos-private-jvm-arm64-v1", os: OS_PROFILE }),
        Profile::MacX64 => Some(MacFields { toolchain: MAC_X64_TOOLCHAIN_PROFILE, target: "macos-x86_64",
            launch: "gradle-macos-private-jvm-x86_64-v1", os: INTEL_OS_PROFILE }),
        Profile::LinuxX64 => None,
    }
}
/// The finite production JDK/loader catalogue is still ARM-only. Paired
/// document parsing is not an Intel supplier, lease or native-execution grant.
pub(crate) fn native_catalog_supports(profile: Profile) -> bool {
    matches!(profile, Profile::MacArm64)
}
const BUNDLETOOL_SHA: &str = "a099cfa1543f55593bc2ed16a70a7c67fe54b1747bb7301f37fdfd6d91028e29";
const BUNDLETOOL_BYTES: u64 = 32_520_401;

pub(crate) fn digest(raw: &[u8]) -> String { Sha256::digest(raw).iter().map(|b| format!("{b:02x}")).collect() }
/// Borrowed exact digest comparison for structural checks BEFORE a work charge.
/// No formatted String, decoded Vec or caller-controlled allocation is created.
pub(crate) fn digest_matches(raw: &[u8], expected: &str) -> bool {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    if expected.len() != 64 { return false; }
    Sha256::digest(raw).iter().zip(expected.as_bytes().chunks_exact(2)).all(|(byte, pair)|
        pair[0] == HEX[usize::from(*byte >> 4)] && pair[1] == HEX[usize::from(*byte & 15)])
}
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
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct FileSpec { pub(crate) path: String, pub(crate) size: u64, pub(crate) sha256: String, pub(crate) mode: u32 }

// These are original members of one genuine SDK distribution, not shebang or
// filename exemptions. The supplier also joins the exact archive/member/mode.
// Foreign originals stay authenticated; they are not ARM64 launch roots.
pub(crate) const SDK35_ARCHIVE_BYTES: u64 = 76_857_898;
pub(crate) const SDK35_ARCHIVE_SHA: &str = "530cdbd1ec315e1477624d7ed2f0f2962108d69f36eddba5894cef9ea2cedb48";
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub(crate) enum Sdk35File { D8, Apksigner, LldShell, LldIntel, CxxIntel, CxxAbiIntel }
pub(crate) struct Sdk35Pin {
    pub(crate) kind: Sdk35File, pub(crate) path: &'static str, pub(crate) member: &'static str,
    pub(crate) bytes: u64, pub(crate) sha256: &'static str, pub(crate) original_mode: u32,
}
pub(crate) const SDK35_PINS: [Sdk35Pin; 6] = [
    Sdk35Pin { kind: Sdk35File::D8, path: "sdk/build-tools/35.0.0/d8", member: "android-15/d8",
        bytes: 2678, sha256: "b773a721be3d4988dea9660815a9e441b76100e5b0f5c72b5893cfadadc76c6f", original_mode: 0o755 },
    Sdk35Pin { kind: Sdk35File::Apksigner, path: "sdk/build-tools/35.0.0/apksigner", member: "android-15/apksigner",
        bytes: 2959, sha256: "b47549e373b895ce6ca620d0c7887e674d9615ffa837a86ac601dcfd04adb0f0", original_mode: 0o755 },
    Sdk35Pin { kind: Sdk35File::LldShell, path: "sdk/build-tools/35.0.0/lld", member: "android-15/lld",
        bytes: 647, sha256: "a4d5291a75bfa2350de74a00a3aa5099f190fd6bc86c581bb38215720884fc15", original_mode: 0o755 },
    Sdk35Pin { kind: Sdk35File::LldIntel, path: "sdk/build-tools/35.0.0/lld-bin/lld", member: "android-15/lld-bin/lld",
        bytes: 33452016, sha256: "7497b5765b30cbaf67b07de4ef631eeaab6f6a21392f2852b3ac252a44a0a250", original_mode: 0o755 },
    Sdk35Pin { kind: Sdk35File::CxxIntel, path: "sdk/build-tools/35.0.0/lib64/libc++.1.dylib", member: "android-15/lib64/libc++.1.dylib",
        bytes: 680976, sha256: "46494d6cd3737f83ddf4fcda11d69c810cd324fa0114e8110757514f8aa767c8", original_mode: 0o644 },
    Sdk35Pin { kind: Sdk35File::CxxAbiIntel, path: "sdk/build-tools/35.0.0/lib64/libc++abi.1.dylib", member: "android-15/lib64/libc++abi.1.dylib",
        bytes: 179936, sha256: "89194f2f5b98042d0e16c4948d9dad4905821749a90dd9326bb7ce509028ba66", original_mode: 0o644 },
];
impl Sdk35File {
    pub(crate) fn pin(self) -> &'static Sdk35Pin {
        &SDK35_PINS[match self { Self::D8 => 0, Self::Apksigner => 1, Self::LldShell => 2,
            Self::LldIntel => 3, Self::CxxIntel => 4, Self::CxxAbiIntel => 5 }]
    }
    pub(crate) fn script(self) -> bool { matches!(self, Self::D8 | Self::Apksigner | Self::LldShell) }
    pub(crate) fn legacy(self) -> bool { !matches!(self, Self::D8 | Self::Apksigner) }
}
impl Sdk35Pin {
    pub(crate) fn matches(&self, path: &str, bytes: u64, sha256: &str, mode: u32) -> bool {
        path == self.path && bytes == self.bytes && sha256 == self.sha256 && mode == (self.original_mode & !0o222)
    }
}
pub(crate) fn sdk35_reserved(path: &str) -> Option<Sdk35File> {
    SDK35_PINS.iter().find(|pin| pin.path == path).map(|pin| pin.kind)
}
pub(crate) fn sdk35_file(spec: &FileSpec) -> Result<Option<Sdk35File>, ()> {
    let Some(kind) = sdk35_reserved(&spec.path) else { return Ok(None); };
    kind.pin().matches(&spec.path, spec.size, &spec.sha256, spec.mode).then_some(Some(kind)).ok_or(())
}
fn sdk35_inventory(files: &[FileSpec], roles: &Roles) -> bool {
    if !crate::android_native_macos_profile::finite_nonhost_inventory(files) { return false; }
    let present = files.iter().any(|file| sdk35_reserved(&file.path).is_some());
    if !present { return true; }
    // The complete legacy/script group cannot be silently omitted/reclassified.
    SDK35_PINS.iter().all(|pin| files.iter().any(|file| pin.matches(&file.path, file.size, &file.sha256, file.mode)))
        && !roles.launch().iter().any(|path| sdk35_reserved(path).is_some_and(Sdk35File::legacy))
        && [("d8", 16_614_740), ("apksigner", 1_074_241)].iter().all(|(name, bytes)| {
            let directory = "sdk/build-tools/35.0.0";
            files.iter().any(|file| file.path == format!("{directory}/lib/{name}.jar")
                && file.size == *bytes && file.mode == 0o444)
                && !files.iter().any(|file| file.path == format!("{directory}/{name}.jar"))
        })
}
pub(crate) fn sdk35_script(kind: Sdk35File, prefix: &[u8], inventory: &Inventory) -> bool {
    kind.script() && prefix.starts_with(b"#!/bin/bash\n")
        && sdk35_inventory(&inventory.data.files, &inventory.data.roles)
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Alias { pub(crate) path: String, pub(crate) target: String, pub(crate) canonical: String }
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
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
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Versions {
    pub(crate) jdk_vendor: String, pub(crate) jdk_version: String, pub(crate) gradle_version: String, pub(crate) agp_version: String,
    pub(crate) sdk_platform: String, pub(crate) sdk_platform_revision: String, pub(crate) sdk_build_tools_version: String,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Distribution { pub(crate) url: String, pub(crate) sha256: String }
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Bundletool { version: String, sha256: String }
// Helper parsing avoids the intermediate generic Value/BTree graph. This is a
// resource bound, NOT a second JSON/schema/business-policy validator.
const JSON_STRING_TOKEN:usize=4096;
const JSON_NUMBER_TOKEN:usize=128;
const PARSE_WORK_BYTES:usize=64*1024;
const VALIDATE_WORK_BYTES:usize=64*1024;
// Rust1.98.1/aarch64: insertion-only String/ZST or &str/&FileSpec node <=384.
// Include one extra split/root node PER live tree separately, even when empty.
const POLICY_NODE_BYTES:usize=512;
// Three simultaneously live trees each retain a possible split/root node,
// in addition to their exact live entry charges. Shared by validator/supplier.
fn policy_nodes_bytes(nodes:usize)->Option<usize>{nodes.checked_mul(POLICY_NODE_BYTES)}
pub(crate) fn proposal_tree_reservation_bytes(files:usize,aliases:usize,directories:usize)->Option<usize>{
    let nodes=files.checked_mul(2)?.checked_add(aliases)?
        .checked_add(directories.checked_mul(2)?)?.checked_add(3)?.checked_add(3)?;
    policy_nodes_bytes(nodes)
}
fn json_tokens_bounded(raw:&[u8])->bool{
    let(mut quoted,mut escaped,mut string_bytes,mut number_bytes)=(false,false,0usize,0usize);
    for &byte in raw{
        if quoted{
            if !escaped && byte==b'"'{quoted=false;continue;}
            string_bytes+=1;if string_bytes>JSON_STRING_TOKEN{return false;}
            if escaped{escaped=false;}
            else if byte==b'\\'{escaped=true;}
        }else if byte==b'"'{
            quoted=true;escaped=false;string_bytes=0;number_bytes=0;
        }else if byte.is_ascii_digit() || number_bytes!=0 && matches!(byte,b'e'|b'E'|b'+'|b'-'|b'.') || byte==b'-'{
            number_bytes+=1;if number_bytes>JSON_NUMBER_TOKEN{return false;}
        }else{number_bytes=0;}
    }
    // Grammar, malformed UTF8/escapes, EOF and duplicate/unknown fields belong
    // to serde. Every valid schema string is ASCII<=512 (escaped<=3072) and
    // every valid numeric field is a <=20-byte u32/u64 integer spelling.
    true
}
fn parse_bound<T>(length:usize,vector_cells:usize)->Option<usize>{
    std::mem::size_of::<T>().checked_add(length.checked_mul(2)?)?
        .checked_add(vector_cells.checked_mul(2)?)?.checked_add(PARSE_WORK_BYTES)
}
fn bounded_typed<T:serde::de::DeserializeOwned>(raw:&[u8],limit:usize,vector_cells:usize,cap:usize)->Option<T>{
    if raw.is_empty() || raw.len()>limit || parse_bound::<T>(raw.len(),vector_cells)? > cap
        || !json_tokens_bounded(raw){return None;}
    // Sum of all decoded String backing <=raw bytes; another raw-sized allowance
    // covers growth/copy transients. Vectors have controlled growth below. The
    // fixed workspace covers <=4096-byte string and <=128-byte numeric scratch,
    // closed-schema error formatting and parser scalar/call-frame temporaries.
    serde_json::from_slice(raw).ok()
}
fn bounded_vec<'de,T:Deserialize<'de>,D:serde::Deserializer<'de>,const LIMIT:usize>(input:D)->Result<Vec<T>,D::Error>{
    struct Elements<T,const LIMIT:usize>(std::marker::PhantomData<T>);
    struct Excess;
    impl<'de> Deserialize<'de> for Excess{
        fn deserialize<D:serde::Deserializer<'de>>(_:D)->Result<Self,D::Error>{
            Err(serde::de::Error::custom("too many entries"))
        }
    }
    impl<'de,T:Deserialize<'de>,const LIMIT:usize> serde::de::Visitor<'de> for Elements<T,LIMIT>{
        type Value=Vec<T>;
        fn expecting(&self,out:&mut std::fmt::Formatter<'_>)->std::fmt::Result{out.write_str("a bounded list")}
        fn visit_seq<A:serde::de::SeqAccess<'de>>(self,mut input:A)->Result<Self::Value,A::Error>{
            let mut values=Vec::new();
            loop{
                if values.len()==LIMIT{
                    // An end delimiter returns None; an extra value refuses
                    // BEFORE deserializing/allocating that value.
                    if input.next_element::<Excess>()?.is_some(){return Err(serde::de::Error::custom("too many entries"));}
                    return Ok(values);
                }
                let Some(value)=input.next_element()? else{return Ok(values);};
                if values.len()==values.capacity(){
                    let target=if values.capacity()==0{1}else{values.capacity()*2}.min(LIMIT);
                    values.try_reserve_exact(target-values.len()).map_err(|_|serde::de::Error::custom("list capacity unavailable"))?;
                    if values.capacity()!=target{return Err(serde::de::Error::custom("unexpected list capacity"));}
                }
                values.push(value);
            }
        }
    }
    input.deserialize_seq(Elements::<T,LIMIT>(std::marker::PhantomData))
}
fn manifest_files<'de,D:serde::Deserializer<'de>>(d:D)->Result<Vec<FileSpec>,D::Error>{bounded_vec::<FileSpec,D,FILE_COUNT>(d)}
fn manifest_aliases<'de,D:serde::Deserializer<'de>>(d:D)->Result<Vec<Alias>,D::Error>{bounded_vec::<Alias,D,ALIAS_COUNT>(d)}
fn provider_files<'de,D:serde::Deserializer<'de>>(d:D)->Result<Vec<FileSpec>,D::Error>{bounded_vec::<FileSpec,D,11>(d)}
fn provider_paths<'de,D:serde::Deserializer<'de>>(d:D)->Result<Vec<String>,D::Error>{bounded_vec::<String,D,2>(d)}
fn add_space(total:&mut usize,bytes:usize,cap:usize)->Option<()>{
    *total=total.checked_add(bytes)?;(*total<=cap).then_some(())
}
fn string_space<'a>(values:impl IntoIterator<Item=&'a String>)->Option<usize>{
    values.into_iter().try_fold(0usize,|sum,value|sum.checked_add(value.capacity()))
}
fn file_space(files:&Vec<FileSpec>)->Option<usize>{
    files.iter().try_fold(files.capacity().checked_mul(std::mem::size_of::<FileSpec>())?,|sum,file|
        sum.checked_add(file.path.capacity())?.checked_add(file.sha256.capacity()))
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Manifest {
    schema_version: u32, profile: String, target: String, instance: String, launch_contract: String,
    pub(crate) versions: Versions, pub(crate) gradle_distribution: Distribution, bundletool: Bundletool,
    pub(crate) roles: Roles,
    #[serde(deserialize_with="manifest_files")]
    pub(crate) files: Vec<FileSpec>,
    #[serde(deserialize_with="manifest_aliases")]
    pub(crate) aliases: Vec<Alias>, os_provider_sha256: String,
}
pub(crate) struct Inventory { pub(crate) data: Manifest, pub(crate) directories: BTreeSet<String> }
impl Manifest{
    fn dynamic_bytes(&self)->Option<usize>{
        let v=&self.versions;let roles=&self.roles;
        let strings=string_space([&self.profile,&self.target,&self.instance,&self.launch_contract,&self.os_provider_sha256,
            &v.jdk_vendor,&v.jdk_version,&v.gradle_version,&v.agp_version,&v.sdk_platform,&v.sdk_platform_revision,&v.sdk_build_tools_version,
            &self.gradle_distribution.url,&self.gradle_distribution.sha256,&self.bundletool.version,&self.bundletool.sha256,
            &roles.java,&roles.javac,&roles.gradle,&roles.bundletool,&roles.sdk])?;
        let aliases=self.aliases.iter().try_fold(self.aliases.capacity().checked_mul(std::mem::size_of::<Alias>())?,|sum,alias|
            sum.checked_add(string_space([&alias.path,&alias.target,&alias.canonical])?))?;
        strings.checked_add(file_space(&self.files)?)?.checked_add(aliases)
    }
}
impl Inventory{
    /// Validated document identity only, never a platform or supplier qualification.
    pub(crate) fn matches_profile(&self, profile: Profile) -> bool {
        mac_fields(profile).is_some_and(|fields| self.data.profile == fields.toolchain
            && self.data.target == fields.target && self.data.launch_contract == fields.launch)
    }
    /// Retained first-party backing only; caller also owns the inline value.
    pub(crate) fn dynamic_bytes(&self)->Option<usize>{
        self.data.dynamic_bytes()?.checked_add(self.directories.len().checked_add(1)?.checked_mul(POLICY_NODE_BYTES)?)?
            .checked_add(string_space(&self.directories)?)
    }
    // Every constructor requires strictly increasing file and alias paths.
    // Borrow that existing order; a lookup adds no cached identity or authority.
    pub(crate) fn exact_file(&self, path: &str) -> Option<&FileSpec> {
        let index = self.data.files.binary_search_by(|file| file.path.as_str().cmp(path)).ok()?;
        self.data.files.get(index)
    }
    pub(crate) fn exact_alias(&self, path: &str) -> Option<&Alias> {
        let index = self.data.aliases.binary_search_by(|alias| alias.path.as_str().cmp(path)).ok()?;
        self.data.aliases.get(index)
    }
    pub(crate) fn file_under(&self, prefix: &str, relative: &str) -> Option<&FileSpec> {
        if !prefix.ends_with('/') || relative.is_empty() || relative.starts_with('/') { return None; }
        let index = self.data.files.binary_search_by(|file| {
            // Compare the virtual prefix+relative key without allocating it.
            // If prefix differs, the first difference precedes relative.
            file.path.strip_prefix(prefix).map_or_else(
                || file.path.as_str().cmp(prefix), |tail| tail.cmp(relative))
        }).ok()?;
        self.data.files.get(index).filter(|file| file.path.strip_prefix(prefix) == Some(relative))
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Registration {
    schema_version: u32, profile: String, target: String, pub(crate) instance: String, pub(crate) owner_uid: u32,
    pub(crate) inventory_sha256: String, pub(crate) os_provider_sha256: String, license_acknowledged: bool,
}
impl Registration {
    pub(crate) fn parse(raw: &[u8], account: u32, instance: &str) -> Option<Self> {
        Self::parse_for(Profile::MacArm64, raw, account, instance)
    }
    pub(crate) fn parse_for(profile: Profile, raw: &[u8], account: u32, instance: &str) -> Option<Self> {
        let fields = mac_fields(profile)?;
        if raw.is_empty() || raw.len() > RECORD_LIMIT || account == 0 || account == u32::MAX { return None; }
        let value: Self = serde_json::from_value(strict_json(raw).ok()?).ok()?;
        value.validate(fields,account,instance)
    }
    pub(crate) fn parse_bounded(raw:&[u8],account:u32,instance:&str,cap:usize)->Option<Self>{
        Self::parse_bounded_for(Profile::MacArm64,raw,account,instance,cap)
    }
    pub(crate) fn parse_bounded_for(profile:Profile,raw:&[u8],account:u32,instance:&str,cap:usize)->Option<Self>{
        let fields=mac_fields(profile)?;
        if account==0 || account==u32::MAX{return None;}
        let value:Self=bounded_typed(raw,RECORD_LIMIT,0,cap)?;
        value.validate(fields,account,instance)
    }
    fn validate(self,fields:MacFields,account:u32,instance:&str)->Option<Self>{
        let value=self;
        (value.schema_version == 1 && value.profile == fields.toolchain && value.target == fields.target
            && value.instance == instance && instance.len() == 32 && instance.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && value.owner_uid == account && sha(&value.inventory_sha256) && sha(&value.os_provider_sha256)
            && value.license_acknowledged).then_some(value)
    }
    pub(crate) fn matches(&self, selected: &MacToolchainSelection) -> bool {
        self.matches_for(Profile::MacArm64, selected)
    }
    pub(crate) fn matches_for(&self, profile: Profile, selected: &MacToolchainSelection) -> bool {
        let Some(fields) = mac_fields(profile) else { return false; };
        self.profile == fields.toolchain && self.target == fields.target
            && selected.valid() && self.instance == selected.instance && self.owner_uid == selected.owner_uid
            && self.inventory_sha256 == selected.inventory_sha256 && self.os_provider_sha256 == selected.os_provider_sha256
    }
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Provider {
    schema_version: u32, profile: String, target: String, shell: String,
    #[serde(deserialize_with="provider_paths")]
    executable_path: Vec<String>,
    #[serde(deserialize_with="provider_paths")]
    roots: Vec<String>,
    #[serde(deserialize_with="provider_files")]
    pub(crate) files: Vec<FileSpec>,
}
impl Provider {
    pub(crate) fn parse(raw: &[u8], selected: &MacToolchainSelection) -> Option<Self> {
        Self::parse_for(Profile::MacArm64, raw, selected)
    }
    pub(crate) fn parse_for(profile: Profile, raw: &[u8], selected: &MacToolchainSelection) -> Option<Self> {
        let fields = mac_fields(profile)?;
        if raw.is_empty() || raw.len() > PROVIDER_LIMIT || digest(raw) != selected.os_provider_sha256 { return None; }
        let value: Self = serde_json::from_value(strict_json(raw).ok()?).ok()?;
        validate_provider(value,fields)
    }
    pub(crate) fn parse_bounded(raw:&[u8],selected:&MacToolchainSelection,cap:usize)->Option<Self>{
        Self::parse_bounded_for(Profile::MacArm64,raw,selected,cap)
    }
    pub(crate) fn parse_bounded_for(profile:Profile,raw:&[u8],selected:&MacToolchainSelection,cap:usize)->Option<Self>{
        let fields=mac_fields(profile)?;
        let cells=OS_FILES.len().checked_mul(std::mem::size_of::<FileSpec>())?
            .checked_add(4*std::mem::size_of::<String>())?;
        let value=bounded_typed(raw,PROVIDER_LIMIT,cells,cap)?;
        if digest(raw)!=selected.os_provider_sha256{return None;}
        validate_provider(value,fields)
    }
    pub(crate) fn dynamic_bytes(&self)->Option<usize>{
        string_space([&self.profile,&self.target,&self.shell])?
            .checked_add(self.executable_path.capacity().checked_add(self.roots.capacity())?.checked_mul(std::mem::size_of::<String>())?)?
            .checked_add(string_space(self.executable_path.iter().chain(&self.roots))?)?.checked_add(file_space(&self.files)?)
    }
}
fn validate_provider(value: Provider, fields: MacFields) -> Option<Provider> {
    if value.schema_version != 1 || value.profile != fields.os || value.target != fields.target || value.shell != "/bin/sh"
        || value.executable_path != ["/usr/bin", "/bin"] || value.roots != OS_ROOTS
        || value.files.len() != OS_FILES.len() { return None; }
    for (file, expected) in value.files.iter().zip(OS_FILES) {
        if file.path != expected || file.size == 0 || file.size > FILE_LIMIT || !sha(&file.sha256)
            || !(if expected.ends_with(".plist") { matches!(file.mode, 0o444 | 0o644) } else { matches!(file.mode, 0o555 | 0o755) }) { return None; }
    }
    Some(value)

}
// ONE lexical resolver for two distinct roots, never a filesystem operation.
// A <=16-component path has <=15 parent components; a <=512-byte target has
// <=256 nonempty components. The271 borrowed slots permit transient depth>16
// without allocating before a supplier structural working-space charge.
fn alias_resolves(path: &str, target: &str, canonical: &str, floor: usize) -> bool {
    if !relative(path) || !relative(canonical) || target.is_empty() || target.len() > 512
        || target.starts_with('/') { return false; }
    let mut parts = [""; 271]; let mut depth = 0;
    for part in path.split('/') { parts[depth] = part; depth += 1; }
    depth -= 1;
    if depth < floor { return false; }
    for part in target.split('/') {
        match part {
            ".." if depth > floor => { depth -= 1; },
            ".." => return false,
            "." => {},
            _ if component(part) => {
                if depth == parts.len() { return false; }
                parts[depth] = part; depth += 1;
            },
            _ => return false,
        }
    }
    let mut expected = canonical.split('/');
    depth > floor && parts[..depth].iter().all(|part| expected.next() == Some(*part)) && expected.next().is_none()
}
/// Bundle-relative SOURCE comparison only. The caller proves Jdk group and
/// SAME picked root; the compiled roster requires a regular canonical member.
pub(crate) fn jdk_source_alias_resolves(path: &str, target: &str, canonical: &str) -> bool {
    alias_resolves(path, target, canonical, 0)
}
// Installed inventory root is jdk/<bundle>, not a picked bundle-relative path.
// Native reads the original link without following it. Never leave the bundle,
// even temporarily before re-entering an otherwise matching final destination.
pub(crate) fn alias_target(alias: &Alias) -> Option<String> {
    if !alias.path.starts_with("jdk/") || !alias.canonical.starts_with("jdk/")
        || !alias.path.split('/').take(2).eq(alias.canonical.split('/').take(2)) { return None; }
    alias_resolves(&alias.path, &alias.target, &alias.canonical, 2).then(|| alias.canonical.clone())
}
pub(crate) fn parse_manifest(raw: &[u8], selected: &MacToolchainSelection) -> Option<Inventory> {
    parse_manifest_for(Profile::MacArm64, raw, selected)
}
pub(crate) fn parse_manifest_for(profile: Profile, raw: &[u8], selected: &MacToolchainSelection) -> Option<Inventory> {
    let fields = mac_fields(profile)?;
    if !selected.valid() || raw.is_empty() || raw.len() > MANIFEST_LIMIT || digest(raw) != selected.inventory_sha256 { return None; }
    let value: Manifest = serde_json::from_value(strict_android_tool_manifest_json(raw).ok()?).ok()?;
    validate_manifest(value,fields,&selected.instance,&selected.os_provider_sha256)
}
/// Helper-only typed parse under the already reserved payload remainder.
/// Ordinary proposal/parse paths and this path share ONE validation authority.
pub(crate) fn parse_manifest_bounded(raw:&[u8],selected:&MacToolchainSelection,cap:usize)->Option<Inventory>{
    parse_manifest_bounded_for(Profile::MacArm64,raw,selected,cap)
}
pub(crate) fn parse_manifest_bounded_for(profile:Profile,raw:&[u8],selected:&MacToolchainSelection,cap:usize)->Option<Inventory>{
    let fields=mac_fields(profile)?;
    if !selected.valid(){return None;}
    let cells=FILE_COUNT.checked_mul(std::mem::size_of::<FileSpec>())?
        .checked_add(ALIAS_COUNT.checked_mul(std::mem::size_of::<Alias>())?)?;
    let value:Manifest=bounded_typed(raw,MANIFEST_LIMIT,cells,cap)?;
    if digest(raw)!=selected.inventory_sha256{return None;}
    validate_manifest_space(value,fields,&selected.instance,&selected.os_provider_sha256,cap)
}
fn validate_manifest(value:Manifest,fields:MacFields,instance:&str,provider_sha256:&str)->Option<Inventory>{
    validate_manifest_space(value,fields,instance,provider_sha256,usize::MAX)
}
fn validate_manifest_space(value: Manifest, fields: MacFields, instance: &str, provider_sha256: &str, cap:usize) -> Option<Inventory> {
    let mut space=value.dynamic_bytes()?.checked_add(std::mem::size_of::<Manifest>())?
        .checked_add(VALIDATE_WORK_BYTES)?.checked_add(policy_nodes_bytes(3)?)?;
    if space>cap{return None;}
    if value.schema_version != 1 || value.profile != fields.toolchain || value.target != fields.target
        || value.instance != instance || value.os_provider_sha256 != provider_sha256
        || value.launch_contract != fields.launch || !value.roles.valid()
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
            || !sha(&file.sha256) || !matches!(file.mode,0o444|0o555) || file.size > FILE_LIMIT { return None; }
        add_space(&mut space,policy_nodes_bytes(2)?.checked_add(file.path.len())?,cap)?;
        if !names.insert(file.path.to_ascii_lowercase()){return None;}
        total = total.checked_add(file.size)?; if total > TOTAL_LIMIT { return None; }
        exact.insert(file.path.as_str(), file);
    }
    for alias in &value.aliases {
        if alias_target(alias).is_none() || !exact.contains_key(alias.canonical.as_str()){return None;}
        add_space(&mut space,policy_nodes_bytes(1)?.checked_add(alias.path.len())?,cap)?;
        if !names.insert(alias.path.to_ascii_lowercase()){return None;}
    }
    for path in value.files.iter().map(|f| &f.path).chain(value.aliases.iter().map(|a| &a.path)) {
        let mut part = path.as_str();
        while let Some((parent,_)) = part.rsplit_once('/') {
            if !directories.contains(parent){
                if names.len().checked_add(directories.len())?.checked_add(4)?>ENTRY_LIMIT{return None;}
                add_space(&mut space,policy_nodes_bytes(1)?.checked_add(parent.len())?,cap)?;
                directories.insert(parent.to_owned());
            }
            part = parent;
        }
    }
    for dir in &directories {
        add_space(&mut space,policy_nodes_bytes(1)?.checked_add(dir.len())?,cap)?;
        if !names.insert(dir.to_ascii_lowercase()) { return None; }
    }
    if names.len() + 3 > ENTRY_LIMIT { return None; }
    for name in [MANIFEST,RECORD,PROVIDER] {
        add_space(&mut space,policy_nodes_bytes(1)?.checked_add(name.len())?,cap)?;
        if !names.insert(name.into()) { return None; }
    }
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
    if !sdk35_inventory(&value.files, &value.roles) { return None; }
    Some(Inventory { data: value, directories })
}


// Canonical proposal construction is DATA only. These typed inputs are not
// renderer/local JSON, a supplier reference, owner consent or native custody.
pub(crate) struct ProposalManifestData {
    pub(crate) versions: Versions,
    pub(crate) gradle_distribution: Distribution,
    pub(crate) roles: Roles,
    pub(crate) files: Vec<FileSpec>,
    pub(crate) aliases: Vec<Alias>,
}
pub(crate) fn proposal_inventory(fields: ProposalManifestData, instance: &str,
    provider_sha256: &str) -> Option<Inventory> {
    proposal_inventory_for(Profile::MacArm64, fields, instance, provider_sha256)
}
pub(crate) fn proposal_inventory_for(profile: Profile, fields: ProposalManifestData, instance: &str,
    provider_sha256: &str) -> Option<Inventory> {
    let expected = mac_fields(profile)?;
    if instance.len() != 32 || !instance.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || !sha(provider_sha256) { return None; }
    validate_manifest(Manifest {
        schema_version: 1, profile: expected.toolchain.into(), target: expected.target.into(),
        instance: instance.into(), launch_contract: expected.launch.into(),
        versions: fields.versions, gradle_distribution: fields.gradle_distribution,
        bundletool: Bundletool { version: "1.18.3".into(), sha256: BUNDLETOOL_SHA.into() },
        roles: fields.roles, files: fields.files, aliases: fields.aliases,
        os_provider_sha256: provider_sha256.into(),
    }, expected, instance, provider_sha256)
}
pub(crate) fn proposal_provider(files: Vec<FileSpec>) -> Option<Provider> {
    proposal_provider_for(Profile::MacArm64, files)
}
pub(crate) fn proposal_provider_for(profile: Profile, files: Vec<FileSpec>) -> Option<Provider> {
    let expected = mac_fields(profile)?;
    validate_provider(Provider { schema_version: 1, profile: expected.os.into(), target: expected.target.into(),
        shell: "/bin/sh".into(), executable_path: vec!["/usr/bin".into(), "/bin".into()],
        roots: OS_ROOTS.iter().map(|s| (*s).into()).collect(), files }, expected)
}
pub(crate) struct CanonicalDocument {
    pub(crate) bytes: Vec<u8>,
    pub(crate) sha256: [u8; 32],
}
impl CanonicalDocument {
    pub(crate) fn digest_hex(&self) -> String {
        self.sha256.iter().map(|b| format!("{b:02x}")).collect()
    }
    pub(crate) fn retained_bytes(&self) -> Option<usize> {
        std::mem::size_of::<Self>().checked_add(self.bytes.capacity())
    }
}
struct CountDigest {
    limit: usize, length: usize, hash: Sha256,
}
impl std::io::Write for CountDigest {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let length = self.length.checked_add(bytes.len()).filter(|n| *n <= self.limit)
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidData))?;
        self.hash.update(bytes); self.length = length; Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
}
struct ExactDigest<'a> {
    bytes: &'a mut Vec<u8>, expected: usize, hash: Sha256,
}
impl std::io::Write for ExactDigest<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let length = self.bytes.len().checked_add(bytes.len()).filter(|n| *n <= self.expected
            && *n <= self.bytes.capacity())
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidData))?;
        // Capacity is reserved before encoding; this cannot trigger growth.
        self.bytes.extend_from_slice(bytes); self.hash.update(bytes);
        debug_assert_eq!(self.bytes.len(), length); Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
}
fn encode_canonical<T: Serialize>(value: &T, limit: usize) -> Option<CanonicalDocument> {
    let mut count = CountDigest { limit, length: 0, hash: Sha256::new() };
    serde_json::to_writer(&mut count, value).ok()?;
    if count.length == 0 { return None; }
    let expected: [u8; 32] = count.hash.finalize().into();
    let mut bytes = Vec::new(); bytes.try_reserve_exact(count.length).ok()?;
    if bytes.capacity() > limit || bytes.capacity() < count.length { return None; }
    let mut output = ExactDigest { bytes: &mut bytes, expected: count.length, hash: Sha256::new() };
    serde_json::to_writer(&mut output, value).ok()?;
    let observed: [u8; 32] = output.hash.finalize().into();
    if bytes.len() != count.length || observed != expected { return None; }
    Some(CanonicalDocument { bytes, sha256: expected })
}
pub(crate) fn encode_inventory(value: &Inventory) -> Option<CanonicalDocument> {
    encode_canonical(&value.data, MANIFEST_LIMIT)
}
pub(crate) fn encode_provider(value: &Provider) -> Option<CanonicalDocument> {
    encode_canonical(value, PROVIDER_LIMIT)
}
/// Preview DATA deliberately contains the value that a future registration
/// would use. It does NOT acknowledge licenses. Actual Register must still
/// check its retained Review, live explicit consent and source-consent binding
/// BEFORE service admission/Hello.
pub(crate) fn encode_registration_proposal(account: u32, instance: &str,
    inventory_sha256: &str, provider_sha256: &str) -> Option<CanonicalDocument> {
    encode_registration_proposal_for(Profile::MacArm64, account, instance, inventory_sha256, provider_sha256)
}
pub(crate) fn encode_registration_proposal_for(profile: Profile, account: u32, instance: &str,
    inventory_sha256: &str, provider_sha256: &str) -> Option<CanonicalDocument> {
    let fields = mac_fields(profile)?;
    if account == 0 || account == u32::MAX || instance.len() != 32
        || !instance.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || !sha(inventory_sha256) || !sha(provider_sha256) { return None; }
    let value = Registration { schema_version: 1, profile: fields.toolchain.into(),
        target: fields.target.into(), instance: instance.into(), owner_uid: account,
        inventory_sha256: inventory_sha256.into(), os_provider_sha256: provider_sha256.into(),
        license_acknowledged: true };
    let encoded = encode_canonical(&value, RECORD_LIMIT)?;
    // This small closed record has no manifest-sized Value tree. Reuse the
    // original account/instance/license DATA checks, not a duplicate validator.
    Registration::parse_for(profile, &encoded.bytes, account, instance)?;
    Some(encoded)
}


/// Architecture selection is a file-data predicate, not execution/Rosetta.
/// Only ARM64 or universal files containing a complete ARM64 slice may launch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct MachSlice { pub(crate) offset: u64, pub(crate) size: u64 }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MachArchitecture { Arm64, X86_64 }
impl MachArchitecture {
    fn cpu(self) -> u32 { match self { Self::Arm64 => 0x0100000c, Self::X86_64 => 0x01000007 } }
}
pub(crate) fn arm64_slice(prefix: &[u8], size: u64) -> Option<MachSlice> {
    native_slice(prefix, size, MachArchitecture::Arm64)
}
pub(crate) fn native_slice(prefix: &[u8], size: u64, architecture: MachArchitecture) -> Option<MachSlice> {
    const ARM64: u32 = 0x0100000c;
    const X64: u32 = 0x01000007;
    if size < 32 || prefix.len() < 8 { return None; }
    let le = |at: usize| prefix.get(at..at+4).and_then(|s| s.try_into().ok()).map(u32::from_le_bytes);
    let be = |at: usize| prefix.get(at..at+4).and_then(|s| s.try_into().ok()).map(u32::from_be_bytes);
    if prefix.starts_with(&[0xcf,0xfa,0xed,0xfe]) {
        return (le(4)? == architecture.cpu()).then_some(MachSlice { offset:0, size });
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
        if cpu == architecture.cpu() { selected = Some(MachSlice { offset, size:length }); }
    }
    selected
}
#[derive(Clone, Debug)]
pub(crate) struct MachCommands {
    pub(crate) architecture: MachArchitecture,
    pub(crate) file_type: u32,
    pub(crate) header_sha256: String,
    pub(crate) install_name: Option<String>,
    pub(crate) loads: Vec<String>, pub(crate) rpaths: Vec<String>,
}
/// Parse the selected original ARM64 header/load-command bytes (not the file's
/// first arbitrary text block). Loader paths remain subject to native resolution.
pub(crate) fn macho_commands(raw: &[u8], slice: MachSlice) -> Option<MachCommands> {
    native_commands(raw, slice, MachArchitecture::Arm64)
}
pub(crate) fn native_commands(raw: &[u8], slice: MachSlice, architecture: MachArchitecture) -> Option<MachCommands> {
    if raw.len() < 32 || !raw.starts_with(&[0xcf,0xfa,0xed,0xfe]) { return None; }
    let le = |at:usize| raw.get(at..at+4).and_then(|s|s.try_into().ok()).map(u32::from_le_bytes);
    let file_type = le(12)?;
    if le(4)? != architecture.cpu() || !matches!(file_type, 2|6|8) { return None; }
    let count = usize::try_from(le(16)?).ok()?; let bytes = usize::try_from(le(20)?).ok()?;
    if count > 1024 || bytes > 256*1024 || bytes.checked_add(32)? > raw.len() || (bytes+32) as u64 > slice.size { return None; }
    let end = bytes + 32; let mut at = 32; let mut loads = Vec::new(); let mut rpaths = Vec::new();
    let mut install_name = None;
    for _ in 0..count {
        let command = le(at)?; let length = usize::try_from(le(at+4)?).ok()?;
        if length < 8 || length % 8 != 0 || at.checked_add(length)? > end { return None; }
        if matches!(command,0x0c|0x0d|0x20|0x80000018|0x8000001f|0x80000023|0x8000001c|0x0e) {
            let minimum = if command == 0x8000001c || command == 0x0e { 12 } else { 24 };
            if length < minimum { return None; }
            let offset = usize::try_from(le(at+8)?).ok()?;
            if offset < minimum || offset >= length { return None; }
            let string = &raw[at+offset..at+length];
            let nul = string.iter().position(|b| *b == 0)?;
            let text = std::str::from_utf8(&string[..nul]).ok()?;
            if text.is_empty() || text.len() > 512 || text.chars().any(|c| c.is_control() || c == '\\' || c == ':') { return None; }
            if command == 0x0d {
                if file_type != 6 || install_name.is_some() { return None; }
                install_name = Some(text.into());
            }
            else if command == 0x8000001c { rpaths.push(text.into()); }
            else if command == 0x0e { if text != "/usr/lib/dyld" { return None; } }
            else { loads.push(text.into()); }
        }
        // Runtime environment declarations cannot introduce native provider paths.
        if command == 0x27 { return None; } // LC_DYLD_ENVIRONMENT
        at += length;
    }
    (at == end && (file_type == 6) == install_name.is_some()).then(|| MachCommands {
        architecture, file_type, header_sha256: digest(&raw[..end]), install_name, loads, rpaths })
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
    // The actual supplier/JDK/post-JLI and legacy role authority is ARM-profile only.
    // Paired Intel document DATA must never borrow it as native qualification.
    if !inventory.matches_profile(Profile::MacArm64) { return false; }
    if commands.loads.len().checked_add(commands.rpaths.len()).is_none_or(|n| n > 1024)
        || commands.loads.iter().chain(&commands.rpaths).any(|s| s.len() > 512) { return false; }
    let legacy = sdk35_reserved(path).is_some_and(|kind| kind.legacy() && !kind.script());
    if commands.architecture != (if legacy { MachArchitecture::X86_64 } else { MachArchitecture::Arm64 }) { return false; }
    let loaded_jvm = match crate::android_native_macos_profile::jdk_post_jli_provider(path, commands, inventory) {
        Ok(value) => value, Err(()) => return false,
    };
    let parent = path.rsplit_once('/').map_or("", |(p,_)| p);
    let jdk_bundle = inventory.data.roles.java.split('/').take(2).collect::<Vec<_>>().join("/") + "/";
    let executable_parent = if path.starts_with(&jdk_bundle) {
        // Every permitted JDK launcher lives in this same Contents/Home/bin.
        inventory.data.roles.java.rsplit_once('/').map(|(p,_)| p)
    } else if inventory.data.roles.launch().iter().any(|p| p == path) { Some(parent) } else { None };
    let token = |value: &str| -> Option<String> {
        if matches!(value, "@loader_path" | "@loader_path/") { return Some(parent.into()); }
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
        if load == "@rpath/libjvm.dylib" {
            if let Some(provider) = loaded_jvm { candidates.insert(provider.to_owned()); }
        }
        if let Some(tail) = load.strip_prefix("@rpath/") {
            for (system, root) in &search {
                let Some(path) = resolve(root,tail) else { return false; };
                if *system {
                    if !system_load(&("/".to_owned()+&path)) { return false; }
                    // The immutable native OS provider is admitted separately.
                    candidates.insert("/".to_owned()+&path);
                } else {
                    let canonical = inventory.exact_alias(&path).map_or(path.as_str(), |a|a.canonical.as_str());
                    if inventory.exact_file(canonical).is_some() { candidates.insert(canonical.to_owned()); }
                }
            }
        } else {
            let Some(path) = token(load) else { return false; };
            let canonical = inventory.exact_alias(&path).map_or(path.as_str(), |a|a.canonical.as_str());
            if inventory.exact_file(canonical).is_some() { candidates.insert(canonical.to_owned()); }
        }
        // Refuse ambiguous provider selection instead of inventing dyld facts.
        if candidates.len() != 1 { return false; }
        let legacy_source = sdk35_reserved(path).is_some_and(|kind| kind.legacy() && !kind.script());
        for candidate in &candidates {
            if !candidate.starts_with('/') {
                let legacy_target = sdk35_reserved(candidate).is_some_and(|kind| kind.legacy() && !kind.script());
                // No ARM64 native/current core route may enter the exact Intel
                // legacy graph; the legacy graph may not borrow ARM64 locals.
                if legacy_source != legacy_target { return false; }
                if sdk35_reserved(candidate).is_some_and(Sdk35File::script)
                    || crate::android_native_macos_profile::target_elf_reserved(candidate).is_some()
                    || candidate == crate::android_native_macos_profile::GRADLE_BAT.path { return false; }
                // A JDK graph belongs to exactly its retained bundle. No SDK,
                // Gradle or outside component can supply or borrow that VM.
                if path.starts_with("jdk/") != candidate.starts_with("jdk/")
                    || path.starts_with("jdk/") && !path.split('/').take(2).eq(candidate.split('/').take(2)) { return false; }
            }
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};
    pub(super) fn proposal_tree_budget_preserves_live_roots_and_overflow_data() {
        assert_eq!(proposal_tree_reservation_bytes(0, 0, 0), Some(6 * 512));
        assert_eq!(proposal_tree_reservation_bytes(7, 2, 4), Some(30 * 512));
        for counts in [(usize::MAX, 0, 0), (0, usize::MAX, 0), (0, 0, usize::MAX)] {
            assert_eq!(proposal_tree_reservation_bytes(counts.0, counts.1, counts.2), None);
        }
    }
    #[test]
    fn proposal_tree_budget_preserves_live_roots_and_overflow() {
        proposal_tree_budget_preserves_live_roots_and_overflow_data();
    }
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
        let (mut selected,mut value)=fixture();
        let canonical="jdk/Test.jdk/Contents/Home/lib/jli/libjli.dylib";
        value["aliases"]=json!([
            {"path":"jdk/Test.jdk/Contents/Home/lib/jli/link-a.dylib","target":"libjli.dylib","canonical":canonical},
            {"path":"jdk/Test.jdk/Contents/Home/lib/jli/link-c.dylib","target":"libjli.dylib","canonical":canonical},
        ]);
        let admitted=inventory(&mut selected,&value).unwrap(); // DATA predicate only.
        // Exact and prefix lookup retain the original row, including both ends
        // of the sorted roster. Neither lookup silently resolves an alias.
        for file in &admitted.data.files {
            assert!(std::ptr::eq(admitted.exact_file(&file.path).unwrap(),file));
            let split=file.path.rfind('/').unwrap()+1;
            let (prefix,relative)=file.path.split_at(split);
            assert!(std::ptr::eq(admitted.file_under(prefix,relative).unwrap(),file));
            assert!(admitted.exact_alias(&file.path).is_none());
        }
        for alias in &admitted.data.aliases {
            assert!(std::ptr::eq(admitted.exact_alias(&alias.path).unwrap(),alias));
            assert!(admitted.exact_file(&alias.path).is_none());
        }
        for path in ["a/missing","jdk/Test.jdk/Contents/Home/bin/javaa","z/missing"] {
            assert!(admitted.exact_file(path).is_none());
        }
        for path in ["a/missing","jdk/Test.jdk/Contents/Home/lib/jli/link-b.dylib","z/missing"] {
            assert!(admitted.exact_alias(path).is_none());
        }
        // These span leading/trailing components and neighboring full keys.
        for (prefix,relative) in [
            ("jdk/Test.jdk/","Contents/Home/bin/java"),
            ("jdk/","Test.jdk/Contents/Home/bin/javac"),
            ("sdk/","platforms/android-35/android.jar"),
            ("a/","missing"),("z/","missing"),
            ("jdk/Test.jdk/","Contents/Home/bin/javaa"),
            ("jdk/Test.jdk2/","Contents/Home/bin/java"),
            ("jdk/Test.jdk/Contents/Home/bin/java/","child"),
        ] {
            assert_eq!(admitted.file_under(prefix,relative),
                admitted.data.files.iter().find(|file|file.path.strip_prefix(prefix)==Some(relative)));
        }
        for (prefix,relative) in [
            ("","jdk/Test.jdk/Contents/Home/bin/java"),
            ("jdk/Test.","jdk/Contents/Home/bin/java"),
            ("jdk/Test.jdk/",""),
            ("jdk/Test.jdk/","/Contents/Home/bin/java"),
        ] {
            assert!(admitted.file_under(prefix,relative).is_none());
        }
        // Sorted unique paths are admission conditions, not a lookup fallback.
        for field in ["files","aliases"] {
            let mut changed=value.clone();
            changed[field].as_array_mut().unwrap().swap(0,1);
            assert!(inventory(&mut selected,&changed).is_none(),"{field} order");
            let mut changed=value.clone();
            let rows=changed[field].as_array_mut().unwrap();
            let duplicate=rows[0].clone();rows.insert(1,duplicate);
            assert!(inventory(&mut selected,&changed).is_none(),"{field} duplicate");
        }
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
        for target in ["/usr/lib/libjli.dylib","../../../../../../tmp/file","../../../../../Other.jdk/file","",
            "../../../../../Test.jdk/Contents/Home/lib/jli/libjli.dylib"] {
            assert!(alias_target(&Alias {target:target.into(),..alias.clone()}).is_none());
        }
        let source=Alias {path:"Contents/Home/lib/jli/link.dylib".into(),target:alias.target.clone(),
            canonical:"Contents/Home/lib/jli/libjli.dylib".into()};
        assert!(alias_target(&source).is_none()); // The installed API stays installed-only.
        for target in ["libjli.dylib", "./libjli.dylib", "../jli/libjli.dylib"] {
            assert!(jdk_source_alias_resolves(&source.path,target,&source.canonical));
            assert_eq!(alias_target(&Alias {target:target.into(),..alias.clone()}),Some(alias.canonical.clone()));
        }
        for target in ["", "/usr/lib/libjli.dylib", "../wrong.dylib", "libjli.dylib/", "a//b",
            "a\\b", "libjli.dylib\n", "\0", "../../../../../Contents/Home/lib/jli/libjli.dylib"] {
            assert!(!jdk_source_alias_resolves(&source.path,target,&source.canonical),"{target:?}");
            assert!(alias_target(&Alias {target:target.into(),..alias.clone()}).is_none(),"{target:?}");
        }
        assert!(!jdk_source_alias_resolves("../link","file","file"));
        assert!(!jdk_source_alias_resolves("dir/link","file","dir/../file"));
        // A legal source name beginning jdk/ is not an installed-root override.
        assert!(jdk_source_alias_resolves("jdk/inner/link","file","jdk/inner/file"));
        let deep=format!("{}{}file","d/".repeat(20),"../".repeat(20));
        assert!(jdk_source_alias_resolves("dir/link",&deep,"dir/file"));
        assert_eq!(alias_target(&Alias {path:"jdk/Test.jdk/dir/link".into(),target:deep,
            canonical:"jdk/Test.jdk/dir/file".into()}),Some("jdk/Test.jdk/dir/file".into()));
        assert!(!jdk_source_alias_resolves("link",&"x".repeat(513),"file"));
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
        assert_eq!(OS_FILES.len(), 11);
        let mut legacy = provider.clone();
        legacy["files"].as_array_mut().unwrap().retain(|file|
            !["/bin/bash", "/bin/ls", "/usr/bin/expr"].contains(&file["path"].as_str().unwrap()));
        let bytes=serde_json::to_vec(&legacy).unwrap();selected.os_provider_sha256=digest(&bytes);
        assert!(Provider::parse(&bytes,&selected).is_none());
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
        word(&mut thin,12,2,false);
        let intel=native_slice(&thin,32,MachArchitecture::X86_64).unwrap();
        assert!(native_commands(&thin,intel,MachArchitecture::X86_64).is_some());
        assert!(macho_commands(&thin,intel).is_none());
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
        word(&mut raw,32,0x0d,false);assert!(macho_commands(&raw,slice).is_none()); // Not valid on an executable.
        word(&mut raw,12,6,false);
        let identity=macho_commands(&raw,slice).unwrap();
        assert!(identity.loads.is_empty());
        assert_eq!(identity.file_type,6);
        assert_eq!(identity.install_name.as_deref(),Some("/usr/lib/libSystem.B.dylib"));
        assert_eq!(identity.header_sha256,digest(&raw));
        let mut duplicate=raw.clone();duplicate.extend_from_slice(&raw[32..]);
        word(&mut duplicate,16,2,false);word(&mut duplicate,20,(length*2)as u32,false);
        assert!(macho_commands(&duplicate,MachSlice {offset:0,size:duplicate.len()as u64}).is_none());
        word(&mut raw,32,0x20,false);assert!(macho_commands(&raw,slice).is_none()); // A dylib needs one identity.
        word(&mut raw,12,2,false);word(&mut raw,32,0x27,false);assert!(macho_commands(&raw,slice).is_none());
    }
    pub(super) fn dyld_search_never_ignores_unprotected_roots_or_assumes_inherited_rpaths_data() {
        let (mut selected,value)=fixture();let inventory=inventory(&mut selected,&value).unwrap();
        let binary=inventory.data.roles.java.as_str();
        let mut commands=MachCommands {architecture:MachArchitecture::Arm64,file_type:2,header_sha256:"".into(),install_name:None,loads:vec!["@rpath/libjli.dylib".into()],rpaths:vec!["@loader_path/../lib/jli".into()]};
        assert!(local_loads(binary,&commands,&inventory));
        commands.rpaths.insert(0,"@loader_path/missing".into());assert!(local_loads(binary,&commands,&inventory));
        commands.rpaths.insert(0,"/tmp/unprotected".into());assert!(!local_loads(binary,&commands,&inventory));
        commands.rpaths.clear();assert!(!local_loads(binary,&commands,&inventory));
        commands.loads=vec!["@loader_path/../lib/jli/libjli.dylib".into()];assert!(local_loads(binary,&commands,&inventory));
        commands.loads=vec!["/usr/local/lib/libjli.dylib".into()];assert!(!local_loads(binary,&commands,&inventory));
        let library="jdk/Test.jdk/Contents/Home/lib/jli/libjli.dylib";
        commands.loads=vec!["@rpath/libjli.dylib".into()];
        for accepted in ["@loader_path", "@loader_path/"] {
            commands.rpaths=vec![accepted.into()];assert!(local_loads(library,&commands,&inventory));
        }
        for refused in ["@loader_path//", "@loader_path//lib", "@loader_path/../../../../../../../../escape",
            "@unknown_path/", "@executable_path/"] {
            commands.rpaths=vec![refused.into()];assert!(!local_loads(library,&commands,&inventory),"{refused}");
        }
        commands.rpaths=vec!["@loader_path/".into(),"/usr/lib".into()];
        assert!(!local_loads(library,&commands,&inventory)); // Still ambiguous; no preferred-provider invention.
    }

    pub(super) fn sdk_original_scripts_and_legacy_native_roles_are_separate_data() {
        let (mut selected, mut value)=fixture();
        let rows=value["files"].as_array_mut().unwrap();
        for pin in SDK35_PINS {
            rows.push(json!({"path":pin.path,"size":pin.bytes,"sha256":pin.sha256,"mode":pin.original_mode&!0o222}));
            let spec=FileSpec {path:pin.path.into(),size:pin.bytes,sha256:pin.sha256.into(),mode:pin.original_mode&!0o222};
            assert_eq!(sdk35_file(&spec),Ok(Some(pin.kind)));
            for changed in [FileSpec {sha256:"e".repeat(64),..spec.clone()},
                FileSpec {size:spec.size+1,..spec.clone()},FileSpec {mode:pin.original_mode,..spec.clone()}] {
                assert_eq!(sdk35_file(&changed),Err(()));
            }
            let changed=FileSpec {path:format!("other/{}",pin.path),..spec};
            assert_eq!(sdk35_file(&changed),Ok(None)); // Not a new script/Intel exception.
        }
        for (name, bytes) in [("d8",16_614_740),("apksigner",1_074_241)] {
            rows.push(json!({"path":format!("sdk/build-tools/35.0.0/lib/{name}.jar"),
                "size":bytes,"sha256":"e".repeat(64),"mode":0o444}));
        }
        rows.sort_by(|a,b|a["path"].as_str().cmp(&b["path"].as_str()));
        let accepted=inventory(&mut selected,&value).unwrap();
        for kind in [Sdk35File::D8,Sdk35File::Apksigner,Sdk35File::LldShell] {
            assert!(sdk35_script(kind,b"#!/bin/bash\n",&accepted));
            for prefix in [b"#!/bin/sh\n".as_slice(),b"#!/usr/bin/env bash\n".as_slice(),b"#!/bin/bash\r\n".as_slice()] {
                assert!(!sdk35_script(kind,prefix,&accepted));
            }
        }
        assert!(!sdk35_script(Sdk35File::LldIntel,b"#!/bin/bash\n",&accepted));
        for pin in SDK35_PINS {
            let mut changed=value.clone();
            changed["files"].as_array_mut().unwrap().retain(|file|file["path"]!=pin.path);
            assert!(inventory(&mut selected,&changed).is_none());
        }
        let mut changed=value.clone();
        changed["files"].as_array_mut().unwrap().retain(|file|file["path"]!="sdk/build-tools/35.0.0/lib/d8.jar");
        assert!(inventory(&mut selected,&changed).is_none());
        let mut commands=MachCommands {architecture:MachArchitecture::X86_64,file_type:2,header_sha256:"".into(),install_name:None,loads:vec!["@rpath/libc++.1.dylib".into()],rpaths:vec!["@loader_path/../lib64".into()]};
        assert!(local_loads(Sdk35File::LldIntel.pin().path,&commands,&accepted));
        commands.loads=vec!["@loader_path/../../../sdk/build-tools/35.0.0/lib64/libc++.1.dylib".into()];
        commands.rpaths.clear();assert!(!local_loads(AAPT2,&commands,&accepted));
        commands.loads=vec!["@loader_path/../../../../jdk/Test.jdk/Contents/Home/lib/jli/libjli.dylib".into()];
        assert!(!local_loads(Sdk35File::LldIntel.pin().path,&commands,&accepted));
        let mut changed=value;
        changed["roles"]["java"]=json!(Sdk35File::LldIntel.pin().path);
        assert!(inventory(&mut selected,&changed).is_none());
    }

    fn exact_jdk_value() -> (MacToolchainSelection, Value) {
        use crate::android_native_macos_profile as profile;
        let (selected, mut value)=fixture();
        value["versions"]["jdkVendor"]=json!("temurin");
        value["versions"]["jdkVersion"]=json!("17.0.20.1");
        let rows=value["files"].as_array_mut().unwrap();
        rows.retain(|file|!file["path"].as_str().unwrap().starts_with("jdk/"));
        for pin in profile::JDK_NATIVE {
            rows.push(json!({"path":format!("jdk/Test.jdk/{}",pin.relative),"size":pin.bytes,
                "sha256":pin.sha256,"mode":pin.original_mode&!0o222}));
        }
        rows.push(json!({"path":"jdk/Test.jdk/Contents/Home/release","size":1638,
            "sha256":"cb6064fe4d7b87d9fbb8b8c7702047044d1bbeac38e0c5217f595579b6cc764b","mode":0o444}));
        rows.push(json!({"path":"jdk/Test.jdk/Contents/Home/lib/jvm.cfg","size":29,
            "sha256":"aa9efb969444c1484e29adecab55a122458090616e766b2f1230ef05bc3867e0","mode":0o444}));
        rows.sort_by(|a,b|a["path"].as_str().cmp(&b["path"].as_str()));
        (selected,value)
    }
    fn expected_jdk_commands(pin:&crate::android_native_macos_profile::JdkNativePin)->MachCommands {
        // Explicit inert expected DATA, not a native read/receipt. Parser bytes
        // have separate tests and actual execution remains a platform gate.
        let h=&pin.header;
        MachCommands {architecture:MachArchitecture::Arm64,file_type:h.file_type,
            header_sha256:h.commands_sha256.into(),install_name:h.install_name.map(str::to_owned),
            loads:h.loads.iter().map(|s|(*s).into()).collect(),rpaths:h.rpaths.iter().map(|s|(*s).into()).collect()}
    }
    pub(super) fn jdk_post_jli_is_finite_and_never_bootstrap_or_cross_component_data() {
        use crate::android_native_macos_profile as profile;
        let (mut selected,value)=exact_jdk_value();
        let original=inventory(&mut selected,&value).unwrap();
        let pin=profile::jdk_native("Contents/Home/lib/libjava.dylib").unwrap();
        let path="jdk/Test.jdk/Contents/Home/lib/libjava.dylib";
        let commands=expected_jdk_commands(pin);
        assert_eq!(profile::jdk_post_jli_provider(path,&commands,&original),
            Ok(Some("jdk/Test.jdk/Contents/Home/lib/server/libjvm.dylib")));
        assert!(local_loads(path,&commands,&original));
        for pin in profile::JDK_NATIVE {
            let path=format!("jdk/Test.jdk/{}",pin.relative);
            let commands=expected_jdk_commands(pin);
            assert!(local_loads(&path,&commands,&original),"{}",pin.relative);
            if pin.phase!=profile::JdkPhase::PostJli {
                assert_eq!(profile::jdk_post_jli_provider(&path,&commands,&original),Ok(None));
            }
        }
        // Keep the actual server provider's protected parent rpath. This exact
        // tuple is not permission for another caller/native to add parent roots.
        let provider=profile::jdk_native("Contents/Home/lib/server/libjvm.dylib").unwrap();
        assert_eq!(provider.header.rpaths, ["@loader_path/.", "@loader_path/.."]);
        let provider_path="jdk/Test.jdk/Contents/Home/lib/server/libjvm.dylib";
        let mut missing=expected_jdk_commands(provider);missing.rpaths.pop();
        assert!(!local_loads(provider_path,&missing,&original));
        let mut escaped=expected_jdk_commands(provider);escaped.rpaths.push("@loader_path/../../..".into());
        assert!(!local_loads(provider_path,&escaped,&original));
        let launcher=profile::jdk_native("Contents/Home/bin/java").unwrap();
        let mut early=expected_jdk_commands(launcher);early.loads.push("@rpath/libjvm.dylib".into());
        assert!(!local_loads(&original.data.roles.java,&early,&original));
        for relative in ["Contents/Home/lib/libjli.dylib","Contents/Home/lib/server/libjvm.dylib",
            "Contents/Home/bin/java","Contents/Home/release","Contents/Home/lib/jvm.cfg"] {
            let mut bad=value.clone();
            bad["files"].as_array_mut().unwrap().iter_mut().find(|file|
                file["path"]==format!("jdk/Test.jdk/{relative}")).unwrap()["sha256"]=json!("f".repeat(64));
            let wrong=inventory(&mut selected,&bad).unwrap();
            assert!(!local_loads(path,&commands,&wrong),"{relative}");
        }
        let mut wrong_cpu=commands.clone();wrong_cpu.architecture=MachArchitecture::X86_64;
        assert!(!local_loads(path,&wrong_cpu,&original));
        let mut wrong_id=commands.clone();wrong_id.install_name=Some("@rpath/changed.dylib".into());
        assert!(!local_loads(path,&wrong_id,&original));
        let mut unknown=commands.clone();unknown.rpaths.push("/tmp/untrusted".into());
        assert!(!local_loads(path,&unknown,&original));
        // Exact non-JDK clients do not inherit the sealed JLI phase.
        let outside=MachCommands {architecture:MachArchitecture::Arm64,file_type:2,header_sha256:"".into(),install_name:None,
            loads:vec!["@loader_path/../../../jdk/Test.jdk/Contents/Home/lib/server/libjvm.dylib".into()],rpaths:vec![]};
        assert!(!local_loads(AAPT2,&outside,&original));
        let mut extra=value;
        extra["files"].as_array_mut().unwrap().push(json!({"path":"jdk/Test.jdk/Contents/Home/lib/libjvm.dylib",
            "size":1,"sha256":"f".repeat(64),"mode":0o444}));
        extra["files"].as_array_mut().unwrap().sort_by(|a,b|a["path"].as_str().cmp(&b["path"].as_str()));
        assert!(!local_loads(path,&commands,&inventory(&mut selected,&extra).unwrap()));
    }
    pub(super) fn finite_target_elf_and_foreign_launcher_never_become_host_providers_data() {
        use crate::android_native_macos_profile as profile;
        let (mut selected,mut value)=fixture();
        for pin in profile::SDK_TARGET_ELFS {
            let spec=FileSpec {path:pin.path.into(),size:pin.bytes,sha256:pin.sha256.into(),mode:0o444};
            assert_eq!(android_target_elf(&spec,pin.header),Ok(true));
            let mut bad=pin.header.to_vec();bad[18]^=1;
            assert_eq!(android_target_elf(&spec,&bad),Err(()));
            assert_eq!(android_target_elf(&FileSpec {mode:0o555,..spec.clone()},pin.header),Err(()));
            assert_eq!(android_target_elf(&FileSpec {sha256:"f".repeat(64),..spec},pin.header),Err(()));
            value["files"].as_array_mut().unwrap().push(json!({"path":pin.path,"size":pin.bytes,"sha256":pin.sha256,"mode":0o444}));
        }
        let pin=&profile::GRADLE_BAT;
        let spec=FileSpec {path:pin.path.into(),size:pin.bytes,sha256:pin.sha256.into(),mode:0o444};
        assert_eq!(gradle_foreign_launcher(&spec),Ok(true));
        assert_eq!(gradle_foreign_launcher(&FileSpec {mode:0o555,..spec.clone()}),Err(()));
        value["files"].as_array_mut().unwrap().push(json!({"path":pin.path,"size":pin.bytes,"sha256":pin.sha256,"mode":0o444}));
        value["files"].as_array_mut().unwrap().sort_by(|a,b|a["path"].as_str().cmp(&b["path"].as_str()));
        let original=inventory(&mut selected,&value).unwrap();
        let target=&profile::SDK_TARGET_ELFS[0];
        let commands=MachCommands {architecture:MachArchitecture::Arm64,file_type:2,header_sha256:"".into(),install_name:None,
            loads:vec![format!("@loader_path/../../../{}",target.path)],rpaths:vec![]};
        assert!(!local_loads("sdk/build-tools/35.0.0/aapt",&commands,&original));
        let mut missing=value.clone();
        missing["files"].as_array_mut().unwrap().retain(|file|file["path"]!=target.path);
        assert!(inventory(&mut selected,&missing).is_none());
        let mut host=value;
        host["roles"]["gradle"]=json!(pin.path);
        assert!(inventory(&mut selected,&host).is_none());
    }
    #[test]
    fn jdk_post_jli_is_finite_and_never_bootstrap_or_cross_component() {
        jdk_post_jli_is_finite_and_never_bootstrap_or_cross_component_data();
    }
    #[test]
    fn finite_target_elf_and_foreign_launcher_never_become_host_providers() {
        finite_target_elf_and_foreign_launcher_never_become_host_providers_data();
    }

    #[test]
    fn sdk_original_scripts_and_legacy_native_roles_are_separate() { sdk_original_scripts_and_legacy_native_roles_are_separate_data(); }
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

    pub(super) fn canonical_proposals_reuse_raw_parser_contract_data() {
        let (mut selected, value) = fixture();
        let old = inventory(&mut selected, &value).unwrap();
        let provider = proposal_provider(OS_FILES.iter().map(|path| FileSpec {
            path: (*path).into(), size: 1, sha256: "e".repeat(64),
            mode: if path.ends_with(".plist") { 0o644 } else { 0o755 },
        }).collect()).unwrap();
        let os = encode_provider(&provider).unwrap();
        selected.os_provider_sha256 = os.digest_hex();
        assert!(Provider::parse(&os.bytes, &selected).is_some());
        let manifest = proposal_inventory(ProposalManifestData {
            versions: old.data.versions, gradle_distribution: old.data.gradle_distribution,
            roles: old.data.roles, files: old.data.files, aliases: old.data.aliases,
        }, &selected.instance, &selected.os_provider_sha256).unwrap();
        let first = encode_inventory(&manifest).unwrap();
        let second = encode_inventory(&manifest).unwrap();
        assert_eq!(first.bytes, second.bytes);
        assert_eq!(first.sha256, second.sha256);
        assert!(first.bytes.capacity() >= first.bytes.len() && first.bytes.capacity() <= MANIFEST_LIMIT);
        selected.inventory_sha256 = first.digest_hex();
        let parsed = parse_manifest(&first.bytes, &selected).unwrap();
        assert_eq!(parsed.data.files, manifest.data.files);
        assert_eq!(parsed.data.aliases, manifest.data.aliases);
        assert_eq!(parsed.directories, manifest.directories);
        let registration = encode_registration_proposal(501, &selected.instance,
            &selected.inventory_sha256, &selected.os_provider_sha256).unwrap();
        assert!(Registration::parse(&registration.bytes, 501, &selected.instance).unwrap().matches(&selected));
        assert!(Registration::parse(&registration.bytes, 502, &selected.instance).is_none());
        let mut wrong = selected.clone(); wrong.os_provider_sha256 = "f".repeat(64);
        assert!(parse_manifest(&first.bytes, &wrong).is_none());
        assert!(Provider::parse(&os.bytes, &wrong).is_none());
        assert!(encode_registration_proposal(0, &selected.instance, &selected.inventory_sha256,
            &selected.os_provider_sha256).is_none());
        // A valid typed serialization never removes duplicate/unknown raw-JSON gates.
        let duplicate = String::from_utf8(first.bytes).unwrap().replacen(
            "{", "{\"schemaVersion\":1,", 1).into_bytes();
        selected.inventory_sha256 = digest(&duplicate);
        assert!(parse_manifest(&duplicate, &selected).is_none());
        let mut bad = manifest.data.files.clone(); bad[0].mode = 0o777;
        assert!(proposal_inventory(ProposalManifestData {
            versions: manifest.data.versions, gradle_distribution: manifest.data.gradle_distribution,
            roles: manifest.data.roles, files: bad, aliases: manifest.data.aliases,
        }, &selected.instance, &selected.os_provider_sha256).is_none());
    }
    pub(super) fn canonical_encoder_refuses_limits_and_second_pass_drift_data() {
        use serde::Serializer;
        use std::cell::Cell;
        struct Changes(Cell<bool>);
        impl Serialize for Changes {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                let old = self.0.replace(true);
                serializer.serialize_str(if old { "two" } else { "one" })
            }
        }
        assert!(encode_canonical(&"fixed", 6).is_none());
        assert!(encode_canonical(&"fixed", 7).is_some());
        assert!(encode_canonical(&Changes(Cell::new(false)), 32).is_none());
    }
    pub(super) fn bounded_helper_parser_keeps_one_schema_authority_data() {
        let (mut selected,value)=fixture();
        let raw=serde_json::to_vec(&value).unwrap();
        selected.inventory_sha256=digest(&raw);
        let ordinary=parse_manifest(&raw,&selected).unwrap();
        let bounded=parse_manifest_bounded(&raw,&selected,32*1024*1024).unwrap();
        assert_eq!(ordinary.data.files,bounded.data.files);
        assert_eq!(ordinary.directories,bounded.directories);
        assert!(bounded.data.files.capacity()<FILE_COUNT); // no eager maximum for tiny manifests
        assert!(bounded.dynamic_bytes().unwrap()>0);
        // Escaped keys and values remain valid, not a second canonical-text rule.
        let escaped=String::from_utf8(raw.clone()).unwrap()
            .replace("\"schemaVersion\"","\"\\u0073chemaVersion\"")
            .replace("android-35","\\u0061ndroid-35").into_bytes();
        selected.inventory_sha256=digest(&escaped);
        assert!(parse_manifest(&escaped,&selected).is_some());
        assert!(parse_manifest_bounded(&escaped,&selected,32*1024*1024).is_some());
        let text=String::from_utf8(raw.clone()).unwrap();
        for bad in [
            text.replacen("{","{\"schemaVersion\":1,",1).into_bytes(),
            text.replacen("{","{\"notAField\":1,",1).into_bytes(),
            [raw.clone(),b" false".to_vec()].concat(),
            raw[..raw.len()-1].to_vec(),
            text.replacen("\"test\"",&format!("\"{}\"","x".repeat(JSON_STRING_TOKEN+1)),1).into_bytes(),
            text.replacen("\"schemaVersion\":1",&format!("\"schemaVersion\":{}","1".repeat(JSON_NUMBER_TOKEN+1)),1).into_bytes(),
        ] {
            selected.inventory_sha256=digest(&bad);
            assert!(parse_manifest(&bad,&selected).is_none());
            assert!(parse_manifest_bounded(&bad,&selected,32*1024*1024).is_none());
        }
        selected.inventory_sha256=digest(&raw);
        let cells=FILE_COUNT*std::mem::size_of::<FileSpec>()+ALIAS_COUNT*std::mem::size_of::<Alias>();
        let gate=parse_bound::<Manifest>(raw.len(),cells).unwrap();
        assert!(parse_manifest_bounded(&raw,&selected,gate-1).is_none());
        assert!(parse_bound::<Manifest>(usize::MAX,cells).is_none());
        assert!(parse_bound::<Manifest>(1,usize::MAX).is_none());
        let provider=proposal_provider(OS_FILES.iter().map(|path|FileSpec{
            path:(*path).into(),size:1,sha256:"e".repeat(64),
            mode:if path.ends_with(".plist"){0o644}else{0o755},
        }).collect()).unwrap();
        let os=encode_provider(&provider).unwrap();selected.os_provider_sha256=os.digest_hex();
        assert_eq!(Provider::parse(&os.bytes,&selected).unwrap().files,
            Provider::parse_bounded(&os.bytes,&selected,1024*1024).unwrap().files);
        assert!(Provider::parse_bounded(&os.bytes,&selected,0).is_none());
        let record=encode_registration_proposal(501,&selected.instance,
            &selected.inventory_sha256,&selected.os_provider_sha256).unwrap();
        assert_eq!(Registration::parse(&record.bytes,501,&selected.instance),
            Registration::parse_bounded(&record.bytes,501,&selected.instance,1024*1024));
        assert!(Registration::parse_bounded(&record.bytes,502,&selected.instance,1024*1024).is_none());
    }
    pub(super) fn bounded_tokens_and_vectors_refuse_before_unbounded_growth_data() {
        fn small<'de,D:serde::Deserializer<'de>>(d:D)->Result<Vec<String>,D::Error>{bounded_vec::<String,D,2>(d)}
        fn zero<'de,D:serde::Deserializer<'de>>(d:D)->Result<Vec<String>,D::Error>{bounded_vec::<String,D,0>(d)}
        #[derive(Deserialize)]
        struct Small{#[serde(deserialize_with="small")] values:Vec<String>}
        #[derive(Deserialize)]
        struct Zero{#[serde(deserialize_with="zero")] values:Vec<String>}
        let empty:Small=serde_json::from_str(r#"{"values":[]}"#).unwrap();
        let one:Small=serde_json::from_str(r#"{"values":["a"]}"#).unwrap();
        let full:Small=serde_json::from_str(r#"{"values":["a","b"]}"#).unwrap();
        assert_eq!((empty.values.capacity(),one.values.capacity(),full.values.capacity()),(0,1,2));
        let empty:Zero=serde_json::from_str(r#"{"values":[]}"#).unwrap();
        assert_eq!(empty.values.capacity(),0);
        // The excess nested value is intentionally unfinished: the list's own
        // limit must refuse before parsing/allocating any part of that value.
        let error=serde_json::from_str::<Small>(r#"{"values":["a","b",{"#).err().unwrap();
        assert!(error.to_string().contains("too many entries"));
        let error=serde_json::from_str::<Zero>(r#"{"values":[{"#).err().unwrap();
        assert!(error.to_string().contains("too many entries"));
        let escaped=r#"{"value":"a\\\"b","number":18446744073709551615}"#;
        assert!(json_tokens_bounded(escaped.as_bytes()));
        assert!(serde_json::from_str::<Value>(escaped).is_ok());
        let inside=format!("\"{}\"","1".repeat(JSON_STRING_TOKEN));
        assert!(json_tokens_bounded(inside.as_bytes())); // digits in a String are not numeric scratch
        assert!(!json_tokens_bounded(format!("\"{}\"","x".repeat(JSON_STRING_TOKEN+1)).as_bytes()));
        assert!(json_tokens_bounded("1".repeat(JSON_NUMBER_TOKEN).as_bytes()));
        assert!(!json_tokens_bounded("1".repeat(JSON_NUMBER_TOKEN+1).as_bytes()));
        assert!(bounded_typed::<String>(br#""broken\"#,64,0,1024*1024).is_none());
    }
    #[test]
    fn bounded_helper_parser_keeps_one_schema_authority(){bounded_helper_parser_keeps_one_schema_authority_data();}
    #[test]
    fn bounded_tokens_and_vectors_refuse_before_unbounded_growth(){bounded_tokens_and_vectors_refuse_before_unbounded_growth_data();}
    #[test]
    fn canonical_proposals_reuse_raw_parser_contract() { canonical_proposals_reuse_raw_parser_contract_data(); }
    #[test]
    fn canonical_encoder_refuses_limits_and_second_pass_drift() { canonical_encoder_refuses_limits_and_second_pass_drift_data(); }

    fn paired_fields() -> ProposalManifestData {
        let (mut selected, value) = fixture();
        let old = inventory(&mut selected, &value).unwrap();
        ProposalManifestData { versions: old.data.versions, gradle_distribution: old.data.gradle_distribution,
            roles: old.data.roles, files: old.data.files, aliases: old.data.aliases }
    }
    fn paired_os_files() -> Vec<FileSpec> {
        OS_FILES.iter().map(|path| FileSpec { path: (*path).into(), size: 1, sha256: "e".repeat(64),
            mode: if path.ends_with(".plist") { 0o644 } else { 0o755 } }).collect()
    }
    fn paired_documents(profile: Profile) -> (MacToolchainSelection, [CanonicalDocument; 3]) {
        let (mut selected, _) = fixture();
        let provider = proposal_provider_for(profile, paired_os_files()).unwrap();
        let os = encode_provider(&provider).unwrap();
        selected.os_provider_sha256 = os.digest_hex();
        let proposed = proposal_inventory_for(profile, paired_fields(), &selected.instance,
            &selected.os_provider_sha256).unwrap();
        let manifest = encode_inventory(&proposed).unwrap();
        selected.inventory_sha256 = manifest.digest_hex();
        let record = encode_registration_proposal_for(profile, selected.owner_uid, &selected.instance,
            &selected.inventory_sha256, &selected.os_provider_sha256).unwrap();
        selected.record_sha256 = record.digest_hex();
        (selected, [manifest, record, os])
    }
    pub(super) fn paired_policy_roundtrips_preserve_arm_defaults_and_bounds_data() {
        // Independent literal expectations, not mac_fields as the oracle.
        for (profile, toolchain, target, launch, os_profile) in [
            (Profile::MacArm64, "android-registered-macos-arm64-v1", "macos-arm64",
             "gradle-macos-private-jvm-arm64-v1", "macos26-arm64-sealed-system-v1"),
            (Profile::MacX64, "android-registered-macos-x86_64-v1", "macos-x86_64",
             "gradle-macos-private-jvm-x86_64-v1", "macos26-x86_64-sealed-system-v1"),
        ] {
            let (selected, docs) = paired_documents(profile);
            let parsed = parse_manifest_for(profile, &docs[0].bytes, &selected).unwrap();
            assert!(parsed.matches_profile(profile));
            assert!(!parsed.matches_profile(Profile::LinuxX64));
            assert_eq!((&parsed.data.profile[..], &parsed.data.target[..], &parsed.data.launch_contract[..]),
                (toolchain, target, launch));
            assert_eq!(encode_inventory(&parsed).unwrap().bytes, docs[0].bytes);
            let bounded = parse_manifest_bounded_for(profile, &docs[0].bytes, &selected, 32*1024*1024).unwrap();
            assert_eq!(parsed.data.files, bounded.data.files);
            assert_eq!(parsed.directories, bounded.directories);
            let provider = Provider::parse_for(profile, &docs[2].bytes, &selected).unwrap();
            assert_eq!((&provider.profile[..], &provider.target[..]), (os_profile, target));
            assert_eq!(provider.files, Provider::parse_bounded_for(profile, &docs[2].bytes, &selected, 1024*1024).unwrap().files);
            let record = Registration::parse_for(profile, &docs[1].bytes, 501, &selected.instance).unwrap();
            assert_eq!((&record.profile[..], &record.target[..]), (toolchain, target));
            assert_eq!(Some(record.clone()), Registration::parse_bounded_for(profile, &docs[1].bytes, 501, &selected.instance, 1024*1024));
            assert!(record.matches_for(profile, &selected));
            let other = if profile == Profile::MacArm64 { Profile::MacX64 } else { Profile::MacArm64 };
            assert!(!record.matches_for(other, &selected));
            assert!(!parsed.matches_profile(other));
            let arm = profile == Profile::MacArm64;
            assert_eq!(parse_manifest(&docs[0].bytes, &selected).is_some(), arm);
            assert_eq!(parse_manifest_bounded(&docs[0].bytes, &selected, 32*1024*1024).is_some(), arm);
            assert_eq!(Provider::parse(&docs[2].bytes, &selected).is_some(), arm);
            assert_eq!(Provider::parse_bounded(&docs[2].bytes, &selected, 1024*1024).is_some(), arm);
            assert_eq!(Registration::parse(&docs[1].bytes, 501, &selected.instance).is_some(), arm);
            assert_eq!(Registration::parse_bounded(&docs[1].bytes, 501, &selected.instance, 1024*1024).is_some(), arm);
            assert_eq!(record.matches(&selected), arm);
            for selector in [profile, Profile::LinuxX64] {
                assert!(parse_manifest_bounded_for(selector, &docs[0].bytes, &selected, 0).is_none());
                assert!(Provider::parse_bounded_for(selector, &docs[2].bytes, &selected, 0).is_none());
                assert!(Registration::parse_bounded_for(selector, &docs[1].bytes, 501, &selected.instance, 0).is_none());
            }
            assert!(parse_manifest_for(Profile::LinuxX64, &docs[0].bytes, &selected).is_none());
            assert!(Provider::parse_for(Profile::LinuxX64, &docs[2].bytes, &selected).is_none());
            assert!(Registration::parse_for(Profile::LinuxX64, &docs[1].bytes, 501, &selected.instance).is_none());
            assert!(!record.matches_for(Profile::LinuxX64, &selected));
            assert!(proposal_inventory_for(Profile::LinuxX64, paired_fields(), &selected.instance, &selected.os_provider_sha256).is_none());
            assert!(proposal_provider_for(Profile::LinuxX64, paired_os_files()).is_none());
            assert!(encode_registration_proposal_for(Profile::LinuxX64, 501, &selected.instance,
                &selected.inventory_sha256, &selected.os_provider_sha256).is_none());
            let mut appended = docs[0].bytes.clone(); appended.push(b'\n');
            assert!(parse_manifest_for(profile, &appended, &selected).is_none());
            assert!(parse_manifest_bounded_for(profile, &appended, &selected, 32*1024*1024).is_none());
            let mut appended = docs[2].bytes.clone(); appended.push(b'\n');
            assert!(Provider::parse_for(profile, &appended, &selected).is_none());
            assert!(Provider::parse_bounded_for(profile, &appended, &selected, 1024*1024).is_none());
            assert!(Registration::parse_for(profile, &docs[1].bytes, 502, &selected.instance).is_none());
            assert!(encode_registration_proposal_for(profile, 0, &selected.instance,
                &selected.inventory_sha256, &selected.os_provider_sha256).is_none());
            let mut fields = paired_fields(); fields.files[0].mode = 0o777;
            assert!(proposal_inventory_for(profile, fields, &selected.instance, &selected.os_provider_sha256).is_none());
        }
    }
    pub(super) fn paired_policy_refuses_rehashed_cross_target_and_invalid_documents_data() {
        for (profile, other, opposite_toolchain, opposite_target, opposite_launch, opposite_os) in [
            (Profile::MacArm64, Profile::MacX64, "android-registered-macos-x86_64-v1", "macos-x86_64",
             "gradle-macos-private-jvm-x86_64-v1", "macos26-x86_64-sealed-system-v1"),
            (Profile::MacX64, Profile::MacArm64, "android-registered-macos-arm64-v1", "macos-arm64",
             "gradle-macos-private-jvm-arm64-v1", "macos26-arm64-sealed-system-v1"),
        ] {
            let (selected, docs) = paired_documents(profile);
            let values: [Value; 3] = std::array::from_fn(|index| serde_json::from_slice(&docs[index].bytes).unwrap());
            for (document, key, opposite) in [(0, "profile", opposite_toolchain), (0, "target", opposite_target),
                (0, "launchContract", opposite_launch), (1, "profile", opposite_toolchain), (1, "target", opposite_target),
                (2, "profile", opposite_os), (2, "target", opposite_target)] {
                for replacement in [opposite, "unknown-profile-data"] {
                    let mut changed = values.clone(); changed[document][key] = json!(replacement);
                    let provider = serde_json::to_vec(&changed[2]).unwrap();
                    let mut anchored = selected.clone(); anchored.os_provider_sha256 = digest(&provider);
                    changed[0]["osProviderSha256"] = json!(anchored.os_provider_sha256);
                    let manifest = serde_json::to_vec(&changed[0]).unwrap(); anchored.inventory_sha256 = digest(&manifest);
                    changed[1]["inventorySha256"] = json!(anchored.inventory_sha256);
                    changed[1]["osProviderSha256"] = json!(anchored.os_provider_sha256);
                    let record = serde_json::to_vec(&changed[1]).unwrap(); anchored.record_sha256 = digest(&record);
                    // Every complete raw anchor has been recomputed. Refusal must prove pairing.
                    assert_eq!(digest(&manifest), anchored.inventory_sha256);
                    assert_eq!(digest(&provider), anchored.os_provider_sha256);
                    assert_eq!(digest(&record), anchored.record_sha256);
                    match document {
                        0 => {
                            assert!(parse_manifest_for(profile, &manifest, &anchored).is_none());
                            assert!(parse_manifest_bounded_for(profile, &manifest, &anchored, 32*1024*1024).is_none());
                        }
                        1 => {
                            assert!(Registration::parse_for(profile, &record, 501, &anchored.instance).is_none());
                            assert!(Registration::parse_bounded_for(profile, &record, 501, &anchored.instance, 1024*1024).is_none());
                        }
                        2 => {
                            assert!(Provider::parse_for(profile, &provider, &anchored).is_none());
                            assert!(Provider::parse_bounded_for(profile, &provider, &anchored, 1024*1024).is_none());
                        }
                        _ => unreachable!(),
                    }
                }
            }
            let (foreign, opposite) = paired_documents(other);
            assert!(parse_manifest_for(profile, &opposite[0].bytes, &foreign).is_none());
            assert!(Provider::parse_for(profile, &opposite[2].bytes, &foreign).is_none());
            assert!(Registration::parse_for(profile, &opposite[1].bytes, 501, &foreign.instance).is_none());
            let mut schema = values[0].clone(); schema["schemaVersion"] = json!(2);
            let raw = serde_json::to_vec(&schema).unwrap(); let mut anchored = selected.clone(); anchored.inventory_sha256 = digest(&raw);
            assert!(parse_manifest_for(profile, &raw, &anchored).is_none());
            assert!(parse_manifest_bounded_for(profile, &raw, &anchored, 32*1024*1024).is_none());
            let mut unlicensed = values[1].clone(); unlicensed["licenseAcknowledged"] = json!(false);
            let raw = serde_json::to_vec(&unlicensed).unwrap();
            assert!(Registration::parse_for(profile, &raw, 501, &selected.instance).is_none());
            assert!(Registration::parse_bounded_for(profile, &raw, 501, &selected.instance, 1024*1024).is_none());
        }
    }
    pub(super) fn intel_document_data_never_borrows_arm_native_role_authority_data() {
        assert!(native_catalog_supports(Profile::MacArm64));
        assert!(!native_catalog_supports(Profile::MacX64));
        assert!(!native_catalog_supports(Profile::LinuxX64));
        let (arm, arm_docs) = paired_documents(Profile::MacArm64);
        let arm_inventory = parse_manifest(&arm_docs[0].bytes, &arm).unwrap();
        let (intel, intel_docs) = paired_documents(Profile::MacX64);
        let intel_inventory = parse_manifest_for(Profile::MacX64, &intel_docs[0].bytes, &intel).unwrap();
        let mut commands = MachCommands { architecture: MachArchitecture::Arm64, file_type: 2,
            header_sha256: "e".repeat(64), install_name: None, loads: vec![], rpaths: vec![] };
        assert!(local_loads(AAPT2, &commands, &arm_inventory));
        for architecture in [MachArchitecture::Arm64, MachArchitecture::X86_64] {
            commands.architecture = architecture;
            for path in [AAPT2, "jdk/Test.jdk/Contents/Home/bin/java", Sdk35File::LldIntel.pin().path] {
                assert!(!local_loads(path, &commands, &intel_inventory));
            }
        }
        // Even exact existing ARM JDK DATA cannot be relabeled as Intel authority.
        let (mut selected, mut value) = exact_jdk_value();
        value["profile"] = json!("android-registered-macos-x86_64-v1");
        value["target"] = json!("macos-x86_64");
        value["launchContract"] = json!("gradle-macos-private-jvm-x86_64-v1");
        let raw = serde_json::to_vec(&value).unwrap(); selected.inventory_sha256 = digest(&raw);
        let data = parse_manifest_for(Profile::MacX64, &raw, &selected).unwrap();
        let pin = crate::android_native_macos_profile::jdk_native("Contents/Home/lib/libjava.dylib").unwrap();
        assert!(!local_loads("jdk/Test.jdk/Contents/Home/lib/libjava.dylib", &expected_jdk_commands(pin), &data));
    }
    #[test]
    fn paired_policy_roundtrips_preserve_arm_defaults_and_bounds() {
        paired_policy_roundtrips_preserve_arm_defaults_and_bounds_data();
    }
    #[test]
    fn paired_policy_refuses_rehashed_cross_target_and_invalid_documents() {
        paired_policy_refuses_rehashed_cross_target_and_invalid_documents_data();
    }
    #[test]
    fn intel_document_data_never_borrows_arm_native_role_authority() {
        intel_document_data_never_borrows_arm_native_role_authority_data();
    }

}

// Explicit harness=false DATA bridge; ordinary libtest wrappers use these same
// inert bodies. No native custody, task, Prepare/Start or qualification is granted.
#[cfg(test)]
pub(crate) fn assert_macos_toolchain_policy_data_contract() {
    tests::paired_policy_roundtrips_preserve_arm_defaults_and_bounds_data();
    tests::paired_policy_refuses_rehashed_cross_target_and_invalid_documents_data();
    tests::intel_document_data_never_borrows_arm_native_role_authority_data();
    tests::proposal_tree_budget_preserves_live_roots_and_overflow_data();
    tests::closed_mac_roles_membership_and_selected_hashes_are_required_data();
    tests::aliases_cannot_escape_change_bundles_or_point_to_another_alias_data();
    tests::registration_and_os_provider_are_closed_and_account_bound_data();
    tests::universal_architecture_table_may_be_unsorted_but_never_overlapping_or_intel_only_data();
    tests::lazy_load_paths_are_parsed_and_loader_environment_commands_refused_data();
    tests::dyld_search_never_ignores_unprotected_roots_or_assumes_inherited_rpaths_data();
    tests::canonical_proposals_reuse_raw_parser_contract_data();
    tests::canonical_encoder_refuses_limits_and_second_pass_drift_data();
    tests::bounded_helper_parser_keeps_one_schema_authority_data();
    tests::bounded_tokens_and_vectors_refuse_before_unbounded_growth_data();
    tests::sdk_original_scripts_and_legacy_native_roles_are_separate_data();
    tests::jdk_post_jli_is_finite_and_never_bootstrap_or_cross_component_data();
    tests::finite_target_elf_and_foreign_launcher_never_become_host_providers_data();
}
