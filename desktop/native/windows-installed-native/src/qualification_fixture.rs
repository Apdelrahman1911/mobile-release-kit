//! Closed cfg(test) protected-fixture prerequisite operations. Never product APIs.
//! Original files and borrowed native arenas remain jointly reachable on Unknown.
use super::*;
use super::qualification_result::*;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

pub(super) const PROFILE: &str = "windows-installed-fullwalk-v1";
pub(super) const DISPATCH: &str = "windows-installed-fullwalk";
pub(super) const PRODUCTION_PROFILE: &str = "windows-runtime-publication-v1";
pub(super) const PRODUCTION_DISPATCH: &str = "windows-runtime-publication";
pub(super) const PASSIVE_PROFILE: &str = "windows-installed-passive-v1";
pub(super) const PASSIVE_DISPATCH: &str = "windows-installed-passive";
pub(super) const PASSIVE_STAGE: &str = "qualification_fixture::hosted_stage_passive_runtime_input";
pub(super) const PASSIVE_OBSERVE: &str = "qualification_fixture::hosted_observe_passive_published_version";
pub(super) const PASSIVE_PRECHECK_FILE: &str = "passive-headless-precheck.private.txt";
pub(super) const PASSIVE_STAGE_FILE: &str = "passive-stage-result.private.txt";
pub(super) const PASSIVE_OBSERVATION_FILE: &str = "passive-publication-observation.private.txt";
pub(super) const PASSIVE_PRECHECK_HEADER: &str = "MRK_WINDOWS_INSTALLED_PASSIVE_PRECHECK_V1";
pub(super) const PASSIVE_OBSERVATION_HEADER: &str = "MRK_WINDOWS_INSTALLED_PASSIVE_SETUP_OBSERVATION_V1";
pub(super) const PASSIVE_SETUP_EXIT_HEADER: &str = "MRK_WINDOWS_INSTALLED_PASSIVE_SETUP_EXIT_V1";
pub(super) const STAGE_INPUT: &str = "qualification_fixture::hosted_stage_fixed_runtime_input";
pub(super) const OBSERVE_BEFORE: &str = "qualification_fixture::hosted_observe_produced_version_before_collision";
pub(super) const OBSERVE_AFTER: &str = "qualification_fixture::hosted_compare_after_occupied_producer";
pub(super) const STAGE_FILE: &str = "producer-stage-result.private.txt";
pub(super) const BEFORE_FILE: &str = "producer-before-result.private.txt";
pub(super) const PRODUCTION_PRECHECK_HEADER: &str = "MRK_WINDOWS_RUNTIME_PUBLICATION_PRECHECK_V1";
pub(super) const HELPER_FIELDS: [&str; 9] = ["helperArtifact", "helperArtifactBytes", "helperArtifactSha256",
    "helperArtifactIdentity", "helperCompileMessagesBytes", "helperCompileMessagesSha256", "helperCompileArgvSha256",
    "helperCommandSha256", "helperNativeFeatures"];
pub(super) const PRODUCER_EXIT_HEADER: &str = "MRK_WINDOWS_RUNTIME_PUBLICATION_ORIGINAL_EXIT_V1";
pub(super) const PRODUCER_EXIT_FIELDS: [&str; 12] = ["profile", "sourceSha", "sourceTree", "runId", "attempt",
    "role", "artifactSha256", "precheckSha256", "commandSha256", "originalWaitReturned", "exitCode", "writerCloseGate"];
pub(super) const OBSERVATION_HEADER: &str = "MRK_WINDOWS_RUNTIME_PUBLICATION_OBSERVATION_V1";
pub(super) const OBSERVATION_FIELDS: [&str; 33] = ["profile", "sourceSha", "sourceTree", "runId", "attempt",
    "observerTest", "artifactBytes", "artifactSha256", "artifactIdentity", "precheckBytes", "precheckSha256",
    "rosterBytes", "rosterSha256", "manifestSha256", "protocolSha256", "inventorySha256", "coreSha256",
    "payloadFiles", "payloadBytes", "objectCount", "sourceReaders", "payloadWriters", "postcheckReaders",
    "fileOriginals", "fileOriginalsClosed", "parentBookSettled", "unknown", "actualFixedProducerObserved",
    "runtimeConsumerEnabled", "pythonExecuted", "appLaunched", "resultCloseGate", "proofCount"];
const SOURCE_DIRECTORY_ROLES: [&str; 4] = ["source-input", "source-target", "source-version", "source-python"];
pub(super) const PRODUCER_PROOFS: [(&str, &str, usize); 6] = [
    ("stage", STAGE_FILE, OWNER_LIMIT), ("stageExit", "producer-stage-exit.private.txt", LIMIT),
    ("helperSuccessExit", "producer-success-exit.private.txt", LIMIT), ("before", BEFORE_FILE, OWNER_LIMIT),
    ("beforeExit", "producer-before-exit.private.txt", LIMIT), ("helperOccupiedExit", "producer-occupied-exit.private.txt", LIMIT),
];
pub(super) const PASSIVE_SETUP_PROOFS: [(&str, &str, usize); 3] = [
    ("stage", PASSIVE_STAGE_FILE, OWNER_LIMIT), ("stageExit", "passive-stage-exit.private.txt", LIMIT),
    ("helperSuccessExit", "passive-publisher-exit.private.txt", LIMIT),
];
pub(super) const PUBLISHER: &str = "qualification_fixture::hosted_publish_protected_version_fixture";
pub(super) const RETIRE: &str = "qualification_fixture::hosted_retire_protected_version_fixture";
pub(super) const ORDINARY_OWNER: &str = "ordinary_owner::hosted_ordinary_original_handle_contract";
pub(super) const ORDINARY_CHILD: &str = "hosted_tests::hosted_native_read_only_contract";
pub(super) const PRECHECK_FILE: &str = "fullwalk-headless-precheck.private.txt";
pub(super) const ROSTER_FILE: &str = "fullwalk-fixture-roster.private.txt";
pub(super) const PUBLICATION_FILE: &str = "fullwalk-publisher-result.private.txt";
pub(super) const PUBLICATION_EXIT: &str = "fullwalk-publisher-exit.private.json";
pub(super) const FINALITY_FILE: &str = "fullwalk-ordinary-finality.private.txt";
pub(super) const PREREQUISITE_FILE: &str = "fullwalk-publication.private.txt";
pub(super) const TEXT_LIMIT: usize = 16 << 10;
const PAYLOAD_LIMIT: usize = 128 << 20;
const DIRECTORY_ROLES: [&str; 5] = ["suffix-mrk", "suffix-versions", "suffix-target", "version", "python"];
const SELECTED: [&str; 3] = ["python/python.exe", "engine_bootstrap.py", "core.zip"];

pub(super) const PAYLOAD_NAMES: [&str; 47] = [
    "android_build_bootstrap.py",
    "config_edit_bootstrap.py",
    "core.zip",
    "engine_bootstrap.py",
    "environment_bootstrap.py",
    "github-ca.pem",
    "github_connection_bootstrap.py",
    "manifest.json",
    "offline_preflight_bootstrap.py",
    "python/LICENSE.txt",
    "python/MRK-EMBEDDED-NOTICES.txt",
    "python/_asyncio.pyd",
    "python/_bz2.pyd",
    "python/_ctypes.pyd",
    "python/_decimal.pyd",
    "python/_elementtree.pyd",
    "python/_hashlib.pyd",
    "python/_lzma.pyd",
    "python/_multiprocessing.pyd",
    "python/_overlapped.pyd",
    "python/_queue.pyd",
    "python/_remote_debugging.pyd",
    "python/_socket.pyd",
    "python/_sqlite3.pyd",
    "python/_ssl.pyd",
    "python/_uuid.pyd",
    "python/_wmi.pyd",
    "python/_zoneinfo.pyd",
    "python/_zstd.pyd",
    "python/libcrypto-3.dll",
    "python/libffi-8.dll",
    "python/libssl-3.dll",
    "python/libtommath.dll",
    "python/pyexpat.pyd",
    "python/python.cat",
    "python/python.exe",
    "python/python3.dll",
    "python/python314._pth",
    "python/python314.dll",
    "python/python314.zip",
    "python/pythonw.exe",
    "python/select.pyd",
    "python/sqlite3.dll",
    "python/unicodedata.pyd",
    "python/vcruntime140.dll",
    "python/vcruntime140_1.dll",
    "python/winsound.pyd",
];

pub(super) const PRECHECK_FIELDS: [&str; 47] = [
    "profile",
    "sourceSha",
    "sourceTree",
    "runId",
    "attempt",
    "sourceInventorySha256",
    "readerSourceSha256",
    "runtimeSourceSha256",
    "buildSourceSha256",
    "nativeResultSourceSha256",
    "appTest",
    "appArtifact",
    "appArtifactBytes",
    "appArtifactSha256",
    "appArtifactIdentity",
    "appCommandSha256",
    "appCompileMessagesBytes",
    "appCompileMessagesSha256",
    "appCompileArgvSha256",
    "ownerArtifact",
    "ownerArtifactBytes",
    "ownerArtifactSha256",
    "ownerArtifactIdentity",
    "ownerCompileMessagesBytes",
    "ownerCompileMessagesSha256",
    "ownerCompileArgvSha256",
    "publisherTest",
    "publisherCommandSha256",
    "fullwalkOwnerTest",
    "fullwalkOwnerCommandSha256",
    "ordinaryOwnerTest",
    "ordinaryOwnerCommandSha256",
    "ordinaryChildCommandSha256",
    "appRootFeatures",
    "standaloneFeatures",
    "appNativeDevFeatures",
    "manifestSha256",
    "protocolSha256",
    "inventorySha256",
    "coreSha256",
    "payloadFiles",
    "payloadBytes",
    "preparedReceiptBytes",
    "preparedReceiptSha256",
    "rosterBytes",
    "rosterSha256",
    "headlessContract",
];
pub(super) const PRECHECK_HEADER: &str = "MRK_WINDOWS_FULLWALK_HEADLESS_PRECHECK_V1";
pub(super) fn passive_precheck_fields() -> Vec<&'static str> {
    let mut fields = PRECHECK_FIELDS[..26].to_vec();
    fields.extend(["stageTest", "stageCommandSha256", "observerTest", "observerCommandSha256", "ownerTest", "ownerCommandSha256"]);
    fields.extend_from_slice(&PRECHECK_FIELDS[33..]);
    fields.extend(HELPER_FIELDS);
    fields
}

pub(super) const PUBLICATION_FIELDS: [&str; 37] = [
    "profile",
    "sourceSha",
    "sourceTree",
    "runId",
    "attempt",
    "publisherTest",
    "artifactBytes",
    "artifactSha256",
    "artifactIdentity",
    "precheckBytes",
    "precheckSha256",
    "rosterBytes",
    "rosterSha256",
    "manifestSha256",
    "protocolSha256",
    "inventorySha256",
    "coreSha256",
    "payloadFiles",
    "payloadBytes",
    "createdFiles",
    "createdDirectories",
    "sourceReaders",
    "sourceReadersClosed",
    "payloadWriters",
    "payloadWritersClosed",
    "postcheckReaders",
    "postcheckReadersClosed",
    "fileOriginals",
    "fileOriginalsClosed",
    "parentBookSettled",
    "occupiedCreateCalls",
    "occupiedCreateError",
    "occupiedObjectsUnchanged",
    "unknown",
    "productionEnabled",
    "resultCloseGate",
    "objectCount",
];
pub(super) const PUBLICATION_HEADER: &str = "MRK_WINDOWS_FULLWALK_PUBLISHER_RESULT_V1";

pub(super) const FINALITY_FIELDS: [&str; 32] = [
    "profile",
    "sourceSha",
    "sourceTree",
    "runId",
    "attempt",
    "ordinaryOwnerTest",
    "ordinaryChildTest",
    "artifactBytes",
    "artifactSha256",
    "artifactBeforeIdentity",
    "artifactAfterIdentity",
    "ordinaryRequestBytes",
    "ordinaryRequestSha256",
    "ordinaryIntentBytes",
    "ordinaryIntentSha256",
    "ordinaryOwnerResultBytes",
    "ordinaryOwnerResultSha256",
    "ordinaryChildResultBytes",
    "ordinaryChildResultSha256",
    "ordinaryOwnerExitBytes",
    "ordinaryOwnerExitSha256",
    "ordinaryInvocationSha256",
    "originTickMs",
    "deadlineTickMs",
    "aggregateBudgetMs",
    "ordinaryResultPrewriteTickMs",
    "originalInputCount",
    "ownerStepOutcome",
    "ownerOriginalExitCode",
    "childOriginalExitCode",
    "accountRemovedAfterSettlement",
    "finalizerCloseGate",
];
pub(super) const FINALITY_HEADER: &str = "MRK_WINDOWS_FULLWALK_ORDINARY_FINALITY_V1";

pub(super) const PREREQUISITE_FIELDS: [&str; 44] = [
    "profile",
    "sourceSha",
    "sourceTree",
    "runId",
    "attempt",
    "precheckBytes",
    "precheckSha256",
    "rosterBytes",
    "rosterSha256",
    "publisherReceiptBytes",
    "publisherReceiptSha256",
    "publisherExitBytes",
    "publisherExitSha256",
    "ordinaryRequestBytes",
    "ordinaryRequestSha256",
    "ordinaryIntentBytes",
    "ordinaryIntentSha256",
    "ordinaryOwnerResultBytes",
    "ordinaryOwnerResultSha256",
    "ordinaryOwnerExitBytes",
    "ordinaryOwnerExitSha256",
    "ordinaryFinalityBytes",
    "ordinaryFinalitySha256",
    "ordinaryInvocationSha256",
    "originTickMs",
    "deadlineTickMs",
    "aggregateBudgetMs",
    "ownerArtifactAfterOrdinaryIdentity",
    "manifestSha256",
    "protocolSha256",
    "inventorySha256",
    "coreSha256",
    "payloadFiles",
    "payloadBytes",
    "versionIdentity",
    "selectedPythonIdentity",
    "selectedBootstrapIdentity",
    "selectedCoreIdentity",
    "publisherStepOutcome",
    "publisherFinalizeStepOutcome",
    "ordinaryOwnerStepOutcome",
    "ordinaryFinalizeStepOutcome",
    "prerequisitesOnlyNotNativeWalk",
    "envelopeCloseGate",
];
pub(super) const PREREQUISITE_HEADER: &str = "MRK_WINDOWS_FULLWALK_PREREQUISITES_V1";

pub(super) const INVOCATION_FIELDS: [&str; 14] = [
    "profile",
    "sourceSha",
    "sourceTree",
    "runId",
    "attempt",
    "ordinaryOwnerTest",
    "artifactBytes",
    "artifactSha256",
    "artifactBeforeIdentity",
    "ordinaryChildCommandSha256",
    "ordinaryRequestSha256",
    "originTickMs",
    "aggregateBudgetMs",
    "deadlineTickMs",
];
pub(super) const INVOCATION_HEADER: &str = "MRK_WINDOWS_FULLWALK_OWNER_INVOCATION_V1";



#[derive(Clone, Debug)]
pub(super) struct Wire { pub values: BTreeMap<String, String> }
impl Wire {
    pub fn parse(raw: &[u8], header: &str, keys: &[&str], limit: usize) -> Result<Self> {
        need(!raw.is_empty() && raw.len() <= limit && raw.is_ascii() && raw.ends_with(b"\n")
            && raw.iter().all(|b| *b == b'\n' || (b' '..=b'~').contains(b)))?;
        let text = std::str::from_utf8(raw).map_err(|_| Error::Unsafe)?;
        let lines: Vec<_> = text[..text.len()-1].split('\n').collect();
        need(lines.len() == keys.len()+1 && lines[0] == header)?;
        let mut values = BTreeMap::new();
        for (line, key) in lines[1..].iter().zip(keys) {
            let (name, value) = line.split_once('=').ok_or(Error::Unsafe)?;
            need(name == *key && !value.is_empty() && !value.contains('='))?;
            if key.ends_with("Sha256") { need(is_hex(value, 64))?; }
            if matches!(*key, "sourceSha" | "sourceTree") { need(is_hex(value, 40) && value != "0".repeat(40))?; }
            need(values.insert(name.to_owned(), value.to_owned()).is_none())?;
        }
        Ok(Self { values })
    }
    pub fn get(&self, key: &str) -> Result<&str> { self.values.get(key).map(String::as_str).ok_or(Error::Unsafe) }
    pub fn number(&self, key: &str, ceiling: u64) -> Result<u64> { number(self.get(key)?, ceiling) }
    pub fn equal(&self, key: &str, value: &str) -> Result<()> { need(self.get(key)? == value) }
    pub fn binding(&self) -> Result<()> {
        self.equal("profile", active_profile()?)?;
        self.equal("sourceSha", option_env!("GITHUB_SHA").ok_or(Error::State)?)?;
        self.equal("sourceTree", option_env!("MRK_WINDOWS_SOURCE_TREE").ok_or(Error::State)?)?;
        self.equal("runId", option_env!("GITHUB_RUN_ID").ok_or(Error::State)?)?;
        self.equal("attempt", "1")?;
        need(decimal(self.get("runId")?))?;
        need(std::env::var("GITHUB_RUN_ID").as_deref()==Ok(self.get("runId")?)
            && std::env::var("MRK_WINDOWS_SOURCE_TREE").as_deref()==Ok(self.get("sourceTree")?))?;
        Ok(())
    }
    pub fn encoded(&self, header: &str, keys: &[&str], limit: usize) -> Result<Vec<u8>> {
        need(self.values.len() == keys.len())?;
        let mut out = format!("{header}\n");
        for key in keys { out.push_str(&format!("{key}={}\n", self.get(key)?)); }
        Self::parse(out.as_bytes(), header, keys, limit)?;
        Ok(out.into_bytes())
    }
    pub fn put(&mut self, key: &str, value: impl ToString) { self.values.insert(key.to_owned(), value.to_string()); }
    pub fn copy(&mut self, other: &Self, keys: &[&str]) -> Result<()> {
        for key in keys { self.put(key, other.get(key)?); }
        Ok(())
    }
}
pub(super) fn number(value: &str, ceiling: u64) -> Result<u64> {
    need(!value.is_empty() && value.len() <= 20 && value.bytes().all(|b| b.is_ascii_digit())
        && (value == "0" || !value.starts_with('0')))?;
    let result = value.parse::<u64>().map_err(|_| Error::Unsafe)?;
    need(result <= ceiling)?; Ok(result)
}
pub(super) fn command_sha(path: &str, test: &str) -> Result<String> {
    let command = format!("\"{path}\" {test} {}", FLAGS.join(" "));
    need(command.encode_utf16().count() <= 1023)?;
    digest(&command.encode_utf16().flat_map(u16::to_le_bytes).collect::<Vec<_>>())
}
pub(super) fn profile() -> Result<()> {
    super::hosted_tests::hosted_source()?;
    let dispatch=std::env::var("MRK_DESKTOP_DISPATCH_SCOPE").map_err(|_|Error::State)?;
    let reference=std::env::var("GITHUB_REF").map_err(|_|Error::State)?;
    need(profile_route(&dispatch,&reference)?==active_profile()?)?;
    for (key, value) in [
        ("GITHUB_EVENT_NAME", "workflow_dispatch"),
        ("GITHUB_JOB", "windows-installed-native"),
        ("MRK_DESKTOP_EXPECTED_SHA", option_env!("GITHUB_SHA").ok_or(Error::State)?),
        ("GITHUB_WORKFLOW_SHA", option_env!("GITHUB_SHA").ok_or(Error::State)?),
    ] { need(std::env::var(key).as_deref() == Ok(value))?; }
    Ok(())
}
pub(super) fn profile_route(dispatch:&str,reference:&str) -> Result<&'static str> {
    match (dispatch,reference) {
        (DISPATCH,"refs/heads/verify/desktop-windows-installed-native")=>Ok(PROFILE),
        (PRODUCTION_DISPATCH,"refs/heads/verify/desktop-windows-runtime-publication")=>Ok(PRODUCTION_PROFILE),
        (PASSIVE_DISPATCH,"refs/heads/verify/desktop-windows-installed-passive")=>Ok(PASSIVE_PROFILE),
        _=>Err(Error::Unsafe),
    }
}
pub(super) fn active_profile() -> Result<&'static str> {
    match std::env::var("MRK_DESKTOP_DISPATCH_SCOPE").as_deref() {
        Ok(DISPATCH) => Ok(PROFILE), Ok(PRODUCTION_DISPATCH) => Ok(PRODUCTION_PROFILE),
        Ok(PASSIVE_DISPATCH) => Ok(PASSIVE_PROFILE), _ => Err(Error::Unsafe),
    }
}
fn precheck_fields(production: bool) -> Vec<&'static str> {
    let mut fields = PRECHECK_FIELDS.to_vec();
    if production { fields.extend(HELPER_FIELDS); }
    fields
}
pub(super) const PRODUCTION_PREREQUISITE_HEADER: &str = "MRK_WINDOWS_RUNTIME_PUBLICATION_PREREQUISITES_V1";
fn prerequisite_fields(production: bool) -> Vec<String> {
    let mut fields: Vec<_> = PREREQUISITE_FIELDS.iter().map(|s| (*s).to_owned()).collect();
    if production {
        for (role,_,_) in PRODUCER_PROOFS {
            fields.push(format!("{role}Bytes")); fields.push(format!("{role}Sha256"));
        }
    }
    fields
}
pub(super) fn outcome(key: &str) -> Result<()> { need(std::env::var(key).as_deref() == Ok("success")) }
pub(super) fn precheck(raw: &[u8], root: &Path) -> Result<Wire> {
    if active_profile()? == PASSIVE_PROFILE { return passive_precheck(raw, root); }
    let production = active_profile()? == PRODUCTION_PROFILE;
    let value = Wire::parse(raw, if production {PRODUCTION_PRECHECK_HEADER} else {PRECHECK_HEADER}, &precheck_fields(production), TEXT_LIMIT)?;
    value.binding()?;
    for (key, expected) in [
        ("appTest", FULLWALK_CHILD), ("publisherTest", if production {OBSERVE_AFTER} else {PUBLISHER}), ("fullwalkOwnerTest", FULLWALK_OWNER),
        ("ordinaryOwnerTest", ORDINARY_OWNER), ("appRootFeatures", if production {"windows-runtime-publisher"} else {"none"}),
        ("standaloneFeatures", if production {"runtime-publication"} else {"none"}),
        ("appNativeDevFeatures", if production {"qualification-result,runtime-publication"} else {"qualification-result"}),
        ("headlessContract", "fixed-version-inspect-settle-no-descendants-v1"),
        ("manifestSha256", option_env!("MRK_BUNDLED_RUNTIME_MANIFEST_SHA256").ok_or(Error::State)?),
        ("protocolSha256", option_env!("MRK_BUNDLED_PROTOCOL_SHA256").ok_or(Error::State)?),
    ] { value.equal(key, expected)?; }
    for (role, name, ceiling) in [("app", "mobile_release_desktop-", APP_ARTIFACT_LIMIT),
                                ("owner", "mrk_windows_installed_native-", PAYLOAD_LIMIT)] {
        let path = fixed_path(value.get(&format!("{role}Artifact"))?)?;
        need(path.parent() == Some(fixed_directories(root)[3].1.as_path()))?;
        let leaf = path.file_name().and_then(|s| s.to_str()).ok_or(Error::Unsafe)?;
        need(leaf.strip_prefix(name).and_then(|s| s.strip_suffix(".exe")).is_some_and(|s| is_hex(s,16)))?;
        original_epoch(value.get(&format!("{role}ArtifactIdentity"))?,value.get(&format!("{role}ArtifactIdentity"))?)?;
        need(value.number(&format!("{role}ArtifactBytes"), ceiling as u64)? > 0)?;
        need(value.number(&format!("{role}CompileMessagesBytes"), 16 << 20)? > 0)?;
    }
    for (key, role, test) in [
        ("appCommandSha256", "appArtifact", FULLWALK_CHILD),
        ("publisherCommandSha256", "ownerArtifact", if production {OBSERVE_AFTER} else {PUBLISHER}),
        ("fullwalkOwnerCommandSha256", "ownerArtifact", FULLWALK_OWNER),
        ("ordinaryOwnerCommandSha256", "ownerArtifact", ORDINARY_OWNER),
        ("ordinaryChildCommandSha256", "ownerArtifact", ORDINARY_CHILD),
    ] { value.equal(key, &command_sha(value.get(role)?, test)?)?; }
    if production {
        let helper = fixed_path(value.get("helperArtifact")?)?;
        need(helper == root.join("mrk-windows-runtime-publish.exe"))?;
        original_epoch(value.get("helperArtifactIdentity")?,value.get("helperArtifactIdentity")?)?;
        need(value.number("helperArtifactBytes",PAYLOAD_LIMIT as u64)?>0
            && value.number("helperCompileMessagesBytes",16<<20)?>0)?;
        value.equal("helperNativeFeatures","runtime-publication")?;
        value.equal("helperCommandSha256",&digest(&format!("\"{}\"",value.get("helperArtifact")?)
            .encode_utf16().flat_map(u16::to_le_bytes).collect::<Vec<_>>())?)?;
    }
    need(value.number("payloadFiles", 2047)? == 46 && value.number("payloadBytes", 1 << 30)? > 0
        && value.number("preparedReceiptBytes", 4096)? > 0 && value.number("rosterBytes", TEXT_LIMIT as u64)? > 0)?;
    Ok(value)
}
fn passive_precheck(raw: &[u8], root: &Path) -> Result<Wire> {
    // Only the fresh setup/test lane. No publisher feature, legacy ordinary
    // preflight, collision replay or consumer activation is admitted here.
    need(!cfg!(feature = "runtime-publication") && !cfg!(feature = "qualification-result"))?;
    let value = Wire::parse(raw, PASSIVE_PRECHECK_HEADER, &passive_precheck_fields(), TEXT_LIMIT)?;
    value.binding()?;
    for (key, expected) in [
        ("appTest", PASSIVE_CHILD), ("stageTest", PASSIVE_STAGE), ("observerTest", PASSIVE_OBSERVE),
        ("ownerTest", PASSIVE_OWNER), ("appRootFeatures", "none"), ("standaloneFeatures", "none"),
        ("appNativeDevFeatures", "qualification-result"), ("helperNativeFeatures", "runtime-publication"),
        ("headlessContract", "fixed-installed-passive-original-owner-v1"),
        ("manifestSha256", option_env!("MRK_BUNDLED_RUNTIME_MANIFEST_SHA256").ok_or(Error::State)?),
        ("protocolSha256", option_env!("MRK_BUNDLED_PROTOCOL_SHA256").ok_or(Error::State)?),
    ] { value.equal(key, expected)?; }
    for (role, name, ceiling) in [("app", "mobile_release_desktop-", APP_ARTIFACT_LIMIT),
                                ("owner", "mrk_windows_installed_native-", PAYLOAD_LIMIT)] {
        let path = fixed_path(value.get(&format!("{role}Artifact"))?)?;
        need(path.parent() == Some(fixed_directories(root)[3].1.as_path()))?;
        let leaf = path.file_name().and_then(|s| s.to_str()).ok_or(Error::Unsafe)?;
        need(leaf.strip_prefix(name).and_then(|s| s.strip_suffix(".exe")).is_some_and(|s| is_hex(s, 16)))?;
        original_epoch(value.get(&format!("{role}ArtifactIdentity"))?, value.get(&format!("{role}ArtifactIdentity"))?)?;
        need(value.number(&format!("{role}ArtifactBytes"), ceiling as u64)? > 0
            && value.number(&format!("{role}CompileMessagesBytes"), 16 << 20)? > 0)?;
    }
    for (key, role, test) in [
        ("appCommandSha256", "appArtifact", PASSIVE_CHILD), ("stageCommandSha256", "ownerArtifact", PASSIVE_STAGE),
        ("observerCommandSha256", "ownerArtifact", PASSIVE_OBSERVE), ("ownerCommandSha256", "ownerArtifact", PASSIVE_OWNER),
    ] { value.equal(key, &command_sha(value.get(role)?, test)?)?; }
    let helper = fixed_path(value.get("helperArtifact")?)?;
    need(helper == root.join("mrk-windows-runtime-publish.exe"))?;
    original_epoch(value.get("helperArtifactIdentity")?, value.get("helperArtifactIdentity")?)?;
    need(value.number("helperArtifactBytes", PAYLOAD_LIMIT as u64)? > 0
        && value.number("helperCompileMessagesBytes", 16 << 20)? > 0)?;
    value.equal("helperCommandSha256", &digest(&format!("\"{}\"", value.get("helperArtifact")?)
        .encode_utf16().flat_map(u16::to_le_bytes).collect::<Vec<_>>())?)?;
    need(value.number("payloadFiles", 2047)? == 46 && value.number("payloadBytes", 1 << 30)? > 0
        && value.number("preparedReceiptBytes", 4096)? > 0 && value.number("rosterBytes", TEXT_LIMIT as u64)? > 0)?;
    Ok(value)
}
#[derive(Clone, Debug)]
pub(super) struct Payload { pub path: String, pub bytes: usize, pub sha: String }
pub(super) fn roster(raw: &[u8]) -> Result<Vec<Payload>> {
    need(!raw.is_empty() && raw.len() <= TEXT_LIMIT && raw.is_ascii() && raw.ends_with(b"\n")
        && !raw.contains(&b'\r'))?;
    let text = std::str::from_utf8(raw).map_err(|_| Error::Unsafe)?;
    let lines: Vec<_> = text[..text.len()-1].split('\n').collect();
    need(lines.len() == 48 && lines[0] == "MRK_WINDOWS_FULLWALK_ROSTER_V1")?;
    let mut result = Vec::with_capacity(47);
    let mut total = 0u64;
    for (line, expected) in lines[1..].iter().zip(PAYLOAD_NAMES) {
        let columns: Vec<_> = line.strip_prefix("file=").ok_or(Error::Unsafe)?.split('|').collect();
        need(columns.len() == 3 && columns[0] == expected && is_hex(columns[2],64))?;
        let bytes = number(columns[1], PAYLOAD_LIMIT as u64)?;
        need(bytes > 0)?;
        total = total.checked_add(bytes).ok_or(Error::Bounds)?;
        need(total <= 1 << 30)?;
        result.push(Payload { path: expected.to_owned(), bytes: bytes as usize, sha: columns[2].to_owned() });
    }
    Ok(result)
}
// Wire roster names use '/', but exact DOS-name checks require native spelling.
// Only the closed roster can contribute components to an already-admitted base.
pub(super) fn payload_path(base: &Path, name: &str) -> Result<PathBuf> {
    need(PAYLOAD_NAMES.contains(&name))?;
    let mut path = base.to_path_buf();
    for component in name.split('/') { path.push(component); }
    Ok(path)
}
pub(super) fn stamp_text(value: &Stamp) -> String {
    format!("{}:{}:{}:{}:{}:{}:{}:{}:{}", value.volume, hex(&value.id), value.creation,
        value.write, value.change, value.size, value.allocation, value.links, value.attributes)
}
pub(super) fn parse_stamp(value: &str) -> Result<Stamp> {
    let v: Vec<_> = value.split(':').collect();
    need(v.len()==9 && is_hex(v[1],32) && v[1] != "0".repeat(32))?;
    let signed = |s: &str| -> Result<i64> { Ok(number(s, i64::MAX as u64)? as i64) };
    let result = Stamp { volume: number(v[0],u64::MAX)?, id: unhex(v[1])?.try_into().map_err(|_|Error::Unsafe)?,
        creation:signed(v[2])?, write:signed(v[3])?, change:signed(v[4])?, size:signed(v[5])?,
        allocation:signed(v[6])?, links:number(v[7],u32::MAX as u64)? as u32,
        attributes:number(v[8],u32::MAX as u64)? as u32 };
    need(result.volume!=0 && result.links==1 && result.creation>0 && result.write>0 && result.change>0
        && result.attributes!=0 && result.attributes & FS::FILE_ATTRIBUTE_REPARSE_POINT == 0)?;
    Ok(result)
}
pub(super) fn same_object(a: &Stamp,b: &Stamp) -> bool {
    a.volume==b.volume && a.id==b.id && a.creation==b.creation && a.links==b.links && a.attributes==b.attributes
}
#[derive(Clone, Debug)]
pub(super) struct Object {
    pub role: String, pub directory: bool, pub created: Stamp, pub sealed: Stamp,
    pub initial_security: String, pub sealed_security: String, pub sha: String,
}
impl Object {
    fn line(&self) -> String {
        format!("object={}|{}|{}|{}|{}|{}|{}\n", self.role,
            if self.directory {"directory"} else {"file"},stamp_text(&self.created),stamp_text(&self.sealed),
            self.initial_security,self.sealed_security,self.sha)
    }
}
pub(super) fn publication(raw: &[u8], items: &[Payload]) -> Result<(Wire,Vec<Object>)> {
    need(!raw.is_empty() && raw.len()<=OWNER_LIMIT && raw.is_ascii() && raw.ends_with(b"\n") && !raw.contains(&b'\r'))?;
    let text=std::str::from_utf8(raw).map_err(|_|Error::Unsafe)?;
    let lines:Vec<_>=text[..text.len()-1].split('\n').collect();
    need(lines.len()==1+PUBLICATION_FIELDS.len()+52)?;
    let prefix=lines[..1+PUBLICATION_FIELDS.len()].join("\n")+"\n";
    let record=Wire::parse(prefix.as_bytes(),PUBLICATION_HEADER,&PUBLICATION_FIELDS,OWNER_LIMIT)?;
    record.binding()?;
    record.equal("profile",PROFILE)?; // legacy synthetic rows never qualify actual production
    for (key,value) in [("publisherTest",PUBLISHER),("createdFiles","47"),("createdDirectories","5"),
        ("payloadFiles","46"),("sourceReaders","47"),("sourceReadersClosed","47"),
        ("payloadWriters","47"),("payloadWritersClosed","47"),("postcheckReaders","94"),("postcheckReadersClosed","94"),
        ("parentBookSettled","true"),("occupiedCreateCalls","1"),("occupiedCreateError","183"),
        ("occupiedObjectsUnchanged","true"),("unknown","false"),("productionEnabled","false"),
        ("resultCloseGate","original-publisher-exit-zero-required"),("objectCount","52")] {record.equal(key,value)?;}
    need(items.len()==47 && record.number("fileOriginals",256)?>=198
        && record.get("fileOriginals")==record.get("fileOriginalsClosed"))?;
    let names:Vec<_>=DIRECTORY_ROLES.iter().copied().chain(items.iter().map(|p|p.path.as_str())).collect();
    let mut objects=Vec::with_capacity(52);let mut identities=BTreeSet::new();
    for (i,(line,name)) in lines[1+PUBLICATION_FIELDS.len()..].iter().zip(names).enumerate() {
        let v:Vec<_>=line.strip_prefix("object=").ok_or(Error::Unsafe)?.split('|').collect();
        need(v.len()==7 && v[0]==name && v[1]==(if i<5 {"directory"} else {"file"})
            && is_hex(v[4],64) && is_hex(v[5],64) && v[4]!=v[5])?;
        let created=parse_stamp(v[2])?;let sealed=parse_stamp(v[3])?;
        need(same_object(&created,&sealed) && sealed.write>=created.write && sealed.change>=created.change
            && (sealed.attributes & FS::FILE_ATTRIBUTE_DIRECTORY != 0)==(i<5)
            && identities.insert((sealed.volume,sealed.id)))?;
        if i<5 {need(v[6]=="-")?;}
        else {need(v[6]==items[i-5].sha && sealed.size==items[i-5].bytes as i64)?;}
        objects.push(Object {role:name.to_owned(),directory:i<5,created,sealed,
            initial_security:v[4].to_owned(),sealed_security:v[5].to_owned(),sha:v[6].to_owned()});
    }
    let volume=objects[0].sealed.volume;
    need(objects.iter().all(|o|o.sealed.volume==volume))?;
    Ok((record,objects))
}

// These are independent observations, NOT synthetic Object creation/seal
// receipts and NOT producer-owned HANDLEs carried across top-level processes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ObservedObject {
    pub role: String, pub directory: bool, pub stamp: Stamp, pub security: String,
    pub sha: String, pub inventory: String,
}
impl ObservedObject {
    fn line(&self) -> String {
        format!("observed={}|{}|{}|{}|{}|{}\n", self.role,
            if self.directory {"directory"} else {"file"},stamp_text(&self.stamp),self.security,self.sha,self.inventory)
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ProducerProof { pub role: String, pub bytes: usize, pub sha: String }
impl ProducerProof {
    fn line(&self) -> String {format!("proof={}|{}|{}\n",self.role,self.bytes,self.sha)}
    fn matches(&self,role:&str,raw:&[u8]) -> Result<()> {
        need(self.role==role && self.bytes==raw.len() && self.sha==digest(raw)?)
    }
}
pub(super) fn observation_roles(stage:bool) -> Vec<String> {
    let mut roles=vec![DIRECTORY_ROLES[0].to_owned()];
    roles.extend(SOURCE_DIRECTORY_ROLES.iter().map(|s|(*s).to_owned()));
    if !stage {roles.extend(DIRECTORY_ROLES[1..].iter().map(|s|(*s).to_owned()));}
    roles.extend(PAYLOAD_NAMES.iter().map(|s|format!("source/{s}")));
    if !stage {roles.extend(PAYLOAD_NAMES.iter().map(|s|(*s).to_owned()));}
    roles
}
fn observed<'a>(objects:&'a [ObservedObject],role:&str) -> Result<&'a ObservedObject> {
    objects.iter().find(|o|o.role==role).ok_or(Error::Unsafe)
}
fn child_rows(objects:&[ObservedObject],role:&str,manifest:&str,stage:bool) -> Result<BTreeMap<String,Stamp>> {
    let mut children=BTreeMap::new();
    let mut add=|name:&str,bound:&str| -> Result<()> {
        need(children.insert(name.to_owned(),observed(objects,bound)?.stamp.clone()).is_none())
    };
    match role {
        "suffix-mrk"=>{add("runtime-input","source-input")?;if !stage {add("versions","suffix-versions")?;}},
        "source-input"=>add("x86_64-pc-windows-msvc","source-target")?,
        "source-target"=>add(manifest,"source-version")?,
        "suffix-versions"=>add("x86_64-pc-windows-msvc","suffix-target")?,
        "suffix-target"=>add(manifest,"version")?,
        "source-version"|"source-python"|"version"|"python"=>{
            let source=role.starts_with("source-");let python=role.ends_with("python");
            if !python {add("python",if source {"source-python"}else{"python"})?;}
            for name in PAYLOAD_NAMES {
                let selected=if python {name.strip_prefix("python/")}else if !name.contains('/') {Some(name)}else{None};
                if let Some(leaf)=selected {add(leaf,&if source {format!("source/{name}")}else{name.to_owned()})?;}
            }
        },
        _=>return Err(Error::Unsafe),
    }
    Ok(children)
}
fn inventory_sha(children:&BTreeMap<String,Stamp>) -> Result<String> {
    // Complete non-dot inventory; actual dot rows, when returned, are separately
    // checked against the same original own/parent full identities.
    let mut raw=String::new();
    for (name,stamp) in children {
        need(decode::component(name))?;
        raw.push_str(&format!("{name}|{}|{}|{}\n",
            if stamp.attributes&FS::FILE_ATTRIBUTE_DIRECTORY!=0 {"directory"}else{"file"},hex(&stamp.id),stamp.attributes));
    }
    digest(raw.as_bytes())
}
pub(super) fn source_unchanged(stage:&[ObservedObject],before:&[ObservedObject]) -> Result<()> {
    need(stage.len()==52 && before.len()==103
        && stage.iter().map(|o|o.role.as_str()).eq(observation_roles(true).iter().map(String::as_str))
        && before.iter().map(|o|o.role.as_str()).eq(observation_roles(false).iter().map(String::as_str)))?;
    for original in stage {
        let current=observed(before,&original.role)?;
        if original.role=="suffix-mrk" {
            // The ONLY cross-process metadata exception: the intended fresh
            // versions child. Both inventories are separately closed/validated.
            need(original.directory && current.directory && child_change(&original.stamp,&current.stamp)
                && original.security==current.security && original.sha=="-" && current.sha=="-"
                && original.inventory!=current.inventory)?;
        }else {need(original==current)?;}
    }
    Ok(())
}
pub(super) fn observations_unchanged(before:&[ObservedObject],after:&[ObservedObject]) -> Result<()> {
    need(before.len()==103 && before==after
        && before.iter().map(|o|o.role.as_str()).eq(observation_roles(false).iter().map(String::as_str)))
}
pub(super) fn observation(raw:&[u8],items:&[Payload],test:&str) -> Result<(Wire,Vec<ObservedObject>,Vec<ProducerProof>)> {
    let passive=matches!(test,PASSIVE_STAGE|PASSIVE_OBSERVE);
    need(matches!(test,STAGE_INPUT|OBSERVE_BEFORE|OBSERVE_AFTER|PASSIVE_STAGE|PASSIVE_OBSERVE) && items.len()==47
        && !raw.is_empty() && raw.len()<=OWNER_LIMIT && raw.is_ascii() && raw.ends_with(b"\n") && !raw.contains(&b'\r'))?;
    let stage=matches!(test,STAGE_INPUT|PASSIVE_STAGE);let proof_count=if stage {0}else if test==OBSERVE_AFTER {6}else{3};
    let roles=observation_roles(stage);let directories=if stage {5}else{9};
    let lines:Vec<_>=std::str::from_utf8(raw).map_err(|_|Error::Unsafe)?[..raw.len()-1].split('\n').collect();
    let prefix=1+OBSERVATION_FIELDS.len();
    need(lines.len()==prefix+proof_count+roles.len())?;
    let header=lines[..prefix].join("\n")+"\n";
    let record=Wire::parse(header.as_bytes(),if passive {PASSIVE_OBSERVATION_HEADER}else{OBSERVATION_HEADER},&OBSERVATION_FIELDS,OWNER_LIMIT)?;
    record.binding()?;record.equal("profile",if passive {PASSIVE_PROFILE}else{PRODUCTION_PROFILE})?;record.equal("observerTest",test)?;
    for (key,value) in [("payloadFiles","46"),("sourceReaders",if stage {"47"}else{"0"}),
        ("payloadWriters",if stage {"47"}else{"0"}),("postcheckReaders",if stage {"47"}else{"94"}),
        ("parentBookSettled","true"),("unknown","false"),
        ("actualFixedProducerObserved",if matches!(test,OBSERVE_AFTER|PASSIVE_OBSERVE) {"true"}else{"false"}),
        ("runtimeConsumerEnabled","false"),("pythonExecuted","false"),("appLaunched","false"),
        ("resultCloseGate","original-observer-exit-zero-required")] {record.equal(key,value)?;}
    need(record.number("objectCount",103)?==roles.len() as u64 && record.number("proofCount",6)?==proof_count as u64
        && record.number("fileOriginals",256)? >= (if stage {146}else{103})
        && record.get("fileOriginals")==record.get("fileOriginalsClosed"))?;
    let mut proofs=Vec::with_capacity(proof_count);
    let proof_roles=if passive {PASSIVE_SETUP_PROOFS.as_slice()}else{PRODUCER_PROOFS.as_slice()};
    for (line,(role,_,limit)) in lines[prefix..prefix+proof_count].iter().zip(proof_roles) {
        let parts:Vec<_>=line.strip_prefix("proof=").ok_or(Error::Unsafe)?.split('|').collect();
        need(parts.len()==3 && parts[0]==*role && is_hex(parts[2],64))?;
        let bytes=number(parts[1],*limit as u64)?;need(bytes>0)?;
        proofs.push(ProducerProof {role:(*role).to_owned(),bytes:bytes as usize,sha:parts[2].to_owned()});
    }
    let mut objects=Vec::with_capacity(roles.len());let mut ids=BTreeSet::new();
    for (ordinal,(line,role)) in lines[prefix+proof_count..].iter().zip(roles).enumerate() {
        let v:Vec<_>=line.strip_prefix("observed=").ok_or(Error::Unsafe)?.split('|').collect();
        let directory=ordinal<directories;
        need(v.len()==6 && v[0]==role && v[1]==(if directory {"directory"}else{"file"})
            && is_hex(v[3],64))?;
        let stamp=parse_stamp(v[2])?;
        need((stamp.attributes&FS::FILE_ATTRIBUTE_DIRECTORY!=0)==directory && ids.insert((stamp.volume,stamp.id)))?;
        if directory {need(v[4]=="-" && is_hex(v[5],64))?;}
        else {
            let name=role.strip_prefix("source/").unwrap_or(&role);
            let item=items.iter().find(|p|p.path==name).ok_or(Error::Unsafe)?;
            need(v[4]==item.sha && stamp.size==item.bytes as i64 && stamp.allocation>=stamp.size && v[5]=="-")?;
        }
        objects.push(ObservedObject {role,directory,stamp,security:v[3].to_owned(),sha:v[4].to_owned(),inventory:v[5].to_owned()});
    }
    need(objects.iter().all(|o|o.stamp.volume==objects[0].stamp.volume))?;
    for object in &objects[..directories] {
        need(object.inventory==inventory_sha(&child_rows(&objects,&object.role,record.get("manifestSha256")?,stage)?)?)?;
    }
    Ok((record,objects,proofs))
}
fn bound_observation(raw:&[u8],test:&str,pre:&Wire,pre_raw:&[u8],roster_raw:&[u8],items:&[Payload])
    -> Result<(Wire,Vec<ObservedObject>,Vec<ProducerProof>)> {
    let (record,objects,proofs)=observation(raw,items,test)?;
    bind_raw(&record,"precheck",pre_raw)?;bind_raw(&record,"roster",roster_raw)?;
    for key in ["manifestSha256","protocolSha256","inventorySha256","coreSha256","payloadFiles","payloadBytes"] {
        record.equal(key,pre.get(key)?)?;
    }
    for (key,from) in [("artifactBytes","ownerArtifactBytes"),("artifactSha256","ownerArtifactSha256"),
        ("artifactIdentity","ownerArtifactIdentity")] {record.equal(key,pre.get(from)?)?;}
    Ok((record,objects,proofs))
}
pub(super) fn producer_exit(raw:&[u8],pre:&Wire,pre_raw:&[u8],role:&str) -> Result<()> {
    let passive=active_profile()?==PASSIVE_PROFILE;
    let (artifact,test,code)=if passive {match role {
        "stage"=>("owner",Some(PASSIVE_STAGE),"0"),"helperSuccess"=>("helper",None,"0"),
        "observe"=>("owner",Some(PASSIVE_OBSERVE),"0"),_=>return Err(Error::Unsafe),
    }}else{match role {
        "stage"=>("owner",Some(STAGE_INPUT),"0"),"before"=>("owner",Some(OBSERVE_BEFORE),"0"),
        "after"=>("owner",Some(OBSERVE_AFTER),"0"),"helperSuccess"=>("helper",None,"0"),
        "helperOccupied"=>("helper",None,"2"),_=>return Err(Error::Unsafe),
    }};
    let record=Wire::parse(raw,if passive {PASSIVE_SETUP_EXIT_HEADER}else{PRODUCER_EXIT_HEADER},&PRODUCER_EXIT_FIELDS,LIMIT)?;
    record.binding()?;record.equal("profile",if passive {PASSIVE_PROFILE}else{PRODUCTION_PROFILE})?;record.equal("role",role)?;
    record.equal("artifactSha256",pre.get(&format!("{artifact}ArtifactSha256"))?)?;
    record.equal("precheckSha256",&digest(pre_raw)?)?;
    let command=match test {Some(test)=>command_sha(pre.get("ownerArtifact")?,test)?,None=>pre.get("helperCommandSha256")?.to_owned()};
    record.equal("commandSha256",&command)?;
    record.equal("originalWaitReturned","true")?;record.equal("exitCode",code)?;
    record.equal("writerCloseGate",&format!("original-{role}-step-success-required"))
}
fn production_outcomes(count:usize) -> Result<()> {
    if active_profile()?==PASSIVE_PROFILE {
        need(count==3)?;
        for role in ["STAGE","PUBLISH"] {
            outcome(&format!("MRK_WINDOWS_PASSIVE_{role}_STEP_OUTCOME"))?;
            outcome(&format!("MRK_WINDOWS_PASSIVE_{role}_FINALIZE_STEP_OUTCOME"))?;
        }
        return Ok(());
    }
    need(count==0 || count==3 || count==6)?;
    let roles=if count==0 {0}else if count==3 {2}else{4};
    for role in ["STAGE","SUCCESS","BEFORE","OCCUPIED"].iter().take(roles) {
        outcome(&format!("MRK_WINDOWS_PRODUCER_{role}_STEP_OUTCOME"))?;
        outcome(&format!("MRK_WINDOWS_PRODUCER_{role}_FINALIZE_STEP_OUTCOME"))?;
    }
    Ok(())
}
fn checked_producer_chain(pre:&Wire,pre_raw:&[u8],roster_raw:&[u8],items:&[Payload],proof_raw:&[Vec<u8>])
    -> Result<(Vec<ObservedObject>,Option<Vec<ObservedObject>>)> {
    let passive=active_profile()?==PASSIVE_PROFILE;
    need(!passive || proof_raw.len()==3)?;
    need(proof_raw.len()==3 || proof_raw.len()==6)?;
    let (_,stage,stage_proofs)=bound_observation(&proof_raw[0],if passive {PASSIVE_STAGE}else{STAGE_INPUT},pre,pre_raw,roster_raw,items)?;
    need(stage_proofs.is_empty())?;
    producer_exit(&proof_raw[1],pre,pre_raw,"stage")?;
    producer_exit(&proof_raw[2],pre,pre_raw,"helperSuccess")?;
    if proof_raw.len()==3 {return Ok((stage,None));}
    let (_,before,proofs)=bound_observation(&proof_raw[3],OBSERVE_BEFORE,pre,pre_raw,roster_raw,items)?;
    for ((proof,(role,_,_)),raw) in proofs.iter().zip(PRODUCER_PROOFS).zip(proof_raw) {proof.matches(role,raw)?;}
    source_unchanged(&stage,&before)?;
    producer_exit(&proof_raw[4],pre,pre_raw,"before")?;
    producer_exit(&proof_raw[5],pre,pre_raw,"helperOccupied")?;
    Ok((stage,Some(before)))
}

// Independent exact W output policy, including image execute permissions. F's
// synthetic sealed-file mask deliberately remains unchanged and is NOT reused.
pub(super) fn production_descriptor(raw:&[u8],directory:bool,name:Option<&str>) -> Result<()> {
    if let Some(name)=name {need(!directory && PAYLOAD_NAMES.contains(&name))?;}
    need(directory || name.is_some())?;
    let image=name.is_some_and(|n|n.ends_with(".exe")||n.ends_with(".dll")||n.ends_with(".pyd"));
    let facts=security::descriptor(raw,if directory {FileKind::Directory}else{FileKind::File},AuthorityScope::ImmutableVersion)?;
    need(facts.owner.bytes()==builtin(544) && facts.control==(S::SE_SELF_RELATIVE|S::SE_DACL_PRESENT|S::SE_DACL_PROTECTED)
        && facts.revision==2 && facts.aces.len()==3)?;
    let group=decode::u32_at(raw,8)? as usize;
    need(security::sid_at(raw,group,raw.len())?.bytes()==builtin(544))?;
    for (i,ace) in facts.aces.iter().enumerate() {
        let sid=match i {0=>system_sid(),1=>builtin(544),_=>builtin(545)};
        let mask=if i<2 {FS::FILE_ALL_ACCESS}else{FS::FILE_GENERIC_READ|if directory||image{FS::FILE_GENERIC_EXECUTE}else{0}};
        need(ace.allow && ace.flags==0 && ace.sid.bytes()==sid && ace.mask==mask)?;
    }
    Ok(())
}

// A self-relative, aligned descriptor is already complete before any OS entry.
// No transient inherited DACL, runner-owner fallback or privilege adjustment.
pub(super) fn fixture_descriptor(directory: bool,sealed: bool) -> Result<Vec<u8>> {
    let owner=builtin(544);
    let mut aces=vec![(system_sid(),FS::FILE_ALL_ACCESS),(owner.clone(),FS::FILE_ALL_ACCESS)];
    if sealed {aces.push((builtin(545),FS::FILE_GENERIC_READ | if directory {FS::FILE_GENERIC_EXECUTE} else {0}));}
    let mut acl=vec![0u8;8];acl[0]=2;
    for (sid,mask) in &aces {
        let size=8+sid.len();
        acl.extend([0,0]);acl.extend((size as u16).to_le_bytes());acl.extend(mask.to_le_bytes());acl.extend(sid);
    }
    let length=acl.len() as u16;acl[2..4].copy_from_slice(&length.to_le_bytes());
    acl[4..6].copy_from_slice(&(aces.len() as u16).to_le_bytes());
    let mut raw=vec![0u8;20];raw[0]=1;
    raw[2..4].copy_from_slice(&(S::SE_SELF_RELATIVE | S::SE_DACL_PRESENT | S::SE_DACL_PROTECTED).to_le_bytes());
    raw[4..8].copy_from_slice(&20u32.to_le_bytes());raw[8..12].copy_from_slice(&20u32.to_le_bytes());
    raw[16..20].copy_from_slice(&(20u32+owner.len() as u32).to_le_bytes());raw.extend(owner);raw.extend(acl);
    check_descriptor(&raw,directory,sealed)?;
    Ok(raw)
}
pub(super) fn check_descriptor(raw:&[u8],directory:bool,sealed:bool) -> Result<()> {
    let facts=security::descriptor(raw,if directory {FileKind::Directory}else{FileKind::File},AuthorityScope::ImmutableVersion)?;
    need(facts.owner.bytes()==builtin(544) && facts.control==(S::SE_SELF_RELATIVE|S::SE_DACL_PRESENT|S::SE_DACL_PROTECTED)
        && facts.revision==2 && facts.aces.len()==if sealed {3}else{2})?;
    let group=decode::u32_at(raw,8)? as usize;
    need(security::sid_at(raw,group,raw.len())?.bytes()==builtin(544))?;
    for (i,ace) in facts.aces.iter().enumerate() {
        let sid=match i {0=>system_sid(),1=>builtin(544),_=>builtin(545)};
        let mask=if i<2 {FS::FILE_ALL_ACCESS}else{FS::FILE_GENERIC_READ|if directory{FS::FILE_GENERIC_EXECUTE}else{0}};
        need(ace.allow && ace.flags==0 && ace.sid.bytes()==sid && ace.mask==mask)?;
    }
    Ok(())
}


// The only cross-process time origin is the first ordinary entry's original
// GetTickCount64 observation. Pure observe() is also the inert control boundary.
pub(super) const AGGREGATE_MS: u64 = 210_000;
pub(super) const SECOND_FLOOR_MS: u64 = 100_000;
#[derive(Clone, Debug)]
pub(super) struct AggregateClock {
    pub origin: u64, pub deadline: u64, pub entry: u64, pub last: u64,
    pub latched: bool, pub second: bool, pub prelaunch: Option<u64>,
}
impl AggregateClock {
    pub fn new(origin: u64, entry: u64, second: bool) -> Result<Self> {
        let deadline = origin.checked_add(AGGREGATE_MS).ok_or(Error::Bounds)?;
        let mut result = Self { origin, deadline, entry, last: origin, latched: false, second, prelaunch: None };
        result.observe(entry, if second { SECOND_FLOOR_MS } else { 0 })?;
        Ok(result)
    }
    pub fn observe(&mut self, now: u64, floor: u64) -> Result<u64> {
        let remaining = self.deadline.checked_sub(now);
        self.latched |= now < self.origin || now < self.entry || now < self.last
            || remaining.is_none_or(|left| left == 0 || left < floor);
        self.last = self.last.max(now);
        need(!self.latched)?;
        Ok(now)
    }
    pub fn prelaunch_at(&mut self,now:u64) -> Result<u64> {
        self.observe(now,if self.second {SECOND_FLOOR_MS}else{0})?;
        self.latched |= self.prelaunch.is_some();need(!self.latched)?;
        self.prelaunch=Some(now);Ok(now)
    }
    pub fn sample(&mut self, prelaunch: bool) -> Result<u64> {
        let now = unsafe { SI::GetTickCount64() };
        if prelaunch {self.prelaunch_at(now)}else{self.observe(now,0)}
    }
}
pub(super) fn invocation(
    source: &str, tree: &str, run: &str, bytes: usize, sha: &str,
    before: &str, command: &str, request_sha: &str, origin: u64,
) -> Result<Wire> {
    let deadline = origin.checked_add(AGGREGATE_MS).ok_or(Error::Bounds)?;
    need(decimal(run) && bytes>0 && bytes<=PAYLOAD_LIMIT)?;original_epoch(before,before)?;
    let mut v = Wire { values: BTreeMap::new() };
    for (key, value) in [
        ("profile", PROFILE), ("sourceSha", source), ("sourceTree", tree), ("runId", run),
        ("attempt", "1"), ("ordinaryOwnerTest", ORDINARY_OWNER), ("artifactSha256", sha),
        ("artifactBeforeIdentity", before), ("ordinaryChildCommandSha256", command),
        ("ordinaryRequestSha256", request_sha),
    ] { v.put(key, value); }
    v.put("artifactBytes", bytes); v.put("originTickMs", origin);
    v.put("aggregateBudgetMs", AGGREGATE_MS); v.put("deadlineTickMs", deadline);
    v.encoded(INVOCATION_HEADER, &INVOCATION_FIELDS, LIMIT)?;
    Ok(v)
}
pub(super) fn invocation_sha(v: &Wire) -> Result<String> {
    digest(&v.encoded(INVOCATION_HEADER, &INVOCATION_FIELDS, LIMIT)?)
}
pub(super) fn invocation_json(v: &Wire) -> Result<String> {
    let mut fields = Vec::with_capacity(INVOCATION_FIELDS.len()+1);
    for key in INVOCATION_FIELDS {
        let value = v.get(key)?;
        let numeric = matches!(key, "attempt" | "artifactBytes" | "originTickMs" | "aggregateBudgetMs" | "deadlineTickMs");
        if numeric { number(value, u64::MAX)?; }
        else { need(value.is_ascii() && !value.contains('"') && !value.contains('\\'))?; }
        fields.push(if numeric { format!("\"{key}\":{value}") } else { format!("\"{key}\":\"{value}\"") });
    }
    fields.push(format!("\"ordinaryInvocationSha256\":\"{}\"", invocation_sha(v)?));
    Ok(format!("{{{}}}", fields.join(",")))
}
pub(super) fn original_epoch(before: &str, after: &str) -> Result<()> {
    let a: Vec<_> = before.split(':').collect(); let b: Vec<_> = after.split(':').collect();
    need(a.len()==6 && b.len()==6 && is_hex(a[1],32) && a[1]!="0".repeat(32))?;
    for i in [0,2,3,4,5] {
        need(number(a[i], if i==5 {u32::MAX as u64} else if i==0 {u64::MAX} else {i64::MAX as u64})? > 0)?;
    }
    for i in [0,1,2,3,5] { need(a[i]==b[i])?; }
    need(number(b[4],i64::MAX as u64)? >= number(a[4],i64::MAX as u64)?)
}
fn bind_raw(record: &Wire, role: &str, raw: &[u8]) -> Result<()> {
    need(record.number(&format!("{role}Bytes"), OWNER_LIMIT as u64)? == raw.len() as u64)?;
    record.equal(&format!("{role}Sha256"), &digest(raw)?)
}
fn identity(value: &Stamp) -> String { format!("{}:{}", value.volume, hex(&value.id)) }
pub(super) struct Admission {
    pub originals: Vec<(usize, Stamp)>, pub invocation: Wire, pub serial_originals: usize,
    pub envelope_bytes: usize, pub envelope_sha: String, pub origin: u64, pub deadline: u64, pub ordinary_prewrite: u64,
}
impl Admission {
    pub fn batch_json(&self, clock: &AggregateClock) -> Result<String> {
        need(clock.origin==self.origin && clock.deadline==self.deadline && clock.second)?;
        let production=self.invocation.get("profile")?==PRODUCTION_PROFILE;
        need(self.serial_originals==(if production {6}else{0}))?;
        let serial=if production {format!(",\"serialPrerequisiteOriginals\":{},\"serialPrerequisiteOriginalsClosed\":{}",self.serial_originals,self.serial_originals)}else{String::new()};
        Ok(format!("{{\"profile\":\"{}\",\"ordinaryInvocationSha256\":\"{}\",\"prerequisiteBytes\":{},\"prerequisiteSha256\":\"{}\",\"originTickMs\":{},\"deadlineTickMs\":{},\"aggregateBudgetMs\":{AGGREGATE_MS},\"entryTickMs\":{}{serial}}}",
            self.invocation.get("profile")?,invocation_sha(&self.invocation)?,self.envelope_bytes,self.envelope_sha,self.origin,self.deadline,clock.entry))
    }
}
pub(super) fn admit(
    request: &FullwalkRequest, root: &Path, files: &mut Vec<OriginalFile>, trace: &mut InputTrace,
    original_end: Instant,
) -> Result<Admission> {
    profile()?;
    let production=active_profile()?==PRODUCTION_PROFILE;
    if production {production_outcomes(6)?;}
    for key in ["MRK_WINDOWS_PUBLISHER_STEP_OUTCOME", "MRK_WINDOWS_FIXTURE_FINALIZE_STEP_OUTCOME",
        "MRK_WINDOWS_ORDINARY_OWNER_STEP_OUTCOME", "MRK_WINDOWS_ORDINARY_FINALIZE_STEP_OUTCOME",
        "MRK_WINDOWS_FULLWALK_PREFLIGHT_STEP_OUTCOME"] { outcome(key)?; }
    let fixed = [
        (PREREQUISITE_FILE,TEXT_LIMIT), (PRECHECK_FILE,TEXT_LIMIT), (ROSTER_FILE,TEXT_LIMIT),
        (PUBLICATION_FILE,OWNER_LIMIT), (PUBLICATION_EXIT,LIMIT), ("ordinary-request.txt",LIMIT),
        ("ordinary-owner-intent.private.json",LIMIT), ("ordinary-owner-result.private.json",OWNER_LIMIT),
        ("ordinary-owner-exit.private.json",LIMIT), (FINALITY_FILE,TEXT_LIMIT),
    ];
    let mut raw = Vec::with_capacity(10); let mut originals = Vec::with_capacity(10);
    for (name, limit) in fixed {
        trace.at(InputRole::Binding,Some(files.len() as u8));
        let owned = owned_file_traced(files,&root.join(name),false,FS::FILE_GENERIC_READ,trace)?;
        let before = files[owned].stamp_traced(trace)?;
        raw.push(files[owned].read_traced(limit,trace)?);
        let after = files[owned].stamp_traced(trace)?;
        trace.need(after == before,InputCheck::ArtifactStable)?;
        originals.push((owned,before));
    }
    let fields=prerequisite_fields(production);let keys:Vec<_>=fields.iter().map(String::as_str).collect();
    let envelope = Wire::parse(&raw[0],if production {PRODUCTION_PREREQUISITE_HEADER}else{PREREQUISITE_HEADER},&keys,TEXT_LIMIT)?;
    envelope.binding()?;
    need(raw[0].len()==request.publication_bytes && digest(&raw[0])?==request.publication_sha)?;
    for (role, bytes) in [
        ("precheck",&raw[1]),("roster",&raw[2]),("publisherReceipt",&raw[3]),("publisherExit",&raw[4]),
        ("ordinaryRequest",&raw[5]),("ordinaryIntent",&raw[6]),("ordinaryOwnerResult",&raw[7]),
        ("ordinaryOwnerExit",&raw[8]),("ordinaryFinality",&raw[9]),
    ] {bind_raw(&envelope,role,bytes)?;}
    for (key, value) in [("publisherStepOutcome","success"),("publisherFinalizeStepOutcome","success"),
        ("ordinaryOwnerStepOutcome","success"),("ordinaryFinalizeStepOutcome","success"),
        ("prerequisitesOnlyNotNativeWalk","true"),("envelopeCloseGate","original-fullwalk-preflight-step-success-required")] {
        envelope.equal(key,value)?;
    }
    let pre = precheck(&raw[1],root)?; bind_raw(&pre,"roster",&raw[2])?;
    let items = roster(&raw[2])?;
    let mut serial_originals=0usize;
    // Only immutable DATA identities cross this branch, never invented legacy
    // created/sealed Object rows or product HANDLE ownership.
    let (published,objects): (Wire,Vec<(String,Stamp)>) = if production {
        let mut proof_raw=Vec::with_capacity(6);let mut late=false;
        let mut serial_gate=||reporting_effect(Instant::now(),original_end,&mut late);
        for (role,name,limit) in PRODUCER_PROOFS {
            serial_gate()?;trace.at(InputRole::Binding,Some(files.len() as u8));
            let owned=owned_file_traced(files,&root.join(name),false,FS::FILE_GENERIC_READ,trace)?;
            serial_gate()?;let before=files[owned].stamp_traced(trace)?;
            serial_gate()?;let bytes=files[owned].read_traced(limit,trace)?;
            serial_gate()?;let after=files[owned].stamp_traced(trace)?;
            trace.need(after==before,InputCheck::ArtifactStable)?;
            serial_gate()?;bind_raw(&envelope,role,&bytes)?;serial_gate()?;
            // Success only after this SAME original close. On any uncertainty
            // leave it in existing owner storage for the ordinary Unknown path.
            // Expiry does not block the caller's established failure settlement.
            files[owned].close()?;need(files[owned].is_closed() && owned+1==files.len())?;
            serial_gate()?;files.pop();serial_originals+=1;proof_raw.push(bytes);
        }
        let (record,observations,proofs)=bound_observation(&raw[3],OBSERVE_AFTER,&pre,&raw[1],&raw[2],&items)?;
        for ((proof,(role,_,_)),bytes) in proofs.iter().zip(PRODUCER_PROOFS).zip(&proof_raw) {proof.matches(role,bytes)?;}
        let (stage,before)=checked_producer_chain(&pre,&raw[1],&raw[2],&items,&proof_raw)?;
        source_unchanged(&stage,&observations)?;
        observations_unchanged(before.as_deref().ok_or(Error::Unsafe)?,&observations)?;
        producer_exit(&raw[4],&pre,&raw[1],"after")?;
        (record,observations.into_iter().map(|o|(o.role,o.stamp)).collect())
    }else {
        let (record,objects)=publication(&raw[3],&items)?;
        (record,objects.into_iter().map(|o|(o.role,o.sealed)).collect())
    };
    bind_raw(&published,"precheck",&raw[1])?; bind_raw(&published,"roster",&raw[2])?;
    let finality = Wire::parse(&raw[9],FINALITY_HEADER,&FINALITY_FIELDS,TEXT_LIMIT)?;
    finality.binding()?;
    for (role, bytes) in [("ordinaryRequest",&raw[5]),("ordinaryIntent",&raw[6]),
        ("ordinaryOwnerResult",&raw[7]),("ordinaryOwnerExit",&raw[8])] {bind_raw(&finality,role,bytes)?;}
    for (key,value) in [("ordinaryOwnerTest",ORDINARY_OWNER),("ordinaryChildTest",ORDINARY_CHILD),
        ("ownerStepOutcome","success"),("ownerOriginalExitCode","0"),("childOriginalExitCode","0"),
        ("accountRemovedAfterSettlement","true"),("finalizerCloseGate","original-ordinary-finalizer-step-success-required")] {
        finality.equal(key,value)?;
    }
    need(root.ancestors().count()<=19 &&
        finality.number("originalInputCount",40)? == root.ancestors().count() as u64 + 8)?;
    let ordinary = Wire::parse(&raw[5],"MRK_WINDOWS_ORDINARY_REQUEST_V1",&[
        "sourceSha","sourceTree","runId","attempt","artifact","artifactBytes","artifactSha256","commandSha256","artifactIdentity"
    ],LIMIT)?;
    for key in ["sourceSha","sourceTree","runId","attempt"] {ordinary.equal(key,pre.get(key)?)?;}
    for (left,right) in [("artifact","ownerArtifact"),("artifactBytes","ownerArtifactBytes"),
        ("artifactSha256","ownerArtifactSha256"),("artifactIdentity","ownerArtifactIdentity"),
        ("commandSha256","ordinaryChildCommandSha256")] {ordinary.equal(left,pre.get(right)?)?;}
    for (left,right) in [("artifactBytes","ownerArtifactBytes"),("artifactSha256","ownerArtifactSha256"),
        ("artifactIdentity","ownerArtifactIdentity")] {published.equal(left,pre.get(right)?)?;}
    finality.equal("artifactBytes",pre.get("ownerArtifactBytes")?)?;
    finality.equal("artifactSha256",pre.get("ownerArtifactSha256")?)?;
    finality.equal("artifactBeforeIdentity",pre.get("ownerArtifactIdentity")?)?;
    original_epoch(finality.get("artifactBeforeIdentity")?,finality.get("artifactAfterIdentity")?)?;
    envelope.equal("ownerArtifactAfterOrdinaryIdentity",finality.get("artifactAfterIdentity")?)?;
    need(request.owner.identity==finality.get("artifactAfterIdentity")?
        && request.owner.path==pre.get("ownerArtifact")? && request.owner.bytes as u64==pre.number("ownerArtifactBytes",PAYLOAD_LIMIT as u64)?
        && request.owner.sha==pre.get("ownerArtifactSha256")?
        && request.app.path==pre.get("appArtifact")? && request.app.identity==pre.get("appArtifactIdentity")?
        && request.app.bytes as u64==pre.number("appArtifactBytes",APP_ARTIFACT_LIMIT as u64)?
        && request.app.sha==pre.get("appArtifactSha256")?)?;
    for (role, artifact) in [("app",&request.app),("owner",&request.owner)] {
        need(artifact.messages_bytes as u64==pre.number(&format!("{role}CompileMessagesBytes"),16<<20)?
            && artifact.messages_sha==pre.get(&format!("{role}CompileMessagesSha256"))?
            && artifact.argv_sha==pre.get(&format!("{role}CompileArgvSha256"))?)?;
    }
    for (key,value) in [("manifestSha256",request.manifest_sha.as_str()),("protocolSha256",request.protocol_sha.as_str()),
        ("inventorySha256",request.inventory_sha.as_str()),("coreSha256",request.core_sha.as_str())] {
        pre.equal(key,value)?; published.equal(key,value)?; envelope.equal(key,value)?;
    }
    for record in [&pre,&published,&envelope] {
        need(record.number("payloadFiles",2047)?==request.files as u64
            && record.number("payloadBytes",1<<30)?==request.payload_bytes)?;
    }
    for ((key,role),expected) in [("versionIdentity","version"),("selectedPythonIdentity",SELECTED[0]),
        ("selectedBootstrapIdentity",SELECTED[1]),("selectedCoreIdentity",SELECTED[2])]
        .into_iter().zip([request.version,request.selected[0],request.selected[1],request.selected[2]]) {
        let stamp=&objects.iter().find(|(name,_)|name==role).ok_or(Error::Unsafe)?.1;
        envelope.equal(key,&identity(stamp))?;
        need(stamp.volume==expected.volume_serial && stamp.id==expected.file_id)?;
    }
    let origin=finality.number("originTickMs",u64::MAX)?;
    let deadline=origin.checked_add(AGGREGATE_MS).ok_or(Error::Bounds)?;
    for record in [&finality,&envelope] {
        need(record.number("originTickMs",u64::MAX)?==origin
            && record.number("deadlineTickMs",u64::MAX)?==deadline
            && record.number("aggregateBudgetMs",u64::MAX)?==AGGREGATE_MS)?;
    }
    let prewrite=finality.number("ordinaryResultPrewriteTickMs",u64::MAX)?;
    need(prewrite>=origin && prewrite<deadline)?;
    let mut invocation=invocation(pre.get("sourceSha")?,pre.get("sourceTree")?,pre.get("runId")?,
        request.owner.bytes,pre.get("ownerArtifactSha256")?,pre.get("ownerArtifactIdentity")?,
        pre.get("ordinaryChildCommandSha256")?,&digest(&raw[5])?,origin)?;
    invocation.put("profile",pre.get("profile")?);
    let sha=invocation_sha(&invocation)?;
    finality.equal("ordinaryInvocationSha256",&sha)?;envelope.equal("ordinaryInvocationSha256",&sha)?;
    Ok(Admission {originals,invocation,serial_originals,envelope_bytes:raw[0].len(),envelope_sha:request.publication_sha.clone(),origin,deadline,ordinary_prewrite:prewrite})
}


#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum MutationKind { Directory, FileCreate, Seal, Disposition }
struct Mutation {
    kind: MutationKind, phase: Phase, path: Vec<u16>, descriptor: Aligned,
    attributes: S::SECURITY_ATTRIBUTES, disposition: FS::FILE_DISPOSITION_INFO,
    handle: F::HANDLE, returned: i32, error: u32, _pin: PhantomPinned,
}
impl Mutation {
    fn new(kind: MutationKind,path: &Path,directory: bool,handle: F::HANDLE) -> Result<Pin<Box<Self>>> {
        let text=path.to_str().ok_or(Error::Unsafe)?;fixed_path(text)?;
        let raw=fixture_descriptor(directory,kind==MutationKind::Seal)?;
        let mut frame=Box::pin(Self {kind,phase:Phase::Prepared,path:wide(text),
            descriptor:Aligned([0;BUFFER]),attributes:S::SECURITY_ATTRIBUTES::default(),
            disposition:FS::FILE_DISPOSITION_INFO::default(),handle,returned:0,error:0,_pin:PhantomPinned});
        let f=unsafe {frame.as_mut().get_unchecked_mut()};
        f.descriptor.0[..raw.len()].copy_from_slice(&raw);
        f.attributes.nLength=size_of::<S::SECURITY_ATTRIBUTES>() as u32;
        f.attributes.lpSecurityDescriptor=f.descriptor.0.as_mut_ptr().cast();
        f.attributes.bInheritHandle=0;f.disposition.DeleteFile=true;
        Ok(frame)
    }
}
pub(super) fn mutation_return(ok:i32,error:u32) -> Result<()> {
    if ok!=0 {return need(error==0);}
    if error==0 || error==F::ERROR_IO_PENDING {Err(Error::Unknown)} else {Err(Error::Unavailable)}
}
pub(super) fn child_change(before:&Stamp,after:&Stamp) -> bool {
    same_object(before,after) && before.attributes & FS::FILE_ATTRIBUTE_DIRECTORY!=0
        && after.write>=before.write && after.change>=before.change && after.size>=0 && after.allocation>=0
}
pub(super) fn payload_change(before:&Stamp,after:&Stamp,bytes:usize) -> bool {
    same_object(before,after) && before.attributes & FS::FILE_ATTRIBUTE_DIRECTORY==0
        && after.write>=before.write && after.change>=before.change
        && after.size==bytes as i64 && after.allocation>=after.size
}
pub(super) fn fixture_capacity(ancestors:usize,program_files:usize,retained:usize,leaf:usize) -> Result<()> {
    need(ancestors<=19 && program_files<=8 && retained<=40 && leaf<=2
        && retained.checked_add(leaf).is_some_and(|total|total<=40))
}
pub(super) fn exact_entries(entries:&[DirectoryEntry],expected:&BTreeMap<String,Stamp>,
    own:&Stamp,parent:Option<&Stamp>) -> Result<usize> {
    let mut seen=BTreeSet::new();let mut payload=0usize;let mut dots=0usize;
    for entry in entries {
        need(seen.insert(entry.name.to_ascii_lowercase()))?;
        if entry.name=="." || entry.name==".." {
            need(entry.kind==FileKind::Directory)?;dots+=1;
            let bound=if entry.name=="." {Some(own)}else{parent};
            if let Some(bound)=bound {need(entry.file_id==bound.id)?;}
            continue;
        }
        let bound=expected.get(&entry.name).ok_or(Error::Unsafe)?;
        need(entry.file_id==bound.id && entry.attributes==bound.attributes
            && (entry.kind==FileKind::Directory)==(bound.attributes&FS::FILE_ATTRIBUTE_DIRECTORY!=0))?;
        payload+=1;
    }
    need(payload==expected.len() && dots<=2)?;
    Ok(entries.len())
}
#[derive(Clone, Debug, Default)]
pub(super) struct CursorEpoch { entered: bool, eof: bool, epoch: Option<usize> }
impl CursorEpoch {
    pub fn begin(&mut self, epoch: usize) -> Result<bool> {
        need(epoch <= 52 && !self.entered)?;
        let restart = self.epoch.is_some();
        if let Some(previous) = self.epoch { need(self.eof && epoch > previous)?; }
        self.entered = true; self.eof = false; self.epoch = Some(epoch);
        Ok(restart)
    }
    pub fn complete(&mut self) -> Result<()> {
        need(self.entered && !self.eof)?; self.entered = false; self.eof = true; Ok(())
    }
}

struct Fixture {
    start:Instant,end:Instant,latched:bool,root:PathBuf,image:PathBuf,
    book:NativeBook,borrowed:Option<usize>,mutation:Option<Held<Mutation>>,
    files:Vec<OriginalFile>,paths:Vec<PathBuf>,cursors:Vec<CursorEpoch>,
    snapshots:BTreeMap<usize,Stamp>,security:BTreeMap<usize,String>,
    opened:usize,closed:usize,source_readers:usize,writers:usize,postcheck_readers:usize,
    objects:Vec<Object>,directories:Vec<usize>,location:Option<KnownLocation>,
    ancestors:usize,program_files:usize,occupied:bool,dispositions:usize,retired_mask:u64,
}
impl Fixture {
    fn new(start:Instant,root:PathBuf,image:PathBuf) -> Result<Self> {
        Ok(Self {start,end:start.checked_add(Duration::from_secs(90)).ok_or(Error::Bounds)?,latched:false,
            root,image,book:NativeBook::new(),borrowed:None,mutation:None,
            files:Vec::with_capacity(40),paths:Vec::with_capacity(40),cursors:Vec::with_capacity(40),
            snapshots:BTreeMap::new(),security:BTreeMap::new(),opened:0,closed:0,
            source_readers:0,writers:0,postcheck_readers:0,objects:Vec::with_capacity(52),
            directories:Vec::with_capacity(5),location:None,ancestors:0,program_files:0,occupied:false,dispositions:0,retired_mask:0})
    }
    fn gate(&mut self) -> Result<()> {reporting_effect(Instant::now(),self.end,&mut self.latched)}
    fn handle(&mut self,index:usize) -> Result<F::HANDLE> {
        need(self.borrowed.is_none() && !self.book.is_unknown())?;
        let body=self.files.get_mut(index).ok_or(Error::State)?.body();
        need(body.state==SlotState::Owned && !body.active && valid_handle(body.handle))?;
        Ok(body.handle)
    }
    fn borrowed_call(&mut self,index:usize,call:Call) -> Result<Complete> {
        self.gate()?;let handle=self.handle(index)?;
        // This arena borrows the actual OriginalFile HANDLE. It never reserves,
        // adopts, replaces, or closes that HANDLE in NativeBook.
        self.borrowed=Some(index);
        let result=self.book.call(call,handle,Vec::new());
        if self.book.is_unknown() {return Err(Error::Unknown);}
        self.borrowed=None;self.gate()?;result
    }
    fn borrowed_restart(&mut self,index:usize) -> Result<Complete> {
        // A NEW post-mutation cursor epoch only after known prior EOF/borrower
        // settlement. Retain the SAME parent original: reopening a parent whose
        // original requested DELETE would require a forbidden sharing workaround.
        self.gate()?;let handle=self.handle(index)?;self.book.clear()?;
        let call=Call::Info(FS::FileIdExtdDirectoryRestartInfo,BUFFER);
        let frame=Box::pin(Arena {call,token_length:0,phase:Cell::new(Phase::Prepared),
            returned:Cell::new(None),completion_refusal:Cell::new(None),input:Vec::new(),handle,output_handle:null_mut(),
            unicode:F::UNICODE_STRING::default(),attributes:OBJECT_ATTRIBUTES::default(),directory:false,
            bytes:UnsafeCell::new(Aligned([0;BUFFER])),count:UnsafeCell::new(u32::MAX),
            iosb:UnsafeCell::new(IO::IO_STATUS_BLOCK {Anonymous:IO::IO_STATUS_BLOCK_0 {Status:F::STATUS_PENDING},
                Information:usize::MAX}),_pin:PhantomPinned});
        self.borrowed=Some(index);self.book.active=Some(ManuallyDrop::new(frame));
        self.book.mark_entered(call)?;
        let frame=self.book.arena()?;
        // Existing NativeBook dispatcher and exact arena, not a second metadata
        // implementation. No allocation/check splits native return from capture.
        let returned=unsafe {invoke(frame)};
        frame.returned.set(Some(returned));frame.phase.set(Phase::Returned);
        if matches!(returned,Returned::Boolean(0,0)|Returned::Boolean(0,F::ERROR_IO_PENDING)) {
            return self.book.unknown();
        }
        let result=if matches!(returned,Returned::Boolean(0,F::ERROR_NO_MORE_FILES)) {
            // This fixed restarted directory cursor, like Call::Entries, has
            // a genuine EOF return. It is NOT success inferred from a diagnostic.
            self.book.take_complete()
        }else {self.book.finish(call,returned)};
        if self.book.is_unknown() {return Err(Error::Unknown);}
        self.borrowed=None;self.gate()?;result
    }
    fn stamp(&mut self,index:usize) -> Result<Stamp> {
        let kind=if self.files[index].directory {FileKind::Directory}else{FileKind::File};
        let handle_info=self.borrowed_call(index,Call::HandleInfo)?;
        need(decode::u32_at(handle_info.bytes(4)?,0)? & F::HANDLE_FLAG_INHERIT == 0)?;
        need(self.borrowed_call(index,Call::FileType)?.scalar()?==FS::FILE_TYPE_DISK)?;
        let basic=self.borrowed_call(index,Call::Info(FS::FileBasicInfo,size_of::<FS::FILE_BASIC_INFO>()))?;
        let standard=self.borrowed_call(index,Call::Info(FS::FileStandardInfo,size_of::<FS::FILE_STANDARD_INFO>()))?;
        let tag=self.borrowed_call(index,Call::Info(FS::FileAttributeTagInfo,size_of::<FS::FILE_ATTRIBUTE_TAG_INFO>()))?;
        let id=self.borrowed_call(index,Call::Info(FS::FileIdInfo,size_of::<FS::FILE_ID_INFO>()))?;
        let m=decode::metadata(kind,basic.bytes(size_of::<FS::FILE_BASIC_INFO>())?,
            standard.bytes(size_of::<FS::FILE_STANDARD_INFO>())?,tag.bytes(size_of::<FS::FILE_ATTRIBUTE_TAG_INFO>())?,
            id.bytes(size_of::<FS::FILE_ID_INFO>())?)?;
        need(m.identity.volume_serial!=0 && m.links==1 && m.creation>0 && m.write>0 && m.change>0 && m.attributes!=0)?;
        if kind==FileKind::Directory {
            let case=self.borrowed_call(index,Call::Info(FS::FileCaseSensitiveInfo,size_of::<FS::FILE_CASE_SENSITIVE_INFO>()))?;
            need(decode::u32_at(case.bytes(4)?,0)?==0)?;
        }
        let path=self.paths[index].clone();self.files[index].named(&path)?;self.gate()?;
        Ok(Stamp {volume:m.identity.volume_serial,id:m.identity.file_id,creation:m.creation,write:m.write,
            change:m.change,size:m.size as i64,allocation:m.allocation_size as i64,links:m.links,attributes:m.attributes})
    }
    fn descriptor(&mut self,index:usize) -> Result<Vec<u8>> {
        self.gate()?;let raw=self.files[index].descriptor()?;self.gate()?;Ok(raw)
    }
    fn checked(&mut self,index:usize,scope:Option<AuthorityScope>,sealed:Option<bool>) -> Result<(Stamp,Vec<u8>)> {
        let before=self.stamp(index)?;
        let streams=self.borrowed_call(index,Call::Streams)?;
        decode::streams(streams.nt_bytes()?,if self.files[index].directory {FileKind::Directory}else{FileKind::File})?;
        let raw=self.descriptor(index)?;
        if let Some(scope)=scope {
            security::descriptor(&raw,if self.files[index].directory {FileKind::Directory}else{FileKind::File},scope)?;
        }
        if let Some(sealed)=sealed {check_descriptor(&raw,self.files[index].directory,sealed)?;}
        need(self.stamp(index)?==before)?;
        Ok((before,raw))
    }
    fn append(&mut self,path:&Path,directory:bool) -> Result<usize> {
        self.gate()?;
        need(self.files.len()<40 && self.opened<256 && self.borrowed.is_none() && self.mutation.is_none())?;
        let file=OriginalFile::fixture_new(path,directory,self.end)?;
        let index=self.files.len();self.files.push(file);self.paths.push(path.to_path_buf());self.cursors.push(CursorEpoch::default());
        Ok(index)
    }
    fn open(&mut self,path:&Path,directory:bool,access:u32) -> Result<usize> {
        let index=self.append(path,directory)?;
        let result=self.files[index].open(access,false,null());
        if self.files[index].body().state==SlotState::Owned {self.opened+=1;}
        result?;self.gate()?;self.files[index].named(path)?;self.gate()?;
        Ok(index)
    }
    fn input(&mut self,path:&Path,limit:usize) -> Result<(usize,Vec<u8>)> {
        let index=self.open(path,false,FS::FILE_GENERIC_READ)?;
        let (before,raw_sd)=self.checked(index,None,None)?;
        let raw=self.files[index].read(limit)?;self.gate()?;
        need(self.stamp(index)?==before)?;
        self.snapshots.insert(index,before);self.security.insert(index,digest(&raw_sd)?);
        Ok((index,raw))
    }
    fn directory(&mut self,path:&Path,access:u32,scope:Option<AuthorityScope>,sealed:Option<bool>) -> Result<usize> {
        let index=self.open(path,true,FS::FILE_GENERIC_READ|FS::FILE_TRAVERSE|access)?;
        let (stamp,raw)=self.checked(index,scope,sealed)?;
        self.snapshots.insert(index,stamp);self.security.insert(index,digest(&raw)?);
        Ok(index)
    }
    fn close(&mut self,index:usize) -> Result<()> {
        // Expiry blocks new effects, not this actual once-only original close.
        need(self.borrowed.is_none() && !self.book.is_unknown()
            && self.mutation.as_ref().is_none_or(|m|m.phase==Phase::Complete))?;
        let owned=self.files[index].body().state==SlotState::Owned;
        self.files[index].close()?;
        if owned {self.closed+=1;}
        self.gate()
    }
    fn pop_closed(&mut self,index:usize) -> Result<()> {
        need(index+1==self.files.len() && self.files[index].is_closed())?;
        self.snapshots.remove(&index);self.security.remove(&index);
        self.files.pop();self.paths.pop();self.cursors.pop();Ok(())
    }
    fn prepare_mutation(&mut self,kind:MutationKind,path:&Path,directory:bool,index:Option<usize>) -> Result<()> {
        self.gate()?;need(self.mutation.is_none() && self.borrowed.is_none() && !self.book.is_unknown())?;
        let handle=match index {Some(index)=>self.handle(index)?,None=>null_mut()};
        self.mutation=Some(ManuallyDrop::new(Mutation::new(kind,path,directory,handle)?));Ok(())
    }
    fn mutation_mut(&mut self) -> Result<&mut Mutation> {
        let frame=self.mutation.as_mut().ok_or(Error::State)?;
        Ok(unsafe {frame.as_mut().get_unchecked_mut()})
    }
    fn release_mutation(&mut self) -> Result<()> {
        need(self.mutation.as_ref().is_some_and(|m|m.phase==Phase::Complete))?;
        let frame=self.mutation.take().ok_or(Error::State)?;
        drop(ManuallyDrop::into_inner(frame));Ok(())
    }
    fn mutate(&mut self,kind:MutationKind,path:&Path,directory:bool,index:Option<usize>) -> Result<(i32,u32)> {
        need(kind!=MutationKind::FileCreate)?;
        self.prepare_mutation(kind,path,directory,index)?;self.gate()?;
        let frame=self.mutation_mut()?;
        need(frame.phase==Phase::Prepared)?;frame.phase=Phase::Entered;
        frame.returned=unsafe {match frame.kind {
            MutationKind::Directory=>FS::CreateDirectoryW(frame.path.as_ptr(),&frame.attributes),
            MutationKind::Seal=>S::SetKernelObjectSecurity(frame.handle,S::DACL_SECURITY_INFORMATION,
                frame.descriptor.0.as_mut_ptr().cast()),
            MutationKind::Disposition=>FS::SetFileInformationByHandle(frame.handle,FS::FileDispositionInfo,
                (&frame.disposition as *const FS::FILE_DISPOSITION_INFO).cast(),size_of::<FS::FILE_DISPOSITION_INFO>() as u32),
            MutationKind::FileCreate=>unreachable!("shared OriginalFile body only"),
        }};
        frame.error=if frame.returned!=0 {0}else{unsafe {F::GetLastError()}};
        frame.phase=Phase::Returned;
        let pair=(frame.returned,frame.error);
        if matches!(mutation_return(pair.0,pair.1),Err(Error::Unknown)) {return Err(Error::Unknown);}
        frame.phase=Phase::Complete;self.release_mutation()?;self.gate()?;Ok(pair)
    }
    fn create_file(&mut self,path:&Path) -> Result<usize> {
        let index=self.append(path,false)?;
        self.prepare_mutation(MutationKind::FileCreate,path,false,None)?;
        self.gate()?;
        let frame=self.mutation_mut()?;frame.phase=Phase::Entered;
        let attributes=&frame.attributes as *const S::SECURITY_ATTRIBUTES;
        let result=self.files[index].open(FS::FILE_GENERIC_WRITE|FS::FILE_READ_ATTRIBUTES|FS::READ_CONTROL|FS::WRITE_DAC,true,attributes);
        if self.files[index].body().state==SlotState::Owned {self.opened+=1;}
        if matches!(result,Err(Error::Unknown)) {return result.map(|_|index);}
        self.mutation_mut()?.phase=Phase::Complete;self.release_mutation()?;
        result?;self.gate()?;self.files[index].named(path)?;self.gate()?;
        self.writers+=1;Ok(index)
    }
    fn entries(&mut self,index:usize,selected:Option<&str>) -> Result<Vec<DirectoryEntry>> {
        self.entries_at(index,selected,0)
    }
    fn entries_at(&mut self,index:usize,selected:Option<&str>,epoch:usize) -> Result<Vec<DirectoryEntry>> {
        need(self.files[index].directory)?;
        if let Some(name)=selected {need(decode::component(name))?;}
        let mut restart=self.cursors[index].begin(epoch)?;
        let mut all=Vec::new();
        loop {
            need(self.book.entries<=MAX_ENTRIES)?;
            let result=if restart {self.borrowed_restart(index)?}else{self.borrowed_call(index,Call::Entries)?};
            restart=false;
            if matches!(result.arena.returned()?,Returned::Boolean(0,F::ERROR_NO_MORE_FILES)) {
                self.cursors[index].complete()?;break;
            }
            let batch=match selected {Some(name)=>decode::ancestor_directory(result.bytes(BUFFER)?,name)?,
                None=>decode::directory(result.bytes(BUFFER)?)?};
            self.book.entries=self.book.entries.checked_add(batch.len()).ok_or(Error::Bounds)?;
            need(self.book.entries<=MAX_ENTRIES)?;all.extend(batch);
        }
        Ok(all)
    }
    fn recheck(&mut self,index:usize) -> Result<()> {
        let before=self.snapshots.get(&index).ok_or(Error::State)?.clone();
        need(self.stamp(index)?==before)?;
        let raw=self.descriptor(index)?;
        need(self.security.get(&index)==Some(&digest(&raw)?))?;
        Ok(())
    }
    fn update_parent(&mut self,parent:usize) -> Result<()> {
        let before=self.snapshots.get(&parent).ok_or(Error::State)?.clone();
        let after=self.stamp(parent)?;need(child_change(&before,&after))?;
        let raw=self.descriptor(parent)?;
        need(self.security.get(&parent)==Some(&digest(&raw)?))?;
        self.snapshots.insert(parent,after);Ok(())
    }
    fn os_location(&mut self) -> Result<usize> {
        self.gate()?;
        need(matches!(self.book.observe_user_once(),Err(Error::Unsafe)))?;self.gate()?;
        let token=self.book.process_token.ok_or(Error::State)?;
        super::hosted_tests::actual_elevated_primary_refusal(&mut self.book,token)?;self.gate()?;
        // The public ordinary routes remain refused and user stays None.
        let location=self.book.location(LocationKind::ProgramFiles)?;self.gate()?;
        need(self.book.user.is_none() && self.book.process_token==Some(token) && !self.book.roots_started)?;
        let root=fixed_path(&location.path)?;
        let mut paths:Vec<_>=root.ancestors().map(Path::to_path_buf).collect();paths.reverse();
        self.program_files=paths.len();
        fixture_capacity(self.ancestors,self.program_files,self.files.len()+self.program_files+5,2)?;
        need(Arc::ptr_eq(&self.book.identity,&location.book) && self.book.mapping(&location.drive)?==location.device)?;
        self.gate()?;
        let mut indices=Vec::new();
        for path in &paths {
            let index=self.directory(path,0,Some(AuthorityScope::AncestorOutsideVersion),None)?;
            let expected=format!("{}{}",location.device,path.to_str().ok_or(Error::Unsafe)?.strip_prefix(&location.drive).ok_or(Error::Unsafe)?);
            need(self.borrowed_call(index,Call::FinalName)?.text(NAME_UNITS,true)?==expected)?;
            need(self.borrowed_call(index,Call::VolumeName)?.text(261,false)?=="NTFS")?;
            let device=self.borrowed_call(index,Call::VolumeDevice)?;let raw=device.nt_bytes()?;
            need(raw.len()==size_of::<NS::FILE_FS_DEVICE_INFORMATION>()
                && decode::u32_at(raw,offset_of!(NS::FILE_FS_DEVICE_INFORMATION,DeviceType))?==FS::FILE_DEVICE_DISK
                && decode::u32_at(raw,offset_of!(NS::FILE_FS_DEVICE_INFORMATION,Characteristics))?&NS::FILE_REMOTE_DEVICE==0)?;
            indices.push(index);
        }
        for pair in indices.windows(2) {
            let name=self.paths[pair[1]].file_name().and_then(|s|s.to_str()).ok_or(Error::Unsafe)?.to_owned();
            self.recheck(pair[0])?;let entries=self.entries(pair[0],Some(&name))?;
            let matches:Vec<_>=entries.iter().filter(|e|e.name.eq_ignore_ascii_case(&name)).collect();
            let next=self.snapshots.get(&pair[1]).ok_or(Error::State)?;
            need(matches.len()==1 && matches[0].name==name && matches[0].kind==FileKind::Directory
                && matches[0].file_id==next.id && matches[0].attributes==next.attributes)?;
            self.recheck(pair[0])?;
        }
        self.location=Some(location);Ok(*indices.last().ok_or(Error::State)?)
    }
    fn root_inputs(&mut self) -> Result<()> {
        let mut paths:Vec<_>=self.root.ancestors().map(Path::to_path_buf).collect();paths.reverse();
        self.ancestors=paths.len();fixture_capacity(self.ancestors,0,self.ancestors,0)?;
        for path in paths {self.directory(&path,0,None,None)?;}
        Ok(())
    }
    fn fixture_paths(&self,manifest:&str) -> Result<[PathBuf;5]> {
        need(is_hex(manifest,64))?;
        let root=Path::new(&self.location.as_ref().ok_or(Error::State)?.path).join("Mobile Release Kit");
        let versions=root.join("versions");let target=versions.join("x86_64-pc-windows-msvc");
        let version=target.join(manifest);let python=version.join("python");
        Ok([root,versions,target,version,python])
    }
    fn seal(&mut self,index:usize) -> Result<(Stamp,Vec<u8>)> {
        let before=self.stamp(index)?;let old=self.descriptor(index)?;
        check_descriptor(&old,self.files[index].directory,false)?;
        let path=self.paths[index].clone();
        let pair=self.mutate(MutationKind::Seal,&path,self.files[index].directory,Some(index))?;
        mutation_return(pair.0,pair.1)?;
        let (after,raw)=self.checked(index,Some(AuthorityScope::ImmutableVersion),Some(true))?;
        need(acl_stamp(&before,&after) && raw!=old)?;
        Ok((after,raw))
    }
    fn verify_all_directories(&mut self) -> Result<()> {
        for role in 0..5 {
            let index=self.directories[role];self.recheck(index)?;
            let mut expected=BTreeMap::new();
            match role {
                0=>{expected.insert("versions".to_owned(),self.objects[1].sealed.clone());},
                1=>{expected.insert("x86_64-pc-windows-msvc".to_owned(),self.objects[2].sealed.clone());},
                2=>{let name=self.paths[self.directories[3]].file_name().and_then(|s|s.to_str()).ok_or(Error::Unsafe)?.to_owned();
                    expected.insert(name,self.objects[3].sealed.clone());},
                3=>{expected.insert("python".to_owned(),self.objects[4].sealed.clone());
                    for object in &self.objects[5..] {if !object.role.contains('/') {expected.insert(object.role.clone(),object.sealed.clone());}}},
                4=>{for object in &self.objects[5..] {if let Some(name)=object.role.strip_prefix("python/") {expected.insert(name.to_owned(),object.sealed.clone());}}},
                _=>return Err(Error::State),
            }
            let entries=self.entries(index,None)?;
            let own=self.snapshots.get(&index).ok_or(Error::State)?;
            let parent_path=self.paths[index].parent().ok_or(Error::Unsafe)?;
            let parent=self.paths.iter().position(|p|p==parent_path).and_then(|i|self.snapshots.get(&i));
            exact_entries(&entries,&expected,own,parent)?;self.recheck(index)?;
        }
        Ok(())
    }
    fn final_inputs(&mut self) -> Result<()> {
        let keys:Vec<_>=self.snapshots.keys().copied().collect();
        for index in keys {self.recheck(index)?;}
        let location=self.location.as_ref().ok_or(Error::State)?;
        self.book.recheck_location(location)?;self.gate()?;
        let token=self.book.process_token.ok_or(Error::State)?;
        super::hosted_tests::actual_elevated_primary_refusal(&mut self.book,token)?;self.gate()
    }
    fn unknown(&mut self) -> bool {
        self.book.is_unknown() || self.borrowed.is_some()
            || self.mutation.as_ref().is_some_and(|m|matches!(m.phase,Phase::Entered|Phase::Returned))
            || self.files.iter_mut().any(|file|{let b=file.body();b.active || matches!(b.state,SlotState::Acquiring|SlotState::Closing|SlotState::Unknown)})
    }
    fn settle(&mut self) -> Result<()> {
        if self.unknown() {return Err(Error::Unknown);}
        if self.mutation.as_ref().is_some_and(|m|m.phase==Phase::Prepared) {
            self.mutation_mut()?.phase=Phase::Complete;self.release_mutation()?;
        }
        if self.book.settle_once()!=CloseOutcome::Settled || !self.book.settled() {return Err(Error::Unknown);}
        for index in (0..self.files.len()).rev() {
            let owned=self.files[index].body().state==SlotState::Owned;
            self.files[index].close()?;
            if owned {self.closed+=1;}
        }
        need(self.closed==self.opened)?;
        self.gate()
    }
}


impl Fixture {
    fn publication_inputs(&mut self) -> Result<(Wire,Vec<Payload>,Vec<u8>,Vec<u8>)> {
        self.root_inputs()?;
        let precheck_name=if active_profile()?==PASSIVE_PROFILE {PASSIVE_PRECHECK_FILE}else{PRECHECK_FILE};
        let (_,pre_raw)=self.input(&self.root.join(precheck_name),TEXT_LIMIT)?;
        let pre=precheck(&pre_raw,&self.root)?;
        let (_,roster_raw)=self.input(&self.root.join(ROSTER_FILE),TEXT_LIMIT)?;
        bind_raw(&pre,"roster",&roster_raw)?;let items=roster(&roster_raw)?;
        let manifest=items.iter().find(|p|p.path=="manifest.json").ok_or(Error::State)?;
        let core=items.iter().find(|p|p.path=="core.zip").ok_or(Error::State)?;
        need(manifest.sha==pre.get("manifestSha256")? && core.sha==pre.get("coreSha256")?
            && items.iter().filter(|p|p.path!="manifest.json").map(|p|p.bytes as u64).sum::<u64>()==pre.number("payloadBytes",1<<30)?)?;
        need(self.image.to_str()==Some(pre.get("ownerArtifact")?))?;
        let (artifact,raw)=self.input(&self.image.clone(),PAYLOAD_LIMIT)?;
        need(raw.len() as u64==pre.number("ownerArtifactBytes",PAYLOAD_LIMIT as u64)?
            && digest(&raw)?==pre.get("ownerArtifactSha256")?
            && self.snapshots.get(&artifact).ok_or(Error::State)?.wire()==pre.get("ownerArtifactIdentity")?)?;
        self.directory(&self.root.join("runtime"),0,None,None)?;
        self.directory(&self.root.join("runtime").join("python"),0,None,None)?;
        Ok((pre,items,pre_raw,roster_raw))
    }
    fn source_paths(&self,manifest:&str) -> Result<[PathBuf;5]> {
        need(is_hex(manifest,64))?;
        let p=Path::new(&self.location.as_ref().ok_or(Error::State)?.path).join("Mobile Release Kit");
        let input=p.join("runtime-input");let target=input.join("x86_64-pc-windows-msvc");
        let version=target.join(manifest);let python=version.join("python");
        Ok([p,input,target,version,python])
    }
    fn production_inputs(&mut self) -> Result<(Wire,Vec<Payload>,Vec<u8>,Vec<u8>)> {
        need(matches!(active_profile()?,PRODUCTION_PROFILE|PASSIVE_PROFILE))?;
        let values=self.publication_inputs()?;let pre=&values.0;
        let path=fixed_path(pre.get("helperArtifact")?)?;
        // Separate original from the executing helper, admitted only after its
        // foreground role (if any) has returned. No binary loader or invocation.
        let (index,raw)=self.input(&path,PAYLOAD_LIMIT)?;
        need(raw.len() as u64==pre.number("helperArtifactBytes",PAYLOAD_LIMIT as u64)?
            && digest(&raw)?==pre.get("helperArtifactSha256")?
            && self.snapshots.get(&index).ok_or(Error::State)?.wire()==pre.get("helperArtifactIdentity")?)?;
        self.recheck(index)?;self.close(index)?;self.pop_closed(index)?;
        Ok(values)
    }
    fn parent_link(&mut self,parent:usize,index:usize) -> Result<()> {
        self.recheck(parent)?;self.recheck(index)?;
        let name=self.paths[index].file_name().and_then(|s|s.to_str()).ok_or(Error::Unsafe)?.to_owned();
        let entries=self.entries(parent,Some(&name))?;
        let selected:Vec<_>=entries.iter().filter(|e|e.name.eq_ignore_ascii_case(&name)).collect();
        let stamp=self.snapshots.get(&index).ok_or(Error::State)?;
        need(selected.len()==1 && selected[0].name==name && selected[0].kind==FileKind::Directory
            && selected[0].file_id==stamp.id && selected[0].attributes==stamp.attributes
            && self.snapshots.get(&parent).is_some_and(|s|s.volume==stamp.volume))?;
        self.recheck(parent)?;self.recheck(index)
    }
    fn observed_directory(&mut self,index:usize,role:&str) -> Result<ObservedObject> {
        self.recheck(index)?;
        Ok(ObservedObject {role:role.to_owned(),directory:true,
            stamp:self.snapshots.get(&index).ok_or(Error::State)?.clone(),
            security:self.security.get(&index).ok_or(Error::State)?.clone(),sha:"-".to_owned(),inventory:String::new()})
    }
    fn observed_inventory(&mut self,index:usize,objects:&[ObservedObject],role:&str,manifest:&str,stage:bool) -> Result<String> {
        self.recheck(index)?;
        let expected=child_rows(objects,role,manifest,stage)?;
        let entries=self.entries(index,None)?;
        let own=self.snapshots.get(&index).ok_or(Error::State)?;
        let parent_path=self.paths[index].parent().ok_or(Error::Unsafe)?;
        let parent=self.paths.iter().position(|p|p==parent_path).and_then(|i|self.snapshots.get(&i));
        exact_entries(&entries,&expected,own,parent)?;self.recheck(index)?;
        // All actual non-dot entries have just been checked for exact names,
        // attributes, kinds and full128-bit IDs, including absence of extras.
        inventory_sha(&expected)
    }
    fn observation_record(&mut self,pre:&Wire,pre_raw:&[u8],roster_raw:&[u8],test:&str,objects:usize,proofs:usize) -> Result<Wire> {
        let mut record=Wire {values:BTreeMap::new()};
        record.copy(pre,&["profile","sourceSha","sourceTree","runId","attempt","manifestSha256",
            "protocolSha256","inventorySha256","coreSha256","payloadFiles","payloadBytes"])?;
        for (key,from) in [("artifactBytes","ownerArtifactBytes"),("artifactSha256","ownerArtifactSha256"),
            ("artifactIdentity","ownerArtifactIdentity")] {record.put(key,pre.get(from)?);}
        record.put("observerTest",test);record.put("precheckBytes",pre_raw.len());record.put("precheckSha256",digest(pre_raw)?);
        record.put("rosterBytes",roster_raw.len());record.put("rosterSha256",digest(roster_raw)?);
        for (key,value) in [("sourceReaders",self.source_readers),("payloadWriters",self.writers),
            ("postcheckReaders",self.postcheck_readers),("objectCount",objects),("proofCount",proofs)] {record.put(key,value);}
        for (key,value) in [("parentBookSettled","true"),("unknown","false"),
            ("actualFixedProducerObserved",if matches!(test,OBSERVE_AFTER|PASSIVE_OBSERVE) {"true"}else{"false"}),
            ("runtimeConsumerEnabled","false"),("pythonExecuted","false"),("appLaunched","false"),
            ("resultCloseGate","original-observer-exit-zero-required")] {record.put(key,value);}
        Ok(record) // Counts of original closes are supplied only AFTER settle().
    }
    fn stage_source(&mut self) -> Result<(Wire,Vec<ObservedObject>,Vec<ProducerProof>)> {
        let passive=active_profile()?==PASSIVE_PROFILE;
        outcome(if passive {"MRK_WINDOWS_PASSIVE_PREFLIGHT_STEP_OUTCOME"}else{"MRK_WINDOWS_ORDINARY_PREFLIGHT_STEP_OUTCOME"})?;
        let (pre,items,pre_raw,roster_raw)=self.production_inputs()?;
        let program_files=self.os_location()?;let paths=self.source_paths(pre.get("manifestSha256")?)?;
        fixture_capacity(self.ancestors,self.program_files,self.files.len()+5,2)?;
        let mut directories=Vec::with_capacity(5);
        for (role,path) in paths.iter().enumerate() {
            let parent=if role==0 {program_files}else{directories[role-1]};
            self.recheck(parent)?;
            let pair=self.mutate(MutationKind::Directory,path,true,None)?;
            // Fresh P is mandatory. Occupancy cannot reach an open/adopt/seal.
            mutation_return(pair.0,pair.1)?;self.update_parent(parent)?;
            let index=self.directory(path,if role==0 {FS::WRITE_DAC}else{0},Some(AuthorityScope::ImmutableVersion),Some(false))?;
            let stamp=self.snapshots.get(&index).ok_or(Error::State)?;
            need(directories.iter().all(|i|self.snapshots.get(i).is_some_and(|s|s.volume==stamp.volume && s.id!=stamp.id)))?;
            directories.push(index);
        }
        let mut leaves=Vec::with_capacity(47);
        for item in &items {
            let (source,raw)=self.input(&payload_path(&self.root.join("runtime"),&item.path)?,PAYLOAD_LIMIT)?;
            self.source_readers+=1;need(raw.len()==item.bytes && digest(&raw)?==item.sha)?;
            let parent=if item.path.starts_with("python/") {directories[4]}else{directories[3]};
            self.recheck(parent)?;
            let destination=payload_path(&paths[3],&item.path)?;
            let writer=self.create_file(&destination)?;self.update_parent(parent)?;
            let (created,initial)=self.checked(writer,Some(AuthorityScope::ImmutableVersion),Some(false))?;
            need(created.size==0 && created.volume==self.snapshots.get(&directories[0]).ok_or(Error::State)?.volume)?;
            self.files[writer].write_fixture_payload(&raw)?;self.gate()?;
            let (written,written_sd)=self.checked(writer,Some(AuthorityScope::ImmutableVersion),Some(false))?;
            need(payload_change(&created,&written,item.bytes) && written_sd==initial)?;
            self.close(writer)?;self.pop_closed(writer)?;
            // Trusted-only source: no grant to ordinary users at any descendant.
            let (reader,readback)=self.input(&destination,PAYLOAD_LIMIT)?;self.postcheck_readers+=1;
            let (stamp,sd)=self.checked(reader,Some(AuthorityScope::ImmutableVersion),Some(false))?;
            need(payload_change(&written,&stamp,item.bytes) && stamp.allocation==written.allocation
                && sd==initial && readback.len()==item.bytes && digest(&readback)?==item.sha)?;
            leaves.push(ObservedObject {role:format!("source/{}",item.path),directory:false,stamp,
                security:digest(&sd)?,sha:item.sha.clone(),inventory:"-".to_owned()});
            self.recheck(reader)?;self.close(reader)?;self.pop_closed(reader)?;
            self.recheck(source)?;self.close(source)?;self.pop_closed(source)?;self.recheck(parent)?;
        }
        need(self.source_readers==47 && self.writers==47 && self.postcheck_readers==47)?;
        // P alone becomes an ordinary-readable/traversable shared ancestor.
        // The source directories/files remain their original trusted-only ACLs.
        let (stamp,sd)=self.seal(directories[0])?;
        self.snapshots.insert(directories[0],stamp);self.security.insert(directories[0],digest(&sd)?);
        let roles=observation_roles(true);let mut objects=Vec::with_capacity(52);
        for (index,role) in directories.iter().zip(&roles[..5]) {objects.push(self.observed_directory(*index,role)?);}
        objects.extend(leaves);
        for ordinal in 0..5 {
            objects[ordinal].inventory=self.observed_inventory(directories[ordinal],&objects,&roles[ordinal],pre.get("manifestSha256")?,true)?;
        }
        self.parent_link(program_files,directories[0])?;self.final_inputs()?;
        let record=self.observation_record(&pre,&pre_raw,&roster_raw,if passive {PASSIVE_STAGE}else{STAGE_INPUT},objects.len(),0)?;
        Ok((record,objects,Vec::new()))
    }
    fn read_producer_proofs(&mut self,count:usize) -> Result<(Vec<Vec<u8>>,Vec<ProducerProof>)> {
        let passive=active_profile()?==PASSIVE_PROFILE;
        need(!passive || count==3)?;
        need(count==3 || count==6)?;
        let mut raw=Vec::with_capacity(count);let mut proofs=Vec::with_capacity(count);
        let roles=if passive {PASSIVE_SETUP_PROOFS.as_slice()}else{PRODUCER_PROOFS.as_slice()};
        for (role,name,limit) in roles.iter().take(count) {
            let (index,bytes)=self.input(&self.root.join(name),*limit)?;
            self.recheck(index)?;self.close(index)?;self.pop_closed(index)?;
            proofs.push(ProducerProof {role:(*role).to_owned(),bytes:bytes.len(),sha:digest(&bytes)?});raw.push(bytes);
        }
        Ok((raw,proofs))
    }
    fn observe_branch(&mut self,paths:&[PathBuf;5],source:bool,items:&[Payload],manifest:&str) -> Result<Vec<ObservedObject>> {
        fixture_capacity(self.ancestors,self.program_files,self.files.len()+4,1)?;
        let mut directories=Vec::with_capacity(4);let mut objects=Vec::with_capacity(51);
        for (ordinal,path) in paths[1..].iter().enumerate() {
            let index=self.directory(path,0,Some(AuthorityScope::ImmutableVersion),if source {Some(false)}else{None})?;
            if !source {production_descriptor(&self.descriptor(index)?,true,None)?;self.recheck(index)?;}
            directories.push(index);
            objects.push(self.observed_directory(index,if source {SOURCE_DIRECTORY_ROLES[ordinal]}else{DIRECTORY_ROLES[ordinal+1]})?);
        }
        for item in items {
            let path=payload_path(&paths[3],&item.path)?;
            let (index,raw)=self.input(&path,PAYLOAD_LIMIT)?;self.postcheck_readers+=1;
            let (stamp,sd)=self.checked(index,Some(AuthorityScope::ImmutableVersion),if source {Some(false)}else{None})?;
            if !source {production_descriptor(&sd,false,Some(&item.path))?;}
            need(raw.len()==item.bytes && digest(&raw)?==item.sha)?;
            objects.push(ObservedObject {role:if source {format!("source/{}",item.path)}else{item.path.clone()},
                directory:false,stamp,security:digest(&sd)?,sha:item.sha.clone(),inventory:"-".to_owned()});
            self.recheck(index)?;self.close(index)?;self.pop_closed(index)?;
        }
        for ordinal in 0..4 {
            let role=objects[ordinal].role.clone();
            objects[ordinal].inventory=self.observed_inventory(directories[ordinal],&objects,&role,manifest,false)?;
        }
        // Serialize branches under the original40-handle cap. Known original
        // closes only: no uncertain close is popped or replaced by a later open.
        for index in directories.into_iter().rev() {self.recheck(index)?;self.close(index)?;self.pop_closed(index)?;}
        Ok(objects)
    }
    fn observe_producer(&mut self,after:bool) -> Result<(Wire,Vec<ObservedObject>,Vec<ProducerProof>)> {
        let passive=active_profile()?==PASSIVE_PROFILE;
        need(!passive || !after)?;
        let proof_count=if after {6}else{3};production_outcomes(proof_count)?;
        let (pre,items,pre_raw,roster_raw)=self.production_inputs()?;
        let (proof_raw,proofs)=self.read_producer_proofs(proof_count)?;
        let (staged,before)=checked_producer_chain(&pre,&pre_raw,&roster_raw,&items,&proof_raw)?;
        let program_files=self.os_location()?;let source_paths=self.source_paths(pre.get("manifestSha256")?)?;
        let output_paths=self.fixture_paths(pre.get("manifestSha256")?)?;
        let p=self.directory(&source_paths[0],0,Some(AuthorityScope::AncestorOutsideVersion),None)?;
        production_descriptor(&self.descriptor(p)?,true,None)?;self.recheck(p)?;
        self.parent_link(program_files,p)?;
        let shared=self.observed_directory(p,"suffix-mrk")?;
        let source=self.observe_branch(&source_paths,true,&items,pre.get("manifestSha256")?)?;
        let output=self.observe_branch(&output_paths,false,&items,pre.get("manifestSha256")?)?;
        let mut objects=Vec::with_capacity(103);objects.push(shared);
        objects.extend_from_slice(&source[..4]);objects.extend_from_slice(&output[..4]);
        objects.extend_from_slice(&source[4..]);objects.extend_from_slice(&output[4..]);
        objects[0].inventory=self.observed_inventory(p,&objects,"suffix-mrk",pre.get("manifestSha256")?,false)?;
        source_unchanged(&staged,&objects)?;
        if after {observations_unchanged(before.as_deref().ok_or(Error::Unsafe)?,&objects)?;}else{need(before.is_none())?;}
        need(objects.len()==103 && self.source_readers==0 && self.writers==0 && self.postcheck_readers==94
            && self.mutation.is_none() && self.dispositions==0)?;
        self.final_inputs()?;
        let test=if passive {PASSIVE_OBSERVE}else if after {OBSERVE_AFTER}else{OBSERVE_BEFORE};
        let record=self.observation_record(&pre,&pre_raw,&roster_raw,test,objects.len(),proofs.len())?;
        Ok((record,objects,proofs))
    }
    fn publish(&mut self) -> Result<Wire> {
        let (pre,items,pre_raw,roster_raw)=self.publication_inputs()?;
        let program_files=self.os_location()?;
        let paths=self.fixture_paths(pre.get("manifestSha256")?)?;
        fixture_capacity(self.ancestors,self.program_files,self.files.len()+5,2)?;
        for (role,path) in paths.iter().enumerate() {
            let parent=if role==0 {program_files}else if role==4 {self.directories[3]}else{self.directories[role-1]};
            self.recheck(parent)?;
            let pair=self.mutate(MutationKind::Directory,path,true,None)?;
            // Collision is terminal before any open/adoption/ACL/copy. This call
            // returns no creation HANDLE; the metadata original below is distinct.
            mutation_return(pair.0,pair.1)?;
            self.update_parent(parent)?;
            let scope=if role<3 {AuthorityScope::AncestorOutsideVersion}else{AuthorityScope::ImmutableVersion};
            let index=self.directory(path,FS::WRITE_DAC,Some(scope),Some(false))?;
            let stamp=self.snapshots.get(&index).ok_or(Error::State)?.clone();
            need(!self.objects.iter().any(|o|o.created.volume==stamp.volume && o.created.id==stamp.id))?;
            let security=self.security.get(&index).ok_or(Error::State)?.clone();
            self.objects.push(Object {role:DIRECTORY_ROLES[role].to_owned(),directory:true,created:stamp.clone(),sealed:stamp,
                initial_security:security.clone(),sealed_security:security,sha:"-".to_owned()});
            self.directories.push(index);
        }
        for item in &items {
            let source_path=payload_path(&self.root.join("runtime"),&item.path)?;
            let (source,raw)=self.input(&source_path,PAYLOAD_LIMIT)?;
            self.source_readers+=1;
            need(raw.len()==item.bytes && digest(&raw)?==item.sha)?;
            let destination=payload_path(&paths[3],&item.path)?;
            let parent=if item.path.starts_with("python/") {self.directories[4]}else{self.directories[3]};
            self.recheck(parent)?;
            let writer=self.create_file(&destination)?;
            self.update_parent(parent)?;
            let (created,initial)=self.checked(writer,Some(AuthorityScope::ImmutableVersion),Some(false))?;
            need(created.size==0 && created.volume==self.objects[3].created.volume
                && !self.objects.iter().any(|o|o.created.volume==created.volume && o.created.id==created.id))?;
            self.files[writer].write_fixture_payload(&raw)?;self.gate()?;
            let written=self.stamp(writer)?;need(payload_change(&created,&written,item.bytes))?;
            let (before_close,sealed_security)=self.seal(writer)?;
            need(before_close.size==written.size && before_close.allocation==written.allocation)?;
            self.close(writer)?;self.pop_closed(writer)?;
            // A new reader is only a postcondition AFTER the original writer
            // closed. It cannot repair or stand in for that writer's settlement.
            let (reader,check)=self.input(&destination,PAYLOAD_LIMIT)?;self.postcheck_readers+=1;
            let (sealed,readback)=self.checked(reader,Some(AuthorityScope::ImmutableVersion),Some(true))?;
            need(payload_change(&before_close,&sealed,item.bytes) && sealed.allocation==before_close.allocation
                && readback==sealed_security && check.len()==item.bytes && digest(&check)?==item.sha)?;
            self.objects.push(Object {role:item.path.clone(),directory:false,created,sealed,
                initial_security:digest(&initial)?,sealed_security:digest(&readback)?,sha:item.sha.clone()});
            self.close(reader)?;self.pop_closed(reader)?;
            self.recheck(source)?;self.close(source)?;self.pop_closed(source)?;self.recheck(parent)?;
        }
        need(self.objects.len()==52 && self.source_readers==47 && self.writers==47 && self.postcheck_readers==47)?;
        // Seal descendants and outer suffixes first; VERSION is the last grant.
        for role in [4usize,0,1,2,3] {
            let index=self.directories[role];self.recheck(index)?;
            let (stamp,raw)=self.seal(index)?;
            self.snapshots.insert(index,stamp.clone());self.security.insert(index,digest(&raw)?);
            self.objects[role].sealed=stamp;self.objects[role].sealed_security=digest(&raw)?;
        }
        self.verify_all_directories()?;
        need(!self.occupied)?;self.occupied=true;
        let pair=self.mutate(MutationKind::Directory,&paths[0],true,None)?;
        need(pair==(0,F::ERROR_ALREADY_EXISTS))?;
        for index in self.directories.clone() {self.recheck(index)?;}
        for (item,object) in items.iter().zip(self.objects[5..].to_vec()) {
            let (reader,raw)=self.input(&payload_path(&paths[3],&item.path)?,PAYLOAD_LIMIT)?;self.postcheck_readers+=1;
            let (stamp,security)=self.checked(reader,Some(AuthorityScope::ImmutableVersion),Some(true))?;
            need(stamp==object.sealed && digest(&security)?==object.sealed_security
                && raw.len()==item.bytes && digest(&raw)?==item.sha)?;
            self.close(reader)?;self.pop_closed(reader)?;
        }
        self.final_inputs()?;
        let mut record=Wire {values:BTreeMap::new()};
        record.copy(&pre,&["profile","sourceSha","sourceTree","runId","attempt","manifestSha256",
            "protocolSha256","inventorySha256","coreSha256","payloadFiles","payloadBytes"])?;
        for (key,from) in [("artifactBytes","ownerArtifactBytes"),("artifactSha256","ownerArtifactSha256"),
            ("artifactIdentity","ownerArtifactIdentity")] {record.put(key,pre.get(from)?);}
        record.put("publisherTest",PUBLISHER);record.put("precheckBytes",pre_raw.len());record.put("precheckSha256",digest(&pre_raw)?);
        record.put("rosterBytes",roster_raw.len());record.put("rosterSha256",digest(&roster_raw)?);
        for (key,value) in [("createdFiles",47),("createdDirectories",5),("sourceReaders",self.source_readers),
            ("sourceReadersClosed",self.source_readers),("payloadWriters",self.writers),("payloadWritersClosed",self.writers),
            ("postcheckReaders",self.postcheck_readers),("postcheckReadersClosed",self.postcheck_readers),
            ("occupiedCreateCalls",1),("occupiedCreateError",F::ERROR_ALREADY_EXISTS as usize),("objectCount",self.objects.len())] {
            record.put(key,value);
        }
        for (key,value) in [("parentBookSettled","true"),("occupiedObjectsUnchanged","true"),("unknown","false"),
            ("productionEnabled","false"),("resultCloseGate","original-publisher-exit-zero-required")] {record.put(key,value);}
        Ok(record) // No receipt write, or original-close claim, before settle().
    }
    fn absent(&mut self,parent:usize,name:&str) -> Result<()> {
        self.recheck(parent)?;
        // dispose() incremented this bounded epoch only after genuine original
        // disposition return; its once-only close already completed.
        need(self.dispositions>0 && self.dispositions<=52)?;
        let entries=self.entries_at(parent,Some(name),self.dispositions)?;
        need(!entries.iter().any(|e|e.name.eq_ignore_ascii_case(name)))?;
        self.recheck(parent)
    }
    fn dispose(&mut self,index:usize,parent:usize) -> Result<()> {
        self.recheck(index)?;self.recheck(parent)?;
        let path=self.paths[index].clone();
        let name=path.file_name().and_then(|s|s.to_str()).ok_or(Error::Unsafe)?.to_owned();
        let pair=self.mutate(MutationKind::Disposition,&path,self.files[index].directory,Some(index))?;
        mutation_return(pair.0,pair.1)?;self.dispositions+=1;
        self.close(index)?;
        self.snapshots.remove(&index);self.security.remove(&index);
        self.update_parent(parent)?;
        self.absent(parent,&name)?;
        let role=match self.directories.iter().position(|i|*i==index) {
            Some(i)=>DIRECTORY_ROLES[i].to_owned(),
            None=>path.strip_prefix(&self.paths[self.directories[3]]).map_err(|_|Error::Unsafe)?
                .to_str().ok_or(Error::Unsafe)?.replace('\\',"/"),
        };
        let ordinal=self.objects.iter().position(|o|o.role==role).ok_or(Error::State)?;
        need(self.retired_mask & (1u64<<ordinal)==0)?;self.retired_mask |= 1u64<<ordinal;Ok(())
    }
    fn retire(&mut self) -> Result<Wire> {
        for key in ["MRK_WINDOWS_ORDINARY_FINALIZE_STEP_OUTCOME","MRK_WINDOWS_FULLWALK_FINALIZE_STEP_OUTCOME",
            "MRK_WINDOWS_FULLWALK_OWNER_STEP_OUTCOME","MRK_WINDOWS_FIXTURE_FINALIZE_STEP_OUTCOME",
            "MRK_WINDOWS_PUBLISHER_STEP_OUTCOME","MRK_WINDOWS_ORDINARY_OWNER_STEP_OUTCOME",
            "MRK_WINDOWS_FULLWALK_PREFLIGHT_STEP_OUTCOME"] {outcome(key)?;}
        self.root_inputs()?;
        let (_,pre_raw)=self.input(&self.root.join(PRECHECK_FILE),TEXT_LIMIT)?;let pre=precheck(&pre_raw,&self.root)?;
        let (_,roster_raw)=self.input(&self.root.join(ROSTER_FILE),TEXT_LIMIT)?;bind_raw(&pre,"roster",&roster_raw)?;
        let items=roster(&roster_raw)?;
        let (_,published_raw)=self.input(&self.root.join(PUBLICATION_FILE),OWNER_LIMIT)?;
        let (published,objects)=publication(&published_raw,&items)?;
        bind_raw(&published,"precheck",&pre_raw)?;bind_raw(&published,"roster",&roster_raw)?;
        let (_,envelope_raw)=self.input(&self.root.join(PREREQUISITE_FILE),TEXT_LIMIT)?;
        let envelope=Wire::parse(&envelope_raw,PREREQUISITE_HEADER,&PREREQUISITE_FIELDS,TEXT_LIMIT)?;
        envelope.binding()?;bind_raw(&envelope,"precheck",&pre_raw)?;bind_raw(&envelope,"roster",&roster_raw)?;
        bind_raw(&envelope,"publisherReceipt",&published_raw)?;
        for key in ["publisherStepOutcome","publisherFinalizeStepOutcome","ordinaryOwnerStepOutcome","ordinaryFinalizeStepOutcome"] {
            envelope.equal(key,"success")?;
        }
        envelope.equal("prerequisitesOnlyNotNativeWalk","true")?;
        envelope.equal("envelopeCloseGate","original-fullwalk-preflight-step-success-required")?;
        let (_,request_raw)=self.input(&self.root.join(FULLWALK_REQUEST),LIMIT)?;
        let request=FullwalkRequest::parse(&request_raw)?;
        request.at_root(&self.root)?;request.compiled_traced(&mut InputTrace::default())?;
        request.check_commands(&mut InputTrace::default())?;
        need(request.publication_bytes==envelope_raw.len() && request.publication_sha==digest(&envelope_raw)?
            && request.owner.path==self.image.to_str().ok_or(Error::Unsafe)?
            && request.owner.identity==envelope.get("ownerArtifactAfterOrdinaryIdentity")?)?;
        let (artifact,raw)=self.input(&self.image.clone(),PAYLOAD_LIMIT)?;
        need(request.owner.matches(self.snapshots.get(&artifact).ok_or(Error::State)?)
            && raw.len()==request.owner.bytes && digest(&raw)?==request.owner.sha
            && request.owner.sha==pre.get("ownerArtifactSha256")?)?;
        for (key,value) in [("manifestSha256",request.manifest_sha.as_str()),("protocolSha256",request.protocol_sha.as_str()),
            ("inventorySha256",request.inventory_sha.as_str()),("coreSha256",request.core_sha.as_str())] {
            pre.equal(key,value)?;envelope.equal(key,value)?;published.equal(key,value)?;
        }
        for record in [&pre,&envelope,&published] {
            need(record.number("payloadFiles",2047)?==request.files as u64
                && record.number("payloadBytes",1<<30)?==request.payload_bytes)?;
        }
        original_epoch(pre.get("ownerArtifactIdentity")?,envelope.get("ownerArtifactAfterOrdinaryIdentity")?)?;
        need(request.owner.bytes as u64==pre.number("ownerArtifactBytes",PAYLOAD_LIMIT as u64)?
            && request.owner.path==pre.get("ownerArtifact")? && request.app.path==pre.get("appArtifact")?
            && request.app.sha==pre.get("appArtifactSha256")? && request.app.identity==pre.get("appArtifactIdentity")?
            && request.app.bytes as u64==pre.number("appArtifactBytes",APP_ARTIFACT_LIMIT as u64)?)?;
        for (role,artifact) in [("app",&request.app),("owner",&request.owner)] {
            need(artifact.messages_bytes as u64==pre.number(&format!("{role}CompileMessagesBytes"),16<<20)?
                && artifact.messages_sha==pre.get(&format!("{role}CompileMessagesSha256"))?
                && artifact.argv_sha==pre.get(&format!("{role}CompileArgvSha256"))?)?;
        }
        for (key,object,id) in std::iter::once(("versionIdentity",&objects[3],request.version))
            .chain(SELECTED.iter().zip(request.selected).zip(["selectedPythonIdentity","selectedBootstrapIdentity","selectedCoreIdentity"])
                .map(|((name,id),key)| (key,objects.iter().find(|o|o.role==*name).expect("closed47 roster"),id))) {
            envelope.equal(key,&identity(&object.sealed))?;
            need(object.sealed.volume==id.volume_serial && object.sealed.id==id.file_id)?;
        }
        let program_files=self.os_location()?;
        let paths=self.fixture_paths(pre.get("manifestSha256")?)?;
        self.objects=objects;
        for (role,path) in paths.iter().enumerate() {
            let index=self.directory(path,FS::DELETE,Some(AuthorityScope::ImmutableVersion),Some(true))?;
            need(self.snapshots.get(&index)==Some(&self.objects[role].sealed)
                && self.security.get(&index)==Some(&self.objects[role].sealed_security))?;
            self.directories.push(index);
        }
        // Verify all47 files and all five exact directories BEFORE the first
        // disposition. A second post-run original is acquired for each deletion.
        for (item,object) in items.iter().zip(self.objects[5..].to_vec()) {
            let (index,raw)=self.input(&payload_path(&paths[3],&item.path)?,PAYLOAD_LIMIT)?;
            let (stamp,security)=self.checked(index,Some(AuthorityScope::ImmutableVersion),Some(true))?;
            need(stamp==object.sealed && digest(&security)?==object.sealed_security
                && raw.len()==item.bytes && digest(&raw)?==item.sha)?;
            self.close(index)?;self.pop_closed(index)?;
        }
        self.verify_all_directories()?;
        for (item,object) in items.iter().zip(self.objects[5..].to_vec()) {
            let path=payload_path(&paths[3],&item.path)?;
            let index=self.open(&path,false,FS::FILE_GENERIC_READ|FS::DELETE)?;
            let (stamp,security)=self.checked(index,Some(AuthorityScope::ImmutableVersion),Some(true))?;
            need(stamp==object.sealed && digest(&security)?==object.sealed_security)?;
            let raw=self.files[index].read(PAYLOAD_LIMIT)?;self.gate()?;
            need(raw.len()==item.bytes && digest(&raw)?==item.sha && self.stamp(index)?==stamp)?;
            self.snapshots.insert(index,stamp);self.security.insert(index,digest(&security)?);
            let parent=if item.path.starts_with("python/") {self.directories[4]}else{self.directories[3]};
            self.dispose(index,parent)?;self.pop_closed(index)?;
        }
        for role in [4usize,3,2,1,0] {
            let index=self.directories[role];
            let parent=if role==0 {program_files}else if role==4 {self.directories[3]}else{self.directories[role-1]};
            let current=self.snapshots.get(&index).ok_or(Error::State)?;
            need(same_object(current,&self.objects[role].sealed)
                && self.security.get(&index)==Some(&self.objects[role].sealed_security))?;
            // NTFS itself refuses a nonempty directory. No recursion, another
            // cursor/retry, sharing-mode workaround, or foreign-entry deletion.
            self.dispose(index,parent)?;
        }
        need(self.dispositions==52 && self.retired_mask.count_ones()==52)?;self.final_inputs()?;
        let mut result=Wire {values:BTreeMap::new()};
        result.copy(&pre,&["sourceSha","sourceTree","runId","attempt"])?;
        result.put("artifactSha256",request.owner.sha);result.put("requestSha256",digest(&request_raw)?);
        result.put("publisherReceiptSha256",digest(&published_raw)?);
        Ok(result)
    }
}

fn fixture_run(retirement:bool,start:Instant) -> Result<()> {
    need(super::ordinary_owner::FULLWALK_PREREQUISITES_REVIEWED)?;
    profile()?;
    need(active_profile()? == PROFILE)?; // neither legacy publisher nor retirement enters the new lane
    if !retirement {outcome("MRK_WINDOWS_ORDINARY_PREFLIGHT_STEP_OUTCOME")?;}
    let root=fixed_path(&std::env::var("MRK_DESKTOP_CI_ROOT").map_err(|_|Error::State)?)?;
    let temp=fixed_path(&std::env::var("RUNNER_TEMP").map_err(|_|Error::State)?)?;
    let run=std::env::var("GITHUB_RUN_ID").map_err(|_|Error::State)?;
    need(decimal(&run) && root==temp.join(format!("mrk-windows-installed-native-{run}-1"))
        && std::env::current_dir().map_err(|_|Error::Unavailable)?==root)?;
    let image=std::env::current_exe().map_err(|_|Error::Unavailable)?;
    args_are(if retirement {RETIRE}else{PUBLISHER},&image)?;
    let mut original=Fixture::new(start,root,image)?;
    let observed=std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if retirement {original.retire()}else{original.publish()}
    }));
    let observed=match observed {Ok(result)=>result,Err(_)=>Err(Error::Unknown)};
    if matches!(observed,Err(Error::Unknown)) || original.unknown() {
        diagnostic_data("fixture-original-operation",None,true,None);
        loop {std::thread::park();std::hint::black_box(&mut original);}
    }
    let settled=std::panic::catch_unwind(std::panic::AssertUnwindSafe(||original.settle()))
        .unwrap_or(Err(Error::Unknown));
    if matches!(settled,Err(Error::Unknown)) || original.unknown() {
        diagnostic_data("fixture-original-close",None,true,None);
        loop {std::thread::park();std::hint::black_box(&mut original);}
    }
    if observed.is_err() || settled.is_err() {
        // The52-bit row mask identifies exactly the known absent postconditions
        // without publishing paths, full IDs or pretending a disposition is close.
        eprintln!("MRK_WINDOWS_FIXTURE_REFUSED={{\"retirement\":{retirement},\"confirmedAbsentMask\":\"{:013x}\",\"dispositionCalls\":{},\"fileOriginalsClosed\":{},\"unknown\":false}}",
            original.retired_mask,original.dispositions,original.closed);
    }
    let mut record=observed?;settled?;
    let (name,raw)=if retirement {
        let text=format!("{{\"schemaVersion\":1,\"profile\":\"{PROFILE}\",\"sourceSha\":\"{}\",\"sourceTree\":\"{}\",\"runId\":\"{}\",\"attempt\":1,\"retirementTest\":\"{RETIRE}\",\"artifactSha256\":\"{}\",\"requestSha256\":\"{}\",\"publisherReceiptSha256\":\"{}\",\"deletedFiles\":47,\"deletedDirectories\":5,\"absentPostconditions\":52,\"dispositionCalls\":{},\"fileOriginals\":{},\"fileOriginalsClosed\":{},\"parentBookSettled\":true,\"unknown\":false,\"productionEnabled\":false,\"resultCloseGate\":\"original-retirement-exit-zero-required\"}}\n",
            record.get("sourceSha")?,record.get("sourceTree")?,record.get("runId")?,record.get("artifactSha256")?,
            record.get("requestSha256")?,record.get("publisherReceiptSha256")?,original.dispositions,original.opened,original.closed);
        need(text.len()<=LIMIT)?;("fullwalk-retirement-result.private.json",text.into_bytes())
    }else {
        record.put("fileOriginals",original.opened);record.put("fileOriginalsClosed",original.closed);
        let mut raw=record.encoded(PUBLICATION_HEADER,&PUBLICATION_FIELDS,OWNER_LIMIT)?;
        for object in &original.objects {raw.extend(object.line().as_bytes());}
        need(raw.len()<=OWNER_LIMIT)?;(PUBLICATION_FILE,raw)
    };
    original.gate()?;
    write_fixture_record(&original.root.join(name),&raw,if retirement {LIMIT}else{OWNER_LIMIT},original.end)?;
    original.gate() // Own result writer/close must precede original exit zero.
}
#[test]
#[ignore = "fixed protected synthetic fixture publisher; separately reviewed fullwalk profile only"]
fn hosted_publish_protected_version_fixture() -> Result<()> {
    let start=Instant::now();fixture_run(false,start)
}
#[test]
#[ignore = "exact52 owned fixture identities, only after both original owner finalizers succeed"]
fn hosted_retire_protected_version_fixture() -> Result<()> {
    let start=Instant::now();fixture_run(true,start)
}

// A separate test-only entry, sharing Fixture's original ownership/settlement
// seam. Neither reader can enter a fixture mutation or the legacy retire path.
fn producer_observation_run(test:&str,start:Instant) -> Result<()> {
    let passive=matches!(test,PASSIVE_STAGE|PASSIVE_OBSERVE);
    need(if passive {!cfg!(feature="runtime-publication") && !cfg!(feature="qualification-result")}
        else {super::ordinary_owner::FULLWALK_PREREQUISITES_REVIEWED})?;
    profile()?;
    need(if passive {active_profile()?==PASSIVE_PROFILE}
        else {active_profile()?==PRODUCTION_PROFILE && matches!(test,STAGE_INPUT|OBSERVE_BEFORE|OBSERVE_AFTER)})?;
    let root=fixed_path(&std::env::var("MRK_DESKTOP_CI_ROOT").map_err(|_|Error::State)?)?;
    let temp=fixed_path(&std::env::var("RUNNER_TEMP").map_err(|_|Error::State)?)?;
    let run=std::env::var("GITHUB_RUN_ID").map_err(|_|Error::State)?;
    need(decimal(&run) && root==temp.join(format!("mrk-windows-installed-native-{run}-1"))
        && std::env::current_dir().map_err(|_|Error::Unavailable)?==root)?;
    let image=std::env::current_exe().map_err(|_|Error::Unavailable)?;args_are(test,&image)?;
    let mut original=Fixture::new(start,root,image)?;
    let observed=std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if matches!(test,STAGE_INPUT|PASSIVE_STAGE) {original.stage_source()}else{original.observe_producer(test==OBSERVE_AFTER)}
    })).unwrap_or(Err(Error::Unknown));
    if matches!(observed,Err(Error::Unknown)) || original.unknown() {
        diagnostic_data("producer-observation-original-operation",None,true,None);
        loop {std::thread::park();std::hint::black_box(&mut original);}
    }
    let settled=std::panic::catch_unwind(std::panic::AssertUnwindSafe(||original.settle())).unwrap_or(Err(Error::Unknown));
    if matches!(settled,Err(Error::Unknown)) || original.unknown() {
        diagnostic_data("producer-observation-original-close",None,true,None);
        loop {std::thread::park();std::hint::black_box(&mut original);}
    }
    let (mut record,objects,proofs)=observed?;settled?;
    record.put("fileOriginals",original.opened);record.put("fileOriginalsClosed",original.closed);
    let mut raw=record.encoded(if passive {PASSIVE_OBSERVATION_HEADER}else{OBSERVATION_HEADER},&OBSERVATION_FIELDS,OWNER_LIMIT)?;
    for proof in &proofs {raw.extend(proof.line().as_bytes());}
    for object in &objects {raw.extend(object.line().as_bytes());}
    need(raw.len()<=OWNER_LIMIT)?;
    // Same strict parser as the later DATA/prerequisite reader, not a new claim
    // about creation/grant/copy calls by the normal publisher.
    let items=PAYLOAD_NAMES.iter().map(|name| {
        let role=if matches!(test,STAGE_INPUT|PASSIVE_STAGE) {format!("source/{name}")}else{(*name).to_owned()};
        let object=objects.iter().find(|o|o.role==role).ok_or(Error::State)?;
        Ok(Payload {path:(*name).to_owned(),bytes:object.stamp.size as usize,sha:object.sha.clone()})
    }).collect::<Result<Vec<_>>>()?;
    observation(&raw,&items,test)?;original.gate()?;
    let name=match test {STAGE_INPUT=>STAGE_FILE,OBSERVE_BEFORE=>BEFORE_FILE,OBSERVE_AFTER=>PUBLICATION_FILE,
        PASSIVE_STAGE=>PASSIVE_STAGE_FILE,PASSIVE_OBSERVE=>PASSIVE_OBSERVATION_FILE,_=>return Err(Error::State)};
    write_fixture_record(&original.root.join(name),&raw,OWNER_LIMIT,original.end)?;original.gate()
}
#[test]
#[ignore = "fresh private fixed runtime-input only; reviewed production profile and no helper execution"]
fn hosted_stage_fixed_runtime_input() -> Result<()> {
    let start=Instant::now();producer_observation_run(STAGE_INPUT,start)
}
#[test]
#[ignore = "read-only independent103-object baseline after actual fixed producer exit0"]
fn hosted_observe_produced_version_before_collision() -> Result<()> {
    let start=Instant::now();producer_observation_run(OBSERVE_BEFORE,start)
}
#[test]
#[ignore = "read-only independent103-object equality after the same fixed producer typed settled exit2"]
fn hosted_compare_after_occupied_producer() -> Result<()> {
    let start=Instant::now();producer_observation_run(OBSERVE_AFTER,start)
}

#[test]
#[ignore = "fresh setup only for the fixed nonpublisher installed-passive profile; no collision replay"]
fn hosted_stage_passive_runtime_input() -> Result<()> {
    let start=Instant::now();producer_observation_run(PASSIVE_STAGE,start)
}
#[test]
#[ignore = "read-only original103-object setup observation after the fresh normal helper original exit0"]
fn hosted_observe_passive_published_version() -> Result<()> {
    let start=Instant::now();producer_observation_run(PASSIVE_OBSERVE,start)
}
