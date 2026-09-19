//! Finite, source-bound disposable-host diagnostics evidence. Not a production
//! qualification, generic command runner, OS fault injector, or GUI test.
//! Only the single ignored entry below can mint the private one-use permits.
use super::*;
use crate::{asset_session::DocumentBinding, bridge::DesktopBridge};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{collections::{BTreeMap, BTreeSet}, fs::{self, File, Metadata, OpenOptions},
    io::{Read, Seek, SeekFrom, Write}, os::{fd::OwnedFd, unix::fs::{FileExt, MetadataExt, OpenOptionsExt, PermissionsExt}},
    path::{Component, Path}, sync::{Condvar, Weak}};

pub(crate) type Check<T> = Result<T, &'static str>;
const SCOPE: &str = "environment-diagnostics-native-v1";
const OFFLINE_SCOPE: &str = "offline-preflight-native-v1";
const INPUT_ANCHOR: Option<&str> = option_env!("MRK_ENVIRONMENT_NATIVE_INPUTS_SHA256");
const WORKFLOW: &str = ".github/workflows/desktop-environment-diagnostics-native.yml";
const SHIM: &str = "tests/native_desktop_environment.py";
const OBSERVER: &str = "tests/workflow/command_bootstrap_fixture.py";
const ORDER: [&str; 20] = ["reader-shared-cap", "reader-late-stderr", "reader-no-eof", "reader-close-error", "wait-nonzero",
    "R1", "R2", "R3", "L1", "L2", "L3a", "L3b", "L3c", "L3d", "L4", "L5", "L6a", "L6b", "L6c", "L7"];
// Shared source/IO helpers and bound DATA only. Offline owns a separate sealed
// permit; none of these exports can enable diagnostics or choose a launcher.
pub(crate) fn require(ok: bool, code: &'static str) -> Check<()> { if ok { Ok(()) } else { Err(code) } }
pub(crate) fn hash(bytes: &[u8]) -> String { format!("{:x}", Sha256::digest(bytes)) }
pub(crate) fn hex(value: &str, n: usize) -> bool { value.len() == n && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) }
pub(crate) fn end_check(end: Instant) -> Check<()> { require(Instant::now() < end, "fixture_original_deadline") }
pub(crate) fn close_file(file: File) -> Check<()> { let fd: OwnedFd = file.into(); nix::unistd::close(fd).map_err(|_| "fixture_original_close") }
pub(crate) fn same(a: &Metadata, b: &Metadata) -> bool {
    a.dev() == b.dev() && a.ino() == b.ino() && a.mode() == b.mode() && a.uid() == b.uid() && a.gid() == b.gid()
        && a.len() == b.len() && a.mtime() == b.mtime() && a.mtime_nsec() == b.mtime_nsec() && a.nlink() == b.nlink()
}
pub(crate) fn anchored(path: &Path) -> Check<()> {
    require(path.is_absolute(), "fixture_absolute_path")?;
    let mut at = PathBuf::new();
    for part in path.components() {
        require(!matches!(part, Component::CurDir | Component::ParentDir | Component::Prefix(_)), "fixture_path_components")?;
        at.push(part.as_os_str());
        require(!fs::symlink_metadata(&at).map_err(|_| "fixture_path_metadata")?.file_type().is_symlink(), "fixture_path_link")?;
    }
    Ok(())
}
pub(crate) fn bound_file(path: &Path, limit: u64) -> Check<(File, Metadata)> {
    anchored(path)?;
    let before = fs::symlink_metadata(path).map_err(|_| "fixture_file_metadata")?;
    require(before.is_file() && before.nlink() == 1 && before.len() <= limit, "fixture_file_kind_size")?;
    let file = OpenOptions::new().read(true).custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC).open(path)
        .map_err(|_| "fixture_original_open")?;
    let opened = file.metadata().map_err(|_| "fixture_original_metadata")?;
    require(same(&before, &opened), "fixture_open_identity")?;
    Ok((file, opened))
}
pub(crate) fn read_bound(path: &Path, limit: u64) -> Check<Vec<u8>> {
    let (mut file, opened) = bound_file(path, limit)?;
    let mut bytes = Vec::new();
    let read = Read::by_ref(&mut file).take(limit + 1).read_to_end(&mut bytes).map_err(|_| "fixture_original_read");
    let checked = read.and_then(|_| require(bytes.len() as u64 == opened.len()
        && same(&opened, &file.metadata().map_err(|_| "fixture_read_metadata")?)
        && same(&opened, &fs::symlink_metadata(path).map_err(|_| "fixture_named_metadata")?), "fixture_read_identity"));
    let closed = close_file(file);
    checked?; closed?; Ok(bytes)
}
fn hash_file(path: &Path, size: u64, expected: &str, end: Instant) -> Check<()> {
    end_check(end)?;
    require(hex(expected, 64), "fixture_hash_shape")?;
    let (mut file, opened) = bound_file(path, size)?;
    let mut digest = Sha256::new(); let mut bytes = 0u64; let mut buffer = [0u8; 64 * 1024];
    let observed = (|| {
        require(opened.len() == size, "fixture_file_size")?;
        loop {
            end_check(end)?;
            let n = file.read(&mut buffer).map_err(|_| "fixture_hash_read")?;
            if n == 0 { break; }
            bytes = bytes.checked_add(n as u64).ok_or("fixture_hash_size")?;
            require(bytes <= size, "fixture_hash_growth")?; digest.update(&buffer[..n]);
        }
        require(bytes == size && format!("{:x}", digest.finalize()) == expected
            && same(&opened, &file.metadata().map_err(|_| "fixture_hash_metadata")?)
            && same(&opened, &fs::symlink_metadata(path).map_err(|_| "fixture_hash_named")?), "fixture_hash_changed")
    })();
    let closed = close_file(file); observed?; closed
}
fn json_file<T: for<'de> Deserialize<'de>>(path: &Path, limit: u64) -> Check<(T, String)> {
    let bytes = read_bound(path, limit)?;
    require(bytes.last() == Some(&b'\n'), "fixture_json_framing")?;
    let value = crate::protocol::strict_json(&bytes).map_err(|_| "fixture_json_structure")?;
    let parsed = T::deserialize(&value).map_err(|_| "fixture_json_schema")?;
    Ok((parsed, hash(&bytes)))
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct FileRow { pub(crate) path: String, pub(crate) size: u64, pub(crate) sha256: String }
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Directory { pub(crate) device: String, pub(crate) inode: String, pub(crate) mode: u32, pub(crate) uid: u32, pub(crate) gid: u32 }
impl Directory {
    fn check(&self, path: &Path) -> Check<()> {
        anchored(path)?; let meta = fs::symlink_metadata(path).map_err(|_| "fixture_directory_metadata")?;
        require(meta.is_dir() && meta.dev().to_string() == self.device && meta.ino().to_string() == self.inode
            && meta.mode() == self.mode && meta.uid() == self.uid && meta.gid() == self.gid, "fixture_directory_changed")
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Host { system: String, kernel_release: String, machine: String, non_root: bool,
    #[serde(rename = "imageOS")] image_os: String, image_version: String }
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Inputs {
    schema_version: u32, pub(crate) scope: String, pub(crate) root: PathBuf, pub(crate) source: PathBuf, pub(crate) python: PathBuf,
    pub(crate) source_sha: String, pub(crate) source_tree: String, pub(crate) platform: String, pub(crate) target: String,
    workflow_path: String, pub(crate) workflow_sha: String, workflow_ref: String, workflow_sha256: String,
    pub(crate) run_id: String, pub(crate) attempt: String, repository: String, event: String, r#ref: String,
    source_files: Vec<FileRow>, core_files: Vec<FileRow>, core_zip_sha256: String, core_zip_bytes: u64,
    python_sha256: String, python_bytes: u64, bootstrap_sha256: String, pub(crate) cwd: PathBuf,
    original_directories: BTreeMap<String, Directory>, observed_host: Host,
    #[serde(default, deserialize_with = "present_saved_configs")] pub(crate) saved_configs: Option<Vec<SavedConfig>>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SavedConfig { pub(crate) case: String, pub(crate) raw_text: String, pub(crate) size: usize, pub(crate) sha256: String }
fn present_saved_configs<'de, D: serde::Deserializer<'de>>(value: D) -> Result<Option<Vec<SavedConfig>>, D::Error> {
    // Missing is None; a present JSON null is NOT the diagnostics shape. An
    // offline manifest must instead supply its exact nine bound byte records.
    Vec::<SavedConfig>::deserialize(value).map(Some)
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ExecutableIdentity { device: String, inode: String, mode: u32, uid: u32, gid: u32, size: u64, mtime_ns: u64 }
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Invocation {
    schema_version: u32, scope: String, inputs_sha256: String, source_sha: String, source_tree: String,
    platform: String, target: String, path: PathBuf, identity: ExecutableIdentity, size: u64, sha256: String,
    invocation_sha256: String, messages_sha256: String, compile_receipt_sha256: String,
}
pub(crate) struct BoundInputs { pub(crate) data: Inputs, pub(crate) digest: String, invocation: Invocation, pub(crate) invocation_digest: String }
impl BoundInputs {
    fn load() -> Check<Self> {
        Self::load_scope(SCOPE)
    }
    pub(crate) fn load_offline() -> Check<Self> { Self::load_scope(OFFLINE_SCOPE) }
    fn load_scope(scope: &str) -> Check<Self> {
        let locator = PathBuf::from(std::env::var_os("MRK_ENVIRONMENT_NATIVE_INPUTS").ok_or("fixture_locator_missing")?);
        let (data, digest): (Inputs, _) = json_file(&locator, 256 * 1024)?;
        require(INPUT_ANCHOR == Some(digest.as_str()) && locator == data.root.join("environment-native-inputs.json"), "fixture_input_anchor")?;
        require(data.schema_version == 1 && data.scope == scope && data.platform == std::env::consts::OS
            && data.target == crate::runtime::COMPILED_TARGET && hex(&data.source_sha, 40) && hex(&data.source_tree, 40)
            && data.workflow_sha == data.source_sha && data.workflow_path == WORKFLOW
            && match (scope, data.r#ref.as_str(), data.platform.as_str()) {
                (SCOPE, "refs/heads/verify/desktop-environment-diagnostics-native", "linux" | "macos")
                | (SCOPE, "refs/heads/verify/desktop-environment-diagnostics-native-macos", "macos")
                | (OFFLINE_SCOPE, "refs/heads/verify/desktop-offline-preflight-native", "linux")
                | (OFFLINE_SCOPE, "refs/heads/verify/desktop-offline-preflight-native-macos", "macos") => true, _ => false,
            }
            && ["push", "workflow_dispatch"].contains(&data.event.as_str()) && !data.repository.is_empty()
            && data.workflow_ref == format!("{}/{WORKFLOW}@{}", data.repository, data.r#ref)
            && !data.run_id.is_empty() && data.run_id.bytes().all(|b| b.is_ascii_digit())
            && !data.attempt.is_empty() && data.attempt.bytes().all(|b| b.is_ascii_digit()), "fixture_workflow_binding")?;
        require(data.cwd == data.source.join("desktop") && Path::new(env!("CARGO_MANIFEST_DIR")) == data.cwd.join("src-tauri")
            && std::env::current_dir().map_err(|_| "fixture_cwd")? == data.cwd
            && std::env::var_os("MRK_DESKTOP_DEV_PYTHON").map(PathBuf::from) == Some(data.python.clone())
            && std::env::var_os("MRK_DESKTOP_DEV_CORE").map(PathBuf::from) == Some(data.source.join("src")), "fixture_runtime_binding")?;
        let host = &data.observed_host;
        let expected_host = if cfg!(target_os = "linux") { ("Linux", "x86_64") } else { ("Darwin", "arm64") };
        require(host.system == expected_host.0 && host.machine == expected_host.1 && host.non_root
            && !host.kernel_release.is_empty() && !host.image_os.is_empty() && !host.image_version.is_empty(), "fixture_host_binding")?;
        let (invocation, invocation_digest): (Invocation, _) = json_file(&data.root.join("environment-native-invocation.json"), 64 * 1024)?;
        require(invocation.schema_version == 1 && invocation.scope == scope && invocation.inputs_sha256 == digest
            && invocation.source_sha == data.source_sha && invocation.source_tree == data.source_tree
            && invocation.platform == data.platform && invocation.target == data.target
            && hex(&invocation.invocation_sha256, 64) && hex(&invocation.messages_sha256, 64) && hex(&invocation.compile_receipt_sha256, 64)
            && invocation.path.starts_with(data.root.join("target"))
            && std::env::current_exe().map_err(|_| "fixture_executable")? == invocation.path, "fixture_invocation_binding")?;
        let bound = Self { data, digest, invocation, invocation_digest };
        bound.recheck(Instant::now() + Duration::from_secs(30))?;
        Ok(bound)
    }
    pub(crate) fn source_file(&self, path: &str) -> Check<&FileRow> { self.data.source_files.iter().find(|row| row.path == path).ok_or("fixture_source_member") }
    pub(crate) fn recheck(&self, end: Instant) -> Check<()> {
        let d = &self.data;
        let mut directories = vec!["root", "source", "cwd", "home", "cargo", "rustup", "tmp", "target", "environment-native"];
        if d.scope == OFFLINE_SCOPE { directories.push("offline-cli11"); }
        require(d.original_directories.len() == directories.len(), "fixture_directory_roster")?;
        for name in directories {
            let path = match name { "root" => d.root.clone(), "source" => d.source.clone(), "cwd" => d.cwd.clone(), _ => d.root.join(name) };
            let row = d.original_directories.get(name).ok_or("fixture_directory_missing")?;
            require(row.uid != 0, "fixture_nonroot")?; row.check(&path)?;
        }
        require(!d.source_files.is_empty() && d.source_files.len() <= 2048 && !d.core_files.is_empty() && d.core_files.len() <= 2048,
            "fixture_inventory_bounds")?;
        let mut names = BTreeSet::new(); let mut total = 0u64; let mut previous = "";
        for row in &d.source_files {
            require(crate::runtime::safe_payload_path(&row.path) && previous < row.path.as_str() && names.insert(row.path.clone())
                && row.size <= 8 * 1024 * 1024, "fixture_source_roster")?;
            total += row.size; require(total <= 64 * 1024 * 1024, "fixture_source_total")?;
            hash_file(&d.source.join(&row.path), row.size, &row.sha256, end)?; previous = &row.path;
        }
        // Exact first-party inventory; only Git administration is excluded.
        let mut pending = vec![(d.source.clone(), String::new())]; let mut actual = BTreeSet::new();
        while let Some((at, prefix)) = pending.pop() {
            end_check(end)?;
            for entry in fs::read_dir(at).map_err(|_| "fixture_source_directory")? {
                let entry = entry.map_err(|_| "fixture_source_entry")?;
                let name = entry.file_name().into_string().map_err(|_| "fixture_source_name")?;
                if prefix.is_empty() && name == ".git" { continue; }
                let path = if prefix.is_empty() { name } else { format!("{prefix}/{name}") };
                require(crate::runtime::safe_payload_path(&path), "fixture_source_path")?;
                let meta = fs::symlink_metadata(entry.path()).map_err(|_| "fixture_source_stat")?;
                if meta.is_dir() { pending.push((entry.path(), path)); }
                else { require(meta.is_file() && actual.insert(path) && actual.len() <= 2048, "fixture_source_extra")?; }
            }
        }
        require(names == actual, "fixture_source_inventory_changed")?;
        let mut previous = ""; let mut total = 0u64;
        for row in &d.core_files {
            require(row.path.as_str() > previous && row.path.starts_with("mobile_release/") && row.size <= 8 * 1024 * 1024,
                "fixture_core_roster")?;
            let source = self.source_file(&format!("src/{}", row.path))?;
            require(source.size == row.size && source.sha256 == row.sha256, "fixture_core_source_binding")?;
            total += row.size; require(total <= 32 * 1024 * 1024, "fixture_core_total")?; previous = &row.path;
        }
        let expected: BTreeSet<_> = d.source_files.iter().filter(|r| r.path.starts_with("src/mobile_release/")
            && ["py", "json", "pem"].iter().any(|extension| r.path.ends_with(&format!(".{extension}"))))
            .map(|r| r.path.trim_start_matches("src/")).collect();
        require(expected == d.core_files.iter().map(|r| r.path.as_str()).collect(), "fixture_complete_core_roster")?;
        require(d.core_zip_bytes <= 40 * 1024 * 1024 && d.python_bytes <= 512 * 1024 * 1024, "fixture_runtime_limits")?;
        hash_file(&d.root.join("core.zip"), d.core_zip_bytes, &d.core_zip_sha256, end)?;
        hash_file(&d.python, d.python_bytes, &d.python_sha256, end)?;
        let bootstrap = if d.scope == OFFLINE_SCOPE { "desktop/offline_preflight_bootstrap.py" } else { "desktop/environment_bootstrap.py" };
        require(self.source_file(bootstrap)?.sha256 == d.bootstrap_sha256
            && self.source_file(WORKFLOW)?.sha256 == d.workflow_sha256, "fixture_bootstrap_workflow_hash")?;
        if d.scope == OFFLINE_SCOPE {
            let cases = ["PF01", "PF02", "PF03", "PF04a", "PF04b", "PF05a", "PF05b", "PF06", "PF07"];
            let rows = d.saved_configs.as_ref().ok_or("fixture_saved_configs_missing")?;
            require(rows.len() == cases.len() && rows.iter().zip(cases).all(|(row, case)| row.case == case
                && row.size == row.raw_text.len() && row.size > 0 && row.size <= 8192
                && row.raw_text.ends_with('\n') && hex(&row.sha256, 64) && hash(row.raw_text.as_bytes()) == row.sha256),
                "fixture_saved_configs_binding")?;
        } else { require(d.saved_configs.is_none(), "fixture_unexpected_saved_configs")?; }
        let i = &self.invocation; hash_file(&i.path, i.size, &i.sha256, end)?;
        let meta = fs::symlink_metadata(&i.path).map_err(|_| "fixture_executable_stat")?;
        let n = &i.identity;
        let mtime = (meta.mtime() as i128) * 1_000_000_000 + meta.mtime_nsec() as i128;
        require(n.device == meta.dev().to_string() && n.inode == meta.ino().to_string() && n.mode == meta.mode()
            && n.uid == meta.uid() && n.gid == meta.gid() && n.size == meta.len() && i.size == meta.len()
            && n.mtime_ns as i128 == mtime, "fixture_executable_identity")
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Case { R1, R2, R3, L1, L2, L3a, L3b, L3c, L3d, L4, L5, L6a, L6b, L6c, L7 }
impl Case {
    fn id(self) -> &'static str { match self { Self::R1 => "R1", Self::R2 => "R2", Self::R3 => "R3", Self::L1 => "L1", Self::L2 => "L2",
        Self::L3a => "L3a", Self::L3b => "L3b", Self::L3c => "L3c", Self::L3d => "L3d", Self::L4 => "L4", Self::L5 => "L5",
        Self::L6a => "L6a", Self::L6b => "L6b", Self::L6c => "L6c", Self::L7 => "L7" } }
    fn shim(self) -> bool { matches!(self, Self::L3a | Self::L3b | Self::L3c | Self::L3d | Self::L4 | Self::L5) }
    fn active_stop(self) -> bool { matches!(self, Self::L3a | Self::L3b | Self::L3c | Self::L3d) }
    fn platform(self) -> wire::Platform {
        if self == Self::R2 || self == Self::R3 && cfg!(target_os = "macos") { wire::Platform::Ios } else { wire::Platform::Android }
    }
    fn enabled(self) -> bool { matches!(self, Self::R1 | Self::R2 | Self::R3) || self.shim() }
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Boundary { Startup, InspectionReturn, WriterClose, ReaderReturn, TerminalHandoff, ObserverReturn }
struct Gate {
    entered: watch::Sender<bool>, released: watch::Sender<bool>, blocking: Condvar, lock: Mutex<()>,
    entered_at: Mutex<Option<Instant>>, released_at: Mutex<Option<Instant>>,
}
impl Gate {
    fn new() -> Self {
        let (entered, _) = watch::channel(false); let (released, _) = watch::channel(false);
        Self { entered, released, blocking: Condvar::new(), lock: Mutex::new(()), entered_at: Mutex::new(None), released_at: Mutex::new(None) }
    }
    fn mark(&self) { if let Ok(mut at) = self.entered_at.lock() { if at.is_none() { *at = Some(Instant::now()); } } self.entered.send_replace(true); }
    async fn hold(&self) {
        self.mark(); let mut released = self.released.subscribe();
        while !*released.borrow_and_update() { if released.changed().await.is_err() { pending::<()>().await; } }
    }
    fn hold_blocking(&self) {
        self.mark(); let Ok(mut lock) = self.lock.lock() else { return; };
        while !*self.released.borrow() { lock = match self.blocking.wait(lock) { Ok(lock) => lock, Err(_) => return }; }
    }
    fn release(&self) {
        // Same mutex as the Condvar waiter prevents a release between its
        // predicate check and original wait from losing the only notification.
        let _lock = self.lock.lock();
        if let Ok(mut at) = self.released_at.lock() { if at.is_none() { *at = Some(Instant::now()); } }
        self.released.send_replace(true); self.blocking.notify_all();
    }
}

// This tuple is inert DATA, not qualification; only the environment resolver
// uses it, and the actual owner permit rechecks the resulting tuple at spawn.
pub(crate) struct RuntimeSelection { core: PathBuf }
impl RuntimeSelection { pub(crate) fn core(&self) -> &Path { &self.core } }
pub(crate) struct RegistrationPermit { owner: Weak<Inner>, id: String, root: PathBuf, generation: u32 }
impl RegistrationPermit {
    pub(crate) fn validate(&self, owner: &EnvironmentDiagnosticsOwner) -> Result<(&str, &Path, u32), BridgeError> {
        if self.owner.upgrade().is_some_and(|inner| Arc::ptr_eq(&inner, &owner.inner)) {
            Ok((&self.id, &self.root, self.generation))
        } else { Err(unavailable()) }
    }
}
pub(super) struct Permit {
    inputs: Arc<BoundInputs>, owner: Weak<Inner>, session: Mutex<Option<Weak<Session>>>, claimed: AtomicBool,
    case: Case, registration: RegistrationPermit, context: Context, gate: Gate, driver_loss: AtomicBool,
    files: Mutex<Option<CaseFiles>>,
}
impl Permit {
    fn belongs(&self, inner: &Inner) -> bool { self.owner.upgrade().is_some_and(|owner| std::ptr::eq(owner.as_ref(), inner)) }
    pub(super) fn permits(&self, inner: &Inner) -> bool {
        self.belongs(inner) && Profile::current().is_some_and(|p| matches!(p, Profile::LinuxX64 | Profile::MacosArm64))
    }
    pub(super) fn bind(&self, owner: &Arc<Session>) -> Result<(), BridgeError> {
        if owner.context != self.context || owner.registration != self.registration.generation || owner.project != self.registration.root
            || self.claimed.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).is_err() { return Err(unavailable()); }
        let mut session = self.session.lock().map_err(|_| unavailable())?;
        if session.is_some() { return Err(unavailable()); } *session = Some(Arc::downgrade(owner)); Ok(())
    }
    fn original(&self, owner: &Session) -> bool {
        self.session.lock().ok().and_then(|session| session.as_ref().and_then(Weak::upgrade))
            .is_some_and(|session| std::ptr::eq(session.as_ref(), owner))
    }
    fn held(&self, boundary: Boundary) -> bool {
        matches!((self.case, boundary), (Case::L1, Boundary::Startup) | (Case::L2, Boundary::InspectionReturn)
            | (Case::L5, Boundary::TerminalHandoff) | (Case::L6a, Boundary::WriterClose)
            | (Case::L6b, Boundary::ReaderReturn) | (Case::L6c, Boundary::ObserverReturn))
    }
    pub(super) async fn boundary(&self, owner: &Session, boundary: Boundary) {
        if self.original(owner) && self.held(boundary) { self.gate.hold().await; }
    }
    pub(super) fn inspection_return(&self, owner: &Session) {
        if self.original(owner) && self.held(Boundary::InspectionReturn) { self.gate.hold_blocking(); }
    }
    pub(super) fn driver_boundary(&self, owner: &Session) {
        if self.original(owner) && self.case == Case::L7 && !self.driver_loss.swap(true, Ordering::SeqCst) {
            panic!("fixed hosted diagnostics original driver loss");
        }
    }
    pub(super) fn prepare_spawn(&self, owner: &Session, runtime: &VerifiedRuntime) -> Result<Option<(PathBuf, PathBuf)>, BridgeError> {
        self.prepare_spawn_checked(owner, runtime).map_err(|_| unavailable())
    }
    fn prepare_spawn_checked(&self, owner: &Session, runtime: &VerifiedRuntime) -> Check<Option<(PathBuf, PathBuf)>> {
        require(self.original(owner) && self.claimed.load(Ordering::SeqCst), "fixture_spawn_original")?;
        self.inputs.recheck(owner.clocks.work)?;
        let d = &self.inputs.data; let core = if self.case == Case::R3 { d.root.join("core.zip") } else { d.source.join("src") };
        require(runtime.python == d.python && runtime.core == core && runtime.cwd == d.cwd
            && runtime.bootstrap == d.cwd.join("environment_bootstrap.py") && owner.context == self.context
            && owner.project == self.registration.root && owner.registration == self.registration.generation, "fixture_spawn_tuple")?;
        if !self.case.shim() { return Ok(None); }
        let mut slot = self.files.lock().map_err(|_| "fixture_file_record")?;
        let files = slot.as_mut().ok_or("fixture_file_record_missing")?;
        let row = json!({"schemaVersion":1,"case":self.case.id(),"runId":owner.id,"ownerGeneration":owner.generation,
            "context":owner.context,"profile":owner.profile,"python":runtime.python,"core":runtime.core,"cwd":runtime.cwd,
            "projectRoot":owner.project,"inputManifestSha256":self.inputs.digest,
            "shimSha256":self.inputs.source_file(SHIM)?.sha256,"observerSha256":self.inputs.source_file(OBSERVER)?.sha256,
            "relayIdentity":[files.relay_identity.dev(),files.relay_identity.ino(),files.relay_identity.uid(),files.relay_identity.mode()]});
        let mut bytes = serde_json::to_vec(&row).map_err(|_| "fixture_control_encode")?; bytes.push(b'\n');
        require(bytes.len() <= 65536, "fixture_control_limit")?;
        let mut original = files.control.take().ok_or("fixture_control_already_used")?;
        let written = (|| { end_check(owner.clocks.work)?; original.write_all(&bytes).map_err(|_| "fixture_control_write")?;
            original.set_permissions(fs::Permissions::from_mode(0o400)).map_err(|_| "fixture_control_mode")?; end_check(owner.clocks.work) })();
        let closed = close_file(original); files.control_closed = Some(closed.is_ok()); written?; closed?;
        Ok(Some((d.source.join(SHIM), files.control_path.clone())))
    }
}
struct CaseFiles { control: Option<File>, control_path: PathBuf, control_closed: Option<bool>,
    relay: Option<File>, relay_path: PathBuf, relay_identity: Metadata, relay_closed: Option<bool> }

pub(crate) fn create_private(path: &Path) -> Check<File> {
    let file = OpenOptions::new().write(true).create_new(true).mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC).open(path).map_err(|_| "fixture_private_create")?;
    let meta = file.metadata().map_err(|_| "fixture_private_metadata")?;
    require(meta.is_file() && meta.nlink() == 1 && meta.mode() & 0o777 == 0o600 && meta.uid() != 0, "fixture_private_identity")?;
    Ok(file)
}
pub(crate) fn create_directory(path: &Path) -> Check<()> {
    fs::create_dir(path).map_err(|_| "fixture_directory_create")?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|_| "fixture_directory_mode")
}
impl CaseFiles {
    fn prepare(root: &Path) -> Check<Self> {
        let control_path = root.join("control.json"); let control = create_private(&control_path)?;
        let relay_path = root.join("relay.trace"); let relay_writer = create_private(&relay_path)?;
        close_file(relay_writer)?;
        let (relay, relay_identity) = bound_file(&relay_path, 0)?;
        Ok(Self { control: Some(control), control_path, control_closed: None,
            relay: Some(relay), relay_path, relay_identity, relay_closed: None })
    }
    fn rows(&self, complete: bool) -> Check<Vec<Value>> {
        let original = self.relay.as_ref().ok_or("fixture_relay_not_owned")?;
        let before = original.metadata().map_err(|_| "fixture_relay_metadata")?;
        let named = fs::symlink_metadata(&self.relay_path).map_err(|_| "fixture_relay_named")?;
        require(before.dev() == self.relay_identity.dev() && before.ino() == self.relay_identity.ino()
            && before.uid() == self.relay_identity.uid() && before.mode() == self.relay_identity.mode()
            && before.is_file() && before.nlink() == 1 && before.len() <= 4096
            && named.dev() == before.dev() && named.ino() == before.ino() && named.mode() == before.mode(), "fixture_relay_identity")?;
        let mut bytes = [0u8; 4097];
        let n = original.read_at(&mut bytes, 0).map_err(|_| "fixture_relay_read")?;
        require(n <= 4096 && (!complete || n as u64 == before.len() && (n == 0 || bytes[n - 1] == b'\n')), "fixture_relay_bound")?;
        let mut rows = Vec::new(); let mut offset = 0;
        for at in 0..n {
            if bytes[at] != b'\n' { continue; }
            require(at + 1 - offset <= 2048 && rows.len() < 2, "fixture_relay_row_bound")?;
            rows.push(crate::protocol::strict_json(&bytes[offset..=at]).map_err(|_| "fixture_relay_json")?); offset = at + 1;
        }
        require(!complete || offset == n, "fixture_relay_complete")?; Ok(rows)
    }
    fn close(&mut self) -> Check<()> {
        let mut okay = true;
        if let Some(file) = self.control.take() { let closed = close_file(file).is_ok(); self.control_closed = Some(closed); okay &= closed; }
        if let Some(file) = self.relay.take() { let closed = close_file(file).is_ok(); self.relay_closed = Some(closed); okay &= closed; }
        require(okay && self.control_closed == Some(true) && self.relay_closed == Some(true), "fixture_file_original_finality")
    }
}
fn draft(enabled: bool) -> Value {
    // A disabled platform must contain only `enabled:false`, and core policy
    // still requires one enabled platform. Every disabled management case
    // selects Android; enabled iOS does not authorize any tool invocation.
    let android = if enabled {
        json!({"enabled":true,"applicationId":"org.synthetic.diagnostics","identityStatus":"unverified"})
    } else { json!({"enabled":false}) };
    json!({"schemaVersion":1,"version":{"source":"release/version.properties","nameKey":"VERSION_NAME","buildKey":"BUILD_NUMBER"},
        "source":{"candidateBranch":"main","productionBranch":"main"},
        "android":android,
        "ios":{"enabled":true,"bundleId":"org.synthetic.diagnostics","identityStatus":"unverified"},
        "metadata":{"root":"release/store","androidLocales":["en-US"],"iosLocales":["en-US"]},
        "services":{"androidFirebase":"disabled","iosFirebase":"disabled"},
        "projectChecks":{"preflight":[],"androidArtifact":[],"iosArtifact":[]}})
}

#[test]
fn management_draft_obeys_core_shape_and_android_routing() {
    // Pure DATA only: use the actual factory without creating a Run, runtime,
    // owner, file or tool. The focused policy check consumes these exact JSON
    // records through the existing core parser, not a Python copy of the draft.
    let disabled = draft(false);
    assert_eq!(disabled["android"], json!({"enabled":false}));
    assert_eq!(disabled["ios"], json!({"enabled":true,"bundleId":"org.synthetic.diagnostics","identityStatus":"unverified"}));
    for case in [Case::L1, Case::L2, Case::L6a, Case::L6b, Case::L6c, Case::L7] {
        assert!(!case.enabled());
        assert!(matches!(case.platform(), wire::Platform::Android));
    }
    let enabled = draft(true);
    let mut expected_enabled = disabled.clone();
    expected_enabled["android"] = json!({"enabled":true,"applicationId":"org.synthetic.diagnostics","identityStatus":"unverified"});
    assert_eq!(enabled, expected_enabled);
    for (variant, value) in [("android-disabled", disabled), ("both-enabled", enabled)] {
        let record = serde_json::to_string(&json!({"schemaVersion":1,"variant":variant,"selectedPlatform":"android","draft":value})).unwrap();
        assert!(record.len() <= 4096);
        // libtest's `test ...` prefix may share a line under --nocapture.
        println!("\nMRK_ENVIRONMENT_DRAFT_POLICY_V1 {record}");
    }
}

struct Run { bridge: Arc<DesktopBridge>, document: DocumentBinding, permit: Arc<Permit>, session: Option<Arc<Session>> }
impl Run {
    fn prepare(inputs: Arc<BoundInputs>, case: Case) -> Check<Self> {
        inputs.recheck(Instant::now() + Duration::from_secs(30))?;
        let root = inputs.data.root.join("environment-native").join(case.id()); create_directory(&root)?;
        let project = root.join("project"); create_directory(&project)?;
        let files = if case.shim() { Some(CaseFiles::prepare(&root)?) } else { None };
        let mut bridge = DesktopBridge::new(inputs.data.root.join("unused-packaged-runtime"));
        if case == Case::R3 {
            let selection = RuntimeSelection { core: inputs.data.root.join("core.zip") };
            Arc::get_mut(&mut bridge.diagnostics.inner).ok_or("fixture_runtime_exclusive")?.runtime.select_environment_fixture_zip(&selection);
        }
        let bridge = Arc::new(bridge);
        let id = format!("environment-native-{}", case.id());
        let context = Context { project_id: id.clone(), draft_revision: 0, baseline_generation: 2, platform: case.platform(), operation: wire::Operation::Build };
        let permit = Arc::new(Permit { inputs, owner: Arc::downgrade(&bridge.diagnostics.inner), session: Mutex::new(None), claimed: AtomicBool::new(false), case,
            registration: RegistrationPermit { owner: Arc::downgrade(&bridge.diagnostics.inner), id, root: project, generation: 2 },
            context, gate: Gate::new(), driver_loss: AtomicBool::new(false), files: Mutex::new(files) });
        *bridge.diagnostics.inner.fixture.lock().map_err(|_| "fixture_owner_slot")? = Some(Arc::downgrade(&permit));
        let document = DocumentBinding::new(bridge.clone());
        require(document.navigation(true), "fixture_original_navigation")?;
        document.observe(|life| life.started(true)); document.hook_installed(); document.observe(|life| life.finished(true));
        document.environment_fixture_registration(&permit.registration, false).map_err(|_| "fixture_original_registration")?;
        Ok(Self { bridge, document, permit, session: None })
    }
    fn input(&self) -> Start {
        let c = &self.permit.context;
        Start { project_id: c.project_id.clone(), draft: draft(self.permit.case.enabled()), draft_revision: c.draft_revision,
            baseline_generation: c.baseline_generation, platform: c.platform, operation: c.operation }
    }
    fn start(&mut self) -> Check<()> {
        // Deliberately discard the invoke's response. Recovery reads the same
        // original registry; no second start or caller-owned task is created.
        let started = self.document.start_environment_diagnostics(self.input()).map_err(|_| "fixture_start_refused")?;
        drop(started);
        self.session = self.bridge.diagnostics.inner.lock().active.as_ref().map(|a| a.owner.clone());
        require(self.session.is_some(), "fixture_original_session")
    }
    fn original(&self) -> Check<&Arc<Session>> { self.session.as_ref().ok_or("fixture_session_missing") }
    fn cancel(&self) -> Check<()> {
        let s = self.original()?;
        self.document.cancel_environment_diagnostics(wire::Cancel { run_id: s.id.clone(), owner_generation: s.generation.clone() })
            .map_err(|_| "fixture_original_cancel")?; Ok(())
    }
    fn offset(&self, at: Instant) -> Check<u64> { Ok(at.saturating_duration_since(self.original()?.clocks.admitted).as_millis() as u64) }
    async fn entered(&self) -> Check<()> {
        let s = self.original()?; let mut changes = self.permit.gate.entered.subscribe();
        loop {
            if *changes.borrow_and_update() { return Ok(()); }
            tokio::time::timeout_at(tokio::time::Instant::from_std(s.clocks.work), changes.changed()).await
                .map_err(|_| "fixture_boundary_not_entered")?.map_err(|_| "fixture_boundary_lost")?;
        }
    }
    async fn observed_clock(&self, finality: bool) -> Check<Instant> {
        let s = self.original()?; let mut changes = self.bridge.diagnostics.subscribe();
        loop {
            let observed = { let r = self.bridge.diagnostics.inner.lock();
                r.active.as_ref().filter(|a| Arc::ptr_eq(&a.owner, s)).is_some_and(|a| if finality { a.unknown } else { a.work_expired }) };
            if observed { return Ok(Instant::now()); }
            // Observation timeout is infrastructure failure, never an endpoint
            // call or a new application cleanup window. Watchdog alone drives W/H.
            tokio::time::timeout_at(tokio::time::Instant::from_std(s.clocks.finality + Duration::from_secs(2)), changes.changed()).await
                .map_err(|_| "fixture_autonomous_watchdog_missing")?.map_err(|_| "fixture_native_changes_lost")?;
        }
    }
    fn relay(&self, complete: bool) -> Check<Vec<Value>> {
        self.permit.files.lock().map_err(|_| "fixture_files_poisoned")?.as_ref().ok_or("fixture_files_missing")?.rows(complete)
    }
    async fn readiness(&self) -> Check<Option<&'static str>> {
        let s = self.original()?;
        loop {
            let rows = self.relay(false)?;
            for row in &rows {
                check_relay_common(row, self)?;
                if row["event"] == "target-ready" {
                    check_ready(row)?;
                    require(Instant::now() < s.clocks.work && !*s.stop.borrow(), "fixture_late_target_ready")?;
                    return Ok(None);
                }
                if row["event"] == "unexecuted" { return Ok(Some(check_unexecuted(row)?)); }
            }
            require(Instant::now() < s.clocks.work, "fixture_target_not_ready")?;
            tokio::time::sleep(Duration::from_millis(5)).await; // Bounded original regular-file reader, not an owner clock.
        }
    }
    async fn settle(&self) -> Check<Projection> {
        let s = self.original()?; let mut changes = self.bridge.diagnostics.subscribe();
        loop {
            let status = self.document.environment_diagnostics_status().map_err(|_| "fixture_status_lost")?;
            if let Some(last) = status.last_terminal { if last.run_id == s.id && last.owner_generation == s.generation { return Ok(last); } }
            if self.permit.case == Case::L7 && s.watchdog_return.lock().map_err(|_| "fixture_join_record")?.is_some() {
                return status.active.ok_or("fixture_negative_original_lost");
            }
            tokio::time::timeout_at(tokio::time::Instant::from_std(s.clocks.finality + Duration::from_secs(20)), changes.changed()).await
                .map_err(|_| "fixture_originals_not_settled")?.map_err(|_| "fixture_settlement_wake_lost")?;
        }
    }
    fn close_files(&self) -> Check<Value> {
        let mut files = self.permit.files.lock().map_err(|_| "fixture_file_slot")?;
        if let Some(files) = files.as_mut() {
            files.close()?; Ok(json!({"controlClosed":files.control_closed,"relayClosed":files.relay_closed}))
        } else { Ok(json!({"controlClosed":null,"relayClosed":null})) }
    }
}

fn keys(value: &Value, expected: &[&str]) -> bool {
    value.as_object().is_some_and(|v| v.len() == expected.len() && expected.iter().all(|k| v.contains_key(*k)))
}
fn check_relay_common(row: &Value, run: &Run) -> Check<()> {
    let s = run.original()?;
    require(row["schemaVersion"] == 1 && row["case"] == run.permit.case.id() && row["runId"] == s.id
        && row["ownerGeneration"] == s.generation, "fixture_relay_session")
}
fn check_ready(row: &Value) -> Check<()> {
    require(keys(row, &["schemaVersion","event","case","runId","ownerGeneration","commandNonce","recipeSha256","remainingNs","sourceDelayNs"])
        && row["event"] == "target-ready" && row["commandNonce"].as_str().is_some_and(|s| hex(s, 32))
        && row["recipeSha256"].as_str().is_some_and(|s| hex(s, 64))
        && row["remainingNs"].as_u64().is_some_and(|n| (1_000_000_000..=3_000_000_000).contains(&n))
        && row["sourceDelayNs"].as_u64().is_some_and(|n| n <= 3_000_000_000), "fixture_ready_contract")
}
fn check_unexecuted(row: &Value) -> Check<&'static str> {
    require(keys(row, &["schemaVersion","event","case","runId","ownerGeneration","intercepts","readyObserved","observerClosed","noNextCall","reason","coreCode"])
        && row["event"] == "unexecuted" && row["intercepts"] == 0 && row["readyObserved"] == false
        && row["observerClosed"] == true && row["noNextCall"] == true && row["coreCode"] == 0, "fixture_unexecuted_contract")?;
    match row["reason"].as_str() { Some("git-not-admitted") => Ok("git-not-admitted"), Some("insufficient-work-margin") => Ok("insufficient-work-margin"),
        _ => Err("fixture_unexecuted_reason") }
}
fn check_ordinary(rows: &[Value], run: &Run) -> Check<Option<&'static str>> {
    require(!rows.is_empty() && rows.len() <= 2, "fixture_ordinary_roster")?;
    for row in rows { check_relay_common(row, run)?; }
    let last = rows.last().ok_or("fixture_ordinary_last")?;
    if last["event"] == "unexecuted" { require(rows.len() == 1, "fixture_unexecuted_rows")?; return Ok(Some(check_unexecuted(last)?)); }
    require(keys(last, &["schemaVersion","event","case","runId","ownerGeneration","commandNonce","recipeSha256","intercepts","readyObserved",
        "resultIntegrity","dispatched","contained","cleanupComplete","cWait","aWait","cFinish","aFinish","targetWait","targetMarker",
        "readersJoined","traceCloses","noNextCall","reason","coreCode","capture","stopBeforeWorkNs"]), "fixture_ordinary_keys")?;
    require(last["event"] == "settled" && last["commandNonce"].as_str().is_some_and(|s| hex(s, 32))
        && last["recipeSha256"].as_str().is_some_and(|s| hex(s, 64)) && last["intercepts"] == 1 && last["resultIntegrity"] == "incomplete"
        && last["dispatched"] == true && last["contained"] == true && last["cleanupComplete"] == true
        && last["cWait"] == last["cFinish"] && last["aWait"] == last["aFinish"]
        && last["cWait"].as_i64().is_some_and(|n| n == 0 || n == 2) && last["aWait"].as_i64().is_some_and(|n| n == 0 || n == 2)
        && keys(&last["targetWait"], &["kind","code"]) && matches!(last["targetWait"]["kind"].as_str(), Some("exit" | "signal"))
        && last["targetWait"]["code"].as_u64().is_some()
        && last["targetMarker"] == true && last["readersJoined"] == true && last["noNextCall"] == true && last["coreCode"] == 0
        && keys(&last["traceCloses"], &["o","c","a","w"]) && ["o","c","a","w"].iter().all(|k| last["traceCloses"][*k] == true)
        && matches!(last["reason"].as_str(), Some("cancelled" | "timed-out" | "command-incomplete")), "fixture_ordinary_original_finality")?;
    let capture = &last["capture"];
    require(keys(capture, &["stdout","stderr","limit","overflow"]) && capture["limit"] == 16384, "fixture_capture_shape")?;
    let stdout = capture["stdout"].as_u64().ok_or("fixture_capture_stdout")?;
    let stderr = capture["stderr"].as_u64().ok_or("fixture_capture_stderr")?;
    if matches!(run.permit.case, Case::L4 | Case::L5) {
        require(stdout == 8192 && stderr == 8193 && capture["overflow"] == true && last["reason"] == "command-incomplete"
            && last["stopBeforeWorkNs"].is_null(), "fixture_aggregate_cap")?;
    } else {
        require(stdout.checked_add(stderr).is_some_and(|n| n <= 16384) && capture["overflow"] == false && last["reason"] == "cancelled"
            && last["readyObserved"] == true && rows.len() == 2
            && last["stopBeforeWorkNs"].as_u64().is_some_and(|n| (1..=3_000_000_000).contains(&n)), "fixture_active_original_stop")?;
    }
    if rows.len() == 2 {
        check_ready(&rows[0])?;
        require(rows[0]["commandNonce"] == last["commandNonce"] && rows[0]["recipeSha256"] == last["recipeSha256"], "fixture_original_recipe")?;
    }
    Ok(None)
}

fn close_state(value: Close) -> &'static str { match value { Close::New => "new", Close::Attempted => "attempted", Close::Settled => "settled", Close::Unknown => "unknown" } }
fn join_kind<T>(record: &Mutex<Option<Result<T, tokio::task::JoinError>>>, okay: impl Fn(&T) -> &'static str) -> Check<&'static str> {
    Ok(match record.lock().map_err(|_| "fixture_original_record_poisoned")?.as_ref() {
        Some(Ok(value)) => okay(value), Some(Err(error)) if error.is_panic() => "panic", Some(Err(error)) if error.is_cancelled() => "cancelled", _ => "not-joined",
    })
}
async fn receipt(run: &Run) -> Check<Value> {
    let owner = run.original()?; let negative = run.permit.case == Case::L7;
    let book = owner.resources.lock().await;
    let startup = owner.startup.lock().map_err(|_| "fixture_startup_record")?;
    let input = owner.input.lock().await; let output = owner.output.lock().await; let error = owner.error.lock().await;
    let driver = join_kind(&owner.driver_return, |_| "ok-unit")?; let manager = join_kind(&owner.manager_return, |_| "ok-unit")?;
    let observer = join_kind(&owner.observer_return, |value| if *value { "ok-true" } else { "ok-false" })?;
    let watchdog = join_kind(&owner.watchdog_return, |value| if *value { "ok-true" } else { "ok-false" })?;
    let driver_retained = owner.driver.try_lock().map_err(|_| "fixture_driver_slot_busy")?.is_some();
    let manager_retained = owner.manager.try_lock().map_err(|_| "fixture_manager_slot_busy")?.is_some();
    let observer_retained = owner.observer.try_lock().map_err(|_| "fixture_observer_slot_busy")?.is_some();
    let watchdog_retained = owner.watchdog.try_lock().map_err(|_| "fixture_watchdog_slot_busy")?.is_some();
    require(manager == "ok-unit" && !manager_retained
        && if negative { driver == "panic" && driver_retained && observer == "ok-false" && observer_retained && watchdog == "ok-false" && watchdog_retained }
            else { driver == "ok-unit" && !driver_retained && observer == "ok-true" && !observer_retained && watchdog == "ok-true" && !watchdog_retained }, "fixture_original_task_receipts")?;
    require(book.inspection.is_none() && book.acquisition.is_none() && !book.inspection_failed && !book.acquisition_failed && !startup.failed
        && startup.child.is_none() && book.writer.is_none() && book.stdout.is_none() && book.stderr.is_none()
        && !book.write_failed && !book.out_failed && !book.err_failed
        && book.write_end.is_some() && book.out_end.is_some() && book.err_end.is_some(), "fixture_original_work_receipts")?;
    if startup.returned {
        require(startup.attempted && book.inspection_joined && book.acquisition_joined
            && book.waited.is_some_and(|s| s.success()) && !book.wait_failed
            && book.write_end.as_ref().is_some_and(|r| r.sent && r.closed && !r.failed)
            && book.out_end.as_ref().is_some_and(|r| r.frames == 2 && r.eof && r.closed && !r.failed)
            && book.err_end.as_ref().is_some_and(|r| r.frames == 0 && r.eof && r.closed && !r.failed)
            && input.close == Close::Settled && output.close == Close::Settled && error.close == Close::Settled,
            "fixture_original_physical_finality")?;
    } else {
        require(matches!(run.permit.case, Case::L1 | Case::L2) && !startup.attempted && book.child.is_none() && book.waited.is_none()
            && !book.acquisition_joined && input.close == Close::New && output.close == Close::New && error.close == Close::New,
            "fixture_no_late_acquisition")?;
    }
    require(input.io.is_none() && output.io.is_none() && error.io.is_none(), "fixture_original_pipe_retention")?;
    let active_retained = run.bridge.diagnostics.inner.lock().active.is_some();
    let disabled = run.bridge.diagnostics.disabled();
    // Do not take can_exit while holding a registry guard.
    let can_exit = run.bridge.diagnostics.can_exit();
    require(active_retained == negative && can_exit != negative, "fixture_normal_exit_gate")?;
    Ok(json!({"startup":{"attempted":startup.attempted,"returned":startup.returned,"failed":startup.failed},
        "inspection":{"joined":book.inspection_joined,"failed":book.inspection_failed,"retained":book.inspection.is_some()},
        "acquisition":{"joined":book.acquisition_joined,"failed":book.acquisition_failed,"retained":book.acquisition.is_some()},
        "child":{"present":book.child.is_some(),"waited":book.waited.is_some(),"code":book.waited.and_then(|s| s.code()),"waitFailed":book.wait_failed},
        "input":{"close":close_state(input.close),"retained":input.io.is_some()},
        "output":{"close":close_state(output.close),"retained":output.io.is_some()},
        "error":{"close":close_state(error.close),"retained":error.io.is_some()},
        "writer":{"joined":book.writer.is_none() && book.write_end.is_some(),"failed":book.write_failed,
            "end":book.write_end.as_ref().map(|r| json!({"sent":r.sent,"closed":r.closed,"failed":r.failed}))},
        "stdout":{"joined":book.stdout.is_none() && book.out_end.is_some(),"failed":book.out_failed,
            "end":book.out_end.as_ref().map(|r| json!({"frames":r.frames,"eof":r.eof,"closed":r.closed,"failed":r.failed}))},
        "stderr":{"joined":book.stderr.is_none() && book.err_end.is_some(),"failed":book.err_failed,
            "end":book.err_end.as_ref().map(|r| json!({"frames":r.frames,"eof":r.eof,"closed":r.closed,"failed":r.failed}))},
        "driver":{"receipt":driver,"retained":driver_retained},"manager":{"receipt":manager,"retained":manager_retained},
        "observer":{"receipt":observer,"retained":observer_retained},"watchdog":{"receipt":watchdog,"retained":watchdog_retained},
        "outputBytes":owner.output_bytes.load(Ordering::SeqCst),"resourceUnknown":owner.resource_unknown.load(Ordering::SeqCst),
        "activeRetained":active_retained,"disabled":disabled,"canExit":can_exit}))
}

async fn native_case(run: &Run) -> Check<Value> {
    let case = run.permit.case; let original = run.original()?;
    let mut intervention = None; let mut unknown = None; let mut refused = None;
    match case {
        Case::L1 => {
            run.entered().await?;
            let recovered = run.document.environment_diagnostics_status().map_err(|_| "fixture_lost_start_status")?;
            let active = recovered.active.ok_or("fixture_lost_start_original")?;
            require(active.run_id == original.id && active.owner_generation == original.generation && recovered.status_revision > 0,
                "fixture_lost_start_identity")?;
            require(run.document.start_environment_diagnostics(run.input()).is_err()
                && run.document.configuration_edit_admit(|_| Ok(())).is_err()
                && run.document.github_connection_connect_token(&json!({})).is_err(), "fixture_reciprocal_refusal")?;
            let stale = if original.generation == "0".repeat(32) { "1".repeat(32) } else { "0".repeat(32) };
            require(run.document.cancel_environment_diagnostics(wire::Cancel { run_id: original.id.clone(), owner_generation: stale }).is_err()
                && !*original.stop.borrow(), "fixture_stale_cancel")?;
            intervention = Some(run.offset(Instant::now())?); run.cancel()?; run.permit.gate.release();
        }
        Case::L2 => { run.entered().await?; run.observed_clock(false).await?; run.permit.gate.release(); }
        Case::L3a | Case::L3b | Case::L3c | Case::L3d => {
            refused = run.readiness().await?;
            if refused.is_none() {
                intervention = Some(run.offset(Instant::now())?);
                require(intervention.is_some_and(|ms| ms < 6000), "fixture_active_route_before_work")?;
                match case {
                    Case::L3a => run.cancel()?,
                    Case::L3b => {
                        run.document.environment_fixture_registration(&run.permit.registration, true).map_err(|_| "fixture_context_generation")?;
                        run.document.environment_diagnostics_status().map_err(|_| "fixture_context_status_route")?;
                    }
                    Case::L3c => {
                        run.document.lost();
                        require(!run.document.navigation(true), "fixture_lost_document_rebound")?;
                    }
                    Case::L3d => { run.bridge.diagnostics.shutdown().await.map_err(|_| "fixture_shutdown_originals")?; }
                    _ => return Err("fixture_closed_route"),
                }
            }
        }
        Case::L5 | Case::L6a | Case::L6b | Case::L6c => {
            run.entered().await?;
            // No relay failure/result read drives this clock observation. L5
            // retains the same decoded original Frame on the stdout stack.
            unknown = Some(run.offset(run.observed_clock(true).await?)?);
            require(unknown.is_some_and(|ms| ms >= 10000), "fixture_original_h_early")?;
            run.permit.gate.release();
        }
        _ => {},
    }
    let projection = run.settle().await?;
    let returned = run.offset(Instant::now())?;
    let native = receipt(run).await?;
    if native["startup"]["returned"] == true {
        require(projection.result.as_ref().is_some_and(|t| t.lifetime.settled()), "fixture_core_original_lifetime")?;
    }
    let ordinary = if case.shim() {
        let rows = run.relay(true)?;
        let actual = check_ordinary(&rows, run)?;
        require(refused.is_none() || refused == actual, "fixture_refusal_sticky")?; refused = actual; rows
    } else { Vec::new() };
    let files = run.close_files()?;
    let value = serde_json::to_value(&projection).map_err(|_| "fixture_projection_encode")?;
    let git = value["result"]["checks"].as_array().and_then(|rows| rows.iter().find(|row| row["id"] == "git"));
    if refused.is_none() {
        let expected = match case { Case::L1 | Case::L3a => Some(Reason::Cancelled), Case::L2 | Case::L5 | Case::L6a | Case::L6b | Case::L6c => Some(Reason::TimedOut),
            Case::L3b => Some(Reason::ContextChanged), Case::L3c => Some(Reason::DocumentLost), Case::L3d => Some(Reason::Shutdown),
            Case::L4 => Some(Reason::CommandFailed), Case::L7 => Some(Reason::CleanupUnknown), _ => None };
        if let Some(reason) = expected { require(projection.reason == reason, "fixture_actual_route_reason")?; }
        if matches!(case, Case::L5 | Case::L6a | Case::L6b | Case::L6c | Case::L7) {
            require(projection.finality == Finality::Unknown && native["disabled"] == true
                && projection.outcome != Some(Outcome::Complete), "fixture_sticky_unknown")?;
        } else { require(projection.finality == Finality::Settled, "fixture_positive_finality")?; }
        if matches!(case, Case::L4 | Case::L5) {
            require(git.is_some_and(|row| row["state"] == "attempted" && row["reason"] == "command-incomplete"), "fixture_hidden_incomplete_preserved")?;
        }
        if case.active_stop() {
            require(value["result"]["lifetime"]["stopObserved"] == "cancelled", "fixture_original_core_stop")?;
        }
        if case == Case::L2 { require(returned < 10000 && native["inspection"]["joined"] == true, "fixture_late_inspection_no_acquisition")?; }
        if case == Case::L1 { require(native["inspection"]["joined"] == false, "fixture_prechild_no_inspection")?; }
        if case == Case::R2 && cfg!(target_os = "linux") {
            require(value["result"]["commandsAttempted"] == 0
                && value["result"]["checks"].as_array().is_some_and(|rows| rows.iter().all(|r| r["reason"] == "host-mismatch")), "fixture_linux_apple_mismatch")?;
        }
    }
    if case != Case::L7 { run.permit.inputs.recheck(Instant::now() + Duration::from_secs(30))?; }
    let held = *run.permit.gate.entered_at.lock().map_err(|_| "fixture_hold_record")?;
    let released = *run.permit.gate.released_at.lock().map_err(|_| "fixture_release_record")?;
    Ok(json!({"id":case.id(),"classification":match case { Case::R1 | Case::R2 => "real-source", Case::R3 => "real-zip", Case::L7 => "expected-driver-loss", _ => "synthetic-lifecycle" },
        "assertion":if refused.is_some() { "unexecuted" } else { "passed" },"reason":refused,
        "timing":{"workMs":6000,"finalityMs":10000,"heldMs":held.map(|at| at.saturating_duration_since(original.clocks.admitted).as_millis() as u64),
            "releasedMs":released.map(|at| at.saturating_duration_since(original.clocks.admitted).as_millis() as u64),
            "interventionMs":intervention,"unknownMs":unknown,"returnedMs":returned},
        "projection":projection,"native":native,"ordinary":ordinary,"reader":null,"files":files}))
}

struct MemoryControl { eof_open: AtomicBool, eof_wait: Mutex<Option<Waker>>, closes: AtomicUsize, read: AtomicUsize }
struct MemoryReader { bytes: Vec<u8>, at: usize, control: Arc<MemoryControl>, close_error: bool }
impl AsyncRead for MemoryReader {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>, buffer: &mut tokio::io::ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        if self.at < self.bytes.len() {
            let count = buffer.remaining().min(self.bytes.len() - self.at); let begin = self.at;
            buffer.put_slice(&self.bytes[begin..begin + count]); self.at += count;
            self.control.read.fetch_add(count, Ordering::SeqCst); return Poll::Ready(Ok(()));
        }
        if self.control.eof_open.load(Ordering::SeqCst) { return Poll::Ready(Ok(())); }
        if let Ok(mut wake) = self.control.eof_wait.lock() { *wake = Some(cx.waker().clone()); }
        if self.control.eof_open.load(Ordering::SeqCst) { Poll::Ready(Ok(())) } else { Poll::Pending }
    }
}
impl OriginalClose for MemoryReader {
    fn original_close(self) -> Result<(), ()> {
        self.control.closes.fetch_add(1, Ordering::SeqCst);
        if self.close_error { Err(()) } else { Ok(()) }
    }
}
fn memory(bytes: Vec<u8>, eof_open: bool, close_error: bool) -> (Arc<AsyncMutex<Pipe<MemoryReader>>>, Arc<MemoryControl>) {
    let control = Arc::new(MemoryControl { eof_open: AtomicBool::new(eof_open), eof_wait: Mutex::new(None), closes: AtomicUsize::new(0), read: AtomicUsize::new(0) });
    (Arc::new(AsyncMutex::new(Pipe { io: Some(MemoryReader { bytes, at: 0, control: control.clone(), close_error }), close: Close::New })), control)
}
fn memory_frames(owner: &Session, pad_to: Option<usize>) -> Check<Vec<u8>> {
    let accepted = json!({"protocol":wire::PROTOCOL,"runId":owner.id,"ownerGeneration":owner.generation,"seq":0,"kind":"accepted",
        "result":{"schemaVersion":1,"context":owner.context,"hostPlatform":"linux"}});
    let terminal = json!({"protocol":wire::PROTOCOL,"runId":owner.id,"ownerGeneration":owner.generation,"seq":1,"kind":"terminal",
        "result":wire::tests::terminal(&owner.context)});
    let mut first = serde_json::to_vec(&accepted).map_err(|_| "fixture_memory_encode")?;
    let mut last = serde_json::to_vec(&terminal).map_err(|_| "fixture_memory_encode")?;
    if let Some(total) = pad_to {
        require(total > first.len() + last.len() + 2 && first.pop() == Some(b'}'), "fixture_memory_pad")?;
        first.resize(total - last.len() - 3, b' '); first.push(b'}');
    }
    first.push(b'\n'); last.push(b'\n'); first.extend(last); Ok(first)
}
async fn reader_case(index: usize) -> Check<Value> {
    let (application, owner) = tests::inert_active(); owner.pipes.send_replace(Pipes::Available);
    let mut secondary_frames = 0; let mut secondary_failed = false; let mut pending_observed = false;
    let (end, count) = match index {
        0 => {
            let (error, _) = memory(vec![b'x'; 33000], true, false);
            let early = read_output(application.inner.clone(), owner.clone(), error, true, Guard::new(&application.inner, &owner)).await;
            secondary_frames = early.frames; secondary_failed = early.failed;
            let bytes = memory_frames(&owner, Some(33000))?; require(bytes.len() == 33000, "fixture_memory_total")?;
            let (output, count) = memory(bytes, true, false);
            let end = read_output(application.inner.clone(), owner.clone(), output, false, Guard::new(&application.inner, &owner)).await;
            require(end.failed && end.eof && end.closed && end.frames < 2 && owner.output_bytes.load(Ordering::SeqCst) == 66000
                && count.read.load(Ordering::SeqCst) == 33000 && early.failed, "fixture_shared_transport_cap")?; (end, count)
        }
        1 => {
            let (output, _) = memory(memory_frames(&owner, None)?, true, false);
            let early = read_output(application.inner.clone(), owner.clone(), output, false, Guard::new(&application.inner, &owner)).await;
            require(early.frames == 2 && early.eof && early.closed && !early.failed, "fixture_positive_reader")?;
            drain(&mut *owner.resources.lock().await, &application.inner, &owner);
            require(application.inner.lock().active.as_ref().is_some_and(|a| a.terminal && !a.unknown), "fixture_terminal_before_stderr")?;
            secondary_frames = early.frames; secondary_failed = early.failed;
            let (error, count) = memory(vec![b'x'], true, false);
            let end = read_output(application.inner.clone(), owner.clone(), error, true, Guard::new(&application.inner, &owner)).await;
            require(end.failed && application.inner.lock().active.as_ref().is_some_and(|a| a.unknown && a.projection.outcome != Some(Outcome::Complete)),
                "fixture_late_stderr_veto")?; (end, count)
        }
        2 => {
            let (output, count) = memory(memory_frames(&owner, None)?, false, false);
            let mut original = Box::pin(read_output(application.inner.clone(), owner.clone(), output, false, Guard::new(&application.inner, &owner)));
            pending_observed = std::future::poll_fn(|cx| Poll::Ready(matches!(original.as_mut().poll(cx), Poll::Pending))).await;
            require(pending_observed && count.closes.load(Ordering::SeqCst) == 0, "fixture_original_eof_held")?;
            drain(&mut *owner.resources.lock().await, &application.inner, &owner);
            require(application.inner.lock().active.as_ref().is_some_and(|a| a.terminal && a.projection.finality == Finality::Pending), "fixture_terminal_not_finality")?;
            count.eof_open.store(true, Ordering::SeqCst);
            if let Some(wake) = count.eof_wait.lock().map_err(|_| "fixture_memory_waker")?.take() { wake.wake(); }
            let end = original.await;
            require(end.frames == 2 && end.eof && end.closed && !end.failed, "fixture_original_eof_return")?; (end, count)
        }
        3 => {
            let (output, count) = memory(Vec::new(), true, true);
            let end = read_output(application.inner.clone(), owner.clone(), output.clone(), false, Guard::new(&application.inner, &owner)).await;
            require(!end.closed && !close_original(&mut *output.lock().await) && count.closes.load(Ordering::SeqCst) == 1
                && application.inner.lock().active.as_ref().is_some_and(|a| a.unknown), "fixture_no_close_retry")?; (end, count)
        }
        _ => return Err("fixture_closed_reader_case"),
    };
    require(count.closes.load(Ordering::SeqCst) == 1, "fixture_reader_original_close_count")?;
    let projection = if index == 0 || index == 3 { None } else { application.inner.lock().active.as_ref().map(|a| a.projection.clone()) };
    Ok(json!({"id":ORDER[index],"classification":"synthetic-reader","assertion":"passed","reason":null,"timing":null,
        "projection":projection,"native":null,"ordinary":[],"files":{"controlClosed":null,"relayClosed":null},
        "reader":{"outputBytes":owner.output_bytes.load(Ordering::SeqCst),"frames":end.frames,"eof":end.eof,"closed":end.closed,"failed":end.failed,
            "closeCalls":count.closes.load(Ordering::SeqCst),"secondaryFrames":secondary_frames,"secondaryFailed":secondary_failed,"pendingObserved":pending_observed}}))
}
fn wait_case() -> Check<Value> {
    use std::os::unix::process::ExitStatusExt;
    let (application, owner) = tests::inert_active();
    observe_child_status(&application.inner, &owner, &ExitStatus::from_raw(7 << 8));
    let r = application.inner.lock(); let projection = r.active.as_ref().ok_or("fixture_wait_original")?.projection.clone();
    require(r.disabled && projection.finality == Finality::Unknown && projection.reason == Reason::ProtocolError,
        "fixture_nonzero_wait_veto")?;
    Ok(json!({"id":"wait-nonzero","classification":"synthetic-wait","assertion":"passed","reason":null,"timing":null,
        "projection":projection,"native":null,"ordinary":[],"reader":null,"files":{"controlClosed":null,"relayClosed":null}}))
}

struct Outputs { progress: Option<File>, result: Option<File> }
pub(crate) fn original_json(file: &mut File, value: &Value, limit: usize) -> Check<()> {
    let mut bytes = serde_json::to_vec(value).map_err(|_| "fixture_output_encode")?; bytes.push(b'\n');
    require(bytes.len() <= limit, "fixture_output_limit")?;
    file.seek(SeekFrom::Start(0)).map_err(|_| "fixture_output_seek")?;
    file.write_all(&bytes).map_err(|_| "fixture_output_write")?;
    file.set_len(bytes.len() as u64).map_err(|_| "fixture_output_size")?;
    file.flush().map_err(|_| "fixture_output_flush")
}
impl Outputs {
    fn create(inputs: &BoundInputs) -> Check<Self> {
        Ok(Self { progress: Some(create_private(&inputs.data.root.join("environment-native-progress.json"))?),
            result: Some(create_private(&inputs.data.root.join("environment-native-result.json"))?) })
    }
    fn progress(&mut self, inputs: &BoundInputs, completed: usize, stage: &'static str, failure: Option<&'static str>) -> Check<()> {
        original_json(self.progress.as_mut().ok_or("fixture_progress_closed")?, &json!({"schemaVersion":1,"scope":SCOPE,
            "inputsSha256":inputs.digest,"sourceSha":inputs.data.source_sha,"platform":inputs.data.platform,"classification":"native-not-settled",
            "completedCases":&ORDER[..completed],"nextCase":ORDER.get(completed),"stage":stage,"failureCode":failure}), 8192)
    }
    fn finish(&mut self, value: &Value) -> Check<()> {
        original_json(self.result.as_mut().ok_or("fixture_result_closed")?, value, 768 * 1024)?;
        let result = self.result.take().ok_or("fixture_result_missing")?; let result_close = close_file(result);
        let progress = self.progress.take().ok_or("fixture_progress_missing")?; let progress_close = close_file(progress);
        result_close?; progress_close
    }
}
fn add_unexecuted(rows: &[Value]) -> Vec<Value> {
    let mut missing = Vec::new();
    for row in rows {
        let id = row["id"].as_str().unwrap_or("");
        if ["R1","R2","R3"].contains(&id) {
            if let Some(checks) = row["projection"]["result"]["checks"].as_array() {
                for check in checks { if check["reason"] != "observed" {
                    missing.push(json!({"case":id,"check":check["id"],"reason":check["reason"]}));
                } }
            }
        } else if row["assertion"] == "unexecuted" { missing.push(json!({"case":id,"check":"git","reason":row["reason"]})); }
    }
    missing
}
struct CompletedFixture { value: Value, _originals: Vec<Run> }
async fn schedule(inputs: Arc<BoundInputs>, outputs: &mut Outputs) -> Check<CompletedFixture> {
    let mut rows = Vec::new();
    for index in 0..4 {
        outputs.progress(&inputs, rows.len(), "reader", None)?;
        match reader_case(index).await {
            Ok(row) => rows.push(row),
            Err(error) => { let _ = outputs.progress(&inputs, rows.len(), "reader", Some("case-assertion")); return Err(error); }
        }
    }
    outputs.progress(&inputs, rows.len(), "reader", None)?;
    match wait_case() {
        Ok(row) => rows.push(row),
        Err(error) => { let _ = outputs.progress(&inputs, rows.len(), "reader", Some("case-assertion")); return Err(error); }
    }
    let mut retained = Vec::new(); let mut git_admitted = false;
    for case in [Case::R1,Case::R2,Case::R3,Case::L1,Case::L2,Case::L3a,Case::L3b,Case::L3c,Case::L3d,Case::L4,Case::L5,Case::L6a,Case::L6b,Case::L6c,Case::L7] {
        outputs.progress(&inputs, rows.len(), if case == Case::L7 { "negative-tail" } else { "native-admission" }, None)?;
        if case.shim() && !git_admitted {
            rows.push(json!({"id":case.id(),"classification":"synthetic-lifecycle","assertion":"unexecuted","reason":"git-not-admitted",
                "timing":null,"projection":null,"native":null,"ordinary":[],"reader":null,"files":{"controlClosed":null,"relayClosed":null}}));
            continue;
        }
        let mut run = Run::prepare(inputs.clone(), case)?;
        if let Err(error) = run.start() {
            let _ = outputs.progress(&inputs, rows.len(), "native-admission", Some("case-assertion"));
            // If admission had published resources despite the failed return,
            // retain their original owner rather than dropping the runtime.
            let published = run.bridge.diagnostics.inner.lock().active.as_ref().map(|a| a.owner.clone());
            if let Some(original) = published {
                run.session = Some(original); let _ = run.cancel(); run.permit.gate.release();
                if run.settle().await.is_err() || receipt(&run).await.is_err() { pending::<()>().await; }
            }
            run.close_files()?; return Err(error);
        }
        let result = match outputs.progress(&inputs, rows.len(), if case == Case::L7 { "negative-tail" } else { "native-originals" }, None) {
            Ok(()) => native_case(&run).await, Err(error) => Err(error),
        };
        let row = match result {
            Ok(row) => row,
            Err(error) => {
                let _ = outputs.progress(&inputs, rows.len(), if case == Case::L7 { "negative-tail" } else { "native-originals" },
                    Some(if error.starts_with("fixture_relay") || error.starts_with("fixture_ordinary") { "ordinary-observation" } else { "case-assertion" }));
                let _ = run.cancel(); run.permit.gate.release();
                // Only original STOP/joins. An unresolved physical tail keeps
                // this runtime/book alive until the disposable job timeout.
                if run.settle().await.is_err() || receipt(&run).await.is_err() || run.close_files().is_err() {
                    let _ = outputs.progress(&inputs, rows.len(), if case == Case::L7 { "negative-tail" } else { "native-originals" }, Some("original-physical-finality"));
                    pending::<()>().await;
                }
                retained.push(run); return Err(error);
            }
        };
        if case == Case::R1 {
            git_admitted = row["projection"]["result"]["checks"].as_array().is_some_and(|checks|
                checks.iter().any(|c| c["id"] == "git" && c["state"] == "completed"));
        }
        rows.push(row); retained.push(run);
    }
    // L7 is last. No further admission, path/runtime/compiler probe, recursive
    // cleanup or replacement owner. Only preowned bounded result DATA follows.
    require(rows.len() == ORDER.len() && rows.iter().zip(ORDER).all(|(row, id)| row["id"] == id), "fixture_complete_schedule")?;
    outputs.progress(&inputs, rows.len(), "result", None)?;
    let unexecuted = add_unexecuted(&rows);
    let complete = rows.iter().all(|r| r["assertion"] == "passed");
    let d = &inputs.data;
    let value = json!({"schemaVersion":1,"scope":SCOPE,"inputsSha256":inputs.digest,"invocationSha256":inputs.invocation_digest,
        "sourceSha":d.source_sha,"sourceTree":d.source_tree,"platform":d.platform,"target":d.target,"workflowSha":d.workflow_sha,
        "runId":d.run_id,"attempt":d.attempt,"caseOrder":ORDER,"cases":rows,"unexecuted":unexecuted,
        "classification":if complete { "finite-complete-with-expected-driver-loss" } else { "finite-incomplete-with-expected-driver-loss" }});
    Ok(CompletedFixture { value, _originals: retained })
}

#[test]
#[ignore = "disposable source-bound Linux/macOS native fixture; not a local or production qualification"]
fn hosted_environment_diagnostics_original_resources() {
    let result = (|| -> Check<()> {
        let inputs = Arc::new(BoundInputs::load()?);
        let mut outputs = Outputs::create(&inputs)?;
        outputs.progress(&inputs, 0, "inputs", None)?;
        let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).max_blocking_threads(2).enable_all().build()
            .map_err(|_| "fixture_runtime_create")?;
        let report = runtime.block_on(schedule(inputs.clone(), &mut outputs));
        match report {
            Ok(report) => outputs.finish(&report.value), // Keep actual originals through both final output closes.
            Err(error) => {
                // All admitted physical resources either joined in schedule or
                // schedule never returns. No successful result is manufactured.
                if let Some(file) = outputs.result.take() { let _ = close_file(file); }
                if let Some(file) = outputs.progress.take() { let _ = close_file(file); }
                Err(error)
            }
        }
    })();
    assert!(result.is_ok(), "finite diagnostics fixture rejected: {}", result.err().unwrap_or("unknown"));
}
