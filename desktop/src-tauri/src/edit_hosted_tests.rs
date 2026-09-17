//! Source-only, ignored real-child checks for the finite configuration owner.
//! The normal/development/packaged edit gate is NOT enabled by these checks.
//! No renderer, picker, subprocess controller, recovery, Store, or OS-fault
//! simulation is involved. Ambiguous custody retains this runtime for hosted-VM
//! disposal. Fixed self-panic and clock-retention cases may return with the edit
//! gate still Unknown only after their distinct original-resource/task proofs.
#![cfg(any(target_os = "linux", target_os = "macos"))]

use super::*;
use std::{fs, io::{Read, Write}, os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt}, path::Path,
    sync::{Condvar, atomic::{AtomicU32, AtomicUsize}}};
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const SCOPE: &str = "configuration-owner-hosted-v1";
const LOSS_SCOPE: &str = "configuration-owner-management-loss-hosted-v1";
const STOP_SCOPE: &str = "configuration-owner-stop-hosted-v1";
const CLOCK_SCOPE: &str = "configuration-owner-clock-retention-hosted-v1";
const EOF_SCOPE: &str = "configuration-transaction-eof-hosted-v1";
const OBSERVATION: Duration = Duration::from_secs(45);
const NOT_VERIFIED: &[&str] = &["production-runtime-custody", "production-save-enablement", "native-gui", "window-reload-crash",
    "parent-death", "native-stuck-wait-close", "windows-filesystem", "stores", "mobile-builds", "installers"];
const IGNORE: &[u8] = b".mobile-release/\n.mobile-release-init-prepare/\n.mobile-release-init/\n.mobile-release-init-cleanup/\n";
const NOOP_IGNORE: &[u8] = b"# fixed synthetic comment\r\n/.mobile-release/\r\n/.mobile-release-init-prepare/\r\n/.mobile-release-init/\r\n/.mobile-release-init-cleanup/\r\n";
const UNRELATED: &[u8] = b"fixed synthetic unrelated content\n";
const EOF_IGNORE_BASE: &[u8] = b"# fixed synthetic EOF ignore\n";
static BATCH_CLAIMED: AtomicBool = AtomicBool::new(false);
static RETAINED: Mutex<Option<Retention>> = Mutex::new(None);
static FIXTURE_FILES: FixtureFiles = FixtureFiles {
    opened: AtomicUsize::new(0), close_attempted: AtomicUsize::new(0),
    close_settled: AtomicUsize::new(0), unknown: AtomicBool::new(false),
};

// Keeping original books is separate from claiming their resources settled.
// Ambiguous custody never returns and drops the Tokio runtime. The fixed
// expected-loss exception below requires complete original-resource proof.
struct Retention { _owner: EditOwner, originals: Vec<Arc<Session>> }

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Failure {
    NotCompleted, HostedGuardRefused, SourceBindingMismatch, FixtureIo, FixtureCustodyUnknown,
    NativeCommandRejected, UnexpectedStatus, ObservationTimeout,
    OriginalCustodyUnknown, UnexpectedOutcome, PayloadMismatch, ReceiptIo,
}
type Check<T> = Result<T, Failure>;
fn require(condition: bool, failure: Failure) -> Check<()> { if condition { Ok(()) } else { Err(failure) } }
fn hash(bytes: &[u8]) -> String { format!("{:x}", Sha256::digest(bytes)) }
fn environment(name: &str) -> Check<String> { std::env::var(name).map_err(|_| Failure::HostedGuardRefused) }

// These finite per-Session scheduling controls never replace a native result,
// move an original resource to a fixture task, or exist in a production build.
// Gates follow the already-reviewed passive fixture pattern, without its core.
struct AsyncGate { open: watch::Sender<bool>, armed: AtomicBool, entered: AtomicBool }
impl Default for AsyncGate {
    fn default() -> Self {
        let (open, _) = watch::channel(true);
        Self { open, armed: AtomicBool::new(false), entered: AtomicBool::new(false) }
    }
}
impl AsyncGate {
    fn hold(&self) -> Check<()> {
        require(!self.armed.swap(true, Ordering::SeqCst), Failure::UnexpectedStatus)?;
        self.open.send_replace(false);
        Ok(())
    }
    async fn wait(&self) {
        let mut open = self.open.subscribe();
        self.entered.store(true, Ordering::SeqCst);
        loop {
            if *open.borrow_and_update() { return; }
            if open.changed().await.is_err() { return; }
        }
    }
    fn release(&self) { self.open.send_replace(true); }
}

#[derive(Default)]
struct BlockingGate { closed: Mutex<bool>, changed: Condvar, armed: AtomicBool, entered: AtomicBool }
impl BlockingGate {
    fn hold(&self) -> Check<()> {
        require(!self.armed.swap(true, Ordering::SeqCst), Failure::UnexpectedStatus)?;
        *self.closed.lock().map_err(|_| Failure::UnexpectedStatus)? = true;
        Ok(())
    }
    fn wait(&self) {
        let mut closed = self.closed.lock().unwrap_or_else(|error| error.into_inner());
        self.entered.store(true, Ordering::SeqCst);
        while *closed { closed = self.changed.wait(closed).unwrap_or_else(|error| error.into_inner()); }
    }
    fn release(&self) {
        *self.closed.lock().unwrap_or_else(|error| error.into_inner()) = false;
        self.changed.notify_all();
    }
}

// The sole extra bootstrap selector is a private, pre-registration two-value
// mode. No renderer/environment method can select it. Its separate source hash
// is admitted before this Schedule can be queued for an original Session.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum EofCase { Precommit, Postcommit }
impl EofCase {
    pub(super) fn name(self) -> &'static str {
        match self { Self::Precommit => "precommit-eof", Self::Postcommit => "postcommit-eof" }
    }
    fn project(self) -> &'static str {
        match self { Self::Precommit => "project-config-precommit-eof", Self::Postcommit => "project-config-postcommit-eof" }
    }
    fn boundary(self) -> &'static str {
        match self { Self::Precommit => "before-COMMITTED", Self::Postcommit => "after-durable-COMMITTED" }
    }
    fn checkpoint(self) -> &'static str {
        match self { Self::Precommit => "publisher-entry", Self::Postcommit => "descriptor-close" }
    }
    fn marker(self) -> &'static [u8] {
        match self {
            Self::Precommit => b"MRK_CONFIG_EOF_V1 precommit-eof boundary=before-COMMITTED\n",
            Self::Postcommit => b"MRK_CONFIG_EOF_V1 postcommit-eof boundary=after-durable-COMMITTED\n",
        }
    }
    fn summary(self) -> &'static [u8] {
        match self {
            Self::Precommit => b"MRK_CONFIG_EOF_V1 precommit-eof eof=1 nonempty=0 readErrors=0 checkpoint=publisher-entry applied=1 committed=0 rolledBack=1 terminal=ROLLED_BACK durable=1 recovery=1 clean=1 settled=1 cancelled=1\n",
            Self::Postcommit => b"MRK_CONFIG_EOF_V1 postcommit-eof eof=1 nonempty=0 readErrors=0 checkpoint=descriptor-close applied=1 committed=1 rolledBack=0 terminal=COMMITTED durable=1 recovery=1 clean=1 settled=1 cancelled=1\n",
        }
    }
    fn stderr_bytes(self) -> usize { self.marker().len() + self.summary().len() }
}
pub(super) fn eof_bootstrap() -> &'static str {
    concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/native_desktop_config_eof.py")
}

// Byte-exact two-record streaming admission. It allocates no input buffer and
// has no arbitrary JSON/log/line parser. Missing, duplicated, malformed, wrong-
// case and extra bytes cannot become an observation. EOF is checked separately
// by the SAME original stderr reader; these records are never stdout frames.
#[derive(Default)]
struct EofControl { bytes: usize, failed: bool }
impl EofControl {
    fn observe(&mut self, case: EofCase, bytes: &[u8]) -> bool {
        if self.failed { return false; }
        for byte in bytes {
            let expected = if self.bytes < case.marker().len() { case.marker().get(self.bytes) }
                else { case.summary().get(self.bytes - case.marker().len()) };
            if expected != Some(byte) { self.failed = true; return false; }
            self.bytes += 1;
        }
        true
    }
    fn boundary_only(&self, case: EofCase) -> bool { !self.failed && self.bytes == case.marker().len() }
    fn complete(&self, case: EofCase) -> bool { !self.failed && self.bytes == case.stderr_bytes() }
    fn records(&self, case: EofCase) -> usize {
        usize::from(!self.failed && self.bytes >= case.marker().len()) + usize::from(self.complete(case))
    }
}

pub(super) struct Schedule {
    prefix: AsyncGate, terminal: AsyncGate, inspection: BlockingGate,
    prefix_bytes: AtomicUsize, apply_suffix_started: AtomicBool,
    accepted_sequence: AtomicU32, held_terminal: Mutex<Option<(u32, wire::CoreEditOutcome)>>,
    inspection_returned: AtomicBool, acquisition_refused: AtomicBool, failed: AtomicBool,
    eof: Option<EofCase>, eof_control: Mutex<EofControl>,
}
impl Default for Schedule {
    fn default() -> Self {
        Self { prefix: AsyncGate::default(), terminal: AsyncGate::default(), inspection: BlockingGate::default(),
            prefix_bytes: AtomicUsize::new(0), apply_suffix_started: AtomicBool::new(false),
            accepted_sequence: AtomicU32::new(u32::MAX), held_terminal: Mutex::new(None),
            inspection_returned: AtomicBool::new(false), acquisition_refused: AtomicBool::new(false), failed: AtomicBool::new(false),
            eof: None, eof_control: Mutex::new(EofControl::default()) }
    }
}
impl Schedule {
    pub(super) fn eof_case(&self) -> Option<EofCase> { self.eof }
    pub(super) fn observe_stderr(&self, bytes: &[u8]) -> bool {
        let Some(case) = self.eof else { return true; }; // Ordinary stderr rules are unchanged.
        let accepted = self.eof_control.lock().map(|mut control| control.observe(case, bytes)).unwrap_or(false);
        if !accepted { self.failed.store(true, Ordering::SeqCst); }
        accepted
    }
    pub(super) fn stderr_complete(&self) -> bool {
        let Some(case) = self.eof else { return true; };
        let complete = self.eof_control.lock().map(|control| control.complete(case)).unwrap_or(false);
        if !complete { self.failed.store(true, Ordering::SeqCst); }
        complete
    }
    pub(super) async fn write_original(&self, writer: &mut ChildStdin, bytes: &[u8], ordinal: usize) -> std::io::Result<()> {
        if ordinal == 3 && self.prefix.armed.load(Ordering::SeqCst) {
            if bytes.first() != Some(&b'{') || bytes.len() < 2 {
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "fixed Apply prefix unavailable"));
            }
            writer.write_all(&bytes[..1]).await?; // Positive ORIGINAL write before the milestone.
            self.prefix_bytes.fetch_add(1, Ordering::SeqCst);
            self.prefix.wait().await;
            self.apply_suffix_started.store(true, Ordering::SeqCst);
            writer.write_all(&bytes[1..]).await
        } else { writer.write_all(bytes).await }
    }
    pub(super) async fn before_frame(&self, frame: &ChildFrame) {
        if let ChildFrame::Terminal(sequence, terminal) = frame {
            if self.terminal.armed.load(Ordering::SeqCst) {
                match self.held_terminal.lock() {
                    Ok(mut held) if held.is_none() => *held = Some((*sequence, terminal.outcome())),
                    _ => { self.failed.store(true, Ordering::SeqCst); },
                }
                // No registry/resource-book mutex is acquired here. This is
                // the same original reader, before its original frame send.
                self.terminal.wait().await;
            }
        }
    }
    pub(super) fn accepted_terminal(&self, sequence: u32) {
        // Called only in the actual correlated terminal acceptance branch.
        if self.accepted_sequence.compare_exchange(u32::MAX, sequence, Ordering::SeqCst, Ordering::SeqCst).is_err() {
            self.failed.store(true, Ordering::SeqCst);
        }
    }
    pub(super) fn inspected(&self, success: bool) {
        if success && self.inspection.armed.load(Ordering::SeqCst) {
            self.inspection_returned.store(true, Ordering::SeqCst);
            self.inspection.wait(); // Inside the ORIGINAL blocking inspection task.
        }
    }
    pub(super) fn refused_acquisition(&self) { self.acquisition_refused.store(true, Ordering::SeqCst); }
    fn sequence(&self) -> Option<u32> {
        match self.accepted_sequence.load(Ordering::SeqCst) { u32::MAX => None, value => Some(value) }
    }
    fn release(&self) { self.prefix.release(); self.terminal.release(); self.inspection.release(); }
    fn released(&self) -> bool {
        *self.prefix.open.borrow() && *self.terminal.open.borrow()
            && self.inspection.closed.lock().map(|closed| !*closed).unwrap_or(false)
    }
}

// STOP precedes release, including error/unwind paths: releasing a held partial
// Apply before cancellation could otherwise authorize its suffix. This guard
// never waits, aborts or takes native handles; the original owner still cleans.
struct GateGuard { owner: EditOwner, schedule: Arc<Schedule>, released: bool }
impl GateGuard {
    fn new(owner: &EditOwner, schedule: Arc<Schedule>) -> Self { Self { owner: owner.clone(), schedule, released: false } }
    fn release(&mut self) {
        if self.released { return; }
        let id = self.owner.inner.lock().active.as_ref().map(|active| active.session.id.clone());
        if let Some(id) = id { let _ = self.owner.close("main", &id); }
        self.schedule.release();
        self.released = true;
    }
}
impl Drop for GateGuard { fn drop(&mut self) { self.release(); } }

// Only this single-entry fixture calls these synchronous file helpers. These
// original-file receipts are separate from the native Session books. None are
// reset: a failed/lost close return permanently prohibits more fixture IO,
// receipt opens, native admission, and destruction of the retained runtime.
struct FixtureFiles {
    opened: AtomicUsize, close_attempted: AtomicUsize, close_settled: AtomicUsize, unknown: AtomicBool,
}
impl FixtureFiles {
    fn all_settled(&self) -> bool {
        let positive = self.opened.load(Ordering::SeqCst) == self.close_attempted.load(Ordering::SeqCst)
            && self.close_attempted.load(Ordering::SeqCst) == self.close_settled.load(Ordering::SeqCst);
        if !positive { self.unknown.store(true, Ordering::SeqCst); }
        positive && !self.unknown.load(Ordering::SeqCst)
    }
    fn admit(&self) -> Check<()> { require(self.all_settled(), Failure::FixtureCustodyUnknown) }
    fn acquired(&self) { self.opened.fetch_add(1, Ordering::SeqCst); }
    fn close_original(&self, file: fs::File) -> Check<()> {
        // Retire before consuming the original descriptor. Even EINTR/EBADF
        // is Unknown: never retry, inspect its number, or assume Drop settled it.
        self.close_attempted.fetch_add(1, Ordering::SeqCst);
        let descriptor: std::os::fd::OwnedFd = file.into();
        match nix::unistd::close(descriptor) {
            Ok(()) => { self.close_settled.fetch_add(1, Ordering::SeqCst); self.admit() },
            Err(_) => { self.unknown.store(true, Ordering::SeqCst); Err(Failure::FixtureCustodyUnknown) },
        }
    }
}

async fn retain_unknown_runtime() {
    // Borrow inherited stderr; do not open another file or panic on a failed
    // diagnostic write while an original descriptor may still be live.
    let _ = std::io::stderr().write_all(b"hosted configuration custody unknown; retaining runtime for infrastructure disposal\n");
    pending::<()>().await;
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Identity { device: u64, inode: u64, mode: u32, owner: u32 }
impl Identity {
    fn of(metadata: &fs::Metadata) -> Self {
        Self { device: metadata.dev(), inode: metadata.ino(), mode: metadata.mode(), owner: metadata.uid() }
    }
}
#[derive(PartialEq, Eq)]
struct OriginalFile { identity: Identity, bytes: Vec<u8> }

fn read_regular(path: &Path, limit: u64) -> Check<OriginalFile> {
    FIXTURE_FILES.admit()?;
    let named = fs::symlink_metadata(path).map_err(|_| Failure::FixtureIo)?;
    require(named.is_file() && named.len() <= limit, Failure::FixtureIo)?;
    let file = fs::OpenOptions::new().read(true).custom_flags(nix::libc::O_NOFOLLOW).open(path)
        .map_err(|_| Failure::FixtureIo)?;
    FIXTURE_FILES.acquired();
    // Bound the descriptor read even if a selected file grows during inspection.
    let mut reader = Read::take(file, limit + 1);
    let mut bytes = Vec::new();
    let read = reader.read_to_end(&mut bytes);
    let file = reader.into_inner();
    let opened = file.metadata();
    FIXTURE_FILES.close_original(file)?;
    require(read.is_ok() && bytes.len() as u64 == named.len(), Failure::FixtureIo)?;
    let opened = opened.map_err(|_| Failure::FixtureIo)?;
    let after = fs::symlink_metadata(path).map_err(|_| Failure::FixtureIo)?;
    require(Identity::of(&named) == Identity::of(&opened) && Identity::of(&named) == Identity::of(&after)
        && opened.len() == named.len() && after.len() == named.len(), Failure::FixtureIo)?;
    Ok(OriginalFile { identity: Identity::of(&named), bytes })
}

fn write_new(path: &Path, bytes: &[u8], mode: u32) -> Check<()> {
    FIXTURE_FILES.admit()?;
    let mut file = fs::OpenOptions::new().write(true).create_new(true).mode(mode).open(path)
        .map_err(|_| Failure::FixtureIo)?;
    FIXTURE_FILES.acquired();
    let wrote = file.write_all(bytes);
    FIXTURE_FILES.close_original(file)?;
    require(wrote.is_ok(), Failure::FixtureIo)
}

fn canonical_input(name: &str, exact: bool) -> Check<PathBuf> {
    FIXTURE_FILES.admit()?;
    let selected = PathBuf::from(environment(name)?);
    require(selected.is_absolute(), Failure::HostedGuardRefused)?;
    let canonical = selected.canonicalize().map_err(|_| Failure::HostedGuardRefused)?;
    require(!exact || selected.as_os_str() == canonical.as_os_str(), Failure::HostedGuardRefused)?;
    Ok(canonical)
}

// Each compiled critical source is compared with the exact checkout file before
// opening any owner. Git cleanliness/SHA provenance is checked by the separate
// reviewed hosted driver; these digests do not pretend to authenticate Git.
struct Source { id: &'static str, relative: &'static str, compiled: &'static [u8] }
const SOURCES: &[Source] = &[
    Source { id: "fixture", relative: "desktop/src-tauri/src/edit_hosted_tests.rs", compiled: include_bytes!("edit_hosted_tests.rs") },
    Source { id: "owner", relative: "desktop/src-tauri/src/edit_owner.rs", compiled: include_bytes!("edit_owner.rs") },
    Source { id: "editProtocol", relative: "desktop/src-tauri/src/edit_protocol.rs", compiled: include_bytes!("edit_protocol.rs") },
    Source { id: "runtime", relative: "desktop/src-tauri/src/runtime.rs", compiled: include_bytes!("runtime.rs") },
    Source { id: "protocol", relative: "desktop/src-tauri/src/protocol.rs", compiled: include_bytes!("protocol.rs") },
    Source { id: "errors", relative: "desktop/src-tauri/src/error.rs", compiled: include_bytes!("error.rs") },
    Source { id: "library", relative: "desktop/src-tauri/src/lib.rs", compiled: include_bytes!("lib.rs") },
    Source { id: "build", relative: "desktop/src-tauri/build.rs", compiled: include_bytes!("../build.rs") },
    Source { id: "cargoManifest", relative: "desktop/src-tauri/Cargo.toml", compiled: include_bytes!("../Cargo.toml") },
    Source { id: "cargoLock", relative: "desktop/src-tauri/Cargo.lock", compiled: include_bytes!("../Cargo.lock") },
    Source { id: "bootstrap", relative: "desktop/config_edit_bootstrap.py", compiled: include_bytes!("../../config_edit_bootstrap.py") },
    Source { id: "passiveBootstrap", relative: "desktop/engine_bootstrap.py", compiled: include_bytes!("../../engine_bootstrap.py") },
    Source { id: "corePackage", relative: "src/mobile_release/__init__.py", compiled: include_bytes!("../../../src/mobile_release/__init__.py") },
    Source { id: "engine", relative: "src/mobile_release/_desktop_edit_engine.py", compiled: include_bytes!("../../../src/mobile_release/_desktop_edit_engine.py") },
    Source { id: "control", relative: "src/mobile_release/_desktop_edit_control.py", compiled: include_bytes!("../../../src/mobile_release/_desktop_edit_control.py") },
    Source { id: "coreProtocol", relative: "src/mobile_release/_desktop_edit_protocol.py", compiled: include_bytes!("../../../src/mobile_release/_desktop_edit_protocol.py") },
    Source { id: "configEdit", relative: "src/mobile_release/config_edit.py", compiled: include_bytes!("../../../src/mobile_release/config_edit.py") },
    Source { id: "configPayloads", relative: "src/mobile_release/config_payloads.py", compiled: include_bytes!("../../../src/mobile_release/config_payloads.py") },
    Source { id: "config", relative: "src/mobile_release/config.py", compiled: include_bytes!("../../../src/mobile_release/config.py") },
    Source { id: "transaction", relative: "src/mobile_release/init_transaction.py", compiled: include_bytes!("../../../src/mobile_release/init_transaction.py") },
    Source { id: "rootCustody", relative: "src/mobile_release/init_workspace_custody.py", compiled: include_bytes!("../../../src/mobile_release/init_workspace_custody.py") },
    Source { id: "cancellation", relative: "src/mobile_release/cancellation.py", compiled: include_bytes!("../../../src/mobile_release/cancellation.py") },
    Source { id: "buildInputs", relative: "src/mobile_release/build_inputs.py", compiled: include_bytes!("../../../src/mobile_release/build_inputs.py") },
    Source { id: "coreErrors", relative: "src/mobile_release/errors.py", compiled: include_bytes!("../../../src/mobile_release/errors.py") },
    Source { id: "preview", relative: "src/mobile_release/api/_preview.py", compiled: include_bytes!("../../../src/mobile_release/api/_preview.py") },
    Source { id: "nativeFixture", relative: "tests/native_desktop_config.py", compiled: include_bytes!("../../../tests/native_desktop_config.py") },
];
// Deliberately not added to SOURCES: ordinary/loss/H1–H4 receipt schemas retain
// their exact 26-key map. Only the separately admitted EOF invocation adds it.
const EOF_SOURCE: Source = Source { id: "transactionEofShim", relative: "tests/native_desktop_config_eof.py",
    compiled: include_bytes!("../../../tests/native_desktop_config_eof.py") };

struct Inputs { root: PathBuf, identity: Identity, bindings: Value }
impl Inputs {
    fn admit() -> Check<Self> {
        FIXTURE_FILES.admit()?;
        require(environment("MRK_DESKTOP_EDIT_HOSTED_CHECKS")? == "configuration-v1"
            && environment("GITHUB_ACTIONS")? == "true"
            && environment("RUNNER_ENVIRONMENT")? == "github-hosted"
            && !cfg!(feature = "desktop-shell") && cfg!(debug_assertions), Failure::HostedGuardRefused)?;
        let runner_os = if cfg!(target_os = "linux") { "Linux" } else { "macOS" };
        require(environment("RUNNER_OS")? == runner_os, Failure::HostedGuardRefused)?;
        let temporary = canonical_input("RUNNER_TEMP", false)?;
        let root = canonical_input("MRK_DESKTOP_EDIT_TEST_ROOT", true)?;
        let manifest = Path::new(env!("CARGO_MANIFEST_DIR")).canonicalize().map_err(|_| Failure::HostedGuardRefused)?;
        let repository = manifest.parent().and_then(Path::parent).ok_or(Failure::HostedGuardRefused)?;
        require(std::env::current_dir().map_err(|_| Failure::HostedGuardRefused)? == manifest
            && root != temporary && root.starts_with(&temporary)
            && !root.starts_with(repository) && !repository.starts_with(&root), Failure::HostedGuardRefused)?;
        let metadata = fs::symlink_metadata(&root).map_err(|_| Failure::HostedGuardRefused)?;
        let temp_metadata = fs::symlink_metadata(&temporary).map_err(|_| Failure::HostedGuardRefused)?;
        let source_metadata = fs::symlink_metadata(&manifest).map_err(|_| Failure::HostedGuardRefused)?;
        require(metadata.is_dir() && temp_metadata.is_dir() && metadata.mode() & 0o7777 == 0o700
            && metadata.uid() == temp_metadata.uid() && metadata.uid() == source_metadata.uid()
            && fs::read_dir(&root).map_err(|_| Failure::HostedGuardRefused)?.next().is_none(), Failure::HostedGuardRefused)?;
        let source = canonical_input("MRK_DESKTOP_DEV_CORE", true)?;
        require(source == repository.join("src") && source.is_dir(), Failure::HostedGuardRefused)?;
        let python = canonical_input("MRK_DESKTOP_DEV_PYTHON", true)?;
        require(!python.starts_with(&root) && !python.starts_with(repository), Failure::HostedGuardRefused)?;
        let python_hash = hash(&read_regular(&python, 64 * 1024 * 1024)?.bytes);
        let source_sha = environment("GITHUB_SHA")?;
        require(matches!(source_sha.len(), 40 | 64)
            && source_sha.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
            && environment("MRK_DESKTOP_EDIT_SOURCE_SHA")? == source_sha
            && option_env!("GITHUB_SHA") == Some(source_sha.as_str()), Failure::SourceBindingMismatch)?;
        let mut source_hashes = serde_json::Map::new();
        for item in SOURCES {
            let actual = read_regular(&repository.join(item.relative), 2 * 1024 * 1024)?;
            let expected = hash(item.compiled);
            require(hash(&actual.bytes) == expected, Failure::SourceBindingMismatch)?;
            source_hashes.insert(item.id.to_owned(), json!(expected));
        }
        let bindings = json!({"sourceSha":source_sha, "host":std::env::consts::OS,
            "target":crate::runtime::COMPILED_TARGET, "runtimeMode":"trusted-development-only",
            "pythonSha256":python_hash, "sourceHashes":source_hashes,
            "payloadHashes":{"draft":hash(&draft_bytes()?), "createConfig":hash(&create_bytes()?),
                "createIgnore":hash(IGNORE), "noOpConfig":hash(&noop_bytes()?), "noOpIgnore":hash(NOOP_IGNORE),
                "unrelated":hash(UNRELATED)}});
        // The hosted driver supplies the canonical setup-Python executable.
        // No process environment or runtime selection is changed by this test.
        Ok(Self { root, identity: Identity::of(&metadata), bindings })
    }
    fn same_root(&self) -> Check<()> {
        FIXTURE_FILES.admit()?;
        let current = fs::symlink_metadata(&self.root).map_err(|_| Failure::FixtureIo)?;
        require(current.is_dir() && Identity::of(&current) == self.identity, Failure::FixtureIo)
    }
    fn admit_eof_source(&mut self) -> Check<()> {
        self.same_root()?;
        require(self.root.file_name().and_then(|name| name.to_str()) == Some("config-transaction-eof"), Failure::HostedGuardRefused)?;
        let repository = Path::new(env!("CARGO_MANIFEST_DIR")).parent().and_then(Path::parent).ok_or(Failure::HostedGuardRefused)?;
        let actual = read_regular(&repository.join(EOF_SOURCE.relative), 2 * 1024 * 1024)?;
        let expected = hash(EOF_SOURCE.compiled);
        require(hash(&actual.bytes) == expected, Failure::SourceBindingMismatch)?;
        let sources = self.bindings.get_mut("sourceHashes").and_then(Value::as_object_mut).ok_or(Failure::SourceBindingMismatch)?;
        require(sources.insert(EOF_SOURCE.id.to_owned(), json!(expected)).is_none(), Failure::SourceBindingMismatch)?;
        let payloads = self.bindings.get_mut("payloadHashes").and_then(Value::as_object_mut).ok_or(Failure::PayloadMismatch)?;
        for (name, value) in [("eofDraft", hash(&eof_draft_bytes()?)), ("eofConfig", hash(&eof_config_bytes()?)),
                              ("eofInitialIgnore", hash(EOF_IGNORE_BASE)), ("eofIgnore", hash(&eof_ignore_bytes()))] {
            require(payloads.insert(name.to_owned(), json!(value)).is_none(), Failure::PayloadMismatch)?;
        }
        Ok(())
    }
}

fn document() -> Value {
    json!({"schemaVersion":1,"version":{"source":"release/version.properties","nameKey":"VERSION_NAME","buildKey":"BUILD_NUMBER"},
        "source":{"candidateBranch":"main","productionBranch":"main"},
        "android":{"enabled":true,"applicationId":"org.fixture.app","identityStatus":"unverified"},"ios":{"enabled":false},
        "metadata":{"root":"release/store","androidLocales":["en-US"],"iosLocales":[]},
        "services":{"androidFirebase":"disabled","iosFirebase":"disabled"},
        "projectChecks":{"preflight":[],"androidArtifact":[],"iosArtifact":[]}})
}
fn draft_bytes() -> Check<Vec<u8>> { serde_json::to_vec(&document()).map_err(|_| Failure::PayloadMismatch) }
fn create_bytes() -> Check<Vec<u8>> {
    // This fixed ASCII fixture has the same object order as its Rust request.
    let mut bytes = serde_json::to_vec_pretty(&document()).map_err(|_| Failure::PayloadMismatch)?;
    bytes.push(b'\n');
    Ok(bytes)
}
fn noop_bytes() -> Check<Vec<u8>> { let mut bytes = draft_bytes()?; bytes.extend_from_slice(b"\r\n"); Ok(bytes) }
fn eof_document() -> Value {
    let mut draft = document();
    draft["android"]["applicationId"] = json!("org.fixture.updated");
    draft
}
fn eof_draft_bytes() -> Check<Vec<u8>> { serde_json::to_vec(&eof_document()).map_err(|_| Failure::PayloadMismatch) }
fn eof_config_bytes() -> Check<Vec<u8>> {
    let mut bytes = serde_json::to_vec_pretty(&eof_document()).map_err(|_| Failure::PayloadMismatch)?;
    bytes.push(b'\n');
    Ok(bytes)
}
fn eof_ignore_bytes() -> Vec<u8> { [EOF_IGNORE_BASE, IGNORE].concat() }

#[derive(Clone, Copy)]
enum Case { Create, NoOp, Discard }
impl Case {
    fn name(self) -> &'static str { match self { Self::Create => "create", Self::NoOp => "no-op", Self::Discard => "discard-editing" } }
    fn project(self) -> &'static str { match self { Self::Create => "project-config-create", Self::NoOp => "project-config-noop", Self::Discard => "project-config-discard" } }
    fn frames(self) -> (usize, usize) { if matches!(self, Self::Discard) { (1, 2) } else { (3, 3) } }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ManagementLoss { Driver, Watchdog }
impl ManagementLoss {
    fn name(self) -> &'static str { match self { Self::Driver => "driver-loss", Self::Watchdog => "watchdog-loss" } }
    fn task(self) -> &'static str { match self { Self::Driver => "driver", Self::Watchdog => "watchdog" } }
    fn project(self) -> &'static str {
        match self { Self::Driver => "project-config-driver-loss", Self::Watchdog => "project-config-watchdog-loss" }
    }
}

fn inventory(root: &Path, expected: &[&str]) -> Check<()> {
    FIXTURE_FILES.admit()?;
    let mut names = Vec::new();
    for entry in fs::read_dir(root).map_err(|_| Failure::FixtureIo)? {
        let entry = entry.map_err(|_| Failure::FixtureIo)?;
        require(names.len() < 16, Failure::PayloadMismatch)?;
        names.push(entry.file_name().into_string().map_err(|_| Failure::PayloadMismatch)?);
    }
    names.sort();
    let mut expected = expected.to_vec(); expected.sort();
    require(names.iter().map(String::as_str).eq(expected), Failure::PayloadMismatch)
}
fn originals(root: &Path) -> Check<Vec<OriginalFile>> {
    ["release/mobile-release.json", ".gitignore", "unrelated.txt"].iter()
        .map(|name| read_regular(&root.join(name), 1024 * 1024)).collect()
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Facts {
    original_wait: bool, stdout_eof: bool, stderr_eof: bool,
    stdin_closed: bool, stdout_closed: bool, stderr_closed: bool,
    startup_joined: bool, io_joined: bool, driver_joined: bool, watchdog_joined: bool, manager_joined: bool,
    request_frames: usize, response_frames: usize, stdout_bytes: usize, stderr_bytes: usize,
    force_attempted: bool,
}

#[derive(Clone, Copy)]
enum ExpectedStderr { Empty, TransactionEof(EofCase) }
impl ExpectedStderr {
    fn accepts(self, session: &Session, end: &ReadEnd) -> bool {
        if end.frames != 0 { return false; } // stderr control never counts as stdout protocol.
        match self {
            Self::Empty => session.fixture_schedule.eof_case().is_none() && end.bytes == 0,
            Self::TransactionEof(case) => session.fixture_schedule.eof_case() == Some(case)
                && end.bytes == case.stderr_bytes() && session.fixture_schedule.stderr_complete(),
        }
    }
}

fn original_resource_facts(session: &Session, loss: Option<ManagementLoss>, expected_stderr: ExpectedStderr) -> Check<Facts> {
    // These are the retained original books. Do not poll/join/close a resource
    // again or replace a missing receipt with an is_finished/Drop observation.
    // Actual manager join plus the complete original-resource proof makes its
    // retained final observer pure; that observer is never joined by a fixture.
    let book = session.resources.try_lock().map_err(|_| Failure::OriginalCustodyUnknown)?;
    let startup = session.startup.try_lock().map_err(|_| Failure::OriginalCustodyUnknown)?;
    let input = session.input.try_lock().map_err(|_| Failure::OriginalCustodyUnknown)?;
    let output = session.output.try_lock().map_err(|_| Failure::OriginalCustodyUnknown)?;
    let error = session.error.try_lock().map_err(|_| Failure::OriginalCustodyUnknown)?;
    let driver = session.driver.try_lock().map_err(|_| Failure::OriginalCustodyUnknown)?;
    let watchdog = session.watchdog.try_lock().map_err(|_| Failure::OriginalCustodyUnknown)?;
    let manager = session.manager.try_lock().map_err(|_| Failure::OriginalCustodyUnknown)?;
    let observer = session.observer.try_lock().map_err(|_| Failure::OriginalCustodyUnknown)?;
    let write = book.write_end.as_ref().ok_or(Failure::OriginalCustodyUnknown)?;
    let out = book.out_end.as_ref().ok_or(Failure::OriginalCustodyUnknown)?;
    let err = book.err_end.as_ref().ok_or(Failure::OriginalCustodyUnknown)?;
    let lost_driver = loss == Some(ManagementLoss::Driver);
    let lost_watchdog = loss == Some(ManagementLoss::Watchdog);
    require(startup.attempted && startup.returned && !startup.failed && startup.child.is_none()
        && book.inspection_joined && book.acquisition_joined && book.inspection.is_none() && book.acquisition.is_none()
        && !book.inspection_join_failed && !book.acquisition_join_failed
        && book.child.as_ref().is_some_and(|child| child.stdin.is_none() && child.stdout.is_none() && child.stderr.is_none())
        && book.waited.as_ref().is_some_and(|status| status.success()) && !book.wait_failed
        && book.writer.is_none() && book.stdout.is_none() && book.stderr.is_none()
        && !book.write_join_failed && !book.out_join_failed && !book.err_join_failed
        && write.closed && !write.failed && out.eof && out.closed && !out.failed && err.eof && err.closed && !err.failed
        && input.io.is_none() && input.close == Receipt::Settled
        && output.io.is_none() && output.close == Receipt::Settled
        && error.io.is_none() && error.close == Receipt::Settled
        && book.driver_joined == !lost_driver && book.watchdog_joined == !lost_watchdog
        && session.driver_joined.load(Ordering::SeqCst) == !lost_driver
        && session.watchdog_joined.load(Ordering::SeqCst) == !lost_watchdog
        && session.driver_join_failed.load(Ordering::SeqCst) == lost_driver
        && session.watchdog_join_failed.load(Ordering::SeqCst) == lost_watchdog
        && session.driver_join_panicked.load(Ordering::SeqCst) == lost_driver
        && session.watchdog_join_panicked.load(Ordering::SeqCst) == lost_watchdog
        && driver.is_some() == lost_driver && watchdog.is_some() == lost_watchdog
        && book.manager_joined && manager.is_none() && !session.manager_join_failed.load(Ordering::SeqCst)
        && !session.manager_join_panicked.load(Ordering::SeqCst) && observer.is_some()
        && book.frames.is_some() && *session.pipes.borrow() == PipeAcquisition::Available
        && session.driver_done.load(Ordering::SeqCst) && session.resource_unknown.load(Ordering::SeqCst) == loss.is_some()
        && !session.fixture_driver_loss.load(Ordering::SeqCst) && !session.fixture_watchdog_loss.load(Ordering::SeqCst)
        && !session.fixture_schedule.failed.load(Ordering::SeqCst)
        && !book.force_attempted && out.bytes > 0 && out.bytes <= wire::STDOUT_LIMIT
        && expected_stderr.accepts(session, err), Failure::OriginalCustodyUnknown)?;
    Ok(Facts { original_wait:true, stdout_eof:out.eof, stderr_eof:err.eof,
        stdin_closed:write.closed, stdout_closed:out.closed, stderr_closed:err.closed,
        startup_joined:book.inspection_joined && book.acquisition_joined,
        io_joined:book.writer.is_none() && book.stdout.is_none() && book.stderr.is_none(),
        driver_joined:book.driver_joined, watchdog_joined:book.watchdog_joined, manager_joined:book.manager_joined,
        request_frames:write.frames, response_frames:out.frames, stdout_bytes:out.bytes, stderr_bytes:err.bytes,
        force_attempted:book.force_attempted })
}
fn original_facts(session: &Session) -> Check<Facts> { original_resource_facts(session, None, ExpectedStderr::Empty) }
fn original_eof_facts(session: &Session, case: EofCase) -> Check<Facts> {
    original_resource_facts(session, None, ExpectedStderr::TransactionEof(case))
}

fn no_acquisition_facts(session: &Session) -> Check<Facts> {
    // Separate proof, NOT a relaxed spawned-child checker. The positive
    // original refusal branch and inspection join establish no acquisition;
    // empty slots alone would not. Absent endpoints keep false EOF/close facts.
    let book = session.resources.try_lock().map_err(|_| Failure::OriginalCustodyUnknown)?;
    let startup = session.startup.try_lock().map_err(|_| Failure::OriginalCustodyUnknown)?;
    let input = session.input.try_lock().map_err(|_| Failure::OriginalCustodyUnknown)?;
    let output = session.output.try_lock().map_err(|_| Failure::OriginalCustodyUnknown)?;
    let error = session.error.try_lock().map_err(|_| Failure::OriginalCustodyUnknown)?;
    let driver = session.driver.try_lock().map_err(|_| Failure::OriginalCustodyUnknown)?;
    let watchdog = session.watchdog.try_lock().map_err(|_| Failure::OriginalCustodyUnknown)?;
    let manager = session.manager.try_lock().map_err(|_| Failure::OriginalCustodyUnknown)?;
    let observer = session.observer.try_lock().map_err(|_| Failure::OriginalCustodyUnknown)?;
    let write = book.write_end.as_ref().ok_or(Failure::OriginalCustodyUnknown)?;
    let out = book.out_end.as_ref().ok_or(Failure::OriginalCustodyUnknown)?;
    let err = book.err_end.as_ref().ok_or(Failure::OriginalCustodyUnknown)?;
    require(session.fixture_schedule.inspection_returned.load(Ordering::SeqCst)
        && session.fixture_schedule.acquisition_refused.load(Ordering::SeqCst)
        && !session.fixture_schedule.failed.load(Ordering::SeqCst)
        && book.inspection_joined && book.inspection.is_none() && !book.inspection_join_failed
        && book.acquisition.is_none() && !book.acquisition_joined && !book.acquisition_join_failed
        && !startup.attempted && !startup.returned && !startup.failed && startup.child.is_none()
        && book.child.is_none() && book.waited.is_none() && !book.wait_failed && !book.force_attempted
        && book.writer.is_none() && book.stdout.is_none() && book.stderr.is_none()
        && !book.write_join_failed && !book.out_join_failed && !book.err_join_failed
        && write.frames == 0 && !write.closed && !write.failed
        && out.frames == 0 && out.bytes == 0 && !out.eof && !out.closed && !out.failed
        && err.frames == 0 && err.bytes == 0 && !err.eof && !err.closed && !err.failed
        && input.io.is_none() && input.close == Receipt::New
        && output.io.is_none() && output.close == Receipt::New
        && error.io.is_none() && error.close == Receipt::New
        && book.driver_joined && book.watchdog_joined && book.manager_joined
        && session.driver_joined.load(Ordering::SeqCst) && session.watchdog_joined.load(Ordering::SeqCst)
        && !session.driver_join_failed.load(Ordering::SeqCst) && !session.watchdog_join_failed.load(Ordering::SeqCst)
        && !session.driver_join_panicked.load(Ordering::SeqCst) && !session.watchdog_join_panicked.load(Ordering::SeqCst)
        && !session.manager_join_failed.load(Ordering::SeqCst) && !session.manager_join_panicked.load(Ordering::SeqCst)
        && driver.is_none() && watchdog.is_none() && manager.is_none() && observer.is_some()
        && book.frames.is_some() && *session.pipes.borrow() == PipeAcquisition::Absent
        && session.driver_done.load(Ordering::SeqCst) && !session.resource_unknown.load(Ordering::SeqCst)
        && !session.fixture_driver_loss.load(Ordering::SeqCst) && !session.fixture_watchdog_loss.load(Ordering::SeqCst),
        Failure::OriginalCustodyUnknown)?;
    Ok(Facts { original_wait:book.waited.is_some(), stdout_eof:out.eof, stderr_eof:err.eof,
        stdin_closed:write.closed, stdout_closed:out.closed, stderr_closed:err.closed,
        startup_joined:book.inspection_joined && book.acquisition_joined,
        io_joined:book.writer.is_none() && book.stdout.is_none() && book.stderr.is_none(),
        driver_joined:book.driver_joined, watchdog_joined:book.watchdog_joined, manager_joined:book.manager_joined,
        request_frames:write.frames, response_frames:out.frames, stdout_bytes:out.bytes, stderr_bytes:err.bytes,
        force_attempted:book.force_attempted })
}

fn projection(status: &ConfigEditStatus, session: &str) -> Check<EditProjection> {
    status.active.as_ref().filter(|p| p.session_id == session)
        .or_else(|| status.last_terminal.as_ref().filter(|p| p.session_id == session))
        .cloned().ok_or(Failure::UnexpectedStatus)
}
async fn observed(owner: &EditOwner, session: &str, desired: Phase) -> Check<EditProjection> {
    let end = Instant::now() + OBSERVATION;
    let mut revisions = owner.subscribe();
    loop {
        let status = owner.status().map_err(|_| Failure::OriginalCustodyUnknown)?;
        let current = projection(&status, session)?;
        require(!owner.disabled() && current.phase != Phase::Unknown && current.native_finality != NativeFinality::Unknown
            && !current.late_settled, Failure::OriginalCustodyUnknown)?;
        if current.phase == desired { return Ok(current); }
        require(current.phase != Phase::Final, Failure::UnexpectedStatus)?;
        if Instant::now() >= end { return Err(Failure::ObservationTimeout); }
        tokio::select! {
            result = revisions.changed() => { result.map_err(|_| Failure::UnexpectedStatus)?; },
            _ = tokio::time::sleep_until(tokio::time::Instant::from_std(end)) => return Err(Failure::ObservationTimeout),
        }
    }
}

struct Batch { owner: EditOwner, originals: Vec<Arc<Session>>, missing_original: bool, cases: Vec<Value> }
impl Batch {
    fn open(&mut self, project: &'static str, root: &Path) -> Check<Arc<Session>> {
        FIXTURE_FILES.admit()?;
        require(self.owner.can_exit() && !self.owner.disabled(), Failure::OriginalCustodyUnknown)?;
        let result = self.owner.open("main", project.to_owned(), root.to_path_buf());
        // Retain before checking even an errored admission result: registration
        // may already have happened. The registry owns the original throughout.
        let original = {
            let registry = self.owner.inner.lock();
            if registry.last.as_ref().is_some_and(|last| !self.originals.iter().any(|owner| owner.id == last.session_id)) {
                self.missing_original = true;
            }
            registry.active.as_ref().map(|active| active.session.clone())
        };
        if let Some(original) = &original {
            self.originals.push(original.clone());
            let mut retained = RETAINED.lock().map_err(|_| Failure::OriginalCustodyUnknown)?;
            retained.as_mut().ok_or(Failure::OriginalCustodyUnknown)?.originals.push(original.clone());
        }
        let admission = result.map_err(|_| Failure::NativeCommandRejected)?;
        let original = match original { Some(original) => original, None => {
            self.missing_original = true;
            return Err(Failure::OriginalCustodyUnknown);
        }};
        let admitted = projection(&admission, &original.id)?;
        require(admitted.phase == Phase::Opening && !admitted.apply_submitted, Failure::UnexpectedStatus)?;
        Ok(original)
    }
    fn all_settled(&self) -> bool {
        FIXTURE_FILES.all_settled() && !self.missing_original && self.owner.can_exit()
            && self.originals.iter().all(|original| original_facts(original).is_ok())
    }
    async fn stop_original(&self) {
        let id = self.owner.inner.lock().active.as_ref().map(|active| active.session.id.clone());
        if let Some(id) = id {
            let _ = self.owner.close("main", &id); // Idempotent original EOF only.
            let _ = observed(&self.owner, &id, Phase::Final).await;
        }
    }
}

async fn exercise(batch: &mut Batch, inputs: &Inputs, case: Case) -> Check<()> {
    inputs.same_root()?;
    let root = inputs.root.join(case.name());
    fs::DirBuilder::new().mode(0o700).create(&root).map_err(|_| Failure::FixtureIo)?;
    let before = if matches!(case, Case::NoOp) {
        fs::DirBuilder::new().mode(0o700).create(root.join("release")).map_err(|_| Failure::FixtureIo)?;
        write_new(&root.join("release/mobile-release.json"), &noop_bytes()?, 0o640)?;
        write_new(&root.join(".gitignore"), NOOP_IGNORE, 0o600)?;
        write_new(&root.join("unrelated.txt"), UNRELATED, 0o600)?;
        Some(originals(&root)?)
    } else { None };
    let original = batch.open(case.project(), &root)?;
    let editing = observed(&batch.owner, &original.id, Phase::Editing).await?;
    let checkout = editing.checkout.as_ref().ok_or(Failure::UnexpectedStatus)?;
    require(checkout.base == if matches!(case, Case::NoOp) { document() } else { Value::Null }, Failure::UnexpectedOutcome)?;
    if matches!(case, Case::Discard) {
        batch.owner.close("main", &original.id).map_err(|_| Failure::NativeCommandRejected)?;
    } else {
        let admission = batch.owner.prepare("main", PrepareConfigEdit { session_id:original.id.clone(),
            revision:checkout.revision.clone(), expected_base:checkout.base.clone(), draft:document(), draft_revision:1, baseline_generation:0 })
            .map_err(|_| Failure::NativeCommandRejected)?;
        require(projection(&admission, &original.id)?.phase == Phase::Preparing, Failure::UnexpectedStatus)?;
        let reviewing = observed(&batch.owner, &original.id, Phase::Reviewing).await?;
        let plan = reviewing.prepared.as_ref().ok_or(Failure::UnexpectedStatus)?;
        require(plan.revision == checkout.revision && plan.draft_revision == 1 && plan.baseline_generation == 0, Failure::UnexpectedStatus)?;
        if matches!(case, Case::Create) {
            inventory(&root, &[])?; // Capture/Prepare did not stage either file.
            require(plan.view.create_release_directory && plan.view.files.iter().all(|file| file.action == "create"), Failure::UnexpectedOutcome)?;
        } else {
            require(!plan.view.create_release_directory && plan.view.files.iter().all(|file| file.action == "preserve"), Failure::UnexpectedOutcome)?;
            require(before.as_ref() == Some(&originals(&root)?), Failure::PayloadMismatch)?;
        }
        let admission = batch.owner.apply("main", &original.id, &plan.plan_token).map_err(|_| Failure::NativeCommandRejected)?;
        require(projection(&admission, &original.id)?.apply_submitted, Failure::UnexpectedStatus)?;
        if matches!(case, Case::Create) {
            // This may observe Applying or Final; it may never queue frame four.
            let duplicate = batch.owner.apply("main", &original.id, &plan.plan_token).map_err(|_| Failure::NativeCommandRejected)?;
            require(projection(&duplicate, &original.id)?.apply_submitted, Failure::UnexpectedStatus)?;
        }
    }
    let terminal = observed(&batch.owner, &original.id, Phase::Final).await?;
    require(terminal.native_finality == NativeFinality::Settled && !terminal.late_settled && batch.owner.can_exit(), Failure::OriginalCustodyUnknown)?;
    let facts = original_facts(&original)?;
    require((facts.request_frames, facts.response_frames) == case.frames(), Failure::UnexpectedOutcome)?;
    let core = terminal.core_outcome.as_ref().ok_or(Failure::UnexpectedOutcome)?;
    let expected = match case {
        Case::Create => core.effect == Effect::Committed && core.journal == Journal::Clean && core.reason == CoreReason::None && terminal.native_reason == Reason::None,
        Case::NoOp => core.effect == Effect::Unchanged && core.journal == Journal::NotCreated && core.reason == CoreReason::None && terminal.native_reason == Reason::None,
        Case::Discard => core.effect == Effect::NotStarted && core.journal == Journal::NotCreated
            && matches!(core.reason, CoreReason::Cancelled | CoreReason::None) && terminal.native_reason == Reason::Discarded && !terminal.apply_submitted,
    };
    require(expected && core.resources == ResourceState::Settled, Failure::UnexpectedOutcome)?;
    match case {
        Case::Create => {
            require(read_regular(&root.join("release/mobile-release.json"), 512 * 1024)?.bytes == create_bytes()?
                && read_regular(&root.join(".gitignore"), 1024 * 1024)?.bytes == IGNORE, Failure::PayloadMismatch)?;
            inventory(&root, &[".gitignore", "release"])?;
            inventory(&root.join("release"), &["mobile-release.json"])?;
        }
        Case::NoOp => {
            require(before.as_ref() == Some(&originals(&root)?), Failure::PayloadMismatch)?;
            inventory(&root, &[".gitignore", "release", "unrelated.txt"])?;
            inventory(&root.join("release"), &["mobile-release.json"])?;
        }
        Case::Discard => inventory(&root, &[])?,
    }
    let mut evidence = serde_json::to_value(&facts).map_err(|_| Failure::ReceiptIo)?;
    evidence["name"] = json!(case.name());
    evidence["outcome"] = json!(core);
    evidence["nativeReason"] = json!(terminal.native_reason);
    evidence["nativeFinality"] = json!(terminal.native_finality);
    batch.cases.push(evidence);
    Ok(())
}

fn management_loss_facts(batch: &Batch, original: &Arc<Session>, loss: ManagementLoss) -> Check<Value> {
    FIXTURE_FILES.admit()?;
    require(!batch.missing_original && batch.originals.len() == 1
        && Arc::ptr_eq(&batch.originals[0], original), Failure::OriginalCustodyUnknown)?;
    let facts = original_resource_facts(original, Some(loss), ExpectedStderr::Empty)?;
    require((facts.request_frames, facts.response_frames) == (1, 2), Failure::UnexpectedOutcome)?;
    let registry_disabled = {
        let registry = batch.owner.inner.lock();
        require(registry.active.as_ref().is_some_and(|active| Arc::ptr_eq(&active.session, original) && active.unknown && active.terminal)
            && registry.last.is_none() && !registry.stopping && !registry.exhausted
            && registry.document_bound && !registry.document_lost
            && !batch.owner.inner.poisoned.load(Ordering::SeqCst), Failure::OriginalCustodyUnknown)?;
        registry.disabled
    };
    let status = batch.owner.status().map_err(|_| Failure::OriginalCustodyUnknown)?;
    let current = projection(&status, &original.id)?;
    let edit_permit_closed = !status.capability.available && status.capability.reason == EditAvailability::CleanupUnknown;
    let native_can_exit = batch.owner.can_exit();
    require(registry_disabled && batch.owner.disabled() && edit_permit_closed && !native_can_exit
        && current.phase == Phase::Unknown && current.native_finality == NativeFinality::Unknown && !current.late_settled
        && current.native_reason == Reason::CleanupUnknown && !current.apply_submitted && current.prepared.is_none()
        && current.checkout.as_ref().is_some_and(|checkout| checkout.base == Value::Null)
        && current.core_outcome.as_ref().is_some_and(|core| core.effect == Effect::NotStarted
            && core.journal == Journal::NotCreated && core.resources == ResourceState::Settled
            && matches!(core.reason, CoreReason::Cancelled | CoreReason::None)),
        Failure::OriginalCustodyUnknown)?;
    let mut evidence = serde_json::to_value(&facts).map_err(|_| Failure::ReceiptIo)?;
    evidence["name"] = json!(loss.name());
    evidence["nativePhase"] = json!(current.phase);
    evidence["nativeFinality"] = json!(current.native_finality);
    evidence["registryDisabled"] = json!(registry_disabled);
    evidence["editPermitClosed"] = json!(edit_permit_closed);
    evidence["nativeCanExit"] = json!(native_can_exit);
    evidence["originalResourcesSettled"] = json!(true);
    evidence["failedTask"] = json!(loss.task());
    // The task-specific panicked/failed receipts checked above are written
    // only after the original JoinHandle actually returns Err(error), with
    // error.is_panic() && !error.is_cancelled(). Its Some handle is never repolled.
    evidence["failedJoinKind"] = json!("panic");
    evidence["failedTaskHandleRetained"] = json!(true);
    Ok(evidence)
}

async fn observed_management_loss(batch: &Batch, original: &Arc<Session>, loss: ManagementLoss) -> Check<Value> {
    let end = Instant::now() + OBSERVATION;
    let mut revisions = batch.owner.subscribe();
    loop {
        FIXTURE_FILES.admit()?;
        match management_loss_facts(batch, original, loss) {
            Ok(evidence) => return Ok(evidence),
            Err(Failure::OriginalCustodyUnknown | Failure::UnexpectedStatus) => {},
            Err(code) => return Err(code),
        }
        if Instant::now() >= end { return Err(Failure::ObservationTimeout); }
        // Read-only inspection of the same retained receipts can be retried;
        // this never polls an original JoinHandle or opens a new OS observer.
        tokio::select! {
            result = revisions.changed() => { result.map_err(|_| Failure::UnexpectedStatus)?; },
            _ = tokio::time::sleep(Duration::from_millis(50)) => {},
        }
    }
}

async fn exercise_management_loss(batch: &mut Batch, inputs: &Inputs, loss: ManagementLoss) -> Check<Value> {
    inputs.same_root()?;
    let root = inputs.root.join(loss.name());
    fs::DirBuilder::new().mode(0o700).create(&root).map_err(|_| Failure::FixtureIo)?;
    let original = batch.open(loss.project(), &root)?;
    let editing = observed(&batch.owner, &original.id, Phase::Editing).await?;
    require(editing.checkout.as_ref().is_some_and(|checkout| checkout.base == Value::Null)
        && !editing.apply_submitted && editing.prepared.is_none(), Failure::UnexpectedStatus)?;
    inventory(&root, &[])?;
    // Exactly one fixed quiescent self-panic, only after real Editing. There
    // is no arbitrary task selector, task.abort(), fault controller, or second
    // arm. The original loop consumes this latch; survivors never consume it.
    let trigger = match loss {
        ManagementLoss::Driver => &original.fixture_driver_loss,
        ManagementLoss::Watchdog => &original.fixture_watchdog_loss,
    };
    trigger.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).map_err(|_| Failure::UnexpectedStatus)?;
    original.wake.notify_waiters();
    let _ = observed_management_loss(batch, &original, loss).await?;
    inventory(&root, &[])?;
    management_loss_facts(batch, &original, loss)
}

fn receipt_document(inputs: &Inputs, document: Value) -> Check<()> {
    inputs.same_root()?;
    let bytes = serde_json::to_vec(&document).map_err(|_| Failure::ReceiptIo)?;
    require(bytes.len() <= 64 * 1024, Failure::ReceiptIo)?;
    let temporary = inputs.root.join("receipt.pending");
    write_new(&temporary, &bytes, 0o600).map_err(|code| match code {
        Failure::FixtureCustodyUnknown => code,
        _ => Failure::ReceiptIo,
    })?;
    fs::rename(temporary, inputs.root.join("receipt.json")).map_err(|_| Failure::ReceiptIo)
}

fn receipt(inputs: &Inputs, cases: &[Value], passed: bool, settled: bool, failure: Option<Failure>) -> Check<()> {
    receipt_document(inputs, json!({"schemaVersion":1,"scope":SCOPE,
        "status":if passed {"passed"} else {"failed"},"allOwnersSettled":settled,"failureCode":failure,
        "bindings":inputs.bindings,"cases":cases,"notVerified":NOT_VERIFIED}))
}

fn loss_receipt(inputs: &Inputs, evidence: Option<Value>, passed: bool, failure: Option<Failure>) -> Check<()> {
    // This schema deliberately has no allOwnersSettled field. Expected
    // management Unknown is not normal finality or authorization to Save.
    require(passed == evidence.is_some() && passed == failure.is_none(), Failure::ReceiptIo)?;
    receipt_document(inputs, json!({"schemaVersion":1,"scope":LOSS_SCOPE,
        "status":if passed {"passed"} else {"failed"},"failureCode":failure,
        "bindings":inputs.bindings,"case":evidence,"notVerified":NOT_VERIFIED}))
}

async fn hosted_management_loss_original_resources(loss: ManagementLoss) {
    if BATCH_CLAIMED.swap(true, Ordering::SeqCst) {
        if !FIXTURE_FILES.all_settled() { retain_unknown_runtime().await; return; }
        panic!("hosted configuration batch was already claimed");
    }
    let inputs = match Inputs::admit() {
        Ok(inputs) => inputs,
        Err(code) => {
            if !FIXTURE_FILES.all_settled() { retain_unknown_runtime().await; return; }
            panic!("hosted configuration admission refused: {code:?}");
        },
    };
    if loss_receipt(&inputs, None, false, Some(Failure::NotCompleted)).is_err() {
        if !FIXTURE_FILES.all_settled() { retain_unknown_runtime().await; return; }
        panic!("hosted configuration loss receipt unavailable before native admission");
    }
    let owner = EditOwner::new(RuntimeConfig::packaged(inputs.root.clone()));
    match RETAINED.lock() {
        Ok(mut retained) => *retained = Some(Retention { _owner:owner.clone(), originals:Vec::new() }),
        Err(_) => panic!("hosted configuration retention unavailable before native admission"),
    }
    owner.inner.fixture_authorized.store(true, Ordering::SeqCst);
    if owner.initial_document("main").is_err() { panic!("hosted original document admission refused"); }
    let mut batch = Batch { owner, originals:Vec::new(), missing_original:false, cases:Vec::new() };
    let evidence = match exercise_management_loss(&mut batch, &inputs, loss).await {
        Ok(evidence) => evidence,
        Err(code) => {
            // No finite failed-case escape after native admission unless the
            // full expected-loss resource proof succeeded. Continue only the
            // original owner's EOF/cleanup; missing proof retains everything.
            batch.stop_original().await;
            if FIXTURE_FILES.all_settled() { let _ = loss_receipt(&inputs, None, false, Some(code)); }
            retain_unknown_runtime().await;
            return;
        },
    };
    if loss_receipt(&inputs, Some(evidence), true, None).is_err() {
        if !FIXTURE_FILES.all_settled() { retain_unknown_runtime().await; return; }
        panic!("hosted configuration loss receipt failed after original resource proof");
    }
    // This finite return is ONLY the negative fixture result: the native owner
    // remains retained, disabled, Unknown, and unable to grant an exit/Save
    // permit. All original OS resources and unaffected tasks are proven above;
    // only its pure final observer may remain. No next case, owner, shutdown,
    // retry, or root cleanup runs in this process. Infrastructure disposes it.
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "only the reviewed disposable original-driver-loss hosted process"]
async fn hosted_config_driver_loss_original_resources() {
    hosted_management_loss_original_resources(ManagementLoss::Driver).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "only the reviewed disposable original-watchdog-loss hosted process"]
async fn hosted_config_watchdog_loss_original_resources() {
    hosted_management_loss_original_resources(ManagementLoss::Watchdog).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "only the reviewed disposable Linux/macOS configuration-owner hosted batch"]
async fn hosted_config_edit_owner_original_resources() {
    if BATCH_CLAIMED.swap(true, Ordering::SeqCst) {
        if !FIXTURE_FILES.all_settled() { retain_unknown_runtime().await; return; }
        panic!("hosted configuration batch was already claimed");
    }
    let inputs = match Inputs::admit() {
        Ok(inputs) => inputs,
        Err(code) => {
            if !FIXTURE_FILES.all_settled() { retain_unknown_runtime().await; return; }
            panic!("hosted configuration admission refused: {code:?}");
        },
    };
    if receipt(&inputs, &[], false, false, Some(Failure::NotCompleted)).is_err() {
        if !FIXTURE_FILES.all_settled() { retain_unknown_runtime().await; return; }
        panic!("hosted configuration receipt unavailable before native admission");
    }
    let owner = EditOwner::new(RuntimeConfig::packaged(inputs.root.clone()));
    match RETAINED.lock() {
        Ok(mut retained) => *retained = Some(Retention { _owner:owner.clone(), originals:Vec::new() }),
        Err(_) => panic!("hosted configuration retention unavailable before native admission"),
    }
    // This private cfg(test,development-runtime) seam is the ONLY gate override,
    // after all hosted/source/root admission. Resolve/spawn remain genuine.
    owner.inner.fixture_authorized.store(true, Ordering::SeqCst);
    if owner.initial_document("main").is_err() { panic!("hosted original document admission refused"); }
    let mut batch = Batch { owner, originals:Vec::new(), missing_original:false, cases:Vec::new() };
    for case in [Case::Create, Case::NoOp, Case::Discard] {
        let checked = exercise(&mut batch, &inputs, case).await;
        if checked.is_err() || !batch.all_settled() || batch.owner.disabled() { batch.stop_original().await; }
        let settled = batch.all_settled();
        if !settled || batch.owner.disabled()
            || matches!(checked, Err(Failure::OriginalCustodyUnknown | Failure::FixtureCustodyUnknown)) {
            // Fixture uncertainty cannot be recorded by opening another receipt
            // descriptor. Leave the prior conservative partial receipt intact.
            if FIXTURE_FILES.all_settled() {
                let _ = receipt(&inputs, &batch.cases, false, false, Some(Failure::OriginalCustodyUnknown));
            }
            // No retry, next native case, replacement owner, task abort, PID
            // lookup, or Drop-as-finality. Infrastructure disposes the retained
            // runtime/root if original custody cannot be positively established.
            retain_unknown_runtime().await;
            return;
        }
        if let Err(code) = checked {
            let _ = receipt(&inputs, &batch.cases, false, true, Some(code));
            if !FIXTURE_FILES.all_settled() { retain_unknown_runtime().await; return; }
            panic!("hosted configuration case failed after original settlement: {code:?}");
        }
        // A partial receipt never asserts finality for a subsequently admitted
        // case. The final passing receipt is written only after the whole batch.
        if receipt(&inputs, &batch.cases, false, false, Some(Failure::NotCompleted)).is_err() {
            if !FIXTURE_FILES.all_settled() { retain_unknown_runtime().await; return; }
            panic!("hosted configuration receipt failed after original settlement");
        }
    }
    if batch.owner.shutdown().await.is_err() || !batch.all_settled() || batch.cases.len() != 3 {
        if FIXTURE_FILES.all_settled() {
            let _ = receipt(&inputs, &batch.cases, false, false, Some(Failure::OriginalCustodyUnknown));
        }
        retain_unknown_runtime().await;
        return;
    }
    if receipt(&inputs, &batch.cases, true, true, None).is_err() {
        if !FIXTURE_FILES.all_settled() { retain_unknown_runtime().await; return; }
        panic!("hosted configuration final receipt failed after original settlement");
    }
}

fn stop_receipt(inputs: &Inputs, cases: &[Value], passed: bool, settled: bool, failure: Option<Failure>) -> Check<()> {
    require(!passed || settled && cases.len() == 2 && failure.is_none(), Failure::ReceiptIo)?;
    receipt_document(inputs, json!({"schemaVersion":1,"scope":STOP_SCOPE,
        "status":if passed {"passed"} else {"failed"},"allOwnersSettled":settled,"failureCode":failure,
        "bindings":inputs.bindings,"cases":cases,"notVerified":NOT_VERIFIED}))
}

fn clock_receipt(inputs: &Inputs, evidence: Option<Value>, passed: bool, failure: Option<Failure>) -> Check<()> {
    require(passed == evidence.is_some() && passed == failure.is_none(), Failure::ReceiptIo)?;
    // Deliberately no allOwnersSettled: verified late resource settlement does
    // not turn native Unknown into normal owner/Save success.
    receipt_document(inputs, json!({"schemaVersion":1,"scope":CLOCK_SCOPE,
        "status":if passed {"passed"} else {"failed"},"failureCode":failure,
        "bindings":inputs.bindings,"case":evidence,"notVerified":NOT_VERIFIED}))
}

async fn delta_inputs(clock: bool) -> Option<Inputs> {
    if BATCH_CLAIMED.swap(true, Ordering::SeqCst) {
        if !FIXTURE_FILES.all_settled() { retain_unknown_runtime().await; return None; }
        panic!("hosted configuration batch was already claimed");
    }
    let inputs = match Inputs::admit() {
        Ok(inputs) => inputs,
        Err(code) => {
            if !FIXTURE_FILES.all_settled() { retain_unknown_runtime().await; return None; }
            panic!("hosted configuration delta admission refused: {code:?}");
        },
    };
    let initial = if clock { clock_receipt(&inputs, None, false, Some(Failure::NotCompleted)) }
        else { stop_receipt(&inputs, &[], false, false, Some(Failure::NotCompleted)) };
    if initial.is_err() {
        if !FIXTURE_FILES.all_settled() { retain_unknown_runtime().await; return None; }
        panic!("hosted configuration delta receipt unavailable before native admission");
    }
    Some(inputs)
}

fn delta_batch(inputs: &Inputs) -> Check<Batch> {
    let owner = EditOwner::new(RuntimeConfig::packaged(inputs.root.clone()));
    {
        let mut retained = RETAINED.lock().map_err(|_| Failure::OriginalCustodyUnknown)?;
        require(retained.is_none(), Failure::OriginalCustodyUnknown)?;
        *retained = Some(Retention { _owner:owner.clone(), originals:Vec::new() });
    }
    owner.inner.fixture_authorized.store(true, Ordering::SeqCst);
    owner.initial_document("main").map_err(|_| Failure::NativeCommandRejected)?;
    Ok(Batch { owner, originals:Vec::new(), missing_original:false, cases:Vec::new() })
}

async fn until(allowance: Duration, mut condition: impl FnMut() -> Check<bool>) -> Check<()> {
    let end = Instant::now() + allowance; // Observer margin, never an owner clock.
    loop {
        if condition()? { return Ok(()); }
        if Instant::now() >= end { return Err(Failure::ObservationTimeout); }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

async fn prepared_review(batch: &mut Batch, root: &Path, project: &'static str) -> Check<(Arc<Session>, Prepared)> {
    let original = batch.open(project, root)?;
    let editing = observed(&batch.owner, &original.id, Phase::Editing).await?;
    let checkout = editing.checkout.as_ref().ok_or(Failure::UnexpectedStatus)?;
    require(checkout.base == Value::Null, Failure::UnexpectedOutcome)?;
    let admission = batch.owner.prepare("main", PrepareConfigEdit { session_id:original.id.clone(),
        revision:checkout.revision.clone(), expected_base:checkout.base.clone(), draft:document(), draft_revision:1, baseline_generation:0 })
        .map_err(|_| Failure::NativeCommandRejected)?;
    require(projection(&admission, &original.id)?.phase == Phase::Preparing, Failure::UnexpectedStatus)?;
    let reviewing = observed(&batch.owner, &original.id, Phase::Reviewing).await?;
    let plan = reviewing.prepared.ok_or(Failure::UnexpectedStatus)?;
    require(plan.revision == checkout.revision && plan.draft_revision == 1 && plan.baseline_generation == 0
        && plan.view.create_release_directory && plan.view.files.iter().all(|file| file.action == "create"), Failure::UnexpectedOutcome)?;
    inventory(root, &[])?;
    Ok((original, plan))
}

#[derive(Clone, Copy)]
enum StopCase { Review, PartialApply }
impl StopCase {
    fn name(self) -> &'static str { match self { Self::Review => "discard-reviewing", Self::PartialApply => "partial-apply-eof" } }
    fn project(self) -> &'static str {
        match self { Self::Review => "project-config-discard-reviewing", Self::PartialApply => "project-config-partial-apply" }
    }
}

async fn exercise_stop(batch: &mut Batch, inputs: &Inputs, case: StopCase) -> Check<()> {
    inputs.same_root()?;
    let root = inputs.root.join(case.name());
    fs::DirBuilder::new().mode(0o700).create(&root).map_err(|_| Failure::FixtureIo)?;
    let (original, plan) = prepared_review(batch, &root, case.project()).await?;
    let partial = matches!(case, StopCase::PartialApply);
    if partial {
        let mut guard = GateGuard::new(&batch.owner, original.fixture_schedule.clone());
        original.fixture_schedule.prefix.hold()?;
        let admission = batch.owner.apply("main", &original.id, &plan.plan_token).map_err(|_| Failure::NativeCommandRejected)?;
        require(projection(&admission, &original.id)?.apply_submitted, Failure::UnexpectedStatus)?;
        until(OBSERVATION, || {
            require(!original.fixture_schedule.failed.load(Ordering::SeqCst), Failure::UnexpectedStatus)?;
            Ok(original.fixture_schedule.prefix.entered.load(Ordering::SeqCst))
        }).await?;
        require(original.fixture_schedule.prefix_bytes.load(Ordering::SeqCst) == 1
            && !original.fixture_schedule.apply_suffix_started.load(Ordering::SeqCst), Failure::UnexpectedOutcome)?;
        batch.owner.close("main", &original.id).map_err(|_| Failure::NativeCommandRejected)?;
        guard.release(); // Sticky original STOP is set before opening the gate.
    } else {
        batch.owner.close("main", &original.id).map_err(|_| Failure::NativeCommandRejected)?;
    }
    let _ = batch.owner.status().map_err(|_| Failure::UnexpectedStatus)?;
    let _ = batch.owner.close("main", &original.id).map_err(|_| Failure::NativeCommandRejected)?;
    let terminal = observed(&batch.owner, &original.id, Phase::Final).await?;
    require(terminal.native_finality == NativeFinality::Settled && !terminal.late_settled
        && terminal.apply_submitted == partial && batch.owner.can_exit(), Failure::OriginalCustodyUnknown)?;
    let facts = original_facts(&original)?;
    require((facts.request_frames, facts.response_frames) == (2, 3), Failure::UnexpectedOutcome)?;
    let core = terminal.core_outcome.as_ref().ok_or(Failure::UnexpectedOutcome)?;
    let reason = if partial { Reason::Cancelled } else { Reason::Discarded };
    require(core.effect == Effect::NotStarted && core.journal == Journal::NotCreated
        && core.resources == ResourceState::Settled && core.reason == CoreReason::Cancelled
        && terminal.native_reason == reason, Failure::UnexpectedOutcome)?;
    let correlation = terminal.prepared.as_ref().is_some_and(|retained| retained.plan_token == plan.plan_token
        && retained.revision == plan.revision && retained.draft_revision == 1 && retained.baseline_generation == 0)
        && terminal.checkout.as_ref().is_some_and(|checkout| checkout.revision == plan.revision && checkout.base == Value::Null)
        && original.fixture_schedule.sequence() == Some(1);
    let prefix = original.fixture_schedule.prefix_bytes.load(Ordering::SeqCst);
    let suffix = original.fixture_schedule.apply_suffix_started.load(Ordering::SeqCst);
    require(correlation && prefix == (if partial { 1 } else { 0 }) && !suffix && original.fixture_schedule.released(), Failure::UnexpectedOutcome)?;
    inventory(&root, &[])?;
    let mut evidence = serde_json::to_value(&facts).map_err(|_| Failure::ReceiptIo)?;
    evidence["name"] = json!(case.name());
    evidence["evidenceKind"] = json!(if partial { "fixed-prefix-scheduling-control" } else { "actual-config-child" });
    evidence["nativePhase"] = json!(terminal.phase);
    evidence["nativeFinality"] = json!(terminal.native_finality);
    evidence["nativeReason"] = json!(terminal.native_reason);
    evidence["applySubmitted"] = json!(terminal.apply_submitted);
    evidence["outcome"] = json!(core);
    evidence["terminalSeq"] = json!(original.fixture_schedule.sequence());
    evidence["preparedCorrelation"] = json!(correlation);
    evidence["prefixBytes"] = json!(prefix);
    evidence["applySuffixStarted"] = json!(suffix);
    batch.cases.push(evidence);
    Ok(())
}

#[derive(Clone, Copy)]
enum ClockCase { TerminalDeadline, StartupStop }
impl ClockCase {
    fn name(self) -> &'static str { match self { Self::TerminalDeadline => "terminal-deadline", Self::StartupStop => "startup-stop" } }
    fn project(self) -> &'static str {
        match self { Self::TerminalDeadline => "project-config-terminal-deadline", Self::StartupStop => "project-config-startup-stop" }
    }
    fn reason(self) -> Reason { match self { Self::TerminalDeadline => Reason::ActiveTimeout, Self::StartupStop => Reason::Discarded } }
    fn facts(self, original: &Session) -> Check<Facts> {
        match self { Self::TerminalDeadline => original_facts(original), Self::StartupStop => no_acquisition_facts(original) }
    }
}

fn original_clock(batch: &Batch, original: &Arc<Session>) -> Check<(Option<Instant>, Option<Instant>)> {
    let registry = batch.owner.inner.lock();
    let active = registry.active.as_ref().ok_or(Failure::UnexpectedStatus)?;
    require(Arc::ptr_eq(&active.session, original), Failure::OriginalCustodyUnknown)?;
    Ok((active.phase_end, active.cleanup_start))
}

async fn exercise_clock(batch: &mut Batch, inputs: &Inputs, case: ClockCase) -> Check<Value> {
    inputs.same_root()?;
    let root = inputs.root.join(case.name());
    fs::DirBuilder::new().mode(0o700).create(&root).map_err(|_| Failure::FixtureIo)?;
    let terminal_case = matches!(case, ClockCase::TerminalDeadline);
    let (original, mut guard, trigger) = if terminal_case {
        let (original, plan) = prepared_review(batch, &root, case.project()).await?;
        let guard = GateGuard::new(&batch.owner, original.fixture_schedule.clone());
        original.fixture_schedule.terminal.hold()?;
        let admission = batch.owner.apply("main", &original.id, &plan.plan_token).map_err(|_| Failure::NativeCommandRejected)?;
        require(projection(&admission, &original.id)?.apply_submitted, Failure::UnexpectedStatus)?;
        let (active, cleanup) = original_clock(batch, &original)?;
        require(cleanup.is_none(), Failure::UnexpectedStatus)?;
        let endpoint = active.ok_or(Failure::UnexpectedStatus)?;
        until(OBSERVATION, || Ok(original.fixture_schedule.terminal.entered.load(Ordering::SeqCst))).await?;
        require(Instant::now() < endpoint && !original.fixture_schedule.failed.load(Ordering::SeqCst), Failure::UnexpectedStatus)?;
        {
            let held = original.fixture_schedule.held_terminal.lock().map_err(|_| Failure::UnexpectedStatus)?;
            let (sequence, core) = held.as_ref().ok_or(Failure::UnexpectedStatus)?;
            require(*sequence == 2 && core.effect == Effect::Committed && core.journal == Journal::Clean
                && core.resources == ResourceState::Settled && core.reason == CoreReason::None, Failure::UnexpectedOutcome)?;
        }
        (original, guard, endpoint) // The scheduled Apply endpoint, not observer wake time.
    } else {
        let schedule = Arc::new(Schedule::default());
        let guard = GateGuard::new(&batch.owner, schedule.clone());
        schedule.inspection.hold()?;
        {
            let mut next = batch.owner.inner.fixture_next_schedule.lock().map_err(|_| Failure::UnexpectedStatus)?;
            require(next.is_none(), Failure::UnexpectedStatus)?;
            *next = Some(schedule.clone()); // Consumed in Session construction, before tasks.
        }
        let original = batch.open(case.project(), &root)?;
        require(Arc::ptr_eq(&original.fixture_schedule, &schedule), Failure::UnexpectedStatus)?;
        until(OBSERVATION, || Ok(schedule.inspection.entered.load(Ordering::SeqCst))).await?;
        require(schedule.inspection_returned.load(Ordering::SeqCst), Failure::UnexpectedStatus)?;
        let before = Instant::now();
        let admission = batch.owner.close("main", &original.id).map_err(|_| Failure::NativeCommandRejected)?;
        let after = Instant::now();
        require(projection(&admission, &original.id)?.native_reason == Reason::Discarded, Failure::UnexpectedStatus)?;
        let (_, cleanup) = original_clock(batch, &original)?;
        let start = cleanup.ok_or(Failure::UnexpectedStatus)?;
        require(start >= before && start <= after, Failure::UnexpectedStatus)?;
        (original, guard, start)
    };
    until(OBSERVATION, || {
        let registry = batch.owner.inner.lock();
        let active = registry.active.as_ref().ok_or(Failure::UnexpectedStatus)?;
        require(Arc::ptr_eq(&active.session, &original), Failure::OriginalCustodyUnknown)?;
        Ok(active.unknown)
    }).await?;
    let cleanup_elapsed = Instant::now().saturating_duration_since(trigger).as_millis();
    require(cleanup_elapsed >= FINALIZATION.as_millis() && cleanup_elapsed <= 60_000, Failure::UnexpectedStatus)?;
    {
        let registry = batch.owner.inner.lock();
        let active = registry.active.as_ref().ok_or(Failure::UnexpectedStatus)?;
        require(registry.disabled && registry.last.is_none() && !registry.stopping && !registry.exhausted
            && !batch.owner.inner.poisoned.load(Ordering::SeqCst)
            && Arc::ptr_eq(&active.session, &original) && active.unknown
            && active.cleanup_start == Some(trigger) && active.phase_end.is_none()
            && active.projection.phase == Phase::Unknown && active.projection.native_finality == NativeFinality::Unknown
            && !active.projection.late_settled && active.projection.core_outcome.is_none()
            && active.projection.native_reason == case.reason() && *original.stop.borrow(), Failure::UnexpectedStatus)?;
    }
    require(batch.owner.disabled() && !batch.owner.can_exit(), Failure::OriginalCustodyUnknown)?;
    // All these observations occur AFTER Unknown. shutdown therefore takes
    // its immediate error path, never a wait that could strand the held gate.
    for _ in 0..2 {
        let _ = batch.owner.status().map_err(|_| Failure::UnexpectedStatus)?;
        let _ = batch.owner.close("main", &original.id).map_err(|_| Failure::NativeCommandRejected)?;
    }
    let shutdown_observed = if terminal_case {
        require(batch.owner.shutdown().await.is_err_and(|error| error.code == "cleanup_unknown"), Failure::UnexpectedStatus)?;
        true
    } else { false };
    require(original_clock(batch, &original)? == (None, Some(trigger)), Failure::UnexpectedStatus)?;
    let retained_status = batch.owner.status().map_err(|_| Failure::UnexpectedStatus)?;
    let expected_availability = if terminal_case { EditAvailability::Shutdown } else { EditAvailability::CleanupUnknown };
    require(!retained_status.capability.available && retained_status.capability.reason == expected_availability
        && batch.owner.disabled() && !batch.owner.can_exit(), Failure::OriginalCustodyUnknown)?;
    guard.release(); // Only now may the original held operation actually return.
    until(OBSERVATION, || Ok(batch.owner.can_exit())).await?;
    require(FIXTURE_FILES.all_settled() && !batch.missing_original && batch.originals.len() == 1
        && Arc::ptr_eq(&batch.originals[0], &original), Failure::OriginalCustodyUnknown)?;
    let facts = case.facts(&original)?;
    let status = batch.owner.status().map_err(|_| Failure::UnexpectedStatus)?;
    let current = projection(&status, &original.id)?;
    let registry_disabled = {
        let registry = batch.owner.inner.lock();
        require(registry.active.is_none() && registry.last.as_ref().is_some_and(|last| last.session_id == original.id)
            && registry.stopping == shutdown_observed && !registry.exhausted && registry.document_bound && !registry.document_lost
            && !batch.owner.inner.poisoned.load(Ordering::SeqCst), Failure::OriginalCustodyUnknown)?;
        registry.disabled
    };
    require(registry_disabled && batch.owner.disabled() && batch.owner.can_exit() && status.active.is_none()
        && !status.capability.available && status.capability.reason == expected_availability
        && current.phase == Phase::Unknown && current.native_finality == NativeFinality::Unknown && current.late_settled
        && current.native_reason == case.reason() && current.apply_submitted == terminal_case
        && original.fixture_schedule.released() && !original.fixture_schedule.failed.load(Ordering::SeqCst), Failure::OriginalCustodyUnknown)?;
    if terminal_case {
        let core = current.core_outcome.as_ref().ok_or(Failure::UnexpectedOutcome)?;
        require(core.effect == Effect::Committed && core.journal == Journal::Clean && core.resources == ResourceState::Settled
            && core.reason == CoreReason::None && original.fixture_schedule.sequence() == Some(2)
            && (facts.request_frames, facts.response_frames) == (3, 3)
            && !original.fixture_schedule.acquisition_refused.load(Ordering::SeqCst), Failure::UnexpectedOutcome)?;
        require(read_regular(&root.join("release/mobile-release.json"), 512 * 1024)?.bytes == create_bytes()?
            && read_regular(&root.join(".gitignore"), 1024 * 1024)?.bytes == IGNORE, Failure::PayloadMismatch)?;
        inventory(&root, &[".gitignore", "release"])?;
        inventory(&root.join("release"), &["mobile-release.json"])?;
    } else {
        require(current.core_outcome.is_none() && current.checkout.is_none() && current.prepared.is_none()
            && original.fixture_schedule.sequence().is_none(), Failure::UnexpectedOutcome)?;
        inventory(&root, &[])?;
    }
    let mut evidence = serde_json::to_value(&facts).map_err(|_| Failure::ReceiptIo)?;
    evidence["name"] = json!(case.name());
    evidence["evidenceKind"] = json!("scheduling-control-not-os-fault");
    evidence["nativePhase"] = json!(current.phase);
    evidence["nativeFinality"] = json!(current.native_finality);
    evidence["nativeReason"] = json!(current.native_reason);
    evidence["applySubmitted"] = json!(current.apply_submitted);
    evidence["outcome"] = json!(current.core_outcome);
    evidence["terminalSeq"] = json!(original.fixture_schedule.sequence());
    evidence["registryDisabled"] = json!(registry_disabled);
    evidence["editPermitClosed"] = json!(!status.capability.available);
    evidence["editAvailability"] = json!(status.capability.reason);
    evidence["nativeCanExit"] = json!(batch.owner.can_exit());
    evidence["originalResourcesSettled"] = json!(true); // case.facts() above, never absence alone.
    evidence["lateSettled"] = json!(current.late_settled);
    evidence["retainedBeforeRelease"] = json!(true);
    evidence["cleanupStartUnchanged"] = json!(true);
    evidence["cleanupElapsedMs"] = json!(cleanup_elapsed);
    evidence["scheduledActiveDeadline"] = json!(terminal_case);
    evidence["inspectionJoined"] = json!(true); // Both exact original fact checkers require it.
    evidence["acquisitionNotAdmitted"] = json!(original.fixture_schedule.acquisition_refused.load(Ordering::SeqCst));
    evidence["pipeAcquisition"] = json!(if terminal_case { "available" } else { "absent" });
    evidence["controlEntered"] = json!(if terminal_case { original.fixture_schedule.terminal.entered.load(Ordering::SeqCst) }
        else { original.fixture_schedule.inspection.entered.load(Ordering::SeqCst) });
    evidence["controlReleased"] = json!(original.fixture_schedule.released());
    evidence["shutdownObserved"] = json!(shutdown_observed);
    Ok(evidence)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "only the reviewed disposable original-config-STOP hosted process"]
async fn hosted_config_stop_original_resources() {
    let Some(inputs) = delta_inputs(false).await else { return; };
    let mut batch = delta_batch(&inputs).unwrap_or_else(|code| panic!("hosted configuration STOP setup refused before native work: {code:?}"));
    for case in [StopCase::Review, StopCase::PartialApply] {
        let checked = exercise_stop(&mut batch, &inputs, case).await;
        if checked.is_err() || !batch.all_settled() || batch.owner.disabled() { batch.stop_original().await; }
        let settled = batch.all_settled();
        if !settled || batch.owner.disabled() || matches!(checked, Err(Failure::OriginalCustodyUnknown | Failure::FixtureCustodyUnknown)) {
            if FIXTURE_FILES.all_settled() { let _ = stop_receipt(&inputs, &batch.cases, false, false, Some(Failure::OriginalCustodyUnknown)); }
            retain_unknown_runtime().await;
            return;
        }
        if let Err(code) = checked {
            let _ = stop_receipt(&inputs, &batch.cases, false, true, Some(code));
            if !FIXTURE_FILES.all_settled() { retain_unknown_runtime().await; return; }
            panic!("hosted configuration STOP case failed after settlement: {code:?}");
        }
        if stop_receipt(&inputs, &batch.cases, false, false, Some(Failure::NotCompleted)).is_err() {
            if !FIXTURE_FILES.all_settled() { retain_unknown_runtime().await; return; }
            panic!("hosted configuration STOP progress receipt failed after settlement");
        }
    }
    if batch.owner.shutdown().await.is_err() || !batch.all_settled() || batch.cases.len() != 2 {
        if FIXTURE_FILES.all_settled() { let _ = stop_receipt(&inputs, &batch.cases, false, false, Some(Failure::OriginalCustodyUnknown)); }
        retain_unknown_runtime().await;
        return;
    }
    if stop_receipt(&inputs, &batch.cases, true, true, None).is_err() {
        if !FIXTURE_FILES.all_settled() { retain_unknown_runtime().await; return; }
        panic!("hosted configuration STOP final receipt failed after settlement");
    }
}

async fn hosted_clock_original_resources(case: ClockCase) {
    let Some(inputs) = delta_inputs(true).await else { return; };
    let mut batch = delta_batch(&inputs).unwrap_or_else(|code| panic!("hosted configuration clock setup refused before native work: {code:?}"));
    let evidence = match exercise_clock(&mut batch, &inputs, case).await {
        Ok(evidence) => evidence,
        Err(code) => {
            // exercise_clock's guard already requested original STOP and
            // released all gates. No proof means no finite native-case escape.
            batch.stop_original().await;
            if FIXTURE_FILES.all_settled() { let _ = clock_receipt(&inputs, None, false, Some(code)); }
            retain_unknown_runtime().await;
            return;
        },
    };
    if clock_receipt(&inputs, Some(evidence), true, None).is_err() {
        if !FIXTURE_FILES.all_settled() { retain_unknown_runtime().await; return; }
        panic!("hosted configuration clock receipt failed after original resource proof");
    }
    // The original resource-bearing tasks really joined. The data-only retained
    // owner stays disabled/Unknown; no next owner, shutdown or root cleanup.
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "only the reviewed disposable original-terminal-deadline hosted process"]
async fn hosted_config_terminal_deadline_original_resources() {
    hosted_clock_original_resources(ClockCase::TerminalDeadline).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "only the reviewed disposable original-startup-STOP hosted process"]
async fn hosted_config_startup_stop_original_resources() {
    hosted_clock_original_resources(ClockCase::StartupStop).await;
}

fn eof_receipt(inputs: &Inputs, cases: &[Value], passed: bool, settled: bool, failure: Option<Failure>) -> Check<()> {
    require(!passed || settled && cases.len() == 2 && failure.is_none(), Failure::ReceiptIo)?;
    receipt_document(inputs, json!({"schemaVersion":1,"scope":EOF_SCOPE,
        "status":if passed {"passed"} else {"failed"},"allOwnersSettled":settled,"failureCode":failure,
        "bindings":inputs.bindings,"cases":cases,"notVerified":NOT_VERIFIED}))
}

fn eof_all_settled(batch: &Batch) -> bool {
    // Do not relax Batch::all_settled's zero-stderr policy for older fixtures.
    FIXTURE_FILES.all_settled() && !batch.missing_original && batch.owner.can_exit()
        && batch.originals.len() <= 2
        && batch.originals.iter().zip([EofCase::Precommit, EofCase::Postcommit])
            .all(|(original, case)| original_eof_facts(original, case).is_ok())
}

async fn exercise_eof(batch: &mut Batch, inputs: &Inputs, case: EofCase) -> Check<()> {
    inputs.same_root()?;
    require(eof_all_settled(batch) && !batch.owner.disabled(), Failure::OriginalCustodyUnknown)?;
    let root = inputs.root.join(case.name());
    fs::DirBuilder::new().mode(0o700).create(&root).map_err(|_| Failure::FixtureIo)?;
    fs::DirBuilder::new().mode(0o700).create(root.join("release")).map_err(|_| Failure::FixtureIo)?;
    write_new(&root.join("release/mobile-release.json"), &noop_bytes()?, 0o640)?;
    write_new(&root.join(".gitignore"), EOF_IGNORE_BASE, 0o600)?;
    write_new(&root.join("unrelated.txt"), UNRELATED, 0o600)?;
    let before = originals(&root)?;
    require(before.iter().map(|file| file.identity.mode & 0o7777).eq([0o640, 0o600, 0o600]), Failure::PayloadMismatch)?;

    let schedule = Arc::new(Schedule { eof: Some(case), ..Schedule::default() });
    {
        let mut next = batch.owner.inner.fixture_next_schedule.lock().map_err(|_| Failure::OriginalCustodyUnknown)?;
        require(next.is_none(), Failure::UnexpectedStatus)?;
        *next = Some(schedule.clone()); // Before original registration; no live selector change.
    }
    let mut guard = GateGuard::new(&batch.owner, schedule.clone());
    let original = batch.open(case.project(), &root)?;
    require(Arc::ptr_eq(&schedule, &original.fixture_schedule), Failure::OriginalCustodyUnknown)?;
    let editing = observed(&batch.owner, &original.id, Phase::Editing).await?;
    let checkout = editing.checkout.as_ref().ok_or(Failure::UnexpectedStatus)?;
    require(checkout.base == document(), Failure::UnexpectedOutcome)?;
    let admission = batch.owner.prepare("main", PrepareConfigEdit { session_id: original.id.clone(),
        revision: checkout.revision.clone(), expected_base: checkout.base.clone(), draft: eof_document(),
        draft_revision: 1, baseline_generation: 0 }).map_err(|_| Failure::NativeCommandRejected)?;
    require(projection(&admission, &original.id)?.phase == Phase::Preparing, Failure::UnexpectedStatus)?;
    let reviewing = observed(&batch.owner, &original.id, Phase::Reviewing).await?;
    let plan = reviewing.prepared.as_ref().ok_or(Failure::UnexpectedStatus)?;
    require(plan.revision == checkout.revision && plan.draft_revision == 1 && plan.baseline_generation == 0
        && !plan.view.create_release_directory && plan.view.files.len() == 2
        && plan.view.files[0].path == "release/mobile-release.json" && plan.view.files[0].action == "replace"
        && plan.view.files[1].path == ".gitignore" && plan.view.files[1].action == "append",
        Failure::UnexpectedOutcome)?;
    require(before == originals(&root)?, Failure::PayloadMismatch)?;
    inventory(&root, &[".gitignore", "release", "unrelated.txt"])?;
    inventory(&root.join("release"), &["mobile-release.json"])?;
    let admission = batch.owner.apply("main", &original.id, &plan.plan_token).map_err(|_| Failure::NativeCommandRejected)?;
    require(projection(&admission, &original.id)?.apply_submitted, Failure::UnexpectedStatus)?;
    let (active, cleanup) = original_clock(batch, &original)?;
    let endpoint = active.ok_or(Failure::UnexpectedStatus)?;
    require(cleanup.is_none(), Failure::UnexpectedStatus)?;

    // Wait only for the original stderr reader's exact marker. Do not acquire
    // its pipe, any registry/resource book across an await, or inspect project
    // and transaction files while installed work is held in the child.
    until(OBSERVATION, || {
        require(!batch.owner.disabled() && !schedule.failed.load(Ordering::SeqCst), Failure::OriginalCustodyUnknown)?;
        let control = schedule.eof_control.lock().map_err(|_| Failure::OriginalCustodyUnknown)?;
        Ok(control.boundary_only(case))
    }).await?;
    let close_before_deadline = Instant::now() < endpoint;
    require(close_before_deadline && !*original.stop.borrow(), Failure::UnexpectedStatus)?;
    let closing = batch.owner.close("main", &original.id).map_err(|_| Failure::NativeCommandRejected)?;
    let closing = projection(&closing, &original.id)?;
    require(closing.phase == Phase::Finalizing && closing.native_reason == Reason::Cancelled
        && closing.apply_submitted, Failure::UnexpectedStatus)?;
    guard.release(); // Only sticky original Close; the shim's gate is select-only.

    let terminal = observed(&batch.owner, &original.id, Phase::Final).await?;
    require(terminal.native_finality == NativeFinality::Settled && !terminal.late_settled
        && terminal.apply_submitted && terminal.native_reason == Reason::Cancelled
        && batch.owner.can_exit() && !batch.owner.disabled(), Failure::OriginalCustodyUnknown)?;
    let facts = original_eof_facts(&original, case)?;
    require((facts.request_frames, facts.response_frames) == (3, 3), Failure::UnexpectedOutcome)?;
    let core = terminal.core_outcome.as_ref().ok_or(Failure::UnexpectedOutcome)?;
    let committed = case == EofCase::Postcommit;
    require(core.effect == if committed { Effect::Committed } else { Effect::RolledBack }
        && core.journal == Journal::Clean && core.resources == ResourceState::Settled
        && core.reason == CoreReason::Cancelled, Failure::UnexpectedOutcome)?;
    let correlation = terminal.prepared.as_ref().is_some_and(|retained| retained.plan_token == plan.plan_token
        && retained.revision == plan.revision && retained.draft_revision == 1 && retained.baseline_generation == 0)
        && terminal.checkout.as_ref().is_some_and(|retained| retained.revision == plan.revision && retained.base == document())
        && schedule.sequence() == Some(2);
    let records = {
        let control = schedule.eof_control.lock().map_err(|_| Failure::OriginalCustodyUnknown)?;
        require(control.complete(case), Failure::UnexpectedOutcome)?;
        control.records(case)
    };
    require(correlation && records == 2 && schedule.released(), Failure::UnexpectedOutcome)?;

    // Only after full original native wait/EOF/close/join receipts may the
    // fixture observe files. The rollback case demands original inodes too.
    let after = originals(&root)?;
    let originals_preserved = before == after;
    let payloads_installed = after[0].bytes == eof_config_bytes()? && after[1].bytes == eof_ignore_bytes();
    let modes_preserved = before.iter().zip(&after).all(|(old, new)| old.identity.mode == new.identity.mode
        && old.identity.device == new.identity.device && old.identity.owner == new.identity.owner);
    let unrelated_preserved = before[2] == after[2];
    require(originals_preserved == !committed && payloads_installed == committed && modes_preserved && unrelated_preserved
        && (!committed || before[0].identity.inode != after[0].identity.inode && before[1].identity.inode != after[1].identity.inode),
        Failure::PayloadMismatch)?;
    inventory(&root, &[".gitignore", "release", "unrelated.txt"])?;
    inventory(&root.join("release"), &["mobile-release.json"])?;
    let fixture_files_settled = FIXTURE_FILES.all_settled();
    require(fixture_files_settled, Failure::FixtureCustodyUnknown)?;
    let mut evidence = serde_json::to_value(&facts).map_err(|_| Failure::ReceiptIo)?;
    evidence["name"] = json!(case.name());
    evidence["evidenceKind"] = json!("real-stdin-eof-at-controlled-transaction-boundary");
    evidence["bootstrapMode"] = json!("instrumented-genuine-engine");
    evidence["nativePhase"] = json!(terminal.phase);
    evidence["nativeFinality"] = json!(terminal.native_finality);
    evidence["nativeReason"] = json!(terminal.native_reason);
    evidence["applySubmitted"] = json!(terminal.apply_submitted);
    evidence["lateSettled"] = json!(terminal.late_settled);
    evidence["ownerDisabled"] = json!(batch.owner.disabled());
    evidence["outcome"] = json!(core);
    evidence["terminalSeq"] = json!(schedule.sequence());
    evidence["preparedCorrelation"] = json!(correlation);
    evidence["closeBeforeActiveDeadline"] = json!(close_before_deadline);
    evidence["controlRecords"] = json!(records);
    evidence["boundary"] = json!(case.boundary());
    // These literal-valued facts are admitted only by the byte-exact original
    // stderr parser above. They do not replace any native resource receipts.
    evidence["actualStdinEof"] = json!(true);
    evidence["eofReadCount"] = json!(1);
    evidence["nonemptyReadCount"] = json!(0);
    evidence["readErrorCount"] = json!(0);
    evidence["originalCheckpoint"] = json!(case.checkpoint());
    evidence["committedPublication"] = json!(committed);
    evidence["rolledBackPublication"] = json!(!committed);
    evidence["terminalDurable"] = json!(true);
    evidence["fixedRecovery"] = json!(true);
    evidence["journalClean"] = json!(true);
    evidence["originalsPreserved"] = json!(originals_preserved);
    evidence["payloadsInstalled"] = json!(payloads_installed);
    evidence["modesPreserved"] = json!(modes_preserved);
    evidence["unrelatedPreserved"] = json!(unrelated_preserved);
    evidence["journalAbsent"] = json!(true);
    evidence["fixtureFilesSettled"] = json!(fixture_files_settled);
    batch.cases.push(evidence);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "only the reviewed disposable real transaction-boundary EOF hosted process"]
async fn hosted_config_transaction_eof_original_resources() {
    if BATCH_CLAIMED.swap(true, Ordering::SeqCst) {
        if !FIXTURE_FILES.all_settled() { retain_unknown_runtime().await; return; }
        panic!("hosted configuration batch was already claimed");
    }
    let mut inputs = match Inputs::admit() {
        Ok(inputs) => inputs,
        Err(code) => {
            if !FIXTURE_FILES.all_settled() { retain_unknown_runtime().await; return; }
            panic!("hosted configuration EOF admission refused: {code:?}");
        },
    };
    if inputs.admit_eof_source().is_err() || eof_receipt(&inputs, &[], false, false, Some(Failure::NotCompleted)).is_err() {
        if !FIXTURE_FILES.all_settled() { retain_unknown_runtime().await; return; }
        panic!("hosted configuration EOF source/receipt refused before native admission");
    }
    let mut batch = delta_batch(&inputs).unwrap_or_else(|code| panic!("hosted configuration EOF setup refused before native work: {code:?}"));
    for case in [EofCase::Precommit, EofCase::Postcommit] {
        let checked = exercise_eof(&mut batch, &inputs, case).await;
        if checked.is_err() || !eof_all_settled(&batch) || batch.owner.disabled() { batch.stop_original().await; }
        let settled = eof_all_settled(&batch);
        if !settled || batch.owner.disabled() || matches!(checked, Err(Failure::OriginalCustodyUnknown | Failure::FixtureCustodyUnknown)) {
            if FIXTURE_FILES.all_settled() { let _ = eof_receipt(&inputs, &batch.cases, false, false, Some(Failure::OriginalCustodyUnknown)); }
            retain_unknown_runtime().await;
            return; // No second case/process admission on missing original proof.
        }
        if let Err(code) = checked {
            let _ = eof_receipt(&inputs, &batch.cases, false, true, Some(code));
            if !FIXTURE_FILES.all_settled() { retain_unknown_runtime().await; return; }
            panic!("hosted configuration EOF case failed after settlement: {code:?}");
        }
        if eof_receipt(&inputs, &batch.cases, false, false, Some(Failure::NotCompleted)).is_err() {
            if !FIXTURE_FILES.all_settled() { retain_unknown_runtime().await; return; }
            panic!("hosted configuration EOF progress receipt failed after settlement");
        }
    }
    if batch.owner.shutdown().await.is_err() || !eof_all_settled(&batch) || batch.cases.len() != 2 {
        if FIXTURE_FILES.all_settled() { let _ = eof_receipt(&inputs, &batch.cases, false, false, Some(Failure::OriginalCustodyUnknown)); }
        retain_unknown_runtime().await;
        return;
    }
    if eof_receipt(&inputs, &batch.cases, true, true, None).is_err() {
        if !FIXTURE_FILES.all_settled() { retain_unknown_runtime().await; return; }
        panic!("hosted configuration EOF final receipt failed after settlement");
    }
}

#[test]
fn eof_control_exact_records_and_chunk_boundaries() {
    // Inert parser only: no owner, clock, runtime, environment, IO or process.
    for case in [EofCase::Precommit, EofCase::Postcommit] {
        let bytes = [case.marker(), case.summary()].concat();
        for chunk_size in 1..=bytes.len() + 1 {
            let mut control = EofControl::default();
            for chunk in bytes.chunks(chunk_size) { assert!(control.observe(case, chunk)); }
            assert!(control.complete(case));
            assert_eq!(control.records(case), 2);
            assert!(!control.observe(case, b"\n"));
            assert!(!control.complete(case));
        }
        let mut control = EofControl::default();
        assert!(control.observe(case, case.marker()));
        assert!(control.boundary_only(case));
        assert_eq!(control.records(case), 1);
        assert!(!control.complete(case));
        assert!(control.observe(case, case.summary()));
        assert!(control.complete(case));
    }
}

#[test]
fn eof_control_refuses_missing_changed_or_duplicate_records() {
    for case in [EofCase::Precommit, EofCase::Postcommit] {
        let bytes = [case.marker(), case.summary()].concat();
        for length in 0..bytes.len() {
            let mut control = EofControl::default();
            assert!(control.observe(case, &bytes[..length]));
            assert!(!control.complete(case));
        }
        for index in 0..bytes.len() {
            let mut changed = bytes.clone();
            changed[index] = b'!';
            let mut control = EofControl::default();
            assert!(!control.observe(case, &changed));
            assert!(!control.complete(case));
        }
        let mut duplicate = EofControl::default();
        assert!(duplicate.observe(case, case.marker()));
        assert!(!duplicate.observe(case, case.marker()));
        let mut reversed = EofControl::default();
        assert!(!reversed.observe(case, case.summary()));
        let other = if case == EofCase::Precommit { EofCase::Postcommit } else { EofCase::Precommit };
        let mut wrong_case = EofControl::default();
        assert!(!wrong_case.observe(case, other.marker()));
    }
}
