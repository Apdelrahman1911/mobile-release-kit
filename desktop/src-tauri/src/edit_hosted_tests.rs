//! Source-only, ignored real-child checks for the finite configuration owner.
//! The normal/development/packaged edit gate is NOT enabled by these checks.
//! No renderer, picker, subprocess controller, recovery, Store, or OS-fault
//! simulation is involved. Ambiguous custody retains this runtime for hosted-VM
//! disposal. Fixed self-panic and clock-retention cases may return with the edit
//! gate still Unknown only after their distinct original-resource/task proofs.
#![cfg(any(target_os = "linux", target_os = "macos"))]

use super::*;
use std::{fs, io::{Read, Write}, os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt}, path::Path,
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
const IGNORE: &[u8] = b".mobile-release/\n.mobile-release-init-prepare/\n.mobile-release-init/\n.mobile-release-init-cleanup/\n.mobile-release-metadata-text-prepare/\n.mobile-release-metadata-text/\n.mobile-release-metadata-text-cleanup/\n.mobile-release-version-prepare/\n.mobile-release-version/\n.mobile-release-version-cleanup/\n";
const NOOP_IGNORE: &[u8] = b"# fixed synthetic comment\r\n/.mobile-release/\r\n/.mobile-release-init-prepare/\r\n/.mobile-release-init/\r\n/.mobile-release-init-cleanup/\r\n/.mobile-release-metadata-text-prepare/\r\n/.mobile-release-metadata-text/\r\n/.mobile-release-metadata-text-cleanup/\r\n/.mobile-release-version-prepare/\r\n/.mobile-release-version/\r\n/.mobile-release-version-cleanup/\r\n";
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
struct Retention {
    _owner: EditOwner, originals: Vec<Arc<Session>>,
    #[cfg(all(debug_assertions, not(feature = "desktop-shell"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    metadata_passive: Option<(Arc<crate::bridge::DesktopBridge>, Arc<crate::supervisor::metadata_fixture_probe::Probe>)>,
}
impl Retention {
    fn new(owner: &EditOwner) -> Self {
        Self { _owner:owner.clone(), originals:Vec::new(),
            #[cfg(all(debug_assertions, not(feature = "desktop-shell"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
            metadata_passive:None }
    }
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Failure {
    NotCompleted, HostedGuardRefused, SourceBindingMismatch, FixtureIo, FixtureCustodyUnknown,
    NativeCommandRejected, UnexpectedStatus, ObservationTimeout,
    OriginalCustodyUnknown, UnexpectedOutcome, PayloadMismatch, ReceiptIo,
    EofSeedModeMismatch, EofPreparedOriginalsMismatch, EofOriginalsMismatch, EofPayloadMismatch,
    EofMetadataMismatch, EofUnrelatedMismatch, EofReplacementInodeMismatch,
    DocumentOriginalNavigationAccepted, DocumentOriginalApplyNotRefused, DocumentOriginalOpenNotRefused,
    DocumentReplacementNavigationRefused, DocumentReplacementPrematurelyBound, DocumentReplacementRebound,
    DocumentReplacementApplyNotRefused, DocumentReplacementOpenNotRefused,
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

// The sole extra bootstrap selector is a private, domain-specific fixed-case
// mode. No renderer/environment method can select it. Its separate source hash
// is admitted before this Schedule can be queued for an original Session.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum EofCase { Precommit, Postcommit, WorkflowPrecommit, WorkflowPostcommit, WorkflowConflict,
    MetadataPrecommit, MetadataPostcommit, MetadataConflict, VersionPrecommit, VersionPostcommit, VersionConflict }
impl EofCase {
    pub(super) fn name(self) -> &'static str {
        match self { Self::Precommit | Self::WorkflowPrecommit | Self::MetadataPrecommit | Self::VersionPrecommit => "precommit-eof",
            Self::Postcommit | Self::WorkflowPostcommit | Self::MetadataPostcommit | Self::VersionPostcommit => "postcommit-eof",
            Self::WorkflowConflict | Self::MetadataConflict | Self::VersionConflict => "precommit-conflict-eof" }
    }
    pub(super) fn domain(self) -> EditDomain {
        match self { Self::Precommit | Self::Postcommit => EditDomain::Configuration,
            Self::WorkflowPrecommit | Self::WorkflowPostcommit | Self::WorkflowConflict => EditDomain::GitHubWorkflows,
            Self::MetadataPrecommit | Self::MetadataPostcommit | Self::MetadataConflict => EditDomain::MetadataText,
            Self::VersionPrecommit | Self::VersionPostcommit | Self::VersionConflict => EditDomain::ReleaseVersion }
    }
    fn project(self) -> &'static str {
        match self { Self::Precommit => "project-config-precommit-eof", Self::Postcommit => "project-config-postcommit-eof",
            Self::WorkflowPrecommit => "project-workflow-precommit-eof", Self::WorkflowPostcommit => "project-workflow-postcommit-eof",
            Self::WorkflowConflict => "project-workflow-precommit-conflict-eof",
            Self::MetadataPrecommit => "project-metadata-precommit-eof", Self::MetadataPostcommit => "project-metadata-postcommit-eof",
            Self::MetadataConflict => "project-metadata-precommit-conflict-eof",
            Self::VersionPrecommit => "project-version-precommit-eof", Self::VersionPostcommit => "project-version-postcommit-eof",
            Self::VersionConflict => "project-version-precommit-conflict-eof" }
    }
    fn boundary(self) -> &'static str {
        match self { Self::Postcommit | Self::WorkflowPostcommit | Self::MetadataPostcommit | Self::VersionPostcommit => "after-durable-COMMITTED", _ => "before-COMMITTED" }
    }
    fn checkpoint(self) -> &'static str {
        match self { Self::Postcommit | Self::WorkflowPostcommit | Self::MetadataPostcommit | Self::VersionPostcommit => "descriptor-close", _ => "publisher-entry" }
    }
    fn marker(self) -> &'static [u8] {
        match self {
            Self::Precommit => b"MRK_CONFIG_EOF_V1 precommit-eof boundary=before-COMMITTED\n",
            Self::Postcommit => b"MRK_CONFIG_EOF_V1 postcommit-eof boundary=after-durable-COMMITTED\n",
            Self::WorkflowPrecommit => b"MRK_WORKFLOW_EOF_V1 precommit-eof boundary=before-COMMITTED\n",
            Self::WorkflowPostcommit => b"MRK_WORKFLOW_EOF_V1 postcommit-eof boundary=after-durable-COMMITTED\n",
            Self::WorkflowConflict => b"MRK_WORKFLOW_EOF_V1 precommit-conflict-eof boundary=before-COMMITTED\n",
            Self::MetadataPrecommit => b"MRK_METADATA_TEXT_EOF_V1 precommit-eof boundary=before-COMMITTED\n",
            Self::VersionPrecommit => b"MRK_RELEASE_VERSION_EOF_V1 precommit-eof boundary=before-COMMITTED\n",
            Self::MetadataPostcommit => b"MRK_METADATA_TEXT_EOF_V1 postcommit-eof boundary=after-durable-COMMITTED\n",
            Self::VersionPostcommit => b"MRK_RELEASE_VERSION_EOF_V1 postcommit-eof boundary=after-durable-COMMITTED\n",
            Self::MetadataConflict => b"MRK_METADATA_TEXT_EOF_V1 precommit-conflict-eof boundary=before-COMMITTED\n",
            Self::VersionConflict => b"MRK_RELEASE_VERSION_EOF_V1 precommit-conflict-eof boundary=before-COMMITTED\n",
        }
    }
    fn summary(self) -> &'static [u8] {
        match self {
            Self::Precommit => b"MRK_CONFIG_EOF_V1 precommit-eof eof=1 nonempty=0 readErrors=0 checkpoint=publisher-entry applied=1 committed=0 rolledBack=1 terminal=ROLLED_BACK durable=1 recovery=1 clean=1 settled=1 cancelled=1\n",
            Self::Postcommit => b"MRK_CONFIG_EOF_V1 postcommit-eof eof=1 nonempty=0 readErrors=0 checkpoint=descriptor-close applied=1 committed=1 rolledBack=0 terminal=COMMITTED durable=1 recovery=1 clean=1 settled=1 cancelled=1\n",
            Self::WorkflowPrecommit => b"MRK_WORKFLOW_EOF_V1 precommit-eof eof=1 nonempty=0 readErrors=0 checkpoint=publisher-entry applied=1 committed=0 rolledBack=1 terminal=ROLLED_BACK durable=1 recovery=1 clean=1 settled=1 cancelled=1\n",
            Self::WorkflowPostcommit => b"MRK_WORKFLOW_EOF_V1 postcommit-eof eof=1 nonempty=0 readErrors=0 checkpoint=descriptor-close applied=1 committed=1 rolledBack=0 terminal=COMMITTED durable=1 recovery=1 clean=1 settled=1 cancelled=1\n",
            Self::WorkflowConflict => b"MRK_WORKFLOW_EOF_V1 precommit-conflict-eof eof=1 nonempty=0 readErrors=0 checkpoint=publisher-entry applied=1 committed=0 rolledBack=0 terminal=UNKNOWN durable=0 recovery=1 clean=0 settled=1 cancelled=1\n",
            Self::MetadataPrecommit => b"MRK_METADATA_TEXT_EOF_V1 precommit-eof eof=1 nonempty=0 readErrors=0 checkpoint=publisher-entry applied=1 committed=0 rolledBack=1 terminal=ROLLED_BACK durable=1 recovery=1 clean=1 settled=1 cancelled=1\n",
            Self::VersionPrecommit => b"MRK_RELEASE_VERSION_EOF_V1 precommit-eof eof=1 nonempty=0 readErrors=0 checkpoint=publisher-entry applied=1 committed=0 rolledBack=1 terminal=ROLLED_BACK durable=1 recovery=1 clean=1 settled=1 cancelled=1\n",
            Self::MetadataPostcommit => b"MRK_METADATA_TEXT_EOF_V1 postcommit-eof eof=1 nonempty=0 readErrors=0 checkpoint=descriptor-close applied=1 committed=1 rolledBack=0 terminal=COMMITTED durable=1 recovery=1 clean=1 settled=1 cancelled=1\n",
            Self::VersionPostcommit => b"MRK_RELEASE_VERSION_EOF_V1 postcommit-eof eof=1 nonempty=0 readErrors=0 checkpoint=descriptor-close applied=1 committed=1 rolledBack=0 terminal=COMMITTED durable=1 recovery=1 clean=1 settled=1 cancelled=1\n",
            Self::MetadataConflict => b"MRK_METADATA_TEXT_EOF_V1 precommit-conflict-eof eof=1 nonempty=0 readErrors=0 checkpoint=publisher-entry applied=1 committed=0 rolledBack=0 terminal=UNKNOWN durable=0 recovery=1 clean=0 settled=1 cancelled=1\n",
            Self::VersionConflict => b"MRK_RELEASE_VERSION_EOF_V1 precommit-conflict-eof eof=1 nonempty=0 readErrors=0 checkpoint=publisher-entry applied=1 committed=0 rolledBack=0 terminal=UNKNOWN durable=0 recovery=1 clean=0 settled=1 cancelled=1\n",
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
        let terminal = match frame {
            ChildFrame::Terminal(sequence, terminal) => Some((*sequence, terminal.outcome())),
            ChildFrame::WorkflowTerminal(sequence, terminal) => Some((*sequence, terminal.outcome())),
            ChildFrame::MetadataTextTerminal(sequence, terminal) => Some((*sequence, terminal.outcome())),
            ChildFrame::ReleaseVersionTerminal(sequence, terminal) => Some((*sequence, terminal.outcome())),
            _ => None,
        };
        if let Some((sequence, outcome)) = terminal {
            if self.terminal.armed.load(Ordering::SeqCst) {
                match self.held_terminal.lock() {
                    Ok(mut held) if held.is_none() => *held = Some((sequence, outcome)),
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
        let original = self.owner.inner.lock().active.as_ref().map(|active| (active.session.id.clone(), active.session.domain));
        if let Some((id, domain)) = original {
            match domain {
                EditDomain::Configuration => { let _ = self.owner.close("main", &id); },
                EditDomain::GitHubWorkflows => { let _ = self.owner.close_workflow("main", &id); },
                EditDomain::MetadataText => { let _ = self.owner.close_metadata_text("main", &id); },
                EditDomain::ReleaseVersion => { let _ = self.owner.close_release_version("main", &id); },
            }
        }
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
struct Identity { device: u64, inode: u64, mode: u32, owner: u32, group: u32 }
impl Identity {
    fn of(metadata: &fs::Metadata) -> Self {
        Self { device: metadata.dev(), inode: metadata.ino(), mode: metadata.mode(), owner: metadata.uid(), group: metadata.gid() }
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
    // Creation modes are filtered by the inherited umask (077 in hosted CI).
    // Set exact fixture permissions through this original, holding both
    // operation results until its one consuming close; close Unknown wins.
    let permissions = file.set_permissions(fs::Permissions::from_mode(mode));
    FIXTURE_FILES.close_original(file)?;
    require(wrote.is_ok() && permissions.is_ok(), Failure::FixtureIo)
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
        Ok(mut retained) => *retained = Some(Retention::new(&owner)),
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
        Ok(mut retained) => *retained = Some(Retention::new(&owner)),
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
        *retained = Some(Retention::new(&owner));
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
    require(before.iter().map(|file| file.identity.mode & 0o7777).eq([0o640, 0o600, 0o600]), Failure::EofSeedModeMismatch)?;

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
    require(before == originals(&root)?, Failure::EofPreparedOriginalsMismatch)?;
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
    require(originals_preserved == !committed, Failure::EofOriginalsMismatch)?;
    require(payloads_installed == committed, Failure::EofPayloadMismatch)?;
    require(modes_preserved, Failure::EofMetadataMismatch)?;
    require(unrelated_preserved, Failure::EofUnrelatedMismatch)?;
    require(!committed || before[0].identity.inode != after[0].identity.inode && before[1].identity.inode != after[1].identity.inode,
        Failure::EofReplacementInodeMismatch)?;
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
            panic!("hosted configuration EOF case {} failed after settlement: {code:?}", case.name());
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

// This extension uses the original Batch/Session, stream decoder, schedules,
// FixtureFiles and retention books above. There is no workflow supervisor or
// alternate recovery owner. A separate ignored invocation selects source or
// the helper's one inventory-bound ZIP before any original owner is admitted.
#[cfg(all(debug_assertions, not(feature = "desktop-shell"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
mod workflow {
    use super::*;
    use crate::{asset_session::DocumentBinding, asset_source::{self, SourceBook}, bridge::{DesktopBridge, Project}};

    const OWNER_SCOPE: &str = "github-workflow-owner-hosted-v1";
    const TRANSACTION_SCOPE: &str = "github-workflow-transaction-eof-hosted-v1";
    const DOMAIN: &str = "github_workflows";
    const REPOSITORY: &str = "Example/mobile-release-kit";
    const PIN: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const PROTECTED_CONFIG: &[u8] = b"fixed synthetic configuration; intentionally not parsed\r\n";
    const PROTECTED_IGNORE: &[u8] = b"# fixed synthetic workflow ignore\r\n";
    const UMASK_PROBE: &[u8] = b"fixed workflow fixture umask\n";
    const WORKFLOW_NOT_VERIFIED: &[&str] = &["production-runtime-custody", "production-workflow-enablement", "native-gui",
        "webview-callbacks-or-crash-hook", "parent-death", "native-stuck-wait-close", "persisted-recovery",
        "macos-windows-workflow-writes", "credentials", "remote-github", "stores", "mobile-builds", "installers"];
    const NAMES: [&str; 4] = ["mobile-preflight.yml", "mobile-candidate.yml", "mobile-external-testing.yml", "mobile-production-submit.yml"];
    const IDS: [&str; 4] = ["preflight", "candidate", "external-testing", "production-submit"];
    const WORKFLOW_IDS: [workflow_wire::WorkflowId; 4] = [workflow_wire::WorkflowId::Preflight, workflow_wire::WorkflowId::Candidate,
        workflow_wire::WorkflowId::ExternalTesting, workflow_wire::WorkflowId::ProductionSubmit];
    const CANONICAL: [&[u8]; 4] = [include_bytes!("../../../templates/workflows/mobile-preflight.yml"),
        include_bytes!("../../../templates/workflows/mobile-candidate.yml"), include_bytes!("../../../templates/workflows/mobile-external-testing.yml"),
        include_bytes!("../../../templates/workflows/mobile-production-submit.yml")];
    const RESOURCE: &[u8] = include_bytes!("../../../src/mobile_release/api/data/github-setup-v1.json");
    const WORKFLOW_PATH: &str = ".github/workflows/desktop-github-workflow-apply-native.yml";
    const WORKFLOW_SOURCE: &[u8] = include_bytes!("../../../.github/workflows/desktop-github-workflow-apply-native.yml");
    const WORKFLOW_REF: &str = "refs/heads/verify/desktop-github-workflow-apply-native";
    const EXTRA_SOURCES: &[Source] = &[
        Source { id:"workflowProtocol", relative:"desktop/src-tauri/src/github_workflow_edit_protocol.rs", compiled:include_bytes!("github_workflow_edit_protocol.rs") },
        Source { id:"bridge", relative:"desktop/src-tauri/src/bridge.rs", compiled:include_bytes!("bridge.rs") },
        Source { id:"documentBinding", relative:"desktop/src-tauri/src/asset_session.rs", compiled:include_bytes!("asset_session.rs") },
        Source { id:"documentLifetime", relative:"desktop/src-tauri/src/document_lifetime.rs", compiled:include_bytes!("document_lifetime.rs") },
        Source { id:"assetSource", relative:"desktop/src-tauri/src/asset_source.rs", compiled:include_bytes!("asset_source.rs") },
        Source { id:"assetCommands", relative:"desktop/src-tauri/src/asset_commands.rs", compiled:include_bytes!("asset_commands.rs") },
        Source { id:"supervisor", relative:"desktop/src-tauri/src/supervisor.rs", compiled:include_bytes!("supervisor.rs") },
        Source { id:"editCommands", relative:"desktop/src-tauri/src/edit_commands.rs", compiled:include_bytes!("edit_commands.rs") },
        Source { id:"githubCommands", relative:"desktop/src-tauri/src/github_commands.rs", compiled:include_bytes!("github_commands.rs") },
        Source { id:"workflowEdit", relative:"src/mobile_release/github_workflow_edit.py", compiled:include_bytes!("../../../src/mobile_release/github_workflow_edit.py") },
        Source { id:"workflowPayloads", relative:"src/mobile_release/workflow_payloads.py", compiled:include_bytes!("../../../src/mobile_release/workflow_payloads.py") },
        Source { id:"githubSetup", relative:"src/mobile_release/api/_github_setup.py", compiled:include_bytes!("../../../src/mobile_release/api/_github_setup.py") },
        Source { id:"githubResource", relative:"src/mobile_release/api/data/github-setup-v1.json", compiled:RESOURCE },
        Source { id:"canonicalPreflight", relative:"templates/workflows/mobile-preflight.yml", compiled:CANONICAL[0] },
        Source { id:"canonicalCandidate", relative:"templates/workflows/mobile-candidate.yml", compiled:CANONICAL[1] },
        Source { id:"canonicalExternalTesting", relative:"templates/workflows/mobile-external-testing.yml", compiled:CANONICAL[2] },
        Source { id:"canonicalProductionSubmit", relative:"templates/workflows/mobile-production-submit.yml", compiled:CANONICAL[3] },
    ];
    static PROBES: Mutex<Vec<SourceBook>> = Mutex::new(Vec::new());

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Mode { Source, Zip }
    impl Mode { fn name(self) -> &'static str { if self == Self::Source { "source" } else { "zip" } } }
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Case { Fresh, Parent, Mixed, Preserve, Conflict, RegisteredRoot, RegistryPrepare, RegistryApply, ConfigBusy, DocumentLost }
    impl Case {
        fn name(self) -> &'static str {
            match self { Self::Fresh => "create-fresh", Self::Parent => "create-under-github", Self::Mixed => "mixed-create-preserve",
                Self::Preserve => "preserve-all", Self::Conflict => "different-refusal", Self::RegisteredRoot => "root-replaced-before-open",
                Self::RegistryPrepare => "registration-before-prepare", Self::RegistryApply => "registration-before-apply",
                Self::ConfigBusy => "config-blocks-workflow", Self::DocumentLost => "document-loss" }
        }
        fn mask(self) -> [bool; 4] {
            match self { Self::Mixed => [true,false,true,false], Self::Preserve => [true;4], Self::Conflict => [true,false,false,false], _ => [false;4] }
        }
    }
    const SOURCE_CASES: [Case; 10] = [Case::Fresh, Case::Parent, Case::Mixed, Case::Preserve, Case::Conflict,
        Case::RegisteredRoot, Case::RegistryPrepare, Case::RegistryApply, Case::ConfigBusy, Case::DocumentLost];
    const EOF_CASES: [EofCase; 3] = [EofCase::WorkflowPrecommit, EofCase::WorkflowPostcommit, EofCase::WorkflowConflict];

    struct Admitted { inputs: Inputs, mode: Mode, eof: bool, python: PathBuf, core: PathBuf, repository: PathBuf,
        payloads: [Vec<u8>;4], allowed: Vec<PathBuf> }

    fn draft() -> Value { let mut value = document(); value["source"]["productionBranch"] = json!("production"); value }
    fn draft_wire() -> Check<Vec<u8>> { serde_json::to_vec(&draft()).map_err(|_| Failure::PayloadMismatch) }

    fn rendered() -> Check<[Vec<u8>;4]> {
        // The actual child uses workflow_payloads.render_workflow_caller. This
        // independent DATA expectation also requires the shipped resource's
        // complete texts to byte-equal the four canonical caller sources.
        let resource: Value = serde_json::from_slice(RESOURCE).map_err(|_| Failure::PayloadMismatch)?;
        require(resource["schemaVersion"] == 1 && resource["workflows"].as_object().is_some_and(|rows| rows.len() == 4), Failure::PayloadMismatch)?;
        let mut result: [Vec<u8>;4] = std::array::from_fn(|_| Vec::new());
        for index in 0..4 {
            let text = std::str::from_utf8(CANONICAL[index]).map_err(|_| Failure::PayloadMismatch)?;
            require(resource["workflows"][IDS[index]].as_str() == Some(text)
                && text.contains("__MOBILE_RELEASE_KIT_SHA__") && text.contains("__MOBILE_RELEASE_KIT_REPOSITORY__"), Failure::PayloadMismatch)?;
            result[index] = text.replace("__MOBILE_RELEASE_KIT_SHA__", PIN).replace("__MOBILE_RELEASE_KIT_REPOSITORY__", REPOSITORY).into_bytes();
            require(!result[index].is_empty() && result[index].len() <= 16 * 1024, Failure::PayloadMismatch)?;
        }
        Ok(result)
    }
    fn source_entry(path: &str) -> bool {
        path.starts_with("mobile_release/") && path.len() <= 256 && path.is_ascii()
            && path.split('/').all(|part| !part.is_empty() && part != "." && part != ".."
                && part.bytes().all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c)))
            && [".py", ".json", ".pem"].iter().any(|suffix| path.ends_with(suffix))
    }
    struct CoreBinding { source_tree: String, workflow_sha256: String, run_id: String, attempt: String, reference: String,
        zip_sha256: String, inventory_sha256: String }
    fn bind_core(repository: &Path, task: &Path, sha: &str) -> Check<CoreBinding> {
        let metadata = read_regular(&task.join("metadata.json"), 2 * 1024 * 1024)?;
        let metadata: Value = serde_json::from_slice(&metadata.bytes).map_err(|_| Failure::SourceBindingMismatch)?;
        require(metadata.as_object().is_some_and(|fields| fields.len() == 8)
            && metadata["sourceSha"].as_str() == Some(sha), Failure::SourceBindingMismatch)?;
        let tree = metadata["sourceTree"].as_str().ok_or(Failure::SourceBindingMismatch)?;
        let run_id = environment("GITHUB_RUN_ID")?; let attempt = environment("GITHUB_RUN_ATTEMPT")?;
        let reference = environment("GITHUB_REF")?;
        require(tree.len() == 40 && tree.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
            && tree != "0".repeat(40) && reference == WORKFLOW_REF
            && [&run_id, &attempt].iter().all(|value| !value.is_empty() && value.len() <= 20
                && !value.starts_with('0') && value.bytes().all(|c| c.is_ascii_digit()))
            && metadata["runId"].as_str() == Some(run_id.as_str()) && metadata["attempt"].as_str() == Some(attempt.as_str())
            && metadata["ref"].as_str() == Some(reference.as_str()), Failure::SourceBindingMismatch)?;
        let workflow_sha256 = hash(WORKFLOW_SOURCE);
        require(hash(&read_regular(&repository.join(WORKFLOW_PATH), 2 * 1024 * 1024)?.bytes) == workflow_sha256
            && metadata["workflowSha256"].as_str() == Some(workflow_sha256.as_str()), Failure::SourceBindingMismatch)?;
        let rows = metadata["coreFiles"].as_array().ok_or(Failure::SourceBindingMismatch)?;
        require(!rows.is_empty() && rows.len() <= 2048, Failure::SourceBindingMismatch)?;
        let mut previous = ""; let mut total = 0usize;
        for row in rows {
            let path = row["path"].as_str().ok_or(Failure::SourceBindingMismatch)?;
            require(row.as_object().is_some_and(|row| row.len() == 3) && source_entry(path) && path > previous, Failure::SourceBindingMismatch)?;
            let file = read_regular(&repository.join("src").join(path), 8 * 1024 * 1024)?;
            total = total.checked_add(file.bytes.len()).ok_or(Failure::SourceBindingMismatch)?;
            require(total <= 32 * 1024 * 1024 && row["size"].as_u64() == Some(file.bytes.len() as u64)
                && row["sha256"].as_str() == Some(hash(&file.bytes).as_str()), Failure::SourceBindingMismatch)?;
            previous = path;
        }
        let zip = read_regular(&task.join("core.zip"), 32 * 1024 * 1024)?;
        let zip_hash = hash(&zip.bytes);
        require(metadata["coreZipSha256"].as_str() == Some(zip_hash.as_str()), Failure::SourceBindingMismatch)?;
        // ZIP content construction/inventory is the reviewed helper's original
        // DATA operation. No ZIP parsing/import/extraction occurs in this fixture.
        // The reviewed helper authenticates sourceTree through its original Git
        // DATA calls. This fixture binds that exact metadata, not a second Git
        // process or a claim that a hash alone authenticates the checkout.
        Ok(CoreBinding { source_tree:tree.to_owned(), workflow_sha256, run_id, attempt, reference, zip_sha256:zip_hash,
            inventory_sha256:hash(&serde_json::to_vec(rows).map_err(|_| Failure::SourceBindingMismatch)?) })
    }
    fn write_mask_probe(root: &Path) -> Check<()> {
        FIXTURE_FILES.admit()?;
        let path = root.join("umask-check");
        let mut original = fs::OpenOptions::new().create_new(true).write(true).mode(0o644).open(&path).map_err(|_| Failure::FixtureIo)?;
        FIXTURE_FILES.acquired();
        let wrote = original.write_all(UMASK_PROBE);
        FIXTURE_FILES.close_original(original)?;
        require(wrote.is_ok(), Failure::FixtureIo)?;
        let observed = read_regular(&path, 128)?;
        require(observed.bytes == UMASK_PROBE && observed.identity.mode & 0o7777 == 0o600, Failure::HostedGuardRefused)
    }
    impl Admitted {
        fn admit(eof: bool) -> Check<Self> {
            FIXTURE_FILES.admit()?;
            require(environment("MRK_DESKTOP_WORKFLOW_HOSTED_CHECKS")? == "github-workflows-v1"
                && environment("GITHUB_ACTIONS")? == "true" && environment("RUNNER_ENVIRONMENT")? == "github-hosted"
                && environment("RUNNER_OS")? == "Linux" && environment("RUNNER_ARCH")? == "X64"
                && crate::runtime::COMPILED_TARGET == "x86_64-unknown-linux-gnu"
                && rustix::process::getuid().as_raw() != 0
                && rustix::process::getuid() == rustix::process::geteuid(), Failure::HostedGuardRefused)?;
            let mode = match environment("MRK_DESKTOP_WORKFLOW_INPUT")?.as_str() {
                "source" => Mode::Source, "zip" if !eof => Mode::Zip, _ => return Err(Failure::HostedGuardRefused),
            };
            let temporary = canonical_input("RUNNER_TEMP", false)?;
            let root = canonical_input("MRK_DESKTOP_EDIT_TEST_ROOT", true)?;
            let task = root.parent().ok_or(Failure::HostedGuardRefused)?;
            let manifest = Path::new(env!("CARGO_MANIFEST_DIR")).canonicalize().map_err(|_| Failure::HostedGuardRefused)?;
            let repository = manifest.parent().and_then(Path::parent).ok_or(Failure::HostedGuardRefused)?.to_path_buf();
            let name = if eof { "workflow-transaction-eof" } else if mode == Mode::Source { "workflow-owner-source" } else { "workflow-owner-zip" };
            require(root.file_name().and_then(|name| name.to_str()) == Some(name) && task != temporary && task.starts_with(&temporary)
                && std::env::current_dir().map_err(|_| Failure::HostedGuardRefused)? == manifest
                && !root.starts_with(&repository) && !repository.starts_with(&root), Failure::HostedGuardRefused)?;
            let metadata = fs::symlink_metadata(&root).map_err(|_| Failure::HostedGuardRefused)?;
            require(metadata.is_dir() && metadata.mode() & 0o7777 == 0o700 && metadata.uid() == rustix::process::geteuid().as_raw()
                && metadata.gid() == rustix::process::getegid().as_raw()
                && fs::read_dir(&root).map_err(|_| Failure::HostedGuardRefused)?.next().is_none(), Failure::HostedGuardRefused)?;
            let python = canonical_input("MRK_DESKTOP_DEV_PYTHON", true)?;
            let core = canonical_input("MRK_DESKTOP_DEV_CORE", true)?;
            require(core == if mode == Mode::Source { repository.join("src") } else { task.join("core.zip") }
                && !python.starts_with(task) && !python.starts_with(&repository), Failure::HostedGuardRefused)?;
            let sha = environment("GITHUB_SHA")?;
            require(sha.len() == 40 && sha.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
                && sha != "0".repeat(40) && environment("MRK_DESKTOP_EDIT_SOURCE_SHA")? == sha
                && option_env!("GITHUB_SHA") == Some(sha.as_str()), Failure::SourceBindingMismatch)?;
            let mut source_hashes = serde_json::Map::new();
            for item in SOURCES.iter().chain(EXTRA_SOURCES).chain(if eof { std::slice::from_ref(&EOF_SOURCE) } else { &[] }) {
                let bytes = read_regular(&repository.join(item.relative), 2 * 1024 * 1024)?.bytes;
                let expected = hash(item.compiled);
                require(hash(&bytes) == expected && source_hashes.insert(item.id.to_owned(), json!(expected)).is_none(), Failure::SourceBindingMismatch)?;
            }
            let core_binding = bind_core(&repository, task, &sha)?;
            let payloads = rendered()?;
            let mut payload_hashes = serde_json::Map::new();
            for index in 0..4 { payload_hashes.insert(IDS[index].into(), json!(hash(&payloads[index]))); }
            let bindings = json!({"sourceSha":sha,"sourceTree":core_binding.source_tree,"workflowSha256":core_binding.workflow_sha256,
                "runId":core_binding.run_id,"attempt":core_binding.attempt,"ref":core_binding.reference,
                "domain":DOMAIN,"host":"linux","target":crate::runtime::COMPILED_TARGET,
                "runtimeMode":"trusted-development-only","runtimeInput":mode.name(),
                "pythonSha256":hash(&read_regular(&python,64*1024*1024)?.bytes),"coreZipSha256":core_binding.zip_sha256,"coreInventorySha256":core_binding.inventory_sha256,
                "sourceHashes":source_hashes,"payloadHashes":{"draft":hash(&draft_wire()?),"workflows":payload_hashes,
                    "protectedConfig":hash(PROTECTED_CONFIG),"protectedIgnore":hash(PROTECTED_IGNORE),"unrelated":hash(UNRELATED),"umaskProbe":hash(UMASK_PROBE)},
                "templateResourceSha256":hash(RESOURCE),"toolingRepository":REPOSITORY,"toolingSha":PIN,
                "inheritedFileMaskObserved":true,"requestedCreateMode":420,"observedCreateMode":384,"newDirectoryMode":493,
                "documentEvidence":"controlled-original-lifetime-not-gui-callbacks"});
            let allowed = if eof { EOF_CASES.iter().map(|case| root.join(case.name())).collect() }
                else if mode == Mode::Zip { vec![root.join(Case::Fresh.name())] }
                else { SOURCE_CASES.iter().map(|case| root.join(case.name()))
                    .chain([root.join("registration-prepare-extra"),root.join("registration-apply-extra")]).collect() };
            write_mask_probe(&root)?;
            Ok(Self { inputs:Inputs { root, identity:Identity::of(&metadata), bindings }, mode, eof, python, core, repository, payloads, allowed })
        }
        fn permit(&self, owner: &EditOwner) -> Check<()> {
            self.inputs.same_root()?;
            require(owner.can_exit() && !owner.disabled() && !owner.inner.hosted_qualified(EditDomain::GitHubWorkflows), Failure::HostedGuardRefused)?;
            let mut slot = owner.inner.fixture_workflow.lock().map_err(|_| Failure::OriginalCustodyUnknown)?;
            require(slot.is_none(), Failure::HostedGuardRefused)?;
            *slot = Some(Arc::new(WorkflowFixturePermit { owner:Arc::downgrade(&owner.inner), roots:self.allowed.clone(),
                python:self.python.clone(), core:self.core.clone(), bootstrap:self.repository.join("desktop/config_edit_bootstrap.py"),
                cwd:self.repository.join("desktop"), binding_sha256:hash(&serde_json::to_vec(&self.inputs.bindings).map_err(|_| Failure::SourceBindingMismatch)?),
                eof:self.eof }));
            Ok(())
        }
    }

    fn probes_settled() -> bool { PROBES.lock().is_ok_and(|books| books.iter().all(SourceBook::settled)) }
    struct Original { batch: Batch, bridge: Arc<DesktopBridge>, document: DocumentBinding }
    impl Original {
        fn new(input: &Admitted) -> Check<Self> {
            let bridge = Arc::new(DesktopBridge::new(input.inputs.root.clone()));
            let owner = bridge.edits.clone();
            {
                let mut retained = RETAINED.lock().map_err(|_| Failure::OriginalCustodyUnknown)?;
                require(retained.is_none(), Failure::OriginalCustodyUnknown)?;
                *retained = Some(Retention::new(&owner));
            }
            input.permit(&owner)?;
            let document = DocumentBinding::new(bridge.clone());
            // Controlled integration observations, explicitly NOT callbacks or
            // evidence that a real webview/crash hook exists in this headless lane.
            require(document.navigation(true), Failure::NativeCommandRejected)?;
            document.observe(|life| life.started(true)); document.hook_installed(); document.observe(|life| life.finished(true));
            require(owner.workflow_status().is_ok_and(|s| s.capability.available), Failure::NativeCommandRejected)?;
            Ok(Self { batch:Batch { owner, originals:Vec::new(), missing_original:false, cases:Vec::new() }, bridge, document })
        }
        fn register(&self, root: &Path) -> Check<Project> {
            require(probes_settled() && FIXTURE_FILES.all_settled(), Failure::OriginalCustodyUnknown)?;
            let generation = self.bridge.native_generation().map_err(|_| Failure::NativeCommandRejected)?;
            let (proof, settled) = {
                let mut originals = PROBES.lock().map_err(|_| Failure::OriginalCustodyUnknown)?;
                require(originals.len() < 12, Failure::OriginalCustodyUnknown)?;
                // Retain BEFORE the original probe can acquire anything. This
                // fixture-only retention mutex is not the document/registry
                // lock. Even an unwind leaves the same original book here.
                originals.push(SourceBook::new());
                let book = originals.last_mut().ok_or(Failure::OriginalCustodyUnknown)?;
                let proof = std::panic::catch_unwind(std::panic::AssertUnwindSafe(||
                    asset_source::probe_project(book, root.to_path_buf(), &[], &mut || false)))
                    .map_err(|_| Failure::OriginalCustodyUnknown)?;
                (proof, book.settled())
            };
            require(settled, Failure::OriginalCustodyUnknown)?;
            let proof = proof.map_err(|_| Failure::NativeCommandRejected)?;
            let project = self.document.workflow_fixture_publish(proof, generation).map_err(|_| Failure::NativeCommandRejected)?;
            let (_, registered) = self.bridge.native_project(&project.id).map_err(|_| Failure::NativeCommandRejected)?;
            let actual = fs::symlink_metadata(root).map_err(|_| Failure::FixtureIo)?;
            let identity = registered.identity.workflow_identity();
            require(registered.path == root && identity.device == actual.dev().to_string() && identity.inode == actual.ino().to_string()
                && identity.mode == actual.mode() && identity.uid == actual.uid() && identity.gid == actual.gid(), Failure::PayloadMismatch)?;
            Ok(project)
        }
        fn retain_open(&mut self) -> Check<Arc<Session>> {
            let original = {
                let registry = self.batch.owner.inner.lock();
                if registry.last.as_ref().is_some_and(|last| !self.batch.originals.iter().any(|owner| owner.id == last.session_id)) {
                    self.batch.missing_original = true;
                }
                registry.active.as_ref().map(|active| active.session.clone())
            };
            let original = original.ok_or_else(|| { self.batch.missing_original = true; Failure::OriginalCustodyUnknown })?;
            self.batch.originals.push(original.clone());
            RETAINED.lock().map_err(|_| Failure::OriginalCustodyUnknown)?.as_mut().ok_or(Failure::OriginalCustodyUnknown)?.originals.push(original.clone());
            Ok(original)
        }
        fn open(&mut self, project: &Project) -> Check<Arc<Session>> {
            require(self.settled() && !self.batch.owner.disabled(), Failure::OriginalCustodyUnknown)?;
            let result = self.bridge.open_workflow_edit(&self.document, "main", project.id.clone());
            let original = self.retain_open()?; // Before even inspecting an error reply.
            let status = result.map_err(|_| Failure::NativeCommandRejected)?;
            require(select(&status, &original.id)?.phase == Phase::Opening && original.domain == EditDomain::GitHubWorkflows, Failure::UnexpectedStatus)?;
            Ok(original)
        }
        fn settled(&self) -> bool {
            FIXTURE_FILES.all_settled() && probes_settled() && !self.batch.missing_original && self.batch.owner.can_exit()
                && self.batch.originals.iter().all(|original| match original.fixture_schedule.eof_case() {
                    Some(case) => original_eof_facts(original,case).is_ok(), None => original_facts(original).is_ok(),
                })
        }
        async fn stop(&self) {
            let current = self.batch.owner.inner.lock().active.as_ref().map(|active| (active.session.id.clone(),active.session.domain));
            if let Some((id, domain)) = current {
                if domain == EditDomain::GitHubWorkflows {
                    let _ = self.batch.owner.close_workflow("main",&id);
                    let _ = observed_workflow(&self.batch.owner,&id,Phase::Final,false).await;
                } else { self.batch.stop_original().await; }
            }
        }
    }
    fn select(status: &WorkflowEditStatus, id: &str) -> Check<workflow_wire::Projection> {
        require(status.domain == DOMAIN, Failure::UnexpectedStatus)?;
        status.active.as_ref().filter(|p| p.session_id == id).or_else(|| status.last_terminal.as_ref().filter(|p| p.session_id == id))
            .cloned().ok_or(Failure::UnexpectedStatus)
    }
    async fn observed_workflow(owner: &EditOwner, id: &str, desired: Phase, expected_effect_unknown: bool) -> Check<workflow_wire::Projection> {
        let end = Instant::now() + OBSERVATION;
        let mut revisions = owner.subscribe();
        loop {
            let status = owner.workflow_status().map_err(|_| Failure::OriginalCustodyUnknown)?;
            let current = select(&status,id)?;
            if !expected_effect_unknown {
                require(!owner.disabled() && current.phase != Phase::Unknown && current.native_finality != NativeFinality::Unknown
                    && !current.late_settled, Failure::OriginalCustodyUnknown)?;
            }
            if current.phase == desired && (!expected_effect_unknown || status.active.is_none()) { return Ok(current); }
            require(current.phase != Phase::Final, Failure::UnexpectedStatus)?;
            tokio::select! {
                result = revisions.changed() => { result.map_err(|_| Failure::UnexpectedStatus)?; },
                _ = tokio::time::sleep_until(tokio::time::Instant::from_std(end)) => return Err(Failure::ObservationTimeout),
            }
        }
    }

    #[derive(PartialEq, Eq)]
    struct Snapshot { files: std::collections::BTreeMap<String,OriginalFile>, directories: std::collections::BTreeMap<String,Identity> }
    fn mkdir(path: &Path) -> Check<()> {
        FIXTURE_FILES.admit()?;
        fs::DirBuilder::new().mode(0o700).create(path).map_err(|_| Failure::FixtureIo)
    }
    fn snapshot(root: &Path) -> Check<Snapshot> {
        // Finite synthetic DATA tree only, not journal discovery or recovery.
        // A journal/nonregular/unknown object refuses this observation outright.
        let mut files = std::collections::BTreeMap::new();
        let mut directories = std::collections::BTreeMap::new();
        let mut pending = vec![String::new()];
        let leaves: Vec<String> = [".gitignore", "unrelated.txt", "release/mobile-release.json", ".github/other.txt", ".github/workflows/unrelated.txt"]
            .into_iter().map(str::to_owned).chain(NAMES.iter().map(|name| format!(".github/workflows/{name}"))).collect();
        while let Some(relative) = pending.pop() {
            FIXTURE_FILES.admit()?;
            let path = root.join(&relative);
            let metadata = fs::symlink_metadata(&path).map_err(|_| Failure::FixtureIo)?;
            require(metadata.is_dir() && directories.len() < 4, Failure::PayloadMismatch)?;
            directories.insert(relative.clone(), Identity::of(&metadata));
            let mut count = 0;
            for entry in fs::read_dir(path).map_err(|_| Failure::FixtureIo)? {
                count += 1; require(count <= 12, Failure::PayloadMismatch)?;
                let entry = entry.map_err(|_| Failure::FixtureIo)?;
                let name = entry.file_name().into_string().map_err(|_| Failure::PayloadMismatch)?;
                let child = if relative.is_empty() { name } else { format!("{relative}/{name}") };
                let stat = fs::symlink_metadata(root.join(&child)).map_err(|_| Failure::FixtureIo)?;
                if stat.is_dir() {
                    require(["release", ".github", ".github/workflows"].contains(&child.as_str()), Failure::PayloadMismatch)?;
                    pending.push(child);
                } else {
                    require(leaves.contains(&child) && files.len() < 9, Failure::PayloadMismatch)?;
                    let read = read_regular(&root.join(&child), 1024 * 1024)?;
                    require(files.insert(child,read).is_none(), Failure::PayloadMismatch)?;
                }
            }
        }
        Ok(Snapshot { files, directories })
    }
    fn seed(input: &Admitted, case: Case) -> Check<PathBuf> {
        input.inputs.same_root()?;
        let root = input.inputs.root.join(case.name());
        mkdir(&root)?;
        write_new(&root.join(".gitignore"),PROTECTED_IGNORE,0o600)?;
        write_new(&root.join("unrelated.txt"),UNRELATED,0o600)?;
        if case != Case::Fresh {
            mkdir(&root.join("release"))?;
            let config = if case == Case::ConfigBusy { noop_bytes()? } else { PROTECTED_CONFIG.to_vec() };
            write_new(&root.join("release/mobile-release.json"),&config,0o640)?;
        }
        if matches!(case, Case::Parent | Case::Mixed | Case::Preserve | Case::Conflict) {
            mkdir(&root.join(".github"))?;
            write_new(&root.join(".github/other.txt"),UNRELATED,0o600)?;
        }
        if matches!(case, Case::Mixed | Case::Preserve | Case::Conflict) {
            mkdir(&root.join(".github/workflows"))?;
            write_new(&root.join(".github/workflows/unrelated.txt"),UNRELATED,0o600)?;
        }
        for (index,preserve) in case.mask().into_iter().enumerate() {
            if preserve {
                let mut bytes = input.payloads[index].clone();
                if case == Case::Conflict { bytes.push(b'\n'); }
                write_new(&root.join(".github/workflows").join(NAMES[index]),&bytes,0o640)?;
            }
        }
        Ok(root)
    }
    fn observed_roster(input: &Admitted, before: &Snapshot, checkout: &workflow_wire::Checkout) -> Check<()> {
        require(checkout.observed.len() == 4, Failure::UnexpectedOutcome)?;
        for index in 0..4 {
            let path = format!(".github/workflows/{}",NAMES[index]);
            let expected = match before.files.get(&path) {
                Some(file) => workflow_wire::ObservedFile::Present { id:WORKFLOW_IDS[index], byte_length:file.bytes.len() as u32, sha256:hash(&file.bytes) },
                None => workflow_wire::ObservedFile::Absent { id:WORKFLOW_IDS[index] },
            };
            require(checkout.observed[index] == expected && input.payloads[index].len() <= 16 * 1024, Failure::UnexpectedOutcome)?;
        }
        Ok(())
    }
    fn prepare_args(id: &str, revision: &str) -> PrepareWorkflowEdit {
        PrepareWorkflowEdit { session_id:id.to_owned(),revision:revision.to_owned(),draft:draft(),tooling_repository:REPOSITORY.into(),
            tooling_sha:PIN.into(),draft_revision:1,baseline_generation:0 }
    }
    async fn prepare(original: &Original, id: &str, checkout: &workflow_wire::Checkout) -> Check<workflow_wire::Prepared> {
        let reply = original.bridge.prepare_workflow_edit(&original.document,"main",prepare_args(id,&checkout.revision))
            .map_err(|_| Failure::NativeCommandRejected)?;
        require(select(&reply,id)?.phase == Phase::Preparing, Failure::UnexpectedStatus)?;
        observed_workflow(&original.batch.owner,id,Phase::Reviewing,false).await?.prepared.ok_or(Failure::UnexpectedOutcome)
    }
    fn verify_plan(input: &Admitted, before: &Snapshot, checkout: &workflow_wire::Checkout, plan: &workflow_wire::Prepared) -> Check<Vec<String>> {
        require(plan.revision == checkout.revision && plan.draft_revision == 1 && plan.baseline_generation == 0
            && plan.view.matches_observed(&checkout.observed) && plan.view.files.len() == 4
            && plan.view.template_set.core_version == crate::runtime::CORE_VERSION && plan.view.template_set.resource_version == 1
            && plan.view.template_set.resource_sha256 == hash(RESOURCE)
            && plan.view.tooling.repository == REPOSITORY && plan.view.tooling.sha == PIN && plan.view.tooling.state == "format-only"
            && plan.view.tooling.schema_reference == format!("https://raw.githubusercontent.com/{REPOSITORY}/{PIN}/schemas/project.schema.json"), Failure::UnexpectedOutcome)?;
        for index in 0..4 {
            let file = &plan.view.files[index]; let path = format!(".github/workflows/{}",NAMES[index]);
            let preserve = before.files.contains_key(&path);
            require(file.id == WORKFLOW_IDS[index] && file.path == path
                && file.action == if preserve { workflow_wire::Action::Preserve } else { workflow_wire::Action::Create }
                && file.generated.content.as_bytes() == input.payloads[index] && file.generated.byte_length as usize == input.payloads[index].len()
                && file.generated.sha256 == hash(&input.payloads[index]), Failure::PayloadMismatch)?;
        }
        let directories: Vec<String> = [".github", ".github/workflows"].into_iter().filter(|name| !before.directories.contains_key(*name)).map(str::to_owned).collect();
        require(plan.view.create_directories == directories, Failure::UnexpectedOutcome)?;
        Ok(directories)
    }
    fn installed(input: &Admitted, root: &Path, before: &Snapshot, directories: &[String]) -> Check<()> {
        let after = snapshot(root)?;
        require(before.files.iter().all(|(path,old)| after.files.get(path) == Some(old))
            && before.directories.iter().all(|(path,old)| after.directories.get(path) == Some(old)), Failure::PayloadMismatch)?;
        for index in 0..4 {
            let path = format!(".github/workflows/{}",NAMES[index]);
            let file = after.files.get(&path).ok_or(Failure::PayloadMismatch)?;
            require(file.bytes == input.payloads[index], Failure::PayloadMismatch)?;
            if !before.files.contains_key(&path) {
                require(file.identity.mode & 0o7777 == 0o600 && file.identity.owner == rustix::process::geteuid().as_raw()
                    && file.identity.group == rustix::process::getegid().as_raw(), Failure::PayloadMismatch)?;
            }
        }
        for name in directories {
            require(after.directories.get(name).is_some_and(|identity| identity.mode & 0o7777 == 0o755), Failure::PayloadMismatch)?;
        }
        let creates = NAMES.iter().filter(|name| !before.files.contains_key(&format!(".github/workflows/{name}"))).count();
        require(after.files.len() == before.files.len() + creates && after.directories.len() == before.directories.len() + directories.len(), Failure::PayloadMismatch)
    }
    fn terminal_data(name: &str, original: &Session, terminal: &workflow_wire::Projection, observations: Value, eof: Option<EofCase>) -> Check<Value> {
        let facts = if let Some(case) = eof { original_eof_facts(original,case)? } else { original_facts(original)? };
        let mut value = serde_json::to_value(facts).map_err(|_| Failure::ReceiptIo)?;
        value["name"] = json!(name); value["domain"] = json!(DOMAIN);
        value["nativePhase"] = json!(terminal.phase); value["nativeFinality"] = json!(terminal.native_finality);
        value["nativeReason"] = json!(terminal.native_reason); value["applySubmitted"] = json!(terminal.apply_submitted);
        value["lateSettled"] = json!(terminal.late_settled); value["outcome"] = json!(terminal.core_outcome);
        value["terminalSeq"] = json!(original.fixture_schedule.sequence());
        value["registeredByOriginalProbe"] = json!(true); value["sourceProbesSettled"] = json!(probes_settled());
        value["observations"] = observations;
        Ok(value)
    }
    fn settled_terminal(owner: &EditOwner, terminal: &workflow_wire::Projection) -> Check<()> {
        require(terminal.phase == Phase::Final && terminal.native_finality == NativeFinality::Settled
            && !terminal.late_settled && owner.can_exit() && !owner.disabled(), Failure::OriginalCustodyUnknown)
    }
    fn cancelled(terminal: &workflow_wire::Projection, native: Reason) -> Check<()> {
        let core = terminal.core_outcome.as_ref().ok_or(Failure::UnexpectedOutcome)?;
        require(!terminal.apply_submitted && terminal.native_reason == native && core.effect == Effect::NotStarted
            && core.journal == Journal::NotCreated && core.resources == ResourceState::Settled
            && matches!(core.reason, CoreReason::Cancelled | CoreReason::None), Failure::UnexpectedOutcome)
    }
    async fn config_busy(original: &mut Original, root: &Path, project: &Project) -> Check<()> {
        let before = snapshot(root)?;
        let previous = original.batch.owner.workflow_status().map_err(|_| Failure::UnexpectedStatus)?.last_terminal.ok_or(Failure::UnexpectedStatus)?;
        original.batch.owner.inner.fixture_authorized.store(true,Ordering::SeqCst);
        let reply = original.bridge.open_config_edit("main",project.id.clone());
        let session = original.retain_open()?;
        require(projection(&reply.map_err(|_| Failure::NativeCommandRejected)?,&session.id)?.phase == Phase::Opening, Failure::UnexpectedStatus)?;
        observed(&original.batch.owner,&session.id,Phase::Editing).await?;
        let own = original.batch.owner.status().map_err(|_| Failure::UnexpectedStatus)?;
        let other = original.batch.owner.workflow_status().map_err(|_| Failure::UnexpectedStatus)?;
        require(other.active.is_none() && other.capability.reason == EditAvailability::OtherEditActive
            && other.last_terminal.as_ref().is_some_and(|last| last.session_id == previous.session_id)
            && own.status_revision == other.status_revision
            && original.bridge.open_workflow_edit(&original.document,"main",project.id.clone()).is_err_and(|error| error.code == "busy"), Failure::UnexpectedStatus)?;
        original.batch.owner.close("main",&session.id).map_err(|_| Failure::NativeCommandRejected)?;
        let terminal = observed(&original.batch.owner,&session.id,Phase::Final).await?;
        let facts = original_facts(&session)?;
        let core = terminal.core_outcome.as_ref().ok_or(Failure::UnexpectedOutcome)?;
        require((facts.request_frames,facts.response_frames) == (1,2) && session.fixture_schedule.sequence() == Some(0)
            && core.effect == Effect::NotStarted && core.journal == Journal::NotCreated && core.resources == ResourceState::Settled
            && matches!(core.reason,CoreReason::Cancelled | CoreReason::None) && terminal.native_reason == Reason::Discarded
            && original.batch.owner.workflow_status().is_ok_and(|status| status.last_terminal.is_none())
            && snapshot(root)? == before && original.settled(), Failure::UnexpectedOutcome)?;
        original.batch.owner.inner.fixture_authorized.store(false,Ordering::SeqCst);
        let mut evidence = serde_json::to_value(facts).map_err(|_| Failure::ReceiptIo)?;
        evidence["name"] = json!(Case::ConfigBusy.name()); evidence["domain"] = json!("configuration");
        evidence["nativePhase"] = json!(terminal.phase); evidence["nativeFinality"] = json!(terminal.native_finality);
        evidence["nativeReason"] = json!(terminal.native_reason); evidence["applySubmitted"] = json!(false);
        evidence["lateSettled"] = json!(terminal.late_settled); evidence["outcome"] = json!(core);
        evidence["terminalSeq"] = json!(0); evidence["registeredByOriginalProbe"] = json!(true); evidence["sourceProbesSettled"] = json!(true);
        evidence["observations"] = json!({"oppositeDomainRefused":true,"sharedStatusRevision":true,"sharedLastTerminalReplaced":true,
            "configurationFilesUnchanged":true,"workflowPermitStillSeparate":true});
        original.batch.cases.push(evidence);
        Ok(())
    }
    async fn exercise_owner(original: &mut Original, input: &Admitted, case: Case) -> Check<()> {
        require(original.settled() && !original.batch.owner.disabled(), Failure::OriginalCustodyUnknown)?;
        let root = seed(input,case)?;
        let project = original.register(&root)?;
        if case == Case::ConfigBusy { return config_busy(original,&root,&project).await; }
        let registered = original.bridge.native_project(&project.id).map_err(|_| Failure::UnexpectedStatus)?;
        if case == Case::RegisteredRoot {
            // Replacement happens before original Open, not through a forged
            // identity. Retain the old synthetic directory for VM disposal.
            fs::rename(&root,input.inputs.root.join("root-before-open-retired")).map_err(|_| Failure::FixtureIo)?;
            mkdir(&root)?; write_new(&root.join("unrelated.txt"),UNRELATED,0o600)?;
            require(fs::symlink_metadata(&root).map_err(|_| Failure::FixtureIo)?.ino().to_string()
                != registered.1.identity.workflow_identity().inode, Failure::PayloadMismatch)?;
        }
        let before = snapshot(&root)?;
        let session = original.open(&project)?;
        require(session.registration.as_ref().is_some_and(|registration| registration.generation == registered.0 && registration.root == registered.1), Failure::UnexpectedStatus)?;
        if case == Case::RegisteredRoot {
            let terminal = observed_workflow(&original.batch.owner,&session.id,Phase::Final,false).await?;
            settled_terminal(&original.batch.owner,&terminal)?;
            let facts = original_facts(&session)?;
            let core = terminal.core_outcome.as_ref().ok_or(Failure::UnexpectedOutcome)?;
            require((facts.request_frames,facts.response_frames) == (1,1) && session.fixture_schedule.sequence() == Some(0)
                && terminal.checkout.is_none() && terminal.prepared.is_none() && !terminal.apply_submitted
                && core.effect == Effect::NotStarted && core.journal == Journal::NotCreated && core.resources == ResourceState::Settled
                && core.reason == CoreReason::StaleRevision && terminal.native_reason == Reason::None && snapshot(&root)? == before, Failure::UnexpectedOutcome)?;
            original.batch.cases.push(terminal_data(case.name(),&session,&terminal,json!({"registeredIdentityRetained":true,
                "replacementRejectedBeforeCheckout":true,"replacementTreeUnchanged":true}),None)?);
            return Ok(());
        }
        let editing = observed_workflow(&original.batch.owner,&session.id,Phase::Editing,false).await?;
        let checkout = editing.checkout.as_ref().ok_or(Failure::UnexpectedOutcome)?;
        observed_roster(input,&before,checkout)?;
        if case == Case::Fresh {
            let config = original.batch.owner.status().map_err(|_| Failure::UnexpectedStatus)?;
            let workflow = original.batch.owner.workflow_status().map_err(|_| Failure::UnexpectedStatus)?;
            require(config.active.is_none() && config.capability.reason == EditAvailability::OtherEditActive
                && config.status_revision == workflow.status_revision
                && original.bridge.open_config_edit("main",project.id.clone()).is_err_and(|error| error.code == "busy"), Failure::UnexpectedStatus)?;
        }
        if case == Case::RegistryPrepare {
            let extra = input.inputs.root.join("registration-prepare-extra"); mkdir(&extra)?; original.register(&extra)?;
            require(original.bridge.prepare_workflow_edit(&original.document,"main",prepare_args(&session.id,&checkout.revision)).is_err(), Failure::UnexpectedStatus)?;
            let terminal = observed_workflow(&original.batch.owner,&session.id,Phase::Final,false).await?;
            settled_terminal(&original.batch.owner,&terminal)?; cancelled(&terminal,Reason::CallerLost)?;
            let facts = original_facts(&session)?;
            require((facts.request_frames,facts.response_frames) == (1,2) && session.fixture_schedule.sequence() == Some(0)
                && terminal.prepared.is_none() && snapshot(&root)? == before, Failure::UnexpectedOutcome)?;
            original.batch.cases.push(terminal_data(case.name(),&session,&terminal,json!({"newRegistrationPublishedUnderDocumentLock":true,
                "originalRegistrationRetained":true,"staleCommandNotSent":true,"treeUnchanged":true}),None)?);
            return Ok(());
        }
        if case == Case::Conflict {
            original.bridge.prepare_workflow_edit(&original.document,"main",prepare_args(&session.id,&checkout.revision)).map_err(|_| Failure::NativeCommandRejected)?;
            let terminal = observed_workflow(&original.batch.owner,&session.id,Phase::Final,false).await?;
            settled_terminal(&original.batch.owner,&terminal)?;
            let core = terminal.core_outcome.as_ref().ok_or(Failure::UnexpectedOutcome)?;
            let conflict = terminal.conflict.as_ref().ok_or(Failure::UnexpectedOutcome)?;
            let facts = original_facts(&session)?;
            require((facts.request_frames,facts.response_frames) == (2,2) && session.fixture_schedule.sequence() == Some(1)
                && terminal.prepared.is_none() && !terminal.apply_submitted && conflict.reason == "existing_workflow_differs"
                && conflict.conflicts.len() == 1 && conflict.conflicts[0].id == WORKFLOW_IDS[0]
                && conflict.matches_observed(&checkout.observed) && core.effect == Effect::NotStarted && core.journal == Journal::NotCreated
                && core.resources == ResourceState::Settled && core.reason == CoreReason::None && terminal.native_reason == Reason::None
                && snapshot(&root)? == before, Failure::UnexpectedOutcome)?;
            original.batch.cases.push(terminal_data(case.name(),&session,&terminal,json!({"noPlanToken":true,"oneDifferingNewline":true,
                "noPreparedFrame":true,"wholeBundleRefused":true,"treeUnchanged":true}),None)?);
            return Ok(());
        }
        let plan = prepare(original,&session.id,checkout).await?;
        let directories = verify_plan(input,&before,checkout,&plan)?;
        require(snapshot(&root)? == before, Failure::PayloadMismatch)?;
        if matches!(case,Case::RegistryApply | Case::DocumentLost) {
            if case == Case::RegistryApply {
                let extra = input.inputs.root.join("registration-apply-extra"); mkdir(&extra)?; original.register(&extra)?;
                require(original.bridge.apply_workflow_edit(&original.document,"main",&session.id,&plan.plan_token).is_err(), Failure::UnexpectedStatus)?;
            } else {
                original.document.lost();
                require(!original.document.navigation(true)
                    && original.bridge.apply_workflow_edit(&original.document,"main",&session.id,&plan.plan_token).is_err()
                    && original.bridge.open_workflow_edit(&original.document,"main",project.id.clone()).is_err(), Failure::UnexpectedStatus)?;
            }
            let terminal = observed_workflow(&original.batch.owner,&session.id,Phase::Final,false).await?;
            settled_terminal(&original.batch.owner,&terminal)?;
            cancelled(&terminal,if case == Case::RegistryApply { Reason::CallerLost } else { Reason::WindowLost })?;
            let facts = original_facts(&session)?;
            require((facts.request_frames,facts.response_frames) == (2,3) && session.fixture_schedule.sequence() == Some(1)
                && terminal.prepared.as_ref().is_some_and(|p| p.plan_token == plan.plan_token && p.revision == checkout.revision)
                && snapshot(&root)? == before, Failure::UnexpectedOutcome)?;
            let observations = if case == Case::RegistryApply { json!({"newRegistrationPublishedUnderDocumentLock":true,
                "originalRegistrationRetained":true,"staleCommandNotSent":true,"treeUnchanged":true}) }
                else { json!({"controlledOriginalDocumentLoss":true,"originalStopRequested":true,"replacementDocumentRefused":true,
                    "preparedCorrelationRetained":true,"treeUnchanged":true,"guiCallbacksNotClaimed":true}) };
            original.batch.cases.push(terminal_data(case.name(),&session,&terminal,observations,None)?);
            return Ok(());
        }
        let reply = original.bridge.apply_workflow_edit(&original.document,"main",&session.id,&plan.plan_token).map_err(|_| Failure::NativeCommandRejected)?;
        require(select(&reply,&session.id)?.apply_submitted, Failure::UnexpectedStatus)?;
        if case == Case::Fresh {
            let duplicate = original.bridge.apply_workflow_edit(&original.document,"main",&session.id,&plan.plan_token).map_err(|_| Failure::NativeCommandRejected)?;
            require(select(&duplicate,&session.id)?.apply_submitted, Failure::UnexpectedStatus)?;
        }
        let terminal = observed_workflow(&original.batch.owner,&session.id,Phase::Final,false).await?;
        settled_terminal(&original.batch.owner,&terminal)?;
        let facts = original_facts(&session)?;
        let core = terminal.core_outcome.as_ref().ok_or(Failure::UnexpectedOutcome)?;
        let preserve = case.mask().into_iter().filter(|value| *value).count();
        require((facts.request_frames,facts.response_frames) == (3,3) && session.fixture_schedule.sequence() == Some(2)
            && terminal.apply_submitted && terminal.native_reason == Reason::None && core.resources == ResourceState::Settled
            && core.reason == CoreReason::None && core.effect == if preserve == 4 { Effect::Unchanged } else { Effect::Committed }
            && core.journal == if preserve == 4 { Journal::NotCreated } else { Journal::Clean }
            && terminal.prepared.as_ref().is_some_and(|p| p.plan_token == plan.plan_token && p.revision == checkout.revision
                && p.draft_revision == 1 && p.baseline_generation == 0), Failure::UnexpectedOutcome)?;
        installed(input,&root,&before,&directories)?;
        let config = original.batch.owner.status().map_err(|_| Failure::UnexpectedStatus)?;
        let workflow = original.batch.owner.workflow_status().map_err(|_| Failure::UnexpectedStatus)?;
        require(config.last_terminal.is_none() && config.status_revision == workflow.status_revision, Failure::UnexpectedStatus)?;
        original.batch.cases.push(terminal_data(case.name(),&session,&terminal,json!({"created":4-preserve,"preserved":preserve,
            "directoriesCreated":directories,"canonicalPayloads":true,"templateIdentity":true,"completePreparedBytes":true,
            "capturePrepareUnchanged":true,"protectedPreserved":true,"existingIdentityPreserved":true,
            "createModesMasked":true,"directoryModesExact":true,"duplicateApplyObservation":case==Case::Fresh,
            "oppositeDomainRefused":case==Case::Fresh,"sharedStatusRevision":true}),None)?);
        Ok(())
    }

    fn introduce_sibling(root: &Path) -> Check<OriginalFile> {
        // The only parent-side mutation while the original child waits at its
        // known pre-COMMITTED barrier. Retain this creating descriptor's facts;
        // never inspect journal slots or install a second EOF reader.
        FIXTURE_FILES.admit()?;
        let path = root.join(".github/workflows/unrelated.txt");
        let mut file = fs::OpenOptions::new().create_new(true).write(true).mode(0o600).custom_flags(nix::libc::O_NOFOLLOW)
            .open(path).map_err(|_| Failure::FixtureIo)?;
        FIXTURE_FILES.acquired();
        let wrote = file.write_all(UNRELATED); let metadata = file.metadata();
        FIXTURE_FILES.close_original(file)?;
        require(wrote.is_ok(), Failure::FixtureIo)?;
        let metadata = metadata.map_err(|_| Failure::FixtureIo)?;
        require(metadata.is_file() && metadata.len() == UNRELATED.len() as u64 && metadata.mode() & 0o7777 == 0o600, Failure::FixtureIo)?;
        Ok(OriginalFile { identity:Identity::of(&metadata),bytes:UNRELATED.to_vec() })
    }
    async fn exercise_eof(original: &mut Original, input: &Admitted, case: EofCase) -> Check<()> {
        require(input.eof && input.mode == Mode::Source && EOF_CASES.contains(&case)
            && original.settled() && !original.batch.owner.disabled(), Failure::OriginalCustodyUnknown)?;
        let root = input.inputs.root.join(case.name()); mkdir(&root)?; mkdir(&root.join("release"))?;
        write_new(&root.join("release/mobile-release.json"),PROTECTED_CONFIG,0o640)?;
        write_new(&root.join(".gitignore"),PROTECTED_IGNORE,0o600)?; write_new(&root.join("unrelated.txt"),UNRELATED,0o600)?;
        let before = snapshot(&root)?;
        let project = original.register(&root)?;
        let schedule = Arc::new(Schedule { eof:Some(case), ..Schedule::default() });
        {
            let mut next = original.batch.owner.inner.fixture_next_schedule.lock().map_err(|_| Failure::OriginalCustodyUnknown)?;
            require(next.is_none(), Failure::UnexpectedStatus)?; *next = Some(schedule.clone());
        }
        let mut guard = GateGuard::new(&original.batch.owner,schedule.clone());
        let session = original.open(&project)?;
        require(Arc::ptr_eq(&session.fixture_schedule,&schedule), Failure::OriginalCustodyUnknown)?;
        let editing = observed_workflow(&original.batch.owner,&session.id,Phase::Editing,false).await?;
        let checkout = editing.checkout.as_ref().ok_or(Failure::UnexpectedOutcome)?;
        observed_roster(input,&before,checkout)?;
        let plan = prepare(original,&session.id,checkout).await?;
        let directories = verify_plan(input,&before,checkout,&plan)?;
        require(directories == [".github", ".github/workflows"] && snapshot(&root)? == before, Failure::PayloadMismatch)?;
        let reply = original.bridge.apply_workflow_edit(&original.document,"main",&session.id,&plan.plan_token).map_err(|_| Failure::NativeCommandRejected)?;
        require(select(&reply,&session.id)?.apply_submitted, Failure::UnexpectedStatus)?;
        let (active,cleanup) = original_clock(&original.batch,&session)?;
        let endpoint = active.ok_or(Failure::UnexpectedStatus)?;
        require(cleanup.is_none(), Failure::UnexpectedStatus)?;
        until(OBSERVATION, || {
            require(!original.batch.owner.disabled() && !schedule.failed.load(Ordering::SeqCst), Failure::OriginalCustodyUnknown)?;
            Ok(schedule.eof_control.lock().map_err(|_| Failure::OriginalCustodyUnknown)?.boundary_only(case))
        }).await?;
        let introduced = if case == EofCase::WorkflowConflict { Some(introduce_sibling(&root)?) } else { None };
        require(Instant::now() < endpoint && !*session.stop.borrow(), Failure::UnexpectedStatus)?;
        let closing = original.batch.owner.close_workflow("main",&session.id).map_err(|_| Failure::NativeCommandRejected)?;
        let closing = select(&closing,&session.id)?;
        require(closing.phase == Phase::Finalizing && closing.native_reason == Reason::Cancelled && closing.apply_submitted, Failure::UnexpectedStatus)?;
        guard.release();
        let unknown = case == EofCase::WorkflowConflict;
        let committed = case == EofCase::WorkflowPostcommit;
        let terminal = observed_workflow(&original.batch.owner,&session.id,if unknown { Phase::Unknown } else { Phase::Final },unknown).await?;
        let facts = original_eof_facts(&session,case)?;
        let core = terminal.core_outcome.as_ref().ok_or(Failure::UnexpectedOutcome)?;
        require(original.settled() && (facts.request_frames,facts.response_frames) == (3,3) && schedule.sequence() == Some(2)
            && terminal.apply_submitted && terminal.native_reason == Reason::Cancelled
            && core.effect == if unknown { Effect::Unknown } else if committed { Effect::Committed } else { Effect::RolledBack }
            && core.journal == if unknown { Journal::RecoveryRequired } else { Journal::Clean }
            && core.resources == ResourceState::Settled && core.reason == CoreReason::Cancelled
            && terminal.prepared.as_ref().is_some_and(|p| p.plan_token == plan.plan_token && p.revision == checkout.revision
                && p.draft_revision == 1 && p.baseline_generation == 0)
            && terminal.checkout.as_ref().is_some_and(|p| p.revision == checkout.revision && p.observed == checkout.observed)
            && schedule.eof_control.lock().is_ok_and(|control| control.complete(case) && control.records(case) == 2)
            && schedule.released(), Failure::UnexpectedOutcome)?;
        if unknown {
            // Intentional effect Unknown is NOT normal native finality. Only
            // the unchanged original wait/EOF/close/join proof above permits
            // these fixed read-only synthetic observations and receipt return.
            require(original.batch.owner.disabled() && terminal.phase == Phase::Unknown && terminal.native_finality == NativeFinality::Unknown
                && terminal.late_settled && original.batch.owner.inner.lock().blocked_projects.contains(&project.id), Failure::UnexpectedOutcome)?;
            let config = original.batch.owner.status().map_err(|_| Failure::UnexpectedStatus)?;
            let workflow = original.batch.owner.workflow_status().map_err(|_| Failure::UnexpectedStatus)?;
            require(config.active.is_none() && workflow.active.is_none() && config.capability.reason == EditAvailability::CleanupUnknown
                && workflow.capability.reason == EditAvailability::CleanupUnknown && config.status_revision == workflow.status_revision,
                Failure::UnexpectedStatus)?;
            require(introduced.as_ref() == Some(&read_regular(&root.join(".github/workflows/unrelated.txt"),1024)?), Failure::PayloadMismatch)?;
            for index in 0..4 {
                require(read_regular(&root.join(".github/workflows").join(NAMES[index]),16*1024)?.bytes == input.payloads[index], Failure::PayloadMismatch)?;
            }
            require(fs::symlink_metadata(root.join(".mobile-release-init")).is_ok_and(|metadata| metadata.is_dir()), Failure::PayloadMismatch)?;
            for (path,file) in &before.files { require(read_regular(&root.join(path),1024*1024)? == *file, Failure::PayloadMismatch)?; }
        } else {
            settled_terminal(&original.batch.owner,&terminal)?;
            if committed { installed(input,&root,&before,&directories)?; }
            else { require(snapshot(&root)? == before, Failure::PayloadMismatch)?; }
        }
        let observations = json!({"evidenceKind":"real-stdin-eof-at-controlled-transaction-boundary",
            "bootstrapMode":"instrumented-genuine-engine","boundary":case.boundary(),"originalCheckpoint":case.checkpoint(),
            "closeBeforeActiveDeadline":true,"controlRecords":2,"actualStdinEof":true,"eofReadCount":1,"nonemptyReadCount":0,"readErrorCount":0,
            "preparedCorrelation":true,"committedPublication":committed,"rolledBackPublication":!committed&&!unknown,
            "terminalDurable":!unknown,"fixedRecovery":true,"journalClean":!unknown,"journalAbsent":!unknown,
            "originalTreeRestored":!committed&&!unknown,"canonicalPayloadsRemain":committed||unknown,"protectedPreserved":true,
            "unrelatedIntroducedBeforeEof":unknown,"introducedOriginalPreserved":unknown,"recoveryEvidenceRetained":unknown,
            "sharedBlockedProject":unknown,"bothDomainsDisabled":unknown,"noFurtherAdmission":unknown,
            "fixtureFilesSettled":FIXTURE_FILES.all_settled()});
        original.batch.cases.push(terminal_data(case.name(),&session,&terminal,observations,Some(case))?);
        Ok(())
    }
    fn receipt(input: &Admitted, cases: &[Value], passed: bool, resources: bool, owner_disabled: bool, failure: Option<Failure>) -> Check<()> {
        let complete = if input.eof { EOF_CASES.len() } else if input.mode == Mode::Source { SOURCE_CASES.len() } else { 1 };
        require(!passed || resources && cases.len() == complete && failure.is_none() && owner_disabled == input.eof, Failure::ReceiptIo)?;
        receipt_document(&input.inputs,json!({"schemaVersion":1,"scope":if input.eof { TRANSACTION_SCOPE } else { OWNER_SCOPE },"domain":DOMAIN,
            "status":if passed { "passed" } else { "failed" },"allOwnersSettled":resources&&!owner_disabled,
            "originalResourcesSettled":resources,"ownerDisabled":owner_disabled,"retainedEffectUnknown":passed&&input.eof,
            "failureCode":failure,"bindings":input.inputs.bindings,"cases":cases,"notVerified":WORKFLOW_NOT_VERIFIED}))
    }
    pub(super) async fn run(eof: bool) {
        if BATCH_CLAIMED.swap(true,Ordering::SeqCst) {
            if !FIXTURE_FILES.all_settled() || !probes_settled() { retain_unknown_runtime().await; return; }
            panic!("hosted workflow batch already claimed");
        }
        let input = match Admitted::admit(eof) {
            Ok(input) => input,
            Err(code) => { if !FIXTURE_FILES.all_settled() { retain_unknown_runtime().await; return; }
                panic!("hosted workflow admission refused: {code:?}"); },
        };
        if receipt(&input,&[],false,false,false,Some(Failure::NotCompleted)).is_err() {
            if !FIXTURE_FILES.all_settled() { retain_unknown_runtime().await; return; }
            panic!("hosted workflow partial receipt unavailable before native work");
        }
        let mut original = match Original::new(&input) {
            Ok(original) => original,
            Err(code) => { if !FIXTURE_FILES.all_settled() || !probes_settled() { retain_unknown_runtime().await; return; }
                panic!("hosted workflow original document refused before native work: {code:?}"); },
        };
        let count = if eof { EOF_CASES.len() } else if input.mode == Mode::Source { SOURCE_CASES.len() } else { 1 };
        for ordinal in 0..count {
            let result = if eof { exercise_eof(&mut original,&input,EOF_CASES[ordinal]).await }
                else { exercise_owner(&mut original,&input,SOURCE_CASES[ordinal]).await };
            let expected_unknown = eof && ordinal == EOF_CASES.len()-1 && result.is_ok();
            if result.is_err() || !original.settled() || original.batch.owner.disabled() && !expected_unknown { original.stop().await; }
            let settled = original.settled();
            if !settled || original.batch.owner.disabled() && !expected_unknown
                || matches!(result,Err(Failure::OriginalCustodyUnknown|Failure::FixtureCustodyUnknown)) {
                if FIXTURE_FILES.all_settled() && probes_settled() {
                    let _ = receipt(&input,&original.batch.cases,false,false,original.batch.owner.disabled(),Some(Failure::OriginalCustodyUnknown));
                }
                retain_unknown_runtime().await; return;
            }
            if let Err(code) = result {
                let _ = receipt(&input,&original.batch.cases,false,true,original.batch.owner.disabled(),Some(code));
                if !FIXTURE_FILES.all_settled() { retain_unknown_runtime().await; return; }
                panic!("hosted workflow case failed after original resource settlement: {code:?}");
            }
            if !expected_unknown && receipt(&input,&original.batch.cases,false,false,false,Some(Failure::NotCompleted)).is_err() {
                if !FIXTURE_FILES.all_settled() { retain_unknown_runtime().await; return; }
                panic!("hosted workflow progress receipt failed after original settlement");
            }
        }
        // No shutdown, reopen, recovery or next native owner after the expected
        // effect-Unknown case. Its disabled original owner remains retained.
        if !eof && original.batch.owner.shutdown().await.is_err() || !original.settled() {
            retain_unknown_runtime().await; return;
        }
        if receipt(&input,&original.batch.cases,true,true,original.batch.owner.disabled(),None).is_err() {
            if !FIXTURE_FILES.all_settled() { retain_unknown_runtime().await; return; }
            panic!("hosted workflow final receipt failed after original settlement");
        }
    }

    #[test]
    fn workflow_fixture_permit_roster_rejects_cross_domain_or_bootstrap_reuse() {
        // Pure DATA checks only, with no runtime/owner/IO/nonce admission.
        assert!(!qualified(EditDomain::GitHubWorkflows,false)); assert!(!qualified(EditDomain::GitHubWorkflows,true));
        assert_eq!(SOURCE_CASES.last().map(|case| case.name()),Some("document-loss"));
        assert_eq!(EOF_CASES.last().map(|case| case.name()),Some("precommit-conflict-eof"));
        assert!(WorkflowFixturePermit::bootstrap_case(false,Path::new("/inert/create-fresh"),None));
        assert!(!WorkflowFixturePermit::bootstrap_case(true,Path::new("/inert/create-fresh"),None));
        for case in EOF_CASES {
            let root = Path::new("/inert").join(case.name());
            assert!(WorkflowFixturePermit::bootstrap_case(true,&root,Some(case)));
            assert!(!WorkflowFixturePermit::bootstrap_case(false,&root,Some(case)));
            assert!(!WorkflowFixturePermit::bootstrap_case(true,Path::new("/inert/wrong-case"),Some(case)));
        }
        for case in [EofCase::Precommit,EofCase::Postcommit] {
            assert!(!WorkflowFixturePermit::bootstrap_case(true,&Path::new("/inert").join(case.name()),Some(case)));
        }
        assert!(source_entry("mobile_release/api/data/github-setup-v1.json"));
        for invalid in ["../mobile_release/a.py","mobile_release/../a.py","mobile_release//a.py","mobile_release/a.pyc","/mobile_release/a.py"] {
            assert!(!source_entry(invalid));
        }
    }
}

#[cfg(all(debug_assertions, not(feature = "desktop-shell"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "only the reviewed disposable source-or-ZIP Linux workflow-owner process"]
async fn hosted_workflow_edit_owner_original_resources() { workflow::run(false).await; }

#[cfg(all(debug_assertions, not(feature = "desktop-shell"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "only the reviewed disposable Linux workflow transaction EOF process"]
async fn hosted_workflow_transaction_eof_original_resources() { workflow::run(true).await; }

#[test]
fn workflow_eof_records_are_domain_distinct_and_exact() {
    // Same original streaming decoder, inert bytes only; no new reader/owner.
    for case in [EofCase::WorkflowPrecommit,EofCase::WorkflowPostcommit,EofCase::WorkflowConflict] {
        assert!(case.domain() == EditDomain::GitHubWorkflows);
        let bytes = [case.marker(),case.summary()].concat();
        for width in 1..=bytes.len()+1 {
            let mut control = EofControl::default();
            for chunk in bytes.chunks(width) { assert!(control.observe(case,chunk)); }
            assert!(control.complete(case)); assert_eq!(control.records(case),2);
            assert!(!control.observe(case,b"\n"));
        }
        for other in [EofCase::Precommit,EofCase::Postcommit,EofCase::WorkflowPrecommit,EofCase::WorkflowPostcommit,EofCase::WorkflowConflict] {
            if case == other { continue; }
            let mut control = EofControl::default(); assert!(!control.observe(case,other.marker()));
        }
        for end in 0..bytes.len() {
            let mut control = EofControl::default(); assert!(control.observe(case,&bytes[..end])); assert!(!control.complete(case));
        }
        for index in 0..bytes.len() {
            let mut changed = bytes.clone(); changed[index] = b'!';
            let mut control = EofControl::default(); assert!(!control.observe(case,&changed));
        }
    }
}

// One finite metadata branch of the existing hosted original-owner fixture.
// Its payloads are literal synthetic DATA, not output of the product renderer.
#[cfg(all(debug_assertions, not(feature = "desktop-shell"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
mod metadata {
    // Deliberately retain the original seven-rule prerequisite in this domain.
    const IGNORE: &[u8] = b".mobile-release/\n.mobile-release-init-prepare/\n.mobile-release-init/\n.mobile-release-init-cleanup/\n.mobile-release-metadata-text-prepare/\n.mobile-release-metadata-text/\n.mobile-release-metadata-text-cleanup/\n";
    use super::*;
    use crate::{asset_session::DocumentBinding, asset_source::{self, SourceBook}, bridge::{DesktopBridge, Project},
        metadata_text_commands, metadata_text_edit_protocol::Platform, protocol::Method,
        supervisor::metadata_fixture_probe::Probe};

    const OWNER_SCOPE: &str = "metadata-text-owner-hosted-v1";
    const TRANSACTION_SCOPE: &str = "metadata-text-transaction-eof-hosted-v1";
    const DOMAIN: &str = "metadata_text";
    const REFERENCE: &str = "refs/heads/verify/desktop-metadata-text-apply-native";
    const WORKFLOW_PATH: &str = ".github/workflows/desktop-github-workflow-apply-native.yml";
    const WORKFLOW_SOURCE: &[u8] = include_bytes!("../../../.github/workflows/desktop-github-workflow-apply-native.yml");
    const RESOURCE: &[u8] = include_bytes!("../../../src/mobile_release/api/data/metadata-text-help-v1.json");
    const SCHEMA: &[u8] = include_bytes!("../../../src/mobile_release/api/data/project.schema.json");
    const UMASK_PROBE: &[u8] = b"fixed metadata fixture umask\n";
    const SENSITIVE: &[u8] = b"password=fixed-synthetic-not-a-credential\n";
    const NONUTF8: &[u8] = b"fixed public notes \xff\n";
    const CONFIG_PUBLIC: &[u8] = concat!(r#"{"android":{"applicationId":"org.fixture.app","enabled":true,"identityStatus":"unverified"},"ios":{"bundleId":"org.fixture.app","enabled":true,"identityStatus":"unverified"},"metadata":{"androidLocales":["en-US","fr-FR"],"iosLocales":["en-US"],"root":"public/store"},"projectChecks":{"androidArtifact":[],"iosArtifact":[],"preflight":[]},"schemaVersion":1,"services":{"androidFirebase":"disabled","iosFirebase":"disabled"},"source":{"candidateBranch":"main","productionBranch":"production"},"version":{"buildKey":"BUILD_NUMBER","nameKey":"VERSION_NAME","source":"release/version.properties"}}"#, "\n").as_bytes();
    const CONFIG_RELEASE: &[u8] = concat!(r#"{"android":{"applicationId":"org.fixture.app","enabled":true,"identityStatus":"unverified"},"ios":{"bundleId":"org.fixture.app","enabled":true,"identityStatus":"unverified"},"metadata":{"androidLocales":["en-US","fr-FR"],"iosLocales":["en-US"],"root":"release/store"},"projectChecks":{"androidArtifact":[],"iosArtifact":[],"preflight":[]},"schemaVersion":1,"services":{"androidFirebase":"disabled","iosFirebase":"disabled"},"source":{"candidateBranch":"main","productionBranch":"production"},"version":{"buildKey":"BUILD_NUMBER","nameKey":"VERSION_NAME","source":"release/version.properties"}}"#, "\n").as_bytes();
    const ANDROID_NAMES: [&str;3] = ["title.txt","short_description.txt","full_description.txt"];
    const IOS_NAMES: [&str;5] = ["description.txt","keywords.txt","privacy_url.txt","support_url.txt","release_notes.txt"];
    const ANDROID_TEXT: [&str;3] = ["Fixture public title\n","A fixed public description.\r\n","Public release details: café.\nSecond line.\n"];
    const IOS_TEXT: [&str;5] = ["Public iOS description: café.\r\nSecond line.\r\n","public,fixture,release","https://public.invalid/privacy",
        "https://public.invalid/support","  Public release notes.\nNo private content.\n"];
    const OLD_ANDROID_TITLE: &str = "Previous public title\n";
    const OLD_ANDROID_SHORT: &str = "Previous public description.\n";
    const OLD_IOS_DESCRIPTION: &str = "Previous public iOS description.\n";
    const OLD_IOS_KEYWORDS: &str = "previous,public";
    const NOT_VERIFIED: &[&str] = &["production-runtime-custody","production-metadata-save-enablement","native-gui",
        "webview-callbacks-or-crash-hook","parent-death","native-stuck-wait-close","persisted-recovery",
        "macos-windows-metadata-writes","credentials","remote-github","stores","mobile-builds","installers"];
    const EXTRA_SOURCES: &[Source] = &[
        Source { id:"metadataProtocol", relative:"desktop/src-tauri/src/metadata_text_edit_protocol.rs", compiled:include_bytes!("metadata_text_edit_protocol.rs") },
        Source { id:"metadataCommands", relative:"desktop/src-tauri/src/metadata_text_commands.rs", compiled:include_bytes!("metadata_text_commands.rs") },
        Source { id:"workflowProtocol", relative:"desktop/src-tauri/src/github_workflow_edit_protocol.rs", compiled:include_bytes!("github_workflow_edit_protocol.rs") },
        Source { id:"bridge", relative:"desktop/src-tauri/src/bridge.rs", compiled:include_bytes!("bridge.rs") },
        Source { id:"documentBinding", relative:"desktop/src-tauri/src/asset_session.rs", compiled:include_bytes!("asset_session.rs") },
        Source { id:"documentLifetime", relative:"desktop/src-tauri/src/document_lifetime.rs", compiled:include_bytes!("document_lifetime.rs") },
        Source { id:"assetSource", relative:"desktop/src-tauri/src/asset_source.rs", compiled:include_bytes!("asset_source.rs") },
        Source { id:"assetCommands", relative:"desktop/src-tauri/src/asset_commands.rs", compiled:include_bytes!("asset_commands.rs") },
        Source { id:"supervisor", relative:"desktop/src-tauri/src/supervisor.rs", compiled:include_bytes!("supervisor.rs") },
        Source { id:"passiveFixture", relative:"desktop/src-tauri/src/hosted_tests.rs", compiled:include_bytes!("hosted_tests.rs") },
        Source { id:"editCommands", relative:"desktop/src-tauri/src/edit_commands.rs", compiled:include_bytes!("edit_commands.rs") },
        Source { id:"githubCommands", relative:"desktop/src-tauri/src/github_commands.rs", compiled:include_bytes!("github_commands.rs") },
        Source { id:"workflowEdit", relative:"src/mobile_release/github_workflow_edit.py", compiled:include_bytes!("../../../src/mobile_release/github_workflow_edit.py") },
        Source { id:"metadataEdit", relative:"src/mobile_release/metadata_text_edit.py", compiled:include_bytes!("../../../src/mobile_release/metadata_text_edit.py") },
        Source { id:"metadataText", relative:"src/mobile_release/metadata_text.py", compiled:include_bytes!("../../../src/mobile_release/metadata_text.py") },
        Source { id:"metadataPolicy", relative:"src/mobile_release/metadata.py", compiled:include_bytes!("../../../src/mobile_release/metadata.py") },
        Source { id:"metadataApi", relative:"src/mobile_release/api/_metadata_text.py", compiled:include_bytes!("../../../src/mobile_release/api/_metadata_text.py") },
        Source { id:"passiveEngine", relative:"src/mobile_release/_desktop_engine.py", compiled:include_bytes!("../../../src/mobile_release/_desktop_engine.py") },
        Source { id:"catalogue", relative:"src/mobile_release/api/_catalog.py", compiled:include_bytes!("../../../src/mobile_release/api/_catalog.py") },
        Source { id:"apiContracts", relative:"src/mobile_release/api/contracts.py", compiled:include_bytes!("../../../src/mobile_release/api/contracts.py") },
        Source { id:"snapshot", relative:"src/mobile_release/api/_snapshot.py", compiled:include_bytes!("../../../src/mobile_release/api/_snapshot.py") },
        Source { id:"metadataResource", relative:"src/mobile_release/api/data/metadata-text-help-v1.json", compiled:RESOURCE },
        Source { id:"schemaResource", relative:"src/mobile_release/api/data/project.schema.json", compiled:SCHEMA },
        // Transitive shared SOURCE only; this fixture still grants no version-write permit.
        Source { id:"versionProtocol", relative:"desktop/src-tauri/src/release_version_edit_protocol.rs", compiled:include_bytes!("release_version_edit_protocol.rs") },
        Source { id:"versionCommands", relative:"desktop/src-tauri/src/release_version_edit_commands.rs", compiled:include_bytes!("release_version_edit_commands.rs") },
        Source { id:"versionEdit", relative:"src/mobile_release/release_version_edit.py", compiled:include_bytes!("../../../src/mobile_release/release_version_edit.py") },
        Source { id:"versionText", relative:"src/mobile_release/version_text.py", compiled:include_bytes!("../../../src/mobile_release/version_text.py") },
        Source { id:"versionResource", relative:"src/mobile_release/api/data/release-version-help-v1.json", compiled:include_bytes!("../../../src/mobile_release/api/data/release-version-help-v1.json") },
    ];
    static PROBES: Mutex<Vec<SourceBook>> = Mutex::new(Vec::new());
    fn probes_settled() -> bool { PROBES.lock().is_ok_and(|books| books.iter().all(SourceBook::settled)) }

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Mode { Source, Zip }
    impl Mode { fn name(self) -> &'static str { if self == Self::Source { "source" } else { "zip" } } }
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Case { AndroidCreate, IosCreate, AndroidNoop, IosNoop, AndroidReplace, IosMixed, NoIgnore,
        Sensitive, Nonutf8, Stale, Isolation, Registration, HeldTerminal, DocumentLost }
    impl Case {
        fn name(self) -> &'static str {
            match self {
                Self::AndroidCreate => "android-observe-create", Self::IosCreate => "ios-observe-create",
                Self::AndroidNoop => "android-observe-noop", Self::IosNoop => "ios-observe-noop",
                Self::AndroidReplace => "android-observe-replace-preserve", Self::IosMixed => "ios-observe-mixed-create-replace-preserve",
                Self::NoIgnore => "observe-without-ignore-save-refused", Self::Sensitive => "observe-last-sensitive-refused",
                Self::Nonutf8 => "observe-last-nonutf8-refused", Self::Stale => "stale-passive-baseline-refused",
                Self::Isolation => "three-domain-owner-isolation", Self::Registration => "registration-changed-before-apply",
                Self::HeldTerminal => "metadata-terminal-held-after-stop", Self::DocumentLost => "metadata-document-loss-before-apply",
            }
        }
        fn selection(self) -> Selection {
            Selection { platform:if matches!(self,Self::IosCreate|Self::IosNoop|Self::IosMixed|Self::Nonutf8) { Platform::Ios } else { Platform::Android },
                locale:if self == Self::AndroidReplace { "fr-FR" } else { "en-US" },
                metadata_root:if self == Self::IosCreate { "release/store" } else { "public/store" } }
        }
        fn fresh(self) -> bool { matches!(self,Self::AndroidCreate|Self::IosCreate|Self::NoIgnore|Self::Isolation|Self::Registration|Self::HeldTerminal|Self::DocumentLost) }
    }
    const SOURCE_CASES: [Case;14] = [Case::AndroidCreate,Case::IosCreate,Case::AndroidNoop,Case::IosNoop,Case::AndroidReplace,
        Case::IosMixed,Case::NoIgnore,Case::Sensitive,Case::Nonutf8,Case::Stale,Case::Isolation,Case::Registration,Case::HeldTerminal,Case::DocumentLost];
    const EOF_CASES: [EofCase;3] = [EofCase::MetadataPrecommit,EofCase::MetadataPostcommit,EofCase::MetadataConflict];
    #[derive(Clone, Copy)]
    struct Selection { platform:Platform, locale:&'static str, metadata_root:&'static str }
    impl Selection {
        fn platform_name(self) -> &'static str { if self.platform == Platform::Android { "android" } else { "ios" } }
        fn names(self) -> &'static [&'static str] { if self.platform == Platform::Android { &ANDROID_NAMES } else { &IOS_NAMES } }
        fn texts(self) -> &'static [&'static str] { if self.platform == Platform::Android { &ANDROID_TEXT } else { &IOS_TEXT } }
        fn config(self) -> &'static [u8] { if self.metadata_root == "release/store" { CONFIG_RELEASE } else { CONFIG_PUBLIC } }
        fn parent(self) -> String { format!("{}/{}/{}",self.metadata_root,self.platform_name(),self.locale) }
        fn path(self,index:usize) -> String { format!("{}/{}",self.parent(),self.names()[index]) }
        fn fields(self) -> Vec<metadata_wire::TextField> {
            self.platform.ids().iter().zip(self.texts()).map(|(id,text)| metadata_wire::TextField { id:*id,text:(*text).into() }).collect()
        }
        fn open(self,project:&Project) -> metadata_text_commands::Open {
            metadata_text_commands::Open { project_id:project.id.clone(),platform:self.platform,locale:self.locale.into() }
        }
    }
    fn eof_selection(case:EofCase) -> Selection {
        if case == EofCase::MetadataPostcommit { Selection { platform:Platform::Ios,locale:"en-US",metadata_root:"release/store" } }
        else { Selection { platform:Platform::Android,locale:"en-US",metadata_root:"public/store" } }
    }
    fn hash_fields(platform:Platform,previous:bool) -> Value {
        if previous {
            if platform == Platform::Android { json!({"title.txt":hash(OLD_ANDROID_TITLE.as_bytes()),"short_description.txt":hash(OLD_ANDROID_SHORT.as_bytes())}) }
            else { json!({"description.txt":hash(OLD_IOS_DESCRIPTION.as_bytes()),"keywords.txt":hash(OLD_IOS_KEYWORDS.as_bytes())}) }
        } else {
            let selection = Selection { platform,locale:"en-US",metadata_root:"public/store" };
            let fields: serde_json::Map<String,Value> = selection.names().iter().zip(selection.texts()).map(|(id,text)| ((*id).into(),json!(hash(text.as_bytes())))).collect();
            Value::Object(fields)
        }
    }
    fn payload_bindings() -> Value {
        json!({"configHashes":{"publicStore":hash(CONFIG_PUBLIC),"releaseStore":hash(CONFIG_RELEASE)},"ignoreSha256":hash(IGNORE),
            "fieldHashes":{"android":hash_fields(Platform::Android,false),"ios":hash_fields(Platform::Ios,false)},
            "previousFieldHashes":{"android":hash_fields(Platform::Android,true),"ios":hash_fields(Platform::Ios,true)},
            "unrelatedSha256":hash(UNRELATED),"umaskProbeSha256":hash(UMASK_PROBE),"sensitiveSha256":hash(SENSITIVE),"nonutf8Sha256":hash(NONUTF8)})
    }
    struct Admitted { inputs:Inputs,mode:Mode,eof:bool,python:PathBuf,core:PathBuf,repository:PathBuf,
        selections:Vec<(PathBuf,Platform,String)> }
    fn source_entry(path:&str) -> bool {
        path.starts_with("mobile_release/") && path.len() <= 256 && path.is_ascii()
            && path.split('/').all(|part| !part.is_empty() && part != "." && part != ".."
                && part.bytes().all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c)))
            && [".py",".json",".pem"].iter().any(|suffix| path.ends_with(suffix))
    }
    fn core_binding(repository:&Path,task:&Path,sha:&str) -> Check<Value> {
        require(canonical_input("MRK_DESKTOP_METADATA_TEXT_CORE_ZIP",true)? == task.join("core.zip")
            && canonical_input("MRK_DESKTOP_METADATA_TEXT_CORE_METADATA",true)? == task.join("metadata.json"), Failure::SourceBindingMismatch)?;
        let raw = read_regular(&task.join("metadata.json"),2*1024*1024)?;
        let value:Value = serde_json::from_slice(&raw.bytes).map_err(|_| Failure::SourceBindingMismatch)?;
        let run = environment("GITHUB_RUN_ID")?;
        let attempt = environment("GITHUB_RUN_ATTEMPT")?;
        let github_repository = environment("GITHUB_REPOSITORY")?;
        require(value.as_object().is_some_and(|fields| fields.len() == 8) && value["sourceSha"].as_str() == Some(sha)
            && value["sourceTree"].as_str().is_some_and(|tree| tree.len() == 40 && tree != "0".repeat(40)
                && tree.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)))
            && !run.is_empty() && run.len() <= 20 && !run.starts_with('0') && run.bytes().all(|c| c.is_ascii_digit())
            && attempt == "1" && environment("GITHUB_EVENT_NAME")? == "push" && environment("MRK_PUSH_EVENT_AFTER")? == sha
            && environment("GITHUB_REF")? == REFERENCE
            && environment("GITHUB_WORKFLOW_SHA")? == sha
            && environment("GITHUB_WORKFLOW_REF")? == format!("{github_repository}/{WORKFLOW_PATH}@{REFERENCE}")
            && value["runId"].as_str() == Some(run.as_str()) && value["attempt"].as_str() == Some(attempt.as_str())
            && value["ref"] == REFERENCE, Failure::SourceBindingMismatch)?;
        let workflow_hash = hash(WORKFLOW_SOURCE);
        require(hash(&read_regular(&repository.join(WORKFLOW_PATH),2*1024*1024)?.bytes) == workflow_hash
            && value["workflowSha256"].as_str() == Some(workflow_hash.as_str()), Failure::SourceBindingMismatch)?;
        let rows = value["coreFiles"].as_array().ok_or(Failure::SourceBindingMismatch)?;
        require(!rows.is_empty() && rows.len() <= 2048,Failure::SourceBindingMismatch)?;
        let mut previous = ""; let mut total = 0usize;
        for row in rows {
            let path = row["path"].as_str().ok_or(Failure::SourceBindingMismatch)?;
            require(row.as_object().is_some_and(|fields| fields.len() == 3) && source_entry(path) && path > previous,Failure::SourceBindingMismatch)?;
            let file = read_regular(&repository.join("src").join(path),8*1024*1024)?;
            total = total.checked_add(file.bytes.len()).ok_or(Failure::SourceBindingMismatch)?;
            require(total <= 32*1024*1024 && row["size"].as_u64() == Some(file.bytes.len() as u64)
                && row["sha256"].as_str() == Some(hash(&file.bytes).as_str()),Failure::SourceBindingMismatch)?;
            previous = path;
        }
        let zip_hash = hash(&read_regular(&task.join("core.zip"),32*1024*1024)?.bytes);
        require(value["coreZipSha256"].as_str() == Some(zip_hash.as_str()),Failure::SourceBindingMismatch)?;
        // The helper owns original Git/inventory/ZIP construction. This binds
        // its exact metadata and bytes; it does not parse/extract another ZIP.
        Ok(json!({"sourceTree":value["sourceTree"],"workflowSha256":workflow_hash,"runId":run,"attempt":attempt,"ref":REFERENCE,
            "coreZipSha256":zip_hash,"coreInventorySha256":hash(&serde_json::to_vec(rows).map_err(|_| Failure::SourceBindingMismatch)?)}))
    }
    impl Admitted {
        fn admit(eof:bool) -> Check<Self> {
            FIXTURE_FILES.admit()?;
            require(environment("MRK_DESKTOP_METADATA_TEXT_HOSTED_CHECKS")? == "metadata-text-v1"
                && environment("GITHUB_ACTIONS")? == "true" && environment("RUNNER_ENVIRONMENT")? == "github-hosted"
                && environment("RUNNER_OS")? == "Linux" && environment("RUNNER_ARCH")? == "X64"
                && crate::runtime::COMPILED_TARGET == "x86_64-unknown-linux-gnu"
                && rustix::process::getuid().as_raw() != 0 && rustix::process::getuid() == rustix::process::geteuid(),Failure::HostedGuardRefused)?;
            let mode = match environment("MRK_DESKTOP_METADATA_TEXT_INPUT")?.as_str() {
                "source" => Mode::Source,"zip" if !eof => Mode::Zip,_ => return Err(Failure::HostedGuardRefused),
            };
            let temporary = canonical_input("RUNNER_TEMP",false)?;
            let root = canonical_input("MRK_DESKTOP_EDIT_TEST_ROOT",true)?;
            let task = root.parent().ok_or(Failure::HostedGuardRefused)?;
            let manifest = Path::new(env!("CARGO_MANIFEST_DIR")).canonicalize().map_err(|_| Failure::HostedGuardRefused)?;
            let repository = manifest.parent().and_then(Path::parent).ok_or(Failure::HostedGuardRefused)?.to_path_buf();
            let name = if eof { "metadata-transaction-eof" } else if mode == Mode::Source { "metadata-owner-source" } else { "metadata-owner-zip" };
            require(root.file_name().and_then(|name| name.to_str()) == Some(name) && task != temporary && task.starts_with(&temporary)
                && std::env::current_dir().map_err(|_| Failure::HostedGuardRefused)? == manifest
                && !root.starts_with(&repository) && !repository.starts_with(&root),Failure::HostedGuardRefused)?;
            let stat = fs::symlink_metadata(&root).map_err(|_| Failure::HostedGuardRefused)?;
            require(stat.is_dir() && stat.mode() & 0o7777 == 0o700 && stat.uid() == rustix::process::geteuid().as_raw()
                && stat.gid() == rustix::process::getegid().as_raw()
                && fs::read_dir(&root).map_err(|_| Failure::HostedGuardRefused)?.next().is_none(),Failure::HostedGuardRefused)?;
            let python = canonical_input("MRK_DESKTOP_DEV_PYTHON",true)?;
            let core = canonical_input("MRK_DESKTOP_DEV_CORE",true)?;
            require(core == if mode == Mode::Source { repository.join("src") } else { task.join("core.zip") }
                && !python.starts_with(task) && !python.starts_with(&repository),Failure::HostedGuardRefused)?;
            let sha = environment("GITHUB_SHA")?;
            require(sha.len() == 40 && sha != "0".repeat(40) && sha.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
                && environment("MRK_DESKTOP_EDIT_SOURCE_SHA")? == sha && option_env!("GITHUB_SHA") == Some(sha.as_str()),Failure::SourceBindingMismatch)?;
            let mut sources = serde_json::Map::new();
            for item in SOURCES.iter().chain(EXTRA_SOURCES).chain(if eof { std::slice::from_ref(&EOF_SOURCE) } else { &[] }) {
                let expected = hash(item.compiled);
                require(hash(&read_regular(&repository.join(item.relative),2*1024*1024)?.bytes) == expected
                    && sources.insert(item.id.into(),json!(expected)).is_none(),Failure::SourceBindingMismatch)?;
            }
            let mut bindings = core_binding(&repository,task,&sha)?;
            bindings["sourceSha"] = json!(sha); bindings["domain"] = json!(DOMAIN); bindings["host"] = json!("linux");
            bindings["target"] = json!(crate::runtime::COMPILED_TARGET); bindings["runtimeMode"] = json!("trusted-development-only");
            bindings["runtimeInput"] = json!(mode.name()); bindings["pythonSha256"] = json!(hash(&read_regular(&python,64*1024*1024)?.bytes));
            bindings["sourceHashes"] = json!(sources); bindings["payloadHashes"] = payload_bindings();
            bindings["metadataResourceSha256"] = json!(hash(RESOURCE)); bindings["schemaResourceSha256"] = json!(hash(SCHEMA));
            bindings["inheritedFileMaskObserved"] = json!(true); bindings["requestedCreateMode"] = json!(420);
            bindings["observedCreateMode"] = json!(384); bindings["newDirectoryMode"] = json!(493);
            bindings["documentEvidence"] = json!("controlled-original-lifetime-not-gui-callbacks");
            let selections = if eof { EOF_CASES.iter().map(|case| { let s=eof_selection(*case); (root.join(case.name()),s.platform,s.locale.into()) }).collect() }
                else if mode == Mode::Zip { let s=Case::IosMixed.selection(); vec![(root.join(Case::IosMixed.name()),s.platform,s.locale.into())] }
                else { SOURCE_CASES.iter().map(|case| { let s=case.selection(); (root.join(case.name()),s.platform,s.locale.into()) })
                    .chain([(root.join("registration-apply-extra"),Platform::Android,"en-US".into())]).collect() };
            let mut probe = fs::OpenOptions::new().create_new(true).write(true).mode(0o644).open(root.join("umask-check")).map_err(|_| Failure::FixtureIo)?;
            FIXTURE_FILES.acquired(); let wrote=probe.write_all(UMASK_PROBE); FIXTURE_FILES.close_original(probe)?;
            require(wrote.is_ok(),Failure::FixtureIo)?;
            let observed=read_regular(&root.join("umask-check"),128)?;
            require(observed.bytes == UMASK_PROBE && observed.identity.mode & 0o7777 == 0o600,Failure::HostedGuardRefused)?;
            Ok(Self { inputs:Inputs { root,identity:Identity::of(&stat),bindings },mode,eof,python,core,repository,selections })
        }
        fn permit(&self,owner:&EditOwner) -> Check<()> {
            self.inputs.same_root()?;
            require(owner.can_exit() && !owner.disabled() && !owner.inner.hosted_qualified(EditDomain::MetadataText),Failure::HostedGuardRefused)?;
            let mut slot=owner.inner.fixture_metadata.lock().map_err(|_| Failure::OriginalCustodyUnknown)?;
            require(slot.is_none(),Failure::HostedGuardRefused)?;
            *slot=Some(Arc::new(MetadataFixturePermit { owner:Arc::downgrade(&owner.inner),selections:self.selections.clone(),
                python:self.python.clone(),core:self.core.clone(),bootstrap:self.repository.join("desktop/config_edit_bootstrap.py"),
                cwd:self.repository.join("desktop"),binding_sha256:hash(&serde_json::to_vec(&self.inputs.bindings).map_err(|_| Failure::SourceBindingMismatch)?),
                zip:self.mode==Mode::Zip,eof:self.eof }));
            Ok(())
        }
    }

    struct Original { batch:Batch,bridge:Arc<DesktopBridge>,document:DocumentBinding,passive:Arc<Probe>,queries:Vec<Value> }
    impl Original {
        fn new(input:&Admitted) -> Check<Self> {
            let bridge=Arc::new(DesktopBridge::new(input.inputs.root.clone()));
            let owner=bridge.edits.clone();
            let passive=Arc::new(Probe::attach(&bridge.supervisor).map_err(|_| Failure::OriginalCustodyUnknown)?);
            {
                let mut retained=RETAINED.lock().map_err(|_| Failure::OriginalCustodyUnknown)?;
                require(retained.is_none(),Failure::OriginalCustodyUnknown)?;
                let mut retention=Retention::new(&owner);
                retention.metadata_passive=Some((bridge.clone(),passive.clone()));
                *retained=Some(retention); // Before any real passive/edit query.
            }
            input.permit(&owner)?;
            let document=DocumentBinding::new(bridge.clone());
            require(document.navigation(true),Failure::NativeCommandRejected)?;
            document.observe(|life| life.started(true)); document.hook_installed(); document.observe(|life| life.finished(true));
            require(owner.metadata_text_status().is_ok_and(|status| status.capability.available)
                && !owner.inner.hosted_qualified(EditDomain::Configuration) && !owner.inner.hosted_qualified(EditDomain::GitHubWorkflows),Failure::NativeCommandRejected)?;
            Ok(Self { batch:Batch { owner,originals:Vec::new(),missing_original:false,cases:Vec::new() },bridge,document,passive,queries:Vec::new() })
        }
        fn settled(&self) -> bool {
            FIXTURE_FILES.all_settled() && probes_settled() && self.passive.settled() && !self.batch.missing_original
                && self.batch.owner.can_exit() && self.batch.originals.iter().all(|original| match original.fixture_schedule.eof_case() {
                    Some(case) => original_eof_facts(original,case).is_ok(),None => original_facts(original).is_ok(),
                })
        }
        fn register(&self,root:&Path) -> Check<Project> {
            require(FIXTURE_FILES.all_settled() && probes_settled() && self.passive.settled(),Failure::OriginalCustodyUnknown)?;
            let generation=self.bridge.native_generation().map_err(|_| Failure::NativeCommandRejected)?;
            let (proof,settled)={
                let mut books=PROBES.lock().map_err(|_| Failure::OriginalCustodyUnknown)?;
                require(books.len() < 16,Failure::OriginalCustodyUnknown)?;
                books.push(SourceBook::new()); // Retain the original before acquisition.
                let book=books.last_mut().ok_or(Failure::OriginalCustodyUnknown)?;
                let proof=std::panic::catch_unwind(std::panic::AssertUnwindSafe(||
                    asset_source::probe_project(book,root.to_path_buf(),&[],&mut || false))).map_err(|_| Failure::OriginalCustodyUnknown)?;
                (proof,book.settled())
            };
            require(settled,Failure::OriginalCustodyUnknown)?;
            let project=self.document.metadata_fixture_publish(proof.map_err(|_| Failure::NativeCommandRejected)?,generation)
                .map_err(|_| Failure::NativeCommandRejected)?;
            let (_,registered)=self.bridge.native_project(&project.id).map_err(|_| Failure::UnexpectedStatus)?;
            let stat=fs::symlink_metadata(root).map_err(|_| Failure::FixtureIo)?;
            let identity=registered.identity.workflow_identity();
            require(registered.path == root && identity.device == stat.dev().to_string() && identity.inode == stat.ino().to_string()
                && identity.mode == stat.mode() && identity.uid == stat.uid() && identity.gid == stat.gid(),Failure::PayloadMismatch)?;
            Ok(project)
        }
        fn retain_open(&mut self) -> Check<Arc<Session>> {
            let original={
                let registry=self.batch.owner.inner.lock();
                if registry.last.as_ref().is_some_and(|last| !self.batch.originals.iter().any(|original| original.id == last.session_id)) {
                    self.batch.missing_original=true;
                }
                registry.active.as_ref().map(|active| active.session.clone())
            };
            let original=original.ok_or_else(|| { self.batch.missing_original=true; Failure::OriginalCustodyUnknown })?;
            self.batch.originals.push(original.clone());
            RETAINED.lock().map_err(|_| Failure::OriginalCustodyUnknown)?.as_mut().ok_or(Failure::OriginalCustodyUnknown)?.originals.push(original.clone());
            Ok(original)
        }
        fn open(&mut self,project:&Project,selection:Selection) -> Check<Arc<Session>> {
            require(self.settled() && !self.batch.owner.disabled(),Failure::OriginalCustodyUnknown)?;
            let reply=self.bridge.open_metadata_text_edit(&self.document,"main",selection.open(project));
            let original=self.retain_open()?;
            let status=reply.map_err(|_| Failure::NativeCommandRejected)?;
            require(select(&status,&original.id)?.phase == Phase::Opening && original.domain == EditDomain::MetadataText,Failure::UnexpectedStatus)?;
            Ok(original)
        }
        async fn observe(&mut self,project:&Project,selection:Selection,error:Option<&'static str>) -> Check<Result<metadata_wire::Observation,BridgeError>> {
            require(self.settled() && !self.batch.owner.disabled(),Failure::OriginalCustodyUnknown)?;
            let reply=self.bridge.observe_metadata_text(&self.document, selection.open(project)).await;
            self.queries.push(self.passive.next(Method::MetadataTextObserve,error).await.map_err(|_| Failure::OriginalCustodyUnknown)?);
            Ok(reply)
        }
        async fn validate(&mut self,selection:Selection) -> Check<()> {
            require(self.settled() && !self.batch.owner.disabled(),Failure::OriginalCustodyUnknown)?;
            let fields=selection.fields();
            let reply=self.bridge.validate_metadata_text(&self.document, metadata_text_commands::Validate { platform:selection.platform,fields:fields.clone() }).await;
            self.queries.push(self.passive.next(Method::MetadataTextValidate,None).await.map_err(|_| Failure::OriginalCustodyUnknown)?);
            let value=reply.map_err(|_| Failure::UnexpectedOutcome)?;
            require(value.schema_version == 1 && value.platform == selection.platform && value.valid
                && value.state == metadata_wire::ValidationState::FormatValid && value.fields.len() == fields.len()
                && value.fields.iter().zip(&fields).enumerate().all(|(index,(row,field))| row.id == field.id && row.valid && row.issues.is_empty()
                    && row.limit == field_limit(selection,index) && row.character_count == scalar_count(&field.text))
                && assurance(&value.assurance,"schema-policy"),Failure::UnexpectedOutcome)
        }
        async fn catalogue(&mut self) -> Check<()> {
            require(self.settled() && !self.batch.owner.disabled(),Failure::OriginalCustodyUnknown)?;
            let reply=self.bridge.catalog(&self.document).await;
            self.queries.push(self.passive.next(Method::Catalog,None).await.map_err(|_| Failure::OriginalCustodyUnknown)?);
            let value=reply.map_err(|_| Failure::UnexpectedOutcome)?;
            let guide:Value=serde_json::from_slice(RESOURCE).map_err(|_| Failure::PayloadMismatch)?;
            let schema:Value=serde_json::from_slice(SCHEMA).map_err(|_| Failure::PayloadMismatch)?;
            require(value["schemaVersion"] == 1 && value["metadataText"] == guide && value["schema"] == schema
                && value["metadata"]["requiredLocaleText"] == json!({"android":ANDROID_NAMES,"ios":IOS_NAMES})
                && value["metadata"]["textLimits"] == json!({"title.txt":30,"name.txt":30,"short_description.txt":80,"subtitle.txt":30,
                    "promotional_text.txt":170,"keywords.txt":100,"description.txt":4000,"full_description.txt":4000,
                    "whats_new.txt":4000,"release_notes.txt":4000,"what-to-test.txt":4000})
                && value["metadata"]["assurance"] == "format-rules-only",Failure::UnexpectedOutcome)
        }
        async fn stop(&self) {
            let current=self.batch.owner.inner.lock().active.as_ref().map(|active| (active.session.id.clone(),active.session.domain));
            if let Some((id,domain))=current {
                match domain {
                    EditDomain::MetadataText => { let _=self.batch.owner.close_metadata_text("main",&id); let _=observed_metadata(&self.batch.owner,&id,Phase::Final,false).await; },
                    EditDomain::Configuration => self.batch.stop_original().await,
                    // Metadata fixture never admits this writer. A foreign arm
                    // still stops through the SAME owner, not a metadata receipt.
                    EditDomain::ReleaseVersion => { let _=self.batch.owner.close_release_version("main",&id); let _=self.batch.owner.shutdown().await; },
                    EditDomain::GitHubWorkflows => { let _=self.batch.owner.close_workflow("main",&id); let _=workflow_observed(&self.batch.owner,&id,Phase::Final).await; },
                }
            }
            if !self.passive.settled() { let _=self.bridge.supervisor.shutdown().await; }
        }
    }
    fn scalar_count(text:&str) -> u32 { text.replace("\r\n","\n").replace('\r',"\n").trim_end_matches('\n').chars().count() as u32 }
    fn field_limit(selection:Selection,index:usize) -> u32 {
        if selection.platform == Platform::Android { [30,80,4000][index] } else { [4000,100,2048,2048,4000][index] }
    }
    fn assurance(value:&metadata_wire::Assurance,basis:&str) -> bool {
        value.basis == basis && !value.project_code_executed && !value.tools_probed && !value.credentials_read && !value.git_observed
            && !value.store_contacted && !value.writes_performed && value.release_readiness == "unknown"
    }
    fn select(status:&MetadataTextEditStatus,id:&str) -> Check<metadata_wire::Projection> {
        require(status.domain == DOMAIN,Failure::UnexpectedStatus)?;
        status.active.as_ref().filter(|p| p.session_id == id).or_else(|| status.last_terminal.as_ref().filter(|p| p.session_id == id))
            .cloned().ok_or(Failure::UnexpectedStatus)
    }
    async fn observed_metadata(owner:&EditOwner,id:&str,desired:Phase,expected_unknown:bool) -> Check<metadata_wire::Projection> {
        let end=Instant::now()+OBSERVATION; let mut revisions=owner.subscribe();
        loop {
            let status=owner.metadata_text_status().map_err(|_| Failure::OriginalCustodyUnknown)?;
            let current=select(&status,id)?;
            if !expected_unknown {
                require(!owner.disabled() && current.phase != Phase::Unknown && current.native_finality != NativeFinality::Unknown
                    && !current.late_settled,Failure::OriginalCustodyUnknown)?;
            }
            if current.phase == desired && (!expected_unknown || status.active.is_none()) { return Ok(current); }
            require(current.phase != Phase::Final,Failure::UnexpectedStatus)?;
            tokio::select! {
                result=revisions.changed() => { result.map_err(|_| Failure::UnexpectedStatus)?; },
                _=tokio::time::sleep_until(tokio::time::Instant::from_std(end)) => return Err(Failure::ObservationTimeout),
            }
        }
    }
    async fn workflow_observed(owner:&EditOwner,id:&str,desired:Phase) -> Check<workflow_wire::Projection> {
        let end=Instant::now()+OBSERVATION; let mut revisions=owner.subscribe();
        loop {
            let status=owner.workflow_status().map_err(|_| Failure::OriginalCustodyUnknown)?;
            let current=status.active.as_ref().filter(|p| p.session_id == id).or_else(|| status.last_terminal.as_ref().filter(|p| p.session_id == id))
                .cloned().ok_or(Failure::UnexpectedStatus)?;
            require(!owner.disabled() && current.native_finality != NativeFinality::Unknown && !current.late_settled,Failure::OriginalCustodyUnknown)?;
            if current.phase == desired { return Ok(current); }
            require(current.phase != Phase::Final,Failure::UnexpectedStatus)?;
            tokio::select! { result=revisions.changed() => { result.map_err(|_| Failure::UnexpectedStatus)?; },
                _=tokio::time::sleep_until(tokio::time::Instant::from_std(end)) => return Err(Failure::ObservationTimeout), }
        }
    }

    #[derive(Clone,Copy,PartialEq,Eq)]
    struct Stamp { modified:i64,modified_ns:i64,changed:i64,changed_ns:i64 }
    impl Stamp { fn of(value:&fs::Metadata) -> Self { Self { modified:value.mtime(),modified_ns:value.mtime_nsec(),changed:value.ctime(),changed_ns:value.ctime_nsec() } } }
    #[derive(PartialEq,Eq)]
    struct RawFile { original:OriginalFile,stamp:Stamp }
    #[derive(PartialEq,Eq)]
    struct Snapshot { files:std::collections::BTreeMap<String,RawFile>,directories:std::collections::BTreeMap<String,Identity> }
    fn raw_file(path:&Path,limit:u64) -> Check<RawFile> {
        FIXTURE_FILES.admit()?;
        let before=fs::symlink_metadata(path).map_err(|_| Failure::FixtureIo)?;
        let original=read_regular(path,limit)?;
        let after=fs::symlink_metadata(path).map_err(|_| Failure::FixtureIo)?;
        require(Identity::of(&before) == original.identity && Identity::of(&after) == original.identity
            && Stamp::of(&before) == Stamp::of(&after),Failure::PayloadMismatch)?;
        Ok(RawFile { original,stamp:Stamp::of(&before) })
    }
    fn mkdir(path:&Path) -> Check<()> {
        FIXTURE_FILES.admit()?; fs::DirBuilder::new().mode(0o700).create(path).map_err(|_| Failure::FixtureIo)
    }
    fn ancestors(relative:&str) -> Vec<String> {
        let mut result=Vec::new(); let mut path=String::new();
        for part in relative.split('/') { if !path.is_empty() { path.push('/'); } path.push_str(part); result.push(path.clone()); }
        result
    }
    fn seed_parent(root:&Path,parent:&str) -> Check<()> {
        for name in ancestors(parent) {
            FIXTURE_FILES.admit()?;
            match fs::symlink_metadata(root.join(&name)) {
                Ok(stat) => require(stat.is_dir(),Failure::FixtureIo)?,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => mkdir(&root.join(name))?,
                Err(_) => return Err(Failure::FixtureIo),
            }
        }
        Ok(())
    }
    fn fixture_roster() -> (BTreeSet<String>,BTreeSet<String>) {
        let mut directories:BTreeSet<String>=["","release",".github",".github/workflows"].into_iter().map(str::to_owned).collect();
        let mut leaves:BTreeSet<String>=[".gitignore","unrelated.txt","release/mobile-release.json","release/other.txt",".github/workflows/unrelated.txt"]
            .into_iter().map(str::to_owned).collect();
        for metadata_root in ["public/store","release/store"] {
            for (platform,locale) in [(Platform::Android,"en-US"),(Platform::Android,"fr-FR"),(Platform::Ios,"en-US")] {
                let selection=Selection { platform,locale,metadata_root };
                directories.extend(ancestors(&selection.parent()));
                leaves.extend(selection.names().iter().enumerate().map(|(index,_)| selection.path(index)));
                leaves.insert(format!("{}/unrelated.txt",selection.parent()));
            }
        }
        (directories,leaves)
    }
    fn snapshot(root:&Path) -> Check<Snapshot> {
        let (allowed_directories,allowed_files)=fixture_roster();
        let mut directories=std::collections::BTreeMap::new(); let mut files=std::collections::BTreeMap::new();
        let mut pending=vec![String::new()];
        while let Some(relative)=pending.pop() {
            FIXTURE_FILES.admit()?;
            require(allowed_directories.contains(&relative) && directories.len() < 24,Failure::PayloadMismatch)?;
            let path=root.join(&relative); let stat=fs::symlink_metadata(&path).map_err(|_| Failure::FixtureIo)?;
            require(stat.is_dir(),Failure::PayloadMismatch)?; directories.insert(relative.clone(),Identity::of(&stat));
            let mut count=0;
            for entry in fs::read_dir(path).map_err(|_| Failure::FixtureIo)? {
                count+=1; require(count <= 12,Failure::PayloadMismatch)?;
                let name=entry.map_err(|_| Failure::FixtureIo)?.file_name().into_string().map_err(|_| Failure::PayloadMismatch)?;
                let child=if relative.is_empty() { name } else { format!("{relative}/{name}") };
                let stat=fs::symlink_metadata(root.join(&child)).map_err(|_| Failure::FixtureIo)?;
                if stat.is_dir() { require(allowed_directories.contains(&child),Failure::PayloadMismatch)?; pending.push(child); }
                else {
                    require(allowed_files.contains(&child) && files.len() < 32,Failure::PayloadMismatch)?;
                    let file=raw_file(&root.join(&child),1024*1024)?;
                    require(files.insert(child,file).is_none(),Failure::PayloadMismatch)?;
                }
            }
        }
        Ok(Snapshot { files,directories })
    }
    fn seed_common(root:&Path,selection:Selection,ignore:bool) -> Check<()> {
        mkdir(root)?; mkdir(&root.join("release"))?;
        write_new(&root.join("release/mobile-release.json"),selection.config(),0o440)?;
        if ignore { write_new(&root.join(".gitignore"),IGNORE,0o400)?; }
        write_new(&root.join("unrelated.txt"),UNRELATED,0o400)?; write_new(&root.join("release/other.txt"),UNRELATED,0o400)?;
        mkdir(&root.join(".github"))?; mkdir(&root.join(".github/workflows"))?;
        write_new(&root.join(".github/workflows/unrelated.txt"),UNRELATED,0o400)
    }
    fn seed_siblings(root:&Path,selection:Selection) -> Check<()> {
        for (platform,locale) in [(Platform::Android,"en-US"),(Platform::Android,"fr-FR"),(Platform::Ios,"en-US")] {
            if selection.platform == platform && selection.locale == locale { continue; }
            let other=Selection { platform,locale,metadata_root:selection.metadata_root };
            seed_parent(root,&other.parent())?;
            for (index,text) in other.texts().iter().enumerate() { write_new(&root.join(other.path(index)),text.as_bytes(),0o400)?; }
        }
        Ok(())
    }
    fn seed(input:&Admitted,case:Case) -> Check<PathBuf> {
        input.inputs.same_root()?; let selection=case.selection(); let root=input.inputs.root.join(case.name());
        seed_common(&root,selection,case != Case::NoIgnore)?;
        if !case.fresh() {
            seed_parent(&root,&selection.parent())?;
            for (index,text) in selection.texts().iter().enumerate() {
                if case == Case::IosMixed && index == 2 { continue; }
                let bytes=if case == Case::AndroidReplace && index == 1 { OLD_ANDROID_SHORT.as_bytes() }
                    else if case == Case::IosMixed && index == 0 { OLD_IOS_DESCRIPTION.as_bytes() }
                    else if case == Case::IosMixed && index == 1 { OLD_IOS_KEYWORDS.as_bytes() }
                    else if case == Case::Sensitive && index == 2 { SENSITIVE }
                    else if case == Case::Nonutf8 && index == 4 { NONUTF8 }
                    else { text.as_bytes() };
                let first_replacement=if case == Case::AndroidReplace { index == 1 } else { index == 0 };
                write_new(&root.join(selection.path(index)),bytes,if first_replacement { 0o640 } else { 0o600 })?;
            }
            seed_siblings(&root,selection)?;
        }
        Ok(root)
    }
    fn rewrite_original(path:&Path,old:&RawFile,bytes:&[u8]) -> Check<()> {
        FIXTURE_FILES.admit()?;
        let mut file=fs::OpenOptions::new().write(true).custom_flags(nix::libc::O_NOFOLLOW).open(path).map_err(|_| Failure::FixtureIo)?;
        FIXTURE_FILES.acquired();
        let result=(|| {
            let opened=file.metadata().map_err(|_| Failure::FixtureIo)?;
            require(Identity::of(&opened) == old.original.identity && Stamp::of(&opened) == old.stamp,Failure::PayloadMismatch)?;
            file.set_len(0).map_err(|_| Failure::FixtureIo)?; file.write_all(bytes).map_err(|_| Failure::FixtureIo)
        })();
        FIXTURE_FILES.close_original(file)?; result
    }
    fn baseline(before:&Snapshot,selection:Selection) -> Check<metadata_wire::Baseline> {
        let config=&before.files.get("release/mobile-release.json").ok_or(Failure::PayloadMismatch)?.original;
        let fields=selection.platform.ids().iter().enumerate().map(|(index,id)| match before.files.get(&selection.path(index)) {
            Some(file) => metadata_wire::BaselineField::Present { id:*id,byte_length:file.original.bytes.len() as u32,sha256:hash(&file.original.bytes) },
            None => metadata_wire::BaselineField::Absent { id:*id },
        }).collect();
        Ok(metadata_wire::Baseline { config:metadata_wire::ContentDigest { byte_length:config.bytes.len() as u32,sha256:hash(&config.bytes) },fields })
    }
    fn observed_roster(before:&Snapshot,selection:Selection,value:&metadata_wire::Observation) -> Check<()> {
        require(value.schema_version == 1 && value.platform == selection.platform && value.locale == selection.locale
            && value.metadata_root == selection.metadata_root && value.observation_scope == "single-request-non-atomic"
            && value.baseline == baseline(before,selection)? && value.fields.len() == selection.names().len()
            && assurance(&value.assurance,"static-text"),Failure::UnexpectedOutcome)?;
        for (index,field) in value.fields.iter().enumerate() {
            let name=selection.path(index); let id=selection.platform.ids()[index];
            let valid=match (field,before.files.get(&name)) {
                (metadata_wire::ObservedField::Absent { id:actual,path },None) => *actual == id && *path == name,
                (metadata_wire::ObservedField::Present { id:actual,path,text,byte_length,sha256 },Some(old)) => *actual == id && *path == name
                    && text.as_bytes() == old.original.bytes && *byte_length as usize == old.original.bytes.len() && *sha256 == hash(&old.original.bytes),
                _ => false,
            };
            require(valid,Failure::UnexpectedOutcome)?;
        }
        Ok(())
    }
    fn prepare_args(id:&str,revision:&str,expected:&metadata_wire::Baseline,selection:Selection) -> PrepareMetadataTextEdit {
        PrepareMetadataTextEdit { session_id:id.into(),revision:revision.into(),expected_baseline:expected.clone(),fields:selection.fields(),
            draft_revision:1,baseline_generation:0 }
    }
    async fn prepare(original:&Original,id:&str,checkout:&metadata_wire::Checkout,expected:&metadata_wire::Baseline,selection:Selection) -> Check<metadata_wire::Prepared> {
        let reply=original.bridge.prepare_metadata_text_edit(&original.document,"main",prepare_args(id,&checkout.revision,expected,selection))
            .map_err(|_| Failure::NativeCommandRejected)?;
        require(select(&reply,id)?.phase == Phase::Preparing,Failure::UnexpectedStatus)?;
        observed_metadata(&original.batch.owner,id,Phase::Reviewing,false).await?.prepared.ok_or(Failure::UnexpectedOutcome)
    }
    fn line_styles(text:&[u8]) -> u8 {
        let mut at=0; let mut styles=0;
        while at < text.len() {
            match text[at] { b'\r' if text.get(at+1) == Some(&b'\n') => { styles|=1; at+=1; },b'\r' => styles|=2,b'\n' => styles|=4,_ => {} }
            at+=1;
        }
        styles
    }
    fn verify_plan(before:&Snapshot,selection:Selection,checkout:&metadata_wire::Checkout,plan:&metadata_wire::Prepared) -> Check<Vec<String>> {
        require(checkout.baseline == baseline(before,selection)? && checkout.metadata_root == selection.metadata_root
            && plan.revision == checkout.revision && plan.draft_revision == 1 && plan.baseline_generation == 0
            && plan.view.platform == selection.platform && plan.view.locale == selection.locale && plan.view.metadata_root == selection.metadata_root
            && plan.view.files.len() == selection.names().len() && plan.view.validation.valid
            && plan.view.validation.platform == selection.platform && plan.view.validation.fields.len() == selection.names().len(),Failure::UnexpectedOutcome)?;
        for (index,file) in plan.view.files.iter().enumerate() {
            let path=selection.path(index); let old=before.files.get(&path); let desired=selection.texts()[index].as_bytes();
            let action=match old { None => metadata_wire::Action::Create,Some(old) if old.original.bytes == desired => metadata_wire::Action::Preserve,
                Some(_) => metadata_wire::Action::Replace };
            let before_matches=match (&file.before,old) {
                (metadata_wire::Before::Absent {},None) => true,
                (metadata_wire::Before::Present { text,byte_length,sha256 },Some(old)) => text.as_bytes() == old.original.bytes
                    && *byte_length as usize == old.original.bytes.len() && *sha256 == hash(&old.original.bytes),_ => false,
            };
            let old_styles=old.map_or(0,|old| line_styles(&old.original.bytes));
            let row=&plan.view.validation.fields[index];
            require(file.id == selection.platform.ids()[index] && file.path == path && file.action == action && before_matches
                && file.after.text.as_bytes() == desired && file.after.byte_length as usize == desired.len() && file.after.sha256 == hash(desired)
                && file.line_endings_changed == (old_styles != line_styles(desired)) && row.id == file.id && row.valid && row.issues.is_empty()
                && row.character_count == scalar_count(selection.texts()[index]) && row.limit == field_limit(selection,index),Failure::PayloadMismatch)?;
        }
        let created:Vec<String>=ancestors(&selection.parent()).into_iter().filter(|name| !before.directories.contains_key(name)).collect();
        require(plan.view.create_directories == created && assurance(&plan.view.validation.assurance,"schema-policy"),Failure::UnexpectedOutcome)?;
        Ok(created)
    }
    fn installed(root:&Path,before:&Snapshot,selection:Selection,created:&[String]) -> Check<()> {
        let after=snapshot(root)?;
        require(before.directories.iter().all(|(name,old)| after.directories.get(name) == Some(old)),Failure::PayloadMismatch)?;
        let selected:Vec<String>=(0..selection.names().len()).map(|index| selection.path(index)).collect();
        for (name,old) in &before.files {
            if !selected.contains(name) { require(after.files.get(name) == Some(old),Failure::PayloadMismatch)?; }
        }
        let mut added=0;
        for (index,name) in selected.iter().enumerate() {
            let file=after.files.get(name).ok_or(Failure::PayloadMismatch)?; let bytes=selection.texts()[index].as_bytes();
            require(file.original.bytes == bytes,Failure::PayloadMismatch)?;
            match before.files.get(name) {
                Some(old) if old.original.bytes == bytes => require(file == old,Failure::PayloadMismatch)?,
                Some(old) => require(file.original.identity.device == old.original.identity.device && file.original.identity.inode != old.original.identity.inode
                    && file.original.identity.mode == old.original.identity.mode && file.original.identity.owner == old.original.identity.owner
                    && file.original.identity.group == old.original.identity.group,Failure::PayloadMismatch)?,
                None => { added+=1; require(file.original.identity.mode & 0o7777 == 0o600
                    && file.original.identity.owner == rustix::process::geteuid().as_raw() && file.original.identity.group == rustix::process::getegid().as_raw(),Failure::PayloadMismatch)?; },
            }
        }
        for name in created { require(after.directories.get(name).is_some_and(|id| id.mode & 0o7777 == 0o755
            && id.owner == rustix::process::geteuid().as_raw() && id.group == rustix::process::getegid().as_raw()),Failure::PayloadMismatch)?; }
        require(after.files.len() == before.files.len()+added && after.directories.len() == before.directories.len()+created.len(),Failure::PayloadMismatch)
    }
    fn restored(root:&Path,before:&Snapshot) -> Check<()> {
        let after=snapshot(root)?;
        // Own rename/restore may change ctime. Compare original identity, mode,
        // owner, group, bytes and mtime, not a false old-ctime requirement.
        require(after.directories == before.directories && after.files.len() == before.files.len()
            && before.files.iter().all(|(name,old)| after.files.get(name).is_some_and(|new| new.original == old.original
                && new.stamp.modified == old.stamp.modified && new.stamp.modified_ns == old.stamp.modified_ns)),Failure::PayloadMismatch)
    }

    fn settled_terminal(owner:&EditOwner,terminal:&metadata_wire::Projection) -> Check<()> {
        require(terminal.phase == Phase::Final && terminal.native_finality == NativeFinality::Settled && !terminal.late_settled
            && owner.can_exit() && !owner.disabled(),Failure::OriginalCustodyUnknown)
    }
    fn correlated(terminal:&metadata_wire::Projection,editing:&metadata_wire::Projection,plan:&metadata_wire::Prepared) -> Check<()> {
        require(terminal.domain == DOMAIN && terminal.owner_generation == editing.owner_generation && terminal.session_id == editing.session_id
            && terminal.project_id == editing.project_id && terminal.platform == editing.platform && terminal.locale == editing.locale
            && terminal.checkout.as_ref().is_some_and(|checkout| editing.checkout.as_ref().is_some_and(|old|
                checkout.revision == old.revision && checkout.metadata_root == old.metadata_root && checkout.baseline == old.baseline))
            && terminal.prepared.as_ref().is_some_and(|retained| retained.plan_token == plan.plan_token && retained.revision == plan.revision
                && retained.draft_revision == plan.draft_revision && retained.baseline_generation == plan.baseline_generation
                && matches!((serde_json::to_value(&retained.view),serde_json::to_value(&plan.view)),(Ok(actual),Ok(expected)) if actual==expected)),Failure::UnexpectedOutcome)
    }
    fn native_data(session:&Session,terminal:&metadata_wire::Projection,eof:Option<EofCase>) -> Check<Value> {
        let facts=if let Some(case)=eof { original_eof_facts(session,case)? } else { original_facts(session)? };
        require(terminal.session_id == session.id && session.domain == EditDomain::MetadataText,Failure::UnexpectedStatus)?;
        let mut value=serde_json::to_value(facts).map_err(|_| Failure::ReceiptIo)?;
        value["domain"]=json!(DOMAIN); value["nativePhase"]=json!(terminal.phase); value["nativeFinality"]=json!(terminal.native_finality);
        value["nativeReason"]=json!(terminal.native_reason); value["applySubmitted"]=json!(terminal.apply_submitted);
        value["lateSettled"]=json!(terminal.late_settled); value["outcome"]=json!(terminal.core_outcome);
        value["terminalSeq"]=json!(session.fixture_schedule.sequence());
        value["checkoutRetained"]=json!(terminal.checkout.is_some()); value["preparedRetained"]=json!(terminal.prepared.is_some());
        Ok(value)
    }
    fn row(original:&mut Original,name:&str,selection:Selection,native:Option<Value>,observations:Value) -> Check<()> {
        require(original.settled(),Failure::OriginalCustodyUnknown)?;
        original.batch.cases.push(json!({"name":name,"domain":DOMAIN,"platform":selection.platform,"locale":selection.locale,
            "native":native,"passive":std::mem::take(&mut original.queries),"observations":observations}));
        Ok(())
    }
    fn statuses(original:&Original,id:&str,domain:EditDomain) -> Check<()> {
        let config=original.batch.owner.status().map_err(|_| Failure::UnexpectedStatus)?;
        let workflow=original.batch.owner.workflow_status().map_err(|_| Failure::UnexpectedStatus)?;
        let metadata=original.batch.owner.metadata_text_status().map_err(|_| Failure::UnexpectedStatus)?;
        require(config.status_revision == workflow.status_revision && workflow.status_revision == metadata.status_revision
            && config.window_generation == workflow.window_generation && workflow.window_generation == metadata.window_generation
            && config.active.as_ref().map(|p| p.session_id.as_str()) == (domain==EditDomain::Configuration).then_some(id)
            && workflow.active.as_ref().map(|p| p.session_id.as_str()) == (domain==EditDomain::GitHubWorkflows).then_some(id)
            && metadata.active.as_ref().map(|p| p.session_id.as_str()) == (domain==EditDomain::MetadataText).then_some(id),Failure::UnexpectedStatus)?;
        for (candidate,capability) in [(EditDomain::Configuration,config.capability),(EditDomain::GitHubWorkflows,workflow.capability),(EditDomain::MetadataText,metadata.capability)] {
            require(capability.reason == if candidate == domain { EditAvailability::Available } else { EditAvailability::OtherEditActive },Failure::UnexpectedStatus)?;
        }
        let last=original.batch.owner.inner.lock().last.as_ref().map(|p| (p.domain,p.session_id.clone()));
        require(config.last_terminal.as_ref().map(|p| p.session_id.as_str()) == last.as_ref().filter(|(d,_)| *d==EditDomain::Configuration).map(|(_,id)| id.as_str())
            && workflow.last_terminal.as_ref().map(|p| p.session_id.as_str()) == last.as_ref().filter(|(d,_)| *d==EditDomain::GitHubWorkflows).map(|(_,id)| id.as_str())
            && metadata.last_terminal.as_ref().map(|p| p.session_id.as_str()) == last.as_ref().filter(|(d,_)| *d==EditDomain::MetadataText).map(|(_,id)| id.as_str()),Failure::UnexpectedStatus)
    }
    fn opposite_commands(original:&Original,project:&Project,selection:Selection,session:&Arc<Session>,revision:&str,
        passive:&metadata_wire::Baseline,domain:EditDomain) -> Check<()> {
        const TOKEN:&str="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        statuses(original,&session.id,domain)?;
        if domain != EditDomain::Configuration {
            require(original.bridge.open_config_edit("main",project.id.clone()).is_err()
                && original.batch.owner.prepare("main",PrepareConfigEdit { session_id:session.id.clone(),revision:revision.into(),expected_base:Value::Null,
                    draft:document(),draft_revision:1,baseline_generation:0 }).is_err()
                && original.batch.owner.apply("main",&session.id,TOKEN).is_err(),Failure::UnexpectedStatus)?;
        }
        if domain != EditDomain::GitHubWorkflows {
            require(original.bridge.open_workflow_edit(&original.document,"main",project.id.clone()).is_err()
                && original.bridge.prepare_workflow_edit(&original.document,"main",PrepareWorkflowEdit { session_id:session.id.clone(),revision:revision.into(),
                    draft:document(),tooling_repository:"Example/mobile-release-kit".into(),tooling_sha:"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
                    draft_revision:1,baseline_generation:0 }).is_err()
                && original.bridge.apply_workflow_edit(&original.document,"main",&session.id,TOKEN).is_err(),Failure::UnexpectedStatus)?;
        }
        if domain != EditDomain::MetadataText {
            require(original.bridge.open_metadata_text_edit(&original.document,"main",selection.open(project)).is_err()
                && original.bridge.prepare_metadata_text_edit(&original.document,"main",prepare_args(&session.id,revision,passive,selection)).is_err()
                && original.bridge.apply_metadata_text_edit(&original.document,"main",&session.id,TOKEN).is_err(),Failure::UnexpectedStatus)?;
        }
        let registry=original.batch.owner.inner.lock(); let active=registry.active.as_ref().ok_or(Failure::OriginalCustodyUnknown)?;
        require(Arc::ptr_eq(&active.session,session) && active.session.domain == domain && active.claimed_seq == 0
            && active.prepare_counters.is_none() && !active.prepared && !active.projection.apply_submitted && active.cleanup_start.is_none(),Failure::UnexpectedStatus)
    }
    fn legacy_data(session:&Session,phase:Phase,finality:NativeFinality,native:Reason,applied:bool,late:bool,core:&wire::CoreEditOutcome) -> Check<Value> {
        let facts=original_facts(session)?;
        require((facts.request_frames,facts.response_frames)==(1,2) && session.fixture_schedule.sequence()==Some(0)
            && phase == Phase::Final && finality == NativeFinality::Settled && native == Reason::Discarded && !applied && !late
            && core.effect == Effect::NotStarted && core.journal == Journal::NotCreated && core.resources == ResourceState::Settled
            && matches!(core.reason,CoreReason::Cancelled|CoreReason::None),Failure::UnexpectedOutcome)?;
        let mut value=serde_json::to_value(facts).map_err(|_| Failure::ReceiptIo)?;
        value["domain"]=json!(if session.domain==EditDomain::Configuration { "configuration" } else { "github_workflows" });
        value["nativePhase"]=json!(phase); value["nativeFinality"]=json!(finality); value["nativeReason"]=json!(native);
        value["applySubmitted"]=json!(applied); value["lateSettled"]=json!(late); value["outcome"]=json!(core); value["terminalSeq"]=json!(0);
        Ok(value)
    }
    async fn legacy_isolation(original:&mut Original,input:&Admitted,root:&Path,project:&Project,selection:Selection,passive:&metadata_wire::Baseline) -> Check<Vec<Value>> {
        require(original.settled(),Failure::OriginalCustodyUnknown)?;
        let metadata_permit=original.batch.owner.inner.fixture_metadata.lock().map_err(|_| Failure::OriginalCustodyUnknown)?.take()
            .ok_or(Failure::HostedGuardRefused)?;
        require(metadata_permit.root(&original.batch.owner.inner,root) && !original.batch.owner.inner.hosted_qualified(EditDomain::MetadataText)
            && !original.batch.owner.inner.hosted_qualified(EditDomain::GitHubWorkflows),Failure::HostedGuardRefused)?;
        original.batch.owner.inner.fixture_authorized.store(true,Ordering::SeqCst);
        require(original.batch.owner.inner.hosted_qualified(EditDomain::Configuration)
            && !original.batch.owner.inner.hosted_qualified(EditDomain::MetadataText),Failure::HostedGuardRefused)?;
        let reply=original.bridge.open_config_edit("main",project.id.clone());
        let session=original.retain_open()?;
        require(projection(&reply.map_err(|_| Failure::NativeCommandRejected)?,&session.id)?.phase==Phase::Opening,Failure::UnexpectedStatus)?;
        let editing=observed(&original.batch.owner,&session.id,Phase::Editing).await?;
        let checkout=editing.checkout.as_ref().ok_or(Failure::UnexpectedOutcome)?;
        opposite_commands(original,project,selection,&session,&checkout.revision,passive,EditDomain::Configuration)?;
        original.batch.owner.close("main",&session.id).map_err(|_| Failure::NativeCommandRejected)?;
        let terminal=observed(&original.batch.owner,&session.id,Phase::Final).await?;
        let config=legacy_data(&session,terminal.phase,terminal.native_finality,terminal.native_reason,terminal.apply_submitted,terminal.late_settled,
            terminal.core_outcome.as_ref().ok_or(Failure::UnexpectedOutcome)?)?;
        require(original.settled(),Failure::OriginalCustodyUnknown)?;
        original.batch.owner.inner.fixture_authorized.store(false,Ordering::SeqCst);
        {
            let mut slot=original.batch.owner.inner.fixture_workflow.lock().map_err(|_| Failure::OriginalCustodyUnknown)?;
            require(slot.is_none(),Failure::HostedGuardRefused)?;
            *slot=Some(Arc::new(WorkflowFixturePermit { owner:Arc::downgrade(&original.batch.owner.inner),roots:vec![root.to_path_buf()],
                python:input.python.clone(),core:input.core.clone(),bootstrap:input.repository.join("desktop/config_edit_bootstrap.py"),
                cwd:input.repository.join("desktop"),binding_sha256:hash(&serde_json::to_vec(&input.inputs.bindings).map_err(|_| Failure::SourceBindingMismatch)?),eof:false }));
        }
        require(!original.batch.owner.inner.hosted_qualified(EditDomain::Configuration)
            && original.batch.owner.inner.hosted_qualified(EditDomain::GitHubWorkflows)
            && !original.batch.owner.inner.hosted_qualified(EditDomain::MetadataText),Failure::HostedGuardRefused)?;
        let reply=original.bridge.open_workflow_edit(&original.document,"main",project.id.clone());
        let session=original.retain_open()?;
        require(reply.map_err(|_| Failure::NativeCommandRejected)?.active.is_some_and(|p| p.session_id==session.id && p.phase==Phase::Opening),Failure::UnexpectedStatus)?;
        let editing=workflow_observed(&original.batch.owner,&session.id,Phase::Editing).await?;
        let checkout=editing.checkout.as_ref().ok_or(Failure::UnexpectedOutcome)?;
        opposite_commands(original,project,selection,&session,&checkout.revision,passive,EditDomain::GitHubWorkflows)?;
        original.batch.owner.close_workflow("main",&session.id).map_err(|_| Failure::NativeCommandRejected)?;
        let terminal=workflow_observed(&original.batch.owner,&session.id,Phase::Final).await?;
        let workflow=legacy_data(&session,terminal.phase,terminal.native_finality,terminal.native_reason,terminal.apply_submitted,terminal.late_settled,
            terminal.core_outcome.as_ref().ok_or(Failure::UnexpectedOutcome)?)?;
        require(original.settled(),Failure::OriginalCustodyUnknown)?;
        original.batch.owner.inner.fixture_workflow.lock().map_err(|_| Failure::OriginalCustodyUnknown)?.take();
        {
            let mut slot=original.batch.owner.inner.fixture_metadata.lock().map_err(|_| Failure::OriginalCustodyUnknown)?;
            require(slot.is_none() && metadata_permit.owns(&original.batch.owner.inner),Failure::HostedGuardRefused)?;
            *slot=Some(metadata_permit); // The same original metadata permit, never a workflow-derived value.
        }
        require(!original.batch.owner.inner.hosted_qualified(EditDomain::Configuration)
            && !original.batch.owner.inner.hosted_qualified(EditDomain::GitHubWorkflows)
            && original.batch.owner.inner.hosted_qualified(EditDomain::MetadataText),Failure::HostedGuardRefused)?;
        Ok(vec![config,workflow])
    }
    async fn exercise_owner(original:&mut Original,input:&Admitted,case:Case) -> Check<()> {
        require(original.settled() && !original.batch.owner.disabled() && original.queries.is_empty(),Failure::OriginalCustodyUnknown)?;
        let selection=case.selection(); let root=seed(input,case)?; let project=original.register(&root)?;
        let mut before=snapshot(&root)?;
        if case==Case::AndroidCreate || input.mode==Mode::Zip { original.catalogue().await?; }
        let passive_count=original.passive.count(); let edit_count=original.batch.originals.len();
        let expected_error=match case { Case::Sensitive=>Some("metadata_text_sensitive"),Case::Nonutf8=>Some("metadata_text_encoding"),_=>None };
        let observed=original.observe(&project,selection,expected_error).await?;
        if let Some(code)=expected_error {
            let expected=BridgeError::new(code,if case==Case::Sensitive { "A selected public text file may contain secret material; no contents were returned." }
                else { "A selected public text file is not valid UTF-8." });
            let error=observed.err().ok_or(Failure::UnexpectedOutcome)?;
            require(error==expected && original.passive.count()==passive_count+1 && original.batch.originals.len()==edit_count
                && original.batch.owner.metadata_text_status().is_ok_and(|s| s.active.is_none()) && snapshot(&root)?==before,Failure::UnexpectedOutcome)?;
            return row(original,case.name(),selection,None,json!({"closedError":code,"lastFieldRefused":true,"noPartialTextOrDigest":true,
                "noEditorAdmitted":true,"treeUnchanged":true,"sourceProbesSettled":probes_settled(),"passiveOriginalsSettled":original.passive.settled()}));
        }
        let passive=observed.map_err(|_| Failure::UnexpectedOutcome)?;
        observed_roster(&before,selection,&passive)?;
        original.validate(selection).await?;
        require(snapshot(&root)?==before,Failure::PayloadMismatch)?;
        let mut legacy=Vec::new();
        if case==Case::Stale {
            let path=selection.path(0);
            rewrite_original(&root.join(&path),before.files.get(&path).ok_or(Failure::PayloadMismatch)?,OLD_ANDROID_TITLE.as_bytes())?;
            before=snapshot(&root)?;
            require(baseline(&before,selection)? != passive.baseline,Failure::PayloadMismatch)?;
        } else if case==Case::Isolation {
            legacy=legacy_isolation(original,input,&root,&project,selection,&passive.baseline).await?;
            require(snapshot(&root)?==before,Failure::PayloadMismatch)?;
        }
        let registration=original.bridge.native_project(&project.id).map_err(|_| Failure::UnexpectedStatus)?;
        let session=original.open(&project,selection)?;
        require(session.registration.as_ref().is_some_and(|r| r.generation==registration.0 && r.root==registration.1)
            && session.fixture_metadata.as_ref().is_some_and(|permit| original.batch.owner.inner.fixture_metadata.lock()
                .is_ok_and(|current| current.as_ref().is_some_and(|current| Arc::ptr_eq(permit,current)))),Failure::UnexpectedStatus)?;
        if case==Case::NoIgnore {
            let terminal=observed_metadata(&original.batch.owner,&session.id,Phase::Final,false).await?;
            settled_terminal(&original.batch.owner,&terminal)?;
            let facts=original_facts(&session)?; let core=terminal.core_outcome.as_ref().ok_or(Failure::UnexpectedOutcome)?;
            require((facts.request_frames,facts.response_frames)==(1,1) && session.fixture_schedule.sequence()==Some(0)
                && terminal.checkout.is_none() && terminal.prepared.is_none() && !terminal.apply_submitted && terminal.native_reason==Reason::None
                && core.effect==Effect::NotStarted && core.journal==Journal::NotCreated && core.resources==ResourceState::Settled
                && core.reason==CoreReason::IgnoreConflict && snapshot(&root)?==before && !before.files.contains_key(".gitignore"),Failure::UnexpectedOutcome)?;
            return row(original,case.name(),selection,Some(native_data(&session,&terminal,None)?),json!({"passiveObserveWithoutIgnore":true,
                "ignoreStillAbsent":true,"noCheckoutOrPlan":true,"treeUnchanged":true,"sourceProbesSettled":probes_settled(),"passiveOriginalsSettled":original.passive.settled()}));
        }
        let editing=observed_metadata(&original.batch.owner,&session.id,Phase::Editing,false).await?;
        let checkout=editing.checkout.as_ref().ok_or(Failure::UnexpectedOutcome)?;
        require(checkout.baseline==baseline(&before,selection)? && checkout.metadata_root==selection.metadata_root
            && editing.platform==selection.platform && editing.locale==selection.locale && editing.project_id==project.id,Failure::UnexpectedOutcome)?;
        if case==Case::Isolation { opposite_commands(original,&project,selection,&session,&checkout.revision,&passive.baseline,EditDomain::MetadataText)?; }
        if case==Case::Stale {
            let reply=original.bridge.prepare_metadata_text_edit(&original.document,"main",prepare_args(&session.id,&checkout.revision,&passive.baseline,selection))
                .map_err(|_| Failure::NativeCommandRejected)?;
            require(select(&reply,&session.id)?.phase==Phase::Preparing,Failure::UnexpectedStatus)?;
            let terminal=observed_metadata(&original.batch.owner,&session.id,Phase::Final,false).await?;
            settled_terminal(&original.batch.owner,&terminal)?;
            let facts=original_facts(&session)?; let core=terminal.core_outcome.as_ref().ok_or(Failure::UnexpectedOutcome)?;
            require((facts.request_frames,facts.response_frames)==(2,2) && session.fixture_schedule.sequence()==Some(1)
                && terminal.prepared.is_none() && !terminal.apply_submitted && terminal.native_reason==Reason::None
                && terminal.checkout.as_ref().is_some_and(|saved| saved.revision==checkout.revision && saved.baseline==checkout.baseline)
                && core.effect==Effect::NotStarted && core.journal==Journal::NotCreated && core.resources==ResourceState::Settled
                && core.reason==CoreReason::StaleRevision && snapshot(&root)?==before,Failure::UnexpectedOutcome)?;
            return row(original,case.name(),selection,Some(native_data(&session,&terminal,None)?),json!({"olderPassiveBaselineRejected":true,
                "newerNativeCheckoutRetained":true,"noPlanOrRebase":true,"externalChangeRetained":true,"treeUnchanged":true,
                "sourceProbesSettled":probes_settled(),"passiveOriginalsSettled":original.passive.settled()}));
        }
        require(checkout.baseline==passive.baseline,Failure::UnexpectedOutcome)?;
        let plan=prepare(original,&session.id,checkout,&passive.baseline,selection).await?;
        let directories=verify_plan(&before,selection,checkout,&plan)?;
        require(snapshot(&root)?==before,Failure::PayloadMismatch)?;
        if matches!(case,Case::Registration|Case::DocumentLost) {
            if case==Case::Registration {
                let extra=input.inputs.root.join("registration-apply-extra"); mkdir(&extra)?; original.register(&extra)?;
                require(original.bridge.apply_metadata_text_edit(&original.document,"main",&session.id,&plan.plan_token).is_err(),Failure::UnexpectedStatus)?;
            } else {
                original.document.lost();
                require(!original.document.navigation(true),Failure::DocumentOriginalNavigationAccepted)?;
                require(original.bridge.apply_metadata_text_edit(&original.document,"main",&session.id,&plan.plan_token)
                    .is_err_and(|error| error.code=="invalid_edit_owner"),Failure::DocumentOriginalApplyNotRefused)?;
                require(original.bridge.open_metadata_text_edit(&original.document,"main",selection.open(&project))
                    .is_err_and(|error| error.code=="invalid_edit_owner"),Failure::DocumentOriginalOpenNotRefused)?;
                let replacement=DocumentBinding::new(original.bridge.clone());
                // Initial navigation is allowed, not an edit capability. Only
                // Finished asks the SAME registry to bind; its loss is final.
                require(replacement.navigation(true),Failure::DocumentReplacementNavigationRefused)?;
                replacement.observe(|life| life.started(true)); replacement.hook_installed();
                let mut bound=true;
                replacement.observe(|life| { bound=life.original_bound(); crate::document_lifetime::DocumentAction::None });
                require(!bound,Failure::DocumentReplacementPrematurelyBound)?;
                replacement.observe(|life| life.finished(true));
                replacement.observe(|life| { bound=life.original_bound(); crate::document_lifetime::DocumentAction::None });
                require(!bound,Failure::DocumentReplacementRebound)?;
                require(original.bridge.apply_metadata_text_edit(&replacement,"main",&session.id,&plan.plan_token)
                    .is_err_and(|error| error.code=="invalid_edit_owner"),Failure::DocumentReplacementApplyNotRefused)?;
                require(original.bridge.open_metadata_text_edit(&replacement,"main",selection.open(&project))
                    .is_err_and(|error| error.code=="invalid_edit_owner"),Failure::DocumentReplacementOpenNotRefused)?;
            }
            let terminal=observed_metadata(&original.batch.owner,&session.id,Phase::Final,false).await?;
            settled_terminal(&original.batch.owner,&terminal)?; correlated(&terminal,&editing,&plan)?;
            let facts=original_facts(&session)?; let core=terminal.core_outcome.as_ref().ok_or(Failure::UnexpectedOutcome)?;
            require((facts.request_frames,facts.response_frames)==(2,3) && session.fixture_schedule.sequence()==Some(1)
                && !terminal.apply_submitted && terminal.native_reason==if case==Case::Registration { Reason::CallerLost } else { Reason::WindowLost }
                && core.effect==Effect::NotStarted && core.journal==Journal::NotCreated && core.resources==ResourceState::Settled
                && matches!(core.reason,CoreReason::Cancelled|CoreReason::None) && snapshot(&root)?==before,Failure::UnexpectedOutcome)?;
            return row(original,case.name(),selection,Some(native_data(&session,&terminal,None)?),json!({"preparedCorrelationRetained":true,
                "treeUnchanged":true,"staleCommandNotSent":true,"newRegistrationPublishedUnderDocumentLock":case==Case::Registration,
                "controlledOriginalDocumentLoss":case==Case::DocumentLost,"replacementDocumentRefused":case==Case::DocumentLost,
                "guiCallbacksNotClaimed":true,"sourceProbesSettled":probes_settled(),"passiveOriginalsSettled":original.passive.settled()}));
        }
        let mut gate=if case==Case::HeldTerminal {
            let guard=GateGuard::new(&original.batch.owner,session.fixture_schedule.clone()); session.fixture_schedule.terminal.hold()?; Some(guard)
        } else { None };
        let reply=original.bridge.apply_metadata_text_edit(&original.document,"main",&session.id,&plan.plan_token).map_err(|_| Failure::NativeCommandRejected)?;
        require(select(&reply,&session.id)?.apply_submitted,Failure::UnexpectedStatus)?;
        if case==Case::AndroidCreate {
            let duplicate=original.bridge.apply_metadata_text_edit(&original.document,"main",&session.id,&plan.plan_token).map_err(|_| Failure::NativeCommandRejected)?;
            require(select(&duplicate,&session.id)?.apply_submitted && original.batch.originals.len()==edit_count+1,Failure::UnexpectedStatus)?;
        }
        if let Some(guard)=gate.as_mut() {
            let (active,cleanup)=original_clock(&original.batch,&session)?; let endpoint=active.ok_or(Failure::UnexpectedStatus)?;
            require(cleanup.is_none(),Failure::UnexpectedStatus)?;
            until(OBSERVATION,|| {
                require(!session.fixture_schedule.failed.load(Ordering::SeqCst),Failure::OriginalCustodyUnknown)?;
                Ok(session.fixture_schedule.terminal.entered.load(Ordering::SeqCst))
            }).await?;
            let held=session.fixture_schedule.held_terminal.lock().map_err(|_| Failure::OriginalCustodyUnknown)?.clone().ok_or(Failure::UnexpectedStatus)?;
            require(held.0==2 && held.1.effect==Effect::Committed && held.1.journal==Journal::Clean && held.1.resources==ResourceState::Settled
                && held.1.reason==CoreReason::None && session.fixture_schedule.sequence().is_none()
                && Instant::now()<endpoint && !*session.stop.borrow(),Failure::UnexpectedOutcome)?;
            let closing=original.batch.owner.close_metadata_text("main",&session.id).map_err(|_| Failure::NativeCommandRejected)?;
            require(select(&closing,&session.id)?.native_reason==Reason::Cancelled && *session.stop.borrow(),Failure::UnexpectedStatus)?;
            guard.release(); // Real Close precedes release of that same reader.
        }
        let terminal=observed_metadata(&original.batch.owner,&session.id,Phase::Final,false).await?;
        settled_terminal(&original.batch.owner,&terminal)?; correlated(&terminal,&editing,&plan)?;
        let facts=original_facts(&session)?; let core=terminal.core_outcome.as_ref().ok_or(Failure::UnexpectedOutcome)?;
        let preserved=plan.view.files.iter().filter(|f| f.action==metadata_wire::Action::Preserve).count();
        let created=plan.view.files.iter().filter(|f| f.action==metadata_wire::Action::Create).count();
        let replaced=plan.view.files.len()-created-preserved;
        let noop=matches!(case,Case::AndroidNoop|Case::IosNoop);
        require((facts.request_frames,facts.response_frames)==(3,3) && session.fixture_schedule.sequence()==Some(2)
            && terminal.apply_submitted && terminal.native_reason==if case==Case::HeldTerminal { Reason::Cancelled } else { Reason::None }
            && core.effect==if noop { Effect::Unchanged } else { Effect::Committed }
            && core.journal==if noop { Journal::NotCreated } else { Journal::Clean }
            && core.resources==ResourceState::Settled && core.reason==CoreReason::None
            && session.fixture_schedule.released(),Failure::UnexpectedOutcome)?;
        installed(&root,&before,selection,&directories)?;
        if noop { require(snapshot(&root)?==before && preserved==selection.names().len(),Failure::PayloadMismatch)?; }
        if case==Case::AndroidReplace { require((created,replaced,preserved)==(0,1,2),Failure::UnexpectedOutcome)?; }
        if case==Case::IosMixed { require((created,replaced,preserved)==(1,2,2),Failure::UnexpectedOutcome)?; }
        let config=original.batch.owner.status().map_err(|_| Failure::UnexpectedStatus)?;
        let workflow=original.batch.owner.workflow_status().map_err(|_| Failure::UnexpectedStatus)?;
        let metadata=original.batch.owner.metadata_text_status().map_err(|_| Failure::UnexpectedStatus)?;
        require(config.last_terminal.is_none() && workflow.last_terminal.is_none()
            && metadata.last_terminal.as_ref().is_some_and(|p| p.session_id==session.id)
            && config.status_revision==workflow.status_revision && workflow.status_revision==metadata.status_revision,Failure::UnexpectedStatus)?;
        let observations=json!({"created":created,"replaced":replaced,"preserved":preserved,"directoriesCreated":directories,
            "completePreparedBytes":true,"passiveBaselineMatchedCheckout":true,"preparedCorrelationRetained":true,
            "capturePrepareRawFactsUnchanged":true,"unselectedAndDependenciesPreserved":true,"existingModesPreserved":true,
            "createModesMasked":true,"directoryModesExact":true,"rawNoopUnchanged":noop,"duplicateApplyObservation":case==Case::AndroidCreate,
            "catalogueResourceMatched":case==Case::AndroidCreate||input.mode==Mode::Zip,"sharedStatusRevision":true,"sharedLastTerminalDomainCorrect":true,
            "threeDomainIsolation":case==Case::Isolation,"domains":legacy,"heldBeforeAcceptance":case==Case::HeldTerminal,
            "realStopBeforeRelease":case==Case::HeldTerminal,"cancelledNotSaved":case==Case::HeldTerminal,
            "sourceProbesSettled":probes_settled(),"passiveOriginalsSettled":original.passive.settled()});
        row(original,case.name(),selection,Some(native_data(&session,&terminal,None)?),observations)
    }

    fn eof_seed(input:&Admitted,case:EofCase) -> Check<PathBuf> {
        let selection=eof_selection(case); let root=input.inputs.root.join(case.name());
        seed_common(&root,selection,true)?;
        if case!=EofCase::MetadataConflict {
            seed_parent(&root,&selection.parent())?;
            for (index,text) in selection.texts().iter().enumerate() {
                let bytes=if index==0 { if selection.platform==Platform::Android { OLD_ANDROID_TITLE.as_bytes() } else { OLD_IOS_DESCRIPTION.as_bytes() } }
                    else { text.as_bytes() };
                write_new(&root.join(selection.path(index)),bytes,if index==0 { 0o640 } else { 0o600 })?;
            }
            seed_siblings(&root,selection)?;
        }
        Ok(root)
    }
    fn introduce_sibling(root:&Path,selection:Selection) -> Check<RawFile> {
        FIXTURE_FILES.admit()?;
        let path=root.join(format!("{}/unrelated.txt",selection.parent()));
        let mut file=fs::OpenOptions::new().create_new(true).write(true).mode(0o600).custom_flags(nix::libc::O_NOFOLLOW)
            .open(&path).map_err(|_| Failure::FixtureIo)?;
        FIXTURE_FILES.acquired(); let wrote=file.write_all(UNRELATED); let stat=file.metadata();
        FIXTURE_FILES.close_original(file)?;
        require(wrote.is_ok(),Failure::FixtureIo)?; let stat=stat.map_err(|_| Failure::FixtureIo)?;
        require(stat.is_file() && stat.len()==UNRELATED.len() as u64 && stat.mode()&0o7777==0o600,Failure::FixtureIo)?;
        // No extra reader while the original transaction is held. These are
        // the creating descriptor's own bytes and actual metadata return.
        Ok(RawFile { original:OriginalFile { identity:Identity::of(&stat),bytes:UNRELATED.to_vec() },stamp:Stamp::of(&stat) })
    }
    async fn exercise_eof(original:&mut Original,input:&Admitted,case:EofCase) -> Check<()> {
        require(input.eof && input.mode==Mode::Source && EOF_CASES.contains(&case) && original.queries.is_empty()
            && original.settled() && !original.batch.owner.disabled(),Failure::OriginalCustodyUnknown)?;
        input.inputs.same_root()?;
        let selection=eof_selection(case); let root=eof_seed(input,case)?; let before=snapshot(&root)?;
        let project=original.register(&root)?;
        let passive=original.observe(&project,selection,None).await?.map_err(|_| Failure::UnexpectedOutcome)?;
        observed_roster(&before,selection,&passive)?; original.validate(selection).await?;
        let schedule=Arc::new(Schedule { eof:Some(case),..Schedule::default() });
        {
            let mut next=original.batch.owner.inner.fixture_next_schedule.lock().map_err(|_| Failure::OriginalCustodyUnknown)?;
            require(next.is_none(),Failure::UnexpectedStatus)?; *next=Some(schedule.clone());
        }
        let mut guard=GateGuard::new(&original.batch.owner,schedule.clone());
        let session=original.open(&project,selection)?;
        require(Arc::ptr_eq(&session.fixture_schedule,&schedule),Failure::OriginalCustodyUnknown)?;
        let editing=observed_metadata(&original.batch.owner,&session.id,Phase::Editing,false).await?;
        let checkout=editing.checkout.as_ref().ok_or(Failure::UnexpectedOutcome)?;
        let plan=prepare(original,&session.id,checkout,&passive.baseline,selection).await?;
        let directories=verify_plan(&before,selection,checkout,&plan)?;
        let unknown=case==EofCase::MetadataConflict; let committed=case==EofCase::MetadataPostcommit;
        require(snapshot(&root)?==before && if unknown { directories==ancestors(&selection.parent()) }
            else { directories.is_empty() && plan.view.files.iter().filter(|f| f.action==metadata_wire::Action::Replace).count()==1 },Failure::PayloadMismatch)?;
        let reply=original.bridge.apply_metadata_text_edit(&original.document,"main",&session.id,&plan.plan_token).map_err(|_| Failure::NativeCommandRejected)?;
        require(select(&reply,&session.id)?.apply_submitted,Failure::UnexpectedStatus)?;
        let (active,cleanup)=original_clock(&original.batch,&session)?; let endpoint=active.ok_or(Failure::UnexpectedStatus)?;
        require(cleanup.is_none(),Failure::UnexpectedStatus)?;
        until(OBSERVATION,|| {
            require(!original.batch.owner.disabled() && !schedule.failed.load(Ordering::SeqCst),Failure::OriginalCustodyUnknown)?;
            Ok(schedule.eof_control.lock().map_err(|_| Failure::OriginalCustodyUnknown)?.boundary_only(case))
        }).await?;
        let introduced=if unknown { Some(introduce_sibling(&root,selection)?) } else { None };
        require(Instant::now()<endpoint && !*session.stop.borrow(),Failure::UnexpectedStatus)?;
        let closing=original.batch.owner.close_metadata_text("main",&session.id).map_err(|_| Failure::NativeCommandRejected)?;
        let closing=select(&closing,&session.id)?;
        require(closing.phase==Phase::Finalizing && closing.native_reason==Reason::Cancelled && closing.apply_submitted,Failure::UnexpectedStatus)?;
        guard.release(); // Only the original owner closes the original stdin.
        let terminal=observed_metadata(&original.batch.owner,&session.id,if unknown { Phase::Unknown } else { Phase::Final },unknown).await?;
        let facts=original_eof_facts(&session,case)?;
        correlated(&terminal,&editing,&plan)?;
        let core=terminal.core_outcome.as_ref().ok_or(Failure::UnexpectedOutcome)?;
        require(original.settled() && (facts.request_frames,facts.response_frames)==(3,3) && schedule.sequence()==Some(2)
            && terminal.apply_submitted && terminal.native_reason==Reason::Cancelled
            && core.effect==if unknown { Effect::Unknown } else if committed { Effect::Committed } else { Effect::RolledBack }
            && core.journal==if unknown { Journal::RecoveryRequired } else { Journal::Clean }
            && core.resources==ResourceState::Settled && core.reason==CoreReason::Cancelled
            && schedule.eof_control.lock().is_ok_and(|control| control.complete(case) && control.records(case)==2)
            && schedule.released(),Failure::UnexpectedOutcome)?;
        if unknown {
            // Effect Unknown remains disabled and is NOT ordinary Final. The
            // original resource proof above admits only these fixed DATA reads
            // and the existing receipt return, never another native operation.
            require(terminal.phase==Phase::Unknown && terminal.native_finality==NativeFinality::Unknown && terminal.late_settled
                && original.batch.owner.disabled() && original.batch.owner.inner.lock().blocked_projects.contains(&project.id),Failure::UnexpectedOutcome)?;
            let config=original.batch.owner.status().map_err(|_| Failure::UnexpectedStatus)?;
            let workflow=original.batch.owner.workflow_status().map_err(|_| Failure::UnexpectedStatus)?;
            let metadata=original.batch.owner.metadata_text_status().map_err(|_| Failure::UnexpectedStatus)?;
            require(config.active.is_none() && workflow.active.is_none() && metadata.active.is_none()
                && config.capability.reason==EditAvailability::CleanupUnknown && workflow.capability.reason==EditAvailability::CleanupUnknown
                && metadata.capability.reason==EditAvailability::CleanupUnknown && config.status_revision==workflow.status_revision
                && workflow.status_revision==metadata.status_revision,Failure::UnexpectedStatus)?;
            let sibling=raw_file(&root.join(format!("{}/unrelated.txt",selection.parent())),1024)?;
            require(introduced.as_ref()==Some(&sibling),Failure::PayloadMismatch)?;
            for (index,text) in selection.texts().iter().enumerate() {
                let installed=read_regular(&root.join(selection.path(index)),32*1024)?;
                require(installed.bytes==text.as_bytes() && installed.identity.mode&0o7777==0o600,Failure::PayloadMismatch)?;
            }
            require(fs::symlink_metadata(root.join(".mobile-release-metadata-text")).is_ok_and(|stat| stat.is_dir()),Failure::PayloadMismatch)?;
            for (path,file) in &before.files { require(raw_file(&root.join(path),1024*1024)?==*file,Failure::PayloadMismatch)?; }
            for (path,identity) in &before.directories {
                require(Identity::of(&fs::symlink_metadata(root.join(path)).map_err(|_| Failure::FixtureIo)?)==*identity,Failure::PayloadMismatch)?;
            }
        } else {
            settled_terminal(&original.batch.owner,&terminal)?;
            if committed { installed(&root,&before,selection,&directories)?; } else { restored(&root,&before)?; }
        }
        let observations=json!({"evidenceKind":"real-stdin-eof-at-controlled-transaction-boundary","bootstrapMode":"instrumented-genuine-engine",
            "boundary":case.boundary(),"originalCheckpoint":case.checkpoint(),"closeBeforeActiveDeadline":true,"controlRecords":2,
            "actualStdinEof":true,"eofReadCount":1,"nonemptyReadCount":0,"readErrorCount":0,"preparedCorrelationRetained":true,
            "metadataProfileAndControlProof":true,"committedPublication":committed,"rolledBackPublication":!committed&&!unknown,
            "terminalDurable":!unknown,"fixedRecovery":true,"journalClean":!unknown,"journalAbsent":!unknown,
            "originalTreeRestored":!committed&&!unknown,"selectedPayloadsRemain":committed||unknown,"unselectedAndDependenciesPreserved":true,
            "unrelatedIntroducedBeforeEof":unknown,"introducedOriginalPreserved":unknown,"recoveryEvidenceRetained":unknown,
            "sharedBlockedProject":unknown,"allThreeDomainsDisabled":unknown,"noFurtherAdmission":unknown,
            "sourceProbesSettled":probes_settled(),"passiveOriginalsSettled":original.passive.settled(),"fixtureFilesSettled":FIXTURE_FILES.all_settled()});
        row(original,case.name(),selection,Some(native_data(&session,&terminal,Some(case))?),observations)
    }
    fn receipt(input:&Admitted,cases:&[Value],passed:bool,resources:bool,disabled:bool,failure:Option<Failure>) -> Check<()> {
        let expected=if input.eof { EOF_CASES.len() } else if input.mode==Mode::Source { SOURCE_CASES.len() } else { 1 };
        require(!passed || resources && cases.len()==expected && failure.is_none() && disabled==input.eof,Failure::ReceiptIo)?;
        receipt_document(&input.inputs,json!({"schemaVersion":1,"scope":if input.eof { TRANSACTION_SCOPE } else { OWNER_SCOPE },"domain":DOMAIN,
            "status":if passed { "passed" } else { "failed" },"allOwnersSettled":resources&&!disabled,
            "originalResourcesSettled":resources,"ownerDisabled":disabled,"retainedEffectUnknown":passed&&input.eof,
            "failureCode":failure,"bindings":input.inputs.bindings,"cases":cases,"notVerified":NOT_VERIFIED}))
    }
    pub(super) async fn run(eof:bool) {
        if BATCH_CLAIMED.swap(true,Ordering::SeqCst) {
            if !FIXTURE_FILES.all_settled() || !probes_settled() { retain_unknown_runtime().await; return; }
            panic!("hosted metadata batch already claimed");
        }
        let input=match Admitted::admit(eof) {
            Ok(input)=>input,Err(code)=> {
                if !FIXTURE_FILES.all_settled() { retain_unknown_runtime().await; return; }
                panic!("hosted metadata admission refused: {code:?}");
            },
        };
        if receipt(&input,&[],false,false,false,Some(Failure::NotCompleted)).is_err() {
            if !FIXTURE_FILES.all_settled() { retain_unknown_runtime().await; return; }
            panic!("hosted metadata partial receipt unavailable before native work");
        }
        let mut original=match Original::new(&input) {
            Ok(original)=>original,Err(code)=> {
                if !FIXTURE_FILES.all_settled() || !probes_settled() { retain_unknown_runtime().await; return; }
                panic!("hosted metadata original document refused before native work: {code:?}");
            },
        };
        let count=if eof { EOF_CASES.len() } else if input.mode==Mode::Source { SOURCE_CASES.len() } else { 1 };
        for ordinal in 0..count {
            let case_name=if eof { EOF_CASES[ordinal].name() } else if input.mode==Mode::Zip { Case::IosMixed.name() } else { SOURCE_CASES[ordinal].name() };
            let result=if eof { exercise_eof(&mut original,&input,EOF_CASES[ordinal]).await }
                else { exercise_owner(&mut original,&input,if input.mode==Mode::Zip { Case::IosMixed } else { SOURCE_CASES[ordinal] }).await };
            let expected_unknown=eof && ordinal==EOF_CASES.len()-1 && result.is_ok();
            if result.is_err() || !original.settled() || original.batch.owner.disabled()&&!expected_unknown { original.stop().await; }
            if !original.settled() || original.batch.owner.disabled()&&!expected_unknown
                || matches!(result,Err(Failure::OriginalCustodyUnknown|Failure::FixtureCustodyUnknown)) {
                if FIXTURE_FILES.all_settled() && probes_settled() && original.passive.settled() {
                    let _=receipt(&input,&original.batch.cases,false,false,original.batch.owner.disabled(),Some(Failure::OriginalCustodyUnknown));
                }
                retain_unknown_runtime().await; return;
            }
            if let Err(code)=result {
                let _=receipt(&input,&original.batch.cases,false,true,original.batch.owner.disabled(),Some(code));
                if !FIXTURE_FILES.all_settled() { retain_unknown_runtime().await; return; }
                panic!("hosted metadata {case_name} failed after original resource settlement: {code:?}");
            }
            if !expected_unknown && receipt(&input,&original.batch.cases,false,false,false,Some(Failure::NotCompleted)).is_err() {
                if !FIXTURE_FILES.all_settled() { retain_unknown_runtime().await; return; }
                panic!("hosted metadata progress receipt failed after original settlement");
            }
        }
        // No shutdown, fixture change, recovery or next native operation after
        // EOF's expected effect Unknown. Retain those exact original books.
        if !eof && (original.batch.owner.shutdown().await.is_err() || original.bridge.supervisor.shutdown().await.is_err())
            || !original.settled() { retain_unknown_runtime().await; return; }
        if receipt(&input,&original.batch.cases,true,true,original.batch.owner.disabled(),None).is_err() {
            if !FIXTURE_FILES.all_settled() { retain_unknown_runtime().await; return; }
            panic!("hosted metadata final receipt failed after original settlement");
        }
    }

    #[test]
    fn metadata_fixture_literal_and_scope_contract_is_closed() {
        // Literal DATA/grammar only. These assertions start no owner or IO.
        assert!(!qualified(EditDomain::MetadataText,false)); assert!(!qualified(EditDomain::MetadataText,true));
        assert_eq!(SOURCE_CASES.len(),14); assert_eq!(SOURCE_CASES.last().map(|case| case.name()),Some("metadata-document-loss-before-apply"));
        assert_eq!(Case::IosMixed.name(),"ios-observe-mixed-create-replace-preserve");
        assert_eq!(hash(CONFIG_PUBLIC),"1b0b02e48d03cca36aaf36e5d8a8daf15f59924803bd4a5c0ec2e655828d3f94");
        assert_eq!(hash(CONFIG_RELEASE),"caabad94b27c616e9deaf8570ded7edca9a41de86ca3e1982ab6e4a3f57073f1");
        assert_eq!(hash(IGNORE),"e60087ecefac81e23666444e6aea9490b3fc42b2510f566cfd4aa5a36a35b7d4");
        assert_eq!(hash_fields(Platform::Android,false),json!({
            "title.txt":"17c61ad21566db1d3e8bc33087e2ea25eced56a923addd81a3a80305dea3ee94",
            "short_description.txt":"233524e36ed836f2fc5b2754e73ff6f125f443d1bb57770942368c2fb90a0c63",
            "full_description.txt":"52002e38814d0b0a78bc21cad572d5fa265ad3f9f72a672829982e889a4422fa"}));
        assert_eq!(hash_fields(Platform::Ios,false),json!({
            "description.txt":"417b4365404b44f1c83e478dbebb43864924c858fcca7346aac4db1b9f2c6ee5",
            "keywords.txt":"d563110a53a8d4b4e320f549a957fcbc6d0f8ca14a02f77dfce9bdfaa2e0f866",
            "privacy_url.txt":"5cb73fc576bb124e3930e583584ad86d8052264a12c273cf207874b3c82aa5ee",
            "support_url.txt":"0cf21b6bc2716d68e9e9b41edda65445ab46e022fa94eeaa150c3c4045da1104",
            "release_notes.txt":"4ec8e8f6389b0ece64c0f2ada003d134934dccba9c942ebbdfbadeb18c2ae5c9"}));
        assert!(MetadataFixturePermit::bootstrap_case(false,Path::new("/inert/owner"),None));
        assert!(!MetadataFixturePermit::bootstrap_case(true,Path::new("/inert/owner"),None));
        for case in EOF_CASES {
            let path=Path::new("/inert").join(case.name());
            assert!(MetadataFixturePermit::bootstrap_case(true,&path,Some(case)));
            assert!(!MetadataFixturePermit::bootstrap_case(false,&path,Some(case)));
            assert!(!MetadataFixturePermit::bootstrap_case(true,Path::new("/inert/wrong"),Some(case)));
            assert!(!WorkflowFixturePermit::bootstrap_case(true,&path,Some(case)));
        }
        for case in [EofCase::Precommit,EofCase::Postcommit,EofCase::WorkflowPrecommit,EofCase::WorkflowPostcommit,EofCase::WorkflowConflict] {
            assert!(!MetadataFixturePermit::bootstrap_case(true,&Path::new("/inert").join(case.name()),Some(case)));
        }
        assert_eq!(EXTRA_SOURCES.len(),28);
        let mut keys=BTreeSet::new();
        for source in SOURCES.iter().chain(EXTRA_SOURCES) { assert!(keys.insert(source.id)); }
        assert_eq!(keys.len(),54);
    }
}

#[cfg(all(debug_assertions, not(feature = "desktop-shell"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "only the reviewed disposable source-or-ZIP Linux metadata-owner process"]
async fn hosted_metadata_text_edit_owner_original_resources() { metadata::run(false).await; }

#[cfg(all(debug_assertions, not(feature = "desktop-shell"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "only the reviewed disposable Linux metadata transaction EOF process"]
async fn hosted_metadata_text_transaction_eof_original_resources() { metadata::run(true).await; }

#[test]
fn metadata_eof_records_are_domain_distinct_and_exact() {
    // Same original streaming observer, inert fixed bytes only.
    let all=[EofCase::Precommit,EofCase::Postcommit,EofCase::WorkflowPrecommit,EofCase::WorkflowPostcommit,EofCase::WorkflowConflict,
        EofCase::MetadataPrecommit,EofCase::MetadataPostcommit,EofCase::MetadataConflict];
    for case in [EofCase::MetadataPrecommit,EofCase::MetadataPostcommit,EofCase::MetadataConflict] {
        assert!(case.domain()==EditDomain::MetadataText);
        let bytes=[case.marker(),case.summary()].concat();
        for width in [1,2,7,case.marker().len(),bytes.len()] {
            let mut control=EofControl::default();
            for chunk in bytes.chunks(width) { assert!(control.observe(case,chunk)); }
            assert!(control.complete(case)); assert_eq!(control.records(case),2); assert!(!control.observe(case,b"\n"));
        }
        for other in all {
            if other==case { continue; }
            let mut control=EofControl::default(); assert!(!control.observe(case,other.marker()));
        }
        for end in 0..bytes.len() {
            let mut control=EofControl::default(); assert!(control.observe(case,&bytes[..end])); assert!(!control.complete(case));
        }
        for index in 0..bytes.len() {
            let mut wrong=bytes.clone(); wrong[index]=b'!';
            let mut control=EofControl::default(); assert!(!control.observe(case,&wrong));
        }
    }
}

// One finite release-version branch of the existing original-owner fixture.
// SOURCE-only preparation does not enable installed or general editing.
#[cfg(all(debug_assertions, not(feature = "desktop-shell"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
mod version {
    use super::*;
    use crate::{asset_session::DocumentBinding, asset_source::{self, SourceBook}, bridge::{DesktopBridge, Project},
        release_version_edit_commands, protocol::Method, supervisor::metadata_fixture_probe::Probe};

    const OWNER_SCOPE: &str = "release-version-owner-hosted-v1";
    const TRANSACTION_SCOPE: &str = "release-version-transaction-eof-hosted-v1";
    const DOMAIN: &str = "release_version";
    const REFERENCE: &str = "refs/heads/verify/desktop-release-version-apply-native";
    const WORKFLOW_PATH: &str = ".github/workflows/desktop-github-workflow-apply-native.yml";
    const WORKFLOW_SOURCE: &[u8] = include_bytes!("../../../.github/workflows/desktop-github-workflow-apply-native.yml");
    const RESOURCE: &[u8] = include_bytes!("../../../src/mobile_release/api/data/release-version-help-v1.json");
    const SCHEMA: &[u8] = include_bytes!("../../../src/mobile_release/api/data/project.schema.json");
    const UMASK_PROBE: &[u8] = b"fixed version fixture umask\n";
    const CONFIG_PUBLIC: &[u8] = concat!(r#"{"android":{"applicationId":"org.fixture.app","enabled":true,"identityStatus":"unverified"},"ios":{"bundleId":"org.fixture.app","enabled":true,"identityStatus":"unverified"},"metadata":{"androidLocales":["en-US","fr-FR"],"iosLocales":["en-US"],"root":"public/store"},"projectChecks":{"androidArtifact":[],"iosArtifact":[],"preflight":[]},"schemaVersion":1,"services":{"androidFirebase":"disabled","iosFirebase":"disabled"},"source":{"candidateBranch":"main","productionBranch":"production"},"version":{"buildKey":"BUILD_NUMBER","nameKey":"VERSION_NAME","source":"public/version.properties"}}"#, "\n").as_bytes();
    const CONFIG_RELEASE: &[u8] = concat!(r#"{"android":{"applicationId":"org.fixture.app","enabled":true,"identityStatus":"unverified"},"ios":{"bundleId":"org.fixture.app","enabled":true,"identityStatus":"unverified"},"metadata":{"androidLocales":["en-US","fr-FR"],"iosLocales":["en-US"],"root":"public/store"},"projectChecks":{"androidArtifact":[],"iosArtifact":[],"preflight":[]},"schemaVersion":1,"services":{"androidFirebase":"disabled","iosFirebase":"disabled"},"source":{"candidateBranch":"main","productionBranch":"production"},"version":{"buildKey":"BUILD_NUMBER","nameKey":"VERSION_NAME","source":"release/version.properties"}}"#, "\n").as_bytes();
    const CONFIG_NESTED: &[u8] = concat!(r#"{"android":{"applicationId":"org.fixture.app","enabled":true,"identityStatus":"unverified"},"ios":{"bundleId":"org.fixture.app","enabled":true,"identityStatus":"unverified"},"metadata":{"androidLocales":["en-US","fr-FR"],"iosLocales":["en-US"],"root":"public/store"},"projectChecks":{"androidArtifact":[],"iosArtifact":[],"preflight":[]},"schemaVersion":1,"services":{"androidFirebase":"disabled","iosFirebase":"disabled"},"source":{"candidateBranch":"main","productionBranch":"production"},"version":{"buildKey":"BUILD_NUMBER","nameKey":"VERSION_NAME","source":"public/version-tree/version.properties"}}"#, "\n").as_bytes();
    const ORIGINAL: &[u8] = "# Café\r\n VERSION_NAME = '1.2.3' \nBUILD_NUMBER = \"7\"\r\nOTHER = keep".as_bytes();
    const EDITED: &[u8] = "# Café\r\n VERSION_NAME = '2.3.4' \nBUILD_NUMBER = \"8\"\r\nOTHER = keep".as_bytes();
    const CREATED: &[u8] = "VERSION_NAME=2.3.4\nBUILD_NUMBER=8\n".as_bytes();
    const EOF_ORIGINAL: &[u8] = "# Keep this comment\r\n VERSION_NAME = '1.2.3' \nBUILD_NUMBER = \"7\"\r\nOTHER = keep".as_bytes();
    const EOF_EDITED: &[u8] = "# Keep this comment\r\n VERSION_NAME = '2.3.4' \nBUILD_NUMBER = \"8\"\r\nOTHER = keep".as_bytes();

    const NOT_VERIFIED: &[&str] = &["production-runtime-custody","production-version-save-enablement","native-gui",
        "webview-callbacks-or-crash-hook","parent-death","native-stuck-wait-close","persisted-recovery",
        "macos-windows-version-writes","credentials","remote-github","stores","mobile-builds","installers"];
    const EXTRA_SOURCES: &[Source] = &[
        Source { id:"metadataProtocol", relative:"desktop/src-tauri/src/metadata_text_edit_protocol.rs", compiled:include_bytes!("metadata_text_edit_protocol.rs") },
        Source { id:"metadataCommands", relative:"desktop/src-tauri/src/metadata_text_commands.rs", compiled:include_bytes!("metadata_text_commands.rs") },
        Source { id:"workflowProtocol", relative:"desktop/src-tauri/src/github_workflow_edit_protocol.rs", compiled:include_bytes!("github_workflow_edit_protocol.rs") },
        Source { id:"bridge", relative:"desktop/src-tauri/src/bridge.rs", compiled:include_bytes!("bridge.rs") },
        Source { id:"documentBinding", relative:"desktop/src-tauri/src/asset_session.rs", compiled:include_bytes!("asset_session.rs") },
        Source { id:"documentLifetime", relative:"desktop/src-tauri/src/document_lifetime.rs", compiled:include_bytes!("document_lifetime.rs") },
        Source { id:"assetSource", relative:"desktop/src-tauri/src/asset_source.rs", compiled:include_bytes!("asset_source.rs") },
        Source { id:"assetCommands", relative:"desktop/src-tauri/src/asset_commands.rs", compiled:include_bytes!("asset_commands.rs") },
        Source { id:"supervisor", relative:"desktop/src-tauri/src/supervisor.rs", compiled:include_bytes!("supervisor.rs") },
        Source { id:"passiveFixture", relative:"desktop/src-tauri/src/hosted_tests.rs", compiled:include_bytes!("hosted_tests.rs") },
        Source { id:"editCommands", relative:"desktop/src-tauri/src/edit_commands.rs", compiled:include_bytes!("edit_commands.rs") },
        Source { id:"githubCommands", relative:"desktop/src-tauri/src/github_commands.rs", compiled:include_bytes!("github_commands.rs") },
        Source { id:"workflowEdit", relative:"src/mobile_release/github_workflow_edit.py", compiled:include_bytes!("../../../src/mobile_release/github_workflow_edit.py") },
        Source { id:"metadataEdit", relative:"src/mobile_release/metadata_text_edit.py", compiled:include_bytes!("../../../src/mobile_release/metadata_text_edit.py") },
        Source { id:"metadataText", relative:"src/mobile_release/metadata_text.py", compiled:include_bytes!("../../../src/mobile_release/metadata_text.py") },
        Source { id:"metadataPolicy", relative:"src/mobile_release/metadata.py", compiled:include_bytes!("../../../src/mobile_release/metadata.py") },
        Source { id:"metadataApi", relative:"src/mobile_release/api/_metadata_text.py", compiled:include_bytes!("../../../src/mobile_release/api/_metadata_text.py") },
        Source { id:"passiveEngine", relative:"src/mobile_release/_desktop_engine.py", compiled:include_bytes!("../../../src/mobile_release/_desktop_engine.py") },
        Source { id:"catalogue", relative:"src/mobile_release/api/_catalog.py", compiled:include_bytes!("../../../src/mobile_release/api/_catalog.py") },
        Source { id:"apiContracts", relative:"src/mobile_release/api/contracts.py", compiled:include_bytes!("../../../src/mobile_release/api/contracts.py") },
        Source { id:"snapshot", relative:"src/mobile_release/api/_snapshot.py", compiled:include_bytes!("../../../src/mobile_release/api/_snapshot.py") },
        Source { id:"metadataResource", relative:"src/mobile_release/api/data/metadata-text-help-v1.json", compiled:include_bytes!("../../../src/mobile_release/api/data/metadata-text-help-v1.json") },
        Source { id:"schemaResource", relative:"src/mobile_release/api/data/project.schema.json", compiled:SCHEMA },
        Source { id:"versionProtocol", relative:"desktop/src-tauri/src/release_version_edit_protocol.rs", compiled:include_bytes!("release_version_edit_protocol.rs") },
        Source { id:"versionCommands", relative:"desktop/src-tauri/src/release_version_edit_commands.rs", compiled:include_bytes!("release_version_edit_commands.rs") },
        Source { id:"versionEdit", relative:"src/mobile_release/release_version_edit.py", compiled:include_bytes!("../../../src/mobile_release/release_version_edit.py") },
        Source { id:"versionText", relative:"src/mobile_release/version_text.py", compiled:include_bytes!("../../../src/mobile_release/version_text.py") },
        Source { id:"versionResource", relative:"src/mobile_release/api/data/release-version-help-v1.json", compiled:RESOURCE },
        Source { id:"versionObservation", relative:"desktop/src-tauri/src/release_version_protocol.rs", compiled:include_bytes!("release_version_protocol.rs") },
        Source { id:"versionObservationApi", relative:"src/mobile_release/api/_release_version.py", compiled:include_bytes!("../../../src/mobile_release/api/_release_version.py") },
    ];
    static PROBES: Mutex<Vec<SourceBook>> = Mutex::new(Vec::new());
    fn probes_settled() -> bool { PROBES.lock().is_ok_and(|books| books.iter().all(SourceBook::settled)) }

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Mode { Source, Zip }
    impl Mode { fn name(self) -> &'static str { if self == Self::Source { "source" } else { "zip" } } }

    #[derive(Clone,Copy,PartialEq,Eq)]
    enum Case { Create, Edit, Noop, Stale, Isolation, Registration, HeldTerminal, DocumentLost }
    impl Case {
        fn name(self) -> &'static str {
            match self { Self::Create=>"explicit-absent-create", Self::Edit=>"observe-edit-two-spans-preserve",
                Self::Noop=>"observe-noop-original-leaf", Self::Stale=>"stale-passive-baseline-refused",
                Self::Isolation=>"four-domain-owner-and-token-isolation", Self::Registration=>"registration-changed-before-apply",
                Self::HeldTerminal=>"version-terminal-held-after-stop", Self::DocumentLost=>"version-document-loss-before-apply" }
        }
        fn selection(self) -> Selection { if self==Self::Create { Selection::Nested } else { Selection::Public } }
    }
    const SOURCE_CASES: [Case;8]=[Case::Create,Case::Edit,Case::Noop,Case::Stale,Case::Isolation,Case::Registration,Case::HeldTerminal,Case::DocumentLost];
    const EOF_CASES: [EofCase;3]=[EofCase::VersionPrecommit,EofCase::VersionPostcommit,EofCase::VersionConflict];
    #[derive(Clone,Copy,PartialEq,Eq)]
    enum Selection { Public, Release, Nested }
    impl Selection {
        fn source(self) -> &'static str { match self { Self::Public=>"public/version.properties",
            Self::Release=>"release/version.properties",Self::Nested=>"public/version-tree/version.properties" } }
        fn parent(self) -> &'static str { match self { Self::Public=>"public",Self::Release=>"release",Self::Nested=>"public/version-tree" } }
        fn config(self) -> &'static [u8] { match self { Self::Public=>CONFIG_PUBLIC,Self::Release=>CONFIG_RELEASE,Self::Nested=>CONFIG_NESTED } }
    }
    fn eof_selection(case:EofCase) -> Selection { if case==EofCase::VersionPostcommit { Selection::Release } else { Selection::Public } }
    fn values() -> version_wire::Values { version_wire::Values { name:"2.3.4".into(),build:"8".into() } }
    fn open_args(project:&Project) -> release_version_edit_commands::Open { release_version_edit_commands::Open { project_id:project.id.clone() } }
    fn payload_bindings() -> Value {
        json!({"configHashes":{"publicVersion":hash(CONFIG_PUBLIC),"releaseVersion":hash(CONFIG_RELEASE),"nestedVersion":hash(CONFIG_NESTED)},
            "ignoreSha256":hash(IGNORE),"versionHashes":{"original":hash(ORIGINAL),"edited":hash(EDITED),"created":hash(CREATED),
                "eofOriginal":hash(EOF_ORIGINAL),"eofEdited":hash(EOF_EDITED)},
            "unrelatedSha256":hash(UNRELATED),"umaskProbeSha256":hash(UMASK_PROBE)})
    }
    struct Admitted { inputs:Inputs,mode:Mode,eof:bool,python:PathBuf,core:PathBuf,repository:PathBuf,roots:Vec<PathBuf> }
    fn source_entry(path:&str) -> bool {
        path.starts_with("mobile_release/") && path.len() <= 256 && path.is_ascii()
            && path.split('/').all(|part| !part.is_empty() && part != "." && part != ".."
                && part.bytes().all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c)))
            && [".py",".json",".pem"].iter().any(|suffix| path.ends_with(suffix))
    }
    fn core_binding(repository:&Path,task:&Path,sha:&str) -> Check<Value> {
        require(canonical_input("MRK_DESKTOP_RELEASE_VERSION_CORE_ZIP",true)? == task.join("core.zip")
            && canonical_input("MRK_DESKTOP_RELEASE_VERSION_CORE_METADATA",true)? == task.join("version.json"), Failure::SourceBindingMismatch)?;
        let raw = read_regular(&task.join("version.json"),2*1024*1024)?;
        let value:Value = serde_json::from_slice(&raw.bytes).map_err(|_| Failure::SourceBindingMismatch)?;
        let run = environment("GITHUB_RUN_ID")?;
        let attempt = environment("GITHUB_RUN_ATTEMPT")?;
        let github_repository = environment("GITHUB_REPOSITORY")?;
        require(value.as_object().is_some_and(|fields| fields.len() == 8) && value["sourceSha"].as_str() == Some(sha)
            && value["sourceTree"].as_str().is_some_and(|tree| tree.len() == 40 && tree != "0".repeat(40)
                && tree.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)))
            && !run.is_empty() && run.len() <= 20 && !run.starts_with('0') && run.bytes().all(|c| c.is_ascii_digit())
            && attempt == "1" && environment("GITHUB_EVENT_NAME")? == "push" && environment("MRK_PUSH_EVENT_AFTER")? == sha
            && environment("GITHUB_REF")? == REFERENCE
            && environment("GITHUB_WORKFLOW_SHA")? == sha
            && environment("GITHUB_WORKFLOW_REF")? == format!("{github_repository}/{WORKFLOW_PATH}@{REFERENCE}")
            && value["runId"].as_str() == Some(run.as_str()) && value["attempt"].as_str() == Some(attempt.as_str())
            && value["ref"] == REFERENCE, Failure::SourceBindingMismatch)?;
        let workflow_hash = hash(WORKFLOW_SOURCE);
        require(hash(&read_regular(&repository.join(WORKFLOW_PATH),2*1024*1024)?.bytes) == workflow_hash
            && value["workflowSha256"].as_str() == Some(workflow_hash.as_str()), Failure::SourceBindingMismatch)?;
        let rows = value["coreFiles"].as_array().ok_or(Failure::SourceBindingMismatch)?;
        require(!rows.is_empty() && rows.len() <= 2048,Failure::SourceBindingMismatch)?;
        let mut previous = ""; let mut total = 0usize;
        for row in rows {
            let path = row["path"].as_str().ok_or(Failure::SourceBindingMismatch)?;
            require(row.as_object().is_some_and(|fields| fields.len() == 3) && source_entry(path) && path > previous,Failure::SourceBindingMismatch)?;
            let file = read_regular(&repository.join("src").join(path),8*1024*1024)?;
            total = total.checked_add(file.bytes.len()).ok_or(Failure::SourceBindingMismatch)?;
            require(total <= 32*1024*1024 && row["size"].as_u64() == Some(file.bytes.len() as u64)
                && row["sha256"].as_str() == Some(hash(&file.bytes).as_str()),Failure::SourceBindingMismatch)?;
            previous = path;
        }
        let zip_hash = hash(&read_regular(&task.join("core.zip"),32*1024*1024)?.bytes);
        require(value["coreZipSha256"].as_str() == Some(zip_hash.as_str()),Failure::SourceBindingMismatch)?;
        // The helper owns original Git/inventory/ZIP construction. This binds
        // its exact version and bytes; it does not parse/extract another ZIP.
        Ok(json!({"sourceTree":value["sourceTree"],"workflowSha256":workflow_hash,"runId":run,"attempt":attempt,"ref":REFERENCE,
            "coreZipSha256":zip_hash,"coreInventorySha256":hash(&serde_json::to_vec(rows).map_err(|_| Failure::SourceBindingMismatch)?)}))
    }
    impl Admitted {
        fn admit(eof:bool) -> Check<Self> {
            FIXTURE_FILES.admit()?;
            require(environment("MRK_DESKTOP_RELEASE_VERSION_HOSTED_CHECKS")? == "release-version-v1"
                && environment("GITHUB_ACTIONS")? == "true" && environment("RUNNER_ENVIRONMENT")? == "github-hosted"
                && environment("RUNNER_OS")? == "Linux" && environment("RUNNER_ARCH")? == "X64"
                && crate::runtime::COMPILED_TARGET == "x86_64-unknown-linux-gnu"
                && rustix::process::getuid().as_raw() != 0 && rustix::process::getuid() == rustix::process::geteuid(),Failure::HostedGuardRefused)?;
            let mode = match environment("MRK_DESKTOP_RELEASE_VERSION_INPUT")?.as_str() {
                "source" => Mode::Source,"zip" if !eof => Mode::Zip,_ => return Err(Failure::HostedGuardRefused),
            };
            let temporary = canonical_input("RUNNER_TEMP",false)?;
            let root = canonical_input("MRK_DESKTOP_EDIT_TEST_ROOT",true)?;
            let task = root.parent().ok_or(Failure::HostedGuardRefused)?;
            let manifest = Path::new(env!("CARGO_MANIFEST_DIR")).canonicalize().map_err(|_| Failure::HostedGuardRefused)?;
            let repository = manifest.parent().and_then(Path::parent).ok_or(Failure::HostedGuardRefused)?.to_path_buf();
            let name = if eof { "version-transaction-eof" } else if mode == Mode::Source { "version-owner-source" } else { "version-owner-zip" };
            require(root.file_name().and_then(|name| name.to_str()) == Some(name) && task != temporary && task.starts_with(&temporary)
                && std::env::current_dir().map_err(|_| Failure::HostedGuardRefused)? == manifest
                && !root.starts_with(&repository) && !repository.starts_with(&root),Failure::HostedGuardRefused)?;
            let stat = fs::symlink_metadata(&root).map_err(|_| Failure::HostedGuardRefused)?;
            require(stat.is_dir() && stat.mode() & 0o7777 == 0o700 && stat.uid() == rustix::process::geteuid().as_raw()
                && stat.gid() == rustix::process::getegid().as_raw()
                && fs::read_dir(&root).map_err(|_| Failure::HostedGuardRefused)?.next().is_none(),Failure::HostedGuardRefused)?;
            let python = canonical_input("MRK_DESKTOP_DEV_PYTHON",true)?;
            let core = canonical_input("MRK_DESKTOP_DEV_CORE",true)?;
            require(core == if mode == Mode::Source { repository.join("src") } else { task.join("core.zip") }
                && !python.starts_with(task) && !python.starts_with(&repository),Failure::HostedGuardRefused)?;
            let sha = environment("GITHUB_SHA")?;
            require(sha.len() == 40 && sha != "0".repeat(40) && sha.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
                && environment("MRK_DESKTOP_EDIT_SOURCE_SHA")? == sha && option_env!("GITHUB_SHA") == Some(sha.as_str()),Failure::SourceBindingMismatch)?;
            let mut sources = serde_json::Map::new();
            for item in SOURCES.iter().chain(EXTRA_SOURCES).chain(if eof { std::slice::from_ref(&EOF_SOURCE) } else { &[] }) {
                let expected = hash(item.compiled);
                require(hash(&read_regular(&repository.join(item.relative),2*1024*1024)?.bytes) == expected
                    && sources.insert(item.id.into(),json!(expected)).is_none(),Failure::SourceBindingMismatch)?;
            }
            let mut bindings = core_binding(&repository,task,&sha)?;
            bindings["sourceSha"] = json!(sha); bindings["domain"] = json!(DOMAIN); bindings["host"] = json!("linux");
            bindings["target"] = json!(crate::runtime::COMPILED_TARGET); bindings["runtimeMode"] = json!("trusted-development-only");
            bindings["runtimeInput"] = json!(mode.name()); bindings["pythonSha256"] = json!(hash(&read_regular(&python,64*1024*1024)?.bytes));
            bindings["sourceHashes"] = json!(sources); bindings["payloadHashes"] = payload_bindings();
            bindings["versionResourceSha256"] = json!(hash(RESOURCE)); bindings["schemaResourceSha256"] = json!(hash(SCHEMA));
            bindings["inheritedFileMaskObserved"] = json!(true); bindings["requestedCreateMode"] = json!(420);
            bindings["observedCreateMode"] = json!(384); bindings["newDirectoryMode"] = json!(493);
            bindings["documentEvidence"] = json!("controlled-original-lifetime-not-gui-callbacks");
            let roots=if eof { EOF_CASES.iter().map(|case| root.join(case.name())).collect() }
                else if mode==Mode::Zip { vec![root.join(Case::Edit.name())] }
                else { SOURCE_CASES.iter().map(|case| root.join(case.name())).chain([root.join("registration-apply-extra")]).collect() };
            let mut probe = fs::OpenOptions::new().create_new(true).write(true).mode(0o644).open(root.join("umask-check")).map_err(|_| Failure::FixtureIo)?;
            FIXTURE_FILES.acquired(); let wrote=probe.write_all(UMASK_PROBE); FIXTURE_FILES.close_original(probe)?;
            require(wrote.is_ok(),Failure::FixtureIo)?;
            let observed=read_regular(&root.join("umask-check"),128)?;
            require(observed.bytes == UMASK_PROBE && observed.identity.mode & 0o7777 == 0o600,Failure::HostedGuardRefused)?;
            Ok(Self { inputs:Inputs { root,identity:Identity::of(&stat),bindings },mode,eof,python,core,repository,roots })
        }
        fn permit(&self,owner:&EditOwner) -> Check<()> {
            self.inputs.same_root()?;
            require(owner.can_exit() && !owner.disabled() && !owner.inner.hosted_qualified(EditDomain::ReleaseVersion),Failure::HostedGuardRefused)?;
            let mut slot=owner.inner.fixture_version.lock().map_err(|_| Failure::OriginalCustodyUnknown)?;
            require(slot.is_none(),Failure::HostedGuardRefused)?;
            *slot=Some(Arc::new(VersionFixturePermit { owner:Arc::downgrade(&owner.inner),roots:self.roots.clone(),
                python:self.python.clone(),core:self.core.clone(),bootstrap:self.repository.join("desktop/config_edit_bootstrap.py"),
                cwd:self.repository.join("desktop"),binding_sha256:hash(&serde_json::to_vec(&self.inputs.bindings).map_err(|_| Failure::SourceBindingMismatch)?),
                zip:self.mode==Mode::Zip,eof:self.eof }));
            Ok(())
        }
    }
    struct Original { batch:Batch,bridge:Arc<DesktopBridge>,document:DocumentBinding,passive:Arc<Probe>,queries:Vec<Value>,consumed_plan:Option<(String,String)> }
    impl Original {
        fn new(input:&Admitted) -> Check<Self> {
            let bridge=Arc::new(DesktopBridge::new(input.inputs.root.clone()));
            let owner=bridge.edits.clone();
            let passive=Arc::new(Probe::attach(&bridge.supervisor).map_err(|_| Failure::OriginalCustodyUnknown)?);
            {
                let mut retained=RETAINED.lock().map_err(|_| Failure::OriginalCustodyUnknown)?;
                require(retained.is_none(),Failure::OriginalCustodyUnknown)?;
                let mut retention=Retention::new(&owner);
                retention.metadata_passive=Some((bridge.clone(),passive.clone()));
                *retained=Some(retention); // Before any real passive/edit query.
            }
            input.permit(&owner)?;
            let document=DocumentBinding::new(bridge.clone());
            require(document.navigation(true),Failure::NativeCommandRejected)?;
            document.observe(|life| life.started(true)); document.hook_installed(); document.observe(|life| life.finished(true));
            require(owner.release_version_status().is_ok_and(|status| status.capability.available)
                && !owner.inner.hosted_qualified(EditDomain::Configuration) && !owner.inner.hosted_qualified(EditDomain::GitHubWorkflows)
                && !owner.inner.hosted_qualified(EditDomain::MetadataText),Failure::NativeCommandRejected)?;
            Ok(Self { batch:Batch { owner,originals:Vec::new(),missing_original:false,cases:Vec::new() },bridge,document,passive,queries:Vec::new(),consumed_plan:None })
        }
        fn settled(&self) -> bool {
            FIXTURE_FILES.all_settled() && probes_settled() && self.passive.settled() && !self.batch.missing_original
                && self.batch.owner.can_exit() && self.batch.originals.iter().all(|original| match original.fixture_schedule.eof_case() {
                    Some(case) => original_eof_facts(original,case).is_ok(),None => original_facts(original).is_ok(),
                })
        }
        fn register(&self,root:&Path) -> Check<Project> {
            require(FIXTURE_FILES.all_settled() && probes_settled() && self.passive.settled(),Failure::OriginalCustodyUnknown)?;
            let generation=self.bridge.native_generation().map_err(|_| Failure::NativeCommandRejected)?;
            let (proof,settled)={
                let mut books=PROBES.lock().map_err(|_| Failure::OriginalCustodyUnknown)?;
                require(books.len() < 16,Failure::OriginalCustodyUnknown)?;
                books.push(SourceBook::new()); // Retain the original before acquisition.
                let book=books.last_mut().ok_or(Failure::OriginalCustodyUnknown)?;
                let proof=std::panic::catch_unwind(std::panic::AssertUnwindSafe(||
                    asset_source::probe_project(book,root.to_path_buf(),&[],&mut || false))).map_err(|_| Failure::OriginalCustodyUnknown)?;
                (proof,book.settled())
            };
            require(settled,Failure::OriginalCustodyUnknown)?;
            let project=self.document.version_fixture_publish(proof.map_err(|_| Failure::NativeCommandRejected)?,generation)
                .map_err(|_| Failure::NativeCommandRejected)?;
            let (_,registered)=self.bridge.native_project(&project.id).map_err(|_| Failure::UnexpectedStatus)?;
            let stat=fs::symlink_metadata(root).map_err(|_| Failure::FixtureIo)?;
            let identity=registered.identity.workflow_identity();
            require(registered.path == root && identity.device == stat.dev().to_string() && identity.inode == stat.ino().to_string()
                && identity.mode == stat.mode() && identity.uid == stat.uid() && identity.gid == stat.gid(),Failure::PayloadMismatch)?;
            Ok(project)
        }
        fn retain_open(&mut self) -> Check<Arc<Session>> {
            let original={
                let registry=self.batch.owner.inner.lock();
                if registry.last.as_ref().is_some_and(|last| !self.batch.originals.iter().any(|original| original.id == last.session_id)) {
                    self.batch.missing_original=true;
                }
                registry.active.as_ref().map(|active| active.session.clone())
            };
            let original=original.ok_or_else(|| { self.batch.missing_original=true; Failure::OriginalCustodyUnknown })?;
            self.batch.originals.push(original.clone());
            RETAINED.lock().map_err(|_| Failure::OriginalCustodyUnknown)?.as_mut().ok_or(Failure::OriginalCustodyUnknown)?.originals.push(original.clone());
            Ok(original)
        }
        fn open(&mut self,project:&Project) -> Check<Arc<Session>> {
            require(self.settled() && !self.batch.owner.disabled(),Failure::OriginalCustodyUnknown)?;
            let reply=self.bridge.open_release_version_edit(&self.document,"main",open_args(project));
            let original=self.retain_open()?;
            let status=reply.map_err(|_| Failure::NativeCommandRejected)?;
            require(select(&status,&original.id)?.phase == Phase::Opening && original.domain == EditDomain::ReleaseVersion,Failure::UnexpectedStatus)?;
            Ok(original)
        }

        async fn observe(&mut self,project:&Project) -> Check<Value> {
            require(self.settled() && !self.batch.owner.disabled(),Failure::OriginalCustodyUnknown)?;
            let reply=self.bridge.observe_release_version(&self.document,crate::release_version_protocol::Request { project_id:project.id.clone() }).await;
            self.queries.push(self.passive.next(Method::ReleaseVersionObserve,None).await.map_err(|_| Failure::OriginalCustodyUnknown)?);
            serde_json::to_value(reply.map_err(|_| Failure::UnexpectedOutcome)?).map_err(|_| Failure::PayloadMismatch)
        }
        async fn stop(&self) {
            let _=self.batch.owner.shutdown().await;
            if !self.passive.settled() { let _=self.bridge.supervisor.shutdown().await; }
        }
    }
    fn select(status:&ReleaseVersionEditStatus,id:&str) -> Check<version_wire::Projection> {
        require(status.domain == DOMAIN,Failure::UnexpectedStatus)?;
        status.active.as_ref().filter(|p| p.session_id == id).or_else(|| status.last_terminal.as_ref().filter(|p| p.session_id == id))
            .cloned().ok_or(Failure::UnexpectedStatus)
    }
    async fn observed_version(owner:&EditOwner,id:&str,desired:Phase,expected_unknown:bool) -> Check<version_wire::Projection> {
        let end=Instant::now()+OBSERVATION; let mut revisions=owner.subscribe();
        loop {
            let status=owner.release_version_status().map_err(|_| Failure::OriginalCustodyUnknown)?;
            let current=select(&status,id)?;
            if !expected_unknown {
                require(!owner.disabled() && current.phase != Phase::Unknown && current.native_finality != NativeFinality::Unknown
                    && !current.late_settled,Failure::OriginalCustodyUnknown)?;
            }
            if current.phase == desired && (!expected_unknown || status.active.is_none()) { return Ok(current); }
            require(current.phase != Phase::Final,Failure::UnexpectedStatus)?;
            tokio::select! {
                result=revisions.changed() => { result.map_err(|_| Failure::UnexpectedStatus)?; },
                _=tokio::time::sleep_until(tokio::time::Instant::from_std(end)) => return Err(Failure::ObservationTimeout),
            }
        }
    }

    #[derive(Clone,Copy,PartialEq,Eq)]
    struct Stamp { modified:i64,modified_ns:i64,changed:i64,changed_ns:i64 }
    impl Stamp { fn of(value:&fs::Metadata) -> Self { Self { modified:value.mtime(),modified_ns:value.mtime_nsec(),changed:value.ctime(),changed_ns:value.ctime_nsec() } } }
    #[derive(PartialEq,Eq)]
    struct RawFile { original:OriginalFile,stamp:Stamp }
    #[derive(PartialEq,Eq)]
    struct Snapshot { files:std::collections::BTreeMap<String,RawFile>,directories:std::collections::BTreeMap<String,Identity> }
    fn raw_file(path:&Path,limit:u64) -> Check<RawFile> {
        FIXTURE_FILES.admit()?;
        let before=fs::symlink_metadata(path).map_err(|_| Failure::FixtureIo)?;
        let original=read_regular(path,limit)?;
        let after=fs::symlink_metadata(path).map_err(|_| Failure::FixtureIo)?;
        require(Identity::of(&before) == original.identity && Identity::of(&after) == original.identity
            && Stamp::of(&before) == Stamp::of(&after),Failure::PayloadMismatch)?;
        Ok(RawFile { original,stamp:Stamp::of(&before) })
    }
    fn mkdir(path:&Path) -> Check<()> {
        FIXTURE_FILES.admit()?; fs::DirBuilder::new().mode(0o700).create(path).map_err(|_| Failure::FixtureIo)
    }
    fn ancestors(relative:&str) -> Vec<String> {
        let mut result=Vec::new(); let mut path=String::new();
        for part in relative.split('/') { if !path.is_empty() { path.push('/'); } path.push_str(part); result.push(path.clone()); }
        result
    }
    fn seed_parent(root:&Path,parent:&str) -> Check<()> {
        for name in ancestors(parent) {
            FIXTURE_FILES.admit()?;
            match fs::symlink_metadata(root.join(&name)) {
                Ok(stat) => require(stat.is_dir(),Failure::FixtureIo)?,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => mkdir(&root.join(name))?,
                Err(_) => return Err(Failure::FixtureIo),
            }
        }
        Ok(())
    }

    fn fixture_roster() -> (BTreeSet<String>,BTreeSet<String>) {
        let directories=["","release",".github",".github/workflows","public","public/version-tree"]
            .into_iter().map(str::to_owned).collect();
        let leaves=[".gitignore","unrelated.txt","release/mobile-release.json","release/other.txt",".github/workflows/unrelated.txt",
            "public/version.properties","public/version-tree/version.properties","release/version.properties","public/unrelated.txt"]
            .into_iter().map(str::to_owned).collect();
        (directories,leaves)
    }
    fn snapshot(root:&Path) -> Check<Snapshot> {
        let (allowed_directories,allowed_files)=fixture_roster();
        let mut directories=std::collections::BTreeMap::new(); let mut files=std::collections::BTreeMap::new();
        let mut pending=vec![String::new()];
        while let Some(relative)=pending.pop() {
            FIXTURE_FILES.admit()?;
            require(allowed_directories.contains(&relative) && directories.len() < 6,Failure::PayloadMismatch)?;
            let path=root.join(&relative); let stat=fs::symlink_metadata(&path).map_err(|_| Failure::FixtureIo)?;
            require(stat.is_dir(),Failure::PayloadMismatch)?; directories.insert(relative.clone(),Identity::of(&stat));
            let mut count=0;
            for entry in fs::read_dir(path).map_err(|_| Failure::FixtureIo)? {
                count+=1; require(count <= 12,Failure::PayloadMismatch)?;
                let name=entry.map_err(|_| Failure::FixtureIo)?.file_name().into_string().map_err(|_| Failure::PayloadMismatch)?;
                let child=if relative.is_empty() { name } else { format!("{relative}/{name}") };
                let stat=fs::symlink_metadata(root.join(&child)).map_err(|_| Failure::FixtureIo)?;
                if stat.is_dir() { require(allowed_directories.contains(&child),Failure::PayloadMismatch)?; pending.push(child); }
                else {
                    require(allowed_files.contains(&child) && files.len() < 9,Failure::PayloadMismatch)?;
                    let file=raw_file(&root.join(&child),1024*1024)?;
                    require(files.insert(child,file).is_none(),Failure::PayloadMismatch)?;
                }
            }
        }
        Ok(Snapshot { files,directories })
    }

    fn seed_common(root:&Path,selection:Selection) -> Check<()> {
        mkdir(root)?; mkdir(&root.join("release"))?;
        write_new(&root.join("release/mobile-release.json"),selection.config(),0o440)?;
        write_new(&root.join(".gitignore"),IGNORE,0o400)?;
        write_new(&root.join("unrelated.txt"),UNRELATED,0o400)?; write_new(&root.join("release/other.txt"),UNRELATED,0o400)?;
        mkdir(&root.join(".github"))?; mkdir(&root.join(".github/workflows"))?;
        write_new(&root.join(".github/workflows/unrelated.txt"),UNRELATED,0o400)
    }
    fn seed(input:&Admitted,case:Case) -> Check<PathBuf> {
        input.inputs.same_root()?; let selection=case.selection(); let root=input.inputs.root.join(case.name());
        seed_common(&root,selection)?;
        if case!=Case::Create {
            seed_parent(&root,selection.parent())?;
            write_new(&root.join(selection.source()),if case==Case::Noop { EDITED } else { ORIGINAL },0o640)?;
        }
        Ok(root)
    }
    fn rewrite_original(path:&Path,old:&RawFile,bytes:&[u8]) -> Check<()> {
        FIXTURE_FILES.admit()?;
        let mut file=fs::OpenOptions::new().write(true).custom_flags(nix::libc::O_NOFOLLOW).open(path).map_err(|_| Failure::FixtureIo)?;
        FIXTURE_FILES.acquired();
        let result=(|| {
            let opened=file.metadata().map_err(|_| Failure::FixtureIo)?;
            require(Identity::of(&opened) == old.original.identity && Stamp::of(&opened) == old.stamp,Failure::PayloadMismatch)?;
            file.set_len(0).map_err(|_| Failure::FixtureIo)?; file.write_all(bytes).map_err(|_| Failure::FixtureIo)
        })();
        FIXTURE_FILES.close_original(file)?; result
    }

    fn baseline(before:&Snapshot,selection:Selection) -> Check<version_wire::Baseline> {
        let config=&before.files.get("release/mobile-release.json").ok_or(Failure::PayloadMismatch)?.original;
        let saved_version=match before.files.get(selection.source()) {
            Some(file)=>version_wire::BaselineFile::Present { bytes:file.original.bytes.len() as u32,sha256:hash(&file.original.bytes) },
            None=>version_wire::BaselineFile::Absent {},
        };
        Ok(version_wire::Baseline { saved_config:version_wire::ContentDigest { bytes:config.bytes.len() as u32,sha256:hash(&config.bytes) },saved_version })
    }
    fn observed_pair(before:&Snapshot,selection:Selection,value:&Value) -> Check<version_wire::Baseline> {
        let expected=baseline(before,selection)?;
        let saved=&before.files.get(selection.source()).ok_or(Failure::PayloadMismatch)?.original.bytes;
        let current=if saved==ORIGINAL || saved==EOF_ORIGINAL { json!({"name":"1.2.3","build":7}) }
            else if saved==EDITED || saved==EOF_EDITED || saved==CREATED { json!({"name":"2.3.4","build":8}) }
            else { return Err(Failure::PayloadMismatch); };
        require(*value==json!({"schemaVersion":2,"source":selection.source(),"version":current,
            "savedConfig":expected.saved_config,"savedVersion":{"bytes":saved.len(),"sha256":hash(saved)},
            "observationScope":"single-request-non-atomic","assurance":{"basis":"static-text","projectCodeExecuted":false,
                "toolsProbed":false,"credentialsRead":false,"gitObserved":false,"storeContacted":false,"writesPerformed":false,"releaseReadiness":"unknown"}}),
            Failure::UnexpectedOutcome)?;
        Ok(expected)
    }
    fn prepare_args(id:&str,revision:&str,expected:&version_wire::Baseline) -> PrepareReleaseVersionEdit {
        PrepareReleaseVersionEdit { session_id:id.into(),revision:revision.into(),expected_baseline:expected.clone(),
            intent:expected.saved_version.intent(),values:values(),draft_revision:1,baseline_generation:0 }
    }
    async fn prepare(original:&Original,id:&str,checkout:&version_wire::Checkout,expected:&version_wire::Baseline) -> Check<version_wire::Prepared> {
        let reply=original.bridge.prepare_release_version_edit(&original.document,"main",prepare_args(id,&checkout.revision,expected))
            .map_err(|_| Failure::NativeCommandRejected)?;
        require(select(&reply,id)?.phase==Phase::Preparing,Failure::UnexpectedStatus)?;
        observed_version(&original.batch.owner,id,Phase::Reviewing,false).await?.prepared.ok_or(Failure::UnexpectedOutcome)
    }
    fn desired(before:&Snapshot,selection:Selection) -> Check<&'static [u8]> {
        Ok(match before.files.get(selection.source()) {
            None=>CREATED,
            Some(file) if file.original.bytes==ORIGINAL || file.original.bytes==EDITED=>EDITED,
            Some(file) if file.original.bytes==EOF_ORIGINAL=>EOF_EDITED,
            _=>return Err(Failure::PayloadMismatch),
        })
    }
    fn verify_plan(before:&Snapshot,selection:Selection,checkout:&version_wire::Checkout,plan:&version_wire::Prepared) -> Check<Vec<String>> {
        let old=before.files.get(selection.source()); let after=desired(before,selection)?;
        let action=match old { None=>version_wire::Action::Create,Some(file) if file.original.bytes==after=>version_wire::Action::Preserve,
            Some(_)=>version_wire::Action::Replace };
        let before_matches=match (&plan.view.file.before,old) {
            (version_wire::Before::Absent {},None)=>true,
            (version_wire::Before::Present { text,bytes,sha256 },Some(file))=>text.as_bytes()==file.original.bytes
                && *bytes as usize==file.original.bytes.len() && *sha256==hash(&file.original.bytes),_=>false,
        };
        let created:Vec<String>=ancestors(selection.parent()).into_iter().filter(|name| !before.directories.contains_key(name)).collect();
        let expected_styles=if old.is_some() { vec![version_wire::LineStyle::Crlf,version_wire::LineStyle::Lf] } else { vec![] };
        require(checkout.baseline==baseline(before,selection)? && checkout.source==selection.source()
            && checkout.name_key=="VERSION_NAME" && checkout.build_key=="BUILD_NUMBER" && checkout.ios_enabled
            && plan.revision==checkout.revision && plan.draft_revision==1 && plan.baseline_generation==0
            && plan.view.schema_version==1 && plan.view.source==checkout.source && plan.view.name_key==checkout.name_key
            && plan.view.build_key==checkout.build_key && plan.view.ios_enabled==checkout.ios_enabled
            && plan.view.intent==checkout.baseline.saved_version.intent() && plan.view.values==values()
            && plan.view.file.path==selection.source() && plan.view.file.action==action && before_matches
            && plan.view.file.after.text.as_bytes()==after && plan.view.file.after.bytes as usize==after.len()
            && plan.view.file.after.sha256==hash(after) && plan.view.file.preserve_mode==old.is_some()
            && plan.view.file.requested_mode==old.map_or(0o644,|file| file.original.identity.mode&0o777)
            && plan.view.create_directories==created && plan.view.line_endings.before==expected_styles
            && plan.view.line_endings.after==if old.is_some() { expected_styles } else { vec![version_wire::LineStyle::Lf] }
            && !plan.view.line_endings.final_newline_before && plan.view.line_endings.final_newline_after==old.is_none()
            && plan.view.line_endings.preserved==old.is_some() && plan.view.validation.valid
            && plan.view.validation.state=="format-valid" && plan.view.validation.issues.is_empty(),Failure::UnexpectedOutcome)?;
        Ok(created)
    }
    fn installed(root:&Path,before:&Snapshot,selection:Selection,created:&[String]) -> Check<()> {
        let after=snapshot(root)?;
        require(before.directories.iter().all(|(name,old)| after.directories.get(name)==Some(old)),Failure::PayloadMismatch)?;
        for (name,old) in &before.files {
            if name!=selection.source() { require(after.files.get(name)==Some(old),Failure::PayloadMismatch)?; }
        }
        let file=after.files.get(selection.source()).ok_or(Failure::PayloadMismatch)?; let bytes=desired(before,selection)?;
        require(file.original.bytes==bytes,Failure::PayloadMismatch)?;
        match before.files.get(selection.source()) {
            Some(old) if old.original.bytes==bytes=>require(file==old,Failure::PayloadMismatch)?,
            Some(old)=>require(file.original.identity.device==old.original.identity.device && file.original.identity.inode!=old.original.identity.inode
                && file.original.identity.mode==old.original.identity.mode && file.original.identity.owner==old.original.identity.owner
                && file.original.identity.group==old.original.identity.group,Failure::PayloadMismatch)?,
            None=>require(file.original.identity.mode&0o7777==0o600 && file.original.identity.owner==rustix::process::geteuid().as_raw()
                && file.original.identity.group==rustix::process::getegid().as_raw(),Failure::PayloadMismatch)?,
        }
        for name in created { require(after.directories.get(name).is_some_and(|id| id.mode&0o7777==0o755
            && id.owner==rustix::process::geteuid().as_raw() && id.group==rustix::process::getegid().as_raw()),Failure::PayloadMismatch)?; }
        require(after.files.len()==before.files.len()+usize::from(!before.files.contains_key(selection.source()))
            && after.directories.len()==before.directories.len()+created.len(),Failure::PayloadMismatch)
    }
    fn restored(root:&Path,before:&Snapshot) -> Check<()> {
        let after=snapshot(root)?;
        // Own rename/restore may change ctime. Compare original identity, mode,
        // owner, group, bytes and mtime, not a false old-ctime requirement.
        require(after.directories == before.directories && after.files.len() == before.files.len()
            && before.files.iter().all(|(name,old)| after.files.get(name).is_some_and(|new| new.original == old.original
                && new.stamp.modified == old.stamp.modified && new.stamp.modified_ns == old.stamp.modified_ns)),Failure::PayloadMismatch)
    }

    fn settled_terminal(owner:&EditOwner,terminal:&version_wire::Projection) -> Check<()> {
        require(terminal.phase == Phase::Final && terminal.native_finality == NativeFinality::Settled && !terminal.late_settled
            && owner.can_exit() && !owner.disabled(),Failure::OriginalCustodyUnknown)
    }
    fn correlated(terminal:&version_wire::Projection,editing:&version_wire::Projection,plan:&version_wire::Prepared) -> Check<()> {
        require(terminal.domain == DOMAIN && terminal.owner_generation == editing.owner_generation && terminal.session_id == editing.session_id
            && terminal.project_id == editing.project_id
            && terminal.checkout.as_ref().is_some_and(|checkout| editing.checkout.as_ref().is_some_and(|old|
                checkout.revision == old.revision && checkout.source == old.source && checkout.baseline == old.baseline))
            && terminal.prepared.as_ref().is_some_and(|retained| retained.plan_token == plan.plan_token && retained.revision == plan.revision
                && retained.draft_revision == plan.draft_revision && retained.baseline_generation == plan.baseline_generation
                && matches!((serde_json::to_value(&retained.view),serde_json::to_value(&plan.view)),(Ok(actual),Ok(expected)) if actual==expected)),Failure::UnexpectedOutcome)
    }
    fn native_data(session:&Session,terminal:&version_wire::Projection,eof:Option<EofCase>) -> Check<Value> {
        let facts=if let Some(case)=eof { original_eof_facts(session,case)? } else { original_facts(session)? };
        require(terminal.session_id == session.id && session.domain == EditDomain::ReleaseVersion,Failure::UnexpectedStatus)?;
        let mut value=serde_json::to_value(facts).map_err(|_| Failure::ReceiptIo)?;
        value["domain"]=json!(DOMAIN); value["nativePhase"]=json!(terminal.phase); value["nativeFinality"]=json!(terminal.native_finality);
        value["nativeReason"]=json!(terminal.native_reason); value["applySubmitted"]=json!(terminal.apply_submitted);
        value["lateSettled"]=json!(terminal.late_settled); value["outcome"]=json!(terminal.core_outcome);
        value["terminalSeq"]=json!(session.fixture_schedule.sequence());
        value["checkoutRetained"]=json!(terminal.checkout.is_some()); value["preparedRetained"]=json!(terminal.prepared.is_some());
        Ok(value)
    }

    fn row(original:&mut Original,name:&str,selection:Selection,native:Value,observations:Value) -> Check<()> {
        require(original.settled(),Failure::OriginalCustodyUnknown)?;
        original.batch.cases.push(json!({"name":name,"domain":DOMAIN,"source":selection.source(),
            "native":native,"passive":std::mem::take(&mut original.queries),"observations":observations}));
        Ok(())
    }
    fn statuses(original:&Original,id:&str,domain:EditDomain) -> Check<()> {
        let config=original.batch.owner.status().map_err(|_| Failure::UnexpectedStatus)?;
        let workflow=original.batch.owner.workflow_status().map_err(|_| Failure::UnexpectedStatus)?;
        let metadata=original.batch.owner.metadata_text_status().map_err(|_| Failure::UnexpectedStatus)?;
        let version=original.batch.owner.release_version_status().map_err(|_| Failure::UnexpectedStatus)?;
        require(config.status_revision==workflow.status_revision && workflow.status_revision==metadata.status_revision
            && metadata.status_revision==version.status_revision && config.window_generation==workflow.window_generation
            && workflow.window_generation==metadata.window_generation && metadata.window_generation==version.window_generation
            && config.active.as_ref().map(|p| p.session_id.as_str())==(domain==EditDomain::Configuration).then_some(id)
            && workflow.active.as_ref().map(|p| p.session_id.as_str())==(domain==EditDomain::GitHubWorkflows).then_some(id)
            && metadata.active.as_ref().map(|p| p.session_id.as_str())==(domain==EditDomain::MetadataText).then_some(id)
            && version.active.as_ref().map(|p| p.session_id.as_str())==(domain==EditDomain::ReleaseVersion).then_some(id),Failure::UnexpectedStatus)?;
        for (candidate,capability) in [(EditDomain::Configuration,config.capability),(EditDomain::GitHubWorkflows,workflow.capability),
            (EditDomain::MetadataText,metadata.capability),(EditDomain::ReleaseVersion,version.capability)] {
            require(capability.reason==if candidate==domain { EditAvailability::Available } else { EditAvailability::OtherEditActive },Failure::UnexpectedStatus)?;
        }
        let last=original.batch.owner.inner.lock().last.as_ref().map(|p| (p.domain,p.session_id.clone()));
        require(config.last_terminal.as_ref().map(|p| p.session_id.as_str())==last.as_ref().filter(|(d,_)| *d==EditDomain::Configuration).map(|(_,id)| id.as_str())
            && workflow.last_terminal.as_ref().map(|p| p.session_id.as_str())==last.as_ref().filter(|(d,_)| *d==EditDomain::GitHubWorkflows).map(|(_,id)| id.as_str())
            && metadata.last_terminal.as_ref().map(|p| p.session_id.as_str())==last.as_ref().filter(|(d,_)| *d==EditDomain::MetadataText).map(|(_,id)| id.as_str())
            && version.last_terminal.as_ref().map(|p| p.session_id.as_str())==last.as_ref().filter(|(d,_)| *d==EditDomain::ReleaseVersion).map(|(_,id)| id.as_str()),Failure::UnexpectedStatus)
    }
    fn opposite_commands(original:&Original,project:&Project,session:&Arc<Session>,revision:&str,
        expected:&version_wire::Baseline,domain:EditDomain) -> Check<()> {
        const TOKEN:&str="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        statuses(original,&session.id,domain)?;
        if domain!=EditDomain::Configuration {
            require(original.bridge.open_config_edit("main",project.id.clone()).is_err()
                && original.batch.owner.prepare("main",PrepareConfigEdit { session_id:session.id.clone(),revision:revision.into(),expected_base:Value::Null,
                    draft:document(),draft_revision:1,baseline_generation:0 }).is_err()
                && original.batch.owner.apply("main",&session.id,TOKEN).is_err(),Failure::UnexpectedStatus)?;
        }
        if domain!=EditDomain::GitHubWorkflows {
            require(original.bridge.open_workflow_edit(&original.document,"main",project.id.clone()).is_err()
                && original.bridge.prepare_workflow_edit(&original.document,"main",PrepareWorkflowEdit { session_id:session.id.clone(),revision:revision.into(),
                    draft:document(),tooling_repository:"Example/mobile-release-kit".into(),tooling_sha:"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
                    draft_revision:1,baseline_generation:0 }).is_err()
                && original.bridge.apply_workflow_edit(&original.document,"main",&session.id,TOKEN).is_err(),Failure::UnexpectedStatus)?;
        }
        if domain!=EditDomain::MetadataText {
            let platform=metadata_wire::Platform::Android;
            let fields=platform.ids().iter().map(|id| metadata_wire::TextField { id:*id,text:"Fixed public value".into() }).collect();
            require(original.bridge.open_metadata_text_edit(&original.document,"main",crate::metadata_text_commands::Open {
                    project_id:project.id.clone(),platform,locale:"en-US".into() }).is_err()
                && original.bridge.prepare_metadata_text_edit(&original.document,"main",PrepareMetadataTextEdit {
                    session_id:session.id.clone(),revision:revision.into(),expected_baseline:metadata_wire::Baseline {
                        config:metadata_wire::ContentDigest { byte_length:expected.saved_config.bytes,sha256:expected.saved_config.sha256.clone() },
                        fields:platform.ids().iter().map(|id| metadata_wire::BaselineField::Absent { id:*id }).collect() },
                    fields,draft_revision:1,baseline_generation:0 }).is_err()
                && original.bridge.apply_metadata_text_edit(&original.document,"main",&session.id,TOKEN).is_err(),Failure::UnexpectedStatus)?;
        }
        if domain!=EditDomain::ReleaseVersion {
            require(original.bridge.open_release_version_edit(&original.document,"main",open_args(project)).is_err()
                && original.bridge.prepare_release_version_edit(&original.document,"main",prepare_args(&session.id,revision,expected)).is_err()
                && original.bridge.apply_release_version_edit(&original.document,"main",&session.id,TOKEN).is_err(),Failure::UnexpectedStatus)?;
        }
        let registry=original.batch.owner.inner.lock(); let active=registry.active.as_ref().ok_or(Failure::OriginalCustodyUnknown)?;
        require(Arc::ptr_eq(&active.session,session) && active.session.domain==domain && active.claimed_seq==0
            && active.prepare_counters.is_none() && !active.prepared && !active.projection.apply_submitted && active.cleanup_start.is_none(),Failure::UnexpectedStatus)
    }

    fn select_metadata(status:&MetadataTextEditStatus,id:&str) -> Check<metadata_wire::Projection> {
        require(status.domain == "metadata_text",Failure::UnexpectedStatus)?;
        status.active.as_ref().filter(|p| p.session_id == id).or_else(|| status.last_terminal.as_ref().filter(|p| p.session_id == id))
            .cloned().ok_or(Failure::UnexpectedStatus)
    }
    async fn observed_metadata(owner:&EditOwner,id:&str,desired:Phase,expected_unknown:bool) -> Check<metadata_wire::Projection> {
        let end=Instant::now()+OBSERVATION; let mut revisions=owner.subscribe();
        loop {
            let status=owner.metadata_text_status().map_err(|_| Failure::OriginalCustodyUnknown)?;
            let current=select_metadata(&status,id)?;
            if !expected_unknown {
                require(!owner.disabled() && current.phase != Phase::Unknown && current.native_finality != NativeFinality::Unknown
                    && !current.late_settled,Failure::OriginalCustodyUnknown)?;
            }
            if current.phase == desired && (!expected_unknown || status.active.is_none()) { return Ok(current); }
            require(current.phase != Phase::Final,Failure::UnexpectedStatus)?;
            tokio::select! {
                result=revisions.changed() => { result.map_err(|_| Failure::UnexpectedStatus)?; },
                _=tokio::time::sleep_until(tokio::time::Instant::from_std(end)) => return Err(Failure::ObservationTimeout),
            }
        }
    }
    async fn workflow_observed(owner:&EditOwner,id:&str,desired:Phase) -> Check<workflow_wire::Projection> {
        let end=Instant::now()+OBSERVATION; let mut revisions=owner.subscribe();
        loop {
            let status=owner.workflow_status().map_err(|_| Failure::OriginalCustodyUnknown)?;
            let current=status.active.as_ref().filter(|p| p.session_id == id).or_else(|| status.last_terminal.as_ref().filter(|p| p.session_id == id))
                .cloned().ok_or(Failure::UnexpectedStatus)?;
            require(!owner.disabled() && current.native_finality != NativeFinality::Unknown && !current.late_settled,Failure::OriginalCustodyUnknown)?;
            if current.phase == desired { return Ok(current); }
            require(current.phase != Phase::Final,Failure::UnexpectedStatus)?;
            tokio::select! { result=revisions.changed() => { result.map_err(|_| Failure::UnexpectedStatus)?; },
                _=tokio::time::sleep_until(tokio::time::Instant::from_std(end)) => return Err(Failure::ObservationTimeout), }
        }
    }
    fn legacy_data(session:&Session,phase:Phase,finality:NativeFinality,native:Reason,applied:bool,late:bool,core:&wire::CoreEditOutcome) -> Check<Value> {
        let facts=original_facts(session)?;
        require((facts.request_frames,facts.response_frames)==(1,2) && session.fixture_schedule.sequence()==Some(0)
            && phase == Phase::Final && finality == NativeFinality::Settled && native == Reason::Discarded && !applied && !late
            && core.effect == Effect::NotStarted && core.journal == Journal::NotCreated && core.resources == ResourceState::Settled
            && matches!(core.reason,CoreReason::Cancelled|CoreReason::None),Failure::UnexpectedOutcome)?;
        let mut value=serde_json::to_value(facts).map_err(|_| Failure::ReceiptIo)?;
        value["domain"]=json!(match session.domain { EditDomain::Configuration=>"configuration",EditDomain::GitHubWorkflows=>"github_workflows",
            EditDomain::MetadataText=>"metadata_text",EditDomain::ReleaseVersion=>return Err(Failure::UnexpectedStatus) });
        value["nativePhase"]=json!(phase); value["nativeFinality"]=json!(finality); value["nativeReason"]=json!(native);
        value["applySubmitted"]=json!(applied); value["lateSettled"]=json!(late); value["outcome"]=json!(core); value["terminalSeq"]=json!(0);
        Ok(value)
    }

    async fn foreign_isolation(original:&mut Original,input:&Admitted,root:&Path,project:&Project,expected:&version_wire::Baseline) -> Check<Vec<Value>> {
        require(original.settled(),Failure::OriginalCustodyUnknown)?;
        let version_permit=original.batch.owner.inner.fixture_version.lock().map_err(|_| Failure::OriginalCustodyUnknown)?.take()
            .ok_or(Failure::HostedGuardRefused)?;
        require(version_permit.root(&original.batch.owner.inner,root) && !original.batch.owner.inner.hosted_qualified(EditDomain::ReleaseVersion),
            Failure::HostedGuardRefused)?;
        original.batch.owner.inner.fixture_authorized.store(true,Ordering::SeqCst);
        require(original.batch.owner.inner.hosted_qualified(EditDomain::Configuration)
            && !original.batch.owner.inner.hosted_qualified(EditDomain::ReleaseVersion),Failure::HostedGuardRefused)?;
        let reply=original.bridge.open_config_edit("main",project.id.clone()); let session=original.retain_open()?;
        require(projection(&reply.map_err(|_| Failure::NativeCommandRejected)?,&session.id)?.phase==Phase::Opening,Failure::UnexpectedStatus)?;
        let editing=observed(&original.batch.owner,&session.id,Phase::Editing).await?;
        let checkout=editing.checkout.as_ref().ok_or(Failure::UnexpectedOutcome)?;
        opposite_commands(original,project,&session,&checkout.revision,expected,EditDomain::Configuration)?;
        original.batch.owner.close("main",&session.id).map_err(|_| Failure::NativeCommandRejected)?;
        let terminal=observed(&original.batch.owner,&session.id,Phase::Final).await?;
        let config=legacy_data(&session,terminal.phase,terminal.native_finality,terminal.native_reason,terminal.apply_submitted,terminal.late_settled,
            terminal.core_outcome.as_ref().ok_or(Failure::UnexpectedOutcome)?)?;
        require(original.settled(),Failure::OriginalCustodyUnknown)?;
        original.batch.owner.inner.fixture_authorized.store(false,Ordering::SeqCst);
        {
            let mut slot=original.batch.owner.inner.fixture_workflow.lock().map_err(|_| Failure::OriginalCustodyUnknown)?;
            require(slot.is_none(),Failure::HostedGuardRefused)?;
            *slot=Some(Arc::new(WorkflowFixturePermit { owner:Arc::downgrade(&original.batch.owner.inner),roots:vec![root.to_path_buf()],
                python:input.python.clone(),core:input.core.clone(),bootstrap:input.repository.join("desktop/config_edit_bootstrap.py"),
                cwd:input.repository.join("desktop"),binding_sha256:hash(&serde_json::to_vec(&input.inputs.bindings).map_err(|_| Failure::SourceBindingMismatch)?),eof:false }));
        }
        let workflow_ticket=original.batch.owner.workflow_open_ticket("main").map_err(|_| Failure::NativeCommandRejected)?;
        let reply=original.bridge.open_workflow_edit(&original.document,"main",project.id.clone()); let session=original.retain_open()?;
        require(reply.map_err(|_| Failure::NativeCommandRejected)?.active.is_some_and(|p| p.session_id==session.id && p.phase==Phase::Opening),Failure::UnexpectedStatus)?;
        let editing=workflow_observed(&original.batch.owner,&session.id,Phase::Editing).await?;
        let checkout=editing.checkout.as_ref().ok_or(Failure::UnexpectedOutcome)?;
        opposite_commands(original,project,&session,&checkout.revision,expected,EditDomain::GitHubWorkflows)?;
        original.batch.owner.close_workflow("main",&session.id).map_err(|_| Failure::NativeCommandRejected)?;
        let terminal=workflow_observed(&original.batch.owner,&session.id,Phase::Final).await?;
        let workflow=legacy_data(&session,terminal.phase,terminal.native_finality,terminal.native_reason,terminal.apply_submitted,terminal.late_settled,
            terminal.core_outcome.as_ref().ok_or(Failure::UnexpectedOutcome)?)?;
        require(original.settled(),Failure::OriginalCustodyUnknown)?;
        original.batch.owner.inner.fixture_workflow.lock().map_err(|_| Failure::OriginalCustodyUnknown)?.take();
        {
            let mut slot=original.batch.owner.inner.fixture_metadata.lock().map_err(|_| Failure::OriginalCustodyUnknown)?;
            require(slot.is_none(),Failure::HostedGuardRefused)?;
            *slot=Some(Arc::new(MetadataFixturePermit { owner:Arc::downgrade(&original.batch.owner.inner),
                selections:vec![(root.to_path_buf(),metadata_wire::Platform::Android,"en-US".into())],
                python:input.python.clone(),core:input.core.clone(),bootstrap:input.repository.join("desktop/config_edit_bootstrap.py"),
                cwd:input.repository.join("desktop"),binding_sha256:hash(&serde_json::to_vec(&input.inputs.bindings).map_err(|_| Failure::SourceBindingMismatch)?),
                zip:false,eof:false }));
        }
        let metadata_ticket=original.batch.owner.metadata_text_open_ticket("main").map_err(|_| Failure::NativeCommandRejected)?;
        let reply=original.bridge.open_metadata_text_edit(&original.document,"main",crate::metadata_text_commands::Open {
            project_id:project.id.clone(),platform:metadata_wire::Platform::Android,locale:"en-US".into() });
        let session=original.retain_open()?;
        require(reply.map_err(|_| Failure::NativeCommandRejected)?.active.is_some_and(|p| p.session_id==session.id && p.phase==Phase::Opening),Failure::UnexpectedStatus)?;
        let editing=observed_metadata(&original.batch.owner,&session.id,Phase::Editing,false).await?;
        let checkout=editing.checkout.as_ref().ok_or(Failure::UnexpectedOutcome)?;
        opposite_commands(original,project,&session,&checkout.revision,expected,EditDomain::MetadataText)?;
        original.batch.owner.close_metadata_text("main",&session.id).map_err(|_| Failure::NativeCommandRejected)?;
        let terminal=observed_metadata(&original.batch.owner,&session.id,Phase::Final,false).await?;
        let metadata=legacy_data(&session,terminal.phase,terminal.native_finality,terminal.native_reason,terminal.apply_submitted,terminal.late_settled,
            terminal.core_outcome.as_ref().ok_or(Failure::UnexpectedOutcome)?)?;
        require(original.settled(),Failure::OriginalCustodyUnknown)?;
        original.batch.owner.inner.fixture_metadata.lock().map_err(|_| Failure::OriginalCustodyUnknown)?.take();
        {
            let mut slot=original.batch.owner.inner.fixture_version.lock().map_err(|_| Failure::OriginalCustodyUnknown)?;
            require(slot.is_none() && version_permit.owns(&original.batch.owner.inner),Failure::HostedGuardRefused)?;
            *slot=Some(version_permit); // Exact original permit, never a foreign authority.
        }
        require(original.batch.owner.inner.hosted_qualified(EditDomain::ReleaseVersion)
            && !original.batch.owner.inner.hosted_qualified(EditDomain::Configuration)
            && !original.batch.owner.inner.hosted_qualified(EditDomain::GitHubWorkflows)
            && !original.batch.owner.inner.hosted_qualified(EditDomain::MetadataText),Failure::HostedGuardRefused)?;
        let (generation,registered)=original.bridge.native_project(&project.id).map_err(|_| Failure::UnexpectedStatus)?;
        for ticket in [workflow_ticket,metadata_ticket] {
            require(original.batch.owner.open_release_version("main",project.id.clone(),RegisteredEditRoot {
                generation,root:registered.clone() },ticket).is_err() && original.batch.owner.inner.lock().active.is_none(),
                Failure::UnexpectedStatus)?;
        }
        Ok(vec![config,workflow,metadata])
    }

    async fn consumed_plan_refusal(original:&mut Original,project:&Project,root:&Path,before:&Snapshot,
        selection:Selection,expected:&version_wire::Baseline) -> Check<Value> {
        require(original.settled(),Failure::OriginalCustodyUnknown)?;
        let (old_id,old_token)=original.consumed_plan.clone().ok_or(Failure::UnexpectedStatus)?;
        let session=original.open(project)?;
        let editing=observed_version(&original.batch.owner,&session.id,Phase::Editing,false).await?;
        let checkout=editing.checkout.as_ref().ok_or(Failure::UnexpectedOutcome)?;
        require(checkout.baseline==*expected,Failure::UnexpectedOutcome)?;
        let plan=prepare(original,&session.id,checkout,expected).await?;
        verify_plan(before,selection,checkout,&plan)?;
        require(old_id!=session.id && old_token!=plan.plan_token && snapshot(root)?==*before,Failure::UnexpectedStatus)?;
        // A wrong consumed token MUST retire this original review. Do not try
        // to preserve/reuse it after the owner's native CallerLost boundary.
        require(original.bridge.apply_release_version_edit(&original.document,"main",&session.id,&old_token)
            .is_err_and(|error| error.code=="invalid_edit_owner") && *session.stop.borrow(),Failure::UnexpectedStatus)?;
        let terminal=observed_version(&original.batch.owner,&session.id,Phase::Final,false).await?;
        settled_terminal(&original.batch.owner,&terminal)?; correlated(&terminal,&editing,&plan)?;
        let facts=original_facts(&session)?; let core=terminal.core_outcome.as_ref().ok_or(Failure::UnexpectedOutcome)?;
        require((facts.request_frames,facts.response_frames)==(2,3) && session.fixture_schedule.sequence()==Some(1)
            && terminal.native_reason==Reason::CallerLost && !terminal.apply_submitted
            && core.effect==Effect::NotStarted && core.journal==Journal::NotCreated && core.resources==ResourceState::Settled
            && matches!(core.reason,CoreReason::Cancelled|CoreReason::None) && snapshot(root)?==*before,
            Failure::UnexpectedOutcome)?;
        require(original.settled(),Failure::OriginalCustodyUnknown)?;
        native_data(&session,&terminal,None)
    }

    async fn exercise_owner(original:&mut Original,input:&Admitted,case:Case) -> Check<()> {
        require(original.settled() && !original.batch.owner.disabled() && original.queries.is_empty(),Failure::OriginalCustodyUnknown)?;
        let selection=case.selection(); let root=seed(input,case)?; let project=original.register(&root)?;
        let mut before=snapshot(&root)?; let edit_count=original.batch.originals.len();
        // Passive v2 observes only PRESENT saved values. Explicit absent Create
        // uses the genuine native checkout; no missing-source success is forged.
        let expected=if case==Case::Create { baseline(&before,selection)? }
            else { observed_pair(&before,selection,&original.observe(&project).await?)? };
        require(snapshot(&root)?==before,Failure::PayloadMismatch)?;
        let mut domains=Vec::new(); let mut spent_refusal=Value::Null;
        if case==Case::Stale {
            rewrite_original(&root.join(selection.source()),before.files.get(selection.source()).ok_or(Failure::PayloadMismatch)?,EDITED)?;
            before=snapshot(&root)?;
            require(baseline(&before,selection)?!=expected,Failure::PayloadMismatch)?;
        } else if case==Case::Isolation {
            domains=foreign_isolation(original,input,&root,&project,&expected).await?;
            spent_refusal=consumed_plan_refusal(original,&project,&root,&before,selection,&expected).await?;
            require(snapshot(&root)?==before,Failure::PayloadMismatch)?;
        }
        let registration=original.bridge.native_project(&project.id).map_err(|_| Failure::UnexpectedStatus)?;
        let session=original.open(&project)?;
        require(session.registration.as_ref().is_some_and(|r| r.generation==registration.0 && r.root==registration.1)
            && session.fixture_version.as_ref().is_some_and(|permit| original.batch.owner.inner.fixture_version.lock()
                .is_ok_and(|current| current.as_ref().is_some_and(|current| Arc::ptr_eq(permit,current)))),Failure::UnexpectedStatus)?;
        let editing=observed_version(&original.batch.owner,&session.id,Phase::Editing,false).await?;
        let checkout=editing.checkout.as_ref().ok_or(Failure::UnexpectedOutcome)?;
        require(checkout.baseline==baseline(&before,selection)? && checkout.source==selection.source()
            && checkout.name_key=="VERSION_NAME" && checkout.build_key=="BUILD_NUMBER" && checkout.ios_enabled
            && editing.project_id==project.id,Failure::UnexpectedOutcome)?;
        if case==Case::Isolation { opposite_commands(original,&project,&session,&checkout.revision,&expected,EditDomain::ReleaseVersion)?; }
        if case==Case::Stale {
            let reply=original.bridge.prepare_release_version_edit(&original.document,"main",prepare_args(&session.id,&checkout.revision,&expected))
                .map_err(|_| Failure::NativeCommandRejected)?;
            require(select(&reply,&session.id)?.phase==Phase::Preparing,Failure::UnexpectedStatus)?;
            let terminal=observed_version(&original.batch.owner,&session.id,Phase::Final,false).await?;
            settled_terminal(&original.batch.owner,&terminal)?;
            let facts=original_facts(&session)?; let core=terminal.core_outcome.as_ref().ok_or(Failure::UnexpectedOutcome)?;
            require((facts.request_frames,facts.response_frames)==(2,2) && session.fixture_schedule.sequence()==Some(1)
                && terminal.prepared.is_none() && !terminal.apply_submitted && terminal.native_reason==Reason::None
                && terminal.checkout.as_ref().is_some_and(|saved| saved.revision==checkout.revision && saved.baseline==checkout.baseline)
                && core.effect==Effect::NotStarted && core.journal==Journal::NotCreated && core.resources==ResourceState::Settled
                && core.reason==CoreReason::StaleRevision && snapshot(&root)?==before,Failure::UnexpectedOutcome)?;
            return row(original,case.name(),selection,native_data(&session,&terminal,None)?,json!({"olderPassiveBaselineRejected":true,
                "newerNativeCheckoutRetained":true,"noPlanOrRebase":true,"externalChangeRetained":true,"treeUnchanged":true,
                "sourceProbesSettled":probes_settled(),"passiveOriginalsSettled":original.passive.settled()}));
        }
        require(checkout.baseline==expected,Failure::UnexpectedOutcome)?;
        let plan=prepare(original,&session.id,checkout,&expected).await?;
        let directories=verify_plan(&before,selection,checkout,&plan)?;
        require(snapshot(&root)?==before,Failure::PayloadMismatch)?;
        if matches!(case,Case::Registration|Case::DocumentLost) {
            if case==Case::Registration {
                let extra=input.inputs.root.join("registration-apply-extra"); mkdir(&extra)?; original.register(&extra)?;
                require(original.bridge.apply_release_version_edit(&original.document,"main",&session.id,&plan.plan_token).is_err(),Failure::UnexpectedStatus)?;
            } else {
                original.document.lost();
                require(!original.document.navigation(true),Failure::DocumentOriginalNavigationAccepted)?;
                require(original.bridge.apply_release_version_edit(&original.document,"main",&session.id,&plan.plan_token)
                    .is_err_and(|error| error.code=="invalid_edit_owner"),Failure::DocumentOriginalApplyNotRefused)?;
                require(original.bridge.open_release_version_edit(&original.document,"main",open_args(&project))
                    .is_err_and(|error| error.code=="invalid_edit_owner"),Failure::DocumentOriginalOpenNotRefused)?;
                let replacement=DocumentBinding::new(original.bridge.clone());
                // Initial navigation is allowed, not an edit capability. Only
                // Finished asks the SAME registry to bind; its loss is final.
                require(replacement.navigation(true),Failure::DocumentReplacementNavigationRefused)?;
                replacement.observe(|life| life.started(true)); replacement.hook_installed();
                let mut bound=true;
                replacement.observe(|life| { bound=life.original_bound(); crate::document_lifetime::DocumentAction::None });
                require(!bound,Failure::DocumentReplacementPrematurelyBound)?;
                replacement.observe(|life| life.finished(true));
                replacement.observe(|life| { bound=life.original_bound(); crate::document_lifetime::DocumentAction::None });
                require(!bound,Failure::DocumentReplacementRebound)?;
                require(original.bridge.apply_release_version_edit(&replacement,"main",&session.id,&plan.plan_token)
                    .is_err_and(|error| error.code=="invalid_edit_owner"),Failure::DocumentReplacementApplyNotRefused)?;
                require(original.bridge.open_release_version_edit(&replacement,"main",open_args(&project))
                    .is_err_and(|error| error.code=="invalid_edit_owner"),Failure::DocumentReplacementOpenNotRefused)?;
            }
            let terminal=observed_version(&original.batch.owner,&session.id,Phase::Final,false).await?;
            settled_terminal(&original.batch.owner,&terminal)?; correlated(&terminal,&editing,&plan)?;
            let facts=original_facts(&session)?; let core=terminal.core_outcome.as_ref().ok_or(Failure::UnexpectedOutcome)?;
            require((facts.request_frames,facts.response_frames)==(2,3) && session.fixture_schedule.sequence()==Some(1)
                && !terminal.apply_submitted && terminal.native_reason==if case==Case::Registration { Reason::CallerLost } else { Reason::WindowLost }
                && core.effect==Effect::NotStarted && core.journal==Journal::NotCreated && core.resources==ResourceState::Settled
                && matches!(core.reason,CoreReason::Cancelled|CoreReason::None) && snapshot(&root)?==before,Failure::UnexpectedOutcome)?;
            return row(original,case.name(),selection,native_data(&session,&terminal,None)?,json!({"preparedCorrelationRetained":true,
                "treeUnchanged":true,"staleCommandNotSent":true,"newRegistrationPublishedUnderDocumentLock":case==Case::Registration,
                "controlledOriginalDocumentLoss":case==Case::DocumentLost,"replacementDocumentRefused":case==Case::DocumentLost,
                "guiCallbacksNotClaimed":true,"sourceProbesSettled":probes_settled(),"passiveOriginalsSettled":original.passive.settled()}));
        }
        let mut gate=if case==Case::HeldTerminal {
            let guard=GateGuard::new(&original.batch.owner,session.fixture_schedule.clone()); session.fixture_schedule.terminal.hold()?; Some(guard)
        } else { None };
        let reply=original.bridge.apply_release_version_edit(&original.document,"main",&session.id,&plan.plan_token).map_err(|_| Failure::NativeCommandRejected)?;
        require(select(&reply,&session.id)?.apply_submitted,Failure::UnexpectedStatus)?;
        if case==Case::Create {
            let duplicate=original.bridge.apply_release_version_edit(&original.document,"main",&session.id,&plan.plan_token).map_err(|_| Failure::NativeCommandRejected)?;
            require(select(&duplicate,&session.id)?.apply_submitted && original.batch.originals.len()==edit_count+1,Failure::UnexpectedStatus)?;
        }
        if let Some(guard)=gate.as_mut() {
            let (active,cleanup)=original_clock(&original.batch,&session)?; let endpoint=active.ok_or(Failure::UnexpectedStatus)?;
            require(cleanup.is_none(),Failure::UnexpectedStatus)?;
            until(OBSERVATION,|| {
                require(!session.fixture_schedule.failed.load(Ordering::SeqCst),Failure::OriginalCustodyUnknown)?;
                Ok(session.fixture_schedule.terminal.entered.load(Ordering::SeqCst))
            }).await?;
            let held=session.fixture_schedule.held_terminal.lock().map_err(|_| Failure::OriginalCustodyUnknown)?.clone().ok_or(Failure::UnexpectedStatus)?;
            require(held.0==2 && held.1.effect==Effect::Committed && held.1.journal==Journal::Clean && held.1.resources==ResourceState::Settled
                && held.1.reason==CoreReason::None && session.fixture_schedule.sequence().is_none()
                && Instant::now()<endpoint && !*session.stop.borrow(),Failure::UnexpectedOutcome)?;
            let closing=original.batch.owner.close_release_version("main",&session.id).map_err(|_| Failure::NativeCommandRejected)?;
            require(select(&closing,&session.id)?.native_reason==Reason::Cancelled && *session.stop.borrow(),Failure::UnexpectedStatus)?;
            guard.release(); // Real Close precedes release of that same reader.
        }
        let terminal=observed_version(&original.batch.owner,&session.id,Phase::Final,false).await?;
        settled_terminal(&original.batch.owner,&terminal)?; correlated(&terminal,&editing,&plan)?;
        let facts=original_facts(&session)?; let core=terminal.core_outcome.as_ref().ok_or(Failure::UnexpectedOutcome)?;
        let noop=case==Case::Noop;
        require((facts.request_frames,facts.response_frames)==(3,3) && session.fixture_schedule.sequence()==Some(2)
            && terminal.apply_submitted && terminal.native_reason==if case==Case::HeldTerminal { Reason::Cancelled } else { Reason::None }
            && core.effect==if noop { Effect::Unchanged } else { Effect::Committed }
            && core.journal==if noop { Journal::NotCreated } else { Journal::Clean }
            && core.resources==ResourceState::Settled && core.reason==CoreReason::None
            && session.fixture_schedule.released(),Failure::UnexpectedOutcome)?;
        installed(&root,&before,selection,&directories)?;

        if noop { require(snapshot(&root)?==before,Failure::PayloadMismatch)?; }
        let after=snapshot(&root)?;
        observed_pair(&after,selection,&original.observe(&project).await?)?;
        require(snapshot(&root)?==after,Failure::PayloadMismatch)?;
        if case==Case::Create { original.consumed_plan=Some((session.id.clone(),plan.plan_token.clone())); }
        let config=original.batch.owner.status().map_err(|_| Failure::UnexpectedStatus)?;
        let workflow=original.batch.owner.workflow_status().map_err(|_| Failure::UnexpectedStatus)?;
        let metadata=original.batch.owner.metadata_text_status().map_err(|_| Failure::UnexpectedStatus)?;
        let version=original.batch.owner.release_version_status().map_err(|_| Failure::UnexpectedStatus)?;
        require(config.last_terminal.is_none() && workflow.last_terminal.is_none() && metadata.last_terminal.is_none()
            && version.last_terminal.as_ref().is_some_and(|p| p.session_id==session.id)
            && config.status_revision==workflow.status_revision && workflow.status_revision==metadata.status_revision
            && metadata.status_revision==version.status_revision,Failure::UnexpectedStatus)?;
        let observations=json!({"action":plan.view.file.action,"directoriesCreated":directories,"explicitAbsentCreate":case==Case::Create,
            "completePreparedBytes":true,"passiveBaselineMatchedCheckout":case!=Case::Create,"preparedCorrelationRetained":true,
            "capturePrepareRawFactsUnchanged":true,"dependenciesAndUnrelatedPreserved":true,"existingModePreserved":true,
            "createModeMasked":true,"directoryModesExact":true,"unicodeCommentsAndOnlyTwoSpansPreserved":case!=Case::Create,
            "rawNoopUnchanged":noop,"duplicateApplyObservation":case==Case::Create,"savedPairReadback":true,
            "sharedStatusRevision":true,"sharedLastTerminalDomainCorrect":true,"fourDomainIsolation":case==Case::Isolation,
            "foreignOriginalTicketsRefused":case==Case::Isolation,"consumedPlanRefused":case==Case::Isolation,"consumedPlanRefusal":spent_refusal,"domains":domains,
            "heldBeforeAcceptance":case==Case::HeldTerminal,"realStopBeforeRelease":case==Case::HeldTerminal,"cancelledNotSaved":case==Case::HeldTerminal,
            "sourceProbesSettled":probes_settled(),"passiveOriginalsSettled":original.passive.settled()});
        row(original,case.name(),selection,native_data(&session,&terminal,None)?,observations)
    }

    fn eof_seed(input:&Admitted,case:EofCase) -> Check<PathBuf> {
        let selection=eof_selection(case); let root=input.inputs.root.join(case.name());
        seed_common(&root,selection)?;
        if case!=EofCase::VersionConflict {
            seed_parent(&root,selection.parent())?;
            write_new(&root.join(selection.source()),EOF_ORIGINAL,0o640)?;
        }
        Ok(root)
    }
    fn introduce_sibling(root:&Path,selection:Selection) -> Check<RawFile> {
        FIXTURE_FILES.admit()?;
        let path=root.join(format!("{}/unrelated.txt",selection.parent()));
        let mut file=fs::OpenOptions::new().create_new(true).write(true).mode(0o600).custom_flags(nix::libc::O_NOFOLLOW)
            .open(&path).map_err(|_| Failure::FixtureIo)?;
        FIXTURE_FILES.acquired(); let wrote=file.write_all(UNRELATED); let stat=file.metadata();
        FIXTURE_FILES.close_original(file)?;
        require(wrote.is_ok(),Failure::FixtureIo)?; let stat=stat.map_err(|_| Failure::FixtureIo)?;
        require(stat.is_file() && stat.len()==UNRELATED.len() as u64 && stat.mode()&0o7777==0o600,Failure::FixtureIo)?;
        // No extra reader while the original transaction is held. These are
        // the creating descriptor's own bytes and actual metadata return.
        Ok(RawFile { original:OriginalFile { identity:Identity::of(&stat),bytes:UNRELATED.to_vec() },stamp:Stamp::of(&stat) })
    }
    async fn exercise_eof(original:&mut Original,input:&Admitted,case:EofCase) -> Check<()> {
        require(input.eof && input.mode==Mode::Source && EOF_CASES.contains(&case) && original.queries.is_empty()
            && original.settled() && !original.batch.owner.disabled(),Failure::OriginalCustodyUnknown)?;
        input.inputs.same_root()?;
        let selection=eof_selection(case); let root=eof_seed(input,case)?; let before=snapshot(&root)?;
        let project=original.register(&root)?;
        let expected=if case==EofCase::VersionConflict { baseline(&before,selection)? }
            else { observed_pair(&before,selection,&original.observe(&project).await?)? };
        let schedule=Arc::new(Schedule { eof:Some(case),..Schedule::default() });
        {
            let mut next=original.batch.owner.inner.fixture_next_schedule.lock().map_err(|_| Failure::OriginalCustodyUnknown)?;
            require(next.is_none(),Failure::UnexpectedStatus)?; *next=Some(schedule.clone());
        }
        let mut guard=GateGuard::new(&original.batch.owner,schedule.clone());
        let session=original.open(&project)?;
        require(Arc::ptr_eq(&session.fixture_schedule,&schedule),Failure::OriginalCustodyUnknown)?;
        let editing=observed_version(&original.batch.owner,&session.id,Phase::Editing,false).await?;
        let checkout=editing.checkout.as_ref().ok_or(Failure::UnexpectedOutcome)?;
        let plan=prepare(original,&session.id,checkout,&expected).await?;
        let directories=verify_plan(&before,selection,checkout,&plan)?;
        let unknown=case==EofCase::VersionConflict; let committed=case==EofCase::VersionPostcommit;
        require(snapshot(&root)?==before && if unknown { directories==ancestors(selection.parent()) }
            else { directories.is_empty() && plan.view.file.action==version_wire::Action::Replace },Failure::PayloadMismatch)?;
        let reply=original.bridge.apply_release_version_edit(&original.document,"main",&session.id,&plan.plan_token).map_err(|_| Failure::NativeCommandRejected)?;
        require(select(&reply,&session.id)?.apply_submitted,Failure::UnexpectedStatus)?;
        let (active,cleanup)=original_clock(&original.batch,&session)?; let endpoint=active.ok_or(Failure::UnexpectedStatus)?;
        require(cleanup.is_none(),Failure::UnexpectedStatus)?;
        until(OBSERVATION,|| {
            require(!original.batch.owner.disabled() && !schedule.failed.load(Ordering::SeqCst),Failure::OriginalCustodyUnknown)?;
            Ok(schedule.eof_control.lock().map_err(|_| Failure::OriginalCustodyUnknown)?.boundary_only(case))
        }).await?;
        let introduced=if unknown { Some(introduce_sibling(&root,selection)?) } else { None };
        require(Instant::now()<endpoint && !*session.stop.borrow(),Failure::UnexpectedStatus)?;
        let closing=original.batch.owner.close_release_version("main",&session.id).map_err(|_| Failure::NativeCommandRejected)?;
        let closing=select(&closing,&session.id)?;
        require(closing.phase==Phase::Finalizing && closing.native_reason==Reason::Cancelled && closing.apply_submitted,Failure::UnexpectedStatus)?;
        guard.release(); // Only the original owner closes the original stdin.
        let terminal=observed_version(&original.batch.owner,&session.id,if unknown { Phase::Unknown } else { Phase::Final },unknown).await?;
        let facts=original_eof_facts(&session,case)?;
        correlated(&terminal,&editing,&plan)?;
        let core=terminal.core_outcome.as_ref().ok_or(Failure::UnexpectedOutcome)?;
        require(original.settled() && (facts.request_frames,facts.response_frames)==(3,3) && schedule.sequence()==Some(2)
            && terminal.apply_submitted && terminal.native_reason==Reason::Cancelled
            && core.effect==if unknown { Effect::Unknown } else if committed { Effect::Committed } else { Effect::RolledBack }
            && core.journal==if unknown { Journal::RecoveryRequired } else { Journal::Clean }
            && core.resources==ResourceState::Settled && core.reason==CoreReason::Cancelled
            && schedule.eof_control.lock().is_ok_and(|control| control.complete(case) && control.records(case)==2)
            && schedule.released(),Failure::UnexpectedOutcome)?;
        if unknown {
            // Effect Unknown remains disabled and is NOT ordinary Final. The
            // original resource proof above admits only these fixed DATA reads
            // and the existing receipt return, never another native operation.
            require(terminal.phase==Phase::Unknown && terminal.native_finality==NativeFinality::Unknown && terminal.late_settled
                && original.batch.owner.disabled() && original.batch.owner.inner.lock().blocked_projects.contains(&project.id),Failure::UnexpectedOutcome)?;
            let config=original.batch.owner.status().map_err(|_| Failure::UnexpectedStatus)?;
            let workflow=original.batch.owner.workflow_status().map_err(|_| Failure::UnexpectedStatus)?;
            let metadata=original.batch.owner.metadata_text_status().map_err(|_| Failure::UnexpectedStatus)?;
            let version=original.batch.owner.release_version_status().map_err(|_| Failure::UnexpectedStatus)?;
            require(config.active.is_none() && workflow.active.is_none() && metadata.active.is_none() && version.active.is_none()
                && config.capability.reason==EditAvailability::CleanupUnknown && workflow.capability.reason==EditAvailability::CleanupUnknown
                && metadata.capability.reason==EditAvailability::CleanupUnknown && version.capability.reason==EditAvailability::CleanupUnknown
                && config.status_revision==workflow.status_revision && workflow.status_revision==metadata.status_revision
                && metadata.status_revision==version.status_revision,Failure::UnexpectedStatus)?;
            let sibling=raw_file(&root.join(format!("{}/unrelated.txt",selection.parent())),1024)?;
            require(introduced.as_ref()==Some(&sibling),Failure::PayloadMismatch)?;
            let saved=read_regular(&root.join(selection.source()),64*1024)?;
            require(saved.bytes==CREATED && saved.identity.mode&0o7777==0o600,Failure::PayloadMismatch)?;
            require(fs::symlink_metadata(root.join(".mobile-release-version")).is_ok_and(|stat| stat.is_dir()),Failure::PayloadMismatch)?;
            for (path,file) in &before.files { require(raw_file(&root.join(path),1024*1024)?==*file,Failure::PayloadMismatch)?; }
            for (path,identity) in &before.directories {
                require(Identity::of(&fs::symlink_metadata(root.join(path)).map_err(|_| Failure::FixtureIo)?)==*identity,Failure::PayloadMismatch)?;
            }
        } else {
            settled_terminal(&original.batch.owner,&terminal)?;
            if committed { installed(&root,&before,selection,&directories)?; } else { restored(&root,&before)?; }
        }
        let observations=json!({"evidenceKind":"real-stdin-eof-at-controlled-transaction-boundary","bootstrapMode":"instrumented-genuine-engine",
            "boundary":case.boundary(),"originalCheckpoint":case.checkpoint(),"closeBeforeActiveDeadline":true,"controlRecords":2,
            "actualStdinEof":true,"eofReadCount":1,"nonemptyReadCount":0,"readErrorCount":0,"preparedCorrelationRetained":true,
            "versionProfileAndControlProof":true,"committedPublication":committed,"rolledBackPublication":!committed&&!unknown,
            "terminalDurable":!unknown,"fixedRecovery":true,"journalClean":!unknown,"journalAbsent":!unknown,
            "originalTreeRestored":!committed&&!unknown,"selectedPayloadsRemain":committed||unknown,"unselectedAndDependenciesPreserved":true,
            "unrelatedIntroducedBeforeEof":unknown,"introducedOriginalPreserved":unknown,"recoveryEvidenceRetained":unknown,
            "sharedBlockedProject":unknown,"allFourDomainsDisabled":unknown,"noFurtherAdmission":unknown,
            "sourceProbesSettled":probes_settled(),"passiveOriginalsSettled":original.passive.settled(),"fixtureFilesSettled":FIXTURE_FILES.all_settled()});
        row(original,case.name(),selection,native_data(&session,&terminal,Some(case))?,observations)
    }
    fn receipt(input:&Admitted,cases:&[Value],passed:bool,resources:bool,disabled:bool,failure:Option<Failure>) -> Check<()> {
        let expected=if input.eof { EOF_CASES.len() } else if input.mode==Mode::Source { SOURCE_CASES.len() } else { 1 };
        require(!passed || resources && cases.len()==expected && failure.is_none() && disabled==input.eof,Failure::ReceiptIo)?;
        receipt_document(&input.inputs,json!({"schemaVersion":1,"scope":if input.eof { TRANSACTION_SCOPE } else { OWNER_SCOPE },"domain":DOMAIN,
            "status":if passed { "passed" } else { "failed" },"allOwnersSettled":resources&&!disabled,
            "originalResourcesSettled":resources,"ownerDisabled":disabled,"retainedEffectUnknown":passed&&input.eof,
            "failureCode":failure,"bindings":input.inputs.bindings,"cases":cases,"notVerified":NOT_VERIFIED}))
    }
    pub(super) async fn run(eof:bool) {
        if BATCH_CLAIMED.swap(true,Ordering::SeqCst) {
            if !FIXTURE_FILES.all_settled() || !probes_settled() { retain_unknown_runtime().await; return; }
            panic!("hosted release-version batch already claimed");
        }
        let input=match Admitted::admit(eof) {
            Ok(input)=>input,Err(code)=> {
                if !FIXTURE_FILES.all_settled() { retain_unknown_runtime().await; return; }
                panic!("hosted release-version admission refused: {code:?}");
            },
        };
        if receipt(&input,&[],false,false,false,Some(Failure::NotCompleted)).is_err() {
            if !FIXTURE_FILES.all_settled() { retain_unknown_runtime().await; return; }
            panic!("hosted release-version partial receipt unavailable before native work");
        }
        let mut original=match Original::new(&input) {
            Ok(original)=>original,Err(code)=> {
                if !FIXTURE_FILES.all_settled() || !probes_settled() { retain_unknown_runtime().await; return; }
                panic!("hosted release-version original document refused before native work: {code:?}");
            },
        };
        let count=if eof { EOF_CASES.len() } else if input.mode==Mode::Source { SOURCE_CASES.len() } else { 1 };
        for ordinal in 0..count {
            let case_name=if eof { EOF_CASES[ordinal].name() } else if input.mode==Mode::Zip { Case::Edit.name() } else { SOURCE_CASES[ordinal].name() };
            let result=if eof { exercise_eof(&mut original,&input,EOF_CASES[ordinal]).await }
                else { exercise_owner(&mut original,&input,if input.mode==Mode::Zip { Case::Edit } else { SOURCE_CASES[ordinal] }).await };
            let expected_unknown=eof && ordinal==EOF_CASES.len()-1 && result.is_ok();
            if result.is_err() || !original.settled() || original.batch.owner.disabled()&&!expected_unknown { original.stop().await; }
            if !original.settled() || original.batch.owner.disabled()&&!expected_unknown
                || matches!(result,Err(Failure::OriginalCustodyUnknown|Failure::FixtureCustodyUnknown)) {
                if FIXTURE_FILES.all_settled() && probes_settled() && original.passive.settled() {
                    let _=receipt(&input,&original.batch.cases,false,false,original.batch.owner.disabled(),Some(Failure::OriginalCustodyUnknown));
                }
                retain_unknown_runtime().await; return;
            }
            if let Err(code)=result {
                let _=receipt(&input,&original.batch.cases,false,true,original.batch.owner.disabled(),Some(code));
                if !FIXTURE_FILES.all_settled() { retain_unknown_runtime().await; return; }
                panic!("hosted release-version {case_name} failed after original resource settlement: {code:?}");
            }
            if !expected_unknown && receipt(&input,&original.batch.cases,false,false,false,Some(Failure::NotCompleted)).is_err() {
                if !FIXTURE_FILES.all_settled() { retain_unknown_runtime().await; return; }
                panic!("hosted release-version progress receipt failed after original settlement");
            }
        }
        // No shutdown, fixture change, recovery or next native operation after
        // EOF's expected effect Unknown. Retain those exact original books.
        if !eof && (original.batch.owner.shutdown().await.is_err() || original.bridge.supervisor.shutdown().await.is_err())
            || !original.settled() { retain_unknown_runtime().await; return; }
        if receipt(&input,&original.batch.cases,true,true,original.batch.owner.disabled(),None).is_err() {
            if !FIXTURE_FILES.all_settled() { retain_unknown_runtime().await; return; }
            panic!("hosted release-version final receipt failed after original settlement");
        }
    }

    #[test]
    fn version_fixture_literal_and_scope_contract_is_closed() {
        // Pure finite DATA. Native admission is not inferred from these checks.
        assert!(!qualified(EditDomain::ReleaseVersion,false)); assert!(!qualified(EditDomain::ReleaseVersion,true));
        assert_eq!(SOURCE_CASES.len(),8);
        assert_eq!(SOURCE_CASES.last().map(|case| case.name()),Some("version-document-loss-before-apply"));
        assert_eq!(Case::Edit.name(),"observe-edit-two-spans-preserve");
        assert_eq!(EOF_CASES.last().map(|case| case.name()),Some("precommit-conflict-eof"));
        assert_eq!(hash(IGNORE),"cdf75f09188ea0e3712fcd26c9dbb42819dd467e9744676c6448b2a29a789c5b");
        assert_eq!(hash(ORIGINAL),"d8453785b2637e76d1b7456dd0e5ea0d343cfd5f7d409a06dc38ab791aa6334a");
        assert_eq!(hash(EDITED),"bc7f934bcf5f4fcf0b1b9c814613bd773ec4a9f579376f1dca01929d4e9e3732");
        assert_eq!(hash(CREATED),"3b8dbd6b58e9f42a0ed893e73020cf2f8ddde787e2b1a153da49d382b1e7a9d4");
        assert_eq!(hash(CONFIG_PUBLIC),"1dcd101a440da3c950903bca1b54f926aa63ce36ae5ed1eead5fb24f7813dfbd");
        assert_eq!(hash(CONFIG_RELEASE),"1b0b02e48d03cca36aaf36e5d8a8daf15f59924803bd4a5c0ec2e655828d3f94");
        assert_eq!(hash(CONFIG_NESTED),"8db69de9d4a3c83d312ee37e8952531f71b633f0f7f36b042b5d143cc2357de9");
        assert!(VersionFixturePermit::bootstrap_case(false,Path::new("/inert/owner"),None));
        assert!(!VersionFixturePermit::bootstrap_case(true,Path::new("/inert/owner"),None));
        for case in EOF_CASES {
            let path=Path::new("/inert").join(case.name());
            assert!(VersionFixturePermit::bootstrap_case(true,&path,Some(case)));
            assert!(!VersionFixturePermit::bootstrap_case(false,&path,Some(case)));
            assert!(!VersionFixturePermit::bootstrap_case(true,Path::new("/inert/wrong"),Some(case)));
            assert!(!WorkflowFixturePermit::bootstrap_case(true,&path,Some(case)));
            assert!(!MetadataFixturePermit::bootstrap_case(true,&path,Some(case)));
        }
        for case in [EofCase::Precommit,EofCase::Postcommit,EofCase::WorkflowPrecommit,EofCase::WorkflowPostcommit,EofCase::WorkflowConflict,
            EofCase::MetadataPrecommit,EofCase::MetadataPostcommit,EofCase::MetadataConflict] {
            assert!(!VersionFixturePermit::bootstrap_case(true,&Path::new("/inert").join(case.name()),Some(case)));
        }
        assert_eq!(EXTRA_SOURCES.len(),30);
        let mut keys=BTreeSet::new();
        for source in SOURCES.iter().chain(EXTRA_SOURCES) { assert!(keys.insert(source.id)); }
        assert_eq!(keys.len(),56);
    }
}

#[cfg(all(debug_assertions, not(feature = "desktop-shell"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "only the reviewed disposable source-or-ZIP Linux release-version-owner process"]
async fn hosted_release_version_edit_owner_original_resources() { version::run(false).await; }

#[cfg(all(debug_assertions, not(feature = "desktop-shell"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "only the reviewed disposable Linux release-version transaction EOF process"]
async fn hosted_release_version_transaction_eof_original_resources() { version::run(true).await; }

#[test]
fn version_eof_records_are_domain_distinct_and_exact() {
    let all=[EofCase::Precommit,EofCase::Postcommit,EofCase::WorkflowPrecommit,EofCase::WorkflowPostcommit,EofCase::WorkflowConflict,
        EofCase::MetadataPrecommit,EofCase::MetadataPostcommit,EofCase::MetadataConflict,
        EofCase::VersionPrecommit,EofCase::VersionPostcommit,EofCase::VersionConflict];
    for case in [EofCase::VersionPrecommit,EofCase::VersionPostcommit,EofCase::VersionConflict] {
        assert!(case.domain()==EditDomain::ReleaseVersion);
        let bytes=[case.marker(),case.summary()].concat();
        for width in [1,2,7,case.marker().len(),bytes.len()] {
            let mut control=EofControl::default();
            for chunk in bytes.chunks(width) { assert!(control.observe(case,chunk)); }
            assert!(control.complete(case)); assert_eq!(control.records(case),2); assert!(!control.observe(case,b"\n"));
        }
        for other in all {
            if other==case { continue; }
            let mut control=EofControl::default(); assert!(!control.observe(case,other.marker()));
        }
        for end in 0..bytes.len() {
            let mut control=EofControl::default(); assert!(control.observe(case,&bytes[..end])); assert!(!control.complete(case));
        }
        for index in 0..bytes.len() {
            let mut wrong=bytes.clone(); wrong[index]=b'!';
            let mut control=EofControl::default(); assert!(!control.observe(case,&wrong));
        }
    }
}
