//! SOURCE-only arm of the original Supervisor. It neither allocates a version
//! nor admits an account, Store floor, state write or release-version edit.
//! The same Resources owns inspection, child, IO, two native POST positions and
//! consuming close. A parsed FIN is necessary before close, never completion.
use super::*;
use crate::asset_source::RegisteredRoot;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[path="supervisor_version_reserve.rs"]
pub(super) mod reserve;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) use reserve::{VersionReserveControl,VersionReserveInvocation,VersionReserveJoined};

pub(crate) const SOURCE_PROTOCOL: &str = "mrk-version-allocation-source/1";
const PROVIDER: &str = "macos-clt-git/1";
const INITIAL_LIMIT: usize = 8192;
const READY_LIMIT: usize = 512;
const FIN_LIMIT: usize = 2048;
const CLEANUP: Duration = Duration::from_secs(10);

fn need(value: bool) -> Result<(), BridgeError> {
    if value {
        Ok(())
    } else {
        Err(BridgeError::protocol())
    }
}
fn unavailable() -> BridgeError {
    BridgeError::unavailable("The original saved-source inspection is unavailable.")
}
fn changed() -> BridgeError {
    BridgeError::new(
        "version_source_changed",
        "Read the saved configuration and version again after the original change settles.",
    )
}
fn hex(value: &str, count: usize) -> bool {
    value.len() == count && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn closed(value: &Value, fields: &[&str]) -> bool {
    value.as_object().is_some_and(|row| row.len() == fields.len() && fields.iter().all(|k| row.contains_key(*k)))
}
pub(crate) fn source_branch(value: &str) -> bool {
    let Some(name) = value.strip_prefix("refs/heads/") else {
        return false;
    };
    !name.is_empty()
        && name.len() <= 200
        && name.as_bytes()[0].is_ascii_alphanumeric()
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b"._/-".contains(&b))
        && !name.contains("..")
        && !name.starts_with("refs/")
        && name.split('/').count() <= 16
        && name.split('/').all(|p| !p.is_empty() && !p.starts_with('.') && !p.ends_with('.') && !p.ends_with(".lock"))
}
fn relative(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 512
        && !value.contains(['\\', '\0'])
        && value != "release/mobile-release.json"
        && value.split('/').count() <= 16
        && value.split('/').all(|p| !p.is_empty() && p.len() <= 255 && !matches!(p, "." | ".." | ".git"))
}

// Closed canonical JSON, matching Python ensure_ascii=True. In particular a
// Unicode native path is not silently assigned a different request digest.
fn encoded(value: &Value, limit: usize) -> Result<Vec<u8>, BridgeError> {
    use std::fmt::Write as _;
    let mut sorted = value.clone();
    sorted.sort_all_objects();
    let text = serde_json::to_string(&sorted).map_err(|_| BridgeError::protocol())?;
    let mut ascii = String::new();
    ascii.try_reserve_exact(text.len().min(limit)).map_err(|_| unavailable())?;
    for c in text.chars() {
        if c < '\u{7f}' {
            ascii.push(c);
        } else {
            for unit in c.encode_utf16(&mut [0; 2]).iter() {
                write!(&mut ascii, "\\u{unit:04x}").map_err(|_| BridgeError::protocol())?;
            }
        }
        need(ascii.len() < limit)?;
    }
    ascii.push('\n');
    Ok(ascii.into_bytes())
}
fn frame(raw: &[u8], limit: usize, nodes: usize, depth: usize) -> Result<Value, BridgeError> {
    need(
        raw.len() > 1
            && raw.len() <= limit
            && raw.last() == Some(&b'\n')
            && raw.iter().filter(|b| **b == b'\n').count() == 1
            && !raw.contains(&b'\r'),
    )?;
    let value = protocol::strict_json(&raw[..raw.len() - 1])?;
    need(github_protocol::bounds(&value, limit, nodes, depth) && encoded(&value, limit)? == raw)?;
    Ok(value)
}

/// Comparison DATA captured from the original saved-input lane under Doc/Edit.
/// Only that retained lane's gate can bind it to an actual native invocation.
pub(crate) struct VersionAllocationSourceInput {
    pub(crate) project_id: String,
    pub(crate) root: RegisteredRoot,
    pub(crate) configuration_size: u32,
    pub(crate) configuration_sha256: String,
    pub(crate) version_path: String,
    pub(crate) version_size: u32,
    pub(crate) version_sha256: String,
    pub(crate) reference: String,
}
impl VersionAllocationSourceInput {
    fn source_value(&self) -> Result<Value, BridgeError> {
        need(
            protocol::valid_id(&self.project_id)
                && source_branch(&self.reference)
                && relative(&self.version_path)
                && (1..=512 * 1024).contains(&self.configuration_size)
                && (1..=64 * 1024).contains(&self.version_size)
                && hex(&self.configuration_sha256, 64)
                && hex(&self.version_sha256, 64),
        )?;
        let root = self.root.path.to_str().ok_or_else(unavailable)?;
        need(
            root.starts_with('/')
                && !root.starts_with("//")
                && root.len() <= 4096
                && !root.contains(['\\', '\0'])
                && root.split('/').count() <= 24
                && root[1..].split('/').all(|p| !p.is_empty() && !matches!(p, "." | "..")),
        )?;
        #[cfg(any(
            all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),
            all(
                target_os = "macos",
                target_pointer_width = "64",
                any(target_arch = "aarch64", target_arch = "x86_64")
            )
        ))]
        let identity = self.root.identity.posix().map_err(|_| unavailable())?.preflight_identity();
        #[cfg(not(any(
            all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),
            all(
                target_os = "macos",
                target_pointer_width = "64",
                any(target_arch = "aarch64", target_arch = "x86_64")
            )
        )))]
        let identity: crate::offline_preflight_protocol::RootIdentity = return Err(unavailable());
        Ok(json!({"projectId":self.project_id,"projectRoot":root,"rootIdentity":identity,
            "savedConfig":{"bytes":self.configuration_size,"sha256":self.configuration_sha256},
            "savedVersion":{"source":self.version_path,"bytes":self.version_size,"sha256":self.version_sha256},"ref":self.reference}))
    }
    pub(crate) fn retained_bytes(&self) -> Option<usize> {
        std::mem::size_of::<Self>()
            .checked_add(self.project_id.capacity())?
            .checked_add(self.root.path.capacity())?
            .checked_add(self.configuration_sha256.capacity())?
            .checked_add(self.version_path.capacity())?
            .checked_add(self.version_sha256.capacity())?
            .checked_add(self.reference.capacity())
    }
    pub(crate) fn matches(&self, source: &VersionAllocationSource) -> bool {
        self.configuration_sha256 == source.configuration_sha256
            && self.version_sha256 == source.version_sha256
            && self.reference == source.reference
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct VersionAllocationSource {
    commit: String,
    tree: String,
    #[serde(rename = "ref")]
    reference: String,
    configuration_sha256: String,
    version_sha256: String,
}
impl VersionAllocationSource {
    fn valid(&self) -> bool {
        hex(&self.commit, 40)
            && hex(&self.tree, 40)
            && source_branch(&self.reference)
            && hex(&self.configuration_sha256, 64)
            && hex(&self.version_sha256, 64)
    }
}

#[derive(Clone, Copy)]
pub(super) struct Endpoints {
    pub(super) work: Instant,
    pub(super) hard: Instant,
}
impl Endpoints {
    pub(crate) fn at(start: Instant) -> Option<Self> {
        Some(Self {
            work: start.checked_add(Duration::from_secs(60))?,
            hard: start.checked_add(Duration::from_secs(70))?,
        })
    }
    pub(super) fn first_failure(self, at: Instant) -> Instant {
        at.min(self.work).checked_add(CLEANUP).unwrap_or(self.hard).min(self.hard)
    }
}

pub(crate) struct VersionAllocationSourceRequest {
    input: Arc<VersionAllocationSourceInput>,
    id: String,
    digest: String,
    initial: Vec<u8>,
    hard_ns: u64,
#[cfg(any(target_os = "linux", target_os = "macos"))]
    allocation: Option<Arc<crate::version_allocation_state_native::dialogue::Request>>,
}
impl VersionAllocationSourceRequest {
    fn from_original(
        input: Arc<VersionAllocationSourceInput>,
        id: &str,
        native: &crate::git_read_protocol::Native,
        work_ns: u64,
        hard_ns: u64,
    ) -> Result<Self, BridgeError> {
        need(
            protocol::valid_id(id)
                && native.valid()
                && work_ns > 0
                && hard_ns.checked_sub(work_ns) == Some(10_000_000_000)
                && native.root == input.root.path.to_str().ok_or_else(unavailable)?
                && (1..=1024).contains(&native.files.head.identity.6)
                && (1..=65536).contains(&native.files.config.identity.6)
                && native.files.index.as_ref().is_some_and(|s| (1..=2 * 1024 * 1024).contains(&s.identity.6)),
        )?;
        let source = input.source_value()?;
        let root = native.directories.root;
        need(
            source["rootIdentity"]
                == json!({"device":root.0.to_string(),"inode":root.1.to_string(),"mode":root.2,"uid":root.3,"gid":root.4}),
        )?;
        let initial = encoded(
            &json!({"protocol":SOURCE_PROTOCOL,"id":id,"action":{
            "source":source,"provider":{"kind":PROVIDER,"native":native},
            "clock":{"name":"CLOCK_UPTIME_RAW","workEndNs":work_ns.to_string(),"hardEndNs":hard_ns.to_string()}}}),
            INITIAL_LIMIT,
        )?;
        // The whole native projection must fit the existing fixed child parser.
        frame(&initial, INITIAL_LIMIT, 256, 8)?;
        let digest = format!("{:x}", Sha256::digest(&initial));
        Ok(Self { input, id: id.into(), digest, initial, hard_ns,
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            allocation:None })
    }
    pub(crate) fn same_input(&self, input: &Arc<VersionAllocationSourceInput>) -> bool {
        Arc::ptr_eq(&self.input, input)
    }
    fn ready(&self, raw: &[u8]) -> Result<(), BridgeError> {
        need(
            frame(raw, READY_LIMIT, 32, 4)?
                == json!({"protocol":SOURCE_PROTOCOL,"id":self.id,"ready":{"requestSha256":self.digest}}),
        )
    }
#[cfg(any(target_os = "linux", target_os = "macos"))]
    pub(crate) fn allocation_request(&self)->Option<&Arc<crate::version_allocation_state_native::dialogue::Request>> {self.allocation.as_ref()}
    pub(crate) fn go(&self) -> Result<Vec<u8>, BridgeError> {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        need(self.allocation.is_none())?;
        encoded(&json!({"protocol":SOURCE_PROTOCOL,"id":self.id,"go":{"requestSha256":self.digest}}), READY_LIMIT)
    }
    fn terminal(&self, raw: &[u8]) -> Result<Terminal, BridgeError> {
        let row = frame(raw, FIN_LIMIT, 64, 6)?;
        need(
            closed(&row, &["protocol", "id", "finished"]) && row["protocol"] == SOURCE_PROTOCOL && row["id"] == self.id,
        )?;
        let row = &row["finished"];
        need(
            closed(row, &["requestSha256", "source", "reason", "firstFailureNs", "lifetime"])
                && row["requestSha256"] == self.digest,
        )?;
        let life = &row["lifetime"];
        need(
            closed(life, &["originalsClosed", "borrowEnded", "handlersRestored", "commands", "profileCalls"])
                && life["originalsClosed"] == true
                && life["borrowEnded"] == true
                && life["handlersRestored"] == true
                && life["profileCalls"].as_u64() == Some(0),
        )?;
        let commands = life["commands"].as_u64().filter(|n| *n <= 7).ok_or_else(BridgeError::protocol)?;
        if row["reason"] == "none" {
            need(
                commands == 7
                    && row["firstFailureNs"].is_null()
                    && closed(&row["source"], &["commit", "tree", "ref", "configurationSha256", "versionSha256"]),
            )?;
            let source: VersionAllocationSource =
                serde_json::from_value(row["source"].clone()).map_err(|_| BridgeError::protocol())?;
            need(source.valid() && self.input.matches(&source))?;
            Ok(Terminal { source: Some(source), failure: None })
        } else {
            let reason = match row["reason"].as_str() {
                Some("source-refused") => Refusal::Source,
                Some("cancelled") => Refusal::Cancelled,
                _ => return Err(BridgeError::protocol()),
            };
            need(row["source"].is_null())?;
            let text = row["firstFailureNs"].as_str().ok_or_else(BridgeError::protocol)?;
            let first = text.parse::<u64>().map_err(|_| BridgeError::protocol())?;
            need(first > 0 && first < self.hard_ns && first.to_string() == text)?;
            Ok(Terminal { source: None, failure: Some((reason, first)) })
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Refusal {
    Allocation,
    Source,
    Cancelled,
}
impl Refusal {
    fn error(self) -> BridgeError {
        match self {
            Self::Allocation => BridgeError::new("version_reserve_refused", "The reservation needs attention; no saved version was changed."),
            Self::Source => changed(),
            Self::Cancelled => BridgeError::new("cancelled", "The original saved-source inspection was stopped."),
        }
    }
}
#[derive(Clone, Debug)]
struct Terminal {
    source: Option<VersionAllocationSource>,
    failure: Option<(Refusal, u64)>,
}

#[derive(Clone, Debug)]
pub(crate) enum VersionAllocationSourceReceipt {
    Pending,
    RetainedUnknown,
    Settled { outcome: Result<VersionAllocationSource, BridgeError>, settled_at: Instant, was_unknown: bool },
}
pub(super) struct Mailbox {
    receipt: VersionAllocationSourceReceipt,
    terminal: Option<Terminal>,
    first: Option<(Refusal, Instant)>,
    terminal_entered: bool,
    stdout_returned: bool,
    before_close: bool,
}
impl Mailbox {
    fn new() -> Self {
        Self {
            receipt: VersionAllocationSourceReceipt::Pending,
            terminal: None,
            first: None,
            terminal_entered: false,
            stdout_returned: false,
            before_close: false,
        }
    }
    fn retain_terminal(&mut self, terminal: Terminal) -> Result<(), BridgeError> {
        need(
            matches!(self.receipt, VersionAllocationSourceReceipt::Pending)
                && !self.terminal_entered
                && self.terminal.is_none(),
        )?;
        self.terminal_entered = true;
        self.terminal = Some(terminal);
        Ok(())
    }
    fn before_close(&mut self) -> Result<(), BridgeError> {
        need(
            matches!(self.receipt, VersionAllocationSourceReceipt::Pending)
                && self.stdout_returned
                && !self.before_close
                && self.terminal.as_ref().is_some_and(|t| t.failure.is_none() || self.first.is_some()),
        )?;
        self.before_close = true;
        Ok(())
    }
    fn unknown(&mut self) {
        if !matches!(self.receipt, VersionAllocationSourceReceipt::Settled { .. }) {
            self.receipt = VersionAllocationSourceReceipt::RetainedUnknown;
        }
    }
}

pub(super) struct Invocation {
    pub(super) gate: crate::asset_session::VersionAllocationSourceGoGate,
    pub(super) input: Arc<VersionAllocationSourceInput>,
    completion: Mutex<Option<crate::asset_session::VersionAllocationSourceCompletion>>,
    pub(super) mailbox: Arc<Mutex<Mailbox>>,
    request: Mutex<Option<Arc<VersionAllocationSourceRequest>>>,
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    reserve: Option<Arc<VersionReserveInvocation>>,
}
impl Invocation {
    pub(super) fn request(&self) -> Result<Arc<VersionAllocationSourceRequest>, BridgeError> {
        self.request
            .lock()
            .map_err(|_| BridgeError::cleanup_unknown())?
            .clone()
            .ok_or_else(BridgeError::cleanup_unknown)
    }
    pub(super) fn arm(&self,owner:&Arc<Owner>) -> Result<(), BridgeError> {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        if let Some(reserve)=&self.reserve {reserve.control.arm(owner)?;}
        self.completion
            .lock()
            .map_err(|_| BridgeError::cleanup_unknown())?
            .as_ref()
            .ok_or_else(BridgeError::cleanup_unknown)?
            .arm()
    }
    pub(super) fn unknown(&self) {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        if let Some(reserve)=&self.reserve {reserve.control.unknown();}
        lock(&self.mailbox).unknown();
        if let Some(completion) = lock(&self.completion).as_ref() {
            completion.unknown();
        }
    }
    // Called by Owner.retire OUTSIDE Supervisor/Resources locks, after all real
    // driver/watchdog/IO/native joins. FIN reader never publishes completion.
    pub(super) fn retire(&self, result: Result<(), BridgeError>, settled_at: Instant, was_unknown: bool, cutoff:Option<Instant>) {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        if let (Some(reserve),Some(cutoff))=(&self.reserve,cutoff) {reserve.control.retain_cutoff(cutoff);}
        let retained_unknown = matches!(lock(&self.mailbox).receipt, VersionAllocationSourceReceipt::RetainedUnknown);
        let mut outcome = result.and_then(|_| {
            let mailbox = lock(&self.mailbox);
            if !mailbox.before_close {
                return Err(BridgeError::cleanup_unknown());
            }
            let terminal = mailbox.terminal.as_ref().ok_or_else(BridgeError::cleanup_unknown)?;
            terminal
                .source
                .clone()
                .ok_or_else(|| terminal.failure.map_or_else(BridgeError::cleanup_unknown, |(r, _)| r.error()))
        });
        let mut unknown =
            was_unknown || retained_unknown || outcome.as_ref().is_err_and(|error| error.code == "cleanup_unknown");
        if unknown {
            outcome = Err(BridgeError::cleanup_unknown());
        }
        let original_completion = { lock(&self.completion).take() };
        let Some(mut completion) = original_completion else {
            self.unknown();
            return;
        };
        if let Err(error) = completion.complete(outcome.as_ref().ok(), unknown) {
            unknown |= error.code == "cleanup_unknown";
            if unknown {
                completion.unknown();
            }
            outcome = Err(error);
        }
        completion.returned();
        let mut mailbox = lock(&self.mailbox);
        if !matches!(mailbox.receipt, VersionAllocationSourceReceipt::Settled { .. }) {
            mailbox.receipt = VersionAllocationSourceReceipt::Settled { outcome, settled_at, was_unknown: unknown };
        }
    }
}

pub(crate) struct VersionAllocationSourceAdmission {
    pub(super) invocation: Invocation,
    pub(super) endpoints: Endpoints,
    #[cfg(all(
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64")
    ))]
    pub(super) originals: Arc<Mutex<Originals>>,
    bytes: usize,
}
impl VersionAllocationSourceAdmission {
    // Native/control backing only. The child has finite source/stream limits;
    // neither this expression nor the wire limits are a CPython RSS bound.
    pub(crate) fn reservation_bytes() -> Option<usize> {
        #[cfg(all(
            target_os = "macos",
            target_pointer_width = "64",
            any(target_arch = "aarch64", target_arch = "x86_64")
        ))]
        {
            let wire = INITIAL_LIMIT
                .checked_mul(6)?
                .checked_add(FIN_LIMIT * 5 + READY_LIMIT * 4)?
                .checked_add(256 * (std::mem::size_of::<Value>() + std::mem::size_of::<String>() + 64))?
                .checked_add(7 * 512 + 2 * 32768)?;
            Originals::working_bytes()?.checked_add(wire)?.checked_add(
                std::mem::size_of::<Self>()
                    + std::mem::size_of::<Owner>()
                    + std::mem::size_of::<Resources>()
                    + std::mem::size_of::<Invocation>()
                    + std::mem::size_of::<Mailbox>()
                    + 32 * 1024,
            )
        }
        #[cfg(not(all(
            target_os = "macos",
            target_pointer_width = "64",
            any(target_arch = "aarch64", target_arch = "x86_64")
        )))]
        {
            None
        }
    }
    /// Metadata allocation only. Called with original Doc/Edit admission; no
    /// filesystem, native account, service/state or repeated Document lock.
    pub(crate) fn reserve(
        input: Arc<VersionAllocationSourceInput>,
        gate: crate::asset_session::VersionAllocationSourceGoGate,
        completion: crate::asset_session::VersionAllocationSourceCompletion,
        started: Instant,
    ) -> Result<Self, BridgeError> {
        let endpoints = Endpoints::at(started).ok_or_else(BridgeError::timeout)?;
        need(Instant::now() < endpoints.work)?;
        #[cfg(all(
            target_os = "macos",
            target_pointer_width = "64",
            any(target_arch = "aarch64", target_arch = "x86_64")
        ))]
        {
            input.source_value()?;
            let bytes = Self::reservation_bytes()
                .and_then(|n| n.checked_add(input.retained_bytes()?))
                .ok_or_else(unavailable)?;
            let originals = Arc::new(Mutex::new(Originals::reserve()?));
            Ok(Self {
                invocation: Invocation {
                    gate,
                    input,
                    completion: Mutex::new(Some(completion)),
                    mailbox: Arc::new(Mutex::new(Mailbox::new())),
                    request: Mutex::new(None),
                    #[cfg(any(target_os = "linux", target_os = "macos"))]
                    reserve: None,
                },
                endpoints,
                originals,
                bytes,
            })
        }
        #[cfg(not(all(
            target_os = "macos",
            target_pointer_width = "64",
            any(target_arch = "aarch64", target_arch = "x86_64")
        )))]
        {
            let _ = (input, gate, completion, endpoints);
            Err(unavailable())
        }
    }
#[cfg(any(target_os = "linux", target_os = "macos"))]
    pub(crate) fn with_reserve(mut self,reserve:Arc<VersionReserveInvocation>)->Result<Self,BridgeError> {
        need(reserve.control.current()&&reserve.control.work_end()==self.endpoints.work&&self.invocation.reserve.is_none())?;
        self.bytes=self.bytes.checked_add(VersionReserveInvocation::reservation_bytes().ok_or_else(unavailable)?).ok_or_else(unavailable)?;
        self.invocation.reserve=Some(reserve);Ok(self)
    }
    pub(crate) fn bytes(&self) -> usize {
        self.bytes
    }
}

pub(super) enum Work {
    Post(Result<Result<(),BridgeError>,tokio::task::JoinError>),
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    State(Option<reserve::StateRequest>),
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    Joined(Result<crate::version_allocation_state_native::jobs::Joined,crate::version_allocation_state_native::jobs::Failure>),
}
impl SourceResources {
    pub(super) fn work_pending(&self)->bool {
        let pending=self.before_go_pending();
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        { return pending||self.remote.as_ref().is_some_and(reserve::RemoteJobs::pending); }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        { pending }
    }
    pub(super) async fn next_work(&mut self)->Work {
        let post=&mut self.posts[0];let post_pending=post.handle.is_some()&&!post.failed;
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        if let Some(remote)=&mut self.remote {
            let join_pending=remote.jobs.join_pending();let receive=remote.requests.is_some()&&!join_pending;
            return tokio::select! {
                result=join_slot(&mut post.handle),if post_pending=>Work::Post(result),
                request=async{match &mut remote.requests {Some(rx)=>rx.recv().await,None=>std::future::pending().await}},if receive=>Work::State(request),
                result=remote.jobs.join_current(),if join_pending=>Work::Joined(result),
            }
        }
        Work::Post(join_slot(&mut post.handle).await)
    }
    pub(super) fn work_returned(&mut self,work:Work,owner:&Arc<Owner>,inner:&Inner)->bool {
        let result:Result<(),BridgeError>=match work {
            Work::Post(result)=>return self.before_go_returned(result,owner,inner),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            Work::State(request)=>self.remote.as_mut().ok_or_else(BridgeError::cleanup_unknown).and_then(|r|r.accept(request,owner)),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            Work::Joined(result)=>self.remote.as_mut().ok_or_else(BridgeError::cleanup_unknown).and_then(|r|r.returned(result,owner)),
        };
        if let Err(error)=result {owner.fail(error);}
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        { return !owner.version_allocation_source.as_ref().and_then(|s|s.reserve.as_ref()).is_some_and(|r|r.control.uncertain()); }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        { true }
    }
}

struct SourceTail {
    original: gh_auth::FinalObserverReturn,
    // 0 fresh, 1 original waiter entered, 2 actual join returned, 3 unknown.
    stage: std::sync::atomic::AtomicU8,
}
pub(crate) struct VersionAllocationSourceTicket {
    owner: Arc<Owner>,
    mailbox: Arc<Mutex<Mailbox>>,
    tail: Arc<SourceTail>,
}
pub(crate) struct VersionAllocationSourceWait {
    owner: Arc<Owner>,
    mailbox: Arc<Mutex<Mailbox>>,
    tail: Arc<SourceTail>,
}
impl VersionAllocationSourceTicket {
    pub(crate) fn operation_id(&self) -> &str {
        &self.owner.id
    }
    pub(crate) fn stop(&self) {
        self.owner.fail(Refusal::Cancelled.error());
    }
    pub(crate) fn receipt(&self) -> VersionAllocationSourceReceipt {
        match (self.tail.stage.load(Ordering::SeqCst), &lock(&self.mailbox).receipt) {
            (3, _) => VersionAllocationSourceReceipt::RetainedUnknown,
            (2, value) => value.clone(),
            (_, VersionAllocationSourceReceipt::Settled { .. }) => VersionAllocationSourceReceipt::Pending,
            (_, value) => value.clone(),
        }
    }
    pub(crate) fn wait_original(&self) -> VersionAllocationSourceWait {
        VersionAllocationSourceWait {
            owner: self.owner.clone(),
            mailbox: self.mailbox.clone(),
            tail: self.tail.clone(),
        }
    }
}
struct SourceWaitGuard<'a> {
    tail: &'a SourceTail,
    returned: bool,
}
impl Drop for SourceWaitGuard<'_> {
    fn drop(&mut self) {
        if !self.returned {
            self.tail.stage.store(3, Ordering::SeqCst);
        }
    }
}
impl VersionAllocationSourceWait {
    pub(crate) async fn returned(self) -> VersionAllocationSourceReceipt {
        if self.tail.stage.compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst).is_err() {
            self.tail.stage.store(3, Ordering::SeqCst);
            return VersionAllocationSourceReceipt::RetainedUnknown;
        }
        let mut guard = SourceWaitGuard { tail: &self.tail, returned: false };
        loop {
            let changed = self.owner.changed.notified();
            let receipt = lock(&self.mailbox).receipt.clone();
            match receipt {
                VersionAllocationSourceReceipt::Pending => changed.await,
                VersionAllocationSourceReceipt::RetainedUnknown => {
                    return VersionAllocationSourceReceipt::RetainedUnknown
                }
                VersionAllocationSourceReceipt::Settled { was_unknown: true, .. } => {
                    return VersionAllocationSourceReceipt::RetainedUnknown
                }
                VersionAllocationSourceReceipt::Settled { .. } => {
                    // Existing COMMON original observer join, not a Gh ticket,
                    // receipt or credential. Call outside Doc and only after
                    // the same Owner's real terminal. Failed/late stays latched.
                    if !self.tail.original.join_original(&self.owner).await {
                        return VersionAllocationSourceReceipt::RetainedUnknown;
                    }
                    self.tail.stage.store(2, Ordering::SeqCst);
                    guard.returned = true;
                    return receipt;
                }
            }
        }
    }
}
pub(super) fn selected(profile: Profile) -> bool {
    cfg!(all(
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64"),
        feature = "desktop-shell",
        feature = "custom-protocol",
        not(feature = "development-runtime"),
        not(feature = "ubuntu-runtime-publisher")
    )) && matches!(profile, Profile::VersionAllocationSource)
}
impl Supervisor {
    pub(crate) fn version_allocation_source_available(&self) -> bool {
        selected(Profile::VersionAllocationSource) && self.inner.runtime.version_allocation_source_profile_available()
    }
    /// Original caller still holds Doc/Edit through registration. Runnable
    /// workers enter only after admit releases its original entry barriers.
    pub(crate) fn start_version_allocation_source(
        &self,
        admission: VersionAllocationSourceAdmission,
    ) -> Result<VersionAllocationSourceTicket, BridgeError> {
        if !self.version_allocation_source_available() {
            return Err(unavailable());
        }
        let mailbox = admission.invocation.mailbox.clone();
        let tail = Arc::new(SourceTail {
            original: gh_auth::FinalObserverReturn::new(),
            stage: std::sync::atomic::AtomicU8::new(0),
        });
        let owner = self
            .admit(AdmissionRequest::VersionAllocationSource(admission), CompletionTarget::VersionAllocationSource)?;
        Ok(VersionAllocationSourceTicket { owner, mailbox, tail })
    }
}

#[cfg(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
pub(super) struct Originals {
    runtime: crate::installed_runtime::VersionAllocationSourceRuntimeSlots,
    source: crate::asset_source::GitReadSources,
    bridge: Option<mrk_macos_installed_native::vault_helper_wire::ClockBridge>,
    inspected: bool,
    before_go: bool,
    after_work: bool,
    closed: bool,
    interrupted: bool,
}
#[cfg(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
impl Originals {
    fn working_bytes() -> Option<usize> {
        crate::installed_runtime::VersionAllocationSourceRuntimeSlots::working_reservation_bytes()?
            .checked_add(crate::asset_source::GitReadSources::working_bytes()?)?
            .checked_add(std::mem::size_of::<Self>())
    }
    fn reserve() -> Result<Self, BridgeError> {
        let mut runtime = crate::installed_runtime::VersionAllocationSourceRuntimeSlots::new();
        runtime.reserve_once().map_err(|_| unavailable())?;
        // A distinct Source-owned instance, never a borrowed GitRead ticket or
        // source result. Retained here before inspection may begin any IO.
        Ok(Self {
            runtime,
            source: crate::asset_source::GitReadSources::new(),
            bridge: None,
            inspected: false,
            before_go: false,
            after_work: false,
            closed: false,
            interrupted: false,
        })
    }
    pub(super) fn no_child_state(&self) -> (bool, bool) {
        (self.runtime.never_started() && self.source.not_started() && !self.closed, self.runtime.no_child_effect())
    }
    pub(super) fn interrupted(&mut self) {
        self.interrupted = true;
        self.runtime.mark_interrupted();
        self.source.mark_interrupted();
    }
    fn source_failure(owner: &Owner, first: Option<(mrk_macos_installed_native::vault_filesystem::Failure, Instant)>) {
        owner.observe_native_failure(first.map(|(f, at)| {
            (
                if f == mrk_macos_installed_native::vault_filesystem::Failure::Unknown {
                    crate::installed_runtime::AdmissionFailure::Unknown
                } else {
                    crate::installed_runtime::AdmissionFailure::Native
                },
                at,
            )
        }));
    }
    pub(super) fn settle(&mut self, owner: &Owner) -> CloseOutcome {
        if self.closed {
            return CloseOutcome::Unknown;
        }
        self.closed = true;
        // Both original sets are attempted within the same contraction-only
        // endpoint. A failed source close is not silently replaced by runtime
        // close, and no caller receives a second close/reopen opportunity.
        let source = self.source.close(&mut |first| {
            Self::source_failure(owner, first);
            owner.native_cleanup_expired(None)
        });
        Self::source_failure(owner, self.source.first_failure());
        let runtime = self.runtime.settle_originals(&mut |first| owner.native_cleanup_expired(first));
        if source.is_ok() && matches!(runtime, CloseOutcome::Settled) && self.settled() {
            CloseOutcome::Settled
        } else {
            CloseOutcome::Unknown
        }
    }
    pub(super) fn settled(&self) -> bool {
        self.closed && !self.interrupted && self.runtime.settled() && self.source.settled()
    }
}

#[cfg(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
pub(super) fn transfer_original(resources: &Resources, inner: &Inner, owner: &Arc<Owner>) -> Result<(), BridgeError> {
    let (inspection, acquisition) = passive_borrows(resources);
    need(
        inspection.returned == Some(ManagementJoin::Returned)
            && inspection.positive()
            && acquisition.returned.is_none()
            && acquisition.positive(),
    )?;
    let original = resources
        .version_allocation_source
        .as_ref()
        .and_then(|s| s.originals.as_ref())
        .ok_or_else(BridgeError::cleanup_unknown)?;
    let mut original = original.try_lock().map_err(|_| BridgeError::cleanup_unknown())?;
    let owners = lock(&inner.owners);
    let state = lock(&owner.state);
    need(source_claim_clear(
        owners.get(&owner.key).is_some_and(|actual| Arc::ptr_eq(actual, owner)),
        owner.profile,
        &state,
        Instant::now(),
        inner.stopping.load(Ordering::SeqCst),
        inner.disabled.load(Ordering::SeqCst),
        *owner.stop.borrow(),
    ))?;
    original.runtime.transfer_once().map_err(|_| BridgeError::cleanup_unknown())
}

impl Invocation {
    #[cfg(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
    pub(super) fn inspect(
        &self,
        config: &RuntimeConfig,
        owner: &Owner,
        originals: &Arc<Mutex<Originals>>,
    ) -> Result<VerifiedRuntime, BridgeError> {
        // The inspection is the SAME retained Resources.inspection original.
        // Document currentness comes first; native/account/file IO is outside
        // Doc. The worker never calls back into Doc with a native mutex held.
        self.gate.check_current(&self.input)?;
        let mut original = originals.lock().map_err(|_| BridgeError::cleanup_unknown())?;
        if original.inspected || original.bridge.is_some() || original.interrupted {
            return Err(BridgeError::cleanup_unknown());
        }
        original.inspected = true;
        let endpoints = owner.version_allocation_source_endpoints.ok_or_else(BridgeError::cleanup_unknown)?;
        original.bridge = Some(
            mrk_macos_installed_native::vault_helper_wire::ClockBridge::capture()
                .ok_or_else(BridgeError::cleanup_unknown)?,
        );
        let clock = original.bridge.as_ref().ok_or_else(BridgeError::cleanup_unknown)?;
        let work_ns = clock.endpoint(endpoints.work).ok_or_else(BridgeError::cleanup_unknown)?;
        let hard_ns = clock.endpoint(endpoints.hard).ok_or_else(BridgeError::cleanup_unknown)?;
        let stop = owner.stop.subscribe();
        let armed = original.runtime.arm_acl_once(owner.endpoint(), &stop);
        owner.observe_native_failure(original.runtime.first_failure());
        armed.map_err(|_| BridgeError::cleanup_unknown())?;
        let selected =
            config.resolve_version_allocation_source_installed(&mut original.runtime, owner.endpoint(), &stop);
        owner.observe_native_failure(original.runtime.first_failure());
        let selected = selected?;
        let live = crate::installed_runtime::VersionAllocationSourceRuntimeSlots::source_runtime_fd_bound();
        let inspected = original.source.inspect(&self.input.root, live, &mut || {
            owner.failed()
                || *stop.borrow()
                || Instant::now() >= owner.endpoint()
                || !self.gate.current_control(&self.input)
        });
        Originals::source_failure(owner, original.source.first_failure());
        inspected.map_err(|reason| {
            if reason == crate::asset_commands::Reason::CleanupUnknown {
                BridgeError::cleanup_unknown()
            } else {
                changed()
            }
        })?;
        let mut request = VersionAllocationSourceRequest::from_original(
            self.input.clone(),
            &owner.id,
            original.source.native_snapshot().map_err(|_| changed())?,
            work_ns,
            hard_ns,
        )?;
        // The same inspection original retains native custody, but drops its
        // SourceBook mutex before Store/NativeUse IO or any final Doc gate.
        drop(original);
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        if let Some(reserve)=&self.reserve {reserve.prepare(&mut request,work_ns,hard_ns)?;}
        let request=Arc::new(request);
        {
            let mut slot = self.request.lock().map_err(|_| BridgeError::cleanup_unknown())?;
            if slot.is_some() {
                return Err(BridgeError::cleanup_unknown());
            }
            *slot = Some(request.clone());
        }
        self.gate.bind_request(&self.input, &owner.id, request)?;
        Ok(selected)
    }
    #[cfg(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
    fn post(&self, owner: &Owner, originals: &Arc<Mutex<Originals>>, phase: PostPhase) -> Result<(), BridgeError> {
        // Driver may be waiting while retaining Resources. These checks are
        // only the existing short control/registry check; the full short Doc/Edit GO gate runs after
        // this actual job returns and is joined, with no native mutex held.
        if !self.gate.current_control(&self.input) {
            return Err(changed());
        }
        let mut original = originals.lock().map_err(|_| BridgeError::cleanup_unknown())?;
        if !original.inspected || original.closed || original.interrupted {
            return Err(BridgeError::cleanup_unknown());
        }
        match phase {
            PostPhase::BeforeGo if !original.before_go && !original.after_work => original.before_go = true,
            PostPhase::AfterWork if original.before_go && !original.after_work => original.after_work = true,
            _ => return Err(BridgeError::cleanup_unknown()),
        }
        let stop = owner.stop.subscribe();
        let end = owner.source_work_end();
        let posted = original
            .runtime
            .capability()
            .and_then(|runtime| runtime.post_original(end, &stop, &mut |first| owner.observe_native_failure(first)));
        owner.observe_native_failure(original.runtime.first_failure());
        posted.map_err(|f| match f {
            crate::installed_runtime::AdmissionFailure::Unknown => BridgeError::cleanup_unknown(),
            crate::installed_runtime::AdmissionFailure::Deadline => BridgeError::timeout(),
            _ => changed(),
        })?;
        let posted = original.source.post(&mut || {
            owner.failed() || *stop.borrow() || Instant::now() >= end || !self.gate.current_control(&self.input)
        });
        Originals::source_failure(owner, original.source.first_failure());
        posted.map_err(|reason| {
            if reason == crate::asset_commands::Reason::CleanupUnknown {
                BridgeError::cleanup_unknown()
            } else {
                changed()
            }
        })?;
        if !self.gate.current_control(&self.input) {
            return Err(changed());
        }
        Ok(())
    }
}

#[cfg(all(
    target_os = "macos",
    target_pointer_width = "64",
    any(target_arch = "aarch64", target_arch = "x86_64"),
    feature = "desktop-shell",
    feature = "custom-protocol",
    not(feature = "development-runtime"),
    not(feature = "ubuntu-runtime-publisher")
))]
pub(super) fn acquire_original(
    inner: &Inner,
    owner: &Arc<Owner>,
    originals: &Arc<Mutex<Originals>>,
) -> Result<Child, AcquisitionError> {
    let mut original = originals.lock().map_err(|_| AcquisitionError::unsupported("Saved-source custody was lost"))?;
    if original.interrupted || !original.inspected || original.closed {
        return Err(AcquisitionError::unsupported("Saved-source custody was refused"));
    }
    let runtime = original.runtime.capability().map_err(AcquisitionError::capability)?;
    let stop = owner.stop.subscribe();
    let mut first = None;
    let selected = runtime
        .prepare_once_observed(owner.endpoint(), &stop, &mut |value| {
            first = value;
            owner.observe_native_failure(value);
        })
        .map_err(|f| AcquisitionError::preparation(f).with_macos_first_failure(first))?;
    let mut command = Command::new(&selected.python);
    command
        .args(["-I", "-S", "-B"])
        .arg(&selected.bootstrap)
        .arg(&selected.core)
        .current_dir(&selected.cwd)
        .env_clear()
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(false);
    crate::runtime::macos_installed_environment(&mut command).map_err(AcquisitionError::from)?;
    let owners = lock(&inner.owners);
    let state = lock(&owner.state);
    if !source_claim_clear(
        owners.get(&owner.key).is_some_and(|actual| Arc::ptr_eq(actual, owner)),
        owner.profile,
        &state,
        Instant::now(),
        inner.stopping.load(Ordering::SeqCst),
        inner.disabled.load(Ordering::SeqCst),
        *owner.stop.borrow(),
    ) {
        return Err(AcquisitionError::unsupported("The original saved-source claim was refused"));
    }
    runtime.claim_once().map_err(AcquisitionError::final_claim)?;
    drop(state);
    drop(owners);
    command.spawn().map_err(AcquisitionError::returned_spawn)
}
#[cfg(all(
    target_os = "macos",
    target_pointer_width = "64",
    any(target_arch = "aarch64", target_arch = "x86_64"),
    not(all(
        feature = "desktop-shell",
        feature = "custom-protocol",
        not(feature = "development-runtime"),
        not(feature = "ubuntu-runtime-publisher")
    ))
))]
pub(super) fn acquire_original(
    _inner: &Inner,
    _owner: &Arc<Owner>,
    _originals: &Arc<Mutex<Originals>>,
) -> Result<Child, AcquisitionError> {
    Err(AcquisitionError::unsupported("The installed saved-source profile is unavailable"))
}

pub(super) fn source_claim_clear(
    original: bool,
    profile: Profile,
    state: &OwnerState,
    now: Instant,
    stopping: bool,
    disabled: bool,
    stop: bool,
) -> bool {
    original
        && matches!(profile, Profile::VersionAllocationSource)
        && !state.terminal
        && !state.unknown
        && state.error.is_none()
        && state.cleanup_endpoint.is_none()
        && !stopping
        && !disabled
        && !stop
        && now < state.endpoint
}
fn claim_go(inner: &Inner, owner: &Arc<Owner>) -> bool {
    let owners = lock(&inner.owners);
    let state = lock(&owner.state);
    source_claim_clear(
        owners.get(&owner.key).is_some_and(|actual| Arc::ptr_eq(actual, owner)),
        owner.profile,
        &state,
        Instant::now(),
        inner.stopping.load(Ordering::SeqCst),
        inner.disabled.load(Ordering::SeqCst),
        *owner.stop.borrow(),
    ) && owner.preflight_go_claimed.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).is_ok()
}
impl Owner {
    fn source_work_end(&self) -> Instant {
        let state = lock(&self.state);
        state.cleanup_endpoint.map_or(state.endpoint, |e| e.min(state.endpoint))
    }
    // Reader-side F observation contracts ONLY. Setting fail/STOP here would
    // kill the child before FIN -> stdin close -> worker EOF can finish.
    fn contract_source_failure(&self, refusal: Refusal, first: Instant) -> Result<(), BridgeError> {
        let endpoints = self.version_allocation_source_endpoints.ok_or_else(BridgeError::cleanup_unknown)?;
        let invocation = self.version_allocation_source.as_ref().ok_or_else(BridgeError::cleanup_unknown)?;
        {
            let mut mailbox = invocation.mailbox.lock().map_err(|_| BridgeError::cleanup_unknown())?;
            if mailbox.first.is_some() || !mailbox.terminal_entered {
                return Err(BridgeError::cleanup_unknown());
            }
            mailbox.first = Some((refusal, first));
        }
        let mut state = lock(&self.state);
        if state.terminal || state.unknown {
            return Err(BridgeError::cleanup_unknown());
        }
        let contracted = endpoints.first_failure(first);
        state.cleanup_endpoint = Some(state.cleanup_endpoint.map_or(contracted, |prior| prior.min(contracted)));
        drop(state);
        self.changed.notify_waiters();
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum PostPhase {
    BeforeGo = 0,
    AfterWork = 1,
}
#[derive(Default)]
struct Post {
    handle: Option<JoinHandle<Result<(), BridgeError>>>,
    returned: Option<Result<(), BridgeError>>,
    failed: bool,
    ack: Option<oneshot::Sender<Result<(), BridgeError>>>,
    entered: bool,
}
#[derive(Default)]
pub(super) struct SourceResources {
    #[cfg(all(
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64")
    ))]
    pub(super) originals: Option<Arc<Mutex<Originals>>>,
    posts: [Post; 2],
#[cfg(any(target_os = "linux", target_os = "macos"))]
    remote: Option<reserve::RemoteJobs>,
}
impl SourceResources {
    pub(super) fn from_admission(admission: &VersionAllocationSourceAdmission) -> Self {
        #[cfg(not(all(
            target_os = "macos",
            target_pointer_width = "64",
            any(target_arch = "aarch64", target_arch = "x86_64")
        )))]
        let _ = admission;
        Self {
            #[cfg(all(
                target_os = "macos",
                target_pointer_width = "64",
                any(target_arch = "aarch64", target_arch = "x86_64")
            ))]
            originals: Some(admission.originals.clone()),
            ..Self::default()
        }
    }
    pub(super) fn jobs_settled(&self) -> bool {
        self.posts.iter().all(|p| p.handle.is_none() && !p.failed && (!p.entered || p.returned.is_some()))
            && self.remote_jobs_settled()
    }
    fn remote_jobs_settled(&self) -> bool {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        { return self.remote.as_ref().is_none_or(reserve::RemoteJobs::settled); }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        { true }
    }
    pub(super) fn before_go_pending(&self) -> bool {
        self.posts[0].handle.is_some() && !self.posts[0].failed
    }
    pub(super) async fn join_before_go(&mut self) -> Result<Result<(), BridgeError>, tokio::task::JoinError> {
        join_slot(&mut self.posts[0].handle).await
    }
    pub(super) fn request_before_go(&mut self, reply: oneshot::Sender<Result<(), BridgeError>>, owner: &Arc<Owner>) {
        if self.posts[0].ack.is_some() || self.posts[0].entered {
            let error = BridgeError::cleanup_unknown();
            owner.fail(error.clone());
            let _ = reply.send(Err(error));
            return;
        }
        self.posts[0].ack = Some(reply);
        if let Err(error) = self.start(owner, PostPhase::BeforeGo) {
            owner.fail(error.clone());
            if let Some(reply) = self.posts[0].ack.take() {
                let _ = reply.send(Err(error));
            }
        }
    }
    fn start(&mut self, owner: &Arc<Owner>, phase: PostPhase) -> Result<(), BridgeError> {
        let post = &mut self.posts[phase as usize];
        if post.entered
            || post.failed
            || post.handle.is_some()
            || post.returned.is_some()
            || owner.failed()
            || Instant::now() >= owner.source_work_end()
        {
            return Err(BridgeError::cleanup_unknown());
        }
        post.entered = true;
        #[cfg(all(
            target_os = "macos",
            target_pointer_width = "64",
            any(target_arch = "aarch64", target_arch = "x86_64")
        ))]
        {
            let originals = self.originals.clone().ok_or_else(BridgeError::cleanup_unknown)?;
            let owner = owner.clone();
            let (release, enter) = oneshot::channel();
            post.handle = Some(tokio::task::spawn_blocking(move || {
                // Nothing native runs until its actual JoinHandle is stored in
                // these same Resources. Cancellation keeps that original handle.
                let result = (|| {
                    enter.blocking_recv().map_err(|_| BridgeError::cleanup_unknown())?;
                    if owner.failed() || *owner.stop.borrow() || Instant::now() >= owner.source_work_end() {
                        return Err(BridgeError::timeout());
                    }
                    owner
                        .version_allocation_source
                        .as_ref()
                        .ok_or_else(BridgeError::cleanup_unknown)?
                        .post(&owner, &originals, phase)
                })();
                if let Err(error) = &result {
                    owner.fail(error.clone());
                }
                result
            }));
            if release.send(()).is_err() {
                return Err(BridgeError::cleanup_unknown());
            }
            Ok(())
        }
        #[cfg(not(all(
            target_os = "macos",
            target_pointer_width = "64",
            any(target_arch = "aarch64", target_arch = "x86_64")
        )))]
        {
            Err(unavailable())
        }
    }
    pub(super) fn before_go_returned(
        &mut self,
        result: Result<Result<(), BridgeError>, tokio::task::JoinError>,
        owner: &Arc<Owner>,
        inner: &Inner,
    ) -> bool {
        let post = &mut self.posts[0];
        let reply = match result {
            Ok(result) => {
                post.returned = Some(result.clone());
                post.handle.take();
                if let Err(error) = &result {
                    owner.fail(error.clone());
                }
                if owner.failed() || *owner.stop.borrow() || Instant::now() >= owner.source_work_end() {
                    Err(lock(&owner.state).error.clone().unwrap_or_else(BridgeError::timeout))
                } else {
                    result
                }
            }
            Err(_) => {
                post.failed = true; // Retain failed original handle; never repoll.
                if let Some(reply) = post.ack.take() {
                    let _ = reply.send(Err(BridgeError::cleanup_unknown()));
                }
                owner.unknown(inner);
                return false;
            }
        };
        if !post.ack.take().is_some_and(|ack| ack.send(reply).is_ok()) {
            owner.fail(BridgeError::cleanup_unknown());
        }
        true
    }
}

/// Actual IO/child joins have already returned when drive calls this. A valid
/// terminal is necessary before any consuming native close. AfterWork remains
/// an original job with its handle retained through the real returned join.
pub(super) async fn before_native_close(resources: &mut Resources, inner: &Inner, owner: &Arc<Owner>) -> bool {
    let checked = (|| {
        if owner.failed()
            || !resources.waited.is_some_and(|s| s.success())
            || !resources.write_end.is_some_and(|e| e.complete)
            || resources.out_end.as_ref().is_none_or(|e| !e.eof || e.overflow)
            || resources.err_end.as_ref().is_none_or(|e| !e.eof || e.overflow || !e.bytes.is_empty())
        {
            return Err(BridgeError::cleanup_unknown());
        }
        let invocation = owner.version_allocation_source.as_ref().ok_or_else(BridgeError::cleanup_unknown)?;
        lock(&invocation.mailbox).before_close()
    })();
    if checked.is_err() {
        owner.unknown(inner);
        return false;
    }
    let Some(source) = resources.version_allocation_source.as_mut() else {
        owner.unknown(inner);
        return false;
    };
    if let Err(error) = source.start(owner, PostPhase::AfterWork) {
        owner.fail(error);
        owner.unknown(inner);
        return false;
    }
    let post = &mut source.posts[1];
    match join_slot(&mut post.handle).await {
        Ok(result) => {
            post.returned = Some(result.clone());
            post.handle.take();
            if let Err(error) = result {
                owner.fail(error);
            }
        }
        Err(_) => {
            post.failed = true;
            owner.unknown(inner);
            return false;
        }
    }
    // Now, and only now, the same mapped refusal enters ordinary first-failure
    // handling. The helper's EOF handshake has finished; STOP can no longer
    // truncate it. Earlier native/IO/Unknown failures retain their precedence.
    if let Some(invocation) = &owner.version_allocation_source {
        if let Some((refusal, first)) = lock(&invocation.mailbox).first {
            let mut state = lock(&owner.state);
            state.fail_at(refusal.error(), first);
            drop(state);
            owner.stop.send_replace(true);
            owner.changed.notify_waiters();
        }
    }
    true
}

// Exactly one stdout cursor. The bounded one-byte read prevents a READY read
// from prefetching a FIN before the original writer has actually written GO.
async fn line<R: AsyncRead + Unpin>(reader: &mut R, limit: usize) -> Result<Vec<u8>, BridgeError> {
    let mut raw = Vec::new();
    raw.try_reserve_exact(limit).map_err(|_| unavailable())?;
    let mut byte = [0u8; 1];
    loop {
        if reader.read(&mut byte).await.map_err(|_| BridgeError::cleanup_unknown())? != 1 {
            return Err(BridgeError::protocol());
        }
        raw.push(byte[0]);
        if byte[0] == b'\n' {
            return Ok(raw);
        }
        if raw.len() == limit {
            return Err(BridgeError::protocol());
        }
    }
}
async fn terminal_after_go<R: AsyncRead + Unpin>(
    reader: &mut R,
    request: &VersionAllocationSourceRequest,
    go_written: oneshot::Receiver<()>,
) -> Result<Terminal, BridgeError> {
    go_written.await.map_err(|_| BridgeError::cleanup_unknown())?;
    let raw = line(reader, FIN_LIMIT).await?;
    request.terminal(&raw)
}
pub(super) async fn read_source<R: AsyncRead + Unpin>(
    mut reader: R,
    request: Arc<VersionAllocationSourceRequest>,
    owner: Arc<Owner>,
    originals: SourceOriginals,
    ready: oneshot::Sender<Result<(), BridgeError>>,
    go_written: oneshot::Receiver<()>,
    finished: oneshot::Sender<()>,
    faults: mpsc::Sender<BridgeError>,
) -> ReadEnd {
    let mut ready = Some(ready);
    let result = async {
        let raw = line(&mut reader, READY_LIMIT).await?;
        request.ready(&raw)?;
        ready
            .take()
            .ok_or_else(BridgeError::cleanup_unknown)?
            .send(Ok(()))
            .map_err(|_| BridgeError::cleanup_unknown())?;
        // Original actual write return, not a reader receipt or a GO claim.
        let terminal = terminal_after_go(&mut reader, &request, go_written).await?;
        let failure = terminal.failure;
        let invocation = owner.version_allocation_source.as_ref().ok_or_else(BridgeError::cleanup_unknown)?;
        lock(&invocation.mailbox).retain_terminal(terminal)?;
        if let Some((refusal, raw_first)) = failure {
            let first = originals.failure_bound(raw_first)?;
            owner.contract_source_failure(refusal, first)?;
        }
        // The writer must close its actual stdin now. Waiting for stdout EOF
        // before this signal would deadlock the child's terminal EOF handshake.
        finished.send(()).map_err(|_| BridgeError::cleanup_unknown())?;
        let mut byte = [0u8; 1];
        need(reader.read(&mut byte).await.map_err(|_| BridgeError::cleanup_unknown())? == 0)?;
        let mut mailbox = lock(&invocation.mailbox);
        need(!mailbox.stdout_returned && mailbox.terminal_entered)?;
        mailbox.stdout_returned = true;
        Ok::<(), BridgeError>(())
    }
    .await;
    if let Err(error) = result {
        if let Some(ready) = ready {
            let _ = ready.send(Err(error.clone()));
        }
        let _ = faults.try_send(error);
        return ReadEnd { bytes: Vec::new(), eof: false, overflow: true };
    }
    ReadEnd { bytes: Vec::new(), eof: true, overflow: false }
}

/// A fixed borrow of this same original source set for ClockBridge only. It
/// cannot nominate a source, replace a bridge, close a book or create a worker.
pub(super) struct SourceOriginals {
    #[cfg(all(
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64")
    ))]
    original: Arc<Mutex<Originals>>,
}
impl SourceResources {
    pub(super) fn reader_original(&self) -> Result<SourceOriginals, BridgeError> {
        #[cfg(all(
            target_os = "macos",
            target_pointer_width = "64",
            any(target_arch = "aarch64", target_arch = "x86_64")
        ))]
        {
            Ok(SourceOriginals { original: self.originals.clone().ok_or_else(BridgeError::cleanup_unknown)? })
        }
        #[cfg(not(all(
            target_os = "macos",
            target_pointer_width = "64",
            any(target_arch = "aarch64", target_arch = "x86_64")
        )))]
        {
            Err(unavailable())
        }
    }
}
impl SourceOriginals {
    fn failure_bound(&self, raw: u64) -> Result<Instant, BridgeError> {
        #[cfg(all(
            target_os = "macos",
            target_pointer_width = "64",
            any(target_arch = "aarch64", target_arch = "x86_64")
        ))]
        {
            let mut original = self.original.lock().map_err(|_| BridgeError::cleanup_unknown())?;
            if original.closed || original.interrupted {
                return Err(BridgeError::cleanup_unknown());
            }
            original
                .bridge
                .as_mut()
                .ok_or_else(BridgeError::cleanup_unknown)?
                .failure_bound(raw)
                .ok_or_else(BridgeError::cleanup_unknown)
        }
        #[cfg(not(all(
            target_os = "macos",
            target_pointer_width = "64",
            any(target_arch = "aarch64", target_arch = "x86_64")
        )))]
        {
            let _ = raw;
            Err(unavailable())
        }
    }
}

pub(super) async fn write_source<W: tokio::io::AsyncWrite + Unpin>(
    mut writer: W,
    request: Arc<VersionAllocationSourceRequest>,
    ready: oneshot::Receiver<Result<(), BridgeError>>,
    go_written: oneshot::Sender<()>,
    finished: oneshot::Receiver<()>,
    post_request: oneshot::Sender<oneshot::Sender<Result<(), BridgeError>>>,
    inner: Arc<Inner>,
    owner: Arc<Owner>,
    faults: mpsc::Sender<BridgeError>,
) -> WriteEnd {
    let mut stop = owner.stop.subscribe();
    let result = async {
        if *stop.borrow() || owner.failed() || Instant::now() >= owner.source_work_end() { return Err(BridgeError::timeout()); }
        tokio::select! { biased; _ = stop.changed() => return Err(BridgeError::shutdown()),
            value = writer.write_all(&request.initial) => value.map_err(|_| BridgeError::cleanup_unknown())? }
        let ready = tokio::select! { biased; _ = stop.changed() => return Err(BridgeError::shutdown()), value = ready => value };
        ready.map_err(|_| BridgeError::cleanup_unknown())??;
        let (reply, returned) = oneshot::channel();
        post_request.send(reply).map_err(|_| BridgeError::cleanup_unknown())?;
        let posted = tokio::select! { biased; _ = stop.changed() => return Err(BridgeError::shutdown()), value = returned => value };
        posted.map_err(|_| BridgeError::cleanup_unknown())??;
        let invocation = owner.version_allocation_source.as_ref().ok_or_else(BridgeError::cleanup_unknown)?;
        let go = invocation.gate.claim(&invocation.input, &owner.id, &request, || claim_go(&inner, &owner))?;
        need(go == request.go()?)?;
        if *stop.borrow() || owner.failed() || Instant::now() >= owner.source_work_end() { return Err(BridgeError::timeout()); }
        tokio::select! { biased; _ = stop.changed() => return Err(BridgeError::shutdown()),
            value = writer.write_all(&go) => value.map_err(|_| BridgeError::cleanup_unknown())? }
        go_written.send(()).map_err(|_| BridgeError::cleanup_unknown())?;
        let terminal = tokio::select! { biased; _ = stop.changed() => return Err(BridgeError::shutdown()), value = finished => value };
        terminal.map_err(|_| BridgeError::cleanup_unknown())?;
        // Source refusal may have shortened the cleanup endpoint without STOP.
        // No extension and no successful closure at or after that bound.
        if owner.failed() || Instant::now() >= owner.source_work_end() { return Err(BridgeError::timeout()); }
        writer.shutdown().await.map_err(|_| BridgeError::cleanup_unknown())?;
        Ok::<(), BridgeError>(())
    }.await;
    // Even an early error drops THIS actual ChildStdin. It is not labelled a
    // successful shutdown/EOF handshake, and the original task is still joined.
    drop(writer);
    match result {
        Ok(()) => WriteEnd { complete: true },
        Err(error) => {
            owner.fail(error.clone());
            let _ = faults.try_send(error);
            WriteEnd { complete: false }
        }
    }
}

/// Install the sole source dialogue in the SAME Resources. All task captures,
/// one-shot cells and buffers are covered by the pre-registration quote. Its
/// release latch prevents any IO before all three original handles are stored.
pub(super) fn install_io(
    resources: &mut Resources,
    inner: &Arc<Inner>,
    owner: &Arc<Owner>,
    stdin: tokio::process::ChildStdin,
    stdout: tokio::process::ChildStdout,
    stderr: tokio::process::ChildStderr,
    faults: &mpsc::Sender<BridgeError>,
) -> Result<oneshot::Receiver<oneshot::Sender<Result<(), BridgeError>>>, BridgeError> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    if owner.version_allocation_source.as_ref().is_some_and(|s|s.reserve.is_some()) {
        return reserve::install_io(resources,inner,owner,stdin,stdout,stderr,faults);
    }
    need(resources.writer.is_none() && resources.stdout.is_none() && resources.stderr.is_none())?;
    let request = owner.version_allocation_source.as_ref().ok_or_else(BridgeError::cleanup_unknown)?.request()?;
    let original =
        resources.version_allocation_source.as_ref().ok_or_else(BridgeError::cleanup_unknown)?.reader_original()?;
    let (ready_send, ready_read) = oneshot::channel();
    let (go_send, go_read) = oneshot::channel();
    let (fin_send, fin_read) = oneshot::channel();
    let (post_send, post_read) = oneshot::channel();
    let (release_writer, enter_writer) = oneshot::channel();
    let (release_stdout, enter_stdout) = oneshot::channel();
    let (release_stderr, enter_stderr) = oneshot::channel();
    let (original_owner, original_inner, output_request, sender) =
        (owner.clone(), inner.clone(), request.clone(), faults.clone());
    resources.writer = Some(tokio::spawn(async move {
        if enter_writer.await.is_err() {
            return WriteEnd { complete: false };
        }
        write_source(
            stdin,
            output_request,
            ready_read,
            go_send,
            fin_read,
            post_send,
            original_inner,
            original_owner,
            sender,
        )
        .await
    }));
    let (original_owner, sender) = (owner.clone(), faults.clone());
    resources.stdout = Some(tokio::spawn(async move {
        if enter_stdout.await.is_err() {
            return ReadEnd { bytes: Vec::new(), eof: false, overflow: true };
        }
        read_source(stdout, request, original_owner, original, ready_send, go_read, fin_send, sender).await
    }));
    let sender = faults.clone();
    resources.stderr = Some(tokio::spawn(async move {
        if enter_stderr.await.is_err() {
            return ReadEnd { bytes: Vec::new(), eof: false, overflow: true };
        }
        read_bounded(stderr, FIN_LIMIT, sender).await
    }));
    if release_stdout.send(()).is_err() || release_stderr.send(()).is_err() || release_writer.send(()).is_err() {
        return Err(BridgeError::cleanup_unknown());
    }
    Ok(post_read)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request_data() -> VersionAllocationSourceRequest {
        // Deliberately NON-native comparison DATA. Never passed to reserve,
        // source_value, a runtime slot, an actual gate or installed IO owner.
        let input = Arc::new(VersionAllocationSourceInput {
            project_id: "comparison-only".into(),
            root: RegisteredRoot {
                path: "/not-opened/comparison".into(),
                identity: crate::asset_source::ProjectIdentity::Windows { volume: 0, file_id: [0; 16] },
            },
            configuration_size: 1,
            configuration_sha256: "a".repeat(64),
            version_path: "version.properties".into(),
            version_size: 1,
            version_sha256: "b".repeat(64),
            reference: "refs/heads/main".into(),
        });
        VersionAllocationSourceRequest {
            input,
            id: "source-data".into(),
            digest: "c".repeat(64),
            initial: Vec::new(),
            hard_ns: 70_000_000_000,
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            allocation:None,
        }
    }
    fn terminal_data(request: &VersionAllocationSourceRequest) -> Value {
        json!({"protocol":SOURCE_PROTOCOL,"id":request.id,"finished":{"requestSha256":request.digest,
            "source":{"commit":"d".repeat(40),"tree":"e".repeat(40),"ref":request.input.reference,
                "configurationSha256":request.input.configuration_sha256,"versionSha256":request.input.version_sha256},
            "reason":"none","firstFailureNs":null,"lifetime":{"originalsClosed":true,"borrowEnded":true,"handlersRestored":true,"commands":7,"profileCalls":0}}})
    }
    #[test]
    fn source_canonical_encoding_is_ascii_bounded_and_not_loose_json() {
        let value = json!({"z":"\u{7f}😀é","a":1});
        let raw = encoded(&value, 128).unwrap();
        assert_eq!(raw, b"{\"a\":1,\"z\":\"\\u007f\\ud83d\\ude00\\u00e9\"}\n");
        assert_eq!(frame(&raw, 128, 8, 2).unwrap(), value);
        assert!(encoded(&value, raw.len() - 1).is_err());
        for raw in [b"{\"a\": 1}\n".as_slice(), b"{\"a\":1,\"a\":1}\n", b"{\"a\":1}\r\n", b"{\"a\":1}\n{}\n"] {
            assert!(frame(raw, 128, 8, 2).is_err());
        }
    }
    #[test]
    fn only_fixed_branch_subset_and_version_path_are_source_inputs() {
        assert!(source_branch("refs/heads/release/1.2"));
        for name in [
            "main",
            "refs/tags/1.2",
            "refs/heads/-bad",
            "refs/heads/x..y",
            "refs/heads/x.lock",
            "refs/heads/refs/main",
            "refs/heads/x/",
        ] {
            assert!(!source_branch(name));
        }
        assert!(relative("app/version.properties"));
        for path in ["", "/version", "../version", ".git/version", "release/mobile-release.json", "a\\b", "a\0b"] {
            assert!(!relative(path));
        }
    }
    #[test]
    fn exact_success_cannot_override_source_pins_or_cleanup_veto() {
        let request = request_data();
        let row = terminal_data(&request);
        assert!(request.terminal(&encoded(&row, FIN_LIMIT).unwrap()).unwrap().source.is_some());
        for field in ["originalsClosed", "borrowEnded", "handlersRestored"] {
            let mut changed = row.clone();
            changed["finished"]["lifetime"][field] = json!(false);
            assert!(request.terminal(&encoded(&changed, FIN_LIMIT).unwrap()).is_err());
        }
        for (field, value) in [("commands", json!(6)), ("profileCalls", json!(1))] {
            let mut changed = row.clone();
            changed["finished"]["lifetime"][field] = value;
            assert!(request.terminal(&encoded(&changed, FIN_LIMIT).unwrap()).is_err());
        }
        for (field, value) in [
            ("ref", json!("refs/heads/other")),
            ("configurationSha256", json!("f".repeat(64))),
            ("versionSha256", json!("f".repeat(64))),
            ("commit", json!("f".repeat(64))),
        ] {
            let mut changed = row.clone();
            changed["finished"]["source"][field] = value;
            assert!(request.terminal(&encoded(&changed, FIN_LIMIT).unwrap()).is_err());
        }
        let mut changed = row.clone();
        changed["finished"]["reason"] = json!("cancelled");
        assert!(request.terminal(&encoded(&changed, FIN_LIMIT).unwrap()).is_err());
    }
    #[test]
    fn clean_refusal_needs_original_first_failure_and_exact_finite_lifetime() {
        let request = request_data();
        let mut row = terminal_data(&request);
        row["finished"]["source"] = Value::Null;
        row["finished"]["reason"] = json!("source-refused");
        row["finished"]["firstFailureNs"] = json!("1000000000");
        row["finished"]["lifetime"]["commands"] = json!(0);
        let parsed = request.terminal(&encoded(&row, FIN_LIMIT).unwrap()).unwrap();
        assert!(parsed.source.is_none());
        assert_eq!(parsed.failure, Some((Refusal::Source, 1_000_000_000)));
        for first in
            [Value::Null, json!(0), json!("0"), json!("01"), json!("70000000000"), json!("18446744073709551616")]
        {
            let mut changed = row.clone();
            changed["finished"]["firstFailureNs"] = first;
            assert!(request.terminal(&encoded(&changed, FIN_LIMIT).unwrap()).is_err());
        }
        for reason in ["none", "cleanup-unknown", "source-changed", ""] {
            let mut changed = row.clone();
            changed["finished"]["reason"] = json!(reason);
            assert!(request.terminal(&encoded(&changed, FIN_LIMIT).unwrap()).is_err());
        }
    }
    #[tokio::test]
    async fn one_line_never_prefetches_the_following_frame() {
        let (mut writer, mut reader) = tokio::io::duplex(64);
        writer.write_all(b"ready\nnext\n").await.unwrap();
        writer.shutdown().await.unwrap();
        assert_eq!(line(&mut reader, 6).await.unwrap(), b"ready\n");
        assert_eq!(line(&mut reader, 6).await.unwrap(), b"next\n");
        assert!(line(&mut reader, 6).await.is_err());
    }
    #[tokio::test]
    async fn no_fin_read_before_actual_go_written_or_after_its_sender_is_lost() {
        let request = request_data();
        let raw = encoded(&terminal_data(&request), FIN_LIMIT).unwrap();
        let (mut writer, mut reader) = tokio::io::duplex(FIN_LIMIT);
        writer.write_all(&raw).await.unwrap();
        let (send, receive) = oneshot::channel();
        {
            let future = terminal_after_go(&mut reader, &request, receive);
            tokio::pin!(future);
            assert!(tokio::time::timeout(Duration::from_millis(1), &mut future).await.is_err());
            send.send(()).unwrap();
            assert!(future.await.unwrap().source.is_some());
        }
        writer.write_all(&raw).await.unwrap();
        let (send, receive) = oneshot::channel();
        drop(send);
        assert!(terminal_after_go(&mut reader, &request, receive).await.is_err());
        assert_eq!(line(&mut reader, FIN_LIMIT).await.unwrap(), raw); // Zero extra reads on lost GO.
    }
    #[test]
    fn terminal_is_not_native_close_or_original_retirement() {
        let request = request_data();
        let terminal = request.terminal(&encoded(&terminal_data(&request), FIN_LIMIT).unwrap()).unwrap();
        let mut mailbox = Mailbox::new();
        mailbox.retain_terminal(terminal.clone()).unwrap();
        assert!(mailbox.before_close().is_err());
        assert!(mailbox.retain_terminal(terminal).is_err());
        assert!(matches!(mailbox.receipt, VersionAllocationSourceReceipt::Pending));
        mailbox.unknown();
        mailbox.stdout_returned = true;
        assert!(mailbox.before_close().is_err());
        assert!(matches!(mailbox.receipt, VersionAllocationSourceReceipt::RetainedUnknown));
    }
    #[test]
    fn source_cutoff_only_contracts_and_profile_does_not_lend_preflight_go() {
        let start = Instant::now();
        let ends = Endpoints::at(start).unwrap();
        assert_eq!(ends.work, start + Duration::from_secs(60));
        assert_eq!(ends.hard, start + Duration::from_secs(70));
        let first = ends.first_failure(start + Duration::from_secs(2));
        assert_eq!(first, start + Duration::from_secs(12));
        assert_eq!(first.min(ends.first_failure(start + Duration::from_secs(30))), first);
        let mut state = OwnerState::new(ends.work, None);
        state.version_allocation_source_endpoints = Some(ends);
        assert!(source_claim_clear(true, Profile::VersionAllocationSource, &state, start, false, false, false));
        assert!(!source_claim_clear(true, Profile::GitHubPreflight, &state, start, false, false, false));
        assert!(!preflight_claim_clear(
            true,
            Profile::VersionAllocationSource,
            Profile::GitHubPreflight,
            &state,
            start,
            false,
            false,
            false
        ));
        state.cleanup_endpoint = Some(first); // Same contraction-only reader state.
        assert!(state.error.is_none());
        assert!(!source_claim_clear(true, Profile::VersionAllocationSource, &state, start, false, false, false));
        state.fail_at(changed(), start + Duration::from_secs(2));
        assert_eq!(state.cleanup_endpoint, Some(first));
    }
}
