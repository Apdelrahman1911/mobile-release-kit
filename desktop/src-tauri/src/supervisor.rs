//! Original-child owner for closed passive API methods and the fixed GitHub
//! read-only profile. Never reuse this for builds, hooks, signing, or an engine
//! that can spawn descendants.
//!
//! An independent watchdog includes blocking runtime inspection and spawn time.
//! Renderer cancellation only drops a reply receiver, never these owner tasks.
//! One final observer owns the original driver/watchdog joins before retirement.
//! After the one cleanup allowance, uncertainty is reported and ownership is
//! retained; late positive settlement cannot restore successful admission.
use std::{collections::BTreeMap, future::pending, process::ExitStatus, sync::{Arc, Mutex, MutexGuard, atomic::{AtomicBool, AtomicU64, Ordering}}, time::{Duration, Instant}};
#[cfg(any(all(feature = "development-runtime", debug_assertions),
    all(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64")),
        not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), any(test, feature = "desktop-shell"))))]
use std::process::Stdio;
use serde_json::Value;
use tokio::{io::{AsyncRead, AsyncReadExt, AsyncWriteExt}, process::Child, sync::{mpsc, oneshot, watch, Mutex as AsyncMutex, Notify, OwnedSemaphorePermit, Semaphore}, task::JoinHandle};
#[cfg(any(all(feature = "development-runtime", debug_assertions),
    all(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64")),
        not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), any(test, feature = "desktop-shell"))))]
use tokio::process::Command;
use crate::{error::BridgeError, github_connection_protocol::{self as github_protocol, GitHubReadOutcome},
    protocol::{self, Method}, runtime::{RuntimeConfig, VerifiedRuntime}};
#[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64")))]
use crate::installed_runtime::{CloseOutcome, PassiveInstalledRuntime, PassiveRuntimeSlots};

pub const OPERATION_TIME: Duration = Duration::from_secs(10);
pub const CLEANUP_TIME: Duration = Duration::from_secs(2);
const ACTIVE_LIMIT: usize = 2;

#[cfg(all(test, feature = "development-runtime"))]
#[path = "hosted_tests.rs"]
mod hosted_tests;
#[cfg(all(test, debug_assertions, feature = "development-runtime", target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
pub(crate) use hosted_tests::github_fixture::{GitHubDocumentFixtureBinding, GitHubDocumentFixturePermit, GitHubFixtureRuntime};
#[cfg(all(test, debug_assertions, feature = "development-runtime", target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
pub(crate) use hosted_tests::github_tls::GitHubTlsRuntime;
#[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "development-runtime", target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
pub(crate) use hosted_tests::session_gtk_probe;
#[cfg(all(test, debug_assertions, feature = "development-runtime", not(feature = "desktop-shell"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
pub(crate) use hosted_tests::metadata_fixture_probe;
#[cfg(test)]
#[path = "passive_management_tests.rs"]
mod management_tests;
#[cfg(all(test, feature = "desktop-shell", target_os = "linux", target_arch = "x86_64", target_env = "gnu",
    not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher")))]
#[path = "installed_shell_shutdown_observation.rs"]
mod shell_shutdown_observation;
#[cfg(all(test, feature = "desktop-shell", target_os = "linux", target_arch = "x86_64", target_env = "gnu",
    not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher")))]
pub(crate) use shell_shutdown_observation::HeldAppInfo;
#[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", target_os = "linux", target_arch = "x86_64", target_env = "gnu",
    not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher")))]
pub(crate) use shell_shutdown_observation::{InstalledSessionQueries, SessionQueryHold};

fn lock<T>(value: &Mutex<T>) -> MutexGuard<'_, T> {
    // No user callback/serialization runs while these small bookkeeping locks
    // are held. Retain the data even on poisoning; never drop the resource owner.
    value.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[derive(Clone)]
pub struct Supervisor { inner: Arc<Inner> }
struct Inner {
    runtime: RuntimeConfig, permits: Arc<Semaphore>, next: AtomicU64,
    stopping: AtomicBool, disabled: AtomicBool,
    owners: Mutex<BTreeMap<u64, Arc<Owner>>>, changed: Notify,
    #[cfg(all(test, feature = "development-runtime"))]
    test: hosted_tests::Hooks,
    #[cfg(all(test, target_os = "linux", target_arch = "x86_64", target_env = "gnu",
        not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher")))]
    native_test: installed_native_fixture::Hooks,
}
struct Owner {
    key: u64, id: String, profile: Profile,
    github_receipt: Option<Arc<Mutex<GitHubReadReceipt>>>,
    state: Mutex<OwnerState>, resources: AsyncMutex<Resources>,
    stop: watch::Sender<bool>, changed: Notify, permit: Mutex<Option<OwnedSemaphorePermit>>,
    driver: AsyncMutex<Option<JoinHandle<DriverEnd>>>, watchdog: AsyncMutex<Option<JoinHandle<WatchdogEnd>>>,
    observer: AsyncMutex<Option<JoinHandle<()>>>,
    #[cfg(all(test, feature = "development-runtime"))]
    observation: Arc<Mutex<hosted_tests::Observation>>,
}
struct OwnerState {
    endpoint: Instant, cleanup_endpoint: Option<Instant>, error: Option<BridgeError>,
    terminal: bool, unknown: bool,
    reply: Option<oneshot::Sender<Result<Value, BridgeError>>>,
    driver_join: ManagementJoin, watchdog_join: ManagementJoin,
    driver_end: Option<DriverEnd>, watchdog_end: Option<WatchdogEnd>,
}

// These are private original-return receipts, not task-body success flags.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ManagementJoin { Pending, Returned, Missing, Cancelled, Panicked, Failed, InvalidReturn }
impl ManagementJoin {
    fn original_result(self) -> bool {
        matches!(self, Self::Returned | Self::Cancelled | Self::Panicked | Self::Failed)
    }
    fn error(error: &tokio::task::JoinError) -> Self {
        if error.is_cancelled() { Self::Cancelled } else if error.is_panic() { Self::Panicked } else { Self::Failed }
    }
}
#[derive(Debug, PartialEq)]
enum ReadOutcome { Passive(Value), GitHub(GitHubReadOutcome) }
enum DriverEnd { Ready(Result<ReadOutcome, BridgeError>), RetainedUnknown }

#[derive(Clone, Copy)]
enum Profile { Passive(Method), GitHubReadOnly }
impl Profile {
    fn stdout_limit(self) -> usize {
        match self {
            Self::Passive(Method::EnvironmentRequirements) => crate::environment::RESPONSE_LIMIT,
            Self::Passive(Method::MetadataTextObserve | Method::MetadataTextValidate) => crate::metadata_text_edit_protocol::RESPONSE_LIMIT,
            Self::Passive(_) => protocol::RESPONSE_LIMIT, Self::GitHubReadOnly => github_protocol::RESPONSE_LIMIT,
        }
    }
    fn decode(self, bytes: &[u8], id: &str) -> Result<ReadOutcome, BridgeError> {
        match self {
            Self::Passive(Method::EnvironmentRequirements) => crate::environment::decode_envelope(bytes, id).map(ReadOutcome::Passive),
            Self::Passive(Method::MetadataTextObserve | Method::MetadataTextValidate) => crate::metadata_text_edit_protocol::decode_passive_envelope(bytes, id).map(ReadOutcome::Passive),
            Self::Passive(_) => protocol::decode_response(bytes, id).map(ReadOutcome::Passive),
            Self::GitHubReadOnly => github_protocol::decode_private_response(id, bytes).map(ReadOutcome::GitHub),
        }
    }
}

// Borrowed admission only, never retained by an owner/task or derived as
// Debug/Clone/Serialize. The one credential copy is the bounded writer buffer.
enum AdmissionRequest<'a> {
    Passive { method: Method, params: &'a Value },
    GitHub { repository: &'a str, expected_account_id: Option<&'a str>, expected_repository_id: Option<&'a str>, token: &'a str },
}
impl AdmissionRequest<'_> {
    fn profile(&self) -> Profile {
        match self { Self::Passive { method, .. } => Profile::Passive(*method), Self::GitHub { .. } => Profile::GitHubReadOnly }
    }
    fn encode(self, id: &str) -> Result<Vec<u8>, BridgeError> {
        match self {
            Self::Passive { method, params } => protocol::encode_request(id, method, params),
            Self::GitHub { repository, expected_account_id, expected_repository_id, token } =>
                github_protocol::encode_private_request(id, repository, expected_account_id, expected_repository_id, token),
        }
    }
}
enum CompletionTarget {
    Passive(oneshot::Sender<Result<Value, BridgeError>>),
    GitHub(Arc<Mutex<GitHubReadReceipt>>),
}

/// A bounded native-only mailbox. Early unknown is not original resource
/// retirement; only Owner::retire may install Settled after its checked joins.
#[derive(Clone, Debug)]
pub(crate) enum GitHubReadReceipt {
    Pending,
    RetainedUnknown,
    Settled { outcome: Result<GitHubReadOutcome, BridgeError>, settled_at: Instant, was_unknown: bool },
}
/// Exact original owner reference, not a PID, renderer handle or new joiner.
/// Drop neither stops nor settles. No token-bearing Debug/Clone/Serialize DTO.
pub(crate) struct GitHubReadTicket {
    owner: Arc<Owner>, receipt: Arc<Mutex<GitHubReadReceipt>>,
}
impl GitHubReadTicket {
    pub(crate) fn operation_id(&self) -> &str { &self.owner.id }
    pub(crate) fn stop(&self) {
        self.owner.fail(BridgeError::new("cancelled", "The GitHub read-only observation was cancelled."));
    }
    pub(crate) fn receipt(&self) -> GitHubReadReceipt { lock(&self.receipt).clone() }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WatchdogEnd {
    DriverObserved(ManagementJoin),
    CleanupExpired { endpoint: Instant, observed_at: Instant },
}

impl OwnerState {
    fn new(endpoint: Instant, reply: Option<oneshot::Sender<Result<Value, BridgeError>>>) -> Self {
        Self { endpoint, cleanup_endpoint: None, error: None, terminal: false, unknown: false, reply,
            driver_join: ManagementJoin::Pending, watchdog_join: ManagementJoin::Pending,
            driver_end: None, watchdog_end: None }
    }
    fn fail_at(&mut self, error: BridgeError, now: Instant) {
        if self.terminal { return; }
        if self.error.is_none() { self.error = Some(error); }
        if self.cleanup_endpoint.is_none() { self.cleanup_endpoint = Some(now.min(self.endpoint) + CLEANUP_TIME); }
    }
    fn management_ready(&self) -> bool {
        self.driver_join == ManagementJoin::Returned && self.watchdog_join == ManagementJoin::Returned
            && matches!(self.driver_end, Some(DriverEnd::Ready(_))) && self.watchdog_end.is_some()
    }
    fn accepts_watchdog(&self, end: WatchdogEnd) -> bool {
        match end {
            // The returned observation is captured inside the original watchdog,
            // so a later driver join cannot legitimize an unexplained early return.
            WatchdogEnd::DriverObserved(observed) => observed.original_result() && observed == self.driver_join,
            WatchdogEnd::CleanupExpired { endpoint, observed_at } => self.unknown
                && self.cleanup_endpoint == Some(endpoint) && observed_at >= endpoint,
        }
    }
    fn retirement_result(&mut self, now: Instant, stopping: bool) -> Option<Result<ReadOutcome, BridgeError>> {
        // The caller holds registry -> state while sampling the real clock and
        // shutdown latch. This small decision also admits fixed-value tests of
        // simultaneous-ready joins/deadlines without replacing the product clock.
        if self.terminal || !self.management_ready() { return None; }
        if stopping { self.fail_at(BridgeError::shutdown(), now); }
        if now >= self.endpoint { self.fail_at(BridgeError::timeout(), now); }
        if self.cleanup_endpoint.is_some_and(|endpoint| now >= endpoint) { self.unknown = true; }
        let Some(DriverEnd::Ready(result)) = self.driver_end.take() else { return None; };
        Some(if self.unknown {
            let error = BridgeError::cleanup_unknown();
            #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
            let error = error.with_linux_passive_cause(self.error.as_ref().and_then(BridgeError::linux_passive_cause));
            Err(error)
        }
            else { match &self.error { Some(error) => Err(error.clone()), None => result } })
    }
}

// The SAME acquisition's error return, not another owner or receipt. The raw
// io::Error remains private; only closed returned facts reach BridgeError.
#[derive(Debug)]
struct AcquisitionError {
    original: std::io::Error,
    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    cause: Option<crate::error::LinuxPassiveCause>,
}
impl From<std::io::Error> for AcquisitionError {
    fn from(original: std::io::Error) -> Self {
        Self { original,
            #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
            cause: None,
        }
    }
}
impl AcquisitionError {
    fn unsupported(message: &'static str) -> Self {
        std::io::Error::new(std::io::ErrorKind::Unsupported, message).into()
    }
    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    fn with_cause(mut self, cause: crate::error::LinuxPassiveCause) -> Self {
        self.cause = Some(cause); self
    }
    #[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64")))]
    fn capability(failure: crate::installed_runtime::AdmissionFailure) -> Self {
        let error = Self::unsupported("passive installed custody is unavailable");
        #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
        let error = error.with_cause(crate::error::LinuxPassiveCause::Capability(failure));
        #[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu")))]
        let _ = failure;
        error
    }
    #[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64")))]
    fn preparation(failure: crate::installed_runtime::AdmissionFailure) -> Self {
        let error = Self::unsupported("passive installed preparation refused");
        #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
        let error = error.with_cause(crate::error::LinuxPassiveCause::Preparation(failure));
        #[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu")))]
        let _ = failure;
        error
    }
    #[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64")))]
    fn final_claim(failure: crate::installed_runtime::AdmissionFailure) -> Self {
        let error = Self::unsupported("passive installed custody is unavailable");
        #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
        let error = error.with_cause(crate::error::LinuxPassiveCause::FinalClaim(failure));
        #[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu")))]
        let _ = failure;
        error
    }
    fn returned_spawn(original: std::io::Error) -> Self {
        #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
        let cause = {
            use crate::error::LinuxSpawnFailure as F;
            use rustix::io::Errno;
            match original.raw_os_error() {
                Some(code) if code == Errno::MFILE.raw_os_error() => F::ProcessFdLimit,
                Some(code) if code == Errno::NFILE.raw_os_error() => F::SystemFdLimit,
                Some(code) if code == Errno::NOMEM.raw_os_error() => F::Memory,
                Some(code) if code == Errno::AGAIN.raw_os_error() => F::ResourceUnavailable,
                Some(code) if code == Errno::ACCESS.raw_os_error() || code == Errno::PERM.raw_os_error() => F::PermissionDenied,
                Some(code) if code == Errno::NOENT.raw_os_error() => F::NotFound,
                Some(code) if code == Errno::NOEXEC.raw_os_error() => F::ExecFormat,
                _ => F::Other,
            }
        };
        Self { original,
            #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
            cause: Some(crate::error::LinuxPassiveCause::ReturnedSpawn(cause)),
        }
    }
    fn into_bridge_error(self) -> BridgeError {
        let error = BridgeError::unavailable("The selected isolated core could not start.");
        #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
        let error = error.with_linux_passive_cause(self.cause);
        error
    }
}

#[derive(Default)]
struct Resources {
    inspection: Option<JoinHandle<Result<VerifiedRuntime, BridgeError>>>,
    inspection_return: Option<ManagementJoin>, inspection_error: Option<tokio::task::JoinError>,
    #[cfg(all(test, debug_assertions, feature = "development-runtime", target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    github_environment: Option<JoinHandle<Result<Option<bool>, ()>>>,
    #[cfg(all(test, target_os = "linux", target_arch = "x86_64", target_env = "gnu",
        not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher")))]
    native_observation: Option<JoinHandle<Result<Vec<installed_native_fixture::ChildObservation>, ()>>>,
    #[cfg(all(test, target_os = "linux", target_arch = "x86_64", target_env = "gnu",
        not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher")))]
    native_observation_return: Option<ManagementJoin>,
    #[cfg(all(test, target_os = "linux", target_arch = "x86_64", target_env = "gnu",
        not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher")))]
    native_snapshots: Vec<installed_native_fixture::ChildObservation>,
    acquisition: Option<JoinHandle<Result<Child, AcquisitionError>>>, child: Option<Child>,
    acquisition_return: Option<ManagementJoin>, acquisition_error: Option<tokio::task::JoinError>,
    #[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64")))]
    passive: Option<Arc<Mutex<PassiveRuntimeSlots>>>,
    #[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64")))]
    native_settlement: Option<JoinHandle<CloseOutcome>>,
    #[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64")))]
    native_return: Option<Result<CloseOutcome, tokio::task::JoinError>>,
    #[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64")))]
    native_started: bool,
    writer: Option<JoinHandle<WriteEnd>>, stdout: Option<JoinHandle<ReadEnd>>, stderr: Option<JoinHandle<ReadEnd>>,
    failed_writer: Option<JoinHandle<WriteEnd>>, failed_stdout: Option<JoinHandle<ReadEnd>>, failed_stderr: Option<JoinHandle<ReadEnd>>,
    waited: Option<ExitStatus>, write_end: Option<WriteEnd>, out_end: Option<ReadEnd>, err_end: Option<ReadEnd>,
    kill_attempted: bool,
}
struct ReadEnd { bytes: Vec<u8>, eof: bool, overflow: bool }
#[derive(Clone, Copy)]
struct WriteEnd { complete: bool }

impl Owner {
    fn fail(&self, error: BridgeError) {
        let mut state = lock(&self.state);
        if state.terminal { return; }
        state.fail_at(error, Instant::now());
        drop(state);
        self.stop.send_replace(true);
        self.changed.notify_waiters();
    }
    fn failed(&self) -> bool { lock(&self.state).error.is_some() }
    fn endpoint(&self) -> Instant { lock(&self.state).endpoint }
    fn unknown(&self, inner: &Inner) {
        let mut state = lock(&self.state);
        if state.terminal { return; }
        inner.disabled.store(true, Ordering::SeqCst);
        state.unknown = true;
        state.fail_at(BridgeError::cleanup_unknown(), Instant::now());
        let reply = state.reply.take();
        #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
        let cause = state.error.as_ref().and_then(BridgeError::linux_passive_cause);
        drop(state);
        // No supervisor bookkeeping lock is held while publishing safe data.
        // A racing actual retirement may already have sealed the final receipt;
        // an earlier unknown reporter must never overwrite that final state.
        if let Some(receipt) = &self.github_receipt {
            let mut receipt = lock(receipt);
            if matches!(&*receipt, GitHubReadReceipt::Pending) { *receipt = GitHubReadReceipt::RetainedUnknown; }
        }
        if let Some(reply) = reply {
            let error = BridgeError::cleanup_unknown();
            #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
            let error = error.with_linux_passive_cause(cause);
            let _ = reply.send(Err(error));
        }
        self.stop.send_replace(true);
        inner.changed.notify_waiters();
        self.changed.notify_waiters();
    }
    fn advance_clock(&self, inner: &Inner, now: Instant) -> Option<Instant> {
        let mut state = lock(&self.state);
        if state.terminal { return None; }
        let timed_out = now >= state.endpoint && state.error.is_none();
        if timed_out { state.fail_at(BridgeError::timeout(), now); }
        let endpoint = state.cleanup_endpoint.unwrap_or(state.endpoint);
        let expired = state.cleanup_endpoint.is_some() && now >= endpoint;
        let newly_unknown = expired && !state.unknown;
        drop(state);
        if timed_out { self.stop.send_replace(true); self.changed.notify_waiters(); }
        if newly_unknown { self.unknown(inner); }
        if expired { None } else { Some(endpoint) }
    }
    fn retire(self: &Arc<Self>, inner: &Inner) -> bool {
        // The short lock order is registry -> state -> permit. Shutdown/admission
        // share the registry lock; no synchronous guard crosses an await.
        let mut owners = lock(&inner.owners);
        let mut state = lock(&self.state);
        if state.terminal { return false; }
        if !owners.get(&self.key).is_some_and(|original| Arc::ptr_eq(original, self)) { return false; }
        // If joins and a timer are ready together, selection order grants no
        // success window beyond either original endpoint.
        let settled_at = Instant::now();
        let Some(result) = state.retirement_result(settled_at, inner.stopping.load(Ordering::SeqCst)) else { return false; };
        if state.unknown { inner.disabled.store(true, Ordering::SeqCst); }
        let was_unknown = state.unknown;
        state.terminal = true;
        let reply = state.reply.take();
        lock(&self.permit).take();
        owners.remove(&self.key);
        drop(state);
        drop(owners);
        // Deliberate end of the management join chain: all original native and
        // required management operations are settled. Only bounded data delivery,
        // notifications and drops remain; no observer-of-observer is required.
        match self.profile {
            Profile::Passive(_) => {
                let result = result.and_then(|value| match value {
                    ReadOutcome::Passive(value) => Ok(value), ReadOutcome::GitHub(_) => Err(BridgeError::protocol()),
                });
                if let Some(reply) = reply { let _ = reply.send(result); }
            }
            Profile::GitHubReadOnly => {
                // A private typed result never passes through passive Value or
                // its public query response channel, even on a profile mismatch.
                drop(reply);
                let outcome = result.and_then(|value| match value {
                    ReadOutcome::GitHub(value) => Ok(value), ReadOutcome::Passive(_) => Err(BridgeError::protocol()),
                });
                if let Some(receipt) = &self.github_receipt {
                    let mut receipt = lock(receipt);
                    let was_unknown = was_unknown || matches!(&*receipt, GitHubReadReceipt::RetainedUnknown);
                    if !matches!(&*receipt, GitHubReadReceipt::Settled { .. }) {
                        *receipt = GitHubReadReceipt::Settled {
                            outcome: if was_unknown { Err(BridgeError::cleanup_unknown()) } else { outcome },
                            settled_at, was_unknown,
                        };
                    }
                }
            }
        }
        inner.changed.notify_waiters();
        self.changed.notify_waiters();
        true
    }
}

struct FinalObserverGuard { inner: Arc<Inner>, owner: Arc<Owner>, retired: bool }
impl FinalObserverGuard {
    fn retired(mut self) {
        // Consume the whole guard so async-move captures its Drop ownership,
        // not just a copy of this bool. Only the observer's actual retirement
        // return may disarm it; losing even an unpolled future still fails closed.
        self.retired = true;
    }
}
impl Drop for FinalObserverGuard {
    fn drop(&mut self) { if !self.retired { self.owner.unknown(&self.inner); } }
}

/// The SAME passive admission's original reply observer. This neither owns a
/// second runner nor cancels/detaches original custody when a caller drops it.
/// It lets DocumentBinding linearize the existing admission with preflight.
pub(crate) struct PassiveQuery {
    inner: Arc<Inner>, owner: Arc<Owner>, receiver: oneshot::Receiver<Result<Value, BridgeError>>,
}
impl PassiveQuery {
    pub(crate) async fn wait(self) -> Result<Value, BridgeError> {
        self.receiver.await.unwrap_or_else(|_| { self.owner.unknown(&self.inner); Err(BridgeError::cleanup_unknown()) })
    }
}

impl Supervisor {
    pub fn new(mut runtime: RuntimeConfig) -> Self {
        runtime.claim_original_supervisor();
        Self { inner: Arc::new(Inner {
            runtime, permits: Arc::new(Semaphore::new(ACTIVE_LIMIT)), next: AtomicU64::new(1),
            stopping: AtomicBool::new(false), disabled: AtomicBool::new(false),
            owners: Mutex::new(BTreeMap::new()), changed: Notify::new(),
            #[cfg(all(test, feature = "development-runtime"))]
            test: hosted_tests::Hooks::default(),
            #[cfg(all(test, target_os = "linux", target_arch = "x86_64", target_env = "gnu",
                not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher")))]
            native_test: installed_native_fixture::Hooks::default(),
        }) }
    }
    pub fn runtime_mode(&self) -> &'static str { self.inner.runtime.mode() }
    pub(crate) fn passive_method_available(&self, name: &str) -> bool { self.inner.runtime.passive_method_available(name) }
    pub(crate) fn bind_original_session_document(&self, identity: &Arc<()>) { self.inner.runtime.bind_original_session_document(identity); }
    pub(crate) fn installed_session_available(&self, identity: &Arc<()>) -> bool { self.inner.runtime.installed_session_available(identity) }
    pub fn disabled(&self) -> bool { self.inner.disabled.load(Ordering::SeqCst) }
    pub fn stopping(&self) -> bool { self.inner.stopping.load(Ordering::SeqCst) }
    pub fn can_exit(&self) -> bool { lock(&self.inner.owners).is_empty() }

    pub async fn query(&self, method: Method, params: Value) -> Result<Value, BridgeError> {
        self.start_passive(method, params)?.wait().await
    }
    /// Fixed passive method admission only. Original admission/roster/cleanup is
    /// unchanged; desktop callers can hold their actual document gate through
    /// this synchronous claim instead of releasing it before an async poll.
    pub(crate) fn start_passive(&self, method: Method, params: Value) -> Result<PassiveQuery, BridgeError> {
        let (reply, receiver) = oneshot::channel();
        let owner = self.admit(AdmissionRequest::Passive { method, params: &params }, CompletionTarget::Passive(reply))?;
        // No owner/task cancellation on receiver abandonment. The registry retains
        // Child, IO tasks, startup handles and permits until actual settlement.
        Ok(PassiveQuery { inner: self.inner.clone(), owner, receiver })
    }

    /// Synchronous admission: the original roster exists before a native session
    /// stores this ticket. No wrapping query future, separate token owner or task.
    pub(crate) fn start_github_readonly(&self, repository: &str, expected_account_id: Option<&str>,
        expected_repository_id: Option<&str>, token: &str) -> Result<GitHubReadTicket, BridgeError> {
        let receipt = Arc::new(Mutex::new(GitHubReadReceipt::Pending));
        let owner = self.admit(AdmissionRequest::GitHub { repository, expected_account_id, expected_repository_id, token },
            CompletionTarget::GitHub(receipt.clone()))?;
        // No fallible operation follows registration. A ready/unknown original
        // remains observable even if its first data delivery won this race.
        Ok(GitHubReadTicket { owner, receipt })
    }

    fn admit(&self, request: AdmissionRequest<'_>, completion: CompletionTarget) -> Result<Arc<Owner>, BridgeError> {
        let endpoint = Instant::now() + OPERATION_TIME;
        let profile = request.profile();
        let (reply, github_receipt) = match (profile, completion) {
            (Profile::Passive(_), CompletionTarget::Passive(reply)) => (Some(reply), None),
            (Profile::GitHubReadOnly, CompletionTarget::GitHub(receipt)) => (None, Some(receipt)),
            _ => return Err(BridgeError::invalid()),
        };
        let executor = tokio::runtime::Handle::try_current()
            .map_err(|_| BridgeError::unavailable("The asynchronous query owner is unavailable."))?;
        if self.disabled() { return Err(BridgeError::cleanup_unknown()); }
        if self.stopping() { return Err(BridgeError::shutdown()); }
        let permit = self.inner.permits.clone().try_acquire_owned()
            .map_err(|_| BridgeError::new("busy", "Two read-only queries already own the available slots."))?;
        let key = self.inner.next.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |value| value.checked_add(1))
            .map_err(|_| BridgeError::new("unavailable", "The query identity space is exhausted."))?;
        let id = match profile { Profile::Passive(_) => format!("query-{key}"), Profile::GitHubReadOnly => format!("github-read-{key}") };
        let bytes = request.encode(&id)?;
        let (stop, _) = watch::channel(false);
        let owner = Arc::new(Owner {
            key, id, profile, github_receipt, state: Mutex::new(OwnerState::new(endpoint, reply)),
            resources: AsyncMutex::new(Resources {
                #[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64")))]
                passive: if passive_selected(profile) {
                    Some(Arc::new(Mutex::new(PassiveRuntimeSlots::new())))
                } else { None },
                ..Resources::default()
            }), stop, changed: Notify::new(),
            permit: Mutex::new(Some(permit)), driver: AsyncMutex::new(None), watchdog: AsyncMutex::new(None), observer: AsyncMutex::new(None),
            #[cfg(all(test, feature = "development-runtime"))]
            observation: Arc::new(Mutex::new(hosted_tests::Observation::default())),
        });
        // All are fresh, uncontended slots. No await/caller cancellation point
        // divides registration; runnable work cannot enter an incomplete roster.
        let resources = owner.resources.try_lock().map_err(|_| BridgeError::cleanup_unknown())?;
        let mut driver = owner.driver.try_lock().map_err(|_| BridgeError::cleanup_unknown())?;
        let mut watchdog_slot = owner.watchdog.try_lock().map_err(|_| BridgeError::cleanup_unknown())?;
        let mut observer = owner.observer.try_lock().map_err(|_| BridgeError::cleanup_unknown())?;
        {
            let mut owners = lock(&self.inner.owners);
            // Serialize registration with shutdown's stop-and-inventory boundary.
            if self.stopping() { return Err(BridgeError::shutdown()); }
            if self.disabled() { return Err(BridgeError::cleanup_unknown()); }
            owners.insert(key, owner.clone());
        }
        // Construct before spawning, not inside the observer's first poll. This
        // also covers partial registration and an unpolled observer's loss.
        let guard = FinalObserverGuard { inner: self.inner.clone(), owner: owner.clone(), retired: false };
        #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", target_os = "linux", target_arch = "x86_64", target_env = "gnu",
            not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher")))]
        shell_shutdown_observation::register_session_query(&self.inner, &owner);
        #[cfg(all(test, feature = "development-runtime"))]
        self.inner.test.register(owner.clone());
        let watch_owner = owner.clone();
        let watch_inner = self.inner.clone();
        #[cfg(all(test, feature = "development-runtime"))]
        let watchdog_return = self.inner.test.watchdog_return.clone();
        *watchdog_slot = Some(executor.spawn(async move {
            let end = watchdog(watch_inner, watch_owner).await;
            #[cfg(all(test, feature = "development-runtime"))]
            watchdog_return.wait().await;
            end
        }));
        let drive_owner = owner.clone();
        let drive_inner = self.inner.clone();
        #[cfg(all(test, feature = "development-runtime"))]
        let driver_return = self.inner.test.driver_return.clone();
        *driver = Some(executor.spawn(async move {
            let end = drive(drive_inner, drive_owner, bytes).await;
            #[cfg(all(test, feature = "development-runtime"))]
            if matches!(&end, DriverEnd::Ready(_)) { driver_return.wait().await; }
            end
        }));
        let final_owner = owner.clone();
        let final_inner = self.inner.clone();
        *observer = Some(executor.spawn(async move {
            observe_management(final_inner, final_owner).await;
            guard.retired();
        }));
        drop(observer);
        drop(watchdog_slot);
        drop(driver);
        drop(resources);
        Ok(owner)
    }

    pub async fn shutdown(&self) -> Result<(), BridgeError> {
        let owners = {
            let owners = lock(&self.inner.owners);
            self.inner.stopping.store(true, Ordering::SeqCst);
            owners.values().cloned().collect::<Vec<_>>()
        };
        for owner in owners { owner.fail(BridgeError::shutdown()); }
        // This only bounds the shutdown observer; it grants no new per-owner
        // cleanup time. Each owner's first cleanup_endpoint is immutable.
        let observer_end = tokio::time::Instant::now() + CLEANUP_TIME;
        loop {
            let changed = self.inner.changed.notified();
            if self.can_exit() { return Ok(()); }
            if self.disabled() { return Err(BridgeError::cleanup_unknown()); }
            tokio::select! {
                _ = changed => {},
                _ = tokio::time::sleep_until(observer_end) => {
                    if self.can_exit() { return Ok(()); }
                    self.inner.disabled.store(true, Ordering::SeqCst);
                    return Err(BridgeError::cleanup_unknown());
                }
            }
        }
    }
}

async fn watchdog(inner: Arc<Inner>, owner: Arc<Owner>) -> WatchdogEnd {
    loop {
        let changed = owner.changed.notified();
        let observed_at = Instant::now();
        let deadline = owner.advance_clock(&inner, observed_at);
        {
            let state = lock(&owner.state);
            if state.driver_join.original_result() { return WatchdogEnd::DriverObserved(state.driver_join); }
            if let Some(endpoint) = state.cleanup_endpoint {
                if observed_at >= endpoint && state.unknown { return WatchdogEnd::CleanupExpired { endpoint, observed_at }; }
            }
        }
        tokio::select! {
            _ = changed => {},
            _ = clock_wait(deadline) => {},
        }
    }
}

async fn clock_wait(endpoint: Option<Instant>) {
    match endpoint {
        Some(endpoint) => tokio::time::sleep_until(tokio::time::Instant::from_std(endpoint)).await,
        None => pending().await,
    }
}

enum ManagementEvent {
    Driver(Result<DriverEnd, tokio::task::JoinError>),
    Watchdog(Result<WatchdogEnd, tokio::task::JoinError>),
    Changed,
}

async fn observe_management(inner: Arc<Inner>, owner: Arc<Owner>) {
    // Slots, not the native resource book, are held by the sole management joiner.
    // A blocked original inspection/spawn/wait cannot hold this observer's clock.
    let mut driver = owner.driver.lock().await;
    let mut watchdog = owner.watchdog.lock().await;
    {
        let mut state = lock(&owner.state);
        if driver.is_none() { state.driver_join = ManagementJoin::Missing; }
        if watchdog.is_none() { state.watchdog_join = ManagementJoin::Missing; }
    }
    if driver.is_none() || watchdog.is_none() { owner.unknown(&inner); }
    loop {
        let changed = owner.changed.notified();
        let deadline = owner.advance_clock(&inner, Instant::now());
        let (driver_pending, watchdog_pending, ready) = {
            let state = lock(&owner.state);
            (state.driver_join == ManagementJoin::Pending, state.watchdog_join == ManagementJoin::Pending, state.management_ready())
        };
        if ready && owner.retire(&inner) { return; }
        if !driver_pending && !watchdog_pending {
            owner.unknown(&inner);
            // Failed originals and their books remain retained. No replacement
            // cleaner, no repoll of an already consumed join, no expired spin.
            pending::<()>().await;
        }
        let event = tokio::select! {
            result = join_slot(&mut driver), if driver_pending => ManagementEvent::Driver(result),
            result = join_slot(&mut watchdog), if watchdog_pending => ManagementEvent::Watchdog(result),
            _ = changed => ManagementEvent::Changed,
            _ = clock_wait(deadline) => ManagementEvent::Changed,
        };
        match event {
            ManagementEvent::Driver(result) => {
                match result {
                    Ok(end) => {
                        let mut state = lock(&owner.state);
                        state.driver_join = ManagementJoin::Returned;
                        if let DriverEnd::Ready(Err(error)) = &end { state.fail_at(error.clone(), Instant::now()); }
                        state.driver_end = Some(end);
                        drop(state);
                        #[cfg(all(test, feature = "development-runtime"))]
                        { lock(&owner.observation).driver_joined = true; }
                        driver.take();
                    }
                    Err(error) => {
                        lock(&owner.state).driver_join = ManagementJoin::error(&error);
                        owner.unknown(&inner); // Keep the consumed failed handle, never await it again.
                    }
                }
                owner.changed.notify_waiters();
            }
            ManagementEvent::Watchdog(result) => {
                match result {
                    Ok(end) => {
                        let mut state = lock(&owner.state);
                        let accepted = state.accepts_watchdog(end);
                        state.watchdog_join = if accepted { ManagementJoin::Returned } else { ManagementJoin::InvalidReturn };
                        state.watchdog_end = Some(end);
                        drop(state);
                        #[cfg(all(test, feature = "development-runtime"))]
                        { lock(&owner.observation).watchdog_joined = true; }
                        if accepted { watchdog.take(); } else { owner.unknown(&inner); }
                    }
                    Err(error) => {
                        lock(&owner.state).watchdog_join = ManagementJoin::error(&error);
                        owner.unknown(&inner);
                    }
                }
                owner.changed.notify_waiters();
            }
            ManagementEvent::Changed => {},
        }
    }
}

#[cfg(not(all(feature = "development-runtime", debug_assertions)))]
fn spawn_original(_runtime: VerifiedRuntime, _owner: Arc<Owner>) -> std::io::Result<Child> {
    Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "packaged runtime execution is not qualified"))
}

#[cfg(all(feature = "development-runtime", debug_assertions))]
fn spawn_original(runtime: VerifiedRuntime, owner: Arc<Owner>) -> std::io::Result<Child> {
    if owner.failed() || Instant::now() >= owner.endpoint() {
        owner.fail(BridgeError::timeout());
        return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "startup admission expired"));
    }
    let mut command = Command::new(&runtime.python);
    command.args(["-I", "-S", "-B"]).arg(&runtime.bootstrap).arg(&runtime.core)
        .current_dir(&runtime.cwd).env_clear().env("LC_ALL", "C").env("LANG", "C")
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).kill_on_drop(false);
    #[cfg(windows)]
    if let Some(system_root) = std::env::var_os("SystemRoot") {
        if std::path::Path::new(&system_root).is_absolute() { command.env("SystemRoot", system_root); }
    }
    // Recheck inside the blocking acquisition, not just before queueing it.
    if owner.failed() || Instant::now() >= owner.endpoint() {
        owner.fail(BridgeError::timeout());
        return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "startup admission expired"));
    }
    command.spawn()
}

async fn read_bounded<R: AsyncRead + Unpin>(mut reader: R, limit: usize, faults: mpsc::Sender<BridgeError>) -> ReadEnd {
    let mut bytes = Vec::new();
    let mut buffer = [0u8; 8192];
    let mut overflow = false;
    loop {
        match reader.read(&mut buffer).await {
            Ok(0) => return ReadEnd { bytes, eof: true, overflow },
            Ok(length) => {
                if !overflow && length <= limit.saturating_sub(bytes.len()) { bytes.extend_from_slice(&buffer[..length]); }
                else if !overflow {
                    overflow = true;
                    let _ = faults.try_send(BridgeError::new("output_limit", "The core exceeded a bounded output channel."));
                }
                // After overflow, discard while draining until genuine EOF.
            }
            Err(_) => {
                let _ = faults.try_send(BridgeError::new("io_error", "An original core output channel failed."));
                return ReadEnd { bytes, eof: false, overflow };
            }
        }
    }
}

async fn write_request(mut writer: tokio::process::ChildStdin, bytes: Vec<u8>, mut stop: watch::Receiver<bool>, faults: mpsc::Sender<BridgeError>) -> WriteEnd {
    if *stop.borrow() { return WriteEnd { complete: false }; }
    let written = tokio::select! {
        _ = stop.changed() => return WriteEnd { complete: false },
        result = async { writer.write_all(&bytes).await?; writer.shutdown().await } => result,
    };
    if written.is_err() {
        let _ = faults.try_send(BridgeError::new("io_error", "The bounded request channel failed."));
        return WriteEnd { complete: false };
    }
    // ChildStdin drops here, supplying EOF even where shutdown alone is a no-op.
    WriteEnd { complete: true }
}

async fn join_slot<T>(slot: &mut Option<JoinHandle<T>>) -> Result<T, tokio::task::JoinError> {
    match slot { Some(task) => task.await, None => pending().await }
}
async fn wait_original(child: &mut Option<Child>) -> std::io::Result<ExitStatus> {
    match child { Some(child) => child.wait().await, None => pending().await }
}

// Decision DATA only. Production callers derive these from the actual retained
// handle and Ready result; no fixture can use them to construct native authority.
#[derive(Clone, Copy)]
struct OriginalBorrow { returned: Option<ManagementJoin>, handle: bool, error: bool }
impl OriginalBorrow {
    fn returned(self) -> bool {
        match self.returned {
            None | Some(ManagementJoin::Returned) => !self.handle && !self.error,
            Some(result) => result.original_result() && self.handle && self.error,
        }
    }
    fn positive(self) -> bool { matches!(self.returned, None | Some(ManagementJoin::Returned)) && self.returned() }
}
fn passive_selected(profile: Profile) -> bool {
    cfg!(all(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64")), not(all(feature = "development-runtime", debug_assertions))))
        && matches!(profile, Profile::Passive(_))
}
fn passive_claim_clear(original: bool, profile: Profile, state: &OwnerState, now: Instant,
    stopping: bool, disabled: bool, stop: bool) -> bool {
    original && matches!(profile, Profile::Passive(_)) && !state.terminal && !state.unknown && state.error.is_none()
        && state.cleanup_endpoint.is_none() && !stopping && !disabled && !stop && now < state.endpoint
}
fn passive_completion_clear(inspection: OriginalBorrow, acquisition: OriginalBorrow,
    started: bool, joined: bool, handle_retained: bool, positive_close: bool, same_ledger_settled: bool) -> bool {
    inspection.returned == Some(ManagementJoin::Returned) && inspection.positive() && acquisition.positive()
        && started && joined && !handle_retained && positive_close && same_ledger_settled
}
fn passive_never_started_clear(inspection: OriginalBorrow, acquisition: OriginalBorrow, empty_unstarted_book: bool) -> bool {
    empty_unstarted_book && inspection.positive() && acquisition.returned.is_none() && acquisition.positive()
}

#[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64")))]
fn passive_borrows(resources: &Resources) -> (OriginalBorrow, OriginalBorrow) {
    (OriginalBorrow { returned: resources.inspection_return, handle: resources.inspection.is_some(), error: resources.inspection_error.is_some() },
     OriginalBorrow { returned: resources.acquisition_return, handle: resources.acquisition.is_some(), error: resources.acquisition_error.is_some() })
}

#[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64")))]
fn passive_worker_lost(resources: &Resources) {
    // Only called AFTER this original inspection/acquisition/settlement worker
    // returned JoinError. Never race a pending borrower because a clock expired.
    if let Some(native) = &resources.passive {
        match native.lock() { Ok(mut slots) => slots.mark_interrupted(), Err(error) => error.into_inner().mark_interrupted() }
    }
}

#[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64")))]
fn transfer_passive(resources: &Resources, inner: &Inner, owner: &Arc<Owner>) -> Result<(), BridgeError> {
    let Some(native) = &resources.passive else {
        return if passive_selected(owner.profile) { Err(BridgeError::cleanup_unknown()) } else { Ok(()) };
    };
    let (inspection, acquisition) = passive_borrows(resources);
    if inspection.returned != Some(ManagementJoin::Returned) || !inspection.positive()
        || acquisition.returned.is_some() || !acquisition.positive() { return Err(BridgeError::cleanup_unknown()); }
    let mut slots = native.try_lock().map_err(|_| BridgeError::cleanup_unknown())?;
    let owners = lock(&inner.owners); let state = lock(&owner.state);
    if !passive_claim_clear(owners.get(&owner.key).is_some_and(|actual| Arc::ptr_eq(actual, owner)), owner.profile,
        &state, Instant::now(), inner.stopping.load(Ordering::SeqCst), inner.disabled.load(Ordering::SeqCst), *owner.stop.borrow()) {
        return Err(state.error.clone().unwrap_or_else(BridgeError::timeout));
    }
    // No native operation or allocation inside the whole-original move.
    slots.transfer_once().map_err(|_| BridgeError::cleanup_unknown())
}

#[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64")))]
struct PreparedPassiveSpawn<'a> {
    runtime: &'a mut PassiveInstalledRuntime,
    #[cfg(all(not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), any(test, feature = "desktop-shell")))]
    command: Command,
}

#[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64")))]
impl<'a> PreparedPassiveSpawn<'a> {
    fn prepare(runtime: &'a mut PassiveInstalledRuntime, end: Instant, stop: &watch::Receiver<bool>) -> Result<Self, AcquisitionError> {
        let selected = runtime.prepare_once(end, stop)
            .map_err(AcquisitionError::preparation)?;
        // All native checks and fixed argument/environment allocations precede
        // the serialized final owner claim. No pathname/Command-taking adapter.
        #[cfg(all(not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), any(test, feature = "desktop-shell")))]
        let command = {
            let mut command = Command::new(&selected.python);
            command.args(["-I", "-S", "-B"]).arg(&selected.bootstrap).arg(&selected.core)
                .current_dir(&selected.cwd).env_clear().env("LC_ALL", "C").env("LANG", "C")
                .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).kill_on_drop(false);
            #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
            crate::runtime::macos_installed_environment(&mut command)?;
            command
        };
        #[cfg(not(all(not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), any(test, feature = "desktop-shell"))))]
        let _ = selected;
        Ok(Self { runtime,
            #[cfg(all(not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), any(test, feature = "desktop-shell")))]
            command,
        })
    }
}

#[cfg(all(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64")),
    not(all(not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), any(test, feature = "desktop-shell")))))]
fn spawn_passive_original(prepared: PreparedPassiveSpawn<'_>) -> Result<Child, AcquisitionError> {
    // Unsupported profiles remain unconditional. Only this no-effect stub has
    // a receipt; it is absent from the fixed installed-shell/native profile.
    prepared.runtime.record_closed_spawn_gate();
    Err(AcquisitionError::unsupported("packaged runtime execution is not qualified"))
}

#[cfg(all(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64")),
    not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), any(test, feature = "desktop-shell")))]
fn spawn_passive_original(mut prepared: PreparedPassiveSpawn<'_>) -> Result<Child, AcquisitionError> {
    // Opaque creation errors provide NO no-child/pipe-close proof. The claimed
    // original stays registered; the existing owner therefore retains Unknown.
    prepared.command.spawn().map_err(AcquisitionError::returned_spawn)
}

#[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64")))]
fn acquire_passive_original(inner: &Inner, owner: &Arc<Owner>, native: &Arc<Mutex<PassiveRuntimeSlots>>) -> Result<Child, AcquisitionError> {
    let refused = || AcquisitionError::unsupported("passive installed custody is unavailable");
    let mut slots = native.lock().map_err(|_| {
        let error = refused();
        #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
        let error = error.with_cause(crate::error::LinuxPassiveCause::AcquisitionLock);
        error
    })?;
    let runtime = slots.capability().map_err(AcquisitionError::capability)?;
    let stop = owner.stop.subscribe();
    let prepared = PreparedPassiveSpawn::prepare(runtime, owner.endpoint(), &stop)?;
    #[cfg(all(target_os = "linux", test, not(feature = "development-runtime"), not(feature = "desktop-shell"), not(feature = "ubuntu-runtime-publisher")))]
    let mut limit = installed_native_fixture::before_claim(inner, owner, &stop)?;
    // All post-lowering ordinary returns, including a failed final claim, leave
    // this body through the one checked restoration below. Its guard also
    // attempts/checks restoration on unwinding, without retrying a failed attempt.
    let result = (|| {
        let owners = lock(&inner.owners); let state = lock(&owner.state);
        if !passive_claim_clear(owners.get(&owner.key).is_some_and(|actual| Arc::ptr_eq(actual, owner)), owner.profile,
            &state, Instant::now(), inner.stopping.load(Ordering::SeqCst), inner.disabled.load(Ordering::SeqCst), *owner.stop.borrow()) {
            let error = refused();
            #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
            let error = error.with_cause(crate::error::LinuxPassiveCause::FinalClaimOwnerGate);
            return Err(error);
        }
        prepared.runtime.claim_once().map_err(AcquisitionError::final_claim)?;
        drop(state); drop(owners);
        let result = spawn_passive_original(prepared); // No await/callback/IO between final claim and creation.
        #[cfg(all(target_os = "linux", test, not(feature = "development-runtime"), not(feature = "desktop-shell"), not(feature = "ubuntu-runtime-publisher")))]
        { *lock(&inner.native_test.creation) = Some((result.is_ok(), result.as_ref().err().and_then(|error| error.original.raw_os_error()))); }
        result
    })();
    #[cfg(all(target_os = "linux", test, not(feature = "development-runtime"), not(feature = "desktop-shell"), not(feature = "ubuntu-runtime-publisher")))]
    if let Some(limit) = &mut limit { limit.restore(); }
    result // Never discard a returned original Child because restoration failed.
}

async fn settle_passive(resources: &mut Resources, inner: &Inner, owner: &Arc<Owner>) -> bool {
    #[cfg(not(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64"))))]
    { let _ = (resources, inner, owner); true }
    #[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64")))]
    {
        #[cfg(all(target_os = "linux", test, not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher")))]
        if resources.native_observation.is_some() { owner.unknown(inner); return false; }
        let Some(native) = resources.passive.clone() else {
            if passive_selected(owner.profile) { owner.unknown(inner); return false; }
            return true; // Explicitly unselected domain/profile, never a missing required book.
        };
        let (inspection, acquisition) = passive_borrows(resources);
        if !inspection.returned() || !acquisition.returned() { owner.unknown(inner); return false; }
        if !resources.native_started {
            let no_child = {
                let slots = match native.try_lock() { Ok(slots) => slots, Err(_) => { owner.unknown(inner); return false; } };
                // Closed profile, or STOP before any worker was created: actual
                // original-return/no-worker records AND a never-started empty book.
                if passive_never_started_clear(inspection, acquisition, slots.never_started()) {
                    return true;
                }
                slots.no_child_effect()
            };
            let consumers_returned = if resources.child.is_none() { no_child } else {
                resources.waited.is_some() && resources.writer.is_none() && resources.stdout.is_none() && resources.stderr.is_none()
                    && resources.failed_writer.is_none() && resources.failed_stdout.is_none() && resources.failed_stderr.is_none()
                    && resources.write_end.is_some() && resources.out_end.as_ref().is_some_and(|end| end.eof)
                    && resources.err_end.as_ref().is_some_and(|end| end.eof)
            };
            if !consumers_returned { owner.unknown(inner); return false; }
            let closing = native.clone();
            let (release, enter) = oneshot::channel();
            resources.native_started = true;
            resources.native_settlement = Some(tokio::task::spawn_blocking(move || {
                if enter.blocking_recv().is_err() { return CloseOutcome::Unknown; }
                match closing.lock() {
                    Ok(mut slots) => slots.settle_originals(),
                    Err(error) => { let mut slots = error.into_inner(); slots.mark_interrupted(); slots.settle_originals() },
                }
            }));
            let _ = release.send(()); // The original close handle is registered before its first effect.
        }
        if resources.native_return.is_none() {
            let result = join_slot(&mut resources.native_settlement).await;
            if result.is_ok() { resources.native_settlement.take(); }
            else { passive_worker_lost(resources); } // Retain consumed failed handle; never poll it again.
            resources.native_return = Some(result);
        }
        let positive = passive_completion_clear(inspection, acquisition, resources.native_started,
            resources.native_return.as_ref().is_some_and(Result::is_ok), resources.native_settlement.is_some(),
            matches!(resources.native_return.as_ref(), Some(Ok(CloseOutcome::Settled))),
            native.try_lock().is_ok_and(|slots| slots.settled()));
        if !positive { owner.unknown(inner); }
        positive
    }
}

async fn ready_after_custody(resources: &mut Resources, inner: &Inner, owner: &Arc<Owner>,
    result: Result<ReadOutcome, BridgeError>) -> DriverEnd {
    if settle_passive(resources, inner, owner).await { DriverEnd::Ready(result) } else { DriverEnd::RetainedUnknown }
}

enum Event { Wait(std::io::Result<ExitStatus>), Write(Result<WriteEnd, tokio::task::JoinError>), Out(Result<ReadEnd, tokio::task::JoinError>), Err(Result<ReadEnd, tokio::task::JoinError>), Fault(Option<BridgeError>), Stop }

async fn drive(inner: Arc<Inner>, owner: Arc<Owner>, bytes: Vec<u8>) -> DriverEnd {
    let mut resources = owner.resources.lock().await;
    if owner.failed() || Instant::now() >= owner.endpoint() {
        owner.fail(BridgeError::timeout());
        return ready_after_custody(&mut resources, &inner, &owner, Err(BridgeError::timeout())).await;
    }
    let config = inner.runtime.clone();
    let endpoint = owner.endpoint();
    let profile = owner.profile;
    #[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64")))]
    let inspection_native = resources.passive.clone();
    #[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64")))]
    let inspection_stop = owner.stop.subscribe();
    #[cfg(all(test, feature = "development-runtime"))]
    let inspection_gate = inner.test.inspection.clone();
    #[cfg(all(windows, test, feature = "development-runtime"))]
    let windows_bootstrap = lock(&inner.test.windows_bootstrap).clone();
    #[cfg(all(test, debug_assertions, feature = "development-runtime", target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    let github_fixture = lock(&inner.test.github_fixture).clone();
    #[cfg(all(test, debug_assertions, feature = "development-runtime", target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    let github_tls = lock(&inner.test.github_tls).clone();
    let (inspect_start, inspect_enter) = oneshot::channel();
    resources.inspection_return = Some(ManagementJoin::Pending);
    resources.inspection = Some(tokio::task::spawn_blocking(move || {
        inspect_enter.blocking_recv().map_err(|_| BridgeError::cleanup_unknown())?;
        #[cfg(all(test, feature = "development-runtime"))]
        inspection_gate.wait();
        let runtime = match profile {
            Profile::Passive(_method) => {
                #[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64")))]
                if passive_selected(profile) {
                    let native = inspection_native.ok_or_else(BridgeError::cleanup_unknown)?;
                    let mut originals = native.lock().map_err(|_| BridgeError::cleanup_unknown())?;
                    return config.resolve_passive_installed(_method, &mut originals, endpoint, &inspection_stop);
                }
                config.resolve(endpoint)?
            },
            Profile::GitHubReadOnly => {
                // The same original inspection and endpoint. This private
                // test-only value exists only after the fixed hosted Case has
                // bound its inputs; ordinary development retains the TLS gate.
                #[cfg(all(test, debug_assertions, feature = "development-runtime", target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
                {
                    // Two distinct, privately minted fixture selections. Never
                    // reinterpret the no-network owner fixture as TLS authority.
                    if github_fixture.is_some() && github_tls.is_some() {
                        return Err(BridgeError::unavailable("Conflicting fixed GitHub fixture selections."));
                    }
                    if let Some(selection) = &github_tls {
                        return config.resolve_github_tls_fixture(endpoint, selection);
                    }
                    if let Some(selection) = &github_fixture {
                        return config.resolve_github_fixture(endpoint, selection);
                    }
                }
                config.resolve_github_readonly(endpoint)?
            },
        };
        #[cfg(all(windows, test, feature = "development-runtime"))]
        let runtime = match profile {
            Profile::Passive(_) => hosted_tests::select_windows_bootstrap(runtime, windows_bootstrap, endpoint)?,
            Profile::GitHubReadOnly => runtime, // Never a fixture override for GitHub/TLS qualification.
        };
        Ok(runtime)
    }));
    let _ = inspect_start.send(());
    let inspected = join_slot(&mut resources.inspection).await;
    resources.inspection_return = Some(match &inspected { Ok(_) => ManagementJoin::Returned, Err(error) => ManagementJoin::error(error) });
    #[cfg(all(test, feature = "development-runtime"))]
    if inspected.is_ok() { lock(&owner.observation).inspection_joined = true; }
    let runtime = match inspected {
        Ok(Ok(runtime)) => { resources.inspection.take(); runtime },
        Ok(Err(error)) => {
            resources.inspection.take();
            owner.fail(error.clone()); // Original detection, not later management-return scheduling.
            return ready_after_custody(&mut resources, &inner, &owner, Err(error)).await;
        }
        Err(error) => {
            resources.inspection_error = Some(error);
            #[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64")))]
            passive_worker_lost(&resources);
            owner.unknown(&inner);
            let _ = settle_passive(&mut resources, &inner, &owner).await;
            return DriverEnd::RetainedUnknown;
        }
    };
    if owner.failed() || Instant::now() >= owner.endpoint() {
        owner.fail(BridgeError::timeout());
        return ready_after_custody(&mut resources, &inner, &owner, Err(BridgeError::timeout())).await;
    }
    #[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64")))]
    if let Err(error) = transfer_passive(&resources, &inner, &owner) {
        if error.code == "cleanup_unknown" { owner.unknown(&inner); }
        owner.fail(error.clone());
        return ready_after_custody(&mut resources, &inner, &owner, Err(error)).await;
    }
    // Blocking startup cannot starve the independent deadline watchdog. Its
    // original result/Child remains in this retained acquisition handle.
    let acquiring_owner = owner.clone();
    #[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64")))]
    let acquiring_inner = inner.clone();
    #[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64")))]
    let acquisition_native = resources.passive.clone();
    #[cfg(all(test, feature = "development-runtime"))]
    let acquisition_gate = inner.test.acquisition.clone();
    let (acquire_start, acquire_enter) = oneshot::channel();
    resources.acquisition_return = Some(ManagementJoin::Pending);
    resources.acquisition = Some(tokio::task::spawn_blocking(move || {
        if acquire_enter.blocking_recv().is_err() {
            let error = AcquisitionError::from(std::io::Error::new(std::io::ErrorKind::Interrupted, "original acquisition entry was not released"));
            #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
            let error = error.with_cause(crate::error::LinuxPassiveCause::AcquisitionEntryNotReleased);
            return Err(error);
        }
        // Scheduling instrumentation inside THIS retained original task,
        // before spawn_original's two final creation checks. No new deadline.
        #[cfg(all(test, feature = "development-runtime"))]
        acquisition_gate.wait();
        #[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64")))]
        if passive_selected(acquiring_owner.profile) {
            let Some(native) = acquisition_native else {
                acquiring_owner.unknown(&acquiring_inner);
                let error = AcquisitionError::unsupported("original passive custody is missing");
                #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
                let error = error.with_cause(crate::error::LinuxPassiveCause::AcquisitionCustodyMissing);
                return Err(error);
            };
            return acquire_passive_original(&acquiring_inner, &acquiring_owner, &native);
        }
        spawn_original(runtime, acquiring_owner).map_err(AcquisitionError::from)
    }));
    let _ = acquire_start.send(());
    let acquired = join_slot(&mut resources.acquisition).await;
    resources.acquisition_return = Some(match &acquired { Ok(_) => ManagementJoin::Returned, Err(error) => ManagementJoin::error(error) });
    #[cfg(all(test, feature = "development-runtime"))]
    if acquired.is_ok() { lock(&owner.observation).acquisition_joined = true; }
    let child = match acquired {
        Ok(Ok(child)) => { resources.acquisition.take(); Some(child) },
        Ok(Err(failure)) => {
            resources.acquisition.take();
            let error = failure.into_bridge_error(); // Only after this original acquisition joined.
            owner.fail(error.clone());
            return ready_after_custody(&mut resources, &inner, &owner, Err(error)).await;
        }
        Err(error) => {
            resources.acquisition_error = Some(error);
            #[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64")))]
            passive_worker_lost(&resources);
            owner.unknown(&inner);
            let _ = settle_passive(&mut resources, &inner, &owner).await;
            return DriverEnd::RetainedUnknown;
        }
    };
    resources.child = child;
    #[cfg(all(test, feature = "development-runtime"))]
    { lock(&owner.observation).spawned = true; }
    #[cfg(all(test, target_os = "linux", target_arch = "x86_64", target_env = "gnu",
        not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher")))]
    if let Some(observed_case) = if passive_selected(profile) { inner.native_test.child_case(&owner) } else { None } {
        // Same original Child, retained before the reader starts, and not yet
        // offered to any wait/reaper. A lost read/close/join retains this slot.
        let Some(id) = resources.child.as_ref().and_then(Child::id) else {
            owner.unknown(&inner); return DriverEnd::RetainedUnknown;
        };
        let observing_inner = inner.clone();
        let observing_key = owner.key;
        let observing_stop = owner.stop.subscribe();
        let (release, enter) = oneshot::channel();
        resources.native_observation_return = Some(ManagementJoin::Pending);
        resources.native_observation = Some(tokio::task::spawn_blocking(move || {
            enter.blocking_recv().map_err(|_| ())?;
            installed_native_fixture::observe_original_child(id, observing_key, endpoint, observing_stop, &observing_inner, observed_case)
        }));
        let _ = release.send(());
        let result = join_slot(&mut resources.native_observation).await;
        resources.native_observation_return = Some(match &result {
            Ok(_) => ManagementJoin::Returned, Err(error) => ManagementJoin::error(error),
        });
        match result {
            Ok(Ok(snapshots)) => { resources.native_observation.take(); resources.native_snapshots = snapshots; },
            _ => { owner.unknown(&inner); return DriverEnd::RetainedUnknown; },
        }
        if Instant::now() >= endpoint { owner.fail(BridgeError::timeout()); }
    }
    #[cfg(all(test, debug_assertions, feature = "development-runtime", target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    if matches!(profile, Profile::GitHubReadOnly) && inner.test.github_observe_environment.load(Ordering::SeqCst) {
        // Only T4-owner-clear requests this read-only observation. The actual
        // Child is ALREADY retained here, before request writing or any wait.
        // The original blocking reader is in the same Resources, not a PID
        // search, new joiner, artificial owner gate or product environment hook.
        let Some(id) = resources.child.as_ref().and_then(Child::id) else {
            owner.unknown(&inner); return DriverEnd::RetainedUnknown;
        };
        resources.github_environment = Some(tokio::task::spawn_blocking(move || hosted_tests::original_child_environment(id)));
        match join_slot(&mut resources.github_environment).await {
            Ok(Ok(value)) => {
                lock(&owner.observation).github_initial_environment = value;
                resources.github_environment.take();
            },
            _ => { owner.unknown(&inner); return DriverEnd::RetainedUnknown; },
        }
    }
    let (stdin, stdout, stderr) = match resources.child.as_mut() {
        Some(child) => (child.stdin.take(), child.stdout.take(), child.stderr.take()),
        None => { owner.unknown(&inner); return DriverEnd::RetainedUnknown; }
    };
    let (faults, mut fault_rx) = mpsc::channel(4);
    if let Some(stdin) = stdin { resources.writer = Some(tokio::spawn(write_request(stdin, bytes, owner.stop.subscribe(), faults.clone()))); }
    if let Some(stdout) = stdout {
        #[cfg(all(test, feature = "development-runtime"))]
        { resources.stdout = Some(tokio::spawn(hosted_tests::observed_read(stdout, profile.stdout_limit(), faults.clone(), owner.observation.clone(), Some(inner.test.stdout_join.clone()), false))); }
        #[cfg(not(all(test, feature = "development-runtime")))]
        { resources.stdout = Some(tokio::spawn(read_bounded(stdout, profile.stdout_limit(), faults.clone()))); }
    }
    if let Some(stderr) = stderr {
        #[cfg(all(test, feature = "development-runtime"))]
        { resources.stderr = Some(tokio::spawn(hosted_tests::observed_read(stderr, protocol::STDERR_LIMIT, faults.clone(), owner.observation.clone(), None, true))); }
        #[cfg(not(all(test, feature = "development-runtime")))]
        { resources.stderr = Some(tokio::spawn(read_bounded(stderr, protocol::STDERR_LIMIT, faults.clone()))); }
    }
    drop(faults);
    if resources.writer.is_none() || resources.stdout.is_none() || resources.stderr.is_none() {
        owner.fail(BridgeError::cleanup_unknown());
    }
    let mut stop = owner.stop.subscribe();
    let mut stopped = false;
    let mut faults_open = true;
    loop {
        if Instant::now() >= owner.endpoint() && !owner.failed() { owner.fail(BridgeError::timeout()); }
        if owner.failed() && !resources.kill_attempted && resources.waited.is_none() {
            resources.kill_attempted = true;
            // Only this exact retained, unreaped Child. No PID/group discovery,
            // external reaper, repeated signal, or kill-on-drop authority.
            let child = match resources.child.as_mut() { Some(child) => child, None => { owner.unknown(&inner); return DriverEnd::RetainedUnknown; } };
            match child.try_wait() {
                Ok(Some(status)) => {
                    #[cfg(all(test, feature = "development-runtime"))]
                    {
                        let mut observed = lock(&owner.observation); observed.waited = true; observed.exit_success = Some(status.success());
                        #[cfg(windows)]
                        { observed.windows_exit_code = status.code(); }
                    }
                    resources.waited = Some(status);
                }
                Ok(None) => { if child.start_kill().is_err() { owner.fail(BridgeError::cleanup_unknown()); } }
                Err(_) => { owner.unknown(&inner); return DriverEnd::RetainedUnknown; }
            }
        }
        let wait_pending = resources.waited.is_none();
        let write_pending = resources.writer.is_some();
        let out_pending = resources.stdout.is_some();
        let err_pending = resources.stderr.is_some();
        if !wait_pending && !write_pending && !out_pending && !err_pending { break; }
        let event = {
            let Resources { child, writer, stdout, stderr, .. } = &mut *resources;
            tokio::select! {
                status = wait_original(child), if wait_pending => Event::Wait(status),
                result = join_slot(writer), if write_pending => Event::Write(result),
                result = join_slot(stdout), if out_pending => Event::Out(result),
                result = join_slot(stderr), if err_pending => Event::Err(result),
                fault = fault_rx.recv(), if faults_open => Event::Fault(fault),
                _ = stop.changed(), if !stopped => Event::Stop,
            }
        };
        match event {
            Event::Wait(Ok(status)) => {
                #[cfg(all(test, feature = "development-runtime"))]
                {
                    let mut observed = lock(&owner.observation); observed.waited = true; observed.exit_success = Some(status.success());
                    #[cfg(windows)]
                    { observed.windows_exit_code = status.code(); }
                }
                if !status.success() { owner.fail(BridgeError::new("engine_failed", "The isolated core exited unsuccessfully.")); }
                resources.waited = Some(status);
            }
            Event::Wait(Err(_)) => { owner.unknown(&inner); return DriverEnd::RetainedUnknown; }
            Event::Write(Ok(end)) => {
                #[cfg(all(test, feature = "development-runtime"))]
                { let mut observed = lock(&owner.observation); observed.writer_joined = true; observed.writer_complete = end.complete; }
                resources.writer.take(); resources.write_end = Some(end);
                if !end.complete { owner.fail(BridgeError::new("io_error", "The request did not close successfully.")); }
            }
            Event::Out(Ok(end)) => {
                #[cfg(all(test, feature = "development-runtime"))]
                { lock(&owner.observation).stdout_joined = true; }
                resources.stdout.take(); resources.out_end = Some(end);
            }
            Event::Err(Ok(end)) => {
                #[cfg(all(test, feature = "development-runtime"))]
                { lock(&owner.observation).stderr_joined = true; }
                resources.stderr.take(); resources.err_end = Some(end);
            }
            Event::Write(Err(_)) => {
                resources.failed_writer = resources.writer.take(); resources.write_end = Some(WriteEnd { complete: false });
                owner.fail(BridgeError::cleanup_unknown());
            }
            Event::Out(Err(_)) => {
                resources.failed_stdout = resources.stdout.take(); resources.out_end = Some(ReadEnd { bytes: Vec::new(), eof: false, overflow: false });
                owner.fail(BridgeError::cleanup_unknown());
            }
            Event::Err(Err(_)) => {
                resources.failed_stderr = resources.stderr.take(); resources.err_end = Some(ReadEnd { bytes: Vec::new(), eof: false, overflow: false });
                owner.fail(BridgeError::cleanup_unknown());
            }
            Event::Fault(Some(error)) => owner.fail(error),
            Event::Fault(None) => faults_open = false,
            Event::Stop => { stopped = true; if !owner.failed() { owner.fail(BridgeError::shutdown()); } }
        }
    }
    if resources.failed_writer.is_some() || resources.failed_stdout.is_some() || resources.failed_stderr.is_some() {
        owner.unknown(&inner); return DriverEnd::RetainedUnknown;
    }
    let eofs = resources.out_end.as_ref().is_some_and(|end| end.eof) && resources.err_end.as_ref().is_some_and(|end| end.eof);
    if !eofs { owner.unknown(&inner); return DriverEnd::RetainedUnknown; }
    if !resources.write_end.is_some_and(|end| end.complete) {
        owner.fail(BridgeError::new("io_error", "The original request writer did not complete."));
    }
    // Original child wait and IO/EOF evidence are still in Resources here.
    // Keep custody through them, then join its one explicit native settlement.
    if !settle_passive(&mut resources, &inner, &owner).await { return DriverEnd::RetainedUnknown; }
    let output = resources.out_end.take();
    let diagnostics = resources.err_end.take();
    if output.as_ref().is_some_and(|end| end.overflow) || diagnostics.as_ref().is_some_and(|end| end.overflow) {
        owner.fail(BridgeError::new("output_limit", "The core exceeded a bounded output channel."));
    }
    // All IO JoinHandles returned, both EOFs observed, and the original child was
    // reaped. Diagnostics are never emitted to renderer/logs as raw contents.
    drop(diagnostics);
    resources.child.take();
    let result = match output { Some(output) => profile.decode(&output.bytes, &owner.id), None => Err(BridgeError::protocol()) };
    if let Err(error) = &result { owner.fail(error.clone()); }
    DriverEnd::Ready(result)
}

// Finite hosted fixtures only. Nothing in this module selects a runtime, grants
// custody, changes the command, or substitutes for an original join/close.
#[cfg(all(test, target_os = "linux", target_arch = "x86_64", target_env = "gnu",
    not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher")))]
mod installed_native_fixture {
    use super::*;
    use std::{fs, io::{Read, Write}, os::unix::fs::{MetadataExt, OpenOptionsExt}, path::{Path, PathBuf}};
    use rustix::process::{getrlimit, setrlimit, Resource, Rlimit};

    const VERSION: &str = "/var/lib/mobile-release-kit/versions/x86_64-unknown-linux-gnu/e3375ff140d69df54b2445f756711e0245d397ba6ded76e8559732ec2e4e3801";
    #[derive(Clone, Copy, Default, Eq, PartialEq)]
    pub(super) enum Case { #[default] None, Observe, Deadline, Shutdown, Emfile, Overlap,
        #[cfg(all(debug_assertions, feature = "desktop-shell", feature = "custom-protocol"))] SessionObserve,
        #[cfg(all(debug_assertions, feature = "desktop-shell", feature = "custom-protocol"))] SessionLoss,
        #[cfg(all(debug_assertions, feature = "desktop-shell", feature = "custom-protocol"))] SessionDeadline,
    }
    #[derive(Default)]
    pub(super) struct LimitObservation {
        pub before: Option<Rlimit>, pub lowered: bool, pub restore_attempted: bool, pub restored: bool,
    }
    #[derive(Default)]
    pub(super) struct Hooks {
        pub case: Mutex<Case>, pub prepared: AtomicBool, pub deadline_crossed: AtomicBool,
        pub held: AtomicBool, pub creation: Mutex<Option<(bool, Option<i32>)>>,
        pub limit: Mutex<LimitObservation>,
        #[cfg(feature = "desktop-shell")]
        pub shell_owner: Mutex<Option<u64>>,
        #[cfg(feature = "desktop-shell")]
        pub shell_token_issued: AtomicBool,
        #[cfg(all(debug_assertions, feature = "desktop-shell", feature = "custom-protocol"))]
        pub session: Mutex<shell_shutdown_observation::SessionQueryBook>,
    }
    impl Hooks {
        fn case(&self) -> Case { *lock(&self.case) }
        pub(super) fn child_case(&self, _owner: &Arc<Owner>) -> Option<Case> {
            #[cfg(all(debug_assertions, feature = "desktop-shell", feature = "custom-protocol"))]
            if let Some(case) = shell_shutdown_observation::session_child_case(self, _owner) { return Some(case); }
            let case = self.case();
            if !matches!(case, Case::Observe | Case::Shutdown | Case::Overlap) { return None; }
            #[cfg(feature = "desktop-shell")]
            {
                if case != Case::Shutdown || !matches!(_owner.profile, Profile::Passive(Method::Capabilities)) { return None; }
                let mut original = lock(&self.shell_owner);
                if original.is_some() { return None; }
                *original = Some(_owner.key); // Consume this fixed observation once, before the original reader.
            }
            Some(case)
        }
    }
    fn need(value: bool) -> Result<(), ()> { if value { Ok(()) } else { Err(()) } }
    fn live(end: Instant, stop: &watch::Receiver<bool>) -> bool {
        Instant::now() < end && !*stop.borrow() && stop.has_changed().is_ok()
    }
    fn same_limit(a: &Rlimit, b: &Rlimit) -> bool { a.current == b.current && a.maximum == b.maximum }

    pub(super) struct NofileRestore<'a> { inner: &'a Inner, owner: &'a Arc<Owner>, original: Rlimit, attempted: bool }
    impl NofileRestore<'_> {
        pub(super) fn restore(&mut self) {
            if self.attempted { return; }
            self.attempted = true; // One explicit attempt, including unwinding; never a retry.
            let returned = setrlimit(Resource::Nofile, Rlimit { current: self.original.current, maximum: self.original.maximum }).is_ok();
            let checked = same_limit(&getrlimit(Resource::Nofile), &self.original);
            { let mut observed = lock(&self.inner.native_test.limit); observed.restore_attempted = true; observed.restored = returned && checked; }
            if !returned || !checked { self.owner.unknown(self.inner); }
        }
    }
    impl Drop for NofileRestore<'_> { fn drop(&mut self) { self.restore(); } }
    pub(super) fn before_claim<'a>(inner: &'a Inner, owner: &'a Arc<Owner>, stop: &watch::Receiver<bool>)
        -> std::io::Result<Option<NofileRestore<'a>>> {
        inner.native_test.prepared.store(true, Ordering::SeqCst);
        if inner.native_test.case() == Case::Deadline {
            // Scheduling in THIS real acquisition borrower, after all native
            // preparation. The watchdog and original 10s/2s remain untouched.
            while live(owner.endpoint(), stop) { std::thread::sleep(Duration::from_millis(1)); }
            inner.native_test.deadline_crossed.store(Instant::now() >= owner.endpoint(), Ordering::SeqCst);
        }
        if inner.native_test.case() != Case::Emfile { return Ok(None); }
        let original = getrlimit(Resource::Nofile);
        if original.current == Some(0) { return Err(std::io::Error::other("unexpected original descriptor limit")); }
        lock(&inner.native_test.limit).before = Some(Rlimit { current: original.current, maximum: original.maximum });
        let mut guard = NofileRestore { inner, owner, original, attempted: false };
        let lowered = setrlimit(Resource::Nofile, Rlimit { current: Some(0), maximum: guard.original.maximum }).is_ok()
            && same_limit(&getrlimit(Resource::Nofile), &Rlimit { current: Some(0), maximum: guard.original.maximum });
        lock(&inner.native_test.limit).lowered = lowered;
        if !lowered { guard.restore(); return Err(std::io::Error::other("descriptor-limit fixture was not established")); }
        Ok(Some(guard))
    }

    #[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
    #[serde(rename_all = "camelCase")]
    pub(super) struct Mapping { role: String, path: String, device_major: u64, device_minor: u64, inode: u64 }
    #[derive(Debug, Eq, PartialEq)]
    pub(super) struct ChildObservation { maps: Vec<Mapping>, environment_clear: bool }
    impl ChildObservation {
        #[cfg(feature = "desktop-shell")]
        pub(super) fn environment_clear(&self) -> bool { self.environment_clear }
    }
    fn flags() -> i32 {
        (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK | rustix::fs::OFlags::CLOEXEC).bits() as i32
    }
    fn original_bytes(path: &Path, limit: usize, control: bool) -> Result<Vec<u8>, ()> {
        let mut original = fs::OpenOptions::new().read(true).custom_flags(flags()).open(path).map_err(|_| ())?;
        let read = (|| {
            if control {
                let st = original.metadata().map_err(|_| ())?;
                // An old opened pending control inode may become unlinked at
                // root's atomic release replacement. This is scheduling DATA,
                // NEVER an exception for a payload or mapped library.
                need(st.is_file() && st.uid() == 0 && st.gid() == 0 && st.mode() & 0o7777 == 0o444 && st.nlink() <= 1)?;
            }
            let mut bytes = Vec::new();
            (&mut original).take((limit + 1) as u64).read_to_end(&mut bytes).map_err(|_| ())?;
            need(bytes.len() <= limit)?;
            Ok(bytes)
        })();
        let closed = nix::unistd::close(original).is_ok(); // Exact original, exactly one consuming close.
        if closed { read } else { Err(()) }
    }
    fn hex(value: &str) -> Result<u64, ()> {
        need(!value.is_empty() && value.len() <= 16 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))?;
        u64::from_str_radix(value, 16).map_err(|_| ())
    }
    fn role(path: &str) -> Option<&'static str> {
        for (name, suffix) in [("python", "/python/bin/python3"), ("libssl.so.3", "/python/lib/libssl.so.3"),
            ("libcrypto.so.3", "/python/lib/libcrypto.so.3")] {
            if path.strip_prefix(VERSION) == Some(suffix) { return Some(name); }
        }
        for name in ["ld-linux-x86-64.so.2", "libc.so.6", "libm.so.6"] {
            if path.strip_prefix("/usr/lib/x86_64-linux-gnu/") == Some(name)
                || path.strip_prefix("/lib/x86_64-linux-gnu/") == Some(name)
                || name == "ld-linux-x86-64.so.2" && path == "/lib64/ld-linux-x86-64.so.2" { return Some(name); }
        }
        None
    }
    fn mappings(raw: &[u8]) -> Result<Option<Vec<Mapping>>, ()> {
        let text = std::str::from_utf8(raw).map_err(|_| ())?;
        need(text.is_empty() || text.ends_with('\n'))?;
        let mut found: BTreeMap<&str, (Mapping, bool)> = BTreeMap::new();
        for (index, line) in text.split_terminator('\n').enumerate() {
            need(index < 4096 && !line.is_empty())?;
            let mut rest = line;
            let mut columns = [""; 5];
            for column in &mut columns {
                rest = rest.trim_start_matches([' ', '\t']);
                let end = rest.find([' ', '\t']).unwrap_or(rest.len());
                need(end > 0)?; *column = &rest[..end]; rest = &rest[end..];
            }
            let (start, end) = columns[0].split_once('-').ok_or(())?;
            need(hex(start)? < hex(end)?)?;
            let permissions = columns[1].as_bytes();
            need(permissions.len() == 4 && matches!(permissions[0], b'r' | b'-') && matches!(permissions[1], b'w' | b'-')
                && matches!(permissions[2], b'x' | b'-') && matches!(permissions[3], b'p' | b's'))?;
            let _ = hex(columns[2])?;
            let (major, minor) = columns[3].split_once(':').ok_or(())?;
            let (major, minor) = (hex(major)?, hex(minor)?);
            need(!columns[4].is_empty() && columns[4].len() <= 20 && columns[4].bytes().all(|byte| byte.is_ascii_digit()))?;
            let inode = columns[4].parse::<u64>().map_err(|_| ())?;
            let path = rest.trim_start_matches([' ', '\t']); // Opaque pathname, not a sixth whitespace token.
            let executable = permissions[2] == b'x';
            if !path.starts_with('/') {
                need(!executable || matches!(path, "[vdso]" | "[vsyscall]"))?;
                continue;
            }
            let Some(role) = role(path) else { need(!executable)?; continue; };
            let st = fs::metadata(path).map_err(|_| ())?;
            need(st.is_file() && st.uid() == 0 && st.gid() == 0 && st.nlink() == 1 && st.mode() & 0o7022 == 0
                && inode > 0 && inode == st.ino() && major == nix::sys::stat::major(st.dev()) && minor == nix::sys::stat::minor(st.dev()))?;
            let row = Mapping { role: role.into(), path: path.into(), device_major: major, device_minor: minor, inode };
            if let Some((previous, code)) = found.get_mut(role) { need(*previous == row)?; *code |= executable; }
            else { found.insert(role, (row, executable)); }
        }
        Ok(if found.len() == 6 && found.values().all(|(_, code)| *code) { Some(found.into_values().map(|(row, _)| row).collect()) } else { None })
    }
    fn child_snapshot(id: u32, end: Instant, stop: &watch::Receiver<bool>) -> Result<Option<ChildObservation>, ()> {
        need(id > 0)?;
        while live(end, stop) {
            let raw = original_bytes(Path::new(&format!("/proc/{id}/maps")), 1 << 20, false)?;
            if let Some(maps) = mappings(&raw)? {
                let mut environment = original_bytes(Path::new(&format!("/proc/{id}/environ")), 8192, false)?;
                let clear = environment.last() == Some(&0) && {
                    let entries = environment[..environment.len() - 1].split(|byte| *byte == 0).collect::<Vec<_>>();
                    entries.len() == 2 && entries.contains(&b"LANG=C".as_slice()) && entries.contains(&b"LC_ALL=C".as_slice())
                };
                environment.fill(0); // No raw environment leaves this original reader.
                need(clear)?;
                return Ok(if live(end, stop) { Some(ChildObservation { maps, environment_clear: true }) } else { None });
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        Ok(None)
    }
    fn run_number(name: &str) -> String {
        let value = std::env::var(name).expect("original hosted run binding");
        assert!(!value.is_empty() && value.len() <= 20 && !value.starts_with('0') && value.bytes().all(|byte| byte.is_ascii_digit()));
        value
    }
    fn controls() -> PathBuf {
        PathBuf::from(format!("/var/lib/mrk-ubuntu-native-{}-{}/control", run_number("GITHUB_RUN_ID"), run_number("GITHUB_RUN_ATTEMPT")))
    }
    fn ready(end: Instant) -> Result<PathBuf, ()> {
        let root = controls();
        for parent in root.ancestors() {
            let st = fs::symlink_metadata(parent).map_err(|_| ())?;
            need(st.is_dir() && st.uid() == 0 && st.gid() == 0 && st.mode() & 0o7022 == 0)?;
        }
        // CLOCK_MONOTONIC first, remaining Instant second: conservative DATA
        // for root's scheduling budget, never a new deadline for this owner.
        let clock = nix::time::clock_gettime(nix::time::ClockId::CLOCK_MONOTONIC).map_err(|_| ())?;
        let seconds = u64::try_from(clock.tv_sec()).map_err(|_| ())?;
        let nanos = u64::try_from(clock.tv_nsec()).map_err(|_| ())?;
        need(nanos < 1_000_000_000)?;
        let remaining = u64::try_from(end.saturating_duration_since(Instant::now()).as_nanos()).map_err(|_| ())?;
        need(remaining > 0)?;
        let endpoint = seconds.checked_mul(1_000_000_000).and_then(|n| n.checked_add(nanos)).and_then(|n| n.checked_add(remaining)).ok_or(())?;
        let bytes = format!("{endpoint}\n");
        need(bytes.len() <= 32)?;
        let mut original = fs::OpenOptions::new().write(true).custom_flags(flags()).open(root.join("passive-ready")).map_err(|_| ())?;
        let written = (|| {
            let st = original.metadata().map_err(|_| ())?;
            need(st.is_file() && st.uid() == 0 && st.gid() == rustix::process::getgid().as_raw()
                && st.mode() & 0o7777 == 0o620 && st.nlink() == 1 && st.len() == 0)?;
            need(original.write(bytes.as_bytes()).map_err(|_| ())? == bytes.len())
        })();
        let closed = nix::unistd::close(original).is_ok();
        if !closed { return Err(()); }
        written?;
        Ok(root.join("passive-release"))
    }
    pub(super) fn observe_original_child(id: u32, _key: u64, end: Instant, stop: watch::Receiver<bool>, inner: &Inner, case: Case)
        -> Result<Vec<ChildObservation>, ()> {
        let mut snapshots = Vec::new();
        let Some(first) = child_snapshot(id, end, &stop)? else { return Ok(snapshots); };
        snapshots.push(first);
        match case {
            #[cfg(all(debug_assertions, feature = "desktop-shell", feature = "custom-protocol"))]
            Case::SessionObserve | Case::SessionLoss | Case::SessionDeadline => {
                // Same original child/IO checkpoint, no new owner or clock.
                shell_shutdown_observation::hold_session_query(inner, _key, end, &stop, case)?;
            },
            Case::Shutdown => {
                inner.native_test.held.store(true, Ordering::SeqCst);
                inner.changed.notify_waiters();
                while live(end, &stop) { std::thread::sleep(Duration::from_millis(1)); }
            },
            Case::Overlap => {
                let release = ready(end)?;
                while live(end, &stop) {
                    let value = original_bytes(&release, 32, true)?;
                    if value.as_slice() == b"release\n" {
                        if let Some(second) = child_snapshot(id, end, &stop)? { snapshots.push(second); }
                        return Ok(snapshots);
                    }
                    need(value.as_slice() == b"pending\n")?;
                    std::thread::sleep(Duration::from_millis(1));
                }
            },
            Case::Observe => {},
            _ => return Err(()),
        }
        Ok(snapshots)
    }
    pub(super) fn report(snapshots: &[ChildObservation]) {
        for snapshot in snapshots {
            assert!(snapshot.environment_clear);
            let json = serde_json::to_string(&snapshot.maps).expect("bounded child mapping DATA");
            assert!(json.len() <= 8192);
            let mut output = std::io::stdout().lock();
            writeln!(output, "\nMRK_INSTALLED_NATIVE_CHILD={json}").expect("original bounded stdout");
            output.flush().expect("original stdout flush");
        }
    }
    #[cfg(not(feature = "desktop-shell"))]
    pub(super) fn routed_supervisor(case: Case) -> Supervisor {
        assert_eq!(std::env::var("GITHUB_ACTIONS").ok().as_deref(), Some("true"));
        assert_eq!(std::env::var("RUNNER_ENVIRONMENT").ok().as_deref(), Some("github-hosted"));
        let source = option_env!("GITHUB_SHA").expect("compiled original source binding");
        assert!(source.len() == 40 && source.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
        assert_eq!(std::env::var("GITHUB_SHA").ok().as_deref(), Some(source));
        assert_eq!(option_env!("MRK_BUNDLED_RUNTIME_MANIFEST_SHA256"), Some("e3375ff140d69df54b2445f756711e0245d397ba6ded76e8559732ec2e4e3801"));
        assert_eq!(option_env!("MRK_BUNDLED_PROTOCOL_SHA256"), Some("860d1cee0072730a487ac8e632206c69e3ba676cab849b144a61755c4b84e41e"));
        assert_ne!(rustix::process::getuid().as_raw(), 0);
        assert_eq!(rustix::process::getuid(), rustix::process::geteuid());
        let _ = (run_number("GITHUB_RUN_ID"), run_number("GITHUB_RUN_ATTEMPT"));
        let supervisor = Supervisor::new(RuntimeConfig::installed_passive_candidate_a());
        *lock(&supervisor.inner.native_test.case) = case;
        supervisor
    }
}

#[cfg(test)]
mod tests {
    // Default cases are pure bookkeeping. Ignored native cases require their
    // separate hosted/installed prerequisites; selection is not qualification.
    use super::*;
    fn inert_owner() -> Owner {
        let (stop, receiver) = watch::channel(false);
        drop(receiver);
        Owner {
            key: 1, id: "query-1".into(), profile: Profile::Passive(Method::Capabilities), github_receipt: None,
            state: Mutex::new(OwnerState::new(Instant::now() + OPERATION_TIME, None)),
            resources: AsyncMutex::new(Resources::default()), stop, changed: Notify::new(),
            permit: Mutex::new(None), driver: AsyncMutex::new(None), watchdog: AsyncMutex::new(None), observer: AsyncMutex::new(None),
            #[cfg(all(test, feature = "development-runtime"))]
            observation: Arc::new(Mutex::new(hosted_tests::Observation::default())),
        }
    }
    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    #[test]
    fn acquisition_native_causes_survive_the_original_error_carrier() {
        use crate::error::LinuxPassiveCause as Cause;
        use crate::installed_runtime::AdmissionFailure as Failure;
        let failures = [
            Failure::UnsupportedPlatform,
            Failure::MissingCompileAnchor,
            Failure::Stopped,
            Failure::Deadline,
            Failure::NativeUnavailable,
            Failure::NativeDenied,
            Failure::Namespace,
            Failure::Mount,
            Failure::Ownership,
            Failure::ExtendedAttributes,
            Failure::IdentityChanged,
            Failure::Manifest,
            Failure::Inventory,
            Failure::Bounds,
            Failure::AlreadyUsed,
            Failure::Interrupted,
            Failure::CloseUncertain,
            Failure::LedgerInvariant,
            Failure::TransferUnavailable,
            Failure::DestinationOccupied,
        ];
        let origins: [(fn(Failure) -> AcquisitionError, fn(Failure) -> Cause); 3] = [
            (AcquisitionError::capability, Cause::Capability),
            (AcquisitionError::preparation, Cause::Preparation),
            (AcquisitionError::final_claim, Cause::FinalClaim),
        ];
        for (map, cause) in origins {
            for failure in failures {
                let original = map(failure);
                assert_eq!(original.original.kind(), std::io::ErrorKind::Unsupported);
                let error = original.into_bridge_error();
                assert_eq!(error, BridgeError::unavailable("The selected isolated core could not start."));
                assert_eq!(error.linux_passive_cause(), Some(cause(failure)));
            }
        }
        let stub = AcquisitionError::unsupported("PRIVATE no-effect refusal").into_bridge_error();
        assert_eq!(stub.linux_passive_cause(), None); // Never a returned-spawn fact.
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    #[test]
    fn returned_spawn_errors_have_closed_classes_without_formatting() {
        use crate::error::{LinuxPassiveCause as Cause, LinuxSpawnFailure as Failure};
        use rustix::io::Errno;
        for (errno, expected) in [(Errno::MFILE, Failure::ProcessFdLimit), (Errno::NFILE, Failure::SystemFdLimit),
            (Errno::NOMEM, Failure::Memory), (Errno::AGAIN, Failure::ResourceUnavailable),
            (Errno::ACCESS, Failure::PermissionDenied), (Errno::PERM, Failure::PermissionDenied),
            (Errno::NOENT, Failure::NotFound), (Errno::NOEXEC, Failure::ExecFormat), (Errno::IO, Failure::Other)] {
            let original = AcquisitionError::returned_spawn(std::io::Error::from_raw_os_error(errno.raw_os_error()));
            assert_eq!(original.original.raw_os_error(), Some(errno.raw_os_error()));
            let error = original.into_bridge_error();
            assert_eq!(error.linux_passive_cause(), Some(Cause::ReturnedSpawn(expected)));
            assert_eq!(error, BridgeError::unavailable("The selected isolated core could not start."));
        }
        struct PrivateError;
        impl std::fmt::Debug for PrivateError {
            fn fmt(&self, _: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { panic!("private Debug must not run") }
        }
        impl std::fmt::Display for PrivateError {
            fn fmt(&self, _: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { panic!("private Display must not run") }
        }
        impl std::error::Error for PrivateError {}
        let original = AcquisitionError::returned_spawn(std::io::Error::new(std::io::ErrorKind::Other, PrivateError));
        assert_eq!(original.original.raw_os_error(), None);
        assert_eq!(original.into_bridge_error().linux_passive_cause(), Some(Cause::ReturnedSpawn(Failure::Other)));
        let original = AcquisitionError::from(std::io::Error::new(std::io::ErrorKind::Interrupted, PrivateError));
        assert_eq!(original.into_bridge_error().linux_passive_cause(), None);
    }

    #[test]
    fn stop_is_latched_before_any_io_receiver_exists() {
        let owner = inert_owner();
        owner.fail(BridgeError::timeout());
        assert!(*owner.stop.subscribe().borrow());
    }
    #[test]
    fn cleanup_allowance_and_first_error_are_never_renewed() {
        let owner = inert_owner();
        owner.fail(BridgeError::timeout());
        let first = lock(&owner.state).cleanup_endpoint;
        owner.fail(BridgeError::shutdown());
        let state = lock(&owner.state);
        assert_eq!(state.cleanup_endpoint, first);
        assert_eq!(state.error.as_ref().map(|error| error.code.as_str()), Some("query_timeout"));
    }
    #[test]
    fn closed_profile_changes_only_the_private_channel_bound() {
        assert_eq!(Profile::Passive(Method::Capabilities).stdout_limit(), protocol::RESPONSE_LIMIT);
        assert_eq!(Profile::Passive(Method::EnvironmentRequirements).stdout_limit(), 64 * 1024);
        assert_eq!(Profile::Passive(Method::MetadataTextObserve).stdout_limit(), 2 * 1024 * 1024);
        assert_eq!(Profile::Passive(Method::MetadataTextValidate).stdout_limit(), 2 * 1024 * 1024);
        assert_eq!(Profile::GitHubReadOnly.stdout_limit(), 64 * 1024);
        assert_eq!(protocol::STDERR_LIMIT, 64 * 1024);
        assert_eq!(ACTIVE_LIMIT, 2);
        assert_eq!(OPERATION_TIME, Duration::from_secs(10));
        assert_eq!(CLEANUP_TIME, Duration::from_secs(2));
    }

    #[test]
    fn passive_claim_uses_the_original_endpoint_stop_and_domain() {
        let now = Instant::now(); let endpoint = now + OPERATION_TIME;
        let mut state = OwnerState::new(endpoint, None);
        let passive = Profile::Passive(Method::Capabilities);
        assert!(passive_claim_clear(true, passive, &state, endpoint - Duration::from_nanos(1), false, false, false));
        assert!(!passive_claim_clear(true, passive, &state, endpoint, false, false, false));
        assert!(!passive_claim_clear(true, passive, &state, endpoint + Duration::from_nanos(1), false, false, false));
        assert!(!passive_claim_clear(false, passive, &state, now, false, false, false));
        assert!(!passive_claim_clear(true, Profile::GitHubReadOnly, &state, now, false, false, false));
        assert!(!passive_selected(Profile::GitHubReadOnly));
        for (stopping, disabled, stop) in [(true, false, false), (false, true, false), (false, false, true)] {
            assert!(!passive_claim_clear(true, passive, &state, now, stopping, disabled, stop));
        }
        state.unknown = true;
        assert!(!passive_claim_clear(true, passive, &state, now, false, false, false));
        state.unknown = false; state.terminal = true;
        assert!(!passive_claim_clear(true, passive, &state, now, false, false, false));
        state.terminal = false;
        state.fail_at(BridgeError::timeout(), now);
        assert!(!passive_claim_clear(true, passive, &state, now, false, false, false));
        assert_eq!(state.cleanup_endpoint, Some(now + CLEANUP_TIME));
        state.fail_at(BridgeError::shutdown(), endpoint);
        assert_eq!(state.endpoint, endpoint);
        assert_eq!(state.cleanup_endpoint, Some(now + Duration::from_secs(2)));
        state.error = None; // Even contradictory decision DATA cannot renew first F.
        assert!(!passive_claim_clear(true, passive, &state, now, false, false, false));
    }

    #[test]
    fn passive_borrow_return_requires_the_original_handle_and_ready_record() {
        let absent = OriginalBorrow { returned: None, handle: false, error: false };
        let joined = OriginalBorrow { returned: Some(ManagementJoin::Returned), ..absent };
        assert!(absent.returned() && absent.positive() && joined.returned() && joined.positive());
        assert!(!(OriginalBorrow { returned: Some(ManagementJoin::Pending), handle: true, error: false }).returned());
        assert!(!(OriginalBorrow { handle: true, ..joined }).returned());
        assert!(!(OriginalBorrow { error: true, ..joined }).returned());
        assert!(!(OriginalBorrow { handle: true, ..absent }).returned());
        for failed in [ManagementJoin::Cancelled, ManagementJoin::Panicked, ManagementJoin::Failed] {
            let actual_failed = OriginalBorrow { returned: Some(failed), handle: true, error: true };
            assert!(actual_failed.returned() && !actual_failed.positive());
            assert!(!(OriginalBorrow { handle: false, ..actual_failed }).returned());
            assert!(!(OriginalBorrow { error: false, ..actual_failed }).returned());
        }
        for invalid in [ManagementJoin::Missing, ManagementJoin::InvalidReturn, ManagementJoin::Pending] {
            assert!(!(OriginalBorrow { returned: Some(invalid), handle: true, error: true }).returned());
        }
    }

    #[test]
    fn passive_completion_requires_join_close_and_same_ledger_settlement() {
        // Bounded decisions only, not fabricated JoinHandles, FDs or capabilities.
        let absent = OriginalBorrow { returned: None, handle: false, error: false };
        let joined = OriginalBorrow { returned: Some(ManagementJoin::Returned), ..absent };
        assert!(passive_completion_clear(joined, joined, true, true, false, true, true));
        assert!(passive_completion_clear(joined, absent, true, true, false, true, true)); // No acquisition ever queued.
        assert!(!passive_completion_clear(absent, absent, true, true, false, true, true));
        for (started, returned, retained, closed, ledger) in [
            (false, true, false, true, true), (true, false, false, true, true),
            (true, true, true, true, true), (true, true, false, false, true), (true, true, false, true, false),
        ] {
            assert!(!passive_completion_clear(joined, joined, started, returned, retained, closed, ledger));
        }
        for incomplete in [
            OriginalBorrow { returned: Some(ManagementJoin::Pending), handle: true, error: false },
            OriginalBorrow { returned: Some(ManagementJoin::Panicked), handle: true, error: true },
            OriginalBorrow { handle: true, ..joined }, OriginalBorrow { error: true, ..joined },
        ] {
            assert!(!passive_completion_clear(incomplete, joined, true, true, false, true, true));
            assert!(!passive_completion_clear(joined, incomplete, true, true, false, true, true));
        }
    }

    #[test]
    fn passive_no_effect_refusal_requires_a_never_started_book_and_returned_borrow() {
        let absent = OriginalBorrow { returned: None, handle: false, error: false };
        let joined = OriginalBorrow { returned: Some(ManagementJoin::Returned), ..absent };
        assert!(passive_never_started_clear(absent, absent, true)); // STOP before worker registration.
        assert!(passive_never_started_clear(joined, absent, true)); // Actual closed-profile return.
        assert!(!passive_never_started_clear(joined, absent, false));
        assert!(!passive_never_started_clear(joined, joined, true));
        for pending_or_lost in [
            OriginalBorrow { returned: Some(ManagementJoin::Pending), handle: true, error: false },
            OriginalBorrow { returned: Some(ManagementJoin::Panicked), handle: true, error: true },
            OriginalBorrow { handle: true, ..joined },
        ] {
            assert!(!passive_never_started_clear(pending_or_lost, absent, true));
            assert!(!passive_never_started_clear(joined, pending_or_lost, true));
        }
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu",
        not(feature = "development-runtime"), not(feature = "desktop-shell")))]
    #[tokio::test(flavor = "current_thread")]
    #[ignore = "only the separately reviewed feature-off passive owner verification"]
    async fn closed_passive_profile_returns_through_original_owner_without_effects() {
        // Existing hosted routing/source guards only: no runtime selection,
        // fixture permit or production-profile override is introduced.
        for (name, value) in [("GITHUB_ACTIONS", "true"), ("RUNNER_ENVIRONMENT", "github-hosted"),
            ("MRK_DESKTOP_HOSTED_CHECKS", "conventional-runtime-bootstrap-smoke-v1")] {
            assert_eq!(std::env::var(name).ok().as_deref(), Some(value), "fixed hosted route required");
        }
        let source = option_env!("GITHUB_SHA").expect("compiled original source binding required");
        assert!(source.len() == 40 && source.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
        assert_eq!(std::env::var("GITHUB_SHA").ok().as_deref(), Some(source), "original source binding differs");
        let supervisor = Supervisor::new(RuntimeConfig::packaged(std::path::PathBuf::from(
            "/inert-passive-owner-path-must-not-be-opened")));
        assert_eq!(supervisor.runtime_mode(), "bundled");
        assert!(passive_selected(Profile::Passive(Method::Capabilities)));
        let ticket = supervisor.start_passive(Method::Capabilities, serde_json::json!({}))
            .expect("the actual passive owner must register");
        let owner = ticket.owner.clone();
        let endpoint = owner.endpoint();
        // Current-thread executor: no spawned management task has been polled.
        // Retain only Arcs to the SAME owner/storage, never clone a native book.
        let originals = {
            let resources = owner.resources.try_lock().expect("fresh original resources");
            let originals = resources.passive.as_ref().expect("production passive slots").clone();
            assert!(lock(&originals).never_started());
            assert!(resources.inspection.is_none() && resources.inspection_return.is_none()
                && resources.acquisition.is_none() && resources.acquisition_return.is_none());
            originals
        };
        {
            let owners = lock(&supervisor.inner.owners);
            assert_eq!(owners.len(), 1);
            assert!(owners.get(&owner.key).is_some_and(|registered| Arc::ptr_eq(registered, &owner)));
        }
        assert!(lock(&owner.permit).is_some());
        assert_eq!(supervisor.inner.permits.available_permits(), ACTIVE_LIMIT - 1);
        assert!(owner.driver.try_lock().unwrap().as_ref().is_some_and(|task| !task.is_finished()));
        assert!(owner.watchdog.try_lock().unwrap().as_ref().is_some_and(|task| !task.is_finished()));
        assert!(owner.observer.try_lock().unwrap().as_ref().is_some_and(|task| !task.is_finished()));
        // All custody/registry/handle guards above have ended before yielding.
        let result = ticket.wait().await;
        // Product code alone consumes driver/watchdog. Move out and await only
        // the original final observer's tail, with no slot guard across the join.
        let observer = { owner.observer.lock().await.take() };
        let Some(mut observer) = observer else {
            eprintln!("closed passive owner verification retained: original observer missing");
            return pending::<()>().await;
        };
        if (&mut observer).await.is_err() {
            // Keep the consumed failed original; never abort, repoll or replace.
            *owner.observer.lock().await = Some(observer);
            eprintln!("closed passive owner verification retained: original observer failed");
            return pending::<()>().await;
        }
        drop(observer); // Actual positive original join, not elapsed-time inference.

        let error = result.expect_err("the production passive profile must still refuse");
        assert_eq!(error.code, "runtime_unavailable");
        assert_eq!(error.message, "The passive installed-runtime release and custody profile are not qualified.");
        {
            let resources = owner.resources.try_lock().expect("original borrowers returned");
            assert!(resources.passive.as_ref().is_some_and(|actual| Arc::ptr_eq(actual, &originals)));
            assert_eq!(resources.inspection_return, Some(ManagementJoin::Returned));
            assert!(resources.inspection.is_none() && resources.inspection_error.is_none());
            assert!(resources.acquisition.is_none() && resources.acquisition_return.is_none()
                && resources.acquisition_error.is_none() && resources.child.is_none());
            assert!(resources.writer.is_none() && resources.stdout.is_none() && resources.stderr.is_none()
                && resources.failed_writer.is_none() && resources.failed_stdout.is_none()
                && resources.failed_stderr.is_none());
            assert!(resources.waited.is_none() && resources.write_end.is_none()
                && resources.out_end.is_none() && resources.err_end.is_none() && !resources.kill_attempted);
            assert!(!resources.native_started && resources.native_settlement.is_none() && resources.native_return.is_none());
        }
        {
            let originals = lock(&originals);
            // This is the never-started/no-effect exception, NOT a close receipt.
            assert!(originals.never_started() && !originals.settled());
        }
        {
            let state = lock(&owner.state);
            assert_eq!(state.endpoint, endpoint);
            assert_eq!(state.driver_join, ManagementJoin::Returned);
            assert_eq!(state.watchdog_join, ManagementJoin::Returned);
            assert!(matches!(state.watchdog_end, Some(WatchdogEnd::DriverObserved(ManagementJoin::Returned))));
            assert!(state.terminal && !state.unknown && state.reply.is_none() && state.cleanup_endpoint.is_some());
            assert_eq!(state.error.as_ref().map(|error| error.code.as_str()), Some("runtime_unavailable"));
        }
        assert!(owner.driver.try_lock().unwrap().is_none() && owner.watchdog.try_lock().unwrap().is_none()
            && owner.observer.try_lock().unwrap().is_none());
        assert!(lock(&owner.permit).is_none());
        assert!(supervisor.can_exit() && !supervisor.disabled() && !supervisor.stopping());
        assert_eq!(supervisor.inner.permits.available_permits(), ACTIVE_LIMIT);
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu",
        not(feature = "development-runtime"), not(feature = "desktop-shell"), not(feature = "ubuntu-runtime-publisher")))]
    #[tokio::test(flavor = "current_thread")]
    #[ignore = "requires separately reviewed disposable installed A and OS-loader qualification; source preparation only"]
    async fn installed_candidate_a_capabilities_and_catalog_retire_originals() {
        // These are routing/source guards, NOT external loader qualification.
        // Execute only after that prerequisite and the immutable installation
        // are separately accepted. No fixture path, permit or fake FD is used.
        let supervisor = installed_native_fixture::routed_supervisor(installed_native_fixture::Case::Observe);
        assert_eq!(supervisor.runtime_mode(), "bundled");
        for method in [Method::Capabilities, Method::Catalog] {
            let ticket = supervisor.start_passive(method, serde_json::json!({})).expect("original passive owner registration");
            let owner = ticket.owner.clone();
            let endpoint = owner.endpoint();
            // Current-thread executor has not polled any management task yet.
            let originals = {
                let resources = owner.resources.try_lock().expect("fresh original resources");
                let originals = resources.passive.as_ref().expect("original passive slots").clone();
                assert!(lock(&originals).never_started());
                assert!(resources.inspection_return.is_none() && resources.acquisition_return.is_none());
                originals
            };
            assert!(lock(&supervisor.inner.owners).get(&owner.key).is_some_and(|actual| Arc::ptr_eq(actual, &owner)));
            assert!(lock(&owner.permit).is_some());
            assert_eq!(supervisor.inner.permits.available_permits(), ACTIVE_LIMIT - 1);

            let result = ticket.wait().await;
            // Product code consumes driver/watchdog. Join only the SAME final
            // observer's tail; never abort, retry or replace a failed original.
            let observer = { owner.observer.lock().await.take() };
            let Some(mut observer) = observer else {
                eprintln!("installed passive verification retained: original observer missing");
                return pending::<()>().await;
            };
            if (&mut observer).await.is_err() {
                *owner.observer.lock().await = Some(observer);
                eprintln!("installed passive verification retained: original observer failed");
                return pending::<()>().await;
            }
            drop(observer);
            let value = result.expect("the actual installed passive query must succeed");
            match method {
                Method::Capabilities => {
                    assert_eq!(value["mode"], "read-only-foundation");
                    let methods = value["methods"].as_array().expect("capabilities roster");
                    for name in ["capabilities", "catalog", "project.snapshot", "config.validate"] {
                        assert!(methods.iter().any(|entry| entry["method"] == name));
                    }
                }
                Method::Catalog => assert!(value["schema"].is_object()
                    && value["fields"].as_array().is_some_and(|fields| !fields.is_empty())),
                _ => unreachable!(),
            }
            {
                let resources = owner.resources.try_lock().expect("original borrowers returned");
                assert!(resources.passive.as_ref().is_some_and(|actual| Arc::ptr_eq(actual, &originals)));
                assert_eq!(resources.inspection_return, Some(ManagementJoin::Returned));
                assert_eq!(resources.acquisition_return, Some(ManagementJoin::Returned));
                assert!(resources.inspection.is_none() && resources.inspection_error.is_none()
                    && resources.acquisition.is_none() && resources.acquisition_error.is_none());
                assert!(resources.waited.as_ref().is_some_and(|status| status.success()));
                assert!(resources.write_end.is_some_and(|end| end.complete));
                assert!(resources.writer.is_none() && resources.stdout.is_none() && resources.stderr.is_none()
                    && resources.failed_writer.is_none() && resources.failed_stdout.is_none() && resources.failed_stderr.is_none());
                // Successful driver settlement checked BOTH real EOFs before
                // taking their DTOs and the already-waited Child out of Resources.
                assert!(resources.child.is_none() && resources.out_end.is_none() && resources.err_end.is_none() && !resources.kill_attempted);
                assert!(resources.native_started && resources.native_settlement.is_none()
                    && matches!(resources.native_return.as_ref(), Some(Ok(CloseOutcome::Settled))));
                assert!(resources.native_observation.is_none());
                assert_eq!(resources.native_observation_return, Some(ManagementJoin::Returned));
                assert_eq!(resources.native_snapshots.len(), 1);
                installed_native_fixture::report(&resources.native_snapshots);
            }
            {
                let slots = lock(&originals);
                assert!(slots.settled() && !slots.no_child_effect());
                let observed = slots.claimed_observation().expect("same transferred and claimed original");
                assert_eq!(observed.phase(), "settled");
                assert_eq!(observed.failure(), None);
                assert!(observed.records() > 8);
                assert_eq!(observed.positive_closes(), observed.records());
                assert_eq!((observed.live_originals(), observed.pending_acquisitions(), observed.uncertain_closes()), (0, 0, 0));
            }
            {
                let state = lock(&owner.state);
                assert_eq!(state.endpoint, endpoint);
                assert_eq!(state.driver_join, ManagementJoin::Returned);
                assert_eq!(state.watchdog_join, ManagementJoin::Returned);
                assert!(matches!(state.watchdog_end, Some(WatchdogEnd::DriverObserved(ManagementJoin::Returned))));
                assert!(state.terminal && !state.unknown && state.error.is_none() && state.cleanup_endpoint.is_none() && state.reply.is_none());
            }
            assert!(owner.driver.try_lock().unwrap().is_none() && owner.watchdog.try_lock().unwrap().is_none()
                && owner.observer.try_lock().unwrap().is_none());
            assert!(lock(&owner.permit).is_none());
            assert!(supervisor.can_exit() && !supervisor.disabled() && !supervisor.stopping());
            assert_eq!(supervisor.inner.permits.available_permits(), ACTIVE_LIMIT);
        }
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu",
        not(feature = "development-runtime"), not(feature = "desktop-shell"), not(feature = "ubuntu-runtime-publisher")))]
    mod native {
        use super::*;
        pub(super) type Originals = Arc<Mutex<PassiveRuntimeSlots>>;
        pub(super) fn registered(case: installed_native_fixture::Case) -> (Supervisor, PassiveQuery, Arc<Owner>, Originals, Instant) {
            let supervisor = installed_native_fixture::routed_supervisor(case);
            let ticket = supervisor.start_passive(Method::Capabilities, serde_json::json!({})).expect("real original owner");
            let owner = ticket.owner.clone();
            let end = owner.endpoint();
            let originals = owner.resources.try_lock().expect("unpolled original resources").passive.as_ref().expect("original slots").clone();
            assert!(lock(&originals).never_started());
            assert!(lock(&supervisor.inner.owners).get(&owner.key).is_some_and(|actual| Arc::ptr_eq(actual, &owner)));
            assert!(lock(&owner.permit).is_some());
            (supervisor, ticket, owner, originals, end)
        }
        pub(super) async fn completed(ticket: PassiveQuery, owner: &Arc<Owner>) -> Result<Value, BridgeError> {
            let result = ticket.wait().await;
            let original = { owner.observer.lock().await.take() };
            let Some(mut original) = original else { return pending().await; };
            if (&mut original).await.is_err() {
                *owner.observer.lock().await = Some(original); // Retain a consumed failed original, never abort/repoll.
                return pending().await;
            }
            result
        }
        pub(super) fn retired(supervisor: &Supervisor, owner: &Arc<Owner>, originals: &Originals, end: Instant) {
            {
                let resources = owner.resources.try_lock().expect("original driver returned");
                assert!(resources.passive.as_ref().is_some_and(|actual| Arc::ptr_eq(actual, originals)));
                assert_eq!(resources.inspection_return, Some(ManagementJoin::Returned));
                assert!(resources.inspection.is_none() && resources.inspection_error.is_none()
                    && resources.acquisition.is_none() && resources.acquisition_error.is_none());
                assert!(resources.child.is_none() && resources.writer.is_none() && resources.stdout.is_none() && resources.stderr.is_none()
                    && resources.failed_writer.is_none() && resources.failed_stdout.is_none() && resources.failed_stderr.is_none());
                assert!(resources.native_started && resources.native_settlement.is_none()
                    && matches!(resources.native_return.as_ref(), Some(Ok(CloseOutcome::Settled))) && resources.native_observation.is_none());
            }
            {
                let slots = lock(originals);
                assert!(slots.settled());
                let observation = slots.fixture_observation().expect("same original book");
                assert_eq!(observation.phase(), "settled");
                assert!(observation.records() > 0);
                assert_eq!(observation.positive_closes(), observation.records());
                assert_eq!((observation.live_originals(), observation.pending_acquisitions(), observation.uncertain_closes()), (0, 0, 0));
            }
            {
                let state = lock(&owner.state);
                assert_eq!(state.endpoint, end);
                assert!(state.terminal && !state.unknown && state.reply.is_none());
                assert_eq!(state.driver_join, ManagementJoin::Returned);
                assert_eq!(state.watchdog_join, ManagementJoin::Returned);
                assert!(matches!(state.watchdog_end, Some(WatchdogEnd::DriverObserved(ManagementJoin::Returned))));
            }
            assert!(owner.driver.try_lock().unwrap().is_none() && owner.watchdog.try_lock().unwrap().is_none()
                && owner.observer.try_lock().unwrap().is_none());
            assert!(lock(&owner.permit).is_none() && supervisor.can_exit() && !supervisor.disabled());
            assert_eq!(supervisor.inner.permits.available_permits(), ACTIVE_LIMIT);
        }
        pub(super) async fn refusal(failure: crate::installed_runtime::AdmissionFailure) {
            let (supervisor, ticket, owner, originals, end) = registered(installed_native_fixture::Case::None);
            let result = completed(ticket, &owner).await;
            retired(&supervisor, &owner, &originals, end);
            assert_eq!(result.expect_err("real installed inspection must refuse").code, "runtime_unavailable");
            assert_eq!(lock(&originals).fixture_observation().unwrap().failure(), Some(failure));
            { let slots = lock(&originals); assert!(slots.no_child_effect() && slots.claimed_observation().is_none()); }
            let resources = owner.resources.try_lock().unwrap();
            assert!(resources.acquisition_return.is_none() && resources.waited.is_none() && resources.write_end.is_none()
                && resources.out_end.is_none() && resources.err_end.is_none() && !resources.kill_attempted
                && resources.native_observation_return.is_none() && resources.native_snapshots.is_empty());
            assert!(!supervisor.inner.native_test.prepared.load(Ordering::SeqCst) && lock(&supervisor.inner.native_test.creation).is_none());
        }
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu",
        not(feature = "development-runtime"), not(feature = "desktop-shell"), not(feature = "ubuntu-runtime-publisher")))]
    #[tokio::test(flavor = "current_thread")]
    #[ignore = "requires independently reviewed pristine never-published writable-ancestor fixture"]
    async fn installed_candidate_a_writable_ancestor_refuses_and_retires() {
        native::refusal(crate::installed_runtime::AdmissionFailure::Ownership).await;
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu",
        not(feature = "development-runtime"), not(feature = "desktop-shell"), not(feature = "ubuntu-runtime-publisher")))]
    #[tokio::test(flavor = "current_thread")]
    #[ignore = "requires independently reviewed pristine never-published extra python3._pth fixture"]
    async fn installed_candidate_a_extra_startup_refuses_and_retires() {
        native::refusal(crate::installed_runtime::AdmissionFailure::Inventory).await;
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu",
        not(feature = "development-runtime"), not(feature = "desktop-shell"), not(feature = "ubuntu-runtime-publisher")))]
    #[tokio::test(flavor = "current_thread")]
    #[ignore = "requires reviewed installed A/native loader context; uses real 10s/2s clocks"]
    async fn installed_candidate_a_deadline_before_claim_retires() {
        let (supervisor, ticket, owner, originals, end) = native::registered(installed_native_fixture::Case::Deadline);
        let result = native::completed(ticket, &owner).await;
        native::retired(&supervisor, &owner, &originals, end);
        assert_eq!(result.expect_err("original deadline forbids late creation").code, "query_timeout");
        assert!(supervisor.inner.native_test.prepared.load(Ordering::SeqCst)
            && supervisor.inner.native_test.deadline_crossed.load(Ordering::SeqCst));
        assert!(lock(&supervisor.inner.native_test.creation).is_none());
        { let slots = lock(&originals); assert!(slots.no_child_effect() && slots.claimed_observation().is_none()); }
        let resources = owner.resources.try_lock().unwrap();
        assert_eq!(resources.acquisition_return, Some(ManagementJoin::Returned));
        assert!(resources.waited.is_none() && resources.write_end.is_none() && resources.out_end.is_none()
            && resources.err_end.is_none() && !resources.kill_attempted && resources.native_observation_return.is_none());
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu",
        not(feature = "development-runtime"), not(feature = "desktop-shell"), not(feature = "ubuntu-runtime-publisher")))]
    #[tokio::test(flavor = "current_thread")]
    #[ignore = "requires reviewed installed A/native loader context and real original child pipes"]
    async fn installed_candidate_a_shutdown_with_child_retires() {
        let (supervisor, ticket, owner, originals, end) = native::registered(installed_native_fixture::Case::Shutdown);
        loop {
            let changed = supervisor.inner.changed.notified();
            if supervisor.inner.native_test.held.load(Ordering::SeqCst) || Instant::now() >= end || owner.failed() { break; }
            tokio::select! { _ = changed => {}, _ = tokio::time::sleep_until(tokio::time::Instant::from_std(end)) => {} }
        }
        // The real child is held in the original pre-writer reader, with all
        // three original pipes. STOP releases scheduling, never destroys it.
        let shutdown = supervisor.shutdown().await;
        let result = native::completed(ticket, &owner).await;
        native::retired(&supervisor, &owner, &originals, end);
        assert!(supervisor.inner.native_test.held.load(Ordering::SeqCst) && supervisor.stopping());
        shutdown.expect("actual shutdown retirement");
        assert_eq!(result.expect_err("shutdown forbids success").code, "shutting_down");
        { let slots = lock(&originals); assert!(slots.claimed_observation().is_some() && !slots.no_child_effect()); }
        let resources = owner.resources.try_lock().unwrap();
        assert_eq!(resources.acquisition_return, Some(ManagementJoin::Returned));
        assert!(resources.waited.is_some() && resources.write_end.is_some() && resources.out_end.is_none()
            && resources.err_end.is_none() && resources.kill_attempted);
        assert_eq!(resources.native_observation_return, Some(ManagementJoin::Returned));
        assert_eq!(resources.native_snapshots.len(), 1);
        installed_native_fixture::report(&resources.native_snapshots);
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu",
        not(feature = "development-runtime"), not(feature = "desktop-shell"), not(feature = "ubuntu-runtime-publisher")))]
    #[tokio::test(flavor = "current_thread")]
    #[ignore = "requires reviewed installed A and designated exit79 carrier ownership; never a normal libtest pass"]
    async fn installed_candidate_a_creation_emfile_retains_unknown() {
        use std::io::Write;
        let (supervisor, ticket, owner, originals, end) = native::registered(installed_native_fixture::Case::Emfile);
        assert_eq!(ticket.wait().await.expect_err("opaque actual creation error").code, "cleanup_unknown");
        loop {
            let changed = owner.changed.notified();
            let returned = {
                let state = lock(&owner.state);
                state.driver_join == ManagementJoin::Returned && state.watchdog_join == ManagementJoin::Returned
            };
            if returned { break; }
            if Instant::now() >= end { return pending::<()>().await; } // Keep Unknown and original handles for the outer owner.
            tokio::select! { _ = changed => {}, _ = tokio::time::sleep_until(tokio::time::Instant::from_std(end)) => {} }
        }
        assert_eq!(*lock(&supervisor.inner.native_test.creation), Some((false, Some(rustix::io::Errno::MFILE.raw_os_error()))));
        {
            let limit = lock(&supervisor.inner.native_test.limit);
            assert!(limit.lowered && limit.restore_attempted && limit.restored);
            let original = limit.before.as_ref().expect("actual original limit");
            let current = rustix::process::getrlimit(rustix::process::Resource::Nofile);
            assert_eq!((current.current, current.maximum), (original.current, original.maximum));
        }
        {
            let resources = owner.resources.try_lock().expect("actual acquisition/driver returned");
            assert!(resources.passive.as_ref().is_some_and(|actual| Arc::ptr_eq(actual, &originals)));
            assert_eq!(resources.inspection_return, Some(ManagementJoin::Returned));
            assert_eq!(resources.acquisition_return, Some(ManagementJoin::Returned));
            assert!(resources.inspection.is_none() && resources.inspection_error.is_none()
                && resources.acquisition.is_none() && resources.acquisition_error.is_none() && resources.child.is_none());
            assert!(resources.writer.is_none() && resources.stdout.is_none() && resources.stderr.is_none()
                && resources.failed_writer.is_none() && resources.failed_stdout.is_none() && resources.failed_stderr.is_none()
                && resources.waited.is_none() && resources.write_end.is_none() && resources.out_end.is_none() && resources.err_end.is_none()
                && !resources.kill_attempted && resources.native_observation.is_none() && resources.native_observation_return.is_none());
            assert!(!resources.native_started && resources.native_settlement.is_none() && resources.native_return.is_none());
        }
        {
            let slots = lock(&originals);
            assert!(!slots.no_child_effect() && !slots.settled());
            let observed = slots.claimed_observation().expect("actual claim without a no-effect receipt");
            assert_eq!(observed.phase(), "passivePrepared");
            assert_eq!(observed.failure(), None);
            assert_eq!((observed.live_originals(), observed.pending_acquisitions(), observed.uncertain_closes()), (9, 0, 0));
            assert_eq!(observed.positive_closes() + 9, observed.records());
        }
        {
            let state = lock(&owner.state);
            assert_eq!(state.endpoint, end);
            assert!(state.unknown && !state.terminal && state.reply.is_none() && matches!(state.driver_end, Some(DriverEnd::RetainedUnknown)));
            assert!(matches!(state.watchdog_end, Some(WatchdogEnd::DriverObserved(ManagementJoin::Returned))));
        }
        assert!(supervisor.disabled() && !supervisor.can_exit() && lock(&owner.permit).is_some());
        assert!(lock(&supervisor.inner.owners).get(&owner.key).is_some_and(|actual| Arc::ptr_eq(actual, &owner)));
        assert_eq!(supervisor.inner.permits.available_permits(), ACTIVE_LIMIT - 1);
        assert!(owner.observer.try_lock().unwrap().is_some()); // Still-pending original observer is NOT aborted/joined away.
        assert_eq!(supervisor.start_passive(Method::Capabilities, serde_json::json!({})).err().expect("disabled admission").code, "cleanup_unknown");
        let mut output = std::io::stdout().lock();
        writeln!(output, "\nMRK_INSTALLED_NATIVE_EMFILE_RETAINED_UNKNOWN").expect("bounded carrier marker");
        output.flush().expect("original marker flush");
        // Deliberate carrier destruction while EVERY owner reference remains
        // held. The outer original C/A/W owner must verify exit79/domain finality.
        // This is neither native close/retirement nor a normal libtest success.
        std::process::exit(79);
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu",
        not(feature = "development-runtime"), not(feature = "desktop-shell"), not(feature = "ubuntu-runtime-publisher")))]
    #[tokio::test(flavor = "current_thread")]
    #[ignore = "requires reviewed P0/F1 publication and original root-worker/control-file ownership"]
    async fn installed_candidate_a_child_spans_f1_publication() {
        let (supervisor, ticket, owner, originals, end) = native::registered(installed_native_fixture::Case::Overlap);
        let result = native::completed(ticket, &owner).await;
        native::retired(&supervisor, &owner, &originals, end);
        assert_eq!(result.expect("same old child must complete within its original deadline")["mode"], "read-only-foundation");
        { let slots = lock(&originals); assert!(slots.claimed_observation().is_some() && !slots.no_child_effect()); }
        assert!(Instant::now() < end);
        let resources = owner.resources.try_lock().unwrap();
        assert_eq!(resources.acquisition_return, Some(ManagementJoin::Returned));
        assert!(resources.waited.as_ref().is_some_and(|status| status.success())
            && resources.write_end.is_some_and(|write| write.complete) && !resources.kill_attempted);
        assert_eq!(resources.native_observation_return, Some(ManagementJoin::Returned));
        assert_eq!(resources.native_snapshots.len(), 2);
        assert_eq!(resources.native_snapshots[0], resources.native_snapshots[1]);
        installed_native_fixture::report(&resources.native_snapshots);
    }
}
