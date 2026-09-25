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
    all(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64"), all(target_os = "windows", target_arch = "x86_64", target_env = "msvc")),
        not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), any(test, feature = "desktop-shell"))))]
use std::process::Stdio;
use serde_json::Value;
use tokio::{io::{AsyncRead, AsyncReadExt, AsyncWriteExt}, process::Child, sync::{mpsc, oneshot, watch, Mutex as AsyncMutex, Notify, OwnedSemaphorePermit, Semaphore}, task::JoinHandle};
#[cfg(any(all(feature = "development-runtime", debug_assertions),
    all(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64"), all(target_os = "windows", target_arch = "x86_64", target_env = "msvc")),
        not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), any(test, feature = "desktop-shell"))))]
use tokio::process::Command;
use crate::{error::BridgeError, github_connection_protocol::{self as github_protocol, GitHubReadOutcome},
    protocol::{self, Method}, runtime::{RuntimeConfig, VerifiedRuntime}};
#[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64")))]
use crate::installed_runtime::{AdmissionFailure as PassiveAdmissionFailure, CloseOutcome, PassiveInstalledRuntime, PassiveRuntimeSlots};
#[cfg(all(target_os = "windows", target_arch = "x86_64", target_env = "msvc"))]
use crate::installed_runtime_windows::{InspectionFailure as PassiveAdmissionFailure, CloseOutcome, PassiveInstalledRuntime, PassiveRuntimeSlots};

#[cfg(all(test, target_os = "windows", target_arch = "x86_64", target_env = "msvc", not(feature = "development-runtime"), not(feature = "desktop-shell"), not(feature = "ubuntu-runtime-publisher"), not(feature = "windows-runtime-publisher"), not(feature = "macos-installed-installer")))]
#[path = "installed_windows_passive_tests.rs"]
mod windows_passive_tests;

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
pub(crate) use shell_shutdown_observation::{InstalledSessionQueries, InstalledSessionQueryDiagnostic, SessionQueryHold,
    assert_installed_session_query_diagnostic_contract};
#[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", target_os = "linux", target_arch = "x86_64", target_env = "gnu",
    not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher")))]
use shell_shutdown_observation::{FirstUnknown, UnknownBoundary};

// Only the installed observer copies caller-held DATA. Ordinary builds erase
// both diagnostic arguments, including any Resources borrow or boundary type.
#[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", target_os = "linux", target_arch = "x86_64", target_env = "gnu",
    not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher")))]
macro_rules! owner_unknown {
    ($owner:expr, $inner:expr, $resources:expr, $boundary:ident) => {
        ($owner).unknown_policy($inner, $resources, UnknownBoundary::$boundary)
    };
}
#[cfg(not(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", target_os = "linux", target_arch = "x86_64", target_env = "gnu",
    not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"))))]
macro_rules! owner_unknown {
    ($owner:expr, $inner:expr, $resources:expr, $boundary:ident) => { ($owner).unknown($inner) };
}

#[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "windows-installed-observation",
    target_os = "windows", target_arch = "x86_64", target_env = "msvc", not(feature = "development-runtime"),
    not(feature = "ubuntu-runtime-publisher"), not(feature = "windows-runtime-publisher"), not(feature = "macos-installed-installer")))]
#[path = "installed_shell_shutdown_observation_windows.rs"]
mod windows_shell_observation;
#[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "windows-installed-observation",
    target_os = "windows", target_arch = "x86_64", target_env = "msvc", not(feature = "development-runtime"),
    not(feature = "ubuntu-runtime-publisher"), not(feature = "windows-runtime-publisher"), not(feature = "macos-installed-installer")))]
pub(crate) use windows_shell_observation::WindowsPassiveWitness;

fn lock<T>(value: &Mutex<T>) -> MutexGuard<'_, T> {
    // No user callback/serialization runs while these small bookkeeping locks
    // are held. Retain the data even on poisoning; never drop the resource owner.
    value.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[derive(Clone)]
pub struct Supervisor { inner: Arc<Inner> }
struct Inner {
    runtime: RuntimeConfig, permits: Arc<Semaphore>, next: AtomicU64,
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "windows-installed-observation",
        target_os = "windows", target_arch = "x86_64", target_env = "msvc", not(feature = "development-runtime"),
        not(feature = "ubuntu-runtime-publisher"), not(feature = "windows-runtime-publisher"), not(feature = "macos-installed-installer")))]
    windows_ui: windows_shell_observation::Hooks,
    #[cfg(all(test, target_os = "windows", target_arch = "x86_64", target_env = "msvc", not(feature = "development-runtime"), not(feature = "desktop-shell"), not(feature = "ubuntu-runtime-publisher"), not(feature = "windows-runtime-publisher"), not(feature = "macos-installed-installer")))]
    windows_test: windows_passive_tests::Hooks,
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
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", target_os = "linux", target_arch = "x86_64", target_env = "gnu",
        not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher")))]
    first_unknown: Option<FirstUnknown>,
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
            driver_end: None, watchdog_end: None,
            #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", target_os = "linux", target_arch = "x86_64", target_env = "gnu",
                not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher")))]
            first_unknown: None,
        }
    }
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", target_os = "linux", target_arch = "x86_64", target_env = "gnu",
        not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher")))]
    fn record_first_unknown(&mut self, resources: Option<&Resources>, boundary: UnknownBoundary) {
        // Called under the SAME original state lock, before its Unknown
        // publication. Copy only the caller's guard; never acquire Resources.
        if !self.terminal && !self.unknown && self.first_unknown.is_none() {
            self.first_unknown = Some(FirstUnknown::capture(resources, boundary));
        }
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
        if self.cleanup_endpoint.is_some_and(|endpoint| now >= endpoint) {
            #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", target_os = "linux", target_arch = "x86_64", target_env = "gnu",
                not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher")))]
            self.record_first_unknown(None, UnknownBoundary::RetireClock);
            self.unknown = true;
        }
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
    #[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64"), all(target_os = "windows", target_arch = "x86_64", target_env = "msvc")))]
    fn capability(failure: PassiveAdmissionFailure) -> Self {
        let error = Self::unsupported("passive installed custody is unavailable");
        #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
        let error = error.with_cause(crate::error::LinuxPassiveCause::Capability(failure));
        #[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu")))]
        let _ = failure;
        error
    }
    #[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64"), all(target_os = "windows", target_arch = "x86_64", target_env = "msvc")))]
    fn preparation(failure: PassiveAdmissionFailure) -> Self {
        let error = Self::unsupported("passive installed preparation refused");
        #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
        let error = error.with_cause(crate::error::LinuxPassiveCause::Preparation(failure));
        #[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu")))]
        let _ = failure;
        error
    }
    #[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64"), all(target_os = "windows", target_arch = "x86_64", target_env = "msvc")))]
    fn final_claim(failure: PassiveAdmissionFailure) -> Self {
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
    native_observation: Option<JoinHandle<Result<Vec<installed_native_fixture::ChildObservation>, installed_native_fixture::ObservationFailure>>>,
    #[cfg(all(test, target_os = "linux", target_arch = "x86_64", target_env = "gnu",
        not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher")))]
    native_observation_return: Option<ManagementJoin>,
    #[cfg(all(test, target_os = "linux", target_arch = "x86_64", target_env = "gnu",
        not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher")))]
    native_observation_failure: Option<installed_native_fixture::ObservationFailure>,
    #[cfg(all(test, target_os = "linux", target_arch = "x86_64", target_env = "gnu",
        not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher")))]
    native_snapshots: Vec<installed_native_fixture::ChildObservation>,
    acquisition: Option<JoinHandle<Result<Child, AcquisitionError>>>, child: Option<Child>,
    acquisition_return: Option<ManagementJoin>, acquisition_error: Option<tokio::task::JoinError>,
    #[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64"), all(target_os = "windows", target_arch = "x86_64", target_env = "msvc")))]
    passive: Option<Arc<Mutex<PassiveRuntimeSlots>>>,
    #[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64"), all(target_os = "windows", target_arch = "x86_64", target_env = "msvc")))]
    native_settlement: Option<JoinHandle<CloseOutcome>>,
    #[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64"), all(target_os = "windows", target_arch = "x86_64", target_env = "msvc")))]
    native_return: Option<Result<CloseOutcome, tokio::task::JoinError>>,
    #[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64"), all(target_os = "windows", target_arch = "x86_64", target_env = "msvc")))]
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
        // Keep the original entry for direct fixtures/unannotated callers.
        #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", target_os = "linux", target_arch = "x86_64", target_env = "gnu",
            not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher")))]
        self.unknown_policy(inner, None, UnknownBoundary::Unspecified);
        #[cfg(not(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", target_os = "linux", target_arch = "x86_64", target_env = "gnu",
            not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"))))]
        self.unknown_policy(inner);
    }
    fn unknown_policy(&self, inner: &Inner,
        #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", target_os = "linux", target_arch = "x86_64", target_env = "gnu",
            not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher")))]
        resources: Option<&Resources>,
        #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", target_os = "linux", target_arch = "x86_64", target_env = "gnu",
            not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher")))]
        boundary: UnknownBoundary,
    ) {
        let mut state = lock(&self.state);
        if state.terminal { return; }
        #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", target_os = "linux", target_arch = "x86_64", target_env = "gnu",
            not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher")))]
        state.record_first_unknown(resources, boundary);
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
        if newly_unknown { owner_unknown!(self, inner, None, Clock); }
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
    fn drop(&mut self) { if !self.retired { owner_unknown!(self.owner, &self.inner, None, ObserverLoss); } }
}

/// The SAME passive admission's original reply observer. This neither owns a
/// second runner nor cancels/detaches original custody when a caller drops it.
/// It lets DocumentBinding linearize the existing admission with preflight.
pub(crate) struct PassiveQuery {
    inner: Arc<Inner>, owner: Arc<Owner>, receiver: oneshot::Receiver<Result<Value, BridgeError>>,
}
impl PassiveQuery {
    pub(crate) async fn wait(self) -> Result<Value, BridgeError> {
        self.receiver.await.unwrap_or_else(|_| { owner_unknown!(self.owner, &self.inner, None, ReplyLoss); Err(BridgeError::cleanup_unknown()) })
    }
}

impl Supervisor {
    pub fn new(mut runtime: RuntimeConfig) -> Self {
        runtime.claim_original_supervisor();
        Self { inner: Arc::new(Inner {
            runtime, permits: Arc::new(Semaphore::new(ACTIVE_LIMIT)), next: AtomicU64::new(1),
            #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "windows-installed-observation",
                target_os = "windows", target_arch = "x86_64", target_env = "msvc", not(feature = "development-runtime"),
                not(feature = "ubuntu-runtime-publisher"), not(feature = "windows-runtime-publisher"), not(feature = "macos-installed-installer")))]
            windows_ui: windows_shell_observation::Hooks::default(),
            #[cfg(all(test, target_os = "windows", target_arch = "x86_64", target_env = "msvc", not(feature = "development-runtime"), not(feature = "desktop-shell"), not(feature = "ubuntu-runtime-publisher"), not(feature = "windows-runtime-publisher"), not(feature = "macos-installed-installer")))]
            windows_test: windows_passive_tests::Hooks::default(),
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
                #[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64"), all(target_os = "windows", target_arch = "x86_64", target_env = "msvc")))]
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
            #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "windows-installed-observation",
                target_os = "windows", target_arch = "x86_64", target_env = "msvc", not(feature = "development-runtime"),
                not(feature = "ubuntu-runtime-publisher"), not(feature = "windows-runtime-publisher"), not(feature = "macos-installed-installer")))]
            windows_shell_observation::registered(&self.inner, &owner);
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
    if driver.is_none() || watchdog.is_none() { owner_unknown!(owner, &inner, None, Management); }
    loop {
        let changed = owner.changed.notified();
        let deadline = owner.advance_clock(&inner, Instant::now());
        let (driver_pending, watchdog_pending, ready) = {
            let state = lock(&owner.state);
            (state.driver_join == ManagementJoin::Pending, state.watchdog_join == ManagementJoin::Pending, state.management_ready())
        };
        if ready && owner.retire(&inner) { return; }
        if !driver_pending && !watchdog_pending {
            owner_unknown!(owner, &inner, None, Management);
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
                        owner_unknown!(owner, &inner, None, Management); // Keep the consumed failed handle, never await it again.
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
                        if accepted { watchdog.take(); } else { owner_unknown!(owner, &inner, None, Management); }
                    }
                    Err(error) => {
                        lock(&owner.state).watchdog_join = ManagementJoin::error(&error);
                        owner_unknown!(owner, &inner, None, Management);
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
    cfg!(all(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64"), all(target_os = "windows", target_arch = "x86_64", target_env = "msvc")), not(all(feature = "development-runtime", debug_assertions))))
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

#[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64"), all(target_os = "windows", target_arch = "x86_64", target_env = "msvc")))]
fn passive_borrows(resources: &Resources) -> (OriginalBorrow, OriginalBorrow) {
    (OriginalBorrow { returned: resources.inspection_return, handle: resources.inspection.is_some(), error: resources.inspection_error.is_some() },
     OriginalBorrow { returned: resources.acquisition_return, handle: resources.acquisition.is_some(), error: resources.acquisition_error.is_some() })
}

#[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64"), all(target_os = "windows", target_arch = "x86_64", target_env = "msvc")))]
fn passive_worker_lost(resources: &Resources) {
    // Only called AFTER this original inspection/acquisition/settlement worker
    // returned JoinError. Never race a pending borrower because a clock expired.
    if let Some(native) = &resources.passive {
        match native.lock() { Ok(mut slots) => slots.mark_interrupted(), Err(error) => error.into_inner().mark_interrupted() }
    }
}

#[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64"), all(target_os = "windows", target_arch = "x86_64", target_env = "msvc")))]
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

#[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64"), all(target_os = "windows", target_arch = "x86_64", target_env = "msvc")))]
struct PreparedPassiveSpawn<'a> {
    runtime: &'a mut PassiveInstalledRuntime,
    #[cfg(all(not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), any(test, feature = "desktop-shell")))]
    command: Command,
}

#[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64"), all(target_os = "windows", target_arch = "x86_64", target_env = "msvc")))]
impl<'a> PreparedPassiveSpawn<'a> {
    fn prepare(runtime: &'a mut PassiveInstalledRuntime, end: Instant, stop: &watch::Receiver<bool>, _inner: &Inner) -> Result<Self, AcquisitionError> {
        let selected = runtime.prepare_once(end, stop)
            .map_err(AcquisitionError::preparation)?;
        // All native checks and fixed argument/environment allocations precede
        // the serialized final owner claim. No pathname/Command-taking adapter.
        #[cfg(all(not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), any(test, feature = "desktop-shell")))]
        let command = {
            let mut command = Command::new(&selected.python);
            command.args(["-I", "-S", "-B"]);
            #[cfg(all(test, target_os = "windows", target_arch = "x86_64", target_env = "msvc", not(feature = "development-runtime"), not(feature = "desktop-shell"), not(feature = "ubuntu-runtime-publisher"), not(feature = "windows-runtime-publisher"), not(feature = "macos-installed-installer")))]
            windows_passive_tests::fixed_arguments(&mut command, selected, _inner)?;
            #[cfg(not(all(test, target_os = "windows", target_arch = "x86_64", target_env = "msvc", not(feature = "development-runtime"), not(feature = "desktop-shell"), not(feature = "ubuntu-runtime-publisher"), not(feature = "windows-runtime-publisher"), not(feature = "macos-installed-installer"))))]
            command.arg(&selected.bootstrap).arg(&selected.core);
            command.current_dir(&selected.cwd).env_clear().env("LC_ALL", "C").env("LANG", "C")
                .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).kill_on_drop(false);
            #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
            crate::runtime::macos_installed_environment(&mut command)?;
            #[cfg(all(target_os = "windows", target_arch = "x86_64", target_env = "msvc"))]
            command.env("SystemRoot", runtime.system_root().map_err(|_| std::io::Error::new(
                std::io::ErrorKind::Unsupported, "native Windows root custody unavailable"))?);
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

#[cfg(all(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64"), all(target_os = "windows", target_arch = "x86_64", target_env = "msvc")),
    not(all(not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), any(test, feature = "desktop-shell")))))]
fn spawn_passive_original(prepared: PreparedPassiveSpawn<'_>) -> Result<Child, AcquisitionError> {
    // Unsupported profiles remain unconditional. Only this no-effect stub has
    // a receipt; it is absent from the fixed installed-shell/native profile.
    prepared.runtime.record_closed_spawn_gate();
    Err(AcquisitionError::unsupported("packaged runtime execution is not qualified"))
}

#[cfg(all(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64"), all(target_os = "windows", target_arch = "x86_64", target_env = "msvc")),
    not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), any(test, feature = "desktop-shell")))]
fn spawn_passive_original(mut prepared: PreparedPassiveSpawn<'_>) -> Result<Child, AcquisitionError> {
    // Opaque creation errors provide NO no-child/pipe-close proof. The claimed
    // original stays registered; the existing owner therefore retains Unknown.
    prepared.command.spawn().map_err(AcquisitionError::returned_spawn)
}

#[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64"), all(target_os = "windows", target_arch = "x86_64", target_env = "msvc")))]
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
    let prepared = PreparedPassiveSpawn::prepare(runtime, owner.endpoint(), &stop, inner)?;
    #[cfg(all(test, target_os = "windows", target_arch = "x86_64", target_env = "msvc", not(feature = "development-runtime"), not(feature = "desktop-shell"), not(feature = "ubuntu-runtime-publisher"), not(feature = "windows-runtime-publisher"), not(feature = "macos-installed-installer")))]
    windows_passive_tests::before_claim(inner, owner);
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
    #[cfg(not(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64"), all(target_os = "windows", target_arch = "x86_64", target_env = "msvc"))))]
    { let _ = (resources, inner, owner); true }
    #[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64"), all(target_os = "windows", target_arch = "x86_64", target_env = "msvc")))]
    {
        #[cfg(all(target_os = "linux", test, not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher")))]
        if resources.native_observation.is_some() { owner_unknown!(owner, inner, Some(&*resources), Settlement); return false; }
        let Some(native) = resources.passive.clone() else {
            if passive_selected(owner.profile) { owner_unknown!(owner, inner, Some(&*resources), Settlement); return false; }
            return true; // Explicitly unselected domain/profile, never a missing required book.
        };
        let (inspection, acquisition) = passive_borrows(resources);
        if !inspection.returned() || !acquisition.returned() { owner_unknown!(owner, inner, Some(&*resources), Settlement); return false; }
        if !resources.native_started {
            let no_child = {
                let slots = match native.try_lock() { Ok(slots) => slots, Err(_) => { owner_unknown!(owner, inner, Some(&*resources), Settlement); return false; } };
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
            if !consumers_returned { owner_unknown!(owner, inner, Some(&*resources), Settlement); return false; }
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
        if !positive { owner_unknown!(owner, inner, Some(&*resources), Settlement); }
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
    #[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64"), all(target_os = "windows", target_arch = "x86_64", target_env = "msvc")))]
    let inspection_native = resources.passive.clone();
    #[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64"), all(target_os = "windows", target_arch = "x86_64", target_env = "msvc")))]
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
                #[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64"), all(target_os = "windows", target_arch = "x86_64", target_env = "msvc")))]
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
            #[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64"), all(target_os = "windows", target_arch = "x86_64", target_env = "msvc")))]
            passive_worker_lost(&resources);
            owner_unknown!(owner, &inner, Some(&resources), Inspection);
            let _ = settle_passive(&mut resources, &inner, &owner).await;
            return DriverEnd::RetainedUnknown;
        }
    };
    if owner.failed() || Instant::now() >= owner.endpoint() {
        owner.fail(BridgeError::timeout());
        return ready_after_custody(&mut resources, &inner, &owner, Err(BridgeError::timeout())).await;
    }
    #[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64"), all(target_os = "windows", target_arch = "x86_64", target_env = "msvc")))]
    if let Err(error) = transfer_passive(&resources, &inner, &owner) {
        if error.code == "cleanup_unknown" { owner_unknown!(owner, &inner, Some(&resources), Transfer); }
        owner.fail(error.clone());
        return ready_after_custody(&mut resources, &inner, &owner, Err(error)).await;
    }
    // Blocking startup cannot starve the independent deadline watchdog. Its
    // original result/Child remains in this retained acquisition handle.
    let acquiring_owner = owner.clone();
    #[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64"), all(target_os = "windows", target_arch = "x86_64", target_env = "msvc")))]
    let acquiring_inner = inner.clone();
    #[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64"), all(target_os = "windows", target_arch = "x86_64", target_env = "msvc")))]
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
        #[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64"), all(target_os = "windows", target_arch = "x86_64", target_env = "msvc")))]
        if passive_selected(acquiring_owner.profile) {
            let Some(native) = acquisition_native else {
                owner_unknown!(acquiring_owner, &acquiring_inner, None, Acquisition);
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
            #[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64"), all(target_os = "windows", target_arch = "x86_64", target_env = "msvc")))]
            passive_worker_lost(&resources);
            owner_unknown!(owner, &inner, Some(&resources), Acquisition);
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
            resources.native_observation_failure = Some(installed_native_fixture::ObservationFailure::ChildId);
            owner_unknown!(owner, &inner, Some(&resources), NativeObserve); return DriverEnd::RetainedUnknown;
        };
        let observing_inner = inner.clone();
        let observing_key = owner.key;
        let observing_stop = owner.stop.subscribe();
        // Same joined acquisition and retained Child. A failed nonblocking
        // projection leaves only generic diagnostics, never a new authority.
        let observing_payload_history = resources.passive.as_ref().and_then(|native|
            native.try_lock().ok().and_then(|slots| slots.historical_payload_snapshot()));
        let (release, enter) = oneshot::channel();
        resources.native_observation_return = Some(ManagementJoin::Pending);
        resources.native_observation = Some(tokio::task::spawn_blocking(move || {
            enter.blocking_recv().map_err(|_| installed_native_fixture::ObservationFailure::Entry)?;
            installed_native_fixture::observe_original_child(id, observing_key, endpoint, observing_stop, &observing_inner, observed_case, observing_payload_history)
        }));
        let _ = release.send(());
        let result = join_slot(&mut resources.native_observation).await;
        resources.native_observation_return = Some(match &result {
            Ok(_) => ManagementJoin::Returned, Err(error) => ManagementJoin::error(error),
        });
        match result {
            Ok(Ok(snapshots)) => { resources.native_observation.take(); resources.native_snapshots = snapshots; },
            Ok(Err(failure)) => {
                // Preserve only the formerly erased returned refusal, under
                // this SAME already-held resource guard. Original handle,
                // Unknown policy and subsequent settlement gates are unchanged.
                resources.native_observation_failure = Some(failure);
                owner_unknown!(owner, &inner, Some(&resources), NativeObserve); return DriverEnd::RetainedUnknown;
            },
            Err(_) => { owner_unknown!(owner, &inner, Some(&resources), NativeObserve); return DriverEnd::RetainedUnknown; },
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
            owner_unknown!(owner, &inner, Some(&resources), DevObserve); return DriverEnd::RetainedUnknown;
        };
        resources.github_environment = Some(tokio::task::spawn_blocking(move || hosted_tests::original_child_environment(id)));
        match join_slot(&mut resources.github_environment).await {
            Ok(Ok(value)) => {
                lock(&owner.observation).github_initial_environment = value;
                resources.github_environment.take();
            },
            _ => { owner_unknown!(owner, &inner, Some(&resources), DevObserve); return DriverEnd::RetainedUnknown; },
        }
    }
    let (stdin, stdout, stderr) = match resources.child.as_mut() {
        Some(child) => (child.stdin.take(), child.stdout.take(), child.stderr.take()),
        None => { owner_unknown!(owner, &inner, Some(&resources), ChildMissing); return DriverEnd::RetainedUnknown; }
    };
    let (faults, mut fault_rx) = mpsc::channel(4);
    if let Some(stdin) = stdin {
        #[cfg(all(test, target_os = "windows", target_arch = "x86_64", target_env = "msvc", not(feature = "development-runtime"), not(feature = "desktop-shell"), not(feature = "ubuntu-runtime-publisher"), not(feature = "windows-runtime-publisher"), not(feature = "macos-installed-installer")))]
        { resources.writer = Some(tokio::spawn(windows_passive_tests::write_request(stdin, bytes, owner.stop.subscribe(), faults.clone(), inner.windows_test.hold_writer()))); }
        #[cfg(not(all(test, target_os = "windows", target_arch = "x86_64", target_env = "msvc", not(feature = "development-runtime"), not(feature = "desktop-shell"), not(feature = "ubuntu-runtime-publisher"), not(feature = "windows-runtime-publisher"), not(feature = "macos-installed-installer"))))]
        {
            #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "windows-installed-observation",
                target_os = "windows", target_arch = "x86_64", target_env = "msvc", not(feature = "development-runtime"),
                not(feature = "ubuntu-runtime-publisher"), not(feature = "windows-runtime-publisher"), not(feature = "macos-installed-installer")))]
            { resources.writer = Some(tokio::spawn(windows_shell_observation::write_request(stdin, bytes, owner.stop.subscribe(), faults.clone(), windows_shell_observation::writer_hold(&inner, &owner)))); }
            #[cfg(not(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "windows-installed-observation",
                target_os = "windows", target_arch = "x86_64", target_env = "msvc", not(feature = "development-runtime"),
                not(feature = "ubuntu-runtime-publisher"), not(feature = "windows-runtime-publisher"), not(feature = "macos-installed-installer"))))]
            { resources.writer = Some(tokio::spawn(write_request(stdin, bytes, owner.stop.subscribe(), faults.clone()))); }
        }
    }
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
    #[cfg(all(test, target_os = "windows", target_arch = "x86_64", target_env = "msvc", not(feature = "development-runtime"), not(feature = "desktop-shell"), not(feature = "ubuntu-runtime-publisher"), not(feature = "windows-runtime-publisher"), not(feature = "macos-installed-installer")))]
    windows_passive_tests::after_io_registered(&inner, &owner, &mut resources);
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "windows-installed-observation",
        target_os = "windows", target_arch = "x86_64", target_env = "msvc", not(feature = "development-runtime"),
        not(feature = "ubuntu-runtime-publisher"), not(feature = "windows-runtime-publisher"), not(feature = "macos-installed-installer")))]
    windows_shell_observation::after_io_registered(&inner, &owner, &mut resources);
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
            let child = match resources.child.as_mut() { Some(child) => child, None => { owner_unknown!(owner, &inner, Some(&resources), ChildMissing); return DriverEnd::RetainedUnknown; } };
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
                Err(_) => { owner_unknown!(owner, &inner, Some(&resources), ChildWait); return DriverEnd::RetainedUnknown; }
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
            Event::Wait(Err(_)) => { owner_unknown!(owner, &inner, Some(&resources), ChildWait); return DriverEnd::RetainedUnknown; }
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
        owner_unknown!(owner, &inner, Some(&resources), Io); return DriverEnd::RetainedUnknown;
    }
    let eofs = resources.out_end.as_ref().is_some_and(|end| end.eof) && resources.err_end.as_ref().is_some_and(|end| end.eof);
    if !eofs { owner_unknown!(owner, &inner, Some(&resources), Io); return DriverEnd::RetainedUnknown; }
    if !resources.write_end.is_some_and(|end| end.complete) {
        owner.fail(BridgeError::new("io_error", "The original request writer did not complete."));
    }
    // Original child wait and IO/EOF evidence are still in Resources here.
    // Keep custody through them, then join its one explicit native settlement.
    if !settle_passive(&mut resources, &inner, &owner).await { return DriverEnd::RetainedUnknown; }
    #[cfg(all(test, target_os = "windows", target_arch = "x86_64", target_env = "msvc", not(feature = "development-runtime"), not(feature = "desktop-shell"), not(feature = "ubuntu-runtime-publisher"), not(feature = "windows-runtime-publisher"), not(feature = "macos-installed-installer")))]
    windows_passive_tests::observe_settled_io(&inner, &resources);
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "windows-installed-observation",
        target_os = "windows", target_arch = "x86_64", target_env = "msvc", not(feature = "development-runtime"),
        not(feature = "ubuntu-runtime-publisher"), not(feature = "windows-runtime-publisher"), not(feature = "macos-installed-installer")))]
    windows_shell_observation::settled_io(&inner, &owner, &resources);
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
    use crate::installed_runtime::{HistoricalPayloadRelation, HistoricalPayloadRole, HistoricalPayloadSnapshot};
    use std::{fs, io::{Read, Write}, os::unix::fs::{MetadataExt, OpenOptionsExt}, path::{Path, PathBuf}};
    use rustix::process::{getrlimit, setrlimit, Resource, Rlimit};

    const VERSION: &str = "/var/lib/mobile-release-kit/versions/x86_64-unknown-linux-gnu/556b2ea59b4b3e9abb9d04a3d263e0fd420e8c44b3f71c478b1f71bdd21ec417";
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
            if !returned || !checked { owner_unknown!(self.owner, self.inner, None, RestoreLimit); }
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
    // Frozen public ELF spellings: diagnostic-only, never an acceptance list.
    // Compiler inventory SHA-256: 1f859cd512392dbd471081f5f1a7dc2d94aef7eba75698a62e2335542df52fcb
    // Runtime manifest SHA-256: e3375ff140d69df54b2445f756711e0245d397ba6ded76e8559732ec2e4e3801
    // Roster SHA-256: 5cc99227e6786b5831e84007659260cbe4c0bbba5e286a87e2b40f68deccbc37
    // Canonical token<TAB>path<LF> SHA-256: bf18de45262438226bbc80a1cc8a3c078821b4a1dc88ec16a00961c05c990710
    // An ID denotes only this refused spelling, not object identity, safety or cause.
    static PUBLIC_MAP_PATH_CANDIDATES: [(&str, &[u8]); 648] = [
        ("/bin/sh", b"map-x-aa"),
        ("/usr/bin/Xvfb", b"map-x-ab"),
        ("/usr/bin/awk", b"map-x-ac"),
        ("/usr/bin/bwrap", b"map-x-ad"),
        ("/usr/bin/cat", b"map-x-ae"),
        ("/usr/bin/dash", b"map-x-af"),
        ("/usr/bin/dbus-daemon", b"map-x-ag"),
        ("/usr/bin/dbus-run-session", b"map-x-ah"),
        ("/usr/bin/fmt", b"map-x-ai"),
        ("/usr/bin/gawk", b"map-x-aj"),
        ("/usr/bin/getopt", b"map-x-ak"),
        ("/usr/bin/mcookie", b"map-x-al"),
        ("/usr/bin/mktemp", b"map-x-am"),
        ("/usr/bin/prlimit", b"map-x-an"),
        ("/usr/bin/rm", b"map-x-ao"),
        ("/usr/bin/stty", b"map-x-ap"),
        ("/usr/bin/touch", b"map-x-aq"),
        ("/usr/bin/xauth", b"map-x-ar"),
        ("/usr/bin/xdg-dbus-proxy", b"map-x-as"),
        ("/usr/bin/xdotool", b"map-x-at"),
        ("/usr/bin/xkbcomp", b"map-x-au"),
        ("/usr/lib/x86_64-linux-gnu/dri/apple_dri.so", b"map-x-av"),
        ("/usr/lib/x86_64-linux-gnu/dri/armada-drm_dri.so", b"map-x-aw"),
        ("/usr/lib/x86_64-linux-gnu/dri/asahi_dri.so", b"map-x-ax"),
        ("/usr/lib/x86_64-linux-gnu/dri/crocus_dri.so", b"map-x-ay"),
        ("/usr/lib/x86_64-linux-gnu/dri/d3d12_dri.so", b"map-x-az"),
        ("/usr/lib/x86_64-linux-gnu/dri/exynos_dri.so", b"map-x-ba"),
        ("/usr/lib/x86_64-linux-gnu/dri/gm12u320_dri.so", b"map-x-bb"),
        ("/usr/lib/x86_64-linux-gnu/dri/hdlcd_dri.so", b"map-x-bc"),
        ("/usr/lib/x86_64-linux-gnu/dri/hx8357d_dri.so", b"map-x-bd"),
        ("/usr/lib/x86_64-linux-gnu/dri/i915_dri.so", b"map-x-be"),
        ("/usr/lib/x86_64-linux-gnu/dri/ili9163_dri.so", b"map-x-bf"),
        ("/usr/lib/x86_64-linux-gnu/dri/ili9225_dri.so", b"map-x-bg"),
        ("/usr/lib/x86_64-linux-gnu/dri/ili9341_dri.so", b"map-x-bh"),
        ("/usr/lib/x86_64-linux-gnu/dri/ili9486_dri.so", b"map-x-bi"),
        ("/usr/lib/x86_64-linux-gnu/dri/imx-dcss_dri.so", b"map-x-bj"),
        ("/usr/lib/x86_64-linux-gnu/dri/imx-drm_dri.so", b"map-x-bk"),
        ("/usr/lib/x86_64-linux-gnu/dri/imx-lcdif_dri.so", b"map-x-bl"),
        ("/usr/lib/x86_64-linux-gnu/dri/ingenic-drm_dri.so", b"map-x-bm"),
        ("/usr/lib/x86_64-linux-gnu/dri/iris_dri.so", b"map-x-bn"),
        ("/usr/lib/x86_64-linux-gnu/dri/kirin_dri.so", b"map-x-bo"),
        ("/usr/lib/x86_64-linux-gnu/dri/kms_swrast_dri.so", b"map-x-bp"),
        ("/usr/lib/x86_64-linux-gnu/dri/komeda_dri.so", b"map-x-bq"),
        ("/usr/lib/x86_64-linux-gnu/dri/libdril_dri.so", b"map-x-br"),
        ("/usr/lib/x86_64-linux-gnu/dri/mali-dp_dri.so", b"map-x-bs"),
        ("/usr/lib/x86_64-linux-gnu/dri/mcde_dri.so", b"map-x-bt"),
        ("/usr/lib/x86_64-linux-gnu/dri/mediatek_dri.so", b"map-x-bu"),
        ("/usr/lib/x86_64-linux-gnu/dri/meson_dri.so", b"map-x-bv"),
        ("/usr/lib/x86_64-linux-gnu/dri/mi0283qt_dri.so", b"map-x-bw"),
        ("/usr/lib/x86_64-linux-gnu/dri/mxsfb-drm_dri.so", b"map-x-bx"),
        ("/usr/lib/x86_64-linux-gnu/dri/nouveau_dri.so", b"map-x-by"),
        ("/usr/lib/x86_64-linux-gnu/dri/panel-mipi-dbi_dri.so", b"map-x-bz"),
        ("/usr/lib/x86_64-linux-gnu/dri/pl111_dri.so", b"map-x-ca"),
        ("/usr/lib/x86_64-linux-gnu/dri/r300_dri.so", b"map-x-cb"),
        ("/usr/lib/x86_64-linux-gnu/dri/r600_dri.so", b"map-x-cc"),
        ("/usr/lib/x86_64-linux-gnu/dri/radeonsi_dri.so", b"map-x-cd"),
        ("/usr/lib/x86_64-linux-gnu/dri/rcar-du_dri.so", b"map-x-ce"),
        ("/usr/lib/x86_64-linux-gnu/dri/repaper_dri.so", b"map-x-cf"),
        ("/usr/lib/x86_64-linux-gnu/dri/rockchip_dri.so", b"map-x-cg"),
        ("/usr/lib/x86_64-linux-gnu/dri/rzg2l-du_dri.so", b"map-x-ch"),
        ("/usr/lib/x86_64-linux-gnu/dri/ssd130x_dri.so", b"map-x-ci"),
        ("/usr/lib/x86_64-linux-gnu/dri/st7586_dri.so", b"map-x-cj"),
        ("/usr/lib/x86_64-linux-gnu/dri/st7735r_dri.so", b"map-x-ck"),
        ("/usr/lib/x86_64-linux-gnu/dri/sti_dri.so", b"map-x-cl"),
        ("/usr/lib/x86_64-linux-gnu/dri/stm_dri.so", b"map-x-cm"),
        ("/usr/lib/x86_64-linux-gnu/dri/sun4i-drm_dri.so", b"map-x-cn"),
        ("/usr/lib/x86_64-linux-gnu/dri/swrast_dri.so", b"map-x-co"),
        ("/usr/lib/x86_64-linux-gnu/dri/udl_dri.so", b"map-x-cp"),
        ("/usr/lib/x86_64-linux-gnu/dri/virtio_gpu_dri.so", b"map-x-cq"),
        ("/usr/lib/x86_64-linux-gnu/dri/vkms_dri.so", b"map-x-cr"),
        ("/usr/lib/x86_64-linux-gnu/dri/vmwgfx_dri.so", b"map-x-cs"),
        ("/usr/lib/x86_64-linux-gnu/dri/zink_dri.so", b"map-x-ct"),
        ("/usr/lib/x86_64-linux-gnu/dri/zynqmp-dpsub_dri.so", b"map-x-cu"),
        ("/usr/lib/x86_64-linux-gnu/enchant-2/enchant_aspell.so", b"map-x-cv"),
        ("/usr/lib/x86_64-linux-gnu/enchant-2/enchant_hspell.so", b"map-x-cw"),
        ("/usr/lib/x86_64-linux-gnu/enchant-2/enchant_hunspell.so", b"map-x-cx"),
        ("/usr/lib/x86_64-linux-gnu/gbm/dri_gbm.so", b"map-x-cy"),
        ("/usr/lib/x86_64-linux-gnu/gdk-pixbuf-2.0/2.10.0/loaders/libpixbufloader-ani.so", b"map-x-cz"),
        ("/usr/lib/x86_64-linux-gnu/gdk-pixbuf-2.0/2.10.0/loaders/libpixbufloader-bmp.so", b"map-x-da"),
        ("/usr/lib/x86_64-linux-gnu/gdk-pixbuf-2.0/2.10.0/loaders/libpixbufloader-gif.so", b"map-x-db"),
        ("/usr/lib/x86_64-linux-gnu/gdk-pixbuf-2.0/2.10.0/loaders/libpixbufloader-icns.so", b"map-x-dc"),
        ("/usr/lib/x86_64-linux-gnu/gdk-pixbuf-2.0/2.10.0/loaders/libpixbufloader-ico.so", b"map-x-dd"),
        ("/usr/lib/x86_64-linux-gnu/gdk-pixbuf-2.0/2.10.0/loaders/libpixbufloader-pnm.so", b"map-x-de"),
        ("/usr/lib/x86_64-linux-gnu/gdk-pixbuf-2.0/2.10.0/loaders/libpixbufloader-qtif.so", b"map-x-df"),
        ("/usr/lib/x86_64-linux-gnu/gdk-pixbuf-2.0/2.10.0/loaders/libpixbufloader-svg.so", b"map-x-dg"),
        ("/usr/lib/x86_64-linux-gnu/gdk-pixbuf-2.0/2.10.0/loaders/libpixbufloader-tga.so", b"map-x-dh"),
        ("/usr/lib/x86_64-linux-gnu/gdk-pixbuf-2.0/2.10.0/loaders/libpixbufloader-tiff.so", b"map-x-di"),
        ("/usr/lib/x86_64-linux-gnu/gdk-pixbuf-2.0/2.10.0/loaders/libpixbufloader-xbm.so", b"map-x-dj"),
        ("/usr/lib/x86_64-linux-gnu/gdk-pixbuf-2.0/2.10.0/loaders/libpixbufloader-xpm.so", b"map-x-dk"),
        ("/usr/lib/x86_64-linux-gnu/gio/modules/libdconfsettings.so", b"map-x-dl"),
        ("/usr/lib/x86_64-linux-gnu/gio/modules/libgiognomeproxy.so", b"map-x-dm"),
        ("/usr/lib/x86_64-linux-gnu/gio/modules/libgiognutls.so", b"map-x-dn"),
        ("/usr/lib/x86_64-linux-gnu/gio/modules/libgiolibproxy.so", b"map-x-do"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgst1394.so", b"map-x-dp"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstaasink.so", b"map-x-dq"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstadaptivedemux2.so", b"map-x-dr"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstadder.so", b"map-x-ds"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstalaw.so", b"map-x-dt"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstalpha.so", b"map-x-du"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstalphacolor.so", b"map-x-dv"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstapetag.so", b"map-x-dw"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstapp.so", b"map-x-dx"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstaudioconvert.so", b"map-x-dy"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstaudiofx.so", b"map-x-dz"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstaudiomixer.so", b"map-x-ea"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstaudioparsers.so", b"map-x-eb"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstaudiorate.so", b"map-x-ec"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstaudioresample.so", b"map-x-ed"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstaudiotestsrc.so", b"map-x-ee"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstauparse.so", b"map-x-ef"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstautodetect.so", b"map-x-eg"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstavi.so", b"map-x-eh"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstbasedebug.so", b"map-x-ei"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstcacasink.so", b"map-x-ej"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstcairo.so", b"map-x-ek"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstcamerabin.so", b"map-x-el"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstcdparanoia.so", b"map-x-em"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstcompositor.so", b"map-x-en"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstcoreelements.so", b"map-x-eo"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstcoretracers.so", b"map-x-ep"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstcutter.so", b"map-x-eq"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstdebug.so", b"map-x-er"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstdeinterlace.so", b"map-x-es"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstdsd.so", b"map-x-et"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstdtmf.so", b"map-x-eu"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstdv.so", b"map-x-ev"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgsteffectv.so", b"map-x-ew"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstencoding.so", b"map-x-ex"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstequalizer.so", b"map-x-ey"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstflac.so", b"map-x-ez"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstflv.so", b"map-x-fa"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstflxdec.so", b"map-x-fb"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstgdkpixbuf.so", b"map-x-fc"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstgio.so", b"map-x-fd"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstgoom.so", b"map-x-fe"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstgoom2k1.so", b"map-x-ff"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgsticydemux.so", b"map-x-fg"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstid3demux.so", b"map-x-fh"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstimagefreeze.so", b"map-x-fi"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstinterleave.so", b"map-x-fj"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstisomp4.so", b"map-x-fk"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstjack.so", b"map-x-fl"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstjpeg.so", b"map-x-fm"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstjpegformat.so", b"map-x-fn"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstlame.so", b"map-x-fo"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstlevel.so", b"map-x-fp"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstlibvisual.so", b"map-x-fq"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstmatroska.so", b"map-x-fr"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstmonoscope.so", b"map-x-fs"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstmpg123.so", b"map-x-ft"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstmulaw.so", b"map-x-fu"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstmultifile.so", b"map-x-fv"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstmultipart.so", b"map-x-fw"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstnavigationtest.so", b"map-x-fx"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstogg.so", b"map-x-fy"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstopus.so", b"map-x-fz"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstoss4.so", b"map-x-ga"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstossaudio.so", b"map-x-gb"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstoverlaycomposition.so", b"map-x-gc"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstpbtypes.so", b"map-x-gd"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstplayback.so", b"map-x-ge"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstpng.so", b"map-x-gf"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstpulseaudio.so", b"map-x-gg"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstrawparse.so", b"map-x-gh"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstreplaygain.so", b"map-x-gi"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstrtp.so", b"map-x-gj"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstrtpmanager.so", b"map-x-gk"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstrtsp.so", b"map-x-gl"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstshapewipe.so", b"map-x-gm"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstshout2.so", b"map-x-gn"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstsmpte.so", b"map-x-go"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstsoup.so", b"map-x-gp"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstspectrum.so", b"map-x-gq"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstspeex.so", b"map-x-gr"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstsubparse.so", b"map-x-gs"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgsttaglib.so", b"map-x-gt"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgsttcp.so", b"map-x-gu"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgsttheora.so", b"map-x-gv"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgsttwolame.so", b"map-x-gw"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgsttypefindfunctions.so", b"map-x-gx"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstudp.so", b"map-x-gy"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstvideo4linux2.so", b"map-x-gz"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstvideobox.so", b"map-x-ha"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstvideoconvertscale.so", b"map-x-hb"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstvideocrop.so", b"map-x-hc"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstvideofilter.so", b"map-x-hd"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstvideomixer.so", b"map-x-he"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstvideorate.so", b"map-x-hf"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstvideotestsrc.so", b"map-x-hg"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstvolume.so", b"map-x-hh"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstvorbis.so", b"map-x-hi"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstvpx.so", b"map-x-hj"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstwavenc.so", b"map-x-hk"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstwavpack.so", b"map-x-hl"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstwavparse.so", b"map-x-hm"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstximagesrc.so", b"map-x-hn"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstxingmux.so", b"map-x-ho"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgsty4menc.so", b"map-x-hp"),
        ("/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-plugin-scanner", b"map-x-hq"),
        ("/usr/lib/x86_64-linux-gnu/gtk-3.0/3.0.0/immodules/im-am-et.so", b"map-x-hr"),
        ("/usr/lib/x86_64-linux-gnu/gtk-3.0/3.0.0/immodules/im-broadway.so", b"map-x-hs"),
        ("/usr/lib/x86_64-linux-gnu/gtk-3.0/3.0.0/immodules/im-cedilla.so", b"map-x-ht"),
        ("/usr/lib/x86_64-linux-gnu/gtk-3.0/3.0.0/immodules/im-cyrillic-translit.so", b"map-x-hu"),
        ("/usr/lib/x86_64-linux-gnu/gtk-3.0/3.0.0/immodules/im-inuktitut.so", b"map-x-hv"),
        ("/usr/lib/x86_64-linux-gnu/gtk-3.0/3.0.0/immodules/im-ipa.so", b"map-x-hw"),
        ("/usr/lib/x86_64-linux-gnu/gtk-3.0/3.0.0/immodules/im-multipress.so", b"map-x-hx"),
        ("/usr/lib/x86_64-linux-gnu/gtk-3.0/3.0.0/immodules/im-thai.so", b"map-x-hy"),
        ("/usr/lib/x86_64-linux-gnu/gtk-3.0/3.0.0/immodules/im-ti-er.so", b"map-x-hz"),
        ("/usr/lib/x86_64-linux-gnu/gtk-3.0/3.0.0/immodules/im-ti-et.so", b"map-x-ia"),
        ("/usr/lib/x86_64-linux-gnu/gtk-3.0/3.0.0/immodules/im-viqr.so", b"map-x-ib"),
        ("/usr/lib/x86_64-linux-gnu/gtk-3.0/3.0.0/immodules/im-wayland.so", b"map-x-ic"),
        ("/usr/lib/x86_64-linux-gnu/gtk-3.0/3.0.0/immodules/im-xim.so", b"map-x-id"),
        ("/usr/lib/x86_64-linux-gnu/libEGL.so.1", b"map-x-ie"),
        ("/usr/lib/x86_64-linux-gnu/libEGL.so.1.1.0", b"map-x-if"),
        ("/usr/lib/x86_64-linux-gnu/libEGL_mesa.so.0", b"map-x-ig"),
        ("/usr/lib/x86_64-linux-gnu/libEGL_mesa.so.0.0.0", b"map-x-ih"),
        ("/usr/lib/x86_64-linux-gnu/libFLAC.so.12", b"map-x-ii"),
        ("/usr/lib/x86_64-linux-gnu/libFLAC.so.12.1.0", b"map-x-ij"),
        ("/usr/lib/x86_64-linux-gnu/libGL.so.1", b"map-x-ik"),
        ("/usr/lib/x86_64-linux-gnu/libGL.so.1.7.0", b"map-x-il"),
        ("/usr/lib/x86_64-linux-gnu/libGLX.so.0", b"map-x-im"),
        ("/usr/lib/x86_64-linux-gnu/libGLX.so.0.0.0", b"map-x-in"),
        ("/usr/lib/x86_64-linux-gnu/libGLX_mesa.so.0", b"map-x-io"),
        ("/usr/lib/x86_64-linux-gnu/libGLX_mesa.so.0.0.0", b"map-x-ip"),
        ("/usr/lib/x86_64-linux-gnu/libGLdispatch.so.0", b"map-x-iq"),
        ("/usr/lib/x86_64-linux-gnu/libGLdispatch.so.0.0.0", b"map-x-ir"),
        ("/usr/lib/x86_64-linux-gnu/libLLVM.so.20.1", b"map-x-is"),
        ("/usr/lib/x86_64-linux-gnu/libLerc.so.4", b"map-x-it"),
        ("/usr/lib/x86_64-linux-gnu/libX11-xcb.so.1", b"map-x-iu"),
        ("/usr/lib/x86_64-linux-gnu/libX11-xcb.so.1.0.0", b"map-x-iv"),
        ("/usr/lib/x86_64-linux-gnu/libX11.so.6", b"map-x-iw"),
        ("/usr/lib/x86_64-linux-gnu/libX11.so.6.4.0", b"map-x-ix"),
        ("/usr/lib/x86_64-linux-gnu/libXau.so.6", b"map-x-iy"),
        ("/usr/lib/x86_64-linux-gnu/libXau.so.6.0.0", b"map-x-iz"),
        ("/usr/lib/x86_64-linux-gnu/libXcomposite.so.1", b"map-x-ja"),
        ("/usr/lib/x86_64-linux-gnu/libXcomposite.so.1.0.0", b"map-x-jb"),
        ("/usr/lib/x86_64-linux-gnu/libXcursor.so.1", b"map-x-jc"),
        ("/usr/lib/x86_64-linux-gnu/libXcursor.so.1.0.2", b"map-x-jd"),
        ("/usr/lib/x86_64-linux-gnu/libXdamage.so.1", b"map-x-je"),
        ("/usr/lib/x86_64-linux-gnu/libXdamage.so.1.1.0", b"map-x-jf"),
        ("/usr/lib/x86_64-linux-gnu/libXdmcp.so.6", b"map-x-jg"),
        ("/usr/lib/x86_64-linux-gnu/libXdmcp.so.6.0.0", b"map-x-jh"),
        ("/usr/lib/x86_64-linux-gnu/libXext.so.6", b"map-x-ji"),
        ("/usr/lib/x86_64-linux-gnu/libXext.so.6.4.0", b"map-x-jj"),
        ("/usr/lib/x86_64-linux-gnu/libXfixes.so.3", b"map-x-jk"),
        ("/usr/lib/x86_64-linux-gnu/libXfixes.so.3.1.0", b"map-x-jl"),
        ("/usr/lib/x86_64-linux-gnu/libXfont2.so.2", b"map-x-jm"),
        ("/usr/lib/x86_64-linux-gnu/libXfont2.so.2.0.0", b"map-x-jn"),
        ("/usr/lib/x86_64-linux-gnu/libXi.so.6", b"map-x-jo"),
        ("/usr/lib/x86_64-linux-gnu/libXi.so.6.1.0", b"map-x-jp"),
        ("/usr/lib/x86_64-linux-gnu/libXinerama.so.1", b"map-x-jq"),
        ("/usr/lib/x86_64-linux-gnu/libXinerama.so.1.0.0", b"map-x-jr"),
        ("/usr/lib/x86_64-linux-gnu/libXmuu.so.1", b"map-x-js"),
        ("/usr/lib/x86_64-linux-gnu/libXmuu.so.1.0.0", b"map-x-jt"),
        ("/usr/lib/x86_64-linux-gnu/libXrandr.so.2", b"map-x-ju"),
        ("/usr/lib/x86_64-linux-gnu/libXrandr.so.2.2.0", b"map-x-jv"),
        ("/usr/lib/x86_64-linux-gnu/libXrender.so.1", b"map-x-jw"),
        ("/usr/lib/x86_64-linux-gnu/libXrender.so.1.3.0", b"map-x-jx"),
        ("/usr/lib/x86_64-linux-gnu/libXtst.so.6", b"map-x-jy"),
        ("/usr/lib/x86_64-linux-gnu/libXtst.so.6.1.0", b"map-x-jz"),
        ("/usr/lib/x86_64-linux-gnu/libXxf86vm.so.1", b"map-x-ka"),
        ("/usr/lib/x86_64-linux-gnu/libXxf86vm.so.1.0.0", b"map-x-kb"),
        ("/usr/lib/x86_64-linux-gnu/libaa.so.1", b"map-x-kc"),
        ("/usr/lib/x86_64-linux-gnu/libaa.so.1.0.4", b"map-x-kd"),
        ("/usr/lib/x86_64-linux-gnu/libapparmor.so.1", b"map-x-ke"),
        ("/usr/lib/x86_64-linux-gnu/libapparmor.so.1.17.2", b"map-x-kf"),
        ("/usr/lib/x86_64-linux-gnu/libaspell.so.15", b"map-x-kg"),
        ("/usr/lib/x86_64-linux-gnu/libaspell.so.15.3.1", b"map-x-kh"),
        ("/usr/lib/x86_64-linux-gnu/libasyncns.so.0", b"map-x-ki"),
        ("/usr/lib/x86_64-linux-gnu/libasyncns.so.0.3.1", b"map-x-kj"),
        ("/usr/lib/x86_64-linux-gnu/libatk-1.0.so.0", b"map-x-kk"),
        ("/usr/lib/x86_64-linux-gnu/libatk-1.0.so.0.25209.1", b"map-x-kl"),
        ("/usr/lib/x86_64-linux-gnu/libatk-bridge-2.0.so.0", b"map-x-km"),
        ("/usr/lib/x86_64-linux-gnu/libatk-bridge-2.0.so.0.0.0", b"map-x-kn"),
        ("/usr/lib/x86_64-linux-gnu/libatomic.so.1", b"map-x-ko"),
        ("/usr/lib/x86_64-linux-gnu/libatomic.so.1.2.0", b"map-x-kp"),
        ("/usr/lib/x86_64-linux-gnu/libatspi.so.0", b"map-x-kq"),
        ("/usr/lib/x86_64-linux-gnu/libatspi.so.0.0.1", b"map-x-kr"),
        ("/usr/lib/x86_64-linux-gnu/libaudit.so.1", b"map-x-ks"),
        ("/usr/lib/x86_64-linux-gnu/libaudit.so.1.0.0", b"map-x-kt"),
        ("/usr/lib/x86_64-linux-gnu/libavc1394.so.0", b"map-x-ku"),
        ("/usr/lib/x86_64-linux-gnu/libavc1394.so.0.3.0", b"map-x-kv"),
        ("/usr/lib/x86_64-linux-gnu/libblkid.so.1", b"map-x-kw"),
        ("/usr/lib/x86_64-linux-gnu/libblkid.so.1.1.0", b"map-x-kx"),
        ("/usr/lib/x86_64-linux-gnu/libbrotlicommon.so.1", b"map-x-ky"),
        ("/usr/lib/x86_64-linux-gnu/libbrotlicommon.so.1.1.0", b"map-x-kz"),
        ("/usr/lib/x86_64-linux-gnu/libbrotlidec.so.1", b"map-x-la"),
        ("/usr/lib/x86_64-linux-gnu/libbrotlidec.so.1.1.0", b"map-x-lb"),
        ("/usr/lib/x86_64-linux-gnu/libbsd.so.0", b"map-x-lc"),
        ("/usr/lib/x86_64-linux-gnu/libbsd.so.0.12.1", b"map-x-ld"),
        ("/usr/lib/x86_64-linux-gnu/libbz2.so.1.0", b"map-x-le"),
        ("/usr/lib/x86_64-linux-gnu/libbz2.so.1.0.4", b"map-x-lf"),
        ("/usr/lib/x86_64-linux-gnu/libcaca.so.0", b"map-x-lg"),
        ("/usr/lib/x86_64-linux-gnu/libcaca.so.0.99.20", b"map-x-lh"),
        ("/usr/lib/x86_64-linux-gnu/libcairo-gobject.so.2", b"map-x-li"),
        ("/usr/lib/x86_64-linux-gnu/libcairo-gobject.so.2.11800.0", b"map-x-lj"),
        ("/usr/lib/x86_64-linux-gnu/libcairo.so.2", b"map-x-lk"),
        ("/usr/lib/x86_64-linux-gnu/libcairo.so.2.11800.0", b"map-x-ll"),
        ("/usr/lib/x86_64-linux-gnu/libcap-ng.so.0", b"map-x-lm"),
        ("/usr/lib/x86_64-linux-gnu/libcap-ng.so.0.0.0", b"map-x-ln"),
        ("/usr/lib/x86_64-linux-gnu/libcap.so.2", b"map-x-lo"),
        ("/usr/lib/x86_64-linux-gnu/libcap.so.2.66", b"map-x-lp"),
        ("/usr/lib/x86_64-linux-gnu/libcdda_interface.so.0", b"map-x-lq"),
        ("/usr/lib/x86_64-linux-gnu/libcdda_interface.so.0.10.2", b"map-x-lr"),
        ("/usr/lib/x86_64-linux-gnu/libcdda_paranoia.so.0", b"map-x-ls"),
        ("/usr/lib/x86_64-linux-gnu/libcdda_paranoia.so.0.10.2", b"map-x-lt"),
        ("/usr/lib/x86_64-linux-gnu/libcom_err.so.2", b"map-x-lu"),
        ("/usr/lib/x86_64-linux-gnu/libcom_err.so.2.1", b"map-x-lv"),
        ("/usr/lib/x86_64-linux-gnu/libcrypto.so.3", b"map-x-lw"),
        ("/usr/lib/x86_64-linux-gnu/libcurl-gnutls.so.4", b"map-x-lx"),
        ("/usr/lib/x86_64-linux-gnu/libcurl-gnutls.so.4.8.0", b"map-x-ly"),
        ("/usr/lib/x86_64-linux-gnu/libdatrie.so.1", b"map-x-lz"),
        ("/usr/lib/x86_64-linux-gnu/libdatrie.so.1.4.0", b"map-x-ma"),
        ("/usr/lib/x86_64-linux-gnu/libdbus-1.so.3", b"map-x-mb"),
        ("/usr/lib/x86_64-linux-gnu/libdbus-1.so.3.32.4", b"map-x-mc"),
        ("/usr/lib/x86_64-linux-gnu/libdeflate.so.0", b"map-x-md"),
        ("/usr/lib/x86_64-linux-gnu/libdl.so.2", b"map-x-me"),
        ("/usr/lib/x86_64-linux-gnu/libdrm.so.2", b"map-x-mf"),
        ("/usr/lib/x86_64-linux-gnu/libdrm.so.2.125.0", b"map-x-mg"),
        ("/usr/lib/x86_64-linux-gnu/libdrm_amdgpu.so.1", b"map-x-mh"),
        ("/usr/lib/x86_64-linux-gnu/libdrm_amdgpu.so.1.125.0", b"map-x-mi"),
        ("/usr/lib/x86_64-linux-gnu/libdrm_intel.so.1", b"map-x-mj"),
        ("/usr/lib/x86_64-linux-gnu/libdrm_intel.so.1.125.0", b"map-x-mk"),
        ("/usr/lib/x86_64-linux-gnu/libduktape.so.207", b"map-x-ml"),
        ("/usr/lib/x86_64-linux-gnu/libdv.so.4", b"map-x-mm"),
        ("/usr/lib/x86_64-linux-gnu/libdv.so.4.0.3", b"map-x-mn"),
        ("/usr/lib/x86_64-linux-gnu/libdw-0.190.so", b"map-x-mo"),
        ("/usr/lib/x86_64-linux-gnu/libdw.so.1", b"map-x-mp"),
        ("/usr/lib/x86_64-linux-gnu/libedit.so.2", b"map-x-mq"),
        ("/usr/lib/x86_64-linux-gnu/libedit.so.2.0.72", b"map-x-mr"),
        ("/usr/lib/x86_64-linux-gnu/libelf-0.190.so", b"map-x-ms"),
        ("/usr/lib/x86_64-linux-gnu/libelf.so.1", b"map-x-mt"),
        ("/usr/lib/x86_64-linux-gnu/libenchant-2.so.2", b"map-x-mu"),
        ("/usr/lib/x86_64-linux-gnu/libenchant-2.so.2.3.3", b"map-x-mv"),
        ("/usr/lib/x86_64-linux-gnu/libepoxy.so.0", b"map-x-mw"),
        ("/usr/lib/x86_64-linux-gnu/libepoxy.so.0.0.0", b"map-x-mx"),
        ("/usr/lib/x86_64-linux-gnu/libevdev.so.2", b"map-x-my"),
        ("/usr/lib/x86_64-linux-gnu/libevdev.so.2.3.0", b"map-x-mz"),
        ("/usr/lib/x86_64-linux-gnu/libexpat.so.1", b"map-x-na"),
        ("/usr/lib/x86_64-linux-gnu/libexpat.so.1.9.1", b"map-x-nb"),
        ("/usr/lib/x86_64-linux-gnu/libffi.so.8", b"map-x-nc"),
        ("/usr/lib/x86_64-linux-gnu/libffi.so.8.1.4", b"map-x-nd"),
        ("/usr/lib/x86_64-linux-gnu/libfontconfig.so.1", b"map-x-ne"),
        ("/usr/lib/x86_64-linux-gnu/libfontconfig.so.1.12.1", b"map-x-nf"),
        ("/usr/lib/x86_64-linux-gnu/libfontenc.so.1", b"map-x-ng"),
        ("/usr/lib/x86_64-linux-gnu/libfontenc.so.1.0.0", b"map-x-nh"),
        ("/usr/lib/x86_64-linux-gnu/libfreetype.so.6", b"map-x-ni"),
        ("/usr/lib/x86_64-linux-gnu/libfreetype.so.6.20.1", b"map-x-nj"),
        ("/usr/lib/x86_64-linux-gnu/libfribidi.so.0", b"map-x-nk"),
        ("/usr/lib/x86_64-linux-gnu/libfribidi.so.0.4.0", b"map-x-nl"),
        ("/usr/lib/x86_64-linux-gnu/libgallium-25.2.8-0ubuntu0.24.04.2.so", b"map-x-nm"),
        ("/usr/lib/x86_64-linux-gnu/libgbm.so.1", b"map-x-nn"),
        ("/usr/lib/x86_64-linux-gnu/libgbm.so.1.0.0", b"map-x-no"),
        ("/usr/lib/x86_64-linux-gnu/libgcc_s.so.1", b"map-x-np"),
        ("/usr/lib/x86_64-linux-gnu/libgcrypt.so.20", b"map-x-nq"),
        ("/usr/lib/x86_64-linux-gnu/libgcrypt.so.20.4.3", b"map-x-nr"),
        ("/usr/lib/x86_64-linux-gnu/libgdk-3.so.0", b"map-x-ns"),
        ("/usr/lib/x86_64-linux-gnu/libgdk-3.so.0.2409.32", b"map-x-nt"),
        ("/usr/lib/x86_64-linux-gnu/libgdk_pixbuf-2.0.so.0", b"map-x-nu"),
        ("/usr/lib/x86_64-linux-gnu/libgdk_pixbuf-2.0.so.0.4200.10", b"map-x-nv"),
        ("/usr/lib/x86_64-linux-gnu/libgio-2.0.so.0", b"map-x-nw"),
        ("/usr/lib/x86_64-linux-gnu/libgio-2.0.so.0.8000.0", b"map-x-nx"),
        ("/usr/lib/x86_64-linux-gnu/libglib-2.0.so.0", b"map-x-ny"),
        ("/usr/lib/x86_64-linux-gnu/libglib-2.0.so.0.8000.0", b"map-x-nz"),
        ("/usr/lib/x86_64-linux-gnu/libgmodule-2.0.so.0", b"map-x-oa"),
        ("/usr/lib/x86_64-linux-gnu/libgmodule-2.0.so.0.8000.0", b"map-x-ob"),
        ("/usr/lib/x86_64-linux-gnu/libgmp.so.10", b"map-x-oc"),
        ("/usr/lib/x86_64-linux-gnu/libgmp.so.10.5.0", b"map-x-od"),
        ("/usr/lib/x86_64-linux-gnu/libgnutls.so.30", b"map-x-oe"),
        ("/usr/lib/x86_64-linux-gnu/libgnutls.so.30.37.1", b"map-x-of"),
        ("/usr/lib/x86_64-linux-gnu/libgobject-2.0.so.0", b"map-x-og"),
        ("/usr/lib/x86_64-linux-gnu/libgobject-2.0.so.0.8000.0", b"map-x-oh"),
        ("/usr/lib/x86_64-linux-gnu/libgpg-error.so.0", b"map-x-oi"),
        ("/usr/lib/x86_64-linux-gnu/libgpg-error.so.0.34.0", b"map-x-oj"),
        ("/usr/lib/x86_64-linux-gnu/libgpm.so.2", b"map-x-ok"),
        ("/usr/lib/x86_64-linux-gnu/libgraphite2.so.3", b"map-x-ol"),
        ("/usr/lib/x86_64-linux-gnu/libgraphite2.so.3.2.1", b"map-x-om"),
        ("/usr/lib/x86_64-linux-gnu/libgssapi_krb5.so.2", b"map-x-on"),
        ("/usr/lib/x86_64-linux-gnu/libgssapi_krb5.so.2.2", b"map-x-oo"),
        ("/usr/lib/x86_64-linux-gnu/libgstallocators-1.0.so.0", b"map-x-op"),
        ("/usr/lib/x86_64-linux-gnu/libgstallocators-1.0.so.0.2402.0", b"map-x-oq"),
        ("/usr/lib/x86_64-linux-gnu/libgstapp-1.0.so.0", b"map-x-or"),
        ("/usr/lib/x86_64-linux-gnu/libgstapp-1.0.so.0.2402.0", b"map-x-os"),
        ("/usr/lib/x86_64-linux-gnu/libgstaudio-1.0.so.0", b"map-x-ot"),
        ("/usr/lib/x86_64-linux-gnu/libgstaudio-1.0.so.0.2402.0", b"map-x-ou"),
        ("/usr/lib/x86_64-linux-gnu/libgstbase-1.0.so.0", b"map-x-ov"),
        ("/usr/lib/x86_64-linux-gnu/libgstbase-1.0.so.0.2402.0", b"map-x-ow"),
        ("/usr/lib/x86_64-linux-gnu/libgstbasecamerabinsrc-1.0.so.0", b"map-x-ox"),
        ("/usr/lib/x86_64-linux-gnu/libgstbasecamerabinsrc-1.0.so.0.2402.0", b"map-x-oy"),
        ("/usr/lib/x86_64-linux-gnu/libgstfft-1.0.so.0", b"map-x-oz"),
        ("/usr/lib/x86_64-linux-gnu/libgstfft-1.0.so.0.2402.0", b"map-x-pa"),
        ("/usr/lib/x86_64-linux-gnu/libgstgl-1.0.so.0", b"map-x-pb"),
        ("/usr/lib/x86_64-linux-gnu/libgstgl-1.0.so.0.2402.0", b"map-x-pc"),
        ("/usr/lib/x86_64-linux-gnu/libgstnet-1.0.so.0", b"map-x-pd"),
        ("/usr/lib/x86_64-linux-gnu/libgstnet-1.0.so.0.2402.0", b"map-x-pe"),
        ("/usr/lib/x86_64-linux-gnu/libgstpbutils-1.0.so.0", b"map-x-pf"),
        ("/usr/lib/x86_64-linux-gnu/libgstpbutils-1.0.so.0.2402.0", b"map-x-pg"),
        ("/usr/lib/x86_64-linux-gnu/libgstphotography-1.0.so.0", b"map-x-ph"),
        ("/usr/lib/x86_64-linux-gnu/libgstphotography-1.0.so.0.2402.0", b"map-x-pi"),
        ("/usr/lib/x86_64-linux-gnu/libgstreamer-1.0.so.0", b"map-x-pj"),
        ("/usr/lib/x86_64-linux-gnu/libgstreamer-1.0.so.0.2402.0", b"map-x-pk"),
        ("/usr/lib/x86_64-linux-gnu/libgstriff-1.0.so.0", b"map-x-pl"),
        ("/usr/lib/x86_64-linux-gnu/libgstriff-1.0.so.0.2402.0", b"map-x-pm"),
        ("/usr/lib/x86_64-linux-gnu/libgstrtp-1.0.so.0", b"map-x-pn"),
        ("/usr/lib/x86_64-linux-gnu/libgstrtp-1.0.so.0.2402.0", b"map-x-po"),
        ("/usr/lib/x86_64-linux-gnu/libgstrtsp-1.0.so.0", b"map-x-pp"),
        ("/usr/lib/x86_64-linux-gnu/libgstrtsp-1.0.so.0.2402.0", b"map-x-pq"),
        ("/usr/lib/x86_64-linux-gnu/libgstsdp-1.0.so.0", b"map-x-pr"),
        ("/usr/lib/x86_64-linux-gnu/libgstsdp-1.0.so.0.2402.0", b"map-x-ps"),
        ("/usr/lib/x86_64-linux-gnu/libgsttag-1.0.so.0", b"map-x-pt"),
        ("/usr/lib/x86_64-linux-gnu/libgsttag-1.0.so.0.2402.0", b"map-x-pu"),
        ("/usr/lib/x86_64-linux-gnu/libgstvideo-1.0.so.0", b"map-x-pv"),
        ("/usr/lib/x86_64-linux-gnu/libgstvideo-1.0.so.0.2402.0", b"map-x-pw"),
        ("/usr/lib/x86_64-linux-gnu/libgtk-3.so.0", b"map-x-px"),
        ("/usr/lib/x86_64-linux-gnu/libgtk-3.so.0.2409.32", b"map-x-py"),
        ("/usr/lib/x86_64-linux-gnu/libgudev-1.0.so.0", b"map-x-pz"),
        ("/usr/lib/x86_64-linux-gnu/libgudev-1.0.so.0.3.0", b"map-x-qa"),
        ("/usr/lib/x86_64-linux-gnu/libharfbuzz-icu.so.0", b"map-x-qb"),
        ("/usr/lib/x86_64-linux-gnu/libharfbuzz-icu.so.0.60830.0", b"map-x-qc"),
        ("/usr/lib/x86_64-linux-gnu/libharfbuzz.so.0", b"map-x-qd"),
        ("/usr/lib/x86_64-linux-gnu/libharfbuzz.so.0.60830.0", b"map-x-qe"),
        ("/usr/lib/x86_64-linux-gnu/libhogweed.so.6", b"map-x-qf"),
        ("/usr/lib/x86_64-linux-gnu/libhogweed.so.6.8", b"map-x-qg"),
        ("/usr/lib/x86_64-linux-gnu/libhunspell-1.7.so.0", b"map-x-qh"),
        ("/usr/lib/x86_64-linux-gnu/libhunspell-1.7.so.0.0.1", b"map-x-qi"),
        ("/usr/lib/x86_64-linux-gnu/libhyphen.so.0", b"map-x-qj"),
        ("/usr/lib/x86_64-linux-gnu/libhyphen.so.0.3.0", b"map-x-qk"),
        ("/usr/lib/x86_64-linux-gnu/libicudata.so.74", b"map-x-ql"),
        ("/usr/lib/x86_64-linux-gnu/libicudata.so.74.2", b"map-x-qm"),
        ("/usr/lib/x86_64-linux-gnu/libicui18n.so.74", b"map-x-qn"),
        ("/usr/lib/x86_64-linux-gnu/libicui18n.so.74.2", b"map-x-qo"),
        ("/usr/lib/x86_64-linux-gnu/libicuuc.so.74", b"map-x-qp"),
        ("/usr/lib/x86_64-linux-gnu/libicuuc.so.74.2", b"map-x-qq"),
        ("/usr/lib/x86_64-linux-gnu/libidn2.so.0", b"map-x-qr"),
        ("/usr/lib/x86_64-linux-gnu/libidn2.so.0.4.0", b"map-x-qs"),
        ("/usr/lib/x86_64-linux-gnu/libiec61883.so.0", b"map-x-qt"),
        ("/usr/lib/x86_64-linux-gnu/libiec61883.so.0.1.1", b"map-x-qu"),
        ("/usr/lib/x86_64-linux-gnu/libjavascriptcoregtk-4.1.so.0", b"map-x-qv"),
        ("/usr/lib/x86_64-linux-gnu/libjavascriptcoregtk-4.1.so.0.10.14", b"map-x-qw"),
        ("/usr/lib/x86_64-linux-gnu/libjbig.so.0", b"map-x-qx"),
        ("/usr/lib/x86_64-linux-gnu/libjpeg.so.8", b"map-x-qy"),
        ("/usr/lib/x86_64-linux-gnu/libjpeg.so.8.2.2", b"map-x-qz"),
        ("/usr/lib/x86_64-linux-gnu/libk5crypto.so.3", b"map-x-ra"),
        ("/usr/lib/x86_64-linux-gnu/libk5crypto.so.3.1", b"map-x-rb"),
        ("/usr/lib/x86_64-linux-gnu/libkeyutils.so.1", b"map-x-rc"),
        ("/usr/lib/x86_64-linux-gnu/libkeyutils.so.1.10", b"map-x-rd"),
        ("/usr/lib/x86_64-linux-gnu/libkrb5.so.3", b"map-x-re"),
        ("/usr/lib/x86_64-linux-gnu/libkrb5.so.3.3", b"map-x-rf"),
        ("/usr/lib/x86_64-linux-gnu/libkrb5support.so.0", b"map-x-rg"),
        ("/usr/lib/x86_64-linux-gnu/libkrb5support.so.0.1", b"map-x-rh"),
        ("/usr/lib/x86_64-linux-gnu/liblber.so.2", b"map-x-ri"),
        ("/usr/lib/x86_64-linux-gnu/liblber.so.2.0.200", b"map-x-rj"),
        ("/usr/lib/x86_64-linux-gnu/liblcms2.so.2", b"map-x-rk"),
        ("/usr/lib/x86_64-linux-gnu/liblcms2.so.2.0.14", b"map-x-rl"),
        ("/usr/lib/x86_64-linux-gnu/libldap.so.2", b"map-x-rm"),
        ("/usr/lib/x86_64-linux-gnu/libldap.so.2.0.200", b"map-x-rn"),
        ("/usr/lib/x86_64-linux-gnu/liblz4.so.1", b"map-x-ro"),
        ("/usr/lib/x86_64-linux-gnu/liblz4.so.1.9.4", b"map-x-rp"),
        ("/usr/lib/x86_64-linux-gnu/liblzma.so.5", b"map-x-rq"),
        ("/usr/lib/x86_64-linux-gnu/liblzma.so.5.4.5", b"map-x-rr"),
        ("/usr/lib/x86_64-linux-gnu/libmanette-0.2.so.0", b"map-x-rs"),
        ("/usr/lib/x86_64-linux-gnu/libmd.so.0", b"map-x-rt"),
        ("/usr/lib/x86_64-linux-gnu/libmd.so.0.1.0", b"map-x-ru"),
        ("/usr/lib/x86_64-linux-gnu/libmount.so.1", b"map-x-rv"),
        ("/usr/lib/x86_64-linux-gnu/libmount.so.1.1.0", b"map-x-rw"),
        ("/usr/lib/x86_64-linux-gnu/libmp3lame.so.0", b"map-x-rx"),
        ("/usr/lib/x86_64-linux-gnu/libmp3lame.so.0.0.0", b"map-x-ry"),
        ("/usr/lib/x86_64-linux-gnu/libmpfr.so.6", b"map-x-rz"),
        ("/usr/lib/x86_64-linux-gnu/libmpfr.so.6.2.1", b"map-x-sa"),
        ("/usr/lib/x86_64-linux-gnu/libmpg123.so.0", b"map-x-sb"),
        ("/usr/lib/x86_64-linux-gnu/libmpg123.so.0.48.2", b"map-x-sc"),
        ("/usr/lib/x86_64-linux-gnu/libmvec.so.1", b"map-x-sd"),
        ("/usr/lib/x86_64-linux-gnu/libncurses.so.6", b"map-x-se"),
        ("/usr/lib/x86_64-linux-gnu/libncurses.so.6.4", b"map-x-sf"),
        ("/usr/lib/x86_64-linux-gnu/libncursesw.so.6", b"map-x-sg"),
        ("/usr/lib/x86_64-linux-gnu/libncursesw.so.6.4", b"map-x-sh"),
        ("/usr/lib/x86_64-linux-gnu/libnettle.so.8", b"map-x-si"),
        ("/usr/lib/x86_64-linux-gnu/libnettle.so.8.8", b"map-x-sj"),
        ("/usr/lib/x86_64-linux-gnu/libnghttp2.so.14", b"map-x-sk"),
        ("/usr/lib/x86_64-linux-gnu/libnghttp2.so.14.26.0", b"map-x-sl"),
        ("/usr/lib/x86_64-linux-gnu/libogg.so.0", b"map-x-sm"),
        ("/usr/lib/x86_64-linux-gnu/libogg.so.0.8.5", b"map-x-sn"),
        ("/usr/lib/x86_64-linux-gnu/libopus.so.0", b"map-x-so"),
        ("/usr/lib/x86_64-linux-gnu/libopus.so.0.9.0", b"map-x-sp"),
        ("/usr/lib/x86_64-linux-gnu/liborc-0.4.so.0", b"map-x-sq"),
        ("/usr/lib/x86_64-linux-gnu/liborc-0.4.so.0.38.0", b"map-x-sr"),
        ("/usr/lib/x86_64-linux-gnu/libp11-kit.so.0", b"map-x-ss"),
        ("/usr/lib/x86_64-linux-gnu/libp11-kit.so.0.3.1", b"map-x-st"),
        ("/usr/lib/x86_64-linux-gnu/libpango-1.0.so.0", b"map-x-su"),
        ("/usr/lib/x86_64-linux-gnu/libpango-1.0.so.0.5200.1", b"map-x-sv"),
        ("/usr/lib/x86_64-linux-gnu/libpangocairo-1.0.so.0", b"map-x-sw"),
        ("/usr/lib/x86_64-linux-gnu/libpangocairo-1.0.so.0.5200.1", b"map-x-sx"),
        ("/usr/lib/x86_64-linux-gnu/libpangoft2-1.0.so.0", b"map-x-sy"),
        ("/usr/lib/x86_64-linux-gnu/libpangoft2-1.0.so.0.5200.1", b"map-x-sz"),
        ("/usr/lib/x86_64-linux-gnu/libpciaccess.so.0", b"map-x-ta"),
        ("/usr/lib/x86_64-linux-gnu/libpciaccess.so.0.11.1", b"map-x-tb"),
        ("/usr/lib/x86_64-linux-gnu/libpcre2-8.so.0", b"map-x-tc"),
        ("/usr/lib/x86_64-linux-gnu/libpcre2-8.so.0.11.2", b"map-x-td"),
        ("/usr/lib/x86_64-linux-gnu/libpixman-1.so.0", b"map-x-te"),
        ("/usr/lib/x86_64-linux-gnu/libpixman-1.so.0.42.2", b"map-x-tf"),
        ("/usr/lib/x86_64-linux-gnu/libpng16.so.16", b"map-x-tg"),
        ("/usr/lib/x86_64-linux-gnu/libpng16.so.16.43.0", b"map-x-th"),
        ("/usr/lib/x86_64-linux-gnu/libproxy.so.0.5.4", b"map-x-ti"),
        ("/usr/lib/x86_64-linux-gnu/libproxy.so.1", b"map-x-tj"),
        ("/usr/lib/x86_64-linux-gnu/libproxy/libpxbackend-1.0.so", b"map-x-tk"),
        ("/usr/lib/x86_64-linux-gnu/libpsl.so.5", b"map-x-tl"),
        ("/usr/lib/x86_64-linux-gnu/libpsl.so.5.3.4", b"map-x-tm"),
        ("/usr/lib/x86_64-linux-gnu/libpthread.so.0", b"map-x-tn"),
        ("/usr/lib/x86_64-linux-gnu/libpulse.so.0", b"map-x-to"),
        ("/usr/lib/x86_64-linux-gnu/libpulse.so.0.24.2", b"map-x-tp"),
        ("/usr/lib/x86_64-linux-gnu/libraw1394.so.11", b"map-x-tq"),
        ("/usr/lib/x86_64-linux-gnu/libraw1394.so.11.1.0", b"map-x-tr"),
        ("/usr/lib/x86_64-linux-gnu/libreadline.so.8", b"map-x-ts"),
        ("/usr/lib/x86_64-linux-gnu/libreadline.so.8.2", b"map-x-tt"),
        ("/usr/lib/x86_64-linux-gnu/libresolv.so.2", b"map-x-tu"),
        ("/usr/lib/x86_64-linux-gnu/librom1394.so.0", b"map-x-tv"),
        ("/usr/lib/x86_64-linux-gnu/librom1394.so.0.3.0", b"map-x-tw"),
        ("/usr/lib/x86_64-linux-gnu/librsvg-2.so.2", b"map-x-tx"),
        ("/usr/lib/x86_64-linux-gnu/librsvg-2.so.2.50.0", b"map-x-ty"),
        ("/usr/lib/x86_64-linux-gnu/librt.so.1", b"map-x-tz"),
        ("/usr/lib/x86_64-linux-gnu/librtmp.so.1", b"map-x-ua"),
        ("/usr/lib/x86_64-linux-gnu/libsasl2.so.2", b"map-x-ub"),
        ("/usr/lib/x86_64-linux-gnu/libsasl2.so.2.0.25", b"map-x-uc"),
        ("/usr/lib/x86_64-linux-gnu/libseccomp.so.2", b"map-x-ud"),
        ("/usr/lib/x86_64-linux-gnu/libseccomp.so.2.5.5", b"map-x-ue"),
        ("/usr/lib/x86_64-linux-gnu/libsecret-1.so.0", b"map-x-uf"),
        ("/usr/lib/x86_64-linux-gnu/libsecret-1.so.0.0.0", b"map-x-ug"),
        ("/usr/lib/x86_64-linux-gnu/libselinux.so.1", b"map-x-uh"),
        ("/usr/lib/x86_64-linux-gnu/libsensors.so.5", b"map-x-ui"),
        ("/usr/lib/x86_64-linux-gnu/libsensors.so.5.0.0", b"map-x-uj"),
        ("/usr/lib/x86_64-linux-gnu/libsharpyuv.so.0", b"map-x-uk"),
        ("/usr/lib/x86_64-linux-gnu/libsharpyuv.so.0.0.1", b"map-x-ul"),
        ("/usr/lib/x86_64-linux-gnu/libshout.so.3", b"map-x-um"),
        ("/usr/lib/x86_64-linux-gnu/libshout.so.3.2.0", b"map-x-un"),
        ("/usr/lib/x86_64-linux-gnu/libsigsegv.so.2", b"map-x-uo"),
        ("/usr/lib/x86_64-linux-gnu/libsigsegv.so.2.0.7", b"map-x-up"),
        ("/usr/lib/x86_64-linux-gnu/libslang.so.2", b"map-x-uq"),
        ("/usr/lib/x86_64-linux-gnu/libslang.so.2.3.3", b"map-x-ur"),
        ("/usr/lib/x86_64-linux-gnu/libsmartcols.so.1", b"map-x-us"),
        ("/usr/lib/x86_64-linux-gnu/libsmartcols.so.1.1.0", b"map-x-ut"),
        ("/usr/lib/x86_64-linux-gnu/libsndfile.so.1", b"map-x-uu"),
        ("/usr/lib/x86_64-linux-gnu/libsndfile.so.1.0.37", b"map-x-uv"),
        ("/usr/lib/x86_64-linux-gnu/libsoup-3.0.so.0", b"map-x-uw"),
        ("/usr/lib/x86_64-linux-gnu/libsoup-3.0.so.0.7.1", b"map-x-ux"),
        ("/usr/lib/x86_64-linux-gnu/libspeex.so.1", b"map-x-uy"),
        ("/usr/lib/x86_64-linux-gnu/libspeex.so.1.5.2", b"map-x-uz"),
        ("/usr/lib/x86_64-linux-gnu/libsqlite3.so.0", b"map-x-va"),
        ("/usr/lib/x86_64-linux-gnu/libsqlite3.so.0.8.6", b"map-x-vb"),
        ("/usr/lib/x86_64-linux-gnu/libssh.so.4", b"map-x-vc"),
        ("/usr/lib/x86_64-linux-gnu/libssh.so.4.9.6", b"map-x-vd"),
        ("/usr/lib/x86_64-linux-gnu/libssl.so.3", b"map-x-ve"),
        ("/usr/lib/x86_64-linux-gnu/libstdc++.so.6", b"map-x-vf"),
        ("/usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.33", b"map-x-vg"),
        ("/usr/lib/x86_64-linux-gnu/libsystemd.so.0", b"map-x-vh"),
        ("/usr/lib/x86_64-linux-gnu/libsystemd.so.0.38.0", b"map-x-vi"),
        ("/usr/lib/x86_64-linux-gnu/libtag.so.1", b"map-x-vj"),
        ("/usr/lib/x86_64-linux-gnu/libtag.so.1.19.1", b"map-x-vk"),
        ("/usr/lib/x86_64-linux-gnu/libtasn1.so.6", b"map-x-vl"),
        ("/usr/lib/x86_64-linux-gnu/libtasn1.so.6.6.3", b"map-x-vm"),
        ("/usr/lib/x86_64-linux-gnu/libthai.so.0", b"map-x-vn"),
        ("/usr/lib/x86_64-linux-gnu/libthai.so.0.3.1", b"map-x-vo"),
        ("/usr/lib/x86_64-linux-gnu/libtheora.so.0", b"map-x-vp"),
        ("/usr/lib/x86_64-linux-gnu/libtheora.so.0.3.10", b"map-x-vq"),
        ("/usr/lib/x86_64-linux-gnu/libtheoradec.so.1", b"map-x-vr"),
        ("/usr/lib/x86_64-linux-gnu/libtheoradec.so.1.1.4", b"map-x-vs"),
        ("/usr/lib/x86_64-linux-gnu/libtheoraenc.so.1", b"map-x-vt"),
        ("/usr/lib/x86_64-linux-gnu/libtheoraenc.so.1.1.2", b"map-x-vu"),
        ("/usr/lib/x86_64-linux-gnu/libtiff.so.6", b"map-x-vv"),
        ("/usr/lib/x86_64-linux-gnu/libtiff.so.6.0.1", b"map-x-vw"),
        ("/usr/lib/x86_64-linux-gnu/libtinfo.so.6", b"map-x-vx"),
        ("/usr/lib/x86_64-linux-gnu/libtinfo.so.6.4", b"map-x-vy"),
        ("/usr/lib/x86_64-linux-gnu/libtwolame.so.0", b"map-x-vz"),
        ("/usr/lib/x86_64-linux-gnu/libtwolame.so.0.0.0", b"map-x-wa"),
        ("/usr/lib/x86_64-linux-gnu/libudev.so.1", b"map-x-wb"),
        ("/usr/lib/x86_64-linux-gnu/libudev.so.1.7.8", b"map-x-wc"),
        ("/usr/lib/x86_64-linux-gnu/libunistring.so.5", b"map-x-wd"),
        ("/usr/lib/x86_64-linux-gnu/libunistring.so.5.0.0", b"map-x-we"),
        ("/usr/lib/x86_64-linux-gnu/libunwind.so.8", b"map-x-wf"),
        ("/usr/lib/x86_64-linux-gnu/libunwind.so.8.0.1", b"map-x-wg"),
        ("/usr/lib/x86_64-linux-gnu/libutil.so.1", b"map-x-wh"),
        ("/usr/lib/x86_64-linux-gnu/libv4l2.so.0", b"map-x-wi"),
        ("/usr/lib/x86_64-linux-gnu/libv4l2.so.0.0.0", b"map-x-wj"),
        ("/usr/lib/x86_64-linux-gnu/libv4lconvert.so.0", b"map-x-wk"),
        ("/usr/lib/x86_64-linux-gnu/libv4lconvert.so.0.0.0", b"map-x-wl"),
        ("/usr/lib/x86_64-linux-gnu/libvisual-0.4.so.0", b"map-x-wm"),
        ("/usr/lib/x86_64-linux-gnu/libvisual-0.4.so.0.0.0", b"map-x-wn"),
        ("/usr/lib/x86_64-linux-gnu/libvorbis.so.0", b"map-x-wo"),
        ("/usr/lib/x86_64-linux-gnu/libvorbis.so.0.4.9", b"map-x-wp"),
        ("/usr/lib/x86_64-linux-gnu/libvorbisenc.so.2", b"map-x-wq"),
        ("/usr/lib/x86_64-linux-gnu/libvorbisenc.so.2.0.12", b"map-x-wr"),
        ("/usr/lib/x86_64-linux-gnu/libvpx.so.9", b"map-x-ws"),
        ("/usr/lib/x86_64-linux-gnu/libvpx.so.9.0.0", b"map-x-wt"),
        ("/usr/lib/x86_64-linux-gnu/libwavpack.so.1", b"map-x-wu"),
        ("/usr/lib/x86_64-linux-gnu/libwavpack.so.1.2.5", b"map-x-wv"),
        ("/usr/lib/x86_64-linux-gnu/libwayland-client.so.0", b"map-x-ww"),
        ("/usr/lib/x86_64-linux-gnu/libwayland-client.so.0.22.0", b"map-x-wx"),
        ("/usr/lib/x86_64-linux-gnu/libwayland-cursor.so.0", b"map-x-wy"),
        ("/usr/lib/x86_64-linux-gnu/libwayland-cursor.so.0.22.0", b"map-x-wz"),
        ("/usr/lib/x86_64-linux-gnu/libwayland-egl.so.1", b"map-x-xa"),
        ("/usr/lib/x86_64-linux-gnu/libwayland-egl.so.1.22.0", b"map-x-xb"),
        ("/usr/lib/x86_64-linux-gnu/libwayland-server.so.0", b"map-x-xc"),
        ("/usr/lib/x86_64-linux-gnu/libwayland-server.so.0.22.0", b"map-x-xd"),
        ("/usr/lib/x86_64-linux-gnu/libwebkit2gtk-4.1.so.0", b"map-x-xe"),
        ("/usr/lib/x86_64-linux-gnu/libwebkit2gtk-4.1.so.0.21.10", b"map-x-xf"),
        ("/usr/lib/x86_64-linux-gnu/libwebp.so.7", b"map-x-xg"),
        ("/usr/lib/x86_64-linux-gnu/libwebp.so.7.1.8", b"map-x-xh"),
        ("/usr/lib/x86_64-linux-gnu/libwebpdemux.so.2", b"map-x-xi"),
        ("/usr/lib/x86_64-linux-gnu/libwebpdemux.so.2.0.14", b"map-x-xj"),
        ("/usr/lib/x86_64-linux-gnu/libwebpmux.so.3", b"map-x-xk"),
        ("/usr/lib/x86_64-linux-gnu/libwebpmux.so.3.0.13", b"map-x-xl"),
        ("/usr/lib/x86_64-linux-gnu/libxcb-dri3.so.0", b"map-x-xm"),
        ("/usr/lib/x86_64-linux-gnu/libxcb-dri3.so.0.1.0", b"map-x-xn"),
        ("/usr/lib/x86_64-linux-gnu/libxcb-glx.so.0", b"map-x-xo"),
        ("/usr/lib/x86_64-linux-gnu/libxcb-glx.so.0.0.0", b"map-x-xp"),
        ("/usr/lib/x86_64-linux-gnu/libxcb-present.so.0", b"map-x-xq"),
        ("/usr/lib/x86_64-linux-gnu/libxcb-present.so.0.0.0", b"map-x-xr"),
        ("/usr/lib/x86_64-linux-gnu/libxcb-randr.so.0", b"map-x-xs"),
        ("/usr/lib/x86_64-linux-gnu/libxcb-randr.so.0.1.0", b"map-x-xt"),
        ("/usr/lib/x86_64-linux-gnu/libxcb-render.so.0", b"map-x-xu"),
        ("/usr/lib/x86_64-linux-gnu/libxcb-render.so.0.0.0", b"map-x-xv"),
        ("/usr/lib/x86_64-linux-gnu/libxcb-shm.so.0", b"map-x-xw"),
        ("/usr/lib/x86_64-linux-gnu/libxcb-shm.so.0.0.0", b"map-x-xx"),
        ("/usr/lib/x86_64-linux-gnu/libxcb-sync.so.1", b"map-x-xy"),
        ("/usr/lib/x86_64-linux-gnu/libxcb-sync.so.1.0.0", b"map-x-xz"),
        ("/usr/lib/x86_64-linux-gnu/libxcb-xfixes.so.0", b"map-x-ya"),
        ("/usr/lib/x86_64-linux-gnu/libxcb-xfixes.so.0.0.0", b"map-x-yb"),
        ("/usr/lib/x86_64-linux-gnu/libxcb.so.1", b"map-x-yc"),
        ("/usr/lib/x86_64-linux-gnu/libxcb.so.1.1.0", b"map-x-yd"),
        ("/usr/lib/x86_64-linux-gnu/libxdo.so.3", b"map-x-ye"),
        ("/usr/lib/x86_64-linux-gnu/libxkbcommon.so.0", b"map-x-yf"),
        ("/usr/lib/x86_64-linux-gnu/libxkbcommon.so.0.0.0", b"map-x-yg"),
        ("/usr/lib/x86_64-linux-gnu/libxkbfile.so.1", b"map-x-yh"),
        ("/usr/lib/x86_64-linux-gnu/libxkbfile.so.1.0.2", b"map-x-yi"),
        ("/usr/lib/x86_64-linux-gnu/libxml2.so.2", b"map-x-yj"),
        ("/usr/lib/x86_64-linux-gnu/libxml2.so.2.9.14", b"map-x-yk"),
        ("/usr/lib/x86_64-linux-gnu/libxshmfence.so.1", b"map-x-yl"),
        ("/usr/lib/x86_64-linux-gnu/libxshmfence.so.1.0.0", b"map-x-ym"),
        ("/usr/lib/x86_64-linux-gnu/libxslt.so.1", b"map-x-yn"),
        ("/usr/lib/x86_64-linux-gnu/libxslt.so.1.1.39", b"map-x-yo"),
        ("/usr/lib/x86_64-linux-gnu/libz.so.1", b"map-x-yp"),
        ("/usr/lib/x86_64-linux-gnu/libz.so.1.3", b"map-x-yq"),
        ("/usr/lib/x86_64-linux-gnu/libzstd.so.1", b"map-x-yr"),
        ("/usr/lib/x86_64-linux-gnu/libzstd.so.1.5.5", b"map-x-ys"),
        ("/usr/lib/x86_64-linux-gnu/pulseaudio/libpulsecommon-16.1.so", b"map-x-yt"),
        ("/usr/lib/x86_64-linux-gnu/webkit2gtk-4.1/WebKitGPUProcess", b"map-x-yu"),
        ("/usr/lib/x86_64-linux-gnu/webkit2gtk-4.1/WebKitNetworkProcess", b"map-x-yv"),
        ("/usr/lib/x86_64-linux-gnu/webkit2gtk-4.1/WebKitWebProcess", b"map-x-yw"),
        ("/usr/lib/x86_64-linux-gnu/webkit2gtk-4.1/injected-bundle/libwebkit2gtkinjectedbundle.so", b"map-x-yx"),
    ];
    // Diagnostic roles do not replace the original strings used to order maps.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(super) enum MapRole { Python, Ssl, Crypto, Loader, Libc, Libm }
    impl MapRole {
        const ALL: [Self; 6] = [Self::Python, Self::Ssl, Self::Crypto, Self::Loader, Self::Libc, Self::Libm];
        fn name(self) -> &'static str {
            match self { Self::Python => "python", Self::Ssl => "libssl.so.3", Self::Crypto => "libcrypto.so.3",
                Self::Loader => "ld-linux-x86-64.so.2", Self::Libc => "libc.so.6", Self::Libm => "libm.so.6" }
        }
        fn diagnostic_tokens(self) -> [&'static [u8]; 8] {
            // Fixed literals only; no observed pathname or metadata is emitted.
            match self {
                Self::Python => [b"map-m-stat-py", b"map-m-type-py", b"map-m-owner-py", b"map-m-links-py", b"map-m-mode-py", b"map-m-inode-py", b"map-m-dev-py", b"map-dup-py"],
                Self::Ssl => [b"map-m-stat-ss", b"map-m-type-ss", b"map-m-owner-ss", b"map-m-links-ss", b"map-m-mode-ss", b"map-m-inode-ss", b"map-m-dev-ss", b"map-dup-ss"],
                Self::Crypto => [b"map-m-stat-cr", b"map-m-type-cr", b"map-m-owner-cr", b"map-m-links-cr", b"map-m-mode-cr", b"map-m-inode-cr", b"map-m-dev-cr", b"map-dup-cr"],
                Self::Loader => [b"map-m-stat-ld", b"map-m-type-ld", b"map-m-owner-ld", b"map-m-links-ld", b"map-m-mode-ld", b"map-m-inode-ld", b"map-m-dev-ld", b"map-dup-ld"],
                Self::Libc => [b"map-m-stat-lc", b"map-m-type-lc", b"map-m-owner-lc", b"map-m-links-lc", b"map-m-mode-lc", b"map-m-inode-lc", b"map-m-dev-lc", b"map-dup-lc"],
                Self::Libm => [b"map-m-stat-lm", b"map-m-type-lm", b"map-m-owner-lm", b"map-m-links-lm", b"map-m-mode-lm", b"map-m-inode-lm", b"map-m-dev-lm", b"map-dup-lm"],
            }
        }
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(super) enum HostedMapSpelling { ShellObserver, ShellNormal, PlatformTests, InstalledTests,
        NativePython, NativeSsl, NativeCrypto, FixturePython, FixtureSsl, FixtureCrypto, OtherNative, OtherFixture }
    impl HostedMapSpelling {
        fn diagnostic_tokens(self) -> [&'static [u8]; 8] {
            // Twelve literal spelling classes by eight numeric relations.
            // No observed text or coordinate is copied into the original frame.
            match self {
                Self::ShellObserver => [b"map-xh-sz", b"map-xh-sa", b"map-xh-sp", b"map-xh-ss", b"map-xh-sc", b"map-xh-sm", b"map-xh-sd", b"map-xh-sx"],
                Self::ShellNormal => [b"map-xh-nz", b"map-xh-na", b"map-xh-np", b"map-xh-ns", b"map-xh-nc", b"map-xh-nm", b"map-xh-nd", b"map-xh-nx"],
                Self::PlatformTests => [b"map-xh-tz", b"map-xh-ta", b"map-xh-tp", b"map-xh-ts", b"map-xh-tc", b"map-xh-tm", b"map-xh-td", b"map-xh-tx"],
                Self::InstalledTests => [b"map-xh-iz", b"map-xh-ia", b"map-xh-ip", b"map-xh-is", b"map-xh-ic", b"map-xh-im", b"map-xh-id", b"map-xh-ix"],
                Self::NativePython => [b"map-xh-pz", b"map-xh-pa", b"map-xh-pp", b"map-xh-ps", b"map-xh-pc", b"map-xh-pm", b"map-xh-pd", b"map-xh-px"],
                Self::NativeSsl => [b"map-xh-lz", b"map-xh-la", b"map-xh-lp", b"map-xh-ls", b"map-xh-lc", b"map-xh-lm", b"map-xh-ld", b"map-xh-lx"],
                Self::NativeCrypto => [b"map-xh-cz", b"map-xh-ca", b"map-xh-cp", b"map-xh-cs", b"map-xh-cc", b"map-xh-cm", b"map-xh-cd", b"map-xh-cx"],
                Self::FixturePython => [b"map-xh-qz", b"map-xh-qa", b"map-xh-qp", b"map-xh-qs", b"map-xh-qc", b"map-xh-qm", b"map-xh-qd", b"map-xh-qx"],
                Self::FixtureSsl => [b"map-xh-rz", b"map-xh-ra", b"map-xh-rp", b"map-xh-rs", b"map-xh-rc", b"map-xh-rm", b"map-xh-rd", b"map-xh-rx"],
                Self::FixtureCrypto => [b"map-xh-gz", b"map-xh-ga", b"map-xh-gp", b"map-xh-gs", b"map-xh-gc", b"map-xh-gm", b"map-xh-gd", b"map-xh-gx"],
                Self::OtherNative => [b"map-xh-uz", b"map-xh-ua", b"map-xh-up", b"map-xh-us", b"map-xh-uc", b"map-xh-um", b"map-xh-ud", b"map-xh-ux"],
                Self::OtherFixture => [b"map-xh-fz", b"map-xh-fa", b"map-xh-fp", b"map-xh-fs", b"map-xh-fc", b"map-xh-fm", b"map-xh-fd", b"map-xh-fx"],
            }
        }
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(super) enum MapMetadataRefusal { Stat, Type, Owner, Links, Mode, Inode, Device }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(super) enum GenericMapPath { Version, Library, Command, Hosted, Memfd, Other }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(super) enum MapRefusal {
        Utf8, Newline, Row, Columns, Address, Order, Permissions, Offset, Device, Inode,
        ExecutableAnonymous, ExecutablePseudo, ExecutableFile, ExecutablePublicPath(u16),
        ExecutableHistoricalPayload(HistoricalPayloadRole),
        ExecutableGenericFile { class: GenericMapPath, deleted: bool, historical_present: bool },
        ExecutableHostedFile { spelling: HostedMapSpelling, relation: HistoricalPayloadRelation },
        Metadata(MapRole, MapMetadataRefusal), Duplicate(MapRole),
    }
    impl MapRefusal {
        fn token(self) -> &'static [u8] {
            match self {
                Self::Utf8 => b"map-p-utf", Self::Newline => b"map-p-nl", Self::Row => b"map-p-row",
                Self::Columns => b"map-p-cols", Self::Address => b"map-p-addr", Self::Order => b"map-p-order",
                Self::Permissions => b"map-p-perm", Self::Offset => b"map-p-offset", Self::Device => b"map-p-dev",
                Self::Inode => b"map-p-inode", Self::ExecutableAnonymous => b"map-x-anon",
                Self::ExecutablePseudo => b"map-x-pseudo", Self::ExecutableFile => b"map-x-file",
                Self::ExecutablePublicPath(index) => PUBLIC_MAP_PATH_CANDIDATES.get(usize::from(index))
                    .map_or(Self::ExecutableFile.token(), |(_, token)| *token),
                Self::ExecutableHistoricalPayload(role) => match role {
                    HistoricalPayloadRole::Python => b"map-x-hist-py", HistoricalPayloadRole::Ssl => b"map-x-hist-ss",
                    HistoricalPayloadRole::Crypto => b"map-x-hist-cr",
                },
                Self::ExecutableGenericFile { class, deleted, historical_present } => {
                    // Fixed spelling/history labels only, never observed text.
                    let tokens: [&[u8]; 4] = match class {
                        GenericMapPath::Version => [b"map-x-v-na", b"map-x-v-np", b"map-x-v-da", b"map-x-v-dp"],
                        GenericMapPath::Library => [b"map-x-l-na", b"map-x-l-np", b"map-x-l-da", b"map-x-l-dp"],
                        GenericMapPath::Command => [b"map-x-c-na", b"map-x-c-np", b"map-x-c-da", b"map-x-c-dp"],
                        GenericMapPath::Hosted => [b"map-x-h-na", b"map-x-h-np", b"map-x-h-da", b"map-x-h-dp"],
                        GenericMapPath::Memfd => [b"map-x-m-na", b"map-x-m-np", b"map-x-m-da", b"map-x-m-dp"],
                        GenericMapPath::Other => [b"map-x-o-na", b"map-x-o-np", b"map-x-o-da", b"map-x-o-dp"],
                    };
                    tokens[usize::from(deleted) * 2 + usize::from(historical_present)]
                },
                Self::ExecutableHostedFile { spelling, relation } => spelling.diagnostic_tokens()[match relation {
                    HistoricalPayloadRelation::Zero => 0, HistoricalPayloadRelation::Ambiguous => 1,
                    HistoricalPayloadRelation::PythonInode => 2, HistoricalPayloadRelation::SslInode => 3,
                    HistoricalPayloadRelation::CryptoInode => 4, HistoricalPayloadRelation::MultipleInodes => 5,
                    HistoricalPayloadRelation::DeviceOnly => 6, HistoricalPayloadRelation::Other => 7,
                }],
                Self::Metadata(role, reason) => role.diagnostic_tokens()[match reason {
                    MapMetadataRefusal::Stat => 0, MapMetadataRefusal::Type => 1, MapMetadataRefusal::Owner => 2,
                    MapMetadataRefusal::Links => 3, MapMetadataRefusal::Mode => 4, MapMetadataRefusal::Inode => 5,
                    MapMetadataRefusal::Device => 6,
                }],
                Self::Duplicate(role) => role.diagnostic_tokens()[7],
            }
        }
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(super) enum ObservationFailure { ChildId, Entry, ExecRead, ExecCheck, MapsRead, MapsCheck(MapRefusal), EnvironmentRead, EnvironmentCheck, HoldRefused }
    impl ObservationFailure {
        pub(super) fn token(self) -> &'static [u8] {
            match self {
                Self::ChildId => b"child-id", Self::Entry => b"observe-entry",
                Self::ExecRead => b"exec-read", Self::ExecCheck => b"exec-check", Self::MapsRead => b"maps-read",
                Self::MapsCheck(reason) => reason.token(), Self::EnvironmentRead => b"env-read", Self::EnvironmentCheck => b"env-check",
                Self::HoldRefused => b"hold-refused",
            }
        }
    }
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
    fn executable_file_refusal(path: &str) -> MapRefusal {
        // Only the existing executable-file refusal calls this; no new observation.
        PUBLIC_MAP_PATH_CANDIDATES.iter().position(|(candidate, _)| path == *candidate)
            .and_then(|index| u16::try_from(index).ok())
            .map_or(MapRefusal::ExecutableFile, MapRefusal::ExecutablePublicPath)
    }
    fn historical_executable_file_refusal(refusal: MapRefusal, historical: Option<HistoricalPayloadSnapshot>,
        major: u64, minor: u64, inode: u64) -> MapRefusal {
        // The original refused row only; public spelling tokens keep precedence.
        // Equality to a closed admission-time tuple does NOT prove live content.
        if refusal != MapRefusal::ExecutableFile { return refusal; }
        historical.and_then(|data| data.matching_role(major, minor, inode))
            .map_or(refusal, MapRefusal::ExecutableHistoricalPayload)
    }
    fn generic_executable_file_refusal(refusal: MapRefusal, path: &str, historical_present: bool) -> MapRefusal {
        // Only the SAME refused row, after exact public and unique historical
        // decisions. None of these lexical labels grants mapping admission.
        if refusal != MapRefusal::ExecutableFile { return refusal; }
        let (path, deleted) = path.strip_suffix(" (deleted)").map_or((path, false), |path| (path, true));
        let below = |prefix: &str| path.strip_prefix(prefix).is_some_and(|tail| !tail.is_empty());
        let hosted = |prefix: &str| {
            let Some(tail) = path.strip_prefix(prefix) else { return false; };
            let Some((ids, tail)) = tail.split_once('/') else { return false; };
            let Some((run, attempt)) = ids.split_once('-') else { return false; };
            let number = |value: &str| !value.is_empty() && value.len() <= 20 && !value.starts_with('0')
                && value.bytes().all(|byte| byte.is_ascii_digit());
            !tail.is_empty() && number(run) && number(attempt)
        };
        // No resolution, dot-component handling, trimming, escape decoding or
        // current-run lookup. The suffix was removed for this diagnostic ONLY.
        let class = if path.strip_prefix(VERSION).and_then(|tail| tail.strip_prefix('/')).is_some_and(|tail| !tail.is_empty()) {
            GenericMapPath::Version
        } else if ["/usr/lib/", "/usr/lib64/", "/lib/", "/lib64/"].into_iter().any(below) {
            GenericMapPath::Library
        } else if ["/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/"].into_iter().any(below) {
            GenericMapPath::Command
        } else if ["/var/lib/mrk-ubuntu-native-", "/var/lib/mrk-ubuntu-shell-fixtures-"].into_iter().any(hosted) {
            GenericMapPath::Hosted
        } else if path.starts_with("/memfd:") { GenericMapPath::Memfd } else { GenericMapPath::Other };
        // Some means only a captured Option with NO unique tuple match; it
        // includes mismatch, ambiguity and inode zero, not a runtime verdict.
        MapRefusal::ExecutableGenericFile { class, deleted, historical_present }
    }
    fn hosted_map_spelling(path: &str) -> Option<HostedMapSpelling> {
        // Lexical DATA from the same rejected row; no current-run inference.
        let (native, rest) = if let Some(rest) = path.strip_prefix("/var/lib/mrk-ubuntu-native-") {
            (true, rest)
        } else if let Some(rest) = path.strip_prefix("/var/lib/mrk-ubuntu-shell-fixtures-") {
            (false, rest)
        } else { return None; };
        let (ids, tail) = rest.split_once('/')?;
        let (run, attempt) = ids.split_once('-')?;
        let number = |value: &str| !value.is_empty() && value.len() <= 20 && !value.starts_with('0')
            && value.bytes().all(|byte| byte.is_ascii_digit());
        if tail.is_empty() || !number(run) || !number(attempt) { return None; }
        if native {
            match tail {
                "shell-observer" => return Some(HostedMapSpelling::ShellObserver),
                "shell-normal" => return Some(HostedMapSpelling::ShellNormal),
                "platform-tests" => return Some(HostedMapSpelling::PlatformTests),
                "installed-tests" => return Some(HostedMapSpelling::InstalledTests),
                _ => {},
            }
        }
        if tail.split('/').all(|component| !component.is_empty() && component != "." && component != "..") {
            for (suffix, native_spelling, fixture_spelling) in [
                ("python/bin/python3", HostedMapSpelling::NativePython, HostedMapSpelling::FixturePython),
                ("python/lib/libssl.so.3", HostedMapSpelling::NativeSsl, HostedMapSpelling::FixtureSsl),
                ("python/lib/libcrypto.so.3", HostedMapSpelling::NativeCrypto, HostedMapSpelling::FixtureCrypto),
            ] {
                if tail == suffix || tail.strip_suffix(suffix).is_some_and(|head| head.ends_with('/')) {
                    return Some(if native { native_spelling } else { fixture_spelling });
                }
            }
        }
        Some(if native { HostedMapSpelling::OtherNative } else { HostedMapSpelling::OtherFixture })
    }
    fn hosted_executable_file_refusal(refusal: MapRefusal, path: &str, historical: Option<HistoricalPayloadSnapshot>,
        major: u64, minor: u64, inode: u64) -> MapRefusal {
        // Refine only the original nondeleted Hosted/history-present refusal.
        // Public/unique-historical precedence and all admission stay unchanged.
        if !matches!(refusal, MapRefusal::ExecutableGenericFile {
            class: GenericMapPath::Hosted, deleted: false, historical_present: true,
        }) { return refusal; }
        let Some(history) = historical else { return refusal; };
        let Some(spelling) = hosted_map_spelling(path) else { return refusal; };
        let Some(relation) = history.coordinate_relation(major, minor, inode) else { return refusal; };
        MapRefusal::ExecutableHostedFile { spelling, relation }
    }
    fn role(path: &str) -> Option<MapRole> {
        for (role, suffix) in [(MapRole::Python, "/python/bin/python3"), (MapRole::Ssl, "/python/lib/libssl.so.3"),
            (MapRole::Crypto, "/python/lib/libcrypto.so.3")] {
            if path.strip_prefix(VERSION) == Some(suffix) { return Some(role); }
        }
        for role in [MapRole::Loader, MapRole::Libc, MapRole::Libm] {
            let name = role.name();
            if path.strip_prefix("/usr/lib/x86_64-linux-gnu/") == Some(name)
                || path.strip_prefix("/lib/x86_64-linux-gnu/") == Some(name)
                || name == "ld-linux-x86-64.so.2" && path == "/lib64/ld-linux-x86-64.so.2" { return Some(role); }
        }
        None
    }
    #[derive(Clone, Copy)]
    struct MapMetadata { regular: bool, uid: u32, gid: u32, links: u64, mode: u32, inode: u64, major: u64, minor: u64 }
    fn check_map_metadata(st: MapMetadata, inode: u64, major: u64, minor: u64) -> Result<(), MapMetadataRefusal> {
        // Pure facts from the SAME original stat; comparisons keep their old order.
        if !st.regular { return Err(MapMetadataRefusal::Type); }
        if st.uid != 0 || st.gid != 0 { return Err(MapMetadataRefusal::Owner); }
        if st.links != 1 { return Err(MapMetadataRefusal::Links); }
        if st.mode & 0o7022 != 0 { return Err(MapMetadataRefusal::Mode); }
        if inode == 0 || inode != st.inode { return Err(MapMetadataRefusal::Inode); }
        if major != st.major || minor != st.minor { return Err(MapMetadataRefusal::Device); }
        Ok(())
    }
    fn insert_mapping(found: &mut BTreeMap<&'static str, (Mapping, bool)>, role: MapRole, row: Mapping, executable: bool) -> Result<(), MapRefusal> {
        if let Some((previous, code)) = found.get_mut(role.name()) {
            if *previous != row { return Err(MapRefusal::Duplicate(role)); }
            *code |= executable;
        } else { found.insert(role.name(), (row, executable)); }
        Ok(())
    }
    fn complete_mappings(found: BTreeMap<&'static str, (Mapping, bool)>) -> Option<Vec<Mapping>> {
        if found.len() == 6 && found.values().all(|(_, code)| *code) { Some(found.into_values().map(|(row, _)| row).collect()) } else { None }
    }
    fn mappings(raw: &[u8], historical: Option<HistoricalPayloadSnapshot>) -> Result<Option<Vec<Mapping>>, MapRefusal> {
        let text = std::str::from_utf8(raw).map_err(|_| MapRefusal::Utf8)?;
        need(text.is_empty() || text.ends_with('\n')).map_err(|_| MapRefusal::Newline)?;
        let mut found = BTreeMap::new();
        for (index, line) in text.split_terminator('\n').enumerate() {
            need(index < 4096 && !line.is_empty()).map_err(|_| MapRefusal::Row)?;
            let mut rest = line;
            let mut columns = [""; 5];
            for column in &mut columns {
                rest = rest.trim_start_matches([' ', '\t']);
                let end = rest.find([' ', '\t']).unwrap_or(rest.len());
                need(end > 0).map_err(|_| MapRefusal::Columns)?; *column = &rest[..end]; rest = &rest[end..];
            }
            let (start, end) = columns[0].split_once('-').ok_or(MapRefusal::Address)?;
            need(hex(start).map_err(|_| MapRefusal::Address)? < hex(end).map_err(|_| MapRefusal::Address)?).map_err(|_| MapRefusal::Order)?;
            let permissions = columns[1].as_bytes();
            need(permissions.len() == 4 && matches!(permissions[0], b'r' | b'-') && matches!(permissions[1], b'w' | b'-')
                && matches!(permissions[2], b'x' | b'-') && matches!(permissions[3], b'p' | b's')).map_err(|_| MapRefusal::Permissions)?;
            let _ = hex(columns[2]).map_err(|_| MapRefusal::Offset)?;
            let (major, minor) = columns[3].split_once(':').ok_or(MapRefusal::Device)?;
            let (major, minor) = (hex(major).map_err(|_| MapRefusal::Device)?, hex(minor).map_err(|_| MapRefusal::Device)?);
            need(!columns[4].is_empty() && columns[4].len() <= 20 && columns[4].bytes().all(|byte| byte.is_ascii_digit())).map_err(|_| MapRefusal::Inode)?;
            let inode = columns[4].parse::<u64>().map_err(|_| MapRefusal::Inode)?;
            let path = rest.trim_start_matches([' ', '\t']); // Opaque pathname, not a sixth whitespace token.
            let executable = permissions[2] == b'x';
            if !path.starts_with('/') {
                need(!executable || matches!(path, "[vdso]" | "[vsyscall]")).map_err(|_|
                    if path.is_empty() { MapRefusal::ExecutableAnonymous } else { MapRefusal::ExecutablePseudo })?;
                continue;
            }
            let Some(role) = role(path) else { need(!executable).map_err(|_| hosted_executable_file_refusal(generic_executable_file_refusal(historical_executable_file_refusal(executable_file_refusal(path), historical, major, minor, inode), path, historical.is_some()), path, historical, major, minor, inode))?; continue; };
            let st = fs::metadata(path).map_err(|_| MapRefusal::Metadata(role, MapMetadataRefusal::Stat))?;
            check_map_metadata(MapMetadata { regular: st.is_file(), uid: st.uid(), gid: st.gid(), links: st.nlink(), mode: st.mode(),
                inode: st.ino(), major: nix::sys::stat::major(st.dev()), minor: nix::sys::stat::minor(st.dev()) }, inode, major, minor)
                .map_err(|reason| MapRefusal::Metadata(role, reason))?;
            let row = Mapping { role: role.name().into(), path: path.into(), device_major: major, device_minor: minor, inode };
            insert_mapping(&mut found, role, row, executable)?;
        }
        Ok(complete_mappings(found))
    }
    #[cfg(all(debug_assertions, any(all(feature = "desktop-shell", feature = "custom-protocol"),
        all(not(feature = "desktop-shell"), not(feature = "custom-protocol")))))]
    pub(super) fn assert_mappings_diagnostic_contract() {
        // Explicit-call DATA only. These parser inputs have no recognized file
        // paths, so no filesystem, /proc reader or native worker is invoked.
        use MapRefusal as R;
        use GenericMapPath as G;
        use HostedMapSpelling as H;
        use HistoricalPayloadRelation as C;
        let generic = |class, deleted, historical_present| R::ExecutableGenericFile { class, deleted, historical_present };
        let hosted = |spelling, relation| R::ExecutableHostedFile { spelling, relation };
        let mappings = |raw: &[u8]| self::mappings(raw, None);
        crate::installed_runtime::assert_historical_payload_diagnostic_contract();
        assert_exec_image_contract();
        let failures: &[(&[u8], R)] = &[
            (b"\xff", R::Utf8), (b"x", R::Newline), (b"\n", R::Row),
            (b"1-2 r--p 0 00:00\n", R::Columns), (b"x r--p 0 00:00 0\n", R::Address),
            (b"1-z r--p 0 00:00 0\n", R::Address), (b"2-1 invalid 0 00:00 0\n", R::Order),
            (b"1-2 invalid x 00:00 0\n", R::Permissions), (b"1-2 r--p x invalid 0\n", R::Offset),
            (b"1-2 r--p 0 invalid invalid\n", R::Device), (b"1-2 r--p 0 00:00 invalid\n", R::Inode),
            (b"1-2 r--p 0 00:00 18446744073709551616\n", R::Inode),
            (b"1-2 r-xp 0 00:00 0\n", R::ExecutableAnonymous),
            (b"1-2 r-xp 0 00:00 0 [heap]\n", R::ExecutablePseudo),
            (b"1-2 r-xp 0 00:00 0 /unrecognized\n", generic(G::Other, false, false)),
        ];
        for &(bytes, expected) in failures { assert_eq!(mappings(bytes), Err(expected)); }
        for bytes in [b"".as_slice(), b"1-2 r--p 0 00:00 0\n", b"1-2 r--p 0 00:00 0 /unrecognized\n",
            b"1-2 r-xp 0 00:00 0 [vdso]\n1-2 r-xp 0 00:00 0 [vsyscall]\n"] {
            assert_eq!(mappings(bytes), Ok(None));
        }
        use MapMetadataRefusal as M;
        let good = MapMetadata { regular: true, uid: 0, gid: 0, links: 1, mode: 0o100755, inode: 1, major: 8, minor: 1 };
        for mode in [0o100400, 0o100644, 0o100755] { assert_eq!(check_map_metadata(MapMetadata { mode, ..good }, 1, 8, 1), Ok(())); }
        let mut bad = MapMetadata { regular: false, uid: 1, links: 2, mode: 0o102777, inode: 2, major: 9, minor: 2, ..good };
        assert_eq!(check_map_metadata(bad, 1, 8, 1), Err(M::Type)); bad.regular = true;
        assert_eq!(check_map_metadata(bad, 1, 8, 1), Err(M::Owner)); bad.uid = 0; bad.gid = 1;
        assert_eq!(check_map_metadata(bad, 1, 8, 1), Err(M::Owner)); bad.gid = 0;
        assert_eq!(check_map_metadata(bad, 1, 8, 1), Err(M::Links)); bad.links = 1;
        assert_eq!(check_map_metadata(bad, 1, 8, 1), Err(M::Mode)); bad.mode = good.mode;
        assert_eq!(check_map_metadata(bad, 1, 8, 1), Err(M::Inode)); bad.inode = good.inode;
        assert_eq!(check_map_metadata(bad, 0, 8, 1), Err(M::Inode));
        assert_eq!(check_map_metadata(bad, 1, 8, 1), Err(M::Device)); bad.major = good.major;
        assert_eq!(check_map_metadata(bad, 1, 8, 1), Err(M::Device)); bad.minor = good.minor;
        assert_eq!(check_map_metadata(bad, 1, 8, 1), Ok(()));

        let row = Mapping { role: MapRole::Python.name().into(), path: "inert-original".into(), device_major: 8, device_minor: 1, inode: 1 };
        let mut found = BTreeMap::new();
        assert_eq!(complete_mappings(found.clone()), None);
        assert_eq!(insert_mapping(&mut found, MapRole::Python, row.clone(), false), Ok(()));
        assert_eq!(complete_mappings(found.clone()), None); // Recognized-but-incomplete is not refusal.
        assert_eq!(insert_mapping(&mut found, MapRole::Python, row.clone(), true), Ok(()));
        assert_eq!(insert_mapping(&mut found, MapRole::Python, row.clone(), false), Ok(()));
        assert_eq!(found.get("python"), Some(&(row.clone(), true)));
        let unchanged = found.clone();
        let conflict = Mapping { inode: 2, ..row };
        assert_eq!(insert_mapping(&mut found, MapRole::Python, conflict, false), Err(R::Duplicate(MapRole::Python)));
        assert_eq!(found, unchanged);
        for role in MapRole::ALL.into_iter().filter(|role| *role != MapRole::Python) {
            let row = Mapping { role: role.name().into(), path: "inert-original".into(), device_major: 8, device_minor: 1, inode: 1 };
            assert_eq!(insert_mapping(&mut found, role, row, role != MapRole::Ssl), Ok(()));
        }
        assert_eq!(complete_mappings(found.clone()), None); // Every one of the six roles must have code.
        found.get_mut(MapRole::Ssl.name()).unwrap().1 = true;
        let complete = complete_mappings(found).unwrap();
        assert_eq!(complete.iter().map(|row| row.role.as_str()).collect::<Vec<_>>(),
            ["ld-linux-x86-64.so.2", "libc.so.6", "libcrypto.so.3", "libm.so.6", "libssl.so.3", "python"]);
        for (path, expected) in [("/lib/x86_64-linux-gnu/libc.so.6", Some(MapRole::Libc)),
            ("/usr/lib/x86_64-linux-gnu/libc.so.6", Some(MapRole::Libc)), ("/lib64/ld-linux-x86-64.so.2", Some(MapRole::Loader)),
            ("/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2", Some(MapRole::Loader)),
            ("/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2", Some(MapRole::Loader)),
            ("/lib/x86_64-linux-gnu/libm.so.6", Some(MapRole::Libm)), ("/usr/lib/x86_64-linux-gnu/libm.so.6", Some(MapRole::Libm)),
            ("/lib64/libc.so.6", None), ("/lib/x86_64-linux-gnu/libc.so.6 (deleted)", None)] {
            assert_eq!(role(path), expected);
        }
        for (suffix, expected) in [("/python/bin/python3", MapRole::Python), ("/python/lib/libssl.so.3", MapRole::Ssl),
            ("/python/lib/libcrypto.so.3", MapRole::Crypto)] {
            assert_eq!(role(&format!("{VERSION}{suffix}")), Some(expected));
        }
        let mut tokens = vec![R::Utf8.token(), R::Newline.token(), R::Row.token(), R::Columns.token(), R::Address.token(),
            R::Order.token(), R::Permissions.token(), R::Offset.token(), R::Device.token(), R::Inode.token(),
            R::ExecutableAnonymous.token(), R::ExecutablePseudo.token(), R::ExecutableFile.token()];
        for role in MapRole::ALL {
            for reason in [M::Stat, M::Type, M::Owner, M::Links, M::Mode, M::Inode, M::Device] { tokens.push(R::Metadata(role, reason).token()); }
            tokens.push(R::Duplicate(role).token());
        }
        for role in [HistoricalPayloadRole::Python, HistoricalPayloadRole::Ssl, HistoricalPayloadRole::Crypto] {
            tokens.push(R::ExecutableHistoricalPayload(role).token());
        }
        for class in [G::Version, G::Library, G::Command, G::Hosted, G::Memfd, G::Other] {
            for deleted in [false, true] {
                for present in [false, true] { tokens.push(generic(class, deleted, present).token()); }
            }
        }
        assert_eq!(tokens.len(), 88);
        assert!(tokens.iter().all(|token| !token.is_empty() && token.len() <= 14
            && token.iter().all(|byte| byte.is_ascii_lowercase() || *byte == b'-')));
        tokens.sort(); tokens.dedup(); assert_eq!(tokens.len(), 88);
        let hosted_spellings = [
            (H::ShellObserver, b's', "/var/lib/mrk-ubuntu-native-1-2/shell-observer"),
            (H::ShellNormal, b'n', "/var/lib/mrk-ubuntu-native-1-2/shell-normal"),
            (H::PlatformTests, b't', "/var/lib/mrk-ubuntu-native-1-2/platform-tests"),
            (H::InstalledTests, b'i', "/var/lib/mrk-ubuntu-native-1-2/installed-tests"),
            (H::NativePython, b'p', "/var/lib/mrk-ubuntu-native-1-2/python/bin/python3"),
            (H::NativeSsl, b'l', "/var/lib/mrk-ubuntu-native-1-2/python/lib/libssl.so.3"),
            (H::NativeCrypto, b'c', "/var/lib/mrk-ubuntu-native-1-2/python/lib/libcrypto.so.3"),
            (H::FixturePython, b'q', "/var/lib/mrk-ubuntu-shell-fixtures-1-2/python/bin/python3"),
            (H::FixtureSsl, b'r', "/var/lib/mrk-ubuntu-shell-fixtures-1-2/python/lib/libssl.so.3"),
            (H::FixtureCrypto, b'g', "/var/lib/mrk-ubuntu-shell-fixtures-1-2/python/lib/libcrypto.so.3"),
            (H::OtherNative, b'u', "/var/lib/mrk-ubuntu-native-1-2/unlisted-fixture"),
            (H::OtherFixture, b'f', "/var/lib/mrk-ubuntu-shell-fixtures-1-2/unlisted-fixture"),
        ];
        let plain_history = [(8, 1, 11), (8, 1, 22), (8, 1, 33)];
        let hosted_relations = [
            (C::Zero, b'z', plain_history, (0, 0, 0)),
            (C::Ambiguous, b'a', [(8, 1, 11), (8, 1, 11), (8, 1, 33)], (8, 1, 11)),
            (C::PythonInode, b'p', plain_history, (9, 2, 11)),
            (C::SslInode, b's', plain_history, (9, 2, 22)),
            (C::CryptoInode, b'c', plain_history, (9, 2, 33)),
            (C::MultipleInodes, b'm', [(8, 1, 11), (8, 2, 11), (8, 3, 33)], (9, 4, 11)),
            (C::DeviceOnly, b'd', plain_history, (8, 1, 99)),
            (C::Other, b'x', plain_history, (9, 2, 99)),
        ];
        for (spelling, spelling_code, path) in hosted_spellings {
            assert_eq!(role(path), None);
            assert_eq!(executable_file_refusal(path), R::ExecutableFile);
            assert_eq!(hosted_map_spelling(path), Some(spelling));
            for (relation, relation_code, tuples, (major, minor, inode)) in hosted_relations {
                let historical = Some(HistoricalPayloadSnapshot::for_contract(tuples));
                let expected = hosted(spelling, relation);
                let token = [b'm', b'a', b'p', b'-', b'x', b'h', b'-', spelling_code, relation_code];
                assert_eq!(expected.token(), token.as_slice());
                assert_eq!(self::mappings(format!("1-2 r-xp 0 {major:x}:{minor:x} {inode} {path}\n").as_bytes(), historical), Err(expected));
                tokens.push(expected.token());
            }
            assert_eq!(self::mappings(format!("1-2 r--p 0 00:00 0 {path}\n").as_bytes(),
                Some(HistoricalPayloadSnapshot::for_contract(plain_history))), Ok(None));
        }
        assert_eq!(tokens.len(), 184);
        tokens.sort(); tokens.dedup(); assert_eq!(tokens.len(), 184);
        assert!(tokens.iter().all(|token| token.len() <= 14
            && token.iter().all(|byte| byte.is_ascii_lowercase() || *byte == b'-')));

        // Every new parser row is role(None): no existing metadata or /proc read.
        assert_eq!(PUBLIC_MAP_PATH_CANDIDATES.len(), 648);
        assert!(PUBLIC_MAP_PATH_CANDIDATES.windows(2).all(|rows| rows[0].0 < rows[1].0));
        let mut public_tokens = Vec::new();
        for (index, &(path, token)) in PUBLIC_MAP_PATH_CANDIDATES.iter().enumerate() {
            assert!(path.is_ascii() && path.starts_with('/') && path.len() <= 87);
            assert_eq!(role(path), None);
            let expected = R::ExecutablePublicPath(u16::try_from(index).unwrap());
            let expected_token = [b'm', b'a', b'p', b'-', b'x', b'-', b'a' + (index / 26) as u8, b'a' + (index % 26) as u8];
            assert_eq!(token, expected_token.as_slice());
            assert_eq!(executable_file_refusal(path), expected);
            assert_eq!(expected.token(), token);
            assert_eq!(mappings(format!("1-2 r-xp 0 00:00 0 {path}\n").as_bytes()), Err(expected));
            assert_eq!(mappings(format!("1-2 r--p 0 00:00 0 {path}\n").as_bytes()), Ok(None));
            public_tokens.push(token);
        }
        assert_eq!(PUBLIC_MAP_PATH_CANDIDATES.iter().map(|(path, _)| path.len()).max(), Some(87));
        assert_eq!(PUBLIC_MAP_PATH_CANDIDATES.iter().map(|(path, _)| path.len()).sum::<usize>(), 29840);
        public_tokens.sort(); public_tokens.dedup(); assert_eq!(public_tokens.len(), 648);
        assert!(public_tokens.iter().all(|token| !tokens.contains(token)));
        for index in [648, u16::MAX] { assert_eq!(R::ExecutablePublicPath(index).token(), R::ExecutableFile.token()); }

        let first = format!("1-2 r-xp 0 00:00 0 {}\n", PUBLIC_MAP_PATH_CANDIDATES[0].0);
        let second = format!("2-3 r-xp 0 00:00 0 {}\n", PUBLIC_MAP_PATH_CANDIDATES[1].0);
        assert_eq!(mappings(format!("{first}{second}").as_bytes()), Err(R::ExecutablePublicPath(0)));
        assert_eq!(mappings(format!("{second}{first}").as_bytes()), Err(R::ExecutablePublicPath(1)));
        for &(bytes, expected) in failures {
            if matches!(expected, R::Utf8 | R::Newline) { continue; } // Whole-buffer guards precede all rows.
            let mut earlier = bytes.to_vec(); earlier.extend_from_slice(first.as_bytes());
            assert_eq!(mappings(&earlier), Err(expected));
            let mut later = first.as_bytes().to_vec(); later.extend_from_slice(bytes);
            assert_eq!(mappings(&later), Err(R::ExecutablePublicPath(0)));
        }
        let mut invalid_utf8 = vec![0xff]; invalid_utf8.extend_from_slice(first.as_bytes());
        assert_eq!(mappings(&invalid_utf8), Err(R::Utf8));
        assert_eq!(mappings(&first.as_bytes()[..first.len() - 1]), Err(R::Newline));
        for (path, class, deleted) in [("/unrecognized", G::Other, false), ("/bin/sh (deleted)", G::Command, true),
            ("/bin/sh ", G::Command, false), ("/bin/sh\t", G::Command, false), ("/bin/sh private tail", G::Command, false),
            ("/bin/sh.extra", G::Command, false), ("/prefix/bin/sh", G::Other, false), ("//bin/sh", G::Other, false),
            ("/BIN/SH", G::Other, false), ("/bin/sh (deleted) ", G::Command, false),
            ("/bin/sh (deleted) tail", G::Command, false), ("/bin/sh (deleted) (deleted)", G::Command, true)] {
            assert!(PUBLIC_MAP_PATH_CANDIDATES.iter().all(|(candidate, _)| *candidate != path));
            assert_eq!(role(path), None);
            assert_eq!(executable_file_refusal(path), R::ExecutableFile);
            assert_eq!(mappings(format!("1-2 r-xp 0 00:00 0 {path}\n").as_bytes()), Err(generic(class, deleted, false)));
        }
        // Complete synthetic historical DATA; these unrecognized spellings
        // never reach metadata lookup and no path/tuple is exported by a token.
        let history = Some(HistoricalPayloadSnapshot::for_contract([(8, 1, 11), (8, 1, 22), (8, 1, 33)]));
        for (inode, role) in [(11, HistoricalPayloadRole::Python), (22, HistoricalPayloadRole::Ssl), (33, HistoricalPayloadRole::Crypto)] {
            assert_eq!(self::mappings(format!("1-2 r-xp 0 08:01 {inode} /unrecognized (deleted)\n").as_bytes(), history),
                Err(R::ExecutableHistoricalPayload(role)));
        }
        for row in ["1-2 r-xp 0 09:01 11 /unrecognized\n", "1-2 r-xp 0 08:02 11 /unrecognized\n",
            "1-2 r-xp 0 08:01 12 /unrecognized\n", "1-2 r-xp 0 08:01 0 /unrecognized\n"] {
            assert_eq!(self::mappings(row.as_bytes(), history), Err(generic(G::Other, false, true)));
        }
        let same_row = b"1-2 r-xp 0 08:01 11 /unrecognized\n";
        assert_eq!(self::mappings(same_row, None), Err(generic(G::Other, false, false)));
        let ambiguous = Some(HistoricalPayloadSnapshot::for_contract([(8, 1, 11), (8, 1, 11), (8, 1, 33)]));
        assert_eq!(self::mappings(same_row, ambiguous), Err(generic(G::Other, false, true)));
        let zero = Some(HistoricalPayloadSnapshot::for_contract([(8, 1, 0), (8, 1, 22), (8, 1, 33)]));
        assert_eq!(self::mappings(b"1-2 r-xp 0 08:01 0 /unrecognized\n", zero), Err(generic(G::Other, false, true)));
        assert_eq!(self::mappings(b"1-2 r--p 0 08:01 11 /unrecognized\n", history), Ok(None));
        assert_eq!(self::mappings(b"1-2 r-xp 0 08:01 11\n", history), Err(R::ExecutableAnonymous));
        assert_eq!(self::mappings(b"1-2 r-xp 0 08:01 11 [heap]\n", history), Err(R::ExecutablePseudo));
        let public = format!("1-2 r-xp 0 08:01 11 {}\n", PUBLIC_MAP_PATH_CANDIDATES[0].0);
        assert_eq!(self::mappings(public.as_bytes(), history), Err(R::ExecutablePublicPath(0)));
        let mut earlier = b"x r-xp 0 08:01 11 /unrecognized\n".to_vec(); earlier.extend_from_slice(same_row);
        assert_eq!(self::mappings(&earlier, history), Err(R::Address));
        let mut later = same_row.to_vec(); later.extend_from_slice(b"x r-xp 0 08:01 11 /unrecognized\n");
        assert_eq!(self::mappings(&later, history), Err(R::ExecutableHistoricalPayload(HistoricalPayloadRole::Python)));
        let mut first_generic = b"1-2 r-xp 0 08:01 99 /unrecognized\n".to_vec(); first_generic.extend_from_slice(same_row);
        assert_eq!(self::mappings(&first_generic, history), Err(generic(G::Other, false, true)));

        // All 24 static outcomes from first, role-unrecognized rows only.
        let version_other = format!("{VERSION}/unlisted-fixture");
        for (path, class, letter) in [(version_other.as_str(), G::Version, b'v'),
            ("/usr/lib/unlisted-fixture", G::Library, b'l'), ("/usr/bin/unlisted-fixture", G::Command, b'c'),
            ("/var/lib/mrk-ubuntu-native-1-2/unlisted-fixture", G::Hosted, b'h'),
            ("/memfd:unlisted-fixture", G::Memfd, b'm'), ("/unrecognized", G::Other, b'o')] {
            for deleted in [false, true] {
                let path = format!("{path}{}", if deleted { " (deleted)" } else { "" });
                assert_eq!(role(&path), None);
                assert_eq!(executable_file_refusal(&path), R::ExecutableFile);
                for present in [false, true] {
                    let historical = if present { history } else { None };
                    let refusal = generic(class, deleted, present);
                    assert_eq!(generic_executable_file_refusal(R::ExecutableFile, &path, present), refusal);
                    let parser_refusal = if class == G::Hosted && !deleted && present { hosted(H::OtherNative, C::Zero) } else { refusal };
                    assert_eq!(self::mappings(format!("1-2 r-xp 0 00:00 0 {path}\n").as_bytes(), historical), Err(parser_refusal));
                    assert_eq!(self::mappings(format!("1-2 r--p 0 00:00 0 {path}\n").as_bytes(), historical), Ok(None));
                    let token = [b'm', b'a', b'p', b'-', b'x', b'-', letter, b'-',
                        if deleted { b'd' } else { b'n' }, if present { b'p' } else { b'a' }];
                    assert_eq!(refusal.token(), token.as_slice());
                }
            }
        }
        let check = |path: &str, class| {
            assert_eq!(role(path), None);
            assert_eq!(executable_file_refusal(path), R::ExecutableFile);
            assert_eq!(mappings(format!("1-2 r-xp 0 00:00 0 {path}\n").as_bytes()), Err(generic(class, false, false)));
        };
        for (prefix, class) in [("/usr/lib/", G::Library), ("/usr/lib64/", G::Library), ("/lib/", G::Library), ("/lib64/", G::Library),
            ("/usr/bin/", G::Command), ("/usr/sbin/", G::Command), ("/bin/", G::Command), ("/sbin/", G::Command)] {
            check(&format!("{prefix}unlisted-fixture"), class);
            check(prefix, G::Other); // Nonempty component required.
        }
        for prefix in ["/var/lib/mrk-ubuntu-native-", "/var/lib/mrk-ubuntu-shell-fixtures-"] {
            for suffix in ["1-2/file", "99999999999999999999-99999999999999999999/file"] {
                check(&format!("{prefix}{suffix}"), G::Hosted);
            }
            for suffix in ["0-1/file", "01-1/file", "1-0/file", "1-01/file", "-1/file", "1-/file", "1-1", "1-1/",
                "1-1-2/file", "1-+2/file", "1-２/file", "111111111111111111111-1/file", "1-111111111111111111111/file",
                "1x-2/file", "1-2x/file"] { check(&format!("{prefix}{suffix}"), G::Other); }
        }
        for path in [VERSION.to_owned(), format!("{VERSION}/"), format!("{VERSION}-sibling/file"), format!("{VERSION}x/file")] {
            check(&path, G::Other);
        }
        for path in ["/usr/libevil/file", "/usr/lib64evil/file", "/usr/local/lib/file", "/usr/local/bin/file",
            "/USR/LIB/file", "/memfdish", "/var/lib/mrk-ubuntu-nativeevil-1-2/file"] { check(path, G::Other); }
        check("/memfd:", G::Memfd); // Literal prefix, not a filesystem claim.
        check(&format!("{VERSION}/../file"), G::Version);
        check("/usr/lib/../file", G::Library); // Lexical only; never normalize for admission.
        let generic_first = b"1-2 r-xp 0 00:00 0 /unrecognized\n";
        let mut bad_first = b"x r-xp 0 00:00 0 /unrecognized\n".to_vec(); bad_first.extend_from_slice(generic_first);
        assert_eq!(mappings(&bad_first), Err(R::Address));
        let mut bad_later = generic_first.to_vec(); bad_later.extend_from_slice(b"x r-xp 0 00:00 0 /unrecognized\n");
        assert_eq!(mappings(&bad_later), Err(generic(G::Other, false, false)));
        let mut bad_utf8 = vec![0xff]; bad_utf8.extend_from_slice(generic_first);
        assert_eq!(mappings(&bad_utf8), Err(R::Utf8));
        assert_eq!(mappings(&generic_first[..generic_first.len() - 1]), Err(R::Newline));

        let check_hosted = |path: &str, expected: Option<H>| {
            assert_eq!(role(path), None);
            assert_eq!(executable_file_refusal(path), R::ExecutableFile);
            assert_eq!(hosted_map_spelling(path), expected);
            let refusal = expected.map_or(generic(G::Other, false, true), |spelling| hosted(spelling, C::Other));
            assert_eq!(self::mappings(format!("1-2 r-xp 0 09:02 99 {path}\n").as_bytes(), history), Err(refusal));
        };
        for (prefix, native) in [("/var/lib/mrk-ubuntu-native-", true), ("/var/lib/mrk-ubuntu-shell-fixtures-", false)] {
            let other = if native { H::OtherNative } else { H::OtherFixture };
            let python = if native { H::NativePython } else { H::FixturePython };
            for ids in ["1-2", "99999999999999999999-99999999999999999999"] {
                check_hosted(&format!("{prefix}{ids}/python/bin/python3"), Some(python));
            }
            for suffix in ["0-1/file", "01-1/file", "1-0/file", "1-01/file", "-1/file", "1-/file", "1-1", "1-1/",
                "1-1-2/file", "1-+2/file", "1-２/file", "111111111111111111111-1/file", "1-111111111111111111111/file",
                "1x-2/file", "1-2x/file"] {
                check_hosted(&format!("{prefix}{suffix}"), None);
            }
            for (suffix, native_spelling, fixture_spelling) in [
                ("python/bin/python3", H::NativePython, H::FixturePython),
                ("python/lib/libssl.so.3", H::NativeSsl, H::FixtureSsl),
                ("python/lib/libcrypto.so.3", H::NativeCrypto, H::FixtureCrypto),
            ] {
                let known = if native { native_spelling } else { fixture_spelling };
                for tail in [suffix.to_owned(), format!("sub/{suffix}"), format!(".hidden/{suffix}")] {
                    check_hosted(&format!("{prefix}1-2/{tail}"), Some(known));
                }
                for tail in [format!("not-{suffix}"), format!("{suffix}.extra"), format!("{suffix}/extra"),
                    format!("/{suffix}"), format!("sub//{suffix}"), format!("./{suffix}"), format!("../{suffix}"),
                    format!("sub/./{suffix}"), format!("sub/../{suffix}"), format!("{suffix}/"), format!("{suffix} "),
                    format!("{suffix} (deleted) "), suffix.replacen('/', "//", 1), suffix.replacen('/', "/./", 1),
                    format!(r"sub\057{suffix}")] {
                    check_hosted(&format!("{prefix}1-2/{tail}"), Some(other));
                }
            }
            for (tail, known) in [("shell-observer", H::ShellObserver), ("shell-normal", H::ShellNormal),
                ("platform-tests", H::PlatformTests), ("installed-tests", H::InstalledTests)] {
                check_hosted(&format!("{prefix}1-2/{tail}"), Some(if native { known } else { other }));
                for tail in [format!("sub/{tail}"), format!("{tail}.extra"), format!("{tail}/"), format!("{tail} ")] {
                    check_hosted(&format!("{prefix}1-2/{tail}"), Some(other));
                }
            }
            let path = format!("{prefix}1-2/python/bin/python3");
            assert_eq!(self::mappings(format!("1-2 r-xp 0 09:02 99 {path}\n").as_bytes(), None), Err(generic(G::Hosted, false, false)));
            assert_eq!(self::mappings(format!("1-2 r-xp 0 09:02 99 {path} (deleted)\n").as_bytes(), history), Err(generic(G::Hosted, true, true)));
            for (inode, role) in [(11, HistoricalPayloadRole::Python), (22, HistoricalPayloadRole::Ssl), (33, HistoricalPayloadRole::Crypto)] {
                assert_eq!(self::mappings(format!("1-2 r-xp 0 08:01 {inode} {path}\n").as_bytes(), history),
                    Err(R::ExecutableHistoricalPayload(role)));
            }
        }
        let path = "/var/lib/mrk-ubuntu-native-1-2/shell-observer";
        let original = generic(G::Hosted, false, true);
        assert_eq!(hosted_executable_file_refusal(original, path, None, 9, 2, 99), original);
        assert_eq!(hosted_executable_file_refusal(original, "/var/lib/mrk-ubuntu-native-01-2/file", history, 9, 2, 99), original);
        assert_eq!(hosted_executable_file_refusal(original, path, history, 8, 1, 11), original);
        for original in [R::ExecutablePublicPath(0), R::ExecutableHistoricalPayload(HistoricalPayloadRole::Python),
            generic(G::Hosted, true, true), generic(G::Hosted, false, false), generic(G::Other, false, true)] {
            assert_eq!(hosted_executable_file_refusal(original, path, history, 9, 2, 99), original);
        }
        let refined = format!("1-2 r-xp 0 09:02 99 {path}\n");
        let refusal = hosted(H::ShellObserver, C::Other);
        for &(bytes, expected) in failures {
            if matches!(expected, R::Utf8 | R::Newline | R::ExecutableGenericFile { .. }) { continue; }
            let mut earlier = bytes.to_vec(); earlier.extend_from_slice(refined.as_bytes());
            assert_eq!(self::mappings(&earlier, history), Err(expected));
            let mut later = refined.as_bytes().to_vec(); later.extend_from_slice(bytes);
            assert_eq!(self::mappings(&later, history), Err(refusal));
        }
        let mut bad_after = refined.as_bytes().to_vec(); bad_after.extend_from_slice(b"\xff\n");
        assert_eq!(self::mappings(&bad_after, history), Err(R::Utf8));
        assert_eq!(self::mappings(&refined.as_bytes()[..refined.len() - 1], history), Err(R::Newline));
    }
    #[cfg(all(debug_assertions, not(feature = "desktop-shell"), not(feature = "custom-protocol")))]
    #[test]
    fn historical_payload_mapping_diagnostic_is_only_data() {
        assert_mappings_diagnostic_contract();
    }
    fn child_snapshot(id: u32, end: Instant, stop: &watch::Receiver<bool>, historical: Option<HistoricalPayloadSnapshot>,
        python: &ExecOriginal, parent: &ExecOriginal, phase: &mut ExecPhase) -> Result<Option<ChildObservation>, ObservationFailure> {
        need(id > 0).map_err(|_| ObservationFailure::ChildId)?;
        while live(end, stop) {
            match exec_checkpoint(id, end, stop, python, parent, phase)? {
                None => return Ok(None),
                Some(false) => { std::thread::sleep(Duration::from_millis(1)); continue; },
                Some(true) => {},
            }
            if !live(end, stop) { return Ok(None); }
            let raw = original_bytes(Path::new(&format!("/proc/{id}/maps")), 1 << 20, false).map_err(|_| ObservationFailure::MapsRead)?;
            if let Some(maps) = mappings(&raw, historical).map_err(ObservationFailure::MapsCheck)? {
                if !live(end, stop) { return Ok(None); }
                let mut environment = original_bytes(Path::new(&format!("/proc/{id}/environ")), 8192, false)
                    .map_err(|_| ObservationFailure::EnvironmentRead)?;
                let clear = environment.last() == Some(&0) && {
                    let entries = environment[..environment.len() - 1].split(|byte| *byte == 0).collect::<Vec<_>>();
                    entries.len() == 2 && entries.contains(&b"LANG=C".as_slice()) && entries.contains(&b"LC_ALL=C".as_slice())
                };
                environment.fill(0); // No raw environment leaves this original reader.
                need(clear).map_err(|_| ObservationFailure::EnvironmentCheck)?;
                if exec_checkpoint(id, end, stop, python, parent, phase)? != Some(true) { return Ok(None); }
                return Ok(if live(end, stop) { Some(ChildObservation { maps, environment_clear: true }) } else { None });
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        Ok(None)
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct ExecIdentity {
        device: u64, inode: u64, mode: u32, uid: u32, gid: u32, links: u64, size: u64,
        mtime: (i64, i64), ctime: (i64, i64),
    }
    impl ExecIdentity {
        fn of(st: &fs::Metadata) -> Self {
            Self { device: st.dev(), inode: st.ino(), mode: st.mode(), uid: st.uid(), gid: st.gid(),
                links: st.nlink(), size: st.len(), mtime: (st.mtime(), st.mtime_nsec()), ctime: (st.ctime(), st.ctime_nsec()) }
        }
        fn protected(self) -> bool {
            self.mode & 0o170000 == 0o100000 && self.inode != 0 && self.uid == 0 && self.gid == 0
                && self.links == 1 && self.size > 0 && self.mode & 0o7022 == 0 && self.mode & 0o111 != 0
                && (0..1_000_000_000).contains(&self.mtime.1) && (0..1_000_000_000).contains(&self.ctime.1)
        }
    }
    #[derive(Clone, Debug, Eq, PartialEq)]
    struct ExecImage { name: std::ffi::OsString, identity: ExecIdentity }
    fn distinct_exec_images(python: &ExecImage, parent: &ExecImage) -> Result<(), ObservationFailure> {
        need(python.identity.protected() && parent.identity.protected() && python.name != parent.name
            && (python.identity.device, python.identity.inode) != (parent.identity.device, parent.identity.inode))
            .map_err(|_| ObservationFailure::ExecCheck)
    }
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum ExecPhase { BeforeExec, RuntimeImage }
    impl ExecPhase {
        fn observe(&mut self, python: &ExecImage, parent: &ExecImage,
            current: Result<ExecImage, ObservationFailure>) -> Result<bool, ObservationFailure> {
            let current = current?; // Inspection/close failure is never a pre-exec wait.
            distinct_exec_images(python, parent)?;
            if current == *python { *self = Self::RuntimeImage; return Ok(true); }
            if *self == Self::BeforeExec && current == *parent { return Ok(false); }
            Err(ObservationFailure::ExecCheck) // Third image, alias or any post-latch regression.
        }
    }
    // Actual-current protected originals, not HistoricalPayloadSnapshot or a
    // pathname/digest receipt. Both stay owned until the whole observer returns.
    struct ExecOriginal { file: fs::File, image: ExecImage }
    impl ExecOriginal {
        fn check_name(&self) -> Result<(), ObservationFailure> {
            need(checked_exec_identity(Path::new(&self.image.name), &self.file)? == self.image.identity)
                .map_err(|_| ObservationFailure::ExecCheck)
        }
        fn close(self) -> Result<(), ObservationFailure> {
            let checked = self.file.metadata().map_err(|_| ObservationFailure::ExecRead)
                .and_then(|st| need(ExecIdentity::of(&st) == self.image.identity).map_err(|_| ObservationFailure::ExecCheck));
            let closed = nix::unistd::close(self.file).is_ok(); // One consuming close even when metadata failed.
            if closed { checked } else { Err(ObservationFailure::ExecRead) }
        }
    }
    fn protected_exec_name(path: &Path) -> Result<(), ObservationFailure> {
        use std::os::unix::ffi::OsStrExt;
        let bytes = path.as_os_str().as_bytes();
        need(bytes.first() == Some(&b'/') && bytes.len() <= 4096
            && bytes[1..].split(|byte| *byte == b'/').all(|part| !part.is_empty() && part != b"." && part != b".."))
            .map_err(|_| ObservationFailure::ExecCheck)?;
        for ancestor in path.ancestors().skip(1) {
            let st = fs::symlink_metadata(ancestor).map_err(|_| ObservationFailure::ExecRead)?;
            need(st.is_dir() && st.uid() == 0 && st.gid() == 0 && st.mode() & 0o7022 == 0)
                .map_err(|_| ObservationFailure::ExecCheck)?;
        }
        Ok(())
    }
    fn checked_exec_identity(path: &Path, original: &fs::File) -> Result<ExecIdentity, ObservationFailure> {
        protected_exec_name(path)?;
        let before = ExecIdentity::of(&fs::symlink_metadata(path).map_err(|_| ObservationFailure::ExecRead)?);
        let held = ExecIdentity::of(&original.metadata().map_err(|_| ObservationFailure::ExecRead)?);
        let after = ExecIdentity::of(&fs::symlink_metadata(path).map_err(|_| ObservationFailure::ExecRead)?);
        let last = ExecIdentity::of(&original.metadata().map_err(|_| ObservationFailure::ExecRead)?);
        need(held.protected() && before == held && after == held && last == held).map_err(|_| ObservationFailure::ExecCheck)?;
        Ok(held)
    }
    fn opened_exec_original(file: fs::File, inspected: Result<ExecImage, ObservationFailure>) -> Result<ExecOriginal, ObservationFailure> {
        match inspected {
            Ok(image) => Ok(ExecOriginal { file, image }),
            Err(failure) => {
                let closed = nix::unistd::close(file).is_ok(); // Partial binding still consumes its original once.
                Err(if closed { failure } else { ObservationFailure::ExecRead })
            },
        }
    }
    fn current_python_original(end: Instant, stop: &watch::Receiver<bool>) -> Result<Option<ExecOriginal>, ObservationFailure> {
        if !live(end, stop) { return Ok(None); }
        let path = Path::new(VERSION).join("python/bin/python3");
        protected_exec_name(&path)?;
        if !live(end, stop) { return Ok(None); }
        let file = fs::OpenOptions::new().read(true).custom_flags(flags()).open(&path).map_err(|_| ObservationFailure::ExecRead)?;
        let inspected = checked_exec_identity(&path, &file).map(|identity| ExecImage { name: path.into_os_string(), identity });
        opened_exec_original(file, inspected).map(Some)
    }
    fn proc_exec_link(path: &Path) -> Result<(), ObservationFailure> {
        // Only fixed original exe links or a borrowed original File's own FD
        // link reach this observer. FD links are inspected, never opened.
        // The already-admitted initial PID namespace is unchanged; verify this
        // fixed observation still addresses a genuine procfs magic link.
        let filesystem = rustix::fs::statfs(path.parent().ok_or(ObservationFailure::ExecCheck)?)
            .map_err(|_| ObservationFailure::ExecRead)?;
        let link = fs::symlink_metadata(path).map_err(|_| ObservationFailure::ExecRead)?;
        need(filesystem.f_type as u64 == 0x9fa0 && link.file_type().is_symlink()).map_err(|_| ObservationFailure::ExecCheck)
    }
    fn proc_exec_name(path: &Path) -> Result<PathBuf, ObservationFailure> {
        proc_exec_link(path)?;
        fs::read_link(path).map_err(|_| ObservationFailure::ExecRead)
    }
    fn coherent_exec_observation(before: ExecIdentity, held: ExecIdentity, after: ExecIdentity, last: ExecIdentity,
        name: &Path, last_name: &Path) -> Result<(), ObservationFailure> {
        need(held.protected() && before == held && after == held && last == held
            && name.as_os_str() == last_name.as_os_str()).map_err(|_| ObservationFailure::ExecCheck)
    }
    fn inspected_proc_exec(path: &Path, file: &fs::File, name: PathBuf) -> Result<ExecImage, ObservationFailure> {
        let before = ExecIdentity::of(&fs::metadata(path).map_err(|_| ObservationFailure::ExecRead)?);
        let held = ExecIdentity::of(&file.metadata().map_err(|_| ObservationFailure::ExecRead)?);
        let after = ExecIdentity::of(&fs::metadata(path).map_err(|_| ObservationFailure::ExecRead)?);
        let last_name = proc_exec_name(path)?;
        let last = ExecIdentity::of(&file.metadata().map_err(|_| ObservationFailure::ExecRead)?);
        coherent_exec_observation(before, held, after, last, &name, &last_name)?;
        Ok(ExecImage { name: name.into_os_string(), identity: held })
    }
    fn inspected_owned_proc_exec(file: &fs::File) -> Result<ExecImage, ObservationFailure> {
        use std::os::fd::AsRawFd;
        // The File stays borrowed throughout. Sample its acquired image, not
        // the child's moving exe link across a legitimate parent -> Python exec.
        let path = PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()));
        let name = proc_exec_name(&path)?;
        inspected_proc_exec(&path, file, name)
    }
    fn proc_exec_original(path: &Path, end: Instant, stop: &watch::Receiver<bool>) -> Result<Option<ExecOriginal>, ObservationFailure> {
        if !live(end, stop) { return Ok(None); }
        proc_exec_link(path)?;
        if !live(end, stop) { return Ok(None); }
        // ONLY these two genuine kernel exe links may be followed. Ordinary
        // payload names retain NOFOLLOW; no caller-controlled path is opened.
        let file = fs::OpenOptions::new().read(true)
            .custom_flags(flags() & !(rustix::fs::OFlags::NOFOLLOW.bits() as i32)).open(path)
            .map_err(|_| ObservationFailure::ExecRead)?;
        // Every fallible post-acquisition check is inside this Result so the
        // original is checked-closed on error, not silently dropped by an early ?.
        let inspected = inspected_owned_proc_exec(&file);
        opened_exec_original(file, inspected).map(Some)
    }
    fn exec_checkpoint(id: u32, end: Instant, stop: &watch::Receiver<bool>, python: &ExecOriginal,
        parent: &ExecOriginal, phase: &mut ExecPhase) -> Result<Option<bool>, ObservationFailure> {
        if !live(end, stop) { return Ok(None); }
        python.check_name()?;
        parent.check_name()?;
        let current_parent = inspected_proc_exec(Path::new("/proc/self/exe"), &parent.file, PathBuf::from(&parent.image.name))?;
        need(current_parent == parent.image).map_err(|_| ObservationFailure::ExecCheck)?;
        distinct_exec_images(&python.image, &parent.image)?;
        let Some(current) = proc_exec_original(Path::new(&format!("/proc/{id}/exe")), end, stop)? else { return Ok(None); };
        let image = current.image.clone();
        let inspected = current.close().map(|()| image);
        phase.observe(&python.image, &parent.image, inspected).map(Some)
    }
    #[cfg(all(debug_assertions, any(all(feature = "desktop-shell", feature = "custom-protocol"),
        all(not(feature = "desktop-shell"), not(feature = "custom-protocol")))))]
    fn assert_exec_image_contract() {
        // Pure identities/phases only. Existing callers execute this without
        // opening a descriptor, consulting /proc or creating another selector.
        let identity = ExecIdentity { device: 1, inode: 2, mode: 0o100555, uid: 0, gid: 0,
            links: 1, size: 128, mtime: (7, 8), ctime: (9, 10) };
        let python = ExecImage { name: "/protected/python".into(), identity };
        let parent = ExecImage { name: "/protected/parent".into(), identity: ExecIdentity { inode: 3, ..identity } };
        let inspected = |image: &ExecImage| {
            coherent_exec_observation(image.identity, image.identity, image.identity, image.identity,
                Path::new(&image.name), Path::new(&image.name)).map(|()| image.clone())
        };
        let mut phase = ExecPhase::BeforeExec;
        assert_eq!(phase.observe(&python, &parent, inspected(&parent)), Ok(false));
        assert_eq!(phase.observe(&python, &parent, inspected(&parent)), Ok(false));
        assert_eq!(phase.observe(&python, &parent, inspected(&python)), Ok(true));
        assert_eq!(phase, ExecPhase::RuntimeImage);
        // This same latch is borrowed by the initial AND Overlap snapshots.
        assert_eq!(phase.observe(&python, &parent, inspected(&python)), Ok(true));
        assert_eq!(phase.observe(&python, &parent, inspected(&parent)), Err(ObservationFailure::ExecCheck));
        assert_eq!(phase, ExecPhase::RuntimeImage);
        for expected in [&python, &parent] {
            let name = Path::new(&expected.name);
            let id = expected.identity;
            for (first, last) in [(Path::new("/changed"), name), (name, Path::new("/changed"))] {
                assert_eq!(coherent_exec_observation(id, id, id, id, first, last), Err(ObservationFailure::ExecCheck));
            }
            for index in 0..11 {
                let mut changed = (*expected).clone();
                match index {
                    0 => changed.identity.device += 1, 1 => changed.identity.inode += 1,
                    2 => changed.identity.mode ^= 0o100, 3 => changed.identity.uid += 1, 4 => changed.identity.gid += 1,
                    5 => changed.identity.links += 1, 6 => changed.identity.size += 1,
                    7 => changed.identity.mtime.0 += 1, 8 => changed.identity.mtime.1 += 1,
                    9 => changed.identity.ctime.0 += 1, 10 => changed.identity.ctime.1 += 1, _ => unreachable!(),
                }
                for mut phase in [ExecPhase::BeforeExec, ExecPhase::RuntimeImage] {
                    assert_eq!(phase.observe(&python, &parent, Ok(changed.clone())), Err(ObservationFailure::ExecCheck));
                }
                for samples in [[changed.identity, id, id, id], [id, changed.identity, id, id],
                    [id, id, changed.identity, id], [id, id, id, changed.identity]] {
                    let observed = coherent_exec_observation(samples[0], samples[1], samples[2], samples[3], name, name);
                    assert_eq!(observed, Err(ObservationFailure::ExecCheck));
                    for mut phase in [ExecPhase::BeforeExec, ExecPhase::RuntimeImage] {
                        let before = phase;
                        assert_eq!(phase.observe(&python, &parent, observed.map(|()| expected.clone())), Err(ObservationFailure::ExecCheck));
                        assert_eq!(phase, before);
                    }
                }
            }
        }
        let third = ExecImage { name: "/third".into(), identity: ExecIdentity { inode: 4, ..identity } };
        for mut phase in [ExecPhase::BeforeExec, ExecPhase::RuntimeImage] {
            for changed in [third.clone(), ExecImage { name: "/alias".into(), ..python.clone() },
                ExecImage { name: "/alias".into(), ..parent.clone() }] {
                assert_eq!(phase.observe(&python, &parent, Ok(changed)), Err(ObservationFailure::ExecCheck));
            }
            for alias in [python.clone(), ExecImage { name: parent.name.clone(), ..python.clone() },
                ExecImage { name: python.name.clone(), ..parent.clone() },
                ExecImage { name: parent.name.clone(), identity: ExecIdentity { size: 129, ..identity } }] {
                assert_eq!(phase.observe(&python, &alias, Ok(python.clone())), Err(ObservationFailure::ExecCheck));
            }
            for failure in [ObservationFailure::ChildId, ObservationFailure::Entry, ObservationFailure::ExecRead,
                ObservationFailure::ExecCheck, ObservationFailure::MapsRead, ObservationFailure::MapsCheck(MapRefusal::Address),
                ObservationFailure::EnvironmentRead, ObservationFailure::EnvironmentCheck, ObservationFailure::HoldRefused] {
                let before = phase;
                assert_eq!(phase.observe(&python, &parent, Err(failure)), Err(failure));
                assert_eq!(phase, before);
            }
        }
        for mode in [0o040555, 0o120555, 0o100755 | 0o020, 0o100555 | 0o4000, 0o100444] {
            let changed = ExecIdentity { mode, ..identity };
            assert!(!changed.protected());
            assert_eq!(coherent_exec_observation(changed, changed, changed, changed,
                Path::new(&python.name), Path::new(&python.name)), Err(ObservationFailure::ExecCheck));
        }
        for changed in [ExecIdentity { inode: 0, ..identity }, ExecIdentity { uid: 1, ..identity },
            ExecIdentity { gid: 1, ..identity }, ExecIdentity { links: 0, ..identity }, ExecIdentity { links: 2, ..identity },
            ExecIdentity { size: 0, ..identity }, ExecIdentity { mtime: (7, -1), ..identity },
            ExecIdentity { mtime: (7, 1_000_000_000), ..identity }, ExecIdentity { ctime: (9, -1), ..identity },
            ExecIdentity { ctime: (9, 1_000_000_000), ..identity }] {
            assert!(!changed.protected());
            assert_eq!(coherent_exec_observation(changed, changed, changed, changed,
                Path::new(&python.name), Path::new(&python.name)), Err(ObservationFailure::ExecCheck));
        }
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
    pub(super) fn observe_original_child(id: u32, _key: u64, end: Instant, stop: watch::Receiver<bool>, inner: &Inner, case: Case,
        historical: Option<HistoricalPayloadSnapshot>)
        -> Result<Vec<ChildObservation>, ObservationFailure> {
        need(id > 0).map_err(|_| ObservationFailure::ChildId)?;
        let Some(python) = current_python_original(end, &stop)? else { return Ok(Vec::new()); };
        let observed = (|| {
            let Some(parent) = proc_exec_original(Path::new("/proc/self/exe"), end, &stop)? else { return Ok(Vec::new()); };
            let returned = (|| {
                if !live(end, &stop) { return Ok(Vec::new()); }
                python.check_name()?;
                parent.check_name()?;
                distinct_exec_images(&python.image, &parent.image)?;
                // One irreversible phase for this unreaped original Child,
                // including both initial and Overlap snapshots below.
                let mut phase = ExecPhase::BeforeExec;
                let mut snapshots = Vec::new();
                let Some(first) = child_snapshot(id, end, &stop, historical, &python, &parent, &mut phase)? else { return Ok(snapshots); };
                snapshots.push(first);
                match case {
                    #[cfg(all(debug_assertions, feature = "desktop-shell", feature = "custom-protocol"))]
                    Case::SessionObserve | Case::SessionLoss | Case::SessionDeadline => {
                        // Same original child/IO checkpoint, no new owner or clock.
                        shell_shutdown_observation::hold_session_query(inner, _key, end, &stop, case).map_err(|_| ObservationFailure::HoldRefused)?;
                    },
                    Case::Shutdown => {
                        inner.native_test.held.store(true, Ordering::SeqCst);
                        inner.changed.notify_waiters();
                        while live(end, &stop) { std::thread::sleep(Duration::from_millis(1)); }
                    },
                    Case::Overlap => {
                        let release = ready(end).map_err(|_| ObservationFailure::HoldRefused)?;
                        while live(end, &stop) {
                            let value = original_bytes(&release, 32, true).map_err(|_| ObservationFailure::HoldRefused)?;
                            if value.as_slice() == b"release\n" {
                                if let Some(second) = child_snapshot(id, end, &stop, historical, &python, &parent, &mut phase)? { snapshots.push(second); }
                                return Ok(snapshots);
                            }
                            need(value.as_slice() == b"pending\n").map_err(|_| ObservationFailure::HoldRefused)?;
                            std::thread::sleep(Duration::from_millis(1));
                        }
                    },
                    Case::Observe => {},
                    _ => return Err(ObservationFailure::Entry),
                }
                Ok(snapshots)
            })();
            // These closures keep all early returns/errors inside both checked
            // closes. Lost close/identity never turns an observation into success.
            let closed = parent.close();
            closed.and(returned)
        })();
        let closed = python.close();
        closed.and(observed)
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
        assert_eq!(option_env!("MRK_BUNDLED_RUNTIME_MANIFEST_SHA256"), Some("556b2ea59b4b3e9abb9d04a3d263e0fd420e8c44b3f71c478b1f71bdd21ec417"));
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
