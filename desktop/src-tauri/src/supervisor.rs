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
#[cfg(all(feature = "development-runtime", debug_assertions))]
use std::process::Stdio;
use serde_json::Value;
use tokio::{io::{AsyncRead, AsyncReadExt, AsyncWriteExt}, process::Child, sync::{mpsc, oneshot, watch, Mutex as AsyncMutex, Notify, OwnedSemaphorePermit, Semaphore}, task::JoinHandle};
#[cfg(all(feature = "development-runtime", debug_assertions))]
use tokio::process::Command;
use crate::{error::BridgeError, github_connection_protocol::{self as github_protocol, GitHubReadOutcome},
    protocol::{self, Method}, runtime::{RuntimeConfig, VerifiedRuntime}};

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
        Some(if self.unknown { Err(BridgeError::cleanup_unknown()) }
            else { match &self.error { Some(error) => Err(error.clone()), None => result } })
    }
}
#[derive(Default)]
struct Resources {
    inspection: Option<JoinHandle<Result<VerifiedRuntime, BridgeError>>>,
    #[cfg(all(test, debug_assertions, feature = "development-runtime", target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    github_environment: Option<JoinHandle<Result<Option<bool>, ()>>>,
    acquisition: Option<JoinHandle<std::io::Result<Child>>>, child: Option<Child>,
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
        drop(state);
        // No supervisor bookkeeping lock is held while publishing safe data.
        // A racing actual retirement may already have sealed the final receipt;
        // an earlier unknown reporter must never overwrite that final state.
        if let Some(receipt) = &self.github_receipt {
            let mut receipt = lock(receipt);
            if matches!(&*receipt, GitHubReadReceipt::Pending) { *receipt = GitHubReadReceipt::RetainedUnknown; }
        }
        if let Some(reply) = reply { let _ = reply.send(Err(BridgeError::cleanup_unknown())); }
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

impl Supervisor {
    pub fn new(runtime: RuntimeConfig) -> Self {
        Self { inner: Arc::new(Inner {
            runtime, permits: Arc::new(Semaphore::new(ACTIVE_LIMIT)), next: AtomicU64::new(1),
            stopping: AtomicBool::new(false), disabled: AtomicBool::new(false),
            owners: Mutex::new(BTreeMap::new()), changed: Notify::new(),
            #[cfg(all(test, feature = "development-runtime"))]
            test: hosted_tests::Hooks::default(),
        }) }
    }
    pub fn runtime_mode(&self) -> &'static str { self.inner.runtime.mode() }
    pub fn disabled(&self) -> bool { self.inner.disabled.load(Ordering::SeqCst) }
    pub fn stopping(&self) -> bool { self.inner.stopping.load(Ordering::SeqCst) }
    pub fn can_exit(&self) -> bool { lock(&self.inner.owners).is_empty() }

    pub async fn query(&self, method: Method, params: Value) -> Result<Value, BridgeError> {
        let (reply, receiver) = oneshot::channel();
        let owner = self.admit(AdmissionRequest::Passive { method, params: &params }, CompletionTarget::Passive(reply))?;
        // No owner/task cancellation on receiver abandonment. The registry retains
        // Child, IO tasks, startup handles and permits until actual settlement.
        receiver.await.unwrap_or_else(|_| {
            owner.unknown(&self.inner);
            Err(BridgeError::cleanup_unknown())
        })
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
            resources: AsyncMutex::new(Resources::default()), stop, changed: Notify::new(),
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

enum Event { Wait(std::io::Result<ExitStatus>), Write(Result<WriteEnd, tokio::task::JoinError>), Out(Result<ReadEnd, tokio::task::JoinError>), Err(Result<ReadEnd, tokio::task::JoinError>), Fault(Option<BridgeError>), Stop }

async fn drive(inner: Arc<Inner>, owner: Arc<Owner>, bytes: Vec<u8>) -> DriverEnd {
    let mut resources = owner.resources.lock().await;
    if owner.failed() || Instant::now() >= owner.endpoint() {
        owner.fail(BridgeError::timeout());
        return DriverEnd::Ready(Err(BridgeError::timeout()));
    }
    let config = inner.runtime.clone();
    let endpoint = owner.endpoint();
    let profile = owner.profile;
    #[cfg(all(test, feature = "development-runtime"))]
    let inspection_gate = inner.test.inspection.clone();
    #[cfg(all(windows, test, feature = "development-runtime"))]
    let windows_bootstrap = lock(&inner.test.windows_bootstrap).clone();
    #[cfg(all(test, debug_assertions, feature = "development-runtime", target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    let github_fixture = lock(&inner.test.github_fixture).clone();
    #[cfg(all(test, debug_assertions, feature = "development-runtime", target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    let github_tls = lock(&inner.test.github_tls).clone();
    resources.inspection = Some(tokio::task::spawn_blocking(move || {
        #[cfg(all(test, feature = "development-runtime"))]
        inspection_gate.wait();
        let runtime = match profile {
            Profile::Passive(_) => config.resolve(endpoint)?,
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
    let inspected = join_slot(&mut resources.inspection).await;
    #[cfg(all(test, feature = "development-runtime"))]
    if inspected.is_ok() { lock(&owner.observation).inspection_joined = true; }
    let runtime = match inspected {
        Ok(Ok(runtime)) => { resources.inspection.take(); runtime },
        Ok(Err(error)) => {
            resources.inspection.take();
            owner.fail(error.clone()); // Original detection, not later management-return scheduling.
            return DriverEnd::Ready(Err(error));
        }
        Err(_) => { owner.unknown(&inner); return DriverEnd::RetainedUnknown; }
    };
    if owner.failed() || Instant::now() >= owner.endpoint() {
        owner.fail(BridgeError::timeout());
        return DriverEnd::Ready(Err(BridgeError::timeout()));
    }
    // Blocking startup cannot starve the independent deadline watchdog. Its
    // original result/Child remains in this retained acquisition handle.
    let acquiring_owner = owner.clone();
    #[cfg(all(test, feature = "development-runtime"))]
    let acquisition_gate = inner.test.acquisition.clone();
    resources.acquisition = Some(tokio::task::spawn_blocking(move || {
        // Scheduling instrumentation inside THIS retained original task,
        // before spawn_original's two final creation checks. No new deadline.
        #[cfg(all(test, feature = "development-runtime"))]
        acquisition_gate.wait();
        spawn_original(runtime, acquiring_owner)
    }));
    let acquired = join_slot(&mut resources.acquisition).await;
    #[cfg(all(test, feature = "development-runtime"))]
    if acquired.is_ok() { lock(&owner.observation).acquisition_joined = true; }
    resources.child = match acquired {
        Ok(Ok(child)) => { resources.acquisition.take(); Some(child) },
        Ok(Err(_)) => {
            resources.acquisition.take();
            let error = BridgeError::unavailable("The selected isolated core could not start.");
            owner.fail(error.clone());
            return DriverEnd::Ready(Err(error));
        }
        Err(_) => { owner.unknown(&inner); return DriverEnd::RetainedUnknown; }
    };
    #[cfg(all(test, feature = "development-runtime"))]
    { lock(&owner.observation).spawned = true; }
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

#[cfg(test)]
mod tests {
    // Pure bookkeeping only. These tests do not start a runtime or child and do
    // not establish native process finality. Genuine IO/fault tests are hosted.
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
}
