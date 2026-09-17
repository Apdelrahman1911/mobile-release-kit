//! Original-child owner for the closed passive API methods only. Never reuse this
//! for builds, hooks, signing, or an engine that can spawn descendants.
//!
//! An independent watchdog includes blocking runtime inspection and spawn time.
//! Renderer cancellation only drops a reply receiver, never these owner tasks.
//! After the one cleanup allowance, uncertainty is reported and ownership is
//! retained; an existing driver may settle later but cannot turn it into success.
use std::{collections::BTreeMap, future::pending, process::ExitStatus, sync::{Arc, Mutex, MutexGuard, atomic::{AtomicBool, AtomicU64, Ordering}}, time::{Duration, Instant}};
#[cfg(all(feature = "development-runtime", debug_assertions))]
use std::process::Stdio;
use serde_json::Value;
use tokio::{io::{AsyncRead, AsyncReadExt, AsyncWriteExt}, process::Child, sync::{mpsc, oneshot, watch, Mutex as AsyncMutex, Notify, OwnedSemaphorePermit, Semaphore}, task::JoinHandle};
#[cfg(all(feature = "development-runtime", debug_assertions))]
use tokio::process::Command;
use crate::{error::BridgeError, protocol::{self, Method}, runtime::{RuntimeConfig, VerifiedRuntime}};

pub const OPERATION_TIME: Duration = Duration::from_secs(10);
pub const CLEANUP_TIME: Duration = Duration::from_secs(2);
const ACTIVE_LIMIT: usize = 2;

#[cfg(all(test, feature = "development-runtime"))]
#[path = "hosted_tests.rs"]
mod hosted_tests;

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
    key: u64, id: String, state: Mutex<OwnerState>, resources: AsyncMutex<Resources>,
    stop: watch::Sender<bool>, changed: Notify, permit: Mutex<Option<OwnedSemaphorePermit>>,
    driver: Mutex<Option<JoinHandle<()>>>, watchdog: Mutex<Option<JoinHandle<()>>>,
    #[cfg(all(test, feature = "development-runtime"))]
    observation: Arc<Mutex<hosted_tests::Observation>>,
}
struct OwnerState {
    endpoint: Instant, cleanup_endpoint: Option<Instant>, error: Option<BridgeError>,
    terminal: bool, unknown: bool,
    reply: Option<oneshot::Sender<Result<Value, BridgeError>>>,
}
#[derive(Default)]
struct Resources {
    inspection: Option<JoinHandle<Result<VerifiedRuntime, BridgeError>>>,
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
        if state.error.is_none() { state.error = Some(error); }
        if state.cleanup_endpoint.is_none() {
            state.cleanup_endpoint = Some(Instant::now().min(state.endpoint) + CLEANUP_TIME);
        }
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
        if state.error.is_none() { state.error = Some(BridgeError::cleanup_unknown()); }
        if state.cleanup_endpoint.is_none() { state.cleanup_endpoint = Some(Instant::now().min(state.endpoint) + CLEANUP_TIME); }
        if let Some(reply) = state.reply.take() { let _ = reply.send(Err(BridgeError::cleanup_unknown())); }
        drop(state);
        self.stop.send_replace(true);
        inner.changed.notify_waiters();
        self.changed.notify_waiters();
    }
    fn finish(&self, inner: &Inner, result: Result<Value, BridgeError>) {
        let mut state = lock(&self.state);
        if state.terminal { return; }
        if Instant::now() >= state.endpoint && state.error.is_none() { state.error = Some(BridgeError::timeout()); }
        let result = match &state.error { Some(error) => Err(error.clone()), None => result };
        state.terminal = true;
        if let Some(reply) = state.reply.take() { let _ = reply.send(result); }
        drop(state);
        lock(&self.permit).take();
        lock(&inner.owners).remove(&self.key);
        inner.changed.notify_waiters();
        self.changed.notify_waiters();
    }
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
        let endpoint = Instant::now() + OPERATION_TIME;
        if self.disabled() { return Err(BridgeError::cleanup_unknown()); }
        if self.stopping() { return Err(BridgeError::shutdown()); }
        let permit = self.inner.permits.clone().try_acquire_owned()
            .map_err(|_| BridgeError::new("busy", "Two read-only queries already own the available slots."))?;
        let key = self.inner.next.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |value| value.checked_add(1))
            .map_err(|_| BridgeError::new("unavailable", "The query identity space is exhausted."))?;
        let id = format!("query-{key}");
        let bytes = protocol::encode_request(&id, method, &params)?;
        let (reply, receiver) = oneshot::channel();
        let (stop, _) = watch::channel(false);
        let owner = Arc::new(Owner {
            key, id, state: Mutex::new(OwnerState { endpoint, cleanup_endpoint: None, error: None, terminal: false, unknown: false, reply: Some(reply) }),
            resources: AsyncMutex::new(Resources::default()), stop, changed: Notify::new(),
            permit: Mutex::new(Some(permit)), driver: Mutex::new(None), watchdog: Mutex::new(None),
            #[cfg(all(test, feature = "development-runtime"))]
            observation: Arc::new(Mutex::new(hosted_tests::Observation::default())),
        });
        {
            let mut owners = lock(&self.inner.owners);
            // Serialize registration with shutdown's stop-and-inventory boundary.
            if self.stopping() { return Err(BridgeError::shutdown()); }
            if self.disabled() { return Err(BridgeError::cleanup_unknown()); }
            owners.insert(key, owner.clone());
        }
        #[cfg(all(test, feature = "development-runtime"))]
        self.inner.test.register(owner.clone());
        let watch_owner = owner.clone();
        let watch_inner = self.inner.clone();
        *lock(&owner.watchdog) = Some(tokio::spawn(async move { watchdog(watch_inner, watch_owner).await; }));
        let drive_owner = owner.clone();
        let drive_inner = self.inner.clone();
        *lock(&owner.driver) = Some(tokio::spawn(async move { drive(drive_inner, drive_owner, bytes).await; }));
        // No owner/task cancellation on receiver abandonment. The registry retains
        // Child, IO tasks, startup handles and permits until actual settlement.
        receiver.await.unwrap_or_else(|_| {
            owner.unknown(&self.inner);
            Err(BridgeError::cleanup_unknown())
        })
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

async fn watchdog(inner: Arc<Inner>, owner: Arc<Owner>) {
    loop {
        let changed = owner.changed.notified();
        let (terminal, failure, endpoint) = {
            let state = lock(&owner.state);
            (state.terminal, state.error.is_some(), state.cleanup_endpoint.unwrap_or(state.endpoint))
        };
        if terminal { return; }
        if Instant::now() >= endpoint {
            if failure { owner.unknown(&inner); return; }
            owner.fail(BridgeError::timeout());
            continue;
        }
        tokio::select! {
            _ = changed => {},
            _ = tokio::time::sleep_until(tokio::time::Instant::from_std(endpoint)) => {}
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

async fn drive(inner: Arc<Inner>, owner: Arc<Owner>, bytes: Vec<u8>) {
    let mut resources = owner.resources.lock().await;
    if owner.failed() || Instant::now() >= owner.endpoint() {
        owner.fail(BridgeError::timeout());
        owner.finish(&inner, Err(BridgeError::timeout()));
        return;
    }
    let config = inner.runtime.clone();
    let endpoint = owner.endpoint();
    #[cfg(all(test, feature = "development-runtime"))]
    let inspection_gate = inner.test.inspection.clone();
    resources.inspection = Some(tokio::task::spawn_blocking(move || {
        #[cfg(all(test, feature = "development-runtime"))]
        inspection_gate.wait();
        config.resolve(endpoint)
    }));
    let inspected = join_slot(&mut resources.inspection).await;
    #[cfg(all(test, feature = "development-runtime"))]
    if inspected.is_ok() { lock(&owner.observation).inspection_joined = true; }
    let runtime = match inspected {
        Ok(Ok(runtime)) => { resources.inspection.take(); runtime },
        Ok(Err(error)) => { resources.inspection.take(); owner.finish(&inner, Err(error)); return; }
        Err(_) => { owner.unknown(&inner); return; }
    };
    if owner.failed() || Instant::now() >= owner.endpoint() {
        owner.fail(BridgeError::timeout());
        owner.finish(&inner, Err(BridgeError::timeout()));
        return;
    }
    // Blocking startup cannot starve the independent deadline watchdog. Its
    // original result/Child remains in this retained acquisition handle.
    let acquiring_owner = owner.clone();
    resources.acquisition = Some(tokio::task::spawn_blocking(move || spawn_original(runtime, acquiring_owner)));
    let acquired = join_slot(&mut resources.acquisition).await;
    #[cfg(all(test, feature = "development-runtime"))]
    if acquired.is_ok() { lock(&owner.observation).acquisition_joined = true; }
    resources.child = match acquired {
        Ok(Ok(child)) => { resources.acquisition.take(); Some(child) },
        Ok(Err(_)) => { resources.acquisition.take(); owner.finish(&inner, Err(BridgeError::unavailable("The selected isolated core could not start."))); return; }
        Err(_) => { owner.unknown(&inner); return; }
    };
    #[cfg(all(test, feature = "development-runtime"))]
    { lock(&owner.observation).spawned = true; }
    let (stdin, stdout, stderr) = match resources.child.as_mut() {
        Some(child) => (child.stdin.take(), child.stdout.take(), child.stderr.take()),
        None => { owner.unknown(&inner); return; }
    };
    let (faults, mut fault_rx) = mpsc::channel(4);
    if let Some(stdin) = stdin { resources.writer = Some(tokio::spawn(write_request(stdin, bytes, owner.stop.subscribe(), faults.clone()))); }
    if let Some(stdout) = stdout {
        #[cfg(all(test, feature = "development-runtime"))]
        { resources.stdout = Some(tokio::spawn(hosted_tests::observed_read(stdout, protocol::RESPONSE_LIMIT, faults.clone(), owner.observation.clone(), Some(inner.test.stdout_join.clone()), false))); }
        #[cfg(not(all(test, feature = "development-runtime")))]
        { resources.stdout = Some(tokio::spawn(read_bounded(stdout, protocol::RESPONSE_LIMIT, faults.clone()))); }
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
            let child = match resources.child.as_mut() { Some(child) => child, None => { owner.unknown(&inner); return; } };
            match child.try_wait() {
                Ok(Some(status)) => {
                    #[cfg(all(test, feature = "development-runtime"))]
                    { let mut observed = lock(&owner.observation); observed.waited = true; observed.exit_success = Some(status.success()); }
                    resources.waited = Some(status);
                }
                Ok(None) => { if child.start_kill().is_err() { owner.fail(BridgeError::cleanup_unknown()); } }
                Err(_) => { owner.unknown(&inner); return; }
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
                { let mut observed = lock(&owner.observation); observed.waited = true; observed.exit_success = Some(status.success()); }
                if !status.success() { owner.fail(BridgeError::new("engine_failed", "The isolated core exited unsuccessfully.")); }
                resources.waited = Some(status);
            }
            Event::Wait(Err(_)) => { owner.unknown(&inner); return; }
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
        owner.unknown(&inner); return;
    }
    let eofs = resources.out_end.as_ref().is_some_and(|end| end.eof) && resources.err_end.as_ref().is_some_and(|end| end.eof);
    if !eofs { owner.unknown(&inner); return; }
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
    let result = match output { Some(output) => protocol::decode_response(&output.bytes, &owner.id), None => Err(BridgeError::protocol()) };
    if let Err(error) = &result { owner.fail(error.clone()); }
    owner.finish(&inner, result);
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
            key: 1, id: "query-1".into(),
            state: Mutex::new(OwnerState { endpoint: Instant::now() + OPERATION_TIME, cleanup_endpoint: None, error: None, terminal: false, unknown: false, reply: None }),
            resources: AsyncMutex::new(Resources::default()), stop, changed: Notify::new(),
            permit: Mutex::new(None), driver: Mutex::new(None), watchdog: Mutex::new(None),
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
}
