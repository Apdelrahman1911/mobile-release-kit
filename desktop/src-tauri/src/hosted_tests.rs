//! Ignored disposable-hosted checks, never local/native execution authority.
//! One fixed batch; original process facts are observed, never synthesized.
//! Scheduling gates are explicitly not OS stuck-spawn/wait/close qualification.
use super::*;
use std::{fs, future::Future, path::{Path, PathBuf}, sync::Condvar, task::Poll};
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};

type Check<T> = Result<T, &'static str>;
type Query = Result<Value, BridgeError>;
const FIXTURE: &str = include_str!("../tests/fixtures/passive_core/_desktop_engine.py");
const PACKAGE: &str = include_str!("../tests/fixtures/passive_core/__init__.py");

// Separate exact-two-case conventional preparation. Never changes the old23
// entry/receipt, TLS profile, production gate or native owner implementation.
#[cfg(all(debug_assertions, not(feature = "desktop-shell"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
#[path = "conventional_smoke_tests.rs"]
mod conventional_smoke;

// Two fixed modes only. No arbitrary bootstrap path/callback or production opt-in.
#[cfg(windows)]
#[derive(Clone, Default)]
pub(super) enum WindowsBootstrap {
    #[default]
    Ordinary,
    Snapshot { group: &'static str, id: &'static str, nonce: String, binding: String, manifest: String },
}

#[cfg(windows)]
pub(super) fn select_windows_bootstrap(runtime: VerifiedRuntime, selection: WindowsBootstrap,
    endpoint: Instant) -> Result<VerifiedRuntime, BridgeError> {
    windows_snapshot::select(runtime, selection, endpoint).map_err(|_| {
        if Instant::now() >= endpoint { BridgeError::timeout() }
        else { BridgeError::unavailable("The fixed hosted Windows fixture copy or descriptor was not admitted.") }
    })
}

#[derive(Clone, Default, Serialize)]
pub(super) struct Observation {
    pub inspection_joined: bool, pub acquisition_joined: bool, pub spawned: bool,
    pub waited: bool, pub exit_success: Option<bool>,
    pub writer_joined: bool, pub writer_complete: bool,
    pub stdout_eof: bool, pub stderr_eof: bool, pub stdout_joined: bool, pub stderr_joined: bool,
    pub stdout_bytes: usize, pub stderr_bytes: usize,
    pub driver_joined: bool, pub watchdog_joined: bool,
    #[serde(skip)]
    pub observer_joined: bool,
    #[cfg(all(debug_assertions, target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    #[serde(skip)]
    pub github_initial_environment: Option<bool>,
    // Private copies only. In particular the passive-hosted-v2 serialized
    // observation and its M1/M2 field set are unchanged.
    #[cfg(windows)]
    #[serde(skip)]
    pub windows_stderr: Vec<u8>,
    #[cfg(windows)]
    #[serde(skip)]
    pub windows_exit_code: Option<i32>,
}

#[derive(Default)]
pub(super) struct BlockingGate { closed: Mutex<bool>, changed: Condvar, entered: AtomicBool }
impl BlockingGate {
    fn close(&self) { *lock(&self.closed) = true; }
    pub(super) fn wait(&self) {
        let mut closed = lock(&self.closed);
        if !*closed { return; }
        self.entered.store(true, Ordering::SeqCst);
        while *closed { closed = self.changed.wait(closed).unwrap_or_else(|error| error.into_inner()); }
    }
    fn release(&self) { *lock(&self.closed) = false; self.changed.notify_all(); }
}

pub(super) struct JoinGate { open: watch::Sender<bool>, entered: AtomicBool }
impl Default for JoinGate {
    fn default() -> Self { let (open, _) = watch::channel(true); Self { open, entered: AtomicBool::new(false) } }
}
impl JoinGate {
    fn close(&self) { self.open.send_replace(false); }
    pub(super) async fn wait(&self) {
        let mut open = self.open.subscribe();
        if *open.borrow() { return; }
        self.entered.store(true, Ordering::SeqCst);
        loop {
            let released = *open.borrow_and_update();
            if released || open.changed().await.is_err() { return; }
        }
    }
    fn release(&self) { self.open.send_replace(true); }
}

#[derive(Default)]
pub(super) struct Hooks {
    pub inspection: Arc<BlockingGate>, pub acquisition: Arc<BlockingGate>, pub stdout_join: Arc<JoinGate>,
    pub driver_return: Arc<JoinGate>, pub watchdog_return: Arc<JoinGate>,
    owners: Mutex<Vec<Arc<Owner>>>,
    #[cfg(windows)]
    pub(super) windows_bootstrap: Mutex<WindowsBootstrap>,
    #[cfg(all(debug_assertions, target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    pub(super) github_fixture: Mutex<Option<github_fixture::GitHubFixtureRuntime>>,
    #[cfg(all(debug_assertions, target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    pub(super) github_tls: Mutex<Option<github_tls::GitHubTlsRuntime>>,
    #[cfg(all(debug_assertions, target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    pub(super) github_observe_environment: AtomicBool,
    #[cfg(all(debug_assertions, target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    github_document_minted: AtomicBool,
}
impl Hooks {
    pub(super) fn register(&self, owner: Arc<Owner>) { lock(&self.owners).push(owner); }
    fn owners(&self) -> Vec<Arc<Owner>> { lock(&self.owners).clone() }
    fn release(&self) {
        self.inspection.release(); self.acquisition.release(); self.stdout_join.release();
        self.driver_return.release(); self.watchdog_return.release();
    }
}

pub(super) async fn observed_read<R: AsyncRead + Unpin>(reader: R, limit: usize, faults: mpsc::Sender<BridgeError>,
    observation: Arc<Mutex<Observation>>, gate: Option<Arc<JoinGate>>, stderr: bool) -> ReadEnd {
    let end = read_bounded(reader, limit, faults).await;
    {
        let mut observed = lock(&observation);
        if stderr {
            observed.stderr_eof = end.eof; observed.stderr_bytes = end.bytes.len();
            #[cfg(windows)]
            { observed.windows_stderr = end.bytes.clone(); }
        }
        else { observed.stdout_eof = end.eof; observed.stdout_bytes = end.bytes.len(); }
    }
    if let Some(gate) = gate { gate.wait().await; }
    end
}

fn require(value: bool, code: &'static str) -> Check<()> { if value { Ok(()) } else { Err(code) } }
fn hash(bytes: &[u8]) -> String { format!("{:x}", Sha256::digest(bytes)) }
fn environment(name: &str) -> Check<String> { std::env::var(name).map_err(|_| "missing_hosted_input") }
#[cfg(all(debug_assertions, target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
pub(super) fn original_child_environment(original_id: u32) -> Result<Option<bool>, ()> {
    use std::{io::Read, os::unix::fs::OpenOptionsExt};
    if original_id == 0 { return Ok(None); }
    let path = PathBuf::from(format!("/proc/{original_id}/environ"));
    let flags = rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK | rustix::fs::OFlags::CLOEXEC;
    let mut bytes = [0u8; 8193];
    let Ok(mut original) = fs::OpenOptions::new().read(true).custom_flags(flags.bits() as i32).open(path) else { return Ok(None); };
    let read = (|| {
        let mut length = 0;
        while length < bytes.len() {
            let count = original.read(&mut bytes[length..]).map_err(|_| ())?;
            if count == 0 { return Ok(length); }
            length += count;
        }
        Err(())
    })();
    let closed = nix::unistd::close(original).is_ok(); // One original close; no numeric retry.
    let allowed = match read {
        Ok(length) if length > 0 && length <= 8192 && bytes[length - 1] == 0 => {
            let entries = bytes[..length - 1].split(|byte| *byte == 0).collect::<Vec<_>>();
            Some(entries.len() == 2 && entries.contains(&b"LANG=C".as_slice()) && entries.contains(&b"LC_ALL=C".as_slice()))
        },
        _ => None,
    };
    bytes.fill(0); // Only the allowlist boolean leaves this original reader.
    if closed { Ok(allowed) } else { Err(()) }
}
fn selected(name: &str) -> Check<PathBuf> {
    let path = PathBuf::from(environment(name)?);
    require(path.is_absolute(), "hosted_input_not_absolute")?;
    path.canonicalize().map_err(|_| "hosted_input_unavailable")
}
fn bounded_hash(path: &Path, limit: u64) -> Check<String> {
    let metadata = fs::symlink_metadata(path).map_err(|_| "hash_input_unavailable")?;
    require(metadata.is_file() && metadata.len() <= limit, "hash_input_limit")?;
    let bytes = fs::read(path).map_err(|_| "hash_input_read_failed")?;
    require(bytes.len() as u64 == metadata.len(), "hash_input_changed")?;
    Ok(hash(&bytes))
}

struct Inputs { root: PathBuf, source: PathBuf, zip: PathBuf, bindings: Value }
impl Inputs {
    fn admit() -> Check<Self> {
        Self::admit_mode("passive-v1")
    }
    fn admit_mode(mode: &'static str) -> Check<Self> {
        Self::admit_scoped(mode, None)
    }
    fn admit_scoped(mode: &'static str, scope: Option<&'static str>) -> Check<Self> {
        // Defense in depth only: runner scheduling must also be approved before
        // the triggering push. Setting these strings is not execution authority.
        require(environment("MRK_DESKTOP_HOSTED_CHECKS")? == mode
            && environment("GITHUB_ACTIONS")? == "true"
            && environment("RUNNER_ENVIRONMENT")? == "github-hosted", "hosted_admission_required")?;
        require(matches!(std::env::consts::OS, "linux" | "macos" | "windows"), "unsupported_host")?;
        let mut root = selected("MRK_DESKTOP_TEST_ROOT")?;
        if let Some(scope) = scope {
            require(mode == "github-readonly-tls-deadline-v1" && matches!(scope, "hosts" | "dns-withhold"), "hosted_scope")?;
            root = root.join(scope);
            fs::create_dir(&root).map_err(|_| "hosted_scope_not_fresh")?;
        }
        require(fs::read_dir(&root).map_err(|_| "test_root_unavailable")?.next().is_none(), "test_root_not_fresh")?;
        let source = selected("MRK_DESKTOP_DEV_CORE")?;
        let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
        let desktop = manifest.parent().ok_or("source_layout")?;
        let expected = desktop.parent().ok_or("source_layout")?.join("src").canonicalize().map_err(|_| "source_layout")?;
        require(source == expected && !source.starts_with(&root), "core_not_exact_checkout")?;
        let zip = selected("MRK_DESKTOP_TEST_CORE_ZIP")?;
        require(!zip.starts_with(&root) && zip.extension().is_some_and(|extension| extension == "zip"), "core_zip_layout")?;
        let python = selected("MRK_DESKTOP_DEV_PYTHON")?;
        require(python.is_file(), "python_not_regular")?;
        // Resolve only the trusted setup output, never an ambient/project route.
        std::env::set_var("MRK_DESKTOP_DEV_PYTHON", python);
        let source_sha = environment("GITHUB_SHA")?;
        require(matches!(source_sha.len(), 40 | 64) && source_sha.bytes().all(|c| c.is_ascii_hexdigit()), "source_sha_shape")?;
        let bindings = json!({
            "sourceSha": source_sha, "host": std::env::consts::OS,
            "target": crate::runtime::COMPILED_TARGET, "runtimeMode": "trusted-development-only",
            "coreZipSha256": bounded_hash(&zip, 32 * 1024 * 1024)?,
            "engineSha256": bounded_hash(&source.join("mobile_release/_desktop_engine.py"), 128 * 1024)?,
            "bootstrapSha256": bounded_hash(&desktop.join("engine_bootstrap.py"), 128 * 1024)?,
            "cargoLockSha256": bounded_hash(&manifest.join("Cargo.lock"), 1024 * 1024)?,
            "fixtureSha256": hash(FIXTURE.as_bytes()),
        });
        Ok(Self { root, source, zip, bindings })
    }
}

struct Receipt { path: PathBuf, bindings: Value, cases: Vec<Value> }
impl Receipt {
    fn write(&self, state: &str, code: Option<&str>) -> Check<()> {
        let bytes = serde_json::to_vec(&json!({"schemaVersion":1, "scope":"passive-hosted-v2",
            "status":state, "allOwnersSettled":state == "passed", "failureCode":code, "bindings":self.bindings, "cases":self.cases,
            "notVerified":["native-gui", "production-runtime-custody", "native-stuck-wait-close", "windows-filesystem", "installers", "mobile-builds", "stores"]}))
            .map_err(|_| "receipt_encoding")?;
        require(bytes.len() <= 64 * 1024, "receipt_limit")?;
        fs::write(&self.path, bytes).map_err(|_| "receipt_write")
    }
}

struct Case {
    name: &'static str, root: PathBuf, control: PathBuf, nonce: String, supervisor: Supervisor,
    callers: Vec<Option<JoinHandle<Query>>>, results: Vec<Value>, notes: Value, begin: Instant,
    #[cfg(all(debug_assertions, target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    github: Option<Arc<Mutex<github_fixture::Retained>>>,
}
impl Case {
    fn new(inputs: &Inputs, name: &'static str, mode: Option<&str>, zip: bool) -> Check<Self> {
        let root = inputs.root.join(name);
        fs::create_dir(&root).map_err(|_| "case_directory")?;
        let control = root.join("control");
        fs::create_dir(&control).map_err(|_| "control_directory")?;
        let nonce = hash(root.to_string_lossy().as_bytes()); // Fresh root, not an authorizing secret.
        let core = if let Some(mode) = mode {
            let core = root.join("fixture");
            let package = core.join("mobile_release");
            fs::create_dir(&core).and_then(|_| fs::create_dir(&package)).map_err(|_| "fixture_directory")?;
            fs::write(package.join("__init__.py"), PACKAGE).map_err(|_| "fixture_write")?;
            fs::write(package.join("_desktop_engine.py"), FIXTURE).map_err(|_| "fixture_write")?;
            let config = serde_json::to_vec(&json!({"mode":mode,"control":control,"nonce":nonce})).map_err(|_| "fixture_encoding")?;
            fs::write(package.join("case.json"), config).map_err(|_| "fixture_write")?;
            core
        } else if zip { inputs.zip.clone() } else { inputs.source.clone() };
        // Called only after the preceding case's startup/child/IO/owner tasks
        // have ALL settled. No per-query environment races or fixture mutation.
        std::env::set_var("MRK_DESKTOP_DEV_CORE", core);
        Ok(Self { name, root, control, nonce, supervisor: Supervisor::new(RuntimeConfig::packaged(inputs.root.clone())),
            callers: Vec::new(), results: Vec::new(), notes: json!({}), begin: Instant::now(),
            #[cfg(all(debug_assertions, target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
            github: None,
        })
    }
    fn start(&mut self, method: Method, params: Value) -> usize {
        let supervisor = self.supervisor.clone();
        self.callers.push(Some(tokio::spawn(async move { supervisor.query(method, params).await })));
        self.callers.len() - 1
    }
    async fn result(&mut self, index: usize) -> Check<Query> {
        let slot = self.callers.get_mut(index).ok_or("caller_index")?;
        let task = slot.as_mut().ok_or("caller_already_consumed")?;
        let outcome = tokio::time::timeout(OPERATION_TIME + CLEANUP_TIME + Duration::from_secs(3), task).await
            .map_err(|_| "caller_observation_timeout")?;
        slot.take();
        let result = outcome.map_err(|_| "caller_task_failed")?;
        self.results.push(match &result { Ok(_) => json!({"return":"ok"}), Err(error) => json!({"return":"error","code":error.code}) });
        Ok(result)
    }
    fn owner(&self, id: &str) -> Check<Arc<Owner>> {
        self.supervisor.inner.test.owners().into_iter().find(|owner| owner.id == id).ok_or("owner_missing")
    }
    async fn ready(&self, id: &str, phase: &str) -> Check<()> {
        let path = self.control.join(format!("ready-{id}.json"));
        let expected = json!({"nonce":self.nonce,"id":id,"phase":phase});
        until(Duration::from_secs(4), || {
            let Ok(metadata) = fs::symlink_metadata(&path) else { return false; };
            if !metadata.is_file() || metadata.len() > 512 { return false; }
            fs::read(&path).ok().and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok()).is_some_and(|value| value == expected)
        }).await.map_err(|_| "fixture_readiness_timeout")
    }
    fn release_one(&self, id: &str) -> Check<()> {
        let path = self.control.join(format!("release-{id}.json"));
        let bytes = serde_json::to_vec(&json!({"nonce":self.nonce,"id":id,"release":true})).map_err(|_| "release_encoding")?;
        if path.exists() { return require(fs::read(path).ok().as_deref() == Some(bytes.as_slice()), "release_changed"); }
        let temporary = self.control.join(format!("release-{id}.tmp"));
        fs::write(&temporary, bytes).map_err(|_| "release_write")?;
        fs::rename(temporary, path).map_err(|_| "release_rename")
    }
    async fn abandon_caller(&mut self, index: usize, owner: &Owner) -> Check<()> {
        let slot = self.callers.get_mut(index).ok_or("caller_index")?;
        let task = slot.as_mut().ok_or("caller_already_consumed")?;
        task.abort(); // ONLY the renderer/caller task, never an owner or IO task.
        let outcome = task.await;
        slot.take();
        require(outcome.is_err_and(|error| error.is_cancelled()), "caller_not_abandoned")?;
        require(lock(&owner.state).reply.as_ref().is_some_and(|reply| reply.is_closed()), "reply_receiver_not_closed")?;
        self.results.push(json!({"return":"caller-abandoned","oneshotClosed":true}));
        Ok(())
    }
    async fn settle(&mut self, failed: bool) -> bool {
        self.supervisor.inner.test.release(); // Every gate, on every path.
        #[cfg(all(debug_assertions, target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
        self.github_begin_cleanup();
        let owners = self.supervisor.inner.test.owners();
        let mut releases_ok = true;
        for owner in &owners { releases_ok &= self.release_one(&owner.id).is_ok(); }
        if failed { let _ = self.supervisor.shutdown().await; }
        let all_finished = || {
            self.supervisor.can_exit() && self.supervisor.inner.permits.available_permits() == ACTIVE_LIMIT
                && owners.iter().all(|owner| lock(&owner.state).terminal
                    && lock(&owner.state).driver_join == ManagementJoin::Returned
                    && lock(&owner.state).watchdog_join == ManagementJoin::Returned
                    && owner.observer.try_lock().is_ok_and(|slot| slot.as_ref().is_some_and(JoinHandle::is_finished)))
                && self.callers.iter().flatten().all(JoinHandle::is_finished)
                && {
                    #[cfg(all(debug_assertions, target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
                    { self.github_material_ready() }
                    #[cfg(not(all(debug_assertions, target_os = "linux", target_arch = "x86_64", target_env = "gnu")))]
                    { true }
                }
        };
        if until(Duration::from_secs(3), all_finished).await.is_err() {
            let _ = self.supervisor.shutdown().await; // Existing allowances, never renewed.
            if until(Duration::from_secs(3), all_finished).await.is_err() { return false; }
        }
        for owner in &owners {
            // Product code alone consumed driver/watchdog. Read its actual
            // receipts, then join only the original final observer's now-data-
            // only tail before changing this fixture's development inputs.
            let mut observer = owner.observer.lock().await;
            let observer_ok = match observer.as_mut() { Some(task) => task.await.is_ok(), None => false };
            if !observer_ok { return false; }
            observer.take();
            drop(observer);
            lock(&owner.observation).observer_joined = true;
            {
                let state = lock(&owner.state);
                let observed = lock(&owner.observation);
                if !state.terminal || state.driver_join != ManagementJoin::Returned
                    || state.watchdog_join != ManagementJoin::Returned
                    || !observed.driver_joined || !observed.watchdog_joined { return false; }
            }
            let resources = owner.resources.lock().await;
            #[cfg(all(debug_assertions, target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
            if resources.github_environment.is_some() { return false; }
            if resources.inspection.is_some() || resources.acquisition.is_some() || resources.child.is_some()
                || resources.writer.is_some() || resources.stdout.is_some() || resources.stderr.is_some()
                || resources.failed_writer.is_some() || resources.failed_stdout.is_some() || resources.failed_stderr.is_some() { return false; }
        }
        for slot in &mut self.callers {
            if let Some(task) = slot.as_mut() {
                let joined = task.await.is_ok();
                slot.take();
                if !joined { return false; }
            }
        }
        if !releases_ok { self.notes["releaseFileFailure"] = json!(true); }
        #[cfg(all(debug_assertions, target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
        if !self.github_finish_retention() { return false; }
        true // Resource finality, not the test's expected-result assertion.
    }
    fn native_facts(&self, child_expected: bool, writer_complete: bool) -> Check<()> {
        let owners = self.supervisor.inner.test.owners();
        require(!owners.is_empty(), "no_original_owner_observed")?;
        for owner in owners {
            let observed = lock(&owner.observation);
            require(observed.inspection_joined && observed.driver_joined && observed.watchdog_joined, "startup_owner_not_joined")?;
            require(observed.spawned == child_expected, "unexpected_native_spawn_state")?;
            if child_expected {
                require(observed.acquisition_joined && observed.waited && observed.stdout_eof && observed.stderr_eof
                    && observed.writer_joined && observed.stdout_joined && observed.stderr_joined, "native_terminal_prerequisite_missing")?;
                require(!writer_complete || observed.writer_complete, "writer_not_complete")?;
                require(observed.stdout_bytes <= owner.profile.stdout_limit() && observed.stderr_bytes <= protocol::STDERR_LIMIT, "retained_output_exceeds_limit")?;
            }
        }
        require(self.notes.get("releaseFileFailure").is_none(), "release_file_failure")
    }
    fn evidence(&self, passed: bool, failure: Option<&str>) -> Value {
        let owners: Vec<Value> = self.supervisor.inner.test.owners().iter().map(|owner| {
            let state = lock(&owner.state);
            json!({"id":owner.id, "terminal":state.terminal, "unknownLatched":state.unknown,
                "permitRetained":lock(&owner.permit).is_some(), "native":lock(&owner.observation).clone()})
        }).collect();
        json!({"case":self.name, "passed":passed,"failureCode":failure,"elapsedMs":self.begin.elapsed().as_millis(),
            "evidenceKind":if self.name.starts_with("controlled-") {"scheduling-control-not-os-fault"} else {"actual-passive-child"},
            "results":self.results,"notes":self.notes,"owners":owners,
            "registeredOwners":lock(&self.supervisor.inner.owners).len(),"disabled":self.supervisor.disabled()})
    }
}
impl Drop for Case { fn drop(&mut self) { self.supervisor.inner.test.release(); } }

async fn until(mut allowance: Duration, mut condition: impl FnMut() -> bool) -> Check<()> {
    // Observer margin only. Never changes an owner's operation/cleanup endpoint.
    allowance = allowance.min(Duration::from_secs(15));
    let end = Instant::now() + allowance;
    loop {
        if condition() { return Ok(()); }
        if Instant::now() >= end { return Err("observation_timeout"); }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}
fn value(result: Query) -> Check<Value> { result.map_err(|_| "unexpected_service_error") }
fn rejection(result: Query, code: &str) -> Check<()> {
    require(result.is_err_and(|error| error.code == code && !error.retryable), "unexpected_rejection")
}
fn draft() -> Value {
    json!({"schemaVersion":1,"version":{"source":"release/version.properties","nameKey":"VERSION_NAME","buildKey":"BUILD_NUMBER"},
        "source":{"candidateBranch":"main","productionBranch":"main"},
        "android":{"enabled":true,"applicationId":"org.fixture.app","identityStatus":"unverified"},"ios":{"enabled":false},
        "metadata":{"root":"release/store","androidLocales":["en-US"],"iosLocales":[]},
        "services":{"androidFirebase":"disabled","iosFirebase":"disabled"},
        "projectChecks":{"preflight":[],"androidArtifact":[],"iosArtifact":[]}})
}

fn native_ready_before_management(owner: &Owner) -> Check<()> {
    let observed = lock(&owner.observation);
    require(observed.inspection_joined && observed.acquisition_joined && observed.spawned
        && observed.waited && observed.exit_success == Some(true) && observed.writer_complete
        && observed.writer_joined && observed.stdout_eof && observed.stderr_eof
        && observed.stdout_joined && observed.stderr_joined, "management_gate_missing_original_native_facts")
}

fn management_still_pending(case: &Case, index: usize, owner: &Arc<Owner>, driver: ManagementJoin) -> Check<()> {
    // Same registry -> state -> permit lock order as the actual retirement.
    let owners = lock(&case.supervisor.inner.owners);
    let state = lock(&owner.state);
    require(owners.len() == 1 && owners.get(&owner.key).is_some_and(|original| Arc::ptr_eq(original, owner))
        && !state.terminal && !state.unknown && state.error.is_none()
        && state.reply.is_some() && state.driver_join == driver && state.watchdog_join == ManagementJoin::Pending
        && lock(&owner.permit).is_some() && case.supervisor.inner.permits.available_permits() == ACTIVE_LIMIT - 1
        && case.callers.get(index).and_then(Option::as_ref).is_some_and(|task| !task.is_finished()),
        "management_return_accepted_before_original_join")
}

async fn exercise_management(case: &mut Case) -> Check<()> {
    let late = case.name == "controlled-management-late";
    let gates = &case.supervisor.inner.test;
    if !late { gates.driver_return.close(); }
    gates.watchdog_return.close(); // Fixed before original owner admission.
    let index = case.start(Method::Capabilities, json!({}));
    if !late {
        until(Duration::from_secs(4), || case.supervisor.inner.test.driver_return.entered.load(Ordering::SeqCst)).await?;
        let owner = case.owner("query-1")?;
        native_ready_before_management(&owner)?;
        management_still_pending(case, index, &owner, ManagementJoin::Pending)?;
        case.notes["nativeSettledBeforeManagementReturns"] = json!(true);
        case.notes["driverReturnHeldBeforeReply"] = json!(true);
        case.supervisor.inner.test.driver_return.release();
    }
    until(Duration::from_secs(4), || case.supervisor.inner.test.watchdog_return.entered.load(Ordering::SeqCst)).await?;
    let owner = case.owner("query-1")?;
    native_ready_before_management(&owner)?;
    management_still_pending(case, index, &owner, ManagementJoin::Returned)?;
    if !late {
        case.notes["watchdogReturnHeldBeforeReply"] = json!(true);
        case.supervisor.inner.test.watchdog_return.release();
        let returned = value(case.result(index).await?)?;
        return require(returned["mode"] == "read-only-foundation", "management_case_core_result");
    }

    case.notes["nativeSettledBeforeWatchdogReturn"] = json!(true);
    let mut shutdown = Box::pin(case.supervisor.shutdown());
    let first_poll = std::future::poll_fn(|cx| Poll::Ready(shutdown.as_mut().poll(cx))).await;
    require(first_poll.is_pending(), "management_shutdown_was_not_pending")?;
    let original_endpoint = lock(&owner.state).cleanup_endpoint.ok_or("management_cleanup_endpoint_missing")?;
    require(shutdown.await.is_err_and(|error| error.code == "cleanup_unknown"), "management_shutdown_did_not_expire")?;
    // The observing shutdown ceiling may wake first; wait for the actual owner
    // decision, without changing or granting another original cleanup endpoint.
    until(Duration::from_secs(1), || lock(&owner.state).unknown).await?;
    require(Instant::now() >= original_endpoint && case.supervisor.disabled()
        && !case.supervisor.can_exit() && *owner.stop.borrow()
        && lock(&case.supervisor.inner.owners).get(&owner.key).is_some_and(|original| Arc::ptr_eq(original, &owner))
        && lock(&owner.permit).is_some() && case.supervisor.inner.permits.available_permits() == ACTIVE_LIMIT - 1,
        "management_late_return_not_retained")?;
    {
        let state = lock(&owner.state);
        require(!state.terminal && state.unknown && state.cleanup_endpoint == Some(original_endpoint)
            && state.driver_join == ManagementJoin::Returned && state.watchdog_join == ManagementJoin::Pending
            && state.error.as_ref().is_some_and(|error| error.code == "shutting_down"), "management_late_state_changed")?;
    }
    rejection(case.result(index).await?, "cleanup_unknown")?;
    require(case.supervisor.shutdown().await.is_err_and(|error| error.code == "cleanup_unknown"), "management_repeat_shutdown_changed")?;
    rejection(case.supervisor.query(Method::Capabilities, json!({})).await, "cleanup_unknown")?;
    require(lock(&owner.state).cleanup_endpoint == Some(original_endpoint), "management_cleanup_endpoint_renewed")?;
    case.notes["originalCleanupEndpointUnchanged"] = json!(true);
    case.notes["retainedWhileUnknown"] = json!(true);
    case.notes["newQueryRefused"] = json!(true);
    // Common settle releases every gate before its original-tail accounting.
    Ok(())
}

async fn exercise(case: &mut Case) -> Check<()> {
    match case.name {
        "controlled-management-returns" | "controlled-management-late" => exercise_management(case).await,
        "core-capabilities" => {
            let index = case.start(Method::Capabilities, json!({}));
            let result = value(case.result(index).await?)?;
            let methods = result["methods"].as_array().ok_or("capabilities_shape")?;
            for method in ["capabilities", "catalog", "project.snapshot", "config.validate"] {
                require(methods.iter().any(|entry| entry["method"] == method), "capability_missing")?;
            }
            require(result["mode"] == "read-only-foundation", "capabilities_mode")
        }
        "core-catalog" | "core-zip-catalog" => {
            let index = case.start(Method::Catalog, json!({}));
            let result = value(case.result(index).await?)?;
            require(result["schema"].is_object() && result["fields"].as_array().is_some_and(|items| !items.is_empty()), "catalog_shape")
        }
        "core-valid-draft" | "core-invalid-draft" => {
            let valid = case.name == "core-valid-draft";
            let index = case.start(Method::ValidateConfig, json!({"draft": if valid {draft()} else {json!({"schemaVersion":false})}}));
            let result = value(case.result(index).await?)?;
            require(result["valid"] == valid && result["assurance"]["releaseReadiness"] == "unknown", "draft_result")
        }
        "core-service-error" => {
            let index = case.start(Method::Catalog, json!({"unsupported":true}));
            rejection(case.result(index).await?, "invalid_params")
        }
        "core-snapshot" => {
            let project = case.root.join("project");
            fs::create_dir(&project).map_err(|_| "snapshot_fixture")?;
            fs::create_dir(project.join("release")).map_err(|_| "snapshot_fixture")?;
            fs::write(project.join("release/mobile-release.json"), serde_json::to_vec(&draft()).map_err(|_| "snapshot_fixture")?).map_err(|_| "snapshot_fixture")?;
            fs::write(project.join("package.json"), b"{\"name\":\"inert-fixture\",\"version\":\"1.0.0\"}").map_err(|_| "snapshot_fixture")?;
            let index = case.start(Method::ProjectSnapshot, json!({"root":project}));
            let result = case.result(index).await?;
            if cfg!(windows) { rejection(result, "platform_unavailable") }
            else {
                let result = value(result)?;
                require(result["config"]["state"] == "format-valid" && result["discovery"]["state"] == "unverified"
                    && result["assurance"]["releaseReadiness"] == "unknown", "snapshot_result")
            }
        }
        "malformed" | "truncated" | "extra_frames" | "wrong_id" | "nonzero_exit" | "stdout_limit" | "stderr_limit" => {
            let index = case.start(Method::Capabilities, json!({}));
            let code = match case.name { "nonzero_exit" => "engine_failed", "stdout_limit" | "stderr_limit" => "output_limit", _ => "protocol_error" };
            rejection(case.result(index).await?, code)
        }
        "pipe_pressure" => {
            let index = case.start(Method::ValidateConfig, json!({"draft":{"padding":"r".repeat(900_000)}}));
            let result = value(case.result(index).await?)?;
            require(result["pressure"].as_str().is_some_and(|text| text.len() == 256 * 1024), "pressure_result")
        }
        "delay_exit" => {
            let index = case.start(Method::Capabilities, json!({}));
            case.ready("query-1", "pipes-closed-child-held").await?;
            let owner = case.owner("query-1")?;
            until(Duration::from_secs(2), || { let observed = lock(&owner.observation); observed.stdout_eof && observed.stderr_eof }).await?;
            require(!lock(&owner.observation).waited && !lock(&owner.state).terminal
                && case.callers[index].as_ref().is_some_and(|task| !task.is_finished()), "reply_accepted_before_original_wait")?;
            case.notes["replyPendingAfterEof"] = json!(true);
            case.release_one("query-1")?;
            value(case.result(index).await?).map(|_| ())
        }
        "busy-abandon" => {
            let first = case.start(Method::Capabilities, json!({}));
            case.ready("query-1", "request-eof").await?;
            // Tie the first caller to the first owner, not Tokio scheduling order.
            let second = case.start(Method::Capabilities, json!({}));
            case.ready("query-2", "request-eof").await?;
            let third = case.start(Method::Capabilities, json!({}));
            rejection(case.result(third).await?, "busy")?;
            let owner = case.owner("query-1")?;
            case.abandon_caller(first, &owner).await?;
            require(lock(&case.supervisor.inner.owners).len() == 2 && lock(&owner.permit).is_some()
                && !lock(&owner.state).terminal, "abandonment_lost_owner")?;
            case.notes["ownerRetainedAfterReceiverClose"] = json!(true);
            case.release_one("query-1")?; case.release_one("query-2")?;
            value(case.result(second).await?).map(|_| ())
        }
        "operation-timeout" => {
            let index = case.start(Method::ValidateConfig, json!({"draft":{"padding":"r".repeat(900_000)}}));
            case.ready("query-1", "input-unread").await?;
            rejection(case.result(index).await?, "query_timeout")?;
            let owner = case.owner("query-1")?;
            let state = lock(&owner.state);
            require(case.begin.elapsed() >= OPERATION_TIME && state.cleanup_endpoint == Some(state.endpoint + CLEANUP_TIME), "operation_deadline_contract")
        }
        "shutdown-active" => {
            let index = case.start(Method::Capabilities, json!({}));
            case.ready("query-1", "request-eof").await?;
            case.supervisor.shutdown().await.map_err(|_| "shutdown_not_settled")?;
            rejection(case.result(index).await?, "shutting_down")?;
            let owner = case.owner("query-1")?;
            let endpoint = lock(&owner.state).cleanup_endpoint;
            case.supervisor.shutdown().await.map_err(|_| "repeat_shutdown_failed")?;
            require(endpoint.is_some() && lock(&owner.state).cleanup_endpoint == endpoint, "shutdown_renewed_cleanup")
        }
        "controlled-startup" | "controlled-io-join" => {
            let startup = case.name == "controlled-startup";
            if startup { case.supervisor.inner.test.inspection.close(); } else { case.supervisor.inner.test.stdout_join.close(); }
            let index = case.start(Method::Capabilities, json!({}));
            rejection(case.result(index).await?, "cleanup_unknown")?;
            let owner = case.owner("query-1")?;
            require(case.supervisor.disabled() && !case.supervisor.can_exit() && lock(&owner.permit).is_some()
                && lock(&owner.state).unknown && *owner.stop.borrow(), "unknown_not_retained")?;
            let entered = if startup { case.supervisor.inner.test.inspection.entered.load(Ordering::SeqCst) }
                else { case.supervisor.inner.test.stdout_join.entered.load(Ordering::SeqCst) };
            require(entered, "control_gate_not_entered")?;
            if startup { require(!lock(&owner.observation).spawned, "expired_startup_spawned")?; }
            else { let observed = lock(&owner.observation); require(observed.waited && observed.stdout_eof && !observed.stdout_joined, "join_control_missing_native_facts")?; }
            rejection(case.supervisor.query(Method::Capabilities, json!({})).await, "cleanup_unknown")?;
            case.notes["retainedWhileUnknown"] = json!(true);
            case.notes["newQueryRefused"] = json!(true);
            // Common cleanup releases the gate; post-cleanup checks require
            // actual late settlement without clearing disabled/unknown/error.
            Ok(())
        }
        _ => Err("unlisted_case"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "only the reviewed disposable GitHub-hosted passive verification workflow"]
async fn passive_hosted_contract() {
    let inputs = match Inputs::admit() { Ok(inputs) => inputs, Err(code) => panic!("hosted passive admission failed: {code}") };
    let mut receipt = Receipt { path: inputs.root.join("receipt.json"), bindings: inputs.bindings.clone(), cases: Vec::new() };
    if receipt.write("running", None).is_err() { panic!("hosted passive receipt unavailable before native work"); }
    // Fixed batch, not arbitrary user-selected test/fixture commands.
    let cases = [
        ("core-capabilities", None), ("core-catalog", None), ("core-zip-catalog", None),
        ("core-valid-draft", None), ("core-invalid-draft", None), ("core-service-error", None), ("core-snapshot", None),
        ("malformed", Some("malformed")), ("truncated", Some("truncated")), ("extra_frames", Some("extra_frames")),
        ("wrong_id", Some("wrong_id")), ("nonzero_exit", Some("nonzero_exit")),
        ("pipe_pressure", Some("pipe_pressure")), ("stdout_limit", Some("stdout_limit")), ("stderr_limit", Some("stderr_limit")),
        ("delay_exit", Some("delay_exit")), ("busy-abandon", Some("wait_release")),
        ("operation-timeout", Some("stalled_input")), ("shutdown-active", Some("wait_release")),
        ("controlled-startup", Some("echo")), ("controlled-io-join", Some("echo")),
        ("controlled-management-returns", None), ("controlled-management-late", None),
    ];
    for (name, mode) in cases {
        let mut case = match Case::new(&inputs, name, mode, name == "core-zip-catalog") {
            Ok(case) => case,
            Err(code) => { let _ = receipt.write("failed", Some(code)); panic!("hosted fixture preparation failed: {code}"); }
        };
        let mut checked = exercise(&mut case).await;
        if !case.settle(checked.is_err()).await {
            receipt.cases.push(case.evidence(false, Some("custody_unresolved")));
            let _ = receipt.write("failed-retained", Some("custody_unresolved"));
            // Preserve the live runtime, original owners/resources and fixture
            // selection until infrastructure disposal. No next case, owner abort,
            // PID lookup, process-tree kill or false clean-success receipt.
            pending::<()>().await;
            return;
        }
        if checked.is_ok() { checked = case.native_facts(name != "controlled-startup", name != "operation-timeout"); }
        if checked.is_ok() && name == "busy-abandon" {
            checked = require(case.supervisor.inner.test.owners().iter().all(|owner|
                lock(&owner.state).error.is_none() && lock(&owner.observation).exit_success == Some(true)), "abandoned_owner_did_not_finish_normally");
        }
        if checked.is_ok() && matches!(name, "controlled-startup" | "controlled-io-join" | "controlled-management-late") {
            checked = require(case.supervisor.disabled() && case.supervisor.can_exit()
                && case.supervisor.inner.test.owners().iter().all(|owner| { let state = lock(&owner.state); state.unknown && state.terminal && state.error.is_some() }), "late_settlement_cleared_failure");
            if checked.is_ok() && name == "controlled-management-late" { case.notes["lateJoinPreservedFailure"] = json!(true); }
        }
        if checked.is_ok() && name == "controlled-management-returns" {
            checked = require(!case.supervisor.disabled() && case.supervisor.can_exit()
                && case.supervisor.inner.test.owners().iter().all(|owner| { let state = lock(&owner.state); !state.unknown && state.terminal && state.error.is_none() }), "management_healthy_retirement_changed");
        }
        receipt.cases.push(case.evidence(checked.is_ok(), checked.err()));
        if let Err(code) = checked { let _ = receipt.write("failed", Some(code)); panic!("hosted passive check failed after settlement: {code}"); }
        if receipt.write("running", None).is_err() { panic!("hosted passive receipt failed after settlement"); }
    }
    std::env::set_var("MRK_DESKTOP_DEV_CORE", &inputs.source); // All work settled.
    if receipt.write("passed", None).is_err() { panic!("hosted passive final receipt failed after settlement"); }
}

// This separate literal entry is deliberately outside every inert test roster.
// It exercises the original private owner, NOT TLS or a real native document.
#[cfg(all(debug_assertions, target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "only the reviewed disposable GitHub-hosted G1 owner verification workflow"]
async fn github_readonly_hosted_contract() { github_fixture::run().await; }

#[cfg(all(debug_assertions, target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
pub(crate) mod github_fixture {
    use super::*;
    use crate::{asset_session::DocumentBinding, asset_source::{self, SourceBook},
        bridge::{DesktopBridge, Project}, github_connection_protocol::{self as wire, FactState, Phase, Reason, SessionState}};

    const GITHUB_FIXTURE: &[u8] = include_bytes!("../tests/fixtures/github_core/_desktop_github_engine.py");
    const GITHUB_BOOTSTRAP: &[u8] = include_bytes!("../../github_connection_bootstrap.py");
    const TOKEN: &str = "INERT_NOT_A_CREDENTIAL";
    const LIMITATIONS: &[&str] = &["live-transport", "authenticated-remote-facts", "native-gui",
        "webview-callbacks-or-crash-hook", "production-runtime-custody", "production-github-enablement",
        "native-stuck-wait-close", "macos-windows-github", "credentials", "stores", "mobile-builds", "installers"];

    struct RuntimeBinding { python: PathBuf, python_size: u64, python_sha256: String, core: PathBuf, case: Vec<u8> }
    /// Immutable selection minted only below after hosted admission and the
    /// finite fixture copy. Clone shares this binding, not a new permission.
    #[derive(Clone)]
    pub(crate) struct GitHubFixtureRuntime { original: Arc<RuntimeBinding> }
    impl GitHubFixtureRuntime {
        pub(crate) fn python_binding(&self) -> (&Path, u64, &str) {
            (&self.original.python, self.original.python_size, &self.original.python_sha256)
        }
        pub(crate) fn core(&self) -> &Path { &self.original.core }
        pub(crate) fn case_bytes(&self) -> &[u8] { &self.original.case }
        fn same(&self, other: &Self) -> bool { Arc::ptr_eq(&self.original, &other.original) }
    }

    /// Non-clonable, private construction and single consumption for exactly
    /// one original Supervisor/document. This does not qualify asset services.
    pub(crate) struct GitHubDocumentFixturePermit { supervisor: Supervisor, selection: GitHubFixtureRuntime }
    pub(crate) struct GitHubDocumentFixtureBinding { supervisor: Supervisor, selection: GitHubFixtureRuntime }
    impl GitHubDocumentFixturePermit {
        fn mint(supervisor: &Supervisor) -> Check<Self> {
            require(supervisor.can_exit() && !supervisor.stopping() && !supervisor.disabled()
                && supervisor.inner.test.owners().is_empty()
                && supervisor.inner.permits.available_permits() == ACTIVE_LIMIT, "g1_document_not_fresh")?;
            let selection = lock(&supervisor.inner.test.github_fixture).clone().ok_or("g1_fixture_not_bound")?;
            require(supervisor.inner.test.github_document_minted.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).is_ok(),
                "g1_document_permission_already_minted")?;
            Ok(Self { supervisor: supervisor.clone(), selection })
        }
        pub(crate) fn consume(self, supervisor: &Supervisor) -> Check<GitHubDocumentFixtureBinding> {
            require(Arc::ptr_eq(&self.supervisor.inner, &supervisor.inner)
                && lock(&supervisor.inner.test.github_fixture).as_ref().is_some_and(|selection| self.selection.same(selection))
                && supervisor.can_exit() && !supervisor.stopping() && !supervisor.disabled(), "g1_document_permission_mismatch")?;
            Ok(GitHubDocumentFixtureBinding { supervisor: self.supervisor, selection: self.selection })
        }
    }
    impl GitHubDocumentFixtureBinding {
        pub(crate) fn permits(&self, supervisor: &Supervisor) -> bool {
            // Identity, not current readiness. Stopping/Unknown must retain the
            // original document's access to genuine late-settlement observation.
            Arc::ptr_eq(&self.supervisor.inner, &supervisor.inner)
                && lock(&supervisor.inner.test.github_fixture).as_ref().is_some_and(|selection| self.selection.same(selection))
        }
    }

    pub(super) struct Retained {
        supervisor: Supervisor, bridge: Arc<DesktopBridge>, document: Option<DocumentBinding>,
        tickets: Vec<Option<GitHubReadTicket>>, books: Vec<SourceBook>,
    }
    // Retain before document/probe/read admission. Even an unexpected unwind
    // must not drop a possibly used token/book or authorize the next Case.
    static RETAINED: Mutex<Option<Arc<Mutex<Retained>>>> = Mutex::new(None);

    struct Admitted { inputs: Inputs, python: PathBuf, python_size: u64, python_sha256: String }
    impl Admitted {
        fn new() -> Check<Self> {
            let mut inputs = Inputs::admit_mode("github-readonly-v1")?;
            require(crate::runtime::COMPILED_TARGET == "x86_64-unknown-linux-gnu"
                && lock(&RETAINED).is_none(), "g1_host_or_previous_custody")?;
            let python = selected("MRK_DESKTOP_DEV_PYTHON")?;
            let python_size = fs::metadata(&python).map_err(|_| "g1_python_metadata")?.len();
            require(python_size > 0 && python_size <= 512 * 1024 * 1024, "g1_python_size")?;
            let python_sha256 = bounded_hash(&python, 512 * 1024 * 1024)?;
            let desktop = Path::new(env!("CARGO_MANIFEST_DIR")).parent().ok_or("source_layout")?;
            require(bounded_hash(&desktop.join("github_connection_bootstrap.py"), 128 * 1024)? == hash(GITHUB_BOOTSTRAP),
                "g1_bootstrap_compiled_binding")?;
            inputs.bindings["githubBootstrapSha256"] = json!(hash(GITHUB_BOOTSTRAP));
            inputs.bindings["githubFixtureSha256"] = json!(hash(GITHUB_FIXTURE));
            inputs.bindings["packageSha256"] = json!(hash(PACKAGE.as_bytes()));
            inputs.bindings["pythonSha256"] = json!(python_sha256);
            inputs.bindings["pythonBytes"] = json!(python_size);
            Ok(Self { inputs, python, python_size, python_sha256 })
        }
        fn case(&self, name: &'static str, mode: &'static str) -> Check<Case> {
            require(lock(&RETAINED).is_none(), "g1_previous_case_retained")?;
            let mut case = Case::new(&self.inputs, name, Some(mode), false)?;
            let core = case.root.join("fixture");
            fs::write(core.join("mobile_release/_desktop_github_engine.py"), GITHUB_FIXTURE).map_err(|_| "g1_fixture_write")?;
            let configuration = serde_json::to_vec(&json!({"mode":mode,"control":case.control,"nonce":case.nonce}))
                .map_err(|_| "g1_fixture_configuration")?;
            require(configuration.len() <= 16 * 1024
                && fs::read(core.join("mobile_release/case.json")).ok().as_deref() == Some(configuration.as_slice()),
                "g1_fixture_configuration_binding")?;
            let selection = GitHubFixtureRuntime { original: Arc::new(RuntimeBinding { python: self.python.clone(),
                python_size: self.python_size, python_sha256: self.python_sha256.clone(), core, case: configuration }) };
            *lock(&case.supervisor.inner.test.github_fixture) = Some(selection);
            // Both constructors are inert. Install the already-fresh Case's
            // original Supervisor before the bridge/document can admit work.
            let mut bridge = DesktopBridge::new(self.inputs.root.clone());
            bridge.supervisor = case.supervisor.clone();
            let retained = Arc::new(Mutex::new(Retained { supervisor: case.supervisor.clone(), bridge: Arc::new(bridge),
                document: None, tickets: Vec::new(), books: Vec::new() }));
            *lock(&RETAINED) = Some(retained.clone());
            case.github = Some(retained);
            Ok(case)
        }
    }

    impl Case {
        fn github_retained(&self) -> Check<Arc<Mutex<Retained>>> { self.github.clone().ok_or("g1_retention_missing") }
        fn github_start(&mut self, refresh: bool) -> Check<usize> {
            let retained = self.github_retained()?;
            let mut retained = lock(&retained);
            require(retained.tickets.len() < 3, "g1_ticket_limit")?;
            let ticket = self.supervisor.start_github_readonly("owner/app", refresh.then_some("11"), refresh.then_some("22"), TOKEN)
                .map_err(|_| "g1_admission_refused")?;
            retained.tickets.push(Some(ticket));
            Ok(retained.tickets.len() - 1)
        }
        fn github_receipt(&self, index: usize) -> Check<GitHubReadReceipt> {
            let retained = self.github_retained()?;
            let retained = lock(&retained);
            retained.tickets.get(index).and_then(Option::as_ref).map(GitHubReadTicket::receipt).ok_or("g1_ticket_missing")
        }
        async fn github_result(&mut self, index: usize) -> Check<GitHubReadReceipt> {
            until(OPERATION_TIME + CLEANUP_TIME + Duration::from_secs(2), ||
                self.github_receipt(index).is_ok_and(|receipt| !matches!(receipt, GitHubReadReceipt::Pending))).await?;
            let receipt = self.github_receipt(index)?;
            self.results.push(receipt_result(&receipt));
            Ok(receipt)
        }
        fn drop_github_ticket(&mut self, index: usize) -> Check<()> {
            let retained = self.github_retained()?;
            let mut retained = lock(&retained);
            let ticket = retained.tickets.get_mut(index).and_then(Option::take).ok_or("g1_ticket_missing")?;
            let original = ticket.owner.clone();
            drop(ticket); // No abort/stop/permit change; Hooks keeps this owner.
            require(original.github_receipt.is_some() && lock(&original.permit).is_some()
                && !lock(&original.state).terminal, "g1_ticket_drop_lost_owner")?;
            self.results.push(json!({"return":"ticket-dropped","ownerRetained":true}));
            Ok(())
        }
        pub(super) fn github_begin_cleanup(&self) {
            if let Some(retained) = &self.github {
                if let Some(document) = &lock(retained).document { document.lost(); }
            }
        }
        pub(super) fn github_material_ready(&self) -> bool {
            let Some(retained) = &self.github else { return true; };
            let Ok(retained) = retained.try_lock() else { return false; };
            if let Some(document) = &retained.document {
                let _ = document.github_connection_status(); // Actual reconciliation, not a supplied receipt.
                if !document.github_fixture_material_settled() { return false; }
            }
            retained.books.iter().all(SourceBook::settled)
                && retained.tickets.iter().flatten().all(|ticket| matches!(ticket.receipt(), GitHubReadReceipt::Settled { .. }))
                && retained.bridge.edits.can_exit()
        }
        pub(super) fn github_finish_retention(&mut self) -> bool {
            let Some(retained) = &self.github else { return true; };
            if !self.github_material_ready() { return false; }
            let mut slot = lock(&RETAINED);
            if !slot.as_ref().is_some_and(|original| Arc::ptr_eq(original, retained)) { return false; }
            let mut state = lock(retained);
            if !Arc::ptr_eq(&state.supervisor.inner, &self.supervisor.inner) { return false; }
            self.notes["originalRetentionSettled"] = json!(true);
            if state.document.is_some() {
                self.notes["sourceBooksSettled"] = json!(state.books.len());
                self.notes["documentMaterialSettled"] = json!(true);
            }
            state.tickets.clear(); // Only actual final receipts have been observed.
            slot.take();
            true
        }
        fn document(&self) -> Check<DocumentBinding> {
            let retained = self.github_retained()?;
            let retained = lock(&retained);
            retained.document.clone().ok_or("g1_document_missing")
        }
        fn bind_document(&mut self) -> Check<()> {
            let retained = self.github_retained()?;
            let mut retained = lock(&retained);
            require(retained.document.is_none(), "g1_document_already_bound")?;
            let permit = GitHubDocumentFixturePermit::mint(&self.supervisor)?;
            let document = DocumentBinding::for_github_fixture(retained.bridge.clone(), permit)?;
            retained.document = Some(document.clone()); // Retain before any supplied lifetime event.
            require(document.navigation(true), "g1_original_navigation_refused")?;
            document.observe(|life| life.started(true)); document.hook_installed(); document.observe(|life| life.finished(true));
            require(document.github_connection_status().capability.read_only_session_available, "g1_document_not_available")?;
            self.notes["documentEvidence"] = json!("controlled-original-lifetime-not-gui-callbacks");
            Ok(())
        }
        fn register_project(&mut self, leaf: &'static str) -> Check<Project> {
            require(matches!(leaf, "project" | "project-next"), "g1_project_not_fixed")?;
            let path = self.root.join(leaf);
            fs::create_dir(&path).map_err(|_| "g1_project_directory")?;
            let retained = self.github_retained()?;
            let mut retained = lock(&retained);
            require(retained.books.len() < 2 && retained.books.iter().all(SourceBook::settled), "g1_probe_custody")?;
            let generation = retained.bridge.native_generation().map_err(|_| "g1_registry_unavailable")?;
            retained.books.push(SourceBook::new()); // Retain before acquisition, including unwind/failure.
            let book = retained.books.last_mut().ok_or("g1_probe_book_missing")?;
            let endpoint = Instant::now() + OPERATION_TIME;
            let proof = std::panic::catch_unwind(std::panic::AssertUnwindSafe(||
                asset_source::probe_project(book, path.clone(), &[], &mut || Instant::now() >= endpoint)))
                .map_err(|_| "g1_probe_unwind")?;
            require(book.settled(), "g1_probe_not_settled")?;
            let proof = proof.map_err(|_| "g1_project_probe_refused")?;
            let document = retained.document.as_ref().ok_or("g1_document_missing")?;
            let project = document.github_fixture_publish(proof, generation).map_err(|_| "g1_registry_publication_refused")?;
            let (current, registered) = retained.bridge.native_project(&project.id).map_err(|_| "g1_registry_lookup_refused")?;
            require(current > generation && registered.path == path
                && retained.bridge.github_registration(&project.id).ok() == Some(current), "g1_registered_project_mismatch")?;
            Ok(project)
        }
    }

    fn receipt_result(receipt: &GitHubReadReceipt) -> Value {
        match receipt {
            GitHubReadReceipt::Pending => json!({"return":"pending"}),
            GitHubReadReceipt::RetainedUnknown => json!({"return":"retained-unknown"}),
            GitHubReadReceipt::Settled { outcome, was_unknown, .. } => match outcome {
                Ok(_) => json!({"return":"github-facts","wasUnknown":was_unknown}),
                Err(error) => json!({"return":"error","code":error.code,"wasUnknown":was_unknown}),
            },
        }
    }

    fn valid_status(status: &wire::Status) -> Check<()> {
        let bytes = serde_json::to_vec(status).map_err(|_| "g1_status_encoding")?;
        require(wire::decode_status(&bytes).is_ok()
            && !bytes.windows(TOKEN.len()).any(|part| part == TOKEN.as_bytes()), "g1_status_contract")
    }
    fn connect(document: &DocumentBinding, project: &Project) -> Check<wire::Status> {
        let status = document.github_connection_connect_token(&json!({"projectId":project.id,"repository":"owner/app","token":TOKEN}))
            .map_err(|_| "g1_document_connect_refused")?;
        valid_status(&status)?;
        require(status.operation.as_ref().is_some_and(|operation| operation.phase == Phase::Running), "g1_connect_not_running")?;
        Ok(status)
    }
    fn disconnected(document: &DocumentBinding, session: &str) -> Check<wire::Status> {
        let status = document.github_connection_disconnect(&json!({"sessionId":session})).map_err(|_| "g1_document_disconnect_refused")?;
        valid_status(&status)?; Ok(status)
    }
    fn session_id(status: &wire::Status) -> Check<&str> { status.session.as_ref().map(|session| session.id.as_str()).ok_or("g1_session_missing") }
    fn operation_id(status: &wire::Status) -> Check<&str> { status.operation.as_ref().map(|operation| operation.id.as_str()).ok_or("g1_operation_missing") }
    fn mailbox(owner: &Owner) -> Check<GitHubReadReceipt> {
        owner.github_receipt.as_ref().map(|receipt| lock(receipt).clone()).ok_or("g1_mailbox_missing")
    }
    async fn settled_mailbox(owner: &Owner) -> Check<GitHubReadReceipt> {
        until(Duration::from_secs(4), || mailbox(owner).is_ok_and(|receipt| matches!(receipt, GitHubReadReceipt::Settled { .. }))).await?;
        mailbox(owner)
    }
    async fn connected(document: &DocumentBinding) -> Check<wire::Status> {
        until(Duration::from_secs(4), || document.github_connection_status().session.as_ref()
            .is_some_and(|session| session.state == SessionState::Connected)).await?;
        let status = document.github_connection_status(); valid_status(&status)?;
        require(status.capability.read_only_session_available && status.account.state == FactState::Observed
            && status.account.value.as_ref().is_some_and(|account| account.id == "11")
            && status.repository.value.as_ref().is_some_and(|repository| repository.id == "22")
            && status.operation.as_ref().is_some_and(|operation| operation.phase == Phase::Settled && operation.reason == Reason::None),
            "g1_connected_facts_missing")?;
        Ok(status)
    }
    fn document_admission_refused(document: &DocumentBinding, project: &Project, session: &str, code: &str) -> Check<()> {
        require(document.github_connection_connect_token(&json!({"projectId":project.id,"repository":"owner/app","token":TOKEN}))
            .is_err_and(|error| error.code == code), "g1_connect_not_refused")?;
        let status = document.github_connection_status();
        require(document.github_connection_refresh(&json!({"sessionId":session,"expectedRevision":status.revision}))
            .is_err_and(|error| error.code == code), "g1_refresh_not_refused")
    }
    async fn exercise_document(case: &mut Case) -> Check<()> {
        if case.name == "g1-document-connect-refresh" {
            let retained = case.github_retained()?;
            let ordinary = DocumentBinding::new(lock(&retained).bridge.clone());
            let unrelated = DocumentBinding::new(Arc::new(DesktopBridge::new(case.root.clone())));
            // Intentionally malformed input: unqualified rejection must win
            // before the borrowed credential decoder is allowed to run.
            for document in [ordinary, unrelated] {
                require(document.github_connection_connect_token(&json!({"unexpected":true}))
                    .is_err_and(|error| error.code == "github_connection_refused_unqualified"), "g1_ordinary_document_admitted")?;
            }
            require(case.supervisor.inner.test.owners().is_empty(), "g1_ordinary_document_started_owner")?;
            case.notes["ordinaryAndUnrelatedRefusedBeforeDecode"] = json!(true);
        }
        case.bind_document()?;
        let project = case.register_project("project")?;
        let document = case.document()?;
        let held = matches!(case.name, "g1-document-disconnect-held" | "g1-document-loss");
        if held { case.supervisor.inner.test.driver_return.close(); }
        if case.name == "g1-document-unknown-late" { case.supervisor.inner.test.watchdog_return.close(); }
        let admitted = connect(&document, &project)?;
        let session = session_id(&admitted)?.to_owned();
        let original_id = operation_id(&admitted)?.to_owned();
        require(original_id == "github-read-1", "g1_document_original_id")?;
        let owner = case.owner(&original_id)?;
        match case.name {
            "g1-document-connect-refresh" => {
                let first = connected(&document).await?;
                let expiry = first.session.as_ref().and_then(|session| session.expires_at.clone());
                let endpoint = owner.endpoint();
                let observed = document.github_connection_status();
                require(observed == first && case.supervisor.inner.test.owners().len() == 1 && owner.endpoint() == endpoint,
                    "g1_status_started_work_or_renewed_clock")?;
                let refreshed = document.github_connection_refresh(&json!({"sessionId":session,"expectedRevision":observed.revision}))
                    .map_err(|_| "g1_refresh_refused")?;
                valid_status(&refreshed)?;
                require(operation_id(&refreshed)? == "github-read-2" && operation_id(&refreshed)? != original_id,
                    "g1_refresh_identity_reused")?;
                let refreshed = connected(&document).await?;
                require(refreshed.session.as_ref().and_then(|session| session.expires_at.clone()) == expiry
                    && refreshed.session.as_ref().is_some_and(|value| value.id == session)
                    && case.supervisor.inner.test.owners().len() == 2, "g1_refresh_session_or_expiry_changed")?;
                case.notes["statusStartsNoRead"] = json!(true);
                case.notes["refreshPinsAndOriginalExpiryPreserved"] = json!(true);
                let status = disconnected(&document, &session)?;
                require(status.session.is_none() && document.github_fixture_material_settled(), "g1_completed_disconnect_material")?;
                Ok(())
            },
            "g1-document-disconnect-held" => {
                until(Duration::from_secs(4), || case.supervisor.inner.test.driver_return.entered.load(Ordering::SeqCst)).await?;
                native_ready_before_management(&owner)?;
                let before = document.github_connection_status();
                require(document.github_connection_disconnect(&json!({"sessionId":"github-session-other"}))
                    .is_err_and(|error| error.code == "github_connection_refused_invalid_input")
                    && document.github_connection_status() == before, "g1_wrong_disconnect_changed_session")?;
                let first = disconnected(&document, &session)?;
                let endpoint = lock(&owner.state).cleanup_endpoint.ok_or("g1_disconnect_endpoint_missing")?;
                require(!first.capability.read_only_session_available && !document.github_fixture_material_settled()
                    && matches!(mailbox(&owner)?, GitHubReadReceipt::Pending), "g1_disconnect_dropped_pending_material")?;
                let repeated = disconnected(&document, &session)?;
                require(repeated == first && lock(&owner.state).cleanup_endpoint == Some(endpoint), "g1_disconnect_renewed_or_changed")?;
                case.supervisor.inner.test.driver_return.release();
                settled_mailbox(&owner).await?;
                let after = document.github_connection_status(); valid_status(&after)?;
                require(after.session.is_none() && after.account.state != FactState::Observed
                    && document.github_fixture_material_settled(), "g1_late_result_restored_disconnect")?;
                case.notes["wrongSessionUnchanged"] = json!(true);
                case.notes["pendingMaterialRetained"] = json!(true);
                case.notes["originalCleanupEndpointUnchanged"] = json!(true);
                case.notes["lateReceiptCannotRestoreSession"] = json!(true);
                Ok(())
            },
            "g1-document-registry-change" => {
                require(matches!(settled_mailbox(&owner).await?, GitHubReadReceipt::Settled { outcome: Ok(_), was_unknown: false, .. }),
                    "g1_registry_case_not_positive_original")?;
                // No status call consumed that positive receipt. Publication
                // mutates the real registry under the actual document lock.
                let next = case.register_project("project-next")?;
                require(next.id != project.id, "g1_registry_generation_not_changed")?;
                let status = document.github_connection_status(); valid_status(&status)?;
                require(!status.capability.read_only_session_available && status.capability.reason == Reason::TargetChanged
                    && status.account.state != FactState::Observed && status.repository.state != FactState::Observed
                    && status.operation.as_ref().is_some_and(|operation| operation.phase == Phase::Settled && operation.reason == Reason::TargetChanged)
                    && document.github_fixture_material_settled(), "g1_registry_change_consumed_stale_positive")?;
                case.notes["registryRecheckedBeforePositiveReceipt"] = json!(true);
                Ok(())
            },
            "g1-document-loss" => {
                case.ready(&original_id, "request-eof").await?;
                document.lost(); // Actual document loss path; supplied event, not OS callback proof.
                let status = document.github_connection_status(); valid_status(&status)?;
                require(!status.capability.read_only_session_available && status.capability.reason == Reason::Cancelled
                    && *owner.stop.borrow() && !document.github_fixture_material_settled(), "g1_document_loss_not_synchronous")?;
                document_admission_refused(&document, &project, &session, "github_connection_refused_cancelled")?;
                disconnected(&document, &session)?;
                case.supervisor.inner.test.driver_return.release();
                settled_mailbox(&owner).await?;
                let status = document.github_connection_status(); valid_status(&status)?;
                require(!status.capability.read_only_session_available && status.session.is_none()
                    && document.github_fixture_material_settled(), "g1_document_loss_resurrected")?;
                case.notes["actualLossPathRetiredSynchronously"] = json!(true);
                case.notes["newAdmissionRefusedAfterLoss"] = json!(true);
                case.notes["lateReceiptCannotRestoreSession"] = json!(true);
                Ok(())
            },
            "g1-document-unknown-late" => {
                until(Duration::from_secs(4), || case.supervisor.inner.test.watchdog_return.entered.load(Ordering::SeqCst)).await?;
                native_ready_before_management(&owner)?;
                let retiring = disconnected(&document, &session)?;
                let retiring_id = operation_id(&retiring)?.to_owned();
                let endpoint = lock(&owner.state).cleanup_endpoint.ok_or("g1_unknown_endpoint_missing")?;
                until(CLEANUP_TIME + Duration::from_secs(1), || lock(&owner.state).unknown).await?;
                let unknown = document.github_connection_status(); valid_status(&unknown)?;
                require(matches!(mailbox(&owner)?, GitHubReadReceipt::RetainedUnknown)
                    && !document.github_fixture_material_settled() && !case.supervisor.can_exit() && case.supervisor.disabled()
                    && operation_id(&unknown)? == retiring_id && unknown.operation.as_ref().is_some_and(|op| op.phase == Phase::CleanupUnknown),
                    "g1_document_unknown_not_retained")?;
                disconnected(&document, &session)?;
                require(lock(&owner.state).cleanup_endpoint == Some(endpoint), "g1_unknown_cleanup_renewed")?;
                document_admission_refused(&document, &project, &session, "github_connection_refused_cleanup_unknown")?;
                case.supervisor.inner.test.watchdog_return.release();
                let final_receipt = settled_mailbox(&owner).await?;
                let GitHubReadReceipt::Settled { outcome: Err(error), settled_at, was_unknown: true } = final_receipt else {
                    return Err("g1_unknown_late_receipt_lost_failure");
                };
                require(error.code == "cleanup_unknown" && settled_at >= endpoint, "g1_unknown_late_receipt_clock")?;
                let after = document.github_connection_status(); valid_status(&after)?;
                require(after == unknown && document.github_fixture_material_settled()
                    && matches!(mailbox(&owner)?, GitHubReadReceipt::Settled { settled_at: again, was_unknown: true, .. } if again == settled_at),
                    "g1_late_material_or_unknown_changed")?;
                case.notes["pendingMaterialRetained"] = json!(true);
                case.notes["originalCleanupEndpointUnchanged"] = json!(true);
                case.notes["lateSettlementPreservedUnknown"] = json!(true);
                case.notes["originalSettledAtImmutable"] = json!(true);
                Ok(())
            },
            "g1-document-terminal-unknown" => {
                let first = connected(&document).await?;
                let completed = first.operation.clone().ok_or("g1_terminal_operation_missing")?;
                case.supervisor.inner.test.watchdog_return.close();
                let second = case.github_start(false)?; // A separate original on the SAME two-slot owner.
                let second_owner = case.owner("github-read-2")?;
                until(Duration::from_secs(4), || case.supervisor.inner.test.watchdog_return.entered.load(Ordering::SeqCst)).await?;
                native_ready_before_management(&second_owner)?;
                require(case.supervisor.shutdown().await.is_err_and(|error| error.code == "cleanup_unknown"), "g1_terminal_shutdown_not_unknown")?;
                until(Duration::from_secs(1), || lock(&second_owner.state).unknown).await?;
                let unknown = document.github_connection_status(); valid_status(&unknown)?;
                let operation = unknown.operation.as_ref().ok_or("g1_reserved_unknown_missing")?;
                require(completed.phase == Phase::Settled && operation.id == "github-unknown-1" && operation.id != completed.id
                    && operation.phase == Phase::CleanupUnknown && operation.reason == Reason::CleanupUnknown
                    && !case.supervisor.can_exit() && document.github_fixture_material_settled(), "g1_terminal_id_rewritten_or_early_exit")?;
                case.supervisor.inner.test.watchdog_return.release();
                require(matches!(settled_mailbox(&second_owner).await?, GitHubReadReceipt::Settled { was_unknown: true, outcome: Err(_), .. }),
                    "g1_terminal_late_owner_not_unknown")?;
                require(matches!(case.github_receipt(second)?, GitHubReadReceipt::Settled { was_unknown: true, .. })
                    && document.github_connection_status() == unknown, "g1_reserved_unknown_not_sticky")?;
                case.notes["terminalOperationUsesReservedUnknownIdentity"] = json!(true);
                case.notes["settledDocumentDoesNotReplaceOwnerFinality"] = json!(true);
                Ok(())
            },
            _ => Err("g1_document_case_not_listed"),
        }
    }

    // Fixed owner-case implementation is inserted at this marker after its
    // source-only author handoff; no arbitrary method or mode dispatch exists.
    // SOURCE-only fragment for the reviewed cfg-test github_fixture module.
    // The original Case owns finalization on every path. This function never
    // fabricates a mailbox outcome, settles an owner, or joins a replacement task.
    async fn exercise_owner(case: &mut Case) -> Check<()> {
        use crate::github_connection_protocol::{Coverage, FactState, Presence, Reason as GitHubReason, WorkflowState};

        fn mailbox(owner: &Owner) -> Check<GitHubReadReceipt> {
            owner.github_receipt.as_ref().map(|receipt| lock(receipt).clone()).ok_or("g1_original_mailbox_missing")
        }
        fn success(receipt: &GitHubReadReceipt) -> Check<Instant> {
            let GitHubReadReceipt::Settled { outcome: Ok(outcome), settled_at, was_unknown: false } = receipt
                else { return Err("g1_expected_typed_success"); };
            require(*settled_at <= Instant::now() && outcome.facts.schema_version == 1
                && outcome.control.reason == GitHubReason::None && outcome.control.credential_expires_at.is_none()
                && outcome.control.cooldown_seconds.is_none() && !outcome.control.cooldown_blocked
                && outcome.facts.account.state == FactState::Observed && outcome.facts.account.reason == GitHubReason::None
                && outcome.facts.account.value.as_ref().is_some_and(|value| value.id == "11" && value.login == "owner")
                && outcome.facts.repository.state == FactState::Observed && outcome.facts.repository.reason == GitHubReason::None
                && outcome.facts.repository.value.as_ref().is_some_and(|value| value.id == "22" && value.full_name == "owner/app")
                && outcome.facts.automation.state == FactState::Observed && outcome.facts.automation.reason == GitHubReason::None
                && outcome.facts.automation.value.as_ref().is_some_and(|value| value.coverage == Coverage::Complete
                    && value.workflows.len() == 4 && value.workflows.iter().all(|row| row.presence == Presence::NotListed
                        && row.remote_id.is_none() && row.state == WorkflowState::Unknown)), "g1_fixture_projection_differs")?;
            Ok(*settled_at)
        }
        fn failure(receipt: &GitHubReadReceipt, expected: &str, unknown: bool) -> Check<Instant> {
            let GitHubReadReceipt::Settled { outcome: Err(error), settled_at, was_unknown } = receipt
                else { return Err("g1_expected_typed_failure"); };
            require(error.code == expected && !error.retryable && *was_unknown == unknown && *settled_at <= Instant::now(),
                "g1_typed_failure_differs")?;
            Ok(*settled_at)
        }
        fn unchanged(before: &GitHubReadReceipt, after: &GitHubReadReceipt) -> Check<()> {
            match (before, after) {
                (GitHubReadReceipt::Settled { outcome: a, settled_at: at, was_unknown: au },
                 GitHubReadReceipt::Settled { outcome: b, settled_at: bt, was_unknown: bu }) =>
                    require(a == b && at == bt && au == bu, "g1_original_terminal_receipt_changed"),
                _ => Err("g1_original_terminal_receipt_missing"),
            }
        }
        fn limits(owner: &Owner) -> Check<()> {
            let observed = lock(&owner.observation);
            require(matches!(owner.profile, Profile::GitHubReadOnly) && owner.profile.stdout_limit() == 64 * 1024
                && observed.stdout_bytes <= owner.profile.stdout_limit() && observed.stderr_bytes <= protocol::STDERR_LIMIT,
                "g1_original_profile_output_bound")
        }
        fn pending(case: &Case, index: usize, owner: &Arc<Owner>, driver: ManagementJoin) -> Check<()> {
            {
                // The same original registry -> state -> permit lock order.
                let owners = lock(&case.supervisor.inner.owners);
                let state = lock(&owner.state);
                require(owners.len() == 1 && owners.get(&owner.key).is_some_and(|value| Arc::ptr_eq(value, owner))
                    && !state.terminal && !state.unknown && state.error.is_none() && state.reply.is_none()
                    && state.driver_join == driver && state.watchdog_join == ManagementJoin::Pending
                    && lock(&owner.permit).is_some() && case.supervisor.inner.permits.available_permits() == ACTIVE_LIMIT - 1,
                    "g1_original_management_prematurely_settled")?;
            }
            require(matches!(case.github_receipt(index)?, GitHubReadReceipt::Pending), "g1_mailbox_published_before_originals")
        }
        async fn stop_held_then_observe_late(case: &mut Case, index: usize, owner: &Arc<Owner>) -> Check<()> {
            let endpoint = owner.endpoint();
            require(lock(&owner.state).error.is_none() && matches!(case.github_receipt(index)?, GitHubReadReceipt::Pending),
                "g1_held_original_was_already_failed")?;
            // Ordinary STOP starts the real first cleanup window. No product budget
            // is shortened/replaced; only stalled-input must consume the full10s.
            let supervisor = case.supervisor.clone();
            let mut shutdown = Box::pin(supervisor.shutdown());
            let first = std::future::poll_fn(|cx| Poll::Ready(shutdown.as_mut().poll(cx))).await;
            require(first.is_pending(), "g1_held_shutdown_was_not_pending")?;
            let cleanup = lock(&owner.state).cleanup_endpoint.ok_or("g1_cleanup_endpoint_missing")?;
            require(shutdown.await.is_err_and(|error| error.code == "cleanup_unknown"), "g1_held_shutdown_did_not_expire")?;
            until(Duration::from_secs(1), || lock(&owner.state).unknown).await?;
            require(matches!(case.github_result(index).await?, GitHubReadReceipt::RetainedUnknown)
                && Instant::now() >= cleanup && case.supervisor.disabled() && !case.supervisor.can_exit()
                && *owner.stop.borrow() && lock(&owner.permit).is_some()
                && case.supervisor.inner.permits.available_permits() == ACTIVE_LIMIT - 1,
                "g1_unknown_original_not_retained")?;
            {
                let originals = lock(&case.supervisor.inner.owners);
                let state = lock(&owner.state);
                require(originals.len() == 1 && originals.get(&owner.key).is_some_and(|value| Arc::ptr_eq(value, owner))
                    && !state.terminal && state.unknown && state.endpoint == endpoint && state.cleanup_endpoint == Some(cleanup)
                    && state.error.as_ref().is_some_and(|error| error.code == "shutting_down"), "g1_unknown_original_identity_changed")?;
            }
            require(case.supervisor.shutdown().await.is_err_and(|error| error.code == "cleanup_unknown"),
                "g1_repeated_shutdown_refusal_changed")?;
            rejection(case.supervisor.query(Method::Capabilities, json!({})).await, "cleanup_unknown")?;
            require(case.supervisor.start_github_readonly("owner/app", None, None, "INERT_NOT_A_CREDENTIAL")
                .is_err_and(|error| error.code == "cleanup_unknown" && !error.retryable), "g1_unknown_admitted_new_github_owner")?;
            require(lock(&owner.state).cleanup_endpoint == Some(cleanup), "g1_cleanup_endpoint_renewed")?;
            case.notes["retainedWhileUnknown"] = json!(true);
            case.notes["newPassiveAndGitHubAdmissionRefused"] = json!(true);

            // Release only this Case's original scheduling gates. The product alone
            // joins its originals and publishes Settled. Case::settle still joins
            // the original final observer and checks all resource books afterwards.
            case.supervisor.inner.test.release();
            until(Duration::from_secs(3), || matches!(case.github_receipt(index), Ok(GitHubReadReceipt::Settled { .. }))).await?;
            let first_receipt = case.github_result(index).await?;
            let settled_at = failure(&first_receipt, "cleanup_unknown", true)?;
            {
                let state = lock(&owner.state);
                require(state.terminal && state.unknown && state.endpoint == endpoint && state.cleanup_endpoint == Some(cleanup)
                    && state.error.as_ref().is_some_and(|error| error.code == "shutting_down")
                    && state.driver_join == ManagementJoin::Returned && state.watchdog_join == ManagementJoin::Returned
                    && settled_at >= cleanup, "g1_late_original_failure_or_endpoint_changed")?;
            }
            require(case.supervisor.disabled() && case.supervisor.can_exit() && lock(&owner.permit).is_none()
                && case.supervisor.inner.permits.available_permits() == ACTIVE_LIMIT, "g1_late_original_not_retired")?;
            rejection(case.supervisor.query(Method::Capabilities, json!({})).await, "cleanup_unknown")?;
            unchanged(&first_receipt, &case.github_receipt(index)?)?;
            case.notes["originalCleanupEndpointUnchanged"] = json!(true);
            case.notes["lateJoinPreservedFailure"] = json!(true);
            case.notes["terminalReceiptAndSettledAtImmutable"] = json!(true);
            Ok(())
        }

        match case.name {
            "g1-correct" => {
                let index = case.github_start(false)?;
                let owner = case.owner("github-read-1")?;
                require(owner.key == 1 && matches!(owner.profile, Profile::GitHubReadOnly) && lock(&owner.state).reply.is_none(),
                    "g1_typed_owner_route_differs")?;
                let receipt = case.github_result(index).await?;
                success(&receipt)?;
                unchanged(&receipt, &mailbox(&owner)?)?;
                limits(&owner)?;
                case.notes["typedGitHubMailbox"] = json!(true);
                case.notes["terminalReceiptAndSettledAtImmutable"] = json!(true);
                Ok(())
            }
            "g1-passive-envelope" | "g1-wrong-id" | "g1-wrong-protocol" | "g1-truncated" | "g1-extra-frames"
            | "g1-nonzero-exit" | "g1-stdout-limit" | "g1-stderr-limit" => {
                let index = case.github_start(false)?;
                let code = match case.name {
                    "g1-nonzero-exit" => "engine_failed",
                    "g1-stdout-limit" | "g1-stderr-limit" => "output_limit",
                    _ => "protocol_error",
                };
                failure(&case.github_result(index).await?, code, false)?;
                let owner = case.owner("github-read-1")?;
                limits(&owner)?;
                if case.name == "g1-nonzero-exit" {
                    let observed = lock(&owner.observation);
                    require(observed.stdout_bytes > 0 && observed.exit_success == Some(false), "g1_nonzero_exit_not_observed")?;
                    case.notes["validOutputDidNotSalvageFailedExit"] = json!(true);
                }
                Ok(())
            }
            "g1-delay-exit" => {
                let index = case.github_start(false)?;
                case.ready("github-read-1", "pipes-closed-child-held").await?;
                let owner = case.owner("github-read-1")?;
                until(Duration::from_secs(2), || { let observed = lock(&owner.observation); observed.stdout_eof && observed.stderr_eof }).await?;
                require(!lock(&owner.observation).waited, "g1_held_child_was_already_waited")?;
                pending(case, index, &owner, ManagementJoin::Pending)?;
                limits(&owner)?;
                case.notes["mailboxPendingAfterBothEofs"] = json!(true);
                case.release_one("github-read-1")?;
                success(&case.github_result(index).await?).map(|_| ())
            }
            "g1-stalled-input" => {
                let index = case.github_start(false)?;
                let owner = case.owner("github-read-1")?;
                let endpoint = owner.endpoint();
                case.ready("github-read-1", "input-unread").await?;
                failure(&case.github_result(index).await?, "query_timeout", false)?;
                {
                    let state = lock(&owner.state);
                    require(Instant::now() >= endpoint && state.endpoint == endpoint
                        && state.cleanup_endpoint == Some(endpoint + CLEANUP_TIME)
                        && state.error.as_ref().is_some_and(|error| error.code == "query_timeout"), "g1_original_operation_deadline_differs")?;
                }
                limits(&owner)?;
                case.notes["originalOperationDeadlineObserved"] = json!(true);
                case.notes["originalCleanupEndpointUnchanged"] = json!(true);
                // <=8KiB may already fit in the pipe. Do not assert writer blockage
                // or incomplete write; require its actual join in common finality.
                case.notes["unreadInputIsNotBlockedWriterEvidence"] = json!(true);
                Ok(())
            }
            "g1-mixed-abandon" => {
                let first = case.github_start(false)?;
                case.ready("github-read-1", "request-eof").await?;
                let second = case.start(Method::Capabilities, json!({}));
                case.ready("query-2", "request-eof").await?;
                let third = case.start(Method::Capabilities, json!({}));
                rejection(case.result(third).await?, "busy")?;
                let github = case.owner("github-read-1")?;
                let passive = case.owner("query-2")?;
                let endpoint = github.endpoint();
                require(matches!(github.profile, Profile::GitHubReadOnly) && matches!(passive.profile, Profile::Passive(Method::Capabilities))
                    && github.key == 1 && passive.key == 2 && case.supervisor.inner.test.owners().len() == 2,
                    "g1_mixed_original_profile_or_roster_differs")?;
                case.drop_github_ticket(first)?;
                {
                    let originals = lock(&case.supervisor.inner.owners);
                    require(originals.len() == 2 && originals.get(&github.key).is_some_and(|value| Arc::ptr_eq(value, &github))
                        && originals.get(&passive.key).is_some_and(|value| Arc::ptr_eq(value, &passive))
                        && lock(&github.permit).is_some() && lock(&passive.permit).is_some()
                        && case.supervisor.inner.permits.available_permits() == 0, "g1_ticket_drop_released_shared_admission")?;
                }
                require(matches!(mailbox(&github)?, GitHubReadReceipt::Pending) && !*github.stop.borrow(),
                    "g1_ticket_drop_stopped_original")?;
                {
                    let state = lock(&github.state);
                    require(!state.terminal && state.endpoint == endpoint, "g1_ticket_drop_changed_original_endpoint")?;
                }
                case.notes["sharedTwoSlotLimit"] = json!(true);
                case.notes["originalRetainedAfterTicketDrop"] = json!(true);
                case.release_one("github-read-1")?;
                case.release_one("query-2")?;
                let passive_value = value(case.result(second).await?)?;
                require(passive_value["case"] == "wait_release", "g1_mixed_passive_result_differs")?;
                until(Duration::from_secs(3), || matches!(mailbox(&github), Ok(GitHubReadReceipt::Settled { .. }))).await?;
                success(&mailbox(&github)?)?;
                limits(&github)?;
                case.notes["droppedTicketOriginalReturnedTypedSuccess"] = json!(true);
                Ok(())
            }
            "g1-controlled-inspection" | "g1-controlled-acquisition" | "g1-controlled-io-join" => {
                let inspection = case.name == "g1-controlled-inspection";
                let acquisition = case.name == "g1-controlled-acquisition";
                if inspection { case.supervisor.inner.test.inspection.close(); }
                else if acquisition { case.supervisor.inner.test.acquisition.close(); }
                else { case.supervisor.inner.test.stdout_join.close(); }
                let index = case.github_start(false)?;
                until(Duration::from_secs(4), || {
                    if inspection { case.supervisor.inner.test.inspection.entered.load(Ordering::SeqCst) }
                    else if acquisition { case.supervisor.inner.test.acquisition.entered.load(Ordering::SeqCst) }
                    else { case.supervisor.inner.test.stdout_join.entered.load(Ordering::SeqCst) }
                }).await?;
                let owner = case.owner("github-read-1")?;
                if inspection || acquisition {
                    let observed = lock(&owner.observation);
                    require(observed.inspection_joined == acquisition && !observed.acquisition_joined && !observed.spawned,
                        "g1_startup_control_was_not_original_precreation")?;
                    case.notes["noChildBeforeHeldStartupReturn"] = json!(true);
                } else {
                    until(Duration::from_secs(2), || {
                        let observed = lock(&owner.observation);
                        observed.waited && observed.exit_success == Some(true) && observed.stdout_eof && observed.stderr_eof
                            && observed.writer_joined && observed.writer_complete && observed.stderr_joined && !observed.stdout_joined
                    }).await?;
                    case.notes["nativeExitAndEofBeforeStdoutJoin"] = json!(true);
                }
                pending(case, index, &owner, ManagementJoin::Pending)?;
                stop_held_then_observe_late(case, index, &owner).await?;
                if inspection || acquisition {
                    let observed = lock(&owner.observation);
                    require(!observed.spawned && !observed.waited && observed.inspection_joined
                        && observed.acquisition_joined == acquisition, "g1_late_startup_created_a_child")?;
                    case.notes["noLateChildAfterCleanupExpiry"] = json!(true);
                } else {
                    let observed = lock(&owner.observation);
                    require(observed.waited && observed.stdout_eof && observed.stdout_joined, "g1_late_original_stdout_join_missing")?;
                    case.notes["lateOriginalStdoutJoined"] = json!(true);
                }
                limits(&owner)
            }
            "g1-controlled-management" | "g1-controlled-management-late" => {
                let late = case.name == "g1-controlled-management-late";
                if !late { case.supervisor.inner.test.driver_return.close(); }
                case.supervisor.inner.test.watchdog_return.close();
                let index = case.github_start(false)?;
                let owner = case.owner("github-read-1")?;
                if !late {
                    until(Duration::from_secs(4), || case.supervisor.inner.test.driver_return.entered.load(Ordering::SeqCst)).await?;
                    native_ready_before_management(&owner)?;
                    pending(case, index, &owner, ManagementJoin::Pending)?;
                    case.notes["nativeSettledBeforeManagementReturns"] = json!(true);
                    case.notes["driverReturnHeldBeforeMailbox"] = json!(true);
                    case.supervisor.inner.test.driver_return.release();
                }
                until(Duration::from_secs(4), || case.supervisor.inner.test.watchdog_return.entered.load(Ordering::SeqCst)).await?;
                native_ready_before_management(&owner)?;
                pending(case, index, &owner, ManagementJoin::Returned)?;
                limits(&owner)?;
                if late {
                    case.notes["nativeSettledBeforeWatchdogReturn"] = json!(true);
                    stop_held_then_observe_late(case, index, &owner).await
                } else {
                    case.notes["watchdogReturnHeldBeforeMailbox"] = json!(true);
                    case.supervisor.inner.test.watchdog_return.release();
                    let receipt = case.github_result(index).await?;
                    success(&receipt)?;
                    unchanged(&receipt, &case.github_receipt(index)?)?;
                    case.notes["terminalReceiptAndSettledAtImmutable"] = json!(true);
                    Ok(())
                }
            }
            _ => Err("unlisted_g1_owner_case"),
        }
    }

    // Integration obligations retained by the existing outer batch:
    // - Case::settle must run despite every returned Err/unwind; join the ORIGINAL
    //   final observer and reconcile all original resources before next-case IO.
    // - Case::native_facts must use owner.profile.stdout_limit(). Startup holds
    //   expect no child; g1-stalled-input does not require writer_complete=false.
    // - Record all17 literal rows, actual typed result class and original observer
    //   final join. A notes=true field is never a substitute for those receipts.
    // - Four late-control rows above remain disabled/unknown after successful
    //   original joins; that actual safe finality is not a reusable session gate.

    const CASES: &[(&str, &str)] = &[
        ("g1-correct", "correct"), ("g1-passive-envelope", "passive_envelope"),
        ("g1-wrong-id", "wrong_id"), ("g1-wrong-protocol", "wrong_protocol"),
        ("g1-truncated", "truncated"), ("g1-extra-frames", "extra_frames"),
        ("g1-nonzero-exit", "nonzero_exit"), ("g1-delay-exit", "delay_exit"),
        ("g1-stdout-limit", "stdout_limit"), ("g1-stderr-limit", "stderr_limit"),
        ("g1-stalled-input", "stalled_input"), ("g1-mixed-abandon", "wait_release"),
        ("g1-controlled-inspection", "correct"), ("g1-controlled-acquisition", "correct"),
        ("g1-controlled-io-join", "correct"), ("g1-controlled-management", "correct"),
        ("g1-controlled-management-late", "correct"),
        ("g1-document-connect-refresh", "correct"), ("g1-document-disconnect-held", "correct"),
        ("g1-document-registry-change", "correct"), ("g1-document-loss", "wait_release"),
        ("g1-document-unknown-late", "correct"), ("g1-document-terminal-unknown", "correct"),
    ];

    struct GitHubReceipt { path: PathBuf, bindings: Value, cases: Vec<Value> }
    impl GitHubReceipt {
        fn write(&self, state: &str, code: Option<&str>) -> Check<()> {
            let bytes = serde_json::to_vec(&json!({"schemaVersion":1,"scope":"github-readonly-hosted-v1",
                "status":state,"allOwnersSettled":state == "passed","failureCode":code,
                "bindings":self.bindings,"cases":self.cases,"notVerified":LIMITATIONS})).map_err(|_| "g1_receipt_encoding")?;
            require(bytes.len() <= 128 * 1024, "g1_receipt_limit")?;
            fs::write(&self.path, bytes).map_err(|_| "g1_receipt_write")
        }
    }
    fn evidence(case: &Case, passed: bool, code: Option<&str>) -> Value {
        let mut row = case.evidence(passed, code);
        row["evidenceKind"] = json!(if case.name.starts_with("g1-controlled-") { "scheduling-control-not-os-fault" }
            else if case.name.starts_with("g1-document-") { "controlled-document-original-owner" }
            else { "actual-private-frame-child" });
        row["owners"] = json!(case.supervisor.inner.test.owners().iter().map(|owner| {
            let state = lock(&owner.state);
            let observed = lock(&owner.observation);
            json!({"id":owner.id,"terminal":state.terminal,"unknownLatched":state.unknown,
                "permitRetained":lock(&owner.permit).is_some(),"native":observed.clone(),
                "profile":match owner.profile { Profile::Passive(_) => "passive", Profile::GitHubReadOnly => "github-readonly" },
                "observerJoined":observed.observer_joined,"firstError":state.error.as_ref().map(|error| &error.code),
                "receipt":owner.github_receipt.as_ref().map(|receipt| receipt_result(&lock(receipt)))})
        }).collect::<Vec<_>>());
        row
    }

    // Catch only this known test future's unwind so independent finalization
    // still runs. No new task/owner, forced cancellation or simulated receipt.
    // RETAINED additionally keeps material if a future destructor itself fails.
    async fn guarded<F: Future>(future: F) -> Check<F::Output> {
        let mut future = Box::pin(future);
        let result = std::future::poll_fn(|cx| {
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| future.as_mut().poll(cx))) {
                Ok(Poll::Pending) => Poll::Pending,
                Ok(Poll::Ready(value)) => Poll::Ready(Ok(value)),
                Err(_) => Poll::Ready(Err("g1_case_unwind")),
            }
        }).await;
        if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(future))).is_err() { return Err("g1_case_drop_unwind"); }
        result
    }

    pub(super) async fn run() {
        let admitted = match Admitted::new() { Ok(value) => value, Err(code) => panic!("G1 hosted admission failed: {code}") };
        let mut receipt = GitHubReceipt { path: admitted.inputs.root.join("receipt.json"), bindings: admitted.inputs.bindings.clone(), cases: Vec::new() };
        if receipt.write("running", None).is_err() { panic!("G1 receipt unavailable before native work"); }
        for &(name, mode) in CASES {
            let mut case = match admitted.case(name, mode) {
                Ok(case) => case,
                Err(code) => { let _ = receipt.write("failed", Some(code)); panic!("G1 fixture preparation failed: {code}"); },
            };
            let mut checked = guarded(async {
                if name.starts_with("g1-document-") { exercise_document(&mut case).await }
                else { exercise_owner(&mut case).await }
            }).await.unwrap_or_else(Err);
            let settled = matches!(guarded(case.settle(checked.is_err())).await, Ok(true));
            if !settled {
                receipt.cases.push(evidence(&case, false, Some("custody_unresolved")));
                let _ = receipt.write("failed-retained", Some("custody_unresolved"));
                // Retain this actual Case/document/books/owners until disposable
                // host teardown. No next case, fixture change or guessed cleanup.
                pending::<()>().await;
                return;
            }
            if checked.is_ok() {
                checked = case.native_facts(!matches!(name, "g1-controlled-inspection" | "g1-controlled-acquisition"), name != "g1-stalled-input");
            }
            let sticky = matches!(name, "g1-controlled-inspection" | "g1-controlled-acquisition" | "g1-controlled-io-join"
                | "g1-controlled-management-late" | "g1-document-unknown-late" | "g1-document-terminal-unknown");
            if checked.is_ok() {
                checked = require(case.supervisor.disabled() == sticky && case.supervisor.can_exit()
                    && case.supervisor.inner.test.owners().iter().all(|owner| {
                        let state = lock(&owner.state);
                        let original_unknown = sticky && !(name == "g1-document-terminal-unknown" && owner.key == 1);
                        state.terminal && state.unknown == original_unknown && (!original_unknown || state.error.is_some())
                            && lock(&owner.observation).observer_joined
                    }), "g1_final_unknown_or_observer_contract");
            }
            receipt.cases.push(evidence(&case, checked.is_ok(), checked.err()));
            if let Err(code) = checked { let _ = receipt.write("failed", Some(code)); panic!("G1 check failed after original settlement: {code}"); }
            if receipt.write("running", None).is_err() { panic!("G1 receipt failed after original settlement"); }
        }
        std::env::set_var("MRK_DESKTOP_DEV_CORE", &admitted.inputs.source); // Every original and retained document settled.
        if receipt.write("passed", None).is_err() { panic!("G1 final receipt failed after original settlement"); }
    }
}

/// SG1 observes only the two real frontend bootstrap originals. No held gate,
/// synthetic core, edit authorization, new query or replacement join lives here.
#[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "development-runtime", target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
pub(crate) mod session_gtk_probe {
    use super::*;
    pub(crate) struct Probe { supervisor: Supervisor, tails: Mutex<Vec<u64>>, failed: AtomicBool }
    struct Tail<'a> { probe: &'a Probe, done: bool }
    impl Drop for Tail<'_> { fn drop(&mut self) { if !self.done { self.probe.failed.store(true, Ordering::SeqCst); } } }
    fn native(owner: &Owner) -> bool {
        let o = lock(&owner.observation);
        o.inspection_joined && o.acquisition_joined && o.spawned && o.waited && o.exit_success == Some(true)
            && o.writer_joined && o.writer_complete && o.stdout_eof && o.stderr_eof && o.stdout_joined && o.stderr_joined
            && o.stdout_bytes > 0 && o.stdout_bytes <= protocol::RESPONSE_LIMIT && o.stderr_bytes <= protocol::STDERR_LIMIT
            && o.driver_joined && o.watchdog_joined
    }
    impl Probe {
        pub(crate) fn attach(supervisor: &Supervisor) -> Check<Self> {
            require(supervisor.can_exit() && !supervisor.disabled() && !supervisor.stopping()
                && supervisor.inner.test.owners().is_empty(), "sg1_passive_not_fresh")?;
            Ok(Self { supervisor:supervisor.clone(), tails:Mutex::new(Vec::with_capacity(2)), failed:AtomicBool::new(false) })
        }
        async fn facts(&self, stopping: bool) -> Check<Value> {
            require(!self.failed.load(Ordering::SeqCst) && self.supervisor.can_exit() && !self.supervisor.disabled()
                && self.supervisor.stopping() == stopping && self.supervisor.inner.permits.available_permits() == ACTIVE_LIMIT,
                "sg1_passive_registry")?;
            let originals = self.supervisor.inner.test.owners();
            require(originals.len() == 2, "sg1_passive_roster")?;
            let mut facts = Vec::with_capacity(2);
            for original in originals {
                {
                    let state = lock(&original.state);
                    require(state.terminal && !state.unknown && state.error.is_none()
                        && state.driver_join == ManagementJoin::Returned && state.watchdog_join == ManagementJoin::Returned
                        && lock(&original.permit).is_none() && native(&original), "sg1_passive_original_unsettled")?;
                }
                if !lock(&self.tails).contains(&original.key) {
                    let mut guard = Tail { probe:self, done:false };
                    let mut slot = original.observer.lock().await;
                    let task = slot.as_mut().ok_or("sg1_passive_tail_missing")?;
                    require(matches!(tokio::time::timeout(Duration::from_secs(2), task).await, Ok(Ok(()))), "sg1_passive_tail_unknown")?;
                    slot.take(); // Positive await of THIS retained original, once.
                    lock(&self.tails).push(original.key); guard.done = true;
                }
                facts.push(json!({"key":original.key.to_string(),"native":lock(&original.observation).clone(),"observerJoin":"ok"}));
            }
            require(lock(&self.tails).len() == 2, "sg1_passive_tail_roster")?;
            Ok(json!({"stopping":stopping,"disabled":false,"registeredOwners":0,"originals":facts}))
        }
        pub(crate) async fn bootstrap(&self) -> Check<Value> { self.facts(false).await }
        pub(crate) async fn final_facts(&self) -> Check<Value> { self.facts(true).await }
    }
}

/// Observation only, for the genuine metadata Observe/Validate/Catalogue path.
/// It retains the existing Supervisor and its original Hooks owners before the
/// first query. No query, process, gate, fake engine or cleanup is created here.
#[cfg(all(test, debug_assertions, feature = "development-runtime", not(feature = "desktop-shell"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
pub(crate) mod metadata_fixture_probe {
    use super::*;
    pub(crate) struct Probe { supervisor: Supervisor, tails: Mutex<Vec<u64>>, failed: AtomicBool }
    struct Tail<'a> { probe: &'a Probe, done: bool }
    impl Drop for Tail<'_> { fn drop(&mut self) { if !self.done { self.probe.failed.store(true, Ordering::SeqCst); } } }

    fn native(owner: &Owner) -> bool {
        let state = lock(&owner.state);
        let o = lock(&owner.observation);
        state.terminal && !state.unknown && state.driver_join == ManagementJoin::Returned
            && state.watchdog_join == ManagementJoin::Returned && lock(&owner.permit).is_none()
            && o.inspection_joined && o.acquisition_joined && o.spawned && o.waited && o.exit_success == Some(true)
            && o.writer_joined && o.writer_complete && o.stdout_eof && o.stderr_eof && o.stdout_joined && o.stderr_joined
            && o.stdout_bytes > 0 && o.stdout_bytes <= owner.profile.stdout_limit() && o.stderr_bytes == 0
            && o.driver_joined && o.watchdog_joined
    }
    fn book_retired(owner: &Owner) -> bool {
        owner.resources.try_lock().is_ok_and(|r| r.inspection.is_none() && r.acquisition.is_none()
            && r.github_environment.is_none() && r.child.is_none() && r.writer.is_none() && r.stdout.is_none() && r.stderr.is_none()
            && r.failed_writer.is_none() && r.failed_stdout.is_none() && r.failed_stderr.is_none()
            && r.waited.as_ref().is_some_and(ExitStatus::success) && r.write_end.is_some_and(|end| end.complete)
            && r.out_end.is_none() && r.err_end.is_none() && !r.kill_attempted)
            && owner.driver.try_lock().is_ok_and(|slot| slot.is_none())
            && owner.watchdog.try_lock().is_ok_and(|slot| slot.is_none())
    }
    impl Probe {
        pub(crate) fn attach(supervisor: &Supervisor) -> Check<Self> {
            require(supervisor.can_exit() && !supervisor.disabled() && !supervisor.stopping()
                && supervisor.inner.test.owners().is_empty()
                && supervisor.inner.permits.available_permits() == ACTIVE_LIMIT, "metadata_passive_not_fresh")?;
            Ok(Self { supervisor:supervisor.clone(), tails:Mutex::new(Vec::new()), failed:AtomicBool::new(false) })
        }
        pub(crate) fn settled(&self) -> bool {
            if self.failed.load(Ordering::SeqCst) || !self.supervisor.can_exit() || self.supervisor.disabled()
                || self.supervisor.inner.permits.available_permits() != ACTIVE_LIMIT { return false; }
            let owners = self.supervisor.inner.test.owners();
            let Ok(tails) = self.tails.lock() else { return false; };
            owners.len() == tails.len() && owners.iter().zip(tails.iter()).all(|(owner, key)|
                owner.key == *key && native(owner) && book_retired(owner)
                    && lock(&owner.observation).observer_joined
                    && owner.observer.try_lock().is_ok_and(|slot| slot.is_none()))
        }
        pub(crate) fn count(&self) -> usize { self.supervisor.inner.test.owners().len() }
        pub(crate) async fn next(&self, method: Method, expected_error: Option<&'static str>) -> Check<Value> {
            // Any missing/failed observation is sticky, including an abandoned
            // future while joining the original now-resource-free observer tail.
            let mut guard = Tail { probe:self, done:false };
            require(!self.failed.load(Ordering::SeqCst) && !self.supervisor.stopping()
                && !self.supervisor.disabled() && self.supervisor.can_exit()
                && self.supervisor.inner.permits.available_permits() == ACTIVE_LIMIT, "metadata_passive_registry")?;
            require(matches!((method, expected_error),
                (Method::MetadataTextObserve, None | Some("metadata_text_sensitive" | "metadata_text_encoding"))
                | (Method::MetadataTextValidate | Method::Catalog, None)), "metadata_passive_method")?;
            let owners = self.supervisor.inner.test.owners();
            let done = self.tails.lock().map_err(|_| "metadata_passive_tail_poison")?.len();
            require(owners.len() == done + 1 && owners.len() <= 40, "metadata_passive_roster")?;
            let owner = owners.last().ok_or("metadata_passive_original_missing")?;
            require(matches!((owner.profile, method),
                (Profile::Passive(Method::MetadataTextObserve), Method::MetadataTextObserve)
                | (Profile::Passive(Method::MetadataTextValidate), Method::MetadataTextValidate)
                | (Profile::Passive(Method::Catalog), Method::Catalog))
                && native(owner) && lock(&owner.state).error.as_ref().map(|error| error.code.as_str()) == expected_error,
                "metadata_passive_original_unsettled")?;
            let mut slot = owner.observer.lock().await;
            let task = slot.as_mut().ok_or("metadata_passive_tail_missing")?;
            // This is not a new operation/cleanup clock. The original native
            // owner already retired; only its existing final observer is joined.
            require(matches!(tokio::time::timeout(CLEANUP_TIME, task).await, Ok(Ok(()))), "metadata_passive_tail_unknown")?;
            slot.take(); drop(slot);
            require(book_retired(owner), "metadata_passive_original_book")?;
            lock(&owner.observation).observer_joined = true;
            self.tails.lock().map_err(|_| "metadata_passive_tail_poison")?.push(owner.key);
            let name = match method { Method::MetadataTextObserve => "observe", Method::MetadataTextValidate => "validate",
                Method::Catalog => "catalogue", _ => return Err("metadata_passive_method") };
            let value = json!({"method":name,"key":owner.key.to_string(),"error":expected_error,
                "native":lock(&owner.observation).clone(),"observerJoin":"ok","permitRetired":true,"resourceBookRetired":true});
            require(self.settled(), "metadata_passive_original_roster_unsettled")?;
            guard.done = true;
            Ok(value)
        }
    }
}

// Pure log-only decoding. This module never observes a process, grants cleanup,
// parses success telemetry, or adds a row/field to the accepted-prefix receipt.
mod windows_snapshot_failure_diagnostics {
    use super::{protocol, Value};
    use serde_json::json;

    const PREFIX: &[u8] = b"MRK_WINDOWS_SNAPSHOT_FAILURE_V1 ";
    const TAG: &[u8] = b"MRK_WINDOWS_SNAPSHOT_FAILURE";
    const TELEMETRY: &[u8] = b"MRK_WINDOWS_SNAPSHOT_V1 ";
    const ENGINE_REJECTION: &[u8] = b"Mobile Release Kit desktop engine rejected the request or transport.";
    const SCOPE: &str = "windows-static-snapshot-native-v1";
    const CASES: &[&str] = &["ordinary-source", "ordinary-zip", "closed-gate", "link-children", "reparse-root",
        "reparse-ancestor", "short-alias", "case-alias", "case-collision", "subst-drive", "unc", "device", "ads",
        "root-reparse-race", "config-reparse-race", "walk-reparse-race", "case-mode-race", "acl-type",
        "read-eof-size", "entry-limit", "candidate-limit", "aggregate-limit", "depth-path-limit",
        "replace", "disappear", "config-disappear", "ending-metadata-case", "drive-map-change",
        "oplock-release", "oplock-withhold", "pending-failstop"];
    const STAGES: &[&str] = &["setup", "reader", "reduction", "restoration"];
    const CODES: &[&str] = &["short_alias_bound", "real_short_alias_unavailable", "real_alias_required",
        "normalized_alias_veto_required", "fixture_native_unavailable", "fixture_failure",
        "short_alias_access_denied", "short_alias_sharing_violation", "short_alias_not_supported",
        "short_alias_invalid_parameter", "short_alias_name_collision", "short_alias_volume_disabled",
        "short_alias_privilege_unavailable", "short_alias_other_refused",
        "saved_dacl_bound", "saved_dacl_unsupported", "world_sid_bound", "fixture_dacl_denial_required", "fixture_dacl_not_effective",
        "dacl_restore_original_object", "saved_dacl_present", "dacl_restoration_not_confirmed",
        "fixture_restoration_bound", "fixture_retained_arena_bound", "fixture_arena_bound",
        "fixture_path_bound", "fixture_inherited_handle", "fixture_zero_file_id"];
    // Frozen original supervisor / API dispatch / snapshot codes, not arbitrary
    // protocol-forwarded strings and not BridgeError Display/Debug/message.
    const OWNER_CODES: &[&str] = &["runtime_unavailable", "protocol_error", "invalid_request", "shutting_down",
        "query_timeout", "cleanup_unknown", "busy", "unavailable", "output_limit", "io_error", "engine_failed",
        "unknown_method", "invalid_params", "unsafe_path", "platform_unavailable", "snapshot_unavailable"];

    #[derive(Debug, PartialEq, Eq)]
    enum Marker { Absent, Invalid, Valid { stage: &'static str, code: &'static str, comparison: Option<Value> } }

    fn closed(value: &str, allowed: &[&'static str]) -> Option<&'static str> {
        allowed.iter().copied().find(|candidate| *candidate == value)
    }

    fn dacl_comparison(value: &Value) -> bool {
        const POLICY: &[&str] = &["presenceEqual", "nullEqual", "controlEqual", "protectedEqual", "defaultedEqual",
            "autoInheritanceEqual", "aclRevisionEqual", "orderedAcesEqual"];
        const OTHER: &[&str] = &["role", "savedShapeValid", "observedShapeValid", "lengthEqual", "bytesEqual"];
        let Some(fields) = value.as_object() else { return false; };
        if fields.len() != POLICY.len() + OTHER.len()
            || !POLICY.iter().chain(OTHER).all(|key| fields.contains_key(*key))
            || !matches!(value["role"].as_str(), Some("denied-file" | "denied-directory")) { return false; }
        let (Some(saved), Some(observed)) = (value["savedShapeValid"].as_bool(), value["observedShapeValid"].as_bool())
            else { return false; };
        let valid = saved && observed;
        if ["lengthEqual", "bytesEqual"].iter().chain(POLICY).any(|key| !value[*key].is_null() && !value[*key].is_boolean())
            || value["lengthEqual"].is_null() != value["bytesEqual"].is_null()
            || (valid && value["lengthEqual"].is_null())
            || POLICY.iter().any(|key| if valid { !value[*key].is_boolean() } else { !value[*key].is_null() }) {
            return false;
        }
        if value["bytesEqual"] == true && (value["lengthEqual"] != true || saved != observed
            || (valid && POLICY.iter().any(|key| value[*key] != true))) { return false; }
        if valid && value["controlEqual"].as_bool() != Some(["presenceEqual", "protectedEqual", "defaultedEqual", "autoInheritanceEqual"]
            .iter().all(|key| value[*key] == true)) { return false; }
        true
    }

    fn marker(bytes: &[u8], id: &str, nonce: &str) -> Marker {
        if bytes.len() > 64 * 1024 { return Marker::Invalid; }
        if !bytes.windows(TAG.len()).any(|window| window == TAG) { return Marker::Absent; }
        if closed(id, CASES).is_none() || nonce.len() != 64
            || !nonce.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || bytes.last() != Some(&b'\n') { return Marker::Invalid; }
        let mut body = None;
        let mut preceding = 0usize;
        let mut engine_rejection = false;
        for line in bytes[..bytes.len() - 1].split(|b| *b == b'\n') {
            if let Some(value) = line.strip_prefix(PREFIX) {
                if body.is_some() || engine_rejection || line.len() + 1 > 1024
                    || value.windows(TAG.len()).any(|window| window == TAG) { return Marker::Invalid; }
                body = Some(value);
            } else if line.windows(TAG.len()).any(|window| window == TAG) {
                return Marker::Invalid; // Embedded/wrong-version markers are not a new frame.
            } else if body.is_none() && line.starts_with(TELEMETRY) && preceding < 3 {
                preceding += 1; // Opaque prior frames only; do NOT validate their native evidence here.
            } else if body.is_some() && !engine_rejection && line == ENGINE_REJECTION {
                engine_rejection = true;
            } else {
                return Marker::Invalid; // No leading/trailing junk, blank lines, retries or injected lines.
            }
        }
        let Some(body) = body else { return Marker::Invalid; };
        if !body.is_ascii() || body.contains(&b'\r') { return Marker::Invalid; }
        let Ok(value) = protocol::strict_json(body) else { return Marker::Invalid; };
        let Some(fields) = value.as_object() else { return Marker::Invalid; };
        let has_comparison = fields.contains_key("comparison");
        if fields.len() != 6 + usize::from(has_comparison) || !["schemaVersion", "scope", "id", "nonce", "stage", "code"].iter()
            .all(|field| fields.contains_key(*field))
            || value["schemaVersion"].as_u64() != Some(1) || value["scope"].as_str() != Some(SCOPE)
            || value["id"].as_str() != Some(id) || value["nonce"].as_str() != Some(nonce) {
            return Marker::Invalid;
        }
        let Some(stage) = value["stage"].as_str().and_then(|value| closed(value, STAGES)) else { return Marker::Invalid; };
        let Some(code) = value["code"].as_str().and_then(|value| closed(value, CODES)) else { return Marker::Invalid; };
        let comparison = if has_comparison {
            if (id, stage, code) != ("acl-type", "restoration", "dacl_restoration_not_confirmed")
                || !dacl_comparison(&value["comparison"]) { return Marker::Invalid; }
            Some(value["comparison"].clone())
        } else { None };
        Marker::Valid { stage, code, comparison }
    }

    fn summary(id: &str, nonce: &str, exit: i32, owner_code: Option<&str>, stderr: &[u8]) -> Value {
        let fixed_id = closed(id, CASES).unwrap_or("unknown_control");
        let owner_code = owner_code.map(|code| closed(code, OWNER_CODES).unwrap_or("unknown_owner_error"));
        let failure = match marker(stderr, id, nonce) {
            Marker::Absent => json!({"status":"absent"}),
            Marker::Invalid => json!({"status":"invalid"}),
            Marker::Valid { stage, code, comparison } => {
                let mut failure = json!({"status":"valid","stage":stage,"code":code});
                if let Some(comparison) = comparison { failure["comparison"] = comparison; }
                failure
            },
        };
        json!({"schemaVersion":1,"scope":SCOPE,"id":fixed_id,"exitCode":exit,
            "ownerErrorCode":owner_code,"fixtureFailure":failure})
    }

    #[cfg(windows)]
    pub(super) fn log_exit(id: &str, nonce: &str, exit: i32, owner_code: Option<&str>, stderr: &[u8]) {
        if let Ok(body) = serde_json::to_vec(&summary(id, nonce, exit, owner_code, stderr)) {
            let mut line = b"MRK_WINDOWS_SNAPSHOT_EXIT_DIAGNOSTIC_V1 ".to_vec();
            line.extend_from_slice(&body);
            line.push(b'\n');
            if line.len() <= 1024 {
                // One best-effort write. Failure/partial output cannot replace the
                // original windows_original_exit_differs or trigger another case.
                let _ = std::io::Write::write(&mut std::io::stderr(), &line);
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn dacl_comparison_is_closed_log_only_and_bounded() -> Result<(), Box<dyn std::error::Error>> {
            let nonce = "a".repeat(64);
            let id = "acl-type";
            let policy = ["presenceEqual", "nullEqual", "controlEqual", "protectedEqual", "defaultedEqual",
                "autoInheritanceEqual", "aclRevisionEqual", "orderedAcesEqual"];
            let facts = json!({"role":"denied-directory","savedShapeValid":true,"observedShapeValid":true,
                "lengthEqual":true,"bytesEqual":false,"presenceEqual":true,"nullEqual":true,"controlEqual":false,
                "protectedEqual":true,"defaultedEqual":true,"autoInheritanceEqual":false,
                "aclRevisionEqual":true,"orderedAcesEqual":true});
            let base = json!({"schemaVersion":1,"scope":SCOPE,"id":id,"nonce":nonce,
                "stage":"restoration","code":"dacl_restoration_not_confirmed","comparison":facts});
            let encode = |value: &Value| -> Result<Vec<u8>, serde_json::Error> {
                let mut bytes = PREFIX.to_vec();
                bytes.extend_from_slice(&serde_json::to_vec(value)?); bytes.push(b'\n');
                Ok(bytes)
            };
            let valid = encode(&base)?;
            let expected = Marker::Valid { stage: "restoration", code: "dacl_restoration_not_confirmed",
                comparison: Some(facts.clone()) };
            assert!(dacl_comparison(&facts));
            assert_eq!(marker(&valid, id, &nonce), expected);
            let result = summary(id, &nonce, 78, Some("engine_failed"), &valid);
            assert_eq!(result, json!({"schemaVersion":1,"scope":SCOPE,"id":id,"exitCode":78,
                "ownerErrorCode":"engine_failed","fixtureFailure":{"status":"valid","stage":"restoration",
                    "code":"dacl_restoration_not_confirmed","comparison":facts}}));
            assert!(!result.to_string().contains(&nonce)); // No new success, raw SD, or reader evidence field.
            for role in ["denied-file", "denied-directory"] {
                let mut frame = base.clone(); frame["comparison"]["role"] = json!(role);
                assert!(matches!(marker(&encode(&frame)?, id, &nonce), Marker::Valid { comparison: Some(_), .. }));
            }
            for (saved, observed) in [(false, false), (false, true), (true, false)] {
                let mut unknown = facts.clone();
                unknown["savedShapeValid"] = json!(saved); unknown["observedShapeValid"] = json!(observed);
                for key in policy { unknown[key] = Value::Null; }
                for (length, bytes) in [(json!(true), json!(false)), (json!(false), json!(false)), (Value::Null, Value::Null)] {
                    unknown["lengthEqual"] = length; unknown["bytesEqual"] = bytes;
                    assert!(dacl_comparison(&unknown));
                    let mut frame = base.clone(); frame["comparison"] = unknown.clone();
                    assert!(matches!(marker(&encode(&frame)?, id, &nonce), Marker::Valid { comparison: Some(_), .. }));
                    for key in policy {
                        let mut bad = unknown.clone(); bad[key] = json!(true);
                        assert!(!dacl_comparison(&bad)); // Invalid layout cannot produce a policy equality fact.
                    }
                }
                unknown["lengthEqual"] = json!(true); unknown["bytesEqual"] = json!(true);
                assert_eq!(dacl_comparison(&unknown), saved == observed);
            }
            let mut normalized = facts.clone();
            for key in policy { normalized[key] = json!(true); }
            normalized["lengthEqual"] = json!(false);
            assert!(dacl_comparison(&normalized)); // Raw differences can accompany complete policy equality.
            normalized["bytesEqual"] = json!(true);
            assert!(!dacl_comparison(&normalized));
            normalized["lengthEqual"] = json!(true);
            assert!(dacl_comparison(&normalized));

            let keys: Vec<String> = facts.as_object().ok_or("pure test object required")?.keys().cloned().collect();
            for key in &keys {
                let mut missing = facts.clone();
                missing.as_object_mut().ok_or("pure test object required")?.remove(key);
                assert!(!dacl_comparison(&missing));
                for bad in [Value::Null, json!(0), json!(1), json!(0.0), json!("true"), json!([]), json!({})] {
                    let mut frame = base.clone(); frame["comparison"][key.as_str()] = bad;
                    assert_eq!(marker(&encode(&frame)?, id, &nonce), Marker::Invalid);
                }
                // strict_json must reject duplicate keys within the optional object too.
                let body = serde_json::to_string(&base)?;
                let member = format!("{}:{}", serde_json::to_string(key)?, facts[key.as_str()]);
                let duplicate = body.replacen(&member, &format!("{member},{member}"), 1);
                assert_ne!(body, duplicate);
                assert_eq!(marker(&[PREFIX, duplicate.as_bytes(), b"\n"].concat(), id, &nonce), Marker::Invalid);
            }
            let mut extra = facts.clone(); extra["extra"] = json!("private-canary");
            let mut wrong_role = facts.clone(); wrong_role["role"] = json!("private-canary");
            let mut wrong_availability = facts.clone(); wrong_availability["savedShapeValid"] = json!(false);
            let mut wrong_bytes = facts.clone(); wrong_bytes["bytesEqual"] = json!(true);
            let mut wrong_control = facts.clone(); wrong_control["controlEqual"] = json!(true);
            for bad in [Value::Null, json!(true), json!([]), json!({}), extra, wrong_role,
                        wrong_availability, wrong_bytes, wrong_control] {
                let mut frame = base.clone(); frame["comparison"] = bad;
                let bytes = encode(&frame)?;
                assert_eq!(marker(&bytes, id, &nonce), Marker::Invalid);
                let result = summary(id, &nonce, 78, Some("private-canary"), &bytes);
                assert_eq!(result["fixtureFailure"], json!({"status":"invalid"}));
                assert_eq!(result["exitCode"], 78);
                assert_eq!(result["ownerErrorCode"], "unknown_owner_error");
                assert!(!result.to_string().contains("private-canary"));
            }
            for (key, wrong) in [("id", "short-alias"), ("stage", "setup"), ("code", "fixture_dacl_not_effective")] {
                let mut frame = base.clone(); frame[key] = json!(wrong);
                let frame_id = frame["id"].as_str().ok_or("pure test id required")?;
                assert_eq!(marker(&encode(&frame)?, frame_id, &nonce), Marker::Invalid);
            }
            let mut exact = valid[..valid.len() - 1].to_vec(); exact.resize(1023, b' '); exact.push(b'\n');
            assert_eq!(marker(&exact, id, &nonce), expected);
            let mut over = exact; over.insert(PREFIX.len(), b' ');
            for bytes in [over, [valid.as_slice(), valid.as_slice()].concat(),
                          [b"injected ", valid.as_slice()].concat(), [valid.as_slice(), b"private-canary\n"].concat()] {
                assert_eq!(marker(&bytes, id, &nonce), Marker::Invalid);
                assert_eq!(summary(id, &nonce, -1073741819, None, &bytes)["exitCode"], -1073741819);
            }
            // Maximum-width closed DATA: both shapes valid; all equality facts false.
            let mut widest = facts.clone();
            for key in &keys {
                if key != "role" { widest[key.as_str()] = json!(matches!(key.as_str(), "savedShapeValid" | "observedShapeValid")); }
            }
            assert!(dacl_comparison(&widest));
            let mut frame = base.clone(); frame["comparison"] = widest;
            let marker_bytes = encode(&frame)?;
            assert!(marker_bytes.len() <= 1024);
            assert!(OWNER_CODES.iter().all(|code| code.len() <= "snapshot_unavailable".len()));
            assert!("unknown_owner_error".len() <= "snapshot_unavailable".len());
            let result = summary(id, &nonce, i32::MIN, Some("snapshot_unavailable"), &marker_bytes);
            let line = [b"MRK_WINDOWS_SNAPSHOT_EXIT_DIAGNOSTIC_V1 ".as_slice(), &serde_json::to_vec(&result)?, b"\n"].concat();
            assert!(line.len() <= 1024);
            assert_eq!(result["exitCode"].as_i64(), Some(i64::from(i32::MIN)));
            Ok(())
        }

        #[test]
        fn closed_failure_marker_and_original_exit_summary() -> Result<(), Box<dyn std::error::Error>> {
            let nonce = "a".repeat(64);
            let id = "short-alias";
            let base = json!({"schemaVersion":1,"scope":SCOPE,"id":id,"nonce":nonce,
                "stage":"setup","code":"real_short_alias_unavailable"});
            let encode = |value: &Value| -> Result<Vec<u8>, serde_json::Error> {
                let mut bytes = PREFIX.to_vec();
                bytes.extend_from_slice(&serde_json::to_vec(value)?);
                bytes.push(b'\n');
                Ok(bytes)
            };
            let valid = encode(&base)?;
            assert!(valid.len() <= 1024);
            assert_eq!(CASES.len(), 31);
            for stage in STAGES {
                for code in CODES {
                    let mut frame = base.clone(); frame["stage"] = json!(stage); frame["code"] = json!(code);
                    assert_eq!(marker(&encode(&frame)?, id, &nonce), Marker::Valid { stage: *stage, code: *code, comparison: None });
                }
            }
            for name in CASES {
                let mut frame = base.clone(); frame["id"] = json!(name);
                assert_eq!(marker(&encode(&frame)?, name, &nonce),
                    Marker::Valid { stage: "setup", code: "real_short_alias_unavailable", comparison: None });
            }
            for (stage, code) in [("setup", "fixture_dacl_not_effective"),
                                  ("restoration", "dacl_restoration_not_confirmed")] {
                let mut frame = base.clone(); frame["id"] = json!("acl-type");
                frame["stage"] = json!(stage); frame["code"] = json!(code);
                let result = summary("acl-type", &nonce, 78, Some("engine_failed"), &encode(&frame)?);
                assert_eq!(result["exitCode"], 78);
                assert_eq!(result["ownerErrorCode"], "engine_failed");
                assert_eq!(result["fixtureFailure"], json!({"status":"valid","stage":stage,"code":code}));
                assert!(!result.to_string().contains(&nonce));
            }
            let mut engine_line = ENGINE_REJECTION.to_vec(); engine_line.push(b'\n');
            for absent in [&b""[..], &engine_line, &b"private-canary-no-marker\n"[..]] {
                assert_eq!(marker(absent, id, &nonce), Marker::Absent);
            }
            let opaque_prior = [TELEMETRY, b"{}\n"].concat();
            for count in 0..=3 {
                let mut bytes = opaque_prior.repeat(count); bytes.extend_from_slice(&valid);
                assert_eq!(marker(&bytes, id, &nonce), Marker::Valid { stage: "setup", code: "real_short_alias_unavailable", comparison: None });
                bytes.extend_from_slice(&engine_line);
                assert_eq!(marker(&bytes, id, &nonce), Marker::Valid { stage: "setup", code: "real_short_alias_unavailable", comparison: None });
            }
            let bad_values = [
                ("schemaVersion", json!(true)), ("schemaVersion", json!("1")), ("schemaVersion", json!(1.0)),
                ("schemaVersion", json!(2)), ("scope", json!("private-canary")), ("scope", Value::Null),
                ("id", json!("case-alias")), ("id", json!("private-canary\nshort-alias")), ("id", json!(0)),
                ("nonce", json!("b".repeat(64))), ("nonce", json!("A".repeat(64))), ("nonce", json!(false)),
                ("stage", json!("admission")), ("stage", json!("complete")), ("stage", json!(["setup"])),
                ("code", json!("private-canary")), ("code", json!({"message":"private-canary"})),
                ("code", Value::Null), ("extra", json!("private-canary")),
            ];
            for (key, bad) in bad_values {
                let mut frame = base.clone(); frame[key] = bad;
                let bytes = encode(&frame)?;
                assert_eq!(marker(&bytes, id, &nonce), Marker::Invalid);
                let result = summary(id, &nonce, 78, Some("private-canary"), &bytes);
                assert_eq!(result["fixtureFailure"], json!({"status":"invalid"}));
                assert!(!result.to_string().contains("private-canary"));
            }
            for key in ["schemaVersion", "scope", "id", "nonce", "stage", "code"] {
                let mut frame = base.clone();
                frame.as_object_mut().ok_or("pure test object required")?.remove(key);
                assert_eq!(marker(&encode(&frame)?, id, &nonce), Marker::Invalid);
                let mut duplicate = PREFIX.to_vec();
                let body = serde_json::to_vec(&base)?;
                duplicate.extend_from_slice(&body[..body.len() - 1]);
                duplicate.extend_from_slice(format!(",{}:{}}}\n", serde_json::to_string(key)?, base[key]).as_bytes());
                assert_eq!(marker(&duplicate, id, &nonce), Marker::Invalid);
            }
            for frame in [json!([]), json!(null), json!(true)] {
                assert_eq!(marker(&encode(&frame)?, id, &nonce), Marker::Invalid);
            }
            let mut exact = valid[..valid.len() - 1].to_vec();
            exact.resize(1023, b' '); exact.push(b'\n');
            assert_eq!(marker(&exact, id, &nonce), Marker::Valid { stage: "setup", code: "real_short_alias_unavailable", comparison: None });
            let mut over_marker = exact.clone(); over_marker.insert(PREFIX.len(), b' ');
            let mut full = TELEMETRY.to_vec();
            full.resize(64 * 1024 - valid.len() - 1, b' '); full.push(b'\n'); full.extend_from_slice(&valid);
            assert_eq!(full.len(), 64 * 1024);
            assert_eq!(marker(&full, id, &nonce), Marker::Valid { stage: "setup", code: "real_short_alias_unavailable", comparison: None });
            let invalid_streams = vec![
                over_marker, [full.as_slice(), b"\n"].concat(), vec![b'x'; 64 * 1024 + 1],
                [valid.as_slice(), valid.as_slice()].concat(), [b"injected ", valid.as_slice()].concat(),
                [b"private-canary\n", valid.as_slice()].concat(), [valid.as_slice(), b"private-canary\n"].concat(),
                [valid.as_slice(), b"\n"].concat(), valid[..valid.len() - 1].to_vec(),
                [&valid[..valid.len() - 1], b"\r\n"].concat(),
                [valid.as_slice(), opaque_prior.as_slice()].concat(),
                [opaque_prior.repeat(4).as_slice(), valid.as_slice()].concat(),
                [engine_line.as_slice(), valid.as_slice()].concat(),
                [valid.as_slice(), engine_line.as_slice(), engine_line.as_slice()].concat(),
                [TELEMETRY, b"{\"injected\":\"", PREFIX, b"{}\"}\n"].concat(),
                [TAG, b"_V2 {}\n"].concat(), [TAG, b"_V1 "].concat(), [PREFIX, b"{not-json}\n"].concat(),
            ];
            for bytes in invalid_streams {
                assert_eq!(marker(&bytes, id, &nonce), Marker::Invalid);
                let result = summary(id, &nonce, -1073741819, Some("private-canary"), &bytes);
                assert_eq!(result["fixtureFailure"], json!({"status":"invalid"}));
                assert_eq!(result["ownerErrorCode"], "unknown_owner_error");
                assert!(!result.to_string().contains("private-canary"));
            }
            for bad_nonce in ["", "short", &"A".repeat(64), &"0".repeat(63)] {
                assert_eq!(marker(&valid, id, bad_nonce), Marker::Invalid);
            }
            for exit in [i32::MIN, -1073741819, -1, 0, 70, 78, i32::MAX] {
                let result = summary(id, &nonce, exit, None, &valid);
                assert_eq!(result["exitCode"].as_i64(), Some(i64::from(exit)));
                assert!(result["ownerErrorCode"].is_null());
                assert_eq!(result["id"], id);
                assert_eq!(result["fixtureFailure"], json!({"status":"valid","stage":"setup","code":"real_short_alias_unavailable"}));
                assert!(!result.to_string().contains(&nonce));
            }
            for code in OWNER_CODES {
                let result = summary(id, &nonce, 78, Some(code), &[]);
                assert_eq!(result["ownerErrorCode"], *code);
                assert_eq!(result["fixtureFailure"], json!({"status":"absent"}));
            }
            let result = summary("private-canary", &nonce, 78, Some("private-canary"), &valid);
            assert_eq!(result["id"], "unknown_control");
            assert_eq!(result["ownerErrorCode"], "unknown_owner_error");
            assert_eq!(result["fixtureFailure"], json!({"status":"invalid"}));
            assert!(!result.to_string().contains("private-canary"));
            Ok(())
        }
    }
}

// The Windows static-reader batch deliberately shares Case/start/result/settle
// and the original passive owner. This module has no process/task controller,
// Windows FFI, owner abort, PID discovery, deadline override or cleanup fallback.
#[cfg(windows)]
mod windows_snapshot {
    use super::*;
    use std::{collections::{BTreeMap, BTreeSet}, io::Read, os::windows::fs::MetadataExt};

    const BOOTSTRAP: &[u8] = include_bytes!("../../../tests/native_desktop_snapshot_windows.py");
    const SCOPE: &str = "windows-static-snapshot-native-v1";
    const SDK: &str = "10.0.26100.0";
    const PAYLOAD: u64 = 32 * 1024 * 1024;
    const FILE_BYTES: u64 = 8 * 1024 * 1024;
    const GROUPS: &[(&str, &[&str])] = &[
        ("W1", &["ordinary-source", "ordinary-zip", "closed-gate"]),
        ("W2", &["link-children", "reparse-root", "reparse-ancestor", "short-alias", "case-alias", "case-collision",
                  "subst-drive", "unc", "device", "ads"]),
        ("W3", &["root-reparse-race", "config-reparse-race", "walk-reparse-race", "case-mode-race"]),
        ("W4", &["acl-type", "read-eof-size", "entry-limit", "candidate-limit", "aggregate-limit", "depth-path-limit"]),
        ("W5", &["replace", "disappear", "config-disappear", "ending-metadata-case", "drive-map-change"]),
        ("W6", &["oplock-release", "oplock-withhold", "pending-failstop"]),
    ];
    const APIS: &[&str] = &["GetCurrentProcess", "IsWow64Process2", "QueryDosDeviceW", "NtCreateFile",
        "GetHandleInformation", "GetFileType", "GetFileInformationByHandleEx", "GetVolumeInformationByHandleW",
        "GetFinalPathNameByHandleW", "ReadFile", "CloseHandle", "DeviceIoControl"];
    const READER_COUNTS: &[&str] = &["acquired", "closeAttempts", "closeSucceeded", "closeFailed", "live", "maxLive",
        "maxBufferBytes", "rootOpens", "relativeOpens", "metadataChecks", "identitiesMatched", "readCalls", "readBytes",
        "readEof", "directoryCalls", "directoryRecords", "directoryEof", "outsideAcquired", "outsideReads", "outsideDescent",
        "aliasMetadataAcquired", "violations", "eventCount"];
    const FIXTURE_COUNTS: &[&str] = &["acquired", "closeAttempts", "closeSucceeded", "closeFailed", "live", "maxLive", "maxArenaBytes"];
    const ISSUES: &[&str] = &["config.missing", "config.invalid", "snapshot.scan-stopped", "snapshot.entry-limit",
        "snapshot.changed", "snapshot.file-limit", "snapshot.file-size", "snapshot.byte-limit", "snapshot.encoding",
        "snapshot.unsafe-file", "snapshot.unsupported", "snapshot.handle-limit", "snapshot.unreadable",
        "snapshot.config-output-limit", "snapshot.path-limit", "snapshot.link-excluded", "snapshot.depth-limit",
        "snapshot.container-limit", "snapshot.output-limit"];
    const NOT_VERIFIED: &[&str] = &["production-windows-enablement", "production-runtime-custody",
        "stateful-or-descendant-backends", "configuration-saving", "native-gui", "installers", "mobile-builds", "stores", "atomic-snapshot"];

    fn object(value: &Value, fields: &[&str]) -> Check<()> {
        let actual = value.as_object().ok_or("windows_object_required")?;
        require(actual.len() == fields.len() && fields.iter().all(|field| actual.contains_key(*field)), "windows_object_fields")
    }
    fn string<'a>(value: &'a Value) -> Check<&'a str> { value.as_str().ok_or("windows_string_required") }
    fn number(value: &Value, max: u64) -> Check<u64> {
        let value = value.as_u64().ok_or("windows_integer_required")?;
        require(value <= max, "windows_integer_bound")?;
        Ok(value)
    }
    fn sha(value: &Value) -> bool { value.as_str().is_some_and(|text|
        text.len() == 64 && text.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))) }
    fn hex_object(value: &Value) -> bool { value.as_str().is_some_and(|text|
        matches!(text.len(), 40 | 64) && text.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))) }
    fn before(end: Instant) -> Check<()> { require(Instant::now() < end, "windows_preparation_deadline") }
    fn canonical(value: &Value) -> Check<Vec<u8>> {
        // serde_json's default ordered map gives Python sort_keys order. Escape
        // non-ASCII explicitly so payload Unicode paths bind ensure_ascii=True.
        let text = serde_json::to_string(value).map_err(|_| "windows_json_encoding")?;
        let mut ascii = String::with_capacity(text.len());
        for c in text.chars() {
            if c.is_ascii() { ascii.push(c); }
            else {
                let mut units = [0u16; 2];
                for unit in c.encode_utf16(&mut units).iter() { ascii.push_str(&format!("\\u{unit:04x}")); }
            }
        }
        Ok(ascii.into_bytes())
    }
    fn depth(value: &Value, maximum: usize) -> Check<()> {
        let mut pending = vec![(value, 0usize)];
        while let Some((item, level)) = pending.pop() {
            require(level <= maximum, "windows_json_depth")?;
            match item {
                Value::Object(items) => pending.extend(items.values().map(|item| (item, level + 1))),
                Value::Array(items) => pending.extend(items.iter().map(|item| (item, level + 1))),
                _ => {},
            }
        }
        Ok(())
    }
    fn parse(bytes: &[u8], limit: usize) -> Check<Value> {
        require(!bytes.is_empty() && bytes.len() <= limit, "windows_json_bound")?;
        let value = protocol::strict_json(bytes).map_err(|_| "windows_strict_json")?;
        depth(&value, 16)?;
        Ok(value)
    }
    fn ordinary(metadata: &fs::Metadata) -> bool {
        !metadata.file_type().is_symlink() && metadata.file_attributes() & 0x400 == 0
    }
    fn anchor(path: &Path) -> Check<()> {
        require(path.is_absolute(), "windows_absolute_path_required")?;
        let mut checked = PathBuf::new();
        for component in path.components() {
            match component {
                std::path::Component::CurDir | std::path::Component::ParentDir => return Err("windows_path_component"),
                std::path::Component::Prefix(_) => { checked.push(component.as_os_str()); continue; },
                _ => checked.push(component.as_os_str()),
            }
            let metadata = fs::symlink_metadata(&checked).map_err(|_| "windows_anchored_input")?;
            require(ordinary(&metadata), "windows_reparse_input")?;
        }
        Ok(())
    }
    fn stamp(metadata: &fs::Metadata) -> (u64, u64, u64, u32) {
        (metadata.len(), metadata.creation_time(), metadata.last_write_time(), metadata.file_attributes())
    }
    fn read(path: &Path, limit: u64, end: Instant) -> Check<Vec<u8>> {
        before(end)?; anchor(path)?;
        let first = fs::symlink_metadata(path).map_err(|_| "windows_file_unavailable")?;
        require(first.is_file() && ordinary(&first) && first.len() <= limit, "windows_file_bound")?;
        let mut file = fs::File::open(path).map_err(|_| "windows_file_open")?;
        let opened = file.metadata().map_err(|_| "windows_file_metadata")?;
        require(ordinary(&opened) && stamp(&first) == stamp(&opened), "windows_file_changed")?;
        let mut bytes = Vec::new();
        let mut block = [0u8; 65536];
        loop {
            before(end)?;
            let count = file.read(&mut block).map_err(|_| "windows_file_read")?;
            if count == 0 { break; }
            require((bytes.len() + count) as u64 <= limit, "windows_file_bound")?;
            bytes.extend_from_slice(&block[..count]);
        }
        let ending = file.metadata().map_err(|_| "windows_file_metadata")?;
        let named = fs::symlink_metadata(path).map_err(|_| "windows_file_metadata")?;
        require(ordinary(&ending) && ordinary(&named) && stamp(&opened) == stamp(&ending)
            && stamp(&ending) == stamp(&named) && bytes.len() as u64 == ending.len(), "windows_file_changed")?;
        Ok(bytes)
    }
    fn relative(path: &Path, root: &Path) -> Check<String> {
        Ok(path.strip_prefix(root).map_err(|_| "windows_relative_path")?.to_str().ok_or("windows_unicode_path")?.replace('\\', "/"))
    }
    fn spelling(path: &Path) -> Check<String> {
        let text = path.to_str().ok_or("windows_unicode_path")?;
        let ordinary = text.strip_prefix("\\\\?\\").unwrap_or(text);
        require(ordinary.as_bytes().get(1) == Some(&b':') && ordinary.as_bytes().get(2) == Some(&b'\\'), "windows_drive_path")?;
        Ok(ordinary.to_owned())
    }

    struct WindowsInputs { base: Inputs, python: PathBuf, private: PathBuf, original: Vec<u8>, binding: String }
    impl WindowsInputs {
        fn admit() -> Check<Self> {
            require(environment("MRK_DESKTOP_HOSTED_CHECKS")? == "windows-snapshot-v1"
                && environment("GITHUB_ACTIONS")? == "true" && environment("RUNNER_ENVIRONMENT")? == "github-hosted"
                && crate::runtime::COMPILED_TARGET == "x86_64-pc-windows-msvc" && cfg!(target_arch = "x86_64")
                && cfg!(debug_assertions), "windows_hosted_admission_required")?;
            let end = Instant::now() + Duration::from_secs(45);
            let root = selected("MRK_DESKTOP_TEST_ROOT")?;
            anchor(&root)?;
            require(root.file_name().is_some_and(|name| name == "windows-snapshot")
                && fs::read_dir(&root).map_err(|_| "windows_root_unavailable")?.next().is_none(), "windows_root_not_fresh")?;
            let task = root.parent().ok_or("windows_task_layout")?;
            require(task.file_name().and_then(|x| x.to_str()).is_some_and(|x| x.starts_with("mrk-desktop-foundation-")), "windows_task_layout")?;
            let checkout = Path::new(env!("CARGO_MANIFEST_DIR")).parent().and_then(Path::parent).ok_or("windows_source_layout")?
                .canonicalize().map_err(|_| "windows_source_layout")?;
            let source = selected("MRK_DESKTOP_DEV_CORE")?;
            require(source == checkout.join("src") && !source.starts_with(&root), "windows_genuine_source_required")?;
            let zip = selected("MRK_DESKTOP_TEST_CORE_ZIP")?;
            require(zip == task.join("core.zip"), "windows_core_zip_layout")?;
            let python = selected("MRK_DESKTOP_DEV_PYTHON")?;
            let private = task.join("windows-snapshot-inputs.json");
            let original = read(&private, 1024 * 1024, end)?;
            let input = parse(&original, 1024 * 1024)?;
            object(&input, &["schemaVersion", "scope", "bindings", "coreFiles", "sdkRoot"])?;
            require(input["schemaVersion"].as_u64() == Some(1) && input["scope"] == SCOPE, "windows_input_scope")?;
            let bindings = input["bindings"].clone();
            object(&bindings, &["sourceSha", "sourceTree", "target", "pythonVersion", "rustVersion", "runId", "attempt", "job", "image",
                "architecture", "coreZipSha256", "coreInventorySha256", "sources", "pythonSha256", "compiledTestSha256", "compileInvocationSha256", "sdk"])?;
            require(bindings["sourceSha"] == environment("GITHUB_SHA")? && hex_object(&bindings["sourceSha"])
                && hex_object(&bindings["sourceTree"]) && bindings["target"] == crate::runtime::COMPILED_TARGET
                && bindings["pythonVersion"] == "3.14.7" && bindings["rustVersion"] == "1.98.0"
                && bindings["architecture"] == "X64", "windows_binding_scope")?;
            for name in ["coreZipSha256", "coreInventorySha256", "pythonSha256", "compiledTestSha256", "compileInvocationSha256"] {
                require(sha(&bindings[name]), "windows_binding_digest")?;
            }
            for name in ["runId", "attempt", "job", "image"] {
                let text = string(&bindings[name])?;
                require(!text.is_empty() && text.len() <= 256 && text.is_ascii() && !text.chars().any(char::is_control), "windows_binding_provenance")?;
            }
            require(hash(&read(&python, 128 * 1024 * 1024, end)?) == string(&bindings["pythonSha256"])?
                && hash(&read(&zip, PAYLOAD, end)?) == string(&bindings["coreZipSha256"])?
                && hash(&read(&std::env::current_exe().map_err(|_| "windows_current_exe")?, 512 * 1024 * 1024, end)?)
                    == string(&bindings["compiledTestSha256"])?, "windows_selected_binary_changed")?;
            let sources = bindings["sources"].as_array().ok_or("windows_source_inventory")?;
            require(!sources.is_empty() && sources.len() <= 256, "windows_source_inventory_bound")?;
            let mut previous = "";
            let mut fixture_bound = false;
            for item in sources {
                object(item, &["path", "sha256", "size"])?;
                let path = string(&item["path"])?;
                require(path > previous && crate::runtime::safe_payload_path(path) && sha(&item["sha256"]), "windows_source_inventory_path")?;
                let bytes = read(&checkout.join(path), FILE_BYTES, end)?;
                require(number(&item["size"], FILE_BYTES)? == bytes.len() as u64 && hash(&bytes) == string(&item["sha256"])?, "windows_bound_source_changed")?;
                if path == "tests/native_desktop_snapshot_windows.py" { fixture_bound = bytes == BOOTSTRAP; }
                previous = path;
            }
            require(fixture_bound, "windows_compiled_fixture_changed")?;
            let files = input["coreFiles"].as_array().ok_or("windows_core_inventory")?;
            require(!files.is_empty() && files.len() <= 2048 && hash(&canonical(&input["coreFiles"])?)
                == string(&bindings["coreInventorySha256"])?, "windows_whole_core_binding")?;
            let mut expected = BTreeSet::new();
            let mut total = 0u64;
            let mut previous = "";
            for item in files {
                object(item, &["path", "sha256", "size"])?;
                let path = string(&item["path"])?;
                require(path > previous && path.starts_with("mobile_release/") && crate::runtime::safe_payload_path(path)
                    && sha(&item["sha256"]), "windows_core_inventory_path")?;
                let bytes = read(&source.join(path), FILE_BYTES, end)?;
                total += bytes.len() as u64;
                require(total <= PAYLOAD && number(&item["size"], FILE_BYTES)? == bytes.len() as u64
                    && hash(&bytes) == string(&item["sha256"])?, "windows_genuine_core_changed")?;
                expected.insert(path.to_owned()); previous = path;
            }
            let mut pending = vec![(source.join("mobile_release"), 0usize)];
            let mut actual = BTreeSet::new();
            let mut entries = 0usize;
            while let Some((directory, level)) = pending.pop() {
                before(end)?; anchor(&directory)?;
                require(level <= 32, "windows_core_depth")?;
                for entry in fs::read_dir(&directory).map_err(|_| "windows_core_inventory")? {
                    let entry = entry.map_err(|_| "windows_core_inventory")?;
                    entries += 1; require(entries <= 8192, "windows_core_entry_bound")?;
                    let metadata = fs::symlink_metadata(entry.path()).map_err(|_| "windows_core_inventory")?;
                    require(ordinary(&metadata), "windows_core_link")?;
                    if metadata.is_dir() { pending.push((entry.path(), level + 1)); }
                    else { require(metadata.is_file(), "windows_core_special")?; actual.insert(relative(&entry.path(), &source)?); }
                }
            }
            require(actual == expected, "windows_core_member_roster")?;
            object(&bindings["sdk"], &["version", "headers"])?;
            require(bindings["sdk"]["version"] == SDK, "windows_sdk_pin")?;
            let sdk = PathBuf::from(string(&input["sdkRoot"])?);
            require(sdk.is_absolute() && sdk.file_name().is_some_and(|name| name == SDK), "windows_sdk_layout")?;
            let headers = bindings["sdk"]["headers"].as_array().ok_or("windows_sdk_headers")?;
            let expected_headers: BTreeSet<&str> = ["shared/ntdef.h", "shared/ntstatus.h", "shared/winerror.h", "um/winternl.h",
                "um/winnt.h", "um/minwinbase.h", "um/WinBase.h", "um/winioctl.h", "um/ioapiset.h", "um/fileapi.h",
                "um/securitybaseapi.h", "um/aclapi.h"].into_iter().collect();
            require(headers.len() == expected_headers.len(), "windows_sdk_header_roster")?;
            let mut seen = BTreeSet::new();
            for header in headers {
                object(header, &["path", "sha256", "size"])?;
                let path = string(&header["path"])?;
                require(expected_headers.contains(path) && seen.insert(path) && sha(&header["sha256"]), "windows_sdk_header_roster")?;
                let bytes = read(&sdk.join(path), FILE_BYTES, end)?;
                require(number(&header["size"], FILE_BYTES)? == bytes.len() as u64 && hash(&bytes) == string(&header["sha256"])?, "windows_installed_sdk_changed")?;
            }
            let binding = hash(&canonical(&bindings)?);
            std::env::set_var("MRK_DESKTOP_DEV_PYTHON", &python);
            Ok(Self { base: Inputs { root, source, zip, bindings }, python, private, original, binding })
        }
        fn unchanged(&self, end: Instant) -> Check<()> {
            require(read(&self.private, 1024 * 1024, end)? == self.original, "windows_private_inputs_changed")
        }
    }

    pub(super) fn select(mut runtime: VerifiedRuntime, selection: WindowsBootstrap, end: Instant) -> Check<VerifiedRuntime> {
        let WindowsBootstrap::Snapshot { group, id, nonce, binding, manifest } = selection else { return Ok(runtime); };
        before(end)?;
        require(environment("MRK_DESKTOP_HOSTED_CHECKS")? == "windows-snapshot-v1"
            && GROUPS.iter().any(|(g, ids)| *g == group && ids.contains(&id)) && id != "closed-gate", "windows_fixed_bootstrap_mode")?;
        let root = selected("MRK_DESKTOP_TEST_ROOT")?;
        let control = root.join(group).join(id).join("control");
        let bootstrap = control.join("engine-bootstrap.py");
        require(read(&bootstrap, 256 * 1024, end)? == BOOTSTRAP, "windows_copied_bootstrap_changed")?;
        let descriptor = parse(&read(&control.join("case.json"), 4096, end)?, 4096)?;
        let expected = json!({"schemaVersion":1,"scope":SCOPE,"id":id,"group":group,"nonce":nonce,
            "coreMode":if id == "ordinary-zip" {"zip"} else {"source"},"bindingSha256":binding,"dataManifestSha256":manifest});
        require(descriptor == expected, "windows_case_descriptor_changed")?;
        require(hash(&read(&control.join("data.json"), 2 * 1024 * 1024, end)?) == string(&expected["dataManifestSha256"])?, "windows_data_manifest_changed")?;
        before(end)?;
        runtime.bootstrap = bootstrap; // Python/core/cwd and the original endpoint are untouched.
        Ok(runtime)
    }

    struct PayloadInventory { files: Value, records: Value, facts: Value }
    fn payload(root: &Path, end: Instant) -> Check<PayloadInventory> {
        let mut pending: Vec<PathBuf> = ["project", "outside", "scratch"].into_iter().map(|name| root.join(name)).collect();
        let mut records = BTreeMap::new();
        let mut files = BTreeMap::new();
        let mut entries = 0u64; let mut bytes = 0u64; let mut max_depth = 0usize;
        while let Some(path) = pending.pop() {
            before(end)?;
            let relative = relative(&path, root)?;
            entries += 1; max_depth = max_depth.max(relative.split('/').count() - 1);
            require(entries <= 12000 && max_depth <= 14, "windows_fixture_entry_depth_bound")?;
            let metadata = fs::symlink_metadata(&path).map_err(|_| "windows_fixture_inventory")?;
            require(ordinary(&metadata), "windows_fixture_not_restored")?;
            if metadata.is_dir() {
                records.insert(relative.clone(), json!({"path":relative,"kind":"directory","sha256":null,"size":0}));
                for child in fs::read_dir(&path).map_err(|_| "windows_fixture_inventory")? {
                    require(entries + (pending.len() as u64) < 12000, "windows_fixture_entry_bound")?;
                    pending.push(child.map_err(|_| "windows_fixture_inventory")?.path());
                }
            } else {
                let content = read(&path, FILE_BYTES, end)?;
                bytes += content.len() as u64; require(bytes <= PAYLOAD, "windows_fixture_payload_bound")?;
                let item = json!({"path":relative,"sha256":hash(&content),"size":content.len()});
                files.insert(relative.clone(), item.clone());
                let mut record = item; record["kind"] = json!("file"); records.insert(relative, record);
            }
        }
        Ok(PayloadInventory { files: Value::Array(files.into_values().collect()), records: Value::Array(records.into_values().collect()),
            facts: json!({"entries":entries,"bytes":bytes,"maxDepth":max_depth}) })
    }

    struct Builder<'a> { root: &'a Path, end: Instant, bytes: u64 }
    impl Builder<'_> {
        fn directory(&self, relative: &str) -> Check<()> {
            before(self.end)?;
            fs::create_dir_all(self.root.join(relative)).map_err(|_| "windows_fixture_directory")
        }
        fn file(&mut self, relative: &str, bytes: &[u8]) -> Check<()> {
            before(self.end)?;
            self.bytes += bytes.len() as u64;
            require(self.bytes <= PAYLOAD && bytes.len() as u64 <= FILE_BYTES, "windows_fixture_write_bound")?;
            let path = self.root.join(relative);
            fs::create_dir_all(path.parent().ok_or("windows_fixture_parent")?).map_err(|_| "windows_fixture_directory")?;
            let mut options = fs::OpenOptions::new(); options.write(true).create_new(true);
            let mut file = options.open(path).map_err(|_| "windows_fixture_new_file")?;
            std::io::Write::write_all(&mut file, bytes).map_err(|_| "windows_fixture_write")
        }
        fn ordinary(&mut self) -> Check<()> {
            self.file("project/release/mobile-release.json", &canonical(&draft())?)?;
            self.file("project/android/app/build.gradle", b"plugins { id 'com.android.application' }\nandroid { defaultConfig { applicationId 'org.fixture.app' } }\n")?;
            self.file("project/ios/Fixture.xcodeproj/project.pbxproj", b"PRODUCT_BUNDLE_IDENTIFIER = org.fixture.ios;\n")?;
            self.file("project/release/version.properties", b"VERSION_NAME=9.9.9\nBUILD_NUMBER=999\n")?;
            self.file("project/caf\u{e9}/ordinary.txt", b"ordinary-unicode-component\n")
        }
        fn outside(&mut self, name: &str) -> Check<()> {
            for (path, label) in [("file-canary", "file"), ("hardlink-canary", "hardlink"),
                ("symlink-dir/build.gradle", "symlink"), ("junction-dir/build.gradle", "junction"),
                ("target/marker.txt", "root"), ("target/next/marker.txt", "root"),
                ("target/mobile-release.json", "config"), ("target/build.gradle", "walk")] {
                self.file(&format!("outside/{path}"), format!("outside-canary:{name}:{label}\n").as_bytes())?;
            }
            Ok(())
        }
    }

    fn prepare(inputs: &WindowsInputs, group: &'static str, name: &'static str) -> Check<(Case, PayloadInventory)> {
        let group_root = inputs.base.root.join(group);
        if !group_root.exists() { fs::create_dir(&group_root).map_err(|_| "windows_group_directory")?; }
        let group_inputs = Inputs { root: group_root, source: inputs.base.source.clone(), zip: inputs.base.zip.clone(), bindings: Value::Null };
        let case = Case::new(&group_inputs, name, None, name == "ordinary-zip")?;
        let end = case.begin + Duration::from_secs(45);
        let mut builder = Builder { root: &case.root, end, bytes: 0 };
        for path in ["project", "outside", "scratch"] { builder.directory(path)?; }
        builder.outside(name)?;
        match name {
            "reparse-root" | "entry-limit" => {},
            "read-eof-size" | "candidate-limit" | "aggregate-limit" | "depth-path-limit"
                | "config-reparse-race" | "case-mode-race" | "acl-type" => builder.directory("project/release")?,
            _ => builder.ordinary()?,
        }
        match name {
            "link-children" => for path in ["project/linked-file", "project/hardlinked", "project/junction-dir"] { builder.directory(path)?; },
            "reparse-ancestor" => builder.directory("project/ancestor")?,
            "short-alias" => builder.directory("project/LongSnapshotDirectory")?,
            "case-alias" => builder.directory("project/CaseExact")?,
            "case-collision" => builder.directory("project/collision")?,
            "root-reparse-race" => builder.directory("project/held")?,
            "walk-reparse-race" => builder.file("project/walk-parent/build.gradle", b"// enumerated original placeholder\n")?,
            "acl-type" => {
                builder.directory("project/release/mobile-release.json")?;
                builder.directory("project/read-denied")?; // Both denied leaves start absent.
                builder.file("project/sibling/build.gradle", b"// accessible sibling\n")?;
            },
            "read-eof-size" => {
                builder.file("project/empty/build.gradle", b"")?;
                builder.file("project/invalid/build.gradle", b"\xff\xfe")?;
                builder.file("project/multi/build.gradle", &vec![b' '; 65536 + 7])?;
                builder.file("project/exact/build.gradle", &vec![b' '; 524288])?;
                builder.file("project/oversize/build.gradle", &vec![b' '; 524289])?;
            },
            "entry-limit" => for index in 0..10001 { builder.file(&format!("project/.ignored-{index:05}"), b"x")?; },
            "candidate-limit" => for index in 0..129 { builder.file(&format!("project/candidate{index:03}/build.gradle"), b"")?; },
            "aggregate-limit" => {
                let bytes = vec![b' '; 524288];
                for index in 0..16 { builder.file(&format!("project/budget{index:02}/build.gradle"), &bytes)?; }
                builder.file("project/extra/build.gradle", b"x")?;
            },
            "depth-path-limit" => {
                let mut path = "project".to_owned();
                for index in 1..=13 { path.push_str(&format!("/d{index:02}")); builder.directory(&path)?; }
                builder.file(&format!("{path}/build.gradle"), b"// inadmissible depth\n")?;
                let component = "p".repeat(180);
                builder.file(&format!("project/{component}/{component}/{component}/build.gradle"), b"// inadmissible relative bytes\n")?;
                builder.file("project/sibling/build.gradle", b"// ordinary sibling\n")?;
            },
            "ending-metadata-case" => builder.directory("project/empty-ending")?,
            "oplock-release" | "oplock-withhold" | "pending-failstop" => {
                builder.file("project/oplock/build.gradle", b"// actual oplock target\n")?;
                if name == "pending-failstop" { builder.file("scratch/pending.bin", b"original-pending-fixture\n")?; }
            },
            _ => {},
        }
        let inventory = payload(&case.root, end)?;
        let manifest = canonical(&inventory.files)?;
        require(manifest.len() <= 2 * 1024 * 1024, "windows_fixture_manifest_bound")?;
        fs::write(case.control.join("data.json"), &manifest).map_err(|_| "windows_fixture_manifest_write")?;
        let manifest_hash = hash(&manifest);
        let descriptor = json!({"schemaVersion":1,"scope":SCOPE,"group":group,"id":name,"nonce":case.nonce,
            "coreMode":if name == "ordinary-zip" {"zip"} else {"source"},"bindingSha256":inputs.binding,"dataManifestSha256":manifest_hash});
        let descriptor_bytes = canonical(&descriptor)?;
        require(descriptor_bytes.len() <= 4096, "windows_descriptor_bound")?;
        fs::write(case.control.join("case.json"), descriptor_bytes).map_err(|_| "windows_descriptor_write")?;
        if name != "closed-gate" {
            fs::write(case.control.join("engine-bootstrap.py"), BOOTSTRAP).map_err(|_| "windows_bootstrap_copy")?;
            require(read(&case.control.join("engine-bootstrap.py"), 256 * 1024, end)? == BOOTSTRAP, "windows_bootstrap_copy_changed")?;
            *lock(&case.supervisor.inner.test.windows_bootstrap) = WindowsBootstrap::Snapshot {
                group, id: name, nonce: case.nonce.clone(), binding: inputs.binding.clone(), manifest: manifest_hash,
            };
        }
        inputs.unchanged(end)?;
        before(end)?;
        Ok((case, inventory))
    }

    fn check_issues(value: &Value) -> Check<Vec<String>> {
        let issues = value.as_array().ok_or("windows_dto_issues")?;
        require(issues.len() <= 64, "windows_dto_issue_bound")?;
        let mut codes = Vec::new();
        for issue in issues {
            object(issue, &["code", "status", "message", "remediation"])?;
            let code = string(&issue["code"])?;
            require(ISSUES.contains(&code) && matches!(string(&issue["status"])?, "SKIP" | "INVALID"), "windows_dto_issue_code")?;
            for field in ["message", "remediation"] {
                let text = string(&issue[field])?;
                require(!text.is_empty() && text.chars().count() <= 1024 && !text.chars().any(char::is_control), "windows_dto_issue_text")?;
            }
            codes.push(code.to_owned());
        }
        Ok(codes)
    }
    fn hint_budget(value: &Value) -> Check<()> {
        let mut pending = vec![value]; let mut count = 0usize;
        while let Some(item) = pending.pop() {
            count += 1; require(count <= 4096, "windows_dto_hint_nodes")?;
            match item {
                Value::Object(items) => {
                    require(items.len() <= 128, "windows_dto_hint_items")?;
                    for (key, item) in items { require(key.chars().count() <= 512, "windows_dto_hint_string")?; pending.push(item); }
                },
                Value::Array(items) => { require(items.len() <= 128, "windows_dto_hint_items")?; pending.extend(items); },
                Value::String(text) => require(text.chars().count() <= 512, "windows_dto_hint_string")?,
                Value::Null | Value::Bool(_) | Value::Number(_) => {},
            }
        }
        Ok(())
    }
    fn android() -> Value { json!({"module":":android:app","buildFile":"android/app/build.gradle",
        "applicationId":"org.fixture.app"}) }
    fn ios() -> Value { json!({"projects":["ios/Fixture.xcodeproj"],"workspaces":[],"schemes":[],
        "bundleIds":["org.fixture.ios"],"generatedProjectSources":[],"bundleId":"org.fixture.ios","project":"ios/Fixture.xcodeproj"}) }
    fn result(case: &Case, outcome: &Query, reader: &Value) -> Check<Value> {
        let name = case.name;
        let expected_error: &[&str] = match name {
            "closed-gate" => &["platform_unavailable"],
            "reparse-root" | "reparse-ancestor" | "root-reparse-race" | "short-alias" | "case-alias" => &["unsafe_path", "snapshot_unavailable"],
            "subst-drive" => &["snapshot_unavailable"],
            "unc" | "device" | "ads" => &["unsafe_path"],
            "oplock-withhold" => &["query_timeout"],
            "pending-failstop" => &["engine_failed"],
            _ => &[],
        };
        if let Err(error) = outcome {
            require(expected_error.contains(&error.code.as_str()), "windows_unexpected_genuine_error")?;
            return Ok(json!({"return":"error","code":error.code,"configState":null,"partial":null,"scan":null,"issueCodes":[],"dtoSha256":null}));
        }
        require(expected_error.is_empty(), "windows_expected_refusal_missing")?;
        let value = outcome.as_ref().map_err(|_| "windows_result_unavailable")?;
        object(value, &["root", "observedAt", "observationScope", "config", "discovery", "assurance", "issues"])?;
        let root = string(&value["root"])?;
        let ordinary = spelling(&case.root.join("project"))?;
        let root_matches = if name == "ordinary-zip" { root == format!("\\\\?\\{ordinary}") }
            else if name == "drive-map-change" { ["Z:", "Y:", "X:"].iter().any(|drive| root == format!("{drive}{}", &ordinary[2..])) }
            else { root == ordinary };
        require(root_matches && value["observationScope"] == "single-request-non-atomic", "windows_dto_scope")?;
        let observed = string(&value["observedAt"])?;
        require((20..=64).contains(&observed.len()) && observed.contains('T') && observed.ends_with("+00:00")
            && observed.bytes().all(|b| b.is_ascii_digit() || b"-T:.+".contains(&b)), "windows_dto_observed_time")?;
        require(value["assurance"] == json!({"basis":"static-text","projectCodeExecuted":false,"toolsProbed":false,
            "credentialsRead":false,"gitObserved":false,"storeContacted":false,"writesPerformed":false,"releaseReadiness":"unknown"}), "windows_dto_false_assurance")?;
        let config = &value["config"];
        object(config, &["path", "state", "data", "issues"])?;
        require(config["path"] == "release/mobile-release.json", "windows_dto_config_path")?;
        let config_state = string(&config["state"])?;
        require(matches!(config_state, "missing" | "format-valid" | "unavailable"), "windows_dto_config_state")?;
        if config_state == "format-valid" { require(config["data"] == draft(), "windows_dto_exact_config")?; }
        else { require(config["data"].is_null(), "windows_dto_untrusted_config")?; }
        check_issues(&config["issues"])?;
        let discovery = &value["discovery"];
        object(discovery, &["state", "partial", "hints", "scan", "limits"])?;
        require(discovery["state"] == "unverified" && discovery["partial"].is_boolean(), "windows_dto_discovery_state")?;
        require(discovery["limits"] == json!({"maxDepth":12,"maxEntries":10000,"maxSourceFiles":128,"maxSourceFileBytes":524288,
            "maxTotalSourceBytes":8388608,"maxRootBytes":4096,"maxRelativePathBytes":512,"maxIssues":64,"maxHintNodes":4096,
            "maxHintStringCharacters":512,"maxHintItems":128,"scanSeconds":5.0,"maxConfigOutputNodes":8000}), "windows_dto_limits")?;
        let scan = &discovery["scan"];
        object(scan, &["entries", "sourceFiles", "sourceBytes", "excludedEntries"])?;
        for (key, limit) in [("entries", 10000), ("sourceFiles", 128), ("sourceBytes", 8388608), ("excludedEntries", 10000)] { number(&scan[key], limit)?; }
        require(scan["sourceBytes"] == reader["readBytes"], "windows_dto_original_read_accounting")?;
        let hints = discovery["hints"].as_object().ok_or("windows_dto_hints")?;
        hint_budget(&discovery["hints"])?;
        require(hints.keys().all(|key| ["android", "ios", "versionSource", "versionNameKey", "versionBuildKey"].contains(&key.as_str())), "windows_dto_hint_fields")?;
        if let Some(value) = hints.get("android") { require(value == &android(), "windows_dto_android_hint")?; }
        if let Some(value) = hints.get("ios") { require(value == &ios(), "windows_dto_ios_hint")?; }
        let version_keys = ["versionSource", "versionNameKey", "versionBuildKey"];
        let version_count = version_keys.iter().filter(|key| hints.contains_key(**key)).count();
        require(version_count == 0 || (version_count == 3 && discovery["hints"]["versionSource"] == "release/version.properties"
            && discovery["hints"]["versionNameKey"] == "VERSION_NAME" && discovery["hints"]["versionBuildKey"] == "BUILD_NUMBER"), "windows_dto_version_hints")?;
        let codes = check_issues(&value["issues"])?;
        let contains = |code: &str| codes.iter().any(|item| item == code);
        if matches!(name, "ordinary-source" | "ordinary-zip") {
            require(config_state == "format-valid" && discovery["partial"] == false && codes.is_empty()
                && hints.len() == 5 && scan["sourceFiles"] == 4 && scan["entries"] == reader["directoryRecords"]
                && scan["excludedEntries"] == 0, "windows_ordinary_dto_not_complete")?;
            let before_files = ["release/mobile-release.json", "android/app/build.gradle", "ios/Fixture.xcodeproj/project.pbxproj", "release/version.properties"];
            let mut expected_bytes = 0u64;
            for path in before_files { expected_bytes += fs::symlink_metadata(case.root.join("project").join(path)).map_err(|_| "windows_ordinary_bytes")?.len(); }
            require(scan["sourceBytes"].as_u64() == Some(expected_bytes), "windows_ordinary_exact_bytes")?;
        } else if name != "oplock-release" {
            require(discovery["partial"] == true && !codes.is_empty(), "windows_partial_dto_required")?;
        }
        if matches!(name, "config-reparse-race" | "case-mode-race" | "acl-type" | "config-disappear" | "drive-map-change") {
            require(config_state == "unavailable", "windows_configuration_must_be_unavailable")?;
        }
        let required: &[&str] = match name {
            "entry-limit" => &["snapshot.entry-limit"], "candidate-limit" => &["snapshot.file-limit"],
            "aggregate-limit" => &["snapshot.byte-limit"], "depth-path-limit" => &["snapshot.depth-limit", "snapshot.path-limit"],
            "replace" | "disappear" | "config-disappear" | "ending-metadata-case" | "drive-map-change" => &["snapshot.changed"],
            "read-eof-size" => &["snapshot.encoding", "snapshot.file-size"], _ => &[],
        };
        require(required.iter().all(|code| contains(code)), "windows_required_actual_issue")?;
        if matches!(name, "replace" | "disappear" | "ending-metadata-case") { require(!hints.contains_key("android"), "windows_changed_hint_leaked")?; }
        Ok(json!({"return":"ok","code":null,"configState":config_state,"partial":discovery["partial"],
            "scan":scan,"issueCodes":codes,"dtoSha256":hash(&canonical(value)?)}))
    }

    async fn original(case: &Case, outcome: &Query) -> Check<(Value, Observation)> {
        case.native_facts(true, true)?;
        let owners = case.supervisor.inner.test.owners();
        require(owners.len() == 1 && owners[0].id == "query-1", "windows_one_original_owner_required")?;
        let owner = &owners[0];
        let observer_returned = owner.observer.lock().await.is_none();
        let observed = lock(&owner.observation).clone();
        let state = lock(&owner.state);
        let error_code = state.error.as_ref().map(|error| error.code.as_str());
        require(error_code == outcome.as_ref().err().map(|error| error.code.as_str()), "windows_original_sticky_result_changed")?;
        let terminal = state.terminal;
        let driver = state.driver_join == ManagementJoin::Returned && observed.driver_joined;
        let watchdog = state.watchdog_join == ManagementJoin::Returned && observed.watchdog_joined;
        let unknown = state.unknown;
        let error_value = error_code.map(str::to_owned);
        drop(state);
        let permit_released = lock(&owner.permit).is_none() && case.supervisor.inner.permits.available_permits() == ACTIVE_LIMIT;
        let registry_empty = lock(&case.supervisor.inner.owners).is_empty();
        require(observer_returned && terminal && driver && watchdog && permit_released && registry_empty
            && !unknown && !case.supervisor.disabled(), "windows_original_not_settled")?;
        let abnormal = matches!(case.name, "oplock-withhold" | "pending-failstop");
        let exit = observed.windows_exit_code.ok_or("windows_original_exit_code_missing")?;
        let exit_check = require(observed.exit_success == Some(!abnormal) && (exit != 0) == abnormal
            && (case.name != "pending-failstop" || exit == 70), "windows_original_exit_differs");
        if exit_check.is_err() && !abnormal {
            windows_snapshot_failure_diagnostics::log_exit(case.name, &case.nonce, exit,
                error_value.as_deref(), &observed.windows_stderr);
        }
        exit_check?;
        require(abnormal || observed.stdout_bytes > 0, "windows_original_response_missing")?;
        let facts = json!({"id":"query-1","inspectionJoined":observed.inspection_joined,"acquisitionJoined":observed.acquisition_joined,
            "spawned":observed.spawned,"waited":observed.waited,"waitExitCode":exit,"exitSuccess":observed.exit_success,
            "writerJoined":observed.writer_joined,"writerComplete":observed.writer_complete,"stdoutEof":observed.stdout_eof,
            "stderrEof":observed.stderr_eof,"stdoutJoined":observed.stdout_joined,"stderrJoined":observed.stderr_joined,
            "stdoutBytes":observed.stdout_bytes,"stderrBytes":observed.stderr_bytes,"driverReturned":driver,"watchdogReturned":watchdog,
            "observerReturned":observer_returned,"terminal":terminal,"permitReleased":permit_released,"registryEmpty":registry_empty,
            "unknownLatched":unknown,"disabled":case.supervisor.disabled(),"errorCode":error_value});
        Ok((facts, observed))
    }

    fn uninstrumented() -> (Value, Value) {
        let mut reader = json!({"state":"uninstrumented","calls":[],"eventSha256":null,"closeDisposition":"uninstrumented"});
        for field in READER_COUNTS { reader[*field] = Value::Null; }
        let mut fixture = json!({"state":"uninstrumented","pending":"none","thread":"none","event":"none",
            "restored":null,"resourcesSettledBy":"uninstrumented","data":null,"profile":null,"checks":{}});
        for field in FIXTURE_COUNTS { fixture[*field] = Value::Null; }
        (reader, fixture)
    }
    fn telemetry(case: &Case, observed: &Observation) -> Check<(Value, Value)> {
        let bytes = &observed.windows_stderr;
        if case.name == "closed-gate" {
            require(bytes.is_empty(), "windows_uninstrumented_stderr")?;
            return Ok(uninstrumented());
        }
        require(!bytes.is_empty() && bytes.len() <= 64 * 1024 && bytes.last() == Some(&b'\n'), "windows_telemetry_bound")?;
        let mut frames = Vec::new();
        for line in bytes[..bytes.len() - 1].split(|b| *b == b'\n') {
            let body = line.strip_prefix(b"MRK_WINDOWS_SNAPSHOT_V1 ").ok_or("windows_unexpected_stderr")?;
            let frame = parse(body, 64 * 1024)?;
            object(&frame, &["schemaVersion", "scope", "id", "nonce", "phase", "reader", "fixture"])?;
            require(frame["schemaVersion"].as_u64() == Some(1) && frame["scope"] == SCOPE
                && frame["id"] == case.name && frame["nonce"] == case.nonce && frames.len() < 4, "windows_telemetry_binding")?;
            frames.push(frame);
        }
        let expected: &[&str] = match case.name {
            "oplock-release" => &["reader-entry", "oplock-break", "complete"],
            "oplock-withhold" => &["reader-entry", "oplock-break"],
            "pending-failstop" => &["pending-entry"],
            _ => &["complete"],
        };
        require(frames.len() == expected.len() && frames.iter().zip(expected).all(|(frame, phase)| frame["phase"] == *phase), "windows_checkpoint_roster")?;
        let last = frames.last().ok_or("windows_checkpoint_missing")?;
        let reader = last["reader"].clone(); let mut fixture = last["fixture"].clone();
        if matches!(case.name, "oplock-withhold" | "pending-failstop") {
            require(reader["state"] == "prefix" && fixture["state"] == "prefix" && fixture["restored"].is_null()
                && fixture["resourcesSettledBy"] == "returned-closes", "windows_abnormal_prefix_shape")?;
            // No adapter-close or thread-join claim. This disposition is derived
            // ONLY after original wait, both EOF/joins and all owner returns.
            fixture["resourcesSettledBy"] = json!("original-process");
            if case.name == "oplock-withhold" {
                require(fixture["checks"]["originalProcessStopped"].is_null(), "windows_child_claimed_original_stop")?;
                fixture["checks"]["originalProcessStopped"] = json!(observed.waited && observed.exit_success == Some(false));
            } else {
                require(fixture["checks"]["afterCallMarker"].is_null() && fixture["checks"]["originalExitCode"].is_null(), "windows_child_claimed_original_exit")?;
                fixture["checks"]["afterCallMarker"] = json!(false); // Exact one pre-entry frame and original stderr EOF.
                fixture["checks"]["originalExitCode"] = json!(observed.windows_exit_code);
            }
        }
        Ok((reader, fixture))
    }

    fn check_reader(name: &str, reader: &Value) -> Check<()> {
        let mut fields = vec!["state", "calls", "eventSha256", "closeDisposition"]; fields.extend_from_slice(READER_COUNTS);
        object(reader, &fields)?;
        if name == "closed-gate" { return require(reader == &uninstrumented().0, "windows_uninstrumented_reader_changed"); }
        let abnormal = matches!(name, "oplock-withhold" | "pending-failstop");
        require(reader["state"] == (if abnormal {"prefix"} else {"complete"})
            && reader["closeDisposition"] == (if abnormal {"not-observed-after-abnormal-exit"} else {"returned-once"})
            && sha(&reader["eventSha256"]), "windows_reader_state")?;
        for field in READER_COUNTS {
            number(&reader[*field], match *field { "live" | "maxLive" => 144, "maxBufferBytes" => 65536,
                "readBytes" => 8388608, _ => 1000000 })?;
        }
        let calls = reader["calls"].as_array().ok_or("windows_reader_calls")?;
        require(calls.len() == APIS.len(), "windows_reader_api_roster")?;
        for (call, api) in calls.iter().zip(APIS) {
            object(call, &["api", "entered", "returned", "completed", "errors"])?;
            require(call["api"] == *api, "windows_reader_api_roster")?;
            let entered = number(&call["entered"], 1000000)?; let returned = number(&call["returned"], 1000000)?;
            let completed = number(&call["completed"], 1000000)?; let errors = number(&call["errors"], 1000000)?;
            require(errors <= completed && completed <= returned && returned <= entered, "windows_reader_classification_accounting")?;
            if !abnormal { require(entered == returned && returned == completed, "windows_reader_unclassified_call")?; }
            else {
                let pending_api = if name == "oplock-withhold" { "NtCreateFile" } else { "DeviceIoControl" };
                require(entered - returned == (if *api == pending_api { 1 } else { 0 }) && returned == completed,
                    "windows_reader_abnormal_entry_roster")?;
            }
            if name == "pending-failstop" && *api == "DeviceIoControl" {
                require(entered == 1 && returned == 0 && completed == 0, "windows_pending_entry_not_original")?;
            }
            if name == "oplock-withhold" && *api == "NtCreateFile" {
                require(entered == returned + 1 && returned == completed, "windows_oplock_original_not_blocked")?;
            }
        }
        require(reader["outsideReads"] == 0 && reader["outsideDescent"] == 0 && reader["violations"] == 0
            && reader["metadataChecks"] == reader["identitiesMatched"] && reader["outsideAcquired"] == reader["aliasMetadataAcquired"]
            && (name == "link-children" || reader["outsideAcquired"] == 0), "windows_reader_outside_or_identity_violation")?;
        let count = |field: &str| number(&reader[field], 1000000);
        let by_api: BTreeMap<&str, &Value> = APIS.iter().copied().zip(calls.iter()).collect();
        let api_count = |api: &str, field: &str| -> Check<u64> {
            let call = by_api.get(api).ok_or("windows_reader_api_roster")?;
            number(&call[field], 1000000)
        };
        // These are the same concrete constraints checked by the final helper,
        // enforced here BEFORE any payload removal. A digest or free-standing
        // success counter cannot substitute for an original classified call.
        require(count("rootOpens")? + count("relativeOpens")? == api_count("NtCreateFile", "entered")?
            && count("acquired")? == api_count("NtCreateFile", "completed")? - api_count("NtCreateFile", "errors")?
            && count("closeAttempts")? == api_count("CloseHandle", "entered")?
            && count("closeSucceeded")? == api_count("CloseHandle", "completed")? - api_count("CloseHandle", "errors")?
            && count("closeFailed")? == api_count("CloseHandle", "errors")? && count("closeFailed")? == 0
            && count("closeSucceeded")? == count("closeAttempts")? && count("closeAttempts")? <= count("acquired")?
            && count("live")? == count("acquired")? - count("closeAttempts")?
            && count("live")? <= count("maxLive")? && count("maxLive")? <= count("acquired")?, "windows_reader_accounting")?;
        let successful_reads = api_count("ReadFile", "completed")? - api_count("ReadFile", "errors")?;
        let completed_calls = calls.iter().try_fold(0u64, |sum, call| -> Check<u64> {
            Ok(sum + number(&call["completed"], 1000000)?)
        })?;
        require(count("metadataChecks")? <= api_count("GetFileType", "completed")?
            && 4 * count("metadataChecks")? + count("directoryEof")? <= api_count("GetFileInformationByHandleEx", "completed")?
            && count("readEof")? <= successful_reads && successful_reads <= api_count("ReadFile", "entered")?
            && api_count("ReadFile", "entered")? <= count("readCalls")?
            && number(&reader["readBytes"], 8388608)? <= 65536 * (successful_reads - count("readEof")?)
            && count("directoryEof")? <= count("directoryCalls")?
            && count("directoryEof")? <= api_count("GetFileInformationByHandleEx", "errors")?
            && count("eventCount")? >= completed_calls, "windows_reader_metadata_eof_accounting")?;
        if count("acquired")? > 0 {
            require(count("maxLive")? > 0 && count("eventCount")? > 0, "windows_reader_acquisition_observation")?;
        }
        if count("readCalls")? > 0 || count("directoryCalls")? > 0 || count("metadataChecks")? > 0 {
            require(count("acquired")? > 0 && count("maxBufferBytes")? > 0, "windows_reader_output_arena_observation")?;
        }
        if !abnormal {
            require(reader["acquired"] == reader["closeAttempts"] && reader["closeAttempts"] == reader["closeSucceeded"]
                && reader["closeFailed"] == 0 && reader["live"] == 0, "windows_reader_closes_unsettled")?;
        }
        if matches!(name, "ordinary-source" | "ordinary-zip" | "oplock-release") {
            require(reader["rootOpens"] == 1 && count("relativeOpens")? > 0 && count("metadataChecks")? > 0
                && count("readEof")? > 0 && count("directoryEof")? > 0, "windows_ordinary_native_observations_missing")?;
        }
        if matches!(name, "unc" | "device" | "ads") {
            require(calls.iter().all(|call| call["entered"] == 0) && reader["acquired"] == 0, "windows_unsafe_namespace_entered")?;
        } else {
            require(api_count("GetCurrentProcess", "completed")? == 1 && api_count("IsWow64Process2", "completed")? == 1
                && api_count("QueryDosDeviceW", "completed")? > 0, "windows_reader_native_admission_observation")?;
        }
        if abnormal {
            require(reader["rootOpens"] == 1 && count("relativeOpens")? > 0 && count("live")? > 0
                && count("identitiesMatched")? > 0, "windows_reader_retained_original_parent")?;
        }
        Ok(())
    }

    enum Rule { Equal(Value), Range(u64, u64) }
    fn checks(name: &str, value: &Value) -> Check<()> {
        let mut rules = BTreeMap::<&str, Rule>::new();
        let truths = match name {
            "ordinary-source" | "ordinary-zip" => "genuineCore configExact androidExact iosExact versionNotDisclosed",
            "link-children" => "hardlinkIdMatch",
            "reparse-root" | "reparse-ancestor" => "unsafeControlMatched rootRefused",
            "short-alias" | "case-alias" => "aliasObserved spellingDiffers sameObject",
            "case-collision" => "distinctIds caseRestored",
            "subst-drive" => "aliasInitiallyAbsent localNonSystemToken subtreeMappingObserved mappingRemoved",
            "unc" | "device" | "ads" => "unsafePathRefused",
            "root-reparse-race" | "config-reparse-race" | "walk-reparse-race" => "parentIdSame mutationSucceeded originalRelativeEntry entryBeforeDeadline unsafeControlMatched sharingWriteDenied sharingDeleteDenied reparseRestored",
            "case-mode-race" => "parentIdSame originalRelativeEntry entryBeforeDeadline missingNotTrusted caseRestored",
            "acl-type" => "fileAccessDenied directoryAccessDenied accessibleSiblingRead configDirectoryRefused initialAbsenceRestored",
            "read-eof-size" => "emptyEof invalidUtf8Refused shortFinalRead multichunkEof exactLimitEof",
            "entry-limit" => "entryLimitIssue", "candidate-limit" => "refusedExtraCandidate sourceFileLimitIssue",
            "aggregate-limit" => "capNotEof byteLimitIssue", "depth-path-limit" => "depthIssue pathIssue siblingRead",
            "replace" => "entryObserved originalIdDiffers changedIssue",
            "disappear" | "config-disappear" => "entryObserved actualMissingReturn changedIssue missingNotTrusted",
            "ending-metadata-case" => "genuineFileEof writeMetadataChanged fileChangeVeto genuineDirectoryEof caseFlagsChanged directoryCaseVeto attributesRestored",
            "drive-map-change" => "aliasInitiallyAbsent localNonSystemToken initialVolumeMapping endingSubtreeMapping changedIssue mappingRemoved",
            "oplock-release" => "grantPending originalReaderEntered breakSignalled completionKnown blockedBeforeRelease holderCloseReturned observerJoined eventCloseReturned originalReaderReturned",
            "oplock-withhold" => "grantPending originalReaderEntered breakSignalled completionKnown originalProcessStopped",
            "pending-failstop" => "originalParentHeld realFsctlEntry",
            "closed-gate" => "", _ => return Err("windows_unknown_case"),
        };
        for field in truths.split_whitespace() { rules.insert(field, Rule::Equal(json!(true))); }
        let mut equal = |field, value| { rules.insert(field, Rule::Equal(value)); };
        match name {
            "ordinary-source" | "ordinary-zip" => equal("spelling", json!(if name == "ordinary-zip" {"verbatim"} else {"ordinary"})),
            "link-children" => {
                equal("fileSymlinkTag", json!(0xA000000Cu64)); equal("directorySymlinkTag", json!(0xA000000Cu64));
                equal("junctionTag", json!(0xA0000003u64)); equal("hardlinkReadBytes", json!(0)); equal("restoredLinks", json!(4));
            },
            "reparse-root" | "reparse-ancestor" => { equal("junctionTag", json!(0xA0000003u64)); equal("reparseRestored", json!(1)); },
            "short-alias" | "case-alias" => equal("aliasReadBytes", json!(0)),
            "case-collision" => { equal("enabledFlags", json!(1)); equal("collisionFiles", json!(2)); equal("collisionDirectoryBatches", json!(0)); },
            "subst-drive" => equal("rootOpens", json!(0)),
            "unc" | "device" | "ads" => { equal("readerFfiEntries", json!(0)); equal("readerInstances", json!(0)); },
            "root-reparse-race" | "config-reparse-race" | "walk-reparse-race" => {
                equal("mutationAccess", json!(256)); equal("mutationTag", json!(0xA0000003u64)); equal("outsideAcquired", json!(0));
                equal("outsideReadBytes", json!(0)); equal("preparatoryDeletes", json!(if name == "walk-reparse-race" {1} else {0}));
            },
            "case-mode-race" => { equal("mutationAccess", json!(256)); equal("enabledFlags", json!(1)); },
            "acl-type" => { equal("denialPoliciesConfirmed", json!(2)); equal("createdObjectsRemoved", json!(2)); },
            "read-eof-size" => equal("oversizeReadBytes", json!(0)),
            "entry-limit" => { equal("chargedEntries", json!(10000)); equal("overBudgetChildOpens", json!(0)); },
            "candidate-limit" => equal("chargedCandidates", json!(128)), "aggregate-limit" => equal("extraByteRead", json!(0)),
            "depth-path-limit" => { equal("depth13Opens", json!(0)); equal("oversizedPathOpens", json!(0)); },
            "replace" => equal("replacementReadBytes", json!(0)), "drive-map-change" => equal("laterProjectOpens", json!(0)),
            "oplock-withhold" => { equal("readerReturnedBeforeStop", json!(false)); equal("holderReleasedBeforeStop", json!(false)); },
            "pending-failstop" => { equal("afterCallMarker", json!(false)); equal("originalExitCode", json!(70)); },
            _ => {},
        }
        let ranges: &[(&str, u64, u64)] = match name {
            "ordinary-source" | "ordinary-zip" => &[("unicodeOpens", 1, 1000000)],
            "link-children" => &[("hardlinkCount", 2, 1024), ("excludedReparses", 3, 10000)],
            "short-alias" | "case-alias" => &[("aliasAcquired", 0, 1)],
            "read-eof-size" => &[("largestRequest", 1, 65536), ("largestReturn", 1, 65536)],
            "entry-limit" => &[("returnedRecords", 10000, 1000000)],
            "aggregate-limit" => &[("chargedBytes", 0, 8388608)], "depth-path-limit" => &[("deepestAdmitted", 0, 12)], _ => &[],
        };
        for (field, min, max) in ranges { rules.insert(field, Rule::Range(*min, *max)); }
        let actual = value.as_object().ok_or("windows_checks_object")?;
        require(actual.len() == rules.len() && actual.keys().all(|field| rules.contains_key(field.as_str())), "windows_checks_roster")?;
        for (field, rule) in rules {
            let value = &value[field];
            let checked = match rule {
                Rule::Equal(expected) => require(value == &expected, "windows_required_native_predicate"),
                Rule::Range(min, max) => number(value, max).and_then(|count| require(count >= min, "windows_required_native_count")),
            };
            if checked.is_err() {
                // Both names come from the compiled-in case/rule roster, never
                // an observed value, native pathname, buffer or credential.
                eprintln!("Windows snapshot rejected fixed check: control={name}, field={field}");
            }
            checked?;
        }
        Ok(())
    }

    fn fixture(name: &str, value: &Value, before_data: &PayloadInventory, bindings: &Value) -> Check<()> {
        let mut fields = vec!["state", "pending", "thread", "event", "restored", "resourcesSettledBy", "data", "profile", "checks"];
        fields.extend_from_slice(FIXTURE_COUNTS); object(value, &fields)?;
        checks(name, &value["checks"])?;
        if name == "closed-gate" { return require(value == &uninstrumented().1, "windows_uninstrumented_fixture_changed"); }
        let abnormal = matches!(name, "oplock-withhold" | "pending-failstop");
        require(value["state"] == (if abnormal {"prefix"} else {"complete"})
            && value["resourcesSettledBy"] == (if abnormal {"original-process"} else {"returned-closes"}), "windows_fixture_state")?;
        for field in FIXTURE_COUNTS { number(&value[*field], match *field {"live" | "maxLive" => 32, "maxArenaBytes" => 131072, _ => 1000000})?; }
        let count = |field: &str| number(&value[field], 1000000);
        require(count("closeSucceeded")? == count("closeAttempts")? && count("closeAttempts")? <= count("acquired")?
            && count("closeFailed")? == 0 && count("live")? == count("acquired")? - count("closeAttempts")?
            && count("live")? <= count("maxLive")? && count("maxLive")? <= count("acquired")?
            && count("maxLive")? > 0 && count("maxArenaBytes")? > 0, "windows_fixture_accounting")?;
        if abnormal {
            require(value["restored"].is_null() && value["event"] == "retained"
                && value["pending"] == (if name == "oplock-withhold" {"completed"} else {"retained"})
                && value["thread"] == (if name == "oplock-withhold" {"not-observed"} else {"none"}), "windows_abnormal_fixture_invented_cleanup")?;
            require(count("live")? >= 2 && count("maxLive")? >= 2 && count("maxArenaBytes")? >= 36,
                "windows_fixture_retained_pending_resources")?;
        } else {
            require(value["restored"] == true && value["acquired"] == value["closeAttempts"]
                && value["closeAttempts"] == value["closeSucceeded"] && value["live"] == 0 && value["closeFailed"] == 0,
                "windows_fixture_closes_unsettled")?;
            let expected = if name == "oplock-release" { ("completed", "joined", "closed") } else { ("none", "none", "none") };
            require(value["pending"] == expected.0 && value["thread"] == expected.1 && value["event"] == expected.2, "windows_fixture_pending_unsettled")?;
            if name == "oplock-release" {
                require(count("acquired")? >= 2 && count("maxLive")? >= 2 && count("maxArenaBytes")? >= 36,
                    "windows_fixture_completed_pending_resources")?;
            }
        }
        let data = &value["data"];
        object(data, &["entries", "bytes", "maxDepth", "manifestSha256", "after"])?;
        for field in ["entries", "bytes", "maxDepth"] { require(data[field] == before_data.facts[field], "windows_fixture_before_accounting")?; }
        require(data["manifestSha256"] == hash(&canonical(&before_data.files)?) && data["after"].is_null(), "windows_fixture_manifest_accounting")?;
        let profile = &value["profile"];
        object(profile, &["pointerBytes", "processMachine", "nativeMachine", "filesystem", "pythonSha256", "ctypesSha256", "dlls", "layoutSha256", "sdkSha256"])?;
        require(profile["pointerBytes"] == 8 && profile["processMachine"] == 0 && profile["nativeMachine"] == 34404
            && profile["filesystem"] == "NTFS" && profile["pythonSha256"] == bindings["pythonSha256"]
            && sha(&profile["ctypesSha256"]) && sha(&profile["layoutSha256"])
            && profile["sdkSha256"] == hash(&canonical(&bindings["sdk"])?), "windows_native_profile")?;
        let dlls = profile["dlls"].as_array().ok_or("windows_dll_roster")?;
        require(dlls.len() == 3, "windows_dll_roster")?;
        for (dll, name) in dlls.iter().zip(["kernel32.dll", "ntdll.dll", "advapi32.dll"]) {
            object(dll, &["name", "sha256", "size"])?;
            require(dll["name"] == name && sha(&dll["sha256"]) && number(&dll["size"], 64 * 1024 * 1024)? > 0, "windows_dll_identity")?;
        }
        Ok(())
    }

    fn expected_after(name: &str, before_data: &PayloadInventory) -> Check<Value> {
        let mut records = before_data.records.as_array().ok_or("windows_before_inventory")?.clone();
        let removed = match name {
            "disappear" => Some("project/android/app/build.gradle"),
            "config-disappear" => Some("project/release/mobile-release.json"),
            "walk-reparse-race" => Some("project/walk-parent/build.gradle"), _ => None,
        };
        if let Some(path) = removed {
            require(records.iter().filter(|item| item["path"] == path && item["kind"] == "file").count() == 1,
                "windows_expected_removed_file")?;
            records.retain(|item| item["path"] != path);
        }
        if name == "replace" {
            let replacement = b"android { defaultConfig { applicationId \"org.fixture.replaced\" } }\n";
            let item = records.iter_mut().find(|item| item["path"] == "project/android/app/build.gradle")
                .ok_or("windows_expected_replacement_file")?;
            item["sha256"] = json!(hash(replacement)); item["size"] = json!(replacement.len());
        }
        // Every other case, especially the narrowly allowed W6 process-stop
        // exceptions, must leave exactly its original ordinary payload. No
        // unexpected native mutation can be re-blessed by a fresh after hash.
        Ok(Value::Array(records))
    }

    fn cleanup_case(case: &Case, after: &PayloadInventory, end: Instant) -> Check<()> {
        // Called only after ALL positive original/resource/restoration/DTO checks.
        // Recheck the full finite ordinary manifest before deleting anything.
        require(payload(&case.root, end)?.records == after.records, "windows_cleanup_inventory_changed")?;
        let mut directories = Vec::new();
        for item in after.records.as_array().ok_or("windows_cleanup_manifest")? {
            let path = case.root.join(string(&item["path"])?);
            let metadata = fs::symlink_metadata(&path).map_err(|_| "windows_cleanup_metadata")?;
            require(ordinary(&metadata), "windows_cleanup_redirected")?;
            if item["kind"] == "directory" { directories.push(path); }
            else {
                require(hash(&read(&path, FILE_BYTES, end)?) == string(&item["sha256"])?, "windows_cleanup_file_changed")?;
                fs::remove_file(path).map_err(|_| "windows_cleanup_file")?;
            }
        }
        directories.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
        for directory in directories {
            before(end)?;
            let metadata = fs::symlink_metadata(&directory).map_err(|_| "windows_cleanup_metadata")?;
            require(ordinary(&metadata) && metadata.is_dir(), "windows_cleanup_redirected")?;
            fs::remove_dir(directory).map_err(|_| "windows_cleanup_directory")?;
        }
        let expected: BTreeSet<&str> = if case.name == "closed-gate" {
            ["case.json", "data.json", "release-query-1.json"].into_iter().collect()
        } else { ["case.json", "data.json", "engine-bootstrap.py", "release-query-1.json"].into_iter().collect() };
        let mut seen = BTreeSet::new(); let mut files = Vec::new();
        for file in fs::read_dir(&case.control).map_err(|_| "windows_cleanup_control")? {
            let file = file.map_err(|_| "windows_cleanup_control")?;
            let name = file.file_name().into_string().map_err(|_| "windows_cleanup_control_name")?;
            require(expected.contains(name.as_str()) && seen.insert(name), "windows_cleanup_control_roster")?;
            let bytes = read(&file.path(), 2 * 1024 * 1024, end)?;
            files.push((file.path(), hash(&bytes)));
        }
        require(seen.len() == expected.len(), "windows_cleanup_control_roster")?;
        for (path, expected) in files {
            require(hash(&read(&path, 2 * 1024 * 1024, end)?) == expected, "windows_cleanup_control_changed")?;
            fs::remove_file(path).map_err(|_| "windows_cleanup_control_remove")?;
        }
        fs::remove_dir(&case.control).and_then(|_| fs::remove_dir(&case.root)).map_err(|_| "windows_cleanup_case")
    }

    struct NativeReceipt { path: PathBuf, bindings: Value, groups: Vec<Value> }
    impl NativeReceipt {
        fn new(inputs: &WindowsInputs) -> Self {
            Self { path: inputs.base.root.join("receipt.json"), bindings: inputs.base.bindings.clone(),
                groups: GROUPS.iter().map(|(id, _)| json!({"id":id,"controls":[]})).collect() }
        }
        fn write(&self, status: &str, failure: Option<&str>) -> Check<()> {
            let passed = status == "passed";
            let receipt = json!({"schemaVersion":1,"scope":SCOPE,"status":status,"failureCode":failure,"bindings":self.bindings,
                "groups":self.groups,"allOwnersSettled":passed,"allFixtureResourcesSettled":passed,"allFixturesRestored":passed,
                "cleanupDisposition":if passed {"proven-settled"} else {"retain"},"notVerified":NOT_VERIFIED});
            depth(&receipt, 16)?;
            let bytes = canonical(&receipt)?;
            require(bytes.len() <= 256 * 1024, "windows_receipt_bound")?;
            fs::write(&self.path, bytes).map_err(|_| "windows_receipt_write")
        }
        fn record(&mut self, group: usize, value: Value) -> Check<()> {
            self.groups.get_mut(group).and_then(|group| group["controls"].as_array_mut())
                .ok_or("windows_receipt_group")?.push(value);
            Ok(())
        }
    }

    pub(super) async fn run() {
        let inputs = match WindowsInputs::admit() {
            Ok(inputs) => inputs,
            Err(code) => { panic!("Windows snapshot source/profile admission failed: {code}"); }
        };
        let begin = Instant::now();
        let mut receipt = NativeReceipt::new(&inputs);
        if receipt.write("running", None).is_err() { panic!("Windows receipt unavailable before original native work"); }
        for (index, (group, names)) in GROUPS.iter().enumerate() {
            for name in *names {
                eprintln!("Windows snapshot fixed control: {group}/{name}");
                if begin.elapsed() >= Duration::from_secs(300) {
                    let _ = receipt.write("failed-retained", Some("windows_batch_allowance"));
                    panic!("Windows snapshot batch observation allowance exceeded; task root retained");
                }
                let (mut case, data) = match prepare(&inputs, group, name) {
                    Ok(case) => case,
                    Err(code) => { let _ = receipt.write("failed-retained", Some(code)); panic!("Windows fixture preparation failed; task root retained: {code}"); }
                };
                let params = match spelling(&case.root.join("project")) {
                    Ok(root) => json!({"root":root,"configPath":"release/mobile-release.json"}),
                    Err(code) => { let _ = receipt.write("failed-retained", Some(code)); panic!("Windows fixed request failed before spawn: {code}"); }
                };
                let request = case.start(Method::ProjectSnapshot, params);
                let outcome = case.result(request).await;
                if !case.settle(outcome.is_err()).await {
                    let _ = receipt.write("failed-retained", Some("windows_original_custody_unresolved"));
                    // Keep this runtime, original owner slots, selection and root.
                    // No next child, task abort, PID cleanup or renewed endpoint.
                    pending::<()>().await;
                    return;
                }
                let checked: Check<(Value, PayloadInventory)> = async {
                    let outcome = outcome?;
                    let (original, observed) = original(&case, &outcome).await?;
                    let (reader, mut fixture_data) = telemetry(&case, &observed)?;
                    check_reader(name, &reader)?;
                    fixture(name, &fixture_data, &data, &inputs.base.bindings)?;
                    let result = result(&case, &outcome, &reader)?;
                    let after = payload(&case.root, case.begin + Duration::from_secs(45))?;
                    require(after.records == expected_after(name, &data)?, "windows_unexpected_payload_change")?;
                    if *name != "closed-gate" {
                        let mut facts = after.facts.clone(); facts["inventorySha256"] = json!(hash(&canonical(&after.records)?));
                        fixture_data["data"]["after"] = facts;
                    }
                    inputs.unchanged(case.begin + Duration::from_secs(45))?;
                    // The original runtime Python selection never changes between cases.
                    require(selected("MRK_DESKTOP_DEV_PYTHON")? == inputs.python, "windows_python_selection_changed")?;
                    require(case.begin.elapsed() <= Duration::from_secs(45), "windows_case_allowance")?;
                    let evidence = match *name {"closed-gate" => "uninstrumented-public-refusal",
                        "oplock-withhold" => "original-process-oplock-stop", "pending-failstop" => "instrumented-pending-classifier-exit",
                        _ => "native-static-reader"};
                    Ok((json!({"id":name,"coreMode":if *name == "ordinary-zip" {"zip"} else {"source"},
                        "bootstrapMode":if *name == "closed-gate" {"ordinary"} else {"windows-snapshot"},"evidenceKind":evidence,
                        "result":result,"reader":reader,"fixture":fixture_data,"original":original,
                        "elapsedMs":case.begin.elapsed().as_millis(),"failureCode":null}), after))
                }.await;
                match checked {
                    Ok((record, after)) => {
                        if let Err(code) = cleanup_case(&case, &after, case.begin + Duration::from_secs(45)) {
                            let _ = receipt.record(index, record); let _ = receipt.write("failed-retained", Some(code));
                            panic!("Windows settled fixture cleanup failed; task root retained: {code}");
                        }
                        if receipt.record(index, record).and_then(|_| receipt.write("running", None)).is_err() {
                            panic!("Windows receipt failed after complete original settlement");
                        }
                    },
                    Err(code) => { let _ = receipt.write("failed-retained", Some(code)); panic!("Windows native predicate failed after original settlement; task root retained: {code}"); },
                }
            }
        }
        std::env::set_var("MRK_DESKTOP_DEV_CORE", &inputs.base.source);
        if receipt.write("passed", None).is_err() { panic!("Windows final receipt failed after all original settlement"); }
    }
}

#[cfg(windows)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "Disposable fixed Windows scope only; independent source review and execution admission required"]
async fn windows_static_snapshot_hosted_contract() { windows_snapshot::run().await; }

// A separate literal entry and runtime selection. This is genuine local TLS in
// the reviewed private namespaces, never an owner23 alias or production opt-in.
#[cfg(all(debug_assertions, target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "only the separately reviewed disposable GitHub-hosted TLS workflow"]
async fn github_tls_hosted_contract() { github_tls::run().await; }

#[cfg(all(debug_assertions, target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "only the separately reviewed disposable T4/T5 hosts namespace"]
async fn github_tls_deadline_hosts_hosted_contract() { github_tls::run_deadline("hosts").await; }

#[cfg(all(debug_assertions, target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "only the separately reviewed disposable T5 dns-withhold namespace"]
async fn github_tls_deadline_dns_hosted_contract() { github_tls::run_deadline("dns-withhold").await; }

#[cfg(all(debug_assertions, target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
pub(crate) mod github_tls {
    use super::*;
    use std::{collections::{BTreeMap, BTreeSet}, io::{Read, Write}, os::unix::fs::{MetadataExt, PermissionsExt}};
    use serde::Deserialize;
    use crate::github_connection_protocol::{Coverage, FactState, Permission, Presence, Reason, Visibility, WorkflowState};

    const INPUTS_ANCHOR: Option<&str> = option_env!("MRK_GITHUB_TLS_INPUTS_SHA256");
    const DEADLINE_INPUTS_ANCHOR: Option<&str> = option_env!("MRK_GITHUB_TLS_DEADLINE_INPUTS_SHA256");
    const BOOTSTRAP: &[u8] = include_bytes!("../../github_connection_bootstrap.py");
    const PEER: &[u8] = include_bytes!("../tests/fixtures/github_tls_peer.py");
    const NAMESPACE: &[u8] = include_bytes!("../tests/fixtures/github_tls_namespace.sh");
    const WORKFLOW: &[u8] = include_bytes!("../../../.github/workflows/desktop-github-connection-tls.yml");
    const PEMS: &[(&str, &[u8])] = &[
        ("root-ca.pem", include_bytes!("../tests/fixtures/github_tls/root-ca.pem")),
        ("other-root-ca.pem", include_bytes!("../tests/fixtures/github_tls/other-root-ca.pem")),
        ("api-valid.pem", include_bytes!("../tests/fixtures/github_tls/api-valid.pem")),
        ("wrong-san.pem", include_bytes!("../tests/fixtures/github_tls/wrong-san.pem")),
        ("api-expired.pem", include_bytes!("../tests/fixtures/github_tls/api-expired.pem")),
        ("server-key.pem", include_bytes!("../tests/fixtures/github_tls/server-key.pem")),
    ];
    const TOKEN: &str = "INERT_NOT_A_CREDENTIAL";
    const PEER_TIME: Duration = Duration::from_secs(16);
    const PEER_OUTPUT_LIMIT: usize = 8 * 1024;
    const FILE_LIMIT: u64 = 512 * 1024 * 1024;
    const LIMITATIONS: &[&str] = &["T4-ambient-proxy-default-ca-keylog", "T5-real-network-deadlines",
        "product-heap-allocation", "CA-file-native-faults", "real-github-authentication", "production-runtime-custody",
        "native-gui", "native-document-lifecycle", "packaged-runtime", "production-enablement"];
    const ROLES: &[&str] = &["python", "bootstrap", "coreZip", "peer", "namespace", "root-ca.pem", "other-root-ca.pem",
        "api-valid.pem", "wrong-san.pem", "api-expired.pem", "server-key.pem", "hosts", "resolv.conf", "nsswitch.conf",
        "ssl", "socket", "_ssl", "_socket", "libssl", "libcrypto", "loader",
        "tool:sudo", "tool:unshare", "tool:env", "tool:bash", "tool:mount", "tool:ip", "tool:sysctl", "tool:setpriv",
        "tool:stat", "tool:sha256sum", "tool:readlink", "tool:findmnt"];

    // Closed public diagnostics only. This finite roster is also checked by the
    // inert Python contract; no arbitrary error, pathname or environment value
    // can be reflected through an admission failure.
    const ADMISSION_CODES: &[&str] = &[
        "core_not_exact_checkout", "core_zip_layout", "hash_input_changed", "hash_input_limit",
        "hash_input_read_failed", "hash_input_unavailable", "hosted_admission_required", "hosted_input_not_absolute",
        "hosted_input_unavailable", "hosted_scope", "hosted_scope_not_fresh", "missing_hosted_input",
        "python_not_regular", "source_layout", "source_sha_shape", "test_root_not_fresh", "test_root_unavailable",
        "tls_admission_unclassified", "tls_artifact_size", "tls_compile_anchor_missing", "tls_compiled_fixture_binding",
        "tls_compiled_pem_binding", "tls_current_artifact", "tls_deadline_fixed_resolver_bytes", "tls_deadline_original_identity",
        "tls_deadline_privilege_ambient", "tls_deadline_privilege_bounding", "tls_deadline_privilege_drop",
        "tls_deadline_privilege_effective", "tls_deadline_privilege_groups", "tls_deadline_privilege_inheritable",
        "tls_deadline_privilege_nonewprivs", "tls_deadline_privilege_permitted", "tls_deadline_privilege_status",
        "tls_deadline_profile_layout", "tls_dynamic_nss_unsupported",
        "tls_file_bound", "tls_file_changed", "tls_file_metadata", "tls_file_open", "tls_file_read", "tls_file_size",
        "tls_fixed_pem", "tls_fixed_role", "tls_genuine_ssl_binding", "tls_host_or_route", "tls_input_bytes", "tls_input_limit",
        "tls_input_order", "tls_input_path", "tls_input_roster", "tls_inputs_binding", "tls_inputs_compile_binding",
        "tls_inputs_json", "tls_inputs_schema", "tls_libc_backing_file", "tls_libc_map_device", "tls_libc_map_inode",
        "tls_libc_map_limit", "tls_libc_maps", "tls_libc_metadata", "tls_libc_original_mapping", "tls_namespace_binding",
        "tls_original_artifact_binding", "tls_parent_environment", "tls_parent_environment_path", "tls_path_not_canonical",
        "tls_path_shape", "tls_path_symlink", "tls_path_unavailable", "tls_private_layout", "tls_private_resolver_bytes",
        "tls_proc_close_unknown", "tls_proc_open", "tls_proc_read", "tls_proc_role", "tls_profile", "tls_resolver_alias",
        "tls_resolver_cache_present", "tls_resolver_config_metadata", "tls_resolver_config_not_supported",
        "tls_resolver_config_role", "tls_resolver_descriptor_scope", "tls_resolver_profile", "tls_resolver_role",
        "tls_resource_address_space", "tls_resource_core", "tls_resource_descriptors", "tls_resource_file",
        "tls_role_missing", "tls_role_unbound", "tls_source_layout", "tls_source_name", "tls_source_roster", "unsupported_host",
    ];
    fn admission_frame(profile: Option<&str>, code: &str) -> String {
        let profile = match profile { None => "original", Some("hosts") => "hosts", Some("dns-withhold") => "dns-withhold",
            _ => "unclassified" };
        let code = ADMISSION_CODES.iter().copied().find(|known| *known == code).unwrap_or("tls_admission_unclassified");
        format!("github-tls-admission: {profile}/{code}\n")
    }
    fn refuse_before_cases(profile: Option<&str>, code: &str) -> ! {
        // ONLY the initial Admitted::new[_profile] Err arms call this. No case,
        // product/probe/peer or retained task book has been constructed. Partial
        // admission directories stay retained. This original process's nonzero
        // exit is a failure, never a finality or cleanup receipt.
        let frame = admission_frame(profile, code);
        if frame.len() <= 256 { let _ = std::io::stderr().lock().write_all(frame.as_bytes()); }
        std::process::exit(101); // Still fails if the diagnostic write failed.
    }

    fn sha(value: &str, length: usize) -> bool {
        value.len() == length && value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }
    fn digits(value: &str) -> bool {
        !value.is_empty() && value.len() <= 20 && !value.starts_with('0') && value.bytes().all(|byte| byte.is_ascii_digit())
    }
    fn ns(value: &str, kind: &str) -> bool {
        value.strip_prefix(kind).and_then(|value| value.strip_suffix(']')).is_some_and(digits)
    }
    fn path(path: &Path) -> Check<()> {
        require(path.is_absolute() && path.to_str().is_some_and(|value| value.is_ascii() && value.len() <= 4096)
            && !path.components().any(|part| matches!(part, std::path::Component::ParentDir)), "tls_path_shape")?;
        let mut prefix = PathBuf::new();
        for part in path.components() {
            prefix.push(part.as_os_str());
            require(!fs::symlink_metadata(&prefix).map_err(|_| "tls_path_unavailable")?.file_type().is_symlink(), "tls_path_symlink")?;
        }
        require(path.canonicalize().map_err(|_| "tls_path_unavailable")?.as_os_str() == path.as_os_str(), "tls_path_not_canonical")
    }
    fn stamp(value: &fs::Metadata) -> (u64, u64, u32, u64, u64, i64, i64, i64, i64) {
        (value.dev(), value.ino(), value.mode(), value.nlink(), value.len(), value.mtime(), value.mtime_nsec(), value.ctime(), value.ctime_nsec())
    }
    fn file(pathname: &Path, limit: u64) -> Check<(fs::File, fs::Metadata)> {
        path(pathname)?;
        let before = fs::symlink_metadata(pathname).map_err(|_| "tls_file_metadata")?;
        require(before.is_file() && before.len() <= limit, "tls_file_bound")?;
        let original = fs::File::open(pathname).map_err(|_| "tls_file_open")?;
        require(stamp(&original.metadata().map_err(|_| "tls_file_metadata")?) == stamp(&before), "tls_file_changed")?;
        Ok((original, before))
    }
    fn unchanged(pathname: &Path, original: &fs::File, before: &fs::Metadata) -> Check<()> {
        require(stamp(&original.metadata().map_err(|_| "tls_file_metadata")?) == stamp(before)
            && stamp(&fs::symlink_metadata(pathname).map_err(|_| "tls_file_metadata")?) == stamp(before), "tls_file_changed")
    }
    fn read(pathname: &Path, limit: u64) -> Check<Vec<u8>> {
        let (mut original, before) = file(pathname, limit)?;
        let mut bytes = Vec::new();
        Read::by_ref(&mut original).take(limit + 1).read_to_end(&mut bytes).map_err(|_| "tls_file_read")?;
        require(bytes.len() as u64 == before.len(), "tls_file_changed")?;
        unchanged(pathname, &original, &before)?;
        Ok(bytes)
    }
    fn file_hash(pathname: &Path, size: u64) -> Check<String> {
        require(size <= FILE_LIMIT, "tls_file_bound")?;
        let (mut original, before) = file(pathname, size)?;
        require(before.len() == size, "tls_file_size")?;
        let mut hash = Sha256::new();
        let mut count = 0u64;
        let mut buffer = [0u8; 64 * 1024];
        loop {
            let length = original.read(&mut buffer).map_err(|_| "tls_file_read")?;
            if length == 0 { break; }
            count = count.checked_add(length as u64).ok_or("tls_file_bound")?;
            require(count <= size, "tls_file_changed")?;
            hash.update(&buffer[..length]);
        }
        require(count == size, "tls_file_changed")?;
        unchanged(pathname, &original, &before)?;
        Ok(format!("{:x}", hash.finalize()))
    }

    #[derive(Clone, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub(crate) struct TlsFile { path: PathBuf, size: u64, sha256: String }
    impl TlsFile {
        pub(crate) fn parts(&self) -> (&Path, u64, &str) { (&self.path, self.size, &self.sha256) }
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct Ssl { openssl_version: String, ignore_unexpected_eof: u64 }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Resolver { family: String, version: String, nss: String }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct Manifest {
        schema_version: u32, scope: String, source_sha: String, source_tree: String, workflow_sha256: String,
        run_id: String, attempt: String, source_root: PathBuf, job_root: PathBuf, python: PathBuf,
        core_source: PathBuf, core_zip: PathBuf, uid: u32, gid: u32, parent_netns: String, parent_mntns: String,
        ssl: Ssl, #[serde(default)] resolver: Option<Resolver>, roles: BTreeMap<String, PathBuf>, files: Vec<TlsFile>,
    }
    impl Manifest {
        fn role(&self, name: &str) -> Check<&Path> { self.roles.get(name).map(PathBuf::as_path).ok_or("tls_role_missing") }
        fn record(&self, path: &Path) -> Check<&TlsFile> { self.files.iter().find(|item| item.path == path).ok_or("tls_role_unbound") }
    }
    struct Common {
        manifest: Manifest, source_files: BTreeSet<String>, peer_env: BTreeMap<String, String>, bindings: Value,
    }
    struct Selection { common: Arc<Common>, core: PathBuf, bootstrap: PathBuf, trust: Vec<u8> }
    /// No constructor outside this admitted, finite harness. Clone preserves the
    /// same immutable original binding; it cannot turn on the product profile.
    #[derive(Clone)]
    pub(crate) struct GitHubTlsRuntime { original: Arc<Selection> }
    impl GitHubTlsRuntime {
        pub(crate) fn python(&self) -> &Path { &self.original.common.manifest.python }
        pub(crate) fn core(&self) -> &Path { &self.original.core }
        pub(crate) fn source(&self) -> &Path { &self.original.common.manifest.core_source }
        pub(crate) fn source_files(&self) -> &BTreeSet<String> { &self.original.common.source_files }
        pub(crate) fn files(&self) -> &[TlsFile] { &self.original.common.manifest.files }
        pub(crate) fn bootstrap(&self) -> &Path { &self.original.bootstrap }
        pub(crate) fn trust(&self) -> &[u8] { &self.original.trust }
    }
    const RESOURCE_LIMITS: &[(rustix::process::Resource, u64, &str)] = &[
        (rustix::process::Resource::Core, 0, "tls_resource_core"),
        (rustix::process::Resource::Fsize, 1024 * 1024, "tls_resource_file"),
        (rustix::process::Resource::Nofile, 128, "tls_resource_descriptors"),
        (rustix::process::Resource::As, 1024 * 1024 * 1024, "tls_resource_address_space"),
    ];
    fn exact_resource_limit(limit: rustix::process::Rlimit, expected: u64) -> bool {
        limit.current == Some(expected) && limit.maximum == Some(expected)
    }
    fn admit_resource_limits() -> Check<()> {
        // Independent actual post-drop observation, never repair or inheritance
        // inference. All profiles check before any case/peer/product is created.
        for &(resource, expected, code) in RESOURCE_LIMITS {
            require(exact_resource_limit(rustix::process::getrlimit(resource), expected), code)?;
        }
        Ok(())
    }

    struct Admitted { inputs: Inputs, common: Arc<Common> }
    impl Admitted {
        fn new() -> Check<Self> {
            Self::new_profile(None)
        }
        fn new_profile(profile: Option<&'static str>) -> Check<Self> {
            require(profile.is_none() || matches!(profile, Some("hosts" | "dns-withhold")), "tls_profile")?;
            let inputs = Inputs::admit_scoped(if profile.is_some() { "github-readonly-tls-deadline-v1" }
                else { "github-readonly-tls-v1" }, profile)?;
            require(crate::runtime::COMPILED_TARGET == "x86_64-unknown-linux-gnu"
                && !crate::runtime::GITHUB_TLS_PROFILE_QUALIFIED && lock(&RETAINED).is_none()
                && environment("GITHUB_REF")? == "refs/heads/verify/desktop-github-connection-tls", "tls_host_or_route")?;
            admit_resource_limits()?;
            let anchor = (if profile.is_some() { DEADLINE_INPUTS_ANCHOR } else { INPUTS_ANCHOR })
                .filter(|value| sha(value, 64)).ok_or("tls_compile_anchor_missing")?;
            let input_path = PathBuf::from(environment("MRK_GITHUB_TLS_INPUTS")?);
            let bytes = read(&input_path, 1024 * 1024)?;
            require(hash(&bytes) == anchor, "tls_inputs_compile_binding")?;
            let manifest_value = protocol::strict_json(&bytes).map_err(|_| "tls_inputs_json")?;
            // Presence is checked before Option deserialization: null is NOT
            // an absent resolver field in the original16 manifest.
            require(manifest_value.as_object().is_some_and(|value| value.contains_key("resolver") == profile.is_some()),
                "tls_resolver_descriptor_scope")?;
            let manifest: Manifest = serde_json::from_value(manifest_value).map_err(|_| "tls_inputs_schema")?;
            let checkout = Path::new(env!("CARGO_MANIFEST_DIR")).parent().and_then(Path::parent).ok_or("tls_source_layout")?
                .canonicalize().map_err(|_| "tls_source_layout")?;
            let python = selected("MRK_DESKTOP_DEV_PYTHON")?;
            require(manifest.schema_version == 1 && manifest.scope == (if profile.is_some() {
                    "github-readonly-tls-deadline-native-v1" } else { "github-readonly-tls-native-v1" })
                && sha(&manifest.source_sha, 40) && sha(&manifest.source_tree, 40) && sha(&manifest.workflow_sha256, 64)
                && manifest.source_sha == environment("GITHUB_SHA")? && manifest.workflow_sha256 == hash(WORKFLOW)
                && digits(&manifest.run_id) && digits(&manifest.attempt)
                && manifest.run_id == environment("GITHUB_RUN_ID")? && manifest.attempt == environment("GITHUB_RUN_ATTEMPT")?
                && manifest.uid != 0 && manifest.gid != 0 && manifest.source_root == checkout
                && manifest.core_source == inputs.source && manifest.core_zip == inputs.zip && manifest.python == python,
                "tls_inputs_binding")?;
            path(&manifest.job_root)?;
            require(input_path == manifest.job_root.join(if profile.is_some() { "github-tls-deadline-inputs.json" } else { "github-tls-inputs.json" })
                && inputs.root.starts_with(&manifest.job_root)
                && inputs.root != manifest.job_root && !inputs.root.starts_with(&checkout), "tls_private_layout")?;
            require(manifest.ssl.openssl_version.starts_with("OpenSSL ") && manifest.ssl.openssl_version.len() <= 160
                && manifest.ssl.openssl_version.is_ascii() && manifest.ssl.ignore_unexpected_eof > 0,
                "tls_genuine_ssl_binding")?;
            let mut expected_roles = ROLES.iter().copied().collect::<BTreeSet<_>>();
            if profile.is_some() {
                for name in ["hosts", "resolv.conf", "nsswitch.conf"] { expected_roles.remove(name); }
                expected_roles.extend(["hosts:hosts", "hosts:resolv.conf", "hosts:nsswitch.conf",
                    "dns-withhold:hosts", "dns-withhold:resolv.conf", "dns-withhold:nsswitch.conf",
                    "libc", "resolver:host.conf", "resolver:gai.conf"]);
            }
            require(manifest.roles.len() == expected_roles.len() && expected_roles.iter().all(|role| manifest.roles.contains_key(*role))
                && !manifest.files.is_empty() && manifest.files.len() <= 2048, "tls_input_roster")?;
            let mut previous: Option<&str> = None;
            let mut total = 0u64;
            let mut source_files = BTreeSet::new();
            for item in &manifest.files {
                let spelling = item.path.to_str().ok_or("tls_input_path")?;
                require(previous.map_or(true, |before| before < spelling) && sha(&item.sha256, 64), "tls_input_order")?;
                previous = Some(spelling);
                total = total.checked_add(item.size).ok_or("tls_input_limit")?;
                require(total <= 1024 * 1024 * 1024 && file_hash(&item.path, item.size)? == item.sha256, "tls_input_bytes")?;
                if let Ok(relative) = item.path.strip_prefix(&manifest.core_source) {
                    let name = relative.to_str().ok_or("tls_source_name")?;
                    require(crate::runtime::safe_payload_path(name) && source_files.insert(name.to_owned()), "tls_source_roster")?;
                }
            }
            require(!source_files.is_empty(), "tls_source_roster")?;
            for pathname in manifest.roles.values() { let _ = manifest.record(pathname)?; }
            let fixtures = checkout.join("desktop/src-tauri/tests/fixtures");
            for (role, expected) in [("python", python), ("bootstrap", checkout.join("desktop/github_connection_bootstrap.py")),
                ("coreZip", inputs.zip.clone()), ("peer", fixtures.join("github_tls_peer.py")),
                ("namespace", fixtures.join("github_tls_namespace.sh"))] {
                require(manifest.role(role)? == expected, "tls_fixed_role")?;
            }
            for &(name, bytes) in PEMS {
                let expected = fixtures.join("github_tls").join(name);
                require(manifest.role(name)? == expected, "tls_fixed_pem")?;
                let item = manifest.record(&expected)?;
                require(item.size > 0 && item.size <= 512 * 1024 && item.sha256 == hash(bytes)
                    && read(&expected, 512 * 1024)?.as_slice() == bytes, "tls_compiled_pem_binding")?;
            }
            for (role, expected) in [("bootstrap", BOOTSTRAP), ("peer", PEER), ("namespace", NAMESPACE)] {
                require(read(manifest.role(role)?, expected.len() as u64)?.as_slice() == expected, "tls_compiled_fixture_binding")?;
            }
            for name in ["hosts", "resolv.conf", "nsswitch.conf"] {
                let role = profile.map_or_else(|| name.to_owned(), |profile| format!("{profile}:{name}"));
                let directory = profile.map_or_else(|| "github-tls-namespace".to_owned(), |profile| format!("github-tls-deadline-namespace-{profile}"));
                let expected = manifest.job_root.join(directory).join(name);
                require(manifest.role(&role)? == expected, "tls_resolver_role")?;
                let visible = Path::new("/etc").join(name);
                let visible = if name == "resolv.conf" {
                    // Only Ubuntu's fixed resolver aliases, already admitted
                    // and RO-bound by the namespace entry. No general symlink
                    // relaxation for source/runtime/trust or other host files.
                    let canonical = visible.canonicalize().map_err(|_| "tls_resolver_alias")?;
                    require(["/etc/resolv.conf", "/run/systemd/resolve/stub-resolv.conf", "/run/systemd/resolve/resolv.conf"]
                        .iter().any(|allowed| canonical == Path::new(allowed)), "tls_resolver_alias")?;
                    canonical
                } else { visible };
                require(read(&expected, 16 * 1024)? == read(&visible, 16 * 1024)?, "tls_private_resolver_bytes")?;
            }
            if let Some(profile) = profile { deadline::admit_resolver(&manifest, profile)?; }
            let netns = environment("MRK_TLS_NETNS")?;
            let mntns = environment("MRK_TLS_MNTNS")?;
            require(ns(&manifest.parent_netns, "net:[") && ns(&manifest.parent_mntns, "mnt:[")
                && ns(&netns, "net:[") && ns(&mntns, "mnt:[") && netns != manifest.parent_netns && mntns != manifest.parent_mntns
                && fs::read_link("/proc/self/ns/net").ok().as_deref() == Some(Path::new(&netns))
                && fs::read_link("/proc/self/ns/mnt").ok().as_deref() == Some(Path::new(&mntns))
                && environment("MRK_TLS_PARENT_NETNS")? == manifest.parent_netns
                && environment("MRK_TLS_PARENT_MNTNS")? == manifest.parent_mntns
                && environment("MRK_TLS_ORIGINAL_UID")? == manifest.uid.to_string()
                && environment("MRK_TLS_ORIGINAL_GID")? == manifest.gid.to_string(), "tls_namespace_binding")?;
            let artifact = PathBuf::from(environment("MRK_GITHUB_TLS_ARTIFACT")?);
            let artifact_sha = environment("MRK_GITHUB_TLS_ARTIFACT_SHA256")?;
            let artifact_size = environment("MRK_GITHUB_TLS_ARTIFACT_BYTES")?.parse::<u64>().map_err(|_| "tls_artifact_size")?;
            require(sha(&artifact_sha, 64) && artifact_size > 0
                && std::env::current_exe().map_err(|_| "tls_current_artifact")? == artifact
                && file_hash(&artifact, artifact_size)? == artifact_sha, "tls_original_artifact_binding")?;
            let mut peer_env = BTreeMap::new();
            for (key, value) in [("MRK_DESKTOP_HOSTED_CHECKS", "github-readonly-tls-v1".to_owned()),
                ("GITHUB_ACTIONS", "true".to_owned()), ("RUNNER_ENVIRONMENT", "github-hosted".to_owned()),
                ("MRK_TLS_PARENT_NETNS", manifest.parent_netns.clone()), ("MRK_TLS_PARENT_MNTNS", manifest.parent_mntns.clone()),
                ("MRK_TLS_NETNS", netns.clone()), ("MRK_TLS_MNTNS", mntns.clone()),
                ("MRK_TLS_ORIGINAL_UID", manifest.uid.to_string()), ("MRK_TLS_ORIGINAL_GID", manifest.gid.to_string()),
                ("MRK_TLS_PEER_SHA256", hash(PEER))] { peer_env.insert(key.to_owned(), value); }
            let bindings = json!({"sourceSha":manifest.source_sha,"sourceTree":manifest.source_tree,
                "workflowSha256":manifest.workflow_sha256,"runId":manifest.run_id,"attempt":manifest.attempt,
                "tlsInputsSha256":anchor,"artifactSha256":artifact_sha,"artifactBytes":artifact_size,
                "coreZipSha256":manifest.record(&manifest.core_zip)?.sha256,"pythonSha256":manifest.record(&manifest.python)?.sha256,
                "namespace":{"parentNetns":manifest.parent_netns,"parentMntns":manifest.parent_mntns,
                    "netns":netns,"mntns":mntns,"uid":manifest.uid,"gid":manifest.gid}});
            Ok(Self { inputs, common: Arc::new(Common { manifest, source_files, peer_env, bindings }) })
        }
    }

    struct Scenario { name: &'static str, zip: bool, other_root: bool, reason: Reason, connections: u64 }
    const CASES: &[Scenario] = &[
        Scenario { name: "T1-source", zip: false, other_root: false, reason: Reason::None, connections: 4 },
        Scenario { name: "T1-zip", zip: true, other_root: false, reason: Reason::None, connections: 5 },
        Scenario { name: "T2-root", zip: false, other_root: true, reason: Reason::TlsFailed, connections: 1 },
        Scenario { name: "T2-name", zip: false, other_root: false, reason: Reason::TlsFailed, connections: 1 },
        Scenario { name: "T2-expired", zip: false, other_root: false, reason: Reason::TlsFailed, connections: 1 },
        Scenario { name: "T3-clean", zip: false, other_root: false, reason: Reason::None, connections: 4 },
        Scenario { name: "T3-ragged", zip: false, other_root: false, reason: Reason::TlsFailed, connections: 1 },
        Scenario { name: "T3-length", zip: false, other_root: false, reason: Reason::ResponseInvalid, connections: 1 },
        Scenario { name: "T3-chunk", zip: false, other_root: false, reason: Reason::ResponseInvalid, connections: 1 },
        Scenario { name: "T6-header", zip: false, other_root: false, reason: Reason::ResponseLimit, connections: 1 },
        Scenario { name: "T6-body", zip: false, other_root: false, reason: Reason::ResponseLimit, connections: 1 },
        Scenario { name: "T6-chunk-metadata", zip: false, other_root: false, reason: Reason::ResponseLimit, connections: 1 },
        Scenario { name: "T6-unauthorized", zip: false, other_root: false, reason: Reason::Unauthorized, connections: 1 },
        Scenario { name: "T6-rate-expiry", zip: false, other_root: false, reason: Reason::ResponseInvalid, connections: 1 },
        Scenario { name: "T6-target", zip: false, other_root: false, reason: Reason::TargetChanged, connections: 4 },
        Scenario { name: "T6-redirect", zip: false, other_root: false, reason: Reason::ResponseInvalid, connections: 1 },
    ];
    impl Scenario {
        // Literal peer plaintext sizes and minimum parser-input progress. These
        // are SOURCE-bound counters, not observations of client reads or heap use.
        fn replies(&self) -> Option<(&'static [u64], &'static [u64])> {
            match self.name {
                "T6-header" => Some((&[40630], &[32768])),
                "T6-body" => Some((&[262215], &[262215])),
                "T6-chunk-metadata" => Some((&[35803], &[33143])),
                "T6-unauthorized" => Some((&[99], &[80])),
                "T6-rate-expiry" => Some((&[175], &[156])),
                "T6-target" => Some((&[95, 222, 102, 222], &[95, 222, 102, 222])),
                "T6-redirect" => Some((&[136], &[117])),
                _ => None,
            }
        }
        fn streaming(&self) -> bool { self.replies().is_some() }
        fn limits(&self) -> (u64, u64) {
            if self.name == "T6-body" { (512 * 1024, 320 * 1024) } else { (128 * 1024, 64 * 1024) }
        }
    }
    fn reason(value: Reason) -> &'static str {
        match value {
            Reason::None => "none", Reason::TlsFailed => "tls-failed", Reason::ResponseInvalid => "response-invalid",
            Reason::ResponseLimit => "response-limit", Reason::Unauthorized => "unauthorized", Reason::TargetChanged => "target-changed",
            Reason::NetworkUnavailable => "network-unavailable",
            _ => "unexpected",
        }
    }
    fn ready(bytes: &[u8], name: &str) -> bool {
        bytes.len() <= 1024 && protocol::strict_json(bytes).ok() == Some(json!({
            "schemaVersion":1,"scope":"github-tls-peer-v1","case":name,"state":"ready"}))
    }
    async fn peer_stdout<R: AsyncRead + Unpin>(mut reader: R, name: &'static str, ready_tx: oneshot::Sender<bool>,
        progress: Option<Arc<Mutex<deadline::Arrivals>>>) -> ReadEnd {
        let mut ready_tx = Some(ready_tx);
        let mut bytes = Vec::new();
        let mut overflow = false;
        let mut buffer = [0u8; 4096];
        loop {
            match reader.read(&mut buffer).await {
                Ok(0) => return ReadEnd { bytes, eof: true, overflow },
                Ok(length) => {
                    let original_read_at = Instant::now();
                    let keep = length.min(PEER_OUTPUT_LIMIT.saturating_sub(bytes.len()));
                    let previous = bytes.len();
                    bytes.extend_from_slice(&buffer[..keep]);
                    overflow |= keep != length;
                    if let Some(progress) = &progress { lock(progress).observe(&bytes, previous, original_read_at); }
                    if let Some(end) = bytes.iter().position(|byte| *byte == b'\n') {
                        if let Some(tx) = ready_tx.take() { let _ = tx.send(ready(&bytes[..end], name)); }
                    } else if bytes.len() > 1024 || overflow {
                        if let Some(tx) = ready_tx.take() { let _ = tx.send(false); }
                    }
                    // Discard excess, but retain this original reader to real EOF.
                }
                Err(_) => return ReadEnd { bytes, eof: false, overflow },
            }
        }
    }
    // This guard is TLS-local; it changes neither the original owner fixture nor
    // product scheduling. Catch each cleanup independently, including its drop.
    async fn guarded<F: Future>(future: F) -> Check<F::Output> {
        let mut future = Box::pin(future);
        let result = std::future::poll_fn(|cx| {
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| future.as_mut().poll(cx))) {
                Ok(Poll::Pending) => Poll::Pending,
                Ok(Poll::Ready(value)) => Poll::Ready(Ok(value)),
                Err(_) => Poll::Ready(Err("tls_case_unwind")),
            }
        }).await;
        if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(future))).is_err() { return Err("tls_case_drop_unwind"); }
        result
    }

    struct ControlOriginal<W = tokio::process::ChildStdin> {
        stdin: Option<W>, completion: Option<oneshot::Receiver<()>>,
    }
    #[derive(Default)]
    struct ControlEnd {
        product_settled: bool, write_complete: bool, shutdown_complete: bool, released: bool, failed: bool,
        completed_at: Option<Instant>,
    }
    struct PeerControl {
        original: Arc<AsyncMutex<ControlOriginal>>, writer: Option<JoinHandle<ControlEnd>>,
        acquired: bool, started: bool, joined: bool, join_failed: bool, failed: bool,
        joined_at: Option<Instant>, end: Option<ControlEnd>,
    }
    impl PeerControl {
        fn new(completion: oneshot::Receiver<()>) -> Self {
            Self { original: Arc::new(AsyncMutex::new(ControlOriginal { stdin: None, completion: Some(completion) })),
                writer: None, acquired: false, started: false, joined: false, join_failed: false, failed: false,
                joined_at: None, end: None }
        }
        fn settled(&self) -> bool {
            self.acquired && self.started && self.joined && !self.join_failed
                && self.end.as_ref().is_some_and(|end| end.released)
        }
        fn evidence(&self, endpoint: Option<Instant>) -> Value {
            json!({"acquired":self.acquired,"started":self.started,"joined":self.joined,
                "writeComplete":self.end.as_ref().is_some_and(|end| end.write_complete),
                "shutdownComplete":self.end.as_ref().is_some_and(|end| end.shutdown_complete),
                "productSettled":self.end.as_ref().is_some_and(|end| end.product_settled),
                "withinEndpoint":self.joined_at.zip(endpoint).is_some_and(|(done, limit)| done < limit)
                    && self.end.as_ref().and_then(|end| end.completed_at).zip(endpoint).is_some_and(|(done, limit)| done < limit),
                "released":self.end.as_ref().is_some_and(|end| end.released),"failed":self.failed})
        }
    }
    async fn control_writer<W: tokio::io::AsyncWrite + Unpin>(original: Arc<AsyncMutex<ControlOriginal<W>>>, endpoint: Instant) -> ControlEnd {
        // Borrow from the pre-acquisition retained slot. Unwind/cancellation can
        // lose neither the original stdin nor its one original receiver.
        let mut original = original.lock().await;
        let mut end = ControlEnd::default();
        if let Some(completion) = original.completion.as_mut() {
            end.product_settled = matches!(guarded(tokio::time::timeout_at(tokio::time::Instant::from_std(endpoint), completion)).await, Ok(Ok(Ok(()))));
        }
        original.completion.take(); // No second receiver or replacement signal.
        if end.product_settled && Instant::now() < endpoint {
            if let Some(stdin) = original.stdin.as_mut() {
                end.write_complete = matches!(guarded(tokio::time::timeout_at(tokio::time::Instant::from_std(endpoint), stdin.write_all(b"S"))).await, Ok(Ok(Ok(()))));
            }
        }
        // Missing/false/unwound completion never writes S. Independently try
        // the same original shutdown even after a failed/unwound write or deadline;
        // there is no renewed allowance and no replacement descriptor/task.
        if let Some(stdin) = original.stdin.as_mut() {
            end.shutdown_complete = matches!(guarded(tokio::time::timeout_at(tokio::time::Instant::from_std(endpoint), stdin.shutdown())).await, Ok(Ok(Ok(()))));
        }
        if end.shutdown_complete {
            drop(original.stdin.take());
            end.released = true;
        }
        end.completed_at = Some(Instant::now());
        end.failed = !end.product_settled || !end.write_complete || !end.shutdown_complete || !end.released
            || end.completed_at.is_some_and(|done| done >= endpoint);
        end
    }

    #[cfg(test)]
    mod control_models {
        // Exercise the actual writer with inert memory only. No Child, native
        // pipe, listener, process, filesystem, peer import or test hook is used.
        use super::*;
        use std::{io, pin::Pin, task::Context};

        #[derive(Clone, Copy, Debug, PartialEq)]
        enum Fault { None, WriteError, WriteUnwind, ShutdownError, ShutdownUnwind, ShutdownPending }
        #[derive(Default)]
        struct Trace { writes: Vec<Vec<u8>>, shutdowns: usize, drops: usize }
        struct MemoryWriter { original: Arc<Mutex<Trace>>, fault: Fault }
        impl tokio::io::AsyncWrite for MemoryWriter {
            fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
                lock(&self.original).writes.push(bytes.to_vec());
                match self.fault {
                    Fault::WriteError => Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
                    Fault::WriteUnwind => panic!("inert control writer unwind"),
                    _ => Poll::Ready(Ok(bytes.len())),
                }
            }
            fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> { Poll::Ready(Ok(())) }
            fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
                lock(&self.original).shutdowns += 1;
                match self.fault {
                    Fault::ShutdownError => Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
                    Fault::ShutdownUnwind => panic!("inert control shutdown unwind"),
                    Fault::ShutdownPending => Poll::Pending,
                    _ => Poll::Ready(Ok(())),
                }
            }
        }
        impl Drop for MemoryWriter {
            fn drop(&mut self) { lock(&self.original).drops += 1; }
        }

        fn runtime() -> tokio::runtime::Runtime {
            match tokio::runtime::Builder::new_current_thread().enable_time().build() {
                Ok(runtime) => runtime,
                Err(_) => panic!("inert current-thread timer unavailable"),
            }
        }
        fn original(fault: Fault, completion: Option<oneshot::Receiver<()>>)
            -> (Arc<AsyncMutex<ControlOriginal<MemoryWriter>>>, Arc<Mutex<Trace>>) {
            let trace = Arc::new(Mutex::new(Trace::default()));
            let slot = ControlOriginal { stdin: Some(MemoryWriter { original: trace.clone(), fault }), completion };
            (Arc::new(AsyncMutex::new(slot)), trace)
        }

        #[test]
        fn original_completion_and_endpoint_gate_the_only_success_byte() {
            for mode in ["confirmed", "absent", "closed", "pending-expired", "queued-expired"] {
                let (sender, receiver) = oneshot::channel();
                let mut retained_sender = Some(sender);
                if matches!(mode, "confirmed" | "queued-expired") {
                    let Some(sender) = retained_sender.take() else { panic!("original sender missing"); };
                    assert!(sender.send(()).is_ok());
                } else if mode == "closed" { drop(retained_sender.take()); }
                let completion = if mode == "absent" { drop(receiver); None } else { Some(receiver) };
                let (slot, trace) = original(Fault::None, completion);
                let expired = mode.ends_with("expired");
                let endpoint = if expired { Instant::now() - Duration::from_secs(1) }
                    else { Instant::now() + Duration::from_secs(10) };
                let end = runtime().block_on(control_writer(slot.clone(), endpoint));
                let facts = lock(&trace);
                assert_eq!(facts.writes, if mode == "confirmed" { vec![b"S".to_vec()] } else { vec![] }, "{mode}");
                assert_eq!(facts.shutdowns, 1, "{mode}");
                assert_eq!(facts.drops, 1, "{mode}");
                assert!(end.shutdown_complete && end.released, "{mode}");
                assert_eq!(end.write_complete, mode == "confirmed", "{mode}");
                assert_eq!(end.failed, mode != "confirmed", "{mode}");
                assert_eq!(end.product_settled, matches!(mode, "confirmed" | "queued-expired"), "{mode}");
                assert_eq!(end.completed_at.is_some_and(|at| at >= endpoint), expired, "{mode}");
                drop(facts);
                let Ok(original) = slot.try_lock() else { panic!("original slot remained borrowed"); };
                assert!(original.stdin.is_none() && original.completion.is_none(), "{mode}");
                // Pending completion is not manufactured by the writer; a late
                // original publication cannot resurrect the consumed receiver.
                if mode == "pending-expired" {
                    let Some(sender) = retained_sender.take() else { panic!("pending original sender missing"); };
                    assert!(sender.send(()).is_err());
                }
            }
        }

        #[test]
        fn failed_or_unwound_write_still_shuts_down_the_same_original() {
            for fault in [Fault::WriteError, Fault::WriteUnwind] {
                let (sender, receiver) = oneshot::channel();
                assert!(sender.send(()).is_ok());
                let (slot, trace) = original(fault, Some(receiver));
                let endpoint = Instant::now() + Duration::from_secs(10);
                let end = runtime().block_on(control_writer(slot.clone(), endpoint));
                let facts = lock(&trace);
                assert_eq!(facts.writes, [b"S".to_vec()]);
                assert_eq!((facts.shutdowns, facts.drops), (1, 1));
                assert!(end.product_settled && !end.write_complete && end.shutdown_complete && end.released && end.failed);
                drop(facts);
                let Ok(original) = slot.try_lock() else { panic!("original slot remained borrowed"); };
                assert!(original.stdin.is_none() && original.completion.is_none());
            }
        }

        #[test]
        fn uncertain_shutdown_retains_the_same_original_without_renewal() {
            for fault in [Fault::ShutdownError, Fault::ShutdownUnwind, Fault::ShutdownPending] {
                let (sender, receiver) = oneshot::channel();
                assert!(sender.send(()).is_ok());
                let (slot, trace) = original(fault, Some(receiver));
                let endpoint = Instant::now() + if fault == Fault::ShutdownPending {
                    Duration::from_millis(100)
                } else { Duration::from_secs(10) };
                let end = runtime().block_on(control_writer(slot.clone(), endpoint));
                let facts = lock(&trace);
                assert_eq!(facts.writes, [b"S".to_vec()]);
                assert!(facts.shutdowns > 0);
                assert_eq!(facts.drops, 0);
                assert!(end.product_settled && end.write_complete && !end.shutdown_complete && !end.released && end.failed);
                assert_eq!(end.completed_at.is_some_and(|at| at >= endpoint), fault == Fault::ShutdownPending);
                drop(facts);
                let Ok(original) = slot.try_lock() else { panic!("original slot remained borrowed"); };
                assert!(original.stdin.as_ref().is_some_and(|writer| Arc::ptr_eq(&writer.original, &trace)));
                assert!(original.completion.is_none());
                // Only an inert Rust value is dropped when this model ends;
                // no native close or producer finality is claimed by the test.
            }
        }
    }

    #[derive(Default)]
    struct Peer {
        endpoint: Option<Instant>, completed_at: Option<Instant>,
        acquisition: Option<JoinHandle<std::io::Result<Child>>>, acquisition_joined: bool, acquisition_failed: bool,
        child: Option<Child>, spawned: bool, spawn_refused: bool, pipes_retained: bool,
        stdout_original: Arc<AsyncMutex<Option<tokio::process::ChildStdout>>>,
        stderr_original: Arc<AsyncMutex<Option<tokio::process::ChildStderr>>>,
        stdout: Option<JoinHandle<ReadEnd>>, stderr: Option<JoinHandle<ReadEnd>>,
        stdout_started: bool, stderr_started: bool, stdout_joined: bool, stderr_joined: bool, stdout_failed: bool, stderr_failed: bool,
        out: Option<ReadEnd>, err: Option<ReadEnd>, ready_rx: Option<oneshot::Receiver<bool>>, ready: bool,
        control: Option<PeerControl>,
        progress: Option<Arc<Mutex<deadline::Arrivals>>>,
        waited: Option<ExitStatus>, wait_failed: bool, stop_attempted: bool, expired: bool,
        settled: bool, protocol_checked: bool, terminal: Option<Value>,
    }
    enum PeerEvent {
        Wait(std::io::Result<ExitStatus>), Out(Result<ReadEnd, tokio::task::JoinError>),
        Err(Result<ReadEnd, tokio::task::JoinError>), Control(Result<ControlEnd, tokio::task::JoinError>), Deadline,
    }
    impl Peer {
        fn begin(&mut self, common: &Common, name: &'static str) -> Check<()> {
            require(self.endpoint.is_none(), "tls_peer_already_started")?;
            let python = common.manifest.python.clone();
            let script = common.manifest.role("peer")?.to_path_buf();
            let cwd = script.parent().ok_or("tls_peer_layout")?.to_path_buf();
            let environment = common.peer_env.clone();
            let controlled = self.control.is_some();
            let endpoint = Instant::now() + PEER_TIME;
            self.endpoint = Some(endpoint); // Includes queue, spawn and readiness.
            self.acquisition = Some(tokio::task::spawn_blocking(move || {
                if Instant::now() >= endpoint { return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "TLS peer admission expired")); }
                let mut command = Command::new(python);
                command.args(["-I", "-S", "-B"]).arg(script).arg(name).current_dir(cwd)
                    .env_clear().env("LC_ALL", "C").env("LANG", "C").envs(environment)
                    .stdin(if controlled { Stdio::piped() } else { Stdio::null() })
                    .stdout(Stdio::piped()).stderr(Stdio::piped()).kill_on_drop(false);
                if Instant::now() >= endpoint { return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "TLS peer admission expired")); }
                command.spawn()
            }));
            Ok(())
        }
        fn retain_pipes(&mut self) -> Check<()> {
            if self.pipes_retained { return Ok(()); }
            let mut input = match self.control.as_ref() {
                Some(control) => Some(control.original.try_lock().map_err(|_| "tls_peer_control_slot_busy")?),
                None => None,
            };
            let mut stdout = self.stdout_original.try_lock().map_err(|_| "tls_peer_stdout_slot_busy")?;
            let mut stderr = self.stderr_original.try_lock().map_err(|_| "tls_peer_stderr_slot_busy")?;
            let child = self.child.as_mut().ok_or("tls_peer_child_missing")?;
            require(stdout.is_none() && stderr.is_none() && input.as_ref().map_or(true, |original| original.stdin.is_none()),
                "tls_peer_original_pipe_replacement")?;
            // No await, allocation or fallible step between taking the original
            // pipes and storing ALL of them in pre-acquisition retained slots.
            *stdout = child.stdout.take();
            *stderr = child.stderr.take();
            let acquired = if let Some(original) = input.as_mut() {
                original.stdin = child.stdin.take();
                original.stdin.is_some()
            } else { false };
            self.pipes_retained = true;
            drop(input);
            if let Some(control) = self.control.as_mut() { control.acquired = acquired; }
            Ok(())
        }
        fn start_stdout(&mut self, name: &'static str) -> Check<()> {
            if self.stdout_started { return require(self.stdout.is_some() || self.stdout_joined, "tls_peer_stdout_task_missing"); }
            self.stdout_started = true; // An uncertain allocation is never retried.
            require(self.stdout_original.try_lock().is_ok_and(|original| original.is_some()), "tls_peer_stdout_missing")?;
            let (ready_tx, ready_rx) = oneshot::channel();
            self.ready_rx = Some(ready_rx);
            let original = self.stdout_original.clone();
            let progress = self.progress.clone();
            self.stdout = Some(tokio::spawn(async move {
                let mut original = original.lock().await;
                let Some(stdout) = original.as_mut() else { return ReadEnd { bytes: Vec::new(), eof: false, overflow: false }; };
                let end = peer_stdout(stdout, name, ready_tx, progress).await;
                if end.eof { drop(original.take()); }
                end
            }));
            Ok(())
        }
        fn start_stderr(&mut self) -> Check<()> {
            if self.stderr_started { return require(self.stderr.is_some() || self.stderr_joined, "tls_peer_stderr_task_missing"); }
            self.stderr_started = true;
            require(self.stderr_original.try_lock().is_ok_and(|original| original.is_some()), "tls_peer_stderr_missing")?;
            let (faults, _receiver) = mpsc::channel(2);
            let original = self.stderr_original.clone();
            self.stderr = Some(tokio::spawn(async move {
                let mut original = original.lock().await;
                let Some(stderr) = original.as_mut() else { return ReadEnd { bytes: Vec::new(), eof: false, overflow: false }; };
                let end = read_bounded(stderr, PEER_OUTPUT_LIMIT, faults).await;
                if end.eof { drop(original.take()); }
                end
            }));
            Ok(())
        }
        fn start_control(&mut self) -> Check<()> {
            let Some(control) = self.control.as_mut() else { return Ok(()); };
            if control.started { return require(control.writer.is_some() || control.joined, "tls_peer_control_task_missing"); }
            control.started = true;
            let endpoint = self.endpoint.ok_or("tls_peer_not_started")?;
            require(control.acquired && control.original.try_lock().is_ok_and(|original| original.stdin.is_some() && original.completion.is_some()),
                "tls_peer_control_missing")?;
            control.writer = Some(tokio::spawn(control_writer(control.original.clone(), endpoint)));
            Ok(())
        }
        async fn prepare_pipes(&mut self, name: &'static str) -> Check<()> {
            // Each original gets its own attempt even if another allocation or
            // setup unwinds. Already-started or uncertain tasks are not replaced.
            let kept = guarded(async { self.retain_pipes() }).await.unwrap_or_else(Err);
            let out = guarded(async { self.start_stdout(name) }).await.unwrap_or_else(Err);
            let err = guarded(async { self.start_stderr() }).await.unwrap_or_else(Err);
            let control = guarded(async { self.start_control() }).await.unwrap_or_else(Err);
            if out.is_err() { self.stdout_failed = true; }
            if err.is_err() { self.stderr_failed = true; }
            if control.is_err() { if let Some(control) = self.control.as_mut() { control.failed = true; } }
            kept.and(out).and(err).and(control)
        }
        async fn acquire(&mut self, name: &'static str) -> Check<()> {
            require(!self.acquisition_failed, "tls_peer_acquisition_unknown")?;
            let endpoint = self.endpoint.ok_or("tls_peer_not_started")?;
            if !self.acquisition_joined {
                let task = self.acquisition.as_mut().ok_or("tls_peer_acquisition_missing")?;
                let result = match tokio::time::timeout_at(tokio::time::Instant::from_std(endpoint), task).await {
                    Ok(result) => result,
                    Err(_) => { self.expired = true; return Err("tls_peer_acquisition_deadline"); },
                };
                let result = match result {
                    Ok(result) => { self.acquisition_joined = true; self.acquisition.take(); result },
                    Err(_) => { self.acquisition_failed = true; return Err("tls_peer_acquisition_unknown"); },
                };
                match result {
                    Ok(child) => { self.child = Some(child); self.spawned = true; },
                    Err(_) => { self.spawn_refused = true; return Err("tls_peer_spawn_refused"); },
                }
            }
            require(self.spawned, "tls_peer_spawn_refused")?;
            self.prepare_pipes(name).await?;
            require(Instant::now() < endpoint, "tls_peer_acquisition_deadline")
        }
        async fn readiness(&mut self, name: &'static str) -> Check<()> {
            self.acquire(name).await?;
            let endpoint = self.endpoint.ok_or("tls_peer_not_started")?;
            let receiver = self.ready_rx.as_mut().ok_or("tls_peer_readiness_missing")?;
            let admitted = tokio::time::timeout_at(tokio::time::Instant::from_std(endpoint), receiver).await
                .map_err(|_| "tls_peer_readiness_deadline")?.map_err(|_| "tls_peer_readiness_closed")?;
            self.ready_rx.take();
            require(admitted && Instant::now() < endpoint, "tls_peer_readiness_invalid")?;
            self.ready = true;
            Ok(())
        }
        fn stop_original(&mut self) {
            if self.stop_attempted || self.waited.is_some() || self.wait_failed { return; }
            let Some(child) = self.child.as_mut() else { return; };
            match child.try_wait() {
                Ok(Some(status)) => self.waited = Some(status),
                Ok(None) => {
                    self.stop_attempted = true;
                    // Even a rejected stop request cannot suppress the original
                    // wait. Only that wait and both reader joins prove finality.
                    let _ = child.start_kill();
                },
                Err(_) => self.wait_failed = true,
            }
        }
        async fn settle(&mut self, name: &'static str, failed: bool) -> bool {
            let Some(endpoint) = self.endpoint else { self.settled = true; return true; };
            if !self.acquisition_joined && !self.acquisition_failed { let _ = guarded(self.acquire(name)).await; }
            if self.spawned { let _ = self.prepare_pipes(name).await; }
            // New cases wait for the positive original product result, not the
            // projection assertion. A projection failure can still dispose with
            // S, but cannot turn the case into success. False/unwind/missing
            // completion instead returns the close-only writer's failure.
            // Failed literal deadline cases dispose their own original peer
            // promptly, including after late acquisition; T6 still waits for S.
            if (failed && (self.control.is_none() || deadline::case_name(name)))
                || self.control.as_ref().is_some_and(|control| control.failed) { self.stop_original(); }
            loop {
                let wait_pending = self.child.is_some() && self.waited.is_none() && !self.wait_failed;
                let out_pending = self.stdout.is_some() && !self.stdout_failed;
                let err_pending = self.stderr.is_some() && !self.stderr_failed;
                let control_pending = self.control.as_ref().is_some_and(|control| control.writer.is_some() && !control.join_failed && !control.joined);
                if !wait_pending && !out_pending && !err_pending && !control_pending {
                    self.completed_at = Some(Instant::now());
                    self.expired |= Instant::now() >= endpoint;
                    self.settled = !self.expired && self.acquisition_joined && !self.acquisition_failed
                        && (self.spawn_refused || self.spawned && self.waited.is_some() && !self.wait_failed
                            && self.stdout_joined && self.stderr_joined && !self.stdout_failed && !self.stderr_failed
                            && self.out.as_ref().is_some_and(|end| end.eof) && self.err.as_ref().is_some_and(|end| end.eof)
                            && self.control.as_ref().map_or(true, PeerControl::settled));
                    if self.settled { self.child.take(); }
                    return self.settled;
                }
                let event = {
                    let Self { child, stdout, stderr, control, .. } = self;
                    tokio::select! {
                        result = wait_original(child), if wait_pending => PeerEvent::Wait(result),
                        result = join_slot(stdout), if out_pending => PeerEvent::Out(result),
                        result = join_slot(stderr), if err_pending => PeerEvent::Err(result),
                        result = async {
                            match control.as_mut() { Some(control) => join_slot(&mut control.writer).await, None => pending().await }
                        }, if control_pending => PeerEvent::Control(result),
                        _ = tokio::time::sleep_until(tokio::time::Instant::from_std(endpoint)) => PeerEvent::Deadline,
                    }
                };
                match event {
                    PeerEvent::Wait(Ok(status)) => self.waited = Some(status),
                    PeerEvent::Wait(Err(_)) => self.wait_failed = true,
                    PeerEvent::Out(Ok(end)) => { self.stdout_joined = true; self.stdout.take(); self.out = Some(end); },
                    PeerEvent::Err(Ok(end)) => { self.stderr_joined = true; self.stderr.take(); self.err = Some(end); },
                    // Keep each failed consumed handle without polling it again;
                    // still attempt the OTHER reader and original child wait.
                    PeerEvent::Out(Err(_)) => self.stdout_failed = true,
                    PeerEvent::Err(Err(_)) => self.stderr_failed = true,
                    PeerEvent::Control(Ok(end)) => {
                        let failed = end.failed;
                        if let Some(control) = self.control.as_mut() {
                            control.joined = true; control.joined_at = Some(Instant::now()); control.writer.take();
                            control.failed |= failed; control.end = Some(end);
                        }
                        if failed { self.stop_original(); }
                    },
                    PeerEvent::Control(Err(_)) => {
                        if let Some(control) = self.control.as_mut() { control.join_failed = true; control.failed = true; }
                        self.stop_original();
                    },
                    PeerEvent::Deadline => {
                        self.expired = true;
                        if let Some(control) = self.control.as_mut() { control.failed = true; }
                        self.stop_original();
                        return false;
                    },
                }
            }
        }
        fn evidence(&self) -> Value {
            let mut value = json!({"acquisitionJoined":self.acquisition_joined,"spawned":self.spawned,"waited":self.waited.is_some(),
                "exitCode":self.waited.as_ref().and_then(ExitStatus::code),"exitSuccess":self.waited.as_ref().map(ExitStatus::success),
                "stopAttempted":self.stop_attempted,"stdoutJoined":self.stdout_joined,"stderrJoined":self.stderr_joined,
                "stdoutEof":self.out.as_ref().is_some_and(|end| end.eof),"stderrEof":self.err.as_ref().is_some_and(|end| end.eof),
                "stdoutBytes":self.out.as_ref().map_or(0, |end| end.bytes.len()),"stderrBytes":self.err.as_ref().map_or(0, |end| end.bytes.len()),
                "stdoutOverflow":self.out.as_ref().is_some_and(|end| end.overflow),"stderrOverflow":self.err.as_ref().is_some_and(|end| end.overflow),
                "ready":self.ready,"settled":self.settled,"withinEndpoint":self.settled && !self.expired && self.completed_at.zip(self.endpoint).is_some_and(|(done, end)| done < end),
                "protocolChecked":self.protocol_checked,"terminal":self.terminal});
            if let Some(control) = self.control.as_ref() { value["control"] = control.evidence(self.endpoint); }
            value
        }
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct RedirectCompletion { empty: bool, unexpected: u64, closed: bool }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct Completion {
        bytes: u64, eof: bool, closed: bool, primary_empty: bool, primary_unexpected: u64, primary_closed: bool,
        redirect: Option<RedirectCompletion>,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct Finished {
        schema_version: u32, scope: String, #[serde(rename = "case")] case_name: String, state: String,
        status: String, code: Option<String>, connections: u64, handshakes: u64, requests: u64, decrypted_bytes: u64,
        auth_bytes: u64, close_notify: u64, tls_refused: bool, wire_read_bytes: Vec<u64>, wire_write_bytes: Vec<u64>,
        reply_bytes: Vec<u64>, all_sockets_closed: bool,
        completion: Option<Completion>, reply_stops: Option<Vec<String>>,
    }
    impl Peer {
        fn check(&mut self, scenario: &Scenario) -> Check<()> {
            require(self.settled && self.spawned && self.ready && !self.expired && !self.stop_attempted
                && self.waited.as_ref().is_some_and(ExitStatus::success), "tls_peer_native_result")?;
            let out = self.out.as_ref().ok_or("tls_peer_stdout_missing")?;
            let err = self.err.as_ref().ok_or("tls_peer_stderr_missing")?;
            require(out.eof && err.eof && !out.overflow && !err.overflow && err.bytes.is_empty()
                && out.bytes.len() <= PEER_OUTPUT_LIMIT, "tls_peer_output_bound")?;
            let lines = out.bytes.split(|byte| *byte == b'\n').collect::<Vec<_>>();
            require(lines.len() == 3 && lines[2].is_empty() && ready(lines[0], scenario.name), "tls_peer_frame_count")?;
            let value = protocol::strict_json(lines[1]).map_err(|_| "tls_peer_terminal_json")?;
            const FIELDS: &[&str] = &["schemaVersion", "scope", "case", "state", "status", "code", "connections", "handshakes",
                "requests", "decryptedBytes", "authBytes", "closeNotify", "tlsRefused", "wireReadBytes", "wireWriteBytes", "replyBytes", "allSocketsClosed"];
            let streaming = scenario.streaming();
            require(value.as_object().is_some_and(|row| row.len() == FIELDS.len() + (if streaming { 2 } else { 0 })
                && FIELDS.iter().all(|name| row.contains_key(*name))
                && (!streaming || row.contains_key("completion") && row.contains_key("replyStops"))),
                "tls_peer_terminal_fields")?;
            let facts: Finished = serde_json::from_value(value.clone()).map_err(|_| "tls_peer_terminal_schema")?;
            let refused = scenario.name.starts_with("T2-");
            let requests = if refused { 0 } else { scenario.connections };
            require(facts.schema_version == 1 && facts.scope == "github-tls-peer-v1" && facts.case_name == scenario.name
                && facts.state == "finished" && facts.status == "passed" && facts.code.is_none() && facts.all_sockets_closed
                && facts.connections == scenario.connections && facts.handshakes == requests && facts.requests == requests
                && facts.tls_refused == refused && facts.close_notify <= facts.connections
                && facts.decrypted_bytes <= facts.connections * 8192
                && facts.auth_bytes == requests * b"Bearer INERT_NOT_A_CREDENTIAL".len() as u64
                && facts.decrypted_bytes >= facts.auth_bytes, "tls_peer_case_observations")?;
            let (wire_limit, reply_limit) = scenario.limits();
            require(facts.wire_read_bytes.len() == facts.connections as usize && facts.wire_write_bytes.len() == facts.connections as usize
                && facts.reply_bytes.len() == facts.connections as usize
                && facts.wire_read_bytes.iter().chain(&facts.wire_write_bytes).all(|size| (1..=wire_limit).contains(size))
                && facts.reply_bytes.iter().all(|size| if refused { *size == 0 } else { (1..=reply_limit).contains(size) }), "tls_peer_wire_bounds")?;
            if refused { require(facts.decrypted_bytes == 0 && facts.close_notify == 0, "tls_peer_authorization_before_refusal")?; }
            match scenario.name {
                "T1-source" | "T1-zip" | "T3-clean" => require(facts.close_notify == scenario.connections, "tls_peer_clean_notify_missing")?,
                "T3-ragged" => require(facts.close_notify == 0, "tls_peer_ragged_notify_present")?,
                "T3-length" | "T3-chunk" => require(facts.close_notify == 1, "tls_peer_framing_notify_missing")?,
                _ => {},
            }
            if let Some((scripted, minima)) = scenario.replies() {
                let control = self.control.as_ref().ok_or("tls_peer_control_missing")?;
                let end = control.end.as_ref().ok_or("tls_peer_control_return_missing")?;
                require(control.settled() && !control.failed && end.product_settled && end.write_complete && end.shutdown_complete
                    && control.joined_at.zip(self.endpoint).is_some_and(|(done, limit)| done < limit)
                    && end.completed_at.zip(self.endpoint).is_some_and(|(done, limit)| done < limit), "tls_peer_control_result")?;
                const COMPLETION_FIELDS: &[&str] = &["bytes", "eof", "closed", "primaryEmpty", "primaryUnexpected", "primaryClosed", "redirect"];
                require(value.get("completion").and_then(Value::as_object).is_some_and(|row|
                    row.len() == COMPLETION_FIELDS.len() && COMPLETION_FIELDS.iter().all(|name| row.contains_key(*name))),
                    "tls_peer_completion_fields")?;
                let completion = facts.completion.as_ref().ok_or("tls_peer_completion_missing")?;
                require(completion.bytes == 1 && completion.eof && completion.closed && completion.primary_empty
                    && completion.primary_unexpected == 0 && completion.primary_closed, "tls_peer_completion_observation")?;
                if scenario.name == "T6-redirect" {
                    let redirect = completion.redirect.as_ref().ok_or("tls_peer_redirect_missing")?;
                    require(redirect.empty && redirect.unexpected == 0 && redirect.closed, "tls_peer_redirect_observation")?;
                } else { require(completion.redirect.is_none(), "tls_peer_redirect_unexpected")?; }
                let stops = facts.reply_stops.as_ref().ok_or("tls_peer_reply_stops_missing")?;
                require(stops.len() == facts.connections as usize && scripted.len() == stops.len() && minima.len() == stops.len(),
                    "tls_peer_reply_stop_count")?;
                let mut notified = 0u64;
                for (index, stop) in stops.iter().enumerate() {
                    let application_complete = match stop.as_str() {
                        "none" => { notified += 1; true },
                        "notify:broken-pipe" | "notify:connection-reset" | "notify:tls-eof" | "notify:tls-close-notify" => true,
                        "reply:broken-pipe" | "reply:connection-reset" | "reply:tls-eof" | "reply:tls-close-notify" => false,
                        _ => return Err("tls_peer_reply_stop_category"),
                    };
                    require(scenario.name != "T6-target" || stop.as_str() == "none", "tls_peer_target_reply_interrupted")?;
                    let minimum = if application_complete { scripted[index] } else { minima[index] };
                    require((minimum..=scripted[index]).contains(&facts.reply_bytes[index])
                        && facts.wire_write_bytes[index] >= minimum, "tls_peer_streaming_progress")?;
                }
                require(facts.close_notify == notified, "tls_peer_streaming_notify_count")?;
                // These are the peer's original S+EOF, monitored-listener probes
                // and sole closes, separate from writer intent/return above.
                // They prove no pending connection at these fixed endpoints,
                // not universal network non-use or product heap allocation.
            }
            // Only this closed, validated redacted frame can enter the receipt.
            // Raw streams and even a peer-provided failure message never do.
            self.terminal = Some(value);
            self.protocol_checked = true;
            Ok(())
        }
    }

    struct Retained {
        supervisor: Supervisor, selection: GitHubTlsRuntime, ticket: Mutex<Option<GitHubReadTicket>>, peer: AsyncMutex<Peer>,
    }
    // Install before acquisition/readiness/admission. A failing future or its
    // destructor cannot drop original resource books or permit another case.
    static RETAINED: Mutex<Option<Arc<Retained>>> = Mutex::new(None);
    struct TlsCase {
        product: Case, retained: Arc<Retained>, scenario: &'static Scenario, projection_checked: bool, result_reason: Option<&'static str>,
        product_completion: Option<oneshot::Sender<()>>, projection: Option<Value>,
    }
    impl Admitted {
        fn case(&self, scenario: &'static Scenario) -> Check<TlsCase> {
            require(lock(&RETAINED).is_none(), "tls_previous_case_retained")?;
            let product = Case::new(&self.inputs, scenario.name, None, scenario.zip)?;
            let private = product.root.join("runtime");
            fs::create_dir(&private).map_err(|_| "tls_private_directory")?;
            let trust_name = if scenario.other_root { "other-root-ca.pem" } else { "root-ca.pem" };
            let trust = read(self.common.manifest.role(trust_name)?, 512 * 1024)?;
            for (name, bytes) in [("github_connection_bootstrap.py", BOOTSTRAP), ("github-ca.pem", trust.as_slice())] {
                let mut original = fs::OpenOptions::new().write(true).create_new(true).open(private.join(name)).map_err(|_| "tls_private_create")?;
                original.write_all(bytes).and_then(|_| original.sync_all()).map_err(|_| "tls_private_write")?;
                original.set_permissions(fs::Permissions::from_mode(0o400)).map_err(|_| "tls_private_mode")?;
            }
            let selection = GitHubTlsRuntime { original: Arc::new(Selection { common: self.common.clone(),
                core: if scenario.zip { self.inputs.zip.clone() } else { self.inputs.source.clone() },
                bootstrap: private.join("github_connection_bootstrap.py"), trust }) };
            *lock(&product.supervisor.inner.test.github_tls) = Some(selection.clone());
            // Allocate the one original private completion channel and all pipe
            // slots before any native acquisition. Old nine cases have no control pipe
            // or new receipt fields; no helper/product arguments are changed.
            let (product_completion, peer_completion) = if scenario.streaming() {
                let (sender, receiver) = oneshot::channel(); (Some(sender), Some(receiver))
            } else { (None, None) };
            let peer = Peer { control: peer_completion.map(PeerControl::new), ..Peer::default() };
            let retained = Arc::new(Retained { supervisor: product.supervisor.clone(), selection,
                ticket: Mutex::new(None), peer: AsyncMutex::new(peer) });
            *lock(&RETAINED) = Some(retained.clone());
            Ok(TlsCase { product, retained, scenario, projection_checked: false, result_reason: None, product_completion, projection: None })
        }
    }
    impl TlsCase {
        async fn exercise(&mut self) -> Check<()> {
            let endpoint = {
                let mut peer = self.retained.peer.lock().await;
                peer.begin(&self.retained.selection.original.common, self.scenario.name)?;
                peer.readiness(self.scenario.name).await?;
                peer.endpoint.ok_or("tls_peer_endpoint_missing")?
            };
            {
                let mut retained = lock(&self.retained.ticket);
                require(retained.is_none(), "tls_ticket_already_admitted")?;
                let ticket = self.product.supervisor.start_github_readonly("owner/app", None, None, TOKEN)
                    .map_err(|_| "tls_product_admission")?;
                *retained = Some(ticket); // No await/fallible step after admission.
            }
            // The peer's original endpoint also bounds this observer. It never
            // changes the product's own original 10s operation/2s cleanup times.
            let observation = tokio::time::timeout_at(tokio::time::Instant::from_std(endpoint), async {
                loop {
                    let receipt = lock(&self.retained.ticket).as_ref().map(GitHubReadTicket::receipt).ok_or("tls_ticket_missing")?;
                    if !matches!(receipt, GitHubReadReceipt::Pending) { return Ok::<_, &'static str>(receipt); }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            }).await.map_err(|_| "tls_product_observation_deadline")??;
            let GitHubReadReceipt::Settled { outcome: Ok(outcome), settled_at, was_unknown: false } = observation
                else { return Err("tls_product_typed_outcome_missing"); };
            let owner = self.product.owner("github-read-1")?;
            let cooldown = if self.scenario.name == "T6-rate-expiry" { Some(120) } else { None };
            require(Instant::now() < endpoint && settled_at <= Instant::now() && settled_at < owner.endpoint()
                && outcome.facts.schema_version == 1 && outcome.control.reason == self.scenario.reason
                && outcome.control.credential_expires_at.is_none() && outcome.control.cooldown_seconds == cooldown
                && !outcome.control.cooldown_blocked, "tls_product_control_projection")?;
            if self.scenario.reason == Reason::None {
                require(outcome.facts.account.state == FactState::Observed && outcome.facts.account.reason == Reason::None
                    && outcome.facts.account.value.as_ref().is_some_and(|account| account.id == "11" && account.login == "owner")
                    && outcome.facts.repository.state == FactState::Observed && outcome.facts.repository.reason == Reason::None
                    && outcome.facts.repository.value.as_ref().is_some_and(|repository| repository.id == "22" && repository.full_name == "owner/app"
                        && repository.default_branch == "main" && repository.visibility == Visibility::Private && !repository.archived
                        && repository.permissions.pull == Permission::ReportedAllowed && repository.permissions.push == Permission::ReportedDenied
                        && repository.permissions.admin == Permission::ReportedDenied)
                    && outcome.facts.automation.state == FactState::Observed && outcome.facts.automation.reason == Reason::None
                    && outcome.facts.automation.value.as_ref().is_some_and(|automation| automation.coverage == Coverage::Complete
                        && automation.workflows.len() == 4 && automation.workflows.iter().all(|row| row.presence == Presence::NotListed
                            && row.remote_id.is_none() && row.state == WorkflowState::Unknown))
                    && outcome.facts.account.observed_at.is_some() && outcome.facts.account.observed_at == outcome.facts.repository.observed_at
                    && outcome.facts.account.observed_at == outcome.facts.automation.observed_at, "tls_product_success_projection")?;
            } else if self.scenario.reason == Reason::TargetChanged {
                require(outcome.facts.account.state == FactState::Observed && outcome.facts.account.reason == Reason::None
                    && outcome.facts.account.value.as_ref().is_some_and(|account| account.id == "11" && account.login == "owner")
                    && outcome.facts.account.observed_at.is_some()
                    && outcome.facts.repository.state == FactState::Unavailable && outcome.facts.repository.value.is_none()
                    && outcome.facts.repository.observed_at.is_none() && outcome.facts.repository.reason == Reason::TargetChanged
                    && outcome.facts.automation.state == FactState::Unavailable && outcome.facts.automation.value.is_none()
                    && outcome.facts.automation.observed_at.is_none() && outcome.facts.automation.reason == Reason::TargetChanged,
                    "tls_product_target_projection")?;
            } else {
                require(outcome.facts.account.state == FactState::Unavailable && outcome.facts.account.value.is_none()
                    && outcome.facts.account.observed_at.is_none() && outcome.facts.account.reason == self.scenario.reason
                    && outcome.facts.repository.state == FactState::Unavailable && outcome.facts.repository.value.is_none()
                    && outcome.facts.repository.observed_at.is_none() && outcome.facts.repository.reason == self.scenario.reason
                    && outcome.facts.automation.state == FactState::Unavailable && outcome.facts.automation.value.is_none()
                    && outcome.facts.automation.observed_at.is_none() && outcome.facts.automation.reason == self.scenario.reason,
                    "tls_product_refusal_projection")?;
            }
            if self.scenario.streaming() {
                self.projection = Some(json!({
                    "account":if outcome.facts.account.state == FactState::Observed { "observed" } else { "unavailable" },
                    "repository":if outcome.facts.repository.state == FactState::Observed { "observed" } else { "unavailable" },
                    "automation":if outcome.facts.automation.state == FactState::Observed { "observed" } else { "unavailable" },
                    "cooldownSeconds":outcome.control.cooldown_seconds,"credentialExpiresAt":outcome.control.credential_expires_at,
                    "cooldownBlocked":outcome.control.cooldown_blocked}));
            }
            self.result_reason = Some(reason(self.scenario.reason));
            self.projection_checked = true;
            Ok(())
        }
        fn product_facts(&self) -> Check<()> {
            self.product.native_facts(true, true)?;
            let owners = self.product.supervisor.inner.test.owners();
            require(owners.len() == 1 && self.product.supervisor.can_exit() && !self.product.supervisor.disabled()
                && self.product.supervisor.inner.permits.available_permits() == ACTIVE_LIMIT, "tls_product_final_roster")?;
            for owner in owners {
                let state = lock(&owner.state);
                let observed = lock(&owner.observation);
                require(matches!(owner.profile, Profile::GitHubReadOnly) && state.terminal && !state.unknown && state.error.is_none()
                    && observed.observer_joined && observed.exit_success == Some(true) && lock(&owner.permit).is_none(), "tls_product_finality")?;
            }
            Ok(())
        }
        async fn evidence(&self, passed: bool, failure: Option<&str>, product_settled: bool) -> Value {
            let owners = self.product.supervisor.inner.test.owners().iter().map(|owner| {
                let state = lock(&owner.state);
                let observed = lock(&owner.observation);
                json!({"id":owner.id,"profile":"github-readonly","terminal":state.terminal,"unknownLatched":state.unknown,
                    "permitRetained":lock(&owner.permit).is_some(),"observerJoined":observed.observer_joined,
                    "firstError":state.error.as_ref().map(|error| &error.code),"native":observed.clone()})
            }).collect::<Vec<_>>();
            let peer = self.retained.peer.lock().await.evidence();
            let mut product = json!({"settled":product_settled,"projectionChecked":self.projection_checked,"reason":self.result_reason,
                "registeredOwners":lock(&self.product.supervisor.inner.owners).len(),"disabled":self.product.supervisor.disabled(),"owners":owners});
            if self.scenario.streaming() { product["projection"] = self.projection.clone().unwrap_or(Value::Null); }
            json!({"case":self.scenario.name,"passed":passed,"failureCode":failure,"elapsedMs":self.product.begin.elapsed().as_millis(),
                "coreMode":if self.scenario.zip { "zip" } else { "source" },
                "trustFixture":if self.scenario.other_root { "other-root-ca.pem" } else { "root-ca.pem" },
                "product":product,"peer":peer})
        }
        fn release_retention(&self) -> Check<()> {
            require(Arc::ptr_eq(&self.retained.supervisor.inner, &self.product.supervisor.inner)
                && self.product.supervisor.can_exit()
                && lock(&self.product.supervisor.inner.test.github_tls).as_ref()
                    .is_some_and(|selection| Arc::ptr_eq(&selection.original, &self.retained.selection.original))
                && lock(&self.retained.ticket).as_ref().map_or(true, |ticket| matches!(ticket.receipt(), GitHubReadReceipt::Settled { .. })),
                "tls_original_retention_not_settled")?;
            let mut slot = lock(&RETAINED);
            require(slot.as_ref().is_some_and(|original| Arc::ptr_eq(original, &self.retained)), "tls_retention_identity")?;
            lock(&self.retained.ticket).take();
            slot.take();
            Ok(())
        }
    }
    struct TlsReceipt { path: PathBuf, bindings: Value, cases: Vec<Value> }
    impl TlsReceipt {
        fn write(&self, state: &str, code: Option<&str>) -> Check<()> {
            let bytes = serde_json::to_vec(&json!({"schemaVersion":1,"scope":"github-readonly-tls-hosted-v1",
                "status":state,"allOwnersSettled":state == "passed","allPeersSettled":state == "passed","failureCode":code,
                "bindings":self.bindings,"cases":self.cases,"outerWait":"external-original-observer-required","notVerified":LIMITATIONS}))
                .map_err(|_| "tls_receipt_encoding")?;
            require(bytes.len() <= 128 * 1024, "tls_receipt_limit")?;
            fs::write(&self.path, bytes).map_err(|_| "tls_receipt_write")
        }
    }
    pub(super) async fn run() {
        let admitted = match Admitted::new() { Ok(value) => value, Err(code) => refuse_before_cases(None, code) };
        let mut receipt = TlsReceipt { path: admitted.inputs.root.join("receipt.json"), bindings: admitted.common.bindings.clone(), cases: Vec::new() };
        if receipt.write("running", None).is_err() { panic!("TLS receipt unavailable before native work"); }
        for scenario in CASES {
            let mut case = match admitted.case(scenario) {
                Ok(case) => case,
                Err(code) => { let _ = receipt.write("failed", Some(code)); panic!("TLS fixture preparation failed: {code}"); },
            };
            let mut checked = guarded(case.exercise()).await.unwrap_or_else(Err);
            let failed = checked.is_err();
            let peer_book = case.retained.clone();
            let product = &mut case.product;
            let mut completion = case.product_completion.take();
            let product_attempt = async move {
                let result = guarded(product.settle(failed)).await;
                // The sole success publication follows the ACTUAL guarded
                // Case::settle true return, including its destructor guard.
                // A false/unwind result only drops the original sender.
                if matches!(result, Ok(true)) {
                    if let Some(sender) = completion.take() { let _ = sender.send(()); }
                }
                drop(completion);
                result
            };
            // Neither early false nor unwind in Case::settle can skip peer
            // stop/wait/readers. Each independent original gets its own guard;
            // join! drives BOTH attempts, never boolean short-circuit or try_join.
            let (product_result, peer_result) = tokio::join!(
                async { guarded(product_attempt).await.unwrap_or_else(Err) },
                guarded(async { peer_book.peer.lock().await.settle(scenario.name, failed).await }),
            );
            let product_settled = matches!(product_result, Ok(true));
            let peer_settled = matches!(peer_result, Ok(true));
            if !product_settled || !peer_settled {
                receipt.cases.push(case.evidence(false, Some("tls_custody_unresolved"), product_settled).await);
                let _ = receipt.write("failed-retained", Some("tls_custody_unresolved"));
                // Keep the actual Case plus static original books, without
                // changing inputs, starting the next case or guessing cleanup.
                pending::<()>().await;
                return;
            }
            let product_check = guarded(async { case.product_facts() }).await.unwrap_or_else(Err);
            let peer_check = guarded(async { case.retained.peer.lock().await.check(scenario) }).await.unwrap_or_else(Err);
            if checked.is_ok() { checked = product_check.and(peer_check); }
            if let Err(code) = case.release_retention() {
                receipt.cases.push(case.evidence(false, Some(code), product_settled).await);
                let _ = receipt.write("failed-retained", Some(code));
                pending::<()>().await;
                return;
            }
            receipt.cases.push(case.evidence(checked.is_ok(), checked.err(), product_settled).await);
            if let Err(code) = checked { let _ = receipt.write("failed", Some(code)); panic!("TLS check failed after independent settlement: {code}"); }
            if receipt.write("running", None).is_err() { panic!("TLS receipt failed after independent settlement"); }
        }
        std::env::set_var("MRK_DESKTOP_DEV_CORE", &admitted.inputs.source); // Every original client AND peer settled.
        if receipt.write("passed", None).is_err() { panic!("TLS final receipt failed after independent settlement"); }
    }

    pub(super) async fn run_deadline(profile: &'static str) { deadline::run(profile).await; }

    // Seven fixed follow-on cases. These are not a product transport, a generic
    // process runner or permission to invoke native fixtures on a shared host.
    // The original16 parser and its positive owner predicates above remain
    // separate; a timeout cannot become an accepted T1--T3 or T6 result.
    mod deadline {
        use super::*;
        use std::os::unix::fs::OpenOptionsExt;

        const DIRECT_ID: &str = "tls-direct-1";
        const CLIENT_RESERVE: Duration = Duration::from_secs(14);
        const CADENCE: Duration = Duration::from_millis(1500);
        const HELPER_EARLIEST: Duration = Duration::from_secs(10);
        const HELPER_LATEST: Duration = Duration::from_secs(12);
        const GET_LATEST: Duration = Duration::from_secs(2);
        const NOT_VERIFIED: &[&str] = &["populated-ambient-ca-directory", "platform-trust-stores",
            "getaddrinfo-internal-cancellation", "T6-streaming-controls", "CA-file-native-faults",
            "native-stuck-spawn-wait-close", "real-github-authentication", "production-runtime-custody",
            "native-gui", "native-document-lifecycle", "packaged-runtime", "production-enablement"];
        const HOSTS: &[Scenario] = &[
            Scenario { name: "T4-owner-clear", zip: false, other_root: false, reason: Reason::None, connections: 4 },
            Scenario { name: "T4-ambient-fixed", zip: false, other_root: false, reason: Reason::None, connections: 4 },
            Scenario { name: "T4-ambient-no-rescue", zip: false, other_root: true, reason: Reason::TlsFailed, connections: 1 },
            Scenario { name: "T5-handshake", zip: false, other_root: false, reason: Reason::NetworkUnavailable, connections: 1 },
            Scenario { name: "T5-read", zip: false, other_root: false, reason: Reason::NetworkUnavailable, connections: 1 },
            Scenario { name: "T5-helper-read", zip: false, other_root: false, reason: Reason::NetworkUnavailable, connections: 1 },
        ];
        const DNS: &[Scenario] = &[
            Scenario { name: "T5-dns", zip: false, other_root: false, reason: Reason::NetworkUnavailable, connections: 0 },
        ];
        fn direct(name: &str) -> bool { matches!(name, "T4-ambient-fixed" | "T4-ambient-no-rescue" | "T5-helper-read") }
        fn owner_deadline(name: &str) -> bool { matches!(name, "T5-dns" | "T5-handshake" | "T5-read") }
        pub(super) fn case_name(name: &str) -> bool { name == "T4-owner-clear" || direct(name) || owner_deadline(name) }
        fn elapsed(origin: Instant, observation: Instant) -> Option<u64> {
            observation.checked_duration_since(origin).and_then(|value| u64::try_from(value.as_nanos()).ok())
        }

        #[derive(Default)]
        pub(super) struct Arrivals {
            frames: Vec<(usize, Instant)>, observed_bytes: usize, invalid: bool,
        }
        impl Arrivals {
            pub(super) fn observe(&mut self, bytes: &[u8], previous: usize, at: Instant) {
                // Called only by the normally driven original stdout reader,
                // immediately after its read. Store LF offsets/times, not a
                // second stream, peer timestamps or later parsing/wait times.
                if previous != self.observed_bytes || previous > bytes.len() || bytes.len() > PEER_OUTPUT_LIMIT {
                    self.invalid = true; return;
                }
                for (offset, byte) in bytes[previous..].iter().enumerate() {
                    if *byte == b'\n' {
                        if self.frames.len() == 26 { self.invalid = true; break; }
                        self.frames.push((previous + offset + 1, at));
                    }
                }
                self.observed_bytes = bytes.len();
            }
        }
        #[derive(Clone, Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Progress {
            schema_version: u32, scope: String, #[serde(rename = "case")] case_name: String, state: String,
            event: String, sequence: u64, requests: u64, body_bytes: u64, wire_read_bytes: u64,
            wire_write_bytes: u64, dns_questions: u64, dns_a: u64,
            #[serde(rename = "dnsAAAA")] dns_aaaa: u64, client_stop: Option<String>,
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Proxy { empty: bool, unexpected: u64, closed: bool }
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Completion {
            bytes: u64, eof: bool, closed: bool, primary_empty: bool, primary_unexpected: u64,
            primary_closed: bool, proxy: Option<Proxy>, dns_empty: Option<bool>, dns_closed: Option<bool>,
        }
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Terminal {
            schema_version: u32, scope: String, #[serde(rename = "case")] case_name: String, state: String,
            status: String, code: Option<String>, connections: u64, handshakes: u64, requests: u64,
            decrypted_bytes: u64, auth_bytes: u64, close_notify: u64, tls_refused: bool,
            wire_read_bytes: Vec<u64>, wire_write_bytes: Vec<u64>, reply_bytes: Vec<u64>, all_sockets_closed: bool,
            sni: u64, phase: String, withheld_wire_bytes: u64, body_bytes: u64, incomplete_body: bool,
            client_stop: Option<String>, progress_count: u64, dns_questions: u64, dns_a: u64,
            #[serde(rename = "dnsAAAA")] dns_aaaa: u64, dns_replies: u64, completion: Completion,
        }
        struct Frames { progress: Vec<(Progress, Instant)>, terminal: Terminal }
        fn fields(value: &Value, expected: &[&str], code: &'static str) -> Check<()> {
            require(value.as_object().is_some_and(|row| row.len() == expected.len()
                && expected.iter().all(|name| row.contains_key(*name))), code)
        }
        fn decode_progress_frame(line: &[u8]) -> Check<Progress> {
            let value = protocol::strict_json(line).map_err(|_| "tls_deadline_progress_json")?;
            fields(&value, &["schemaVersion", "scope", "case", "state", "event", "sequence", "requests", "bodyBytes",
                "wireReadBytes", "wireWriteBytes", "dnsQuestions", "dnsA", "dnsAAAA", "clientStop"], "tls_deadline_progress_fields")?;
            serde_json::from_value(value).map_err(|_| "tls_deadline_progress_schema")
        }
        fn decode_terminal_frame(line: &[u8]) -> Check<(Terminal, Value)> {
            let value = protocol::strict_json(line).map_err(|_| "tls_deadline_terminal_json")?;
            fields(&value, &["schemaVersion", "scope", "case", "state", "status", "code", "connections", "handshakes", "requests",
                "decryptedBytes", "authBytes", "closeNotify", "tlsRefused", "wireReadBytes", "wireWriteBytes", "replyBytes",
                "allSocketsClosed", "sni", "phase", "withheldWireBytes", "bodyBytes", "incompleteBody", "clientStop",
                "progressCount", "dnsQuestions", "dnsA", "dnsAAAA", "dnsReplies", "completion"], "tls_deadline_terminal_fields")?;
            fields(&value["completion"], &["bytes", "eof", "closed", "primaryEmpty", "primaryUnexpected", "primaryClosed",
                "proxy", "dnsEmpty", "dnsClosed"], "tls_deadline_completion_fields")?;
            let terminal: Terminal = serde_json::from_value(value.clone()).map_err(|_| "tls_deadline_terminal_schema")?;
            Ok((terminal, value))
        }
        fn client_stop(value: Option<&str>, handshake: bool) -> bool {
            matches!(value, Some("tcp-eof" | "connection-reset"))
                || !handshake && matches!(value, Some("broken-pipe" | "tls-close-notify"))
        }
        impl Frames {
            fn from_original(peer: &mut Peer, scenario: &Scenario) -> Check<Self> {
                require(peer.settled && peer.spawned && peer.ready && !peer.expired && !peer.stop_attempted
                    && peer.waited.as_ref().is_some_and(ExitStatus::success), "tls_deadline_peer_native")?;
                let endpoint = peer.endpoint.ok_or("tls_peer_endpoint_missing")?;
                let control = peer.control.as_ref().ok_or("tls_deadline_control_missing")?;
                require(control.settled() && !control.failed
                    && control.joined_at.is_some_and(|at| at < endpoint)
                    && control.end.as_ref().is_some_and(|end| end.product_settled && end.write_complete
                        && end.shutdown_complete && !end.failed && end.completed_at.is_some_and(|at| at < endpoint)),
                    "tls_deadline_control_not_confirmed")?;
                let out = peer.out.as_ref().ok_or("tls_peer_stdout_missing")?;
                let err = peer.err.as_ref().ok_or("tls_peer_stderr_missing")?;
                require(out.eof && err.eof && !out.overflow && !err.overflow && err.bytes.is_empty()
                    && out.bytes.len() <= PEER_OUTPUT_LIMIT, "tls_deadline_peer_output")?;
                let arrivals = lock(peer.progress.as_ref().ok_or("tls_deadline_arrivals_missing")?);
                let lines = out.bytes.split(|byte| *byte == b'\n').collect::<Vec<_>>();
                require(!arrivals.invalid && arrivals.observed_bytes == out.bytes.len()
                    && (3..=27).contains(&lines.len()) && lines.last().is_some_and(|line| line.is_empty())
                    && lines.len() == arrivals.frames.len() + 1 && ready(lines[0], scenario.name), "tls_deadline_frame_count")?;
                let mut offset = 0usize;
                let mut previous_time = None;
                for (line, (end, at)) in lines[..lines.len() - 1].iter().zip(&arrivals.frames) {
                    offset += line.len() + 1;
                    require(!line.is_empty() && line.len() <= 4096 && *end == offset && *at < endpoint
                        && previous_time.map_or(true, |before| before <= *at), "tls_deadline_frame_arrival")?;
                    previous_time = Some(*at);
                }
                let mut progress = Vec::new();
                for (index, line) in lines[1..lines.len() - 2].iter().enumerate() {
                    let item = decode_progress_frame(line)?;
                    require(item.schema_version == 1 && item.scope == "github-tls-peer-v1" && item.case_name == scenario.name
                        && item.state == "progress" && item.sequence == index as u64 + 1 && item.sequence <= 24,
                        "tls_deadline_progress_identity")?;
                    progress.push((item, arrivals.frames[index + 1].1));
                }
                let (terminal, value) = decode_terminal_frame(lines[lines.len() - 2])?;
                let frames = Self { progress, terminal };
                frames.check(scenario)?;
                drop(arrivals);
                peer.terminal = Some(value); // Validated redacted fields only.
                peer.protocol_checked = true;
                Ok(frames)
            }
            fn check(&self, scenario: &Scenario) -> Check<()> {
                let facts = &self.terminal;
                let completion = &facts.completion;
                let dns = scenario.name == "T5-dns";
                let handshake = scenario.name == "T5-handshake";
                let read = matches!(scenario.name, "T5-read" | "T5-helper-read");
                let refused = scenario.name == "T4-ambient-no-rescue";
                let requests = if dns || handshake || refused { 0 } else { scenario.connections };
                require(facts.schema_version == 1 && facts.scope == "github-tls-peer-v1" && facts.case_name == scenario.name
                    && facts.state == "finished" && facts.status == "passed" && facts.code.is_none() && facts.all_sockets_closed
                    && facts.connections == scenario.connections && facts.sni == scenario.connections
                    && facts.handshakes == requests && facts.requests == requests && facts.tls_refused == refused
                    && facts.decrypted_bytes <= facts.connections * 8192
                    && facts.auth_bytes == requests * b"Bearer INERT_NOT_A_CREDENTIAL".len() as u64
                    && facts.decrypted_bytes >= facts.auth_bytes && facts.close_notify == (if read || handshake || refused || dns { 0 } else { 4 })
                    && facts.phase == (if dns { "dns" } else if handshake { "handshake" } else if read { "read" } else { "ambient" }),
                    "tls_deadline_peer_facts")?;
                require(completion.bytes == 1 && completion.eof && completion.closed && completion.primary_empty
                    && completion.primary_unexpected == 0 && completion.primary_closed
                    && (if scenario.name.starts_with("T4-") { completion.proxy.as_ref().is_some_and(|sink| sink.empty && sink.unexpected == 0 && sink.closed) }
                        else { completion.proxy.is_none() })
                    && completion.dns_empty == (if dns { Some(true) } else { None })
                    && completion.dns_closed == (if dns { Some(true) } else { None }), "tls_deadline_peer_horizon")?;
                require(facts.wire_read_bytes.len() == facts.connections as usize && facts.wire_write_bytes.len() == facts.connections as usize
                    && facts.reply_bytes.len() == facts.connections as usize
                    && facts.wire_read_bytes.iter().all(|bytes| (1..=128 * 1024).contains(bytes))
                    && facts.wire_write_bytes.iter().all(|bytes| if handshake { *bytes == 0 } else { (1..=128 * 1024).contains(bytes) })
                    && facts.reply_bytes.iter().all(|bytes| if refused || handshake { *bytes == 0 } else { (1..=64 * 1024).contains(bytes) }),
                    "tls_deadline_peer_wire")?;
                require((if handshake { (1..=128 * 1024).contains(&facts.withheld_wire_bytes) } else { facts.withheld_wire_bytes == 0 })
                    && facts.incomplete_body == read && (if read { (1..=14).contains(&facts.body_bytes) } else { facts.body_bytes == 0 }),
                    "tls_deadline_withheld_phase")?;
                require((if read || handshake { client_stop(facts.client_stop.as_deref(), handshake) } else { facts.client_stop.is_none() })
                    && facts.dns_replies == 0 && facts.dns_a <= 8 && facts.dns_aaaa <= 8 && facts.dns_a + facts.dns_aaaa == facts.dns_questions
                    && (if dns { (1..=8).contains(&facts.dns_questions) } else { facts.dns_questions == 0 })
                    && facts.progress_count == self.progress.len() as u64, "tls_deadline_peer_phase_completion")?;
                if refused || handshake || dns { require(facts.decrypted_bytes == 0, "tls_deadline_unexpected_http")?; }
                let mut body = 0;
                let mut questions = 0;
                let mut a = 0;
                let mut aaaa = 0;
                let mut bytes_read = 0;
                let mut bytes_written = 0;
                let mut phase_seen = false;
                let mut stopped = false;
                for (item, _) in &self.progress {
                    require(!stopped && item.wire_read_bytes >= bytes_read && item.wire_write_bytes >= bytes_written
                        && item.wire_read_bytes <= facts.wire_read_bytes.iter().sum::<u64>()
                        && item.wire_write_bytes <= facts.wire_write_bytes.iter().sum::<u64>(), "tls_deadline_progress_wire")?;
                    match item.event.as_str() {
                        "dns-question" => {
                            require(dns && item.dns_questions == questions + 1 && item.dns_a <= 8 && item.dns_aaaa <= 8
                                && item.dns_a >= a && item.dns_aaaa >= aaaa
                                && item.dns_a + item.dns_aaaa == item.dns_questions, "tls_deadline_dns_progress")?;
                            questions = item.dns_questions; a = item.dns_a; aaaa = item.dns_aaaa;
                            phase_seen = true;
                        },
                        "client-hello" => {
                            require(handshake && !phase_seen && item.wire_read_bytes > 0 && item.wire_write_bytes == 0,
                                "tls_deadline_hello_progress")?;
                            phase_seen = true;
                        },
                        "first-get" => {
                            require(!dns && !handshake && !refused && !phase_seen && item.requests == 1
                                && item.wire_read_bytes > 0 && item.wire_write_bytes > 0, "tls_deadline_get_progress")?;
                            phase_seen = true;
                        },
                        "body-byte" => {
                            require(read && phase_seen && item.body_bytes == body + 1 && item.body_bytes <= 14
                                && item.wire_write_bytes > bytes_written, "tls_deadline_body_progress")?;
                            body = item.body_bytes;
                        },
                        "client-stop" => {
                            require((read || handshake) && phase_seen && client_stop(item.client_stop.as_deref(), handshake)
                                && item.client_stop == facts.client_stop, "tls_deadline_client_stop")?;
                            stopped = true;
                        },
                        _ => return Err("tls_deadline_progress_event"),
                    }
                    require(item.body_bytes == body && item.requests == (if dns || handshake || refused { 0 } else { 1 })
                        && item.dns_questions == questions && item.dns_a == a && item.dns_aaaa == aaaa
                        && (stopped == item.client_stop.is_some()), "tls_deadline_progress_counters")?;
                    bytes_read = item.wire_read_bytes; bytes_written = item.wire_write_bytes;
                }
                require(phase_seen != refused && stopped == (read || handshake) && body == facts.body_bytes
                    && questions == facts.dns_questions && a == facts.dns_a && aaaa == facts.dns_aaaa,
                    "tls_deadline_progress_terminal_consistency")
            }
            fn first(&self, event: &str) -> Option<Instant> {
                self.progress.iter().find(|(item, _)| item.event == event).map(|(_, at)| *at)
            }
            fn body_times(&self) -> Vec<Instant> {
                self.progress.iter().filter(|(item, _)| item.event == "body-byte").map(|(_, at)| *at).collect()
            }
            fn evidence(&self, origin: Instant) -> Value {
                json!(self.progress.iter().map(|(item, at)| json!({"event":item.event,"sequence":item.sequence,
                    "requests":item.requests,"bodyBytes":item.body_bytes,"wireReadBytes":item.wire_read_bytes,
                    "wireWriteBytes":item.wire_write_bytes,"dnsQuestions":item.dns_questions,"dnsA":item.dns_a,
                    "dnsAAAA":item.dns_aaaa,"clientStop":item.client_stop,"afterPeerStartNs":elapsed(origin, *at)})).collect::<Vec<_>>())
            }
        }

        // Pure predicates consume original observations; they do not control,
        // delay, synthesize or replace the real clocks/readers above.
        fn progressing(get: Instant, until: Instant, body: &[Instant]) -> bool {
            !body.is_empty() && body[0] >= get && body[0] <= get + CADENCE
                && body.windows(2).all(|pair| pair[1] > pair[0] && pair[1] <= pair[0] + CADENCE)
                && body.iter().all(|at| *at <= until + CADENCE)
                && body.iter().copied().filter(|at| *at <= until).last().is_some_and(|last| until <= last + CADENCE)
        }
        fn helper_window(launch: Instant, get: Instant, frame: Instant, stop: Instant, body: &[Instant]) -> bool {
            get >= launch && get <= launch + GET_LATEST && frame >= launch + HELPER_EARLIEST
                && frame <= launch + HELPER_LATEST && stop >= launch + HELPER_EARLIEST
                && progressing(get, frame.min(stop), body)
        }
        fn owner_window(endpoint: Instant, cleanup: Option<Instant>, settled: Instant, phase: Instant) -> bool {
            phase < endpoint && cleanup == Some(endpoint + CLEANUP_TIME)
                && settled >= endpoint && settled < endpoint + CLEANUP_TIME
        }

        const CACHE_PATHS: &[&str] = &["/run/nscd/socket", "/var/run/nscd/socket", "/run/.nscd_socket", "/var/run/.nscd_socket"];
        const CONFIGS: &[(&str, &str, &[u8])] = &[
            ("hosts", "hosts", b"127.0.0.1 api.github.com localhost\n::1 localhost\n"),
            ("hosts", "resolv.conf", b"# Synthetic namespace: DNS is disabled by hosts: files.\nnameserver 127.0.0.1\noptions timeout:1 attempts:1\n"),
            ("hosts", "nsswitch.conf", b"passwd: files\ngroup: files\nhosts: files\n"),
            ("dns-withhold", "hosts", b"127.0.0.1 localhost\n::1 localhost\n"),
            ("dns-withhold", "resolv.conf", b"nameserver 127.0.0.1\noptions timeout:15 attempts:1 ndots:1\n"),
            ("dns-withhold", "nsswitch.conf", b"passwd: files\ngroup: files\nhosts: dns\n"),
        ];
        fn caches_absent() -> bool { CACHE_PATHS.iter().all(|pathname| absent(Path::new(pathname))) }
        fn host_configuration(bytes: &[u8], host_conf: bool) -> bool {
            if bytes.len() > 16 * 1024 || bytes.contains(&0) { return false; }
            let Ok(text) = std::str::from_utf8(bytes) else { return false; };
            let mut seen = BTreeSet::new();
            let mut count = 0;
            for line in text.split('\n') {
                count += 1;
                if count > 128 || line.len() > 512 { return false; }
                let active = line.split('#').next().unwrap_or("").trim_matches([' ', '\t', '\r']);
                if !active.is_empty() && (!host_conf || !matches!(active, "order hosts,bind" | "multi on") || !seen.insert(active)) {
                    return false;
                }
            }
            true
        }
        fn proc_bytes(pathname: &'static str, limit: usize) -> Check<Vec<u8>> {
            require(matches!(pathname, "/proc/self/maps" | "/proc/self/status"), "tls_proc_role")?;
            let flags = rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK | rustix::fs::OFlags::CLOEXEC;
            let mut original = fs::OpenOptions::new().read(true).custom_flags(flags.bits() as i32).open(pathname)
                .map_err(|_| "tls_proc_open")?;
            let mut bytes = Vec::new();
            let result = Read::by_ref(&mut original).take(limit as u64 + 1).read_to_end(&mut bytes);
            let closed = nix::unistd::close(original).is_ok(); // One close on success OR read failure.
            require(closed, "tls_proc_close_unknown")?;
            require(result.is_ok() && !bytes.is_empty() && bytes.len() <= limit, "tls_proc_read")?;
            Ok(bytes)
        }
        #[derive(Debug, PartialEq)]
        struct MapRow<'a> { major: u64, minor: u64, inode: u64, remainder: &'a str }
        fn map_row(line: &str) -> Check<MapRow<'_>> {
            require(!line.is_empty() && line.len() <= 512 * 1024
                && !line.bytes().any(|byte| matches!(byte, 0 | b'\n')), "tls_libc_maps")?;
            let mut rest = line;
            let mut columns = [""; 5];
            for column in &mut columns {
                rest = rest.trim_start_matches([' ', '\t']);
                let end = rest.find([' ', '\t']).unwrap_or(rest.len());
                require(end > 0, "tls_libc_maps")?;
                *column = &rest[..end];
                rest = &rest[end..];
            }
            let hexadecimal = |value: &str, code: &'static str| -> Check<u64> {
                require(!value.is_empty() && value.len() <= 16 && value.bytes().all(|byte| byte.is_ascii_hexdigit()), code)?;
                u64::from_str_radix(value, 16).map_err(|_| code)
            };
            let (start, end) = columns[0].split_once('-').ok_or("tls_libc_maps")?;
            require(hexadecimal(start, "tls_libc_maps")? < hexadecimal(end, "tls_libc_maps")?, "tls_libc_maps")?;
            let permissions = columns[1].as_bytes();
            require(permissions.len() == 4 && matches!(permissions[0], b'r' | b'-')
                && matches!(permissions[1], b'w' | b'-') && matches!(permissions[2], b'x' | b'-')
                && matches!(permissions[3], b'p' | b's'), "tls_libc_maps")?;
            let _ = hexadecimal(columns[2], "tls_libc_maps")?;
            let (major, minor) = columns[3].split_once(':').ok_or("tls_libc_map_device")?;
            let major = hexadecimal(major, "tls_libc_map_device")?;
            let minor = hexadecimal(minor, "tls_libc_map_device")?;
            require(!columns[4].is_empty() && columns[4].len() <= 20
                && columns[4].bytes().all(|byte| byte.is_ascii_digit()), "tls_libc_map_inode")?;
            let inode = columns[4].parse::<u64>().map_err(|_| "tls_libc_map_inode")?;
            // Linux has five columns followed by an opaque label/pathname, NOT
            // six whitespace tokens. Preserve trailing bytes of that remainder.
            Ok(MapRow { major, minor, inode, remainder: rest.trim_start_matches([' ', '\t']) })
        }
        fn mapped_libc_path<'a>(row: &MapRow<'a>) -> Check<Option<&'a Path>> {
            if !row.remainder.starts_with('/') { return Ok(None); }
            let (spelling, deleted) = row.remainder.strip_suffix(" (deleted)")
                .map_or((row.remainder, false), |name| (name, true));
            let mapped = Path::new(spelling);
            let name = mapped.file_name().and_then(|name| name.to_str()).ok_or("tls_libc_maps")?;
            // Deleted modules remain modules: the suffix must not hide NSS or
            // a stale libc from the same policy that rejects their live names.
            require(!name.starts_with("libnss_"), "tls_dynamic_nss_unsupported")?;
            if name != "libc.so.6" && !name.starts_with("libc-") { return Ok(None); }
            require(!deleted, "tls_libc_backing_file")?;
            Ok(Some(mapped))
        }
        fn mapped_libc(manifest: &Manifest) -> Check<()> {
            let libc = manifest.role("libc")?;
            let record = manifest.record(libc)?;
            path(libc)?;
            let metadata = fs::symlink_metadata(libc).map_err(|_| "tls_libc_metadata")?;
            require(metadata.is_file() && metadata.uid() == 0 && metadata.gid() == 0 && metadata.nlink() == 1
                && metadata.mode() & 0o7022 == 0 && file_hash(libc, record.size)? == record.sha256, "tls_libc_backing_file")?;
            let bytes = proc_bytes("/proc/self/maps", 512 * 1024)?;
            let text = std::str::from_utf8(&bytes).map_err(|_| "tls_libc_maps")?;
            let mut identities = BTreeSet::new();
            let mut segments = 0usize;
            require(text.ends_with('\n'), "tls_libc_maps")?;
            for line in text.split_terminator('\n') {
                let row = map_row(line)?;
                let Some(mapped) = mapped_libc_path(&row)? else { continue; };
                segments += 1;
                require(segments <= 16, "tls_libc_map_limit")?;
                let mapped = mapped.canonicalize().map_err(|_| "tls_libc_backing_file")?;
                let MapRow { major, minor, inode, .. } = row;
                require(mapped == libc && inode == metadata.ino() && major == nix::sys::stat::major(metadata.dev())
                    && minor == nix::sys::stat::minor(metadata.dev()), "tls_libc_original_mapping")?;
                identities.insert((major, minor, inode, mapped));
            }
            // Multiple normal ELF segment VMAs are one backing object. This is
            // equality to the very libc genuinely version-probed by the selected
            // Python collector, NOT a second native Rust glibc-version probe.
            require(segments > 0 && identities.len() == 1
                && stamp(&fs::symlink_metadata(libc).map_err(|_| "tls_libc_metadata")?) == stamp(&metadata), "tls_libc_original_mapping")
        }
        fn resolver_runtime(manifest: &Manifest) -> Check<()> {
            require(manifest.resolver.as_ref().is_some_and(|resolver| resolver.family == "glibc"
                && resolver.version == "2.39" && resolver.nss == "builtin-files-dns"), "tls_resolver_profile")?;
            mapped_libc(manifest)?;
            for (role, pathname, host_conf) in [("resolver:host.conf", "/etc/host.conf", true), ("resolver:gai.conf", "/etc/gai.conf", false)] {
                let pathname = Path::new(pathname);
                require(manifest.role(role)? == pathname, "tls_resolver_config_role")?;
                let metadata = fs::symlink_metadata(pathname).map_err(|_| "tls_resolver_config_metadata")?;
                let record = manifest.record(pathname)?;
                let bytes = read(pathname, 16 * 1024)?;
                require(metadata.is_file() && metadata.uid() == 0 && metadata.gid() == 0 && metadata.nlink() == 1
                    && metadata.mode() & 0o7022 == 0 && record.size == bytes.len() as u64 && record.sha256 == hash(&bytes)
                    && host_configuration(&bytes, host_conf), "tls_resolver_config_not_supported")?;
            }
            require(caches_absent(), "tls_resolver_cache_present")
        }
        fn parent_environment(manifest: &Manifest, profile: &'static str) -> Check<()> {
            let mut expected = BTreeMap::new();
            for (key, value) in [("LANG", "C"), ("LC_ALL", "C"), ("MRK_DESKTOP_HOSTED_CHECKS", "github-readonly-tls-deadline-v1"),
                ("GITHUB_ACTIONS", "true"), ("RUNNER_ENVIRONMENT", "github-hosted"),
                ("GITHUB_REF", "refs/heads/verify/desktop-github-connection-tls"), ("MRK_GITHUB_TLS_PROFILE", profile)] {
                expected.insert(key.to_owned(), value.to_owned());
            }
            for (key, value) in [("GITHUB_SHA", manifest.source_sha.clone()), ("GITHUB_RUN_ID", manifest.run_id.clone()),
                ("GITHUB_RUN_ATTEMPT", manifest.attempt.clone()), ("MRK_TLS_ORIGINAL_UID", manifest.uid.to_string()),
                ("MRK_TLS_ORIGINAL_GID", manifest.gid.to_string()), ("MRK_TLS_PARENT_NETNS", manifest.parent_netns.clone()),
                ("MRK_TLS_PARENT_MNTNS", manifest.parent_mntns.clone())] { expected.insert(key.to_owned(), value); }
            for key in ["MRK_TLS_NETNS", "MRK_TLS_MNTNS", "MRK_GITHUB_TLS_ARTIFACT", "MRK_GITHUB_TLS_ARTIFACT_SHA256", "MRK_GITHUB_TLS_ARTIFACT_BYTES"] {
                // Independently checked by Admitted immediately after this
                // closed-role-set check, not accepted as arbitrary values.
                expected.insert(key.to_owned(), environment(key)?);
            }
            for (key, pathname) in [("MRK_DESKTOP_TEST_ROOT", manifest.job_root.join("github-tls-deadline")),
                ("MRK_DESKTOP_TEST_CORE_ZIP", manifest.core_zip.clone()), ("MRK_DESKTOP_DEV_CORE", manifest.core_source.clone()),
                ("MRK_DESKTOP_DEV_PYTHON", manifest.python.clone()), ("MRK_GITHUB_TLS_INPUTS", manifest.job_root.join("github-tls-deadline-inputs.json"))] {
                expected.insert(key.to_owned(), pathname.to_str().ok_or("tls_parent_environment_path")?.to_owned());
            }
            if profile == "hosts" {
                let root = manifest.job_root.join("github-tls-deadline-ambient");
                expected.extend(ambient_values(manifest.role("other-root-ca.pem")?, &root, &root.join("owner-clear.keylog"))?);
            }
            let actual = std::env::vars_os().map(|(key, value)| Ok((key.into_string().map_err(|_| "tls_parent_environment")?,
                value.into_string().map_err(|_| "tls_parent_environment")?))).collect::<Check<BTreeMap<_, _>>>()?;
            require(actual == expected, "tls_parent_environment")
        }
        fn privilege_status(status: &str) -> Check<()> {
            require(!status.is_empty() && status.len() <= 64 * 1024 && status.ends_with('\n')
                && !status.bytes().any(|byte| matches!(byte, 0 | b'\r')), "tls_deadline_privilege_status")?;
            for (name, expected, code) in [
                ("CapInh:", "0000000000000000", "tls_deadline_privilege_inheritable"),
                ("CapPrm:", "0000000000000000", "tls_deadline_privilege_permitted"),
                ("CapEff:", "0000000000000000", "tls_deadline_privilege_effective"),
                ("CapBnd:", "0000000000000000", "tls_deadline_privilege_bounding"),
                ("CapAmb:", "0000000000000000", "tls_deadline_privilege_ambient"),
                ("NoNewPrivs:", "1", "tls_deadline_privilege_nonewprivs"),
                ("Groups:", "", "tls_deadline_privilege_groups"),
            ] {
                let mut rows = status.split_terminator('\n').filter_map(|line| line.strip_prefix(name));
                let value = rows.next().ok_or(code)?;
                require(rows.next().is_none(), code)?;
                let admitted = if name == "Groups:" {
                    // Empty membership can include kernel horizontal padding.
                    // Never trim Unicode whitespace or accept any numeric group.
                    value.strip_prefix('\t').is_some_and(|suffix| suffix.bytes().all(|byte| matches!(byte, b' ' | b'\t')))
                } else {
                    // Capabilities and no-new-privs retain their exact values.
                    value.strip_prefix('\t') == Some(expected)
                };
                require(admitted, code)?;
            }
            Ok(())
        }
        pub(super) fn admit_resolver(manifest: &Manifest, profile: &'static str) -> Check<()> {
            require(matches!(profile, "hosts" | "dns-withhold") && environment("MRK_GITHUB_TLS_PROFILE")? == profile
                && PathBuf::from(environment("MRK_DESKTOP_TEST_ROOT")?) == manifest.job_root.join("github-tls-deadline"),
                "tls_deadline_profile_layout")?;
            for &(fixed_profile, name, expected) in CONFIGS {
                let role = format!("{fixed_profile}:{name}");
                let pathname = manifest.job_root.join(format!("github-tls-deadline-namespace-{fixed_profile}")).join(name);
                require(manifest.role(&role)? == pathname && read(&pathname, 16 * 1024)?.as_slice() == expected,
                    "tls_deadline_fixed_resolver_bytes")?;
            }
            parent_environment(manifest, profile)?;
            require(rustix::process::getuid().as_raw() == manifest.uid && rustix::process::geteuid().as_raw() == manifest.uid
                && rustix::process::getgid().as_raw() == manifest.gid && rustix::process::getegid().as_raw() == manifest.gid,
                "tls_deadline_original_identity")?;
            let status = proc_bytes("/proc/self/status", 64 * 1024)?;
            let status = std::str::from_utf8(&status).map_err(|_| "tls_deadline_privilege_status")?;
            privilege_status(status)?;
            resolver_runtime(manifest)
        }

        fn absent(pathname: &Path) -> bool {
            matches!(fs::symlink_metadata(pathname), Err(error) if error.kind() == std::io::ErrorKind::NotFound)
        }
        fn owned_directory(pathname: &Path, uid: u32, gid: u32) -> Check<()> {
            path(pathname)?;
            let metadata = fs::symlink_metadata(pathname).map_err(|_| "tls_ambient_directory")?;
            require(metadata.is_dir() && metadata.uid() == uid && metadata.gid() == gid
                && metadata.mode() & 0o7022 == 0, "tls_ambient_directory")
        }
        fn nonzero_file_limit() -> bool {
            let limit = rustix::process::getrlimit(rustix::process::Resource::Fsize);
            limit.current.zip(limit.maximum).is_some_and(|(soft, hard)| soft > 0 && soft <= hard && hard <= 1024 * 1024)
        }
        fn probe_spawn_admission(now: Instant, endpoint: Instant, file_limit: bool) -> Check<()> {
            require(now + CLIENT_RESERVE <= endpoint, "tls_probe_spawn_deadline")?;
            require(file_limit, "tls_probe_spawn_file_limit")
        }
        fn ambient_values(ca: &Path, root: &Path, keylog: &Path) -> Check<BTreeMap<String, String>> {
            let mut environment = BTreeMap::new();
            for key in ["HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"] {
                environment.insert(key.to_owned(), "http://127.0.0.1:18888".to_owned());
            }
            for (key, value) in [("LANG", "C"), ("LC_ALL", "C"), ("NO_PROXY", ""), ("no_proxy", "")] {
                environment.insert(key.to_owned(), value.to_owned());
            }
            let empty_ca = root.join("empty-ca-dir");
            for (key, pathname) in [("SSL_CERT_FILE", ca), ("SSL_CERT_DIR", empty_ca.as_path()), ("SSLKEYLOGFILE", keylog)] {
                environment.insert(key.to_owned(), pathname.to_str().ok_or("tls_ambient_path")?.to_owned());
            }
            Ok(environment)
        }
        struct Ambient {
            root: PathBuf, empty_ca: PathBuf, keylog: PathBuf, control: PathBuf,
            uid: u32, gid: u32, environment: BTreeMap<String, String>, role_hash: String,
            created: bool, written: bool, synced: bool, close_claimed: bool, closed: bool,
            keylog_before: bool, keylog_after: bool, empty_before: bool, empty_after: bool, file_limit: bool,
        }
        impl Ambient {
            fn new(common: &Common, case: &Case) -> Check<Self> {
                let owner = case.name == "T4-owner-clear";
                require(owner || direct(case.name), "tls_ambient_case")?;
                let root = if owner { common.manifest.job_root.join("github-tls-deadline-ambient") }
                    else { case.root.join("ambient") };
                let empty_ca = root.join("empty-ca-dir");
                let keylog = root.join(if owner { "owner-clear.keylog" } else { "client.keylog" });
                let ca = common.manifest.role(if case.name == "T4-ambient-no-rescue" { "root-ca.pem" } else { "other-root-ca.pem" })?;
                let environment = ambient_values(ca, &root, &keylog)?;
                let role_hash = hash(&serde_json::to_vec(&environment).map_err(|_| "tls_ambient_encoding")?);
                Ok(Self { control: root.join("write-control"), root, empty_ca, keylog, uid: common.manifest.uid, gid: common.manifest.gid,
                    environment, role_hash, created: false, written: false, synced: false, close_claimed: false, closed: false,
                    keylog_before: false, keylog_after: false, empty_before: false, empty_after: false, file_limit: false })
            }
            fn empty(&self) -> bool {
                owned_directory(&self.empty_ca, self.uid, self.gid).is_ok()
                    && fs::read_dir(&self.empty_ca).is_ok_and(|mut entries| entries.next().is_none())
            }
            fn prepare(&mut self, create: bool) -> Check<()> {
                if create {
                    fs::create_dir(&self.root).and_then(|_| fs::create_dir(&self.empty_ca)).map_err(|_| "tls_ambient_not_fresh")?;
                }
                owned_directory(&self.root, self.uid, self.gid)?;
                self.empty_before = self.empty();
                self.keylog_before = absent(&self.keylog);
                self.file_limit = nonzero_file_limit();
                require(self.empty_before && self.keylog_before && self.file_limit
                    && rustix::process::getuid().as_raw() == self.uid && rustix::process::geteuid().as_raw() == self.uid
                    && rustix::process::getgid().as_raw() == self.gid && rustix::process::getegid().as_raw() == self.gid,
                    "tls_ambient_control_admission")?;
                let flags = rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK | rustix::fs::OFlags::CLOEXEC;
                let mut original = fs::OpenOptions::new().write(true).create_new(true).mode(0o600)
                    .custom_flags(flags.bits() as i32).open(&self.control).map_err(|_| "tls_ambient_control_create")?;
                self.created = true;
                let identity = original.metadata().is_ok_and(|metadata| metadata.is_file() && metadata.uid() == self.uid
                    && metadata.gid() == self.gid && metadata.nlink() == 1 && metadata.mode() & 0o7777 == 0o600);
                if identity { self.written = original.write_all(b"w").is_ok(); }
                self.synced = original.sync_all().is_ok();
                self.close_claimed = true;
                self.closed = nix::unistd::close(original).is_ok(); // Sole original close, even after a write/sync failure.
                require(identity && self.written && self.synced && self.closed, "tls_ambient_control_write_close")
            }
            fn after(&mut self) -> Check<()> {
                owned_directory(&self.root, self.uid, self.gid)?;
                self.keylog_after = absent(&self.keylog);
                self.empty_after = self.empty();
                require(self.keylog_after && self.empty_after && self.created && self.written && self.synced && self.closed
                    && nonzero_file_limit() && read(&self.control, 1)?.as_slice() == b"w", "tls_ambient_postcondition")?;
                let mut names = BTreeSet::new();
                for entry in fs::read_dir(&self.root).map_err(|_| "tls_ambient_postcondition")? {
                    let entry = entry.map_err(|_| "tls_ambient_postcondition")?;
                    require(names.len() < 2 && names.insert(entry.file_name()), "tls_ambient_extra_output")?;
                }
                require(names == [std::ffi::OsString::from("empty-ca-dir"), std::ffi::OsString::from("write-control")]
                    .into_iter().collect(), "tls_ambient_extra_output")
            }
            fn settled(&self) -> bool { !self.created || self.close_claimed && self.closed }
            fn evidence(&self, initial: Option<&str>) -> Value {
                json!({"roleSetSha256":self.role_hash,"writableControlCreated":self.created,"writableControlWritten":self.written,
                    "writableControlSynced":self.synced,"writableControlClosed":self.closed,"keylogAbsentBefore":self.keylog_before,
                    "keylogAbsentAfter":self.keylog_after,"emptyCaDirectoryBefore":self.empty_before,"emptyCaDirectoryAfter":self.empty_after,
                    "fileSizeLimitNonzero":self.file_limit,"initialEnvironment":initial})
            }
        }

        #[derive(Default)]
        struct ProbeInput { stdin: Option<tokio::process::ChildStdin>, request: Option<Vec<u8>> }
        #[derive(Default)]
        struct ProbeWrite { complete: bool, shutdown: bool, released: bool }
        struct ProbeRead { output: ReadEnd, frame: Option<Instant> }
        async fn probe_writer(original: Arc<AsyncMutex<ProbeInput>>, endpoint: Instant) -> ProbeWrite {
            let mut original = original.lock().await;
            let mut end = ProbeWrite::default();
            let ProbeInput { stdin, request } = &mut *original;
            if let (Some(stdin), Some(bytes)) = (stdin.as_mut(), request.as_ref()) {
                if Instant::now() < endpoint {
                    end.complete = matches!(guarded(tokio::time::timeout_at(tokio::time::Instant::from_std(endpoint),
                        stdin.write_all(bytes))).await, Ok(Ok(Ok(()))));
                }
            }
            // Attempt the same original shutdown independently after a failed
            // write/unwind. Never duplicate a pipe or renew the resource clock.
            if let Some(stdin) = original.stdin.as_mut() {
                end.shutdown = matches!(guarded(tokio::time::timeout_at(tokio::time::Instant::from_std(endpoint),
                    stdin.shutdown())).await, Ok(Ok(Ok(()))));
            }
            if end.shutdown { drop(original.stdin.take()); end.released = true; }
            if let Some(bytes) = original.request.as_mut() { bytes.fill(0); }
            original.request.take();
            end
        }
        async fn probe_stdout<R: AsyncRead + Unpin>(reader: &mut R) -> ProbeRead {
            let mut bytes = Vec::new();
            let mut overflow = false;
            let mut frame = None;
            let mut buffer = [0u8; 8192];
            loop {
                match reader.read(&mut buffer).await {
                    Ok(0) => return ProbeRead { output: ReadEnd { bytes, eof: true, overflow }, frame },
                    Ok(length) => {
                        // F is captured here, in the original normally driven
                        // response read, even if later parsing/wait is delayed.
                        let at = Instant::now();
                        let keep = length.min(github_protocol::RESPONSE_LIMIT.saturating_sub(bytes.len()));
                        bytes.extend_from_slice(&buffer[..keep]);
                        overflow |= keep != length;
                        if frame.is_none() && buffer[..keep].contains(&b'\n') { frame = Some(at); }
                    },
                    Err(_) => return ProbeRead { output: ReadEnd { bytes, eof: false, overflow }, frame },
                }
            }
        }
        #[derive(Default)]
        struct Probe {
            endpoint: Option<Instant>, launch: Option<Instant>, completed_at: Option<Instant>,
            acquisition: Option<JoinHandle<Check<(Child, Instant)>>>, acquisition_joined: bool, acquisition_failed: bool, spawn_refused: bool,
            child: Option<Child>, spawned: bool, pipes_retained: bool,
            input: Arc<AsyncMutex<ProbeInput>>, stdout_original: Arc<AsyncMutex<Option<tokio::process::ChildStdout>>>,
            stderr_original: Arc<AsyncMutex<Option<tokio::process::ChildStderr>>>,
            writer: Option<JoinHandle<ProbeWrite>>, stdout: Option<JoinHandle<ProbeRead>>, stderr: Option<JoinHandle<ReadEnd>>,
            writer_started: bool, stdout_started: bool, stderr_started: bool,
            writer_joined: bool, stdout_joined: bool, stderr_joined: bool,
            writer_failed: bool, stdout_failed: bool, stderr_failed: bool,
            write: Option<ProbeWrite>, out: Option<ProbeRead>, err: Option<ReadEnd>,
            waited: Option<ExitStatus>, wait_failed: bool, stop_attempted: bool, expired: bool, settled: bool,
        }
        enum ProbeEvent {
            Wait(std::io::Result<ExitStatus>), Write(Result<ProbeWrite, tokio::task::JoinError>),
            Out(Result<ProbeRead, tokio::task::JoinError>), Err(Result<ReadEnd, tokio::task::JoinError>), Deadline,
        }
        impl Probe {
            fn begin(&mut self, selection: GitHubTlsRuntime, config: RuntimeConfig, name: &'static str,
                environment: BTreeMap<String, String>, endpoint: Instant) -> Check<()> {
                require(direct(name) && self.endpoint.is_none() && Instant::now() + CLIENT_RESERVE <= endpoint
                    && nonzero_file_limit(), "tls_probe_admission")?;
                let bytes = github_protocol::encode_private_request(DIRECT_ID, "owner/app", None, None, TOKEN)
                    .map_err(|_| "tls_probe_request")?;
                self.input.try_lock().map_err(|_| "tls_probe_input_busy")?.request = Some(bytes);
                self.endpoint = Some(endpoint); // The peer's original acquisition-inclusive clock, not a new 16s.
                self.acquisition = Some(tokio::task::spawn_blocking(move || {
                    // Resolve the genuine admitted runtime. Constructing an
                    // unchecked VerifiedRuntime would bypass the source/CA/
                    // runtime inventory and is intentionally not available.
                    let runtime = config.resolve_github_tls_fixture(endpoint, &selection).map_err(|_| "tls_probe_runtime")?;
                    let mut command = Command::new(&runtime.python);
                    command.args(["-I", "-S", "-B"]).arg(&runtime.bootstrap).arg(&runtime.core)
                        .current_dir(&runtime.cwd).env_clear().envs(environment)
                        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).kill_on_drop(false);
                    probe_spawn_admission(Instant::now(), endpoint, nonzero_file_limit())?;
                    let launch = Instant::now(); // L, immediately before THIS actual original spawn call.
                    command.spawn().map(|child| (child, launch)).map_err(|_| "tls_probe_spawn_refused")
                }));
                Ok(())
            }
            fn retain_pipes(&mut self) -> Check<()> {
                if self.pipes_retained { return Ok(()); }
                let mut input = self.input.try_lock().map_err(|_| "tls_probe_input_busy")?;
                let mut out = self.stdout_original.try_lock().map_err(|_| "tls_probe_output_busy")?;
                let mut err = self.stderr_original.try_lock().map_err(|_| "tls_probe_output_busy")?;
                let child = self.child.as_mut().ok_or("tls_probe_child_missing")?;
                require(input.stdin.is_none() && out.is_none() && err.is_none(), "tls_probe_pipe_replacement")?;
                input.stdin = child.stdin.take();
                *out = child.stdout.take();
                *err = child.stderr.take();
                self.pipes_retained = true; // No await/fallible step between taking/storing originals.
                Ok(())
            }
            fn start_writer(&mut self) -> Check<()> {
                if self.writer_started { return require(self.writer.is_some() || self.writer_joined, "tls_probe_writer_missing"); }
                self.writer_started = true;
                require(self.input.try_lock().is_ok_and(|input| input.stdin.is_some() && input.request.is_some()), "tls_probe_input_missing")?;
                let endpoint = self.endpoint.ok_or("tls_probe_not_started")?;
                self.writer = Some(tokio::spawn(probe_writer(self.input.clone(), endpoint)));
                Ok(())
            }
            fn start_stdout(&mut self) -> Check<()> {
                if self.stdout_started { return require(self.stdout.is_some() || self.stdout_joined, "tls_probe_stdout_missing"); }
                self.stdout_started = true;
                require(self.stdout_original.try_lock().is_ok_and(|original| original.is_some()), "tls_probe_stdout_missing")?;
                let original = self.stdout_original.clone();
                self.stdout = Some(tokio::spawn(async move {
                    let mut original = original.lock().await;
                    let Some(stdout) = original.as_mut() else {
                        return ProbeRead { output: ReadEnd { bytes: Vec::new(), eof: false, overflow: false }, frame: None };
                    };
                    let result = probe_stdout(stdout).await;
                    if result.output.eof { drop(original.take()); }
                    result
                }));
                Ok(())
            }
            fn start_stderr(&mut self) -> Check<()> {
                if self.stderr_started { return require(self.stderr.is_some() || self.stderr_joined, "tls_probe_stderr_missing"); }
                self.stderr_started = true;
                require(self.stderr_original.try_lock().is_ok_and(|original| original.is_some()), "tls_probe_stderr_missing")?;
                let original = self.stderr_original.clone();
                let (faults, _receiver) = mpsc::channel(2);
                self.stderr = Some(tokio::spawn(async move {
                    let mut original = original.lock().await;
                    let Some(stderr) = original.as_mut() else { return ReadEnd { bytes: Vec::new(), eof: false, overflow: false }; };
                    let result = read_bounded(stderr, protocol::STDERR_LIMIT, faults).await;
                    if result.eof { drop(original.take()); }
                    result
                }));
                Ok(())
            }
            async fn prepare_pipes(&mut self) -> Check<()> {
                let kept = guarded(async { self.retain_pipes() }).await.unwrap_or_else(Err);
                let writer = guarded(async { self.start_writer() }).await.unwrap_or_else(Err);
                let out = guarded(async { self.start_stdout() }).await.unwrap_or_else(Err);
                let err = guarded(async { self.start_stderr() }).await.unwrap_or_else(Err);
                if writer.is_err() { self.writer_failed = true; }
                if out.is_err() { self.stdout_failed = true; }
                if err.is_err() { self.stderr_failed = true; }
                kept.and(writer).and(out).and(err)
            }
            async fn acquire(&mut self) -> Check<()> {
                require(!self.acquisition_failed, "tls_probe_acquisition_unknown")?;
                let endpoint = self.endpoint.ok_or("tls_probe_not_started")?;
                if !self.acquisition_joined {
                    let task = self.acquisition.as_mut().ok_or("tls_probe_acquisition_missing")?;
                    let result = match tokio::time::timeout_at(tokio::time::Instant::from_std(endpoint), task).await {
                        Ok(result) => result,
                        Err(_) => { self.expired = true; return Err("tls_probe_acquisition_deadline"); },
                    };
                    let result = match result {
                        Ok(result) => { self.acquisition_joined = true; self.acquisition.take(); result },
                        Err(_) => { self.acquisition_failed = true; return Err("tls_probe_acquisition_unknown"); },
                    };
                    match result {
                        Ok((child, launch)) => { self.child = Some(child); self.launch = Some(launch); self.spawned = true; },
                        Err(code) => { self.spawn_refused = true; return Err(code); },
                    }
                }
                require(self.spawned, "tls_probe_spawn_refused")?;
                self.prepare_pipes().await?;
                require(Instant::now() < endpoint, "tls_probe_acquisition_deadline")
            }
            fn stop_original(&mut self) {
                if self.stop_attempted || self.waited.is_some() || self.wait_failed { return; }
                let Some(child) = self.child.as_mut() else { return; };
                match child.try_wait() {
                    Ok(Some(status)) => self.waited = Some(status),
                    Ok(None) => { self.stop_attempted = true; let _ = child.start_kill(); },
                    Err(_) => self.wait_failed = true,
                }
            }
            async fn settle(&mut self, failed: bool) -> bool {
                if self.settled { return true; }
                let Some(endpoint) = self.endpoint else { self.settled = true; return true; };
                if !self.acquisition_joined && !self.acquisition_failed { let _ = guarded(self.acquire()).await; }
                if self.spawned { let _ = self.prepare_pipes().await; }
                if failed || self.writer_failed || self.stdout_failed || self.stderr_failed { self.stop_original(); }
                loop {
                    let wait_pending = self.child.is_some() && self.waited.is_none() && !self.wait_failed;
                    let writer_pending = self.writer.is_some() && !self.writer_failed;
                    let out_pending = self.stdout.is_some() && !self.stdout_failed;
                    let err_pending = self.stderr.is_some() && !self.stderr_failed;
                    if !wait_pending && !writer_pending && !out_pending && !err_pending {
                        self.completed_at = Some(Instant::now());
                        self.expired |= Instant::now() >= endpoint;
                        self.settled = !self.expired && self.acquisition_joined && !self.acquisition_failed
                            && (self.spawn_refused || self.spawned && self.waited.is_some() && !self.wait_failed
                                && self.writer_joined && self.stdout_joined && self.stderr_joined
                                && !self.writer_failed && !self.stdout_failed && !self.stderr_failed
                                && self.write.as_ref().is_some_and(|end| end.released)
                                && self.out.as_ref().is_some_and(|end| end.output.eof) && self.err.as_ref().is_some_and(|end| end.eof));
                        if self.settled { self.child.take(); }
                        return self.settled;
                    }
                    let event = {
                        let Self { child, writer, stdout, stderr, .. } = self;
                        tokio::select! {
                            result = wait_original(child), if wait_pending => ProbeEvent::Wait(result),
                            result = join_slot(writer), if writer_pending => ProbeEvent::Write(result),
                            result = join_slot(stdout), if out_pending => ProbeEvent::Out(result),
                            result = join_slot(stderr), if err_pending => ProbeEvent::Err(result),
                            _ = tokio::time::sleep_until(tokio::time::Instant::from_std(endpoint)) => ProbeEvent::Deadline,
                        }
                    };
                    match event {
                        ProbeEvent::Wait(Ok(status)) => self.waited = Some(status),
                        ProbeEvent::Wait(Err(_)) => self.wait_failed = true,
                        ProbeEvent::Write(Ok(end)) => {
                            let failed = !end.complete || !end.shutdown || !end.released;
                            self.writer_joined = true; self.writer.take(); self.write = Some(end);
                            if failed { self.stop_original(); }
                        },
                        ProbeEvent::Out(Ok(end)) => {
                            let failed = !end.output.eof || end.output.overflow;
                            self.stdout_joined = true; self.stdout.take(); self.out = Some(end);
                            if failed { self.stop_original(); }
                        },
                        ProbeEvent::Err(Ok(end)) => {
                            let failed = !end.eof || end.overflow;
                            self.stderr_joined = true; self.stderr.take(); self.err = Some(end);
                            if failed { self.stop_original(); }
                        },
                        ProbeEvent::Write(Err(_)) => { self.writer_failed = true; self.stop_original(); },
                        ProbeEvent::Out(Err(_)) => { self.stdout_failed = true; self.stop_original(); },
                        ProbeEvent::Err(Err(_)) => { self.stderr_failed = true; self.stop_original(); },
                        ProbeEvent::Deadline => { self.expired = true; self.stop_original(); return false; },
                    }
                }
            }
            fn outcome(&self) -> Check<GitHubReadOutcome> {
                require(self.settled && self.spawned && !self.stop_attempted && !self.expired
                    && self.waited.as_ref().is_some_and(ExitStatus::success)
                    && self.write.as_ref().is_some_and(|end| end.complete && end.shutdown && end.released), "tls_probe_native_result")?;
                let out = self.out.as_ref().ok_or("tls_probe_response_missing")?;
                let err = self.err.as_ref().ok_or("tls_probe_stderr_missing")?;
                require(out.output.eof && !out.output.overflow && out.frame.is_some() && err.eof && !err.overflow
                    && err.bytes.is_empty(), "tls_probe_output")?;
                github_protocol::decode_private_response(DIRECT_ID, &out.output.bytes).map_err(|_| "tls_probe_response_protocol")
            }
            fn evidence(&self) -> Value {
                json!({"acquisitionJoined":self.acquisition_joined,"spawned":self.spawned,"waited":self.waited.is_some(),
                    "exitCode":self.waited.as_ref().and_then(ExitStatus::code),"exitSuccess":self.waited.as_ref().map(ExitStatus::success),
                    "stopAttempted":self.stop_attempted,"writerJoined":self.writer_joined,
                    "writeComplete":self.write.as_ref().is_some_and(|end| end.complete),"shutdownComplete":self.write.as_ref().is_some_and(|end| end.shutdown),
                    "stdinReleased":self.write.as_ref().is_some_and(|end| end.released),"stdoutJoined":self.stdout_joined,"stderrJoined":self.stderr_joined,
                    "stdoutEof":self.out.as_ref().is_some_and(|end| end.output.eof),"stderrEof":self.err.as_ref().is_some_and(|end| end.eof),
                    "stdoutBytes":self.out.as_ref().map_or(0, |end| end.output.bytes.len()),"stderrBytes":self.err.as_ref().map_or(0, |end| end.bytes.len()),
                    "stdoutOverflow":self.out.as_ref().is_some_and(|end| end.output.overflow),"stderrOverflow":self.err.as_ref().is_some_and(|end| end.overflow),
                    "settled":self.settled,"withinEndpoint":self.settled && !self.expired
                        && self.completed_at.zip(self.endpoint).is_some_and(|(done, endpoint)| done < endpoint),
                    "frameObserved":self.out.as_ref().is_some_and(|end| end.frame.is_some())})
            }
        }

        fn projection(outcome: &GitHubReadOutcome, expected: Reason) -> Check<()> {
            require(outcome.facts.schema_version == 1 && outcome.control.reason == expected
                && outcome.control.credential_expires_at.is_none() && outcome.control.cooldown_seconds.is_none()
                && !outcome.control.cooldown_blocked, "tls_deadline_control_projection")?;
            if expected == Reason::None {
                require(outcome.facts.account.state == FactState::Observed && outcome.facts.account.reason == Reason::None
                    && outcome.facts.account.value.as_ref().is_some_and(|account| account.id == "11" && account.login == "owner")
                    && outcome.facts.repository.state == FactState::Observed && outcome.facts.repository.reason == Reason::None
                    && outcome.facts.repository.value.as_ref().is_some_and(|repository| repository.id == "22" && repository.full_name == "owner/app"
                        && repository.default_branch == "main" && repository.visibility == Visibility::Private && !repository.archived
                        && repository.permissions.pull == Permission::ReportedAllowed && repository.permissions.push == Permission::ReportedDenied
                        && repository.permissions.admin == Permission::ReportedDenied)
                    && outcome.facts.automation.state == FactState::Observed && outcome.facts.automation.reason == Reason::None
                    && outcome.facts.automation.value.as_ref().is_some_and(|automation| automation.coverage == Coverage::Complete
                        && automation.workflows.len() == 4 && automation.workflows.iter().all(|row| row.presence == Presence::NotListed
                            && row.remote_id.is_none() && row.state == WorkflowState::Unknown))
                    && outcome.facts.account.observed_at.is_some() && outcome.facts.account.observed_at == outcome.facts.repository.observed_at
                    && outcome.facts.account.observed_at == outcome.facts.automation.observed_at, "tls_deadline_success_projection")
            } else {
                require(outcome.facts.account.state == FactState::Unavailable && outcome.facts.account.value.is_none()
                    && outcome.facts.account.observed_at.is_none() && outcome.facts.account.reason == expected
                    && outcome.facts.repository.state == FactState::Unavailable && outcome.facts.repository.value.is_none()
                    && outcome.facts.repository.observed_at.is_none() && outcome.facts.repository.reason == expected
                    && outcome.facts.automation.state == FactState::Unavailable && outcome.facts.automation.value.is_none()
                    && outcome.facts.automation.observed_at.is_none() && outcome.facts.automation.reason == expected,
                    "tls_deadline_refusal_projection")
            }
        }
        struct Extra {
            retained: Arc<Retained>, probe: AsyncMutex<Probe>, ambient: Mutex<Option<Ambient>>,
        }
        // Additional originals for exactly the three direct probes. Retained
        // alongside the accepted original peer/product book BEFORE any native
        // acquisition, not stashed after a failed attempt to recover handles.
        static ORIGINALS: Mutex<Option<Arc<Extra>>> = Mutex::new(None);
        struct DeadlineCase {
            base: TlsCase, originals: Arc<Extra>, completion: Option<oneshot::Sender<()>>,
            owner_settled_at: Option<Instant>, timing: Value, progress: Value, cache_after: Option<bool>,
        }
        impl DeadlineCase {
            fn new(admitted: &Admitted, scenario: &'static Scenario) -> Check<Self> {
                require(lock(&ORIGINALS).is_none() && case_name(scenario.name), "tls_deadline_previous_originals")?;
                let base = admitted.case(scenario)?;
                let originals = Arc::new(Extra { retained: base.retained.clone(), probe: AsyncMutex::new(Probe::default()),
                    ambient: Mutex::new(None) });
                *lock(&ORIGINALS) = Some(originals.clone());
                if scenario.name == "T4-owner-clear" || direct(scenario.name) {
                    *lock(&originals.ambient) = Some(Ambient::new(&admitted.common, &base.product)?);
                }
                let (sender, receiver) = oneshot::channel();
                {
                    let mut peer = base.retained.peer.try_lock().map_err(|_| "tls_deadline_peer_busy")?;
                    peer.control = Some(PeerControl::new(receiver));
                    peer.progress = Some(Arc::new(Mutex::new(Arrivals::default())));
                }
                if scenario.name == "T4-owner-clear" {
                    base.product.supervisor.inner.test.github_observe_environment.store(true, Ordering::SeqCst);
                }
                Ok(Self { base, originals, completion: Some(sender), owner_settled_at: None,
                    timing: Value::Null, progress: Value::Null, cache_after: None })
            }
            async fn exercise(&mut self) -> Check<()> {
                let name = self.base.scenario.name;
                if let Some(ambient) = lock(&self.originals.ambient).as_mut() { ambient.prepare(direct(name))?; }
                resolver_runtime(&self.originals.retained.selection.original.common.manifest)?;
                let endpoint = {
                    let mut peer = self.base.retained.peer.lock().await;
                    peer.begin(&self.base.retained.selection.original.common, name)?;
                    peer.readiness(name).await?;
                    peer.endpoint.ok_or("tls_peer_endpoint_missing")?
                };
                require(Instant::now() + CLIENT_RESERVE <= endpoint, "tls_deadline_insufficient_peer_time")?;
                if direct(name) {
                    let environment = lock(&self.originals.ambient).as_ref().ok_or("tls_probe_ambient_missing")?.environment.clone();
                    let mut probe = self.originals.probe.lock().await;
                    probe.begin(self.base.retained.selection.clone(), self.base.product.supervisor.inner.runtime.clone(), name, environment, endpoint)?;
                    probe.acquire().await?;
                    require(probe.settle(false).await, "tls_probe_custody_unresolved")?;
                    projection(&probe.outcome()?, self.base.scenario.reason)?;
                    self.base.result_reason = Some(reason(self.base.scenario.reason));
                } else {
                    {
                        let mut retained = lock(&self.base.retained.ticket);
                        require(retained.is_none(), "tls_ticket_already_admitted")?;
                        let ticket = self.base.product.supervisor.start_github_readonly("owner/app", None, None, TOKEN)
                            .map_err(|_| "tls_product_admission")?;
                        *retained = Some(ticket); // No fallible operation/await between admission and retention.
                    }
                    let receipt = tokio::time::timeout_at(tokio::time::Instant::from_std(endpoint), async {
                        loop {
                            let receipt = lock(&self.base.retained.ticket).as_ref().map(GitHubReadTicket::receipt).ok_or("tls_ticket_missing")?;
                            if !matches!(receipt, GitHubReadReceipt::Pending) { return Ok::<_, &'static str>(receipt); }
                            tokio::time::sleep(Duration::from_millis(5)).await;
                        }
                    }).await.map_err(|_| "tls_product_observation_deadline")??;
                    let GitHubReadReceipt::Settled { outcome, settled_at, was_unknown: false } = receipt
                        else { return Err("tls_deadline_owner_not_settled"); };
                    self.owner_settled_at = Some(settled_at);
                    if owner_deadline(name) {
                        require(outcome.is_err_and(|error| error.code == "query_timeout"), "tls_deadline_owner_timeout_missing")?;
                        self.base.result_reason = Some("query_timeout");
                    } else {
                        let outcome = outcome.map_err(|_| "tls_deadline_owner_outcome")?;
                        projection(&outcome, self.base.scenario.reason)?;
                        self.base.result_reason = Some(reason(self.base.scenario.reason));
                    }
                }
                self.base.projection_checked = true;
                Ok(())
            }
            fn owner_facts(&self) -> Check<()> {
                let name = self.base.scenario.name;
                let owners = self.base.product.supervisor.inner.test.owners();
                require(self.base.product.supervisor.can_exit() && !self.base.product.supervisor.disabled()
                    && self.base.product.supervisor.inner.permits.available_permits() == ACTIVE_LIMIT, "tls_deadline_owner_roster")?;
                if direct(name) {
                    return require(owners.is_empty() && lock(&self.base.retained.ticket).is_none(), "tls_probe_not_an_owner");
                }
                self.base.product.native_facts(true, true)?;
                require(owners.len() == 1, "tls_deadline_owner_roster")?;
                let owner = &owners[0];
                let state = lock(&owner.state);
                let observed = lock(&owner.observation);
                require(matches!(owner.profile, Profile::GitHubReadOnly) && state.terminal && !state.unknown
                    && observed.observer_joined && lock(&owner.permit).is_none(), "tls_deadline_owner_finality")?;
                if owner_deadline(name) {
                    require(state.error.as_ref().is_some_and(|error| error.code == "query_timeout")
                        && observed.exit_success == Some(false) && observed.stdout_bytes == 0 && observed.stderr_bytes == 0,
                        "tls_deadline_owner_first_failure")?;
                } else {
                    require(state.error.is_none() && observed.exit_success == Some(true)
                        && observed.github_initial_environment == Some(true), "tls_owner_initial_environment_not_observed")?;
                }
                Ok(())
            }
            async fn timing(&mut self, frames: &Frames) -> Check<()> {
                let name = self.base.scenario.name;
                let endpoint = self.base.retained.peer.lock().await.endpoint.ok_or("tls_peer_endpoint_missing")?;
                let origin = endpoint.checked_sub(PEER_TIME).ok_or("tls_peer_clock")?;
                self.progress = frames.evidence(origin);
                if direct(name) {
                    let probe = self.originals.probe.lock().await;
                    let launch = probe.launch.ok_or("tls_probe_launch_missing")?;
                    let done = probe.completed_at.ok_or("tls_probe_completion_missing")?;
                    let frame = probe.out.as_ref().and_then(|out| out.frame).ok_or("tls_probe_frame_missing")?;
                    let get = frames.first("first-get");
                    let stop = frames.first("client-stop");
                    let body = frames.body_times();
                    let helper = name == "T5-helper-read";
                    let timing_ok = !helper || get.zip(stop).is_some_and(|(get, stop)| helper_window(launch, get, frame, stop, &body));
                    self.timing = json!({"kind":"fixture-owned-bootstrap","spawnAfterPeerStartNs":elapsed(origin, launch),
                        "settledAfterPeerStartNs":elapsed(origin, done),"firstGetAfterLaunchNs":get.and_then(|get| elapsed(launch, get)),
                        "responseAfterLaunchNs":elapsed(launch, frame),"clientStopAfterLaunchNs":stop.and_then(|stop| elapsed(launch, stop)),
                        "bodyProgressAfterLaunchNs":body.iter().map(|at| elapsed(launch, *at)).collect::<Vec<_>>(),
                        "helperWindowChecked":helper && timing_ok});
                    require(launch >= origin && done < endpoint && frame >= launch && frame <= done && timing_ok,
                        "tls_helper_original_reader_window")?;
                } else {
                    let owner = self.base.product.owner("github-read-1")?;
                    let state = lock(&owner.state);
                    let owner_endpoint = state.endpoint;
                    let start = owner_endpoint.checked_sub(OPERATION_TIME).ok_or("tls_owner_clock")?;
                    let settled = self.owner_settled_at.ok_or("tls_owner_settlement_missing")?;
                    let phase_name = if name == "T5-dns" { "dns-question" } else if name == "T5-handshake" { "client-hello" } else { "first-get" };
                    let phase = frames.first(phase_name).ok_or("tls_deadline_phase_missing")?;
                    let deadline = owner_deadline(name);
                    let exact_cleanup = state.cleanup_endpoint == Some(owner_endpoint + CLEANUP_TIME);
                    let checked = if deadline { owner_window(owner_endpoint, state.cleanup_endpoint, settled, phase) }
                        else { state.cleanup_endpoint.is_none() && settled < owner_endpoint && phase < settled };
                    self.timing = json!({"kind":"ordinary-owner","operationStartAfterPeerNs":elapsed(origin, start),
                        "operationEndpointAfterPeerNs":elapsed(origin, owner_endpoint),
                        "cleanupEndpointAfterPeerNs":state.cleanup_endpoint.and_then(|at| elapsed(origin, at)),
                        "settledAfterPeerNs":elapsed(origin, settled),"phaseAfterPeerNs":elapsed(origin, phase),"phase":phase_name,
                        "originalDeadlineChecked":deadline && checked,"cleanupExact":deadline && exact_cleanup});
                    require(start >= origin && settled < endpoint && phase >= start && checked, "tls_owner_original_endpoint")?;
                    if matches!(name, "T5-handshake" | "T5-read") {
                        let stop = frames.first("client-stop").ok_or("tls_deadline_client_stop_missing")?;
                        require(stop >= owner_endpoint, "tls_owner_early_client_stop")?;
                        if name == "T5-read" { require(progressing(phase, owner_endpoint, &frames.body_times()), "tls_owner_read_progress_gap")?; }
                    }
                }
                Ok(())
            }
            async fn final_checks(&mut self) -> Check<()> {
                // All independent assertions run, even if an earlier one fails.
                // Assertions cannot substitute for the preceding native joins.
                let owner = guarded(async { self.owner_facts() }).await.unwrap_or_else(Err);
                let frames = guarded(async { Frames::from_original(&mut *self.base.retained.peer.lock().await, self.base.scenario) })
                    .await.unwrap_or_else(Err);
                let ambient = guarded(async {
                    if let Some(ambient) = lock(&self.originals.ambient).as_mut() { ambient.after()?; }
                    Ok(())
                }).await.unwrap_or_else(Err);
                let resolver = guarded(async {
                    resolver_runtime(&self.base.retained.selection.original.common.manifest)?;
                    if self.base.scenario.name == "T5-dns" { self.cache_after = Some(caches_absent()); }
                    Ok(())
                }).await.unwrap_or_else(Err);
                let timing = match frames { Ok(frames) => guarded(self.timing(&frames)).await.unwrap_or_else(Err), Err(code) => Err(code) };
                owner.and(ambient).and(resolver).and(timing)
            }
            async fn evidence(&self, passed: bool, failure: Option<&str>, client_settled: bool) -> Value {
                let legacy = self.base.evidence(passed, failure, client_settled).await;
                let direct = direct(self.base.scenario.name);
                let probe = if direct { self.originals.probe.lock().await.evidence() } else { Value::Null };
                let initial = if self.base.scenario.name == "T4-owner-clear" {
                    self.base.product.supervisor.inner.test.owners().first().map(|owner| match lock(&owner.observation).github_initial_environment {
                        Some(true) => "observed-allowlist", Some(false) => "observed-not-allowlist", None => "unavailable-source-bound-only",
                    })
                } else { None };
                let ambient = lock(&self.originals.ambient).as_ref().map(|ambient| ambient.evidence(initial));
                json!({"case":self.base.scenario.name,"entry":if direct { "fixture-owned-bootstrap" } else { "ordinary-supervisor" },
                    "passed":passed,"failureCode":failure,"coreMode":"source",
                    "trustFixture":if self.base.scenario.other_root { "other-root-ca.pem" } else { "root-ca.pem" },
                    "elapsedMs":self.base.product.begin.elapsed().as_millis(),"clientSettled":client_settled,
                    "projectionChecked":self.base.projection_checked,"reason":self.base.result_reason,
                    "product":if direct { Value::Null } else { legacy["product"].clone() },"probe":probe,"ambient":ambient,
                    "timing":self.timing,"progress":self.progress,"peer":legacy["peer"],"resolverCacheAbsentAfter":self.cache_after})
            }
            async fn release(&self) -> Check<()> {
                require(self.originals.probe.lock().await.settled && self.base.retained.peer.lock().await.settled
                    && lock(&self.originals.ambient).as_ref().map_or(true, Ambient::settled), "tls_deadline_originals_unsettled")?;
                let mut originals = lock(&ORIGINALS);
                require(originals.as_ref().is_some_and(|old| Arc::ptr_eq(old, &self.originals))
                    && Arc::ptr_eq(&self.originals.retained, &self.base.retained), "tls_deadline_original_identity")?;
                self.base.release_retention()?;
                originals.take();
                Ok(())
            }
        }
        struct DeadlineReceipt { path: PathBuf, profile: &'static str, bindings: Value, cases: Vec<Value> }
        impl DeadlineReceipt {
            fn write(&self, state: &str, code: Option<&str>) -> Check<()> {
                let bytes = serde_json::to_vec(&json!({"schemaVersion":1,"scope":"github-readonly-tls-deadline-hosted-v1",
                    "profile":self.profile,"status":state,"allOwnersSettled":state == "passed","allProbesSettled":state == "passed",
                    "allPeersSettled":state == "passed","failureCode":code,"bindings":self.bindings,"cases":self.cases,
                    "outerWait":"external-original-observer-required","notVerified":NOT_VERIFIED})).map_err(|_| "tls_deadline_receipt_encoding")?;
                require(bytes.len() <= 128 * 1024, "tls_deadline_receipt_limit")?;
                fs::write(&self.path, bytes).map_err(|_| "tls_deadline_receipt_write")
            }
        }
        pub(super) async fn run(profile: &'static str) {
            let admitted = match Admitted::new_profile(Some(profile)) {
                Ok(admitted) => admitted, Err(code) => refuse_before_cases(Some(profile), code),
            };
            let mut receipt = DeadlineReceipt { path: admitted.inputs.root.join("receipt.json"), profile,
                bindings: admitted.common.bindings.clone(), cases: Vec::new() };
            if receipt.write("running", None).is_err() { panic!("TLS deadline receipt unavailable before native work"); }
            let cases = if profile == "hosts" { HOSTS } else { DNS };
            for scenario in cases {
                let mut case = match DeadlineCase::new(&admitted, scenario) {
                    Ok(case) => case,
                    Err(code) => { let _ = receipt.write("failed", Some(code)); panic!("TLS deadline preparation failed: {code}"); },
                };
                let mut checked = guarded(case.exercise()).await.unwrap_or_else(Err);
                let failed = checked.is_err();
                let originals = case.originals.clone();
                let peer_book = case.base.retained.clone();
                let completion = case.completion.take();
                // The one completion sender travels with actual client cleanup.
                // An unwind/false/missing original closes it without success.
                // Both client books and the peer are driven independently.
                let (client, peer) = tokio::join!(guarded(async {
                    let (product, probe) = tokio::join!(guarded(case.base.product.settle(failed)),
                        guarded(async { originals.probe.lock().await.settle(failed).await }));
                    let settled = matches!(product, Ok(true)) && matches!(probe, Ok(true))
                        && lock(&originals.ambient).as_ref().map_or(true, Ambient::settled);
                    let spawned = if direct(scenario.name) { originals.probe.lock().await.spawned }
                        else { originals.retained.supervisor.inner.test.owners().iter().any(|owner| lock(&owner.observation).spawned) };
                    if settled && spawned {
                        if let Some(completion) = completion { let _ = completion.send(()); }
                    } else { drop(completion); }
                    settled
                }), guarded(async { peer_book.peer.lock().await.settle(scenario.name, failed).await }));
                let client_settled = matches!(client, Ok(true));
                let peer_settled = matches!(peer, Ok(true));
                if !client_settled || !peer_settled {
                    receipt.cases.push(case.evidence(false, Some("tls_deadline_custody_unresolved"), client_settled).await);
                    let _ = receipt.write("failed-retained", Some("tls_deadline_custody_unresolved"));
                    pending::<()>().await; // Original books retained, no next case or cleanup-to-success.
                    return;
                }
                let assertions = guarded(case.final_checks()).await.unwrap_or_else(Err);
                if checked.is_ok() { checked = assertions; }
                if let Err(code) = case.release().await {
                    receipt.cases.push(case.evidence(false, Some(code), client_settled).await);
                    let _ = receipt.write("failed-retained", Some(code));
                    pending::<()>().await;
                    return;
                }
                receipt.cases.push(case.evidence(checked.is_ok(), checked.err(), client_settled).await);
                if let Err(code) = checked { let _ = receipt.write("failed", Some(code)); panic!("TLS deadline check failed after original joins: {code}"); }
                if receipt.write("running", None).is_err() { panic!("TLS deadline receipt failed after original joins"); }
            }
            // Both profile invocations use the same closed source runtime; all
            // original owner/probe/peer tasks have returned before this point.
            if receipt.write("passed", None).is_err() { panic!("TLS deadline final receipt failed after original joins"); }
        }

        #[cfg(test)]
        mod models {
            // DATA-only predicates. These tests create no Child, descriptor,
            // socket, namespace, file or certificate and certify no native run.
            use super::*;

            #[test]
            fn probe_spawn_preserves_reserve_and_attributes_file_limit() {
                let now = Instant::now();
                let endpoint = now + CLIENT_RESERVE;
                let tick = Duration::from_nanos(1);
                assert_eq!(probe_spawn_admission(now, endpoint, true), Ok(()));
                assert_eq!(probe_spawn_admission(now, endpoint + tick, true), Ok(()));
                assert_eq!(probe_spawn_admission(now, endpoint, false), Err("tls_probe_spawn_file_limit"));
                assert_eq!(probe_spawn_admission(now + tick, endpoint, true), Err("tls_probe_spawn_deadline"));
                assert_eq!(probe_spawn_admission(now + tick, endpoint, false), Err("tls_probe_spawn_deadline"));
            }

            #[test]
            fn sha256_known_answers_and_bounded_streaming_diagnostic() {
                assert_eq!(hash(b""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
                assert_eq!(hash(b"abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
                let chunk = [b'a'; 64 * 1024];
                let mut million = Sha256::new();
                for _ in 0..(1_000_000 / chunk.len()) { million.update(&chunk); }
                million.update(&chunk[..1_000_000 % chunk.len()]);
                assert_eq!(format!("{:x}", million.finalize()),
                    "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");

                // One bounded hot-path observation, not a benchmark or a timing
                // pass threshold. This is not full filesystem/runtime admission
                // or native TLS evidence; every real byte check stays mandatory.
                let started = Instant::now();
                let mut digest = Sha256::new();
                for _ in 0..(100_000_000 / chunk.len()) { digest.update(&chunk); }
                digest.update(&chunk[..100_000_000 % chunk.len()]);
                let digest = format!("{:x}", digest.finalize());
                let elapsed_ns = started.elapsed().as_nanos();
                assert_eq!(digest, "83d30385a4a11980275dc23de3fb49ff37b906cc841efa048a96c62d90ff3b5f");
                println!("TLS_SHA256_100MB bytes=100000000 chunk_bytes=65536 elapsed_ns={elapsed_ns} sha256={digest}");
            }

            // Literal producer wire keys, not Serialize-derived Rust DTOs. These
            // inert frames exercise decoding, not native peer/finality evidence.
            const WIRE_PROGRESS: &str = concat!(
                r#"{"schemaVersion":1,"scope":"github-tls-peer-v1","case":"T4-owner-clear","state":"progress","event":"first-get","sequence":1,"#,
                r#""requests":1,"bodyBytes":0,"wireReadBytes":100,"wireWriteBytes":150,"dnsQuestions":0,"dnsA":0,"dnsAAAA":0,"clientStop":null}"#,
            );
            const WIRE_TERMINAL: &str = concat!(
                r#"{"schemaVersion":1,"scope":"github-tls-peer-v1","case":"T4-owner-clear","state":"finished","status":"passed","code":null,"#,
                r#""connections":4,"handshakes":4,"requests":4,"decryptedBytes":1000,"authBytes":116,"closeNotify":4,"tlsRefused":false,"#,
                r#""wireReadBytes":[100,100,100,100],"wireWriteBytes":[150,150,150,150],"replyBytes":[125,125,125,125],"allSocketsClosed":true,"#,
                r#""sni":4,"phase":"ambient","withheldWireBytes":0,"bodyBytes":0,"incompleteBody":false,"clientStop":null,"progressCount":1,"#,
                r#""dnsQuestions":0,"dnsA":0,"dnsAAAA":0,"dnsReplies":0,"completion":{"bytes":1,"eof":true,"closed":true,"primaryEmpty":true,"#,
                r#""primaryUnexpected":0,"primaryClosed":true,"proxy":{"empty":true,"unexpected":0,"closed":true},"dnsEmpty":null,"dnsClosed":null}}"#,
            );
            #[test]
            fn deadline_wire_frames_preserve_exact_dns_acronym() {
                let progress = decode_progress_frame(WIRE_PROGRESS.as_bytes()).unwrap();
                assert_eq!((progress.dns_questions, progress.dns_a, progress.dns_aaaa), (0, 0, 0));
                let (terminal, wire) = decode_terminal_frame(WIRE_TERMINAL.as_bytes()).unwrap();
                assert_eq!((terminal.dns_questions, terminal.dns_a, terminal.dns_aaaa), (0, 0, 0));
                assert_eq!(wire["dnsAAAA"], json!(0));
                assert!(wire.get("dnsAaaa").is_none() && wire.get("dns_aaaa").is_none());

                // Nonzero counters prove the canonical field was actually read,
                // not silently ignored/defaulted. Semantic phase checks stay in
                // Frames::check; these helpers only decode the closed wire DTOs.
                let mut dns_progress = protocol::strict_json(WIRE_PROGRESS.as_bytes()).unwrap();
                let mut dns_terminal = protocol::strict_json(WIRE_TERMINAL.as_bytes()).unwrap();
                for value in [&mut dns_progress, &mut dns_terminal] {
                    value["case"] = json!("T5-dns");
                    value["dnsQuestions"] = json!(3);
                    value["dnsA"] = json!(1);
                    value["dnsAAAA"] = json!(2);
                }
                let progress = decode_progress_frame(&serde_json::to_vec(&dns_progress).unwrap()).unwrap();
                let (terminal, wire) = decode_terminal_frame(&serde_json::to_vec(&dns_terminal).unwrap()).unwrap();
                assert_eq!((progress.dns_questions, progress.dns_a, progress.dns_aaaa), (3, 1, 2));
                assert_eq!((terminal.dns_questions, terminal.dns_a, terminal.dns_aaaa), (3, 1, 2));
                assert_eq!(wire["dnsAAAA"], json!(2));
            }
            #[test]
            fn deadline_wire_frames_reject_noncanonical_dns_fields() {
                type Decode = fn(&[u8]) -> Check<()>;
                let decoders: [(&str, Decode, &str, &str, &str); 2] = [
                    (WIRE_PROGRESS, |raw| decode_progress_frame(raw).map(|_| ()), "tls_deadline_progress_fields",
                        "tls_deadline_progress_json", "tls_deadline_progress_schema"),
                    (WIRE_TERMINAL, |raw| decode_terminal_frame(raw).map(|_| ()), "tls_deadline_terminal_fields",
                        "tls_deadline_terminal_json", "tls_deadline_terminal_schema"),
                ];
                for (raw, decode, fields_code, json_code, schema_code) in decoders {
                    let original = protocol::strict_json(raw.as_bytes()).unwrap();
                    let mut missing = original.clone();
                    missing.as_object_mut().unwrap().remove("dnsAAAA");
                    assert_eq!(decode(&serde_json::to_vec(&missing).unwrap()), Err(fields_code));
                    for alias in ["dnsAaaa", "dns_aaaa"] {
                        let mut only_alias = missing.clone();
                        only_alias[alias] = json!(0);
                        assert_eq!(decode(&serde_json::to_vec(&only_alias).unwrap()), Err(fields_code));
                        let mut both = original.clone();
                        both[alias] = json!(0);
                        assert_eq!(decode(&serde_json::to_vec(&both).unwrap()), Err(fields_code));
                    }
                    let mut unknown = original.clone();
                    unknown["unrecognized"] = json!(0);
                    assert_eq!(decode(&serde_json::to_vec(&unknown).unwrap()), Err(fields_code));
                    for invalid in [json!(true), json!(-1), json!("0"), Value::Null] {
                        let mut wrong_type = original.clone();
                        wrong_type["dnsAAAA"] = invalid;
                        assert_eq!(decode(&serde_json::to_vec(&wrong_type).unwrap()), Err(schema_code));
                    }
                    // Preserve duplicate keys as raw bytes so strict_json must
                    // reject them before Value could overwrite a repeated key.
                    let duplicate = raw.replacen(r#""dnsAAAA":0"#, r#""dnsAAAA":0,"dnsAAAA":1"#, 1);
                    assert_ne!(duplicate, raw);
                    assert_eq!(decode(duplicate.as_bytes()), Err(json_code));
                }
                let mut completion = protocol::strict_json(WIRE_TERMINAL.as_bytes()).unwrap();
                completion["completion"]["unrecognized"] = json!(0);
                assert_eq!(decode_terminal_frame(&serde_json::to_vec(&completion).unwrap()).err(),
                    Some("tls_deadline_completion_fields"));
            }

            #[test]
            fn resource_limits_require_both_exact_finite_sides() {
                use rustix::process::Rlimit;
                assert_eq!(RESOURCE_LIMITS.iter().map(|(_, expected, _)| *expected).collect::<Vec<_>>(),
                    [0, 1048576, 128, 1073741824]);
                for &(_, expected, _) in RESOURCE_LIMITS {
                    assert!(exact_resource_limit(Rlimit { current: Some(expected), maximum: Some(expected) }, expected));
                    for wrong in [None, Some(u64::MAX), Some(expected + 1), Some(expected.saturating_sub(1)), Some(0)] {
                        if wrong == Some(expected) { continue; }
                        assert!(!exact_resource_limit(Rlimit { current: wrong, maximum: Some(expected) }, expected));
                        assert!(!exact_resource_limit(Rlimit { current: Some(expected), maximum: wrong }, expected));
                    }
                    assert!(!exact_resource_limit(Rlimit { current: None, maximum: None }, expected));
                }
            }

            fn privilege_status_fixture(group_padding: &str) -> String {
                format!(concat!("Name:\tinert-status-model\n", "CapInh:\t0000000000000000\n",
                    "CapPrm:\t0000000000000000\n", "CapEff:\t0000000000000000\n",
                    "CapBnd:\t0000000000000000\n", "CapAmb:\t0000000000000000\n",
                    "NoNewPrivs:\t1\n", "Groups:\t{}\n"), group_padding)
            }
            #[test]
            fn privilege_status_accepts_only_empty_group_padding() {
                for padding in ["", " ", "\t \t"] {
                    assert_eq!(privilege_status(&privilege_status_fixture(padding)), Ok(()));
                }
                for membership in ["0", "0 ", "1001 1002 ", "\u{a0}", "\u{2003}", "\u{b}"] {
                    assert_eq!(privilege_status(&privilege_status_fixture(membership)), Err("tls_deadline_privilege_groups"));
                }
                let missing_separator = privilege_status_fixture("").replace("Groups:\t\n", "Groups:\n");
                assert_eq!(privilege_status(&missing_separator), Err("tls_deadline_privilege_groups"));
                // Additional ordinary kernel fields carry no privilege authority.
                assert_eq!(privilege_status(&(privilege_status_fixture(" ") + "FutureKernelField:\t1\n")), Ok(()));
            }
            #[test]
            fn privilege_status_refuses_incomplete_unsafe_or_ambiguous_rows() {
                let valid = privilege_status_fixture(" ");
                for (name, replacement, code) in [
                    ("CapInh:", "\t0000000000000001", "tls_deadline_privilege_inheritable"),
                    ("CapPrm:", "\t0000000000000001", "tls_deadline_privilege_permitted"),
                    ("CapEff:", "\t0000000000000001", "tls_deadline_privilege_effective"),
                    ("CapBnd:", "\t0000000000000001", "tls_deadline_privilege_bounding"),
                    ("CapAmb:", "\t0000000000000001", "tls_deadline_privilege_ambient"),
                    ("NoNewPrivs:", "\t0", "tls_deadline_privilege_nonewprivs"),
                    ("Groups:", "\t0 ", "tls_deadline_privilege_groups"),
                ] {
                    let mut rows = valid.lines().map(str::to_owned).collect::<Vec<_>>();
                    let index = rows.iter().position(|row| row.starts_with(name)).unwrap();
                    let original = rows[index].clone();
                    rows[index] = format!("{name}{replacement}");
                    assert_eq!(privilege_status(&(rows.join("\n") + "\n")), Err(code));
                    rows.remove(index);
                    assert_eq!(privilege_status(&(rows.join("\n") + "\n")), Err(code));
                    assert_eq!(privilege_status(&format!("{valid}{original}\n")), Err(code));
                }
                for payload in [" 0000000000000000", "\t0", "\t0000000000000000 ", "\t\t0000000000000000"] {
                    let changed = valid.replace("CapEff:\t0000000000000000", &format!("CapEff:{payload}"));
                    assert_eq!(privilege_status(&changed), Err("tls_deadline_privilege_effective"));
                }
                for payload in [" 1", "\t01", "\t1 ", "\t\t1"] {
                    let changed = valid.replace("NoNewPrivs:\t1", &format!("NoNewPrivs:{payload}"));
                    assert_eq!(privilege_status(&changed), Err("tls_deadline_privilege_nonewprivs"));
                }
                for malformed in [String::new(), valid.trim_end_matches('\n').to_owned(), valid.replace('\n', "\r\n"),
                    valid.replace("Groups:\t ", "Groups:\t\0"), "x".repeat(64 * 1024) + "\n"] {
                    assert_eq!(privilege_status(&malformed), Err("tls_deadline_privilege_status"));
                }
            }

            #[test]
            fn maps_rows_preserve_opaque_names_and_original_backing_columns() {
                let prefix = "7f000000-7f001000 r--p 00001000 08:02 1234";
                let plain = map_row(prefix).unwrap();
                assert_eq!((plain.major, plain.minor, plain.inode, plain.remainder), (8, 2, 1234, ""));
                assert_eq!(mapped_libc_path(&plain), Ok(None));
                for label in ["[anon: glibc: pthread stack]", "[anon: glibc: malloc arena]",
                    "/opt/unrelated folder/ordinary file "] {
                    let line = format!("{prefix}     {label}");
                    let row = map_row(&line).unwrap();
                    assert_eq!(row.remainder, label); // Including the trailing space.
                    assert_eq!(mapped_libc_path(&row), Ok(None));
                }
                let row = map_row("7f000000-7f001000 r-xp 00001000 08:02 1234 /usr/lib/libc.so.6").unwrap();
                assert_eq!((row.major, row.minor, row.inode), (8, 2, 1234));
                assert_eq!(mapped_libc_path(&row), Ok(Some(Path::new("/usr/lib/libc.so.6"))));
            }
            #[test]
            fn maps_rows_reject_malformed_columns_and_deleted_runtime_modules() {
                for line in ["", "1000-2000 r--p 0 00:00", "1000-1000 r--p 0 00:00 0",
                    "-1000-2000 r--p 0 00:00 0", "1000-2000 r--q 0 00:00 0", "1000-2000 r--p z 00:00 0",
                    "1000-2000 r--p 0 00:zz 0", "1000-2000 r--p 0 00:00 -1",
                    "1000-2000 r--p 0 00:00 18446744073709551616", "1000-2000 r--p 0 00:00 0\0",
                    "1000-2000 r--p 0 00:00 0\n"] {
                    assert!(map_row(line).is_err(), "{line:?}");
                }
                for (name, error) in [("libnss_dns.so.2", "tls_dynamic_nss_unsupported"),
                    ("libnss_dns.so.2 (deleted)", "tls_dynamic_nss_unsupported"),
                    ("libc.so.6 (deleted)", "tls_libc_backing_file"), ("libc-2.39.so (deleted)", "tls_libc_backing_file")] {
                    let line = format!("1000-2000 r--p 0 00:01 1234 /usr/lib/{name}");
                    let row = map_row(&line).unwrap();
                    assert_eq!(mapped_libc_path(&row), Err(error));
                }
                let row = map_row("1000-2000 r--p 0 00:01 1234 /unrelated file (deleted)").unwrap();
                assert_eq!(mapped_libc_path(&row), Ok(None));
            }
            #[test]
            fn admission_frames_are_closed_bounded_data_only() {
                let unique = ADMISSION_CODES.iter().copied().collect::<BTreeSet<_>>();
                assert_eq!(unique.len(), ADMISSION_CODES.len());
                for profile in [None, Some("hosts"), Some("dns-withhold")] {
                    for code in ADMISSION_CODES {
                        let frame = admission_frame(profile, code);
                        assert!(frame.is_ascii() && frame.len() <= 256 && frame.ends_with('\n'));
                        assert_eq!(frame, format!("github-tls-admission: {}/{code}\n", profile.unwrap_or("original")));
                    }
                    let frame = admission_frame(profile, "private-path/token\nsecond-frame");
                    assert!(frame.ends_with("/tls_admission_unclassified\n") && !frame.contains("private"));
                }
                assert_eq!(admission_frame(Some("private-profile"), "private-code"),
                    "github-tls-admission: unclassified/tls_admission_unclassified\n");
                // This pure codec test never calls refuse_before_cases or exit.
            }

            fn progress_until(launch: Instant, seconds: u64) -> Vec<Instant> {
                (0..seconds).map(|second| launch + Duration::from_millis(200) + Duration::from_secs(second)).collect()
            }
            #[test]
            fn helper_response_uses_original_frame_lower_and_upper_bounds() {
                let launch = Instant::now();
                let get = launch + Duration::from_millis(100);
                for second in [10, 12] {
                    let frame = launch + Duration::from_secs(second);
                    let body = progress_until(launch, second);
                    assert!(helper_window(launch, get, frame, frame + Duration::from_millis(1), &body));
                }
                let frame = launch + HELPER_EARLIEST - Duration::from_nanos(1);
                let later_wait = launch + HELPER_LATEST;
                assert!(!helper_window(launch, get, frame, later_wait, &progress_until(launch, 10)));
                let frame = launch + HELPER_LATEST + Duration::from_nanos(1);
                assert!(!helper_window(launch, get, frame, frame, &progress_until(launch, 12)));
                assert!(!helper_window(launch, launch + GET_LATEST + Duration::from_nanos(1), later_wait,
                    later_wait, &progress_until(launch, 12)));
            }
            #[test]
            fn helper_requires_genuine_continuing_progress_and_no_early_stop() {
                let launch = Instant::now();
                let get = launch + Duration::from_millis(100);
                let frame = launch + Duration::from_secs(10);
                let valid = progress_until(launch, 10);
                assert!(helper_window(launch, get, frame, frame, &valid));
                assert!(!helper_window(launch, get, frame, frame, &[]));
                assert!(!helper_window(launch, get, frame, frame - Duration::from_nanos(1), &valid));
                let mut gap = valid.clone(); gap.remove(4);
                assert!(!helper_window(launch, get, frame, frame, &gap));
                let mut queued = valid.clone(); queued[4] = queued[3];
                assert!(!helper_window(launch, get, frame, frame, &queued));
                assert!(!helper_window(launch, get, frame, frame, &valid[..8]));
                let mut late_first = valid; late_first[0] = get + CADENCE + Duration::from_nanos(1);
                assert!(!helper_window(launch, get, frame, frame, &late_first));
            }
            #[test]
            fn owner_cleanup_is_anchored_to_its_original_operation_endpoint() {
                let origin = Instant::now();
                let endpoint = origin + OPERATION_TIME;
                let phase = origin + Duration::from_secs(1);
                assert!(owner_window(endpoint, Some(endpoint + CLEANUP_TIME), endpoint, phase));
                assert!(!owner_window(endpoint, None, endpoint, phase));
                assert!(!owner_window(endpoint, Some(phase + CLEANUP_TIME), endpoint, phase));
                assert!(!owner_window(endpoint, Some(endpoint + CLEANUP_TIME), endpoint + CLEANUP_TIME, phase));
                assert!(!owner_window(endpoint, Some(endpoint + CLEANUP_TIME), endpoint - Duration::from_nanos(1), phase));
                assert!(!owner_window(endpoint, Some(endpoint + CLEANUP_TIME), endpoint, endpoint));
            }
            #[test]
            fn original_progress_arrivals_track_split_lf_frames_without_retiming() {
                let origin = Instant::now();
                let later = origin + Duration::from_secs(1);
                let mut arrivals = Arrivals::default();
                arrivals.observe(b"ready\npart", 0, origin);
                arrivals.observe(b"ready\npartial\n", 10, later);
                assert!(!arrivals.invalid);
                assert_eq!(arrivals.frames, [(6, origin), (14, later)]);
                arrivals.observe(b"ready\npartial\n", 0, later);
                assert!(arrivals.invalid); // No replay of queued bytes as fresh observations.
            }
            fn read_frames() -> Frames {
                let name = "T5-read";
                let origin = Instant::now();
                let progress = [
                    ("first-get", 0, 100, None), ("body-byte", 1, 150, None), ("client-stop", 1, 150, Some("tcp-eof")),
                ].into_iter().enumerate().map(|(index, (event, body_bytes, wire_write_bytes, stop))| (Progress {
                    schema_version: 1, scope: "github-tls-peer-v1".to_owned(), case_name: name.to_owned(), state: "progress".to_owned(),
                    event: event.to_owned(), sequence: index as u64 + 1, requests: 1, body_bytes, wire_read_bytes: 100,
                    wire_write_bytes, dns_questions: 0, dns_a: 0, dns_aaaa: 0, client_stop: stop.map(str::to_owned),
                }, origin + Duration::from_secs(index as u64))).collect();
                Frames { progress, terminal: Terminal {
                    schema_version: 1, scope: "github-tls-peer-v1".to_owned(), case_name: name.to_owned(), state: "finished".to_owned(),
                    status: "passed".to_owned(), code: None, connections: 1, handshakes: 1, requests: 1, decrypted_bytes: 100,
                    auth_bytes: b"Bearer INERT_NOT_A_CREDENTIAL".len() as u64, close_notify: 0, tls_refused: false,
                    wire_read_bytes: vec![100], wire_write_bytes: vec![150], reply_bytes: vec![125], all_sockets_closed: true,
                    sni: 1, phase: "read".to_owned(), withheld_wire_bytes: 0, body_bytes: 1, incomplete_body: true,
                    client_stop: Some("tcp-eof".to_owned()), progress_count: 3, dns_questions: 0, dns_a: 0, dns_aaaa: 0, dns_replies: 0,
                    completion: Completion { bytes: 1, eof: true, closed: true, primary_empty: true, primary_unexpected: 0,
                        primary_closed: true, proxy: None, dns_empty: None, dns_closed: None },
                } }
            }
            #[test]
            fn classified_progress_needs_positive_wire_bytes_and_original_horizon() {
                let scenario = &HOSTS[4];
                let mut frames = read_frames();
                assert!(frames.check(scenario).is_ok());
                frames.progress[1].0.wire_write_bytes = frames.progress[0].0.wire_write_bytes;
                assert!(frames.check(scenario).is_err());
                let mut frames = read_frames(); frames.terminal.completion.primary_empty = false;
                assert!(frames.check(scenario).is_err());
                let mut frames = read_frames(); frames.terminal.completion.eof = false;
                assert!(frames.check(scenario).is_err());
                let mut frames = read_frames(); frames.terminal.body_bytes = 25;
                assert!(frames.check(scenario).is_err());
                let mut frames = read_frames(); frames.terminal.dns_replies = 1;
                assert!(frames.check(scenario).is_err());
            }
            #[test]
            fn resolver_profile_refuses_ambient_policy_and_unbounded_configuration() {
                assert!(host_configuration(b"# fixed\norder hosts,bind\nmulti on\n", true));
                assert!(host_configuration(b"# default precedence\n", false));
                for bytes in [b"multi off\n".as_slice(), b"multi on\nmulti on\n", b"spoofalert on\n", b"multi on\0"] {
                    assert!(!host_configuration(bytes, true));
                }
                assert!(!host_configuration(b"precedence ::ffff:0:0/96 100\n", false));
                assert!(!host_configuration(&vec![b'#'; 513], true));
                assert!(!host_configuration(&vec![b'\n'; 128], true));
                assert!(!host_configuration(b"\xff", true));
            }
        }
    }
}
