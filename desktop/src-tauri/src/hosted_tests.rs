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
    pub inspection: Arc<BlockingGate>, pub stdout_join: Arc<JoinGate>,
    pub driver_return: Arc<JoinGate>, pub watchdog_return: Arc<JoinGate>,
    owners: Mutex<Vec<Arc<Owner>>>,
    #[cfg(windows)]
    pub(super) windows_bootstrap: Mutex<WindowsBootstrap>,
}
impl Hooks {
    pub(super) fn register(&self, owner: Arc<Owner>) { lock(&self.owners).push(owner); }
    fn owners(&self) -> Vec<Arc<Owner>> { lock(&self.owners).clone() }
    fn release(&self) {
        self.inspection.release(); self.stdout_join.release();
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
        // Defense in depth only: runner scheduling must also be approved before
        // the triggering push. Setting these strings is not execution authority.
        require(environment("MRK_DESKTOP_HOSTED_CHECKS")? == "passive-v1"
            && environment("GITHUB_ACTIONS")? == "true"
            && environment("RUNNER_ENVIRONMENT")? == "github-hosted", "hosted_admission_required")?;
        require(matches!(std::env::consts::OS, "linux" | "macos" | "windows"), "unsupported_host")?;
        let root = selected("MRK_DESKTOP_TEST_ROOT")?;
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
            callers: Vec::new(), results: Vec::new(), notes: json!({}), begin: Instant::now() })
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
            {
                let state = lock(&owner.state);
                let observed = lock(&owner.observation);
                if !state.terminal || state.driver_join != ManagementJoin::Returned
                    || state.watchdog_join != ManagementJoin::Returned
                    || !observed.driver_joined || !observed.watchdog_joined { return false; }
            }
            let resources = owner.resources.lock().await;
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
                require(observed.stdout_bytes <= protocol::RESPONSE_LIMIT && observed.stderr_bytes <= protocol::STDERR_LIMIT, "retained_output_exceeds_limit")?;
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
