//! Ignored disposable-hosted checks, never local/native execution authority.
//! One fixed batch; original process facts are observed, never synthesized.
//! Scheduling gates are explicitly not OS stuck-spawn/wait/close qualification.
use super::*;
use std::{fs, path::{Path, PathBuf}, sync::Condvar};
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};

type Check<T> = Result<T, &'static str>;
type Query = Result<Value, BridgeError>;
const FIXTURE: &str = include_str!("../tests/fixtures/passive_core/_desktop_engine.py");
const PACKAGE: &str = include_str!("../tests/fixtures/passive_core/__init__.py");

#[derive(Clone, Default, Serialize)]
pub(super) struct Observation {
    pub inspection_joined: bool, pub acquisition_joined: bool, pub spawned: bool,
    pub waited: bool, pub exit_success: Option<bool>,
    pub writer_joined: bool, pub writer_complete: bool,
    pub stdout_eof: bool, pub stderr_eof: bool, pub stdout_joined: bool, pub stderr_joined: bool,
    pub stdout_bytes: usize, pub stderr_bytes: usize,
    pub driver_joined: bool, pub watchdog_joined: bool,
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
    async fn wait(&self) {
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
    owners: Mutex<Vec<Arc<Owner>>>,
}
impl Hooks {
    pub(super) fn register(&self, owner: Arc<Owner>) { lock(&self.owners).push(owner); }
    fn owners(&self) -> Vec<Arc<Owner>> { lock(&self.owners).clone() }
    fn release(&self) { self.inspection.release(); self.stdout_join.release(); }
}

pub(super) async fn observed_read<R: AsyncRead + Unpin>(reader: R, limit: usize, faults: mpsc::Sender<BridgeError>,
    observation: Arc<Mutex<Observation>>, gate: Option<Arc<JoinGate>>, stderr: bool) -> ReadEnd {
    let end = read_bounded(reader, limit, faults).await;
    {
        let mut observed = lock(&observation);
        if stderr { observed.stderr_eof = end.eof; observed.stderr_bytes = end.bytes.len(); }
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
        let bytes = serde_json::to_vec(&json!({"schemaVersion":1, "scope":"passive-hosted-v1",
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
                    && lock(&owner.driver).as_ref().is_some_and(JoinHandle::is_finished)
                    && lock(&owner.watchdog).as_ref().is_some_and(JoinHandle::is_finished))
                && self.callers.iter().flatten().all(JoinHandle::is_finished)
        };
        if until(Duration::from_secs(3), all_finished).await.is_err() {
            let _ = self.supervisor.shutdown().await; // Existing allowances, never renewed.
            if until(Duration::from_secs(3), all_finished).await.is_err() { return false; }
        }
        for owner in &owners {
            // These are the retained ORIGINAL JoinHandles, not replacement waits.
            let mut driver = lock(&owner.driver).take();
            let mut watchdog = lock(&owner.watchdog).take();
            let driver_ok = match driver.as_mut() { Some(task) => task.await.is_ok(), None => false };
            let watchdog_ok = match watchdog.as_mut() { Some(task) => task.await.is_ok(), None => false };
            if !driver_ok || !watchdog_ok {
                *lock(&owner.driver) = driver; *lock(&owner.watchdog) = watchdog;
                return false;
            }
            let mut observed = lock(&owner.observation);
            observed.driver_joined = true; observed.watchdog_joined = true;
            drop(observed);
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

async fn exercise(case: &mut Case) -> Check<()> {
    match case.name {
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
        if checked.is_ok() && name.starts_with("controlled-") {
            checked = require(case.supervisor.disabled() && case.supervisor.can_exit()
                && case.supervisor.inner.test.owners().iter().all(|owner| { let state = lock(&owner.state); state.unknown && state.terminal && state.error.is_some() }), "late_settlement_cleared_failure");
        }
        receipt.cases.push(case.evidence(checked.is_ok(), checked.err()));
        if let Err(code) = checked { let _ = receipt.write("failed", Some(code)); panic!("hosted passive check failed after settlement: {code}"); }
        if receipt.write("running", None).is_err() { panic!("hosted passive receipt failed after settlement"); }
    }
    std::env::set_var("MRK_DESKTOP_DEV_CORE", &inputs.source); // All work settled.
    if receipt.write("passed", None).is_err() { panic!("hosted passive final receipt failed after settlement"); }
}
