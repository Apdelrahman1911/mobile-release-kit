//! Fixed nonshipping Windows candidate only. Never compiled with the shell,
//! development runtime or publisher. These hooks exercise the existing owner;
//! they create no process, worker, deadline controller or native authority.
use super::*;
use mrk_windows_installed_native as native;
use std::{collections::BTreeSet, path::PathBuf};
use serde_json::json;

// Byte-for-byte accepted WIN probe, compile-embedded (not loaded from a writable
// source path). Its self observations are DATA, never owner/settlement receipts.
const PROBE: &str = include_str!("../../../tests/native_desktop_installed_windows_probe.py");
#[derive(Clone, Copy, Eq, PartialEq)]
enum Case { Engine, Closure, StopBeforeClaim, StopChild }
pub(super) struct Hooks {
    case: Mutex<Case>,
    ready: watch::Sender<bool>,
    live: AtomicBool,
    consumed_io: Mutex<ConsumedIo>,
}
impl Default for Hooks {
    fn default() -> Self {
        let (ready, _) = watch::channel(false);
        Self { case: Mutex::new(Case::Engine), ready, live: AtomicBool::new(false),
            consumed_io: Mutex::new(ConsumedIo::Absent) }
    }
}
impl Hooks {
    pub(super) fn hold_writer(&self) -> bool { *lock(&self.case) == Case::StopChild }
}

// DATA only, captured on the original driver immediately before it consumes
// the real read results. No bytes, handles, authority or substitute join receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConsumedIo {
    Absent,
    Once { stdout: Option<(bool, bool)>, stderr: Option<(bool, bool)> },
    Repeated,
}
impl ConsumedIo {
    fn record(&mut self, stdout: Option<(bool, bool)>, stderr: Option<(bool, bool)>) {
        *self = match *self { Self::Absent => Self::Once { stdout, stderr }, _ => Self::Repeated };
    }
    fn complete(self) -> bool {
        matches!(self, Self::Once { stdout: Some((true, false)), stderr: Some((true, false)) })
    }
}
pub(super) fn observe_settled_io(inner: &Inner, resources: &Resources) {
    lock(&inner.windows_test.consumed_io).record(
        resources.out_end.as_ref().map(|end| (end.eof, end.overflow)),
        resources.err_end.as_ref().map(|end| (end.eof, end.overflow)));
}

#[derive(Clone, Copy)]
struct ConsumerReturn {
    waited: bool,
    acquisition: Option<ManagementJoin>,
    child_retained: bool,
    write_returned: bool,
    stdout_retained: bool,
    stderr_retained: bool,
    no_child_effect: bool,
    kill_attempted: bool,
    io: ConsumedIo,
}
impl ConsumerReturn {
    fn consistent(self) -> bool {
        if self.child_retained || self.stdout_retained || self.stderr_retained { return false; }
        if self.waited {
            self.acquisition == Some(ManagementJoin::Returned) && self.write_returned
                && !self.no_child_effect && self.io.complete()
        } else {
            matches!(self.acquisition, None | Some(ManagementJoin::Returned))
                && self.no_child_effect && !self.write_returned && !self.kill_attempted
                && self.io == ConsumedIo::Absent
        }
    }
}

#[derive(Clone, Copy)]
enum PhaseMarker { Start, Settled, QueryUnknown, ObserverMissing, ObserverFailed,
    ResourceBorrow, SlotsMissing, NativeBorrow, FinalityMissing }
fn diagnostic(case: Case, method: Method, phase: PhaseMarker) {
    use std::io::Write;
    let case = match (case, method) {
        (Case::Engine, Method::Capabilities) => "capabilities",
        (Case::Engine, Method::Catalog) => "catalog",
        (Case::Engine, Method::ValidateConfig) => "config-validate",
        (Case::Engine, Method::SuggestConfig) => "config-suggest",
        (Case::Engine, Method::PreviewConfig) => "config-preview",
        (Case::Closure, Method::Catalog) => "closure",
        (Case::StopBeforeClaim, Method::Capabilities) => "stop-before-claim",
        (Case::StopChild, Method::Catalog) => "stop-owned-child",
        (Case::Engine, Method::ProjectSnapshot) => "closed-method",
        _ => "unexpected-fixed-case",
    };
    let phase = match phase {
        PhaseMarker::Start => "start", PhaseMarker::Settled => "settled",
        PhaseMarker::QueryUnknown => "query-finality-unknown", PhaseMarker::ObserverMissing => "observer-missing",
        PhaseMarker::ObserverFailed => "observer-failed", PhaseMarker::ResourceBorrow => "resource-borrow-outstanding",
        PhaseMarker::SlotsMissing => "native-slots-missing", PhaseMarker::NativeBorrow => "native-borrow-outstanding",
        PhaseMarker::FinalityMissing => "finality-postcondition-missing",
    };
    // Best effort on the existing stream only. Failure cannot unwind originals;
    // stream inheritance/marker visibility is not assumed or used as authority.
    let _ = writeln!(std::io::stderr().lock(), "MRK_WINDOWS_PASSIVE_CASE=case={case};phase={phase}");
}
fn probe_command_units(python: &str, core: &str) -> Option<usize> {
    // Conservative std Command quoting bound: include every quote/backslash,
    // both selected paths, flags, quotes, separators and the terminating NUL.
    [PROBE, python, core].into_iter().try_fold(64usize, |count, value| {
        count.checked_add(value.encode_utf16().count())?
            .checked_add(value.bytes().filter(|b| matches!(*b, b'\\' | b'"')).count())
    }).filter(|count| *count <= 32767)
}
pub(super) fn fixed_arguments(command: &mut Command, selected: &VerifiedRuntime, inner: &Inner) -> std::io::Result<()> {
    if *lock(&inner.windows_test.case) == Case::Closure {
        let paths = selected.python.to_str().zip(selected.core.to_str());
        if !paths.is_some_and(|(python, core)| probe_command_units(python, core).is_some()) {
            return Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "fixed probe command exceeds the Windows limit"));
        }
        command.arg("-c").arg(PROBE).arg(&selected.core);
    } else { command.arg(&selected.bootstrap).arg(&selected.core); }
    Ok(())
}
pub(super) fn before_claim(inner: &Inner, owner: &Arc<Owner>) {
    if *lock(&inner.windows_test.case) == Case::StopBeforeClaim {
        // Actual acquisition worker, after native preparation but BEFORE the
        // serialized claim. This is the real existing absorbing failure latch.
        owner.fail(BridgeError::new("cancelled", "Fixed Windows precreation cancellation."));
    }
}
pub(super) async fn write_request(writer: tokio::process::ChildStdin, bytes: Vec<u8>,
    mut stop: watch::Receiver<bool>, faults: mpsc::Sender<BridgeError>, held: bool) -> WriteEnd {
    if held && !*stop.borrow() { let _ = stop.changed().await; }
    super::write_request(writer, bytes, stop, faults).await
}
pub(super) fn after_io_registered(inner: &Inner, owner: &Arc<Owner>, resources: &mut Resources) {
    if !inner.windows_test.hold_writer() { return; }
    // This very original Child and its registered writer/readers—not a PID
    // reopen, substitute process or elapsed-time inference.
    let returned = resources.child.as_mut().map(Child::try_wait);
    match returned {
        Some(Ok(None)) => {
            inner.windows_test.live.store(true, Ordering::SeqCst);
            inner.windows_test.ready.send_replace(true);
        },
        Some(Ok(Some(status))) => {
            resources.waited = Some(status); // Record an actual early original wait.
            owner.fail(BridgeError::new("fixture_early_exit", "The owned child was not outstanding."));
        },
        _ => owner.unknown(inner),
    }
}

struct Observation {
    result: Result<Value, BridgeError>,
    native: Option<(native::FullwalkFacts, VerifiedRuntime, String, bool)>,
    child: bool,
    kill: bool,
    write_complete: bool,
    live: bool,
}
async fn retain_originals(supervisor: &Supervisor, owner: &Arc<Owner>, case: Case,
    method: Method, phase: PhaseMarker) -> Observation {
    owner.unknown(&supervisor.inner);
    diagnostic(case, method, phase);
    pending::<Observation>().await // Borrow THIS owner/supervisor; no replacement controller.
}
async fn case(case: Case, method: Method, params: Value) -> Observation {
    diagnostic(case, method, PhaseMarker::Start);
    let supervisor = Supervisor::new(RuntimeConfig::installed_windows_passive_candidate());
    *lock(&supervisor.inner.windows_test.case) = case;
    let mut created = supervisor.inner.windows_test.ready.subscribe();
    let ticket = supervisor.start_passive(method, params).expect("fixed request registration");
    let owner = ticket.owner.clone();
    let endpoint = owner.endpoint();
    let response = ticket.wait(); tokio::pin!(response);
    let mut early = None;
    if case == Case::StopChild {
        tokio::select! {
            result = &mut response => early = Some(result),
            changed = created.changed() => {
                if changed.is_ok() && *created.borrow() {
                    owner.fail(BridgeError::new("cancelled", "Fixed Windows outstanding child cancellation."));
                } else { owner.unknown(&supervisor.inner); }
            },
        }
    }
    let result = match early { Some(result) => result, None => response.await };
    if result.as_ref().err().is_some_and(|error| error.code == "cleanup_unknown") {
        return retain_originals(&supervisor, &owner, case, method, PhaseMarker::QueryUnknown).await;
    }
    let observer = { owner.observer.lock().await.take() };
    let Some(mut observer) = observer else {
        return retain_originals(&supervisor, &owner, case, method, PhaseMarker::ObserverMissing).await;
    };
    if (&mut observer).await.is_err() {
        *owner.observer.lock().await = Some(observer);
        return retain_originals(&supervisor, &owner, case, method, PhaseMarker::ObserverFailed).await;
    }
    drop(observer);
    let management = {
        let state = lock(&owner.state);
        state.terminal && !state.unknown && state.endpoint == endpoint
            && state.driver_join == ManagementJoin::Returned && state.watchdog_join == ManagementJoin::Returned
    } && owner.driver.try_lock().is_ok_and(|slot| slot.is_none())
        && owner.watchdog.try_lock().is_ok_and(|slot| slot.is_none())
        && lock(&owner.permit).is_none() && supervisor.can_exit() && !supervisor.disabled() && !supervisor.stopping()
        && supervisor.inner.permits.available_permits() == ACTIVE_LIMIT;
    let resources = match owner.resources.try_lock() {
        Ok(resources) => resources,
        Err(_) => return retain_originals(&supervisor, &owner, case, method, PhaseMarker::ResourceBorrow).await,
    };
    let Some(originals) = resources.passive.as_ref() else {
        drop(resources);
        return retain_originals(&supervisor, &owner, case, method, PhaseMarker::SlotsMissing).await;
    };
    let slots = match originals.try_lock() {
        Ok(slots) => slots,
        Err(_) => return retain_originals(&supervisor, &owner, case, method, PhaseMarker::NativeBorrow).await,
    };
    // The driver deliberately consumes Child and both read DTOs before Ready.
    // The retained actual wait, not a live Child slot, proves that it existed.
    let child = resources.waited.is_some();
    let joined = resources.inspection_return == Some(ManagementJoin::Returned)
        && resources.inspection.is_none() && resources.inspection_error.is_none()
        && resources.acquisition.is_none() && resources.acquisition_error.is_none()
        && resources.writer.is_none() && resources.stdout.is_none() && resources.stderr.is_none()
        && resources.failed_writer.is_none() && resources.failed_stdout.is_none() && resources.failed_stderr.is_none();
    let consumers = ConsumerReturn {
        waited: child, acquisition: resources.acquisition_return, child_retained: resources.child.is_some(),
        write_returned: resources.write_end.is_some(), stdout_retained: resources.out_end.is_some(),
        stderr_retained: resources.err_end.is_some(), no_child_effect: slots.no_child_effect(),
        kill_attempted: resources.kill_attempted, io: *lock(&supervisor.inner.windows_test.consumed_io),
    }.consistent();
    let (inspection, acquisition) = passive_borrows(&resources);
    let native = if slots.never_started() {
        !resources.native_started && resources.native_return.is_none() && resources.native_settlement.is_none()
            && passive_never_started_clear(inspection, acquisition, true)
    } else {
        passive_completion_clear(inspection, acquisition, resources.native_started,
            resources.native_return.as_ref().is_some_and(Result::is_ok), resources.native_settlement.is_some(),
            matches!(resources.native_return.as_ref(), Some(Ok(CloseOutcome::Settled))), slots.settled())
    };
    if !management || !joined || !consumers || !native {
        drop(slots); drop(resources);
        return retain_originals(&supervisor, &owner, case, method, PhaseMarker::FinalityMissing).await;
    }
    let observation = Observation { result, native: slots.settled_observation(), child, kill: resources.kill_attempted,
        write_complete: resources.write_end.as_ref().is_some_and(|w| w.complete),
        live: supervisor.inner.windows_test.live.load(Ordering::SeqCst) };
    drop(slots); drop(resources);
    diagnostic(case, method, PhaseMarker::Settled);
    observation
}

#[test]
fn fixed_probe_and_candidate_are_bounded_and_nonshipping() {
    // Same DATA predicate as the native fixture, not invented native receipts.
    let mut io = ConsumedIo::Absent;
    io.record(Some((true, false)), Some((true, false)));
    let child = ConsumerReturn { waited: true, acquisition: Some(ManagementJoin::Returned),
        child_retained: false, write_returned: true, stdout_retained: false, stderr_retained: false,
        no_child_effect: false, kill_attempted: false, io };
    assert!(child.consistent());
    assert!(ConsumerReturn { kill_attempted: true, ..child }.consistent()); // Settled STOP; outcome/write completeness are separate.
    for wrong in [
        ConsumerReturn { waited: false, ..child }, ConsumerReturn { acquisition: None, ..child },
        ConsumerReturn { acquisition: Some(ManagementJoin::Pending), ..child },
        ConsumerReturn { acquisition: Some(ManagementJoin::Panicked), ..child },
        ConsumerReturn { child_retained: true, ..child }, ConsumerReturn { write_returned: false, ..child },
        ConsumerReturn { stdout_retained: true, ..child }, ConsumerReturn { stderr_retained: true, ..child },
        ConsumerReturn { no_child_effect: true, ..child }, ConsumerReturn { io: ConsumedIo::Absent, ..child },
    ] { assert!(!wrong.consistent()); }
    for wrong in [
        ConsumedIo::Once { stdout: None, stderr: Some((true, false)) },
        ConsumedIo::Once { stdout: Some((true, false)), stderr: None },
        ConsumedIo::Once { stdout: Some((false, false)), stderr: Some((true, false)) },
        ConsumedIo::Once { stdout: Some((true, false)), stderr: Some((false, false)) },
        ConsumedIo::Once { stdout: Some((true, true)), stderr: Some((true, false)) },
        ConsumedIo::Once { stdout: Some((true, false)), stderr: Some((true, true)) },
    ] { assert!(!ConsumerReturn { io: wrong, ..child }.consistent()); }
    io.record(Some((true, false)), Some((true, false)));
    assert_eq!(io, ConsumedIo::Repeated);
    assert!(!ConsumerReturn { io, ..child }.consistent());
    io.record(Some((true, false)), Some((true, false)));
    assert_eq!(io, ConsumedIo::Repeated);
    let no_child = ConsumerReturn { waited: false, acquisition: None, write_returned: false,
        no_child_effect: true, io: ConsumedIo::Absent, ..child };
    assert!(no_child.consistent()); // Closed method; native never-started shape checked separately.
    assert!(ConsumerReturn { acquisition: Some(ManagementJoin::Returned), ..no_child }.consistent()); // Preclaim STOP.
    for wrong in [
        ConsumerReturn { waited: true, ..no_child }, ConsumerReturn { no_child_effect: false, ..no_child },
        ConsumerReturn { write_returned: true, ..no_child }, ConsumerReturn { kill_attempted: true, ..no_child },
        ConsumerReturn { acquisition: Some(ManagementJoin::Pending), ..no_child },
        ConsumerReturn { io: child.io, ..no_child }, ConsumerReturn { io: ConsumedIo::Repeated, ..no_child },
    ] { assert!(!wrong.consistent()); }
    assert_eq!(PROBE.len(), 27173);
    assert!(probe_command_units(&"a".repeat(507), &"a".repeat(507)).is_some());
    assert!(probe_command_units(&"a".repeat(32767), "C:\\core.zip").is_none());
    let normal = RuntimeConfig::packaged(PathBuf::new());
    for name in ["capabilities", "catalog", "project.snapshot", "config.validate", "config.suggest", "config.preview"] {
        assert!(!normal.passive_method_available(name));
    }
    let candidate = RuntimeConfig::installed_windows_passive_candidate();
    for name in ["project.snapshot", "credentials.assess", "config.save", "android.build", "github.setup.propose", "environment.requirements"] {
        assert!(!candidate.passive_method_available(name));
    }
    assert!(!candidate.project_selection_profile_available() && !candidate.configuration_edit_profile_available());
    assert!(candidate.resolve(Instant::now()).is_err());
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "fixed reviewed Windows installed-passive original ordinary owner only; no local/raw invocation"]
async fn native_installed_passive_original_owner_contract() {
    native::require_passive_qualification().expect("fixed original Windows qualification binding");
    let reporting_end = Instant::now() + Duration::from_secs(80); // One batch boundary inside its original90s outer owner.
    let mut completed_methods = 0;
    let mut settled_owners = 0;
    let mut original = None;
    for (method, params) in [
        (Method::Capabilities, json!({})), (Method::Catalog, json!({})),
        (Method::ValidateConfig, json!({"draft":{}})), (Method::SuggestConfig, json!({"hints":{}})),
        (Method::PreviewConfig, json!({"base":null,"draft":{}})),
    ] {
        assert!(Instant::now() < reporting_end, "original Windows batch expired before next query");
        let observed = case(Case::Engine, method, params).await;
        let value = observed.result.expect("real unchanged-engine response");
        assert!(observed.child && !observed.kill && observed.write_complete);
        let (facts, _, _, claimed) = observed.native.expect("settled admitted Windows loader book");
        assert!(claimed);
        match method {
            Method::Capabilities => assert_eq!(value["hostPlatform"], "windows"),
            Method::Catalog => assert!(value["schema"].is_object() && value["fields"].is_array()),
            Method::ValidateConfig => assert_eq!(value["valid"], false),
            Method::SuggestConfig => assert!(value["draft"].is_object() && value["provenance"].is_array()),
            Method::PreviewConfig => assert_eq!(value["comparison"]["kind"], "proposed-create"),
            _ => unreachable!(),
        }
        if let Some(prior) = &original {
            let prior: &native::FullwalkFacts = prior;
            assert_eq!(facts.version_identity, prior.version_identity);
            assert_eq!(facts.selected_identities, prior.selected_identities);
            assert_eq!(facts.account_sid_sha256, prior.account_sid_sha256);
        } else { original = Some(facts); }
        completed_methods += 1; settled_owners += 1;
    }
    assert!(Instant::now() < reporting_end, "original Windows batch expired before closure");
    let observed = case(Case::Closure, Method::Catalog, json!({})).await;
    assert!(observed.child && !observed.kill && observed.write_complete);
    let value = observed.result.expect("actual installed import/image closure");
    let (facts, selection, system_root, claimed) = observed.native.unwrap();
    assert!(claimed);
    assert_eq!(value["scope"], "windows-embedded-payload-native-v1");
    assert_eq!(value["manifestSha256"], facts.manifest_sha256);
    assert_eq!(value["coreSha256"], facts.core_sha256);
    assert_eq!(value["executable"].as_str(), selection.python.to_str());
    assert_eq!(value["environment"]["SystemRoot"].as_str(), Some(system_root.as_str()));
    assert_eq!(value["imports"].as_array().unwrap().len(), 15);
    let mut names = BTreeSet::new();
    let mut payload_images = 0; let mut system_images = 0;
    for image in value["loadedImages"].as_array().unwrap() {
        let name = image["name"].as_str().unwrap(); assert!(names.insert(name));
        match image["origin"].as_str() {
            Some("payload") => payload_images += 1,
            Some("system32") => { assert!(native::SystemImage::from_name(name).is_some()); system_images += 1; },
            _ => panic!("unadmitted installed code origin"),
        }
    }
    assert!((22..=33).contains(&payload_images) && (1..=31).contains(&system_images));
    settled_owners += 1;
    assert!(Instant::now() < reporting_end, "original Windows batch expired before preclaim case");
    let before = case(Case::StopBeforeClaim, Method::Capabilities, json!({})).await;
    let before_stopped = before.result.as_ref().err().is_some_and(|e| e.code == "cancelled")
        && !before.child && !before.kill && before.native.as_ref().is_some_and(|(_, _, _, claimed)| !claimed);
    assert!(before_stopped); settled_owners += 1;
    assert!(Instant::now() < reporting_end, "original Windows batch expired before child case");
    let child = case(Case::StopChild, Method::Catalog, json!({})).await;
    let child_stopped = child.result.as_ref().err().is_some_and(|e| e.code == "cancelled")
        && child.child && child.kill && child.live && !child.write_complete
        && child.native.as_ref().is_some_and(|(_, _, _, claimed)| *claimed);
    assert!(child_stopped); settled_owners += 1;
    assert!(Instant::now() < reporting_end, "original Windows batch expired before closed-method case");
    let closed = case(Case::Engine, Method::ProjectSnapshot, json!({"root":"Z:\\must-not-open"})).await;
    assert!(closed.result.as_ref().err().is_some_and(|e| e.code == "runtime_unavailable")
        && !closed.child && !closed.kill && closed.native.is_none());
    settled_owners += 1;
    assert!(Instant::now() < reporting_end, "original Windows batch observation/settlement expired");
    let facts = native::PassiveFacts { version: original.unwrap(), completed_methods, settled_owners,
        payload_images, system_images, stopped_before_claim: before_stopped, stopped_owned_child: child_stopped };
    native::write_passive_result_once(&facts, reporting_end).expect("original passive result write/close");
}
