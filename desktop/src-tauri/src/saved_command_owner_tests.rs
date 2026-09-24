//! Inert finite-domain/clock/decoder vectors. Invented DATA and memory IO below
//! are not runtime/tool/process custody, original native joins or qualification.
//! No test opens a file, inspects a runtime, launches a process or makes a permit.
use super::*;
use std::path::PathBuf;
use serde_json::{json, Value};

fn project() -> RegisteredRoot { RegisteredRoot { path: PathBuf::from("/unopened-saved-command-project"),
    identity: crate::asset_source::ProjectIdentity::Posix(crate::asset_source::DirectoryIdentity::synthetic_evidence_identity()) } }
fn application(domain: SavedCommandDomain) -> SavedCommandOwner {
    SavedCommandOwner::new(RuntimeConfig::packaged(PathBuf::from("/unopened-saved-command-runtime")), domain)
}
fn context(domain: SavedCommandDomain) -> Context { match domain {
    SavedCommandDomain::OfflinePreflight => Context::OfflinePreflight(wire::tests::context()),
    SavedCommandDomain::AndroidBuild => Context::AndroidBuild(android_wire::tests::context()),
} }
fn projection(domain: SavedCommandDomain) -> RunProjection { RunProjection {
    operation_id: "a".repeat(32), owner_generation: "b".repeat(32), context: context(domain),
    phase: Phase::AwaitingConsent, intent_usable: true, outcome: None, reason: Reason::None, result: None, stage: None,
} }
fn active(domain: SavedCommandDomain) -> (SavedCommandOwner, Arc<Session>) {
    active_in(application(domain))
}
// Only cfg(test) DATA. A clone keeps the existing bridge owner's Arc; no
// replacement registry/permit, native handle or positive receipt is installed.
fn active_in(application: SavedCommandOwner) -> (SavedCommandOwner, Arc<Session>) {
    let domain = application.inner.domain; let mut p = projection(domain);
    let (stop, _) = watch::channel(false); let (pipes, _) = watch::channel(Pipes::Pending);
    let (frames, receiver) = mpsc::channel(2);
    let clocks = Clocks::new(domain, Instant::now());
    let (native_audit_cutoff, _) = watch::channel(clocks.work);
    let profile = match domain { SavedCommandDomain::OfflinePreflight => Profile::OfflinePreflight(wire::Profile::LinuxX64),
        SavedCommandDomain::AndroidBuild => Profile::AndroidBuild(android_wire::Profile::LinuxX64) };
    let owner = Arc::new(Session { domain, id: p.operation_id.clone(), generation: p.owner_generation.clone(), context: p.context.clone(),
        profile, clocks, registration: 1, project: project(), request: AsyncMutex::new(None),
        stop, pipes, frames, wake: Notify::new(), native_audit_cutoff, output_bytes: AtomicUsize::new(0), resource_unknown: AtomicBool::new(false),
        driver_done: AtomicBool::new(false), driver_joined: AtomicBool::new(false), driver_failed: AtomicBool::new(false),
        watchdog_joined: AtomicBool::new(false), watchdog_failed: AtomicBool::new(false), manager_failed: AtomicBool::new(false),
        startup: Mutex::new(Startup::default()), resources: AsyncMutex::new(Resources { frames: Some(receiver), ..Resources::default() }),
        input: Arc::new(AsyncMutex::new(Pipe::default())), output: Arc::new(AsyncMutex::new(Pipe::default())), error: Arc::new(AsyncMutex::new(Pipe::default())),
        driver: AsyncMutex::new(None), watchdog: Mutex::new(None), manager: AsyncMutex::new(None), observer: AsyncMutex::new(None),
        driver_return: Mutex::new(None), manager_return: Mutex::new(None), observer_return: Mutex::new(None), watchdog_return: Mutex::new(None),
        #[cfg(all(test, debug_assertions, feature = "development-runtime", not(feature = "desktop-shell"),
            any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64"))))]
        fixture: None,
    });
    p.phase = Phase::Starting; p.intent_usable = false;
    application.inner.lock().active = Some(Active { owner: owner.clone(), projection: p, first_stop: None, work_expired: false,
        accepted: false, terminal: false, unknown: false, final_join_seen: false });
    (application, owner)
}

#[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
fn bound_document_model() -> (Arc<crate::bridge::DesktopBridge>, crate::asset_session::DocumentBinding) {
    // The normal bridge constructor creates an EditOwner nonce, not a runtime
    // or task. These invented lifecycle inputs do not qualify a native hook.
    let bridge = Arc::new(crate::bridge::DesktopBridge::new("/unopened-document-model-runtime".into()));
    assert!(!bridge.edits.disabled());
    let document = crate::asset_session::DocumentBinding::new(bridge.clone());
    document.hook_installed();
    document.observe(|lifetime| lifetime.started(true));
    document.observe(|lifetime| lifetime.finished(true));
    (bridge, document)
}

#[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
#[test]
fn document_prepared_saved_domains_exclude_peers_and_retire_before_configuration_callback() {
    for domain in [SavedCommandDomain::OfflinePreflight, SavedCommandDomain::AndroidBuild] {
        let (bridge, document) = bound_document_model();
        let original = match domain {
            SavedCommandDomain::OfflinePreflight => bridge.preflight.original_for_test(),
            SavedCommandDomain::AndroidBuild => bridge.android_build.original_for_test(),
        };
        original.inner.lock().prepared = Some(Prepared { projection: projection(domain),
            expires: Instant::now() + INTENT, registration: bridge.registry_generation(), project: project() });
        assert!(!original.inner.qualified());
        assert_eq!(document.offline_preflight_status().unwrap().availability, wire::Availability::Busy);
        assert_eq!(document.android_build_status().unwrap().availability, android_wire::Availability::Busy);
        assert_eq!(document.environment_diagnostics_status().unwrap().capability.reason,
            crate::environment_diagnostics_protocol::Availability::Busy);
        assert!(document.open_session().err().unwrap().reason == crate::asset_commands::Reason::Busy);
        assert_eq!(document.passive_query(&bridge, crate::protocol::Method::Catalog, json!({})).err().unwrap().code, domain.busy().code);
        assert_eq!(bridge.open_config_edit("main", "unregistered-model".into()).err().unwrap().code, domain.busy().code);
        // Only the document's actual admission callback runs; this callback
        // writes no file, creates no EditOwner session and cannot launch work.
        let entered = std::cell::Cell::new(false);
        document.configuration_edit_admit(|_| { entered.set(true); Ok(()) }).unwrap();
        assert!(entered.get() && original.can_exit());
        let r = original.inner.lock();
        assert!(r.prepared.is_none() && r.active.is_none());
        let retired = r.last.as_ref().unwrap();
        assert_eq!(retired.reason, Reason::ContextChanged);
        assert!(!retired.intent_usable && retired.result.is_none());
        drop(r);
        // Removing the redundant shell idle check does not bypass shutdown or
        // document loss: the same admission method must still refuse callback.
        entered.set(false); original.request_shutdown();
        assert_eq!(document.configuration_edit_admit(|_| { entered.set(true); Ok(()) }).err().unwrap().code, "shutting_down");
        document.lost();
        assert!(document.configuration_edit_admit(|_| { entered.set(true); Ok(()) }).is_err());
        assert!(!entered.get());
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
#[test]
fn document_active_saved_domains_stop_before_writes_and_unknown_retains_status_and_cancel() {
    for domain in [SavedCommandDomain::OfflinePreflight, SavedCommandDomain::AndroidBuild] {
        let (bridge, document) = bound_document_model();
        let original = match domain {
            SavedCommandDomain::OfflinePreflight => bridge.preflight.original_for_test(),
            SavedCommandDomain::AndroidBuild => bridge.android_build.original_for_test(),
        };
        let (application, owner) = active_in(original.clone());
        assert!(Arc::ptr_eq(&application.inner, &original.inner) && !application.inner.qualified());
        // Real mutex contention keeps reconciliation observation-only while
        // exercising Active. There is NO synthetic JoinHandle/return receipt.
        // Once released, the real missing-original path must become Unknown.
        let watchdog = owner.watchdog.lock().unwrap();
        assert!(watchdog.is_none());
        assert_eq!(document.offline_preflight_status().unwrap().availability, wire::Availability::Busy);
        assert_eq!(document.android_build_status().unwrap().availability, android_wire::Availability::Busy);
        assert_eq!(document.environment_diagnostics_status().unwrap().capability.reason,
            crate::environment_diagnostics_protocol::Availability::Busy);
        assert!(document.open_session().err().unwrap().reason == crate::asset_commands::Reason::Busy);
        assert_eq!(document.passive_query(&bridge, crate::protocol::Method::Catalog, json!({})).err().unwrap().code, domain.busy().code);
        let entered = std::cell::Cell::new(false);
        assert_eq!(document.configuration_edit_admit(|_| { entered.set(true); Ok(()) }).err().unwrap().code, domain.busy().code);
        assert!(!entered.get() && *owner.stop.borrow());
        let lookup = std::cell::Cell::new(false);
        assert!(document.workflow_edit_admit(|_| { lookup.set(true); Ok("unregistered-model".into()) }, |_, _| Ok(())).is_err());
        assert!(!lookup.get());
        let first_stop = {
            let r = application.inner.lock(); let a = r.active.as_ref().unwrap();
            assert!(Arc::ptr_eq(&a.owner, &owner) && !a.unknown && !a.final_join_seen && r.last.is_none());
            assert_eq!(a.projection.reason, Reason::ContextChanged); a.first_stop.unwrap()
        };
        drop(watchdog);
        assert!(!application.can_exit() && application.disabled());
        assert_eq!(document.offline_preflight_status().unwrap().availability, wire::Availability::CleanupUnknown);
        assert_eq!(document.android_build_status().unwrap().availability, android_wire::Availability::CleanupUnknown);
        assert_eq!(document.passive_query(&bridge, crate::protocol::Method::Catalog, json!({})).err().unwrap().code, "cleanup_unknown");
        assert!(document.configuration_edit_admit(|_| { entered.set(true); Ok(()) }).is_err());
        assert!(!entered.get());
        document.lost(); application.request_shutdown();
        match domain {
            SavedCommandDomain::OfflinePreflight => {
                let status = document.cancel_offline_preflight(wire::Cancel { operation_id: owner.id.clone(), owner_generation: owner.generation.clone() }).unwrap();
                assert_eq!(status.operation.unwrap().phase, wire::Phase::Unknown);
            },
            SavedCommandDomain::AndroidBuild => {
                let status = document.cancel_android_build(android_wire::Cancel { operation_id: owner.id.clone(), owner_generation: owner.generation.clone() }).unwrap();
                assert_eq!(status.operation.unwrap().phase, android_wire::Phase::Unknown);
            },
        }
        let r = application.inner.lock(); let a = r.active.as_ref().unwrap();
        assert!(Arc::ptr_eq(&a.owner, &owner) && a.unknown && !a.final_join_seen && r.last.is_none());
        assert_eq!(a.first_stop, Some(first_stop)); assert!(a.projection.public().result.is_none());
        let resources = owner.resources.try_lock().unwrap();
        assert!(resources.inspection.is_none() && resources.acquisition.is_none() && resources.child.is_none());
        assert!(resources.writer.is_none() && resources.stdout.is_none() && resources.stderr.is_none());
        assert!(!owner.startup.lock().unwrap().attempted && owner.driver_return.lock().unwrap().is_none()
            && owner.manager_return.lock().unwrap().is_none() && owner.observer_return.lock().unwrap().is_none()
            && owner.watchdog_return.lock().unwrap().is_none());
        // This model proves gate/STOP behavior only. Acquired active custody,
        // native dialog quit, positive joins and actual disposal remain hosted.
    }
}

fn android_terminal(value: &Value) -> android_wire::Terminal {
    android_wire::terminal(value, &android_wire::tests::context()).unwrap()
}
fn frame(domain: SavedCommandDomain, sequence: u32, kind: &str, payload: Value) -> Vec<u8> {
    let protocol = match domain { SavedCommandDomain::OfflinePreflight => wire::PROTOCOL, SavedCommandDomain::AndroidBuild => android_wire::PROTOCOL };
    let mut bytes = serde_json::to_vec(&json!({"protocol":protocol,"operationId":"a".repeat(32),"ownerGeneration":"b".repeat(32),
        "sequence":sequence,"kind":kind,"payload":payload})).unwrap(); bytes.push(b'\n'); bytes
}
fn accepted(domain: SavedCommandDomain) -> Vec<u8> {
    let context = match context(domain) { Context::OfflinePreflight(c) => serde_json::to_value(c).unwrap(),
        Context::AndroidBuild(c) => serde_json::to_value(c).unwrap() };
    frame(domain, 0, "accepted", json!({"schemaVersion":1,"context":context}))
}
fn complete_stream(domain: SavedCommandDomain, progress: bool) -> Vec<Vec<u8>> {
    let mut frames = vec![accepted(domain)];
    match domain {
        SavedCommandDomain::OfflinePreflight => {
            let wire::Frame::Terminal(terminal) = wire::tests::terminal_frame(&wire::tests::context()) else { panic!("offline DATA") };
            frames.push(frame(domain, 1, "terminal", serde_json::to_value(terminal).unwrap()));
        }
        SavedCommandDomain::AndroidBuild => {
            if progress { for stage in ["inputs-bound", "building", "capturing", "inspecting", "disposing-work"] {
                frames.push(frame(domain, frames.len() as u32, "progress", json!({"schemaVersion":1,"stage":stage})));
            } }
            frames.push(frame(domain, frames.len() as u32, "terminal", android_wire::tests::complete_with_failed_inspection()));
        }
    }
    frames
}

#[test]
fn two_domains_have_fixed_nonrenewable_clocks_and_distinct_limits() {
    let admitted = Instant::now();
    assert_eq!(INTENT, Duration::from_secs(300));
    for (domain, work, hard, request, frames) in [
        (SavedCommandDomain::OfflinePreflight, 1800, 1810, 16384, 2),
        (SavedCommandDomain::AndroidBuild, 3000, 3010, 32768, 8),
    ] {
        let c = Clocks::new(domain, admitted);
        assert_eq!(c.work, admitted + Duration::from_secs(work));
        assert_eq!(c.finality, admitted + Duration::from_secs(hard));
        assert_eq!(c.settlement(None), c.finality);
        assert_eq!(c.settlement(Some(admitted + Duration::from_secs(2))), admitted + Duration::from_secs(12));
        assert_eq!(c.settlement(Some(c.finality)), c.finality);
        assert_eq!((domain.request_limit(), domain.response_limit(), domain.frame_limit()), (request, 65536, frames));
    }
}

#[test]
fn typed_consent_cannot_cross_domains_and_android_burns_before_any_custody() {
    let owner = application(SavedCommandDomain::AndroidBuild);
    let offline = wire::prepare(&json!({"projectId":"inert-offline","draftRevision":2,"baselineGeneration":3,
        "savedConfig":{"bytes":512,"sha256":"c".repeat(64)}})).unwrap();
    let revision = owner.inner.lock().revision;
    assert!(owner.prepare_offline(offline, 1, project(), wire::Availability::Available).is_err());
    assert_eq!(owner.inner.lock().revision, revision);
    assert!(owner.inner.lock().prepared.is_none() && owner.inner.lock().active.is_none());
    assert!(!owner.inner.qualified());
    let wrong_consent = json!({"operationId":"a".repeat(32),"ownerGeneration":"b".repeat(32),"consentVersion":wire::CONSENT});
    assert!(android_wire::start(&wrong_consent).is_err());
    // Unacquired comparison DATA alone cannot arm Android. Inserting an inert
    // intent tests one-use refusal; it does not install a qualification permit.
    owner.inner.lock().prepared = Some(Prepared { projection: projection(SavedCommandDomain::AndroidBuild),
        expires: Instant::now() + INTENT, registration: 1, project: project() });
    assert!(owner.start_offline(wire::start(&wrong_consent).unwrap(), Instant::now(), Some((1, project())), wire::Availability::Available).is_err());
    assert!(owner.inner.lock().prepared.is_some());
    let request = json!({"operationId":"a".repeat(32),"ownerGeneration":"b".repeat(32),"consentVersion":android_wire::CONSENT});
    let status = owner.start_android(android_wire::start(&request).unwrap(), Instant::now(), Some((1, project())),
        android_wire::Availability::Available).unwrap().release();
    let p = status.operation.unwrap();
    assert_eq!((p.phase, p.outcome), (android_wire::Phase::Terminal, Some(android_wire::Outcome::Refused)));
    assert!(p.result.is_none() && p.activity.is_none() && p.disposition.is_none() && p.stage.is_none());
    assert!(owner.inner.lock().prepared.is_none() && owner.inner.lock().active.is_none());
    assert!(owner.start_android(android_wire::start(&request).unwrap(), Instant::now(), Some((1, project())),
        android_wire::Availability::Available).is_err());
}

#[test]
fn unsupported_android_without_originals_never_claims_document_loss() {
    let owner = application(SavedCommandDomain::AndroidBuild);
    owner.document_lost();
    let status = owner.status_android(android_wire::Availability::UnsupportedPlatform).unwrap();
    assert_eq!(status.availability, android_wire::Availability::UnsupportedPlatform);
    assert!(status.operation.is_none() && owner.can_exit());
}

#[tokio::test]
async fn missing_android_tool_custody_refuses_before_inspection_or_acquisition() {
    let (application, owner) = active(SavedCommandDomain::AndroidBuild);
    // Missing fixed selection/qualification refuses before the implemented
    // custody path. An inert Session cannot turn its DTO into authority.
    start_original(&application.inner, &owner).await;
    let book = owner.resources.lock().await;
    assert!(book.inspection.is_none() && book.acquisition.is_none() && book.child.is_none());
    assert!(book.writer.is_none() && book.stdout.is_none() && book.stderr.is_none());
    assert!(!native_final(&book, SavedCommandDomain::AndroidBuild));
    assert!(native_final(&book, SavedCommandDomain::OfflinePreflight)); // Added conjunct never borrows Offline tools.
    assert!(!owner.startup.lock().unwrap().attempted && owner.request.lock().await.is_none());
    let r = application.inner.lock(); let a = r.active.as_ref().unwrap();
    assert_eq!((a.projection.reason, a.projection.outcome), (Reason::ToolchainUnavailable, Some(Outcome::Refused)));
    assert!(a.first_stop.is_some() && !a.terminal && !a.final_join_seen && r.last.is_none());
}

#[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
#[tokio::test]
async fn failed_original_startup_tasks_keep_ready_errors_and_are_not_repolled() {
    let (application, owner) = active(SavedCommandDomain::AndroidBuild);
    {
        let mut book = owner.resources.lock().await;
        // Real memory-task handles, not native inspection/acquisition success.
        book.inspection = Some(tokio::spawn(pending::<Result<VerifiedRuntime, BridgeError>>()));
        book.acquisition = Some(tokio::spawn(pending::<()>()));
        assert!(!native_consumers_returned(&book, &owner.startup.lock().unwrap(), &application.inner, &owner));
        book.inspection_failed = true; book.acquisition_failed = true;
        assert!(!native_consumers_returned(&book, &owner.startup.lock().unwrap(), &application.inner, &owner));
        book.inspection_failed = false; book.acquisition_failed = false;
        book.inspection.as_ref().unwrap().abort(); book.acquisition.as_ref().unwrap().abort();
    }
    continue_original(&application.inner, &owner).await;
    {
        let book = owner.resources.lock().await;
        assert!(book.inspection_failed && !book.inspection_joined && book.inspection.is_some());
        assert!(book.acquisition_failed && !book.acquisition_joined && book.acquisition.is_some());
        assert!(book.inspection_error.as_ref().is_some_and(|e| e.is_cancelled()));
        assert!(book.acquisition_error.as_ref().is_some_and(|e| e.is_cancelled()));
        // Actual failed Ready joins prove only that these no-launch borrowers
        // returned. Missing books/native finality still cannot become Complete.
        assert!(native_consumers_returned(&book, &owner.startup.lock().unwrap(), &application.inner, &owner));
        assert!(book.native.is_none() && !book.native_started && !native_final(&book, owner.domain));
    }
    continue_original(&application.inner, &owner).await; // Re-polling either completed handle would panic.
    let book = owner.resources.lock().await;
    assert!(book.inspection_error.is_some() && book.acquisition_error.is_some());
    assert!(!owner.startup.lock().unwrap().attempted && book.child.is_none());
    assert!(owner.resource_unknown.load(Ordering::SeqCst) && !application.can_exit());
}

#[tokio::test]
async fn late_inspection_data_is_cleanup_only_and_cannot_rearm_acquisition() {
    let (application, owner) = active(SavedCommandDomain::AndroidBuild);
    let (release, enter) = oneshot::channel();
    owner.resources.lock().await.inspection = Some(tokio::spawn(async move {
        enter.await.unwrap();
        // Unopened path DATA is deliberately not a native custody fixture.
        Ok(VerifiedRuntime { python: "/unopened/python".into(), bootstrap: "/unopened/bootstrap".into(),
            core: "/unopened/core".into(), cwd: "/unopened".into() })
    }));
    application.inner.advance_locked(&mut application.inner.lock(), &owner, owner.clocks.finality);
    release.send(()).unwrap();
    continue_original(&application.inner, &owner).await;
    start_original(&application.inner, &owner).await;
    let book = owner.resources.lock().await;
    assert!(book.inspection_joined && !book.inspection_failed && book.inspection.is_none());
    assert!(book.acquisition.is_none() && !book.acquisition_joined && book.child.is_none());
    assert!(!book.native_started && !owner.startup.lock().unwrap().attempted);
    assert!(owner.request.lock().await.is_none());
    let r = application.inner.lock(); let active = r.active.as_ref().unwrap();
    assert!(Arc::ptr_eq(&active.owner, &owner) && active.unknown && r.last.is_none());
    assert_eq!(active.first_stop, Some(owner.clocks.work));
    assert!(active.projection.public().result.is_none());
}

#[tokio::test]
async fn late_positive_memory_returns_cannot_retire_unknown_and_original_cutoff_never_renews() {
    for domain in [SavedCommandDomain::OfflinePreflight, SavedCommandDomain::AndroidBuild] {
        let (application, owner) = active(domain);
        assert!(!application.inner.qualified());
        let cutoff = owner.native_audit_cutoff.subscribe();
        assert_eq!(*cutoff.borrow(), owner.clocks.work);
        {
            let mut r = application.inner.lock();
            application.inner.stop_locked(&mut r, &owner, Reason::Cancelled, owner.clocks.admitted);
            application.inner.stop_locked(&mut r, &owner, Reason::Shutdown, owner.clocks.admitted + Duration::from_secs(5));
            assert_eq!(r.active.as_ref().unwrap().first_stop, Some(owner.clocks.admitted));
            let expected = if domain == SavedCommandDomain::AndroidBuild { owner.clocks.admitted + SETTLEMENT } else { owner.clocks.work };
            assert_eq!(*cutoff.borrow(), expected);
            application.inner.advance_locked(&mut r, &owner, owner.clocks.admitted + SETTLEMENT);
            assert!(!final_clock_clear(&r, &owner, owner.clocks.admitted + SETTLEMENT));
        }
        // These true payloads are arbitrary memory DATA to attack the final
        // join envelope, NOT invented positive native/resource receipts. There
        // is no native book, child, runtime, permit or successful final owner.
        *owner.observer.lock().await = Some(tokio::spawn(async { true }));
        assert!(!watchdog(application.inner.clone(), owner.clone(), Guard::new(&application.inner, &owner)).await);
        assert!(matches!(&*owner.observer_return.lock().unwrap(), Some(Ok(true))));
        assert!(owner.observer.lock().await.is_some()); // Veto precedes observer.take().
        assert!(application.inner.lock().active.as_ref().unwrap().unknown);

        // Separately attack the last synchronous reconciliation boundary with
        // an actual Ready memory task: its old positive DATA must be retained,
        // never repolled and never allowed to remove the now Unknown Active.
        let (application, owner) = active(domain);
        let (release, enter) = oneshot::channel(); let (sent, ready) = oneshot::channel();
        *owner.watchdog.lock().unwrap() = Some(tokio::spawn(async move {
            enter.await.unwrap(); sent.send(()).unwrap(); true
        }));
        release.send(()).unwrap(); ready.await.unwrap();
        application.inner.advance_locked(&mut application.inner.lock(), &owner, owner.clocks.finality);
        application.reconcile(); application.reconcile();
        assert!(matches!(&*owner.watchdog_return.lock().unwrap(), Some(Ok(true))));
        assert!(owner.watchdog.lock().unwrap().is_some());
        let r = application.inner.lock(); let active = r.active.as_ref().unwrap();
        assert!(Arc::ptr_eq(&active.owner, &owner) && active.unknown && active.final_join_seen && r.disabled && r.last.is_none());
        assert!(active.projection.public().result.is_none()); drop(r);
        assert!(!application.can_exit());
    }
}

#[test]
fn foreign_domain_frames_fail_closed_without_converting_any_result() {
    for domain in [SavedCommandDomain::OfflinePreflight, SavedCommandDomain::AndroidBuild] {
        let (application, owner) = active(domain);
        let foreign = match domain { SavedCommandDomain::OfflinePreflight => Frame::AndroidBuild(android_wire::Frame::Accepted),
            SavedCommandDomain::AndroidBuild => Frame::OfflinePreflight(wire::Frame::Accepted) };
        application.inner.accept_at(&owner, foreign, owner.clocks.admitted);
        let r = application.inner.lock(); let a = r.active.as_ref().unwrap();
        assert!(a.unknown && r.disabled && !a.accepted && !a.terminal);
        assert_eq!(a.projection.reason, Reason::ProtocolError);
        assert_eq!(a.projection.public().reason, Reason::CleanupUnknown);
        assert!(a.projection.public().result.is_none() && a.projection.stage.is_none());
    }
}

#[test]
fn android_complete_with_policy_fail_is_provisional_and_late_data_never_undoes_f() {
    for due in [ANDROID_WORK, ANDROID_HARD] { for clock_first in [false, true] {
        let (application, owner) = active(SavedCommandDomain::AndroidBuild); let t = owner.clocks.admitted;
        application.inner.accept_at(&owner, Frame::AndroidBuild(android_wire::Frame::Accepted), t);
        application.inner.accept_at(&owner, Frame::AndroidBuild(android_wire::Frame::Progress(android_wire::Stage::Inspecting)), t);
        let now = t + due;
        if clock_first { application.inner.advance_locked(&mut application.inner.lock(), &owner, now); }
        application.inner.accept_at(&owner, Frame::AndroidBuild(android_wire::Frame::Terminal(
            android_terminal(&android_wire::tests::complete_with_failed_inspection()))), now);
        application.inner.advance_locked(&mut application.inner.lock(), &owner, now);
        let r = application.inner.lock(); let a = r.active.as_ref().unwrap();
        assert_eq!((a.first_stop, a.projection.reason, a.projection.outcome), (Some(owner.clocks.work), Reason::TimedOut, Some(Outcome::TimedOut)));
        assert_eq!(a.unknown, due == ANDROID_HARD);
        assert!(a.projection.public().result.is_none() && r.last.is_none());
    } }
    let (application, owner) = active(SavedCommandDomain::AndroidBuild); let t = owner.clocks.admitted;
    application.inner.accept_at(&owner, Frame::AndroidBuild(android_wire::Frame::Accepted), t);
    application.inner.accept_at(&owner, Frame::AndroidBuild(android_wire::Frame::Terminal(
        android_terminal(&android_wire::tests::complete_with_failed_inspection()))), t);
    let r = application.inner.lock(); let a = r.active.as_ref().unwrap();
    assert!(a.first_stop.is_none() && a.projection.result.is_some() && !a.final_join_seen);
    let p = a.projection.public().android().unwrap();
    assert_eq!(p.stage, Some(android_wire::Stage::DisposingWork));
    assert!(p.outcome.is_none() && p.result.is_none() && p.activity.is_none() && p.disposition.is_none());
    assert!(owner.watchdog_return.lock().unwrap().is_none() && r.last.is_none());
}

#[test]
fn known_retained_work_preserves_failed_outcome_and_original_stop_reason() {
    for (reason, core_stop) in [(Reason::Cancelled, "cancelled"), (Reason::TimedOut, "timed-out")] {
        let (application, owner) = active(SavedCommandDomain::AndroidBuild); let t = owner.clocks.admitted;
        application.inner.accept_at(&owner, Frame::AndroidBuild(android_wire::Frame::Accepted), t);
        application.inner.stop_locked(&mut application.inner.lock(), &owner, reason, t);
        let mut data = android_wire::tests::negative_terminal(7);
        data["reason"] = json!(core_stop); data["lifetime"]["stopObserved"] = json!(core_stop);
        data["disposition"]["work"] = json!("retained-work");
        application.inner.accept_at(&owner, Frame::AndroidBuild(android_wire::Frame::Terminal(android_terminal(&data))), t);
        let mut r = application.inner.lock(); let a = r.active.as_ref().unwrap();
        assert_eq!((a.first_stop, a.projection.reason, a.projection.outcome), (Some(t), reason, Some(Outcome::Failed)));
        assert!(a.projection.public().result.is_none() && !a.final_join_seen);
        // Projection-only predicate, NOT a filled native join or published
        // terminal: the active owner's physical records remain entirely empty.
        let mut projection = a.projection.clone(); projection.phase = Phase::Terminal;
        let p = projection.public().android().unwrap();
        assert_eq!(p.outcome, Some(android_wire::Outcome::Failed));
        assert_eq!(p.reason, reason.android());
        assert_eq!(p.disposition.as_ref().unwrap().work, android_wire::WorkDisposition::RetainedWork);
        let status = android_wire::Status { schema_version: 1, status_revision: 1,
            availability: android_wire::Availability::RuntimeUnqualified, operation: Some(p) };
        assert!(android_wire::status_bytes(&status).is_ok());
        application.inner.advance_locked(&mut r, &owner, t + SETTLEMENT);
        let p = r.active.as_ref().unwrap().projection.public().android().unwrap();
        assert_eq!((p.phase, p.reason), (android_wire::Phase::Unknown, android_wire::Reason::CleanupUnknown));
        assert!(p.activity.is_none() && p.disposition.is_none() && p.result.is_none());
        assert!(owner.watchdog_return.lock().unwrap().is_none() && r.last.is_none());
    }
}

#[test]
fn stdout_decoder_cannot_reopen_a_finished_domain_stream() {
    for domain in [SavedCommandDomain::OfflinePreflight, SavedCommandDomain::AndroidBuild] {
        let (_application, owner) = active(domain);
        let mut decoder = OutputDecoder::new(&owner).unwrap();
        for bytes in complete_stream(domain, true) { assert!(decoder.push(&bytes, &owner).is_ok()); }
        assert!(decoder.finish());
        assert!(decoder.push(&accepted(domain), &owner).is_err());
        assert!(!decoder.finish());
    }
}

struct MemoryControl { read: AtomicUsize, closes: AtomicUsize, fail_close: bool }
struct MemoryReader { bytes: Vec<u8>, at: usize, control: Arc<MemoryControl> }
impl AsyncRead for MemoryReader {
    fn poll_read(mut self: Pin<&mut Self>, _: &mut TaskContext<'_>, buffer: &mut tokio::io::ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        let count = buffer.remaining().min(self.bytes.len() - self.at); let at = self.at;
        buffer.put_slice(&self.bytes[at..at + count]); self.at += count;
        self.control.read.fetch_add(count, Ordering::SeqCst); Poll::Ready(Ok(()))
    }
}
impl OriginalClose for MemoryReader {
    fn original_close(self) -> Result<(), ()> {
        self.control.closes.fetch_add(1, Ordering::SeqCst); if self.control.fail_close { Err(()) } else { Ok(()) }
    }
}
fn memory(bytes: Vec<u8>, fail_close: bool) -> (Arc<AsyncMutex<Pipe<MemoryReader>>>, Arc<MemoryControl>) {
    let control = Arc::new(MemoryControl { read: AtomicUsize::new(0), closes: AtomicUsize::new(0), fail_close });
    (Arc::new(AsyncMutex::new(Pipe { io: Some(MemoryReader { bytes, at: 0, control: control.clone() }), close: Close::New })), control)
}

#[tokio::test]
async fn seven_android_frames_backpressure_two_slots_without_creating_native_finality() {
    let (application, owner) = active(SavedCommandDomain::AndroidBuild);
    assert_eq!(owner.frames.capacity(), 2);
    owner.pipes.send_replace(Pipes::Available);
    let mut receiver = owner.resources.lock().await.frames.take().unwrap();
    let frames = complete_stream(SavedCommandDomain::AndroidBuild, true);
    assert_eq!(frames.len(), 7);
    let bytes: Vec<u8> = frames.into_iter().flatten().collect(); let count = bytes.len();
    let (output, control) = memory(bytes, false);
    let reading = read_output(application.inner.clone(), owner.clone(), output, false, Guard::new(&application.inner, &owner));
    let consuming = async {
        for _ in 0..7 { application.inner.accept(&owner, receiver.recv().await.unwrap()); }
    };
    let (end, ()) = tokio::join!(reading, consuming);
    assert!(end.eof && end.closed && end.decoder_settled && !end.failed); assert_eq!(end.frames, 7);
    assert_eq!(control.read.load(Ordering::SeqCst), count); assert_eq!(control.closes.load(Ordering::SeqCst), 1);
    assert_eq!(owner.output_bytes.load(Ordering::SeqCst), count);
    { let r = application.inner.lock(); let a = r.active.as_ref().unwrap();
        assert!(a.accepted && a.terminal && !a.unknown && a.first_stop.is_none() && r.last.is_none());
        assert!(a.projection.public().result.is_none() && owner.watchdog_return.lock().unwrap().is_none()); }
    // No actual native final JoinHandle exists in this memory vector. Ordinary
    // status MUST veto the core terminal instead of promoting those DATA facts.
    let p = application.status_android(android_wire::Availability::Available).unwrap().operation.unwrap();
    assert_eq!(p.phase, android_wire::Phase::Unknown);
    assert!(p.result.is_none() && p.activity.is_none() && p.disposition.is_none());
    assert!(application.inner.lock().active.is_some() && !application.can_exit());
}

#[tokio::test]
async fn both_domains_drain_rejected_bytes_charge_stderr_and_never_retry_a_close() {
    for domain in [SavedCommandDomain::OfflinePreflight, SavedCommandDomain::AndroidBuild] {
        for fail_close in [false, true] {
            let (application, owner) = active(domain); owner.pipes.send_replace(Pipes::Available);
            let (error, error_control) = memory(vec![b'e'; 33000], false);
            let err = read_output(application.inner.clone(), owner.clone(), error, true, Guard::new(&application.inner, &owner)).await;
            let (output, output_control) = memory(vec![b'x'; 33000], fail_close);
            let end = read_output(application.inner.clone(), owner.clone(), output.clone(), false, Guard::new(&application.inner, &owner)).await;
            assert!(err.failed && err.eof && err.closed && end.failed && end.eof && !end.decoder_settled);
            assert_eq!(end.closed, !fail_close);
            assert_eq!(owner.output_bytes.load(Ordering::SeqCst), 66000);
            assert_eq!(error_control.read.load(Ordering::SeqCst), 33000);
            assert_eq!(output_control.read.load(Ordering::SeqCst), 33000);
            assert_eq!(close_original(&mut *output.lock().await), !fail_close);
            assert_eq!(output_control.closes.load(Ordering::SeqCst), 1);
            assert_eq!(error_control.closes.load(Ordering::SeqCst), 1);
            let r = application.inner.lock(); let a = r.active.as_ref().unwrap();
            assert!(r.disabled && a.unknown && a.projection.public().result.is_none());
        }
    }
}

#[tokio::test]
async fn accepted_only_eof_is_not_a_settled_decoder_in_either_domain() {
    for domain in [SavedCommandDomain::OfflinePreflight, SavedCommandDomain::AndroidBuild] {
        let (application, owner) = active(domain); owner.pipes.send_replace(Pipes::Available);
        let (output, control) = memory(accepted(domain), false);
        let end = read_output(application.inner.clone(), owner.clone(), output, false, Guard::new(&application.inner, &owner)).await;
        assert!(end.failed && end.eof && end.closed && !end.decoder_settled); assert_eq!(end.frames, 1);
        assert_eq!(control.closes.load(Ordering::SeqCst), 1);
        assert!(application.inner.lock().active.as_ref().unwrap().unknown);
    }
}
