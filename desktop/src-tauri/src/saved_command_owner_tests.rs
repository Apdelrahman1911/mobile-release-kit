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
    SavedCommandDomain::ProjectRecovery => Context::ProjectRecovery(recovery_wire::tests::context()),
    SavedCommandDomain::IOSArchive => Context::IOSArchive(ios_wire::tests::context()),
    SavedCommandDomain::ArtifactInspection => Context::ArtifactInspection(artifact_wire::tests::context()),
} }
#[test]
fn ios_mode_gate_keeps_matched_non_ios_pass_through_and_exact_mode_selection() {
    use ios_wire::{ModeCapabilities as Modes, Operation};
    let supported = Modes { unsigned: true, signed: true, recovery: true };
    assert_eq!(ios_mode_selection(true, None), supported);
    assert_eq!(ios_mode_selection(false, None), Modes::NONE);
    // Exhaust the three-mode observer mask. DATA can narrow an installed
    // provider, never substitute for one; a closed observation has no fallback.
    for mask in 0..8 {
        let observed = Modes { unsigned: mask & 1 != 0, signed: mask & 2 != 0, recovery: mask & 4 != 0 };
        assert_eq!(ios_mode_selection(true, Some(observed)), observed);
        assert_eq!(ios_mode_selection(false, Some(observed)), Modes::NONE);
    }
    for domain in [SavedCommandDomain::OfflinePreflight, SavedCommandDomain::AndroidBuild, SavedCommandDomain::ProjectRecovery] {
        let owner = application(domain);
        assert_eq!(owner.inner.ios_mode_capabilities(), Modes::NONE);
        for selected in [SavedCommandDomain::OfflinePreflight, SavedCommandDomain::AndroidBuild,
            SavedCommandDomain::ProjectRecovery, SavedCommandDomain::IOSArchive] {
            assert_eq!(owner.inner.ios_mode_qualified(&context(selected), None), selected == domain);
        }
    }
    let ios = application(SavedCommandDomain::IOSArchive);
    let modes = ios.inner.ios_mode_capabilities();
    assert_eq!(modes, ios_mode_selection(ios.inner.ios_installed_selected(), None));
    assert_eq!(ios.inner.qualified(None), ios.inner.ios_installed_selected());
    for (selected, operation) in [
        (context(SavedCommandDomain::IOSArchive), Operation::IOSUnsignedArchive),
        (Context::IOSArchive(ios_wire::tests::signed_context()), Operation::IOSSignedExport),
        (Context::IOSArchive(ios_wire::tests::recovery_context()), Operation::IOSLocalRecovery),
    ] {
        assert_eq!(ios.inner.ios_mode_qualified(&selected, None), modes.supports(operation));
    }
    assert!(!ios.inner.ios_mode_qualified(&context(SavedCommandDomain::OfflinePreflight), None));
    // Linux deliberately has no iOS profile. Check the actual native gate's
    // busy branch in SOURCE, rather than inventing platform qualification.
    let source = include_str!("asset_session.rs");
    let gate = source.split_once("    fn ios_archive_gate(").unwrap().1
        .split_once("    pub(crate) fn ios_archive_subscribe").unwrap().0;
    let peer_contract = |value: &str| {
        let calls = ["self.inner.bridge.artifact_inspection.disabled()",
            "self.inner.bridge.artifact_inspection.stopping()",
            "self.inner.bridge.artifact_inspection.busy()"];
        if calls.iter().any(|call| value.matches(*call).count() != 1) { return false; }
        let disabled = value.find(calls[0]).unwrap();
        let stopping = value.find(calls[1]).unwrap();
        let busy = value.find(calls[2]).unwrap();
        let Some(platform) = value.find("ios_archive_document_gate(state,") else { return false; };
        disabled < stopping && stopping < platform && platform < busy
            && value[disabled..stopping].contains("return Availability::CleanupUnknown;")
            && value[stopping..platform].contains("return Availability::Shutdown;")
            && value[busy..].contains("return Availability::Busy;")
    };
    assert!(peer_contract(gate));
    for call in ["self.inner.bridge.artifact_inspection.disabled()",
        "self.inner.bridge.artifact_inspection.stopping()",
        "self.inner.bridge.artifact_inspection.busy()"] {
        assert!(!peer_contract(&gate.replacen(call, "false", 1)));
    }
    assert_eq!((modes.unsigned, modes.signed, modes.recovery),
        (ios.inner.ios_installed_selected(), ios.inner.ios_installed_selected(), ios.inner.ios_installed_selected()));
}
#[test]
fn mode_only_status_changes_use_the_original_counter_without_changing_other_domains() {
    let ios = application(SavedCommandDomain::IOSArchive);
    let mut r = ios.inner.lock();
    let unsigned = ios_wire::ModeCapabilities { unsigned: true, signed: false, recovery: false };
    ios.inner.record_capabilities(&mut r, Availability::RuntimeUnqualified, Some(ios_wire::ModeCapabilities::NONE));
    let first = r.revision;
    ios.inner.record_capabilities(&mut r, Availability::RuntimeUnqualified, Some(ios_wire::ModeCapabilities::NONE));
    assert_eq!(r.revision, first);
    ios.inner.record_capabilities(&mut r, Availability::RuntimeUnqualified, Some(unsigned));
    assert_eq!(r.revision, first + 1); assert_eq!(r.ios_mode_capabilities, Some(unsigned));
    ios.inner.record_capabilities(&mut r, Availability::RuntimeUnqualified, Some(unsigned));
    assert_eq!(r.revision, first + 1);
    r.revision = u32::MAX - 1;
    ios.inner.record_capabilities(&mut r, Availability::RuntimeUnqualified, Some(ios_wire::ModeCapabilities::NONE));
    assert!(r.exhausted && ios.inner.snapshot_locked(&mut r, Availability::Available).is_err());
    drop(r);
    for domain in [SavedCommandDomain::OfflinePreflight, SavedCommandDomain::AndroidBuild, SavedCommandDomain::ProjectRecovery] {
        let owner = application(domain); let mut r = owner.inner.lock();
        owner.inner.record_capabilities(&mut r, Availability::RuntimeUnqualified, None);
        assert_eq!(r.revision, 0);
        owner.inner.record_capabilities(&mut r, Availability::Busy, None);
        owner.inner.record_capabilities(&mut r, Availability::Busy, None);
        assert_eq!(r.revision, 1); assert_eq!(r.ios_mode_capabilities, None);
    }
}
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
    let context = context(application.inner.domain);
    active_with_context(application, context)
}
fn active_with_context(application: SavedCommandOwner, context: Context) -> (SavedCommandOwner, Arc<Session>) {
    let domain = application.inner.domain; let mut p = projection(domain); p.context = context;
    let (stop, _) = watch::channel(false); let (pipes, _) = watch::channel(Pipes::Pending);
    let (frames, receiver) = mpsc::channel(2);
    let clocks = Clocks::for_context(&p.context, Instant::now());
    let (native_audit_cutoff, _) = watch::channel(clocks.work);
    let (native_cleanup_cutoff, _) = watch::channel(clocks.cleanup_end(None));
    let profile = match domain { SavedCommandDomain::OfflinePreflight => Profile::OfflinePreflight(wire::Profile::LinuxX64),
        SavedCommandDomain::AndroidBuild => Profile::AndroidBuild(android_wire::Profile::LinuxX64),
        SavedCommandDomain::ProjectRecovery => Profile::ProjectRecovery(recovery_wire::Profile::LinuxX64),
        SavedCommandDomain::IOSArchive => Profile::IOSArchive(ios_wire::Profile::MacArm64),
        SavedCommandDomain::ArtifactInspection => Profile::ArtifactInspection(artifact_wire::Profile::MacosArm64) };
    let owner = Arc::new(Session { domain, id: p.operation_id.clone(), generation: p.owner_generation.clone(), context: p.context.clone(),
        profile, clocks, registration: 1, project: project(), recovery_stamp: None, request: AsyncMutex::new(None),
        material: Mutex::new(None), material_retired: AtomicBool::new(true), recovery: None, android_selection: None, artifact_selection: None, artifact_tools: None, artifact_binding: Mutex::new(None), native_failure: Mutex::new(None),
        #[cfg(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"), not(feature = "macos-android-registration-helper")))]
        android_control: None,
        #[cfg(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"), not(feature = "macos-android-registration-helper")))]
        android_close: None,
        stop, pipes, frames, wake: Notify::new(), native_audit_cutoff, native_cleanup_cutoff, output_bytes: AtomicUsize::new(0), resource_unknown: AtomicBool::new(false),
        driver_done: AtomicBool::new(false), driver_joined: AtomicBool::new(false), driver_failed: AtomicBool::new(false),
        watchdog_joined: AtomicBool::new(false), watchdog_failed: AtomicBool::new(false), manager_failed: AtomicBool::new(false),
        startup: Mutex::new(Startup::default()), resources: AsyncMutex::new(Resources { frames: Some(receiver), ..Resources::default() }),
        input: Arc::new(AsyncMutex::new(Pipe::default())), output: Arc::new(AsyncMutex::new(Pipe::default())), error: Arc::new(AsyncMutex::new(Pipe::default())),
        driver: AsyncMutex::new(None), watchdog: Mutex::new(None), manager: AsyncMutex::new(None), observer: AsyncMutex::new(None),
        driver_return: Mutex::new(None), manager_return: Mutex::new(None), observer_return: Mutex::new(None), watchdog_return: Mutex::new(None),
        #[cfg(all(test, debug_assertions, feature = "development-runtime", not(feature = "desktop-shell"),
            any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))))]
        fixture: None,
    });
    p.phase = Phase::Starting; p.intent_usable = false;
    application.inner.lock().active = Some(Active { owner: owner.clone(), projection: p, first_stop: None, work_expired: false,
        accepted: false, terminal: false, unknown: false, final_join_seen: false, context_invalidated: false });
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
    for domain in [SavedCommandDomain::OfflinePreflight, SavedCommandDomain::AndroidBuild, SavedCommandDomain::ProjectRecovery, SavedCommandDomain::IOSArchive, SavedCommandDomain::ArtifactInspection] {
        let (bridge, document) = bound_document_model();
        let original = match domain {
            SavedCommandDomain::OfflinePreflight => bridge.preflight.original_for_test(),
            SavedCommandDomain::AndroidBuild => bridge.android_build.original_for_test(),
            SavedCommandDomain::ProjectRecovery => bridge.project_recovery.original_for_test(),
            SavedCommandDomain::IOSArchive => bridge.ios_archive.original_for_test(),
            SavedCommandDomain::ArtifactInspection => &bridge.artifact_inspection,
        };
        original.inner.lock().prepared = Some(Prepared { projection: projection(domain),
            expires: Instant::now() + INTENT, registration: bridge.registry_generation(), project: project(), recovery_stamp: None, material: None, recovery: None, android_selection: None, artifact_selection: None, artifact_tools: None });
        assert_eq!(original.inner.qualified(None), domain == SavedCommandDomain::OfflinePreflight && cfg!(feature = "custom-protocol")
            && original.inner.runtime.offline_preflight_installed_profile_available());
        assert_eq!(document.offline_preflight_status().unwrap().availability, wire::Availability::Busy);
        assert_eq!(document.android_build_status().unwrap().availability, android_wire::Availability::Busy);
        assert_eq!(document.project_recovery_status().unwrap().availability, recovery_wire::Availability::Busy);
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
        if domain == SavedCommandDomain::ArtifactInspection {
            // Actual original peer shutdown precedes unsupported-platform DATA.
            assert_eq!(document.ios_archive_status().unwrap().availability, ios_wire::Availability::Shutdown);
        }
        assert_eq!(document.configuration_edit_admit(|_| { entered.set(true); Ok(()) }).err().unwrap().code, "shutting_down");
        document.lost();
        assert!(document.configuration_edit_admit(|_| { entered.set(true); Ok(()) }).is_err());
        assert!(!entered.get());
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
#[test]
fn document_active_saved_domains_stop_before_writes_and_unknown_retains_status_and_cancel() {
    for domain in [SavedCommandDomain::OfflinePreflight, SavedCommandDomain::AndroidBuild, SavedCommandDomain::ProjectRecovery, SavedCommandDomain::IOSArchive, SavedCommandDomain::ArtifactInspection] {
        let (bridge, document) = bound_document_model();
        let original = match domain {
            SavedCommandDomain::OfflinePreflight => bridge.preflight.original_for_test(),
            SavedCommandDomain::AndroidBuild => bridge.android_build.original_for_test(),
            SavedCommandDomain::ProjectRecovery => bridge.project_recovery.original_for_test(),
            SavedCommandDomain::IOSArchive => bridge.ios_archive.original_for_test(),
            SavedCommandDomain::ArtifactInspection => &bridge.artifact_inspection,
        };
        let (application, owner) = active_in(original.clone());
        assert!(Arc::ptr_eq(&application.inner, &original.inner));
        assert_eq!(application.inner.qualified(None), domain == SavedCommandDomain::OfflinePreflight && cfg!(feature = "custom-protocol")
            && application.inner.runtime.offline_preflight_installed_profile_available());
        // Real mutex contention keeps reconciliation observation-only while
        // exercising Active. There is NO synthetic JoinHandle/return receipt.
        // Once released, the real missing-original path must become Unknown.
        let watchdog = owner.watchdog.lock().unwrap();
        assert!(watchdog.is_none());
        assert_eq!(document.offline_preflight_status().unwrap().availability, wire::Availability::Busy);
        assert_eq!(document.android_build_status().unwrap().availability, android_wire::Availability::Busy);
        assert_eq!(document.project_recovery_status().unwrap().availability, recovery_wire::Availability::Busy);
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
        if domain == SavedCommandDomain::ArtifactInspection {
            // Missing actual joins become retained Unknown, not a new iOS run.
            assert_eq!(document.ios_archive_status().unwrap().availability, ios_wire::Availability::CleanupUnknown);
        }
        assert_eq!(document.offline_preflight_status().unwrap().availability, wire::Availability::CleanupUnknown);
        assert_eq!(document.android_build_status().unwrap().availability, android_wire::Availability::CleanupUnknown);
        assert_eq!(document.project_recovery_status().unwrap().availability, recovery_wire::Availability::CleanupUnknown);
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
            SavedCommandDomain::ProjectRecovery => {
                let status = document.cancel_project_recovery(recovery_wire::Cancel { operation_id: owner.id.clone(), owner_generation: owner.generation.clone() }).unwrap();
                assert_eq!(status.operation.unwrap().phase, recovery_wire::Phase::Unknown);
            },
            SavedCommandDomain::IOSArchive => {
                let status = document.cancel_ios_archive(ios_wire::Cancel { operation_id: owner.id.clone(), owner_generation: owner.generation.clone() }).unwrap();
                assert_eq!(status.operation.unwrap().phase, ios_wire::Phase::Unknown);
            },
            SavedCommandDomain::ArtifactInspection => {
                let status = document.artifact_inspection_cancel(artifact_wire::Cancel { operation_id: owner.id.clone(), owner_generation: owner.generation.clone() }).unwrap();
                assert_eq!(status.operation.unwrap().phase, artifact_wire::Phase::Unknown);
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
    let protocol = match domain { SavedCommandDomain::OfflinePreflight => wire::PROTOCOL, SavedCommandDomain::AndroidBuild => android_wire::PROTOCOL,
        SavedCommandDomain::ProjectRecovery => recovery_wire::PROTOCOL, SavedCommandDomain::IOSArchive => ios_wire::PROTOCOL, SavedCommandDomain::ArtifactInspection => artifact_wire::PROTOCOL };
    let mut bytes = serde_json::to_vec(&json!({"protocol":protocol,"operationId":"a".repeat(32),"ownerGeneration":"b".repeat(32),
        "sequence":sequence,"kind":kind,"payload":payload})).unwrap(); bytes.push(b'\n'); bytes
}
fn accepted(domain: SavedCommandDomain) -> Vec<u8> {
    let context = match context(domain) { Context::OfflinePreflight(c) => serde_json::to_value(c).unwrap(),
        Context::AndroidBuild(c) => serde_json::to_value(c).unwrap(),
        Context::ProjectRecovery(c) => serde_json::to_value(c).unwrap(), Context::IOSArchive(c) => serde_json::to_value(c).unwrap(), Context::ArtifactInspection(c) => serde_json::to_value(c).unwrap() };
    frame(domain, 0, "accepted", json!({"schemaVersion":1,"context":context}))
}
fn complete_stream(domain: SavedCommandDomain, progress: bool) -> Vec<Vec<u8>> {
    let mut frames = vec![accepted(domain)];
    match domain {
        SavedCommandDomain::ArtifactInspection => frames.push(frame(domain, 1, "terminal", artifact_wire::tests::terminal()["payload"].clone())),
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
        SavedCommandDomain::ProjectRecovery => frames.push(frame(domain, 1, "terminal", recovery_wire::tests::terminal_value(&recovery_wire::tests::context()))),
        SavedCommandDomain::IOSArchive => {
            if progress { for stage in ["inputs-bound", "checking-xcode", "preparing", "archiving", "inspecting", "disposing-snapshot", "disposing-work"] {
                frames.push(frame(domain, frames.len() as u32, "progress", json!({"schemaVersion":1,"stage":stage})));
            } }
            frames.push(frame(domain, frames.len() as u32, "terminal", ios_wire::tests::complete()));
        }
    }
    frames
}

#[test]
fn declared_domains_have_fixed_nonrenewable_clocks_and_distinct_limits() {
    let admitted = Instant::now();
    assert_eq!(INTENT, Duration::from_secs(300));
    for (domain, work, hard, request, response, frames) in [
        (SavedCommandDomain::OfflinePreflight, 1800, 1810, 16384, 65536, 2),
        (SavedCommandDomain::AndroidBuild, 3000, 3010, 32768, 65536, 8),
        (SavedCommandDomain::ProjectRecovery, 120, 130, 16384, 32768, 2),
        (SavedCommandDomain::IOSArchive, 5400, 5410, 32768, 65536, 9),
        (SavedCommandDomain::ArtifactInspection, 900, 910, 32768, 65536, 2),
    ] {
        let c = Clocks::new(domain, admitted);
        let ordinary = application(domain).inner.start_clocks(admitted);
        assert_eq!((ordinary.admitted, ordinary.work, ordinary.finality), (c.admitted, c.work, c.finality));
        assert_eq!(c.work, admitted + Duration::from_secs(work));
        assert_eq!(c.finality, admitted + Duration::from_secs(hard));
        assert_eq!(c.settlement(None), c.finality);
        assert_eq!(c.settlement(Some(admitted + Duration::from_secs(2))), admitted + Duration::from_secs(12));
        assert_eq!(c.settlement(Some(c.finality)), c.finality);
        assert_eq!((domain.request_limit(), domain.response_limit(), domain.frame_limit()), (request, response, frames));
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
    assert!(!owner.inner.qualified(None));
    let wrong_consent = json!({"operationId":"a".repeat(32),"ownerGeneration":"b".repeat(32),"consentVersion":wire::CONSENT});
    assert!(android_wire::start(&wrong_consent).is_err());
    let old_consent = json!({"operationId":"a".repeat(32),"ownerGeneration":"b".repeat(32),"consentVersion":"saved-android-build-inspect-v1"});
    assert!(android_wire::start(&old_consent).is_err());
    // Unacquired comparison DATA alone cannot arm Android. Inserting an inert
    // intent tests one-use refusal; it does not install a qualification permit.
    for context in [android_wire::tests::context(), android_wire::tests::upload_context()] {
        let owner = application(SavedCommandDomain::AndroidBuild);
        let mut prepared = projection(SavedCommandDomain::AndroidBuild);
        prepared.context = Context::AndroidBuild(context.clone());
        owner.inner.lock().prepared = Some(Prepared { projection: prepared,
            expires: Instant::now() + INTENT, registration: 1, project: project(), recovery_stamp: None, material: None, recovery: None, android_selection: None, artifact_selection: None, artifact_tools: None });
        assert!(owner.start_offline(wire::start(&wrong_consent).unwrap(), Instant::now(), Some((1, project())), wire::Availability::Available).is_err());
        assert!(owner.inner.lock().prepared.is_some());
        let request = json!({"operationId":"a".repeat(32),"ownerGeneration":"b".repeat(32),"consentVersion":android_wire::CONSENT});
        let status = owner.start_android(android_wire::start(&request).unwrap(), Instant::now(), Some((1, project())),
            android_wire::Availability::Available).unwrap().release();
        let p = status.operation.unwrap();
        assert_eq!((p.phase, p.outcome), (android_wire::Phase::Terminal, Some(android_wire::Outcome::Refused)));
        assert_eq!(p.context, context); // Retirement preserves the original saved mode/fingerprint unchanged.
        assert!(p.result.is_none() && p.activity.is_none() && p.disposition.is_none() && p.stage.is_none());
        { let r = owner.inner.lock(); assert!(r.prepared.is_none() && r.active.is_none()); }
        assert!(owner.start_android(android_wire::start(&request).unwrap(), Instant::now(), Some((1, project())),
            android_wire::Availability::Available).is_err());
    }
}

#[test]
fn recovery_uses_its_own_closed_domain_and_one_use_intent_without_opening_a_runtime() {
    let owner = application(SavedCommandDomain::ProjectRecovery);
    assert_eq!(owner.inner.qualified(None), cfg!(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))
        && owner.inner.recovery_installed_selected());
    assert_eq!(owner.inner.recovery_installed_selected(), cfg!(feature = "custom-protocol")
        && owner.inner.runtime.project_recovery_installed_profile_available());
    let foreign = wire::prepare(&json!({"projectId":"inert-project","draftRevision":2,"baselineGeneration":3,
        "savedConfig":{"bytes":123,"sha256":"d".repeat(64)}})).unwrap();
    assert!(owner.prepare_offline(foreign, 1, project(), wire::Availability::Available).is_err());
    let request = recovery_wire::prepare(&json!({"projectId":"inert-project","draftRevision":2,
        "baselineGeneration":3,"action":"recover"})).unwrap();
    assert!(owner.prepare_recovery(request, 1, project(), recovery_wire::Availability::Available).is_err());
    { let r = owner.inner.lock(); assert!(r.recovery_review.is_none() && r.prepared.is_none()); }
    owner.inner.lock().prepared = Some(Prepared { projection: projection(SavedCommandDomain::ProjectRecovery),
        expires: Instant::now() + INTENT, registration: 1, project: project(), recovery_stamp: None, material: None, recovery: None, android_selection: None, artifact_selection: None, artifact_tools: None });
    let input = json!({"operationId":"a".repeat(32),"ownerGeneration":"b".repeat(32),"consentVersion":recovery_wire::CONSENT});
    // An unqualified runtime or this plain test's absent executor refuses the
    // comparison-only intent before acquisition. Available is not custody.
    let status = owner.start_recovery(recovery_wire::start(&input).unwrap(), Instant::now(), Some((1, project())),
        recovery_wire::Availability::Available).unwrap().release();
    let operation = status.operation.unwrap();
    assert_eq!(operation.phase, recovery_wire::Phase::Terminal);
    assert_eq!(operation.outcome, Some(recovery_wire::Outcome::Refused));
    assert!(operation.result.is_none() && operation.effect.is_none());
    { let r = owner.inner.lock(); assert!(r.prepared.is_none() && r.active.is_none()); }
    assert!(owner.start_recovery(recovery_wire::start(&input).unwrap(), Instant::now(), Some((1, project())),
        recovery_wire::Availability::Available).is_err());
    for reason in [Reason::ReviewStale, Reason::ManualRequired, Reason::ProjectChanged, Reason::ProjectBusy,
        Reason::ProjectConflict, Reason::RecoveryIncomplete] {
        assert!(reason.offline().is_err() && reason.android().is_err() && reason.ios().is_err() && reason.recovery().is_ok());
    }
}

#[test]
fn recovery_core_terminal_is_provisional_and_never_mints_a_review_before_original_joins() {
    let (application, owner) = active(SavedCommandDomain::ProjectRecovery);
    let t = owner.clocks.admitted;
    application.inner.accept_at(&owner, Frame::ProjectRecovery(recovery_wire::Frame::Accepted), t);
    application.inner.accept_at(&owner, Frame::ProjectRecovery(recovery_wire::tests::terminal_frame(&recovery_wire::tests::context())), t);
    let mut r = application.inner.lock(); let active = r.active.as_ref().unwrap();
    assert!(active.accepted && active.terminal && !active.final_join_seen && active.projection.result.is_some());
    assert!(active.projection.public().recovery().unwrap().result.is_none());
    assert!(recovery_review_after_finality(active, &owner, t).is_none() && r.recovery_review.is_none());
    // Renderer projection-only DATA: inspect the private-field redaction, not
    // a native success path. No positive handle or original receipt is filled.
    let mut projection = active.projection.clone(); projection.phase = Phase::Terminal;
    let public = serde_json::to_value(projection.public().recovery().unwrap()).unwrap();
    assert!(public.get("reviewStamp").is_none());
    assert!(public["result"].get("reviewStamp").is_none());
    assert!(!public.to_string().contains(&"d".repeat(64)));
    application.inner.advance_locked(&mut r, &owner, t + RECOVERY_HARD);
    let active = r.active.as_ref().unwrap();
    assert!(active.unknown && recovery_review_after_finality(active, &owner, t + RECOVERY_HARD).is_none());
    assert!(active.projection.public().recovery().unwrap().result.is_none());
}

#[test]
fn signed_and_recovery_clocks_share_only_original_first_failure_cleanup_not_work_or_material() {
    let start = Instant::now();
    let android = Context::AndroidBuild(android_wire::tests::signed_context());
    assert!(android.requires_private_material()); assert!(!android.signed_ios());
    let clocks = Clocks::for_context(&android, start);
    assert_eq!((clocks.signed, clocks.recovery), (false, false));
    assert_eq!((clocks.work, clocks.finality), (start + Duration::from_secs(3000), start + Duration::from_secs(3010)));
    let first = start + Duration::from_secs(2);
    assert_eq!(clocks.cleanup_end(Some(first)), first + Duration::from_secs(10));
    assert_eq!(clocks.settlement(Some(first)), first + Duration::from_secs(10));
    assert_eq!(android.frame_limit(), 10);
    // Exercise the same protocol-count predicate used by both consuming/native
    // preconditions and observe_final. These DATA flags certify no actual join.
    for (context, limit) in [
        (android, 10), (context(SavedCommandDomain::AndroidBuild), 8),
        (context(SavedCommandDomain::OfflinePreflight), 2), (context(SavedCommandDomain::ProjectRecovery), 2),
        (context(SavedCommandDomain::IOSArchive), ios_wire::MAX_FRAMES),
        (Context::IOSArchive(ios_wire::tests::signed_context()), ios_wire::SIGNED_MAX_FRAMES),
        (Context::IOSArchive(ios_wire::tests::recovery_context()), ios_wire::RECOVERY_MAX_FRAMES),
    ] {
        for frames in [0, 1, 2, 8, 9, 10, 11, limit, limit + 1] {
            let end = ReadEnd { frames, eof: false, closed: false, failed: false, decoder_settled: true };
            assert_eq!(end.protocol_settled_for(&context), (2..=limit).contains(&frames));
        }
        let mut end = ReadEnd { frames: limit, eof: false, closed: false, failed: true, decoder_settled: true };
        assert!(!end.protocol_settled_for(&context));
        end.failed = false; end.decoder_settled = false;
        assert!(!end.protocol_settled_for(&context));
    }
    for (context, work, cleanup, hard, signed, recovery) in [
        (ios_wire::tests::signed_context(), 5400, 5520, 5530, true, false),
        (ios_wire::tests::recovery_context(), 120, 240, 250, false, true),
    ] {
        let clocks = Clocks::for_context(&Context::IOSArchive(context), start);
        assert_eq!(clocks.work, start + Duration::from_secs(work));
        assert_eq!(clocks.cleanup_end(None), start + Duration::from_secs(cleanup));
        assert_eq!(clocks.settlement(None), start + Duration::from_secs(hard));
        assert_eq!((clocks.signed, clocks.recovery), (signed, recovery));
        let first = start + Duration::from_secs(2);
        assert_eq!(clocks.cleanup_end(Some(first)), first + Duration::from_secs(120));
        assert_eq!(clocks.settlement(Some(first)), first + Duration::from_secs(130));
        assert_eq!(clocks.audit_end(Some(first)), clocks.settlement(Some(first)));
        assert_eq!(clocks.cleanup_end(Some(clocks.finality)), clocks.cleanup);
        assert_eq!(clocks.settlement(Some(clocks.finality)), clocks.finality);
    }
}

fn recovery_terminal_data() -> ios_wire::Terminal {
    let context = ios_wire::tests::recovery_context();
    ios_wire::terminal(&json!({"schemaVersion":1,"context":context,"outcome":"complete","reason":"none",
        "activity":{"stage":"disposing-work"},"lifetime":{"complete":true,"fatal":false,"contained":true,
            "commandDispatched":false,"commands":0,"profileCalls":0,"stopObserved":"none","inputClosed":true,
            "handlersRestored":true,"invocationClosed":true,"snapshotClosed":true,"filesClosed":true,
            "namespaceClosed":true,"signingClosed":true,"buildInputsClosed":true,"materialRetired":true},
        "report":{"schemaVersion":1,"scope":"local-ios-recovery",
            "account":{"status":"pending","session":"c".repeat(32),"next":"ordinary"},
            "project":{"status":"idle","session":null,"next":"none"},
            "limitations":ios_wire::RECOVERY_LIMITATIONS}}), &context, &"a".repeat(32)).unwrap()
}

fn recovery_action() -> Context {
    Context::IOSArchive(ios_wire::prepare(&json!({"projectId":"inert-ios",
        "recovery":{"action":"account","session":"c".repeat(32)}})).unwrap().context())
}

#[test]
fn recovery_observation_needs_original_final_join_binding_not_just_a_success_report() {
    let (_app, original) = active_with_context(application(SavedCommandDomain::IOSArchive),
        Context::IOSArchive(ios_wire::tests::recovery_context()));
    let observation = IOSRecoveryObservation { original: original.clone(), terminal: recovery_terminal_data() };
    let action = recovery_action();
    assert!(!observation.matches(&action, 1, &project()));
    // Explicit predicate DATA, not an executed task or a native finality
    // receipt. Positive native issuance still requires reconcile's real Ready.
    original.watchdog_joined.store(true, Ordering::SeqCst);
    *original.watchdog_return.lock().unwrap() = Some(Ok(true));
    assert!(observation.matches(&action, 1, &project()));
    assert!(!observation.matches(&action, 2, &project()));
    let mut foreign = project(); foreign.path = PathBuf::from("/unopened-other-project");
    assert!(!observation.matches(&action, 1, &foreign));
    assert!(!observation.matches(&Context::IOSArchive(ios_wire::tests::recovery_context()), 1, &project()));
    let wrong = Context::IOSArchive(ios_wire::prepare(&json!({"projectId":"inert-ios",
        "recovery":{"action":"account","session":"d".repeat(32)}})).unwrap().context());
    assert!(!observation.matches(&wrong, 1, &project()));
    original.material_retired.store(false, Ordering::SeqCst); assert!(!observation.matches(&action, 1, &project()));
    original.material_retired.store(true, Ordering::SeqCst);
    original.resource_unknown.store(true, Ordering::SeqCst); assert!(!observation.matches(&action, 1, &project()));
    original.resource_unknown.store(false, Ordering::SeqCst);
    *original.watchdog_return.lock().unwrap() = Some(Ok(false)); assert!(!observation.matches(&action, 1, &project()));
}

#[test]
fn recovery_start_consumes_observation_and_refuses_a_different_arc_or_lost_context_before_effects() {
    for same in [false, true] {
        let (_source, original) = active_with_context(application(SavedCommandDomain::IOSArchive),
            Context::IOSArchive(ios_wire::tests::recovery_context()));
        original.watchdog_joined.store(true, Ordering::SeqCst);
        *original.watchdog_return.lock().unwrap() = Some(Ok(true)); // Inert predicate DATA only.
        let observed = Arc::new(IOSRecoveryObservation { original: original.clone(), terminal: recovery_terminal_data() });
        let prepared = if same { observed.clone() }
            else { Arc::new(IOSRecoveryObservation { original, terminal: recovery_terminal_data() }) };
        let app = application(SavedCommandDomain::IOSArchive);
        let mut p = projection(SavedCommandDomain::IOSArchive); p.context = recovery_action();
        { let mut r = app.inner.lock(); r.recovery = Some(observed);
            r.prepared = Some(Prepared { projection:p, expires:Instant::now()+INTENT, registration:1,
                project:project(), recovery_stamp:None, material:None, recovery:Some(prepared), android_selection: None, artifact_selection: None, artifact_tools: None }); }
        let admitted = app.start(Start { operation_id:"a".repeat(32), owner_generation:"b".repeat(32) },
            Instant::now(), Some((1, project())), Availability::Available).unwrap();
        assert!(admitted.release.is_none());
        let r = app.inner.lock(); assert!(r.recovery.is_none() && r.prepared.is_none() && r.active.is_none());
        assert_eq!(r.last.as_ref().unwrap().reason, if same { Reason::RuntimeUnavailable } else { Reason::StaleIntent });
    }
    let (app, owner) = active_with_context(application(SavedCommandDomain::IOSArchive),
        Context::IOSArchive(ios_wire::tests::recovery_context()));
    let held = owner.watchdog.lock().unwrap(); // No handle is present or polled.
    app.inner.stop(&owner, Reason::CommandFailed);
    let first = app.inner.lock().active.as_ref().unwrap().first_stop;
    app.context_changed();
    { let r = app.inner.lock(); let a = r.active.as_ref().unwrap();
        assert!(a.context_invalidated && r.recovery.is_none());
        assert_eq!(a.first_stop, first); assert_eq!(a.projection.reason, Reason::CommandFailed); }
    drop(held);
}

#[test]
fn android_normal_selection_requires_first_owner_and_original_live_document_without_observation() {
    let runtime = RuntimeConfig::packaged(PathBuf::from("/unopened-android-normal-selection"));
    let toolchain = AndroidToolchainProfile::compiled();
    let selected = runtime.android_build_installed_runtime_available()
        && toolchain.as_ref().is_some_and(AndroidToolchainProfile::installed_candidate_matches_compiled);
    let peer = SavedCommandOwner::offline_preflight(runtime.clone());
    let first = SavedCommandOwner::android_build(runtime.clone(), toolchain.clone());
    let second = SavedCommandOwner::android_build(runtime.clone(), toolchain.clone());
    let document = Arc::new(()); let replacement = Arc::new(());
    assert!(!ANDROID_NATIVE_QUALIFIED && !ANDROID_RUNTIME_QUALIFIED && !ANDROID_TOOLCHAIN_QUALIFIED);
    assert!(!first.inner.qualified(None)); // Even complete compile DATA needs its real binding.
    second.bind_original_android_document(&replacement);
    first.bind_original_android_document(&document);
    first.bind_original_android_document(&replacement);
    assert!(first.android_original_document_matches(&document));
    assert!(!first.android_original_document_matches(&replacement));
    assert_eq!(first.inner.qualified(None), selected);
    assert_eq!(first.android_normal_selected(&document), selected);
    assert_eq!(first.clone().android_normal_selected(&document), selected);
    assert!(!first.android_normal_selected(&replacement));
    assert!(!second.android_original_document_matches(&replacement) && !second.inner.qualified(None));
    { let r = first.inner.lock(); assert!(r.active.is_none() && r.prepared.is_none() && r.last.is_none()); }
    drop(document);
    first.bind_original_android_document(&replacement);
    assert!(!first.inner.qualified(None) && !first.android_original_document_matches(&replacement));
    drop(first);
    let later = SavedCommandOwner::android_build(runtime, toolchain);
    later.bind_original_android_document(&replacement);
    assert!(!later.inner.android_original_owner && !later.inner.qualified(None));
    peer.bind_original_android_document(&replacement);
    assert!(!peer.android_original_document_matches(&replacement));
}

#[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
#[test]
fn android_actual_document_gate_preserves_original_until_duplicate_main_latches_loss() {
    let (bridge, document) = bound_document_model();
    let original = document.android_build_status().unwrap().availability;
    assert_ne!(original, android_wire::Availability::DocumentLost);
    let other = crate::asset_session::DocumentBinding::new(bridge.clone());
    // Initial Finished is pending: construction reports Busy, not original loss.
    assert_eq!(other.android_build_status().unwrap().availability, android_wire::Availability::Busy);
    assert_eq!(document.clone().android_build_status().unwrap().availability, original);
    // A second completed main lifetime is real loss, not harmless construction.
    other.hook_installed();
    other.observe(|lifetime| lifetime.started(true));
    other.observe(|lifetime| lifetime.finished(true));
    assert_eq!(other.android_build_status().unwrap().availability, android_wire::Availability::DocumentLost);
    assert_eq!(document.clone().android_build_status().unwrap().availability, android_wire::Availability::DocumentLost);
    drop(document);
    assert_eq!(other.android_build_status().unwrap().availability, android_wire::Availability::DocumentLost);
    let later = crate::asset_session::DocumentBinding::new(bridge);
    later.hook_installed();
    later.observe(|lifetime| lifetime.started(true));
    later.observe(|lifetime| lifetime.finished(true));
    assert_eq!(later.android_build_status().unwrap().availability, android_wire::Availability::DocumentLost);
}

#[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
#[test]
fn android_unselected_stale_and_stopped_intents_refuse_before_any_native_book() {
    for scenario in ["missing-toolchain", "second-owner", "stale-document", "shutdown", "disabled", "lost", "stale-registration"] {
        let runtime = RuntimeConfig::packaged(PathBuf::from("/unopened-android-refusal"));
        let toolchain = if scenario == "missing-toolchain" { None } else { AndroidToolchainProfile::compiled() };
        let first = SavedCommandOwner::android_build(runtime.clone(), toolchain.clone());
        let owner = if scenario == "second-owner" { SavedCommandOwner::android_build(runtime, toolchain) } else { first };
        let mut document = Some(Arc::new(()));
        owner.bind_original_android_document(document.as_ref().unwrap());
        match scenario {
            "stale-document" => { drop(document.take()); },
            "shutdown" => owner.request_shutdown(),
            "disabled" => owner.inner.lock().disabled = true,
            "lost" => owner.document_lost(),
            _ => {},
        }
        if scenario != "stale-registration" {
            if let Some(document) = &document { assert!(!owner.android_normal_selected(document)); }
            else { assert!(!owner.inner.android_installed_selected(None, None)); }
            // A bad selection cannot hide behind the later executor check.
            assert!(owner.prepare(context(SavedCommandDomain::AndroidBuild), 1, project(), Availability::Available).is_err());
        }
        let reason = match scenario {
            "shutdown" => Reason::Shutdown,
            "disabled" => Reason::CleanupUnknown,
            "lost" => Reason::DocumentLost,
            "stale-registration" => Reason::StaleIntent,
            "missing-toolchain" if owner.inner.android_runtime_selected(None) => Reason::ToolchainUnavailable,
            _ => Reason::RuntimeUnavailable,
        };
        // Comparison DATA only, as in the existing one-use consent vectors.
        // No positive runtime/toolchain/observer permission is manufactured.
        { let mut r = owner.inner.lock();
            assert!(r.active.is_none() && r.prepared.is_none());
            r.prepared = Some(Prepared { projection: projection(SavedCommandDomain::AndroidBuild), expires: Instant::now() + INTENT,
                registration: 1, project: project(), recovery_stamp: None, material: None, recovery: None, android_selection: None, artifact_selection: None, artifact_tools: None }); }
        let request = json!({"operationId":"a".repeat(32),"ownerGeneration":"b".repeat(32),"consentVersion":android_wire::CONSENT});
        let registration = if scenario == "stale-registration" { 2 } else { 1 };
        let status = owner.start_android(android_wire::start(&request).unwrap(), Instant::now(), Some((registration, project())),
            android_wire::Availability::Available).unwrap().release();
        assert!(!status.operation.as_ref().unwrap().intent_usable);
        { let r = owner.inner.lock();
            assert!(r.active.is_none() && r.prepared.is_none()); // No Session/AndroidNativeBooks was admitted.
            let last = r.last.as_ref().unwrap();
            assert_eq!(last.reason, reason, "{scenario}");
            assert!(last.result.is_none()); }
        assert!(owner.start_android(android_wire::start(&request).unwrap(), Instant::now(), Some((registration, project())),
            android_wire::Availability::Available).is_err());
    }
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
    assert!(!native_final(&book, &owner));
    let (_offline_application, offline_owner) = active(SavedCommandDomain::OfflinePreflight);
    assert!(native_final(&book, &offline_owner)); // Added conjunct never borrows Offline tools.
    assert!(!owner.startup.lock().unwrap().attempted && owner.request.lock().await.is_none());
    let r = application.inner.lock(); let a = r.active.as_ref().unwrap();
    assert_eq!((a.projection.reason, a.projection.outcome), (Reason::ToolchainUnavailable, Some(Outcome::Refused)));
    assert!(a.first_stop.is_some() && !a.terminal && !a.final_join_seen && r.last.is_none());
}

#[test]
fn offline_installed_closer_requires_original_core_lifetime_not_policy_pass() {
    for mode in ["missing", "unsettled", "negative", "cancelled"] {
        let (application, owner) = active(SavedCommandDomain::OfflinePreflight); let now = owner.clocks.admitted;
        {
            let r = application.inner.lock();
            assert!(!offline_installed_closure_ready(&r, &owner, true, true));
            assert!(offline_installed_closure_ready(&r, &owner, false, true));
            assert!(!offline_installed_closure_ready(&r, &owner, false, false));
        }
        application.inner.accept_at(&owner, Frame::OfflinePreflight(wire::Frame::Accepted), now);
        if mode != "missing" {
            let Context::OfflinePreflight(context) = &owner.context else { panic!("offline DATA") };
            // Existing complete fixture contains a FAIL finding. Policy
            // failure is not unresolved C/A/W lifetime or a runtime borrower.
            let wire::Frame::Terminal(terminal) = wire::tests::terminal_frame(context) else { panic!("terminal DATA") };
            let mut value = serde_json::to_value(terminal).unwrap();
            if mode == "unsettled" {
                value["outcome"] = json!("unknown"); value["reason"] = json!("cleanup-unknown");
                value["result"] = Value::Null; value["lifetime"]["invocationClosed"] = json!(false);
            } else if mode == "cancelled" {
                value["outcome"] = json!("cancelled"); value["reason"] = json!("cancelled");
                value["result"] = Value::Null; value["lifetime"]["stopObserved"] = json!("cancelled");
            }
            let parsed = wire::decode(&frame(owner.domain, 1, "terminal", value), &owner.id, &owner.generation, context).unwrap();
            application.inner.accept_at(&owner, Frame::OfflinePreflight(parsed), now);
        }
        let (_, foreign) = active(SavedCommandDomain::OfflinePreflight);
        let (_, android) = active(SavedCommandDomain::AndroidBuild);
        let mut r = application.inner.lock();
        // Direct engine0/IO-return DATA is deliberately insufficient by itself.
        assert_eq!(offline_installed_closure_ready(&r, &owner, true, true), matches!(mode, "negative" | "cancelled"));
        assert!(!offline_installed_closure_ready(&r, &owner, true, false));
        assert!(!offline_installed_closure_ready(&r, &foreign, true, true));
        assert!(!offline_installed_closure_ready(&r, &android, true, true));
        if mode == "unsettled" { assert!(r.active.as_ref().unwrap().unknown); }
        if mode == "negative" {
            // Even wrong-domain settled terminal DATA cannot qualify Offline's
            // closer. Real transport routing refuses this earlier as well.
            r.active.as_mut().unwrap().projection.result = Some(Terminal::AndroidBuild(
                android_terminal(&android_wire::tests::complete_with_failed_inspection())));
            assert!(!offline_installed_closure_ready(&r, &owner, true, true));
        }
    }
}

#[test]
fn selected_offline_runtime_cannot_use_the_unselected_native_finality_shortcut() {
    let (_offline_application, owner) = active(SavedCommandDomain::OfflinePreflight);
    let mut book = Resources::default();
    assert!(native_final(&book, &owner));
    book.offline_selected = true;
    assert!(!native_final(&book, &owner));
    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    {
        book.offline_installed = Some(Arc::new(Mutex::new(OfflinePreflightRuntimeSlots::new())));
        assert!(!native_final(&book, &owner));
        book.offline_selected = false; // Stray original slot is not a dev/headless exemption either.
        assert!(!native_final(&book, &owner));
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
#[tokio::test]
async fn offline_preclaim_workers_need_actual_ready_and_spawn_failure_never_means_no_child() {
    let (application, owner) = active(SavedCommandDomain::OfflinePreflight);
    {
        let mut book = owner.resources.lock().await;
        book.inspection_started = true; book.acquisition_started = true;
        book.inspection = Some(tokio::spawn(pending::<Result<VerifiedRuntime, BridgeError>>()));
        book.acquisition = Some(tokio::spawn(pending::<()>()));
        book.write_end = Some(WriteEnd { sent: false, closed: false, failed: false });
        book.out_end = Some(ReadEnd { frames: 0, eof: false, closed: false, failed: false, decoder_settled: false });
        book.err_end = Some(ReadEnd { frames: 0, eof: false, closed: false, failed: false, decoder_settled: false });
        assert!(!offline_consumers_returned(&book, &owner.startup.lock().unwrap(), true));
        book.inspection_failed = true; book.acquisition_failed = true;
        assert!(!offline_consumers_returned(&book, &owner.startup.lock().unwrap(), true));
        book.inspection_failed = false; book.acquisition_failed = false;
        book.inspection.as_ref().unwrap().abort(); book.acquisition.as_ref().unwrap().abort();
    }
    continue_original(&application.inner, &owner).await;
    continue_original(&application.inner, &owner).await;
    let book = owner.resources.lock().await;
    assert!(book.inspection_error.as_ref().is_some_and(|e| e.is_cancelled())
        && book.acquisition_error.as_ref().is_some_and(|e| e.is_cancelled()));
    assert!(book.inspection.is_some() && book.acquisition.is_some());
    assert!(offline_consumers_returned(&book, &owner.startup.lock().unwrap(), true));
    assert!(!offline_consumers_returned(&book, &owner.startup.lock().unwrap(), false));
    let mut startup = owner.startup.lock().unwrap(); startup.attempted = true; startup.failed = true;
    assert!(!offline_consumers_returned(&book, &startup, true));
    assert!(!book.offline_started && book.offline_settlement.is_none() && book.offline_return.is_none());
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
        assert!(book.native.is_none() && !book.native_started && !native_final(&book, &owner));
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
    for domain in [SavedCommandDomain::OfflinePreflight, SavedCommandDomain::AndroidBuild, SavedCommandDomain::ProjectRecovery, SavedCommandDomain::IOSArchive] {
        let (application, owner) = active(domain);
        let selected = match domain {
            SavedCommandDomain::OfflinePreflight => application.inner.offline_installed_selected(),
            SavedCommandDomain::AndroidBuild => false, // No original document/catalog selection was bound.
            SavedCommandDomain::ProjectRecovery => cfg!(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))
                && application.inner.recovery_installed_selected(),
            SavedCommandDomain::IOSArchive => application.inner.ios_installed_selected(),
            SavedCommandDomain::ArtifactInspection => application.inner.artifact_installed_selected(),
        };
        assert_eq!(application.inner.qualified(None), selected);
        let cutoff = owner.native_audit_cutoff.subscribe();
        assert_eq!(*cutoff.borrow(), owner.clocks.work);
        {
            let mut r = application.inner.lock();
            application.inner.stop_locked(&mut r, &owner, Reason::Cancelled, owner.clocks.admitted);
            application.inner.stop_locked(&mut r, &owner, Reason::Shutdown, owner.clocks.admitted + Duration::from_secs(5));
            assert_eq!(r.active.as_ref().unwrap().first_stop, Some(owner.clocks.admitted));
            let expected = match domain {
                SavedCommandDomain::AndroidBuild | SavedCommandDomain::IOSArchive => owner.clocks.admitted + SETTLEMENT,
                SavedCommandDomain::ArtifactInspection => owner.clocks.work,
                SavedCommandDomain::OfflinePreflight | SavedCommandDomain::ProjectRecovery => owner.clocks.work,
            };
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
    for domain in [SavedCommandDomain::OfflinePreflight, SavedCommandDomain::AndroidBuild, SavedCommandDomain::ProjectRecovery, SavedCommandDomain::IOSArchive] {
        let (application, owner) = active(domain);
        let foreign = match domain { SavedCommandDomain::OfflinePreflight => Frame::AndroidBuild(android_wire::Frame::Accepted),
            SavedCommandDomain::AndroidBuild | SavedCommandDomain::ProjectRecovery | SavedCommandDomain::IOSArchive | SavedCommandDomain::ArtifactInspection => Frame::OfflinePreflight(wire::Frame::Accepted) };
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
        assert_eq!(p.reason, reason.android().unwrap());
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
    for domain in [SavedCommandDomain::OfflinePreflight, SavedCommandDomain::AndroidBuild, SavedCommandDomain::ProjectRecovery, SavedCommandDomain::IOSArchive] {
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
    assert!(application.inner.lock().active.is_some());
    assert!(!application.can_exit());
}

#[tokio::test]
async fn declared_domains_drain_rejected_bytes_charge_stderr_and_never_retry_a_close() {
    for domain in [SavedCommandDomain::OfflinePreflight, SavedCommandDomain::AndroidBuild, SavedCommandDomain::ProjectRecovery, SavedCommandDomain::IOSArchive] {
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
async fn accepted_only_eof_is_not_a_settled_decoder_in_any_domain() {
    for domain in [SavedCommandDomain::OfflinePreflight, SavedCommandDomain::AndroidBuild, SavedCommandDomain::ProjectRecovery, SavedCommandDomain::IOSArchive] {
        let (application, owner) = active(domain); owner.pipes.send_replace(Pipes::Available);
        let (output, control) = memory(accepted(domain), false);
        let end = read_output(application.inner.clone(), owner.clone(), output, false, Guard::new(&application.inner, &owner)).await;
        assert!(end.failed && end.eof && end.closed && !end.decoder_settled); assert_eq!(end.frames, 1);
        assert_eq!(control.closes.load(Ordering::SeqCst), 1);
        assert!(application.inner.lock().active.as_ref().unwrap().unknown);
    }
}

#[test]
fn ios_consent_is_domain_local_one_use_and_cannot_qualify_runtime_custody() {
    let owner = application(SavedCommandDomain::IOSArchive);
    assert_eq!(owner.inner.qualified(None), owner.inner.ios_installed_selected());
    let mut android = serde_json::to_value(android_wire::tests::context()).unwrap();
    android.as_object_mut().unwrap().remove("platform"); android.as_object_mut().unwrap().remove("operation");
    assert!(owner.prepare_android(android_wire::prepare(&android).unwrap(), 1, project(), android_wire::Availability::Available).is_err());
    assert_eq!(owner.inner.lock().revision, 0);
    assert!(owner.inner.lock().prepared.is_none() && owner.inner.lock().active.is_none());
    owner.inner.lock().prepared = Some(Prepared { projection: projection(SavedCommandDomain::IOSArchive),
        expires: Instant::now() + INTENT, registration: 1, project: project(), recovery_stamp: None, material: None, recovery: None, android_selection: None, artifact_selection: None, artifact_tools: None });
    let request = json!({"operationId":"a".repeat(32),"ownerGeneration":"b".repeat(32),"consentVersion":ios_wire::CONSENT});
    let status = owner.start_ios(ios_wire::start(&request).unwrap(), Instant::now(), Some((1,project())), ios_wire::Availability::Available).unwrap().release();
    let projection = status.operation.unwrap();
    assert_eq!((projection.phase,projection.outcome),(ios_wire::Phase::Terminal,Some(ios_wire::Outcome::Refused)));
    assert!(projection.result.is_none() && projection.activity.is_none() && projection.disposition.is_none());
    assert!(owner.inner.lock().prepared.is_none() && owner.inner.lock().active.is_none());
    assert!(owner.start_ios(ios_wire::start(&request).unwrap(), Instant::now(), Some((1,project())), ios_wire::Availability::Available).is_err());
}

#[tokio::test]
async fn ios_nine_frames_backpressure_and_core_success_never_replace_original_native_finality() {
    let (application, owner) = active(SavedCommandDomain::IOSArchive);
    owner.pipes.send_replace(Pipes::Available);
    let mut receiver = owner.resources.lock().await.frames.take().unwrap();
    let frames = complete_stream(SavedCommandDomain::IOSArchive,true); assert_eq!(frames.len(),9);
    let bytes: Vec<u8> = frames.into_iter().flatten().collect(); let count = bytes.len();
    let (output,control) = memory(bytes,false);
    let reading = read_output(application.inner.clone(),owner.clone(),output,false,Guard::new(&application.inner,&owner));
    let consuming = async { for _ in 0..9 { application.inner.accept(&owner,receiver.recv().await.unwrap()); } };
    let (end,()) = tokio::join!(reading,consuming);
    assert!(end.eof && end.closed && end.decoder_settled && !end.failed && end.frames == 9);
    assert_eq!(control.read.load(Ordering::SeqCst),count); assert_eq!(control.closes.load(Ordering::SeqCst),1);
    assert_eq!(owner.output_bytes.load(Ordering::SeqCst),count);
    {
        let registry = application.inner.lock(); let active = registry.active.as_ref().unwrap();
        assert!(active.accepted && active.terminal && active.projection.result.is_some() && !active.final_join_seen);
        let projected = active.projection.public().ios().unwrap();
        assert!(projected.result.is_none() && projected.activity.is_none() && projected.disposition.is_none());
    }
    // There is no actual runtime/tool book or native join in this DATA vector.
    let status = application.status_ios(ios_wire::Availability::Available).unwrap().operation.unwrap();
    assert_eq!(status.phase,ios_wire::Phase::Unknown);
    assert!(status.result.is_none() && status.activity.is_none() && status.disposition.is_none());
    assert!(!application.can_exit());
}

#[test]
fn ios_late_core_terminal_never_undoes_first_failure_or_extends_original_endpoint() {
    for due in [IOS_WORK,IOS_HARD] {
        let (application,owner) = active(SavedCommandDomain::IOSArchive); let admitted = owner.clocks.admitted;
        application.inner.accept_at(&owner,Frame::IOSArchive(ios_wire::Frame::Accepted),admitted);
        let terminal = ios_wire::terminal(&ios_wire::tests::complete(),&ios_wire::tests::context(),&owner.id).unwrap();
        application.inner.accept_at(&owner,Frame::IOSArchive(ios_wire::Frame::Terminal(terminal)),admitted+due);
        let registry = application.inner.lock(); let active = registry.active.as_ref().unwrap();
        assert_eq!(active.first_stop,Some(owner.clocks.work)); assert_eq!(active.projection.reason,Reason::TimedOut);
        assert_eq!(active.unknown,due == IOS_HARD); assert!(active.projection.public().result.is_none());
        assert!(registry.last.is_none());
    }
}

#[test]
fn earlier_actual_native_failure_shortens_original_cutoff_even_when_observed_after_cancel() {
    // Invented timestamp DATA only. No runtime, tool, process or native join.
    let (application, owner) = active(SavedCommandDomain::AndroidBuild);
    let earlier=owner.clocks.admitted+Duration::from_secs(1);
    let later=owner.clocks.admitted+Duration::from_secs(5);
    let cutoff=owner.native_audit_cutoff.subscribe();
    let mut registry=application.inner.lock();
    application.inner.stop_locked(&mut registry,&owner,Reason::Cancelled,later);
    assert_eq!(*cutoff.borrow(),later+SETTLEMENT);
    *owner.native_failure.lock().unwrap()=Some((Reason::ToolchainMismatch,earlier));
    application.inner.advance_locked(&mut registry,&owner,later);
    assert_eq!(registry.active.as_ref().unwrap().first_stop,Some(earlier));
    assert_eq!(*cutoff.borrow(),earlier+SETTLEMENT);
    application.inner.stop_locked(&mut registry,&owner,Reason::Shutdown,later+Duration::from_secs(2));
    assert_eq!(*cutoff.borrow(),earlier+SETTLEMENT);
    application.inner.advance_locked(&mut registry,&owner,earlier+SETTLEMENT);
    assert!(registry.active.as_ref().unwrap().unknown);
    assert!(!final_clock_clear(&registry,&owner,earlier+SETTLEMENT));
}

#[test]
fn artifact_two_frames_without_selected_originals_never_publish_and_first_stop_never_renews() {
    // Same real registry and shutdown method, with an inert unstarted intent.
    // No selected-original/worker custody is invented by this DATA fixture.
    let prepared = application(SavedCommandDomain::ArtifactInspection);
    assert!(prepared.can_exit() && !prepared.stopping());
    let intent = projection(SavedCommandDomain::ArtifactInspection);
    let intent_id = intent.operation_id.clone();
    let intent_generation = intent.owner_generation.clone();
    prepared.inner.lock().prepared = Some(Prepared { projection: intent,
        expires: Instant::now() + INTENT, registration: 1, project: project(),
        recovery_stamp: None, material: None, recovery: None, android_selection: None,
        artifact_selection: None, artifact_tools: None });
    assert!(prepared.busy() && !prepared.can_exit());
    prepared.request_shutdown();
    assert!(prepared.stopping() && prepared.can_exit());
    for _ in 0..2 {
        let registry = prepared.inner.lock();
        assert!(registry.prepared.is_none() && registry.active.is_none());
        let retired = registry.last.as_ref().unwrap();
        assert_eq!((&retired.operation_id, &retired.owner_generation), (&intent_id, &intent_generation));
        assert_eq!(retired.reason, Reason::Shutdown);
        assert!(!retired.intent_usable && retired.result.is_none());
        drop(registry);
        prepared.request_shutdown();
    }
    assert!(prepared.can_exit() && prepared.stopping());

    let (application,owner)=active(SavedCommandDomain::ArtifactInspection);
    let t=owner.clocks.admitted;
    assert_eq!(owner.clocks.work,t+Duration::from_secs(900));
    assert_eq!(owner.clocks.finality,t+Duration::from_secs(910));
    assert!(!owner.clocks.signed&&!owner.clocks.recovery);
    // Complete-looking core DATA cannot supply the original selected-ID loan.
    let mut decoder=OutputDecoder::new(&owner).unwrap();
    assert!(decoder.push(&accepted(SavedCommandDomain::ArtifactInspection),&owner).is_ok());
    let terminal=frame(SavedCommandDomain::ArtifactInspection,1,"terminal",artifact_wire::tests::terminal()["payload"].clone());
    assert!(decoder.push(&terminal,&owner).is_err());
    assert!(!decoder.finish());
    {
        let r=application.inner.lock();
        assert!(!artifact_installed_closure_ready(&r,&owner,false,false));
        assert!(!artifact_installed_closure_ready(&r,&owner,true,true));
        assert!(r.last.is_none());
    }
    application.inner.accept_at(&owner,Frame::ArtifactInspection(artifact_wire::Frame::Accepted),t);
    application.inner.accept_at(&owner,Frame::OfflinePreflight(wire::Frame::Accepted),t);
    let first=application.inner.lock().active.as_ref().unwrap().first_stop;
    assert_eq!(first,Some(t));
    application.context_changed();application.request_shutdown();
    let r=application.inner.lock();let active=r.active.as_ref().unwrap();
    assert!(Arc::ptr_eq(&active.owner,&owner)&&active.unknown&&!active.final_join_seen);
    assert_eq!(active.first_stop,first);assert!(active.projection.public().result.is_none());
    assert!(r.last.is_none()&&r.prepared.is_none());
    drop(r);
    assert!(application.stopping() && !application.can_exit());
}

#[test]
fn artifact_original_closure_distinguishes_unentered_from_claimed_and_unreturned_workers() {
    let (application,owner)=active(SavedCommandDomain::ArtifactInspection);
    let r=application.inner.lock();
    let mut projected=r.active.as_ref().unwrap().projection.clone();
    projected.outcome=Some(Outcome::Failed);projected.reason=Reason::ProtocolError;
    assert_eq!(projected.artifact().unwrap().outcome,Some(artifact_wire::Outcome::Failed));
    // These are production-used necessary predicates, not native receipts.
    assert!(artifact_installed_closure_ready(&r,&owner,false,true));
    assert!(!artifact_installed_closure_ready(&r,&owner,false,false));
    assert!(!artifact_installed_closure_ready(&r,&owner,true,true));
    drop(r);
    let book=Resources::default();let startup=Startup::default();
    assert!(!offline_consumers_returned(&book,&startup,true));
    let mut book=book;book.artifact_selected=true;
    assert!(!artifact_installed_final(&book));
    assert!(!owner.startup.lock().unwrap().attempted);
    assert!(!owner.resource_unknown.load(Ordering::SeqCst));
    assert!(owner.artifact_selection.is_none()&&owner.artifact_tools.is_none());
}
