//! Inert document predicates, empty-owner DATA and compile-time source guards.
//! No DesktopBridge/RNG, selected root, process, task, IO, GUI or native receipt.
//! Source assertions are wiring coverage, NOT exercised native finality.
use super::*;
use crate::android_build_protocol::{Availability, Profile};

fn empty_state() -> DocumentState {
    DocumentState { lifetime: DocumentLifetime::default(), revision: 0, next_operation: 0, next_context: 0,
        exhausted: false, lost_observed: false, session: false, stopping: false, unknown: false,
        quit_pending: false, retiring: false, lock_pending: false, compatibility_picker_pending: false,
        context: None, slot: None, records: Vec::new(), assignments: Vec::new(), quit: None,
        quit_accepted: false, quit_cleanup_end: None, github: ConnectionState::new(), evidence: EvidenceRegistry::new() }
}
fn section<'a>(text: &'a str, start: &str, end: &str) -> &'a str {
    text.split_once(start).unwrap().1.split_once(end).unwrap().0
}
const DOCUMENT: &str = include_str!("asset_session.rs");
const SHELL: &str = include_str!("shell.rs");

#[test]
fn android_pending_finished_and_unsupported_absence_do_not_poison_passive_work() {
    let mut state = empty_state();
    assert!(passive_document_gate(&state).is_ok());
    assert_eq!(android_build_document_gate(&state, Some(Profile::LinuxX64)), Some(Availability::Busy));
    assert_eq!(android_build_document_gate(&state, None), Some(Availability::UnsupportedPlatform));
    state.lifetime.crash_hook_installed(); state.lifetime.started(true);
    assert_eq!(android_build_document_gate(&state, Some(Profile::LinuxX64)), Some(Availability::Busy));
    state.lifetime.finished(true);
    assert_eq!(android_build_document_gate(&state, Some(Profile::LinuxX64)), None);
    state.lifetime.invalidate(); state.lost_observed = true;
    assert_eq!(android_build_document_gate(&state, Some(Profile::LinuxX64)), Some(Availability::DocumentLost));
    assert_eq!(android_build_document_gate(&state, None), Some(Availability::UnsupportedPlatform));
    assert!(passive_document_gate(&state).is_ok());
    state.quit_pending = true; assert!(passive_document_gate(&state).is_err());
    state.quit_pending = false; state.unknown = true; assert!(passive_document_gate(&state).is_err());
}

#[test]
fn an_empty_unqualified_android_owner_does_not_claim_resource_work() {
    // This constructor only retains RuntimeConfig DATA and empty owner books.
    let owner = crate::android_build_owner::AndroidBuildOwner::new(
        crate::runtime::RuntimeConfig::packaged("/never-opened-android-wiring-runtime".into()), None);
    let status = owner.status(Availability::Available).unwrap();
    assert_eq!(status.availability, if Profile::current().is_some() { Availability::RuntimeUnqualified } else { Availability::UnsupportedPlatform });
    assert!(status.operation.is_none() && owner.can_exit() && !owner.busy() && !owner.disabled());
    assert!(owner.ensure_idle().is_ok());
    owner.document_lost();
    let status = owner.status(Availability::DocumentLost).unwrap();
    assert_eq!(status.availability, if Profile::current().is_some() { Availability::DocumentLost } else { Availability::UnsupportedPlatform });
    assert!(status.operation.is_none() && owner.ensure_idle().is_ok());
    owner.request_shutdown();
    assert_eq!(owner.status(Availability::Shutdown).unwrap().availability, Availability::Shutdown);
    assert!(owner.can_exit() && !owner.disabled() && owner.ensure_idle().is_err());
}

#[test]
fn android_commands_stay_raw_local_and_closed_without_generic_permissions() {
    let commands = section(include_str!("../build.rs"), "const COMMANDS: &[&str] = &[", "];");
    let handlers = section(SHELL, ".invoke_handler(tauri::generate_handler![", "])");
    let capability: Value = serde_json::from_str(include_str!("../capabilities/main.json")).unwrap();
    assert_eq!(capability["local"], true); assert_eq!(capability["windows"], serde_json::json!(["main"]));
    assert!(capability.get("remote").is_none());
    let permissions = capability["permissions"].as_array().unwrap();
    for command in ["prepare_android_build", "start_android_build", "android_build_status", "cancel_android_build"] {
        assert_eq!(commands.matches(format!("\"{command}\"").as_str()).count(), 1);
        assert_eq!(handlers.matches(command).count(), 1);
        let permission = format!("allow-{}", command.replace('_', "-"));
        assert_eq!(permissions.iter().filter(|p| p.as_str() == Some(permission.as_str())).count(), 1);
        let body = section(SHELL, &format!("async fn {command}("), "\n}");
        assert!(body.contains("edit_window(&webview)") && body.contains("android_build_request_body(request.body())?"));
        assert!(body.contains("fixture_command!(state, Forbidden") && !body.contains("not_closing(") && !body.contains(".await"));
    }
    for permission in permissions {
        let permission = permission.as_str().unwrap();
        assert!(permission.starts_with("allow-") || ["core:event:allow-listen", "core:event:allow-unlisten"].contains(&permission));
    }
    let parser = section(SHELL, "fn android_build_request_body(", "\n}");
    assert!(parser.contains("InvokeBody::Raw(bytes) => crate::android_build_protocol::raw_request(bytes)"));
    assert!(parser.contains("InvokeBody::Json(_) => Err(crate::android_build_protocol::invalid())"));
}

#[test]
fn android_admission_and_reciprocal_exclusion_use_the_real_document_gate() {
    let prepare = section(DOCUMENT, "pub(crate) fn prepare_android_build(", "\n    }");
    assert!(prepare.find("self.lock()").unwrap() < prepare.find("self.android_build_gate(&state)").unwrap());
    assert!(prepare.find("self.android_build_gate(&state)").unwrap() < prepare.find("native_project(&args.project_id)").unwrap());
    assert!(prepare.find("native_project(&args.project_id)").unwrap() < prepare.find("android_build.prepare(args, generation, root, gate)").unwrap());
    let start = section(DOCUMENT, "pub(crate) fn start_android_build(", "\n    }");
    let ordered = ["Instant::now()", "self.lock()", "android_build.prepared_project(", "native_project(&project)",
        "android_build.start(args, admitted_at, selected, self.android_build_gate(&state))?", "drop(state)", "admitted.release()"];
    for pair in ordered.windows(2) { assert!(start.find(pair[0]).unwrap() < start.find(pair[1]).unwrap()); }
    assert!(!start.contains(".await") && !start.contains("spawn("));
    let gate = section(DOCUMENT, "fn android_build_gate(", "\n    }");
    for required in ["state.unknown", "state.exhausted", "state.quit_pending", "state.retiring", "state.lock_pending", "state.compatibility_picker_pending",
        "android_build_document_gate(", "slot.phase != Phase::Idle || !slot.owner.resources_settled()", "state.github.registration().is_some()",
        "!self.inner.bridge.edits.can_exit()", "self.inner.bridge.edits.preflight_attention()", "!self.inner.bridge.supervisor.can_exit()",
        "self.inner.bridge.diagnostics.busy()", "self.inner.bridge.preflight.disabled()", "self.inner.bridge.preflight.stopping()", "self.inner.bridge.preflight.busy()"] {
        assert!(gate.contains(required), "missing Android gate: {required}");
    }
    for name in ["fn preflight_gate(", "fn environment_gate(", "fn gate(", "fn github_gate("] {
        let body = section(DOCUMENT, name, "\n    }");
        for check in ["android_build.disabled()", "android_build.stopping()", "android_build.busy()"] { assert!(body.contains(check), "{name}: {check}"); }
    }
    for name in ["pub(crate) fn passive_query(", "pub(crate) fn configuration_edit_admit<T>(", "fn registered_edit_admit<T>(",
        "pub(crate) fn compatibility_picker_begin(", "pub(crate) fn compatibility_picker_publish(", "pub(crate) fn not_quitting("] {
        assert!(section(DOCUMENT, name, "\n    }").contains("android_build.ensure_idle()?"), "{name}");
    }
    assert!(section(DOCUMENT, "fn evidence_gate(", "\n    }").contains("self.gate(state, false)"));
    let passive = section(DOCUMENT, "pub(crate) fn passive_query(", "\n    }");
    assert!(passive.find("android_build.ensure_idle()?").unwrap() < passive.find("supervisor.start_passive(").unwrap());
    assert!(!passive.contains("drop(state)") && !passive.contains(".await"));
}

#[test]
fn android_retirement_never_hides_status_stop_or_lends_offline_fixture_authority() {
    for name in ["pub(crate) fn configuration_edit_admit<T>(", "fn registered_edit_admit<T>(", "pub(crate) fn compatibility_picker_begin("] {
        let body = section(DOCUMENT, name, "\n    }");
        assert!(body.find("android_build.context_changed()").unwrap() < body.find("android_build.ensure_idle()?").unwrap());
    }
    for name in ["pub(crate) fn context(", "pub(crate) fn choose_project("] {
        let body = section(DOCUMENT, name, "\n    }");
        assert!(body.find("android_build.context_changed()").unwrap() < body.find("self.gate(").unwrap());
    }
    assert!(section(DOCUMENT, "pub(crate) fn lock_session(", "\n    }").contains("android_build.context_changed()"));
    for name in ["fn exhaust(", "fn loss_locked(", "pub(crate) fn android_build_relay_lost("] {
        assert!(section(DOCUMENT, name, "\n    }").contains("android_build.document_lost()"), "{name}");
    }
    for name in ["pub(crate) fn android_build_status(", "pub(crate) fn cancel_android_build("] {
        let body = section(DOCUMENT, name, "\n    }");
        assert!(!body.contains("ensure_idle(") && !body.contains("not_quitting(") && !body.contains("if gate"));
    }
    for name in ["open_config_edit", "prepare_config_edit", "apply_config_edit"] {
        let body = section(SHELL, &format!("async fn {name}("), "\n}");
        assert!(body.contains("configuration_edit_admit(") && !body.contains("not_closing("));
    }
    let config = section(DOCUMENT, "pub(crate) fn configuration_edit_admit<T>(", "\n    }");
    for required in ["state.unknown || state.exhausted", "!state.lifetime.original_bound() || state.lost_observed", "state.stopping",
        "state.quit_pending || state.retiring || state.lock_pending || state.compatibility_picker_pending", "preflight.ensure_idle()?",
        "android_build.ensure_idle()?", "diagnostics.ensure_idle()?"] { assert!(config.contains(required)); }
    let bridge = include_str!("bridge.rs");
    assert!(bridge.contains("AndroidBuildOwner::new(runtime, crate::android_toolchain::AndroidToolchainProfile::compiled())"));
    for name in ["pub fn open_config_edit(", "pub(crate) fn register_picked_project("] {
        assert!(section(bridge, name, "\n    }").contains("self.android_build.ensure_idle()?"));
    }
    let fixture = section(bridge, "pub(crate) fn offline_fixture_registration(", "\n    }");
    assert!(fixture.contains("OfflineRegistrationPermit") && fixture.contains("permit.validate(&self.preflight)?"));
    assert!(!fixture.contains("android_build"));
    let owner = include_str!("saved_command_owner.rs");
    assert!(section(owner, "pub(crate) fn can_exit(", "pub(crate) fn busy(").contains("r.active.is_none() && r.prepared.is_none()"));
    for flag in ["ANDROID_NATIVE_QUALIFIED", "ANDROID_RUNTIME_QUALIFIED", "ANDROID_TOOLCHAIN_QUALIFIED"] {
        assert!(owner.contains(&format!("const {flag}: bool = false;")));
    }
}

#[test]
fn android_relay_loss_and_both_quit_backends_keep_originals_in_finality() {
    let relay = section(SHELL, "fn start_relay(", "\nasync fn settle_relay(");
    let spawn = relay.find("tauri::async_runtime::spawn(async move {").unwrap();
    let enter = relay.find("enter.await").unwrap();
    for before in ["document.android_build_subscribe()", "let preflight_guard = PreflightRelayGuard", "let android_build_guard = AndroidBuildRelayGuard"] {
        assert!(relay.find(before).unwrap() < spawn);
    }
    for binding in ["let mut preflight_guard = preflight_guard;", "let mut android_build_guard = android_build_guard;"] {
        let captured = relay.find(binding).unwrap();
        assert!(spawn < captured && captured < enter);
    }
    assert!(section(SHELL, "impl Drop for AndroidBuildRelayGuard", "\nfn start_relay(").contains("self.document.android_build_relay_lost()"));
    for required in ["android_build_revision != Some(status.status_revision)", "crate::android_build_protocol::EVENT", "document.android_build_relay_lost()",
        "android_build.changed()", "android_build_guard.closed = true"] { assert!(relay.contains(required)); }
    let settled = section(SHELL, "async fn settle_relay(", "\n#[cfg(target_os = \"linux\")]");
    assert!(settled.find("book.handle.as_mut()").unwrap() < settled.find("let joined = handle.await").unwrap());
    assert!(settled.find("let joined = handle.await").unwrap() < settled.find("book.handle.take()").unwrap());
    for name in ["fn gui_response(", "pub(crate) fn compatibility_quit_result("] {
        assert!(section(DOCUMENT, name, "\n    }").contains("android_build.request_shutdown()"));
    }
    assert!(section(DOCUMENT, "pub(crate) fn can_exit(", "\n    }").contains("android_build.can_exit()"));
    let quit = section(DOCUMENT, "async fn run_quit(", "\n#[cfg(all(test");
    let joined = section(quit, "tokio::join!(", ");");
    for original in ["gui", "document.shutdown_assets()", "supervisor.shutdown()", "edits.shutdown()", "diagnostics.shutdown()", "preflight.shutdown()", "android_build.shutdown()"] {
        assert!(joined.contains(original), "{original}");
    }
    assert!(section(quit, "while !(", ") {").contains("android_build.can_exit()"));
    let compatibility = section(SHELL, "#[cfg(not(target_os = \"linux\"))]\nfn request_shutdown(", "\n#[derive");
    assert!(section(compatibility, "tokio::join!(", ");").contains("bridge.android_build.shutdown()"));
    assert!(compatibility.contains("android_build.is_ok()") && compatibility.matches("bridge.android_build.can_exit()").count() == 2);
    assert!(!quit.contains("try_join!") && !compatibility.contains("try_join!") && !relay.contains(".abort("));
}
