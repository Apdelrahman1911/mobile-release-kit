//! Inert document predicates, empty-owner DATA and compile-time source guards.
//! No DesktopBridge/RNG, selected root, process, task, IO, GUI or native receipt.
//! Source assertions are wiring coverage, NOT exercised native finality.
use super::*;
use crate::android_build_protocol::{Availability, Profile};

fn empty_state() -> DocumentState {
    DocumentState { lifetime: DocumentLifetime::default(), revision: 0, next_operation: 0, next_context: 0,
        exhausted: false, lost_observed: false, session: false, stopping: false, unknown: false,
        quit_pending: false, retiring: false, lock_pending: false, compatibility_picker_pending: false,
        saved_observation: None, saved_input: None, session_owner_reason: None, context: None, slot: None, records: Vec::new(), assignments: Vec::new(), quit: None,
        quit_accepted: false, quit_cleanup_end: None, github: ConnectionState::new(), evidence: EvidenceRegistry::new(), images: images::Registry::new(), installation: installation::Registry::new(),
        #[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64")))]
        vault: None,
        #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
        first_origin: None }
}
fn section<'a>(text: &'a str, start: &str, end: &str) -> &'a str {
    let body = text.split_once(start).unwrap_or_else(|| panic!("missing source section: {start}")).1;
    body.split_once(end).unwrap_or_else(|| panic!("missing end {end:?} for source section: {start}")).0
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
    let handlers = section(SHELL, "tauri::generate_handler![", "];");
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
    for name in ["fn preflight_gate(", "fn environment_gate(", "fn common_gate(", "fn github_gate("] {
        let body = section(DOCUMENT, name, "\n    }");
        for check in ["android_build.disabled()", "android_build.stopping()", "android_build.busy()"] { assert!(body.contains(check), "{name}: {check}"); }
    }
    let private_gate = section(DOCUMENT, "fn gate(", "\n    }");
    let common = private_gate.find("self.common_gate(state, session)?").expect("private gate must delegate to common lifecycle gate");
    for qualification in ["self.live_session_owner_reason()", "ordinary_asset_platform_gate()?", "self.native_qualified()", "session_writable(state)"] {
        let qualified = private_gate.find(qualification).unwrap_or_else(|| panic!("missing private qualification: {qualification}"));
        assert!(common < qualified, "common lifecycle gate must precede {qualification}");
    }
    for name in ["pub(crate) fn passive_query(", "pub(crate) fn configuration_edit_admit_published<T>(", "fn registered_edit_root_locked_published(",
        "pub(crate) fn compatibility_picker_begin(", "pub(crate) fn compatibility_picker_publish(", "pub(crate) fn not_quitting("] {
        assert!(section(DOCUMENT, name, "\n    }").contains("android_build.ensure_idle()?"), "{name}");
    }
    assert!(section(DOCUMENT, "fn evidence_gate(", "\n    }").contains("self.common_gate(state, false)"));
    let passive = section(DOCUMENT, "pub(crate) fn passive_query(", "\n    }");
    assert!(passive.find("android_build.ensure_idle()?").unwrap() < passive.find("supervisor.start_passive(").unwrap());
    assert!(!passive.contains("drop(state)") && !passive.contains(".await"));
}

#[test]
fn android_retirement_never_hides_status_stop_or_lends_offline_fixture_authority() {
    for name in ["pub(crate) fn configuration_edit_admit_published<T>(", "fn registered_edit_root_locked_published(", "pub(crate) fn compatibility_picker_begin("] {
        let body = section(DOCUMENT, name, "\n    }");
        assert!(body.find("android_build.context_changed_published(").unwrap() < body.find("android_build.ensure_idle()?").unwrap());
    }
    for (name, gate) in [("pub(crate) fn context(", "self.gate(&state, true)?"),
        ("pub(crate) fn choose_project(", "self.common_gate(&state, false)?")] {
        let body = section(DOCUMENT, name, "\n    }");
        let invalidated = body.find("android_build.context_changed_published(").unwrap_or_else(|| panic!("{name}: missing Android context invalidation"));
        let gated = body.find(gate).unwrap_or_else(|| panic!("{name}: missing expected gate {gate}"));
        assert!(invalidated < gated, "{name}: Android context invalidation must precede {gate}");
    }
    assert!(section(DOCUMENT, "pub(crate) fn lock_session(", "\n    }").contains("android_build.context_changed_published("));
    for name in ["fn exhaust(", "fn loss_locked(", "pub(crate) fn android_build_relay_lost("] {
        assert!(section(DOCUMENT, name, "\n    }").contains("android_build.document_lost_published("), "{name}");
    }
    for name in ["pub(crate) fn android_build_status(", "pub(crate) fn cancel_android_build("] {
        let body = section(DOCUMENT, name, "\n    }");
        assert!(!body.contains("ensure_idle(") && !body.contains("not_quitting(") && !body.contains("if gate"));
    }
    for name in ["open_config_edit", "prepare_config_edit", "apply_config_edit"] {
        let body = section(SHELL, &format!("async fn {name}("), "\n}");
        assert!(body.contains("configuration_edit_admit_published(") && !body.contains("not_closing("));
    }
    let config = section(DOCUMENT, "pub(crate) fn configuration_edit_admit_published<T>(", "\n    }");
    for required in ["state.unknown || state.exhausted", "!state.lifetime.original_bound() || state.lost_observed", "state.stopping",
        "state.quit_pending || state.retiring || state.lock_pending || state.compatibility_picker_pending", "preflight.ensure_idle()?",
        "android_build.ensure_idle()?", "diagnostics.ensure_idle()?"] { assert!(config.contains(required)); }
    let bridge = include_str!("bridge.rs");
    assert!(bridge.contains("AndroidBuildOwner::new(runtime.clone(), crate::android_toolchain::AndroidToolchainProfile::compiled())"));
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
    let settled = section(SHELL, "async fn settle_relay(", "\n}\n");
    assert!(settled.find("book.handle.as_mut()").unwrap() < settled.find("let joined = handle.await").unwrap());
    assert!(settled.find("let joined = handle.await").unwrap() < settled.find("book.handle.take()").unwrap());
    for name in ["fn gui_response(", "pub(crate) fn compatibility_quit_result("] {
        assert!(section(DOCUMENT, name, "\n    }").contains("android_build.request_shutdown_published("));
    }
    assert!(section(DOCUMENT, "pub(crate) fn can_exit(", "\n    }").contains("android_build.can_exit()"));
    let quit = section(DOCUMENT, "async fn run_quit(", "\n#[cfg(all(test");
    let joined = section(quit, "tokio::join!(", ");");
    for original in ["gui", "document.shutdown_assets()", "supervisor.shutdown()", "edits.shutdown()", "diagnostics.shutdown()", "preflight.shutdown()", "android_build.shutdown()"] {
        assert!(joined.contains(original), "{original}");
    }
    assert!(section(quit, "while !(", ") {").contains("android_build.can_exit()"));
    let compatibility = section(SHELL, "#[cfg(not(any(target_os = \"linux\", target_os = \"macos\", target_os = \"windows\")))]\nfn request_shutdown(", "\n#[derive");
    assert!(section(compatibility, "tokio::join!(", ");").contains("bridge.android_build.shutdown()"));
    assert!(compatibility.contains("android_build.is_ok()") && compatibility.matches("bridge.android_build.can_exit()").count() == 2);
    assert!(!quit.contains("try_join!") && !compatibility.contains("try_join!") && !relay.contains(".abort("));
}

#[test]
fn registration_shell4_are_actual_raw_local_handlers_on_the_retained_relay() {
    let commands=section(include_str!("../build.rs"),"const COMMANDS: &[&str] = &[","];");
    let handlers=section(SHELL,"tauri::generate_handler![","];");
    let capability:Value=serde_json::from_str(include_str!("../capabilities/main.json")).unwrap();
    let permissions=capability["permissions"].as_array().unwrap();
    for command in ["android_tool_registration_status","inspect_android_tool_sources",
        "register_android_tool_sources","cancel_android_tool_registration"] {
        assert_eq!(commands.matches(format!("\"{command}\"").as_str()).count(),1);
        assert_eq!(handlers.matches(command).count(),1);
        let permission=format!("allow-{}",command.replace('_',"-"));
        assert_eq!(permissions.iter().filter(|value|value.as_str()==Some(permission.as_str())).count(),1);
        let body=section(SHELL,&format!("async fn {command}("),"\n}");
        assert!(body.contains("edit_window(&webview)") && body.contains("android_registration_request_body(request.body())?"));
        assert!(body.contains("fixture_command!(state, Forbidden") && body.contains(&format!("state.document.{command}(")));
        assert!(!body.contains(".await") && !body.contains("not_closing("));
    }
    let raw=section(SHELL,"fn android_registration_request_body(","\n}");
    assert!(raw.contains("InvokeBody::Raw(bytes)") && raw.contains("REQUEST_LIMIT"));
    assert!(raw.contains("_ => Err(crate::android_registration_app_protocol::invalid())"));
    let relay=section(SHELL,"fn start_relay(","\nasync fn settle_relay(");
    for required in ["document.android_tool_registration_status()","android_registration_revision != Some(status.status_revision)",
        "crate::android_registration_app_protocol::EVENT","document.android_build_relay_lost()"] {
        assert!(relay.contains(required),"{required}");
    }
}

#[test]
fn saved_observation_is_parsed_once_by_original_retirement_before_sender_delivery() {
    let supervisor=include_str!("supervisor.rs");let bridge=include_str!("bridge.rs");
    let retired=section(supervisor,"fn retire(self, value: Result<Value, BridgeError>, was_unknown: bool)","\nenum CompletionTarget");
    let ordered=["value.and_then(crate::release_version_protocol::result)","completion.complete(",
        "completion.returned()","sender.send(observation)"];
    for pair in ordered.windows(2){assert!(retired.find(pair[0]).unwrap()<retired.find(pair[1]).unwrap());}
    assert_eq!(retired.matches("release_version_protocol::result").count(),1);
    let observed=section(bridge,"pub(crate) async fn observe_release_version(","\n    }");
    assert!(observed.contains("document.saved_observation(self, &input.project_id)") && observed.contains("wait().await"));
    assert!(!observed.contains("release_version_protocol::result") && !observed.contains("saved_input"));
    let unknown=section(supervisor,"fn unknown_policy(","// No supervisor bookkeeping lock");
    assert!(unknown.contains("Some(reply @ PassiveReply::ReleaseVersionObserve { .. }) => reply.sender_for_unknown()"));
    let sender_only=section(supervisor,"fn sender_for_unknown(","fn arm(");
    assert!(sender_only.contains("completion.unknown()") && sender_only.contains("sender.take().map(FailedPassiveReply::ReleaseVersionObserve)"));
    let lane=include_str!("asset_session_saved_observation.rs");
    let complete=section(lane,"pub(crate) fn complete(","pub(crate) fn returned(");
    for required in ["Arc::ptr_eq(lane, &self.lane)","saved_observation_gate(&state, Some(&self.lane))",
        "saved_registration_guard(","edit.matches(&self.lane.stamp)","matches_epoch(self.lane.epoch)"] {
        assert!(complete.contains(required),"{required}");
    }
}

#[test]
fn registration_work_cut_rechecks_actual_first_unknown_and_w_after_book_contention() {
    let owner=include_str!("saved_command_android_registration.rs");
    let work=section(owner,"pub(crate) fn work(&self)","pub(crate) fn first(");
    let book=work.find("self.slot.book.lock()").unwrap();
    let proceed=work.find("if !ControlSlot::pending(&book)").unwrap();
    let actual_first=work.find("self.admission_failure(&book)").unwrap();
    let now=work.find("let entered_at = Instant::now()").unwrap();
    assert!(book<proceed && proceed<actual_first && actual_first<now && now<work.find("return Ok(())").unwrap());
    assert!(work[book..proceed].contains("self.slot.is_unknown() || self.control.unknown.load(Ordering::SeqCst)"));
    assert!(work.contains("self.slot.wake.wait_timeout(book, remaining)"));
    assert!(!work.contains(".borrow()")); // No watch::Ref may survive the real WAIT.
    let cleanup=section(owner,"pub(crate) fn cleanup_expired(","pub(crate) fn publishable(");
    assert!(cleanup.contains("self.import_retained(true)") && cleanup.contains("self.control.advance(now)"));
    assert!(!cleanup.contains("pending(") && !cleanup.contains("wait_timeout") && !cleanup.contains(".work()"));
}

#[test]
fn source_native_cleanup_and_current_document_finality_keep_the_worker_mutex_cut() {
    let owner=include_str!("saved_command_android_registration.rs");
    assert_eq!(owner.matches("original.sources.lock()").count(),1);
    let worker=section(owner,"fn inspect_source(","fn poll_source(");
    assert!(worker.contains("original.sources.lock()") && worker.contains("entry_gate.work()"));
    for body in [section(owner,"fn finalize_under_document(","fn status("),
        section(owner,"fn registration_retained_bytes(","#[cfg(test)]")] {
        assert!(!body.contains(".sources.lock()") && !body.contains(".sources.try_lock()"));
    }
    let finality=section(owner,"fn finalize_under_document(","fn status(");
    for required in ["original.joined_at.get()","original.known_return()","ControlSlot::pending(&book)",
        "original.control.latches.load(Ordering::SeqCst)","original.saved.same_binding(current)","book.review=Some(ReviewRoute"] {
        assert!(finality.contains(required),"{required}");
    }
    let document=include_str!("asset_session_android_registration.rs");
    let finalize=section(document,"fn reconcile_android_registration_locked(","pub(crate) fn android_tool_registration_status(");
    assert!(finalize.contains("saved_registration_guard(") && finalize.contains("validated_saved_input_with_edit("));
    for source in [include_str!("android_registration_source_macos.rs"),include_str!("installed_runtime_macos.rs")] {
        assert!(source.contains("ObservePhase::Cleanup") && source.contains("gate.source_cleanup_expired("));
        assert!(source.contains("gate.source_work()"));
    }
    let source=include_str!("android_registration_source_macos.rs");
    let point=section(source,"fn point(&self, end: Instant", "fn fd(");
    assert!(point.find("gate.source_work()").unwrap()<point.find("self.audit.borrow()").unwrap());
    assert!(include_str!("android_fixed_support_macos.rs").contains("original.original.registration_gate=gate"));
}

#[test]
fn review_cancel_route_and_register_refusal_do_not_create_native_authority() {
    let owner=include_str!("saved_command_android_registration.rs");
    let reserve=section(owner,"pub(crate) fn reserve_cancel(","impl CancelPublisher");
    assert!(reserve.contains("route.operation_id==input.operation_id && route.generation==input.registration_generation"));
    assert!(!reserve.contains("input.review_id"));
    let install=section(owner,"fn install(&self,original:","fn clear_review(");
    assert!(install.contains("Self::pending(&book)") && install.contains("route.matches(review)"));
    assert!(install.find("book.review=None").unwrap()<install.find("book.original=Some(original)").unwrap());
    let admit=section(owner,"pub(crate) fn admit_android_tool_registration(","pub(crate) fn cancel_android_tool_registration(");
    let register=section(admit,"if let Request::Register(input)=&snapshot.request{","#[cfg(not(all(target_os=");
    assert!(register.contains("return Err(wire::unavailable())"));
    assert!(!register.contains(".begin(") && !register.contains("spawn(") && !register.contains(".install("));
    let poll=section(DOCUMENT,"fn reconcile_checked(","fn reconcile_checked_published(");
    assert!(poll.contains("RegistrationPublisherKind::General,false") && poll.contains("Err(error) if error.code==\"busy\"=>return"));
    let sources=include_str!("saved_command_android_sources.rs");
    for name in ["pub(crate) fn admit_android_source_pick(","pub(crate) fn publish_android_source("] {
        let body=section(sources,name,"\n    }");
        assert!(body.contains("publisher.accepted()") && body.contains("publisher.same_slot(&self.inner.android_registration_control)"));
    }
}
