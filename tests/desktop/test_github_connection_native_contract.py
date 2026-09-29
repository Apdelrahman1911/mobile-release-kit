"""SOURCE wiring contracts; no imports of the core/helper, native IO or GUI.

These checks read only fixed first-party SOURCE files. They do not qualify
Tauri, TLS, native process settlement or an installed runtime.
"""
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
COMMANDS = (
    "github_connection_status", "github_connection_connect_token",
    "github_connection_start_device", "github_connection_open_device_page",
    "github_connection_refresh", "github_connection_inspect", "github_connection_disconnect",
)


def source(path):
    return (ROOT / path).read_text(encoding="utf-8")


def section(text, start, end):
    return text.split(start, 1)[1].split(end, 1)[0]


class GitHubNativeWiringTests(unittest.TestCase):
    def test_installed_mapping_observer_cannot_block_the_request_that_loads_ssl(self):
        supervisor = source("desktop/src-tauri/src/supervisor.rs")
        drive = section(supervisor, "async fn drive(", "\n}")
        self.assertEqual(drive.count("inner.native_test.child_case(&owner)"), 1)
        self.assertEqual(drive.count("observe_installed_original("), 2)
        passive = drive.index("observed_case.filter(|case| !case.after_io())")
        github = drive.index("observed_case.filter(|case| case.after_io())")
        self.assertLess(passive, drive.index("let (stdin, stdout, stderr)"))
        self.assertGreater(github, drive.index("if resources.writer.is_none() || resources.stdout.is_none() || resources.stderr.is_none()"))
        self.assertLess(github, drive.index("child.try_wait()"))
        self.assertIn("Some((&mut fault_rx, &mut faults_open))", drive)
        join = section(supervisor, "async fn join_installed_observation<T>(", "\n}")
        self.assertLess(join.index("fault = receiver.recv()"), join.index("result = join_slot(original)"))
        self.assertIn("biased;", join)
        self.assertIn("Some(error) => fail(error)", join)
        self.assertIn("None => **open = false", join)
        self.assertNotIn("tokio::spawn", join)
        self.assertNotIn("timeout", join)
        self.assertNotIn(".take()", join)

    def test_installed_original_io_is_observed_before_consumption_and_final_handle_is_serialized(self):
        supervisor = source("desktop/src-tauri/src/supervisor.rs")
        peer = source("desktop/src-tauri/src/github_tls_peer_owner.rs")
        drive = section(supervisor, "async fn drive(", "\n}")
        self.assertLess(drive.index("settle_installed(&mut resources"), drive.index("witness.observe_settled_io(&owner, &resources)"))
        self.assertLess(drive.index("witness.observe_settled_io(&owner, &resources)"), drive.index("resources.out_end.take()"))
        observe = section(peer, "pub(crate) async fn observe_retired(", "\n        }")
        self.assertLess(observe.index("self.observing.lock().await"), observe.index("self.observe_retired_inner("))
        self.assertIn("resources.out_end.is_none() && resources.err_end.is_none()", peer)
        self.assertIn("lock(&self.io_checked).contains(&owner.key)", peer)
        self.assertIn("state.cleanup_endpoint.is_some()==(self.case.deadline()||self.case.active_control())", peer)
        observer = source("desktop/src-tauri/src/installed_shell_github_observation.rs")
        self.assertIn("DomObservation::Stale=>return", observer)
        self.assertIn("DomObservation::Refused=>{self.fail();return;}", observer)
        self.assertIn('original["operationId"].as_str()==Some(id.as_str())', observer)


    def test_normal_boundaries_join_actual_peer_and_original_child_without_another_owner(self):
        peer = source("desktop/src-tauri/src/github_tls_peer_owner.rs")
        supervisor = source("desktop/src-tauri/src/supervisor.rs")
        ui = source("desktop/src-tauri/src/installed_shell_github_observation.rs")
        profile = section(peer, "pub(crate) fn profile(self) -> RuntimeProfile", "pub(crate) fn manifest(")
        self.assertIn("Self::NormalNegative|Self::DnsDeadline|Self::ConnectDeadline=>RuntimeProfile::Normal", profile)
        original = section(supervisor, "pub(super) fn observe_original_child(", "pub(super) fn report(")
        self.assertEqual(original.count("witness.observe_boundary(id,_key,profile,end,&stop)"), 1)
        self.assertLess(original.index("child_snapshot("), original.index("witness.observe_boundary("))
        boundary = section(peer, "fn observe_boundary(", "fn register(")
        for value in ("self.original_profile(&owner)==Some(RuntimeProfile::Normal)", "owner.endpoint()==end",
                      "arrivals.installed_first_dns", "original_socket_fds(id,end)", "joined_boundary("):
            self.assertIn(value, boundary)
        for forbidden in ("spawn(", "Command::new", ".try_wait(", ".wait(", ".start_kill(", "Instant::now() +"):
            self.assertNotIn(forbidden, boundary)
        joined = section(peer, "fn joined_boundary(", "fn dns_protocol(")
        self.assertIn("if before!=after{return Ok(None);}", joined)
        self.assertIn("*inode==row.inode && after.get(fd)==Some(inode)", joined)
        self.assertIn('require(selected.is_none(),"installed_github_boundary_ambiguous")', joined)
        self.assertIn("rustix::fs::RawDir::new(&directory,&mut buffer)", peer)
        self.assertIn('nix::unistd::close(directory).is_err()', peer)
        settle = section(ui, "pub(super) async fn settle_for_exit(", "pub(super) fn complete(")
        self.assertLess(settle.index("self.product.observe_retired("), settle.index("peer.settle(success,"))
        self.assertLess(settle.index("peer.settle(success,"), settle.index("peer.validate("))
        self.assertIn('"notProven":self.case.not_proven()', ui)

    def test_closed_commands_match_handler_build_and_local_capability(self):
        shell = source("desktop/src-tauri/src/shell.rs")
        handlers = section(shell, "tauri::generate_handler![", "];")
        build = source("desktop/src-tauri/build.rs")
        capability = json.loads(source("desktop/src-tauri/capabilities/main.json"))
        self.assertTrue(capability["local"])
        self.assertNotIn("remote", capability)
        self.assertEqual(capability["windows"], ["main"])
        for command in COMMANDS:
            self.assertEqual(handlers.count(command), 1)
            self.assertEqual(build.count(f'"{command}"'), 1)
            self.assertEqual(capability["permissions"].count("allow-" + command.replace("_", "-")), 1)
            body = section(shell, f"async fn {command}(", "\n}")
            self.assertIn("fixture_command!(state, Forbidden", body)
            self.assertIn("github_connection_body(&webview, &request)?", body)
        entry = section(shell, "async fn github_connection_connect_token(", "\n}")
        self.assertNotIn(".await", entry)
        relay = section(shell, "fn start_relay(", "\nasync fn settle_relay(")
        self.assertIn("document.github_connection_status()", relay)
        self.assertIn("github_connection_wire::EVENT", relay)
        self.assertEqual(relay.count("Duration::from_millis(100)"), 1)

    def test_device_original_admission_mailbox_and_browser_claim_are_separate(self):
        supervisor = source("desktop/src-tauri/src/supervisor.rs")
        session = source("desktop/src-tauri/src/github_connection_session.rs")
        document = source("desktop/src-tauri/src/asset_session.rs")
        shell = source("desktop/src-tauri/src/shell.rs")
        protocol = source("desktop/src-tauri/src/github_device_protocol.rs")
        self.assertIn('include_bytes!("../../github-device-publisher.json")', protocol)
        self.assertEqual(json.loads(source("desktop/github-device-publisher.json"))["schemaVersion"], 1)
        begin = section(session, "pub(crate) fn begin_device(", "\n    fn consume_device_original(")
        self.assertIn('format!("github-authorize-{sequence}")', begin)
        self.assertIn("supervisor.start_github_device(", begin)
        reconcile = section(session, "pub(crate) fn reconcile(", "\n    fn accept_final(")
        self.assertNotIn("start_github", reconcile); self.assertNotIn("advance_device_if_due", reconcile)
        take = section(supervisor, "pub(crate) fn take_settled(", "\n    }")
        self.assertIn("outcome.take()", take); self.assertNotIn(".clone()", take)
        outer = section(supervisor, "enum ReadOutcome {", "\n#[derive(Clone, Copy)]")
        self.assertNotIn("derive", outer); self.assertNotIn("Debug", outer)
        start = section(supervisor, "pub(crate) fn start_github_device(", "\n    pub(crate) fn start_github_preflight(")
        self.assertIn("original_end.min(started_at + OPERATION_TIME)", start)
        self.assertIn("self.admit_until(", start)
        browser = section(shell, "async fn github_connection_open_device_page(", "\n}")
        self.assertLess(browser.index("app.run_on_main_thread"), browser.index("document.claim_github_device_page"))
        self.assertLess(browser.index("document.claim_github_device_page"), browser.index("open_fixed_device_page"))
        claim = section(document, "pub(crate) fn claim_github_device_page(", "\n    }")
        for required in ("self.github_gate(&state)", "github_registration(project)", "generation != original", "state.github.allow_device_page"):
            self.assertIn(required, claim)
        for forbidden in ("self.expire(", ".reconcile(", "open_fixed_device_page", "start_github", ".await"):
            self.assertNotIn(forbidden, claim)
        refresh = section(session, "pub(crate) fn refresh(", "\n    pub(crate) fn disconnect(")
        self.assertLess(refresh.index("private.retirement"), refresh.index("supervisor.start_github_readonly"))
        self.assertIn("op.kind != OperationKind::Authorize", refresh)

    def test_metadata_inspection_reuses_connection_owner_and_has_no_filesystem_request_authority(self):
        document = source("desktop/src-tauri/src/asset_session.rs")
        session = source("desktop/src-tauri/src/github_connection_session.rs")
        supervisor = source("desktop/src-tauri/src/supervisor.rs")
        inspect = section(document, "pub(crate) fn github_connection_inspect(", "\n    }")
        self.assertLess(inspect.index("self.expire("), inspect.index("decode_command_value"))
        self.assertLess(inspect.index("self.github_gate("), inspect.index("decode_command_value"))
        self.assertIn("state.github.inspect(args", inspect)
        for forbidden in ("std::fs", "project.root", "project.path", ".await"):
            self.assertNotIn(forbidden, inspect)
        selected = section(session, "fn refresh_selected(", "\n    pub(crate) fn disconnect(")
        for required in ("private.retirement", "private.clock.end", "private.account_pin", "private.repository_pin",
                         "self.status.account.state != FactState::Observed", "self.status.repository.state != FactState::Observed",
                         "private.inspection = selection", "self.fact_retirement(Reason::Stale)"):
            self.assertIn(required, selected)
        final = section(session, "fn accept_final(", "\n    fn accept_facts(")
        self.assertLess(final.index("private.inspection.take()"), final.index("outcome.metadata"))
        self.assertLess(final.index("self.apply_control("), final.index("expected_inspection.as_ref()"))
        self.assertLess(final.index("expected_inspection.as_ref()"), final.index("self.accept_facts("))
        owner = section(supervisor, "pub(crate) fn start_github_metadata(", "\n    pub(crate) fn start_github_device(")
        self.assertIn("Some(original_end), Some(selection)", owner)
        self.assertIn("CompletionTarget::GitHub(receipt.clone())", owner)
        self.assertNotIn("tokio::spawn", owner)
        self.assertNotIn("CompletionTarget::Metadata", supervisor)

    def test_device_helper_is_one_exchange_without_auto_poll_or_dynamic_publisher_resource(self):
        transport = source("src/mobile_release/_github_connection_transport.py")
        step = section(transport, "def device_step(", "\ndef _make_live_reader(")
        self.assertEqual(step.count('exchange("POST", path, body)'), 1)
        self.assertNotIn("while ", step); self.assertNotIn("sleep(", step)
        self.assertIn('result.observation["body"].clear()', step)
        exchange = section(transport, "def _make_live_exchange(", "\ndef _device_form(")
        self.assertIn("if device_claimed:", exchange); self.assertIn("device_claimed = True", exchange)
        self.assertIn("connection.auto_open = 0", exchange)
        self.assertIn("context.keylog_filename = None", exchange)
        self.assertIn("original.close()", exchange)
        self.assertNotIn("github-device-publisher.json", source("desktop/tools/prepare_runtime.py"))
        self.assertNotIn("github-device-publisher.json", source("src/mobile_release/_desktop_github_engine.py"))
        profile = section(source("desktop/src-tauri/src/runtime.rs"), "impl GitHubDeviceInstalledProfile {", "\n}")
        self.assertIn("SOURCE_BINDING", profile)
        self.assertIn("DEVICE_PUBLISHER_ANCHOR", profile)
        self.assertNotIn("std::env", profile)

    def test_real_document_retirement_and_exit_do_not_change_vault_lock_semantics(self):
        document = source("desktop/src-tauri/src/asset_session.rs")
        session = source("desktop/src-tauri/src/github_connection_session.rs")
        bridge = source("desktop/src-tauri/src/bridge.rs")
        self.assertIn("github: ConnectionState", section(document, "struct DocumentState {", "\n}"))
        connect = section(document, "pub(crate) fn github_connection_connect_token(", "\n    }")
        self.assertLess(connect.index("self.github_gate(&state)"), connect.index("decode_command_value"))
        self.assertLess(connect.index("github_registration"), connect.index("state.github.connect("))
        self.assertNotIn(".await", connect)
        lookup = section(bridge, "pub(crate) fn github_registration(", "\n    }")
        self.assertLess(lookup.index("self.projects.lock()"), lookup.index("self.project_generation.load("))
        self.assertIn("projects.contains_key(id)", lookup)
        for forbidden in ("project.root", "project.path", "native_project", "std::fs", "clear_poison"):
            self.assertNotIn(forbidden, lookup)
        for name in ("fn loss_locked(", "fn gui_response(", "pub(crate) fn choose_project("):
            body = section(document, name, "\n    }")
            self.assertIn("state.github.retire(", body)
        choose = section(document, "pub(crate) fn choose_project(", "\n    }")
        self.assertLess(choose.index("state.github.retire("), choose.index("self.install("))
        self.assertIn("state.github.exhaust()", section(document, "fn exhaust(", "\n    }"))
        self.assertNotIn("github", section(document, "fn assets_can_exit_locked(", "\n}"))
        for name in ("async fn shutdown_assets(", "pub(crate) fn can_exit(", "fn retained_material_can_exit("):
            self.assertIn("state.github.material_settled()", section(document, name, "\n    }"))
        self.assertIn("const GITHUB_CONNECTION_NATIVE_QUALIFIED: bool = false;", session)
        qualified = section(document, "fn github_qualified(", "\n    }")
        self.assertIn("github_session::qualified_for(&self.inner.bridge.supervisor)", qualified)
        availability = section(session, "pub(crate) fn qualified_for(", "\n}")
        self.assertIn("supervisor.github_readonly_profile_available()", availability)
        self.assertNotIn("INSTALLED_SESSION_INPUTS_QUALIFIED", availability)
        self.assertNotIn("tokio::spawn", session)
        self.assertNotIn("Mutex<", session)
        self.assertNotIn("Serialize", section(session, "struct PrivateSession {", "\n}"))

    def test_installed_github_keeps_its_own_sealed_profile_and_original_owner_custody(self):
        runtime = source("desktop/src-tauri/src/runtime.rs")
        supervisor = source("desktop/src-tauri/src/supervisor.rs")
        installed = source("desktop/src-tauri/src/installed_runtime.rs")
        profile = section(runtime, "impl GitHubReadOnlyInstalledProfile {", "\n}")
        self.assertIn('bootstrap: cwd.join("github_connection_bootstrap.py")', profile)
        self.assertIn('release == b"6.17.0-1022-azure"', profile)
        available = section(runtime, "pub(crate) fn github_readonly_installed_profile_available(", "\n    }")
        resolve = section(runtime, "pub(crate) fn resolve_github_readonly_installed(", "\n    }")
        self.assertIn("self.github_readonly_installed_profile()", available)
        self.assertIn("self.github_readonly_installed_profile()", resolve)
        self.assertNotIn("std::env", profile)
        self.assertIn("let manifest = self.manifest_anchor()?", profile)
        custody = section(installed, "fn inspect_edit_once(", "\n    fn start_edit_preparation")
        self.assertIn("github.manifest_anchor()", custody)
        self.assertIn("self.inspect_inner_with_manifest(Some(anchor), end, stop)", custody)
        ordinary = section(installed, "fn inspect_inner(", "\n    }")
        self.assertIn("self.inspect_inner_with_manifest(MANIFEST_ANCHOR, end, stop)", ordinary)
        self.assertIn("pub(crate) const GITHUB_TLS_PROFILE_QUALIFIED: bool = false;", runtime)
        for value in ("GitHubReadOnlyPreparing", "GitHubReadOnlyPrepared",
                      "GitHubReadOnly(crate::runtime::GitHubReadOnlyInstalledProfile)",
                      "pub(crate) struct GitHubReadOnlyRuntimeSlots"):
            self.assertIn(value, installed)
        resources = section(supervisor, "struct Resources {", "\n}")
        self.assertIn("github_readonly: Option<Arc<Mutex<GitHubReadOnlyRuntimeSlots>>>", resources)
        admission = section(supervisor, "fn admit(", "\n    pub async fn shutdown")
        self.assertLess(admission.index("GitHubReadOnlyRuntimeSlots::new()"), admission.index("owners.insert("))
        self.assertLess(admission.index("owners.insert("), admission.index("executor.spawn("))
        acquire = section(supervisor, "fn acquire_github_original(inner:", "\n}")
        self.assertLess(acquire.index("runtime.prepare_once("), acquire.index("Command::new("))
        self.assertLess(acquire.index("github_claim_clear("), acquire.index("runtime.claim_once()"))
        self.assertLess(acquire.index("runtime.claim_once()"), acquire.index("command.spawn()"))
        self.assertIn(".env_clear()", acquire)
        self.assertNotIn(".await", acquire)
        self.assertNotIn("spawn_original(", acquire)
        settlement = section(supervisor, "async fn settle_installed(", "\nasync fn ready_after_custody")
        for value in ("installed_settlement_slots(resources, owner.profile)", "inspection.returned()",
                      "acquisition.returned()", "resources.waited.is_some()", "resources.native_settlement",
                      "resources.native_return", "native.settled()"):
            self.assertIn(value, settlement)
        drive = section(supervisor, "async fn drive(", "\n#[cfg(all(test,")
        self.assertIn("config.resolve_github_readonly_installed(", drive)
        self.assertIn("acquire_github_original(", drive)
        self.assertIn("settle_installed(", drive)



if __name__ == "__main__":
    unittest.main()
