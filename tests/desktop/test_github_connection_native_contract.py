"""SOURCE wiring and inert-bootstrap DATA contracts; no core/engine imports.

Wiring checks read fixed first-party SOURCE. The bootstrap truth table executes
only its fixed body with injected inert os/sys/time/engine modules, never the
real engine, native IO, TLS or GUI. No installed-runtime qualification is made.
"""
import json
from pathlib import Path
import posixpath
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[2]
COMMANDS = (
    "github_connection_status", "github_connection_connect_token",
    "github_connection_refresh", "github_connection_disconnect",
)
LINUX_CFG = '#[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]'
MAC_CFG = '#[cfg(all(target_os = "macos", target_arch = "aarch64"))]'


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
        profile = section(runtime, LINUX_CFG + "\nimpl GitHubReadOnlyInstalledProfile {", "\n}")
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

    def test_macos_readonly_uses_its_typed_book_and_prepares_environment_before_claim(self):
        runtime = source("desktop/src-tauri/src/runtime.rs")
        supervisor = source("desktop/src-tauri/src/supervisor.rs")
        installed = source("desktop/src-tauri/src/installed_runtime_macos.rs")
        profile = section(runtime, MAC_CFG + "\nimpl GitHubReadOnlyInstalledProfile {", "\n}")
        factory = section(runtime, MAC_CFG + "\n    fn github_readonly_installed_profile(", "\n    }")
        self.assertIn("if !macos_bindings()", profile)
        self.assertIn("crate::installed_runtime::runtime_root()", profile)
        self.assertIn('bootstrap: cwd.join("github_connection_bootstrap.py")', profile)
        self.assertIn('python: cwd.join("python/bin/python3")', profile)
        self.assertIn('core: cwd.join("core.zip")', profile)
        self.assertIn("if macos_bindings()", factory)
        self.assertIn("GitHubReadOnlyInstalledProfile { _private: () }", factory)
        for forbidden in ("manifest_anchor", "accepts_platform", "observation", "std::env", "PassiveInstalledProfile"):
            self.assertNotIn(forbidden, profile)
            self.assertNotIn(forbidden, factory)
        available = section(runtime, "pub(crate) fn github_readonly_installed_profile_available(", "\n    }")
        resolve = section(runtime, "pub(crate) fn resolve_github_readonly_installed(", "\n    }")
        self.assertIn('all(target_os = "macos", target_arch = "aarch64")', available)
        self.assertIn("originals.inspect_once(self.github_readonly_installed_profile()?, end, stop)", resolve)
        binding = "slots!(GitHubReadOnlyRuntimeSlots, GitHubReadOnlyInstalledRuntime, runtime::GitHubReadOnlyInstalledProfile);"
        self.assertEqual(installed.count(binding), 1)
        slots = section(installed, "macro_rules! slots {", "\nslots!(")
        for original in ("original: Book", "let original = match self.inspection.take()",
                         "self.acquisition = Some($capability { original, selection",
                         "self.original.prepare(end, stop)?", "self.claimed = true"):
            self.assertIn(original, slots)
        self.assertNotIn("slots!(GitHubPreflight", installed)
        self.assertNotIn("slots!(GitHubRelease", installed)
        acquire = section(supervisor, "fn acquire_github_original(inner:", "\n}")
        self.assertLess(acquire.index("runtime.prepare_once("), acquire.index("macos_installed_environment("))
        self.assertLess(acquire.index(".env_clear()"), acquire.index("macos_installed_environment("))
        self.assertLess(acquire.index("macos_installed_environment("), acquire.index("let owners = lock("))
        self.assertIn("macos_installed_environment(&mut command).map_err(AcquisitionError::from)?", acquire)
        self.assertLess(acquire.index("let owners = lock("), acquire.index("github_claim_clear("))
        self.assertLess(acquire.index("runtime.claim_once()"), acquire.index("command.spawn()"))
        self.assertNotIn("macos_installed_environment", acquire.split("runtime.claim_once()", 1)[1])
        selected = section(supervisor, "fn github_installed_selected(", "\n}")
        self.assertIn('all(target_os = "macos", target_arch = "aarch64")', selected)
        self.assertIn('not(all(feature = "development-runtime", debug_assertions))', selected)
        self.assertIn("matches!(profile, Profile::GitHubReadOnly)", selected)
        books = section(supervisor, "fn installed_settlement_slots(", "\n}")
        readonly = books.split("if github_preflight_selected(profile)", 1)[0]
        self.assertIn("if resources.passive.is_some()", readonly)
        self.assertIn("if resources.github_readonly.is_some()", readonly)
        self.assertIn('all(target_os = "macos", target_arch = "aarch64")', readonly)
        self.assertIn("GitHubReadOnly(slots.clone())", readonly)
        for name in ("github_preflight_profile_available", "github_release_profile_available"):
            self.assertNotIn('target_os = "macos"', section(runtime, "pub(crate) fn " + name + "(", "\n    }"))
        for name in ("github_preflight_selected", "github_release_selected"):
            self.assertNotIn('target_os = "macos"', section(supervisor, "fn " + name + "(", "\n}"))
        self.assertIn("pub(crate) fn macos_github_readonly_profile_contract()", runtime)
        self.assertIn("pub(crate) fn macos_github_readonly_original_contract()", supervisor)
        self.assertIn("github_installed_contract_tests::original_claim_contract();", supervisor)
        self.assertIn("github_installed_contract_tests::exact_original_book_contract();", supervisor)
        self.assertIn("Arc::ptr_eq(&selected, resources.github_readonly.as_ref().unwrap())", supervisor)


class GitHubBootstrapDataTests(unittest.TestCase):
    def bootstrap_case(self, *, platform="darwin", argv=None, isolated=1, no_site=1,
                       bytecode=True, version=(3, 11), bootstrap="/fixed/runtime/github_connection_bootstrap.py"):
        argv = [bootstrap, "/fixed/runtime/core.zip"] if argv is None else list(argv)
        inert_sys = SimpleNamespace(argv=argv, flags=SimpleNamespace(isolated=isolated, no_site=no_site),
                                    dont_write_bytecode=bytecode, version_info=version,
                                    platform=platform, path=["inert-original-path"])
        engine_calls = []
        imports = []

        def run_engine(**arguments):
            engine_calls.append(arguments)
            return 0

        modules = {
            "os": SimpleNamespace(path=SimpleNamespace(isabs=posixpath.isabs, dirname=posixpath.dirname)),
            "sys": inert_sys,
            "time": SimpleNamespace(monotonic=lambda: 123.0),
            "mobile_release._desktop_github_engine": SimpleNamespace(main=run_engine),
        }

        def inert_import(name, globals=None, locals=None, fromlist=(), level=0):
            self.assertEqual(level, 0)
            self.assertIn(name, modules)
            if name == "mobile_release._desktop_github_engine":
                self.assertEqual(fromlist, ("main",))
            imports.append(name)
            return modules[name]

        namespace = {
            "__name__": "_inert_github_bootstrap_data_contract",
            "__file__": bootstrap,
            "__builtins__": {"__import__": inert_import, "len": len, "int": int},
        }
        # Only the actual fixed bootstrap body runs. No real engine import,
        # sys.path mutation, filesystem probe, TLS, subprocess or native owner.
        exec(source("desktop/github_connection_bootstrap.py"), namespace)
        code = namespace["main"]()
        return code, engine_calls, imports, inert_sys.path

    def test_actual_bootstrap_platform_flags_and_absolute_path_truth_table(self):
        for platform in ("linux", "darwin"):
            for version in ((3, 11), (3, 12)):
                with self.subTest(platform=platform, version=version):
                    code, calls, imports, paths = self.bootstrap_case(platform=platform, version=version)
                    self.assertEqual(code, 0)
                    self.assertEqual(calls, [{"started": 123.0, "runtime_dir": "/fixed/runtime"}])
                    self.assertEqual(imports, ["os", "sys", "time", "mobile_release._desktop_github_engine"])
                    self.assertEqual(paths, ["/fixed/runtime/core.zip", "inert-original-path"])
        refused = [
            {"platform": "win32"}, {"platform": "freebsd"}, {"platform": "linux2"},
            {"isolated": 0}, {"no_site": 0}, {"bytecode": False}, {"version": (3, 10)},
            {"argv": []}, {"argv": ["/fixed/runtime/github_connection_bootstrap.py"]},
            {"argv": ["/fixed/runtime/github_connection_bootstrap.py", "/fixed/runtime/core.zip", "extra"]},
            {"argv": ["/fixed/runtime/github_connection_bootstrap.py", "core.zip"]},
            {"bootstrap": "github_connection_bootstrap.py"},
        ]
        for case in refused:
            with self.subTest(case=case):
                code, calls, imports, paths = self.bootstrap_case(**case)
                self.assertEqual(code, 78)
                self.assertEqual(calls, [])
                self.assertEqual(imports, ["os", "sys", "time"])
                self.assertEqual(paths, ["inert-original-path"])


if __name__ == "__main__":
    unittest.main()
