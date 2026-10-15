"""Fixed DATA/source regressions only; no Swift, AppKit, Keychain or app execution.

Actual accessibility, native storage and original-worker finality still require
the reviewed hosted Mac candidate. These checks never produce native receipts.
"""
import ast
import base64
import hashlib
import json
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).absolute().parents[2]
NATIVE = ROOT / "desktop/native/macos-normal-ui"


class NormalPersistenceSourceTests(unittest.TestCase):

    def test_real_two_source_update_uses_owned_sentinel_and_login_without_reinitialize(self):
        source = (NATIVE / "MRKNormalAppUITests/NormalAppUITests.swift").read_text()
        bootstrap = source.split("@MainActor func testQualifiedP0CredentialBootstrap() throws {", 1)[1].split("@MainActor func testQualifiedP1CredentialResume", 1)[0]
        resume = source.split("@MainActor func testQualifiedP1CredentialResume() throws {", 1)[1].split("@MainActor func testSyntheticPersistentCredentials", 1)[0]
        for part in (bootstrap, resume):
            self.assertIn("executionTimeAllowance = 300", part)
            self.assertEqual(part.count("try beginCase(seconds: 300)"), 1)
            self.assertIn("fixture.prepare(.persistentCredentials)", part)
            self.assertNotIn(".terminate()", part)
        self.assertLess(bootstrap.index('fixture.admitUpdateCredentials("p0-bootstrap")'), bootstrap.index("launchForJourney(profile: .updateP0Bootstrap)"))
        self.assertIn("fixture.assertUpdateVaultAbsent()", bootstrap)
        self.assertIn('privateStatus(storage, action: "initialize", mutation: true)', bootstrap)
        self.assertIn("fixture.acceptStore(.saveP12)", bootstrap)
        self.assertIn("count: 1, assigned: 0", bootstrap)
        self.assertLess(resume.index('fixture.admitUpdateCredentials("p1-resume")'), resume.index("launchForJourney()"))
        self.assertIn("openAndUnlockPrivateVault(storage, renderer: renderer)", resume)
        self.assertNotIn('action: "initialize"', resume)
        self.assertNotIn('"Create encrypted vault"', resume)
        self.assertIn("assigned: false, notChecked: true", resume)
        self.assertIn("fixture.acceptStore(.deleteUpdateP12)", resume)
        self.assertIn("count: 0, assigned: 0", resume)
        final = source.split("private func finishUpdateCredentialSegment(", 1)[1].split("func testQualifiedP0CredentialBootstrap", 1)[0]
        self.assertLess(final.index("completeNormalQuit(app)"), final.index("fixture.closeOriginals()"))
        self.assertLess(final.index("fixture.closeOriginals()"), final.index("acceptFinalScenario()"))
        self.assertLess(final.index("acceptFinalScenario()"), final.index('print("MRK_MACOS_UPDATE_CREDENTIALS="'))
        self.assertIn("applicationSource == harnessSource", source)
        self.assertIn("only the closed source-qualified P0 credential bootstrap", source)
        for required in ("original parent-admitted update input digest differs", "only the exact baseline-owned app-data root may be reused",
                         "P0 bootstrap requires only its original sentinel", "P1 resume requires exactly the original controls and one record"):
            self.assertIn(required, source)
        self.assertNotIn("SecItemDelete", resume.split("fixture.acceptStore(.deleteUpdateP12)", 1)[0])
        runner = (ROOT / "desktop/tools/macos_normal_ui_runner.py").read_text()
        syntax = ast.parse(runner)
        defs = {target.id: node.value for node in syntax.body if isinstance(node, ast.Assign) for target in node.targets if isinstance(target, ast.Name)}
        self.assertEqual(len(ast.literal_eval(defs["NORMAL_SELECTIONS"])), 8)
        selected = ast.literal_eval(defs["CREDENTIAL_UPDATE_SELECTIONS"])
        self.assertEqual(set(selected), {"p0-bootstrap", "p1-resume"})
        self.assertEqual(ast.literal_eval(defs["CREDENTIAL_UPDATE_REF"]), "refs/heads/verify/desktop-macos-positive-update")
        for required in ("update-credential-source-module-collision", "update-credential-genuine-qualified-baseline",
                         "update-credential-current-update-lineage", "update-credential-exact-bootstrap-handoff",
                         "update-credential-only-owned-record-deleted", "update-credential-source-pre-post"):
            self.assertIn(required, runner)
        workflow = (ROOT / ".github/workflows/desktop-macos-installed.yml").read_text()
        for segment in ("p0-bootstrap", "p1-resume"):
            for phase in ("test", "summary"):
                self.assertEqual(workflow.count("--normal-update-" + segment + "-" + phase + " \\\n"), 1)
        self.assertLess(workflow.index("id: update_p0_bootstrap_summary"), workflow.index("id: package_install"))
        self.assertLess(workflow.index("id: package_install"), workflow.index("id: update_p1_resume_test"))
        package = workflow.split("id: package_install", 1)[1].split("      - name:", 1)[0]
        self.assertEqual(package.count("macos_android_helper_package.py package-install --target"), 1)
        self.assertIn("steps.update_p0_bootstrap_summary.outcome == 'success'", workflow.split("id: package_install", 1)[0][-600:])
        for key in ("p0-readonly-enrollment.json", "update-predecessors.json"):
            row = json.loads((ROOT / "desktop/macos-installed-inputs" / key).read_bytes())
            self.assertEqual(row, {"schemaVersion": 1, "mode": "unconfigured"})
        # This source check is neither an Add/Lookup native result nor an authority
        # to activate dormant refs or mutate a login Keychain.
        # KC-R1: invoke only these actual AST-selected DATA readers with fully
        # synthetic descriptors/stat/body originals. No product module import,
        # live file descriptor, process, credential, or Keychain is involved.
        import stat as data_stat
        from types import SimpleNamespace
        actual_function = next(n for n in syntax.body if isinstance(n, ast.FunctionDef)
                               and n.name == "credential_source_state")
        actual_class = next(n for n in syntax.body if isinstance(n, ast.ClassDef)
                            and n.name == "CredentialUpdateInputs")
        method_names = {"read", "leaf_snapshot", "snapshot", "close", "__enter__", "__exit__"}
        methods = [n for n in actual_class.body if isinstance(n, ast.FunctionDef) and n.name in method_names]
        self.assertEqual({n.name for n in methods}, method_names)
        passive = ast.Module(body=[actual_function, ast.ClassDef(name="CredentialUpdateInputs",
            bases=[], keywords=[], body=methods, decorator_list=[], type_params=[])], type_ignores=[])
        ast.fix_missing_locations(passive)

        class DataRefused(ValueError):
            pass

        def data_need(ok, reason):
            if not ok: raise DataRefused(reason)

        def info(mode):
            return SimpleNamespace(st_dev=1, st_ino=2, st_mode=mode, st_uid=1000,
                st_gid=1000, st_nlink=1, st_size=4, st_mtime_ns=5, st_ctime_ns=6, st_flags=0)

        def full(info):
            return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
                    info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)

        class DataOS:
            O_RDONLY, O_NONBLOCK, O_NOFOLLOW, O_CLOEXEC, O_DIRECTORY = 0, 1, 2, 4, 8
            def __init__(self):
                self.closes = []
                self.close_errors = []
                self.file = info(data_stat.S_IFREG | 0o600)
                self.directory = info(data_stat.S_IFDIR | 0o700)
                self.vault_mode = False
                self.list_failure = None
            def open(self, *args, **kwargs): return 102
            def close(self, fd):
                self.closes.append(fd)
                error = OSError("synthetic-secondary-close")
                self.close_errors.append(error)
                raise error
            def fstat(self, fd):
                return self.directory if fd in (101, 200) or self.vault_mode else self.file
            def stat(self, *args, **kwargs):
                return self.directory if self.vault_mode else self.file
            def getuid(self): return 1000
            def getgid(self): return 1000
            def listdir(self, fd):
                if fd == 200: return ["sentinel", "credential-vault-v1"]
                if self.list_failure is not None: raise self.list_failure
                return ["vault-lock", "initialization-reservation", "vault-header"]

        data_os = DataOS()
        data_sys = SimpleNamespace(modules={})
        clock = SimpleNamespace(check=lambda: None)
        paths = ast.literal_eval(defs["CREDENTIAL_SOURCE_PATHS"])
        body = b"synthetic-data"
        digest = hashlib.sha256(body).hexdigest()
        blob = hashlib.sha1(b"blob " + str(len(body)).encode() + b"\0" + body).hexdigest()
        roster = b"".join(b"100644 blob " + blob.encode() + b"\t" + name.encode() + b"\0" for name in paths)
        phase = SimpleNamespace(root=Path("/synthetic-owned-source"), clock=clock,
            call=lambda *args: SimpleNamespace(returncode=0, stdout=roster))
        read_primary = RuntimeError("synthetic-original-read")
        def original_fault(*args, **kwargs): raise read_primary
        def original_ok(*args, **kwargs): return body, full(data_os.file), digest
        namespace = {"os": data_os, "sys": data_sys, "Path": Path, "stat": data_stat,
            "hashlib": hashlib, "CREDENTIAL_SOURCE_PATHS": paths,
            "need": data_need, "Refused": DataRefused, "full9": full,
            "decimal": lambda value: [str(v) for v in value],
            "sha": lambda value: hashlib.sha256(value).hexdigest(),
            "open_directory": lambda path: 101, "original_body": original_fault}
        exec(compile(passive, "<actual-credential-reader-data-slice>", "exec"), namespace)
        Reader = namespace["CredentialUpdateInputs"]
        def fresh():
            value = object.__new__(Reader)
            value.phase, value.held, value.modules, value.closed = phase, {}, {}, False
            value.update = SimpleNamespace(credential_facts=full)
            value.root_fd, value.root_parent = None, None
            return value
        allowed_notes = {
            "update-credential-source-secondary-close", "update-credential-input-secondary-close",
            "update-credential-leaf-secondary-close", "update-credential-vault-secondary-close",
            "update-credential-consuming-close", "update-credential-secondary-consuming-close"}
        def notes(error, count):
            values = getattr(error, "__notes__", ())
            self.assertEqual(len(values), count)
            self.assertTrue(set(values) <= allowed_notes)
            self.assertFalse(any("synthetic-secondary" in note or "/" in note for note in values))

        # The original source/read/leaf exception remains the identical object;
        # every acquired descriptor gets one close even when every close fails.
        for call, expected in (
            (lambda: namespace["credential_source_state"](phase, "synthetic-source"), [102, 101]),
            (lambda: fresh().read(Path("/synthetic-input/receipt"), 32768, keep=False), [102, 101]),
            (lambda: fresh().leaf_snapshot(101, "synthetic-leaf"), [102]),
        ):
            read_primary = RuntimeError("synthetic-original-read")
            data_os.closes.clear()
            with self.assertRaises(RuntimeError) as caught: call()
            self.assertIs(caught.exception, read_primary)
            self.assertEqual(data_os.closes, expected)
            notes(read_primary, len(expected))
        namespace["original_body"] = original_ok
        for call, expected in (
            (lambda: namespace["credential_source_state"](phase, "synthetic-source"), [102, 101]),
            (lambda: fresh().read(Path("/synthetic-input/receipt"), 32768, keep=False), [102, 101]),
            (lambda: fresh().leaf_snapshot(101, "synthetic-leaf"), [102]),
        ):
            data_os.closes.clear()
            with self.assertRaises(DataRefused) as caught: call()
            self.assertTrue(str(caught.exception).endswith("-close"))
            self.assertEqual(data_os.closes, expected)
            notes(caught.exception, len(expected) - 1)

        # Vault close cannot replace its original roster/leaf refusal. The
        # surrounding root/sentinel admissions here are explicitly synthetic.
        sentinel = b"synthetic-sentinel"
        update = SimpleNamespace(SENTINEL=sentinel, credential_facts=full,
            credential_fact_values=lambda *args, **kwargs: None,
            credential_state_data=lambda *args, **kwargs: None)
        def snapshot_reader():
            value = fresh()
            value.root_fd, value.sentinel_name, value.update, value.baseline = 200, "sentinel", update, {"sentinel": {}}
            value.root_post, value.check = lambda: None, lambda: None
            value.leaf_snapshot = lambda *args: {"bytes": len(sentinel), "sha256": hashlib.sha256(sentinel).hexdigest()}
            return value
        data_os.vault_mode = True
        vault_primary = RuntimeError("synthetic-original-vault-roster")
        data_os.list_failure = vault_primary
        data_os.closes.clear()
        with self.assertRaises(RuntimeError) as caught: snapshot_reader().snapshot(records=1)
        self.assertIs(caught.exception, vault_primary)
        self.assertEqual(data_os.closes, [102])
        notes(vault_primary, 1)
        data_os.list_failure = None
        data_os.closes.clear()
        with self.assertRaises(DataRefused) as caught: snapshot_reader().snapshot(records=1)
        self.assertEqual(str(caught.exception), "update-credential-vault-close")
        self.assertEqual(data_os.closes, [102])
        notes(caught.exception, 0)
        data_os.vault_mode = False

        # Successful keep=True transfers custody, not a close obligation retry.
        value = fresh()
        data_os.closes.clear()
        self.assertEqual(value.read(Path("/synthetic-input/held"), 32768), body)
        self.assertEqual(data_os.closes, [])
        with self.assertRaises(OSError): value.close()
        self.assertEqual(data_os.closes, [102, 101])
        self.assertEqual(value.held, {})

        def held_reader():
            value = fresh()
            value.held = {Path("/synthetic-input/held"): (301, 302, (), (), "", 0, b"")}
            value.root_fd, value.root_parent = 303, 304
            module = object()
            value.modules = {"synthetic_owned_module": module}
            data_sys.modules = dict(value.modules)
            value.check = lambda: None
            return value
        for mode in ("close", "enter", "exit-check", "exit-primary", "exit-success"):
            value = held_reader()
            data_os.closes.clear()
            data_os.close_errors.clear()
            primary = RuntimeError("synthetic-original-context")
            def fail(): raise primary
            if mode == "enter": value.baseline_inputs = fail
            if mode == "exit-check": value.check = fail
            if mode == "exit-primary":
                self.assertFalse(value.__exit__(RuntimeError, primary, None))
                notes(primary, 4)
            else:
                expected = RuntimeError if mode in ("enter", "exit-check") else OSError
                with self.assertRaises(expected) as caught:
                    if mode == "close": value.close()
                    elif mode == "enter": value.__enter__()
                    else: value.__exit__(None, None, None)
                if expected is RuntimeError:
                    self.assertIs(caught.exception, primary)
                    notes(primary, 4)
                else:
                    self.assertIs(caught.exception, data_os.close_errors[0])
                    notes(caught.exception, 3)
            self.assertEqual(data_os.closes, [301, 302, 303, 304])
            self.assertTrue(value.closed)
            self.assertEqual(value.held, {})
            self.assertIsNone(value.root_fd)
            self.assertIsNone(value.root_parent)
            self.assertEqual(value.modules, {})
            self.assertEqual(data_sys.modules, {})
            with self.assertRaises(DataRefused): value.close()
            self.assertEqual(data_os.closes, [301, 302, 303, 304])

    def test_closed_fixture_reuses_inert_envelopes_and_saved_signing_configuration(self):
        path = NATIVE / "MRKNormalAppUITests/Fixtures/normal-persistence-v1.json"
        data = path.read_bytes()
        self.assertLess(len(data), 64 * 1024)
        fixture = json.loads(data)
        self.assertEqual(set(fixture), {"schemaVersion", "files", "stages"})
        self.assertEqual(fixture["schemaVersion"], 1)
        self.assertEqual(fixture["stages"], {})
        expected = {
            "project/release/mobile-release.json", "project/release/version.properties",
            "project/.gitignore", "project/README-user.txt",
            "project/ios/MRKObserved.xcodeproj/project.pbxproj",
            "project/ios/MRKObserved.xcodeproj/xcshareddata/xcschemes/MRKObserved.xcscheme",
            "project/ios/MRKObserved.xcodeproj/project.xcworkspace/contents.xcworkspacedata",
            "project/ios/MRKObserved/main.m", "project/ios/MRKObserved/Info.plist",
            "sources/synthetic.p12", "sources/synthetic.mobileprovision",
        }
        self.assertEqual(set(fixture["files"]), expected)
        files = {name: base64.b64decode(value, validate=True) for name, value in fixture["files"].items()}
        self.assertTrue(all(len(value) < 32 * 1024 for value in files.values()))
        self.assertLess(sum(map(len, files.values())), 64 * 1024)
        # Read literal DATA, never import the process/native qualification driver.
        syntax = ast.parse((ROOT / "desktop/tools/macos_aqua_qualification.py").read_text())
        definitions = {target.id: node.value for node in syntax.body if isinstance(node, ast.Assign)
                       for target in node.targets if isinstance(target, ast.Name)}
        config = json.loads(ast.literal_eval(definitions["IOS_CONFIG_SIGNED"]))
        config["version"]["source"] = "release/version.properties"
        self.assertEqual(json.loads(files["project/release/mobile-release.json"]), config)
        for name, constant in (("sources/synthetic.p12", "IOS_SYNTHETIC_P12"),
                               ("sources/synthetic.mobileprovision", "IOS_SYNTHETIC_PROFILE")):
            node = definitions[constant]
            self.assertIsInstance(node, ast.Call)
            self.assertEqual(ast.unparse(node.func), "bytes.fromhex")
            self.assertEqual(len(node.args), 1)
            self.assertFalse(node.keywords)
            self.assertEqual(files[name], bytes.fromhex(ast.literal_eval(node.args[0])))
            self.assertIn(b"private-envelope-only-canary", files[name])
        self.assertEqual(files["project/README-user.txt"], b"MRK_NORMAL_PERSISTENCE_UNRELATED_ORIGINAL\n")
        project = (NATIVE / "MRKNormalAppUI.xcodeproj/project.pbxproj").read_text()
        self.assertEqual(project.count('path = "Fixtures/normal-persistence-v1.json"'), 1)
        self.assertIn("files = (A10000000000000000000010, A10000000000000000000012)", project)

    def test_ordinary_journey_keeps_explicit_mutation_assignment_and_cancellation_boundaries(self):
        source = (NATIVE / "MRKNormalAppUITests/NormalAppUITests.swift").read_text()
        journey = source.split("@MainActor func testSyntheticPersistentCredentials() throws {", 1)[1]
        journey = journey.split("@MainActor func testSyntheticProjectPathFields()", 1)[0]
        self.assertLess(journey.index("fixture.admitDefaultVault()"), journey.index("launchForJourney()"))
        self.assertIn("executionTimeAllowance = 300", journey)
        self.assertIn("try beginCase(seconds: 300)", journey)
        self.assertLess(journey.index("try beginCase(seconds: 300)"), journey.index("fixture.admitDefaultVault()"))
        self.assertLess(journey.index('"Create encrypted vault"'), journey.index("explicitlySubmit: true"))
        self.assertIn('privateStatus(storage, action: "initialize", mutation: true)', journey)
        self.assertIn('reviewTarget: "New \\(input.rawValue.lowercased()) encrypted record"', journey)
        self.assertIn("assigned: false, notChecked: true", journey)
        cancellation = journey.split('stage("persistence-replacement-cancel")', 1)[1]
        cancellation = cancellation.split('stage("persistence-replace-current-record")', 1)[0]
        for marker in ('"Storage closed"', 'privateStatus(storage, action: "choose-file")',
                       "count: 0, assigned: 0", "fixture.assertStoreUnchanged()", "reopenPrivateVault("):
            self.assertIn(marker, cancellation)
        self.assertLess(cancellation.index("fixture.assertStoreUnchanged()"), cancellation.index("reopenPrivateVault("))
        for claim in ("appRestart=passed", "ordinaryLifetimes=2", "cleanExitStatus=unavailable", "allWorkerFinality=unavailable",
                      "fixtures=retained-for-disposable-job-retirement"):
            self.assertIn(claim, journey)
        secure = source.split("@MainActor private func savePrivate(", 1)[1].split("@MainActor private func assignPrivate(", 1)[0]
        self.assertIn("[.secureTextField]", secure)
        self.assertIn("password.typeText(", secure)
        self.assertNotIn("password.value", secure)
        self.assertNotIn("replace(password", secure)
        self.assertNotIn(".terminate()", journey)

    def test_restart_retains_both_originals_and_never_refreshes_clock_or_cleanup(self):
        source = (NATIVE / "MRKNormalAppUITests/NormalAppUITests.swift").read_text()
        transition = source.split("private func retainPersistenceLifetimeForRestart(", 1)[1].split("private func checkOriginalOwners()", 1)[0]
        for required in ("completedPersistenceLifetime == nil && normalQuitObserved && app.state == .notRunning",
                         "try owner.acceptTerminal()", "try fixture.assertStoreUnchanged()",
                         "CompletedPersistenceLifetime(owner: owner, gate: gate, normalQuit: normalQuitObserved)"):
            self.assertIn(required, transition)
        assignment = "\n        completedPersistenceLifetime = CompletedPersistenceLifetime("
        self.assertEqual(source.count(assignment), 1)
        for earlier, later in (("owner.acceptTerminal()", "fixture.assertStoreUnchanged()"),
                               ("fixture.assertStoreUnchanged()", assignment),
                               (assignment, "originalLaunch = nil"),
                               (assignment, "entryGateObservation = nil")):
            self.assertLess(transition.index(earlier), transition.index(later))
        self.assertEqual(source.count("try retainPersistenceLifetimeForRestart(app, fixture: fixture)"), 1)
        self.assertNotIn("CaseClock(", transition)
        self.assertNotIn("beginCase(", transition)
        self.assertNotIn("journeyDeadline =", transition)
        owners = source.split("private func checkOriginalOwners()", 1)[1].split("private func acceptPersistenceRestart()", 1)[0]
        for required in ("first.normalQuit", "first.owner.acceptTerminal()", "owner.healthy()"):
            self.assertIn(required, owners)
        for name in ("require", "remaining"):
            section = source.split("private func " + name + "(", 1)[1].split("\n    @MainActor ", 1)[0]
            self.assertIn("try checkOriginalOwners()", section)
        final = source.split("private func acceptPersistenceRestart()", 1)[1].split("private final class GateObservation", 1)[0]
        for required in ("try require(normalQuitObserved", "first.normalQuit", "first.owner.acceptTerminal()",
                         "owner.acceptTerminal()", "try remaining(1)", "MRK_MACOS_PERSISTENCE_LIFETIME=phase=2"):
            self.assertIn(required, final)
        self.assertLess(final.index("try remaining(1)"), final.index("MRK_MACOS_PERSISTENCE_LIFETIME=phase=2"))
        single = source.split("private func acceptFinalScenario()", 1)[1].split("private func retainPersistenceLifetimeForRestart(", 1)[0]
        self.assertIn("completedPersistenceLifetime == nil", single)
        teardown = source.split("override func tearDown() async throws", 1)[1]
        for required in ("owner.tearDown(normalQuit: normalQuitObserved)", "first.owner.recheckCompletedTerminal()",
                         "entryGateObservation?.closeOriginal()", "completedPersistenceLifetime?.gate.closeOriginal()"):
            self.assertIn(required, teardown)
        self.assertNotIn("first.owner.tearDown(", teardown)
        self.assertNotIn("clock.end(", teardown)
        recheck = source.split("func recheckCompletedTerminal()", 1)[1].split("private func driveCleanup(", 1)[0]
        for required in ("callbackHealthy(complete: true)", "payloadIdentity()", "!workClosed, app.isTerminated, !normalRequested, !forceRequested"):
            self.assertIn(required, recheck)
        for forbidden in ("clock.end(", "driveCleanup(", ".terminate(", ".forceTerminate("):
            self.assertNotIn(forbidden, recheck)

    def test_restart_preserves_store_and_awaits_ordinary_context_before_explicit_reassessment(self):
        source = (NATIVE / "MRKNormalAppUITests/NormalAppUITests.swift").read_text()
        journey = source.split("@MainActor func testSyntheticPersistentCredentials() throws {", 1)[1]
        journey = journey.split("@MainActor func testSyntheticProjectPathFields()", 1)[0]
        restart = journey.split('stage("persistence-restart-launch")', 1)[1]
        self.assertLess(journey.index("try completeNormalQuit(app)"), journey.index("retainPersistenceLifetimeForRestart("))
        self.assertLess(restart.index("retainPersistenceLifetimeForRestart("), restart.index("launchForJourney()"))
        self.assertEqual(journey.count("try beginCase(seconds: 300)"), 1)
        self.assertEqual(journey.count("fixture.admitDefaultVault()"), 1)
        self.assertEqual(journey.count("fixture.prepare(.persistentCredentials)"), 1)
        self.assertEqual(journey.count("fixture.closeOriginals()"), 1)
        self.assertLess(restart.index("completeNormalQuit(restartedApp)"), restart.index("fixture.closeOriginals()"))
        self.assertLess(restart.index("fixture.closeOriginals()"), restart.index("acceptPersistenceRestart()"))
        for forbidden in ("fixture.acceptStore(", "fixture.admitDefaultVault()", "fixture.assertDefaultVaultAbsent()",
                          "fixture.prepare(", '"Create encrypted vault"', "explicitlySubmit: true", '"Submit current context"'):
            self.assertNotIn(forbidden, restart)
        for earlier, later in (('"Storage closed"', 'label: "Platform"'),
                               ('label: "Input purpose"', "openAndUnlockPrivateVault("),
                               ("openAndUnlockPrivateVault(", "privateContext(storage, renderer: restartedRenderer)"),
                               ("privateContext(storage, renderer: restartedRenderer)", "count: 1, assigned: 0"),
                               ("assigned: false, notChecked: true", "assignPrivate(storageAfterRestart"),
                               ("assignPrivate(storageAfterRestart", "completeNormalQuit(restartedApp)")):
            self.assertLess(restart.index(earlier), restart.index(later))
        self.assertIn('label: "Synthetic distribution replacement", revision: 2', restart)
        self.assertGreaterEqual(restart.count("fixture.assertStoreUnchanged()"), 3)
        unlock = source.split("private func openAndUnlockPrivateVault(", 1)[1].split("private func reopenPrivateVault(", 1)[0]
        self.assertLess(unlock.index('"Encrypted vault · locked"'), unlock.index("count: 0, assigned: 0"))
        self.assertLess(unlock.index("count: 0, assigned: 0"), unlock.index('"Unlock vault"'))
        self.assertNotIn("privateContext(", unlock)
        old_reopen = source.split("private func reopenPrivateVault(", 1)[1].split("func testSyntheticPersistentCredentials()", 1)[0]
        self.assertIn("count: 2, assigned: 0", old_reopen)
        self.assertIn("revision: 1, assigned: false, notChecked: true", old_reopen)

    def test_store_observation_preserves_permanent_controls_and_refuses_unowned_state(self):
        source = (NATIVE / "MRKNormalAppUITests/NormalAppUITests.swift").read_text()
        for invariant in ('"vault-lock": 0, "initialization-reservation": 48, "vault-header": 104',
                          'result == -1 && error == ENOENT, "existing default app-data is not task-owned"',
                          '"default app-data namespace collision"',
                          "directory.facts.mode & 0o7777 == 0o700 && directory.facts.flags == 0",
                          "before.mode & 0o7777 == 0o600 && before.flags == 0",
                          "records.count <= 2", "total <= 64 * 1024",
                          "new.facts.inode != old.facts.inode && new.bytes != old.bytes",
                          "current.facts == old.facts && current.bytes == old.bytes",
                          "after == before.subtracting([name])", "while let fd = descriptors.popLast()"):
            self.assertIn(invariant, source)
        for forbidden in ("removeItem(", "unlink(", "SecItemDelete", "SecKeychainUnlock", "NSPasteboard",
                          "evaluateJavaScript", "AppleScript", "XCTSkip"):
            self.assertNotIn(forbidden, source)
        guidance = (ROOT / "desktop/src/components/ReleaseInputGuidance.tsx").read_text()
        self.assertIn("encrypted storage has its own native availability", guidance)
        self.assertNotIn("persistent encrypted storage remains unavailable", guidance)


    def test_current_launches_use_one_admitted_account_and_preserve_prefixture_admission(self):
        source = (NATIVE / "MRKNormalAppUITests/NormalAppUITests.swift").read_text()
        basic = source.split("func testLaunchCancelAndQuit() throws {", 1)[1]
        basic = basic.split("// Finite synthetic files only.", 1)[0]
        admission = source.split("private func admittedJourneyApplication(profile: SourceProfile = .sameBuild)", 1)[1]
        admission = admission.split("@MainActor private func launchForJourney()", 1)[0]
        launch = source.split("@MainActor private func launchForJourney()", 1)[1]
        launch = launch.split("private enum PrivateInput", 1)[0]
        self.assertEqual(admission.count("let account = try admitHostedAccount(profile)"), 1)
        self.assertIn("return (url, account)", admission)
        self.assertIn("_ = try admittedJourneyApplication(profile: profile)", basic)
        self.assertIn("_ = try admittedJourneyApplication()", launch)
        self.assertEqual(basic.count("let app = try launchOrdinaryApplication()"), 1)
        self.assertEqual(launch.count("let app = try launchOrdinaryApplication()"), 1)
        self.assertNotIn("admitHostedAccount(", launch)
        self.assertEqual(source.count("try launchCancelAndQuit(profile: .packagedEntry)"), 1)
        self.assertEqual(source.count("configuration.arguments = []"), 1)
        self.assertNotIn("configuration.environment", source)
        self.assertNotIn("app.launchEnvironment", source)
        self.assertNotIn("app.launchArguments", source)
        # The unchanged entry, not arbitrary runner environment, remains the
        # payload's clean-environment authority. All old journeys stay strict.
        same_build = source.split("case .sameBuild:", 1)[1].split("case .packagedEntry:", 1)[0]
        self.assertIn("applicationSource == harnessSource", same_build)
        persistence = source.split("@MainActor func testSyntheticPersistentCredentials() throws {", 1)[1]
        persistence = persistence.split('stage("persistence-launch")', 1)[0]
        self.assertLess(persistence.index("_ = try admittedJourneyApplication()"),
                        persistence.index("try fixture.admitDefaultVault()"))
        self.assertLess(persistence.index("try fixture.admitDefaultVault()"),
                        persistence.index("try fixture.prepare(.persistentCredentials)"))
        self.assertNotIn("testHostedAccountAdmissionOnly", source)

    def test_local_project_journey_precedes_persistence_without_changing_its_gates(self):
        source = (ROOT / ".github/workflows/desktop-macos-installed.yml").read_bytes()
        blocks = re.findall(rb"(?ms)^      - name: .*?(?=^      - name: |\Z)", source)
        ids = []
        for block in blocks:
            found = re.search(rb"(?m)^        id: ([a-z0-9_]+)$", block)
            ids.append(found[1] if found else None)
        order = (b"normal_ui_result", b"normal_project_ui_test", b"normal_project_ui_result",
                 b"normal_persistence_ui_test", b"normal_persistence_ui_result")
        for identifier in order:
            self.assertEqual(ids.count(identifier), 1, identifier)
        start = ids.index(order[0])
        self.assertEqual(tuple(ids[start:start + len(order)]), order)
        # Reviewed finite file-budget guards and explicit original-status exits,
        # not native-success receipts. Keep success-only admission, package/test
        # count bindings, deadlines and finality limitations intact.
        pins = {
            b"normal_ui_build": "c6ebf32fdd6f2d7eb52fe542e50c684a651f241420fc3092194efb63a775f615",
            b"normal_ui_test": "1ccc1cbd1059565b87a50fa767e9772e3e6c133975d536607d4af65ed5e0b56e",
            b"normal_project_ui_test": "8610371ad9fbc357cac42d8b6796275799a0c1ed436c8331416455974f2c99b5",
            b"normal_project_ui_result": "b0c6b67f2f0914e1e69cd5182b20e04043ce95a7c9299d5115225a1f62f9acf2",
            b"normal_persistence_ui_test": "9cc77c35a6fe15ae7cc52155f2b5def9dedd72f9a266f031698fdb7c1e295635",
        }
        for identifier, expected in pins.items():
            self.assertEqual(ids.count(identifier), 1, identifier)
            self.assertEqual(hashlib.sha256(blocks[ids.index(identifier)]).hexdigest(), expected)
        self.assertEqual(source.count(
            b"-only-testing:MRKNormalAppUITests/NormalAppUITests/testSyntheticProjectLocalEditsAndImages"
        ), 1)


if __name__ == "__main__":
    unittest.main()
