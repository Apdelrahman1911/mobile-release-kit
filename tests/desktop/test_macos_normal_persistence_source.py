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
