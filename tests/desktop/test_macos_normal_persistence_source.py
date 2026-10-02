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
        journey = journey.split("@MainActor func testSyntheticProjectLocalEdits()", 1)[0]
        self.assertLess(journey.index("fixture.admitDefaultVault()"), journey.index("launchForJourney()"))
        self.assertIn("executionTimeAllowance = 300", journey)
        self.assertIn("journeyDeadline = ProcessInfo.processInfo.systemUptime + 300", journey)
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
        for claim in ("appRestart=not-run", "cleanExitStatus=unavailable", "allWorkerFinality=unavailable",
                      "fixtures=retained-for-disposable-job-retirement"):
            self.assertIn(claim, journey)
        secure = source.split("@MainActor private func savePrivate(", 1)[1].split("@MainActor private func assignPrivate(", 1)[0]
        self.assertIn("[.secureTextField]", secure)
        self.assertIn("password.typeText(", secure)
        self.assertNotIn("password.value", secure)
        self.assertNotIn("replace(password", secure)
        self.assertNotIn(".terminate()", journey)

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
        # These are the unchanged cddcb74 project blocks, not native-success
        # receipts. Keep success-only admission, original package/test count
        # bindings, deadlines and explicit finality limitations when moving them.
        pins = {
            b"normal_project_ui_test": "36683e59244e8f5a206c669a04f3bbcb2916dd54e41e018822b935fe764a02f3",
            b"normal_project_ui_result": "9dfb28a9c746958d0c2df3e922706445e66faf43e60e49533ecc26a462aa21d5",
        }
        for identifier, expected in pins.items():
            self.assertEqual(hashlib.sha256(blocks[ids.index(identifier)]).hexdigest(), expected)
        self.assertEqual(source.count(
            b"-only-testing:MRKNormalAppUITests/NormalAppUITests/testSyntheticProjectLocalEditsAndImages"
        ), 1)


if __name__ == "__main__":
    unittest.main()
