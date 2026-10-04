"""SOURCE-only bindings for ordinary Mac diagnostics, saved offline checks and Idle inspection.

These methods read first-party bytes and AST/literals only. They do not launch
XCTest, import product code, qualify native resources, or stand in for the
original future XCTest result. The four fixed negative mutations are applied
by the separately authorized local verification route, never by native retry.
"""
from __future__ import annotations

import ast
import base64
import hashlib
import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).absolute().parents[2]
SWIFT = "desktop/native/macos-normal-ui/MRKNormalAppUITests/NormalAppUITests.swift"
FIXTURE = "desktop/native/macos-normal-ui/MRKNormalAppUITests/Fixtures/normal-project-v1.json"
METHOD = "testSyntheticProjectBuildToolDiagnostics"
SCOPE = "ordinary-ui-observed-original-diagnostics-report-and-settled-projection"
SOURCE_METHODS = ['test_macos_normal_diagnostics_source.NormalDiagnosticsSourceTests.test_normal_diagnostics_observes_original_complete_report_and_settled_projection',
 'test_macos_normal_diagnostics_source.NormalDiagnosticsSourceTests.test_normal_diagnostics_workflow_has_one_bounded_original_result']
# Exact product two-lifetime baseline plus reviewed require-site diagnostics.
# Only the explicitly checked heading/readiness/diagnostic blocks below are
# restored or removed; original-owner and restart paths remain bound.
ORIGINAL_SWIFT_SHA256 = "43e84e8f4b8cf917b3b1505cdeca927dcf3b61003dbcd7faaeade2473ca14790"
DIAGNOSTICS_INSERTION_SHA256 = "d6c1730aa9c3b82467a5f6f15b549a463746e0901556174fc52a602d903b798d"
DASHBOARD_QUERY_BEGIN = '        // Fixed dashboard query diagnostics only; observations are non-atomic.\n'
DASHBOARD_QUERY_END = '        // End fixed dashboard query diagnostics.\n'
DASHBOARD_QUERY_ORIGINAL = '        _ = try unique(heading, "dashboard heading is ambiguous")\n'
DASHBOARD_QUERY_DIAGNOSTICS_SHA256 = "4a0f78d6468535805756ea785f0cdf5fbcede31c38d276635485a476b9fb6ad6"
# Authored h1/h2/h3 singleton queries only; no badge, native-sheet or
# existence-only selector is normalized. Every complete line and multiplicity
# is independently enumerated, then the unchanged whole-source pins apply.
SEMANTIC_HEADING_PREFIX = 'staticTexts.matching(NSPredicate(format: "title == %@", '
SEMANTIC_HEADING_LINES = (
    ('        let heading = renderer.staticTexts.matching(identifier: "Good releases start here.")\n',
     '        let heading = renderer.staticTexts.matching(NSPredicate(format: "title == %@", "Good releases start here."))\n', 1),
    ('        _ = try waitElement(review.staticTexts.matching(identifier: title), in: storage, failures: Self.privateInputFailures)\n',
     '        _ = try waitElement(review.staticTexts.matching(NSPredicate(format: "title == %@", title)), in: storage, failures: Self.privateInputFailures)\n', 1),
    ('        _ = try waitElement(storage.staticTexts.matching(identifier: "Supplied-input assessment"), in: storage,\n',
     '        _ = try waitElement(storage.staticTexts.matching(NSPredicate(format: "title == %@", "Supplied-input assessment")), in: storage,\n', 1),
    ('            _ = try waitElement(renderer.staticTexts.matching(identifier: "Let’s get project ready."), in: renderer,\n',
     '            _ = try waitElement(renderer.staticTexts.matching(NSPredicate(format: "title == %@", "Let’s get project ready.")), in: renderer,\n', 5),
    ('            _ = try waitElement(renderer.staticTexts.matching(identifier: "Format validation complete"), in: renderer,\n',
     '            _ = try waitElement(renderer.staticTexts.matching(NSPredicate(format: "title == %@", "Format validation complete")), in: renderer,\n', 1),
    ('            _ = try waitElement(review.staticTexts.matching(identifier: "Submitted configuration saved"), in: review,\n',
     '            _ = try waitElement(review.staticTexts.matching(NSPredicate(format: "title == %@", "Submitted configuration saved")), in: review,\n', 1),
    ('            _ = try waitElement(proposal.staticTexts.matching(identifier: "Four read-only workflow previews"), in: proposal)\n',
     '            _ = try waitElement(proposal.staticTexts.matching(NSPredicate(format: "title == %@", "Four read-only workflow previews")), in: proposal)\n', 1),
    ('            _ = try waitElement(review.staticTexts.matching(identifier: "Reviewed local workflow bundle installed"), in: review,\n',
     '            _ = try waitElement(review.staticTexts.matching(NSPredicate(format: "title == %@", "Reviewed local workflow bundle installed")), in: review,\n', 1),
    ('            _ = try waitElement(review.staticTexts.matching(identifier: "Text saved"), in: review, timeout: 48, failures: Self.textFailures)\n',
     '            _ = try waitElement(review.staticTexts.matching(NSPredicate(format: "title == %@", "Text saved")), in: review, timeout: 48, failures: Self.textFailures)\n', 1),
    ('                _ = try waitElement(renderer.staticTexts.matching(identifier: "Original image selection cancelled"), in: renderer,\n',
     '                _ = try waitElement(renderer.staticTexts.matching(NSPredicate(format: "title == %@", "Original image selection cancelled")), in: renderer,\n', 1),
    ('                _ = try unique(review.staticTexts.matching(identifier: "Final lexical Store input order"), "final image order was not displayed")\n',
     '                _ = try unique(review.staticTexts.matching(NSPredicate(format: "title == %@", "Final lexical Store input order")), "final image order was not displayed")\n', 1),
    ('                _ = try waitElement(review.staticTexts.matching(identifier: "Reviewed public images copied locally"), in: review,\n',
     '                _ = try waitElement(review.staticTexts.matching(NSPredicate(format: "title == %@", "Reviewed public images copied locally")), in: review,\n', 1),
    ('            _ = try unique(report.staticTexts.matching(identifier: "Returned offline-check report"), "returned offline report heading is missing")\n',
     '            _ = try unique(report.staticTexts.matching(NSPredicate(format: "title == %@", "Returned offline-check report")), "returned offline report heading is missing")\n', 1),
    ('            _ = try unique(panel.staticTexts.matching(identifier: "No pending build-input record observed"),\n',
     '            _ = try unique(panel.staticTexts.matching(NSPredicate(format: "title == %@", "No pending build-input record observed")),\n', 2),
    ('            let fresh = panel.staticTexts.matching(identifier: "Tool observations from this run")\n',
     '            let fresh = panel.staticTexts.matching(NSPredicate(format: "title == %@", "Tool observations from this run"))\n', 1),
    ('                _ = try unique(panel.staticTexts.matching(identifier: label), "fixed Android diagnostics card is missing or repeated")\n',
     '                _ = try unique(panel.staticTexts.matching(NSPredicate(format: "title == %@", label)), "fixed Android diagnostics card is missing or repeated")\n', 1),
    ('            _ = try waitElement(restartedRenderer.staticTexts.matching(identifier: "Let’s get project ready."), in: restartedRenderer,\n',
     '            _ = try waitElement(restartedRenderer.staticTexts.matching(NSPredicate(format: "title == %@", "Let’s get project ready.")), in: restartedRenderer,\n', 1),
)
RENDERER_QUERY_BEGIN = '        // Fixed renderer singleton diagnostic; no additional query or wait.\n'
RENDERER_QUERY_END = '        // End fixed renderer singleton diagnostic.\n'
RENDERER_QUERY_ORIGINAL = '        let renderer = try unique(window.webViews, "ordinary first-party renderer is missing or ambiguous")\n'
RENDERER_QUERY_DIAGNOSTICS_SHA256 = 'dea59830e6aef376217856dc9779acffb9634aa5fd2d260847db0b876cb7a0c4'
RENDERER_READINESS_BEGIN = '        // Bounded initial renderer readiness; observed ambiguity remains terminal.\n'
RENDERER_READINESS_END = '        // End bounded initial renderer readiness.\n'
RENDERER_READINESS_SHA256 = '9f8936dd612d12ae8dc10c561181686359171a3ce98021603c12c17a486c2a8a'
ORIGINAL_ROSTER_SHA256 = "293426d49f6bb226563ea325527858b894aa98ac2e72dea6b70875157cfd58e4"
ROSTER_SHA256 = "1cf265f8c97381708d68c1dedc8bc61ebcaf182c104d3021bda8b8211f016d65"
# The normal result also binds M2-A entry identity without claiming full M2/maintenance readiness.
BLOCK_PINS = {'normal_ui_result': '9b88586efe9d1532bf810fa3cb0ea2e9706c1edd0c6c942210b0be009048748e',
 'normal_project_ui_test': 'd903ce62063fd858c158a87bcc2a5532c47c043f13ddaf9147a568222b306bd2',
 'normal_project_ui_result': '20cd5b0114ff6e2cc725e0324d62dccefd4896426ce4eff67baeea935290013d',
 'normal_persistence_ui_test': '2396acc5b9f10129447f2b52933feab88d06c6a84a512edaad8c637994a59a99',
 'normal_persistence_ui_result': '0fbce9ceda8158a7e0c8585d24d2991d860121171d030afc78073a92ff1143fe',
 'normal_diagnostics_ui_test': '633a31e2b44a1b7fb21abc05a0182e66753fcbe2508090aacac3d5ff2127a613',
 'normal_diagnostics_ui_result': '5987afe38eaac0e72dce32aed908f1276b3fe7572c831e43935f09f24896096f',
 'normal_saved_checks_ui_test': 'e4fa12c713afdd5d88f62d61e943024eb821833d5182b2159f43031de5570f3c',
 'normal_saved_checks_ui_result': '7a28b53e92362616f6839d0c2dd75fe758f74ba91ff253b2830916febf3b43d0'}
# One added source regression covers the two deliberately separate GUI scopes.
# The workflow appends only this method after the unchanged original81 selection.
SAVED_CHECKS_SOURCE_METHOD = 'test_macos_normal_diagnostics_source.NormalDiagnosticsSourceTests.test_normal_saved_offline_and_empty_recovery_use_original_gui_only'
SAVED_CHECKS_BEGIN = "    // Ordinary saved offline checks and empty project-recovery inspection only.\n"
SAVED_CHECKS_END = "    // End ordinary saved offline and empty recovery journeys.\n\n"
SAVED_CHECKS_INSERTION_SHA256 = "f51d6f4576db08022016938624571f0b05781fdff8b66a060cc927801696e391"
SAVED_CHECKS_SOURCE_REFS = [
    'desktop/src/components/OfflinePreflight.tsx',
    'desktop/src/components/ProjectRecovery.tsx',
    'desktop/src/components/Common.tsx',
    'desktop/src/offlinePreflight.ts',
    'desktop/src/projectRecoveryController.ts',
    'desktop/src/offlinePreflightProtocol.ts',
    'desktop/src/projectRecoveryProtocol.ts',
    'src/mobile_release/desktop_preflight.py',
    'src/mobile_release/desktop_project_recovery.py',
    'src/mobile_release/build_inputs.py',
    'src/mobile_release/discovery.py',
]

SOURCE_REFS = ['tests/desktop/test_macos_normal_diagnostics_source.py',
 'desktop/native/macos-normal-ui/MRKNormalAppUITests/NormalAppUITests.swift',
 'desktop/native/macos-normal-ui/MRKNormalAppUITests/Fixtures/normal-project-v1.json',
 'desktop/src/components/EnvironmentDiagnostics.tsx',
 'desktop/src/environmentDiagnosticsController.ts',
 'desktop/src-tauri/src/environment_diagnostics_owner.rs']
EVIDENCE_LEAVES = ['diagnostics-test-file-limit.status',
 'diagnostics-test-file-budget.status',
 'diagnostics-test-file-budget.json',
 'diagnostics-test.status',
 'diagnostics-safe-facts.json',
 'diagnostics-summary.status',
 'diagnostics-result.json']


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def steps(workflow: str) -> tuple[list[str | None], dict[str, str]]:
    blocks = re.findall(r"(?ms)^      - name: .*?(?=^      - name: |\Z)", workflow)
    ids: list[str | None] = []
    mapped = {}
    for block in blocks:
        found = re.search(r"(?m)^        id: ([a-z0-9_]+)$", block)
        ident = found[1] if found else None
        ids.append(ident)
        if ident is not None:
            if ident in mapped:
                raise ValueError("duplicate workflow step identifier")
            mapped[ident] = block
    return ids, mapped


def inline_python(block: str, marker: str) -> str:
    head = "          \"$MRK_PYTHON\" -I -S -B - <<'" + marker + "'\n"
    if block.count(head) != 1:
        raise ValueError("missing original inline Python boundary")
    value = block.split(head, 1)[1].split("          " + marker + "\n", 1)[0]
    lines = value.splitlines(keepends=True)
    if not all(not line.strip() or line.startswith("          ") for line in lines):
        raise ValueError("inline Python indentation changed")
    source = "".join(line[10:] if line.strip() else line for line in lines)
    ast.parse(source)
    return source


class NormalDiagnosticsSourceTests(unittest.TestCase):
    def restored_initial_renderer_readiness(self, swift: str) -> str:
        # This one reviewed readiness allowance is not a general normalization:
        # the other launch site and every byte outside this block remain bound.
        self.assertEqual(swift.count(RENDERER_READINESS_BEGIN), 1)
        self.assertEqual(swift.count(RENDERER_READINESS_END), 1)
        begin = swift.index(RENDERER_READINESS_BEGIN)
        end = swift.index(RENDERER_READINESS_END) + len(RENDERER_READINESS_END)
        self.assertLess(begin, end)
        block = swift[begin:end]
        launch = swift.split('private func launchCancelAndQuit(profile:', 1)[1].split(
            '    private struct FixtureSpec', 1)[0]
        self.assertEqual(launch.count(block), 1)
        self.assertEqual(digest(block.encode()), RENDERER_READINESS_SHA256)
        ordered = (
            'let rendererQuery = window.webViews',
            'let rendererCount = rendererQuery.count',
            'if rendererCount != 1 {',
            'try require(rendererCount <= 1, "ordinary first-party renderer is ambiguous")',
            'var observedReadyCount = rendererCount',
            'if rendererCount == 0 {',
            'try require(rendererQuery.element(boundBy: 0).waitForExistence(timeout: try remaining(5)),',
            'observedReadyCount = rendererQuery.count',
            'try require(observedReadyCount == 1, "ordinary first-party renderer is missing or ambiguous")',
            'let renderer = rendererQuery.element(boundBy: 0)',
        )
        positions = []
        for token in ordered:
            self.assertEqual(block.count(token), 1, token)
            positions.append(block.index(token))
        self.assertEqual(positions, sorted(positions))
        self.assertIn('if rendererCount == 0 {\n'
                      '            try require(rendererQuery.element(boundBy: 0).waitForExistence(timeout: try remaining(5)),\n'
                      '                        "ordinary first-party renderer did not appear")\n'
                      '            observedReadyCount = rendererQuery.count\n'
                      '        }\n', block)
        for token, count in (('window.webViews', 1), ('.count', 2), ('.element(', 2),
                             ('waitForExistence(', 1), ('remaining(5)', 1), ('print(', 1)):
            self.assertEqual(block.count(token), count, token)
        for forbidden in ('firstMatch', 'matching(', 'allElements', 'descendants(', 'children(',
                          'snapshot(', 'debugDescription', 'sleep(', 'while ', 'return',
                          'try?', 'catch', '.click(', 'evaluateJavaScript', 'app.', 'Process()',
                          'FileManager', 'write(', 'beginCase(', 'journeyDeadline ='):
            self.assertNotIn(forbidden, block, forbidden)
        strict = swift.split('private func launchForJourney() throws -> (XCUIApplication, XCUIElement, XCUIElement) {', 1)[1].split(
            '    private enum PrivateInput: String {', 1)[0]
        self.assertEqual(strict.count(RENDERER_QUERY_BEGIN), 1)
        self.assertEqual(strict.count(RENDERER_QUERY_END), 1)
        original = strict[strict.index(RENDERER_QUERY_BEGIN):strict.index(RENDERER_QUERY_END) + len(RENDERER_QUERY_END)]
        self.assertEqual(len(original.encode()), 576)
        self.assertEqual(digest(original.encode()), RENDERER_QUERY_DIAGNOSTICS_SHA256)
        return swift[:begin] + original + swift[end:]

    def restored_renderer_queries(self, swift: str) -> str:
        swift = self.restored_initial_renderer_readiness(swift)
        # After that exact allowance, bind the same original query/count/refusal
        # at exactly the two existing launch sites without other changes.
        self.assertEqual(swift.count(RENDERER_QUERY_BEGIN), 2)
        self.assertEqual(swift.count(RENDERER_QUERY_END), 2)
        self.assertEqual(swift.count(RENDERER_QUERY_ORIGINAL), 0)
        begin = swift.index(RENDERER_QUERY_BEGIN)
        end = swift.index(RENDERER_QUERY_END, begin) + len(RENDERER_QUERY_END)
        block = swift[begin:end]
        self.assertEqual(swift.count(block), 2)
        for signature, following in (
            ('    func testLaunchCancelAndQuit() throws {', '    // Finite synthetic files only.'),
            ('    @MainActor private func launchForJourney() throws -> (XCUIApplication, XCUIElement, XCUIElement) {',
             '    private enum PrivateInput: String {'),
        ):
            self.assertEqual(swift.count(signature), 1)
            self.assertEqual(swift.count(following), 1)
            caller = swift.split(signature, 1)[1].split(following, 1)[0]
            self.assertEqual(caller.count(block), 1)
            self.assertIn('try require(window.isHittable, "ordinary main window is not usable")\n' + block
                          + '        try dashboard(renderer)\n', caller)
        for fragment in (
            'let rendererQuery = window.webViews',
            'let rendererCount = rendererQuery.count',
            'if rendererCount != 1 {\n            print(',
            'min(rendererCount, 5)', 'rendererCount > 4 ? 1 : 0',
            'try require(rendererCount == 1, "ordinary first-party renderer is missing or ambiguous")',
            'let renderer = rendererQuery.element(boundBy: 0)',
        ):
            self.assertEqual(block.count(fragment), 1, fragment)
        self.assertEqual(block.count('window.webViews'), 1)
        self.assertEqual(block.count('.count'), 1)
        self.assertEqual(block.count('.element('), 1)
        self.assertEqual(block.count('print('), 1)
        self.assertEqual(block.count('MRK_MACOS_NORMAL_RENDERER_QUERY=observation=initial;matches='), 1)
        self.assertEqual(block.count(';nonAtomic=1"'), 1)
        self.assertEqual(swift.count('MRK_MACOS_NORMAL_RENDERER_QUERY='), 2)
        self.assertLess(block.index('let rendererQuery = window.webViews'), block.index('let rendererCount = rendererQuery.count'))
        self.assertLess(block.index('let rendererCount = rendererQuery.count'), block.index('if rendererCount != 1'))
        self.assertLess(block.index('if rendererCount != 1'), block.index('print('))
        self.assertIn('        }\n        try require(rendererCount == 1, "ordinary first-party renderer is missing or ambiguous")\n'
                      '        let renderer = rendererQuery.element(boundBy: 0)\n', block)
        for forbidden in ('firstMatch', 'matching(', 'allElements', 'descendants(', 'children(',
                          'snapshot(', 'debugDescription', 'waitFor', 'sleep(', 'while ', 'return',
                          'try?', 'catch', '.click(', 'evaluateJavaScript', 'app.', 'Process()',
                          'FileManager', 'write('):
            self.assertNotIn(forbidden, block, forbidden)
        self.assertEqual(digest(block.encode()), RENDERER_QUERY_DIAGNOSTICS_SHA256)
        return swift.replace(block, RENDERER_QUERY_ORIGINAL)

    def restored_semantic_heading_queries(self, swift: str) -> str:
        # Refuse a missing, duplicate, broadened or unexpected title selector
        # before restoring only the reviewed complete source lines.
        self.assertEqual(len(SEMANTIC_HEADING_LINES), 17)
        self.assertEqual(swift.count(SEMANTIC_HEADING_PREFIX), 22)
        for original, semantic, count in SEMANTIC_HEADING_LINES:
            self.assertEqual(swift.count(semantic), count, semantic)
            self.assertEqual(swift.count(original), 0, original)
        for original, semantic, _count in SEMANTIC_HEADING_LINES:
            swift = swift.replace(semantic, original)
        self.assertNotIn(SEMANTIC_HEADING_PREFIX, swift)
        return swift

    def restored_dashboard_query(self, swift: str) -> str:
        # Validate this exact diagnostic allowance before reconstructing the old
        # singleton line for the unchanged whole-original-source pin below.
        self.assertEqual(swift.count(DASHBOARD_QUERY_BEGIN), 1)
        self.assertEqual(swift.count(DASHBOARD_QUERY_END), 1)
        begin = swift.index(DASHBOARD_QUERY_BEGIN)
        end = swift.index(DASHBOARD_QUERY_END) + len(DASHBOARD_QUERY_END)
        self.assertLess(begin, end)
        block = swift[begin:end]
        dashboard = swift.split('    @MainActor private func dashboard(_ renderer: XCUIElement) throws {', 1)[1].split(
            '    @MainActor private func quitSheet(', 1)[0]
        self.assertEqual(dashboard.count(block), 1)
        for fragment in (
            'let observedCount = heading.count',
            'if observedCount != 1 {\n            print(',
            'if observedCount > 1 && observedCount <= 4 {\n                for property in [',
            'for property in ["identifier", "title", "label", "value", "placeholderValue"] {',
            'heading.matching(NSPredicate(format: "%K == %@", property, "Good releases start here.")).count',
            'heading.containing(.staticText, identifier: "Good releases start here.").count',
            'try require(observedCount == 1, "dashboard heading is ambiguous")',
        ):
            self.assertEqual(block.count(fragment), 1, fragment)
        for value in ('observedCount', 'matches', 'containing'):
            self.assertEqual(block.count('min(' + value + ', 5)'), 1)
            self.assertEqual(block.count(value + ' > 4 ? 1 : 0'), 1)
        self.assertEqual(block.count('.count'), 3)
        self.assertEqual(block.count('print('), 3)
        self.assertEqual(block.count('MRK_MACOS_NORMAL_DASHBOARD_QUERY=observation='), 3)
        self.assertEqual(block.count(';nonAtomic=1"'), 3)
        self.assertLess(block.index('let observedCount = heading.count'), block.index('if observedCount != 1'))
        self.assertLess(block.index('observation=initial'), block.index('if observedCount > 1 && observedCount <= 4'))
        self.assertLess(block.index('if observedCount > 1 && observedCount <= 4'), block.index('heading.matching('))
        self.assertLess(block.index('heading.containing('), block.index('try require(observedCount == 1'))
        self.assertIn('            }\n        }\n        // Later diagnostic observations cannot repair the original singleton refusal.\n'
                      '        try require(observedCount == 1, "dashboard heading is ambiguous")\n', block)
        for forbidden in ('firstMatch', 'element(', 'allElements', 'snapshot(', 'debugDescription',
                          'waitFor', 'sleep(', 'while ', 'return', 'try?', 'catch', '.click(',
                          'evaluateJavaScript', 'app.', 'Process()', 'FileManager', 'write('):
            self.assertNotIn(forbidden, block, forbidden)
        self.assertEqual(digest(block.encode()), DASHBOARD_QUERY_DIAGNOSTICS_SHA256)
        return swift.replace(block, DASHBOARD_QUERY_ORIGINAL, 1)

    def checked_saved_checks_block(self, swift: str) -> str:
        # Do not broadly strip added methods or accept a self-reported boundary.
        # Both callers validate this single independently pinned closed block.
        self.assertEqual(swift.count(SAVED_CHECKS_BEGIN), 1)
        self.assertEqual(swift.count(SAVED_CHECKS_END), 1)
        begin = swift.index(SAVED_CHECKS_BEGIN)
        end = swift.index(SAVED_CHECKS_END) + len(SAVED_CHECKS_END)
        self.assertLess(begin, end)
        self.assertEqual(swift[end:end + len("    // One ordinary current diagnostics run,")],
                         "    // One ordinary current diagnostics run,")
        block = swift[begin:end]
        self.assertEqual(digest(block.encode()), SAVED_CHECKS_INSERTION_SHA256)
        self.assertEqual(re.findall(r'@MainActor func (test\w+)\(\) throws', block),
                         ['testSyntheticProjectSavedOfflineChecks', 'testSyntheticProjectEmptyBuildInputInspection'])
        for fragment, count in (
            ('executionTimeAllowance = 300', 2),
            ('try beginCase(seconds: 300)', 2),
            ('launchForJourney()', 2), ('let fixture = LocalFixture()', 2), ('try fixture.prepare()', 2),
            ('start.click()', 1), ('acknowledgement.click()', 1), ('inspect.click()', 1),
            ('let sheet = try quitSheet(app, window)', 2), ('try completeNormalQuit(app)', 2), ('try acceptFinalScenario()', 2),
            ('try fixture.closeOriginals()', 2), ('ownedFixture = nil', 2),
        ):
            self.assertEqual(block.count(fragment), count, fragment)
        for fragment in (
            '!run.isEnabled', '(acknowledgement.value as? String) == "0"',
            '(acknowledgement.value as? String) == "1"',
            'labels[start + 1] == "complete"', 'labels[start] == "Outcome: complete"',
            '"Original operation settled"', '"This invocation only"', '"Historical / stale context"',
            'panel.staticTexts.matching(identifier: unconfirmed).count == 0',
            'counts["MISSING", default: 0] >= 2 && counts["SKIP", default: 0] >= 1',
            '"Complete is not PASS or release readiness."',
            '"No pending build-input record observed"', '!review.isEnabled && panel.checkBoxes.count == 0',
            'panel.buttons.matching(identifier: "Recover reviewed build inputs").count == 0',
            'panel.buttons.matching(identifier: "Retire reviewed metadata").count == 0',
            'for label in [unconfirmed, historical, "Recorded session:",',
            'mutationRecovery=not-run;projectCleanliness=not-established',
        ):
            self.assertIn(fragment, block, fragment)
        self.assertGreaterEqual(block.count('try fixture.assertUnchanged()'), 11)
        for forbidden in ('app.launch()', 'app.terminate()', 'fixture.accept(', 'persistentCredentials',
                          'admitDefaultVault(', 'evaluateJavaScript', 'invoke(', 'Process()',
                          'FileManager', 'write(to:', 'Check original status', 'screenshot()', 'debugDescription'):
            self.assertNotIn(forbidden, block, forbidden)
        return block

    def test_normal_saved_offline_and_empty_recovery_use_original_gui_only(self):
        swift = self.restored_semantic_heading_queries((ROOT / SWIFT).read_text())
        block = self.checked_saved_checks_block(swift)
        offline = block.split('@MainActor func testSyntheticProjectSavedOfflineChecks() throws {', 1)[1]
        offline, recovery = offline.split('@MainActor func testSyntheticProjectEmptyBuildInputInspection() throws {', 1)
        # Ten seconds is a helper maximum, not a renewed native wait.
        for name, route in (
            ("press", ("try waitElement(", "timeout: timeout")),
            ("waitElement", ("XCTWaiter.wait(for: [expected], timeout: try remaining(timeout))",)),
            ("remaining", ("return try clock.remaining(requested, before: deadline)",)),
        ):
            helper = swift.split("private func " + name + "(", 1)[1].split("\n    @MainActor ", 1)[0]
            for fragment in route:
                self.assertTrue(fragment in helper, "missing original-clock clamp in " + name)
        for journey, prefix in ((offline, 'offline'), (recovery, 'recovery-idle')):
            for stage in ('launch', 'fixture', 'project-open', 'original-report', 'readback-and-quit'):
                self.assertEqual(journey.count('stage("' + prefix + '-' + stage + '")'), 1)
            for fragment in ('try goToFolder(sheet, path: fixture.projectPath)', 'try nativeOpen(sheet)',
                             'matching(identifier: fixture.projectPath)', 'matching(identifier: "org.fixture.app")',
                             'try savedOperationComplete(panel)', 'timeout: 10, failures: failures',
                             'cleanExitStatus=unavailable;allWorkerFinality=unavailable'):
                self.assertTrue(fragment in journey, prefix + ": missing " + fragment)
        for fragment in (
            'named(renderer, "Review the saved inputs and project-code effects")\n'
            '                .containing(.button, identifier: "Refresh saved configuration observation")',
            'try press(panel, "Refresh saved configuration observation"',
            'try press(panel, "Review offline checks"', 'named(panel, "Confirm this saved offline-check intent")',
            'let savedBytes = try fixture.text(LocalFixture.config).utf8.count',
            'Saved comparison: \\(savedBytes) bytes.',
            'matching(identifier: "Awaiting explicit consent")',
            'let run = try unique(consent.buttons.matching(identifier: "Run saved offline checks")',
            'let acknowledgement = try unique(consent.checkBoxes',
            'let start = try waitElement(consent.buttons.matching(identifier: "Run saved offline checks")',
            'enabled: true, timeout: try remaining(5), failures: failures', 'timeout: 90, failures: failures',
            'let report = try unique(named(panel, "Saved offline check findings")',
            'let counts = try savedOfflineCounts(report)',
            'panel.staticTexts.matching(identifier: historical).count == 0',
            'report.staticTexts.matching(identifier: "Historical / stale context").count == 0',
            'named(panel, "Confirm this saved offline-check intent").count == 0',
            'panel.buttons.matching(identifier: "Run saved offline checks").count == 0',
            'ordinary-ui-observed-saved-offline-report-and-settled-projection',
            'releaseReadiness=not-assessed', 'this is not zero-command evidence',
        ):
            self.assertTrue(fragment in offline, "offline: missing " + fragment)
        self.assertLess(offline.index('!run.isEnabled'), offline.index('acknowledgement.click()'))
        self.assertLess(offline.index('(acknowledgement.value as? String) == "0"'), offline.index('acknowledgement.click()'))
        self.assertLess(offline.index('(acknowledgement.value as? String) == "1"'), offline.index('start.click()'))
        self.assertLess(offline.index('start.click()'), offline.index('stage("offline-original-report")'))
        self.assertEqual(offline.count('try press(panel, "Review offline checks"'), 1)
        self.assertEqual(offline.count('let failures = ["No new offline-check outcome was confirmed", "Original cleanup unknown"]'), 1)
        self.assertNotIn('unconfirmed', offline.split('let failures = ', 1)[1].split('\n', 1)[0])
        for fragment in (
            'named(renderer, "Inspect first, then review what can safely be recovered")\n'
            '                .containing(.button, identifier: "Help: Project build-input recovery")',
            'let inspect = try waitElement(panel.buttons.matching(identifier: "Inspect build-input state")',
            'timeout: 135, failures: failures',
            'This is a build-input observation only. It does not mean the whole project, a previous file edit, signing account or Store release is clean.',
            '"Reviewed build-input session recovered."', '"Reviewed terminal metadata retired."',
            '"Pending build-input session", "Only terminal recovery metadata remains"] + failures',
            'panel.staticTexts.matching(identifier: label).count == 0',
            'ordinary-ui-observed-empty-build-input-inspection-and-settled-projection',
        ):
            self.assertTrue(fragment in recovery, "recovery: missing " + fragment)
        self.assertNotIn('start.click()', recovery)
        self.assertNotIn('acknowledgement.click()', recovery)
        self.assertLess(recovery.index('!review.isEnabled'), recovery.index('inspect.click()'))
        self.assertLess(recovery.index('inspect.click()'), recovery.index('stage("recovery-idle-original-report")'))
        self.assertEqual(recovery.count('let failures = ["No new recovery outcome was confirmed", "Original cleanup unknown"]'), 1)
        self.assertNotIn('unconfirmed', recovery.split('let failures = ', 1)[1].split('\n', 1)[0])
        for fragment in ('statuses = ["PASS", "FAIL", "MISSING", "BLOCKED", "INVALID", "SKIP", "MANUAL", "CONFIGURED", "NOT_APPLICABLE"]',
                         'starts.count == 1', 'start + statuses.count * 2 <= labels.count',
                         '(0...128).contains(count), value == String(count)', 'let total = counts.values.reduce(0, +)',
                         '0 omitted from that list. Counts below include every reported finding.',
                         '"Android module configuration.", "Android Gradle wrapper policy.", "Core early-exit or remaining-check policy."'):
            self.assertTrue(fragment in block, "saved-checks: missing " + fragment)

        # The original fixture is unchanged; no copied recovery journal, service
        # credentials, wrapper or configured arbitrary command is added for a pass.
        raw = (ROOT / FIXTURE).read_bytes()
        self.assertEqual(digest(raw), 'ea9b004f0026c053bc1a12607cc70bd0a6f7e07afe9f33cf2a17506de62d512c')
        fixture = json.loads(raw)
        files = {name: base64.b64decode(value, validate=True) for name, value in fixture['files'].items()}
        expected = {'project/release/mobile-release.json', 'project/release/version.properties', 'project/.gitignore',
                    'project/README-user.txt', 'project/.github/workflows/keep-user.yml', 'sources/01.png', 'sources/02.png'}
        expected.update('project/release/store/android/' + locale + '/' + name + '.txt'
                        for locale in ('en-US', 'fr-FR') for name in ('title', 'short_description', 'full_description'))
        self.assertEqual(set(files), expected)
        config = json.loads(files['project/release/mobile-release.json'])
        self.assertEqual(config['android'], {'applicationId': 'org.fixture.app', 'enabled': True, 'identityStatus': 'unverified'})
        self.assertEqual(config['ios'], {'enabled': False})
        self.assertEqual(config['services'], {'androidFirebase': 'disabled', 'iosFirebase': 'disabled'})
        self.assertEqual(config['projectChecks'], {'preflight': [], 'androidArtifact': [], 'iosArtifact': []})
        fixture_helper = swift.split('private final class LocalFixture {', 1)[1].split('@MainActor private var ownedFixture:', 1)[0]
        unchanged = fixture_helper.split('func assertUnchanged() throws {', 1)[1].split('func accept(', 1)[0]
        self.assertIn('old.bytes == observed.bytes && old.facts == observed.facts', unchanged)
        self.assertIn('try checkRoster()', unchanged)

        sources = {name: (ROOT / name).read_text() for name in SAVED_CHECKS_SOURCE_REFS}
        offline_ui = sources['desktop/src/components/OfflinePreflight.tsx']
        recovery_ui = sources['desktop/src/components/ProjectRecovery.tsx']
        for fragment in ('<section className="card offline-preflight" aria-labelledby={label}>',
                         '<h3 id={label}>Review the saved inputs and project-code effects</h3>',
                         '>Refresh saved configuration observation</button>',
                         'aria-label="Confirm this saved offline-check intent"', 'disabled={runReason !== null}',
                         "terminal: 'Original operation settled'", 'aria-label="Saved offline check findings"',
                         "historical ? 'Historical / stale context' : 'This invocation only'", 'Complete is not PASS or release readiness.'):
            self.assertIn(fragment, offline_ui)
        for fragment in ('<h3 id={label}>Inspect first, then review what can safely be recovered</h3>',
                         "label: 'Project build-input recovery'", "controller.prepare('inspect')", "controller.prepare('recover')",
                         'disabled={recoverReason !== null}', "idle: 'No pending build-input record observed'",
                         "terminal: 'Original operation settled'", 'value.status === \'idle\''):
            self.assertIn(fragment, recovery_ui)
        self.assertIn('aria-label={`Help: ${content.label}`}', sources['desktop/src/components/Common.tsx'])
        offline_controller = sources['desktop/src/offlinePreflight.ts']
        for fragment in ('savedConfig: parseSavedConfigContent(project.savedConfigContent)',
                         'attempt.identity = id(op); attempt.prepareReply = true;',
                         'attempt.startSent = true; attempt.startAfter = attempt.observer.status?.statusRevision ?? 0;',
                         'consent: null, pending: \'start\', originalUnconfirmed: true, historical: false',
                         'historical: !attempt || !matched || attempt.retired || !this.matches(attempt)',
                         'originalUnconfirmed: finished || startObserved ? false : this.state.originalUnconfirmed',
                         "sameOfflineIdentity(status.operation, attempt.identity) || status.operation.phase === 'awaiting-consent'"):
            self.assertIn(fragment, offline_controller)
        recovery_controller = sources['desktop/src/projectRecoveryController.ts']
        for fragment in ("acknowledged: action === 'inspect'", "if (action === 'inspect') await this.start(op.operationId, op.ownerGeneration);",
                         "op.phase !== 'terminal' || op.outcome !== 'complete'", 'this.state.historical',
                         "return recoveryEligible(inspected) ? null : 'The inspection has no eligible pending build-input session to recover.'"):
            self.assertIn(fragment, recovery_controller)
        self.assertIn("op.outcome === 'complete' ? !result(op.result) || !sameSavedConfig(op.result.usedConfig, op.context.savedConfig) : op.result !== null",
                      sources['desktop/src/offlinePreflightProtocol.ts'])
        self.assertIn("if (!result(op.result, op.context) || op.effect !== (op.context.action === 'inspect' ? 'inspection' : 'recovery-attempted')) return null;",
                      sources['desktop/src/projectRecoveryProtocol.ts'])
        service = sources['src/mobile_release/desktop_preflight.py']
        for fragment in ('mode="offline", platforms=("android",)', 'run_builds=False,', 'artifacts=None, credentials_file=None',
                         'credentials_from_env=False, require_tools=False', 'signing_lease=None, invocation=invocation'):
            self.assertIn(fragment, service)
        self.assertNotIn('invocation.materialization(', service)
        discovery = sources['src/mobile_release/discovery.py']
        for fragment in ('"GIT_CONFIG_NOSYSTEM": "1"', '"GIT_CONFIG_GLOBAL": os.devnull', '"GIT_OPTIONAL_LOCKS": "0"',
                         '"GIT_NO_LAZY_FETCH": "1"', '"GIT_ALLOW_PROTOCOL": ""', '"core.fsmonitor=false"',
                         '"core.hooksPath=" + os.devnull', '"protocol.allow=never"', 'timeout=10'):
            self.assertIn(fragment, discovery)
        recovery_service = sources['src/mobile_release/desktop_project_recovery.py']
        self.assertIn('_desktop_inspect_build_inputs(', recovery_service)
        inputs = sources['src/mobile_release/build_inputs.py']
        inspection = inputs.split('def _desktop_inspect_build_inputs(', 1)[1].split('def _desktop_recover_build_inputs(', 1)[0]
        self.assertIn('if project.meta.number is None or _stat(project.meta.number, _PENDING) is None:', inspection)
        self.assertIn('return _DesktopRecoveryInspection("idle")', inspection)
        self.assertNotIn('ensure_meta(', inspection)
        finish = inputs.split('    def _finish(self) -> None:', 1)[1].split('    def cleanup(self) -> None:', 1)[0]
        self.assertLess(finish.index('_consumer_idle(self.cancellation)'), finish.index('self.quiescence = "original"'))
        self.assertLess(finish.index('self.quiescence = "original"'), finish.index('self._checkpoint()'))
        self.assertNotIn('operator', block.split('@MainActor func testSyntheticProjectEmptyBuildInputInspection()', 1)[1])

    def checked_diagnostics_source(self) -> tuple[str, str]:
        swift = self.restored_semantic_heading_queries((ROOT / SWIFT).read_text())
        swift = self.restored_renderer_queries(swift)
        swift = self.restored_dashboard_query(swift)
        added = self.checked_saved_checks_block(swift)
        swift = swift.replace(added, "", 1)
        start = "    // One ordinary current diagnostics run, not full doctor or project-code execution.\n"
        end = "    override func tearDown() async throws {\n"
        self.assertEqual(swift.count(start), 1)
        self.assertEqual(swift.count(end), 1)
        insertion = start + swift.split(start, 1)[1].split(end, 1)[0]
        self.assertEqual(digest(insertion.encode()), DIAGNOSTICS_INSERTION_SHA256)
        # Fixture/content policy is unchanged; the separately reviewed common
        # original-owner/deadline migration is included in this pinned baseline.
        self.assertEqual(digest(swift.replace(insertion, "", 1).encode()), ORIGINAL_SWIFT_SHA256)
        return swift, insertion

    def test_renderer_readiness_preserves_one_query_and_current_baseline(self):
        self.checked_diagnostics_source()
        source = (ROOT / SWIFT).read_text()
        original, semantic, count = SEMANTIC_HEADING_LINES[0]
        self.assertEqual(count, 1)
        restart_original, restart_semantic, restart_count = SEMANTIC_HEADING_LINES[-1]
        self.assertEqual(restart_count, 1)
        self.assertIn("restartedRenderer.staticTexts", restart_semantic)
        for label, changed in (
            ("broad identifier reversion", source.replace(semantic, original, 1)),
            ("duplicate dashboard heading", source.replace(semantic, semantic + semantic, 1)),
            ("looser title predicate", source.replace(
                semantic, semantic.replace("title == %@", "title CONTAINS %@", 1), 1)),
            ("broad restart heading reversion", source.replace(restart_semantic, restart_original, 1)),
        ):
            with self.subTest(semantic_heading_refusal=label):
                with self.assertRaises(AssertionError):
                    self.restored_semantic_heading_queries(changed)

    def test_normal_diagnostics_observes_original_complete_report_and_settled_projection(self):
        swift, insertion = self.checked_diagnostics_source()
        self.assertEqual(insertion.count("@MainActor func " + METHOD + "() throws"), 1)
        for fragment in (
            'launchForJourney()', 'let fixture = LocalFixture()', 'ownedFixture = fixture', 'try fixture.prepare()',
            'try goToFolder(sheet, path: fixture.projectPath)', 'try nativeOpen(sheet)',
            'label: "Release platform", value: "Android"', 'label: "Activity", value: "Build / archive"',
            'named(renderer, "Observed build-tool checks")\n'
            '                .containing(.button, identifier: "Check build tools")',
            '"Tool observations from this run"',
            '"Phase: settled"', '"Outcome: complete"', '"Native finality: settled"',
            '"Android / build · draft "', '" · core host macos"',
            '" · acknowledged original Start. Receipt time is not a native deadline or a fresh probe."',
            '"macOS developer selection", "Git version", "Java runtime version", "Java compiler version"',
            '"Core resource observations — provisional, not native finality"',
            'rows[0] == "Core outcome" && rows[1] == "complete" && rows[2] == "Commands attempted"',
            '(1...4).contains(attempts), rows[3] == String(attempts)',
            '"complete": "true", "fatal": "false", "contained": "true"',
            '"commandDispatched": "true", "commands": String(attempts), "inputClosed": "true"',
            '"handlersRestored": "true", "toolDescriptorsClosed": "true", "stopObserved": "none"',
            'expected[rows[offset]] != nil && observed[rows[offset]] == nil', 'observed == expected',
            'commandsAttempted = try diagnosticsCoreReport(panel)',
            'context.element(boundBy: 0).label == originalContext',
            'for query in [fresh, phase, outcome, finality, provenance]',
            'let sheet = try quitSheet(app, window)', 'try completeNormalQuit(app)', 'try acceptFinalScenario()',
            'try fixture.closeOriginals()', 'ownedFixture = nil', SCOPE,
        ):
            self.assertIn(fragment, insertion, fragment)
        self.assertEqual(insertion.count('start.click()'), 1)
        self.assertEqual(insertion.count('matching(identifier: "Check build tools")'), 1)
        self.assertEqual(insertion.count('executionTimeAllowance = 300'), 1)
        self.assertEqual(insertion.count('try beginCase(seconds: 300)'), 1)
        self.assertEqual(insertion.count('journeyDeadline = min(wholeDeadline, try clock.end(within: 15))'), 1)
        self.assertIn('defer { journeyDeadline = wholeDeadline }', insertion)
        self.assertGreaterEqual(insertion.count('try fixture.assertUnchanged()'), 5)
        for forbidden in ('app.launch()', 'app.terminate()', 'fixture.accept(', 'evaluateJavaScript',
                          'invoke(', 'Process()', 'xcode-select', 'Run saved offline checks',
                          'Recover reviewed build inputs', 'Read native status', 'screenshot()', 'debugDescription'):
            self.assertNotIn(forbidden, insertion)
        fixture = json.loads((ROOT / FIXTURE).read_bytes())
        config = json.loads(base64.b64decode(fixture['files']['project/release/mobile-release.json'], validate=True))
        self.assertIs(config['android']['enabled'], True)
        self.assertEqual(config['android']['applicationId'], 'org.fixture.app')
        self.assertIs(config['ios']['enabled'], False)
        self.assertEqual(config['projectChecks']['preflight'], [])
        # The queried fields are actual shipped result/provenance presentation.
        component = (ROOT / 'desktop/src/components/EnvironmentDiagnostics.tsx').read_text()
        for fragment in ('const result = observation?.projection.result ?? null;', '!compact && observation && result',
                         'observation.stale ? \'Earlier / stale tool observations\' : \'Tool observations from this run\'',
                         'row.finality', 'observation.projection', "'acknowledged original Start'",
                         '<dt>Core outcome</dt><dd>{result.outcome}</dd>',
                         '<dt>Commands attempted</dt><dd>{result.commandsAttempted}</dd>', 'Object.entries(result.lifetime)'):
            self.assertIn(fragment, component)
        controller = (ROOT / 'desktop/src/environmentDiagnosticsController.ts').read_text()
        for fragment in ('sameDiagnosticsContext(row.context, attempt.binding)', 'sameRun(row, attempt.projection)',
                         'status.statusRevision > attempt.binding.nativeStatusRevision && row.runId !== attempt.binding.previousRunId',
                         'acknowledged: attempt.acknowledged || acknowledgedBinding === attempt.binding',
                         'stale: !currentAttempt || !binding || !this.matches(binding)',
                         "provenance: currentAttempt ? currentAttempt.acknowledged ? 'acknowledged-start'"):
            self.assertIn(fragment, controller)
        owner = (ROOT / 'desktop/src-tauri/src/environment_diagnostics_owner.rs').read_text()
        for fragment in ('a.projection.result = Some(terminal)', 'let Poll::Ready(result) = Pin::new(handle).poll(&mut context)',
                         'if positive && recorded', 'if !final_clock_clear(&self.inner, &r, &owner, now)',
                         'manager_joined && startup_settled && io_joined && io && protocol && installed_final(&book, &owner)',
                         'book.out_end.as_ref().is_some_and(|r| r.closed && r.eof)',
                         'book.err_end.as_ref().is_some_and(|r| r.closed && r.eof)'):
            self.assertIn(fragment, owner)
        self.assertEqual(owner.count('active.projection.phase = Phase::Settled; active.projection.finality = Finality::Settled;'), 1)

    def test_normal_diagnostics_workflow_has_one_bounded_original_result(self):
        workflow = (ROOT / '.github/workflows/desktop-macos-installed.yml').read_text()
        ids, blocks = steps(workflow)
        order = ['normal_ui_result', 'normal_project_ui_test', 'normal_project_ui_result',
                 'normal_persistence_ui_test', 'normal_persistence_ui_result',
                 'normal_diagnostics_ui_test', 'normal_diagnostics_ui_result',
                 'normal_saved_checks_ui_test', 'normal_saved_checks_ui_result']
        begin = ids.index(order[0])
        self.assertEqual(ids[begin:begin + len(order)], order)
        for ident, pin in BLOCK_PINS.items():
            self.assertEqual(ids.count(ident), 1)
            self.assertEqual(digest(blocks[ident].encode()), pin, ident)
        test = blocks['normal_diagnostics_ui_test']
        result = blocks['normal_diagnostics_ui_result']
        self.assertIn("steps.normal_persistence_ui_result.outcome == 'success'", test)
        self.assertIn("steps.normal_diagnostics_ui_test.outcome == 'success'", result)
        self.assertEqual(test.count('desktop/tools/macos_normal_ui_runner.py test-without-building'), 1)
        selector = '-only-testing:MRKNormalAppUITests/NormalAppUITests/' + METHOD
        self.assertEqual(workflow.count(selector), 1)
        for fragment in ('timeout-minutes: 7', 'ulimit -f 1048576', 'resource.getrlimit(resource.RLIMIT_FSIZE)',
                         'admitted = actual == (expected, expected)', '"phase": "diagnostics-test"',
                         '[[ "$file_limit_status" == 0 ]] || exit "$file_limit_status"',
                         '[[ "$file_budget_status" == 0 ]] || exit "$file_budget_status"',
                         '-derivedDataPath "$MRK_MACOS_WORK/normal-ui/DerivedData"',
                         '-resultBundlePath "$MRK_MACOS_WORK/normal-ui/diagnostics-test.xcresult"',
                         '-default-test-execution-time-allowance 300 -maximum-test-execution-time-allowance 300',
                         'TEST_RUNNER_MRK_NORMAL_UI_HOSTED_JOB=github-hosted-macos26-arm64',
                         'TEST_RUNNER_MRK_NORMAL_UI_APPLICATION_SOURCE=$GITHUB_SHA',
                         'TEST_RUNNER_MRK_NORMAL_UI_HARNESS_SOURCE=$GITHUB_SHA',
                         '[[ "$test_status" == 0 ]] || exit "$test_status"'):
            self.assertIn(fragment, test, fragment)
        self.assertLess(test.index('[[ "$file_budget_status" == 0 ]]'), test.index('desktop/tools/macos_normal_ui_runner.py test-without-building'))
        budget = inline_python(test, 'PY_UI_FILE_BUDGET')
        safe = inline_python(test, 'PY_DIAGNOSTICS_SAFE_FACTS')
        result_source = inline_python(result, 'PY_DIAGNOSTICS_RESULT')
        for source in (budget, safe, result_source):
            self.assertIn('os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC', source)
            self.assertIn('os.fsync(', source)
            self.assertIn('finally: os.close(fd)', source)
        self.assertIn('"nativeSuccessInferred": False, "rawTextExported": False', safe)
        self.assertIn('if len(events) > 64:', safe)
        self.assertIn('("launch", "fixture", "project-open", "context", "original-report", "readback-and-quit")', safe)
        self.assertIn('json.loads(summary_bytes, object_pairs_hook=unique)', result_source)
        self.assertIn('"totalTestCount": 1, "passedTests": 1, "failedTests": 0, "skippedTests": 0, "expectedFailures": 0', result_source)
        self.assertIn('type(summary.get(key)) is not int or summary[key] != value', result_source)
        self.assertIn('MRKNormalAppUITests/NormalAppUITests/' + METHOD, result_source)
        for fragment in ('source != os.environ["MRK_EXPECTED_SHA"]', 'prior["sourceTree"] != preview["sourceTree"]',
                         'prior["signedAppBinarySha256"] != preview["signedAppBinarySha256"]',
                         'prior["runtimeManifestSha256"] != preview["runtimeManifestSha256"]',
                         'set(budget) != set(expected_budget)', 'type(budget[key]) is not type(value)',
                         '"hardBytes": 1073741824', '"safeFactsSha256": hashlib.sha256(facts_bytes).hexdigest()',
                         SCOPE, '"diagnosticsReportAndSettledProjectionUI": "passed"',
                         '"cleanExitStatus": None', '"independentOwnerResourceProof": False',
                         '"allWorkerFinality": "not-established-by-XCTest-UI-state"',
                         '"fullDoctorExecuted": False, "offlinePreflightExecuted": False, "projectRecoveryExecuted": False',
                         '"releaseReadinessEstablished": False', '"productReady": False'):
            self.assertIn(fragment, result_source, fragment)
        evidence = blocks['evidence']
        for leaf in EVIDENCE_LEAVES:
            self.assertEqual(evidence.count('${{ steps.work.outputs.root }}/normal-ui/' + leaf + '\n'), 1)
        for suffix in ('diagnostics-test.log', 'diagnostics-summary.raw.json', 'diagnostics-summary.stderr',
                       'diagnostics-test.xcresult', 'diagnostics-test.tail.txt'):
            self.assertNotIn('/normal-ui/' + suffix, evidence)
        cleanup = workflow.split("      - name: Remove only this completed preview build's disposable compiler outputs\n", 1)[1]
        self.assertIn("steps.normal_diagnostics_ui_result.outcome == 'success'", cleanup.split('        run: |', 1)[0])
        self.assertIn('root / "normal-ui/diagnostics-test.xcresult"', cleanup)
        self.assertIn('"diagnostics-test.log", "diagnostics-summary.raw.json", "diagnostics-summary.stderr"', cleanup)
        data = blocks['data_contracts']
        names = ast.literal_eval(re.search(r'          names = (\[\n.*?\n          \])\n', data, re.S)[1])
        selected_digest = lambda values: digest(json.dumps(values, separators=(',', ':')).encode())
        self.assertEqual(len(names), 82)
        self.assertEqual(len(set(names)), 82)
        self.assertEqual(selected_digest(names[:79]), '81ca0c9325763f3aaf2a181e521d7b6adde06b7c0321eecacfc2b93a78c3c051')
        self.assertEqual(names[79:81], SOURCE_METHODS)
        self.assertEqual(selected_digest(names[:81]), ORIGINAL_ROSTER_SHA256)
        self.assertEqual(names[81:], [SAVED_CHECKS_SOURCE_METHOD])
        self.assertEqual(selected_digest(names), ROSTER_SHA256)
        self.assertEqual(data.count(ROSTER_SHA256), 2)
        sources = ast.literal_eval(re.search(r'          source_names = (\(\n.*?\n          \))\n', data, re.S)[1])
        self.assertEqual(len(sources), 69)
        self.assertEqual(len(sources), len(set(sources)))
        self.assertEqual(selected_digest(sources[:53]), "5d544a55d63d5ac1f14f341b0ba51509c6c77e762e2f7e7c964fc9f87ec44bf4")
        self.assertEqual(list(sources[53:64]), SAVED_CHECKS_SOURCE_REFS)
        self.assertEqual(list(sources[64:]), [
            "desktop/macos-installed-inputs/build-release.json",
            "desktop/src-tauri/src/macos_build_release.rs",
            "desktop/src-tauri/src/macos_install_fixed_paths.rs",
            "desktop/src-tauri/src/macos_install_paths.rs",
            "desktop/src-tauri/tauri.conf.json",
        ])
        self.assertTrue(set(SOURCE_REFS).issubset(sources))
        for fragment in ('len(names) != 82 or len(set(names)) != 82', 'suite.countTestCases() != 82',
                         'facts["testsRun"] == 82', 'counts.get("testsRun") != 82', '"pythonExpectedCount": 82',
                         '"githubActionCount": 22, "normalDiagnosticsSourceCount": 3',
                         '"test_macos_normal_diagnostics_source") or not method.startswith("test_")'):
            self.assertIn(fragment, data, fragment)


        # One already-built runner invocation contains precisely these two independent journeys.
        saved_test = blocks['normal_saved_checks_ui_test']
        saved_result = blocks['normal_saved_checks_ui_result']
        saved_methods = ['testSyntheticProjectSavedOfflineChecks', 'testSyntheticProjectEmptyBuildInputInspection']
        saved_identifiers = ['MRKNormalAppUITests/NormalAppUITests/' + name for name in saved_methods]
        self.assertEqual(workflow.count('/usr/bin/xcodebuild build-for-testing'), 1)
        self.assertEqual(workflow.count('desktop/tools/macos_normal_ui_runner.py test-without-building'), 5)
        self.assertEqual(saved_test.count('desktop/tools/macos_normal_ui_runner.py test-without-building'), 1)
        self.assertEqual(re.findall(r'-only-testing:MRKNormalAppUITests/NormalAppUITests/(test[A-Za-z0-9_]+)', saved_test), saved_methods)
        for identifier in saved_identifiers:
            self.assertEqual(workflow.count('-only-testing:' + identifier), 1)
        self.assertIn("steps.normal_diagnostics_ui_result.outcome == 'success'", saved_test)
        self.assertIn("steps.normal_saved_checks_ui_test.outcome == 'success'", saved_result)
        for fragment in ('timeout-minutes: 12', 'ulimit -f 1048576', 'resource.getrlimit(resource.RLIMIT_FSIZE)',
                         'admitted = actual == (expected, expected)', '"phase": "saved-checks-test"',
                         '[[ "$file_limit_status" == 0 ]] || exit "$file_limit_status"',
                         '[[ "$file_budget_status" == 0 ]] || exit "$file_budget_status"',
                         '-project desktop/native/macos-normal-ui/MRKNormalAppUI.xcodeproj -scheme MRKNormalAppUI',
                         "-configuration Debug -destination 'platform=macOS,arch=arm64' -destination-timeout 15",
                         '-derivedDataPath "$MRK_MACOS_WORK/normal-ui/DerivedData"',
                         '-resultBundlePath "$MRK_MACOS_WORK/normal-ui/saved-checks-test.xcresult"',
                         '-parallel-testing-enabled NO -test-timeouts-enabled YES',
                         '-default-test-execution-time-allowance 300 -maximum-test-execution-time-allowance 300',
                         'TEST_RUNNER_MRK_NORMAL_UI_HOSTED_JOB=github-hosted-macos26-arm64',
                         'TEST_RUNNER_MRK_NORMAL_UI_APPLICATION_SOURCE=$GITHUB_SHA',
                         'TEST_RUNNER_MRK_NORMAL_UI_HARNESS_SOURCE=$GITHUB_SHA',
                         '[[ "$test_status" == 0 ]] || exit "$test_status"'):
            self.assertIn(fragment, saved_test, fragment)
        self.assertLess(saved_test.index('[[ "$file_budget_status" == 0 ]]'), saved_test.index('desktop/tools/macos_normal_ui_runner.py test-without-building'))
        saved_budget = inline_python(saved_test, 'PY_UI_FILE_BUDGET')
        saved_safe = inline_python(saved_test, 'PY_SAVED_CHECKS_SAFE_FACTS')
        saved_result_source = inline_python(saved_result, 'PY_SAVED_CHECKS_RESULT')
        for code in (saved_budget, saved_safe, saved_result_source):
            self.assertIn('os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC', code)
            self.assertIn('os.fsync(', code)
            self.assertIn('finally: os.close(fd)', code)
        stages = next(node.value for node in ast.parse(saved_safe).body if isinstance(node, ast.Assign)
                      and any(isinstance(target, ast.Name) and target.id == 'stages' for target in node.targets))
        self.assertEqual(ast.literal_eval(stages), {
            'offline-launch', 'offline-fixture', 'offline-project-open', 'offline-review-and-start',
            'offline-original-report', 'offline-readback-and-quit',
            'recovery-idle-launch', 'recovery-idle-fixture', 'recovery-idle-project-open', 'recovery-idle-inspect',
            'recovery-idle-original-report', 'recovery-idle-readback-and-quit'})
        for fragment in ('"nativeSuccessInferred": False, "rawTextExported": False', 'if len(events) > 64:',
                         'before.st_size <= 16 * 1024 * 1024', 'before.st_size - 262144'):
            self.assertIn(fragment, saved_safe)
        assignments = {target.id: node.value for node in ast.parse(saved_result_source).body if isinstance(node, ast.Assign)
                       for target in node.targets if isinstance(target, ast.Name)}
        self.assertEqual(ast.literal_eval(assignments['prior_expected']),
                         {"totalTestCount": 1, "passedTests": 1, "failedTests": 0, "skippedTests": 0, "expectedFailures": 0})
        self.assertEqual(ast.literal_eval(assignments['expected']),
                         {"totalTestCount": 2, "passedTests": 2, "failedTests": 0, "skippedTests": 0, "expectedFailures": 0})
        fields = {key.value: value for key, value in zip(assignments['result'].keys, assignments['result'].values)}
        self.assertEqual(ast.literal_eval(fields['testIdentifiers']), saved_identifiers)
        self.assertEqual(ast.literal_eval(fields['scope']), 'ordinary-ui-observed-saved-offline-and-empty-build-input-inspection')
        journeys = ast.literal_eval(fields['journeys'])
        self.assertEqual(list(journeys), ['savedOfflineChecks', 'emptyBuildInputInspection'])
        for journey, identifier in zip(journeys.values(), saved_identifiers):
            self.assertEqual(journey['testIdentifier'], identifier)
            self.assertEqual(journey['coreOutcomeObserved'], 'complete')
            self.assertEqual(journey['nativeProjectionObserved'], {"phase": "settled", "finality": "settled"})
            self.assertEqual(journey['fixtureReadback'], 'unchanged-before-and-after-normal-quit')
            self.assertEqual(journey['applicationStateAfterNormalQuit'], 'notRunning')
        offline_result = journeys['savedOfflineChecks']
        self.assertEqual(offline_result['scope'], 'ordinary-ui-observed-saved-offline-report-and-settled-projection')
        self.assertEqual(offline_result['savedOfflineReportAndSettledProjectionUI'], 'passed')
        self.assertEqual(offline_result['negativeFindingsAssertion'],
                         {"missingAtLeast": 2, "skippedAtLeast": 1, "moduleWrapperAndEarlyExitObserved": True})
        idle_result = journeys['emptyBuildInputInspection']
        self.assertEqual(idle_result['scope'], 'ordinary-ui-observed-empty-build-input-inspection-and-settled-projection')
        self.assertEqual(idle_result['emptyBuildInputInspectionAndSettledProjectionUI'], 'passed')
        self.assertEqual(idle_result['inspectionStatusObserved'], 'idle')
        self.assertIs(idle_result['mutationRecoveryExecuted'], False)
        self.assertIs(idle_result['projectCleanlinessEstablished'], False)
        for name in ('result.json', 'project-result.json', 'persistence-result.json', 'diagnostics-result.json'):
            self.assertIn('("' + name + '", ', saved_result_source)
        for fragment in ('source != os.environ["MRK_EXPECTED_SHA"]', 'prior["sourceTree"] != preview["sourceTree"]',
                         'prior["signedAppBinarySha256"] != preview["signedAppBinarySha256"]',
                         'prior["runtimeManifestSha256"] != preview["runtimeManifestSha256"]',
                         'prior["applicationStateAfterNormalQuit"] != "notRunning"',
                         'type(prior["testCounts"][key]) is not int', 'type(summary.get(key)) is not int or summary[key] != value',
                         'json.loads(summary_bytes, object_pairs_hook=unique)',
                         'set(budget) != set(expected_budget)', 'type(budget[key]) is not type(value)', '"hardBytes": 1073741824',
                         '"safeFactsSha256": hashlib.sha256(facts_bytes).hexdigest()',
                         'normal-saved-offline-and-empty-recovery-ui-diagnostics-only'):
            self.assertIn(fragment, saved_result_source, fragment)
        self.assertIs(ast.literal_eval(fields['cleanExitStatus']), None)
        self.assertEqual(ast.literal_eval(fields['allWorkerFinality']), 'not-established-by-XCTest-UI-state')
        self.assertEqual(ast.literal_eval(fields['applicationStateAfterBothNormalQuits']), 'notRunning')
        for field in ('independentOwnerResourceProof', 'fullDoctorExecuted', 'mutationRecoveryExecuted', 'zeroCommandEvidence',
                      'networkIsolationEstablished', 'releaseReadinessEstablished', 'fullUIQualified', 'distributionQualified', 'productReady'):
            self.assertIs(ast.literal_eval(fields[field]), False, field)
        for field in ('offlinePreflightExecuted', 'projectRecoveryInspectionExecuted'):
            self.assertIs(ast.literal_eval(fields[field]), True, field)
        for leaf in ('saved-checks-test-file-limit.status', 'saved-checks-test-file-budget.status', 'saved-checks-test-file-budget.json',
                     'saved-checks-test.status', 'saved-checks-safe-facts.json', 'saved-checks-summary.status', 'saved-checks-result.json'):
            self.assertEqual(evidence.count('${{ steps.work.outputs.root }}/normal-ui/' + leaf + '\n'), 1)
        for suffix in ('saved-checks-test.log', 'saved-checks-summary.raw.json', 'saved-checks-summary.stderr',
                       'saved-checks-test.xcresult', 'saved-checks-test.tail.txt'):
            self.assertNotIn('/normal-ui/' + suffix, evidence)
        self.assertIn("steps.normal_saved_checks_ui_result.outcome == 'success'", cleanup.split('        run: |', 1)[0])
        self.assertIn('root / "normal-ui/saved-checks-test.xcresult"', cleanup)
        self.assertIn('"saved-checks-test.log", "saved-checks-summary.raw.json", "saved-checks-summary.stderr"', cleanup)


if __name__ == '__main__':
    unittest.main()
