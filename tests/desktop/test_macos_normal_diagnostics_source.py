"""SOURCE-only bindings for one ordinary Mac build-tool diagnostics UI journey.

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
ORIGINAL_SWIFT_SHA256 = "376817b2c3617e8324bff0dbdc9929f63ed5ed395286e6d919f23de291c0f631"
DIAGNOSTICS_INSERTION_SHA256 = "7b5aeb18210ac3862362e59602adb024040b7232dee12a64e98a534ffc42b44a"
ROSTER_SHA256 = "293426d49f6bb226563ea325527858b894aa98ac2e72dea6b70875157cfd58e4"
BLOCK_PINS = {'normal_ui_result': 'cad0ea48888071634eac7834632e4057e71ae482f93814974c8d5c6501629657',
 'normal_project_ui_test': '161d12ffaada989d866466ec297dd17ed64de10ac6b84bc9cc1973e76d7d07fb',
 'normal_project_ui_result': '20cd5b0114ff6e2cc725e0324d62dccefd4896426ce4eff67baeea935290013d',
 'normal_persistence_ui_test': '01bded1ba9c28bff4d9ce7a224665cc8e2a1bcb1327a2f097da4bde50fec390e',
 'normal_persistence_ui_result': 'a90cb1adc4c4e39109b73c9cedb531e46e55e910dca1ec962f44452674b27eb9',
 'normal_diagnostics_ui_test': '8ee2d21556928969d8fd12b5e92d4a5e7a7321df70ce224e122e76e7a0138453',
 'normal_diagnostics_ui_result': '5987afe38eaac0e72dce32aed908f1276b3fe7572c831e43935f09f24896096f'}
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
    def test_normal_diagnostics_observes_original_complete_report_and_settled_projection(self):
        swift = (ROOT / SWIFT).read_text()
        start = "    // One ordinary current diagnostics run, not full doctor or project-code execution.\n"
        end = "    override func tearDown() async throws {\n"
        self.assertEqual(swift.count(start), 1)
        self.assertEqual(swift.count(end), 1)
        insertion = start + swift.split(start, 1)[1].split(end, 1)[0]
        self.assertEqual(digest(insertion.encode()), DIAGNOSTICS_INSERTION_SHA256)
        # Account admission, fixture, every earlier journey and teardown are exact
        # existing source, not relaxed as a side effect of this appended journey.
        self.assertEqual(digest(swift.replace(insertion, "", 1).encode()), ORIGINAL_SWIFT_SHA256)
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
            'let sheet = try quitSheet(app, window)', 'normalQuitObserved = true',
            'try fixture.closeOriginals()', 'ownedFixture = nil', SCOPE,
        ):
            self.assertIn(fragment, insertion, fragment)
        self.assertEqual(insertion.count('start.click()'), 1)
        self.assertEqual(insertion.count('matching(identifier: "Check build tools")'), 1)
        self.assertEqual(insertion.count('executionTimeAllowance = 300'), 1)
        self.assertEqual(insertion.count('journeyDeadline = ProcessInfo.processInfo.systemUptime + 300'), 1)
        self.assertEqual(insertion.count('journeyDeadline = min(wholeDeadline, ProcessInfo.processInfo.systemUptime + 15)'), 1)
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
                 'normal_diagnostics_ui_test', 'normal_diagnostics_ui_result']
        begin = ids.index(order[0])
        self.assertEqual(ids[begin:begin + len(order)], order)
        for ident, pin in BLOCK_PINS.items():
            self.assertEqual(ids.count(ident), 1)
            self.assertEqual(digest(blocks[ident].encode()), pin, ident)
        test = blocks['normal_diagnostics_ui_test']
        result = blocks['normal_diagnostics_ui_result']
        self.assertIn("steps.normal_persistence_ui_result.outcome == 'success'", test)
        self.assertIn("steps.normal_diagnostics_ui_test.outcome == 'success'", result)
        self.assertEqual(test.count('/usr/bin/xcodebuild test-without-building'), 1)
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
        self.assertLess(test.index('[[ "$file_budget_status" == 0 ]]'), test.index('/usr/bin/xcodebuild test-without-building'))
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
        self.assertEqual(len(names), 81)
        self.assertEqual(len(set(names)), 81)
        self.assertEqual(selected_digest(names[:79]), '81ca0c9325763f3aaf2a181e521d7b6adde06b7c0321eecacfc2b93a78c3c051')
        self.assertEqual(names[79:], SOURCE_METHODS)
        self.assertEqual(selected_digest(names), ROSTER_SHA256)
        self.assertEqual(data.count(ROSTER_SHA256), 2)
        sources = ast.literal_eval(re.search(r'          source_names = (\(\n.*?\n          \))\n', data, re.S)[1])
        self.assertEqual(len(sources), len(set(sources)))
        self.assertTrue(set(SOURCE_REFS).issubset(sources))
        for fragment in ('len(names) != 81 or len(set(names)) != 81', 'suite.countTestCases() != 81',
                         'facts["testsRun"] == 81', 'counts.get("testsRun") != 81', '"pythonExpectedCount": 81',
                         '"githubActionCount": 22, "normalDiagnosticsSourceCount": 2',
                         '"test_macos_normal_diagnostics_source") or not method.startswith("test_")'):
            self.assertIn(fragment, data, fragment)


if __name__ == '__main__':
    unittest.main()
