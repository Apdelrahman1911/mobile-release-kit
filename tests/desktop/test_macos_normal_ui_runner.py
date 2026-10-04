"""Inert DATA/source regressions, NOT XCTest, native API or app evidence."""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import plistlib
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).absolute().parents[2]
SPEC = importlib.util.spec_from_file_location("mrk_normal_ui_runner_data", ROOT / "desktop/tools/macos_normal_ui_runner.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
SWIFT = ROOT / "desktop/native/macos-normal-ui/MRKNormalAppUITests/NormalAppUITests.swift"


def target():
    return {"BlueprintName": MODULE.TARGET, "IsUITestBundle": True,
        "TestHostPath": "__TESTROOT__/" + MODULE.RUNNER,
        "TestBundlePath": "__TESTHOST__/Contents/PlugIns/MRKNormalAppUITests.xctest",
        "TestHostBundleIdentifier": "dev.mobile-release-kit.normal-ui-tests.xctrunner"}


def manifest():
    return plistlib.dumps({"__xctestrun_metadata__": {"FormatVersion": 2},
        "TestConfigurations": [{"IsEnabled": True, "TestTargets": [target()]}]})


def result_data():
    selected = "-[MRKNormalAppUITests.NormalAppUITests testPackagedEntryLaunchCancelAndQuit]"
    output = "\n".join(("Test Case '" + selected + "' started.", MODULE.ORIGINAL_MARKER,
        MODULE.ENTRY_MARKER, MODULE.UI_MARKER, "Test Case '" + selected + "' passed (1.000 seconds).", "")).encode()
    summary = json.dumps({"totalTestCount": 1, "passedTests": 1, "failedTests": 0,
                          "skippedTests": 0, "expectedFailures": 0}).encode()
    tree = json.dumps({"testNodes": [{"name": MODULE.TARGET, "nodeType": "Unit test bundle", "children": [
        {"name": "NormalAppUITests", "nodeType": "Test Suite", "children": [
            {"name": "testPackagedEntryLaunchCancelAndQuit()", "nodeType": "Test Case",
             "nodeIdentifier": "NormalAppUITests/testPackagedEntryLaunchCancelAndQuit()", "result": "Passed"}]}]}]}).encode()
    return output, summary, tree


def normal_arguments(result="test.xcresult"):
    methods, allowance, _ = MODULE.NORMAL_SELECTIONS[result]
    root = Path("/Users/runner/work/_temp/mrk-macos-installed.ABCDef12/normal-ui")
    return ["test-without-building", "-project", MODULE.PROJECT, "-scheme", "MRKNormalAppUI",
        "-configuration", "Debug", "-destination", "platform=macOS,arch=arm64",
        "-destination-timeout", "15", "-derivedDataPath", str(root / "DerivedData"),
        "-resultBundlePath", str(root / result), *["-only-testing:" + MODULE.CLASS + method for method in methods],
        "-parallel-testing-enabled", "NO", "-test-timeouts-enabled", "YES",
        "-default-test-execution-time-allowance", str(allowance),
        "-maximum-test-execution-time-allowance", str(allowance), "-disableAutomaticPackageResolution"]


class RunnerAdmissionDataTests(unittest.TestCase):
    def test_only_strict_absent_or_false_entitlement_is_admitted(self):
        self.assertEqual(MODULE.sandbox_entitlement(plistlib.dumps({})), "absent")
        self.assertEqual(MODULE.sandbox_entitlement(plistlib.dumps({
            "com.apple.security.app-sandbox": False, "com.apple.security.get-task-allow": True})), "false")
        for body in (b"", b"not a plist", plistlib.dumps([]), *[
            plistlib.dumps({"com.apple.security.app-sandbox": value}) for value in (True, 0, 1, "false", b"false")]):
            with self.subTest(body=body[:40]), self.assertRaises(MODULE.Refused):
                MODULE.sandbox_entitlement(body)
        duplicate = (b'<?xml version="1.0"?><plist version="1.0"><dict>'
            b'<key>com.apple.security.app-sandbox</key><true/>'
            b'<key>com.apple.security.app-sandbox</key><false/></dict></plist>')
        with self.assertRaisesRegex(MODULE.Refused, "duplicate-plist-key"):
            MODULE.sandbox_entitlement(duplicate)

    def test_ui_target_requests_boolean_false_sandbox_at_build_time(self):
        # Source intent only; the actual generated signature is admitted separately.
        project_root = ROOT / "desktop/native/macos-normal-ui"
        project = (project_root / "MRKNormalAppUI.xcodeproj/project.pbxproj").read_text(encoding="utf-8")
        target_marker = "\t\tA10000000000000000000008 = {\n"
        self.assertEqual(project.count("isa = PBXNativeTarget;"), 1)
        self.assertEqual(project.count(target_marker), 1)
        target = project.split(target_marker, 1)[1].split("\n\t\t};", 1)[0]
        self.assertIn("name = MRKNormalAppUITests;", target)
        self.assertIn('productType = "com.apple.product-type.bundle.ui-testing";', target)
        self.assertIn("buildConfigurationList = A1000000000000000000000E;", target)
        self.assertIn("A1000000000000000000000E = {isa = XCConfigurationList; "
                      "buildConfigurations = (A1000000000000000000000F);", project)
        config_marker = "\t\tA1000000000000000000000F = {\n"
        self.assertEqual(project.count(config_marker), 1)
        config = project.split(config_marker, 1)[1].split("\n\t\t};", 1)[0]
        self.assertEqual(project.count("CODE_SIGN_ENTITLEMENTS"), 1)
        self.assertIn("CODE_SIGN_ENTITLEMENTS = MRKNormalAppUITests.entitlements;", config)
        for preserved in ('CODE_SIGN_IDENTITY = "-";', "CODE_SIGN_STYLE = Manual;",
                          'DEVELOPMENT_TEAM = "";', "ENABLE_APP_SANDBOX = NO;",
                          "ENABLE_HARDENED_RUNTIME = NO;", "name = Debug;"):
            self.assertIn(preserved, config)
        body = (project_root / "MRKNormalAppUITests.entitlements").read_bytes()
        value = MODULE.plist(body)  # Strict dictionary/duplicate-key parsing.
        self.assertEqual(set(value), {"com.apple.security.app-sandbox"})
        self.assertIs(value["com.apple.security.app-sandbox"], False)

    def test_manifest_is_exact_one_generated_runner_not_an_app_target(self):
        products = Path("/fresh/DerivedData/Build/Products")
        self.assertEqual(MODULE.target_from_xctestrun(manifest(), products)["BlueprintName"], MODULE.TARGET)
        for change in (
            {"TestHostPath": "__TESTROOT__/Debug/Other.app"},
            {"TestBundlePath": "__TESTROOT__/../Elsewhere.xctest"},
            {"UITargetAppPath": "/Library/Application Support/MobileReleaseKit/Mobile Release Kit.app"},
            {"TestHostBundleIdentifier": "dev.mobile-release-kit.desktop"},
            {"IsUITestBundle": False}):
            value = plistlib.loads(manifest())
            value["TestConfigurations"][0]["TestTargets"][0].update(change)
            with self.subTest(change=change), self.assertRaises(MODULE.Refused):
                MODULE.target_from_xctestrun(plistlib.dumps(value), products)
        for key in ("TestTargets", "configuration"):
            value = plistlib.loads(manifest())
            if key == "TestTargets":
                value["TestConfigurations"][0]["TestTargets"].append(target())
            else:
                value["TestConfigurations"].append(value["TestConfigurations"][0])
            with self.assertRaises(MODULE.Refused):
                MODULE.target_from_xctestrun(plistlib.dumps(value), products)

    def test_normal_cli_preserves_every_old_selection_and_rejects_reuse_switch(self):
        for result in MODULE.NORMAL_SELECTIONS:
            derived, selected, methods, allowance, timeout = MODULE.normal_cli_arguments(normal_arguments(result))
            self.assertEqual(selected.name, result)
            self.assertEqual(derived.name, "DerivedData")
            self.assertNotIn(MODULE.PACKAGED_METHOD, methods)
            self.assertIn(allowance, (60, 300))
            self.assertEqual(timeout, MODULE.NORMAL_SELECTIONS[result][2])
        for mutate in (
            lambda args: args + ["-retry-tests-on-failure"],
            lambda args: [value.replace("testLaunchCancelAndQuit", "testPackagedEntryLaunchCancelAndQuit") for value in args],
            lambda args: [value.replace("Debug", "Release") for value in args],
            lambda args: [value.replace("platform=macOS,arch=arm64", "platform=macOS") for value in args]):
            with self.assertRaises(MODULE.Refused):
                MODULE.normal_cli_arguments(mutate(normal_arguments()))
        for allowance in (True, 300, 600):
            with self.assertRaises(MODULE.Refused):
                MODULE.xcode_test_arguments("/fixed.xctestrun", "/fresh.xcresult", (MODULE.PACKAGED_METHOD,), allowance)

    def test_closed_result_requires_every_original_terminal_fact(self):
        original = result_data()
        accepted = MODULE.packaged_ui_result(*original)
        self.assertIsNone(accepted["cleanExitStatus"])
        for key in ("sameBuildQualified", "fullUIQualified", "fullM2Qualified", "productReady"):
            self.assertIs(accepted[key], False)
        output = original[0]
        for body in (
            output.replace(b"completion=1", b"completion=2"),
            output.replace(b"body=1", b"body=0"),
            output.replace(b"handoff=1", b"handoff=2"),
            output.replace(b"payloadIdentity=1", b"payloadIdentity=0"),
            output.replace(b"originalTerminated=1", b"originalTerminated=0"),
            output.replace(b"gateFree=1", b"gateFree=0"),
            output.replace(b"gateClosed=1", b"gateClosed=0"),
            output.replace(b"caseDeadlineMet=1", b"caseDeadlineMet=0"),
            output.replace(b"failureCleanup=0", b"failureCleanup=1"),
            output + MODULE.ORIGINAL_MARKER.encode() + b"\n",
            output + b"MRK_MACOS_UI_FAILURE_CLEANUP=normalRequested=true\n",
            output.replace(MODULE.ORIGINAL_MARKER.encode() + b"\n", b"")):
            with self.subTest(body=body[-60:]), self.assertRaises(MODULE.Refused):
                MODULE.packaged_ui_result(body, original[1], original[2])

    def test_count_selection_and_retry_cannot_be_repaired_by_a_marker(self):
        output, summary, tree = result_data()
        for key, value in (("totalTestCount", 0), ("passedTests", True), ("failedTests", 1),
                           ("skippedTests", 1), ("expectedFailures", 1)):
            altered = json.loads(summary); altered[key] = value
            with self.assertRaises(MODULE.Refused):
                MODULE.packaged_ui_result(output, json.dumps(altered).encode(), tree)
        for selected in (tree.replace(b"testPackagedEntryLaunchCancelAndQuit", b"testLaunchCancelAndQuit"),
                         tree.replace(b'"Passed"', b'"Skipped"'), b'{"testNodes":[]}'):
            with self.assertRaises(MODULE.Refused):
                MODULE.packaged_ui_result(output, summary, selected)
        with self.assertRaises(MODULE.Refused):
            MODULE.packaged_ui_result(output.splitlines(keepends=True)[0] + output, summary, tree)
        with self.assertRaises(MODULE.Refused):
            MODULE.packaged_ui_result(output, summary[:-1] + b',"passedTests":1}', tree)

    def test_source_has_one_fixed_request_and_only_original_cleanup_receivers(self):
        source = SWIFT.read_text()
        self.assertEqual(source.count("NSWorkspace.shared.openApplication(at: Self.outerURL"), 1)
        self.assertEqual(source.count("let app = try launchOrdinaryApplication()"), 2)
        self.assertEqual(source.count("original.terminate()"), 1)
        self.assertEqual(source.count("original.forceTerminate()"), 1)
        for forbidden in ("app.launch()", "app.activate()", "app.terminate()", "monitor.launch(",
                          "monitor.activate(", "monitor.terminate(", "runningApplications(",
                          "runningApplications(withBundleIdentifier:", "processIdentifier", "kill(", "Process()"):
            self.assertNotIn(forbidden, source)
        for required in ("configuration.createsNewApplicationInstance = true",
                         "configuration.allowsRunningApplicationSubstitution = false",
                         "configuration.arguments = []", "private let lock = NSLock()",
                         "entries = min(2, entries + 1)", "bodies = min(2, bodies + 1)",
                         "handoffs = min(2, handoffs + 1)", "late original is cleanup-only",
                         "if ticket == 1", "if original == nil { original = value.first }",
                         "DispatchQueue.main.async { self.handoff() }"):
            self.assertIn(required, source)
        launch = source.split("private func launchOrdinaryApplication()", 1)[1].split("private func completeNormalQuit(", 1)[0]
        for earlier, later in (("outer.state == .notRunning && monitor.state == .notRunning", "entryGateObservation = gate"),
                               ("try gate.probe(busy: false)", "originalLaunch = owner"),
                               ("originalLaunch = owner", "try owner.requestAndAwait()"),
                               ("try owner.requestAndAwait()", "try gate.probe(busy: true)")):
            self.assertLess(launch.index(earlier), launch.index(later))
        self.assertIn("original.bundleURL?.path == Self.payloadURL.path", source)
        self.assertIn('original.bundleIdentifier == "dev.mobile-release-kit.desktop"', source)

    def test_first_callback_custody_survives_reordered_main_handoffs(self):
        source = SWIFT.read_text()
        reply = source.split("private final class LaunchReply:", 1)[1].split(
            "@MainActor private final class OrdinaryLaunch", 1)[0]
        body = reply.split("func body(", 1)[1].split("func snapshot()", 1)[0]
        handoff = source.split("private func handoff()", 1)[1].split(
            "private func callbackHealthy(", 1)[0]
        self.assertIn("if ticket == 1 {\n                first = application", body)
        self.assertLess(body.index("first = application"), body.index("bodies = min("))
        self.assertIn("first = application // Retain before ANY fallible validation.\n                error = failed", body)
        healthy = source.split("private func callbackHealthy(", 1)[1].split("func healthy()", 1)[0]
        self.assertIn("!value.error, original != nil", healthy)
        self.assertIn("guard let launchEnd, !workClosed else", handoff)
        self.assertEqual(handoff.count("if original == nil { original = value.first }"), 1)
        self.assertLess(handoff.index("original = value.first"), handoff.index("try callbackHealthy()"))
        self.assertNotIn("if handoffs == 1 { original", source)
        self.assertIn('workClosed = true\n                _ = clock.fail("launch completion refused")', handoff)

        # Deterministic inert schedule oracle bound to the literal custody
        # statements above. This does NOT execute Swift, a callback thread,
        # AppKit, or a native cleanup receiver and is not native UI evidence.
        def fresh_state():
            return dict(entries=0, bodies=0, handoffs=0, first=None, error=False,
                        original=None, failed=False, work_closed=False)
        state = fresh_state()
        def enter():
            state["entries"] = min(2, state["entries"] + 1)
            return state["entries"]
        def complete(ticket, value, error=False):
            if ticket == 1:
                state["first"] = value
                state["error"] = error
            state["bodies"] = min(2, state["bodies"] + 1)
        def handoff_only():
            state["handoffs"] = min(2, state["handoffs"] + 1)
            if state["original"] is None:
                state["original"] = state["first"]
            duplicate = any(state[key] > 1 for key in ("entries", "bodies", "handoffs"))
            bad_first = state["handoffs"] == 1 and (
                state["entries"] != 1 or state["bodies"] != 1 or
                state["error"] or state["original"] is None)
            if state["work_closed"] or duplicate or bad_first:
                state["failed"] = state["work_closed"] = True  # Sticky.

        first, second = object(), object()
        ticket1 = enter()               # First callback pauses before its body.
        ticket2 = enter()
        self.assertEqual((ticket1, ticket2), (1, 2))
        complete(ticket2, second)
        handoff_only()                  # Second callback reaches main first.
        self.assertTrue(state["failed"])
        self.assertIsNone(state["first"])
        self.assertIsNone(state["original"])
        complete(ticket1, first)
        handoff_only()                  # Late ticket1 restores custody, NOT work.
        self.assertIs(state["first"], first)
        self.assertIs(state["original"], first)
        self.assertTrue(state["failed"])
        complete(ticket2, second)
        handoff_only()
        self.assertIs(state["original"], first)
        self.assertIsNot(state["original"], second)
        self.assertTrue(state["failed"])
        self.assertEqual(tuple(state[key] for key in ("entries", "bodies", "handoffs")), (2, 2, 2))
        cleanup_receivers = [state["original"]]  # Record identity only, no call.
        self.assertEqual(cleanup_receivers, [first])
        self.assertTrue(state["work_closed"])

        # First nil may NEVER be repaired by a nonnil second callback. Exercise
        # both normal and reversed main/body arrival; no real receiver is used.
        for reordered in (False, True):
            with self.subTest(first="nil", reordered=reordered):
                state = fresh_state()
                ticket1 = enter()
                if reordered:
                    ticket2 = enter()
                    complete(ticket2, second)
                    handoff_only()
                    self.assertIsNone(state["original"])
                complete(ticket1, None)
                handoff_only()
                self.assertIsNone(state["original"])
                self.assertTrue(state["failed"])
                self.assertTrue(state["work_closed"])
                if not reordered:
                    ticket2 = enter()
                complete(ticket2, second)
                handoff_only()
                self.assertIsNone(state["first"])
                self.assertIsNone(state["original"])
                self.assertFalse(state["error"])
                self.assertTrue(state["failed"])
                self.assertTrue(state["work_closed"])
                cleanup_receivers = [] if state["original"] is None else [state["original"]]
                self.assertEqual(cleanup_receivers, [])

        # Error+nonnull first is retained for cleanup ONLY. A later callback
        # without error cannot clear first's error, reopen work or replace it.
        for reordered in (False, True):
            with self.subTest(first="error-and-original", reordered=reordered):
                state = fresh_state()
                ticket1 = enter()
                if reordered:
                    ticket2 = enter()
                    complete(ticket2, second)
                    handoff_only()
                    self.assertIsNone(state["original"])
                complete(ticket1, first, error=True)
                handoff_only()
                self.assertIs(state["original"], first)
                self.assertTrue(state["error"])
                self.assertTrue(state["failed"])
                self.assertTrue(state["work_closed"])
                if not reordered:
                    ticket2 = enter()
                complete(ticket2, second, error=False)
                handoff_only()
                self.assertIs(state["first"], first)
                self.assertIs(state["original"], first)
                self.assertIsNot(state["original"], second)
                self.assertTrue(state["error"])
                self.assertTrue(state["failed"])
                self.assertTrue(state["work_closed"])
                cleanup_receivers = [state["original"]]  # Identity only, no call.
                self.assertEqual(cleanup_receivers, [first])

    def test_source_packaged_require_site_is_forwarded_and_first_failure_only(self):
        source = SWIFT.read_text()
        self.assertEqual(source.count("line: UInt = #line"), 3)
        self.assertIn("private enum RequireCheck: String { case condition, singleton, actionable }", source)
        self.assertEqual(source.count("packagedRequireDiagnosticActive = true"), 1)
        self.assertEqual(source.count("packagedRequireDiagnosticActive = false"), 2)  # Initial + scoped defer.
        self.assertEqual(source.count("packagedRequireDiagnosticEmitted = false"), 1)
        self.assertEqual(source.count("packagedRequireDiagnosticEmitted = true"), 1)
        selected = source.split("func testPackagedEntryLaunchCancelAndQuit() throws {", 1)[1].split(
            "\n    @MainActor private func launchCancelAndQuit", 1)[0]
        self.assertIn("try launchCancelAndQuit(profile: .packagedEntry)", selected)
        self.assertNotIn("packagedRequireDiagnosticActive", selected)
        shared = source.split("@MainActor private func launchCancelAndQuit(profile: SourceProfile) throws {", 1)[1]
        order = ("packagedRequireDiagnosticActive = true", "defer { packagedRequireDiagnosticActive = false }",
                 "try beginCase(seconds: 60)", "try admittedJourneyApplication(profile: profile)")
        self.assertEqual([shared.index(item) for item in order], sorted(shared.index(item) for item in order))
        self.assertEqual(source.count("try launchCancelAndQuit(profile: .sameBuild)"), 1)
        self.assertEqual(source.count("try launchCancelAndQuit(profile: .packagedEntry)"), 1)
        self.assertEqual(MODULE.NORMAL_SELECTIONS["test.xcresult"][0], ("testLaunchCancelAndQuit",))
        self.assertFalse(any("testPackagedEntryLaunchCancelAndQuit" in methods
                             for methods, _, _ in MODULE.NORMAL_SELECTIONS.values()))
        require = source.split("private func require(", 1)[1].split("private func unique(", 1)[0]
        false_guard = require.split("guard value else {", 1)[1].split("\n        try checkOriginalOwners()", 1)[0]
        ordered = ("let originalFailureAbsent = caseClock?.firstFailure == nil",
                   "let refusal = caseClock?.fail(reason) ?? Refusal.condition(reason)",
                   "if packagedRequireDiagnosticActive && originalFailureAbsent && !packagedRequireDiagnosticEmitted",
                   "&& line >= 1 && line <= 65535", "packagedRequireDiagnosticEmitted = true",
                   'print("MRK_MACOS_PACKAGED_REQUIRE_FAILURE=v1;line=\\(line);check=\\(check.rawValue)")',
                   "throw refusal")
        positions = [false_guard.index(item) for item in ordered]
        self.assertEqual(positions, sorted(positions))
        self.assertEqual(source.count("MRK_MACOS_PACKAGED_REQUIRE_FAILURE="), 1)
        self.assertEqual(require.count("caseClock?.fail(reason) ?? Refusal.condition(reason)"), 1)
        for forbidden in ("XCTFail", "recordIssue", "waitFor", "remaining(", "systemUptime", "owner.", "checkOriginalOwners(", "catch", "try?"):
            self.assertNotIn(forbidden, false_guard)
        self.assertEqual(require.count("try checkOriginalOwners()"), 1)
        # A false guard still throws; true values retain BOTH original gates.
        self.assertIn("throw refusal\n        }\n        try checkOriginalOwners()\n"
                      "        if let clock = caseClock { _ = try clock.remaining(1, before: journeyDeadline) }", require)
        unique = source.split("private func unique(", 1)[1].split("private func click(", 1)[0]
        click = source.split("private func click(", 1)[1].split("private func dashboard(", 1)[0]
        self.assertIn("try require(query.count == 1, reason, line: line, check: .singleton)", unique)
        self.assertIn("return query.element(boundBy: 0)", unique)
        self.assertIn("let element = try unique(query, reason, line: line)", click)
        self.assertIn("try require(element.isEnabled && element.isHittable, reason, line: line, check: .actionable)", click)
        self.assertLess(click.index("try unique(query, reason, line: line)"), click.index("try require("))
        self.assertLess(click.index("try require("), click.index("element.click()"))
        clock = source.split("func fail(_ reason: String) -> Refusal {", 1)[1].split("private func now()", 1)[0]
        self.assertIn("if firstFailure == nil { firstFailure = reason }\n            return .condition(firstFailure!)", clock)

    def test_source_uses_nonrenewable_case_clock_and_all_terminal_gates(self):
        source = SWIFT.read_text()
        custody = source.split("    private final class GateObservation {", 1)[0]
        self.assertEqual(source.count("try beginCase(seconds: 60)"), 1)
        self.assertEqual(source.count("try beginCase(seconds: 300)"), 5)
        self.assertEqual(source.count("try completeNormalQuit(app)"), 6)
        self.assertEqual(source.count("try completeNormalQuit(restartedApp)"), 1)
        self.assertEqual(source.count("try acceptFinalScenario()"), 5)
        self.assertEqual(source.count("try acceptPersistenceRestart()"), 1)
        self.assertEqual(source.count("normalQuitObserved = true"), 1)
        for required in ("let deadline: TimeInterval", "value.isFinite, value >= last",
                         "if firstFailure == nil", "caseClock == nil && journeyDeadline == nil",
                         "journeyDeadline = clock.deadline", "min(deadline, start + maximum)",
                         "min(deadline, end ?? deadline) - (try now())", "return min(maximum, left)",
                         "try clock.end(within: 15)", "clock.progress(until:",
                         "if cleanupEnd == nil", "clock.end(within: 5, cleanup: true)",
                         "try clock.remaining(10, before: end)", "SAME ten seconds"):
            self.assertTrue(required in source, "missing case-clock gate: " + required)
        for forbidden in ("journeyDeadline = ProcessInfo.processInfo.systemUptime +",
                          "else { return requested }", "timeout: 5)", "timeout: 10)"):
            section = custody if forbidden == "timeout: 10)" else source
            self.assertFalse(forbidden in section, "unbounded case-clock token: " + forbidden)
        # Literal ten seconds is a maximum only on the clamped press helper route.
        for line in source.splitlines():
            if "timeout: 10)" in line:
                self.assertTrue(line.lstrip().startswith("try press("), "raw ten-second wait outside custody")
        for name, route in (
            ("press", ("try waitElement(", "timeout: timeout")),
            ("waitElement", ("XCTWaiter.wait(for: [expected], timeout: try remaining(timeout))",)),
            ("remaining", ("return try clock.remaining(requested, before: deadline)",)),
        ):
            helper = source.split("private func " + name + "(", 1)[1].split("\n    @MainActor ", 1)[0]
            for required in route:
                self.assertTrue(required in helper, "missing original-clock clamp in " + name)
        terminal = source.split("private func completeNormalQuit(", 1)[1].split("private func acceptFinalScenario()", 1)[0]
        self.assertLess(terminal.index("owner.observeNormalTermination"), terminal.index("gate.probe(busy: false)"))
        self.assertLess(terminal.index("gate.closeOriginal()"), terminal.index("normalQuitObserved = true"))
        teardown = source.split("override func tearDown() async throws", 1)[1]
        for required in ("owner.tearDown(normalQuit: normalQuitObserved)", "entryGateObservation?.closeOriginal()",
                         "fixture.closeOriginals()", "super.tearDown()", "if cleanupFailure == nil"):
            self.assertTrue(required in teardown, "missing terminal cleanup gate: " + required)

    def test_reuse_profile_cannot_relax_the_existing_same_build_cases(self):
        source = SWIFT.read_text()
        self.assertEqual(source.count("try launchCancelAndQuit(profile: .packagedEntry)"), 1)
        self.assertIn("try launchCancelAndQuit(profile: .sameBuild)", source)
        self.assertIn("private func admittedJourneyApplication(profile: SourceProfile = .sameBuild)", source)
        profile = source.split("case .sameBuild:", 1)[1].split("case .packagedEntry:", 1)[0]
        self.assertIn("applicationSource == harnessSource", profile)
        basic = source.split("private func launchCancelAndQuit(profile:", 1)[1].split("private struct FixtureSpec", 1)[0]
        for required in ("try beginCase(seconds: 60)", "try admittedJourneyApplication(profile: profile)",
                         'title: "Choose a mobile project folder"', '"normal Quit Cancel is unavailable"',
                         '"post-Cancel navigation is unavailable"', '"normal affirmative Quit is unavailable"'):
            self.assertIn(required, basic)
        self.assertLess(basic.index("try beginCase(seconds: 60)"), basic.index("try admittedJourneyApplication"))


@unittest.skipUnless(hasattr(os, "O_NOFOLLOW") and hasattr(os, "pread"), "POSIX inert original-file DATA")
class GeneratedProductOriginalTests(unittest.TestCase):
    def fixture(self, root):
        derived = Path(root) / "DerivedData"
        products = derived / "Build/Products"
        bodies = {MODULE.RUNNER_EXECUTABLE: b"INERT RUNNER DATA; NEVER EXECUTED\n",
            MODULE.TEST_EXECUTABLE: b"INERT TEST DATA; NEVER EXECUTED\n",
            MODULE.RUNNER_INFO: plistlib.dumps({"CFBundleIdentifier": "dev.mobile-release-kit.normal-ui-tests.xctrunner",
                                               "CFBundleExecutable": "MRKNormalAppUITests-Runner"}),
            MODULE.TEST_INFO: plistlib.dumps({"CFBundleIdentifier": "dev.mobile-release-kit.normal-ui-tests",
                                             "CFBundleExecutable": "MRKNormalAppUITests"}),
            "MRKNormalAppUI_macosx26.0-arm64.xctestrun": manifest()}
        for name, body in bodies.items():
            path = products / name
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            path.write_bytes(body)
            path.chmod(0o700 if name in (MODULE.RUNNER_EXECUTABLE, MODULE.TEST_EXECUTABLE) else 0o600)
        return derived, products

    def test_retained_product_originals_close_and_mutations_fail(self):
        with tempfile.TemporaryDirectory(prefix="mrk-ui-inert-products-") as root:
            derived, products = self.fixture(root)
            with MODULE.RunnerProducts(derived) as originals:
                self.assertEqual(set(originals.held), originals.keep)
                originals.check()
                (products / MODULE.RUNNER_EXECUTABLE).write_bytes(b"CHANGED INERT DATA\n")
                with self.assertRaisesRegex(MODULE.Refused, "pre-post"):
                    originals.check()
            self.assertEqual(originals.held, {})
            self.assertIsNone(originals.fd)
            self.assertTrue(originals.closed)

    def test_sandbox_refusal_never_reaches_the_test_invocation(self):
        with tempfile.TemporaryDirectory(prefix="mrk-ui-inert-products-") as root:
            derived, _ = self.fixture(root)
            calls = []
            def call(role, argv, timeout):
                calls.append(role)
                body = plistlib.dumps({"com.apple.security.app-sandbox": True}) if role.endswith("entitlements") else b""
                return subprocess.CompletedProcess(argv, 0, body, b"")
            with self.assertRaisesRegex(MODULE.Refused, "sandboxed-or-unknown"):
                MODULE.run_admitted_test(call, derived, Path(root) / "test.xcresult",
                                         (MODULE.PACKAGED_METHOD,), 60, 180)
            self.assertEqual(calls, ["verify-generated-runner", "generated-runner-entitlements"])

    def test_external_or_cyclic_build_product_links_refuse_before_native_commands(self):
        for target in ("/tmp", "../../outside", "link"):
            with self.subTest(target=target), tempfile.TemporaryDirectory(prefix="mrk-ui-inert-products-") as root:
                derived, products = self.fixture(root)
                os.symlink(target, products / "Debug/link")
                with self.assertRaises(MODULE.Refused):
                    with MODULE.RunnerProducts(derived):
                        self.fail("bad product link was admitted")

    def test_unknown_close_is_consuming_and_other_originals_still_close(self):
        with tempfile.TemporaryDirectory(prefix="mrk-ui-inert-products-") as root:
            derived, _ = self.fixture(root)
            originals = MODULE.RunnerProducts(derived).__enter__()
            selected = next(iter(originals.held.values()))
            expected = set(originals.held.values()) | {originals.fd}
            actual_close = os.close
            closed = []
            def close(fd):
                closed.append(fd)
                actual_close(fd)
                if fd == selected:
                    raise OSError("synthetic unknown close, never retried")
            with patch.object(MODULE.os, "close", close):
                with self.assertRaises(OSError):
                    originals.close()
                originals.close()
            self.assertEqual(set(closed), expected)
            self.assertEqual(len(closed), len(expected))
            self.assertEqual(originals.held, {})
            self.assertIsNone(originals.fd)


if __name__ == "__main__":
    unittest.main()
