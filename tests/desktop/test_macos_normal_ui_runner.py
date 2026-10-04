"""Inert DATA/source regressions, NOT XCTest, native API or app evidence."""
from __future__ import annotations

import importlib.util
import dataclasses
import hashlib
import io
import json
import os
from pathlib import Path
import plistlib
import re
import stat
import subprocess
import tempfile
import sys
from contextlib import ExitStack
from types import SimpleNamespace
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
        self.assertEqual(MODULE.LOADER_SHA,
                         hashlib.sha256((ROOT / "desktop/tools/macos_aqua_qualification.py").read_bytes()).hexdigest())
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
                   "if let (sample, waiter) = dashboard, (1...4).contains(sample.ordinal), waiter != .completed",
                   "MRK_MACOS_PACKAGED_DASHBOARD_FAILURE=v1;", "throw refusal")
        positions = [false_guard.index(item) for item in ordered]
        self.assertEqual(positions, sorted(positions))
        self.assertEqual(source.count("MRK_MACOS_PACKAGED_REQUIRE_FAILURE="), 1)
        self.assertEqual(require.count("caseClock?.fail(reason) ?? Refusal.condition(reason)"), 1)
        for forbidden in ("XCTFail", "recordIssue", "waitFor", "remaining(", "systemUptime", "owner.", "checkOriginalOwners(",
                          "catch", "try?", "isEnabled", "isHittable", "renderer.", "firstMatch", "XCUIElement"):
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
        self.assertEqual(source.count("MRK_MACOS_PACKAGED_DASHBOARD_FAILURE="), 1)
        self.assertIn("dashboard: (DashboardSnapshot, DashboardWaiter)? = nil", require)
        self.assertIn(";sample=pre-wait;nonAtomic=1", false_guard)
        snapshot_type = source.split("private struct DashboardSnapshot {", 1)[1].split("\n    }", 1)[0]
        self.assertEqual(snapshot_type.count("let "), 4)
        self.assertNotIn("var ", snapshot_type)
        dashboard = source.split("private func dashboard(", 1)[1].split("private func quitSheet(", 1)[0]
        self.assertIn("diagnosticOrdinal: UInt8? = nil", dashboard)
        sample = dashboard.split("let snapshot: DashboardSnapshot?", 1)[1].split("        let ready =", 1)[0]
        order = ("if packagedRequireDiagnosticActive, let ordinal = diagnosticOrdinal, (1...4).contains(ordinal)",
                 "try checkOriginalOwners()", "_ = try remaining(5)",
                 "let enabled = open.isEnabled", "let hittable = open.isHittable",
                 "if !enabled || !hittable {", "for (titles, reason) in reasons")
        self.assertEqual([sample.index(item) for item in order], sorted(sample.index(item) for item in order))
        # Entry, each group, and exit use the original owner/case end; no new wait or lease.
        self.assertEqual(sample.count("try checkOriginalOwners()"), 3)
        self.assertEqual(sample.count("try remaining(5)"), 3)
        self.assertEqual(sample.count("open.isEnabled"), 1)
        self.assertEqual(sample.count("open.isHittable"), 1)
        self.assertNotIn(".firstMatch", sample)
        self.assertEqual(sample.count("let reasons: [([String], DashboardReason)] = ["), 1)
        self.assertEqual(sample.count("                ([\n"), 15)
        self.assertEqual(sample.count("for (titles, reason) in reasons"), 1)
        self.assertEqual(sample.count("renderer.staticTexts."), 1)
        self.assertEqual(sample.count(".count"), 1)
        self.assertEqual(source.count("private enum DashboardReason: String {"), 1)
        self.assertIn("    private enum DashboardReason: String {\n        case loading, notLoaded = \"not-loaded\", bridgeUnavailable = \"bridge-unavailable\"\n        case selectionUnavailable = \"selection-unavailable\", selectionInProgress = \"selection-in-progress\"\n        case shuttingDown = \"shutting-down\"\n        case ownerOfflinePreflight = \"owner-offline-preflight\", ownerAndroidBuild = \"owner-android-build\"\n        case ownerIOSArchive = \"owner-ios-archive\", ownerProjectRecovery = \"owner-project-recovery\"\n        case ownerGitHubPreflight = \"owner-github-preflight\", ownerGitHubRelease = \"owner-github-release\"\n        case ownerProjectPath = \"owner-project-path\", ownerSavedVersionEdit = \"owner-saved-version-edit\"\n        case ownerMetadataImages = \"owner-metadata-images\"\n        case otherOrUnobserved = \"other-or-unobserved\", ambiguous\n    }\n", source)
        groups = (
            ("loading", "loading", (
                "Application capabilities are being loaded.",
            )),
            ("notLoaded", "not-loaded", (
                "Application capabilities have not been loaded.",
            )),
            ("bridgeUnavailable", "bridge-unavailable", (
                "The native desktop bridge is unavailable.",
            )),
            ("selectionUnavailable", "selection-unavailable", (
                "Project selection is not available in the current desktop runtime profile.",
            )),
            ("selectionInProgress", "selection-in-progress", (
                "Finish the original project selection first.",
            )),
            ("shuttingDown", "shutting-down", (
                "The application is shutting down.",
            )),
            ("ownerOfflinePreflight", "owner-offline-preflight", (
                "Offline-check ownership or finality is unverified. Keep the original status; conflicting work is disabled.",
                "Saved offline checks hold the original intent or execution slot. Cancel or settle that original operation before conflicting work.",
                "The original offline-check status is unverified. Check retained status before conflicting work.",
            )),
            ("ownerAndroidBuild", "owner-android-build", (
                "Android-build ownership or finality is unverified. Keep original Status and Cancel; conflicting work is disabled.",
                "The original Android service action is active or unconfirmed. Keep its Status and Cancel; do not repeat registration.",
                "The original Android source inspection or protected registration is active or unconfirmed. Keep its Status and Cancel; do not repeat copy.",
                "An original source review is retained. Register that exact review or explicitly discard it before conflicting work.",
                "The original Android tool picker or folder check is active or unconfirmed. Keep tool-selection Status and Cancel before conflicting work.",
                "The original Android tool catalog is still reading, stopping or unconfirmed. Keep catalog Status and Cancel before conflicting work.",
                "The Android build holds its original consent or execution slot. Cancel or settle that original operation before conflicting work.",
                "The original Android-build status is unverified. Check retained Status before conflicting work.",
            )),
            ("ownerIOSArchive", "owner-ios-archive", (
                "iOS-archive ownership or finality is unverified. Keep original Status and Cancel; conflicting work is disabled.",
                "The iOS archive holds its original consent or execution slot. Cancel or settle that original operation before conflicting work.",
                "The original iOS-archive status is unverified. Check retained Status before conflicting work.",
            )),
            ("ownerProjectRecovery", "owner-project-recovery", (
                "Project-recovery ownership or finality is unverified. Keep the original status; conflicting work is disabled.",
                "Project build-input recovery holds the original intent or execution slot. Cancel or settle that original operation before conflicting work.",
                "The original project-recovery status is unverified. Check retained status before conflicting work.",
            )),
            ("ownerGitHubPreflight", "owner-github-preflight", (
                "The original GitHub preflight action is running or unverified. Read its local Status before starting another operation.",
            )),
            ("ownerGitHubRelease", "owner-github-release", (
                "The original protected release workflow action is running or unverified. Read its local Status before starting another operation.",
            )),
            ("ownerProjectPath", "owner-project-path", (
                "The original project-path outcome or cleanup is unverified. Conflicting native operations remain blocked.",
                "Finish the original project-path selection. Changing drafts or projects does not cancel it.",
            )),
            ("ownerSavedVersionEdit", "owner-saved-version-edit", (
                "Saved-version edit ownership is unverified. Keep its original operation and do not retry.",
                "A saved-version edit is still owned. Close or finish that original session before another operation.",
                "This project needs separately authorized saved-version recovery. No other edit can clear that journal.",
            )),
            ("ownerMetadataImages", "owner-metadata-images", (
                "Original image ownership or cleanup is unverified. Observe that original operation; do not start a competing one.",
                "An original image selection or local-copy review is retained. Finish or stop that operation first.",
                "This project needs a separate image recovery inspection. Another edit cannot bypass its journal.",
            )),
        )
        self.assertEqual(len(groups), 15)
        literals = [title for _, _, titles in groups for title in titles]
        self.assertEqual(len(literals), 33)
        self.assertEqual(len(set(literals)), 33)
        self.assertEqual(len({label for _, label, _ in groups}), 15)
        expected_table = "            let reasons: [([String], DashboardReason)] = [\n"
        for name, _, titles in groups:
            expected_table += "                ([\n"
            expected_table += "".join("                    " + json.dumps(title) + ",\n" for title in titles)
            expected_table += "                ], ." + name + "),\n"
        expected_table += "            ]\n"
        self.assertIn(expected_table, sample)
        expected_scan = "            var selected: DashboardReason?\n            var ambiguous = false\n            // Already-ready samples need no refusal queries; the real wait below is still required.\n            if !enabled || !hittable {\n                for (titles, reason) in reasons {\n                    try checkOriginalOwners()\n                    _ = try remaining(5)\n                    let matches = renderer.staticTexts.matching(NSPredicate(\n                        format: \"identifier IN %@ OR label IN %@ OR title IN %@\",\n                        argumentArray: [titles, titles, titles])).count\n                    if matches > 1 || (matches == 1 && selected != nil) {\n                        ambiguous = true\n                        break // No further diagnostic observation can repair ambiguity.\n                    }\n                    if matches == 1 { selected = reason }\n                }\n            }\n            try checkOriginalOwners()\n            _ = try remaining(5)\n"
        self.assertIn(expected_scan, sample)
        # Inert count DATA only, paired with the exact Swift reducer above.
        # This does not execute XCTest queries or prove native AX exposure.
        def reduce_counts(counts, *, enabled=False, hittable=False):
            self.assertEqual(len(counts), 15)
            selected, ambiguous, observations = None, False, 0
            if not enabled or not hittable:
                for index, matches in enumerate(counts):
                    observations += 1
                    if matches > 1 or (matches == 1 and selected is not None):
                        ambiguous = True
                        break
                    if matches == 1:
                        selected = groups[index][1]
            return ("ambiguous" if ambiguous else selected or "other-or-unobserved"), observations

        # Both mixed samples still classify. Ready samples consume no queries,
        # even when the unused count data contains matching or ambiguous reasons.
        for enabled, hittable in ((False, False), (False, True), (True, False), (True, True)):
            for counts, not_ready in (
                    ([0] * 15, ("other-or-unobserved", 15)),
                    ([1] + [0] * 14, ("loading", 15)),
                    ([2] + [0] * 14, ("ambiguous", 1)),
                    ([1, 1] + [0] * 13, ("ambiguous", 2))):
                with self.subTest(enabled=enabled, hittable=hittable, counts=counts):
                    self.assertEqual(
                        reduce_counts(counts, enabled=enabled, hittable=hittable),
                        ("other-or-unobserved", 0) if enabled and hittable else not_ready)

        self.assertEqual(reduce_counts([0] * 15), ("other-or-unobserved", 15))
        for index, (_, label, _) in enumerate(groups):
            counts = [0] * 15
            counts[index] = 1
            self.assertEqual(reduce_counts(counts), (label, 15))
            for duplicate_count in (2, 5):
                counts[index] = duplicate_count
                self.assertEqual(reduce_counts(counts), ("ambiguous", index + 1))
            for second in range(index + 1, 15):
                conflicting = [0] * 15
                conflicting[index] = conflicting[second] = 1
                self.assertEqual(reduce_counts(conflicting), ("ambiguous", second + 1))
        self.assertIn("reason: ambiguous ? .ambiguous : selected ?? .otherOrUnobserved)", sample)
        for forbidden in ("print(", ".label", ".value", "debugDescription", "screenshot",
                          "while ", "sleep(", "waitFor", "XCTWaiter", "catch", "try?", "Date(", "systemUptime"):
            self.assertNotIn(forbidden, sample)
        self.assertEqual(dashboard.count('NSPredicate(format: "enabled == true AND hittable == true"), object: open'), 1)
        self.assertEqual(dashboard.count("XCTWaiter.wait(for: [ready], timeout: try remaining(5))"), 1)
        self.assertIn("let returned = XCTWaiter.wait(for: [ready], timeout: try remaining(5))\n"
                      "        let readiness = snapshot.map { ($0, DashboardWaiter(returned)) }\n"
                      '        try require(returned == .completed, "ordinary project control is not usable", dashboard: readiness)', dashboard)
        self.assertEqual(source.count("diagnosticOrdinal:"), 5)  # Default plus only four shared-case callers.
        case_body = shared.split("    // Finite synthetic files only.", 1)[0]
        for ordinal in range(1, 5):
            self.assertEqual(case_body.count(f"try dashboard(renderer, diagnosticOrdinal: {ordinal})"), 1)
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

    def test_native_panels_display_fixed_purpose_without_relaxing_sheet_identity(self):
        native = (ROOT / "desktop/native/macos-installed-native/src/native.m").read_text()
        start = native.split("static int mrk_panel_start_inner(", 1)[1]
        title = "[panel setTitle:title];"
        message = "[panel setMessage:title];"
        self.assertEqual(native.count(message), 1)
        self.assertEqual(start.count(title), 1)
        self.assertIn('NSString *title = kind == 1 ? @"Choose a mobile project folder"', start)
        self.assertLess(start.index(title), start.index(message))
        self.assertLess(start.index(message), start.index("[panel setCanChooseFiles:"))
        self.assertLess(start.index(message), start.index("beginSheetModalForWindow:s->parent"))
        # A visible purpose is not permission to accept an arbitrary native sheet.
        sheet = SWIFT.read_text().split("private func nativeSheet(", 1)[1].split(
            "private func goToFolder(", 1)[0]
        self.assertIn("let sheet = try waitElement(window.sheets, in: window)", sheet)
        self.assertIn("if sheet.label != title && sheet.staticTexts.matching(identifier: title).count != 1 {", sheet)
        self.assertIn('throw Refusal.condition("unexpected original native sheet title in " + journeyStage)', sheet)

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


@unittest.skipUnless(hasattr(os, "O_NOFOLLOW") and hasattr(os, "pread"), "POSIX inert normal-phase DATA")
class NormalPhaseDataTests(unittest.TestCase):
    def test_normal_loader_registers_real_dataclasses_and_preserves_original_custody(self):
        name = MODULE.LOADER_MODULE
        self.assertNotIn(name, sys.modules)
        for collision in (None, object()):
            sys.modules[name] = collision
            try:
                with patch.object(MODULE.os, "open", side_effect=AssertionError("collision must precede open")):
                    with self.assertRaisesRegex(MODULE.Refused, "loader-collision"):
                        MODULE.load_normal_owner(ROOT)
                self.assertIs(sys.modules[name], collision)
            finally:
                if name in sys.modules and sys.modules[name] is collision:
                    del sys.modules[name]
        original_spec = MODULE.importlib.util.spec_from_file_location
        original_open, original_close, original_body = os.open, os.close, MODULE.original_body
        for fault in (None, "execution", "registry-before-core", "registry-after-core",
                      "source-before-core", "source-after-core", "close", "primary-and-close"):
            with self.subTest(fault=fault), ExitStack() as stack:
                opened, closed, modules, calls = [], [], [], []
                foreign, sentinel = object(), object()
                first_failure = ValueError("private synthetic loader failure")
                close_failure = OSError("private synthetic close failure")
                reads = 0

                def opening(path, flags, *args, **kwargs):
                    fd = original_open(path, flags, *args, **kwargs)
                    if Path(path) == ROOT / MODULE.LOADER:
                        opened.append(fd)
                    return fd

                def closing(fd):
                    if fd in opened:
                        closed.append(fd)
                    original_close(fd)
                    if fd in opened and fault in ("close", "primary-and-close"):
                        raise close_failure

                def reading(fd, limit, collect=False):
                    nonlocal reads
                    value = original_body(fd, limit, collect)
                    reads += 1
                    if (fault == "source-before-core" and reads == 3
                            or fault == "source-after-core" and reads == 4):
                        return value[:2] + ("0" * 64,)
                    return value

                def spec_for(module_name, path):
                    self.assertEqual((module_name, Path(path)), (name, ROOT / MODULE.LOADER))
                    spec = original_spec(module_name, path)
                    actual = spec.loader

                    class DefinitionLoader:
                        def create_module(self, _spec):
                            return None

                        def exec_module(self, module):
                            modules.append(module)
                            self_registered = sys.modules.get(name)
                            if self_registered is not module:
                                raise AssertionError("real definitions require original registration")
                            actual.exec_module(module)  # Actual helper/dataclasses, NOT core/native execution.
                            if not dataclasses.is_dataclass(module.Binding):
                                raise AssertionError("real Binding dataclass was not loaded")

                            def no_core(root):
                                calls.append(root)
                                if fault == "registry-after-core":
                                    sys.modules[name] = foreign
                                return sentinel

                            module.load_owner = no_core  # Stub only before the first possible core entry.
                            if fault in ("execution", "primary-and-close"):
                                raise first_failure
                            if fault == "registry-before-core":
                                sys.modules[name] = foreign

                    spec.loader = DefinitionLoader()
                    return spec

                stack.enter_context(patch.object(MODULE.importlib.util, "spec_from_file_location", spec_for))
                stack.enter_context(patch.object(MODULE.os, "open", opening))
                stack.enter_context(patch.object(MODULE.os, "close", closing))
                stack.enter_context(patch.object(MODULE, "original_body", reading))
                try:
                    if fault is None:
                        self.assertIs(MODULE.load_normal_owner(ROOT), sentinel)
                        self.assertIs(sys.modules[name], modules[0])
                    else:
                        with self.assertRaises((MODULE.Refused, ValueError, OSError)) as raised:
                            MODULE.load_normal_owner(ROOT)
                        if fault in ("execution", "primary-and-close"):
                            self.assertIs(raised.exception, first_failure)
                        elif fault == "close":
                            self.assertIs(raised.exception, close_failure)
                        if fault.startswith("registry-"):
                            self.assertIs(sys.modules[name], foreign)
                        else:
                            self.assertNotIn(name, sys.modules)
                    self.assertEqual(len(opened), 1)
                    self.assertEqual(closed, opened)
                    self.assertEqual(len(calls), 0 if fault in (
                        "execution", "primary-and-close", "registry-before-core", "source-before-core") else 1)
                finally:
                    # Only these fixture-owned entries are retired; no blanket registry restore.
                    if name in sys.modules and (sys.modules[name] is foreign
                            or any(sys.modules[name] is item for item in modules)):
                        del sys.modules[name]

    def test_admission_exception_projection_is_closed_and_preserves_main_failure(self):
        private = "private-synthetic-credential-or-path"
        try:
            MODULE.need(False, private)
        except MODULE.Refused as error:
            value = MODULE.normal_admission_failure("loader", error, None, [])
        self.assertEqual(value["exceptionClass"], "Refused")
        self.assertEqual(value["sourceFrames"][0]["source"], "macos_normal_ui_runner.py")
        self.assertNotIn(private.encode(), MODULE.encoded(value))
        projected = MODULE.classify_normal_admission_failure(MODULE.encoded(value) + b"\n")
        self.assertEqual(projected["status"], "observed-exception-only")
        self.assertFalse(projected["nativeSuccessInferred"])
        self.assertIs(projected["ownerFailure"]["cleanupComplete"], None)
        foreign_frame = SimpleNamespace(tb_frame=SimpleNamespace(f_code=SimpleNamespace(
            co_filename="/private/macos_normal_ui_runner.py")), tb_lineno=12, tb_next=None)
        fake_error = SimpleNamespace(__traceback__=foreign_frame)
        self.assertEqual(MODULE.normal_admission_failure("loader", fake_error, None, [])["sourceFrames"], [])
        command = {"role": "normal-ui-build", "returncode": 65, "timeoutSeconds": 120, "roleCapSeconds": 240,
            "outputLimitBytes": 1048576, "stdoutBytes": 32, "stderrBytes": 12,
            "argvSha256": "a" * 64, "stdoutSha256": "b" * 64, "stderrSha256": "c" * 64}
        with_commands = dict(value, commands=[command])
        selected = MODULE.classify_normal_admission_failure(MODULE.encoded(with_commands))
        self.assertEqual(selected["commands"], [{"role": "normal-ui-build", "returncode": 65, "stdoutBytes": 32, "stderrBytes": 12}])
        mutations = []
        for key, bad in (("schemaVersion", True), ("productReady", True), ("stage", "private-stage"),
                         ("exceptionClass", private), ("sourceFrames", [{"source": "/private/macos_normal_ui_runner.py", "line": 1}]),
                         ("sourceFrames", [{"source": "macos_normal_ui_runner.py", "line": True}]),
                         ("ownerFailure", {"dispatched": 1, "contained": True, "cleanupComplete": None}),
                         ("commands", [{"private": private}])):
            mutations.append(MODULE.encoded(dict(value, **{key: bad})))
        mutations += [b"", b"x" * 65537, MODULE.encoded(value) + b"\nprivate native output\n",
            MODULE.encoded(value) + MODULE.encoded(value), b'{"schemaVersion":1,"schemaVersion":1}',
            b'{"schemaVersion":NaN}', MODULE.encoded(dict(value, extra=private))]
        mutations += [MODULE.encoded(dict(value, commands=[dict(command, **{key: bad})]))
                      for key, bad in (("role", private), ("returncode", True), ("stderrBytes", 1048576),
                                       ("argvSha256", private), ("timeoutSeconds", 241))]
        for body in mutations:
            self.assertEqual(MODULE.classify_normal_admission_failure(body)["status"], "unavailable")
        # Main returns1 even for an early loader exception; no owner/native call.
        normal = "/Users/runner/work/_temp/mrk-macos-installed.ABCDef12/normal-ui/tmp/"
        with patch.object(MODULE.sys, "argv", ["helper", "--normal-build"]), \
                patch.object(MODULE.os, "environ", {"TMPDIR": normal}), \
                patch.object(MODULE.time, "monotonic_ns", return_value=0), \
                patch.object(MODULE, "normal_context", return_value=(ROOT, "a" * 40, {}, (32 * 1024**3,) * 2)), \
                patch.object(MODULE, "load_normal_owner", side_effect=AttributeError(private)), \
                patch.object(MODULE, "execute_normal_phase", side_effect=AssertionError("must not execute")), \
                patch.object(MODULE.sys, "stderr", io.StringIO()) as errors:
            self.assertEqual(MODULE.main(), 1)
        classified = MODULE.classify_normal_admission_failure(errors.getvalue().encode())
        self.assertEqual((classified["stage"], classified["exceptionClass"]), ("loader", "AttributeError"))
        self.assertNotIn(private, errors.getvalue())

    def test_normal_runner_build_is_early_but_ui_stays_after_installation(self):
        workflow = (ROOT / ".github/workflows/desktop-macos-installed.yml").read_text()
        label = "      - name: Build only the external normal-app XCTest runner, not an instrumented app\n"
        self.assertEqual(workflow.count(label), 1)
        source_end = workflow.index("          PY_SOURCE\n")
        start = workflow.index(label)
        self.assertEqual(workflow[source_end + len("          PY_SOURCE\n"):start], "")
        self.assertLess(start, workflow.index("      - name: Acquire and verify the two fixed Android support archives as DATA"))
        build = workflow.split(label, 1)[1].split("      - name:", 1)[0]
        self.assertIn("if: github.ref == 'refs/heads/verify/desktop-macos-preview'", build)
        self.assertNotIn("steps.preview_upload", build)
        self.assertEqual(build.count(" --normal-build "), 1)
        self.assertIn("classify_normal_admission_failure", build)
        self.assertIn('exit "$build_status"', build)
        self.assertIn('original_body(fd, 65536, collect=True)', build)
        self.assertIn('exclusive_output(normal / "build.admission-diagnostics.json"', build)
        action = workflow.split("      - name: Launch the exact ordinary app, Cancel its real Quit sheet, then Quit normally\n", 1)[1].split("      - name:", 1)[0]
        self.assertIn("steps.normal_ui_build.outcome == 'success' && steps.preview_upload.outcome == 'success'", action)
        self.assertLess(workflow.index("      - name: Nonroot byte/mode readback, not a headless GUI substitute"),
                        workflow.index("      - name: Launch the exact ordinary app,"))
        artifact = workflow.split("        id: evidence\n", 1)[1]
        self.assertIn("/normal-ui/build.admission-diagnostics.json", artifact)
        self.assertNotIn("/normal-ui/build.log", artifact.split("      # Do not start", 1)[0])

    """Only fake original owners and private synthetic files, never Apple tools."""

    def test_fixed_normal_modes_environment_and_returned_original_contract(self):
        normal = Path("/Users/runner/work/_temp/mrk-macos-installed.ABCDef12/normal-ui")
        temporary = str(normal / "tmp") + "/"
        build = MODULE.normal_request(["--normal-build"], temporary)
        self.assertEqual((build["phase"], build["derived"], build["result"], build["phaseSeconds"]),
                         ("build", normal / "DerivedData", None, 450))
        self.assertEqual(MODULE.normal_build_arguments(build["derived"]), [
            "/usr/bin/xcodebuild", "build-for-testing", "-project", MODULE.PROJECT, "-scheme", "MRKNormalAppUI",
            "-configuration", "Debug", "-destination", "platform=macOS,arch=arm64", "-destination-timeout", "15",
            "-derivedDataPath", str(normal / "DerivedData"), "-jobs", "2", "-disableAutomaticPackageResolution",
            "COMPILER_INDEX_STORE_ENABLE=NO"])
        for name, (_, allowance, cap) in MODULE.NORMAL_SELECTIONS.items():
            summary = MODULE.normal_request(["--normal-summary", name], temporary)
            test = MODULE.normal_request(normal_arguments(name), temporary)
            self.assertEqual((summary["phase"], summary["result"], summary["timeout"], summary["phaseSeconds"]),
                             ("summary", normal / name, 30, 90))
            self.assertEqual((test["result"], test["allowance"], test["timeout"]), (normal / name, allowance, cap))
            self.assertEqual(test["phaseSeconds"], {180: 345, 420: 585, 720: 885}[cap])
        for arguments in ([], ["--normal-build", "extra"], ["--normal-summary"],
                          ["--normal-summary", "../test.xcresult"], ["--normal-summary", "other.xcresult"],
                          ["--normal-summary", "test.xcresult", "extra"]):
            with self.subTest(arguments=arguments), self.assertRaises(MODULE.Refused):
                MODULE.normal_request(arguments, temporary)
        for temporary_value in ("", temporary + "/", temporary.replace("/normal-ui/", "/elsewhere/")):
            with self.assertRaises(MODULE.Refused):
                MODULE.normal_request(["--normal-build"], temporary_value)
        tools = {"xcode": b"Xcode 26.0\nBuild version 17A324\n", "sdkVersion": b"26.0\n",
                 "sdkBuild": b"25A352\n", "sdkPath": b"/Applications/Xcode_26.0.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX26.0.sdk\n"}
        self.assertEqual(MODULE.normal_toolchain(tools)["sdkVersion"], "26.0")
        MODULE.normal_toolchain(dict(tools, sdkPath=tools["sdkPath"].replace(b"Xcode_26.0.app", b"Xcode.app").replace(b"MacOSX26.0.sdk", b"MacOSX.sdk")))
        for key, value in (("xcode", b"Xcode 25.0\nBuild version 1A\n"), ("sdkVersion", b"26.0\nextra"),
                           ("sdkBuild", b"private value"), ("sdkPath", tools["sdkPath"].replace(b"SDKs/", b"SDKs/../SDKs/")),
                           ("sdkPath", b"/private/arbitrary/SDK.sdk\n"), ("xcode", b"x" * 513)):
            with self.subTest(tool=key), self.assertRaises((MODULE.Refused, UnicodeError)):
                MODULE.normal_toolchain(dict(tools, **{key: value}))
        source = "a" * 40
        environment = dict(PATH="/usr/bin:/bin:/usr/sbin:/sbin", HOME="/Users/runner", USER="runner", LOGNAME="runner",
            TMPDIR=temporary, LANG="en_US.UTF-8", LC_ALL="en_US.UTF-8", TZ="UTC", DEVELOPER_DIR=MODULE.DEVELOPER,
            TEST_RUNNER_MRK_NORMAL_UI_HOSTED_JOB="github-hosted-macos26-arm64",
            TEST_RUNNER_MRK_NORMAL_UI_APPLICATION_SOURCE=source, TEST_RUNNER_MRK_NORMAL_UI_HARNESS_SOURCE=source)
        account = SimpleNamespace(pw_uid=501, pw_gid=20, pw_name="runner", pw_dir="/Users/runner")
        root = Path("/Users/runner/work/mobile-release-kit/mobile-release-kit")
        with ExitStack() as stack:
            for context in (
                patch.dict(sys.modules, {"resource": SimpleNamespace(RLIMIT_FSIZE=1, getrlimit=lambda _: (32 * 1024**3,) * 2),
                                         "pwd": SimpleNamespace(getpwuid=lambda _: account)}),
                patch.object(MODULE.sys, "platform", "darwin"), patch.object(MODULE.platform, "machine", return_value="arm64"),
                patch.object(MODULE.platform, "mac_ver", return_value=("26.0", (), "arm64")),
                patch.object(MODULE, "__file__", str(root / "desktop/tools/macos_normal_ui_runner.py")),
                patch.object(MODULE.Path, "cwd", return_value=root), patch.object(MODULE.os, "environ", dict(environment)),
                patch.object(MODULE.os, "getuid", return_value=501), patch.object(MODULE.os, "geteuid", return_value=501),
                patch.object(MODULE.os, "getgid", return_value=20), patch.object(MODULE.os, "getegid", return_value=20),
                patch.object(MODULE.os, "stat", return_value=SimpleNamespace(st_uid=501)),
            ):
                stack.enter_context(context)
            self.assertEqual(MODULE.normal_context(build), (root, source, environment, (32 * 1024**3,) * 2))
            for key in ("PATH", "HOME", "LANG", "DEVELOPER_DIR", "TEST_RUNNER_MRK_NORMAL_UI_HOSTED_JOB",
                        "TEST_RUNNER_MRK_NORMAL_UI_APPLICATION_SOURCE"):
                with self.subTest(environment=key), patch.dict(MODULE.os.environ, {key: "not-admitted"}), self.assertRaises(MODULE.Refused):
                    MODULE.normal_context(build)
            with patch.object(MODULE.os, "geteuid", return_value=502), self.assertRaises(MODULE.Refused):
                MODULE.normal_context(build)
        argv = ["/usr/bin/xcodebuild", "-version"]
        original = subprocess.CompletedProcess(argv, 65, b"ordinary original", b"ordinary stderr")
        self.assertIs(MODULE.original_command(original, argv, 4096), original)
        for changed in (SimpleNamespace(args=argv, returncode=0, stdout=b"", stderr=b""),
                        subprocess.CompletedProcess(tuple(argv), 0, b"", b""),
                        subprocess.CompletedProcess(argv, True, b"", b""),
                        subprocess.CompletedProcess(argv, -1, b"", b""),
                        subprocess.CompletedProcess(argv, 0, "text", b""),
                        subprocess.CompletedProcess(argv, 0, b"x" * 4096, b"x")):
            with self.assertRaises(MODULE.Refused):
                MODULE.original_command(changed, argv, 4096)
        calls = []
        def fake_owned(arguments, **kwargs):
            calls.append((arguments, kwargs))
            return original
        phase = MODULE.NormalPhase(SimpleNamespace(run_owned=fake_owned), environment, root,
                                   MODULE.PhaseClock(90, now=lambda: 0))
        self.assertIs(phase.call("normal-toolchain-xcode", argv, 15, 4096), original)
        self.assertEqual(calls, [(argv, dict(environ=environment, cwd=root, timeout=15, capture=True, text=False, output_limit=4096))])
        self.assertEqual(phase.records[0]["argvSha256"], MODULE.sha(MODULE.encoded(argv)))

    def test_normal_phase_deadlines_file_limits_source_and_receipt_finality(self):
        for phase, limit in (("build", 32 * 1024**3), ("test", 1024**3), ("summary", 1024**3)):
            self.assertEqual(MODULE.normal_file_limit(phase, (limit, limit)), (limit, limit))
            for actual in ((-1, -1), (limit, -1), [limit, limit], (True, limit), (limit - 1, limit - 1)):
                with self.subTest(phase=phase, actual=actual), self.assertRaises(MODULE.Refused):
                    MODULE.normal_file_limit(phase, actual)
        tick = [0]
        clock = MODULE.PhaseClock(90, now=lambda: tick[0])
        tick[0] = 70 * 1_000_000_000
        self.assertEqual(clock.allowance(30), 7)  # remaining20 - owner3 - publication10
        self.assertEqual(clock.deadline, 90 * 1_000_000_000)
        tick[0] = 77 * 1_000_000_000
        with self.assertRaisesRegex(MODULE.Refused, "no-command-budget"):
            clock.allowance(30)
        tick[0] = 0
        with self.assertRaisesRegex(MODULE.Refused, "terminal"):
            clock.allowance(30)
        for invalid in (-1, True, 0.5, 90 * 1_000_000_000):
            tick = [1]
            clock = MODULE.PhaseClock(90, now=lambda: tick[0], started=0)
            tick[0] = invalid
            with self.assertRaises(MODULE.Refused): clock.check()
            self.assertTrue(clock.failed)
        finished = MODULE.PhaseClock(90, now=lambda: 0)
        finished.finish()
        with self.assertRaisesRegex(MODULE.Refused, "terminal"): finished.allowance(15)
        calls = []
        tick = [0]
        def late_original(argv, **_):
            calls.append(argv); tick[0] = 90 * 1_000_000_000
            return subprocess.CompletedProcess(argv, 0, b"", b"")
        phase = MODULE.NormalPhase(SimpleNamespace(run_owned=late_original), {}, Path("/inert"),
                                   MODULE.PhaseClock(90, now=lambda: tick[0]))
        for _ in range(2):
            with self.assertRaises(MODULE.Refused): phase.call("normal-ui-summary", ["fixed"], 30, 262144)
        self.assertEqual(calls, [["fixed"]])
        # Real SOURCE readers/receipt originals; fake owner returns inert bytes only.
        for fault in (None, "native-nonzero", "query-nonzero", "source-changed", "late-command", "close", "late-close"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory(prefix="mrk-normal-phase-data-") as temporary:
                root = Path(temporary)
                normal = root / "normal-ui"; normal.mkdir(mode=0o700)
                relative_names = ("desktop/tools/macos_normal_ui_runner.py",
                    "desktop/native/macos-normal-ui/MRKNormalAppUITests/NormalAppUITests.swift")
                source_rows = []
                for relative in relative_names:
                    path = root / relative; path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                    body = b"inert source fixture, never imported or compiled\n"; path.write_bytes(body)
                    blob = hashlib.sha1(b"blob " + str(len(body)).encode() + b"\0" + body).hexdigest()
                    source_rows.append(b"100644 blob " + blob.encode() + b"\t" + relative.encode() + b"\0")
                tool_values = (b"Xcode 26.0\nBuild version 17A324\n",
                    b"/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX26.0.sdk\n",
                    b"26.0\n", b"25A352\n")
                query_values = {tuple(query[2]): body for query, body in zip(MODULE.TOOLCHAIN_QUERIES, tool_values)}
                tick, owned = [0], []
                def owned_fake(argv, **kwargs):
                    owned.append((argv, kwargs))
                    if argv[0] == "/usr/bin/git":
                        return subprocess.CompletedProcess(argv, 0, b"".join(source_rows), b"")
                    if tuple(argv) in query_values:
                        return subprocess.CompletedProcess(argv, 66 if fault == "query-nonzero" else 0, query_values[tuple(argv)], b"")
                    if argv[1] == "build-for-testing":
                        if fault == "source-changed": (root / relative_names[0]).write_bytes(b"changed inert SOURCE\n")
                        if fault == "late-command": tick[0] = 450 * 1_000_000_000
                        return subprocess.CompletedProcess(argv, 65 if fault == "native-nonzero" else 0, b"inert build original\n", b"")
                    self.fail("unexpected fake original route")
                request = MODULE.normal_request(["--normal-build"], str(normal / "tmp") + "/")
                phase = MODULE.NormalPhase(SimpleNamespace(run_owned=owned_fake), {}, root, MODULE.PhaseClock(450, now=lambda: tick[0]))
                receipt_fd, closed = [None], []
                original_open, original_close = os.open, os.close
                def open_original(path, flags, *args, **kwargs):
                    fd = original_open(path, flags, *args, **kwargs)
                    if str(path).endswith("/build.command-admission.json"): receipt_fd[0] = fd
                    return fd
                def close_original(fd):
                    original_close(fd)
                    if fd == receipt_fd[0]:
                        closed.append(fd)
                        if fault == "close": raise OSError("synthetic consuming close failure")
                        if fault == "late-close": tick[0] = 450 * 1_000_000_000
                with patch.object(MODULE.os, "open", open_original), patch.object(MODULE.os, "close", close_original):
                    if fault in (None, "native-nonzero"):
                        original = MODULE.execute_normal_phase(phase, request, "a" * 40, (32 * 1024**3,) * 2)
                        self.assertEqual(original.returncode, 65 if fault else 0)
                    else:
                        with self.assertRaises((MODULE.Refused, MODULE.NativeQueryFailure, OSError)):
                            MODULE.execute_normal_phase(phase, request, "a" * 40, (32 * 1024**3,) * 2)
                if fault in ("query-nonzero", "source-changed", "late-command"):
                    self.assertFalse((normal / "build.command-admission.json").exists())
                if fault == "query-nonzero": self.assertEqual(len(owned), 2)
                if fault in (None, "native-nonzero", "close", "late-close"):
                    self.assertEqual(len(closed), 1)
                if fault is None:
                    facts = json.loads((normal / "build.command-admission.json").read_bytes())
                    self.assertEqual([row["role"] for row in facts["commands"]], ["normal-ui-source-roster",
                        "normal-toolchain-xcode", "normal-toolchain-sdkPath", "normal-toolchain-sdkVersion",
                        "normal-toolchain-sdkBuild", "normal-ui-build", "normal-ui-source-roster"])
                    self.assertTrue(facts["sourcePrePostMatched"])
                    self.assertTrue(facts["phaseClock"]["postCloseDeadlineRequired"])
                    self.assertEqual(stat.S_IMODE((normal / "build.command-admission.json").stat().st_mode), 0o600)
                    with self.assertRaises(OSError): MODULE.exclusive_output(normal / "build.command-admission.json", b"no overwrite\n", 32768)
                    # Same checked original source route for the fixed summary, no Apple command.
                    (normal / "test.xcresult").mkdir(mode=0o700)
                    def summary_fake(argv, **kwargs):
                        owned.append((argv, kwargs))
                        return subprocess.CompletedProcess(argv, 0, b"".join(source_rows) if argv[0] == "/usr/bin/git" else b'{"totalTestCount":1}\n', b"")
                    summary = MODULE.normal_request(["--normal-summary", "test.xcresult"], str(normal / "tmp") + "/")
                    summary_phase = MODULE.NormalPhase(SimpleNamespace(run_owned=summary_fake), {}, root, MODULE.PhaseClock(90, now=lambda: 0))
                    MODULE.execute_normal_phase(summary_phase, summary, "a" * 40, (1024**3,) * 2)
                    self.assertEqual(owned[-2][0], ["/usr/bin/xcrun", "xcresulttool", "get", "test-results", "summary", "--path", str(normal / "test.xcresult"), "--compact"])
                    self.assertEqual(owned[-2][1]["timeout"], 30)
                    self.assertEqual(owned[-2][1]["output_limit"], 262144)
                    self.assertEqual(json.loads((normal / "summary.command-admission.json").read_bytes())["resultBundle"], "test.xcresult")

    def test_closed_normal_failure_diagnostics_preserve_original_nonzero_and_privacy(self):
        selected = "testLaunchCancelAndQuit"
        query = b"MRK_MACOS_NORMAL_DASHBOARD_QUERY=observation=title;matches=2;exceedsFour=0;nonAtomic=1\n"
        secret = b"PRIVATE-SYNTHETIC-NOT-FOR-PUBLIC-output"
        body = (b"/Users/private/" + secret + b" Error Domain=NSCocoaErrorDomain Code=-4 description=" + secret + b"\n"
            b"NormalAppUITests.swift:123:9: error: -[MRKNormalAppUITests.NormalAppUITests testLaunchCancelAndQuit] : private reason\n"
            b"Test Case '-[MRKNormalAppUITests.NormalAppUITests testLaunchCancelAndQuit]' started.\n" + query + query)
        original = subprocess.CompletedProcess(["fixed-original"], 65, body, b"** TEST EXECUTE FAILED **\n")
        value = MODULE.normal_failure_diagnostics("test", "test.xcresult", original)
        self.assertEqual(value["errorCodes"], [{"stream": "stdout", "domain": "NSCocoaErrorDomain", "code": -4}])
        self.assertEqual(value["sourceFailures"], [{"stream": "stdout", "source": "NormalAppUITests.swift", "method": selected, "line": 123, "column": 9}])
        self.assertEqual(len(value["queryObservations"]), 2)  # Preserve repeats, never substitute the last as authority.
        self.assertEqual(value["requireObservations"], [])
        # Same-original diagnostic DATA, never a new test selection or success.
        marker = b"MRK_MACOS_PACKAGED_REQUIRE_FAILURE=v1;line=123;check=condition\n"
        for line, check, ending in ((1, "condition", b"\n"), (123, "singleton", b"\n"),
                                    (65535, "actionable", b"\r\n")):
            fixed = f"MRK_MACOS_PACKAGED_REQUIRE_FAILURE=v1;line={line};check={check}".encode() + ending
            observed = MODULE.normal_failure_diagnostics("test", "test.xcresult",
                subprocess.CompletedProcess([], 65, fixed, b""))
            self.assertEqual(observed["requireObservations"],
                [{"source": "NormalAppUITests.swift", "line": line, "check": check}])
            self.assertEqual(observed["status"], "classified")
            self.assertEqual(observed["originalReturncode"], 65)
        malformed = (marker[:-1], marker.replace(b"123", b"0"), marker.replace(b"123", b"01"),
            marker.replace(b"123", b"+1"), marker.replace(b"123", b"-1"), marker.replace(b"123", b"65536"),
            marker.replace(b"v1", b"v2"), marker.replace(b"condition", b"PRIVATE"),
            b"prefix " + marker, marker[:-1] + b";private=" + secret + b"\n", marker + marker,
            marker + marker.replace(b"123", b"124"), marker + marker[:-1],
            marker + marker.replace(b"condition", b"PRIVATE"))
        for raw in malformed:
            with self.subTest(require_marker=raw[:100]):
                observed = MODULE.normal_failure_diagnostics("test", "test.xcresult",
                    subprocess.CompletedProcess([], 65, query + raw, b""))
                self.assertEqual(observed["requireObservations"], [])
                self.assertEqual(observed["status"], "unavailable")
                self.assertEqual(len(observed["queryObservations"]), 1)  # Retain unrelated finite observations.
                self.assertEqual(observed["originalReturncode"], 65)
                self.assertNotIn(secret, MODULE.encoded(observed))
                self.assertNotIn(b"PRIVATE", MODULE.encoded(observed))
        other = next(name for name in MODULE.NORMAL_SELECTIONS if name != "test.xcresult")
        for phase, selection, stdout, stderr in (("test", "test.xcresult", b"", marker),
                ("test", other, marker, b""), ("summary", "test.xcresult", marker, b""),
                ("build", None, marker, b""), ("query", None, marker, b"")):
            observed = MODULE.normal_failure_diagnostics(phase, selection,
                subprocess.CompletedProcess([], 65, stdout, stderr))
            self.assertEqual(observed["requireObservations"], [])
        with self.assertRaises(MODULE.Refused):
            MODULE.normal_failure_diagnostics("test", "packaged-entry.xcresult",
                subprocess.CompletedProcess([], 65, marker, b""))
        self.assertTrue(value["markers"]["selectedCaseStarted"] and value["markers"]["testExecuteFailed"])
        self.assertEqual(value["stdoutSha256"], hashlib.sha256(body).hexdigest())
        for private in (secret, b"/Users/private", b"private reason", b"description="):
            self.assertNotIn(private, MODULE.encoded(value))
        invalid = (query.rstrip(b"\n") + b" invalid\n" + query.rstrip(b"\n") + b"\nextra=private\n" +
            b"Error Domain=NSCocoaErrorDomain Code=-0\nError Domain=NSCocoaErrorDomain Code=2147483648\n" +
            b"Error Domain=PrivateDomain Code=1\nNormalAppUITests.swift:65536:9: error: -[MRKNormalAppUITests.NormalAppUITests testLaunchCancelAndQuit] : bad\n")
        invalid_value = MODULE.normal_failure_diagnostics("test", "test.xcresult", subprocess.CompletedProcess([], 65, invalid, b""))
        self.assertEqual(invalid_value["errorCodes"], [])
        self.assertEqual(invalid_value["sourceFailures"], [])
        incomplete = MODULE.normal_failure_diagnostics("test", "test.xcresult", subprocess.CompletedProcess([], 65, query[:-1], b""))
        self.assertEqual(incomplete["queryObservations"], [])
        many = MODULE.normal_failure_diagnostics("test", "test.xcresult", subprocess.CompletedProcess([], 65, query * 5, b""))
        self.assertEqual(len(many["queryObservations"]), 4)
        self.assertTrue(many["findingsTruncated"])
        self.assertLessEqual(len(MODULE.encoded(many)) + 1, 4096)
        long_body = b"x" * 65537 + b"\nError Domain=NSPOSIXErrorDomain Code=2\n"
        complete = MODULE.normal_failure_diagnostics("build", None, subprocess.CompletedProcess([], 65, long_body, b""))
        self.assertEqual(complete["errorCodes"][0]["code"], 2)  # Not a truncated64-KiB tail/prefix.
        for phase, selection, cap in (("build", None, 1048576), ("test", "test.xcresult", 1048576),
                                      ("summary", "test.xcresult", 262144), ("query", None, 4096)):
            with self.assertRaises(MODULE.Refused):
                MODULE.normal_failure_diagnostics(phase, selection, subprocess.CompletedProcess([], 65, b"x" * (cap + 1), b""))
        for bad in (subprocess.CompletedProcess([], 0, b"", b""), subprocess.CompletedProcess([], True, b"", b""),
                    SimpleNamespace(returncode=65, stdout=secret, stderr=b"")):
            with self.assertRaises(MODULE.Refused): MODULE.normal_failure_diagnostics("build", None, bad)
        normal = Path("/Users/runner/work/_temp/mrk-macos-installed.ABCDef12/normal-ui")
        request = MODULE.normal_request(["--normal-build"], str(normal / "tmp") + "/")
        # Main's formatter/output failures preserve a genuine COMPLETE original failure.
        # Context/owner are inert fakes here, not actual runtime/native admission.
        for fault in ("formatter", "oversize", "publication", "query"):
            with self.subTest(fault=fault), ExitStack() as stack:
                published = []
                output, errors = io.BytesIO(), io.BytesIO()
                stream = lambda buffer: SimpleNamespace(buffer=buffer, write=lambda value: buffer.write(value.encode()), flush=lambda: None)
                native = subprocess.CompletedProcess(["fixed-original"], 66 if fault == "query" else 65, secret, b"private stderr")
                for context in (
                    patch.object(MODULE.sys, "argv", ["helper", "--normal-build"]),
                    patch.object(MODULE.os, "environ", {"TMPDIR": str(normal / "tmp") + "/"}),
                    patch.object(MODULE.time, "monotonic_ns", return_value=0),
                    patch.object(MODULE, "normal_context", return_value=(Path("/inert"), "a" * 40, {}, (32 * 1024**3,) * 2)),
                    patch.object(MODULE, "load_normal_owner", return_value=SimpleNamespace(ProcessError=OSError, ProcessInterrupted=InterruptedError)),
                    patch.object(MODULE, "execute_normal_phase", side_effect=MODULE.NativeQueryFailure(native) if fault == "query" else None, return_value=native),
                    patch.object(MODULE.sys, "stdout", stream(output)), patch.object(MODULE.sys, "stderr", stream(errors)),
                ): stack.enter_context(context)
                if fault == "formatter": stack.enter_context(patch.object(MODULE, "normal_failure_diagnostics", side_effect=ValueError(secret.decode())))
                if fault == "oversize": stack.enter_context(patch.object(MODULE, "normal_failure_diagnostics", return_value={"private": "x" * 5000}))
                def publish(path, data, cap):
                    published.append((path, data, cap))
                    if fault == "publication": raise OSError("synthetic original close failure")
                stack.enter_context(patch.object(MODULE, "exclusive_output", publish))
                self.assertEqual(MODULE.main(), native.returncode)
                self.assertEqual(len(published), 1)
                self.assertNotIn(secret, published[0][1])
                self.assertLessEqual(len(published[0][1]), 4096)
                diagnostic = json.loads(published[0][1])
                self.assertEqual(diagnostic["originalReturncode"], native.returncode)
                if fault in ("formatter", "oversize"): self.assertEqual(diagnostic["status"], "unavailable")
                if fault == "query":
                    self.assertEqual(published[0][0].name, "toolchain.failure-diagnostics.json")
                    self.assertEqual(output.getvalue(), b"")
                if fault == "publication": self.assertIn(b"normal-failure-diagnostic-publication-failed\n", errors.getvalue())

    def test_dashboard_failure_diagnostics_preserve_finite_prewait_data(self):
        reasons = (
            "loading", "not-loaded", "bridge-unavailable", "selection-unavailable",
            "selection-in-progress", "shutting-down", "owner-offline-preflight",
            "owner-android-build", "owner-ios-archive", "owner-project-recovery",
            "owner-github-preflight", "owner-github-release", "owner-project-path",
            "owner-saved-version-edit", "owner-metadata-images", "other-or-unobserved", "ambiguous",
        )
        waiters = ("timed-out", "incorrect-order", "inverted-fulfillment", "interrupted", "unknown")
        self.assertEqual(len(set(reasons)), 17)
        for index, reason in enumerate(reasons):
            ordinal, line = index % 4 + 1, 1 if index % 2 == 0 else 65535
            waiter, enabled, hittable = waiters[index % 5], bool(index % 2), bool(index // 2 % 2)
            ending = b"\n" if index % 2 == 0 else b"\r\n"
            require = f"MRK_MACOS_PACKAGED_REQUIRE_FAILURE=v1;line={line};check=condition".encode()
            row = (f"MRK_MACOS_PACKAGED_DASHBOARD_FAILURE=v1;line={line};ordinal={ordinal};waiter={waiter}"
                   f";enabled={int(enabled)};hittable={int(hittable)};reason={reason};sample=pre-wait;nonAtomic=1").encode()
            with self.subTest(reason=reason, ordinal=ordinal, waiter=waiter):
                value = MODULE.normal_failure_diagnostics("test", "test.xcresult",
                    subprocess.CompletedProcess([], 65, require + ending + row + ending, b""))
                self.assertEqual(value["requireObservations"],
                    [{"source": "NormalAppUITests.swift", "line": line, "check": "condition"}])
                self.assertEqual(value["dashboardReadiness"], {
                    "stream": "stdout", "line": line, "ordinal": ordinal, "waiter": waiter,
                    "enabled": enabled, "hittable": hittable, "reason": reason,
                    "sample": "pre-wait", "nonAtomic": True})
                self.assertEqual(value["originalReturncode"], 65)
                self.assertEqual(value["status"], "classified")
                self.assertFalse(any(value["markers"].values()))  # Not a XCTest outcome or final UI state.

        require = b"MRK_MACOS_PACKAGED_REQUIRE_FAILURE=v1;line=65535;check=condition\n"
        row = (b"MRK_MACOS_PACKAGED_DASHBOARD_FAILURE=v1;line=65535;ordinal=4;waiter=inverted-fulfillment;"
               b"enabled=0;hittable=0;reason=owner-saved-version-edit;sample=pre-wait;nonAtomic=1\n")
        for phase, selection in (
                ("build", None), ("query", None), ("summary", "test.xcresult"),
                *(("test", name) for name in MODULE.NORMAL_SELECTIONS if name != "test.xcresult")):
            with self.subTest(phase=phase, selection=selection):
                value = MODULE.normal_failure_diagnostics(phase, selection,
                    subprocess.CompletedProcess([], 65, require + row, b""))
                self.assertIsNone(value["dashboardReadiness"])
                self.assertEqual(value["requireObservations"], [])
                self.assertEqual(value["originalReturncode"], 65)
        stderr_only = MODULE.normal_failure_diagnostics("test", "test.xcresult",
            subprocess.CompletedProcess([], 65, b"", require + row))
        self.assertIsNone(stderr_only["dashboardReadiness"])  # Existing normal REQUIRE remains stdout-only.
        self.assertEqual(stderr_only["requireObservations"], [])

        # Fill every existing retained category with widest public scalar values.
        query = (b"MRK_MACOS_NORMAL_DASHBOARD_QUERY=observation=containingSameStaticText;"
                 b"matches=4;exceedsFour=0;nonAtomic=1\n")
        codes = b"".join(f"Error Domain=IDETestOperationsObserverErrorDomain Code={-2147483648 + i}\n".encode()
                         for i in range(8))
        sites = b"".join(b"NormalAppUITests.swift:" + str(line).encode() + b":4096: error: "
            b"-[MRKNormalAppUITests.NormalAppUITests testLaunchCancelAndQuit] : fixture-secret\n"
            for line in range(65532, 65536))
        value = MODULE.normal_failure_diagnostics("test", "test.xcresult",
            subprocess.CompletedProcess([], 65, require + row + codes + sites + query * 4, b""))
        self.assertEqual([len(value[key]) for key in ("errorCodes", "sourceFailures", "queryObservations")],
                         [8, 4, 4])
        self.assertEqual(value["dashboardReadiness"]["waiter"], "inverted-fulfillment")
        self.assertEqual(value["dashboardReadiness"]["reason"], "owner-saved-version-edit")
        self.assertFalse(value["findingsTruncated"])
        self.assertEqual(value["originalReturncode"], 65)
        self.assertLessEqual(len(MODULE.encoded(value)) + 1, 4096)
        self.assertNotIn(b"fixture-secret", MODULE.encoded(value))

    def test_dashboard_failure_diagnostics_reject_ambiguous_or_malformed_data(self):
        require = b"MRK_MACOS_PACKAGED_REQUIRE_FAILURE=v1;line=508;check=condition\n"
        row = (b"MRK_MACOS_PACKAGED_DASHBOARD_FAILURE=v1;line=508;ordinal=1;waiter=timed-out;"
               b"enabled=0;hittable=0;reason=loading;sample=pre-wait;nonAtomic=1\n")
        site = {"source": "NormalAppUITests.swift", "line": 508, "check": "condition"}
        for stdout, stderr, expected in (
                (row, b"", []), (require, b"", [site]), (require, row, [site]), (row, require, []),
                (require.replace(b"line=508", b"line=509") + row, b"", [dict(site, line=509)]),
                (require.replace(b"condition", b"singleton") + row, b"", [dict(site, check="singleton")]),
                (require + require + row, b"", []), (require + row, require, [site]),
                (require + row + row, b"", [site]), (require + row, row, [site]),
                (require + row + row.replace(b"ordinal=1", b"ordinal=2"), b"", [site]),
                (require + row + require[:-1] + b";private=MRK_MACOS_PACKAGED_DASHBOARD_FAILURE\n", b"", [])):
            with self.subTest(stdout_bytes=len(stdout), stderr_bytes=len(stderr), expected=expected):
                value = MODULE.normal_failure_diagnostics("test", "test.xcresult",
                    subprocess.CompletedProcess([], 65, stdout, stderr))
                self.assertIsNone(value["dashboardReadiness"])
                self.assertEqual(value["requireObservations"], expected)
                self.assertEqual(value["originalReturncode"], 65)
                self.assertNotIn(b"private", MODULE.encoded(value))

        namespace = b"MRK_MACOS_PACKAGED_DASHBOARD_FAILURE"
        malformed = [row.replace(old, new, 1) for old, new in (
            (b"v1;", b"v2;"), (b"line=508", b"line=0"), (b"line=508", b"line=0508"),
            (b"line=508", b"line=65536"), (b"ordinal=1", b"ordinal=0"), (b"ordinal=1", b"ordinal=5"),
            (b"ordinal=1", b"ordinal=01"), (b"timed-out", b"completed"), (b"timed-out", b"fixture-secret"),
            (b"enabled=0", b"enabled=true"), (b"hittable=0", b"hittable=2"),
            (b"reason=loading", b"reason=fixture-secret"), (b"sample=pre-wait", b"sample=post-wait"),
            (b"reason=loading", b"reason=owner-native"), (b"reason=loading", b"reason=owner-Android-build"),
            (b"reason=loading", b"reason=owner-offline-preflight-extra"),
            (b"reason=loading", b"reason=owner-metadata-images;detail=fixture-secret"),
            (b"nonAtomic=1", b"nonAtomic=0"))]
        malformed += [row[:-1], namespace[:-1], b"fixture-secret " + namespace[:-1],
                      b"fixture-secret " + row, row[:-1] + b";extra=fixture-secret\n",
                      row[:-1] + b"\r\r\n", row.replace(namespace, namespace + b"_EXTRA")]
        for bad in malformed:
            for observations in (bad, row + bad, bad + row):
                with self.subTest(bad_bytes=len(bad), observations=len(observations)):
                    value = MODULE.normal_failure_diagnostics("test", "test.xcresult",
                        subprocess.CompletedProcess([], 65, require + observations, b""))
                    self.assertIsNone(value["dashboardReadiness"])
                    self.assertEqual(value["requireObservations"], [site])
                    self.assertEqual(value["status"], "classified")
                    self.assertEqual(value["originalReturncode"], 65)
                    self.assertNotIn(b"fixture-secret", MODULE.encoded(value))
        for bad in (namespace[:-1], row[:-1] + b";extra=fixture-secret\n"):
            value = MODULE.normal_failure_diagnostics("test", "test.xcresult",
                subprocess.CompletedProcess([], 65, require + row, bad))
            self.assertIsNone(value["dashboardReadiness"])
            self.assertEqual(value["requireObservations"], [site])
            self.assertEqual(value["status"], "classified")
            self.assertEqual(value["originalReturncode"], 65)
            self.assertNotIn(b"fixture-secret", MODULE.encoded(value))

    def test_acl_complete_source_inventory_reads_originals_at_current_native_size(self):
        workflow = (ROOT / ".github/workflows/desktop-macos-installed.yml").read_text()
        begin = "          # Fixed complete ACL SOURCE reader; logs retain their separate 128-KiB bound.\n"
        end = "          # End fixed complete ACL SOURCE reader.\n"
        self.assertEqual(workflow.count(begin), 1); self.assertEqual(workflow.count(end), 1)
        source = workflow.split(begin, 1)[1].split(end, 1)[0]
        self.assertTrue(all(not line.strip() or line.startswith("          ") for line in source.splitlines()))
        source = "\n".join(line[10:] for line in source.splitlines()) + "\n"
        namespace = dict(hashlib=hashlib, json=json, os=os, re=re, stat=stat)
        exec(compile(source, "<fixed ACL source reader only>", "exec"), namespace)
        read_sources = namespace["acl_source_hashes"]
        paths = ("desktop/native/macos-installed-native/src/native.m", "desktop/native/macos-installed-native/tests/acl_probe.m")
        current_length = len((ROOT / paths[0]).read_bytes())
        self.assertGreater(current_length, 131072); self.assertLessEqual(current_length, 262144)
        for length in (current_length, 262144):
            with self.subTest(length=length), tempfile.TemporaryDirectory(prefix="mrk-acl-source-data-") as temporary:
                root = Path(temporary)
                rows = []
                for name, size in zip(paths, (length, 73)):
                    body = b"x" * size
                    path = root / name; path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                    path.write_bytes(body); path.chmod(0o644)
                    rows.append({"path": name, "gitMode": "100644", "size": len(body), "sha256": hashlib.sha256(body).hexdigest(),
                                 "blob": hashlib.sha1(b"blob " + str(len(body)).encode() + b"\0" + body).hexdigest()})
                original = dict(source="a" * 40, tree="b" * 40, files=rows)
                inventory = root / "source-inventory.json"
                def save(value):
                    inventory.write_text(json.dumps(value)); inventory.chmod(0o600)
                save(original)
                expected = {row["path"]: row["sha256"] for row in rows}
                self.assertEqual(read_sources(str(root), str(inventory), "a" * 40, "a" * 40), expected)
                for key, bad in (("sha256", "0" * 64), ("blob", "0" * 40), ("size", length - 1),
                                 ("size", True), ("size", 262145), ("gitMode", "100755")):
                    changed = dict(original, files=[dict(rows[0], **{key: bad}), rows[1]])
                    save(changed)
                    with self.subTest(row=key), self.assertRaises(ValueError):
                        read_sources(str(root), str(inventory), "a" * 40, "a" * 40)
                save(dict(original, files=rows + [rows[0]]))
                with self.assertRaises(ValueError): read_sources(str(root), str(inventory), "a" * 40, "a" * 40)
                inventory.write_text(json.dumps(original)[:-1] + ',"source":"' + "a" * 40 + '"}')
                with self.assertRaises(ValueError): read_sources(str(root), str(inventory), "a" * 40, "a" * 40)
                save(original)
                with self.assertRaises(ValueError): read_sources(str(root), str(inventory), "a" * 40, "c" * 40)
                with self.assertRaises(ValueError): read_sources(str(root), str(inventory), "c" * 40, "c" * 40)
                native = root / paths[0]
                native.chmod(0o744)
                with self.assertRaises(ValueError): read_sources(str(root), str(inventory), "a" * 40, "a" * 40)
                native.chmod(0o644)
                link = root / "task-hardlink"; os.link(native, link)
                with self.assertRaises(ValueError): read_sources(str(root), str(inventory), "a" * 40, "a" * 40)
                link.unlink()
                native.unlink(); os.symlink(root / paths[1], native)
                with self.assertRaises(OSError): read_sources(str(root), str(inventory), "a" * 40, "a" * 40)
                native.unlink(); native.write_bytes(b"x" * (262144 + 1)); native.chmod(0o644)
                with self.assertRaises(ValueError): read_sources(str(root), str(inventory), "a" * 40, "a" * 40)
                native.write_bytes(b"x" * length)
                actual_open, actual_read, actual_close = os.open, os.read, os.close
                for fault in ("early-eof", "changed", "close"):
                    selected, closed, changed = [None], [], [False]
                    def opened(path, flags, *args, **kwargs):
                        fd = actual_open(path, flags, *args, **kwargs)
                        if str(path) == str(native):
                            self.assertTrue(flags & os.O_NOFOLLOW and flags & os.O_NONBLOCK)
                            selected[0] = fd
                        return fd
                    def reading(fd, size):
                        if fd == selected[0] and fault == "early-eof": return b""
                        data = actual_read(fd, size)
                        if fd == selected[0] and fault == "changed" and not changed[0]:
                            changed[0] = True
                            with native.open("ab") as output: output.write(b"!")
                        return data
                    def closing(fd):
                        actual_close(fd)
                        if fd == selected[0]:
                            closed.append(fd)
                            if fault == "close": raise OSError("synthetic consuming source close failure")
                    with patch.object(os, "open", opened), patch.object(os, "read", reading), patch.object(os, "close", closing):
                        with self.assertRaises((ValueError, OSError)):
                            read_sources(str(root), str(inventory), "a" * 40, "a" * 40)
                    self.assertEqual(len(closed), 1)
                    native.write_bytes(b"x" * length)


if __name__ == "__main__":
    unittest.main()
