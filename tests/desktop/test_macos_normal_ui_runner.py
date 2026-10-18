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
from contextlib import ExitStack, contextmanager
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


def applications_output():
    # Independent expected observation, deliberately NOT the ordinary-original marker.
    case = "-[MRKNormalAppUITests.NormalAppUITests testApplicationsLaunchAndQuit]"
    marker = ("MRK_MACOS_APPLICATIONS_UI=launcherRequest=1;callbackLauncher=1;payloadEvent=1;"
        "retainedIdentity=1;dashboardNavigation=1;normalQuit=1;launcherTerminated=1;eventPayloadTerminated=1;"
        "gateFree=1;gateClosed=1;failureCleanup=0;caseDeadlineMet=1;payloadRequestCorrelation=unavailable;"
        "cleanExitStatus=unavailable;allWorkerFinality=unavailable")
    return ("\n".join(("Test Case '" + case + "' started.", marker,
        "Test Case '" + case + "' passed (1.000 seconds).", ""))).encode()


def normal_project_output():
    # Literal independent roster/markers: never generated from the helper's table.
    methods = ("testSyntheticProjectLocalEditsAndImages", "testSyntheticProjectPathFields")
    markers = (
        ("MRK_MACOS_NORMAL_PROJECT_UI=project-config-workflows-text-version-images;cleanExitStatus=unavailable;allWorkerFinality=unavailable",),
        ("MRK_MACOS_NORMAL_PROJECT_FIELDS_UI=ordinary-four-field-browse-two-cancels-draft-only-invalid-pair-observed;cleanExitStatus=unavailable;allWorkerFinality=unavailable",
         "MRK_MACOS_NORMAL_ANDROID_SOURCE_UI=ordinary-jdk-sdk-gradle-native-cancel-jdk-reselect-backend-source-refused-selection-only;cleanExitStatus=unavailable;allWorkerFinality=unavailable"),
    )
    lines = []
    for method, case_markers in zip(methods, markers):
        selected = "-[MRKNormalAppUITests.NormalAppUITests " + method + "]"
        lines.extend(("Test Case '" + selected + "' started.", MODULE.ORIGINAL_MARKER, *case_markers,
                      "Test Case '" + selected + "' passed (1.000 seconds)."))
    return ("\n".join(lines) + "\n").encode()


def normal_workflow_refusal_output():
    # Independent literal returned-output fixture; no native command is run.
    selected = "-[MRKNormalAppUITests.NormalAppUITests testSyntheticProjectManagedWorkflowRefusal]"
    return ("\n".join(("Test Case '" + selected + "' started.", MODULE.ORIGINAL_MARKER,
        "MRK_MACOS_NORMAL_WORKFLOW_REFUSAL_UI=ordinary-preview-customized-candidate-whole-bundle-refused-originals-preserved;cleanExitStatus=unavailable;allWorkerFinality=unavailable",
        "Test Case '" + selected + "' passed (1.000 seconds).", ""))).encode()


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

    def test_android_verification_resource_is_fixed_without_widening_normal_fixture_limits(self):
        # Actual public SOURCE/DATA only; this does not execute the Swift reader.
        import base64
        import xml.etree.ElementTree as ET
        native = ROOT / "desktop/native/macos-normal-ui"
        fixtures = native / "MRKNormalAppUITests/Fixtures"
        name = "android-positive-verification-v1.xml"
        xml = (fixtures / name).read_bytes()
        digest = "5d00856c785363da964e00da72ad38571cfd088da915ebe86cf20640bb1c7545"
        self.assertEqual((len(xml), hashlib.sha256(xml).hexdigest()), (90045, digest))
        self.assertGreater(len(xml), 32 * 1024)
        self.assertEqual(len(base64.b64encode(xml)), 120060)
        self.assertGreater(len(base64.b64encode(xml)), 64 * 1024)
        self.assertNotIn(b"<!DOCTYPE", xml)
        self.assertNotIn(b"<!ENTITY", xml)
        tree = ET.fromstring(xml)
        ns = "{https://schema.gradle.org/dependency-verification}"
        self.assertEqual(tree.tag, ns + "verification-metadata")
        self.assertEqual(tree.findtext(ns + "configuration/" + ns + "verify-metadata"), "true")
        components = tree.findall(ns + "components/" + ns + "component")
        self.assertEqual(len(components), 234)
        artifacts = [artifact for component in components for artifact in component.findall(ns + "artifact")]
        self.assertEqual(len(artifacts), 386)
        self.assertTrue(all(len(artifact.findall(ns + "sha256")) == 1
                            and re.fullmatch(r"[0-9a-f]{64}", artifact.find(ns + "sha256").get("value", ""))
                            for artifact in artifacts))
        # Both old bundled JSON fixtures are unchanged, not repackaged with a
        # larger decoder or a base64 copy of this XML.
        for filename, length, expected in (
            ("normal-project-v1.json", 19560, "ea9b004f0026c053bc1a12607cc70bd0a6f7e07afe9f33cf2a17506de62d512c"),
            ("normal-persistence-v1.json", 10690, "99965739ae4dedf7de4dbc4c20d519eeea31e7a7eaab59484c5969f8cb03cce4"),
        ):
            with self.subTest(fixture=filename):
                raw = (fixtures / filename).read_bytes()
                self.assertEqual((len(raw), hashlib.sha256(raw).hexdigest()), (length, expected))
                self.assertLessEqual(len(raw), 64 * 1024)
                spec = json.loads(raw)
                values = [*spec["files"].values(), *[value for stage in spec["stages"].values() for value in stage.values()]]
                decoded = [base64.b64decode(value, validate=True) for value in values]
                self.assertTrue(all(len(value) <= 32 * 1024 for value in decoded))
                self.assertLessEqual(sum(map(len, decoded)), 256 * 1024)
                self.assertNotIn("project/gradle/verification-metadata.xml", spec["files"])

        # Public positive PROJECT only: genuine A9 + B2 locks + five normal
        # user/locale sentinels. No supplier, private key or runtime handoff is
        # part of this bundled DATA; current generic preparation is unchanged.
        positive_raw = (fixtures / "normal-android-positive-v1.json").read_bytes()
        self.assertEqual((len(positive_raw), hashlib.sha256(positive_raw).hexdigest()),
                         (15695, "f0936a01330d095da8863571d78c1580e037d6d2a69d26c19a31814ffa251f4e"))
        self.assertLessEqual(len(positive_raw), 64 * 1024)
        positive = json.loads(positive_raw)
        self.assertEqual(set(positive), {"schemaVersion", "files", "stages"})
        self.assertIs(type(positive["schemaVersion"]), int)
        self.assertEqual(positive["schemaVersion"], 1)
        self.assertEqual(positive["stages"], {})
        self.assertEqual((json.dumps(positive, sort_keys=True, indent=2, ensure_ascii=True) + "\n").encode(),
                         positive_raw)
        expected_positive = {
            'project/.github/workflows/keep-user.yml': (76, '365244a6298332816ce5faeca4c2d8445fb29d887f981b0666ea32da005d742a'),
            'project/.gitignore': (48, 'b4babbcd85071657df35045a4bc38c465e1720a96ffe4a07c4c2d6504e1d2cc8'),
            'project/README-user.txt': (56, '3a6675d287793428f05e033457dbb6ca839a008fc6f70423f67ebddab9cb58f5'),
            'project/app/build.gradle': (915, 'b78bad2b96b50b6613ed6c55c34be35a8b49842b595d447ad2a8c59fd1455f35'),
            'project/app/gradle.lockfile': (326, 'b8ca8e27e9b203531b6bd0d08c8d9a906ba8fecf63a7797fbbb64cd34e316ec4'),
            'project/app/src/main/AndroidManifest.xml': (306, 'dba12a22f84ec6f275f99979263344b25ba8c45131520648e1a8adb86695eb8d'),
            'project/app/src/main/java/org/example/saved/MainActivity.java': (93, '8177c62171176ac7756a85bff7180eeb10f56d02465adc8c3e6ef979d3f96f96'),
            'project/build.gradle': (674, '94666f4e4fe591e43c78929a5765c38c4b1553665f49834121f872f811232759'),
            'project/buildscript-gradle.lockfile': (6566, 'ff53ec4b7427f2da997ed040dd338b0086c856564fe7001a0d030583c778ac85'),
            'project/gradle/wrapper/gradle-wrapper.properties': (168, 'ef6da5202b4ca5bc4564e427bfcff6c2f761cbf761367f9ea561bf5141e33628'),
            'project/release/mobile-release.json': (733, 'a64b904e27dac9df06377c7ad5d1f79988df3eec6295f689d2a5ead7c4d52144'),
            'project/release/store/android/en-US/full_description.txt': (79, '61a57bfd859d0fd1fded8756580f38f51dc66c19e8ca6163588c1840aaf0584b'),
            'project/release/store/android/en-US/short_description.txt': (49, '66f1806ac841eb119d3e3a9cfcb7218ab76d88c6120f7e7db43929933dbdea5c'),
            'project/release/store/android/en-US/title.txt': (15, '8f06c2070f1e3f84db731b2a1ff568a06f18916dd7f24e75aa6e8a6359b629b3'),
            'project/release/version.properties': (34, 'a811da0677c243236101fb4aa93319d28b731f963f8a295c1028b8aee136386b'),
            'project/settings.gradle': (991, '0238825f1dccf203000d3cc80f5a4d1987b0456835f9c745efe25767f66901ea'),
        }
        self.assertEqual(set(positive["files"]), set(expected_positive))
        positive_files = {path: base64.b64decode(value, validate=True)
                          for path, value in positive["files"].items()}
        self.assertEqual(len(positive_files), 16)
        for path, (length, expected_sha) in expected_positive.items():
            with self.subTest(positive_file=path):
                raw = positive_files[path]
                self.assertEqual((len(raw), hashlib.sha256(raw).hexdigest()), (length, expected_sha))
                self.assertEqual(base64.b64encode(raw).decode("ascii"), positive["files"][path])
                self.assertGreater(len(raw), 0)
                self.assertLessEqual(len(raw), 32 * 1024)
        positive_directories = {"/".join(path.split("/")[:depth]) for path in positive_files
                                for depth in range(1, len(path.split("/")))}
        self.assertEqual(len(positive_directories), 16)
        self.assertEqual(sum(map(len, positive_files.values())), 11129)
        self.assertEqual(max(map(len, positive_files.values())), 6566)
        self.assertNotIn("project/gradle/verification-metadata.xml", positive_files)
        self.assertEqual(sum(map(len, positive_files.values())) + len(xml), 101174)
        self.assertLessEqual(sum(map(len, positive_files.values())) + len(xml), 256 * 1024)

        positive_config = json.loads(positive_files["project/release/mobile-release.json"])
        self.assertEqual(positive_config["version"], {"source": "release/version.properties",
                         "nameKey": "VERSION_NAME", "buildKey": "BUILD_NUMBER"})
        self.assertEqual(positive_config["android"], {"enabled": True, "module": ":app", "variant": "release",
                         "applicationId": "org.example.saved", "identityStatus": "unverified"})
        self.assertEqual(positive_config["ios"], {"enabled": False})
        self.assertEqual(positive_config["source"], {"candidateBranch": "main", "productionBranch": "main"})
        self.assertEqual(positive_config["services"], {"androidFirebase": "disabled", "iosFirebase": "disabled"})
        self.assertEqual(positive_config["projectChecks"], {"preflight": [], "androidArtifact": [], "iosArtifact": []})
        self.assertEqual(positive_config["metadata"], {"root": "release/store", "androidLocales": ["en-US"],
                         "iosLocales": []})
        self.assertEqual(positive_files["project/release/version.properties"], b"VERSION_NAME=1.2.3\nBUILD_NUMBER=7\n")
        # The public starting config intentionally lacks the same-job signer
        # fingerprint. The later ordinary UI must save the real public cert;
        # this fixture cannot fabricate signing approval or a private asset.
        self.assertNotIn("uploadCertificateSha256", positive_config["android"])
        self.assertNotIn("signing", positive_config)
        positive_app = positive_files["project/app/build.gradle"].decode("utf-8")
        for required in (
            "namespace 'org.example.saved'", "applicationId 'org.example.saved'",
            "compileSdk 35", "buildToolsVersion '35.0.0'", "minSdk 23", "targetSdk 35",
            "versionCode Integer.parseInt(System.getenv('MOBILE_RELEASE_BUILD_NUMBER'))",
            "versionName System.getenv('MOBILE_RELEASE_VERSION_NAME')", "debuggable false",
        ):
            self.assertIn(required, positive_app)
        self.assertNotIn("signingConfig", positive_app)
        positive_manifest = ET.fromstring(positive_files["project/app/src/main/AndroidManifest.xml"])
        self.assertEqual(positive_manifest.tag, "manifest")
        positive_application = positive_manifest.find("application")
        self.assertIsNotNone(positive_application)
        android_ns = "{http://schemas.android.com/apk/res/android}"
        self.assertNotIn(android_ns + "debuggable", positive_application.attrib)
        self.assertEqual(positive_application.get(android_ns + "testOnly"), "false")
        self.assertEqual(positive_application.find("activity").get(android_ns + "name"), ".MainActivity")
        self.assertEqual(positive_files["project/app/src/main/java/org/example/saved/MainActivity.java"],
                         b"package org.example.saved;\n\npublic final class MainActivity extends android.app.Activity {\n}\n")
        positive_settings = positive_files["project/settings.gradle"].decode("utf-8")
        positive_build = positive_files["project/build.gradle"].decode("utf-8")
        for required in ("DependencyVerificationMode.STRICT", "file('gradle/verification-metadata.xml').isFile()",
                         "rootProject.name = 'MacAndroidSignedBuildFixture'", "include(':app')"):
            self.assertIn(required, positive_settings)
        for required in ("classpath 'com.android.tools.build:gradle:8.9.2'",
                         "resolutionStrategy.activateDependencyLocking()", "lockAllConfigurations()",
                         "lockMode = LockMode.STRICT"):
            self.assertIn(required, positive_build)
        for forbidden in ("--write-locks", "--write-verification-metadata", "failOnNonReproducibleResolution"):
            self.assertNotIn(forbidden, positive_settings + positive_build + positive_app)
        self.assertEqual(positive_files["project/gradle/wrapper/gradle-wrapper.properties"].decode("ascii").splitlines(), [
            r"distributionUrl=https\://services.gradle.org/distributions/gradle-8.14.5-bin.zip",
            "distributionSha256Sum=6f74b601422d6d6fc4e1f9a1ab6522f642c2fdcbc15ae33ebd30ba3d7198e854",
        ])
        self.assertEqual(positive_files["project/.gitignore"], b"/.mobile-release/\n/.gradle/\n/build/\n/app/build/\n")

        lock_header = ["# This is a Gradle generated file for dependency locking.",
                       "# Manual edits can break the build and are not advised.",
                       "# This file is expected to be part of source control."]
        root_lock = positive_files["project/buildscript-gradle.lockfile"].decode("ascii").splitlines()
        app_lock = positive_files["project/app/gradle.lockfile"].decode("ascii").splitlines()
        self.assertEqual(root_lock[:3], lock_header)
        self.assertEqual(root_lock[-1], "empty=")
        root_locked = root_lock[3:-1]
        self.assertEqual(len(root_locked), 123)
        self.assertEqual(root_locked, sorted(set(root_locked)))
        self.assertTrue(all(row.endswith("=classpath") and row.count("=") == 1 for row in root_locked))
        self.assertIn("com.android.tools.build:gradle:8.9.2=classpath", root_locked)
        xml_coordinates = {(row.get("group"), row.get("name"), row.get("version")) for row in components}
        self.assertTrue(all(tuple(row.removesuffix("=classpath").split(":")) in xml_coordinates for row in root_locked))
        self.assertEqual(app_lock, lock_header + [
            "empty=androidApis,androidJdkImage,lintChecks,releaseAnnotationProcessorClasspath,"
            "releaseCompileClasspath,releaseReverseMetadataValues,releaseRuntimeClasspath"
        ])
        self.assertEqual(len(app_lock[3].removeprefix("empty=").split(",")), 7)
        normal_public = json.loads((fixtures / "normal-project-v1.json").read_bytes())
        for path in ("project/README-user.txt", "project/.github/workflows/keep-user.yml",
                     "project/release/store/android/en-US/title.txt",
                     "project/release/store/android/en-US/short_description.txt",
                     "project/release/store/android/en-US/full_description.txt"):
            self.assertEqual(positive_files[path], base64.b64decode(normal_public["files"][path], validate=True))
        for name, limit in (("title", 30), ("short_description", 80), ("full_description", 4000)):
            text = positive_files[f"project/release/store/android/en-US/{name}.txt"].decode("utf-8")
            self.assertTrue(text.strip())
            self.assertLessEqual(len(text.rstrip("\n")), limit)

    def test_android_output_custody_is_bounded_without_activating_a_profile(self):
        import base64
        fixture_path = SWIFT.parent / "Fixtures/normal-ios-unsigned-v1.json"
        body = fixture_path.read_bytes()
        self.assertEqual((len(body), hashlib.sha256(body).hexdigest()),
                         (10237, "999a48f946b2a26164d250086d5ece7588f3ff9b2b88824e596168b82faa8daf"))
        fixture = json.loads(body)
        self.assertEqual(set(fixture), {"schemaVersion", "files", "stages"})
        self.assertEqual(fixture["stages"], {})
        decoded = {key: base64.b64decode(value, validate=True) for key, value in fixture["files"].items()}
        self.assertEqual((len(decoded), sum(map(len, decoded.values())), max(map(len, decoded.values()))), (9, 7264, 3903))
        self.assertEqual(set(decoded), {"project/.gitignore", "project/keep.txt", "project/release/mobile-release.json",
            "project/release/version.properties", "project/ios/MRKObserved.xcodeproj/project.pbxproj",
            "project/ios/MRKObserved.xcodeproj/xcshareddata/xcschemes/MRKObserved.xcscheme",
            "project/ios/MRKObserved.xcodeproj/project.xcworkspace/contents.xcworkspacedata",
            "project/ios/MRKObserved/main.m", "project/ios/MRKObserved/Info.plist"})
        self.assertNotIn(MODULE.IOS_UNSIGNED_RESULT, MODULE.NORMAL_SELECTIONS)

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
        # One separately selected unsigned iOS original; it is not part of the
        # seven ordinary groups and cannot borrow an arbitrary 900s allowance.
        temporary = "/Users/runner/work/_temp/mrk-macos-installed.ABCDef12/normal-ui/tmp/"
        normal = Path(temporary).parent
        selected = MODULE.CLASS + "testSyntheticProjectUnsignedIOSArchive"
        self.assertEqual(MODULE.IOS_UNSIGNED_METHOD, "testSyntheticProjectUnsignedIOSArchive")
        self.assertNotIn(MODULE.IOS_UNSIGNED_RESULT, MODULE.NORMAL_SELECTIONS)
        self.assertEqual(len(MODULE.NORMAL_SELECTIONS), 9)
        for target, machine in ((MODULE.ARM_TARGET, "arm64"), (MODULE.INTEL_TARGET, "x86_64")):
            request = MODULE.normal_request(["--target", target, "--normal-ios-unsigned-archive-test"], temporary)
            self.assertEqual(request, dict(phase="test", derived=normal / "DerivedData",
                result=normal / "ios-unsigned-archive-test.xcresult", methods=(selected,), allowance=900,
                timeout=1020, phaseSeconds=1245, iosUnsigned=True, target=target))
            summary = MODULE.normal_request(["--target", target, "--normal-ios-unsigned-archive-summary"], temporary)
            self.assertEqual(summary, dict(request, phase="summary", methods=(), allowance=None,
                                           timeout=30, phaseSeconds=90))
            command = MODULE.xcode_test_arguments(Path("fixed.xctestrun"), request["result"],
                                                  (selected,), 900, target=target, ios_unsigned=True)
            self.assertEqual(command, ["/usr/bin/xcodebuild", "test-without-building", "-xctestrun", "fixed.xctestrun",
                "-destination", "platform=macOS" if machine == "x86_64" else "platform=macOS,arch=" + machine, "-destination-timeout", "15",
                "-resultBundlePath", str(request["result"]), "-only-testing:" + selected,
                "-parallel-testing-enabled", "NO", "-test-timeouts-enabled", "YES",
                "-default-test-execution-time-allowance", "900", "-maximum-test-execution-time-allowance", "900",
                "-disableAutomaticPackageResolution"])
        for arguments in (["--normal-ios-unsigned-archive-test", "extra"],
                          ["--normal-ios-unsigned-archive-summary", "ios-unsigned-archive-test.xcresult"],
                          ["--normal-ios-unsigned-archive-test", "--retry"],
                          ["--normal-ios-unsigned-archive-test", "--target", MODULE.ARM_TARGET]):
            with self.subTest(ios_arguments=arguments), self.assertRaises(MODULE.Refused):
                MODULE.normal_request(arguments, temporary)
        for changed in (dict(ios_unsigned=False), dict(ios_unsigned=1), dict(engineering=True),
                        dict(output_data=True), dict(android_positive=True), dict(allowance=300),
                        dict(allowance=True), dict(methods=(MODULE.OUTPUT_DATA_METHOD,)),
                        dict(methods=(selected, selected)), dict(result=normal / "test.xcresult")):
            values = dict(methods=(selected,), allowance=900, result=normal / MODULE.IOS_UNSIGNED_RESULT,
                          ios_unsigned=True)
            values.update(changed)
            with self.subTest(ios_arguments=changed), self.assertRaises(MODULE.Refused):
                MODULE.xcode_test_arguments(Path("fixed.xctestrun"), **values)
        for changed in (dict(ios_unsigned=1), dict(engineering=True), dict(output_data=True),
                        dict(android_positive=True), dict(allowance=300), dict(timeout=900),
                        dict(methods=(MODULE.OUTPUT_DATA_METHOD,)), dict(result=normal / "test.xcresult")):
            values = dict(methods=(selected,), allowance=900, timeout=1020, result=normal / MODULE.IOS_UNSIGNED_RESULT,
                          ios_unsigned=True)
            values.update(changed)
            with self.subTest(ios_owner=changed), patch.object(MODULE, "RunnerProducts") as unopened:
                with self.assertRaises(MODULE.Refused):
                    MODULE.run_admitted_test(lambda *_: self.fail("invalid iOS original dispatched"),
                                             normal / "DerivedData", **values)
                unopened.assert_not_called()

        # Removal remains a separate closed in-process owner, never an ordinary CLI selector.
        for case in ("ordinary", "abrupt"):
            method, result_name = MODULE.removal_selection(case)
            values = dict(methods=(method,), allowance=300, result=normal / result_name, removal_case=case)
            for selected_target, destination in ((MODULE.ARM_TARGET, "platform=macOS,arch=arm64"),
                                                 (MODULE.INTEL_TARGET, "platform=macOS")):
                command = MODULE.xcode_test_arguments(Path("fixed.xctestrun"), **dict(values, target=selected_target))
                self.assertEqual([v for v in command if v.startswith("-only-testing:")], ["-only-testing:" + method])
                self.assertEqual(command[command.index("-destination") + 1], destination)
                # Admission reaches only the existing product owner, not a native child.
                class ReachedProducts(Exception): pass
                with patch.object(MODULE, "RunnerProducts", side_effect=ReachedProducts):
                    with self.assertRaises(ReachedProducts):
                        MODULE.run_admitted_test(lambda *_: self.fail("no native work"), normal / "DerivedData",
                            timeout=420, **dict(values, target=selected_target))
            self.assertNotIn(result_name, MODULE.NORMAL_SELECTIONS)
            for changed in (dict(removal_case=None), dict(removal_case=True), dict(removal_case="unknown"),
                            dict(target="x86_64h-apple-darwin"), dict(engineering=True), dict(output_data=True),
                            dict(android_positive=True), dict(ios_unsigned=True), dict(allowance=60),
                            dict(methods=(method, method)), dict(result=normal / "test.xcresult")):
                with self.subTest(removal=case, changed=changed), self.assertRaises(MODULE.Refused):
                    MODULE.xcode_test_arguments(Path("fixed.xctestrun"), **dict(values, **changed))
            with patch.object(MODULE, "RunnerProducts") as unopened:
                for timeout in (True, 419, 421):
                    with self.assertRaises(MODULE.Refused):
                        MODULE.run_admitted_test(lambda *_: self.fail("invalid removal dispatched"),
                            normal / "DerivedData", timeout=timeout, **values)
                unopened.assert_not_called()
            with self.assertRaises(MODULE.Refused):
                MODULE.normal_request(["--normal-summary", result_name], temporary)


    def test_project_batch_is_exactly_two_methods_with_existing_finite_deadlines(self):
        expected = ("testSyntheticProjectLocalEditsAndImages", "testSyntheticProjectPathFields")
        self.assertEqual(MODULE.NORMAL_SELECTIONS["project-test.xcresult"], (expected, 300, 720))
        arguments = normal_arguments("project-test.xcresult")
        derived, result, methods, allowance, timeout = MODULE.normal_cli_arguments(arguments)
        self.assertEqual(methods, tuple(MODULE.CLASS + method for method in expected))
        temporary = str(derived.parent / "tmp") + "/"
        self.assertEqual(MODULE.normal_request(arguments, temporary)["phaseSeconds"], 885)
        fixed = MODULE.xcode_test_arguments("/fixed.xctestrun", result, methods, allowance)
        self.assertEqual([item for item in fixed if item.startswith("-only-testing:")],
                         ["-only-testing:" + method for method in methods])
        for changed in (arguments[:15] + arguments[16:], arguments[:16] + arguments[17:],
                        arguments[:16] + arguments[15:16] + arguments[16:],
                        [item.replace("testSyntheticProjectPathFields", "testSyntheticProjectLocalEdits")
                         for item in arguments],
                        arguments[:15] + list(reversed(arguments[15:17])) + arguments[17:]):
            with self.subTest(selection=changed[15:18]), self.assertRaises(MODULE.Refused):
                MODULE.normal_cli_arguments(changed)

    def test_project_output_requires_both_originals_exact_attempts_and_terminal_markers(self):
        output = normal_project_output()
        self.assertIs(MODULE.normal_project_markers(output), True)
        original = MODULE.ORIGINAL_MARKER.encode() + b"\n"
        markers = [line + b"\n" for line in output.splitlines()
                   if line.startswith((b"MRK_MACOS_NORMAL_PROJECT", b"MRK_MACOS_NORMAL_ANDROID_SOURCE_UI="))]
        self.assertEqual(len(markers), 3)
        started = [line + b"\n" for line in output.splitlines() if line.endswith(b"' started.")]
        passed = [line + b"\n" for line in output.splitlines() if b"' passed (" in line]
        bad = [b"", b"x" * (1024 * 1024 + 1), output.replace(original, b"", 1), output + original,
               output + b"MRK_MACOS_UI_FAILURE_CLEANUP=normalRequested=true\n",
               output.replace(b"completion=1", b"completion=0", 1),
               output.replace(b"testSyntheticProjectPathFields", b"testUnexpectedProjectMethod"),
               output.replace(b"MRKNormalAppUITests.NormalAppUITests", b"OtherTests.OtherClass"),
               output.replace(b"passed (1.000 seconds).", b"failed (1.000 seconds).", 1),
               output.replace(b"passed (1.000 seconds).", b"passed (... seconds).", 1),
               output.replace(b"backend-source-refused-selection-only", b"cancelled-selection-only")]
        for row in markers + started + passed:
            bad.extend((output.replace(row, b"", 1), output + row))
        for body in bad:
            with self.subTest(bytes=len(body)), self.assertRaises(MODULE.Refused):
                MODULE.normal_project_markers(body)
        for body in (None, "not bytes", bytearray(output)):
            with self.assertRaises(MODULE.Refused): MODULE.normal_project_markers(body)
        with self.assertRaises(UnicodeDecodeError): MODULE.normal_project_markers(output + b"\xff")

    def test_project_marker_admission_gates_zero_only_and_preserves_original_nonzero(self):
        arguments = normal_arguments("project-test.xcresult")
        request = MODULE.normal_request(arguments, str(Path(arguments[12]).parent / "tmp") + "/")
        clock = SimpleNamespace(before_publication=lambda: {}, check=lambda: None)
        phase = SimpleNamespace(call=lambda *args: self.fail("no native execution"), records=[], clock=clock, environment={})
        for status, output in ((0, normal_project_output()), (0, b"missing original markers"), (65, b"native failed")):
            original = subprocess.CompletedProcess([], status, output, b"")
            with self.subTest(status=status, bytes=len(output)), \
                    patch.object(MODULE, "normal_source_state", return_value={"inert": "source"}), \
                    patch.object(MODULE, "run_admitted_test", return_value=(original, {})), \
                    patch.object(MODULE, "exclusive_output") as publish, \
                    patch.object(MODULE, "normal_project_markers", wraps=MODULE.normal_project_markers) as parse:
                if status == 0 and output != normal_project_output():
                    with self.assertRaises(MODULE.Refused):
                        MODULE.execute_normal_phase(phase, request, "a" * 40, (1024**3,) * 2)
                    publish.assert_not_called()
                    continue
                self.assertIs(MODULE.execute_normal_phase(phase, request, "a" * 40, (1024**3,) * 2), original)
                receipt = json.loads(publish.call_args.args[1])
                self.assertEqual(receipt["originalTestReturncode"], status)
                if status == 0:
                    self.assertIs(receipt["projectFieldAndEditMarkersObserved"], True)
                    self.assertIs(receipt["androidToolSourceBrowseMarkerObserved"], True)
                    parse.assert_called_once_with(output)
                else:
                    self.assertNotIn("projectFieldAndEditMarkersObserved", receipt)
                    self.assertNotIn("androidToolSourceBrowseMarkerObserved", receipt)
                    parse.assert_not_called()

    def test_applications_observation_is_one_fixed_same_budget_selection(self):
        name = "applications-test.xcresult"
        self.assertEqual(MODULE.NORMAL_SELECTIONS[name], (("testApplicationsLaunchAndQuit",), 60, 180))
        self.assertEqual(MODULE.NORMAL_SELECTIONS["test.xcresult"], (("testLaunchCancelAndQuit",), 60, 180))
        for target_value, machine in ((MODULE.ARM_TARGET, "arm64"), (MODULE.INTEL_TARGET, "x86_64")):
            args = normal_arguments(name)
            args[8] = "platform=macOS,arch=" + machine
            temporary = str(Path(args[12]).parent / "tmp") + "/"
            request = MODULE.normal_request(["--target", target_value, *args], temporary)
            self.assertEqual((request["allowance"], request["timeout"], request["phaseSeconds"]), (60, 180, 345))
            command = MODULE.xcode_test_arguments("/inert/runner.xctestrun", request["result"],
                request["methods"], request["allowance"], target=target_value)
            self.assertEqual([item for item in command if item.startswith("-only-testing:")],
                ["-only-testing:MRKNormalAppUITests/NormalAppUITests/testApplicationsLaunchAndQuit"])
            summary = MODULE.normal_request(["--target", target_value, "--normal-summary", name], temporary)
            self.assertEqual((summary["phase"], summary["timeout"]), ("summary", 30))
            self.assertEqual(MODULE.SUMMARY_STEMS[name], "applications-summary")
            for wrong in (args[:15] + ["-only-testing:" + MODULE.CLASS + "testLaunchCancelAndQuit"] + args[16:],
                          args + ["-only-testing:" + MODULE.CLASS + "testLaunchCancelAndQuit"],
                          [item.replace("applications-test.xcresult", "foreign-test.xcresult") for item in args],
                          ["300" if item == "60" else item for item in args]):
                with self.assertRaises(MODULE.Refused): MODULE.normal_cli_arguments(wrong, target=target_value)

    def test_applications_observation_marker_and_summary_are_not_original_authority(self):
        output = applications_output()
        self.assertIs(MODULE.applications_ui_markers(output), True)
        rows = output.splitlines(keepends=True)
        for bad in (b"", output + rows[1], output + rows[0], output.replace(rows[1], b""),
                    rows[1] + rows[0] + rows[2], rows[0] + rows[2] + rows[1],
                    output.replace(b"testApplicationsLaunchAndQuit", b"testLaunchCancelAndQuit"),
                    output.replace(b" passed ", b" skipped "),
                    output.replace(b"payloadEvent=1", b"payloadEvent=2"),
                    output.replace(b"payloadRequestCorrelation=unavailable", b"payloadRequestCorrelation=1"),
                    output + MODULE.ORIGINAL_MARKER.encode() + b"\n",
                    output + b"MRK_MACOS_APPLICATIONS_UI_FAILURE=launcherCleanupOnly=1\n",
                    output + b"MRK_MACOS_UI_FAILURE_CLEANUP=normalRequested=1\n"):
            with self.subTest(bytes=len(bad)), self.assertRaises(MODULE.Refused):
                MODULE.applications_ui_markers(bad)
        expected = {"totalTestCount": 1, "passedTests": 1, "failedTests": 0, "skippedTests": 0, "expectedFailures": 0}
        self.assertEqual(MODULE.applications_ui_summary(json.dumps(expected).encode()), expected)
        for key in expected:
            for value in (True, expected[key] + 1):
                with self.subTest(key=key, value=value), self.assertRaises(MODULE.Refused):
                    MODULE.applications_ui_summary(json.dumps(dict(expected, **{key: value})).encode())
        with self.assertRaises(MODULE.Refused): MODULE.applications_ui_summary(b"{}")

    def test_applications_phase_requires_its_original_zero_marker_and_summary(self):
        args = normal_arguments("applications-test.xcresult")
        request = MODULE.normal_request(args, str(Path(args[12]).parent / "tmp") + "/")
        clock = SimpleNamespace(before_publication=lambda: {}, check=lambda: None)
        phase = SimpleNamespace(call=lambda *args: self.fail("no native execution"), records=[], clock=clock, environment={})
        for status, output in ((0, applications_output()), (0, b"no observation"), (65, b"native failed")):
            original = subprocess.CompletedProcess([], status, output, b"")
            with self.subTest(status=status), patch.object(MODULE, "normal_source_state", return_value={"inert": "source"}), \
                 patch.object(MODULE, "run_admitted_test", return_value=(original, {})), \
                 patch.object(MODULE, "exclusive_output") as publish:
                if status == 0 and output != applications_output():
                    with self.assertRaises(MODULE.Refused):
                        MODULE.execute_normal_phase(phase, request, "a" * 40, (1024**3,) * 2)
                    publish.assert_not_called()
                else:
                    self.assertIs(MODULE.execute_normal_phase(phase, request, "a" * 40, (1024**3,) * 2), original)
                    receipt = json.loads(publish.call_args.args[1])
                    self.assertEqual(receipt["originalTestReturncode"], status)
                    self.assertEqual(receipt.get("applicationsLaunchObservationMarker"), True if status == 0 else None)
        with tempfile.TemporaryDirectory() as directory:
            normal = Path(directory) / "normal-ui"
            result = normal / "applications-test.xcresult"
            result.mkdir(parents=True)
            request = MODULE.normal_request(["--normal-summary", result.name], str(normal / "tmp") + "/")
            counts = {"totalTestCount": 1, "passedTests": 1, "failedTests": 0, "skippedTests": 0, "expectedFailures": 0}
            for status, body in ((0, json.dumps(counts).encode()), (0, b"{}"), (65, b"native failed")):
                original = subprocess.CompletedProcess([], status, body, b"")
                phase.call = lambda *args: original # Inert native boundary; real phase/count handling below.
                with self.subTest(summary=status, body=body), \
                     patch.object(MODULE, "normal_source_state", return_value={"inert": "source"}), \
                     patch.object(MODULE, "exclusive_output") as publish:
                    if status == 0 and body == b"{}":
                        with self.assertRaises(MODULE.Refused):
                            MODULE.execute_normal_phase(phase, request, "a" * 40, (1024**3,) * 2)
                        publish.assert_not_called()
                    else:
                        self.assertIs(MODULE.execute_normal_phase(phase, request, "a" * 40, (1024**3,) * 2), original)
                        receipt = json.loads(publish.call_args.args[1])
                        self.assertEqual(receipt.get("applicationsObservedTestCounts"), counts if status == 0 else None)

    def test_workflow_refusal_selection_is_opt_in_and_preserves_all_old_budgets(self):
        old = {
            "test.xcresult": (("testLaunchCancelAndQuit",), 60, 180),
            "project-test.xcresult": (("testSyntheticProjectLocalEditsAndImages",
                                      "testSyntheticProjectPathFields"), 300, 720),
            "persistence-test.xcresult": (("testSyntheticPersistentCredentials",), 300, 420),
            "diagnostics-test.xcresult": (("testSyntheticProjectBuildToolDiagnostics",), 300, 420),
            "saved-checks-test.xcresult": (("testSyntheticProjectSavedOfflineChecks",
                                          "testSyntheticProjectEmptyBuildInputInspection"), 300, 720),
        }
        result_name = "workflow-refusal-test.xcresult"
        self.assertEqual({name: value for name, value in MODULE.NORMAL_SELECTIONS.items() if name not in (result_name, "saved-version-recovery-test.xcresult", "release-evidence-test.xcresult", "applications-test.xcresult")}, old)
        self.assertEqual(MODULE.NORMAL_SELECTIONS[result_name],
                         (("testSyntheticProjectManagedWorkflowRefusal",), 300, 420))
        arguments = normal_arguments(result_name)
        derived, result, methods, allowance, timeout = MODULE.normal_cli_arguments(arguments)
        self.assertEqual((methods, allowance, timeout),
                         ((MODULE.CLASS + "testSyntheticProjectManagedWorkflowRefusal",), 300, 420))
        temporary = str(derived.parent / "tmp") + "/"
        self.assertEqual(MODULE.normal_request(arguments, temporary)["phaseSeconds"], 585)
        summary = MODULE.normal_request(["--normal-summary", result_name], temporary)
        self.assertEqual((summary["phase"], summary["result"], summary["timeout"], summary["phaseSeconds"]),
                         ("summary", result, 30, 90))
        self.assertEqual(MODULE.SUMMARY_STEMS[result_name], "workflow-refusal-summary")
        fixed = MODULE.xcode_test_arguments("/fixed.xctestrun", result, methods, allowance)
        self.assertEqual([arg for arg in fixed if arg.startswith("-only-testing:")],
                         ["-only-testing:" + MODULE.CLASS + "testSyntheticProjectManagedWorkflowRefusal"])
        for changed in (
            arguments[:15] + arguments[16:],
            arguments[:16] + arguments[15:16] + arguments[16:],
            arguments + ["-retry-tests-on-failure"],
            [arg.replace("testSyntheticProjectManagedWorkflowRefusal", "testSyntheticProjectLocalEditsAndImages")
             for arg in arguments],
            [arg.replace("workflow-refusal-test.xcresult", "project-test.xcresult") for arg in arguments],
            ["60" if arg == "300" else arg for arg in arguments],
        ):
            with self.subTest(selection=changed[15:18]), self.assertRaises(MODULE.Refused):
                MODULE.normal_cli_arguments(changed)

        # Current recovery SOURCE is the genuine configured runtime nomination,
        # not an arbitrary replacement digest or a claim of native qualification.
        expected_source = '10d3f2cf13155335444c8376a346d89581c03a43f0ae642e67401e379745dca2'
        nomination = json.loads((ROOT / "desktop/macos-installed-inputs/python-signed-runtime-binding.json").read_bytes())
        self.assertEqual(set(nomination["targets"]), {MODULE.ARM_TARGET, MODULE.INTEL_TARGET})
        for target in (MODULE.ARM_TARGET, MODULE.INTEL_TARGET):
            self.assertEqual(nomination["targets"][target]["state"], "configured")
            self.assertEqual(nomination["targets"][target]["sourceInputsSha256"], expected_source)
        self.assertEqual(MODULE.SAVED_VERSION_SOURCE, expected_source)
        profile = "desktop/packaging/macos-history-provider.profile"
        self.assertEqual(hashlib.sha256((ROOT / profile).read_bytes()).hexdigest(),
                         "76ce1597468fd1d4d420b1453194ea6ab89c1556de6bba5664c79637754c2e4b")
        # The new singleton adds no budget to or extra method in any old call.
        selected = "saved-version-recovery-test.xcresult"
        self.assertEqual(MODULE.NORMAL_SELECTIONS[selected], (("testSyntheticProjectSavedVersionRecovery",), 300, 420))
        self.assertEqual(MODULE.SUMMARY_STEMS[selected], "saved-version-recovery-summary")
        args = normal_arguments(selected)
        request = MODULE.normal_request(args, str(Path(args[12]).parent / "tmp") + "/")
        self.assertEqual((request["methods"], request["allowance"], request["timeout"], request["phaseSeconds"]),
                         ((MODULE.CLASS + "testSyntheticProjectSavedVersionRecovery",), 300, 420, 585))
        for changed in (args + ["-retry-tests-on-failure"], args + [args[15]],
                        [v.replace("SavedVersionRecovery", "SavedOfflineChecks") for v in args]):
            with self.assertRaises(MODULE.Refused): MODULE.normal_cli_arguments(changed)
        case = "-[MRKNormalAppUITests.NormalAppUITests testSyntheticProjectSavedVersionRecovery]"
        marker = ("MRK_MACOS_NORMAL_SAVED_VERSION_RECOVERY_UI=original-core-interrupt86-fresh-ui-inspect-close-reinspect-confirm-rollback-reload;"
                  "interruptedGuiSave=not-observed;cleanExitStatus=unavailable;allWorkerFinality=unavailable")
        output = ("\n".join(("Test Case '" + case + "' started.", MODULE.ORIGINAL_MARKER, marker,
                            "Test Case '" + case + "' passed (1.000 seconds).", ""))).encode()
        self.assertIs(MODULE.normal_saved_version_markers(output), True)
        for wrong in (output + output, output.replace(marker.encode(), b"wrong"), output[:-1],
                      output.replace(b"passed (", b"failed ("), output.replace(b"SavedVersionRecovery", b"SavedOfflineChecks"),
                      output + b"MRK_MACOS_UI_FAILURE_CLEANUP=normalRequested=true\n",
                      b"\n".join((output.splitlines()[0], marker.encode(), MODULE.ORIGINAL_MARKER.encode(), output.splitlines()[3], b""))):
            with self.assertRaises(MODULE.Refused): MODULE.normal_saved_version_markers(wrong)
        frames = [dict(protocol="mrk-release-version/1", session="0123456789abcdef0123456789abcdef", seq=i,
                       kind=kind, result=dict(scopeResources="settled", **result))
                  for i, (kind, result) in enumerate((("opened", {"source": "release/version.properties", "values": {"name": "1.2.3", "build": "7"}}),
                                                       ("prepared", {"view": {"synthetic": True}})))]
        body = b"".join(json.dumps(row).encode() + b"\n" for row in frames)
        self.assertEqual(MODULE.saved_version_producer_frames(body), hashlib.sha256(body).hexdigest())
        for wrong in (body + b'{}\n', body.replace(b'"seq": 1', b'"seq": true'), body.replace(b'"prepared"', b'"terminal"'),
                      body.replace(b'"settled"', b'"unknown"', 1), body.replace(b'"1.2.3"', b'"2.3.4"'), body[:-1]):
            with self.assertRaises(MODULE.Refused): MODULE.saved_version_producer_frames(wrong)

        # A separate saved-document singleton; never changes ordinary-seven or recovery.
        result_name = "release-evidence-test.xcresult"
        self.assertEqual(MODULE.NORMAL_SELECTIONS[result_name], (("testSyntheticProjectSavedReleaseEvidence",), 300, 420))
        self.assertEqual(MODULE.SUMMARY_STEMS[result_name], "release-evidence-summary")
        args = normal_arguments(result_name)
        request = MODULE.normal_request(args, str(Path(args[12]).parent / "tmp") + "/")
        self.assertEqual((request["methods"], request["allowance"], request["timeout"], request["phaseSeconds"]),
                         ((MODULE.CLASS + "testSyntheticProjectSavedReleaseEvidence",), 300, 420, 585))
        summary = MODULE.normal_request(["--normal-summary", result_name], str(Path(args[12]).parent / "tmp") + "/")
        self.assertEqual((summary["timeout"], summary["phaseSeconds"]), (30, 90))
        for changed in (args + ["-retry-tests-on-failure"], args + [args[15]],
                        [v.replace("SavedReleaseEvidence", "ManagedWorkflowRefusal") for v in args],
                        [v.replace("release-evidence-test", "saved-checks-test") for v in args],
                        ["900" if v == "300" else v for v in args]):
            with self.assertRaises(MODULE.Refused): MODULE.normal_cli_arguments(changed)

    def test_workflow_refusal_output_requires_one_original_exact_final_case_and_scope(self):
        output = normal_workflow_refusal_output()
        self.assertIs(MODULE.normal_workflow_refusal_markers(output), True)
        rows = output.splitlines(keepends=True)
        self.assertEqual(len(rows), 4)
        bad = [b"", b"x" * (1024 * 1024 + 1), output[:-1],
               output + b"MRK_MACOS_UI_FAILURE_CLEANUP=normalRequested=true\n",
               output.replace(b"completion=1", b"completion=0", 1),
               output.replace(b"testSyntheticProjectManagedWorkflowRefusal", b"testUnexpectedMethod"),
               output.replace(b"MRKNormalAppUITests.NormalAppUITests", b"OtherTests.OtherClass"),
               output.replace(b"passed (1.000 seconds).", b"failed (1.000 seconds)."),
               output.replace(b"passed (1.000 seconds).", b"passed (... seconds)."),
               output.replace(b"whole-bundle-refused-originals-preserved", b"preview-only"),
               output + b"Test Case 'unselected' failed (1.000 seconds).\n",
               output + b"Test Case 'unselected' started\n",
               rows[3] + b"".join(rows[:3]),
               rows[0] + rows[2] + rows[1] + rows[3]]
        for row in rows:
            bad.extend((output.replace(row, b"", 1), output + row))
        for prefix in (b"MRK_MACOS_UI_ORIGINAL=", b"MRK_MACOS_NORMAL_WORKFLOW_REFUSAL_UI="):
            bad.append(output + prefix + b"wrong-extra-value\n")
        for body in bad:
            with self.subTest(bytes=len(body)), self.assertRaises(MODULE.Refused):
                MODULE.normal_workflow_refusal_markers(body)
        for body in (None, "not bytes", bytearray(output)):
            with self.assertRaises(MODULE.Refused): MODULE.normal_workflow_refusal_markers(body)
        with self.assertRaises(UnicodeDecodeError):
            MODULE.normal_workflow_refusal_markers(output + b"\xff\n")
        with self.assertRaises(MODULE.Refused):
            MODULE.normal_workflow_refusal_markers(normal_project_output())
        self.assertIs(MODULE.normal_project_markers(normal_project_output()), True)

        case = "-[MRKNormalAppUITests.NormalAppUITests testSyntheticProjectSavedReleaseEvidence]"
        marker = 'MRK_MACOS_NORMAL_RELEASE_EVIDENCE_UI=ordinary-picker-candidate-documents-only-shared-guidance-stage-retained-replacement-cancel-stale-release-inputs-empty-originals-preserved;cleanExitStatus=unavailable;allWorkerFinality=unavailable;remoteRelease=not-attempted'
        output = ("\n".join(("Test Case '" + case + "' started.", MODULE.ORIGINAL_MARKER, marker,
                             "Test Case '" + case + "' passed (1.000 seconds).", ""))).encode()
        self.assertIs(MODULE.normal_release_evidence_markers(output), True)
        rows = output.splitlines(keepends=True)
        for bad in (b"", output[:-1], output + output, b"x" * (1024 * 1024 + 1),
                    output.replace(b"passed (", b"failed ("), output.replace(b"SavedReleaseEvidence", b"ManagedWorkflowRefusal"),
                    output.replace(b"documents-only", b"store-authenticated"),
                    output + b"MRK_MACOS_UI_FAILURE_CLEANUP=normalRequested=true\n",
                    rows[0] + rows[2] + rows[1] + rows[3], normal_workflow_refusal_output()):
            with self.assertRaises(MODULE.Refused): MODULE.normal_release_evidence_markers(bad)
        for row in rows:
            for bad in (output + row, output.replace(row, b"", 1)):
                with self.assertRaises(MODULE.Refused): MODULE.normal_release_evidence_markers(bad)
        with self.assertRaises(MODULE.Refused): MODULE.normal_workflow_refusal_markers(output)

    def test_workflow_refusal_marker_gate_is_only_new_selection_original_zero(self):
        clock = SimpleNamespace(before_publication=lambda: {}, check=lambda: None)
        phase = SimpleNamespace(call=lambda *args: self.fail("no native execution"), records=[], clock=clock, environment={})
        selected = "workflow-refusal-test.xcresult"
        for name, status, output in (
            (selected, 0, normal_workflow_refusal_output()), (selected, 0, b"missing original markers"),
            (selected, 65, b"native failed"),
            ("project-test.xcresult", 0, normal_project_output()),
            ("diagnostics-test.xcresult", 0, b"not a workflow-refusal case"),
        ):
            arguments = normal_arguments(name)
            request = MODULE.normal_request(arguments, str(Path(arguments[12]).parent / "tmp") + "/")
            original = subprocess.CompletedProcess([], status, output, b"")
            with self.subTest(selection=name, status=status, bytes=len(output)), \
                    patch.object(MODULE, "normal_source_state", return_value={"inert": "source"}), \
                    patch.object(MODULE, "run_admitted_test", return_value=(original, {})), \
                    patch.object(MODULE, "exclusive_output") as publish, \
                    patch.object(MODULE, "normal_workflow_refusal_markers",
                                 wraps=MODULE.normal_workflow_refusal_markers) as parse:
                if name == selected and status == 0 and output != normal_workflow_refusal_output():
                    with self.assertRaises(MODULE.Refused):
                        MODULE.execute_normal_phase(phase, request, "a" * 40, (1024**3,) * 2)
                    parse.assert_called_once_with(output)
                    publish.assert_not_called()
                    continue
                self.assertIs(MODULE.execute_normal_phase(phase, request, "a" * 40, (1024**3,) * 2), original)
                receipt = json.loads(publish.call_args.args[1])
                self.assertEqual(receipt["originalTestReturncode"], status)
                if name == selected and status == 0:
                    self.assertIs(receipt["managedWorkflowRefusalMarkerObserved"], True)
                    parse.assert_called_once_with(output)
                    self.assertNotIn("projectFieldAndEditMarkersObserved", receipt)
                else:
                    self.assertNotIn("managedWorkflowRefusalMarkerObserved", receipt)
                    parse.assert_not_called()

        case = "-[MRKNormalAppUITests.NormalAppUITests testSyntheticProjectSavedReleaseEvidence]"
        marker = 'MRK_MACOS_NORMAL_RELEASE_EVIDENCE_UI=ordinary-picker-candidate-documents-only-shared-guidance-stage-retained-replacement-cancel-stale-release-inputs-empty-originals-preserved;cleanExitStatus=unavailable;allWorkerFinality=unavailable;remoteRelease=not-attempted'
        output = ("\n".join(("Test Case '" + case + "' started.", MODULE.ORIGINAL_MARKER, marker,
                             "Test Case '" + case + "' passed (1.000 seconds).", ""))).encode()
        for name, status, body in (("release-evidence-test.xcresult", 0, output),
                                   ("release-evidence-test.xcresult", 0, b"missing markers"),
                                   ("release-evidence-test.xcresult", 65, b"failure"),
                                   ("workflow-refusal-test.xcresult", 0, normal_workflow_refusal_output())):
            args = normal_arguments(name)
            request = MODULE.normal_request(args, str(Path(args[12]).parent / "tmp") + "/")
            original = subprocess.CompletedProcess([], status, body, b"")
            with patch.object(MODULE, "normal_source_state", return_value={"inert": "source"}), \
                 patch.object(MODULE, "run_admitted_test", return_value=(original, {})), \
                 patch.object(MODULE, "exclusive_output") as publish, \
                 patch.object(MODULE, "normal_release_evidence_markers", wraps=MODULE.normal_release_evidence_markers) as parser:
                if name == "release-evidence-test.xcresult" and status == 0 and body != output:
                    with self.assertRaises(MODULE.Refused): MODULE.execute_normal_phase(phase, request, "a" * 40, (1024**3,) * 2)
                    parser.assert_called_once_with(body); publish.assert_not_called()
                    continue
                self.assertIs(MODULE.execute_normal_phase(phase, request, "a" * 40, (1024**3,) * 2), original)
                receipt = json.loads(publish.call_args.args[1])
                if name == "release-evidence-test.xcresult" and status == 0:
                    self.assertIs(receipt["savedReleaseEvidenceMarkerObserved"], True)
                    parser.assert_called_once_with(body)
                else:
                    self.assertNotIn("savedReleaseEvidenceMarkerObserved", receipt); parser.assert_not_called()

    def test_workflow_refusal_source_derives_originals_before_creation_and_never_applies(self):
        import base64
        current = SWIFT.read_text()
        rows = current.split("static let releaseEvidenceDocuments: [(String, String, Int, String)] = [", 1)[1].split("\n        ]", 1)[0]
        additions = re.findall(r'\("([^"]+)", "([A-Za-z0-9+/=]+)", ([0-9]+), "([0-9a-f]{64})"\)', rows)
        expected = {
            "evidence/candidate-manifest.json": "candidate-valid.json",
            "evidence/candidate-receipt.json": "receipt-candidate-valid.json",
            "evidence/operation/candidate-operation-intent.json": "intent-candidate-valid.json",
        }
        self.assertEqual(len(additions), 3); self.assertEqual({r[0] for r in additions}, set(expected))
        total = 0
        for path, encoded, size, digest in additions:
            observed = base64.b64decode(encoded, validate=True)
            actual = (ROOT / "tests/fixtures" / expected[path]).read_bytes()
            self.assertEqual(observed, actual)
            self.assertEqual((len(observed), hashlib.sha256(observed).hexdigest()), (int(size), digest))
            self.assertLessEqual(len(observed), 4096); total += len(observed)
        self.assertEqual(total, 11366)


    def _assert_android_source_browse_bindings(self, source, prepare, journey, workflow, runtime):
        # SOURCE/literal DATA inside the existing selected test. The independent
        # Rust16-cell test and actual native journeys remain separately required.
        rust = ROOT / "desktop/src-tauri/src"
        sources = (rust / "android_tool_sources.rs").read_text()
        status_helper = sources.split("pub(crate) fn status_availability(", 1)[1].split("pub(crate) fn unavailable()", 1)[0]
        self.assertEqual(" ".join(status_helper.split()),
                         "gate: Availability, source_selection_available: bool) -> Availability { "
                         "match (gate, source_selection_available) { "
                         "(Availability::Available, false) => Availability::RuntimeUnqualified, _ => gate, } }")
        oracle = [
            ("Available", "RuntimeUnqualified", "Available"),
            ("Busy", "Busy", "Busy"), ("Shutdown", "Shutdown", "Shutdown"),
            ("CleanupUnknown", "CleanupUnknown", "CleanupUnknown"),
            ("DocumentLost", "DocumentLost", "DocumentLost"),
            ("UnsupportedPlatform", "UnsupportedPlatform", "UnsupportedPlatform"),
            ("RuntimeUnqualified", "RuntimeUnqualified", "RuntimeUnqualified"),
            ("ToolchainUnqualified", "ToolchainUnqualified", "ToolchainUnqualified"),
        ]
        table = sources.split("let cases = [", 1)[1].split("];", 1)[0]
        self.assertEqual(re.findall(r"^\s+\(([A-Za-z]+), ([A-Za-z]+), ([A-Za-z]+)\),$", table, re.M), oracle)
        for literal in ("assert_eq!(status_availability(gate, false), unqualified);",
                        "assert_eq!(status_availability(gate, true), qualified);"):
            self.assertIn(literal, sources)
        protocol = (rust / "android_build_protocol.rs").read_text()
        variants = protocol.split("pub(crate) enum Availability {", 1)[1].split("}", 1)[0]
        self.assertEqual([name.strip() for name in variants.split(",")], [row[0] for row in oracle])

        document = (rust / "asset_session.rs").read_text()
        status = document.split("pub(crate) fn android_tool_sources_status(", 1)[1].split(
            "pub(crate) fn cancel_android_tool_source(", 1)[0]
        ordered = ("publisher.is_none() && !self.inner.android_registration_control.is_unknown()",
                   "crate::android_build_protocol::Availability::Busy",
                   "} else { self.android_build_gate(&state) };",
                   "let gate = crate::android_tool_sources::status_availability(",
                   "gate, self.inner.bridge.installed_android_source_selection_available());",
                   "self.inner.bridge.android_build.sources_status(gate)")
        self.assertEqual([status.index(item) for item in ordered], sorted(status.index(item) for item in ordered))
        self.assertEqual(status.count("status_availability("), 1)
        self.assertEqual(status.count("installed_android_source_selection_available()"), 1)
        self.assertEqual(status.count("sources_status(gate)"), 1)
        self.assertNotIn(".availability =", status)
        choose = document.split("pub(crate) fn choose_android_tool_source(", 1)[1].split("pub(crate) fn choose_project_path(", 1)[0]
        self.assertIn("if gate != crate::android_build_protocol::Availability::Available\n"
                      "                || !self.inner.bridge.installed_android_source_selection_available()", choose)
        self.assertNotIn("status_availability(", choose)
        cancel = document.split("pub(crate) fn cancel_android_tool_source(", 1)[1].split("fn observe_android_source_slot(", 1)[0]
        self.assertIn("cancel_source(input, self.android_build_gate(&state))?", cancel)
        self.assertNotIn("installed_android_source_selection_available", cancel)
        self.assertNotIn("status_availability", cancel)
        bridge = (rust / "bridge.rs").read_text()
        self.assertEqual(bridge.count("let installed_android_source_selection_available = runtime.android_source_selection_profile_available();"), 1)
        self.assertIn("pub(crate) fn installed_android_source_selection_available(&self) -> bool { self.installed_android_source_selection_available }", bridge)
        profile = runtime.split("pub(crate) fn android_source_selection_profile_available(", 1)[1].split(
            "pub(crate) fn evidence_selection_profile_available(", 1)[0]
        self.assertIn("INSTALLED_MAC_ANDROID_SOURCE_SELECTION_QUALIFIED && self.project_selection_profile_available()", profile)
        self.assertIn('#[cfg(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]\n'
                      '        { INSTALLED_MAC_ANDROID_SOURCE_SELECTION_QUALIFIED && self.project_selection_profile_available()\n'
                      '            && crate::android_build_protocol::Profile::current().is_some_and(crate::android_toolchain_macos_policy::native_catalog_supports) }', profile)
        self.assertIn('#[cfg(not(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"))))]\n        { false }', profile)
        ui = (ROOT / "desktop/src/components/AndroidBuild.tsx").read_text()
        self.assertIn("const sourceRoles: AndroidToolSourceRole[] = ['jdk', 'sdk', 'gradle'];", ui)
        self.assertEqual(ui.count("role=\"group\" aria-label={`${help.label} source folder`}"), 1)
        controller = (ROOT / "desktop/src/androidBuild.ts").read_text()
        self.assertIn("if (this.state.toolSources.availability !== 'available') return androidBuildAvailabilityText[this.state.toolSources.availability];", controller)

        deep = "sources/tool-refused/" + "/".join(["d"] * 123)
        expected_paths = {"sources/tool-jdk.jdk/README.txt", "sources/tool-sdk/README.txt", "sources/tool-gradle/README.txt",
                          "sources/tool-jdk-replacement.jdk/README.txt", deep + "/README.txt"}
        additions = source.split("static let androidSourceAdditions: [String: Data] = [", 1)[1].split("\n        ]", 1)[0]
        rows = re.findall(r'^\s+"([^"]+)": Data\(("(?:\\.|[^"\\])*")\.utf8\)', additions, re.M)
        self.assertEqual(len(rows), 5)
        self.assertEqual({path for path, _ in rows}, expected_paths)
        self.assertEqual([json.loads(value) for _, value in rows], ["MRK_NORMAL_ANDROID_SOURCE_SELECTION_ONLY\n"] * 5)
        self.assertEqual([len(json.loads(value).encode()) for _, value in rows], [41] * 5)
        actual_deep = json.loads(source.split("static let androidRefusedDirectory = ", 1)[1].splitlines()[0])
        self.assertEqual(actual_deep, deep)
        absolute = "/private/tmp/mrk-normal-project-XXXXXX/" + deep
        self.assertEqual((len(deep.split("/")), len([part for part in absolute.split("/") if part]), len(absolute.encode())), (125, 128, 305))
        fixture = json.loads((SWIFT.parent / "Fixtures/normal-project-v1.json").read_bytes())
        field_paths = {"project/inputs/VERSION", "project/ios/Example.xcodeproj/project.pbxproj",
                       "project/ios/Example.xcworkspace/contents.xcworkspacedata", "project/metadata/README.txt"}
        leaves = set(fixture["files"]) | field_paths | expected_paths
        directories = {""}
        for path in leaves:
            parts = path.split("/")
            directories.update("/".join(parts[:count]) for count in range(1, len(parts)))
        self.assertEqual((len(leaves), len(directories), len(directories) + 3, len(directories) + 4), (22, 143, 146, 147))
        names = (leaves | directories) - {""}
        fanouts = [sum(name.startswith(prefix) and "/" not in name[len(prefix):] for name in names)
                   for prefix in (path + "/" if path else "" for path in directories)]
        self.assertEqual((max(fanouts), len(names), len(names) + 3 * len(directories)), (7, 164, 593))
        for fragment in ("Self.androidSourceAdditions.count == 5", "$0.count == 41",
                         "Set(originals.keys).isDisjoint(with: Self.androidSourceAdditions.keys)",
                         "originals.count == 22 && Self.ancestors(Set(originals.keys)).count == 143",
                         'Self.androidRefusedDirectory.split(separator: "/").count == 125',
                         'refusedPath.split(separator: "/").count == 128 && refusedPath.utf8.count == 305',
                         "current.count == 22 && directories.count == 143 && anchors.count == 3", "descriptors.count == 146"):
            self.assertIn(fragment, prepare)
        self.assertLess(prepare.index("originals.count == 22"), prepare.index('adoptDirectory(open("/"'))
        self.assertLess(prepare.index("try checkRoster()"), prepare.index("descriptors.count == 146"))
        for fragment in ("result.count < 64", "bytes.count <= 32 * 1024", "<= 256 * 1024"):
            self.assertIn(fragment, source)
        for forbidden in ("getrlimit(", "setrlimit(", "RLIMIT_NOFILE"):
            self.assertNotIn(forbidden, prepare)

        android = journey.split("// Six ordinary native source actions", 1)[1].split("@MainActor func settings(", 1)[0]
        self.assertLess(journey.index('try stage("project-open")'), journey.index("// Six ordinary native source actions"))
        self.assertLess(journey.index('try stage("android-source-refused")'), journey.index('try stage("field-version")'))
        self.assertEqual(re.findall(r'try stage\("android-source-([^"]+)"\)', android), ["jdk", "sdk", "gradle", "cancel", "reselect", "refused"])
        self.assertEqual(re.findall(r'try androidBrowse\("([^"]+)"', android), ["jdk", "sdk", "gradle", "jdk", "jdk", "jdk"])
        for fragment in ('"jdk": "Java development kit (JDK)"', '"sdk": "Android SDK"', '"gradle": "Gradle distribution"',
                         'controls(renderer, [.group], label: label + " source folder")',
                         'try nativeSheet(window, title: title)', 'try nativeOpen(sheet)',
                         'try goToFolder(sheet, path: fixture.rootPath + "/" + relative)',
                         'try click(sheet.buttons.matching(identifier: "Cancel")',
                         'relative: "sources/tool-jdk.jdk", cancel: true',
                         'relative: "sources/tool-sdk"', 'relative: "sources/tool-gradle"',
                         'relative: "sources/tool-jdk-replacement.jdk"',
                         "relative: LocalFixture.androidRefusedDirectory, refused: true",
                         'try androidStatus("Folder selection cancelled."',
                         'reason: "The native folder dialog was closed without selecting a folder."',
                         'try androidStatus("Folder selection could not be used."',
                         'reason: "Choose a real, readable local folder, not an alias or archive. This check does not inspect the tools inside it."',
                         'try androidStatus("Original folder selection retained."',
                         'reason: "Folder selection alone is not supplier inspection or a protected copy. Check the separate original registration Status."',
                         "try androidRetained()\n            try fixture.assertUnchanged()",
                         'in: group, enabled: true, timeout: 48)', 'in: renderer, timeout: 48, failures: failures)'):
            self.assertIn(fragment, android)
        self.assertEqual(android.count("androidSelections[role] = String(name)"), 1)
        for branch in (android.split("if refused {", 1)[1].split("} else {", 1)[0],
                       android.split("if cancel {", 1)[1].split("} else {", 1)[0]):
            self.assertNotIn("androidSelections[role] = String(name)", branch)
        for forbidden in ("firstMatch", "element(boundBy:", "evaluateJavaScript", "setValue(", "try?", "catch",
                          "inspectToolSources(", "registerTools(", "checkAndroidToolService(", "requestAndroidToolServiceRegistration("):
            self.assertNotIn(forbidden, android)
        marker = "MRK_MACOS_NORMAL_ANDROID_SOURCE_UI=ordinary-jdk-sdk-gradle-native-cancel-jdk-reselect-backend-source-refused-selection-only;cleanExitStatus=unavailable;allWorkerFinality=unavailable"
        self.assertEqual(journey.count('print("' + marker + '")'), 1)
        self.assertLess(journey.index("try acceptFinalScenario()"), journey.index('print("' + marker + '")'))

        # Unchanged real directory-refusal route, not a synthetic returned DTO.
        shared_source = (rust / "asset_source.rs").read_text()
        mac_source = (rust / "asset_source_macos.rs").read_text()
        self.assertIn("const COMPONENT_LIMIT: usize = 128;", shared_source)
        self.assertIn("pub(crate) const PATH_LIMIT: usize = 4096;", shared_source)
        parts = mac_source.split("fn parts(path: &Path)", 1)[1].split("fn source_extra(", 1)[0]
        self.assertIn("components.len() >= COMPONENT_LIMIT - 1 { return Err(Reason::SourceRefused); }", parts)
        probe = mac_source.split("pub(crate) fn probe_project_excluding_vault(", 1)[1].split("pub(crate) fn probe_vault_exclusion(", 1)[0]
        self.assertLess(probe.index("let project_parts = parts(&path)?;"), probe.index("book.begin("))
        job = document.split("Job::AndroidSource { app, binding } => {", 1)[1].split("Job::ProjectPath {", 1)[0]
        self.assertIn("DialogChoice::AndroidToolSource(binding.role)", job)
        self.assertIn("ChildJob::Probe { path, origins: Vec::new(), vault: None }", job)
        self.assertIn("book.not_started() || book.settled()", document)
        self.assertIn('runner.get("androidToolSourceBrowseMarkerObserved") is not True', workflow)
        self.assertIn('"androidToolSourceBrowseUI": "passed"', workflow)
        self.assertIn('"androidToolSourceBrowseScope": "selection-only-three-roles-native-cancel-reselect-backend-source-refused"', workflow)
        self.assertIn('"supplierInspectionQualified": False, "protectedToolCopyQualified": False, "androidBuildQualified": False', workflow)

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
    def test_android_private_input_schema_current_run_and_public_projection(self):
        # Inert closed DATA; no key generation, source registration or UI call.
        import copy
        source, run, attempt = 'a' * 40, '42', '1'
        normal = Path('/Users/runner/work/_temp/mrk-macos-installed.ABCDef12/normal-ui')
        root = normal / 'android-inputs'
        facts = ['0'] * 10
        commands = [dict(role=role, returncode=0, timeoutSeconds=30, roleCapSeconds=30,
            outputLimitBytes=2097152, argvSha256='b'*64, stdoutBytes=0, stdoutSha256=hashlib.sha256(b'').hexdigest(),
            stderrBytes=0, stderrSha256=hashlib.sha256(b'').hexdigest())
            for role in ('android-ui-disposable-jks', 'android-ui-public-certificate')]
        value = dict(schemaVersion=1, scope='one-owned-android-ui-inputs', sourceCommit=source,
            target=MODULE.ARM_TARGET, runId=run, runAttempt=attempt, workflow=MODULE.ANDROID_WORKFLOW,
            ref=MODULE.ANDROID_REF, root=str(root), rootFacts=facts, credentialDirectoryFacts=facts,
            sourceCatalogueSha256=MODULE.ANDROID_CATALOGUE, sourceRosterSha256='c'*64,
            publicCertificateSha256='d'*64,
            roots={k: dict(relative=v, facts=facts) for k,v in MODULE.ANDROID_ROOTS.items()},
            files={k: dict(relative='credentials/'+k, facts=facts, sha256='e'*64) for k in MODULE.ANDROID_PRIVATE_FILES},
            keyCommands=commands, parentReturncodeRequired=0,
            phaseClock=dict(startNs='1', deadlineNs=str(1+1200*10**9), beforePublicationNs='2', postCloseDeadlineRequired=True))
        def admit(item):
            return MODULE.android_input_document(MODULE.encoded(item)+b'\n', source=source, run=run, attempt=attempt, root=root)
        self.assertEqual(admit(value), value)
        candidate = dict(value, ref=MODULE.ANDROID_CANDIDATE_REF)
        self.assertEqual(MODULE.android_input_document(MODULE.encoded(candidate)+b'\n',source=source,
            run=run,attempt=attempt,root=root,expected_ref=MODULE.ANDROID_CANDIDATE_REF),candidate)
        current=dict(value,ref=MODULE.ANDROID_CONSUMER_REF,workflow=MODULE.ANDROID_CONSUMER_WORKFLOW)
        self.assertEqual(MODULE.android_input_document(MODULE.encoded(current)+b'\n',source=source,
            run=run,attempt=attempt,root=root,expected_ref=MODULE.ANDROID_CONSUMER_REF),current)
        for changed in (dict(current,workflow=MODULE.ANDROID_WORKFLOW),dict(current,sourceCommit='b'*40),dict(current,runId='43')):
            with self.assertRaises(MODULE.Refused):MODULE.android_input_document(MODULE.encoded(changed)+b'\n',source=source,
                run=run,attempt=attempt,root=root,expected_ref=MODULE.ANDROID_CONSUMER_REF)
        with self.assertRaises(MODULE.Refused):admit(current)
        with self.assertRaises(MODULE.Refused): admit(candidate) # Never infer trust from the handoff.
        for selected, expected in ((value,MODULE.ANDROID_CANDIDATE_REF),(candidate,MODULE.ANDROID_REF),
                                   (candidate,'refs/heads/main'),(candidate,None)):
            with self.subTest(expected_ref=expected),self.assertRaises(MODULE.Refused):
                MODULE.android_input_document(MODULE.encoded(selected)+b'\n',source=source,
                    run=run,attempt=attempt,root=root,expected_ref=expected)
        for target_value in (MODULE.ARM_TARGET, MODULE.INTEL_TARGET):
            selected = dict(value, target=target_value, sourceCatalogueSha256=MODULE.android_catalogue(target_value))
            self.assertEqual(MODULE.android_input_document(MODULE.encoded(selected)+b'\n', source=source,
                run=run, attempt=attempt, root=root, target=target_value), selected)
            other = MODULE.INTEL_TARGET if target_value == MODULE.ARM_TARGET else MODULE.ARM_TARGET
            for bad in (dict(selected, target=other), dict(selected, sourceCatalogueSha256=MODULE.android_catalogue(other))):
                with self.assertRaises(MODULE.Refused):
                    MODULE.android_input_document(MODULE.encoded(bad)+b'\n', source=source,
                        run=run, attempt=attempt, root=root, target=target_value)
        for key, replacement in [('runId','41'),('runAttempt','2'),('sourceCommit','b'*40),('target',MODULE.INTEL_TARGET),
            ('root',str(root/'elsewhere')),('schemaVersion',True),('parentReturncodeRequired',False),
            ('sourceCatalogueSha256','0'*64),('unknown','private message')]:
            bad=copy.deepcopy(value);bad[key]=replacement
            with self.subTest(key=key),self.assertRaises(MODULE.Refused): admit(bad)
        for mutation in ('command-bool','command-extra','command-order','clock','path','facts','digest'):
            bad=copy.deepcopy(value)
            if mutation=='command-bool': bad['keyCommands'][0]['returncode']=False
            elif mutation=='command-extra': bad['keyCommands'][0]['stderr']='private'
            elif mutation=='command-order': bad['keyCommands'].reverse()
            elif mutation=='clock': bad['phaseClock']['deadlineNs']=str(1200*10**9)
            elif mutation=='path': bad['files']['upload.jks']['relative']='../upload.jks'
            elif mutation=='facts': bad['rootFacts']=[0]*10
            elif mutation=='digest': bad['publicCertificateSha256']='F'*64
            with self.subTest(mutation=mutation),self.assertRaises(MODULE.Refused): admit(bad)
        raw=MODULE.encoded(value)+b'\n'
        for bad in (raw[:-1], raw+b' ', b'{"schemaVersion":1,'+raw[1:], b'x'*16385):
            with self.assertRaises((MODULE.Refused,ValueError)):
                MODULE.android_input_document(bad,source=source,run=run,attempt=attempt,root=root)
        scalars=dict(alias='mrk-disposable-android-ui',storePassword='1'*48,keyPassword='2'*48)
        self.assertEqual(MODULE.android_input_scalars(MODULE.encoded(scalars)+b'\n'),scalars)
        for key,badvalue in [('alias','other'),('storePassword','1'*49),('keyPassword',None)]:
            bad=dict(scalars);bad[key]=badvalue
            with self.assertRaises(MODULE.Refused): MODULE.android_input_scalars(MODULE.encoded(bad)+b'\n')
        public=dict(schemaVersion=1,scope=MODULE.ANDROID_FACTS_SCOPE,sourceCommit=source,target=MODULE.ARM_TARGET,
            runId=run,runAttempt=attempt,sourceRegistrationObserved=True,nativeSigningVerified=True,
            serviceEnabledObserved=True, serviceRegistrationRequested=False, vendorAcknowledgementAutomated=True,
            protectedCopyInstance="7"*32,
            privateOriginalsClosed=True,memorySessionDiscarded=True,outputPostMatched=True,normalQuitObserved=True,
            releaseQualified=False,parentReturncodeRequired=0,operationId='3'*32,ownerGeneration='4'*32,
            publicCertificateSha256='d'*64,artifactSha256='5'*64,artifactBytes=3,outputEntries=20,
            outputNameBytes=1000,outputLogicalBytes=12,moduleLogicalBytes=9,outputCensusSha256='6'*64)
        self.assertEqual(MODULE.android_signed_facts(public,source=source,run=run,attempt=attempt),public)
        candidate=dict(public,scope='one-local-android-candidate-inputs-ui',operationId='a'*12+'4'+'a'*3+'8'+'a'*15,
            historyCheckpoint=4,candidateReviewed=True,candidateAbandoned=True,bundlePreserved=True,storeActionPerformed=False,
            candidateSha256='8'*64,projectCommit='9'*40,projectTree='0'*40)
        self.assertEqual(MODULE.android_signed_facts(candidate,source=source,run=run,attempt=attempt,candidate=True),candidate)
        selected=b'-[MRKNormalAppUITests.NormalAppUITests '+MODULE.ANDROID_CANDIDATE_METHOD.encode()+b']'
        def candidate_marker(row):
            return b'\n'.join([b"Test Case '"+selected+b"' started.",MODULE.ORIGINAL_MARKER.encode(),
                b'MRK_MACOS_ANDROID_CANDIDATE_INPUTS_UI='+MODULE.encoded(row),b"Test Case '"+selected+b"' passed (2.000 seconds)."])+b'\n'
        fixture=SimpleNamespace(commit='9'*40,tree='0'*40)
        def parse_candidate(raw):
            return MODULE.android_candidate_marker(raw,source=source,run=run,attempt=attempt,certificate='d'*64,fixture=fixture,target=MODULE.ARM_TARGET)
        self.assertEqual(parse_candidate(candidate_marker(candidate)),candidate)
        for key,replacement in [('candidateReviewed',False),('candidateAbandoned',False),('bundlePreserved',False),
                                ('storeActionPerformed',True),('historyCheckpoint',3),('operationId','a'*32),
                                ('projectCommit','a'*40),('projectTree','a'*40),('publicCertificateSha256','e'*64)]:
            with self.subTest(candidate_fact=key),self.assertRaises(MODULE.Refused):
                parse_candidate(candidate_marker(dict(candidate,**{key:replacement})))
        with self.assertRaises(MODULE.Refused):parse_candidate(candidate_marker(candidate)+candidate_marker(candidate))
        with self.assertRaises(MODULE.Refused):MODULE.android_signed_facts(candidate,source=source,run=run,attempt=attempt)
        for target_value in (MODULE.ARM_TARGET, MODULE.INTEL_TARGET):
            selected_public = dict(public, target=target_value)
            self.assertEqual(MODULE.android_signed_facts(selected_public, source=source, run=run,
                attempt=attempt, target=target_value), selected_public)
            with self.assertRaises(MODULE.Refused):
                MODULE.android_signed_facts(dict(selected_public, target='unsupported'), source=source,
                    run=run, attempt=attempt, target=target_value)
        for requested in (False, True):
            observed = dict(public, serviceRegistrationRequested=requested)
            self.assertEqual(MODULE.android_signed_facts(observed,source=source,run=run,attempt=attempt), observed)
        for missing in ("sourceRegistrationObserved", "serviceEnabledObserved", "serviceRegistrationRequested",
                        "vendorAcknowledgementAutomated", "protectedCopyInstance"):
            bad = dict(public); del bad[missing]
            with self.subTest(missing=missing), self.assertRaises(MODULE.Refused):
                MODULE.android_signed_facts(bad,source=source,run=run,attempt=attempt)
        for field, invalid in [('source','private/path'),('source',True),('run','0'),('run','secret'),('attempt','01'),('attempt',1)]:
            context=dict(source=source,run=run,attempt=attempt);context[field]=invalid
            bad=dict(public);bad[{'source':'sourceCommit','run':'runId','attempt':'runAttempt'}[field]]=invalid
            with self.subTest(public_context=field,value=invalid),self.assertRaisesRegex(MODULE.Refused,'android-signed-public-context'):
                MODULE.android_signed_facts(bad,**context)
        selected=b'-[MRKNormalAppUITests.NormalAppUITests '+MODULE.ANDROID_METHOD.encode()+b']'
        stdout=b'\n'.join([b"Test Case '"+selected+b"' started.",MODULE.ORIGINAL_MARKER.encode(),
            MODULE.ANDROID_FACTS_PREFIX+MODULE.encoded(public),b"Test Case '"+selected+b"' passed (2.000 seconds)."])+b'\n'
        self.assertEqual(MODULE.android_signed_marker(stdout,source=source,run=run,attempt=attempt,certificate='d'*64),public)
        for key,badvalue in [('runId','2'),('privateOriginalsClosed',False),('sourceRegistrationObserved',False),
            ('serviceEnabledObserved',False),('vendorAcknowledgementAutomated',False),
            ('serviceRegistrationRequested',1),('serviceRegistrationRequested','true'),
            ('protectedCopyInstance','private/path'),('protectedCopyInstance','A'*32),
            ('parentReturncodeRequired',False),('operationId','private/path'),('artifactBytes',True),
            ('moduleLogicalBytes',13),('privateKeySha256','e'*64)]:
            bad=dict(public);bad[key]=badvalue
            with self.subTest(public=key),self.assertRaises(MODULE.Refused):
                MODULE.android_signed_facts(bad,source=source,run=run,attempt=attempt)
        for bad in (stdout+MODULE.ANDROID_FACTS_PREFIX+MODULE.encoded(public)+b'\n',
                    stdout.replace(b' passed (',b' failed ('),stdout+b'MRK_MACOS_UI_FAILURE_CLEANUP=unknown\n',b'x'*1048577):
            with self.assertRaises(MODULE.Refused): MODULE.android_signed_marker(bad,source=source,run=run,attempt=attempt,certificate='d'*64)
        request=MODULE.normal_request(['--normal-android-signed-build-test'],str(normal/'tmp')+'/')
        self.assertEqual((request['methods'],request['allowance'],request['timeout'],request['phaseSeconds']),
            ((MODULE.CLASS+MODULE.ANDROID_METHOD,),900,1020,1245))
        self.assertEqual(MODULE.normal_request(['--normal-android-signed-build-summary'],str(normal/'tmp')+'/')['phaseSeconds'],90)
        self.assertNotIn(MODULE.ANDROID_RESULT,MODULE.NORMAL_SELECTIONS)
        for args in (['--target','unsupported','--normal-android-signed-build-test'],
                     ['--normal-android-signed-build-test','--work','/tmp/private']):
            with self.assertRaises(MODULE.Refused): MODULE.normal_request(args,str(normal/'tmp')+'/')

        # Exercise the ACTUAL new normal_context with the exact Metadata
        # clean environment. Only host/account observations are inert adapters;
        # there is no caller private path, no target env and no native command.
        import resource
        import pwd
        checkout=Path('/Users/runner/work/mobile-release-kit/mobile-release-kit')
        env=dict(PATH='/usr/bin:/bin:/usr/sbin:/sbin',HOME='/Users/runner',USER='runner',LOGNAME='runner',
            TMPDIR=str(normal/'tmp')+'/',LANG='en_US.UTF-8',LC_ALL='en_US.UTF-8',TZ='UTC',
            DEVELOPER_DIR=MODULE.DEVELOPER,TEST_RUNNER_MRK_NORMAL_UI_HOSTED_JOB='github-hosted-macos26-arm64',
            TEST_RUNNER_MRK_NORMAL_UI_APPLICATION_SOURCE=source,TEST_RUNNER_MRK_NORMAL_UI_HARNESS_SOURCE=source,
            GITHUB_REPOSITORY='Apdelrahman1911/mobile-release-kit',GITHUB_EVENT_NAME='push',GITHUB_REF=MODULE.ANDROID_REF,
            GITHUB_SHA=source,GITHUB_WORKFLOW_SHA=source,
            GITHUB_WORKFLOW_REF='Apdelrahman1911/mobile-release-kit/'+MODULE.ANDROID_WORKFLOW+'@'+MODULE.ANDROID_REF,
            GITHUB_WORKSPACE=str(checkout),GITHUB_RUN_ID=run,GITHUB_RUN_ATTEMPT=attempt,
            RUNNER_ENVIRONMENT='github-hosted',RUNNER_OS='macOS',RUNNER_ARCH='ARM64')
        with ExitStack() as stack:
            stack.enter_context(patch.object(MODULE,'__file__',str(checkout/'desktop/tools/macos_normal_ui_runner.py')))
            stack.enter_context(patch.object(MODULE.sys,'platform','darwin'))
            stack.enter_context(patch.object(MODULE.sys,'version_info',(3,14,7)))
            stack.enter_context(patch.object(MODULE.sys,'flags',SimpleNamespace(isolated=1,no_site=1)))
            stack.enter_context(patch.object(MODULE.sys,'dont_write_bytecode',True))
            stack.enter_context(patch.object(MODULE.platform,'machine',return_value='arm64'))
            stack.enter_context(patch.object(MODULE.platform,'mac_ver',return_value=('26.6.2',(),'')))
            stack.enter_context(patch.object(resource,'getrlimit',return_value=(1024**3,1024**3)))
            stack.enter_context(patch.object(pwd,'getpwuid',return_value=SimpleNamespace(pw_uid=1000,pw_gid=1000,pw_name='runner',pw_dir='/Users/runner')))
            for function in ('getuid','geteuid','getgid','getegid'):
                stack.enter_context(patch.object(MODULE.os,function,return_value=1000))
            stack.enter_context(patch.object(MODULE.os,'stat',return_value=SimpleNamespace(st_uid=1000)))
            stack.enter_context(patch.object(MODULE.Path,'cwd',return_value=checkout))
            with patch.dict(MODULE.os.environ,env,clear=True):
                admitted,actual,forwarded,limit=MODULE.normal_context(request)
            self.assertEqual((admitted,actual,limit),(checkout,source,(1024**3,1024**3)))
            self.assertEqual(forwarded[MODULE.ANDROID_INPUT_ENV],str(normal/'android-input-fixture.json'))
            self.assertEqual((forwarded[MODULE.ANDROID_RUN_ENV],forwarded[MODULE.ANDROID_ATTEMPT_ENV]),(run,attempt))
            self.assertNotIn('MRK_MACOS_TARGET',forwarded)
            self.assertNotIn('GITHUB_SHA',forwarded)
            intel_request = MODULE.normal_request(['--target', MODULE.INTEL_TARGET,
                '--normal-android-signed-build-test'], str(normal/'tmp')+'/')
            intel_env = dict(env, RUNNER_ARCH='X64', TEST_RUNNER_MRK_NORMAL_UI_HOSTED_JOB='github-hosted-macos26-x86_64')
            with patch.object(MODULE.platform, 'machine', return_value='x86_64'), patch.dict(MODULE.os.environ, intel_env, clear=True):
                self.assertEqual(MODULE.normal_context(intel_request)[:2], (checkout, source))
            for altered in (dict(intel_env, RUNNER_ARCH='ARM64'), dict(intel_env, TEST_RUNNER_MRK_NORMAL_UI_HOSTED_JOB='github-hosted-macos26-arm64')):
                with patch.object(MODULE.platform, 'machine', return_value='x86_64'), patch.dict(MODULE.os.environ, altered, clear=True), self.assertRaises(MODULE.Refused):
                    MODULE.normal_context(intel_request)
            for key,badvalue in [('GITHUB_RUN_ID','0'),('GITHUB_RUN_ATTEMPT','secret'),('GITHUB_SHA','b'*40),
                ('GITHUB_WORKFLOW_SHA','b'*40),('GITHUB_REF','refs/heads/other'),('RUNNER_ARCH','X64')]:
                altered=dict(env);altered[key]=badvalue
                with self.subTest(context=key),patch.dict(MODULE.os.environ,altered,clear=True),self.assertRaisesRegex(MODULE.Refused,'android-signed-fixed-installed-context'):
                    MODULE.normal_context(request)

    def test_android_two_target_commands_and_private_receipt_correspondence(self):
        # Complete synthetic receipts exercise the real fixed validators, not
        # native signing, generated-runner admission or an installed UI claim.
        import copy
        source, run, attempt = 'a'*40, '42', '1'
        normal = Path('/inert/normal-ui')
        roster = 'b'*64
        def clock(seconds):
            return dict(startNs='1', deadlineNs=str(1+seconds*10**9), beforePublicationNs='2', postCloseDeadlineRequired=True)
        def records(rows):
            return [dict(role=role, returncode=0, timeoutSeconds=cap, roleCapSeconds=cap,
                outputLimitBytes=limit, argvSha256=MODULE.sha(MODULE.encoded(argv)), stdoutBytes=0,
                stderrBytes=0, stdoutSha256=MODULE.sha(b''), stderrSha256=MODULE.sha(b''))
                for role,cap,limit,argv in rows]
        source_row = ('normal-ui-source-roster',15,1048576,MODULE.output_data_source_argv(source))
        for target_value in (MODULE.ARM_TARGET, MODULE.INTEL_TARGET):
            with self.subTest(target=target_value):
                request = MODULE.normal_request(['--target',target_value,'--normal-android-signed-build-test'],str(normal/'tmp')+'/')
                self.assertEqual((request['target'],request['timeout'],request['phaseSeconds']),(target_value,1020,1245))
                manifest = normal/'DerivedData/Build/Products/MRKNormalAppUI_macosx26.xctestrun'
                command = MODULE.xcode_test_arguments(manifest,normal/MODULE.ANDROID_RESULT,
                    (MODULE.CLASS+MODULE.ANDROID_METHOD,),900,target=target_value,android_positive=True)
                self.assertEqual(command[command.index('-destination')+1],
                    'platform=macOS' if target_value==MODULE.INTEL_TARGET else 'platform=macOS,arch=arm64')
                self.assertEqual([part for part in command if part.startswith('-only-testing:')],
                    ['-only-testing:'+MODULE.CLASS+MODULE.ANDROID_METHOD])
                events=[]
                class Products:
                    products=manifest.parent
                    def __init__(self, derived): self.manifest=manifest.name; events.append(('open',derived))
                    def __enter__(self): return self
                    def admit(self, call): events.append('admit'); return {}
                    def check(self): events.append('post')
                    def __exit__(self, *args): events.append('close')
                original=SimpleNamespace(returncode=0,stdout=b'',stderr=b'')
                def call(role, argv, timeout):
                    self.assertEqual((role,argv,timeout),('one-admitted-ui-test',command,1020))
                    events.append('original'); return original
                with patch.object(MODULE,'RunnerProducts',Products),patch.object(MODULE.os.path,'lexists',return_value=False):
                    observed,admission=MODULE.run_admitted_test(call,normal/'DerivedData',normal/MODULE.ANDROID_RESULT,
                        (MODULE.CLASS+MODULE.ANDROID_METHOD,),900,1020,target=target_value,android_positive=True)
                self.assertIs(observed,original)
                self.assertEqual(events,[('open',normal/'DerivedData'),'admit','post','original','post','close'])
                self.assertEqual(admission,dict(originalProductsPrePostMatched=True,originalClosesCompleted=True))
                build_argv = MODULE.normal_build_arguments(normal/'DerivedData',target=target_value)
                self.assertEqual('ARCHS=x86_64' in build_argv,target_value==MODULE.INTEL_TARGET)
                build = dict(schemaVersion=1,scope='normal-ui-original-command-admission-only',phase='build',
                    resultBundle=None,originalCommandRole='normal-ui-build',originalReturncode=0,target=target_value,
                    sourceCommit=source,sourceRosterSha256=roster,sourcePrePostMatched=True,originalCommandReturned=True,
                    fileLimitBytes=[32*1024**3]*2,receiptPolicy='exclusive0600-readback-consuming-close',phaseClock=clock(450),
                    commands=records([source_row,*[('normal-toolchain-'+key,15,4096,list(argv))
                        for key,_,argv in MODULE.TOOLCHAIN_QUERIES],('normal-ui-build',240,1048576,build_argv),source_row]))
                public=dict(schemaVersion=1,scope=MODULE.ANDROID_FACTS_SCOPE,sourceCommit=source,target=target_value,
                    runId=run,runAttempt=attempt,sourceRegistrationObserved=True,nativeSigningVerified=True,
                    serviceEnabledObserved=True, serviceRegistrationRequested=False, vendorAcknowledgementAutomated=True,
                    protectedCopyInstance="7"*32,
                    privateOriginalsClosed=True,memorySessionDiscarded=True,outputPostMatched=True,normalQuitObserved=True,
                    releaseQualified=False,parentReturncodeRequired=0,operationId='3'*32,ownerGeneration='4'*32,
                    publicCertificateSha256='d'*64,artifactSha256='5'*64,artifactBytes=3,outputEntries=20,
                    outputNameBytes=1000,outputLogicalBytes=12,moduleLogicalBytes=9,outputCensusSha256='6'*64)
                row=['file',['1','2',str(0o100600),'501','20','1','100','3','4'],'c'*64]
                runner=dict(schemaVersion=1,scope='actual-generated-xctrunner-admission-only',
                    runnerPath=str(normal/'DerivedData/Build/Products'/MODULE.RUNNER),strictCodesignOriginalZero=True,
                    reSignedOrRepaired=False,originalProductsPrePostMatched=True,originalClosesCompleted=True,
                    xctestrunPath=str(manifest),runnerExecutable=copy.deepcopy(row),testExecutable=copy.deepcopy(row),
                    xctestrun=copy.deepcopy(row),productEntryCount=5,productRosterSha256='e'*64,
                    entitlementsSha256='f'*64,appSandboxEntitlement='absent')
                common=dict(schemaVersion=1,scope='android-signed-private-original-admission',resultBundle=MODULE.ANDROID_RESULT,
                    sourceCommit=source,target=target_value,runId=run,runAttempt=attempt,sourceRosterSha256=roster,
                    sourcePrePostMatched=True,originalCommandReturned=True,originalReturncode=0,fileLimitBytes=[1024**3]*2,
                    receiptPolicy='exclusive0600-readback-consuming-close')
                test=dict(common,phase='test',originalCommandRole='one-admitted-ui-test',runnerAdmission=runner,
                    parentPrivateOriginalsClosed=True,observation=public,phaseClock=clock(1245),commands=records([source_row,
                    ('verify-generated-runner',30,1048576,['/usr/bin/codesign','--verify','--strict',runner['runnerPath']]),
                    ('generated-runner-entitlements',30,1048576,['/usr/bin/codesign','-d','--entitlements',':-',runner['runnerPath']]),
                    ('one-admitted-ui-test',1020,1048576,command),source_row]))
                summary=dict(common,phase='summary',originalCommandRole='normal-ui-summary',phaseClock=clock(90),
                    testCounts=dict(totalTestCount=1,passedTests=1,failedTests=0,skippedTests=0,expectedFailures=0),
                    commands=records([source_row,('normal-ui-summary',30,262144,['/usr/bin/xcrun','xcresulttool','get',
                    'test-results','summary','--path',str(normal/MODULE.ANDROID_RESULT),'--compact']),source_row]))
                def admit(b=build,t=test,s=summary,f=public):
                    return MODULE.android_signed_receipts(b,t,s,f,source=source,normal=normal,run=run,attempt=attempt,target=target_value)
                self.assertIsNone(admit())
                # The existing private receipt must carry these exact facts,
                # not a different valid request observation or protected instance.
                requested = dict(public, serviceRegistrationRequested=True)
                requested_test = dict(test, observation=requested)
                self.assertIsNone(admit(t=requested_test, f=requested))
                for key, changed in (("serviceRegistrationRequested", True), ("protectedCopyInstance", "8"*32)):
                    different = dict(public); different[key] = changed
                    with self.subTest(receipt_fact=key), self.assertRaises(MODULE.Refused): admit(f=different)
                other=MODULE.INTEL_TARGET if target_value==MODULE.ARM_TARGET else MODULE.ARM_TARGET
                for index in range(4):
                    cases=copy.deepcopy([build,test,summary,public]);cases[index]['target']=other
                    with self.assertRaises(MODULE.Refused): admit(*cases)
                bad=copy.deepcopy(build)
                bad['commands'][-2]['argvSha256']=MODULE.sha(MODULE.encoded(MODULE.normal_build_arguments(normal/'DerivedData',target=other)))
                with self.assertRaises(MODULE.Refused): admit(b=bad)
                bad=copy.deepcopy(test);bad['commands'][3]['returncode']=65
                with self.assertRaises(MODULE.Refused): admit(t=bad)
                bad=copy.deepcopy(test);bad['parentPrivateOriginalsClosed']=False
                with self.assertRaises(MODULE.Refused): admit(t=bad)
                bad=copy.deepcopy(summary);bad['testCounts']['skippedTests']=1
                with self.assertRaises(MODULE.Refused): admit(s=bad)
        # No non-Android target restriction is weakened by the new selector.
        for flag in ('--normal-output-data-test',):
            with self.assertRaises(MODULE.Refused): MODULE.normal_request(['--target',MODULE.INTEL_TARGET,flag],str(normal/'tmp')+'/')
        with self.assertRaises(MODULE.Refused): MODULE.xcode_test_arguments(Path('m'),Path('r'),
            (MODULE.ENGINEERING_METHOD,),60,target=MODULE.INTEL_TARGET,engineering=True)

    def test_android_private_reader_real_originals_post_and_consuming_close(self):
        # Real tiny files and FD bindings, with only the fixed Mac root mapped to
        # an isolated private test directory. No actual credential/vendor bytes.
        native=Path('/Users/runner/work/_temp/mrk-macos-installed.ABCDef12/normal-ui')
        real_open,real_close,real_stat,real_fstat=os.open,os.close,os.stat,os.fstat
        for fault in (None,'ancestor','leaf','fifo','hardlink','close','primary-close','post-close-clock',
                      'protected-root','protected-ancestors','unknown-ancestor-flag','task-flag','normal-flag',
                      'tool-flag','ancestor-flags-post','ancestor-group-write','ancestor-foreign-owner'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as temporary:
                scratch=Path(temporary);normal=scratch/str(native).lstrip('/');normal.mkdir(parents=True,mode=0o700)
                for parent in normal.parents:
                    if parent==scratch: break
                    parent.chmod(0o700)
                root=normal/'android-inputs';credentials=root/'credentials';credentials.mkdir(parents=True,mode=0o700);root.chmod(0o700);credentials.chmod(0o700)
                tools=root/'tools';tools.mkdir(mode=0o700);(tools/'jdk').mkdir(mode=0o755);(tools/'jdk').chmod(0o755)
                for relative in MODULE.ANDROID_ROOTS.values():
                    (root/relative).mkdir(mode=0o755);(root/relative).chmod(0o755)
                data={'upload.jks':b'inert-not-a-key','upload.der':b'inert-not-a-certificate',
                    'scalars.json':MODULE.encoded(dict(alias='mrk-disposable-android-ui',storePassword='1'*48,keyPassword='2'*48))+b'\n'}
                for name,body in data.items():
                    path=credentials/name;path.write_bytes(body);path.chmod(0o600)
                wire=lambda path:MODULE.decimal(MODULE.saved_version_facts(real_stat(path,follow_symlinks=False)))
                commands=[dict(role=role,returncode=0,timeoutSeconds=30,roleCapSeconds=30,outputLimitBytes=2097152,
                    argvSha256='b'*64,stdoutBytes=0,stdoutSha256=hashlib.sha256(b'').hexdigest(),
                    stderrBytes=0,stderrSha256=hashlib.sha256(b'').hexdigest())
                    for role in ('android-ui-disposable-jks','android-ui-public-certificate')]
                doc=dict(schemaVersion=1,scope='one-owned-android-ui-inputs',sourceCommit='a'*40,target=MODULE.ARM_TARGET,
                    runId='42',runAttempt='1',workflow=MODULE.ANDROID_WORKFLOW,ref=MODULE.ANDROID_REF,
                    root=str(native/'android-inputs'),rootFacts=wire(root),credentialDirectoryFacts=wire(credentials),
                    sourceCatalogueSha256=MODULE.ANDROID_CATALOGUE,sourceRosterSha256='c'*64,
                    publicCertificateSha256=hashlib.sha256(data['upload.der']).hexdigest(),
                    roots={k:dict(relative=v,facts=wire(root/v))for k,v in MODULE.ANDROID_ROOTS.items()},
                    files={k:dict(relative='credentials/'+k,facts=wire(credentials/k),sha256=hashlib.sha256(v).hexdigest())for k,v in data.items()},
                    keyCommands=commands,parentReturncodeRequired=0,
                    phaseClock=dict(startNs='1',deadlineNs=str(1+1200*10**9),beforePublicationNs='2',postCloseDeadlineRequired=True))
                handoff=normal/'android-input-fixture.json';handoff.write_bytes(MODULE.encoded(doc)+b'\n');handoff.chmod(0o600)
                if fault=='fifo':
                    (credentials/'upload.jks').unlink();os.mkfifo(credentials/'upload.jks',0o600)
                    doc['credentialDirectoryFacts']=wire(credentials)
                    handoff.write_bytes(MODULE.encoded(doc)+b'\n')
                if fault=='hardlink': os.link(credentials/'upload.jks',scratch/'linked')
                # Only Darwin metadata is modeled; real descriptors, names,
                # bytes, replacement detection and consuming closes remain live.
                identities = lambda path: (real_stat(path).st_dev, real_stat(path).st_ino)
                root_key = identities(scratch)
                flag_values = {}
                if fault in ('protected-root', 'ancestor-flags-post', 'ancestor-group-write', 'ancestor-foreign-owner'):
                    flag_values[root_key] = 0x00100000
                elif fault == 'protected-ancestors':
                    for relative in ('Users', 'Users/runner', 'Users/runner/work', 'Users/runner/work/_temp'):
                        flag_values[identities(scratch / relative)] = 0x00980000
                elif fault == 'unknown-ancestor-flag': flag_values[root_key] = 0x2
                elif fault in ('task-flag', 'normal-flag', 'tool-flag'):
                    chosen = normal.parent if fault == 'task-flag' else normal if fault == 'normal-flag' else root / MODULE.ANDROID_ROOTS['jdk']
                    flag_values[identities(chosen)] = 0x00100000
                def metadata(value):
                    fields = {key: getattr(value, key) for key in ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid',
                        'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')}
                    key = (value.st_dev, value.st_ino)
                    fields['st_flags'] = flag_values.get(key, 0)
                    if key == root_key:
                        if fault == 'ancestor-group-write': fields['st_mode'] |= 0o020
                        if fault == 'ancestor-foreign-owner': fields['st_uid'] = os.getuid() + 1
                    return SimpleNamespace(**fields)
                opened,closed,flags=[],[],[]
                sentinel=ValueError('synthetic primary remains private')
                def opening(path,mode,*args,**kwargs):
                    actual=scratch if path=='/' else path
                    fd=real_open(actual,mode,*args,**kwargs);opened.append(fd);flags.append((path,mode));return fd
                def stating(path,*args,**kwargs): return metadata(real_stat(scratch if path=='/' else path,*args,**kwargs))
                def closing(fd):
                    closed.append(fd);real_close(fd)
                    if fault in ('close','primary-close'): raise OSError('synthetic consuming close')
                reader=None
                def check():
                    if fault=='post-close-clock' and reader is not None and reader.closed: raise ValueError('clock')
                phase=SimpleNamespace(clock=SimpleNamespace(check=check),environment={MODULE.ANDROID_RUN_ENV:'42',MODULE.ANDROID_ATTEMPT_ENV:'1'})
                reader=MODULE.AndroidPrivateInputs(phase,'a'*40,native)
                failure=None
                with patch.object(MODULE.os,'open',opening),patch.object(MODULE.os,'stat',stating), \
                     patch.object(MODULE.os,'fstat',lambda fd: metadata(real_fstat(fd))),patch.object(MODULE.os,'close',closing):
                    try:
                        with reader:
                            self.assertEqual((len(reader.fds),len(reader.files)),(18,4))
                            self.assertEqual(reader.public_certificate,doc['publicCertificateSha256'])
                            if fault=='ancestor':
                                (scratch/'Users/runner/work').rename(scratch/'Users/runner/old-work')
                                (scratch/'Users/runner/work').mkdir(mode=0o700)
                            elif fault=='leaf':
                                leaf=credentials/'upload.jks';leaf.write_bytes(b'x'*len(data['upload.jks']))
                            elif fault=='ancestor-flags-post': flag_values[root_key] = 0x00080000
                            elif fault=='primary-close': raise sentinel
                    except BaseException as error: failure=error
                    finally:
                        # Safety precedes assertions, including failed __enter__.
                        reader.close(primary=True)
                self.assertTrue(reader.closed)
                self.assertEqual(len(opened),len(closed))
                self.assertEqual(len(closed),len(set(closed)))
                self.assertFalse(reader.fds or reader.files or reader.directories)
                self.assertTrue(all(mode&os.O_NONBLOCK for path,mode in flags if path in ('android-input-fixture.json',*MODULE.ANDROID_PRIVATE_FILES)))
                if fault in (None, 'protected-root', 'protected-ancestors'): self.assertIsNone(failure)
                elif fault=='primary-close': self.assertIs(failure,sentinel)
                else:
                    expected={'ancestor':'android-input-ancestor-post','leaf':'android-input-private-post',
                        'fifo':'android-input-private-file','hardlink':'android-input-private-file',
                        'close':'android-input-close-or-clock','post-close-clock':'android-input-close-or-clock',
                        'ancestor-flags-post':'android-input-ancestor-post',
                        **{key:'android-input-directory-original' for key in ('unknown-ancestor-flag','task-flag',
                            'normal-flag','tool-flag','ancestor-group-write','ancestor-foreign-owner')}}[fault]
                    self.assertIsInstance(failure,MODULE.Refused)
                    self.assertEqual(str(failure),expected)


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
        # The original owner wait callsite used to disappear from the bounded
        # first+last3 traceback. Preserve only its exact SOURCE/qualname, not locals.
        command_source = ROOT / "src/mobile_release/_command_process.py"
        normal_source = str(ROOT / "desktop/tools/macos_normal_ui_runner.py")
        def trace(specs):
            following = None
            for filename, line, qualname in reversed(specs):
                code = SimpleNamespace(co_filename=filename)
                if qualname is not None: code.co_qualname = qualname
                following = SimpleNamespace(tb_frame=SimpleNamespace(f_code=code), tb_lineno=line, tb_next=following)
            return SimpleNamespace(__traceback__=following)
        core_source = str(command_source)
        rows = [(normal_source, 1, "main"), (core_source, 3307, "_Outer.body"),
                (core_source, 100, "other"), (core_source, 3264, "_Outer._until"),
                (core_source, 1162, "Context.check"), (core_source, 52, "_require")]
        kept = MODULE.normal_admission_failure("execute", trace(rows), None, [])
        self.assertEqual(kept["sourceFrames"], [{"source": "macos_normal_ui_runner.py", "line": 1},
            {"source": "_command_process.py", "line": 3307}, {"source": "_command_process.py", "line": 1162},
            {"source": "_command_process.py", "line": 52}])
        self.assertTrue(kept["sourceFramesTruncated"])
        self.assertEqual(MODULE.classify_normal_admission_failure(MODULE.encoded(kept))["sourceFrames"], kept["sourceFrames"])
        for qualname in (None, "_Other.body", "private-" + private):
            fallback = list(rows); fallback[1] = (core_source, 3307, qualname)
            ordinary = MODULE.normal_admission_failure("execute", trace(fallback), None, [])
            self.assertEqual([row["line"] for row in ordinary["sourceFrames"]], [1, 3264, 1162, 52])
            self.assertNotIn(private.encode(), MODULE.encoded(ordinary))
        foreign = list(rows); foreign[1] = ("/private/_command_process.py", 3307, "_Outer.body")
        self.assertEqual([row["line"] for row in MODULE.normal_admission_failure("execute", trace(foreign), None, [])["sourceFrames"]],
                         [1, 3264, 1162, 52])
        for short in (rows[:2], rows[:3], rows[:4], rows[1:2]):
            self.assertEqual([row["line"] for row in MODULE.normal_admission_failure("execute", trace(short), None, [])["sourceFrames"]],
                             [row[1] for row in short])  # Keep all <=4 without duplicate owner/caller.
        long = [(core_source, index + 1, "other") for index in range(70)]
        long[66] = (core_source, 3307, "_Outer.body")
        limited = MODULE.normal_admission_failure("execute", trace(long), None, [])
        self.assertEqual([row["line"] for row in limited["sourceFrames"]], [1, 62, 63, 64])
        self.assertTrue(limited["sourceFramesTruncated"])
        command = {"role": "normal-ui-build", "returncode": 65, "timeoutSeconds": 120, "roleCapSeconds": 240,
            "outputLimitBytes": 1048576, "stdoutBytes": 32, "stderrBytes": 12,
            "argvSha256": "a" * 64, "stdoutSha256": "b" * 64, "stderrSha256": "c" * 64}
        with_commands = dict(value, commands=[command])
        selected = MODULE.classify_normal_admission_failure(MODULE.encoded(with_commands))
        self.assertEqual(selected["commands"], [{"role": "normal-ui-build", "returncode": 65, "stdoutBytes": 32, "stderrBytes": 12}])
        # Real existing record emitters, inert process port: these seven fixed
        # returned roles must not erase an unrelated original exception.
        for role in ('ios-account-produce','ios-account-observe','candidate-fixture-git-init','candidate-fixture-git-add',
                     'candidate-fixture-git-commit','candidate-fixture-git-identity','candidate-fixture-git-clean'):
            for code in (0,1):
                def returned(argv,**kwargs):
                    return subprocess.CompletedProcess(argv,code,private.encode(),b'private stderr')
                clock=SimpleNamespace(allowance=lambda cap:cap,check=lambda:None)
                phase=MODULE.NormalPhase(SimpleNamespace(run_owned=returned),{},ROOT,clock,retain_nonzero=True)
                argv=['inert-never-executed',private]
                if role.startswith('ios-account-'):
                    mode=role.removeprefix('ios-account-');cap,limit=(180,16384) if mode=='produce' else (90,2048)
                    fixture=object.__new__(MODULE.NormalIOSRecoveryFixture);fixture.phase=phase
                    original=fixture._account_original(argv,{},ROOT,cap,limit,mode)
                else:
                    original=phase.call(role,argv,15,65536)
                try: MODULE.need(False,private)
                except MODULE.Refused as error:
                    failure=MODULE.normal_admission_failure('execute',error,None,phase.records)
                projected=MODULE.classify_normal_admission_failure(MODULE.encoded(failure))
                self.assertEqual(projected['status'],'observed-exception-only')
                self.assertEqual(projected['commands'],[dict(role=role,returncode=code,stdoutBytes=len(private),stderrBytes=14)])
                self.assertEqual(projected['sourceFrames'],failure['sourceFrames'])
                self.assertEqual(projected['ownerFailure'],failure['ownerFailure'])
                self.assertFalse(projected['nativeSuccessInferred']);self.assertTrue(projected['unknownStateRetained'])
                self.assertIs(phase.first_nonzero,original if code else None)
                self.assertEqual(original.returncode,code);self.assertNotIn(private.encode(),MODULE.encoded(projected))
                self.assertNotIn(b'private stderr',MODULE.encoded(projected));self.assertLessEqual(len(MODULE.encoded(projected))+1,4096)
                for unknown in ('ios-account-delete','candidate-fixture-git-fetch'):
                    bad=dict(failure,commands=[dict(phase.records[0],role=unknown)])
                    self.assertEqual(MODULE.classify_normal_admission_failure(MODULE.encoded(bad))['status'],'unavailable')
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
        # Real result-query guard with inert original/FD doubles only. There is
        # no xcresult bundle, native command, filesystem access or new owner.
        base = (11, 22, stat.S_IFDIR | 0o700, 1001, 1002, 2, 4096, 700, 800)
        names = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
        mask_keys = ("heldVsPre", "namedVsPre", "heldVsNamed")
        request = dict(target=MODULE.ARM_TARGET, methods=(MODULE.OUTPUT_DATA_METHOD,), allowance=60,
            timeout=120, phaseSeconds=345, derived=Path("/inert/normal-ui/DerivedData"),
            result=Path("/inert/normal-ui/output-data-test.xcresult"))
        mutable = base[:5] + tuple(value + 1 for value in base[5:])
        def exercise(held, named, *, query_kind="summary", nonzero=False, annotation_fault=False,
                     close_fault=False, clock_fault=False, first_query_metadata=False):
            events, records, published = [], [], []
            guard_error = MODULE.Refused("output-data-result-post")
            original = subprocess.CompletedProcess(["inert-xctest"], 0, b"inert-original", b"")
            real_need = MODULE.need
            def need_original(condition, reason):
                if not condition and reason == "output-data-result-post": raise guard_error
                return real_need(condition, reason)
            def current(values):
                changed_at = 1 if query_kind == "summary" else 2
                if len(records) >= changed_at: return values
                return mutable if first_query_metadata and len(records) == 1 else base
            def fd_stat(fd):
                self.assertEqual(fd, 77); events.append("fstat")
                return SimpleNamespace(**dict(zip(names, current(held))))
            def named_stat(path, *, follow_symlinks):
                self.assertEqual(path, request["result"]); self.assertFalse(follow_symlinks); events.append("stat")
                return SimpleNamespace(**dict(zip(names, current(named))))
            def consume(fd):
                self.assertEqual(fd, 77); events.append("close")
                if close_fault: raise OSError("inert-consuming-close")
            def clock_check():
                events.append("clock")
                if clock_fault: raise TimeoutError("inert-result-deadline")
            def source_state(*args): events.append("source"); return ()
            def query(role, argv, cap, limit):
                self.assertEqual((cap, limit), (30, 262144)); events.append(role)
                code = 17 if nonzero and argv[4] == query_kind else 0
                records.append(dict(command, role=role, returncode=code, timeoutSeconds=30, roleCapSeconds=30,
                    outputLimitBytes=262144, stdoutBytes=1, stderrBytes=0))
                return subprocess.CompletedProcess(argv, code, b"x", b"")
            def parse(*args): events.append("parse"); return {"inert": True}
            def capture(*args): events.append("write"); published.append(args)
            def annotate_failure(*args): raise KeyboardInterrupt("inert-annotation-interruption")
            phase = SimpleNamespace(call=query, records=records,
                clock=SimpleNamespace(check=clock_check, before_publication=lambda: {}))
            returned = caught = None
            with ExitStack() as stack:
                for name, replacement in (("normal_source_state", source_state),
                        ("output_data_read_build", lambda *args: "a" * 64),
                        ("run_admitted_test", lambda *args, **kwargs: (original, {})),
                        ("open_directory", lambda *args: 77), ("need", need_original),
                        ("os", SimpleNamespace(fstat=fd_stat, stat=named_stat, close=consume,
                                               getuid=lambda: base[3], getgid=lambda: base[4])),
                        ("output_data_result", parse), ("exclusive_output", capture)):
                    stack.enter_context(patch.object(MODULE, name, replacement))
                if annotation_fault:
                    stack.enter_context(patch.object(MODULE, "output_data_result_post_masks", annotate_failure))
                try: returned = MODULE.execute_output_data_phase(phase, request, "a" * 40, (1024**3,) * 2)
                except BaseException as error: caught = error
            self.assertEqual(events.count("close"), 1)
            self.assertEqual(events.count("clock"), 2 if caught is None and returned.returncode == 0 else 1)
            return returned, caught, guard_error, records, events, published

        # Original object/type/permissions stay fixed across both queries.
        # Layout metadata is allowed to change only with a matching live name.
        for index in range(5):
            altered = tuple(value + (slot == index) for slot, value in enumerate(base))
            with self.subTest(result_post_component=index):
                returned, caught, expected, records, events, published = exercise(altered, altered)
                self.assertIsNone(returned); self.assertIs(caught, expected)
                self.assertEqual(events, ["source", "fstat", "stat", "normal-ui-summary", "fstat", "stat", "close", "clock"])
                self.assertEqual(published, [])
                result = MODULE.normal_admission_failure("execute", caught, None, records)
                observation = result["resultPost"]
                self.assertEqual(observation, dict(schemaVersion=1, query="summary", originalReturncode=0,
                    heldVsPre=[slot == index for slot in range(9)], namedVsPre=[slot == index for slot in range(9)],
                    heldVsNamed=[False] * 9))
                projected = MODULE.classify_normal_admission_failure(MODULE.encoded(result))
                self.assertEqual(projected["resultPost"], observation)
                self.assertEqual(projected["status"], "observed-exception-only")
                self.assertFalse(projected["nativeSuccessInferred"])
                self.assertLessEqual(len(MODULE.encoded(projected)) + 1, 4096)
        # Reproduce all four observed mutable fields, independently and together,
        # at either query. Both queries, semantic parsing and SOURCE POST still run.
        for index in (5, 6, 7, 8, None):
            altered = mutable if index is None else tuple(value + (slot == index) for slot, value in enumerate(base))
            for kind in ("summary", "tests"):
                with self.subTest(mutable_component=index, query=kind):
                    returned, caught, _, observed_records, events, published = exercise(altered, altered, query_kind=kind)
                    self.assertIsNone(caught); self.assertEqual(returned.returncode, 0)
                    self.assertEqual([row["role"] for row in observed_records], ["normal-ui-summary", "normal-ui-test-tree"])
                    self.assertEqual(events.count("source"), 2); self.assertEqual(events.count("parse"), 1)
                    self.assertEqual(len(published), 1)
            # Mutable is not an exemption for disagreement between the held
            # original and its name: even timestamp-only disagreement refuses.
            returned, caught, expected, _, events, published = exercise(base, altered)
            self.assertIsNone(returned); self.assertIs(caught, expected)
            self.assertNotIn("parse", events); self.assertEqual(published, [])
        # A successful mutable first query never adopts a new identity baseline.
        changed_owner = mutable[:4] + (base[4] + 1,) + mutable[5:]
        for held, named in ((changed_owner, changed_owner), (mutable, changed_owner)):
            returned, caught, expected, observed_records, events, published = exercise(
                held, named, query_kind="tests", first_query_metadata=True)
            self.assertIsNone(returned); self.assertIs(caught, expected)
            self.assertEqual(len(observed_records), 2); self.assertNotIn("parse", events)
            self.assertEqual(events.count("source"), 1); self.assertEqual(published, [])
        # Successful queries cannot outrun a consuming close or phase deadline.
        for flags, error_type in (({"close_fault": True}, OSError), ({"clock_fault": True}, TimeoutError)):
            returned, caught, _, _, events, published = exercise(mutable, mutable, **flags)
            self.assertIsNone(returned); self.assertIsInstance(caught, error_type)
            self.assertNotIn("parse", events); self.assertEqual(published, [])
        replacement = tuple(value + (index == 1) for index, value in enumerate(base))
        returned, caught, expected, records, events, published = exercise(base, replacement, query_kind="tests")
        self.assertIs(caught, expected); self.assertIsNone(returned); self.assertEqual(published, [])
        self.assertEqual([x for x in events if x.startswith("normal-ui-")], ["normal-ui-summary", "normal-ui-test-tree"])
        self.assertNotIn("parse", events); self.assertNotIn("write", events); self.assertEqual(events.count("source"), 1)
        valid = MODULE.normal_admission_failure("execute", caught, None, records)
        self.assertEqual(valid["resultPost"]["heldVsPre"], [False] * 9)
        self.assertEqual(valid["resultPost"]["namedVsPre"], [index == 1 for index in range(9)])
        self.assertEqual(valid["resultPost"]["heldVsNamed"], valid["resultPost"]["namedVsPre"])
        other = tuple(value + 2 * (index == 1) for index, value in enumerate(base))
        triple = MODULE.output_data_result_post_masks("tests", base, replacement, other)
        self.assertEqual(MODULE.admit_output_data_result_post(triple, records), triple)
        for flags in ((True, False), (False, True)):
            returned, caught, expected, observed_records, events, published = exercise(replacement, replacement,
                annotation_fault=flags[0], close_fault=flags[1])
            self.assertIs(caught, expected); self.assertIsNone(returned); self.assertEqual(published, [])
            self.assertEqual(events[-2:], ["close", "clock"])
            value = MODULE.normal_admission_failure("execute", caught, None, observed_records)
            self.assertEqual("resultPost" in value, not flags[0])
        for kind in ("summary", "tests"):
            returned, caught, _, observed_records, events, published = exercise(replacement, replacement, query_kind=kind, nonzero=True)
            self.assertIsNone(caught); self.assertEqual(returned.returncode, 17); self.assertEqual(published, [])
            self.assertNotIn("parse", events); self.assertNotIn("write", events)
            self.assertEqual(events.count("source"), 1)
            self.assertEqual(len(observed_records), 1 if kind == "summary" else 2)
        returned, caught, _, records_ok, events, published = exercise(base, base)
        self.assertIsNone(caught); self.assertEqual(returned.returncode, 0); self.assertEqual(len(published), 1)
        self.assertEqual(events.count("source"), 2); self.assertEqual(events.count("parse"), 1)

        # Closed decoder: no raw stats/names/paths, impossible equality triples,
        # absent guard failure, wrong query original, or later command is accepted.
        bad_observations = [dict(valid["resultPost"], **change) for change in (
            {"schemaVersion": True}, {"query": "private-query"}, {"originalReturncode": True},
            {"extra": private}, {"heldVsPre": [False] * 8}, {"heldVsPre": [0] * 9},
            {"heldVsPre": [False] * 9, "namedVsPre": [False] * 9, "heldVsNamed": [False] * 9})]
        for index in range(3):
            impossible = dict(valid["resultPost"], **{key: [False] * 9 for key in mask_keys})
            impossible[mask_keys[index]][0] = True
            bad_observations.append(impossible)
        invalid_records = [dict(valid, resultPost=entry) for entry in bad_observations]
        invalid_records += [dict(valid, **change) for change in (
            {"stage": "loader"}, {"exceptionClass": "OSError"},
            {"commands": [dict(valid["commands"][-1], returncode=1)]},
            {"commands": [dict(valid["commands"][-1], role="normal-ui-summary")]},
            {"commands": valid["commands"] + [dict(command, role="normal-ui-source-roster", returncode=0)]})]
        for invalid in invalid_records:
            self.assertEqual(MODULE.classify_normal_admission_failure(MODULE.encoded(invalid))["status"], "unavailable")
        for stage, error in (("loader", expected), ("execute", MODULE.Refused("different-refusal")),
                             ("execute", ValueError("output-data-result-post"))):
            error._output_data_result_post = valid["resultPost"]
            self.assertNotIn("resultPost", MODULE.normal_admission_failure(stage, error, None, valid["commands"]))
        with patch.object(MODULE, "admit_output_data_result_post", side_effect=KeyboardInterrupt(private)):
            expected._output_data_result_post = valid["resultPost"]
            self.assertNotIn("resultPost", MODULE.normal_admission_failure("execute", expected, None, valid["commands"]))



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
        self.assertEqual(build["target"], "aarch64-apple-darwin")
        arm_build = MODULE.normal_build_arguments(build["derived"])
        targets = (("aarch64-apple-darwin", "arm64", "github-hosted-macos26-arm64"),
                   ("x86_64-apple-darwin", "x86_64", "github-hosted-macos26-x86_64"))
        requests = {}
        for target_value, machine, marker in targets:
            self.assertEqual(MODULE.normal_target_data(target_value), (machine, marker))
            selected_build = MODULE.normal_request(["--target", target_value, "--normal-build"], temporary)
            expected_build = list(arm_build)
            expected_build[expected_build.index("-destination") + 1] = ("platform=macOS" if machine == "x86_64"
                else "platform=macOS,arch=" + machine)
            if machine == "x86_64": expected_build.append("ARCHS=x86_64")
            self.assertEqual(MODULE.normal_build_arguments(build["derived"], target=target_value), expected_build)
            self.assertEqual(selected_build, dict(build, target=target_value))
            for name, (_, allowance, cap) in MODULE.NORMAL_SELECTIONS.items():
                arguments = normal_arguments(name)
                arguments[8] = "platform=macOS,arch=" + machine
                selected_test = MODULE.normal_request(["--target", target_value, *arguments], temporary)
                selected_summary = MODULE.normal_request(["--target", target_value, "--normal-summary", name], temporary)
                self.assertEqual(selected_test["target"], target_value)
                self.assertEqual((selected_test["allowance"], selected_test["timeout"], selected_test["phaseSeconds"]),
                                 (allowance, cap, {180: 345, 420: 585, 720: 885}[cap]))
                self.assertEqual((selected_summary["target"], selected_summary["timeout"], selected_summary["phaseSeconds"]),
                                 (target_value, 30, 90))
                command = MODULE.xcode_test_arguments("/fixed.xctestrun", normal / name,
                    selected_test["methods"], allowance, target=target_value)
                self.assertEqual(command[command.index("-destination") + 1],
                                 "platform=macOS" if machine == "x86_64" else arguments[8])
                self.assertFalse(any(value.startswith("ARCHS=") for value in command))
                other = "x86_64-apple-darwin" if machine == "arm64" else "aarch64-apple-darwin"
                with self.assertRaises(MODULE.Refused):
                    MODULE.normal_request(["--target", other, *arguments], temporary)
                if name == "test.xcresult": requests[target_value] = (selected_build, selected_test, selected_summary)
        for invalid in (None, True, "arm64", "x86_64", "X86_64-apple-darwin", "x86_64-apple-darwin "):
            with self.subTest(target=invalid), self.assertRaises(MODULE.Refused):
                MODULE.normal_build_arguments(build["derived"], target=invalid)
        for arguments in (["--target"], ["--target", "x86_64-apple-darwin"],
                          ["--target", "other", "--normal-build"],
                          ["--target", "x86_64-apple-darwin", "--target", "x86_64-apple-darwin", "--normal-build"],
                          ["--normal-build", "--target", "x86_64-apple-darwin"],
                          ["--target=x86_64-apple-darwin", "--normal-build"],
                          ["--target", "x86_64-apple-darwin", *normal_arguments()]):
            with self.subTest(arguments=arguments), self.assertRaises(MODULE.Refused):
                MODULE.normal_request(arguments, temporary)
        with self.assertRaises(MODULE.Refused):
            MODULE.xcode_test_arguments("/fixed.xctestrun", "/fresh.xcresult", (MODULE.PACKAGED_METHOD,),
                                       60, target="x86_64-apple-darwin")
        with patch.object(MODULE, "RunnerProducts") as unopened:
            with self.assertRaises(MODULE.Refused):
                MODULE.run_admitted_test(lambda *args: self.fail("no dispatch"), build["derived"], normal / "test.xcresult",
                                         (MODULE.PACKAGED_METHOD,), 60, 180, target="x86_64-apple-darwin")
            unopened.assert_not_called()
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
            for target_value, machine, marker in targets:
                selected_environment = dict(environment, TEST_RUNNER_MRK_NORMAL_UI_HOSTED_JOB=marker)
                with patch.object(MODULE.platform, "machine", return_value=machine), \
                        patch.dict(MODULE.os.environ, selected_environment, clear=True):
                    for request in requests[target_value]:
                        limit = 32 * 1024**3 if request["phase"] == "build" else 1024**3
                        with patch.object(sys.modules["resource"], "getrlimit", return_value=(limit, limit)):
                            self.assertEqual(MODULE.normal_context(request),
                                             (root, source, selected_environment, (limit, limit)))
                            other_machine = "x86_64" if machine == "arm64" else "arm64"
                            with patch.object(MODULE.platform, "machine", return_value=other_machine), self.assertRaises(MODULE.Refused):
                                MODULE.normal_context(request)
                            with patch.dict(MODULE.os.environ, {"TEST_RUNNER_MRK_NORMAL_UI_HOSTED_JOB": "github-hosted-macos26-" + other_machine}), \
                                    self.assertRaises(MODULE.Refused):
                                MODULE.normal_context(request)
                            with self.assertRaises(MODULE.Refused):
                                MODULE.normal_context(dict(request, target="unsupported"))
            for key in ("PATH", "HOME", "LANG", "DEVELOPER_DIR", "TEST_RUNNER_MRK_NORMAL_UI_HOSTED_JOB",
                        "TEST_RUNNER_MRK_NORMAL_UI_APPLICATION_SOURCE"):
                with self.subTest(environment=key), patch.dict(MODULE.os.environ, {key: "not-admitted"}), self.assertRaises(MODULE.Refused):
                    MODULE.normal_context(build)
            with patch.object(MODULE.os, "geteuid", return_value=502), self.assertRaises(MODULE.Refused):
                MODULE.normal_context(build)
        # Actual Python handoffs, with only inert original/IO doubles. This is
        # target propagation and first-return DATA, never native/UI evidence.
        for target_value, machine, _ in targets:
            for request in requests[target_value]:
                for status in (0, 65):
                    returned = []
                    def fixed_call(role, arguments, timeout, output_limit=1024 * 1024):
                        body = tools[role[len("normal-toolchain-"):]] if role.startswith("normal-toolchain-") else b"inert original"
                        value = subprocess.CompletedProcess(arguments, 0 if role.startswith("normal-toolchain-") else status, body, b"")
                        returned.append((role, value, timeout, output_limit))
                        return value
                    phase = SimpleNamespace(call=fixed_call, records=[], environment={},
                        clock=SimpleNamespace(check=lambda: None, before_publication=lambda: {}))
                    with self.subTest(target=target_value, phase=request["phase"], status=status), \
                            patch.object(MODULE, "normal_source_state", return_value={"inert": "source"}) as source_check, \
                            patch.object(MODULE, "exclusive_output") as publication, \
                            patch.object(MODULE.os.path, "lexists", return_value=False), \
                            patch.object(MODULE.os, "stat", return_value=SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=501)), \
                            patch.object(MODULE.os, "getuid", return_value=501), \
                            patch.object(MODULE, "RunnerProducts") as products_type:
                        products = products_type.return_value.__enter__.return_value
                        products_type.return_value.__exit__.return_value = False
                        products.products = build["derived"] / "Build/Products"
                        products.manifest = "fixed.xctestrun"
                        products.admit.return_value = {"scope": "inert-products-not-native-authority"}
                        limit = 32 * 1024**3 if request["phase"] == "build" else 1024**3
                        actual = MODULE.execute_normal_phase(phase, request, source, (limit, limit))
                        self.assertIs(actual, returned[-1][1])
                        self.assertEqual(actual.returncode, status)
                        facts = json.loads(publication.call_args.args[1])
                        self.assertEqual(facts["target"], target_value)
                        self.assertEqual(source_check.call_count, 2)
                        if request["phase"] == "build":
                            expected = list(arm_build)
                            expected[expected.index("-destination") + 1] = ("platform=macOS" if machine == "x86_64"
                                else "platform=macOS,arch=" + machine)
                            if machine == "x86_64": expected.append("ARCHS=x86_64")
                            self.assertEqual(actual.args, expected)
                            self.assertEqual(returned[-1][2], 240)
                            products_type.assert_not_called()
                        elif request["phase"] == "summary":
                            self.assertEqual(actual.args, ["/usr/bin/xcrun", "xcresulttool", "get", "test-results", "summary",
                                "--path", str(normal / "test.xcresult"), "--compact"])
                            self.assertEqual(returned[-1][2:], (30, 262144))
                            products_type.assert_not_called()
                        else:
                            self.assertEqual(actual.args, ["/usr/bin/xcodebuild", "test-without-building", "-xctestrun",
                                str(products.products / products.manifest), "-destination", "platform=macOS" if machine == "x86_64" else "platform=macOS,arch=" + machine,
                                "-destination-timeout", "15", "-resultBundlePath", str(normal / "test.xcresult"),
                                "-only-testing:" + MODULE.CLASS + "testLaunchCancelAndQuit", "-parallel-testing-enabled", "NO",
                                "-test-timeouts-enabled", "YES", "-default-test-execution-time-allowance", "60",
                                "-maximum-test-execution-time-allowance", "60", "-disableAutomaticPackageResolution"])
                            self.assertEqual(returned[-1][2], 180)
                            products.admit.assert_called_once_with(fixed_call)
                            self.assertEqual(products.check.call_count, 2)
                            products_type.return_value.__exit__.assert_called_once_with(None, None, None)
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

        # Closed engineering profile DATA only. Ordinary/packaged routing is
        # still exercised above; no test here launches an app or compiler.
        engineering_work = Path("/Users/runner/work/_temp/mrk-macos-engineering-ui.ABCDef12")
        engineering_tmp = str(engineering_work / "normal-ui/tmp") + "/"
        engineering_requests = {}
        for mode, seconds, cap in (("build", 450, 240), ("test", 345, 180), ("summary", 90, 30)):
            arguments = ["--engineering-main-" + mode, "--work", str(engineering_work)]
            request = MODULE.engineering_request(arguments, engineering_tmp)
            engineering_requests[mode] = request
            self.assertEqual((request["phase"], request["phaseSeconds"], request["timeout"], request["target"]),
                             (mode, seconds, cap, "aarch64-apple-darwin"))
            self.assertEqual(request["work"], engineering_work)
            self.assertEqual(request["derived"], engineering_work / "normal-ui/DerivedData")
            self.assertEqual(request["methods"], (MODULE.ENGINEERING_METHOD,) if mode == "test" else ())
            with self.assertRaises(MODULE.Refused): MODULE.normal_request(arguments, engineering_tmp)
            for changed in (arguments[1:], arguments + ["extra"], ["--target", MODULE.INTEL_TARGET] + arguments,
                            [arguments[0], "--work", str(engineering_work) + "/"],
                            [arguments[0], "--work", str(engineering_work).replace("engineering-ui.", "installed.")],
                            ["--normal-" + mode, *arguments[1:]]):
                with self.subTest(engineering_arguments=changed), self.assertRaises(MODULE.Refused):
                    MODULE.engineering_request(changed, engineering_tmp)
            with self.assertRaises(MODULE.Refused): MODULE.engineering_request(arguments, temporary)
        selected_method = "MRKNormalAppUITests/NormalAppUITests/testEngineeringMainCatalogueAndQuit"
        self.assertEqual(MODULE.ENGINEERING_METHOD, selected_method)
        self.assertEqual(MODULE.ENGINEERING_MAIN_BYTES, 256 * 1024 * 1024)
        expected_arguments = ["/usr/bin/xcodebuild", "test-without-building", "-xctestrun", "fixed.xctestrun",
            "-destination", "platform=macOS,arch=arm64", "-destination-timeout", "15", "-resultBundlePath", "fixed.xcresult",
            "-only-testing:" + selected_method, "-parallel-testing-enabled", "NO", "-test-timeouts-enabled", "YES",
            "-default-test-execution-time-allowance", "60", "-maximum-test-execution-time-allowance", "60",
            "-disableAutomaticPackageResolution"]
        self.assertEqual(MODULE.xcode_test_arguments(Path("fixed.xctestrun"), Path("fixed.xcresult"),
                         (selected_method,), 60, engineering=True), expected_arguments)
        for selected, allowance, target_value, enabled in (((MODULE.PACKAGED_METHOD,), 60, MODULE.ARM_TARGET, True),
                ((selected_method,), 300, MODULE.ARM_TARGET, True), ((selected_method,), 60, MODULE.INTEL_TARGET, True),
                ((selected_method,), 60, MODULE.ARM_TARGET, False), ((selected_method,), 60, MODULE.ARM_TARGET, 1)):
            with self.assertRaises(MODULE.Refused):
                MODULE.xcode_test_arguments(Path("fixed.xctestrun"), Path("fixed.xcresult"), selected,
                                            allowance, target=target_value, engineering=enabled)
        with patch.object(MODULE, "RunnerProducts") as products_type:
            with self.assertRaises(MODULE.Refused):
                MODULE.run_admitted_test(lambda *_: self.fail("mixed scope dispatched"), Path("inert"), Path("inert-result"),
                                         (selected_method,), 60, 180, target=MODULE.INTEL_TARGET, engineering=True)
            products_type.assert_not_called()

        binding = dict(sourceSha="a" * 40, sourceTree="b" * 40,
            workflowPath=".github/workflows/desktop-macos-engineering-ui.yml", workflowSha="a" * 40,
            workflowRef="mobile-release-kit/mobile-release-kit/.github/workflows/desktop-macos-engineering-ui.yml@refs/heads/verify/desktop-macos-engineering-ui",
            workflowSha256="c" * 64, runId="123", attempt="1", engineeringWork=str(engineering_work))
        rust = dict(release="1.98.1", commitHash="48a229ceaefd4985c50990b14116b6d856af0985", target="aarch64-apple-darwin")
        compiled = dict(relativePath="target/engineering-main/mobile-release-kit-desktop", bytes=17, sha256="d" * 64)
        checks = {"acquire": ("rust-version-target", "mac-cargo-version", "locked-platform-metadata", "node-version", "npm-locked-no-scripts"),
                  "compile": ("rust-version-target", "mac-cargo-version", "node-version", "typescript-no-emit", "vite-assets", "tauri-debug-compile-only")}
        for mode in ("acquire", "compile"):
            receipt = dict(schemaVersion=1, scope="desktop-macos-engineering-ui-compile-only-v1", phase=mode,
                status="passed", **binding, platform="macos", rust=rust, node="v24.20.0",
                checks=[dict(check=name, exitCode=0) for name in checks[mode]])
            if mode == "compile": receipt["compiledMain"] = compiled
            MODULE.engineering_compile_receipt(receipt, binding, mode, compiled=compiled if mode == "compile" else None)
            for key, changed_value in (("schemaVersion", True), ("status", "failed"), ("sourceTree", "e" * 40),
                    ("engineeringWork", str(engineering_work) + "-foreign"), ("checks", receipt["checks"][:-1]),
                    ("checks", [*receipt["checks"], receipt["checks"][0]]), ("node", "v0.0.0"),
                    ("rust", dict(rust, target="x86_64-apple-darwin"))):
                with self.subTest(engineering_receipt=(mode, key)), self.assertRaises(MODULE.Refused):
                    MODULE.engineering_compile_receipt(dict(receipt, **{key: changed_value}), binding, mode,
                                                       compiled=compiled if mode == "compile" else None)
            for key in tuple(receipt):
                changed = dict(receipt); del changed[key]
                with self.assertRaises(MODULE.Refused):
                    MODULE.engineering_compile_receipt(changed, binding, mode, compiled=compiled if mode == "compile" else None)
            with self.assertRaises(MODULE.Refused):
                MODULE.engineering_compile_receipt(dict(receipt, productReady=True), binding, mode,
                                                   compiled=compiled if mode == "compile" else None)
            if mode == "compile":
                for key, value in (("bytes", True), ("bytes", 0), ("bytes", 256 * 1024 * 1024 + 1),
                        ("relativePath", "target/aarch64-apple-darwin/debug/mobile-release-kit-desktop"),
                        ("sha256", "not-a-digest")):
                    wrong = dict(compiled, **{key: value})
                    with self.assertRaises(MODULE.Refused):
                        MODULE.engineering_compile_receipt(dict(receipt, compiledMain=wrong), binding, mode, compiled=wrong)

        marker = ("MRK_MACOS_ENGINEERING_MAIN_UI=mainRequest=1;completion=1;body=1;handoff=1;mainIdentity=1;catalogueGuide=1;"
                  "projectSelected=0;editCapability=unavailable;originalTerminated=1;failureCleanup=0;caseDeadlineMet=1;"
                  "cleanExitStatus=unavailable;allWorkerFinality=unavailable")
        case = "-[MRKNormalAppUITests.NormalAppUITests testEngineeringMainCatalogueAndQuit]"
        output = ("Test Case '" + case + "' started.\n" + marker + "\nTest Case '" + case + "' passed (1.000 seconds).\n").encode()
        summary = dict(totalTestCount=1, passedTests=1, failedTests=0, skippedTests=0, expectedFailures=0)
        value = MODULE.engineering_ui_result(output, json.dumps(summary).encode())
        self.assertEqual(value["testIdentifier"], selected_method)
        self.assertEqual(value["testCounts"], summary)
        self.assertIs(value["sameOriginalNormalQuitObserved"], True)
        self.assertIsNone(value["cleanExitStatus"])
        self.assertEqual(value["allWorkerFinality"], "not-established")
        self.assertFalse(value["fullUIQualified"])
        self.assertFalse(value["productReady"])
        for changed in (b"", output + output, output.replace(marker.encode(), b""),
                output.replace(b"catalogueGuide=1", b"catalogueGuide=0"), output.replace(b"originalTerminated=1", b"originalTerminated=0"),
                output.replace(b"testEngineeringMainCatalogueAndQuit", b"testLaunchCancelAndQuit"),
                output.replace(b" passed ", b" failed "), output.replace(b"failureCleanup=0", b"failureCleanup=1"),
                output.replace(marker.encode(), marker.encode() + b"\n" + marker.encode()),
                (marker + "\n").encode() + output.replace((marker + "\n").encode(), b""),
                output + b"MRK_MACOS_UI_FAILURE_CLEANUP=attempted\n", output + b"MRK_MACOS_NORMAL_UI=not-authority\n"):
            with self.assertRaises(MODULE.Refused): MODULE.engineering_ui_result(changed, json.dumps(summary).encode())
        for key in summary:
            for invalid in (True, summary[key] + 1):
                with self.assertRaises(MODULE.Refused):
                    MODULE.engineering_ui_result(output, json.dumps(dict(summary, **{key: invalid})).encode())
        with self.assertRaises(MODULE.Refused):
            MODULE.engineering_ui_result(output, b'{"totalTestCount":1,"passedTests":1,"passedTests":1}')

        # Exercise actual engineering_context with inert directory originals;
        # only this module's os binding is replaced, never a real syscall here.
        compiler_root = Path("/Users/runner/work/_temp/mrk-desktop-foundation-ABCDef12")
        engine_environment = dict(environment, TMPDIR=engineering_tmp,
            GITHUB_SHA=source, GITHUB_WORKSPACE=str(root), GITHUB_REPOSITORY="mobile-release-kit/mobile-release-kit",
            GITHUB_EVENT_NAME="push", GITHUB_REF="refs/heads/verify/desktop-macos-engineering-ui", GITHUB_WORKFLOW_SHA=source,
            GITHUB_WORKFLOW_REF=binding["workflowRef"], GITHUB_RUN_ID="123", GITHUB_RUN_ATTEMPT="1",
            MRK_MACOS_WORK=str(engineering_work), MRK_DESKTOP_CI_ROOT=str(compiler_root),
            MUST_NOT_INHERIT="inert private environment sentinel")
        observed = SimpleNamespace(st_dev=1, st_ino=2, st_mode=stat.S_IFDIR | 0o700, st_uid=501, st_gid=20,
                                   st_nlink=2, st_size=0, st_mtime_ns=1, st_ctime_ns=1)
        closed_directories = []
        inert_os = SimpleNamespace(environ=engine_environment, getuid=lambda: 501, geteuid=lambda: 501,
            getgid=lambda: 20, getegid=lambda: 20, stat=lambda *_a, **_k: observed,
            fstat=lambda _fd: observed, close=closed_directories.append)
        with ExitStack() as stack:
            for context in (patch.dict(sys.modules, {"resource": SimpleNamespace(RLIMIT_FSIZE=1, getrlimit=lambda _: (32 * 1024**3,) * 2),
                                                     "pwd": SimpleNamespace(getpwuid=lambda _: account)}),
                    patch.object(MODULE, "os", inert_os), patch.object(MODULE.sys, "platform", "darwin"),
                    patch.object(MODULE.platform, "machine", return_value="arm64"),
                    patch.object(MODULE.platform, "mac_ver", return_value=("26.0", (), "arm64")),
                    patch.object(MODULE, "__file__", str(root / "desktop/tools/macos_normal_ui_runner.py")),
                    patch.object(MODULE.Path, "cwd", return_value=root), patch.object(MODULE, "open_directory", return_value=77)):
                stack.enter_context(context)
            request = dict(engineering_requests["build"])
            actual_root, actual_source, clean, limits = MODULE.engineering_context(request)
            self.assertEqual((actual_root, actual_source, limits), (root, source, (32 * 1024**3,) * 2))
            self.assertEqual(request["compiler"], compiler_root)
            self.assertEqual(clean, dict(environment, TMPDIR=engineering_tmp, TEST_RUNNER_MRK_ENGINEERING_UI_WORK=str(engineering_work)))
            self.assertEqual(closed_directories, [77, 77])
            for key in ("GITHUB_SHA", "GITHUB_WORKSPACE", "GITHUB_EVENT_NAME", "GITHUB_REF", "GITHUB_WORKFLOW_SHA", "GITHUB_WORKFLOW_REF",
                        "GITHUB_REPOSITORY", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "MRK_MACOS_WORK", "MRK_DESKTOP_CI_ROOT", "PATH"):
                original_value = engine_environment[key]
                try:
                    engine_environment[key] = "not-admitted"
                    with self.subTest(engineering_context=key), self.assertRaises(MODULE.Refused):
                        MODULE.engineering_context(dict(engineering_requests["build"]))
                finally:
                    engine_environment[key] = original_value
            with patch.object(MODULE.platform, "machine", return_value="x86_64"), self.assertRaises(MODULE.Refused):
                MODULE.engineering_context(dict(engineering_requests["build"]))
            with self.assertRaises(MODULE.Refused):
                MODULE.engineering_context(dict(engineering_requests["build"], target=MODULE.INTEL_TARGET))

        # Main publishes only existing closed exception/command facts, including
        # context refusals after a parsed fixed CLI. Native output stays PRIVATE.
        private = b"PRIVATE-engineering-diagnostic-sentinel"
        for fault in (None, "context", "loader", "exception", "native", "query", "malformed"):
            with self.subTest(engineering_main_failure=fault), ExitStack() as stack:
                published, output, errors = [], io.BytesIO(), io.BytesIO()
                stream = lambda buffer: SimpleNamespace(buffer=buffer, write=lambda value: buffer.write(value.encode()), flush=lambda: None)
                native = subprocess.CompletedProcess(["fixed-original"], 65 if fault in ("native", "query") else 0, private, b"private stderr")
                owner = SimpleNamespace(ProcessError=OSError, ProcessInterrupted=InterruptedError,
                                        run_owned=lambda *_a, **_k: native)
                def execute(phase, _request, _source, _limits):
                    if fault == "exception": raise TypeError(private.decode())
                    original = phase.call("one-admitted-ui-test", ["fixed-original"], 180)
                    if fault == "query": raise MODULE.NativeQueryFailure(original)
                    return original
                arguments = ["helper", "--engineering-main-build", "--work", str(engineering_work)]
                if fault == "malformed": arguments.append("extra")
                for context in (
                    patch.object(MODULE.sys, "argv", arguments),
                    patch.object(MODULE.os, "environ", {"TMPDIR": engineering_tmp}),
                    patch.object(MODULE.time, "monotonic_ns", return_value=0),
                    patch.object(MODULE, "engineering_context", side_effect=ValueError(private.decode()) if fault == "context" else None,
                                 return_value=(Path("/inert"), "a" * 40, {}, (32 * 1024**3,) * 2)),
                    patch.object(MODULE, "load_normal_owner", side_effect=OSError(private.decode()) if fault == "loader" else None, return_value=owner),
                    patch.object(MODULE, "execute_engineering_phase", side_effect=execute),
                    patch.object(MODULE, "publish_engineering_failure", side_effect=lambda request, value: published.append((request, value))),
                    patch.object(MODULE, "execute_normal_phase", side_effect=AssertionError("ordinary route selected")),
                    patch.object(MODULE.sys, "stdout", stream(output)), patch.object(MODULE.sys, "stderr", stream(errors)),
                ): stack.enter_context(context)
                self.assertEqual(MODULE.main(), 0 if fault is None else 65 if fault in ("native", "query") else 1)
                if fault in (None, "malformed"):
                    self.assertEqual(published, [])
                else:
                    self.assertEqual(len(published), 1)
                    request, failure = published[0]
                    self.assertEqual(request["work"], engineering_work)
                    expected_fields = {"schemaVersion", "scope", "productReady", "error", "stage", "exceptionClass",
                                       "sourceFrames", "sourceFramesTruncated", "commands", "ownerFailure", "ownerDiagnostic", "unknownStateRetained"}
                    if fault in ("native", "query"):
                        expected_fields.add("nativeDiagnostics")
                    self.assertEqual(set(failure), expected_fields)
                    self.assertIsNone(failure["ownerDiagnostic"])
                    self.assertIs(type(failure["sourceFramesTruncated"]), bool)
                    self.assertEqual(failure["scope"], "generated-ui-runner-refused")
                    self.assertFalse(failure["productReady"])
                    self.assertTrue(failure["unknownStateRetained"])
                    self.assertNotIn(private, MODULE.encoded(failure))
                    self.assertNotIn(b"private stderr", MODULE.encoded(failure))
                    if fault in ("native", "query"):
                        self.assertEqual(len(failure["commands"]), 1)
                        self.assertEqual(failure["commands"][0]["returncode"], 65)
                        self.assertEqual(failure["commands"][0]["stdoutSha256"], hashlib.sha256(private).hexdigest())
                        native_diagnostic = failure["nativeDiagnostics"]
                        self.assertEqual(native_diagnostic["scope"], "engineering-main-ui-failure-diagnostic-only")
                        self.assertEqual(native_diagnostic["phase"], "query" if fault == "query" else "build")
                        self.assertEqual(native_diagnostic["originalReturncode"], 65)
                        self.assertFalse(native_diagnostic["markers"]["selectedCaseStarted"])
                        self.assertEqual(output.getvalue(), private)
                    else:
                        self.assertEqual(failure["commands"], [])
                        self.assertEqual(failure["stage"], "context" if fault == "context" else "loader" if fault == "loader" else "execute")
        # Fixed unsigned iOS result grammar. These are inert original-return
        # DATA tests, not a native archive, and do not reimplement core inspection.
        ios_source = "a" * 40
        ios_facts = dict(schemaVersion=1, scope="one-ordinary-local-unsigned-ios-archive", sourceCommit=ios_source,
            operationId="b" * 32, ownerGeneration="c" * 32, savedVersion="1.2.3", savedBuild=7,
            originalEntries=3, originalBytes=1024, inputFiles=9, inputBytes=7264, topLevelDirectories=4,
            archiveDescendantsObserved=False, nativeResultDisplayed=True, outputPostMatched=True,
            originalsClosed=True, normalQuitObserved=True, successBeforeCutoff=True, signed=False,
            ipaExported=False, releaseQualified=False, parentReturncodeRequired=0)
        ios_case = b"-[MRKNormalAppUITests.NormalAppUITests testSyntheticProjectUnsignedIOSArchive]"
        def ios_stdout(value):
            return (b"Test Case '" + ios_case + b"' started.\n" + MODULE.ORIGINAL_MARKER.encode() + b"\n"
                    + MODULE.IOS_UNSIGNED_PREFIX + MODULE.encoded(value) + b"\nTest Case '" + ios_case
                    + b"' passed (12.000 seconds).\n")
        ios_output = ios_stdout(ios_facts)
        self.assertIs(MODULE.ios_unsigned_facts(ios_facts, source=ios_source), ios_facts)
        self.assertEqual(MODULE.ios_unsigned_marker(ios_output, source=ios_source), ios_facts)
        for key, value in ios_facts.items():
            bad = dict(ios_facts)
            del bad[key]
            with self.subTest(ios_missing=key), self.assertRaises(MODULE.Refused):
                MODULE.ios_unsigned_facts(bad, source=ios_source)
            bad[key] = not value if type(value) is bool else True if type(value) is int else "wrong"
            with self.subTest(ios_changed=key), self.assertRaises(MODULE.Refused):
                MODULE.ios_unsigned_facts(bad, source=ios_source)
        for changed in (dict(ios_facts, extra=True), dict(ios_facts, originalEntries=0),
                        dict(ios_facts, originalEntries=100001), dict(ios_facts, originalBytes=0),
                        dict(ios_facts, originalBytes=(8 << 30) + 1)):
            with self.assertRaises(MODULE.Refused): MODULE.ios_unsigned_facts(changed, source=ios_source)
        self.assertEqual(MODULE.ios_unsigned_facts(dict(ios_facts, originalEntries=100000, originalBytes=8 << 30),
                                                  source=ios_source)["originalBytes"], 8 << 30)
        for changed in (b"", b"x" * 1048577, ios_output + ios_output,
                ios_output.replace(MODULE.ORIGINAL_MARKER.encode(), b""),
                ios_output.replace(MODULE.IOS_UNSIGNED_PREFIX, b"not-the-marker="),
                ios_output.replace(b" passed ", b" failed "),
                ios_output.replace(ios_case, b"-[MRKNormalAppUITests.NormalAppUITests testLaunchCancelAndQuit]"),
                ios_output.replace(MODULE.encoded(ios_facts), json.dumps(ios_facts).encode()),
                ios_output.replace(b'"schemaVersion":1', b'"schemaVersion":1,"schemaVersion":1'),
                ios_output + b"MRK_MACOS_UI_ORIGINAL=unqualified\n",
                ios_output + b"MRK_MACOS_UI_FAILURE_CLEANUP=attempted\n",
                MODULE.IOS_UNSIGNED_PREFIX + MODULE.encoded(ios_facts) + b"\n" + ios_output.replace(
                    MODULE.IOS_UNSIGNED_PREFIX + MODULE.encoded(ios_facts) + b"\n", b"")):
            with self.assertRaises(MODULE.Refused): MODULE.ios_unsigned_marker(changed, source=ios_source)
        with self.assertRaises(MODULE.Refused): MODULE.ios_unsigned_marker(ios_output, source="d" * 40)
        ios_counts = dict(totalTestCount=1, passedTests=1, failedTests=0, skippedTests=0, expectedFailures=0)
        self.assertEqual(MODULE.ios_unsigned_summary(MODULE.encoded(ios_counts)), ios_counts)
        for key, value in ios_counts.items():
            for wrong in (True, value + 1):
                with self.assertRaises(MODULE.Refused):
                    MODULE.ios_unsigned_summary(MODULE.encoded(dict(ios_counts, **{key: wrong})))
        with self.assertRaises(MODULE.Refused):
            MODULE.ios_unsigned_summary(b'{"totalTestCount":1,"passedTests":1,"passedTests":1}')

        ios_temporary = "/Users/runner/work/_temp/mrk-macos-installed.ABCDef12/normal-ui/tmp/"
        ios_requests = {name: MODULE.normal_request(["--normal-ios-unsigned-archive-" + name], ios_temporary)
                        for name in ("test", "summary")}
        ios_limits = (1024**3,) * 2
        ios_stat = SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=501)
        ios_inert_os = SimpleNamespace(path=SimpleNamespace(lexists=lambda _: False),
                                      stat=lambda *_a, **_k: ios_stat, getuid=lambda: 501)
        # The actual NormalPhase/run_admitted_test/executor run against a finite
        # generated-product adapter and inert original owner. No filesystem or
        # process is used; every adapted product close is still observed.
        for mode, code, fault in (("test", 0, None), ("summary", 0, None), ("test", 65, None),
                ("summary", 75, None), ("test", 0, "marker"), ("summary", 0, "counts"),
                ("test", 0, "post"), ("test", 0, "close"), ("test", 65, "close"),
                ("test", 0, "source"), ("test", 0, "publication")):
            with self.subTest(ios_execute=(mode, code, fault)), ExitStack() as stack:
                events, originals, publications = [], [], []
                request = ios_requests[mode]
                class IOSProducts:
                    def __init__(self, derived):
                        self.products, self.manifest = Path("/inert-products"), "fixed.xctestrun"
                        self.checks = 0
                    def __enter__(self): events.append("entered"); return self
                    def admit(self, _call): events.append("admitted"); return {"generatedRunner": True}
                    def check(self):
                        self.checks += 1; events.append("post")
                        if fault == "post" and self.checks == 2: raise OSError("inert product POST refusal")
                    def __exit__(self, _kind, _error, _tb):
                        events.append("closed")
                        if fault == "close": raise OSError("inert consuming product close refusal")
                        return False
                def ios_owned(arguments, **kwargs):
                    body = ios_output if mode == "test" else MODULE.encoded(ios_counts)
                    if fault in ("marker", "counts"): body = b"{}"
                    value = subprocess.CompletedProcess(list(arguments), code, body, b"")
                    originals.append((value, kwargs)); return value
                def ios_source_state(_phase, _source):
                    events.append("source")
                    return {"source": "changed" if fault == "source" and events.count("source") == 2 else ios_source}
                def ios_publish(path, body, limit):
                    if fault == "publication": raise OSError("inert receipt consuming close refusal")
                    publications.append((path, MODULE.document(body), limit))
                for context in (patch.object(MODULE, "os", ios_inert_os), patch.object(MODULE, "RunnerProducts", IOSProducts),
                        patch.object(MODULE, "normal_source_state", side_effect=ios_source_state),
                        patch.object(MODULE, "exclusive_output", side_effect=ios_publish)):
                    stack.enter_context(context)
                phase = MODULE.NormalPhase(SimpleNamespace(run_owned=ios_owned), {}, Path("/inert-source"),
                    MODULE.PhaseClock(request["phaseSeconds"], now=lambda: 0), retain_nonzero=True)
                if fault is not None:
                    with self.assertRaises((MODULE.Refused, OSError)):
                        MODULE.execute_normal_phase(phase, request, ios_source, ios_limits)
                    self.assertEqual(publications, [])
                else:
                    original = MODULE.execute_normal_phase(phase, request, ios_source, ios_limits)
                    self.assertIs(original, originals[0][0])
                    self.assertEqual(len(publications), 2 if mode == "test" and code == 0 else 1)
                    receipt = publications[0][1]
                    self.assertTrue(receipt["sourcePrePostMatched"])
                    self.assertEqual(receipt["commands"][0]["returncode"], code)
                    self.assertEqual(receipt["fileLimitBytes"], list(ios_limits))
                    if mode == "test" and code == 0:
                        self.assertEqual(receipt["iosUnsignedObservation"], ios_facts)
                        self.assertTrue(receipt["originalProductsPrePostMatched"])
                        self.assertTrue(receipt["originalClosesCompleted"])
                        self.assertEqual(publications[1], (request["derived"].parent / "ios-unsigned-archive.facts.json", ios_facts, 16384))
                    elif mode == "summary" and code == 0:
                        self.assertEqual(receipt["iosUnsignedTestCounts"], ios_counts)
                    else:
                        self.assertNotIn("iosUnsignedObservation", receipt)
                        self.assertNotIn("iosUnsignedTestCounts", receipt)
                self.assertEqual(len(originals), 1)
                self.assertEqual((originals[0][1]["timeout"], originals[0][1]["output_limit"]),
                                 (1020, 1048576) if mode == "test" else (30, 262144))
                self.assertEqual(events.count("closed"), 1 if mode == "test" else 0)
                self.assertIs(phase.first_nonzero, originals[0][0] if code else None)

        # Real main + real executor + real NormalPhase retain the FIRST admitted
        # return before a late clock, receipt-close, or interrupted diagnostic.
        # Both standard streams are scoped and restored; no private text escapes.
        actual_execute = MODULE.execute_normal_phase
        for mode, code, fault in (("test", 0, None), ("summary", 0, None), ("test", 65, None),
                ("test", 0, "late"), ("test", 65, "late"), ("test", 0, "close"), ("test", 65, "close"),
                ("test", 65, "diagnostic-interrupt"), ("test", 65, "diagnostic-exit"),
                ("summary", 75, "diagnostic-interrupt"), ("test", 0, "context")):
            with self.subTest(ios_main=(mode, code, fault)), ExitStack() as stack:
                tick, phases, originals, published, events = [0], [], [], [], []
                output, errors = io.BytesIO(), io.BytesIO()
                request = ios_requests[mode]
                class IOSMainProducts:
                    def __init__(self, _derived): self.products, self.manifest = Path("/inert-products"), "fixed.xctestrun"
                    def __enter__(self): return self
                    def admit(self, _call): return {"generatedRunner": True}
                    def check(self): pass
                    def __exit__(self, _kind, _error, _tb): events.append("closed"); return False
                def ios_main_owned(arguments, **kwargs):
                    body = ios_output if mode == "test" else MODULE.encoded(ios_counts)
                    value = subprocess.CompletedProcess(list(arguments), code, body, b"private inert diagnostic")
                    originals.append(value)
                    if fault == "late": tick[0] = request["phaseSeconds"] * 10**9
                    return value
                def ios_main_execute(phase, *args): phases.append(phase); return actual_execute(phase, *args)
                def ios_main_publish(path, body, limit):
                    if fault == "close" and path.name.endswith("admission.json"):
                        raise OSError("inert consuming publication close refusal")
                    published.append((path, MODULE.document(body), limit))
                def ios_main_diagnostic(*_a, **_k):
                    if fault == "diagnostic-interrupt": raise KeyboardInterrupt()
                    if fault == "diagnostic-exit": raise SystemExit(99)
                stream = lambda buffer: SimpleNamespace(buffer=buffer, write=lambda value: buffer.write(value.encode()), flush=lambda: None)
                owner = SimpleNamespace(run_owned=ios_main_owned, ProcessError=OSError, ProcessInterrupted=InterruptedError)
                main_os = SimpleNamespace(environ={"TMPDIR": ios_temporary}, path=ios_inert_os.path,
                                          stat=ios_inert_os.stat, getuid=ios_inert_os.getuid)
                for context in (patch.object(MODULE.sys, "argv", ["helper", "--normal-ios-unsigned-archive-" + mode]),
                        patch.object(MODULE, "os", main_os), patch.object(MODULE.time, "monotonic_ns", side_effect=lambda: tick[0]),
                        patch.object(MODULE, "normal_context", side_effect=MODULE.Refused("inert context refusal") if fault == "context" else None,
                                     return_value=(Path("/inert-source"), ios_source, {}, ios_limits)),
                        patch.object(MODULE, "load_normal_owner", return_value=owner),
                        patch.object(MODULE, "RunnerProducts", IOSMainProducts),
                        patch.object(MODULE, "normal_source_state", return_value={"source": ios_source}),
                        patch.object(MODULE, "execute_normal_phase", side_effect=ios_main_execute),
                        patch.object(MODULE, "exclusive_output", side_effect=ios_main_publish),
                        patch.object(MODULE, "publish_failure_diagnostics", side_effect=ios_main_diagnostic),
                        patch.object(MODULE.sys, "stdout", stream(output)), patch.object(MODULE.sys, "stderr", stream(errors))):
                    stack.enter_context(context)
                self.assertEqual(MODULE.main(), code if code else 0 if fault is None else 1)
                if fault == "context":
                    self.assertEqual((originals, phases, published, events), ([], [], [], []))
                    continue
                self.assertEqual(len(originals), 1)
                self.assertIs(phases[0].first_nonzero, originals[0] if code else None)
                self.assertEqual(events.count("closed"), 1 if mode == "test" else 0)
                if fault is not None:
                    self.assertTrue(phases[0].clock.failed)
                    self.assertFalse(any(path.name == "ios-unsigned-archive.facts.json" for path, _, _ in published))
                    self.assertTrue(all(b"private inert diagnostic" not in MODULE.encoded(value) for _, value, _ in published))

    def test_removal_ui_clock_observation_and_finality(self):
        tick = [0]
        clock = MODULE.RemovalPhaseClock(500 * 10**9, now=lambda: tick[0])
        self.assertEqual(clock.deadline, 500 * 10**9)
        self.assertEqual(MODULE.RemovalPhaseClock(900 * 10**9, now=lambda: 0).deadline, 585 * 10**9)
        tick[0] = 499 * 10**9
        with self.assertRaises(MODULE.Refused): clock.allowance(420)
        tick[0] = 0
        with self.assertRaises(MODULE.Refused): clock.check()
        for endpoint in (True, 0, -1, 1.5):
            with self.assertRaises(MODULE.Refused): MODULE.RemovalPhaseClock(endpoint, now=lambda: 0)

        def output(case):
            method = MODULE.REMOVAL_METHODS[case]
            selected = "-[MRKNormalAppUITests.NormalAppUITests " + method + "]"
            marker = ("MRK_MACOS_REMOVAL_UI=v1;case=" + case + ";cancelObserved="
                      + ("1" if case == "ordinary" else "0")
                      + ";continueObserved=1;originalTerminated=1;gateClosed=1;gateFree=unqualified;normalQuit=0;channelClosed=1")
            stdout = ("Test Case '" + selected + "' started.\n" + marker
                      + "\nTest Case '" + selected + "' passed (1.0 seconds).\n").encode()
            summary = MODULE.encoded(dict(totalTestCount=1, passedTests=1, failedTests=0, skippedTests=0, expectedFailures=0))
            tests = MODULE.encoded(dict(testNodes=[dict(name=MODULE.TARGET, nodeType="Test Suite", children=[
                dict(name=method + "()", nodeType="Test Case", nodeIdentifier="NormalAppUITests/" + method + "()", result="Passed")])]))
            return stdout, summary, tests

        for case in ("ordinary", "abrupt"):
            stdout, summary, tests = output(case)
            facts = MODULE.removal_ui_result(stdout, summary, tests, case)
            self.assertIs(facts["normalQuit"], False)
            self.assertEqual(facts["gateFree"], "unqualified")
            self.assertIs(facts["productReady"], False)
            for body in (stdout + stdout, stdout.replace(b"originalTerminated=1", b"originalTerminated=0"),
                         stdout.replace(b"gateFree=unqualified", b"gateFree=1"),
                         stdout.replace(b"normalQuit=0", b"normalQuit=1"),
                         stdout.replace(b"channelClosed=1", b"channelClosed=0"),
                         stdout + MODULE.ORIGINAL_MARKER.encode(), stdout.replace(b" passed ", b" skipped ")):
                with self.assertRaises(MODULE.Refused): MODULE.removal_ui_result(body, summary, tests, case)
            for key in ("totalTestCount", "passedTests", "skippedTests"):
                bad = json.loads(summary); bad[key] += 1
                with self.assertRaises(MODULE.Refused):
                    MODULE.removal_ui_result(stdout, MODULE.encoded(bad), tests, case)
            with self.assertRaises(MODULE.Refused):
                MODULE.removal_ui_result(stdout, summary, tests, "abrupt" if case == "ordinary" else "ordinary")

        # Explicit context admission reads only supplied environment and actual (mocked) native facts.
        derived = Path("/Users/runner/work/_temp/mrk-macos-installed.ABCDef12/normal-ui/DerivedData")
        channel = derived.parent.parent / ("removal-ui-v1/r-" + "a" * 32)
        source, limit = "a" * 40, (1024**3,) * 2
        environment = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": "/Users/runner", "USER": "runner",
            "LOGNAME": "runner", "TMPDIR": str(derived.parent / "tmp") + "/", "LANG": "en_US.UTF-8",
            "LC_ALL": "en_US.UTF-8", "TZ": "UTC", "DEVELOPER_DIR": MODULE.DEVELOPER,
            "TEST_RUNNER_MRK_NORMAL_UI_HOSTED_JOB": "github-hosted-macos26-arm64",
            "TEST_RUNNER_MRK_NORMAL_UI_APPLICATION_SOURCE": source,
            "TEST_RUNNER_MRK_NORMAL_UI_HARNESS_SOURCE": source, MODULE.REMOVAL_CHANNEL_ENV: str(channel)}
        def make_phase(root, env=None, now=lambda: 0):
            return MODULE.NormalPhase(SimpleNamespace(), dict(environment if env is None else env), root,
                MODULE.RemovalPhaseClock(600 * 10**9, now=now), retain_nonzero=True)
        root = Path("/Users/runner/work/mobile-release-kit/mobile-release-kit")
        resource = SimpleNamespace(RLIMIT_FSIZE=1, getrlimit=lambda _: limit)
        for selected_target, machine, hosted in ((MODULE.ARM_TARGET, "arm64", "github-hosted-macos26-arm64"),
                                                  (MODULE.INTEL_TARGET, "x86_64", "github-hosted-macos26-x86_64")):
            selected_environment = dict(environment, TEST_RUNNER_MRK_NORMAL_UI_HOSTED_JOB=hosted)
            with patch.object(MODULE.sys, "platform", "darwin"), patch.object(MODULE.platform, "machine", return_value=machine), \
                 patch.object(MODULE.platform, "mac_ver", return_value=("26.6", (), "")), patch.object(MODULE, "_removal_resource", resource):
                for case in ("ordinary", "abrupt"):
                    phase = make_phase(root, selected_environment)
                    kwargs = dict(case=case, derived=derived, channel=channel, source=source, file_limit=limit, target=selected_target)
                    self.assertEqual(MODULE.removal_phase_context(phase, **kwargs)[1].name, "removal-" + case + "-test.xcresult")
                    other = MODULE.INTEL_TARGET if selected_target == MODULE.ARM_TARGET else MODULE.ARM_TARGET
                    for mutation in (dict(channel=channel.parent / ("r-" + "0" * 32)), dict(channel=Path("/foreign/r-" + "a" * 32)),
                                     dict(source="b" * 40), dict(target=other), dict(target="other"), dict(file_limit=(-1, -1))):
                        with self.assertRaises(MODULE.Refused): MODULE.removal_phase_context(phase, **dict(kwargs, **mutation))
                    for mutation in (dict(PATH="/foreign"), dict(UNEXPECTED="value"), {MODULE.REMOVAL_CHANNEL_ENV: str(channel) + "/other"},
                                     dict(TEST_RUNNER_MRK_NORMAL_UI_HOSTED_JOB="github-hosted-macos26-arm64" if machine == "x86_64" else "github-hosted-macos26-x86_64")):
                        with self.assertRaises(MODULE.Refused):
                            MODULE.removal_phase_context(make_phase(root, dict(selected_environment, **mutation)), **kwargs)
        kwargs = dict(case="ordinary", derived=derived, channel=channel, source=source, file_limit=limit, target=MODULE.ARM_TARGET)

        # Actual result/receipt descriptors in disposable files; all native calls remain inert.
        for fault in (None, "native-nonzero", "query-nonzero", "result-replaced", "source-changed",
                      "bad-marker", "result-close", "receipt-close", "late-receipt"):
            with self.subTest(removal_finality=fault), tempfile.TemporaryDirectory(prefix="mrk-removal-ui-data-") as temporary:
                normal = Path(temporary); derived = normal / "DerivedData"
                result = normal / "removal-ordinary-test.xcresult"; result.mkdir(mode=0o700)
                stdout, summary, tests = output("ordinary")
                if fault == "bad-marker": stdout = stdout.replace(b"gateClosed=1", b"gateClosed=0")
                original = subprocess.CompletedProcess(["inert-test"], 65 if fault == "native-nonzero" else 0, stdout, b"")
                tick, result_fd, receipt_fd, closed = [0], [None], [None], []
                phase = make_phase(normal, now=lambda: tick[0])
                def query(role, argv, seconds, cap):
                    if fault == "result-replaced" and role == "normal-ui-summary":
                        result.rename(normal / "old-result"); result.mkdir(mode=0o700)
                    return subprocess.CompletedProcess(argv, 66 if fault == "query-nonzero" else 0,
                        summary if role == "normal-ui-summary" else tests, b"")
                phase.call = query
                original_open, original_close = MODULE.os.open, MODULE.os.close
                def opened(path, flags, *args, **kwargs):
                    fd = original_open(path, flags, *args, **kwargs)
                    if str(path).endswith(".runner-admission.json"): receipt_fd[0] = fd
                    return fd
                def directory(path):
                    fd = original_open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
                    result_fd[0] = fd; return fd
                def close(fd):
                    original_close(fd); closed.append(fd)
                    if fault == "result-close" and receipt_fd[0] is None and fd == result_fd[0]: raise OSError("synthetic consumed result close")
                    if receipt_fd[0] is not None and fd == receipt_fd[0]:
                        if fault == "receipt-close": raise OSError("synthetic consumed receipt close")
                        if fault == "late-receipt": tick[0] = 585 * 10**9
                before = {"inert-source": ["fixed"]}
                post = {} if fault == "source-changed" else before
                with patch.object(MODULE, "removal_phase_context", return_value=(MODULE.CLASS + MODULE.REMOVAL_METHODS["ordinary"], result)), \
                     patch.object(MODULE, "normal_source_state", side_effect=[before, post]), \
                     patch.object(MODULE, "output_data_read_build", return_value="b" * 64), \
                     patch.object(MODULE, "run_admitted_test", return_value=(original, {"originalClosesCompleted": True})), \
                     patch.object(MODULE, "open_directory", side_effect=directory), \
                     patch.object(MODULE, "_removal_resource", resource), \
                     patch.object(MODULE.os, "open", side_effect=opened), patch.object(MODULE.os, "close", side_effect=close):
                    kwargs = dict(case="ordinary", derived=derived, channel=channel, source=source, file_limit=limit)
                    if fault is None:
                        returned, facts = MODULE.execute_removal_ui_phase(phase, **kwargs)
                        self.assertIs(returned, original)
                        self.assertEqual(facts["workerJoin"], "pending-caller-original-join")
                        self.assertTrue(phase.clock.finalized)
                    else:
                        with self.assertRaises((MODULE.Refused, MODULE.NativeQueryFailure, OSError)):
                            MODULE.execute_removal_ui_phase(phase, **kwargs)
                        self.assertTrue(phase.clock.failed)
                    with self.assertRaises(MODULE.Refused): MODULE.execute_removal_ui_phase(phase, **kwargs)
                if result_fd[0] is not None:
                    with self.assertRaises(OSError): os.fstat(result_fd[0])
                receipt = result.with_suffix(".runner-admission.json")
                if fault not in (None, "receipt-close", "late-receipt"): self.assertFalse(receipt.exists())
                if fault is None:
                    self.assertEqual(stat.S_IMODE(receipt.stat().st_mode), 0o600)
                    self.assertEqual(json.loads(receipt.read_bytes())["observation"]["gateFree"], "unqualified")



    def test_android_consumer_context_keeps_current_fixture_and_application_sources_distinct(self):
        import resource, pwd
        helper = MODULE.SAVED_VERSION_CANDIDATE_ROOT / '.candidate-consumer-helper'
        normal = Path('/Users/runner/work/_temp/mrk-macos-installed.abcdefgh/normal-ui')
        env = dict(PATH='/usr/bin:/bin:/usr/sbin:/sbin', HOME='/Users/runner', USER='runner', LOGNAME='runner',
            TMPDIR=str(normal/'tmp')+'/', LANG='en_US.UTF-8', LC_ALL='en_US.UTF-8', TZ='UTC', DEVELOPER_DIR=MODULE.DEVELOPER,
            TEST_RUNNER_MRK_NORMAL_UI_APPLICATION_SOURCE='a'*40, TEST_RUNNER_MRK_NORMAL_UI_HARNESS_SOURCE='b'*40,
            TEST_RUNNER_MRK_NORMAL_UI_HOSTED_JOB='github-hosted-macos26-arm64',
            GITHUB_REPOSITORY='Apdelrahman1911/mobile-release-kit', GITHUB_EVENT_NAME='push',
            GITHUB_REF=MODULE.ANDROID_CONSUMER_REF, GITHUB_SHA='b'*40, GITHUB_WORKFLOW_SHA='b'*40,
            GITHUB_WORKFLOW_REF='Apdelrahman1911/mobile-release-kit/'+MODULE.ANDROID_CONSUMER_WORKFLOW+'@'+MODULE.ANDROID_CONSUMER_REF,
            GITHUB_WORKSPACE=str(MODULE.SAVED_VERSION_CANDIDATE_ROOT), GITHUB_RUN_ID='42', GITHUB_RUN_ATTEMPT='1',
            RUNNER_ENVIRONMENT='github-hosted', RUNNER_OS='macOS', RUNNER_ARCH='ARM64')
        env[MODULE.ANDROID_CURRENT_ENV] = MODULE.ANDROID_CURRENT_SCOPE
        with ExitStack() as stack:
            stack.enter_context(patch.object(MODULE,'__file__',str(helper/'desktop/tools/macos_normal_ui_runner.py')))
            stack.enter_context(patch.object(MODULE.sys,'platform','darwin'))
            stack.enter_context(patch.object(MODULE.sys,'version_info',(3,14,7)))
            stack.enter_context(patch.object(MODULE.sys,'flags',SimpleNamespace(isolated=1,no_site=1)))
            stack.enter_context(patch.object(MODULE.sys,'dont_write_bytecode',True))
            stack.enter_context(patch.object(MODULE.platform,'mac_ver',return_value=('26.6.2',(),'')))
            stack.enter_context(patch.object(pwd,'getpwuid',return_value=SimpleNamespace(pw_uid=1000,pw_gid=1000,pw_name='runner',pw_dir='/Users/runner')))
            for function in ('getuid','geteuid','getgid','getegid'):
                stack.enter_context(patch.object(MODULE.os,function,return_value=1000))
            stack.enter_context(patch.object(MODULE.os,'stat',return_value=SimpleNamespace(st_uid=1000)))
            stack.enter_context(patch.object(MODULE.Path,'cwd',return_value=helper))
            for target, machine, arch, hosted in ((MODULE.ARM_TARGET,'arm64','ARM64','github-hosted-macos26-arm64'),
                                                (MODULE.INTEL_TARGET,'x86_64','X64','github-hosted-macos26-x86_64')):
                for application in ('a'*40,'b'*40):
                    for flag in ('--normal-build','--normal-android-candidate-inputs-test','--normal-android-candidate-inputs-summary'):
                        request=MODULE.normal_request(['--target',target,flag],str(normal/'tmp')+'/')
                        actual=dict(env,RUNNER_ARCH=arch,TEST_RUNNER_MRK_NORMAL_UI_HOSTED_JOB=hosted,
                                    TEST_RUNNER_MRK_NORMAL_UI_APPLICATION_SOURCE=application)
                        cap=32*1024**3 if request['phase']=='build' else 1024**3
                        with patch.object(MODULE.platform,'machine',return_value=machine),patch.dict(MODULE.os.environ,actual,clear=True),patch.object(resource,'getrlimit',return_value=(cap,cap)):
                            root,source,forwarded,_=MODULE.normal_context(request)
                        self.assertEqual((root,source),(helper,'b'*40))
                        self.assertEqual(forwarded[MODULE.ANDROID_CURRENT_ENV],MODULE.ANDROID_CURRENT_SCOPE)
                        self.assertEqual(forwarded['TEST_RUNNER_MRK_NORMAL_UI_APPLICATION_SOURCE'],application)
                        if request['phase']!='build':
                            self.assertEqual(forwarded[MODULE.ANDROID_INPUT_ENV],str(normal/'android-input-fixture.json'))
                            self.assertEqual(forwarded[MODULE.ANDROID_CANDIDATE_ENV],str(normal/'android-candidate-fixture.json'))
                        self.assertNotIn('GITHUB_SHA',forwarded)
            request=MODULE.normal_request(['--normal-android-candidate-inputs-test'],str(normal/'tmp')+'/')
            for key,bad in [('GITHUB_REF',MODULE.ANDROID_CANDIDATE_REF),('GITHUB_WORKFLOW_REF','other'),
                ('GITHUB_WORKSPACE',str(helper)),('GITHUB_EVENT_NAME','workflow_dispatch'),('GITHUB_SHA','a'*40),
                (MODULE.ANDROID_CURRENT_ENV,'other'),(MODULE.IOS_TOOLS_CURRENT_ENV,MODULE.IOS_TOOLS_CURRENT_SCOPE),
                ('TEST_RUNNER_MRK_NORMAL_UI_APPLICATION_SOURCE','0'*40)]:
                with self.subTest(field=key),patch.object(MODULE.platform,'machine',return_value='arm64'),patch.dict(MODULE.os.environ,dict(env,**{key:bad}),clear=True),patch.object(resource,'getrlimit',return_value=(1024**3,1024**3)),self.assertRaises(MODULE.Refused):
                    MODULE.normal_context(request)
            for flag in ('--normal-android-signed-build-test','--normal-ios-unsigned-archive-test'):
                request=MODULE.normal_request([flag],str(normal/'tmp')+'/')
                with self.assertRaises(MODULE.Refused): MODULE.android_candidate_consumer_context(request,env,helper)
        # The actual existing summary path publishes helper SOURCE and a separate
        # app label, while retaining original native0/source POST and strict counts.
        for failure in (None,'native','post'):
            with tempfile.TemporaryDirectory() as temporary:
                normal=Path(temporary)/'normal-ui';normal.mkdir();result=normal/MODULE.ANDROID_CANDIDATE_RESULT;result.mkdir()
                request=MODULE.normal_request(['--normal-android-candidate-inputs-summary'],str(normal/'tmp')+'/')
                counts=MODULE.encoded(dict(totalTestCount=1,passedTests=1,failedTests=0,skippedTests=0,expectedFailures=0))
                original=subprocess.CompletedProcess([],65 if failure=='native' else 0,counts,b'')
                phase=MODULE.NormalPhase(SimpleNamespace(run_owned=lambda argv,**kw:subprocess.CompletedProcess(argv,original.returncode,original.stdout,original.stderr)),
                    dict(env,**{MODULE.ANDROID_RUN_ENV:'42',MODULE.ANDROID_ATTEMPT_ENV:'1'}),helper,MODULE.PhaseClock(90))
                with patch.object(MODULE,'normal_source_state',side_effect=[{'same':True},{} if failure=='post' else {'same':True}]):
                    if failure=='post':
                        with self.assertRaisesRegex(MODULE.Refused,'candidate-ui-source-pre-post'):
                            MODULE.execute_normal_phase(phase,request,'b'*40,(1024**3,1024**3))
                        self.assertFalse((normal/'android-candidate-inputs-summary.runner-admission.json').exists())
                    else:
                        returned=MODULE.execute_normal_phase(phase,request,'b'*40,(1024**3,1024**3))
                        self.assertEqual(returned.returncode,original.returncode)
                        row=json.loads((normal/'android-candidate-inputs-summary.runner-admission.json').read_bytes())
                        self.assertEqual((row['sourceCommit'],row['applicationSourceCommit']),('b'*40,'a'*40))
                        self.assertEqual(row['currentCandidateScope'],MODULE.ANDROID_CURRENT_SCOPE)
                        self.assertEqual(row['originalReturncode'],original.returncode)
                        self.assertEqual(row['testCounts'] is None,failure=='native')

    def test_current_ordinary_context_receipt_and_fixed_identity_diagnostic(self):
        # Project selection's heading is not a completed async snapshot. Keep
        # the native work/cleanup window inside the existing case, not a new
        # global timeout, and preserve exact identity+terminal failure checks.
        swift=SWIFT.read_text()
        helper=swift.split('@MainActor private func waitForSnapshotIdentity(',1)[1].split('@MainActor private func waitGone(',1)[0]
        self.assertIn('try waitElement(query, in: renderer, timeout: 15, failures: [',helper)
        self.assertIn('], snapshotObservation: true, line: line)',helper)
        for title in ('Static observation unavailable','Only a partial static observation is available'):
            self.assertIn('"'+title+'"',helper)
        # Disabled iOS legitimately renders textValue's default 'Not configured'
        # alongside a valid Android identity; global status text is NOT failure.
        import base64
        fixture=json.loads((SWIFT.parent/'Fixtures/normal-project-v1.json').read_bytes())
        config=json.loads(base64.b64decode(fixture['files']['project/release/mobile-release.json'],validate=True))
        self.assertFalse(config['ios']['enabled']);self.assertNotIn('bundleId',config['ios'])
        self.assertEqual(config['android']['applicationId'],'org.fixture.app')
        # Typed content readers keep the original subtree/count/order/grammar.
        # This is SOURCE/bound coverage; actual AX runs in the existing journey.
        displayed=swift.split('private func displayed(',1)[1].split('private func inventory(',1)[0]
        self.assertIn('item.staticTexts.count == 1',displayed)
        self.assertIn('try staticTextContent(item.staticTexts.element(boundBy: 0))',displayed)
        self.assertIn('value == normalized',displayed)
        for name,end in (('savedOperationComplete','savedOfflineCounts'),('savedOfflineCounts','testSyntheticProjectSavedOfflineChecks')):
            reader=swift.split('func '+name+'(',1)[1].split('func '+end+'(',1)[0]
            self.assertIn('try staticTextContent($0)',reader);self.assertNotIn('$0.label',reader)
        refusal=swift.split('func testSyntheticProjectManagedWorkflowRefusal()',1)[1].split('func savedOperationComplete(',1)[0]
        self.assertIn('texts.count <= 128',refusal);self.assertIn('factTexts.count == 8',refusal)
        self.assertIn('try staticTextContent($0, limit: 64)',refusal);self.assertNotIn('$0.label',refusal)
        # Typed waits preserve immediate >=1/singleton cases and the original
        # absolute endpoint; no Foundation comparison is applied to Any AXValue.
        typed=swift.split('@MainActor private func waitStaticTexts(',1)[1].split('@MainActor private func waitStaticText(',1)[0]
        self.assertEqual(typed.count('clock.end(within: timeout)'),1)
        self.assertLess(typed.index('clock.end(within: timeout)'),typed.index('while true'))
        self.assertIn('clock.remaining(1, before: end)',typed)
        self.assertIn('clock.progress(until: end)',typed)
        self.assertIn('readyExists.allSatisfy',typed);self.assertIn('query.element(boundBy: 0).exists',typed)
        self.assertIn('matches.allSatisfy { $0.count <= 1 }',typed)
        self.assertNotIn('catch',typed);self.assertNotIn('NSPredicate',typed)
        self.assertLess(typed.index('try check()\n                return selected'),typed.index('clock.progress(until: end)'))
        path=swift.split('func testSyntheticProjectPathFields()',1)[1].split('func testSyntheticProjectLocalEditsAndImages()',1)[0]
        self.assertLess(path.index('exerciseStaticTextContentData()'),path.index('let fixture = LocalFixture()'))
        self.assertIn('matching: .equalOrContains(name,',path)
        self.assertIn('matching: .contains(phase), timeout: 48, failures: failures',path)
        self.assertIn('matching: .contains(reason), timeout: 48, failures: failures',path)
        version=swift.split('let panel = try waitElement(named(editor, "Saved-version recovery inspection")',1)[1].split('func testSyntheticProjectSavedReleaseEvidence()',1)[0]
        self.assertIn('try require(facts.count >= 1, "recovery byte/mode facts unavailable")',version)
        self.assertIn('waitStaticText(panel, matching: .contains("Native: settled; reason: discarded."), timeout: 48)',version)
        offline=swift.split('func testSyntheticProjectSavedOfflineChecks()',1)[1].split('func testSyntheticProjectBuildToolDiagnostics()',1)[0]
        self.assertIn('staticTextMatching(consent, .contains(comparison))',offline)
        self.assertIn('comparisonFields.count == 1',offline);self.assertIn('scopeFields.count == 1',offline)
        self.assertIn('staticTextFailureCount(panel, failures)',offline)
        self.assertIn('staticTextFailureCount(review, refusalFailures)',refusal)
        self.assertNotIn('staticTexts.matching(NSPredicate(format: "label IN %@"',offline)
        self.assertNotIn('staticTexts.matching(NSPredicate(format: "label IN %@"',refusal)
        for name,end in (('testSyntheticProjectBuildToolDiagnostics','iosCurrentArchiveIdentity'),('observeIOSToolDiagnostics','testSyntheticProjectUnsignedIOSArchive')):
            body=swift.split('func '+name+'(',1)[1].split('func '+end+'(',1)[0]
            self.assertIn('matching: [contextMatch, provenanceMatch]',body)
            self.assertIn('ready: [fresh, phase, outcome, finality], timeout: 15, failures: failures',body)
            self.assertIn('staticTextContent(currentText[0][0]) == originalContext',body)
            self.assertNotIn('label BEGINSWITH',body);self.assertNotIn('.label',body)
        report=swift.split('func diagnosticsCoreReport(',1)[1].split('func testSyntheticProjectBuildToolDiagnostics()',1)[0]
        self.assertIn('try staticTextContent($0, limit: 64)',report)
        self.assertIn('start + 22 <= texts.count',report)
        self.assertNotIn('.label',report)
        # Remaining non-diagnostic callers reuse the SAME typed reader/wait;
        # no new helper/profile or native action, old immediate counts preserved.
        evidence=swift.split('func testSyntheticProjectSavedReleaseEvidence()',1)[1].split('func testSyntheticProjectManagedWorkflowRefusal()',1)[0]
        self.assertIn('guidanceFields.count == 1',evidence)
        self.assertIn('separationFields.count == 1',evidence)
        current=evidence.split('func currentDocuments()',1)[1].split('func staleDocuments()',1)[0]
        self.assertEqual(current.count('try staticTextMatching('),2)
        self.assertNotIn('waitStaticText(',current)
        self.assertIn('waitStaticText(renderer, matching: .contains(guidance))',evidence)
        self.assertNotIn('staticTexts.matching(NSPredicate(format: "label CONTAINS',evidence)
        history=swift.split('func candidateHistoryAction(',1)[1].split('func syntheticAndroidBuild(',1)[0]
        self.assertIn('waitStaticText(history,matching:.prefix("Checkpoint \\(checkpoint)."),timeout:48)',history)
        android=swift.split('func syntheticAndroidBuild(',1)[1]
        self.assertEqual(android.count('waitStaticText(service, matching: .prefix("Service action completed."), timeout: 48, failures: failures)'),2)
        self.assertEqual(android.count('waitStaticText(catalog, matching: .contains("Tool catalog: ready."), timeout: 48)'),2)
        self.assertIn('waitStaticText(group, matching: .equalOrContains(leaf,',android)
        self.assertNotIn('staticTexts.matching(NSPredicate(format: "label ',android)
        # Interactive consent retains its original named role and checkbox state.
        self.assertIn('review.checkBoxes.matching(NSPredicate(format: "label BEGINSWITH %@"',android)
        # Complete fixed previews and added diffs fit the existing4096 reader;
        # do not increase the generic fixture32KiB or content limits.
        for path,encoded in fixture['stages']['workflows'].items():
            text=base64.b64decode(encoded,validate=True).decode('utf8');lines=text.removesuffix('\n').split('\n')
            shown=path.removeprefix('project/')
            diff=f'--- /dev/null\n+++ {shown}\n@@ -0,0 +1,{len(lines)} @@\n'+''.join('+'+line+'\n' for line in lines)
            self.assertLessEqual(len(text.encode('utf8')),4096);self.assertLessEqual(len(diff.encode('utf8')),4096)
        self.assertNotIn('"Not configured"',helper);self.assertNotIn('"Needs attention"',helper)
        wait=swift.split('@MainActor private func waitElement(',1)[1].split('@MainActor private func waitForSnapshotIdentity(',1)[0]
        self.assertIn('timeout: TimeInterval = 5',wait)
        self.assertIn('timeout: try remaining(timeout)',wait)
        self.assertIn('matchCount != 1',wait)
        observer=helper.split('@MainActor private func observeSnapshotState(',1)[1]
        self.assertIn('clock.observationAllowed(now, before: end)',observer)
        self.assertIn('clock.observationAllowed(finish, before: end)',observer)
        self.assertNotIn('remaining(',observer);self.assertNotIn('clock.fail(',observer)
        self.assertEqual(observer.count('try root.snapshot()'),1)
        self.assertIn('catch { return }',observer)
        self.assertIn('children.count <= 1024 - visited - pending.count',observer)
        self.assertIn('children.isEmpty || depth < 32',observer)
        self.assertIn('guard observed.count < 256',observer)
        self.assertIn('knownReasons.first',observer)
        self.assertNotIn('.matching(',observer)
        self.assertNotIn('dictionaryRepresentation',observer)
        self.assertNotIn('value(forKey:',observer)

        # Ten existing post-selection identity assertions now share the narrow
        # wait; the later explicit-refresh assertion retains its old contract.
        self.assertEqual(swift.count('waitForSnapshotIdentity('),11)
        self.assertIn('try waitGone(earlier)\n            _ = try waitElement(renderer.staticTexts.matching(identifier: "org.fixture.app"), in: renderer)',swift)
        for label in ('org.example.saved','org.example.mrk.observed'):
            self.assertIn('waitForSnapshotIdentity(renderer.staticTexts.matching(identifier: "'+label+'"), in: renderer)',swift)
        self.assertEqual(MODULE.ORDINARY_CURRENT_RESULTS, ("applications-test.xcresult", "project-test.xcresult",
            "persistence-test.xcresult", "saved-checks-test.xcresult", "release-evidence-test.xcresult", "workflow-refusal-test.xcresult"))
        root=MODULE.SAVED_VERSION_CANDIDATE_ROOT/".candidate-consumer-helper"
        env={MODULE.ORDINARY_CURRENT_ENV:MODULE.ORDINARY_CURRENT_SCOPE,
             "TEST_RUNNER_MRK_NORMAL_UI_APPLICATION_SOURCE":"a"*40,
             "TEST_RUNNER_MRK_NORMAL_UI_HARNESS_SOURCE":"b"*40}
        temporary="/Users/runner/work/_temp/mrk-macos-installed.ABCDef12/normal-ui/tmp/"
        for target in (MODULE.ARM_TARGET,MODULE.INTEL_TARGET):
            for result in (None,*MODULE.ORDINARY_CURRENT_RESULTS):
                request=MODULE.normal_request(["--target",target,*( ["--normal-build"] if result is None else ["--normal-summary",result])],temporary)
                self.assertEqual(MODULE.ordinary_candidate_context(request,env,root),{MODULE.ORDINARY_CURRENT_ENV:MODULE.ORDINARY_CURRENT_SCOPE})
            for name in MODULE.ORDINARY_CURRENT_RESULTS:
                args=normal_arguments(name); args[8]="platform=macOS,arch="+MODULE.normal_target_data(target)[0]
                request=MODULE.normal_request(["--target",target,*args],temporary)
                self.assertEqual(MODULE.ordinary_candidate_context(request,env,root),{MODULE.ORDINARY_CURRENT_ENV:MODULE.ORDINARY_CURRENT_SCOPE})
            for changes in ({MODULE.ORDINARY_CURRENT_ENV:"other"},{"TEST_RUNNER_MRK_NORMAL_UI_APPLICATION_SOURCE":"b"*40},
                {"TEST_RUNNER_MRK_NORMAL_UI_APPLICATION_SOURCE":"0"*40},{"TEST_RUNNER_MRK_NORMAL_UI_HARNESS_SOURCE":"0"*40},
                *({key:"mixed"} for key in (MODULE.IOS_TOOLS_CURRENT_ENV,MODULE.SAVED_VERSION_CURRENT_ENV,
                    MODULE.IOS_PENDING_CURRENT_ENV,MODULE.ANDROID_CURRENT_ENV,MODULE.FIXED_RESUME_ENV,MODULE.FIXED_NORMAL_BATCH_ENV))):
                with self.assertRaises(MODULE.Refused): MODULE.ordinary_candidate_context(request,{**env,**changes},root)
            for changes in (dict(result=Path("test.xcresult")),dict(result=Path(MODULE.IOS_UNSIGNED_RESULT)),
                dict(result=Path(MODULE.SAVED_VERSION_RESULT)),dict(result=Path("diagnostics-test.xcresult")),
                dict(phase="query"),*({key:True} for key in ('iosUnsigned','iosPending','androidPositive','androidCandidate','outputData','credentialUpdate'))):
                with self.assertRaises(MODULE.Refused): MODULE.ordinary_candidate_context({**request,**changes},env,root)
            with self.assertRaises(MODULE.Refused):MODULE.ordinary_candidate_context(request,env,MODULE.SAVED_VERSION_CANDIDATE_ROOT)
            self.assertEqual(MODULE.ordinary_candidate_context(request,{},root),{})
            # Existing normal phase emits the actual two-source receipt through
            # its real original SOURCE reads and consuming publication.
            with tempfile.TemporaryDirectory() as tmp:
                path=Path(tmp);normal=path/'normal-ui';normal.mkdir(mode=0o700)
                result='project-test.xcresult';(normal/result).mkdir(mode=0o700)
                rows=[]
                for relative in ('desktop/tools/macos_normal_ui_runner.py',
                    'desktop/native/macos-normal-ui/MRKNormalAppUITests/NormalAppUITests.swift',
                    'desktop/src/components/IOSArchive.tsx'):
                    leaf=path/relative;leaf.parent.mkdir(parents=True,exist_ok=True)
                    body=b'public inert original SOURCE\n';leaf.write_bytes(body)
                    blob=hashlib.sha1(b'blob '+str(len(body)).encode()+b'\0'+body).hexdigest()
                    rows.append(b'100644 blob '+blob.encode()+b'\t'+relative.encode()+b'\0')
                roster=b''.join(rows)
                def call(argv,**kw):
                    self.assertEqual(kw['cwd'],path)
                    return subprocess.CompletedProcess(argv,0,roster if argv[0]=='/usr/bin/git' else MODULE.encoded(dict(totalTestCount=2,passedTests=2,failedTests=0,skippedTests=0,expectedFailures=0)),b'')
                request=MODULE.normal_request(['--target',target,'--normal-summary',result],str(normal/'tmp')+'/')
                phase=MODULE.NormalPhase(SimpleNamespace(run_owned=call),env,path,MODULE.PhaseClock(90))
                self.assertEqual(MODULE.execute_normal_phase(phase,request,'b'*40,(1<<30,1<<30)).returncode,0)
                row=json.loads((normal/'project-summary.command-admission.json').read_bytes())
                self.assertEqual((row['sourceCommit'],row['applicationSourceCommit'],row['currentCandidateScope']),('b'*40,'a'*40,MODULE.ORDINARY_CURRENT_SCOPE))
                self.assertTrue(row['sourcePrePostMatched'])
                self.assertEqual([x['role'] for x in row['commands']],['normal-ui-source-roster','normal-ui-summary','normal-ui-source-roster'])
        valid=b'MRK_NORMAL_PROJECT_IDENTITY=v1;sample=pre-wait;staticText=0;anyRole=1;androidCaption=1;iosCaption=1;nonAtomic=1\n'
        private=b'PRIVATE-keystrokes-and-credential-value\n'
        original=subprocess.CompletedProcess(['fixed-original'],65,valid+private,b'')
        diagnostic=MODULE.normal_failure_diagnostics('test','project-test.xcresult',original)
        self.assertEqual(diagnostic['originalReturncode'],65)
        self.assertEqual(diagnostic['projectIdentity']['sample'],dict(staticText=0,anyRole=1,androidCaption=1,iosCaption=1,timing='pre-wait',countsCappedAt=5,nonAtomic=True))
        self.assertNotIn(b'PRIVATE',MODULE.encoded(diagnostic));self.assertLessEqual(len(MODULE.encoded(diagnostic))+1,4096)
        for a,b in ((valid+valid,b''),(valid[:-1],b''),(b'prefix '+valid,b''),(valid.replace(b'staticText=0',b'staticText=6'),b''),(b'',valid),(valid.replace(b'pre-wait',b'PRIVATE'),b'')):
            self.assertEqual(MODULE.project_identity_diagnostics(a,b)['state'],'refused')
        self.assertNotIn('projectIdentity',MODULE.normal_failure_diagnostics('test','test.xcresult',original))
        self.assertNotIn('projectIdentity',MODULE.normal_failure_diagnostics('summary','project-test.xcresult',original))
        with self.assertRaises(MODULE.Refused): MODULE.project_identity_diagnostics(b'x'*(1024*1024+1),b'')
        snapshot=b'MRK_NORMAL_SNAPSHOT_STATE=v2;sample=post-wait;waiter=timed-out;error=0;partial=0;unread=1;loading=0;empty=1;unsupported=1;invalid=0;missing=0;runtime=0;protocol=0;engineDisabled=0;engineUnavailable=1;firstKnownReason=runtime-inspection;nonAtomic=1\n'
        for selection in ('project-test.xcresult',MODULE.ANDROID_CANDIDATE_RESULT):
            original=subprocess.CompletedProcess(['fixed-original'],65,snapshot+private,b'')
            diagnostic=MODULE.normal_failure_diagnostics('test',selection,original)
            self.assertEqual(diagnostic['originalReturncode'],65)
            sample=diagnostic['snapshotState']['samples'][0]
            self.assertEqual((sample['unread'],sample['empty'],sample['unsupported']),(1,1,1))
            self.assertEqual((sample['timing'],sample['waiter']),('post-wait','timed-out'))
            self.assertEqual((sample['engineUnavailable'],sample['firstKnownReason'],sample['reasonSelection']), (1,'runtime-inspection','first-observed-fixed-order'))
            self.assertNotIn(b'PRIVATE',MODULE.encoded(diagnostic));self.assertLessEqual(len(MODULE.encoded(diagnostic))+1,4096)
        # Two existing project methods may fail separately. Preserve both fixed
        # observations, never infer they were atomic or a single method's state.
        self.assertEqual(len(MODULE.snapshot_state_diagnostics(snapshot*2,b'')['samples']),2)
        # Mac Book/profile refusals are distinct source literals, not the Linux
        # original-custody message; keep the observer and closed decoder paired.
        for code,text in (
            ('mac-runtime-inspection','The installed Mac runtime failed original custody inspection.'),
            ('mac-inspection-stopped','Installed Mac runtime inspection stopped before completion.'),
            ('mac-inspection-deadline','Installed Mac runtime inspection exceeded its deadline.'),
            ('mac-inspection-bounds','Installed Mac runtime inspection exceeded its resource limit.'),
            ('mac-inspection-native','Installed Mac runtime native or data inspection could not finish.'),
            ('mac-inspection-ownership','Installed Mac runtime ownership or filesystem protections could not be verified.'),
            ('mac-inspection-inventory','Installed Mac runtime inventory could not be verified.'),
            ('mac-inspection-identity','Installed Mac runtime original file identity could not be confirmed.'),
            ('mac-inspection-reused','Installed Mac runtime inspection was already used.'),
            ('mac-inspection-unknown','Installed Mac runtime original custody could not be confirmed.'),
            ('mac-runtime-profile','This Mac method is outside its passive profile or original document-bound signing-input assessment profile.'),
        ):
            self.assertIn('("'+code+'", "'+text+'")',SWIFT.read_text())
        for reason in (b'none',b'query-timeout',b'android-2',b'images-3',b'mac-runtime-inspection',b'mac-runtime-profile',b'mac-inspection-stopped',b'mac-inspection-deadline',b'mac-inspection-bounds',b'mac-inspection-native',b'mac-inspection-ownership',b'mac-inspection-inventory',b'mac-inspection-identity',b'mac-inspection-reused',b'mac-inspection-unknown'):
            row=MODULE.snapshot_state_diagnostics(snapshot.replace(b'runtime-inspection',reason),b'')['samples'][0]
            self.assertEqual(row['firstKnownReason'],reason.decode())
        pair=MODULE.normal_failure_diagnostics('test','project-test.xcresult',subprocess.CompletedProcess([],65,snapshot*2+valid+private,b''))
        self.assertEqual(len(pair['snapshotState']['samples']),2)
        self.assertLessEqual(len(MODULE.encoded(pair))+1,4096)
        for a,b in ((snapshot*3,b''),(snapshot[:-1],b''),(b'prefix '+snapshot,b''),(snapshot.replace(b'error=0',b'error=6'),b''),(b'',snapshot),(snapshot.replace(b'post-wait',b'PRIVATE'),b''),(snapshot.replace(b'runtime-inspection',b'PRIVATE'),b''),(snapshot.replace(b'engineDisabled=0',b'engineDisabled=6'),b'')):
            self.assertEqual(MODULE.snapshot_state_diagnostics(a,b)['state'],'refused')
        self.assertNotIn('snapshotState',MODULE.normal_failure_diagnostics('summary','project-test.xcresult',original))
        with self.assertRaises(MODULE.Refused): MODULE.snapshot_state_diagnostics(b'x'*(1024*1024+1),b'')
        self.assertIn('observeSnapshotState(root, waiter: result)',wait)
        self.assertNotIn('try? observeSnapshotState(',wait)

    def test_current_ios_candidate_context_is_two_source_and_only_two_journeys(self):
        root=MODULE.SAVED_VERSION_CANDIDATE_ROOT / ".candidate-consumer-helper"
        env={MODULE.IOS_TOOLS_CURRENT_ENV:MODULE.IOS_TOOLS_CURRENT_SCOPE,
            "TEST_RUNNER_MRK_NORMAL_UI_APPLICATION_SOURCE":"a"*40,
            "TEST_RUNNER_MRK_NORMAL_UI_HARNESS_SOURCE":"b"*40}
        temporary="/Users/runner/work/_temp/mrk-macos-installed.ABCDef12/normal-ui/tmp/"
        for target in (MODULE.ARM_TARGET,MODULE.INTEL_TARGET):
            for args in (["--normal-build"],["--normal-ios-unsigned-archive-test"],["--normal-ios-unsigned-archive-summary"],
                         ["--normal-summary","diagnostics-test.xcresult"]):
                request=MODULE.normal_request(["--target",target,*args],temporary)
                self.assertEqual(MODULE.ios_tools_candidate_context(request,env,root),
                                 {MODULE.IOS_TOOLS_CURRENT_ENV:MODULE.IOS_TOOLS_CURRENT_SCOPE})
            args=normal_arguments("diagnostics-test.xcresult")
            args[8]="platform=macOS,arch="+MODULE.normal_target_data(target)[0]
            request=MODULE.normal_request(["--target",target,*args],temporary)
            self.assertEqual(MODULE.ios_tools_candidate_context(request,env,root),
                             {MODULE.IOS_TOOLS_CURRENT_ENV:MODULE.IOS_TOOLS_CURRENT_SCOPE})
            for change in ({MODULE.IOS_TOOLS_CURRENT_ENV:"unknown"},
                {"TEST_RUNNER_MRK_NORMAL_UI_APPLICATION_SOURCE":"b"*40},
                {"TEST_RUNNER_MRK_NORMAL_UI_APPLICATION_SOURCE":"0"*40},
                {"TEST_RUNNER_MRK_NORMAL_UI_HARNESS_SOURCE":"0"*40},
                {MODULE.SAVED_VERSION_CURRENT_ENV:MODULE.SAVED_VERSION_CURRENT_SCOPE},
                {MODULE.FIXED_RESUME_ENV:MODULE.FIXED_NORMAL_SCOPE},{MODULE.FIXED_NORMAL_BATCH_ENV:"doctor-saved-checks"}):
                with self.subTest(change=change),self.assertRaises(MODULE.Refused):
                    MODULE.ios_tools_candidate_context(request,{**env,**change},root)
            for change in (dict(result=Path(MODULE.SAVED_VERSION_RESULT)),dict(result=Path("project-test.xcresult")),
                dict(phase="query"),dict(iosUnsigned=True),dict(androidPositive=True),dict(androidCandidate=True),
                dict(outputData=True),dict(credentialUpdate="p1-resume"),dict(iosPending=True)):
                with self.subTest(change=change),self.assertRaises(MODULE.Refused):
                    MODULE.ios_tools_candidate_context({**request,**change},env,root)
            unsigned=MODULE.normal_request(["--target",target,"--normal-ios-unsigned-archive-test"],temporary)
            with self.assertRaises(MODULE.Refused):MODULE.ios_tools_candidate_context(dict(unsigned,iosUnsigned=False),env,root)
            with self.assertRaises(MODULE.Refused):MODULE.ios_tools_candidate_context(request,env,MODULE.SAVED_VERSION_CANDIDATE_ROOT)
            self.assertEqual(MODULE.ios_tools_candidate_context(request,{},root),{})
        saved=dict(phase="test",result=Path(MODULE.SAVED_VERSION_RESULT))
        with self.assertRaises(MODULE.Refused):MODULE.saved_version_candidate_context(saved,
            {**env,MODULE.SAVED_VERSION_CURRENT_ENV:MODULE.SAVED_VERSION_CURRENT_SCOPE},root)

    def test_current_ios_summary_receipt_keeps_original_source_and_close(self):
        # Actual existing source readers and exclusive receipt writer; no native
        # xcrun or app. Three original-command boundaries use an inert owner.
        for target in (MODULE.ARM_TARGET,MODULE.INTEL_TARGET):
            for name in ("diagnostics-test.xcresult",MODULE.IOS_UNSIGNED_RESULT):
                with self.subTest(target=target,name=name),tempfile.TemporaryDirectory(prefix="mrk-current-ios-summary-") as temporary:
                    root=Path(temporary);normal=root/"normal-ui";normal.mkdir(mode=0o700)
                    (normal/name).mkdir(mode=0o700)
                    rows=[]
                    for relative in ("desktop/tools/macos_normal_ui_runner.py",
                        "desktop/native/macos-normal-ui/MRKNormalAppUITests/NormalAppUITests.swift", "desktop/src/components/IOSArchive.tsx"):
                        source=root/relative;source.parent.mkdir(parents=True,exist_ok=True)
                        body=b"inert original source never executed\n";source.write_bytes(body)
                        blob=hashlib.sha1(b"blob "+str(len(body)).encode()+b"\0"+body).hexdigest()
                        rows.append(b"100644 blob "+blob.encode()+b"\t"+relative.encode()+b"\0")
                    roster=b"".join(rows)
                    counts=MODULE.encoded(dict(totalTestCount=1,passedTests=1,failedTests=0,skippedTests=0,expectedFailures=0))
                    calls=[]
                    def original(argv,**kw):
                        calls.append((argv,kw))
                        if argv[0]=="/usr/bin/git":
                            self.assertIn("b"*40,argv)
                            return subprocess.CompletedProcess(argv,0,roster,b"")
                        self.assertEqual(argv[:5],["/usr/bin/xcrun","xcresulttool","get","test-results","summary"])
                        return subprocess.CompletedProcess(argv,0,counts,b"")
                    arguments=["--normal-ios-unsigned-archive-summary"] if name==MODULE.IOS_UNSIGNED_RESULT else ["--normal-summary",name]
                    request=MODULE.normal_request(["--target",target,*arguments],str(normal/"tmp")+"/")
                    env={MODULE.IOS_TOOLS_CURRENT_ENV:MODULE.IOS_TOOLS_CURRENT_SCOPE,
                        "TEST_RUNNER_MRK_NORMAL_UI_APPLICATION_SOURCE":"a"*40,
                        "TEST_RUNNER_MRK_NORMAL_UI_HARNESS_SOURCE":"b"*40}
                    phase=MODULE.NormalPhase(SimpleNamespace(run_owned=original),env,root,MODULE.PhaseClock(90))
                    returned=MODULE.execute_normal_phase(phase,request,"b"*40,(1<<30,1<<30))
                    self.assertEqual(returned.returncode,0)
                    receipt=normal/(MODULE.SUMMARY_STEMS[name]+".command-admission.json")
                    value=json.loads(receipt.read_bytes())
                    self.assertEqual(value['sourceCommit'],"b"*40)
                    self.assertEqual(value['applicationSourceCommit'],"a"*40)
                    self.assertEqual(value['currentCandidateScope'],MODULE.IOS_TOOLS_CURRENT_SCOPE)
                    self.assertEqual([r['role'] for r in value['commands']],
                                     ['normal-ui-source-roster','normal-ui-summary','normal-ui-source-roster'])
                    self.assertTrue(value['sourcePrePostMatched'])
                    self.assertEqual(stat.S_IMODE(receipt.stat().st_mode),0o600)
                    self.assertEqual(len(calls),3)
                    self.assertTrue(all(kw['cwd']==root for _,kw in calls))
                    if name==MODULE.IOS_UNSIGNED_RESULT:self.assertEqual(value['iosUnsignedTestCounts']['passedTests'],1)

    def test_saved_version_fresh_root_group_normalization_is_original_and_scoped(self):
        # Real private descriptors; only Darwin's inherited-group observation is
        # modeled. A separate nonroot setgid-parent check exercises real fchown.
        for fault in (None, "same-group", "nonempty", "wrong-owner", "wrong-mode", "existing", "fchown", "post"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as temporary:
                parent = Path(temporary)
                os.chown(parent, -1, os.getgid())  # Only this exclusive test directory.
                root = parent / "mrk-normal-project-regression"
                root.mkdir(mode=0o700)
                if fault == "nonempty": (root / "keep").write_bytes(b"preserve")
                if fault == "wrong-mode": root.chmod(0o755)
                fixture = object.__new__(MODULE.SavedVersionFixture)
                fixture.fds, fixture.dirs, fixture.root = [], {}, root
                fixture.temporary = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
                before = MODULE.saved_version_facts(root.stat())
                original_facts, original_chown = MODULE.saved_version_facts, os.fchown
                normalized, calls = [fault == "same-group"], []
                def observed(info):
                    values = list(original_facts(info))
                    if values[:2] == list(before[:2]):
                        if not normalized[0]: values[4] = os.getgid() + 1
                        if fault == "wrong-owner": values[3] = os.getuid() + 1
                        if fault == "post" and normalized[0]: values[2] = stat.S_IFDIR | 0o755
                    return tuple(values)
                def change(fd, uid, gid):
                    self.assertIn(fd, fixture.fds)
                    self.assertEqual(original_facts(os.fstat(fd))[:2], before[:2])
                    self.assertEqual((uid, gid), (-1, os.getgid()))
                    calls.append(fd)
                    if fault == "fchown": raise PermissionError("injected group change refusal")
                    original_chown(fd, uid, gid)
                    normalized[0] = True
                try:
                    with patch.object(MODULE, "SAVED_VERSION_TEMPORARY", parent), \
                            patch.object(MODULE, "saved_version_facts", observed), patch.object(MODULE.os, "fchown", change):
                        if fault not in (None, "same-group"):
                            with self.assertRaises((MODULE.Refused, PermissionError)):
                                fixture._directory("", fixture.temporary, root.name, created_root=fault != "existing")
                            self.assertEqual(fixture.dirs, {})
                        else:
                            fd = fixture._directory("", fixture.temporary, root.name, created_root=True)
                            self.assertEqual(fixture.dirs[""][3], original_facts(os.fstat(fd)))
                    self.assertEqual(len(calls), int(fault in (None, "fchown", "post")))
                    self.assertEqual(original_facts(root.stat())[:8], before[:8])
                    self.assertEqual(os.stat(parent).st_gid, os.getgid())
                    if fault == "nonempty": self.assertEqual((root / "keep").read_bytes(), b"preserve")
                finally:
                    for fd in reversed(fixture.fds): os.close(fd)
                    os.close(fixture.temporary)

    def test_current_saved_version_candidate_context_is_two_source_and_single_journey(self):
        root = MODULE.SAVED_VERSION_CANDIDATE_ROOT / ".candidate-consumer-helper"
        env = {MODULE.SAVED_VERSION_CURRENT_ENV: MODULE.SAVED_VERSION_CURRENT_SCOPE,
            "TEST_RUNNER_MRK_NORMAL_UI_APPLICATION_SOURCE": "a" * 40,
            "TEST_RUNNER_MRK_NORMAL_UI_HARNESS_SOURCE": "b" * 40}
        for mode in ("build", "test", "summary"):
            request = dict(phase=mode, result=None if mode == "build" else Path(MODULE.SAVED_VERSION_RESULT))
            self.assertEqual(MODULE.saved_version_candidate_context(request, env, root),
                             {MODULE.SAVED_VERSION_CURRENT_ENV: MODULE.SAVED_VERSION_CURRENT_SCOPE})
        request = dict(phase="test", result=Path(MODULE.SAVED_VERSION_RESULT))
        for change in ({MODULE.SAVED_VERSION_CURRENT_ENV: "unknown"},
                       {"TEST_RUNNER_MRK_NORMAL_UI_APPLICATION_SOURCE": "b" * 40},
                       {"TEST_RUNNER_MRK_NORMAL_UI_APPLICATION_SOURCE": "unknown"},
                       {MODULE.FIXED_RESUME_ENV: MODULE.FIXED_NORMAL_SCOPE},
                       {MODULE.FIXED_NORMAL_BATCH_ENV: "saved-version-recovery"}):
            with self.subTest(environment=change), self.assertRaises(MODULE.Refused):
                MODULE.saved_version_candidate_context(request, {**env, **change}, root)
        for changed in (dict(request, result=Path("project-test.xcresult")), dict(request, phase="query"),
                        dict(request, iosUnsigned=True), dict(request, androidPositive=True)):
            with self.assertRaises(MODULE.Refused): MODULE.saved_version_candidate_context(changed, env, root)
        with self.assertRaises(MODULE.Refused):
            MODULE.saved_version_candidate_context(request, env, MODULE.SAVED_VERSION_CANDIDATE_ROOT)
        self.assertEqual(MODULE.saved_version_candidate_context(request, {}, root), {})

    def test_current_saved_version_actual_core_parser_and_retained_originals(self):
        # Real ZIP/manifest parsers and real private file originals; installation
        # ownership/xattrs/Apple directory admission are explicitly inert Linux
        # fixtures. No native app, installer or core subprocess is executed here.
        import zipfile
        module_name = "_mrk_current_saved_version_test_stager"
        spec = importlib.util.spec_from_file_location(module_name, ROOT / MODULE.SAVED_VERSION_STAGER)
        stage = importlib.util.module_from_spec(spec)
        self.assertNotIn(module_name, sys.modules)
        sys.modules[module_name] = stage
        try:
            spec.loader.exec_module(stage)
            for target in (MODULE.ARM_TARGET, MODULE.INTEL_TARGET):
                for fault in (None, "git-source", "core-bytes", "manifest-core", "manifest-target", "wrapper", "post-core", "post-source", "late-post", "child-zero", "child-unknown", "close"):
                    with self.subTest(target=target, fault=fault), tempfile.TemporaryDirectory(prefix="mrk-current-version-data-") as temporary:
                        base = Path(temporary); source = base / "candidate"; source.mkdir()
                        normal = base / "normal-ui"; normal.mkdir()
                        installed = base / "installed"; installed.mkdir(); runtime = installed / "runtime"; runtime.mkdir()
                        wrappers = set(stage.CURRENT_BOOTSTRAPS) | {"local_store_preflight_bootstrap.py", "local_store_prepare_bootstrap.py",
                            "local_store_execute_bootstrap.py", "local_store_reconcile_bootstrap.py"}
                        bodies = {"desktop/" + name: b"inert matching wrapper data\n" for name in wrappers}
                        bodies.update({"src/mobile_release/__init__.py": b'__version__ = "0.3.0"\n',
                            "src/mobile_release/_desktop_engine.py": (ROOT / "src/mobile_release/_desktop_engine.py").read_bytes(),
                            "desktop/cpython-source-inputs/github-ca.pem": b"inert CA data\n",
                            "desktop/tools/prepare_runtime.py": b"inert producer source\n",
                            "desktop/packaging/macos-history-provider.profile": b"inert profile\n",
                            MODULE.SAVED_VERSION_STAGER: b"inert selected parser SOURCE not executed in test\n",
                            MODULE.SAVED_VERSION_PRODUCER: b"inert selected producer SOURCE not executed in test\n",
                            MODULE.SAVED_VERSION_DATA: (ROOT / MODULE.SAVED_VERSION_DATA).read_bytes()})
                        for leaf in ("build-release.json", "build-release-intel.json"):
                            bodies["desktop/macos-installed-inputs/" + leaf] = (ROOT / "desktop/macos-installed-inputs" / leaf).read_bytes()
                        git_rows = []
                        for name, body in sorted(bodies.items()):
                            path = source / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(body); path.chmod(0o600)
                            blob = hashlib.sha1(b"blob " + str(len(body)).encode() + b"\0" + body).hexdigest()
                            git_rows.append(b"100644 blob " + blob.encode() + b"\t" + name.encode() + b"\0")
                        packed = io.BytesIO()
                        with zipfile.ZipFile(packed, "w") as archive:
                            for name in sorted(n for n in bodies if n.startswith("src/mobile_release/")):
                                info = zipfile.ZipInfo(name[4:], date_time=(1980, 1, 1, 0, 0, 0))
                                info.compress_type = zipfile.ZIP_DEFLATED; info.create_system = 3
                                info.external_attr = (stat.S_IFREG | 0o644) << 16
                                content = bodies[name] + (b"# changed\n" if fault == "core-bytes" else b"")
                                archive.writestr(info, content)
                        files = {name: bodies["desktop/" + name] for name in wrappers}
                        files.update({"core.zip": packed.getvalue(), "github-ca.pem": bodies["desktop/cpython-source-inputs/github-ca.pem"],
                                      "python/bin/python3": b"inert interpreter bytes; never executed"})
                        if fault == "wrapper": files["config_edit_bootstrap.py"] += b"wrong"
                        rows = [dict(path=name, size=len(body), sha256=MODULE.sha(body)) for name, body in sorted(files.items())]
                        if fault == "manifest-core":
                            next(row for row in rows if row["path"] == "core.zip")["sha256"] = "c" * 64
                        manifest = dict(schemaVersion=1, protocol=1, coreVersion="0.3.0", target=target,
                            coreSha256=next(row for row in rows if row["path"] == "core.zip")["sha256"],
                            protocolSha256=stage.CURRENT_PROTOCOL, inventorySha256=stage.digest(stage.canonical(rows)), files=rows)
                        if fault == "manifest-target": manifest["target"] = "invalid"
                        files["manifest.json"] = stage.canonical(manifest)
                        for name, body in files.items():
                            path = runtime / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(body); path.chmod(0o600)
                        if fault == "git-source": (source / MODULE.SAVED_VERSION_PRODUCER).write_bytes(b"different selected source")
                        called, tick = [], [0]
                        def owned(argv, **kwargs):
                            called.append(argv)
                            if argv[0] == "/inert/python":
                                self.assertEqual(argv[4], str(source / MODULE.SAVED_VERSION_PRODUCER))
                                self.assertEqual(argv[-2:], ["release_version", "interrupt"])
                                self.assertEqual((kwargs["timeout"], kwargs["output_limit"]), (20, 65536))
                                if fault == "child-unknown": raise MODULE.Refused("synthetic unreturned interrupt")
                                return subprocess.CompletedProcess(argv, 0, b"", b"")
                            self.assertEqual(argv[:3], ["/usr/bin/git", "-C", str(source)])
                            self.assertIn("a" * 40, argv); self.assertNotIn("b" * 40, argv)
                            return subprocess.CompletedProcess(argv, 0, b"".join(git_rows), b"")
                        env = {MODULE.SAVED_VERSION_CURRENT_ENV: MODULE.SAVED_VERSION_CURRENT_SCOPE,
                            "TEST_RUNNER_MRK_NORMAL_UI_APPLICATION_SOURCE": "a" * 40,
                            "TEST_RUNNER_MRK_NORMAL_UI_HARNESS_SOURCE": "b" * 40}
                        phase = MODULE.NormalPhase(SimpleNamespace(run_owned=owned), env, base / "helper", MODULE.PhaseClock(585, now=lambda: tick[0]))
                        selected = []
                        @contextmanager
                        def installation(root, names, *, selection):
                            selected.append(selection)
                            self.assertEqual(selection.target, target)
                            self.assertEqual(selection.release, stage.source_build_selection(target).release)
                            fd = os.open(installed, os.O_RDONLY | os.O_DIRECTORY)
                            try: yield None, None, fd
                            finally: os.close(fd)
                        @contextmanager
                        def directory(parent, name, mode):
                            self.assertEqual((name, mode), ("runtime", 0o555))
                            fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY, dir_fd=parent)
                            try: yield fd, None
                            finally: os.close(fd)
                        with patch.object(MODULE, "SAVED_VERSION_CANDIDATE_ROOT", source), \
                                patch.object(stage, "installation_metadata_directory", installation), patch.object(stage, "maintenance_directory", directory):
                            fixture = MODULE.SavedVersionFixture(phase, "b" * 40, normal); fixture.phase_target = target
                            def parser():
                                fixture.runtime_stager = stage; sys.modules[fixture.runtime_module_name] = stage
                                return stage
                            def leaf(parent, name, limit):
                                entry = fixture._read(parent, name, limit)
                                fixture.runtime_entries.append((parent, name, entry, limit, False))
                                return entry[1]
                            try:
                                with patch.object(fixture, "_current_stager", parser), patch.object(fixture, "_installed_runtime_leaf", leaf):
                                    if fault in ("child-zero", "child-unknown"):
                                        fake_sys = SimpleNamespace(flags=SimpleNamespace(isolated=1, no_site=1, dont_write_bytecode=1),
                                                                   executable="/inert/python", modules=sys.modules)
                                        def staged(): fixture.root = base / "inert-project"
                                        with patch.object(fixture, "_stage", staged), patch.object(MODULE, "sys", fake_sys), self.assertRaises(MODULE.Refused):
                                            fixture.interrupt(target)
                                        self.assertFalse(fixture.handoff.exists()); self.assertIsNone(fixture.receipt)
                                    elif fault in ("git-source", "core-bytes", "manifest-core", "manifest-target", "wrapper"):
                                        with self.assertRaises((MODULE.Refused, stage.Refused)):
                                            fixture._sources()
                                        self.assertIsNone(fixture.root); self.assertFalse(fixture.handoff.exists())
                                    else:
                                        fixture._sources()
                                        self.assertNotEqual(fixture.source_inputs, MODULE.SAVED_VERSION_SOURCE)
                                        self.assertEqual(fixture.runtime_name, "manifest.json")
                                        self.assertFalse((normal.parent / "runtime-result.json").exists())
                                        self.assertEqual(fixture.runtime_witness["applicationSourceCommit"], "a" * 40)
                                        self.assertEqual(fixture.runtime_witness["harnessSourceCommit"], "b" * 40)
                                        self.assertTrue(fixture.runtime_witness["installedCoreMatched"])
                                        if fault == "post-core": (runtime / "core.zip").write_bytes(b"changed")
                                        if fault == "post-source": (source / MODULE.SAVED_VERSION_PRODUCER).write_bytes(b"changed")
                                        if fault == "late-post": tick[0] = 585 * 10**9
                                        if fault in ("post-core", "post-source", "late-post"):
                                            with self.assertRaises(MODULE.Refused): fixture.check_sources()
                                        else: fixture.check_sources()
                                    self.assertEqual(len(called), 2 if fault in ("child-zero", "child-unknown") else 1)
                                    # Failed binding never dispatches child/UI; unreturned/non86 child never publishes handoff.
                            finally:
                                if fault == "close":
                                    original_close = MODULE.os.close; closed = []
                                    def consuming(fd):
                                        original_close(fd); closed.append(fd)
                                        if len(closed) == 1: raise OSError("synthetic consuming close")
                                    with patch.object(MODULE.os, "close", consuming), self.assertRaises(OSError): fixture.close()
                                    self.assertEqual(len(closed), len(set(closed)))
                                else: fixture.close()
                                self.assertFalse(fixture.fds)
                                self.assertNotIn(MODULE.SAVED_VERSION_CURRENT_STAGER_MODULE, sys.modules)
        finally:
            if sys.modules.get(module_name) is stage: del sys.modules[module_name]

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
                    "desktop/native/macos-normal-ui/MRKNormalAppUITests/NormalAppUITests.swift", "desktop/src/components/IOSArchive.tsx")
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

        # The SAME real-filesystem group also exercises the fixed engineering
        # assembly/input/receipt path. Small synthetic bytes only: no archive,
        # interpreter, signer, Xcode, or application is executed by this test.
        for fault in (None, "runtime-changed", "source-changed", "native-nonzero", "late-test",
                      "input-close", "receipt-close", "summary-nonzero", "late-summary-close",
                      "resources-missing", "resources-symlink", "resources-nonempty"):
            with self.subTest(engineering_original=fault), tempfile.TemporaryDirectory(prefix="mrk-engineering-main-data-") as temporary:
                base = Path(temporary)
                root, compiler, work = (base / name for name in ("source", "compiler", "work"))
                for directory in (root, compiler, work): directory.mkdir(mode=0o700)
                normal = work / "normal-ui"; normal.mkdir(mode=0o700)
                (normal / "tmp").mkdir(mode=0o700)
                def put(path, body, mode=0o600):
                    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                    path.write_bytes(body); path.chmod(mode)
                relative_names = ("desktop/tools/macos_normal_ui_runner.py",
                    "desktop/native/macos-normal-ui/MRKNormalAppUITests/NormalAppUITests.swift", "desktop/src/components/IOSArchive.tsx")
                source_rows = []
                for relative in relative_names:
                    body = b"synthetic SOURCE only, never imported or compiled\n"
                    put(root / relative, body)
                    blob = hashlib.sha1(b"blob " + str(len(body)).encode() + b"\0" + body).hexdigest()
                    source_rows.append(b"100644 blob " + blob.encode() + b"\t" + relative.encode() + b"\0")
                workflow_name = ".github/workflows/desktop-macos-engineering-ui.yml"
                workflow_body = b"synthetic fixed workflow SOURCE, never executed\n"
                put(root / workflow_name, workflow_body)
                bootstrap = b"synthetic bootstrap SOURCE, never executed\n"
                protocol = b"synthetic core protocol SOURCE, never imported\n"
                put(root / "desktop/engine_bootstrap.py", bootstrap)
                put(root / "src/mobile_release/_desktop_engine.py", protocol)
                plist_body = plistlib.dumps(dict(CFBundleIdentifier="dev.mobile-release-kit.engineering-ui",
                    CFBundleExecutable="mobile-release-kit-desktop", CFBundleName="Mobile Release Kit", CFBundlePackageType="APPL"))
                put(root / "desktop/native/macos-normal-ui/engineering-main-app.plist", plist_body)
                binary = b"synthetic original main, not an executable format\n"
                put(compiler / "target/engineering-main/mobile-release-kit-desktop", binary, 0o700)
                binding = dict(sourceSha="a" * 40, sourceTree="b" * 40, workflowPath=workflow_name,
                    workflowSha="a" * 40, workflowSha256=hashlib.sha256(workflow_body).hexdigest(),
                    workflowRef="mobile-release-kit/mobile-release-kit/" + workflow_name + "@refs/heads/verify/desktop-macos-engineering-ui",
                    runId="123", attempt="1", engineeringWork=str(work))
                context = dict(binding, root=str(compiler), source=str(root), platform="macos", executionScope="macos-engineering-ui-compile-v1")
                public = dict(binding, platform="macos", scope="desktop-macos-engineering-ui-compile-only-v1",
                              bootstrapSha256=hashlib.sha256(bootstrap).hexdigest())
                put(compiler / "context.json", json.dumps(context).encode())
                put(compiler / "public-bindings.json", json.dumps(public).encode())
                rust = dict(release="1.98.1", commitHash="48a229ceaefd4985c50990b14116b6d856af0985", target="aarch64-apple-darwin")
                check_names = {"acquire": ("rust-version-target", "mac-cargo-version", "locked-platform-metadata", "node-version", "npm-locked-no-scripts"),
                    "compile": ("rust-version-target", "mac-cargo-version", "node-version", "typescript-no-emit", "vite-assets", "tauri-debug-compile-only")}
                for mode in ("acquire", "compile"):
                    receipt = dict(schemaVersion=1, scope="desktop-macos-engineering-ui-compile-only-v1", phase=mode,
                        status="passed", **binding, platform="macos", rust=rust, node="v24.20.0",
                        checks=[dict(check=name, exitCode=0) for name in check_names[mode]])
                    if mode == "compile":
                        receipt["compiledMain"] = dict(relativePath="target/engineering-main/mobile-release-kit-desktop",
                            bytes=len(binary), sha256=hashlib.sha256(binary).hexdigest())
                    put(compiler / (mode + "-checks.json"), json.dumps(receipt).encode())
                runtime = work / "runtime"
                runtime_inputs = {"core.zip": b"synthetic core bytes, not parsed as a ZIP\n",
                                  "engine_bootstrap.py": bootstrap, "python/bin/python3": b"synthetic interpreter, never executed\n"}
                rows = []
                for name, body in sorted(runtime_inputs.items()):
                    put(runtime / name, body, 0o555 if name == "python/bin/python3" else 0o444)
                    rows.append(dict(path=name, size=len(body), sha256=hashlib.sha256(body).hexdigest()))
                manifest = dict(schemaVersion=1, protocol=1, coreVersion="fixture", target="aarch64-apple-darwin",
                    coreSha256=hashlib.sha256(runtime_inputs["core.zip"]).hexdigest(),
                    protocolSha256=hashlib.sha256(protocol).hexdigest(),
                    inventorySha256=hashlib.sha256(json.dumps(rows, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest(),
                    files=rows)
                manifest_body = json.dumps(manifest).encode()
                put(runtime / "manifest.json", manifest_body, 0o444)
                for directory in sorted((p for p in runtime.rglob("*") if p.is_dir()), key=lambda p: len(p.parts), reverse=True):
                    directory.chmod(0o555)
                runtime.chmod(0o555)
                description = dict(qualification="current-source-description-only-not-build-or-install-authority", target="aarch64-apple-darwin",
                    supplierOrigin="fresh-public-source", supplierReceiptSha256="2f9cf013c0598b08e89fd9b26d1d74d8ab08be2c22c152ae27cb3219139cd81d",
                    supplierProfile="mrk-macos-cpython-source-supplier-v1", pythonVersion="3.14.7", gil=True,
                    successorManifestSha256=hashlib.sha256(manifest_body).hexdigest(),
                    **{key: manifest[key] for key in ("inventorySha256", "coreSha256", "protocolSha256")})
                put(work / "runtime-description.json", json.dumps(description).encode())
                put(work / "runtime-result.json", json.dumps(dict(description, qualification="current-source-staged-no-native-execution")).encode())
                tool_values = (b"Xcode 26.0\nBuild version 17A324\n",
                    b"/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX26.0.sdk\n",
                    b"26.0\n", b"25A352\n")
                query_values = {tuple(query[2]): body for query, body in zip(MODULE.TOOLCHAIN_QUERIES, tool_values)}
                marker = ("MRK_MACOS_ENGINEERING_MAIN_UI=mainRequest=1;completion=1;body=1;handoff=1;mainIdentity=1;catalogueGuide=1;"
                    "projectSelected=0;editCapability=unavailable;originalTerminated=1;failureCleanup=0;caseDeadlineMet=1;"
                    "cleanExitStatus=unavailable;allWorkerFinality=unavailable")
                case = "-[MRKNormalAppUITests.NormalAppUITests testEngineeringMainCatalogueAndQuit]"
                ui_stdout = ("Test Case '" + case + "' started.\n" + marker + "\nTest Case '" + case + "' passed (1.000 seconds).\n").encode()
                summary_body = b'{"totalTestCount":1,"passedTests":1,"failedTests":0,"skippedTests":0,"expectedFailures":0}\n'
                tick, owned, current_mode = [0], [], ["build"]
                def owned_fake(argv, **kwargs):
                    owned.append((argv, kwargs))
                    if argv[0] == "/usr/bin/git":
                        body = ((binding["sourceSha"] + "\n" + binding["sourceTree"] + "\n").encode() if "rev-parse" in argv
                                else b"" if "diff" in argv else b"".join(source_rows))
                        return subprocess.CompletedProcess(argv, 0, body, b"")
                    if tuple(argv) in query_values:
                        return subprocess.CompletedProcess(argv, 0, query_values[tuple(argv)], b"")
                    if argv[0] == "/usr/bin/codesign":
                        if "--sign" in argv:
                            app = work / "Mobile Release Kit.app"
                            resources = app / "Contents/Resources"
                            self.assertTrue(stat.S_ISDIR(resources.lstat().st_mode))
                            self.assertEqual(stat.S_IMODE(resources.lstat().st_mode), 0o700)
                            self.assertEqual(list(resources.iterdir()), [])
                            put(app / "Contents/_CodeSignature/CodeResources", b"synthetic signature envelope\n")
                            put(app / "Contents/MacOS/mobile-release-kit-desktop", binary + b"synthetic ad-hoc mutation\n", 0o700)
                        return subprocess.CompletedProcess(argv, 0, b"", b"")
                    if argv[1] == "build-for-testing":
                        (normal / "DerivedData").mkdir(mode=0o700)
                        return subprocess.CompletedProcess(argv, 0, b"synthetic build original\n", b"")
                    if argv[1] == "test-without-building":
                        (normal / "engineering-test.xcresult").mkdir(mode=0o700)
                        if fault == "runtime-changed":
                            path = runtime / "core.zip"; path.chmod(0o644); path.write_bytes(b"changed runtime"); path.chmod(0o444)
                        if fault == "source-changed": (root / relative_names[0]).write_bytes(b"changed source\n")
                        if fault == "late-test": tick[0] = 345 * 1_000_000_000
                        return subprocess.CompletedProcess(argv, 65 if fault == "native-nonzero" else 0,
                                                           b"" if fault == "native-nonzero" else ui_stdout, b"")
                    if argv[:4] == ["/usr/bin/xcrun", "xcresulttool", "get", "test-results"]:
                        return subprocess.CompletedProcess(argv, 66 if fault == "summary-nonzero" else 0, summary_body, b"")
                    self.fail("unexpected engineering fake original route")
                original_open, original_close = os.open, os.close
                original_enter = MODULE.EngineeringInputs.__enter__
                close_target, close_failures = [None], []
                def remember_inputs(instance):
                    returned = original_enter(instance)
                    if current_mode[0] == "test" and fault == "input-close":
                        close_target[0] = instance.held[runtime / "core.zip"][0]
                    return returned
                def open_original(path, flags, *args, **kwargs):
                    fd = original_open(path, flags, *args, **kwargs)
                    if flags & os.O_CREAT and str(path).endswith("/engineering-test.runner-admission.json") and fault == "receipt-close":
                        close_target[0] = fd
                    if flags & os.O_CREAT and str(path).endswith("/engineering-summary.command-admission.json") and fault == "late-summary-close":
                        close_target[0] = fd
                    return fd
                def close_original(fd):
                    original_close(fd)
                    if fd == close_target[0]:
                        close_target[0] = None; close_failures.append(fd)
                        if fault == "late-summary-close": tick[0] = 90 * 1_000_000_000
                        else: raise OSError("synthetic consuming original close failure")
                request = dict(engineering=True, phase="build", target="aarch64-apple-darwin", work=work, compiler=compiler,
                    binding={key: value for key, value in binding.items() if key not in ("sourceTree", "workflowSha256")},
                    derived=normal / "DerivedData", result=None, methods=(), allowance=None, timeout=240, phaseSeconds=450)
                result = normal / "engineering-smoke.json"
                try:
                    with patch.object(MODULE.os, "open", open_original), patch.object(MODULE.os, "close", close_original), \
                            patch.object(MODULE.EngineeringInputs, "__enter__", remember_inputs), patch.object(MODULE, "RunnerProducts") as products_type:
                        products = products_type.return_value.__enter__.return_value
                        products_type.return_value.__exit__.return_value = False
                        products.products = normal / "DerivedData/Build/Products"
                        products.manifest = "fixed.xctestrun"
                        products.admit.side_effect = lambda _call: {"scope": "inert-products-not-native-authority"}
                        build_phase = MODULE.NormalPhase(SimpleNamespace(run_owned=owned_fake), {}, root, MODULE.PhaseClock(450, now=lambda: tick[0]))
                        built = MODULE.execute_engineering_phase(build_phase, request, binding["sourceSha"], (32 * 1024**3,) * 2)
                        self.assertEqual(built.returncode, 0)
                        self.assertFalse(result.exists())
                        self.assertEqual((compiler / "target/engineering-main/mobile-release-kit-desktop").read_bytes(), binary)
                        self.assertEqual((work / "Mobile Release Kit.app/Contents/Info.plist").read_bytes(), plist_body)
                        self.assertEqual((work / "Mobile Release Kit.app/Contents/MacOS/mobile-release-kit-desktop").read_bytes(), binary + b"synthetic ad-hoc mutation\n")
                        build_facts = json.loads((normal / "engineering-build.command-admission.json").read_bytes())
                        self.assertEqual(build_facts["compilerBinarySha256"], hashlib.sha256(binary).hexdigest())
                        self.assertTrue(build_facts["inputOriginalClosesCompleted"])
                        resources = work / "Mobile Release Kit.app/Contents/Resources"
                        self.assertTrue(stat.S_ISDIR(resources.lstat().st_mode))
                        self.assertEqual(stat.S_IMODE(resources.lstat().st_mode), 0o555)
                        self.assertEqual(list(resources.iterdir()), [])
                        # Real strict path resolution matches Tauri's macOS
                        # resource_dir requirement; no Tauri/native call is faked.
                        self.assertEqual((work / "Mobile Release Kit.app/Contents/MacOS/../Resources").resolve(strict=True),
                                         resources.resolve(strict=True))
                        if fault in ("resources-missing", "resources-symlink"):
                            resources.parent.chmod(0o700)
                            resources.rmdir()
                            if fault == "resources-symlink":
                                resources.symlink_to(normal / "tmp", target_is_directory=True)
                            resources.parent.chmod(0o555)
                        elif fault == "resources-nonempty":
                            resources.chmod(0o700)
                            put(resources / "unexpected", b"not a runtime input\n", 0o444)
                            resources.chmod(0o555)
                        current_mode[0] = "test"
                        tested_request = dict(request, phase="test", result=normal / "engineering-test.xcresult",
                            methods=(MODULE.ENGINEERING_METHOD,), allowance=60, timeout=180, phaseSeconds=345)
                        test_phase = MODULE.NormalPhase(SimpleNamespace(run_owned=owned_fake), {}, root, MODULE.PhaseClock(345, now=lambda: tick[0]))
                        before_test_calls = len(owned)
                        if fault in ("runtime-changed", "source-changed", "late-test", "input-close", "receipt-close",
                                     "resources-missing", "resources-symlink", "resources-nonempty"):
                            with self.assertRaises((MODULE.Refused, OSError)):
                                MODULE.execute_engineering_phase(test_phase, tested_request, binding["sourceSha"], (1024**3,) * 2)
                        else:
                            tested = MODULE.execute_engineering_phase(test_phase, tested_request, binding["sourceSha"], (1024**3,) * 2)
                            self.assertEqual(tested.returncode, 65 if fault == "native-nonzero" else 0)
                            test_facts = json.loads((normal / "engineering-test.runner-admission.json").read_bytes())
                            self.assertEqual(test_facts["sameOriginalNormalQuitObserved"], fault != "native-nonzero")
                            self.assertTrue(test_facts["generatedRunnerOriginalClosesCompleted"])
                            original_stdout = b"" if fault == "native-nonzero" else ui_stdout
                            self.assertEqual(test_facts["testStdoutSha256"], hashlib.sha256(original_stdout).hexdigest())
                            self.assertEqual((normal / "engineering-test.stdout").read_bytes(), original_stdout)
                            self.assertEqual((normal / "engineering-test.stderr").read_bytes(), b"")
                            current_mode[0] = "summary"
                            summarized = dict(tested_request, phase="summary", timeout=30, phaseSeconds=90, methods=(), allowance=None)
                            summary_phase = MODULE.NormalPhase(SimpleNamespace(run_owned=owned_fake), {}, root, MODULE.PhaseClock(90, now=lambda: tick[0]))
                            if fault in ("native-nonzero", "late-summary-close"):
                                with self.assertRaises(MODULE.Refused):
                                    MODULE.execute_engineering_phase(summary_phase, summarized, binding["sourceSha"], (1024**3,) * 2)
                            else:
                                returned = MODULE.execute_engineering_phase(summary_phase, summarized, binding["sourceSha"], (1024**3,) * 2)
                                self.assertEqual(returned.returncode, 66 if fault == "summary-nonzero" else 0)
                        if fault is None:
                            facts = json.loads(result.read_bytes())
                            self.assertEqual(set(facts), {"schemaVersion", "scope", "status", "sourceSha", "sourceTree", "workflowPath",
                                "workflowSha", "workflowRef", "workflowSha256", "runId", "attempt", "engineeringWork", "compilerRoot", "target",
                                "compilerReceiptSha256", "runtimeResultSha256", "runtimeManifestSha256", "runtimeRosterSha256", "applicationRosterSha256",
                                "compilerBinarySha256", "testAdmissionSha256", "testIdentifier", "testCounts", "nativeSummarySha256",
                                "sameOriginalNormalQuitObserved", "cleanExitStatus", "allWorkerFinality", "fullUIQualified", "productReady",
                                "sourcePrePostMatched", "inputPrePostMatched", "inputOriginalClosesCompleted", "generatedRunnerOriginalClosesCompleted",
                                "originalCommandsReturned", "summaryAdmissionSha256", "originalWrapperZeroRequired"})
                            self.assertEqual(facts["scope"], "engineering-main-ui-smoke-only")
                            self.assertEqual(facts["status"], "passed")
                            self.assertEqual(facts["testCounts"], dict(totalTestCount=1, passedTests=1, failedTests=0, skippedTests=0, expectedFailures=0))
                            self.assertEqual(facts["compilerReceiptSha256"], hashlib.sha256((compiler / "compile-checks.json").read_bytes()).hexdigest())
                            self.assertEqual(facts["summaryAdmissionSha256"], hashlib.sha256((normal / "engineering-summary.command-admission.json").read_bytes()).hexdigest())
                            self.assertEqual(facts["testAdmissionSha256"], hashlib.sha256((normal / "engineering-test.runner-admission.json").read_bytes()).hexdigest())
                            self.assertEqual(facts["nativeSummarySha256"], hashlib.sha256(summary_body).hexdigest())
                            for key in ("sameOriginalNormalQuitObserved", "sourcePrePostMatched", "inputPrePostMatched",
                                        "inputOriginalClosesCompleted", "generatedRunnerOriginalClosesCompleted", "originalCommandsReturned", "originalWrapperZeroRequired"):
                                self.assertIs(facts[key], True)
                            self.assertIsNone(facts["cleanExitStatus"])
                            self.assertEqual(facts["allWorkerFinality"], "not-established")
                            self.assertFalse(facts["fullUIQualified"]); self.assertFalse(facts["productReady"])
                            self.assertEqual(stat.S_IMODE(result.stat().st_mode), 0o600)
                            # Published JSON alone is NOT the external wrapper's original return.
                            self.assertFalse((normal / "engineering-summary.status").exists())
                            with self.assertRaises(OSError): MODULE.exclusive_output(result, b"do not overwrite\n", 16384)
                            with self.assertRaises(MODULE.Refused): MODULE.exclusive_output(normal / "empty-receipt.json", b"", 16384)
                            with self.assertRaises(MODULE.Refused): MODULE.exclusive_output(normal / "empty-receipt.json", b"", 16384, allow_empty=1)
                            self.assertFalse((normal / "empty-receipt.json").exists())
                        else:
                            self.assertFalse(result.exists())
                        if fault in ("input-close", "receipt-close", "late-summary-close"):
                            self.assertEqual(len(close_failures), 1)
                        if fault in ("runtime-changed", "source-changed", "late-test", "input-close",
                                     "resources-missing", "resources-symlink", "resources-nonempty"):
                            self.assertFalse((normal / "engineering-test.runner-admission.json").exists())
                        if fault == "native-nonzero":
                            self.assertFalse(any(argv[:4] == ["/usr/bin/xcrun", "xcresulttool", "get", "test-results"] for argv, _ in owned))
                        if fault in ("resources-missing", "resources-symlink", "resources-nonempty"):
                            self.assertEqual(len(owned), before_test_calls)
                            products_type.assert_not_called()
                            products.admit.assert_not_called()
                            products.check.assert_not_called()
                            products_type.return_value.__exit__.assert_not_called()
                            self.assertFalse(any(argv[1:2] == ["test-without-building"] for argv, _ in owned))
                        else:
                            products.admit.assert_called_once()
                            self.assertEqual(products.check.call_count, 2 if fault != "late-test" else 1)
                            products_type.return_value.__exit__.assert_called_once()
                            self.assertEqual(sum(argv[1:2] == ["test-without-building"] for argv, _ in owned), 1)
                finally:
                    # Remove only this fixture's explicit symlink before the
                    # existing readonly-tree cleanup; never follow it for chmod.
                    resources_link = work / "Mobile Release Kit.app/Contents/Resources"
                    if resources_link.is_symlink():
                        resources_link.parent.chmod(0o700)
                        resources_link.unlink()
                    # Only this test's known temporary tree, including deliberate
                    # readonly fixture inputs, is made removable for its owner.
                    for directory in [base, *(p for p in base.rglob("*") if p.is_dir())]:
                        directory.chmod(0o700)

        # The fixed diagnostic destination also uses real private directory/file
        # originals. Its publication can never overwrite, retry, or imply success.
        with tempfile.TemporaryDirectory(prefix="mrk-engineering-diagnostic-data-") as temporary:
            work = Path(temporary); work.chmod(0o700)
            normal = work / "normal-ui"; normal.mkdir(mode=0o700)
            request = dict(engineering=True, phase="build", work=work, derived=normal / "DerivedData")
            failure = MODULE.normal_admission_failure("context", ValueError("PRIVATE-diagnostic-value"), None, [])
            expected = MODULE.encoded(failure) + b"\n"
            for mode in ("build", "test", "summary"):
                selected = dict(request, phase=mode)
                path = normal / ("engineering-" + mode + ".failure-diagnostics.json")
                MODULE.publish_engineering_failure(selected, failure)
                self.assertEqual(path.read_bytes(), expected)
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                self.assertNotIn(b"PRIVATE", path.read_bytes())
                with patch.object(MODULE.sys, "stderr", io.StringIO()) as errors:
                    MODULE.publish_engineering_failure(selected, dict(failure, stage="loader"))
                    self.assertEqual(errors.getvalue(), "engineering-failure-diagnostic-publication-failed\n")
                self.assertEqual(path.read_bytes(), expected)
                path.unlink()
            for invalid in (dict(request, engineering=False), dict(request, phase="../foreign"),
                            dict(request, derived=work / "foreign/DerivedData")):
                with patch.object(MODULE.sys, "stderr", io.StringIO()):
                    MODULE.publish_engineering_failure(invalid, failure)
                self.assertEqual(list(normal.iterdir()), [])
            for directory in (work, normal):
                directory.chmod(0o755)
                try:
                    with patch.object(MODULE.sys, "stderr", io.StringIO()):
                        MODULE.publish_engineering_failure(request, failure)
                    self.assertEqual(list(normal.iterdir()), [])
                finally:
                    directory.chmod(0o700)
            normal.rmdir()
            other = work / "foreign"; other.mkdir(mode=0o700)
            normal.symlink_to(other, target_is_directory=True)
            try:
                with patch.object(MODULE.sys, "stderr", io.StringIO()):
                    MODULE.publish_engineering_failure(request, failure)
                self.assertEqual(list(other.iterdir()), [])
            finally:
                normal.unlink(); normal.mkdir(mode=0o700)
            with patch.object(MODULE.sys, "stderr", io.StringIO()):
                MODULE.publish_engineering_failure(request, dict(failure, commands=["x" * 16384]))
            self.assertEqual(list(normal.iterdir()), [])
            actual_open, actual_close = os.open, os.close
            selected_fd, consumed = [None], []
            def diagnostic_open(path, flags, *args, **kwargs):
                fd = actual_open(path, flags, *args, **kwargs)
                if flags & os.O_CREAT: selected_fd[0] = fd
                return fd
            def diagnostic_close(fd):
                actual_close(fd)
                if fd == selected_fd[0]:
                    selected_fd[0] = None; consumed.append(fd)
                    raise OSError("PRIVATE-consuming-close")
            with patch.object(MODULE.os, "open", diagnostic_open), patch.object(MODULE.os, "close", diagnostic_close), \
                    patch.object(MODULE.sys, "stderr", io.StringIO()) as errors:
                MODULE.publish_engineering_failure(request, failure)
                self.assertEqual(errors.getvalue(), "engineering-failure-diagnostic-publication-failed\n")
            self.assertEqual(len(consumed), 1)
            self.assertEqual((normal / "engineering-build.failure-diagnostics.json").read_bytes(), expected)
            self.assertFalse((normal / "engineering-smoke.json").exists())

        # One additional fixture in this EXISTING real-FS group. The fake owner
        # returns only inert frames and makes named fixture renames below; no
        # producer, interpreter, signer, Xcode or application is executed here.
        # Actual core interruption remains the unchanged joined-child test/native prerequisite.
        fixture_data = (ROOT / MODULE.SAVED_VERSION_DATA).read_bytes()
        source_faults = {"profile-missing", "profile-bytes", "runtime-old-s", "runtime-count", "runtime-target", "runtime-qualification"}
        for fault in (None, "producer-zero", "original-unknown", "seed-facts", "source-bytes", "consuming-close",
                      "interrupt-named", "restored-facts", "profile-missing", "profile-bytes", "profile-post",
                      "runtime-old-s", "runtime-count", "runtime-target", "runtime-qualification"):
            with self.subTest(saved_version_custody=fault), tempfile.TemporaryDirectory(prefix="mrk-saved-version-handoff-data-") as temporary:
                base = Path(temporary)
                source_root, work, parent = (base / value for value in ("source", "work", "temporary"))
                for directory in (source_root, work, parent): directory.mkdir(mode=0o700)
                normal = work / "normal-ui"; normal.mkdir(mode=0o700)
                fixed = {"desktop/" + name for name in MODULE.SAVED_VERSION_BOOTSTRAPS}
                profile = "desktop/packaging/macos-history-provider.profile"
                fixed.update(("desktop/cpython-source-inputs/github-ca.pem", "desktop/tools/prepare_runtime.py",
                              profile, "src/mobile_release/__init__.py"))
                bodies = {name: b"inert admitted SOURCE, never imported or executed\n" for name in fixed | {MODULE.SAVED_VERSION_PRODUCER}}
                bodies[MODULE.SAVED_VERSION_DATA] = fixture_data
                rows, git_rows = [], []
                for name, body in sorted(bodies.items()):
                    path = source_root / name; path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                    path.write_bytes(body); path.chmod(0o600)
                    if name in fixed: rows.append(dict(path=name, size=len(body), sha256=hashlib.sha256(body).hexdigest()))
                    blob = hashlib.sha1(b"blob " + str(len(body)).encode() + b"\0" + body).hexdigest()
                    git_rows.append(b"100644 blob " + blob.encode() + b"\t" + name.encode() + b"\0")
                source_s = hashlib.sha256(MODULE.encoded(rows)).hexdigest()
                # Keep the admitted expected S fixed even for a coherent changed
                # profile+Git blob. A new Git row is not runtime-source authority.
                if fault == "profile-missing":
                    git_rows = [row for row in git_rows if not row.endswith(b"\t" + profile.encode() + b"\0")]
                elif fault == "profile-bytes":
                    changed = b"different inert profile, never imported or executed\n"
                    (source_root / profile).write_bytes(changed)
                    blob = hashlib.sha1(b"blob " + str(len(changed)).encode() + b"\0" + changed).hexdigest()
                    git_rows = [(b"100644 blob " + blob.encode() + b"\t" + profile.encode() + b"\0")
                                if row.endswith(b"\t" + profile.encode() + b"\0") else row for row in git_rows]
                runtime = dict(sourceInputsSha256=source_s, sourceInputCount=len(rows), target=MODULE.ARM_TARGET,
                               qualification="current-source-staged-no-native-execution", successorManifestSha256="b" * 64)
                if fault == "runtime-old-s": runtime["sourceInputsSha256"] = 'fa624512af03437f075f2da10357b3808d1a58c8f36e1db6103bc2abe54150e0'
                if fault == "runtime-count": runtime["sourceInputCount"] -= 1
                if fault == "runtime-target": runtime["target"] = MODULE.INTEL_TARGET
                if fault == "runtime-qualification": runtime["qualification"] = "native-qualified"
                (work / "runtime-result.json").write_bytes(json.dumps(runtime).encode())
                owned, envs = [], []
                fixture = None
                case = "-[MRKNormalAppUITests.NormalAppUITests testSyntheticProjectSavedVersionRecovery]"
                ui_stdout = ("\n".join(("Test Case '" + case + "' started.", MODULE.ORIGINAL_MARKER, MODULE.SAVED_VERSION_MARKER,
                                       "Test Case '" + case + "' passed (1.000 seconds).", ""))).encode()
                def owned_fake(argv, **kwargs):
                    owned.append(argv); envs.append(kwargs["environ"])
                    if argv[0] == "/usr/bin/git": return subprocess.CompletedProcess(argv, 0, b"".join(git_rows), b"")
                    if argv[0] == "/inert/python":
                        self.assertEqual(argv, ["/inert/python", "-I", "-S", "-B", str(source_root / MODULE.SAVED_VERSION_PRODUCER),
                                                "--restart-child", str(fixture.root / "project"), "release_version", "interrupt"])
                        self.assertEqual((kwargs["timeout"], kwargs["output_limit"]), (20, 65536))
                        self.assertNotIn(MODULE.SAVED_VERSION_ENV, kwargs["environ"])
                        if fault == "original-unknown": raise MODULE.Refused("synthetic unreturned original")
                        journal = fixture.root / MODULE.SAVED_VERSION_JOURNAL; journal.mkdir(mode=0o700)
                        controls = {"header.json": {"schemaVersion": 2, "domain": "release_version", "transactionId": "d" * 32},
                                    "plan.json": {"transactionId": "d" * 32, "files": [{"path": "release/version.properties"}]},
                                    "commit.pending": {}, "rollback.pending": {}}
                        for name, value in controls.items():
                            path = journal / name; path.write_bytes(json.dumps(value).encode()); path.chmod(0o600)
                        (journal / "new-0").write_bytes(fixture.after); (journal / "new-0").chmod(0o600)
                        os.rename(fixture.root / MODULE.SAVED_VERSION_PATH, journal / "old-0")
                        for directory in (journal, fixture.root / "project/release"):
                            fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
                            try: os.fsync(fd)
                            finally: os.close(fd)
                        if fault == "interrupt-named":
                            path = fixture.root / "project/README-user.txt"
                            replacement = path.with_name("replacement-fixture-only")
                            replacement.write_bytes(fixture.files["project/README-user.txt"]); replacement.chmod(0o600)
                            os.replace(replacement, path)  # Same bytes/mode, different named original.
                        frames = [dict(protocol="mrk-release-version/1", session="0123456789abcdef0123456789abcdef", seq=i,
                            kind=kind, result=dict(scopeResources="settled", **value)) for i, (kind, value) in enumerate((
                                ("opened", {"source": "release/version.properties", "values": {"name": "1.2.3", "build": "7"}}),
                                ("prepared", {"view": {"synthetic": True}})))]
                        return subprocess.CompletedProcess(argv, 0 if fault == "producer-zero" else 86,
                            b"".join(json.dumps(row).encode() + b"\n" for row in frames), b"")
                    self.assertEqual(argv, ["/inert/xcodebuild"])
                    self.assertEqual(kwargs["environ"][MODULE.SAVED_VERSION_ENV], str(fixture.handoff))
                    journal = fixture.root / MODULE.SAVED_VERSION_JOURNAL
                    os.rename(journal / "old-0", fixture.root / MODULE.SAVED_VERSION_PATH)
                    for path in journal.iterdir(): path.unlink()
                    journal.rmdir()
                    if fault == "restored-facts":
                        path = fixture.root / "project/README-user.txt"; previous = path.stat()
                        os.utime(path, ns=(previous.st_atime_ns, previous.st_mtime_ns + 1_000_000))
                    return subprocess.CompletedProcess(argv, 0, ui_stdout, b"")
                original_environment = {"PATH": "/inert", "HOME": "/inert"}
                phase = MODULE.NormalPhase(SimpleNamespace(run_owned=owned_fake), original_environment, source_root,
                                           MODULE.PhaseClock(585, now=lambda: 0))
                fake_sys = SimpleNamespace(flags=SimpleNamespace(isolated=1, no_site=1, dont_write_bytecode=1), executable="/inert/python")
                with patch.object(MODULE, "sys", fake_sys), patch.object(MODULE, "SAVED_VERSION_TEMPORARY", parent), \
                        patch.object(MODULE, "SAVED_VERSION_SOURCE", source_s):
                    fixture = MODULE.SavedVersionFixture(phase, "a" * 40, normal)
                    try:
                        if fault in source_faults:
                            reason = "saved-version-current-s" if fault.startswith("profile-") else "saved-version-runtime-source-binding"
                            with self.assertRaisesRegex(MODULE.Refused, "^" + reason + "$"):
                                fixture.interrupt(MODULE.ARM_TARGET)
                            self.assertIsNone(fixture.root)
                            self.assertFalse(fixture.handoff.exists())
                            self.assertEqual(len(owned), 1)
                            self.assertEqual([row["role"] for row in phase.records], ["saved-version-source-roster"])
                            self.assertIs(phase.environment, original_environment)
                            self.assertLessEqual(len(fixture.fds), 28)
                            continue
                        if fault in ("producer-zero", "original-unknown", "interrupt-named"):
                            with self.assertRaises(MODULE.Refused): fixture.interrupt(MODULE.ARM_TARGET)
                            self.assertFalse(fixture.handoff.exists())
                            self.assertEqual(len(owned), 2)
                            self.assertLessEqual(len(fixture.fds), 59)
                            continue
                        fixture.interrupt(MODULE.ARM_TARGET)
                        # Synthetic census:19SOURCE (13 bootstraps+profile)+7parents+
                        # 2runtime+1tmp+11fixture dirs+13public+6journal+2handoff=61;
                        # one restored version adds a retained original later.
                        # Local controls also budget stdio/transients separately.
                        self.assertEqual(len(fixture.fds), 61)
                        self.assertEqual(len(set(fixture.fds)), 61)
                        self.assertIn(profile, fixture.sources)
                        for path in fixture.originals.keys() - {MODULE.SAVED_VERSION_PATH}:
                            self.assertIs(fixture.seed[path], fixture.originals[path])
                        self.assertEqual([row["role"] for row in phase.records], ["saved-version-source-roster", "saved-version-core-interrupt"])
                        self.assertEqual(phase.records[1]["returncode"], 86)
                        self.assertEqual(stat.S_IMODE(fixture.handoff.stat().st_mode), 0o600)
                        self.assertLessEqual(fixture.handoff.stat().st_size, 16384)
                        handoff = json.loads(fixture.handoff.read_bytes())
                        self.assertEqual((len(handoff["files"]), len(fixture.originals)), (18, 13))
                        self.assertFalse((fixture.root / MODULE.SAVED_VERSION_PATH).exists())
                        self.assertEqual(fixture.files["project/.gitignore"], MODULE.saved_version_payload(fixture_data)[0]["project/.gitignore"])
                        fixture.check_seed()
                        if fault == "seed-facts":
                            path = fixture.root / "project/README-user.txt"; old = path.stat()
                            os.utime(path, ns=(old.st_atime_ns, old.st_mtime_ns + 1_000_000))
                        elif fault == "source-bytes":
                            (source_root / MODULE.SAVED_VERSION_PRODUCER).write_bytes(b"changed original source\n")
                        elif fault == "profile-post":
                            (source_root / profile).write_bytes(b"changed original history profile\n")
                        if fault in ("seed-facts", "source-bytes", "profile-post"):
                            with self.assertRaises(MODULE.Refused): fixture.ui_call("one-admitted-ui-test", ["/inert/xcodebuild"], 420)
                            self.assertEqual(len(owned), 2)
                            self.assertIs(phase.environment, original_environment)
                            continue
                        fixture.original = fixture.ui_call("one-admitted-ui-test", ["/inert/xcodebuild"], 420)
                        self.assertIs(phase.environment, original_environment)
                        if fault == "restored-facts":
                            with self.assertRaises(MODULE.Refused): fixture.restored()
                            self.assertNotIn("originalFixtureRestored", fixture.receipt)
                            self.assertLessEqual(len(fixture.fds), 62)
                            continue
                        result = fixture.restored()
                        self.assertEqual(len(fixture.fds), 62)
                        self.assertEqual(len(set(fixture.fds)), 62)
                        self.assertTrue(all(result[k] for k in ("originalFixtureRestored", "unrelatedOriginalsUnchanged", "readyJournalRemoved",
                                                               "sourcePrePostMatched", "uiOriginalMarkersObserved")))
                        self.assertFalse(result["interruptedGuiSaveObserved"])
                        self.assertEqual((fixture.root / MODULE.SAVED_VERSION_PATH).read_bytes(), fixture.files[MODULE.SAVED_VERSION_PATH])
                        self.assertFalse((fixture.root / MODULE.SAVED_VERSION_JOURNAL).exists())
                        if fault == "consuming-close":
                            close, first, closed = os.close, fixture.fds[-1], []
                            def consuming(fd):
                                close(fd); closed.append(fd)
                                if fd == first: raise OSError("synthetic consumed recovery original close")
                            owned_fds = set(fixture.fds)
                            with patch.object(MODULE.os, "close", consuming), self.assertRaises(OSError): fixture.close()
                            self.assertEqual(set(closed), owned_fds)
                            self.assertEqual(len(closed), len(owned_fds))
                    finally:
                        held = tuple(fixture.fds)
                        fixture.close()
                        self.assertLessEqual(len(held), 62)
                        self.assertEqual(fixture.fds, [])
                        for fd in held:
                            with self.assertRaises(OSError): os.fstat(fd)

    def test_closed_normal_failure_diagnostics_preserve_original_nonzero_and_privacy(self):
        # Genuine selected error records retain only finite lexical XCTest kinds.
        selected = "project-test.xcresult"
        site = (b"NormalAppUITests.swift:5009:7: error: "
            b"-[MRKNormalAppUITests.NormalAppUITests testSyntheticProjectPathFields] : ")
        private = b"PRIVATE-synthetic-path-and-typed-secret"
        cases = (
            (b"Failed to get matching snapshots: ", "matching-snapshot"),
            (b"Failed to get attributes for element ", "attribute-acquisition"),
            (b"Multiple matching elements found for ", "multiple-match"),
            (b"No matches found for ", "no-match"),
            (b"Timed out while evaluating UI query: ", "query-timeout"),
            (b"caught error: ", "caught-error"),
        )
        def classify(raw, phase="test", selection=selected):
            return MODULE.normal_failure_diagnostics(phase, selection,
                subprocess.CompletedProcess([], 65, raw, b""))
        old = classify(site + b"unknown " + private + b"\n")
        field = b"MRK_NORMAL_PROJECT_FIELD=v1;field=project;clamped=1;waiter=timed-out;matches=0;fields=1;relation=empty;nonAtomic=1\n"
        row = {"kind":"project-field", "stream":"stdout", "field":"project", "allowanceClamped":True,
            "waiter":"timed-out", "matches":0, "fields":1, "relation":"empty", "nonAtomic":True}
        self.assertEqual(classify(field)["queryObservations"], [row])
        for relation in (b'exact', b'empty', b'other', b'non-string', b'unavailable'):
            value = classify(private+b'\n'+field.replace(b'relation=empty',b'relation='+relation))
            self.assertEqual(value['queryObservations'][0]['relation'],relation.decode())
            self.assertEqual(value['originalReturncode'],65);self.assertNotIn(private,MODULE.encoded(value))
            self.assertLessEqual(len(MODULE.encoded(value))+1,4096)
        unavailable=field.replace(b'fields=1;relation=empty',b'fields=unavailable;relation=unavailable')
        self.assertIsNone(classify(unavailable)['queryObservations'][0]['fields'])
        for raw in (field+field,field[:-1],b'prefix '+field,field.replace(b'project;',b'private;'),
                field.replace(b'clamped=1',b'clamped=2'),field.replace(b'matches=0',b'matches=6'),
                field.replace(b'fields=1',b'fields=0'),field.replace(b'empty',private),b'x'*4096+field):
            value=classify(raw);self.assertEqual(value['queryObservations'],[])
            self.assertNotIn(private,MODULE.encoded(value))
        self.assertEqual(MODULE.normal_failure_diagnostics('test',selected,
            subprocess.CompletedProcess([],65,b'',field))['queryObservations'],[])
        for phase,selection in (('build',None),('test','test.xcresult'),('test','release-evidence-test.xcresult')):
            self.assertEqual(classify(field,phase,selection)['queryObservations'],[])
        for prefix, kind in cases:
            for path in (b"", b"/Users/runner/work/private source/"):
                value = classify(path + site + prefix + private + b"\r\n")
                self.assertEqual(value["xctestIssues"], [{"stream":"stdout",
                    "method":"testSyntheticProjectPathFields", "line":5009, "column":7, "kind":kind}])
                self.assertEqual(value["sourceFailures"], old["sourceFailures"])
                self.assertEqual(value["originalReturncode"], 65)
                self.assertNotIn(private, MODULE.encoded(value))
                self.assertNotIn(b"private source", MODULE.encoded(value))
                self.assertLessEqual(len(MODULE.encoded(value)) + 1, 4096)
        good = site + cases[0][0] + private + b"\n"
        for raw in (good[:-1], b"private: " + good, b"unknown "+good,
                good.replace(b"testSyntheticProjectPathFields", b"unselected"),
                good.replace(b":5009:7:", b":65536:7:"), good.replace(b":5009:7:", b":5009:4097:"),
                site + cases[0][0] + b"x" * 4096 + b"\n", site + b"unknown " + cases[0][0] + b"\n",
                good.replace(private, b"private\x00value"), site + b"Failed to get attributes for elementary text\n",
                site + b"Timed out while evaluating UI queryPrivate\n"):
            self.assertNotIn("xctestIssues", classify(raw))
        self.assertNotIn("xctestIssues", classify(good, phase="summary"))
        self.assertNotIn("xctestIssues", classify(good, selection="test.xcresult"))
        capped = classify(b"".join(good.replace(b":5009:7:", (":"+str(n)+":7:").encode()) for n in range(1,6)))
        self.assertEqual(len(capped["xctestIssues"]), 4); self.assertTrue(capped["findingsTruncated"])
        encode = MODULE.encoded
        with patch.object(MODULE, "encoded", side_effect=lambda v: b"x" * 4096 if "xctestIssues" in v else encode(v)):
            bounded = classify(good)
        self.assertNotIn("xctestIssues", bounded); self.assertTrue(bounded["findingsTruncated"])
        self.assertEqual(bounded["sourceFailures"], old["sourceFailures"])
        self.assertEqual(bounded["originalReturncode"], 65)

        # Direct clock/text-reader throws bypass require(), but their complete
        # fixed errors can still be explained without exporting arbitrary text.
        reasons = (
            (b"case clock unavailable", "case-clock-unavailable"),
            (b"case clock moved backwards or became unavailable", "case-clock-invalid"),
            (b"invalid bounded wait", "invalid-wait"),
            (b"original case or stage deadline elapsed", "wait-deadline"),
            (b"original case deadline elapsed", "case-deadline"),
            (b"original static text wait context missing", "static-text-context"),
            (b"static text selector count differs", "static-text-selectors"),
            (b"static text prefix collection exceeds its bound", "static-text-count"),
            (b"static text prefix role differs", "static-text-role"),
            (b"static text content exceeds its bound", "static-text-bytes"),
            (b"static text failure roster exceeds its bound", "static-text-failures"),
        )
        for method in (b"testSyntheticProjectPathFields", b"testSyntheticProjectLocalEditsAndImages"):
            for reason, code in reasons:
                for prefix in (b'caught error: ', b'failed: caught error: '):
                    for quote in (b'"', b'\\"'):
                        message = prefix + b'"condition(' + quote + reason + quote + b')"'
                        raw = site.replace(b"testSyntheticProjectPathFields", method) + message + b"\n"
                        value = classify(raw)
                        self.assertEqual(value["xctestIssues"][0]["condition"], code)
                        self.assertEqual(value["originalReturncode"], 65)
                        self.assertLessEqual(len(MODULE.encoded(value)) + 1, 4096)
        for message in (message + private, message.replace(reason, reason + private),
                message.replace(reason, private), b'caught error: prefix ' + message,
                message[:-1], message + b' ', message + b'\x00'):
            self.assertTrue(all("condition" not in row
                for row in classify(site + message + b"\n").get("xctestIssues", [])))
        exact = site + b'caught error: "condition(\\"original case or stage deadline elapsed\\")"\n'
        for raw, phase, selection in ((exact[:-1], "test", selected),
                (exact.replace(b"testSyntheticProjectPathFields", b"unselected"), "test", selected),
                (exact, "summary", selected), (exact, "test", "test.xcresult"),
                (exact[:-1] + b"x" * 4096 + b"\n", "test", selected)):
            self.assertTrue(all("condition" not in row
                for row in classify(raw, phase=phase, selection=selection).get("xctestIssues", [])))

        def navigation_marker(method='testSyntheticProjectPathFields',phase='after-typing',role='combo-child',
                relation='exact',unchanged='0',field='ready',fields='1',combos='1',go='ready',opened='disabled',cancel='ready'):
            return ('MRK_NORMAL_PROJECT_NAVIGATION=v1;method='+method+';phase='+phase+';role='+role+';relation='+relation
                +';unchanged='+unchanged+';field='+field+';fields='+fields+';combos='+combos+';go='+go
                +';open='+opened+';cancel='+cancel+';nonAtomic=1\n').encode()
        methods=('testSyntheticProjectPathFields','testSyntheticProjectLocalEditsAndImages')
        phases=('after-typing','after-return-timeout')
        markers=b''.join(navigation_marker(method,phase) for method in methods for phase in phases)
        parsed=MODULE.project_navigation_diagnostics(markers,b'')
        self.assertEqual(parsed['state'],'observed');self.assertEqual(len(parsed['observations']),4)
        self.assertEqual(set(parsed['observations'][0]),{'method','phase','role','relation','unchangedFromBefore','elementState','fields','combos','go','open','cancel','nonAtomic'})
        for relation in MODULE.PROJECT_NAVIGATION_RELATIONS:
            row=MODULE.project_navigation_diagnostics(navigation_marker(relation=relation),b'')['observations'][0]
            self.assertEqual(row['relation'],relation);self.assertIs(row['nonAtomic'],True)
        for role in ('standalone-field','combo-child','combo'):
            self.assertEqual(MODULE.project_navigation_diagnostics(navigation_marker(role=role,fields='2',combos='0'),b'')['observations'][0]['role'],role)
        for state in ('absent','ambiguous','disabled','obscured','ready'):
            self.assertEqual(MODULE.project_navigation_diagnostics(navigation_marker(go=state),b'')['observations'][0]['go'],state)
        self.assertEqual(MODULE.project_navigation_diagnostics(b'ordinary output\n',b''),{'state':'absent','observations':[]})
        one=navigation_marker()
        for bad in (one[:-1], b'prefix '+one, b'MRK_NORMAL_PROJECT_NAVIG', b'x'*513+one,
                navigation_marker(method='unselected'), navigation_marker(phase='later'), navigation_marker(role='other'),
                navigation_marker(relation='PRIVATE-synthetic-value'), navigation_marker(unchanged='true'),
                navigation_marker(relation='non-string',unchanged='1'),navigation_marker(field='ambiguous'),
                navigation_marker(fields='3'),navigation_marker(combos='-1'),navigation_marker(go='unknown'),
                navigation_marker(opened='unknown'),navigation_marker(cancel='unknown'),one.replace(b'nonAtomic=1',b'nonAtomic=0'),
                one.replace(b';role=',b';raw=private;role='),one.replace(b';role=',b';role=\x00'),one+one,markers+one):
            self.assertEqual(MODULE.project_navigation_diagnostics(bad,b''),{'state':'refused','observations':[]})
        self.assertEqual(MODULE.project_navigation_diagnostics(one,one)['state'],'refused')
        self.assertEqual(MODULE.project_navigation_diagnostics(one.replace(b'\n',b'\r\n'),b'')['state'],'observed')
        with self.assertRaises(MODULE.Refused): MODULE.project_navigation_diagnostics(b'x'*(1024*1024+1),b'')
        source_site=b'MRK_NORMAL_PROJECT_REQUIRE_FAILURE=v1;method=testSyntheticProjectPathFields;line=4240;check=condition\n'
        failed=subprocess.CompletedProcess([],65,markers+source_site,b'')
        observed=MODULE.normal_failure_diagnostics('test','project-test.xcresult',failed)
        self.assertEqual(observed['projectNavigation'],parsed)
        self.assertEqual(observed['sourceFailures'][0]['line'],4240);self.assertEqual(observed['originalReturncode'],65)
        self.assertLessEqual(len(MODULE.encoded(observed))+1,4096)
        malformed=MODULE.normal_failure_diagnostics('test','project-test.xcresult',subprocess.CompletedProcess([],65,source_site+one+one,b''))
        self.assertEqual(malformed['sourceFailures'],observed['sourceFailures'])
        self.assertEqual(malformed['projectNavigation'],{'state':'refused','observations':[]})
        self.assertTrue(malformed['findingsTruncated'])
        for phase,selection in (('test','test.xcresult'),('summary','project-test.xcresult'),('build',None)):
            self.assertNotIn('projectNavigation',MODULE.normal_failure_diagnostics(phase,selection,failed))
        encode_navigation=MODULE.encoded
        # Exercise both pressure exits without weakening the real serialized cap.
        for envelope_fits in (True,False):
            def navigation_pressure(value):
                nav=value.get('projectNavigation')
                return b'x'*4096 if nav is not None and (not envelope_fits or nav['state']=='observed') else encode_navigation(value)
            with patch.object(MODULE,'encoded',side_effect=navigation_pressure):
                bounded=MODULE.normal_failure_diagnostics('test','project-test.xcresult',failed)
            self.assertTrue(bounded['findingsTruncated'])
            self.assertEqual(bounded['sourceFailures'],observed['sourceFailures'])
            self.assertEqual(bounded['projectProgress'],observed['projectProgress'])
            self.assertEqual(bounded['originalReturncode'],65)
            self.assertLessEqual(len(encode_navigation(bounded))+1,4096)
            if envelope_fits:self.assertEqual(bounded['projectNavigation'],{'state':'refused','observations':[]})
            else:self.assertNotIn('projectNavigation',bounded)

        def marker(method,line=4725,check='condition',ending=b'\n'):
            return ('MRK_NORMAL_PROJECT_REQUIRE_FAILURE=v1;method='+method+';line='+str(line)+';check='+check).encode()+ending
        method_names=('testSyntheticProjectPathFields','testSyntheticProjectLocalEditsAndImages')
        first=marker(method_names[0]); second=marker(method_names[1],4975,'singleton',b'\r\n')
        sites=MODULE.project_require_source_sites(first+second,b'')
        self.assertEqual([r['method'] for r in sites],list(method_names))
        self.assertEqual([r['line'] for r in sites],[4725,4975])
        self.assertEqual(MODULE.project_require_source_sites(b'unrelated\n',b''),[])
        for bad in (first, first[:-1], marker('unselected'), marker(method_names[1],65536),
                marker(method_names[1],0),marker(method_names[1],1,'private-reason'),
                b'prefix '+second,b'MRK_NORMAL_PROJECT_REQUI',b'x'*193+second,
                second.replace(b';line=',b';line=0')):
            self.assertIsNone(MODULE.project_require_source_sites(first+bad,b''))
        self.assertIsNone(MODULE.project_require_source_sites(first,second))
        selected='project-test.xcresult'
        observed=MODULE.normal_failure_diagnostics('test',selected,subprocess.CompletedProcess([],65,first+second,b''))
        self.assertEqual(observed['sourceFailures'],sites)
        self.assertEqual(observed['status'],'classified')
        self.assertNotIn(b'MRK_NORMAL_PROJECT_REQUIRE_FAILURE',MODULE.encoded(observed))
        refused=MODULE.normal_failure_diagnostics('test',selected,subprocess.CompletedProcess([],65,first+first,b''))
        self.assertEqual(refused['sourceFailures'],[]);self.assertEqual(refused['status'],'unavailable')
        for phase,selected in (('test','test.xcresult'),('summary','project-test.xcresult')):
            other=MODULE.normal_failure_diagnostics(phase,selected,subprocess.CompletedProcess([],65,first,b''))
            self.assertEqual(other['sourceFailures'],[])

        # Saved evidence shares the literal marker grammar, never the project
        # method authorization. Both old forms keep their selected source site.
        saved_method='testSyntheticProjectSavedReleaseEvidence'
        saved=marker(saved_method,5310,'actionable')
        saved_wait=saved.replace(b'REQUIRE_FAILURE',b'STATIC_WAIT_FAILURE').replace(b';check=actionable',b'')
        for body in (saved,saved_wait):
            original=subprocess.CompletedProcess([],65,body+b'PRIVATE saved bytes or paths\n',b'')
            observed=MODULE.normal_failure_diagnostics('test','release-evidence-test.xcresult',original)
            self.assertEqual(observed['sourceFailures'],[dict(source='NormalAppUITests.swift',method=saved_method,
                line=5310,column=None,stream='stdout')])
            self.assertEqual(observed['originalReturncode'],65)
            self.assertNotIn(b'PRIVATE',MODULE.encoded(observed));self.assertLessEqual(len(MODULE.encoded(observed))+1,4096)
            self.assertIsNone(MODULE.project_require_source_sites(body,b''))
            for phase,selection in (('test','project-test.xcresult'),('summary','release-evidence-test.xcresult'),
                                    ('test','diagnostics-test.xcresult'),('test',MODULE.IOS_PENDING_RESULT)):
                self.assertEqual(MODULE.normal_failure_diagnostics(phase,selection,original)['sourceFailures'],[])
        for bad in (saved+saved,saved+saved_wait,saved+first,first,saved[:-1],b'prefix '+saved,
                    saved.replace(b'5310',b'65536'),saved.replace(b'actionable',b'PRIVATE')):
            self.assertIsNone(MODULE.project_require_source_sites(bad,b'',release_evidence=True))
        self.assertIsNone(MODULE.project_require_source_sites(b'',saved,release_evidence=True))
        with self.assertRaises(MODULE.Refused): MODULE.project_require_source_sites(saved,b'',release_evidence=1)
        with self.assertRaises(MODULE.Refused):
            MODULE.normal_failure_diagnostics('test','release-evidence-test.xcresult',subprocess.CompletedProcess([],0,saved,b''))
        saved_request=MODULE.normal_request(normal_arguments('release-evidence-test.xcresult'),
            '/Users/runner/work/_temp/mrk-macos-installed.ABCDef12/normal-ui/tmp/')
        saved_published=[]
        with patch.object(MODULE,'exclusive_output',side_effect=lambda path,body,cap:saved_published.append((path,body,cap))):
            MODULE.publish_failure_diagnostics(saved_request,subprocess.CompletedProcess([],65,saved_wait,b''))
        self.assertEqual(saved_published[0][0].name,'release-evidence-test.failure-diagnostics.json')
        self.assertEqual(json.loads(saved_published[0][1])['sourceFailures'][0]['line'],5310)
        self.assertEqual(saved_published[0][2],4096)

        # The two genuine project methods reuse stages; observations are not a
        # single case FSM, and an absent marker cannot prove work not attempted.
        def event(stage,result='started',ending=b'\n'):
            return ('MRK_NORMAL_PROJECT_STAGE='+stage+';result='+result+(';laterStages=not-run' if result=='failed' else '')).encode()+ending
        project_body=(event('launch')+event('launch','passed')+event('project-open')+event('project-open','failed')
            +event('launch')+event('launch','passed')+event('quit','passed',b'\r\n'))
        progress=dict(state='observed',firstFailed='project-open',lastObserved=dict(stage='quit',result='passed'))
        self.assertEqual(MODULE.project_stage_diagnostics(project_body,b''),progress)
        selection='project-test.xcresult'
        site=b'NormalAppUITests.swift:4935: error: -[MRKNormalAppUITests.NormalAppUITests testSyntheticProjectLocalEditsAndImages] : synthetic-private-reason\n'
        original=subprocess.CompletedProcess([],65,project_body+site,b'')
        value=MODULE.normal_failure_diagnostics('test',selection,original)
        self.assertEqual(value['projectProgress'],progress)
        self.assertEqual(value['sourceFailures'][0]['line'],4935)
        self.assertEqual(value['originalReturncode'],65)
        self.assertNotIn(b'synthetic-private-reason',MODULE.encoded(value))
        self.assertEqual(MODULE.project_stage_diagnostics(b'no stage\n',b''),dict(state='absent',firstFailed=None,lastObserved=None))
        self.assertEqual(MODULE.project_stage_diagnostics(event('launch')*128,b'')['state'],'observed')
        for raw in (event('unknown'),event('launch')[:-1],event('launch','failed').replace(b';laterStages=not-run',b''),
                event('launch').replace(b';result=started',b';result=started;laterStages=not-run'),
                b'prefix '+event('launch'),event('launch').replace(b'launch',b'x'*193),
                b'MRK_NORMAL_PROJECT_STA',event('launch')*129,event('launch').replace(b'launch',b'launch\x00')):
            refused=MODULE.project_stage_diagnostics(project_body+raw,b'')
            self.assertEqual(refused,dict(state='refused',firstFailed=None,lastObserved=None))
        self.assertEqual(MODULE.project_stage_diagnostics(project_body,event('launch'))['state'],'refused')
        self.assertIsNone(MODULE.failure_base('test',selection,original)['projectProgress'])
        for phase,other in (('test','test.xcresult'),('summary',selection),('build',None)):
            self.assertNotIn('projectProgress',MODULE.normal_failure_diagnostics(phase,other,original))
        # Added observation never displaces established fields or the 4096 cap.
        encode=MODULE.encoded
        def projected_size(item):
            body=encode(item)
            return b' '*4096 if item.get('projectProgress') is not None else body
        with patch.object(MODULE,'encoded',side_effect=projected_size):
            bounded=MODULE.normal_failure_diagnostics('test',selection,original)
        self.assertIsNone(bounded['projectProgress']);self.assertTrue(bounded['findingsTruncated'])
        request=MODULE.normal_request(normal_arguments(selection),'/Users/runner/work/_temp/mrk-macos-installed.ABCDef12/normal-ui/tmp/')
        published=[]
        with patch.object(MODULE,'exclusive_output',side_effect=lambda path,body,cap:published.append((path,body,cap))):
            MODULE.publish_failure_diagnostics(request,original)
        self.assertEqual(published[0][0].name,'project-test.failure-diagnostics.json')
        self.assertEqual(json.loads(published[0][1])['projectProgress'],progress)
        self.assertEqual(published[0][2],4096)
        # Both exact iOS originals use the same finite grammar and existing publisher.
        marker = b"MRK_MACOS_PACKAGED_REQUIRE_FAILURE=v1;line=3942;check=singleton\n"
        for selection, method, option in (
            (MODULE.IOS_UNSIGNED_RESULT, MODULE.IOS_UNSIGNED_METHOD, "--normal-ios-unsigned-archive-test"),
            (MODULE.IOS_PENDING_RESULT, MODULE.IOS_PENDING_METHOD, "--normal-ios-pending-recovery-test"),
        ):
            original = subprocess.CompletedProcess([], 65, marker + b"private synthetic text\n", b"")
            value = MODULE.normal_failure_diagnostics("test", selection, original)
            self.assertEqual(value["originalReturncode"], 65)
            self.assertEqual(value["requireObservations"], [{"source": "NormalAppUITests.swift", "line": 3942, "check": "singleton"}])
            self.assertIsNone(value["dashboardReadiness"])
            self.assertNotIn("private synthetic text", json.dumps(value))
            for stdout, stderr in ((marker * 2, b""), (marker, marker), (marker.rstrip(b"\n"), b""),
                    (marker.replace(b"3942", b"65536"), b""), (marker.replace(b"singleton", b"unknown"), b""),
                    (marker, marker.replace(b"singleton", b"unknown"))):
                rejected = MODULE.normal_failure_diagnostics("test", selection, subprocess.CompletedProcess([], 65, stdout, stderr))
                self.assertEqual(rejected["requireObservations"], [])
            request = MODULE.normal_request([option], "/Users/runner/work/_temp/mrk-macos-installed.ABCDef12/normal-ui/tmp/")
            written = []
            with patch.object(MODULE, "exclusive_output", side_effect=lambda path, body, cap: written.append((path, body, cap))):
                MODULE.publish_failure_diagnostics(request, original)
            self.assertEqual(len(written), 1)
            self.assertEqual(written[0][0].name, selection.removesuffix(".xcresult") + ".failure-diagnostics.json")
            self.assertEqual(json.loads(written[0][1])["requireObservations"], value["requireObservations"])
            self.assertEqual(written[0][2], 4096)
            for code in (0, True, -1, 256):
                with self.assertRaises(MODULE.Refused):
                    MODULE.failure_base("test", selection, subprocess.CompletedProcess([], code, b"", b""))
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
        # Applications now intentionally has this diagnostic; select an
        # actually unwired cohort rather than depending on dictionary order.
        other = "project-test.xcresult"
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

        engineering_selection = "engineering-test.xcresult"
        engineering_method = "testEngineeringMainCatalogueAndQuit"
        engineering_marker = b"MRK_MACOS_ENGINEERING_REQUIRE_FAILURE=v1;line=821;check=condition\n"
        engineering_case = "-[MRKNormalAppUITests.NormalAppUITests " + engineering_method + "]"
        engineering_body = (f"Test Case '{engineering_case}' started.\n"
            f"NormalAppUITests.swift:821:7: error: {engineering_case} : ".encode() + secret + b"\n" + engineering_marker +
            f"Test Case '{engineering_case}' failed (1.234 seconds).\n".encode())
        native_error = b"Error Domain=FBSOpenApplicationServiceErrorDomain Code=1 description=" + secret + b"\n** TEST EXECUTE FAILED **\n"
        engineering_original = subprocess.CompletedProcess(["fixed-original"], 65, engineering_body, native_error)
        observed = MODULE.normal_failure_diagnostics("test", engineering_selection, engineering_original, engineering=True)
        self.assertEqual(observed["scope"], "engineering-main-ui-failure-diagnostic-only")
        self.assertEqual(observed["selection"], engineering_selection)
        self.assertEqual(observed["originalReturncode"], 65)
        self.assertTrue(observed["markers"]["selectedCaseStarted"] and observed["markers"]["selectedCaseFailed"])
        self.assertEqual(observed["sourceFailures"], [{"stream": "stdout", "source": "NormalAppUITests.swift",
            "method": engineering_method, "line": 821, "column": 7}])
        self.assertEqual(observed["requireObservations"], [{"source": "NormalAppUITests.swift", "line": 821, "check": "condition"}])
        self.assertEqual(observed["errorCodes"], [{"stream": "stderr", "domain": "FBSOpenApplicationServiceErrorDomain", "code": 1}])
        self.assertEqual(observed["queryObservations"], [])
        self.assertIsNone(observed["dashboardReadiness"])
        self.assertNotIn(secret, MODULE.encoded(observed))
        framework_only = MODULE.normal_failure_diagnostics("test", engineering_selection,
            subprocess.CompletedProcess([], 65, b"", native_error), engineering=True)
        self.assertFalse(framework_only["markers"]["selectedCaseStarted"])
        self.assertFalse(framework_only["markers"]["selectedCaseFailed"])
        self.assertEqual(framework_only["requireObservations"], [])  # Unobserved is not proof of nonexecution.
        for line, check, end in ((1, "condition", b"\n"), (42, "singleton", b"\r\n"), (65535, "actionable", b"\n")):
            mark = f"MRK_MACOS_ENGINEERING_REQUIRE_FAILURE=v1;line={line};check={check}".encode() + end
            one = MODULE.normal_failure_diagnostics("test", engineering_selection,
                subprocess.CompletedProcess([], 65, mark, b""), engineering=True)
            self.assertEqual(one["requireObservations"], [{"source": "NormalAppUITests.swift", "line": line, "check": check}])
        invalid_engineering = (engineering_marker[:-1], engineering_marker.replace(b"821", b"0"),
            engineering_marker.replace(b"821", b"0821"), engineering_marker.replace(b"821", b"65536"),
            engineering_marker.replace(b"condition", secret), b"prefix " + engineering_marker,
            engineering_marker + engineering_marker, engineering_marker + engineering_marker[:-1],
            engineering_marker + b"MRK_MACOS_ENGINEERING_REQUIRE", engineering_marker.replace(b"v1", b"v2"),
            engineering_marker[:-1] + b";private=" + secret + b"\n")
        for raw in invalid_engineering:
            bad = MODULE.normal_failure_diagnostics("test", engineering_selection,
                subprocess.CompletedProcess([], 65, raw, b""), engineering=True)
            self.assertEqual(bad["requireObservations"], [])
            self.assertEqual(bad["status"], "unavailable")
            self.assertNotIn(secret, MODULE.encoded(bad))
        for stdout, stderr in ((b"", engineering_marker), (engineering_marker, engineering_marker)):
            bad = MODULE.normal_failure_diagnostics("test", engineering_selection,
                subprocess.CompletedProcess([], 65, stdout, stderr), engineering=True)
            self.assertEqual(bad["requireObservations"], [])
            self.assertEqual(bad["status"], "unavailable")
        foreign = MODULE.normal_failure_diagnostics("test", engineering_selection,
            subprocess.CompletedProcess([], 65, body + marker, b""), engineering=True)
        self.assertFalse(foreign["markers"]["selectedCaseStarted"])
        self.assertEqual(foreign["sourceFailures"], [])
        self.assertEqual(foreign["requireObservations"], [])
        self.assertEqual(foreign["queryObservations"], [])
        ordinary = MODULE.normal_failure_diagnostics("test", "test.xcresult",
            subprocess.CompletedProcess([], 65, engineering_body, b""))
        self.assertEqual(ordinary["requireObservations"], [])
        self.assertEqual(ordinary["sourceFailures"], [])
        self.assertFalse(ordinary["markers"]["selectedCaseStarted"])
        for phase, selection in (("build", None), ("query", None), ("summary", engineering_selection)):
            outside = MODULE.normal_failure_diagnostics(phase, selection,
                subprocess.CompletedProcess([], 65, engineering_marker, b""), engineering=True)
            self.assertEqual(outside["requireObservations"], [])
        for engineering, selection in ((False, engineering_selection), (True, "test.xcresult"),
                (True, "packaged-entry.xcresult"), (True, "foreign.xcresult"), (1, engineering_selection)):
            with self.subTest(engineering=engineering, selection=selection), self.assertRaises(MODULE.Refused):
                MODULE.normal_failure_diagnostics("test", selection, engineering_original, engineering=engineering)
        for code in (0, True):
            with self.assertRaises(MODULE.Refused):
                MODULE.normal_failure_diagnostics("test", engineering_selection,
                    subprocess.CompletedProcess([], code, b"", b""), engineering=True)
        with self.assertRaises(MODULE.Refused):
            MODULE.normal_failure_diagnostics("test", engineering_selection,
                subprocess.CompletedProcess([], 65, b"x" * (1048576 + 1), b""), engineering=True)

        # First failure is captured by the original CaseClock itself, including
        # teardown; phase is only the last ENTERED fixed step, never completion.
        first_phases = ("admission", "launch", "catalogue", "guideSelection", "artifactStatus", "artifactSample",
                        "artifactValue", "quitCancel", "postCancel", "quitConfirm", "termination", "terminal")
        first_marker = b"MRK_MACOS_ENGINEERING_FIRST_FAILURE=v1;line=103;phase=artifactValue\n"
        self.assertIsNone(observed["engineeringFirstFailure"])
        for index, first_phase in enumerate(first_phases):
            line = (1, 103, 65535)[index % 3]
            ending = b"\r\n" if index % 2 else b"\n"
            fixed = f"MRK_MACOS_ENGINEERING_FIRST_FAILURE=v1;line={line};phase={first_phase}".encode() + ending
            one_first = MODULE.normal_failure_diagnostics("test", engineering_selection,
                subprocess.CompletedProcess([], 65, fixed, b""), engineering=True)
            self.assertEqual(one_first["engineeringFirstFailure"], {"line": line, "phase": first_phase})
            self.assertEqual(one_first["status"], "classified")
            self.assertEqual(one_first["originalReturncode"], 65)
            self.assertEqual(one_first["requireObservations"], [])
        malformed_first = (first_marker[:-1], first_marker.replace(b"103", b"0"),
            first_marker.replace(b"103", b"0103"), first_marker.replace(b"103", b"+1"),
            first_marker.replace(b"103", b"-1"), first_marker.replace(b"103", b"65536"),
            first_marker.replace(b"v1", b"v2"), first_marker.replace(b"artifactValue", b"unknown"),
            first_marker.replace(b"artifactValue", secret), b"prefix " + first_marker,
            first_marker[:-1] + b";private=" + secret + b"\n", first_marker + first_marker,
            first_marker + first_marker.replace(b"103", b"104"), first_marker + first_marker[:-1],
            b"MRK_MACOS_ENGINEERING_FIRST_", b"tail MRK_MACOS_ENGINEERING_FIRST_",
            first_marker[:-1] + engineering_marker)
        for raw in malformed_first:
            for whole in (raw, first_marker + raw, raw + first_marker):
                first_bad = MODULE.normal_failure_diagnostics("test", engineering_selection,
                    subprocess.CompletedProcess([], 65, whole, native_error), engineering=True)
                self.assertIsNone(first_bad["engineeringFirstFailure"])
                self.assertEqual(first_bad["status"], "unavailable")
                self.assertEqual(first_bad["originalReturncode"], 65)
                self.assertEqual(first_bad["errorCodes"], observed["errorCodes"])
                self.assertNotIn(secret, MODULE.encoded(first_bad))
        for stdout, stderr in ((b"", first_marker), (first_marker, first_marker),
                               (first_marker, first_marker[:-1])):
            first_bad = MODULE.normal_failure_diagnostics("test", engineering_selection,
                subprocess.CompletedProcess([], 65, stdout, stderr), engineering=True)
            self.assertIsNone(first_bad["engineeringFirstFailure"])
            self.assertEqual(first_bad["status"], "unavailable")
        for phase, selection in (("build", None), ("query", None), ("summary", engineering_selection)):
            first_outside = MODULE.normal_failure_diagnostics(phase, selection,
                subprocess.CompletedProcess([], 65, first_marker, b""), engineering=True)
            self.assertNotIn("engineeringFirstFailure", first_outside)
            self.assertEqual(first_outside["status"], "unavailable")
        first_ordinary = MODULE.normal_failure_diagnostics("test", "test.xcresult",
            subprocess.CompletedProcess([], 65, query * 5 + first_marker, b""))
        for key in many:
            if key not in ("stdoutBytes", "stdoutSha256"):
                self.assertEqual(first_ordinary[key], many[key])
        self.assertNotIn("engineeringFirstFailure", first_ordinary)

        # Six finite samples describe the SAME fixed guide, not a selector or
        # atomic catalogue result. A prefix remains a prefix, never six zero rows.
        guide_tuples = tuple((prop, kind) for prop in ("label", "title") for kind in ("any", "button", "checkBox"))
        guide_rows = [(f"MRK_MACOS_ENGINEERING_GUIDE_QUERY=v1;property={prop};type={kind};matches={index};"
                       f"exceedsFour={int(index == 5)};nonAtomic=1").encode() + (b"\r\n" if index % 2 else b"\n")
                      for index, (prop, kind) in enumerate(guide_tuples)]
        guide_expected = [{"stream": "stdout", "kind": "guide", "property": prop, "elementType": kind,
                           "matches": index, "exceedsFour": index == 5, "nonAtomic": True}
                          for index, (prop, kind) in enumerate(guide_tuples)]
        for length in range(7):
            raw = b"".join(guide_rows[:length])
            partial = MODULE.normal_failure_diagnostics("test", engineering_selection,
                subprocess.CompletedProcess(["fixed-original"], 65, raw, b""), engineering=True)
            self.assertEqual(partial["queryObservations"], guide_expected[:length])
            self.assertEqual(partial["status"], "classified" if length else "unclassified")
            self.assertEqual(partial["requireObservations"], [])
            self.assertIsNone(partial["dashboardReadiness"])
            self.assertFalse(any(partial["markers"].values()))
            self.assertFalse(partial["findingsTruncated"])
            self.assertEqual(partial["originalReturncode"], 65)
        reverse = MODULE.normal_failure_diagnostics("test", engineering_selection,
            subprocess.CompletedProcess(["fixed-original"], 65, b"".join(reversed(guide_rows)), b""), engineering=True)
        self.assertEqual(reverse["queryObservations"], list(reversed(guide_expected)))

        guide_row = guide_rows[0]
        invalid_guides = (
            guide_row[:-1], guide_row.replace(b"v1", b"v2"), guide_row.replace(b"label", b"value"),
            guide_row.replace(b"type=any", b"type=window"), guide_row.replace(b"type=any", b"type=checkbox"),
            *(guide_row.replace(b"matches=0", b"matches=" + token) for token in (b"-1", b"01", b"+1", b"6", b"true")),
            guide_row.replace(b"exceedsFour=0", b"exceedsFour=1"),
            guide_rows[5].replace(b"exceedsFour=1", b"exceedsFour=0"),
            guide_row.replace(b"exceedsFour=0", b"exceedsFour=true"),
            guide_row.replace(b"nonAtomic=1", b"nonAtomic=0"),
            guide_row.replace(b"nonAtomic=1", b"nonAtomic=true"),
            b"prefix " + guide_row, b" " + guide_row, guide_row[:-1] + b" \n",
            guide_row[:-1] + b";private=" + secret + b"\n", guide_row.replace(b";type=", b"\n;type="),
            guide_row + guide_row, guide_row + guide_row.replace(b"matches=0", b"matches=2"),
            guide_row + guide_row[:-1], b"MRK_MACOS_ENGINEERING_GUIDE", b"MRK_MACOS_ENGINEERING_",
            b"noise\ntrailing MRK_MACOS_ENGINEERING_GUIDE_",
        )
        for raw in invalid_guides:
            for surrounding in (b"".join(guide_rows) + raw, raw + b"".join(guide_rows)):
                with self.subTest(guide_marker=raw[:100]):
                    rejected = MODULE.normal_failure_diagnostics("test", engineering_selection,
                        subprocess.CompletedProcess(["fixed-original"], 65, surrounding, native_error), engineering=True)
                    self.assertEqual(rejected["queryObservations"], [])  # No valid-neighbor salvage/deduplication.
                    self.assertEqual(rejected["status"], "unavailable")
                    self.assertEqual(rejected["errorCodes"], observed["errorCodes"])
                    self.assertFalse(rejected["findingsTruncated"])
                    self.assertEqual(rejected["originalReturncode"], 65)
                    self.assertNotIn(secret, MODULE.encoded(rejected))
        for stdout, stderr in ((b"", guide_row), (b"".join(guide_rows), guide_row),
                               (guide_row, guide_row[:-1]), (guide_row, b"MRK_MACOS_ENGINEERING_GUIDE")):
            rejected = MODULE.normal_failure_diagnostics("test", engineering_selection,
                subprocess.CompletedProcess(["fixed-original"], 65, stdout, stderr), engineering=True)
            self.assertEqual(rejected["queryObservations"], [])
            self.assertEqual(rejected["status"], "unavailable")
        for phase, selection in (("build", None), ("query", None), ("summary", engineering_selection)):
            outside = MODULE.normal_failure_diagnostics(phase, selection,
                subprocess.CompletedProcess(["fixed-original"], 65, guide_row, b""), engineering=True)
            self.assertEqual(outside["queryObservations"], [])
            self.assertEqual(outside["status"], "unavailable")
        # New engineering namespace cannot change ordinary four-row retention,
        # including its deliberate repeat preservation and truncation signal.
        ordinary_guides = MODULE.normal_failure_diagnostics("test", "test.xcresult",
            subprocess.CompletedProcess(["fixed-original"], 65, query * 5 + b"".join(guide_rows), b""))
        for key in many:
            if key not in ("stdoutBytes", "stdoutSha256"):
                self.assertEqual(ordinary_guides[key], many[key])

        # Fill every engineering category to its retained maximum, with longest
        # fixed public scalars, without borrowing the ordinary four-row budget.
        guide_maximum = b"".join((f"MRK_MACOS_ENGINEERING_GUIDE_QUERY=v1;property={prop};type={kind};"
                                 "matches=4;exceedsFour=0;nonAtomic=1\n").encode() for prop, kind in guide_tuples)
        codes_maximum = b"".join(f"Error Domain=FBSOpenApplicationServiceErrorDomain Code={-2147483648 + i}\n".encode()
                                 for i in range(8))
        sites_maximum = b"".join(f"NormalAppUITests.swift:{line}:4096: error: {engineering_case} : PRIVATE\n".encode()
                                 for line in range(65532, 65536))
        require_maximum = b"MRK_MACOS_ENGINEERING_REQUIRE_FAILURE=v1;line=65535;check=actionable\n"
        first_maximum = b"MRK_MACOS_ENGINEERING_FIRST_FAILURE=v1;line=65535;phase=guideSelection\n"
        maximum = MODULE.normal_failure_diagnostics("test", engineering_selection,
            subprocess.CompletedProcess(["fixed-original"], 65,
                guide_maximum + codes_maximum + sites_maximum + require_maximum + first_maximum, b""), engineering=True)
        self.assertEqual([len(maximum[key]) for key in ("errorCodes", "sourceFailures", "queryObservations", "requireObservations")],
                         [8, 4, 6, 1])
        self.assertEqual(maximum["queryObservations"], [dict(row, matches=4, exceedsFour=False) for row in guide_expected])
        self.assertEqual(maximum["requireObservations"], [{"source": "NormalAppUITests.swift", "line": 65535, "check": "actionable"}])
        self.assertEqual(maximum["engineeringFirstFailure"], {"line": 65535, "phase": "guideSelection"})
        self.assertEqual(maximum["status"], "classified")
        self.assertFalse(maximum["findingsTruncated"])
        self.assertLessEqual(len(MODULE.encoded(maximum)) + 1, 4096)
        self.assertNotIn(b"PRIVATE", MODULE.encoded(maximum))

        # Same failed original, closed nine-text roster, three properties only.
        # Zero means no exact match in this one sample; missing rows stay unknown.
        artifact_states = ("available", "runtime-unqualified", "busy", "shutdown", "cleanup-unknown",
                           "document-lost", "unsupported-platform", "waiting", "error")
        artifact_rows = [(f"MRK_MACOS_ENGINEERING_ARTIFACT_QUERY=v1;property={prop};type=staticText;"
                          "counts=0,1,2,3,4,5,0,1,2;sample=pre-wait;nonAtomic=1").encode()
                         + (b"\r\n" if index % 2 else b"\n")
                         for index, prop in enumerate(("label", "title", "value"))]
        artifact_expected = [{"stream": "stdout", "kind": "artifactAvailability", "property": prop,
            "elementType": "staticText", "counts": dict(zip(artifact_states, (0, 1, 2, 3, 4, 5, 0, 1, 2))),
            "sample": "pre-wait", "nonAtomic": True} for prop in ("label", "title", "value")]
        for length in range(4):
            partial = MODULE.normal_failure_diagnostics("test", engineering_selection,
                subprocess.CompletedProcess(["fixed-original"], 65, b"".join(artifact_rows[:length]), b""), engineering=True)
            self.assertEqual(partial["queryObservations"], artifact_expected[:length])
            self.assertEqual(partial["status"], "classified" if length else "unclassified")
            self.assertEqual(partial["originalReturncode"], 65)
            self.assertEqual(partial["requireObservations"], [])
            self.assertFalse(any(partial["markers"].values()))
            self.assertIsNone(partial["dashboardReadiness"])
        reversed_rows = MODULE.normal_failure_diagnostics("test", engineering_selection,
            subprocess.CompletedProcess([], 65, b"".join(reversed(artifact_rows)), b""), engineering=True)
        self.assertEqual(reversed_rows["queryObservations"], list(reversed(artifact_expected)))
        for artifact_count in range(6):
            row = artifact_rows[0].replace(b"0,1,2,3,4,5,0,1,2", b",".join([str(artifact_count).encode()] * 9))
            admitted = MODULE.normal_failure_diagnostics("test", engineering_selection,
                subprocess.CompletedProcess([], 65, row, b""), engineering=True)
            self.assertEqual(admitted["queryObservations"][0]["counts"], dict.fromkeys(artifact_states, artifact_count))
        artifact_row = artifact_rows[0]
        invalid_artifacts = (
            artifact_row[:-1], artifact_row.replace(b"v1", b"v2"), artifact_row.replace(b"label", b"identifier"),
            artifact_row.replace(b"staticText", b"any"), artifact_row.replace(b"staticText", b"staticTexts"),
            *(artifact_row.replace(b"0,1,2,3,4,5,0,1,2", token) for token in (
                b"", b"0,1,2,3,4,5,0,1", b"0,1,2,3,4,5,0,1,2,3", b"6,1,2,3,4,5,0,1,2",
                b"-1,1,2,3,4,5,0,1,2", b"01,1,2,3,4,5,0,1,2", b"+1,1,2,3,4,5,0,1,2",
                b"true,1,2,3,4,5,0,1,2", b"0, 1,2,3,4,5,0,1,2")),
            artifact_row.replace(b"pre-wait", b"after-wait"), artifact_row.replace(b"nonAtomic=1", b"nonAtomic=0"),
            b"prefix " + artifact_row, artifact_row[:-1] + b";private=" + secret + b"\n",
            artifact_row + artifact_row, artifact_row + artifact_row[:-1],
            b"MRK_MACOS_ENGINEERING_ARTIFACT", b"noise\ntrailing MRK_MACOS_ENGINEERING_ARTIFACT_",
        )
        for raw in invalid_artifacts:
            for supplied in (raw + b"".join(artifact_rows), b"".join(artifact_rows) + raw):
                rejected = MODULE.normal_failure_diagnostics("test", engineering_selection,
                    subprocess.CompletedProcess([], 65, guide_maximum + require_maximum + supplied, native_error), engineering=True)
                self.assertEqual(rejected["queryObservations"], maximum["queryObservations"])
                self.assertEqual(rejected["requireObservations"], maximum["requireObservations"])
                self.assertEqual(rejected["errorCodes"], observed["errorCodes"])
                self.assertEqual(rejected["status"], "unavailable")
                self.assertEqual(rejected["originalReturncode"], 65)
                self.assertNotIn(secret, MODULE.encoded(rejected))
        for stdout, stderr in ((b"", artifact_row), (artifact_row, artifact_row),
                               (artifact_row, artifact_row[:-1])):
            rejected = MODULE.normal_failure_diagnostics("test", engineering_selection,
                subprocess.CompletedProcess([], 65, stdout, stderr), engineering=True)
            self.assertEqual(rejected["queryObservations"], [])
            self.assertEqual(rejected["status"], "unavailable")
        for phase, selection in (("build", None), ("query", None), ("summary", engineering_selection)):
            rejected = MODULE.normal_failure_diagnostics(phase, selection,
                subprocess.CompletedProcess([], 65, artifact_row, b""), engineering=True)
            self.assertEqual(rejected["queryObservations"], [])
            self.assertEqual(rejected["status"], "unavailable")
        ordinary_artifacts = MODULE.normal_failure_diagnostics("test", "test.xcresult",
            subprocess.CompletedProcess([], 65, query * 5 + b"".join(artifact_rows), b""))
        for key in many:
            if key not in ("stdoutBytes", "stdoutSha256"):
                self.assertEqual(ordinary_artifacts[key], many[key])
        full = MODULE.normal_failure_diagnostics("test", engineering_selection,
            subprocess.CompletedProcess([], 65, guide_maximum + codes_maximum + sites_maximum + require_maximum
                                        + first_maximum + b"".join(artifact_rows), b""), engineering=True)
        for key in maximum:
            if key not in ("stdoutBytes", "stdoutSha256", "queryObservations"):
                self.assertEqual(full[key], maximum[key])
        self.assertEqual(full["queryObservations"], maximum["queryObservations"] + artifact_expected)
        self.assertLessEqual(len(MODULE.encoded(full)) + 1, 4096)
        self.assertFalse(full["findingsTruncated"])
        self.assertNotIn(b"PRIVATE", MODULE.encoded(full))

        engineering_work = Path("/Users/runner/work/_temp/mrk-macos-engineering-ui.ABCDef12")
        engineering_tmp = str(engineering_work / "normal-ui/tmp") + "/"
        request = MODULE.engineering_request(["--engineering-main-test", "--work", str(engineering_work)], engineering_tmp)
        owner = SimpleNamespace(ProcessError=OSError, ProcessInterrupted=InterruptedError)
        original_generic = MODULE.normal_admission_failure("diagnostic", MODULE.NativeQueryFailure(engineering_original), owner, [])
        enhanced = MODULE.engineering_native_failure(request, engineering_original, owner, [])
        self.assertEqual({key: value for key, value in enhanced.items() if key != "nativeDiagnostics"}, original_generic)
        self.assertEqual(enhanced["nativeDiagnostics"], observed)
        for fault in ("base", "format", "oversize"):
            with self.subTest(engineering_formatter=fault), ExitStack() as stack:
                if fault == "base": stack.enter_context(patch.object(MODULE, "failure_base", side_effect=ValueError(secret.decode())))
                elif fault == "format": stack.enter_context(patch.object(MODULE, "normal_failure_diagnostics", side_effect=ValueError(secret.decode())))
                else: stack.enter_context(patch.object(MODULE, "normal_failure_diagnostics", return_value={"private": "x" * 5000}))
                failed = MODULE.engineering_native_failure(request, engineering_original, owner, [])
                if fault == "base": self.assertEqual(failed, original_generic)
                else: self.assertEqual(failed["nativeDiagnostics"]["status"], "unavailable")
                self.assertNotIn(secret, MODULE.encoded(failed))
        # NativeQueryFailure can carry a verify-app result larger than the4KiB
        # diagnostic query cap. It remains the same original65, not main's1.
        large_query = subprocess.CompletedProcess(["fixed-original"], 65, b"x" * 4097, b"")
        large_generic = MODULE.normal_admission_failure("diagnostic", MODULE.NativeQueryFailure(large_query), owner, [])
        self.assertEqual(MODULE.engineering_native_failure(request, large_query, owner, [], query=True), large_generic)
        record = {"role": "one-admitted-ui-test", "argvSha256": "a" * 64, "returncode": 65,
            "stdoutBytes": len(engineering_body), "stdoutSha256": hashlib.sha256(engineering_body).hexdigest(),
            "stderrBytes": len(native_error), "stderrSha256": hashlib.sha256(native_error).hexdigest(),
            "timeoutSeconds": 180, "roleCapSeconds": 180, "outputLimitBytes": 1048576}
        outer_bound_exercised = False
        for count in range(1, 65):
            records = [record] * count
            generic = MODULE.normal_admission_failure("diagnostic", MODULE.NativeQueryFailure(engineering_original), owner, records)
            if len(MODULE.encoded(generic)) + 1 <= 16384 < len(MODULE.encoded({**generic, "nativeDiagnostics": observed})) + 1:
                self.assertEqual(MODULE.engineering_native_failure(request, engineering_original, owner, records), generic)
                outer_bound_exercised = True
                break
        self.assertTrue(outer_bound_exercised)

        # Real main and existing failure publisher; only original native command,
        # directory observations and exclusive write are inert DATA doubles.
        for fault in ("none", "query-over-cap", "formatter", "oversize", "publication"):
            with self.subTest(engineering_main_diagnostic=fault), ExitStack() as stack:
                native = large_query if fault == "query-over-cap" else engineering_original
                calls, published, closes = [], [], []
                output, errors = io.BytesIO(), io.BytesIO()
                stream = lambda buffer: SimpleNamespace(buffer=buffer, write=lambda value: buffer.write(value.encode()), flush=lambda: None)
                observed_dir = SimpleNamespace(st_dev=1, st_ino=2, st_mode=stat.S_IFDIR | 0o700,
                    st_uid=501, st_gid=20, st_nlink=2, st_size=0, st_mtime_ns=1, st_ctime_ns=1)
                fake_os = SimpleNamespace(environ={"TMPDIR": engineering_tmp}, getuid=lambda: 501, getgid=lambda: 20,
                    fstat=lambda _fd: observed_dir, stat=lambda *_a, **_k: observed_dir,
                    open=lambda *_a, **_k: 78, close=closes.append,
                    O_RDONLY=os.O_RDONLY, O_DIRECTORY=os.O_DIRECTORY, O_NOFOLLOW=os.O_NOFOLLOW, O_CLOEXEC=os.O_CLOEXEC)
                def native_call(*_args, **_kwargs):
                    calls.append(1)
                    return native
                fake_owner = SimpleNamespace(ProcessError=OSError, ProcessInterrupted=InterruptedError, run_owned=native_call)
                def execute(phase, _request, _source, _limits):
                    result = phase.call("one-admitted-ui-test", ["fixed-original"], 180)
                    if fault == "query-over-cap": raise MODULE.NativeQueryFailure(result)
                    return result
                def publish(path, data, cap):
                    published.append((path, data, cap))
                    if fault == "publication": raise OSError(secret.decode())
                for context in (
                    patch.object(MODULE.sys, "argv", ["helper", "--engineering-main-test", "--work", str(engineering_work)]),
                    patch.object(MODULE, "os", fake_os), patch.object(MODULE.time, "monotonic_ns", return_value=0),
                    patch.object(MODULE, "engineering_context", return_value=(Path("/inert"), "a" * 40, {}, (1024**3,) * 2)),
                    patch.object(MODULE, "load_normal_owner", return_value=fake_owner),
                    patch.object(MODULE, "execute_engineering_phase", side_effect=execute),
                    patch.object(MODULE, "execute_normal_phase", side_effect=AssertionError("ordinary route selected")),
                    patch.object(MODULE, "open_directory", return_value=77), patch.object(MODULE, "exclusive_output", side_effect=publish),
                    patch.object(MODULE.sys, "stdout", stream(output)), patch.object(MODULE.sys, "stderr", stream(errors)),
                ): stack.enter_context(context)
                if fault == "formatter": stack.enter_context(patch.object(MODULE, "normal_failure_diagnostics", side_effect=ValueError(secret.decode())))
                if fault == "oversize": stack.enter_context(patch.object(MODULE, "normal_failure_diagnostics", return_value={"private": "x" * 5000}))
                self.assertEqual(MODULE.main(), 65)
                self.assertEqual(calls, [1])
                self.assertEqual(closes, [78, 77])
                self.assertEqual(output.getvalue(), native.stdout)
                self.assertTrue(errors.getvalue().endswith(native.stderr))
                self.assertEqual(len(published), 1)
                self.assertEqual(published[0][0].name, "engineering-test.failure-diagnostics.json")
                self.assertEqual(published[0][2], 16384)
                self.assertLessEqual(len(published[0][1]), 16384)
                self.assertNotIn(secret, published[0][1])
                diagnostic = json.loads(published[0][1])
                self.assertEqual(diagnostic["commands"][0]["returncode"], 65)
                if fault == "query-over-cap": self.assertNotIn("nativeDiagnostics", diagnostic)
                else:
                    self.assertEqual(diagnostic["nativeDiagnostics"]["originalReturncode"], 65)
                    if fault in ("formatter", "oversize"):
                        self.assertEqual(diagnostic["nativeDiagnostics"]["status"], "unavailable")
                if fault == "publication": self.assertIn(b"engineering-failure-diagnostic-publication-failed\n", errors.getvalue())

        # Fixed Android DATA failure supplement: source literals only, never raw
        # XCTest/private paths. It cannot turn the original65 into a test pass.
        data_method = "testPositiveAndroidOutputCustodyData"
        data_case = "-[MRKNormalAppUITests.NormalAppUITests " + data_method + "]"
        data_namespace = b"MRK_MACOS_ANDROID_OUTPUT_DATA_FAILURE"
        data_scenarios = ('valid', 'late-close', 'extra-operation', 'work', 'journal', 'project-cache', 'extra-artifact', 'symlink', 'hardlink', 'depth', 'mode', 'input', 'wrong-result', 'identity', 'repeated-start',
            'ios-valid', 'ios-work', 'ios-extra-operation', 'ios-foreign-output', 'ios-symlink', 'ios-replacement', 'ios-partial-open', 'ios-late-close', 'ios-input')
        data_reasons = (
            (b'fixture: Android AAB byte bound', 'r001'),
            (b'fixture: Android AAB exact EOF', 'r002'),
            (b'fixture: Android AAB original read', 'r003'),
            (b'fixture: Android AAB read bound', 'r004'),
            (b'fixture: Android DATA adopted root is not the original', 'r005'),
            (b'fixture: Android DATA census accounting', 'r006'),
            (b'fixture: Android DATA cleanup original differs', 'r007'),
            (b'fixture: Android DATA cleanup root close', 'r008'),
            (b'fixture: Android DATA cleanup root replaced', 'r009'),
            (b'fixture: Android DATA cleanup row absent', 'r010'),
            (b'fixture: Android DATA closed deadline refusal', 'r011'),
            (b'fixture: Android DATA created root facts absent', 'r012'),
            (b'fixture: Android DATA exact entry limit', 'r013'),
            (b'fixture: Android DATA fixed original removal', 'r014'),
            (b'fixture: Android DATA hardlink setup', 'r015'),
            (b'fixture: Android DATA input parent missing', 'r016'),
            (b'fixture: Android DATA late close did not clear state and refuse', 'r017'),
            (b'fixture: Android DATA later close refusal', 'r018'),
            (b'fixture: Android DATA mode mutation', 'r019'),
            (b'fixture: Android DATA original parent replaced', 'r020'),
            (b'fixture: Android DATA original parent row absent', 'r021'),
            (b'fixture: Android DATA primary closure failure was masked or state retained', 'r022'),
            (b'fixture: Android DATA private root retirement', 'r023'),
            (b'fixture: Android DATA production close deleted output', 'r024'),
            (b'fixture: Android DATA scenario unmapped', 'r025'),
            (b'fixture: Android DATA symlink setup', 'r026'),
            (b'fixture: Android DATA temporary close', 'r027'),
            (b'fixture: Android DATA unopened cleanup root differs', 'r028'),
            (b'fixture: Android DATA unopened private root retirement', 'r029'),
            (b'fixture: Android XML original consuming close failed', 'r030'),
            (b'fixture: Android XML original content differs', 'r031'),
            (b'fixture: Android XML resource consuming close failed', 'r032'),
            (b'fixture: Android XML resource content or original changed', 'r033'),
            (b'fixture: Android XML resource open failed', 'r034'),
            (b'fixture: Android XML resource parent changed', 'r035'),
            (b'fixture: Android XML resource parent open failed', 'r036'),
            (b'fixture: Android XML resource parent shape or binding', 'r037'),
            (b'fixture: Android XML resource read failed', 'r038'),
            (b'fixture: Android XML resource read limit', 'r039'),
            (b'fixture: Android XML resource shape, binding or exact length', 'r040'),
            (b'fixture: Android captured AAB mode', 'r041'),
            (b'fixture: Android census enumeration conversion', 'r042'),
            (b'fixture: Android census enumeration failed', 'r043'),
            (b'fixture: Android census enumeration open', 'r044'),
            (b'fixture: Android census limit selection', 'r045'),
            (b'fixture: Android current build identity shape', 'r046'),
            (b'fixture: Android current terminal artifact differs', 'r047'),
            (b'fixture: Android earlier consuming close failed', 'r048'),
            (b'fixture: Android final output observation was not joined before close', 'r049'),
            (b'fixture: Android immutable input changed', 'r050'),
            (b'fixture: Android input consuming close failed', 'r051'),
            (b'fixture: Android input directory roster', 'r052'),
            (b'fixture: Android input parent absent', 'r053'),
            (b'fixture: Android input roster consuming close failed', 'r054'),
            (b'fixture: Android module output byte bound', 'r055'),
            (b'fixture: Android operation output roster', 'r056'),
            (b'fixture: Android original Start identity or state differs', 'r057'),
            (b'fixture: Android output DATA case deadline', 'r058'),
            (b'fixture: Android output DATA cleanup original', 'r059'),
            (b'fixture: Android output DATA cleanup parent', 'r060'),
            (b'fixture: Android output DATA create leaf', 'r061'),
            (b'fixture: Android output DATA creation consuming close', 'r062'),
            (b'fixture: Android output DATA exact refusal missing', 'r063'),
            (b'fixture: Android output DATA leaf write', 'r064'),
            (b'fixture: Android output DATA mkdir', 'r065'),
            (b'fixture: Android output DATA private root creation', 'r067'),
            (b'fixture: Android output DATA temporary consuming close', 'r068'),
            (b'fixture: Android output DATA temporary original', 'r069'),
            (b'fixture: Android output canonical duplicate', 'r070'),
            (b'fixture: Android output census name or entry bound', 'r071'),
            (b'fixture: Android output closure is not terminal', 'r072'),
            (b'fixture: Android output consuming close failed', 'r073'),
            (b'fixture: Android output depth bound', 'r074'),
            (b'fixture: Android output enumeration consuming close failed', 'r075'),
            (b'fixture: Android output existed before review', 'r076'),
            (b'fixture: Android output name encoding', 'r077'),
            (b'fixture: Android output name length', 'r078'),
            (b'fixture: Android output named binding unavailable', 'r079'),
            (b'fixture: Android output named directory changed', 'r080'),
            (b'fixture: Android output observation repeated or mixed with Save', 'r081'),
            (b'fixture: Android output original POST', 'r082'),
            (b'fixture: Android output original alias', 'r083'),
            (b'fixture: Android output original directory changed', 'r084'),
            (b'fixture: Android output original open', 'r085'),
            (b'fixture: Android output parent absent', 'r086'),
            (b'fixture: Android output regular leaf shape', 'r087'),
            (b'fixture: Android output root absent or type', 'r088'),
            (b'fixture: Android output roster changed', 'r089'),
            (b'fixture: Android output total byte bound', 'r090'),
            (b'fixture: Android output type owner mode or binding', 'r091'),
            (b'fixture: Android parsed terminal artifact shape', 'r092'),
            (b'fixture: Android positive input prerequisites absent', 'r093'),
            (b'fixture: Android private output directory mode', 'r094'),
            (b'fixture: Android private root output roster', 'r095'),
            (b'fixture: Android project AAB candidate roster', 'r096'),
            (b'fixture: Android report byte bound', 'r097'),
            (b'fixture: Android report output roster', 'r098'),
            (b'fixture: Android report parent roster', 'r099'),
            (b'fixture: Android required AAB observations absent', 'r100'),
            (b'fixture: Android retained artifact roster', 'r101'),
            (b'fixture: Android retained output changed', 'r102'),
            (b'fixture: Android root build output roster', 'r103'),
            (b'fixture: Android root census bound', 'r104'),
            (b'fixture: Android running original identity differs', 'r105'),
            (b'fixture: Android terminal original identity differs', 'r106'),
            (b'fixture: Android unexpected input-adjacent output', 'r107'),
            (b'fixture: Android unrecognized output directory', 'r108'),
            (b'fixture: Android unrecognized output leaf', 'r109'),
            (b'fixture: Android work or journal remains', 'r110'),
            (b'fixture: admitted Android XML pin differs', 'r111'),
            (b'fixture: an earlier consuming close failed', 'r112'),
            (b'fixture: directory binding changed', 'r113'),
            (b'fixture: directory entry changed', 'r114'),
            (b'fixture: directory open failed', 'r115'),
            (b'fixture: directory original changed', 'r116'),
            (b'fixture: fixed Android XML original was not admitted', 'r117'),
            (b'fixture: fixed Android XML resource absent or misplaced', 'r118'),
            (b'fixture: fixed leaf changed during observation', 'r119'),
            (b'fixture: fixed leaf open failed', 'r120'),
            (b'fixture: fixed leaf read failed', 'r121'),
            (b'fixture: fixed leaf read limit', 'r122'),
            (b'fixture: leaf shape/mode/limit', 'r123'),
            (b'fixture: missing fixed parent', 'r124'),
            (b'fixture: not an original directory', 'r125'),
            (b'fixture: original descriptor stat failed', 'r126'),
            (b'fixture: owned roster changed during enumeration', 'r127'),
            (b'fixture: owned roster conversion failed', 'r128'),
            (b'fixture: owned roster limit/duplicate', 'r129'),
            (b'fixture: owned roster open failed', 'r130'),
            (b'fixture: owned roster read failed', 'r131'),
            (b'fixture: Android output DATA private original root mode differs', 'r132'),
            (b'fixture: Android output DATA private original root uid differs', 'r133'),
            (b'fixture: Android output DATA private original root gid differs', 'r134'),
            (b'fixture: Android output DATA private original root flags differ', 'r135'),
            (b'fixture: Android output DATA private original root kind differs', 'r136'),
            (b'fixture: Android output DATA private original root descriptor differs', 'r137'),
            (b'fixture: Android output DATA private original root entry differs', 'r138'),
            (b'fixture: new private root initialization precondition', 'r139'),
            (b'fixture: new private root group initialization failed', 'r140'),
            (b'fixture: new private root initialization transition differs', 'r141'),
        )
        self.assertEqual(len(data_reasons), 140)
        self.assertEqual([code for _, code in data_reasons], [f"r{i:03d}" for i in range(1, 142) if i != 66])
        self.assertEqual(len({literal for literal, _ in data_reasons}), 140)

        def data_marker(scenario="valid", ending=b"\n"):
            return (b"MRK_MACOS_ANDROID_OUTPUT_DATA_FAILURE=v1;scenario=" + scenario.encode()
                + b";sample=after-cleanup-attempt;originalFailurePreserved=1" + ending)

        def data_error(literal, quote=b'"', ending=b"\n", line=1969, column=9):
            site = f"NormalAppUITests.swift:{line}" + (f":{column}" if column is not None else "")
            return (b"/Users/private/" + secret + b"/" + site.encode() + b": error: " + data_case.encode()
                + b" : private XCTest wrapper " + secret + b" condition(" + quote + literal + quote
                + b") private suffix " + secret + ending)

        def data_diagnostic(stdout, stderr=b""):
            return MODULE.normal_failure_diagnostics("test", MODULE.OUTPUT_DATA_RESULT,
                subprocess.CompletedProcess(["fixed-original"], 65, stdout, stderr))

        self.assertNotIn("outputDataFailure", value)
        self.assertIsNone(MODULE.failure_base("test", MODULE.OUTPUT_DATA_RESULT,
            subprocess.CompletedProcess([], 65, b"", b""))["outputDataFailure"])
        expected_code = "r063"  # Only the no-error path now yields exact-refusal-missing.
        known_literal = b"fixture: Android output DATA exact refusal missing"
        for ordinal, (literal, code) in enumerate(data_reasons):
            for quote, ending in ((b'"', b"\n"), (b'\\"', b"\r\n")):
                with self.subTest(output_data_code=code, escaped=(quote != b'"')):
                    scenario = data_scenarios[ordinal % len(data_scenarios)]
                    raw = data_marker(scenario, ending) + data_error(literal, quote, ending)
                    observed = data_diagnostic(raw)
                    self.assertEqual(observed["outputDataFailure"], {"scenario": scenario, "reasonCode": code,
                        "source": "NormalAppUITests.swift", "method": data_method, "line": 1969, "column": 9,
                        "sample": "after-cleanup-attempt"})
                    self.assertEqual(observed["sourceFailures"], [{"stream": "stdout", "source": "NormalAppUITests.swift",
                        "method": data_method, "line": 1969, "column": 9}])
                    self.assertEqual(observed["status"], "classified")
                    self.assertEqual(observed["originalReturncode"], 65)
                    self.assertEqual(observed["stdoutBytes"], len(raw))
                    self.assertEqual(observed["stdoutSha256"], hashlib.sha256(raw).hexdigest())
                    self.assertNotIn(secret, MODULE.encoded(observed))
                    self.assertNotIn(literal, MODULE.encoded(observed))
                    self.assertNotIn(b"/Users/private", MODULE.encoded(observed))
                    self.assertLessEqual(len(MODULE.encoded(observed)) + 1, 4096)
        data_good_marker, data_good_error = data_marker(), data_error(known_literal)
        marker_only = data_diagnostic(data_good_marker)["outputDataFailure"]
        self.assertEqual(marker_only, {"scenario": "valid", "reasonCode": None, "source": "NormalAppUITests.swift",
            "method": data_method, "line": None, "column": None, "sample": "after-cleanup-attempt"})
        reason_only = data_diagnostic(data_good_error)["outputDataFailure"]
        self.assertEqual(reason_only, dict(marker_only, scenario=None, reasonCode=expected_code, line=1969, column=9, sample=None))
        for unknown in (secret, b"fixture: named stat failed: PRIVATE", b"fixture: original close errors: PRIVATE",
                        known_literal + b" PRIVATE", b"fixture: not a fixed source literal"):
            observed = data_diagnostic(data_good_marker + data_error(unknown))
            self.assertEqual(observed["outputDataFailure"], dict(marker_only, line=1969, column=9))
            self.assertIsNone(data_diagnostic(data_error(unknown))["outputDataFailure"])
            self.assertNotIn(unknown, MODULE.encoded(observed))
        for line, column in ((1, None), (65535, 4096)):
            observed = data_diagnostic(data_good_marker + data_error(known_literal, line=line, column=column))
            self.assertEqual((observed["outputDataFailure"]["line"], observed["outputDataFailure"]["column"]), (line, column))
        bad_markers = (data_good_marker[:-1], data_good_marker.replace(b"v1", b"v2"),
            data_good_marker.replace(b"scenario=valid", b"scenario=PRIVATE"),
            data_good_marker.replace(b"after-cleanup-attempt", b"cleanup-complete"),
            data_good_marker.replace(b"Preserved=1", b"Preserved=0"),
            b"prefix " + data_good_marker, b" " + data_good_marker, data_good_marker[:-1] + b" \n",
            data_good_marker[:-1] + b";private=" + secret + b"\n",
            data_good_marker.replace(b";sample=", b"\n;sample="), data_namespace, data_namespace[:-3],
            b"trailing " + data_namespace[:-3], data_good_marker + data_good_marker,
            data_good_marker + data_marker("identity"), data_good_marker + data_good_marker[:-1])
        for raw in bad_markers:
            for stdout in (data_good_error + data_good_marker + raw, raw + data_good_marker + data_good_error):
                with self.subTest(output_data_bad_marker=raw[:80]):
                    observed = data_diagnostic(stdout)
                    self.assertIsNone(observed["outputDataFailure"])
                    self.assertEqual(observed["status"], "unavailable")
                    self.assertEqual(observed["originalReturncode"], 65)
                    self.assertNotIn(secret, MODULE.encoded(observed))
        malformed_errors = (data_good_error[:-1],
            data_error(known_literal, line=0), data_error(known_literal, line=65536),
            data_error(known_literal, line="01"), data_error(known_literal, column=4097),
            data_error(known_literal, column=0), data_error(known_literal, column="01"),
            data_good_error.replace(data_case.encode(), data_case[:-1].encode()),
            data_good_error.replace(b'condition("', b'condition(\\"', 1),
            data_good_error.replace(b'") private suffix', b'" private suffix'),
            data_error(b"x" * 129), data_error(b"fixture: private\x00token"),
            data_good_error[:-1] + b' condition("fixture: Android DATA mode mutation")\n',
            data_good_error + data_good_error, data_good_error + data_error(b"fixture: Android DATA mode mutation"),
            data_good_error + data_good_error[:-1],
            data_good_error.rstrip(b"\n") + b" " + data_good_error)
        for raw in malformed_errors:
            with self.subTest(output_data_bad_site=raw[:80]):
                observed = data_diagnostic(data_good_marker + raw)
                self.assertIsNone(observed["outputDataFailure"])
                self.assertEqual(observed["status"], "unavailable")
                self.assertEqual(observed["originalReturncode"], 65)
                self.assertNotIn(secret, MODULE.encoded(observed))
        for stdout, stderr in ((b"", data_good_marker + data_good_error), (data_good_marker, data_good_error),
                               (data_good_error, data_good_marker), (data_good_marker + data_good_error, data_good_marker),
                               (data_good_marker + data_good_error, data_good_error), (data_good_marker, data_namespace[:-2])):
            observed = data_diagnostic(stdout, stderr)
            self.assertIsNone(observed["outputDataFailure"])
            self.assertEqual(observed["status"], "unavailable")
        for phase, selection, engineering in (("build", None, False), ("query", None, False),
                ("summary", MODULE.OUTPUT_DATA_RESULT, False), ("test", "test.xcresult", False),
                ("test", "engineering-test.xcresult", True)):
            outside = MODULE.normal_failure_diagnostics(phase, selection,
                subprocess.CompletedProcess([], 65, data_good_marker + data_good_error, b""), engineering=engineering)
            self.assertNotIn("outputDataFailure", outside)
        wrong_method = data_good_error.replace(data_method.encode(), b"testLaunchCancelAndQuit")
        self.assertIsNone(data_diagnostic(wrong_method)["outputDataFailure"])
        self.assertEqual(data_diagnostic(data_good_marker + wrong_method)["outputDataFailure"], marker_only)
        capped = data_good_marker + data_good_error
        capped += b"x" * (1048576 - len(capped))
        self.assertEqual(data_diagnostic(capped)["outputDataFailure"]["reasonCode"], expected_code)
        with self.assertRaises(MODULE.Refused): data_diagnostic(capped + b"x")
        # Existing finite findings survive a refused supplement, never repaired
        # by a valid neighbor, a marker on stderr, or an incomplete tail.
        unrelated = data_diagnostic(data_good_error + data_good_marker + data_good_marker,
            b"Error Domain=NSPOSIXErrorDomain Code=2\n")
        self.assertEqual(len(unrelated["sourceFailures"]), 1)
        self.assertEqual(unrelated["errorCodes"], [{"stream": "stderr", "domain": "NSPOSIXErrorDomain", "code": 2}])
        self.assertIsNone(unrelated["outputDataFailure"])
        self.assertEqual(unrelated["status"], "unavailable")
        data_request = {"phase": "test", "result": Path("/inert/output-data-test.xcresult"),
            "derived": Path("/inert/DerivedData"), "outputData": True}
        data_original = subprocess.CompletedProcess(["fixed-original"], 65, data_good_marker + data_good_error, b"")
        for fault in ("none", "formatter", "oversize", "publication"):
            with self.subTest(output_data_publisher=fault), ExitStack() as stack:
                published = []
                def publish_data(path, raw, cap):
                    published.append((path, raw, cap))
                    if fault == "publication": raise OSError(secret.decode())
                stack.enter_context(patch.object(MODULE, "exclusive_output", side_effect=publish_data))
                stack.enter_context(patch.object(MODULE.sys, "stderr", io.StringIO()))
                if fault == "formatter": stack.enter_context(patch.object(MODULE, "normal_failure_diagnostics", side_effect=ValueError(secret.decode())))
                if fault == "oversize": stack.enter_context(patch.object(MODULE, "normal_failure_diagnostics", return_value={"private": "x" * 5000}))
                MODULE.publish_failure_diagnostics(data_request, data_original, role="one-admitted-ui-test")
                self.assertEqual(data_original.returncode, 65)
                self.assertEqual(len(published), 1)
                self.assertEqual(published[0][0].name, "output-data-test.failure-diagnostics.json")
                self.assertEqual(published[0][2], 4096)
                self.assertLessEqual(len(published[0][1]), 4096)
                self.assertNotIn(secret, published[0][1])
                diagnostic = json.loads(published[0][1])
                self.assertEqual(diagnostic["originalReturncode"], 65)
                self.assertEqual(diagnostic["originalCommandRole"], "one-admitted-ui-test")
                if fault in ("formatter", "oversize"):
                    self.assertEqual(diagnostic["status"], "unavailable")
                    self.assertIsNone(diagnostic["outputDataFailure"])
                else: self.assertEqual(diagnostic["outputDataFailure"]["reasonCode"], expected_code)


        # Standard Swift compiler diagnostics do not contain XCTest method text.
        # Exercise the actual parser/publisher, never another compiler/CLI owner.
        compiler_prefix = b"/Users/runner/work/mobile-release-kit/mobile-release-kit/desktop/native/macos-normal-ui/MRKNormalAppUITests/NormalAppUITests.swift"
        def compiler_line(message, *, line=321, column=17, severity=b"error", path=compiler_prefix, ending=b"\n"):
            return path + f":{line}:{column}: ".encode() + severity + b": " + message + ending
        def compiler_diagnostic(stdout, stderr=b"", **kwargs):
            return MODULE.normal_failure_diagnostics("build", None,
                subprocess.CompletedProcess(["fixed-build"], 65, stdout, stderr), **kwargs)
        compile_error = compiler_line(b"cannot convert value of type '" + secret + b"' to expected argument type 'Int'")
        compile_note = compiler_line(b"PRIVATE unexpected note " + secret, line=322, severity=b"note",
            path=b"NormalAppUITests.swift", ending=b"\r\n")
        observed = compiler_diagnostic(compile_error, compile_note + b"** BUILD FAILED **\n")
        self.assertEqual(observed["compilerDiagnostics"], [
            {"stream": "stdout", "source": "NormalAppUITests.swift", "line": 321, "column": 17,
             "severity": "error", "reasonCodes": ["type-mismatch"]},
            {"stream": "stderr", "source": "NormalAppUITests.swift", "line": 322, "column": 17,
             "severity": "note", "reasonCodes": []}])
        self.assertTrue(observed["markers"]["buildFailed"])
        self.assertEqual(observed["status"], "classified")
        self.assertEqual(observed["sourceFailures"], [])
        self.assertEqual(observed["originalReturncode"], 65)
        self.assertEqual(observed["stdoutSha256"], hashlib.sha256(compile_error).hexdigest())
        for hidden in (secret, b"/Users/runner", b"unexpected note", b"expected argument type"):
            self.assertNotIn(hidden, MODULE.encoded(observed))
        for message, code in ((b"value has no member 'PRIVATE'", "missing-member"),
                (b"cannot find 'PRIVATE' in scope", "missing-name"),
                (b"'PRIVATE' is inaccessible due to 'private' protection level", "inaccessible"),
                (b"missing argument for parameter 'PRIVATE' in call", "missing-argument"),
                (b"extra argument 'PRIVATE' in call", "extra-argument"),
                (b"generic parameter 'PRIVATE' could not be inferred", "inference"),
                (b"ambiguous use of 'PRIVATE'", "ambiguous-overload"),
                (b"variable 'PRIVATE' used before being initialized", "initialization"),
                (b"call can throw but is not marked with 'try'", "throwing"),
                (b"call to main actor-isolated method 'PRIVATE'", "actor-isolation"),
                (b"capture of 'PRIVATE' with non-sendable type", "sendability"),
                (b"expected expression after 'PRIVATE'", "syntax"),
                (b"invalid redeclaration of 'PRIVATE'", "redeclaration")):
            with self.subTest(compiler_category=code):
                item = compiler_diagnostic(compiler_line(message))["compilerDiagnostics"][0]
                self.assertIn(code, item["reasonCodes"])
                self.assertNotIn(b"PRIVATE", MODULE.encoded(item))
        unknown = compiler_diagnostic(compiler_line(secret))
        self.assertEqual(unknown["compilerDiagnostics"][0]["reasonCodes"], [])
        self.assertEqual(unknown["status"], "classified")  # A usable public SOURCE site, not a cause claim.
        for raw in (compile_error[:-1], compiler_line(b"x" * 4096),
                compiler_line(secret, line=0), compiler_line(secret, line=65536), compiler_line(secret, line="01"),
                compiler_line(secret, column=0), compiler_line(secret, column=4097), compiler_line(secret, column="01"),
                compiler_line(secret, severity=b"warning"), compiler_line(secret, path=b"Private.swift"),
                compiler_line(secret, path=b"/Users/private/NormalAppUITests.swift"),
                compiler_line(secret, path=compiler_prefix + b".bak"),
                b"prefix " + compile_error, compiler_line(secret + b"\x00suffix")):
            with self.subTest(compiler_bad_site=raw[:80]):
                item = compiler_diagnostic(raw)
                self.assertEqual(item["compilerDiagnostics"], [])
                self.assertNotIn(secret, MODULE.encoded(item))
        self.assertTrue(compiler_diagnostic(compile_error[:-1])["findingsTruncated"])
        self.assertTrue(compiler_diagnostic(compiler_line(b"x" * 4096))["findingsTruncated"])
        for path in (b"NormalAppUITests.swift", compiler_prefix,
                b"desktop/native/macos-normal-ui/MRKNormalAppUITests/NormalAppUITests.swift"):
            item = compiler_diagnostic(compiler_line(b"unknown", line=65535, column=4096, path=path))
            self.assertEqual((item["compilerDiagnostics"][0]["line"], item["compilerDiagnostics"][0]["column"]), (65535, 4096))
        crowded = b"".join(compiler_line(b"unknown", line=n, severity=b"note") for n in range(1, 9)) + compile_error
        item = compiler_diagnostic(crowded, b"Error Domain=NSPOSIXErrorDomain Code=2\n")
        self.assertEqual(len(item["compilerDiagnostics"]), 4)
        self.assertEqual(item["compilerDiagnostics"][0]["severity"], "error")
        self.assertTrue(item["findingsTruncated"])
        self.assertEqual(item["errorCodes"], [{"stream": "stderr", "domain": "NSPOSIXErrorDomain", "code": 2}])
        self.assertLessEqual(len(MODULE.encoded(item)) + 1, 4096)
        # Stress optional-row trimming without weakening the existing final cap.
        actual_base = MODULE.failure_base
        def nearly_full_base(*args, **kwargs):
            value = actual_base(*args, **kwargs)
            value["legacyPadding"] = "x" * (3900 - len(MODULE.encoded(value)))
            return value
        with patch.object(MODULE, "failure_base", side_effect=nearly_full_base):
            item = compiler_diagnostic(crowded)
        self.assertTrue(item["findingsTruncated"])
        self.assertLess(len(item["compilerDiagnostics"]), 4)
        self.assertEqual(item["compilerDiagnostics"][0], observed["compilerDiagnostics"][0])
        self.assertIn("legacyPadding", item)
        self.assertLessEqual(len(MODULE.encoded(item)) + 1, 4096)
        exact = compile_error + b"x" * (1048576 - len(compile_error))
        self.assertEqual(len(compiler_diagnostic(exact)["compilerDiagnostics"]), 1)
        with self.assertRaises(MODULE.Refused): compiler_diagnostic(exact + b"x")
        for phase, selection, engineering in (("query", None, False), ("summary", "test.xcresult", False),
                ("test", "test.xcresult", False), ("build", None, True)):
            value = MODULE.normal_failure_diagnostics(phase, selection,
                subprocess.CompletedProcess([], 65, compile_error, b""), engineering=engineering)
            self.assertNotIn("compilerDiagnostics", value)
            self.assertNotIn("buildFailed", value["markers"])
        build_request = {"phase": "build", "result": None, "derived": Path("/inert/DerivedData")}
        build_original = subprocess.CompletedProcess(["fixed-build"], 65, compile_error, b"")
        for fault in ("none", "formatter", "publication"):
            with self.subTest(compiler_publication=fault), ExitStack() as stack:
                captured = []
                def publish_build(path, raw, cap):
                    captured.append((path, raw, cap))
                    if fault == "publication": raise OSError(secret.decode())
                stack.enter_context(patch.object(MODULE, "exclusive_output", side_effect=publish_build))
                stack.enter_context(patch.object(MODULE.sys, "stderr", io.StringIO()))
                if fault == "formatter": stack.enter_context(patch.object(MODULE, "normal_failure_diagnostics", side_effect=ValueError(secret.decode())))
                MODULE.publish_failure_diagnostics(build_request, build_original)
                self.assertEqual(build_original.returncode, 65)
                self.assertEqual(len(captured), 1)
                self.assertEqual((captured[0][0].name, captured[0][2]), ("build.failure-diagnostics.json", 4096))
                self.assertLessEqual(len(captured[0][1]), 4096)
                self.assertNotIn(secret, captured[0][1])
                self.assertEqual(json.loads(captured[0][1])["originalReturncode"], 65)

    def test_android_private_condition_is_exact_bounded_and_preserves_native_failure(self):
        method = MODULE.ANDROID_CANDIDATE_METHOD
        selection = MODULE.ANDROID_CANDIDATE_RESULT
        unavailable = {"status": "unavailable", "condition": None}
        swift = SWIFT.read_text()
        private = b"PRIVATE password keystrokes /private/account credential-value\n"
        stage = b"MRK_NORMAL_PROJECT_STAGE=android-private-admission;result=failed;laterStages=not-run\n"
        def record(reason, escaped=False):
            quote = b'\\"' if escaped else b'"'
            return (b"NormalAppUITests.swift:4630: error: -[MRKNormalAppUITests.NormalAppUITests "
                    + method.encode() + b'] : threw error condition(' + quote + reason + quote + b')\n')
        def observe(body, stderr=b"", selected=selection, mode="test", code=65):
            return MODULE.normal_failure_diagnostics(mode, selected,
                subprocess.CompletedProcess(["fixed-original"], code, body, stderr))
        for reason, label in MODULE.ANDROID_CANDIDATE_CONDITIONS.items():
            text = reason.decode()
            self.assertTrue('"' + text + '"' in swift or text.startswith("fixture: ")
                            and '"' + text.removeprefix("fixture: ") + '"' in swift)
            for escaped in (False, True):
                result = observe(stage + record(reason, escaped) + private)
                self.assertEqual(result["androidCandidateCondition"], {"status": "classified", "condition": label})
                self.assertEqual(result["androidCandidateProgress"]["firstFailed"], "android-private-admission")
                self.assertEqual(result["originalReturncode"], 65)
                self.assertLessEqual(len(MODULE.encoded(result)) + 1, 4096)
                self.assertNotIn("credential-value", MODULE.encoded(result).decode())
        good = record(b"fixture: Android private owned directory")
        for bad in (good + good, good + record(b"PRIVATE unknown"), good.rstrip(b"\n"),
                    good.replace(method.encode(), method.encode() + b"Other"),
                    good.replace(b": error:", b": note:"), good.replace(b":4630:", b":65536:"),
                    good.replace(b"NormalAppUITests.swift:", b"Foreign.swift:"),
                    good.replace(b"condition(", b"condition(condition("),
                    b"x" * 4096 + good, record(b"fixture: Android private object shape differs"),
                    record(b"Android private owned directory"), record(b"PRIVATE" * 50)):
            self.assertEqual(observe(bad)["androidCandidateCondition"], unavailable)
        self.assertEqual(observe(b"", good)["androidCandidateCondition"],
                         {"status": "classified", "condition": "android-private-owned-directory"})
        self.assertNotIn("androidCandidateCondition", observe(good, selected="test.xcresult"))
        self.assertNotIn("androidCandidateCondition", observe(good, mode="summary"))
        with self.assertRaises(MODULE.Refused): observe(b"x" * (1024 * 1024 + 1))
        with self.assertRaises(MODULE.Refused): observe(good, code=0)
        # Same existing direct native65 publication, no candidate-helper import/owner.
        published = []
        request = dict(phase="test", result=Path("/case") / selection, derived=Path("/case/DerivedData"))
        original = subprocess.CompletedProcess(["fixed-original"], 65, stage + good + private, b"")
        def publish(path, body, limit, **kw):
            published.append((path, body, limit))
        with patch.object(MODULE, "exclusive_output", side_effect=publish):
            MODULE.publish_failure_diagnostics(request, original)
        self.assertEqual(original.returncode, 65)
        self.assertEqual(len(published), 1)
        self.assertEqual(published[0][0].name, "android-candidate-inputs-test.failure-diagnostics.json")
        data = json.loads(published[0][1]); self.assertEqual(data["originalReturncode"], 65)
        self.assertEqual(data["androidCandidateCondition"]["condition"], "android-private-owned-directory")
        self.assertNotIn(b"PRIVATE", published[0][1])

    def test_android_candidate_failure_diagnostics_keep_private_text_out(self):
        selection = "android-candidate-inputs-test.xcresult"
        method = "testSyntheticProjectAndroidCandidateInputs"
        case = "-[MRKNormalAppUITests.NormalAppUITests " + method + "]"
        private = b"PRIVATE-keystore-password-and-project-path"
        stages = ("android-private-admission", "android-public-project-and-certificate", "android-saved-input-read",
            "android-separate-installed-service-setup", "android-source-inspection-without-license-acceptance",
            "android-fresh-reviewed-protected-copy", "android-new-protected-copy-full-readback",
            "android-memory-input-assignment", "android-one-signed-build-original", "android-known-native-terminal",
            "candidate-original-history-review-and-abandon", "android-output-census-and-normal-quit")
        def event(stage, result="started"):
            return ("MRK_NORMAL_PROJECT_STAGE=" + stage + ";result=" + result
                    + (";laterStages=not-run" if result == "failed" else "") + "\n").encode()
        site = ("/private/not-published/NormalAppUITests.swift:765:9: error: " + case + " : ").encode() + private + b"\n"
        body = ("Test Case '" + case + "' started.\n").encode() + b'Type "' + private + b'"\n'
        body += event(stages[0]) + event(stages[0], "passed") + event(stages[5]) + event(stages[5], "failed") + site
        body += ("Test Case '" + case + "' failed (1.000 seconds).\n").encode()
        stderr = b'Error Domain=NSPOSIXErrorDomain Code=13 "' + private + b'"\n'
        def observe(stdout=body, errors=stderr, selected=selection, phase="test"):
            return MODULE.normal_failure_diagnostics(phase, selected, subprocess.CompletedProcess([], 65, stdout, errors))
        value = observe()
        self.assertEqual(value["sourceFailures"], [{"stream": "stdout", "source": "NormalAppUITests.swift",
            "method": method, "line": 765, "column": 9}])
        self.assertEqual(value["errorCodes"][0]["domain"], "NSPOSIXErrorDomain")
        self.assertEqual(value["androidCandidateProgress"], {"state": "observed", "firstFailed": stages[5],
            "lastObserved": {"stage": stages[5], "result": "failed"}})
        self.assertTrue(value["markers"]["selectedCaseStarted"] and value["markers"]["selectedCaseFailed"])
        self.assertEqual(value["requireObservations"], [])  # This Swift method does not emit that namespace.
        self.assertNotIn(private, MODULE.encoded(value)); self.assertNotIn(b"/private/", MODULE.encoded(value))
        self.assertLessEqual(len(MODULE.encoded(value)) + 1, 4096)
        for stage in stages:
            self.assertEqual(observe(event(stage), b"")["androidCandidateProgress"]["lastObserved"]["stage"], stage)
        for bad in (event("unselected-private"), event("launch"), event(stages[0])[:-1], b"prefix " + event(stages[0]),
                    event(stages[0]).replace(b";result=", b";private=value;result="), event(stages[0]) * 129):
            self.assertEqual(observe(bad, b"")["androidCandidateProgress"]["state"], "refused")
        self.assertEqual(observe(b"", event(stages[0]))["androidCandidateProgress"]["state"], "refused")
        self.assertEqual(MODULE.project_stage_diagnostics(event("launch"), b"")["lastObserved"]["stage"], "launch")
        self.assertEqual(MODULE.project_stage_diagnostics(event(stages[0]), b"")["state"], "refused")
        self.assertEqual(observe(body.replace(method.encode(), b"testApplicationsLaunchAndQuit"))["sourceFailures"], [])
        self.assertNotIn("androidCandidateProgress", observe(selected="test.xcresult"))
        self.assertNotIn("androidCandidateProgress", observe(phase="summary"))
        with self.assertRaises(MODULE.Refused): observe(selected="unselected.xcresult")
        with self.assertRaises(MODULE.Refused): observe(stdout=b"x" * (1024 * 1024 + 1), errors=b"")
        with self.assertRaises(MODULE.Refused): MODULE.project_stage_diagnostics(b"", b"", android_candidate=1)

    def test_android_candidate_native_failure_publication_preserves_first_status(self):
        work = Path("/Users/runner/work/_temp/mrk-macos-installed.ABCDef12")
        private = b"PRIVATE-password-original-output"
        body = b"MRK_NORMAL_PROJECT_STAGE=android-private-admission;result=failed;laterStages=not-run\n" + private + b"\n"
        for target in (MODULE.ARM_TARGET, MODULE.INTEL_TARGET):
            for fault in ("none", "post-native", "admission", "formatter", "oversize", "publication", "original-bound", "zero"):
                with self.subTest(target=target, fault=fault), ExitStack() as stack:
                    output, errors, published, calls = io.BytesIO(), io.BytesIO(), [], []
                    original = subprocess.CompletedProcess(["fixed-native"], 0 if fault == "zero" else 65,
                        b"x" * (1024 * 1024 + 1) if fault == "original-bound" else body, b"")
                    def native(*_a, **_kw):
                        calls.append(1); return original
                    owner = SimpleNamespace(ProcessError=OSError, ProcessInterrupted=InterruptedError, run_owned=native)
                    def execute(phase, *_args):
                        if fault == "admission": raise MODULE.Refused(private.decode())
                        # Original-bound simulates the already returned oversized
                        # original; real owner rejection remains independently tested.
                        if fault == "original-bound": return original
                        value = phase.call("one-admitted-ui-test", ["fixed-native"], 1020)
                        if fault == "post-native": raise MODULE.Refused(private.decode())
                        return value
                    def publish(path, data, cap):
                        if fault == "publication" and path.name.endswith(".failure-diagnostics.json"):
                            raise OSError(private.decode())
                        published.append((path, data, cap))
                    def stream(buffer):
                        return SimpleNamespace(buffer=buffer, write=lambda value: buffer.write(value.encode()), flush=lambda: None)
                    for patcher in (
                        patch.object(MODULE.sys, "argv", ["helper", "--target", target, "--normal-android-candidate-inputs-test"]),
                        patch.dict(MODULE.os.environ, {"TMPDIR": str(work / "normal-ui/tmp") + "/"}),
                        patch.object(MODULE.time, "monotonic_ns", return_value=0),
                        patch.object(MODULE, "normal_context", return_value=(Path("/inert"), "a" * 40, {}, (1024**3,) * 2)),
                        patch.object(MODULE, "load_normal_owner", return_value=owner),
                        patch.object(MODULE, "execute_normal_phase", side_effect=execute),
                        patch.object(MODULE, "exclusive_output", side_effect=publish),
                        patch.object(MODULE.sys, "stdout", stream(output)), patch.object(MODULE.sys, "stderr", stream(errors))):
                        stack.enter_context(patcher)
                    if fault == "formatter": stack.enter_context(patch.object(MODULE, "normal_failure_diagnostics", side_effect=ValueError(private.decode())))
                    if fault == "oversize": stack.enter_context(patch.object(MODULE, "normal_failure_diagnostics", return_value={"private": "x" * 5000}))
                    self.assertEqual(MODULE.main(), 0 if fault == "zero" else 1 if fault == "admission" else 65)
                    self.assertEqual(calls, [] if fault in ("admission", "original-bound") else [1])
                    rows = {path.name: json.loads(data) for path, data, _ in published}
                    if fault == "zero": self.assertEqual(rows, {}); continue
                    self.assertEqual(rows["android-candidate-inputs.failure.json"]["originalStatus"], 1 if fault == "admission" else 65)
                    if fault in ("publication", "original-bound"):
                        self.assertNotIn("android-candidate-inputs-test.failure-diagnostics.json", rows)
                    else:
                        diagnostic = rows["android-candidate-inputs-test.failure-diagnostics.json"]
                        if fault != "admission":
                            self.assertEqual(diagnostic["originalReturncode"], 65)
                            self.assertEqual(diagnostic["status"], "unavailable" if fault in ("formatter", "oversize") else "unclassified")
                    for path, data, cap in published:
                        self.assertNotIn(private, data); self.assertLessEqual(len(data), cap)
                    if fault not in ("post-native", "admission"):
                        self.assertEqual(output.getvalue(), original.stdout)  # PRIVATE workflow capture, not artifact.

    def test_dashboard_failure_diagnostics_preserve_finite_prewait_data(self):
        reasons = (
            "loading", "not-loaded", "bridge-unavailable", "selection-unavailable",
            "selection-in-progress", "shutting-down", "owner-offline-preflight",
            "owner-android-build", "owner-ios-archive", "owner-project-recovery",
            "owner-github-preflight", "owner-github-release", "owner-project-path",
            "owner-saved-version-edit", "owner-metadata-images", "other-or-unobserved", "ambiguous",
            "owner-local-history", "owner-store-readback", "owner-store-execution",
            "owner-store-preparation", "owner-store-access",
        )
        waiters = ("timed-out", "incorrect-order", "inverted-fulfillment", "interrupted", "unknown")
        self.assertEqual(len(set(reasons)), 22)
        selections = ("test.xcresult", "applications-test.xcresult", MODULE.IOS_PENDING_RESULT)
        for index, reason in enumerate(reasons):
            ordinal, line = index % 4 + 1, 1 if index % 2 == 0 else 65535
            waiter, enabled, hittable = waiters[index % 5], bool(index % 2), bool(index // 2 % 2)
            ending = b"\n" if index % 2 == 0 else b"\r\n"
            require = f"MRK_MACOS_PACKAGED_REQUIRE_FAILURE=v1;line={line};check=condition".encode()
            row = (f"MRK_MACOS_PACKAGED_DASHBOARD_FAILURE=v1;line={line};ordinal={ordinal};waiter={waiter}"
                   f";enabled={int(enabled)};hittable={int(hittable)};reason={reason};sample=pre-wait;nonAtomic=1").encode()
            for selection in selections:
                with self.subTest(selection=selection, reason=reason, ordinal=ordinal, waiter=waiter):
                    value = MODULE.normal_failure_diagnostics("test", selection,
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
                *(("test", name) for name in MODULE.NORMAL_SELECTIONS if name not in selections),
                ("test", MODULE.IOS_UNSIGNED_RESULT)):
            with self.subTest(phase=phase, selection=selection):
                value = MODULE.normal_failure_diagnostics(phase, selection,
                    subprocess.CompletedProcess([], 65, require + row, b""))
                self.assertIsNone(value["dashboardReadiness"])
                self.assertEqual(value["requireObservations"],
                    [{"source": "NormalAppUITests.swift", "line": 65535, "check": "condition"}]
                    if phase == "test" and selection == MODULE.IOS_UNSIGNED_RESULT else [])
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

        swift = SWIFT.read_text()
        apps = swift.split("func testApplicationsLaunchAndQuit() throws {", 1)[1].split("\n    }", 1)[0]
        self.assertIn("packagedRequireDiagnosticActive = true", apps)
        self.assertIn("defer { packagedRequireDiagnosticActive = false }", apps)
        for ordinal in (1, 2):
            self.assertIn(f"try dashboard(renderer, diagnosticOrdinal: {ordinal})", apps)
        pending = swift.split("func testInstalledIOSPendingAccountRecoveryThroughUI() throws {", 1)[1].split("\n    @MainActor", 1)[0]
        self.assertIn("try launchForJourney(profile: profile, diagnosticOrdinal: 1)", pending)
        self.assertIn("diagnosticOrdinal: UInt8? = nil) throws ->", swift)
        self.assertIn("try dashboard(renderer, diagnosticOrdinal: diagnosticOrdinal)", swift)

    def test_dashboard_failure_diagnostics_reject_ambiguous_or_malformed_data(self):
        require = b"MRK_MACOS_PACKAGED_REQUIRE_FAILURE=v1;line=508;check=condition\n"
        row = (b"MRK_MACOS_PACKAGED_DASHBOARD_FAILURE=v1;line=508;ordinal=1;waiter=timed-out;"
               b"enabled=0;hittable=0;reason=loading;sample=pre-wait;nonAtomic=1\n")
        site = {"source": "NormalAppUITests.swift", "line": 508, "check": "condition"}
        for stdout, stderr, expected in (
                (row, b"", []), (require, b"", [site]), (require, row, [site]), (row, require, []),
                (require.replace(b"line=508", b"line=509") + row, b"", [dict(site, line=509)]),
                (require.replace(b"condition", b"singleton") + row, b"", [dict(site, check="singleton")]),
                (require + require + row, b"", []), (require + row, require, []),
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


@contextmanager
def pending_account_module():
    """Real passive SOURCE module; no app, account or native invocation."""
    name = "_mrk_normal_pending_regression_aqua"
    if name in sys.modules:
        raise AssertionError("pending regression module binding already exists")
    spec = importlib.util.spec_from_file_location(name, ROOT / MODULE.LOADER)
    loader = importlib.util.module_from_spec(spec)
    with patch.dict(sys.modules, {name: loader, MODULE.LOADER_MODULE: loader}):
        spec.loader.exec_module(loader)
        yield loader


def pending_account_data(loader, binding, uid, gid):
    home = "/Users/runner"
    identity = lambda inode: [7, inode, stat.S_IFDIR | 0o700, uid, gid]
    private = dict(home=home, homeIdentity=identity(1), leaseIdentity=identity(2), sessionIdentity=identity(3),
        nativeIdentity=identity(4), token="e" * 32,
        baseline=dict(default=home + "/Library/Keychains/login.keychain-db", search=[home + "/Library/Keychains/login.keychain-db"]),
        members=[dict(path=home + "/Library/Keychains/login.keychain-db", identity=[7, 5, stat.S_IFREG | 0o600, uid, gid, 1])],
        controls={name: dict(bytes=2, sha256=loader.digest(b"{}")) for name in ("intent.json", "state.json")},
        native={"signing.keychain-db": dict(device=7, inode=6)})
    common = dict(schemaVersion=1, case=loader.IOS_ACCOUNT_CASE, profileCalls=0, commandFinalities=True,
        leaseClosed=True, sessionClosed=True, handlersRestored=True, fixtureDescriptorsClosed=True,
        originalDeadlineMet=True, keychainContentsRead=False)
    producer = dict(common, scope="real-core-pending-account-fixture-v1", commands=17, pendingLeft=True, private=private)
    observer = dict(common, scope="real-core-account-baseline-readback-v1", commands=2, pendingAbsent=True,
        baselinePreferencesMatched=True, baselineMemberIdentitiesMatched=True)
    marker = dict(schemaVersion=1, sourceCommit=binding.source, target=binding.target, runId=binding.run,
        runAttempt=binding.attempt, fixtureSha256=loader.digest(str(binding.root() / loader.IOS_ACCOUNT_CASE).encode()),
        sessionSha256=loader.digest(private["token"].encode()), inspectUnchecked=True, recoverUnchecked=True, ordinaryQuit=True,
        inspect=dict(operationId="1" * 32, ownerGeneration="2" * 32, phase="terminal", outcome="complete", reason="none", accountStatus="pending"),
        recover=dict(operationId="3" * 32, ownerGeneration="4" * 32, phase="terminal", outcome="complete", reason="none", accountStatus="recovered"))
    case = b"-[MRKNormalAppUITests.NormalAppUITests " + MODULE.IOS_PENDING_METHOD.encode() + b"]"
    output = b"\n".join((b"Test Case '" + case + b"' started.", MODULE.ORIGINAL_MARKER.encode(),
        MODULE.IOS_PENDING_PREFIX + MODULE.encoded(marker), b"Test Case '" + case + b"' passed (1.0 seconds).")) + b"\n"
    return private, producer, observer, marker, output


class NormalIOSPendingRecoveryDataTests(unittest.TestCase):
    def test_pending_recovery_stage_and_source_diagnostics_remain_private(self):
        method = MODULE.IOS_PENDING_METHOD
        selection = MODULE.IOS_PENDING_RESULT
        stage = b"MRK_NORMAL_PROJECT_STAGE=ios-recovery-inspect;result=failed;laterStages=not-run\n"
        site = ("MRK_NORMAL_PROJECT_REQUIRE_FAILURE=v1;method=" + method + ";line=8100;check=singleton\n").encode()
        private = b"PRIVATE credential value and selected account path\n"
        def observe(stdout, stderr=b"", selected=selection, phase="test"):
            return MODULE.normal_failure_diagnostics(phase, selected, subprocess.CompletedProcess([], 65, stdout, stderr))
        value = observe(stage + site + private)
        self.assertEqual(value["iosPendingProgress"]["firstFailed"], "ios-recovery-inspect")
        self.assertEqual(value["sourceFailures"][0]["method"], method)
        self.assertEqual(value["sourceFailures"][0]["line"], 8100)
        self.assertEqual(value["originalReturncode"], 65)
        self.assertNotIn(b"PRIVATE", MODULE.encoded(value))
        self.assertLessEqual(len(MODULE.encoded(value)) + 1, 4096)
        wait = site.replace(b"REQUIRE_FAILURE", b"STATIC_WAIT_FAILURE").replace(b";check=singleton", b"")
        self.assertEqual(observe(stage + wait)["sourceFailures"], value["sourceFailures"])
        for bad in (site + site, site[:-1], b"prefix " + site, site.replace(b"8100", b"65536"), site.replace(method.encode(), b"unselected")):
            self.assertIsNone(MODULE.project_require_source_sites(bad, b"", ios_pending=True))
        self.assertIsNone(MODULE.project_require_source_sites(b"", site, ios_pending=True))
        for options in ({"ios_pending": 1}, {"ios_pending": True, "saved_version": True}, {"ios_pending": True, "release_evidence": True}):
            with self.assertRaises(MODULE.Refused): MODULE.project_require_source_sites(site, b"", **options)
        for selected, phase in (("project-test.xcresult", "test"), ("release-evidence-test.xcresult", "test"), (selection, "summary")):
            other = observe(stage + site, selected=selected, phase=phase)
            self.assertNotIn("iosPendingProgress", other)
            self.assertEqual(other["sourceFailures"], [])
        foreign = stage.replace(b"ios-recovery-inspect", b"saved-version-inspect-close")
        self.assertEqual(observe(foreign)["iosPendingProgress"]["state"], "refused")
        caught = ("NormalAppUITests.swift:8140: error: -[MRKNormalAppUITests.NormalAppUITests " + method
            + '] : caught error: "condition(\\"original case or stage deadline elapsed\\")"\n').encode()
        self.assertEqual(observe(caught)["xctestIssues"][0]["condition"], "wait-deadline")
        self.assertNotIn("condition", observe(caught.replace(b"original case or stage deadline elapsed", b"PRIVATE"))["xctestIssues"][0])

    def test_pending_consumer_context_and_summary_keep_separate_sources(self):
        import resource, pwd
        helper = MODULE.SAVED_VERSION_CANDIDATE_ROOT / '.candidate-consumer-helper'
        normal = Path('/Users/runner/work/_temp/mrk-macos-installed.abcdefgh/normal-ui')
        env = dict(PATH='/usr/bin:/bin:/usr/sbin:/sbin', HOME='/Users/runner', USER='runner', LOGNAME='runner',
            TMPDIR=str(normal/'tmp')+'/', LANG='en_US.UTF-8', LC_ALL='en_US.UTF-8', TZ='UTC', DEVELOPER_DIR=MODULE.DEVELOPER,
            TEST_RUNNER_MRK_NORMAL_UI_APPLICATION_SOURCE='a'*40, TEST_RUNNER_MRK_NORMAL_UI_HARNESS_SOURCE='b'*40,
            TEST_RUNNER_MRK_NORMAL_UI_HOSTED_JOB='github-hosted-macos26-arm64',
            GITHUB_REPOSITORY='Apdelrahman1911/mobile-release-kit', GITHUB_EVENT_NAME='push',
            GITHUB_REF=MODULE.ANDROID_CONSUMER_REF, GITHUB_SHA='b'*40, GITHUB_WORKFLOW_SHA='b'*40,
            GITHUB_WORKFLOW_REF='Apdelrahman1911/mobile-release-kit/'+MODULE.ANDROID_CONSUMER_WORKFLOW+'@'+MODULE.ANDROID_CONSUMER_REF,
            GITHUB_WORKSPACE=str(MODULE.SAVED_VERSION_CANDIDATE_ROOT), GITHUB_RUN_ID='42', GITHUB_RUN_ATTEMPT='1',
            RUNNER_ENVIRONMENT='github-hosted', RUNNER_OS='macOS', RUNNER_ARCH='ARM64')
        env[MODULE.IOS_PENDING_CURRENT_ENV] = MODULE.IOS_PENDING_CURRENT_SCOPE
        with ExitStack() as stack:
            stack.enter_context(patch.object(MODULE,'__file__',str(helper/'desktop/tools/macos_normal_ui_runner.py')))
            stack.enter_context(patch.object(MODULE.sys,'platform','darwin'))
            stack.enter_context(patch.object(MODULE.sys,'version_info',(3,14,7)))
            stack.enter_context(patch.object(MODULE.sys,'flags',SimpleNamespace(isolated=1,no_site=1)))
            stack.enter_context(patch.object(MODULE.sys,'dont_write_bytecode',True))
            stack.enter_context(patch.object(MODULE.platform,'mac_ver',return_value=('26.6.2',(),'')))
            stack.enter_context(patch.object(pwd,'getpwuid',return_value=SimpleNamespace(pw_uid=1000,pw_gid=1000,pw_name='runner',pw_dir='/Users/runner')))
            for function in ('getuid','geteuid','getgid','getegid'):
                stack.enter_context(patch.object(MODULE.os,function,return_value=1000))
            stack.enter_context(patch.object(MODULE.os,'stat',return_value=SimpleNamespace(st_uid=1000)))
            stack.enter_context(patch.object(MODULE.Path,'cwd',return_value=helper))
            for target, machine, arch, hosted in ((MODULE.ARM_TARGET,'arm64','ARM64','github-hosted-macos26-arm64'),
                                                (MODULE.INTEL_TARGET,'x86_64','X64','github-hosted-macos26-x86_64')):
                for application in ('a'*40,'b'*40):
                    for flag in ('--normal-build','--normal-ios-pending-recovery-test','--normal-ios-pending-recovery-summary'):
                        request=MODULE.normal_request(['--target',target,flag],str(normal/'tmp')+'/')
                        actual=dict(env,RUNNER_ARCH=arch,TEST_RUNNER_MRK_NORMAL_UI_HOSTED_JOB=hosted,
                                    TEST_RUNNER_MRK_NORMAL_UI_APPLICATION_SOURCE=application)
                        cap=32*1024**3 if request['phase']=='build' else 1024**3
                        with patch.object(MODULE.platform,'machine',return_value=machine),patch.dict(MODULE.os.environ,actual,clear=True),patch.object(resource,'getrlimit',return_value=(cap,cap)):
                            root,source,forwarded,_=MODULE.normal_context(request)
                        self.assertEqual((root,source),(helper,'b'*40))
                        self.assertEqual(forwarded[MODULE.IOS_PENDING_CURRENT_ENV],MODULE.IOS_PENDING_CURRENT_SCOPE)
                        self.assertEqual(forwarded['TEST_RUNNER_MRK_NORMAL_UI_APPLICATION_SOURCE'],application)
                        if request['phase']!='build':
                            self.assertEqual(forwarded[MODULE.IOS_PENDING_RUN],'42')
                            self.assertEqual(forwarded[MODULE.IOS_PENDING_ATTEMPT],'1')
                            self.assertNotIn(MODULE.ANDROID_INPUT_ENV,forwarded)
                        self.assertNotIn('GITHUB_SHA',forwarded)
            request=MODULE.normal_request(['--normal-ios-pending-recovery-test'],str(normal/'tmp')+'/')
            for key,bad in [('GITHUB_REF',MODULE.ANDROID_CANDIDATE_REF),('GITHUB_WORKFLOW_REF','other'),
                ('GITHUB_WORKSPACE',str(helper)),('GITHUB_EVENT_NAME','workflow_dispatch'),('GITHUB_SHA','a'*40),
                (MODULE.IOS_PENDING_CURRENT_ENV,'other'),(MODULE.IOS_TOOLS_CURRENT_ENV,MODULE.IOS_TOOLS_CURRENT_SCOPE),
                ('TEST_RUNNER_MRK_NORMAL_UI_APPLICATION_SOURCE','0'*40)]:
                with self.subTest(field=key),patch.object(MODULE.platform,'machine',return_value='arm64'),patch.dict(MODULE.os.environ,dict(env,**{key:bad}),clear=True),patch.object(resource,'getrlimit',return_value=(1024**3,1024**3)),self.assertRaises(MODULE.Refused):
                    MODULE.normal_context(request)
            for flag in ('--normal-android-signed-build-test','--normal-ios-unsigned-archive-test'):
                request=MODULE.normal_request([flag],str(normal/'tmp')+'/')
                with self.assertRaises(MODULE.Refused): MODULE.ios_pending_candidate_context(request,env,helper)
        # The actual existing summary path publishes helper SOURCE and a separate
        # app label, while retaining original native0/source POST and strict counts.
        for failure in (None,'native','post'):
            with tempfile.TemporaryDirectory() as temporary:
                normal=Path(temporary)/'normal-ui';normal.mkdir();result=normal/MODULE.IOS_PENDING_RESULT;result.mkdir()
                request=MODULE.normal_request(['--normal-ios-pending-recovery-summary'],str(normal/'tmp')+'/')
                counts=MODULE.encoded(dict(totalTestCount=1,passedTests=1,failedTests=0,skippedTests=0,expectedFailures=0))
                original=subprocess.CompletedProcess([],65 if failure=='native' else 0,counts,b'')
                phase=MODULE.NormalPhase(SimpleNamespace(run_owned=lambda argv,**kw:subprocess.CompletedProcess(argv,original.returncode,original.stdout,original.stderr)),
                    env,helper,MODULE.PhaseClock(90))
                with patch.object(MODULE,'normal_source_state',side_effect=[{'same':True},{} if failure=='post' else {'same':True}]):
                    if failure=='post':
                        with self.assertRaisesRegex(MODULE.Refused,'normal-ui-source-pre-post'):
                            MODULE.execute_normal_phase(phase,request,'b'*40,(1024**3,1024**3))
                        self.assertFalse((normal/'ios-pending-recovery-summary.command-admission.json').exists())
                    else:
                        returned=MODULE.execute_normal_phase(phase,request,'b'*40,(1024**3,1024**3))
                        self.assertEqual(returned.returncode,original.returncode)
                        row=json.loads((normal/'ios-pending-recovery-summary.command-admission.json').read_bytes())
                        self.assertEqual((row['sourceCommit'],row['applicationSourceCommit']),('b'*40,'a'*40))
                        self.assertEqual(row['currentCandidateScope'],MODULE.IOS_PENDING_CURRENT_SCOPE)
                        self.assertEqual(row['originalReturncode'],original.returncode)
                        self.assertEqual('iosPendingRecoveryTestCounts' in row,failure is None)


    def test_pending_installed_runtime_uses_actual_record_manifest_and_originals_without_producer_files(self):
        # Real parsers and real tiny file descriptors; root ownership/flags and
        # canonical system path are explicit inert adapters, never native proof.
        from tests.desktop.test_macos_installed_staging import TOOL as stage
        original_stat, original_fstat, original_close = os.stat, os.fstat, os.close
        app_source, helper_source = 'a'*40, 'b'*40
        for target in (MODULE.ARM_TARGET, MODULE.INTEL_TARGET):
            selection = stage.source_build_selection(target)
            for fault in (None, 'same-source', 'large-manifest', 'record-source', 'record-release', 'record-identity',
                          'record-manifest', 'record-inventory', 'core-bytes', 'python-mode', 'core-hardlink',
                          'post-replace', 'post-flags', 'unknown-close'):
                with self.subTest(target=target,fault=fault), pending_account_module() as loader, tempfile.TemporaryDirectory() as tmp:
                    root=Path(tmp); install=root/str(stage.INSTALL_ROOT).lstrip('/')
                    release=install/'versions'/selection.release;runtime=release/'runtime'
                    (runtime/'python/bin').mkdir(parents=True)
                    for path in (install,install/'versions',release):path.chmod(0o755)
                    for path in (runtime,runtime/'python',runtime/'python/bin'):path.chmod(0o555)
                    # Temporarily writable task-only runtime so synthetic files can be prepared.
                    runtime.chmod(0o755);(runtime/'python/bin').chmod(0o755)
                    core,python=b'non-executable synthetic core bytes',b'non-executable interpreter fixture'
                    entries={name:dict(path=name,sha256=stage.digest(b'x'),size=1) for name in stage.CURRENT_BOOTSTRAPS|{'github-ca.pem'}}
                    for name,body in (('core.zip',core),('python/bin/python3',python)):
                        entries[name]=dict(path=name,sha256=stage.digest(body),size=len(body))
                    if fault=='large-manifest':
                        for index in range(10000):
                            name='python/lib/metadata-bound-%05d.py'%index
                            entries[name]=dict(path=name,sha256=stage.digest(b''),size=0)
                    rows=[entries[name] for name in sorted(entries)]
                    manifest=dict(schemaVersion=1,protocol=1,coreVersion='0.1.2',target=target,
                        coreSha256=entries['core.zip']['sha256'],protocolSha256=stage.CURRENT_PROTOCOL,
                        inventorySha256=stage.digest(stage.canonical(rows)),files=rows)
                    manifest_body=stage.canonical(manifest);manifest_sha=stage.digest(manifest_body)
                    if fault=='large-manifest':self.assertTrue(1024*1024<len(manifest_body)<=stage.MANIFEST_BYTES)
                    all_rows={ 'runtime/'+name:dict(row,path='runtime/'+name,executable=name=='python/bin/python3') for name,row in entries.items() }
                    all_rows['runtime/manifest.json']=dict(path='runtime/manifest.json',sha256=manifest_sha,size=len(manifest_body),executable=False)
                    for name in (stage.ENTRY_BINARY,stage.APP_BINARY,stage.VAULT_HELPER,'Contents/Info.plist',stage.PAYLOAD_INFO):
                        path='app/'+name;all_rows[path]=dict(path=path,size=1,sha256=stage.digest(b'x'),executable=name in (stage.ENTRY_BINARY,stage.APP_BINARY,stage.VAULT_HELPER))
                    inventory=stage.canonical(dict(schemaVersion=1,release=selection.release,runtimeManifestSha256=manifest_sha,
                        files=[all_rows[name] for name in sorted(all_rows)]))
                    def protected(value,*,flags=0):
                        data={name:getattr(value,name) for name in dir(value) if name.startswith('st_')}
                        data.update(st_uid=0,st_gid=0,st_flags=flags)
                        return SimpleNamespace(**data)
                    record=dict(schemaVersion=1,basis='protected-recorded-installation-inventory',phase='inventory-recorded',kind='ordinary',
                        instance='1'*32,packageIdentifier=stage.PACKAGE_ID,packageVersion=selection.package_version,bundleIdentifier=stage.BUNDLE_ID,
                        release=selection.release,sourceCommit=app_source,protocolSha256=stage.CURRENT_PROTOCOL,runtimeManifestSha256=manifest_sha,
                        inventory=dict(name=stage.INSTALLATION_INVENTORY_NAME,bytes=len(inventory),sha256=stage.digest(inventory)),
                        policy='fixed-root-wheel-readonly-v1',installRoot=stage.installation_directory_data(protected(original_stat(install))),
                        releaseDirectory=stage.installation_directory_data(protected(original_stat(release))))
                    if fault=='record-source':record['sourceCommit']='c'*40
                    if fault=='record-release':record['release']+='-wrong'
                    if fault=='record-identity':record['installRoot']['inode']+=1
                    if fault=='record-manifest':record['runtimeManifestSha256']='f'*64
                    if fault=='record-inventory':record['inventory']['sha256']='e'*64
                    files=((release/stage.INSTALLATION_RECORD_NAME,stage.canonical(record),0o444),
                        (release/stage.INSTALLATION_INVENTORY_NAME,inventory,0o444),(runtime/'manifest.json',manifest_body,0o444),
                        (runtime/'core.zip',core+b'!' if fault=='core-bytes' else core,0o444),
                        (runtime/'python/bin/python3',python,0o444 if fault=='python-mode' else 0o555))
                    for path,body,mode in files:path.write_bytes(body);path.chmod(mode)
                    if fault=='core-hardlink':os.link(runtime/'core.zip',runtime/'other-core')
                    runtime.chmod(0o555);(runtime/'python/bin').chmod(0o555)
                    binding=loader.Binding(app_source if fault=='same-source' else helper_source,'42','1',target)
                    fixtures=loader.Fixtures(binding,os.getuid(),os.getgid(),loader.IOS_ACCOUNT_CASE)
                    native_open=fixtures._open;post_flags=[False];admitted=False
                    def open_original(name,parent=None,**kw):return native_open(str(root) if name=='/' and parent is None else name,parent,**kw)
                    def named(name,*args,**kw):
                        value=original_stat(str(root) if name=='/' and kw.get('dir_fd') is None else name,*args,**kw)
                        return protected(value,flags=1 if post_flags[0] else 0)
                    def held(fd):return protected(original_fstat(fd),flags=1 if post_flags[0] else 0)
                    with ExitStack() as stack:
                        stack.enter_context(patch.object(fixtures,'_open',side_effect=open_original))
                        source=stack.enter_context(patch.object(loader,'_gate_load_stager',return_value=(stage,selection)))
                        stack.enter_context(patch.object(loader.os,'stat',side_effect=named))
                        stack.enter_context(patch.object(loader.os,'fstat',side_effect=held))
                        try:
                            if fault in ('record-source','record-release','record-identity','record-manifest','record-inventory',
                                         'core-bytes','python-mode','core-hardlink'):
                                with self.assertRaises((loader.Refused,stage.Refused)):
                                    fixtures.admit_normal_account_runtime(MODULE.SAVED_VERSION_CANDIDATE_ROOT,
                                        Path('/Users/runner/work/_temp/mrk-macos-installed.abcdefgh'),application_source=app_source)
                                self.assertFalse(fixtures.account_produced)
                            else:
                                fixtures.admit_normal_account_runtime(MODULE.SAVED_VERSION_CANDIDATE_ROOT,
                                    Path('/Users/runner/work/_temp/mrk-macos-installed.abcdefgh'),application_source=app_source)
                                admitted=True
                                self.assertEqual(fixtures.recovery_runtime_paths(),(str(stage.INSTALL_ROOT/'versions'/selection.release/'runtime/python/bin/python3'),
                                    str(stage.INSTALL_ROOT/'versions'/selection.release/'runtime/core.zip')))
                                self.assertEqual(len(fixtures.fds),14) # Nine fixed directory originals + five actual leaves.
                                source.assert_called_once_with(fixtures,MODULE.SAVED_VERSION_CANDIDATE_ROOT,target=target,registrations=[])
                                self.assertNotEqual(manifest_sha,json.loads((ROOT/'desktop/macos-installed-inputs/python-signed-runtime-binding.json').read_bytes())['targets'][target]['runtimeManifestSha256'])
                                if fault=='post-replace':
                                    (runtime/'core.zip').chmod(0o644);(runtime/'core.zip').write_bytes(core+b'!')
                                    with self.assertRaises(loader.Refused):fixtures.recovery_runtime_paths()
                                if fault=='post-flags':
                                    post_flags[0]=True
                                    with self.assertRaises(loader.Refused):fixtures.recovery_runtime_paths()
                            self.assertFalse((root/'runtime-result.json').exists())
                            self.assertFalse(fixtures.inflight)
                        finally:
                            observed=list(fixtures.fds)
                            if fault=='unknown-close':
                                first=observed[0]
                                def close_once(fd):
                                    original_close(fd)
                                    if fd==first:raise OSError('inert consumed close failure')
                                with patch.object(loader.os,'close',side_effect=close_once),self.assertRaises(OSError):fixtures.close()
                                self.assertIsNotNone(fixtures.first_close_error)
                            else:fixtures.close()
                            for fd in observed:
                                with self.assertRaises(OSError):original_fstat(fd)
                    # Task-owned fixtures only; reopen modes for TemporaryDirectory removal.
                    for path in (runtime,runtime/'python',runtime/'python/bin'):path.chmod(0o755)

    def test_pending_retained_metadata_collection_is_role_bounded_and_admission_failure_does_not_start_producer(self):
        with pending_account_module() as loader,tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp);body=b'x'*(1024*1024+1);(path/'manifest.json').write_bytes(body);(path/'manifest.json').chmod(0o444)
            fixture=loader.Fixtures(loader.Binding('a'*40,'42','1'),os.getuid(),os.getgid(),loader.IOS_ACCOUNT_CASE)
            parent=fixture._open(str(path),directory=True)
            real_stat,real_fstat=os.stat,os.fstat
            def protected(value):
                data={name:getattr(value,name) for name in dir(value) if name.startswith('st_')};data['st_uid']=0
                return SimpleNamespace(**data)
            try:
                with patch.object(loader.os,'stat',side_effect=lambda *a,**k:protected(real_stat(*a,**k))),patch.object(loader.os,'fstat',side_effect=lambda *a,**k:protected(real_fstat(*a,**k))):
                    _,hashed,actual=fixture._recovery_read(parent,'manifest.json',0,12*1024*1024,0o444,retain=True,collect=True)
                    self.assertEqual((actual,hashed),(body,loader.digest(body)))
                    for name,cap in (('manifest.json',12*1024*1024+1),('core.zip',12*1024*1024),('private.json',12*1024*1024)):
                        with self.assertRaisesRegex(loader.Refused,'collect-bound'):fixture._recovery_read(parent,name,0,cap,0o444,retain=True,collect=True)
            finally:fixture.close()
            env={MODULE.IOS_PENDING_RUN:'42',MODULE.IOS_PENDING_ATTEMPT:'1','HOME':'/Users/runner',
                MODULE.IOS_PENDING_CURRENT_ENV:MODULE.IOS_PENDING_CURRENT_SCOPE,
                'TEST_RUNNER_MRK_NORMAL_UI_APPLICATION_SOURCE':'c'*40}
            phase=MODULE.NormalPhase(None,env,ROOT,MODULE.PhaseClock(1080))
            current=MODULE.NormalIOSRecoveryFixture(phase,'a'*40,MODULE.normal_request(['--normal-ios-pending-recovery-test'],str(path/'normal-ui/tmp')+'/'))
            producer=unittest.mock.Mock()
            with patch.object(current.fixtures,'prepare',side_effect=lambda:setattr(current.fixtures,'account_home','/Users/runner')),\
                 patch.object(current.fixtures,'admit_normal_account_runtime',side_effect=loader.Refused('actual runtime refused')) as admit,\
                 patch.object(loader,'_run_ios_account_child',producer),self.assertRaisesRegex(loader.Refused,'actual runtime refused'):
                current.__enter__()
            admit.assert_called_once_with(MODULE.SAVED_VERSION_CANDIDATE_ROOT,current.request['derived'].parent.parent,application_source='c'*40)
            producer.assert_not_called();self.assertFalse(current.prepared);self.assertFalse(current.fixtures.fds)

    def test_pending_fixed_requests_and_original_marker_are_bound_to_both_targets(self):
        # Pending uses its actual five-original account fixture, not the unrelated
        # LocalFixture prefix. SOURCE wiring only; next native journey checks AX.
        swift = SWIFT.read_text()
        navigation = swift.split('private func goToFolder(', 1)[1].split('let cancels =', 1)[0]
        self.assertIn('recoveryFixture: IOSRecoveryFixture? = nil', navigation)
        self.assertIn('recoveryFixture === ownedIOSRecoveryFixture && path == recoveryFixture.projectPath', navigation)
        self.assertLess(navigation.index('recoveryFixture ==='), navigation.index('try recoveryFixture.post()'))
        self.assertIn('} else {\n            try require(path.hasPrefix("/private/tmp/mrk-normal-project-")', navigation)
        pending = swift.split('func testInstalledIOSPendingAccountRecoveryThroughUI()', 1)[1].split('func testSyntheticProjectAndroidSignedBuild()', 1)[0]
        # Native Foundation cases run inside the existing journey before any
        # private fixture admission; this Linux test proves wiring, not AX results.
        self.assertLess(pending.index('try Self.exerciseStaticTextContentData()'),pending.index('try fixture.open(.pending)'))
        content=swift.split('private static func staticTextContent(value:',1)[1].split('@MainActor private func staticTextPrefix(',1)[0]
        self.assertIn('(value as? String) ?? label',content)
        self.assertIn('element.elementType == .staticText',content)
        self.assertNotIn('String(describing:',content)
        collection=swift.split('@MainActor private func staticTextSelections(',1)[1].split('@MainActor private func staticTextMatching(',1)[0]
        self.assertIn('check: () throws -> Void',collection)
        self.assertLess(collection.index('guard count <= 256'),collection.index('query.allElementsBoundByIndex'))
        self.assertIn('guard elements.count <= 256',collection)
        self.assertIn('element.elementType == .staticText',collection)
        self.assertIn('Self.staticTextContent(value: value, label: label)',collection)
        self.assertIn('selectors[index].accepts(text)',collection)
        self.assertNotIn('NSPredicate',collection);self.assertNotIn('require(',collection);self.assertNotIn('remaining(',collection)
        prefix=swift.split('@MainActor private func staticTextPrefix(',1)[1].split('@MainActor private func staticTextFailureCount(',1)[0]
        self.assertIn('try staticTextMatching(root, .prefix(prefix), check: check)',prefix)
        data=swift.split('private static func exerciseStaticTextContentData()',1)[1].split('@MainActor private func androidCurrentBuildIdentity',1)[0]
        self.assertNotIn('evaluate(',data);self.assertIn('NSNumber(value: 4)',data)
        self.assertIn('([noMatch], 0)',data);self.assertIn('([oneMatch, oneMatch], 2)',data)
        cleanup=swift.split('private func settleFailedIOSArchive(',1)[1].split('func testSyntheticProjectUnsignedIOSArchive()',1)[0]
        self.assertIn('try staticTextPrefix(details, prefix, check: check)',cleanup)
        self.assertIn('try need(fields.count == 1)',cleanup)
        self.assertIn('try require(fields.count == 1, "current recovery field missing or repeated", check: .singleton)',swift)
        for name,end in (('androidCurrentBuildIdentity','testPositiveAndroidOutputCustodyData'),
                         ('iosCurrentArchiveIdentity','iosPublicText'),('iosRecoveryObservation','iosRecoverySession'),
                         ('iosRecoveryAccount','testInstalledIOSPendingAccountRecoveryThroughUI')):
            body=swift.split('func '+name+'(',1)[1].split('func '+end+'(',1)[0]
            self.assertIn('staticTextPrefix(',body);self.assertIn('try staticTextContent(',body)
        for name,end in (('androidPublicText','androidMatch'),('iosPublicText','iosResult')):
            body=swift.split('func '+name+'(',1)[1].split('func '+end+'(',1)[0]
            self.assertIn('try staticTextContent(query.element(boundBy: index))',body)
            self.assertIn('<= 32768',body)
        call = 'try goToFolder(sheet, path: fixture.projectPath, recoveryFixture: fixture); try nativeOpen(sheet)'
        self.assertEqual(swift.count(call), 1)
        self.assertLess(pending.index('ownedIOSRecoveryFixture = fixture'), pending.index(call))
        self.assertLess(pending.index('try fixture.open(.pending)'), pending.index(call))
        self.assertIn('try fixture.post()', pending.split(call, 1)[1])
        with pending_account_module() as loader:
            for target in (MODULE.ARM_TARGET, MODULE.INTEL_TARGET):
                binding = loader.Binding("a" * 40, "123", "1", target)
                _, _, _, marker, output = pending_account_data(loader, binding, os.getuid(), os.getgid())
                request = MODULE.normal_request(["--target", target, "--normal-ios-pending-recovery-test"], "/inert/normal-ui/tmp/")
                self.assertEqual((request["allowance"], request["timeout"], request["phaseSeconds"]), (525, 645, 1080))
                self.assertTrue(request["iosPending"])
                self.assertEqual(request["methods"], (MODULE.CLASS + MODULE.IOS_PENDING_METHOD,))
                argv = MODULE.xcode_test_arguments("/inert/runner.xctestrun", request["result"], request["methods"],
                    request["allowance"], target=target, ios_pending=True)
                self.assertIn("-only-testing:" + MODULE.CLASS + MODULE.IOS_PENDING_METHOD, argv)
                self.assertEqual(argv[argv.index("-maximum-test-execution-time-allowance") + 1], "525")
                for extra in (dict(android_positive=True), dict(ios_unsigned=True), dict(engineering=True), dict(output_data=True)):
                    with self.assertRaises(MODULE.Refused):
                        MODULE.xcode_test_arguments("/inert/runner.xctestrun", request["result"], request["methods"],
                            request["allowance"], target=target, ios_pending=True, **extra)
                summary = MODULE.normal_request(["--target", target, "--normal-ios-pending-recovery-summary"], "/inert/normal-ui/tmp/")
                self.assertEqual((summary["phase"], summary["methods"], summary["timeout"], summary["phaseSeconds"]), ("summary", (), 30, 90))
                self.assertEqual(MODULE.ios_pending_marker(output, binding=binding, loader=loader), marker)
                lines = output.splitlines()
                bad_outputs = (b"", output + output, output + lines[2] + b"\n", output.replace(lines[1], b"missing"),
                    output.replace(lines[2], MODULE.IOS_PENDING_PREFIX + json.dumps(marker).encode()),
                    b"\n".join((lines[0], lines[2], lines[1], lines[3])),
                    output + b"MRK_MACOS_UI_FAILURE_CLEANUP=unexpected\n", output.replace(b" passed (", b" failed ("))
                for bad in bad_outputs:
                    with self.subTest(target=target, malformed=len(bad)), self.assertRaises((MODULE.Refused, loader.Refused)):
                        MODULE.ios_pending_marker(bad, binding=binding, loader=loader)
                wrong = dict(marker, runAttempt="2")
                with self.assertRaises(loader.Refused):
                    MODULE.ios_pending_marker(output.replace(MODULE.encoded(marker), MODULE.encoded(wrong)), binding=binding, loader=loader)
                counts = dict(totalTestCount=1, passedTests=1, failedTests=0, skippedTests=0, expectedFailures=0)
                self.assertEqual(MODULE.ios_pending_summary(MODULE.encoded(counts)), counts)
                for key in counts:
                    for value in (True, counts[key] + 1):
                        with self.assertRaises(MODULE.Refused): MODULE.ios_pending_summary(MODULE.encoded(dict(counts, **{key: value})))
                with self.assertRaises(MODULE.Refused):
                    MODULE.normal_request(["--target", target, "--normal-ios-pending-recovery-test", "--normal-ios-unsigned-archive-test"], "/inert/normal-ui/tmp/")

    def test_pending_original_sequence_preserves_failure_and_requires_runner_finality_before_observer(self):
        # Actual normal phase, child transport parser, account acceptance and
        # readback orchestration. Only native owner and filesystem observations
        # are inert ports; this is not Mac account/runtime qualification.
        with pending_account_module() as loader:
            for fault in (None, "producer-unknown", "producer-nonzero", "producer-late", "ui-unknown", "ui-nonzero",
                          "ui-marker", "runner-post", "runner-close", "observer-unknown", "observer-nonzero", "project-post"):
                with self.subTest(fault=fault), ExitStack() as stack:
                    tick, calls = [0], []
                    request = MODULE.normal_request(["--normal-ios-pending-recovery-test"], "/inert/normal-ui/tmp/")
                    environment = {MODULE.IOS_PENDING_RUN: "123", MODULE.IOS_PENDING_ATTEMPT: "1", "HOME": "/Users/runner"}
                    phase = MODULE.NormalPhase(None, environment, ROOT, MODULE.PhaseClock(1080, now=lambda: tick[0]), retain_nonzero=True)
                    fixture = MODULE.NormalIOSRecoveryFixture(phase, "a" * 40, request)
                    fixtures = fixture.fixtures
                    private, producer, observer, marker, output = pending_account_data(loader, fixture.binding, fixtures.uid, fixtures.gid)
                    fixture.prepared = True
                    fixtures.account_home = private["home"]
                    fixtures.recovery_runtime = ("/inert/python3", "/inert/core.zip")
                    fixtures.account_baseline_files = [object()]
                    stack.enter_context(patch.object(fixture, "check_sources"))
                    stack.enter_context(patch.object(fixtures, "recovery_runtime_paths", return_value=fixtures.recovery_runtime))
                    stack.enter_context(patch.object(fixtures, "_account_current"))
                    post = stack.enter_context(patch.object(fixtures, "readback", side_effect=loader.Refused("inert project post") if fault == "project-post" else None))
                    def adopt(value):
                        self.assertIsNot(value, producer)
                        self.assertEqual(value, producer)  # Genuine child JSON parser ran.
                        self.assertFalse(fixtures.inflight); self.assertTrue(fixtures.last_returned)
                        fixtures.account_private = value["private"]
                        fixtures.account_private_sha = loader.digest(MODULE.encoded(value["private"]))
                        fixtures.account_producer_attestation = {k: v for k, v in value.items() if k != "private"}
                        fixtures.account_produced = True
                    stack.enter_context(patch.object(fixtures, "accept_account_producer", side_effect=adopt))
                    originals = {}
                    def owned(argv, **kwargs):
                        mode = argv[7] if len(argv) == 12 and argv[0] == "/inert/python3" else argv[0]
                        calls.append((mode, argv, kwargs))
                        prefix = "producer" if mode == "produce" else "observer" if mode == "observe" else "ui" if mode == "inert-ui" else mode
                        if fault == prefix + "-unknown": raise OSError("inert unknown original")
                        if mode in ("produce", "observe"):
                            self.assertNotIn("HOME", kwargs["environ"])
                            self.assertEqual(kwargs["environ"], loader._account_environment(fixtures.path / "state" / loader.IOS_ACCOUNT_CASE, fixtures.uid, "runner"))
                            self.assertEqual((kwargs["timeout"], kwargs["output_limit"]), (180, 16384) if mode == "produce" else (90, 2048))
                            self.assertEqual(int(argv[10]) - int(argv[9]), 25_000_000_000)
                        if mode == "observe":
                            self.assertTrue(fixtures.account_app_returned)
                            self.assertEqual(argv[11], fixtures.account_private_sha)
                        body = MODULE.encoded(producer if mode == "produce" else observer) + b"\n" if mode in ("produce", "observe") else output if mode == "inert-ui" else b""
                        if fault == "ui-marker" and mode == "inert-ui": body = b"no marker\n"
                        result = subprocess.CompletedProcess(argv, 67 if fault == prefix + "-nonzero" else 0, body, b"")
                        originals[mode] = result
                        if fault == "producer-late" and mode == "produce": tick[0] = 1080 * 1_000_000_000
                        return result
                    phase.owner = SimpleNamespace(run_owned=owned)
                    proof = dict(originalProductsPrePostMatched=fault != "runner-post", originalClosesCompleted=fault != "runner-close",
                        strictCodesignOriginalZero=True, reSignedOrRepaired=False)
                    def execute():
                        phase.call("normal-ui-source-roster", ["inert-source"], 15)
                        fixture.ui_call("verify-generated-runner", ["inert-verify"], 30)
                        fixture.ui_call("generated-runner-entitlements", ["inert-entitlements"], 30)
                        original = fixture.ui_call("one-admitted-ui-test", ["inert-ui"], 645)
                        self.assertIs(original, originals["inert-ui"])
                        result = fixture.recovered(original, proof)
                        phase.call("normal-ui-source-roster", ["inert-source"], 15)
                        return result
                    if fault is None:
                        result = execute()
                        self.assertEqual([row["role"] for row in phase.records], ["normal-ui-source-roster", "verify-generated-runner",
                            "generated-runner-entitlements", "ios-account-produce", "one-admitted-ui-test", "ios-account-observe", "normal-ui-source-roster"])
                        self.assertEqual([row["roleCapSeconds"] for row in phase.records], [15, 30, 30, 180, 645, 90, 15])
                        self.assertEqual(result["observation"], marker)
                        self.assertFalse(result["originalClosesCompleted"])
                        self.assertTrue(result["account"]["exactPendingSessionRecovered"])
                        self.assertFalse(result["account"]["signedExportQualified"])
                        self.assertNotIn(private["token"], json.dumps(result))
                        post.assert_called_once_with(loader.IOS_ACCOUNT_CASE)
                        self.assertIsNone(fixture.close())
                        with self.assertRaises(MODULE.Refused): fixture.ui_call("one-admitted-ui-test", ["inert-ui"], 645)
                    else:
                        with self.assertRaises((MODULE.Refused, loader.Refused, OSError)): execute()
                        modes = [row[0] for row in calls]
                        if fault.startswith("producer-"):
                            self.assertNotIn("inert-ui", modes); self.assertNotIn("observe", modes)
                        elif fault.startswith("ui-") or fault.startswith("runner-"):
                            self.assertNotIn("observe", modes)
                        self.assertEqual(modes.count("inert-source"), 1)
                        if fault.endswith("-nonzero"):
                            key = "produce" if fault.startswith("producer-") else "observe" if fault.startswith("observer-") else "inert-ui"
                            self.assertIs(phase.first_nonzero, originals[key])
                        if fault.endswith("-unknown") or fault == "producer-late":
                            self.assertTrue(fixtures.inflight)
                            self.assertIsNotNone(fixture.close())  # Unknown original never claimed closed.
                        else:
                            self.assertIsNone(fixture.close())

    def test_pending_close_consumes_loader_original_preserves_foreign_registration_and_primary_error(self):
        with pending_account_module() as loader, tempfile.TemporaryDirectory(prefix="mrk-pending-close-data-") as temporary:
            root = Path(temporary)
            path = root / "loader"; path.write_bytes(b"inert original")
            for fault in (None, "fixture-close", "loader-close", "both", "inflight"):
                with self.subTest(fault=fault), ExitStack() as stack:
                    phase = MODULE.NormalPhase(None, {MODULE.IOS_PENDING_RUN: "123", MODULE.IOS_PENDING_ATTEMPT: "1"}, ROOT, MODULE.PhaseClock(1080, now=lambda: 0))
                    fixture = MODULE.NormalIOSRecoveryFixture(phase, "a" * 40,
                        MODULE.normal_request(["--normal-ios-pending-recovery-test"], "/inert/normal-ui/tmp/"))
                    fixture.loader_fd = fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
                    fixture.fixtures.inflight = fault == "inflight"
                    own, foreign = object(), object()
                    fixture.fixtures.normal_stager_registrations = [own]
                    stack.enter_context(patch.dict(sys.modules, {"_mrk_shipping_gate_stager": foreign}))
                    first = OSError("inert fixture close")
                    if fault in ("fixture-close", "both"):
                        stack.enter_context(patch.object(fixture.fixtures, "close", side_effect=first))
                    real_close = os.close
                    def consumed(number):
                        real_close(number)
                        if number == fd and fault in ("loader-close", "both"): raise OSError("inert loader consuming close")
                    stack.enter_context(patch.object(MODULE.os, "close", side_effect=consumed))
                    error = fixture.close()
                    self.assertIsNone(fixture.loader_fd)
                    with self.assertRaises(OSError): os.fstat(fd)
                    self.assertIs(sys.modules["_mrk_shipping_gate_stager"], foreign)
                    if fault is None: self.assertIsNone(error)
                    else: self.assertIsInstance(error, (OSError, loader.Refused))
                    if fault in ("fixture-close", "both"): self.assertIs(error, first)
                    if fault == "both": self.assertEqual(fixture.cleanup_errors, ["OSError", "OSError"])
            # Normal source POST uses the SAME genuine retained descriptor;
            # named replacement, in-place bytes and module custody all veto it.
            source_path = root / MODULE.LOADER
            source_path.parent.mkdir(parents=True, exist_ok=True)
            source_path.write_bytes(b"inert source original")
            phase = MODULE.NormalPhase(None, {MODULE.IOS_PENDING_RUN: "123", MODULE.IOS_PENDING_ATTEMPT: "1"}, ROOT, MODULE.PhaseClock(1080, now=lambda: 0))
            fixture = MODULE.NormalIOSRecoveryFixture(phase, "a" * 40,
                MODULE.normal_request(["--normal-ios-pending-recovery-test"], "/inert/normal-ui/tmp/"))
            phase.root = root
            fixture.loader_fd = source_fd = os.open(source_path, os.O_RDONLY | os.O_CLOEXEC)
            _, identity, digest = MODULE.original_body(source_fd, 1024*1024)
            fixture.loader_original = (identity, digest)
            try:
                fixture.check_sources()
                with patch.dict(sys.modules, {MODULE.LOADER_MODULE: object()}), self.assertRaises(MODULE.Refused):
                    fixture.check_sources()
                source_path.write_bytes(b"inert source changed!")
                with self.assertRaises(MODULE.Refused): fixture.check_sources()
            finally:
                self.assertIsNone(fixture.close())
            with self.assertRaises(OSError): os.fstat(source_fd)
            # Consuming failure is added to an existing primary, not substituted.
            primary = MODULE.Refused("inert primary")
            with patch.object(fixture, "close", return_value=OSError("inert secondary")):
                self.assertFalse(fixture.__exit__(type(primary), primary, None))
            self.assertEqual(primary.__notes__, ["normal recovery fixture also had a consuming-close refusal"])


    def test_pending_shared_source_query_matches_real_build_receipt_on_both_targets(self):
        # Real current SOURCE and receipt files, inert seven-original port.
        # The new IOSArchive.tsx selection must agree in producer and consumer.
        source = "a" * 40
        for target in (MODULE.ARM_TARGET, MODULE.INTEL_TARGET):
            with self.subTest(target=target), tempfile.TemporaryDirectory(prefix="mrk-pending-source-data-") as temporary:
                root = Path(temporary); normal = root / "normal-ui"; normal.mkdir(mode=0o700)
                names = ("desktop/tools/macos_normal_ui_runner.py",
                    "desktop/native/macos-normal-ui/MRKNormalAppUITests/NormalAppUITests.swift", "desktop/src/components/IOSArchive.tsx")
                rows = []
                for name in names:
                    path = root / name; path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                    body = b"inert SOURCE, never executed\n"; path.write_bytes(body)
                    blob = hashlib.sha1(b"blob " + str(len(body)).encode() + b"\0" + body).hexdigest()
                    rows.append(b"100644 blob " + blob.encode() + b"\t" + name.encode() + b"\0")
                tool_values = (b"Xcode 26.0\nBuild version 17A324\n",
                    b"/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX26.0.sdk\n",
                    b"26.0\n", b"25A352\n")
                queries = {tuple(query[2]): body for query, body in zip(MODULE.TOOLCHAIN_QUERIES, tool_values)}
                calls = []
                expected = ["/usr/bin/git", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null",
                    "ls-tree", "-r", "-z", "--full-tree", source, "--", "desktop/native/macos-normal-ui",
                    "desktop/tools/macos_normal_ui_runner.py", "desktop/src/components/IOSArchive.tsx"]
                def original(argv, **kwargs):
                    calls.append(argv)
                    if argv[0] == "/usr/bin/git":
                        self.assertEqual(argv, expected)
                        body = b"".join(rows)
                    elif tuple(argv) in queries: body = queries[tuple(argv)]
                    else:
                        self.assertEqual(argv, MODULE.normal_build_arguments(normal / "DerivedData", target=target))
                        body = b"inert build original\n"
                    return subprocess.CompletedProcess(argv, 0, body, b"")
                request = MODULE.normal_request(["--target", target, "--normal-build"], str(normal / "tmp") + "/")
                phase = MODULE.NormalPhase(SimpleNamespace(run_owned=original), {}, root, MODULE.PhaseClock(450, now=lambda: 0))
                result = MODULE.execute_normal_phase(phase, request, source, (32 * 1024**3,) * 2)
                self.assertEqual(result.returncode, 0)
                # execute_normal_phase POST-checks the consumed receipt; the
                # CLI caller still owns stream publication and final finish().
                self.assertFalse(phase.clock.finalized); self.assertFalse(phase.clock.failed)
                self.assertEqual(calls[0], expected); self.assertEqual(calls[-1], expected); self.assertEqual(len(calls), 7)
                self.assertEqual(MODULE.output_data_source_argv(source), expected)
                receipt_path = normal / "build.command-admission.json"
                receipt = MODULE.document(receipt_path.read_bytes())
                MODULE.output_data_build_receipt(receipt, source, normal, receipt["sourceRosterSha256"], target=target)
                self.assertEqual(stat.S_IMODE(receipt_path.stat().st_mode), 0o600)
                # Honest old selector transcript is not a valid new receipt,
                # even when its own digest is recomputed consistently.
                old = json.loads(json.dumps(receipt))
                for index in (0, -1): old["commands"][index]["argvSha256"] = MODULE.sha(MODULE.encoded(expected[:-1]))
                with self.assertRaises(MODULE.Refused):
                    MODULE.output_data_build_receipt(old, source, normal, old["sourceRosterSha256"], target=target)
                with self.assertRaises(MODULE.Refused):
                    MODULE.output_data_build_receipt(receipt, source, normal, receipt["sourceRosterSha256"],
                        target=MODULE.INTEL_TARGET if target == MODULE.ARM_TARGET else MODULE.ARM_TARGET)
                # Missing required field SOURCE is refused before a build.
                rows.pop()
                missing = MODULE.NormalPhase(SimpleNamespace(run_owned=original), {}, root, MODULE.PhaseClock(450, now=lambda: 0))
                before = len(calls)
                with self.assertRaisesRegex(MODULE.Refused, "normal-ui-source-complete"):
                    MODULE.normal_source_state(missing, source)
                self.assertEqual(len(calls), before + 1)
                phase.clock.finish()  # Explicit caller finality, not a receipt claim.
                self.assertTrue(phase.clock.finalized)
                with self.assertRaisesRegex(MODULE.Refused, "normal-phase-terminal"):
                    phase.clock.allowance(15)


class AndroidCandidateProjectTests(unittest.TestCase):
    @contextmanager
    def prepared(self, *, fail=None):
        # Actual Git is confined to this test's owned empty namespace; no app,
        # credential, native gate, product grant or library-process proof.
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);normal=root/'normal-ui';normal.mkdir(mode=0o700)
            calls=[]
            def run(argv,**kw):
                self.assertEqual(argv[0],'/usr/bin/git')
                calls.append(argv)
                if fail is not None and fail(argv):return subprocess.CompletedProcess(argv,1,b'',b'fixed failure')
                return subprocess.run(argv,cwd=kw['cwd'],env=kw['environ'],timeout=kw['timeout'],capture_output=True,check=False)
            phase=MODULE.NormalPhase(SimpleNamespace(run_owned=run),
                {'PATH':'/usr/bin:/bin','HOME':str(root),'LANG':'C','LC_ALL':'C',MODULE.ANDROID_RUN_ENV:'12',MODULE.ANDROID_ATTEMPT_ENV:'1'},
                ROOT,MODULE.PhaseClock(120))
            inputs=SimpleNamespace(public_certificate='a'*64,post=lambda:None)
            with patch.object(MODULE,'ANDROID_CANDIDATE_TEMP',root):
                fixture=MODULE.AndroidCandidateFixture(phase,'b'*40,normal,inputs,MODULE.ARM_TARGET)
                try:yield fixture,phase,calls
                finally:fixture.close()
    def test_owned_git_fixture_has_exact_saved_public_inputs_and_known_closed_roster(self):
        with self.prepared() as (fixture,phase,calls):
            with fixture:
                self.assertEqual(len(calls),5)
                self.assertEqual(len(fixture.bodies),17)
                self.assertEqual({name for name,row in fixture.dirs.items() if not row[4]},
                    {'project/.git/objects/info','project/.git/objects/pack','project/.git/refs/tags'})
                config=json.loads(fixture.bodies['project/release/mobile-release.json'])
                self.assertIs(config['source']['localStoreEnabled'],True)
                self.assertEqual(config['android']['uploadCertificateSha256'],'a'*64)
                self.assertFalse((fixture.root/'project/.mobile-release').exists())
                self.assertNotIn('GIT_AUTHOR_NAME',phase.environment)
                source=subprocess.run(['/usr/bin/git','-C',str(fixture.root/'project'),'ls-tree','-r','--name-only','HEAD'],
                    capture_output=True,check=True,timeout=5,env={'PATH':'/usr/bin:/bin','GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':'/dev/null'})
                self.assertEqual(set(source.stdout.decode().splitlines()),{p[8:] for p in fixture.bodies})
                fixture.post()
                # Same source originals may coexist with the narrowly permitted output roots.
                for output in ('project/build','project/app/build','project/.mobile-release'):
                    (fixture.root/output).mkdir(mode=0o700)
                fixture.post()
                self.assertLessEqual(len(fixture.fds),fixture.MAX_FDS)
            self.assertTrue(fixture.closed);self.assertEqual(fixture.fds,[])
    def test_original_file_change_or_extra_git_object_is_not_adopted(self):
        for mutation in ('body','extra','replacement','root-replacement'):
            with self.subTest(mutation=mutation),self.prepared() as (fixture,phase,calls):
                fixture.__enter__()
                path=fixture.root/'project/release/version.properties'
                if mutation=='body':path.write_bytes(b'foreign')
                elif mutation=='extra':(fixture.root/'project/.git/objects/foreign').write_bytes(b'foreign')
                elif mutation=='root-replacement':
                    fixture.root.rename(fixture.root.with_name(fixture.root.name+'-moved'));fixture.root.mkdir(mode=0o700)
                else:
                    body=path.read_bytes();path.rename(path.with_name('moved'));path.write_bytes(body)
                with self.assertRaises(MODULE.Refused):fixture.post()
                self.assertEqual(len(calls),5)
    def test_failed_owned_git_preparation_closes_originals_and_never_emits_handoff(self):
        with self.prepared(fail=lambda argv:'commit' in argv) as (fixture,phase,calls):
            with self.assertRaisesRegex(MODULE.Refused,'candidate-fixture-git-original-zero'):fixture.__enter__()
            self.assertEqual(len(calls),3);self.assertTrue(fixture.closed);self.assertEqual(fixture.fds,[])
            self.assertFalse((fixture.normal/'android-candidate-fixture.json').exists())
            self.assertNotIn('GIT_AUTHOR_NAME',phase.environment)
    def test_candidate_canonical_public_vector_matches_actual_producer(self):
        # Native regression consumes these same exact public literals. This DATA
        # check executes the real producer encoder, not a second JSON encoder.
        swift=SWIFT.read_text()
        regression=swift.split('static func exerciseCandidateCanonicalData() throws {',1)[1].split('private func adoptAndroidCandidate(',1)[0]
        vector=regression.split('let vector = #"',1)[1].split('"#',1)[0].encode('ascii')+b'\n'
        value=MODULE.document(vector)
        self.assertEqual(MODULE.encoded(value)+b'\n',vector)
        self.assertEqual(value['integer'],[-(1<<63),(1<<63)-1])
        self.assertEqual(list(value['files']),['project/.git/HEAD','project/.git/config',
            'project/.git/objects/10/a','project/.git/objects/2/a'])
        self.assertEqual(value['values'],[True,False,None])
        self.assertIn('é',value['text']);self.assertIn(chr(127),value['text'])
        self.assertIn(chr(0x1f600),value['text'])
        sample={'project/.git/config':2,'project/.git/HEAD':1}
        expected=regression.split('let python = Data(#"',1)[1].split('"#.utf8)',1)[0].encode('ascii')+b'\n'
        self.assertEqual(MODULE.encoded(sample)+b'\n',expected)
        # Canonical byte equality (not semantic equality) retains original
        # duplicate/whitespace/order/escape/numeric representation refusals.
        for body in (b'{"schemaVersion":1,"schemaVersion":1}\n', b'{"schemaVersion":1,}\n'):
            with self.assertRaises((MODULE.Refused,ValueError)): MODULE.document(body)
        for body in (b'{ "schemaVersion":1}\n',b'{"schemaVersion":1}',
                     b'{"b":1,"a":2}\n',b'{"a":"\\/"}\n',b'{"a":"\\u007F"}\n'):
            self.assertNotEqual(MODULE.encoded(MODULE.document(body))+b'\n',body)
        for body in (b'{"schemaVersion":true}\n',b'{"schemaVersion":1.0}\n',b'{"schemaVersion":1e0}\n'):
            row=MODULE.document(body);row['schemaVersion']=1
            self.assertNotEqual(MODULE.encoded(row)+b'\n',body)

    def test_candidate_selector_cannot_be_relabelled_as_ordinary(self):
        derived=Path('/Users/runner/work/_temp/mrk-macos-installed.abcdefgh/normal-ui/DerivedData')
        result=derived.parent/MODULE.ANDROID_CANDIDATE_RESULT
        args=MODULE.xcode_test_arguments(derived/'Build/Products/test.xctestrun',result,
            (MODULE.CLASS+MODULE.ANDROID_CANDIDATE_METHOD,),900,android_positive=True,android_candidate=True)
        self.assertIn('-only-testing:'+MODULE.CLASS+MODULE.ANDROID_CANDIDATE_METHOD,args)
        for candidate,method in ((False,MODULE.ANDROID_CANDIDATE_METHOD),(True,MODULE.ANDROID_METHOD)):
            with self.assertRaises(MODULE.Refused):
                MODULE.xcode_test_arguments(derived/'Build/Products/test.xctestrun',result,
                    (MODULE.CLASS+method,),900,android_positive=True,android_candidate=candidate)


class PanelTopologyDiagnosticTests(unittest.TestCase):
    def test_pending_recovery_field_rows_are_closed_and_failure_only(self):
        def row(phase='awaiting-consent',field='operation-id'):
            return ('MRK_NORMAL_RECOVERY_FIELD=v2;phase='+phase+';field='+field+
                ';sample=pre-check;exactPrefix=0;trimmedPrefix=1;captionOnly=1;anyPrefix=0;role=group;children=0;descendants=0;rendererPrefix=1;nonAtomic=1\n').encode()
        private=b'PRIVATE operation values, account paths and secure text\n'
        for phase in ('awaiting-consent','terminal'):
            for field in ('operation-id','owner-generation','phase','outcome','reason'):
                original=subprocess.CompletedProcess(['original'],65,row(phase,field)+private,b'')
                value=MODULE.normal_failure_diagnostics('test',MODULE.IOS_PENDING_RESULT,original)
                self.assertEqual(value['originalReturncode'],65)
                self.assertEqual(value['recoveryField'],dict(state='observed',sample=dict(phase=phase,field=field,
                    timing='pre-check',countsCappedAt=5,nonAtomic=True,exactPrefix=0,trimmedPrefix=1,captionOnly=1,anyPrefix=0,
                    role='group',directChildren=0,allDescendants=0,rendererPrefix=1)))
                self.assertNotIn(b'PRIVATE',MODULE.encoded(value));self.assertLessEqual(len(MODULE.encoded(value))+1,4096)
        valid=row()
        extension=b';role=group;children=0;descendants=0;rendererPrefix=1'
        legacy=valid.replace(b'=v2;',b'=v1;').replace(extension,b'')
        old=MODULE.recovery_field_diagnostics(legacy,b'')
        self.assertEqual(old['state'],'observed');self.assertNotIn('role',old['sample'])
        for role in (b'group',b'static-text',b'other'):
            self.assertEqual(MODULE.recovery_field_diagnostics(valid.replace(b'role=group',b'role='+role),b'')['sample']['role'],role.decode())
        for bad in (valid.replace(b'=v2;',b'=v1;'),valid.replace(extension,b''),
            valid.replace(b'children=0',b'children=6'),valid.replace(b'role=group',b'role=PRIVATE'),
            valid.replace(b';descendants=0',b''),legacy+valid):
            self.assertEqual(MODULE.recovery_field_diagnostics(bad,b''),dict(state='refused',sample=None))
        for stdout,stderr in ((valid+valid,b''),(b'',valid),(valid[:-1],b''),(b'prefix '+valid,b''),
            (row('PRIVATE'),b''),(row(field='PRIVATE'),b''),(valid.replace(b'exactPrefix=0',b'exactPrefix=6'),b''),
            (valid.replace(b'nonAtomic=1',b'nonAtomic=0'),b'')):
            self.assertEqual(MODULE.recovery_field_diagnostics(stdout,stderr),dict(state='refused',sample=None))
        self.assertEqual(MODULE.recovery_field_diagnostics(private,b''),dict(state='absent',sample=None))
        with self.assertRaises(MODULE.Refused): MODULE.recovery_field_diagnostics(b'x'*(1024*1024+1),b'')
        # Three public String channels remain separate; caption-only includes
        # either exact caption spelling (with or without its trailing space).
        channel_keys=("staticTexts","nonStaticPrefix","titleFull","titleTrimmed","titleCaption","titleHex",
                      "valueFull","valueTrimmed","valueCaption","valueHex","labelFull","labelTrimmed","labelCaption","labelHex")
        channels=('MRK_NORMAL_RECOVERY_FIELD=v3;phase=awaiting-consent;field=operation-id;sample=pre-check;'
                  +';'.join(key+'='+str(index%6) for index,key in enumerate(channel_keys))+';nonAtomic=1\n').encode()
        for phase in ('awaiting-consent','terminal'):
            for field in ('operation-id','owner-generation','phase','outcome','reason'):
                body=channels.replace(b'awaiting-consent',phase.encode()).replace(b'operation-id',field.encode())
                value=MODULE.recovery_field_diagnostics(body+private,b'')
                self.assertEqual(value['state'],'observed')
                self.assertEqual(value['sample'],dict(zip(channel_keys,(i%6 for i in range(len(channel_keys)))),
                    phase=phase,field=field,timing='pre-check',countsCappedAt=5,nonAtomic=True,source='single-details-snapshot'))
                self.assertNotIn('exactPrefix',value['sample']);self.assertNotIn(b'PRIVATE',MODULE.encoded(value))
        for bad in (channels+valid,legacy+channels,channels+channels,channels[:-1],b'prefix '+channels,
            channels.replace(b'titleFull=2',b'titleFull=6'),channels.replace(b'valueFull=0',b'valueFull=PRIVATE'),
            channels.replace(b';labelHex=1',b''),channels.replace(b'nonAtomic=1',b'nonAtomic=0'),
            channels.replace(b'=v3;',b'=v2;'),valid.replace(b'=v2;',b'=v3;')):
            self.assertEqual(MODULE.recovery_field_diagnostics(bad,b''),dict(state='refused',sample=None))
        self.assertEqual(MODULE.recovery_field_diagnostics(b'',channels),dict(state='refused',sample=None))
        # Pending consent samples expose only fixed-caption counts from one
        # failed original wait. No native names, values or raw messages escape.
        consent_keys=("matches","children","nodes","checkboxes","enabled","identifier","title","label","value",
                      "placeholder","whitespace","nonCheckboxName","unchecked","checked","otherValue")
        consent=(b'MRK_NORMAL_RECOVERY_CONSENT=v1;phase=inspection;sample=post-wait;waiter=timed-out;rootRole=group;'
                 +b';'.join(key.encode()+b'='+str(i%6).encode() for i,key in enumerate(consent_keys))+b';nonAtomic=1\n')
        for phase in (b'inspection',b'account'):
            for role in (b'group',b'static-text',b'checkbox',b'other'):
                body=consent.replace(b'phase=inspection',b'phase='+phase).replace(b'rootRole=group',b'rootRole='+role)
                original=subprocess.CompletedProcess([],65,channels+body+private,b'private stderr')
                observed=MODULE.normal_failure_diagnostics('test',MODULE.IOS_PENDING_RESULT,original)
                expected=dict(zip(consent_keys,(i%6 for i in range(len(consent_keys)))),phase=phase.decode(),waiter='timed-out',
                    rootRole=role.decode(),timing='post-wait',countsCappedAt=5,nonAtomic=True,source='single-review-snapshot',hittability='not-observed')
                self.assertEqual(observed['recoveryConsent'],dict(state='observed',sample=expected))
                self.assertEqual(observed['originalReturncode'],65)
                self.assertLessEqual(len(MODULE.encoded(observed))+1,4096)
                self.assertNotIn(b'private',MODULE.encoded(observed));self.assertNotIn(b'PRIVATE',MODULE.encoded(observed))
        for bad in (consent+consent,consent[:-1],b'prefix '+consent,consent.replace(b'group',b'PRIVATE'),
            consent.replace(b'phase=inspection',b'phase=unknown'),consent.replace(b'matches=0',b'matches=6'),
            consent.replace(b';otherValue=2',b''),consent.replace(b'nonAtomic=1',b'nonAtomic=0'),
            consent.replace(b';sample=post-wait',b';sample=pre-wait'),consent.replace(b'timed-out',b'unknown'),
            consent.replace(b';checked=1',b';checked=private-value')):
            value=MODULE.normal_failure_diagnostics('test',MODULE.IOS_PENDING_RESULT,subprocess.CompletedProcess([],65,bad+private,b''))
            self.assertEqual(value['recoveryConsent'],dict(state='refused',sample=None))
            self.assertTrue(value['findingsTruncated']);self.assertEqual(value['originalReturncode'],65)
            self.assertNotIn(b'PRIVATE',MODULE.encoded(value));self.assertNotIn(b'private-value',MODULE.encoded(value))
        self.assertEqual(MODULE.recovery_consent_diagnostics(b'',consent),dict(state='refused',sample=None))
        self.assertEqual(MODULE.recovery_consent_diagnostics(private,b''),dict(state='absent',sample=None))
        with self.assertRaises(MODULE.Refused): MODULE.recovery_consent_diagnostics(b'x'*(1024*1024+1),b'')
        for phase,selected in (('test','project-test.xcresult'),('test','diagnostics-test.xcresult'),('summary',MODULE.IOS_PENDING_RESULT)):
            value=MODULE.normal_failure_diagnostics(phase,selected,subprocess.CompletedProcess([],65,consent,b''))
            self.assertNotIn('recoveryConsent',value)
        encode_consent=MODULE.encoded
        with patch.object(MODULE,'encoded',side_effect=lambda row: b'x'*4096 if 'recoveryConsent' in row else encode_consent(row)):
            value=MODULE.normal_failure_diagnostics('test',MODULE.IOS_PENDING_RESULT,subprocess.CompletedProcess([],65,consent,b''))
        self.assertNotIn('recoveryConsent',value);self.assertTrue(value['findingsTruncated']);self.assertEqual(value['originalReturncode'],65)

        # The new static-wait marker shares the original project source-site
        # reducer; require/wait duplicates across the same case are refused.
        methods=('testSyntheticProjectPathFields','testSyntheticProjectLocalEditsAndImages')
        def wait_row(method,line=65535):
            return ('MRK_NORMAL_PROJECT_STATIC_WAIT_FAILURE=v1;method='+method+';line='+str(line)+'\n').encode()
        first=wait_row(methods[0],6321); second=wait_row(methods[1])
        unrelated=b'MRK_NORMAL_PROJECT_STAGE=config;result=started\n'
        observed=MODULE.normal_failure_diagnostics('test','project-test.xcresult',subprocess.CompletedProcess([],65,unrelated+first+second+private,b''))
        self.assertEqual([(r['method'],r['line']) for r in observed['sourceFailures']],list(zip(methods,(6321,65535))))
        self.assertEqual(observed['originalReturncode'],65);self.assertNotIn(b'PRIVATE',MODULE.encoded(observed))
        old=first.replace(b'STATIC_WAIT_FAILURE',b'REQUIRE_FAILURE').replace(b'\n',b';check=condition\n')
        self.assertEqual(MODULE.project_require_source_sites(old+second,b'')[0]['line'],6321)
        for bad in (first+first,first+old,first[:-1],b'prefix '+first,wait_row('unselected'),wait_row(methods[0],65536),
            wait_row(methods[0],0),first.replace(b';line=',b';line=0'),first.replace(b'\n',b';check=condition\n'),
            old.replace(b';check=condition',b''),first+b'MRK_NORMAL_PROJECT_STATIC_WAIT',first+b'x'*193+second):
            self.assertIsNone(MODULE.project_require_source_sites(bad,b''))
        self.assertIsNone(MODULE.project_require_source_sites(b'',first))
        self.assertEqual(MODULE.project_require_source_sites(unrelated,b''),[])
        for phase,selected in (('test',MODULE.IOS_PENDING_RESULT),('summary','project-test.xcresult')):
            value=MODULE.normal_failure_diagnostics(phase,selected,subprocess.CompletedProcess([],65,first,b''))
            self.assertEqual(value['sourceFailures'],[])
        swift=SWIFT.read_text()
        observer=swift.split('private func iosRecoveryFieldDiagnostic(',1)[1].split('private func iosRecoveryObservation(',1)[0]
        self.assertEqual(observer.count('try details.snapshot()'),1)
        for source in ('catch { return nil }','children.count <= 64 - visited - pending.count',
            'children.isEmpty || depth < 16','guard staticTexts <= 32','node.value as? String',
            'text == trimmed || text == prefix','bytes.count == 32','clock.observationAllowed(finish, before: end)'):
            self.assertIn(source,observer)
        for forbidden in ('.matching(','.label BEGINSWITH','remaining(','clock.fail(','dictionaryRepresentation','value(forKey:'):
            self.assertNotIn(forbidden,observer)
        reader=swift.split('private func iosRecoveryObservation(',1)[1].split('private func iosRecoverySession(',1)[0]
        self.assertIn('fields.count == 1 ? nil : iosRecoveryFieldDiagnostic(',reader)
        self.assertIn('try require(fields.count == 1, "current recovery field missing or repeated"',reader)
        self.assertNotIn('label BEGINSWITH',reader)
        caught=reader.split('catch {',1)[1].split('let text =',1)[0]
        self.assertIn('throw error',caught);self.assertNotIn('snapshot()',caught)
        original=subprocess.CompletedProcess([],65,channels+consent,b'')
        for mode,selection in (('test','project-test.xcresult'),('test','diagnostics-test.xcresult'),('summary',MODULE.IOS_PENDING_RESULT)):
            self.assertNotIn('recoveryField',MODULE.normal_failure_diagnostics(mode,selection,original))
        # Use actual existing publication; failures remain diagnostics, never
        # change native65 or turn malformed data into a completion receipt.
        with tempfile.TemporaryDirectory() as temporary:
            normal=Path(temporary);request=dict(phase='test',result=normal/MODULE.IOS_PENDING_RESULT,derived=normal/'DerivedData')
            MODULE.publish_failure_diagnostics(request,original)
            published=json.loads((normal/'ios-pending-recovery-test.failure-diagnostics.json').read_bytes())
            self.assertEqual(published['originalReturncode'],65);self.assertEqual(published['recoveryField']['state'],'observed')
            self.assertEqual(published['recoveryConsent']['state'],'observed')
            fallback=normal/'fallback';fallback.mkdir()
            request=dict(request,result=fallback/MODULE.IOS_PENDING_RESULT,derived=fallback/'DerivedData')
            with patch.object(MODULE,'recovery_field_diagnostics',side_effect=RuntimeError('PRIVATE parser fault')):
                MODULE.publish_failure_diagnostics(request,original)
            body=(fallback/'ios-pending-recovery-test.failure-diagnostics.json').read_bytes()
            self.assertEqual(json.loads(body)['recoveryField'],dict(state='absent',sample=None))
            self.assertNotIn(b'PRIVATE',body);self.assertEqual(original.returncode,65)
            consent_fault=normal/'consent-fault';consent_fault.mkdir()
            request=dict(request,result=consent_fault/MODULE.IOS_PENDING_RESULT,derived=consent_fault/'DerivedData')
            with patch.object(MODULE,'recovery_consent_diagnostics',side_effect=RuntimeError('PRIVATE consent parser fault')):
                MODULE.publish_failure_diagnostics(request,original)
            body=(consent_fault/'ios-pending-recovery-test.failure-diagnostics.json').read_bytes()
            self.assertEqual(json.loads(body)['recoveryConsent'],dict(state='absent',sample=None))
            self.assertNotIn(b'PRIVATE',body);self.assertEqual(original.returncode,65)
            with self.assertRaises(MODULE.Refused):
                MODULE.normal_failure_diagnostics('test',MODULE.IOS_PENDING_RESULT,subprocess.CompletedProcess([],0,valid,b''))

    def test_closed_panel_rows_preserve_failure_and_never_disclose_labels(self):
        before = (b"MRK_NORMAL_PANEL_TOPOLOGY=v1;phase=before;waiter=not-run;fields=1;combos=0;search=1;sheets=0;"
            b"fieldLabel=search;fieldPlaceholder=other;comboLabel=none;comboPlaceholder=none;comboChildren=0;nonAtomic=1\n")
        after = before.replace(b"phase=before;waiter=not-run",b"phase=after;waiter=completed").replace(b"combos=0",b"combos=1").replace(b"comboLabel=none",b"comboLabel=folder")
        body = before + after
        observed = MODULE.panel_topology_diagnostics(body, b"private unrelated error text\n")
        self.assertEqual(observed["state"], "observed")
        self.assertEqual([row["phase"] for row in observed["rows"]], ["before", "after"])
        self.assertTrue(all(row["nonAtomic"] and row["countsCappedAt"] == 5 for row in observed["rows"]))
        self.assertEqual(observed["rows"][1]["comboLabel"], "folder")
        self.assertNotIn("private", json.dumps(observed))
        self.assertEqual(MODULE.panel_topology_diagnostics(before.replace(b"\n",b"\r\n"),b"")["state"],"observed")
        self.assertEqual(MODULE.panel_topology_diagnostics(b"unrelated private text\n",b"")["state"],"absent")
        for stdout, stderr in ((b"",before),(after,b""),(before+before,b""),(body+after,b""),
                (before.replace(b"fields=1",b"fields=6"),b""),
                (before.replace(b"fieldLabel=search",b"fieldLabel=private-secret"),b""),
                (before.replace(b"\n",b"\r\r\n"),b""),(before[:-1],b""),
                (before[:20],b""),(b"prefix "+before,b""),
                (after.replace(b"phase=after",b"phase=before"),b"")):
            with self.subTest(stdout=stdout[:30], stderr=bool(stderr)):
                self.assertEqual(MODULE.panel_topology_diagnostics(stdout,stderr),{"state":"refused","rows":[]})
        original = subprocess.CompletedProcess(["xcodebuild"],65,body,b"private unrelated error text\n")
        for selected in MODULE.PANEL_TOPOLOGY_SELECTIONS:
            diagnostic = MODULE.normal_failure_diagnostics("test",selected,original)
            self.assertEqual(diagnostic["originalReturncode"],65)
            self.assertEqual(diagnostic["panelTopology"],observed)
            self.assertLessEqual(len(MODULE.encoded(diagnostic))+1,4096)
            self.assertNotIn("private",json.dumps(diagnostic))
        self.assertNotIn("panelTopology",MODULE.normal_failure_diagnostics("test","persistence-test.xcresult",original))
        self.assertNotIn("panelTopology",MODULE.normal_failure_diagnostics("summary",MODULE.PANEL_TOPOLOGY_SELECTIONS[0],original))
        swift=SWIFT.read_text()
        # Historical bounded rows still decode; the current helper no longer
        # rejects unrelated browse fields or sends a second diagnostic shortcut.
        self.assertNotIn("private func diagnosePanelBaseline(",swift)
        panel=swift.split("private func goToFolder(",1)[1].split("private func nativeOpen(",1)[0]
        self.assertEqual(panel.count('sheet.typeKey("g"'),1)
        self.assertIn("let navigationSheets = sheet.children(matching: .sheet)",panel)
        self.assertLess(panel.index("try require(navigationSheets.count == 0"),panel.index('sheet.typeKey("g"'))
        self.assertLess(panel.index("let navigation = navigationSheets.element(boundBy: 0)"),panel.index("let fields = navigation.textFields"))
        self.assertIn("guard navigationSheets.count == 1 && navigation.exists else { return false }",panel)
        self.assertEqual(panel.count("timeout: try remaining(5)"),1)
        self.assertIn("let combos = navigation.comboBoxes",panel)
        self.assertNotIn("sheet.textFields",panel);self.assertNotIn("sheet.comboBoxes",panel)
        self.assertIn("navigation.exists == false AND cancel.exists == true",panel)
        self.assertIn("navigationSheets.count == 0 && !navigation.exists",panel)
        self.assertIn('path == recoveryFixture.projectPath',panel)
        self.assertIn('settled == .completed && typedValue == path',panel)
        self.assertIn('pasteboard.changeCount == ownedPasteboardGeneration',panel)


if __name__ == "__main__":
    unittest.main()
