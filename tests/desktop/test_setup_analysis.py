"""Small inert setup-guidance tests: no project execution/native/Store evidence."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

from mobile_release.api._setup_analysis import analyze_setup, MAX_RESULT_BYTES
from mobile_release.api.contracts import ApiError
from mobile_release.config import default_config_data, ReleaseConfig
from mobile_release.discovery import parse_project_sources


def hints() -> dict:
    return parse_project_sources({
        "app/build.gradle.kts": 'plugins { id("com.android.application") }\nandroid { namespace = "org.example.code"\n defaultConfig { applicationId = "org.example.app" } }',
        "release/version.properties": "VERSION_NAME=1.0.0\nBUILD_NUMBER=1\n",
    }, ())


def rows(result: dict) -> dict:
    return {row["id"]: row for row in result["requirements"]}


class SetupAnalysisTests(unittest.TestCase):
    def test_shared_static_selectors_local_first_and_no_io(self):
        found = hints()
        self.assertEqual(found["android"]["applicationId"], "org.example.app")
        config = default_config_data(found)
        original = copy.deepcopy((config, found))
        config["projectChecks"]["preflight"] = [["./never-execute"]]
        with patch.object(os, "open", side_effect=AssertionError("file open")), \
             patch.object(Path, "read_text", side_effect=AssertionError("file read")), \
             patch.object(subprocess, "Popen", side_effect=AssertionError("process")), \
             patch.object(ReleaseConfig, "release_version", side_effect=AssertionError("version read")):
            result = analyze_setup("format-valid", config, found, partial=False)
        data = rows(result)
        self.assertEqual(data["android-identity"]["field"], "android.applicationId")
        self.assertEqual(data["android-module"]["state"], "detected")
        self.assertEqual(data["android-store"]["state"], "deferred")
        self.assertEqual(data["android-tools"]["state"], "not-checked")
        self.assertEqual(data["android-signing"]["state"], "not-checked")
        self.assertEqual(result["assurance"]["releaseReadiness"], "unknown")
        self.assertTrue(all(value is False for key, value in result["assurance"].items() if key not in {"basis", "releaseReadiness"}))
        config["projectChecks"]["preflight"] = []
        self.assertEqual((config, found), original)
        encoded = json.dumps(result)
        for private_value in ("org.example.app", "org.example.code", "never-execute"):
            self.assertNotIn(private_value, encoded)
        self.assertLess(len(encoded.encode()), MAX_RESULT_BYTES)
        for unrelated in ({}, {"ios": {"projects": ["Other.xcodeproj"]}}):
            self.assertNotEqual(rows(analyze_setup("format-valid", config, unrelated, partial=False))["project-layout"]["state"], "detected")

    def test_missing_and_partial_are_guidance_not_invented_configuration(self):
        complete = rows(analyze_setup("missing", None, {}, partial=False))
        partial = rows(analyze_setup("missing", None, {}, partial=True))
        self.assertEqual(complete["project-layout"]["state"], "needs-input")
        self.assertEqual(partial["project-layout"]["state"], "unverified")
        self.assertEqual(partial["version-source"]["state"], "unverified")
        self.assertNotIn("android-identity", complete)
        self.assertEqual(rows(analyze_setup("unavailable", None, hints(), partial=True))["release-settings"]["state"], "unverified")
        result = analyze_setup("missing", None, hints(), partial=False)
        self.assertEqual(rows(result)["android-identity"]["state"], "detected")
        self.assertNotIn("com.example.product", json.dumps(result))

    def test_ambiguous_android_requires_explicit_module_not_namespace(self):
        found = {"android": {"ambiguous": True, "candidates": [
            {"module": ":one", "buildFile": "one/build.gradle.kts", "namespace": "org.example.code"},
            {"module": ":two", "buildFile": "two/build.gradle", "applicationId": "org.example.other"},
        ]}}
        data = rows(analyze_setup("missing", None, found, partial=False))
        self.assertEqual(data["android-module"]["state"], "ambiguous")
        self.assertEqual(data["android-identity"]["state"], "ambiguous")
        config = default_config_data(found)
        config["android"]["module"] = ":two"
        data = rows(analyze_setup("format-valid", config, found, partial=False))
        self.assertEqual(data["android-module"]["state"], "configured")
        self.assertEqual(data["android-module"]["reference"], "two/build.gradle")
        no_id = rows(analyze_setup("missing", None, {"android": found["android"]["candidates"][0]}, partial=False))
        self.assertEqual(no_id["android-identity"]["state"], "needs-input")
        pruned = rows(analyze_setup("missing", None, {"android": {"ambiguous": True}}, partial=True))
        self.assertEqual(pruned["android-module"]["state"], "ambiguous")

    def test_ios_conventional_and_generated_layouts_remain_explicit(self):
        found = {"ios": {"projects": ["App.xcodeproj"], "project": "App.xcodeproj", "workspaces": [],
            "schemes": ["App"], "scheme": "App", "bundleIds": ["org.example.app"], "bundleId": "org.example.app", "generatedProjectSources": []}}
        data = rows(analyze_setup("missing", None, found, partial=False))
        self.assertEqual(data["ios-container"]["reference"], "App.xcodeproj")
        self.assertEqual(data["ios-scheme"]["state"], "detected")
        self.assertEqual(data["ios-store"]["state"], "deferred")
        generated = {"ios": {"projects": [], "workspaces": [], "schemes": [], "bundleIds": [], "generatedProjectSources": ["Project.swift"]}}
        data = rows(analyze_setup("missing", None, generated, partial=False))
        self.assertEqual(data["ios-container"]["state"], "unsupported")
        self.assertEqual(data["ios-container"]["reference"], "Project.swift")
        incomplete = rows(analyze_setup("missing", None, generated, partial=True))["ios-container"]
        self.assertEqual(incomplete["state"], "unverified")
        self.assertNotIn("Produce", incomplete["summary"])
        config = default_config_data(found)
        config["ios"]["identityStatus"] = "blocked"
        self.assertEqual(rows(analyze_setup("format-valid", config, found, partial=False))["ios-store"]["state"], "blocked")

    def test_schema_is_not_relaxed_and_disabled_platform_not_resurrected(self):
        found = hints()
        config = default_config_data(found)
        config["android"]["externalTrack"] = {"kind": "invalid", "name": "alpha"}
        with self.assertRaises(ApiError):
            analyze_setup("format-valid", config, found, partial=False)
        config = default_config_data(found)
        config["android"]["identityStatus"] = "approved"
        with self.assertRaises(ApiError):
            analyze_setup("format-valid", config, found, partial=False)
        config = default_config_data(found)
        config["android"] = {"enabled": False}
        config["ios"] = {"enabled": True, "bundleId": "org.example.app", "identityStatus": "unverified"}
        config["metadata"]["iosLocales"] = ["en-US"]
        result = analyze_setup("format-valid", config, found, partial=False)
        self.assertEqual(result["platforms"], ["ios"])
        self.assertNotIn("android-tools", rows(result))
        self.assertEqual(rows(analyze_setup("invalid", None, found, partial=False))["release-settings"]["state"], "needs-input")

    def test_closed_bounds_and_safe_display_references(self):
        for state, config, found, partial in (
            ("valid", None, {}, False), ("missing", {}, {}, False), ("missing", None, {}, 1),
            ("missing", None, {"android": None}, False), ("missing", None, {"ios": None}, False),
            ("missing", None, {"run": "command"}, False), ("missing", None, {"android": {"module": []}}, False),
            ("missing", None, {"ios": {"schemes": ["x"] * 129}}, False),
        ):
            with self.subTest(found=found), self.assertRaises(ApiError):
                analyze_setup(state, config, found, partial=partial)
        for path in ("../foreign", "/absolute", "a//b", "C:/foreign", "a/./b", "a\\b"):
            found = {"android": {"module": "app", "buildFile": path}}
            self.assertIsNone(rows(analyze_setup("missing", None, found, partial=False))["android-module"]["reference"])


if __name__ == "__main__":
    unittest.main()
