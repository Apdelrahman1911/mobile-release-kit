"""Passive environment contracts and fixed-source pin joins; no native tools.

Tests use in-memory synthetic drafts. Only the pin-source guard reads known
repository source files; it never imports historical execution modules.
"""
from __future__ import annotations

import ast
import copy
import json
import os
import shutil
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from mobile_release import _desktop_engine as engine, toolchain_policy as pins
from mobile_release.api import ApiError, METHODS, execute
from mobile_release.api import _environment as environment

SOURCE = Path(__file__).resolve().parents[2]
EXPECTED = {
    ("android", "build"): ["android-jdk", "android-gradle-wrapper", "android-sdk"],
    ("android", "artifact-validation"): ["android-jdk", "android-bundletool"],
    ("ios", "build"): ["apple-macos", "apple-xcode", "apple-signing-tools"],
    ("ios", "artifact-validation"): ["apple-macos", "apple-codesign", "apple-openssl", "apple-security-framework"],
}


def draft() -> dict:
    return {
        "schemaVersion": 1,
        "version": {"source": "release/version.properties", "nameKey": "VERSION_NAME", "buildKey": "BUILD_NUMBER"},
        "source": {"candidateBranch": "main", "productionBranch": "main"},
        "android": {"enabled": True, "applicationId": "org.inert.environment", "identityStatus": "unverified"},
        "ios": {"enabled": True, "bundleId": "org.inert.environment", "identityStatus": "unverified"},
        "metadata": {"root": "release/store", "androidLocales": ["en-US"], "iosLocales": ["en-US"]},
        "services": {"androidFirebase": "disabled", "iosFirebase": "disabled"},
        "projectChecks": {"preflight": [], "androidArtifact": [], "iosArtifact": []},
    }


def request(platform="android", operation="build", **overrides) -> dict:
    return {"draft": draft(), "platform": platform, "operation": operation, **overrides}


class EnvironmentRequirementsTests(unittest.TestCase):
    def test_context_role_sets_help_and_never_verified_assurance(self):
        for context, expected in EXPECTED.items():
            with self.subTest(context=context):
                result = execute("environment.requirements", request(*context))
                self.assertEqual([row["id"] for row in result["requirements"]], expected)
                self.assertEqual(result["context"], dict(zip(("platform", "operation"), context)))
                self.assertEqual(result["state"], "requirements-only")
                self.assertTrue(result["platformEnabled"])
                self.assertEqual(result["coverage"], "toolchain-prerequisites-only")
                self.assertEqual(result["nativeInspection"], "unavailable")
                self.assertEqual(result["dependencyCompleteness"], "unknown")
                self.assertEqual(result["assurance"], {
                    "basis": "schema-policy", "projectCodeExecuted": False, "toolsProbed": False,
                    "credentialsRead": False, "gitObserved": False, "storeContacted": False,
                    "writesPerformed": False, "releaseReadiness": "unknown",
                })
                for row in result["requirements"]:
                    self.assertEqual((row["presence"], row["versionState"], row["inspection"]), ("unknown", "unknown", "not-run"))
                    self.assertEqual(set(row["baseline"]), {"kind", "version", "build", "sha256", "maxBytes"})
                    self.assertNotIn("observedVersion", row)
                for help_value in [*result["help"].values(), *(row["help"] for row in result["requirements"])]:
                    self.assertEqual(set(help_value), {"label", "requiredness", "requiredWhen", "what", "why", "where", "format", "failure"})
                    self.assertTrue(all(type(value) is str and 0 < len(value.encode("utf-8")) <= 1024 for value in help_value.values()))
                frame = engine.encode_response(engine.Request("e" * 64, "environment.requirements", request(*context)), result=result)
                self.assertTrue(frame.endswith(b"\n"))
                self.assertLessEqual(len(frame), 65_536)

    def test_disabled_platform_is_explicit_not_a_successful_environment_check(self):
        for platform in ("android", "ios"):
            value = draft()
            value[platform] = {"enabled": False}
            for operation in ("build", "artifact-validation"):
                with self.subTest(platform=platform, operation=operation):
                    result = execute("environment.requirements", request(platform, operation, draft=value))
                    self.assertEqual(result["requirements"], [])
                    self.assertFalse(result["platformEnabled"])
                    self.assertEqual(result["state"], "platform-disabled")
                    self.assertEqual(result["assurance"]["releaseReadiness"], "unknown")

    def test_host_observation_cannot_be_replaced_by_the_intended_platform(self):
        for actual, expected in (("linux", "linux"), ("darwin", "macos"), ("win32", "windows"), ("inert", "other")):
            with self.subTest(host=actual), patch.object(sys, "platform", actual):
                result = execute("environment.requirements", request("ios", "artifact-validation"))
                self.assertEqual(result["hostPlatform"], expected)
                self.assertEqual(result["context"]["platform"], "ios")
                self.assertTrue(all(row["presence"] == "unknown" for row in result["requirements"]))

    def test_request_refusals_are_closed_and_do_not_reflect_fields_or_exceptions(self):
        for value in (None, [], {"private-field-sentinel": True}, request(platform=[]), request(operation="PRIVATE_OPERATION"),
                      request(draft=[]), request(hostPlatform="PRIVATE_HOST"), {**request(), 1: "PRIVATE_VALUE"}):
            with self.subTest(kind=type(value).__name__), self.assertRaises(ApiError) as refused:
                execute("environment.requirements", value)
            self.assertEqual((refused.exception.code, refused.exception.message), ("environment_request_invalid", environment.REQUEST_ERROR))

    def test_invalid_deep_oversize_and_python_only_drafts_have_one_fixed_error(self):
        deep = {}
        cursor = deep
        for _ in range(34):
            cursor["next"] = {}
            cursor = cursor["next"]
        cyclic = {}
        cyclic["same"] = cyclic
        invalid = [dict(draft(), PRIVATE_FIELD_SENTINEL="PRIVATE_VALUE_SENTINEL"), {},
                   dict(draft(), schemaVersion=True), dict(draft(), secret="x" * (512 * 1024)),
                   dict(draft(), nested=deep), dict(draft(), python_only=object()),
                   dict(draft(), invalid_unicode="\ud800"), cyclic]
        for value in invalid:
            with self.subTest(kind=list(value)[:1]), self.assertRaises(ApiError) as refused:
                execute("environment.requirements", request(draft=value))
            self.assertEqual((refused.exception.code, refused.exception.message), ("environment_draft_invalid", environment.DRAFT_ERROR))

    def test_valid_private_like_configuration_is_not_returned_and_no_io_occurs(self):
        value = draft()
        value["version"]["source"] = "release/PRIVATE_SOURCE_SENTINEL.properties"
        value["projectChecks"]["preflight"] = [["private-command-sentinel", "PRIVATE_ARG_SENTINEL"]]
        with patch.object(os, "open", side_effect=AssertionError("file open")), \
             patch.object(os, "stat", side_effect=AssertionError("file stat")), \
             patch.object(Path, "open", side_effect=AssertionError("path open")), \
             patch.object(os, "getenv", side_effect=AssertionError("environment lookup")), \
             patch.object(shutil, "which", side_effect=AssertionError("tool lookup")), \
             patch.object(subprocess, "Popen", side_effect=AssertionError("process creation")):
            result = execute("environment.requirements", request(draft=value))
        output = json.dumps(result)
        for sentinel in ("PRIVATE_SOURCE_SENTINEL", "private-command-sentinel", "PRIVATE_ARG_SENTINEL", "org.inert.environment"):
            self.assertNotIn(sentinel, output)

    def test_exact_pins_framework_help_and_context_specific_baselines(self):
        android = execute("environment.requirements", request("android", "artifact-validation"))
        self.assertEqual(android["requirements"][1]["baseline"], {
            "kind": "exact-pin", "version": pins.BUNDLETOOL_VERSION, "build": None,
            "sha256": pins.BUNDLETOOL_SHA256, "maxBytes": pins.BUNDLETOOL_MAX_BYTES,
        })
        self.assertEqual(android["requirements"][0]["baseline"]["kind"], "workflow-reference")
        self.assertIn("not a universal", android["requirements"][0]["help"]["format"])
        ios = execute("environment.requirements", request("ios"))
        self.assertEqual(ios["requirements"][1]["baseline"], {
            "kind": "exact-pin", "version": pins.XCODE_VERSION, "build": pins.XCODE_BUILD, "sha256": None, "maxBytes": None,
        })
        self.assertEqual(ios["requirements"][2]["help"]["requiredness"], "conditional")
        inspection = execute("environment.requirements", request("ios", "artifact-validation"))
        self.assertTrue(all(row["baseline"]["kind"] == "platform-defined" for row in inspection["requirements"]))
        self.assertIn("CoreFoundation", inspection["requirements"][-1]["help"]["what"] + inspection["requirements"][-1]["help"]["format"])

    def test_response_mutation_and_oversize_help_do_not_change_core_policy(self):
        result = execute("environment.requirements", request())
        original = copy.deepcopy(result)
        result["requirements"][0]["help"]["label"] = "caller mutation"
        result["requirements"][0]["baseline"]["version"] = "caller version"
        self.assertEqual(execute("environment.requirements", request()), original)
        with patch.object(environment, "_RESULT_LIMIT", 16), self.assertRaises(ApiError) as refused:
            execute("environment.requirements", request())
        self.assertEqual((refused.exception.code, refused.exception.message), ("environment_unavailable", environment.UNAVAILABLE_ERROR))

    def test_pin_extraction_preserves_all_original_names_without_importing_callers(self):
        expected = {"XCODE_VERSION": "26.3", "XCODE_BUILD": "17C529", "BUNDLETOOL_VERSION": "1.18.3",
                    "BUNDLETOOL_SHA256": "a099cfa1543f55593bc2ed16a70a7c67fe54b1747bb7301f37fdfd6d91028e29",
                    "BUNDLETOOL_MAX_BYTES": 32_520_401}
        self.assertEqual({key: getattr(pins, key) for key in expected}, expected)
        callers = {
            "preflight.py": {"XCODE_VERSION": "XCODE_VERSION", "XCODE_BUILD": "XCODE_BUILD"},
            "android.py": {"BUNDLETOOL_VERSION": "BUNDLETOOL_VERSION", "BUNDLETOOL_SHA256": "BUNDLETOOL_SHA256"},
            "checked_files.py": {key: key for key in expected if key.startswith("BUNDLETOOL")},
            "build_inputs.py": {"BUNDLETOOL_MAX_BYTES": "_BUNDLETOOL_BYTES", "BUNDLETOOL_SHA256": "_BUNDLETOOL_SHA256"},
        }
        for filename, aliases in callers.items():
            tree = ast.parse((SOURCE / "src/mobile_release" / filename).read_text(encoding="utf-8"))
            imports = {item.name: item.asname or item.name for node in tree.body if isinstance(node, ast.ImportFrom) and node.module == "toolchain_policy" for item in node.names}
            with self.subTest(filename=filename):
                self.assertEqual(imports, aliases)
                self.assertFalse({target.id for node in tree.body if isinstance(node, ast.Assign) for target in node.targets if isinstance(target, ast.Name)} & set(aliases.values()))
        for workflow in ("reusable-preflight.yml", "reusable-candidate.yml"):
            source = (SOURCE / ".github/workflows" / workflow).read_text(encoding="utf-8")
            self.assertIn("distribution: temurin", source)
            self.assertIn("java-version: '21'", source)

    def test_api_and_transport_agree_on_exactly_one_new_passive_method(self):
        self.assertEqual(set(METHODS), engine.METHODS)
        self.assertEqual(len(METHODS), 11)
        caps = execute("capabilities", {})
        self.assertEqual([row for row in caps["methods"] if row["method"] == "environment.requirements"][0]["available"], True)
        self.assertTrue(all(not row["available"] for row in caps["actions"]))
