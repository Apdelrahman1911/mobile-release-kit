"""Pure source-scoped preview tests: in-memory JSON and mocked no-IO guards.

No fixture files, child processes, native probes, CLI imports, threads, signals,
project execution, credential reads or Store calls. Execution requires separate
approval; source authoring is not a test pass or platform/finality evidence.
"""
from __future__ import annotations

import builtins
import copy
import importlib
import json
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from mobile_release import _desktop_engine as engine
from mobile_release.api import ApiError, execute
from mobile_release.api import _preview as preview
from mobile_release.config import (CONFIGURATION_FIELD_PATHS, ConfigurationError,
                                   ReleaseConfig, default_config, default_config_data,
                                   parse_config_text, validate_config_data)


def draft() -> dict:
    return {
        "schemaVersion": 1,
        "version": {"source": "release/version.properties", "nameKey": "VERSION_NAME", "buildKey": "BUILD_NUMBER"},
        "source": {"candidateBranch": "main", "productionBranch": "main"},
        "android": {"enabled": True, "applicationId": "org.fixture.app", "identityStatus": "unverified"},
        "ios": {"enabled": False},
        "metadata": {"root": "release/store", "androidLocales": ["en-US"], "iosLocales": []},
        "services": {"androidFirebase": "disabled", "iosFirebase": "disabled"},
        "projectChecks": {"preflight": [], "androidArtifact": [], "iosArtifact": []},
    }


def both_platforms() -> dict:
    value = draft()
    value["ios"] = {"enabled": True, "bundleId": "org.fixture.app", "identityStatus": "unverified"}
    value["metadata"]["iosLocales"] = ["en-US"]
    return value


def compare(base, value) -> dict:
    return execute("config.preview", {"base": base, "draft": value})


def contexts(result: dict) -> dict:
    return {item["path"]: item for item in result["fields"]}


class ConfigPreviewTests(unittest.TestCase):
    def test_closed_contract_and_no_authorization_fields(self):
        result = compare(None, draft())
        self.assertEqual(set(result), {"schemaVersion", "validation", "comparison", "fields", "assurance"})
        comparison = result["comparison"]
        self.assertEqual(set(comparison), {"baseProvided", "kind", "state", "semanticallyChanged",
                                           "counts", "changes", "unreviewedCount"})
        self.assertFalse(comparison["baseProvided"])
        self.assertEqual(comparison["kind"], "proposed-create")
        self.assertTrue(comparison["semanticallyChanged"])
        self.assertEqual(comparison["state"], "complete")
        self.assertEqual(set(comparison["counts"]), {"added", "changed", "removed"})
        self.assertEqual(set(contexts(result)), set(CONFIGURATION_FIELD_PATHS))
        self.assertEqual(len(result["fields"]), 40)
        self.assertEqual([item["path"] for item in result["fields"]], sorted(contexts(result)))
        for item in result["fields"]:
            self.assertEqual(set(item), {"path", "state", "present", "reason"})
        self.assertTrue(result["validation"]["valid"])
        self.assertTrue(all(item["state"] == "unknown" for item in result["validation"]["requirements"]))
        self.assertEqual(result["assurance"]["releaseReadiness"], "unknown")
        self.assertFalse(any(value for key, value in result["assurance"].items()
                             if key not in {"basis", "releaseReadiness"}))
        for forbidden in ("revision", "planToken", "rootIdentity", "fileAbsent", "serializedBytes"):
            self.assertNotIn(forbidden, json.dumps(result))

    def test_closed_method_and_parameter_admission(self):
        requests = (
            ("config.preview", {"draft": draft()}),
            ("config.preview", {"base": None, "draft": draft(), "save": True}),
            ("config.preview", {"base": [], "draft": draft()}),
            ("config.preview", {"base": None, "draft": []}),
            ("config.suggest", {}), ("config.suggest", {"hints": {}, "root": "/must-not-open"}),
            ("config.suggest", {"hints": []}), ("config.save", {"draft": draft()}),
        )
        for method, params in requests:
            with self.subTest(method=method), self.assertRaises(ApiError):
                execute(method, params)

    def test_object_order_is_ignored_and_array_order_is_retained(self):
        value = draft()
        value["projectChecks"]["preflight"] = [["./fixed", "first"], ["./fixed", "second"]]
        reordered = {key: ({k: v for k, v in reversed(list(item.items()))} if type(item) is dict else item)
                     for key, item in reversed(list(value.items()))}
        unchanged = compare(value, reordered)["comparison"]
        self.assertFalse(unchanged["semanticallyChanged"])
        self.assertEqual(unchanged["changes"], [])
        changed = copy.deepcopy(value)
        changed["projectChecks"]["preflight"].reverse()
        result = compare(value, changed)["comparison"]
        self.assertTrue(result["semanticallyChanged"])
        self.assertEqual([item["path"] for item in result["changes"]], ["projectChecks.preflight"])
        self.assertEqual(result["changes"][0]["after"], {"present": True, "type": "array", "count": 2})

    def test_comparison_distinguishes_scalar_types_and_absence(self):
        for old, new in ((False, 0), (True, 1), (1, 1.0), (None, ""), ([], {})):
            before, after = draft(), draft()
            before["source"]["projectReadTokenRequired"] = old
            after["source"]["projectReadTokenRequired"] = new
            with self.subTest(old_type=type(old).__name__, new_type=type(new).__name__):
                result = compare(before, after)["comparison"]
                self.assertTrue(result["semanticallyChanged"])
                self.assertEqual(result["counts"], {"added": 0, "changed": 1, "removed": 0})
        value = draft()
        value["source"]["projectReadTokenRequired"] = None
        change = compare(draft(), value)["comparison"]["changes"][0]
        self.assertEqual(change["before"], {"present": False})
        self.assertEqual(change["after"], {"present": True, "type": "null"})
        self.assertEqual(change["operation"], "add")
        removed = compare(value, draft())["comparison"]["changes"][0]
        self.assertEqual(removed["operation"], "remove")
        self.assertEqual(removed["after"], {"present": False})

    def test_known_malformed_containers_and_values_are_not_rebuilt(self):
        before, after = both_platforms(), both_platforms()
        before["ios"]["symbols"] = "private-malformed-value"
        after["ios"]["symbols"] = ["preserve-this-malformed-value"]
        originals = copy.deepcopy((before, after))
        result = compare(before, after)
        self.assertEqual((before, after), originals)
        self.assertFalse(result["validation"]["valid"])
        self.assertEqual(result["comparison"]["changes"], [{
            "path": "ios.symbols", "operation": "change",
            "before": {"present": True, "type": "string"},
            "after": {"present": True, "type": "array", "count": 1},
        }])
        self.assertEqual(contexts(result)["ios.symbols.policy"]["state"], "unknown")
        self.assertNotIn("private-malformed-value", json.dumps(result))
        self.assertNotIn("preserve-this-malformed-value", json.dumps(result))
        empty = draft()
        empty["ios"] = {}
        missing = copy.deepcopy(empty)
        del missing["ios"]
        self.assertEqual(compare(missing, empty)["comparison"]["changes"][0], {
            "path": "ios", "operation": "add", "before": {"present": False},
            "after": {"present": True, "type": "object", "count": 0},
        })

    def test_unknown_changes_are_partial_counted_and_never_named(self):
        before, after = both_platforms(), both_platforms()
        after["sensitive-root-key"] = "sensitive-root-value"
        after["android"]["sensitive-nested-key"] = "sensitive-nested-value"
        after["ios"]["symbols"] = {"policy": "retain", "sensitive-symbol-key": "sensitive-symbol-value"}
        result = compare(before, after)
        self.assertTrue(result["comparison"]["semanticallyChanged"])
        self.assertEqual(result["comparison"]["state"], "partial")
        self.assertEqual(result["comparison"]["unreviewedCount"], 3)
        self.assertNotIn("sensitive-", json.dumps(result))
        only_unknown = copy.deepcopy(before)
        only_unknown["unknown-key"] = ["unknown-value"]
        result = compare(before, only_unknown)["comparison"]
        self.assertTrue(result["semanticallyChanged"])
        self.assertEqual(result["changes"], [])
        self.assertEqual(result["unreviewedCount"], 1)
        self.assertEqual(result["state"], "partial")

    def test_argv_values_and_invalid_key_text_do_not_leave_preview(self):
        before, after = draft(), draft()
        after["projectChecks"]["preflight"] = [["/do-not-run-private-executable", "secret-argument-marker"]]
        result = compare(before, after)
        self.assertTrue(result["validation"]["valid"])
        rendered = json.dumps(result)
        self.assertNotIn("secret-argument-marker", rendered)
        self.assertNotIn("/do-not-run-private-executable", rendered)
        after["untrusted\nkey-secret-marker"] = {"raw": "private-value-marker"}
        result = compare(before, after)
        rendered = json.dumps(result)
        self.assertFalse(result["validation"]["valid"])
        self.assertNotIn("key-secret-marker", rendered)
        self.assertNotIn("private-value-marker", rendered)
        self.assertNotIn("\n", result["validation"]["issues"][0]["message"])

    def test_disabled_and_malformed_platform_controllers_preserve_dependent_fields(self):
        for controller, expected in ((False, "forbidden"), (0, "unknown"), (1, "unknown"),
                                     ("false", "unknown"), ([], "unknown"), ({}, "unknown"), (None, "unknown")):
            value = both_platforms()
            value["android"]["enabled"] = controller
            original = copy.deepcopy(value)
            result = compare(original, value)
            field = contexts(result)["android.applicationId"]
            with self.subTest(controller_type=type(controller).__name__):
                self.assertEqual(field["state"], expected)
                self.assertTrue(field["present"])
                self.assertFalse(result["validation"]["valid"])
                self.assertEqual(value, original)

    def test_approved_identity_and_nested_members_follow_shared_policy(self):
        value = both_platforms()
        for platform in ("android", "ios"):
            value[platform]["identityStatus"] = "approved"
        result = contexts(compare(draft(), value))
        for path in ("android.externalTrack.name", "android.externalTrack.kind", "android.uploadCertificateSha256",
                     "ios.appStoreAppId", "ios.teamId", "ios.externalTestFlightGroup",
                     "ios.distributionCertificateSha256", "ios.symbols.policy", "ios.review.demoAccountRequired"):
            self.assertEqual(result[path]["state"], "required", path)
        value["android"]["identityStatus"] = {}
        self.assertEqual(contexts(compare(None, value))["android.uploadCertificateSha256"]["state"], "unknown")
        value = both_platforms()
        value["android"]["externalTrack"] = {}
        value["ios"]["review"] = {}
        result = contexts(compare(None, value))
        self.assertEqual(result["android.externalTrack.kind"]["state"], "required")
        self.assertEqual(result["ios.review.usesNonExemptEncryption"]["state"], "required")

    def test_workspace_and_symbols_conditions_are_explicit_not_destructive(self):
        value = both_platforms()
        value["ios"].update({"project": "App.xcodeproj", "workspace": "App.xcworkspace"})
        original = copy.deepcopy(value)
        result = contexts(compare(None, value))
        self.assertEqual(result["ios.project"]["state"], "forbidden")
        self.assertEqual(result["ios.workspace"]["state"], "forbidden")
        self.assertEqual(value, original)
        for policy, expected in (("required", "required"), ("retain", "forbidden"),
                                 ("disabled", "forbidden"), ([], "unknown"), (None, "unknown")):
            value["ios"]["symbols"] = {"policy": policy, "uploadCommand": ["./not-executed"]}
            result = contexts(compare(None, value))
            self.assertEqual(result["ios.symbols.uploadCommand"]["state"], expected)
            self.assertTrue(result["ios.symbols.uploadCommand"]["present"])

    def test_required_optional_and_present_empty_values_are_not_conflated(self):
        value = draft()
        value["source"]["projectReadTokenRequired"] = False
        result = contexts(compare(None, value))
        self.assertEqual(result["source.projectReadTokenRequired"]["state"], "optional")
        self.assertTrue(result["source.projectReadTokenRequired"]["present"])
        self.assertEqual(result["metadata.iosLocales"]["state"], "required")
        self.assertTrue(result["metadata.iosLocales"]["present"])
        self.assertEqual(result["projectChecks.preflight"]["state"], "required")
        self.assertEqual(result["$schema"]["state"], "optional")
        self.assertFalse(result["$schema"]["present"])

    def test_shared_validation_and_default_proposal_compatibility(self):
        hints = {"android": {"applicationId": "org.fixture.app"}, "versionSource": "version.properties"}
        with patch.object(Path, "resolve", side_effect=AssertionError("root resolution")), \
             patch.object(Path, "stat", side_effect=AssertionError("root inspection")):
            self.assertEqual(default_config(Path("/unconsumed/root"), hints), default_config_data(hints))
        candidates = [draft(), both_platforms()]
        invalid = draft()
        invalid["android"]["enabled"] = False
        candidates.append(invalid)
        invalid = draft()
        invalid["schemaVersion"] = 1.0
        candidates.append(invalid)
        for value in candidates:
            try:
                validate_config_data(value)
                valid = True
            except ConfigurationError:
                valid = False
            self.assertEqual(compare(None, value)["validation"]["valid"], valid)
            if valid:
                self.assertEqual(parse_config_text(json.dumps(value)), value)

    def test_suggestions_distinguish_no_platform_hints_defaults_and_examples(self):
        result = execute("config.suggest", {"hints": {}})
        self.assertEqual(set(result), {"schemaVersion", "draft", "platformSelectionRequired", "provenance", "validation", "assurance"})
        self.assertTrue(result["platformSelectionRequired"])
        self.assertEqual(result["draft"]["android"], {"enabled": False})
        self.assertEqual(result["draft"]["ios"], {"enabled": False})
        self.assertFalse(result["validation"]["valid"])
        self.assertTrue(all(item["source"] == "default" for item in result["provenance"]))
        result = execute("config.suggest", {"hints": {"platforms": ["android"]}})
        self.assertFalse(result["platformSelectionRequired"])
        self.assertEqual(result["draft"]["android"]["identityStatus"], "unverified")
        self.assertTrue(result["validation"]["valid"])
        provenance = {item["path"]: item["source"] for item in result["provenance"]}
        self.assertEqual(provenance["android.applicationId"], "example")
        self.assertEqual(provenance["android.enabled"], "hint")
        self.assertEqual(provenance["source.candidateBranch"], "default")

    def test_suggestion_closed_scalar_hints_are_preserved_and_policy_checked(self):
        hints = {"platforms": ["ios", "android"], "androidApplicationId": "org.fixture.app",
                 "iosBundleId": "org.fixture.app", "versionSource": "version.properties",
                 "versionNameKey": "APP_VERSION_NAME", "versionBuildKey": "APP_BUILD_NUMBER"}
        original = copy.deepcopy(hints)
        result = execute("config.suggest", {"hints": hints})
        self.assertEqual(hints, original)
        self.assertTrue(result["validation"]["valid"])
        self.assertEqual(result["draft"]["version"], {"source": "version.properties", "nameKey": "APP_VERSION_NAME", "buildKey": "APP_BUILD_NUMBER"})
        self.assertEqual(result["draft"]["ios"]["bundleId"], "org.fixture.app")
        self.assertTrue(all(item["source"] != "example" for item in result["provenance"]))
        result = execute("config.suggest", {"hints": {"platforms": ["android"], "versionSource": "../never-open"}})
        self.assertFalse(result["validation"]["valid"])

    def test_invalid_hints_refuse_without_echoing_keys_or_values(self):
        for hints in (
            {"root-secret-marker": "/path-secret-marker"}, {1: "private"},
            {"platforms": ["android", "android"]}, {"platforms": [True]}, {"platforms": "android"},
            {"androidApplicationId": "org.fixture.app"}, {"versionSource": {"private": "value"}},
            {"versionSource": "line\nbreak"}, {"versionSource": "\ud800"},
            {"versionSource": ""}, {"versionSource": "é" * 257},
        ):
            with self.subTest(hints_type=type(hints).__name__), self.assertRaises(ApiError) as caught:
                execute("config.suggest", {"hints": hints})
            self.assertEqual(caught.exception.code, "invalid_params")
            self.assertNotIn("secret-marker", caught.exception.message)

    def test_documents_pair_depth_nodes_and_non_json_values_are_bounded(self):
        # Root depth is zero: a scalar at the declared limit is admissible,
        # but even an empty additional container at that depth must reject.
        scalar_at_limit = 0
        for _ in range(preview.MAX_DOCUMENT_DEPTH - 1):
            scalar_at_limit = [scalar_at_limit]
        at_limit = {"extra": scalar_at_limit}
        self.assertFalse(compare(at_limit, at_limit)["comparison"]["semanticallyChanged"])
        for empty in ({}, []):
            at_container_limit = empty
            for _ in range(preview.MAX_DOCUMENT_DEPTH - 1):
                at_container_limit = [at_container_limit]
            with self.assertRaises(ApiError) as caught:
                compare(None, {"extra": at_container_limit})
            self.assertEqual(caught.exception.code, "invalid_params")
        deep = 0
        for _ in range(30):
            deep = [deep]
        cyclic = []
        cyclic.append(cyclic)
        for invalid in ({"extra": "x" * (512 * 1024)}, {"extra": [0] * 8_000},
                        {"extra": deep}, {"extra": cyclic}, {"extra": object()},
                        {"extra": float("inf")}, {"extra": float("nan")}, {"extra": "\ud800"}):
            for base_side in (False, True):
                with self.subTest(base_side=base_side), self.assertRaises(ApiError) as caught:
                    compare(invalid if base_side else draft(), draft() if base_side else invalid)
                self.assertEqual(caught.exception.code, "invalid_params")
        with self.assertRaises(ApiError) as caught:
            compare({"extra": "x" * (400 * 1024)}, {"extra": "y" * (400 * 1024)})
        self.assertEqual(caught.exception.code, "invalid_params")

    def test_output_change_and_field_overflow_refuse_instead_of_truncating(self):
        for limit in ("MAX_RESULT_BYTES", "MAX_FIELDS", "MAX_CHANGES"):
            with patch.object(preview, limit, 0), self.subTest(limit=limit), self.assertRaises(ApiError) as caught:
                compare(None, draft())
            self.assertEqual(caught.exception.code, "preview_output_limit")
        with patch.object(preview, "MAX_RESULT_BYTES", 0), self.assertRaises(ApiError) as caught:
            execute("config.suggest", {"hints": {}})
        self.assertEqual(caught.exception.code, "preview_output_limit")

    def test_methods_are_portable_and_never_consume_files_or_execute_commands(self):
        value = draft()
        value["$schema"] = "https://must-not-fetch.invalid/schema.json"
        value["projectChecks"]["preflight"] = [["./must-not-execute"]]
        with patch.object(sys, "platform", "win32"), \
             patch.object(builtins, "open", side_effect=AssertionError("filesystem open")), \
             patch.object(os, "open", side_effect=AssertionError("descriptor open")), \
             patch.object(os, "system", side_effect=AssertionError("shell execution")), \
             patch.object(Path, "open", side_effect=AssertionError("path read")), \
             patch.object(ReleaseConfig, "project_path", side_effect=AssertionError("project read")), \
             patch.object(ReleaseConfig, "release_version", side_effect=AssertionError("version read")):
            methods = {item["method"]: item["available"] for item in execute("capabilities", {})["methods"]}
            self.assertTrue(methods["config.preview"] and methods["config.suggest"])
            self.assertEqual(methods["project.snapshot"], os.name == "nt")
            self.assertTrue(compare(None, value)["validation"]["valid"])
            execute("config.suggest", {"hints": {"platforms": ["android"]}})
            self.assertTrue(all(not item["available"] for item in execute("capabilities", {})["actions"]))

    def test_fresh_import_graph_and_engine_allowlist_stay_passive(self):
        forbidden = {
            "mobile_release.cli", "mobile_release.credentials", "mobile_release.cancellation",
            "mobile_release.owned_process", "mobile_release._native_process", "mobile_release._command_process",
            "mobile_release._profile_process", "mobile_release.build_inputs",
            "mobile_release.local_signing", "mobile_release.preflight", "mobile_release.android",
            "mobile_release.ios", "mobile_release.stores", "mobile_release.workflow",
        }
        native_forbidden = {"ctypes", "_ctypes", "fcntl"}

        class Guard:
            def find_spec(self, fullname, path=None, target=None):
                if fullname in forbidden or fullname.split(".", 1)[0] in native_forbidden:
                    raise AssertionError("forbidden runtime import")
                return None

        with patch.dict(sys.modules):
            for name in tuple(sys.modules):
                if (name == "mobile_release" or name.startswith("mobile_release.")
                        or name.split(".", 1)[0] in native_forbidden):
                    del sys.modules[name]
            with patch.object(sys, "meta_path", [Guard(), *sys.meta_path]), \
                 patch.object(os, "register_at_fork", create=True, side_effect=AssertionError("fork hook")), \
                 patch.object(builtins, "open", side_effect=AssertionError("filesystem open")), \
                 patch.object(os, "open", side_effect=AssertionError("descriptor open")), \
                 patch.object(os, "mkdir", side_effect=AssertionError("directory creation")), \
                 patch.object(os, "rename", side_effect=AssertionError("filesystem rename")), \
                 patch.object(os, "unlink", side_effect=AssertionError("filesystem unlink")), \
                 patch.object(os, "rmdir", side_effect=AssertionError("directory removal")), \
                 patch.object(os, "system", side_effect=AssertionError("shell execution")), \
                 patch.object(Path, "open", side_effect=AssertionError("path read")):
                fresh = importlib.import_module("mobile_release.api")
                # M1 admits this module only for passive reserved-name facts.
                # That exception must not admit native binding or a workspace.
                transaction = sys.modules["mobile_release.init_transaction"]
                discovery = sys.modules["mobile_release.discovery"]
                self.assertIs(discovery.STATE_NAMES, transaction.STATE_NAMES)
                self.assertIs(discovery.is_state_name, transaction.is_state_name)
                with patch.object(transaction.InitWorkspace, "__init__", side_effect=AssertionError("transaction execution")), \
                     patch.object(transaction.InitWorkspace, "__enter__", side_effect=AssertionError("transaction execution")), \
                     patch.object(transaction.InitWorkspace, "observe", side_effect=AssertionError("transaction execution")), \
                     patch.object(transaction.InitWorkspace, "apply", side_effect=AssertionError("transaction execution")), \
                     patch.object(transaction.InitWorkspace, "recover", side_effect=AssertionError("transaction execution")), \
                     patch.object(transaction, "_rename_function", side_effect=AssertionError("native binding")):
                    fresh.execute("config.preview", {"base": None, "draft": draft()})
                    fresh.execute("config.suggest", {"hints": {}})
                    self.assertFalse(forbidden & set(sys.modules))
                    self.assertFalse(native_forbidden & {name.split(".", 1)[0] for name in sys.modules})
                    with self.assertRaisesRegex(AssertionError, "forbidden runtime import"):
                        importlib.import_module("mobile_release.cli")
                    with self.assertRaisesRegex(AssertionError, "forbidden runtime import"):
                        importlib.import_module("ctypes")
                    # Negative control invokes only the patched constructor.
                    with self.assertRaisesRegex(AssertionError, "transaction execution"):
                        transaction.InitWorkspace(Path("/must-not-open"))
        for method, params in (("config.preview", {"base": None, "draft": draft()}),
                               ("config.suggest", {"hints": {}})):
            raw = json.dumps({"protocol": 1, "id": "pure", "method": method, "params": params}, separators=(",", ":")).encode() + b"\n"
            request = engine.parse_request(raw)
            self.assertEqual(request.method, method)
            self.assertEqual(request.params, params)


if __name__ == "__main__":
    unittest.main()
