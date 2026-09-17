"""Inert desktop API contracts only; never import historical/native test suites.

Fixtures are small task-owned ordinary files, links and in-memory dictionaries.
No child process, project code, native validator, signal or Store call is run.
Special-file and cleanup failures are mocked contracts, not native finality proof.
"""
from __future__ import annotations

import copy
import importlib
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import Mock, patch

from mobile_release import discovery
from mobile_release.api import ApiError, execute
from mobile_release.api import _snapshot as snapshot
from mobile_release.config import ConfigurationError, ReleaseConfig, parse_config_text, validate_config_data
from mobile_release.credential_requirements import requirements
from mobile_release.discovery import parse_project_sources


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


def put(root: Path, name: str, value: str | bytes) -> Path:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(value.encode("utf-8") if isinstance(value, str) else value)
    return path


def schema_leaves(schema: dict) -> set[str]:
    def visit(node: dict, prefix: str) -> set[str]:
        if "$ref" in node:
            target = schema
            for part in node["$ref"].removeprefix("#/").split("/"):
                target = target[part]
            node = target
        if "properties" not in node:
            return {prefix}
        result: set[str] = set()
        for name, child in node["properties"].items():
            result |= visit(child, f"{prefix}.{name}" if prefix else name)
        return result
    return visit(schema, "")


class ApiPureTests(unittest.TestCase):
    def test_legacy_discovery_mock_seams_stay_lazy_and_patchable(self):
        # Entire dependency modules are fake before the legacy seam is called.
        # Neither real credentials nor the real process owner is ever imported.
        fake_owner = ModuleType("mobile_release.owned_process")
        fake_owner.OUTPUT_LIMIT = 1234
        fake_owner.ProcessError = type("FakeProcessError", (Exception,), {})
        fake_owner.run_owned = Mock(return_value="forwarded")
        fake_credentials = ModuleType("mobile_release.credentials")
        fake_credentials.scrub_credential_capabilities = lambda environment: dict(environment)
        with patch.dict(sys.modules, {fake_owner.__name__: fake_owner, fake_credentials.__name__: fake_credentials}), \
             patch.dict(os.environ, {"PATH": "/fictional/tools"}, clear=True):
            self.assertEqual(discovery.OUTPUT_LIMIT, 1234)
            with patch.object(discovery, "OUTPUT_LIMIT", 64), \
                 patch.object(discovery, "run_owned", return_value=SimpleNamespace(returncode=0, stdout="hint\n")) as seam:
                self.assertEqual(discovery._run(Path("/fictional/project"), ["git", "status"]), "hint")
            seam.assert_called_once()
            self.assertEqual(seam.call_args.kwargs["output_limit"], 64)
            fake_owner.run_owned.assert_not_called()
            self.assertEqual(discovery.run_owned(["fake"], capture=True), "forwarded")
            fake_owner.run_owned.assert_called_once_with(["fake"], capture=True)

    def test_validating_is_pure_and_never_saves_or_checks_version(self):
        value = draft()
        value["$schema"] = "https://untrusted.invalid/never-fetch.json"
        value["projectChecks"]["preflight"] = [["./must-not-run"]]
        original = copy.deepcopy(value)
        with patch.object(os, "open", side_effect=AssertionError("filesystem open")), \
             patch.object(Path, "read_text", side_effect=AssertionError("filesystem read")), \
             patch.object(subprocess, "Popen", side_effect=AssertionError("process creation")), \
             patch.object(os, "system", side_effect=AssertionError("shell execution")), \
             patch.object(ReleaseConfig, "release_version", side_effect=AssertionError("version file read")), \
             patch.object(ReleaseConfig, "project_path", side_effect=AssertionError("path resolution")):
            result = execute("config.validate", {"draft": value})
        self.assertTrue(result["valid"])
        self.assertEqual(result["state"], "format-valid")
        self.assertEqual(value, original)
        self.assertEqual(result["assurance"]["releaseReadiness"], "unknown")
        self.assertTrue(all(not flag for key, flag in result["assurance"].items()
                            if key not in {"basis", "releaseReadiness"}))
        self.assertTrue(all(item["state"] == "unknown" for item in result["requirements"]))

    def test_malformed_nested_enum_containers_are_validation_failures(self):
        for keys in (("android", "identityStatus"), ("services", "androidFirebase"),
                     ("android", "externalTrack", "kind"), ("ios", "symbols", "policy")):
            for bad in ([], {}):
                value = draft()
                value["android"]["externalTrack"] = {"name": "beta", "kind": "open"}
                value["ios"] = {"enabled": True, "bundleId": "org.fixture.app", "identityStatus": "unverified",
                                "symbols": {"policy": "retain"}}
                value["metadata"]["iosLocales"] = ["en-US"]
                current = value
                for key in keys[:-1]:
                    current = current[key]
                current[keys[-1]] = bad
                with self.subTest(keys=keys, bad=bad):
                    with self.assertRaises(ConfigurationError):
                        validate_config_data(value)
                    result = execute("config.validate", {"draft": value})
                    self.assertFalse(result["valid"])
                    self.assertEqual(len(result["issues"]), 1)
                    self.assertEqual(result["issues"][0]["code"], "config.invalid")

    def test_public_parser_duplicate_nonfinite_and_byte_bounds(self):
        for raw in ('{"schemaVersion":1,"schemaVersion":1}', '{"schemaVersion":NaN}',
                    '{"schemaVersion":Infinity}', "[" * 2000 + "0" + "]" * 2000,
                    "x" * (512 * 1024 + 1), "\ud800"):
            with self.subTest(raw_size=len(raw)), self.assertRaises(ConfigurationError):
                parse_config_text(raw)
        self.assertEqual(parse_config_text(json.dumps(draft())), draft())

    def test_drafts_reject_python_values_complexity_and_large_inputs(self):
        deep: object = 0
        for _ in range(40):
            deep = [deep]
        cycle: list = []
        cycle.append(cycle)
        for value in ({1: "key"}, {"x": object()}, float("inf"), {"x": "\ud800"}, deep,
                      cycle, [0] * 20_001, {"x": "x" * (512 * 1024 + 1)}):
            with self.subTest(kind=type(value).__name__):
                result = execute("config.validate", {"draft": value})
                self.assertFalse(result["valid"])
                self.assertLessEqual(len(result["issues"][0]["message"]), 1024)

    def test_closed_dispatch_never_admits_future_actions_or_parameters(self):
        for method, params in (("build", {}), ("__import__", {}), ([], {}),
                               ("catalog", {"root": "/"}), ("capabilities", {"probe": True}),
                               ("config.validate", {}), ("config.validate", {"draft": draft(), "save": True}),
                               ("project.snapshot", {"root": "/selected", "includeGit": True}),
                               ("catalog", []), ("catalog", {1: True})):
            with self.subTest(method=method), self.assertRaises(ApiError):
                execute(method, params)
        self.assertTrue(all(action["available"] is False for action in execute("capabilities", {})["actions"]))

    def test_all_leaf_settings_have_help_from_shipped_schema(self):
        result = execute("catalog", {})
        by_path = {item["path"]: item for item in result["fields"]}
        self.assertEqual(set(by_path), schema_leaves(result["schema"]))
        self.assertEqual(len(by_path), len(result["fields"]))
        for item in result["fields"]:
            for key in ("label", "requiredness", "requiredWhen", "what", "why", "where", "format", "failure"):
                self.assertTrue(item[key].strip(), (item["path"], key))
        self.assertIn("never executed", by_path["ios.symbols.uploadCommand"]["failure"])
        self.assertIn("not native", by_path["android.identityStatus"]["failure"])
        source = Path(__file__).resolve().parents[2]
        self.assertEqual((source / "schemas/project.schema.json").read_bytes(),
                         (source / "src/mobile_release/api/data/project.schema.json").read_bytes())

    def test_catalog_and_requirements_never_consume_ambient_values(self):
        with patch.dict(os.environ, {"MOBILE_RELEASE_TOOLING_ROOT": "/not/the/package",
                                    "MOBILE_RELEASE_ANDROID_KEYSTORE_PASSWORD": "private-value-must-not-appear"}):
            result = execute("catalog", {})
            value = draft()
            value["source"]["projectReadTokenRequired"] = True
            validated = execute("config.validate", {"draft": value})
        self.assertNotIn("private-value-must-not-appear", json.dumps(result) + json.dumps(validated))
        selected = ReleaseConfig(Path("unused"), Path("."), value)
        expected = [(item.name, item.stage, item.platform) for item in requirements(selected)]
        self.assertEqual([(item["name"], item["stage"], item["platform"]) for item in validated["requirements"]], expected)
        self.assertTrue(all(item["state"] == "unknown" for item in validated["requirements"]))
        self.assertTrue(all(item["requiredness"] == "conditional" for item in result["credentials"]))
        self.assertEqual(result["metadata"]["androidReleaseNoteLimit"], 500)
        self.assertEqual(result["metadata"]["assurance"], "format-rules-only")

    def test_import_graph_refuses_runtime_execution_and_native_modules(self):
        forbidden = {
            "mobile_release.cli", "mobile_release.credentials", "mobile_release.cancellation",
            "mobile_release.owned_process", "mobile_release._native_process", "mobile_release._command_process",
            "mobile_release._profile_process", "mobile_release.build_inputs", "mobile_release.local_signing",
            "mobile_release.preflight", "mobile_release.android", "mobile_release.ios",
            "mobile_release.stores", "mobile_release.workflow",
        }

        class Guard:
            def find_spec(self, fullname, path=None, target=None):
                if fullname in forbidden:
                    raise AssertionError("forbidden runtime import: " + fullname)
                return None

        with patch.dict(sys.modules):
            for name in tuple(sys.modules):
                if name == "mobile_release" or name.startswith("mobile_release."):
                    del sys.modules[name]
            with patch.object(sys, "meta_path", [Guard(), *sys.meta_path]), \
                 patch.object(os, "register_at_fork", create=True, side_effect=AssertionError("fork hook registration")), \
                 patch.object(subprocess, "Popen", side_effect=AssertionError("process creation")), \
                 patch.object(os, "system", side_effect=AssertionError("shell execution")):
                fresh = importlib.import_module("mobile_release.api")
                fresh.execute("catalog", {})
                fresh.execute("capabilities", {})
                fresh.execute("config.validate", {"draft": draft()})
                self.assertFalse(forbidden & set(sys.modules))
                # Negative control: the guard actually rejects a forbidden route.
                with self.assertRaisesRegex(AssertionError, "forbidden runtime import"):
                    importlib.import_module("mobile_release.cli")

    def test_windows_refuses_snapshot_without_any_filesystem_attempt(self):
        with patch.object(sys, "platform", "win32"), \
             patch.object(snapshot, "_WINDOWS_SNAPSHOT_QUALIFIED", False), \
             patch.object(os, "open", side_effect=AssertionError("filesystem open")):
            caps = execute("capabilities", {})
            self.assertEqual(caps["hostPlatform"], "windows")
            methods = {item["method"]: item["available"] for item in caps["methods"]}
            self.assertEqual(methods, {"capabilities": True, "catalog": True, "project.snapshot": False,
                                       "config.validate": True, "config.suggest": True, "config.preview": True,
                                       "github.setup.propose": True, "credentials.assess": True})
            self.assertTrue(execute("config.validate", {"draft": draft()})["valid"])
            with self.assertRaises(ApiError) as caught:
                execute("project.snapshot", {"root": "C:\\selected"})
            self.assertEqual(caught.exception.code, "platform_unavailable")

    def test_in_memory_discovery_reuses_native_project_hint_parsers(self):
        sources = {
            "gradle/libs.versions.toml": '[plugins]\nandroid-app = { id = "com.android.application", version = "1" }\n',
            "app/build.gradle.kts": 'plugins { alias(libs.plugins.android.app) }\napplicationId = "org.fixture.app"\n',
            "other/build.gradle": 'plugins { id "com.android.application" }\napplicationId "org.fixture.other"\n',
            "release/version.properties": "VERSION_NAME=9.9.9\nBUILD_NUMBER=42\n",
            "App.xcodeproj/project.pbxproj": "BASE_ID = org.fixture.app;\nPRODUCT_BUNDLE_IDENTIFIER = $(BASE_ID);\n",
            "App.xcodeproj/xcshareddata/xcschemes/App.xcscheme": "",
        }
        with patch.object(os, "open", side_effect=AssertionError("filesystem read")), \
             patch.object(Path, "stat", side_effect=AssertionError("filesystem stat")):
            hints = parse_project_sources(sources, ["App.xcodeproj", "App.xcodeproj/project.xcworkspace", "App.xcworkspace"])
        self.assertTrue(hints["android"]["ambiguous"])
        self.assertEqual(hints["ios"]["bundleId"], "org.fixture.app")
        self.assertEqual(hints["ios"]["workspaces"], ["App.xcworkspace"])
        self.assertEqual(hints["versionNameKey"], "VERSION_NAME")
        self.assertNotIn("9.9.9", json.dumps(hints))

    def test_path_admission_is_explicit_nonprivate_and_relative(self):
        for path in ("../mobile-release.json", "/mobile-release.json", "release/../mobile-release.json",
                     "C:\\mobile-release.json", ".aws/mobile-release.json", "private/mobile-release.json",
                     "release/private/mobile-release.json", "release/service-account.json", "x\x00/mobile-release.json"):
            with self.subTest(path=path), self.assertRaises(ApiError):
                snapshot.validate_config_path(path)
        self.assertEqual(snapshot.validate_config_path("release/mobile-release.json"), "release/mobile-release.json")
        for root in ("relative", "/a/../b", "/a//b", "/a/", "//a", "/a/./b"):
            with self.assertRaises(ApiError):
                snapshot.validate_root(root)

    def test_special_file_refusal_precedes_open(self):
        fake = os.stat_result((stat.S_IFIFO | 0o600, 1, 1, 1, 0, 0, 0, 0, 0, 0))
        with patch.object(os, "stat", return_value=fake), \
             patch.object(os, "open", side_effect=AssertionError("must not open FIFO")):
            with self.assertRaises(snapshot._ReadProblem) as caught:
                snapshot._read_file(123, "mobile-release.json", "mobile-release.json", snapshot._Inventory())
        self.assertEqual(caught.exception.code, "snapshot.unsafe-file")

    def test_close_failure_retires_once_attempts_other_closes_and_cannot_be_partial(self):
        slots = [123, 456, 789]  # Synthetic numbers; the patched function never closes a real descriptor.
        original = OSError("synthetic unknown close outcome")
        seen = []

        def close(descriptor):
            seen.append(descriptor)
            if descriptor == 789:
                raise original

        with patch.object(os, "close", side_effect=close):
            with self.assertRaises(snapshot._DescriptorCleanupError) as caught:
                snapshot._close_handles(slots)
        self.assertEqual(slots, [])
        self.assertEqual(seen, [789, 456, 123])
        self.assertIs(caught.exception.__cause__, original)
        self.assertNotIsInstance(caught.exception, OSError)


@unittest.skipUnless(snapshot.posix_snapshot_available(), "Requires the static POSIX ordinary-file reader; not Windows evidence")
class InertSnapshotTests(unittest.TestCase):
    def test_static_snapshot_never_executes_and_labels_unknown_freshness(self):
        with tempfile.TemporaryDirectory(prefix="mrk-desktop-api-") as temporary:
            root = Path(temporary).resolve()
            value = draft()
            value["projectChecks"]["preflight"] = [["./must-not-run"]]
            put(root, "release/mobile-release.json", json.dumps(value))
            put(root, "release/version.properties", "VERSION_NAME=9.9.9\nBUILD_NUMBER=42\n")
            put(root, "app/build.gradle.kts", 'plugins { id("com.android.application") }\napplicationId = "org.fixture.app"\n')
            with patch.object(subprocess, "Popen", side_effect=AssertionError("project process")), \
                 patch.object(os, "system", side_effect=AssertionError("project shell")), \
                 patch.object(ReleaseConfig, "release_version", side_effect=AssertionError("version authority")):
                result = execute("project.snapshot", {"root": str(root)})
            self.assertEqual(result["config"]["state"], "format-valid")
            self.assertEqual(result["discovery"]["state"], "unverified")
            self.assertFalse(result["discovery"]["partial"])
            self.assertEqual(result["discovery"]["hints"]["android"]["applicationId"], "org.fixture.app")
            self.assertEqual(result["observationScope"], "single-request-non-atomic")
            self.assertTrue(result["observedAt"].endswith("+00:00"))
            self.assertEqual(result["assurance"]["releaseReadiness"], "unknown")
            self.assertNotIn("9.9.9", json.dumps(result))
            self.assertFalse((root / "must-not-run").exists())

    def test_private_generated_and_hidden_directories_are_pruned_before_enumeration(self):
        with tempfile.TemporaryDirectory(prefix="mrk-desktop-api-") as temporary:
            root = Path(temporary).resolve()
            for prefix in ("release/private", "node_modules", ".ssh", ".aws", ".mobile-release", "secrets"):
                put(root, prefix + "/build.gradle", 'plugins { id "com.android.application" }\napplicationId "org.secret.neverread"\n')
            put(root, "app/build.gradle", 'plugins { id "com.android.application" }\napplicationId "org.fixture.app"\n')
            original = snapshot._read_file
            paths = []

            def read(parent, name, relative, inventory):
                paths.append(relative)
                return original(parent, name, relative, inventory)

            with patch.object(snapshot, "_read_file", side_effect=read):
                result = execute("project.snapshot", {"root": str(root)})
            self.assertTrue(set(paths) <= {"release/mobile-release.json", "app/build.gradle"})
            self.assertGreaterEqual(result["discovery"]["scan"]["excludedEntries"], 6)
            self.assertNotIn("org.secret.neverread", json.dumps(result))

    def test_symlink_roots_parents_catalogs_and_hardlinks_never_supply_hints(self):
        with tempfile.TemporaryDirectory(prefix="mrk-desktop-api-") as temporary:
            area = Path(temporary).resolve()
            root, outside = area / "project", area / "outside"
            root.mkdir()
            put(outside, "mobile-release.json", json.dumps(draft()))
            external = put(outside, "build.gradle", 'plugins { id "com.android.application" }\napplicationId "org.secret.outside"\n')
            (root / "release").symlink_to(outside, target_is_directory=True)
            (root / "gradle").symlink_to(outside, target_is_directory=True)
            (root / "build.gradle").symlink_to(external)
            (root / "hard").mkdir()
            os.link(external, root / "hard/build.gradle")
            alias = area / "alias"
            alias.symlink_to(root, target_is_directory=True)
            with self.assertRaises(ApiError):
                execute("project.snapshot", {"root": str(alias)})
            result = execute("project.snapshot", {"root": str(root)})
            self.assertEqual(result["config"]["state"], "unavailable")
            self.assertTrue(result["discovery"]["partial"])
            self.assertNotIn("android", result["discovery"]["hints"])
            self.assertNotIn("org.secret.outside", json.dumps(result))

    def test_oversized_invalid_utf8_and_growing_files_are_explicit_partial_observations(self):
        with tempfile.TemporaryDirectory(prefix="mrk-desktop-api-") as temporary:
            root = Path(temporary).resolve()
            put(root, "big/build.gradle", b"x" * (snapshot.MAX_SOURCE_BYTES + 1))
            put(root, "bad/build.gradle", b"\xff")
            changing = put(root, "changing/build.gradle", 'plugins { id "com.android.application" }\n')
            target_identity = (changing.stat().st_dev, changing.stat().st_ino)
            original_read = os.read
            changed = False

            def read(descriptor, size):
                nonlocal changed
                chunk = original_read(descriptor, size)
                observed = os.fstat(descriptor)
                if not changed and (observed.st_dev, observed.st_ino) == target_identity:
                    changed = True
                    with changing.open("ab") as stream:
                        stream.write(b'\napplicationId "org.changed.neveruse"\n')
                return chunk

            with patch.object(os, "read", side_effect=read):
                result = execute("project.snapshot", {"root": str(root)})
            codes = {item["code"] for item in result["issues"]}
            self.assertTrue({"snapshot.file-size", "snapshot.encoding", "snapshot.changed"} <= codes)
            self.assertTrue(result["discovery"]["partial"])
            self.assertNotIn("android", result["discovery"]["hints"])

    def test_present_then_open_disappearance_is_changed_not_missing(self):
        with tempfile.TemporaryDirectory(prefix="mrk-desktop-api-") as temporary:
            root = Path(temporary).resolve()
            put(root, "mobile-release.json", json.dumps(draft()))
            descriptor = os.open(root, snapshot._directory_flags())
            try:
                with patch.object(os, "open", side_effect=FileNotFoundError("synthetic change")):
                    result = snapshot._config(descriptor, "mobile-release.json", snapshot._Inventory())
            finally:
                os.close(descriptor)
            self.assertEqual(result["state"], "unavailable")
            self.assertEqual(result["issues"][0]["code"], "snapshot.changed")

    def test_entry_depth_source_and_aggregate_limits_remain_explicit(self):
        for limit, value, expected in (("MAX_ENTRIES", 2, "snapshot.entry-limit"),
                                       ("MAX_DEPTH", 1, "snapshot.depth-limit"),
                                       ("MAX_SOURCE_FILES", 1, "snapshot.file-limit"),
                                       ("MAX_TOTAL_BYTES", 16, "snapshot.byte-limit")):
            with self.subTest(limit=limit), tempfile.TemporaryDirectory(prefix="mrk-desktop-api-") as temporary:
                root = Path(temporary).resolve()
                put(root, "one/deep/build.gradle", "x" * 32)
                put(root, "two/build.gradle", "x" * 32)
                put(root, "three/build.gradle", "x" * 32)
                with patch.object(snapshot, limit, value):
                    # A root-level config path remains admissible when the
                    # fixture deliberately narrows traversal to one directory.
                    result = execute("project.snapshot", {"root": str(root), "configPath": "mobile-release.json"})
                self.assertTrue(result["discovery"]["partial"])
                self.assertIn(expected, {item["code"] for item in result["issues"]})
        inventory = snapshot._Inventory(deadline=0)
        snapshot._walk(-1, (), inventory, "release/mobile-release.json")
        self.assertTrue(inventory.partial)
        self.assertEqual(inventory.issues[0]["code"], "snapshot.deadline")

    def test_invalid_configuration_does_not_export_arbitrary_file_values(self):
        with tempfile.TemporaryDirectory(prefix="mrk-desktop-api-") as temporary:
            root = Path(temporary).resolve()
            put(root, "release/mobile-release.json", '{"client_secret":"never-export-this-private-value"}')
            result = execute("project.snapshot", {"root": str(root)})
            self.assertEqual(result["config"]["state"], "invalid")
            self.assertIsNone(result["config"]["data"])
            self.assertNotIn("never-export-this-private-value", json.dumps(result))

    def test_oversized_hints_are_omitted_not_truncated_into_new_identifiers(self):
        with tempfile.TemporaryDirectory(prefix="mrk-desktop-api-") as temporary:
            root = Path(temporary).resolve()
            put(root, "build.gradle", 'plugins { id "com.android.application" }\napplicationId "org.' + "a" * 513 + '"\n')
            result = execute("project.snapshot", {"root": str(root)})
            self.assertTrue(result["discovery"]["partial"])
            self.assertNotIn("applicationId", result["discovery"]["hints"]["android"])
            self.assertIn("snapshot.hint-limit", {item["code"] for item in result["issues"]})

    def test_configuration_output_budget_is_not_misreported_as_invalid_policy(self):
        with tempfile.TemporaryDirectory(prefix="mrk-desktop-api-") as temporary:
            root = Path(temporary).resolve()
            value = draft()
            value["metadata"]["androidLocales"] = ["a" + chr(97 + number // 1000) + f"-{number % 1000:03d}" for number in range(8100)]
            put(root, "release/mobile-release.json", json.dumps(value))
            result = execute("project.snapshot", {"root": str(root)})
            self.assertEqual(result["config"]["state"], "unavailable")
            self.assertIsNone(result["config"]["data"])
            self.assertIn("snapshot.config-output-limit", {item["code"] for item in result["issues"]})


if __name__ == "__main__":
    unittest.main()
