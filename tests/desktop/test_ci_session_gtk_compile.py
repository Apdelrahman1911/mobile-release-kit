"""Inert SG1 compiler admission/receipt/argv checks. No native/tool execution."""
from __future__ import annotations

import ast
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import re
import unittest
from unittest.mock import patch

HELPER = Path(__file__).resolve().parents[2] / "desktop/tools/ci_foundation.py"
SPEC = importlib.util.spec_from_file_location("desktop_session_gtk_compile_contract", HELPER)
assert SPEC is not None and SPEC.loader is not None
helper = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(helper)


def environment() -> dict[str, str]:
    return {"GITHUB_SHA": "1" * 40, "GITHUB_WORKFLOW_SHA": "1" * 40,
            "GITHUB_REPOSITORY": "fictional/project", "GITHUB_REF": helper.GTK_COMPILE_REF,
            "GITHUB_WORKFLOW_REF": f"fictional/project/{helper.GTK_COMPILE_WORKFLOW}@{helper.GTK_COMPILE_REF}",
            "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "2", "GITHUB_EVENT_NAME": "push"}


def context() -> dict:
    return {**helper.compile_workflow_binding(environment(), helper.GTK_COMPILE_SCOPE),
            "root": "/synthetic/compiler", "source": "/synthetic/source", "python": "/selected/python",
            "platform": "linux", "workflowSha256": "2" * 64, "sourceTree": "3" * 40,
            "executionScope": helper.GTK_COMPILE_SCOPE,
            "sg1": {"features": list(helper.GTK_COMPILE_FEATURES), "testTarget": "session-gtk-qualification",
                    "execution": "no-run", "sources": [
                        {"path": path, "size": 1, "sha256": "4" * 64} for path in helper.GTK_COMPILE_SOURCES]}}


def receipt(phase: str) -> dict:
    binding = context()
    return {"schemaVersion": 1, "scope": helper.GTK_COMPILE_EVIDENCE_SCOPE, "phase": phase, "status": "passed",
            **{key: binding[key] for key in ("sourceSha", "sourceTree", "platform", "workflowPath", "workflowSha",
                                           "workflowRef", "workflowSha256", "runId", "attempt", "sg1")},
            "rust": {"release": helper.RUST, "target": helper.TARGETS["linux"]}, "node": helper.NODE,
            "checks": [{"check": check, "exitCode": 0} for check in helper.GTK_COMPILE_CHECKS[phase]]}


class SessionGtkCompileContractTests(unittest.TestCase):
    def test_core_inventory_rejects_substitutions_and_malformed_rows(self):
        original = [{"path": path, "size": 1, "sha256": "4" * 64} for path in helper.GTK_CORE_PATHS]
        helper.validate_gtk_core_inventory(original)
        self.assertEqual(len(original), 91)
        variants = (None, {}, tuple(original), original[:-1], original + [original[0]],
                    [original[0]] + original[:-1], list(reversed(original)))
        for value in variants:
            with self.subTest(value_type=type(value).__name__), self.assertRaises(helper.CheckFailure):
                helper.validate_gtk_core_inventory(value)
        for key, value in (("path", "mobile_release/substituted.py"), ("path", 1),
                           ("size", True), ("size", 1.0), ("size", -1), ("size", 8 * 1024 * 1024 + 1),
                           ("sha256", "A" * 64), ("sha256", "4" * 63), ("sha256", None), ("extra", False)):
            broken = deepcopy(original)
            broken[0][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(helper.CheckFailure):
                helper.validate_gtk_core_inventory(broken)
        for row in (None, {}, {"path": original[0]["path"], "size": 1}):
            with self.subTest(row=row), self.assertRaises(helper.CheckFailure):
                helper.validate_gtk_core_inventory([row, *original[1:]])
        broken = deepcopy(original)
        for row in broken[:5]:
            row["size"] = 8 * 1024 * 1024
        with self.assertRaises(helper.CheckFailure):
            helper.validate_gtk_core_inventory(broken)

    def test_qualification_rosters_cover_current_core_and_integration_modules(self):
        # Fixed SOURCE reads only: never import the native driver or execute GTK.
        root = HELPER.parents[2]
        driver = (root / "desktop/tools/qualify_session_gtk.py").read_text(encoding="utf-8")
        native = (root / "desktop/src-tauri/src/session_gtk_qualification.rs").read_text(encoding="utf-8")
        python_block = driver.split("\nSOURCES = (\n", 1)[1].split("\n)\n", 1)[0]
        rust_block = native.split("const SOURCES: &[Source] = &[\n", 1)[1].split("\n];", 1)[0]
        python_paths = re.findall(r"^    '([^']+)',$", python_block, re.MULTILINE)
        rust_paths = re.findall(r'^    source!\("([^\"]+)"\),$', rust_block, re.MULTILINE)
        self.assertEqual(python_paths, rust_paths)
        self.assertEqual(python_paths, sorted(set(python_paths)))
        self.assertEqual(len(python_paths), 244)
        self.assertNotIn("len(SOURCES) == 154", driver)
        self.assertNotIn("len(SOURCES) == 182", driver)
        self.assertNotIn("len(SOURCES) == 197", driver)
        self.assertNotIn("len(SOURCES) == 201", driver)
        self.assertNotIn("len(SOURCES) == 213", driver)
        self.assertNotIn("len(SOURCES) == 217", driver)
        self.assertNotIn("len(SOURCES) == 223", driver)
        self.assertNotIn("len(SOURCES) == 228", driver)
        self.assertEqual(driver.count("len(SOURCES) == 244"), 2)
        self.assertEqual(len(helper.GTK_COMPILE_SOURCES), 56)
        for relative in (
                "desktop/offline_preflight_bootstrap.py",
                "desktop/src-tauri/src/offline_preflight_owner.rs",
                "desktop/src-tauri/src/offline_preflight_owner_tests.rs",
                "desktop/src-tauri/src/offline_preflight_protocol.rs",
                "desktop/src-tauri/src/offline_preflight_protocol_tests.rs",
                "desktop/src-tauri/src/offline_preflight_shell_tests.rs",
        ):
            self.assertIn(relative, helper.GTK_COMPILE_SOURCES)
        self.assertEqual(tuple(path.removeprefix("src/") for path in python_paths if path.startswith("src/")),
                         helper.GTK_CORE_PATHS)
        package = root / "src/mobile_release"
        observed = []
        for path in package.rglob("*"):
            self.assertFalse(path.is_symlink())
            if path.is_file():
                observed.append(path.relative_to(root / "src").as_posix())
        self.assertEqual(tuple(sorted(observed)), helper.GTK_CORE_PATHS)
        # Current saved-offline runtime/compiler/UI members, not a new SG1 qualification.
        for relative in (
                "desktop/offline_preflight_bootstrap.py",
                "desktop/src-tauri/src/offline_preflight_owner.rs",
                "desktop/src-tauri/src/offline_preflight_owner_tests.rs",
                "desktop/src-tauri/src/offline_preflight_protocol.rs",
                "desktop/src-tauri/src/offline_preflight_protocol_tests.rs",
                "desktop/src-tauri/src/offline_preflight_shell_tests.rs",
                "desktop/src/components/OfflinePreflight.tsx",
                "desktop/src/offlinePreflight.ts",
                "desktop/src/offlinePreflightProtocol.ts",
                "desktop/src/offlinePreflightTypes.ts",
                "src/mobile_release/_desktop_preflight_budget.py",
                "src/mobile_release/_desktop_preflight_control.py",
                "src/mobile_release/_desktop_preflight_engine.py",
                "src/mobile_release/_desktop_preflight_protocol.py",
                "src/mobile_release/desktop_preflight.py",
        ):
            self.assertIn(relative, python_paths)
        library = (root / "desktop/src-tauri/src/lib.rs").read_text(encoding="utf-8")
        integration = (root / "desktop/src-tauri/tests/session_gtk_qualification.rs").read_text(encoding="utf-8")
        modules = re.findall(r"^(?:pub )?mod ([a-z_]+);$", library, re.MULTILINE)
        registrations = re.findall(r'#\[path = "\.\./src/([a-z_]+)\.rs"\] mod ([a-z_]+);', integration)
        self.assertEqual(sorted(modules), sorted(name for _, name in registrations))
        for filename, name in registrations:
            self.assertEqual(filename, name)
            self.assertIn(f"desktop/src-tauri/src/{name}.rs", python_paths)
        for name in ("environment", "environment_diagnostics_protocol", "environment_diagnostics_owner",
                     "github_workflow_edit_protocol", "github_connection_protocol", "github_connection_session",
                      "metadata_text_commands", "metadata_text_edit_protocol", "release_version_protocol",
                      "candidate_evidence_protocol"):
            self.assertIn(f"desktop/src-tauri/src/{name}.rs", helper.GTK_COMPILE_SOURCES)
        for relative in ("desktop/environment_bootstrap.py",
                         ".github/workflows/desktop-environment-diagnostics-native.yml",
                         "desktop/src-tauri/src/environment_diagnostics_hosted_tests.rs",
                         "tests/native_desktop_environment.py",
                         "tests/workflow/command_bootstrap_fixture.py",
                         "desktop/src/components/EnvironmentDiagnostics.tsx",
                         "desktop/src/environmentDiagnosticsTypes.ts",
                         "desktop/src/environmentDiagnosticsProtocol.ts",
                         "desktop/src/environmentDiagnosticsController.ts", "desktop/src/environment.ts", "desktop/src/components/MetadataTextEditor.tsx", "desktop/src/metadataText.ts",
                          "desktop/src/metadataTextEditController.ts", "desktop/src/metadataTextProtocol.ts", "desktop/src/releaseVersion.ts",
                         "desktop/src/candidateEvidence.ts", "desktop/src/pages/Artifacts.tsx",
                         "src/mobile_release/api/_candidate_evidence.py"):
            self.assertIn(relative, python_paths)
        # These test-cfg owners and includes also compile in the SG1 target;
        # do not infer completeness from the consumer's own roster constant.
        for relative in ("desktop/github_connection_bootstrap.py",
                         "desktop/tests/fixtures/candidate-evidence.json",
                         "desktop/src-tauri/tests/fixtures/github_core/_desktop_github_engine.py",
                         ".github/workflows/desktop-github-connection-tls.yml",
                         ".github/workflows/desktop-github-workflow-apply-native.yml",
                         "templates/workflows/mobile-candidate.yml",
                         "templates/workflows/mobile-external-testing.yml",
                         "templates/workflows/mobile-preflight.yml",
                         "templates/workflows/mobile-production-submit.yml",
                         "desktop/src-tauri/tests/fixtures/github_tls_peer.py",
                         "desktop/src-tauri/tests/fixtures/github_tls_namespace.sh",
                         "desktop/src-tauri/tests/fixtures/github_tls/api-expired.pem",
                         "desktop/src-tauri/tests/fixtures/github_tls/api-valid.pem",
                         "desktop/src-tauri/tests/fixtures/github_tls/other-root-ca.pem",
                         "desktop/src-tauri/tests/fixtures/github_tls/root-ca.pem",
                         "desktop/src-tauri/tests/fixtures/github_tls/server-key.pem",
                         "desktop/src-tauri/tests/fixtures/github_tls/wrong-san.pem",
                         "desktop/src-tauri/src/runtime.rs", "desktop/src-tauri/src/supervisor.rs",
                         "desktop/src-tauri/src/edit_hosted_tests.rs",
                         "desktop/src-tauri/src/hosted_tests.rs", "desktop/src-tauri/src/asset_session.rs"):
            self.assertIn(relative, python_paths)
            self.assertIn(relative, helper.GTK_COMPILE_SOURCES)

    def test_sg1_observes_only_unavailable_diagnostics_status_without_starting_work(self):
        root = HELPER.parents[2]
        driver = (root / "desktop/tools/qualify_session_gtk.py").read_text(encoding="utf-8")
        native = (root / "desktop/src-tauri/src/session_gtk_qualification.rs").read_text(encoding="utf-8")
        shell = (root / "desktop/src-tauri/src/shell.rs").read_text(encoding="utf-8")
        parsed = ast.parse(driver)
        commands = next(node.value for node in parsed.body if isinstance(node, ast.Assign)
                        and any(isinstance(target, ast.Name) and target.id == "COMMANDS" for target in node.targets))
        names = re.search(r"pub\(super\) enum Command \{([^}]+)\}", native).group(1).split(",")
        self.assertEqual(names[-2:], ["EnvironmentStatus", "Forbidden"])
        self.assertEqual(ast.literal_eval(commands), tuple(re.sub(r"(?<!^)(?=[A-Z])", "-", name).lower()
                                                          for name in names[:-1]))
        self.assertIn("count(EventKind::CommandEnter)==10 && count(EventKind::CommandReturn)==10", native)
        self.assertIn('len(actual) == 10, "ten exact real SG1 commands"', driver)
        self.assertIn('u(event["detail"], 8)', driver)
        for command in ("start_environment_diagnostics", "cancel_environment_diagnostics"):
            body = shell.split(f"async fn {command}(", 1)[1].split("\n}", 1)[0]
            self.assertIn("fixture_command!(state, Forbidden, observed,", body)
        status = shell.split("async fn environment_diagnostics_status(", 1)[1].split("\n}", 1)[0]
        self.assertIn("fixture_command!(state, EnvironmentStatus, observed,", status)
        self.assertIn("state.document.environment_diagnostics_status()", status)
        self.assertIn("fixture_result!(observed, environment_status_returned, &result)", status)
        self.assertIn("diagnostics_owner.can_exit() && !diagnostics_owner.disabled() && diagnostics_owner.stopping()", native)
        self.assertIn("API_INVENTORY: str | None = None", driver)
        # Execute only these five bounded DATA validators and their exception;
        # never import the native driver or its IO/process/fixture definitions.
        selected = {"Refused", "require", "u", "closed", "fixed", "diagnostics_observation"}
        nodes = [node for node in parsed.body if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name in selected]
        self.assertEqual({node.name for node in nodes}, selected)
        self.assertEqual(len(nodes), len(selected))
        namespace = {"Any": object}
        exec(compile(ast.Module(body=nodes, type_ignores=[]), "<sg1-diagnostics-data-only>", "exec"), namespace)
        observe, refused = namespace["diagnostics_observation"], namespace["Refused"]
        value = {"schemaVersion": 1, "statusRevision": 0, "capability": {"available": False, "reason": "busy"},
                 "active": None, "lastTerminal": None}
        for reason in ("busy", "document-lost", "runtime-unqualified"):
            observe({**value, "capability": {"available": False, "reason": reason}}, final=False)
        observe({**value, "capability": {"available": False, "reason": "shutdown"}}, final=True)
        for key, bad in (("schemaVersion", True), ("statusRevision", True), ("statusRevision", 2**32-1),
                         ("active", {}), ("lastTerminal", {}), ("extra", None)):
            with self.subTest(key=key, bad=bad), self.assertRaises(refused):
                observe({**value, key: bad}, final=False)
        for capability in ({"available": True, "reason": "available"}, {"available": 0, "reason": "busy"},
                           {"available": False, "reason": "cleanup-unknown"}, {"available": False, "reason": "shutdown"}):
            with self.subTest(capability=capability), self.assertRaises(refused):
                observe({**value, "capability": capability}, final=False)
        with self.assertRaises(refused):
            observe(value, final=True)

    def test_native_phases_and_non_linux_profiles_refuse_before_context_or_tools(self):
        with patch.object(helper, "load_context", side_effect=AssertionError("no context IO")), \
                patch.object(helper, "tools", side_effect=AssertionError("no compiler selection")):
            for name in ("native", "config-owner", "config-task-loss", "config-owner-delta",
                         "config-transaction-eof", "config-core", "windows-snapshot", "github-owner", "unknown"):
                with self.subTest(phase=name), self.assertRaises(helper.CheckFailure):
                    helper.phase(name, "linux", helper.GTK_COMPILE_SCOPE)
            for platform in ("macos", "windows", "unknown"):
                for name in helper.COMPILE_PHASES:
                    with self.subTest(platform=platform, phase=name), self.assertRaises(helper.CheckFailure):
                        helper.phase(name, platform, helper.GTK_COMPILE_SCOPE)
                    with self.assertRaises(helper.CheckFailure):
                        helper.prepare(platform, helper.GTK_COMPILE_SCOPE)
        for name in helper.COMPILE_PHASES:
            helper.admit_phase(helper.GTK_COMPILE_SCOPE, name)

    def test_workflow_ref_sha_attempt_and_dispatch_binding_are_profile_specific(self):
        original = environment()
        expected = helper.compile_workflow_binding(original, helper.GTK_COMPILE_SCOPE)
        self.assertEqual(expected["workflowPath"], helper.GTK_COMPILE_WORKFLOW)
        for key, value in (("GITHUB_REF", helper.COMPILE_REF), ("GITHUB_SHA", "bad"),
                           ("GITHUB_WORKFLOW_SHA", "5" * 40), ("GITHUB_WORKFLOW_REF", "other/workflow"),
                           ("GITHUB_REPOSITORY", "other/project"), ("GITHUB_RUN_ID", "0"),
                           ("GITHUB_RUN_ATTEMPT", "-1"), ("GITHUB_EVENT_NAME", "pull_request")):
            with self.subTest(key=key), self.assertRaises(helper.CheckFailure):
                helper.compile_workflow_binding({**original, key: value}, helper.GTK_COMPILE_SCOPE)
        with self.assertRaises(helper.CheckFailure):
            helper.compile_workflow_binding(original)  # SG1 cannot substitute for the existing shell profile.
        shell = {**original, "GITHUB_REF": helper.COMPILE_REF,
                 "GITHUB_WORKFLOW_REF": f"fictional/project/{helper.COMPILE_WORKFLOW}@{helper.COMPILE_REF}"}
        with self.assertRaises(helper.CheckFailure):
            helper.compile_workflow_binding(shell, helper.GTK_COMPILE_SCOPE)
        dispatch = {**original, "GITHUB_EVENT_NAME": "workflow_dispatch"}
        with self.assertRaises(helper.CheckFailure):
            helper.compile_workflow_binding(dispatch, helper.GTK_COMPILE_SCOPE)
        self.assertEqual(helper.compile_workflow_binding({**dispatch, "MRK_EXPECTED_SHA": "1" * 40},
                                                        helper.GTK_COMPILE_SCOPE), expected)

    def test_receipts_require_complete_original_source_feature_and_check_rosters(self):
        for phase in helper.GTK_COMPILE_CHECKS:
            original = receipt(phase)
            self.assertEqual(helper.validate_compile_receipt(original, context(), phase), original)
            for key, value in (("schemaVersion", True), ("scope", helper.COMPILE_EVIDENCE_SCOPE),
                               ("sourceSha", "6" * 40), ("sourceTree", "6" * 40), ("platform", "windows"),
                               ("runId", "124"), ("attempt", "3"), ("workflowPath", helper.COMPILE_WORKFLOW),
                               ("workflowSha", "5" * 40), ("workflowRef", "other/workflow"),
                               ("workflowSha256", "5" * 64), ("status", "failed"), ("node", "other"),
                               ("rust", {"release": helper.RUST, "target": "wrong"}),
                               ("checks", original["checks"][:-1]), ("checks", original["checks"] * 2),
                               ("sg1", None), ("extra", False)):
                with self.subTest(phase=phase, key=key), self.assertRaises(helper.CheckFailure):
                    helper.validate_compile_receipt({**original, key: value}, context(), phase)
            for key, value in (("features", ["development-runtime"]), ("execution", "run"),
                               ("sources", original["sg1"]["sources"][:-1]),
                               ("testTarget", "mobile-release-kit-desktop")):
                broken = deepcopy(original)
                broken["sg1"][key] = value
                with self.assertRaises(helper.CheckFailure):
                    helper.validate_compile_receipt(broken, context(), phase)
            for code in (False, 1, None, 0.0):
                broken = deepcopy(original)
                broken["checks"][0]["exitCode"] = code
                with self.assertRaises(helper.CheckFailure):
                    helper.validate_compile_receipt(broken, context(), phase)
            for size in (True, 1.0):
                broken = deepcopy(original)
                broken["sg1"]["sources"][0]["size"] = size
                with self.assertRaises(helper.CheckFailure):
                    helper.validate_compile_receipt(broken, context(), phase)
            for scope in (helper.COMPILE_SCOPE, helper.BOUNDARY_SCOPE, "unknown"):
                with self.assertRaises(helper.CheckFailure):
                    helper.validate_compile_receipt(original, {**context(), "executionScope": scope}, phase)
        for value in (None, [], True, "passed"):
            with self.assertRaises(helper.CheckFailure):
                helper.validate_compile_receipt(value, context(), "compile")

    def test_duplicate_nonfinite_or_extra_receipt_data_is_not_cleanup_authority(self):
        raw = json.dumps(receipt("compile"), separators=(",", ":")).encode()
        self.assertEqual(helper.parse_compile_receipt(raw), receipt("compile"))
        for broken in (raw.replace(b'"schemaVersion":1', b'"schemaVersion":0,"schemaVersion":1'),
                       raw.replace(b'"exitCode":0', b'"exitCode":1,"exitCode":0', 1),
                       raw + b'{}', b'{"check":NaN}', b'\xff', b' ' * 16385, b''):
            with self.assertRaises(helper.CheckFailure):
                helper.parse_compile_receipt(broken)

    def test_fixed_compile_path_is_fail_fast_no_run_and_has_no_native_or_full_matrix(self):
        binding = context()
        calls = []
        def run(argv, **kwargs):
            calls.append((argv, kwargs))
            if kwargs["check"] == "node-version":
                return helper.NODE
            if kwargs["check"] == "gtk-c-pkg-config":
                return "-I/synthetic/include -lglib-2.0 -pthread"
            return ""
        with patch.object(helper, "load_context", return_value=binding), \
                patch.object(helper, "clean_environment", return_value={}), \
                patch.object(helper, "source_unchanged") as source_check, \
                patch.object(helper, "no_cargo_configuration"), \
                patch.object(helper, "tools", return_value=("/selected/cargo", "/selected/rustc")), \
                patch.object(helper.shutil, "which", return_value="/selected/node"), \
                patch.object(helper, "gtk_compiler_tools", return_value=("/selected/cc", "/selected/pkg-config")), \
                patch.object(helper, "gtk_compile_binding", return_value=binding["sg1"]), \
                patch.object(helper, "run", side_effect=run), patch.object(helper, "phase_receipt") as emit:
            helper.phase("compile", "linux", helper.GTK_COMPILE_SCOPE)
        self.assertEqual([item[1]["check"] for item in calls], list(helper.GTK_COMPILE_CHECKS["compile"])[1:])
        self.assertEqual(source_check.call_count, 2)
        emit.assert_called_once_with(binding, "compile", list(helper.GTK_COMPILE_CHECKS["compile"]), node=helper.NODE)
        rust = calls[-1][0]
        self.assertEqual(rust[:2], ["/selected/cargo", "test"])
        for item in ("--locked", "--offline", "--no-default-features", "--no-run"):
            self.assertIn(item, rust)
        for name, value in (("--jobs", "1"), ("--target", "x86_64-unknown-linux-gnu"),
                            ("--test", "session-gtk-qualification"),
                            ("--features", "desktop-shell,development-runtime"),
                            ("--target-dir", "/synthetic/compiler/target")):
            self.assertEqual(rust[rust.index(name) + 1], value)
        self.assertNotIn("--", rust)
        self.assertNotIn("--lib", rust)
        python = calls[1][0]
        self.assertEqual(python[1:5], ["-I", "-S", "-B", "-c"])
        self.assertEqual(python[5], helper.GTK_PYTHON_SYNTAX)
        self.assertEqual(calls[2][0][1], "--check")
        compiled_c = calls[4][0]
        self.assertEqual(compiled_c[compiled_c.index("-o") + 1], "/synthetic/compiler/target/session-gtk-input")
        self.assertTrue(all(argv[0] != "/synthetic/compiler/target/session-gtk-input" for argv, _ in calls))
        self.assertTrue(all(0 < kwargs["timeout"] <= 1500 for _, kwargs in calls))

    def test_failed_compiler_cannot_publish_a_positive_phase_receipt(self):
        binding = context()
        with patch.object(helper, "load_context", return_value=binding), \
                patch.object(helper, "clean_environment", return_value={}), \
                patch.object(helper, "source_unchanged"), patch.object(helper, "no_cargo_configuration"), \
                patch.object(helper, "tools", return_value=("/selected/cargo", "/selected/rustc")), \
                patch.object(helper, "compile_gtk", side_effect=helper.CheckFailure("fixed failure")), \
                patch.object(helper, "phase_receipt", side_effect=AssertionError("cannot emit success")):
            with self.assertRaises(helper.CheckFailure):
                helper.phase("compile", "linux", helper.GTK_COMPILE_SCOPE)


if __name__ == "__main__":
    unittest.main()
