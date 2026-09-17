"""Inert SG1 compiler admission/receipt/argv checks. No native/tool execution."""
from __future__ import annotations

from copy import deepcopy
import importlib.util
import json
from pathlib import Path
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
    def test_native_phases_and_non_linux_profiles_refuse_before_context_or_tools(self):
        with patch.object(helper, "load_context", side_effect=AssertionError("no context IO")), \
                patch.object(helper, "tools", side_effect=AssertionError("no compiler selection")):
            for name in ("native", "config-owner", "config-task-loss", "config-owner-delta",
                         "config-transaction-eof", "config-core", "windows-snapshot", "unknown"):
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
