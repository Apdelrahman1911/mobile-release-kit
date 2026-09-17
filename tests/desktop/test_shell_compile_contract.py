"""In-memory compiler-only admission/cleanup contracts, never helper execution."""
from __future__ import annotations

from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

HELPER = Path(__file__).resolve().parents[2] / "desktop/tools/ci_foundation.py"
SPEC = importlib.util.spec_from_file_location("desktop_shell_compile_contract", HELPER)
assert SPEC is not None and SPEC.loader is not None
helper = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(helper)


def environment() -> dict[str, str]:
    return {"GITHUB_SHA": "1" * 40, "GITHUB_WORKFLOW_SHA": "1" * 40,
            "GITHUB_REPOSITORY": "fictional/project", "GITHUB_REF": helper.COMPILE_REF,
            "GITHUB_WORKFLOW_REF": f"fictional/project/{helper.COMPILE_WORKFLOW}@{helper.COMPILE_REF}",
            "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "2", "GITHUB_EVENT_NAME": "push"}


def context() -> dict:
    return {**helper.compile_workflow_binding(environment()), "platform": "linux",
            "workflowSha256": "2" * 64, "executionScope": helper.COMPILE_SCOPE}


def receipt(phase: str) -> dict:
    binding = context()
    return {"schemaVersion": 1, "scope": helper.COMPILE_EVIDENCE_SCOPE, "phase": phase, "status": "passed",
            **{key: binding[key] for key in ("sourceSha", "platform", "workflowPath", "workflowSha", "workflowRef", "workflowSha256", "runId", "attempt")},
            "rust": {"release": helper.RUST, "target": helper.TARGETS["linux"]}, "node": helper.NODE,
            "checks": [{"check": check, "exitCode": 0} for check in helper.COMPILE_CHECKS[phase]]}


class ShellCompileContractTests(unittest.TestCase):
    def test_compile_scope_refuses_every_native_phase_before_context_or_tools(self):
        with patch.object(helper, "load_context", side_effect=AssertionError("context must not be opened")), \
                patch.object(helper, "tools", side_effect=AssertionError("no tool may be selected")):
            for phase in ("native", "config-owner", "config-task-loss", "config-owner-delta",
                          "config-transaction-eof", "config-core", "unexpected"):
                with self.subTest(phase=phase), self.assertRaises(helper.CheckFailure):
                    helper.phase(phase, "linux", helper.COMPILE_SCOPE)
        for phase in helper.COMPILE_PHASES:
            helper.admit_phase(helper.COMPILE_SCOPE, phase)
        helper.admit_phase(helper.BOUNDARY_SCOPE, "native")  # No native call.
        with self.assertRaises(helper.CheckFailure):
            helper.admit_phase("unknown", "compile")

    def test_compile_binding_requires_actual_fixed_workflow_ref_source_and_attempt(self):
        original = environment()
        expected = helper.compile_workflow_binding(original)
        self.assertEqual(expected["sourceSha"], "1" * 40)
        for key, value in (("GITHUB_REF", "refs/heads/main"), ("GITHUB_SHA", "bad"),
                           ("GITHUB_WORKFLOW_SHA", "3" * 40), ("GITHUB_WORKFLOW_REF", "other/workflow"),
                           ("GITHUB_REPOSITORY", "other/project"), ("GITHUB_RUN_ID", "0"),
                           ("GITHUB_RUN_ATTEMPT", "-1"), ("GITHUB_EVENT_NAME", "pull_request")):
            with self.subTest(key=key), self.assertRaises(helper.CheckFailure):
                helper.compile_workflow_binding({**original, key: value})
        dispatched = {**original, "GITHUB_EVENT_NAME": "workflow_dispatch"}
        with self.assertRaises(helper.CheckFailure):
            helper.compile_workflow_binding(dispatched)
        self.assertEqual(helper.compile_workflow_binding({**dispatched, "MRK_EXPECTED_SHA": "1" * 40}), expected)

    def test_compile_cleanup_requires_complete_matching_original_positive_receipts(self):
        for phase in helper.COMPILE_CHECKS:
            original = receipt(phase)
            self.assertEqual(helper.validate_compile_receipt(original, context(), phase), original)
            for key, value in (("schemaVersion", True), ("scope", "passive-development-foundation-only"),
                               ("sourceSha", "3" * 40), ("platform", "macos"), ("runId", "124"),
                               ("attempt", "1"), ("workflowPath", ".github/workflows/desktop-foundation.yml"),
                               ("workflowSha", "4" * 40), ("workflowRef", "other/workflow"),
                               ("workflowSha256", "5" * 64), ("status", "failed"), ("node", "other"),
                               ("rust", {"release": helper.RUST, "target": "wrong"}),
                               ("checks", original["checks"][:-1]), ("extra", False)):
                with self.subTest(phase=phase, key=key), self.assertRaises(helper.CheckFailure):
                    helper.validate_compile_receipt({**original, key: value}, context(), phase)
            for exit_code in (False, 1, None):
                broken = deepcopy(original)
                broken["checks"][0]["exitCode"] = exit_code
                with self.assertRaises(helper.CheckFailure):
                    helper.validate_compile_receipt(broken, context(), phase)
            with self.assertRaises(helper.CheckFailure):
                helper.validate_compile_receipt(None, context(), phase)
            with self.assertRaises(helper.CheckFailure):
                helper.validate_compile_receipt(original, {**context(), "executionScope": helper.BOUNDARY_SCOPE}, phase)

    def test_compile_cleanup_never_adopts_native_or_unexpected_outputs(self):
        names = set(helper.COMPILER_DIRECTORIES + helper.EMPTY_NATIVE_DIRECTORIES + helper.COMPILER_PRIVATE_FILES + helper.COMPILE_PUBLIC_FILES)
        helper.validate_compile_inventory(names, set())
        for altered in (names | {"native-checks.json"}, names | {"foreign-output"}, names - {"compile-checks.json"}):
            with self.assertRaises(helper.CheckFailure):
                helper.validate_compile_inventory(altered, set())
        with self.assertRaises(helper.CheckFailure):
            helper.validate_compile_inventory(names, {"native"})

    def test_compile_receipt_bytes_reject_duplicate_nonfinite_extra_or_oversized_frames(self):
        value = receipt("compile")
        raw = json.dumps(value, separators=(",", ":")).encode()
        self.assertEqual(helper.parse_compile_receipt(raw), value)
        for broken in (raw.replace(b'"schemaVersion":1', b'"schemaVersion":0,"schemaVersion":1'),
                       raw.replace(b'"exitCode":0', b'"exitCode":1,"exitCode":0', 1),
                       raw + b'{}', b'{"secret":"not real","bad":NaN}', b'\xff', b' ' * 16385, b''):
            with self.assertRaises(helper.CheckFailure):
                helper.parse_compile_receipt(broken)


if __name__ == "__main__":
    unittest.main()
