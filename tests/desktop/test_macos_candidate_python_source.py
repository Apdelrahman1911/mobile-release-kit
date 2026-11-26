"""Candidate supplier admission DATA; no compiler, install or signing runs."""
import importlib.util
import os
from pathlib import Path
import re
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "desktop/tools" / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


BUILD = load("_mrk_candidate_python_source_build", "macos_cpython_source_build.py")
PREP = load("_mrk_candidate_python_source_prepare", "macos_cpython_orchestrator.py")


class CandidatePythonSourceTests(unittest.TestCase):
    def candidate(self):
        return (BUILD.REPOSITORY + "/" + BUILD.CANDIDATE_WORKFLOW + "@" + BUILD.CANDIDATE_REFERENCE,
                BUILD.CANDIDATE_REFERENCE, "workflow_dispatch")

    def test_candidate_refresh_is_explicit_arm_source_route(self):
        target, profile = BUILD.producer_route(*self.candidate())
        original = BUILD.target_profile(BUILD.ARM_TARGET)
        self.assertEqual(target, BUILD.ARM_TARGET)
        self.assertEqual(profile, {**original, "reference": BUILD.CANDIDATE_REFERENCE,
                                   "workflow": BUILD.CANDIDATE_WORKFLOW})
        self.assertEqual(original["reference"], BUILD.REFERENCE)

    def test_push_pr_foreign_and_mismatched_workflow_do_not_enter_refresh(self):
        workflow, ref, event = self.candidate()
        for changed in ((workflow, ref, "push"), (workflow, ref, "pull_request"),
                        (workflow, ref, None), (workflow, "refs/heads/main", event),
                        (workflow.replace(BUILD.REPOSITORY, "foreign/repository"), ref, event),
                        (workflow.replace(BUILD.CANDIDATE_WORKFLOW, BUILD.WORKFLOW), ref, event),
                        (workflow.replace("installed.yml", "signing.yml"), ref, event),
                        (workflow + "-foreign", ref, event)):
            with self.subTest(route=changed), self.assertRaises(BUILD.BuildRefused):
                BUILD.producer_route(*changed)

    def test_historical_push_routes_keep_their_original_target(self):
        for target in (BUILD.ARM_TARGET, BUILD.INTEL_TARGET):
            profile = BUILD.target_profile(target)
            workflow = BUILD.REPOSITORY + "/" + profile["workflow"] + "@" + profile["reference"]
            self.assertEqual(BUILD.producer_route(workflow, profile["reference"], "push"), (target, profile))
            with self.assertRaises(BUILD.BuildRefused):
                BUILD.producer_route(workflow, profile["reference"], "workflow_dispatch")

    def test_actual_hosted_sdk_27_0_preserves_minimum_deployment_and_rejects_future_sdk(self):
        for version in ("26.0", "26.1", "26.2.1", "27.0"):
            self.assertTrue(BUILD.admitted_sdk_version(version))
        for version in ("27.1", "27.0.1", "28.0", "25.0", "27", "27.0\n", " 27.0", "27.0beta", True, None):
            self.assertFalse(BUILD.admitted_sdk_version(version))
        for target in (BUILD.ARM_TARGET, BUILD.INTEL_TARGET):
            self.assertIn("-mmacosx-version-min=26.0", BUILD.compiler_flags("/inert/sdk", target))

    def test_refresh_workflow_is_in_actual_source_snapshot(self):
        original = BUILD.source_snapshot(ROOT)
        refreshed = BUILD.source_snapshot(ROOT, workflow=BUILD.CANDIDATE_WORKFLOW)
        self.assertIn(BUILD.WORKFLOW, original)
        self.assertIn(BUILD.CANDIDATE_WORKFLOW, refreshed)
        self.assertIn(BUILD.CANDIDATE_SOURCE_WORKFLOW, refreshed)
        self.assertEqual({key: row for key, row in original.items() if key != BUILD.WORKFLOW},
                         {key: row for key, row in refreshed.items()
                          if key not in {BUILD.CANDIDATE_WORKFLOW, BUILD.CANDIDATE_SOURCE_WORKFLOW}})
        for target, workflow in ((BUILD.INTEL_TARGET, BUILD.CANDIDATE_WORKFLOW),
                                 (BUILD.ARM_TARGET, "foreign/workflow.yml")):
            with self.assertRaisesRegex(BUILD.BuildRefused, "^producer-source-workflow$"):
                BUILD.source_snapshot(Path("/inert/no-access"), target, workflow=workflow)

    def test_preparation_context_joins_dispatch_source_without_entering_native_owner(self):
        source = "a" * 40
        workflow, ref, event = self.candidate()
        with tempfile.TemporaryDirectory(prefix="candidate-python-context-") as name:
            root = Path(name)
            (root / ".git").mkdir()
            head = root / ".git/HEAD"
            head.write_text(source + "\n")
            head.chmod(0o644)
            env = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "macOS",
                   "RUNNER_ARCH": "ARM64", "GITHUB_REPOSITORY": BUILD.REPOSITORY,
                   "GITHUB_EVENT_NAME": event, "GITHUB_REF": ref, "GITHUB_SHA": source,
                   "GITHUB_WORKFLOW_SHA": source, "GITHUB_WORKFLOW_REF": workflow,
                   "GITHUB_JOB": "producer", "GITHUB_WORKSPACE": str(root), "RUNNER_TEMP": str(root),
                   "GITHUB_RUN_ID": "100", "GITHUB_RUN_ATTEMPT": "2"}
            # Finite host DATA fixture; this does not qualify this Mac27 host
            # or enter the native producer admitted only on a hosted Mac26.
            with patch.object(PREP.platform, "mac_ver", return_value=("26.0", (), "arm64")), \
                    patch.object(PREP, "_BUILD", BUILD), patch.object(BUILD, "CHECKOUT", root), \
                    patch.object(BUILD, "WORK_PARENT", root), patch.dict(os.environ, env, clear=True):
                ctx = PREP.context()
                self.assertEqual(ctx["sourceWorkflow"], BUILD.CANDIDATE_WORKFLOW)
                self.assertEqual(PREP.identity_fields(ctx), {"sourceCommit": source, "run": "100", "attempt": "2",
                                                           "target": BUILD.ARM_TARGET, "machine": "arm64"})
                for field, value in (("GITHUB_WORKFLOW_SHA", "b" * 40), ("GITHUB_JOB", "other"),
                                     ("GITHUB_EVENT_NAME", "push"), ("GITHUB_REF", "refs/heads/main")):
                    with self.subTest(field=field), patch.dict(os.environ, {field: value}), \
                            self.assertRaises((BUILD.BuildRefused, PREP.PreparationRefused)):
                        PREP.context()
                with patch.object(PREP.platform, "mac_ver", return_value=("27.0", (), "arm64")), \
                        self.assertRaisesRegex(PREP.PreparationRefused, "^fixed-preparation-host$"):
                    PREP.context()

    def test_workflow_retains_only_closed_supplier_without_activating_candidates(self):
        body = (ROOT / BUILD.CANDIDATE_SOURCE_WORKFLOW).read_text()
        caller = (ROOT / BUILD.CANDIDATE_WORKFLOW).read_text()
        original = (ROOT / BUILD.WORKFLOW).read_text()
        def sections(text):
            starts = list(re.finditer(r"^      - id: ([a-z_]+)$", text, re.MULTILINE))
            return {row[1]: text[row.start():starts[index + 1].start() if index + 1 < len(starts) else len(text)]
                    for index, row in enumerate(starts)}
        old_steps, new_steps = sections(original), sections(body)
        self.assertEqual(list(new_steps), list(old_steps))
        for step in ("checkout", "prepare", "build", "retire", "source_post"):
            self.assertEqual(new_steps[step], old_steps[step])
        self.assertIn("on:\n  workflow_call:", body)
        self.assertNotIn("\n  push:", body)
        self.assertNotIn("workflow_dispatch:", body)
        self.assertIn('"$GITHUB_WORKFLOW_REF" == "$GITHUB_REPOSITORY/' + BUILD.CANDIDATE_WORKFLOW + '@$GITHUB_REF"', body)
        source_job = caller.split("  candidate-python-source:\n", 1)[1].split("  candidate-tests:\n", 1)[0]
        for gate in ("github.event_name == 'workflow_dispatch'", "github.ref == 'refs/heads/verify/desktop-macos-candidate'",
                     "inputs.operation == 'candidate-python-source'", "inputs.target == 'aarch64-apple-darwin'",
                     "github.sha == github.workflow_sha"):
            self.assertIn(gate, source_job)
        self.assertIn("uses: ./" + BUILD.CANDIDATE_SOURCE_WORKFLOW, source_job)
        self.assertNotIn("secrets:", source_job)
        self.assertIn("github.ref == 'refs/heads/verify/desktop-macos-candidate'", body)
        self.assertIn("github.sha == github.workflow_sha", body)
        self.assertIn("cancel-in-progress: false", body)
        supplier = body.split("      - id: supplier\n", 1)[1]
        for gate in ("prepare", "build", "retire", "source_post", "preparation_evidence", "evidence"):
            self.assertIn("steps." + gate + ".outcome == 'success'", supplier)
        self.assertIn("retention-days: 90", supplier)
        self.assertIn("overwrite: false", supplier)
        self.assertIn("/public/supplier.tar", supplier)
        self.assertIn("/public/supplier-receipt.json", supplier)
        for forbidden in ("secrets.", "contents: write", "id-token:", "continue-on-error:",
                          "sudo ", "gh release", "actions/cache@", "actions/download-artifact@"):
            self.assertNotIn(forbidden, body)
        self.assertIn("persist-credentials: false", body)

    def test_source_dispatch_keeps_existing_application_and_signing_jobs_closed(self):
        caller = (ROOT / BUILD.CANDIDATE_WORKFLOW).read_text()
        conditions = {}
        for job in ("engineering-install", "candidate-tests", "xcode-setup-companion",
                    "prepared-install", "shipping-image-compile"):
            section = caller.split("  " + job + ":\n", 1)[1]
            conditions[job] = re.search(r"^    if: (.+)$", section, re.MULTILINE)[1]
        for job in ("engineering-install", "shipping-image-compile"):
            self.assertIn("github.event_name == 'push'", conditions[job])
        self.assertIn("inputs.operation == 'candidate-tests'", conditions["candidate-tests"])
        self.assertIn("inputs.operation == 'xcode-setup-companion'", conditions["xcode-setup-companion"])
        self.assertIn("inputs.operation == 'prepared-install'", conditions["prepared-install"])
        for condition in conditions.values():
            self.assertNotIn("candidate-python-source", condition)
        source_job = caller.split("  candidate-python-source:\n", 1)[1].split("  candidate-tests:\n", 1)[0]
        for forbidden in ("needs:", "environment:", "secrets:", "steps:"):
            self.assertNotIn(forbidden, source_job)


if __name__ == "__main__":
    unittest.main()
