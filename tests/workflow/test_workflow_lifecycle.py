from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from itertools import product
from pathlib import Path

from .workflow_harness import evaluate_condition, load_workflow, simulate_steps, step_by_id


ROOT = Path(__file__).resolve().parents[2]
STAGES = ("candidate", "external-testing", "production-submit")
PLATFORMS = ("android", "ios")
SHA = "1" * 40


def workflow(stage: str) -> dict:
    return load_workflow(ROOT / ".github" / "workflows" / f"reusable-{stage}.yml")


def store_job(stage: str, platform: str) -> dict:
    return workflow(stage)["jobs"][platform + ("_store" if stage == "candidate" else "")]


def calls(steps: list[dict], token: str) -> list[dict]:
    return [step for step in steps if token in step.get("run", "") or token in step.get("uses", "")]


class WorkflowLifecycleTests(unittest.TestCase):
    """Real YAML control flow plus real shell scripts, no credentials/network.

    GitHub expression/action scheduling is simulated, not a hosted-runner claim.
    Helper API/attestation tests and Ruby Store tests separately exercise the
    external boundaries and reconciliation, instead of assuming step success.
    """

    def test_desktop_release_callers_match_packaged_templates_and_forward_optional_trio(self) -> None:
        resource = json.loads((ROOT / "src/mobile_release/api/data/github-setup-v1.json").read_text())
        trio = ("desktop_request", "desktop_source_sha", "desktop_expected_ref")
        for stage in STAGES:
            with self.subTest(stage=stage):
                path = ROOT / "templates/workflows" / f"mobile-{stage}.yml"
                self.assertEqual(path.read_text(), resource["workflows"][stage])
                caller, reusable = load_workflow(path), workflow(stage)
                self.assertEqual(1, len(caller["jobs"]))
                call = next(iter(caller["jobs"].values()))
                self.assertEqual("${{ github.sha }}", call["with"]["source_sha"])
                self.assertEqual(f"__MOBILE_RELEASE_KIT_REPOSITORY__/.github/workflows/reusable-{stage}.yml@__MOBILE_RELEASE_KIT_SHA__", call["uses"])
                for name in trio:
                    for kind, value in (("workflow_dispatch", caller), ("workflow_call", reusable)):
                        # Psych's YAML1.1 loader turns unquoted `on` into the
                        # boolean key; the harness's JSON spelling is `true`.
                        event = value.get("on", value.get("true"))
                        spec = event[kind]["inputs"][name]
                        self.assertEqual((False, "", "string"), (spec["required"], spec["default"], spec["type"]))
                    self.assertEqual("${{ inputs." + name + " }}", call["with"][name])
                self.assertIn(f"format('MRK Desktop {stage} [{{0}}]', inputs.desktop_request)", caller["run-name"])
                self.assertLessEqual(len(caller.get("on", caller.get("true"))["workflow_dispatch"]["inputs"]), 25)
                self.assertEqual({}, caller["permissions"])
                self.assertEqual({"group": "mobile-release-store-mutations", "cancel-in-progress": False}, reusable["concurrency"])

    def test_desktop_source_guard_dominates_every_resolver_build_and_store_job(self) -> None:
        for stage, guard_result, mode in product(STAGES, ("failure", "cancelled", "skipped"), ("fresh", "resume", "complete")):
            with self.subTest(stage=stage, guard=guard_result, mode=mode):
                jobs = workflow(stage)["jobs"]
                guard = jobs["validate-platform"]
                self.assertNotIn("needs", guard); self.assertNotIn("if", guard)
                self.assertEqual({}, guard["permissions"])
                self.assertEqual(1, len(guard["steps"]))
                self.assertNotIn("continue-on-error", guard["steps"][0])
                results = {"validate-platform": {"result": guard_result, "outputs": {}}}
                for name, job in jobs.items():
                    if name == "validate-platform":
                        continue
                    needs = job["needs"] if isinstance(job["needs"], list) else [job["needs"]]
                    self.assertTrue(needs)
                    self.assertTrue(set(needs) <= results.keys(), "every dependency must already have guard-derived results")
                    context = {"inputs": {"platform": "both" if stage != "production-submit" else name},
                               "needs": {key: results[key] for key in needs}}
                    allowed = evaluate_condition(job.get("if"), context,
                        success=all(results[key]["result"] == "success" for key in needs), cancelled=False)
                    self.assertFalse(allowed, f"{stage}/{name} bypasses a non-successful earliest guard")
                    results[name] = {"result": "skipped", "outputs": {"mode": mode}}

    def test_desktop_builtin_guard_preserves_manual_calls_and_refuses_partial_or_drifted_review(self) -> None:
        for stage in STAGES:
            step = workflow(stage)["jobs"]["validate-platform"]["steps"][0]
            platforms = "android|ios" if stage == "production-submit" else "android|ios|both"
            # Admit ONLY this inspected builtin-only program for this contract
            # test. A later script change cannot cause a general workflow step,
            # checkout, project hook, service or Store operation to run here.
            self.assertEqual([
                "set -euo pipefail",
                '[[ "$MOBILE_RELEASE_PLATFORM" =~ ^(' + platforms + ')$ ]]',
                '[[ "$MOBILE_RELEASE_RUNNER_ENVIRONMENT" == "github-hosted" ]]',
                'if [[ -n "$MOBILE_RELEASE_DESKTOP_REQUEST$MOBILE_RELEASE_DESKTOP_SOURCE_SHA$MOBILE_RELEASE_DESKTOP_EXPECTED_REF" ]]; then',
                '  [[ "$MOBILE_RELEASE_DESKTOP_REQUEST" =~ ^[0-9a-f]{32}$ ]]',
                '  [[ "$MOBILE_RELEASE_DESKTOP_SOURCE_SHA" =~ ^[0-9a-f]{40}$ ]]',
                '  [[ "$MOBILE_RELEASE_DESKTOP_EXPECTED_REF" == refs/heads/* ]]',
                '  [[ "$MOBILE_RELEASE_DESKTOP_SOURCE_SHA" == "$MOBILE_RELEASE_SOURCE_SHA" ]]',
                '  [[ "$MOBILE_RELEASE_DESKTOP_SOURCE_SHA" == "$MOBILE_RELEASE_CALLER_SHA" ]]',
                '  [[ "$MOBILE_RELEASE_DESKTOP_EXPECTED_REF" == "$MOBILE_RELEASE_CALLER_REF" ]]',
                "fi",
            ], step["run"].splitlines())
            trio = {"MOBILE_RELEASE_DESKTOP_REQUEST": "d" * 32, "MOBILE_RELEASE_DESKTOP_SOURCE_SHA": SHA,
                    "MOBILE_RELEASE_DESKTOP_EXPECTED_REF": "refs/heads/main"}
            fixed = {"PATH": "/nonexistent", "LC_ALL": "C", "MOBILE_RELEASE_PLATFORM": "android",
                     "MOBILE_RELEASE_RUNNER_ENVIRONMENT": "github-hosted", "MOBILE_RELEASE_SOURCE_SHA": SHA,
                     "MOBILE_RELEASE_CALLER_SHA": SHA, "MOBILE_RELEASE_CALLER_REF": "refs/heads/main"}
            cases = [(dict(zip(trio, values)), all(values) or not any(values))
                     for values in product(*[("", value) for value in trio.values()])]
            cases += [({**trio, name: bad}, False) for name, bad in (
                ("MOBILE_RELEASE_DESKTOP_REQUEST", "short"), ("MOBILE_RELEASE_DESKTOP_SOURCE_SHA", "a" * 40),
                ("MOBILE_RELEASE_DESKTOP_EXPECTED_REF", "refs/tags/main"), ("MOBILE_RELEASE_SOURCE_SHA", "b" * 40),
                ("MOBILE_RELEASE_CALLER_SHA", "c" * 40), ("MOBILE_RELEASE_CALLER_REF", "refs/heads/other"),
                ("MOBILE_RELEASE_RUNNER_ENVIRONMENT", "self-hosted"), ("MOBILE_RELEASE_PLATFORM", "invented"))]
            cases += [({**{key: "" for key in trio}, "MOBILE_RELEASE_PLATFORM": "both"}, stage != "production-submit")]
            for inputs, accepted in cases:
                with self.subTest(stage=stage, inputs=inputs):
                    result = subprocess.run(["/bin/bash", "--noprofile", "--norc", "-c", step["run"]],
                        cwd=ROOT, env={**fixed, **inputs}, stdin=subprocess.DEVNULL,
                        capture_output=True, text=True, close_fds=True, timeout=2)
                    self.assertEqual(accepted, result.returncode == 0)
                    self.assertEqual("", result.stdout)

    def test_candidate_needs_results_never_bypass_the_resolver_or_build(self) -> None:
        states = ("success", "failure", "cancelled", "skipped")
        modes = ("fresh", "prepare", "resume", "complete", "", "invalid")
        for platform in PLATFORMS:
            job = store_job("candidate", platform)
            self.assertEqual([f"{platform}_resolve", f"{platform}_build"], job["needs"])
            for resolver, build, mode, cancelled in product(states, states, modes, (False, True)):
                context = {"needs": {
                    f"{platform}_resolve": {"result": resolver, "outputs": {"mode": mode}},
                    f"{platform}_build": {"result": build},
                }}
                expected = not cancelled and resolver == "success" and (
                    mode in {"resume", "complete"} or (mode == "fresh" and build == "success")
                )
                with self.subTest(platform=platform, resolver=resolver, build=build, mode=mode, cancelled=cancelled):
                    self.assertEqual(expected, evaluate_condition(job["if"], context, success=resolver == build == "success", cancelled=cancelled))

    def test_online_and_build_paths_require_fresh_successful_resolution(self) -> None:
        jobs = workflow("candidate")["jobs"]
        for platform, mode, resolver, online in product(PLATFORMS, ("fresh", "resume", "complete", "prepare", ""), ("success", "failure", "skipped"), ("success", "failure", "skipped")):
            context = {"needs": {
                f"{platform}_resolve": {"result": resolver, "outputs": {"mode": mode}},
                f"{platform}_online": {"result": online},
            }}
            with self.subTest(platform=platform, mode=mode, resolver=resolver, online=online):
                self.assertEqual(mode == "fresh" and resolver == "success", evaluate_condition(jobs[f"{platform}_online"]["if"], context, success=resolver == "success", cancelled=False))
                self.assertEqual(mode == "fresh" and resolver == online == "success", evaluate_condition(jobs[f"{platform}_build"]["if"], context, success=resolver == online == "success", cancelled=False))

    def test_complete_or_missing_mode_cannot_reenter_a_store_or_artifact_action(self) -> None:
        for stage, platform, mode in product(STAGES, PLATFORMS, ("complete", "", "fresh", "invalid")):
            with self.subTest(stage=stage, platform=platform, mode=mode):
                steps, _ = simulate_steps(store_job(stage, platform), mode=mode)
                for token in ("--execute-store", "--prepare-operation", "google-github-actions/auth@", "ruby/setup-ruby@", "actions/attest-build-provenance@", "actions/upload-artifact@", "package-final", "seal-intent"):
                    self.assertEqual([], calls(steps, token), token)
                self.assertFalse(any(step.get("with", {}).get("path") == "app" for step in steps))

    def test_all_six_paths_persist_authority_before_the_only_execution(self) -> None:
        for stage, platform in product(STAGES, PLATFORMS):
            with self.subTest(stage=stage, platform=platform):
                job = store_job(stage, platform)
                steps, _ = simulate_steps(job, mode="prepare")
                indexes = {step["name"]: index for index, step in enumerate(steps)}
                ordered = (
                    "Prepare immutable Store operation without mutation",
                    "Bind durable intent to its actual workflow attempt and job",
                    "Attest original Store intent and producer proof",
                    "Persist immutable authorization before any Store mutation",
                    "Execute or reconcile the exact authorized Store operation",
                    "Validate complete readback chain and package immutable evidence",
                    "Attest complete final evidence and authenticated inventory",
                    "Upload immutable final evidence last; never overwrite an existing artifact",
                )
                positions = [indexes[name] for name in ordered]
                self.assertEqual(sorted(positions), positions)
                self.assertEqual(1, len(calls(steps, "--execute-store")))
                self.assertEqual(1, len(calls(steps, "--prepare-operation")))
                self.assertEqual("upload_final", steps[-1]["id"])
                for identifier in ("upload_intent", "upload_final"):
                    options = step_by_id(job, identifier)["with"]
                    self.assertEqual(90, options["retention-days"])
                    self.assertNotIn("overwrite", options)
                    self.assertEqual("error", options["if-no-files-found"])
                if stage == "candidate":
                    self.assertLess(indexes["Attest exact signed candidate before any Store mutation"], positions[3])

    def test_any_pre_execution_failure_or_cancellation_prevents_mutation(self) -> None:
        for stage, platform in product(STAGES, PLATFORMS):
            job = store_job(stage, platform)
            execute_index = job["steps"].index(step_by_id(job, "execute"))
            for step in job["steps"][:execute_index]:
                for kind in ("fail", "cancel"):
                    with self.subTest(stage=stage, platform=platform, step=step["name"], failure=kind):
                        executed, state = simulate_steps(job, mode="prepare", **{kind: step.get("id", step["name"])})
                        self.assertEqual([], calls(executed, "--execute-store"))
                        self.assertEqual([], calls(executed, "package-final"))
                        for phase in ("prepare", "execute"):
                            auth = state["steps"].get(f"google_{phase}_auth", {})
                            if auth.get("outputs", {}).get("credentials_file_path"):
                                self.assertNotEqual("skipped", state["steps"][f"google_{phase}_cleanup"]["outcome"])

    def test_resume_never_prepares_a_new_intent_or_reuploads_the_old_one(self) -> None:
        for stage, platform in product(STAGES, PLATFORMS):
            with self.subTest(stage=stage, platform=platform):
                steps, _ = simulate_steps(store_job(stage, platform), mode="resume")
                self.assertEqual([], calls(steps, "--prepare-operation"))
                self.assertEqual([], calls(steps, "seal-intent"))
                self.assertNotIn("upload_intent", {step.get("id") for step in steps})
                self.assertEqual(1, len(calls(steps, "--execute-store")))
                self.assertEqual(1 if platform == "android" else 0, len(calls(steps, "google-github-actions/auth@")))

    def test_finalization_failures_have_no_hidden_mutation_retry(self) -> None:
        for stage, platform, fail in product(STAGES, PLATFORMS, ("package", "Attest complete final evidence and authenticated inventory", "upload_final")):
            with self.subTest(stage=stage, platform=platform, failure=fail):
                steps, _ = simulate_steps(store_job(stage, platform), mode="prepare", fail=fail)
                self.assertEqual(1, len(calls(steps, "--execute-store")))
                self.assertEqual(1, sum(step.get("id") == "upload_intent" for step in steps))
                # A resolver-confirmed complete artifact on retry is reference-only.
                reused, _ = simulate_steps(store_job(stage, platform), mode="complete")
                self.assertEqual([], calls(reused, "--execute-store"))
                self.assertEqual([], calls(reused, "actions/upload-artifact@"))

    def test_google_files_are_cleaned_before_third_party_evidence_actions(self) -> None:
        for stage, mode in product(STAGES, ("prepare", "resume")):
            with self.subTest(stage=stage, mode=mode):
                steps, _ = simulate_steps(store_job(stage, "android"), mode=mode)
                live: set[str] = set()
                for step in steps:
                    identifier = step.get("id", "")
                    for phase in ("prepare", "execute"):
                        if identifier == f"google_{phase}_auth":
                            live.add(phase)
                        if identifier == f"google_{phase}_cleanup":
                            live.remove(phase)
                    if calls([step], "actions/attest-build-provenance@") or calls([step], "actions/upload-artifact@"):
                        self.assertEqual(set(), live, step["name"])
                self.assertEqual(set(), live)

    def test_apple_secrets_exist_only_on_the_two_explicit_cli_steps(self) -> None:
        for stage in STAGES:
            for step in store_job(stage, "ios")["steps"]:
                secrets = {key for key, value in step.get("env", {}).items() if "secrets." in str(value)}
                with self.subTest(stage=stage, step=step["name"]):
                    if secrets:
                        self.assertIn(step.get("id"), {"prepare", "execute"})
                        self.assertNotIn("uses", step)
                    self.assertNotIn("MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_BASE64", store_job(stage, "ios").get("env", {}))

    def test_real_ci_shell_passes_fixed_argv_and_never_evaluates_confirmation(self) -> None:
        for stage, platform, mode in product(STAGES, PLATFORMS, ("prepare", "execute")):
            with self.subTest(stage=stage, platform=platform, mode=mode), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                app, tooling, tools = root / "app", root / "tooling", root / "bin"
                for directory in (app, tooling, tools):
                    directory.mkdir()
                capture = root / "argv.json"
                fake_python = tools / "python"
                fake_python.write_text(f"#!{sys.executable}\nimport json,os,sys\nopen(os.environ['CAPTURE'], 'w').write(json.dumps(sys.argv[1:]))\n")
                fake_python.chmod(0o700)
                fake_git = tools / "git"
                fake_git.write_text(f"#!/bin/sh\nprintf '%s\\n' '{SHA}'\n")
                fake_git.chmod(0o700)
                marker = root / "must-not-exist"
                confirmation = f"{stage}:both:1.2.3:42;$(touch {marker})"
                env = {
                    "PATH": f"{tools}:/usr/bin:/bin", "CAPTURE": str(capture),
                    "MOBILE_RELEASE_TOOLING_SHA": SHA, "GITHUB_RUN_ID": "200",
                    "MOBILE_RELEASE_AUTHORIZATION_RUN_ID": "100",
                    "MOBILE_RELEASE_CONFIRMATION": confirmation,
                    "MOBILE_RELEASE_SELECTED_PLATFORM": "both",
                    "MOBILE_RELEASE_RECOVERY_CONFIRMATION": "opaque:operator:confirmation",
                }
                script = step_by_id(store_job(stage, platform), mode)["run"]
                result = subprocess.run(["/bin/bash", "--noprofile", "--norc", "-e", "-o", "pipefail", "-c", script], cwd=app, env=env, capture_output=True, text=True, timeout=20)
                self.assertEqual(0, result.returncode, result.stderr)
                argv = json.loads(capture.read_text())
                self.assertEqual(["-P", "-m", "mobile_release", "ci", stage], argv[:5])
                self.assertEqual(confirmation.replace(":both:", f":{platform}:"), argv[argv.index("--confirm") + 1])
                self.assertEqual("100", argv[argv.index("--recovery-run-id") + 1])
                self.assertEqual("opaque:operator:confirmation", argv[argv.index("--recovery-confirmation") + 1])
                self.assertIn("--prepare-operation" if mode == "prepare" else "--execute-store", argv)
                self.assertNotIn("--run-builds", argv)
                self.assertFalse(marker.exists())

    def test_real_resolver_shell_rejects_conflicting_predecessor_selectors(self) -> None:
        for stage, platform in product(("external-testing", "production-submit"), PLATFORMS):
            with self.subTest(stage=stage, platform=platform), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                tools = root / "bin"
                tools.mkdir()
                git = tools / "git"
                git.write_text(f"#!/bin/sh\nprintf '%s\\n' '{SHA}'\n")
                git.chmod(0o700)
                python = tools / "python"
                python.write_text("#!/bin/sh\ntouch \"$MARKER\"\n")
                python.chmod(0o700)
                marker = root / "resolver-was-invoked"
                env = {"PATH": f"{tools}:/usr/bin:/bin", "MARKER": str(marker), "RUNNER_TEMP": str(root), "MOBILE_RELEASE_TOOLING_SHA": SHA, "MOBILE_RELEASE_RECOVERY_RUN_ID": "", "MOBILE_RELEASE_CANDIDATE_RUN_ID": "100", "MOBILE_RELEASE_CANDIDATE_PLATFORM_RUN_ID": "101", "MOBILE_RELEASE_EXTERNAL_RUN_ID": "", "MOBILE_RELEASE_EXTERNAL_PLATFORM_RUN_ID": ""}
                result = subprocess.run(["/bin/bash", "-e", "-o", "pipefail", "-c", step_by_id(store_job(stage, platform), "resolve")["run"]], cwd=root, env=env, capture_output=True, text=True, timeout=20)
                self.assertNotEqual(0, result.returncode)
                self.assertIn("Conflicting", result.stderr)
                self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()
