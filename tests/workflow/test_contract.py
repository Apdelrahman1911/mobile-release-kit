from __future__ import annotations

import ast
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from mobile_release.stores import _play_state_journal_path

from .workflow_harness import load_workflow, step_by_id


ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"
TEMPLATES = ROOT / "templates" / "workflows"
README = ROOT / "README.md"
LIFECYCLE = ROOT / "docs" / "lifecycle.md"
INTEGRATION = ROOT / "docs" / "integration.md"
CLI = ROOT / "src" / "mobile_release" / "cli.py"
PREFLIGHT_SOURCE = ROOT / "src" / "mobile_release" / "preflight.py"
CREDENTIAL_SOURCE = ROOT / "src" / "mobile_release" / "credentials.py"

REUSABLE = {
    "preflight": WORKFLOWS / "reusable-preflight.yml",
    "candidate": WORKFLOWS / "reusable-candidate.yml",
    "external-testing": WORKFLOWS / "reusable-external-testing.yml",
    "production-submit": WORKFLOWS / "reusable-production-submit.yml",
}
SHARED_CI = WORKFLOWS / "ci.yml"

CALLERS = {
    "preflight": TEMPLATES / "mobile-preflight.yml",
    "candidate": TEMPLATES / "mobile-candidate.yml",
    "external-testing": TEMPLATES / "mobile-external-testing.yml",
    "production-submit": TEMPLATES / "mobile-production-submit.yml",
}

MUTATING = ("candidate", "external-testing", "production-submit")
PROMOTION_ONLY = ("external-testing", "production-submit")
ENVIRONMENT_SECRETS = {
    "candidate": {
        "MOBILE_RELEASE_ANDROID_GOOGLE_SERVICES_JSON_BASE64",
        "MOBILE_RELEASE_ANDROID_KEYSTORE_BASE64",
        "MOBILE_RELEASE_ANDROID_KEYSTORE_PASSWORD",
        "MOBILE_RELEASE_ANDROID_KEY_PASSWORD",
        "MOBILE_RELEASE_APPLE_DISTRIBUTION_P12_BASE64",
        "MOBILE_RELEASE_APPLE_DISTRIBUTION_P12_PASSWORD",
        "MOBILE_RELEASE_APPLE_PROVISIONING_PROFILE_BASE64",
        "MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_BASE64",
        "MOBILE_RELEASE_IOS_GOOGLE_SERVICE_INFO_PLIST_BASE64",
        "MOBILE_RELEASE_PROJECT_READ_TOKEN",
    },
    "external-testing": {
        "MOBILE_RELEASE_OPERATION_COMMITMENT_KEY_BASE64",
        "MOBILE_RELEASE_APPLE_DEMO_ACCOUNT_PASSWORD",
        "MOBILE_RELEASE_APPLE_DEMO_ACCOUNT_USERNAME",
        "MOBILE_RELEASE_APPLE_REVIEW_CONTACT_EMAIL",
        "MOBILE_RELEASE_APPLE_REVIEW_CONTACT_FIRST_NAME",
        "MOBILE_RELEASE_APPLE_REVIEW_CONTACT_LAST_NAME",
        "MOBILE_RELEASE_APPLE_REVIEW_CONTACT_PHONE",
        "MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_BASE64",
    },
    "production-submit": {
        "MOBILE_RELEASE_OPERATION_COMMITMENT_KEY_BASE64",
        "MOBILE_RELEASE_APPLE_DEMO_ACCOUNT_PASSWORD",
        "MOBILE_RELEASE_APPLE_DEMO_ACCOUNT_USERNAME",
        "MOBILE_RELEASE_APPLE_REVIEW_CONTACT_EMAIL",
        "MOBILE_RELEASE_APPLE_REVIEW_CONTACT_FIRST_NAME",
        "MOBILE_RELEASE_APPLE_REVIEW_CONTACT_LAST_NAME",
        "MOBILE_RELEASE_APPLE_REVIEW_CONTACT_PHONE",
        "MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_BASE64",
    },
}
FULL_SHA = re.compile(r"^[0-9a-fA-F]{40}$")
USES_LINE = re.compile(r"^\s*(?:-\s*)?uses:\s*([^\s#]+)", re.MULTILINE)


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def job_block(text: str, job: str) -> str:
    match = re.search(
        rf"(?ms)^  {re.escape(job)}:\n(.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)",
        text,
    )
    if match is None:
        raise AssertionError(f"workflow job is missing: {job}")
    return match.group(1)


def workflow_uses(text: str) -> list[str]:
    return USES_LINE.findall(text)


def external_uses_reference_is_immutable(reference: str) -> bool:
    if reference.startswith("./") or reference.startswith("docker://"):
        return True
    if "@" not in reference:
        return False
    revision = reference.rsplit("@", 1)[1]
    return bool(FULL_SHA.fullmatch(revision))


class ReusableWorkflowContractTests(unittest.TestCase):
    def test_required_reusable_workflows_exist(self) -> None:
        for name, path in REUSABLE.items():
            with self.subTest(workflow=name):
                self.assertTrue(path.is_file(), f"missing {path.relative_to(ROOT)}")

    def test_reusable_workflows_are_call_only(self) -> None:
        for name, path in REUSABLE.items():
            text = read(path)
            with self.subTest(workflow=name):
                self.assertRegex(text, r"(?m)^\s*workflow_call\s*:")
                self.assertNotRegex(text, r"(?m)^\s*(push|pull_request|schedule)\s*:")

    def test_all_external_actions_are_pinned_to_full_sha(self) -> None:
        for path in (*REUSABLE.values(), SHARED_CI):
            for reference in workflow_uses(read(path)):
                with self.subTest(workflow=path.name, reference=reference):
                    self.assertTrue(
                        external_uses_reference_is_immutable(reference),
                        f"{path.relative_to(ROOT)} has mutable/unversioned uses: {reference}",
                    )

    def test_linux_runners_are_version_pinned(self) -> None:
        for path in (*REUSABLE.values(), SHARED_CI):
            runners = re.findall(r"(?m)^\s*runs-on:\s*(ubuntu-[^\s#]+)", read(path))
            with self.subTest(workflow=path.name):
                self.assertTrue(runners)
                self.assertEqual({"ubuntu-24.04"}, set(runners))

    def test_every_reusable_job_aborts_steps_when_runner_reports_self_hosted(self) -> None:
        declaration = "MOBILE_RELEASE_RUNNER_ENVIRONMENT: ${{ runner.environment }}"
        assertion = '[[ "$MOBILE_RELEASE_RUNNER_ENVIRONMENT" == "github-hosted" ]]'
        for name, path in REUSABLE.items():
            text = read(path)
            jobs = len(re.findall(r"(?m)^\s+runs-on:\s*", text))
            with self.subTest(workflow=name):
                self.assertGreaterEqual(jobs, 3)
                self.assertEqual(jobs, text.count(declaration))
                self.assertEqual(jobs, text.count(assertion))

    def test_invalid_direct_platform_inputs_fail_in_an_unconditional_job(self) -> None:
        allowed = {
            "preflight": "^(android|ios|both)$",
            "candidate": "^(android|ios|both)$",
            "external-testing": "^(android|ios|both)$",
            "production-submit": "^(android|ios)$",
        }
        for name, pattern in allowed.items():
            text = read(REUSABLE[name])
            gate = job_block(text, "validate-platform")
            with self.subTest(workflow=name):
                self.assertNotRegex(gate, r"(?m)^\s+if:")
                self.assertIn("permissions: {}", gate)
                self.assertIn(pattern, gate)
                self.assertEqual(2, text.count("needs: validate-platform"))

    def test_no_workflow_inherits_all_secrets(self) -> None:
        for path in REUSABLE.values():
            with self.subTest(workflow=path.name):
                self.assertNotRegex(read(path), r"(?i)secrets\s*:\s*inherit")

    def test_preflight_is_secretless_and_has_no_environment(self) -> None:
        text = read(REUSABLE["preflight"])
        self.assertNotRegex(text, r"(?m)^\s*environment\s*:")
        self.assertNotIn("secrets:", text)
        self.assertNotIn("MOBILE_RELEASE_ANDROID_KEYSTORE", text)
        self.assertNotIn("MOBILE_RELEASE_APPLE_DISTRIBUTION_P12", text)
        self.assertNotIn("MOBILE_RELEASE_ASC_PRIVATE_KEY", text)

    def test_public_preflight_defers_only_explicit_private_dependency_builds(self) -> None:
        text = read(REUSABLE["preflight"])
        self.assertEqual(
            2,
            text.count("jq -e '.source.projectReadTokenRequired == true'"),
        )
        self.assertEqual(2, text.count("build_flag=--run-builds"))
        self.assertEqual(2, text.count("build_flag=--skip-builds"))
        self.assertIn("build-validation-deferred-android.json", text)
        self.assertIn("build-validation-deferred-ios.json", text)
        self.assertEqual(2, text.count("credentialed build validation will run"))

    def test_mutations_share_non_cancelling_concurrency(self) -> None:
        for name in MUTATING:
            text = read(REUSABLE[name])
            with self.subTest(workflow=name):
                self.assertIn("mobile-release-store-mutations", text)
                self.assertRegex(text, r"(?i)cancel-in-progress\s*:\s*false")

    def test_mutations_use_only_fixed_environments(self) -> None:
        expected = {
            "candidate": "mobile-candidate",
            "external-testing": "mobile-external-testing",
            "production-submit": "mobile-production",
        }
        allowed = set(expected.values())
        for name, environment in expected.items():
            text = read(REUSABLE[name])
            with self.subTest(workflow=name):
                actual = set(re.findall(r"(?m)^\s*environment:\s*([^\s#]+)", text))
                self.assertEqual({environment}, actual)
                self.assertLessEqual(actual, allowed)

    def test_workflow_authority_is_bound_to_the_resolved_reusable_workflow(self) -> None:
        for name, path in REUSABLE.items():
            text = read(path)
            with self.subTest(workflow=name):
                self.assertIn("job.workflow_repository", text)
                self.assertIn("job.workflow_sha", text)
                self.assertIn("job.workflow_ref", text)
                self.assertIn("repository: ${{ job.workflow_repository }}", text)
                self.assertIn("ref: ${{ job.workflow_sha }}", text)
                self.assertIn(
                    f'$MOBILE_RELEASE_WORKFLOW_REPOSITORY/.github/workflows/reusable-{name}.yml@',
                    text,
                )
                self.assertIn('MOBILE_RELEASE_SOURCE_SHA" == "$MOBILE_RELEASE_CALLER_SHA', text)
                self.assertNotRegex(text, r"(?m)^\s*repository:\s*[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\s*$")

    def test_configuration_path_is_fixed(self) -> None:
        for name, path in REUSABLE.items():
            text = read(path)
            with self.subTest(workflow=name):
                self.assertIn("release/mobile-release.json", text)
                self.assertNotRegex(text, r"(?m)^\s+config_path\s*:")

    def test_shared_ci_is_credential_free(self) -> None:
        from .test_ci_verification import ci_module, controller_module, coordinator_shell, fixture_paths

        text = read(SHARED_CI)
        self.assertNotIn("secrets.", text)
        self.assertNotRegex(text, r"(?m)^\s*environment\s*:")
        workflow = load_workflow(SHARED_CI)
        for platform, job in (("linux", "test-linux"), ("macos", "test-native-profiles")):
            self.assertEqual(workflow["jobs"][job]["steps"][-1]["run"], coordinator_shell(platform))
        controller = controller_module()
        paths = fixture_paths(controller)
        catalog = controller.catalog(paths, "linux", deadline=12345.0)
        gates = {step.id: step for step in catalog}
        self.assertEqual(len(gates), len(catalog))
        python = gates["python-full"]
        self.assertEqual(python.argv[:6], (str(paths.source_python), "-I", "-B", str(paths.checks), "--check", "python-full"))
        self.assertEqual(dict(python.env)["MOBILE_RELEASE_REQUIRE_RUBY_CONTRACTS"], "1")
        self.assertEqual(dict(python.env)["FASTLANE_SKIP_UPDATE_CHECK"], "true")
        ruby = {Path(step.argv[len(paths.bundle) + 2]).name for step in catalog if step.id.startswith("ruby-")}
        self.assertEqual(ruby, {
            "test_fastlane_support.rb", "test_play_store.rb", "test_play_lanes.rb", "test_apple_store.rb",
            "test_apple_lanes.rb", "test_apple_production.rb", "test_apple_production_lane.rb",
            "test_apple_asset_upload.rb", "test_ios_upload_validation.rb", "test_android_upload_validation.rb",
            "test_native_upload_validation.rb", "test_native_signal_observation.rb",
            "test_native_process_spawn.rb", "test_native_upload_process.rb", "test_installed_ruby_capture.rb",
            "test_workflow_yaml.rb", "test_supply_wif.rb",
        })
        self.assertEqual(gates["fastfile"].argv, (*paths.bundle, "exec", str(paths.ruby),
                                              str(ROOT / "fastlane/run_lane.rb"), "--validate"))
        lock = json.loads(read(ROOT / ".github/verification-tools.json"))
        self.assertEqual(lock["actionlint"]["version"], "1.7.12")
        self.assertEqual(lock["actionlint"]["sha256"], "8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8")
        lint = gates["actionlint"].argv
        self.assertEqual(lint[:4], (str(paths.inputs / "actionlint/actionlint"), "-no-color", "-ignore",
                                  'property "workflow_(repository|sha|ref)" is not defined in object type'))
        self.assertEqual(lint[4:], tuple(map(str, sorted(WORKFLOWS.glob("*.yml")) + sorted(TEMPLATES.glob("*.yml")))))
        build = gates["wheel-build"]
        self.assertEqual(build.argv, (str(paths.source_python), "-I", "-B", "-m", "pip", "wheel", "--no-index",
                                     "--find-links", str(paths.inputs / "python"), "--no-deps", "--wheel-dir",
                                     str(paths.work / "wheels"), str(paths.work / "wheel-build")))
        self.assertNotIn("PIP_NO_BUILD_ISOLATION", dict(build.env))
        smoke = gates["wheel-smoke"]
        self.assertEqual(smoke.argv[:6], (str(paths.wheel_python), "-I", "-B", str(paths.checks), "--check", "wheel-smoke"))
        self.assertEqual(smoke.argv[smoke.argv.index("--wheel") + 1], str(paths.wheel))
        self.assertEqual(smoke.parser, "check")
        self.assertFalse(smoke.cwd.is_relative_to(ROOT))
        ids = [step.id for step in catalog]
        self.assertLess(ids.index("wheel-build"), ids.index("wheel-inspect"))
        self.assertLess(ids.index("wheel-inspect"), ids.index("wheel-install"))
        self.assertLess(ids.index("wheel-install"), ids.index("wheel-smoke"))
        checks = ci_module("ci_checks")
        self.assertEqual(checks.TOOLING_REPOSITORY, "example/mobile-release-kit")
        self.assertEqual(checks.TOOLING_SHA, "1" * 40)
        self.assertEqual(set(checks.TOOLING_FILES), {
            "Gemfile", "Gemfile.lock", "fastlane/Fastfile", "fastlane/play_store.rb", "fastlane/apple_store.rb",
            "fastlane/apple_production.rb", "fastlane/apple_asset_upload.rb", "fastlane/apple_create_retry.rb",
            "fastlane/ios_upload_validation.rb", "fastlane/android_upload_validation.rb", "fastlane/native_upload_validation.rb",
            "fastlane/native_process_spawn.rb", "fastlane/native_upload_process.rb",
            "fastlane/release_support.rb", "fastlane/run_lane.rb", "schemas/project.schema.json", "schemas/candidate.schema.json",
            "schemas/receipt.schema.json", "schemas/store-operation-intent.schema.json", "templates/mobile-release.json",
            "templates/workflows/mobile-preflight.yml", "templates/workflows/mobile-candidate.yml",
            "templates/workflows/mobile-external-testing.yml", "templates/workflows/mobile-production-submit.yml",
        })

    def test_android_play_state_journals_are_retained_after_credential_cleanup(self) -> None:
        for workflow, receipt in (("candidate", "android-internal.json"), ("external-testing", "android-external.json"), ("production-submit", "android-production-draft.json")):
            job = load_workflow(REUSABLE[workflow])["jobs"]["android_store" if workflow == "candidate" else "android"]
            cleanup = step_by_id(job, "google_execute_cleanup")
            journal = _play_state_journal_path(Path(receipt)).name
            retained = [step for step in job["steps"] if step.get("with", {}).get("path") == f"app/.mobile-release/store/{journal}"]
            with self.subTest(workflow=workflow):
                self.assertEqual(1, len(retained))
                step = retained[0]
                self.assertLess(job["steps"].index(cleanup), job["steps"].index(step))
                self.assertIn("steps.google_execute_cleanup.outcome == 'success'", step["if"])
                self.assertIn("always()", step["if"])
                self.assertIn(f"hashFiles('app/.mobile-release/store/{journal}')", step["if"])
                self.assertIs(step["with"]["include-hidden-files"], True)

    def test_reusable_workflows_execute_exact_checkout_without_package_install(self) -> None:
        forbidden = (
            "pip install",
            "python -m pip",
            "pipx install",
            "poetry install",
            "uv pip",
            "uv sync",
            "cache: pip",
        )
        for name, path in REUSABLE.items():
            text = read(path)
            with self.subTest(workflow=name):
                self.assertIn("PYTHONPATH: ${{ github.workspace }}/tooling/src", text)
                for command in forbidden:
                    self.assertNotIn(command, text)

    def test_store_workflows_disable_fastlane_update_network_checks(self) -> None:
        for name in MUTATING:
            text = read(REUSABLE[name])
            with self.subTest(workflow=name):
                self.assertIn("FASTLANE_SKIP_UPDATE_CHECK: 'true'", text)
                self.assertIn("FASTLANE_OPT_OUT_USAGE: 'true'", text)

    def test_promotions_cannot_build_or_receive_signing_material(self) -> None:
        forbidden = (
            "gradlew",
            "assembleRelease",
            "bundleRelease",
            "xcodebuild archive",
            "MOBILE_RELEASE_ANDROID_KEYSTORE_BASE64",
            "MOBILE_RELEASE_ANDROID_KEYSTORE_PASSWORD",
            "MOBILE_RELEASE_ANDROID_KEY_PASSWORD",
            "MOBILE_RELEASE_APPLE_DISTRIBUTION_P12_BASE64",
            "MOBILE_RELEASE_APPLE_DISTRIBUTION_P12_PASSWORD",
            "MOBILE_RELEASE_APPLE_PROVISIONING_PROFILE_BASE64",
        )
        for name in PROMOTION_ONLY:
            text = read(REUSABLE[name])
            for token in forbidden:
                with self.subTest(workflow=name, forbidden=token):
                    self.assertNotIn(token, text)

    def test_promotions_download_evidence_not_candidate_binaries(self) -> None:
        for name in PROMOTION_ONLY:
            text = read(REUSABLE[name])
            with self.subTest(workflow=name):
                self.assertIn("mobile_release.workflow", text)
                self.assertIn("--candidate-run-id", text)
                self.assertIn(".mobile-release/input/candidate/candidate-manifest.json", text)
                self.assertNotIn("candidate-binaries", text)
                self.assertNotIn("app-release.aab", text)
                self.assertNotIn("app.ipa", text)

    def test_prior_evidence_attestations_bind_workflow_and_tooling_digest(self) -> None:
        helper = read(ROOT / "src/mobile_release/workflow.py")
        for flag in ("--signer-workflow", "--signer-digest", "--source-digest", "--source-ref", "--deny-self-hosted-runners"):
            self.assertIn(flag, helper)
        for name in PROMOTION_ONLY:
            for platform in ("android", "ios"):
                job = load_workflow(REUSABLE[name])["jobs"][platform]
                resolve = step_by_id(job, "resolve")
                self.assertIn("python -P -m mobile_release.workflow", resolve["run"])
                self.assertLess(job["steps"].index(resolve), job["steps"].index(step_by_id(job, "prepare")))
                self.assertEqual("${{ github.token }}", resolve["env"]["GH_TOKEN"])

    def test_predecessors_use_authenticated_producer_attempts_not_run_success(self) -> None:
        helper = read(ROOT / "src/mobile_release/workflow.py")
        self.assertIn("/attempts/{attempt}", helper)
        self.assertIn("/attempts/{authority['attempt']}/jobs", helper)
        self.assertIn("runInvocationURI", helper)
        self.assertIn('type(job.get("run_attempt")) is int', helper)
        self.assertIn('job["run_attempt"] == authority["attempt"]', helper)
        self.assertIn('result.get("event") == "workflow_dispatch"', helper)
        self.assertIn('result.get("path") == authority["callerPath"]', helper)
        for name in PROMOTION_ONLY:
            text = read(REUSABLE[name])
            self.assertNotIn('.conclusion == "success"', text)
            self.assertNotIn('.run_attempt == $attempt', text)
            for platform in ("android", "ios"):
                self.assertIn(f"inputs.candidate_{platform}_run_id", text)
        # Behavioral fake-API cases cover job/attempt/certificate mismatches;
        # the workflows must reach that helper rather than inline jq guesses.

    def test_release_evidence_uses_the_audited_provenance_action(self) -> None:
        expected = (
            "actions/attest-build-provenance@"
            "4d101475d8b20a2381f78447822ac1eab6504dd8"
        )
        for name in MUTATING:
            text = read(REUSABLE[name])
            with self.subTest(workflow=name):
                self.assertIn(expected, text)
                self.assertNotIn("uses: actions/attest@", text)

    def test_production_resolves_original_source_before_staging_or_store_execution(self) -> None:
        for platform in ("android", "ios"):
            job = load_workflow(REUSABLE["production-submit"])["jobs"][platform]
            checkout = next(step for step in job["steps"] if step.get("with", {}).get("path") == "app")
            self.assertEqual("${{ steps.resolve.outputs.source_sha }}", checkout["with"]["ref"])
            self.assertEqual(0, checkout["with"]["fetch-depth"])
            stage = next(step for step in job["steps"] if "mobile_release.workflow stage" in step.get("run", ""))
            self.assertIn('git -C app rev-parse HEAD', stage["run"])
            self.assertIn("git -C app rev-parse 'HEAD^{tree}'", stage["run"])
            self.assertLess(job["steps"].index(stage), job["steps"].index(step_by_id(job, "prepare")))
            self.assertNotIn("GITHUB_SHA=", read(REUSABLE["production-submit"]))

    def test_candidate_uses_verified_bundletool_and_one_ephemeral_ios_signing_owner(self) -> None:
        text = read(REUSABLE["candidate"])
        self.assertIn("BUNDLETOOL_VERSION: 1.18.3", text)
        self.assertIn("a099cfa1543f55593bc2ed16a70a7c67fe54b1747bb7301f37fdfd6d91028e29", text)
        self.assertIn("sha256sum --check --status", text)
        self.assertNotIn("security import", text)
        self.assertNotIn("security create-keychain", text)
        self.assertNotIn("base64 --decode", text)
        build = load_workflow(REUSABLE["candidate"])["jobs"]["ios_build"]
        signing = [step for step in build["steps"] if "--signing" in step.get("run", "")]
        self.assertEqual(1, len(signing))
        self.assertIn("--run-builds", signing[0]["run"])
        self.assertIn("--platform ios", signing[0]["run"])
        self.assertIn("def _temporary_apple_signing_environment", read(CREDENTIAL_SOURCE))

    def test_actual_consumer_toolchains_are_pinned(self) -> None:
        for name, path in REUSABLE.items():
            text = read(path)
            document = load_workflow(path)
            for key, job in document["jobs"].items():
                if job["runs-on"] == "macos-26":
                    with self.subTest(workflow=name, job=key, tool="xcode"):
                        self.assertEqual("/Applications/Xcode_26.3.app/Contents/Developer", job["env"]["DEVELOPER_DIR"])
                        scripts = "\n".join(step.get("run", "") for step in job["steps"])
                        self.assertIn('== "Xcode 26.3"', scripts)
                        self.assertIn('== "Build version 17C529"', scripts)
            if name in ("preflight", "candidate"):
                self.assertIn("XCODEGEN_VERSION: 2.45.4", text)
                self.assertIn("090ec29491aad50aec10631bf6e62253fed733c50f3aab0f5ffc86bc170bdbef", text)
                java = [step["with"]["java-version"] for job in document["jobs"].values() for step in job["steps"] if "actions/setup-java@" in step.get("uses", "")]
                self.assertGreaterEqual(len(java), 2)
                self.assertEqual({"21"}, set(java))
        for path in (*REUSABLE.values(), SHARED_CI):
            ruby = [step["with"]["ruby-version"] for job in load_workflow(path)["jobs"].values() for step in job["steps"] if "ruby/setup-ruby@" in step.get("uses", "")]
            if ruby:
                self.assertEqual({"3.3.12"}, set(ruby))

    def test_android_project_build_cannot_inherit_google_play_adc(self) -> None:
        text = read(REUSABLE["candidate"])
        online = job_block(text, "android_online")
        build = job_block(text, "android_build")
        store = job_block(text, "android_store")
        self.assertIn("Authenticate to Google Play for non-publishing online gate", online)
        self.assertIn("Remove online-gate Google Play credentials", online)
        jobs = load_workflow(REUSABLE["candidate"])["jobs"]
        self.assertIn("android_online", jobs["android_build"]["needs"])
        self.assertIn("android_build", jobs["android_store"]["needs"])
        self.assertIn("Build, sign, and validate Android candidate without Store authority", build)
        for token in ("id-token: write", "google-github-actions/auth@", "GOOGLE_APPLICATION_CREDENTIALS", "MOBILE_RELEASE_GOOGLE_WIF_PROVIDER", "--execute-store"):
            self.assertNotIn(token, build)
        self.assertIn("Authenticate to Google Play for execute", store)
        self.assertIn("--execute-store", store)
        self.assertNotIn("--run-builds", store)
        self.assertNotIn("./gradlew", store)
        self.assertIn("cache-disabled: true", text)

    def test_google_adc_is_removed_before_non_store_postprocessing(self) -> None:
        for stage in MUTATING:
            job = load_workflow(REUSABLE[stage])["jobs"]["android_store" if stage == "candidate" else "android"]
            for phase, consumer in (("prepare", "prepare"), ("execute", "execute")):
                with self.subTest(workflow=stage, phase=phase):
                    cleanup = step_by_id(job, f"google_{phase}_cleanup")
                    self.assertLess(job["steps"].index(step_by_id(job, consumer)), job["steps"].index(cleanup))
                    self.assertIn("always()", cleanup["if"])
                    self.assertIn(f"steps.google_{phase}_auth.outputs.credentials_file_path", cleanup["if"])
                    self.assertIn('rm -f -- "$MOBILE_RELEASE_GOOGLE_ADC_PATH"', cleanup["run"])
                    self.assertIn('[[ ! -e "$MOBILE_RELEASE_GOOGLE_ADC_PATH" && ! -L "$MOBILE_RELEASE_GOOGLE_ADC_PATH" ]]', cleanup["run"])

    def test_every_generated_google_adc_is_restricted_before_use(self) -> None:
        jobs = [(load_workflow(REUSABLE[stage])["jobs"]["android_store" if stage == "candidate" else "android"], ("prepare", "execute")) for stage in MUTATING]
        jobs.append((load_workflow(REUSABLE["candidate"])["jobs"]["android_online"], ("online",)))
        for job, phases in jobs:
            for phase in phases:
                auth = step_by_id(job, f"google_{phase}_auth")
                consumer = next(step for step in job["steps"] if ("--online" in step.get("run", "") if phase == "online" else step.get("id") == phase))
                between = job["steps"][job["steps"].index(auth) + 1 : job["steps"].index(consumer)]
                restrictions = [step for step in between if 'chmod 600 -- "$MOBILE_RELEASE_GOOGLE_ADC_PATH"' in step.get("run", "")]
                self.assertEqual(1, len(restrictions))
                restricted = restrictions[0]
                self.assertIn(f"steps.google_{phase}_auth.outputs.credentials_file_path", restricted["env"]["MOBILE_RELEASE_GOOGLE_ADC_PATH"])
                for fragment in ('[[ -f "$MOBILE_RELEASE_GOOGLE_ADC_PATH"', '! -L "$MOBILE_RELEASE_GOOGLE_ADC_PATH"', "stat -c '%a'", '"$GITHUB_WORKSPACE"/*|"$RUNNER_TEMP"/*'):
                    self.assertIn(fragment, restricted["run"])

    def test_candidate_store_credentials_cannot_reenter_project_code(self) -> None:
        candidate = read(REUSABLE["candidate"])
        for platform, window in (
            ("android-online", job_block(candidate, "android_online")),
            ("android-store", job_block(candidate, "android_store")),
            ("ios-online", job_block(candidate, "ios_online")),
            ("ios-store", job_block(candidate, "ios_store")),
        ):
            with self.subTest(platform=platform):
                self.assertNotIn("./gradlew", window)
                self.assertNotIn("--run-builds", window)
                self.assertNotIn("prepareCommand", window)
                self.assertNotIn("projectChecks", window)

        for platform, window in (
            ("android", job_block(candidate, "android_build")),
            ("ios", job_block(candidate, "ios_build")),
        ):
            with self.subTest(platform=f"{platform}-build"):
                self.assertIn("--run-builds", window)
                self.assertNotIn("id-token: write", window)
                self.assertNotIn("MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_BASE64", window)
                self.assertNotIn("google-github-actions/auth@", window)
                self.assertNotIn("--execute-store", window)

        tree = ast.parse(read(CLI))
        policy = next(
            node
            for node in tree.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == "_require_ci_policy"
        )
        direct_calls = {
            node.func.id
            for node in ast.walk(policy)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }
        self.assertEqual(
            {"ValidationError", "doctor", "metadata_findings"},
            direct_calls,
            "mutation-time CI policy must stay static and must not execute application code",
        )

    def test_online_preflight_returns_before_any_project_or_build_execution(self) -> None:
        source = read(PREFLIGHT_SOURCE)
        online_project_gate = source.index('if mode == "online":')
        online_store_gate = source.index('if mode == "online":', online_project_gate + 1)
        online_return = source.index("        return report", online_store_gate)
        effective_identity = source.index("effective_identity_findings", online_return)
        project_build_loop = source.index("if run_builds:", effective_identity)
        self.assertIn("else:", source[online_project_gate:online_store_gate])
        self.assertIn("run_project_checks", source[online_project_gate:online_store_gate])
        self.assertLess(online_return, effective_identity)
        self.assertLess(online_return, project_build_loop)

    def test_candidate_handoff_is_fixed_checksum_bound_and_revalidated(self) -> None:
        candidate = read(REUSABLE["candidate"])
        for platform, primary in (("android", "app-release.aab"), ("ios", "app.ipa")):
            build = load_workflow(REUSABLE["candidate"])["jobs"][f"{platform}_build"]
            store = load_workflow(REUSABLE["candidate"])["jobs"][f"{platform}_store"]
            with self.subTest(platform=platform):
                handoff = step_by_id(build, "upload_handoff")
                self.assertEqual(f"mobile-release-candidate-handoff-{platform}", handoff["with"]["name"])
                self.assertEqual(90, handoff["with"]["retention-days"])
                self.assertIn("artifact-digest", build["outputs"]["handoff_digest"])
                resolve = step_by_id(store, "resolve")
                self.assertEqual("${{ needs." + platform + "_build.outputs.handoff_digest }}", resolve["env"]["MOBILE_RELEASE_HANDOFF_DIGEST"])
                self.assertIn("--handoff-digest", resolve["run"])
                self.assertIn('[[ "$MOBILE_RELEASE_HANDOFF_DIGEST" =~ ^[0-9a-f]{64}$ ]]', resolve["run"])
                self.assertIn("SHA256SUMS", job_block(candidate, f"{platform}_build"))
                self.assertIn(primary, step_by_id(store, "prepare")["run"])
                self.assertIn("--execute-store", step_by_id(store, "execute")["run"])

    def test_tooling_commit_is_rechecked_in_each_store_authenticated_python_step(self) -> None:
        jobs = (
            ("candidate", "android_online", "python -P -m mobile_release preflight"),
            ("candidate", "ios_online", "python -P -m mobile_release preflight"),
            ("candidate", "android_store", "python -P -m mobile_release ci candidate"),
            ("candidate", "ios_store", "python -P -m mobile_release ci candidate"),
            (
                "external-testing",
                "android",
                "python -P -m mobile_release ci external-testing",
            ),
            (
                "external-testing",
                "ios",
                "python -P -m mobile_release ci external-testing",
            ),
            (
                "production-submit",
                "android",
                "python -P -m mobile_release ci production-submit",
            ),
            (
                "production-submit",
                "ios",
                "python -P -m mobile_release ci production-submit",
            ),
        )
        check = '[[ "$(git -C ../tooling rev-parse HEAD)" == "$MOBILE_RELEASE_TOOLING_SHA" ]]'
        for workflow, job, command in jobs:
            body = job_block(read(REUSABLE[workflow]), job)
            mutation = body.index(command)
            step_start = body.rfind("set -euo pipefail", 0, mutation)
            with self.subTest(workflow=workflow, job=job):
                self.assertGreaterEqual(step_start, 0)
                self.assertIn(check, body[step_start:mutation])

    def test_pinned_tooling_cannot_be_shadowed_by_an_application_package(self) -> None:
        for name, path in (*REUSABLE.items(), ("ci", SHARED_CI)):
            text = read(path)
            with self.subTest(workflow=name):
                self.assertIn("PYTHONSAFEPATH: '1'", text)
                self.assertNotRegex(text, r"(?<!-P )python -m mobile_release")

        with tempfile.TemporaryDirectory() as temporary:
            cwd = Path(temporary)
            hostile = cwd / "mobile_release"
            hostile.mkdir()
            (hostile / "__init__.py").write_text(
                "raise RuntimeError('APP_PACKAGE_EXECUTED')\n", encoding="utf-8"
            )
            environ = os.environ.copy()
            environ["PYTHONPATH"] = str(ROOT / "src")
            environ["PYTHONSAFEPATH"] = "1"
            result = subprocess.run(
                [
                    sys.executable,
                    "-P",
                    "-c",
                    "import mobile_release; print(mobile_release.__file__)",
                ],
                cwd=cwd,
                env=environ,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertNotIn("APP_PACKAGE_EXECUTED", result.stderr + result.stdout)
            self.assertEqual(
                (ROOT / "src/mobile_release/__init__.py").resolve(),
                Path(result.stdout.strip()).resolve(),
            )

    def test_generated_fastlane_artifacts_never_belong_to_the_source_tree(self) -> None:
        ignored = read(ROOT / ".gitignore").splitlines()
        for relative in (
            "fastlane/report.xml",
            "fastlane/Preview.html",
            "fastlane/screenshots",
            "fastlane/test_output",
        ):
            with self.subTest(path=relative):
                self.assertFalse((ROOT / relative).exists())
        for pattern in (
            "fastlane/report.xml",
            "fastlane/Preview.html",
            "fastlane/screenshots/",
            "fastlane/test_output/",
        ):
            self.assertIn(pattern, ignored)

    def test_cheap_doctor_gate_precedes_expensive_project_tool_setup(self) -> None:
        for workflow in ("preflight", "candidate"):
            text = read(REUSABLE[workflow])
            with self.subTest(workflow=workflow, platform="android"):
                self.assertLess(text.index("Diagnose Android"), text.index("Set up Java"))
                self.assertLess(text.index("Diagnose Android"), text.index("Install pinned bundletool"))
            with self.subTest(workflow=workflow, platform="ios"):
                self.assertLess(text.index("Diagnose iOS"), text.index("Install pinned XcodeGen"))
        preflight = read(REUSABLE["preflight"])
        self.assertEqual(2, preflight.count("if: always()"))
        self.assertEqual(2, preflight.count("if-no-files-found: warn"))

    def test_every_app_writing_job_establishes_a_non_symlink_private_root(self) -> None:
        for name, path in REUSABLE.items():
            text = read(path)
            with self.subTest(workflow=name):
                app_checkouts = len(re.findall(r"(?m)^\s+path: app\s*$", text))
                self.assertGreaterEqual(app_checkouts, 2)
                self.assertEqual(
                    app_checkouts,
                    text.count("Establish safe private workflow output directory"),
                )
                self.assertEqual(app_checkouts, text.count('[[ -d "$output" && ! -L "$output" ]]'))
                self.assertEqual(app_checkouts, text.count('find "$output" -mindepth 1 -print -quit'))

    def test_candidate_retains_exact_manifest_bound_metadata_and_validation_report(self) -> None:
        for platform in ("android", "ios"):
            job = load_workflow(REUSABLE["candidate"])["jobs"][f"{platform}_store"]
            for identifier in ("prepare", "execute"):
                self.assertIn(f"--artifact validation-report=.mobile-release/artifacts/{platform}/validation-report.json", step_by_id(job, identifier)["run"])
            intent = step_by_id(job, "upload_intent")
            self.assertEqual("app/.mobile-release/operation", intent["with"]["path"])
            final = step_by_id(job, "upload_final")
            self.assertEqual(f"app/.mobile-release/package/candidate/{platform}", final["with"]["path"])
        helper = read(ROOT / "src/mobile_release/workflow.py")
        self.assertIn("store-metadata.zip", helper)
        self.assertNotIn("candidate-binaries", read(REUSABLE["candidate"]))

    def test_every_new_receipt_is_chain_validated_before_attestation(self) -> None:
        for stage in MUTATING:
            for platform in ("android", "ios"):
                job = load_workflow(REUSABLE[stage])["jobs"][platform + ("_store" if stage == "candidate" else "")]
                package = step_by_id(job, "package")
                attest = next(step for step in job["steps"] if step["name"] == "Attest complete final evidence and authenticated inventory")
                self.assertIn("mobile_release.workflow package-final", package["run"])
                self.assertIn(f"--evidence-dir app/.mobile-release/staging/{stage}/{platform}", package["run"])
                self.assertLess(job["steps"].index(package), job["steps"].index(attest))
                self.assertIn(f"/{stage}-receipt.json", attest["with"]["subject-path"])
                self.assertIn("/workflow-provenance.json", attest["with"]["subject-path"])
                self.assertIn("/store-receipt.json", attest["with"]["subject-path"])

    def test_local_bundletool_pin_matches_candidate_workflow(self) -> None:
        workflow = read(REUSABLE["candidate"])
        integration = read(INTEGRATION)
        version = "1.18.3"
        digest = "a099cfa1543f55593bc2ed16a70a7c67fe54b1747bb7301f37fdfd6d91028e29"
        for document in (workflow, integration):
            self.assertIn(version, document)
            self.assertIn(digest, document)
        self.assertIn(
            "github.com/google/bundletool/releases/download/1.18.3/"
            "bundletool-all-1.18.3.jar",
            integration,
        )

    def test_production_has_no_automatic_public_release_setting(self) -> None:
        text = read(REUSABLE["production-submit"])
        self.assertNotRegex(text, r"(?i)automatic[_-]release\s*[:=]\s*true")
        self.assertNotRegex(text, r"(?i)(release_status|track_promote_release_status)\s*[:=]\s*completed")

    def test_expected_receipt_directories_are_explicit(self) -> None:
        for stage in MUTATING:
            for platform in ("android", "ios"):
                text = read(REUSABLE[stage])
                self.assertIn(f".mobile-release/staging/{stage}/{platform}", text)
                self.assertIn(f".mobile-release/package/{stage}/{platform}", text)


class CallerTemplateContractTests(unittest.TestCase):
    def test_required_caller_templates_exist(self) -> None:
        for name, path in CALLERS.items():
            with self.subTest(template=name):
                self.assertTrue(path.is_file(), f"missing {path.relative_to(ROOT)}")

    def test_mutating_callers_are_manual_only(self) -> None:
        for name in MUTATING:
            text = read(CALLERS[name])
            with self.subTest(template=name):
                self.assertRegex(text, r"(?m)^\s*workflow_dispatch\s*:")
                self.assertNotRegex(text, r"(?m)^\s*(push|pull_request|schedule)\s*:")

    def test_callers_do_not_inherit_secrets(self) -> None:
        for path in CALLERS.values():
            with self.subTest(template=path.name):
                text = read(path)
                self.assertNotRegex(text, r"(?i)secrets\s*:\s*inherit")
                self.assertNotRegex(
                    text,
                    r"(?m)^\s+secrets\s*:",
                    "fixed-environment secrets must be resolved by the called jobs",
                )

    def test_environment_secrets_are_not_declared_as_caller_inputs(self) -> None:
        for name in MUTATING:
            text = read(REUSABLE[name])
            trigger = text.split("permissions:", 1)[0]
            with self.subTest(workflow=name):
                self.assertNotRegex(trigger, r"(?m)^\s+secrets\s*:")

    def test_fixed_environment_secret_matrices_are_exact_and_explicit(self) -> None:
        for name, expected in ENVIRONMENT_SECRETS.items():
            text = read(REUSABLE[name])
            actual = set(re.findall(r"secrets\.([A-Z0-9_]+)", text))
            with self.subTest(workflow=name):
                self.assertEqual(expected, actual)
                for secret in expected:
                    self.assertIn(f"{secret}: ${{{{ secrets.{secret} }}}}", text)

    def test_templates_pin_uses_and_tooling_sha_to_same_placeholder(self) -> None:
        placeholder = "__MOBILE_RELEASE_KIT_SHA__"
        repository = "__MOBILE_RELEASE_KIT_REPOSITORY__"
        for name, path in CALLERS.items():
            text = read(path)
            with self.subTest(template=name):
                self.assertIn(f"uses: {repository}/.github/workflows/", text)
                self.assertIn(f"@{placeholder}", text)
                self.assertRegex(
                    text,
                    rf"(?m)^\s*tooling_sha\s*:\s*['\"]?{placeholder}['\"]?\s*$",
                )

    def test_callers_always_use_the_dispatched_commit_as_source(self) -> None:
        for name, path in CALLERS.items():
            text = read(path)
            with self.subTest(template=name):
                self.assertRegex(text, r"(?m)^\s*source_sha:\s*\$\{\{ github\.sha \}\}\s*$")
                self.assertNotRegex(text, r"(?m)^\s+source_sha:\s*\n")


class DocumentationContractTests(unittest.TestCase):
    def test_quick_start_requires_explicit_tooling_repository_and_sha(self) -> None:
        readme = read(README)
        integration = read(INTEGRATION)
        for document in (readme, integration):
            self.assertIn("--tooling-repository <TOOLING_OWNER>/<TOOLING_REPOSITORY>", document)
            self.assertIn("--tooling-sha", document)

    def test_status_is_documented_as_evidence_only(self) -> None:
        readme = read(README)
        lifecycle = read(LIFECYCLE)
        self.assertIn(
            "`mobile-release status` | none | Validate and summarize recorded evidence; "
            "it does not query either Store.",
            readme,
        )
        self.assertIn("status` validates recorded evidence only", lifecycle)
        self.assertIn(
            "Later asynchronous progress requires a separate non-publishing Console or API check",
            lifecycle,
        )
        self.assertNotIn("a later `status` run records progress", lifecycle)

    def test_single_profile_scope_is_explicit(self) -> None:
        readme = read(README)
        integration = read(INTEGRATION)
        for document in (readme, integration):
            with self.subTest(document=document[:40]):
                self.assertIn("one provisioning profile", document)
                self.assertIn("main application Bundle ID", document)
                self.assertIn("project-owned signing", document)

    def test_runner_guard_is_documented_as_defense_in_depth(self) -> None:
        documents = (read(README), read(INTEGRATION), read(ROOT / "SECURITY.md"))
        for document in documents:
            with self.subTest(document=document[:40]):
                self.assertIn("not a server-side", document)
                self.assertIn("self-hosted runner", document)
                self.assertIn("ubuntu-24.04", document)
                self.assertIn("macos-26", document)


if __name__ == "__main__":
    unittest.main()
