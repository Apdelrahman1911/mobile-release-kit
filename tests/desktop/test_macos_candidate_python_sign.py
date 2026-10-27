"""Candidate signing admission and receipt DATA; never credentials or signing."""
import importlib.util
import json
from pathlib import Path
import re
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


HELPER = load("_mrk_candidate_sign_helper", "desktop/tools/macos_android_helper_package.py")
STAGE = load("_mrk_candidate_sign_stage", "desktop/tools/stage_macos_installed.py")
BUILD = load("_mrk_candidate_sign_source", "desktop/tools/macos_cpython_source_build.py")
FIXTURES = load("_mrk_candidate_sign_receipt_fixture", "tests/desktop/test_macos_fresh_python_consumer.py")


class CandidatePythonSigningTests(unittest.TestCase):
    def environment(self):
        source = "a" * 40
        return {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "macOS",
                "RUNNER_ARCH": "ARM64", "GITHUB_REPOSITORY": "Apdelrahman1911/mobile-release-kit",
                "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REF": HELPER.CANDIDATE_REF,
                "GITHUB_WORKFLOW_REF": STAGE.signed_python_workflow(STAGE.ARM_TARGET),
                "GITHUB_SHA": source, "GITHUB_WORKFLOW_SHA": source,
                "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1", "GITHUB_JOB": "signed-python",
                "GITHUB_WORKSPACE": str(ROOT), "MRK_EXPECTED_SHA": source,
                "MRK_MACOS_INSTALL_SOURCE_COMMIT": source, "DEVELOPER_DIR": "/Library/Developer/CommandLineTools",
                "MACOSX_DEPLOYMENT_TARGET": "26.0", "MRK_MACOS_PYTHON_SIGNING_SCOPE": "candidate-only",
                "MRK_MACOS_WORK": str(HELPER.WORK_PARENT / "mrk-macos-python-signing.ABCDEFGH")}

    def admitted(self, environment, *, phase="python-shipping", target=STAGE.ARM_TARGET):
        # Actual local host observation, inert environment/path DATA only.
        # No owner creation, credential access, child, or local qualification.
        with patch.object(HELPER, "CHECKOUT", ROOT):
            return HELPER.admit(environment, phase=phase, target=target)

    def test_exact_arm_candidate_derivation_is_admitted_as_data(self):
        env = self.environment()
        self.assertTrue(HELPER.candidate_python_signing_context(env, "python-shipping", STAGE.ARM_TARGET))
        self.assertEqual(self.admitted(env), Path(env["MRK_MACOS_WORK"]))

    def test_foreign_source_event_job_and_purpose_fail_before_owner_creation(self):
        env = self.environment()
        for field, value in (("GITHUB_EVENT_NAME", "push"), ("GITHUB_EVENT_NAME", "pull_request"),
                             ("GITHUB_REF", "refs/heads/main"), ("GITHUB_JOB", "producer"),
                             ("GITHUB_WORKFLOW_REF", env["GITHUB_WORKFLOW_REF"].replace("installed.yml", "foreign.yml")),
                             ("GITHUB_REPOSITORY", "foreign/repository"), ("GITHUB_WORKFLOW_SHA", "b" * 40),
                             ("MRK_EXPECTED_SHA", "b" * 40), ("GITHUB_RUN_ID", "0"),
                             ("MRK_MACOS_PYTHON_SIGNING_SCOPE", "disabled")):
            with self.subTest(field=field, value=value), self.assertRaises(HELPER.Refused):
                self.admitted({**env, field: value})
        for phase in ("python-engineering", "sign-desktop-image", "package-install"):
            with self.subTest(phase=phase), self.assertRaises(HELPER.Refused):
                self.admitted(env, phase=phase)
        self.assertFalse(HELPER.candidate_python_signing_context(env, "python-shipping", STAGE.INTEL_TARGET))

    def test_candidate_scope_cannot_borrow_install_notary_or_native_authority(self):
        env = self.environment()
        for field, value in (("MRK_MACOS_NATIVE_SCOPE", "tool-setup"), ("MRK_MACOS_PREPARED_RESUME", "true"),
                             ("MRK_MACOS_SAME_PACKAGE_SCOPE", HELPER.SAME_PACKAGE_PHASE),
                             ("MRK_MACOS_XCODE_SETUP_SCOPE", "companion-only"),
                             ("MRK_MACOS_PACKAGE_ROLE", "ordinary-image"),
                             *((name, "INERT NOT A CREDENTIAL") for name in
                               HELPER.INSTALLER_CREDENTIAL_VARIABLES + (HELPER.NOTARY_KEY_VARIABLE,))):
            with self.subTest(field=field), self.assertRaises(HELPER.Refused):
                self.admitted({**env, field: value})

    def test_original_push_purposes_remain_admitted(self):
        for phase in HELPER.PYTHON_PHASES:
            env = self.environment()
            env.pop("MRK_MACOS_PYTHON_SIGNING_SCOPE")
            ref = "refs/heads/verify/desktop-macos-python-runtime-signing-" + phase[len("python-"):]
            env.update(GITHUB_EVENT_NAME="push", GITHUB_REF=ref,
                       GITHUB_WORKFLOW_REF="Apdelrahman1911/mobile-release-kit/.github/workflows/desktop-macos-python-runtime-signing.yml@" + ref)
            self.assertEqual(self.admitted(env, phase=phase), Path(env["MRK_MACOS_WORK"]))
            with self.assertRaises(HELPER.Refused):
                self.admitted({**env, "GITHUB_EVENT_NAME": "workflow_dispatch"}, phase=phase)

    def test_helper_stager_and_workflow_bind_one_complete_verified_supplier(self):
        self.assertEqual(HELPER.PYTHON_SUPPLIERS, STAGE.SIGNED_ORIGINAL_SUPPLIERS)
        pins = HELPER.PYTHON_SUPPLIERS[STAGE.ARM_TARGET]
        self.assertEqual(pins, {"receiptSha256": "e6b23316078020c513ab1b05b3b55e4f87b8d15908a8dee022ad5ee03b8f763e",
                               "tarSha256": "ead75b364118139561a34da6aa48e3c54791e152154ab32c46196b0223962359",
                               "sourceCommit": "c6551aa07d0673436aa9587b3a039889d22449c3", "runId": "40473858216",
                               "runAttempt": "1", "artifactId": "12719943283"})
        workflow = (ROOT / BUILD.CANDIDATE_SIGNING_WORKFLOW).read_text()
        self.assertIn("run-id: '" + pins["runId"] + "'", workflow)
        self.assertIn("artifact-ids: '" + pins["artifactId"] + "'", workflow)
        self.assertEqual(STAGE.SIGNED_ORIGINAL_SUPPLIERS[STAGE.INTEL_TARGET]["sourceCommit"],
                         "a2f7a10b4c86305f5ee65c6779ceaf6b128cd8fa")

    def test_signing_snapshot_captures_actual_caller_and_both_reusable_files(self):
        plain = BUILD.source_snapshot(ROOT, workflow=BUILD.CANDIDATE_WORKFLOW)
        signed = BUILD.source_snapshot(ROOT, workflow=BUILD.CANDIDATE_WORKFLOW, signing=True)
        self.assertIn(BUILD.CANDIDATE_SIGNING_WORKFLOW, signed)
        self.assertEqual({name: row for name, row in signed.items() if name != BUILD.CANDIDATE_SIGNING_WORKFLOW}, plain)
        for kwargs in ({"signing": True}, {"target": STAGE.INTEL_TARGET, "signing": True},
                       {"workflow": BUILD.CANDIDATE_WORKFLOW, "signing": "true"}):
            with self.subTest(kwargs=kwargs), self.assertRaises(BUILD.BuildRefused):
                BUILD.source_snapshot(Path("/inert/no-access"), **kwargs)

    def test_actual_receipt_parser_rejects_foreign_and_historical_arm_signer(self):
        for target in (STAGE.ARM_TARGET, STAGE.INTEL_TARGET):
            fixture = FIXTURES.signed_fixture_data(target)
            parser = FIXTURES.TOOL
            with patch.object(parser, "SIGNED_ORIGINAL_SUPPLIERS", {target: fixture.nomination}):
                def parse(body):
                    options = SimpleNamespace(target=target, **fixture.options)
                    options.expected_signing_receipt = parser.digest(body)
                    return parser.signed_python_receipt(body, fixture.signed, options, fixture.original,
                        fixture.original_receipt, fixture.producer, fixture.service, fixture.empty)
                self.assertEqual(parse(fixture.body)["signer"]["workflow"], STAGE.signed_python_workflow(target))
                for workflow in (STAGE.signed_python_workflow(target).replace("Apdelrahman1911", "foreign"),
                                 STAGE.signed_python_workflow(STAGE.INTEL_TARGET if target == STAGE.ARM_TARGET else STAGE.ARM_TARGET)):
                    value = json.loads(fixture.body); value["signer"]["workflow"] = workflow
                    with self.subTest(target=target, workflow=workflow), self.assertRaises(parser.Refused):
                        parse(parser.canonical(value) + b"\n")

    def test_signing_keeps_original_command_and_closed_retention_gates(self):
        body = (ROOT / BUILD.CANDIDATE_SIGNING_WORKFLOW).read_text()
        old = (ROOT / ".github/workflows/desktop-macos-python-runtime-signing.yml").read_text()
        step = "      - name: Sign and probe one derived executable through the same original owner\n"
        def command(text):
            return text.split(step, 1)[1].split("      - name:", 1)[0].split("        run: |\n", 1)[1]
        self.assertEqual(command(body), command(old))
        for required in ("on:\n  workflow_call:", "environment: macos-developer-id", "runs-on: macos-26",
                         "MRK_MACOS_PYTHON_SIGNING_SCOPE: candidate-only", "digest-mismatch: error",
                         "persist-credentials: false", "cancel-in-progress: false", "retention-days: 90"):
            self.assertIn(required, body)
        capsule = body.split("      - name: Retain the signed capsule only after the original zero exit\n", 1)[1]
        self.assertIn("steps.sign.outcome == 'success'", capsule)
        self.assertIn("steps.source_post.outcome == 'success'", capsule)
        for forbidden in ("workflow_dispatch:", "push:", "matrix:", "contents: write", "id-token:",
                          "continue-on-error:", "gh release", "notarytool", "npm ", "cargo ", "sudo "):
            self.assertNotIn(forbidden, body)

    def test_signing_dispatch_does_not_admit_any_app_or_test_job(self):
        caller = (ROOT / BUILD.CANDIDATE_WORKFLOW).read_text()
        section = caller.split("  candidate-python-sign:\n", 1)[1].split("  candidate-python-source:\n", 1)[0]
        for gate in ("inputs.operation == 'candidate-python-sign'", "inputs.target == 'aarch64-apple-darwin'",
                     "github.event_name == 'workflow_dispatch'", "github.ref == 'refs/heads/verify/desktop-macos-candidate'",
                     "github.sha == github.workflow_sha"):
            self.assertIn(gate, section)
        self.assertIn("uses: ./" + BUILD.CANDIDATE_SIGNING_WORKFLOW, section)
        for job in ("engineering-install", "candidate-python-source", "candidate-tests", "xcode-setup-companion",
                    "prepared-install", "shipping-image-compile"):
            condition = re.search(r"^    if: (.+)$", caller.split("  " + job + ":\n", 1)[1], re.MULTILINE)[1]
            self.assertNotIn("candidate-python-sign", condition)


if __name__ == "__main__":
    unittest.main()
