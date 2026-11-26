"""In-memory local provisioning pairing; no keys, files, native calls or accounts.

The existing mechanical observations below are fictional DATA, not P12/P8
validation, source custody, profile authentication or an assignment grant.
"""
from __future__ import annotations

import copy
from pathlib import Path
import unittest
from unittest.mock import patch

from mobile_release.api import ApiError, execute
from mobile_release.api import _credential_assessment as assessment
from mobile_release.config import ReleaseConfig
from mobile_release.credential_requirements import (
    Requirement, local_ios_provisioning_requirements, requirements,
)
from mobile_release.errors import CredentialError
from tests.desktop.test_credential_assessment import ERRORS, SCALARS, checks, draft, encoded, request


KINDS = ("asc-p8", "apple-p12", "apple-profile")
PREFIX = "MOBILE_RELEASE_"
SIGNING = (
    "APPLE_DISTRIBUTION_P12_BASE64", "APPLE_DISTRIBUTION_P12_PASSWORD",
    "APPLE_PROVISIONING_PROFILE_BASE64",
)
ASC = ("ASC_PRIVATE_KEY_P8_BASE64", "ASC_KEY_ID", "ASC_ISSUER_ID")


def provisioning(kind="apple-p12"):
    body = request(kind, platform="ios", purpose="provisioning")
    body["context"]["executionMode"] = "local"
    return body


def config(data=None):
    return ReleaseConfig(Path("unused"), Path("."), draft() if data is None else data)


class ProvisioningAssessmentTests(unittest.TestCase):
    def refuse(self, body):
        with self.assertRaises(ApiError) as caught:
            execute("credentials.assess", body)
        self.assertEqual(caught.exception.code, "assessment_invalid_request")
        self.assertEqual(caught.exception.message, ERRORS["assessment_invalid_request"])

    def test_three_kinds_are_independent_not_an_all_inputs_gate(self):
        # There is deliberately NO supplied profile in either P8/P12 request.
        # The profile is the later provisioning output, not a creation input.
        for kind in KINDS:
            with self.subTest(kind=kind):
                body = provisioning(kind)
                with patch.object(assessment, "requirements", side_effect=AssertionError("not a release gate")):
                    result = execute("credentials.assess", body)
                self.assertEqual(result["kind"], kind)
                self.assertEqual(result["context"], {
                    "executionMode": "local", "platform": "ios", "stage": "candidate", "purpose": "provisioning",
                })
                self.assertEqual(result["applicability"], {"state": "required", "reason": "selected"})
                self.assertEqual(result["state"], "configured")
                self.assertEqual([row["id"] for row in result["fields"]],
                                 ["file", *SCALARS[kind]])
                self.assertEqual(result["identity"], "not-applicable")

    def test_fixed_rows_reuse_existing_names_alternatives_and_reasons_without_extra_inputs(self):
        rows = local_ios_provisioning_requirements(config())
        expected = [
            Requirement(PREFIX + SIGNING[0], "secret", "candidate", "ios",
                        (PREFIX + "APPLE_DISTRIBUTION_P12_PATH",), "Apple distribution certificate and private key"),
            Requirement(PREFIX + SIGNING[1], "secret", "candidate", "ios", reason="Apple P12 password"),
            Requirement(PREFIX + SIGNING[2], "secret", "candidate", "ios",
                        (PREFIX + "APPLE_PROVISIONING_PROFILE_PATH",), "App Store provisioning profile"),
            Requirement(PREFIX + ASC[0], "secret", "candidate", "ios",
                        (PREFIX + "ASC_PRIVATE_KEY_P8_PATH",), "App Store Connect API private key"),
            Requirement(PREFIX + ASC[1], "variable", "candidate", "ios", reason="App Store Connect API key ID"),
            Requirement(PREFIX + ASC[2], "variable", "candidate", "ios", reason="App Store Connect API issuer ID"),
        ]
        # The draft enables Firebase, dependency tokens and review/demo inputs.
        self.assertEqual(rows, expected)
        rows.clear()
        self.assertEqual(local_ios_provisioning_requirements(config()), expected)

    def test_explicit_local_mode_is_required_before_selecting_any_rows(self):
        for mode in ("missing", "github", None, True, "LOCAL", {"local": True}):
            body = provisioning()
            if mode == "missing":
                body["context"].pop("executionMode")
            else:
                body["context"]["executionMode"] = mode
            with self.subTest(mode=mode), patch.object(
                assessment, "local_ios_provisioning_requirements", side_effect=AssertionError("bad context reached selector"),
            ):
                self.refuse(body)

    def test_other_platforms_stages_and_kinds_cannot_borrow_the_new_purpose(self):
        for name, value in (("platform", "android"), ("platform", "project"),
                            ("stage", "external-testing"), ("stage", "production"),
                            ("purpose", "Provisioning")):
            body = provisioning()
            body["context"][name] = value
            self.refuse(body)
        for kind in SCALARS.keys() - set(KINDS):
            with self.subTest(kind=kind):
                self.refuse(provisioning(kind))

    def test_disabled_ios_is_not_required_and_does_not_assess_supplied_secrets(self):
        data = draft()
        data["ios"] = {"enabled": False}
        self.assertEqual(local_ios_provisioning_requirements(config(data)), [])
        for kind in KINDS:
            body = provisioning(kind)
            body["context"]["draft"] = copy.deepcopy(data)
            result = execute("credentials.assess", body)
            self.assertEqual(result["applicability"], {"state": "not-applicable", "reason": "platform-disabled"})
            self.assertEqual(result["state"], "not-applicable")
            self.assertTrue(all(row["state"] == "not-applicable" and not row["checks"] for row in result["fields"]))

    def test_missing_and_unknown_file_observations_never_become_configured(self):
        for kind in KINDS:
            for observation, state, issue in (
                (None, "missing", "required-missing"),
                ({"status": "unavailable", "reason": "incomplete"}, "unknown", "incomplete"),
                ({"status": "rejected", "reason": "malformed-container"}, "invalid", "malformed-container"),
            ):
                with self.subTest(kind=kind, state=state):
                    body = provisioning(kind)
                    body["input"]["observation"] = observation
                    result = execute("credentials.assess", body)
                    self.assertEqual(result["state"], state)
                    self.assertEqual(result["fields"][0]["issues"], [issue])
                    self.assertEqual(result["assurance"]["nativeValidation"], "not-run")

    def test_existing_p8_algorithm_and_scalar_policies_remain_in_force(self):
        body = provisioning("asc-p8")
        body["input"]["observation"].update(algorithm="rsa", curve=None)
        result = execute("credentials.assess", body)
        self.assertEqual(result["state"], "invalid")
        self.assertEqual(result["fields"][0]["issues"], ["pkcs8-algorithm"])
        for kind, field, value, state, issue in (
            ("asc-p8", "keyId", None, "missing", "required-missing"),
            ("asc-p8", "issuerId", "invalid-issuer", "invalid", "scalar-format"),
            ("apple-p12", "password", "", "missing", "required-missing"),
            ("apple-p12", "password", "fictional\0password", "invalid", "value-nul"),
        ):
            body = provisioning(kind)
            body["input"]["fields"][field] = value
            result = execute("credentials.assess", body)
            self.assertEqual(result["state"], state)
            row = next(row for row in result["fields"] if row["id"] == field)
            self.assertEqual(row["issues"], [issue])

    def test_envelopes_and_password_admission_do_not_claim_native_or_service_proof(self):
        for kind, scope in (("apple-p12", "pfx-envelope"), ("apple-profile", "cms-signed-data-envelope"),
                            ("asc-p8", "pkcs8-envelope")):
            result = execute("credentials.assess", provisioning(kind))
            self.assertEqual(checks(result["fields"][0])[0], (scope, "asserted-pass"))
            assurance = result["assurance"]
            self.assertEqual(assurance["basis"], "supplied-input-only")
            self.assertEqual(assurance["sourceCustody"], "not-established")
            self.assertEqual(assurance["nativeValidation"], "not-run")
            self.assertEqual(assurance["serviceValidation"], "not-run")
            self.assertEqual(assurance["releaseReadiness"], "unknown")
            for flag in ("selectedFilesRead", "keyringAccessed", "storageWritesPerformed", "projectCodeExecuted"):
                self.assertFalse(assurance[flag])
            text = encoded(result).decode()
            for scalar in SCALARS[kind].values():
                self.assertNotIn(scalar, text)
            self.assertNotIn("distributionCertificateSha256", text)
            if kind == "apple-p12":
                self.assertEqual(checks(result["fields"][1]), [("value-admission", "passed")])

    def test_observation_cannot_supply_private_material_or_an_assignment_fingerprint(self):
        for field in ("privateKey", "certificateSha256", "distributionCertificateSha256", "keyRef"):
            body = provisioning()
            body["input"]["observation"][field] = "fictional-never-reflect"
            self.refuse(body)

    def test_generic_release_requirements_reject_new_purpose_and_old_rows_are_unchanged(self):
        for stage in ("all", "candidate", "external-testing", "production"):
            with self.assertRaises(CredentialError):
                requirements(config(), stage, purpose="provisioning", platforms=("ios",))
        firebase = "IOS_GOOGLE_SERVICE_INFO_PLIST_BASE64"
        dependency = "PROJECT_READ_TOKEN"
        for purpose, names in (
            ("signing", (*SIGNING, firebase, dependency)),
            ("store", ASC),
            ("full", (*SIGNING, firebase, *ASC, dependency)),
        ):
            rows = requirements(config(), "candidate", purpose=purpose, platforms=("ios",))
            self.assertEqual([row.name for row in rows], [PREFIX + name for name in names])
            if purpose != "store":
                self.assertEqual(rows[:3], local_ios_provisioning_requirements(config())[:3])
        for stage in ("external-testing", "production"):
            self.assertEqual(requirements(config(), stage, purpose="signing", platforms=("ios",)), [])
            for purpose in ("full", "store"):
                rows = requirements(config(), stage, purpose=purpose, platforms=("ios",))
                self.assertEqual([row.name for row in rows[:3]], [PREFIX + name for name in ASC])
                self.assertNotIn(PREFIX + SIGNING[0], {row.name for row in rows})
                self.assertIn(PREFIX + "OPERATION_COMMITMENT_KEY_BASE64", {row.name for row in rows})


if __name__ == "__main__":
    unittest.main()
