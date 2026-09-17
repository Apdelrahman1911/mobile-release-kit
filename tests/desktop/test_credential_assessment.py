"""Fictional in-memory R1 contracts, not native credential/vault qualification.

No selected files, keyring, native parsers, subprocesses or services are used.
The import isolation negative controls are guarded; the engine helpers only
frame in-memory JSON. Do not discover historical suites to run these leaves.
"""
from __future__ import annotations

import builtins
import copy
import importlib
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from mobile_release import _desktop_engine as engine
from mobile_release import credential_policy as policy
from mobile_release import api
from mobile_release.api import ApiError, execute
from mobile_release.api import _credential_assessment as assessment
from mobile_release.api import _credential_guide as guide
from mobile_release.config import ConfigurationError, ReleaseConfig
from mobile_release.credential_requirements import Requirement, requirements

ERRORS = {
    "assessment_invalid_request": "The assessment request has an unsupported shape or value type.",
    "assessment_limit": "The assessment request exceeds a supported interface bound.",
    "assessment_version": "This assessment schema version is unavailable.",
    "assessment_policy_stale": "Credential policy changed; prepare the context again.",
    "assessment_context_invalid": "The submitted draft is not valid for assessment.",
    "assessment_unavailable": "Credential assessment is unavailable; no credential was verified.",
}
SCALARS = {
    "android-keystore": {"storePassword": "fictional-store-password", "keyAlias": "fixture_alias", "keyPassword": "fictional-key-password"},
    "android-firebase": {}, "apple-p12": {"password": "fictional-p12-password"}, "apple-profile": {},
    "asc-p8": {"keyId": "FIXTURE123", "issuerId": "12345678-1234-1234-1234-123456789abc"},
    "ios-firebase": {},
    "google-wif": {"provider": "projects/123/locations/global/workloadIdentityPools/fixture/providers/fixture",
                   "serviceAccount": "fixture@fixture-project.iam.gserviceaccount.com"},
    "project-read-token": {"token": "fictional-read-token"},
}


def draft():
    return {
        "schemaVersion": 1,
        "version": {"source": "release/version.properties", "nameKey": "VERSION_NAME", "buildKey": "BUILD_NUMBER"},
        "source": {"candidateBranch": "main", "productionBranch": "main", "projectReadTokenRequired": True},
        "android": {"enabled": True, "applicationId": "org.assessment.fixture", "identityStatus": "unverified"},
        "ios": {"enabled": True, "bundleId": "org.assessment.fixture", "identityStatus": "unverified"},
        "metadata": {"root": "release/store", "androidLocales": ["en-US"], "iosLocales": ["en-US"]},
        "services": {"androidFirebase": "required", "iosFirebase": "required"},
        "projectChecks": {"preflight": [["./never-execute-fixture"]], "androidArtifact": [], "iosArtifact": []},
    }


def client(package="org.assessment.fixture"):
    return {"clientInfo": {"androidClientInfo": {"packageName": package}}}


def observed(kind):
    extra = {
        "android-keystore": {"format": "jks", "version": 2},
        "android-firebase": {"format": "firebase-json", "document": {"root": "object", "clients": [client()]}},
        "apple-p12": {"format": "pkcs12", "version": 3, "authSafe": "data"},
        "apple-profile": {"format": "cms-signed-data", "encoding": "der"},
        "asc-p8": {"format": "pkcs8", "encoding": "pem", "algorithm": "ec", "curve": "p256"},
        "ios-firebase": {"format": "firebase-plist", "encoding": "xml", "document": {"root": "dictionary", "bundleId": "org.assessment.fixture"}},
    }.get(kind)
    return {"status": "observed", "byteCount": 128, **extra} if extra is not None else None


def request(kind="android-keystore", *, platform=None, stage="candidate", purpose="full"):
    return {"schemaVersion": 1, "policyVersion": "credential-policy-v1",
            "context": {"draft": draft(), "platform": platform or guide._KIND_LAYOUT[kind][0], "stage": stage, "purpose": purpose},
            "input": {"kind": kind, "fields": copy.deepcopy(SCALARS[kind]), "observation": observed(kind)}}


def encoded(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def checks(field):
    return [(check["scope"], check["outcome"]) for check in field["checks"]]


class CredentialAssessmentTests(unittest.TestCase):
    def refusal(self, body, code="assessment_invalid_request"):
        with self.assertRaises(ApiError) as raised:
            execute("credentials.assess", body)
        self.assertEqual(raised.exception.code, code)
        self.assertEqual(raised.exception.message, ERRORS[code])
        return raised.exception

    def test_all_eight_unions_have_ordered_constant_fields_and_honest_assurance(self):
        for kind, (_, layout) in guide._KIND_LAYOUT.items():
            with self.subTest(kind=kind):
                body = request(kind)
                result = execute("credentials.assess", body)
                self.assertEqual(set(result), {"schemaVersion", "policyVersion", "kind", "context", "applicability", "state", "fields", "identity", "assurance"})
                self.assertEqual(result["context"], {key: body["context"][key] for key in ("platform", "stage", "purpose")})
                self.assertEqual(result["applicability"], {"state": "required", "reason": "selected"})
                self.assertEqual([(field["id"], field["requirement"]) for field in result["fields"]],
                                 [(field_id, "MOBILE_RELEASE_" + suffix) for field_id, suffix, _, _ in layout])
                firebase = kind in ("android-firebase", "ios-firebase")
                self.assertEqual(result["state"], "format-valid" if firebase else "configured")
                self.assertEqual(result["identity"], "match" if firebase else "not-applicable")
                self.assertLessEqual(len(encoded(result)), 16 * 1024)
                for field in result["fields"]:
                    self.assertEqual(set(field), {"id", "requirement", "presence", "state", "issues", "checks"})
                    self.assertEqual(field["presence"], "supplied")
                    self.assertEqual(field["issues"], [])
                    self.assertLessEqual(len(field["checks"]), 3)
                    self.assertEqual(len(checks(field)), len(set(checks(field))))
                self.assertEqual(result["assurance"], {
                    "basis": "supplied-input-only", "scalarValuesProcessed": bool(SCALARS[kind]),
                    "fileObservationsProcessed": observed(kind) is not None,
                    "selectedFilesRead": False, "keyringAccessed": False, "storageWritesPerformed": False,
                    "projectCodeExecuted": False, "sourceCustody": "not-established", "nativeValidation": "not-run",
                    "serviceValidation": "not-run", "releaseReadiness": "unknown",
                })
                self.assertNotIn("credentialsRead", result["assurance"])

    def test_stage_purpose_platform_service_selection_uses_only_shared_requirements(self):
        for kind, (platform, layout) in guide._KIND_LAYOUT.items():
            names = {"MOBILE_RELEASE_" + suffix for _, suffix, _, _ in layout}
            for stage in ("candidate", "external-testing", "production"):
                for purpose in ("full", "signing", "store"):
                    with self.subTest(kind=kind, stage=stage, purpose=purpose):
                        body = request(kind, stage=stage, purpose=purpose)
                        config = ReleaseConfig(Path("unused"), Path("."), body["context"]["draft"])
                        selection = () if platform == "project" else (platform,)
                        selected = {item.name for item in requirements(config, stage, purpose=purpose, platforms=selection)} & names
                        with patch.object(assessment, "requirements", wraps=requirements) as selector:
                            result = execute("credentials.assess", body)
                        selector.assert_called_once()
                        self.assertEqual(selector.call_args.args[1], stage)
                        self.assertEqual(selector.call_args.kwargs, {"purpose": purpose, "platforms": selection})
                        self.assertEqual(result["applicability"], {
                            "state": "required" if selected else "not-applicable", "reason": "selected" if selected else "not-required",
                        })
                        if not selected:
                            self.assertEqual(result["state"], "not-applicable")
                            self.assertTrue(all(field["state"] == "not-applicable" and not field["issues"] and not field["checks"] for field in result["fields"]))
        for kind, service in (("android-firebase", "androidFirebase"), ("ios-firebase", "iosFirebase")):
            body = request(kind)
            body["context"]["draft"]["services"][service] = "disabled"
            self.assertEqual(execute("credentials.assess", body)["applicability"]["reason"], "not-required")

    def test_applicability_precedence_and_explicit_project_token_context(self):
        body = request("android-keystore", platform="ios", stage="production", purpose="store")
        body["context"]["draft"]["ios"] = {"enabled": False}
        self.assertEqual(execute("credentials.assess", body)["applicability"]["reason"], "wrong-platform")
        body["context"]["platform"] = "android"
        body["context"]["draft"] = draft()
        body["context"]["draft"]["android"] = {"enabled": False}
        self.assertEqual(execute("credentials.assess", body)["applicability"]["reason"], "platform-disabled")
        for enabled in ("android", "ios"):
            body = request("project-read-token")
            body["context"]["draft"]["ios" if enabled == "android" else "android"] = {"enabled": False}
            result = execute("credentials.assess", body)
            self.assertEqual(result["state"], "configured")
            body["context"]["platform"] = enabled
            self.assertEqual(execute("credentials.assess", body)["applicability"]["reason"], "wrong-platform")
            body["context"]["platform"] = "project"
            body["context"]["draft"]["source"]["projectReadTokenRequired"] = False
            self.assertEqual(execute("credentials.assess", body)["applicability"]["reason"], "not-required")
        body = request("android-firebase", platform="project")
        self.assertEqual(execute("credentials.assess", body)["identity"], "not-assessed")

    def test_partial_requirement_association_is_unavailable(self):
        partial = [Requirement("MOBILE_RELEASE_ANDROID_KEY_ALIAS", "variable", "candidate", "android")]
        with patch.object(assessment, "requirements", return_value=partial):
            self.refusal(request(), "assessment_unavailable")
        with patch.object(assessment, "requirements", return_value=[]):
            self.assertEqual(execute("credentials.assess", request())["applicability"]["reason"], "not-required")

    def test_missing_empty_and_nul_are_field_admission_not_password_checks(self):
        for value, state, issue, expected_checks, processed in (
            (None, "missing", "required-missing", [], False),
            ("", "missing", "required-missing", [], True),
            ("fictional\0value", "invalid", "value-nul", [("value-admission", "failed")], True),
            ("   ", "configured", None, [("value-admission", "passed")], True),
        ):
            for kind, key in (("project-read-token", "token"), ("apple-p12", "password")):
                body = request(kind)
                body["input"]["fields"][key] = value
                result = execute("credentials.assess", body)
                field = result["fields"][-1]
                self.assertEqual(field["state"], state)
                self.assertEqual(field["presence"], "missing" if value is None or value == "" else "supplied")
                self.assertEqual(field["issues"], [issue] if issue else [])
                self.assertEqual(checks(field), expected_checks)
                self.assertEqual(result["assurance"]["scalarValuesProcessed"], processed)
                if kind == "apple-p12":
                    self.assertEqual(result["fields"][0]["state"], "configured")
                    self.assertEqual(checks(result["fields"][0]), [("pfx-envelope", "asserted-pass")])

    def test_shared_scalar_identifiers_remain_exact_and_untrimmed(self):
        cases = (("android-keystore", "keyAlias"), ("asc-p8", "keyId"), ("asc-p8", "issuerId"),
                 ("google-wif", "provider"), ("google-wif", "serviceAccount"))
        for kind, key in cases:
            for value in (SCALARS[kind][key], " " + SCALARS[kind][key], SCALARS[kind][key] + "\n", "bad\0identifier"):
                body = request(kind)
                body["input"]["fields"][key] = value
                result = execute("credentials.assess", body)
                field = next(field for field in result["fields"] if field["id"] == key)
                if "\0" in value:
                    self.assertEqual(field["issues"], ["value-nul"])
                    self.assertEqual(checks(field), [("value-admission", "failed")])
                else:
                    valid = policy.credential_format_error(field["requirement"], value) is None
                    self.assertEqual(field["state"], "configured" if valid else "invalid")
                    self.assertEqual(field["issues"], [] if valid else ["scalar-format"])
                    self.assertEqual(checks(field), [("value-admission", "passed"), ("identifier-format", "passed" if valid else "failed")])

    def test_file_recognition_stays_independent_of_missing_or_invalid_companions(self):
        for kind, key, bad in (("android-keystore", "storePassword", "bad\0password"),
                                ("android-keystore", "keyAlias", "not an alias"),
                                ("apple-p12", "password", "bad\0password"),
                                ("asc-p8", "keyId", "not-an-id"), ("asc-p8", "issuerId", "not-an-id")):
            baseline = execute("credentials.assess", request(kind))["fields"][0]
            for companion, aggregate in ((None, "missing"), ("", "missing"), (bad, "invalid")):
                body = request(kind)
                body["input"]["fields"][key] = companion
                result = execute("credentials.assess", body)
                self.assertEqual(result["fields"][0], baseline)
                self.assertEqual(result["state"], aggregate)
                self.assertEqual(baseline["state"], "configured")
                self.assertEqual(baseline["issues"], [])

    def test_aggregate_invalid_missing_unknown_do_not_relabel_other_fields(self):
        body = request()
        body["input"]["observation"] = {"status": "unavailable", "reason": "incomplete"}
        self.assertEqual(execute("credentials.assess", body)["state"], "unknown")
        body["input"]["fields"]["storePassword"] = None
        result = execute("credentials.assess", body)
        self.assertEqual(result["state"], "missing")
        self.assertEqual([field["state"] for field in result["fields"]], ["unknown", "missing", "configured", "configured"])
        body["input"]["fields"]["keyAlias"] = "bad alias"
        result = execute("credentials.assess", body)
        self.assertEqual(result["state"], "invalid")
        self.assertEqual([field["state"] for field in result["fields"]], ["unknown", "missing", "invalid", "configured"])
        body["input"]["observation"] = None
        result = execute("credentials.assess", body)
        self.assertEqual(result["state"], "invalid")
        self.assertEqual(result["fields"][0]["state"], "missing")

    def test_unavailable_and_rejected_observations_have_only_named_scopes(self):
        unavailable = ("not-run", "incomplete", "unsupported-format", "unsupported-variant", "material-limit", "parser-limit")
        rejected = {"empty-file": "file-nonempty", "suffix-conflict": "suffix-consistency", "malformed-container": "container-parse"}
        for kind in (kind for kind in guide.KIND_IDS if observed(kind) is not None):
            for status, reasons in (("unavailable", unavailable), ("rejected", tuple(rejected))):
                for reason in reasons:
                    body = request(kind)
                    body["input"]["observation"] = {"status": status, "reason": reason}
                    result = execute("credentials.assess", body)
                    field = result["fields"][0]
                    self.assertEqual(field["presence"], "supplied")
                    self.assertEqual(field["state"], "unknown" if status == "unavailable" else "invalid")
                    self.assertEqual(field["issues"], [reason])
                    self.assertEqual(checks(field), [] if status == "unavailable" else [(rejected[reason], "asserted-fail")])
                    self.assertEqual(result["identity"], "not-assessed" if kind in ("android-firebase", "ios-firebase") else "not-applicable")

    def test_envelope_recognition_never_claims_password_key_or_native_validity(self):
        variants = [
            ("android-keystore", {"format": "jks", "version": version}, "jks-header") for version in (1, 2)
        ] + [
            (kind, {"format": "pkcs12", "version": 3, "authSafe": auth}, "pfx-envelope")
            for kind in ("android-keystore", "apple-p12") for auth in ("data", "signed-data")
        ] + [("apple-profile", {"format": "cms-signed-data", "encoding": "der"}, "cms-signed-data-envelope")]
        for kind, extra, scope in variants:
            body = request(kind)
            body["input"]["observation"] = {"status": "observed", "byteCount": 1, **extra}
            result = execute("credentials.assess", body)
            self.assertEqual(result["state"], "configured")
            self.assertEqual(checks(result["fields"][0]), [(scope, "asserted-pass")])
            self.assertFalse(result["assurance"]["selectedFilesRead"])
            self.assertEqual(result["assurance"]["nativeValidation"], "not-run")

    def test_pkcs8_algorithm_policy_is_separate_from_envelope_assertion(self):
        for encoding in ("pem", "der"):
            for algorithm, curve in (("ec", "p256"), ("ec", "other"), ("ec", None), ("rsa", None), ("other", None)):
                body = request("asc-p8")
                body["input"]["observation"].update(encoding=encoding, algorithm=algorithm, curve=curve)
                result = execute("credentials.assess", body)
                valid = algorithm == "ec" and curve == "p256"
                self.assertEqual(result["state"], "configured" if valid else "invalid")
                self.assertEqual(result["fields"][0]["issues"], [] if valid else ["pkcs8-algorithm"])
                self.assertEqual(checks(result["fields"][0]), [("pkcs8-envelope", "asserted-pass"), ("ec-p256-identifiers", "passed" if valid else "failed")])
                body["input"]["fields"]["keyId"] = None
                companion_missing = execute("credentials.assess", body)
                self.assertEqual(companion_missing["fields"][0], result["fields"][0])
                self.assertEqual(companion_missing["state"], "missing" if valid else "invalid")

    def test_android_projection_requires_every_client_and_exact_identity(self):
        cases = [
            ({"root": "other", "clients": None}, "firebase-shape", "not-assessed"),
            ({"root": "object", "clients": None}, "firebase-shape", "not-assessed"),
            ({"root": "object", "clients": []}, "identity-mismatch", "mismatch"),
            ({"root": "object", "clients": [client("ORG.assessment.fixture")]}, "identity-mismatch", "mismatch"),
            ({"root": "object", "clients": [client("org.assessment.fixture ")]}, "identity-mismatch", "mismatch"),
            ({"root": "object", "clients": [client("other.fixture"), client(), client()]}, None, "match"),
        ]
        for bad in (None, {"clientInfo": None}, {"clientInfo": {"androidClientInfo": None}}, client(None), client("")):
            cases.extend(({"root": "object", "clients": clients}, "firebase-shape", "not-assessed") for clients in ([bad, client()], [client(), bad]))
        for document, issue, identity in cases:
            body = request("android-firebase")
            body["input"]["observation"]["document"] = document
            original = copy.deepcopy(body)
            result = execute("credentials.assess", body)
            self.assertEqual(body, original)
            self.assertEqual(result["identity"], identity)
            self.assertEqual(result["state"], "format-valid" if issue is None else "invalid")
            self.assertEqual(result["fields"][0]["issues"], [] if issue is None else [issue])
            self.assertEqual(checks(result["fields"][0])[0], ("json-document", "asserted-pass"))
            if issue == "firebase-shape":
                self.assertEqual(checks(result["fields"][0])[1:], [("firebase-shape", "failed")])
            else:
                self.assertEqual(checks(result["fields"][0])[1:], [("firebase-shape", "passed"), ("application-identity", "passed" if issue is None else "failed")])

    def test_ios_projection_distinguishes_shape_from_identity_in_both_encodings(self):
        for encoding in ("xml", "binary"):
            for document, issue, identity in (
                ({"root": "other", "bundleId": None}, "firebase-shape", "not-assessed"),
                ({"root": "dictionary", "bundleId": None}, "firebase-shape", "not-assessed"),
                ({"root": "dictionary", "bundleId": ""}, "identity-mismatch", "mismatch"),
                ({"root": "dictionary", "bundleId": "ORG.assessment.fixture"}, "identity-mismatch", "mismatch"),
                ({"root": "dictionary", "bundleId": "org.assessment.fixture "}, "identity-mismatch", "mismatch"),
                ({"root": "dictionary", "bundleId": "org.assessment.fixture"}, None, "match"),
            ):
                body = request("ios-firebase")
                body["input"]["observation"].update(encoding=encoding, document=document)
                result = execute("credentials.assess", body)
                self.assertEqual(result["identity"], identity)
                self.assertEqual(result["fields"][0]["issues"], [] if issue is None else [issue])
                self.assertEqual(checks(result["fields"][0])[0], ("plist-document", "asserted-pass"))
                self.assertEqual(len(checks(result["fields"][0])), 2 if issue == "firebase-shape" else 3)

    def test_shared_firebase_detail_preserves_legacy_bool_semantics(self):
        def decoded(package="org.assessment.fixture"):
            return {"client_info": {"android_client_info": {"package_name": package}}}

        class Dictionary(dict):
            pass

        class String(str):
            pass

        cases = [
            ("android", {"client": [decoded()]}, (True, True)),
            ("android", {"client": [decoded("other.fixture"), decoded()]}, (True, True)),
            ("android", {"client": []}, (True, False)),
            ("android", {"client": [decoded("other.fixture")]}, (True, False)),
            ("android", {"client": [decoded(), None]}, (False, False)),
            ("android", {"client": [decoded("")]}, (False, False)),
            ("android", {"client": [Dictionary(decoded())]}, (False, False)),
            ("ios", {"BUNDLE_ID": "org.assessment.fixture"}, (True, True)),
            ("ios", {"BUNDLE_ID": ""}, (True, False)),
            ("ios", {"BUNDLE_ID": None}, (False, False)),
            ("ios", {"BUNDLE_ID": String("org.assessment.fixture")}, (False, False)),
            ("ios", Dictionary({"BUNDLE_ID": "org.assessment.fixture"}), (False, False)),
            ("other", {"BUNDLE_ID": "org.assessment.fixture"}, (False, False)),
        ]
        for platform, payload, expected in cases:
            details = policy.firebase_payload_shape_and_match(payload, platform=platform, expected_identity="org.assessment.fixture")
            self.assertEqual(details, expected)
            self.assertIs(policy.firebase_payload_matches_application(payload, platform=platform, expected_identity="org.assessment.fixture"), expected[1])
        for expected in (None, "", True, 1, String("org.assessment.fixture")):
            self.assertEqual(policy.firebase_payload_shape_and_match({"client": [decoded()]}, platform="android", expected_identity=expected), (True, False))
            self.assertFalse(policy.firebase_payload_matches_application({"client": [decoded()]}, platform="android", expected_identity=expected))
        # Legacy scalar admission did not change when the detail seam was added.
        for value in ("", "bad\0value", "  fictional  "):
            self.assertIsNone(policy.credential_format_error("MOBILE_RELEASE_PROJECT_READ_TOKEN", value))

    def test_request_keys_and_exact_types_are_closed_at_every_level(self):
        for keys in ((), ("context",), ("input",), ("input", "fields")):
            baseline = request()
            node = baseline
            for key in keys:
                node = node[key]
            for missing in tuple(node):
                body = copy.deepcopy(baseline)
                current = body
                for key in keys:
                    current = current[key]
                del current[missing]
                self.refusal(body)
            body = copy.deepcopy(baseline)
            current = body
            for key in keys:
                current = current[key]
            current["fictional-private-extra-name"] = "fictional-private-value"
            self.refusal(body)
        for bad in (None, [], (), True, "text", 1, {1: "key"}):
            self.refusal(bad)
        for key in SCALARS["android-keystore"]:
            for bad in (True, 1, 1.0, [], {}, b"fictional"):
                body = request()
                body["input"]["fields"][key] = bad
                self.refusal(body)
        for key, bad in (("platform", "all"), ("stage", "all"), ("purpose", "all"), ("draft", []), ("platform", {})):
            body = request()
            body["context"][key] = bad
            self.refusal(body)
        for kind in ("google-wif", "project-read-token"):
            body = request(kind)
            body["input"]["observation"] = {"status": "unavailable", "reason": "not-run"}
            self.refusal(body)

    def test_policy_version_tokens_and_schema_versions_use_fixed_refusals(self):
        for bad in (None, True, 1, [], {}, "", "é", "bad token", "a\0b", "x" * 65):
            body = request()
            body["policyVersion"] = bad
            self.refusal(body)
        for stale in ("credential-policy-v2", "x" * 64, "A._-09"):
            body = request()
            body["policyVersion"] = stale
            self.refusal(body, "assessment_policy_stale")
        for bad in (None, True, "1", 1.0, [], {}):
            body = request()
            body["schemaVersion"] = bad
            self.refusal(body)
        for version in (0, -1, 2, 10 ** 100):
            body = request()
            body["schemaVersion"] = version
            self.refusal(body, "assessment_version")

    def test_draft_validation_is_independent_bounded_and_nonreflective(self):
        body = request()
        with patch.object(api, "validate_draft", side_effect=AssertionError("reflective validate_draft route")), \
             patch.object(assessment, "parse_config_text", wraps=assessment.parse_config_text) as parse, \
             patch.object(assessment, "bounded_json_text", wraps=assessment.bounded_json_text) as serialize:
            self.assertEqual(execute("credentials.assess", body)["state"], "configured")
        parse.assert_called_once_with(encoded(body["context"]["draft"]).decode())
        self.assertTrue(any(call.args[0] == body["context"]["draft"]
                            and 512 * 1024 <= call.kwargs["max_bytes"] <= 512 * 1024 + assessment.MAX_NODES
                            for call in serialize.call_args_list))
        for mutate in (
            lambda data: data.update({"fictional-private-config-key": "fictional-private-value"}),
            lambda data: data["android"].update(applicationId="fictional invalid identity"),
            lambda data: data["services"].update(androidFirebase=[]),
        ):
            body = request()
            mutate(body["context"]["draft"])
            self.refusal(body, "assessment_context_invalid")
        body = request()
        body["context"]["draft"]["$schema"] = "x" * (512 * 1024)
        self.refusal(body, "assessment_limit")
        with patch.object(assessment, "parse_config_text", side_effect=ConfigurationError("fictional-private-config-details")):
            self.refusal(request(), "assessment_context_invalid")

    def test_scalar_utf8_and_aggregate_admission_bounds_do_not_trim(self):
        for value in ("x" * 4096, "é" * 2048, " " * 4096):
            body = request("project-read-token")
            body["input"]["fields"]["token"] = value
            self.assertEqual(execute("credentials.assess", body)["state"], "configured")
        for value in ("x" * 4097, "é" * 2049):
            body = request("project-read-token")
            body["input"]["fields"]["token"] = value
            self.refusal(body, "assessment_limit")
        body = request()
        body["input"]["fields"] = {key: "x" * 4096 for key in SCALARS["android-keystore"]}
        # The closed union has at most three scalars, so its aggregate cannot
        # reach 64 KiB. The alias policy can fail without an interface refusal.
        self.assertEqual(execute("credentials.assess", body)["state"], "invalid")
        self.assertEqual(assessment.MAX_SCALARS_BYTES, 65536)
        with patch.object(assessment, "MAX_SCALARS_BYTES", 3 * 4096 - 1):
            self.refusal(body, "assessment_limit")

    def test_observation_and_projection_bounds_count_escaping_and_all_clients(self):
        body = request("android-firebase")
        body["input"]["observation"]["document"]["clients"] = [client()] * 256
        self.assertEqual(execute("credentials.assess", body)["state"], "format-valid")
        body["input"]["observation"]["document"]["clients"].append(client())
        self.refusal(body, "assessment_limit")
        for name, admitted in (("é" * 512, True), ("é" * 513, False)):
            body = request("android-firebase")
            body["input"]["observation"]["document"]["clients"] = [client(name)]
            if admitted:
                self.assertEqual(execute("credentials.assess", body)["identity"], "mismatch")
            else:
                self.refusal(body, "assessment_limit")
        body = request("android-firebase")
        body["input"]["observation"]["document"]["clients"] = [client("\0" * 1024) for _ in range(12)]
        self.assertGreater(len(encoded(body["input"]["observation"])), 64 * 1024)
        self.refusal(body, "assessment_limit")
        body = request("android-firebase")
        entries = [client("") for _ in range(64)]
        body["input"]["observation"]["document"]["clients"] = entries
        remaining = 64 * 1024 - len(encoded(body["input"]["observation"]))
        for entry in entries:
            count = min(1024, remaining)
            entry["clientInfo"]["androidClientInfo"]["packageName"] = "x" * count
            remaining -= count
        self.assertEqual(remaining, 0)
        self.assertEqual(len(encoded(body["input"]["observation"])), 64 * 1024)
        self.assertEqual(execute("credentials.assess", body)["state"], "invalid")
        room = next(entry for entry in entries if len(entry["clientInfo"]["androidClientInfo"]["packageName"]) < 1024)
        room["clientInfo"]["androidClientInfo"]["packageName"] += "x"
        self.refusal(body, "assessment_limit")

    def test_direct_json_depth_nodes_unicode_and_python_values_are_bounded(self):
        class Dictionary(dict):
            pass

        class String(str):
            pass

        for value in (object(), (), b"fictional", float("nan"), float("inf"), "\ud800", Dictionary(), String("text")):
            body = request()
            body["context"]["draft"]["fictional"] = value
            self.refusal(body)
        cycle = []
        cycle.append(cycle)
        deep = None
        for _ in range(40):
            deep = [deep]
        for value in (cycle, deep, [0] * 20_001):
            body = request()
            body["context"]["draft"]["fictional"] = value
            self.refusal(body, "assessment_limit")
        body = request()
        body["context"]["draft"][1] = "fictional"
        self.refusal(body)
        self.refusal(Dictionary(request()))
        body = request()
        body["input"]["fields"]["storePassword"] = String("fictional")
        self.refusal(body)

    def test_material_count_is_an_assertion_with_per_kind_limits(self):
        for kind, (_, layout) in guide._KIND_LAYOUT.items():
            if observed(kind) is None:
                continue
            limit = policy.material_size_limit("MOBILE_RELEASE_" + layout[0][1])
            for count in (1, limit):
                body = request(kind)
                body["input"]["observation"]["byteCount"] = count
                result = execute("credentials.assess", body)
                self.assertNotIn("byteCount", json.dumps(result))
            body["input"]["observation"]["byteCount"] = limit + 1
            self.refusal(body, "assessment_limit")
            for count in (None, 0, -1, True, 1.0, "128"):
                body["input"]["observation"]["byteCount"] = count
                self.refusal(body)

    def test_observation_discriminants_and_projection_keys_reject_contradictions(self):
        for kind in (kind for kind in guide.KIND_IDS if observed(kind) is not None):
            baseline = request(kind)
            for key in tuple(baseline["input"]["observation"]):
                body = copy.deepcopy(baseline)
                del body["input"]["observation"][key]
                self.refusal(body)
            for key in ("path", "bytes", "base64", "filename", "verified", "nativeValidation", "fictional-private-extra"):
                body = copy.deepcopy(baseline)
                body["input"]["observation"][key] = "fictional-private-value"
                self.refusal(body)
            body = copy.deepcopy(baseline)
            body["input"]["observation"] = {"status": "unavailable", "reason": "empty-file"}
            self.refusal(body)
            body["input"]["observation"] = {"status": "rejected", "reason": "incomplete"}
            self.refusal(body)
        for bad in (True, 1.0, 0, 3, "2"):
            body = request()
            body["input"]["observation"]["version"] = bad
            self.refusal(body)
        for algorithm in ("rsa", "other"):
            body = request("asc-p8")
            body["input"]["observation"].update(algorithm=algorithm, curve="p256")
            self.refusal(body)
        body = request("apple-p12")
        body["input"]["observation"] = observed("android-keystore")
        self.refusal(body)
        documents = (
            {"root": "other", "clients": []}, {"root": "object", "clients": {}},
            {"root": "object", "clients": [{"clientInfo": {}}]},
            {"root": "object", "clients": [client(True)]},
            {"root": "object", "clients": [client()], "allClientsValid": True},
        )
        for document in documents:
            body = request("android-firebase")
            body["input"]["observation"]["document"] = document
            self.refusal(body)
        for document in ({"root": "other", "bundleId": "fictional"}, {"root": "dictionary", "bundleId": True}, {"root": "dictionary"}):
            body = request("ios-firebase")
            body["input"]["observation"]["document"] = document
            self.refusal(body)

    def test_result_and_fixed_refusals_never_reflect_supplied_values(self):
        marker = "fictional-private-marker"
        body = request()
        body["input"]["fields"].update(storePassword=marker, keyPassword=marker, keyAlias=marker)
        body["context"]["draft"]["projectChecks"]["preflight"] = [[marker]]
        self.assertNotIn(marker, json.dumps(execute("credentials.assess", body)))
        for kind in ("android-firebase", "ios-firebase"):
            body = request(kind)
            document = {"root": "object", "clients": [client(marker)]} if kind == "android-firebase" else {"root": "dictionary", "bundleId": marker}
            body["input"]["observation"]["document"] = document
            result = execute("credentials.assess", body)
            self.assertEqual(result["identity"], "mismatch")
            self.assertNotIn(marker, json.dumps(result))
        body = request()
        body[marker] = marker
        error = self.refusal(body)
        framed = engine.encode_response(engine.Request("fixture-1", "credentials.assess", {}),
                                        error={"code": error.code, "message": error.message, "retryable": False})
        self.assertNotIn(marker.encode(), framed)
        self.assertIs(json.loads(framed)["error"]["retryable"], False)

    def test_assessment_is_pure_does_not_mutate_inputs_or_touch_ambient_material(self):
        for kind in guide.KIND_IDS:
            body = request(kind)
            body["context"]["draft"]["$schema"] = "https://untrusted.invalid/never-fetch.json"
            original = copy.deepcopy(body)
            with patch.object(builtins, "open", side_effect=AssertionError("filesystem read")), \
                 patch.object(os, "open", side_effect=AssertionError("filesystem open")), \
                 patch.object(Path, "read_text", side_effect=AssertionError("filesystem read")), \
                 patch.object(Path, "read_bytes", side_effect=AssertionError("filesystem read")), \
                 patch.object(ReleaseConfig, "project_path", side_effect=AssertionError("path custody")), \
                 patch.object(ReleaseConfig, "release_version", side_effect=AssertionError("version read")), \
                 patch.object(guide, "_read_resource_bytes", side_effect=AssertionError("guide is not assessment policy")), \
                 patch.object(subprocess, "Popen", side_effect=AssertionError("process")), \
                 patch.object(os, "system", side_effect=AssertionError("shell")), \
                 patch.dict(os.environ, {"MOBILE_RELEASE_PROJECT_READ_TOKEN": "fictional-ambient-marker"}):
                result = execute("credentials.assess", body)
            self.assertEqual(body, original)
            self.assertNotIn("fictional-ambient-marker", json.dumps(result))
            self.assertFalse(result["assurance"]["selectedFilesRead"])

    def test_passive_import_graph_and_assessment_do_not_reach_native_dependencies(self):
        forbidden = {"mobile_release.credentials", "mobile_release.checked_files", "mobile_release.cancellation",
                     "mobile_release.owned_process", "mobile_release._native_process", "mobile_release.build_inputs",
                     "mobile_release.local_signing", "mobile_release.cli", "mobile_release.stores", "mobile_release.preflight",
                     "ssl", "plistlib", "pyexpat", "xml.parsers.expat", "keyring", "cryptography"}
        original_import = builtins.__import__

        def guarded_import(name, globals=None, locals=None, fromlist=(), level=0):
            absolute = importlib.util.resolve_name("." * level + name, globals["__package__"]) if level else name
            names = {absolute, *(absolute + "." + item for item in fromlist or () if item != "*")}
            if names & forbidden:
                raise AssertionError("forbidden credential/native import")
            return original_import(name, globals, locals, fromlist, level)

        with patch.dict(sys.modules):
            for name in tuple(sys.modules):
                if name == "mobile_release" or name.startswith("mobile_release."):
                    del sys.modules[name]
            with patch.object(builtins, "__import__", side_effect=guarded_import), \
                 patch.object(os, "register_at_fork", create=True, side_effect=AssertionError("fork hook")), \
                 patch.object(subprocess, "Popen", side_effect=AssertionError("process")), \
                 patch.object(os, "system", side_effect=AssertionError("shell")):
                fresh = importlib.import_module("mobile_release.api")
                result = fresh.execute("credentials.assess", request("android-firebase"))
                self.assertEqual(result["state"], "format-valid")
                self.assertFalse(result["assurance"]["selectedFilesRead"])
                self.assertTrue(all(not action["available"] for action in fresh.execute("capabilities", {})["actions"]))
                with self.assertRaisesRegex(AssertionError, "forbidden credential/native import"):
                    guarded_import("mobile_release.credentials")

    def test_engine_registration_and_in_memory_framing_keep_new_error_contract(self):
        self.assertEqual(engine.METHODS, frozenset(api.METHODS))
        self.assertIn("credentials.assess", engine.METHODS)
        value = {"protocol": 1, "id": "fixture-1", "method": "credentials.assess", "params": request("project-read-token")}
        parsed = engine.parse_request(encoded(value) + b"\n")
        response = json.loads(engine.encode_response(parsed, result=execute(parsed.method, parsed.params)))
        self.assertTrue(response["ok"])
        self.assertEqual(response["result"]["state"], "configured")
        bad = encoded(value).replace(b'"schemaVersion":1', b'"schemaVersion":1,"schemaVersion":1', 1) + b"\n"
        with self.assertRaises(engine.ProtocolError):
            engine.parse_request(bad)
        self.assertEqual(engine.MAX_REQUEST_BYTES, 1024 * 1024)
        self.assertEqual(engine.MAX_RESPONSE_BYTES, 4 * 1024 * 1024)
        self.assertEqual((engine.MAX_DEPTH, engine.MAX_VALUES), (32, 20_000))

    def test_unexpected_dependency_errors_follow_constant_engine_failure_path(self):
        for unexpected in (RuntimeError("fictional-private-exception"), ApiError("fictional-private-code", "fictional-private-exception")):
            with patch.object(assessment, "requirements", side_effect=unexpected):
                with self.assertRaises(RuntimeError) as raised:
                    execute("credentials.assess", request())
            self.assertEqual(str(raised.exception), "Unexpected credential assessment failure.")
            self.assertNotIsInstance(raised.exception, ApiError)
            self.assertTrue(raised.exception.__suppress_context__)

    def test_result_dedicated_limit_refuses_internally_instead_of_returning_partial_data(self):
        with patch.object(assessment, "MAX_RESULT_BYTES", 1):
            self.refusal(request(), "assessment_unavailable")


if __name__ == "__main__":
    unittest.main()
