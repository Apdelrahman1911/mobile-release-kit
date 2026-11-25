"""Inert shared-policy regressions; no CLI/native credential module is imported.

All values are fictional in-memory examples. Legacy seams are inspected as
source rather than importing their process/keychain/file-custody dependency
graph. These checks do not claim native signing or full CLI integration parity.
"""
from __future__ import annotations

import ast
import base64
import unittest
from pathlib import Path

from mobile_release import credential_policy as policy

SOURCE = Path(__file__).resolve().parents[2]
PREFIX = "MOBILE_RELEASE_"


def client(package="org.fixture.app"):
    return {"client_info": {"android_client_info": {"package_name": package}}}


class CredentialPolicyTests(unittest.TestCase):
    def test_material_limit_aliases_and_legacy_substring_fallback(self):
        self.assertEqual(policy.CREDENTIALS_FILE_MAX_BYTES, 256 * 1024)
        self.assertEqual(policy.PRIVATE_SMALL_MAX_BYTES, 4 * 1024 * 1024)
        self.assertEqual(policy.PRIVATE_GENERAL_MAX_BYTES, 32 * 1024 * 1024)
        self.assertEqual(policy.SMALL_PRIVATE_MATERIAL_SIZE, policy.PRIVATE_SMALL_MAX_BYTES)
        self.assertEqual(policy.MAX_PRIVATE_MATERIAL_SIZE, policy.PRIVATE_GENERAL_MAX_BYTES)
        for name in ("ASC_PRIVATE_KEY_P8_BASE64", "APPLE_PROVISIONING_PROFILE_PATH",
                     "ANDROID_GOOGLE_SERVICES_JSON_BASE64", "IOS_GOOGLE_SERVICE_INFO_PLIST_PATH"):
            self.assertEqual(policy.material_size_limit(PREFIX + name), 4 * 1024 * 1024)
        for name in ("ANDROID_KEYSTORE_BASE64", "APPLE_DISTRIBUTION_P12_PATH",
                     "OPERATION_COMMITMENT_KEY_BASE64", "UNKNOWN", ""):
            self.assertEqual(policy.material_size_limit(PREFIX + name), 32 * 1024 * 1024)
        # This helper was not an allowlist: preserve noncanonical name handling.
        for name in ("prefixP8suffix", "PROFILED", "SERVICE", "SERVICES"):
            self.assertEqual(policy.material_size_limit(name), 4 * 1024 * 1024)
        self.assertEqual(policy.material_size_limit("profile-service-p8"), 32 * 1024 * 1024)

    def test_scalar_identifier_golden_boundaries_and_messages(self):
        cases = {
            "ANDROID_KEY_ALIAS": (("a", "A._-09", "a" * 255), ("", "a" * 256, "a b", "é", "a\n")),
            "ASC_KEY_ID": (("A0B1C2D3E4", "0" * 10), ("", "a0B1C2D3E4", "A" * 9, "A" * 11)),
            "ASC_ISSUER_ID": (("01234567-89AB-cdef-0123-456789abcdef",),
                              ("0123456789ABcdef0123456789abcdef", "not-a-uuid", "0" * 36)),
            "GOOGLE_WIF_PROVIDER": (("projects/1/locations/global/workloadIdentityPools/a_-9/providers/B_-0",),
                                    ("projects/0/locations/global/workloadIdentityPools/a/providers/b",
                                     "projects/01/locations/global/workloadIdentityPools/a/providers/b",
                                     "projects/1/locations/global/workloadIdentityPools/a.b/providers/c",
                                     "projects/1/locations/global/workloadIdentityPools/a/providers/")),
            "GOOGLE_SERVICE_ACCOUNT": (("A._-9@fixture-1.iam.gserviceaccount.com", "a@p.iam.gserviceaccount.com"),
                                       ("a@example.com", "_a@p.iam.gserviceaccount.com", "a@p.iam.gserviceaccount.com\n")),
            "OPERATION_COMMITMENT_KEY_VERSION": (("A._-09", "v" * 64), ("", "v" * 65, "v 1", "é")),
        }
        for name, (valid, invalid) in cases.items():
            for value in valid:
                with self.subTest(name=name, case="valid", value=value):
                    self.assertIsNone(policy.credential_format_error(PREFIX + name, value))
            for value in invalid:
                with self.subTest(name=name, case="invalid", value=value):
                    self.assertEqual(policy.credential_format_error(PREFIX + name, value),
                                     "The configured value has an invalid public identifier format.")

    def test_deferred_commitment_and_review_rules_are_preserved(self):
        name = PREFIX + "OPERATION_COMMITMENT_KEY_BASE64"
        self.assertIsNone(policy.credential_format_error(name, base64.b64encode(bytes(range(32))).decode()))
        self.assertEqual(policy.credential_format_error(name, "not!base64"),
                         "The commitment key must be canonical base64.")
        for content in (b"", b"fixture", bytes(31), bytes(33)):
            self.assertEqual(policy.credential_format_error(name, base64.b64encode(content).decode()),
                             "The commitment key must decode to exactly 32 bytes.")
        # Existing b64decode(validate=True) does not re-encode to check pad bits.
        # Preserve that behavior despite the pre-existing canonical error text.
        self.assertIsNone(policy.credential_format_error(name, "A" * 42 + "B="))
        email = PREFIX + "APPLE_REVIEW_CONTACT_EMAIL"
        self.assertIsNone(policy.credential_format_error(email, "review@example.test"))
        for value in ("", "not-an-email", "a @example.test", "a@example", "a@example.test\n"):
            self.assertEqual(policy.credential_format_error(email, value),
                             "The configured review contact email has an invalid format.")

    def test_scalar_helper_is_not_nonempty_nul_or_value_admission(self):
        # Loading/value-state callers still own admission. Do not accidentally
        # tighten these legacy format-only cases as desktop policy is added.
        for name in ("ANDROID_KEYSTORE_PASSWORD", "ANDROID_KEY_PASSWORD", "APPLE_DISTRIBUTION_P12_PASSWORD",
                     "PROJECT_READ_TOKEN", "APPLE_DEMO_ACCOUNT_PASSWORD", "APPLE_REVIEW_CONTACT_FIRST_NAME",
                     "APPLE_REVIEW_CONTACT_LAST_NAME", "APPLE_REVIEW_CONTACT_PHONE", "UNKNOWN"):
            for value in ("", "\x00", "  fictional value  "):
                self.assertIsNone(policy.credential_format_error(PREFIX + name, value), name)

    def test_android_every_client_shape_and_at_least_one_exact_match(self):
        match = lambda payload: policy.firebase_payload_matches_application(
            payload, platform="android", expected_identity="org.fixture.app")
        self.assertTrue(match({"client": [client()]}))
        self.assertTrue(match({"client": [client("other.app"), client()], "extra": True}))
        self.assertFalse(match({"client": [client("ORG.fixture.app")]}))
        self.assertFalse(match({"client": [client("org.fixture.app ")]}))
        for invalid in (None, [], {}, {"client": []}, {"client": {}}, {"client": [None]},
                        {"client": [{"client_info": []}]}, {"client": [{"client_info": {}}]},
                        {"client": [client("")]}, {"client": [client(1)]}, {"client": [client(True)]}):
            with self.subTest(invalid=invalid):
                self.assertFalse(match(invalid))
        for invalid_client in (None, {}, client(""), client(1)):
            self.assertFalse(match({"client": [client(), invalid_client]}))
            self.assertFalse(match({"client": [invalid_client, client()]}))

    def test_ios_shape_expected_identity_and_exact_builtin_types(self):
        class Dictionary(dict):
            pass

        class String(str):
            pass

        for platform, payload in (("ios", {"BUNDLE_ID": "org.fixture.app"}),
                                  ("android", {"client": [client()]})):
            self.assertTrue(policy.firebase_payload_matches_application(
                payload, platform=platform, expected_identity="org.fixture.app"))
            for expected in (None, "", True, 3, String("org.fixture.app")):
                self.assertFalse(policy.firebase_payload_matches_application(
                    payload, platform=platform, expected_identity=expected))
            self.assertFalse(policy.firebase_payload_matches_application(
                Dictionary(payload), platform=platform, expected_identity="org.fixture.app"))
        for payload in (None, [], {}, {"BUNDLE_ID": 1}, {"BUNDLE_ID": True}, {"BUNDLE_ID": ""},
                        {"BUNDLE_ID": "ORG.fixture.app"}, {"BUNDLE_ID": String("org.fixture.app")}):
            self.assertFalse(policy.firebase_payload_matches_application(
                payload, platform="ios", expected_identity="org.fixture.app"))
        self.assertFalse(policy.firebase_payload_matches_application(
            {"BUNDLE_ID": "org.fixture.app"}, platform="other", expected_identity="org.fixture.app"))
        self.assertFalse(policy.firebase_payload_matches_application(
            {"client": [Dictionary(client())]}, platform="android", expected_identity="org.fixture.app"))

    def test_source_only_legacy_delegates_leave_readers_and_admission_in_cli(self):
        source = (SOURCE / "src/mobile_release/credentials.py").read_text()
        functions = {node.name: node for node in ast.parse(source).body if isinstance(node, ast.FunctionDef)}
        for name, target, arguments in (("_material_size_limit", "_shared_material_size_limit", ("name",)),
                                        ("_credential_format_error", "_shared_credential_format_error", ("name", "value"))):
            body = functions[name].body
            self.assertIsInstance(body[0], ast.Expr)  # documentation, then one exact delegate
            self.assertEqual(len(body), 2)
            self.assertIsInstance(body[1], ast.Return)
            call = body[1].value
            self.assertIsInstance(call, ast.Call)
            self.assertIsInstance(call.func, ast.Name)
            self.assertEqual(call.func.id, target)
            self.assertEqual([arg.id for arg in call.args], list(arguments))
            self.assertFalse(call.keywords)
        firebase = ast.get_source_segment(source, functions["_firebase_content_matches_application"])
        self.assertIn('json.loads(content.decode("utf-8"))', firebase)
        self.assertIn("plistlib.loads(content)", firebase)
        self.assertIn("0 < len(content) <= SMALL_PRIVATE_MATERIAL_SIZE", firebase)
        self.assertEqual(firebase.count("_shared_firebase_payload_matches_application("), 2)
        loader = ast.get_source_segment(source, functions["load_credentials_file"])
        self.assertIn('if "\\x00" in value:', loader)
        self.assertIn("if not value:", loader)

    def test_policy_import_surface_and_file_limit_direction_are_pure(self):
        source = SOURCE / "src/mobile_release/credential_policy.py"
        tree = ast.parse(source.read_text())
        imports = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                self.assertEqual(node.level, 0)
                imports.add(node.module)
        self.assertEqual(imports, {"__future__", "base64", "binascii", "re"})
        checked = ast.parse((SOURCE / "src/mobile_release/checked_files.py").read_text())
        imported_limits = {alias.name for node in checked.body if isinstance(node, ast.ImportFrom)
                           and node.module == "credential_policy" for alias in node.names}
        self.assertEqual(imported_limits, {"CREDENTIALS_FILE_MAX_BYTES", "PRIVATE_SMALL_MAX_BYTES", "PRIVATE_GENERAL_MAX_BYTES"})


if __name__ == "__main__":
    unittest.main()
