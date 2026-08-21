from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCHEMAS = ROOT / "schemas"
FIXTURES = ROOT / "tests" / "fixtures"

try:
    import jsonschema
except ImportError:  # pragma: no cover - exercised in dependency-minimal environments
    jsonschema = None


class JsonFileTests(unittest.TestCase):
    def test_all_json_files_parse(self) -> None:
        paths = [
            *SCHEMAS.glob("*.json"),
            *(ROOT / "templates").glob("*.json"),
            *FIXTURES.glob("*.json"),
        ]
        self.assertTrue(paths)
        for path in paths:
            with self.subTest(path=path.relative_to(ROOT)):
                def reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
                    result: dict[str, object] = {}
                    for key, value in pairs:
                        if key in result:
                            raise ValueError(f"duplicate JSON key: {key}")
                        result[key] = value
                    return result

                json.loads(
                    path.read_text(encoding="utf-8"),
                    object_pairs_hook=reject_duplicate_pairs,
                )

    def test_schemas_are_strict_at_the_root(self) -> None:
        expected_ids = {
            "project.schema.json": "urn:mobile-release-kit:schema:project:1",
            "candidate.schema.json": "urn:mobile-release-kit:schema:candidate:1",
            "receipt.schema.json": "urn:mobile-release-kit:schema:receipt:1",
        }
        for path in SCHEMAS.glob("*.json"):
            schema = json.loads(path.read_text(encoding="utf-8"))
            with self.subTest(path=path.name):
                self.assertEqual(schema["$schema"], "https://json-schema.org/draft/2020-12/schema")
                self.assertEqual(schema["$id"], expected_ids[path.name])
                self.assertIs(schema.get("additionalProperties"), False)
                self.assertEqual(schema["properties"]["schemaVersion"], {"const": 1})

    def test_evidence_fixtures_have_valid_canonical_integrity(self) -> None:
        for path in FIXTURES.glob("*.json"):
            value = json.loads(path.read_text(encoding="utf-8"))
            if "integrity" not in value:
                continue
            integrity = value.pop("integrity")
            canonical = json.dumps(
                value,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
            actual = hashlib.sha256(canonical).hexdigest()
            with self.subTest(path=path.name):
                self.assertEqual(integrity, {"algorithm": "sha256", "sha256": actual})

    def test_receipt_fixture_chain_uses_integrity_hashes(self) -> None:
        candidate = json.loads((FIXTURES / "candidate-valid.json").read_text(encoding="utf-8"))
        candidate_receipt = json.loads(
            (FIXTURES / "receipt-candidate-valid.json").read_text(encoding="utf-8")
        )
        external = json.loads(
            (FIXTURES / "receipt-external-valid.json").read_text(encoding="utf-8")
        )
        production = json.loads(
            (FIXTURES / "receipt-production-valid.json").read_text(encoding="utf-8")
        )
        candidate_hash = candidate["integrity"]["sha256"]
        self.assertEqual(candidate_receipt["candidateManifestSha256"], candidate_hash)
        self.assertEqual(external["candidateManifestSha256"], candidate_hash)
        self.assertEqual(production["candidateManifestSha256"], candidate_hash)
        self.assertEqual(
            external["previousReceiptSha256"], candidate_receipt["integrity"]["sha256"]
        )
        self.assertEqual(
            production["previousReceiptSha256"], external["integrity"]["sha256"]
        )

    @unittest.skipIf(jsonschema is None, "jsonschema is not installed")
    def test_schemas_are_valid_draft_2020_12(self) -> None:
        for path in SCHEMAS.glob("*.json"):
            schema = json.loads(path.read_text(encoding="utf-8"))
            with self.subTest(path=path.name):
                jsonschema.Draft202012Validator.check_schema(schema)

    @unittest.skipIf(jsonschema is None, "jsonschema is not installed")
    def test_valid_fixtures_validate(self) -> None:
        pairs = (
            ("project.schema.json", "project-valid.json"),
            ("candidate.schema.json", "candidate-valid.json"),
            ("receipt.schema.json", "receipt-candidate-valid.json"),
            ("receipt.schema.json", "receipt-external-valid.json"),
            ("receipt.schema.json", "receipt-production-valid.json"),
        )
        checker = jsonschema.FormatChecker()
        for schema_name, fixture_name in pairs:
            schema = json.loads((SCHEMAS / schema_name).read_text(encoding="utf-8"))
            instance = json.loads((FIXTURES / fixture_name).read_text(encoding="utf-8"))
            validator = jsonschema.Draft202012Validator(schema, format_checker=checker)
            with self.subTest(fixture=fixture_name):
                validator.validate(instance)

    @unittest.skipIf(jsonschema is None, "jsonschema is not installed")
    def test_project_schema_rejects_unknown_keys_and_placeholder_approval(self) -> None:
        schema = json.loads((SCHEMAS / "project.schema.json").read_text(encoding="utf-8"))
        valid = json.loads((FIXTURES / "project-valid.json").read_text(encoding="utf-8"))
        validator = jsonschema.Draft202012Validator(
            schema, format_checker=jsonschema.FormatChecker()
        )

        unknown = json.loads(json.dumps(valid))
        unknown["deploymentEngine"] = {}
        self.assertFalse(validator.is_valid(unknown))

        placeholder = json.loads(json.dumps(valid))
        placeholder["android"]["uploadCertificateSha256"] = "0" * 64
        self.assertFalse(validator.is_valid(placeholder))

        missing_review = json.loads(json.dumps(valid))
        del missing_review["ios"]["review"]
        self.assertFalse(validator.is_valid(missing_review))

    @unittest.skipIf(jsonschema is None, "jsonschema is not installed")
    def test_project_schema_rejects_runtime_unsafe_paths_and_fingerprints(self) -> None:
        schema = json.loads((SCHEMAS / "project.schema.json").read_text(encoding="utf-8"))
        valid = json.loads((FIXTURES / "project-valid.json").read_text(encoding="utf-8"))
        validator = jsonschema.Draft202012Validator(schema)

        for unsafe in (
            "./release/version.properties",
            "release//version.properties",
            "release/./version.properties",
            "release/../version.properties",
            "release\\version.properties",
            "release/version.properties/",
            "C:/release/version.properties",
            "C:release/version.properties",
        ):
            instance = json.loads(json.dumps(valid))
            instance["version"]["source"] = unsafe
            with self.subTest(path=unsafe):
                self.assertFalse(validator.is_valid(instance))

        for unsafe in ("A" * 63, "0" * 64, "AA:" * 21 + "A"):
            instance = json.loads(json.dumps(valid))
            instance["android"]["uploadCertificateSha256"] = unsafe
            with self.subTest(fingerprint=unsafe):
                self.assertFalse(validator.is_valid(instance))

    @unittest.skipIf(jsonschema is None, "jsonschema is not installed")
    def test_project_schema_matches_runtime_argv_and_text_guards(self) -> None:
        schema = json.loads((SCHEMAS / "project.schema.json").read_text(encoding="utf-8"))
        valid = json.loads((FIXTURES / "project-valid.json").read_text(encoding="utf-8"))
        validator = jsonschema.Draft202012Validator(schema)

        for unsafe in (
            "line\nbreak",
            "carriage\rreturn",
            "nul\x00byte",
            "`shell`",
            "$(shell)",
            "${HOME}",
            "${",
            "x${MOBILE_RELEASE_AAB_PATH}${",
        ):
            instance = json.loads(json.dumps(valid))
            instance["projectChecks"]["preflight"] = [["./check", unsafe]]
            with self.subTest(argv=repr(unsafe)):
                self.assertFalse(validator.is_valid(instance))

        for placeholder in (
            "${MOBILE_RELEASE_AAB_PATH}",
            "${MOBILE_RELEASE_IPA_PATH}",
            "${MOBILE_RELEASE_DSYM_PATH}",
        ):
            instance = json.loads(json.dumps(valid))
            instance["projectChecks"]["preflight"] = [["./check", placeholder]]
            with self.subTest(placeholder=placeholder):
                self.assertTrue(validator.is_valid(instance))

        for field, value in (
            (("android", "externalTrack", "name"), " \t "),
            (("android", "externalTrack", "name"), "closed\ntrack"),
            (("ios", "scheme"), "Release\rScheme"),
            (("ios", "externalTestFlightGroup"), "\x00group"),
            (("source", "candidateBranch"), "main\rnext"),
            (("$schema",), "schema\nlocation"),
            (("$schema",), "not a URI"),
            (("$schema",), "https://example.invalid/" + "a" * 2025),
        ):
            instance = json.loads(json.dumps(valid))
            target = instance
            for key in field[:-1]:
                target = target[key]
            target[field[-1]] = value
            with self.subTest(field=".".join(field), value=repr(value)):
                self.assertFalse(validator.is_valid(instance))

        disabled = json.loads(json.dumps(valid))
        disabled["android"] = {"enabled": False, "applicationId": "com.example.reader"}
        self.assertFalse(validator.is_valid(disabled))

        root_module = json.loads(json.dumps(valid))
        root_module["android"]["module"] = ":"
        self.assertTrue(validator.is_valid(root_module))
        for unsafe_module in ("", "app", "::", ":app:", ":app::feature"):
            instance = json.loads(json.dumps(valid))
            instance["android"]["module"] = unsafe_module
            with self.subTest(android_module=unsafe_module):
                self.assertFalse(validator.is_valid(instance))

    @unittest.skipIf(jsonschema is None, "jsonschema is not installed")
    def test_evidence_schemas_reject_runtime_invalid_canonical_values(self) -> None:
        candidate_schema = json.loads(
            (SCHEMAS / "candidate.schema.json").read_text(encoding="utf-8")
        )
        receipt_schema = json.loads(
            (SCHEMAS / "receipt.schema.json").read_text(encoding="utf-8")
        )
        candidate = json.loads((FIXTURES / "candidate-valid.json").read_text(encoding="utf-8"))
        receipt = json.loads(
            (FIXTURES / "receipt-candidate-valid.json").read_text(encoding="utf-8")
        )
        checker = jsonschema.FormatChecker()
        candidate_validator = jsonschema.Draft202012Validator(
            candidate_schema, format_checker=checker
        )
        receipt_validator = jsonschema.Draft202012Validator(
            receipt_schema, format_checker=checker
        )

        for document, validator in (
            (candidate, candidate_validator),
            (receipt, receipt_validator),
        ):
            for field_path, value in (
                (("integrity", "sha256"), "A" * 64),
                (("source", "commit"), "a" * 64),
                (("source", "tree"), "a" * 64),
                (("tooling", "commit"), "a" * 64),
                (("repository", "id"), "0"),
                (("repository", "id"), "01"),
                (("createdBy", "runId"), "0"),
                (("createdBy", "runId"), "01"),
                (("createdAt",), "2026-01-01T00:00:00.000Z"),
                (("createdAt",), "2026-01-01T00:00:00+00:00"),
                (("version", "marketing"), "release-1"),
            ):
                instance = json.loads(json.dumps(document))
                target = instance
                for key in field_path[:-1]:
                    target = target[key]
                target[field_path[-1]] = value
                with self.subTest(schema=validator.schema["title"], field=field_path, value=value):
                    self.assertFalse(validator.is_valid(instance))

        wrong_kind = json.loads(json.dumps(candidate))
        wrong_kind["artifacts"][0]["kind"] = "apk"
        self.assertFalse(candidate_validator.is_valid(wrong_kind))

        duplicate = json.loads(json.dumps(candidate))
        duplicate["artifacts"].append(json.loads(json.dumps(duplicate["artifacts"][0])))
        duplicate["artifacts"][-1]["fileName"] = "duplicate.aab"
        self.assertFalse(candidate_validator.is_valid(duplicate))

        no_primary = json.loads(json.dumps(candidate))
        no_primary["artifacts"] = [
            item
            for item in no_primary["artifacts"]
            if item["logicalName"] != "android-aab"
        ]
        self.assertFalse(candidate_validator.is_valid(no_primary))

        no_validation_report = json.loads(json.dumps(candidate))
        no_validation_report["artifacts"] = [
            item
            for item in no_validation_report["artifacts"]
            if item["logicalName"] != "validation-report"
        ]
        self.assertFalse(candidate_validator.is_valid(no_validation_report))

        android_apk = json.loads(json.dumps(candidate))
        android_apk["artifacts"].append(
            {
                "logicalName": "android-apk",
                "platform": "android",
                "kind": "apk",
                "fileName": "app.apk",
                "size": 1,
                "sha256": "c" * 64,
                "architectures": [],
            }
        )
        self.assertFalse(candidate_validator.is_valid(android_apk))

        cross_platform_artifact = json.loads(json.dumps(candidate))
        cross_platform_artifact["artifacts"].append(
            {
                "logicalName": "ios-archive",
                "platform": "ios",
                "kind": "xcarchive",
                "fileName": "archive.zip",
                "size": 1,
                "sha256": "d" * 64,
                "architectures": ["arm64"],
            }
        )
        self.assertFalse(candidate_validator.is_valid(cross_platform_artifact))

        multiple_signers = json.loads(json.dumps(candidate))
        multiple_signers["signing"].append(json.loads(json.dumps(multiple_signers["signing"][0])))
        self.assertFalse(candidate_validator.is_valid(multiple_signers))

        wrong_signing_platform = json.loads(json.dumps(candidate))
        wrong_signing_platform["signing"][0].update(
            {"platform": "ios", "kind": "apple-distribution"}
        )
        self.assertFalse(candidate_validator.is_valid(wrong_signing_platform))

        unexpected_android_store_id = json.loads(json.dumps(candidate))
        unexpected_android_store_id["platforms"]["android"]["storeAppId"] = "123"
        self.assertFalse(candidate_validator.is_valid(unexpected_android_store_id))

        for document, validator, field_path in (
            (candidate, candidate_validator, ("schemaVersion",)),
            (candidate, candidate_validator, ("version", "build")),
            (candidate, candidate_validator, ("artifacts", 0, "size")),
            (candidate, candidate_validator, ("createdBy", "attempt")),
            (receipt, receipt_validator, ("schemaVersion",)),
            (receipt, receipt_validator, ("version", "build")),
            (receipt, receipt_validator, ("createdBy", "attempt")),
        ):
            instance = json.loads(json.dumps(document))
            target = instance
            for key in field_path[:-1]:
                target = target[key]
            target[field_path[-1]] = True
            with self.subTest(schema=validator.schema["title"], boolean_at=field_path):
                self.assertFalse(validator.is_valid(instance))

        wrong_signer_platform = json.loads(json.dumps(candidate))
        wrong_signer_platform["signing"][0].update(
            {
                "platform": "ios",
                "kind": "apple-distribution",
                "teamId": "ABCDE12345",
                "profileUuid": "11111111-2222-3333-4444-555555555555",
                "profileExpiresAt": "2027-01-01T00:00:00Z",
            }
        )
        self.assertFalse(candidate_validator.is_valid(wrong_signer_platform))

        ios_candidate = json.loads(json.dumps(candidate))
        ios_candidate["platforms"] = {
            "ios": {"applicationId": "com.example.reader", "storeAppId": "1234567890"}
        }
        ios_candidate["signing"] = [
            {
                "platform": "ios",
                "kind": "apple-distribution",
                "certificateSha256": "a" * 64,
                "teamId": "ABCDE12345",
                "profileUuid": "11111111-2222-3333-4444-555555555555",
                "profileExpiresAt": "2027-01-01T00:00:00Z",
            }
        ]
        shared_artifacts = {
            item["logicalName"]: json.loads(json.dumps(item))
            for item in candidate["artifacts"]
            if item["logicalName"] in {"store-metadata", "validation-report"}
        }
        ios_candidate["artifacts"] = [
            {
                "logicalName": "ios-ipa",
                "platform": "ios",
                "kind": "ipa",
                "fileName": "app.ipa",
                "size": 1,
                "sha256": "b" * 64,
                "architectures": ["arm64"],
            },
            shared_artifacts["store-metadata"],
            shared_artifacts["validation-report"],
        ]
        ios_candidate["storeReceipts"] = [
            {
                "provider": "app-store-connect",
                "applicationId": "com.example.reader",
                "storeBuildId": "build-resource-id",
                "marketingVersion": ios_candidate["version"]["marketing"],
                "build": ios_candidate["version"]["build"],
                "channel": "testflight-internal",
                "state": "processed",
                "observedAt": "2026-01-01T00:00:00Z",
            }
        ]
        self.assertTrue(candidate_validator.is_valid(ios_candidate))
        for invalid_uuid in (
            "1-22222222-3333-4444-55555555555555",
            "11111111222233334444555555555555",
            "{11111111-2222-3333-4444-555555555555}",
            "11111111-2222-3333-4444-55555555555Z",
            "11111111-2222-3333-4444-555555555555-extra",
        ):
            instance = json.loads(json.dumps(ios_candidate))
            instance["signing"][0]["profileUuid"] = invalid_uuid
            with self.subTest(profile_uuid=invalid_uuid):
                self.assertFalse(candidate_validator.is_valid(instance))

        for invalid_ios_version in ("1.2.3.4", "1.2-beta"):
            instance = json.loads(json.dumps(ios_candidate))
            instance["signing"][0]["profileUuid"] = "11111111-2222-3333-4444-555555555555"
            instance["version"]["marketing"] = invalid_ios_version
            instance["storeReceipts"][0]["marketingVersion"] = invalid_ios_version
            with self.subTest(ios_candidate_version=invalid_ios_version):
                self.assertFalse(candidate_validator.is_valid(instance))

        ios_receipt = json.loads(json.dumps(receipt))
        ios_receipt.update(
            {
                "platform": "ios",
                "provider": "app-store-connect",
                "operation": "uploaded",
                "destination": {"channel": "testflight-internal"},
                "readback": {
                    "state": "processed",
                    "observedAt": "2026-01-01T00:00:00Z",
                },
            }
        )
        self.assertTrue(receipt_validator.is_valid(ios_receipt))
        ios_receipt["version"]["marketing"] = "1.2.3.4"
        self.assertFalse(receipt_validator.is_valid(ios_receipt))

    @unittest.skipIf(jsonschema is None, "jsonschema is not installed")
    def test_candidate_and_receipt_schemas_narrow_states_by_platform_stage(self) -> None:
        candidate_schema = json.loads(
            (SCHEMAS / "candidate.schema.json").read_text(encoding="utf-8")
        )
        candidate = json.loads((FIXTURES / "candidate-valid.json").read_text(encoding="utf-8"))
        candidate_validator = jsonschema.Draft202012Validator(candidate_schema)
        candidate["storeReceipts"][0]["state"] = "processed"
        self.assertFalse(candidate_validator.is_valid(candidate))

        receipt_schema = json.loads(
            (SCHEMAS / "receipt.schema.json").read_text(encoding="utf-8")
        )
        receipt_validator = jsonschema.Draft202012Validator(receipt_schema)
        external = json.loads(
            (FIXTURES / "receipt-external-valid.json").read_text(encoding="utf-8")
        )
        external.update(
            {
                "platform": "ios",
                "provider": "app-store-connect",
                "operation": "distributed",
                "destination": {"channel": "testflight-external"},
            }
        )
        for state in (
            "available-to-testers",
            "submitted-for-review",
            "in-review",
            "approved",
        ):
            external["readback"]["state"] = state
            with self.subTest(external_state=state):
                self.assertTrue(receipt_validator.is_valid(external))
        external["readback"]["state"] = "processed"
        self.assertFalse(receipt_validator.is_valid(external))

    @unittest.skipIf(jsonschema is None, "jsonschema is not installed")
    def test_blocked_identity_needs_no_external_store_values(self) -> None:
        schema = json.loads((SCHEMAS / "project.schema.json").read_text(encoding="utf-8"))
        instance = json.loads((ROOT / "templates" / "mobile-release.json").read_text(encoding="utf-8"))
        instance["android"]["identityStatus"] = "blocked"
        instance["ios"]["identityStatus"] = "blocked"
        validator = jsonschema.Draft202012Validator(schema)
        self.assertTrue(validator.is_valid(instance), list(validator.iter_errors(instance)))

    @unittest.skipIf(jsonschema is None, "jsonschema is not installed")
    def test_production_receipts_cannot_enable_public_release(self) -> None:
        schema = json.loads((SCHEMAS / "receipt.schema.json").read_text(encoding="utf-8"))
        validator = jsonschema.Draft202012Validator(schema)
        android = json.loads(
            (FIXTURES / "receipt-production-valid.json").read_text(encoding="utf-8")
        )
        self.assertTrue(validator.is_valid(android), list(validator.iter_errors(android)))
        android["destination"]["releaseStatus"] = "completed"
        self.assertFalse(validator.is_valid(android))

        ios = json.loads(
            (FIXTURES / "receipt-production-valid.json").read_text(encoding="utf-8")
        )
        ios.update(
            {
                "platform": "ios",
                "provider": "app-store-connect",
                "storeBuildId": "example-build-42",
                "operation": "submitted",
                "destination": {
                    "channel": "app-store-review",
                    "automaticRelease": False,
                },
                "readback": {
                    "state": "submitted-for-review",
                    "observedAt": "2026-01-03T00:00:00Z",
                },
            }
        )
        self.assertTrue(validator.is_valid(ios), list(validator.iter_errors(ios)))
        ios["destination"]["automaticRelease"] = True
        self.assertFalse(validator.is_valid(ios))


if __name__ == "__main__":
    unittest.main()
