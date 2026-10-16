"""Pure local Store draft DATA tests; no files, tools, credentials or Store calls."""
import dataclasses
import json
import unittest

from mobile_release.discovery import GitContext
from mobile_release.local_release_intent import (
    MAX_DRAFT_BYTES, LocalDraftError, LocalStorePolicy, decode_local_draft, prepare_local_draft,
)
from mobile_release.provenance import _artifact_record, validate_operation_intent
from mobile_release.errors import ValidationError

OPERATION = "12345678-1234-4234-8234-123456789abc"
PROJECT = "22345678-1234-4234-8234-123456789abc"
PRIOR = "32345678-1234-4234-8234-123456789abc"
SOURCE = GitContext(None, None, "a" * 40, "b" * 40, "refs/heads/main", "main", False)


def fixture(platform="android", stage="candidate"):
    names = (["android-aab"] if platform == "android" else ["ios-ipa", "ios-archive"]) + [
        "store-metadata", "validation-report"]
    artifacts = [_artifact_record(name, file_name=name + ".fixture", size=123,
        sha256="c" * 64 if name == "store-metadata" else "d" * 64, architectures=[])
        for name in names]
    prior = {} if stage == "candidate" else {
        "origin": "local-desktop", "operationId": PRIOR,
        "candidateManifestSha256": "e" * 64, "candidateReceiptSha256": "f" * 64}
    if stage == "production-submit":
        prior["externalReceiptSha256"] = "0" * 64
    return {
        "documentType": "local-store-intent-draft", "schemaVersion": 1, "origin": "local-desktop",
        "operationId": OPERATION, "projectId": PROJECT,
        "source": {k: SOURCE.as_dict()[k] for k in ("commit", "tree", "branch", "ref", "dirty")},
        "platform": platform, "stage": stage,
        "application": {"id": "com.example.reader", "identityStatus": "approved",
                        **({"storeAppId": "123456789"} if platform == "ios" else {})},
        "version": {"marketing": "1.2.3", "build": 7},
        "confirmation": f"{stage}:{platform}:1.2.3:7",
        "configuration": {"path": "release/mobile-release.json", "sha256": "1" * 64, "metadataSha256": "c" * 64},
        "versionSource": {"path": "release/version.properties", "sha256": "2" * 64},
        "artifacts": artifacts,
        "assignments": [{"kind": "google-adc" if platform == "android" else "asc-p8",
                         "recordId": "3" * 32, "expectedRevision": 2, "contextRevision": 1}],
        "predecessors": prior,
    }


def encoded(value):
    return json.dumps(value).encode()


class LocalReleaseDraftTests(unittest.TestCase):
    def refuse(self, value):
        with self.assertRaisesRegex(LocalDraftError, "^Invalid local Store draft$"):
            decode_local_draft(encoded(value))

    def test_six_stage_platform_drafts_reuse_artifact_shape_and_roundtrip(self):
        for platform in ("android", "ios"):
            for stage in ("candidate", "external-testing", "production-submit"):
                with self.subTest(platform=platform, stage=stage):
                    value = fixture(platform, stage)
                    draft = prepare_local_draft(encoded(value), observed_source=SOURCE,
                                                policy=LocalStorePolicy(enabled=True))
                    self.assertEqual(draft.to_dict(), value)
                    self.assertEqual(decode_local_draft(draft.to_bytes()), draft)
                    self.assertEqual((draft.operation_id, draft.project_id, draft.platform, draft.stage),
                                     (OPERATION, PROJECT, platform, stage))
                    self.assertEqual(draft.source, SOURCE)
                    self.assertEqual((draft.release.name, draft.release.build), ("1.2.3", 7))
                    # Existing CI authority is not acquired by parsing local DATA.
                    with self.assertRaises(ValidationError):
                        validate_operation_intent(draft.to_dict())

    def test_policy_and_current_source_match_are_required_only_for_preparation(self):
        raw = encoded(fixture())
        self.assertEqual(decode_local_draft(raw).source, SOURCE)
        for policy in (LocalStorePolicy(), LocalStorePolicy(enabled=1), True,
                       LocalStorePolicy(enabled=True, candidate_branch="other")):
            with self.subTest(policy=policy), self.assertRaises(LocalDraftError):
                prepare_local_draft(raw, observed_source=SOURCE, policy=policy)
        for changes in ({"dirty": True}, {"dirty": None}, {"commit": None}, {"tree": "c" * 40},
                        {"ref": "refs/heads/other", "branch": "other"}):
            with self.subTest(changes=changes), self.assertRaises(LocalDraftError):
                prepare_local_draft(raw, observed_source=dataclasses.replace(SOURCE, **changes),
                                    policy=LocalStorePolicy(enabled=True))
        value = fixture(stage="production-submit")
        value["source"].update(branch="release", ref="refs/heads/release")
        observed = dataclasses.replace(SOURCE, branch="release", ref="refs/heads/release")
        self.assertEqual(prepare_local_draft(encoded(value), observed_source=observed,
            policy=LocalStorePolicy(enabled=True, production_branch="release")).stage, "production-submit")
        # A known hosting hint neither grants nor is required for local authority.
        self.assertEqual(prepare_local_draft(raw, observed_source=dataclasses.replace(
            SOURCE, repository="example/project", repository_id="123"),
            policy=LocalStorePolicy(enabled=True)).source.repository, None)

    def test_origin_uuid_unknown_fields_and_predecessor_requirements(self):
        for key, wrong in (("origin", "github-actions"), ("documentType", "store-operation-intent"),
                           ("schemaVersion", True), ("operationId", "12345678-1234-1234-8234-123456789abc"),
                           ("projectId", PROJECT.upper()), ("stage", "public-release")):
            value = fixture(); value[key] = wrong; self.refuse(value)
        for key in ("authorizedBy", "runId", "workflow", "execute", "password"):
            value = fixture(); value[key] = "never-echo-private-value"; self.refuse(value)
        for stage in ("external-testing", "production-submit"):
            for key, wrong in (("origin", "github-actions"), ("operationId", OPERATION),
                               ("candidateManifestSha256", "bad")):
                value = fixture(stage=stage); value["predecessors"][key] = wrong; self.refuse(value)
        value = fixture(stage="production-submit"); del value["predecessors"]["externalReceiptSha256"]; self.refuse(value)
        value = fixture(); value["predecessors"] = fixture(stage="external-testing")["predecessors"]; self.refuse(value)
        value = fixture(); value["source"]["repositoryId"] = "123"; self.refuse(value)

    def test_source_identity_version_and_confirmation_are_not_hints(self):
        for section, key, wrong in (("source", "dirty", 0), ("source", "commit", "A" * 40),
                ("source", "ref", "refs/tags/v1"), ("source", "branch", "../main"),
                ("application", "identityStatus", "unverified"), ("application", "id", "not-an-app"),
                ("version", "build", True), ("version", "build", 2_100_000_001),
                ("version", "marketing", "1.2.release")):
            value = fixture(); value[section][key] = wrong; self.refuse(value)
        value = fixture(); value["confirmation"] += " "; self.refuse(value)
        value = fixture("ios"); value["application"]["storeAppId"] = "0123"; self.refuse(value)
        value = fixture("ios"); value["version"]["marketing"] = "1"; self.refuse(value)

    def test_artifact_metadata_and_input_bindings_reject_cross_platform_and_aliases(self):
        for section, key, wrong in (("configuration", "path", "../release.json"),
                ("versionSource", "path", "/private/version.properties"),
                ("configuration", "sha256", "not-a-digest"),
                ("versionSource", "path", "release/mobile-release.json"),
                ("configuration", "metadataSha256", "0" * 64)):
            value = fixture(); value[section][key] = wrong; self.refuse(value)
        for key, wrong in (("logicalName", "ios-ipa"), ("platform", "ios"), ("kind", "apk"),
                ("fileName", "../candidate.aab"), ("size", True), ("size", 0),
                ("sha256", "A" * 64), ("architectures", ["arm64", "arm64"]),
                ("architectures", ["private\ntext"])):
            value = fixture(); value["artifacts"][0][key] = wrong; self.refuse(value)
        value = fixture(); value["artifacts"].append(value["artifacts"][0].copy()); self.refuse(value)
        value = fixture(); value["artifacts"][1]["fileName"] = value["artifacts"][0]["fileName"]; self.refuse(value)
        value = fixture("ios"); value["artifacts"] = [v for v in value["artifacts"] if v["logicalName"] != "ios-archive"]; self.refuse(value)
        value = fixture(); value["artifacts"] = []; self.refuse(value)

    def test_assignment_revisions_are_closed_references_not_secret_material(self):
        for key, wrong in (("kind", "asc-p8"), ("recordId", "secret-text"),
                ("expectedRevision", True), ("expectedRevision", 0), ("contextRevision", 2**32 - 1)):
            value = fixture(); value["assignments"][0][key] = wrong; self.refuse(value)
        value = fixture(); value["assignments"][0]["privateKey"] = "never-echo-private-value"; self.refuse(value)
        value = fixture(); value["assignments"].append(value["assignments"][0].copy()); self.refuse(value)
        value = fixture(); value["assignments"].append({"kind": "operation-commitment-key", "recordId": "4" * 32,
            "expectedRevision": 1, "contextRevision": 2}); self.refuse(value)
        value = fixture(); value["assignments"] = []; self.refuse(value)

    def test_decoding_is_bounded_duplicate_free_and_nonreflective(self):
        good = encoded(fixture())
        for bad in (b"", b" " * MAX_DRAFT_BYTES + good, b"{", b"[]", b"null", b"\xff",
                    b'{' + b'"origin":"github-actions",' + good[1:],
                    good.replace(b'"build": 7', b'"build": NaN'),
                    good.replace(b'"build": 7', b'"build": 7.0'),
                    b'[' * 2000 + b'0' + b']' * 2000,
                    good.replace(b'"id": "com.example.reader"', b'"id": "\\ud800"')):
            with self.subTest(size=len(bad)), self.assertRaisesRegex(LocalDraftError, "^Invalid local Store draft$"):
                decode_local_draft(bad)
        for wrong_type in (good.decode(), bytearray(good), None):
            with self.assertRaises(LocalDraftError): decode_local_draft(wrong_type)

    def test_retained_draft_is_immutable_and_returned_documents_are_detached(self):
        draft = decode_local_draft(encoded(fixture()))
        original = draft.to_bytes()
        with self.assertRaises(dataclasses.FrozenInstanceError): draft.stage = "production-submit"
        with self.assertRaises(dataclasses.FrozenInstanceError): draft.source.commit = "0" * 40
        copy = draft.to_dict()
        copy["artifacts"][0]["sha256"] = "0" * 64
        copy["assignments"][0]["expectedRevision"] = 99
        self.assertEqual(draft.to_bytes(), original)
        self.assertEqual(draft.to_dict(), fixture())


if __name__ == "__main__":
    unittest.main()
