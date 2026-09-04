from __future__ import annotations

import json
import os
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from mobile_release.config import load_config
from mobile_release.discovery import GitContext
from mobile_release.errors import ValidationError
from mobile_release.provenance import (
    artifact_records,
    build_candidate_manifest,
    build_receipt,
    load_evidence,
    seal,
    validate_store_receipt,
    validate_receipt_chain,
    validate_evidence_document,
    verify_sealed,
    write_evidence,
)

from .helpers import android_config, ios_config, write_project


def play_store_state(*, stage: str = "candidate", outcome: str = "mutated") -> dict:
    observed = "a" * 64
    state = {
        "canonicalization": "mrk-play-track-state-v1",
        "mode": "observation" if outcome == "already-present" else "mutation",
        "readbackEditId": "readback-edit",
        "destinationBeforeSha256": observed if outcome == "already-present" else "b" * 64,
        "destinationExpectedSha256": observed,
        "destinationCommittedSha256": observed,
        "unrelatedBeforeSha256": "c" * 64,
        "unrelatedCommittedSha256": "c" * 64,
        "targetReleaseSha256": "d" * 64,
    }
    if outcome != "already-present":
        state["mutationEditId"] = "mutation-edit"
    if stage != "candidate":
        state["sourceBeforeSha256"] = "e" * 64
        state["sourceExpectedSha256"] = "e" * 64
        state["sourceCommittedSha256"] = "e" * 64
        state["sourceUnrelatedBeforeSha256"] = "f" * 64
        state["sourceUnrelatedCommittedSha256"] = "f" * 64
        state["sourceTargetTransition"] = "retained"
    return state


class ProvenanceTests(unittest.TestCase):
    def test_observation_only_android_external_receipt_cannot_authorize_production(self) -> None:
        fixtures = Path(__file__).resolve().parents[1] / "fixtures"
        candidate = json.loads((fixtures / "candidate-valid.json").read_text(encoding="utf-8"))
        candidate_receipt = json.loads(
            (fixtures / "receipt-candidate-valid.json").read_text(encoding="utf-8")
        )
        external = verify_sealed(
            json.loads((fixtures / "receipt-external-valid.json").read_text(encoding="utf-8"))
        )
        external["outcome"] = "already-present"
        state = external["storeState"]
        state["mode"] = "observation"
        state.pop("mutationEditId")
        state["destinationBeforeSha256"] = state["destinationExpectedSha256"]
        state["sourceTargetTransition"] = "already-deactivated"
        observation = seal(external)

        validate_receipt_chain(
            candidate_manifest=candidate,
            candidate_receipt=candidate_receipt,
            external_receipt=observation,
            platform="android",
        )
        with self.assertRaisesRegex(ValidationError, "observation-only"):
            validate_receipt_chain(
                candidate_manifest=candidate,
                candidate_receipt=candidate_receipt,
                external_receipt=observation,
                platform="android",
                require_production_eligible_external=True,
            )

    def test_builder_round_trip_matches_committed_schema_shape(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = load_config(write_project(root, android_config()))
            aab = root / "app.aab"
            with zipfile.ZipFile(aab, "w") as archive:
                archive.writestr("BundleConfig.pb", b"x")
                archive.writestr("base/manifest/AndroidManifest.xml", b"x")
                archive.writestr("base/dex/classes.dex", b"x")
                archive.writestr("base/lib/arm64-v8a/libx.so", b"x")
            metadata = root / "metadata.zip"
            metadata.write_bytes(b"metadata")
            validation_report = root / "validation-report.json"
            validation_report.write_bytes(b"validation")
            git = GitContext(
                repository="example/mobile-app",
                repository_id="100000000",
                commit="2" * 40,
                tree="3" * 40,
                ref="refs/heads/main",
                branch="main",
                dirty=False,
            )
            raw = {
                "schemaVersion": 2,
                "operation": "android_internal_upload",
                "platform": "android",
                "appIdentity": "com.example.reader",
                "marketingVersion": "1.2.3",
                "buildNumber": 42,
                "observedAt": "2026-01-01T00:00:00Z",
                "result": "accepted",
                "state": "available-to-testers",
                "versionCode": 42,
                "destinationTrack": "internal",
                "releaseStatus": "completed",
                "storeEditId": "readback-edit",
                "storeState": play_store_state(),
            }
            release = config.release_version()
            validated = validate_store_receipt(
                raw, config=config, release=release, stage="candidate", platform="android"
            )
            environment = {
                "MOBILE_RELEASE_TOOLING_SHA": "1" * 40,
                "GITHUB_WORKFLOW": "Mobile candidate",
                "GITHUB_RUN_ID": "1000000000",
                "GITHUB_RUN_ATTEMPT": "1",
                "SOURCE_DATE_EPOCH": "1767225600",
            }
            with patch.dict(os.environ, environment, clear=False):
                manifest = build_candidate_manifest(
                    config=config,
                    release=release,
                    git=git,
                    platform="android",
                    artifacts=artifact_records(
                        [
                            ("android-aab", aab),
                            ("store-metadata", metadata),
                            ("validation-report", validation_report),
                        ]
                    ),
                    store_receipt=validated,
                    metadata_sha256=__import__("hashlib").sha256(b"metadata").hexdigest(),
                )
                manifest_path = root / "candidate.json"
                write_evidence(manifest_path, manifest)
                loaded = load_evidence(manifest_path)
                self.assertEqual(loaded["platforms"]["android"]["applicationId"], "com.example.reader")
                self.assertEqual(loaded["artifacts"][0]["architectures"], ["arm64-v8a"])
                without_report = verify_sealed(manifest)
                without_report["artifacts"] = [
                    item
                    for item in without_report["artifacts"]
                    if item["logicalName"] != "validation-report"
                ]
                with self.assertRaisesRegex(ValidationError, "validation report"):
                    validate_evidence_document(seal(without_report))
                opposite_platform = verify_sealed(manifest)
                opposite_platform["artifacts"] = [*opposite_platform["artifacts"],
                    {
                        "logicalName": "ios-ipa",
                        "platform": "ios",
                        "kind": "ipa",
                        "fileName": "foreign.ipa",
                        "size": 1,
                        "sha256": "f" * 64,
                        "architectures": [],
                    },
                ]
                with self.assertRaisesRegex(ValidationError, "unsupported or duplicated"):
                    validate_evidence_document(seal(opposite_platform))
                receipt = build_receipt(
                    stage="candidate",
                    platform="android",
                    candidate_manifest=manifest,
                    store_receipt=validated,
                )
                receipt_path = root / "receipt.json"
                write_evidence(receipt_path, receipt)
                self.assertEqual(load_evidence(receipt_path)["operation"], "uploaded")
                validate_receipt_chain(
                    candidate_manifest=manifest,
                    candidate_receipt=receipt,
                    platform="android",
                )
                external = build_receipt(
                    stage="external-testing",
                    platform="android",
                    candidate_manifest=manifest,
                    previous_receipt=receipt,
                    store_receipt={
                        "result": "accepted",
                        "versionCode": 42,
                        "destinationTrack": "closed-testing",
                        "releaseStatus": "completed",
                        "state": "available-to-testers",
                        "observedAt": "2026-01-01T00:01:00Z",
                        "closedTesterAssignmentVerified": True,
                        "storeState": play_store_state(stage="external-testing"),
                    },
                )
                production = build_receipt(
                    stage="production-submit",
                    platform="android",
                    candidate_manifest=manifest,
                    previous_receipt=external,
                    store_receipt={
                        "result": "accepted",
                        "versionCode": 42,
                        "destinationTrack": "production",
                        "releaseStatus": "draft",
                        "state": "draft",
                        "observedAt": "2026-01-01T00:02:00Z",
                        "storeState": play_store_state(stage="production-submit"),
                    },
                )
                validate_receipt_chain(
                    candidate_manifest=manifest,
                    candidate_receipt=receipt,
                    external_receipt=external,
                    production_receipt=production,
                    platform="android",
                    config=config,
                )
                changed_production = verify_sealed(production)
                changed_production["previousReceiptSha256"] = "f" * 64
                with self.assertRaisesRegex(ValidationError, "external receipt"):
                    validate_receipt_chain(
                        candidate_manifest=manifest,
                        candidate_receipt=receipt,
                        external_receipt=external,
                        production_receipt=seal(changed_production),
                        platform="android",
                        config=config,
                    )
                tampered = verify_sealed(receipt)
                tampered["storeBuildId"] = "different-build"
                with self.assertRaisesRegex(ValidationError, "storeBuildId"):
                    validate_receipt_chain(
                        candidate_manifest=manifest,
                        candidate_receipt=seal(tampered),
                        platform="android",
                    )

    def test_external_testflight_approved_readback_is_explicitly_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = load_config(write_project(root, ios_config(), platform="ios"))
            raw = {
                "schemaVersion": 2,
                "operation": "ios_testflight_external",
                "platform": "ios",
                "appIdentity": "com.example.reader",
                "appStoreAppId": "1234567890",
                "marketingVersion": "1.2.3",
                "buildNumber": 42,
                "buildResourceId": "build-resource-1",
                "processingState": "VALID",
                "externalGroup": "External Testers",
                "betaReviewState": "APPROVED",
                "observedAt": "2026-01-01T00:00:00Z",
                "result": "accepted",
                "state": "approved",
            }
            validated = validate_store_receipt(
                raw,
                config=config,
                release=config.release_version(),
                stage="external-testing",
                platform="ios",
            )
            self.assertEqual(validated["state"], "approved")

    def test_tampering_and_unknown_store_state_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = load_config(write_project(root, android_config()))
            raw = {
                "schemaVersion": 2,
                "operation": "android_internal_upload",
                "platform": "android",
                "appIdentity": "com.example.reader",
                "marketingVersion": "1.2.3",
                "buildNumber": 42,
                "observedAt": "2026-01-01T00:00:00Z",
                "result": "accepted",
                "state": "UNKNOWN",
                "versionCode": 42,
                "destinationTrack": "internal",
                "releaseStatus": "completed",
                "storeEditId": "readback-edit",
                "storeState": play_store_state(),
            }
            with self.assertRaisesRegex(ValidationError, "availability"):
                validate_store_receipt(
                    raw,
                    config=config,
                    release=config.release_version(),
                    stage="candidate",
                    platform="android",
                )

    def test_closed_play_external_receipt_requires_verified_tester_assignment(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = load_config(write_project(root, android_config()))
            raw = {
                "schemaVersion": 2,
                "operation": "android_external_promote",
                "platform": "android",
                "appIdentity": "com.example.reader",
                "marketingVersion": "1.2.3",
                "buildNumber": 42,
                "observedAt": "2026-01-01T00:00:00Z",
                "result": "accepted",
                "state": "available-to-testers",
                "versionCode": 42,
                "sourceTrack": "internal",
                "destinationTrack": "closed-testing",
                "releaseStatus": "completed",
                "storeEditId": "readback-edit",
                "storeState": play_store_state(stage="external-testing"),
            }
            with self.assertRaisesRegex(ValidationError, "tester-group"):
                validate_store_receipt(
                    raw,
                    config=config,
                    release=config.release_version(),
                    stage="external-testing",
                    platform="android",
                )
            raw["closedTesterAssignmentVerified"] = True
            validated = validate_store_receipt(
                raw,
                config=config,
                release=config.release_version(),
                stage="external-testing",
                platform="android",
            )
            self.assertTrue(validated["closedTesterAssignmentVerified"])

    def test_play_source_transition_evidence_is_fail_closed(self) -> None:
        fixtures = Path(__file__).resolve().parents[1] / "fixtures"
        external = verify_sealed(
            json.loads((fixtures / "receipt-external-valid.json").read_text(encoding="utf-8"))
        )

        invalid_cases = []
        changed_unrelated = json.loads(json.dumps(external))
        changed_unrelated["storeState"]["sourceUnrelatedCommittedSha256"] = "1" * 64
        invalid_cases.append((changed_unrelated, "unrelated source"))

        retained_changed = json.loads(json.dumps(external))
        retained_changed["storeState"]["sourceCommittedSha256"] = "2" * 64
        invalid_cases.append((retained_changed, "retained source"))

        false_deactivation = json.loads(json.dumps(external))
        false_deactivation["storeState"]["sourceTargetTransition"] = "deactivated"
        invalid_cases.append((false_deactivation, "did not change"))

        impossible_expected = json.loads(json.dumps(external))
        impossible_expected["storeState"]["sourceTargetTransition"] = "deactivated"
        impossible_expected["storeState"]["sourceCommittedSha256"] = "2" * 64
        impossible_expected["storeState"]["sourceExpectedSha256"] = "3" * 64
        invalid_cases.append((impossible_expected, "outside the allowed transition"))

        for payload, message in invalid_cases:
            with self.subTest(message=message), self.assertRaisesRegex(ValidationError, message):
                validate_evidence_document(seal(payload))

        deactivated = json.loads(json.dumps(external))
        state = deactivated["storeState"]
        state["sourceTargetTransition"] = "deactivated"
        state["sourceCommittedSha256"] = "2" * 64
        state["sourceExpectedSha256"] = state["sourceCommittedSha256"]
        validate_evidence_document(seal(deactivated))


if __name__ == "__main__":
    unittest.main()
