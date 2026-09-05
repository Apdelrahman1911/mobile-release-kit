from __future__ import annotations

import copy
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mobile_release.config import load_config
from mobile_release.errors import ValidationError
from mobile_release.provenance import (
    build_receipt, load_evidence, seal, validate_store_receipt,
    validate_receipt_chain, validate_evidence_document, verify_sealed, write_evidence,
)
from .evidence_helpers import build_lifecycle, fixture_chain, raw_receipt, workflow_environment
from .helpers import android_config, ios_config, write_project


def chain_arguments(docs: dict) -> dict:
    return {name: docs[name] for name in ("candidate_receipt", "external_receipt", "production_receipt", "candidate_intent", "external_intent", "production_intent")} | {"candidate_manifest": docs["candidate"]}


class ProvenanceTests(unittest.TestCase):
    def test_builder_round_trip_matches_committed_schema_shape(self) -> None:
        for platform in ("android", "ios"):
            with self.subTest(platform=platform), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                config = load_config(write_project(root, android_config() if platform == "android" else ios_config(), platform=platform))
                docs = build_lifecycle(config, platform=platform)
                validate_receipt_chain(**chain_arguments(docs), platform=platform, config=config)
                path = root / "candidate.json"
                write_evidence(path, docs["candidate"])
                self.assertEqual(load_evidence(path), docs["candidate"])
                self.assertEqual(docs["candidate"]["platforms"][platform]["applicationId"], "com.example.reader")
                if platform == "android":
                    self.assertEqual(docs["candidate"]["artifacts"][0]["architectures"], ["arm64-v8a"])
                for role in ("authorizedBy", "executedBy", "producedBy"):
                    self.assertEqual(docs["candidate"][role]["runId"], "1000000000")
                self.assertNotIn("createdBy", docs["candidate"])
                for field, expected in (("previousReceiptSha256", "external receipt"), ("storeBuildId", "Store build")):
                    changed = verify_sealed(docs["production_receipt"])
                    changed[field] = "f" * 64
                    args = chain_arguments(docs) | {"production_receipt": seal(changed)}
                    with self.assertRaises(ValidationError):
                        validate_receipt_chain(**args, platform=platform, config=config)

    def test_candidate_requires_platform_scoped_artifacts_and_one_signer(self) -> None:
        candidate = verify_sealed(fixture_chain()["candidate"])
        for mutate in (
            lambda value: value["artifacts"].pop(),
            lambda value: value["artifacts"].append(copy.deepcopy(value["artifacts"][0])),
            lambda value: value["signing"].append(copy.deepcopy(value["signing"][0])),
            lambda value: value["artifacts"][0].update({"logicalName": "ios-ipa", "kind": "ipa", "platform": "ios"}),
            lambda value: value["artifacts"][0].update({"architectures": [{}]}),
        ):
            changed = copy.deepcopy(candidate)
            mutate(changed)
            with self.assertRaises(ValidationError):
                validate_evidence_document(seal(changed))

    def test_observation_only_android_external_receipt_cannot_authorize_production(self) -> None:
        docs = fixture_chain()
        intent = verify_sealed(docs["external_intent"])
        snapshot = intent["storePrecondition"]["snapshot"]
        snapshot["destinationState"] = copy.deepcopy(snapshot["destinationTargetState"])
        snapshot["targetPresent"] = True
        observation_intent = seal(intent)
        with patch.dict(os.environ, workflow_environment("external-testing")):
            observation = build_receipt(stage="external-testing", platform="android", candidate_manifest=docs["candidate"], store_receipt=raw_receipt(observation_intent, result="already_present"), operation_intent=observation_intent, previous_receipt=docs["candidate_receipt"])
        args = {"candidate_manifest": docs["candidate"], "candidate_receipt": docs["candidate_receipt"], "candidate_intent": docs["candidate_intent"], "external_receipt": observation, "external_intent": observation_intent, "platform": "android"}
        validate_receipt_chain(**args)
        with self.assertRaisesRegex(ValidationError, "observation-only"):
            validate_receipt_chain(**args, require_production_eligible_external=True)

    def test_external_testflight_approved_is_pending_not_production_authority(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = load_config(write_project(Path(temporary), ios_config(), platform="ios"))
            docs = build_lifecycle(config, platform="ios")
            intent = docs["external_intent"]
            raw = raw_receipt(intent)
            raw["state"] = "approved"
            with patch.dict(os.environ, workflow_environment("external-testing")):
                validate_store_receipt(raw, config=config, release=config.release_version(), stage="external-testing", platform="ios", operation_intent=intent)
                pending = build_receipt(stage="external-testing", platform="ios", candidate_manifest=docs["candidate"], previous_receipt=docs["candidate_receipt"], operation_intent=intent, store_receipt=raw)
            args = {"candidate_manifest": docs["candidate"], "candidate_receipt": docs["candidate_receipt"], "candidate_intent": docs["candidate_intent"], "external_receipt": pending, "external_intent": intent, "platform": "ios"}
            validate_receipt_chain(**args)
            with self.assertRaisesRegex(ValidationError, "available-to-testers"):
                validate_receipt_chain(**args, require_production_eligible_external=True)

    def test_tampering_and_unknown_store_state_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = load_config(write_project(Path(temporary), android_config()))
            intent = fixture_chain()["candidate_intent"]
            raw = raw_receipt(intent)
            raw["state"] = "UNKNOWN"
            with patch.dict(os.environ, workflow_environment()), self.assertRaisesRegex(ValidationError, "availability"):
                validate_store_receipt(raw, config=config, release=config.release_version(), stage="candidate", platform="android", operation_intent=intent)

    def test_closed_play_external_receipt_requires_verified_tester_assignment(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = load_config(write_project(Path(temporary), android_config()))
            intent = fixture_chain()["external_intent"]
            raw = raw_receipt(intent)
            del raw["closedTesterAssignmentVerified"]
            with patch.dict(os.environ, workflow_environment("external-testing")):
                with self.assertRaisesRegex(ValidationError, "tester-group"):
                    validate_store_receipt(raw, config=config, release=config.release_version(), stage="external-testing", platform="android", operation_intent=intent)
                raw["closedTesterAssignmentVerified"] = True
                self.assertTrue(validate_store_receipt(raw, config=config, release=config.release_version(), stage="external-testing", platform="android", operation_intent=intent)["closedTesterAssignmentVerified"])

    def test_play_source_transition_evidence_is_fail_closed(self) -> None:
        external = verify_sealed(fixture_chain()["external_receipt"])
        for field, value, message in (("sourceUnrelatedCommittedSha256", "1" * 64, "unrelated source"), ("sourceCommittedSha256", "2" * 64, "retained source"), ("sourceTargetTransition", "deactivated", "did not change")):
            changed = copy.deepcopy(external)
            changed["storeState"][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ValidationError, message):
                validate_evidence_document(seal(changed))
        impossible = copy.deepcopy(external)
        impossible["storeState"].update({"sourceTargetTransition": "deactivated", "sourceCommittedSha256": "2" * 64, "sourceExpectedSha256": "3" * 64})
        with self.assertRaisesRegex(ValidationError, "outside the allowed transition"):
            validate_evidence_document(seal(impossible))

    def test_integrity_only_matching_hashes_do_not_substitute_for_intent_state(self) -> None:
        docs = fixture_chain()
        payload = verify_sealed(docs["external_receipt"])
        payload["storeState"]["destinationExpectedSha256"] = "0" * 64
        payload["storeState"]["destinationCommittedSha256"] = "0" * 64
        forged = seal(payload)
        # Local equality and the SHA seal alone are deliberately not authenticity.
        validate_evidence_document(forged)
        with self.assertRaisesRegex(ValidationError, "authenticated intent"):
            validate_receipt_chain(candidate_manifest=docs["candidate"], candidate_receipt=docs["candidate_receipt"], candidate_intent=docs["candidate_intent"], external_receipt=forged, external_intent=docs["external_intent"], platform="android")

    def test_evidence_cannot_drop_or_swap_its_original_intent(self) -> None:
        docs = fixture_chain()
        with self.assertRaisesRegex(ValidationError, "exact authenticated operation intent"):
            validate_receipt_chain(candidate_manifest=docs["candidate"], candidate_receipt=docs["candidate_receipt"], platform="android")
        with self.assertRaisesRegex(ValidationError, "stage/platform"):
            validate_receipt_chain(candidate_manifest=docs["candidate"], candidate_receipt=docs["candidate_receipt"], candidate_intent=docs["external_intent"], platform="android")


if __name__ == "__main__":
    unittest.main()
