"""Wrap actual fake-HTTP Ruby outputs in complete, explicitly synthetic envelopes.

The exporter uses minimal lane-harness intents, not authenticated workflow
evidence. Only their outer intent links are replaced below when adding Python's
repository/artifact/predecessor context. Store snapshots, observations, logical
create keys, targets, and read-back IDs remain the actual Ruby output. These
fixtures test a cross-language contract, not signatures or GitHub authentication.
"""
from __future__ import annotations

import copy
import json
import os
import zipfile
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from mobile_release.config import load_config
from mobile_release.metadata import build_metadata_archive
from mobile_release.provenance import (
    artifact_records, build_candidate_manifest, build_operation_intent,
    build_receipt, canonical_sha256, sha256_file, validate_store_receipt,
)

from .evidence_helpers import FIXTURES, git_identity, workflow_environment
from .helpers import ios_config, write_project


def apple_samples() -> dict:
    return json.loads((FIXTURES / "apple-store-contract.json").read_text())["cases"]


def authority_environment(authority: dict, stage: str) -> dict[str, str]:
    env = workflow_environment(stage, attempt=authority["attempt"], run_id=authority["runId"], head=authority["headSha"])
    env.update({
        "GITHUB_WORKFLOW": authority["workflow"],
        "GITHUB_REF": authority["ref"],
        "MOBILE_RELEASE_TOOLING_SHA": authority["reusableCommit"],
        "MOBILE_RELEASE_REUSABLE_WORKFLOW_REPOSITORY": authority["reusableRepository"],
    })
    return env


def wrap_apple_contracts(root: Path, *, samples: dict | None = None) -> tuple[object, dict[str, dict]]:
    values = ios_config()
    values["ios"].update({"bundleId": "test.example.release", "appStoreAppId": "12345", "externalTestFlightGroup": "External QA"})
    # Match the actual lane harness's configured scope; do not infer a new scope
    # from its target vector (which also retains unconfigured Store locales).
    values["metadata"]["iosLocales"] = ["en-US", "fr-FR", "de-DE"]
    config = load_config(write_project(root, values, platform="ios"))
    (root / "release/version.properties").write_text("VERSION_NAME=1.2.3\nBUILD_NUMBER=123\n")
    ipa = root / "candidate.ipa"
    with zipfile.ZipFile(ipa, "w") as archive:
        archive.writestr("Payload/Fictional.app/Fictional", b"not executable or signed")
    report = root / "validation-report.json"
    report.write_text('{"fixture":true}\n')
    metadata = root / "store-metadata.zip"
    build_metadata_archive(root / "release/store", metadata, platform="ios")
    artifacts = artifact_records([("ios-ipa", ipa), ("store-metadata", metadata), ("validation-report", report)])
    metadata_sha256 = sha256_file(metadata)
    signing = {"platform": "ios", "kind": "apple-distribution", "certificateSha256": "b" * 64, "teamId": "ABCDE12345", "profileUuid": "11111111-2222-3333-4444-555555555555", "profileExpiresAt": "2027-01-01T00:00:00Z"}
    docs: dict[str, dict] = {}
    for name, sample in (apple_samples() if samples is None else samples).items():
        raw = copy.deepcopy(sample["receipt"])
        stage = sample["intent"]["stage"]
        authorized = raw["authorizedBy"]
        git = replace(git_identity(), commit=authorized["headSha"], tree="c" * 40)
        candidate = docs.get("candidate", {}).get("candidate")
        candidate_receipt = docs.get("candidate", {}).get("receipt")
        # Production must follow actual available-to-testers observation, not
        # the earlier immutable pending Beta Review receipt.
        external_receipt = docs.get("external-available", {}).get("receipt")
        with patch.dict(os.environ, authority_environment(authorized, stage), clear=True):
            intent = build_operation_intent(
                config=config, release=config.release_version(), git=git, stage=stage,
                platform="ios", confirmation=f"{stage}:ios:1.2.3:123",
                metadata_sha256=metadata_sha256, artifacts=artifacts,
                signing_evidence=signing, store_precondition=sample["precondition"],
                private_state_commitments=sample["intent"]["privateStateCommitments"],
                candidate_manifest=candidate, candidate_receipt=candidate_receipt,
                external_receipt=external_receipt,
            )
        raw["operationIntentSha256"] = intent["integrity"]["sha256"]
        if "createRetry" in raw:
            retry = raw["createRetry"]
            retry["inventory"]["operationIntentSha256"] = intent["integrity"]["sha256"]
            retry["inventorySha256"] = canonical_sha256(retry["inventory"])
        recovery = authorized["runId"] if raw["executedBy"]["runId"] != authorized["runId"] else None
        with patch.dict(os.environ, authority_environment(raw["executedBy"], stage), clear=True):
            validate_store_receipt(raw, config=config, release=config.release_version(), stage=stage, platform="ios", operation_intent=intent, recovery_run_id=recovery)
            if stage == "candidate":
                candidate = build_candidate_manifest(config=config, release=config.release_version(), git=git, platform="ios", artifacts=artifacts, store_receipt=raw, metadata_sha256=metadata_sha256, operation_intent=intent, signing_evidence=signing)
            receipt = build_receipt(stage=stage, platform="ios", candidate_manifest=candidate, store_receipt=raw, operation_intent=intent, previous_receipt=candidate_receipt if stage == "external-testing" else external_receipt)
        docs[name] = {"intent": intent, "raw": raw, "receipt": receipt, "candidate": candidate}
    return config, docs
