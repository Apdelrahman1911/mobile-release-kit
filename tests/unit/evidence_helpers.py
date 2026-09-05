"""Credential-free evidence fixtures with independently constructed Store state."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

from mobile_release.discovery import GitContext


FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
STAGES = ("candidate", "external-testing", "production-submit")


def workflow_environment(stage: str = "candidate", *, attempt: int = 1, run_id: str | None = None, head: str = "2" * 40) -> dict[str, str]:
    return {
        "MOBILE_RELEASE_TOOLING_SHA": "1" * 40,
        "MOBILE_RELEASE_CALLER_WORKFLOW_PATH": ".github/workflows/" + {"candidate": "mobile-candidate.yml", "external-testing": "mobile-external-testing.yml", "production-submit": "mobile-production-submit.yml"}[stage],
        "MOBILE_RELEASE_REUSABLE_WORKFLOW_REPOSITORY": "example/mobile-release-kit",
        "MOBILE_RELEASE_REUSABLE_WORKFLOW_PATH": f".github/workflows/reusable-{stage}.yml",
        "GITHUB_WORKFLOW": f"Mobile {stage}",
        "GITHUB_RUN_ID": run_id or str(1000000000 + STAGES.index(stage)),
        "GITHUB_RUN_ATTEMPT": str(attempt),
        "GITHUB_SHA": head,
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_ACTIONS": "true",
        "MOBILE_RELEASE_CI_MUTATIONS_ALLOWED": "true",
        "MOBILE_RELEASE_ENVIRONMENT": {"candidate": "mobile-candidate", "external-testing": "mobile-external-testing", "production-submit": "mobile-production"}[stage],
        "GITHUB_REPOSITORY": "example/mobile-app",
        "GITHUB_REPOSITORY_ID": "100000000",
        "SOURCE_DATE_EPOCH": "1767225600",
    }


def git_identity() -> GitContext:
    return GitContext(repository="example/mobile-app", repository_id="100000000", commit="2" * 40, tree="3" * 40, ref="refs/heads/main", branch="main", dirty=False)


def fixture_chain() -> dict[str, dict]:
    files = {"candidate": "candidate-valid", "candidate_receipt": "receipt-candidate-valid", "external_receipt": "receipt-external-valid", "production_receipt": "receipt-production-valid", "candidate_intent": "intent-candidate-valid", "external_intent": "intent-external-valid", "production_intent": "intent-production-valid"}
    return {name: json.loads((FIXTURES / f"{file}.json").read_text()) for name, file in files.items()}


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def play_digest(value: object, domain: str = "track") -> str:
    return hashlib.sha256(b"mrk-play-track-state-v2:" + domain.encode("ascii") + b":" + canonical(value)).hexdigest()


def play_state(snapshot: dict, *, stage: str = "candidate", outcome: str = "accepted", source_deactivated: bool = False) -> dict:
    before, target = snapshot["destinationState"], snapshot["destinationTargetState"]
    target_release = snapshot["targetRelease"]
    code = target_release["versionCodes"][0]
    without = lambda track: [release for release in track["releases"] if code not in release["versionCodes"]]
    state = {
        "canonicalization": "mrk-play-track-state-v2", "mode": "recovery" if outcome == "reconciled" else "observation" if outcome == "already_present" else "mutation", "readbackEditId": "readback-edit",
        "destinationBeforeSha256": play_digest(before), "destinationExpectedSha256": play_digest(target), "destinationCommittedSha256": play_digest(target),
        "unrelatedBeforeSha256": play_digest(without(before), "release-set"), "unrelatedCommittedSha256": play_digest(without(target), "release-set"), "targetReleaseSha256": play_digest(target_release, "release"),
    }
    if state["mode"] == "mutation":
        state["mutationEditId"] = "mutation-edit"
    if stage != "candidate":
        source = snapshot["sourceState"]
        source_after = snapshot["sourceAllowedStates"][-1] if source_deactivated else source
        state.update({"sourceBeforeSha256": play_digest(source), "sourceExpectedSha256": play_digest(source_after), "sourceCommittedSha256": play_digest(source_after), "sourceUnrelatedBeforeSha256": play_digest(without(source), "release-set"), "sourceUnrelatedCommittedSha256": play_digest(without(source_after), "release-set"), "sourceTargetTransition": "deactivated" if source_deactivated else "retained"})
    if stage == "production-submit":
        before_metadata = {key: value for key, value in snapshot["metadataBefore"].items() if key != "observedImageIds"}
        state.update({"metadataBeforeSha256": play_digest(before_metadata, "metadata"), "metadataExpectedSha256": play_digest(snapshot["metadataTarget"], "metadata"), "metadataCommittedSha256": play_digest(snapshot["metadataTarget"], "metadata")})
    return state


def android_precondition(config, *, stage: str = "candidate", artifacts: list[dict] | None = None) -> dict:
    fixture = fixture_chain()[{"candidate": "candidate_intent", "external-testing": "external_intent", "production-submit": "production_intent"}[stage]]["storePrecondition"]
    value = copy.deepcopy(fixture)
    release = config.release_version()
    value.update({"appIdentity": config.section("android")["applicationId"], "marketingVersion": release.name, "buildNumber": release.build})
    if stage != "candidate" and artifacts:
        value["snapshot"]["bundles"][0]["sha256"] = next(item["sha256"] for item in artifacts if item["logicalName"] == "android-aab")
    return value


def apple_build() -> dict:
    return {"id": "build-resource-id", "appId": "1234567890", "marketingVersion": "1.2.3", "buildNumber": "42", "processingState": "VALID", "uploadedDate": "2025-12-31T00:00:00Z", "expirationDate": "2027-01-01T00:00:00Z", "expired": False, "usesNonExemptEncryption": False, "autoNotifyEnabled": False}


def ios_precondition(config, *, stage: str = "candidate") -> dict:
    snapshot = {"canonicalization": "mrk-apple-operation-v1", "appStoreAppId": "1234567890", "serverObservedAt": "2026-01-01T00:00:00Z", "build": None if stage == "candidate" else apple_build()}
    if stage == "external-testing":
        snapshot["external"] = {"groupId": "group-resource-id", "groupName": "External Testers", "reviewDetailId": "review-detail-id", "assigned": False, "externalState": "READY_FOR_BETA_SUBMISSION", "betaReviewState": "NOT_SUBMITTED", "usesNonExemptEncryption": False, "autoNotifyEnabled": False, "localizations": [], "targetLocalizations": [{"locale": "en-US", "whatsNew": "Verify the reader."}], "whatToTestSha256": hashlib.sha256(b"Verify the reader.").hexdigest()}
        snapshot["privateStateCommitments"] = {"algorithm": "hmac-sha256", "keyVersion": "test-v1", "domains": {"beta-review": {"before": "a" * 64, "target": "b" * 64}}}
    if stage == "production-submit":
        snapshot.update({"production": None, "appInfo": None, "liveReference": None, "appInfoReference": None, "unrelatedVersions": [], "reviewSubmissions": [], "operationNonce": "f" * 32, "metadataTarget": {"version": {"copyright": "", "localizations": [{"locale": "en-US", **{field: "" for field in ("description", "keywords", "marketingUrl", "promotionalText", "supportUrl", "whatsNew")}}]}, "appInfo": {"categories": {field: None for field in ("primaryCategory", "primarySubcategoryOne", "primarySubcategoryTwo", "secondaryCategory", "secondarySubcategoryOne", "secondarySubcategoryTwo")}, "localizations": [{"locale": "en-US", "name": "Reader", **{field: "" for field in ("subtitle", "privacyPolicyUrl", "privacyPolicyText", "privacyChoicesUrl")}}]}, "screenshots": []}, "privateStateCommitments": {"algorithm": "hmac-sha256", "keyVersion": "test-v1", "domains": {"app-review": {"before": "a" * 64, "target": "b" * 64}}}})
    return {"schemaVersion": 1, "documentType": "store-precondition", "operation": {"candidate": "ios_testflight_internal", "external-testing": "ios_testflight_external", "production-submit": "ios_app_store_submit"}[stage], "platform": "ios", "appIdentity": "com.example.reader", "marketingVersion": "1.2.3", "buildNumber": 42, "observedAt": "2026-01-01T00:00:00Z", "snapshot": snapshot}


def raw_receipt(intent: dict, *, result: str = "accepted", executed_by: dict | None = None) -> dict:
    stage, platform = intent["stage"], intent["platform"]
    raw = {"schemaVersion": 3, "operation": intent["storePrecondition"]["operation"], "platform": platform, "appIdentity": intent["application"]["id"], "marketingVersion": intent["version"]["marketing"], "buildNumber": intent["version"]["build"], "observedAt": "2026-01-01T00:00:00Z", "result": result, "operationIntentSha256": intent["integrity"]["sha256"], "authorizedBy": copy.deepcopy(intent["authorizedBy"]), "executedBy": copy.deepcopy(executed_by or intent["authorizedBy"])}
    if platform == "android":
        raw.update({"versionCode": intent["version"]["build"], "destinationTrack": intent["destination"]["channel"], "releaseStatus": intent["destination"]["releaseStatus"], "storeEditId": "readback-edit", "state": "draft" if stage == "production-submit" else "available-to-testers", "storeState": play_state(intent["storePrecondition"]["snapshot"], stage=stage, outcome=result)})
        if stage != "candidate":
            raw["sourceTrack"] = intent["storePrecondition"]["snapshot"]["sourceTrack"]
        if stage == "external-testing":
            raw["closedTesterAssignmentVerified"] = True
    else:
        raw.update({"appStoreAppId": "1234567890", "buildResourceId": "build-resource-id", "processingState": "VALID", "state": "processed" if stage == "candidate" else "available-to-testers" if stage == "external-testing" else "submitted-for-review"})
        if stage != "production-submit":
            raw["autoNotifyEnabled"] = False
        if stage == "external-testing":
            raw.update({"externalGroup": "External Testers", "betaReviewState": "APPROVED"})
        if stage == "production-submit":
            raw.update({"automaticRelease": False, "submissionState": "WAITING_FOR_REVIEW", "appStoreVersionId": "version-resource-id", "reviewSubmissionId": "review-resource-id", "storeStateSha256": "a" * 64})
    return raw


def build_lifecycle(config, *, platform: str = "android") -> dict:
    """Build an offline evidence chain; this does not pretend to validate a binary."""
    import os
    import shutil
    import tempfile
    import zipfile
    from unittest.mock import patch
    from mobile_release.metadata import build_metadata_archive
    from mobile_release.provenance import artifact_records, build_operation_intent, build_candidate_manifest, build_receipt, sha256_file, validate_store_receipt

    binary = config.root / ("app.aab" if platform == "android" else "app.ipa")
    inputs = []
    if platform == "ios":
        from .ios_artifact_helpers import packed_artifact_set

        with tempfile.TemporaryDirectory() as temporary:
            for name, path in packed_artifact_set(Path(temporary)).items():
                destination = config.root / path.name
                shutil.copyfile(path, destination)
                inputs.append((name, destination))
    else:
        with zipfile.ZipFile(binary, "w") as archive:
            archive.writestr("base/lib/arm64-v8a/libx.so", b"fixture, not an executable")
        inputs.append(("android-aab", binary))
    metadata = config.root / "store-metadata.zip"
    build_metadata_archive(config.project_path(config.section("metadata")["root"]), metadata, platform=platform)
    report = config.root / "validation-report.json"
    report.write_text('{"fixture":true}\n')
    records = artifact_records([*inputs, ("store-metadata", metadata), ("validation-report", report)])
    signing = None if platform == "android" else {"platform": "ios", "kind": "apple-distribution", "certificateSha256": "b" * 64, "teamId": "ABCDE12345", "profileUuid": "11111111-2222-3333-4444-555555555555", "profileExpiresAt": "2027-01-01T00:00:00Z"}
    docs = {"records": records, "metadata_sha256": sha256_file(metadata), "signing": signing}
    for stage in STAGES:
        with patch.dict(os.environ, workflow_environment(stage), clear=False):
            precondition = android_precondition(config, stage=stage, artifacts=records) if platform == "android" else ios_precondition(config, stage=stage)
            intent = build_operation_intent(config=config, release=config.release_version(), git=git_identity(), stage=stage, platform=platform, confirmation=f"{stage}:{platform}:1.2.3:42", metadata_sha256=docs["metadata_sha256"], store_precondition=precondition, artifacts=records, signing_evidence=signing, candidate_manifest=docs.get("candidate"), candidate_receipt=docs.get("candidate_receipt"), external_receipt=docs.get("external_receipt"), private_state_commitments=precondition["snapshot"].get("privateStateCommitments", {}))
            docs[{"candidate": "candidate_intent", "external-testing": "external_intent", "production-submit": "production_intent"}[stage]] = intent
            raw = raw_receipt(intent)
            validate_store_receipt(raw, config=config, release=config.release_version(), stage=stage, platform=platform, operation_intent=intent)
            if stage == "candidate":
                docs["candidate"] = build_candidate_manifest(config=config, release=config.release_version(), git=git_identity(), platform=platform, artifacts=records, store_receipt=raw, metadata_sha256=docs["metadata_sha256"], operation_intent=intent, signing_evidence=signing)
            receipt = build_receipt(stage=stage, platform=platform, candidate_manifest=docs["candidate"], store_receipt=raw, operation_intent=intent, previous_receipt=docs.get("candidate_receipt" if stage == "external-testing" else "external_receipt"))
            docs[{"candidate": "candidate_receipt", "external-testing": "external_receipt", "production-submit": "production_receipt"}[stage]] = receipt
    return docs
