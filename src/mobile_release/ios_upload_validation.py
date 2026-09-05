"""Toolkit-only, credential-free current eligibility gate for Transporter.

The pinned Store executor calls this module using ``python -I -S`` and a fixed
stdlib bootstrap selecting only the pinned toolkit directory after any absence
polling. It is not a Store operation, an attestation verifier, or a way
to manufacture historical validation: authenticity is established by the
workflow before the executor gets an intent. Every NEW upload still validates
the exact original IPA against current native signing/profile policy here.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

from .config import load_config
from .credentials import artifact_validation_environment
from .errors import MobileReleaseError, ValidationError
from .ios import ipa_signing_evidence, validate_ipa_current_signing
from .provenance import load_operation_intent, sha256_file, validate_operation_intent
from .reporting import FAILING_STATUSES, Status


def validate_current_upload(
    *,
    app_root: Path,
    config_path: Path,
    intent_path: Path,
    ipa_path: Path,
    intent_sha256: str,
) -> dict[str, Any]:
    """Validate original identity/bytes plus full *current* upload eligibility."""

    if not re.fullmatch(r"[0-9a-f]{64}", intent_sha256):
        raise ValidationError("current-upload operation intent digest is invalid")
    if not app_root.is_absolute() or app_root.is_symlink() or not app_root.is_dir():
        raise ValidationError("current-upload application root must be a real absolute directory")
    config = load_config(config_path)
    if config.root != app_root.resolve() or config.path != config.project_path("release/mobile-release.json"):
        raise ValidationError("current-upload configuration is outside the approved application root")
    for path in (intent_path, ipa_path):
        if not path.is_absolute() or config.project_path(str(path)) != path or path.is_symlink() or not path.is_file():
            raise ValidationError("current-upload inputs must be regular files inside the application root")
    intent_document = load_operation_intent(intent_path)
    intent = validate_operation_intent(intent_document)
    if intent_document["integrity"]["sha256"] != intent_sha256:
        raise ValidationError("current-upload intent differs from the executor's authenticated intent")
    if intent["stage"] != "candidate" or intent["platform"] != "ios":
        raise ValidationError("current-upload validation requires an iOS candidate intent")
    section = config.section("ios")
    if not config.platform_enabled("ios") or section["identityStatus"] != "approved":
        raise ValidationError("current-upload iOS identity is not approved")
    release = config.release_version()
    if intent["version"] != {"marketing": release.name, "build": release.build} or intent["application"] != {
        "id": section["bundleId"], "storeAppId": str(section["appStoreAppId"]),
    }:
        raise ValidationError("current-upload application/version differs from the original intent")
    if sha256_file(config.path) != intent["configuration"]["sha256"]:
        raise ValidationError("current-upload configuration differs from the original intent")
    record = next(item for item in intent["artifacts"] if item["logicalName"] == "ios-ipa")
    before_hash = sha256_file(ipa_path)
    if ipa_path.name != record["fileName"] or ipa_path.stat().st_size != record["size"] or before_hash != record["sha256"]:
        raise ValidationError("current-upload IPA differs from the original intent's exact artifact")
    findings, interval = validate_ipa_current_signing(
        ipa_path,
        expected_bundle_id=section["bundleId"],
        expected_team_id=section["teamId"],
        expected_fingerprint=section["distributionCertificateSha256"],
        release=release,
        require_tools=True,
    )
    failures = [item for item in findings if item.status in FAILING_STATUSES or item.status == Status.SKIP]
    if failures or interval is None:
        # Findings contain only toolkit-supplied diagnostics, not native-tool
        # stdout/stderr, Store secrets, private profiles, or certificate bytes.
        detail = failures[0].message if failures else "complete current signing evidence is missing"
        raise ValidationError(f"new IPA upload is ineligible: {detail}")
    if [ipa_signing_evidence(ipa_path)] != intent["signing"]:
        raise ValidationError("current-upload signer/profile differs from the original intent")
    if sha256_file(ipa_path) != before_hash or ipa_path.stat().st_size != record["size"]:
        raise ValidationError("current-upload IPA changed during native validation")
    interval.require_current()
    return {
        "documentType": "ios-current-upload-validation",
        "schemaVersion": 1,
        "operationIntentSha256": intent_sha256,
        "ipaSha256": before_hash,
        "ipaSize": record["size"],
        "notBefore": interval.lower_bound.isoformat().replace("+00:00", "Z"),
        "notAfter": interval.upper_bound.isoformat().replace("+00:00", "Z"),
    }


def main(argv: list[str] | None = None) -> int:
    # Ruby already starts this interpreter with a minimal environment. Scrub
    # again as defense in depth before any native binary/profile inspection.
    clean = artifact_validation_environment(os.environ)
    os.environ.clear()
    os.environ.update(clean)
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--app-root", type=Path, required=True)
    parser.add_argument("--config-path", type=Path, required=True)
    parser.add_argument("--operation-intent", type=Path, required=True)
    parser.add_argument("--ipa", type=Path, required=True)
    parser.add_argument("--intent-sha256", required=True)
    args = parser.parse_args(argv)
    try:
        result = validate_current_upload(
            app_root=args.app_root,
            config_path=args.config_path,
            intent_path=args.operation_intent,
            ipa_path=args.ipa,
            intent_sha256=args.intent_sha256,
        )
    except MobileReleaseError as error:
        print(f"Current IPA upload validation failed: {error}", file=sys.stderr)
        return 1
    except (OSError, ValueError, subprocess.SubprocessError):
        # Do not print exception text from subprocesses/environment/files; it
        # can include native output or credential-adjacent filesystem paths.
        print("Current IPA upload validation could not complete safely; no upload is authorized.", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
