"""Pinned, credential-free current eligibility gate for each new Play AAB send.

This is a same-process check, not a reusable attestation or Store operation.
The workflow authenticates the original intent; this helper verifies its exact
inputs again and requires current native validation before a new upload.
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

from .android import validate_aab
from .config import load_config
from .credentials import artifact_validation_environment
from .errors import MobileReleaseError, ValidationError
from .provenance import load_operation_intent, sha256_file, validate_operation_intent
from .reporting import FAILING_STATUSES, Status


def validate_current_upload(
    *, app_root: Path, config_path: Path, intent_path: Path,
    aab_path: Path, intent_sha256: str,
) -> dict[str, Any]:
    if not re.fullmatch(r"[0-9a-f]{64}", intent_sha256):
        raise ValidationError("current-upload operation intent digest is invalid")
    if not app_root.is_absolute() or app_root.is_symlink() or not app_root.is_dir():
        raise ValidationError("current-upload application root must be a real absolute directory")
    config = load_config(config_path)
    if config.root != app_root.resolve() or config.path != config.project_path("release/mobile-release.json"):
        raise ValidationError("current-upload configuration is outside the approved application root")
    for path in (intent_path, aab_path):
        if not path.is_absolute() or config.project_path(str(path)) != path or path.is_symlink() or not path.is_file():
            raise ValidationError("current-upload inputs must be regular files inside the application root")
    document = load_operation_intent(intent_path)
    intent = validate_operation_intent(document)
    if document["integrity"]["sha256"] != intent_sha256:
        raise ValidationError("current-upload intent differs from the executor's authenticated intent")
    if intent["stage"] != "candidate" or intent["platform"] != "android":
        raise ValidationError("current-upload validation requires an Android candidate intent")
    section = config.section("android")
    if not config.platform_enabled("android") or section["identityStatus"] != "approved":
        raise ValidationError("current-upload Android identity is not approved")
    release = config.release_version()
    if intent["version"] != {"marketing": release.name, "build": release.build} or intent["application"] != {"id": section["applicationId"]}:
        raise ValidationError("current-upload application/version differs from the original intent")
    if sha256_file(config.path) != intent["configuration"]["sha256"]:
        raise ValidationError("current-upload configuration differs from the original intent")
    fingerprint = section["uploadCertificateSha256"].replace(":", "").lower()
    if intent["signing"] != [{"platform": "android", "kind": "android-upload", "certificateSha256": fingerprint}]:
        raise ValidationError("current-upload signer differs from the original intent")
    record = next(item for item in intent["artifacts"] if item["logicalName"] == "android-aab")
    before_hash = sha256_file(aab_path)
    if aab_path.name != record["fileName"] or aab_path.stat().st_size != record["size"] or before_hash != record["sha256"]:
        raise ValidationError("current-upload AAB differs from the original intent's exact artifact")
    findings = validate_aab(
        aab_path, expected_application_id=section["applicationId"], release=release,
        expected_fingerprint=fingerprint, require_tools=True, check_signer=True,
    )
    required = {"android.aab.structure", "android.aab.manifest", "android.aab.signature", "android.aab.signer"}
    if any(item.status in FAILING_STATUSES or item.status == Status.SKIP for item in findings) or not required <= {item.code for item in findings if item.status == Status.PASS}:
        raise ValidationError("new AAB upload is ineligible: complete current bundletool/jarsigner/keytool validation is required")
    # Recheck path safety as well as bytes after potentially slow native tools.
    if config.project_path(str(aab_path)) != aab_path or aab_path.is_symlink() or not aab_path.is_file() or sha256_file(aab_path) != before_hash or aab_path.stat().st_size != record["size"]:
        raise ValidationError("current-upload AAB changed during native validation")
    return {
        "documentType": "android-current-upload-validation", "schemaVersion": 1,
        "operationIntentSha256": intent_sha256,
        "aabSha256": before_hash, "aabSize": record["size"],
    }


def main(argv: list[str] | None = None) -> int:
    # Only the public JAR path is added to the native-tool allowlist. Its bytes
    # are still verified against the reviewed bundletool SHA-256 by validate_aab.
    jar = os.environ.get("MOBILE_RELEASE_BUNDLETOOL_JAR")
    clean = artifact_validation_environment(os.environ)
    if jar:
        clean["MOBILE_RELEASE_BUNDLETOOL_JAR"] = jar
    os.environ.clear()
    os.environ.update(clean)
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--app-root", type=Path, required=True)
    parser.add_argument("--config-path", type=Path, required=True)
    parser.add_argument("--operation-intent", type=Path, required=True)
    parser.add_argument("--aab", type=Path, required=True)
    parser.add_argument("--intent-sha256", required=True)
    args = parser.parse_args(argv)
    try:
        result = validate_current_upload(
            app_root=args.app_root, config_path=args.config_path,
            intent_path=args.operation_intent, aab_path=args.aab,
            intent_sha256=args.intent_sha256,
        )
    except MobileReleaseError as error:
        print(f"Current AAB upload validation failed: {error}", file=sys.stderr)
        return 1
    except (OSError, ValueError, subprocess.SubprocessError):
        print("Current AAB upload validation could not complete safely; no upload is authorized.", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
