"""Pure credential scalar/material policy and decoded Firebase identity checks.

No credential reader, project/filesystem custody, native tool, process owner or
service is imported. Requirements/stage/platform/purpose selection remains in
credential_requirements; these helpers do not decide whether an input is needed.

The legacy scalar helper is deliberately not value admission: empty/NUL values
and source-size checks belong to its caller, just as before extraction. Desktop
assessment adds its own bounded admission without tightening the CLI.
"""
from __future__ import annotations

import base64
import binascii
import re

CREDENTIAL_POLICY_VERSION = "credential-policy-v1"
CREDENTIALS_FILE_MAX_BYTES = 256 * 1024
PRIVATE_SMALL_MAX_BYTES = 4 * 1024 * 1024
PRIVATE_GENERAL_MAX_BYTES = 32 * 1024 * 1024

# Retain the names used by the CLI as aliases of the file-custody limits.
MAX_PRIVATE_MATERIAL_SIZE = PRIVATE_GENERAL_MAX_BYTES
SMALL_PRIVATE_MATERIAL_SIZE = PRIVATE_SMALL_MAX_BYTES


def material_size_limit(name: str) -> int:
    if any(token in name for token in ("P8", "PROFILE", "SERVICE", "SERVICES")):
        return SMALL_PRIVATE_MATERIAL_SIZE
    return MAX_PRIVATE_MATERIAL_SIZE


def credential_format_error(name: str, value: str) -> str | None:
    if name == "MOBILE_RELEASE_OPERATION_COMMITMENT_KEY_BASE64":
        try:
            decoded = base64.b64decode(value, validate=True)
        except (binascii.Error, ValueError):
            return "The commitment key must be canonical base64."
        if len(decoded) != 32:
            return "The commitment key must decode to exactly 32 bytes."
    patterns = {
        "MOBILE_RELEASE_ANDROID_KEY_ALIAS": r"[A-Za-z0-9_.-]{1,255}",
        "MOBILE_RELEASE_ASC_KEY_ID": r"[A-Z0-9]{10}",
        "MOBILE_RELEASE_ASC_ISSUER_ID": (
            r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-"
            r"[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}"
        ),
        "MOBILE_RELEASE_GOOGLE_WIF_PROVIDER": (
            r"projects/[1-9][0-9]*/locations/global/workloadIdentityPools/"
            r"[A-Za-z0-9_-]+/providers/[A-Za-z0-9_-]+"
        ),
        "MOBILE_RELEASE_GOOGLE_SERVICE_ACCOUNT": (
            r"[A-Za-z0-9][A-Za-z0-9._-]*@[A-Za-z0-9-]+\.iam\.gserviceaccount\.com"
        ),
        "MOBILE_RELEASE_OPERATION_COMMITMENT_KEY_VERSION": r"[A-Za-z0-9_.-]{1,64}",
    }
    pattern = patterns.get(name)
    if pattern and not re.fullmatch(pattern, value):
        return "The configured value has an invalid public identifier format."
    if name == "MOBILE_RELEASE_APPLE_REVIEW_CONTACT_EMAIL" and not re.fullmatch(
        r"[^\s@]+@[^\s@]+\.[^\s@]+", value
    ):
        return "The configured review contact email has an invalid format."
    return None


def firebase_payload_shape_and_match(
    payload: object, *, platform: str, expected_identity: str | None,
) -> tuple[bool, bool]:
    """Return (complete shape, identity match) for a caller-decoded document.

    Every Android client must have the existing exact decoded shape and a
    nonempty package name; at least one must equal the expected application ID.
    iOS requires an ordinary dictionary with an exact string BUNDLE_ID match.
    An empty Android array or iOS string has complete shape but cannot match.
    Shape failure is distinct from an identity mismatch for pure assessment.
    No duplicate/depth/parser limits are retrofitted onto the CLI's readers.
    """
    expected_valid = type(expected_identity) is str and bool(expected_identity)
    if platform == "android":
        if type(payload) is not dict or type(payload.get("client")) is not list:
            return False, False
        matched = False
        for client in payload["client"]:
            if type(client) is not dict or type(client.get("client_info")) is not dict:
                return False, False
            info = client["client_info"].get("android_client_info")
            if type(info) is not dict or type(info.get("package_name")) is not str or not info["package_name"]:
                return False, False
            matched |= expected_valid and info["package_name"] == expected_identity
        return True, matched
    if platform != "ios":
        return False, False
    shape = type(payload) is dict and type(payload.get("BUNDLE_ID")) is str
    return shape, bool(shape and expected_valid and payload["BUNDLE_ID"] == expected_identity)


def firebase_payload_matches_application(
    payload: object, *, platform: str, expected_identity: str | None,
) -> bool:
    """Keep the legacy bool predicate; never read bytes or a source path."""
    return firebase_payload_shape_and_match(
        payload, platform=platform, expected_identity=expected_identity,
    )[1]
