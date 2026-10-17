"""Closed local execution receipt/attempt DATA, never dispatch or finality authority.

The exact local Execute owner supplies authenticated original intent, current
one-use consent, enrolled journal and all original joins; these DATA functions
alone provide none of that authority.
A matching new authorization ID does not prove a previous request was dispatched.
"""
from __future__ import annotations
import hashlib
from .errors import ValidationError
from .config import ReleaseVersion
from .local_release_intent import (_keys, _need, _sha, _local_json, _local_project, _local_authority,
    decode_local_operation_intent, validate_local_execution_authority)
from .provenance import (canonical_json_bytes, _validate_timestamp,
    _validate_android_store_receipt_body, _validate_ios_store_receipt_body)

MAX_LOCAL_RECEIPT_BYTES = 64 * 1024
_LOCAL_LANES = {"android": "android_internal_upload", "ios": "ios_testflight_internal"}
_ATTEMPT_DOMAIN = b"mrk-local-store-attempt-v1\0"
_RECEIPT_FIELDS = frozenset(("documentType", "schemaVersion", "origin", "project",
    "operationId", "candidateSha256", "operationIntentSha256", "preparedBy", "executedBy",
    "operation", "platform", "appIdentity", "marketingVersion", "buildNumber", "observedAt",
    "result", "state", "destinationTrack", "releaseStatus", "versionCode", "storeEditId", "storeState"))

_IOS_RECEIPT_FIELDS = (_RECEIPT_FIELDS - {"destinationTrack", "releaseStatus", "versionCode", "storeEditId", "storeState"}
    | {"appStoreAppId", "buildResourceId", "processingState", "autoNotifyEnabled"})

class LocalReceiptError(ValidationError):
    def __init__(self):
        super().__init__("Invalid local Store receipt or attempt DATA")


def _inputs(*, intent_data: bytes, authority_data: bytes, purpose: str,
            expected_intent_sha256: str, platform: str) -> tuple[dict, dict]:
    _need(_sha(expected_intent_sha256))
    intent = decode_local_operation_intent(intent_data, platform=platform)
    _need(intent["integrity"]["sha256"] == expected_intent_sha256)
    authority = validate_local_execution_authority(authority_data,
        intent_data=intent_data, purpose=purpose, platform=platform)
    return intent, authority


def local_execution_attempt_key(*, intent_data: bytes, authority_data: bytes,
                                purpose: str, expected_intent_sha256: str, platform: str = "android") -> str:
    """Prepare a fixed-domain refusal key; creates/looks up/removes no marker.

    Separate from CI execution_attempt_key. The closed local StoreLaneAttempt
    seam additionally requires its same original Execute owner; this key alone
    is not authority or original ownership.
    """
    try:
        _, authority = _inputs(intent_data=intent_data, authority_data=authority_data,
            purpose=purpose, expected_intent_sha256=expected_intent_sha256, platform=platform)
        raw = canonical_json_bytes(authority)
        _need(len(raw) <= 8 * 1024)
        lane = _LOCAL_LANES[platform].encode("ascii")
        return hashlib.sha256(_ATTEMPT_DOMAIN + bytes.fromhex(expected_intent_sha256)
            + len(raw).to_bytes(4, "big") + raw + bytes((len(lane),)) + lane).hexdigest()
    except (ValidationError, ValueError, TypeError, KeyError, AttributeError, RecursionError):
        raise LocalReceiptError() from None


def validate_local_execution_receipt(data: bytes, *, intent_data: bytes,
        authority_data: bytes, purpose: str, expected_intent_sha256: str, platform: str = "android") -> dict:
    """Validate this explicit local envelope against original comparison DATA.

    Not a reusable receipt grant, same-invocation completion, prior dispatch proof
    or evidence that an unknown old native tail settled. No IO/environment use.
    """
    try:
        intent, authority = _inputs(intent_data=intent_data, authority_data=authority_data,
            purpose=purpose, expected_intent_sha256=expected_intent_sha256, platform=platform)
        receipt = _keys(_local_json(data, MAX_LOCAL_RECEIPT_BYTES),
            _RECEIPT_FIELDS if platform == "android" else _IOS_RECEIPT_FIELDS)
        _need(receipt["documentType"] == "local-store-execution-receipt"
            and type(receipt["schemaVersion"]) is int and receipt["schemaVersion"] == 1
            and receipt["origin"] == "local-desktop" and receipt["operation"] == _LOCAL_LANES[platform]
            and receipt["platform"] == platform)
        # Structural validation precedes equality: JSON true must not compare
        # equal to integer1 in enrolled/assignment revisions.
        _local_project(receipt["project"])
        _local_authority(receipt["preparedBy"], purpose="prepare", platform=platform)
        _local_authority(receipt["executedBy"], purpose=purpose, platform=platform)
        _need(all(receipt[k] == intent[k] for k in ("project", "operationId", "candidateSha256", "preparedBy"))
            and receipt["operationIntentSha256"] == expected_intent_sha256
            and receipt["executedBy"] == authority)
        _need(receipt["appIdentity"] == intent["application"]["id"]
            and receipt["marketingVersion"] == intent["version"]["marketing"]
            and type(receipt["buildNumber"]) is int and receipt["buildNumber"] == intent["version"]["build"]
            and (platform != "android" or type(receipt["versionCode"]) is int))
        _need(type(receipt["result"]) is str and receipt["result"] in {"accepted", "reconciled"}
            and (purpose != "recover" or receipt["result"] == "reconciled"))
        _validate_timestamp(receipt["observedAt"], "local Store receipt observedAt")
        if platform == "android":
            _validate_android_store_receipt_body(receipt,
                platform_config={"applicationId": intent["application"]["id"]},
                release=ReleaseVersion(name=intent["version"]["marketing"], build=intent["version"]["build"]),
                stage="candidate", outcome="mutated" if receipt["result"] == "accepted" else "reconciled", intent=intent)
            # Readback-only recovery cannot carry a mutation-shaped receipt. Same-
            # invocation Execute may legitimately reconcile an ambiguous commit.
            _need(purpose != "recover" or receipt["storeState"]["mode"] == "recovery")
        else:
            _validate_ios_store_receipt_body(receipt,
                platform_config={"bundleId": intent["application"]["id"], "appStoreAppId": intent["application"]["storeAppId"]},
                stage="candidate", outcome="mutated" if receipt["result"] == "accepted" else "reconciled", intent=intent)
        return receipt
    except (ValidationError, ValueError, TypeError, KeyError, AttributeError, RecursionError):
        raise LocalReceiptError() from None
