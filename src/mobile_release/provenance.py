from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

from . import __version__
from .config import ReleaseConfig, ReleaseVersion
from .discovery import GitContext
from .errors import ValidationError

HEX_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SENSITIVE_KEY_RE = re.compile(r"(?i)(password|private.?key|secret|token|credential|keystore.?base64)")
SENSITIVE_VALUE_RE = re.compile(r"-----BEGIN (?:[A-Z ]*PRIVATE KEY|CERTIFICATE)-----")


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValidationError(f"duplicate JSON key in release evidence: {key}")
        result[key] = value
    return result


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def canonical_json_bytes(value: Any) -> bytes:
    _validate_json_value(value)
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _validate_json_value(value: Any, path: str = "$") -> None:
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float):
        raise ValidationError(f"floating-point values are forbidden in canonical evidence: {path}")
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_json_value(item, f"{path}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValidationError(f"non-string JSON key in evidence: {path}")
            if SENSITIVE_KEY_RE.search(key):
                raise ValidationError(f"sensitive field is forbidden in release evidence: {path}.{key}")
            if isinstance(item, str) and SENSITIVE_VALUE_RE.search(item):
                raise ValidationError(f"private material is forbidden in release evidence: {path}.{key}")
            _validate_json_value(item, f"{path}.{key}")
        return
    raise ValidationError(f"unsupported canonical evidence value at {path}: {type(value).__name__}")


def timestamp() -> str:
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    try:
        current = (
            datetime.fromtimestamp(int(epoch, 10), tz=timezone.utc)
            if epoch is not None
            else datetime.now(tz=timezone.utc)
        )
    except (ValueError, OverflowError, OSError) as error:
        raise ValidationError("SOURCE_DATE_EPOCH must be a supported base-10 Unix timestamp") from error
    return current.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _validate_timestamp(value: object, field: str) -> None:
    if not isinstance(value, str) or not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value
    ):
        raise ValidationError(f"{field} must be second-precision UTC RFC3339")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as error:
        raise ValidationError(f"{field} is not a real UTC timestamp") from error


def seal(payload: dict[str, Any]) -> dict[str, Any]:
    if "integrity" in payload:
        raise ValidationError("unsealed payload must not contain integrity")
    result = dict(payload)
    result["integrity"] = {"algorithm": "sha256", "sha256": canonical_sha256(payload)}
    return result


def verify_sealed(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValidationError("release evidence must be a JSON object")
    document = dict(value)
    _validate_json_value(document)
    integrity = value.get("integrity")
    if not isinstance(integrity, dict) or set(integrity) != {"algorithm", "sha256"}:
        raise ValidationError("release evidence integrity must contain only algorithm and sha256")
    if integrity.get("algorithm") != "sha256":
        raise ValidationError("release evidence is missing SHA-256 integrity")
    expected = integrity.get("sha256")
    if not isinstance(expected, str) or not HEX_SHA256_RE.fullmatch(expected):
        raise ValidationError("release evidence has an invalid SHA-256 integrity value")
    payload = document
    del payload["integrity"]
    actual = canonical_sha256(payload)
    if actual != expected:
        raise ValidationError("release evidence integrity mismatch")
    return payload


def _evidence_path_has_symlink(path: Path) -> bool:
    boundary = next(
        (ancestor for ancestor in (path.parent, *path.parent.parents) if (ancestor / ".git").exists()),
        path.parent,
    )
    try:
        relative = path.relative_to(boundary)
    except ValueError:
        return True
    current = boundary
    if current.is_symlink():
        return True
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            return True
    return False


def validate_evidence_output_path(path: Path) -> Path:
    destination = path.expanduser().absolute()
    if _evidence_path_has_symlink(destination):
        raise ValidationError("release evidence output must not traverse a symbolic link")
    if destination.exists() or destination.is_symlink():
        raise ValidationError("immutable release evidence output already exists")
    if destination.parent.exists() and not destination.parent.is_dir():
        raise ValidationError("release evidence output parent must be a directory")
    return destination


def write_evidence(path: Path, value: dict[str, Any]) -> None:
    validate_evidence_document(value)
    path = validate_evidence_output_path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path = validate_evidence_output_path(path)
    payload = json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        try:
            os.link(temporary, path, follow_symlinks=False)
        except FileExistsError as error:
            raise ValidationError("immutable release evidence output already exists") from error
        except OSError as error:
            raise ValidationError("release evidence could not be published atomically") from error
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def load_evidence(path: Path) -> dict[str, Any]:
    path = path.expanduser().absolute()
    if _evidence_path_has_symlink(path) or not path.is_file():
        raise ValidationError(f"release evidence must be a regular non-symlink file: {path}")
    if path.stat().st_size > 2 * 1024 * 1024:
        raise ValidationError(f"release evidence is unexpectedly large: {path}")
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicate_pairs
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValidationError(f"release evidence is not valid UTF-8 JSON: {path}") from error
    if not isinstance(value, dict):
        raise ValidationError("release evidence must contain a JSON object")
    validate_evidence_document(value)
    return value


def _exact_keys(value: object, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValidationError(f"{label} must be an object")
    if set(value) != keys:
        missing = sorted(keys - set(value))
        unknown = sorted(set(value) - keys)
        raise ValidationError(
            f"{label} fields differ from schema; missing={missing}, unknown={unknown}"
        )
    return value


def validate_evidence_document(value: Mapping[str, Any]) -> None:
    payload = verify_sealed(value)
    common_sha = lambda item: isinstance(item, str) and bool(HEX_SHA256_RE.fullmatch(item))
    git_id = lambda item: isinstance(item, str) and bool(
        re.fullmatch(r"[0-9A-Fa-f]{40}", item)
    )
    if "stage" in payload:
        required = {
            "schemaVersion",
            "stage",
            "candidateManifestSha256",
            "tooling",
            "repository",
            "source",
            "platform",
            "provider",
            "applicationId",
            "version",
            "storeBuildId",
            "operation",
            "outcome",
            "destination",
            "readback",
            "createdBy",
            "createdAt",
        }
        if payload.get("stage") != "candidate":
            required.add("previousReceiptSha256")
        if payload.get("platform") == "android":
            required.add("storeState")
        receipt = _exact_keys(payload, required, "receipt")
        if (
            type(receipt["schemaVersion"]) is not int
            or receipt["schemaVersion"] != 2
            or receipt["stage"]
            not in {
                "candidate",
                "external-testing",
                "production-submit",
            }
        ):
            raise ValidationError("receipt schemaVersion/stage is invalid")
        if not common_sha(receipt["candidateManifestSha256"]) or (
            "previousReceiptSha256" in receipt
            and not common_sha(receipt["previousReceiptSha256"])
        ):
            raise ValidationError("receipt linkage hash is invalid")
        platform = receipt["platform"]
        if platform not in {"android", "ios"}:
            raise ValidationError("receipt platform is invalid")
        expected_provider = "google-play" if platform == "android" else "app-store-connect"
        if receipt["provider"] != expected_provider:
            raise ValidationError("receipt provider/platform mismatch")
        _validate_common_evidence(receipt, git_id)
        if platform == "ios" and not re.fullmatch(
            r"[0-9]+(?:\.[0-9]+){1,2}", receipt["version"]["marketing"]
        ):
            raise ValidationError("iOS receipt marketing version is invalid")
        _exact_keys(receipt["source"], {"commit", "tree"}, "receipt.source")
        if (
            not isinstance(receipt["applicationId"], str)
            or not 1 <= len(receipt["applicationId"]) <= 255
        ):
            raise ValidationError("receipt applicationId is invalid")
        if (
            not isinstance(receipt["storeBuildId"], str)
            or not 1 <= len(receipt["storeBuildId"]) <= 255
        ):
            raise ValidationError("receipt storeBuildId is invalid")
        expected_operations = {
            ("candidate", "android"): "uploaded",
            ("candidate", "ios"): "uploaded",
            ("external-testing", "android"): "promoted",
            ("external-testing", "ios"): "distributed",
            ("production-submit", "android"): "promoted",
            ("production-submit", "ios"): "submitted",
        }
        if receipt["operation"] != expected_operations[(receipt["stage"], platform)]:
            raise ValidationError("receipt operation does not match its stage/platform")
        if receipt["outcome"] not in {"mutated", "reconciled", "already-present"}:
            raise ValidationError("receipt outcome is invalid")
        if receipt["stage"] == "candidate" and receipt["outcome"] == "already-present":
            raise ValidationError("candidate receipt cannot adopt an already-present build")
        if (
            platform == "android"
            and receipt["stage"] == "production-submit"
            and receipt["outcome"] == "already-present"
        ):
            raise ValidationError("production Play receipt cannot adopt an existing draft")
        if platform == "ios" and receipt["outcome"] == "reconciled":
            raise ValidationError("iOS receipt cannot claim unsupported reconciliation")
        if platform == "android":
            _validate_play_store_state(
                receipt["storeState"],
                stage=receipt["stage"],
                outcome=receipt["outcome"],
            )
        destination_keys = {"channel"}
        if platform == "android":
            destination_keys.add("releaseStatus")
            if (
                receipt["stage"] == "external-testing"
                and isinstance(receipt.get("destination"), dict)
                and "closedTesterAssignmentVerified" in receipt["destination"]
            ):
                destination_keys.add("closedTesterAssignmentVerified")
        elif receipt["stage"] == "production-submit":
            destination_keys.add("automaticRelease")
        destination = _exact_keys(receipt["destination"], destination_keys, "receipt.destination")
        if (
            not isinstance(destination["channel"], str)
            or not 1 <= len(destination["channel"]) <= 255
        ):
            raise ValidationError("receipt destination channel is invalid")
        if platform == "android":
            expected_status = "draft" if receipt["stage"] == "production-submit" else "completed"
            if destination["releaseStatus"] != expected_status:
                raise ValidationError("receipt Play release status does not match its stage")
            if receipt["stage"] == "candidate" and destination["channel"] != "internal":
                raise ValidationError("candidate Play receipt must target internal")
            if receipt["stage"] == "external-testing" and destination["channel"] in {
                "internal",
                "production",
            }:
                raise ValidationError("external Play receipt must target a testing track")
            if (
                "closedTesterAssignmentVerified" in destination
                and destination["closedTesterAssignmentVerified"] is not True
            ):
                raise ValidationError("closed Play tester-assignment evidence must be true")
            if receipt["stage"] == "production-submit" and destination["channel"] != "production":
                raise ValidationError("production Play receipt must target production draft")
        else:
            if "storeState" in receipt:
                raise ValidationError("iOS receipt must not contain Play Store-state evidence")
            expected_channel = {
                "candidate": "testflight-internal",
                "external-testing": "testflight-external",
                "production-submit": "app-store-review",
            }[receipt["stage"]]
            if destination["channel"] != expected_channel:
                raise ValidationError("receipt Apple destination does not match its stage")
            if receipt["stage"] == "production-submit" and destination["automaticRelease"] is not False:
                raise ValidationError("App Store receipt must disable automatic release")
        readback = _exact_keys(receipt["readback"], {"state", "observedAt"}, "receipt.readback")
        _validate_timestamp(readback["observedAt"], "receipt.readback.observedAt")
        allowed_states = {
            ("candidate", "android"): {"available-to-testers"},
            ("candidate", "ios"): {"processed", "available-to-testers"},
            ("external-testing", "android"): {"available-to-testers"},
            ("external-testing", "ios"): {
                "available-to-testers",
                "submitted-for-review",
                "in-review",
                "approved",
            },
            ("production-submit", "android"): {"draft"},
            ("production-submit", "ios"): {
                "submitted-for-review",
                "in-review",
                "approved",
                "pending-developer-release",
            },
        }
        if readback["state"] not in allowed_states[(receipt["stage"], platform)]:
            raise ValidationError("receipt readback state does not match its stage/platform")
        return

    required = {
        "schemaVersion",
        "tooling",
        "repository",
        "source",
        "configuration",
        "version",
        "platforms",
        "artifacts",
        "signing",
        "storeReceipts",
        "createdBy",
        "createdAt",
    }
    manifest = _exact_keys(payload, required, "candidate")
    if type(manifest["schemaVersion"]) is not int or manifest["schemaVersion"] != 1:
        raise ValidationError("candidate schemaVersion must be 1")
    _validate_common_evidence(manifest, git_id)
    source = _exact_keys(manifest["source"], {"commit", "tree", "ref"}, "candidate.source")
    if not isinstance(source["ref"], str) or not 1 <= len(source["ref"]) <= 512:
        raise ValidationError("candidate source ref is invalid")
    configuration = _exact_keys(
        manifest["configuration"], {"path", "sha256", "metadataSha256"}, "configuration"
    )
    if configuration["path"] != "release/mobile-release.json" or not all(
        common_sha(configuration[key]) for key in ("sha256", "metadataSha256")
    ):
        raise ValidationError("candidate configuration evidence is invalid")
    if not isinstance(manifest["platforms"], dict) or not manifest["platforms"]:
        raise ValidationError("candidate platforms must be a non-empty object")
    if len(manifest["platforms"]) != 1 or not set(manifest["platforms"]) <= {"android", "ios"}:
        raise ValidationError("candidate must contain exactly one supported platform")
    platform = next(iter(manifest["platforms"]))
    if platform == "ios" and not re.fullmatch(
        r"[0-9]+(?:\.[0-9]+){1,2}", manifest["version"]["marketing"]
    ):
        raise ValidationError("iOS candidate marketing version is invalid")
    identity_keys = {"applicationId", "storeAppId"} if platform == "ios" else {"applicationId"}
    identity = _exact_keys(
        manifest["platforms"][platform], identity_keys, f"candidate.platforms.{platform}"
    )
    if (
        not isinstance(identity["applicationId"], str)
        or not 3 <= len(identity["applicationId"]) <= 255
    ):
        raise ValidationError("candidate application identity is invalid")
    if platform == "ios" and (
        not isinstance(identity["storeAppId"], str)
        or not 1 <= len(identity["storeAppId"]) <= 255
    ):
        raise ValidationError("candidate App Store application ID is invalid")
    if (
        not isinstance(manifest["artifacts"], list)
        or not manifest["artifacts"]
        or len(manifest["artifacts"]) > 64
    ):
        raise ValidationError("candidate artifacts must be non-empty")
    artifact_names: set[str] = set()
    artifact_types = {
        "android-aab": ("android", "aab"),
        "android-mapping": ("android", "r8-mapping"),
        "android-native-symbols": ("android", "native-symbols"),
        "ios-ipa": ("ios", "ipa"),
        "ios-archive": ("ios", "xcarchive"),
        "ios-dsyms": ("ios", "dsym"),
        "store-metadata": ("shared", "metadata"),
        "validation-report": ("shared", "validation-report"),
    }
    allowed_artifacts = {
        "android": {
            "android-aab",
            "android-mapping",
            "android-native-symbols",
            "store-metadata",
            "validation-report",
        },
        "ios": {
            "ios-ipa",
            "ios-archive",
            "ios-dsyms",
            "store-metadata",
            "validation-report",
        },
    }[platform]
    for artifact in manifest["artifacts"]:
        value = _exact_keys(
            artifact,
            {"logicalName", "platform", "kind", "fileName", "size", "sha256", "architectures"},
            "artifact",
        )
        if (
            isinstance(value["size"], bool)
            or not isinstance(value["size"], int)
            or value["size"] < 1
            or not common_sha(value["sha256"])
        ):
            raise ValidationError("candidate artifact size/hash is invalid")
        if (
            not isinstance(value["logicalName"], str)
            or value["logicalName"] in artifact_names
            or value["logicalName"] not in allowed_artifacts
        ):
            raise ValidationError("candidate artifact logical name is unsupported or duplicated")
        artifact_names.add(value["logicalName"])
        if (value["platform"], value["kind"]) != artifact_types[value["logicalName"]]:
            raise ValidationError("candidate artifact platform/kind does not match its logical name")
        if (
            not isinstance(value["fileName"], str)
            or value["fileName"] in {"", ".", ".."}
            or len(value["fileName"]) > 255
            or "/" in value["fileName"]
            or "\\" in value["fileName"]
        ):
            raise ValidationError("candidate artifact fileName must be a basename")
        architectures = value["architectures"]
        if (
            not isinstance(architectures, list)
            or len(architectures) != len(set(architectures))
            or any(
                not isinstance(item, str)
                or not re.fullmatch(r"[A-Za-z0-9_.-]+", item)
                for item in architectures
            )
        ):
            raise ValidationError("candidate artifact architectures are invalid")
    required_primary = "android-aab" if platform == "android" else "ios-ipa"
    required_artifacts = {required_primary, "store-metadata", "validation-report"}
    if not required_artifacts <= artifact_names:
        raise ValidationError(
            "candidate lacks its primary binary, deterministic metadata, or validation report"
        )
    if not isinstance(manifest["signing"], list) or not manifest["signing"]:
        raise ValidationError("candidate signing evidence must be non-empty")
    if len(manifest["signing"]) != 1:
        raise ValidationError("candidate must contain exactly one signing identity")
    signing_keys = {"platform", "kind", "certificateSha256"}
    if platform == "ios":
        signing_keys.update({"teamId", "profileUuid", "profileExpiresAt"})
    signing = _exact_keys(manifest["signing"][0], signing_keys, "candidate.signing")
    expected_kind = "android-upload" if platform == "android" else "apple-distribution"
    if (
        signing["platform"] != platform
        or signing["kind"] != expected_kind
        or not common_sha(signing["certificateSha256"])
    ):
        raise ValidationError("candidate signing identity does not match its platform")
    if platform == "ios":
        if not re.fullmatch(r"[A-Z0-9]{10}", str(signing["teamId"])) or not re.fullmatch(
            r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-"
            r"[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}",
            str(signing["profileUuid"]),
        ):
            raise ValidationError("candidate Apple signing/profile identity is invalid")
        _validate_timestamp(signing["profileExpiresAt"], "candidate.signing.profileExpiresAt")
    if not isinstance(manifest["storeReceipts"], list) or not manifest["storeReceipts"]:
        raise ValidationError("candidate internal Store readback must be non-empty")
    if len(manifest["storeReceipts"]) != 1:
        raise ValidationError("candidate must contain exactly one internal Store readback")
    store = _exact_keys(
        manifest["storeReceipts"][0],
        {
            "provider",
            "applicationId",
            "storeBuildId",
            "marketingVersion",
            "build",
            "channel",
            "state",
            "observedAt",
        },
        "candidate.storeReceipt",
    )
    expected_provider = "google-play" if platform == "android" else "app-store-connect"
    expected_channel = "internal" if platform == "android" else "testflight-internal"
    allowed_candidate_states = (
        {"available-to-testers"} if platform == "android" else {"processed", "available-to-testers"}
    )
    if (
        store["provider"] != expected_provider
        or store["applicationId"] != identity["applicationId"]
        or store["marketingVersion"] != manifest["version"]["marketing"]
        or store["build"] != manifest["version"]["build"]
        or store["channel"] != expected_channel
        or store["state"] not in allowed_candidate_states
        or not isinstance(store["storeBuildId"], str)
        or not 1 <= len(store["storeBuildId"]) <= 255
    ):
        raise ValidationError("candidate Store readback is not bound to its exact internal build")
    _validate_timestamp(store["observedAt"], "candidate.storeReceipt.observedAt")


def _validate_common_evidence(value: Mapping[str, Any], git_id: Any) -> None:
    tooling = _exact_keys(value["tooling"], {"version", "commit"}, "tooling")
    repository = _exact_keys(value["repository"], {"fullName", "id"}, "repository")
    version = _exact_keys(value["version"], {"marketing", "build"}, "version")
    workflow = _exact_keys(value["createdBy"], {"workflow", "runId", "attempt"}, "createdBy")
    if not git_id(tooling["commit"]):
        raise ValidationError("tooling commit is not a full Git object ID")
    if not isinstance(tooling["version"], str) or not re.fullmatch(
        r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?", tooling["version"]
    ):
        raise ValidationError("tooling version is invalid")
    if not isinstance(repository["fullName"], str) or not re.fullmatch(
        r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository["fullName"]
    ):
        raise ValidationError("repository fullName is invalid")
    if not isinstance(repository["id"], str) or not re.fullmatch(r"[1-9][0-9]*", repository["id"]):
        raise ValidationError("repository ID is invalid")
    if (
        not isinstance(version["marketing"], str)
        or len(version["marketing"]) > 64
        or not re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,3}(?:[-+][0-9A-Za-z.-]+)?", version["marketing"])
        or isinstance(version["build"], bool)
        or not isinstance(version["build"], int)
        or not 1 <= version["build"] <= 2_100_000_000
    ):
        raise ValidationError("evidence version is invalid")
    if (
        not isinstance(workflow["workflow"], str)
        or not workflow["workflow"]
        or len(workflow["workflow"]) > 255
        or not isinstance(workflow["runId"], str)
        or not re.fullmatch(r"[1-9][0-9]*", workflow["runId"])
        or isinstance(workflow["attempt"], bool)
        or not isinstance(workflow["attempt"], int)
        or workflow["attempt"] < 1
    ):
        raise ValidationError("workflow run ID is invalid")
    source = value["source"]
    if not isinstance(source, dict) or not git_id(source.get("commit")) or not git_id(
        source.get("tree")
    ):
        raise ValidationError("source Git object IDs are invalid")
    _validate_timestamp(value["createdAt"], "createdAt")


def load_store_receipt(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValidationError(f"Store receipt must be a regular non-symlink file: {path}")
    if path.stat().st_size > 1024 * 1024:
        raise ValidationError("Store receipt is unexpectedly large")
    try:
        receipt = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicate_pairs
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValidationError("Store receipt is not valid UTF-8 JSON") from error
    if not isinstance(receipt, dict):
        raise ValidationError("Store receipt must be a JSON object")
    _validate_json_value(receipt)
    return receipt


def _validate_play_store_state(
    value: object,
    *,
    stage: str,
    outcome: str,
    store_edit_id: object | None = None,
) -> dict[str, Any]:
    required = {
        "canonicalization",
        "mode",
        "readbackEditId",
        "destinationBeforeSha256",
        "destinationExpectedSha256",
        "destinationCommittedSha256",
        "unrelatedBeforeSha256",
        "unrelatedCommittedSha256",
        "targetReleaseSha256",
    }
    if outcome in {"mutated", "reconciled"}:
        required.add("mutationEditId")
    if stage != "candidate":
        required.update(
            {
                "sourceBeforeSha256",
                "sourceExpectedSha256",
                "sourceCommittedSha256",
                "sourceUnrelatedBeforeSha256",
                "sourceUnrelatedCommittedSha256",
                "sourceTargetTransition",
            }
        )
    state = _exact_keys(value, required, "receipt.storeState")
    if state["canonicalization"] != "mrk-play-track-state-v1":
        raise ValidationError("Play Store-state canonicalization is unsupported")
    expected_mode = "observation" if outcome == "already-present" else "mutation"
    if state["mode"] != expected_mode:
        raise ValidationError("Play Store-state mode does not match receipt outcome")
    for field in required & {
        "mutationEditId",
        "readbackEditId",
    }:
        if (
            not isinstance(state[field], str)
            or not state[field].strip()
            or len(state[field]) > 255
        ):
            raise ValidationError(f"Play Store-state {field} is invalid")
    if store_edit_id is not None and state["readbackEditId"] != store_edit_id:
        raise ValidationError("Play Store receipt/readback edit IDs do not match")
    if "mutationEditId" in state and state["mutationEditId"] == state["readbackEditId"]:
        raise ValidationError("Play mutation and readback must use distinct edits")
    hash_fields = required - {
        "canonicalization",
        "mode",
        "mutationEditId",
        "readbackEditId",
        "sourceTargetTransition",
    }
    if not all(
        isinstance(state[field], str) and HEX_SHA256_RE.fullmatch(state[field])
        for field in hash_fields
    ):
        raise ValidationError("Play Store-state evidence contains an invalid SHA-256")
    if state["destinationExpectedSha256"] != state["destinationCommittedSha256"]:
        raise ValidationError("Play committed destination differs from the guarded expected state")
    if state["unrelatedBeforeSha256"] != state["unrelatedCommittedSha256"]:
        raise ValidationError("Play receipt does not preserve unrelated destination releases")
    if stage != "candidate":
        if (
            state["sourceUnrelatedBeforeSha256"]
            != state["sourceUnrelatedCommittedSha256"]
        ):
            raise ValidationError("Play receipt does not preserve unrelated source releases")
        transition = state["sourceTargetTransition"]
        if outcome == "already-present":
            if transition not in {"retained", "already-deactivated"}:
                raise ValidationError("Play observation has an invalid source transition")
            if not (
                state["sourceBeforeSha256"]
                == state["sourceExpectedSha256"]
                == state["sourceCommittedSha256"]
            ):
                raise ValidationError("Play observation contains a source-state change")
        else:
            if transition not in {"retained", "deactivated"}:
                raise ValidationError("Play mutation has an invalid source transition")
            if state["sourceExpectedSha256"] not in {
                state["sourceBeforeSha256"],
                state["sourceCommittedSha256"],
            }:
                raise ValidationError("Play source expected state is outside the allowed transition")
            if transition == "retained" and not (
                state["sourceBeforeSha256"]
                == state["sourceExpectedSha256"]
                == state["sourceCommittedSha256"]
            ):
                raise ValidationError("Play retained source transition changed source state")
            if (
                transition == "deactivated"
                and state["sourceBeforeSha256"] == state["sourceCommittedSha256"]
            ):
                raise ValidationError("Play deactivated source transition did not change source state")
    if outcome == "already-present" and not (
        state["destinationBeforeSha256"]
        == state["destinationExpectedSha256"]
        == state["destinationCommittedSha256"]
    ):
        raise ValidationError("Play observation receipt contains a mutation-shaped state change")
    return state


def validate_store_receipt(
    receipt: Mapping[str, Any],
    *,
    config: ReleaseConfig,
    release: ReleaseVersion,
    stage: str,
    platform: str,
) -> dict[str, Any]:
    operations = {
        ("candidate", "android"): "android_internal_upload",
        ("candidate", "ios"): "ios_testflight_internal",
        ("external-testing", "android"): "android_external_promote",
        ("external-testing", "ios"): "ios_testflight_external",
        ("production-submit", "android"): "android_production_draft",
        ("production-submit", "ios"): "ios_app_store_submit",
    }
    operation = operations.get((stage, platform))
    if not operation:
        raise ValidationError(f"unsupported Store receipt stage/platform: {stage}/{platform}")
    required_common = {
        "schemaVersion",
        "operation",
        "platform",
        "appIdentity",
        "marketingVersion",
        "buildNumber",
        "observedAt",
        "result",
        "state",
    }
    missing = sorted(required_common - set(receipt))
    if missing:
        raise ValidationError(f"Store receipt is missing fields: {', '.join(missing)}")
    if type(receipt["schemaVersion"]) is not int or receipt["schemaVersion"] != 2:
        raise ValidationError("Store receipt schemaVersion must be 2")
    if receipt["operation"] != operation or receipt["platform"] != platform:
        raise ValidationError("Store receipt operation/platform does not match the requested stage")
    platform_config = config.section(platform)
    allowed = set(required_common)
    if platform == "android":
        allowed.update(
            {
                "destinationTrack",
                "releaseStatus",
                "versionCode",
                "storeEditId",
                "releaseId",
                "storeState",
            }
        )
        if stage != "candidate":
            allowed.add("sourceTrack")
        if (
            stage == "external-testing"
            and platform_config.get("externalTrack", {}).get("kind") == "closed"
        ):
            allowed.add("closedTesterAssignmentVerified")
    else:
        allowed.update({"appStoreAppId", "buildResourceId", "processingState"})
        if stage == "external-testing":
            allowed.update({"externalGroup", "betaReviewState"})
        elif stage == "production-submit":
            allowed.update({"automaticRelease", "submissionState"})
    unknown = sorted(set(receipt) - allowed)
    if unknown:
        raise ValidationError(f"Store receipt contains unexpected fields: {', '.join(unknown)}")
    identity_key = "applicationId" if platform == "android" else "bundleId"
    if receipt["appIdentity"] != platform_config.get(identity_key):
        raise ValidationError("Store receipt application identity does not match configuration")
    if (
        receipt["marketingVersion"] != release.name
        or isinstance(receipt["buildNumber"], bool)
        or receipt["buildNumber"] != release.build
    ):
        raise ValidationError("Store receipt version/build does not match committed release version")
    if receipt["result"] not in {"accepted", "reconciled", "already_present"}:
        raise ValidationError(
            "Store receipt does not prove accepted, reconciled, or already-present Store state"
        )
    if platform == "ios" and receipt["result"] == "reconciled":
        raise ValidationError("iOS Store receipt cannot claim unsupported reconciliation")
    if stage == "candidate" and receipt["result"] == "already_present":
        raise ValidationError("candidate upload must be newly accepted; adoption is forbidden")
    if (
        platform == "android"
        and stage == "production-submit"
        and receipt["result"] == "already_present"
    ):
        raise ValidationError("production Play draft adoption is forbidden")
    _validate_timestamp(receipt["observedAt"], "Store receipt observedAt")

    if platform == "android":
        for field in ("destinationTrack", "releaseStatus", "versionCode"):
            if field not in receipt:
                raise ValidationError(f"Android Store receipt is missing {field}")
        if isinstance(receipt["versionCode"], bool) or receipt["versionCode"] != release.build:
            raise ValidationError("Play versionCode does not match the committed build number")
        if not receipt.get("storeEditId") and not receipt.get("releaseId"):
            raise ValidationError("Android Store receipt lacks authoritative edit/release readback")
        for field in ("storeEditId", "releaseId"):
            if field in receipt and (
                not isinstance(receipt[field], str)
                or not receipt[field].strip()
                or len(receipt[field]) > 255
            ):
                raise ValidationError(f"Android Store receipt {field} is invalid")
        outcome = {
            "accepted": "mutated",
            "reconciled": "reconciled",
            "already_present": "already-present",
        }[receipt["result"]]
        _validate_play_store_state(
            receipt.get("storeState"),
            stage=stage,
            outcome=outcome,
            store_edit_id=receipt.get("storeEditId"),
        )
        expected_track = {
            "candidate": "internal",
            "external-testing": platform_config.get("externalTrack", {}).get("name"),
            "production-submit": "production",
        }[stage]
        if receipt["destinationTrack"] != expected_track:
            raise ValidationError("Play destination track does not match configured lifecycle stage")
        if stage == "external-testing" and receipt.get("sourceTrack") != "internal":
            raise ValidationError("External Play promotion must read from internal")
        if (
            stage == "external-testing"
            and platform_config.get("externalTrack", {}).get("kind") == "closed"
            and receipt.get("closedTesterAssignmentVerified") is not True
        ):
            raise ValidationError(
                "Closed Play promotion lacks an API-verified nonempty tester-group assignment"
            )
        if stage == "production-submit" and receipt.get("sourceTrack") != platform_config.get(
            "externalTrack", {}
        ).get("name"):
            raise ValidationError("Production Play draft must promote the configured external track")
        if stage == "production-submit":
            if receipt["releaseStatus"] != "draft":
                raise ValidationError("Play production preparation must remain draft")
            if receipt["state"] != "draft":
                raise ValidationError("Play production readback state must explicitly be draft")
        elif receipt["releaseStatus"] != "completed":
            raise ValidationError("Play testing releases must be completed on their testing track")
        elif receipt["state"] != "available-to-testers":
            raise ValidationError("Play testing readback must prove availability to testers")
    else:
        for field in ("appStoreAppId", "buildResourceId", "processingState"):
            if (
                not isinstance(receipt.get(field), str)
                or not receipt[field].strip()
                or len(receipt[field]) > 255
            ):
                raise ValidationError(f"Apple Store receipt is missing {field}")
        if str(receipt["appStoreAppId"]) != str(platform_config.get("appStoreAppId")):
            raise ValidationError("App Store app ID does not match configuration")
        if stage == "external-testing":
            if receipt.get("externalGroup") != platform_config.get("externalTestFlightGroup"):
                raise ValidationError("TestFlight external group does not match configuration")
            if (
                not isinstance(receipt.get("betaReviewState"), str)
                or not receipt["betaReviewState"].strip()
                or len(receipt["betaReviewState"]) > 255
            ):
                raise ValidationError("External TestFlight receipt lacks Beta Review readback")
        if stage == "production-submit":
            if receipt.get("automaticRelease") is not False:
                raise ValidationError("App Store production must set automaticRelease=false")
            if (
                not isinstance(receipt.get("submissionState"), str)
                or not receipt["submissionState"].strip()
                or len(receipt["submissionState"]) > 255
            ):
                raise ValidationError("App Store receipt lacks submission-state readback")
            if receipt["state"] not in {
                "submitted-for-review",
                "in-review",
                "approved",
                "pending-developer-release",
            }:
                raise ValidationError("App Store production readback state is not submission evidence")
        elif stage == "external-testing":
            if receipt["state"] not in {
                "available-to-testers",
                "submitted-for-review",
                "in-review",
                "approved",
            }:
                raise ValidationError(
                    "External TestFlight receipt lacks an allowed explicit review/testing state"
                )
        elif receipt["state"] not in {"processed", "available-to-testers"}:
            raise ValidationError("Internal TestFlight receipt lacks explicit processing state")
    return dict(receipt)


ARTIFACT_TYPES = {
    "android-aab": ("android", "aab"),
    "android-apk": ("android", "apk"),
    "android-mapping": ("android", "r8-mapping"),
    "android-native-symbols": ("android", "native-symbols"),
    "ios-ipa": ("ios", "ipa"),
    "ios-archive": ("ios", "xcarchive"),
    "ios-dsyms": ("ios", "dsym"),
    "store-metadata": ("shared", "metadata"),
    "validation-report": ("shared", "validation-report"),
}


def _artifact_architectures(name: str, path: Path) -> list[str]:
    if name == "android-aab":
        try:
            with zipfile.ZipFile(path) as archive:
                return sorted(
                    {
                        parts[2]
                        for item in archive.namelist()
                        if (parts := item.split("/"))[:2] == ["base", "lib"] and len(parts) > 3
                    }
                )
        except zipfile.BadZipFile:
            return []
    return []


def artifact_records(artifacts: Iterable[tuple[str, Path]]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    seen: set[str] = set()
    for name, path in artifacts:
        if name in seen:
            raise ValidationError(f"duplicate artifact name: {name}")
        seen.add(name)
        if path.is_symlink() or not path.is_file():
            raise ValidationError(f"artifact must be a regular non-symlink file: {name}")
        if name not in ARTIFACT_TYPES:
            raise ValidationError(f"unsupported artifact logical name: {name}")
        if path.stat().st_size < 1:
            raise ValidationError(f"artifact is empty: {name}")
        platform, kind = ARTIFACT_TYPES[name]
        records.append(
            {
                "logicalName": name,
                "platform": platform,
                "kind": kind,
                "fileName": path.name,
                "size": path.stat().st_size,
                "sha256": sha256_file(path),
                "architectures": _artifact_architectures(name, path),
            }
        )
    return sorted(records, key=lambda item: item["logicalName"])


def _workflow_run(stage: str) -> dict[str, Any]:
    names = {
        "candidate": "mobile-candidate",
        "external-testing": "mobile-external-testing",
        "production-submit": "mobile-production-submit",
    }
    workflow = os.environ.get("GITHUB_WORKFLOW")
    run_id = os.environ.get("GITHUB_RUN_ID")
    attempt_text = os.environ.get("GITHUB_RUN_ATTEMPT")
    if not workflow or len(workflow) > 255:
        raise ValidationError(f"{names[stage]} evidence requires GITHUB_WORKFLOW")
    if not run_id or not re.fullmatch(r"[1-9][0-9]*", run_id):
        raise ValidationError(f"{names[stage]} evidence requires a positive GITHUB_RUN_ID")
    if not attempt_text or not re.fullmatch(r"[1-9][0-9]*", attempt_text):
        raise ValidationError(f"{names[stage]} evidence requires a positive GITHUB_RUN_ATTEMPT")
    return {"workflow": workflow, "runId": run_id, "attempt": int(attempt_text, 10)}


def _tooling() -> dict[str, str]:
    commit = os.environ.get("MOBILE_RELEASE_TOOLING_SHA") or os.environ.get(
        "MOBILE_RELEASE_TOOLING_COMMIT"
    )
    if not commit or not re.fullmatch(r"[0-9A-Fa-f]{40}", commit):
        raise ValidationError("MOBILE_RELEASE_TOOLING_SHA must be an immutable full Git commit")
    return {"version": __version__, "commit": commit.lower()}


def _repository(git: GitContext) -> dict[str, str]:
    if (
        not git.repository
        or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", git.repository)
        or not git.repository_id
        or not re.fullmatch(r"[1-9][0-9]*", git.repository_id)
    ):
        raise ValidationError("candidate evidence requires GitHub repository full name and numeric ID")
    return {"fullName": git.repository, "id": git.repository_id}


def _source(git: GitContext, *, include_ref: bool) -> dict[str, str]:
    object_id = r"[0-9A-Fa-f]{40}"
    if (
        not git.commit
        or not re.fullmatch(object_id, git.commit)
        or not git.tree
        or not re.fullmatch(object_id, git.tree)
    ):
        raise ValidationError("candidate evidence requires immutable source commit and tree")
    result = {"commit": git.commit, "tree": git.tree}
    if include_ref:
        if not git.ref or len(git.ref) > 512:
            raise ValidationError("candidate evidence requires the actual dispatch ref")
        result["ref"] = git.ref
    return result


def validate_evidence_context(git: GitContext, *, stage: str) -> None:
    """Validate all Store-independent evidence context before any mutation."""

    if stage not in {"candidate", "external-testing", "production-submit"}:
        raise ValidationError(f"unsupported evidence stage: {stage}")
    _tooling()
    _repository(git)
    _source(git, include_ref=stage == "candidate")
    _workflow_run(stage)


def _normalized_manifest_store_receipt(
    raw: Mapping[str, Any], *, platform: str, release: ReleaseVersion
) -> dict[str, Any]:
    if platform == "android":
        provider = "google-play"
        store_build_id = str(raw["versionCode"])
    else:
        provider = "app-store-connect"
        store_build_id = str(raw["buildResourceId"])
    state = raw.get("state")
    if state not in {"uploaded", "processed", "available-to-testers"}:
        raise ValidationError("candidate Store readback lacks an allowed explicit state")
    return {
        "provider": provider,
        "applicationId": raw["appIdentity"],
        "storeBuildId": store_build_id,
        "marketingVersion": release.name,
        "build": release.build,
        "channel": raw.get("destinationTrack", "testflight-internal"),
        "state": state,
        "observedAt": raw["observedAt"],
    }


def _signing_identity(
    config: ReleaseConfig, platform: str, supplied: Mapping[str, Any] | None
) -> dict[str, Any]:
    section = config.section(platform)
    if platform == "android":
        return {
            "platform": "android",
            "kind": "android-upload",
            "certificateSha256": section["uploadCertificateSha256"].replace(":", "").lower(),
        }
    if supplied is None:
        raise ValidationError(
            "iOS evidence requires public signer/profile fields extracted from the final IPA"
        )
    expected = section["distributionCertificateSha256"].replace(":", "").lower()
    if supplied.get("certificateSha256") != expected or supplied.get("teamId") != section["teamId"]:
        raise ValidationError("extracted iOS signing evidence does not match approved configuration")
    return dict(supplied)


def build_candidate_manifest(
    *,
    config: ReleaseConfig,
    release: ReleaseVersion,
    git: GitContext,
    platform: str,
    artifacts: list[dict[str, Any]],
    store_receipt: Mapping[str, Any] | None,
    metadata_sha256: str,
    signing_evidence: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    platform_config = config.section(platform)
    identity_key = "applicationId" if platform == "android" else "bundleId"
    if store_receipt is None:
        raise ValidationError("candidate manifest requires authoritative internal Store readback")
    platform_identity: dict[str, str] = {"applicationId": platform_config[identity_key]}
    if platform == "ios":
        platform_identity["storeAppId"] = str(platform_config["appStoreAppId"])
    try:
        config_relative = config.path.relative_to(config.root).as_posix()
    except ValueError as error:
        raise ValidationError("configuration file must live in the caller repository") from error
    if config_relative != "release/mobile-release.json":
        raise ValidationError("CI evidence requires configuration at release/mobile-release.json")
    payload: dict[str, Any] = {
        "schemaVersion": 1,
        "tooling": _tooling(),
        "repository": _repository(git),
        "source": _source(git, include_ref=True),
        "configuration": {
            "path": config_relative,
            "sha256": sha256_file(config.path),
            "metadataSha256": metadata_sha256,
        },
        "version": {"marketing": release.name, "build": release.build},
        "platforms": {platform: platform_identity},
        "artifacts": artifacts,
        "signing": [_signing_identity(config, platform, signing_evidence)],
        "storeReceipts": [
            _normalized_manifest_store_receipt(store_receipt, platform=platform, release=release)
        ],
        "createdBy": _workflow_run("candidate"),
        "createdAt": timestamp(),
    }
    return seal(payload)


def build_receipt(
    *,
    stage: str,
    platform: str,
    candidate_manifest: Mapping[str, Any],
    store_receipt: Mapping[str, Any],
    external_receipt: Mapping[str, Any] | None = None,
    previous_receipt: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    candidate_payload = verify_sealed(candidate_manifest)
    if platform not in candidate_payload.get("platforms", {}):
        raise ValidationError("candidate manifest does not include the receipt platform")
    provider = "google-play" if platform == "android" else "app-store-connect"
    application_id = candidate_payload["platforms"][platform]["applicationId"]
    store_build_id = str(
        store_receipt["versionCode"]
        if platform == "android"
        else store_receipt["buildResourceId"]
    )
    operations = {
        ("candidate", "android"): "uploaded",
        ("candidate", "ios"): "uploaded",
        ("external-testing", "android"): "promoted",
        ("external-testing", "ios"): "distributed",
        ("production-submit", "android"): "promoted",
        ("production-submit", "ios"): "submitted",
    }
    if platform == "android":
        destination: dict[str, Any] = {
            "channel": store_receipt["destinationTrack"],
            "releaseStatus": store_receipt["releaseStatus"],
        }
        if stage == "external-testing" and store_receipt.get(
            "closedTesterAssignmentVerified"
        ) is True:
            destination["closedTesterAssignmentVerified"] = True
    else:
        channel = {
            "candidate": "testflight-internal",
            "external-testing": "testflight-external",
            "production-submit": "app-store-review",
        }[stage]
        destination = {"channel": channel}
        if stage == "production-submit":
            destination["automaticRelease"] = False
    state = store_receipt.get("state")
    allowed_states = {
        "uploaded",
        "processed",
        "available-to-testers",
        "submitted-for-review",
        "in-review",
        "approved",
        "pending-developer-release",
        "draft",
    }
    if state not in allowed_states:
        raise ValidationError("Store readback lacks an allowed explicit state")
    outcome = {
        "accepted": "mutated",
        "reconciled": "reconciled",
        "already_present": "already-present",
    }[store_receipt["result"]]
    payload: dict[str, Any] = {
        "schemaVersion": 2,
        "stage": stage,
        "candidateManifestSha256": candidate_manifest["integrity"]["sha256"],
        "tooling": candidate_payload["tooling"],
        "repository": candidate_payload["repository"],
        "source": {
            "commit": candidate_payload["source"]["commit"],
            "tree": candidate_payload["source"]["tree"],
        },
        "platform": platform,
        "provider": provider,
        "applicationId": application_id,
        "version": candidate_payload["version"],
        "storeBuildId": store_build_id,
        "operation": operations[(stage, platform)],
        "outcome": outcome,
        "destination": destination,
        "readback": {"state": state, "observedAt": store_receipt["observedAt"]},
        "createdBy": _workflow_run(stage),
        "createdAt": timestamp(),
    }
    if platform == "android":
        payload["storeState"] = dict(store_receipt["storeState"])
    predecessor = previous_receipt or external_receipt
    if stage != "candidate":
        if predecessor is None:
            raise ValidationError(f"{stage} receipt requires its immediate predecessor receipt")
        verify_sealed(predecessor)
        payload["previousReceiptSha256"] = predecessor["integrity"]["sha256"]
    return seal(payload)


def validate_receipt_chain(
    *,
    candidate_manifest: Mapping[str, Any],
    candidate_receipt: Mapping[str, Any] | None = None,
    external_receipt: Mapping[str, Any] | None = None,
    production_receipt: Mapping[str, Any] | None = None,
    platform: str,
    config: ReleaseConfig | None = None,
    require_production_eligible_external: bool = False,
) -> None:
    validate_evidence_document(candidate_manifest)
    for receipt_document in (candidate_receipt, external_receipt, production_receipt):
        if receipt_document is not None:
            validate_evidence_document(receipt_document)
    candidate = verify_sealed(candidate_manifest)
    if platform not in candidate.get("platforms", {}):
        raise ValidationError("candidate evidence platform does not match requested platform")
    candidate_hash = candidate_manifest["integrity"]["sha256"]

    def require_candidate_binding(receipt: Mapping[str, Any]) -> None:
        store_receipts = candidate.get("storeReceipts", [])
        if len(store_receipts) != 1:
            raise ValidationError("candidate Store receipt cardinality is invalid")
        store = store_receipts[0]
        identity = candidate["platforms"][platform]["applicationId"]
        expected = {
            "candidateManifestSha256": candidate_hash,
            "tooling": candidate["tooling"],
            "repository": candidate["repository"],
            "source": {
                "commit": candidate["source"]["commit"],
                "tree": candidate["source"]["tree"],
            },
            "applicationId": identity,
            "version": candidate["version"],
            "storeBuildId": store["storeBuildId"],
            "provider": store["provider"],
        }
        for field, value in expected.items():
            if receipt.get(field) != value:
                raise ValidationError(f"receipt {field} is not bound to the candidate")

    if candidate_receipt is not None:
        receipt = verify_sealed(candidate_receipt)
        if receipt.get("stage") != "candidate" or receipt.get("platform") != platform:
            raise ValidationError("candidate receipt stage/platform mismatch")
        if receipt.get("candidateManifestSha256") != candidate_hash:
            raise ValidationError("candidate receipt is not bound to the supplied manifest")
        require_candidate_binding(receipt)
    if external_receipt is not None:
        if candidate_receipt is None:
            raise ValidationError("external receipt requires the candidate receipt")
        receipt = verify_sealed(external_receipt)
        if receipt.get("stage") != "external-testing" or receipt.get("platform") != platform:
            raise ValidationError("external receipt stage/platform mismatch")
        if receipt.get("candidateManifestSha256") != candidate_hash:
            raise ValidationError("external receipt is not bound to the supplied manifest")
        require_candidate_binding(receipt)
        if candidate_receipt is not None and receipt.get("previousReceiptSha256") != candidate_receipt[
            "integrity"
        ]["sha256"]:
            raise ValidationError("external receipt is not bound to the candidate receipt")
        if (
            config is not None
            and platform == "android"
            and config.section("android").get("externalTrack", {}).get("kind") == "closed"
            and receipt.get("destination", {}).get("closedTesterAssignmentVerified") is not True
        ):
            raise ValidationError(
                "external receipt lacks closed Play tester-assignment verification"
            )
        if (
            platform == "ios"
            and (production_receipt is not None or require_production_eligible_external)
            and receipt.get("readback", {}).get("state") != "available-to-testers"
        ):
            raise ValidationError(
                "iOS production requires an external receipt whose readback.state is "
                "available-to-testers; rerun external-testing after Beta Review approval"
            )
        if (
            platform == "android"
            and (production_receipt is not None or require_production_eligible_external)
            and receipt.get("outcome") not in {"mutated", "reconciled"}
        ):
            raise ValidationError(
                "Android production requires an external receipt produced by a confirmed "
                "promotion; an observation-only already-present receipt is not authorization"
            )
    if production_receipt is not None:
        if candidate_receipt is None or external_receipt is None:
            raise ValidationError(
                "production receipt requires candidate and external predecessor receipts"
            )
        receipt = verify_sealed(production_receipt)
        if receipt.get("stage") != "production-submit" or receipt.get("platform") != platform:
            raise ValidationError("production receipt stage/platform mismatch")
        if receipt.get("candidateManifestSha256") != candidate_hash:
            raise ValidationError("production receipt is not bound to the supplied manifest")
        require_candidate_binding(receipt)
        if receipt.get("previousReceiptSha256") != external_receipt["integrity"]["sha256"]:
            raise ValidationError("production receipt is not bound to the external receipt")
