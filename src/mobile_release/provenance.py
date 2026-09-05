from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import shutil
import tempfile
import zipfile
from base64 import b64decode
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

from . import __version__
from .config import ReleaseConfig, ReleaseVersion
from .discovery import GitContext
from .errors import ValidationError
from .metadata import android_release_notes, validate_android_release_note

HEX_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SENSITIVE_KEY_RE = re.compile(r"(?i)(password|private.?key|secret|token|credential|keystore.?base64)")
SENSITIVE_VALUE_RE = re.compile(r"-----BEGIN (?:[A-Z ]*PRIVATE KEY|CERTIFICATE)-----")

EVIDENCE_TYPES = {
    "candidate-manifest",
    "store-operation-intent",
    "store-receipt",
}
WORKFLOW_PATHS = {
    "candidate": ("mobile-candidate.yml", "reusable-candidate.yml"),
    "external-testing": ("mobile-external-testing.yml", "reusable-external-testing.yml"),
    "production-submit": ("mobile-production-submit.yml", "reusable-production-submit.yml"),
}


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
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (ValueError, UnicodeEncodeError, RecursionError) as error:
        raise ValidationError("canonical evidence contains an invalid JSON value") from error


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _validate_json_value(value: Any, path: str = "$", *, depth: int = 0) -> None:
    if depth > 64:
        raise ValidationError("canonical evidence exceeds the nesting limit")
    if isinstance(value, str):
        try:
            value.encode("utf-8")
        except UnicodeEncodeError as error:
            raise ValidationError("canonical evidence contains invalid Unicode") from error
        if SENSITIVE_VALUE_RE.search(value):
            raise ValidationError(f"private material is forbidden in release evidence: {path}")
        return
    if value is None or isinstance(value, (bool, int)):
        return
    if isinstance(value, float):
        raise ValidationError(f"floating-point values are forbidden in canonical evidence: {path}")
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_json_value(item, f"{path}[{index}]", depth=depth + 1)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValidationError(f"non-string JSON key in evidence: {path}")
            if SENSITIVE_KEY_RE.search(key):
                raise ValidationError(f"sensitive field is forbidden in release evidence: {path}.{key}")
            if isinstance(item, str) and SENSITIVE_VALUE_RE.search(item):
                raise ValidationError(f"private material is forbidden in release evidence: {path}.{key}")
            _validate_json_value(item, f"{path}.{key}", depth=depth + 1)
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


def validate_immutable_copy(source: Path, destination: Path) -> None:
    """Check both paths and any existing exact copy without changing directories."""
    source = source.expanduser().absolute()
    destination = destination.expanduser().absolute()
    if _evidence_path_has_symlink(source) or not source.is_file():
        raise ValidationError("immutable copy source must be a regular non-symlink file")
    if _evidence_path_has_symlink(destination):
        raise ValidationError("immutable copy destination must not traverse a symbolic link")

    if destination.exists():
        if (
            _evidence_path_has_symlink(destination)
            or not destination.is_file()
            or destination.stat().st_size != source.stat().st_size
            or sha256_file(destination) != sha256_file(source)
        ):
            raise ValidationError("existing immutable file conflicts with the original bytes")
    else:
        validate_evidence_output_path(destination)


def copy_immutable_file(source: Path, destination: Path) -> None:
    """Publish exact bytes atomically, or verify an existing immutable copy.

    In particular, an interrupted metadata/intent copy must never leave a
    truncated final pathname that makes an otherwise recoverable upload unusable.
    A collision is accepted only after byte-identity verification; no unlink or
    replacement of an existing evidence file is permitted.
    """

    source = source.expanduser().absolute()
    destination = destination.expanduser().absolute()
    validate_immutable_copy(source, destination)
    if destination.exists():
        return
    destination = validate_evidence_output_path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination = validate_evidence_output_path(destination)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{destination.name}.", dir=destination.parent)
    try:
        with os.fdopen(descriptor, "wb") as output, source.open("rb") as original:
            shutil.copyfileobj(original, output, length=1024 * 1024)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary, 0o600)
        try:
            os.link(temporary, destination, follow_symlinks=False)
        except FileExistsError:
            validate_immutable_copy(source, destination)
        except OSError as error:
            raise ValidationError("immutable file could not be published atomically") from error
    finally:
        os.unlink(temporary)


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
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError) as error:
        raise ValidationError(f"release evidence is not valid UTF-8 JSON: {path}") from error
    if not isinstance(value, dict):
        raise ValidationError("release evidence must contain a JSON object")
    validate_evidence_document(value)
    return value


def _load_json_object(path: Path, *, label: str, maximum_size: int) -> dict[str, Any]:
    """Load one bounded, non-symlink JSON object with duplicate-key rejection."""

    path = path.expanduser().absolute()
    if _evidence_path_has_symlink(path) or not path.is_file():
        raise ValidationError(f"{label} must be a regular non-symlink file: {path}")
    if path.stat().st_size > maximum_size:
        raise ValidationError(f"{label} is unexpectedly large: {path}")
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicate_pairs
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError) as error:
        raise ValidationError(f"{label} is not valid UTF-8 JSON: {path}") from error
    if not isinstance(value, dict):
        raise ValidationError(f"{label} must contain a JSON object")
    _validate_json_value(value)
    return value


def load_operation_intent(path: Path) -> dict[str, Any]:
    value = _load_json_object(
        path, label="Store operation intent", maximum_size=2 * 1024 * 1024
    )
    validate_operation_intent(value)
    return value


def load_candidate_manifest(path: Path) -> dict[str, Any]:
    value = load_evidence(path)
    if value["documentType"] != "candidate-manifest":
        raise ValidationError("candidate manifest path does not contain a candidate-manifest")
    return value


def load_release_receipt(path: Path) -> dict[str, Any]:
    value = load_evidence(path)
    if value["documentType"] != "store-receipt":
        raise ValidationError("release receipt path does not contain a store-receipt")
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


def _validate_workflow_authority(value: object, label: str) -> dict[str, Any]:
    authority = _exact_keys(
        value,
        {
            "workflow",
            "callerPath",
            "reusableRepository",
            "reusablePath",
            "reusableCommit",
            "runId",
            "attempt",
            "headSha",
            "ref",
            "event",
        },
        label,
    )
    bounded = ("workflow", "callerPath", "reusableRepository", "reusablePath", "ref")
    if any(
        not isinstance(authority[field], str)
        or not authority[field]
        or len(authority[field]) > (255 if field == "workflow" else 512)
        or any(ord(character) < 32 for character in authority[field])
        for field in bounded
    ):
        raise ValidationError(f"{label} contains an invalid workflow identity")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", authority["reusableRepository"]):
        raise ValidationError(f"{label}.reusableRepository is invalid")
    if any(not re.fullmatch(r"\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml", authority[field])
           for field in ("callerPath", "reusablePath")):
        raise ValidationError(f"{label} workflow paths must be repository workflow paths")
    if not isinstance(authority["reusableCommit"], str) or not re.fullmatch(r"[0-9a-f]{40}", authority["reusableCommit"]):
        raise ValidationError(f"{label}.reusableCommit must be a full Git object ID")
    if not isinstance(authority["headSha"], str) or not re.fullmatch(r"[0-9a-f]{40}", authority["headSha"]):
        raise ValidationError(f"{label}.headSha must be a full Git object ID")
    if not authority["ref"].startswith("refs/heads/") or len(authority["ref"]) <= len("refs/heads/"):
        raise ValidationError(f"{label}.ref must be a branch ref")
    if not isinstance(authority["runId"], str) or not re.fullmatch(
        r"[1-9][0-9]*", authority["runId"]
    ):
        raise ValidationError(f"{label}.runId must be a positive integer string")
    if (
        isinstance(authority["attempt"], bool)
        or not isinstance(authority["attempt"], int)
        or authority["attempt"] < 1
    ):
        raise ValidationError(f"{label}.attempt must be a positive integer")
    if authority["event"] != "workflow_dispatch":
        raise ValidationError(f"{label}.event must be workflow_dispatch")
    return authority


def _authority_for_stage(value: object, stage: str, label: str) -> dict[str, Any]:
    authority = _validate_workflow_authority(value, label)
    caller, reusable = WORKFLOW_PATHS[stage]
    if authority["callerPath"] != f".github/workflows/{caller}" or authority["reusablePath"] != f".github/workflows/{reusable}":
        raise ValidationError(f"{label} workflow paths do not match the release stage")
    return authority


def _same_workflow(authority: Mapping[str, Any], other: Mapping[str, Any], label: str) -> None:
    for field in ("workflow", "callerPath", "reusableRepository", "reusablePath", "reusableCommit", "ref", "event"):
        if authority[field] != other[field]:
            raise ValidationError(f"{label} workflow authority differs: {field}")
    if authority["runId"] == other["runId"] and authority["headSha"] != other["headSha"]:
        raise ValidationError(f"{label} run head differs from the immutable dispatch")


def _validate_evidence_authorities(value: Mapping[str, Any], stage: str) -> None:
    authorized = _authority_for_stage(value["authorizedBy"], stage, "evidence.authorizedBy")
    executed = _authority_for_stage(value["executedBy"], stage, "evidence.executedBy")
    produced = _authority_for_stage(value["producedBy"], stage, "evidence.producedBy")
    _same_workflow(authorized, executed, "Store executor")
    _same_workflow(authorized, produced, "evidence producer")
    if authorized["reusableCommit"] != value["tooling"]["commit"]:
        raise ValidationError("evidence workflow/tooling commits differ")
    if executed["runId"] == authorized["runId"] and executed["attempt"] < authorized["attempt"]:
        raise ValidationError("Store execution predates operation authorization")
    if produced["runId"] == executed["runId"]:
        if produced["attempt"] < executed["attempt"]:
            raise ValidationError("evidence production predates Store execution")
    elif executed["runId"] != authorized["runId"] or produced["runId"] == authorized["runId"]:
        raise ValidationError("evidence cannot reuse an unrelated recovery run's raw receipt")


def _validate_source_identity(value: object, label: str, *, include_ref: bool) -> dict[str, Any]:
    keys = {"commit", "tree", "ref"} if include_ref else {"commit", "tree"}
    source = _exact_keys(value, keys, label)
    for field in ("commit", "tree"):
        if not isinstance(source[field], str) or not re.fullmatch(
            r"[0-9A-Fa-f]{40}", source[field]
        ):
            raise ValidationError(f"{label}.{field} must be a full Git object ID")
    if include_ref and (
        not isinstance(source["ref"], str)
        or not source["ref"].startswith("refs/heads/")
        or len(source["ref"]) > 512
    ):
        raise ValidationError(f"{label}.ref must be a branch ref")
    return source


def _bounded_text(value: object, label: str, *, maximum: int = 255, empty: bool = False) -> str:
    if not isinstance(value, str) or len(value.encode("utf-8")) > maximum or (not empty and not value) or "\x00" in value:
        raise ValidationError(f"{label} must be bounded text")
    return value


def _nullable_id(value: object, label: str) -> None:
    if value is not None:
        _bounded_text(value, label)


def _array(value: object, label: str, maximum: int) -> list[Any]:
    if not isinstance(value, list) or len(value) > maximum:
        raise ValidationError(f"{label} must be a bounded array")
    return value


def _unique_records(values: list[Any], field: str, label: str) -> None:
    keys = [value[field] for value in values]
    if len(keys) != len(set(keys)):
        raise ValidationError(f"{label} contains duplicate {field}")


def _validate_play_release(value: object) -> dict[str, Any]:
    required = {"versionCodes", "status"}
    allowed = required | {"name", "releaseNotes", "userFraction", "inAppUpdatePriority", "countryTargeting"}
    if not isinstance(value, dict) or not required <= set(value) or set(value) - allowed:
        raise ValidationError("Play release contains missing or unknown fields")
    if not isinstance(value["status"], str) or value["status"] not in {"draft", "inProgress", "halted", "completed"}:
        raise ValidationError("Play release status is unsupported")
    codes = _array(value["versionCodes"], "Play release versionCodes", 10_000)
    if not codes or any(not isinstance(code, str) or not re.fullmatch(r"[1-9][0-9]{0,9}", code) or int(code) > 2_100_000_000 for code in codes):
        raise ValidationError("Play release versionCodes are invalid")
    if codes != sorted(set(codes)):
        raise ValidationError("Play release versionCodes must be unique and canonical")
    if "name" in value and value["name"] is not None:
        _bounded_text(value["name"], "Play release name", maximum=512, empty=True)
    if "userFraction" in value and value["userFraction"] is not None:
        # The API uses a number; the cross-language evidence uses exact decimal
        # text, avoiding differing Ruby/Python float serialization.
        fraction = value["userFraction"]
        if not isinstance(fraction, str) or not re.fullmatch(r"0\.[0-9]{0,323}[1-9]", fraction):
            raise ValidationError("Play release userFraction must be a canonical decimal between zero and one")
    if "inAppUpdatePriority" in value and value["inAppUpdatePriority"] is not None:
        priority = value["inAppUpdatePriority"]
        if type(priority) is not int or not 0 <= priority <= 5:
            raise ValidationError("Play release inAppUpdatePriority is invalid")
    if "releaseNotes" in value and value["releaseNotes"] is not None:
        notes = _array(value["releaseNotes"], "Play release notes", 250)
        for note in notes:
            note = _exact_keys(note, {"language", "text"}, "Play release note")
            _bounded_text(note["language"], "Play release note language", maximum=35)
            _bounded_text(note["text"], "Play release note text", maximum=64 * 1024, empty=True)
        _unique_records(notes, "language", "Play release notes")
        if notes != sorted(notes, key=canonical_json_bytes):
            raise ValidationError("Play release notes are not canonical")
    if "countryTargeting" in value and value["countryTargeting"] is not None:
        targeting = value["countryTargeting"]
        if not isinstance(targeting, dict) or not set(targeting) <= {"countries", "includeRestOfWorld"}:
            raise ValidationError("Play country targeting contains unknown fields")
        countries = _array(targeting.get("countries", []), "Play targeting countries", 300)
        if any(not isinstance(country, str) or not re.fullmatch(r"[A-Z]{2}", country) for country in countries) or countries != sorted(set(countries)):
            raise ValidationError("Play targeting countries must be canonical country codes")
        if "includeRestOfWorld" in targeting and type(targeting["includeRestOfWorld"]) is not bool:
            raise ValidationError("Play country targeting includeRestOfWorld must be boolean")
    return value


def _validate_play_track(value: object, track: str) -> dict[str, Any]:
    state = _exact_keys(value, {"canonicalization", "track", "releases"}, "Play track state")
    if state["canonicalization"] != "mrk-play-track-state-v2" or state["track"] != track:
        raise ValidationError("Play snapshot track identity/canonicalization is invalid")
    releases = _array(state["releases"], "Play track releases", 10_000)
    for release in releases:
        _validate_play_release(release)
    if releases != sorted(releases, key=canonical_json_bytes):
        raise ValidationError("Play track releases are not canonical")
    all_codes = [code for release in releases for code in release["versionCodes"]]
    if len(all_codes) != len(set(all_codes)):
        raise ValidationError("Play track contains ambiguous duplicate version codes")
    return state


def _validate_play_metadata(value: object, *, observed: bool) -> dict[str, Any]:
    keys = {"listings", "images"} | ({"observedImageIds"} if observed else set())
    metadata = _exact_keys(value, keys, "Play metadata state")
    listings = _array(metadata["listings"], "Play metadata listings", 250)
    for listing in listings:
        _exact_keys(listing, {"language", "title", "shortDescription", "fullDescription", "video"}, "Play listing")
        for field, text in listing.items():
            _bounded_text(text, f"Play listing {field}", maximum=64 * 1024, empty=field != "language")
    _unique_records(listings, "language", "Play listings")
    images = _array(metadata["images"], "Play metadata images", 500)
    image_keys = []
    for image in images:
        _exact_keys(image, {"language", "type", "order", "sha256", "size"}, "Play image")
        _bounded_text(image["language"], "Play image language", maximum=35)
        if not isinstance(image["type"], str) or image["type"] not in {"icon", "featureGraphic", "promoGraphic", "tvBanner", "phoneScreenshots", "sevenInchScreenshots", "tenInchScreenshots", "tvScreenshots", "wearScreenshots"}:
            raise ValidationError("Play image type is unsupported")
        if type(image["order"]) is not int or not 0 <= image["order"] < 50 or type(image["size"]) is not int or not 1 <= image["size"] <= 10 * 1024 * 1024:
            raise ValidationError("Play image size/order is invalid")
        if not isinstance(image["sha256"], str) or not HEX_SHA256_RE.fullmatch(image["sha256"]):
            raise ValidationError("Play image SHA-256 is invalid")
        image_keys.append((image["language"], image["type"], image["order"]))
    if len(image_keys) != len(set(image_keys)):
        raise ValidationError("Play image order is ambiguous")
    if observed:
        ids = _array(metadata["observedImageIds"], "Play observed image IDs", 500)
        id_keys = []
        for item in ids:
            _exact_keys(item, {"language", "type", "order", "id"}, "Play observed image ID")
            _bounded_text(item["id"], "Play image ID")
            id_keys.append((item["language"], item["type"], item["order"]))
        if id_keys != image_keys:
            raise ValidationError("Play observed image identity/order differs from content inventory")
    return metadata


def _validate_apple_build(value: object, *, app_id: str, version: str, build: int) -> dict[str, Any]:
    record = _exact_keys(value, {"id", "appId", "marketingVersion", "buildNumber", "processingState", "uploadedDate", "expirationDate", "expired", "usesNonExemptEncryption", "autoNotifyEnabled"}, "Apple candidate build")
    _bounded_text(record["id"], "Apple build resource ID")
    if record["appId"] != app_id or record["marketingVersion"] != version or record["buildNumber"] != str(build):
        raise ValidationError("Apple snapshot build is not the exact application/version/build")
    if record["processingState"] != "VALID" or record["expired"] is not False:
        raise ValidationError("Apple promotion intent requires a valid non-expired candidate")
    for name in ("uploadedDate", "expirationDate"):
        # The API SDK returns second-precision UTC in normalized snapshots.
        _validate_timestamp(record[name], f"Apple build {name}")
    if record["expirationDate"] <= record["uploadedDate"]:
        raise ValidationError("Apple build expiration must follow upload")
    for name in ("usesNonExemptEncryption", "autoNotifyEnabled"):
        if record[name] is not None and type(record[name]) is not bool:
            raise ValidationError(f"Apple build {name} must be boolean or null")
    return record


def _validate_apple_external(value: object) -> dict[str, Any]:
    state = _exact_keys(value, {"groupId", "groupName", "reviewDetailId", "assigned", "externalState", "betaReviewState", "usesNonExemptEncryption", "autoNotifyEnabled", "localizations", "targetLocalizations", "whatToTestSha256"}, "Apple external snapshot")
    for name in ("groupId", "groupName", "reviewDetailId"):
        _bounded_text(state[name], f"Apple external {name}")
    if type(state["assigned"]) is not bool:
        raise ValidationError("Apple external assignment must be boolean")
    if not isinstance(state["externalState"], str) or state["externalState"] not in {"PROCESSING", "MISSING_EXPORT_COMPLIANCE", "READY_FOR_BETA_SUBMISSION", "IN_EXPORT_COMPLIANCE_REVIEW", "WAITING_FOR_BETA_REVIEW", "IN_BETA_REVIEW", "BETA_APPROVED", "READY_FOR_BETA_TESTING", "IN_BETA_TESTING"}:
        raise ValidationError("Apple external state is unsupported or rejected")
    if not isinstance(state["betaReviewState"], str) or state["betaReviewState"] not in {"NOT_SUBMITTED", "WAITING_FOR_REVIEW", "WAITING_FOR_BETA_REVIEW", "SUBMITTED", "IN_REVIEW", "IN_BETA_REVIEW", "BETA_APPROVED", "APPROVED"}:
        raise ValidationError("Apple beta review state is unsupported or rejected")
    for name in ("usesNonExemptEncryption", "autoNotifyEnabled"):
        if state[name] is not None and type(state[name]) is not bool:
            raise ValidationError(f"Apple external {name} must be boolean or null")
    if not isinstance(state["whatToTestSha256"], str) or not HEX_SHA256_RE.fullmatch(state["whatToTestSha256"]):
        raise ValidationError("Apple what-to-test digest is invalid")
    for name in ("localizations", "targetLocalizations"):
        values = _array(state[name], f"Apple beta {name}", 100)
        for record in values:
            keys = {"locale", "whatsNew"} | ({"id"} if name == "localizations" else set())
            _exact_keys(record, keys, "Apple beta localization")
            if "id" in record:
                _bounded_text(record["id"], "Apple beta localization ID")
            _bounded_text(record["locale"], "Apple beta locale", maximum=35)
            _bounded_text(record["whatsNew"], "Apple beta text", maximum=64 * 1024, empty=True)
        _unique_records(values, "locale", "Apple beta localizations")
        if name == "localizations":
            _unique_records(values, "id", "Apple beta localizations")
        if values != sorted(values, key=lambda item: item["locale"]):
            raise ValidationError("Apple beta localizations are not canonical")
    if not state["targetLocalizations"] or not {item["locale"] for item in state["localizations"]} <= {item["locale"] for item in state["targetLocalizations"]}:
        raise ValidationError("Apple beta targets cannot remove an existing localization")
    return state


APPLE_VERSION_TEXT = {"description", "keywords", "marketingUrl", "promotionalText", "supportUrl", "whatsNew"}
APPLE_INFO_TEXT = {"name", "subtitle", "privacyPolicyUrl", "privacyPolicyText", "privacyChoicesUrl"}
APPLE_CATEGORIES = {"primaryCategory", "primarySubcategoryOne", "primarySubcategoryTwo", "secondaryCategory", "secondarySubcategoryOne", "secondarySubcategoryTwo"}
APPLE_LIVE_STATES = {"READY_FOR_SALE", "READY_FOR_DISTRIBUTION"}
APPLE_HISTORICAL_STATES = {"REPLACED_WITH_NEW_VERSION", "REPLACED_WITH_NEW_INFO", "REMOVED_FROM_SALE", "DEVELOPER_REMOVED_FROM_SALE"}
APPLE_VERSION_STATES = {"PREPARE_FOR_SUBMISSION", "READY_FOR_REVIEW", "WAITING_FOR_REVIEW", "IN_REVIEW", "ACCEPTED", "PENDING_DEVELOPER_RELEASE"}


def _validate_apple_localizations(value: object, *, info: bool, observed: bool) -> list[Any]:
    records = _array(value, "Apple production localizations", 100)
    fields = APPLE_INFO_TEXT if info else APPLE_VERSION_TEXT
    for record in records:
        required = {"locale"} | fields | ({"id"} if observed else set())
        if observed and not info:
            required.add("screenshotSets")
        _exact_keys(record, required, "Apple production localization")
        _bounded_text(record["locale"], "Apple production locale", maximum=35)
        if observed:
            _bounded_text(record["id"], "Apple localization ID")
        for field in fields:
            _bounded_text(record[field], f"Apple localization {field}", maximum=64 * 1024, empty=True)
        if info and not observed and not record["name"]:
            raise ValidationError("AppInfo localization target requires an approved name")
        if observed and not info:
            sets = _array(record["screenshotSets"], "Apple screenshot sets", 100)
            for item in sets:
                _exact_keys(item, {"id", "displayType", "screenshots"}, "Apple screenshot set")
                _bounded_text(item["id"], "Apple screenshot set ID")
                _bounded_text(item["displayType"], "Apple screenshot displayType", maximum=100)
                shots = _array(item["screenshots"], "Apple screenshots", 10)
                for order, shot in enumerate(shots):
                    _exact_keys(shot, {"id", "order", "fileName", "fileSize", "sourceFileChecksum", "deliveryState"}, "Apple screenshot")
                    _bounded_text(shot["id"], "Apple screenshot ID")
                    _bounded_text(shot["fileName"], "Apple screenshot filename", maximum=512)
                    if type(shot["order"]) is not int or shot["order"] != order or type(shot["fileSize"]) is not int or not 1 <= shot["fileSize"] <= 10 * 1024 * 1024:
                        raise ValidationError("Apple screenshot size/order is invalid")
                    if not isinstance(shot["sourceFileChecksum"], str) or not re.fullmatch(r"(?:[a-f0-9]{32})?", shot["sourceFileChecksum"]):
                        raise ValidationError("Apple screenshot checksum is invalid")
                    if not isinstance(shot["deliveryState"], str) or shot["deliveryState"] not in {"AWAITING_UPLOAD", "UPLOAD_COMPLETE", "COMPLETE", "FAILED"}:
                        raise ValidationError("Apple screenshot delivery state is unsupported")
                _unique_records(shots, "id", "Apple screenshots")
            _unique_records(sets, "id", "Apple screenshot sets")
            _unique_records(sets, "displayType", "Apple screenshot sets")
    _unique_records(records, "locale", "Apple localizations")
    if observed:
        _unique_records(records, "id", "Apple localizations")
    if records != sorted(records, key=lambda item: item["locale"]):
        raise ValidationError("Apple production localizations are not canonical")
    return records


def _validate_apple_categories(value: object) -> None:
    categories = _exact_keys(value, APPLE_CATEGORIES, "Apple categories")
    for name, identity in categories.items():
        _nullable_id(identity, f"Apple category {name}")


def _validate_apple_version(value: object, *, app_id: str, detailed: bool) -> dict[str, Any]:
    keys = {"id", "appId", "platform", "versionString", "state", "buildId", "releaseType", "earliestReleaseDate", "copyright"}
    if detailed:
        keys |= {"localizations", "privateDetailId", "phasedRelease"}
    version = _exact_keys(value, keys, "Apple App Store version")
    _bounded_text(version["id"], "Apple App Store version ID")
    _bounded_text(version["versionString"], "Apple App Store marketing version", maximum=64)
    if version["appId"] != app_id or version["platform"] != "IOS":
        raise ValidationError("Apple App Store version belongs to a different application/platform")
    if not isinstance(version["state"], str) or version["state"] not in APPLE_VERSION_STATES | APPLE_LIVE_STATES | APPLE_HISTORICAL_STATES:
        raise ValidationError("Apple App Store version state is unsupported")
    _nullable_id(version["buildId"], "Apple selected build ID")
    if not isinstance(version["releaseType"], str) or version["releaseType"] not in {"MANUAL", "AFTER_APPROVAL", "SCHEDULED"}:
        raise ValidationError("Apple version release mode is unsupported")
    for field in ("earliestReleaseDate", "copyright"):
        _bounded_text(version[field], f"Apple version {field}", maximum=64 * 1024, empty=True)
    if detailed:
        _validate_apple_localizations(version["localizations"], info=False, observed=True)
        _nullable_id(version["privateDetailId"], "Apple review detail ID")
        if version["phasedRelease"] is not None:
            phased = _exact_keys(version["phasedRelease"], {"id", "state"}, "Apple phased release")
            _bounded_text(phased["id"], "Apple phased release ID")
            if not isinstance(phased["state"], str) or phased["state"] not in {"INACTIVE", "ACTIVE", "PAUSED", "COMPLETE"}:
                raise ValidationError("Apple phased release state is unsupported")
    return version


def _validate_apple_app_info(value: object, *, app_id: str) -> dict[str, Any]:
    info = _exact_keys(value, {"id", "appId", "state", "categories", "localizations"}, "Apple AppInfo")
    _bounded_text(info["id"], "Apple AppInfo ID")
    if info["appId"] != app_id:
        raise ValidationError("Apple AppInfo belongs to a different application")
    if not isinstance(info["state"], str) or info["state"] not in APPLE_VERSION_STATES | APPLE_LIVE_STATES | APPLE_HISTORICAL_STATES | {"PENDING_RELEASE"}:
        raise ValidationError("Apple AppInfo state is unsupported")
    _validate_apple_categories(info["categories"])
    _validate_apple_localizations(info["localizations"], info=True, observed=True)
    return info


def _validate_apple_production_snapshot(snapshot: dict[str, Any], precondition: dict[str, Any]) -> None:
    app_id = snapshot["appStoreAppId"]
    version = precondition["marketingVersion"]
    for field in ("production", "liveReference"):
        if snapshot[field] is not None:
            record = _validate_apple_version(snapshot[field], app_id=app_id, detailed=True)
            if field == "production":
                if record["versionString"] != version or record["buildId"] != snapshot["build"]["id"] or record["releaseType"] != "MANUAL" or record["earliestReleaseDate"]:
                    raise ValidationError("existing intended App Store version must select the candidate and manual release")
            elif record["versionString"] == version or record["state"] not in APPLE_LIVE_STATES:
                raise ValidationError("Apple live reference must be a different exact live version")
    for field in ("appInfo", "appInfoReference"):
        if snapshot[field] is not None:
            info = _validate_apple_app_info(snapshot[field], app_id=app_id)
            if field == "appInfoReference" and info["state"] not in APPLE_LIVE_STATES:
                raise ValidationError("Apple AppInfo reference must be the exact live resource")
    if snapshot["appInfo"] and snapshot["appInfoReference"] and snapshot["appInfo"]["id"] == snapshot["appInfoReference"]["id"]:
        raise ValidationError("editable and live AppInfo identities must be distinct")
    unrelated = _array(snapshot["unrelatedVersions"], "Apple unrelated versions", 10_000)
    for record in unrelated:
        record = _validate_apple_version(record, app_id=app_id, detailed=False)
        if record["versionString"] == version or record["state"] not in APPLE_LIVE_STATES | APPLE_HISTORICAL_STATES:
            raise ValidationError("Apple unrelated version is active or aliases the intended version")
    _unique_records(unrelated, "id", "Apple unrelated versions")
    _unique_records(unrelated, "versionString", "Apple unrelated versions")
    live = [record for record in unrelated if record["state"] in APPLE_LIVE_STATES]
    reference = snapshot["liveReference"]
    if len(live) > 1 or (reference is None) != (not live) or (reference is not None and any(reference[key] != live[0][key] for key in live[0])):
        raise ValidationError("Apple inherited live reference is not bound to the complete version inventory")
    submissions = _array(snapshot["reviewSubmissions"], "Apple review submissions", 10_000)
    for submission in submissions:
        _exact_keys(submission, {"id", "state", "platform", "items"}, "Apple review submission")
        _bounded_text(submission["id"], "Apple review submission ID")
        if not isinstance(submission["platform"], str) or submission["platform"] not in {"", "IOS", "MAC_OS", "TV_OS", "VISION_OS"}:
            raise ValidationError("Apple review submission platform is unsupported")
        if not isinstance(submission["state"], str) or submission["state"] not in {"READY_FOR_REVIEW", "WAITING_FOR_REVIEW", "IN_REVIEW", "COMPLETING", "COMPLETE", "CANCELING", "CANCELED", "UNRESOLVED_ISSUES"}:
            raise ValidationError("Apple review submission state is unsupported")
        if submission["platform"] == "" and submission["state"] != "COMPLETE":
            raise ValidationError("unscoped open Apple review submission is ambiguous")
        items = _array(submission["items"], "Apple review items", 10_000)
        for item in items:
            _exact_keys(item, {"id", "state", "resource"}, "Apple review item")
            _bounded_text(item["id"], "Apple review item ID")
            _bounded_text(item["state"], "Apple review item state", empty=True)
            resource = _exact_keys(item["resource"], {"type", "id"}, "Apple review item resource")
            if not isinstance(resource["type"], str) or resource["type"] not in {"appStoreVersions", "appStoreVersionExperiments", "appCustomProductPageVersions", "appEvents"}:
                raise ValidationError("Apple review item resource type is unsupported")
            _bounded_text(resource["id"], "Apple review item resource ID")
        _unique_records(items, "id", "Apple review items")
    _unique_records(submissions, "id", "Apple review submissions")
    nonce = snapshot["operationNonce"]
    if not isinstance(nonce, str) or not re.fullmatch(r"[a-f0-9]{32}", nonce):
        raise ValidationError("Apple screenshot operation nonce must contain 128 bits")
    target = _exact_keys(snapshot["metadataTarget"], {"version", "appInfo", "screenshots"}, "Apple metadata target")
    version_target = _exact_keys(target["version"], {"copyright", "localizations"}, "Apple version target")
    _bounded_text(version_target["copyright"], "Apple copyright target", maximum=64 * 1024, empty=True)
    _validate_apple_localizations(version_target["localizations"], info=False, observed=False)
    info_target = _exact_keys(target["appInfo"], {"categories", "localizations"}, "Apple AppInfo target")
    _validate_apple_categories(info_target["categories"])
    _validate_apple_localizations(info_target["localizations"], info=True, observed=False)
    screenshots = _array(target["screenshots"], "Apple screenshot targets", 1000)
    group_hashes: dict[tuple[str, str], set[str]] = {}
    before_names = {
        shot["fileName"] for before in (snapshot["production"], snapshot["liveReference"]) if before
        for localization in before["localizations"] for screenshot_set in localization["screenshotSets"] for shot in screenshot_set["screenshots"]
    }
    for shot in screenshots:
        _exact_keys(shot, {"localPath", "locale", "displayType", "fileName", "fileSize", "sha256", "sourceFileChecksum"}, "Apple screenshot target")
        path = _bounded_text(shot["localPath"], "Apple screenshot local path", maximum=1024)
        parts = path.split("/")
        if len(parts) not in {3, 4} or parts[0] != "screenshots" or parts[1] != shot["locale"] or any(part in {"", ".", ".."} for part in parts) or "\\" in path or ":" in path or any(ord(char) < 32 for char in path):
            raise ValidationError("Apple screenshot local path is unsafe")
        if not isinstance(shot["displayType"], str) or not re.fullmatch(r"APP_(?:IPHONE|IPAD|WATCH)_[A-Z0-9_]+", shot["displayType"]) or (len(parts) == 4 and parts[2] != shot["displayType"]):
            raise ValidationError("Apple screenshot display type is invalid")
        if not isinstance(shot["sha256"], str) or not HEX_SHA256_RE.fullmatch(shot["sha256"]) or not isinstance(shot["sourceFileChecksum"], str) or not re.fullmatch(r"[a-f0-9]{32}", shot["sourceFileChecksum"]):
            raise ValidationError("Apple screenshot content checksums are invalid")
        suffix = Path(path).suffix.lower()
        if suffix not in {".png", ".jpg", ".jpeg"} or shot["fileName"] != f"mrk-{nonce}-{shot['sha256']}{suffix}" or shot["fileName"] in before_names:
            raise ValidationError("Apple screenshot target filename is not uniquely operation-owned")
        if type(shot["fileSize"]) is not int or not 1 <= shot["fileSize"] <= 10 * 1024 * 1024:
            raise ValidationError("Apple screenshot target size is invalid")
        key = (shot["locale"], shot["displayType"])
        hashes = group_hashes.setdefault(key, set())
        if shot["sha256"] in hashes or len(hashes) >= 10:
            raise ValidationError("Apple screenshot targets are duplicated or exceed set bounds")
        hashes.add(shot["sha256"])
    _unique_records(screenshots, "localPath", "Apple screenshot targets")


def _validate_store_precondition(value: object, *, stage: str, platform: str) -> dict[str, Any]:
    if not isinstance(stage, str) or stage not in WORKFLOW_PATHS or not isinstance(platform, str) or platform not in {"android", "ios"}:
        raise ValidationError("Store precondition stage/platform is unsupported")
    precondition = _exact_keys(
        value,
        {
            "schemaVersion",
            "documentType",
            "operation",
            "platform",
            "appIdentity",
            "marketingVersion",
            "buildNumber",
            "observedAt",
            "snapshot",
        },
        "intent.storePrecondition",
    )
    expected_operation = {
        ("candidate", "android"): "android_internal_upload",
        ("candidate", "ios"): "ios_testflight_internal",
        ("external-testing", "android"): "android_external_promote",
        ("external-testing", "ios"): "ios_testflight_external",
        ("production-submit", "android"): "android_production_draft",
        ("production-submit", "ios"): "ios_app_store_submit",
    }[(stage, platform)]
    if (
        type(precondition["schemaVersion"]) is not int
        or precondition["schemaVersion"] != 1
        or precondition["documentType"] != "store-precondition"
        or precondition["operation"] != expected_operation
        or precondition["platform"] != platform
    ):
        raise ValidationError("intent Store precondition identity is invalid")
    if not isinstance(precondition["appIdentity"], str) or not precondition[
        "appIdentity"
    ]:
        raise ValidationError("intent Store precondition application identity is invalid")
    if not isinstance(precondition["marketingVersion"], str) or not precondition[
        "marketingVersion"
    ]:
        raise ValidationError("intent Store precondition marketing version is invalid")
    if (
        isinstance(precondition["buildNumber"], bool)
        or not isinstance(precondition["buildNumber"], int)
        or not 1 <= precondition["buildNumber"] <= 2_100_000_000
    ):
        raise ValidationError("intent Store precondition build number is invalid")
    _validate_timestamp(precondition["observedAt"], "intent.storePrecondition.observedAt")
    snapshot = precondition["snapshot"]
    if not isinstance(snapshot, dict) or not snapshot:
        raise ValidationError("intent Store precondition snapshot must be a non-empty object")
    # Bound attacker-controlled Store responses before canonicalization or transport.
    encoded = canonical_json_bytes(snapshot)
    if len(encoded) > 1024 * 1024:
        raise ValidationError("intent Store precondition snapshot is unexpectedly large")
    expected_canonicalization = (
        "mrk-play-operation-v1" if platform == "android" else "mrk-apple-operation-v1"
    )
    if snapshot.get("canonicalization") != expected_canonicalization:
        raise ValidationError("intent Store precondition canonicalization is unsupported")
    if platform == "android":
        expected_snapshot_keys = {
            "canonicalization",
            "destinationTrack",
            "destinationState",
            "sourceTrack",
            "sourceState",
            "bundles",
            "targetPresent",
            "targetRelease",
            "destinationTargetState",
            "sourceAllowedStates",
        }
        if stage == "production-submit":
            expected_snapshot_keys.update({"metadataBefore", "metadataTarget"})
        _exact_keys(snapshot, expected_snapshot_keys, "intent Store Play snapshot")
        if not isinstance(snapshot["targetPresent"], bool):
            raise ValidationError("intent Play targetPresent must be boolean")
        if not isinstance(snapshot["bundles"], list) or len(snapshot["bundles"]) > 10_000:
            raise ValidationError("intent Play bundle inventory is invalid")
        seen_codes: set[int] = set()
        for bundle in snapshot["bundles"]:
            bundle = _exact_keys(bundle, {"versionCode", "sha256"}, "intent Play bundle")
            code = bundle["versionCode"]
            if (
                isinstance(code, bool)
                or not isinstance(code, int)
                or not 1 <= code <= 2_100_000_000
                or code in seen_codes
                or not isinstance(bundle["sha256"], str)
                or not HEX_SHA256_RE.fullmatch(bundle["sha256"])
            ):
                raise ValidationError("intent Play bundle inventory contains an invalid record")
            seen_codes.add(code)
        expected_destination = {
            "candidate": "internal",
            "production-submit": "production",
        }.get(stage)
        if expected_destination and snapshot["destinationTrack"] != expected_destination:
            raise ValidationError("intent Play destination track is invalid")
        destination = _bounded_text(snapshot["destinationTrack"], "intent Play destination track")
        if stage == "external-testing" and destination in {"internal", "production"}:
            raise ValidationError("external Play intent must target a testing track")
        if stage == "candidate" and (
            snapshot["sourceTrack"] is not None
            or snapshot["sourceState"] is not None
            or snapshot["sourceAllowedStates"] != []
        ):
            raise ValidationError("candidate Play intent must not contain a source track")
        before = _validate_play_track(snapshot["destinationState"], destination)
        target = _validate_play_track(snapshot["destinationTargetState"], destination)
        release_target = _validate_play_release(snapshot["targetRelease"])
        code = str(precondition["buildNumber"])
        if release_target["versionCodes"] != [code] or release_target["status"] != ("draft" if stage == "production-submit" else "completed") or release_target.get("userFraction") is not None:
            raise ValidationError("intent Play target is not the exact intended release")
        previous_targets = [item for item in before["releases"] if code in item["versionCodes"]]
        if bool(previous_targets) != snapshot["targetPresent"]:
            raise ValidationError("intent Play targetPresent contradicts the full destination")
        expected_target = before if previous_targets else {**before, "releases": sorted([*before["releases"], release_target], key=canonical_json_bytes)}
        if target != expected_target or (previous_targets and previous_targets != [release_target]):
            raise ValidationError("intent Play destination target would change unrelated releases")
        allowed_sources = _array(snapshot["sourceAllowedStates"], "intent Play sourceAllowedStates", 2)
        if stage != "candidate":
            source = _bounded_text(snapshot["sourceTrack"], "intent Play source track")
            if source == destination or (stage == "external-testing" and source != "internal") or (stage == "production-submit" and source in {"internal", "production"}):
                raise ValidationError("intent Play source track is invalid")
            source_before = _validate_play_track(snapshot["sourceState"], source)
            source_releases = [item for item in source_before["releases"] if code in item["versionCodes"]]
            expected_sources = [source_before]
            if source_releases:
                if len(source_releases) != 1 or source_releases[0]["versionCodes"] != [code] or source_releases[0]["status"] != "completed":
                    raise ValidationError("intent Play source must contain the exact completed singleton build")
                expected_sources.append({**source_before, "releases": [item for item in source_before["releases"] if code not in item["versionCodes"]]})
            elif stage != "external-testing" or not snapshot["targetPresent"]:
                raise ValidationError("intent Play source candidate is missing")
            for source_state in allowed_sources:
                _validate_play_track(source_state, source)
            if allowed_sources != expected_sources:
                raise ValidationError("intent Play allowed source states would change unrelated releases")
        if stage == "production-submit":
            notes = release_target.get("releaseNotes")
            if not notes:
                raise ValidationError("production Play target requires nonempty release notes")
            for note in notes:
                validate_android_release_note(note["text"])
            _validate_play_metadata(snapshot["metadataBefore"], observed=True)
            _validate_play_metadata(snapshot["metadataTarget"], observed=False)
    else:
        expected_snapshot_keys = {
            "candidate": {"canonicalization", "appStoreAppId", "serverObservedAt", "build"},
            "external-testing": {
                "canonicalization",
                "appStoreAppId",
                "serverObservedAt",
                "build",
                "external",
                "privateStateCommitments",
            },
            "production-submit": {
                "canonicalization",
                "appStoreAppId",
                "serverObservedAt",
                "build",
                "production",
                "appInfo",
                "liveReference",
                "appInfoReference",
                "unrelatedVersions",
                "reviewSubmissions",
                "operationNonce",
                "metadataTarget",
                "privateStateCommitments",
            },
        }[stage]
        _exact_keys(snapshot, expected_snapshot_keys, "intent Store Apple snapshot")
        _validate_timestamp(snapshot["serverObservedAt"], "intent Apple serverObservedAt")
        _bounded_text(snapshot["appStoreAppId"], "intent Apple appStoreAppId")
        if stage == "candidate" and snapshot["build"] is not None:
            raise ValidationError("candidate Apple intent cannot adopt a pre-existing build")
        if stage != "candidate":
            build = _validate_apple_build(snapshot["build"], app_id=snapshot["appStoreAppId"], version=precondition["marketingVersion"], build=precondition["buildNumber"])
            if build["expirationDate"] <= snapshot["serverObservedAt"] or build["uploadedDate"] > snapshot["serverObservedAt"]:
                raise ValidationError("intent Apple candidate timestamps do not permit promotion")
        if stage == "external-testing":
            external = _validate_apple_external(snapshot["external"])
            if any(external[name] != snapshot["build"][name] for name in ("usesNonExemptEncryption", "autoNotifyEnabled")):
                raise ValidationError("Apple external/build snapshots disagree")
        elif stage == "production-submit":
            _validate_apple_production_snapshot(snapshot, precondition)
        if stage != "candidate":
            _validate_private_state_commitments(
                snapshot["privateStateCommitments"],
                required="external" if stage == "external-testing" else "production",
                allow_inherited=stage == "production-submit" and snapshot["production"] is None and snapshot["liveReference"] is not None,
            )
    return precondition


def validate_store_precondition(
    value: object, *, stage: str, platform: str
) -> dict[str, Any]:
    return _validate_store_precondition(value, stage=stage, platform=platform)


def _validate_private_state_commitments(
    value: object, *, required: bool | str, allow_inherited: bool = False
) -> dict[str, Any]:
    commitments = _exact_keys(
        value,
        {"algorithm", "keyVersion", "domains"} if required else set(),
        "intent.privateStateCommitments",
    )
    if not required:
        return commitments
    if commitments["algorithm"] != "hmac-sha256":
        raise ValidationError("private-state commitment algorithm is invalid")
    if (
        not isinstance(commitments["keyVersion"], str)
        or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", commitments["keyVersion"])
    ):
        raise ValidationError("private-state commitment key version is invalid")
    domains = commitments["domains"]
    expected_domains = {"beta-review"} if required == "external" else {"app-review"}
    if not isinstance(domains, dict) or set(domains) != expected_domains:
        raise ValidationError("private-state commitment domains are invalid")
    for domain, pair in domains.items():
        keys = {"before", "target"}
        if allow_inherited and isinstance(pair, dict) and "inherited" in pair:
            keys.add("inherited")
        pair = _exact_keys(pair, keys, f"intent private domain {domain}")
        if not all(isinstance(pair[name], str) and HEX_SHA256_RE.fullmatch(pair[name]) for name in pair):
            raise ValidationError("private-state commitment digest is invalid")
    return commitments


def validate_operation_intent(value: Mapping[str, Any]) -> dict[str, Any]:
    payload = verify_sealed(value)
    required = {
        "documentType",
        "schemaVersion",
        "stage",
        "platform",
        "tooling",
        "repository",
        "candidateSource",
        "operationSource",
        "authorizedBy",
        "confirmation",
        "application",
        "version",
        "destination",
        "configuration",
        "artifacts",
        "signing",
        "predecessors",
        "storePrecondition",
        "privateStateCommitments",
        "createdAt",
    }
    intent = _exact_keys(payload, required, "Store operation intent")
    if intent["documentType"] != "store-operation-intent" or type(intent["schemaVersion"]) is not int or intent["schemaVersion"] != 1:
        raise ValidationError("Store operation intent document type/schemaVersion is invalid")
    stage = intent["stage"]
    platform = intent["platform"]
    if not isinstance(stage, str) or stage not in {"candidate", "external-testing", "production-submit"} or not isinstance(platform, str) or platform not in {
        "android",
        "ios",
    }:
        raise ValidationError("Store operation intent stage/platform is invalid")
    tooling = _exact_keys(intent["tooling"], {"version", "commit"}, "intent.tooling")
    if not isinstance(tooling["version"], str) or not re.fullmatch(
        r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?", tooling["version"]
    ):
        raise ValidationError("intent tooling version is invalid")
    if not isinstance(tooling["commit"], str) or not re.fullmatch(
        r"[0-9A-Fa-f]{40}", tooling["commit"]
    ):
        raise ValidationError("intent tooling commit is invalid")
    repository = _exact_keys(intent["repository"], {"fullName", "id"}, "intent.repository")
    if not isinstance(repository["fullName"], str) or not re.fullmatch(
        r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository["fullName"]
    ):
        raise ValidationError("intent repository name is invalid")
    if not isinstance(repository["id"], str) or not re.fullmatch(r"[1-9][0-9]*", repository["id"]):
        raise ValidationError("intent repository ID is invalid")
    _validate_source_identity(intent["candidateSource"], "intent.candidateSource", include_ref=True)
    _validate_source_identity(intent["operationSource"], "intent.operationSource", include_ref=True)
    authority = _authority_for_stage(intent["authorizedBy"], stage, "intent.authorizedBy")
    if authority["reusableCommit"].lower() != tooling["commit"].lower():
        raise ValidationError("intent reusable workflow commit differs from tooling commit")
    if authority["headSha"] != intent["operationSource"]["commit"] or authority["ref"] != intent["operationSource"]["ref"]:
        raise ValidationError("intent authorization is not bound to the original operation source")
    if stage == "candidate" and intent["candidateSource"] != intent["operationSource"]:
        raise ValidationError("candidate intent source identities differ")
    if stage == "external-testing" and any(
        intent["candidateSource"][field] != intent["operationSource"][field]
        for field in ("commit", "tree")
    ):
        raise ValidationError("external-testing intent must use the exact candidate source commit/tree")
    expected_confirmation = f"{stage}:{platform}:{intent['version'].get('marketing') if isinstance(intent['version'], dict) else ''}:{intent['version'].get('build') if isinstance(intent['version'], dict) else ''}"
    if intent["confirmation"] != expected_confirmation:
        raise ValidationError("intent textual confirmation is invalid")
    application_keys = {"id"} | ({"storeAppId"} if platform == "ios" else set())
    application = _exact_keys(intent["application"], application_keys, "intent.application")
    if not isinstance(application["id"], str) or not 1 <= len(application["id"]) <= 255 or "\x00" in application["id"]:
        raise ValidationError("intent application identity is invalid")
    if platform == "ios" and (
        not isinstance(application["storeAppId"], str)
        or not 1 <= len(application["storeAppId"]) <= 255
        or "\x00" in application["storeAppId"]
    ):
        raise ValidationError("intent App Store application ID is invalid")
    version = _exact_keys(intent["version"], {"marketing", "build"}, "intent.version")
    if not isinstance(version["marketing"], str) or len(version["marketing"]) > 64 or not re.fullmatch(
        r"[0-9]+(?:\.[0-9]+){1,3}(?:[-+][0-9A-Za-z.-]+)?", version["marketing"]
    ):
        raise ValidationError("intent marketing version is invalid")
    if platform == "ios" and not re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,2}", version["marketing"]):
        raise ValidationError("intent iOS marketing version is invalid")
    if isinstance(version["build"], bool) or not isinstance(version["build"], int) or not 1 <= version[
        "build"
    ] <= 2_100_000_000:
        raise ValidationError("intent build number is invalid")
    destination_keys = {"channel", "releaseStatus"} if platform == "android" else {"channel"}
    if platform == "ios" and stage == "production-submit":
        destination_keys.add("automaticRelease")
    destination = _exact_keys(intent["destination"], destination_keys, "intent.destination")
    if len(canonical_json_bytes(destination)) > 64 * 1024:
        raise ValidationError("intent destination is unexpectedly large")
    expected_channel = {
        ("candidate", "android"): "internal",
        ("external-testing", "android"): None,
        ("production-submit", "android"): "production",
        ("candidate", "ios"): "testflight-internal",
        ("external-testing", "ios"): "testflight-external",
        ("production-submit", "ios"): "app-store-review",
    }[(stage, platform)]
    if (
        not isinstance(destination["channel"], str)
        or not 1 <= len(destination["channel"]) <= 255
        or (expected_channel is not None and destination["channel"] != expected_channel)
        or (
            stage == "external-testing"
            and platform == "android"
            and destination["channel"] in {"internal", "production"}
        )
    ):
        raise ValidationError("intent destination channel is invalid")
    if platform == "android":
        expected_status = "draft" if stage == "production-submit" else "completed"
        if destination["releaseStatus"] != expected_status:
            raise ValidationError("intent Play release status is invalid")
    elif stage == "production-submit" and destination["automaticRelease"] is not False:
        raise ValidationError("intent App Store destination must preserve manual release")
    configuration = _exact_keys(
        intent["configuration"], {"path", "sha256", "metadataSha256"}, "intent.configuration"
    )
    if configuration["path"] != "release/mobile-release.json" or not all(
        isinstance(configuration[name], str) and HEX_SHA256_RE.fullmatch(configuration[name])
        for name in ("sha256", "metadataSha256")
    ):
        raise ValidationError("intent configuration binding is invalid")
    if not isinstance(intent["artifacts"], list) or len(intent["artifacts"]) > 64:
        raise ValidationError("intent artifacts are invalid")
    if not isinstance(intent["signing"], list) or len(intent["signing"]) > 8:
        raise ValidationError("intent signing evidence is invalid")
    if not intent["artifacts"] or not intent["signing"]:
        raise ValidationError("operation intent requires candidate artifact and signing evidence")
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
    artifact_kinds = {
        "android-aab": ("android", "aab"),
        "android-mapping": ("android", "r8-mapping"),
        "android-native-symbols": ("android", "native-symbols"),
        "ios-ipa": ("ios", "ipa"),
        "ios-archive": ("ios", "xcarchive"),
        "ios-dsyms": ("ios", "dsym"),
        "store-metadata": ("shared", "metadata"),
        "validation-report": ("shared", "validation-report"),
    }
    artifact_names: set[str] = set()
    for artifact_value in intent["artifacts"]:
        artifact = _exact_keys(
            artifact_value,
            {
                "logicalName",
                "platform",
                "kind",
                "fileName",
                "size",
                "sha256",
                "architectures",
            },
            "intent artifact",
        )
        name = artifact["logicalName"]
        if (
            not isinstance(name, str)
            or name not in allowed_artifacts
            or name in artifact_names
            or (artifact["platform"], artifact["kind"]) != artifact_kinds.get(name)
            or not isinstance(artifact["fileName"], str)
            or artifact["fileName"] in {"", ".", ".."}
            or len(artifact["fileName"]) > 255
            or "/" in artifact["fileName"]
            or "\\" in artifact["fileName"]
            or isinstance(artifact["size"], bool)
            or not isinstance(artifact["size"], int)
            or artifact["size"] < 1
            or not isinstance(artifact["sha256"], str)
            or not HEX_SHA256_RE.fullmatch(artifact["sha256"])
            or not isinstance(artifact["architectures"], list)
            or any(
                not isinstance(item, str) or not re.fullmatch(r"[A-Za-z0-9_.-]+", item)
                for item in artifact["architectures"]
            )
            or len(artifact["architectures"]) != len(set(artifact["architectures"]))
        ):
            raise ValidationError("intent artifact record is invalid")
        artifact_names.add(name)
        if name == "store-metadata" and artifact["sha256"] != configuration["metadataSha256"]:
            raise ValidationError("intent metadata artifact and configuration digests differ")
    primary = "android-aab" if platform == "android" else "ios-ipa"
    if not {primary, "store-metadata", "validation-report"} <= artifact_names:
        raise ValidationError("operation intent lacks required candidate artifacts")
    if len(intent["signing"]) != 1:
        raise ValidationError("operation intent requires exactly one signing identity")
    signing_keys = {"platform", "kind", "certificateSha256"}
    if platform == "ios":
        signing_keys.update({"teamId", "profileUuid", "profileExpiresAt"})
    signing = _exact_keys(intent["signing"][0], signing_keys, "intent signing")
    expected_kind = "android-upload" if platform == "android" else "apple-distribution"
    if (
        signing["platform"] != platform
        or signing["kind"] != expected_kind
        or not isinstance(signing["certificateSha256"], str)
        or not HEX_SHA256_RE.fullmatch(signing["certificateSha256"])
    ):
        raise ValidationError("intent signing identity is invalid")
    if platform == "ios":
        if not isinstance(signing["teamId"], str) or not re.fullmatch(r"[A-Z0-9]{10}", signing["teamId"]) or not isinstance(signing["profileUuid"], str) or not re.fullmatch(
            r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-"
            r"[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}",
            signing["profileUuid"],
        ):
            raise ValidationError("intent Apple signing/profile identity is invalid")
        _validate_timestamp(signing["profileExpiresAt"], "intent.signing.profileExpiresAt")
    predecessors = intent["predecessors"]
    expected_predecessors = {
        "candidate": set(),
        "external-testing": {"candidateManifestSha256", "candidateReceiptSha256"},
        "production-submit": {
            "candidateManifestSha256",
            "candidateReceiptSha256",
            "externalReceiptSha256",
        },
    }[stage]
    predecessors = _exact_keys(predecessors, expected_predecessors, "intent.predecessors")
    if not all(isinstance(item, str) and HEX_SHA256_RE.fullmatch(item) for item in predecessors.values()):
        raise ValidationError("intent predecessor digest is invalid")
    precondition = _validate_store_precondition(intent["storePrecondition"], stage=stage, platform=platform)
    if (
        precondition["appIdentity"] != application["id"]
        or precondition["marketingVersion"] != version["marketing"]
        or precondition["buildNumber"] != version["build"]
    ):
        raise ValidationError("intent Store precondition is not bound to the operation identity")
    snapshot = precondition["snapshot"]
    if platform == "android":
        if snapshot["destinationTrack"] != destination["channel"]:
            raise ValidationError("intent Play snapshot/destination tracks differ")
        if stage in {"candidate", "production-submit"} and snapshot["targetPresent"]:
            raise ValidationError("intent cannot adopt an existing candidate/production target")
        bundles = [item for item in snapshot["bundles"] if item["versionCode"] == version["build"]]
        primary_digest = next(item["sha256"] for item in intent["artifacts"] if item["logicalName"] == "android-aab")
        if (stage == "candidate" and bundles) or (stage != "candidate" and (len(bundles) != 1 or bundles[0]["sha256"] != primary_digest)):
            raise ValidationError("intent Play bundle inventory is not bound to the original AAB")
    elif snapshot["appStoreAppId"] != application["storeAppId"]:
        raise ValidationError("intent Apple snapshot/application IDs differ")
    commitment_mode: bool | str = False
    if platform == "ios" and stage == "external-testing":
        commitment_mode = "external"
    elif platform == "ios" and stage == "production-submit":
        commitment_mode = "production"
    commitments = _validate_private_state_commitments(
        intent["privateStateCommitments"], required=commitment_mode,
        allow_inherited=commitment_mode == "production" and snapshot["production"] is None and snapshot["liveReference"] is not None,
    )
    snapshot_commitments = precondition["snapshot"].get("privateStateCommitments")
    if commitment_mode and snapshot_commitments != commitments:
        raise ValidationError("intent private-state commitments differ from Store precondition")
    _validate_timestamp(intent["createdAt"], "intent.createdAt")
    return payload


def validate_evidence_document(value: Mapping[str, Any]) -> None:
    payload = verify_sealed(value)
    document_type = payload.get("documentType")
    if document_type == "store-operation-intent":
        validate_operation_intent(value)
        return
    if not isinstance(document_type, str) or document_type not in {"candidate-manifest", "store-receipt"}:
        raise ValidationError(
            "release evidence is missing a supported documentType; regenerate legacy evidence"
        )
    common_sha = lambda item: isinstance(item, str) and bool(HEX_SHA256_RE.fullmatch(item))
    git_id = lambda item: isinstance(item, str) and bool(
        re.fullmatch(r"[0-9A-Fa-f]{40}", item)
    )
    if document_type == "store-receipt":
        required = {
            "documentType",
            "schemaVersion",
            "stage",
            "candidateManifestSha256",
            "operationIntentSha256",
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
            "authorizedBy",
            "executedBy",
            "producedBy",
            "createdAt",
        }
        if payload.get("stage") != "candidate":
            required.add("previousReceiptSha256")
        if payload.get("platform") == "android":
            required.add("storeState")
        if payload.get("outcome") == "operator-authorized-create-retry":
            required.add("createRetry")
        if payload.get("platform") == "ios" and payload.get("stage") == "production-submit":
            required.update({"appStoreVersionId", "reviewSubmissionId", "storeStateSha256"})
        receipt = _exact_keys(payload, required, "receipt")
        if (
            type(receipt["schemaVersion"]) is not int
            or receipt["schemaVersion"] != 3
            or not isinstance(receipt["stage"], str)
            or receipt["stage"]
            not in {
                "candidate",
                "external-testing",
                "production-submit",
            }
        ):
            raise ValidationError("receipt schemaVersion/stage is invalid")
        if receipt["documentType"] != "store-receipt":
            raise ValidationError("receipt documentType is invalid")
        if not common_sha(receipt["candidateManifestSha256"]) or (
            "previousReceiptSha256" in receipt
            and not common_sha(receipt["previousReceiptSha256"])
        ):
            raise ValidationError("receipt linkage hash is invalid")
        if not common_sha(receipt["operationIntentSha256"]):
            raise ValidationError("receipt operation-intent hash is invalid")
        platform = receipt["platform"]
        if not isinstance(platform, str) or platform not in {"android", "ios"}:
            raise ValidationError("receipt platform is invalid")
        expected_provider = "google-play" if platform == "android" else "app-store-connect"
        if receipt["provider"] != expected_provider:
            raise ValidationError("receipt provider/platform mismatch")
        _validate_common_evidence(receipt, git_id)
        _validate_evidence_authorities(receipt, receipt["stage"])
        if platform == "ios" and receipt["stage"] == "production-submit":
            for field in ("appStoreVersionId", "reviewSubmissionId"):
                if not isinstance(receipt[field], str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,255}", receipt[field]):
                    raise ValidationError(f"Apple production {field} is invalid")
            if not common_sha(receipt["storeStateSha256"]):
                raise ValidationError("Apple production public state digest is invalid")
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
        if not isinstance(receipt["outcome"], str) or receipt["outcome"] not in {
            "mutated",
            "reconciled",
            "already-present",
            "operator-authorized-reconciliation",
            "operator-authorized-retry",
            "operator-authorized-create-retry",
        }:
            raise ValidationError("receipt outcome is invalid")
        if receipt["stage"] == "candidate" and receipt["outcome"] == "already-present":
            raise ValidationError("candidate receipt cannot adopt an already-present build")
        if (
            platform == "android"
            and receipt["stage"] == "production-submit"
            and receipt["outcome"] == "already-present"
        ):
            raise ValidationError("production Play receipt cannot adopt an existing draft")
        _validate_recovery_outcome(receipt, stage=receipt["stage"], platform=platform)
        if receipt["outcome"] == "operator-authorized-create-retry":
            _validate_create_retry_shape(receipt["createRetry"])
            if receipt["createRetry"]["executedBy"] != receipt["executedBy"] or receipt["createRetry"]["inventory"]["operationIntentSha256"] != receipt["operationIntentSha256"]:
                raise ValidationError("create retry evidence has a different executor/intent")
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
        readback_keys = {"state", "observedAt"}
        if platform == "ios" and receipt["stage"] != "production-submit":
            readback_keys.add("autoNotifyEnabled")
        readback = _exact_keys(receipt["readback"], readback_keys, "receipt.readback")
        if "autoNotifyEnabled" in readback and readback["autoNotifyEnabled"] is not False:
            raise ValidationError("Apple evidence must prove automatic tester notification is disabled")
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
        if not isinstance(readback["state"], str) or readback["state"] not in allowed_states[(receipt["stage"], platform)]:
            raise ValidationError("receipt readback state does not match its stage/platform")
        return

    required = {
        "documentType",
        "schemaVersion",
        "operationIntentSha256",
        "tooling",
        "repository",
        "source",
        "configuration",
        "version",
        "platforms",
        "artifacts",
        "signing",
        "storeReceipts",
        "authorizedBy",
        "executedBy",
        "producedBy",
        "createdAt",
    }
    manifest = _exact_keys(payload, required, "candidate")
    if manifest["documentType"] != "candidate-manifest":
        raise ValidationError("candidate documentType is invalid")
    if type(manifest["schemaVersion"]) is not int or manifest["schemaVersion"] != 2:
        raise ValidationError("candidate schemaVersion must be 2")
    if not common_sha(manifest["operationIntentSha256"]):
        raise ValidationError("candidate operation-intent hash is invalid")
    _validate_common_evidence(manifest, git_id)
    _validate_evidence_authorities(manifest, "candidate")
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
            or any(
                not isinstance(item, str)
                or not re.fullmatch(r"[A-Za-z0-9_.-]+", item)
                for item in architectures
            )
            or len(architectures) != len(set(architectures))
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
        if not isinstance(signing["teamId"], str) or not re.fullmatch(r"[A-Z0-9]{10}", signing["teamId"]) or not isinstance(signing["profileUuid"], str) or not re.fullmatch(
            r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-"
            r"[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}",
            signing["profileUuid"],
        ):
            raise ValidationError("candidate Apple signing/profile identity is invalid")
        _validate_timestamp(signing["profileExpiresAt"], "candidate.signing.profileExpiresAt")
    if not isinstance(manifest["storeReceipts"], list) or not manifest["storeReceipts"]:
        raise ValidationError("candidate internal Store readback must be non-empty")
    if len(manifest["storeReceipts"]) != 1:
        raise ValidationError("candidate must contain exactly one internal Store readback")
    store_keys = {
        "provider", "applicationId", "storeBuildId", "marketingVersion", "build",
        "channel", "state", "observedAt",
    } | ({"autoNotifyEnabled"} if platform == "ios" else set())
    store = _exact_keys(
        manifest["storeReceipts"][0],
        store_keys,
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
        or type(store["build"]) is not int
        or store["build"] != manifest["version"]["build"]
        or store["channel"] != expected_channel
        or not isinstance(store["state"], str)
        or store["state"] not in allowed_candidate_states
        or not isinstance(store["storeBuildId"], str)
        or not 1 <= len(store["storeBuildId"]) <= 255
    ):
        raise ValidationError("candidate Store readback is not bound to its exact internal build")
    if platform == "ios" and store["autoNotifyEnabled"] is not False:
        raise ValidationError("Apple candidate must disable automatic tester notification")
    _validate_timestamp(store["observedAt"], "candidate.storeReceipt.observedAt")


def _validate_common_evidence(value: Mapping[str, Any], git_id: Any) -> None:
    tooling = _exact_keys(value["tooling"], {"version", "commit"}, "tooling")
    repository = _exact_keys(value["repository"], {"fullName", "id"}, "repository")
    version = _exact_keys(value["version"], {"marketing", "build"}, "version")
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
    source = value["source"]
    if not isinstance(source, dict) or not git_id(source.get("commit")) or not git_id(
        source.get("tree")
    ):
        raise ValidationError("source Git object IDs are invalid")
    _validate_timestamp(value["createdAt"], "createdAt")


def load_store_receipt(path: Path) -> dict[str, Any]:
    return _load_json_object(path, label="Store readback", maximum_size=2 * 1024 * 1024)


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
    mode = value.get("mode") if isinstance(value, dict) else None
    if outcome in {"mutated", "reconciled"} and mode == "mutation":
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
    if stage == "production-submit":
        required.update(
            {
                "metadataBeforeSha256",
                "metadataExpectedSha256",
                "metadataCommittedSha256",
            }
        )
    state = _exact_keys(value, required, "receipt.storeState")
    if state["canonicalization"] != "mrk-play-track-state-v2":
        raise ValidationError("Play Store-state canonicalization is unsupported")
    expected_modes = {
        "mutated": {"mutation"},
        "reconciled": {"mutation", "recovery"},
        "already-present": {"observation"},
    }[outcome]
    if not isinstance(state["mode"], str) or state["mode"] not in expected_modes:
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
    if stage == "production-submit" and (
        state["metadataExpectedSha256"] != state["metadataCommittedSha256"]
    ):
        raise ValidationError("Play production metadata differs from the authenticated target")
    if stage != "candidate":
        if (
            state["sourceUnrelatedBeforeSha256"]
            != state["sourceUnrelatedCommittedSha256"]
        ):
            raise ValidationError("Play receipt does not preserve unrelated source releases")
        transition = state["sourceTargetTransition"]
        if outcome == "already-present":
            if not isinstance(transition, str) or transition not in {"retained", "already-deactivated"}:
                raise ValidationError("Play observation has an invalid source transition")
            if not (
                state["sourceBeforeSha256"]
                == state["sourceExpectedSha256"]
                == state["sourceCommittedSha256"]
            ):
                raise ValidationError("Play observation contains a source-state change")
        else:
            if not isinstance(transition, str) or transition not in {"retained", "deactivated"}:
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


def _play_digest(value: Any, domain: str = "track") -> str:
    return hashlib.sha256(b"mrk-play-track-state-v2:" + domain.encode("ascii") + b":" + canonical_json_bytes(value)).hexdigest()


def _validate_play_state_intent(state: Mapping[str, Any], intent: Mapping[str, Any]) -> None:
    snapshot = intent["storePrecondition"]["snapshot"]
    code = str(intent["version"]["build"])
    before = snapshot["destinationState"]
    expected = snapshot["destinationTargetState"]
    without = lambda track: [item for item in track["releases"] if code not in item["versionCodes"]]
    expected_hashes = {
        "destinationBeforeSha256": _play_digest(before),
        "destinationExpectedSha256": _play_digest(expected),
        "destinationCommittedSha256": _play_digest(expected),
        "unrelatedBeforeSha256": _play_digest(without(before), "release-set"),
        "unrelatedCommittedSha256": _play_digest(without(expected), "release-set"),
        "targetReleaseSha256": _play_digest(snapshot["targetRelease"], "release"),
    }
    if snapshot["sourceTrack"]:
        source = snapshot["sourceState"]
        allowed = {_play_digest(item) for item in snapshot["sourceAllowedStates"]}
        if state["sourceCommittedSha256"] not in allowed or state["sourceExpectedSha256"] != state["sourceCommittedSha256"]:
            raise ValidationError("Play receipt source state is outside the authenticated intent")
        expected_hashes.update({
            "sourceBeforeSha256": _play_digest(source),
            "sourceUnrelatedBeforeSha256": _play_digest(without(source), "release-set"),
            "sourceUnrelatedCommittedSha256": _play_digest(without(source), "release-set"),
        })
    if intent["stage"] == "production-submit":
        metadata_before = {key: value for key, value in snapshot["metadataBefore"].items() if key != "observedImageIds"}
        expected_hashes.update({
            "metadataBeforeSha256": _play_digest(metadata_before, "metadata"),
            "metadataExpectedSha256": _play_digest(snapshot["metadataTarget"], "metadata"),
            "metadataCommittedSha256": _play_digest(snapshot["metadataTarget"], "metadata"),
        })
    if any(state.get(field) != digest for field, digest in expected_hashes.items()):
        raise ValidationError("Play Store-state readback is not bound to the authenticated intent")


def _normalized_outcome(result: str, *, stage: str, platform: str) -> str:
    outcomes = {"accepted": "mutated", "reconciled": "reconciled", "already_present": "already-present"}
    if platform == "ios":
        if stage == "candidate":
            outcomes.update({"operator_authorized_reconciliation": "operator-authorized-reconciliation", "operator_authorized_retry": "operator-authorized-retry"})
        else:
            outcomes["operator_authorized_retry"] = "operator-authorized-create-retry"
    if not isinstance(result, str) or result not in outcomes:
        raise ValidationError("Store receipt does not prove a supported accepted/reconciled result")
    return outcomes[result]


def _validate_recovery_outcome(value: Mapping[str, Any], *, stage: str, platform: str) -> None:
    outcome = value["outcome"]
    authorized, executed = value["authorizedBy"], value["executedBy"]
    operator = outcome in {"operator-authorized-reconciliation", "operator-authorized-retry", "operator-authorized-create-retry"}
    if operator and (platform != "ios" or executed["runId"] == authorized["runId"]):
        raise ValidationError("operator-authorized Store recovery requires a different protected iOS dispatch")
    if outcome in {"operator-authorized-retry", "operator-authorized-create-retry"} and executed["attempt"] != 1:
        raise ValidationError("operator-authorized retry cannot be replayed on a workflow rerun")
    if outcome in {"operator-authorized-reconciliation", "operator-authorized-retry"} and stage != "candidate":
        raise ValidationError("candidate recovery outcome is not valid for this release stage")
    if outcome == "operator-authorized-create-retry" and stage == "candidate":
        raise ValidationError("candidate upload cannot use a resource-create retry grant")
    if platform == "ios" and stage == "candidate" and outcome in {"mutated", "reconciled"} and executed != authorized:
        raise ValidationError("a later iOS candidate process requires explicit operator reconciliation/retry")


CREATE_RETRY_TYPES = {
    "appStoreVersions": "apps", "appStoreVersionLocalizations": "appStoreVersions",
    "appInfoLocalizations": "appInfos", "appScreenshotSets": "appStoreVersionLocalizations",
    "appScreenshots": "appScreenshotSets", "appStoreReviewDetails": "appStoreVersions",
    "reviewSubmissions": "apps", "reviewSubmissionItems": "reviewSubmissions",
    "betaBuildLocalizations": "builds", "betaAppReviewSubmissions": "builds",
    "betaGroupRelationships": "builds",
}


def _validate_create_retry_shape(value: object) -> dict[str, Any]:
    retry = _exact_keys(value, {"mode", "inventorySha256", "inventory", "executedBy", "usedCreates"}, "iOS create-retry evidence")
    if retry["mode"] != "operator-authorized-create-retry":
        raise ValidationError("iOS retry evidence mode is invalid")
    inventory = _exact_keys(retry["inventory"], {"documentType", "schemaVersion", "operationIntentSha256", "stage", "platform", "application", "candidate", "publicStateSha256", "creates"}, "iOS retry inventory")
    if inventory["documentType"] != "ios-create-retry-inventory" or type(inventory["schemaVersion"]) is not int or inventory["schemaVersion"] != 1 or inventory["platform"] != "ios" or not isinstance(inventory["stage"], str) or inventory["stage"] not in {"external-testing", "production-submit"}:
        raise ValidationError("iOS retry inventory type/stage is invalid")
    _authority_for_stage(retry["executedBy"], inventory["stage"], "iOS retry executor")
    for field in ("operationIntentSha256", "publicStateSha256"):
        if not isinstance(inventory[field], str) or not HEX_SHA256_RE.fullmatch(inventory[field]):
            raise ValidationError("iOS retry inventory digest is invalid")
    app = _exact_keys(inventory["application"], {"bundleId", "appStoreAppId"}, "iOS retry application")
    candidate = _exact_keys(inventory["candidate"], {"marketingVersion", "buildNumber", "storeBuildId"}, "iOS retry candidate")
    for name, text in {**app, **{key: val for key, val in candidate.items() if key != "buildNumber"}}.items():
        _bounded_text(text, f"iOS retry {name}")
    if type(candidate["buildNumber"]) is not int or not 1 <= candidate["buildNumber"] <= 2_100_000_000:
        raise ValidationError("iOS retry candidate build is invalid")
    nodes = _array(inventory["creates"], "iOS retry creates", 2000)
    for node in nodes:
        _exact_keys(node, {"logicalIdentity", "logicalKeySha256", "resourceType", "method", "endpointKind", "parent", "dependencies", "targetSha256"}, "iOS retry create")
        resource = node["resourceType"]
        if not isinstance(resource, str) or resource not in CREATE_RETRY_TYPES or node["method"] != "POST" or node["endpointKind"] != resource:
            raise ValidationError("iOS retry endpoint is unsupported")
        identity = _exact_keys(node["logicalIdentity"], {"resourceType", "scope", "locator"}, "iOS retry logical identity")
        scope = _exact_keys(identity["scope"], {"appStoreAppId", "platform", "marketingVersion", "buildNumber", "storeBuildId"}, "iOS retry scope")
        if scope != {"appStoreAppId": app["appStoreAppId"], "platform": "IOS", **candidate} or identity["resourceType"] != resource:
            raise ValidationError("iOS retry logical scope differs from its candidate")
        locator_keys = {
            "appStoreVersions": set(), "reviewSubmissions": set(), "reviewSubmissionItems": set(), "betaAppReviewSubmissions": set(),
            "appStoreVersionLocalizations": {"locale"}, "appInfoLocalizations": {"locale"},
            "betaBuildLocalizations": {"locale", "whatsNewSha256"}, "betaGroupRelationships": {"groupId"},
            "appStoreReviewDetails": {"domain", "keyVersion", "targetHmacSha256"},
            "appScreenshotSets": {"locale", "displayType"},
            "appScreenshots": {"locale", "displayType", "order", "fileName", "fileSize", "sha256", "sourceFileChecksum"},
        }[resource]
        locator = _exact_keys(identity["locator"], locator_keys, "iOS retry locator")
        for field, item in locator.items():
            if field in {"order", "fileSize"}:
                if type(item) is not int or item < (1 if field == "fileSize" else 0):
                    raise ValidationError("iOS retry screenshot bounds are invalid")
            else:
                _bounded_text(item, f"iOS retry locator {field}", maximum=512)
        if node["logicalKeySha256"] != hashlib.sha256(b"mrk-ios-create-retry-v1:logical-key:" + canonical_json_bytes(identity)).hexdigest() or not isinstance(node["targetSha256"], str) or not HEX_SHA256_RE.fullmatch(node["targetSha256"]):
            raise ValidationError("iOS retry logical/target digest is invalid")
        parent = node["parent"]
        if not isinstance(parent, dict) or not isinstance(parent.get("mode"), str) or parent.get("mode") not in {"present", "missing", "automatic"} or parent.get("resourceType") != CREATE_RETRY_TYPES[resource]:
            raise ValidationError("iOS retry parent type/mode is invalid")
        keys = {"mode", "resourceType"} | {"present": {"id"}, "missing": {"logicalKeySha256"}, "automatic": {"appStoreAppId", "referenceSha256", "versionKeySha256"}}[parent["mode"]]
        _exact_keys(parent, keys, "iOS retry parent")
        for field in keys - {"mode", "resourceType"}:
            _bounded_text(parent[field], f"iOS retry parent {field}")
        if parent["mode"] == "automatic" and resource != "appInfoLocalizations":
            raise ValidationError("iOS retry automatic parent is not an AppInfo default")
        dependencies = _array(node["dependencies"], "iOS retry dependencies", 2000)
        if any(not isinstance(key, str) or not HEX_SHA256_RE.fullmatch(key) for key in dependencies) or dependencies != sorted(set(dependencies)):
            raise ValidationError("iOS retry dependencies are invalid")
    _unique_records(nodes, "logicalKeySha256", "iOS retry creates")
    if nodes != sorted(nodes, key=lambda node: node["logicalKeySha256"]):
        raise ValidationError("iOS retry creates are not canonical")
    used = _array(retry["usedCreates"], "iOS retried creates", 2000)
    if not used:
        raise ValidationError("iOS retry evidence must identify a read-back insertion")
    keys = {node["logicalKeySha256"] for node in nodes}
    for item in used:
        _exact_keys(item, {"logicalKeySha256", "resourceId"}, "iOS retried create")
        if not isinstance(item["logicalKeySha256"], str) or item["logicalKeySha256"] not in keys or not isinstance(item["resourceId"], str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,255}", item["resourceId"]):
            raise ValidationError("iOS retried create has no scoped Store readback")
    _unique_records(used, "logicalKeySha256", "iOS retried creates")
    if used != sorted(used, key=lambda item: item["logicalKeySha256"]):
        raise ValidationError("iOS retried creates are not canonical")
    if retry["inventorySha256"] != canonical_sha256(inventory):
        raise ValidationError("iOS retry inventory integrity differs")
    return retry


def validate_create_retry_inventory(value: object, *, operation_intent: Mapping[str, Any]) -> dict[str, Any]:
    """Validate public, intent-derived retry keys, never a caller-supplied URL.

    This proves structural/context binding, not that a Store POST was rejected.
    The attested Store executor must independently observe/classify the entire
    public state and enforce the one-shot protected recovery authorization.
    """

    intent = validate_operation_intent(operation_intent)
    inventory = _exact_keys(value, {"documentType", "schemaVersion", "operationIntentSha256", "stage", "platform", "application", "candidate", "publicStateSha256", "creates"}, "iOS create-retry inventory")
    if len(canonical_json_bytes(inventory)) > 1024 * 1024:
        raise ValidationError("iOS create-retry inventory is oversized")
    stage = intent["stage"]
    snapshot = intent["storePrecondition"]["snapshot"]
    if intent["platform"] != "ios" or stage not in {"external-testing", "production-submit"}:
        raise ValidationError("iOS create retry is not valid for this operation intent")
    if inventory["documentType"] != "ios-create-retry-inventory" or type(inventory["schemaVersion"]) is not int or inventory["schemaVersion"] != 1 or inventory["stage"] != stage or inventory["platform"] != "ios" or inventory["operationIntentSha256"] != operation_intent["integrity"]["sha256"]:
        raise ValidationError("iOS create-retry inventory identity differs from the intent")
    expected_application = {"bundleId": intent["application"]["id"], "appStoreAppId": intent["application"]["storeAppId"]}
    expected_candidate = {"marketingVersion": intent["version"]["marketing"], "buildNumber": intent["version"]["build"], "storeBuildId": snapshot["build"]["id"]}
    if inventory["application"] != expected_application or inventory["candidate"] != expected_candidate:
        raise ValidationError("iOS create-retry inventory is not bound to the original Store build")
    if not isinstance(inventory["publicStateSha256"], str) or not HEX_SHA256_RE.fullmatch(inventory["publicStateSha256"]):
        raise ValidationError("iOS create-retry public state digest is invalid")
    scope = {"appStoreAppId": expected_application["appStoreAppId"], "platform": "IOS", **expected_candidate}
    scope["buildNumber"] = expected_candidate["buildNumber"]
    nodes = _array(inventory["creates"], "iOS missing creates", 2000)
    by_key: dict[str, dict[str, Any]] = {}
    for node in nodes:
        _exact_keys(node, {"logicalIdentity", "logicalKeySha256", "resourceType", "method", "endpointKind", "parent", "dependencies", "targetSha256"}, "iOS create node")
        resource = node["resourceType"]
        if not isinstance(resource, str) or resource not in CREATE_RETRY_TYPES or node["method"] != "POST" or node["endpointKind"] != resource:
            raise ValidationError("iOS retry resource/endpoint is unsupported")
        if resource.startswith("beta") != (stage == "external-testing"):
            raise ValidationError("iOS retry resource is not part of the requested stage")
        identity = _exact_keys(node["logicalIdentity"], {"resourceType", "scope", "locator"}, "iOS create logical identity")
        if identity["resourceType"] != resource or identity["scope"] != scope:
            raise ValidationError("iOS retry logical scope differs from the immutable candidate")
        locator = identity["locator"]
        expected_target: Any
        if resource in {"appStoreVersions", "reviewSubmissions", "reviewSubmissionItems", "betaAppReviewSubmissions"}:
            _exact_keys(locator, set(), "iOS retry locator")
            expected_target = {
                "appStoreVersions": {"platform": "IOS", "versionString": intent["version"]["marketing"], "releaseType": "MANUAL"},
                "reviewSubmissions": {"platform": "IOS", "appId": expected_application["appStoreAppId"], "buildId": expected_candidate["storeBuildId"]},
                "reviewSubmissionItems": {"versionString": intent["version"]["marketing"], "buildId": expected_candidate["storeBuildId"]},
                "betaAppReviewSubmissions": {"buildId": expected_candidate["storeBuildId"]},
            }[resource]
        elif resource == "betaGroupRelationships":
            _exact_keys(locator, {"groupId"}, "iOS retry group locator")
            if locator["groupId"] != snapshot["external"]["groupId"]:
                raise ValidationError("iOS retry group differs from the intended external group")
            expected_target = {"buildId": expected_candidate["storeBuildId"], "groupId": locator["groupId"]}
        elif resource in {"appStoreVersionLocalizations", "appInfoLocalizations", "betaBuildLocalizations"}:
            keys = {"locale", "whatsNewSha256"} if resource == "betaBuildLocalizations" else {"locale"}
            _exact_keys(locator, keys, "iOS retry locale locator")
            targets = snapshot["external"]["targetLocalizations"] if stage == "external-testing" else snapshot["metadataTarget"]["appInfo" if resource == "appInfoLocalizations" else "version"]["localizations"]
            matches = [item for item in targets if item["locale"] == locator["locale"]]
            if len(matches) != 1:
                raise ValidationError("iOS retry locale was not authorized by the intent")
            expected_target = matches[0]
            if resource == "betaBuildLocalizations" and locator["whatsNewSha256"] != hashlib.sha256(expected_target["whatsNew"].encode("utf-8")).hexdigest():
                raise ValidationError("iOS retry beta text differs from the intent")
        elif resource == "appStoreReviewDetails":
            commitments = intent["privateStateCommitments"]
            expected_target = {"domain": "app-review", "keyVersion": commitments["keyVersion"], "targetHmacSha256": commitments["domains"]["app-review"]["target"]}
            if locator != expected_target:
                raise ValidationError("iOS retry private target commitment differs from the intent")
        else:
            keys = {"locale", "displayType"}
            if resource == "appScreenshots":
                keys |= {"order", "fileName", "fileSize", "sha256", "sourceFileChecksum"}
            _exact_keys(locator, keys, "iOS retry screenshot locator")
            shots = [item for item in snapshot["metadataTarget"]["screenshots"] if item["locale"] == locator["locale"] and item["displayType"] == locator["displayType"]]
            if not shots:
                raise ValidationError("iOS retry screenshot set is not authorized by the intent")
            expected_target = {"screenshotDisplayType": locator["displayType"]}
            if resource == "appScreenshots":
                order = locator["order"]
                if type(order) is not int or not 0 <= order < len(shots):
                    raise ValidationError("iOS retry screenshot order differs from the intent")
                expected_target = shots[order]
                if any(expected_target[field] != locator[field] for field in keys - {"order"}):
                    raise ValidationError("iOS retry screenshot content differs from the intent")
        key = hashlib.sha256(b"mrk-ios-create-retry-v1:logical-key:" + canonical_json_bytes(identity)).hexdigest()
        if node["logicalKeySha256"] != key or key in by_key or node["targetSha256"] != canonical_sha256(expected_target):
            raise ValidationError("iOS retry logical/target digest is invalid or duplicated")
        by_key[key] = node
        parent = node["parent"]
        if not isinstance(parent, dict) or parent.get("resourceType") != CREATE_RETRY_TYPES[resource]:
            raise ValidationError("iOS retry parent resource type is invalid")
        mode = parent.get("mode")
        if mode == "present":
            _exact_keys(parent, {"mode", "resourceType", "id"}, "iOS retry existing parent")
            if not isinstance(parent["id"], str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,255}", parent["id"]):
                raise ValidationError("iOS retry parent resource ID is invalid")
            known_id = {"apps": expected_application["appStoreAppId"], "builds": expected_candidate["storeBuildId"]}.get(parent["resourceType"])
            if known_id is not None and parent["id"] != known_id:
                raise ValidationError("iOS retry parent application/build ID differs from the intent")
        elif mode == "missing":
            _exact_keys(parent, {"mode", "resourceType", "logicalKeySha256"}, "iOS retry missing parent")
            if not isinstance(parent["logicalKeySha256"], str) or not HEX_SHA256_RE.fullmatch(parent["logicalKeySha256"]):
                raise ValidationError("iOS retry missing parent must identify an exact logical key")
        elif mode == "automatic" and resource == "appInfoLocalizations":
            _exact_keys(parent, {"mode", "resourceType", "appStoreAppId", "referenceSha256", "versionKeySha256"}, "iOS retry automatic parent")
            if snapshot["production"] is not None or snapshot["appInfo"] is not None or parent["appStoreAppId"] != expected_application["appStoreAppId"] or parent["referenceSha256"] != canonical_sha256(snapshot["appInfoReference"]):
                raise ValidationError("iOS automatic parent defaults are not authorized by the intent")
            if not isinstance(parent["versionKeySha256"], str) or not HEX_SHA256_RE.fullmatch(parent["versionKeySha256"]):
                raise ValidationError("iOS retry automatic parent must identify the exact version key")
        else:
            raise ValidationError("iOS retry parent mode is unsupported")
        dependencies = _array(node["dependencies"], "iOS retry dependencies", 2000)
        if any(not isinstance(dependency, str) or not HEX_SHA256_RE.fullmatch(dependency) for dependency in dependencies) or dependencies != sorted(set(dependencies)):
            raise ValidationError("iOS retry dependencies are not canonical")
    if nodes != sorted(nodes, key=lambda node: node["logicalKeySha256"]):
        raise ValidationError("iOS retry nodes are not canonical")
    completed: set[str] = set()
    for node in nodes:
        parent = node["parent"]
        resource = node["resourceType"]
        locator = node["logicalIdentity"]["locator"]
        parent_key = parent.get("logicalKeySha256", parent.get("versionKeySha256"))
        expected_dependencies: set[str] = set()
        if parent_key is not None:
            if not isinstance(parent_key, str) or parent_key not in by_key or parent_key not in node["dependencies"]:
                raise ValidationError("iOS retry missing parent is not a bound DAG dependency")
            parent_type = "appStoreVersions" if parent["mode"] == "automatic" else parent["resourceType"]
            parent_locator = {field: locator[field] for field in (
                ("locale", "displayType") if resource == "appScreenshots" else
                ("locale",) if resource == "appScreenshotSets" else ()
            )}
            expected_identity = {"resourceType": parent_type, "scope": scope, "locator": parent_locator}
            if by_key[parent_key]["logicalIdentity"] != expected_identity:
                raise ValidationError("iOS retry DAG parent identity/locale/display differs from its child")
            expected_dependencies.add(parent_key)
        if stage == "production-submit":
            if parent["mode"] == "present":
                _validate_known_retry_parent(node, snapshot)
            version_nodes = [key for key, value in by_key.items() if value["resourceType"] == "appStoreVersions"]
            if resource in {"reviewSubmissions", "reviewSubmissionItems"}:
                expected_dependencies.update(version_nodes)
        if set(node["dependencies"]) != expected_dependencies:
            raise ValidationError("iOS retry dependencies differ from the exact parent/version DAG")
    while len(completed) < len(nodes):
        ready = {key for key, node in by_key.items() if key not in completed and set(node["dependencies"]) <= completed}
        if not ready:
            raise ValidationError("iOS retry dependency graph contains a cycle")
        completed |= ready
    return inventory


def _validate_known_retry_parent(node: Mapping[str, Any], snapshot: Mapping[str, Any]) -> None:
    """Do not substitute an observed original parent or attach to a live sibling.

    IDs allocated only after preparation are bound by the authenticated executor's
    complete public-state hash. IDs already present in the intent can additionally
    be compared here without inferring unknown Store state.
    """

    parent = node["parent"]
    kind, identity = parent["resourceType"], parent["id"]
    locator = node["logicalIdentity"]["locator"]
    original, reference = snapshot["production"], snapshot["liveReference"]
    known: set[str] = set()
    expected: str | None = None
    if kind == "appStoreVersions":
        known = {item["id"] for item in snapshot["unrelatedVersions"]}
        if original is not None:
            expected = original["id"]
    elif kind == "appInfos":
        if snapshot["appInfoReference"] is not None:
            known.add(snapshot["appInfoReference"]["id"])
        if snapshot["appInfo"] is not None:
            expected = snapshot["appInfo"]["id"]
    elif kind in {"appStoreVersionLocalizations", "appScreenshotSets"}:
        for version in (original, reference):
            if version is None:
                continue
            for locale in version["localizations"]:
                if kind == "appStoreVersionLocalizations":
                    known.add(locale["id"])
                    if version is original and locale["locale"] == locator["locale"]:
                        expected = locale["id"]
                else:
                    for screenshot_set in locale["screenshotSets"]:
                        known.add(screenshot_set["id"])
                        if version is original and locale["locale"] == locator["locale"] and screenshot_set["displayType"] == locator["displayType"]:
                            expected = screenshot_set["id"]
    elif kind == "reviewSubmissions":
        known = {item["id"] for item in snapshot["reviewSubmissions"]}
        original_id = original["id"] if original else None
        intended = [item for item in snapshot["reviewSubmissions"] if item["platform"] == "IOS" and (item["state"] != "COMPLETE" or any(child["resource"] == {"type": "appStoreVersions", "id": original_id} for child in item["items"]))]
        if len(intended) > 1:
            raise ValidationError("iOS retry original review submission parent is ambiguous")
        if intended:
            expected = intended[0]["id"]
    if (expected is not None and identity != expected) or (expected is None and identity in known):
        raise ValidationError("iOS retry substituted a known original or unrelated Store parent")


def _validate_create_retry(value: object, *, operation_intent: Mapping[str, Any], executed_by: Mapping[str, Any]) -> dict[str, Any]:
    retry = _exact_keys(value, {"mode", "inventorySha256", "inventory", "executedBy", "usedCreates"}, "iOS create-retry evidence")
    if retry["mode"] != "operator-authorized-create-retry" or retry["executedBy"] != executed_by:
        raise ValidationError("iOS retry mode/executor differs from the Store receipt")
    inventory = validate_create_retry_inventory(retry["inventory"], operation_intent=operation_intent)
    if retry["inventorySha256"] != canonical_sha256(inventory):
        raise ValidationError("iOS retry inventory digest is invalid")
    used = _array(retry["usedCreates"], "iOS retried creates", 2000)
    if not used:
        raise ValidationError("operator-authorized create retry must identify a read-back insertion")
    by_key = {item["logicalKeySha256"]: item for item in inventory["creates"]}
    for item in used:
        _exact_keys(item, {"logicalKeySha256", "resourceId"}, "iOS retried create")
        if not isinstance(item["logicalKeySha256"], str) or item["logicalKeySha256"] not in by_key or not isinstance(item["resourceId"], str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,255}", item["resourceId"]):
            raise ValidationError("iOS retried create is unscoped or has no exact Store readback")
        node = by_key[item["logicalKeySha256"]]
        if node["resourceType"] == "betaGroupRelationships" and item["resourceId"] != node["logicalIdentity"]["locator"]["groupId"]:
            raise ValidationError("iOS retried group insertion read back another group")
    _unique_records(used, "logicalKeySha256", "iOS retried creates")
    if used != sorted(used, key=lambda item: item["logicalKeySha256"]):
        raise ValidationError("iOS retried creates are not canonical")
    return retry


def validate_store_receipt(
    receipt: Mapping[str, Any],
    *,
    config: ReleaseConfig,
    release: ReleaseVersion,
    stage: str,
    platform: str,
    operation_intent: Mapping[str, Any] | None = None,
    recovery_run_id: str | None = None,
) -> dict[str, Any]:
    if not isinstance(stage, str) or stage not in WORKFLOW_PATHS or not isinstance(platform, str) or platform not in {"android", "ios"}:
        raise ValidationError("unsupported Store receipt stage/platform")
    return _validate_store_receipt_document(
        receipt, platform_config=config.section(platform), release=release,
        stage=stage, platform=platform, operation_intent=operation_intent,
        current_authority=workflow_authority(stage), recovery_run_id=recovery_run_id,
    )


def _validate_store_receipt_document(
    receipt: Mapping[str, Any], *, platform_config: Mapping[str, Any],
    release: ReleaseVersion, stage: str, platform: str,
    operation_intent: Mapping[str, Any] | None,
    current_authority: Mapping[str, Any] | None = None,
    recovery_run_id: str | None = None,
) -> dict[str, Any]:
    operations = {
        ("candidate", "android"): "android_internal_upload",
        ("candidate", "ios"): "ios_testflight_internal",
        ("external-testing", "android"): "android_external_promote",
        ("external-testing", "ios"): "ios_testflight_external",
        ("production-submit", "android"): "android_production_draft",
        ("production-submit", "ios"): "ios_app_store_submit",
    }
    if not isinstance(receipt, Mapping):
        raise ValidationError("Store receipt must be a JSON object")
    _validate_json_value(dict(receipt))
    if not isinstance(stage, str) or not isinstance(platform, str):
        raise ValidationError("unsupported Store receipt stage/platform")
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
        "operationIntentSha256",
        "authorizedBy",
        "executedBy",
    }
    missing = sorted(required_common - set(receipt))
    if missing:
        raise ValidationError(f"Store receipt is missing fields: {', '.join(missing)}")
    if type(receipt["schemaVersion"]) is not int or receipt["schemaVersion"] != 3:
        raise ValidationError("Store receipt schemaVersion must be 3")
    if receipt["operation"] != operation or receipt["platform"] != platform:
        raise ValidationError("Store receipt operation/platform does not match the requested stage")
    if operation_intent is None:
        raise ValidationError("Store receipt validation requires its operation intent")
    intent = validate_operation_intent(operation_intent)
    if intent["stage"] != stage or intent["platform"] != platform or intent["version"] != {"marketing": release.name, "build": release.build}:
        raise ValidationError("Store receipt operation intent does not match this operation")
    if receipt["operationIntentSha256"] != operation_intent["integrity"]["sha256"]:
        raise ValidationError("Store receipt operation-intent hash does not match")
    authorized = _validate_workflow_authority(
        receipt["authorizedBy"], "Store receipt authorizedBy"
    )
    executed = _validate_workflow_authority(receipt["executedBy"], "Store receipt executedBy")
    if authorized != intent["authorizedBy"]:
        raise ValidationError("Store receipt authorization identity does not match intent")
    _same_workflow(authorized, executed, "Store receipt executor")
    if current_authority is not None:
        current = _authority_for_stage(current_authority, stage, "Store receipt current executor")
        if current["runId"] != authorized["runId"]:
            if recovery_run_id != authorized["runId"]:
                raise ValidationError("cross-run Store receipt use requires its original recovery_run_id")
        elif recovery_run_id is not None:
            raise ValidationError("same-run Store receipt use cannot claim cross-run recovery")
        _same_workflow(current, executed, "Store receipt reuse")
        if executed["runId"] == current["runId"]:
            if executed["attempt"] > current["attempt"]:
                raise ValidationError("Store receipt was produced by a future execution attempt")
        elif executed["runId"] != authorized["runId"] or recovery_run_id != authorized["runId"] or current["runId"] == authorized["runId"]:
            raise ValidationError("Store receipt belongs to an unauthorized workflow run")
    if executed["runId"] == authorized["runId"] and executed["attempt"] < authorized["attempt"]:
        raise ValidationError("Store receipt execution predates the operation intent")
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
            allowed.update({"externalGroup", "betaReviewState", "autoNotifyEnabled"})
        elif stage == "production-submit":
            allowed.update({"automaticRelease", "submissionState", "appStoreVersionId", "reviewSubmissionId", "storeStateSha256"})
        else:
            allowed.add("autoNotifyEnabled")
        if stage != "candidate" and receipt.get("result") == "operator_authorized_retry":
            allowed.add("createRetry")
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
    outcome = _normalized_outcome(receipt["result"], stage=stage, platform=platform)
    _validate_recovery_outcome({**receipt, "outcome": outcome}, stage=stage, platform=platform)
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
        _validate_play_store_state(
            receipt.get("storeState"),
            stage=stage,
            outcome=outcome,
            store_edit_id=receipt.get("storeEditId"),
        )
        _validate_play_state_intent(receipt["storeState"], intent)
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
        if receipt["processingState"] != "VALID":
            raise ValidationError("Apple Store receipt must prove VALID processing")
        if stage != "candidate" and receipt["buildResourceId"] != intent["storePrecondition"]["snapshot"]["build"]["id"]:
            raise ValidationError("Apple Store receipt substituted a different candidate build")
        if stage != "production-submit" and receipt.get("autoNotifyEnabled") is not False:
            raise ValidationError("Apple Store receipt must prove automatic tester notification is disabled")
        if outcome == "operator-authorized-create-retry":
            _validate_create_retry(receipt.get("createRetry"), operation_intent=operation_intent, executed_by=executed)
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
            if not isinstance(receipt["state"], str) or receipt["state"] not in {
                "submitted-for-review",
                "in-review",
                "approved",
                "pending-developer-release",
            }:
                raise ValidationError("App Store production readback state is not submission evidence")
            for field in ("appStoreVersionId", "reviewSubmissionId"):
                if not isinstance(receipt.get(field), str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,255}", receipt[field]):
                    raise ValidationError(f"App Store production receipt lacks exact {field}")
            if not isinstance(receipt.get("storeStateSha256"), str) or not HEX_SHA256_RE.fullmatch(receipt["storeStateSha256"]):
                raise ValidationError("App Store production receipt lacks its final complete public state digest")
            production_before = intent["storePrecondition"]["snapshot"]["production"]
            if production_before is not None and receipt["appStoreVersionId"] != production_before["id"]:
                raise ValidationError("App Store production receipt substituted its version resource")
        elif stage == "external-testing":
            if not isinstance(receipt["state"], str) or receipt["state"] not in {
                "available-to-testers",
                "submitted-for-review",
                "in-review",
                "approved",
            }:
                raise ValidationError(
                    "External TestFlight receipt lacks an allowed explicit review/testing state"
                )
        elif not isinstance(receipt["state"], str) or receipt["state"] not in {"processed", "available-to-testers"}:
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


def workflow_authority(stage: str) -> dict[str, Any]:
    """Return the caller and reusable-workflow identity for this protected dispatch."""

    expected_paths = {
        "candidate": (
            ".github/workflows/mobile-candidate.yml",
            ".github/workflows/reusable-candidate.yml",
        ),
        "external-testing": (
            ".github/workflows/mobile-external-testing.yml",
            ".github/workflows/reusable-external-testing.yml",
        ),
        "production-submit": (
            ".github/workflows/mobile-production-submit.yml",
            ".github/workflows/reusable-production-submit.yml",
        ),
    }
    if stage not in expected_paths:
        raise ValidationError(f"unsupported workflow authority stage: {stage}")
    workflow = os.environ.get("GITHUB_WORKFLOW")
    run_id = os.environ.get("GITHUB_RUN_ID")
    attempt = os.environ.get("GITHUB_RUN_ATTEMPT")
    caller_path = os.environ.get("MOBILE_RELEASE_CALLER_WORKFLOW_PATH")
    reusable_repository = os.environ.get("MOBILE_RELEASE_REUSABLE_WORKFLOW_REPOSITORY")
    reusable_path = os.environ.get("MOBILE_RELEASE_REUSABLE_WORKFLOW_PATH")
    reusable_commit = os.environ.get("MOBILE_RELEASE_TOOLING_SHA")
    head_sha = os.environ.get("MOBILE_RELEASE_DISPATCH_SHA") or os.environ.get("GITHUB_SHA")
    ref = os.environ.get("MOBILE_RELEASE_DISPATCH_REF") or os.environ.get("GITHUB_REF")
    event = os.environ.get("GITHUB_EVENT_NAME")
    caller_expected, reusable_expected = expected_paths[stage]
    if caller_path != caller_expected or reusable_path != reusable_expected:
        raise ValidationError("workflow authority paths do not match the requested release stage")
    value = {
        "workflow": workflow,
        "callerPath": caller_path,
        "reusableRepository": reusable_repository,
        "reusablePath": reusable_path,
        "reusableCommit": reusable_commit,
        "runId": run_id,
        "attempt": int(attempt, 10) if attempt and re.fullmatch(r"[1-9][0-9]*", attempt) else 0,
        "headSha": head_sha,
        "ref": ref,
        "event": event,
    }
    return _authority_for_stage(value, stage, "workflow authority")


def _intent_destination(config: ReleaseConfig, stage: str, platform: str) -> dict[str, Any]:
    section = config.section(platform)
    if platform == "android":
        channel = {
            "candidate": "internal",
            "external-testing": section.get("externalTrack", {}).get("name"),
            "production-submit": "production",
        }[stage]
        return {
            "channel": channel,
            "releaseStatus": "draft" if stage == "production-submit" else "completed",
        }
    return {
        "channel": {
            "candidate": "testflight-internal",
            "external-testing": "testflight-external",
            "production-submit": "app-store-review",
        }[stage],
        **({"automaticRelease": False} if stage == "production-submit" else {}),
    }


def _intent_configuration(config: ReleaseConfig, metadata_sha256: str) -> dict[str, str]:
    try:
        relative = config.path.relative_to(config.root).as_posix()
    except ValueError as error:
        raise ValidationError("configuration file must live in the caller repository") from error
    if relative != "release/mobile-release.json":
        raise ValidationError("CI evidence requires configuration at release/mobile-release.json")
    return {
        "path": relative,
        "sha256": sha256_file(config.path),
        "metadataSha256": metadata_sha256,
    }


def _validate_external_locale_scope(intent: Mapping[str, Any], config: ReleaseConfig) -> None:
    """Config-aware authorization, not a reinterpretation of historical shape."""
    if intent["platform"] != "ios" or intent["stage"] != "external-testing":
        return
    external = intent["storePrecondition"]["snapshot"]["external"]
    before = {item["locale"]: item["whatsNew"] for item in external["localizations"]}
    target = {item["locale"]: item["whatsNew"] for item in external["targetLocalizations"]}
    configured = set(config.section("metadata")["iosLocales"])
    if set(target) != set(before) | configured or any(target[locale] != text for locale, text in before.items() if locale not in configured):
        raise ValidationError("TestFlight intent must preserve unconfigured locales and target exactly the configured locale scope")


def _validate_android_note_scope(intent: Mapping[str, Any], config: ReleaseConfig) -> None:
    if intent["platform"] == "android" and intent["stage"] == "production-submit":
        target = intent["storePrecondition"]["snapshot"]["targetRelease"]["releaseNotes"]
        if target != android_release_notes(config):
            raise ValidationError("Play intent release notes differ from configured locales/committed-build text")


def build_operation_intent(
    *,
    config: ReleaseConfig,
    release: ReleaseVersion,
    git: GitContext,
    stage: str,
    platform: str,
    confirmation: str,
    metadata_sha256: str,
    store_precondition: Mapping[str, Any],
    artifacts: list[dict[str, Any]] | None = None,
    signing_evidence: Mapping[str, Any] | None = None,
    candidate_manifest: Mapping[str, Any] | None = None,
    candidate_receipt: Mapping[str, Any] | None = None,
    external_receipt: Mapping[str, Any] | None = None,
    private_state_commitments: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the immutable authorization that must exist before Store mutation."""

    if stage == "candidate":
        candidate_source = _source(git, include_ref=True)
        predecessors: dict[str, str] = {}
    else:
        if candidate_manifest is None or candidate_receipt is None:
            raise ValidationError(f"{stage} intent requires candidate evidence")
        candidate_payload = verify_sealed(candidate_manifest)
        candidate_source = dict(candidate_payload["source"])
        predecessors = {
            "candidateManifestSha256": candidate_manifest["integrity"]["sha256"],
            "candidateReceiptSha256": candidate_receipt["integrity"]["sha256"],
        }
        if stage == "production-submit":
            if external_receipt is None:
                raise ValidationError("production intent requires external-testing evidence")
            predecessors["externalReceiptSha256"] = external_receipt["integrity"]["sha256"]
    section = config.section(platform)
    identity_key = "applicationId" if platform == "android" else "bundleId"
    application: dict[str, str] = {"id": section[identity_key]}
    if platform == "ios":
        application["storeAppId"] = str(section["appStoreAppId"])
    if stage == "candidate":
        intent_artifacts = list(artifacts or [])
        signing = [_signing_identity(config, platform, signing_evidence)]
    else:
        candidate_payload = verify_sealed(candidate_manifest)  # type: ignore[arg-type]
        intent_artifacts = list(candidate_payload["artifacts"])
        signing = list(candidate_payload["signing"])
    payload: dict[str, Any] = {
        "documentType": "store-operation-intent",
        "schemaVersion": 1,
        "stage": stage,
        "platform": platform,
        "tooling": _tooling(),
        "repository": _repository(git),
        "candidateSource": candidate_source,
        "operationSource": _source(git, include_ref=True),
        "authorizedBy": workflow_authority(stage),
        "confirmation": confirmation,
        "application": application,
        "version": {"marketing": release.name, "build": release.build},
        "destination": _intent_destination(config, stage, platform),
        "configuration": _intent_configuration(config, metadata_sha256),
        "artifacts": intent_artifacts,
        "signing": signing,
        "predecessors": predecessors,
        "storePrecondition": dict(store_precondition),
        "privateStateCommitments": dict(private_state_commitments or {}),
        "createdAt": timestamp(),
    }
    result = seal(payload)
    validate_operation_intent(result)
    _validate_external_locale_scope(payload, config)
    _validate_android_note_scope(payload, config)
    return result


def validate_operation_intent_context(
    intent_document: Mapping[str, Any],
    *,
    config: ReleaseConfig,
    release: ReleaseVersion,
    git: GitContext,
    stage: str,
    platform: str,
    confirmation: str,
    metadata_sha256: str,
    artifacts: list[dict[str, Any]] | None = None,
    signing_evidence: Mapping[str, Any] | None = None,
    candidate_manifest: Mapping[str, Any] | None = None,
    candidate_receipt: Mapping[str, Any] | None = None,
    external_receipt: Mapping[str, Any] | None = None,
    recovery_run_id: str | None = None,
) -> dict[str, Any]:
    intent = validate_operation_intent(intent_document)
    if intent["stage"] != stage or intent["platform"] != platform:
        raise ValidationError("operation intent stage/platform does not match invocation")
    if intent["confirmation"] != confirmation:
        raise ValidationError("operation intent confirmation does not match invocation")
    if intent["version"] != {"marketing": release.name, "build": release.build}:
        raise ValidationError("operation intent version does not match committed version")
    if intent["tooling"] != _tooling() or intent["repository"] != _repository(git):
        raise ValidationError("operation intent toolkit/repository identity does not match")
    operation_source = _source(git, include_ref=True)
    if intent["operationSource"] != operation_source:
        raise ValidationError("checked-out operation source does not match operation intent")
    if intent["configuration"] != _intent_configuration(config, metadata_sha256):
        raise ValidationError("operation intent configuration or metadata has changed")
    _validate_external_locale_scope(intent, config)
    _validate_android_note_scope(intent, config)
    if intent["destination"] != _intent_destination(config, stage, platform):
        raise ValidationError("operation intent destination has changed")
    section = config.section(platform)
    application = {"id": section["applicationId" if platform == "android" else "bundleId"]}
    if platform == "ios":
        application["storeAppId"] = str(section["appStoreAppId"])
    if intent["application"] != application:
        raise ValidationError("operation intent Store application identity has changed")
    if stage == "candidate" and intent["artifacts"] != list(artifacts or []):
        raise ValidationError("candidate artifacts do not match operation intent")
    if stage == "candidate" and intent["signing"] != [_signing_identity(config, platform, signing_evidence)]:
        raise ValidationError("candidate signing identity does not match operation intent")
    expected_predecessors: dict[str, str] = {}
    if stage != "candidate":
        if candidate_manifest is None or candidate_receipt is None:
            raise ValidationError("promotion intent validation requires candidate evidence")
        expected_predecessors = {
            "candidateManifestSha256": candidate_manifest["integrity"]["sha256"],
            "candidateReceiptSha256": candidate_receipt["integrity"]["sha256"],
        }
        candidate_source = verify_sealed(candidate_manifest)["source"]
        if intent["candidateSource"] != candidate_source:
            raise ValidationError("operation intent candidate source has changed")
        candidate_payload = verify_sealed(candidate_manifest)
        if (
            intent["artifacts"] != candidate_payload["artifacts"]
            or intent["signing"] != candidate_payload["signing"]
        ):
            raise ValidationError(
                "operation intent candidate artifact/signing binding has changed"
            )
        if platform == "ios" and intent["storePrecondition"]["snapshot"]["build"]["id"] != candidate_payload["storeReceipts"][0]["storeBuildId"]:
            raise ValidationError("operation intent substituted the original App Store build")
        if candidate_payload["tooling"] != intent["tooling"] or candidate_payload["repository"] != intent["repository"] or candidate_payload["configuration"] != intent["configuration"]:
            raise ValidationError("operation intent changed the candidate repository/tooling/configuration")
    if stage == "production-submit":
        if external_receipt is None:
            raise ValidationError("production intent validation requires external evidence")
        expected_predecessors["externalReceiptSha256"] = external_receipt["integrity"]["sha256"]
    if intent["predecessors"] != expected_predecessors:
        raise ValidationError("operation intent predecessor chain has changed")
    current = workflow_authority(stage)
    authorized = intent["authorizedBy"]
    if authorized["headSha"].lower() != intent["operationSource"]["commit"].lower():
        raise ValidationError("operation intent authorization head differs from operation source")
    same_run = current["runId"] == authorized["runId"]
    if recovery_run_id:
        if recovery_run_id != authorized["runId"] or same_run:
            raise ValidationError("explicit recovery run does not match the intent authorization run")
    elif not same_run:
        raise ValidationError("cross-run intent use requires an explicit recovery_run_id")
    if same_run and current["attempt"] < authorized["attempt"]:
        raise ValidationError("operation intent was prepared by a later workflow attempt")
    _same_workflow(current, authorized, "operation intent")
    if platform == "ios" and stage == "external-testing" and intent["storePrecondition"]["snapshot"]["external"]["groupName"] != section["externalTestFlightGroup"]:
        raise ValidationError("operation intent external group differs from configuration")
    if platform == "android" and stage == "production-submit" and intent["storePrecondition"]["snapshot"]["sourceTrack"] != section["externalTrack"]["name"]:
        raise ValidationError("operation intent Play source track differs from configuration")
    return intent


def private_state_commitment(*, domain: str, value: Mapping[str, Any], key: bytes) -> str:
    if not isinstance(domain, str) or not re.fullmatch(r"[a-z0-9-]{1,64}", domain):
        raise ValidationError("private-state commitment domain is invalid")
    if not isinstance(key, bytes) or len(key) != 32:
        raise ValidationError("private-state commitment key must contain exactly 256 bits")

    def validate_private(item: object, depth: int = 0) -> None:
        # Private input is never evidence. Its serializer must permit fields
        # such as demoAccountPassword without weakening the public serializer
        # or including a private field name/value in an exception.
        if depth > 64:
            raise ValidationError("private-state commitment input is invalid")
        if item is None or isinstance(item, (str, bool, int)):
            return
        if isinstance(item, list):
            for child in item:
                validate_private(child, depth + 1)
            return
        if isinstance(item, dict) and all(isinstance(name, str) for name in item):
            for child in item.values():
                validate_private(child, depth + 1)
            return
        raise ValidationError("private-state commitment input is invalid")

    if not isinstance(value, Mapping):
        raise ValidationError("private-state commitment input must be an object")
    private = dict(value)
    validate_private(private)
    try:
        encoded = json.dumps(private, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (ValueError, UnicodeEncodeError) as error:
        raise ValidationError("private-state commitment input is invalid") from error
    if len(encoded) > 1024 * 1024:
        raise ValidationError("private-state commitment input is oversized")
    message = b"mobile-release-kit:hmac:v1:" + domain.encode("ascii") + b":" + encoded
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def commitment_key_from_base64(value: str) -> bytes:
    try:
        key = b64decode(value, validate=True)
    except (ValueError, TypeError) as error:
        raise ValidationError("private-state commitment key must be canonical base64") from error
    if len(key) != 32:
        raise ValidationError("private-state commitment key must decode to exactly 32 bytes")
    return key


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
    _source(git, include_ref=True)
    workflow_authority(stage)
    timestamp()


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
    if not isinstance(state, str) or state not in {"uploaded", "processed", "available-to-testers"}:
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
        **({"autoNotifyEnabled": raw["autoNotifyEnabled"]} if platform == "ios" else {}),
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
    operation_intent: Mapping[str, Any],
    signing_evidence: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    platform_config = config.section(platform)
    identity_key = "applicationId" if platform == "android" else "bundleId"
    if store_receipt is None:
        raise ValidationError("candidate manifest requires authoritative internal Store readback")
    intent = validate_operation_intent(operation_intent)
    if intent["stage"] != "candidate" or intent["platform"] != platform:
        raise ValidationError("candidate operation intent does not match the candidate")
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
        "documentType": "candidate-manifest",
        "schemaVersion": 2,
        "operationIntentSha256": operation_intent["integrity"]["sha256"],
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
        "authorizedBy": intent["authorizedBy"],
        "executedBy": store_receipt["executedBy"],
        "producedBy": workflow_authority("candidate"),
        "createdAt": timestamp(),
    }
    result = seal(payload)
    validate_candidate_intent_binding(result, operation_intent=operation_intent)
    return result


def build_receipt(
    *,
    stage: str,
    platform: str,
    candidate_manifest: Mapping[str, Any],
    store_receipt: Mapping[str, Any],
    operation_intent: Mapping[str, Any],
    external_receipt: Mapping[str, Any] | None = None,
    previous_receipt: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    candidate_payload = verify_sealed(candidate_manifest)
    intent = validate_operation_intent(operation_intent)
    if intent["stage"] != stage or intent["platform"] != platform:
        raise ValidationError("receipt operation intent does not match its stage/platform")
    if store_receipt.get("operationIntentSha256") != operation_intent["integrity"]["sha256"]:
        raise ValidationError("Store readback is not bound to the operation intent")
    if not isinstance(platform, str) or platform not in candidate_payload.get("platforms", {}):
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
    if not isinstance(state, str) or state not in allowed_states:
        raise ValidationError("Store readback lacks an allowed explicit state")
    outcome = _normalized_outcome(store_receipt["result"], stage=stage, platform=platform)
    payload: dict[str, Any] = {
        "documentType": "store-receipt",
        "schemaVersion": 3,
        "stage": stage,
        "candidateManifestSha256": candidate_manifest["integrity"]["sha256"],
        "operationIntentSha256": operation_intent["integrity"]["sha256"],
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
        "readback": {"state": state, "observedAt": store_receipt["observedAt"], **({"autoNotifyEnabled": store_receipt["autoNotifyEnabled"]} if platform == "ios" and stage != "production-submit" else {})},
        "authorizedBy": intent["authorizedBy"],
        "executedBy": store_receipt["executedBy"],
        "producedBy": workflow_authority(stage),
        "createdAt": timestamp(),
    }
    if platform == "android":
        payload["storeState"] = dict(store_receipt["storeState"])
    if outcome == "operator-authorized-create-retry":
        payload["createRetry"] = _validate_create_retry(store_receipt.get("createRetry"), operation_intent=operation_intent, executed_by=store_receipt["executedBy"])
    if platform == "ios" and stage == "production-submit":
        for field in ("appStoreVersionId", "reviewSubmissionId", "storeStateSha256"):
            payload[field] = store_receipt[field]
    predecessor = previous_receipt or external_receipt
    if stage != "candidate":
        if predecessor is None:
            raise ValidationError(f"{stage} receipt requires its immediate predecessor receipt")
        verify_sealed(predecessor)
        payload["previousReceiptSha256"] = predecessor["integrity"]["sha256"]
    result = seal(payload)
    validate_receipt_intent_binding(result, operation_intent=operation_intent, candidate_manifest=candidate_manifest)
    return result


def validate_candidate_intent_binding(
    candidate_manifest: Mapping[str, Any], *, operation_intent: Mapping[str, Any]
) -> None:
    validate_evidence_document(candidate_manifest)
    candidate = verify_sealed(candidate_manifest)
    if candidate.get("documentType") != "candidate-manifest":
        raise ValidationError("candidate evidence has the wrong documentType")
    intent = validate_operation_intent(operation_intent)
    platform = next(iter(candidate["platforms"]))
    if intent["stage"] != "candidate" or intent["platform"] != platform:
        raise ValidationError("candidate intent has the wrong stage/platform")
    expected_identity = {"applicationId": intent["application"]["id"]}
    if platform == "ios":
        expected_identity["storeAppId"] = intent["application"]["storeAppId"]
    expected = {
        "operationIntentSha256": operation_intent["integrity"]["sha256"],
        "tooling": intent["tooling"], "repository": intent["repository"],
        "source": intent["candidateSource"], "configuration": intent["configuration"],
        "version": intent["version"], "platforms": {platform: expected_identity},
        "artifacts": intent["artifacts"], "signing": intent["signing"],
        "authorizedBy": intent["authorizedBy"],
    }
    for field, value in expected.items():
        if candidate[field] != value:
            raise ValidationError(f"candidate {field} differs from its authenticated operation intent")


def validate_candidate_raw_binding(
    candidate_manifest: Mapping[str, Any], *, store_receipt: Mapping[str, Any]
) -> None:
    """Require the original readback when completing an immutable partial manifest.

    The caller separately validates the complete raw receipt against its intent;
    this comparison never upgrades an unauthenticated raw receipt to authority.
    A later readback cannot be relabeled as the observation that made a manifest.
    """

    validate_evidence_document(candidate_manifest)
    candidate = verify_sealed(candidate_manifest)
    if candidate["documentType"] != "candidate-manifest":
        raise ValidationError("raw receipt binding requires a candidate manifest")
    if not isinstance(store_receipt, Mapping):
        raise ValidationError("candidate raw receipt must be an object")
    platform = next(iter(candidate["platforms"]))
    required = {"platform", "appIdentity", "marketingVersion", "buildNumber", "state", "observedAt", "authorizedBy", "executedBy", "operationIntentSha256"}
    required |= {"versionCode", "destinationTrack"} if platform == "android" else {"buildResourceId", "autoNotifyEnabled"}
    if not required <= set(store_receipt):
        raise ValidationError("candidate raw receipt is incomplete")
    for field in ("authorizedBy", "executedBy", "operationIntentSha256"):
        if store_receipt[field] != candidate[field]:
            raise ValidationError("candidate raw receipt authority/intent differs from its manifest")
    if store_receipt["platform"] != platform or store_receipt["marketingVersion"] != candidate["version"]["marketing"] or type(store_receipt["buildNumber"]) is not int or store_receipt["buildNumber"] != candidate["version"]["build"]:
        raise ValidationError("candidate raw receipt version/platform differs from its manifest")
    release = ReleaseVersion(name=candidate["version"]["marketing"], build=candidate["version"]["build"])
    if candidate["storeReceipts"] != [_normalized_manifest_store_receipt(store_receipt, platform=platform, release=release)]:
        raise ValidationError("candidate raw receipt differs from the original manifest observation")


def validate_receipt_raw_binding(
    receipt_document: Mapping[str, Any], *, store_receipt: Mapping[str, Any],
    operation_intent: Mapping[str, Any], candidate_manifest: Mapping[str, Any],
) -> None:
    """Compare authenticated raw readback and final evidence without ambient CI.

    Authenticity and producer job/artifact identity are checked by the workflow
    consumer before this function. This pure check deliberately does not replace
    current-run authorization in validate_store_receipt or consult Store state.
    Configuration-specific promotion policy is enforced by validate_receipt_chain.
    """

    validate_receipt_intent_binding(receipt_document, operation_intent=operation_intent, candidate_manifest=candidate_manifest)
    receipt = verify_sealed(receipt_document)
    intent = validate_operation_intent(operation_intent)
    stage, platform = receipt["stage"], receipt["platform"]
    snapshot = intent["storePrecondition"]["snapshot"]
    platform_config: dict[str, Any]
    if platform == "android":
        platform_config = {
            "applicationId": intent["application"]["id"],
            "externalTrack": {
                "name": intent["destination"]["channel"] if stage == "external-testing" else snapshot["sourceTrack"],
                "kind": "closed" if "closedTesterAssignmentVerified" in receipt["destination"] else "open",
            },
        }
    else:
        platform_config = {
            "bundleId": intent["application"]["id"],
            "appStoreAppId": intent["application"]["storeAppId"],
            "externalTestFlightGroup": snapshot["external"]["groupName"] if stage == "external-testing" else None,
        }
    raw = _validate_store_receipt_document(
        store_receipt, platform_config=platform_config,
        release=ReleaseVersion(name=intent["version"]["marketing"], build=intent["version"]["build"]),
        stage=stage, platform=platform, operation_intent=operation_intent,
    )
    expected: dict[str, Any] = {
        "authorizedBy": raw["authorizedBy"], "executedBy": raw["executedBy"],
        "outcome": _normalized_outcome(raw["result"], stage=stage, platform=platform),
        "storeBuildId": str(raw["versionCode"] if platform == "android" else raw["buildResourceId"]),
        "readback": {"state": raw["state"], "observedAt": raw["observedAt"]},
    }
    if platform == "android":
        expected["storeState"] = raw["storeState"]
        expected["destination"] = {"channel": raw["destinationTrack"], "releaseStatus": raw["releaseStatus"]}
        if "closedTesterAssignmentVerified" in raw:
            expected["destination"]["closedTesterAssignmentVerified"] = raw["closedTesterAssignmentVerified"]
    elif stage == "production-submit":
        expected["destination"] = {"channel": "app-store-review", "automaticRelease": raw["automaticRelease"]}
        for field in ("appStoreVersionId", "reviewSubmissionId", "storeStateSha256"):
            expected[field] = raw[field]
    else:
        expected["readback"]["autoNotifyEnabled"] = raw["autoNotifyEnabled"]
    if expected["outcome"] == "operator-authorized-create-retry":
        expected["createRetry"] = raw["createRetry"]
    for field, value in expected.items():
        if receipt[field] != value:
            raise ValidationError(f"final receipt {field} differs from its authenticated raw readback")
    if stage == "candidate":
        validate_candidate_raw_binding(candidate_manifest, store_receipt=raw)
        if candidate_manifest["producedBy"] != receipt["producedBy"]:
            raise ValidationError("candidate manifest and receipt have different final producers")


def validate_receipt_intent_binding(
    receipt_document: Mapping[str, Any], *, operation_intent: Mapping[str, Any],
    candidate_manifest: Mapping[str, Any]
) -> None:
    validate_evidence_document(receipt_document)
    validate_evidence_document(candidate_manifest)
    receipt = verify_sealed(receipt_document)
    candidate = verify_sealed(candidate_manifest)
    if receipt.get("documentType") != "store-receipt" or candidate.get("documentType") != "candidate-manifest":
        raise ValidationError("receipt/candidate evidence documentType is invalid")
    intent = validate_operation_intent(operation_intent)
    stage, platform = receipt["stage"], receipt["platform"]
    if intent["stage"] != stage or intent["platform"] != platform:
        raise ValidationError("receipt intent has the wrong stage/platform")
    if receipt["operationIntentSha256"] != operation_intent["integrity"]["sha256"] or receipt["authorizedBy"] != intent["authorizedBy"]:
        raise ValidationError("receipt authorization is not bound to the exact operation intent")
    if intent["candidateSource"] != candidate["source"] or any(intent[field] != candidate[field] for field in ("tooling", "repository", "configuration", "artifacts", "signing", "version")):
        raise ValidationError("receipt operation intent is not bound to the immutable candidate")
    identity = candidate["platforms"].get(platform)
    if identity is None or identity["applicationId"] != intent["application"]["id"] or (platform == "ios" and identity["storeAppId"] != intent["application"]["storeAppId"]):
        raise ValidationError("receipt intent application differs from the candidate")
    if receipt["candidateManifestSha256"] != candidate_manifest["integrity"]["sha256"] or receipt["storeBuildId"] != candidate["storeReceipts"][0]["storeBuildId"]:
        raise ValidationError("receipt changed the original candidate manifest/Store build")
    if any(receipt[field] != intent[field] for field in ("tooling", "repository", "version")) or receipt["source"] != {key: intent["candidateSource"][key] for key in ("commit", "tree")} or receipt["applicationId"] != intent["application"]["id"]:
        raise ValidationError("receipt source/application/tooling identity differs from the operation intent")
    destination = {key: value for key, value in receipt["destination"].items() if key != "closedTesterAssignmentVerified"}
    if destination != intent["destination"]:
        raise ValidationError("receipt destination differs from the operation intent")
    if stage == "candidate":
        if candidate["operationIntentSha256"] != receipt["operationIntentSha256"]:
            raise ValidationError("candidate receipt/manifest operation intents differ")
    else:
        predecessor_key = "candidateReceiptSha256" if stage == "external-testing" else "externalReceiptSha256"
        if intent["predecessors"]["candidateManifestSha256"] != receipt["candidateManifestSha256"] or intent["predecessors"][predecessor_key] != receipt["previousReceiptSha256"]:
            raise ValidationError("receipt predecessor differs from the operation intent")
        if platform == "ios" and intent["storePrecondition"]["snapshot"]["build"]["id"] != receipt["storeBuildId"]:
            raise ValidationError("receipt intent substituted another App Store build")
    if platform == "android":
        _validate_play_state_intent(receipt["storeState"], intent)
    if receipt["outcome"] == "operator-authorized-create-retry":
        _validate_create_retry(receipt["createRetry"], operation_intent=operation_intent, executed_by=receipt["executedBy"])


def validate_receipt_chain(
    *,
    candidate_manifest: Mapping[str, Any],
    candidate_receipt: Mapping[str, Any] | None = None,
    external_receipt: Mapping[str, Any] | None = None,
    production_receipt: Mapping[str, Any] | None = None,
    platform: str,
    config: ReleaseConfig | None = None,
    require_production_eligible_external: bool = False,
    candidate_intent: Mapping[str, Any] | None = None,
    external_intent: Mapping[str, Any] | None = None,
    production_intent: Mapping[str, Any] | None = None,
) -> None:
    if candidate_intent is None:
        raise ValidationError("candidate evidence requires its exact authenticated operation intent")
    validate_candidate_intent_binding(candidate_manifest, operation_intent=candidate_intent)
    for receipt_document in (candidate_receipt, external_receipt, production_receipt):
        if receipt_document is not None:
            validate_evidence_document(receipt_document)
    candidate = verify_sealed(candidate_manifest)
    if not isinstance(platform, str) or platform not in candidate.get("platforms", {}):
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
        validate_receipt_intent_binding(candidate_receipt, operation_intent=candidate_intent, candidate_manifest=candidate_manifest)
        receipt = verify_sealed(candidate_receipt)
        if receipt.get("stage") != "candidate" or receipt.get("platform") != platform:
            raise ValidationError("candidate receipt stage/platform mismatch")
        if receipt.get("candidateManifestSha256") != candidate_hash:
            raise ValidationError("candidate receipt is not bound to the supplied manifest")
        require_candidate_binding(receipt)
    if external_receipt is not None:
        if candidate_receipt is None:
            raise ValidationError("external receipt requires the candidate receipt")
        if external_intent is None:
            raise ValidationError("external evidence requires its exact authenticated operation intent")
        validate_receipt_intent_binding(external_receipt, operation_intent=external_intent, candidate_manifest=candidate_manifest)
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
                "available-to-testers; start a NEW external-testing dispatch after Beta Review "
                "approval using the original candidate, without recovery_run_id. "
                "Rerunning the old dispatch preserves its immutable pending receipt."
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
        if production_intent is None:
            raise ValidationError("production evidence requires its exact authenticated operation intent")
        validate_receipt_intent_binding(production_receipt, operation_intent=production_intent, candidate_manifest=candidate_manifest)
        production_intent_payload = validate_operation_intent(production_intent)
        if production_intent_payload["predecessors"]["candidateReceiptSha256"] != candidate_receipt["integrity"]["sha256"]:
            raise ValidationError("production intent candidate receipt is not the supplied predecessor")
        receipt = verify_sealed(production_receipt)
        if receipt.get("stage") != "production-submit" or receipt.get("platform") != platform:
            raise ValidationError("production receipt stage/platform mismatch")
        if receipt.get("candidateManifestSha256") != candidate_hash:
            raise ValidationError("production receipt is not bound to the supplied manifest")
        require_candidate_binding(receipt)
        if receipt.get("previousReceiptSha256") != external_receipt["integrity"]["sha256"]:
            raise ValidationError("production receipt is not bound to the external receipt")
