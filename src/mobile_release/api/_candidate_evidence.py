"""Three local candidate documents, not authenticated release or artifact history.

Native supplies a separately selected, purpose-bound root and its original
identity. No document can direct another read. Business rules stay in the pure
provenance validators; this adapter owns only admission, custody and projection.
"""
from __future__ import annotations

import json
import os
import re
import sys
import unicodedata
from typing import Any, NoReturn, cast

from ..errors import ValidationError
from ..provenance import (validate_evidence_document, validate_operation_intent,
                          validate_receipt_chain, verify_sealed)
from . import _snapshot
from .contracts import (ApiError, CandidateEvidenceAssurance,
                        CandidateEvidenceDocument, CandidateEvidenceResult,
                        CandidateEvidenceSummary)

DOCUMENTS = (
    ("manifest", "candidate-manifest.json", "candidate-manifest", 2),
    ("receipt", "candidate-receipt.json", "store-receipt", 3),
    ("intent", "operation/candidate-operation-intent.json", "store-operation-intent", 1),
)
MAX_DOCUMENT_BYTES = 2 * 1024 * 1024
MAX_TOTAL_BYTES = 6 * 1024 * 1024
MAX_DOCUMENT_NODES = 20_000
MAX_TOTAL_NODES = 60_000
MAX_DOCUMENT_DEPTH = 32
MAX_DECIMAL_DIGITS = 64
MAX_RESULT_BYTES = 64 * 1024
MAX_RESULT_NODES = 2048
MAX_RESULT_DEPTH = 8
MAX_ARTIFACTS = 5
_ROLE_ORDER = (
    "android-aab", "android-mapping", "android-native-symbols", "ios-ipa",
    "ios-archive", "ios-dsyms", "store-metadata", "validation-report",
)
_U64 = re.compile(r"(?:0|[1-9][0-9]{0,19})\Z", re.ASCII)
_POSITIVE_DECIMAL = re.compile(r"[1-9][0-9]*\Z", re.ASCII)
_HEX40 = re.compile(r"[0-9A-Fa-f]{40}\Z", re.ASCII)
_HEX64 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_ERRORS = {
    "invalid_params": "Candidate evidence input has an unsupported shape or size.",
    "artifacts_unavailable": "Local candidate evidence inspection is unavailable.",
    "artifacts_unsafe": "The selected evidence paths cannot be read safely.",
    "artifacts_changed": "The selected evidence folder or documents changed during observation.",
    "artifacts_unreadable": "The selected evidence documents could not be read.",
    "artifacts_encoding": "A selected evidence document is not valid UTF-8.",
    "artifacts_limit": "The evidence observation exceeds a supported input or projection limit.",
    "artifacts_deadline": "The original evidence observation reached its time limit.",
    "artifacts_cleanup_unknown": "Original evidence observation cleanup could not be confirmed.",
}
_READ_ERRORS = {
    "snapshot.deadline": "artifacts_deadline",
    "snapshot.file-limit": "artifacts_limit",
    "snapshot.file-size": "artifacts_limit",
    "snapshot.byte-limit": "artifacts_limit",
    "snapshot.entry-limit": "artifacts_limit",
    "snapshot.unsafe-file": "artifacts_unsafe",
    "snapshot.changed": "artifacts_changed",
    "snapshot.encoding": "artifacts_encoding",
}


class _Refusal(Exception):
    """Internal closed reason; never retain or render rejected document values."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


class _InvalidDocument(ValueError):
    pass


def _refuse(code: str) -> NoReturn:
    raise ApiError(code, _ERRORS[code]) from None


def candidate_evidence_observation_available() -> bool:
    # A new narrow Linux reader, not an opt-in to another staged native profile.
    return sys.platform.startswith("linux") and _snapshot.posix_snapshot_available()


def _params(params: object) -> tuple[str, tuple[int, ...]]:
    if (type(params) is not dict or any(type(key) is not str for key in params)
            or set(params) != {"root", "expectedRoot"} or type(params["root"]) is not str):
        _refuse("invalid_params")
    expected = params["expectedRoot"]
    if (type(expected) is not dict or any(type(key) is not str for key in expected)
            or set(expected) != {"device", "inode", "mode", "uid", "gid"}):
        _refuse("invalid_params")
    numbers: list[int] = []
    for name in ("device", "inode"):
        value = expected[name]
        if (type(value) is not str or len(value) > 20 or _U64.fullmatch(value) is None
                or int(value) > (1 << 64) - 1):
            _refuse("invalid_params")
        numbers.append(int(value))
    for name in ("mode", "uid", "gid"):
        value = expected[name]
        if type(value) is not int or not 0 <= value <= (1 << 32) - 1:
            _refuse("invalid_params")
        numbers.append(value)
    return params["root"], tuple(numbers)


def _tick(inventory: _snapshot._Inventory) -> None:
    if not inventory.tick():
        raise _Refusal("artifacts_deadline")


def _pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, child in items:
        if key in value:
            raise _InvalidDocument() from None
        value[key] = child
    return value


def _integer(text: str) -> int:
    if len(text) - int(text.startswith("-")) > MAX_DECIMAL_DIGITS:
        raise _Refusal("artifacts_limit")
    return int(text)


def _not_integer(_text: str) -> NoReturn:
    raise _InvalidDocument() from None


def _nodes(value: object, inventory: _snapshot._Inventory, *, maximum: int, depth_limit: int) -> int:
    """Postdecode admission; byte limits, not this walk, bound decoder input."""
    pending = [(value, 1)]
    count = 0
    while pending:
        _tick(inventory)
        item, depth = pending.pop()
        count += 1
        if count > maximum or depth > depth_limit:
            raise _Refusal("artifacts_limit")
        if type(item) is dict:
            if count + len(pending) + 2 * len(item) > maximum:
                raise _Refusal("artifacts_limit")
            for key, child in item.items():
                pending.extend(((key, depth + 1), (child, depth + 1)))
        elif type(item) is list:
            if count + len(pending) + len(item) > maximum:
                raise _Refusal("artifacts_limit")
            pending.extend((child, depth + 1) for child in item)
    return count


def _document(text: str, inventory: _snapshot._Inventory) -> tuple[dict[str, Any], int]:
    _tick(inventory)
    try:
        value = json.loads(text, object_pairs_hook=_pairs, parse_int=_integer,
                           parse_float=_not_integer, parse_constant=_not_integer)
    except RecursionError:
        raise _Refusal("artifacts_limit") from None
    except ValueError:
        raise _InvalidDocument() from None
    _tick(inventory)
    count = _nodes(value, inventory, maximum=MAX_DOCUMENT_NODES, depth_limit=MAX_DOCUMENT_DEPTH)
    if type(value) is not dict:
        raise _InvalidDocument() from None
    return value, count


def _validate(document: dict[str, Any], kind: str, document_type: str, version: int,
              inventory: _snapshot._Inventory) -> dict[str, Any]:
    # Fixed role admission, not a duplicate implementation of provenance policy.
    if (document.get("documentType") != document_type
            or type(document.get("schemaVersion")) is not int
            or document["schemaVersion"] != version
            or (kind != "manifest" and document.get("stage") != "candidate")):
        raise _InvalidDocument() from None
    _tick(inventory)
    if kind == "intent":
        payload = validate_operation_intent(document)
    else:
        validate_evidence_document(document)
        _tick(inventory)
        payload = verify_sealed(document)
    _tick(inventory)
    return payload


def _display_text(value: object, *, characters: int, byte_limit: int) -> str:
    if type(value) is not str or not 1 <= len(value) <= characters:
        raise _Refusal("artifacts_limit")
    try:
        if (len(value.encode("utf-8")) > byte_limit
                or any(unicodedata.category(char) in {"Cc", "Cf", "Cs"} for char in value)):
            raise _Refusal("artifacts_limit")
    except UnicodeError:
        raise _Refusal("artifacts_limit") from None
    return value


def _decimal(value: object) -> str:
    text = str(value) if type(value) is int else value
    if (type(text) is not str or len(text) > MAX_DECIMAL_DIGITS
            or _POSITIVE_DECIMAL.fullmatch(text) is None):
        raise _Refusal("artifacts_limit")
    return text


def _digest(value: object, *, git: bool = False) -> str:
    if type(value) is not str or (_HEX40 if git else _HEX64).fullmatch(value) is None:
        # This would contradict the reused validators, not authorize a new shape.
        raise _Refusal("artifacts_unavailable")
    return value


def _summary(manifest: dict[str, Any], documents: dict[str, dict[str, Any]]) -> CandidateEvidenceSummary:
    platform = next(iter(manifest["platforms"]))
    artifacts = manifest["artifacts"]
    if len(artifacts) > MAX_ARTIFACTS or any(item["logicalName"] not in _ROLE_ORDER for item in artifacts):
        raise _Refusal("artifacts_limit")
    runs = {
        name: {"runId": _decimal(manifest[name]["runId"]), "attempt": _decimal(manifest[name]["attempt"])}
        for name in ("authorizedBy", "executedBy", "producedBy")
    }
    return cast(CandidateEvidenceSummary, {
        "platform": platform,
        "applicationId": _display_text(manifest["platforms"][platform]["applicationId"], characters=255, byte_limit=1024),
        "version": {"marketing": _display_text(manifest["version"]["marketing"], characters=64, byte_limit=256),
                    "build": manifest["version"]["build"]},
        "source": {"commit": _digest(manifest["source"]["commit"], git=True),
                   "tree": _digest(manifest["source"]["tree"], git=True)},
        "artifacts": [{"logicalName": item["logicalName"], "declaredBytes": _decimal(item["size"]),
                       "sha256": _digest(item["sha256"])}
                      for item in sorted(artifacts, key=lambda item: _ROLE_ORDER.index(item["logicalName"]))],
        "recordedRuns": runs,
        "documentPayloadSha256": {kind: _digest(documents[kind]["integrity"]["sha256"])
                                  for kind in ("manifest", "receipt", "intent")},
    })


def _assurance() -> CandidateEvidenceAssurance:
    return {
        "level": "local-document-consistency", "documentsOnly": True,
        "artifactBytesVerified": False, "workflowAuthenticated": False,
        "storeStateObserved": False, "comparedWithSourceProject": False,
        "releaseReady": False, "recoveryAuthorized": False,
    }


def _read_outcome(reader: _snapshot._NamedTextReads, inventory: _snapshot._Inventory) -> CandidateEvidenceResult:
    rows: list[CandidateEvidenceDocument] = []
    documents: dict[str, dict[str, Any]] = {}
    manifest: dict[str, Any] | None = None
    total_nodes = 0
    for kind, relative, document_type, version in DOCUMENTS:
        text = reader.read(relative, limit=MAX_DOCUMENT_BYTES)
        if inventory.counts["sourceBytes"] > MAX_TOTAL_BYTES:
            raise _Refusal("artifacts_limit")
        row = cast(CandidateEvidenceDocument, {"kind": kind, "state": "missing"})
        rows.append(row)
        if text is None:
            continue
        row["state"] = "invalid"
        try:
            document, count = _document(text, inventory)
            total_nodes += count
            if total_nodes > MAX_TOTAL_NODES:
                raise _Refusal("artifacts_limit")
            payload = _validate(document, kind, document_type, version, inventory)
        except (_InvalidDocument, ValidationError):
            # Fixed DATA outcome, never the provenance exception's private text.
            _tick(inventory)
            continue
        documents[kind] = document
        if kind == "manifest":
            manifest = payload
        row["state"] = "valid"
    result: CandidateEvidenceResult = {
        "schemaVersion": 1, "outcome": "invalid", "documents": rows,
        "summary": None, "assurance": _assurance(),
    }
    if any(row["state"] == "invalid" for row in rows):
        return result
    if any(row["state"] == "missing" for row in rows):
        result["outcome"] = "incomplete"
        return result
    if manifest is None:
        raise _Refusal("artifacts_unavailable")
    _tick(inventory)
    try:
        validate_receipt_chain(candidate_manifest=documents["manifest"],
                               candidate_receipt=documents["receipt"],
                               candidate_intent=documents["intent"],
                               platform=next(iter(manifest["platforms"])), config=None)
    except ValidationError:
        result["outcome"] = "inconsistent"
        _tick(inventory)
        return result
    _tick(inventory)
    result["summary"] = _summary(manifest, documents)
    result["outcome"] = "consistent"
    _tick(inventory)
    return result


def _failure(error: Exception, inventory: _snapshot._Inventory) -> str:
    if isinstance(error, _snapshot._DescriptorCleanupError):
        return "artifacts_cleanup_unknown"
    if isinstance(error, _Refusal):
        return error.code
    if isinstance(error, _snapshot._ReadProblem):
        # The shared alias helper reports entry-limit for either entry or time
        # exhaustion; retain the first cooperative deadline instead of renaming it.
        if inventory.stopped and any(item["code"] == "snapshot.deadline" for item in inventory.issues):
            return "artifacts_deadline"
        return _READ_ERRORS.get(error.code, "artifacts_unreadable")
    if isinstance(error, ApiError):
        if error.code in _ERRORS:
            return error.code
        if error.code == "unsafe_path":
            return "artifacts_unsafe"
        if inventory.stopped:
            return "artifacts_deadline"
        return "artifacts_unreadable"
    if isinstance(error, (RecursionError, MemoryError)):
        return "artifacts_limit"
    if isinstance(error, OSError):
        return "artifacts_unreadable"
    # Unexpected validator/adapter faults cannot become a successful observation.
    return "artifacts_unavailable"


def observe_candidate_evidence(params: object) -> CandidateEvidenceResult:
    root, expected = _params(params)
    if not candidate_evidence_observation_available():
        _refuse("artifacts_unavailable")
    inventory = _snapshot._Inventory()
    result: CandidateEvidenceResult | None = None
    failure: str | None = None
    try:
        root = _snapshot.validate_root(root)
        with _snapshot._root_handles(root, inventory) as descriptor:
            try:
                observed = os.fstat(descriptor)
                if (observed.st_dev, observed.st_ino, observed.st_mode, observed.st_uid, observed.st_gid) != expected:
                    raise _Refusal("artifacts_changed")
                with _snapshot._named_text_reads(descriptor, inventory) as reader:
                    try:
                        result = _read_outcome(reader, inventory)
                    except Exception as error:
                        # Even ordinary invalid/limit/refusal paths finish the
                        # original context's normal-return checks before output.
                        failure = _failure(error, inventory)
            except Exception as error:
                code = _failure(error, inventory)
                if failure != "artifacts_cleanup_unknown":
                    failure = code
        if failure != "artifacts_cleanup_unknown":
            if any(item["code"] == "snapshot.changed" for item in inventory.issues):
                failure = "artifacts_changed"
            elif inventory.stopped or inventory.partial:
                failure = "artifacts_deadline" if any(item["code"] == "snapshot.deadline" for item in inventory.issues) else "artifacts_limit"
        if failure is not None:
            _refuse(failure)
        if result is None:
            _refuse("artifacts_unavailable")
        # These run only after every original descriptor/iterator has closed.
        _nodes(result, inventory, maximum=MAX_RESULT_NODES, depth_limit=MAX_RESULT_DEPTH)
        encoded = json.dumps(result, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8")
        if len(encoded) > MAX_RESULT_BYTES:
            _refuse("artifacts_limit")
        _tick(inventory)
        return result
    except Exception as error:
        # If an outer original close failed it overrides all prior outcomes.
        _refuse(_failure(error, inventory))
