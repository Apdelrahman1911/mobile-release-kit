"""Bounded named public-text observation and pure shared-policy validation.

There is no write path, general filename/root override or native import here.
Observation is all-or-error and single-request non-atomic, never a Save receipt.
"""
from __future__ import annotations

import json
from importlib.resources import files
from typing import Any, cast

from ..config import MAX_CONFIG_BYTES
from ..errors import ConfigurationError
from ..metadata import REQUIRED_LOCALE_TEXT, check_metadata_text
from ..metadata_text import (CONFIG_PATH, MAX_REQUEST_BYTES, MAX_RESULT_BYTES,
                             MAX_TEXT_BYTES, MetadataTextInputError, baseline,
                             content_digest, locale_value, platform_value,
                             public_text_selection, text_fields)
from . import _snapshot
from ._json import bounded_json_text
from .contracts import (ApiError, MetadataObservationResult, MetadataTextGuide,
                        MetadataValidationResult, assurance)

_ERRORS = {
    "invalid_params": "Metadata text input has an unsupported shape or size.",
    "unavailable": "Selected public text observation is unavailable on this platform.",
    "config_missing": "Save the project configuration before loading locale text.",
    "config_invalid": "The saved configuration is invalid; correct it before loading locale text.",
    "not_configured": "Select an enabled platform and a locale declared in the saved configuration.",
    "unsafe": "A selected public text path cannot be read safely.",
    "changed": "The selected configuration or public text changed during observation.",
    "unreadable": "The selected configuration or public text could not be read.",
    "limit": "The selected public text exceeds the bounded editor observation limit.",
    "encoding": "A selected public text file is not valid UTF-8.",
    "sensitive": "A selected public text file may contain secret material; no contents were returned.",
    "cleanup_unknown": "Original observation resource cleanup could not be confirmed.",
}
_MESSAGES = {
    "metadata.empty-text": "Public Store text must contain non-whitespace content.",
    "metadata.nul": "Public Store text must not contain NUL.",
    "metadata.placeholder": "Public Store text contains an unresolved placeholder.",
    "metadata.secret-pattern": "Public Store text may contain secret material. Remove it and rotate exposed credentials.",
    "metadata.url": "Use an absolute credential-free HTTPS URL without a query or fragment.",
    "metadata.length": "Public Store text exceeds the shared core character limit.",
}
_READ_REASONS = {
    "snapshot.deadline": "limit", "snapshot.file-limit": "limit",
    "snapshot.file-size": "limit", "snapshot.byte-limit": "limit",
    "snapshot.entry-limit": "limit", "snapshot.unsafe-file": "unsafe",
    "snapshot.changed": "changed", "snapshot.encoding": "encoding",
}


def _refuse(reason: str) -> None:
    raise ApiError("metadata_text_" + reason, _ERRORS[reason]) from None


def _params(params: object, keys: set[str]) -> dict[str, Any]:
    if type(params) is not dict or set(params) != keys:
        _refuse("invalid_params")
    try:
        bounded_json_text(params, max_bytes=MAX_REQUEST_BYTES, max_nodes=128, max_depth=8)
    except (ConfigurationError, ValueError, TypeError, UnicodeError, RecursionError):
        _refuse("invalid_params")
    return cast(dict[str, Any], params)


def validate_metadata_text(params: object) -> MetadataValidationResult:
    supplied = _params(params, {"platform", "fields"})
    try:
        platform = platform_value(supplied["platform"])
        fields = text_fields(platform, supplied["fields"])
    except MetadataTextInputError:
        _refuse("invalid_params")
    rows = []
    for identity, text in fields:
        checked = check_metadata_text(identity, text)
        rows.append({"id": identity, "valid": not checked.issues,
                     "characterCount": checked.character_count, "limit": checked.limit,
                     "issues": [{"code": code, "status": status.value, "message": _MESSAGES[code]}
                                for code, status in checked.issues]})
    valid = all(item["valid"] for item in rows)
    return cast(MetadataValidationResult, {
        "schemaVersion": 1, "platform": platform, "valid": valid,
        "state": "format-valid" if valid else "invalid", "fields": rows,
        "assurance": assurance("schema-policy"),
    })


def metadata_text_observation_available() -> bool:
    # The staged Windows reader is deliberately not inherited by this seam.
    return _snapshot.posix_snapshot_available()


def observe_metadata_text(params: object) -> MetadataObservationResult:
    supplied = _params(params, {"root", "platform", "locale"})
    try:
        platform, locale = platform_value(supplied["platform"]), locale_value(supplied["locale"])
    except MetadataTextInputError:
        _refuse("invalid_params")
    if not metadata_text_observation_available():
        _refuse("unavailable")
    inventory = _snapshot._Inventory()
    try:
        root = _snapshot.validate_root(supplied["root"])
        with _snapshot._root_handles(root, inventory) as descriptor:
            with _snapshot._named_text_reads(descriptor, inventory) as reader:
                config = reader.read(CONFIG_PATH, limit=MAX_CONFIG_BYTES)
                if config is None:
                    _refuse("config_missing")
                if any(code == "metadata.secret-pattern" for code, _ in check_metadata_text("mobile-release.json", config).issues):
                    _refuse("sensitive")
                selection = public_text_selection(config, platform, locale)
                rows = []
                originals = []
                for identity, path in zip(selection.ids, selection.paths):
                    text = reader.read(path, limit=MAX_TEXT_BYTES)
                    if text is None:
                        rows.append({"id": identity, "path": path, "state": "absent"})
                        originals.append(None)
                    else:
                        if any(code == "metadata.secret-pattern" for code, _ in check_metadata_text(identity, text).issues):
                            _refuse("sensitive")
                        raw = text.encode("utf-8")
                        originals.append(raw)
                        rows.append({"id": identity, "path": path, "state": "present",
                                     "text": text, **content_digest(raw)})
                result = {
                    "schemaVersion": 1, "platform": platform, "locale": locale,
                    "metadataRoot": selection.metadata_root,
                    "observationScope": "single-request-non-atomic",
                    "baseline": baseline(config.encode("utf-8"), selection.ids, tuple(originals)),
                    "fields": rows, "assurance": assurance("static-text"),
                }
                bounded_json_text(result, max_bytes=MAX_RESULT_BYTES, max_nodes=1024, max_depth=12)
        # Root/ancestor rechecks and every original close must settle first.
        if inventory.partial:
            _refuse("changed" if any(item["code"] == "snapshot.changed" for item in inventory.issues) else "limit")
        return cast(MetadataObservationResult, result)
    except _snapshot._DescriptorCleanupError:
        _refuse("cleanup_unknown")
    except MetadataTextInputError as error:
        _refuse(error.reason)
    except _snapshot._ReadProblem as error:
        _refuse(_READ_REASONS.get(error.code, "unreadable"))
    except ApiError as error:
        if error.code.startswith("metadata_text_"):
            raise
        _refuse({"invalid_params": "invalid_params", "unsafe_path": "unsafe",
                 "snapshot_unavailable": "unreadable"}.get(error.code, "unreadable"))
    except (ConfigurationError, UnicodeError, RecursionError):
        _refuse("limit")
    except OSError:
        _refuse("unreadable")


_HELP = {"requiredWhen", "label", "what", "why", "where", "format", "failure"}
_ACTION_IDS = ("load", "validate", "review", "save", "discard")
_GUIDE_ERROR = "The bundled metadata text guide is unavailable or invalid; no alternate resource was used"


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate guide key")
        result[key] = value
    return result


def _guide(value: object) -> MetadataTextGuide:
    def require(condition: bool) -> None:
        if not condition:
            raise ValueError("invalid metadata guide")

    require(type(value) is dict and set(value) == {"schemaVersion", "fields", "actions", "limits"})
    guide = cast(dict[str, Any], value)
    require(type(guide["schemaVersion"]) is int and guide["schemaVersion"] == 1)
    roster = tuple((platform, identity) for platform, ids in REQUIRED_LOCALE_TEXT.items() for identity in ids)
    require(type(guide["fields"]) is list and len(guide["fields"]) == len(roster))
    require(type(guide["actions"]) is list and len(guide["actions"]) == len(_ACTION_IDS))
    for row, (platform, identity) in zip(guide["fields"], roster):
        require(type(row) is dict and set(row) == _HELP | {"id", "platform", "requiredness"}
                and row["id"] == identity and row["platform"] == platform and row["requiredness"] == "required")
    for row, identity in zip(guide["actions"], _ACTION_IDS):
        require(type(row) is dict and set(row) == _HELP | {"id", "requiredness"}
                and row["id"] == identity and row["requiredness"] == "optional")
    for row in [*guide["fields"], *guide["actions"]]:
        for key in _HELP:
            text = row[key]
            require(type(text) is str and bool(text.strip()) and len(text.encode("utf-8")) <= 2048
                    and all(ord(char) >= 32 and ord(char) != 127 for char in text))
    limits = {"maxTextBytes": MAX_TEXT_BYTES, "maxCachedLocales": 32, "maxCachedTextBytes": 8 * 1024 * 1024}
    require(type(guide["limits"]) is dict and guide["limits"] == limits
            and all(type(item) is int for item in guide["limits"].values()))
    return cast(MetadataTextGuide, guide)


def metadata_text_help() -> MetadataTextGuide:
    try:
        with files("mobile_release.api").joinpath("data", "metadata-text-help-v1.json").open("rb") as source:
            raw = source.read(64 * 1024 + 1)
        if len(raw) > 64 * 1024:
            raise ValueError("guide bound")
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs)
        bounded_json_text(value, max_bytes=64 * 1024, max_nodes=512, max_depth=8)
        return _guide(value)
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, RecursionError, ConfigurationError):
        raise ApiError("resource_unavailable", _GUIDE_ERROR) from None
