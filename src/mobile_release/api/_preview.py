"""Bounded in-memory suggestions and redacted draft comparison.

No project/root, file bytes, revision, plan token or mutation authority enters or
leaves this module. Known structure and contextual policy come from config.py;
bundled help is not read or interpreted as executable validation policy.
"""
from __future__ import annotations

from typing import Any, cast

from ..config import (CONFIGURATION_FIELD_PATHS, CONFIGURATION_OBJECT_KEYS,
                      MAX_CONFIG_BYTES, configuration_data_equal, configuration_field_context,
                      default_config_data, validate_config_data)
from ..errors import ConfigurationError
from ._catalog import requirement_descriptors
from ._json import bounded_json_text
from .contracts import (ApiError, FieldChange, FieldContext, PreviewResult,
                        SuggestionProvenance, SuggestResult, ValidateResult,
                        ValueSummary, assurance, issue)

MAX_DOCUMENT_NODES = 8_000
MAX_DOCUMENT_DEPTH = 28
MAX_PAIR_BYTES = 768 * 1024
MAX_PAIR_NODES = 16_000
MAX_HINT_BYTES = 8 * 1024
MAX_HINT_NODES = 64
MAX_HINT_STRING_BYTES = 512
MAX_RESULT_BYTES = 128 * 1024
MAX_FIELDS = 64
MAX_CHANGES = 64

_MISSING = object()
_HINT_KEYS = frozenset({"platforms", "androidApplicationId", "iosBundleId",
                        "versionSource", "versionNameKey", "versionBuildKey"})
_VERSION_HINTS = {"versionSource": "source", "versionNameKey": "nameKey", "versionBuildKey": "buildKey"}
_IDENTITY_HINTS = {"android": ("androidApplicationId", "applicationId"), "ios": ("iosBundleId", "bundleId")}
_INVALID_DRAFT = "Configuration does not satisfy the shared core format/policy rules; review the draft and contextual field guidance."


def _admit(value: Any, *, max_bytes: int, max_nodes: int, max_depth: int) -> None:
    try:
        bounded_json_text(value, max_bytes=max_bytes, max_nodes=max_nodes, max_depth=max_depth)
    except ConfigurationError:
        # Neither arbitrary keys nor rejected values belong in public errors.
        raise ApiError("invalid_params", "Pure configuration input must fit the bounded JSON contract") from None


def _result(result: dict[str, Any]) -> None:
    try:
        bounded_json_text(result, max_bytes=MAX_RESULT_BYTES, max_nodes=8_000, max_depth=16)
    except ConfigurationError:
        raise ApiError("preview_output_limit", "The complete pure configuration result exceeds its output bound") from None


def _validate(data: dict[str, Any]) -> ValidateResult:
    try:
        validate_config_data(data)
    except ConfigurationError:
        # Shared validation may name an unknown input key. Do not relay its raw
        # exception. The caller's untouched draft, not this summary, is editable.
        return {"valid": False, "state": "invalid", "issues": [issue("config.invalid", _INVALID_DRAFT)],
                "requirements": [], "assurance": assurance("schema-policy")}
    return {"valid": True, "state": "format-valid", "issues": [],
            "requirements": requirement_descriptors(data), "assurance": assurance("schema-policy")}


def _same(first: Any, second: Any) -> bool:
    if first is _MISSING or second is _MISSING:
        return first is second
    return configuration_data_equal(first, second)


def _summary(value: Any) -> ValueSummary:
    if value is _MISSING:
        return {"present": False}
    kind = {type(None): "null", bool: "boolean", int: "number", float: "number",
            str: "string", list: "array", dict: "object"}[type(value)]
    result = cast(ValueSummary, {"present": True, "type": kind})
    if type(value) in (list, dict):
        result["count"] = len(value)
    return result


def _changes(base: dict[str, Any], draft: dict[str, Any]) -> list[FieldChange]:
    result: list[FieldChange] = []

    def visit(path: str, before: Any, after: Any) -> None:
        if _same(before, after):
            return
        if path in CONFIGURATION_OBJECT_KEYS and type(before) is dict and type(after) is dict:
            for key in sorted(CONFIGURATION_OBJECT_KEYS[path]):
                visit(f"{path}.{key}" if path else key, before.get(key, _MISSING), after.get(key, _MISSING))
            return
        # A missing or malformed known container is summarized as one intact
        # change, not reconstructed from its visible leaf controls.
        if len(result) >= MAX_CHANGES:
            raise ApiError("preview_output_limit", "The complete configuration diff exceeds its change bound")
        result.append({"path": path,
                       "operation": "add" if before is _MISSING else "remove" if after is _MISSING else "change",
                       "before": _summary(before), "after": _summary(after)})

    visit("", base, draft)
    return result


def _unreviewed(path: str, before: Any, after: Any) -> int:
    if path not in CONFIGURATION_OBJECT_KEYS:
        return 0
    old = before if type(before) is dict else {}
    new = after if type(after) is dict else {}
    known = CONFIGURATION_OBJECT_KEYS[path]
    count = sum(not _same(old.get(key, _MISSING), new.get(key, _MISSING))
                for key in (old.keys() | new.keys()) - known)
    for key in known:
        child = f"{path}.{key}" if path else key
        count += _unreviewed(child, old.get(key, _MISSING), new.get(key, _MISSING))
    return count


def preview_config(base: object, draft: object) -> PreviewResult:
    if type(draft) is not dict or (base is not None and type(base) is not dict):
        raise ApiError("invalid_params", "Preview requires an object draft and an object or null base")
    for value in (base, draft):
        _admit(value, max_bytes=MAX_CONFIG_BYTES, max_nodes=MAX_DOCUMENT_NODES, max_depth=MAX_DOCUMENT_DEPTH)
    _admit({"base": base, "draft": draft}, max_bytes=MAX_PAIR_BYTES,
           max_nodes=MAX_PAIR_NODES, max_depth=MAX_DOCUMENT_DEPTH + 1)
    old = base if base is not None else {}
    changes = _changes(old, draft)
    unreviewed = _unreviewed("", old, draft)
    fields = configuration_field_context(draft)
    if len(fields) > MAX_FIELDS:
        raise ApiError("preview_output_limit", "The complete field context exceeds its field bound")
    result: PreviewResult = {
        "schemaVersion": 1, "validation": _validate(draft),
        "comparison": {
            "baseProvided": base is not None, "kind": "compare" if base is not None else "proposed-create",
            "state": "partial" if unreviewed else "complete", "semanticallyChanged": not _same(base, draft),
            "counts": {"added": sum(item["operation"] == "add" for item in changes),
                       "changed": sum(item["operation"] == "change" for item in changes),
                       "removed": sum(item["operation"] == "remove" for item in changes)},
            "changes": changes, "unreviewedCount": unreviewed,
        },
        "fields": cast(list[FieldContext], fields), "assurance": assurance("schema-policy"),
    }
    _result(cast(dict[str, Any], result))
    return result


def suggest_config(hints: object) -> SuggestResult:
    if type(hints) is not dict or set(hints) - _HINT_KEYS:
        raise ApiError("invalid_params", "Suggestions require only the closed in-memory hint fields")
    _admit(hints, max_bytes=MAX_HINT_BYTES, max_nodes=MAX_HINT_NODES, max_depth=4)
    platforms = hints.get("platforms", [])
    if (type(platforms) is not list or len(platforms) > 2
            or any(type(item) is not str or item not in {"android", "ios"} for item in platforms)
            or len(set(platforms)) != len(platforms)):
        raise ApiError("invalid_params", "Platform hints must be a unique list of Android and/or iOS")
    for key, value in hints.items():
        if key != "platforms" and (type(value) is not str or not value
                or len(value.encode("utf-8")) > MAX_HINT_STRING_BYTES
                or any(ord(char) < 32 or ord(char) == 127 for char in value)):
            raise ApiError("invalid_params", "Scalar hints must be bounded nonempty text without controls")
    discovered: dict[str, Any] = {key: hints[key] for key in _VERSION_HINTS if key in hints}
    hinted: set[str] = {f"version.{field}" for key, field in _VERSION_HINTS.items() if key in hints}
    examples: set[str] = set()
    for platform, (hint_key, field) in _IDENTITY_HINTS.items():
        if hint_key in hints and platform not in platforms:
            raise ApiError("invalid_params", "An identity hint requires its platform to be explicitly listed")
        if platform in platforms:
            # Nonempty evidence marker matches the existing pure proposal's
            # platform-presence convention, without inventing an identifier.
            discovered[platform] = {"detected": True}
            hinted.add(f"{platform}.enabled")
            if hint_key in hints:
                discovered[platform][field] = hints[hint_key]
                hinted.add(f"{platform}.{field}")
            else:
                examples.add(f"{platform}.{field}")
    draft = default_config_data(discovered)
    provenance: list[SuggestionProvenance] = []
    for item in configuration_field_context(draft):
        if not item["present"]:
            continue
        path = item["path"]
        if path in examples:
            source, reason = "example", "Example identifier only; replace it with the intended application identity."
        elif path in hinted:
            source, reason = "hint", "Supplied static hint only; project files, identities and tools were not verified."
        else:
            source, reason = "default", "Bundled default suggestion, not an observed project value; review before adopting."
        provenance.append(cast(SuggestionProvenance, {"path": path, "source": source, "reason": reason}))
    if len(provenance) > MAX_FIELDS or len(CONFIGURATION_FIELD_PATHS) > MAX_FIELDS:
        raise ApiError("preview_output_limit", "The complete suggestion provenance exceeds its field bound")
    result: SuggestResult = {
        "schemaVersion": 1, "draft": draft, "platformSelectionRequired": not platforms,
        "provenance": provenance, "validation": _validate(draft), "assurance": assurance("schema-policy"),
    }
    _result(cast(dict[str, Any], result))
    return result
