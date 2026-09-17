"""Closed, versioned credential guidance from the selected package only.

This is static presentation data, not credential admission or requiredness.
credential_requirements remains the sole stage/platform/purpose selector. No
credential value, source file, keyring or native/service capability is observed.
"""
from __future__ import annotations

import json
from importlib.resources import files
from typing import Any, cast

from ..credential_policy import CREDENTIAL_POLICY_VERSION, material_size_limit
from ..errors import ConfigurationError
from ._json import bounded_json_text
from .contracts import ApiError, CredentialGuide

MAX_RESOURCE_BYTES = 128 * 1024
MAX_RESOURCE_NODES = 8_000
MAX_RESOURCE_DEPTH = 12
_RESOURCE_ERROR = "The bundled credential guide is unavailable or invalid; no alternate resource was used"
_HELP_FIELDS = frozenset({"label", "requiredness", "requiredWhen", "what", "why", "where", "format", "failure"})
_KIND_FIELDS = frozenset({"id", "label", "platform", "defaultLabel", "fields", "plannedChecks", "notVerified"})
_FIELD_FIELDS = _HELP_FIELDS | {"id", "requirement", "alternatives", "input", "maxBytes", "suffixes"}

# A closed association with canonical core requirements, not a second selector.
# Each tuple is (field id, canonical requirement suffix, input, picker suffixes).
_KIND_LAYOUT = {
    "android-keystore": ("android", (
        ("file", "ANDROID_KEYSTORE_BASE64", "file", (".jks", ".keystore", ".p12", ".pfx")),
        ("storePassword", "ANDROID_KEYSTORE_PASSWORD", "secret", ()),
        ("keyAlias", "ANDROID_KEY_ALIAS", "text", ()),
        ("keyPassword", "ANDROID_KEY_PASSWORD", "secret", ()),
    )),
    "android-firebase": ("android", (
        ("file", "ANDROID_GOOGLE_SERVICES_JSON_BASE64", "file", (".json",)),
    )),
    "apple-p12": ("ios", (
        ("file", "APPLE_DISTRIBUTION_P12_BASE64", "file", (".p12", ".pfx")),
        ("password", "APPLE_DISTRIBUTION_P12_PASSWORD", "secret", ()),
    )),
    "apple-profile": ("ios", (
        ("file", "APPLE_PROVISIONING_PROFILE_BASE64", "file", (".mobileprovision",)),
    )),
    "asc-p8": ("ios", (
        ("file", "ASC_PRIVATE_KEY_P8_BASE64", "file", (".p8",)),
        ("keyId", "ASC_KEY_ID", "text", ()),
        ("issuerId", "ASC_ISSUER_ID", "text", ()),
    )),
    "ios-firebase": ("ios", (
        ("file", "IOS_GOOGLE_SERVICE_INFO_PLIST_BASE64", "file", (".plist",)),
    )),
    "google-wif": ("android", (
        ("provider", "GOOGLE_WIF_PROVIDER", "text", ()),
        ("serviceAccount", "GOOGLE_SERVICE_ACCOUNT", "text", ()),
    )),
    "project-read-token": ("project", (
        ("token", "PROJECT_READ_TOKEN", "secret", ()),
    )),
}
KIND_IDS = tuple(_KIND_LAYOUT)
CONTROL_IDS = ("project", "platform", "stage", "purpose", "mode", "label", "choose", "prepare",
               "review", "save", "assign", "replace", "delete", "cancel", "discard", "lock")
STATE_IDS = ("unknown", "missing", "invalid", "configured", "format-valid", "native-not-run",
             "service-not-run", "stored", "locked", "unlocked", "assigned", "stale",
             "cleanup-unknown", "unavailable")


def _require(condition: bool) -> None:
    if not condition:
        raise ValueError("Invalid closed credential guidance")


def _object(value: object, keys: set[str] | frozenset[str]) -> dict[str, Any]:
    _require(type(value) is dict and set(value) == keys)
    return cast(dict[str, Any], value)


def _text(value: object, maximum: int) -> str:
    _require(type(value) is str and 0 < len(value) <= maximum)
    text = cast(str, value)
    _require(bool(text.strip()) and len(text.encode("utf-8")) <= maximum)
    _require(all(ord(char) >= 32 and ord(char) != 127 for char in text))
    return text


def _list(value: object, count: int) -> list[Any]:
    _require(type(value) is list and len(value) == count)
    return cast(list[Any], value)


def _help(entry: dict[str, Any], *, field: bool = False) -> None:
    _text(entry["label"], 96)
    for key in ("requiredWhen", "what", "why", "where", "format", "failure"):
        _text(entry[key], 1024)
    _require(entry["requiredness"] in (("conditional",) if field else ("required", "conditional", "optional")))


def _text_list(value: object, maximum: int) -> None:
    _require(type(value) is list and 1 <= len(value) <= maximum)
    for entry in cast(list[Any], value):
        _text(entry, 512)


def _guide(value: object) -> CredentialGuide:
    guide = _object(value, {"schemaVersion", "policyVersion", "availability", "kinds", "controls", "states"})
    _require(type(guide["schemaVersion"]) is int and guide["schemaVersion"] == 1)
    _require(guide["policyVersion"] == CREDENTIAL_POLICY_VERSION and guide["availability"] == "guide-only")
    for raw_kind, identity in zip(_list(guide["kinds"], len(KIND_IDS)), KIND_IDS):
        kind = _object(raw_kind, _KIND_FIELDS)
        platform, layout = _KIND_LAYOUT[identity]
        _require(kind["id"] == identity and kind["platform"] == platform)
        _text(kind["label"], 96)
        _text(kind["defaultLabel"], 64)
        _text_list(kind["plannedChecks"], 3)
        _require(all(check.startswith("Planned only, not run: ") for check in kind["plannedChecks"]))
        _text_list(kind["notVerified"], 8)
        for raw_field, (field_id, suffix, input_kind, suffixes) in zip(_list(kind["fields"], len(layout)), layout):
            entry = _object(raw_field, _FIELD_FIELDS)
            name = "MOBILE_RELEASE_" + suffix
            alternatives = [name.removesuffix("_BASE64") + "_PATH"] if input_kind == "file" else []
            _require(entry["id"] == field_id and entry["requirement"] == name and entry["input"] == input_kind)
            _require(type(entry["alternatives"]) is list and entry["alternatives"] == alternatives)
            _require(type(entry["suffixes"]) is list and entry["suffixes"] == list(suffixes))
            if input_kind == "file":
                _require(type(entry["maxBytes"]) is int and entry["maxBytes"] == material_size_limit(name))
            else:
                _require(entry["maxBytes"] is None)
            _help(entry, field=True)
    for raw_control, identity in zip(_list(guide["controls"], len(CONTROL_IDS)), CONTROL_IDS):
        control = _object(raw_control, _HELP_FIELDS | {"id"})
        _require(control["id"] == identity)
        _help(control)
    for raw_state, identity in zip(_list(guide["states"], len(STATE_IDS)), STATE_IDS):
        state = _object(raw_state, {"id", "label", "meaning"})
        _require(state["id"] == identity)
        _text(state["label"], 96)
        _text(state["meaning"], 1024)
    return cast(CredentialGuide, guide)


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        _require(key not in result)
        result[key] = value
    return result


def _nonfinite(_value: str) -> None:
    raise ValueError("Non-finite bundled JSON")


def _read_resource_bytes() -> bytes:
    # This fixed selected-package path is never derived from a project, request,
    # URL, environment override or neighboring installation.
    with files("mobile_release.api").joinpath("data", "credential-guide-v1.json").open("rb") as source:
        return source.read(MAX_RESOURCE_BYTES + 1)


def credential_guide() -> CredentialGuide:
    try:
        raw = _read_resource_bytes()
        _require(type(raw) is bytes and 0 < len(raw) <= MAX_RESOURCE_BYTES)
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=_nonfinite)
        bounded_json_text(value, max_bytes=MAX_RESOURCE_BYTES, max_nodes=MAX_RESOURCE_NODES,
                          max_depth=MAX_RESOURCE_DEPTH)
        return _guide(value)
    except (OSError, ValueError, TypeError, UnicodeError, RecursionError, OverflowError, ConfigurationError) as error:
        raise ApiError("resource_unavailable", _RESOURCE_ERROR) from error
