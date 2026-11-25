"""One saved-config-derived release-version/input-pair observation; never preflight.

Ordinary policy refusals remain DATA until the original named/root contexts
finish their normal-return rechecks and every original close has settled.
Comparisons describe the exact bytes read, not file custody or build consent.
"""
from __future__ import annotations

import hashlib
import unicodedata
from typing import Any, cast

from ..config import (MAX_CONFIG_BYTES, MAX_VERSION_BYTES, parse_config_text,
                      parse_key_value_text, release_version_from_values)
from ..errors import ConfigurationError
from ..metadata import check_metadata_text
from . import _snapshot
from ._json import bounded_json_text
from .contracts import ApiError, ReleaseVersionObservationResult, assurance

CONFIG_PATH = "release/mobile-release.json"
MAX_PARAMS_BYTES = 8 * 1024
MAX_RESULT_BYTES = 4 * 1024  # DTO only; the passive engine owns finite framing.
_DOS_STEMS = {"con", "prn", "aux", "nul", *(f"com{i}" for i in range(10)),
              *(f"lpt{i}" for i in range(10))}
_ERRORS = {
    "invalid_params": "Release-version input has an unsupported shape or size.",
    "unavailable": "Saved release-version observation is unavailable on this platform.",
    "config_missing": "Save the project configuration before reading the release version.",
    "config_invalid": "The saved configuration is invalid; correct it before reading the release version.",
    "source_missing": "The saved configuration's version file was not found.",
    "source_invalid": "The version file does not satisfy the saved release-version policy.",
    "unsafe": "The saved configuration or version path cannot be read safely.",
    "changed": "The saved configuration or version source changed during observation.",
    "unreadable": "The saved configuration or version source could not be read.",
    "limit": "The release-version observation exceeded a supported input or observation limit.",
    "encoding": "The saved configuration or version source is not valid UTF-8.",
    "sensitive": "The saved configuration or version source may contain secret material; no values were returned.",
    "cleanup_unknown": "Original release-version observation cleanup could not be confirmed.",
}
_READ_REASONS = {
    "snapshot.deadline": "limit", "snapshot.file-limit": "limit",
    "snapshot.file-size": "limit", "snapshot.byte-limit": "limit",
    "snapshot.entry-limit": "limit", "snapshot.unsafe-file": "unsafe",
    "snapshot.changed": "changed", "snapshot.encoding": "encoding",
}


def _refuse(reason: str) -> None:
    raise ApiError("release_version_" + reason, _ERRORS[reason]) from None


def release_version_observation_available() -> bool:
    # No inheritance from the separately staged Windows snapshot reader.
    return _snapshot.posix_snapshot_available()


def _params(params: object) -> dict[str, Any]:
    if (type(params) is not dict or any(type(key) is not str for key in params)
            or set(params) != {"root"} or type(params["root"]) is not str):
        _refuse("invalid_params")
    try:
        bounded_json_text(params, max_bytes=MAX_PARAMS_BYTES, max_nodes=8, max_depth=2)
    except (ConfigurationError, ValueError, TypeError, UnicodeError, RecursionError):
        _refuse("invalid_params")
    return cast(dict[str, Any], params)


def _source_path(value: str) -> bool:
    """Caller admission required by _NamedTextReads; no normalization or IO."""
    parts = tuple(value.split("/"))
    try:
        return (0 < len(value.encode("utf-8")) <= _snapshot.MAX_RELATIVE_BYTES
                and len(parts) <= _snapshot.MAX_DEPTH
                and not _snapshot._excluded(parts)
                and all(_snapshot._safe_component(part)
                        and not part.endswith((" ", "."))
                        and unicodedata.normalize("NFC", part) == part
                        and part.casefold() not in {"review", "testflight"}
                        and part.split(".", 1)[0].casefold() not in _DOS_STEMS
                        and not any(char in '<>"|?*' for char in part)
                        for part in parts))
    except UnicodeError:
        return False


def _sensitive(text: str) -> bool:
    # Only the existing secret guard, not Store text/URL/length policy.
    return any(code == "metadata.secret-pattern"
               for code, _ in check_metadata_text("release-version", text).issues)


def _read_outcome(reader: _snapshot._NamedTextReads) -> tuple[str | None, ReleaseVersionObservationResult | None]:
    config_raw = cast(bytes | None, reader.read(CONFIG_PATH, limit=MAX_CONFIG_BYTES, binary=True))
    if config_raw is None:
        return "config_missing", None
    try:
        config = config_raw.decode("utf-8")
    except UnicodeError:
        return "encoding", None
    if _sensitive(config):
        return "sensitive", None
    try:
        data = parse_config_text(config)
    except (ConfigurationError, ValueError, TypeError, UnicodeError, RecursionError):
        return "config_invalid", None
    spec = data["version"]
    source = spec["source"]
    if not _source_path(source):
        return "unsafe", None
    version_raw = cast(bytes | None, reader.read(source, limit=MAX_VERSION_BYTES, binary=True))
    if version_raw is None:
        return "source_missing", None
    try:
        text = version_raw.decode("utf-8")
    except UnicodeError:
        return "encoding", None
    if _sensitive(text):
        return "sensitive", None
    try:
        version = release_version_from_values(
            parse_key_value_text(text), name_key=spec["nameKey"], build_key=spec["buildKey"],
            ios_enabled=data["ios"].get("enabled") is True, source_label=source,
        )
    except (ConfigurationError, ValueError, TypeError, UnicodeError, RecursionError):
        # Includes Python's decimal-conversion digit limit; never echo inputs.
        return "source_invalid", None
    return None, {
        "schemaVersion": 2, "source": source,
        "version": {"name": version.name, "build": version.build},
        # Never hash parsed/reformatted JSON or normalized version values.
        # These remain provisional DATA until both original contexts settle.
        "savedConfig": {"bytes": len(config_raw), "sha256": hashlib.sha256(config_raw).hexdigest()},
        "savedVersion": {"bytes": len(version_raw), "sha256": hashlib.sha256(version_raw).hexdigest()},
        "observationScope": "single-request-non-atomic", "assurance": assurance("static-text"),
    }


def observe_release_version(params: object) -> ReleaseVersionObservationResult:
    supplied = _params(params)
    if not release_version_observation_available():
        _refuse("unavailable")
    inventory = _snapshot._Inventory()
    try:
        root = _snapshot.validate_root(supplied["root"])
        with _snapshot._root_handles(root, inventory) as descriptor:
            with _snapshot._named_text_reads(descriptor, inventory) as reader:
                # Do not raise/return ordinary policy outcomes inside either
                # context: that skips their original post-yield rechecks.
                reason, result = _read_outcome(reader)
        # These contexts recheck and close original resources, not replacements.
        if inventory.partial:
            _refuse("changed" if any(item["code"] == "snapshot.changed" for item in inventory.issues) else "limit")
        if reason is not None:
            _refuse(reason)
        if result is None:
            _refuse("unreadable")
        bounded_json_text(result, max_bytes=MAX_RESULT_BYTES, max_nodes=64, max_depth=4)
        return cast(ReleaseVersionObservationResult, result)
    except _snapshot._DescriptorCleanupError:
        _refuse("cleanup_unknown")
    except _snapshot._ReadProblem as error:
        _refuse(_READ_REASONS.get(error.code, "unreadable"))
    except ApiError as error:
        reason = error.code.removeprefix("release_version_")
        if error.code.startswith("release_version_") and reason in _ERRORS:
            _refuse(reason)
        _refuse({"invalid_params": "invalid_params", "unsafe_path": "unsafe",
                 "snapshot_unavailable": "unreadable"}.get(error.code, "unreadable"))
    except (ConfigurationError, ValueError, TypeError, UnicodeError, RecursionError):
        _refuse("limit")
    except OSError:
        _refuse("unreadable")
