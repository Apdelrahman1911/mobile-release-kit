"""One explicit bounded saved-metadata report; no edits or Store readiness.

Only configured locale files, canonical image groups and three fixed iOS notes
are read. Sibling trees and other platforms are not traversed. Private input
sources and credential/session storage are never consulted. File contents and
content-derived digests (especially iOS notes) never enter the report.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import PurePosixPath
from typing import Any, cast

from ..config import (MAX_CONFIG_BYTES, MAX_VERSION_BYTES, parse_config_text,
                      parse_key_value_text, release_version_from_values)
from ..errors import ConfigurationError, ValidationError
from ..metadata import (ANDROID_NOTE_MAX_BYTES, REQUIRED_LOCALE_TEXT,
                        _reject_duplicate_json_pairs, check_metadata_text,
                        validate_android_release_note)
from ..metadata_images import (MAX_IMAGE_BYTES, MetadataImagesInputError, image_summary, image_type,
                               public_image_selection, safe_name, _types)
from ..metadata_text import (CONFIG_PATH, MAX_TEXT_BYTES, MetadataTextInputError,
                             platform_value, public_text_selection)
from . import _snapshot
from ._json import bounded_json_text
from ._release_version import _sensitive, _source_path
from .contracts import ApiError, SavedMetadataValidationResult, assurance

MAX_PARAMS_BYTES = 8 * 1024
MAX_RESULT_BYTES = 256 * 1024
MAX_ROWS = 2048
IOS_NOTES = ("review/ios-beta-notes.txt", "review/ios-notes.txt",
             "testflight/what-to-test.txt")
_TEXT_SUFFIXES = frozenset({".txt", ".md", ".json"})
_IMAGE_SUFFIXES = frozenset({".png", ".jpg", ".jpeg"})
_ERRORS = {
    "invalid_params": "Saved metadata validation requires a selected project and one platform.",
    "unavailable": "Saved metadata validation is unavailable on this platform.",
    "config_missing": "Save release/mobile-release.json before validating metadata.",
    "config_invalid": "Correct and save the project configuration before validating metadata.",
    "not_configured": "Enable the selected platform and save at least one configured locale.",
    "unsafe": "A requested metadata path or portable alias cannot be inspected safely.",
    "changed": "The selected configuration or metadata changed during this check. Run a new check.",
    "unreadable": "The selected metadata could not be read safely. No complete report was returned.",
    "limit": "The local check exceeded its bounded file, byte, entry, result or time limit. No complete report was returned.",
    "encoding": "The saved configuration is not valid UTF-8.",
    "sensitive": "The saved configuration may contain secret material. No values were returned.",
    "catalog_unavailable": "The bundled image policy is unavailable. No complete report was returned.",
    "cleanup_unknown": "Original metadata observation cleanup could not be confirmed.",
}
_READ_REASONS = {
    "snapshot.deadline": "limit", "snapshot.file-limit": "limit",
    "snapshot.file-size": "limit", "snapshot.byte-limit": "limit",
    "snapshot.entry-limit": "limit", "snapshot.unsafe-file": "unsafe",
    "snapshot.changed": "changed", "snapshot.encoding": "encoding",
}


def _refuse(reason: str) -> None:
    raise ApiError("metadata_validation_" + reason, _ERRORS[reason]) from None


def metadata_validation_available() -> bool:
    # Do not inherit qualification from the separate Windows snapshot reader.
    return _snapshot.posix_snapshot_available()


def _params(value: object) -> dict[str, Any]:
    if (type(value) is not dict or set(value) != {"root", "platform"}
            or type(value.get("root")) is not str):
        _refuse("invalid_params")
    try:
        bounded_json_text(value, max_bytes=MAX_PARAMS_BYTES, max_nodes=8, max_depth=2)
        platform_value(value["platform"])
    except (MetadataTextInputError, ConfigurationError, ValueError, TypeError, UnicodeError, RecursionError):
        _refuse("invalid_params")
    return cast(dict[str, Any], value)


def _tick(reader: _snapshot._NamedTextReads) -> None:
    if not reader.inventory.tick():
        raise _snapshot._ReadProblem("snapshot.deadline", "Metadata observation limit.")


def _append(rows: list[dict[str, Any]], row: dict[str, Any]) -> None:
    if len(rows) >= MAX_ROWS:
        raise _snapshot._ReadProblem("snapshot.file-limit", "Metadata report limit.")
    rows.append(row)


def _file(kind: str, identity: str, path: str | None, locale: str | None,
          required: bool, raw: bytes | None, codes: list[str]) -> dict[str, Any]:
    # No byte lengths, values, hashes, character counts or summaries from notes.
    issues = list(dict.fromkeys(codes))
    state = "missing" if raw is None else "invalid" if issues else "checked"
    if raw is None:
        issues = ["metadata.missing"]
    return {"kind": kind, "id": identity, "path": path, "locale": locale,
            "required": required, "state": state, "issues": issues}


def _text(reader: _snapshot._NamedTextReads, path: str, identity: str,
          locale: str | None, required: bool, kind: str = "public-text") -> dict[str, Any]:
    raw = cast(bytes | None, reader.read(path, limit=MAX_TEXT_BYTES, binary=True))
    codes: list[str] = []
    if raw is not None:
        try:
            value = raw.decode("utf-8")
        except UnicodeError:
            codes.append("metadata.utf8")
        else:
            codes.extend(code for code, _ in check_metadata_text(identity, value).issues)
            if identity.lower().endswith(".json"):
                try:
                    json.loads(value, object_pairs_hook=_reject_duplicate_json_pairs)
                except (ValueError, ValidationError, RecursionError):
                    codes.append("metadata.json")
    return _file(kind, identity, path, locale, required, raw, codes)


def _android_build(reader: _snapshot._NamedTextReads, data: dict[str, Any]) -> int | None:
    spec = data["version"]
    source = spec["source"]
    if not _source_path(source):
        raise MetadataTextInputError("unsafe")
    raw = cast(bytes | None, reader.read(source, limit=MAX_VERSION_BYTES, binary=True))
    if raw is None:
        return None
    try:
        text = raw.decode("utf-8")
        if _sensitive(text):
            return None
        return release_version_from_values(
            parse_key_value_text(text), name_key=spec["nameKey"], build_key=spec["buildKey"],
            ios_enabled=data["ios"].get("enabled") is True, source_label="saved version source",
        ).build
    except (ConfigurationError, ValueError, TypeError, UnicodeError, RecursionError):
        return None


def _android_note(reader: _snapshot._NamedTextReads, root: str,
                  locale: str, build: int | None) -> dict[str, Any]:
    if build is None:
        return {"kind": "android-note", "id": "release-notes", "path": None,
                "locale": locale, "required": True, "state": "invalid",
                "issues": ["metadata.android-version"]}
    directory = f"{root}/android/{locale}/changelogs"
    paths = (f"{directory}/{build}.txt", f"{directory}/default.txt")
    # A locale's ordinary text may fit while this deeper fallback path does not.
    # The named reader deliberately trusts its caller's admitted relative path.
    if any(not _source_path(candidate) for candidate in paths):
        raise MetadataTextInputError("unsafe")
    path = paths[0]
    raw = cast(bytes | None, reader.read(path, limit=ANDROID_NOTE_MAX_BYTES, binary=True))
    if raw is None:
        path = paths[1]
        raw = cast(bytes | None, reader.read(path, limit=ANDROID_NOTE_MAX_BYTES, binary=True))
    codes: list[str] = []
    if raw is not None:
        try:
            text = raw.decode("utf-8")
        except UnicodeError:
            codes.append("metadata.utf8")
        else:
            try:
                validate_android_release_note(text)
            except ValidationError:
                codes.append("metadata.android-note")
    # Invalid/unsafe exact-version files never fall back to a different file.
    return _file("android-note", "release-notes", path, locale, True, raw, codes)


def _image_set(reader: _snapshot._NamedTextReads, config: str, platform: str,
               locale: str, identity: str, rows: list[dict[str, Any]],
               sets: list[dict[str, Any]]) -> None:
    selection = public_image_selection(config, platform, locale, identity)
    names = reader.metadata_names(selection.folder)
    if names is None:
        return
    kind = image_type(platform, identity)
    if kind.singleton:
        # Check each canonical spelling even when absent: portable aliases of a
        # requested slot must not disappear behind an unrelated-sibling filter.
        selected = [identity + suffix for suffix in (".png", ".jpg", ".jpeg")]
    else:
        selected = sorted(name for name in names if not name.startswith(".")
                          and PurePosixPath(name).suffix.lower() in _IMAGE_SUFFIXES)
    seen: set[str] = set()
    current: list[dict[str, Any]] = []
    for name in selected:
        _tick(reader)
        if not safe_name(name):
            raise MetadataImagesInputError("unsafe")
        path = selection.relative_path(name)
        raw = cast(bytes | None, reader.read(path, limit=MAX_IMAGE_BYTES, binary=True))
        if raw is None:
            continue
        # This is the existing complete bounded read contract, not a prefix
        # disguised as a whole image. The policy still inspects headers only.
        summary, problems = image_summary(raw, name, kind)
        codes = list(problems)
        if summary["sha256"] in seen:
            codes.append("image.duplicate")
        seen.add(summary["sha256"])
        row = _file("image", identity, path, locale, False, raw, codes)
        _append(rows, row)
        current.append(row)
    if not current:
        return
    issues = ["image.count"] if len(current) > kind.max_count else []
    if any("image.duplicate" in row["issues"] for row in current):
        issues.append("image.duplicate")
    _append(sets, {"locale": locale, "id": identity, "count": len(current),
                   "required": False, "issues": issues})


def _outcome(reader: _snapshot._NamedTextReads, platform: str
             ) -> tuple[str | None, dict[str, Any] | None]:
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
    locales = data["metadata"][platform + "Locales"]
    if data[platform].get("enabled") is not True or not locales:
        return "not_configured", None
    locales = sorted(locales)
    selections = []
    for locale in locales:
        _tick(reader)
        selections.append(public_text_selection(config, platform, locale))
    root = selections[0].metadata_root
    types = tuple(kind.identity for kind in _types() if kind.platform == platform)
    build = _android_build(reader, data) if platform == "android" else None
    rows: list[dict[str, Any]] = []
    sets: list[dict[str, Any]] = []
    for selection in selections:
        _tick(reader)
        locale = selection.locale
        directory = f"{root}/{platform}/{locale}"
        names = reader.metadata_names(directory) or ()
        required = REQUIRED_LOCALE_TEXT[platform]
        for identity, path in zip(selection.ids, selection.paths):
            _append(rows, _text(reader, path, identity, locale, True))
        # Only direct public text/JSON metadata is added; no arbitrary child
        # directory is traversed. Hidden and unsupported user extras are left alone.
        for name in sorted(names):
            if name in required or name.startswith(".") or PurePosixPath(name).suffix.lower() not in _TEXT_SUFFIXES:
                continue
            path = directory + "/" + name
            if not _source_path(path):
                raise MetadataTextInputError("unsafe")
            _append(rows, _text(reader, path, name, locale, False))
        if platform == "android":
            _append(rows, _android_note(reader, root, locale, build))
        for identity in types:
            _tick(reader)
            _image_set(reader, config, platform, locale, identity, rows, sets)
    if platform == "ios":
        for name in IOS_NOTES:
            _append(rows, _text(reader, root + "/" + name, PurePosixPath(name).name,
                               None, True, "ios-note"))
    valid = all(row["state"] == "checked" for row in rows) and all(not row["issues"] for row in sets)
    result = {"schemaVersion": 1, "platform": platform, "metadataRoot": root,
              "locales": locales, "androidBuild": build,
              "savedConfig": {"bytes": len(config_raw), "sha256": hashlib.sha256(config_raw).hexdigest()},
              "scope": "configured-locales-canonical-images-fixed-notes",
              "observationScope": "single-request-non-atomic",
              "valid": valid, "state": "checked" if valid else "issues",
              "files": rows, "imageSets": sets, "assurance": assurance("static-text")}
    bounded_json_text(result, max_bytes=MAX_RESULT_BYTES, max_nodes=32_768, max_depth=8)
    return None, result


def validate_saved_metadata(params: object) -> SavedMetadataValidationResult:
    supplied = _params(params)
    if not metadata_validation_available():
        _refuse("unavailable")
    inventory = _snapshot._Inventory()
    try:
        root = _snapshot.validate_root(supplied["root"])
        with _snapshot._root_handles(root, inventory) as descriptor:
            with _snapshot._named_text_reads(descriptor, inventory) as reader:
                # Expected negative outcomes take the same normal-return POST
                # route. They cannot skip original parent/absence/roster rechecks.
                try:
                    reason, result = _outcome(reader, supplied["platform"])
                except (MetadataTextInputError, MetadataImagesInputError) as error:
                    reason, result = error.reason, None
                except _snapshot._ReadProblem as error:
                    reason, result = _READ_REASONS.get(error.code, "unreadable"), None
                except (ConfigurationError, ValueError, TypeError, UnicodeError, RecursionError):
                    reason, result = "limit", None
                except OSError:
                    reason, result = "unreadable", None
        if inventory.partial or not inventory.root_settled:
            _refuse("changed" if any(row["code"] == "snapshot.changed" for row in inventory.issues) else "limit")
        if reason is not None:
            _refuse(reason if reason in _ERRORS else "unsafe")
        if result is None:
            _refuse("unreadable")
        return cast(SavedMetadataValidationResult, result)
    except _snapshot._DescriptorCleanupError:
        _refuse("cleanup_unknown")
    except _snapshot._ReadProblem as error:
        _refuse(_READ_REASONS.get(error.code, "unreadable"))
    except ApiError as error:
        reason = error.code.removeprefix("metadata_validation_")
        if error.code.startswith("metadata_validation_") and reason in _ERRORS:
            _refuse(reason)
        _refuse({"invalid_params": "invalid_params", "unsafe_path": "unsafe",
                 "snapshot_unavailable": "unreadable"}.get(error.code, "unreadable"))
    except OSError:
        _refuse("unreadable")
