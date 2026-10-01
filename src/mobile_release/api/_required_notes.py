"""Passive, bounded required-note observation and shared-policy validation.

Only the saved configuration/version select a path. Original bytes and absence
are comparison DATA, never an owner lease, write authorization or Store result.
Policy refusals settle the existing named/root rechecks before being published.
"""
from __future__ import annotations

import json
from importlib.resources import files
from typing import Any, cast

from ..config import MAX_CONFIG_BYTES, MAX_VERSION_BYTES
from ..errors import ConfigurationError
from ..metadata import check_metadata_text
from ..metadata_text import CONFIG_PATH
from ..required_notes import (KINDS, NotesContext, RequiredNotesInputError,
                              check_required_note, notes_baseline,
                              notes_configuration, notes_context,
                              notes_selection_view, required_note_selection,
                              required_note_sensitive,
                              validate_required_note_input)
from . import _snapshot
from ._json import bounded_json_text
from .contracts import (ApiError, RequiredNoteValidationResult,
                        RequiredNotesGuide, RequiredNotesObservationResult)

MAX_OBSERVE_PARAMS_BYTES = 8 * 1024
# One 64KiB note can expand sixfold when control characters are JSON-escaped.
# These local limits do not change the passive engine's request/response caps.
MAX_VALIDATE_PARAMS_BYTES = 512 * 1024
MAX_RESULT_BYTES = 512 * 1024
_ERRORS = {
    "invalid_params": "Required-note input has an unsupported shape or size.",
    "unavailable": "Saved required-note observation is unavailable on this platform.",
    "config_missing": "Save the project configuration before loading release or review notes.",
    "config_invalid": "Correct the saved project configuration before loading these notes.",
    "not_configured": "Enable the selected platform and choose a locale declared in the saved configuration.",
    "version_missing": "Save the configured release-version file before loading Android notes.",
    "version_invalid": "Correct the saved release version before loading Android notes.",
    "unsafe": "A selected configuration, version or note path cannot be read safely.",
    "changed": "A selected configuration, version, note or original absence changed during observation.",
    "unreadable": "A selected configuration, version or note could not be read.",
    "limit": "The required-note observation exceeded its disclosed editor or observation limit.",
    "encoding": "A selected configuration, version or note file is not valid UTF-8.",
    "sensitive": "A selected file may contain secret material; no contents were returned.",
    "cleanup_unknown": "Original required-note observation cleanup could not be confirmed.",
}
_READ_REASONS = {
    "snapshot.deadline": "limit", "snapshot.file-limit": "limit",
    "snapshot.file-size": "limit", "snapshot.byte-limit": "limit",
    "snapshot.entry-limit": "limit", "snapshot.unsafe-file": "unsafe",
    "snapshot.changed": "changed", "snapshot.encoding": "encoding",
}


def _refuse(reason: str) -> None:
    raise ApiError("required_notes_" + reason, _ERRORS[reason]) from None


def _params(params: object, keys: set[str], limit: int) -> dict[str, Any]:
    if (type(params) is not dict or any(type(key) is not str for key in params)
            or set(params) != keys):
        _refuse("invalid_params")
    try:
        bounded_json_text(params, max_bytes=limit, max_nodes=32, max_depth=4)
    except (ConfigurationError, ValueError, TypeError, UnicodeError, RecursionError):
        _refuse("invalid_params")
    return cast(dict[str, Any], params)


def validate_required_notes(params: object) -> RequiredNoteValidationResult:
    supplied = _params(params, {"context", "text"}, MAX_VALIDATE_PARAMS_BYTES)
    try:
        return cast(RequiredNoteValidationResult, validate_required_note_input(supplied))
    except RequiredNotesInputError:
        _refuse("invalid_params")


def required_notes_observation_available() -> bool:
    # Do not inherit the separately staged Windows snapshot reader.
    return _snapshot.posix_snapshot_available()


def _configuration_sensitive(text: str) -> bool:
    # Preserve the existing generic policy for config/version, whose contents
    # are never returned. Selected notes use the separate raw disclosure guard.
    return any(code == "metadata.secret-pattern"
               for code, _ in check_metadata_text("required-note", text).issues)


def _read_outcome(reader: _snapshot._NamedTextReads, context: NotesContext
                  ) -> tuple[str | None, RequiredNotesObservationResult | None]:
    """All ordinary policy outcomes stay DATA until the original contexts exit."""
    config_raw = cast(bytes | None, reader.read(CONFIG_PATH, limit=MAX_CONFIG_BYTES, binary=True))
    if config_raw is None:
        return "config_missing", None
    try:
        config = config_raw.decode("utf-8")
        if _configuration_sensitive(config):
            return "sensitive", None
        configured = notes_configuration(config, context.wire())
        version_raw = None
        if configured.version is not None:
            version_raw = cast(bytes | None, reader.read(
                configured.version.source, limit=MAX_VERSION_BYTES, binary=True))
            if version_raw is None:
                return "version_missing", None
            if _configuration_sensitive(version_raw.decode("utf-8")):
                return "sensitive", None
        selection = required_note_selection(configured, version_raw)
        note = cast(bytes | None, reader.read(
            selection.path, limit=selection.editor_byte_limit, binary=True))
        original: dict[str, Any] = {"state": "absent"}
        if note is not None:
            text = note.decode("utf-8")
            if required_note_sensitive(context.kind, text):
                return "sensitive", None
            original = {"state": "present", "text": text}
        counterpart = (cast(bytes | None, reader.read(
            selection.counterpart_path, limit=selection.editor_byte_limit, binary=True))
            if selection.counterpart_path is not None else None)
        # Ordinary invalid selected text remains editable. Counterpart contents
        # are never returned; its presence/validity affect Android's summary.
        return None, cast(RequiredNotesObservationResult, {
            "schemaVersion": 1,
            "selection": notes_selection_view(selection, note, counterpart),
            "baseline": notes_baseline(config_raw, version_raw, note, counterpart),
            "original": original,
            "validation": check_required_note(context.kind, note).wire(),
        })
    except UnicodeError:
        return "encoding", None
    except RequiredNotesInputError as error:
        return error.reason if error.reason in _ERRORS else "invalid_params", None


def observe_required_notes(params: object) -> RequiredNotesObservationResult:
    supplied = _params(params, {"root", "context"}, MAX_OBSERVE_PARAMS_BYTES)
    if type(supplied["root"]) is not str:
        _refuse("invalid_params")
    try:
        context = notes_context(supplied["context"])
    except RequiredNotesInputError:
        _refuse("invalid_params")
    if not required_notes_observation_available():
        _refuse("unavailable")
    inventory = _snapshot._Inventory()
    try:
        root = _snapshot.validate_root(supplied["root"])
        with _snapshot._root_handles(root, inventory) as descriptor:
            with _snapshot._named_text_reads(descriptor, inventory) as reader:
                reason, result = _read_outcome(reader, context)
        # Neither success nor ordinary refusal escapes before final original
        # rechecks and every consuming close. Read/close errors never mean absence.
        if inventory.partial:
            _refuse("changed" if any(item["code"] == "snapshot.changed" for item in inventory.issues) else "limit")
        if not inventory.root_settled:
            _refuse("changed")
        if reason is not None:
            _refuse(reason)
        if result is None:
            _refuse("unreadable")
        bounded_json_text(result, max_bytes=MAX_RESULT_BYTES, max_nodes=256, max_depth=8)
        return cast(RequiredNotesObservationResult, result)
    except _snapshot._DescriptorCleanupError:
        _refuse("cleanup_unknown")
    except _snapshot._ReadProblem as error:
        _refuse(_READ_REASONS.get(error.code, "unreadable"))
    except ApiError as error:
        reason = error.code.removeprefix("required_notes_")
        if error.code.startswith("required_notes_") and reason in _ERRORS:
            _refuse(reason)
        _refuse({"invalid_params": "invalid_params", "unsafe_path": "unsafe",
                 "snapshot_unavailable": "unreadable"}.get(error.code, "unreadable"))
    except (ConfigurationError, ValueError, TypeError, UnicodeError, RecursionError):
        _refuse("limit")
    except OSError:
        _refuse("unreadable")


_HELP = {"requiredWhen", "label", "what", "why", "where", "format", "failure"}
_ACTION_IDS = ("load", "validate", "review", "save", "import", "discard")
_AUDIENCES = ("public-play", "public-play", "apple-review", "apple-review", "testflight-testers")
_GUIDE_ERROR = "The bundled required-note guide is unavailable or invalid; no alternate resource was used"


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate guide key")
        value[key] = item
    return value


def _guide(value: object) -> RequiredNotesGuide:
    def require(condition: bool) -> None:
        if not condition:
            raise ValueError("invalid required-note guide")

    require(type(value) is dict and set(value) == {"schemaVersion", "fields", "actions"})
    guide = cast(dict[str, Any], value)
    require(type(guide["schemaVersion"]) is int and guide["schemaVersion"] == 1)
    require(type(guide["fields"]) is list and len(guide["fields"]) == len(KINDS))
    require(type(guide["actions"]) is list and len(guide["actions"]) == len(_ACTION_IDS))
    for row, identity, audience in zip(guide["fields"], KINDS, _AUDIENCES):
        require(type(row) is dict and set(row) == _HELP | {"id", "audience", "requiredness"}
                and row["id"] == identity and row["audience"] == audience
                and row["requiredness"] == "conditional")
    for row, identity in zip(guide["actions"], _ACTION_IDS):
        require(type(row) is dict and set(row) == _HELP | {"id", "requiredness"}
                and row["id"] == identity and row["requiredness"] == "optional")
    for row in [*guide["fields"], *guide["actions"]]:
        for key in _HELP:
            text = row[key]
            require(type(text) is str and bool(text.strip()) and len(text.encode("utf-8")) <= 2048
                    and all(ord(char) >= 32 and ord(char) != 127 for char in text))
    return cast(RequiredNotesGuide, guide)


def required_notes_help() -> RequiredNotesGuide:
    try:
        with files("mobile_release.api").joinpath("data", "required-notes-help-v1.json").open("rb") as source:
            raw = source.read(64 * 1024 + 1)
        if len(raw) > 64 * 1024:
            raise ValueError("guide bound")
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs)
        bounded_json_text(value, max_bytes=64 * 1024, max_nodes=512, max_depth=8)
        return _guide(value)
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, RecursionError, ConfigurationError):
        raise ApiError("resource_unavailable", _GUIDE_ERROR) from None
