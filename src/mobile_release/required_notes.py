"""Closed required-note DATA/policy; never a file, picker or write capability.

The original owner must capture config/ignore/version and bind returned paths.
No file is opened here. Public locale selection and its roster remain unchanged.
"""
from __future__ import annotations

import hashlib
import re
import unicodedata
from dataclasses import dataclass
from typing import Any

from .config import (MAX_CONFIG_BYTES, MAX_VERSION_BYTES, parse_config_text,
                     parse_key_value_text, release_version_from_values)
from .discovery import PRIVATE_PREFIXES
from .errors import ConfigurationError, ValidationError
from .init_transaction import is_state_name, validate_paths
from .metadata import (ANDROID_NOTE_CASE_MAP, ANDROID_NOTE_LIMIT, ANDROID_NOTE_MAX_BYTES,
                       ANDROID_NOTE_SECRET_RE, SECRET_RE, check_metadata_text,
                       validate_android_release_note)
from .metadata_text import (DEPENDENCY_PATHS, MAX_COMPONENTS, MAX_RELATIVE_BYTES,
                            MetadataTextInputError, _DOS_STEMS, _PRIVATE, locale_value)
from .version_text import VersionSelection, VersionTextInputError, public_version_selection

KINDS = ("android-build", "android-default", "ios-beta-review", "ios-app-review",
         "testflight-what-to-test")
IOS_PATHS = {"ios-beta-review": "review/ios-beta-notes.txt",
             "ios-app-review": "review/ios-notes.txt",
             "testflight-what-to-test": "testflight/what-to-test.txt"}
REVIEW_EDITOR_MAX_BYTES = 32 * 1024  # Local editor cap; NOT an Apple field limit.
TESTFLIGHT_MAX_BYTES = 64 * 1024  # Matches Fastfile's bounded raw note read.
TESTFLIGHT_CHARACTER_LIMIT = 4000
RUBY_STRIP_CHARACTERS = "\x00\t\n\v\f\r "  # Ruby String#strip, not Unicode str.strip.


class RequiredNotesInputError(ValueError):
    """Closed reason only. Never retain or echo selected text/config/parser data."""

    def __init__(self, reason: str = "invalid_params"):
        super().__init__("Required-note input was refused")
        self.reason = reason


def _require(condition: bool, reason: str = "invalid_params") -> None:
    if not condition:
        raise RequiredNotesInputError(reason)


@dataclass(frozen=True)
class NotesContext:
    kind: str
    locale: str | None = None

    @property
    def platform(self) -> str:
        return "android" if self.kind.startswith("android-") else "ios"

    def wire(self) -> dict[str, str]:
        return {"kind": self.kind, "locale": self.locale} if self.locale is not None else {"kind": self.kind}


def notes_context(value: object) -> NotesContext:
    _require(type(value) is dict and type(value.get("kind")) is str and value["kind"] in KINDS)
    kind = value["kind"]  # type: ignore[index]
    if kind.startswith("android-"):
        _require(set(value) == {"kind", "locale"})
        try:
            locale = locale_value(value["locale"])  # type: ignore[index]
        except MetadataTextInputError:
            raise RequiredNotesInputError() from None
        return NotesContext(kind, locale)
    _require(set(value) == {"kind"})
    return NotesContext(kind)


def required_note_sensitive(kind: str, text: str) -> bool:
    """Private-disclosure guard, independent of policy's early-failure order.

    Reuse the existing detectors on their original raw views. Universal-newline
    normalization can reduce a quoted value below a detector's minimum length;
    it must not erase an existing raw Android or generic sensitivity match.
    The normalized generic check remains for backwards-compatible coverage.
    This does not alter, normalize or return the selected text.
    """
    _require(type(kind) is str and kind in KINDS and type(text) is str and len(text) <= 65537)
    try:
        _require(len(text.encode("utf-8")) <= 4 * 65537)
    except UnicodeEncodeError:
        raise RequiredNotesInputError() from None
    return (SECRET_RE.search(text) is not None
            or (kind.startswith("android-")
                and ANDROID_NOTE_SECRET_RE.search(text.translate(ANDROID_NOTE_CASE_MAP)) is not None)
            or any(code == "metadata.secret-pattern"
                   for code, _ in check_metadata_text("required-note", text).issues))


def editor_byte_limit(kind: str) -> int:
    _require(type(kind) is str and kind in KINDS)
    return (ANDROID_NOTE_MAX_BYTES if kind.startswith("android-") else
            TESTFLIGHT_MAX_BYTES if kind == "testflight-what-to-test" else REVIEW_EDITOR_MAX_BYTES)


def _root_safe(root: str) -> bool:
    # The same root exclusions as public_text_selection remain in force. Only
    # the three fixed suffixes below are allowed to contain review/testflight.
    parts = tuple(root.split("/"))
    folded = tuple(part.casefold() for part in parts)
    return bool(parts) and all(
        part not in {"", ".", ".."} and not part.startswith(".")
        and not part.endswith((" ", ".")) and unicodedata.normalize("NFC", part) == part
        and part.casefold() not in _PRIVATE and not is_state_name(part)
        and part.split(".", 1)[0].casefold() not in _DOS_STEMS
        and len(part.encode("utf-8")) <= 255
        and not any(ord(char) < 32 or ord(char) == 127 or char in '\\:<>"|?*' for char in part)
        for part in parts
    ) and not any(folded[:len(prefix)] == prefix for prefix in PRIVATE_PREFIXES)


@dataclass(frozen=True)
class NotesConfiguration:
    """Pure first-stage routing DATA, not an authenticated config observation."""

    context: NotesContext
    metadata_root: str
    version: VersionSelection | None


def notes_configuration(config_text: object, context: object) -> NotesConfiguration:
    selected = notes_context(context)
    try:
        _require(type(config_text) is str and 0 < len(config_text.encode("utf-8")) <= MAX_CONFIG_BYTES,
                 "config_invalid")
        _require(not any(code == "metadata.secret-pattern" for code, _ in
                         check_metadata_text("mobile-release.json", config_text).issues), "config_invalid")
        data = parse_config_text(config_text)
        _require(data[selected.platform].get("enabled") is True, "not_configured")
        if selected.platform == "android":
            _require(selected.locale in data["metadata"]["androidLocales"], "not_configured")
        root = data["metadata"]["root"]
        _require(_root_safe(root), "unsafe")
        version = public_version_selection(config_text) if selected.platform == "android" else None
        return NotesConfiguration(selected, root, version)
    except RequiredNotesInputError:
        raise
    except (ConfigurationError, ValidationError, VersionTextInputError, ValueError,
            TypeError, KeyError, UnicodeError, RecursionError):
        raise RequiredNotesInputError("config_invalid") from None


@dataclass(frozen=True)
class RequiredNotesSelection:
    """Detached DATA. Only an original sealed owner descriptor may authorize it."""

    context: NotesContext
    metadata_root: str
    path: str
    build: int | None
    version_source: str | None
    counterpart_path: str | None
    directories: tuple[str, ...]
    editor_byte_limit: int

    @property
    def paths(self) -> tuple[str, ...]:
        return (self.path,)


def required_note_selection(configured: NotesConfiguration, saved_version: object = None) -> RequiredNotesSelection:
    _require(type(configured) is NotesConfiguration and type(configured.context) is NotesContext)
    # Re-admit detached context DATA. This is not an authenticity check or lease.
    context = notes_context(configured.context.wire())
    try:
        root = configured.metadata_root
        _require(type(root) is str and _root_safe(root), "unsafe")
        build = None
        version_source = counterpart = None
        if context.platform == "android":
            spec = configured.version
            _require(type(spec) is VersionSelection, "version_invalid")
            _require(type(saved_version) is bytes and 0 < len(saved_version) <= MAX_VERSION_BYTES,
                     "version_invalid")
            text = saved_version.decode("utf-8")
            _require(not any(code == "metadata.secret-pattern" for code, _ in
                             check_metadata_text("version", text).issues), "version_invalid")
            parsed = parse_key_value_text(text)
            version = release_version_from_values(parsed, name_key=spec.name_key, build_key=spec.build_key,
                                                  ios_enabled=spec.ios_enabled, source_label="saved version source")
            build, version_source = version.build, spec.source
            exact = f"{root}/android/{context.locale}/changelogs/{build}.txt"
            default = f"{root}/android/{context.locale}/changelogs/default.txt"
            path, counterpart = (exact, default) if context.kind == "android-build" else (default, exact)
        else:
            _require(configured.version is None and saved_version is None)
            path = f"{root}/{IOS_PATHS[context.kind]}"
        all_paths = (*DEPENDENCY_PATHS, *((version_source,) if version_source is not None else ()),
                     path, *((counterpart,) if counterpart is not None else ()))
        _require(all(len(value.encode("utf-8")) <= MAX_RELATIVE_BYTES and
                     len(value.split("/")) <= MAX_COMPONENTS for value in all_paths), "unsafe")
        validate_paths(list(all_paths))
        parts = path.split("/")
        directories = tuple("/".join(parts[:depth]) for depth in range(1, len(parts)))
        return RequiredNotesSelection(context, root, path, build, version_source, counterpart,
                                      directories, editor_byte_limit(context.kind))
    except RequiredNotesInputError:
        raise
    except (ConfigurationError, ValidationError, ValueError, TypeError, KeyError, UnicodeError, RecursionError):
        raise RequiredNotesInputError("version_invalid" if context.platform == "android" else "unsafe") from None


# Fixed safe messages only. The shared Android validator still makes the policy
# decision; this table merely maps its closed reasons to UI diagnostics.
_ANDROID_REASONS = {
    "Android release notes must be UTF-8 text": "notes.utf8",
    "Android release notes must contain non-whitespace text without NUL": "notes.android-content",
    f"Android release notes exceed the {ANDROID_NOTE_LIMIT}-character limit (including whitespace)": "notes.android-length",
    "Android release notes contain an unresolved placeholder": "metadata.placeholder",
    "Android release notes contain possible secret material": "metadata.secret-pattern",
}
ISSUE_MESSAGES = {
    "notes.missing": "This selected note file has not been saved yet.",
    "notes.utf8": "Use a UTF-8 text file. The selected contents were not decoded or changed.",
    "notes.editor-byte-limit": "This note exceeds its disclosed local text-editor byte limit. It was not truncated.",
    "notes.android-content": "Google Play notes need non-whitespace text without NUL characters.",
    "notes.android-length": "Google Play notes allow 500 Unicode characters, including all whitespace and line endings.",
    "notes.android-policy": "Google Play notes failed the shared core release-note policy.",
    "notes.apple-empty": "Apple receives an empty value after its whitespace trimming. Add useful instructions.",
    "notes.testflight-length": "TestFlight what-to-test allows at most 4000 characters after Apple-bound whitespace trimming.",
    "metadata.empty-text": "Add non-whitespace instructions instead of an empty note.",
    "metadata.nul": "Text notes must not contain NUL characters.",
    "metadata.placeholder": "Replace unresolved placeholders with reviewed release or testing instructions.",
    "metadata.secret-pattern": "Remove possible credentials from this note. Use the separate credential fields; rotate any exposed credential.",
    "metadata.length": "The note exceeds the existing core preflight character limit.",
}


@dataclass(frozen=True)
class RequiredNoteCheck:
    kind: str
    raw_byte_count: int | None
    character_count: int | None
    character_limit: int | None
    outbound_character_count: int | None
    editor_byte_limit: int
    issues: tuple[str, ...]

    @property
    def valid(self) -> bool:
        return not self.issues

    def wire(self) -> dict[str, Any]:
        """Direct validation DATA only. Never include this in routine events."""
        return {"schemaVersion": 1, "kind": self.kind, "valid": self.valid,
                "state": "format-valid" if self.valid else "invalid",
                "rawByteCount": self.raw_byte_count, "characterCount": self.character_count,
                "characterLimit": self.character_limit, "outboundCharacterCount": self.outbound_character_count,
                "editorByteLimit": self.editor_byte_limit,
                "issues": [{"code": code, "message": ISSUE_MESSAGES[code]} for code in self.issues]}


def check_required_note(kind: object, raw: object) -> RequiredNoteCheck:
    """One shared editor/saved-note API policy; preserve input bytes exactly.

    The caller owns file admission. None means *observed absence*, never a caught
    read/nonregular/symlink error. The saved-note summary must select issue codes
    only, omitting content, digests, byte/character counts and outbound summaries.
    """
    _require(type(kind) is str and kind in KINDS)
    maximum = editor_byte_limit(kind)
    limit = ANDROID_NOTE_LIMIT if kind.startswith("android-") else (
        TESTFLIGHT_CHARACTER_LIMIT if kind == "testflight-what-to-test" else None)
    _require(raw is None or type(raw) is bytes)
    size = None if raw is None else len(raw)

    def result(codes: tuple[str, ...], count: int | None = None,
               outbound: int | None = None) -> RequiredNoteCheck:
        return RequiredNoteCheck(kind, size, count, limit, outbound, maximum, tuple(dict.fromkeys(codes)))

    if raw is None:
        return result(("notes.missing",))
    if len(raw) > maximum:
        return result(("notes.editor-byte-limit",))
    try:
        text = raw.decode("utf-8")
    except UnicodeError:
        return result(("notes.utf8",))
    if kind.startswith("android-"):
        try:
            validate_android_release_note(text)
        except ValidationError as error:
            return result((_ANDROID_REASONS.get(str(error), "notes.android-policy"),), len(text))
        return result((), len(text))
    checked = check_metadata_text(IOS_PATHS[kind].rsplit("/", 1)[1], text)
    codes = tuple(code for code, _ in checked.issues)
    outbound = text.strip(RUBY_STRIP_CHARACTERS)
    if not outbound:
        codes += ("notes.apple-empty",)
    if kind == "testflight-what-to-test" and len(outbound) > TESTFLIGHT_CHARACTER_LIMIT:
        codes += ("notes.testflight-length",)
    return result(codes, checked.character_count, len(outbound))


@dataclass(frozen=True)
class EffectiveAndroidNote:
    source: str
    check: RequiredNoteCheck


def effective_android_note(exact: object, default: object) -> EffectiveAndroidNote:
    """Presence precedes validity. Original safe-read errors must propagate first."""
    _require((exact is None or type(exact) is bytes) and (default is None or type(default) is bytes))
    if exact is not None:
        return EffectiveAndroidNote("exact", check_required_note("android-build", exact))
    return EffectiveAndroidNote("default" if default is not None else "missing",
                                check_required_note("android-default", default))


def validate_required_note_input(params: object) -> dict[str, Any]:
    """Closed pure direct-call seam; not registered as an available API in Phase A."""
    _require(type(params) is dict and set(params) == {"context", "text"})
    context = notes_context(params["context"])
    text = params["text"]
    _require(type(text) is str and len(text) <= TESTFLIGHT_MAX_BYTES + 1)
    try:
        raw = text.encode("utf-8")
    except UnicodeError:
        raise RequiredNotesInputError() from None
    result = check_required_note(context.kind, raw).wire()
    # Import uses this decision before privately returning selected text. Neither
    # first-policy failure nor CRLF normalization may conceal a raw sensitivity
    # match. Keep policy diagnostics/counts intact and add only the fixed guard.
    if required_note_sensitive(context.kind, text):
        result["valid"] = False
        result["state"] = "invalid"
        if not any(issue["code"] == "metadata.secret-pattern" for issue in result["issues"]):
            result["issues"].append({
                "code": "metadata.secret-pattern", "message": ISSUE_MESSAGES["metadata.secret-pattern"]})
    return result


def _notes_digest(raw: bytes) -> dict[str, Any]:
    return {"byteLength": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def _notes_assertion(raw: bytes | None) -> dict[str, Any]:
    return {"state": "absent"} if raw is None else {"state": "present", **_notes_digest(raw)}


def notes_baseline(config: bytes, version: bytes | None, note: bytes | None,
                   counterpart: bytes | None) -> dict[str, Any]:
    """Private comparison DATA from exact owned reads; never a write capability.

    None is an observed absence, not a read failure. A missing version denotes
    the Apple context; Android callers must supply the saved captured version.
    Per-kind note admission remains the original caller's responsibility.
    """
    _require(type(config) is bytes and 0 < len(config) <= MAX_CONFIG_BYTES)
    _require(version is None or type(version) is bytes and 0 < len(version) <= MAX_VERSION_BYTES)
    _require(note is None or type(note) is bytes and len(note) <= TESTFLIGHT_MAX_BYTES)
    _require(counterpart is None or type(counterpart) is bytes and len(counterpart) <= ANDROID_NOTE_MAX_BYTES)
    _require(version is not None or counterpart is None)
    return {"config": _notes_digest(config),
            "version": None if version is None else _notes_digest(version),
            "note": _notes_assertion(note),
            "counterpart": None if version is None else _notes_assertion(counterpart)}


def notes_selection_view(selection: RequiredNotesSelection, note: bytes | None,
                         counterpart: bytes | None) -> dict[str, Any]:
    """One direct response projection shared by Observe and original Prepare."""
    _require(type(selection) is RequiredNotesSelection and type(selection.context) is NotesContext)
    context = notes_context(selection.context.wire())
    _require(note is None or type(note) is bytes and len(note) <= editor_byte_limit(context.kind))
    if context.platform == "android":
        _require(type(selection.build) is int and 1 <= selection.build <= 2_100_000_000)
        _require(counterpart is None or type(counterpart) is bytes and len(counterpart) <= ANDROID_NOTE_MAX_BYTES)
        # An invalid exact file is still authoritative over a valid default.
        chosen = (effective_android_note(note, counterpart) if context.kind == "android-build"
                  else effective_android_note(counterpart, note))
        effective = {"source": chosen.source, "valid": chosen.check.valid}
    else:
        _require(selection.build is None and counterpart is None)
        effective = None
    return {"context": context.wire(), "metadataRoot": selection.metadata_root,
            "destination": selection.path, "savedBuild": selection.build, "effective": effective}


def admit_notes_baseline(context: NotesContext, value: object) -> dict[str, Any]:
    """Closed detached request DATA. The original checkout must compare it."""
    _require(type(context) is NotesContext)
    context = notes_context(context.wire())
    _require(type(value) is dict and set(value) == {"config", "version", "note", "counterpart"})

    def digest(row: object, maximum: int, *, nonempty: bool = False) -> dict[str, Any]:
        _require(type(row) is dict and set(row) == {"byteLength", "sha256"})
        _require(type(row["byteLength"]) is int and int(nonempty) <= row["byteLength"] <= maximum
                 and type(row["sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", row["sha256"]) is not None)
        return {"byteLength": row["byteLength"], "sha256": row["sha256"]}

    def assertion(row: object, maximum: int) -> dict[str, Any]:
        _require(type(row) is dict and type(row.get("state")) is str)
        if row["state"] == "absent":
            _require(set(row) == {"state"})
            return {"state": "absent"}
        _require(row["state"] == "present" and set(row) == {"state", "byteLength", "sha256"})
        return {"state": "present", **digest({"byteLength": row["byteLength"], "sha256": row["sha256"]}, maximum)}

    configured = digest(value["config"], MAX_CONFIG_BYTES, nonempty=True)
    selected = assertion(value["note"], editor_byte_limit(context.kind))
    if context.platform == "android":
        version = digest(value["version"], MAX_VERSION_BYTES, nonempty=True)
        counterpart = assertion(value["counterpart"], ANDROID_NOTE_MAX_BYTES)
    else:
        _require(value["version"] is None and value["counterpart"] is None)
        version = counterpart = None
    return {"config": configured, "version": version, "note": selected, "counterpart": counterpart}
