"""Pure saved-version selection and two-span payloads, never file authority.

The ordinary version parser and release policy remain the source of truth.
Writer-only ambiguity refusals do not change CLI or passive observation reads.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any

from .config import (MAX_CONFIG_BYTES, MAX_VERSION_BYTES, parse_config_text,
                     parse_key_value_text, release_version_from_values)
from .errors import ConfigurationError, ValidationError
from .init_transaction import validate_paths

CONFIG_PATH = "release/mobile-release.json"
IGNORE_PATH = ".gitignore"
DEPENDENCY_PATHS = (CONFIG_PATH, IGNORE_PATH)
DEPENDENCY_LIMITS = (MAX_CONFIG_BYTES, 1024 * 1024)
MAX_REQUEST_BYTES = 16 * 1024
MAX_OPENED_BYTES = 512 * 1024
MAX_PREPARED_BYTES = 1024 * 1024
MAX_RESULT_BYTES = 2 * 1024 * 1024
MAX_RELATIVE_BYTES = 512
MAX_COMPONENTS = 12
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_ATOM = re.compile(r"[0-9A-Z_a-z.+-]+\Z")
_BREAKS = (("\r\n", "crlf"), ("\n", "lf"), ("\r", "cr"), ("\v", "vt"),
           ("\f", "ff"), ("\x1c", "fs"), ("\x1d", "gs"), ("\x1e", "rs"),
           ("\x85", "nel"), ("\u2028", "ls"), ("\u2029", "ps"))


class VersionTextInputError(ValueError):
    """Closed reason/field only; never reflect private parser/input text."""

    def __init__(self, reason: str = "invalid_params", field: str | None = None):
        super().__init__("Saved version input was refused")
        self.reason, self.field = reason, field


def _require(condition: bool, reason: str = "invalid_params", field: str | None = None) -> None:
    if not condition:
        raise VersionTextInputError(reason, field)


@dataclass(frozen=True)
class VersionSelection:
    """Detached DATA. Only VersionTargets bound by a lease can authorize it."""

    source: str
    name_key: str
    build_key: str
    ios_enabled: bool
    paths: tuple[str, ...]
    directories: tuple[str, ...]


def public_version_selection(config_text: str) -> VersionSelection:
    # Reuse the observation's exact public-path and secret guards. The lazy
    # import avoids an API initialization cycle and performs no observation.
    from .api._release_version import _sensitive, _source_path
    try:
        _require(not _sensitive(config_text), "config_invalid")
        data = parse_config_text(config_text)
        spec = data["version"]
        source, name_key, build_key = spec["source"], spec["nameKey"], spec["buildKey"]
        _require(name_key.casefold() != build_key.casefold(), "config_invalid")
        _require(_source_path(source) and len(source.encode("utf-8")) <= MAX_RELATIVE_BYTES
                 and len(source.split("/")) <= MAX_COMPONENTS, "unsafe")
        validate_paths([*DEPENDENCY_PATHS, source])
    except VersionTextInputError:
        raise
    except (ConfigurationError, ValidationError, ValueError, TypeError, UnicodeError, RecursionError):
        raise VersionTextInputError("config_invalid") from None
    parts = source.split("/")
    return VersionSelection(source, name_key, build_key, data["ios"].get("enabled") is True,
                            (source,), tuple("/".join(parts[:n]) for n in range(1, len(parts))))


def values_input(value: object) -> dict[str, str]:
    """Proposed strings only. Original values have a separate, larger bound."""
    _require(type(value) is dict and set(value) == {"name", "build"})
    for field, maximum in (("name", 64), ("build", 10)):
        item = value[field]  # type: ignore[index]
        _require(type(item) is str and 0 < len(item) <= maximum and item.isascii(), field=field)
    _require(re.fullmatch(r"[0-9]+", value["build"]) is not None, field="build")  # type: ignore[index]
    return {"name": value["name"], "build": value["build"]}  # type: ignore[index]


def validate_values(selection: VersionSelection, value: object) -> dict[str, str]:
    values = values_input(value)
    # The same shared policy decides each field; its reflective exceptions never
    # cross this boundary. These fixed field IDs can be used by focused callers.
    for field in ("name", "build"):
        candidate = {selection.name_key: values["name"] if field == "name" else "1.0",
                     selection.build_key: values["build"] if field == "build" else "1"}
        try:
            release_version_from_values(candidate, name_key=selection.name_key,
                                        build_key=selection.build_key, ios_enabled=selection.ios_enabled,
                                        source_label="saved version source")
        except (ConfigurationError, ValueError, TypeError, UnicodeError, RecursionError):
            raise VersionTextInputError("value_invalid", field) from None
    return values


@dataclass(frozen=True)
class VersionOriginal:
    text: str
    parsed: tuple[tuple[str, str], ...]
    values: tuple[str, str]
    spans: tuple[tuple[int, int], ...]


def original_text(selection: VersionSelection, raw: bytes) -> VersionOriginal:
    """Admit the whole file, locating only two unambiguous inner byte spans."""
    from .api._release_version import _sensitive
    _require(type(raw) is bytes and 0 < len(raw) <= MAX_VERSION_BYTES, "source_invalid")
    try:
        text = raw.decode("utf-8")
        _require(not _sensitive(text), "sensitive")
        parsed = parse_key_value_text(text)
        keys = (selection.name_key, selection.build_key)
        _require(all(key in parsed for key in keys), "source_invalid")
        folded = {key.casefold() for key in keys}
        _require(not any(key.casefold() in folded and key not in keys for key in parsed), "source_invalid")
        spans: dict[str, tuple[int, int]] = {}
        offset = 0
        for raw_line in text.splitlines(keepends=True):
            line = raw_line.rstrip("\r\n\v\f\x1c\x1d\x1e\x85\u2028\u2029")
            stripped = line.strip()
            if stripped and not stripped.startswith(("#", "//", ";")):
                equal = line.find("=")  # First '=' exactly as the shared parser.
                key = line[:equal].strip()
                if key in keys:
                    tail = line[equal + 1:]
                    start = equal + 1 + len(tail) - len(tail.lstrip())
                    end = len(line.rstrip())
                    if line[start:start + 1] in {"'", '"'}:
                        start, end = start + 1, end - 1
                    value = line[start:end]
                    _require(key not in spans and _ATOM.fullmatch(value) is not None
                             and value == parsed[key], "source_invalid")
                    spans[key] = (len(text[:offset + start].encode("utf-8")),
                                  len(text[:offset + end].encode("utf-8")))
            offset += len(raw_line)
        _require(set(spans) == set(keys) and text.encode("utf-8") == raw, "source_invalid")
        return VersionOriginal(text, tuple(parsed.items()), (parsed[keys[0]], parsed[keys[1]]),
                               tuple(spans[key] for key in keys))
    except VersionTextInputError:
        raise
    except (ConfigurationError, ValueError, TypeError, UnicodeError, RecursionError):
        raise VersionTextInputError("source_invalid") from None


def prepare_payload(selection: VersionSelection, raw: bytes | None, intent: object,
                    supplied: object) -> tuple[bytes | None, bytes, dict[str, str]]:
    _require(type(intent) is str and intent == ("create" if raw is None else "edit"))
    values = validate_values(selection, supplied)
    keys = (selection.name_key, selection.build_key)
    if raw is None:
        after = f"{keys[0]}={values['name']}\n{keys[1]}={values['build']}\n".encode("utf-8")
        expected = dict(zip(keys, (values["name"], values["build"])))
    else:
        original = original_text(selection, raw)
        after = raw
        for (start, end), value in sorted(zip(original.spans, (values["name"], values["build"])), reverse=True):
            after = after[:start] + value.encode("ascii") + after[end:]
        expected = dict(original.parsed)
        expected.update(zip(keys, (values["name"], values["build"])))
    _require(len(after) <= MAX_VERSION_BYTES, "source_invalid")
    checked = original_text(selection, after)
    _require(dict(checked.parsed) == expected, "source_invalid")
    return (None if raw == after else after), after, values


def content_digest(raw: bytes) -> dict[str, Any]:
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def baseline(config: bytes, version: bytes | None) -> dict[str, Any]:
    return {"savedConfig": content_digest(config), "savedVersion":
            {"state": "absent"} if version is None else {"state": "present", **content_digest(version)}}


def admit_baseline(value: object) -> dict[str, Any]:
    _require(type(value) is dict and set(value) == {"savedConfig", "savedVersion"})

    def digest(item: object, keys: set[str], minimum: int, maximum: int) -> dict[str, Any]:
        _require(type(item) is dict and set(item) == keys and type(item["bytes"]) is int
                 and minimum <= item["bytes"] <= maximum and type(item["sha256"]) is str
                 and _DIGEST.fullmatch(item["sha256"]) is not None)
        return {"bytes": item["bytes"], "sha256": item["sha256"]}  # type: ignore[index]

    config = digest(value["savedConfig"], {"bytes", "sha256"}, 1, MAX_CONFIG_BYTES)  # type: ignore[index]
    version = value["savedVersion"]  # type: ignore[index]
    _require(type(version) is dict and type(version.get("state")) is str and version.get("state") in {"present", "absent"})
    if version["state"] == "absent":
        _require(set(version) == {"state"})
        version = {"state": "absent"}
    else:
        version = {"state": "present", **digest(version, {"state", "bytes", "sha256"}, 1, MAX_VERSION_BYTES)}
    return {"savedConfig": config, "savedVersion": version}


def line_endings(text: str) -> list[str]:
    styles = []
    for separator, label in _BREAKS:
        if separator in text:
            styles.append(label)
        text = text.replace(separator, "")
    return styles


def final_newline(text: str) -> bool:
    return text.endswith(tuple(separator for separator, _ in _BREAKS))
