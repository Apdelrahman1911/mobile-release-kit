"""Pure admission for the small public-locale text editor, not file authority.

Only the original native lease may turn a selection derived here into writable
targets. Renderer baselines and dictionaries are comparison data, not receipts.
The shared generic metadata policy remains in metadata.check_metadata_text.
"""
from __future__ import annotations

import hashlib
import re
import unicodedata
from dataclasses import dataclass
from typing import Any

from .config import MAX_CONFIG_BYTES, parse_config_text
from .discovery import IGNORED_PARTS, PRIVATE_PREFIXES
from .errors import ConfigurationError, ValidationError
from .init_transaction import is_state_name, validate_paths
from .metadata import LOCALE_RE, REQUIRED_LOCALE_TEXT

MAX_TEXT_BYTES = 32 * 1024
MAX_RELATIVE_BYTES = 512
MAX_COMPONENTS = 12
MAX_REQUEST_BYTES = 1024 * 1024
MAX_RESULT_BYTES = 2 * 1024 * 1024
MAX_PREPARED_BYTES = 768 * 1024
CONFIG_PATH = "release/mobile-release.json"
IGNORE_PATH = ".gitignore"
DEPENDENCY_PATHS = (CONFIG_PATH, IGNORE_PATH)
DEPENDENCY_LIMITS = (MAX_CONFIG_BYTES, 1024 * 1024)
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_DOS_STEMS = {"con", "prn", "aux", "nul", *("com" + str(i) for i in range(10)),
              *("lpt" + str(i) for i in range(10))}
_PRIVATE = {name.casefold() for name in IGNORED_PARTS} | {
    ".venv", "venv", ".tox", ".cache", ".swiftpm", ".build", "dist", "target",
    "__pycache__", "private", "secrets", "credentials", "review", "testflight",
}


class MetadataTextInputError(ValueError):
    """Closed reason only; never an input, config/parser or filesystem echo."""

    def __init__(self, reason: str):
        super().__init__("Metadata text input was refused")
        self.reason = reason


def _require(condition: bool, reason: str = "invalid_params") -> None:
    if not condition:
        raise MetadataTextInputError(reason)


def platform_value(value: object) -> str:
    _require(type(value) is str and value in REQUIRED_LOCALE_TEXT)
    return value  # type: ignore[return-value]


def locale_value(value: object) -> str:
    _require(type(value) is str and 2 <= len(value) <= 12
             and value.isascii() and LOCALE_RE.fullmatch(value) is not None)
    return value  # type: ignore[return-value]


@dataclass(frozen=True)
class PublicTextSelection:
    """Detached pure DATA. This object alone grants no native permission."""

    platform: str
    locale: str
    metadata_root: str
    ids: tuple[str, ...]
    paths: tuple[str, ...]
    directories: tuple[str, ...]


def public_text_selection(config_text: str, platform: object, locale: object) -> PublicTextSelection:
    selected_platform, selected_locale = platform_value(platform), locale_value(locale)
    try:
        data = parse_config_text(config_text)
    except (ConfigurationError, ValueError, TypeError, UnicodeError, RecursionError):
        raise MetadataTextInputError("config_invalid") from None
    metadata = data["metadata"]
    _require(data[selected_platform].get("enabled") is True
             and selected_locale in metadata[selected_platform + "Locales"], "not_configured")
    root = metadata["root"]
    parts = tuple(root.split("/"))
    lowered = tuple(part.casefold() for part in parts)
    try:
        safe = (all(part not in {"", ".", ".."} and not part.startswith(".")
                    and not part.endswith((" ", "."))
                    and unicodedata.normalize("NFC", part) == part
                    and part.casefold() not in _PRIVATE and not is_state_name(part)
                    and part.split(".", 1)[0].casefold() not in _DOS_STEMS
                    and len(part.encode("utf-8")) <= 255
                    and not any(ord(char) < 32 or ord(char) == 127 or char in '\\:<>"|?*' for char in part)
                    for part in parts)
                and not any(lowered[:len(prefix)] == prefix for prefix in PRIVATE_PREFIXES))
        ids = REQUIRED_LOCALE_TEXT[selected_platform]
        paths = tuple(f"{root}/{selected_platform}/{selected_locale}/{identity}" for identity in ids)
        safe = safe and all(len(path.encode("utf-8")) <= MAX_RELATIVE_BYTES
                            and len(path.split("/")) <= MAX_COMPONENTS for path in paths)
        _require(safe, "unsafe")
        # The original transaction's portable-alias/file-parent proof is also
        # applied to dependencies here. It does not observe or grant a path.
        validate_paths([*DEPENDENCY_PATHS, *paths])
    except MetadataTextInputError:
        raise
    except (ValueError, UnicodeError, ConfigurationError, ValidationError):
        raise MetadataTextInputError("unsafe") from None
    directories = tuple(sorted({"/".join(path.split("/")[:depth])
                                for path in paths for depth in range(1, len(path.split("/")))},
                               key=lambda path: (path.count("/"), path)))
    return PublicTextSelection(selected_platform, selected_locale, root, ids, paths, directories)


def text_fields(platform: object, fields: object) -> tuple[tuple[str, str], ...]:
    """Exact ordered named fields, rejecting Python lookalikes and surrogates."""
    ids = REQUIRED_LOCALE_TEXT[platform_value(platform)]
    _require(type(fields) is list and len(fields) == len(ids))
    result = []
    for identity, item in zip(ids, fields):  # type: ignore[arg-type]
        _require(type(item) is dict and set(item) == {"id", "text"}
                 and type(item["id"]) is str and item["id"] == identity
                 and type(item["text"]) is str and len(item["text"]) <= MAX_TEXT_BYTES)
        try:
            _require(len(item["text"].encode("utf-8")) <= MAX_TEXT_BYTES)
        except UnicodeError:
            raise MetadataTextInputError("invalid_params") from None
        result.append((identity, item["text"]))
    return tuple(result)


def content_digest(raw: bytes) -> dict[str, Any]:
    return {"byteLength": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def baseline(config: bytes, ids: tuple[str, ...], originals: tuple[bytes | None, ...]) -> dict[str, Any]:
    return {"config": content_digest(config), "fields": [
        {"id": identity, "state": "absent"} if raw is None else
        {"id": identity, "state": "present", **content_digest(raw)}
        for identity, raw in zip(ids, originals)
    ]}


def admit_baseline(platform: object, value: object) -> dict[str, Any]:
    """Return detached assertions only; they cannot replace original captures."""
    ids = REQUIRED_LOCALE_TEXT[platform_value(platform)]
    _require(type(value) is dict and set(value) == {"config", "fields"})
    config, fields = value["config"], value["fields"]  # type: ignore[index]

    def digest(item: object, keys: set[str], minimum: int, maximum: int) -> dict[str, Any]:
        _require(type(item) is dict and set(item) == keys
                 and type(item["byteLength"]) is int and minimum <= item["byteLength"] <= maximum
                 and type(item["sha256"]) is str and _DIGEST.fullmatch(item["sha256"]) is not None)
        return {"byteLength": item["byteLength"], "sha256": item["sha256"]}  # type: ignore[index]

    config = digest(config, {"byteLength", "sha256"}, 1, MAX_CONFIG_BYTES)
    _require(type(fields) is list and len(fields) == len(ids))
    rows = []
    for identity, item in zip(ids, fields):
        _require(type(item) is dict and type(item.get("id")) is str and item["id"] == identity
                 and type(item.get("state")) is str and item["state"] in {"absent", "present"})
        if item["state"] == "absent":
            _require(set(item) == {"id", "state"})
            rows.append({"id": identity, "state": "absent"})
        else:
            rows.append({"id": identity, "state": "present",
                         **digest(item, {"id", "state", "byteLength", "sha256"}, 0, MAX_TEXT_BYTES)})
    return {"config": config, "fields": rows}


def newline_styles(text: str) -> frozenset[str]:
    """Raw style disclosure only; no newline or whitespace rewrite on Save."""
    styles = set()
    if "\r\n" in text:
        styles.add("crlf")
    remainder = text.replace("\r\n", "")
    if "\r" in remainder:
        styles.add("cr")
    if "\n" in remainder:
        styles.add("lf")
    return frozenset(styles)
