"""Saved Android selection over already-captured bytes, not file authority.

The operation must supply its original bounded reads, retain/recheck their
receipts, and establish finality. These pure values cannot authorize a read,
build, signing operation or cleanup. Configuration and version are parsed once;
the same immutable effective release is used by build and inspection.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any

from .api._release_version import _source_path
from .config import (MAX_CONFIG_BYTES, MAX_VERSION_BYTES, ReleaseVersion,
                     parse_config_text, parse_key_value_text,
                     release_version_from_values)
from .errors import ConfigurationError
from .metadata import check_metadata_text

_SHA = re.compile(r"[0-9a-f]{64}\Z")


class AndroidSelectionRefused(ValueError):
    """Fixed public reason; never reflect configuration or parser messages."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__("The saved Android release selection was refused")


def _refuse(reason: str) -> None:
    raise AndroidSelectionRefused(reason) from None


def _comparison(value: object, maximum: int) -> tuple[int, str]:
    if (type(value) is not dict or set(value) != {"bytes", "sha256"}
            or type(value["bytes"]) is not int or not 1 <= value["bytes"] <= maximum
            or type(value["sha256"]) is not str or _SHA.fullmatch(value["sha256"]) is None):
        _refuse("protocol-error")
    return value["bytes"], value["sha256"]


def _captured(raw: bytes | None, comparison: tuple[int, str], *, kind: str, maximum: int) -> str:
    if raw is None:
        _refuse(f"saved-{kind}-missing")
    if type(raw) is not bytes or not raw:
        _refuse(f"saved-{kind}-invalid")
    if len(raw) > maximum:
        _refuse(f"saved-{kind}-too-large")
    if (len(raw), hashlib.sha256(raw).hexdigest()) != comparison:
        _refuse(f"saved-{kind}-changed")
    try:
        text = raw.decode("utf-8")
    except UnicodeError:
        _refuse(f"saved-{kind}-invalid")
    if any(code == "metadata.secret-pattern"
           for code, _ in check_metadata_text("saved-android-build", text).issues):
        _refuse(f"saved-{kind}-sensitive")
    return text


@dataclass(frozen=True, slots=True)
class SavedAndroidConfiguration:
    """Immutable selection DATA from the exact saved config, never a draft."""

    raw: bytes
    source: str
    name_key: str
    build_key: str
    ios_enabled: bool
    module: str
    variant: str
    application_id: str


@dataclass(frozen=True, slots=True)
class SavedAndroidSelection:
    configuration: SavedAndroidConfiguration
    version_raw: bytes
    release: ReleaseVersion


def select_saved_android_configuration(
    raw: bytes | None, expected: object,
) -> tuple[dict[str, Any], SavedAndroidConfiguration]:
    """Resolve which version file the original operation must capture next.

    The returned dict is a fresh private parse for that invocation's
    ReleaseConfig. All fields used for the build selection are also immutable
    DATA; neither result owns the project or permits filesystem work.
    """
    text = _captured(raw, _comparison(expected, MAX_CONFIG_BYTES), kind="config", maximum=MAX_CONFIG_BYTES)
    try:
        data = parse_config_text(text)
    except (ConfigurationError, ValueError, TypeError, UnicodeError, RecursionError):
        _refuse("saved-config-invalid")
    android = data["android"]
    if android.get("enabled") is not True:
        _refuse("platform-disabled")
    module = android.get("module")
    if not module:
        _refuse("module-required")
    # Shared config syntax allows dot-only Gradle components. They cannot be
    # turned into an original project-relative output path for this operation.
    if module != ":" and any(part in {"", ".", ".."} for part in module[1:].split(":")):
        _refuse("saved-config-unsafe")
    spec = data["version"]
    if not _source_path(spec["source"]):
        _refuse("saved-version-unsafe")
    return data, SavedAndroidConfiguration(
        raw=raw, source=spec["source"], name_key=spec["nameKey"], build_key=spec["buildKey"],
        ios_enabled=data["ios"].get("enabled") is True, module=module,
        variant=android.get("variant", "release"), application_id=android["applicationId"],
    )


def bind_saved_android_version(
    selected: SavedAndroidConfiguration, raw: bytes | None, expected: object,
) -> SavedAndroidSelection:
    """Bind bytes, selected path AND the displayed name/build independently.

    Correct hashes cannot compensate for a forged/stale displayed version.
    No version or configuration file is reread to choose another effective
    release. Original IO identity and post-run drift checks remain mandatory.
    """
    if (type(selected) is not SavedAndroidConfiguration or type(expected) is not dict
            or set(expected) != {"source", "bytes", "sha256", "name", "build"}
            or type(expected["source"]) is not str or not _source_path(expected["source"])
            or type(expected["name"]) is not str or not 1 <= len(expected["name"]) <= 64
            or type(expected["build"]) is not int or not 1 <= expected["build"] <= 2_100_000_000):
        _refuse("protocol-error")
    if expected["source"] != selected.source:
        _refuse("saved-version-changed")
    compared = _comparison({"bytes": expected["bytes"], "sha256": expected["sha256"]}, MAX_VERSION_BYTES)
    text = _captured(raw, compared, kind="version", maximum=MAX_VERSION_BYTES)
    try:
        release = release_version_from_values(
            parse_key_value_text(text), name_key=selected.name_key, build_key=selected.build_key,
            ios_enabled=selected.ios_enabled, source_label=selected.source,
        )
    except (ConfigurationError, ValueError, TypeError, UnicodeError, RecursionError):
        _refuse("saved-version-invalid")
    if release.name != expected["name"] or release.build != expected["build"]:
        _refuse("saved-version-changed")
    return SavedAndroidSelection(configuration=selected, version_raw=raw, release=release)
