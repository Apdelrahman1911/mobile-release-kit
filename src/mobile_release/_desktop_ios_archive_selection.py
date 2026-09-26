"""Saved iOS selection over captured bytes; never filesystem authority."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ._desktop_android_build_selection import _captured, _comparison
from .api._release_version import _source_path
from .config import (MAX_CONFIG_BYTES, MAX_VERSION_BYTES, ReleaseConfig, ReleaseVersion,
                     parse_config_text, parse_key_value_text, release_version_from_values)
from .discovery import selected_ios_container, selected_ios_scheme
from .errors import ConfigurationError


class IOSSelectionRefused(ValueError):
    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__("The saved iOS release selection was refused")


def _refuse(reason: str) -> None:
    raise IOSSelectionRefused(reason) from None


@dataclass(frozen=True, slots=True)
class SavedIOSConfiguration:
    raw: bytes
    source: str
    name_key: str
    build_key: str
    container: tuple[str, str]
    scheme: str
    configuration: str
    bundle_id: str
    symbols_policy: str
    prepare: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class SavedIOSSelection:
    configuration: SavedIOSConfiguration
    version_raw: bytes
    release: ReleaseVersion


def select_saved_ios_configuration(raw: bytes | None, expected: object) -> tuple[dict[str, Any], SavedIOSConfiguration]:
    from ._desktop_android_build_selection import AndroidSelectionRefused
    try:
        text = _captured(raw, _comparison(expected, MAX_CONFIG_BYTES), kind="config", maximum=MAX_CONFIG_BYTES)
    except AndroidSelectionRefused as error:
        _refuse(error.reason)
    try:
        data = parse_config_text(text)
    except (ConfigurationError, ValueError, TypeError, UnicodeError, RecursionError):
        _refuse("saved-config-invalid")
    ios, spec = data["ios"], data["version"]
    if ios.get("enabled") is not True:
        _refuse("platform-disabled")
    # Shared selectors with empty discovery deliberately require saved values.
    # These objects only serve selector policy; no path or IO method is called.
    from pathlib import Path
    config = ReleaseConfig(path=Path("release/mobile-release.json"), root=Path("."), data=data)
    container, scheme = selected_ios_container(config, {}), selected_ios_scheme(config, {})
    if container is None:
        _refuse("container-required")
    if scheme is None:
        _refuse("scheme-required")
    if not _source_path(spec["source"]):
        _refuse("saved-version-unsafe")
    return data, SavedIOSConfiguration(raw, spec["source"], spec["nameKey"], spec["buildKey"], container,
        scheme, ios.get("archiveConfiguration", "Release"), ios["bundleId"], ios.get("symbols", {}).get("policy", "disabled"),
        tuple(ios.get("prepareCommand") or ()))


def bind_saved_ios_version(selected: SavedIOSConfiguration, raw: bytes | None, expected: object) -> SavedIOSSelection:
    from ._desktop_ios_archive_protocol import ProtocolError, saved_version
    from ._desktop_android_build_selection import AndroidSelectionRefused
    if type(selected) is not SavedIOSConfiguration:
        _refuse("protocol-error")
    try:
        expected = saved_version(expected)
    except ProtocolError:
        _refuse("protocol-error")
    if expected["source"] != selected.source:
        _refuse("saved-version-changed")
    try:
        comparison = _comparison({"bytes": expected["bytes"], "sha256": expected["sha256"]}, MAX_VERSION_BYTES)
        text = _captured(raw, comparison, kind="version", maximum=MAX_VERSION_BYTES)
    except AndroidSelectionRefused as error:
        _refuse(error.reason)
    try:
        release = release_version_from_values(parse_key_value_text(text), name_key=selected.name_key,
            build_key=selected.build_key, ios_enabled=True, source_label=selected.source)
    except (ConfigurationError, ValueError, TypeError, UnicodeError, RecursionError):
        _refuse("saved-version-invalid")
    if (release.name, release.build) != (expected["name"], expected["build"]):
        _refuse("saved-version-changed")
    return SavedIOSSelection(selected, raw, release)
