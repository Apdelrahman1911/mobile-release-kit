"""Closed public supplier DATA, not download/installation authority.

The native owner supplies this projection of its already checked, compiled
supplier. The renderer never supplies URLs, hashes, extraction paths or modes.
Parsing these values cannot establish a native profile or a missing-tool census.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
import json
import re
import stat
import unicodedata
from urllib.parse import urlsplit

ARCHIVE_LIMIT = 256 * 1024 * 1024
FILE_LIMIT = 512 * 1024 * 1024
TOTAL_LIMIT = 1024 * 1024 * 1024
MEMBER_LIMIT = 32768
MANIFEST_LIMIT = 8 * 1024 * 1024
CHUNK = 64 * 1024
RESERVE_BYTES = 2 * 1024 * 1024 * 1024
METADATA_RESERVE = 64 * 1024 * 1024
PROFILES = frozenset(("macos-arm64", "macos-x86_64"))
_SHA = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z", re.ASCII)
_REASONS = frozenset(("input", "unsupported", "stale", "census-incomplete", "recovery-required",
    "cache-conflict", "disk-space", "network", "redirect", "framing", "archive-digest", "archive-layout",
    "archive-member", "limit", "cancelled", "unknown", "already-used"))


class AcquisitionError(ValueError):
    """Closed reason only; no upstream URL/query, local path or server text."""
    def __init__(self, reason: str):
        self.reason = reason if type(reason) is str and reason in _REASONS else "input"
        super().__init__("The required tools could not be safely prepared.")


def require(condition: bool, reason: str = "input") -> None:
    if not condition:
        raise AcquisitionError(reason)


def digest(value: object) -> bool:
    return type(value) is str and _SHA.fullmatch(value) is not None


def operation_id(value: object) -> bool:
    return type(value) is str and _ID.fullmatch(value) is not None


def relative(value: object) -> str:
    require(type(value) is str, "archive-layout")
    try:
        encoded = value.encode("utf-8")
    except UnicodeError:
        raise AcquisitionError("archive-layout") from None
    require(0 < len(encoded) <= 512, "archive-layout")
    require(unicodedata.normalize("NFC", value) == value and "\\" not in value and ":" not in value,
            "archive-layout")
    parts = value.split("/")
    require(len(parts) <= 16 and all(part not in ("", ".", "..") and len(part.encode("utf-8")) <= 255
        and not part.endswith((".", " ")) and not any(ord(c) < 32 or ord(c) == 127 for c in part)
        for part in parts), "archive-layout")
    return value


def name_key(value: str) -> str:
    return unicodedata.normalize("NFC", value).casefold()


class Component(str, Enum):
    JDK = "jdk"
    SDK_PLATFORM = "sdk-platform"
    SDK_BUILD_TOOLS = "sdk-build-tools"
    GRADLE = "gradle"

    @property
    def group(self) -> str:
        return "sdk" if self in (self.SDK_PLATFORM, self.SDK_BUILD_TOOLS) else self.value

    @property
    def folder(self) -> str:
        return {"jdk": "jdk.jdk", "sdk": "android-sdk", "gradle": "gradle"}[self.group]


COMPONENTS = tuple(Component)


def vendor_url(component: Component, value: object, profile: str) -> tuple[str, str]:
    require(type(component) is Component and type(profile) is str and profile in PROFILES)
    require(type(value) is str and len(value) <= 2048 and all(0x21 <= ord(c) <= 0x7e for c in value))
    try:
        parsed = urlsplit(value)
        require(parsed.scheme == "https" and parsed.netloc == parsed.hostname and not parsed.query
                and not parsed.fragment and "\\" not in value)
    except ValueError:
        raise AcquisitionError("input") from None
    if component is Component.JDK:
        arch = "aarch64" if profile == "macos-arm64" else "x64"
        pattern = (r"/adoptium/temurin17-binaries/releases/download/jdk-[0-9A-Za-z._+%-]+/"
                   r"OpenJDK17U-jdk_" + arch + r"_mac_hotspot_[0-9A-Za-z._+-]+\.tar\.gz")
        valid = parsed.hostname == "github.com" and re.fullmatch(pattern, parsed.path, re.ASCII)
        require("%" not in parsed.path.replace("%2B", ""))
    elif component is Component.GRADLE:
        valid = parsed.hostname == "github.com" and re.fullmatch(
            r"/gradle/gradle-distributions/releases/download/v[0-9.]+/gradle-[0-9.]+-bin\.zip", parsed.path, re.ASCII)
    else:
        pattern = (r"/android/repository/platform-[0-9]+_r[0-9]+\.zip"
                   if component is Component.SDK_PLATFORM else r"/android/repository/build-tools_r[0-9]+_macosx\.zip")
        valid = parsed.hostname == "dl.google.com" and re.fullmatch(pattern, parsed.path, re.ASCII)
    require(bool(valid))
    return parsed.hostname, parsed.path


def _object(value: object, fields: set[str]) -> dict:
    require(type(value) is dict and set(value) == fields)
    return value


def _integer(value: object, maximum: int, minimum: int = 0) -> int:
    require(type(value) is int and minimum <= value <= maximum)
    return value


@dataclass(frozen=True, slots=True)
class Member:
    name: str
    kind: str
    archive_mode: int
    size: int
    sha256: str | None
    source_relative: str | None
    source_mode: int | None


@dataclass(frozen=True, slots=True)
class Parent:
    relative: str
    mode: int


@dataclass(frozen=True, slots=True)
class Archive:
    component: Component
    url: str
    size: int
    sha256: str
    expanded_bytes: int
    members: tuple[Member, ...]
    parents: tuple[Parent, ...]


@dataclass(frozen=True, slots=True)
class Manifest:
    profile: str
    reference_sha256: str
    projection_sha256: str
    archives: tuple[Archive, ...]

    def archive(self, component: Component) -> Archive:
        return self.archives[COMPONENTS.index(component)]


def canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True, allow_nan=False).encode("ascii")


def _pairs(items: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in items:
        require(key not in result)
        result[key] = value
    return result


def decode_manifest(data: bytes) -> Manifest:
    """Validate the bounded original-bootstrap projection; never a URL picker."""
    require(type(data) is bytes and 0 < len(data) <= MANIFEST_LIMIT)
    try:
        value = json.loads(data, object_pairs_hook=_pairs, parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (ValueError, UnicodeError, RecursionError):
        raise AcquisitionError("input") from None
    _object(value, {"schemaVersion", "profile", "referenceSha256", "archives"})
    require(type(value["schemaVersion"]) is int and value["schemaVersion"] == 1
            and type(value["profile"]) is str and value["profile"] in PROFILES and digest(value["referenceSha256"]))
    require(type(value["archives"]) is list and len(value["archives"]) == len(COMPONENTS))
    archives = []
    total_members = total_bytes = 0
    for expected, raw in zip(COMPONENTS, value["archives"]):
        _object(raw, {"component", "url", "bytes", "sha256", "expandedBytes", "members", "parents"})
        require(raw["component"] == expected.value and digest(raw["sha256"]))
        vendor_url(expected, raw["url"], value["profile"])
        size = _integer(raw["bytes"], ARCHIVE_LIMIT, 1)
        expanded = _integer(raw["expandedBytes"], TOTAL_LIMIT)
        require(expanded <= size * 8, "limit")
        require(type(raw["members"]) is list and 0 < len(raw["members"]) <= MEMBER_LIMIT)
        require(type(raw["parents"]) is list and len(raw["parents"]) <= MEMBER_LIMIT)
        members, parents = [], []
        names, destinations = {}, {}
        file_bytes = 0
        for item in raw["members"]:
            _object(item, {"name", "kind", "archiveMode", "bytes", "sha256", "sourceRelative", "sourceMode"})
            name = relative(item["name"])
            kind = item["kind"]
            require(kind in ("file", "directory"), "archive-member")
            mode = _integer(item["archiveMode"], 0o177777)
            require(stat.S_IFMT(mode) in (0, stat.S_IFREG if kind == "file" else stat.S_IFDIR), "archive-member")
            require(mode & 0o7000 == 0 or (expected is Component.JDK and kind == "directory" and mode == 0o42755),
                    "archive-member")
            member_bytes = _integer(item["bytes"], FILE_LIMIT)
            require((kind == "file" and digest(item["sha256"])) or
                    (kind == "directory" and member_bytes == 0 and item["sha256"] is None))
            key = name_key(name)
            require(key not in names, "archive-layout")
            names[key] = kind
            destination, target_mode = item["sourceRelative"], item["sourceMode"]
            if destination is None:
                require(kind == "directory" and target_mode is None)
            else:
                relative(destination)
                require(type(target_mode) is int and target_mode in ((0o755,) if kind == "directory" else (0o444, 0o644, 0o755)))
                key = name_key(destination)
                require(key not in destinations, "archive-layout")
                destinations[key] = kind
            members.append(Member(name, kind, mode, member_bytes, item["sha256"], destination, target_mode))
            file_bytes += member_bytes
        for item in raw["parents"]:
            _object(item, {"relative", "mode"})
            path = relative(item["relative"])
            require(type(item["mode"]) is int and item["mode"] == 0o755)
            key = name_key(path)
            require(key not in destinations, "archive-layout")
            destinations[key] = "directory"
            parents.append(Parent(path, item["mode"]))
        for collection in (names, destinations):
            for name in collection:
                parts = name.split("/")
                require(all(collection.get("/".join(parts[:i]), "directory") == "directory"
                            for i in range(1, len(parts))), "archive-layout")
        require(file_bytes == expanded, "archive-layout")
        total_bytes += expanded
        total_members += len(members) + len(parents)
        require(total_bytes <= TOTAL_LIMIT and total_members <= MEMBER_LIMIT, "limit")
        archives.append(Archive(expected, raw["url"], size, raw["sha256"], expanded, tuple(members), tuple(parents)))
    # Bind the EXACT native bootstrap bytes, not an independently reserialized
    # renderer-shaped object. Native computes this digest before lending bytes.
    return Manifest(value["profile"], value["referenceSha256"], hashlib.sha256(data).hexdigest(), tuple(archives))
