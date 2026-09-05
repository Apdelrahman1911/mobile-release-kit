from __future__ import annotations

import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit

from .errors import ConfigurationError

ROOT_KEYS = {
    "$schema",
    "schemaVersion",
    "version",
    "source",
    "android",
    "ios",
    "metadata",
    "services",
    "projectChecks",
}
SECTION_KEYS = {
    "version": {"source", "nameKey", "buildKey"},
    "source": {"candidateBranch", "productionBranch", "projectReadTokenRequired"},
    "android": {
        "enabled",
        "applicationId",
        "identityStatus",
        "module",
        "variant",
        "externalTrack",
        "uploadCertificateSha256",
    },
    "ios": {
        "enabled",
        "bundleId",
        "identityStatus",
        "appStoreAppId",
        "teamId",
        "project",
        "workspace",
        "scheme",
        "archiveConfiguration",
        "externalTestFlightGroup",
        "distributionCertificateSha256",
        "prepareCommand",
        "symbols",
        "review",
    },
    "metadata": {"root", "androidLocales", "iosLocales"},
    "services": {"androidFirebase", "iosFirebase"},
    "projectChecks": {"preflight", "androidArtifact", "iosArtifact"},
}
IDENTITY_STATUSES = {"unverified", "approved", "blocked"}
SERVICE_POLICIES = {"disabled", "required"}
SYMBOL_POLICIES = {"disabled", "retain", "required"}
TRACK_KINDS = {"closed", "open"}
VERSION_RE = re.compile(r"^[0-9]+(?:\.[0-9]+){1,3}(?:[-+][0-9A-Za-z.-]+)?$")
IOS_MARKETING_VERSION_RE = re.compile(r"^[0-9]+(?:\.[0-9]+){1,2}$")
KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]*$")
CONFIG_KEY_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
BRANCH_RE = re.compile(r"^(?!/)(?!.*(?:\.\.|//|@\{|\\|[ ~^:?*\[]))(?!.*[./]$).+$")
LOCALE_RE = re.compile(r"^[a-z]{2,3}(?:-[A-Z][a-z]{3})?(?:-[A-Z]{2}|-[0-9]{3})?$")
ANDROID_ID_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+$")
IOS_ID_RE = re.compile(r"^[A-Za-z][A-Za-z0-9-]*(?:\.[A-Za-z][A-Za-z0-9-]*)+$")
FINGERPRINT_RE = re.compile(r"^(?!0{64}$)[A-Fa-f0-9]{64}$")
TEAM_ID_RE = re.compile(r"^[A-Z0-9]{10}$")
APP_STORE_ID_RE = re.compile(r"^[0-9]{1,20}$")
REQUIRED_ROOT_SECTIONS = {
    "version",
    "source",
    "android",
    "ios",
    "metadata",
    "services",
    "projectChecks",
}
MAX_CONFIG_BYTES = 512 * 1024


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ConfigurationError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _object(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ConfigurationError(f"{name} must be a JSON object")
    return value


def _reject_unknown(section: str, value: dict[str, Any], allowed: set[str]) -> None:
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise ConfigurationError(f"unknown {section} field(s): {', '.join(unknown)}")


def _optional_string(value: dict[str, Any], key: str, section: str) -> None:
    if key in value and (
        not isinstance(value[key], str)
        or not value[key].strip()
        or len(value[key]) > 4096
        or "\x00" in value[key]
        or "\n" in value[key]
        or "\r" in value[key]
    ):
        raise ConfigurationError(f"{section}.{key} must be a non-empty string")


def _optional_bool(value: dict[str, Any], key: str, section: str) -> None:
    if key in value and not isinstance(value[key], bool):
        raise ConfigurationError(f"{section}.{key} must be a boolean")


def _optional_schema_uri(value: dict[str, Any]) -> None:
    if "$schema" not in value:
        return
    schema_uri = value["$schema"]
    if (
        not isinstance(schema_uri, str)
        or not 1 <= len(schema_uri) <= 2048
        or not re.fullmatch(r"[A-Za-z][A-Za-z0-9+.-]*:\S+", schema_uri)
    ):
        raise ConfigurationError("root.$schema must be a bounded absolute URI")
    try:
        parsed = urlsplit(schema_uri)
    except ValueError as error:
        raise ConfigurationError("root.$schema must be a bounded absolute URI") from error
    if not parsed.scheme:
        raise ConfigurationError("root.$schema must be a bounded absolute URI")


def _validate_argv(value: Any, field: str) -> list[str]:
    if not isinstance(value, list) or not value or len(value) > 64:
        raise ConfigurationError(f"{field} must be a non-empty argv array")
    if not all(isinstance(part, str) and part and len(part) <= 4096 for part in value):
        raise ConfigurationError(f"{field} argv items must be non-empty strings")
    for part in value:
        if "\x00" in part or "\n" in part or "\r" in part or "$(" in part or "`" in part:
            raise ConfigurationError(f"{field} contains forbidden shell syntax or control bytes")
        allowed = {
            "MOBILE_RELEASE_AAB_PATH",
            "MOBILE_RELEASE_IPA_PATH",
            "MOBILE_RELEASE_DSYM_PATH",
        }
        cursor = 0
        while (start := part.find("${", cursor)) >= 0:
            match = re.match(r"\$\{([A-Z][A-Z0-9_]*)\}", part[start:])
            if match is None or match.group(1) not in allowed:
                raise ConfigurationError(
                    f"{field} contains an unsupported variable placeholder"
                )
            cursor = start + match.end()
    return value


def _validate_commands(value: Any, field: str) -> None:
    if not isinstance(value, list) or len(value) > 32:
        raise ConfigurationError(f"{field} must be an array of argv arrays")
    for index, command in enumerate(value):
        _validate_argv(command, f"{field}[{index}]")


def _validate_config(data: dict[str, Any]) -> None:
    _reject_unknown("root", data, ROOT_KEYS)
    missing_sections = sorted(REQUIRED_ROOT_SECTIONS - set(data))
    if missing_sections:
        raise ConfigurationError(
            f"missing required root field(s): {', '.join(missing_sections)}"
        )
    if type(data.get("schemaVersion")) is not int or data["schemaVersion"] != 1:
        raise ConfigurationError("schemaVersion must be exactly 1")
    _optional_schema_uri(data)

    for section, allowed in SECTION_KEYS.items():
        if section in data:
            section_value = _object(data[section], section)
            _reject_unknown(section, section_value, allowed)

    version = _object(data.get("version"), "version")
    for key in ("source", "nameKey", "buildKey"):
        _optional_string(version, key, "version")
        if key not in version:
            raise ConfigurationError(f"version.{key} is required")
    _validate_relative_path(version["source"], "version.source")
    for key in ("nameKey", "buildKey"):
        if not CONFIG_KEY_RE.fullmatch(version[key]):
            raise ConfigurationError(f"version.{key} must be an uppercase configuration key")

    source = _object(data.get("source"), "source")
    for key in ("candidateBranch", "productionBranch"):
        _optional_string(source, key, "source")
        if key not in source:
            raise ConfigurationError(f"source.{key} is required")
        if len(source[key]) > 255 or not BRANCH_RE.fullmatch(source[key]):
            raise ConfigurationError(f"source.{key} is not a safe Git branch name")
    _optional_bool(source, "projectReadTokenRequired", "source")

    for platform in ("android", "ios"):
        section = _object(data.get(platform), platform)
        _optional_bool(section, "enabled", platform)
        if "enabled" not in section:
            raise ConfigurationError(f"{platform}.enabled is required")
        for key, item in section.items():
            if key not in {"enabled", "prepareCommand", "symbols", "review", "externalTrack"}:
                _optional_string(section, key, platform)
        status = section.get("identityStatus", "unverified")
        if status not in IDENTITY_STATUSES:
            raise ConfigurationError(
                f"{platform}.identityStatus must be one of {sorted(IDENTITY_STATUSES)}"
            )
        if section.get("enabled"):
            identity_key = "applicationId" if platform == "android" else "bundleId"
            if not section.get(identity_key) or "identityStatus" not in section:
                raise ConfigurationError(
                    f"enabled {platform} requires {platform}.{identity_key} and identityStatus"
                )
        elif set(section) - {"enabled"}:
            raise ConfigurationError(f"disabled {platform} must contain only enabled=false")
    if not any(data[platform].get("enabled") for platform in ("android", "ios")):
        raise ConfigurationError("at least one release platform must be enabled")

    android = _object(data.get("android", {}), "android")
    if android.get("enabled"):
        identity = android.get("applicationId", "")
        if len(identity) > 255 or not ANDROID_ID_RE.fullmatch(identity):
            raise ConfigurationError("android.applicationId is invalid")
        if "module" in android and not re.fullmatch(
            r"^:$|^:[A-Za-z0-9_.-]+(?::[A-Za-z0-9_.-]+)*$", android["module"]
        ):
            raise ConfigurationError("android.module is not a Gradle module path")
        if len(android.get("module", "")) > 512:
            raise ConfigurationError("android.module must be at most 512 characters")
        if "variant" in android and not re.fullmatch(
            r"^[A-Za-z][A-Za-z0-9_-]*$", android["variant"]
        ):
            raise ConfigurationError("android.variant is invalid")
        if len(android.get("variant", "")) > 128:
            raise ConfigurationError("android.variant must be at most 128 characters")
    if "externalTrack" in android:
        track = _object(android["externalTrack"], "android.externalTrack")
        _reject_unknown("android.externalTrack", track, {"name", "kind"})
        for key in ("name", "kind"):
            if key not in track:
                raise ConfigurationError(f"android.externalTrack.{key} is required")
        _optional_string(track, "name", "android.externalTrack")
        if len(track["name"]) > 100:
            raise ConfigurationError("android.externalTrack.name must be at most 100 characters")
        if track.get("kind") not in TRACK_KINDS:
            raise ConfigurationError(
                f"android.externalTrack.kind must be one of {sorted(TRACK_KINDS)}"
            )
        if track.get("name") in {"internal", "production"}:
            raise ConfigurationError("android.externalTrack.name must be a testing track")
    if "uploadCertificateSha256" in android and not FINGERPRINT_RE.fullmatch(
        android["uploadCertificateSha256"]
    ):
        raise ConfigurationError("android.uploadCertificateSha256 is invalid or a placeholder")
    if android.get("enabled") and android.get("identityStatus") == "approved":
        for key in ("externalTrack", "uploadCertificateSha256"):
            if key not in android:
                raise ConfigurationError(f"approved Android identity requires android.{key}")

    ios = _object(data.get("ios", {}), "ios")
    if ios.get("enabled"):
        bundle_id = ios.get("bundleId", "")
        if len(bundle_id) > 255 or not IOS_ID_RE.fullmatch(bundle_id):
            raise ConfigurationError("ios.bundleId is invalid")
    if "project" in ios and "workspace" in ios:
        raise ConfigurationError("ios.project and ios.workspace are mutually exclusive")
    for key in ("project", "workspace"):
        if key in ios:
            _validate_relative_path(ios[key], f"ios.{key}")
    for key in ("scheme", "archiveConfiguration", "externalTestFlightGroup"):
        if len(ios.get(key, "")) > 255:
            raise ConfigurationError(f"ios.{key} must be at most 255 characters")
    if "prepareCommand" in ios:
        _validate_argv(ios["prepareCommand"], "ios.prepareCommand")
    if "symbols" in ios:
        symbols = _object(ios["symbols"], "ios.symbols")
        _reject_unknown("ios.symbols", symbols, {"policy", "uploadCommand"})
        if symbols.get("policy") not in SYMBOL_POLICIES:
            raise ConfigurationError(f"ios.symbols.policy must be one of {sorted(SYMBOL_POLICIES)}")
        if "uploadCommand" in symbols:
            _validate_argv(symbols["uploadCommand"], "ios.symbols.uploadCommand")
        if symbols.get("policy") == "required" and "uploadCommand" not in symbols:
            raise ConfigurationError(
                "ios.symbols.uploadCommand is required when ios.symbols.policy is required"
            )
        if symbols.get("policy") != "required" and "uploadCommand" in symbols:
            raise ConfigurationError(
                "ios.symbols.uploadCommand is only allowed when ios.symbols.policy is required"
            )
    if "review" in ios:
        review = _object(ios["review"], "ios.review")
        _reject_unknown(
            "ios.review", review, {"usesNonExemptEncryption", "demoAccountRequired"}
        )
        for key in ("usesNonExemptEncryption", "demoAccountRequired"):
            _optional_bool(review, key, "ios.review")
            if key not in review:
                raise ConfigurationError(f"ios.review.{key} is required")
    if "teamId" in ios and not TEAM_ID_RE.fullmatch(ios["teamId"]):
        raise ConfigurationError("ios.teamId is invalid")
    if "appStoreAppId" in ios and not APP_STORE_ID_RE.fullmatch(ios["appStoreAppId"]):
        raise ConfigurationError("ios.appStoreAppId is invalid")
    if "distributionCertificateSha256" in ios and not FINGERPRINT_RE.fullmatch(
        ios["distributionCertificateSha256"]
    ):
        raise ConfigurationError(
            "ios.distributionCertificateSha256 is invalid or a placeholder"
        )
    if ios.get("enabled") and ios.get("identityStatus") == "approved":
        for key in (
            "appStoreAppId",
            "teamId",
            "externalTestFlightGroup",
            "distributionCertificateSha256",
            "symbols",
            "review",
        ):
            if key not in ios:
                raise ConfigurationError(f"approved iOS identity requires ios.{key}")

    metadata = _object(data.get("metadata"), "metadata")
    _optional_string(metadata, "root", "metadata")
    for key in ("root", "androidLocales", "iosLocales"):
        if key not in metadata:
            raise ConfigurationError(f"metadata.{key} is required")
    _validate_relative_path(metadata["root"], "metadata.root")
    for key in ("androidLocales", "iosLocales"):
        if key in metadata:
            values = metadata[key]
            if not isinstance(values, list) or not all(
                isinstance(locale, str) and locale for locale in values
            ):
                raise ConfigurationError(f"metadata.{key} must be an array of locale strings")
            if len(values) != len(set(values)):
                raise ConfigurationError(f"metadata.{key} contains duplicate locales")
            if any(not LOCALE_RE.fullmatch(locale) for locale in values):
                raise ConfigurationError(f"metadata.{key} contains an invalid locale")
    if android.get("enabled") and not metadata["androidLocales"]:
        raise ConfigurationError("enabled Android requires at least one metadata.androidLocales")
    if ios.get("enabled") and not metadata["iosLocales"]:
        raise ConfigurationError("enabled iOS requires at least one metadata.iosLocales")

    services = _object(data.get("services"), "services")
    for key in ("androidFirebase", "iosFirebase"):
        if key not in services:
            raise ConfigurationError(f"services.{key} is required")
    for key, value in services.items():
        if value not in SERVICE_POLICIES:
            raise ConfigurationError(f"services.{key} must be one of {sorted(SERVICE_POLICIES)}")

    checks = _object(data.get("projectChecks"), "projectChecks")
    for key in ("preflight", "androidArtifact", "iosArtifact"):
        if key not in checks:
            raise ConfigurationError(f"projectChecks.{key} is required")
    for key, commands in checks.items():
        _validate_commands(commands, f"projectChecks.{key}")


def _validate_relative_path(value: str, field: str) -> None:
    path = Path(value)
    if (
        path.is_absolute()
        or not value
        or len(value) > 512
        or bool(re.match(r"^[A-Za-z]:", value))
        or "\\" in value
        or any(part in {"", ".", ".."} for part in value.split("/"))
    ):
        raise ConfigurationError(f"{field} must be a safe repository-relative path")


@dataclass(frozen=True)
class ReleaseVersion:
    name: str
    build: int


@dataclass(frozen=True)
class ReleaseConfig:
    path: Path
    root: Path
    data: dict[str, Any]

    def section(self, name: str) -> dict[str, Any]:
        return dict(self.data.get(name, {}))

    def platform_enabled(self, name: str) -> bool:
        return bool(self.data.get(name, {}).get("enabled", False))

    @property
    def enabled_platforms(self) -> tuple[str, ...]:
        return tuple(name for name in ("android", "ios") if self.platform_enabled(name))

    def project_path(self, value: str) -> Path:
        supplied = Path(value).expanduser()
        if supplied.is_absolute():
            absolute = Path(os.path.abspath(supplied))
            repository_alias = next(
                (
                    ancestor
                    for ancestor in (absolute, *absolute.parents)
                    if ancestor.resolve() == self.root
                ),
                None,
            )
            if repository_alias is None or repository_alias.is_symlink():
                raise ConfigurationError(f"project path escapes repository root: {value}")
            relative = absolute.relative_to(repository_alias)
        else:
            relative = supplied
        lexical = self.root
        for part in relative.parts:
            if part in {"", "."}:
                continue
            lexical = lexical / part
            if lexical.is_symlink():
                raise ConfigurationError(
                    f"project path must not traverse a symbolic link: {value}"
                )
        candidate = (self.root / relative).resolve()
        try:
            candidate.relative_to(self.root.resolve())
        except ValueError as error:
            raise ConfigurationError(f"project path escapes repository root: {value}") from error
        return candidate

    def release_version(self) -> ReleaseVersion:
        spec = self.section("version")
        path = self.project_path(spec["source"])
        values = parse_key_value_file(path)
        name_key = spec["nameKey"]
        build_key = spec["buildKey"]
        if name_key not in values:
            raise ConfigurationError(f"version source does not contain {name_key}: {path}")
        if build_key not in values:
            raise ConfigurationError(f"version source does not contain {build_key}: {path}")
        name = values[name_key]
        if len(name) > 64 or not VERSION_RE.fullmatch(name):
            raise ConfigurationError(f"invalid marketing version {name!r}; use dotted numeric form")
        if self.platform_enabled("ios") and not IOS_MARKETING_VERSION_RE.fullmatch(name):
            raise ConfigurationError(
                "iOS marketing version must contain two or three dot-separated numeric components"
            )
        build_text = values[build_key]
        if not re.fullmatch(r"[1-9][0-9]*", build_text):
            raise ConfigurationError(f"{build_key} must be a canonical positive base-10 integer")
        build = int(build_text, 10)
        if build < 1 or build > 2_100_000_000:
            raise ConfigurationError(f"{build_key} must be between 1 and 2100000000")
        return ReleaseVersion(name=name, build=build)

    def commands(self, phase: str) -> list[list[str]]:
        return [list(command) for command in self.data.get("projectChecks", {}).get(phase, [])]


def _lexical_repository_root(start: Path) -> Path:
    for candidate in (start, *start.parents):
        marker = candidate / ".git"
        if marker.exists() or marker.is_symlink():
            return candidate
    if start.name == "release":
        return start.parent
    return start


def load_config(path: Path | str) -> ReleaseConfig:
    requested_path = Path(os.path.abspath(Path(path).expanduser()))
    lexical_root = _lexical_repository_root(requested_path.parent)
    try:
        relative = requested_path.relative_to(lexical_root)
    except ValueError as error:
        raise ConfigurationError("configuration file is not lexically inside its repository") from error
    current = lexical_root
    if current.is_symlink():
        raise ConfigurationError(f"configuration path must not traverse a symlink: {current}")
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise ConfigurationError(f"configuration path must not traverse a symlink: {current}")
        if current != requested_path and current.exists() and not current.is_dir():
            raise ConfigurationError(f"configuration parent is not a directory: {current}")
    config_path = requested_path.resolve()
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(config_path, flags)
    except (FileNotFoundError, NotADirectoryError) as error:
        raise ConfigurationError(f"configuration file not found: {config_path}") from error
    except OSError as error:
        if config_path.is_symlink():
            raise ConfigurationError(f"configuration file must not be a symlink: {config_path}") from error
        raise ConfigurationError(f"configuration file could not be opened: {config_path}") from error
    try:
        details = os.fstat(descriptor)
        if not stat.S_ISREG(details.st_mode):
            raise ConfigurationError(f"configuration path is not a regular file: {config_path}")
        if details.st_size > MAX_CONFIG_BYTES:
            raise ConfigurationError(f"configuration file is unexpectedly large: {config_path}")
        with os.fdopen(descriptor, "r", encoding="utf-8") as handle:
            descriptor = -1
            raw = handle.read(MAX_CONFIG_BYTES + 1)
        if len(raw.encode("utf-8")) > MAX_CONFIG_BYTES:
            raise ConfigurationError(f"configuration file is unexpectedly large: {config_path}")
    except UnicodeDecodeError as error:
        raise ConfigurationError(f"configuration must be UTF-8: {config_path}") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    try:
        data = json.loads(raw, object_pairs_hook=_reject_duplicate_pairs)
    except json.JSONDecodeError as error:
        raise ConfigurationError(
            f"invalid JSON at line {error.lineno}, column {error.colno}: {error.msg}"
        ) from error
    data = _object(data, "root")
    _validate_config(data)
    root = find_repository_root(config_path.parent)
    return ReleaseConfig(path=config_path, root=root, data=data)


def find_repository_root(start: Path) -> Path:
    current = start.resolve()
    for candidate in (current, *current.parents):
        if (candidate / ".git").exists():
            return candidate
    # Temporary projects and source archives may not carry .git.
    if current.name == "release":
        return current.parent
    return current


def parse_key_value_file(path: Path) -> dict[str, str]:
    if not path.is_file():
        raise ConfigurationError(f"version source not found: {path}")
    if path.is_symlink():
        raise ConfigurationError(f"version source must not be a symlink: {path}")
    if path.stat().st_size > 64 * 1024:
        raise ConfigurationError(f"version source is unexpectedly large: {path}")
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise ConfigurationError(f"version source must be UTF-8: {path}") from error
    result: dict[str, str] = {}
    for number, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line or line.startswith(("#", "//", ";")):
            continue
        if "=" not in line:
            raise ConfigurationError(f"invalid version line {number}: expected KEY=VALUE")
        key, value = (part.strip() for part in line.split("=", 1))
        if not KEY_RE.fullmatch(key):
            raise ConfigurationError(f"invalid version key on line {number}: {key!r}")
        if key in result:
            raise ConfigurationError(f"duplicate version key on line {number}: {key}")
        if not value or "$" in value or "`" in value or "\x00" in value:
            raise ConfigurationError(f"unsafe or empty version value on line {number}: {key}")
        starts_quote = value.startswith(("'", '"'))
        ends_quote = value.endswith(("'", '"'))
        if starts_quote or ends_quote:
            if not (starts_quote and ends_quote and value[0] == value[-1]):
                raise ConfigurationError(f"unmatched version quote on line {number}: {key}")
            value = value[1:-1]
        if not value or value != value.strip():
            raise ConfigurationError(f"unsafe or empty version value on line {number}: {key}")
        result[key] = value
    return result


def default_config(root: Path, discovered: dict[str, Any]) -> dict[str, Any]:
    version_source = discovered.get("versionSource", "release/version.properties")
    android_id = (
        discovered.get("android", {}).get("applicationId") or "com.example.product"
    )
    ios_id = discovered.get("ios", {}).get("bundleId") or "com.example.product"
    android_found = bool(discovered.get("android"))
    ios_found = bool(discovered.get("ios"))
    android: dict[str, Any] = {"enabled": False}
    if android_found:
        android = {
            "enabled": True,
            "applicationId": android_id,
            "identityStatus": "unverified",
        }
    ios: dict[str, Any] = {"enabled": False}
    if ios_found:
        ios = {
            "enabled": True,
            "bundleId": ios_id,
            "identityStatus": "unverified",
        }
    return {
        "schemaVersion": 1,
        "version": {
            "source": version_source,
            "nameKey": discovered.get("versionNameKey", "VERSION_NAME"),
            "buildKey": discovered.get("versionBuildKey", "BUILD_NUMBER"),
        },
        "source": {"candidateBranch": "main", "productionBranch": "main"},
        "android": android,
        "ios": ios,
        "metadata": {
            "root": "release/store",
            "androidLocales": ["en-US"] if android_found else [],
            "iosLocales": ["en-US"] if ios_found else [],
        },
        "services": {"androidFirebase": "disabled", "iosFirebase": "disabled"},
        "projectChecks": {"preflight": [], "androidArtifact": [], "iosArtifact": []},
    }
