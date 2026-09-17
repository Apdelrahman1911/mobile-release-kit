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
# Shared structural/conditional facts for validation and the pure draft editor.
# The editor never infers policy by parsing help prose or a project's values.
REQUIRED_SECTION_FIELDS = {
    "version": ("source", "nameKey", "buildKey"),
    "source": ("candidateBranch", "productionBranch"),
    "metadata": ("root", "androidLocales", "iosLocales"),
    "services": ("androidFirebase", "iosFirebase"),
    "projectChecks": ("preflight", "androidArtifact", "iosArtifact"),
}
PLATFORM_IDENTITY_FIELDS = {"android": "applicationId", "ios": "bundleId"}
APPROVED_IDENTITY_FIELDS = {
    "android": ("externalTrack", "uploadCertificateSha256"),
    "ios": (
        "appStoreAppId", "teamId", "externalTestFlightGroup",
        "distributionCertificateSha256", "symbols", "review",
    ),
}
NESTED_SECTION_KEYS = {
    "android.externalTrack": {"name", "kind"},
    "ios.symbols": {"policy", "uploadCommand"},
    "ios.review": {"usesNonExemptEncryption", "demoAccountRequired"},
}
REQUIRED_NESTED_FIELDS = {
    "android.externalTrack": ("name", "kind"),
    "ios.symbols": ("policy",),
    "ios.review": ("usesNonExemptEncryption", "demoAccountRequired"),
}
IOS_PROJECT_CHOICES = ("project", "workspace")
CONFIGURATION_OBJECT_KEYS = {"": ROOT_KEYS, **SECTION_KEYS, **NESTED_SECTION_KEYS}
CONFIGURATION_FIELD_PATHS = tuple(sorted(
    (f"{parent}.{key}" if parent else key)
    for parent, keys in CONFIGURATION_OBJECT_KEYS.items() for key in keys
    if (f"{parent}.{key}" if parent else key) not in CONFIGURATION_OBJECT_KEYS
))
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


def _section_data(data: dict[str, Any], name: str) -> dict[str, Any]:
    value = data.get(name)
    return value if type(value) is dict else {}


def _enabled_state(section: dict[str, Any]) -> bool | None:
    value = section.get("enabled")
    return value if type(value) is bool else None


def _approved_state(section: dict[str, Any]) -> bool | None:
    value = section.get("identityStatus")
    return value == "approved" if isinstance(value, str) and value in IDENTITY_STATUSES else None


def _symbols_required_state(symbols: dict[str, Any]) -> bool | None:
    value = symbols.get("policy")
    return value == "required" if isinstance(value, str) and value in SYMBOL_POLICIES else None


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
    for key in REQUIRED_SECTION_FIELDS["version"]:
        _optional_string(version, key, "version")
        if key not in version:
            raise ConfigurationError(f"version.{key} is required")
    _validate_relative_path(version["source"], "version.source")
    for key in ("nameKey", "buildKey"):
        if not CONFIG_KEY_RE.fullmatch(version[key]):
            raise ConfigurationError(f"version.{key} must be an uppercase configuration key")

    source = _object(data.get("source"), "source")
    for key in REQUIRED_SECTION_FIELDS["source"]:
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
        if _enabled_state(section) is True:
            identity_key = PLATFORM_IDENTITY_FIELDS[platform]
            if not section.get(identity_key) or "identityStatus" not in section:
                raise ConfigurationError(
                    f"enabled {platform} requires {platform}.{identity_key} and identityStatus"
                )
        elif set(section) - {"enabled"}:
            raise ConfigurationError(f"disabled {platform} must contain only enabled=false")
    if not any(_enabled_state(data[platform]) is True for platform in ("android", "ios")):
        raise ConfigurationError("at least one release platform must be enabled")

    android = _object(data.get("android", {}), "android")
    if _enabled_state(android) is True:
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
        _reject_unknown("android.externalTrack", track, NESTED_SECTION_KEYS["android.externalTrack"])
        for key in REQUIRED_NESTED_FIELDS["android.externalTrack"]:
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
    if _enabled_state(android) is True and _approved_state(android) is True:
        for key in APPROVED_IDENTITY_FIELDS["android"]:
            if key not in android:
                raise ConfigurationError(f"approved Android identity requires android.{key}")

    ios = _object(data.get("ios", {}), "ios")
    if _enabled_state(ios) is True:
        bundle_id = ios.get("bundleId", "")
        if len(bundle_id) > 255 or not IOS_ID_RE.fullmatch(bundle_id):
            raise ConfigurationError("ios.bundleId is invalid")
    if all(key in ios for key in IOS_PROJECT_CHOICES):
        raise ConfigurationError("ios.project and ios.workspace are mutually exclusive")
    for key in IOS_PROJECT_CHOICES:
        if key in ios:
            _validate_relative_path(ios[key], f"ios.{key}")
    for key in ("scheme", "archiveConfiguration", "externalTestFlightGroup"):
        if len(ios.get(key, "")) > 255:
            raise ConfigurationError(f"ios.{key} must be at most 255 characters")
    if "prepareCommand" in ios:
        _validate_argv(ios["prepareCommand"], "ios.prepareCommand")
    if "symbols" in ios:
        symbols = _object(ios["symbols"], "ios.symbols")
        _reject_unknown("ios.symbols", symbols, NESTED_SECTION_KEYS["ios.symbols"])
        if symbols.get("policy") not in SYMBOL_POLICIES:
            raise ConfigurationError(f"ios.symbols.policy must be one of {sorted(SYMBOL_POLICIES)}")
        if "uploadCommand" in symbols:
            _validate_argv(symbols["uploadCommand"], "ios.symbols.uploadCommand")
        if _symbols_required_state(symbols) is True and "uploadCommand" not in symbols:
            raise ConfigurationError(
                "ios.symbols.uploadCommand is required when ios.symbols.policy is required"
            )
        if _symbols_required_state(symbols) is False and "uploadCommand" in symbols:
            raise ConfigurationError(
                "ios.symbols.uploadCommand is only allowed when ios.symbols.policy is required"
            )
    if "review" in ios:
        review = _object(ios["review"], "ios.review")
        _reject_unknown(
            "ios.review", review, NESTED_SECTION_KEYS["ios.review"]
        )
        for key in REQUIRED_NESTED_FIELDS["ios.review"]:
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
    if _enabled_state(ios) is True and _approved_state(ios) is True:
        for key in APPROVED_IDENTITY_FIELDS["ios"]:
            if key not in ios:
                raise ConfigurationError(f"approved iOS identity requires ios.{key}")

    metadata = _object(data.get("metadata"), "metadata")
    _optional_string(metadata, "root", "metadata")
    for key in REQUIRED_SECTION_FIELDS["metadata"]:
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
    if _enabled_state(android) is True and not metadata["androidLocales"]:
        raise ConfigurationError("enabled Android requires at least one metadata.androidLocales")
    if _enabled_state(ios) is True and not metadata["iosLocales"]:
        raise ConfigurationError("enabled iOS requires at least one metadata.iosLocales")

    services = _object(data.get("services"), "services")
    for key in REQUIRED_SECTION_FIELDS["services"]:
        if key not in services:
            raise ConfigurationError(f"services.{key} is required")
    for key, value in services.items():
        if value not in SERVICE_POLICIES:
            raise ConfigurationError(f"services.{key} must be one of {sorted(SERVICE_POLICIES)}")

    checks = _object(data.get("projectChecks"), "projectChecks")
    for key in REQUIRED_SECTION_FIELDS["projectChecks"]:
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


def validate_config_data(data: Any) -> None:
    """Validate configuration policy in memory without resolving any paths.

    This is the shared CLI/API policy, not a build, account or filesystem check.
    Malformed JSON container types must not leak an implementation TypeError
    from enum membership tests. Valid inputs and first-policy-error ordering are
    otherwise unchanged.
    """
    data = _object(data, "root")
    try:
        _validate_config(data)
    except (TypeError, ValueError, OverflowError) as error:
        raise ConfigurationError("configuration contains an invalid value type") from error


_FIELD_MISSING = object()


def _field_value(data: dict[str, Any], path: str) -> Any:
    current: Any = data
    for part in path.split("."):
        if type(current) is not dict or part not in current:
            return _FIELD_MISSING
        current = current[part]
    return current


def _field_state(data: dict[str, Any], path: str) -> tuple[str, str]:
    parts = path.split(".")
    if len(parts) == 1:
        return (("required", "The configuration schema version is required.")
                if path == "schemaVersion" else
                ("optional", "The schema reference is optional and is never fetched."))
    section_name, name = parts[:2]
    section = data.get(section_name)
    if type(section) is not dict:
        return "unknown", "The parent section is missing or is not an object; no value was replaced."
    if section_name in PLATFORM_IDENTITY_FIELDS:
        enabled = _enabled_state(section)
        if name == "enabled":
            return "required", "Declare a boolean platform selection; at least one platform must be enabled."
        if enabled is None:
            return "unknown", "Platform enabled is missing or is not a boolean; dependent settings were preserved."
        if not enabled:
            return "forbidden", "A disabled platform permits only enabled=false; explicitly review dependent removals."
        if name in {PLATFORM_IDENTITY_FIELDS[section_name], "identityStatus"}:
            return "required", "An enabled platform requires its application identity and declared identity status."
        if section_name == "ios" and name in IOS_PROJECT_CHOICES:
            if any(choice != name and choice in section for choice in IOS_PROJECT_CHOICES):
                return "forbidden", "Project and workspace are mutually exclusive; explicitly choose which setting to retain."
            return "optional", "Choose a project or workspace if needed; both cannot be configured together."
        approved = _approved_state(section)
        if len(parts) == 3:
            nested = section.get(name, _FIELD_MISSING)
            if nested is not _FIELD_MISSING and type(nested) is not dict:
                return "unknown", "The containing setting is not an object; its malformed value was preserved."
            if name == "symbols" and parts[2] == "uploadCommand":
                required = _symbols_required_state(nested if type(nested) is dict else {})
                if required is None:
                    return "unknown", "Choose a valid symbols policy before assessing its upload command."
                if required:
                    return "required", "An upload command is required when symbols policy is required; it is not executed here."
                return "forbidden", "An upload command is allowed only when symbols policy is required; removal is explicit."
            if type(nested) is dict:
                if parts[2] in REQUIRED_NESTED_FIELDS[f"{section_name}.{name}"]:
                    return "required", "Every required member of this explicitly configured setting must be supplied."
                return "optional", "This member is optional within the explicitly configured setting."
            if approved is None:
                return "unknown", "Identity status is missing or invalid; approval-dependent requirements are unknown."
            if approved:
                return "required", "A declared approved identity requires this setting; approval is not verified here."
            return "optional", "This setting is optional for an unapproved identity; configuring it requires its members."
        if name in APPROVED_IDENTITY_FIELDS[section_name]:
            if approved is None:
                return "unknown", "Identity status is missing or invalid; approval-dependent requirements are unknown."
            if approved:
                return "required", "A declared approved identity requires this setting; approval is not verified here."
        return "optional", "This setting is optional for the current declared platform policy."
    if section_name == "metadata" and name in {"androidLocales", "iosLocales"}:
        platform = "android" if name == "androidLocales" else "ios"
        enabled = _enabled_state(_section_data(data, platform))
        if enabled is None:
            return "unknown", "The locale array is required, but its minimum depends on a valid platform enabled value."
        if enabled:
            return "required", "An enabled platform requires a nonempty, unique list of valid locales."
        return "required", "The locale array is required even for a disabled platform and may be empty."
    if name in REQUIRED_SECTION_FIELDS.get(section_name, ()):
        return "required", "This field is required by the shared configuration policy."
    return "optional", "This field is optional under the shared configuration policy."


def configuration_field_context(data: dict[str, Any]) -> list[dict[str, Any]]:
    """Known-field presentation derived from the same facts as validation.

    Callers admit/bound JSON first. This neither normalizes a draft nor removes
    forbidden or malformed values. Reasons and paths never contain input text.
    """
    result = []
    for path in CONFIGURATION_FIELD_PATHS:
        state, reason = _field_state(data, path)
        result.append({"path": path, "state": state,
                       "present": _field_value(data, path) is not _FIELD_MISSING,
                       "reason": reason})
    return result


def parse_config_text(raw: str) -> dict[str, Any]:
    """Parse bounded UTF-8 JSON and validate policy, without reading or writing.

    The optional $schema is informational: it is never fetched or imported.
    """
    if not isinstance(raw, str):
        raise ConfigurationError("configuration must be UTF-8 JSON text")
    try:
        size = len(raw.encode("utf-8"))
    except UnicodeError as error:
        raise ConfigurationError("configuration must be UTF-8 JSON text") from error
    if size > MAX_CONFIG_BYTES:
        raise ConfigurationError("configuration file is unexpectedly large")

    def reject_constant(_: str) -> None:
        raise ConfigurationError("configuration must not contain non-finite numbers")

    try:
        data = json.loads(raw, object_pairs_hook=_reject_duplicate_pairs,
                          parse_constant=reject_constant)
    except json.JSONDecodeError as error:
        raise ConfigurationError(
            f"invalid JSON at line {error.lineno}, column {error.colno}: {error.msg}"
        ) from error
    except (RecursionError, ValueError) as error:
        raise ConfigurationError("configuration JSON is too complex") from error
    validate_config_data(data)
    return data


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
    data = parse_config_text(raw)
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


def default_config_data(discovered: dict[str, Any]) -> dict[str, Any]:
    """Pure configuration suggestions from already supplied discovery hints.

    No root, file or project is inspected. Missing identities are examples;
    platform detection and defaults never establish approved release identity.
    The desktop admits its smaller closed hint contract before calling this.
    """
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


def default_config(root: Path, discovered: dict[str, Any]) -> dict[str, Any]:
    """Compatibility entry point; the historical root argument is not consumed."""
    return default_config_data(discovered)
