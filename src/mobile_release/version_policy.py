"""Optional version DATA policy, not source, Store or mutation authority.

Manual is the default. Automatic proposals require explicit exact-ref rules and
complete, fresh observations supplied by the original Store owners. No clock,
file, credential, process, network request or allocation lives in this module.
Arithmetic is NOT coordination: only the repository allocator can reserve it.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

from .config import ReleaseVersion, release_version_from_values
from .errors import ConfigurationError

MAX_BUILD = 2_100_000_000
# ios._archive_command and ios_artifacts require the shared integer verbatim as
# CURRENT_PROJECT_VERSION/CFBundleVersion, not a converted dotted build. Bound
# automatic allocation to CFBundleVersion's four-digit first component. This
# deliberately does not change the existing, wider manual parser policy.
IOS_INTEGER_MAX_BUILD = 9999
MAX_RULES = 32
MAX_STORE_AGE_SECONDS = 3600
INCREMENTS = frozenset({"build", "patch", "minor", "major"})
_SHA = re.compile(r"[0-9a-f]{40}\Z", re.ASCII)
_DIGEST = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_NUMERIC_VERSION = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*))?\Z", re.ASCII)
REASONS = frozenset({"invalid-input", "invalid-policy", "manual-policy", "ambiguous-rule",
    "ref-not-allowed", "unsupported-version", "build-exhausted", "ios-integer-build-exhausted",
    "store-observation-incomplete", "store-observation-stale", "store-identity-changed",
    "store-platform-mismatch", "store-format-unsupported", "reservation-consumed"})


class VersionPolicyError(ValueError):
    """Closed diagnostics; rejected source/provider values are never reflected."""

    def __init__(self, reason: str = "invalid-input") -> None:
        if reason not in REASONS:
            reason = "invalid-input"
        self.reason = reason
        super().__init__("Version policy input was refused")


def _need(condition: bool, reason: str = "invalid-input") -> None:
    if not condition:
        raise VersionPolicyError(reason)


def _object(value: object, keys: set[str]) -> dict[str, Any]:
    _need(type(value) is dict and set(value) == keys)
    return value  # type: ignore[return-value]


def canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True,
                      separators=(",", ":")).encode("ascii")


def digest(value: object) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def _match(value: object, pattern: re.Pattern[str]) -> str:
    _need(type(value) is str and pattern.fullmatch(value) is not None)
    return value  # type: ignore[return-value]


def _integer(value: object, maximum: int, minimum: int = 0) -> int:
    _need(type(value) is int and minimum <= value <= maximum)
    return value  # type: ignore[return-value]


def platforms(value: object) -> tuple[str, ...]:
    _need(type(value) is tuple and value in (("android",), ("ios",), ("android", "ios")))
    return value  # type: ignore[return-value]


def source_ref(value: object) -> str:
    """Exact bounded branch/tag subset. No glob, inferred tag or detached HEAD."""
    _need(type(value) is str and len(value) <= 220)
    prefix = next((p for p in ("refs/heads/", "refs/tags/") if value.startswith(p)), None)
    _need(prefix is not None)
    name = value[len(prefix):]
    _need(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,199}", name) is not None)
    parts = name.split("/")
    _need(len(parts) <= 16 and ".." not in name and not name.startswith("refs/")
          and all(part and not part.startswith(".") and not part.endswith((".", ".lock"))
                  for part in parts))
    return value


def version(value: object, enabled: tuple[str, ...], *, automatic: bool = False) -> ReleaseVersion:
    """The shared release parser remains authoritative for ordinary values."""
    platforms(enabled)
    _need(type(value) is ReleaseVersion and type(value.name) is str
          and type(value.build) is int and 1 <= value.build <= MAX_BUILD)
    try:
        checked = release_version_from_values({"NAME": value.name, "BUILD": str(value.build)},
            name_key="NAME", build_key="BUILD", ios_enabled="ios" in enabled,
            source_label="version policy")
    except (ConfigurationError, TypeError, ValueError, UnicodeError):
        raise VersionPolicyError("unsupported-version") from None
    if automatic:
        _need(_NUMERIC_VERSION.fullmatch(checked.name) is not None, "unsupported-version")
    return checked


def version_value(value: ReleaseVersion) -> dict[str, Any]:
    return {"name": value.name, "build": value.build}


def parse_version(value: object, enabled: tuple[str, ...], *, automatic: bool = False) -> ReleaseVersion:
    row = _object(value, {"name", "build"})
    return version(ReleaseVersion(row["name"], row["build"]), enabled, automatic=automatic)


def numeric_version(name: str) -> tuple[int, int, int]:
    _need(type(name) is str and len(name) <= 64 and _NUMERIC_VERSION.fullmatch(name) is not None,
          "unsupported-version")
    parts = tuple(int(part) for part in name.split("."))
    return parts if len(parts) == 3 else (*parts, 0)


@dataclass(frozen=True, slots=True)
class RefRule:
    ref: str
    increment: str

    def __post_init__(self) -> None:
        source_ref(self.ref)
        _need(type(self.increment) is str and self.increment in INCREMENTS, "invalid-policy")

    @classmethod
    def parse(cls, value: object) -> RefRule:
        row = _object(value, {"ref", "increment"})
        return cls(row["ref"], row["increment"])

    def value(self) -> dict[str, str]:
        return {"ref": self.ref, "increment": self.increment}


@dataclass(frozen=True, slots=True)
class VersionPolicy:
    mode: str = "manual"
    rules: tuple[RefRule, ...] = ()
    build_ceiling: int = MAX_BUILD
    store_max_age_seconds: int = 900
    # v1 is byte-for-byte unchanged. v2/v3/v4 are explicit current-visible iOS,
    # Android and same-context paired inventories, not historical observations.
    store_scope: str = "application-all-builds"

    def __post_init__(self) -> None:
        _need(type(self.mode) is str and self.mode in {"manual", "automatic"}, "invalid-policy")
        _need(type(self.rules) is tuple and len(self.rules) <= MAX_RULES
              and all(type(rule) is RefRule for rule in self.rules), "invalid-policy")
        _integer(self.build_ceiling, MAX_BUILD, 1)
        _integer(self.store_max_age_seconds, MAX_STORE_AGE_SECONDS, 1)
        _need(type(self.store_scope) is str and self.store_scope in
              {"application-all-builds", "require-current-ios-inventory",
               "require-current-android-inventory", "require-current-shared-inventory"}, "invalid-policy")
        _need(self.store_scope == "application-all-builds" or self.mode == "automatic", "invalid-policy")
        _need((self.mode == "manual" and not self.rules)
              or (self.mode == "automatic" and bool(self.rules)), "invalid-policy")
        _need(len({rule.ref for rule in self.rules}) == len(self.rules), "ambiguous-rule")

    @classmethod
    def parse(cls, value: object = None) -> VersionPolicy:
        if value is None:
            return cls()
        _need(type(value) is dict and {"schemaVersion", "mode", "rules", "buildCeiling", "storeMaxAgeSeconds"} <= set(value))
        _need(type(value.get("schemaVersion")) is int
              and value["schemaVersion"] in {1, 2, 3, 4}, "invalid-policy")
        newer = value["schemaVersion"] != 1
        row = _object(value, {"schemaVersion", "mode", "rules", "buildCeiling", "storeMaxAgeSeconds"}
                      | ({"storeScope"} if newer else set()))
        _need(not newer or row["storeScope"] == {2: "require-current-ios-inventory",
            3: "require-current-android-inventory", 4: "require-current-shared-inventory"}[row["schemaVersion"]], "invalid-policy")
        _need(type(row["schemaVersion"]) is int
              and type(row["rules"]) is list and len(row["rules"]) <= MAX_RULES, "invalid-policy")
        return cls(row["mode"], tuple(RefRule.parse(rule) for rule in row["rules"]),
                   row["buildCeiling"], row["storeMaxAgeSeconds"],
                   row["storeScope"] if newer else "application-all-builds")

    def value(self) -> dict[str, Any]:
        result = {"schemaVersion": self.schema_version, "mode": self.mode,
                "rules": [rule.value() for rule in self.rules], "buildCeiling": self.build_ceiling,
                "storeMaxAgeSeconds": self.store_max_age_seconds}
        if self.schema_version != 1:
            result["storeScope"] = self.store_scope
        return result

    @property
    def schema_version(self) -> int:
        return {"application-all-builds": 1, "require-current-ios-inventory": 2,
                "require-current-android-inventory": 3, "require-current-shared-inventory": 4}[self.store_scope]

    @property
    def sha256(self) -> str:
        return digest(self.value())

    def increment_for(self, ref: str) -> str:
        _need(self.mode == "automatic", "manual-policy")
        source_ref(ref)
        matching = [rule.increment for rule in self.rules if rule.ref == ref]
        _need(len(matching) == 1, "ref-not-allowed" if not matching else "ambiguous-rule")
        return matching[0]


@dataclass(frozen=True, slots=True)
class SourceBinding:
    """Pre-edit source intent DATA, not the final signed candidate's source.

    The candidate owner must separately bind the approved version edit and the
    final committed clean source. A reservation never waives that requirement.
    """
    commit: str
    tree: str
    ref: str
    configuration_sha256: str
    version_sha256: str

    def __post_init__(self) -> None:
        _match(self.commit, _SHA)
        _match(self.tree, _SHA)
        source_ref(self.ref)
        _match(self.configuration_sha256, _DIGEST)
        _match(self.version_sha256, _DIGEST)

    @classmethod
    def parse(cls, value: object) -> SourceBinding:
        row = _object(value, {"commit", "tree", "ref", "configurationSha256", "versionSha256"})
        return cls(row["commit"], row["tree"], row["ref"], row["configurationSha256"], row["versionSha256"])

    def value(self) -> dict[str, str]:
        return {"commit": self.commit, "tree": self.tree, "ref": self.ref,
                "configurationSha256": self.configuration_sha256, "versionSha256": self.version_sha256}


@dataclass(frozen=True, slots=True)
class StoreObservation:
    """Sanitized original-provider DATA, never a Store response or consent.

    max_build covers ALL builds/trains, not one page/track or only releases.
    Unknown/dotted iOS formats must not be coerced to an integer by an adapter.
    Empty application observations use max_build=0 and marketing_version=None.
    """
    platform: str
    identity_revision: str
    revision: str
    observed_at: int
    max_build: int
    marketing_version: str | None
    complete: bool = True
    format_supported: bool = True

    def __post_init__(self) -> None:
        _need(type(self.platform) is str and self.platform in {"android", "ios"})
        _match(self.identity_revision, _DIGEST)
        _match(self.revision, _DIGEST)
        _integer(self.observed_at, (1 << 63) - 1)
        _integer(self.max_build, MAX_BUILD)
        _need(self.marketing_version is None or type(self.marketing_version) is str
              and 0 < len(self.marketing_version) <= 64)
        _need(type(self.complete) is bool and type(self.format_supported) is bool)

    @classmethod
    def parse(cls, value: object) -> StoreObservation:
        row = _object(value, {"platform", "identityRevision", "revision", "observedAt", "maxBuild",
                              "marketingVersion", "complete", "formatSupported", "scope"})
        _need(row["scope"] == "application-all-builds")
        return cls(row["platform"], row["identityRevision"], row["revision"], row["observedAt"],
                   row["maxBuild"], row["marketingVersion"], row["complete"], row["formatSupported"])

    def value(self) -> dict[str, Any]:
        return {"platform": self.platform, "identityRevision": self.identity_revision,
                "revision": self.revision, "observedAt": self.observed_at, "maxBuild": self.max_build,
                "marketingVersion": self.marketing_version, "complete": self.complete,
                "formatSupported": self.format_supported, "scope": "application-all-builds"}


def store_constraints(observations: tuple[StoreObservation, ...], enabled: tuple[str, ...],
                      identity_revision: str, policy: VersionPolicy, *, now: int) -> tuple[int, tuple[str, ...]]:
    platforms(enabled)
    _match(identity_revision, _DIGEST)
    _integer(now, (1 << 63) - 1)
    _need(type(policy) is VersionPolicy and type(observations) is tuple
          and len(observations) <= 2 and all(type(item) is StoreObservation for item in observations))
    _need(policy.store_scope == "application-all-builds", "invalid-policy")
    _need(tuple(item.platform for item in observations) == enabled, "store-platform-mismatch")
    for item in observations:
        _need(item.identity_revision == identity_revision, "store-identity-changed")
        _need(item.complete, "store-observation-incomplete")
        _need(item.format_supported, "store-format-unsupported")
        _need(0 <= now - item.observed_at <= policy.store_max_age_seconds, "store-observation-stale")
        _need((item.max_build == 0) == (item.marketing_version is None), "store-observation-incomplete")
        if item.marketing_version is not None:
            try:
                numeric_version(item.marketing_version)
            except VersionPolicyError:
                raise VersionPolicyError("store-format-unsupported") from None
    return (max(item.max_build for item in observations),
            tuple(item.marketing_version for item in observations if item.marketing_version is not None))


def propose_version(policy: VersionPolicy, *, source: str, base: ReleaseVersion,
                    allocated: ReleaseVersion, enabled: tuple[str, ...], identity_revision: str,
                    observations: tuple[StoreObservation, ...], now: int) -> ReleaseVersion:
    """Derive one proposal. Never expose this as an offline allocation fallback."""
    _need(type(policy) is VersionPolicy)
    increment = policy.increment_for(source)
    base = version(base, enabled, automatic=True)
    allocated = version(allocated, enabled, automatic=True)
    floor, marketing = store_constraints(observations, enabled, identity_revision, policy, now=now)
    next_build = max(base.build, allocated.build, floor) + 1
    if "ios" in enabled:
        _need(next_build <= IOS_INTEGER_MAX_BUILD, "ios-integer-build-exhausted")
    _need(next_build <= policy.build_ceiling, "build-exhausted")
    # Equal numeric forms preserve the saved form first; bump actions yield
    # three canonical components. A newer shared reservation cannot regress.
    name = max((base.name, allocated.name, *marketing), key=numeric_version)
    major, minor, patch = numeric_version(name)
    if increment != "build":
        parts = {"patch": (major, minor, patch + 1), "minor": (major, minor + 1, 0),
                 "major": (major + 1, 0, 0)}[increment]
        name = ".".join(str(part) for part in parts)
    return version(ReleaseVersion(name, next_build), enabled, automatic=True)


def check_reserved_for_new_release(reserved: ReleaseVersion, policy: VersionPolicy, *,
                                   enabled: tuple[str, ...], identity_revision: str,
                                   observations: tuple[StoreObservation, ...], now: int) -> None:
    """A retry can reuse allocated DATA without gaining fresh upload eligibility.

    Consumed values require a new candidate or original release recovery; never
    bump the same candidate to hide an earlier uncertain/accepted Store send.
    """
    version(reserved, enabled, automatic=True)
    floor, names = store_constraints(observations, enabled, identity_revision, policy, now=now)
    _need(reserved.build > floor and all(numeric_version(reserved.name) >= numeric_version(name)
                                      for name in names), "reservation-consumed")
