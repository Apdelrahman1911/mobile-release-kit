"""Local Store *draft* DATA, never permission to execute or recovery evidence.

No filesystem, Store, credential, journal, native or Git operation occurs here.
The future original owner must authenticate its journal, obtain fresh consent,
recheck source/material/artifact custody and enforce the Store state machine.
Existing CI authorization and evidence readers do not consume this contract.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import re
from pathlib import Path
from uuid import UUID

from .config import (
    ANDROID_ID_RE, BRANCH_RE, IOS_ID_RE, MAX_CONFIG_BYTES, MAX_VERSION_BYTES,
    ReleaseConfig, ReleaseVersion, parse_config_text, parse_key_value_text,
    release_version_from_values, validate_config_data,
)
from .discovery import GitContext, valid_observed_source
from .errors import ConfigurationError, ValidationError
from .provenance import _artifact_type, _reject_duplicate_pairs, canonical_json_bytes
from .release_confirmation import expected_confirmation

MAX_DRAFT_BYTES = 32 * 1024
STAGES = frozenset(("candidate", "external-testing", "production-submit"))
ORIGIN = "local-desktop"
_ERROR = "Invalid local Store draft"
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_TOKEN = re.compile(r"[0-9a-f]{32}\Z")
_TOP = {"documentType", "schemaVersion", "origin", "operationId", "projectId",
        "source", "platform", "stage", "application", "version", "confirmation",
        "configuration", "versionSource", "artifacts", "assignments", "predecessors"}


class LocalDraftError(ValidationError):
    """Fixed non-reflective failure: rejected private values are never echoed."""


def _need(condition: bool) -> None:
    if not condition:
        raise LocalDraftError(_ERROR)


def _keys(value: object, keys: set[str]) -> dict:
    _need(type(value) is dict and set(value) == keys)
    return value


def _text(value: object, maximum: int) -> bool:
    return (type(value) is str and 0 < len(value) <= maximum
            and all(ord(c) >= 32 and ord(c) != 127 for c in value))


def _sha(value: object) -> bool:
    return type(value) is str and _SHA.fullmatch(value) is not None


def _integer(value: object, maximum: int, minimum: int = 1) -> bool:
    return type(value) is int and minimum <= value <= maximum


def _uuid(value: object) -> bool:
    if not _text(value, 36):
        return False
    try:
        parsed = UUID(value)
        return parsed.version == 4 and str(parsed) == value
    except ValueError:
        return False


def _path(value: object, *, basename: bool = False) -> bool:
    if not _text(value, 255 if basename else 1024) or any(c in value for c in "\\:"):
        return False
    parts = value.split("/")
    return (not basename or len(parts) == 1) and all(part not in {"", ".", ".."}
        and len(part) <= 255 for part in parts)


@dataclass(frozen=True)
class LocalStorePolicy:
    """Explicit caller policy for drafting only; never a mutation enable flag."""
    enabled: bool = False
    candidate_branch: str = "main"
    production_branch: str = "main"

    @classmethod
    def from_config(cls, config: ReleaseConfig) -> LocalStorePolicy:
        """Derive draft policy from core-validated configuration, without IO.

        The native caller must provide its original saved configuration. A
        constructed ReleaseConfig is not proof of custody, consent or access.
        This method does not change the existing CI-only mutation guard.
        """
        _need(type(config) is ReleaseConfig)
        try:
            validate_config_data(config.data)
        except ConfigurationError:
            raise LocalDraftError(_ERROR) from None
        source = config.data["source"]
        return cls(enabled=source.get("localStoreEnabled", False),
                   candidate_branch=source["candidateBranch"],
                   production_branch=source["productionBranch"])


@dataclass(frozen=True)
class LocalReleaseDraft:
    operation_id: str
    project_id: str
    platform: str
    stage: str
    source: GitContext
    release: ReleaseVersion
    _canonical: bytes = field(repr=False)

    def to_dict(self) -> dict:
        """Return a detached copy; mutation cannot change the retained draft."""
        return json.loads(self._canonical)

    def to_bytes(self) -> bytes:
        return self._canonical


def _artifacts(rows: object, platform: str, metadata_sha: str) -> None:
    _need(type(rows) is list and 1 <= len(rows) <= 8)
    names: set[str] = set()
    files: set[str] = set()
    for row in rows:
        _keys(row, {"logicalName", "platform", "kind", "fileName", "size", "sha256", "architectures"})
        name = row["logicalName"]
        _need(_text(name, 64) and name not in names and name != "android-apk")
        expected_platform, expected_kind = _artifact_type(name)
        _need(expected_platform in {platform, "shared"}
              and (row["platform"], row["kind"]) == (expected_platform, expected_kind))
        _need(_path(row["fileName"], basename=True) and row["fileName"] not in files)
        _need(_integer(row["size"], 2**63 - 1) and _sha(row["sha256"]))
        arches = row["architectures"]
        _need(type(arches) is list and len(arches) <= 16)
        _need(all(_text(v, 64) and re.fullmatch(r"[A-Za-z0-9_.-]+", v) for v in arches))
        _need(len(set(arches)) == len(arches))
        if name == "store-metadata":
            _need(row["sha256"] == metadata_sha)
        names.add(name)
        files.add(row["fileName"])
    required = {"store-metadata", "validation-report"}
    required.update({"android-aab"} if platform == "android" else {"ios-ipa", "ios-archive"})
    _need(required <= names)


def _assignments(rows: object, platform: str) -> None:
    _need(type(rows) is list and 1 <= len(rows) <= 8)
    # Use the real Desktop asset-kind names, not environment-variable aliases.
    allowed = {"google-service-account", "operation-commitment"} if platform == "android" else {
        "asc-p8", "operation-commitment", "apple-review-contact", "apple-review-demo"}
    kinds: set[str] = set()
    records: set[str] = set()
    for row in rows:
        _keys(row, {"kind", "recordId", "expectedRevision", "contextRevision"})
        _need(_text(row["kind"], 64) and row["kind"] in allowed and row["kind"] not in kinds)
        _need(type(row["recordId"]) is str and _TOKEN.fullmatch(row["recordId"]) is not None
              and row["recordId"] not in records)
        _need(_integer(row["expectedRevision"], 2**32 - 2)
              and _integer(row["contextRevision"], 2**32 - 2))
        _need(row["contextRevision"] == rows[0]["contextRevision"])
        kinds.add(row["kind"])
        records.add(row["recordId"])
    _need(("google-service-account" if platform == "android" else "asc-p8") in kinds)


def _decode(data: bytes) -> LocalReleaseDraft:
    _need(type(data) is bytes and 0 < len(data) <= MAX_DRAFT_BYTES)
    def reject_constant(_: str) -> None:
        raise LocalDraftError(_ERROR)
    value = json.loads(data.decode("utf-8"), object_pairs_hook=_reject_duplicate_pairs,
                       parse_constant=reject_constant)
    _keys(value, _TOP)
    _need(value["documentType"] == "local-store-intent-draft"
          and type(value["schemaVersion"]) is int and value["schemaVersion"] == 1
          and value["origin"] == ORIGIN)
    _need(_uuid(value["operationId"]) and _uuid(value["projectId"]))
    platform, stage = value["platform"], value["stage"]
    _need(type(platform) is str and platform in {"android", "ios"})
    _need(type(stage) is str and stage in STAGES)
    source = _keys(value["source"], {"commit", "tree", "branch", "ref", "dirty"})
    _need(_text(source["branch"], 255) and BRANCH_RE.fullmatch(source["branch"]) is not None)
    _need(source["ref"] == "refs/heads/" + source["branch"])
    observed = GitContext(None, None, source["commit"], source["tree"], source["ref"], source["branch"], source["dirty"])
    _need(valid_observed_source(observed))
    _need(all(re.fullmatch(r"[0-9a-f]{40}", source[key]) for key in ("commit", "tree")))
    app = _keys(value["application"], {"id", "identityStatus"} | ({"storeAppId"} if platform == "ios" else set()))
    _need(app["identityStatus"] == "approved" and _text(app["id"], 255)
          and (ANDROID_ID_RE if platform == "android" else IOS_ID_RE).fullmatch(app["id"]) is not None)
    if platform == "ios":
        _need(type(app["storeAppId"]) is str and re.fullmatch(r"[1-9][0-9]{0,19}", app["storeAppId"]) is not None)
    version = _keys(value["version"], {"marketing", "build"})
    _need(_text(version["marketing"], 64) and _integer(version["build"], 2_100_000_000))
    release = release_version_from_values({"NAME": version["marketing"], "BUILD": str(version["build"])},
        name_key="NAME", build_key="BUILD", ios_enabled=platform == "ios", source_label="local draft")
    _need(value["confirmation"] == expected_confirmation(stage, platform, release))
    config = _keys(value["configuration"], {"path", "sha256", "metadataSha256"})
    version_source = _keys(value["versionSource"], {"path", "sha256"})
    _need(_path(config["path"]) and _sha(config["sha256"]) and _sha(config["metadataSha256"]))
    _need(_path(version_source["path"]) and _sha(version_source["sha256"])
          and version_source["path"] != config["path"])
    _artifacts(value["artifacts"], platform, config["metadataSha256"])
    _assignments(value["assignments"], platform)
    predecessor_keys = set() if stage == "candidate" else {
        "origin", "operationId", "candidateManifestSha256", "candidateReceiptSha256"}
    if stage == "production-submit":
        predecessor_keys.add("externalReceiptSha256")
    prior = _keys(value["predecessors"], predecessor_keys)
    if prior:
        _need(prior["origin"] == ORIGIN and _uuid(prior["operationId"])
              and prior["operationId"] != value["operationId"])
        _need(all(_sha(prior[key]) for key in predecessor_keys - {"origin", "operationId"}))
    canonical = canonical_json_bytes(value)
    _need(len(canonical) <= MAX_DRAFT_BYTES)
    return LocalReleaseDraft(value["operationId"], value["projectId"], platform, stage, observed, release, canonical)


def decode_local_draft(data: bytes) -> LocalReleaseDraft:
    """Validate bounded structural DATA only, including historical drafts.

    Success is not authentication, current consent, observed source or custody.
    """
    try:
        return _decode(data)
    except (ValidationError, ConfigurationError, ValueError, TypeError, KeyError, RecursionError):
        raise LocalDraftError(_ERROR) from None


def prepare_local_draft(data: bytes, *, observed_source: GitContext,
                        policy: LocalStorePolicy = LocalStorePolicy()) -> LocalReleaseDraft:
    """Bind a draft to caller-supplied fresh Git observations and explicit policy.

    The caller must obtain that observation from its original owned Git reader;
    neither a deserialized GitContext nor this pure builder proves provenance.
    No GitHub repository, token, workflow or environment setting is required.
    """
    _need(type(policy) is LocalStorePolicy and policy.enabled is True)
    draft = decode_local_draft(data)
    _need(type(observed_source) is GitContext and valid_observed_source(observed_source))
    expected_branch = policy.production_branch if draft.stage == "production-submit" else policy.candidate_branch
    _need(_text(expected_branch, 255) and BRANCH_RE.fullmatch(expected_branch) is not None)
    _need(draft.source.branch == expected_branch)
    _need(all(getattr(draft.source, key) == getattr(observed_source, key)
              for key in ("commit", "tree", "ref", "branch", "dirty")))
    return draft


def prepare_local_release(data: bytes, *, observed_source: GitContext,
                          configuration_bytes: bytes, version_bytes: bytes) -> LocalReleaseDraft:
    """Bind draft DATA to the original caller's captured saved input bytes.

    Unlike structural decoding, this cannot select a different application,
    version file, version or branch from the supplied saved configuration. The
    caller must capture release/mobile-release.json and its configured version
    file using the existing owned readers, and retain/recheck those originals.
    Supplying bytes here does not authenticate their source or grant execution.
    Artifact/metadata custody, credentials, consent and journal admission remain
    separate obligations. No file is read, resolved, created or mutated here.
    """
    try:
        _need(type(configuration_bytes) is bytes and 0 < len(configuration_bytes) <= MAX_CONFIG_BYTES)
        _need(type(version_bytes) is bytes and 0 < len(version_bytes) <= MAX_VERSION_BYTES)
        config = ReleaseConfig(Path("release/mobile-release.json"), Path("."),
                               parse_config_text(configuration_bytes.decode("utf-8")))
        draft = prepare_local_draft(data, observed_source=observed_source,
                                    policy=LocalStorePolicy.from_config(config))
        value = draft.to_dict()
        _need(value["configuration"]["path"] == "release/mobile-release.json")
        _need(value["configuration"]["sha256"] == hashlib.sha256(configuration_bytes).hexdigest())
        spec = config.section("version")
        _need(value["versionSource"]["path"] == spec["source"])
        _need(value["versionSource"]["sha256"] == hashlib.sha256(version_bytes).hexdigest())
        release = release_version_from_values(parse_key_value_text(version_bytes.decode("utf-8")),
            name_key=spec["nameKey"], build_key=spec["buildKey"],
            ios_enabled=config.platform_enabled("ios"), source_label="local release version")
        _need(draft.release == release)
        platform = config.section(draft.platform)
        _need(platform.get("enabled") is True and platform.get("identityStatus") == "approved")
        _need(value["application"]["id"] == platform.get(
            "applicationId" if draft.platform == "android" else "bundleId"))
        if draft.platform == "ios":
            _need(value["application"]["storeAppId"] == platform.get("appStoreAppId"))
        return draft
    except (ValidationError, ConfigurationError, ValueError, TypeError, KeyError, RecursionError):
        raise LocalDraftError(_ERROR) from None
