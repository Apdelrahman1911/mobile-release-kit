"""Local Store draft and closed intent DATA, never execution permission.

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


def prepare_owned_local_release(data: bytes, *, source) -> LocalReleaseDraft:
    """Prepare candidate DATA using the live observed project, not Git hints.

    This performs no Store operation and mints no durable intent/authorization.
    The source's original scope must remain live through any subsequent build;
    its exit and the separate producer closes still gate publication. Existing
    callers of prepare_local_release retain the unchanged DATA-only contract.
    """
    from .local_release_source import LocalSourceObservation

    _need(type(source) is LocalSourceObservation)
    observed = source.check()
    draft = prepare_local_release(data, observed_source=observed,
        configuration_bytes=source.configuration_bytes, version_bytes=source.version_bytes)
    _need(draft.platform == "android" and draft.stage == "candidate")
    source._unchanged()  # Pure draft parsing performed no external work.
    return draft


# These explicit DATA readers are not used by CI or an execution owner. A seal
# proves bytes only; journal authentication, original custody and native consent
# must independently precede any future Store effect.
MAX_LOCAL_INTENT_BYTES = 2 * 1024 * 1024
MAX_LOCAL_AUTHORITY_BYTES = 8 * 1024
_LOCAL_BODY = {"tooling", "candidateSource", "operationSource", "confirmation", "application",
    "version", "destination", "configuration", "artifacts", "signing", "predecessors",
    "storePrecondition", "privateStateCommitments", "createdAt"}
_LOCAL_INTENT = _LOCAL_BODY | {"documentType", "schemaVersion", "origin", "platform", "stage",
    "project", "operationId", "candidateSha256", "preparedBy"}
_LOCAL_AUTHORITY = {"schemaVersion", "origin", "purpose", "project", "operationId",
    "candidateSha256", "authorizationId", "source", "assignment", "confirmationSha256", "intentSha256"}
_LOCAL_FILES = (("android-aab", "app-release.aab", 1024**3),
    ("store-metadata", "store-metadata.zip", 512 * 1024**2),
    ("validation-report", "validation-report.json", 64 * 1024))


class LocalIntentError(ValidationError):
    def __init__(self):
        super().__init__("Invalid local Store intent or authority DATA")


def _local_json(data: bytes, maximum: int) -> dict:
    _need(type(data) is bytes and 0 < len(data) <= maximum)
    value = json.loads(data.decode("utf-8"), object_pairs_hook=_reject_duplicate_pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(LocalIntentError()))
    _need(type(value) is dict)
    # Existing bounded-depth/type/private-material/canonical UTF-8 policy.
    canonical_json_bytes(value)
    return value


def _local_project(value: object) -> None:
    from .local_release_journal import _enrollment
    _enrollment(value)  # Exact same enrolled project/key identity; no key IO.


def _local_source(value: object) -> None:
    _keys(value, {"commit", "tree", "ref"})
    _need(all(type(value[k]) is str and re.fullmatch(r"[0-9a-f]{40}", value[k]) for k in ("commit", "tree")))
    ref = value["ref"]
    _need(_text(ref, 266) and ref.startswith("refs/heads/") and BRANCH_RE.fullmatch(ref[11:]) is not None)


def _local_authority(value: object, *, purpose: str, platform: str = "android", stage: str = "candidate") -> dict:
    _need(type(stage) is str and stage in STAGES and (stage == "candidate" or purpose in {"prepare", "execute"}))
    later_apple = stage != "candidate" and platform == "ios"
    _keys(value, _LOCAL_AUTHORITY | ({"supplementalAssignments"} if later_apple else set()))
    _need(type(purpose) is str and purpose in {"prepare", "execute", "recover"}
        and type(value["schemaVersion"]) is int and value["schemaVersion"] == 1
        and value["origin"] == ORIGIN and value["purpose"] == purpose)
    _local_project(value["project"])
    _local_source(value["source"])
    _need(_uuid(value["operationId"]) and _uuid(value["authorizationId"])
        and _sha(value["candidateSha256"]) and _sha(value["confirmationSha256"]))
    assignment = _keys(value["assignment"], {"kind", "recordId", "expectedRevision", "contextRevision"})
    _need(type(platform) is str and platform in {"android", "ios"}
        and (platform != "ios" or purpose in {"prepare", "execute", "recover"})
        and assignment["kind"] == ("google-service-account" if platform == "android" else "asc-p8"))
    _assignments([assignment], platform)
    if later_apple:
        extra = value["supplementalAssignments"]
        _need(type(extra) is list and len(extra) in (2, 3)
              and [row.get("kind") for row in extra if type(row) is dict] ==
              ["apple-review-contact", "operation-commitment"] + (["apple-review-demo"] if len(extra) == 3 else []))
        _assignments([assignment, *extra], platform)
    _need(value["intentSha256"] is None if purpose == "prepare" else _sha(value["intentSha256"]))
    return value


def decode_local_authority(data: bytes, *, purpose: str, platform: str = "android", stage: str = "candidate") -> dict:
    """Decode a fixed-purpose identity record, NEVER a native authorization grant."""
    try:
        return _local_authority(_local_json(data, MAX_LOCAL_AUTHORITY_BYTES), purpose=purpose, platform=platform, stage=stage)
    except (ValidationError, ValueError, TypeError, KeyError, AttributeError, RecursionError):
        raise LocalIntentError() from None


def decode_local_operation_intent(data: bytes, *, platform: str = "android", stage: str = "candidate") -> dict:
    """Return checked sealed local DATA. No IO, authentication or release consent."""
    from .provenance import verify_sealed, _validate_operation_intent_body
    try:
        document = _local_json(data, MAX_LOCAL_INTENT_BYTES)
        _need(type(stage) is str and stage in STAGES)
        intent = _keys(verify_sealed(document), _LOCAL_INTENT | ({"candidateOperationId"} if stage != "candidate" else set()))
        _need(intent["documentType"] == "local-store-operation-intent"
            and type(intent["schemaVersion"]) is int and intent["schemaVersion"] == 1
            and intent["origin"] == ORIGIN and intent["stage"] == stage
            and type(platform) is str and platform in {"android", "ios"} and intent["platform"] == platform)
        _local_project(intent["project"])
        _need(_uuid(intent["operationId"]) and _sha(intent["candidateSha256"]))
        for name in ("candidateSource", "operationSource"):
            _local_source(intent[name])
        if stage != "production-submit":
            _need(intent["candidateSource"] == intent["operationSource"])
        if stage != "candidate":
            _need(_uuid(intent["candidateOperationId"]) and intent["candidateOperationId"] != intent["operationId"]
                  and intent["predecessors"].get("candidateManifestSha256") == intent["candidateSha256"])
        tooling = _keys(intent["tooling"], {"version", "commit"})
        _need(type(tooling["version"]) is str and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?", tooling["version"])
            and type(tooling["commit"]) is str and re.fullmatch(r"[0-9a-f]{40}", tooling["commit"]))
        # The exact original shared platform/Store body, never a fake CI envelope.
        _validate_operation_intent_body(intent, stage=stage, platform=platform,
            artifact_encoding="files" if platform == "android" else (
                "local-ios-directory" if stage == "candidate" else "local-ios-stage-directory"))
        _need((ANDROID_ID_RE if platform == "android" else IOS_ID_RE).fullmatch(intent["application"]["id"]) is not None)
        files = _LOCAL_FILES
        if platform == "ios":
            app = intent["application"]["storeAppId"]
            _need(type(app) is str and re.fullmatch(r"[1-9][0-9]{0,19}", app) is not None
                and (stage != "candidate" or intent["storePrecondition"]["snapshot"]["build"] is None))
            _need(len(intent["artifacts"]) == 4)
            ipa = intent["artifacts"][0]["fileName"]
            _need(_path(ipa, basename=True) and len(ipa.encode("utf-8")) <= 255 and ipa.endswith(".ipa"))
            files = (("ios-ipa", ipa, 4 << 30), *_LOCAL_FILES[1:])
            archive = intent["artifacts"][-1]
            from .provenance import _validate_local_ios_archive_artifact
            _validate_local_ios_archive_artifact(archive)
        else:
            _need(len(intent["artifacts"]) == len(files))
        for row, (logical, filename, maximum) in zip(intent["artifacts"], files):
            _need(row["logicalName"] == logical and row["fileName"] == filename
                and _integer(row["size"], maximum))
        prepared = _local_authority(intent["preparedBy"], purpose="prepare", platform=platform, stage=stage)
        _need(all(prepared[k] == intent[k] for k in ("project", "operationId", "candidateSha256"))
            and prepared["source"] == intent["operationSource"]
            and prepared["confirmationSha256"] == hashlib.sha256(intent["confirmation"].encode("utf-8")).hexdigest())
        return document
    except (ValidationError, ValueError, TypeError, KeyError, AttributeError, RecursionError):
        raise LocalIntentError() from None


def validate_local_execution_authority(data: bytes, *, intent_data: bytes, purpose: str,
                                       platform: str = "android", stage: str = "candidate") -> dict:
    """Compare local DATA with exact intent bytes; not one-use/dispatch permission.

    Fresh native consent, credential originals and journal/checkpoint custody are
    missing by design here. A different authorization ID proves no prior call.
    """
    try:
        _need(type(purpose) is str and purpose in {"execute", "recover"})
        intent = decode_local_operation_intent(intent_data, platform=platform, stage=stage)
        value = decode_local_authority(data, purpose=purpose, platform=platform, stage=stage)
        prepared = intent["preparedBy"]
        _need(value["intentSha256"] == intent["integrity"]["sha256"]
            and value["authorizationId"] != prepared["authorizationId"]
            and all(value[k] == prepared[k] for k in ("project", "operationId", "candidateSha256",
                "source", "assignment", "confirmationSha256"))
            and value.get("supplementalAssignments") == prepared.get("supplementalAssignments"))
        return value
    except (ValidationError, ValueError, TypeError, KeyError, AttributeError, RecursionError):
        raise LocalIntentError() from None
