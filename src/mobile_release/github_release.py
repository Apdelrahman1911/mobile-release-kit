"""Closed Desktop requests for the three existing protected release workflows.

This is request/observation policy, not a Store engine or evidence verifier.
The original native GitHub session owns credentials, consent, deadline and GO.
The existing protected workflows own Resolver, provenance and Store mutations.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import github_preflight as preflight
from ._desktop_github_engine import _check_control, _check_values
from ._github_connection_transport import ReadFailure, ReadResult, _control
from .api._github_connection import _account, _coordinate, _id, _read, _utc
from .api._github_setup import _resource
from .api._json import bounded_json_text
from .config import (MAX_CONFIG_BYTES, MAX_VERSION_BYTES, ReleaseConfig, ReleaseVersion,
                     parse_config_text, parse_key_value_text, release_version_from_values)
from .credential_requirements import ENVIRONMENT_NAMES, requirements
from .errors import ConfigurationError, ValidationError
from .release_confirmation import expected_confirmation
from .version_text import VersionTextInputError, public_version_selection
from .workflow_payloads import render_workflow_caller

PROTOCOL = "mrk-github-release/1"
API_VERSION = preflight.API_VERSION
TOOLING_REPOSITORY = preflight.TOOLING_REPOSITORY
CONFIG_PATH = "release/mobile-release.json"
MAX_CALLER_BYTES = preflight.MAX_CALLER_BYTES
MAX_REQUESTS = 10
MAX_TREE_ENTRIES = 1000
MAX_REQUEST_BODY = preflight.MAX_REQUEST_BODY
MAX_PREPARED_BYTES = 3900  # Full64 status + review/run/envelopes fit unchanged256KiB; native checks before admission.
MAX_RUN_BYTES = 4096
MAX_RECOVERY_CONFIRMATION_BYTES = 342
ASSURANCE = "github-workflow-observation-not-release-evidence"
ORIGINAL_ASSURANCE = "declared-original-references-not-authenticated-release-evidence"
REASONS = preflight.REASONS | {"config-invalid", "version-invalid", "platform-disabled", "branch-mismatch", "source-tree-unavailable"}
_STAGES = ("candidate", "external-testing", "production-submit")
_WORKFLOW_NAMES = {"candidate": "Mobile internal candidate", "external-testing": "Mobile external testing",
                   "production-submit": "Mobile production submission"}
_JOB_SUFFIXES = {"validate-platform": "input-guard", "android_resolve": "android-resolve",
                 "android_online": "android-online", "android_build": "android-build", "android_store": "android-store",
                 "ios_resolve": "ios-resolve", "ios_online": "ios-online", "ios_build": "ios-build", "ios_store": "ios-store",
                 "android": "android", "ios": "ios"}
_DIGEST, _SHA, _MARKER = preflight._DIGEST, preflight._SHA, preflight._MARKER
_object, _match, _upstream_id = preflight._object, preflight._match, preflight._upstream_id
_require = preflight._require


def _plain(value: object, maximum: int) -> str:
    _require(type(value) is str and 0 < len(value.encode("utf-8")) <= maximum
             and all(ord(c) >= 32 and ord(c) != 127 for c in value))
    return value  # type: ignore[return-value]


def _version(value: object, *, ios: bool) -> ReleaseVersion:
    row = _object(value, {"name", "build"})
    _require(type(row["name"]) is str and len(row["name"]) <= 64
             and type(row["build"]) is int and 1 <= row["build"] <= 2_100_000_000)
    return release_version_from_values({"name": row["name"], "build": str(row["build"])},
        name_key="name", build_key="build", ios_enabled=ios, source_label="declared release")


def _version_value(value: ReleaseVersion) -> dict[str, Any]:
    return {"name": value.name, "build": value.build}


def _quote_path(value: str) -> str:
    # Per-component UTF-8 encoding; slash is a path separator, never renderer
    # URL authority or a query delimiter. Selection is admitted by core first.
    safe = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
    return "/".join("".join(chr(b) if b in safe else "%" + format(b, "02X")
                            for b in part.encode("utf-8")) for part in value.split("/"))


def _recovery_confirmation(value: object, *, stage: str) -> str:
    # Format admission only. Original intent/artifact/inventory authority stays in core.
    _require(type(value) is str and 0 < len(value) <= MAX_RECOVERY_CONFIRMATION_BYTES and value.isascii())
    parts = value.split(":")
    _require(len(parts) == 3)
    prefix, intent, detail = parts
    _match(intent, _DIGEST)
    if stage == "candidate" and prefix == "recover-ios-candidate":
        # Explicit Desktop build-ID profile, not a bound inferred from normalized_ios_build.
        _require(re.fullmatch(r"[A-Za-z0-9_.-]{1,255}", detail, re.ASCII) is not None)
    else:
        _require(stage == "candidate" and prefix == "retry-ios-candidate-upload"
                 or stage in ("external-testing", "production-submit") and prefix == "retry-ios-operation-creates")
        _match(detail, _DIGEST)
    return value  # type: ignore[return-value]


@dataclass(frozen=True, slots=True)
class Selection:
    stage: str
    candidate_run_id: str | None
    external_run_id: str | None
    recovery_run_id: str | None
    original_source_sha: str | None
    original_version: ReleaseVersion | None
    recovery_confirmation: str | None = None

    @classmethod
    def parse(cls, value: object, *, ios: bool) -> Selection:
        extra = {"recoveryConfirmation"} if type(value) is dict and "recoveryConfirmation" in value else set()
        row = _object(value, {"stage", "candidateRunId", "externalRunId", "recoveryRunId",
                              "originalSourceSha", "originalVersion"} | extra)
        _require(type(row["stage"]) is str and row["stage"] in _STAGES)
        ids = [None if row[key] is None else _id(row[key]) for key in
               ("candidateRunId", "externalRunId", "recoveryRunId")]
        source = None if row["originalSourceSha"] is None else _match(row["originalSourceSha"], _SHA)
        version = None if row["originalVersion"] is None else _version(row["originalVersion"], ios=ios)
        stage = row["stage"]
        needs_original = stage != "candidate" or ids[2] is not None
        _require(needs_original == (source is not None) and needs_original == (version is not None))
        _require(stage != "candidate" or ids[0] is None and ids[1] is None)
        _require(stage == "production-submit" or ids[1] is None)
        _require(stage == "candidate" or ids[2] is not None or ids[0] is not None)
        _require(stage != "production-submit" or ids[2] is not None or ids[1] is not None)
        recovery = None
        if extra:
            _require(ios and ids[2] is not None)
            recovery = _recovery_confirmation(row["recoveryConfirmation"], stage=stage)
        return cls(stage, *ids, source, version, recovery)

    def value(self) -> dict[str, Any]:
        row = {"stage": self.stage, "candidateRunId": self.candidate_run_id, "externalRunId": self.external_run_id,
               "recoveryRunId": self.recovery_run_id, "originalSourceSha": self.original_source_sha,
               "originalVersion": None if self.original_version is None else _version_value(self.original_version)}
        if self.recovery_confirmation is not None:
            row["recoveryConfirmation"] = self.recovery_confirmation
        return row


@dataclass(frozen=True, slots=True)
class Target:
    project_binding: str
    repository: str
    account_id: str
    repository_id: str
    branch: str
    tooling_sha: str
    platform: str
    marker: str
    selection: Selection

    @classmethod
    def parse(cls, value: object) -> Target:
        row = _object(value, {"projectBinding", "repository", "accountId", "repositoryId", "branch",
                              "toolingRepository", "toolingSha", "platform", "marker", "selection"})
        _require(row["toolingRepository"] == TOOLING_REPOSITORY and row["platform"] in ("android", "ios"))
        return cls(_match(row["projectBinding"], _DIGEST), _coordinate(row["repository"]),
                   _id(row["accountId"]), _id(row["repositoryId"]), preflight.branch(row["branch"]),
                   _match(row["toolingSha"], _SHA), row["platform"], _match(row["marker"], _MARKER),
                   Selection.parse(row["selection"], ios=row["platform"] == "ios"))

    def value(self) -> dict[str, Any]:
        return {"projectBinding": self.project_binding, "repository": self.repository, "accountId": self.account_id,
                "repositoryId": self.repository_id, "branch": self.branch, "toolingRepository": TOOLING_REPOSITORY,
                "toolingSha": self.tooling_sha, "platform": self.platform, "marker": self.marker,
                "selection": self.selection.value()}

    @property
    def workflow_path(self) -> str:
        return ".github/workflows/mobile-" + self.selection.stage + ".yml"

    @property
    def workflow_name(self) -> str:
        return _WORKFLOW_NAMES[self.selection.stage]

    @property
    def display_title(self) -> str:
        return "MRK Desktop " + self.selection.stage + " [" + self.marker + "]"


def canonical_caller(target: Target) -> bytes:
    _, resource = _resource()
    return render_workflow_caller(resource["workflows"][target.selection.stage].encode("utf-8"),
                                  TOOLING_REPOSITORY, target.tooling_sha)


def _destination(value: object, target: Target) -> dict[str, str]:
    row = _object(value, {"applicationId", "destination", "assurance"})
    _plain(row["applicationId"], 255)
    _plain(row["destination"], 256)
    _require(row["assurance"] == "current-dispatch-config-not-authenticated-original-destination")
    return row


def _checklist(value: object) -> list[dict[str, str]]:
    _require(type(value) is list and len(value) <= 16)
    seen = set()
    for row in value:
        _object(row, {"name", "kind", "reason"})
        _require(type(row["name"]) is str and re.fullmatch(r"MOBILE_RELEASE_[A-Z0-9_]{1,96}", row["name"]) is not None
                 and row["name"] not in seen and row["kind"] in ("secret", "variable", "file", "manual"))
        seen.add(row["name"])
        _plain(row["reason"], 192)
    return value  # type: ignore[return-value]


@dataclass(frozen=True, slots=True)
class Prepared:
    target: Target
    source_sha: str
    source_tree: str
    workflow_id: str
    caller_sha256: str
    observed_at: str
    config_sha256: str
    version_source: str
    version_sha256: str
    current_version: ReleaseVersion
    destination: dict[str, str]
    checklist: list[dict[str, str]]

    @property
    def confirmation(self) -> str:
        return expected_confirmation(self.target.selection.stage, self.target.platform,
                                     self.target.selection.original_version or self.current_version)

    @classmethod
    def parse(cls, value: object) -> Prepared:
        row = _object(value, {"target", "sourceSha", "sourceTree", "workflowId", "workflowPath", "callerSha256", "observedAt",
                              "expectedRef", "displayTitle", "configSha256", "versionSource", "versionSha256",
                              "currentVersion", "destination", "checklist", "environment", "confirmation", "originalAssurance"})
        target = Target.parse(row["target"])
        version_source = _plain(row["versionSource"], 512)
        # This is a retained path description, not a new file authority. Prepare
        # selects it through public_version_selection before any Contents GET.
        from .api._release_version import _source_path
        _require(_source_path(version_source) and len(version_source.split("/")) <= 12)
        prepared = cls(target, _match(row["sourceSha"], _SHA), _match(row["sourceTree"], _SHA), _id(row["workflowId"]),
                       _match(row["callerSha256"], _DIGEST), _utc(row["observedAt"]),
                       _match(row["configSha256"], _DIGEST), version_source, _match(row["versionSha256"], _DIGEST),
                       _version(row["currentVersion"], ios=target.platform == "ios"),
                       _destination(row["destination"], target), _checklist(row["checklist"]))
        _require(row == prepared.value() and len(_canonical(row)) <= MAX_PREPARED_BYTES)
        _require(hashlib.sha256(canonical_caller(target)).hexdigest() == prepared.caller_sha256)
        return prepared

    def value(self) -> dict[str, Any]:
        stage = "production" if self.target.selection.stage == "production-submit" else self.target.selection.stage
        return {"target": self.target.value(), "sourceSha": self.source_sha, "sourceTree": self.source_tree, "workflowId": self.workflow_id,
                "workflowPath": self.target.workflow_path, "callerSha256": self.caller_sha256,
                "observedAt": self.observed_at, "expectedRef": "refs/heads/" + self.target.branch,
                "displayTitle": self.target.display_title, "configSha256": self.config_sha256,
                "versionSource": self.version_source, "versionSha256": self.version_sha256,
                "currentVersion": _version_value(self.current_version), "destination": self.destination,
                "checklist": self.checklist, "environment": ENVIRONMENT_NAMES[stage],
                "confirmation": self.confirmation, "originalAssurance": ORIGINAL_ASSURANCE}


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True, allow_nan=False).encode("utf-8")


@dataclass(frozen=True, slots=True, repr=False)
class Action:
    kind: str
    target: Target
    prepared: Prepared | None = None
    run_id: str | None = None

    @classmethod
    def parse(cls, value: object) -> Action:
        row = _object(value, {"kind", "target", "prepared", "runId"})
        _require(type(row["kind"]) is str and row["kind"] in {"prepare", "dispatch", "track", "reconcile"})
        target = Target.parse(row["target"])
        prepared = None if row["prepared"] is None else Prepared.parse(row["prepared"])
        run_id = None if row["runId"] is None else _id(row["runId"])
        _require((row["kind"] == "prepare") == (prepared is None) and (prepared is None or prepared.target == target)
                 and (row["kind"] == "track") == (run_id is not None))
        return cls(row["kind"], target, prepared, run_id)

    def value(self) -> dict[str, Any]:
        return {"kind": self.kind, "target": self.target.value(),
                "prepared": None if self.prepared is None else self.prepared.value(), "runId": self.run_id}


def dispatch_body(prepared: Prepared) -> bytes:
    target, selected = prepared.target, prepared.target.selection
    inputs = {"platform": target.platform, "confirmation": prepared.confirmation,
              "recovery_run_id": selected.recovery_run_id or "",
              "recovery_confirmation": selected.recovery_confirmation if selected.recovery_confirmation is not None else "",
              "desktop_request": target.marker, "desktop_source_sha": prepared.source_sha,
              "desktop_expected_ref": "refs/heads/" + target.branch}
    if selected.stage != "candidate":
        inputs["candidate_run_id"] = selected.candidate_run_id or ""
    if selected.stage == "production-submit":
        inputs["external_run_id"] = selected.external_run_id or ""
    # Original source is declarative review DATA, not a replacement for the
    # resolver's authenticated evidence source. No invented workflow input.
    raw = _canonical({"ref": target.branch, "return_run_details": True, "inputs": inputs})
    _require(len(raw) <= MAX_REQUEST_BODY)
    return raw


class Schedule:
    """A closed, one-use request sequence. Claimed requests are never retried."""
    def __init__(self, action: Action) -> None:
        self.action = action
        self.steps: list[str] = []
        self.run_id = action.run_id
        self.source_sha: str | None = None

    def claim(self, step: str, reference: str | None = None) -> preflight.HttpRequest:
        schedules = {
            "prepare": ("account", "repository-before", "branch-before", "workflow", "caller", "config", "source-tree", "version", "branch-after", "repository-after"),
            "dispatch": ("account", "repository-before", "branch-before", "workflow", "dispatch"),
            "track": ("account", "repository-before", "attempt", "jobs", "repository-after"),
            "reconcile": ("account", "repository-before", "runs", "attempt", "jobs", "repository-after"),
        }
        schedule = schedules[self.action.kind]
        _require(len(self.steps) < len(schedule) <= MAX_REQUESTS and step == schedule[len(self.steps)])
        self.steps.append(step)
        target, prepared = self.action.target, self.action.prepared
        prefix = "/repos/" + target.repository
        if step == "account":
            path = "/user"
        elif step in {"repository-before", "repository-after"}:
            path = prefix
        elif step in {"branch-before", "branch-after"}:
            path = prefix + "/branches/" + preflight._quote(target.branch)
        elif step == "workflow":
            path = prefix + "/actions/workflows/mobile-" + target.selection.stage + ".yml"
        elif step == "caller":
            self.source_sha = _match(reference, _SHA)
            path = prefix + "/contents/" + target.workflow_path + "?ref=" + self.source_sha
        elif step == "config":
            _require(self.source_sha is not None and reference is None)
            path = prefix + "/contents/" + CONFIG_PATH + "?ref=" + self.source_sha
        elif step == "source-tree":
            _require(self.source_sha is not None)
            path = prefix + "/git/trees/" + _match(reference, _SHA) + "?recursive=1"
        elif step == "version":
            _require(self.source_sha is not None and type(reference) is str)
            from .api._release_version import _source_path
            _require(_source_path(reference) and len(reference.encode("utf-8")) <= 512 and len(reference.split("/")) <= 12)
            path = prefix + "/contents/" + _quote_path(reference) + "?ref=" + self.source_sha
        elif step == "dispatch":
            _require(prepared is not None and reference is None)
            return preflight.HttpRequest("POST", prefix + "/actions/workflows/" + prepared.workflow_id + "/dispatches", dispatch_body(prepared))
        elif step == "runs":
            _require(prepared is not None)
            path = (prefix + "/actions/workflows/" + prepared.workflow_id + "/runs?event=workflow_dispatch&branch="
                    + preflight._quote(target.branch) + "&head_sha=" + prepared.source_sha + "&per_page=100&page=1")
        elif step in {"attempt", "jobs"}:
            if step == "attempt" and self.action.kind == "reconcile":
                self.run_id = _id(reference)
            _require(self.run_id is not None)
            path = prefix + "/actions/runs/" + self.run_id + "/attempts/1"
            if step == "jobs":
                path += "/jobs?per_page=100&page=1"
        else:
            raise ValueError("Invalid fixed release request step")
        _require(reference is None or step in {"caller", "source-tree", "version"} or step == "attempt" and self.action.kind == "reconcile")
        return preflight.HttpRequest("GET", path, None)


class Refused(ValueError):
    def __init__(self, reason: str) -> None:
        _require(reason in REASONS and reason != "none")
        self.reason = reason
        super().__init__("The fixed GitHub release request was refused")


def _same(condition: bool, reason: str) -> None:
    if not condition:
        raise Refused(reason)


def _workflow(body: dict[str, Any], target: Target) -> str:
    _same(body.get("path") == target.workflow_path and body.get("name") == target.workflow_name
          and body.get("state") == "active", "workflow-unavailable")
    return _upstream_id(body.get("id"))


def _source(body: dict[str, Any], target: Target) -> tuple[str, str]:
    # Unlike git/ref, the documented branch endpoint exposes the commit's
    # actual root-tree identity. Never address a tree API with a commit SHA.
    _same(body.get("name") == target.branch, "source-changed")
    commit = body.get("commit")
    _require(type(commit) is dict and type(commit.get("commit")) is dict)
    source = _match(commit.get("sha"), _SHA)
    tree = commit["commit"].get("tree")
    _require(type(tree) is dict)
    tree_sha = _match(tree.get("sha"), _SHA)
    _same(tree.get("url") == "https://api.github.com/repos/" + target.repository + "/git/trees/" + tree_sha, "source-changed")
    return source, tree_sha


def _source_tree(body: dict[str, Any], target: Target, tree_sha: str,
                 selected: tuple[str, str, str]) -> dict[str, dict[str, Any]]:
    """Mode proof over a complete finite immutable tree, not Contents labels."""
    _same(body.get("sha") == tree_sha and body.get("truncated") is False
          and body.get("url") == "https://api.github.com/repos/" + target.repository + "/git/trees/" + tree_sha,
          "source-tree-unavailable")
    rows = body.get("tree")
    _same(type(rows) is list and 0 < len(rows) <= MAX_TREE_ENTRIES, "source-tree-unavailable")
    entries: dict[str, dict[str, Any]] = {}
    mode_types = {"040000": "tree", "100644": "blob", "100755": "blob", "120000": "blob", "160000": "commit"}
    for row in rows:
        _same(type(row) is dict and {"path", "mode", "type", "sha"} <= set(row)
              and set(row) <= {"path", "mode", "type", "sha", "url", "size"}, "source-tree-unavailable")
        path = _plain(row["path"], 4096)
        parts = path.split("/")
        _same(len(parts) <= 128 and all(part not in ("", ".", "..") for part in parts)
              and "\\" not in path and path not in entries, "source-tree-unavailable")
        mode, kind = row["mode"], row["type"]
        _same(type(mode) is str and mode in mode_types and kind == mode_types[mode], "source-tree-unavailable")
        sha = _match(row["sha"], _SHA)
        endpoint = {"tree": "trees", "blob": "blobs", "commit": "commits"}[kind]
        # A submodule's commit can belong to another repository and need not
        # have a URL. It is never traversed and cannot be a selected ancestor.
        _same(row.get("url") == "https://api.github.com/repos/" + target.repository + "/git/" + endpoint + "/" + sha
              or kind == "commit" and row.get("url") is None,
              "source-tree-unavailable")
        _same((kind == "blob" and type(row.get("size")) is int and 0 <= row["size"] < 1 << 63)
              or kind != "blob" and "size" not in row, "source-tree-unavailable")
        entries[path] = row
    for path in selected:
        row = entries.get(path)
        _same(row is not None and row["mode"] in ("100644", "100755") and row["type"] == "blob", "source-tree-unavailable")
        parts = path.split("/")
        for n in range(1, len(parts)):
            parent = entries.get("/".join(parts[:n]))
            _same(parent is not None and parent["mode"] == "040000" and parent["type"] == "tree", "source-tree-unavailable")
    return {path: entries[path] for path in selected}


def _match_blob(row: dict[str, Any], raw: bytes) -> None:
    blob = hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw, usedforsecurity=False).hexdigest()
    _same(row["sha"] == blob and row["size"] == len(raw), "source-tree-unavailable")


def _contents(body: dict[str, Any], path: str, maximum: int, reason: str) -> bytes:
    _same(body.get("type") == "file" and body.get("path") == path and body.get("encoding") == "base64"
          and "target" not in body and "submodule_git_url" not in body and body.get("truncated", False) is False, reason)
    size, text = body.get("size"), body.get("content")
    encoded = 4 * ((maximum + 2) // 3)
    _same(type(size) is int and 0 < size <= maximum and type(text) is str
          and len(text) <= encoded + encoded // 60 + 2, reason)
    _same(re.fullmatch(r"[A-Za-z0-9+/=\n]*", text, re.ASCII) is not None, reason)
    compact = text.replace("\n", "")
    _same(len(compact) <= 4 * ((size + 2) // 3), reason)
    try:
        raw = base64.b64decode(compact, validate=True)
    except ValueError:
        raise Refused(reason) from None
    _same(len(raw) == size, reason)
    blob = hashlib.sha1(b"blob " + str(size).encode("ascii") + b"\0" + raw, usedforsecurity=False).hexdigest()
    _same(body.get("sha") == blob, reason)  # Consistency, never attestation.
    return raw


def _configuration(raw: bytes, target: Target) -> tuple[ReleaseConfig, Any]:
    try:
        text = raw.decode("utf-8")
        selection = public_version_selection(text)
        data = parse_config_text(text)
    except (ConfigurationError, ValidationError, VersionTextInputError, ValueError, UnicodeError, RecursionError):
        raise Refused("config-invalid") from None
    config = ReleaseConfig(Path(CONFIG_PATH), Path("."), data)  # DATA construction only; no path resolution/read.
    _same(config.platform_enabled(target.platform), "platform-disabled")
    key = "productionBranch" if target.selection.stage == "production-submit" else "candidateBranch"
    _same(config.section("source").get(key) == target.branch, "branch-mismatch")
    return config, selection


def _prepared(target: Target, source: str, source_tree: str, workflow: str, caller: bytes, config_raw: bytes,
              config: ReleaseConfig, selection: Any, version_raw: bytes, observed_at: str) -> Prepared:
    try:
        from .api._release_version import _sensitive
        text = version_raw.decode("utf-8")
        _same(not _sensitive(text), "version-invalid")
        version = release_version_from_values(parse_key_value_text(text), name_key=selection.name_key,
            build_key=selection.build_key, ios_enabled=selection.ios_enabled, source_label="committed version")
    except (ConfigurationError, ValueError, UnicodeError, RecursionError):
        raise Refused("version-invalid") from None
    stage = "production" if target.selection.stage == "production-submit" else target.selection.stage
    section = config.section(target.platform)
    if target.platform == "android":
        destination = ("internal" if stage == "candidate" else "production draft (not served)" if stage == "production"
                       else str(section["externalTrack"]["name"]))
        app_id = section["applicationId"]
    else:
        destination = ("TestFlight internal" if stage == "candidate" else "App Review; manual release" if stage == "production"
                       else str(section["externalTestFlightGroup"]))
        app_id = section["bundleId"]
    result = Prepared(target, source, source_tree, workflow, hashlib.sha256(caller).hexdigest(), observed_at,
        hashlib.sha256(config_raw).hexdigest(), selection.source, hashlib.sha256(version_raw).hexdigest(), version,
        {"applicationId": app_id, "destination": destination, "assurance": "current-dispatch-config-not-authenticated-original-destination"},
        [{"name": row.name, "kind": row.kind, "reason": row.reason}
         for row in requirements(config, stage=stage, platforms=(target.platform,))])
    return Prepared.parse(result.value())


def _run_identity(body: dict[str, Any], prepared: Prepared, run_id: str | None = None) -> str:
    target = prepared.target
    actual = _upstream_id(body.get("id"))
    _same(run_id is None or actual == run_id, "run-changed")
    for key in ("repository", "head_repository"):
        row = body.get(key)
        _same(type(row) is dict and _upstream_id(row.get("id")) == target.repository_id
              and row.get("full_name") == target.repository, "run-changed")
    for key in ("actor", "triggering_actor"):
        row = body.get(key)
        _same(type(row) is dict and _upstream_id(row.get("id")) == target.account_id, "run-changed")
    _same(type(body.get("run_attempt")) is int and body["run_attempt"] == 1
          and _upstream_id(body.get("workflow_id")) == prepared.workflow_id
          and body.get("path") == target.workflow_path and body.get("name") == target.workflow_name
          and body.get("head_sha") == prepared.source_sha and body.get("head_branch") == target.branch
          and body.get("event") == "workflow_dispatch" and body.get("display_title") == target.display_title
          and body.get("html_url") == "https://github.com/" + target.repository + "/actions/runs/" + actual, "run-changed")
    return actual


def reconcile_run(body: dict[str, Any], prepared: Prepared) -> str:
    count, rows = body.get("total_count"), body.get("workflow_runs")
    _same(type(count) is int and 0 <= count <= preflight.MAX_RUNS and type(rows) is list and len(rows) == count, "unresolved-run")
    seen, matches = set(), []
    for row in rows:
        _require(type(row) is dict)
        identity = _upstream_id(row.get("id"))
        _same(identity not in seen, "ambiguous-run")
        seen.add(identity)
        if row.get("display_title") == prepared.target.display_title:
            matches.append(_run_identity(row, prepared))
    _same(bool(matches), "unresolved-run")
    _same(len(matches) == 1, "ambiguous-run")
    return matches[0]


def observed_run(body: dict[str, Any], jobs: dict[str, Any], prepared: Prepared, run_id: str, observed_at: str) -> dict[str, Any]:
    _run_identity(body, prepared, run_id)
    status, conclusion = preflight._status(body)
    count, rows = jobs.get("total_count"), jobs.get("jobs")
    _same(type(count) is int and 0 <= count <= preflight.MAX_JOBS and type(rows) is list and len(rows) == count, "jobs-incomplete")
    suffixes = ({key: value for key, value in _JOB_SUFFIXES.items() if key not in ("android", "ios")}
                if prepared.target.selection.stage == "candidate" else
                {key: _JOB_SUFFIXES[key] for key in ("validate-platform", "android", "ios")})
    allowed = {prepared.target.selection.stage + " / " + key: value for key, value in suffixes.items()}
    ids, names, selected = set(), set(), []
    for row in rows:
        _require(type(row) is dict)
        identity, name = _upstream_id(row.get("id")), row.get("name")
        _same(identity not in ids and type(name) is str and name in allowed and name not in names, "jobs-incomplete")
        ids.add(identity); names.add(name)
        _same(_upstream_id(row.get("run_id")) == run_id and type(row.get("run_attempt")) is int
              and row["run_attempt"] == 1 and row.get("head_sha") == prepared.source_sha, "run-changed")
        state, result = preflight._status(row)
        selected.append({"id": identity, "kind": allowed[name], "status": state, "conclusion": result})
    if status == "completed" and conclusion == "success":
        platform = prepared.target.platform
        required = {"input-guard", *( (platform + "-resolve", platform + "-store")
                     if prepared.target.selection.stage == "candidate" else (platform,) )}
        _same(all(any(row["kind"] == kind and row["status"] == "completed" and row["conclusion"] == "success"
                      for row in selected) for kind in required), "jobs-incomplete")
        # Complete evidence reuse/recovery can skip online/build legitimately.
        # No generic "all jobs succeeded" assertion or invented evidence IDs.
    result = {"id": run_id, "attempt": 1, "status": status, "conclusion": conclusion, "observedAt": observed_at,
              "jobs": selected, "url": "https://github.com/" + prepared.target.repository + "/actions/runs/" + run_id,
              "assurance": ASSURANCE}
    _same(len(_canonical(result)) <= MAX_RUN_BYTES, "response-limit")
    return result


def execute(action: Action, reader: preflight.Reader, *, observed_at: str) -> dict[str, Any]:
    _utc(observed_at)
    control = _control()
    result: dict[str, Any] = {"schemaVersion": 1, "action": action.kind, "reason": "none",
        "effect": "not-sent" if action.kind == "dispatch" else "none", "prepared": None, "runId": None, "run": None, "control": control}

    def take(step: str, reference: str | None = None) -> dict[str, Any]:
        nonlocal control
        if step == "dispatch":
            result["effect"] = "potentially-applied"  # Before even connection setup; no no-send proof after this point.
        reply = reader.read(step, reference)
        _require(type(reply) is ReadResult)
        control = _check_control(reply.control)
        _check_values(reply.observation, nodes=20_000, depth=24)
        if step == "config" and action.kind == "prepare" and reply.observation.get("status") == 200:
            # Connection/G's public _read stays256KiB. Only this fixed config
            # role admits base64 overhead for the core's512KiB decoded limit.
            row = _object(reply.observation, {"status", "body", "failure"})
            _require(type(row["status"]) is int and row["status"] == 200 and row["failure"] == "none" and type(row["body"]) is dict)
            bounded_json_text(row["body"], max_bytes=768 * 1024, max_nodes=20_000, max_depth=24)
            body, reason = row["body"], "none"
        else:
            body, reason = _read(reply.observation)
        if control["reason"] != "none":
            raise Refused(control["reason"])
        if body is None:
            raise Refused(reason)
        return body

    try:
        account = take("account")
        _upstream_id(account.get("id"))
        _same(_account(account)["id"] == action.target.account_id, "target-changed")
        preflight._identity(take("repository-before"), action.target)
        if action.kind in {"prepare", "dispatch"}:
            source, source_tree = _source(take("branch-before"), action.target)
            workflow = _workflow(take("workflow"), action.target)
            if action.kind == "prepare":
                caller = _contents(take("caller", source), action.target.workflow_path, MAX_CALLER_BYTES, "caller-mismatch")
                _same(caller == canonical_caller(action.target), "caller-mismatch")
                config_raw = _contents(take("config"), CONFIG_PATH, MAX_CONFIG_BYTES, "config-invalid")
                config, selection = _configuration(config_raw, action.target)
                entries = _source_tree(take("source-tree", source_tree), action.target, source_tree,
                                       (action.target.workflow_path, CONFIG_PATH, selection.source))
                _match_blob(entries[action.target.workflow_path], caller)
                _match_blob(entries[CONFIG_PATH], config_raw)
                version_raw = _contents(take("version", selection.source), selection.source, MAX_VERSION_BYTES, "version-invalid")
                _match_blob(entries[selection.source], version_raw)
                _same(_source(take("branch-after"), action.target) == (source, source_tree), "source-changed")
                preflight._identity(take("repository-after"), action.target)
                result["prepared"] = _prepared(action.target, source, source_tree, workflow, caller, config_raw, config, selection, version_raw, observed_at).value()
            else:
                _require(action.prepared is not None)
                _same((source, source_tree) == (action.prepared.source_sha, action.prepared.source_tree), "source-changed")
                _same(workflow == action.prepared.workflow_id, "workflow-unavailable")
                result["runId"] = preflight.dispatched_run(take("dispatch"), action.prepared)
                result["effect"] = "accepted"
        else:
            _require(action.prepared is not None)
            run_id = reconcile_run(take("runs"), action.prepared) if action.kind == "reconcile" else action.run_id
            _require(run_id is not None)
            run = take("attempt", run_id if action.kind == "reconcile" else None)
            _run_identity(run, action.prepared, run_id)
            selected = observed_run(run, take("jobs"), action.prepared, run_id, observed_at)
            preflight._identity(take("repository-after"), action.target)
            result["runId"], result["run"] = run_id, selected
    except (Refused, preflight.Refused, ReadFailure) as error:
        result["reason"] = error.reason
    except (ConfigurationError, ValidationError, ValueError, TypeError, KeyError, UnicodeError, OverflowError, RecursionError):
        result["reason"] = "response-invalid"
    result["control"] = control
    return result


def _make_live_reader(action: Action, token: str, *, started: float, runtime_dir: str) -> preflight.Reader:
    from ._github_connection_transport import _ExchangeProfile, _ResponseRole, _make_live_exchange
    schedule = Schedule(action)
    profile = _ExchangeProfile.RELEASE_PREPARE if action.kind == "prepare" else _ExchangeProfile.STANDARD
    exchange = _make_live_exchange(token, started=started, runtime_dir=runtime_dir, api_version=API_VERSION, _profile=profile)

    class FixedReader:
        def read(self, step: str, reference: str | None = None) -> ReadResult:
            request = schedule.claim(step, reference)
            role = (_ResponseRole.RELEASE_CONFIG if step == "config" else _ResponseRole.RELEASE_VERSION
                    if step == "version" else _ResponseRole.STANDARD)
            return exchange(request.method, request.path, request.body, _role=role)

    return FixedReader()
