"""One complete GitHub environment input group; private, finite action policy.

The native document/connection/Supervisor owns material, consent and final GO.
This module never receives plaintext, chooses a URL, or upgrades metadata into
write evidence. The original exchange remains alive from READ through PUT.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from . import github_preflight as preflight
from . import github_release as release
from ._desktop_github_engine import _check_control, _check_values, _decode_json
from ._github_connection_transport import ReadFailure, ReadResult, _CloseFailure, _control
from .api._github_connection import _account, _coordinate, _id, _read, _utc
from .api._github_setup import _resource
from .api._json import bounded_json_text
from .config import MAX_CONFIG_BYTES, ReleaseConfig, parse_config_text
from .credential_group_envelope import (INPUT_GROUP_PROTOCOL, groups_for_requirements,
                                        input_group)
from .credential_requirements import ENVIRONMENT_NAMES, requirements
from .errors import ConfigurationError, CredentialError, ValidationError
from .workflow_payloads import render_workflow_caller

PROTOCOL = "mrk-github-input-group-action/1"
API_VERSION = "2026-03-10"
TOOLING_REPOSITORY = preflight.TOOLING_REPOSITORY
CONFIG_PATH = "release/mobile-release.json"
MAX_REQUESTS = 11
MAX_PUT_BODY = 70 * 1024
MAX_CIPHERTEXT_BYTES = 48_048
MAX_PREPARED_BYTES = 4096
MAX_RECORD_BYTES = 3900
MAX_POLICY_BYTES = 1536
ASSURANCE = "metadata-only-not-secret-value-or-write-confirmation"
REASONS = frozenset({
    "none", "unauthorized", "forbidden", "not-found-or-inaccessible", "target-changed",
    "rate-limited", "network-unavailable", "tls-failed", "response-invalid", "response-limit",
    "expired", "cancelled", "config-mismatch", "caller-incompatible", "environment-unready",
    "input-invalid", "destination-limit", "source-changed", "metadata-changed",
    "journal-incomplete", "context-stale", "assignment-unavailable", "runner-unverified",
    "sealing-unavailable", "consent-expired",
})
_DENIALS = frozenset({"unauthorized", "forbidden", "not-found-or-inaccessible",
                      "input-invalid", "rate-limited"})
_READ_STEPS = ("account", "repository-before", "source-before", "caller", "config",
               "environment", "public-key", "metadata", "source-after", "repository-after")
_RECONCILE_STEPS = ("account", "repository-before", "environment", "metadata", "repository-after")
_DIGEST, _SHA, _MARKER = preflight._DIGEST, preflight._SHA, preflight._MARKER
_object, _match, _upstream_id, _require = (preflight._object, preflight._match,
                                         preflight._upstream_id, preflight._require)


def canonical(value: object) -> bytes:
    """P2-only cross-language JSON domain: no floats, open mappings or large ints."""
    remaining = 20_000

    def admit(item: object, depth: int) -> None:
        nonlocal remaining
        remaining -= 1
        _require(remaining >= 0 and depth <= 24)
        if item is None or type(item) is bool:
            return
        if type(item) is int:
            _require(-(1 << 63) <= item < (1 << 64))
        elif type(item) is str:
            item.encode("utf-8")
        elif type(item) is list:
            for child in item:
                admit(child, depth + 1)
        elif type(item) is dict:
            for key, child in item.items():
                _require(type(key) is str)
                admit(key, depth + 1)
                admit(child, depth + 1)
        else:
            _require(False)

    admit(value, 0)
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


@dataclass(frozen=True, slots=True)
class Scope:
    platform: str
    stage: str
    purpose: str

    @classmethod
    def parse(cls, value: object) -> Scope:
        row = _object(value, {"platform", "stage", "purpose"})
        _require(type(row["platform"]) is str and row["platform"] in {"android", "ios"}
                 and type(row["stage"]) is str and row["stage"] in ENVIRONMENT_NAMES
                 and type(row["purpose"]) is str and row["purpose"] in {"full", "signing", "store"})
        return cls(row["platform"], row["stage"], row["purpose"])

    def value(self) -> dict[str, str]:
        return {"platform": self.platform, "stage": self.stage, "purpose": self.purpose}


@dataclass(frozen=True, slots=True)
class Target:
    project_binding: str
    repository: str
    account_id: str
    repository_id: str
    branch: str
    tooling_sha: str
    scope: Scope
    kind: str
    marker: str
    native_config_sha256: str

    @classmethod
    def parse(cls, value: object) -> Target:
        row = _object(value, {"projectBinding", "repository", "accountId", "repositoryId", "branch",
                              "toolingRepository", "toolingSha", "scope", "kind", "marker",
                              "nativeConfigSha256"})
        _require(row["toolingRepository"] == TOOLING_REPOSITORY and type(row["kind"]) is str)
        group = input_group(row["kind"])
        return cls(_match(row["projectBinding"], _DIGEST), _coordinate(row["repository"]),
                   _id(row["accountId"]), _id(row["repositoryId"]), preflight.branch(row["branch"]),
                   _match(row["toolingSha"], _SHA), Scope.parse(row["scope"]), group.kind,
                   _match(row["marker"], _MARKER), _match(row["nativeConfigSha256"], _DIGEST))

    def value(self) -> dict[str, Any]:
        return {"projectBinding": self.project_binding, "repository": self.repository,
                "accountId": self.account_id, "repositoryId": self.repository_id,
                "branch": self.branch, "toolingRepository": TOOLING_REPOSITORY,
                "toolingSha": self.tooling_sha, "scope": self.scope.value(), "kind": self.kind,
                "marker": self.marker, "nativeConfigSha256": self.native_config_sha256}

    @property
    def environment(self) -> str:
        return ENVIRONMENT_NAMES[self.scope.stage]

    @property
    def secret_name(self) -> str:
        return input_group(self.kind).secret_name

    @property
    def caller_path(self) -> str:
        stage = "production-submit" if self.scope.stage == "production" else self.scope.stage
        return ".github/workflows/mobile-" + stage + ".yml"


def canonical_caller(target: Target) -> bytes:
    _, resource = _resource()
    stage = "production-submit" if target.scope.stage == "production" else target.scope.stage
    return render_workflow_caller(resource["workflows"][stage].encode("utf-8"),
                                  TOOLING_REPOSITORY, target.tooling_sha)


@dataclass(frozen=True, slots=True)
class Metadata:
    state: str
    observed_at: str
    created_at: str | None = None
    updated_at: str | None = None

    @classmethod
    def parse(cls, value: object) -> Metadata:
        _require(type(value) is dict)
        if value.get("state") == "present":
            row = _object(value, {"state", "createdAt", "updatedAt", "observedAt"})
            return cls("present", _utc(row["observedAt"]), _utc(row["createdAt"]), _utc(row["updatedAt"]))
        row = _object(value, {"state", "observedAt"})
        _require(row["state"] == "missing-or-inaccessible")
        return cls("missing-or-inaccessible", _utc(row["observedAt"]))

    def value(self) -> dict[str, str]:
        result = {"state": self.state, "observedAt": self.observed_at}
        if self.state == "present":
            _require(self.created_at is not None and self.updated_at is not None)
            result.update(createdAt=self.created_at, updatedAt=self.updated_at)
        return result

    def identity(self) -> tuple[str, str | None, str | None]:
        return self.state, self.created_at, self.updated_at


def _policy_bytes(value: object) -> bytes:
    row = _object(value, {"canAdminsBypass", "branchPolicy", "rules"})
    _require(type(row["canAdminsBypass"]) is bool)
    branch = row["branchPolicy"]
    if branch is not None:
        _object(branch, {"protectedBranches", "customBranchPolicies"})
        _require(type(branch["protectedBranches"]) is bool and type(branch["customBranchPolicies"]) is bool
                 and not (branch["protectedBranches"] and branch["customBranchPolicies"]))
    rules = row["rules"]
    _require(type(rules) is list and len(rules) <= 8)
    seen = set()
    for rule in rules:
        _require(type(rule) is dict and type(rule.get("type")) is str)
        identity = _id(rule.get("id"))
        kind = rule["type"]
        _require(kind not in seen)
        seen.add(kind)
        if kind == "wait_timer":
            _object(rule, {"id", "type", "waitTimer"})
            _require(type(rule["waitTimer"]) is int and 0 <= rule["waitTimer"] <= 43200)
        elif kind == "required_reviewers":
            _object(rule, {"id", "type", "preventSelfReview", "reviewers"})
            _require(type(rule["preventSelfReview"]) is bool and type(rule["reviewers"]) is list
                     and 1 <= len(rule["reviewers"]) <= 6)
            reviewers = set()
            for reviewer in rule["reviewers"]:
                _object(reviewer, {"type", "id"})
                _require(type(reviewer["type"]) is str and reviewer["type"] in {"User", "Team"})
                selected = reviewer["type"], _id(reviewer["id"])
                _require(selected not in reviewers)
                reviewers.add(selected)
        else:
            _object(rule, {"id", "type"})
            _require(kind == "branch_policy")
        _require(identity == rule["id"])
    raw = canonical(row)
    _require(len(raw) <= MAX_POLICY_BYTES)
    return raw


def _key(value: object) -> tuple[str, str]:
    row = _object(value, {"keyId", "key"})
    key_id, key = row["keyId"], row["key"]
    _require(type(key_id) is str and 1 <= len(key_id) <= 128
             and all(0x21 <= ord(char) <= 0x7e and char not in '"\\' for char in key_id)
             and type(key) is str and len(key) == 44)
    try:
        decoded = base64.b64decode(key, validate=True)
    except (ValueError, binascii.Error):
        raise ValueError("Invalid fixed input-group public key") from None
    _require(len(decoded) == 32 and base64.b64encode(decoded).decode("ascii") == key)
    return key_id, key


@dataclass(frozen=True, slots=True)
class Prepared:
    target: Target
    source_sha: str
    caller_sha256: str
    config_sha256: str
    environment_id: str
    environment_policy: bytes
    public_key_id: str
    public_key: str
    metadata: Metadata
    observed_at: str

    @classmethod
    def parse(cls, value: object) -> Prepared:
        row = _object(value, {"target", "sourceSha", "callerSha256", "configSha256",
                              "environmentId", "environmentPolicy", "publicKey", "metadata", "observedAt"})
        target = Target.parse(row["target"])
        key_id, key = _key(row["publicKey"])
        prepared = cls(target, _match(row["sourceSha"], _SHA), _match(row["callerSha256"], _DIGEST),
                       _match(row["configSha256"], _DIGEST), _id(row["environmentId"]),
                       _policy_bytes(row["environmentPolicy"]), key_id, key,
                       Metadata.parse(row["metadata"]), _utc(row["observedAt"]))
        _require(prepared.metadata.observed_at == prepared.observed_at
                 and hashlib.sha256(canonical_caller(target)).hexdigest() == prepared.caller_sha256
                 and len(canonical(row)) <= MAX_PREPARED_BYTES and row == prepared.value())
        _require(len(canonical({"prepared": row, "write": {"state": "explicitly-rejected",
                 "reason": "not-found-or-inaccessible"}, "intentSha256": "0" * 64})) <= MAX_RECORD_BYTES)
        return prepared

    def value(self) -> dict[str, Any]:
        return {"target": self.target.value(), "sourceSha": self.source_sha,
                "callerSha256": self.caller_sha256, "configSha256": self.config_sha256,
                "environmentId": self.environment_id,
                "environmentPolicy": _decode_json(self.environment_policy, limit=MAX_POLICY_BYTES,
                                                  nodes=256, depth=8, exact=True),
                "publicKey": {"keyId": self.public_key_id, "key": self.public_key},
                "metadata": self.metadata.value(), "observedAt": self.observed_at}

    def public_target(self) -> dict[str, Any]:
        target = self.target
        return {"projectBinding": target.project_binding, "repository": target.repository,
                "repositoryId": target.repository_id, "accountId": target.account_id,
                "environment": target.environment, "environmentId": self.environment_id,
                "branch": target.branch, "sourceSha": self.source_sha, "toolingSha": target.tooling_sha,
                "callerPath": target.caller_path, "callerSha256": self.caller_sha256,
                "configSha256": self.config_sha256, "scope": target.scope.value(),
                "kind": target.kind, "secretName": target.secret_name, "protocol": INPUT_GROUP_PROTOCOL}


@dataclass(frozen=True, slots=True, repr=False)
class Action:
    kind: str
    target: Target
    prepared: Prepared | None = None

    @classmethod
    def parse(cls, value: object) -> Action:
        row = _object(value, {"kind", "target", "prepared"})
        _require(type(row["kind"]) is str and row["kind"] in {"prepare", "apply", "reconcile"})
        target = Target.parse(row["target"])
        prepared = None if row["prepared"] is None else Prepared.parse(row["prepared"])
        _require((row["kind"] == "prepare") == (prepared is None)
                 and (prepared is None or prepared.target == target))
        return cls(row["kind"], target, prepared)

    def value(self) -> dict[str, Any]:
        return {"kind": self.kind, "target": self.target.value(),
                "prepared": None if self.prepared is None else self.prepared.value()}


def validate_put_body(raw: bytes, key_id: str) -> bytes:
    """Admit original compact sealed body bytes; never reserialize for transport."""
    _require(type(raw) is bytes and 0 < len(raw) <= MAX_PUT_BODY)
    row = _object(_decode_json(raw, limit=MAX_PUT_BODY, nodes=8, depth=2, exact=True),
                  {"encrypted_value", "key_id"})
    _require(row["key_id"] == key_id and type(row["encrypted_value"]) is str)
    value = row["encrypted_value"]
    _require(64 <= len(value) <= 4 * ((MAX_CIPHERTEXT_BYTES + 2) // 3))
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        raise ValueError("Invalid fixed sealed input-group body") from None
    _require(48 < len(decoded) <= MAX_CIPHERTEXT_BYTES
             and base64.b64encode(decoded).decode("ascii") == value)
    # Compact adapter bytes may not carry whitespace/duplicate/extra members.
    # This equality is admission only: the returned object is the original raw.
    _require(raw == json.dumps(row, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
    return raw


class Schedule:
    """Read positions do not admit mutation; the separate last claim is one-use."""
    def __init__(self, action: Action) -> None:
        self.action = action
        self.steps: list[str] = []
        self.source_sha: str | None = None
        self.write_claimed = False

    def claim(self, step: str, reference: str | None = None) -> preflight.HttpRequest:
        schedule = _RECONCILE_STEPS if self.action.kind == "reconcile" else _READ_STEPS
        _require(len(self.steps) < len(schedule) and step == schedule[len(self.steps)]
                 and not self.write_claimed)
        self.steps.append(step)  # Consumed even if parsing/transport later fails.
        target = self.action.target
        prefix = "/repos/" + target.repository
        environment = prefix + "/environments/" + target.environment
        _require(reference is None or step == "caller")
        if step == "account":
            path = "/user"
        elif step in {"repository-before", "repository-after"}:
            path = prefix
        elif step in {"source-before", "source-after"}:
            path = prefix + "/git/ref/heads/" + preflight._quote(target.branch)
        elif step == "caller":
            self.source_sha = _match(reference, _SHA)
            path = prefix + "/contents/" + target.caller_path + "?ref=" + self.source_sha
        elif step == "config":
            _require(self.source_sha is not None)
            path = prefix + "/contents/" + CONFIG_PATH + "?ref=" + self.source_sha
        elif step == "environment":
            path = environment
        elif step == "public-key":
            path = environment + "/secrets/public-key"
        else:
            _require(step == "metadata")
            path = environment + "/secrets/" + target.secret_name
        return preflight.HttpRequest("GET", path, None)

    def claim_write(self, body: bytes) -> preflight.HttpRequest:
        _require(self.action.kind == "apply" and self.steps == list(_READ_STEPS)
                 and not self.write_claimed and self.action.prepared is not None)
        self.write_claimed = True
        target = self.action.target
        admitted = validate_put_body(body, self.action.prepared.public_key_id)
        return preflight.HttpRequest("PUT", "/repos/" + target.repository + "/environments/" +
                                     target.environment + "/secrets/" + target.secret_name, admitted)


class Reader(Protocol):
    def read(self, step: str, reference: str | None = None) -> ReadResult: ...
    def put(self, body: bytes, observer): ...


class Refused(ValueError):
    def __init__(self, reason: str) -> None:
        _require(reason in REASONS and reason != "none")
        self.reason = reason
        super().__init__("The fixed input-group action was refused")


def _same(condition: bool, reason: str) -> None:
    if not condition:
        raise Refused(reason)


def _environment(body: dict[str, Any], target: Target) -> tuple[str, bytes]:
    _same(body.get("name") == target.environment, "environment-unready")
    identity = _upstream_id(body.get("id"))
    _same(type(body.get("can_admins_bypass")) is bool and "deployment_branch_policy" in body
          and type(body.get("protection_rules")) is list and len(body["protection_rules"]) <= 8,
          "environment-unready")
    branch = body["deployment_branch_policy"]
    if branch is not None:
        _same(type(branch) is dict and type(branch.get("protected_branches")) is bool
              and type(branch.get("custom_branch_policies")) is bool, "environment-unready")
        branch = {"protectedBranches": branch["protected_branches"],
                  "customBranchPolicies": branch["custom_branch_policies"]}
    rules = []
    for original in body["protection_rules"]:
        _same(type(original) is dict and type(original.get("type")) is str, "environment-unready")
        rule = {"id": _upstream_id(original.get("id")), "type": original["type"]}
        if rule["type"] == "wait_timer":
            rule["waitTimer"] = original.get("wait_timer")
        elif rule["type"] == "required_reviewers":
            reviewers = original.get("reviewers")
            _same(type(reviewers) is list and 1 <= len(reviewers) <= 6, "environment-unready")
            selected = []
            for entry in reviewers:
                _same(type(entry) is dict and type(entry.get("reviewer")) is dict, "environment-unready")
                selected.append({"type": entry.get("type"), "id": _upstream_id(entry["reviewer"].get("id"))})
            rule.update(preventSelfReview=original.get("prevent_self_review"), reviewers=selected)
        else:
            _same(rule["type"] == "branch_policy", "environment-unready")
        rules.append(rule)
    try:
        projected = _policy_bytes({"canAdminsBypass": body["can_admins_bypass"], "branchPolicy": branch, "rules": rules})
    except (ValueError, TypeError, UnicodeError):
        raise Refused("environment-unready") from None
    return identity, projected


def _configuration(raw: bytes, target: Target) -> str:
    try:
        data = parse_config_text(raw.decode("utf-8"))
        digest = hashlib.sha256(canonical(data)).hexdigest()
        config = ReleaseConfig(Path(CONFIG_PATH), Path("."), data)  # DATA only, no path IO.
        _same(config.platform_enabled(target.scope.platform), "input-invalid")
        branch_key = "productionBranch" if target.scope.stage == "production" else "candidateBranch"
        _same(config.section("source").get(branch_key) == target.branch, "config-mismatch")
        selected = groups_for_requirements(requirements(config, target.scope.stage,
            purpose=target.scope.purpose, platforms=(target.scope.platform,)))
        _same(any(group.kind == target.kind for group in selected), "input-invalid")
        _same(digest == target.native_config_sha256, "config-mismatch")
        return hashlib.sha256(raw).hexdigest()
    except (ConfigurationError, CredentialError, ValidationError, UnicodeError, RecursionError):
        raise Refused("config-mismatch") from None


def compare_prepared(original: Prepared, current: Prepared) -> None:
    _same(current.target == original.target, "target-changed")
    _same(current.source_sha == original.source_sha, "source-changed")
    _same(current.caller_sha256 == original.caller_sha256, "caller-incompatible")
    _same(current.config_sha256 == original.config_sha256, "config-mismatch")
    _same(current.environment_id == original.environment_id
          and current.environment_policy == original.environment_policy, "environment-unready")
    _same((current.public_key_id, current.public_key) == (original.public_key_id, original.public_key),
          "target-changed")
    _same(current.metadata.identity() == original.metadata.identity(), "metadata-changed")


def result_value(kind: str) -> dict[str, Any]:
    _require(kind in {"prepare", "apply", "reconcile"})
    return {"schemaVersion": 1, "action": kind, "reason": "none", "prepared": None,
            "record": None, "observation": None, "control": _control(),
            "networkCleanup": "not-run", "journal": "not-run"}


def observe_reads(action: Action, reader: Reader, *, observed_at: str) -> dict[str, Any]:
    """All synchronous GETs settle before the caller can create writable READY.

    Returned objects contain safe projections only; raw bodies/config/caller
    buffers stay in this call and are not retained into the later write phase.
    This is reference/lifetime accounting, not a Python secure-erasure claim.
    """
    _utc(observed_at)
    result = result_value(action.kind)
    total = 0

    def take(step: str, reference: str | None = None) -> dict[str, Any] | None:
        nonlocal total
        result["networkCleanup"] = "unknown"
        reply = reader.read(step, reference)
        result["networkCleanup"] = "confirmed"
        _require(type(reply) is ReadResult)
        control = _check_control(reply.control)
        result["control"] = control
        maximum = 768 * 1024 if step == "config" else 256 * 1024
        total += len(bounded_json_text(reply.observation, max_bytes=maximum + 128,
                                       max_nodes=20_000, max_depth=24).encode("utf-8"))
        _same(total <= 2 * 1024 * 1024, "response-limit")
        if step == "config" and reply.observation.get("status") == 200:
            row = _object(reply.observation, {"status", "body", "failure"})
            _require(type(row["status"]) is int and row["failure"] == "none" and type(row["body"]) is dict)
            body, reason = row["body"], "none"
        else:
            body, reason = _read(reply.observation)
        if (step == "metadata" and reply.observation.get("status") == 404
                and reason == "not-found-or-inaccessible" and control == _control("not-found-or-inaccessible")):
            # Missing OR inaccessible is an explicit upsert preview state, not
            # proof of absence. No cooldown/control error is cleared here.
            result["control"] = _control()
            return None
        if control["reason"] != "none":
            raise Refused(control["reason"])
        if body is None:
            raise Refused(reason)
        return body

    try:
        account = take("account")
        _require(account is not None)
        _upstream_id(account.get("id"))
        _same(_account(account)["id"] == action.target.account_id, "target-changed")
        del account
        preflight._identity(take("repository-before"), action.target)
        if action.kind != "reconcile":
            source = preflight._source(take("source-before"), action.target)
            caller = release._contents(take("caller", source), action.target.caller_path,
                                       preflight.MAX_CALLER_BYTES, "caller-mismatch")
            _same(caller == canonical_caller(action.target), "caller-incompatible")
            caller_digest = hashlib.sha256(caller).hexdigest()
            del caller
            config_raw = release._contents(take("config"), CONFIG_PATH, MAX_CONFIG_BYTES, "config-invalid")
            config_digest = _configuration(config_raw, action.target)
            del config_raw
        environment_body = take("environment")
        if action.kind == "reconcile":
            _require(environment_body is not None)
            _same(environment_body.get("name") == action.target.environment, "environment-unready")
            environment_id = _upstream_id(environment_body.get("id"))
        else:
            environment_id, protection = _environment(environment_body, action.target)
        del environment_body
        if action.kind != "reconcile":
            public = take("public-key")
            _require(public is not None)
            key_id, key = _key({"keyId": public.get("key_id"), "key": public.get("key")})
            del public
        selected = take("metadata")
        if selected is None:
            metadata = Metadata("missing-or-inaccessible", observed_at)
        else:
            _require(selected.get("name") == action.target.secret_name)
            metadata = Metadata("present", observed_at, _utc(selected.get("created_at")), _utc(selected.get("updated_at")))
        del selected
        if action.kind != "reconcile":
            _same(preflight._source(take("source-after"), action.target) == source, "source-changed")
        preflight._identity(take("repository-after"), action.target)
        if action.kind == "reconcile":
            _require(action.prepared is not None)
            _same(environment_id == action.prepared.environment_id, "environment-unready")
            result["observation"] = {"originalOperationId": action.target.marker,
                "metadata": metadata.value(), "assurance": ASSURANCE}
        else:
            prepared = Prepared(action.target, source, caller_digest, config_digest, environment_id,
                                protection, key_id, key, metadata, observed_at)
            Prepared.parse(prepared.value())
            if action.kind == "apply":
                _require(action.prepared is not None)
                compare_prepared(action.prepared, prepared)
            result["prepared"] = prepared.value()
    except Refused as error:
        result["reason"] = error.reason
    except (preflight.Refused, release.Refused) as error:
        result["reason"] = {"caller-mismatch": "caller-incompatible", "workflow-unavailable": "caller-incompatible",
                            "config-invalid": "config-mismatch"}.get(error.reason, error.reason)
    except ReadFailure as error:
        result["reason"] = error.reason
    except _CloseFailure:
        result["reason"] = "network-unavailable"
    except (ConfigurationError, CredentialError, ValidationError, ValueError, TypeError, KeyError,
            UnicodeError, OverflowError, RecursionError):
        result["reason"] = "response-invalid"
    return result


def parse_write(value: object) -> dict[str, Any]:
    _require(type(value) is dict and type(value.get("state")) is str)
    state = value["state"]
    if state in {"not-attempted", "attempted-outcome-unknown"}:
        _object(value, {"state"})
    elif state in {"acknowledged-created", "acknowledged-updated"}:
        _object(value, {"state", "statusCode"})
        _require(type(value["statusCode"]) is int
                 and value["statusCode"] == (201 if state == "acknowledged-created" else 204))
    else:
        _object(value, {"state", "reason"})
        _require(state == "explicitly-rejected" and type(value["reason"]) is str and value["reason"] in _DENIALS)
    return dict(value)


def intent_digest(prepared: Prepared) -> str:
    """Exact nonsecret journal intent encoder, including the terminal LF."""
    raw = canonical({"schemaVersion": 1, "protocol": PROTOCOL, "prepared": prepared.value()}) + b"\n"
    return hashlib.sha256(raw).hexdigest()


def record_value(prepared: Prepared, write: object, intent_sha256: str) -> dict[str, Any]:
    _require(_match(intent_sha256, _DIGEST) == intent_digest(prepared))
    record = {"prepared": prepared.value(), "write": parse_write(write),
              "intentSha256": _match(intent_sha256, _DIGEST)}
    # Public projection worst-case includes only smaller target DATA, but keep
    # private full64 history bounded too instead of relying on that reduction.
    _require(len(canonical(record)) <= MAX_RECORD_BYTES)
    return record


def parse_record(value: object) -> dict[str, Any]:
    row = _object(value, {"prepared", "write", "intentSha256"})
    return record_value(Prepared.parse(row["prepared"]), row["write"], row["intentSha256"])


def validate_result(action: Action, value: object) -> dict[str, Any]:
    row = _object(value, {"schemaVersion", "action", "reason", "prepared", "record", "observation",
                          "control", "networkCleanup", "journal"})
    _require(type(row["schemaVersion"]) is int and row["schemaVersion"] == 1
             and row["action"] == action.kind and type(row["reason"]) is str and row["reason"] in REASONS
             and row["networkCleanup"] in {"not-run", "confirmed", "unknown"}
             and row["journal"] in {"not-run", "confirmed", "unknown"})
    _check_control(row["control"])
    if action.kind == "prepare":
        _require(row["record"] is None and row["observation"] is None and row["journal"] == "not-run")
        _require((row["reason"] == "none") == (row["prepared"] is not None))
        if row["prepared"] is not None:
            _require(Prepared.parse(row["prepared"]).target == action.target
                     and row["networkCleanup"] == "confirmed" and row["control"]["reason"] == "none")
    else:
        _require(row["prepared"] is None and action.prepared is not None)
        if row["record"] is not None:
            record = parse_record(row["record"])
            _require(Prepared.parse(record["prepared"]) == action.prepared)
        if action.kind == "apply":
            _require(row["observation"] is None)
            if row["reason"] == "none":
                _require(row["record"] is not None
                         and row["record"]["write"]["state"] in {"acknowledged-created", "acknowledged-updated"}
                         and row["networkCleanup"] == row["journal"] == "confirmed"
                         and row["control"]["reason"] == "none")
        else:
            _require(row["record"] is not None)
            observation = row["observation"]
            _require((row["reason"] == "none") == (observation is not None))
            if observation is not None:
                _object(observation, {"originalOperationId", "metadata", "assurance"})
                _require(observation["originalOperationId"] == action.target.marker
                         and observation["assurance"] == ASSURANCE and row["networkCleanup"] == "confirmed")
                Metadata.parse(observation["metadata"])
    _check_values(row, nodes=2000, depth=16)
    return row


def _make_live_reader(action: Action, token: str, *, started: float, runtime_dir: str) -> Reader:
    from ._github_connection_transport import _ExchangeProfile, _ResponseRole, _make_live_exchange

    schedule = Schedule(action)
    exchange = _make_live_exchange(token, started=started, runtime_dir=runtime_dir,
                                   api_version=API_VERSION, _profile=_ExchangeProfile.INPUT_GROUP)

    class FixedReader:
        def read(self, step: str, reference: str | None = None) -> ReadResult:
            request = schedule.claim(step, reference)
            role = _ResponseRole.INPUT_GROUP_CONFIG if step == "config" else _ResponseRole.STANDARD
            return exchange(request.method, request.path, request.body, _role=role)

        def put(self, body: bytes, observer):
            request = schedule.claim_write(body)
            return exchange(request.method, request.path, request.body,
                            _role=_ResponseRole.INPUT_GROUP_WRITE, _on_write_status=observer)

    return FixedReader()
