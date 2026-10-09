"""Closed DATA and request sequences for two repository settings.

No credential, clock, consent, socket, child or local-finality owner lives here.
A Schedule is not network authority. Live Setup admission and native one-use
consent are separate, required integrations; existing engine routes stay closed.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

from ._desktop_github_engine import _ID, _check_control, _check_values, _decode_json
from ._github_connection_transport import ReadFailure, ReadResult, _control
from .api._github_connection import _account, _coordinate, _id, _read, _repository, _utc
from .github_preflight import HttpRequest, Reader, _DIGEST, _match, _object, _require

PROTOCOL = "mrk-github-setup/1"
API_VERSION = "2026-03-10"
MAX_REQUESTS = 6
MAX_BODY_BYTES = 8 * 1024
MAX_INITIAL_BYTES = 8 * 1024
MAX_GO_BYTES = 8 * 1024
MAX_READY_BYTES = 512
MAX_RESULT_BYTES = 64 * 1024
KINDS = frozenset({"actions_enabled", "workflow_token_policy"})
REASONS = frozenset({"none", "no-change", "policy-unsupported", "policy-changed",
                     "organization-restricted", "repository-archived", "unauthorized", "forbidden",
                     "not-found-or-inaccessible", "target-changed", "rate-limited", "network-unavailable",
                     "tls-failed", "response-invalid", "response-limit", "expired", "cancelled"})


class Refused(ValueError):
    def __init__(self, reason: str) -> None:
        _require(type(reason) is str and reason in REASONS and reason != "none")
        self.reason = reason
        super().__init__("The fixed GitHub setup observation was refused")


def _same(condition: bool, reason: str) -> None:
    if not condition:
        raise Refused(reason)


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
                      allow_nan=False).encode("ascii")


@dataclass(frozen=True, slots=True)
class Selection:
    kind: str
    desired: tuple[Any, ...]

    @classmethod
    def parse(cls, value: object) -> Selection:
        _require(type(value) is dict and type(value.get("kind")) is str and value["kind"] in KINDS)
        if value["kind"] == "actions_enabled":
            row = _object(value, {"kind", "enabled"})
            _require(type(row["enabled"]) is bool)
            return cls(row["kind"], (row["enabled"],))
        row = _object(value, {"kind", "defaultWorkflowPermissions", "canApprovePullRequestReviews"})
        _require(type(row["defaultWorkflowPermissions"]) is str
                 and row["defaultWorkflowPermissions"] in {"read", "write"}
                 and type(row["canApprovePullRequestReviews"]) is bool)
        return cls(row["kind"], (row["defaultWorkflowPermissions"], row["canApprovePullRequestReviews"]))

    def value(self) -> dict[str, Any]:
        if self.kind == "actions_enabled":
            return {"kind": self.kind, "enabled": self.desired[0]}
        return {"kind": self.kind, "defaultWorkflowPermissions": self.desired[0],
                "canApprovePullRequestReviews": self.desired[1]}


@dataclass(frozen=True, slots=True)
class Target:
    project_binding: str
    repository: str
    account_id: str
    repository_id: str
    selection: Selection

    @classmethod
    def parse(cls, value: object) -> Target:
        row = _object(value, {"projectBinding", "repository", "accountId", "repositoryId", "selection"})
        return cls(_match(row["projectBinding"], _DIGEST), _coordinate(row["repository"]),
                   _id(row["accountId"]), _id(row["repositoryId"]), Selection.parse(row["selection"]))

    def value(self) -> dict[str, Any]:
        return {"projectBinding": self.project_binding, "repository": self.repository,
                "accountId": self.account_id, "repositoryId": self.repository_id,
                "selection": self.selection.value()}


@dataclass(frozen=True, slots=True)
class Policy:
    kind: str
    fields: tuple[Any, ...]

    @classmethod
    def parse(cls, kind: str, value: object, *, upstream: bool = False) -> Policy:
        _require(type(kind) is str and kind in KINDS and type(value) is dict)
        if kind == "actions_enabled":
            required = {"enabled", "allowed_actions", "sha_pinning_required"}
            if upstream:
                # Optional documented policy fields cannot become defaults.
                # Extra semantic policy fields require a reviewed preservation rule.
                _same(required <= set(value) <= required | {"selected_actions_url"}, "policy-unsupported")
                if "selected_actions_url" in value:
                    text = value["selected_actions_url"]
                    _require(type(text) is str and 1 <= len(text) <= 2048
                             and all(0x21 <= ord(char) <= 0x7e for char in text))
                    # Never follow, emit or use this URL as an endpoint.
            else:
                _object(value, required)
            _require(type(value["enabled"]) is bool and type(value["sha_pinning_required"]) is bool
                     and type(value["allowed_actions"]) is str
                     and value["allowed_actions"] in {"all", "local_only", "selected"})
            return cls(kind, (value["enabled"], value["allowed_actions"], value["sha_pinning_required"]))
        _object(value, {"default_workflow_permissions", "can_approve_pull_request_reviews"})
        _require(type(value["default_workflow_permissions"]) is str
                 and value["default_workflow_permissions"] in {"read", "write"}
                 and type(value["can_approve_pull_request_reviews"]) is bool)
        return cls(kind, (value["default_workflow_permissions"], value["can_approve_pull_request_reviews"]))

    def value(self) -> dict[str, Any]:
        if self.kind == "actions_enabled":
            return dict(zip(("enabled", "allowed_actions", "sha_pinning_required"), self.fields))
        return dict(zip(("default_workflow_permissions", "can_approve_pull_request_reviews"), self.fields))

    def changed(self, selection: Selection) -> Policy:
        _require(self.kind == selection.kind)
        if self.kind == "actions_enabled":
            return Policy(self.kind, (selection.desired[0], self.fields[1], self.fields[2]))
        return Policy(self.kind, selection.desired)


@dataclass(frozen=True, slots=True)
class Prepared:
    target: Target
    before: Policy
    observed_at: str

    @classmethod
    def parse(cls, value: object) -> Prepared:
        row = _object(value, {"target", "before", "after", "observedAt", "confirmation"})
        target = Target.parse(row["target"])
        before = Policy.parse(target.selection.kind, row["before"])
        result = cls(target, before, _utc(row["observedAt"]))
        _require(Policy.parse(target.selection.kind, row["after"]) == result.after)
        _require(result.before != result.after and row == result.value())
        return result

    @property
    def after(self) -> Policy:
        return self.before.changed(self.target.selection)

    def value(self) -> dict[str, Any]:
        notice = ("Change " + self.target.selection.kind + " for " + self.target.repository
                  + "? Review the exact before and after values. Enabling Actions can allow configured workflows "
                  "to run; write tokens or review approvals grant additional privileges. GitHub does not provide "
                  "an atomic compare-and-set here: another administrator can change settings after this review. "
                  "This does not configure secrets, change local workflows, or qualify a release.")
        return {"target": self.target.value(), "before": self.before.value(), "after": self.after.value(),
                "observedAt": self.observed_at, "confirmation": notice}


@dataclass(frozen=True, slots=True, repr=False)
class Action:
    kind: str
    target: Target
    prepared: Prepared | None = None

    @classmethod
    def parse(cls, value: object) -> Action:
        row = _object(value, {"kind", "target", "prepared"})
        _require(type(row["kind"]) is str and row["kind"] in {"prepare", "apply"})
        target = Target.parse(row["target"])
        prepared = None if row["prepared"] is None else Prepared.parse(row["prepared"])
        _require((row["kind"] == "prepare") == (prepared is None))
        _require(prepared is None or prepared.target == target)
        return cls(row["kind"], target, prepared)

    def value(self) -> dict[str, Any]:
        return {"kind": self.kind, "target": self.target.value(),
                "prepared": None if self.prepared is None else self.prepared.value()}


class Schedule:
    """DATA-only fixed endpoint cursor, claimed before any possible send."""
    def __init__(self, action: Action) -> None:
        self.action = Action.parse(action.value())
        self.steps: list[str] = []

    def claim(self, step: str, reference: str | None = None) -> HttpRequest:
        schedule = (("account", "repository-before", "resource-before", "repository-after")
                    if self.action.kind == "prepare" else
                    ("account", "repository-before", "resource-before", "write", "resource-after", "repository-after"))
        _require(reference is None and len(self.steps) < len(schedule) <= MAX_REQUESTS
                 and step == schedule[len(self.steps)])
        self.steps.append(step)  # Includes failed attempts; no retry or rollback.
        if step == "account":
            return HttpRequest("GET", "/user", None)
        prefix = "/repos/" + self.action.target.repository
        if step in {"repository-before", "repository-after"}:
            return HttpRequest("GET", prefix, None)
        path = prefix + "/actions/permissions"
        if self.action.target.selection.kind == "workflow_token_policy":
            path += "/workflow"
        if step == "write":
            _require(self.action.prepared is not None)
            raw = _canonical(self.action.prepared.after.value())
            _require(len(raw) <= MAX_BODY_BYTES)
            return HttpRequest("PUT", path, raw)
        return HttpRequest("GET", path, None)


def _identity(body: dict[str, Any], target: Target) -> None:
    _require(type(body.get("id")) is int)
    selected = _repository(body)
    _same(selected["id"] == target.repository_id
          and selected["fullName"].lower() == target.repository.lower(), "target-changed")
    _same(not selected["archived"], "repository-archived")


def execute(action: Action, reader: Reader, *, observed_at: str) -> dict[str, Any]:
    """One original's finite sequence, not a claim of native settlement.

    The existing owned reader must clip all exchanges and closes to the SAME
    original endpoint and enforce existing response/aggregate/header bounds.
    Only the private Setup factory below may construct that owned reader.
    """
    action = Action.parse(action.value())
    _utc(observed_at)
    result: dict[str, Any] = {"schemaVersion": 1, "action": action.kind, "reason": "none",
                              "effect": "not-started", "writeClaimed": False, "writeAcknowledged": False,
                              "prepared": None, "observed": None, "control": _control()}

    def take(step: str) -> dict[str, Any] | None:
        if step == "write":
            # This means loss of no-send proof, not proof bytes reached GitHub.
            result["writeClaimed"], result["effect"] = True, "unknown"
        reply = reader.read(step)
        _require(type(reply) is ReadResult)
        control = dict(_check_control(reply.control))
        result["control"] = control
        _check_values(reply.observation, nodes=20_000, depth=24)
        row = _object(reply.observation, {"status", "body", "failure"})
        if control["reason"] != "none":
            raise Refused(control["reason"])
        if step == "write" and type(row["status"]) is int and row["status"] == 204:
            _require(row["body"] is None and row["failure"] == "none")
            result["writeAcknowledged"] = True
            return None
        body, reason = _read(row)
        if step == "write":
            if row["status"] == 409 and action.target.selection.kind == "workflow_token_policy":
                raise Refused("organization-restricted")
            raise Refused(reason if reason != "none" else "response-invalid")
        if body is None:
            raise Refused(reason)
        return body

    try:
        account = take("account")
        _require(account is not None and type(account.get("id")) is int)
        _same(_account(account)["id"] == action.target.account_id, "target-changed")
        _identity(take("repository-before"), action.target)  # type: ignore[arg-type]
        before = Policy.parse(action.target.selection.kind, take("resource-before"), upstream=True)
        if action.kind == "prepare":
            _identity(take("repository-after"), action.target)  # type: ignore[arg-type]
            result["observed"] = before.value()
            if before == before.changed(action.target.selection):
                result["reason"] = "no-change"
            else:
                result["prepared"] = Prepared(action.target, before, observed_at).value()
        else:
            _require(action.prepared is not None)
            _same(before == action.prepared.before, "policy-changed")
            take("write")
            after = Policy.parse(action.target.selection.kind, take("resource-after"), upstream=True)
            _same(after == action.prepared.after, "policy-changed")
            _identity(take("repository-after"), action.target)  # type: ignore[arg-type]
            result["observed"], result["effect"] = after.value(), "readback-confirmed"
    except Refused as error:
        result["reason"] = error.reason
    except ReadFailure as error:
        result["reason"] = error.reason
    except (ValueError, TypeError, KeyError, UnicodeError, OverflowError):
        result["reason"] = "response-invalid"
    return result


def _make_live_reader(action: Action, token: str, *, started: float, runtime_dir: str) -> Reader:
    """Private Setup-only factory, called after the genuine native final GO."""
    from ._github_connection_transport import _ExchangeProfile, _ResponseRole, _make_live_exchange

    schedule = Schedule(action)
    exchange = _make_live_exchange(token, started=started, runtime_dir=runtime_dir,
                                   api_version=API_VERSION, _profile=_ExchangeProfile.SETUP)

    class FixedReader:
        def read(self, step: str, reference: str | None = None) -> ReadResult:
            request = schedule.claim(step, reference)
            role = _ResponseRole.STANDARD
            if step == "write":
                role = (_ResponseRole.SETUP_ACTIONS_WRITE if schedule.action.target.selection.kind == "actions_enabled"
                        else _ResponseRole.SETUP_WORKFLOW_WRITE)
            return exchange(request.method, request.path, request.body, _role=role)

    return FixedReader()


@dataclass(frozen=True, slots=True, repr=False)
class Initial:
    id: str
    action: Action
    digest: str


def _frame(raw: bytes, maximum: int, *, nodes: int, depth: int) -> Any:
    _require(type(raw) is bytes and 1 < len(raw) <= maximum and raw.endswith(b"\n")
             and raw.count(b"\n") == 1 and b"\r" not in raw)
    return _decode_json(raw[:-1], limit=maximum - 1, nodes=nodes, depth=depth, exact=True)


def parse_initial(raw: bytes) -> Initial:
    row = _object(_frame(raw, MAX_INITIAL_BYTES, nodes=256, depth=8), {"protocol", "id", "action"})
    _require(row["protocol"] == PROTOCOL)
    return Initial(_match(row["id"], _ID), Action.parse(row["action"]), hashlib.sha256(raw).hexdigest())


def ready_frame(request: Initial) -> bytes:
    raw = _canonical({"protocol": PROTOCOL, "id": request.id,
                      "ready": {"requestSha256": request.digest}}) + b"\n"
    _require(len(raw) <= MAX_READY_BYTES)
    return raw


def parse_go(raw: bytes, request: Initial) -> str:
    # Actual native context/consent checks precede this private token handoff.
    row = _object(_frame(raw, MAX_GO_BYTES, nodes=32, depth=4), {"protocol", "id", "go"})
    _require(row["protocol"] == PROTOCOL and row["id"] == request.id)
    go = _object(row["go"], {"requestSha256", "token"})
    _require(go["requestSha256"] == request.digest)
    token = go["token"]
    _require(type(token) is str and 1 <= len(token) <= 4096
             and all(0x21 <= ord(char) <= 0x7e for char in token))
    return token


def encode_result(request: Initial, value: object) -> bytes:
    row = _object(value, {"schemaVersion", "action", "reason", "effect", "writeClaimed",
                          "writeAcknowledged", "prepared", "observed", "control"})
    _require(type(row["schemaVersion"]) is int and row["schemaVersion"] == 1
             and row["action"] == request.action.kind and type(row["reason"]) is str
             and row["reason"] in REASONS and type(row["writeClaimed"]) is bool
             and type(row["writeAcknowledged"]) is bool)
    _check_control(row["control"])
    if row["observed"] is not None:
        Policy.parse(request.action.target.selection.kind, row["observed"])
    _require(not row["writeAcknowledged"] or row["writeClaimed"])
    if row["control"]["reason"] != "none":
        _require(row["reason"] == row["control"]["reason"])
    if request.action.kind == "prepare":
        _require(row["effect"] == "not-started" and not row["writeClaimed"] and not row["writeAcknowledged"])
        _require((row["reason"] == "none") == (row["prepared"] is not None))
        _require((row["reason"] in {"none", "no-change"}) == (row["observed"] is not None))
        if row["prepared"] is not None:
            prepared = Prepared.parse(row["prepared"])
            _require(prepared.target == request.action.target and row["observed"] == prepared.before.value())
        if row["reason"] == "no-change":
            policy = Policy.parse(request.action.target.selection.kind, row["observed"])
            _require(policy == policy.changed(request.action.target.selection))
    else:
        _require(row["prepared"] is None and row["reason"] != "no-change")
        if row["effect"] == "readback-confirmed":
            _require(row["reason"] == "none" and row["writeAcknowledged"]
                     and request.action.prepared is not None
                     and row["observed"] == request.action.prepared.after.value())
        else:
            _require(row["effect"] == ("unknown" if row["writeClaimed"] else "not-started")
                     and row["reason"] != "none" and row["observed"] is None)
    envelope = {"protocol": PROTOCOL, "id": request.id, "result": row}
    _check_values(envelope, nodes=1024, depth=12)
    raw = _canonical(envelope) + b"\n"
    _require(len(raw) <= MAX_RESULT_BYTES)
    return raw
