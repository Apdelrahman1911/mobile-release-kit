"""Bounded authenticated runner-inventory prerequisite; never a mutation.

The separate fixed native profile owns authentication/transport/settlement.
These parsers and DATA schedules do not create native authority. Organization
coverage is deliberately all organization/inherited groups, not an undocumented
repository filter. Administrator maintenance remains a runtime responsibility.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable

from ._desktop_github_engine import (
    ProtocolError, ReadRequest, REASONS, _ID, _check_control, _check_values,
    _decode_json, _numeric_id, _JsonError, _JsonLimit,
)
from ._github_connection_transport import (
    ReadResult, ReadFailure, _control, _refuse, _make_live_exchange,
    _ExchangeProfile, _ResponseRole, MAX_BODY_BYTES, MAX_BODY_TOTAL,
)
from .workflow_payloads import TOOLING_REPOSITORY_RE

PROTOCOL = "mrk-github-runner-prerequisite/1"
API_VERSION = "2026-03-10"
REQUEST_LIMIT = 8192
RESPONSE_LIMIT = 256 * 1024
GROUP_LIMIT = 8
RUNNER_LIMIT = 100
LABEL_LIMIT = 64
LABEL_BYTES = 256
GET_LIMIT = 14
FORBIDDEN_LABELS = frozenset({"ubuntu-24.04", "macos-26"})
RESULT_REASONS = REASONS | {"runner-collision"}


@dataclass(frozen=True, slots=True, repr=False)
class RunnerRequest(ReadRequest):
    pass


class Refused(ValueError):
    def __init__(self, reason: str) -> None:
        if reason not in RESULT_REASONS - {"none"}:
            raise ValueError("Invalid runner prerequisite disposition")
        self.reason = reason
        super().__init__("The runner prerequisite was not established")


def _require(condition: bool, reason: str = "response-invalid") -> None:
    if not condition:
        raise Refused(reason)


def _object(value: object, keys: set[str]) -> dict[str, Any]:
    _require(type(value) is dict and set(value) == keys)
    return value


def _upstream_id(value: object) -> str:
    _require(type(value) is int and 0 < value <= 2**64 - 1)
    return str(value)


def _utc(value: object) -> str:
    _require(type(value) is str and len(value) == 20 and value.endswith("Z"))
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except (ValueError, TypeError):
        raise Refused("response-invalid") from None
    _require(parsed.strftime("%Y-%m-%dT%H:%M:%SZ") == value)
    return value


def parse_request(raw: bytes) -> RunnerRequest:
    try:
        _require(type(raw) is bytes and 1 < len(raw) <= REQUEST_LIMIT and raw.endswith(b"\n")
                 and raw.count(b"\n") == 1 and b"\r" not in raw)
        value = _object(_decode_json(raw[:-1], limit=REQUEST_LIMIT - 1, nodes=128,
                                    depth=6, exact=True), {"protocol", "id", "params"})
        _require(value["protocol"] == PROTOCOL and type(value["id"]) is str
                 and _ID.fullmatch(value["id"]) is not None)
        params = _object(value["params"], {"repository", "expectedAccountId", "expectedRepositoryId", "token"})
        repository, account, repo, token = (params[name] for name in
            ("repository", "expectedAccountId", "expectedRepositoryId", "token"))
        _require(type(repository) is str and TOOLING_REPOSITORY_RE.fullmatch(repository) is not None
                 and _numeric_id(account) and _numeric_id(repo) and type(token) is str
                 and 1 <= len(token) <= 4096 and all(0x21 <= ord(c) <= 0x7e for c in token))
        return RunnerRequest(value["id"], repository, account, repo, token)
    except (Refused, _JsonError, TypeError, UnicodeError, OverflowError, RecursionError):
        raise ProtocolError("Invalid private runner prerequisite frame") from None


def _account(body: object, request: RunnerRequest) -> str:
    _require(type(body) is dict)
    identity = _upstream_id(body.get("id"))
    _require(identity == request.expected_account_id, "target-changed")
    return identity


def _repository(body: object, request: RunnerRequest) -> dict[str, Any]:
    _require(type(body) is dict and type(body.get("owner")) is dict
             and type(body.get("permissions")) is dict)
    owner, permissions = body["owner"], body["permissions"]
    identity, owner_id = _upstream_id(body.get("id")), _upstream_id(owner.get("id"))
    full_name, owner_login, owner_type = body.get("full_name"), owner.get("login"), owner.get("type")
    _require(type(full_name) is str and TOOLING_REPOSITORY_RE.fullmatch(full_name) is not None
             and type(owner_login) is str and owner_type in {"User", "Organization"})
    _require(identity == request.expected_repository_id and full_name.lower() == request.repository.lower()
             and owner_login.lower() == request.repository.split("/", 1)[0].lower(), "target-changed")
    _require(body.get("archived") is False and permissions.get("admin") is True, "forbidden")
    return {"repositoryId": identity, "repository": full_name,
            "owner": {"id": owner_id, "type": owner_type}}


def _list(body: object, field: str, maximum: int) -> list[Any]:
    _require(type(body) is dict and type(body.get("total_count")) is int
             and body["total_count"] >= 0 and type(body.get(field)) is list)
    rows = body[field]
    _require(body["total_count"] <= maximum and len(rows) <= maximum, "response-limit")
    _require(body["total_count"] == len(rows))
    return rows


def _groups(body: object) -> list[dict[str, Any]]:
    result, seen = [], set()
    for row in _list(body, "runner_groups", GROUP_LIMIT):
        _require(type(row) is dict and type(row.get("inherited")) is bool)
        identity = _upstream_id(row.get("id"))
        _require(identity not in seen)
        seen.add(identity)
        result.append({"id": identity, "inherited": row["inherited"]})
    return result


def _runners(body: object, seen: set[str]) -> list[dict[str, Any]]:
    result = []
    for row in _list(body, "runners", RUNNER_LIMIT):
        _require(type(row) is dict and type(row.get("labels")) is list)
        identity = _upstream_id(row.get("id"))
        _require(identity not in seen)
        seen.add(identity)
        _require(len(row["labels"]) <= LABEL_LIMIT, "response-limit")
        names, labels = set(), set()
        for label in row["labels"]:
            _require(type(label) is dict and type(label.get("name")) is str
                     and label.get("type") in {"read-only", "custom"})
            label_id = _upstream_id(label.get("id"))
            name = label["name"]
            _require(0 < len(name.encode("utf-8")) <= LABEL_BYTES and not any(ord(c) < 0x20 or ord(c) == 0x7f for c in name))
            normalized = name.casefold()
            _require(0 < len(normalized.encode("utf-8")) <= LABEL_BYTES, "response-limit")
            _require(label_id not in labels and normalized not in names)
            labels.add(label_id); names.add(normalized)
            _require(normalized not in FORBIDDEN_LABELS, "runner-collision")
        result.append({"id": identity, "labels": sorted(names)})
    return result


class _FixedReader:
    """One private finite roster, not a page engine or arbitrary route delegate."""
    def __init__(self, request: RunnerRequest, exchange: Callable[..., ReadResult]) -> None:
        _require(type(request) is RunnerRequest)
        self.request, self.exchange = request, exchange
        self.prefix = "/repos/" + request.repository
        self.org = "/orgs/" + request.repository.split("/", 1)[0]
        self.roster = [("user-before", "/user"), ("repository-before", self.prefix),
                       ("repository-runners", self.prefix + "/actions/runners?per_page=100&page=1")]
        self.claimed = 0
        self.failed = False
        self.owner_type: str | None = None

    def read(self, step: str) -> ReadResult:
        _require(not self.failed and self.claimed < min(len(self.roster), GET_LIMIT)
                 and step == self.roster[self.claimed][0])
        path = self.roster[self.claimed][1]
        self.claimed += 1  # Spend this logical read before the first exchange.
        self.failed = True  # An exception/refusal never permits a later route.
        result = self.exchange("GET", path, None, _role=_ResponseRole.RUNNER_PREREQUISITE)
        try:
            _require(type(result) is ReadResult)
            control = _check_control(result.control)
            observation = _object(result.observation, {"status", "body", "failure"})
            _require(type(observation["status"]) is int and observation["status"] == 200
                     and observation["failure"] == "none" and type(observation["body"]) is dict
                     and control["reason"] == "none")
            # Only validated actual identity/group responses extend this finite
            # roster. observe() owns full inventory/budget validation and stops
            # before any dependent read on a policy refusal.
            if step in {"user-before", "user-after"}:
                _account(observation["body"], self.request)
            elif step == "repository-before":
                self.owner_type = _repository(observation["body"], self.request)["owner"]["type"]
            elif step == "repository-runners" and self.owner_type is not None:
                if self.owner_type == "Organization":
                    self.roster.append(("organization-groups", self.org + "/actions/runner-groups?per_page=100&page=1"))
                else:
                    self.roster.extend((("repository-after", self.prefix), ("user-after", "/user")))
            elif step == "organization-groups":
                groups = _groups(observation["body"])
                self.roster.extend(("group-runners-" + str(index), self.org + "/actions/runner-groups/" + group["id"]
                                    + "/runners?per_page=100&page=1") for index, group in enumerate(groups))
                self.roster.extend((("repository-after", self.prefix), ("user-after", "/user")))
            self.failed = False
        except (Refused, ValueError, TypeError, UnicodeError, OverflowError):
            # Keep the original response/control for observe() to report; never
            # turn malformed DATA into success or lose authenticated cooldown.
            pass
        return result


def _make_live_reader(request: RunnerRequest, *, started: float, runtime_dir: str) -> _FixedReader:
    _require(type(request) is RunnerRequest)
    exchange = _make_live_exchange(request.token, started=started, runtime_dir=runtime_dir,
                                  api_version=API_VERSION, _profile=_ExchangeProfile.RUNNER_PREREQUISITE)
    return _FixedReader(request, exchange)


def observe(request: RunnerRequest, reader, *, observed_at: str) -> dict[str, Any]:
    _require(type(request) is RunnerRequest and _numeric_id(request.expected_account_id)
             and _numeric_id(request.expected_repository_id))
    _utc(observed_at)
    outcome: dict[str, Any] = {"schemaVersion": 1, "reason": "none", "facts": None,
                              "control": _control(), "networkCleanup": "not-run"}
    total, requests = 0, 0

    def take(step: str) -> dict[str, Any]:
        nonlocal total, requests
        _require(requests < GET_LIMIT, "response-limit")
        requests += 1
        outcome["networkCleanup"] = "unknown"
        result = reader.read(step)
        _require(type(result) is ReadResult)
        # The live exchange returns only after its actual synchronous close.
        outcome["networkCleanup"] = "confirmed"
        discarded = (result.observation.get("body") if type(result.observation) is dict else None)
        try:
            outcome["control"] = _check_control(result.control)
            observation = _object(result.observation, {"status", "body", "failure"})
            if outcome["control"]["reason"] != "none":
                raise Refused(outcome["control"]["reason"])
            _require(observation["failure"] == "none" and observation["status"] == 200
                     and type(observation["status"]) is int and type(observation["body"]) is dict)
            body = observation["body"]
            # Shared live transport counts actual body bytes including discarded
            # DATA. This also bounds the inert exchange seam's supplied bodies.
            _check_values(body, nodes=20000, depth=24)
            size = len(json.dumps(body, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8"))
            total += size
            _require(size <= MAX_BODY_BYTES and total <= MAX_BODY_TOTAL, "response-limit")
            return body
        except BaseException:
            if type(discarded) is dict:
                discarded.clear()
            raise

    body = None

    try:
        body = take("user-before")
        account = _account(body, request); body.clear()
        body = take("repository-before")
        repository = _repository(body, request); body.clear()
        seen: set[str] = set()
        body = take("repository-runners")
        runners = _runners(body, seen); body.clear()
        groups: list[dict[str, Any]] = []
        if repository["owner"]["type"] == "Organization":
            body = take("organization-groups")
            groups = _groups(body); body.clear()
            for index, group in enumerate(groups):
                body = take("group-runners-" + str(index))
                group["runners"] = _runners(body, seen); body.clear()
        body = take("repository-after")
        ending = _repository(body, request); body.clear()
        _require(ending == repository, "target-changed")
        body = take("user-after")
        _require(_account(body, request) == account, "target-changed"); body.clear()
        _require(requests == (5 if repository["owner"]["type"] == "User" else 6 + len(groups)))
        outcome["facts"] = {"accountId": account, **repository, "repositoryRunners": runners,
                            "groups": groups, "observedAt": observed_at}
        # Bound the actual complete result, not only individual inventories.
        encode_response(request.id, outcome)
    except Refused as error:
        outcome["reason"] = error.reason
    except ReadFailure as error:
        outcome["reason"] = error.reason
        outcome["control"] = _refuse(outcome["control"], error.reason)
    except _JsonLimit:
        outcome["reason"] = "response-limit"
    except (ProtocolError, _JsonError, ValueError, TypeError, UnicodeError, OverflowError, RecursionError):
        outcome["reason"] = "response-invalid"
    except Exception:
        # In particular, an actual transport close failure remains Unknown.
        outcome["reason"] = "network-unavailable"
    finally:
        if type(body) is dict:
            body.clear()
    if outcome["reason"] != "none":
        outcome["facts"] = None
        if outcome["reason"] in REASONS:
            outcome["control"] = _refuse(outcome["control"], outcome["reason"])
    return outcome


def _normalized_runners(value: object, seen: set[str]) -> None:
    _require(type(value) is list and len(value) <= RUNNER_LIMIT)
    for row in value:
        row = _object(row, {"id", "labels"})
        _require(_numeric_id(row["id"]) and row["id"] not in seen)
        seen.add(row["id"])
        labels = row["labels"]
        _require(type(labels) is list and len(labels) <= LABEL_LIMIT)
        previous = None
        for label in labels:
            _require(type(label) is str and 0 < len(label.encode("utf-8")) <= LABEL_BYTES
                     and label == label.casefold() and label not in FORBIDDEN_LABELS
                     and not any(ord(c) < 0x20 or ord(c) == 0x7f for c in label)
                     and (previous is None or previous < label))
            previous = label


def encode_response(request_id: str, outcome: object) -> bytes:
    _require(type(request_id) is str and _ID.fullmatch(request_id) is not None)
    result = _object(outcome, {"schemaVersion", "reason", "facts", "control", "networkCleanup"})
    _require(type(result["schemaVersion"]) is int and result["schemaVersion"] == 1
             and type(result["reason"]) is str and result["reason"] in RESULT_REASONS
             and result["networkCleanup"] in {"not-run", "confirmed", "unknown"})
    control = _check_control(result["control"])
    if result["reason"] == "none":
        _require(control["reason"] == "none" and result["networkCleanup"] == "confirmed")
        facts = _object(result["facts"], {"accountId", "repositoryId", "repository", "owner", "repositoryRunners", "groups", "observedAt"})
        _require(_numeric_id(facts["accountId"]) and _numeric_id(facts["repositoryId"])
                 and type(facts["repository"]) is str and TOOLING_REPOSITORY_RE.fullmatch(facts["repository"]) is not None)
        owner = _object(facts["owner"], {"id", "type"})
        _require(_numeric_id(owner["id"]) and owner["type"] in {"User", "Organization"})
        _utc(facts["observedAt"])
        seen: set[str] = set()
        _normalized_runners(facts["repositoryRunners"], seen)
        groups = facts["groups"]
        _require(type(groups) is list and len(groups) <= GROUP_LIMIT and (owner["type"] != "User" or not groups))
        group_ids: set[str] = set()
        for group in groups:
            group = _object(group, {"id", "inherited", "runners"})
            _require(_numeric_id(group["id"]) and group["id"] not in group_ids and type(group["inherited"]) is bool)
            group_ids.add(group["id"])
            _normalized_runners(group["runners"], seen)
    else:
        _require(result["facts"] is None)
        if control["reason"] != "none":
            _require(result["reason"] in {control["reason"], "response-invalid", "response-limit"})
    value = {"protocol": PROTOCOL, "id": request_id, "result": result}
    _check_values(value, nodes=20000, depth=12)
    raw = json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8") + b"\n"
    _require(len(raw) <= RESPONSE_LIMIT, "response-limit")
    return raw
