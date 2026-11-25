"""Closed empty-repository creation policy; no credential or execution owner.

The original native connection supplies the authenticated account and project
binding. These DATA helpers do not prove authentication, durable custody, native
settlement, or permission to create a repository. Only Create can attempt POST.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Protocol

from ._desktop_github_engine import _check_control
from ._github_connection_transport import ReadFailure, ReadResult, _control
from .api._github_connection import _id
from .github_preflight import HttpRequest

PROTOCOL = "mrk-github-repository-create/1"
MAX_REQUESTS = 8
MAX_RECORDS = 32
MAX_RECORD_BYTES = 4096
MAX_RESULT_BYTES = 128 * 1024
REASONS = frozenset({"none", "invalid-input", "target-changed", "repository-exists",
    "membership-unconfirmed", "permission-unconfirmed", "unauthorized", "forbidden",
    "not-found-or-inaccessible", "rate-limited", "network-unavailable", "tls-failed",
    "response-invalid", "response-limit", "expired", "cancelled", "journal-unavailable",
    "previous-attempt", "unresolved", "unattributed"})
_LOGIN = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?\Z", re.ASCII)
_NAME = re.compile(r"[A-Za-z0-9._-]{1,100}\Z", re.ASCII)


def require(condition: bool) -> None:
    if not condition:
        raise ValueError("Invalid closed repository-creation data")


def obj(value: object, keys: set[str]) -> dict:
    require(type(value) is dict and set(value) == keys)
    return value  # type: ignore[return-value]


def canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True,
                      separators=(",", ":")).encode("ascii")


def login(value: object) -> str:
    require(type(value) is str and _LOGIN.fullmatch(value) is not None and "--" not in value)
    return value  # type: ignore[return-value]


def coordinate(value: object) -> str:
    require(type(value) is str and value.count("/") == 1)
    owner, name = value.split("/")  # type: ignore[union-attr]
    login(owner)
    require(_NAME.fullmatch(name) is not None and name not in {".", ".."}
            and not name.lower().endswith(".git"))
    return value  # type: ignore[return-value]


def hex_text(value: object, size: int) -> str:
    require(type(value) is str and re.fullmatch(r"[0-9a-f]{" + str(size) + "}", value) is not None)
    return value  # type: ignore[return-value]


class Refused(ValueError):
    def __init__(self, reason: str):
        require(reason in REASONS and reason != "none")
        self.reason = reason
        super().__init__("The repository-creation operation was refused")


def need(condition: bool, reason: str = "response-invalid") -> None:
    if not condition:
        raise Refused(reason)


@dataclass(frozen=True, slots=True)
class Target:
    project_binding: str
    repository: str
    account_id: str
    account_login: str
    owner_kind: str
    visibility: str
    marker: str

    @classmethod
    def parse(cls, value: object) -> Target:
        row = obj(value, {"projectBinding", "repository", "accountId", "accountLogin", "ownerKind", "visibility", "marker"})
        require(row["ownerKind"] in ("user", "organization") and row["visibility"] in ("private", "public"))
        result = cls(hex_text(row["projectBinding"], 64), coordinate(row["repository"]), _id(row["accountId"]),
                     login(row["accountLogin"]), row["ownerKind"], row["visibility"], hex_text(row["marker"], 32))
        require(result.owner_kind != "user" or result.owner.lower() == result.account_login.lower())
        return result

    @property
    def owner(self) -> str:
        return self.repository.split("/")[0]

    @property
    def name(self) -> str:
        return self.repository.split("/")[1]

    def value(self) -> dict:
        return {"projectBinding": self.project_binding, "repository": self.repository, "accountId": self.account_id,
                "accountLogin": self.account_login, "ownerKind": self.owner_kind, "visibility": self.visibility, "marker": self.marker}

    def body(self) -> dict:
        return {"name": self.name, "private": self.visibility == "private", "auto_init": False}

    def endpoint(self) -> str:
        return "/user/repos" if self.owner_kind == "user" else "/orgs/" + self.owner + "/repos"


def confirmation(target: Target) -> str:
    return ("Create " + target.repository + " as a " + target.visibility.upper() + " GitHub repository? "
            + ("Anyone can see a public repository and files you later upload. " if target.visibility == "public" else "")
            + "No local files, Git commits, remotes, pushes or workflows are added. "
            "Organization rules and token permissions still apply. Stopping cannot undo a sent request.")


@dataclass(frozen=True, slots=True)
class Prepared:
    target: Target
    owner_id: str
    membership: str

    def value(self) -> dict:
        return {"target": self.target.value(), "ownerId": self.owner_id, "membership": self.membership,
                "repositoryObservation": "not-found-or-inaccessible", "creationPermission": "not-proven",
                "autoInit": False, "confirmation": confirmation(self.target)}

    @classmethod
    def parse(cls, value: object) -> Prepared:
        row = obj(value, {"target", "ownerId", "membership", "repositoryObservation", "creationPermission", "autoInit", "confirmation"})
        result = cls(Target.parse(row["target"]), _id(row["ownerId"]), row["membership"])
        require(result.membership in (("self",) if result.target.owner_kind == "user" else ("active-member", "active-admin")))
        require(result.target.owner_kind != "user" or result.owner_id == result.target.account_id)
        require(row == result.value() and row["autoInit"] is False and len(canonical(row)) <= MAX_RECORD_BYTES)
        return result


def observation(value: object, prepared: Prepared) -> dict:
    """Exact redacted stored projection, not an upstream JSON body."""
    row = obj(value, {"id", "fullName", "ownerId", "visibility", "url"})
    _id(row["id"]); _id(row["ownerId"]); coordinate(row["fullName"])
    require(row["fullName"].lower() == prepared.target.repository.lower() and row["ownerId"] == prepared.owner_id
            and row["visibility"] == prepared.target.visibility and row["url"] == "https://github.com/" + row["fullName"])
    return dict(row)


def _repository(value: object, prepared: Prepared) -> dict:
    need(type(value) is dict)
    owner = value.get("owner")
    need(type(owner) is dict and type(value.get("id")) is int and type(owner.get("id")) is int)
    need(owner.get("type") == ("User" if prepared.target.owner_kind == "user" else "Organization")
         and login(owner.get("login")).lower() == prepared.target.owner.lower()
         and value.get("fork") is False and value.get("archived") is False, "target-changed")
    need(type(value.get("private")) is bool and value["private"] == (prepared.target.visibility == "private"), "target-changed")
    return observation({"id": _id(value["id"], upstream=True), "fullName": coordinate(value.get("full_name")),
                        "ownerId": _id(owner["id"], upstream=True), "visibility": value.get("visibility"),
                        "url": "https://github.com/" + coordinate(value.get("full_name"))}, prepared)


class Exchange(Protocol):
    def __call__(self, request: HttpRequest) -> ReadResult: ...


class Journal(Protocol):
    def create_intent(self, prepared: dict) -> None: ...
    def claim(self) -> None: ...
    def record(self, repository: dict) -> None: ...


class Operation:
    def __init__(self, target: Target, exchange: Exchange):
        self.target = Target.parse(target.value())
        self.exchange = exchange
        self.steps: set[str] = set()
        self.control = _control()

    def take(self, step: str, path: str, *, creating: bool = False, absent: bool = False) -> dict | None:
        need(step not in self.steps and len(self.steps) < MAX_REQUESTS, "response-limit")
        self.steps.add(step)
        reply = self.exchange(HttpRequest("POST" if creating else "GET", path,
            canonical(self.target.body()) if creating else None))
        need(type(reply) is ReadResult)
        self.control = dict(_check_control(reply.control))
        row = obj(reply.observation, {"status", "body", "failure"})
        if self.control["reason"] != "none":
            raise Refused(self.control["reason"])
        if row["failure"] != "none":
            raise Refused(row["failure"])
        need(type(row["status"]) is int)
        if not creating and absent and row["status"] == 404:
            need(row["body"] is None)
            return None
        if row["status"] != (201 if creating else 200):
            raise Refused({401: "unauthorized", 403: "forbidden", 404: "not-found-or-inaccessible",
                           422: "permission-unconfirmed", 409: "repository-exists", 429: "rate-limited"}.get(
                           row["status"], "network-unavailable" if row["status"] >= 500 else "response-invalid"))
        need(type(row["body"]) is dict and len(canonical(row["body"])) <= 256 * 1024, "response-limit")
        return row["body"]

    def identity(self) -> tuple[str, str]:
        account = self.take("account", "/user")
        need(account is not None and type(account.get("id")) is int and account.get("type") == "User")
        need(_id(account["id"], upstream=True) == self.target.account_id
             and login(account.get("login")).lower() == self.target.account_login.lower(), "target-changed")
        if self.target.owner_kind == "user":
            need(self.target.owner.lower() == self.target.account_login.lower(), "target-changed")
            return self.target.account_id, "self"
        organization = self.take("organization", "/orgs/" + self.target.owner)
        need(organization is not None and type(organization.get("id")) is int
             and login(organization.get("login")).lower() == self.target.owner.lower(), "target-changed")
        owner_id = _id(organization["id"], upstream=True)
        membership = self.take("membership", "/user/memberships/orgs/" + self.target.owner)
        need(membership is not None and membership.get("state") == "active"
             and membership.get("role") in ("admin", "member"), "membership-unconfirmed")
        member, org = membership.get("user"), membership.get("organization")
        need(type(member) is dict and type(org) is dict and type(member.get("id")) is int and type(org.get("id")) is int
             and _id(member["id"], upstream=True) == self.target.account_id
             and login(member.get("login")).lower() == self.target.account_login.lower()
             and _id(org["id"], upstream=True) == owner_id
             and login(org.get("login")).lower() == self.target.owner.lower(), "target-changed")
        return owner_id, "active-" + membership["role"]


def prepare(target: Target, exchange: Exchange) -> tuple[Prepared, dict]:
    op = Operation(target, exchange)
    owner_id, membership = op.identity()
    need(op.take("name-check", "/repos/" + target.repository, absent=True) is None, "repository-exists")
    prepared = Prepared.parse(Prepared(target, owner_id, membership).value())
    return prepared, op.control


def create(prepared: Prepared, exchange: Exchange, journal: Journal) -> dict:
    prepared = Prepared.parse(prepared.value())
    op = Operation(prepared.target, exchange)
    result = {"effect": "not-sent", "reason": "none", "claimed": False, "acknowledged": None,
              "observed": None, "control": _control()}
    try:
        need(op.identity() == (prepared.owner_id, prepared.membership), "target-changed")
        need(op.take("name-check", "/repos/" + prepared.target.repository, absent=True) is None, "repository-exists")
        journal.create_intent(prepared.value())
        # A partial/failed claim is preserved by the original journal. Claiming
        # before the exchange never authorizes replay even if no reply arrives.
        journal.claim()
        result.update(effect="potentially-applied", claimed=True)
        created = _repository(op.take("create", prepared.target.endpoint(), creating=True), prepared)
        journal.record(created)
        result["acknowledged"] = created
        observed = _repository(op.take("readback", "/repos/" + prepared.target.repository), prepared)
        need(observed == created, "target-changed")
        result.update(effect="created-observed", observed=observed)
    except (Refused, ReadFailure) as error:
        result["reason"] = error.reason
    except (ValueError, TypeError, KeyError, UnicodeError, OverflowError, RecursionError):
        result["reason"] = "response-invalid"
    except OSError:
        result["reason"] = "journal-unavailable"
    result["control"] = op.control
    return result


def pending_record(value: object) -> dict:
    row = obj(value, {"prepared", "claimed", "acknowledged"})
    prepared = Prepared.parse(row["prepared"])
    require(type(row["claimed"]) is bool and (row["acknowledged"] is None or row["claimed"]))
    return {"prepared": prepared.value(), "claimed": row["claimed"], "acknowledged":
            None if row["acknowledged"] is None else observation(row["acknowledged"], prepared)}


def reconcile(record: dict, exchange: Exchange) -> dict:
    original = pending_record(record)
    prepared = Prepared.parse(original["prepared"])
    op = Operation(prepared.target, exchange)
    result = {"effect": "unresolved", "reason": "unresolved", "claimed": original["claimed"],
              "acknowledged": original["acknowledged"], "observed": None, "control": _control()}
    try:
        owner_id, _ = op.identity()
        need(owner_id == prepared.owner_id, "target-changed")
        row = op.take("readback", "/repos/" + prepared.target.repository, absent=True)
        if row is not None:
            observed = _repository(row, prepared)
            if original["acknowledged"] is None:
                result.update(effect="found-unattributed", reason="unattributed", observed=observed)
            else:
                need(observed == original["acknowledged"], "target-changed")
                result.update(effect="created-observed", reason="none", observed=observed)
    except (Refused, ReadFailure) as error:
        result["reason"] = error.reason
    except (ValueError, TypeError, KeyError, UnicodeError, OverflowError, RecursionError):
        result["reason"] = "response-invalid"
    result["control"] = op.control
    return result


def creation_result(value: object, prepared: Prepared, kind: str) -> dict:
    """Validate the closed core result, never its native or durable finality."""
    require(kind in ("create", "reconcile"))
    Prepared.parse(prepared.value())
    row = obj(value, {"effect", "reason", "claimed", "acknowledged", "observed", "control"})
    require(row["reason"] in REASONS and type(row["claimed"]) is bool)
    _check_control(row["control"])
    ack = None if row["acknowledged"] is None else observation(row["acknowledged"], prepared)
    seen = None if row["observed"] is None else observation(row["observed"], prepared)
    require(ack is None or row["claimed"])
    effect = row["effect"]
    if effect == "not-sent":
        require(kind == "create" and not row["claimed"] and ack is None and seen is None and row["reason"] != "none")
    elif effect == "potentially-applied":
        require(kind == "create" and row["claimed"] and seen is None and row["reason"] != "none")
    elif effect == "created-observed":
        require(row["claimed"] and ack is not None and seen == ack and row["reason"] == "none")
    elif effect == "unresolved":
        require(kind == "reconcile" and seen is None and row["reason"] != "none")
    elif effect == "found-unattributed":
        require(kind == "reconcile" and ack is None and seen is not None and row["reason"] == "unattributed")
    else:
        require(False)
    return dict(row)


def digest(prepared: Prepared) -> str:
    return hashlib.sha256(canonical(Prepared.parse(prepared.value()).value())).hexdigest()
