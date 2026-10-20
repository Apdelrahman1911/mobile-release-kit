"""Inspect the one published version counter using the existing GitHub owner.

Enrollment trusts an explicitly reviewed, currently published canonical ledger.
It cannot reconstruct erased history, keep branch protection in force, authorize
a reservation, or establish a Store floor.  There is no Git/FS/process owner here.
"""
from __future__ import annotations

import base64
import re
from dataclasses import dataclass
from typing import Protocol

from . import version_allocation as allocation
from . import version_policy as policy
from ._desktop_github_engine import _check_control, _decode_json
from ._github_connection_transport import ReadFailure, ReadResult, _control
from .api._github_connection import _account, _coordinate, _id, _repository
from .api._json import bounded_json_text
from .github_preflight import HttpRequest
from .config import ReleaseVersion

PROTOCOL = "mrk-version-enrollment/1"
MAX_HTTP_BYTES = allocation.MAX_HTTP_BYTES
MAX_OFFER_BYTES = 4096
MAX_REQUESTS = 10
REASONS = frozenset({"none", "counter-missing", "protection-unavailable", "protection-unsupported",
    "authority-changed", "authority-rewound", "ledger-invalid", "review-changed", "invalid-input",
    "unauthorized", "forbidden", "not-found-or-inaccessible", "target-changed", "rate-limited",
    "network-unavailable", "tls-failed", "response-invalid", "response-limit", "expired", "cancelled"})

ROLE_ACCOUNT = "version-enrollment-account"
ROLE_REPOSITORY = "version-enrollment-repository"
ROLE_PROTECTION = "version-enrollment-protection"
ROLE_REF = "version-enrollment-ref"
ROLE_LEDGER = "version-enrollment-ledger"
ROLE_COMPARE = "version-enrollment-compare"
ROLES = {ROLE_ACCOUNT: "VERSION_ENROLLMENT_ACCOUNT", ROLE_REPOSITORY: "VERSION_ENROLLMENT_REPOSITORY",
    ROLE_PROTECTION: "VERSION_ENROLLMENT_PROTECTION", ROLE_REF: "VERSION_ENROLLMENT_REF",
    ROLE_LEDGER: "VERSION_ENROLLMENT_LEDGER", ROLE_COMPARE: "VERSION_ENROLLMENT_COMPARE"}


class Refused(ValueError):
    def __init__(self, reason: str):
        self.reason = reason if reason in REASONS else "response-invalid"
        super().__init__("Shared version counter enrollment was refused")


def need(condition: bool, reason: str = "invalid-input") -> None:
    if not condition:
        raise Refused(reason)


@dataclass(frozen=True, slots=True)
class Target:
    project_binding: str
    repository: str
    account_id: str
    repository_id: str

    def __post_init__(self):
        policy._match(self.project_binding, policy._DIGEST)
        _coordinate(self.repository)
        _id(self.account_id)
        _id(self.repository_id)

    @classmethod
    def parse(cls, value: object) -> Target:
        row = policy._object(value, {"projectBinding", "repository", "accountId", "repositoryId"})
        return cls(row["projectBinding"], row["repository"], row["accountId"], row["repositoryId"])

    def value(self) -> dict:
        return {"projectBinding": self.project_binding, "repository": self.repository,
                "accountId": self.account_id, "repositoryId": self.repository_id}


@dataclass(frozen=True, slots=True)
class Offer:
    """Bounded comparison DATA; only the actual native read can retain a review."""
    authority: allocation.AuthorityRegistration
    checkpoint: allocation.Checkpoint
    blob: str
    version: ReleaseVersion

    def __post_init__(self):
        need(type(self.authority) is allocation.AuthorityRegistration and self.authority.protected_branch
             and type(self.checkpoint) is allocation.Checkpoint)
        policy._match(self.blob, policy._SHA)
        policy.version(self.version, ("android",), automatic=True)
        need(len(policy.canonical(self.value())) <= MAX_OFFER_BYTES)

    @classmethod
    def parse(cls, value: object) -> Offer:
        row = policy._object(value, {"authority", "checkpoint", "blob", "version"})
        return cls(allocation.AuthorityRegistration.parse(row["authority"]),
                   allocation.Checkpoint.parse(row["checkpoint"]), row["blob"],
                   policy.parse_version(row["version"], ("android",), automatic=True))

    def value(self) -> dict:
        return {"authority": self.authority.value(), "checkpoint": self.checkpoint.value(),
                "blob": self.blob, "version": policy.version_value(self.version)}


def validate_endpoint(role: str, method: str, path: str) -> None:
    """Called only after shared enum profile/role admission; never a URL port."""
    need(type(role) is str and role in ROLES and method == "GET" and type(path) is str
         and len(path) <= 1024)
    if role == ROLE_ACCOUNT:
        need(path == "/user")
        return
    parts = path.split("/")
    need(len(parts) >= 4 and parts[:2] == ["", "repos"])
    _coordinate(parts[2] + "/" + parts[3])
    tail = "/".join(parts[4:])
    fixed = {ROLE_REPOSITORY: "", ROLE_PROTECTION: "branches/" + allocation.LEDGER_BRANCH + "/protection",
             ROLE_REF: "git/ref/heads/" + allocation.LEDGER_BRANCH}
    if role in fixed:
        need(tail == fixed[role] and not path.endswith("/"))
    elif role == ROLE_LEDGER:
        need(re.fullmatch("contents/" + re.escape(allocation.LEDGER_PATH) + r"\?ref=[0-9a-f]{40}", tail,
                          re.ASCII) is not None)
    else:
        need(role == ROLE_COMPARE and re.fullmatch(r"compare/[0-9a-f]{40}\.\.\.[0-9a-f]{40}\?per_page=1&page=1",
                                                   tail, re.ASCII) is not None)


def validate_body(role: str, body: object, *, path: str) -> None:
    validate_endpoint(role, "GET", path)
    need(body is None)  # No remote creation, PUT, POST, reset or generic role.


class Reader(Protocol):
    control: dict
    def read(self, step: str, commit: str | None = None) -> ReadResult: ...


class _Reader:
    """One selected target and one finite schedule, not a caller-selected HTTP API."""
    def __init__(self, target: Target, previous: allocation.Checkpoint | None, send):
        need(type(target) is Target and (previous is None or type(previous) is allocation.Checkpoint)
             and callable(send))
        self.target, self.previous, self.send = target, previous, send
        self.steps = ("account", "repository-before", "protection-before", "ref-before", "ledger",
                      *(("compare",) if previous is not None else ()),
                      "ref-after", "protection-after", "repository-after")
        self.index, self.control, self.stopped, self.commit = 0, _control(), False, None

    def read(self, step: str, commit: str | None = None) -> ReadResult:
        need(not self.stopped and self.index < len(self.steps) and step == self.steps[self.index])
        self.index += 1  # Even a failed/unknown exchange consumes this step.
        root = "/repos/" + self.target.repository
        if step == "account":
            role, path = ROLE_ACCOUNT, "/user"
        elif step.startswith("repository-"):
            role, path = ROLE_REPOSITORY, root
        elif step.startswith("protection-"):
            role, path = ROLE_PROTECTION, root + "/branches/" + allocation.LEDGER_BRANCH + "/protection"
        elif step.startswith("ref-"):
            role, path = ROLE_REF, root + "/git/ref/heads/" + allocation.LEDGER_BRANCH
        elif step == "ledger":
            policy._match(commit, policy._SHA)
            self.commit = commit
            role, path = ROLE_LEDGER, root + "/contents/" + allocation.LEDGER_PATH + "?ref=" + commit
        else:
            need(self.previous is not None and commit == self.commit and self.commit is not None)
            role, path = ROLE_COMPARE, root + "/compare/" + self.previous.commit + "..." + commit + "?per_page=1&page=1"
        need((commit is not None) == (step in {"ledger", "compare"}))
        validate_body(role, None, path=path)
        try:
            result = self.send(role, HttpRequest("GET", path, None))
            need(type(result) is ReadResult, "response-invalid")
            self.control = dict(_check_control(result.control))
            bounded_json_text(result.observation, max_bytes=MAX_HTTP_BYTES, max_nodes=20_000, max_depth=24)
            row = policy._object(result.observation, {"status", "body", "failure"})
            if self.control["reason"] != "none" or row["failure"] != "none" or row["status"] != 200:
                self.stopped = True
            if self.index == len(self.steps):
                self.stopped = True
            return result
        except BaseException:
            self.stopped = True
            raise


def _body(reader: Reader, step: str, commit: str | None = None) -> dict:
    result = reader.read(step, commit)
    need(type(result) is ReadResult, "response-invalid")
    control = _check_control(result.control)
    row = policy._object(result.observation, {"status", "body", "failure"})
    # Preserve the original control even when a semantic explanation is clearer.
    if row["status"] == 404 and step == "ledger":
        raise Refused("counter-missing")
    if row["status"] == 404 and step.startswith("protection-"):
        raise Refused("protection-unavailable")
    need(control["reason"] == "none", control["reason"])
    need(row["failure"] == "none", row["failure"])
    need(type(row["status"]) is int and row["status"] == 200 and type(row["body"]) is dict,
         "response-invalid")
    return row["body"]


def _identity(body: dict, target: Target) -> None:
    value = _repository(body)
    need(value["id"] == target.repository_id and value["fullName"].lower() == target.repository.lower()
         and not value["archived"], "authority-changed")


def _protection(body: dict) -> None:
    # Classic branch protection only. An inaccessible/ruleset-only response is
    # not equivalent. These are minimum observed controls, not a full policy or
    # an assertion that administrators cannot later change the protection.
    for key, required in (("enforce_admins", True), ("allow_force_pushes", False), ("allow_deletions", False)):
        need(type(body.get(key)) is dict and body[key].get("enabled") is required,
             "protection-unsupported")


def _snapshot(body: dict, commit: str, target: Target) -> allocation.LedgerSnapshot:
    need(body.get("type") == "file" and body.get("path") == allocation.LEDGER_PATH
         and body.get("encoding") == "base64" and "target" not in body and "submodule_git_url" not in body,
         "ledger-invalid")
    size = body.get("size")
    encoded = body.get("content")
    need(type(size) is int and 0 < size <= allocation.MAX_LEDGER_BYTES
         and type(encoded) is str and len(encoded) <= 2 * allocation.MAX_LEDGER_BYTES, "ledger-invalid")
    try:
        raw = base64.b64decode(encoded.replace("\n", ""), validate=True)
        need(len(raw) == size and allocation.blob_sha(raw) == body.get("sha"), "ledger-invalid")
        value = policy._object(_decode_json(raw, limit=allocation.MAX_LEDGER_BYTES, nodes=20_000, depth=16),
                               {"schemaVersion", "protocol", "genesis", "reservations"})
        genesis = allocation.Genesis.parse(value["genesis"])
        need(genesis.repository_id == target.repository_id, "authority-changed")
        authority = allocation.AuthorityRegistration(genesis.project_id, target.repository,
            target.repository_id, genesis.ledger_id, genesis.sha256, True)
        ledger = allocation.Ledger.parse(raw, authority)
        return allocation.LedgerSnapshot(ledger, commit, body["sha"])
    except Refused:
        raise
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError):
        raise Refused("ledger-invalid") from None


def execute(target: Target, reader: Reader, *, review: Offer | None = None,
            previous: allocation.Checkpoint | None = None) -> dict:
    """Read/review only. Native confirmation/CAS happens after the worker joins."""
    need(type(target) is Target and (review is None or type(review) is Offer)
         and (previous is None or type(previous) is allocation.Checkpoint)
         and (previous is None or review is not None))
    result = {"schemaVersion": 1, "reason": "none", "offer": None, "control": _control()}
    try:
        need(_account(_body(reader, "account"))["id"] == target.account_id, "target-changed")
        _identity(_body(reader, "repository-before"), target)
        _protection(_body(reader, "protection-before"))
        commit = allocation._ref_commit(_body(reader, "ref-before"))
        if review is not None:
            need(review.authority.repository == target.repository
                 and review.authority.repository_id == target.repository_id
                 and review.checkpoint.commit == commit, "review-changed")
        snapshot = _snapshot(_body(reader, "ledger", commit), commit, target)
        genesis = snapshot.ledger.genesis
        authority = allocation.AuthorityRegistration(genesis.project_id, target.repository,
            target.repository_id, genesis.ledger_id, genesis.sha256, True)
        offer = Offer(authority, snapshot.checkpoint, snapshot.blob, snapshot.ledger.last_version)
        if review is not None:
            need(offer == review, "review-changed")
        if previous is not None:
            snapshot.ledger.admit(authority, previous)
            allocation._ancestry(_body(reader, "compare", commit), previous.commit, commit)
        need(allocation._ref_commit(_body(reader, "ref-after")) == commit, "authority-changed")
        _protection(_body(reader, "protection-after"))
        _identity(_body(reader, "repository-after"), target)
        result["offer"] = offer.value()
    except (Refused, ReadFailure) as error:
        result["reason"] = error.reason if error.reason in REASONS else "response-invalid"
    except allocation.VersionAllocationError as error:
        result["reason"] = error.reason if error.reason in REASONS else "ledger-invalid"
    except (ValueError, TypeError, KeyError, UnicodeError, OverflowError, RecursionError):
        result["reason"] = "response-invalid"
    result["control"] = dict(_check_control(reader.control))
    if result["control"]["reason"] != "none":
        result["offer"] = None
        if result["reason"] == "none":
            result["reason"] = result["control"]["reason"]
    return result


def make_reader(target: Target, token: str, *, previous: allocation.Checkpoint | None,
                started: float, runtime_dir: str) -> _Reader:
    """Private original native GO only; no credential discovery or fallback."""
    from . import _github_connection_transport as native
    try:
        profile = native._ExchangeProfile.VERSION_ENROLLMENT
        roles = {role: native._ResponseRole[name] for role, name in ROLES.items()}
    except (AttributeError, KeyError):
        raise Refused("protection-unavailable") from None
    exchange = native._make_live_exchange(token, started=started, runtime_dir=runtime_dir,
                                          api_version="2026-03-10", _profile=profile)
    return _Reader(target, previous, lambda role, request: exchange(request.method, request.path,
                   body=request.body, _role=roles[role]))
