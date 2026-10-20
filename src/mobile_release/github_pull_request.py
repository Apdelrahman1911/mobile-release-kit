"""One explicitly approved same-repository draft PR, on the original HTTP owner.

No Git push, merge, ready-for-review or release operation. Text is private input;
public/journal projections contain hashes only. A matching marker is observation,
not proof that this original POST created it and never permission to send again.
"""
from __future__ import annotations

import hashlib
import json
import unicodedata
from dataclasses import dataclass
from typing import Protocol

from ._desktop_github_engine import _check_control
from ._github_connection_transport import ReadFailure, ReadResult, _control
from .api._github_connection import _id
from .github_preflight import HttpRequest, branch, _quote
from .github_repository_create import coordinate, hex_text, obj, require

PROTOCOL = "mrk-github-pull-request/1"
MAX_REQUESTS = 12
MAX_RECORDS = 32
MAX_RECORD_BYTES = 4096
MAX_RESULT_BYTES = 192 * 1024
BODY_LIMIT = 256 * 1024
TOTAL_BODY_LIMIT = 2 * 1024 * 1024
REASONS = frozenset({"none", "invalid-input", "target-changed", "branches-changed", "pull-request-exists",
    "no-changes", "permission-unconfirmed", "unauthorized", "forbidden", "not-found-or-inaccessible",
    "rate-limited", "network-unavailable", "tls-failed", "response-invalid", "response-limit", "expired",
    "cancelled", "journal-unavailable", "previous-attempt", "unresolved", "unattributed"})
CHANGES = ("added", "removed", "modified", "renamed", "copied", "changed", "unchanged")


def canonical(value: object) -> bytes:
    # Match the existing native canonical serde Value map: sorted keys, UTF-8.
    # Text never enters initial/public frames; this also binds Unicode filenames.
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


class Refused(ValueError):
    def __init__(self, reason: str):
        require(reason in REASONS and reason != "none")
        self.reason = reason
        super().__init__("The draft pull request operation was refused")


def need(value: bool, reason: str = "response-invalid") -> None:
    if not value:
        raise Refused(reason)


def user_text(value: object, maximum: int, *, multiline: bool = False, empty: bool = False) -> str:
    require(type(value) is str and (empty or bool(value.strip())) and len(value.encode("utf-8")) <= maximum)
    require(all(unicodedata.category(c) not in ("Cc", "Cf", "Cs") or multiline and c == "\n" for c in value)
            and "mrk-draft-pr:" not in value)
    return value


def sha_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True, repr=False)
class Draft:
    base: str
    head: str
    title: str
    body: str

    @classmethod
    def parse(cls, value: object) -> Draft:
        r = obj(value, {"base", "head", "title", "body"})
        result = cls(branch(r["base"]), branch(r["head"]), user_text(r["title"], 256),
                     user_text(r["body"], 4096, multiline=True, empty=True))
        require(result.base != result.head)
        return result

    def value(self) -> dict:
        return {"base": self.base, "head": self.head, "title": self.title, "body": self.body}

    def matches(self, target: Target) -> bool:
        i = target.intent
        return i is not None and (self.base, self.head, sha_text(self.title), sha_text(self.body)) == (
            i["base"], i["head"], i["titleSha256"], i["bodySha256"])

    def post_body(self, target: Target) -> dict:
        require(self.matches(target))
        return {"base": self.base, "head": self.head, "title": self.title,
                "body": self.body + marker_suffix(target), "draft": True}


@dataclass(frozen=True, slots=True)
class Target:
    scope: dict
    intent: dict | None

    @classmethod
    def parse(cls, value: object) -> Target:
        r = obj(value, {"scope", "intent"})
        s = obj(r["scope"], {"projectBinding", "repository", "accountId", "repositoryId"})
        hex_text(s["projectBinding"], 64); coordinate(s["repository"]); _id(s["accountId"]); _id(s["repositoryId"])
        i = r["intent"]
        if i is not None:
            i = obj(i, {"base", "head", "marker", "titleSha256", "bodySha256"})
            branch(i["base"]); branch(i["head"]); require(i["base"] != i["head"])
            hex_text(i["marker"], 32); hex_text(i["titleSha256"], 64); hex_text(i["bodySha256"], 64)
        return cls(dict(s), None if i is None else dict(i))

    def value(self) -> dict:
        return {"scope": dict(self.scope), "intent": None if self.intent is None else dict(self.intent)}

    @property
    def repository(self) -> str:
        return self.scope["repository"]

    def same_scope(self, other: Target) -> bool:
        return all(self.scope[k] == other.scope[k] for k in ("projectBinding", "accountId", "repositoryId")) \
            and self.repository.lower() == other.repository.lower()


def marker_suffix(target: Target) -> str:
    require(target.intent is not None)
    return "\n\n<!-- mrk-draft-pr:" + target.intent["marker"] + " -->"


def confirmation(target: Target) -> str:
    require(target.intent is not None)
    return ("Create a draft pull request in " + target.repository + " from " + target.intent["head"]
            + " into " + target.intent["base"] + " with the text you reviewed? Existing GitHub workflows may run. "
            "No code is pushed or merged. This does not authorize a release. Stopping cannot undo a sent request.")


def count(value: object) -> int:
    require(type(value) is int and 0 <= value <= 2**31 - 1)
    return value


@dataclass(frozen=True, slots=True)
class Prepared:
    target: Target
    base_sha: str
    head_sha: str
    comparison: dict

    def value(self) -> dict:
        return {"target": self.target.value(), "baseSha": self.base_sha, "headSha": self.head_sha,
                "comparison": self.comparison, "draft": True, "creationPermission": "not-proven",
                "confirmation": confirmation(self.target)}

    @classmethod
    def parse(cls, value: object) -> Prepared:
        r = obj(value, {"target", "baseSha", "headSha", "comparison", "draft", "creationPermission", "confirmation"})
        t = Target.parse(r["target"]); require(t.intent is not None)
        c = obj(r["comparison"], {"aheadBy", "behindBy", "totalCommits", "reportedFiles", "coverage", "files"})
        require(count(c["aheadBy"]) > 0); count(c["behindBy"]); count(c["totalCommits"]); count(c["reportedFiles"])
        require(c["coverage"] == "windowed" and type(c["files"]) is list and len(c["files"]) <= 4
                and c["reportedFiles"] >= len(c["files"]))
        paths: set[str] = set()
        for file in c["files"]:
            f = obj(file, {"path", "change"}); user_text(f["path"], 192)
            require(f["change"] in CHANGES and f["path"] not in paths); paths.add(f["path"])
        result = cls(t, hex_text(r["baseSha"], 40), hex_text(r["headSha"], 40), c)
        require(result.base_sha != result.head_sha and r["draft"] is True and r == result.value()
                and len(canonical(r)) <= MAX_RECORD_BYTES - 64)
        return result


def digest(prepared: Prepared) -> str:
    return hashlib.sha256(canonical(Prepared.parse(prepared.value()).value())).hexdigest()


def acknowledgement(value: object, prepared: Prepared) -> dict:
    r = obj(value, {"id", "number", "url"})
    _id(r["id"]); _id(r["number"])
    require(r["url"] == "https://github.com/" + prepared.target.repository + "/pull/" + r["number"])
    return dict(r)


def _number(value: object) -> str:
    require(type(value) is int)
    return _id(value, upstream=True)


def _ack(value: object, prepared: Prepared) -> dict:
    need(type(value) is dict)
    t = prepared.target
    for side in ("base", "head"):
        ref = value.get(side)
        need(type(ref) is dict and type(ref.get("repo")) is dict)
        repo = ref["repo"]
        need(_number(repo.get("id")) == t.scope["repositoryId"] and coordinate(repo.get("full_name")).lower() == t.repository.lower()
             and ref.get("ref") == t.intent[side], "target-changed")
    number = _number(value.get("number"))
    return acknowledgement({"id": _number(value.get("id")), "number": number,
                            "url": "https://github.com/" + t.repository + "/pull/" + number}, prepared)


def _observed(value: object, prepared: Prepared) -> dict:
    ack = _ack(value, prepared)
    suffix = marker_suffix(prepared.target)
    need(value.get("state") == "open" and value.get("draft") is True
         and value["base"].get("sha") == prepared.base_sha and value["head"].get("sha") == prepared.head_sha, "branches-changed")
    title, body = value.get("title"), value.get("body")
    need(type(title) is str and type(body) is str and len(title.encode("utf-8")) <= 256
         and len(body.encode("utf-8")) <= 4096 + len(suffix) and body.endswith(suffix))
    need(sha_text(title) == prepared.target.intent["titleSha256"]
         and sha_text(body[:-len(suffix)]) == prepared.target.intent["bodySha256"], "target-changed")
    return ack


class Exchange(Protocol):
    def __call__(self, request: HttpRequest) -> ReadResult: ...


class Journal(Protocol):
    def create_intent(self, value: dict) -> None: ...
    def claim(self) -> None: ...
    def record(self, value: dict) -> None: ...


class Operation:
    def __init__(self, target: Target, exchange: Exchange):
        self.target = Target.parse(target.value()); self.exchange = exchange
        self.steps: set[str] = set(); self.bytes = 0; self.control = _control()
        self.base = "/repos/" + self.target.repository

    def take(self, step: str, path: str, *, body: bytes | None = None, listing: bool = False):
        need(step not in self.steps and len(self.steps) < MAX_REQUESTS, "response-limit")
        self.steps.add(step)
        reply = self.exchange(HttpRequest("GET" if body is None else "POST", path, body))
        need(type(reply) is ReadResult)
        self.control = dict(_check_control(reply.control)); r = obj(reply.observation, {"status", "body", "failure"})
        if self.control["reason"] != "none": raise Refused(self.control["reason"])
        if r["failure"] != "none": raise Refused(r["failure"])
        need(type(r["status"]) is int)
        if r["status"] != (200 if body is None else 201):
            raise Refused({401: "unauthorized", 403: "forbidden", 404: "not-found-or-inaccessible", 409: "target-changed",
                422: "permission-unconfirmed", 429: "rate-limited"}.get(r["status"], "network-unavailable" if r["status"] >= 500 else "response-invalid"))
        need(type(r["body"]) is (list if listing else dict))
        size = len(canonical(r["body"])); self.bytes += size
        need(size <= BODY_LIMIT and self.bytes <= TOTAL_BODY_LIMIT, "response-limit")
        if listing: need(len(r["body"]) <= 2, "response-limit")
        return r["body"]

    def identity(self) -> None:
        user = self.take("account", "/user")
        need(_number(user.get("id")) == self.target.scope["accountId"] and user.get("type") == "User", "target-changed")
        self.repository("repository")

    def repository(self, step: str) -> None:
        r = self.take(step, self.base)
        need(_number(r.get("id")) == self.target.scope["repositoryId"]
             and coordinate(r.get("full_name")).lower() == self.target.repository.lower()
             and r.get("archived") is False and r.get("disabled") is False, "target-changed")
        permissions = r.get("permissions")
        # An observed push bit is a prerequisite, not proof of PR permission or
        # branch rules. Fork PRs and unproven permissions use GitHub explicitly.
        need(type(permissions) is dict and permissions.get("push") is True, "permission-unconfirmed")

    def ref(self, side: str, step: str) -> str:
        name = self.target.intent[side]
        r = self.take(step, self.base + "/git/ref/heads/" + _quote(name))
        o = r.get("object")
        need(r.get("ref") == "refs/heads/" + name and type(o) is dict and o.get("type") == "commit", "branches-changed")
        return hex_text(o.get("sha"), 40)

    def list_path(self, *, opened: bool) -> str:
        t = self.target
        return self.base + "/pulls?state=" + ("open" if opened else "all") + "&head=" + _quote(t.repository.split("/")[0] + ":" + t.intent["head"]) \
            + "&base=" + _quote(t.intent["base"]) + "&per_page=2&page=1"

    def prepare(self) -> Prepared:
        require(self.target.intent is not None)
        self.identity()
        base, head = self.ref("base", "base"), self.ref("head", "head")
        need(base != head, "no-changes")
        c = self.take("comparison", self.base + "/compare/" + base + "..." + head + "?per_page=1&page=1")
        need(type(c.get("base_commit")) is dict and c["base_commit"].get("sha") == base, "branches-changed")
        need(c.get("status") in ("ahead", "diverged") and count(c.get("ahead_by")) > 0, "no-changes")
        files = c.get("files"); need(type(files) is list and len(files) <= 300, "response-limit")
        summary = []
        for row in files[:4]:
            need(type(row) is dict and row.get("status") in CHANGES)
            summary.append({"path": user_text(row.get("filename"), 192), "change": row["status"]})
        # A successful empty filtered first page is a point-in-time observation,
        # not global absence. Server rules/races still apply to the single POST.
        need(self.take("existing-pr", self.list_path(opened=True), listing=True) == [], "pull-request-exists")
        need(self.ref("base", "base-after") == base and self.ref("head", "head-after") == head, "branches-changed")
        self.repository("repository-after")
        return Prepared.parse(Prepared(self.target, base, head, {"aheadBy": count(c["ahead_by"]),
            "behindBy": count(c.get("behind_by")), "totalCommits": count(c.get("total_commits")),
            "reportedFiles": len(files), "coverage": "windowed", "files": summary}).value())


def prepare(target: Target, draft: Draft, exchange: Exchange) -> tuple[Prepared, dict]:
    Draft.parse(draft.value()); require(draft.matches(target))
    op = Operation(target, exchange)
    return op.prepare(), op.control


def create(prepared: Prepared, draft: Draft, exchange: Exchange, journal: Journal) -> dict:
    prepared = Prepared.parse(prepared.value()); Draft.parse(draft.value()); require(draft.matches(prepared.target))
    op = Operation(prepared.target, exchange)
    result = {"effect": "not-sent", "reason": "none", "claimed": False, "acknowledged": None, "observed": None, "control": _control()}
    try:
        need(op.prepare().value() == prepared.value(), "branches-changed")
        journal.create_intent(prepared.value())
        journal.claim()  # Durable before send; partial claims are never replayed.
        result.update(effect="potentially-applied", claimed=True)
        raw = op.take("create", op.base + "/pulls", body=canonical(draft.post_body(prepared.target)))
        ack = _ack(raw, prepared)
        # Preserve actual 201 evidence even when its durable recording fails.
        result.update(effect="acknowledged-unconfirmed", acknowledged=ack)
        journal.record(ack)
        observed = _observed(op.take("readback", op.base + "/pulls/" + ack["number"]), prepared)
        need(observed == ack, "target-changed")
        op.repository("final-repository")
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
    require(type(value) is dict and set(value) in ({"prepared", "claimed", "acknowledged"}, {"prepared", "claimed", "acknowledged", "closed"}))
    r = value; prepared = Prepared.parse(r["prepared"])
    require(type(r["claimed"]) is bool and (r["acknowledged"] is None or r["claimed"]))
    out = {"prepared": prepared.value(), "claimed": r["claimed"], "acknowledged": None if r["acknowledged"] is None else acknowledgement(r["acknowledged"], prepared)}
    if "closed" in r:
        from .github_pull_request_management import closed_observation
        require(out["acknowledged"] is not None)
        out["closed"] = closed_observation(r["closed"], out["acknowledged"])
    return out


def reconcile(record: dict, exchange: Exchange, *, journal=None) -> dict:
    original = pending_record(record)
    if original["acknowledged"] is not None:
        from .github_pull_request_management import reconcile_acknowledged
        return reconcile_acknowledged(original, exchange, journal)
    prepared = Prepared.parse(original["prepared"]); op = Operation(prepared.target, exchange)
    result = {"effect": "unresolved", "reason": "unresolved", "claimed": original["claimed"], "acknowledged": original["acknowledged"],
              "observed": None, "control": _control()}
    try:
        op.identity()
        ack = original["acknowledged"]
        if ack is not None:
            observed = _observed(op.take("readback", op.base + "/pulls/" + ack["number"]), prepared)
            need(observed == ack, "target-changed")
        else:
            rows = op.take("lookup", op.list_path(opened=False), listing=True)
            # No partial-page absence conclusion. Only an exact match in this
            # bounded window is useful, and still cannot establish attribution.
            matches = []
            for row in rows:
                try: matches.append(_observed(row, prepared))
                except (Refused, ValueError, TypeError, KeyError): pass
            need(len(matches) == 1, "unresolved")
            observed = _observed(op.take("readback", op.base + "/pulls/" + matches[0]["number"]), prepared)
            need(observed == matches[0], "target-changed")
        op.repository("repository-after")
        result.update(effect="created-observed" if ack is not None else "found-unattributed",
                      reason="none" if ack is not None else "unattributed", observed=observed)
    except (Refused, ReadFailure) as error: result["reason"] = error.reason
    except (ValueError, TypeError, KeyError, UnicodeError, OverflowError, RecursionError): result["reason"] = "response-invalid"
    result["control"] = op.control
    return result


def creation_result(value: object, prepared: Prepared, kind: str) -> dict:
    require(kind in ("create", "reconcile")); Prepared.parse(prepared.value())
    r = obj(value, {"effect", "reason", "claimed", "acknowledged", "observed", "control"})
    require(r["reason"] in REASONS and type(r["claimed"]) is bool); _check_control(r["control"])
    ack = None if r["acknowledged"] is None else acknowledgement(r["acknowledged"], prepared)
    seen = None if r["observed"] is None else acknowledgement(r["observed"], prepared)
    require(ack is None or r["claimed"])
    e = r["effect"]
    if e == "not-sent": require(kind == "create" and not r["claimed"] and ack is None and seen is None and r["reason"] != "none")
    elif e == "potentially-applied": require(kind == "create" and r["claimed"] and ack is None and seen is None and r["reason"] != "none")
    elif e == "acknowledged-unconfirmed": require(kind == "create" and r["claimed"] and ack is not None and seen is None and r["reason"] != "none")
    elif e == "created-observed": require(r["claimed"] and ack is not None and seen == ack and r["reason"] == "none")
    elif e == "closed-confirmed": require(kind == "reconcile" and r["claimed"] and ack is not None and seen == ack and r["reason"] == "none")
    elif e == "unresolved": require(kind == "reconcile" and seen is None and r["reason"] != "none")
    elif e == "found-unattributed": require(kind == "reconcile" and ack is None and seen is not None and r["reason"] == "unattributed")
    else: require(False)
    return dict(r)
