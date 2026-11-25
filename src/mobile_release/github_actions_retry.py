"""One explicitly approved GitHub failed/dependent-job retry, never a scheduler.

The provider has no expected-attempt precondition or idempotency key. A review
binds the immutable run/workflow/source and shows the observed attempt; it does
not pretend that GitHub atomically executes that attempt. A durable claim is
never replayed. Readback is observation, not workflow success or attribution.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Protocol

from . import github_activity as activity
from ._desktop_github_engine import _check_control
from ._github_connection_transport import ReadFailure, ReadResult, _control
from .api._github_connection import _id, _utc
from .github_preflight import HttpRequest
from .github_repository_create import coordinate, hex_text, login, obj, require

PROTOCOL = "mrk-github-actions-retry/1"
MAX_REQUESTS = 8
MAX_RECORDS = 32
MAX_RECORD_BYTES = 4096
MAX_RESULT_BYTES = 192 * 1024
BODY_LIMIT = 256 * 1024
TOTAL_BODY_LIMIT = 2 * 1024 * 1024
POST_BODY = b'{"enable_debug_logging":false}'
REASONS = activity.REASONS | frozenset({"not-retryable", "permission-unconfirmed", "journal-unavailable",
    "previous-attempt", "journal-full", "unresolved", "unattributed"})


def canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


class Refused(ValueError):
    def __init__(self, reason: str):
        require(reason in REASONS and reason != "none")
        self.reason = reason
        super().__init__("The original GitHub Actions retry is unavailable")


def need(value: bool, reason: str = "response-invalid") -> None:
    if not value:
        raise Refused(reason)


@dataclass(frozen=True, slots=True)
class Target:
    scope: dict
    selection: dict | None

    @classmethod
    def parse(cls, value: object) -> Target:
        r = obj(value, {"scope", "selection"})
        scope = activity.Target.parse(r["scope"]).value()
        selected = r["selection"]
        if selected is not None:
            selected = obj(selected, {"runId", "attempt", "headSha", "marker"})
            _id(selected["runId"]); activity.attempt(selected["attempt"])
            hex_text(selected["headSha"], 40); hex_text(selected["marker"], 32)
        return cls(scope, None if selected is None else dict(selected))

    def value(self) -> dict:
        return {"scope": dict(self.scope), "selection": None if self.selection is None else dict(self.selection)}

    @property
    def repository(self) -> str:
        return self.scope["repository"]

    def same_scope(self, other: Target) -> bool:
        return all(self.scope[k] == other.scope[k] for k in ("projectBinding", "accountId", "repositoryId")) \
            and self.repository.lower() == other.repository.lower()


RUN_KEYS = frozenset({"id", "attempt", "name", "workflowId", "workflowPath", "status", "conclusion", "headSha",
    "headBranch", "headRepository", "headRepositoryId", "event", "createdAt", "updatedAt"})


def run_data(value: object) -> dict:
    r = obj(value, RUN_KEYS)
    _id(r["id"]); _id(r["workflowId"]); activity.attempt(r["attempt"])
    activity.text(r["name"]); activity.text(r["workflowPath"])
    require(bool(r["workflowPath"]))
    require(r["status"] in activity.STATUSES and (r["conclusion"] is None or r["conclusion"] in activity.CONCLUSIONS)
            and (r["status"] == "completed" or r["conclusion"] is None))
    hex_text(r["headSha"], 40)
    if r["headBranch"] is not None: activity.text(r["headBranch"], 200)
    require((r["headRepository"] is None) == (r["headRepositoryId"] is None))
    if r["headRepository"] is not None:
        coordinate(r["headRepository"]); _id(r["headRepositoryId"])
    activity.text(r["event"], 64); _utc(r["createdAt"]); _utc(r["updatedAt"])
    return dict(r)


def _run(value: object, target: Target) -> dict:
    base = activity._run(value, activity.Target.parse(target.scope))
    head = value.get("head_repository")
    base.update(workflowId=activity.upstream_id(value.get("workflow_id")),
                workflowPath=activity.text(value.get("path")),
                headRepositoryId=None if head is None else activity.upstream_id(head.get("id")))
    return run_data(base)


def confirmation(target: Target, run: dict) -> str:
    return ("Retry failed and dependent jobs for run " + run["id"] + " in " + target.repository
            + "? Observed attempt " + str(run["attempt"]) + ". GitHub may select its latest attempt when it receives this request. "
            "This approval is for the same immutable run, workflow " + run["workflowId"] + " and source " + run["headSha"]
            + ", not another run. Dependent jobs may run again, and the workflow may publish or change external services "
            "using its existing privileges. Stopping cannot undo an accepted request.")


@dataclass(frozen=True, slots=True)
class Prepared:
    target: Target
    account_login: str
    run: dict

    def value(self) -> dict:
        return {"target": self.target.value(), "accountLogin": self.account_login, "run": dict(self.run),
                "retryPermission": "not-proven", "confirmation": confirmation(self.target, self.run)}

    @classmethod
    def parse(cls, value: object) -> Prepared:
        r = obj(value, {"target", "accountLogin", "run", "retryPermission", "confirmation"})
        target = Target.parse(r["target"]); require(target.selection is not None)
        run = run_data(r["run"])
        require(run["id"] == target.selection["runId"] and run["attempt"] == target.selection["attempt"]
                and run["headSha"] == target.selection["headSha"] and run["status"] == "completed"
                and run["conclusion"] in ("failure", "timed_out"))
        if run["headRepository"] is not None and run["headRepository"].lower() == target.repository.lower():
            require(run["headRepositoryId"] == target.scope["repositoryId"])
        result = cls(target, login(r["accountLogin"]), run)
        require(r == result.value() and len(canonical(r)) <= MAX_RECORD_BYTES - 128)
        return result


def digest(prepared: Prepared) -> str:
    return hashlib.sha256(canonical(Prepared.parse(prepared.value()).value())).hexdigest()


def same_run_source(run: dict, prepared: Prepared) -> bool:
    # Workflow name/path/event are reviewed source metadata, never filesystem
    # paths or a request to use a different workflow. An advanced attempt may
    # change timing/status, but cannot silently change this reviewed source.
    return all(run[k] == prepared.run[k] for k in ("id", "workflowId", "workflowPath", "name", "event", "headSha",
        "headBranch", "headRepository", "headRepositoryId", "createdAt")) and run["attempt"] >= prepared.run["attempt"]


class Exchange(Protocol):
    def __call__(self, request: HttpRequest) -> ReadResult: ...


class Journal(Protocol):
    def create_intent(self, value: dict) -> None: ...
    def claim(self) -> None: ...
    def record_accepted(self) -> None: ...


class Operation:
    def __init__(self, target: Target, exchange: Exchange):
        self.target = Target.parse(target.value()); self.exchange = exchange
        self.steps: set[str] = set(); self.bytes = 0; self.control = _control()
        self.base = "/repos/" + self.target.repository

    def take(self, step: str, path: str, *, post: bool = False):
        need(step not in self.steps and len(self.steps) < MAX_REQUESTS, "response-limit")
        self.steps.add(step)
        try:
            reply = self.exchange(HttpRequest("POST" if post else "GET", path, POST_BODY if post else None))
        except ReadFailure:
            self.control = dict(_check_control(getattr(self.exchange, "control", self.control)))
            raise
        need(type(reply) is ReadResult)
        self.control = dict(_check_control(reply.control)); r = obj(reply.observation, {"status", "body", "failure"})
        if self.control["reason"] != "none": raise Refused(self.control["reason"])
        if r["failure"] != "none": raise Refused(r["failure"])
        need(type(r["status"]) is int)
        if r["status"] != (201 if post else 200):
            raise Refused({401: "unauthorized", 403: "forbidden", 404: "not-found-or-inaccessible", 409: "selection-changed",
                422: "not-retryable", 429: "rate-limited"}.get(r["status"], "network-unavailable" if r["status"] >= 500 else "response-invalid"))
        if post:
            need(r["body"] is None)
            return None
        need(type(r["body"]) is dict)
        size = len(canonical(r["body"])); self.bytes += size
        need(size <= BODY_LIMIT and self.bytes <= TOTAL_BODY_LIMIT, "response-limit")
        return r["body"]

    def repository(self, step: str) -> None:
        r = self.take(step, self.base)
        need(activity.upstream_id(r.get("id")) == self.target.scope["repositoryId"]
             and coordinate(r.get("full_name")).lower() == self.target.repository.lower()
             and r.get("archived") is False and r.get("disabled") is False, "target-changed")
        permissions = r.get("permissions")
        # A write bit cannot prove fine-grained Actions-write permission, SSO,
        # environment approval or the actor privileges of the original run.
        need(type(permissions) is dict and permissions.get("push") is True, "permission-unconfirmed")

    def identity(self) -> str:
        user = self.take("account", "/user")
        need(activity.upstream_id(user.get("id")) == self.target.scope["accountId"] and user.get("type") == "User", "target-changed")
        name = login(user.get("login"))
        self.repository("repository")
        return name

    def latest(self, step: str) -> dict:
        require(self.target.selection is not None)
        run = _run(self.take(step, self.base + "/actions/runs/" + self.target.selection["runId"]), self.target)
        need(run["id"] == self.target.selection["runId"], "selection-changed")
        return run

    def prepare(self) -> Prepared:
        name = self.identity(); run = self.latest("run")
        need(run["attempt"] == self.target.selection["attempt"] and run["headSha"] == self.target.selection["headSha"], "selection-changed")
        need(run["status"] == "completed" and run["conclusion"] in ("failure", "timed_out"), "not-retryable")
        return Prepared.parse(Prepared(self.target, name, run).value())


def prepare(target: Target, exchange: Exchange) -> tuple[Prepared, dict]:
    op = Operation(target, exchange)
    return op.prepare(), op.control


def retry(prepared: Prepared, exchange: Exchange, journal: Journal) -> dict:
    prepared = Prepared.parse(prepared.value()); op = Operation(prepared.target, exchange)
    result = {"effect": "not-sent", "reason": "none", "claimed": False, "acknowledged": False, "observed": None, "control": _control()}
    try:
        need(op.prepare().value() == prepared.value(), "selection-changed")
        journal.create_intent(prepared.value())
        # Recheck current provider selection immediately before the durable
        # send claim. There is still no server CAS: the confirmation says so.
        need(op.latest("run-before-send") == prepared.run, "selection-changed")
        journal.claim()
        result.update(effect="potentially-applied", claimed=True)
        op.take("retry", op.base + "/actions/runs/" + prepared.run["id"] + "/rerun-failed-jobs", post=True)
        result.update(effect="accepted-unconfirmed", acknowledged=True)
        journal.record_accepted()
        observed = op.latest("run-after")
        need(same_run_source(observed, prepared), "selection-changed")
        op.repository("repository-after")
        result.update(effect="accepted", observed=observed)
    except (Refused, activity.Refused, ReadFailure) as error:
        result["reason"] = error.reason
    except (ValueError, TypeError, KeyError, UnicodeError, OverflowError, RecursionError):
        result["reason"] = "response-invalid"
    except OSError:
        result["reason"] = "journal-unavailable"
    result["control"] = dict(op.control)
    return result


def pending_record(value: object) -> dict:
    r = obj(value, {"prepared", "claimed", "acknowledged"})
    prepared = Prepared.parse(r["prepared"])
    require(type(r["claimed"]) is bool and type(r["acknowledged"]) is bool and (not r["acknowledged"] or r["claimed"]))
    return {"prepared": prepared.value(), "claimed": r["claimed"], "acknowledged": r["acknowledged"]}


def reconcile(record: dict, exchange: Exchange) -> dict:
    original = pending_record(record); prepared = Prepared.parse(original["prepared"]); op = Operation(prepared.target, exchange)
    result = {"effect": "unresolved", "reason": "unresolved", "claimed": original["claimed"],
              "acknowledged": original["acknowledged"], "observed": None, "control": _control()}
    try:
        op.identity(); observed = op.latest("run")
        need(same_run_source(observed, prepared), "selection-changed")
        op.repository("repository-after")
        if original["acknowledged"]:
            result.update(effect="accepted", reason="none", observed=observed)
        elif observed["attempt"] > prepared.run["attempt"]:
            result.update(effect="advanced-unattributed", reason="unattributed", observed=observed)
        # No changed attempt is negative evidence of a send. An advanced
        # attempt is not proof that this original request caused it either.
    except (Refused, activity.Refused, ReadFailure) as error:
        result["reason"] = error.reason
    except (ValueError, TypeError, KeyError, UnicodeError, OverflowError, RecursionError):
        result["reason"] = "response-invalid"
    result["control"] = dict(op.control)
    return result


def action_result(value: object, prepared: Prepared, kind: str) -> dict:
    require(kind in ("retry", "reconcile")); Prepared.parse(prepared.value())
    r = obj(value, {"effect", "reason", "claimed", "acknowledged", "observed", "control"})
    require(r["reason"] in REASONS and type(r["claimed"]) is bool and type(r["acknowledged"]) is bool
            and (not r["acknowledged"] or r["claimed"]))
    _check_control(r["control"])
    seen = None if r["observed"] is None else run_data(r["observed"])
    require(seen is None or same_run_source(seen, prepared))
    e = r["effect"]
    if e == "not-sent": require(kind == "retry" and not r["claimed"] and not r["acknowledged"] and seen is None and r["reason"] != "none")
    elif e == "potentially-applied": require(kind == "retry" and r["claimed"] and not r["acknowledged"] and seen is None and r["reason"] != "none")
    elif e == "accepted-unconfirmed": require(kind == "retry" and r["claimed"] and r["acknowledged"] and seen is None and r["reason"] != "none")
    elif e == "accepted": require(r["claimed"] and r["acknowledged"] and seen is not None and r["reason"] == "none")
    elif e == "unresolved": require(kind == "reconcile" and seen is None and r["reason"] != "none")
    elif e == "advanced-unattributed": require(kind == "reconcile" and not r["acknowledged"] and seen is not None
        and seen["attempt"] > prepared.run["attempt"] and r["reason"] == "unattributed")
    else: require(False)
    return dict(r)
