"""Bounded PR/Actions metadata reads. No write, eligibility or execution authority.

The original Connection/Setup owner supplies identity and the transport. Private
upstream bodies are projected immediately; bodies, patches, logs, artifact URLs
and provider-supplied links never enter this result.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone

from .api._github_connection import _id, _text, _utc
from ._desktop_github_engine import _check_control
from ._github_connection_transport import ReadResult, ReadFailure, _control
from .github_preflight import HttpRequest, branch, _quote
from .github_repository_create import coordinate, hex_text, login

PROTOCOL = "mrk-github-activity/1"
MAX_ROWS = 30
MAX_REQUESTS = 8
MAX_RESULT_BYTES = 128 * 1024
REASONS = frozenset({"none", "invalid-input", "target-changed", "selection-changed", "unauthorized", "forbidden",
    "not-found-or-inaccessible", "rate-limited", "network-unavailable", "tls-failed", "response-invalid",
    "response-limit", "expired", "cancelled"})
STATUSES = ("queued", "in_progress", "completed", "waiting", "pending", "requested")
CONCLUSIONS = ("success", "failure", "neutral", "cancelled", "skipped", "timed_out", "action_required", "stale", "startup_failure")


def require(value: bool) -> None:
    if not value:
        raise ValueError("Invalid closed GitHub activity data")


def obj(value: object, keys: set[str]) -> dict:
    require(type(value) is dict and set(value) == keys)
    return value


def canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")


class Refused(ValueError):
    def __init__(self, reason: str):
        require(reason in REASONS and reason != "none")
        self.reason = reason
        super().__init__("The bounded GitHub activity read was unavailable")


def need(value: bool, reason: str = "response-invalid") -> None:
    if not value:
        raise Refused(reason)


def count(value: object) -> int:
    require(type(value) is int and 0 <= value <= 2**31 - 1)
    return value


def attempt(value: object) -> int:
    require(type(value) is int and 1 <= value <= 1000)
    return value


def text(value: object, maximum: int = 512) -> str:
    need(type(value) is str)
    need(len(value.encode("utf-8")) <= maximum, "response-limit")
    return _text(value, maximum)


def upstream_id(value: object) -> str:
    # REST numeric IDs never pass through a JS number or a coerced JSON string.
    require(type(value) is int)
    return _id(value, upstream=True)


@dataclass(frozen=True, slots=True)
class Target:
    project_binding: str
    repository: str
    account_id: str
    repository_id: str

    @classmethod
    def parse(cls, value: object) -> Target:
        r = obj(value, {"projectBinding", "repository", "accountId", "repositoryId"})
        return cls(hex_text(r["projectBinding"], 64), coordinate(r["repository"]), _id(r["accountId"]), _id(r["repositoryId"]))

    def value(self) -> dict:
        return {"projectBinding": self.project_binding, "repository": self.repository,
                "accountId": self.account_id, "repositoryId": self.repository_id}


def selection(value: object) -> dict:
    require(type(value) is dict)
    kind = value.get("kind")
    if kind == "overview":
        r = obj(value, {"kind", "branch"})
        if r["branch"] is not None:
            branch(r["branch"])
    elif kind == "pull-request":
        r = obj(value, {"kind", "number"}); _id(r["number"])
    else:
        r = obj(value, {"kind", "runId", "attempt"})
        require(kind == "workflow-run"); _id(r["runId"]); attempt(r["attempt"])
    return dict(r)


def _pull(value: object, target: Target) -> dict:
    need(type(value) is dict)
    base, head = value.get("base"), value.get("head")
    need(type(base) is dict and type(head) is dict and type(base.get("repo")) is dict)
    need(upstream_id(base["repo"].get("id")) == target.repository_id
         and coordinate(base["repo"].get("full_name")).lower() == target.repository.lower(), "target-changed")
    hr = head.get("repo")
    need(hr is None or type(hr) is dict)
    if hr is not None and coordinate(hr.get("full_name")).lower() == target.repository.lower():
        need(upstream_id(hr.get("id")) == target.repository_id, "target-changed")
    state = value.get("state")
    need(state in ("open", "closed") and type(value.get("draft")) is bool)
    return {"id": upstream_id(value.get("id")), "number": upstream_id(value.get("number")),
            "title": text(value.get("title")), "state": state, "draft": value["draft"],
            "headSha": hex_text(head.get("sha"), 40), "headBranch": text(head.get("ref"), 200),
            "headRepository": None if hr is None else coordinate(hr.get("full_name")),
            "baseSha": hex_text(base.get("sha"), 40), "baseBranch": text(base.get("ref"), 200),
            "updatedAt": _utc(value.get("updated_at"))}


def _run(value: object, target: Target) -> dict:
    need(type(value) is dict and type(value.get("repository")) is dict)
    repo = value["repository"]
    need(upstream_id(repo.get("id")) == target.repository_id
         and coordinate(repo.get("full_name")).lower() == target.repository.lower(), "target-changed")
    head_repo = value.get("head_repository")
    need(head_repo is None or type(head_repo) is dict)
    head_name = None if head_repo is None else coordinate(head_repo.get("full_name"))
    if head_name is not None and head_name.lower() == target.repository.lower():
        need(upstream_id(head_repo.get("id")) == target.repository_id, "target-changed")
    status, conclusion = value.get("status"), value.get("conclusion")
    need(status in STATUSES and (conclusion is None or conclusion in CONCLUSIONS)
         and (status == "completed" or conclusion is None))
    return {"id": upstream_id(value.get("id")), "attempt": attempt(value.get("run_attempt")),
            "name": text(value.get("name")), "status": status, "conclusion": conclusion,
            "headSha": hex_text(value.get("head_sha"), 40),
            "headBranch": None if value.get("head_branch") is None else text(value["head_branch"], 200),
            "headRepository": head_name,
            "event": text(value.get("event"), 64), "createdAt": _utc(value.get("created_at")),
            "updatedAt": _utc(value.get("updated_at"))}


def _file(v: object) -> dict:
    need(type(v) is dict and v.get("status") in ("added", "removed", "modified", "renamed", "copied", "changed", "unchanged"))
    return {"path": text(v.get("filename"), 1024), "change": v["status"],
            "additions": count(v.get("additions")), "deletions": count(v.get("deletions"))}


def _review(v: object) -> dict:
    need(type(v) is dict and v.get("state") in ("APPROVED", "CHANGES_REQUESTED", "COMMENTED", "DISMISSED", "PENDING"))
    user = v.get("user")
    need(user is None or type(user) is dict)
    return {"id": upstream_id(v.get("id")), "reviewer": None if user is None else login(user.get("login")),
            "state": v["state"], "commitSha": None if v.get("commit_id") is None else hex_text(v["commit_id"], 40),
            "submittedAt": None if v.get("submitted_at") is None else _utc(v["submitted_at"])}


def _status(v: object) -> dict:
    need(type(v) is dict and v.get("state") in ("error", "failure", "pending", "success"))
    return {"id": upstream_id(v.get("id")), "name": text(v.get("context")), "state": v["state"],
            "updatedAt": _utc(v.get("updated_at"))}


def _check(v: object, sha: str) -> dict:
    need(type(v) is dict and v.get("head_sha") == sha, "selection-changed")
    return _job(v)


def _job(v: object) -> dict:
    need(type(v) is dict and v.get("status") in STATUSES
         and (v.get("conclusion") is None or v["conclusion"] in CONCLUSIONS)
         and (v["status"] == "completed" or v.get("conclusion") is None))
    return {"id": upstream_id(v.get("id")), "name": text(v.get("name")),
            "status": v["status"], "conclusion": v.get("conclusion")}


def _rows(value: object, project, identity: str = "id") -> list:
    need(type(value) is list and len(value) <= MAX_ROWS, "response-limit")
    rows = [project(v) for v in value]
    need(len({r[identity] for r in rows}) == len(rows))
    return rows


def section(rows: list | None, *, reason: str = "none", total: int | None = None) -> dict:
    if rows is None:
        require(reason in ("forbidden", "not-found-or-inaccessible"))
        return {"state": "unavailable", "reason": reason, "coverage": "unknown", "total": None, "rows": []}
    if total is not None:
        count(total); need(total >= len(rows))
    return {"state": "read", "reason": "none", "coverage": "complete" if total == len(rows) else "windowed",
            "total": total, "rows": rows}


class Reader:
    """One finite schedule, not an HTTP/process owner or retry interface."""
    def __init__(self, target: Target, exchange):
        self.target = Target.parse(target.value())
        self.exchange = exchange
        self.control = _control()
        self.requests = 0

    def get(self, path: str, optional: bool = False):
        need(self.requests < MAX_REQUESTS, "response-limit")
        self.requests += 1
        try:
            result = self.exchange(HttpRequest("GET", path, None))
        except ReadFailure:
            # A post-read deadline/refusal must not discard an already captured
            # cooldown or credential rejection from the same fixed exchange.
            self.control = dict(_check_control(getattr(self.exchange, "control", self.control)))
            raise
        need(type(result) is ReadResult)
        self.control = dict(_check_control(result.control))
        o = obj(result.observation, {"status", "body", "failure"})
        reason = self.control["reason"]
        if o["failure"] != "none":
            need(o["failure"] in REASONS)
            raise Refused(o["failure"])
        if optional and o["status"] in (403, 404) and reason in ("forbidden", "not-found-or-inaccessible"):
            need(o["body"] is None)
            return None, reason
        if reason != "none":
            need(reason in REASONS)
            raise Refused(reason)
        need(type(o["status"]) is int and o["status"] == 200)
        return o["body"], "none"

    def read_section(self, path: str, project, *, key: str | None = None, total: int | None = None, identity: str = "id", sha: str | None = None) -> dict:
        body, reason = self.get(path, optional=True)
        if body is None:
            return section(None, reason=reason)
        if key is not None:
            need(type(body) is dict)
            if sha is not None:
                need(body.get("sha") == sha, "selection-changed")
            total = count(body.get("total_count")); body = body.get(key)
        return section(_rows(body, project, identity), total=total)

    def identity(self) -> None:
        user, _ = self.get("/user")
        need(type(user) is dict and upstream_id(user.get("id")) == self.target.account_id, "target-changed")
        self.repository_identity()

    def repository_identity(self) -> None:
        repo, _ = self.get("/repos/" + self.target.repository)
        need(type(repo) is dict and upstream_id(repo.get("id")) == self.target.repository_id
             and coordinate(repo.get("full_name")).lower() == self.target.repository.lower(), "target-changed")

    def overview(self, s: dict) -> dict:
        base = "/repos/" + self.target.repository
        branch_name = s["branch"]
        head = None
        def ref() -> str:
            v, _ = self.get(base + "/git/ref/heads/" + _quote(branch_name))
            need(type(v) is dict and v.get("ref") == "refs/heads/" + branch_name and type(v.get("object")) is dict)
            need(v["object"].get("type") == "commit")
            return hex_text(v["object"].get("sha"), 40)
        if branch_name is not None:
            head = ref()
        pulls = base + "/pulls?state=open&sort=updated&direction=desc&per_page=30&page=1"
        runs = base + "/actions/runs?per_page=30&page=1"
        if branch_name is not None:
            pulls += "&head=" + _quote(self.target.repository.split("/")[0] + ":" + branch_name)
            runs += "&branch=" + _quote(branch_name)
        prs = self.read_section(pulls, lambda r: _pull(r, self.target))
        workflows = self.read_section(runs, lambda r: _run(r, self.target), key="workflow_runs")
        if branch_name is not None:
            need(ref() == head, "selection-changed")
            need(all(p["headBranch"] == branch_name and p["headRepository"] is not None
                     and p["headRepository"].lower() == self.target.repository.lower() for p in prs["rows"]), "selection-changed")
            need(all(r["headBranch"] == branch_name and r["headRepository"] is not None
                     and r["headRepository"].lower() == self.target.repository.lower() for r in workflows["rows"]), "selection-changed")
        # Empty pages have no embedded repository IDs. Recheck the same
        # immutable repository so a delete/recreate cannot become empty success.
        self.repository_identity()
        return {"kind": "overview", "branchHead": head, "pullRequests": prs, "workflowRuns": workflows}

    def pull_request(self, s: dict) -> dict:
        base = "/repos/" + self.target.repository
        path = base + "/pulls/" + s["number"]
        body, _ = self.get(path)
        pr = _pull(body, self.target); need(pr["number"] == s["number"], "selection-changed")
        total = count(body.get("changed_files"))
        files = self.read_section(path + "/files?per_page=30&page=1", _file, total=total, identity="path")
        # GitHub's reviews endpoint is a chronological first page, NOT latest
        # review-per-person nor an overall approval/branch-protection verdict.
        reviews = self.read_section(path + "/reviews?per_page=30&page=1", _review)
        commit = base + "/commits/" + pr["headSha"]
        statuses = self.read_section(commit + "/status?per_page=30&page=1", _status, key="statuses", sha=pr["headSha"])
        checks = self.read_section(commit + "/check-runs?per_page=30&page=1", lambda v: _check(v, pr["headSha"]), key="check_runs")
        end, _ = self.get(path); after = _pull(end, self.target)
        need(all(after[k] == pr[k] for k in ("id", "number", "headSha", "headBranch", "headRepository", "baseSha", "baseBranch"))
             and count(end.get("changed_files")) == total, "selection-changed")
        return {"kind": "pull-request", "pullRequest": after, "changedFiles": files, "reviews": reviews,
                "commitStatuses": statuses, "checkRuns": checks, "headChecked": True}

    def workflow_run(self, s: dict) -> dict:
        path = "/repos/" + self.target.repository + "/actions/runs/" + s["runId"] + "/attempts/" + str(s["attempt"])
        body, _ = self.get(path); run = _run(body, self.target)
        need(run["id"] == s["runId"] and run["attempt"] == s["attempt"], "selection-changed")
        def job(v: object) -> dict:
            need(type(v) is dict and upstream_id(v.get("run_id")) == run["id"]
                 and attempt(v.get("run_attempt")) == run["attempt"] and v.get("head_sha") == run["headSha"], "selection-changed")
            return _job(v)
        jobs = self.read_section(path + "/jobs?per_page=30&page=1", job, key="jobs")
        last, _ = self.get(path); after = _run(last, self.target)
        need(all(after[k] == run[k] for k in ("id", "attempt", "headSha", "headBranch", "headRepository")), "selection-changed")
        return {"kind": "workflow-run", "run": after, "jobs": jobs, "attemptChecked": True}


def observe(target: Target, selected: dict, exchange, *, observed_at: str | None = None) -> dict:
    target = Target.parse(target.value()); selected = selection(selected)
    reader = Reader(target, exchange)
    result = {"schemaVersion": 1, "target": target.value(), "selection": selected,
              "observedAt": _utc(observed_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")),
              "reason": "none", "data": None, "control": _control()}
    try:
        reader.identity()
        read = {"overview": reader.overview, "pull-request": reader.pull_request, "workflow-run": reader.workflow_run}[selected["kind"]]
        result["data"] = read(selected)
        need(len(canonical(result)) <= MAX_RESULT_BYTES - 512, "response-limit")
    except (Refused, ReadFailure) as error:
        result["reason"] = error.reason; result["data"] = None
    except (ValueError, TypeError, KeyError, UnicodeError, OverflowError, RecursionError):
        result["reason"] = "response-invalid"; result["data"] = None
    result["control"] = dict(reader.control)
    # A positively observed identity mismatch retires this credential use in the
    # existing parent. A moving head is only a stale selection, not bad login.
    if result["reason"] in ("target-changed", "response-invalid"):
        result["control"]["reason"] = result["reason"]
    return result
