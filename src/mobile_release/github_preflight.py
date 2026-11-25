"""Closed, non-publishing Desktop preflight policy.

This module does not own a credential, a clock, a process or dispatch consent.
The native application supplies the publisher-bound tooling identity and the
original private session. The only network seam is the finite action reader;
none of these DTOs authorizes a request, retry, Store operation or attestation.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Protocol

from ._desktop_github_engine import _check_control, _check_values
from ._github_connection_transport import ReadFailure, ReadResult, _control
from .api._github_connection import _account, _coordinate, _id, _read, _repository, _utc
from .api._github_setup import _resource
from .workflow_payloads import render_workflow_caller

PROTOCOL = "mrk-github-preflight/1"
API_VERSION = "2026-03-10"
WORKFLOW_PATH = ".github/workflows/mobile-preflight.yml"
WORKFLOW_NAME = "Mobile release preflight"
TOOLING_REPOSITORY = "Apdelrahman1911/mobile-release-kit"
MAX_CALLER_BYTES = 16 * 1024
MAX_RUNS = 100
MAX_JOBS = 100
MAX_REQUESTS = 6
MAX_REQUEST_BODY = 2048
_SHA = re.compile(r"[0-9a-f]{40}\Z", re.ASCII)
_DIGEST = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_MARKER = re.compile(r"[0-9a-f]{32}\Z", re.ASCII)
_BRANCH = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,199}\Z", re.ASCII)
_PLATFORMS = frozenset({"android", "ios", "both"})
_ACTIONS = frozenset({"prepare", "dispatch", "track", "reconcile"})
_STATUS = frozenset({"queued", "in_progress", "completed", "waiting", "pending", "requested"})
_CONCLUSIONS = frozenset({"success", "failure", "neutral", "cancelled", "skipped", "timed_out",
                          "action_required", "stale", "startup_failure"})
_JOB_NAMES = {"preflight / validate-platform": "input-guard", "preflight / android": "android",
              "preflight / ios": "ios"}
REASONS = frozenset({"none", "caller-mismatch", "workflow-unavailable", "source-changed",
                     "unresolved-run", "ambiguous-run", "run-changed", "jobs-incomplete",
                     "unauthorized", "forbidden", "not-found-or-inaccessible", "target-changed",
                     "rate-limited", "network-unavailable", "tls-failed", "response-invalid",
                     "response-limit", "expired", "cancelled"})


def _require(condition: bool) -> None:
    if not condition:
        raise ValueError("Invalid fixed GitHub preflight data")


def _object(value: object, keys: set[str]) -> dict[str, Any]:
    _require(type(value) is dict and set(value) == keys)
    return value  # type: ignore[return-value]


def _match(value: object, pattern: re.Pattern[str]) -> str:
    _require(type(value) is str and pattern.fullmatch(value) is not None)
    return value  # type: ignore[return-value]


def _upstream_id(value: object) -> str:
    _require(type(value) is int)
    return _id(value, upstream=True)


def branch(value: object) -> str:
    """Deliberately bounded ASCII branch subset; never accepts a tag/ref URL."""
    selected = _match(value, _BRANCH)
    parts = selected.split("/")
    _require(len(parts) <= 16 and not selected.startswith("refs/") and ".." not in selected)
    _require(all(part and not part.startswith(".") and not part.endswith((".", ".lock")) for part in parts))
    return selected


def _quote(value: str) -> str:
    # All callers supply an already admitted ASCII branch. No URL parser, host,
    # redirect or arbitrary path comes from a renderer or upstream response.
    return "".join(char if char.isascii() and (char.isalnum() or char in "-._~")
                   else "%" + format(ord(char), "02X") for char in value)


def display_title(marker: str) -> str:
    return "MRK Desktop preflight [" + _match(marker, _MARKER) + "]"


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

    @classmethod
    def parse(cls, value: object) -> Target:
        row = _object(value, {"projectBinding", "repository", "accountId", "repositoryId", "branch",
                              "toolingRepository", "toolingSha", "platform", "marker"})
        _require(row["toolingRepository"] == TOOLING_REPOSITORY)
        _require(type(row["platform"]) is str and row["platform"] in _PLATFORMS)
        return cls(_match(row["projectBinding"], _DIGEST), _coordinate(row["repository"]),
                   _id(row["accountId"]), _id(row["repositoryId"]), branch(row["branch"]),
                   _match(row["toolingSha"], _SHA), row["platform"], _match(row["marker"], _MARKER))

    def value(self) -> dict[str, str]:
        return {"projectBinding": self.project_binding, "repository": self.repository,
                "accountId": self.account_id, "repositoryId": self.repository_id, "branch": self.branch,
                "toolingRepository": TOOLING_REPOSITORY, "toolingSha": self.tooling_sha,
                "platform": self.platform, "marker": self.marker}


def canonical_caller(target: Target) -> bytes:
    # Same shipped source of truth as the local workflow preview/Apply journey.
    # The SHA is admitted by the native publisher binding, not this grammar.
    _, resource = _resource()
    return render_workflow_caller(resource["workflows"]["preflight"].encode("utf-8"),
                                  TOOLING_REPOSITORY, target.tooling_sha)


@dataclass(frozen=True, slots=True)
class Prepared:
    target: Target
    source_sha: str
    workflow_id: str
    caller_sha256: str
    observed_at: str

    @classmethod
    def parse(cls, value: object) -> Prepared:
        row = _object(value, {"target", "sourceSha", "workflowId", "workflowPath", "callerSha256",
                              "observedAt", "expectedRef", "displayTitle", "confirmation"})
        target = Target.parse(row["target"])
        result = cls(target, _match(row["sourceSha"], _SHA), _id(row["workflowId"]),
                     _match(row["callerSha256"], _DIGEST), _utc(row["observedAt"]))
        _require(row == result.value())
        _require(hashlib.sha256(canonical_caller(target)).hexdigest() == result.caller_sha256)
        return result

    def value(self) -> dict[str, Any]:
        return {"target": self.target.value(), "sourceSha": self.source_sha,
                "workflowId": self.workflow_id, "workflowPath": WORKFLOW_PATH,
                "callerSha256": self.caller_sha256, "observedAt": self.observed_at,
                "expectedRef": "refs/heads/" + self.target.branch,
                "displayTitle": display_title(self.target.marker),
                "confirmation": ("Run credential-free " + self.target.platform + " preflight for "
                                 + self.target.repository + " at " + self.source_sha
                                 + "? This may build project code, download dependencies, use GitHub-hosted minutes "
                                 "and upload diagnostic reports. The reviewed canonical workflow does not sign, upload to a Store or publish a release. "
                                 "GitHub dispatch uses this mutable branch, not an atomic commit lock. Authorized writers can replace its workflow after review; use a trusted protected branch.")}


@dataclass(frozen=True, slots=True, repr=False)
class Action:
    kind: str
    target: Target
    prepared: Prepared | None = None
    run_id: str | None = None

    @classmethod
    def parse(cls, value: object) -> Action:
        row = _object(value, {"kind", "target", "prepared", "runId"})
        _require(type(row["kind"]) is str and row["kind"] in _ACTIONS)
        target = Target.parse(row["target"])
        prepared = None if row["prepared"] is None else Prepared.parse(row["prepared"])
        run_id = None if row["runId"] is None else _id(row["runId"])
        _require((row["kind"] == "prepare") == (prepared is None))
        _require(prepared is None or prepared.target == target)
        _require((row["kind"] == "track") == (run_id is not None))
        return cls(row["kind"], target, prepared, run_id)

    def value(self) -> dict[str, Any]:
        return {"kind": self.kind, "target": self.target.value(),
                "prepared": None if self.prepared is None else self.prepared.value(), "runId": self.run_id}


@dataclass(frozen=True, slots=True, repr=False)
class HttpRequest:
    method: str
    path: str
    body: bytes | None


def dispatch_body(prepared: Prepared) -> bytes:
    value = {"ref": prepared.target.branch, "return_run_details": True, "inputs": {
        "platform": prepared.target.platform, "desktop_request": prepared.target.marker,
        "desktop_source_sha": prepared.source_sha, "desktop_expected_ref": "refs/heads/" + prepared.target.branch}}
    raw = json.dumps(value, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode("ascii")
    _require(len(raw) <= MAX_REQUEST_BODY)
    return raw


class Schedule:
    """Original one-use finite action schedule, separate from Connect/Refresh."""
    def __init__(self, action: Action) -> None:
        self.action = action
        self.steps: list[str] = []
        self.run_id = action.run_id

    def claim(self, step: str, reference: str | None = None) -> HttpRequest:
        schedules = {
            "prepare": ("account", "repository-before", "branch", "workflow", "caller", "repository-after"),
            "dispatch": ("account", "repository-before", "branch", "workflow", "dispatch"),
            "track": ("account", "repository-before", "attempt", "jobs", "repository-after"),
            "reconcile": ("account", "repository-before", "runs", "attempt", "jobs", "repository-after"),
        }
        schedule = schedules[self.action.kind]
        _require(len(self.steps) < len(schedule) <= MAX_REQUESTS and step == schedule[len(self.steps)])
        self.steps.append(step)  # A claimed logical request is never retried.
        target, prepared = self.action.target, self.action.prepared
        prefix = "/repos/" + target.repository
        if step == "account":
            path = "/user"
        elif step in {"repository-before", "repository-after"}:
            path = prefix
        elif step == "branch":
            path = prefix + "/git/ref/heads/" + _quote(target.branch)
        elif step == "workflow":
            path = prefix + "/actions/workflows/mobile-preflight.yml"
        elif step == "caller":
            path = prefix + "/contents/" + WORKFLOW_PATH + "?ref=" + _match(reference, _SHA)
        elif step == "dispatch":
            _require(prepared is not None and reference is None)
            return HttpRequest("POST", prefix + "/actions/workflows/" + prepared.workflow_id + "/dispatches",
                               dispatch_body(prepared))
        elif step == "runs":
            _require(prepared is not None)
            path = (prefix + "/actions/workflows/" + prepared.workflow_id + "/runs?event=workflow_dispatch&branch="
                    + _quote(target.branch) + "&head_sha=" + prepared.source_sha + "&per_page=100&page=1")
        elif step in {"attempt", "jobs"}:
            if step == "attempt" and self.action.kind == "reconcile":
                self.run_id = _id(reference)
            _require(self.run_id is not None)
            path = prefix + "/actions/runs/" + self.run_id + "/attempts/1"
            if step == "jobs":
                path += "/jobs?per_page=100&page=1"
        else:
            raise ValueError("Invalid fixed GitHub preflight schedule")
        _require(reference is None or step == "caller" or step == "attempt" and self.action.kind == "reconcile")
        return HttpRequest("GET", path, None)


class Reader(Protocol):
    def read(self, step: str, reference: str | None = None) -> ReadResult: ...


class Refused(ValueError):
    def __init__(self, reason: str) -> None:
        _require(reason in REASONS and reason != "none")
        self.reason = reason
        super().__init__("The fixed GitHub preflight observation was refused")


def _same(condition: bool, reason: str) -> None:
    if not condition:
        raise Refused(reason)


def _identity(body: dict[str, Any], target: Target) -> None:
    _upstream_id(body.get("id"))
    selected = _repository(body)
    _same(selected["id"] == target.repository_id
          and selected["fullName"].lower() == target.repository.lower(), "target-changed")
    _same(not selected["archived"], "workflow-unavailable")


def _source(body: dict[str, Any], target: Target) -> str:
    _same(body.get("ref") == "refs/heads/" + target.branch, "source-changed")
    obj = body.get("object")
    _require(type(obj) is dict)
    _same(obj.get("type") == "commit", "source-changed")
    return _match(obj.get("sha"), _SHA)


def _workflow(body: dict[str, Any]) -> str:
    _same(body.get("path") == WORKFLOW_PATH and body.get("state") == "active"
          and body.get("name") == WORKFLOW_NAME, "workflow-unavailable")
    return _upstream_id(body.get("id"))


def _caller(body: dict[str, Any], target: Target) -> bytes:
    _same(body.get("type") == "file" and body.get("path") == WORKFLOW_PATH
          and body.get("encoding") == "base64", "caller-mismatch")
    size, text = body.get("size"), body.get("content")
    _require(type(size) is int and 0 < size <= MAX_CALLER_BYTES
             and type(text) is str and len(text) <= 24 * 1024)
    _require(re.fullmatch(r"[A-Za-z0-9+/=\n]*", text, re.ASCII) is not None)
    try:
        decoded = base64.b64decode(text.replace("\n", ""), validate=True)
    except ValueError:
        raise Refused("caller-mismatch") from None
    expected = canonical_caller(target)
    _same(len(decoded) == size and decoded == expected, "caller-mismatch")
    # Git's SHA-1 blob identifier is API consistency DATA, not an authenticity or
    # cryptographic-security claim. The canonical equality above is authoritative.
    blob = hashlib.sha1(b"blob " + str(size).encode("ascii") + b"\0" + decoded, usedforsecurity=False).hexdigest()
    _same(body.get("sha") == blob, "caller-mismatch")
    return decoded


def dispatched_run(body: dict[str, Any], prepared: Prepared) -> str:
    run_id = _upstream_id(body.get("workflow_run_id"))
    prefix = prepared.target.repository
    _require(body.get("run_url") == "https://api.github.com/repos/" + prefix + "/actions/runs/" + run_id)
    _require(body.get("html_url") == "https://github.com/" + prefix + "/actions/runs/" + run_id)
    return run_id  # Candidate exact identity, NOT an observed run or success.


def _run_identity(body: dict[str, Any], prepared: Prepared, run_id: str | None = None) -> str:
    target = prepared.target
    actual = _upstream_id(body.get("id"))
    _same(run_id is None or actual == run_id, "run-changed")
    repository, head_repository = body.get("repository"), body.get("head_repository")
    _require(type(repository) is dict and type(head_repository) is dict)
    for repo in (repository, head_repository):
        _same(_upstream_id(repo.get("id")) == target.repository_id
              and repo.get("full_name") == target.repository, "run-changed")
    for name in ("actor", "triggering_actor"):
        actor = body.get(name)
        _require(type(actor) is dict)
        _same(_upstream_id(actor.get("id")) == target.account_id, "run-changed")
    _same(type(body.get("run_attempt")) is int and body["run_attempt"] == 1
          and _upstream_id(body.get("workflow_id")) == prepared.workflow_id
          and body.get("path") == WORKFLOW_PATH and body.get("name") == WORKFLOW_NAME
          and body.get("head_sha") == prepared.source_sha and body.get("head_branch") == target.branch
          and body.get("event") == "workflow_dispatch"
          and body.get("display_title") == display_title(target.marker), "run-changed")
    _same(body.get("html_url") == "https://github.com/" + target.repository + "/actions/runs/" + actual,
          "run-changed")
    return actual


def _status(body: dict[str, Any]) -> tuple[str, str | None]:
    status, conclusion = body.get("status"), body.get("conclusion")
    _require(type(status) is str and status in _STATUS)
    _require((status == "completed" and type(conclusion) is str and conclusion in _CONCLUSIONS)
             or (status != "completed" and conclusion is None))
    return status, conclusion


def reconcile_run(body: dict[str, Any], prepared: Prepared) -> str:
    count, rows = body.get("total_count"), body.get("workflow_runs")
    _same(type(count) is int and 0 <= count <= MAX_RUNS
          and type(rows) is list and len(rows) == count, "unresolved-run")
    ids: set[str] = set()
    matches: list[str] = []
    for row in rows:
        _require(type(row) is dict)
        identity = _upstream_id(row.get("id"))
        _same(identity not in ids, "ambiguous-run")
        ids.add(identity)
        # A different title is an unrelated run, not a weak substring match.
        # A same-title invalid identity is explicitly unresolved, never skipped
        # in favor of a different plausible record.
        if row.get("display_title") == display_title(prepared.target.marker):
            matches.append(_run_identity(row, prepared))
    _same(bool(matches), "unresolved-run")
    _same(len(matches) == 1, "ambiguous-run")
    return matches[0]


def observed_run(body: dict[str, Any], jobs: dict[str, Any], prepared: Prepared, run_id: str,
                 observed_at: str) -> dict[str, Any]:
    _run_identity(body, prepared, run_id)
    status, conclusion = _status(body)
    count, rows = jobs.get("total_count"), jobs.get("jobs")
    _same(type(count) is int and 0 <= count <= MAX_JOBS and type(rows) is list and len(rows) == count,
          "jobs-incomplete")
    selected: list[dict[str, Any]] = []
    seen: set[str] = set()
    names: set[str] = set()
    for row in rows:
        _require(type(row) is dict)
        identity = _upstream_id(row.get("id"))
        name = row.get("name")
        _same(identity not in seen and type(name) is str and name in _JOB_NAMES and name not in names,
              "jobs-incomplete")
        seen.add(identity)
        names.add(name)
        _same(_upstream_id(row.get("run_id")) == run_id
              and type(row.get("run_attempt")) is int and row["run_attempt"] == 1
              and row.get("head_sha") == prepared.source_sha, "run-changed")
        job_status, job_conclusion = _status(row)
        selected.append({"id": identity, "kind": _JOB_NAMES[name], "status": job_status,
                         "conclusion": job_conclusion})
    if status == "completed" and conclusion == "success":
        required = {"input-guard"} | ({"android", "ios"} if prepared.target.platform == "both" else {prepared.target.platform})
        _same(all(any(row["kind"] == kind and row["status"] == "completed" and row["conclusion"] == "success"
                      for row in selected) for kind in required), "jobs-incomplete")
    return {"id": run_id, "attempt": 1, "status": status, "conclusion": conclusion,
            "observedAt": _utc(observed_at), "jobs": selected,
            "url": "https://github.com/" + prepared.target.repository + "/actions/runs/" + run_id,
            "assurance": "github-workflow-observation-not-release-evidence"}


def execute(action: Action, reader: Reader, *, observed_at: str) -> dict[str, Any]:
    """One finite action. A Reader exception can never cause a second POST."""
    _utc(observed_at)
    control = _control()
    result: dict[str, Any] = {"schemaVersion": 1, "action": action.kind, "reason": "none",
                              "effect": "not-sent" if action.kind == "dispatch" else "none",
                              "prepared": None, "runId": None, "run": None, "control": control}

    def take(step: str, reference: str | None = None) -> dict[str, Any]:
        nonlocal control
        if step == "dispatch":
            # Conservative entry mark precedes even connection setup. This is
            # not fabricated proof a byte was sent, only loss of no-send proof.
            result["effect"] = "potentially-applied"
        reply = reader.read(step, reference)
        _require(type(reply) is ReadResult)
        control = _check_control(reply.control)
        _check_values(reply.observation, nodes=20_000, depth=24)
        body, reason = _read(reply.observation)
        if control["reason"] != "none":
            raise Refused(control["reason"])
        if body is None:
            raise Refused(reason)
        return body

    try:
        account_body = take("account")
        _upstream_id(account_body.get("id"))
        account = _account(account_body)
        _same(account["id"] == action.target.account_id, "target-changed")
        _identity(take("repository-before"), action.target)
        if action.kind in {"prepare", "dispatch"}:
            source = _source(take("branch"), action.target)
            workflow = _workflow(take("workflow"))
            if action.kind == "prepare":
                caller = _caller(take("caller", source), action.target)
                _identity(take("repository-after"), action.target)
                result["prepared"] = Prepared(action.target, source, workflow,
                                               hashlib.sha256(caller).hexdigest(), observed_at).value()
            else:
                _require(action.prepared is not None)
                _same(source == action.prepared.source_sha, "source-changed")
                _same(workflow == action.prepared.workflow_id, "workflow-unavailable")
                result["runId"] = dispatched_run(take("dispatch"), action.prepared)
                result["effect"] = "accepted"
        else:
            _require(action.prepared is not None)
            run_id = (reconcile_run(take("runs"), action.prepared) if action.kind == "reconcile" else action.run_id)
            _require(run_id is not None)
            run = take("attempt", run_id if action.kind == "reconcile" else None)
            _run_identity(run, action.prepared, run_id)
            jobs = take("jobs")
            selected = observed_run(run, jobs, action.prepared, run_id, observed_at)
            _identity(take("repository-after"), action.target)
            result["runId"], result["run"] = run_id, selected
    except Refused as error:
        result["reason"] = error.reason
    except ReadFailure as error:
        result["reason"] = error.reason
    except (ValueError, TypeError, KeyError, UnicodeError, OverflowError):
        result["reason"] = "response-invalid"
    result["control"] = control
    return result


def _make_live_reader(action: Action, token: str, *, started: float, runtime_dir: str) -> Reader:
    """Private helper-only entry; never called by a DTO/parser or pure test."""
    from ._github_connection_transport import _make_live_exchange

    schedule = Schedule(action)
    exchange = _make_live_exchange(token, started=started, runtime_dir=runtime_dir, api_version=API_VERSION)

    class FixedReader:
        def read(self, step: str, reference: str | None = None) -> ReadResult:
            request = schedule.claim(step, reference)
            return exchange(request.method, request.path, request.body)

    return FixedReader()
