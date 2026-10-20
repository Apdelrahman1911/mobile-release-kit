"""Closed metadata GET roles on the original GitHub TLS/framing transport."""
from __future__ import annotations

import re

from . import github_activity as p
from .github_preflight import branch, _quote
from ._desktop_github_engine import _check_control
from ._github_connection_transport import _Budget, _ExchangeProfile, _ResponseRole, _control, _make_live_exchange


def _branch(encoded: str, *, head: bool = False) -> None:
    # Decode only this admitted ASCII query/path component, then require its
    # canonical spelling. No URL parsing, relative path or alternate host.
    p.require(len(encoded) <= 640 and re.fullmatch(r"(?:[A-Za-z0-9._~-]|%[0-9A-F]{2})+", encoded) is not None)
    raw = re.sub(r"%([0-9A-F]{2})", lambda m: chr(int(m[1], 16)), encoded)
    p.require(raw.isascii() and _quote(raw) == encoded)
    if head:
        owner, separator, raw = raw.partition(":")
        p.require(separator == ":"); p.login(owner)
    branch(raw)


def validate_endpoint(role: _ResponseRole, method: str, path: str) -> None:
    p.require(role in (_ResponseRole.ACTIVITY_OBJECT, _ResponseRole.ACTIVITY_LIST)
              and method == "GET" and type(path) is str and len(path) <= 1024)
    if path == "/user":
        p.require(role is _ResponseRole.ACTIVITY_OBJECT); return
    parts = path.split("/", 4)
    p.require(len(parts) >= 4 and parts[:2] == ["", "repos"])
    p.coordinate(parts[2] + "/" + parts[3])
    tail = parts[4] if len(parts) == 5 else ""
    is_list = False
    if tail.startswith("git/ref/heads/"):
        _branch(tail[len("git/ref/heads/"):])
    elif tail.startswith("pulls?state=open&sort=updated&direction=desc&per_page=30&page=1"):
        extra = tail[len("pulls?state=open&sort=updated&direction=desc&per_page=30&page=1"):]
        if extra:
            p.require(extra.startswith("&head=")); _branch(extra[6:], head=True)
        is_list = True
    elif tail.startswith("actions/runs?per_page=30&page=1"):
        extra = tail[len("actions/runs?per_page=30&page=1"):]
        if extra:
            p.require(extra.startswith("&branch=")); _branch(extra[8:])
    elif re.fullmatch(r"pulls/[1-9][0-9]{0,19}(?:/(?:files|reviews)\?per_page=30&page=1)?", tail):
        p._id(tail.split("/")[1]); is_list = "/" in tail[len("pulls/"):]
    elif re.fullmatch(r"commits/[0-9a-f]{40}/(?:status|check-runs)\?per_page=30&page=1", tail):
        pass
    elif re.fullmatch(r"actions/runs/[1-9][0-9]{0,19}/attempts/[1-9][0-9]{0,3}(?:/jobs\?per_page=30&page=1)?", tail):
        v = tail.split("/"); p._id(v[2]); p.attempt(int(v[4]))
    else:
        p.require(tail == "")
    p.require((role is _ResponseRole.ACTIVITY_LIST) == is_list)


def request_role(target: p.Target, selected: dict, request) -> _ResponseRole:
    p.require(request.method == "GET" and request.body is None)
    path = request.path
    is_list = "/pulls?" in path or "/files?" in path or "/reviews?" in path
    role = _ResponseRole.ACTIVITY_LIST if is_list else _ResponseRole.ACTIVITY_OBJECT
    validate_endpoint(role, "GET", path)
    base = "/repos/" + target.repository
    allowed = {"/user", base}
    if selected["kind"] == "overview":
        pulls = base + "/pulls?state=open&sort=updated&direction=desc&per_page=30&page=1"
        runs = base + "/actions/runs?per_page=30&page=1"
        if selected["branch"] is not None:
            allowed.add(base + "/git/ref/heads/" + _quote(selected["branch"]))
            pulls += "&head=" + _quote(target.repository.split("/")[0] + ":" + selected["branch"])
            runs += "&branch=" + _quote(selected["branch"])
        allowed.update((pulls, runs))
    elif selected["kind"] == "pull-request":
        pr = base + "/pulls/" + selected["number"]
        allowed.update((pr, pr + "/files?per_page=30&page=1", pr + "/reviews?per_page=30&page=1"))
        # Exact SHA comes only from the bounded selected-PR response. The fixed
        # core schedule checks it again; no caller-selected URL can reach here.
        if re.fullmatch(re.escape(base) + r"/commits/[0-9a-f]{40}/(?:status|check-runs)\?per_page=30&page=1", path):
            allowed.add(path)
    else:
        run = base + "/actions/runs/" + selected["runId"] + "/attempts/" + str(selected["attempt"])
        allowed.update((run, run + "/jobs?per_page=30&page=1"))
    p.require(path in allowed)
    return role


def make_exchange(target: p.Target, selected: dict, token: str, *, started: float, runtime_dir: str, budget: _Budget):
    p.Target.parse(target.value()); p.selection(selected)
    p.require(type(budget) is _Budget and budget.profile is _ExchangeProfile.ACTIVITY
              and budget.started == started and budget.end == started + 60.0)
    exchange = _make_live_exchange(token, started=started, runtime_dir=runtime_dir, api_version="2026-03-10",
                                  _profile=_ExchangeProfile.ACTIVITY, _setup_budget=budget)
    count = 0
    def send(request):
        nonlocal count
        budget.remaining(); p.need(count < p.MAX_REQUESTS, "response-limit")
        role = request_role(target, selected, request)
        count += 1
        result = exchange("GET", request.path, None, _role=role)
        send.control = dict(_check_control(result.control))
        budget.remaining()
        return result
    send.control = _control()
    return send
