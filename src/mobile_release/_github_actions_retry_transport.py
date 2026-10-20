"""Only latest-run reads and rerun-failed-jobs on the original TLS transport."""
from __future__ import annotations

import re

from . import github_actions_retry as p
from ._desktop_github_engine import _check_control
from ._github_connection_transport import _Budget, _ExchangeProfile, _ResponseRole, _control, _make_live_exchange


def validate_endpoint(role: _ResponseRole, method: str, path: str) -> None:
    p.require(type(path) is str and len(path) <= 1024
              and role in (_ResponseRole.ACTIONS_RETRY_READ, _ResponseRole.ACTIONS_RETRY_WRITE))
    if path == "/user":
        p.require(method == "GET" and role is _ResponseRole.ACTIONS_RETRY_READ); return
    parts = path.split("/", 4)
    p.require(len(parts) >= 4 and parts[:2] == ["", "repos"])
    p.coordinate(parts[2] + "/" + parts[3]); tail = "" if len(parts) == 4 else parts[4]
    if role is _ResponseRole.ACTIONS_RETRY_WRITE:
        match = re.fullmatch(r"actions/runs/([1-9][0-9]{0,19})/rerun-failed-jobs", tail)
        p.require(method == "POST" and match is not None); p._id(match[1]); return
    p.require(method == "GET")
    if tail:
        match = re.fullmatch(r"actions/runs/([1-9][0-9]{0,19})", tail)
        p.require(match is not None); p._id(match[1])


def validate_body(role: _ResponseRole, body: object) -> None:
    p.require(body == p.POST_BODY and type(body) is bytes if role is _ResponseRole.ACTIONS_RETRY_WRITE else body is None)


def request_role(target: p.Target, request) -> _ResponseRole:
    base = "/repos/" + target.repository
    if request.method == "POST":
        p.require(target.selection is not None and request.path == base + "/actions/runs/" + target.selection["runId"] + "/rerun-failed-jobs")
        role = _ResponseRole.ACTIONS_RETRY_WRITE
    else:
        p.require(request.method == "GET")
        allowed = {"/user", base}
        if target.selection is not None:
            allowed.add(base + "/actions/runs/" + target.selection["runId"])
        p.require(request.path in allowed)
        role = _ResponseRole.ACTIONS_RETRY_READ
    validate_endpoint(role, request.method, request.path); validate_body(role, request.body)
    return role


def make_exchange(target: p.Target, token: str, *, started: float, runtime_dir: str, budget: _Budget, checkpoint):
    p.Target.parse(target.value())
    p.require(type(budget) is _Budget and budget.profile is _ExchangeProfile.ACTIONS_RETRY
              and budget.started == started and budget.end == started + 60.0 and budget.body_total_limit == p.TOTAL_BODY_LIMIT)
    exchange = _make_live_exchange(token, started=started, runtime_dir=runtime_dir, api_version="2026-03-10",
                                  _profile=_ExchangeProfile.ACTIONS_RETRY, _setup_budget=budget)
    count = 0; write_claimed = False
    def send(request):
        nonlocal count, write_claimed
        checkpoint(); budget.remaining(); p.need(count < p.MAX_REQUESTS, "response-limit")
        role = request_role(target, request)
        if role is _ResponseRole.ACTIONS_RETRY_WRITE:
            p.need(not write_claimed, "previous-attempt")
            write_claimed = True  # No repeat even when the original call throws.
        count += 1
        result = exchange(request.method, request.path, request.body, _role=role)
        send.control = dict(_check_control(result.control))
        if role is _ResponseRole.ACTIONS_RETRY_WRITE:
            # Preserve the actual accepted response before later custody/time
            # checks. The caller records it before attempting any next read.
            return result
        checkpoint(); budget.remaining()
        return result
    send.control = _control()
    return send
