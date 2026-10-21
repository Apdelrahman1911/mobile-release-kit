"""Closed candidate-cleanup paths on the original GitHub HTTPS transport.

No URL, token source, provider edit ID, run search, Contents write or arbitrary
workflow input can enter this profile. Only Dispatch has one POST attempt.
"""
from __future__ import annotations

import re

from . import github_play_cleanup as p
from ._desktop_github_engine import _check_control, _decode_json
from ._github_connection_transport import _Budget, _ExchangeProfile, _ResponseRole, _control, _make_live_exchange


def validate_endpoint(role: _ResponseRole, method: str, path: str) -> None:
    p.require(type(path) is str and path.isascii() and len(path) <= 2048
        and role in (_ResponseRole.PLAY_CLEANUP_READ, _ResponseRole.PLAY_CLEANUP_CONFIG, _ResponseRole.PLAY_CLEANUP_WRITE))
    if path == "/user":
        p.require(method == "GET" and role is _ResponseRole.PLAY_CLEANUP_READ)
        return
    parts = path.split("/", 4)
    p.require(len(parts) >= 4 and parts[:2] == ["", "repos"])
    p.coordinate(parts[2] + "/" + parts[3])
    tail = "" if len(parts) == 4 else parts[4]
    if role is _ResponseRole.PLAY_CLEANUP_WRITE:
        match = re.fullmatch(r"actions/workflows/([1-9][0-9]{0,19})/dispatches", tail, re.ASCII)
        p.require(method == "POST" and match is not None)
        p._id(match[1])
        return
    p.require(method == "GET")
    sha = r"[0-9a-f]{40}"
    if role is _ResponseRole.PLAY_CLEANUP_CONFIG:
        p.require(re.fullmatch(r"contents/release/mobile-release\.json\?ref=" + sha, tail, re.ASCII) is not None)
        return
    component = r"(?:[A-Za-z0-9._~-]|%[0-9A-F]{2})+"
    p.require(tail in ("", "actions/workflows/mobile-candidate.yml",
        "branches/" + p.allocation.LEDGER_BRANCH + "/protection",
        "git/ref/heads/" + p.allocation.LEDGER_BRANCH)
        or re.fullmatch(r"branches/" + component, tail, re.ASCII) is not None
        or re.fullmatch(r"git/commits/" + sha, tail, re.ASCII) is not None
        or re.fullmatch(r"git/trees/" + sha + r"\?recursive=1", tail, re.ASCII) is not None
        or re.fullmatch(r"compare/" + sha + r"\.\.\." + sha + r"\?per_page=1&page=1", tail, re.ASCII) is not None
        or re.fullmatch(r"contents/" + component + r"(?:/" + component + r"){0,11}\?ref=" + sha, tail, re.ASCII) is not None)
    p.require(not tail.startswith("contents/release/mobile-release.json?"))


def validate_body(role: _ResponseRole, body: object) -> None:
    if role is not _ResponseRole.PLAY_CLEANUP_WRITE:
        p.require(body is None)
        return
    p.require(type(body) is bytes and 0 < len(body) <= 1024)
    value = p.obj(_decode_json(body, limit=1024, nodes=12, depth=3, exact=True), {"ref", "inputs"})
    p.branch(value["ref"])
    inputs = p.obj(value["inputs"], {"operation", "platform", "confirmation"})
    p.require(inputs["operation"] == "recover-play-edit" and inputs["platform"] in ("android", "both"))
    confirmation = inputs["confirmation"]
    p.require(type(confirmation) is str)
    parts = confirmation.split(":")
    p.require(len(parts) == 3 and parts[0] == "recover-play-edit")
    p.allocation._uuid(parts[1]); p.allocation._uuid(parts[2])
    p.require(p.canonical(value) == body)


def request_role(target: p.Target, source: p.Source | None, retained: p.Prepared | None,
                 kind: str, request) -> _ResponseRole:
    p.require(kind in ("prepare", "dispatch", "observe"))
    base = "/repos/" + target.repository
    p.require(request.path == "/user" or request.path == base or request.path.startswith(base + "/"))
    if request.method == "POST":
        p.require(kind == "dispatch" and retained is not None and retained.target == target
            and request.path == base + "/actions/workflows/" + retained.workflow_id + "/dispatches"
            and request.body == p.dispatch_body(retained))
        role = _ResponseRole.PLAY_CLEANUP_WRITE
    else:
        p.require(request.method == "GET")
        role = (_ResponseRole.PLAY_CLEANUP_CONFIG if request.path.startswith(base + "/contents/release/mobile-release.json?")
                else _ResponseRole.PLAY_CLEANUP_READ)
        if request.path.startswith(base + "/branches/"):
            allowed = {base + "/branches/" + p.allocation.LEDGER_BRANCH + "/protection"}
            if kind in ("prepare", "dispatch"):
                p.require(source is not None)
                allowed.add(base + "/branches/" + p._quote(source.branch))
            p.require(request.path in allowed)
        if kind == "dispatch":
            p.require(retained is not None)
            p.require(request.path in {"/user", base,
                base + "/branches/" + p._quote(retained.branch),
                base + "/actions/workflows/mobile-candidate.yml",
                base + "/branches/" + p.allocation.LEDGER_BRANCH + "/protection",
                base + "/git/ref/heads/" + p.allocation.LEDGER_BRANCH,
                base + "/contents/" + p.hosted.JOURNAL_PATH + "?ref=" + retained.checkpoint.commit})
        elif kind == "observe":
            # No source reads/run search/POST in a later journal observation.
            tail = request.path[len(base) + 1:] if request.path.startswith(base + "/") else ""
            p.require(request.path in {"/user", base} or tail.startswith(("contents/" + p.allocation.LEDGER_PATH + "?ref=",
                "contents/" + p.hosted.JOURNAL_PATH + "?ref=", "compare/"))
                or tail in {"branches/" + p.allocation.LEDGER_BRANCH + "/protection", "git/ref/heads/" + p.allocation.LEDGER_BRANCH})
    validate_endpoint(role, request.method, request.path)
    validate_body(role, request.body)
    return role


def make_exchange(target: p.Target, token: str, *, source: p.Source | None, retained: p.Prepared | None,
                  kind: str, started: float, runtime_dir: str, budget: _Budget, checkpoint):
    p.Target.parse(target.value())
    p.require(kind in ("prepare", "dispatch", "observe")
        and (source is not None) == (kind in ("prepare", "dispatch"))
        and (retained is not None) == (kind != "prepare"))
    if retained is not None:
        p.require(p.Prepared.parse(retained.value()).target == target)
    p.require(type(budget) is _Budget and budget.profile is _ExchangeProfile.PLAY_CLEANUP
        and budget.started == started and budget.end == started + 60.0 and budget.body_total_limit == p.TOTAL_BODY_LIMIT)
    exchange = _make_live_exchange(token, started=started, runtime_dir=runtime_dir, api_version="2026-03-10",
                                  _profile=_ExchangeProfile.PLAY_CLEANUP, _setup_budget=budget)
    count = 0
    write_claimed = False
    maximum = p.MAX_DISPATCH_REQUESTS if kind == "dispatch" else p.MAX_REQUESTS
    def send(request):
        nonlocal count, write_claimed
        checkpoint(); budget.remaining()
        p.need(count < maximum, "response-limit")
        role = request_role(target, source, retained, kind, request)
        if role is _ResponseRole.PLAY_CLEANUP_WRITE:
            p.need(not write_claimed, "previous-attempt")
            write_claimed = True
        count += 1
        result = exchange(request.method, request.path, request.body, _role=role)
        send.control = dict(_check_control(result.control))
        if role is _ResponseRole.PLAY_CLEANUP_WRITE:
            # Return actual empty-204 receipt before post-source/journal checks.
            # Original transport/worker/native closes are still required.
            return result
        checkpoint(); budget.remaining()
        return result
    send.control = _control()
    send.decode_checkpoint = budget.remaining  # SAME original clock, not a renewed parsing budget.
    return send
