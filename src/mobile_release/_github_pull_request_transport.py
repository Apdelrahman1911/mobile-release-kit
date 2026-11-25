"""Closed PR roles on the existing credential/TLS/framing/close implementation."""
from __future__ import annotations

import re

from . import github_pull_request as p
from ._desktop_github_engine import _check_control, _decode_json
from ._github_activity_transport import _branch
from ._github_connection_transport import _Budget, _ExchangeProfile, _ResponseRole, _control, _make_live_exchange


def validate_endpoint(role: _ResponseRole, method: str, path: str) -> None:
    p.require(type(path) is str and len(path) <= 1024 and role in
              (_ResponseRole.PULL_REQUEST_OBJECT, _ResponseRole.PULL_REQUEST_LIST, _ResponseRole.PULL_REQUEST_WRITE))
    if path == "/user":
        p.require(method == "GET" and role is _ResponseRole.PULL_REQUEST_OBJECT); return
    parts = path.split("/", 4)
    p.require(len(parts) >= 4 and parts[:2] == ["", "repos"])
    p.coordinate(parts[2] + "/" + parts[3]); tail = "" if len(parts) == 4 else parts[4]
    if role is _ResponseRole.PULL_REQUEST_WRITE:
        p.require(method == "POST" and tail == "pulls"); return
    p.require(method == "GET")
    if role is _ResponseRole.PULL_REQUEST_LIST:
        m = re.fullmatch(r"pulls\?state=(?:open|all)&head=([^&]+)&base=([^&]+)&per_page=2&page=1", tail)
        p.require(m is not None); _branch(m[1], head=True); _branch(m[2]); return
    if tail.startswith("git/ref/heads/"):
        _branch(tail[len("git/ref/heads/"):]); return
    if re.fullmatch(r"compare/[0-9a-f]{40}\.\.\.[0-9a-f]{40}\?per_page=1&page=1", tail): return
    if re.fullmatch(r"pulls/[1-9][0-9]{0,19}", tail): p._id(tail[6:]); return
    p.require(tail == "")


def validate_body(role: _ResponseRole, raw: object) -> None:
    if role is not _ResponseRole.PULL_REQUEST_WRITE:
        p.require(raw is None); return
    p.require(type(raw) is bytes and 0 < len(raw) <= 32 * 1024)
    r = p.obj(_decode_json(raw, limit=32 * 1024, nodes=16, depth=2, exact=True), {"base", "head", "title", "body", "draft"})
    p.require(type(r["draft"]) is bool and type(r["body"]) is str and p.canonical(r) == raw)
    m = re.search(r"\n\n<!-- mrk-draft-pr:([0-9a-f]{32}) -->\Z", r["body"])
    p.require(m is not None)
    p.Draft.parse({"base": r["base"], "head": r["head"], "title": r["title"], "body": r["body"][:m.start()],
                   **({"creationMode": "ready-for-review"} if not r["draft"] else {})})


def request_role(target: p.Target, draft: p.Draft | None, request) -> _ResponseRole:
    path = request.path; base = "/repos/" + target.repository
    if request.method == "POST":
        p.require(draft is not None and draft.matches(target) and path == base + "/pulls"
                  and request.body == p.canonical(draft.post_body(target)))
        role = _ResponseRole.PULL_REQUEST_WRITE
    else:
        p.require(request.method == "GET" and request.body is None)
        role = _ResponseRole.PULL_REQUEST_LIST if "/pulls?" in path else _ResponseRole.PULL_REQUEST_OBJECT
        allowed = {"/user", base}
        if target.intent is not None:
            for side in ("base", "head"): allowed.add(base + "/git/ref/heads/" + p._quote(target.intent[side]))
            op = p.Operation(target, lambda _: None)
            allowed.update((op.list_path(opened=True), op.list_path(opened=False)))
            # SHA/number coordinates come from the fixed core read schedule;
            # this only admits those closed metadata roles, not arbitrary URLs.
            if re.fullmatch(re.escape(base) + r"/(?:pulls/[1-9][0-9]{0,19}|compare/[0-9a-f]{40}\.\.\.[0-9a-f]{40}\?per_page=1&page=1)", path):
                allowed.add(path)
        p.require(path in allowed)
    validate_endpoint(role, request.method, path); validate_body(role, request.body)
    return role


def make_exchange(target: p.Target, draft: p.Draft | None, token: str, *, started: float, runtime_dir: str, budget: _Budget, checkpoint):
    p.Target.parse(target.value())
    p.require(type(budget) is _Budget and budget.profile is _ExchangeProfile.PULL_REQUEST
              and budget.started == started and budget.end == started + 60.0 and budget.body_total_limit == p.TOTAL_BODY_LIMIT)
    exchange = _make_live_exchange(token, started=started, runtime_dir=runtime_dir, api_version="2026-03-10",
                                  _profile=_ExchangeProfile.PULL_REQUEST, _setup_budget=budget)
    count = 0
    def send(request):
        nonlocal count
        checkpoint(); budget.remaining(); p.need(count < p.MAX_REQUESTS, "response-limit")
        role = request_role(target, draft, request); count += 1
        result = exchange(request.method, request.path, request.body, _role=role)
        send.control = dict(_check_control(result.control)); checkpoint(); budget.remaining()
        return result
    send.control = _control()
    return send
