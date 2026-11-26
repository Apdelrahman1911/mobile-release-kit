"""One closed route on the existing GitHub TLS/framing/close implementation."""
from __future__ import annotations

from . import github_repository_create as p
from ._desktop_github_engine import _check_control, _decode_json
from ._github_connection_transport import _Budget, _ExchangeProfile, _ResponseRole, _control, _make_live_exchange


def validate_endpoint(role: _ResponseRole, method: str, path: str) -> None:
    p.require(type(path) is str and len(path) <= 256 and method in ("GET", "POST"))
    parts = path.split("/")
    if role is _ResponseRole.REPOSITORY_CREATE_ACCOUNT:
        p.require(method == "GET" and path == "/user")
    elif role is _ResponseRole.REPOSITORY_CREATE_OWNER:
        p.require(method == "GET" and ((len(parts) == 3 and parts[:2] == ["", "orgs"])
                  or (len(parts) == 5 and parts[:4] == ["", "user", "memberships", "orgs"])))
        p.login(parts[-1])
    elif role is _ResponseRole.REPOSITORY_CREATE_LOOKUP:
        p.require(method == "GET" and len(parts) == 4 and parts[:2] == ["", "repos"])
        p.coordinate(parts[2] + "/" + parts[3])
    elif role is _ResponseRole.REPOSITORY_CREATE_WRITE:
        p.require(method == "POST" and (path == "/user/repos"
                  or len(parts) == 4 and parts[:2] == ["", "orgs"] and parts[3] == "repos"))
        if path != "/user/repos":
            p.login(parts[2])
    else:
        p.require(False)


def validate_body(role: _ResponseRole, raw: object) -> None:
    if role is not _ResponseRole.REPOSITORY_CREATE_WRITE:
        p.require(raw is None)
        return
    p.require(type(raw) is bytes and 0 < len(raw) <= 256)
    row = p.obj(_decode_json(raw, limit=256, nodes=16, depth=2, exact=True), {"name", "private", "auto_init"})
    p.coordinate("owner/" + row["name"])
    p.require(type(row["private"]) is bool and row["auto_init"] is False and p.canonical(row) == raw)


def request_role(target: p.Target, request) -> _ResponseRole:
    path, method, raw = request.path, request.method, request.body
    allowed = {"/user": _ResponseRole.REPOSITORY_CREATE_ACCOUNT,
               "/repos/" + target.repository: _ResponseRole.REPOSITORY_CREATE_LOOKUP}
    if target.owner_kind == "organization":
        allowed.update({"/orgs/" + target.owner: _ResponseRole.REPOSITORY_CREATE_OWNER,
                        "/user/memberships/orgs/" + target.owner: _ResponseRole.REPOSITORY_CREATE_OWNER})
    if method == "POST":
        p.require(path == target.endpoint() and raw == p.canonical(target.body()))
        role = _ResponseRole.REPOSITORY_CREATE_WRITE
    else:
        p.require(path in allowed)
        role = allowed[path]
    validate_endpoint(role, method, path)
    validate_body(role, raw)
    return role


def make_exchange(target: p.Target, token: str, *, started: float, runtime_dir: str, budget: _Budget, checkpoint):
    p.Target.parse(target.value())
    p.require(type(budget) is _Budget and budget.profile is _ExchangeProfile.REPOSITORY_CREATE
              and budget.started == started and budget.end == started + 60.0)
    exchange = _make_live_exchange(token, started=started, runtime_dir=runtime_dir, api_version="2026-03-10",
                                  _profile=_ExchangeProfile.REPOSITORY_CREATE, _setup_budget=budget)
    count = 0

    def send(request):
        nonlocal count
        checkpoint(); budget.remaining()
        p.need(count < p.MAX_REQUESTS, "response-limit")
        role = request_role(target, request)
        count += 1
        result = exchange(request.method, request.path, request.body, _role=role)
        send.control = dict(_check_control(result.control))
        checkpoint(); budget.remaining()
        return result

    send.control = _control()
    return send
