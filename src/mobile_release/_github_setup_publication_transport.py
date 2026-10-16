"""Original GitHub transport reuse for a closed setup-publication profile.

No new TLS/socket owner or renderer URL API. Only the native-owned engine may
construct this factory, using its original 60s budget and private token loan.
"""
from __future__ import annotations

import re

from ._desktop_github_engine import _check_control, _decode_json
from ._github_connection_transport import _Budget, _ExchangeProfile, _ResponseRole, _make_live_exchange, _control
from .github_setup_publication import (CONFIG_PATH, CONFIRMATION, MAX_CALLER_BYTES, MAX_CONFIG_BYTES,
    MAX_REQUESTS, MAX_REVIEW_BYTES, PATHS, Source, Target, _SHA, _coordinate, _match, _object, _quote,
    _require, branch)

ROLES = (_ResponseRole.PUBLICATION_READ, _ResponseRole.PUBLICATION_CREATE, _ResponseRole.PUBLICATION_LIST)


def validate_endpoint(role: _ResponseRole, method: str, path: str) -> None:
    """Second transport boundary; the factory additionally binds exact target."""
    _require(role in ROLES and method in {"GET", "POST"} and type(path) is str and len(path) <= 2048)
    if path == "/user":
        _require(method == "GET" and role is _ResponseRole.PUBLICATION_READ)
        return
    parts = path.split("/")
    _require(len(parts) >= 4 and parts[:2] == ["", "repos"])
    _coordinate(parts[2] + "/" + parts[3])
    tail = "/".join(parts[4:])
    if role is _ResponseRole.PUBLICATION_CREATE:
        _require(method == "POST" and tail in {"git/trees", "git/commits", "git/refs", "pulls"})
    elif role is _ResponseRole.PUBLICATION_LIST:
        _require(method == "GET" and re.fullmatch(r"pulls\?state=all&head=[A-Za-z0-9._~%/-]+&base=[A-Za-z0-9._~%/-]+&per_page=2&page=1", tail) is not None)
    else:
        _require(method == "GET" and (not tail or re.fullmatch(
            r"git/(?:(?:commits|blobs|trees)/[0-9a-f]{40}|ref/heads/[A-Za-z0-9._~%/-]+)", tail) is not None))


def request_role(target: Target, request) -> _ResponseRole:
    prefix = "/repos/" + target.repository
    path, method, raw = request.path, request.method, request.body
    _require(path == "/user" or path == prefix or path.startswith(prefix + "/"))
    tail = path[len(prefix) + 1:] if path.startswith(prefix + "/") else ""
    role = (_ResponseRole.PUBLICATION_CREATE if method == "POST" else
            _ResponseRole.PUBLICATION_LIST if tail.startswith("pulls?") else _ResponseRole.PUBLICATION_READ)
    validate_endpoint(role, method, path)
    if method == "GET":
        _require(raw is None)
        if tail.startswith("git/ref/heads/"):
            _require(tail.removeprefix("git/ref/heads/") in {_quote(target.base), _quote(target.head)})
        if role is _ResponseRole.PUBLICATION_LIST:
            _require(tail == "pulls?state=all&head=" + _quote(target.repository.split("/")[0] + ":" + target.head)
                     + "&base=" + _quote(target.base) + "&per_page=2&page=1")
        return role
    _require(type(raw) is bytes and 0 < len(raw) <= MAX_REVIEW_BYTES)
    value = _decode_json(raw, limit=MAX_REVIEW_BYTES, nodes=128, depth=5, exact=True)
    if tail == "git/trees":
        row = _object(value, {"base_tree", "tree"}); _match(row["base_tree"], _SHA)
        _require(type(row["tree"]) is list and len(row["tree"]) == len(PATHS))
        content = []
        for entry, path in zip(row["tree"], PATHS, strict=True):
            _object(entry, {"path", "mode", "type", "content"})
            _require(entry["path"] == path and entry["mode"] == "100644" and entry["type"] == "blob"
                     and type(entry["content"]) is str)
            content.append(entry["content"].encode("utf-8"))
        source = Source.from_saved(content[0], target)
        _require(source.files == tuple(content))
    elif tail == "git/commits":
        row = _object(value, {"message", "tree", "parents"})
        _require(row["message"] == target.title and type(row["parents"]) is list and len(row["parents"]) == 1)
        _match(row["tree"], _SHA); _match(row["parents"][0], _SHA)
    elif tail == "git/refs":
        row = _object(value, {"ref", "sha"})
        _require(row["ref"] == "refs/heads/" + target.head); _match(row["sha"], _SHA)
    else:
        _require(_object(value, {"title", "head", "base", "body", "draft"}) == {
            "title": target.title, "head": target.head, "base": target.base, "body": CONFIRMATION, "draft": True})
        _require(value["draft"] is True)
    return role


def make_exchange(target: Target, token: str, *, started: float, runtime_dir: str, budget: _Budget,
                  checkpoint):
    Target.parse(target.value())
    _require(type(budget) is _Budget and budget.profile is _ExchangeProfile.PUBLICATION
             and budget.started == started and budget.end == started + 60.0)
    exchange = _make_live_exchange(token, started=started, runtime_dir=runtime_dir, api_version="2026-03-10",
                                  _profile=_ExchangeProfile.PUBLICATION, _setup_budget=budget)
    count = 0

    def send(request):
        nonlocal count
        checkpoint(); budget.remaining()
        _require(count < MAX_REQUESTS)
        role = request_role(target, request)
        count += 1  # Never refund an attempted logical request.
        result = exchange(request.method, request.path, request.body, _role=role)
        send.control = dict(_check_control(result.control))
        checkpoint(); budget.remaining()
        return result

    send.control = _control()
    return send
