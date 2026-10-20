"""Fixed read-only Activity dialogue in the existing Setup bootstrap/owner."""
from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass

from . import github_activity as p
from ._desktop_github_engine import _ID, _check_control, _read_request, _write_response, ProtocolError
from ._github_connection_transport import _Budget, _ExchangeProfile
from ._github_activity_transport import make_exchange
from .github_setup_remote import _frame

INITIAL_LIMIT = GO_LIMIT = 8192


@dataclass(frozen=True, slots=True, repr=False)
class Initial:
    id: str
    target: p.Target
    selection: dict
    digest: str


def parse_initial(raw: bytes) -> Initial:
    r = p.obj(_frame(raw, INITIAL_LIMIT, nodes=128, depth=6), {"protocol", "id", "action"})
    p.require(r["protocol"] == p.PROTOCOL and type(r["id"]) is str and _ID.fullmatch(r["id"]) is not None)
    a = p.obj(r["action"], {"target", "selection"})
    return Initial(r["id"], p.Target.parse(a["target"]), p.selection(a["selection"]), hashlib.sha256(raw).hexdigest())


def ready_frame(r: Initial) -> bytes:
    return p.canonical({"protocol": p.PROTOCOL, "id": r.id, "ready": {"requestSha256": r.digest}}) + b"\n"


def parse_go(raw: bytes, r: Initial) -> str:
    v = p.obj(_frame(raw, GO_LIMIT, nodes=32, depth=3), {"protocol", "id", "go"})
    p.require(v["protocol"] == p.PROTOCOL and v["id"] == r.id)
    go = p.obj(v["go"], {"requestSha256", "token"})
    token = go["token"]
    p.require(go["requestSha256"] == r.digest and type(token) is str and 1 <= len(token) <= 4096
              and all(0x21 <= ord(c) <= 0x7e for c in token))
    return token


def run_owned(control: int, output: int, initial: bytes, *, started: float, runtime_dir: str) -> None:
    def check() -> None:
        now = time.monotonic()
        if now < started or now >= started + 60.0:
            raise ProtocolError("Original activity deadline elapsed")
    check()
    request = parse_initial(initial)
    _write_response(output, ready_frame(request)); check()
    token = parse_go(_read_request(control, started + 60.0), request)
    budget = _Budget(started, _profile=_ExchangeProfile.ACTIVITY)
    exchange = make_exchange(request.target, request.selection, token, started=started, runtime_dir=runtime_dir, budget=budget)
    token = None
    result = p.observe(request.target, request.selection, exchange)
    _check_control(result["control"])
    raw = p.canonical({"protocol": p.PROTOCOL, "id": request.id, "result": result}) + b"\n"
    p.require(len(raw) <= p.MAX_RESULT_BYTES)
    exchange = None
    check(); _write_response(output, raw); check()
