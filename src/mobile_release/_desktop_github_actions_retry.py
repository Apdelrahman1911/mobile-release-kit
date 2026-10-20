"""Closed Actions retry dialogue in the existing Setup bootstrap/Supervisor."""
from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass

from . import github_actions_retry as p
from ._desktop_github_engine import _ID, _check_control, _read_request, _write_response, ProtocolError
from ._github_actions_retry_journal import Journal
from ._github_actions_retry_transport import make_exchange
from ._github_connection_transport import _Budget, _ExchangeProfile, _control, ReadFailure
from ._github_preflight_journal import JournalError
from .github_setup_remote import _frame

KINDS = ("prepare", "retry", "pending", "reconcile")
INITIAL_LIMIT = GO_LIMIT = 8192


@dataclass(frozen=True, slots=True, repr=False)
class Initial:
    id: str
    kind: str
    target: p.Target
    home: str | None
    prepared_sha256: str | None
    digest: str


def parse_initial(raw: bytes) -> Initial:
    row = p.obj(_frame(raw, INITIAL_LIMIT, nodes=128, depth=6), {"protocol", "id", "action"})
    p.require(row["protocol"] == p.PROTOCOL and type(row["id"]) is str and _ID.fullmatch(row["id"]) is not None)
    action = p.obj(row["action"], {"kind", "target", "home", "preparedSha256"})
    p.require(action["kind"] in KINDS and (action["home"] is None) == (action["kind"] == "prepare"))
    if action["home"] is not None:
        Journal(action["home"], end=0)  # Grammar only; no IO or selected secret.
    digest = action["preparedSha256"]
    p.require((digest is not None) == (action["kind"] in ("retry", "reconcile")))
    if digest is not None: p.hex_text(digest, 64)
    target = p.Target.parse(action["target"])
    p.require((target.selection is None) == (action["kind"] == "pending"))
    return Initial(row["id"], action["kind"], target, action["home"], digest, hashlib.sha256(raw).hexdigest())


def ready_frame(request: Initial) -> bytes:
    return p.canonical({"protocol": p.PROTOCOL, "id": request.id, "ready": {"requestSha256": request.digest}}) + b"\n"


def parse_go(raw: bytes, request: Initial) -> tuple[str | None, p.Prepared | None]:
    row = p.obj(_frame(raw, GO_LIMIT, nodes=256, depth=8), {"protocol", "id", "go"})
    p.require(row["protocol"] == p.PROTOCOL and row["id"] == request.id)
    go = p.obj(row["go"], {"requestSha256", "token", "prepared"})
    p.require(go["requestSha256"] == request.digest)
    token = go["token"]
    if request.kind == "pending": p.require(token is None)
    else: p.require(type(token) is str and 1 <= len(token) <= 4096 and all(0x21 <= ord(c) <= 0x7e for c in token))
    prepared = go["prepared"]
    p.require((prepared is not None) == (request.kind in ("retry", "reconcile")))
    if prepared is not None:
        prepared = p.Prepared.parse(prepared)
        p.require(prepared.target == request.target and p.digest(prepared) == request.prepared_sha256)
    return token, prepared


def execute(request: Initial, token: str | None, retained: p.Prepared | None, *, started: float, runtime_dir: str) -> dict:
    budget = _Budget(started, _profile=_ExchangeProfile.ACTIONS_RETRY)
    result = {"schemaVersion": 1, "kind": request.kind, "reason": "none", "prepared": None,
              "retry": None, "pending": None, "control": _control()}
    journal = exchange = None
    try:
        budget.remaining()
        if request.home is not None:
            journal = Journal(request.home, end=budget.end)
            journal.open()
        if request.kind == "pending":
            p.require(token is None and retained is None and journal is not None)
            result["pending"] = journal.pending(request.target)
        else:
            exchange = make_exchange(request.target, token, started=started, runtime_dir=runtime_dir,
                budget=budget, checkpoint=journal._post if journal is not None else budget.remaining)
            if request.kind == "prepare":
                p.require(retained is None and journal is None)
                prepared, _ = p.prepare(request.target, exchange)
                result["prepared"] = prepared.value()
            elif request.kind == "retry":
                p.require(retained is not None and journal is not None)
                result["retry"] = p.retry(retained, exchange, journal)
                result["reason"] = result["retry"]["reason"]
            else:
                p.require(request.kind == "reconcile" and retained is not None and journal is not None)
                matches = [row for row in journal.pending(request.target) if row["prepared"] == retained.value()]
                p.need(len(matches) == 1, "journal-unavailable")
                result["retry"] = p.reconcile(matches[0], exchange)
                result["reason"] = result["retry"]["reason"]
    except (p.Refused, p.activity.Refused, ReadFailure) as error:
        result["reason"] = error.reason
    except (JournalError, OSError):
        result["reason"] = "journal-unavailable"
    except (ValueError, TypeError, KeyError, UnicodeError, OverflowError, RecursionError):
        result["reason"] = "response-invalid"
    finally:
        if exchange is not None:
            result["control"] = dict(_check_control(exchange.control))
            if result["retry"] is not None: result["retry"]["control"] = dict(result["control"])
        if journal is not None:
            journal.close()  # Unknown consuming close cannot manufacture FIN.
    return result


def encode_result(request: Initial, result: dict, retained: p.Prepared | None = None) -> bytes:
    p.obj(result, {"schemaVersion", "kind", "reason", "prepared", "retry", "pending", "control"})
    p.require(type(result["schemaVersion"]) is int and result["schemaVersion"] == 1
              and result["kind"] == request.kind and result["reason"] in p.REASONS)
    _check_control(result["control"])
    if request.kind in ("retry", "reconcile"):
        p.require(retained is not None and retained.target == request.target and p.digest(retained) == request.prepared_sha256)
    else: p.require(retained is None)
    p.require((request.kind == "prepare" and result["reason"] == "none") == (result["prepared"] is not None))
    p.require((request.kind == "pending" and result["reason"] == "none") == (result["pending"] is not None))
    if result["prepared"] is not None:
        p.require(request.kind == "prepare" and result["reason"] == "none" and p.Prepared.parse(result["prepared"]).target == request.target)
    if result["pending"] is not None:
        p.require(request.kind == "pending" and type(result["pending"]) is list and len(result["pending"]) <= p.MAX_RECORDS)
        markers: set[str] = set()
        for row in result["pending"]:
            record = p.pending_record(row); target = p.Target.parse(record["prepared"]["target"])
            p.require(target.same_scope(request.target) and target.selection["marker"] not in markers)
            markers.add(target.selection["marker"])
    if result["retry"] is not None:
        p.require(request.kind in ("retry", "reconcile") and retained is not None)
        row = p.action_result(result["retry"], retained, request.kind)
        p.require(row["reason"] == result["reason"] and row["control"] == result["control"])
    elif request.kind in ("retry", "reconcile"):
        p.require(result["reason"] != "none")
    raw = p.canonical({"protocol": p.PROTOCOL, "id": request.id, "result": result}) + b"\n"
    p.require(len(raw) <= p.MAX_RESULT_BYTES)
    return raw


def run_owned(control: int, output: int, initial: bytes, *, started: float, runtime_dir: str) -> None:
    def check() -> None:
        now = time.monotonic()
        if now < started or now >= started + 60.0:
            raise ProtocolError("Original Actions retry deadline elapsed")
    check(); request = parse_initial(initial)
    _write_response(output, ready_frame(request)); check()
    token, prepared = parse_go(_read_request(control, started + 60.0), request)
    result = execute(request, token, prepared, started=started, runtime_dir=runtime_dir)
    token = None
    response = encode_result(request, result, prepared); prepared = None
    check(); _write_response(output, response); check()
