"""Fixed cleanup dialogue in the existing Setup bootstrap and original clock."""
from __future__ import annotations

import hashlib
import os
import time
from contextlib import ExitStack
from dataclasses import dataclass

from . import github_play_cleanup as p
from ._desktop_github_engine import _ID, _check_control, _write_response, ProtocolError
from ._github_connection_transport import _Budget, _ExchangeProfile, _control, ReadFailure
from ._github_play_cleanup_journal import Journal
from ._github_play_cleanup_transport import make_exchange
from ._github_preflight_journal import JournalError
from .github_setup_remote import _frame
from .github_setup_secret_inputs import (publication_source, observe_play_cleanup_configuration,
                                        SecretConfigurationError)

KINDS = ("prepare", "dispatch", "pending", "observe")
INITIAL_LIMIT = 8192
GO_LIMIT = 16 * 1024  # Complete 4096-byte token + bounded review, no global change.


@dataclass(frozen=True, slots=True, repr=False)
class Initial:
    id: str
    kind: str
    target: p.Target
    source: dict | None
    home: str | None
    prepared_sha256: str | None
    digest: str


def parse_initial(raw: bytes) -> Initial:
    row = p.obj(_frame(raw, INITIAL_LIMIT, nodes=256, depth=8), {"protocol", "id", "action"})
    p.require(row["protocol"] == p.PROTOCOL and type(row["id"]) is str and _ID.fullmatch(row["id"]) is not None)
    action = p.obj(row["action"], {"kind", "target", "source", "home", "preparedSha256"})
    kind = action["kind"]
    p.require(kind in KINDS and (action["source"] is not None) == (kind in ("prepare", "dispatch"))
        and (action["home"] is None) == (kind == "prepare"))
    if action["source"] is not None:
        publication_source(action["source"])  # Native identity grammar, no path read/loan.
    if action["home"] is not None:
        Journal(action["home"], end=0)
    digest = action["preparedSha256"]
    p.require((digest is not None) == (kind in ("dispatch", "observe")))
    if digest is not None:
        p.hex_text(digest, 64)
    target = p.Target.parse(action["target"])
    p.require(target.pending_purpose is None or kind == "pending")
    return Initial(row["id"], kind, target, action["source"], action["home"], digest,
                   hashlib.sha256(raw).hexdigest())


def ready_frame(request: Initial) -> bytes:
    return p.canonical({"protocol": p.PROTOCOL, "id": request.id, "ready": {"requestSha256": request.digest}}) + b"\n"


def parse_go(raw: bytes, request: Initial) -> tuple[str | None, p.Prepared | None]:
    row = p.obj(_frame(raw, GO_LIMIT, nodes=1024, depth=12), {"protocol", "id", "go"})
    p.require(row["protocol"] == p.PROTOCOL and row["id"] == request.id)
    go = p.obj(row["go"], {"requestSha256", "token", "prepared"})
    p.require(go["requestSha256"] == request.digest)
    token = go["token"]
    if request.kind == "pending":
        p.require(token is None)
    else:
        p.require(type(token) is str and 1 <= len(token) <= 4096 and all(0x21 <= ord(c) <= 0x7e for c in token))
    value = go["prepared"]
    p.require((value is not None) == (request.kind in ("dispatch", "observe")))
    prepared = None if value is None else p.Prepared.parse(value)
    if prepared is not None:
        p.require(prepared.target == request.target and p.digest(prepared) == request.prepared_sha256)
    return token, prepared


def execute(request: Initial, token: str | None, retained: p.Prepared | None, *, started: float, runtime_dir: str) -> dict:
    budget = _Budget(started, _profile=_ExchangeProfile.PLAY_CLEANUP)
    result = {"schemaVersion": 1, "kind": request.kind, "reason": "none", "prepared": None,
        "cleanup": None, "pending": None, "control": _control()}
    journal = exchange = None
    try:
        with ExitStack() as stack:
            budget.remaining()
            observed = None
            if request.source is not None:
                observed = stack.enter_context(observe_play_cleanup_configuration(request.source, budget=budget))
            if observed is None:
                source = None
            elif request.target.version_tag is None:
                source = p.Source.from_saved(observed.saved_bytes())
            else:
                from .github_version_tag import saved_source
                source = saved_source(observed.saved_bytes())
            if request.home is not None:
                journal = Journal(request.home, end=budget.end)
                # Register its consuming close before open: partial traversal
                # also belongs to this same original and cannot be forgotten.
                stack.callback(journal.close)
                journal.open()
            def checkpoint():
                budget.remaining()
                if observed is not None:
                    observed.checkpoint()
                if journal is not None:
                    journal._post()
            if request.kind == "pending":
                p.require(token is None and retained is None and journal is not None)
                result["pending"] = journal.pending(request.target)
            else:
                exchange = make_exchange(request.target, token, source=source, retained=retained, kind=request.kind,
                    started=started, runtime_dir=runtime_dir, budget=budget, checkpoint=checkpoint)
                if request.kind == "prepare":
                    p.require(source is not None and retained is None and journal is None)
                    prepared, _ = p.prepare(request.target, source, exchange)
                    result["prepared"] = prepared.value()
                elif request.kind == "dispatch":
                    p.require(source is not None and retained is not None and journal is not None)
                    result["cleanup"] = p.dispatch(retained, source, exchange, journal)
                    result["reason"] = result["cleanup"]["reason"]
                else:
                    p.require(request.kind == "observe" and retained is not None and journal is not None)
                    matches = [row for row in journal.pending(request.target) if row["prepared"] == retained.value()]
                    p.need(len(matches) == 1, "journal-unavailable")
                    result["cleanup"] = p.observe(matches[0], exchange)
                    result["reason"] = result["cleanup"]["reason"]
            checkpoint()
    except SecretConfigurationError as error:
        # Unknown original source close must never emit a known terminal.
        if getattr(error, "_cleanup_unknown", True):
            raise
        result["prepared"] = None
        result["reason"] = "source-changed"
    except JournalError:
        # Custodian close failure is not merely an API rejection; the real
        # enclosing worker must return failure and native keeps Unknown.
        raise
    except (ValueError, TypeError, KeyError, UnicodeError, OverflowError, RecursionError,
            p.ConfigurationError, p.ValidationError, OSError, ReadFailure) as error:
        result["prepared"] = None
        result["reason"] = p.reason(error)
    finally:
        if exchange is not None:
            result["control"] = dict(_check_control(exchange.control))
        if result["cleanup"] is not None:
            result["cleanup"]["control"] = dict(result["control"])
            # Retain actual acknowledged/claimed facts on a late known source
            # refusal. Nothing converts them to not-sent or grants a replay.
            result["cleanup"]["reason"] = result["reason"]
            if result["reason"] != "none" and request.kind == "observe":
                result["cleanup"].update(effect="unresolved", observed=None)
        if result["reason"] != "none":
            result["prepared"] = None
            result["pending"] = None
    return result


def encode_result(request: Initial, result: dict, retained: p.Prepared | None = None) -> bytes:
    p.obj(result, {"schemaVersion", "kind", "reason", "prepared", "cleanup", "pending", "control"})
    p.require(type(result["schemaVersion"]) is int and result["schemaVersion"] == 1
        and result["kind"] == request.kind and result["reason"] in p.REASONS)
    _check_control(result["control"])
    if request.kind in ("dispatch", "observe"):
        p.require(retained is not None and retained.target == request.target and p.digest(retained) == request.prepared_sha256)
    else:
        p.require(retained is None)
    p.require((request.kind == "prepare" and result["reason"] == "none") == (result["prepared"] is not None))
    p.require((request.kind == "pending" and result["reason"] == "none") == (result["pending"] is not None))
    if result["prepared"] is not None:
        p.require(p.Prepared.parse(result["prepared"]).target == request.target)
    if result["pending"] is not None:
        p.require(type(result["pending"]) is list and len(result["pending"]) <= p.MAX_RECORDS)
        markers: set[str] = set()
        for row in result["pending"]:
            record = p.pending_record(row)
            target = p.Target.parse(record["prepared"]["target"])
            p.require(target.same_scope(request.target) and target.marker not in markers)
            markers.add(target.marker)
    if result["cleanup"] is not None:
        p.require(request.kind in ("dispatch", "observe") and retained is not None)
        row = p.action_result(result["cleanup"], retained, request.kind)
        p.require(row["reason"] == result["reason"] and row["control"] == result["control"])
    elif request.kind in ("dispatch", "observe"):
        p.require(result["reason"] != "none")
    raw = p.canonical({"protocol": p.PROTOCOL, "id": request.id, "result": result}) + b"\n"
    p.require(len(raw) <= p.MAX_RESULT_BYTES)
    return raw


def run_owned(control: int, output: int, initial: bytes, *, started: float, runtime_dir: str) -> None:
    def check():
        now = time.monotonic()
        if now < started or now >= started + 60.0:
            raise ProtocolError("Original Play cleanup deadline elapsed")
    check()
    request = parse_initial(initial)
    _write_response(output, ready_frame(request)); check()
    # Same original control FD and finite read pattern as Publication; only
    # this closed profile's bound accounts for its complete token + review.
    raw = bytearray()
    while True:
        check()
        block = os.read(control, min(4096, GO_LIMIT + 1 - len(raw)))
        check()
        if not block:
            break
        raw.extend(block)
        if len(raw) > GO_LIMIT:
            raise ProtocolError("Private Play cleanup GO exceeded its bound")
    token, prepared = parse_go(bytes(raw), request)
    raw.clear()
    result = execute(request, token, prepared, started=started, runtime_dir=runtime_dir)
    token = None
    response = encode_result(request, result, prepared)
    prepared = None
    check(); _write_response(output, response); check()
