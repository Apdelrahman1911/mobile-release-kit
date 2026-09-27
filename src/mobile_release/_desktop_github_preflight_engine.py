"""Private two-frame preflight helper; never a CLI or general HTTP interface.

Initial nonsecret request -> original journal durability/READY -> native final
document/session GO + credential -> at most one finite action -> final result.
The native Supervisor owns startup, pipes, deadline, stop and original finality.
An emitted READY/result alone does not establish native cleanup or success.
"""
from __future__ import annotations

import hashlib
import math
import os
import time
from dataclasses import dataclass
from typing import Any

from ._desktop_github_engine import (READ_SECONDS, ProtocolError, _ID, _check_control, _check_values,
                                    _decode_json, _read_request, _write_response)
from ._github_preflight_journal import Journal, MAX_RECORDS, canonical
from ._github_action_family import Family, policy_for
from .api._github_connection import _coordinate, _id
from .github_preflight import (PROTOCOL, REASONS, Action, Prepared, _DIGEST, _match, _object,
                               _require, _make_live_reader, execute)

MAX_INITIAL_BYTES = 16 * 1024
MAX_GO_BYTES = 8 * 1024
MAX_READY_BYTES = 512
MAX_RESULT_BYTES = 256 * 1024


@dataclass(frozen=True, slots=True, repr=False)
class Initial:
    id: str
    action: Action | None
    pending_scope: dict[str, str] | None
    home: str | None
    digest: str
    family: Family = Family.PREFLIGHT

    @property
    def kind(self) -> str:
        return "pending" if self.action is None else self.action.kind


def _frame(raw: bytes, maximum: int, *, nodes: int = 1024, depth: int = 12) -> Any:
    if (type(raw) is not bytes or not 1 < len(raw) <= maximum or not raw.endswith(b"\n")
            or raw.count(b"\n") != 1 or b"\r" in raw):
        raise ProtocolError("Invalid fixed preflight frame")
    return _decode_json(raw[:-1], limit=maximum - 1, nodes=nodes, depth=depth, exact=True)


def parse_initial(raw: bytes, *, family: Family = Family.PREFLIGHT) -> Initial:
    policy = policy_for(family)
    row = _object(_frame(raw, MAX_INITIAL_BYTES), {"protocol", "id", "action", "pendingScope", "home"})
    _require(row["protocol"] == policy.PROTOCOL)
    identity = _match(row["id"], _ID)
    action = None if row["action"] is None else policy.Action.parse(row["action"])
    scope = row["pendingScope"]
    _require((action is None) == (scope is not None))
    if scope is not None:
        scope = _object(scope, {"projectBinding", "repository", "accountId", "repositoryId"})
        scope = {"projectBinding": _match(scope["projectBinding"], _DIGEST),
                 "repository": _coordinate(scope["repository"]), "accountId": _id(scope["accountId"]),
                 "repositoryId": _id(scope["repositoryId"])}
    needs_journal = action is None or action.kind != "prepare"
    home = row["home"]
    _require((home is not None) == needs_journal)
    if home is not None:
        _require(type(home) is str and home.startswith("/") and len(home.encode("utf-8")) <= 4016
                 and not any(ord(char) < 32 or ord(char) == 127 for char in home))
    return Initial(identity, action, scope, home, hashlib.sha256(raw).hexdigest(), family)


def ready_frame(request: Initial) -> bytes:
    journal = {"prepare": "not-applicable", "dispatch": "durable-intent", "track": "matched-intent",
               "reconcile": "matched-intent", "pending": "loaded"}[request.kind]
    return canonical({"protocol": policy_for(request.family).PROTOCOL, "id": request.id,
                      "ready": {"requestSha256": request.digest, "journal": journal}}) + b"\n"


def parse_go(raw: bytes, request: Initial) -> str | None:
    row = _object(_frame(raw, MAX_GO_BYTES, nodes=32, depth=4), {"protocol", "id", "go"})
    _require(row["protocol"] == policy_for(request.family).PROTOCOL and row["id"] == request.id)
    go = _object(row["go"], {"requestSha256", "token"})
    _require(go["requestSha256"] == request.digest)
    token = go["token"]
    if request.kind == "pending":
        _require(token is None)
    else:
        _require(type(token) is str and 1 <= len(token) <= 4096
                 and all(0x21 <= ord(char) <= 0x7e for char in token))
    return token


def _read_initial(fd: int, end: float) -> bytes:
    value = bytearray()
    while b"\n" not in value:
        if time.monotonic() >= end:
            raise ProtocolError("Fixed preflight input deadline elapsed")
        part = os.read(fd, min(4096, MAX_INITIAL_BYTES + 1 - len(value)))
        if not part:
            raise ProtocolError("Fixed preflight initial frame was incomplete")
        value.extend(part)
        if len(value) > MAX_INITIAL_BYTES:
            raise ProtocolError("Fixed preflight initial frame exceeded its bound")
    # There may not be a pre-sent GO in this read. Only the native original
    # writer, after READY and the final context check, can supply the next frame.
    _frame(bytes(value), MAX_INITIAL_BYTES)
    return bytes(value)


def encode_result(request: Initial, result: dict[str, Any] | None,
                  pending: list[dict[str, Any]] | None = None) -> bytes:
    policy = policy_for(request.family)
    if request.kind == "pending":
        _require(result is None and type(pending) is list and len(pending) <= MAX_RECORDS)
        for row in pending:
            selected = _object(row, {"prepared", "runId"})
            policy.Prepared.parse(selected["prepared"])
            if selected["runId"] is not None:
                _id(selected["runId"])
    else:
        _require(pending is None)
        value = _object(result, {"schemaVersion", "action", "reason", "effect", "prepared", "runId", "run", "control"})
        _require(type(value["schemaVersion"]) is int and value["schemaVersion"] == 1 and value["action"] == request.kind
                 and type(value["reason"]) is str and value["reason"] in policy.REASONS)
        _check_control(value["control"])
        if request.kind == "prepare":
            _require(value["effect"] == "none" and value["runId"] is None and value["run"] is None)
            _require((value["reason"] == "none") == (value["prepared"] is not None))
            if value["prepared"] is not None:
                prepared = policy.Prepared.parse(value["prepared"])
                _require(request.action is not None and prepared.target == request.action.target)
        elif request.kind == "dispatch":
            _require(value["prepared"] is None and value["run"] is None)
            _require(value["effect"] in {"not-sent", "potentially-applied", "accepted"})
            _require((value["effect"] == "accepted") == (value["reason"] == "none"))
            _require((value["effect"] == "accepted") == (value["runId"] is not None))
            if value["runId"] is not None:
                _id(value["runId"])
        else:
            _require(value["effect"] == "none" and value["prepared"] is None)
            _require((value["reason"] == "none") == (value["run"] is not None and value["runId"] is not None))
            if value["run"] is not None:
                _require(value["run"]["id"] == _id(value["runId"]) and value["run"]["attempt"] == 1)
    envelope = {"protocol": policy.PROTOCOL, "id": request.id, "result": result, "pending": pending}
    _check_values(envelope, nodes=20_000, depth=16)
    raw = canonical(envelope) + b"\n"
    _require(len(raw) <= MAX_RESULT_BYTES)
    return raw


def main(*, started: float, runtime_dir: str, family: Family = Family.PREFLIGHT) -> int:
    owned: list[int] = []
    journal: Journal | None = None
    status = 0
    try:
        policy = policy_for(family)
        if (type(started) not in (int, float) or not math.isfinite(started)
                or not math.isfinite(started + READ_SECONDS)
                or type(runtime_dir) is not str or not os.path.isabs(runtime_dir)):
            return 78
        end = started + READ_SECONDS
        control = os.dup(0); owned.append(control); os.set_inheritable(control, False)
        output = os.dup(1); owned.append(output); os.set_inheritable(output, False)
        null = os.open(os.devnull, os.O_RDONLY); owned.append(null)
        os.dup2(null, 0, inheritable=False)
        os.dup2(2, 1, inheritable=False)
        request = parse_initial(_read_initial(control, end), family=family)
        pending = None
        if request.home is not None:
            journal = Journal(request.home, end=end, family=family)
            journal.open()
            if request.action is None:
                _require(request.pending_scope is not None)
                pending = journal.pending(request.pending_scope)
                journal.close()
            else:
                _require(request.action.prepared is not None)
                if request.kind == "dispatch":
                    journal.create_intent(request.action.prepared)
                else:
                    journal.match_intent(request.action.prepared, request.action.run_id)
        # No token or network client exists before durable intent/readback and
        # the original writer's checked close. Native final GO is still owed.
        _write_response(output, ready_frame(request))
        token = parse_go(_read_request(control, end), request)
        if time.monotonic() >= end:
            raise ProtocolError("Fixed preflight GO arrived after the original endpoint")
        result = None
        if request.action is not None:
            _require(token is not None)
            from datetime import datetime, timezone

            reader = policy._make_live_reader(request.action, token, started=started, runtime_dir=runtime_dir)
            observed = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
            result = policy.execute(request.action, reader, observed_at=observed)
            if result["runId"] is not None:
                _require(journal is not None and request.action.prepared is not None)
                journal.bind_run(request.action.prepared, result["runId"])
        token = None
        if journal is not None and not journal.closed:
            journal.close()
        # No successful result precedes the journal's actual original closes.
        # Channel-close failure below still changes the child exit disposition;
        # the native parent does not accept an earlier result over that failure.
        _write_response(output, encode_result(request, result, pending))
    except (KeyboardInterrupt, SystemExit):
        status = 130
    except Exception:
        status = 70
        try:
            os.write(2, b"Mobile Release Kit private preflight action failed.\n")
        except OSError:
            pass
    finally:
        if journal is not None and not journal.closed:
            try:
                journal.close()
            except BaseException:
                status = status or 74
        while owned:
            fd = owned.pop()
            try:
                os.close(fd)
            except OSError:
                status = status or 74
    return status
