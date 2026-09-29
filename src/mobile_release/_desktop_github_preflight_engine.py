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
    if request.family is Family.INPUT_GROUP:
        if request.kind == "pending":
            _require(result is None and type(pending) is list and len(pending) <= MAX_RECORDS
                     and request.pending_scope is not None)
            markers = set()
            for item in pending:
                record = policy.parse_record(item)
                target = policy.Prepared.parse(record["prepared"]).target
                _require(target.marker not in markers)
                markers.add(target.marker)
                _require(all(target.value()[key] == expected for key, expected in request.pending_scope.items()))
        else:
            _require(pending is None and request.action is not None)
            policy.validate_result(request.action, result)
        envelope = {"protocol": policy.PROTOCOL, "id": request.id, "result": result, "pending": pending}
        _check_values(envelope, nodes=20_000, depth=16)
        raw = policy.canonical(envelope) + b"\n"
        _require(len(raw) <= MAX_RESULT_BYTES)
        return raw
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



MAX_INPUT_READ_BYTES = 8 * 1024
MAX_INPUT_RECHECK_BYTES = 8 * 1024
MAX_INPUT_GO_BYTES = 96 * 1024
MAX_INPUT_OUTCOME_BYTES = 1024
MAX_INPUT_STDOUT_BYTES = 271872


def _input_policy():
    return policy_for(Family.INPUT_GROUP)


def input_ready_frame(request: Initial) -> bytes:
    _require(request.family is Family.INPUT_GROUP)
    journal = {"prepare": "not-applicable", "apply": "opened", "reconcile": "matched-intent",
               "pending": "loaded"}[request.kind]
    raw = _input_policy().canonical({"protocol": _input_policy().PROTOCOL, "id": request.id,
            "ready": {"requestSha256": request.digest, "phase": "observe", "journal": journal}}) + b"\n"
    _require(len(raw) <= MAX_READY_BYTES)
    return raw


def parse_input_read(raw: bytes, request: Initial) -> str | None:
    _require(request.family is Family.INPUT_GROUP)
    row = _object(_frame(raw, MAX_INPUT_READ_BYTES, nodes=32, depth=4), {"protocol", "id", "read"})
    _require(row["protocol"] == _input_policy().PROTOCOL and row["id"] == request.id)
    read = _object(row["read"], {"requestSha256", "token"})
    _require(read["requestSha256"] == request.digest)
    token = read["token"]
    if request.kind == "pending":
        _require(token is None)
    else:
        _require(type(token) is str and 1 <= len(token) <= 4096
                 and all(0x21 <= ord(char) <= 0x7e for char in token))
    return token


def input_rechecked_frame(request: Initial, snapshot, intent_sha256: str) -> tuple[bytes, str]:
    policy = _input_policy()
    _require(request.family is Family.INPUT_GROUP and request.kind == "apply"
             and request.action is not None and request.action.prepared is not None)
    _require(intent_sha256 == policy.intent_digest(request.action.prepared))
    admitted = policy.Prepared.parse(snapshot.value())
    policy.compare_prepared(request.action.prepared, admitted)
    digest = hashlib.sha256(policy.canonical(admitted.value())).hexdigest()
    raw = policy.canonical({"protocol": policy.PROTOCOL, "id": request.id, "rechecked": {
        "requestSha256": request.digest, "snapshotSha256": digest,
        "intentSha256": _match(intent_sha256, _DIGEST), "snapshot": admitted.value()}}) + b"\n"
    _require(len(raw) <= MAX_INPUT_RECHECK_BYTES)
    return raw, digest


def parse_input_go(raw: bytes, request: Initial, snapshot_sha256: str, intent_sha256: str) -> bytes:
    import base64
    import binascii

    policy = _input_policy()
    _require(request.family is Family.INPUT_GROUP and request.kind == "apply"
             and request.action is not None and request.action.prepared is not None)
    row = _object(_frame(raw, MAX_INPUT_GO_BYTES, nodes=32, depth=4), {"protocol", "id", "go"})
    _require(row["protocol"] == policy.PROTOCOL and row["id"] == request.id)
    go = _object(row["go"], {"requestSha256", "snapshotSha256", "intentSha256", "putBodyBase64"})
    _require(go["requestSha256"] == request.digest and go["snapshotSha256"] == snapshot_sha256
             and go["intentSha256"] == intent_sha256)
    encoded = go["putBodyBase64"]
    _require(type(encoded) is str and 0 < len(encoded) <= 4 * ((policy.MAX_PUT_BODY + 2) // 3))
    try:
        body = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error):
        raise ProtocolError("Invalid fixed sealed input-group frame") from None
    _require(base64.b64encode(body).decode("ascii") == encoded)
    return policy.validate_put_body(body, request.action.prepared.public_key_id)


def input_outcome_frame(request: Initial, snapshot_sha256: str, intent_sha256: str,
                        write: object, control: object) -> bytes:
    policy = _input_policy()
    _require(request.family is Family.INPUT_GROUP and request.kind == "apply")
    raw = policy.canonical({"protocol": policy.PROTOCOL, "id": request.id, "outcome": {
        "requestSha256": request.digest, "snapshotSha256": _match(snapshot_sha256, _DIGEST),
        "intentSha256": _match(intent_sha256, _DIGEST),
        "write": policy.parse_write(write), "control": _check_control(control)}}) + b"\n"
    _require(len(raw) <= MAX_INPUT_OUTCOME_BYTES)
    return raw


def _read_input_phase(fd: int, end: float, maximum: int, *, eof: bool) -> bytes:
    """Original reader only. No read-chunk boundary is a message boundary."""
    value = bytearray()
    while True:
        if time.monotonic() >= end:
            raise ProtocolError("Fixed input-group original endpoint elapsed")
        part = os.read(fd, min(4096, maximum + 1 - len(value)))
        if time.monotonic() >= end:
            raise ProtocolError("Fixed input-group original endpoint elapsed")
        if not part:
            _frame(bytes(value), maximum)
            return bytes(value)
        value.extend(part)
        if len(value) > maximum:
            raise ProtocolError("Fixed input-group frame exceeded its bound")
        if not eof and b"\n" in value:
            # A final GO cannot legally be pre-sent with READ: RECHECKED and
            # native sealing have not occurred. For final GO require EOF.
            _frame(bytes(value), maximum)
            return bytes(value)


class _InputOutput:
    """Small phase/byte ledger around the original already-owned stdout FD."""
    def __init__(self, request: Initial, output: int) -> None:
        self.request = request
        self.output = output
        self.phase = "initial"
        self.total = 0
        self.go_accepted = False
        self.failed = False

    def emit(self, phase: str, raw: bytes) -> None:
        legal = ((phase == "ready" and self.phase == "initial")
                 or phase == "rechecked" and self.phase == "ready" and self.request.kind == "apply"
                 or phase == "outcome" and self.phase == "rechecked" and self.go_accepted
                 or phase == "result" and self.phase in {"ready", "rechecked", "outcome"})
        limits = {"ready": MAX_READY_BYTES, "rechecked": MAX_INPUT_RECHECK_BYTES,
                  "outcome": MAX_INPUT_OUTCOME_BYTES, "result": MAX_RESULT_BYTES}
        _require(not self.failed and legal and phase in limits and len(raw) <= limits[phase]
                 and self.total + len(raw) <= MAX_INPUT_STDOUT_BYTES)
        self.phase = phase
        self.total += len(raw)  # Claim before write, including partial failure.
        try:
            _write_response(self.output, raw)
        except BaseException:
            self.failed = True
            raise


def _run_input_group(request: Initial, control: int, writer: _InputOutput, journal: Journal | None,
                     *, started: float, runtime_dir: str) -> dict[str, Any] | None:
    from datetime import datetime, timezone
    from ._github_connection_transport import _InputWriteResult

    policy = _input_policy()
    end = started + READ_SECONDS
    token = None
    reader = None
    body = None
    result = None if request.kind == "pending" else policy.result_value(request.kind)
    intent = None
    if request.kind == "reconcile":
        _require(journal is not None and request.action is not None and request.action.prepared is not None)
        result["record"] = journal.input_record(request.action.prepared)
    try:
        writer.emit("ready", input_ready_frame(request))
        token = parse_input_read(_read_input_phase(control, end, MAX_INPUT_READ_BYTES,
                                                  eof=request.kind != "apply"), request)
        if request.action is None:
            return None
        _require(token is not None and result is not None)
        reader = policy._make_live_reader(request.action, token, started=started, runtime_dir=runtime_dir)
        observed = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
        result = policy.observe_reads(request.action, reader, observed_at=observed)
        if request.kind == "reconcile":
            _require(journal is not None and request.action.prepared is not None)
            result["record"] = journal.input_record(request.action.prepared)
        if request.kind != "apply":
            return result
        current = result["prepared"]
        result["prepared"] = None
        if result["reason"] != "none":
            return result
        _require(journal is not None and request.action.prepared is not None)
        snapshot = policy.Prepared.parse(current)
        current = None
        # Retain ORIGINAL consent snapshot, never the freshly timed recheck.
        intent = journal.create_intent(request.action.prepared)
        result["record"] = policy.record_value(request.action.prepared, {"state": "not-attempted"}, intent)
        ready, snapshot_digest = input_rechecked_frame(request, snapshot, intent)
        snapshot = None
        writer.emit("rechecked", ready)
        ready = None
        body = parse_input_go(_read_input_phase(control, end, MAX_INPUT_GO_BYTES, eof=True),
                              request, snapshot_digest, intent)
        if time.monotonic() >= end:
            raise ProtocolError("Fixed input-group final GO missed its original endpoint")
        writer.go_accepted = True
        result["record"] = policy.record_value(request.action.prepared,
                                               {"state": "attempted-outcome-unknown"}, intent)
        result["networkCleanup"] = "unknown"

        def observed_outcome(write, safe_control) -> None:
            # Remote acknowledgement is latched before output/close/fsync.
            result["record"] = policy.record_value(request.action.prepared, write, intent)
            result["control"] = _check_control(safe_control)
            writer.emit("outcome", input_outcome_frame(request, snapshot_digest, intent,
                                                       write, safe_control))

        reply = reader.put(body, observed_outcome)
        body = None
        _require(type(reply) is _InputWriteResult and reply.cleanup in {"confirmed", "unknown"})
        result["record"] = policy.record_value(request.action.prepared, reply.write, intent)
        result["control"] = _check_control(reply.control)
        result["networkCleanup"] = reply.cleanup
        write = result["record"]["write"]
        result["reason"] = (reply.control["reason"] if reply.control["reason"] != "none"
                            else "network-unavailable" if reply.cleanup != "confirmed"
                            else write["reason"] if write["state"] == "explicitly-rejected"
                            else "none" if write["state"] in {"acknowledged-created", "acknowledged-updated"}
                            and reply.observation_sent else "network-unavailable")
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as error:
        if result is None:
            raise
        # No exception text, token, body, local path or key is reflected.
        from ._github_preflight_journal import JournalError
        result["reason"] = "journal-incomplete" if isinstance(error, JournalError) else "response-invalid"
        result["prepared"] = None
        result["observation"] = None
        if intent is not None and result["record"] is None:
            result["record"] = policy.record_value(request.action.prepared,
                {"state": "attempted-outcome-unknown" if writer.go_accepted else "not-attempted"}, intent)
    finally:
        body = None
        reader = None
        token = None
        # At most one immutable outcome attempt, on the original owner. A
        # partial/colliding output is preserved; never repair/retry/delete it.
        if intent is not None and result is not None and result["record"] is not None:
            try:
                journal.bind_outcome(request.action.prepared, result["record"]["write"])
            except BaseException:
                result["journal"] = "unknown"
                result["reason"] = "journal-incomplete"
    return result


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
        is_input = family is Family.INPUT_GROUP
        if request.home is not None:
            journal = Journal(request.home, end=end, family=family)
            journal.open()
            if request.action is None:
                _require(request.pending_scope is not None)
                pending = journal.pending(request.pending_scope)
                if not is_input:
                    journal.close()
            else:
                _require(request.action.prepared is not None)
                if is_input:
                    if request.kind == "apply":
                        # Readiness grants observations only, not intent/PUT.
                        journal.admit_input_intent(request.action.prepared)
                    else:
                        journal.match_intent(request.action.prepared)
                elif request.kind == "dispatch":
                    journal.create_intent(request.action.prepared)
                else:
                    journal.match_intent(request.action.prepared, request.action.run_id)
        if is_input:
            writer = _InputOutput(request, output)
            result = _run_input_group(request, control, writer, journal,
                                      started=started, runtime_dir=runtime_dir)
            if journal is not None and not journal.closed:
                try:
                    journal.close()
                    if result is not None and result["journal"] != "unknown":
                        result["journal"] = "confirmed"
                except BaseException:
                    status = 74
                    if result is None:
                        raise
                    result["journal"] = "unknown"
                    result["reason"] = "journal-incomplete"
                    if request.kind == "reconcile":
                        result["observation"] = None
            if result is not None and result["networkCleanup"] == "unknown":
                status = status or 74
            writer.emit("result", encode_result(request, result, pending))
        else:
            # Original workflow/device profiles keep their existing two frames,
            # request limits, intent chronology and GO-to-EOF token flow.
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
            _write_response(output, encode_result(request, result, pending))
    except (KeyboardInterrupt, SystemExit):
        status = 130
    except Exception:
        status = status or 70
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
