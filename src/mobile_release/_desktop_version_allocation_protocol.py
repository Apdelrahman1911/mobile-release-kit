"""Private allocation dialogue DATA; no public route, credential or IO owner.

Only an original native allocation admission may issue these frames. A parsed
ACK/FIN is not native currentness, consent, Store freshness or process finality.
Candidate creation/enrollment are deliberately absent from the worker protocol.
"""
from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass

from . import version_allocation as allocation
from . import version_allocation_state as state
from . import version_policy as policy
from ._desktop_github_engine import ProtocolError, _ID, _check_control, _decode_json
from .api._github_connection import _id

PROTOCOL = "mrk-version-allocation-runtime/1"
NATIVE_PROTOCOL = "mrk-version-reserve/1"
INITIAL_LIMIT = 8192
READY_LIMIT = 512
REQUEST_LIMIT = 16 * 1024
OBSERVATIONS_LIMIT = 4096
TOKEN_LIMIT = 4096
STATE_BASE64_LIMIT = 4 * ((state.MAX_STATE_BYTES + 2) // 3)
# Includes worst-case JSON quoting of each token character. State base64 has
# no escapable characters; request/observation caps already include JSON syntax.
GO_LIMIT = STATE_BASE64_LIMIT + REQUEST_LIMIT + OBSERVATIONS_LIMIT + 2 * TOKEN_LIMIT + 1024
TRANSITION_LIMIT = allocation.MAX_PENDING_BYTES + 512
STATE_FRAME_LIMIT = TRANSITION_LIMIT + 1024
ACK_LIMIT = 1024
FIN_LIMIT = 32 * 1024
MAX_TRANSITIONS = 5  # Current allocator needs at most four actual CAS writes.
WORK_SECONDS = 60.0
FINALITY_SECONDS = 70.0
KINDS = frozenset({"reserve", "reconcile"})


def require(value: bool) -> None:
    if not value:
        raise ProtocolError("Private allocation dialogue was refused")


def frame(raw: bytes, maximum: int, *, nodes: int = 2048, depth: int = 16) -> dict:
    require(type(raw) is bytes and 1 < len(raw) <= maximum and raw.endswith(b"\n")
            and raw.count(b"\n") == 1 and b"\r" not in raw)
    value = _decode_json(raw[:-1], limit=maximum - 1, nodes=nodes, depth=depth, exact=True)
    require(type(value) is dict and policy.canonical(value) + b"\n" == raw)
    return value


def encoded(value: dict, maximum: int) -> bytes:
    raw = policy.canonical(value) + b"\n"
    require(len(raw) <= maximum)
    return raw


def _clock(value: object) -> dict:
    row = policy._object(value, {"name", "workEndNs", "hardEndNs"})
    require(row["name"] == "CLOCK_UPTIME_RAW")
    for key in ("workEndNs", "hardEndNs"):
        text = row[key]
        require(type(text) is str and 1 <= len(text) <= 20 and text.isascii() and text.isdecimal()
                and not text.startswith("0") and int(text) <= (1 << 64) - 1)
    require(0 <= int(row["hardEndNs"]) - int(row["workEndNs"]) <= 10_000_000_000)
    return dict(row)


@dataclass(frozen=True, slots=True, repr=False)
class Initial:
    id: str
    kind: str
    local_project_id: str
    authority: allocation.AuthorityRegistration
    account_id: str
    candidate_id: str
    request_sha256: str
    clock: dict
    digest: str
    source: object = None
    provider: object = None


def message_protocol(initial: Initial) -> str:
    require(type(initial) is Initial and (initial.source is None) == (initial.provider is None))
    return NATIVE_PROTOCOL if initial.source is not None else PROTOCOL


def parse_initial(raw: bytes) -> Initial:
    row = policy._object(frame(raw, INITIAL_LIMIT, nodes=256, depth=8), {"protocol", "id", "action"})
    require(row["protocol"] in (PROTOCOL, NATIVE_PROTOCOL))
    native = row["protocol"] == NATIVE_PROTOCOL
    keys = {"kind", "localProjectId", "authority", "accountId", "candidateId", "requestSha256", "clock"}
    action = policy._object(row["action"], keys | ({"source", "provider"} if native else set()))
    require(type(action["kind"]) is str and action["kind"] in KINDS)
    authority = allocation.AuthorityRegistration.parse(action["authority"])
    require(authority.protected_branch)
    source = provider = None
    if native:
        from ._desktop_version_allocation_source_protocol import SourceRequest
        from ._desktop_version_allocation_source_provider import Provider
        source = SourceRequest.parse(action["source"])
        provider = Provider.parse(action["provider"], source)
    return Initial(policy._match(row["id"], _ID), action["kind"], state._local_project_id(action["localProjectId"]),
                   authority, _id(action["accountId"]), allocation._uuid(action["candidateId"]),
                   policy._match(action["requestSha256"], policy._DIGEST), _clock(action["clock"]),
                   hashlib.sha256(raw).hexdigest(), source, provider)


def ready_frame(initial: Initial) -> bytes:
    return encoded({"protocol": message_protocol(initial), "id": initial.id, "ready": {"requestSha256": initial.digest}}, READY_LIMIT)


@dataclass(frozen=True, slots=True, repr=False)
class Go:
    token: str
    request: allocation.AllocationRequest
    snapshot: state.NativeStateSnapshot
    observations: allocation.StoreObservations


def bound_request(initial: Initial, request: allocation.AllocationRequest) -> None:
    require(type(request) is allocation.AllocationRequest and request.version_policy.mode == "automatic"
            and request.sha256 == initial.request_sha256 and request.candidate_id == initial.candidate_id
            and request.project_id == initial.authority.project_id)
    if initial.source is not None:
        require(request.version_policy.schema_version == 2 and request.enabled_platforms == ("ios",)
                and initial.source.matches(request.source))


def parse_go(raw: bytes, initial: Initial) -> Go:
    row = policy._object(frame(raw, GO_LIMIT), {"protocol", "id", "go"})
    require(row["protocol"] == message_protocol(initial) and row["id"] == initial.id)
    go = policy._object(row["go"], {"requestSha256", "token", "request", "state", "observations"})
    require(go["requestSha256"] == initial.digest)
    token = go["token"]
    require(type(token) is str and 1 <= len(token) <= TOKEN_LIMIT and all(0x21 <= ord(c) <= 0x7e for c in token))
    require(len(policy.canonical(go["request"])) <= REQUEST_LIMIT)
    request = allocation.AllocationRequest.parse(go["request"])
    bound_request(initial, request)
    record = policy._object(go["state"], {"revision", "payload"})
    payload = record["payload"]
    require(type(payload) is str and 0 < len(payload) <= STATE_BASE64_LIMIT)
    try:
        decoded = base64.b64decode(payload, validate=True)
    except (ValueError, UnicodeError):
        raise ProtocolError("Private allocation state was refused") from None
    require(base64.b64encode(decoded).decode("ascii") == payload)
    snapshot = state.NativeStateSnapshot(record["revision"], decoded)
    if initial.source is not None:
        # SAME finite native subset before the ordinary typed state parser.
        # Neither an oversized namespace nor a tiny-map DOM bomb is truncated.
        require(len(decoded) <= 256 * 1024 and decoded.endswith(b"\n"))
        _decode_json(decoded[:-1], limit=256 * 1024 - 1, nodes=4096, depth=20, exact=True)
    retained = state.AllocationState.parse(snapshot.payload)
    selected = retained.enrolled(initial.local_project_id, initial.authority)
    candidate = retained.candidate(initial.local_project_id)
    require(candidate is not None and candidate.request == request)
    require((initial.kind == "reconcile") == (selected.pending is not None))
    if selected.pending is not None:
        require(selected.pending.reservation.request == request)
    require(type(go["observations"]) is list and len(go["observations"]) <= 2
            and len(policy.canonical(go["observations"])) <= OBSERVATIONS_LIMIT)
    observations = allocation.parse_observations(request, go["observations"])
    require(request.version_policy.schema_version == 1 or len(observations) == 1
            or (initial.kind == "reconcile" and not observations))
    return Go(token, request, snapshot, observations)


def transition(value: object, initial: Initial, request: allocation.AllocationRequest) -> dict:
    bound_request(initial, request)
    require(type(value) is dict and type(value.get("kind")) is str)
    kind = value["kind"]
    keys = {"checkpoint": {"kind", "checkpoint"}, "pending": {"kind", "pending"},
            "rejected": {"kind", "pending"}, "resolved": {"kind", "pending", "checkpoint"},
            "reused": {"kind", "reservation", "checkpoint"}}.get(kind)
    require(keys is not None)
    row = policy._object(value, keys)
    if "checkpoint" in row:
        allocation.Checkpoint.parse(row["checkpoint"])
    if "pending" in row:
        pending = allocation.PendingAllocation.parse(policy.canonical(row["pending"]) + b"\n")
        require(pending.authority == initial.authority and pending.reservation.request == request)
    if "reservation" in row:
        require(allocation.Reservation.parse(row["reservation"]).request == request)
    if initial.kind == "reconcile":
        require(kind in {"checkpoint", "resolved"})  # Never clear/re-send an unknown original sender.
    require(len(policy.canonical(row)) <= TRANSITION_LIMIT)
    return row


def state_frame(initial: Initial, request: allocation.AllocationRequest, sequence: int,
                expected_revision: int, payload_sha256: str, change: dict) -> bytes:
    policy._integer(sequence, MAX_TRANSITIONS, 1)
    policy._integer(expected_revision, state.MAX_REVISION - 1)
    policy._match(payload_sha256, policy._DIGEST)
    return encoded({"protocol": message_protocol(initial), "id": initial.id, "state": {
        "requestSha256": initial.digest, "sequence": sequence, "expectedRevision": expected_revision,
        "payloadSha256": payload_sha256, "transition": transition(change, initial, request)}}, STATE_FRAME_LIMIT)


def parse_ack(raw: bytes, initial: Initial, *, sequence: int, expected_revision: int, payload_sha256: str) -> None:
    row = policy._object(frame(raw, ACK_LIMIT, nodes=64, depth=4), {"protocol", "id", "ack"})
    require(row["protocol"] == message_protocol(initial) and row["id"] == initial.id)
    ack = policy._object(row["ack"], {"requestSha256", "sequence", "revision", "payloadSha256", "effect", "durability", "cleanup"})
    require(type(ack["sequence"]) is int and ack["sequence"] == sequence
            and type(ack["revision"]) is int and ack["revision"] == expected_revision + 1
            and ack["requestSha256"] == initial.digest and ack["payloadSha256"] == payload_sha256
            and ack["effect"] == "committed" and ack["durability"] == "durable" and ack["cleanup"] == "settled")


def finish_frame(initial: Initial, request: allocation.AllocationRequest, outcome: allocation.AllocationOutcome,
                 *, sequence: int, snapshot: state.NativeStateSnapshot) -> bytes:
    bound_request(initial, request)
    policy._integer(sequence, MAX_TRANSITIONS)
    require(type(snapshot) is state.NativeStateSnapshot and type(outcome) is allocation.AllocationOutcome
            and outcome.status in {"reserved", "conflict", "rejected", "unavailable", "recovery-required"}
            and outcome.reason in allocation.REASONS and type(outcome.write_claimed) is bool
            and type(outcome.write_acknowledged) is bool and (not outcome.write_acknowledged or outcome.write_claimed))
    _check_control(outcome.control)
    require((outcome.status == "reserved") == (outcome.reservation is not None))
    if initial.kind == "reconcile":
        require(not outcome.write_claimed and not outcome.write_acknowledged)
    if outcome.reservation is not None:
        require(outcome.control["reason"] == "none")
        retained = state.AllocationState.parse(snapshot.payload)
        selected = retained.enrolled(initial.local_project_id, initial.authority)
        candidate = retained.candidate(initial.local_project_id)
        require(outcome.reason == "none" and outcome.reservation.request == request and selected.pending is None
                and selected.checkpoint == outcome.checkpoint and candidate is not None
                and candidate.reservation == outcome.reservation)
    return encoded({"protocol": message_protocol(initial), "id": initial.id, "finished": {
        "requestSha256": initial.digest, "sequence": sequence, "revision": snapshot.revision,
        "payloadSha256": hashlib.sha256(snapshot.payload).hexdigest(), "outcome": outcome.value()}}, FIN_LIMIT)
