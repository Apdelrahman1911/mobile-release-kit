"""Closed project recovery DATA; private review stamps never reach the renderer.

The native application selects one registered project and owns one-use consent.
Core observation is not process finality. Native still joins every original.
"""
from __future__ import annotations

import json
import re
import stat
from dataclasses import dataclass
from typing import Any

PROTOCOL = "mrk-project-recovery/1"
CONSENT = "reviewed-project-build-input-recovery-v1"
REQUEST_LIMIT, RESPONSE_LIMIT = 16 * 1024, 32 * 1024
WORK_SECONDS, FINALITY_SECONDS = 120, 130
SCOPE = "project-build-inputs-only"
PROFILES = {"linux-gnu-x86_64": ("linux", "x86_64"), "linux-gnu-aarch64": ("linux", "aarch64"),
            "macos-x86_64": ("macos", "x86_64"), "macos-arm64": ("macos", "arm64")}
REASONS = frozenset(("none", "cancelled", "context-changed", "document-lost", "shutdown", "timed-out",
    "protocol-error", "runtime-unavailable", "intent-expired", "stale-intent", "project-changed",
    "review-stale", "manual-required", "project-busy", "project-conflict", "recovery-incomplete",
    "input-limit", "result-limit", "cleanup-unknown"))
OUTCOMES = frozenset(("complete", "refused", "cancelled", "timed-out", "failed", "unknown"))
LIMITATIONS = ("build-inputs-only-not-store-or-account-recovery", "recorded-quiescence-not-new-worker-proof",
              "foreign-changes-preserved", "cancellation-does-not-undo-completed-cleanup",
              "project-and-release-readiness-not-assessed")
_TOKEN = re.compile(r"[0-9a-f]{32}\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_PROJECT = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
_DECIMAL = re.compile(r"(?:0|[1-9][0-9]{0,19})\Z")


class ProtocolError(ValueError):
    """Fixed public diagnostic only, with no rejected input or private text."""


def require(condition: bool) -> None:
    if not condition:
        raise ProtocolError("Invalid project recovery protocol")


def integer(value: object, maximum: int, minimum: int = 0) -> bool:
    return type(value) is int and minimum <= value <= maximum


def _text(value: object, pattern: re.Pattern) -> bool:
    return type(value) is str and pattern.fullmatch(value) is not None


def _enum(value: object, choices) -> bool:
    return type(value) is str and value in choices


def _keys(value: object, fields: set[str]) -> dict:
    require(type(value) is dict and all(type(key) is str for key in value) and set(value) == fields)
    return value


def _pairs(values: list[tuple[str, Any]]) -> dict:
    result = {}
    for key, value in values:
        require(key not in result)
        result[key] = value
    return result


def _structure(value: object, depth: int = 0, count: list[int] | None = None) -> None:
    if count is None:
        count = [0]
    count[0] += 1
    require(count[0] <= 2048 and depth <= 12)
    if type(value) is dict:
        for key, item in value.items():
            require(type(key) is str)
            _structure(key, depth + 1, count)
            _structure(item, depth + 1, count)
    elif type(value) is list:
        for item in value:
            _structure(item, depth + 1, count)
    elif type(value) is str:
        require(len(value.encode("utf-8")) <= 4096)
    elif type(value) is int:
        require(abs(value) <= 2**53 - 1)
    else:
        require(value is None or type(value) is bool)


def observation(value: object) -> dict:
    value = _keys(value, {"status", "session", "roles", "quiescence"})
    require(_enum(value["status"], {"idle", "busy", "conflict", "pending", "cleanup-only"})
            and _enum(value["quiescence"], {"none", "original", "operator"})
            and type(value["roles"]) is list and len(value["roles"]) <= 2
            and all(_enum(role, {"android-services", "ios-services"}) for role in value["roles"])
            and value["roles"] == sorted(set(value["roles"])))
    if value["status"] in {"idle", "busy", "conflict"}:
        require(value["session"] is None and not value["roles"] and value["quiescence"] == "none")
    else:
        require(_text(value["session"], _TOKEN))
        if value["status"] == "cleanup-only":
            require(not value["roles"] and value["quiescence"] != "none")
    return {**value, "roles": list(value["roles"])}


def eligible(value: dict) -> bool:
    return value["status"] in {"pending", "cleanup-only"} and value["quiescence"] in {"original", "operator"}


def context(value: object) -> dict:
    value = _keys(value, {"projectId", "draftRevision", "baselineGeneration", "action", "review"})
    require(_text(value["projectId"], _PROJECT) and integer(value["draftRevision"], 2**32 - 2)
            and integer(value["baselineGeneration"], 2**32 - 2) and _enum(value["action"], {"inspect", "recover"}))
    if value["action"] == "inspect":
        require(value["review"] is None)
        return dict(value)
    review = observation(value["review"])
    require(eligible(review))
    return {**value, "review": review}


def _path(value: object) -> str:
    require(type(value) is str and value.startswith("/") and len(value.encode("utf-8")) <= 4096)
    if value != "/":
        parts = value[1:].split("/")
        require(len(parts) <= 128 and all(part not in {"", ".", ".."} and len(part.encode("utf-8")) <= 255
                and not any(ord(c) < 32 or ord(c) == 127 or c in "\\:" for c in part) for part in parts))
    return value


@dataclass(frozen=True)
class ProjectRecoveryRequest:
    operation_id: str
    owner_generation: str
    context: dict
    native: dict


def parse_request(raw: bytes) -> ProjectRecoveryRequest:
    require(type(raw) is bytes and 1 <= len(raw) <= REQUEST_LIMIT and raw.endswith(b"\n")
            and raw.count(b"\n") == 1 and not raw.startswith(b"\xef\xbb\xbf"))
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs, parse_float=lambda _: require(False),
                           parse_constant=lambda _: require(False))
        _structure(value)
    except (ValueError, UnicodeError, TypeError, RecursionError):
        raise ProtocolError("Invalid project recovery protocol") from None
    value = _keys(value, {"protocol", "operationId", "ownerGeneration", "context", "native"})
    require(value["protocol"] == PROTOCOL and _text(value["operationId"], _TOKEN)
            and _text(value["ownerGeneration"], _TOKEN))
    selected = context(value["context"])
    native = _keys(value["native"], {"profile", "projectRoot", "rootIdentity", "cwd", "reviewStamp"})
    require(_enum(native["profile"], PROFILES))
    _path(native["projectRoot"])
    _path(native["cwd"])
    identity = _keys(native["rootIdentity"], {"device", "inode", "mode", "uid", "gid"})
    for key in ("device", "inode"):
        require(_text(identity[key], _DECIMAL) and int(identity[key]) <= 2**64 - 1)
    require(identity["inode"] != "0" and all(integer(identity[key], 2**32 - 1) for key in ("mode", "uid", "gid"))
            and stat.S_ISDIR(identity["mode"]))
    require(native["reviewStamp"] is None if selected["action"] == "inspect" else _text(native["reviewStamp"], _SHA))
    return ProjectRecoveryRequest(value["operationId"], value["ownerGeneration"], selected,
                                  {**native, "rootIdentity": dict(identity)})


def result(request: ProjectRecoveryRequest, *, inspected: dict | None = None, recovered: str | None = None) -> dict:
    value = {"schemaVersion": 1, "scope": SCOPE, "action": request.context["action"],
             "observation": inspected, "recoveredSession": recovered, "limitations": list(LIMITATIONS)}
    validate_result(value, request.context)
    return value


def validate_result(value: object, selected: dict) -> None:
    value = _keys(value, {"schemaVersion", "scope", "action", "observation", "recoveredSession", "limitations"})
    require(type(value["schemaVersion"]) is int and value["schemaVersion"] == 1 and value["scope"] == SCOPE
            and value["action"] == selected["action"] and value["limitations"] == list(LIMITATIONS))
    if value["action"] == "inspect":
        observation(value["observation"])
        require(value["recoveredSession"] is None)
    else:
        require(value["observation"] is None and value["recoveredSession"] == selected["review"]["session"])


def validate_terminal(value: object, request: ProjectRecoveryRequest) -> None:
    value = _keys(value, {"schemaVersion", "context", "outcome", "reason", "result", "effect", "reviewStamp", "lifetime"})
    require(type(value["schemaVersion"]) is int and value["schemaVersion"] == 1
            and context(value["context"]) == request.context and _enum(value["outcome"], OUTCOMES)
            and _enum(value["reason"], REASONS)
            and _enum(value["effect"], {"not-attempted", "inspection", "recovery-attempted"}))
    require(value["effect"] != "inspection" or request.context["action"] == "inspect")
    require(value["effect"] != "recovery-attempted" or request.context["action"] == "recover")
    life = _keys(value["lifetime"], {"complete", "fatal", "contained", "commandDispatched", "commands", "profileCalls",
                                  "inputClosed", "handlersRestored", "resourcesClosed", "stopObserved"})
    require(all(type(life[key]) is bool for key in ("complete", "fatal", "contained", "inputClosed",
            "handlersRestored", "resourcesClosed"))
            and (life["commandDispatched"] is None or life["commandDispatched"] is False)
            and type(life["commands"]) is int and life["commands"] == 0
            and type(life["profileCalls"]) is int and life["profileCalls"] == 0
            and _enum(life["stopObserved"], {"none", "cancelled", "timed-out"}))
    settled = (life["complete"] and not life["fatal"] and life["contained"] and life["inputClosed"]
               and life["handlersRestored"] and life["resourcesClosed"] and life["commandDispatched"] is False)
    if value["outcome"] == "complete":
        require(settled and life["stopObserved"] == "none" and value["reason"] == "none"
                and value["effect"] == ("inspection" if request.context["action"] == "inspect" else "recovery-attempted"))
        validate_result(value["result"], request.context)
        if request.context["action"] == "inspect" and eligible(value["result"]["observation"]):
            require(_text(value["reviewStamp"], _SHA))
        else:
            require(value["reviewStamp"] is None)
    else:
        require(value["result"] is None and value["reviewStamp"] is None and value["reason"] != "none"
                and (settled or value["outcome"] == "unknown"))
        if value["outcome"] == "unknown":
            require(value["reason"] == "cleanup-unknown" and not settled)
        if value["outcome"] in {"cancelled", "timed-out"}:
            require(value["reason"] == value["outcome"] == life["stopObserved"])


def response(request: ProjectRecoveryRequest, kind: str, payload: dict) -> bytes:
    require(type(request) is ProjectRecoveryRequest and kind in {"accepted", "terminal"})
    if kind == "accepted":
        require(payload == {"schemaVersion": 1, "context": request.context})
    else:
        validate_terminal(payload, request)
    value = {"protocol": PROTOCOL, "operationId": request.operation_id, "ownerGeneration": request.owner_generation,
             "sequence": 0 if kind == "accepted" else 1, "kind": kind, "payload": payload}
    _structure(value)
    raw = json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii") + b"\n"
    require(len(raw) <= RESPONSE_LIMIT)
    return raw
