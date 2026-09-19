"""Closed, redacted DATA for the one saved Android offline-preflight action.

No report messages, details, paths, command arguments or exception text cross
this boundary. Core terminal DATA is provisional until original native finality.
"""
from __future__ import annotations

import json
import math
import re
import stat
from dataclasses import dataclass
from typing import Any

from .config import MAX_CONFIG_BYTES

PROTOCOL = "mrk-offline-preflight/1"
CONSENT = "saved-offline-android-v1"
REQUEST_LIMIT, RESPONSE_LIMIT = 16 * 1024, 64 * 1024
WORK_SECONDS, FINALITY_SECONDS = 1800, 1810
SCOPE = "saved-offline-android-no-core-build"
PROFILES = {"linux-gnu-x86_64": ("linux", "x86_64"), "linux-gnu-aarch64": ("linux", "aarch64"),
            "macos-x86_64": ("macos", "x86_64"), "macos-arm64": ("macos", "arm64")}
STATUSES = ("PASS", "FAIL", "MISSING", "BLOCKED", "INVALID", "SKIP", "MANUAL", "CONFIGURED", "NOT_APPLICABLE")
CHECKS = ("version-source", "platform-selection", "android-module", "android-gradle-wrapper",
          "android-debug-identity", "workspace-private-output", "android-artifact", "preflight-early-exit",
          "configuration-policy", "metadata-policy", "configured-project-check", "core-lifecycle", "other-core-finding")
LIMITATIONS = ("saved-inputs-not-atomic", "project-code-effects-possible", "not-network-isolated",
              "core-builds-disabled", "artifact-validation-not-requested",
              "toolkit-signing-credentials-store-not-requested", "release-readiness-not-assessed")
REASONS = frozenset(("none", "cancelled", "context-changed", "document-lost", "shutdown", "timed-out",
    "protocol-error", "runtime-unavailable", "intent-expired", "stale-intent", "saved-config-missing",
    "saved-config-invalid", "saved-config-changed", "saved-config-sensitive", "saved-config-unsafe",
    "saved-config-too-large", "platform-disabled", "project-admission-refused", "input-limit", "result-limit",
    "command-incomplete", "cleanup-unknown"))
OUTCOMES = frozenset(("complete", "refused", "cancelled", "timed-out", "failed", "unknown"))
_TOKEN = re.compile(r"[0-9a-f]{32}\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_PROJECT = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
_DECIMAL = re.compile(r"(?:0|[1-9][0-9]{0,19})\Z")
_PROJECT_CHECK = re.compile(r"project-check\.preflight\.(0|[1-9]|[12][0-9]|3[01])\Z")


class ProtocolError(ValueError):
    """Fixed failure only; a caller's rejected value is never a UI message."""


def require(condition: bool) -> None:
    if not condition:
        raise ProtocolError("Invalid saved offline-preflight protocol")


def integer(value: object, maximum: int, minimum: int = 0) -> bool:
    return type(value) is int and minimum <= value <= maximum


def _keys(value: object, fields: set[str]) -> dict:
    require(type(value) is dict and set(value) == fields)
    return value


def _pairs(values: list[tuple[str, Any]]) -> dict:
    result = {}
    for key, value in values:
        require(key not in result)
        result[key] = value
    return result


def _structure(value: object, *, depth: int = 0, count: list[int] | None = None) -> None:
    if count is None:
        count = [0]
    count[0] += 1
    require(count[0] <= 8192 and depth <= 16)
    if type(value) is dict:
        for key, item in value.items():
            require(type(key) is str)
            _structure(key, depth=depth + 1, count=count)
            _structure(item, depth=depth + 1, count=count)
    elif type(value) is list:
        for item in value:
            _structure(item, depth=depth + 1, count=count)
    elif type(value) is str:
        require(len(value.encode("utf-8")) <= 4096)
    elif type(value) is int:
        require(abs(value) <= 2**53 - 1)
    else:
        require(value is None or type(value) is bool or type(value) is float and math.isfinite(value))


def content(value: object) -> dict:
    value = _keys(value, {"bytes", "sha256"})
    require(integer(value["bytes"], MAX_CONFIG_BYTES, 1)
            and type(value["sha256"]) is str and _SHA.fullmatch(value["sha256"]) is not None)
    return dict(value)


def context(value: object) -> dict:
    value = _keys(value, {"projectId", "draftRevision", "baselineGeneration", "savedConfig", "platform", "operation"})
    require(type(value["projectId"]) is str and _PROJECT.fullmatch(value["projectId"]) is not None
            and integer(value["draftRevision"], 2**32 - 2) and integer(value["baselineGeneration"], 2**32 - 2)
            and value["platform"] == "android" and value["operation"] == "offline-preflight")
    return {**value, "savedConfig": content(value["savedConfig"])}


def _path(value: object) -> str:
    require(type(value) is str and value.startswith("/") and len(value.encode("utf-8")) <= 4096)
    if value != "/":
        parts = value[1:].split("/")
        require(len(parts) <= 128 and all(part not in {"", ".", ".."} and len(part.encode("utf-8")) <= 255
                and not any(ord(c) < 32 or ord(c) == 127 or c in "\\:" for c in part) for part in parts))
    return value


@dataclass(frozen=True)
class PreflightRequest:
    operation_id: str
    owner_generation: str
    context: dict
    native: dict


def parse_request(raw: bytes) -> PreflightRequest:
    require(type(raw) is bytes and 1 <= len(raw) <= REQUEST_LIMIT and raw.endswith(b"\n")
            and raw.count(b"\n") == 1 and not raw.startswith(b"\xef\xbb\xbf"))
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs,
                           parse_constant=lambda _: require(False))
        _structure(value)
    except (ValueError, UnicodeError, RecursionError):
        raise ProtocolError("Invalid saved offline-preflight protocol") from None
    value = _keys(value, {"protocol", "operationId", "ownerGeneration", "context", "native"})
    require(value["protocol"] == PROTOCOL and type(value["operationId"]) is str
            and _TOKEN.fullmatch(value["operationId"]) is not None and type(value["ownerGeneration"]) is str
            and _TOKEN.fullmatch(value["ownerGeneration"]) is not None)
    selected = context(value["context"])
    native = _keys(value["native"], {"profile", "projectRoot", "rootIdentity", "cwd"})
    require(type(native["profile"]) is str and native["profile"] in PROFILES)
    _path(native["projectRoot"])
    _path(native["cwd"])
    identity = _keys(native["rootIdentity"], {"device", "inode", "mode", "uid", "gid"})
    for field in ("device", "inode"):
        require(type(identity[field]) is str and _DECIMAL.fullmatch(identity[field]) is not None
                and int(identity[field]) <= 2**64 - 1)
    require(identity["inode"] != "0" and all(integer(identity[key], 2**32 - 1) for key in ("mode", "uid", "gid"))
            and stat.S_ISDIR(identity["mode"]))
    return PreflightRequest(value["operationId"], value["ownerGeneration"], selected,
                            {**native, "rootIdentity": dict(identity)})


def project_finding(code: str, category: str) -> tuple[str, int | None]:
    exact = {"version.source": "version-source", "platform.selection": "platform-selection",
        "android.module": "android-module", "android.gradle-wrapper": "android-gradle-wrapper",
        "android.debug-identity": "android-debug-identity", "workspace.private-output": "workspace-private-output",
        "android.artifact": "android-artifact", "preflight.early-exit": "preflight-early-exit"}
    if code in exact:
        return exact[code], None
    match = _PROJECT_CHECK.fullmatch(code)
    if match is not None:
        return "configured-project-check", int(match[1])
    if code == "project-check.preflight":
        return "configured-project-check", None
    if code.startswith("metadata."):
        return "metadata-policy", None
    if category == "configuration":
        return "configuration-policy", None
    if code in {"preflight.process-lifetime", "preflight.build-input-ownership", "preflight.artifact-input-exit"}:
        return "core-lifecycle", None
    return "other-core-finding", None


def project_result(report, used: dict) -> dict:
    from .reporting import Report, Finding, Status
    require(type(report) is Report and len(report.findings) <= 4096)
    rows, counts = [], {status: 0 for status in STATUSES}
    for ordinal, finding in enumerate(report.findings):
        require(type(finding) is Finding and type(finding.code) is str and type(finding.status) is Status)
        counts[finding.status.value] += 1
        if ordinal < 128:
            check, index = project_finding(finding.code, finding.category)
            rows.append({"ordinal": ordinal, "check": check, "status": finding.status.value,
                         "message": check, "projectCheckIndex": index})
    result = {"schemaVersion": 1, "scope": SCOPE, "usedConfig": content(used), "findings": rows,
              "summary": {"total": len(report.findings), "shown": len(rows),
                          "omitted": len(report.findings) - len(rows), "counts": counts},
              "limitations": list(LIMITATIONS)}
    validate_result(result)
    return result


def validate_result(value: object) -> None:
    value = _keys(value, {"schemaVersion", "scope", "usedConfig", "findings", "summary", "limitations"})
    require(type(value["schemaVersion"]) is int and value["schemaVersion"] == 1 and value["scope"] == SCOPE
            and type(value["limitations"]) is list and value["limitations"] == list(LIMITATIONS))
    content(value["usedConfig"])
    summary = _keys(value["summary"], {"total", "shown", "omitted", "counts"})
    counts = _keys(summary["counts"], set(STATUSES))
    require(all(integer(summary[key], 4096) for key in ("total", "shown", "omitted"))
            and all(integer(n, 4096) for n in counts.values()) and sum(counts.values()) == summary["total"]
            and summary["shown"] == min(summary["total"], 128)
            and summary["omitted"] == summary["total"] - summary["shown"]
            and type(value["findings"]) is list and len(value["findings"]) == summary["shown"])
    shown = {status: 0 for status in STATUSES}
    for ordinal, row in enumerate(value["findings"]):
        row = _keys(row, {"ordinal", "check", "status", "message", "projectCheckIndex"})
        require(type(row["ordinal"]) is int and row["ordinal"] == ordinal and row["check"] in CHECKS
                and row["message"] == row["check"] and row["status"] in STATUSES
                and (row["projectCheckIndex"] is None or row["check"] == "configured-project-check"
                     and integer(row["projectCheckIndex"], 31)))
        shown[row["status"]] += 1
    require(all(shown[key] <= counts[key] for key in STATUSES))


def validate_terminal(value: object, request: PreflightRequest) -> None:
    value = _keys(value, {"schemaVersion", "context", "outcome", "reason", "result", "lifetime"})
    require(type(value["schemaVersion"]) is int and value["schemaVersion"] == 1
            and context(value["context"]) == request.context
            and value["outcome"] in OUTCOMES and value["reason"] in REASONS)
    life = _keys(value["lifetime"], {"complete", "fatal", "contained", "commandDispatched", "commands", "profileCalls",
                                  "inputClosed", "handlersRestored", "invocationClosed", "stopObserved"})
    require(all(type(life[key]) is bool for key in ("complete", "fatal", "contained", "inputClosed",
            "handlersRestored", "invocationClosed")) and (life["commandDispatched"] is None
            or type(life["commandDispatched"]) is bool) and integer(life["commands"], 4096)
            and type(life["profileCalls"]) is int and life["profileCalls"] == 0
            and life["stopObserved"] in {"none", "cancelled", "timed-out"})
    settled = (life["complete"] and not life["fatal"] and life["contained"] and life["inputClosed"]
               and life["handlersRestored"] and life["invocationClosed"] and life["commandDispatched"] is not None)
    if value["outcome"] == "complete":
        require(settled and life["stopObserved"] == "none" and value["reason"] == "none")
        validate_result(value["result"])
        require(value["result"]["usedConfig"] == request.context["savedConfig"])
    else:
        require(value["result"] is None and value["reason"] != "none")
        require(settled or value["outcome"] == "unknown")
        if value["outcome"] == "unknown":
            require(value["reason"] == "cleanup-unknown" and not settled)
        if value["outcome"] in {"cancelled", "timed-out"}:
            require(value["reason"] == value["outcome"] == life["stopObserved"])


def response(request: PreflightRequest, kind: str, payload: dict) -> bytes:
    require(type(request) is PreflightRequest and kind in {"accepted", "terminal"})
    if kind == "accepted":
        require(payload == {"schemaVersion": 1, "context": request.context})
    else:
        validate_terminal(payload, request)
    value = {"protocol": PROTOCOL, "operationId": request.operation_id,
             "ownerGeneration": request.owner_generation, "sequence": 0 if kind == "accepted" else 1,
             "kind": kind, "payload": payload}
    raw = json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii") + b"\n"
    require(len(raw) <= RESPONSE_LIMIT)
    return raw
