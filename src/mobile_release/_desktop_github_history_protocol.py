"""One private History initial/READY/GO/result grammar; DATA is not authority."""
from __future__ import annotations

import hashlib
import json
import re
import stat
from dataclasses import dataclass
from typing import Any

from .errors import ValidationError
from .github_history import (HistoryBudget, HistoryContext, REFUSED, UNAVAILABLE,
    _decode_json, _hex, _integer, _keys, _text, parse_result)

PROTOCOL = "mrk-github-history/1"
WORK_SECONDS, FINALITY_SECONDS = 900, 910
REQUEST_LIMIT, GO_LIMIT, READY_LIMIT, RESULT_LIMIT = 16384, 8192, 512, 32768
PROVIDER_RELATIVE = "tools/gh"
CONFIG_RELATIVE = "release/mobile-release.json"
REASONS = REFUSED | UNAVAILABLE | frozenset(("none", "not-connected", "busy", "cancelled", "expired", "cleanup-unknown"))


class ProtocolError(ValidationError):
    """Fixed private framing failure; never include credential/input text."""


def require(condition: bool) -> None:
    if not condition:
        raise ProtocolError("History private protocol is invalid")


def _id(value: object) -> str:
    text = _text(value, 64)
    require(re.fullmatch(r"[A-Za-z0-9_-]{1,64}", text) is not None)
    return text


def _u64(value: object, *, zero: bool = False) -> str:
    text = _text(value, 20)
    require(re.fullmatch(r"0|[1-9][0-9]*", text) is not None
            and (0 if zero else 1) <= int(text) <= (1 << 64) - 1)
    return text


def _i64(value: object) -> str:
    text = _text(value, 20)
    require(re.fullmatch(r"0|-?[1-9][0-9]*", text) is not None
            and -(1 << 63) <= int(text) < (1 << 63))
    return text


def _path(value: object) -> str:
    text = _text(value, 4096)
    require(len(text.encode("utf-8")) <= 4096 and text.startswith("/")
            and text != "/" and all(part not in ("", ".", "..") for part in text[1:].split("/")))
    return text


def _identity(value: object, *, directory: bool) -> dict[str, Any]:
    names = ("device", "inode", "mode", "uid", "gid")
    if not directory:
        names += ("nlink", "bytes", "mtimeSeconds", "mtimeNanos", "ctimeSeconds", "ctimeNanos", "flags")
    row = _keys(value, names)
    _u64(row["device"]); _u64(row["inode"])
    for key in ("mode", "uid", "gid"):
        _integer(row[key], 0, (1 << 32) - 1)
    require(stat.S_ISDIR(row["mode"]) if directory else stat.S_ISREG(row["mode"]))
    if not directory:
        require(_u64(row["nlink"]) == "1")
        _u64(row["bytes"], zero=True)
        for key in ("mtimeSeconds", "ctimeSeconds"):
            _i64(row[key])
        for key in ("mtimeNanos", "ctimeNanos"):
            _integer(row[key], 0, 999999999)
        _integer(row["flags"], 0, (1 << 32) - 1)
    return dict(row)


def _frame(raw: bytes, maximum: int, budget: HistoryBudget) -> Any:
    require(type(raw) is bytes and 1 < len(raw) <= maximum and raw.endswith(b"\n")
            and raw.count(b"\n") == 1 and b"\r" not in raw)
    return _decode_json(raw[:-1], budget)


def canonical(value: object, maximum: int) -> bytes:
    raw = json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True,
                     separators=(",", ":")).encode("utf-8") + b"\n"
    require(len(raw) <= maximum)
    return raw


@dataclass(frozen=True, slots=True, repr=False)
class HistoryRequest:
    id: str
    owner_generation: str
    context: HistoryContext
    native: dict[str, Any]
    digest: str


def parse_request(raw: bytes, budget: HistoryBudget) -> HistoryRequest:
    row = _keys(_frame(raw, REQUEST_LIMIT, budget), ("protocol", "id", "ownerGeneration", "context", "native"))
    require(type(row["protocol"]) is str and row["protocol"] == PROTOCOL)
    context = HistoryContext.parse(row["context"])
    native = _keys(row["native"], ("profile", "projectRoot", "rootIdentity", "configIdentity",
        "workRoot", "workIdentity", "provider", "parentDescriptorReservation", "clock"))
    require(type(native["profile"]) is str and native["profile"] in ("macos-arm64", "macos-x86_64"))
    root, work = _path(native["projectRoot"]), _path(native["workRoot"])
    require(work != root and not work.startswith(root + "/"))
    root_identity = _identity(native["rootIdentity"], directory=True)
    work_identity = _identity(native["workIdentity"], directory=True)
    require(stat.S_IMODE(work_identity["mode"]) == 0o700)
    config = _identity(native["configIdentity"], directory=False)
    require(0 < int(config["bytes"]) <= 512 * 1024)
    provider = _keys(native["provider"], ("relativePath", "version", "target", "sourceManifestSha256", "sha256", "identity"))
    require(provider["relativePath"] == PROVIDER_RELATIVE and provider["version"] == "2.88.1"
            and provider["target"] == {"macos-arm64": "aarch64-apple-darwin", "macos-x86_64": "x86_64-apple-darwin"}[native["profile"]])
    _hex(provider["sourceManifestSha256"], 64); _hex(provider["sha256"], 64)
    provider_identity = _identity(provider["identity"], directory=False)
    require(0 < int(provider_identity["bytes"]) <= 128 * 1024 * 1024
            and provider_identity["uid"] == 0 and provider_identity["gid"] == 0
            and provider_identity["mode"] & 0o222 == 0 and provider_identity["mode"] & 0o111 != 0)
    _integer(native["parentDescriptorReservation"], 0, 56)
    clock = _keys(native["clock"], ("name", "workEndNs", "hardEndNs"))
    require(clock["name"] == "CLOCK_UPTIME_RAW")
    work_end, hard_end = int(_u64(clock["workEndNs"])), int(_u64(clock["hardEndNs"]))
    require(work_end <= hard_end <= work_end + 10_000_000_000)
    native = {**native, "projectRoot": root, "workRoot": work, "rootIdentity": root_identity,
        "workIdentity": work_identity, "configIdentity": config,
        "provider": {**provider, "identity": provider_identity}, "clock": dict(clock)}
    return HistoryRequest(_id(row["id"]), _id(row["ownerGeneration"]), context, native,
                          hashlib.sha256(raw).hexdigest())


def ready_frame(request: HistoryRequest) -> bytes:
    require(type(request) is HistoryRequest)
    return canonical({"protocol": PROTOCOL, "id": request.id,
                      "ready": {"requestSha256": request.digest}}, READY_LIMIT)


def parse_go(raw: bytes, request: HistoryRequest, budget: HistoryBudget) -> str:
    require(type(request) is HistoryRequest)
    row = _keys(_frame(raw, GO_LIMIT, budget), ("protocol", "id", "go"))
    require(row["protocol"] == PROTOCOL and row["id"] == request.id)
    go = _keys(row["go"], ("requestSha256", "token"))
    require(go["requestSha256"] == request.digest)
    token = go["token"]
    require(type(token) is str and 1 <= len(token) <= 4096
            and all(0x21 <= ord(char) <= 0x7e for char in token))
    return token


def terminal_frame(request: HistoryRequest, result: object, reason: str, lifetime: object) -> bytes:
    require(type(request) is HistoryRequest and type(reason) is str and reason in REASONS)
    life = _keys(lifetime, ("complete", "fatal", "contained", "commandDispatched", "commands", "verifierCalls",
                            "inputClosed", "handlersRestored", "invocationClosed", "stopObserved"))
    for key in ("complete", "fatal", "contained", "inputClosed", "handlersRestored", "invocationClosed", "stopObserved"):
        require(type(life[key]) is bool)
    require(life["commandDispatched"] is None or type(life["commandDispatched"]) is bool)
    _integer(life["commands"], 0, 128); _integer(life["verifierCalls"], 0, 19)
    require(life["verifierCalls"] <= life["commands"]
            and (life["commandDispatched"] is not True or life["commands"] > 0))
    if result is not None:
        require(reason == "none" and all(life[k] for k in ("complete", "contained", "inputClosed", "handlersRestored", "invocationClosed"))
                and not life["fatal"] and not life["stopObserved"] and type(life["commandDispatched"]) is bool)
        result = parse_result(result, request.context)
    else:
        require(reason not in ("none", "busy", "not-connected"))
    return canonical({"protocol": PROTOCOL, "id": request.id, "requestSha256": request.digest,
        "result": result, "reason": reason, "lifetime": dict(life)}, RESULT_LIMIT)
