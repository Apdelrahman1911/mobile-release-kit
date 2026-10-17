"""Closed local history wire. Parsed DATA is not key, lease or Store authority."""
from __future__ import annotations
import json
import re
from dataclasses import dataclass
from .local_release_journal import canonical, _enrollment, _uuid
PROTOCOL = "mrk-local-release-history/1"
WORK_SECONDS, FINALITY_SECONDS = 60, 62
REQUEST_LIMIT, RESPONSE_LIMIT = 16 * 1024, 32 * 1024
KEY_PREFIX, KEY_SUFFIX = b"MRK-LOCAL-KEY/1\n", b"\nMRK-LOCAL-KEY-END\n"
class ProtocolError(ValueError):
    def __init__(self, *_ignored): super().__init__("Local release history protocol refused")
def require(value):
    if not value: raise ProtocolError()
def _pairs(pairs):
    out = {}
    for key, value in pairs:
        require(key not in out); out[key] = value
    return out
def decode(raw, maximum=REQUEST_LIMIT):
    require(type(raw) is bytes and 0 < len(raw) <= maximum and raw.endswith(b"\n") and raw.count(b"\n") == 1)
    try: return json.loads(raw, object_pairs_hook=_pairs, parse_constant=lambda _: require(False))
    except (ValueError, TypeError, UnicodeError, RecursionError): raise ProtocolError() from None
def token(value): return type(value) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", value) is not None
def integer(value, maximum, minimum=0): return type(value) is int and minimum <= value <= maximum
def path(value):
    require(type(value) is str and value.startswith("/") and len(value.encode()) <= 4096
            and "\\" not in value and not any(ord(c) < 32 or ord(c) == 127 for c in value)
            and all(v and v not in {".", ".."} for v in value.split("/")[1:]) and len(value.split("/")) <= 128)
    return value
def root(value):
    require(type(value) is dict and set(value) == {"device", "inode", "mode", "uid", "gid"})
    for field in ("device", "inode"):
        require(type(value[field]) is str and re.fullmatch(r"[1-9][0-9]{0,19}", value[field]) is not None
                and int(value[field]) < 1 << 64)
    require(integer(value["mode"], 0o177777) and value["mode"] & 0o170000 == 0o040000
            and value["mode"] & 0o7022 == 0 and integer(value["uid"], (1 << 32)-1, 1)
            and integer(value["gid"], (1 << 32)-1))
    return value
def candidate_action(value):
    return type(value) is dict and value.get("action") in {"review-inputs","abandon-inputs","review-prepared","review-execution","review-reconcile"}
def context(value):
    extra={"candidateOperationId"} if candidate_action(value) else set()
    require(type(value) is dict and set(value)=={"projectId","executionMode","action"}|extra
            and token(value["projectId"]) and value["executionMode"]=="local"
            and value["action"] in {"enroll","verify","review-inputs","abandon-inputs","review-prepared","review-execution","review-reconcile"})
    if extra: require(_uuid(value["candidateOperationId"]))
    return value
@dataclass(frozen=True)
class LocalHistoryRequest:
    operation_id: str
    owner_generation: str
    context: dict
    native: dict
    digest: str

def parse_request(raw):
    import hashlib
    value = decode(raw)
    require(type(value) is dict and set(value) == {"protocol", "operationId", "ownerGeneration", "context", "native"}
            and value["protocol"] == PROTOCOL and token(value["operationId"]) and token(value["ownerGeneration"]))
    n = value["native"]
    require(type(n) is dict and set(n) == {"profile", "projectRoot", "rootIdentity", "leaseFd", "home", "cwd", "nonce", "clock"}
            and n["profile"] in {"macos-arm64", "macos-x86_64"} and integer(n["leaseFd"], 255, 3)
            and type(n["nonce"]) is str and re.fullmatch(r"[0-9a-f]{32}", n["nonce"]) is not None
            and n["nonce"] != "0" * 32)
    for name in ("projectRoot", "home", "cwd"): path(n[name])
    root(n["rootIdentity"])
    require(type(n["clock"]) is dict and set(n["clock"]) == {"workEndNs", "hardEndNs"})
    for v in n["clock"].values(): require(type(v) is str and re.fullmatch(r"[1-9][0-9]{0,19}", v) is not None)
    require(int(n["clock"]["workEndNs"]) <= int(n["clock"]["hardEndNs"]) < 1 << 64
            and int(n["clock"]["hardEndNs"]) - int(n["clock"]["workEndNs"]) <= 2_000_000_000)
    return LocalHistoryRequest(value["operationId"], value["ownerGeneration"], context(value["context"]), n, hashlib.sha256(raw).hexdigest())

def response(request, kind, payload, sequence):
    require(type(request) is LocalHistoryRequest and kind in {"accepted", "lease-ready", "empty-journal-ready", "durable-genesis", "history-head", "abandoned-head", "terminal"}
            and integer(sequence, 7))
    if kind=="abandoned-head": require(request.context["action"]=="abandon-inputs")
    raw = canonical({"protocol": PROTOCOL, "operationId": request.operation_id, "ownerGeneration": request.owner_generation,
                     "sequence": sequence, "kind": kind, "nonce": request.native["nonce"], "requestSha256": request.digest, "payload": payload}) + b"\n"
    require(len(raw) <= (16*1024 if kind == "terminal" else 1024)); return raw

def reply(raw, request, kind, step):
    value = decode(raw, 2048)
    require(type(value) is dict and set(value) == {"protocol", "operationId", "ownerGeneration", "nonce", "requestSha256", "kind", "step", "payload"}
            and value["protocol"] == PROTOCOL and value["operationId"] == request.operation_id
            and value["ownerGeneration"] == request.owner_generation and value["nonce"] == request.native["nonce"]
            and value["requestSha256"] == request.digest and value["kind"] == kind
            and integer(value["step"], 3, 1) and value["step"] == step)
    if kind == "key-material": return _enrollment(value["payload"])
    require(value["payload"] == {}); return None
