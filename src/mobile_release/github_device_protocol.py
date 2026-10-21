"""Closed session-only OAuth device frames. No network, configuration or token store.

This module's private replies are NEVER renderer results. Only the native
registration may publish a user code, after the original worker has retired.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass

PROTOCOL = "mrk-github-device/1"
REQUEST_LIMIT = RESPONSE_LIMIT = 16 * 1024
WORK_SECONDS = 10
FINALITY_SECONDS = 12
TOKEN_LIMIT = 4096
DEVICE_LIMIT = 1024
VERIFICATION_URI = "https://github.com/login/device"
GRANT = "urn:ietf:params:oauth:grant-type:device_code"
_ID = re.compile(r"[A-Za-z0-9_-]{1,64}\Z", re.ASCII)
_CLIENT = re.compile(r"[A-Za-z0-9_.-]{1,128}\Z", re.ASCII)
_REPO = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?/[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,98}[A-Za-z0-9])?\Z", re.ASCII)
_USER = re.compile(r"[A-Z0-9]{4}-[A-Z0-9]{4}\Z", re.ASCII)
_SCOPE = re.compile(r"[a-z][a-z0-9_:.-]{0,63}\Z", re.ASCII)


class ProtocolError(ValueError):
    """Fixed diagnostic only: never include input, provider text or secrets."""


def require(value: bool) -> None:
    if not value:
        raise ProtocolError("The fixed device connection frame was refused")


def _object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def decode(raw: bytes, *, limit: int = RESPONSE_LIMIT):
    require(type(raw) is bytes and 0 < len(raw) <= limit)
    try:
        value = json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=_object,
                           parse_constant=lambda _: require(False))
    except (ValueError, UnicodeError, RecursionError):
        raise ProtocolError("The fixed device connection frame was refused") from None
    # These exact objects have depth <=3; do not accept arbitrary nested DATA.
    def walk(item, depth=0):
        require(depth <= 4)
        if type(item) is dict:
            require(len(item) <= 16)
            for key, child in item.items():
                require(type(key) is str and len(key) <= 64)
                walk(child, depth + 1)
        elif type(item) is list:
            require(len(item) <= 32)
            for child in item:
                walk(child, depth + 1)
        else:
            require(type(item) in (str, int, type(None)))
    walk(value)
    return value


def encode(value: dict) -> bytes:
    raw = json.dumps(value, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode("ascii") + b"\n"
    require(len(raw) <= RESPONSE_LIMIT)
    return raw


def printable(value, maximum: int) -> bool:
    return type(value) is str and 0 < len(value) <= maximum and all(0x21 <= ord(c) <= 0x7e for c in value)


def _integer(value, maximum):
    return type(value) is int and 0 < value <= maximum


@dataclass(frozen=True, slots=True, repr=False)
class Request:
    id: str
    role: str
    context: dict
    client_id: str
    device_code: str | None
    work_end_ns: int
    hard_end_ns: int
    digest: str


def parse_request(raw: bytes) -> Request:
    require(type(raw) is bytes and len(raw) <= REQUEST_LIMIT and raw.endswith(b"\n") and raw.count(b"\n") == 1)
    value = decode(raw, limit=REQUEST_LIMIT)
    require(type(value) is dict and set(value) == {"protocol", "id", "role", "context", "clientId", "deviceCode", "clock"}
            and value["protocol"] == PROTOCOL and type(value["id"]) is str and _ID.fullmatch(value["id"]) is not None
            and value["role"] in {"start", "poll"} and type(value["clientId"]) is str
            and _CLIENT.fullmatch(value["clientId"]) is not None)
    context = value["context"]
    require(type(context) is dict and set(context) == {"operationId", "projectId", "repository", "generation", "sequence"}
            and all(type(context[k]) is str and _ID.fullmatch(context[k]) is not None for k in ("operationId", "projectId"))
            and type(context["repository"]) is str and _REPO.fullmatch(context["repository"]) is not None
            and _integer(context["generation"], 2**32-1) and type(context["sequence"]) is int
            and 0 <= context["sequence"] <= 120)
    require((value["role"] == "start" and context["sequence"] == 0 and value["deviceCode"] is None)
            or (value["role"] == "poll" and 1 <= context["sequence"] <= 120 and printable(value["deviceCode"], DEVICE_LIMIT)))
    clock = value["clock"]
    require(type(clock) is dict and set(clock) == {"workEndNs", "hardEndNs"}
            and _integer(clock["workEndNs"], 2**63-1) and _integer(clock["hardEndNs"], 2**63-1)
            and clock["workEndNs"] < clock["hardEndNs"] <= clock["workEndNs"] + 2_000_000_000)
    return Request(value["id"], value["role"], context, value["clientId"], value["deviceCode"],
                   clock["workEndNs"], clock["hardEndNs"], hashlib.sha256(raw).hexdigest())


def _control(request: Request, kind: str) -> bytes:
    require(type(request) is Request and kind in {"ready", "go"})
    return encode({"protocol": PROTOCOL, "id": request.id, "role": request.role,
                   "requestSha256": request.digest, "kind": kind})


def ready(request: Request) -> bytes:
    return _control(request, "ready")


def go(request: Request) -> bytes:
    return _control(request, "go")


def provider_reply(role: str, value: dict) -> dict:
    """Strict PRIVATE projection; error descriptions/URLs are never forwarded."""
    require(role in {"start", "poll"} and type(value) is dict)
    if "error" in value:
        require(set(value) <= {"error", "error_description", "error_uri"}
                and all(type(v) is str and len(v.encode("utf-8")) <= 1024 for v in value.values()))
        errors = {"authorization_pending": "pending", "slow_down": "slow-down", "expired_token": "expired",
                  "access_denied": "denied", "incorrect_client_credentials": "client-refused",
                  "incorrect_device_code": "invalid", "unsupported_grant_type": "invalid", "device_flow_disabled": "client-refused"}
        require(value["error"] in errors)
        kind = errors[value["error"]]
        require(role == "poll" or kind in {"client-refused", "invalid"})
        return {"kind": kind}
    if role == "start":
        require(set(value) in ({"device_code", "user_code", "verification_uri", "expires_in"},
                               {"device_code", "user_code", "verification_uri", "expires_in", "interval"})
                and printable(value["device_code"], DEVICE_LIMIT) and type(value["user_code"]) is str
                and _USER.fullmatch(value["user_code"]) is not None and value["verification_uri"] == VERIFICATION_URI
                and _integer(value["expires_in"], 900) and _integer(value.get("interval", 5), 900))
        return {"kind": "code", "deviceCode": value["device_code"], "userCode": value["user_code"],
                "expiresIn": value["expires_in"], "interval": max(5, value.get("interval", 5))}
    require(set(value) in ({"access_token", "token_type", "scope"}, {"access_token", "token_type", "scope", "expires_in"})
            and printable(value["access_token"], TOKEN_LIMIT) and value["token_type"] == "bearer"
            and type(value["scope"]) is str and len(value["scope"]) <= 2048)
    scopes = value["scope"].split(",") if value["scope"] else []
    require(len(scopes) <= 32 and len(set(scopes)) == len(scopes)
            and all(_SCOPE.fullmatch(scope) is not None for scope in scopes)
            and ("expires_in" not in value or _integer(value["expires_in"], 2**32-1)))
    return {"kind": "token", "token": value["access_token"], "scopes": scopes, "expiresIn": value.get("expires_in")}


def form(role: str, client_id: str, device_code: str | None) -> bytes:
    from urllib.parse import urlencode  # Encoding only, never urllib.request.
    require(type(client_id) is str and _CLIENT.fullmatch(client_id) is not None)
    if role == "start":
        require(device_code is None)
        fields = (("client_id", client_id), ("scope", "repo"))
    else:
        require(role == "poll" and printable(device_code, DEVICE_LIMIT))
        fields = (("client_id", client_id), ("device_code", device_code), ("grant_type", GRANT))
    raw = urlencode(fields).encode("ascii")
    require(len(raw) <= 4096)
    return raw


def validate_body(role: str, raw: bytes | None) -> None:
    from urllib.parse import parse_qsl
    require(role in {"device-start", "device-poll"} and type(raw) is bytes and 0 < len(raw) <= 4096)
    try:
        pairs = parse_qsl(raw.decode("ascii"), strict_parsing=True, keep_blank_values=True, max_num_fields=3)
    except (ValueError, UnicodeError):
        raise ProtocolError("The fixed device request was refused") from None
    require(len(dict(pairs)) == len(pairs))
    values = dict(pairs)
    if role == "device-start":
        require(set(values) == {"client_id", "scope"} and values["scope"] == "repo")
        expected = form("start", values["client_id"], None)
    else:
        require(set(values) == {"client_id", "device_code", "grant_type"} and values["grant_type"] == GRANT)
        expected = form("poll", values["client_id"], values["device_code"])
    require(raw == expected)


def terminal(request: Request, status: str, reply: dict | None, first_failure_ns: int | None = None) -> bytes:
    require(type(request) is Request and status in {"ok", "refused", "cancelled", "timed-out", "cleanup-unknown"}
            and (status == "ok") == (type(reply) is dict))
    require(first_failure_ns is None or type(first_failure_ns) is int and 0 < first_failure_ns < 2**63)
    require(status != "ok" or first_failure_ns is None)
    return encode({"protocol": PROTOCOL, "id": request.id, "role": request.role,
                   "requestSha256": request.digest, "status": status, "firstFailureNs": first_failure_ns, "reply": reply})
