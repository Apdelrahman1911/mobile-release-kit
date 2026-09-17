"""Closed, finite configuration-edit framing. No IO or mutation authority."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from ._desktop_engine import ProtocolError, _check_depth, _check_values, _pairs, _constant

PROTOCOL = "mrk-config-edit/1"
REQUEST_LIMIT = 1024 * 1024
RESPONSE_LIMIT = 4 * 1024 * 1024
TERMINAL_LIMIT = 16 * 1024
TOKEN = re.compile(r"[0-9a-f]{32}\Z")


@dataclass(frozen=True)
class EditRequest:
    session: str
    seq: int
    op: str
    params: dict[str, Any]


def parse_request(raw: bytes, *, sequence: int, session: str | None) -> EditRequest:
    if (type(raw) is not bytes or not 2 <= len(raw) <= REQUEST_LIMIT
            or not raw.endswith(b"\n") or raw[:1] != b"{" or raw[-2:-1] != b"}"
            or b"\r" in raw or b"\n" in raw[:-1]):
        raise ProtocolError("Invalid edit frame")
    try:
        text = raw[:-1].decode("utf-8", errors="strict")
        _check_depth(text)
        decoder = json.JSONDecoder(object_pairs_hook=_pairs, parse_constant=_constant)
        value, end = decoder.raw_decode(text)
        if end != len(text):
            raise ProtocolError("Trailing edit frame data")
        _check_values(value)
    except (ValueError, UnicodeError, RecursionError):
        raise ProtocolError("Invalid edit JSON") from None
    if (type(value) is not dict or set(value) != {"protocol", "session", "seq", "op", "params"}
            or value["protocol"] != PROTOCOL or type(value["session"]) is not str
            or TOKEN.fullmatch(value["session"]) is None
            or session is not None and value["session"] != session
            or type(value["seq"]) is not int or value["seq"] != sequence
            or sequence not in {0, 1, 2} or type(value["op"]) is not str
            or type(value["params"]) is not dict):
        raise ProtocolError("Invalid edit envelope")
    op, params = value["op"], value["params"]
    if sequence == 0:
        valid = op == "open" and set(params) == {"root"} and type(params["root"]) is str
    elif op == "discard":
        valid = not params
    elif sequence == 1:
        valid = (op == "prepare" and set(params) == {"revision", "expectedBase", "draft"}
                 and type(params["revision"]) is str and TOKEN.fullmatch(params["revision"]) is not None
                 and (params["expectedBase"] is None or type(params["expectedBase"]) is dict)
                 and type(params["draft"]) is dict)
    else:
        valid = (op == "apply" and set(params) == {"planToken"}
                 and type(params["planToken"]) is str and TOKEN.fullmatch(params["planToken"]) is not None)
    if not valid:
        raise ProtocolError("Invalid edit operation")
    return EditRequest(value["session"], sequence, op, params)


def response(request: EditRequest, kind: str, result: dict[str, Any]) -> bytes:
    if kind not in {"opened", "prepared", "terminal"}:
        raise ProtocolError("Invalid edit response")
    value = {"protocol": PROTOCOL, "session": request.session, "seq": request.seq,
             "kind": kind, "result": result}
    _check_values(value)
    try:
        raw = json.dumps(value, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8") + b"\n"
    except (ValueError, UnicodeError, RecursionError, OverflowError):
        raise ProtocolError("Invalid edit response JSON") from None
    if len(raw) > (TERMINAL_LIMIT if kind == "terminal" else RESPONSE_LIMIT):
        raise ProtocolError("Edit response exceeded its bound")
    return raw
