"""Closed, finite typed-edit framing. No IO or mutation authority."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from ._desktop_engine import ProtocolError, _check_depth, _check_values, _pairs, _constant
from .metadata_text import (MAX_PREPARED_BYTES, MetadataTextInputError, admit_baseline,
                             locale_value, platform_value, text_fields)

PROTOCOL = "mrk-config-edit/1"
WORKFLOW_PROTOCOL = "mrk-github-workflows/1"
METADATA_PROTOCOL = "mrk-metadata-text/1"
REQUEST_LIMIT = 1024 * 1024
RESPONSE_LIMIT = 4 * 1024 * 1024
WORKFLOW_RESPONSE_LIMIT = 256 * 1024
METADATA_RESPONSE_LIMIT = 2 * 1024 * 1024
TERMINAL_LIMIT = 16 * 1024
TOKEN = re.compile(r"[0-9a-f]{32}\Z")


@dataclass(frozen=True)
class EditRequest:
    session: str
    seq: int
    op: str
    params: dict[str, Any]
    protocol: str = PROTOCOL


def registered_identity(value: object) -> dict[str, int]:
    """Private native ABI: full st_mode, never a renderer path/identity hint."""
    if type(value) is not dict or set(value) != {"device", "inode", "mode", "uid", "gid"}:
        raise ProtocolError("Invalid registered directory identity")
    result: dict[str, int] = {}
    for name in ("device", "inode"):
        text = value[name]
        if (type(text) is not str or re.fullmatch(r"0|[1-9][0-9]{0,19}", text) is None
                or int(text) > 2**64 - 1 or name == "inode" and text == "0"):
            raise ProtocolError("Invalid registered directory identity")
        result[name] = int(text)
    for name in ("mode", "uid", "gid"):
        if type(value[name]) is not int or not 0 <= value[name] <= 2**32 - 1:
            raise ProtocolError("Invalid registered directory identity")
        result[name] = value[name]
    if result["mode"] & 0o170000 != 0o040000:
        raise ProtocolError("Invalid registered directory identity")
    return result


def _workflow_value(value: object, *, depth_limit: int, byte_limit: int) -> None:
    # The common parser already checks JSON scalar types. This second, narrower
    # DATA bound admits this domain's draft/results without changing config wire.
    pending, count = [(value, 0)], 0
    while pending:
        item, depth = pending.pop()
        count += 1
        if count > 8_000 or depth > depth_limit:
            raise ProtocolError("Workflow edit value exceeded its bound")
        if type(item) is dict:
            if depth >= depth_limit or count + len(pending) + 2 * len(item) > 8_000:
                raise ProtocolError("Workflow edit value exceeded its bound")
            for key, child in item.items():
                pending.extend(((key, depth + 1), (child, depth + 1)))
        elif type(item) is list:
            if depth >= depth_limit or count + len(pending) + len(item) > 8_000:
                raise ProtocolError("Workflow edit value exceeded its bound")
            pending.extend((child, depth + 1) for child in item)
    raw = json.dumps(value, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    if len(raw) > byte_limit:
        raise ProtocolError("Workflow edit value exceeded its bound")


def parse_request(raw: bytes, *, sequence: int, session: str | None,
                  protocol: str = PROTOCOL) -> EditRequest:
    if (type(protocol) is not str or protocol not in {PROTOCOL, WORKFLOW_PROTOCOL, METADATA_PROTOCOL}
            or type(raw) is not bytes or not 2 <= len(raw) <= REQUEST_LIMIT
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
            or value["protocol"] != protocol
            or type(value["session"]) is not str
            or TOKEN.fullmatch(value["session"]) is None
            or session is not None and value["session"] != session
            or type(value["seq"]) is not int or value["seq"] != sequence
            or sequence not in {0, 1, 2} or type(value["op"]) is not str
            or type(value["params"]) is not dict):
        raise ProtocolError("Invalid edit envelope")
    op, params = value["op"], value["params"]
    if sequence == 0:
        if protocol == METADATA_PROTOCOL:
            names = {"root", "registeredIdentity", "platform", "locale"}
        elif protocol == WORKFLOW_PROTOCOL:
            names = {"root", "registeredIdentity"}
        else:
            names = {"root"}
        valid = op == "open" and set(params) == names and type(params["root"]) is str
        if valid and protocol in {WORKFLOW_PROTOCOL, METADATA_PROTOCOL}:
            registered_identity(params["registeredIdentity"])
        if valid and protocol == METADATA_PROTOCOL:
            try:
                platform_value(params["platform"])
                locale_value(params["locale"])
            except MetadataTextInputError:
                valid = False
    elif op == "discard":
        valid = not params
    elif sequence == 1 and protocol == METADATA_PROTOCOL:
        valid = (op == "prepare" and set(params) == {"revision", "expectedBaseline", "fields"}
                 and type(params["revision"]) is str and TOKEN.fullmatch(params["revision"]) is not None
                 and type(params["fields"]) is list and len(params["fields"]) in {3, 5})
        if valid:
            # Shape-only roster inference; the retained original checkout
            # separately binds the platform, locale, baseline and target set.
            platform = "android" if len(params["fields"]) == 3 else "ios"
            try:
                text_fields(platform, params["fields"])
                admit_baseline(platform, params["expectedBaseline"])
            except MetadataTextInputError:
                valid = False
    elif sequence == 1 and protocol == WORKFLOW_PROTOCOL:
        valid = (op == "prepare" and set(params) == {"revision", "draft", "toolingRepository", "toolingSha"}
                 and type(params["revision"]) is str and TOKEN.fullmatch(params["revision"]) is not None
                 and type(params["draft"]) is dict
                 and type(params["toolingRepository"]) is str and len(params["toolingRepository"].encode("utf-8")) <= 140
                 and type(params["toolingSha"]) is str and len(params["toolingSha"].encode("utf-8")) <= 40)
        if valid:
            _workflow_value(params["draft"], depth_limit=28, byte_limit=512 * 1024)
    elif sequence == 1 and protocol == PROTOCOL:
        valid = (op == "prepare" and set(params) == {"revision", "expectedBase", "draft"}
                 and type(params["revision"]) is str and TOKEN.fullmatch(params["revision"]) is not None
                 and (params["expectedBase"] is None or type(params["expectedBase"]) is dict)
                 and type(params["draft"]) is dict)
    else:
        valid = (op == "apply" and set(params) == {"planToken"}
                 and type(params["planToken"]) is str and TOKEN.fullmatch(params["planToken"]) is not None)
    if not valid:
        raise ProtocolError("Invalid edit operation")
    return EditRequest(value["session"], sequence, op, params, protocol)


def response(request: EditRequest, kind: str, result: dict[str, Any]) -> bytes:
    if kind not in {"opened", "prepared", "terminal"} or request.protocol not in {PROTOCOL, WORKFLOW_PROTOCOL, METADATA_PROTOCOL}:
        raise ProtocolError("Invalid edit response")
    if request.protocol == METADATA_PROTOCOL:
        keys = ({"revision", "metadataRoot", "baseline", "scopeResources"} if kind == "opened" else
                {"revision", "planToken", "view", "scopeResources"} if kind == "prepared" else
                {"kind", "planToken", "effect", "journal", "resources", "reason"})
        if (type(result) is not dict or set(result) != keys
                or kind == "terminal" and result["kind"] != "outcome"
                or kind != "terminal" and result["scopeResources"] != "settled"):
            raise ProtocolError("Invalid metadata edit response")
    value = {"protocol": request.protocol, "session": request.session, "seq": request.seq,
             "kind": kind, "result": result}
    _check_values(value)
    try:
        if request.protocol == WORKFLOW_PROTOCOL:
            _workflow_value(result, depth_limit=16, byte_limit=WORKFLOW_RESPONSE_LIMIT)
        elif request.protocol == METADATA_PROTOCOL:
            _workflow_value(result, depth_limit=16, byte_limit=METADATA_RESPONSE_LIMIT)
            if kind == "prepared":
                _workflow_value(result["view"], depth_limit=16, byte_limit=MAX_PREPARED_BYTES)
        raw = json.dumps(value, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8") + b"\n"
    except (ValueError, UnicodeError, RecursionError, OverflowError):
        raise ProtocolError("Invalid edit response JSON") from None
    limit = (WORKFLOW_RESPONSE_LIMIT if request.protocol == WORKFLOW_PROTOCOL else
             METADATA_RESPONSE_LIMIT if request.protocol == METADATA_PROTOCOL else RESPONSE_LIMIT)
    if len(raw) > (TERMINAL_LIMIT if kind == "terminal" else limit):
        raise ProtocolError("Edit response exceeded its bound")
    return raw
