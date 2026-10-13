"""Private bounded image edit frames, never renderer image transport.

Only the initial native-owned import frame has a larger allowance. Decoded
image bodies replace base64 before a request is retained; later requests stay
small. This DATA decoder does not confer picker, root or transaction authority.
"""
from __future__ import annotations

import json
import re
from typing import Any

from ._desktop_engine import ProtocolError, _check_values, _constant, _pairs
from .metadata_images import (MAX_IMAGES, MAX_PREPARED_BYTES, MAX_REQUEST_BYTES,
                              MAX_RESULT_BYTES, MetadataImagesInputError,
                              admit_baseline, decode_native_images, image_type,
                              protected_project_sources, protected_source_objects)
from .metadata_text import MetadataTextInputError, locale_value, platform_value

PROTOCOL = "mrk-metadata-images/1"
SMALL_REQUEST_LIMIT = 64 * 1024
TOKEN = re.compile(r"[0-9a-f]{32}\Z")


def _root(value: object) -> bool:
    # Match the native writer's bounded private root, not a renderer field.
    if type(value) is not str or not value.startswith("/") or len(value) > 4096:
        return False
    try:
        return (len(value.encode("utf-8")) <= 4096
                and not any(ord(char) < 32 or ord(char) == 127 for char in value))
    except UnicodeError:
        return False


def request_limit(sequence: int) -> int:
    return MAX_REQUEST_BYTES if sequence == 0 else SMALL_REQUEST_LIMIT


def _scan(text: str) -> None:
    """Bound containers/scalars before JSON allocation, including a wide list.

    A 33MiB allowance is for a few long base64 strings, not millions of small
    values. Escape/shape validity is still checked by the strict JSON decoder.
    """
    depth = count = 0
    quoted = escaped = atom = False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted, atom = True, False
            count += 1
        elif char in "[{":
            depth += 1
            count += 1
            atom = False
        elif char in "]}":
            depth -= 1
            atom = False
        elif char in ",: \t\r\n":
            atom = False
        elif not atom:
            atom = True
            count += 1
        if depth < 0 or depth > 16 or count > 4096:
            raise ProtocolError("Image edit JSON exceeded its bound")


def parse_request(raw: bytes, *, sequence: int, session: str | None):
    from ._desktop_edit_protocol import EditRequest, registered_identity
    if (type(sequence) is not int or sequence not in {0, 1, 2}
            or type(raw) is not bytes or not 2 <= len(raw) <= request_limit(sequence)
            or not raw.endswith(b"\n") or raw[:1] != b"{" or raw[-2:-1] != b"}"
            or b"\r" in raw or raw.find(b"\n") != len(raw) - 1):
        raise ProtocolError("Invalid image edit frame")
    try:
        # Decode the existing LF-terminated frame rather than slicing another
        # potentially 33MiB bytes object. The strict decoder must stop exactly
        # before that one admitted LF; this does not permit trailing whitespace.
        text = raw.decode("utf-8", errors="strict")
        _scan(text)
        decoder = json.JSONDecoder(object_pairs_hook=_pairs, parse_constant=_constant)
        value, end = decoder.raw_decode(text)
        if end != len(text) - 1:
            raise ProtocolError("Trailing image edit data")
    except (ValueError, UnicodeError, RecursionError):
        raise ProtocolError("Invalid image edit JSON") from None
    del text  # Raw frame and parsed base64 remain; release widened Unicode now.
    if (type(value) is not dict or set(value) != {"protocol", "session", "seq", "op", "params"}
            or value["protocol"] != PROTOCOL or type(value["session"]) is not str
            or TOKEN.fullmatch(value["session"]) is None
            or session is not None and value["session"] != session
            or type(value["seq"]) is not int or value["seq"] != sequence
            or type(value["op"]) is not str or type(value["params"]) is not dict):
        raise ProtocolError("Invalid image edit envelope")
    op, params = value["op"], value["params"]
    images = None
    valid = False
    try:
        if sequence == 0:
            intent = params.get("intent")
            names = {"root", "registeredIdentity", "intent"}
            if intent == "import":
                names |= {"platform", "locale", "assetType", "images", "protectedSources", "protectedObjects"}
            valid = (op == "open" and set(params) == names and _root(params["root"])
                     and type(intent) is str and intent in {"import", "recover"})
            if valid:
                registered_identity(params["registeredIdentity"])
                if intent == "import":
                    platform_value(params["platform"])
                    locale_value(params["locale"])
                    image_type(params["platform"], params["assetType"])
                    protected_project_sources(params["protectedSources"])
                    if type(params["images"]) is not list:
                        raise MetadataImagesInputError()
                    protected_source_objects(params["protectedObjects"], len(params["images"]))
                    # Remove all encoded bodies from retained request DATA.
                    # Decoder validates exact lengths, canonical base64 and
                    # native digests before allocating each bounded body.
                    encoded = params.pop("images")
                    images = decode_native_images(encoded)
                    del encoded
                elif len(raw) > SMALL_REQUEST_LIMIT:
                    valid = False
        elif op == "discard":
            valid = not params
        elif sequence == 1:
            valid = (op == "prepare" and set(params) == {"revision", "expectedBaseline", "choices"}
                     and type(params["revision"]) is str and TOKEN.fullmatch(params["revision"]) is not None
                     and type(params["choices"]) is list and len(params["choices"]) <= MAX_IMAGES)
            if valid:
                admit_baseline(params["expectedBaseline"])
                tokens = set()
                for row in params["choices"]:
                    if (type(row) is not dict or set(row) != {"itemId", "replaceExisting"}
                            or type(row["itemId"]) is not str or TOKEN.fullmatch(row["itemId"]) is None
                            or row["itemId"] in tokens or type(row["replaceExisting"]) is not bool):
                        valid = False
                        break
                    tokens.add(row["itemId"])
        else:
            valid = (op == "apply" and set(params) == {"planToken"}
                     and type(params["planToken"]) is str and TOKEN.fullmatch(params["planToken"]) is not None)
        _check_values(value)  # Small values only; decoded bytes are added below.
    except (MetadataImagesInputError, MetadataTextInputError, KeyError, TypeError):
        valid = False
    if not valid:
        raise ProtocolError("Invalid image edit operation")
    if images is not None:
        params["images"] = images
    return EditRequest(value["session"], sequence, op, params, PROTOCOL)


def response(request, kind: str, result: dict[str, Any]) -> bytes:
    from ._desktop_edit_protocol import TERMINAL_LIMIT, _workflow_value
    keys = ({"intent", "revision", "baseline", "view", "scopeResources"} if kind == "opened" else
            {"revision", "planToken", "view", "scopeResources"} if kind == "prepared" else
            {"kind", "planToken", "effect", "journal", "resources", "reason"})
    if (request.protocol != PROTOCOL or kind not in {"opened", "prepared", "terminal"}
            or type(result) is not dict or set(result) != keys
            or kind != "terminal" and result["scopeResources"] != "settled"
            or kind == "terminal" and result["kind"] != "outcome"
            or kind == "opened" and result["intent"] not in {"import", "recover"}):
        raise ProtocolError("Invalid image edit response")
    value = {"protocol": PROTOCOL, "session": request.session, "seq": request.seq,
             "kind": kind, "result": result}
    try:
        _check_values(value)
        if kind != "terminal":
            _workflow_value(result["view"], depth_limit=16, byte_limit=MAX_PREPARED_BYTES)
        raw = json.dumps(value, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8") + b"\n"
    except (ValueError, UnicodeError, RecursionError, OverflowError):
        raise ProtocolError("Invalid image response JSON") from None
    if len(raw) > (TERMINAL_LIMIT if kind == "terminal" else MAX_RESULT_BYTES):
        raise ProtocolError("Image edit response exceeded its bound")
    return raw
