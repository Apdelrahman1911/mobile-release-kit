"""Private, one-shot read-only desktop transport.

This is not a CLI or an owner for builds, subprocesses, signing or Store work.
The desktop's Rust owner supplies the deadline, output limits and original-child
settlement. This module handles only the closed, passive API described in
``docs/desktop.md``. Never add stateful methods to this transport implicitly.
"""

from __future__ import annotations

import json
import math
import os
import re
from dataclasses import dataclass
from typing import Any

PROTOCOL = 1
MAX_REQUEST_BYTES = 1024 * 1024
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
MAX_DEPTH = 32
MAX_VALUES = 20_000
METHODS = frozenset({"capabilities", "catalog", "project.snapshot", "config.validate", "config.suggest", "config.preview",
                     "github.setup.propose"})
_ID = re.compile(r"[A-Za-z0-9_-]{1,64}\Z", re.ASCII)


class ProtocolError(ValueError):
    """A public constant diagnostic, never a rendering of the rejected input."""


@dataclass(frozen=True)
class Request:
    id: str
    method: str
    params: dict[str, Any]


def _pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in items:
        if key in value:
            raise ProtocolError("Duplicate object key")
        value[key] = item
    return value


def _constant(_value: str) -> None:
    raise ProtocolError("Non-finite number")


def _check_depth(text: str) -> None:
    """Bound decoder recursion before allocating the decoded containers."""
    depth = 0
    quoted = escaped = False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "[{":
            depth += 1
            if depth > MAX_DEPTH:
                raise ProtocolError("JSON nesting limit exceeded")
        elif char in "]}":
            depth -= 1


def _check_values(value: Any) -> None:
    pending = [(value, 0)]
    count = 0
    while pending:
        item, depth = pending.pop()
        count += 1
        if count > MAX_VALUES or depth > MAX_DEPTH:
            raise ProtocolError("JSON value limit exceeded")
        if isinstance(item, dict):
            if depth >= MAX_DEPTH:
                raise ProtocolError("JSON nesting limit exceeded")
            if count + len(pending) + 2 * len(item) > MAX_VALUES:
                raise ProtocolError("JSON value limit exceeded")
            for key, child in item.items():
                if not isinstance(key, str):
                    raise ProtocolError("Object keys must be strings")
                pending.extend(((key, depth + 1), (child, depth + 1)))
        elif isinstance(item, list):
            if depth >= MAX_DEPTH:
                raise ProtocolError("JSON nesting limit exceeded")
            if count + len(pending) + len(item) > MAX_VALUES:
                raise ProtocolError("JSON value limit exceeded")
            pending.extend((child, depth + 1) for child in item)
        elif isinstance(item, str):
            try:
                item.encode("utf-8", errors="strict")
            except UnicodeError:
                raise ProtocolError("Invalid Unicode string") from None
        elif isinstance(item, float):
            if not math.isfinite(item):
                raise ProtocolError("Non-finite number")
        elif item is not None and type(item) not in (bool, int):
            raise ProtocolError("Unsupported JSON value")


def parse_request(raw: bytes) -> Request:
    """Parse one complete frame including its final newline, with no side effects."""
    if not isinstance(raw, bytes) or not 1 < len(raw) <= MAX_REQUEST_BYTES:
        raise ProtocolError("Request size limit exceeded")
    if not raw.endswith(b"\n"):
        raise ProtocolError("Incomplete request frame")
    try:
        text = raw[:-1].decode("utf-8", errors="strict")
    except UnicodeError:
        raise ProtocolError("Invalid UTF-8") from None
    _check_depth(text)
    try:
        decoder = json.JSONDecoder(object_pairs_hook=_pairs, parse_constant=_constant)
        value, end = decoder.raw_decode(text)
        if end != len(text):
            raise ProtocolError("Trailing data after request")
    except (ValueError, RecursionError) as error:
        if isinstance(error, ProtocolError):
            raise
        raise ProtocolError("Invalid JSON") from None
    _check_values(value)
    if not isinstance(value, dict) or set(value) != {"protocol", "id", "method", "params"}:
        raise ProtocolError("Invalid request envelope")
    if type(value["protocol"]) is not int or value["protocol"] != PROTOCOL:
        raise ProtocolError("Unsupported protocol")
    if not isinstance(value["id"], str) or _ID.fullmatch(value["id"]) is None:
        raise ProtocolError("Invalid request identity")
    if not isinstance(value["method"], str) or value["method"] not in METHODS:
        raise ProtocolError("Unsupported method")
    if not isinstance(value["params"], dict):
        raise ProtocolError("Parameters must be an object")
    return Request(value["id"], value["method"], value["params"])


def encode_response(request: Request, *, result: Any = None, error: dict[str, Any] | None = None) -> bytes:
    """Encode bounded typed service data, never arbitrary repr/exception objects."""
    value: dict[str, Any] = {"protocol": PROTOCOL, "id": request.id, "ok": error is None}
    if error is None:
        value["result"] = result
    else:
        message = error.get("message")
        try:
            safe_message = (
                isinstance(message, str) and 1 <= len(message.encode("utf-8")) <= 1600
                and not any(ord(char) < 32 or ord(char) == 127 for char in message)
            )
        except UnicodeError:
            safe_message = False
        if (
            set(error) != {"code", "message", "retryable"}
            or not isinstance(error["code"], str)
            or _ID.fullmatch(error["code"]) is None
            or not safe_message
            or error["retryable"] is not False
        ):
            raise ProtocolError("Invalid error contract")
        value["error"] = error
    _check_values(value)
    try:
        raw = json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8") + b"\n"
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise ProtocolError("Invalid service result") from None
    if len(raw) > MAX_RESPONSE_BYTES:
        raise ProtocolError("Response size limit exceeded")
    return raw


def _read_request(fd: int) -> bytes:
    chunks: list[bytes] = []
    size = 0
    while True:
        block = os.read(fd, min(64 * 1024, MAX_REQUEST_BYTES + 1 - size))
        if not block:
            return b"".join(chunks)
        chunks.append(block)
        size += len(block)
        if size > MAX_REQUEST_BYTES:
            raise ProtocolError("Request size limit exceeded")


def _write_response(fd: int, raw: bytes) -> None:
    remaining = memoryview(raw)
    while remaining:
        written = os.write(fd, remaining)
        if written <= 0:
            raise OSError("Protocol write failed")
        remaining = remaining[written:]


def main() -> int:
    """Take custody of private channels before importing the passive services."""
    owned: list[int] = []
    status = 0
    try:
        control = os.dup(0)
        owned.append(control)
        os.set_inheritable(control, False)
        result = os.dup(1)
        owned.append(result)
        os.set_inheritable(result, False)
        if os.name == "nt":
            import msvcrt

            msvcrt.setmode(control, os.O_BINARY)
            msvcrt.setmode(result, os.O_BINARY)
        null = os.open(os.devnull, os.O_RDONLY)
        owned.append(null)
        os.dup2(null, 0, inheritable=False)
        os.dup2(2, 1, inheritable=False)
        # Descriptors, not just Python wrappers, now route incidental tool/log
        # output away from the result pipe. Neither private channel is inherited.
        from .api import ApiError, execute

        request = parse_request(_read_request(control))
        try:
            response = encode_response(request, result=execute(request.method, request.params))
        except ApiError as error:
            response = encode_response(request, error={"code": error.code, "message": error.message, "retryable": False})
        _write_response(result, response)
    except (KeyboardInterrupt, SystemExit):
        status = 130
    except Exception:
        # No traceback, request, selected path, file contents or credential can
        # reach diagnostics. The parent reports a bounded transport error.
        status = 70
        try:
            os.write(2, b"Mobile Release Kit desktop engine rejected the request or transport.\n")
        except OSError:
            pass
    finally:
        while owned:
            fd = owned.pop()  # Retire before the sole close attempt.
            try:
                os.close(fd)
            except OSError:
                status = status or 74
    return status


if __name__ == "__main__":
    raise SystemExit(main())
