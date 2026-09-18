"""One-shot private G1B framing, not a CLI or a general API method.

Importing this module does not import the API services, HTTP, socket or SSL.
Only main takes private-channel custody and enters the fixed live transport.
Pure parsers/encoders do not establish original native settlement or authority.
"""
from __future__ import annotations

import json
import math
import os
import re
import time
from dataclasses import dataclass
from typing import Any

from .workflow_payloads import TOOLING_REPOSITORY_RE

PROTOCOL = "mrk-github-readonly/1"
MAX_REQUEST_BYTES = 8 * 1024
MAX_RESPONSE_BYTES = 64 * 1024
READ_SECONDS = 10.0
MAX_COOLDOWN_SECONDS = 604800
REASONS = frozenset({"none", "unauthorized", "forbidden", "not-found-or-inaccessible",
                     "target-changed", "rate-limited", "network-unavailable", "tls-failed",
                     "response-invalid", "response-limit", "expired", "cancelled"})
_ID = re.compile(r"[A-Za-z0-9_-]{1,64}\Z", re.ASCII)
_NUMERIC_ID = re.compile(r"[1-9][0-9]{0,19}\Z", re.ASCII)
_U64 = "18446744073709551615"


class ProtocolError(ValueError):
    """Constant diagnostics only; never render the rejected private input."""


class _JsonError(ValueError):
    pass


class _JsonLimit(_JsonError):
    pass


@dataclass(frozen=True, slots=True, repr=False)
class ReadRequest:
    id: str
    repository: str
    expected_account_id: str | None
    expected_repository_id: str | None
    token: str


def _pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        if key in result:
            raise _JsonError("Duplicate JSON key")
        result[key] = value
    return result


def _constant(_value: str) -> None:
    raise _JsonError("Non-finite JSON")


def _integer(value: str) -> int:
    # The wire/body byte ceiling bounds scanning; this additional finite scalar
    # ceiling avoids dependence on the interpreter's big-integer conversion cap.
    if len(value) > 128:
        raise _JsonLimit("JSON numeric scalar limit")
    return int(value)


def _floating(value: str) -> float:
    if len(value) > 128:
        raise _JsonLimit("JSON numeric scalar limit")
    result = float(value)
    if not math.isfinite(result):
        raise _JsonError("Non-finite JSON")
    return result


def _check_values(value: Any, *, nodes: int, depth: int) -> None:
    pending = [(value, 0)]
    count = 0
    while pending:
        item, level = pending.pop()
        count += 1
        kind = type(item)
        if count > nodes or level > depth or kind in (dict, list) and level >= depth:
            raise _JsonLimit("JSON complexity limit")
        if kind is dict:
            if count + len(pending) + 2 * len(item) > nodes:
                raise _JsonLimit("JSON complexity limit")
            for key, child in item.items():
                if type(key) is not str:
                    raise _JsonError("JSON object key type")
                pending.extend(((key, level + 1), (child, level + 1)))
        elif kind is list:
            if count + len(pending) + len(item) > nodes:
                raise _JsonLimit("JSON complexity limit")
            pending.extend((child, level + 1) for child in item)
        elif kind is str:
            try:
                item.encode("utf-8", errors="strict")
            except UnicodeError:
                raise _JsonError("Invalid JSON Unicode") from None
        elif kind is float:
            if not math.isfinite(item):
                raise _JsonError("Non-finite JSON")
        elif item is not None and kind not in (bool, int):
            raise _JsonError("Unsupported JSON value")


def _decode_json(raw: bytes, *, limit: int, nodes: int, depth: int,
                 exact: bool = False) -> Any:
    if type(raw) is not bytes or not raw:
        raise _JsonError("Invalid JSON bytes")
    if len(raw) > limit:
        raise _JsonLimit("JSON byte limit")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeError:
        raise _JsonError("Invalid JSON UTF-8") from None
    # Bound nesting BEFORE json allocates nested containers. Strings/escapes do
    # not count as structure. The decoder still checks all actual JSON syntax.
    level = 0
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
            level += 1
            if level > depth:
                raise _JsonLimit("JSON nesting limit")
        elif char in "]}":
            level -= 1
            if level < 0:
                raise _JsonError("Invalid JSON structure")
    try:
        decoder = json.JSONDecoder(object_pairs_hook=_pairs, parse_constant=_constant,
                                   parse_int=_integer, parse_float=_floating)
        if exact:
            value, end = decoder.raw_decode(text)
            if end != len(text):
                raise _JsonError("Trailing JSON data")
        else:
            value = decoder.decode(text)
    except _JsonError:
        raise
    except (ValueError, RecursionError, OverflowError):
        raise _JsonError("Invalid JSON") from None
    _check_values(value, nodes=nodes, depth=depth)
    return value


def _numeric_id(value: object) -> bool:
    return (type(value) is str and _NUMERIC_ID.fullmatch(value) is not None
            and (len(value) < len(_U64) or value <= _U64))


def parse_request(raw: bytes) -> ReadRequest:
    """One exact frame, including the sole terminal newline and complete EOF."""
    try:
        if (type(raw) is not bytes or not 1 < len(raw) <= MAX_REQUEST_BYTES
                or not raw.endswith(b"\n") or raw.count(b"\n") != 1 or b"\r" in raw):
            raise ProtocolError("Invalid private GitHub frame")
        value = _decode_json(raw[:-1], limit=MAX_REQUEST_BYTES - 1, nodes=128, depth=6, exact=True)
        if type(value) is not dict or set(value) != {"protocol", "id", "params"}:
            raise ProtocolError("Invalid private GitHub frame")
        if (value["protocol"] != PROTOCOL or type(value["id"]) is not str
                or _ID.fullmatch(value["id"]) is None):
            raise ProtocolError("Invalid private GitHub frame")
        params = value["params"]
        if type(params) is not dict or set(params) != {"repository", "expectedAccountId", "expectedRepositoryId", "token"}:
            raise ProtocolError("Invalid private GitHub frame")
        repository, account, repo, token = (params[name] for name in
                                            ("repository", "expectedAccountId", "expectedRepositoryId", "token"))
        if (type(repository) is not str or TOOLING_REPOSITORY_RE.fullmatch(repository) is None
                or account is not None and not _numeric_id(account)
                or repo is not None and (account is None or not _numeric_id(repo))
                or type(token) is not str or not 1 <= len(token) <= 4096
                or any(not 0x21 <= ord(char) <= 0x7e for char in token)):
            raise ProtocolError("Invalid private GitHub frame")
        return ReadRequest(value["id"], repository, account, repo, token)
    except (_JsonError, TypeError, UnicodeError, RecursionError, OverflowError):
        raise ProtocolError("Invalid private GitHub frame") from None


def _check_control(control: object) -> dict[str, Any]:
    if type(control) is not dict or set(control) != {"reason", "credentialExpiresAt", "cooldownSeconds", "cooldownBlocked"}:
        raise ProtocolError("Invalid private GitHub control")
    reason, expiry = control["reason"], control["credentialExpiresAt"]
    delay, blocked = control["cooldownSeconds"], control["cooldownBlocked"]
    if (type(reason) is not str or reason not in REASONS or type(blocked) is not bool
            or delay is not None and (type(delay) is not int or not 1 <= delay <= MAX_COOLDOWN_SECONDS)
            or blocked and delay is not None
            or reason == "rate-limited" and delay is None and not blocked
            or reason not in {"rate-limited", "response-invalid"} and (delay is not None or blocked)):
        raise ProtocolError("Invalid private GitHub control")
    if expiry is not None:
        # Reserved canonical DATA support, not a wire-header grammar. The live
        # source-stage profile ALWAYS emits null and refuses any expiry header.
        from .api._github_connection import _utc

        try:
            _utc(expiry)
        except (ValueError, TypeError, UnicodeError, OverflowError):
            raise ProtocolError("Invalid private GitHub control") from None
    return control


def encode_response(request_id: str, *, facts: object, control: object) -> bytes:
    """Encode only whitelisted facts/control; no Request/token serialization."""
    from .api._github_connection import _projection
    from .errors import ConfigurationError

    try:
        if type(request_id) is not str or _ID.fullmatch(request_id) is None:
            raise ProtocolError("Invalid private GitHub response")
        selected = _projection(facts)
        if any(selected[name]["state"] not in {"observed", "unavailable"}
               or selected[name]["reason"] not in REASONS for name in ("account", "repository", "automation")):
            raise ProtocolError("Invalid private GitHub response")
        safe_control = _check_control(control)
        if safe_control["reason"] == "none" and any(selected[name]["state"] != "observed"
                                                   for name in ("account", "repository", "automation")):
            raise ProtocolError("Invalid private GitHub response")
        # A fatal projected reason cannot be hidden by a retryable disposition.
        # response-invalid may dominate another refusal (including a separately
        # validated cooldown); cancelled dependents do not erase the real cause.
        required = {
            "unauthorized": {"unauthorized", "response-invalid"},
            "target-changed": {"target-changed", "response-invalid"},
            "response-invalid": {"response-invalid"},
            "expired": {"expired", "response-invalid"},
            "rate-limited": {"rate-limited", "response-invalid"},
        }
        for name in ("account", "repository", "automation"):
            reason = selected[name]["reason"]
            if (reason in required and safe_control["reason"] not in required[reason]
                    or reason == "rate-limited" and safe_control["cooldownSeconds"] is None
                    and not safe_control["cooldownBlocked"]):
                raise ProtocolError("Invalid private GitHub response")
        value = {"protocol": PROTOCOL, "id": request_id, "facts": selected, "control": safe_control}
        _check_values(value, nodes=2000, depth=12)
        raw = json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8") + b"\n"
        if len(raw) > MAX_RESPONSE_BYTES:
            raise ProtocolError("Invalid private GitHub response")
        return raw
    except (ValueError, TypeError, UnicodeError, RecursionError, ConfigurationError, OverflowError):
        raise ProtocolError("Invalid private GitHub response") from None


def _read_request(fd: int, end: float) -> bytes:
    chunks: list[bytes] = []
    size = 0
    while True:
        if time.monotonic() >= end:
            raise ProtocolError("Private GitHub input deadline")
        block = os.read(fd, min(4096, MAX_REQUEST_BYTES + 1 - size))
        if not block:
            return b"".join(chunks)
        chunks.append(block)
        size += len(block)
        if size > MAX_REQUEST_BYTES:
            raise ProtocolError("Invalid private GitHub frame")


def _write_response(fd: int, raw: bytes) -> None:
    remaining = memoryview(raw)
    while remaining:
        written = os.write(fd, remaining[:4096])
        if written <= 0:
            raise OSError("Private GitHub response write failed")
        remaining = remaining[written:]


def main(*, started: float, runtime_dir: str) -> int:
    """Sole live entry, after the fixed bootstrap; never called by pure tests."""
    owned: list[int] = []
    status = 0
    try:
        if (type(started) not in (float, int) or not math.isfinite(started)
                or not math.isfinite(started + READ_SECONDS) or type(runtime_dir) is not str
                or not os.path.isabs(runtime_dir)):
            return 78
        control = os.dup(0)
        owned.append(control)
        os.set_inheritable(control, False)
        result = os.dup(1)
        owned.append(result)
        os.set_inheritable(result, False)
        null = os.open(os.devnull, os.O_RDONLY)
        owned.append(null)
        os.dup2(null, 0, inheritable=False)
        os.dup2(2, 1, inheritable=False)
        # Incidental imports/logs cannot use the response pipe. Ordinary API
        # initialization is real; it is not bypassed with a fictitious submodule.
        from datetime import datetime, timezone
        from ._github_connection_transport import _make_live_reader, observe

        request = parse_request(_read_request(control, started + READ_SECONDS))
        reader = _make_live_reader(request, started=started, runtime_dir=runtime_dir)
        observed_at = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
        outcome = observe(request, reader, observed_at=observed_at)
        _write_response(result, encode_response(request.id, facts=outcome["facts"], control=outcome["control"]))
    except (KeyboardInterrupt, SystemExit):
        status = 130
    except Exception:
        status = 70
        try:
            os.write(2, b"Mobile Release Kit private GitHub read failed.\n")
        except OSError:
            pass
    finally:
        while owned:
            fd = owned.pop()  # Retire before each descriptor's sole close.
            try:
                os.close(fd)
            except OSError:
                status = status or 74
    return status
