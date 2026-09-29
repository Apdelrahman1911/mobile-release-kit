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
DEVICE_PROTOCOL = "mrk-github-device/1"
METADATA_PROTOCOL = "mrk-github-input-metadata/1"
DEVICE_VERIFICATION_URI = "https://github.com/login/device"
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


@dataclass(frozen=True, slots=True, repr=False)
class MetadataRequest(ReadRequest):
    stage: str
    name: str


@dataclass(frozen=True, slots=True, repr=False)
class DeviceRequest:
    id: str
    step: str
    client_id: str
    device_code: str | None


def _device_code(value: object) -> bool:
    return type(value) is str and len(value) == 40 and all(0x21 <= ord(c) <= 0x7e for c in value)


def _user_code(value: object) -> bool:
    return type(value) is str and re.fullmatch(r"[A-Z0-9]{4}-[A-Z0-9]{4}", value, flags=re.ASCII) is not None


def _client_id(value: object) -> bool:
    return type(value) is str and re.fullmatch(r"[A-Za-z0-9._-]{1,128}", value, flags=re.ASCII) is not None


def _seconds(value: object) -> bool:
    return type(value) is int and 1 <= value <= 86_400


def _app_token(value: object, prefix: str) -> bool:
    return (type(value) is str and value.startswith(prefix) and len(prefix) < len(value) <= 4096
            and re.fullmatch(r"[A-Za-z0-9_]+", value, flags=re.ASCII) is not None)


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


def parse_request(raw: bytes) -> ReadRequest | MetadataRequest | DeviceRequest:
    """One exact frame, including the sole terminal newline and complete EOF."""
    try:
        if (type(raw) is not bytes or not 1 < len(raw) <= MAX_REQUEST_BYTES
                or not raw.endswith(b"\n") or raw.count(b"\n") != 1 or b"\r" in raw):
            raise ProtocolError("Invalid private GitHub frame")
        value = _decode_json(raw[:-1], limit=MAX_REQUEST_BYTES - 1, nodes=128, depth=6, exact=True)
        if type(value) is not dict or set(value) != {"protocol", "id", "params"}:
            raise ProtocolError("Invalid private GitHub frame")
        if (value["protocol"] not in {PROTOCOL, DEVICE_PROTOCOL, METADATA_PROTOCOL} or type(value["id"]) is not str
                or _ID.fullmatch(value["id"]) is None):
            raise ProtocolError("Invalid private GitHub frame")
        params = value["params"]
        if value["protocol"] == DEVICE_PROTOCOL:
            if type(params) is not dict or set(params) != {"step", "clientId", "deviceCode"}:
                raise ProtocolError("Invalid private GitHub device frame")
            step, client, code = params["step"], params["clientId"], params["deviceCode"]
            if (type(step) is not str or step not in {"start", "poll"} or not _client_id(client)
                    or step == "start" and code is not None or step == "poll" and not _device_code(code)):
                raise ProtocolError("Invalid private GitHub device frame")
            return DeviceRequest(value["id"], step, client, code)
        metadata = value["protocol"] == METADATA_PROTOCOL
        expected_keys = {"repository", "expectedAccountId", "expectedRepositoryId", "token"}
        if metadata:
            expected_keys |= {"stage", "name"}
        if type(params) is not dict or set(params) != expected_keys:
            raise ProtocolError("Invalid private GitHub frame")
        repository, account, repo, token = (params[name] for name in
                                            ("repository", "expectedAccountId", "expectedRepositoryId", "token"))
        if (type(repository) is not str or TOOLING_REPOSITORY_RE.fullmatch(repository) is None
                or account is not None and not _numeric_id(account)
                or repo is not None and (account is None or not _numeric_id(repo))
                or type(token) is not str or not 1 <= len(token) <= 4096
                or any(not 0x21 <= ord(char) <= 0x7e for char in token)):
            raise ProtocolError("Invalid private GitHub frame")
        if metadata:
            from .credential_requirements import ENVIRONMENT_NAMES, ENVIRONMENT_INPUT_TYPES

            stage, name = params["stage"], params["name"]
            if (account is None or repo is None or type(stage) is not str or stage not in ENVIRONMENT_NAMES
                    or type(name) is not str or name not in ENVIRONMENT_INPUT_TYPES):
                raise ProtocolError("Invalid fixed environment metadata selection")
            return MetadataRequest(value["id"], repository, account, repo, token, stage, name)
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


def _device_failure(reason: str = "response-invalid", *, delay: int | None = None,
                    blocked: bool = False) -> dict[str, Any]:
    return {"kind": "failed", "reason": reason, "cooldownSeconds": delay, "cooldownBlocked": blocked}


def project_device_result(request: DeviceRequest, observation: object, control: object) -> dict[str, Any]:
    """Private credential projection, NEVER a renderer/API projection or log.

    The ordinary live exchange has already completed its actual synchronous
    close. Native still must consume its original settled process receipt.
    """
    try:
        admitted = _check_control(control)
        if admitted["reason"] != "none":
            return _device_failure(admitted["reason"], delay=admitted["cooldownSeconds"], blocked=admitted["cooldownBlocked"])
        if (type(request) is not DeviceRequest or request.step not in {"start", "poll"}
                or type(observation) is not dict or set(observation) != {"status", "body", "failure"}
                or type(observation["status"]) is not int or observation["status"] != 200
                or observation["failure"] != "none" or type(observation["body"]) is not dict):
            return _device_failure()
        body = observation["body"]
        if "error" in body:
            if (not set(body) <= {"error", "error_description", "error_uri", "interval"}
                    or type(body["error"]) is not str or len(body["error"]) > 64
                    or any(type(body[k]) is not str or len(body[k]) > 4096 for k in ("error_description", "error_uri") if k in body)
                    or "interval" in body and not _seconds(body["interval"])):
                return _device_failure()
            error = body["error"]
            if request.step == "poll" and error == "authorization_pending":
                return {"kind": "pending", "interval": body.get("interval")}
            if request.step == "poll" and error == "slow_down" and "interval" in body:
                return {"kind": "slow-down", "interval": body["interval"]}
            reason = {"access_denied": "unauthorized", "unverified_user_email": "unauthorized",
                      "expired_token": "expired", "token_expired": "expired",
                      "incorrect_client_credentials": "publisher-unconfigured",
                      "device_flow_disabled": "publisher-unconfigured"}.get(error, "response-invalid")
            return _device_failure(reason)
        if request.step == "start":
            if (set(body) != {"device_code", "user_code", "verification_uri", "expires_in", "interval"}
                    or not _device_code(body["device_code"]) or not _user_code(body["user_code"])
                    or body["verification_uri"] != DEVICE_VERIFICATION_URI
                    or not _seconds(body["expires_in"]) or not _seconds(body["interval"])):
                return _device_failure()
            return {"kind": "code", "deviceCode": body["device_code"], "userCode": body["user_code"],
                    "expiresIn": body["expires_in"], "interval": body["interval"]}
        required = {"access_token", "token_type", "scope"}
        expiry = {"expires_in", "refresh_token", "refresh_token_expires_in"}
        if (set(body) not in (required, required | expiry) or body["token_type"] != "bearer"
                or body["scope"] != "" or not _app_token(body["access_token"], "ghu_")):
            return _device_failure()
        if "expires_in" in body and (type(body["expires_in"]) is not int or body["expires_in"] != 28_800
                or type(body["refresh_token_expires_in"]) is not int or body["refresh_token_expires_in"] != 15_897_600
                or not _app_token(body["refresh_token"], "ghr_")):
            return _device_failure()
        # Refresh material never crosses the private result frame or persists.
        return {"kind": "token", "token": body["access_token"], "expiresIn": body.get("expires_in")}
    except (ValueError, TypeError, UnicodeError, OverflowError, KeyError):
        return _device_failure()


def encode_device_response(request_id: str, result: object) -> bytes:
    """Only the finite private device DTO crosses the private native pipe."""
    if type(request_id) is not str or _ID.fullmatch(request_id) is None or type(result) is not dict:
        raise ProtocolError("Invalid private GitHub device response")
    kind = result.get("kind")
    valid = False
    if kind == "code" and set(result) == {"kind", "deviceCode", "userCode", "expiresIn", "interval"}:
        valid = (_device_code(result["deviceCode"]) and _user_code(result["userCode"])
                 and _seconds(result["expiresIn"]) and _seconds(result["interval"]))
    elif kind == "pending" and set(result) == {"kind", "interval"}:
        valid = result["interval"] is None or _seconds(result["interval"])
    elif kind == "slow-down" and set(result) == {"kind", "interval"}:
        valid = _seconds(result["interval"])
    elif kind == "token" and set(result) == {"kind", "token", "expiresIn"}:
        valid = (_app_token(result["token"], "ghu_") and (result["expiresIn"] is None
                 or type(result["expiresIn"]) is int and result["expiresIn"] == 28_800))
    elif kind == "failed" and set(result) == {"kind", "reason", "cooldownSeconds", "cooldownBlocked"}:
        reason, delay, blocked = result["reason"], result["cooldownSeconds"], result["cooldownBlocked"]
        valid = (type(reason) is str and reason in (REASONS - {"none", "target-changed"}) | {"publisher-unconfigured"}
                 and type(blocked) is bool and (delay is None or type(delay) is int and 1 <= delay <= MAX_COOLDOWN_SECONDS)
                 and not (blocked and delay is not None) and (reason != "rate-limited" or delay is not None or blocked)
                 and (reason in {"rate-limited", "response-invalid"} or delay is None and not blocked))
    if not valid:
        raise ProtocolError("Invalid private GitHub device response")
    raw = json.dumps({"protocol": DEVICE_PROTOCOL, "id": request_id, "result": result},
                     ensure_ascii=True, allow_nan=False, separators=(",", ":")).encode("utf-8") + b"\n"
    if len(raw) > MAX_RESPONSE_BYTES:
        raise ProtocolError("Invalid private GitHub device response")
    return raw


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


def main(*, started: float, runtime_dir: str, runner_prerequisite: bool = False) -> int:
    """Sole live entry, after the fixed bootstrap; never called by pure tests."""
    owned: list[int] = []
    status = 0
    try:
        if (type(started) not in (float, int) or not math.isfinite(started)
                or not math.isfinite(started + READ_SECONDS) or type(runtime_dir) is not str
                or not os.path.isabs(runtime_dir) or type(runner_prerequisite) is not bool):
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
        from ._github_connection_transport import _make_live_reader, observe, device_step

        if runner_prerequisite:
            # Only the separate fixed installed bootstrap chooses this parser.
            # Its protocol is not admitted by the ordinary read/device entry.
            from . import github_runner_prerequisite as runner

            request = runner.parse_request(_read_request(control, started + READ_SECONDS))
            reader = runner._make_live_reader(request, started=started, runtime_dir=runtime_dir)
            observed_at = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
            outcome = runner.observe(request, reader, observed_at=observed_at)
            _write_response(result, runner.encode_response(request.id, outcome))
        else:
            request = parse_request(_read_request(control, started + READ_SECONDS))
        if not runner_prerequisite and type(request) is DeviceRequest:
            outcome = device_step(request, started=started, runtime_dir=runtime_dir)
            _write_response(result, encode_device_response(request.id, outcome))
        elif not runner_prerequisite and type(request) is MetadataRequest:
            from . import github_environment_metadata as metadata

            reader = metadata._make_live_reader(request, started=started, runtime_dir=runtime_dir)
            observed_at = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
            outcome = metadata.observe(request, reader, observed_at=observed_at)
            _write_response(result, metadata.encode_response(request, outcome))
        elif not runner_prerequisite:
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
