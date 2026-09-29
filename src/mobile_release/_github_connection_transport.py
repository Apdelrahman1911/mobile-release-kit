"""Fixed GitHub API reads/actions and one-shot App device authorization profiles.

No socket/http.client/ssl import occurs at module import. Only the private live
factory loads them, from the original private engine entry after channel custody.
The finite readers below are the delegates of that factory's HTTPResponse
subclass, not a general HTTP client, URL dispatcher or alternative TLS stack.
"""
from __future__ import annotations

import math
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Protocol

from ._desktop_github_engine import (MAX_COOLDOWN_SECONDS, READ_SECONDS, ReadRequest, DeviceRequest,
                                    _client_id, _device_code, project_device_result,
                                    _JsonError, _JsonLimit, _check_control, _check_values,
                                    _decode_json)

MAX_BODY_BYTES = 256 * 1024
MAX_BODY_TOTAL = 1024 * 1024
MAX_HEADER_BYTES = 32 * 1024
MAX_HEADER_FIELDS = 64
MAX_HEADER_LINE = 8 * 1024
MAX_FRAMING_BYTES = 32 * 1024
MAX_METADATA_TOTAL = 320 * 1024
MAX_CHUNK_LINE = 128
MAX_CHUNKS = 4096  # Includes the terminal zero chunk.
MAX_TRAILER_FIELDS = 16
MAX_TRAILER_BYTES = 8 * 1024
MAX_TRAILER_LINE = 2 * 1024
MAX_CA_BYTES = 512 * 1024
_READ_CHUNK = 4096
_TCHAR = frozenset(b"!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")
_CONTROL_NAMES = frozenset({"github-authentication-token-expiration", "retry-after",
                            "x-ratelimit-remaining", "x-ratelimit-reset"})
_FORBIDDEN_TRAILERS = _CONTROL_NAMES | frozenset({
    "authorization", "proxy-authorization", "www-authenticate", "proxy-authenticate",
    "authentication-info", "proxy-authentication-info",
    "host", "connection", "upgrade", "content-length", "transfer-encoding", "te",
    "trailer", "content-encoding", "content-type", "cookie", "set-cookie",
})
_LONG = object()
_EPOCH_LIMIT = 2**63 - 1
_FATAL = frozenset({"unauthorized", "target-changed", "response-invalid", "expired"})


class _ExchangeProfile(Enum):
    STANDARD = "standard"
    RELEASE_PREPARE = "release-prepare"
    DEVICE_START = "device-start"
    DEVICE_POLL = "device-poll"
    INPUT_GROUP = "input-group"
    RUNNER_PREREQUISITE = "runner-prerequisite"


class _ResponseRole(Enum):
    STANDARD = "standard"
    RELEASE_CONFIG = "release-config"
    RELEASE_VERSION = "release-version"
    INPUT_GROUP_CONFIG = "input-group-config"
    INPUT_GROUP_WRITE = "input-group-write"
    RUNNER_PREREQUISITE = "runner-prerequisite"


def _role_limits(profile: _ExchangeProfile, role: _ResponseRole) -> tuple[int, int]:
    """Closed private roles, never caller-provided numeric limits."""
    if type(profile) is not _ExchangeProfile or type(role) is not _ResponseRole:
        raise ValueError("Invalid fixed GitHub response role")
    if role in {_ResponseRole.RELEASE_CONFIG, _ResponseRole.RELEASE_VERSION}:
        if profile is not _ExchangeProfile.RELEASE_PREPARE:
            raise ValueError("Fixed GitHub response role belongs to another action")
    elif role in {_ResponseRole.INPUT_GROUP_CONFIG, _ResponseRole.INPUT_GROUP_WRITE}:
        if profile is not _ExchangeProfile.INPUT_GROUP:
            raise ValueError("Fixed GitHub response role belongs to another action")
    elif role is _ResponseRole.RUNNER_PREREQUISITE:
        if profile is not _ExchangeProfile.RUNNER_PREREQUISITE:
            raise ValueError("Fixed runner response role belongs to another action")
    if profile in {_ExchangeProfile.DEVICE_START, _ExchangeProfile.DEVICE_POLL}:
        return 64 * 1024, 128
    return (768 * 1024 if role in {_ResponseRole.RELEASE_CONFIG, _ResponseRole.INPUT_GROUP_CONFIG} else MAX_BODY_BYTES,
            2048 if role is _ResponseRole.RELEASE_VERSION else 1024)

def _request_limits(profile: _ExchangeProfile, role: _ResponseRole, method: str, path: str) -> tuple[int, int]:
    limits = _role_limits(profile, role)
    if profile in {_ExchangeProfile.DEVICE_START, _ExchangeProfile.DEVICE_POLL}:
        expected = "/login/device/code" if profile is _ExchangeProfile.DEVICE_START else "/login/oauth/access_token"
        if method != "POST" or path != expected:
            raise ValueError("Fixed GitHub device endpoint differs")
    prefix = r"/repos/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/contents/"
    if role in {_ResponseRole.RELEASE_CONFIG, _ResponseRole.INPUT_GROUP_CONFIG}:
        if method != "GET" or type(path) is not str or re.fullmatch(prefix + r"release/mobile-release\.json\?ref=[0-9a-f]{40}", path) is None:
            raise ValueError("Fixed release config response role differs")
    elif role is _ResponseRole.RELEASE_VERSION:
        component = r"(?:[A-Za-z0-9._~-]|%[0-9A-F]{2})+"
        if method != "GET" or type(path) is not str or re.fullmatch(prefix + component + r"(?:/" + component + r"){0,11}\?ref=[0-9a-f]{40}", path) is None:
            raise ValueError("Fixed release version response role differs")
    if profile is _ExchangeProfile.INPUT_GROUP:
        from .credential_group_envelope import INPUT_GROUP_ENVIRONMENT_NAMES
        repo = r"/repos/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+"
        environment = repo + r"/environments/mobile-(?:candidate|external-testing|production)"
        secret = environment + "/secrets/(?:" + "|".join(sorted(INPUT_GROUP_ENVIRONMENT_NAMES)) + ")"
        if role is _ResponseRole.INPUT_GROUP_WRITE:
            valid = method == "PUT" and type(path) is str and re.fullmatch(secret, path) is not None
        elif role is _ResponseRole.INPUT_GROUP_CONFIG:
            valid = True  # Exact fixed Contents route checked above.
        else:
            caller = prefix + r"\.github/workflows/mobile-(?:candidate|external-testing|production-submit)\.yml\?ref=[0-9a-f]{40}"
            ref = repo + r"/git/ref/heads/(?:[A-Za-z0-9._~-]|%[0-9A-F]{2}){1,600}"
            valid = (role is _ResponseRole.STANDARD and method == "GET" and type(path) is str
                     and (path == "/user" or any(re.fullmatch(pattern, path) is not None
                          for pattern in (repo, caller, ref, environment, environment + "/secrets/public-key", secret))))
        if not valid:
            raise ValueError("Fixed input-group request role differs")
    if profile is _ExchangeProfile.RUNNER_PREREQUISITE:
        repository = r"/repos/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+"
        organization = r"/orgs/[A-Za-z0-9_.-]+"
        suffix = r"\?per_page=100&page=1"
        group = (re.fullmatch(organization + r"/actions/runner-groups/([1-9][0-9]{0,19})/runners" + suffix, path)
                 if type(path) is str else None)
        valid = (role is _ResponseRole.RUNNER_PREREQUISITE and method == "GET" and type(path) is str
                 and (path == "/user" or re.fullmatch(repository, path) is not None
                      or re.fullmatch(repository + r"/actions/runners" + suffix, path) is not None
                      or re.fullmatch(organization + r"/actions/runner-groups" + suffix, path) is not None
                      or group is not None and int(group[1]) <= 2**64 - 1))
        if not valid:
            raise ValueError("Fixed runner prerequisite request role differs")
    return limits

class ReadFailure(Exception):
    def __init__(self, reason: str) -> None:
        if reason not in {"network-unavailable", "tls-failed", "response-invalid", "response-limit", "cancelled"}:
            raise ValueError("Invalid fixed GitHub failure")
        self.reason = reason
        super().__init__("The fixed GitHub read was unavailable")


class _CloseFailure(RuntimeError):
    pass


def _control(reason: str = "none", delay: int | None = None, blocked: bool = False) -> dict[str, Any]:
    # No wire expiry grammar has been established. Never synthesize a server
    # timestamp from the native ceiling or parse a plausible-looking header.
    return {"reason": reason, "credentialExpiresAt": None,
            "cooldownSeconds": delay, "cooldownBlocked": blocked}


def _refuse(control: dict[str, Any], reason: str) -> dict[str, Any]:
    delay, blocked = control["cooldownSeconds"], control["cooldownBlocked"]
    if delay is not None or blocked:
        # A known not-before must survive body/identity/header refusal. The
        # reviewed response-invalid path also retires credential use natively.
        return _control("rate-limited" if reason == "rate-limited" else "response-invalid", delay, blocked)
    if control["reason"] in _FATAL and reason != "response-invalid":
        reason = control["reason"]
    return _control(reason)


@dataclass(slots=True, repr=False)
class ReadResult:
    observation: dict[str, Any]
    control: dict[str, Any]


def _failed(reason: str, control: dict[str, Any] | None = None) -> ReadResult:
    # These are failed/unsent observations, not invented HTTP responses.
    return ReadResult({"status": None, "body": None, "failure": reason},
                      _refuse(control or _control(), reason))


class _Reader(Protocol):
    def read(self, step: str) -> ReadResult: ...


class _Budget:
    def __init__(self, started: float, *, monotonic: Callable[[], float] = time.monotonic,
                 wall: Callable[[], float] = time.time, _profile: _ExchangeProfile = _ExchangeProfile.STANDARD) -> None:
        _role_limits(_profile, _ResponseRole.STANDARD)
        if type(started) not in (int, float):
            raise ReadFailure("network-unavailable")
        self.started = started
        self.end = started + READ_SECONDS
        self.monotonic = monotonic
        self.wall = wall
        self.body_bytes = 0
        self.metadata_bytes = 0
        self.profile = _profile
        self.body_total_limit = (64 * 1024 if _profile in {_ExchangeProfile.DEVICE_START, _ExchangeProfile.DEVICE_POLL}
                                 else 2 * 1024 * 1024 if _profile in {_ExchangeProfile.RELEASE_PREPARE, _ExchangeProfile.INPUT_GROUP} else MAX_BODY_TOTAL)
        if not math.isfinite(started) or not math.isfinite(self.end):
            raise ReadFailure("network-unavailable")

    def remaining(self) -> float:
        now = self.monotonic()
        if type(now) not in (int, float) or not math.isfinite(now) or now < self.started or now >= self.end:
            # A helper budget is NOT proof that the credential expired.
            raise ReadFailure("network-unavailable")
        return self.end - now

    def wall_seconds(self) -> int | None:
        try:
            value = self.wall()
            if type(value) not in (int, float) or not math.isfinite(value):
                return None
            whole = math.floor(value)
            return whole if -_EPOCH_LIMIT <= whole <= _EPOCH_LIMIT else None
        except Exception:
            return None


@dataclass(slots=True, repr=False)
class _Head:
    status: int
    version: int
    headers: dict[str, list[str | None]]
    invalid: bool = False
    framing: str = "eof"
    length: int | None = None
    error: str | None = None


def _field(line: bytes) -> tuple[str | None, str | None]:
    name, separator, value = line[:-2].partition(b":")
    if not separator or not name or any(byte not in _TCHAR for byte in name):
        return None, None
    key = name.decode("ascii").lower()
    if any(not 0x20 <= byte <= 0x7e for byte in value):
        return key, None
    return key, value.decode("ascii").strip(" ")


def _single(headers: dict[str, list[str | None]], name: str) -> tuple[str | None, bool, bool]:
    values = headers.get(name)
    if values is None:
        return None, False, True
    if len(values) != 1 or values[0] is None:
        return None, True, False
    return values[0], True, True


def _decimal(value: str, maximum: int) -> int | object:
    if not value or any(not "0" <= char <= "9" for char in value):
        raise ValueError("Invalid bounded decimal")
    significant = value.lstrip("0") or "0"
    bound = str(maximum)
    if len(significant) > len(bound) or len(significant) == len(bound) and significant > bound:
        return _LONG
    return int(significant)


def _framing(head: _Head, maximum: int = MAX_BODY_BYTES) -> None:
    length, has_length, length_ok = _single(head.headers, "content-length")
    coding, has_coding, coding_ok = _single(head.headers, "transfer-encoding")
    encoding, has_encoding, encoding_ok = _single(head.headers, "content-encoding")
    if (head.invalid or not length_ok or not coding_ok or not encoding_ok
            or has_length and has_coding or has_coding and coding.lower() != "chunked"
            or has_encoding and encoding.lower() != "identity"
            or "upgrade" in head.headers
            or any(value is not None and "upgrade" in (part.strip(" ").lower() for part in value.split(","))
                   for value in head.headers.get("connection", []))):
        head.error = "response-invalid"
        return
    if has_coding:
        head.framing = "chunked"
    elif has_length:
        try:
            size = _decimal(length, maximum)
        except ValueError:
            head.error = "response-invalid"
            return
        head.framing = "length"
        head.length = maximum + 1 if size is _LONG else size
        if size is _LONG and head.status == 200:
            head.error = "response-limit"
    if head.status == 200:
        media, present, valid = _single(head.headers, "content-type")
        if (not present or not valid or re.fullmatch(
                r"application/(?:json|vnd\.github\+json)(?: *; *charset=utf-8)?", media, re.ASCII | re.IGNORECASE) is None):
            head.error = "response-invalid"


def _chunk_size(line: bytes, maximum: int = MAX_BODY_BYTES) -> int:
    body = line[:-2]
    index = 0
    while index < len(body) and body[index] in b"0123456789abcdefABCDEF":
        index += 1
    if index == 0:
        raise ReadFailure("response-invalid")
    digits = body[:index].lstrip(b"0") or b"0"
    bound = format(maximum, "x").encode("ascii")
    if len(digits) > len(bound) or len(digits) == len(bound) and digits.lower() > bound:
        raise ReadFailure("response-limit")
    size = int(digits, 16)
    # The supported finite extension subset is ;token[=token/quoted-string].
    # Discarded extensions still count toward every raw framing bound.
    while index < len(body):
        if body[index] != ord(";"):
            raise ReadFailure("response-invalid")
        index += 1
        start = index
        while index < len(body) and body[index] in _TCHAR:
            index += 1
        if index == start:
            raise ReadFailure("response-invalid")
        if index < len(body) and body[index] == ord("="):
            index += 1
            if index < len(body) and body[index] == ord('"'):
                index += 1
                closed = False
                while index < len(body):
                    byte = body[index]
                    index += 1
                    if byte == ord('"'):
                        closed = True
                        break
                    if byte == ord("\\"):
                        if index >= len(body) or not 0x20 <= body[index] <= 0x7e:
                            raise ReadFailure("response-invalid")
                        index += 1
                    elif not 0x20 <= byte <= 0x7e:
                        raise ReadFailure("response-invalid")
                if not closed:
                    raise ReadFailure("response-invalid")
            else:
                start = index
                while index < len(body) and body[index] in _TCHAR:
                    index += 1
                if index == start:
                    raise ReadFailure("response-invalid")
    return size


class _ResponseBody:
    """Narrow finite delegate used by the live HTTPResponse subclass.

    Inert tests supply BytesIO, not an HTTP/TLS/socket factory. Each raw read is
    sized and rechecks the original budget. Header/framing accounting happens
    during reads, not after http.client/email has allocated unbounded metadata.
    """
    def __init__(self, source: Any, budget: _Budget, *, before_read: Callable[[float], None] | None = None,
                 _role: _ResponseRole = _ResponseRole.STANDARD) -> None:
        self.source = source
        self.budget = budget
        self.maximum, _ = _role_limits(budget.profile, _role)
        self.before_read = before_read
        self.header_bytes = 0
        self.framing_bytes = 0
        self.trailer_bytes = 0
        self.body_bytes = 0
        self.chunks = 0
        self.chunk_left: int | None = None
        self.done = False
        self.control: dict[str, Any] | None = None
        self.head = self._head()
        self.length_left = self.head.length

    def _raw(self, size: int) -> bytes:
        remaining = self.budget.remaining()
        if self.before_read is not None:
            self.before_read(remaining)
        # One finite buffered/raw operation; never read() with no size.
        reader = getattr(self.source, "read1", self.source.read)
        block = reader(size)
        self.budget.remaining()  # A late return cannot renew the helper budget.
        if type(block) is not bytes or len(block) > size:
            raise ReadFailure("response-invalid")
        return block

    def _allow_meta(self, size: int, kind: str) -> None:
        local, limit = ((self.header_bytes, MAX_HEADER_BYTES) if kind == "headers"
                        else (self.framing_bytes, MAX_FRAMING_BYTES))
        if (local + size > limit or self.budget.metadata_bytes + size > MAX_METADATA_TOTAL
                or kind == "trailers" and self.trailer_bytes + size > MAX_TRAILER_BYTES):
            raise ReadFailure("response-limit")

    def _charge_meta(self, size: int, kind: str) -> None:
        self.budget.metadata_bytes += size
        if kind == "headers":
            self.header_bytes += size
        else:
            self.framing_bytes += size
            if kind == "trailers":
                self.trailer_bytes += size

    def _line(self, limit: int, kind: str) -> bytes:
        line = bytearray()
        while len(line) < limit:
            self._allow_meta(1, kind)
            block = self._raw(1)
            if not block:
                raise ReadFailure("response-invalid")
            self._charge_meta(1, kind)
            line.extend(block)
            if block == b"\n":
                if not line.endswith(b"\r\n"):
                    raise ReadFailure("response-invalid")
                return bytes(line)
        raise ReadFailure("response-limit")

    def _fixed_meta(self, size: int) -> bytes:
        data = bytearray()
        while len(data) < size:
            self._allow_meta(size - len(data), "framing")
            block = self._raw(size - len(data))
            if not block:
                raise ReadFailure("response-invalid")
            self._charge_meta(len(block), "framing")
            data.extend(block)
        return bytes(data)

    def _head(self) -> _Head:
        status_line = self._line(MAX_HEADER_LINE, "headers")
        match = re.fullmatch(rb"HTTP/1\.([01]) ([1-5][0-9]{2})(?: [\x20-\x7e]*)?\r\n", status_line)
        if match is None:
            raise ReadFailure("response-invalid")
        status = int(match[2])
        if status < 200:  # No stdlib informational-loop or protocol upgrade.
            raise ReadFailure("response-invalid")
        head = _Head(status, 10 if match[1] == b"0" else 11, {})
        previous: str | None = None
        count = 0
        while True:
            line = self._line(MAX_HEADER_LINE if count < MAX_HEADER_FIELDS else 2, "headers")
            if line == b"\r\n":
                break
            count += 1
            if line[:1] in (b" ", b"\t"):
                head.invalid = True
                if previous is not None:
                    head.headers[previous][-1] = None
                continue
            name, value = _field(line)
            previous = name
            if name is None:
                head.invalid = True
                continue
            head.headers.setdefault(name, []).append(value)
            if value is None:
                head.invalid = True
        _framing(head, self.maximum)
        return head

    def _trailers(self) -> None:
        fields = 0
        while True:
            line = self._line(MAX_TRAILER_LINE if fields < MAX_TRAILER_FIELDS else 2, "trailers")
            if line == b"\r\n":
                return
            fields += 1
            name, value = _field(line)
            if name is None or value is None or name in _FORBIDDEN_TRAILERS:
                raise ReadFailure("response-invalid")

    def _next_chunk(self) -> None:
        if self.chunk_left == 0 and self._fixed_meta(2) != b"\r\n":
            raise ReadFailure("response-invalid")
        if self.chunks >= MAX_CHUNKS:
            raise ReadFailure("response-limit")
        line = self._line(MAX_CHUNK_LINE, "framing")
        self.chunks += 1
        size = _chunk_size(line, self.maximum)
        if size > self.maximum - self.body_bytes or size > self.budget.body_total_limit - self.budget.body_bytes:
            raise ReadFailure("response-limit")
        if size == 0:
            self._trailers()  # Missing terminal CRLF/trailers are NOT EOF success.
            self.done = True
        self.chunk_left = size

    def read(self, maximum: int) -> bytes:
        if type(maximum) is not int or not 1 <= maximum <= _READ_CHUNK:
            raise ReadFailure("response-invalid")
        if self.head.error is not None:
            raise ReadFailure(self.head.error)
        if self.done:
            return b""
        if self.head.framing == "chunked":
            if self.chunk_left in (None, 0):
                self._next_chunk()
            if self.done:
                return b""
            maximum = min(maximum, self.chunk_left)
        elif self.head.framing == "length":
            if self.length_left == 0:
                self.done = True
                return b""
            maximum = min(maximum, self.length_left)
        # A one-byte overflow probe is permitted for unknown-length bodies.
        maximum = min(maximum, self.maximum + 1 - self.body_bytes,
                      self.budget.body_total_limit + 1 - self.budget.body_bytes)
        if maximum <= 0:
            raise ReadFailure("response-limit")
        block = self._raw(maximum)
        if not block:
            if self.head.framing != "eof":
                raise ReadFailure("response-invalid")
            self.done = True
            return b""
        self.body_bytes += len(block)
        self.budget.body_bytes += len(block)
        if self.body_bytes > self.maximum or self.budget.body_bytes > self.budget.body_total_limit:
            raise ReadFailure("response-limit")
        if self.head.framing == "chunked":
            self.chunk_left -= len(block)
        elif self.head.framing == "length":
            self.length_left -= len(block)
        return block


_WEEKDAYS = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")
_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")


def _http_date(value: str) -> int:
    # Strict IMF-fixdate is client policy, not a claim GitHub emits date-form
    # Retry-After. No email/dateutil/locale parser or obsolete HTTP date forms.
    match = re.fullmatch(r"(Mon|Tue|Wed|Thu|Fri|Sat|Sun), ([0-9]{2}) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) ([0-9]{4}) ([0-9]{2}):([0-9]{2}):([0-9]{2}) GMT", value, re.ASCII)
    if match is None:
        raise ValueError("Invalid fixed HTTP date")
    date = datetime(int(match[4]), _MONTHS.index(match[3]) + 1, int(match[2]),
                    int(match[5]), int(match[6]), int(match[7]), tzinfo=timezone.utc)
    if _WEEKDAYS[date.weekday()] != match[1]:
        raise ValueError("Invalid fixed HTTP date")
    delta = date - datetime(1970, 1, 1, tzinfo=timezone.utc)
    return delta.days * 86400 + delta.seconds


def _status_reason(status: int) -> str:
    return {200: "none", 401: "unauthorized", 403: "forbidden", 404: "not-found-or-inaccessible", 429: "rate-limited"}.get(
        status, "network-unavailable" if status >= 500 else "response-invalid")


def _header_control(head: _Head, budget: _Budget, *, _input_group_write: bool = False) -> dict[str, Any]:
    if _input_group_write and budget.profile is not _ExchangeProfile.INPUT_GROUP:
        raise ValueError("Input-group acknowledgement belongs to its fixed profile")
    expiry, has_expiry, expiry_ok = _single(head.headers, "github-authentication-token-expiration")
    retry, has_retry, retry_ok = _single(head.headers, "retry-after")
    remaining, has_remaining, remaining_ok = _single(head.headers, "x-ratelimit-remaining")
    reset, has_reset, reset_ok = _single(head.headers, "x-ratelimit-reset")
    invalid = has_expiry or not expiry_ok or head.invalid
    exhausted = False
    hints: list[tuple[str, int | object]] = []
    if has_remaining and remaining_ok:
        try:
            exhausted = _decimal(remaining, 0) == 0
        except ValueError:
            remaining_ok = False
    if has_retry and retry_ok:
        try:
            if retry and all("0" <= char <= "9" for char in retry):
                hints.append(("delta", _decimal(retry, MAX_COOLDOWN_SECONDS)))
            else:
                hints.append(("absolute", _http_date(retry)))
        except (ValueError, OverflowError):
            retry_ok = False
    if has_reset and reset_ok:
        try:
            parsed_reset = _decimal(reset, _EPOCH_LIMIT)
            if exhausted:
                hints.append(("absolute", parsed_reset))
        except ValueError:
            reset_ok = False
    invalid = invalid or not retry_ok or not remaining_ok or not reset_ok
    recognized = head.status == 429 or exhausted or head.status == 403 and has_retry and retry_ok
    # One wall-clock sample per response, only when needed. Integer conversion
    # includes the reviewed conservative second and never rounds a delay down.
    wall = budget.wall_seconds() if any(kind == "absolute" for kind, _ in hints) else None
    delays: list[int] = []
    blocked = False
    for kind, value in hints:
        if value is _LONG or kind == "absolute" and wall is None:
            blocked = True
            continue
        difference = value if kind == "delta" else value - wall + 1
        if not -_EPOCH_LIMIT <= difference <= _EPOCH_LIMIT:
            blocked = True
            continue
        delay = max(1, difference)
        if delay > MAX_COOLDOWN_SECONDS:
            blocked = True
        else:
            delays.append(delay)
    delay = None if blocked else max(delays) if delays else 60 if recognized else None
    base = "none" if _input_group_write and head.status in {201, 204} else _status_reason(head.status)
    if invalid:
        reason = "response-invalid"
    elif delay is not None or blocked:
        # In particular, a 401 can NEVER become retryable just because it also
        # has quota metadata. Preserve the hint using the retiring refusal path.
        reason = "rate-limited" if recognized and head.status in {200, 403, 429} else "response-invalid"
    else:
        reason = base
    return _control(reason, delay, blocked)


def _response_result(response: _ResponseBody, budget: _Budget) -> ReadResult:
    head = response.head
    control = _header_control(head, budget)
    response.control = control  # Retain a validated hint if a later IO read fails.
    if head.error is not None:
        return _failed(head.error, control)
    if control["reason"] == "response-invalid":
        return _failed("response-invalid", control)
    if head.status != 200:
        # Never read/parse/retain arbitrary error bodies, even JSON-looking ones.
        if head.status == 403 and control["reason"] == "rate-limited":
            return _failed("rate-limited", control)
        return ReadResult({"status": head.status, "body": None, "failure": "none"}, control)
    try:
        if head.length is not None and head.length > budget.body_total_limit - budget.body_bytes:
            raise ReadFailure("response-limit")
        chunks: list[bytes] = []
        while True:
            block = response.read(_READ_CHUNK)
            if not block:
                break
            chunks.append(block)
        body = _decode_json(b"".join(chunks), limit=response.maximum, nodes=20_000, depth=24)
        if type(body) is not dict:
            raise ReadFailure("response-invalid")
        return ReadResult({"status": 200, "body": body, "failure": "none"}, control)
    except _JsonLimit:
        return _failed("response-limit", control)
    except _JsonError:
        return _failed("response-invalid", control)
    except ReadFailure as error:
        return _failed(error.reason, control)


@dataclass(slots=True, repr=False)
class _InputWriteResult:
    # A remote head fact is separate from later original cleanup/publication.
    # This type belongs only to the fixed P2 PUT, never to old read profiles.
    write: dict[str, Any]
    control: dict[str, Any]
    cleanup: str = "pending"
    observation_sent: bool = False
    head_valid: bool = False


def _input_write_result(response: _ResponseBody, budget: _Budget) -> _InputWriteResult:
    if budget.profile is not _ExchangeProfile.INPUT_GROUP:
        raise ValueError("Input-group acknowledgement belongs to its fixed profile")
    head = response.head
    control = _header_control(head, budget, _input_group_write=True)
    response.control = control
    invalid = (head.invalid or head.error is not None
               or head.length is not None and head.length > response.maximum
               or head.status == 204 and (head.framing == "chunked" or head.length not in {None, 0}))
    if invalid:
        return _InputWriteResult({"state": "attempted-outcome-unknown"},
                                 _refuse(control, head.error or "response-invalid"))
    if head.status == 201:
        write = {"state": "acknowledged-created", "statusCode": 201}
    elif head.status == 204:
        write = {"state": "acknowledged-updated", "statusCode": 204}
    elif head.status in {401, 403, 404, 422, 429}:
        reason = {401: "unauthorized", 403: "forbidden", 404: "not-found-or-inaccessible",
                  422: "input-invalid", 429: "rate-limited"}[head.status]
        if head.status == 403 and control["reason"] == "rate-limited":
            reason = "rate-limited"
        write = {"state": "explicitly-rejected", "reason": reason}
    else:
        write = {"state": "attempted-outcome-unknown"}
    # Never consume an upstream PUT body. Exact TLS/head observation is enough
    # for its limited acknowledgement; close/finality/credential validity are
    # separate obligations. _ResponseBody already validated bounded framing.
    return _InputWriteResult(write, control, head_valid=True)


def _publish_input_write(result: _InputWriteResult, observer) -> None:
    if not result.head_valid:
        return
    try:
        # Copies prevent the notification adapter from rewriting latched DATA.
        observer(dict(result.write), dict(result.control))
        result.observation_sent = True
    except BaseException:
        # No native observation is fabricated. Every original close is still
        # attempted by exchange's existing finally; the fact itself survives.
        result.control = _refuse(result.control, "response-invalid")


def _settle_originals(originals: tuple[Any, Any], close_failed: list[bool],
                      write_result: _InputWriteResult | None = None) -> None:
    for original in originals:
        if original is not None:
            try:
                original.close()
            except BaseException:
                close_failed[0] = True
    if write_result is not None:
        write_result.cleanup = "unknown" if close_failed[0] else "confirmed"
        if close_failed[0]:
            write_result.control = _refuse(write_result.control, "response-invalid")
    elif close_failed[0]:
        raise _CloseFailure("Original GitHub close did not return") from None


def observe(request: ReadRequest, reader: _Reader, *, observed_at: str) -> dict[str, Any]:
    """Fixed at-most-five-read schedule; the fake seam is not a runtime option."""
    from .api._github_connection import (_account, _automation, _read, _repository, _utc,
                                         project_github_observations)
    from .api._json import bounded_json_text
    from .api.contracts import ApiError
    from .errors import ConfigurationError

    _utc(observed_at)
    unavailable = lambda: {"status": None, "body": None, "failure": "cancelled"}
    values: dict[str, Any] = {
        "repository": request.repository, "observedAt": observed_at,
        "expectedAccountId": request.expected_account_id, "expectedRepositoryId": request.expected_repository_id,
        "account": unavailable(), "repositoryBefore": unavailable(), "workflowPages": [], "repositoryAfter": unavailable(),
    }
    control = _control()

    def take(step: str) -> ReadResult:
        admitted_control: dict[str, Any] | None = None
        try:
            result = reader.read(step)
            if type(result) is not ReadResult:
                raise ValueError("Invalid fixed read result")
            admitted_control = _check_control(result.control)
            _read(result.observation)
            trial = dict(values)
            if step in {"workflows-1", "workflows-2"}:
                trial["workflowPages"] = [*values["workflowPages"], result.observation]
            else:
                trial[{"account": "account", "repository-before": "repositoryBefore",
                       "repository-after": "repositoryAfter"}[step]] = result.observation
            # Stop BEFORE another dependent GET if the combined bodies/envelope
            # exceed bounds, not only when finally encoding the result.
            _check_values(trial, nodes=20_000, depth=24)
            bounded_json_text(trial, max_bytes=MAX_BODY_TOTAL, max_nodes=20_000, max_depth=24)
            return result
        except ReadFailure as error:
            return _failed(error.reason, admitted_control)
        except (_JsonLimit, ConfigurationError):
            return _failed("response-limit", admitted_control)
        except (ValueError, TypeError, UnicodeError, OverflowError):
            return _failed("response-invalid", admitted_control)

    def finish() -> dict[str, Any]:
        nonlocal control
        try:
            # Account for ALL supplied bodies plus keys/wrappers before the
            # unchanged projector. Per-response admission alone is insufficient.
            _check_values(values, nodes=20_000, depth=24)
            bounded_json_text(values, max_bytes=MAX_BODY_TOTAL, max_nodes=20_000, max_depth=24)
        except (_JsonError, ConfigurationError, ValueError, TypeError, UnicodeError, OverflowError):
            control = _refuse(control, "response-limit")
            reduced = {**values, "account": {"status": None, "body": None, "failure": "response-limit"},
                       "repositoryBefore": unavailable(), "workflowPages": [], "repositoryAfter": unavailable()}
            facts = project_github_observations(reduced)
        else:
            try:
                facts = project_github_observations(values)
            except ApiError:
                control = _refuse(control, "response-invalid")
                reduced = {**values, "account": {"status": None, "body": None, "failure": "response-invalid"},
                           "repositoryBefore": unavailable(), "workflowPages": [], "repositoryAfter": unavailable()}
                facts = project_github_observations(reduced)
        if control["reason"] == "none":
            for name in ("account", "repository", "automation"):
                if facts[name]["state"] != "observed":
                    control = _refuse(control, facts[name]["reason"])
                    break
        return {"facts": facts, "control": control}

    account = take("account")
    values["account"], control = account.observation, account.control
    body, _ = _read(account.observation)
    if body is None:
        return finish()
    try:
        identity = _account(body)
    except (ValueError, TypeError, UnicodeError, OverflowError):
        values["account"] = _failed("response-invalid").observation
        control = _refuse(control, "response-invalid")
        return finish()
    if request.expected_account_id is not None and identity["id"] != request.expected_account_id:
        control = _refuse(control, "target-changed")
        return finish()
    if control["reason"] != "none":
        return finish()

    before = take("repository-before")
    values["repositoryBefore"], control = before.observation, before.control
    body, _ = _read(before.observation)
    if body is None:
        return finish()
    try:
        initial = _repository(body)
    except (ValueError, TypeError, UnicodeError, OverflowError):
        values["repositoryBefore"] = _failed("response-invalid").observation
        control = _refuse(control, "response-invalid")
        return finish()
    if (initial["fullName"].lower() != request.repository.lower()
            or request.expected_repository_id is not None and initial["id"] != request.expected_repository_id):
        control = _refuse(control, "target-changed")
        return finish()
    if control["reason"] != "none":
        return finish()

    for step in ("workflows-1", "workflows-2"):
        page = take(step)
        values["workflowPages"].append(page.observation)
        control = page.control
        body, _ = _read(page.observation)
        if body is not None:
            try:
                # Reuse the existing page/row validator, including ambiguous
                # listings. This is NOT a made-up repository identity bracket.
                _automation([_read(item) for item in values["workflowPages"]], observed_at)
            except (ValueError, TypeError, UnicodeError, OverflowError):
                values["workflowPages"][-1] = _failed("response-invalid").observation
                control = _refuse(control, "response-invalid")
                return finish()
        if control["reason"] in {"unauthorized", "rate-limited", "target-changed", "response-invalid", "expired", "cancelled"}:
            return finish()
        if body is None:
            code = page.observation["status"]
            # Ordinary listing 403/404/5xx may still bracket the target. A
            # transport refusal, limit or authorization failure never does.
            if code not in {403, 404} and not (type(code) is int and 500 <= code <= 599):
                return finish()
            break
        if step == "workflows-2" or len(body["workflows"]) != 100 or body["total_count"] <= 100:
            break

    listing_control = control
    after = take("repository-after")
    values["repositoryAfter"] = after.observation
    control = after.control if after.control["reason"] != "none" else listing_control
    body, _ = _read(after.observation)
    if body is not None:
        try:
            ending = _repository(body)
        except (ValueError, TypeError, UnicodeError, OverflowError):
            values["repositoryAfter"] = _failed("response-invalid").observation
            control = _refuse(control, "response-invalid")
        else:
            if (ending["fullName"].lower() != request.repository.lower() or ending["id"] != initial["id"]
                    or request.expected_repository_id is not None and ending["id"] != request.expected_repository_id):
                control = _refuse(control, "target-changed")
    return finish()


def _fixed_ca(runtime_dir: str, budget: _Budget) -> str:
    # This is a fixed sibling input, not a discovery/API/file-picker interface.
    # Byte/identity checks are defense in depth, NOT immutable runtime custody.
    import os
    import stat

    if type(runtime_dir) is not str or not os.path.isabs(runtime_dir):
        raise ValueError("Fixed GitHub trust is unavailable")
    path = os.path.join(runtime_dir, "github-ca.pem")
    budget.remaining()
    before = os.lstat(path)
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or not 0 < before.st_size <= MAX_CA_BYTES:
        raise ValueError("Fixed GitHub trust is unavailable")
    owned = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.set_inheritable(owned, False)
        state = lambda value: (value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
                               value.st_size, value.st_mtime_ns, value.st_ctime_ns)
        if state(os.fstat(owned)) != state(before):
            raise ValueError("Fixed GitHub trust is unavailable")
        chunks: list[bytes] = []
        size = 0
        while size <= before.st_size:
            budget.remaining()
            block = os.read(owned, min(_READ_CHUNK, before.st_size + 1 - size))
            if not block:
                break
            chunks.append(block)
            size += len(block)
        if (size != before.st_size or state(os.fstat(owned)) != state(before)
                or state(os.lstat(path)) != state(before)):
            raise ValueError("Fixed GitHub trust is unavailable")
        return b"".join(chunks).decode("ascii", errors="strict")
    finally:
        retired, owned = owned, -1
        os.close(retired)  # Sole close; failure cannot be reported as success.


def _fixed_host(profile: _ExchangeProfile) -> str:
    _role_limits(profile, _ResponseRole.STANDARD)
    return "github.com" if profile in {_ExchangeProfile.DEVICE_START, _ExchangeProfile.DEVICE_POLL} else "api.github.com"


def _wrap_fixed_tls(context: Any, source: Any, *, ignore_eof_option: int,
                    _profile: _ExchangeProfile = _ExchangeProfile.STANDARD) -> Any:
    """One fixed documented wrap, with no suppressed unexpected TLS EOF.

    The live caller supplies the actual SSLContext/option/socket. Inert tests
    supply recording DATA doubles; they cannot establish TLS close integrity.
    An unavailable option API refuses instead of choosing a version's defaults.
    """
    option = int(ignore_eof_option)
    if option <= 0:
        raise ReadFailure("tls-failed")
    context.options = int(context.options) & ~option
    if int(context.options) & option:
        raise ReadFailure("tls-failed")
    return context.wrap_socket(source, server_hostname=_fixed_host(_profile), suppress_ragged_eofs=False)


def _make_live_exchange(token: str | None, *, started: float, runtime_dir: str, api_version: str | None,
                        _profile: _ExchangeProfile = _ExchangeProfile.STANDARD) -> Callable[..., ReadResult | _InputWriteResult]:
    """Private bounded TLS/framing shared by closed native GitHub profiles.

    This is not a renderer/API URL interface. The calling profile separately
    claims each fixed endpoint once; this layer cannot grant or retry an action.
    """
    device = _profile in {_ExchangeProfile.DEVICE_START, _ExchangeProfile.DEVICE_POLL}
    if ((device and (token is not None or api_version is not None))
            or not device and (api_version not in {"2022-11-28", "2026-03-10"} or type(token) is not str
            or not 1 <= len(token) <= 4096 or any(not 0x21 <= ord(c) <= 0x7e for c in token))):
        raise ValueError("Invalid fixed GitHub transport input")
    _role_limits(_profile, _ResponseRole.STANDARD)
    if _profile in {_ExchangeProfile.INPUT_GROUP, _ExchangeProfile.RUNNER_PREREQUISITE} and api_version != "2026-03-10":
        raise ValueError("The fixed action requires its own API version")
    host = _fixed_host(_profile)
    device_claimed = False
    # http.client itself imports ssl. Both must stay inside this original live
    # entry, not at pure frame/schedule import or fixture construction time.
    import http.client
    import ssl

    budget = _Budget(started, _profile=_profile)
    budget.remaining()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.keylog_filename = None
    context.set_alpn_protocols(["http/1.1"])
    context.load_verify_locations(cadata=_fixed_ca(runtime_dir, budget))
    # Never create_default_context/load_default_certs/default_verify_paths;
    # never urllib transport, proxies, netrc, environment credentials or workflow clients.

    def exchange(method: str, path: str, body: bytes | None = None, *,
                 _role: _ResponseRole = _ResponseRole.STANDARD,
                 _on_write_status=None) -> ReadResult | _InputWriteResult:
        nonlocal device_claimed
        _, path_limit = _request_limits(_profile, _role, method, path)
        writing = _profile is _ExchangeProfile.INPUT_GROUP and _role is _ResponseRole.INPUT_GROUP_WRITE
        if (writing and not callable(_on_write_status) or not writing and _on_write_status is not None):
            raise ValueError("Fixed write observation callback differs")
        if (method not in ({"PUT"} if writing else {"GET", "POST"}) or type(path) is not str or not path.startswith("/")
                or len(path) > path_limit or any(not 0x21 <= ord(c) <= 0x7e for c in path)
                or "#" in path or "\\" in path
                or method == "GET" and body is not None
                or method == "POST" and (type(body) is not bytes or not 1 <= len(body) <= 2048)
                or writing and (type(body) is not bytes or not 1 <= len(body) <= 70 * 1024)):
            raise ValueError("Invalid fixed GitHub transport request")
        if device:
            if device_claimed:
                raise ValueError("The original GitHub device step was already claimed")
            device_claimed = True  # Includes transport ambiguity; never retry.
        original_response: list[Any] = [None]
        close_failed = [False]
        original_socket: list[Any] = [None]

        def timeout(remaining: float) -> None:
            if original_socket[0] is None:
                raise ReadFailure("network-unavailable")
            original_socket[0].settimeout(remaining)

        def prior_control() -> dict[str, Any] | None:
            response = original_response[0]
            bounded = getattr(response, "bounded", None)
            return None if bounded is None else bounded.control

        class FixedResponse(http.client.HTTPResponse):
            def __init__(self, *args: Any, **kwargs: Any) -> None:
                self._close_claimed = False
                original_response[0] = self
                super().__init__(*args, **kwargs)

            def begin(self) -> None:
                nonlocal write_result
                if self.headers is not None:
                    return
                self.bounded = _ResponseBody(self.fp, budget, before_read=timeout, _role=_role)
                head = self.bounded.head
                self.code = self.status = head.status
                self.reason = ""  # Raw upstream reason phrases are discarded.
                self.version = head.version
                self.headers = self.msg = http.client.HTTPMessage()
                for name, values in head.headers.items():
                    for value in values:
                        if value is not None:
                            self.headers[name] = value
                self.chunked = head.framing == "chunked"
                self.chunk_left = None
                self.length = head.length
                self.will_close = head.framing == "eof" or self._check_close()
                if writing:
                    write_result = _input_write_result(self.bounded, budget)
                    # stdlib getresponse may close the connection before
                    # returning to exchange. Emit here, before that happens.
                    _publish_input_write(write_result, _on_write_status)

            def read(self, amt: int | None = None) -> bytes:
                return self.bounded.read(amt)

            def close(self) -> None:
                if self._close_claimed:
                    return
                self._close_claimed = True  # Includes stdlib failure closes.
                try:
                    super().close()
                except BaseException:
                    close_failed[0] = True
                    raise

        class FixedConnection(http.client.HTTPSConnection):
            def __init__(self) -> None:
                self._close_claimed = False
                super().__init__(host, 443, timeout=budget.remaining(), context=context)
                self.response_class = FixedResponse
                self.set_debuglevel(0)

            def connect(self) -> None:
                # HTTPSConnection's default wrap suppresses ragged EOF.
                # Use the ordinary base TCP connect, then one explicit TLS
                # wrap. No tunnel/host override or second owner is added.
                http.client.HTTPConnection.connect(self)
                self.sock.settimeout(budget.remaining())
                self.sock = _wrap_fixed_tls(context, self.sock,
                                           ignore_eof_option=getattr(ssl, "OP_IGNORE_UNEXPECTED_EOF", 0), _profile=_profile)

            def close(self) -> None:
                if self._close_claimed:
                    return
                self._close_claimed = True
                try:
                    super().close()
                except BaseException:
                    close_failed[0] = True
                    raise

        def fail(reason: str) -> None:
            nonlocal result, write_result
            if write_result is None:
                result = _failed(reason, prior_control())
            elif write_result.head_valid:
                write_result.control = _refuse(write_result.control, reason)
            else:
                write_result = _InputWriteResult({"state": "attempted-outcome-unknown"},
                                                  _failed(reason, prior_control()).control)

        connection: Any = None
        result: ReadResult = _failed("network-unavailable")
        # FixedResponse may outlive this call through its original-response
        # custody cycle. Its captured cell must never retain raw GET data.
        write_result: _InputWriteResult | None = (_InputWriteResult({"state": "attempted-outcome-unknown"},
                _control("network-unavailable")) if writing else None)
        try:
            if writing:
                budget.remaining()
                if budget.body_bytes + len(body) > budget.body_total_limit:
                    raise ReadFailure("response-limit")
                budget.body_bytes += len(body)
            connection = FixedConnection()
            connection.connect()
            original_socket[0] = connection.sock
            timeout(budget.remaining())
            connection.auto_open = 0  # No implicit reconnect after our connect.
            connection.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
            headers = (("Host", host), ("User-Agent", "MobileReleaseKit-Desktop/0.3.0"),
                       ("Accept", "application/json" if device else "application/vnd.github+json"))
            if not device:
                headers += (("X-GitHub-Api-Version", api_version),)
            headers += (("Accept-Encoding", "identity"), ("Connection", "close"))
            if not device:
                headers += (("Authorization", "Bearer " + token),)
            for name, value in headers:
                connection.putheader(name, value)
            timeout(budget.remaining())
            if body is not None:
                connection.putheader("Content-Type", "application/x-www-form-urlencoded" if device else "application/json")
                connection.putheader("Content-Length", str(len(body)))
            connection.endheaders(body)
            timeout(budget.remaining())
            response = connection.getresponse()
            if not writing:
                result = _response_result(response.bounded, budget)
        except ReadFailure as error:
            fail(error.reason)
        except ssl.SSLError:
            fail("tls-failed")
        except http.client.HTTPException:
            fail("response-invalid")
        except OSError:
            fail("network-unavailable")
        finally:
            # Each original response/connection has one synchronous close
            # claim, even if stdlib already closed it on its own failure path.
            # No retry, scan, replacement joiner or cleanup timeout is added.
            _settle_originals((original_response[0], connection), close_failed, write_result)
        return write_result if write_result is not None else result

    return exchange


def _device_form(request: DeviceRequest) -> tuple[_ExchangeProfile, str, bytes]:
    # The standard URI encoder is DATA-only: no urllib request/proxy machinery.
    from urllib.parse import urlencode

    if type(request) is not DeviceRequest or not _client_id(request.client_id):
        raise ValueError("Invalid fixed GitHub device request")
    values = {"client_id": request.client_id}
    if request.step == "start" and request.device_code is None:
        profile, path = _ExchangeProfile.DEVICE_START, "/login/device/code"
    elif request.step == "poll" and _device_code(request.device_code):
        profile, path = _ExchangeProfile.DEVICE_POLL, "/login/oauth/access_token"
        values.update(device_code=request.device_code, grant_type="urn:ietf:params:oauth:grant-type:device_code")
    else:
        raise ValueError("Invalid fixed GitHub device request")
    return profile, path, urlencode(values).encode("ascii")


def device_step(request: DeviceRequest, *, started: float, runtime_dir: str) -> dict[str, Any]:
    """Exactly ONE original OAuth request, never a polling loop or API delegate."""
    profile, path, body = _device_form(request)
    exchange = _make_live_exchange(None, started=started, runtime_dir=runtime_dir, api_version=None, _profile=profile)
    result = exchange("POST", path, body)
    try:
        return project_device_result(request, result.observation, result.control)
    finally:
        # Private raw OAuth/refresh fields are not retained after projection.
        if type(result.observation.get("body")) is dict:
            result.observation["body"].clear()


def _make_live_reader(request: ReadRequest, *, started: float, runtime_dir: str) -> _Reader:
    """Unchanged at-most-five-GET Connect/Refresh profile, never a POST grant."""
    exchange = _make_live_exchange(request.token, started=started, runtime_dir=runtime_dir,
                                   api_version="2022-11-28")

    class FixedReader:
        def __init__(self) -> None:
            self.steps: list[str] = []

        def read(self, step: str) -> ReadResult:
            expected = ("account" if not self.steps else "repository-before" if self.steps == ["account"]
                        else "workflows-1" if self.steps == ["account", "repository-before"] else None)
            if expected is not None:
                valid = step == expected
            elif self.steps == ["account", "repository-before", "workflows-1"]:
                valid = step in {"workflows-2", "repository-after"}
            else:
                valid = self.steps == ["account", "repository-before", "workflows-1", "workflows-2"] and step == "repository-after"
            if not valid or len(self.steps) >= 5:
                raise ValueError("Invalid fixed GitHub schedule")
            self.steps.append(step)  # Never retry a claimed logical read.
            prefix = "/repos/" + request.repository
            path = ("/user" if step == "account" else prefix if step in {"repository-before", "repository-after"}
                    else prefix + "/actions/workflows?per_page=100&page=" + ("1" if step == "workflows-1" else "2"))
            return exchange("GET", path, None)

    return FixedReader()
