"""Finite stateless Git roles on the ORIGINAL GitHub HTTP/TLS owner.

No socket, HTTP, TLS or credential discovery implementation lives here. The
private factory only composes the existing transport and a same-original clock;
it is not installed as a native action/issuer by this supporting slice. Target
and reply objects are comparison DATA, not project/account/GO authority.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
import math
import re
from typing import Callable

from . import git_remote_wire as wire
from ._desktop_github_engine import _check_control
from . import _github_connection_transport as http
from .api._github_connection import _account, _coordinate, _id, _read, _repository


ACCOUNT = "git-remote-account"
REPOSITORY = "git-remote-repository"
ADVERTISEMENT = "git-remote-advertisement"
LS_REFS = "git-remote-ls-refs"
FETCH = "git-remote-fetch"
ROLES = frozenset({ACCOUNT, REPOSITORY, ADVERTISEMENT, LS_REFS, FETCH})
BINARY_ROLES = frozenset({ADVERTISEMENT, LS_REFS, FETCH})
MAX_REQUESTS = 7
BODY_TOTAL = 34 * 1024 * 1024
WORK_SECONDS = 45.0
_KEY = object()
_LOGIN = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?\Z", re.ASCII)
_REASONS = frozenset({"response-invalid", "response-limit", "unsupported-protocol", "target-changed",
    "network-unavailable", "tls-failed", "unauthorized", "forbidden", "not-found-or-inaccessible",
    "rate-limited", "expired", "cancelled", "cleanup-unknown"})


class RemoteError(ValueError):
    def __init__(self, reason: str = "response-invalid") -> None:
        self.reason = reason if reason in _REASONS else "response-invalid"
        super().__init__("Git remote request refused: " + self.reason)


def require(value: bool, reason: str = "response-invalid") -> None:
    if not value:
        raise RemoteError(reason)


@dataclass(frozen=True, slots=True, repr=False)
class Target:
    repository: str
    login: str
    account_id: str
    repository_id: str
    selected: wire.Selection

    def __post_init__(self) -> None:
        try:
            _coordinate(self.repository); _id(self.account_id); _id(self.repository_id)
            require(type(self.login) is str and _LOGIN.fullmatch(self.login) is not None)
            require(type(self.selected) is wire.Selection)
            wire.Selection(self.selected.reference, self.selected.oid)
        except ValueError:
            raise RemoteError() from None


def validate_endpoint(role: str, method: str, path: str) -> None:
    require(type(role) is str and role in ROLES and type(method) is str
            and type(path) is str and path.isascii() and len(path) <= 256)
    if role == ACCOUNT:
        require(method == "GET" and path == "/user"); return
    if role == REPOSITORY:
        require(method == "GET" and path.startswith("/repos/"))
        coordinate = path[len("/repos/"):]
    else:
        ending = ".git/info/refs?service=git-upload-pack" if role == ADVERTISEMENT else ".git/git-upload-pack"
        require(method == ("GET" if role == ADVERTISEMENT else "POST")
                and path.startswith("/") and path.endswith(ending))
        coordinate = path[1:-len(ending)]
    try:
        _coordinate(coordinate)
    except ValueError:
        raise RemoteError() from None


def validate_body(role: str, body: object) -> None:
    require(type(role) is str and role in ROLES)
    if role in (LS_REFS, FETCH):
        # Exact command/ref/capability matching additionally occurs at the
        # retained round, before the original exchange can claim/send anything.
        require(type(body) is bytes and 0 < len(body) <= wire.MAX_REQUEST)
    else:
        require(body is None)


def host(role: str) -> str:
    require(type(role) is str and role in ROLES)
    return "github.com" if role in BINARY_ROLES else "api.github.com"


def response_media(role: str) -> str:
    require(role in BINARY_ROLES)
    return ("application/x-git-upload-pack-advertisement" if role == ADVERTISEMENT
            else "application/x-git-upload-pack-result")


def private_headers(role: str, token: str, login: str, api_version: str) -> tuple[tuple[str, str], ...]:
    """Only the existing factory calls this, inside private request custody."""
    require(type(token) is str and 1 <= len(token) <= 4096
            and all(0x21 <= ord(c) <= 0x7e for c in token)
            and type(login) is str and _LOGIN.fullmatch(login) is not None
            and api_version == "2026-03-10")
    fixed = (("Host", host(role)), ("User-Agent", "MobileReleaseKit-Desktop/0.3.0"),
             ("Accept-Encoding", "identity"), ("Connection", "close"))
    if role in BINARY_ROLES:
        secret = base64.b64encode((login + ":" + token).encode("ascii")).decode("ascii")
        return fixed + (("Accept", response_media(role)), ("Git-Protocol", "version=2"),
                        ("Authorization", "Basic " + secret))
    return fixed + (("Accept", "application/vnd.github+json"), ("X-GitHub-Api-Version", api_version),
                    ("Authorization", "Bearer " + token))


class _Delivery:
    """One exact response, bounded metadata or the SAME helper→Git pipe.

    There is deliberately no full-pack body/spool. IO callbacks below are
    private original-pipe/currentness seams, never renderer-selected sinks.
    Parsing completion here is not a close receipt or publication authority.
    """
    __slots__ = ("role", "selected", "offered", "request", "write", "current", "buffer",
                 "stream", "entered", "complete", "failed", "claimed", "value", "taken")

    def __init__(self, role: str, selected: wire.Selection, offered: wire.Advertisement | None,
                 request: bytes | None, *, write: Callable[[bytes], None] | None,
                 current: Callable[[], None], _key: object) -> None:
        require(_key is _KEY and role in BINARY_ROLES and type(selected) is wire.Selection)
        require((role == FETCH) == (write is not None) and callable(current))
        self.role, self.selected, self.offered, self.request = role, selected, offered, request
        self.write, self.current, self.buffer = write, current, bytearray()
        self.stream = wire.FetchStream(selected, offered, request) if role == FETCH else None
        self.entered = self.complete = self.failed = self.claimed = self.taken = False
        self.value = None

    def claim(self, role: str, body: bytes | None) -> None:
        require(not self.claimed and not self.failed and self.role == role and self.request == body)
        self.claimed = True  # Before original clock/currentness or native IO.
        try:
            self.current()
        except BaseException:
            self.failed = True
            raise

    def feed(self, block: bytes) -> None:
        require(self.claimed and not self.entered and not self.failed and not self.complete)
        self.entered = True
        try:
            self.current()
            require(type(block) is bytes and 0 < len(block) <= wire.READ_CHUNK)
            if self.stream is None:
                require(len(block) <= wire.MAX_METADATA - len(self.buffer), "response-limit")
                self.buffer.extend(block)
            else:
                for frame in self.stream.feed(block):
                    for start in range(0, len(frame), wire.READ_CHUNK):
                        self.current()
                        require(self.write(frame[start:start + wire.READ_CHUNK]) is None)
                        self.current()
            self.current()
        except BaseException:
            self.failed = True
            raise
        finally:
            self.entered = False

    def finish(self) -> None:
        require(self.claimed and not self.failed and not self.entered and not self.complete)
        self.entered = True
        try:
            self.current()
            if self.role == ADVERTISEMENT:
                self.value = wire.advertisement(bytes(self.buffer))
            elif self.role == LS_REFS:
                self.value = wire.ls_refs_response(bytes(self.buffer), self.selected)
            else:
                self.stream.finish()
            self.current()
            self.complete = True
        except BaseException:
            self.failed = True
            raise
        finally:
            self.entered = False

    def after_exchange(self):
        # Called only after the ORIGINAL exchange's finally returned. This is
        # deliberately not callable from the body delegate to synthesize EOF.
        require(self.complete and not self.failed and not self.entered and not self.taken)
        self.taken = True
        self.current()
        raw = bytes(self.buffer) if self.stream is None else None
        self.buffer.clear()
        return self.value, raw


def stream_response(response, budget, delivery: _Delivery):
    """Delegate invoked INSIDE existing _response_result/finally custody."""
    require(type(delivery) is _Delivery and delivery.claimed
            and response.role.value == delivery.role and budget is response.budget)
    try:
        while True:
            block = response.read(wire.READ_CHUNK)
            if not block:
                break
            delivery.feed(block)
        delivery.finish()
        # Framed length/chunk success is not clean TLS EOF. Existing owner and
        # unexpected-EOF policy supply this actual final probe before close.
        if response.head.framing != "eof":
            probe = response._raw(1)
            response.body_bytes += len(probe); budget.body_bytes += len(probe)
            if budget.body_bytes > budget.body_total_limit:
                raise http.ReadFailure("response-limit")
            if probe:
                raise http.ReadFailure("response-invalid")
        budget.remaining()
        return http.ReadResult({"status": 200, "body": None, "failure": "none"}, response.control)
    except (wire.WireError, RemoteError, http.ReadFailure) as error:
        delivery.failed = True
        if error.reason == "cleanup-unknown":
            raise  # Original custody uncertainty is not an ordinary HTTP error.
        reason = error.reason if error.reason in {"response-limit", "cancelled", "network-unavailable"} else "response-invalid"
        return http._failed(reason, response.control)
    except BaseException:
        delivery.failed = True
        raise


class _RemoteTransport:
    """One finite seven-request transcript; never a generic exchange API."""
    def __init__(self, target: Target, exchange, budget, current: Callable[[], None]) -> None:
        require(type(target) is Target and callable(current))
        self.target, self.exchange, self.budget, self.current = target, exchange, budget, current
        self.phase = 0
        self.entered = self.failed = False
        self.control = http._control()
        self.offered = self.selected = None

    def _call(self, phase: int, role: str, body: bytes | None = None, delivery: _Delivery | None = None):
        require(not self.failed and not self.entered and self.phase == phase)
        self.entered = True
        self.phase += 1  # Includes failures/reentry at currentness or send.
        try:
            self.current(); self.budget.remaining()
            path = ("/user" if role == ACCOUNT else "/repos/" + self.target.repository if role == REPOSITORY
                    else "/" + self.target.repository + (".git/info/refs?service=git-upload-pack"
                                                        if role == ADVERTISEMENT else ".git/git-upload-pack"))
            method = "POST" if role in (LS_REFS, FETCH) else "GET"
            validate_endpoint(role, method, path); validate_body(role, body)
            result = self.exchange(method, path, body, _role=http._ResponseRole(role), _remote_delivery=delivery)
            require(type(result) is http.ReadResult)
            self.control = dict(_check_control(result.control))
            require(self.control["reason"] == "none", self.control["reason"])
            if delivery is not None:
                require(result.observation == {"status": 200, "body": None, "failure": "none"},
                        result.observation.get("failure", "response-invalid") if type(result.observation) is dict else "response-invalid")
                value = delivery.after_exchange()
            else:
                observed, reason = _read(result.observation)
                require(observed is not None, reason)
                if role == ACCOUNT:
                    row = _account(observed)
                    require(row["id"] == self.target.account_id
                            and row["login"].lower() == self.target.login.lower(), "target-changed")
                else:
                    row = _repository(observed)
                    require(row["id"] == self.target.repository_id
                            and row["fullName"].lower() == self.target.repository.lower()
                            and observed.get("clone_url") == "https://github.com/" + self.target.repository + ".git",
                            "target-changed")
                    require(row["permissions"]["pull"] == "reported-allowed", "forbidden")
                value = None
            self.current(); self.budget.remaining()
            return value
        except BaseException:
            self.failed = True
            raise
        finally:
            self.entered = False

    def before(self) -> None:
        self._call(0, ACCOUNT); self._call(1, REPOSITORY)

    def advertisement(self) -> bytes:
        delivery = _Delivery(ADVERTISEMENT, self.target.selected, None, None,
                             write=None, current=self.current, _key=_KEY)
        self.offered, raw = self._call(2, ADVERTISEMENT, delivery=delivery)
        return raw

    def ls_refs(self, raw: bytes) -> bytes:
        try:
            wire.ls_refs_request(raw, self.target.selected, self.offered)
            delivery = _Delivery(LS_REFS, self.target.selected, self.offered, raw,
                                 write=None, current=self.current, _key=_KEY)
            oid, returned = self._call(3, LS_REFS, raw, delivery)
            self.selected = wire.Selection(self.target.selected.reference, oid)
            return returned
        except BaseException:
            self.failed = True
            raise

    def fetch(self, raw: bytes, write: Callable[[bytes], None]) -> None:
        try:
            # This body is the reviewed Apply transfer. Metadata discovery is
            # not permission to download a newly observed unreviewed object.
            require(self.target.selected.oid is not None)
            delivery = _Delivery(FETCH, self.selected, self.offered, raw,
                                 write=write, current=self.current, _key=_KEY)
            self._call(4, FETCH, raw, delivery)
        except BaseException:
            self.failed = True
            raise

    def after(self) -> None:
        self._call(5, ACCOUNT); self._call(6, REPOSITORY)


def _make_transport(target: Target, token: str, *, started: float, runtime_dir: str,
                    budget, current: Callable[[], None]) -> _RemoteTransport:
    """Future original helper entry only; no native issuer/route is installed.

    `budget` MUST be the original operation's already-bridged/clamped clock.
    Supplying a timestamp, target or callback does not establish that authority.
    Missing shared profile refuses before loading any socket/SSL code.
    """
    profile = getattr(http._ExchangeProfile, "GIT_REMOTE", None)
    require(profile is not None and type(budget) is http._Budget and budget.profile is profile
            and type(started) in (int, float) and math.isfinite(started)
            and budget.started == started and started < budget.end <= started + WORK_SECONDS
            and type(target) is Target and callable(current))
    current(); budget.remaining()
    exchange = http._make_live_exchange(token, started=started, runtime_dir=runtime_dir,
        api_version="2026-03-10", _profile=profile, _setup_budget=budget,
        _git_remote_login=target.login, _git_remote_current=current)
    current(); budget.remaining()
    return _RemoteTransport(target, exchange, budget, current)
