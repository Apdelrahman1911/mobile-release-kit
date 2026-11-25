"""One receive-pack update on the EXISTING GitHub HTTP/TLS owner.

This closed facet adds no socket, credential resolver, clock or process owner.
Its private factory remains unavailable without the separate original profile
and native source/FD8 hooks. Review/reconcile are GET-only; body/response facts
never constitute a journal ACK, a native join or permission to repeat a POST.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
import math
from typing import Callable

from . import _github_connection_transport as http
from .api._github_connection import _account, _coordinate, _id, _read, _repository
from .git_remote_transport import _LOGIN, RemoteError
from . import git_remote_control as controls
from . import git_push_body as bodies
from . import git_push_wire as wire


ACCOUNT = "git-push-account"
REPOSITORY = "git-push-repository"
ADVERTISEMENT = "git-push-advertisement"
SEND = "git-push-send"
ROLES = frozenset({ACCOUNT, REPOSITORY, ADVERTISEMENT, SEND})
BINARY_ROLES = frozenset({ADVERTISEMENT, SEND})
MAX_REQUESTS = 7
BODY_TOTAL = 2 * 1024 * 1024  # Responses only; the sole request-body has its own fixed cap.
WORK_SECONDS = 45.0
_KEY = object()
_REASONS = frozenset({"response-invalid", "response-limit", "unsupported-protocol", "target-changed",
    "network-unavailable", "tls-failed", "unauthorized", "forbidden", "not-found-or-inaccessible",
    "rate-limited", "expired", "cancelled", "cleanup-unknown", "remote-rejected"})


class PushError(RemoteError):
    def __init__(self, reason="response-invalid"):
        self.reason = reason if reason in _REASONS else "response-invalid"
        ValueError.__init__(self, "Git Push request refused: " + self.reason)


def require(value, reason="response-invalid"):
    if not value:
        raise PushError(reason)


def failure_reason(error: BaseException) -> str:
    if isinstance(error, (PushError, wire.WireError, http.ReadFailure)):
        reason = error.reason
        return reason if reason in _REASONS else "cleanup-unknown"
    return "cleanup-unknown"


@dataclass(frozen=True, slots=True, repr=False)
class Target:
    repository: str
    login: str
    account_id: str
    repository_id: str
    selected: wire.Selection

    def __post_init__(self):
        try:
            _coordinate(self.repository); _id(self.account_id); _id(self.repository_id)
            require(type(self.login) is str and _LOGIN.fullmatch(self.login) is not None)
            wire.selection(wire.selection_kind(self.selected), self.selected.local_ref, self.selected.remote_ref,
                           self.selected.old_oid, self.selected.new_oid)
        except ValueError:
            raise PushError() from None


def validate_endpoint(role: str, method: str, path: str):
    require(type(role) is str and role in ROLES and type(method) is str
            and type(path) is str and path.isascii() and len(path) <= 256)
    if role == ACCOUNT:
        require(method == "GET" and path == "/user")
        return
    if role == REPOSITORY:
        require(method == "GET" and path.startswith("/repos/"))
        coordinate = path[len("/repos/"):]
    else:
        ending = ".git/info/refs?service=git-receive-pack" if role == ADVERTISEMENT else ".git/git-receive-pack"
        require(method == ("GET" if role == ADVERTISEMENT else "POST")
                and path.startswith("/") and path.endswith(ending))
        coordinate = path[1:-len(ending)]
    try:
        _coordinate(coordinate)
    except ValueError:
        raise PushError() from None


def validate_body(role: str, body: object, private_body: object):
    # The generic bytes body remains NONE. No generic file, iterator, path or
    # new numeric body allowance reaches the shared HTTP implementation.
    require(role in ROLES and body is None)
    if role == SEND:
        require(type(private_body) is bodies._PushBody and not private_body.failed
                and private_body.phase == "send-claimed" and private_body.digest is not None
                and 0 < private_body.digest.body_bytes <= wire.MAX_BODY)
    else:
        require(private_body is None)


def host(role: str) -> str:
    require(role in ROLES)
    return "github.com" if role in BINARY_ROLES else "api.github.com"


def response_media(role: str) -> str:
    require(role in BINARY_ROLES)
    return ("application/x-git-receive-pack-advertisement" if role == ADVERTISEMENT
            else "application/x-git-receive-pack-result")


def private_headers(role: str, token: str, login: str, api_version: str):
    require(type(token) is str and 1 <= len(token) <= 4096
            and all(0x21 <= ord(c) <= 0x7e for c in token)
            and type(login) is str and _LOGIN.fullmatch(login) is not None
            and api_version == "2026-03-10")
    fixed = (("Host", host(role)), ("User-Agent", "MobileReleaseKit-Desktop/0.3.0"),
             ("Accept-Encoding", "identity"), ("Connection", "close"))
    if role in BINARY_ROLES:
        secret = base64.b64encode((login + ":" + token).encode("ascii")).decode("ascii")
        # receive-pack uses its original advertised capabilities. In
        # particular, Fetch's Git-Protocol: version=2 header is NOT inherited.
        return fixed + (("Accept", response_media(role)), ("Authorization", "Basic " + secret))
    return fixed + (("Accept", "application/vnd.github+json"), ("X-GitHub-Api-Version", api_version),
                    ("Authorization", "Bearer " + token))


class _Delivery:
    """One bounded response retained before entering the original exchange.

    `value` may retain a genuine parsed response even if later currentness or
    original close fails. It is historical DATA, never send/native finality.
    """
    __slots__ = ("role", "mode", "selected", "offered", "body", "current", "failure", "buffer",
                 "raw", "value", "claimed", "entered", "failed", "complete", "taken")

    def __init__(self, role, mode, selected, offered, body, current, failure, *, _key):
        require(_key is _KEY and role in BINARY_ROLES and mode in {"before", "after", "reconcile", "send"}
                and (role == SEND) == (mode == "send")
                and wire.selection_kind(selected) in ("push", "push-new-branch")
                and callable(current) and callable(failure))
        require((role == SEND and type(body) is bodies._PushBody and body.selected is selected
                 and body.offered is offered and body.io.current is current)
                or (role == ADVERTISEMENT and body is None and offered is None))
        self.role, self.mode, self.selected, self.offered, self.body = role, mode, selected, offered, body
        self.current, self.failure = current, failure
        self.buffer, self.raw, self.value = bytearray(), None, None
        self.claimed = self.entered = self.failed = self.complete = self.taken = False

    def claim(self, role, body):
        require(not self.claimed and not self.failed and role == self.role and body is self.body)
        self.claimed = True
        try:
            self.current()
        except BaseException:
            self.failed = True
            raise

    def feed(self, block):
        require(self.claimed and not self.entered and not self.failed and not self.complete)
        self.entered = True
        try:
            self.current()
            require(type(block) is bytes and 0 < len(block) <= wire.READ_CHUNK
                    and len(block) <= wire.MAX_METADATA - len(self.buffer), "response-limit")
            self.buffer.extend(block)
            self.current()
        except BaseException:
            self.failed = True
            raise
        finally:
            self.entered = False

    def finish(self, failure):
        require(self.claimed and not self.entered and not self.failed and not self.complete)
        require(callable(failure))
        self.entered = True
        try:
            self.current()
            self.raw = bytes(self.buffer)
            self.buffer.clear()
            if self.mode == "send":
                self.value = wire.status_response(self.raw, self.selected, self.offered, self.body.request)
                if self.value.outcome == "rejected":
                    # Preserve the exact parsed receipt before first-F. No
                    # after-GET or fresh send may follow a known rejection.
                    failure("remote-rejected")
                    raise PushError("remote-rejected")
            elif self.mode == "before":
                self.value = wire.advertisement(self.raw, self.selected)
            elif self.mode == "after":
                self.value = wire.after_advertisement(self.raw, self.selected)
            else:
                self.value = wire.reconcile_advertisement(self.raw, self.selected)
            self.current()
            self.complete = True
        except BaseException:
            self.failed = True
            raise
        finally:
            self.entered = False

    def after_exchange(self):
        require(self.complete and not self.failed and not self.entered and not self.taken)
        self.taken = True
        self.current()
        return self.value, self.raw


def stream_response(response, budget, delivery: _Delivery, *, failure):
    """Bounded delegate INSIDE the same existing HTTP finally/close owner."""
    require(type(delivery) is _Delivery and delivery.claimed
            and response.role.value == delivery.role and budget is response.budget and callable(failure))
    try:
        while True:
            block = response.read(wire.READ_CHUNK)
            if not block:
                break
            delivery.feed(block)
        # Probe actual TLS EOF before interpreting status. Once a validated
        # negative status is observed, first-F must precede finally, not leave
        # work enabled merely to finish another read or after-GET.
        if response.head.framing != "eof":
            probe = response._raw(1)
            response.body_bytes += len(probe); budget.body_bytes += len(probe)
            if budget.body_bytes > budget.body_total_limit:
                raise http.ReadFailure("response-limit")
            if probe:
                raise http.ReadFailure("response-invalid")
        budget.remaining()
        delivery.finish(failure)
        return http.ReadResult({"status": 200, "body": None, "failure": "none"}, response.control)
    except (wire.WireError, PushError, http.ReadFailure) as error:
        delivery.failed = True
        if error.reason == "cleanup-unknown":
            raise
        reason = error.reason if error.reason in {"response-limit", "cancelled", "network-unavailable"} else "response-invalid"
        failure(error.reason)
        return http._failed(reason, response.control)
    except BaseException:
        delivery.failed = True
        failure("cleanup-unknown")
        raise


class _PushTransport:
    """Fixed five-GET Review/Reconcile or seven-call, one-POST Apply schedule."""
    def __init__(self, target: Target, mode, exchange, budget, current, failure):
        require(type(target) is Target and mode in {"review", "apply", "reconcile"}
                and (exchange is None or callable(exchange)) and callable(current) and callable(failure))
        self.target, self.mode, self.exchange, self.budget = target, mode, exchange, budget
        self.current, self.failure = current, failure
        self.phase = 0
        self.entered = self.failed = self.finished = False
        self.offered = self.readback = self.posted = None
        self.control = http._control()

    def observe_control(self, value):
        # SAME original HTTP finalizers publish only bounded memory DATA here.
        # A close failure cannot erase a known cooldown or credential refusal.
        self.control = controls.merge(self.control, value)

    def _call(self, phase, role, *, body=None, delivery=None):
        require(not self.entered and not self.failed and not self.finished and self.phase == phase
                and callable(self.exchange))
        self.entered = True
        self.phase += 1  # Before callbacks/send, including any uncertain failure.
        try:
            self.current(); self.budget.remaining()
            path = ("/user" if role == ACCOUNT else "/repos/" + self.target.repository if role == REPOSITORY
                    else "/" + self.target.repository + (".git/info/refs?service=git-receive-pack"
                                                        if role == ADVERTISEMENT else ".git/git-receive-pack"))
            method = "POST" if role == SEND else "GET"
            validate_endpoint(role, method, path); validate_body(role, None, body)
            result = self.exchange(method, path, None, _role=http._ResponseRole(role),
                                   _push_body=body, _push_delivery=delivery)
            require(type(result) is http.ReadResult)
            self.observe_control(result.control)
            require(self.control["reason"] == "none", self.control["reason"])
            if delivery is not None:
                if result.observation != {"status": 200, "body": None, "failure": "none"}:
                    _, reason = _read(result.observation)
                    raise PushError(reason)
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
                    require(not row["archived"] and row["permissions"]["pull"] == "reported-allowed"
                            and row["permissions"]["push"] == "reported-allowed", "forbidden")
                value = None
            self.current(); self.budget.remaining()
            return value
        except BaseException as error:
            self.failed = True
            self.control = controls.refusal(self.control, failure_reason(error))
            self.failure(getattr(error, "reason", "cleanup-unknown"))
            raise
        finally:
            self.entered = False

    def before(self):
        self._call(0, ACCOUNT); self._call(1, REPOSITORY)

    def advertisement(self):
        require(self.phase == 2)
        mode = "reconcile" if self.mode == "reconcile" else "before"
        delivery = _Delivery(ADVERTISEMENT, mode, self.target.selected, None, None,
                             self.current, self.failure, _key=_KEY)
        value, raw = self._call(2, ADVERTISEMENT, delivery=delivery)
        if self.mode == "reconcile":
            self.readback = value
        else:
            self.offered = value
        return raw

    def finish_read(self):
        require(self.mode in {"review", "reconcile"})
        self._call(3, ACCOUNT); self._call(4, REPOSITORY)
        self.finished = True
        return self.offered if self.mode == "review" else self.readback

    def publish(self, body: bodies._PushBody):
        require(self.mode == "apply" and self.phase == 3 and not self.failed and self.posted is None)
        try:
            require(type(body) is bodies._PushBody and body.selected is self.target.selected
                    and body.offered is self.offered and body.io.current is self.current)
            self.posted = _Delivery(SEND, "send", self.target.selected, self.offered, body,
                                    self.current, self.failure, _key=_KEY)
            body.claim_send(body.request)
            _, raw = self._call(3, SEND, body=body, delivery=self.posted)
            return raw
        except BaseException as error:
            self.failed = True
            self.failure(getattr(error, "reason", "cleanup-unknown"))
            raise

    def after(self):
        require(self.mode == "apply")
        self._call(4, ACCOUNT); self._call(5, REPOSITORY)
        delivery = _Delivery(ADVERTISEMENT, "after", self.target.selected, None, None,
                             self.current, self.failure, _key=_KEY)
        self.readback, _ = self._call(6, ADVERTISEMENT, delivery=delivery)
        self.finished = True


def _make_transport(target: Target, mode, token: str, *, started: float, runtime_dir: str,
                    budget, current: Callable[[], None], failure: Callable[[str], None]):
    profile = getattr(http._ExchangeProfile, "GIT_PUSH", None)
    require(profile is not None and type(budget) is http._Budget and budget.profile is profile
            and type(started) in (int, float) and math.isfinite(started) and budget.started == started
            and started < budget.end <= started + WORK_SECONDS and type(target) is Target
            and mode in {"review", "apply", "reconcile"} and callable(current) and callable(failure))
    current(); budget.remaining()
    remote = _PushTransport(target, mode, None, budget, current, failure)
    exchange = http._make_live_exchange(token, started=started, runtime_dir=runtime_dir,
        api_version="2026-03-10", _profile=profile, _setup_budget=budget,
        _git_remote_login=target.login, _git_remote_current=current, _git_remote_failure=failure,
        _git_remote_control=remote.observe_control)
    current(); budget.remaining()
    remote.exchange = exchange
    return remote
