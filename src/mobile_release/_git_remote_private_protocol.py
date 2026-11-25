"""Finite private FD8 dialogue. No socket, token discovery or public endpoint.

Only the original socketpair plus original input/command ownership supplies the
capability. These bounded values merely compare that operation. No repr or error
includes a token, rejected frame or provider response. Python memory copies are
not claimed zeroized; the native original still owns the credential lifetime.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import json
import re

from ._desktop_github_engine import _decode_json
from . import _desktop_git_read_protocol as source
from .git_remote_transport import Target, _REASONS as REMOTE_REASONS
from .git_remote_wire import Selection
from . import git_remote_control as controls

PROTOCOL = "mrk-git-remote-private/1"
FRAME_LIMIT = 8192
RETURN_LIMIT = 512
_REMOTE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z", re.ASCII)


class PrivateError(ValueError):
    def __init__(self):
        super().__init__("The original private Git credential dialogue was refused.")


def require(condition):
    if not condition:
        raise PrivateError()


def _keys(value, keys):
    require(type(value) is dict and set(value) == set(keys))
    return value


def _decode(raw):
    try:
        require(type(raw) is bytes and 1 < len(raw) <= FRAME_LIMIT
                and raw.endswith(b"\n") and raw.count(b"\n") == 1 and b"\r" not in raw)
        return _decode_json(raw[:-1], limit=FRAME_LIMIT - 1, nodes=96, depth=3, exact=True)
    except (ValueError, TypeError, UnicodeError, OverflowError):
        raise PrivateError() from None


def _encode(value):
    try:
        raw = (json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True,
                          separators=(",", ":")) + "\n").encode("ascii")
        require(len(raw) <= FRAME_LIMIT and raw.count(b"\n") == 1)
        return raw
    except (ValueError, TypeError, UnicodeError, OverflowError):
        raise PrivateError() from None


def token(value):
    require(type(value) is str and 1 <= len(value) <= 4096
            and all(0x21 <= ord(char) <= 0x7e for char in value))
    return value


@dataclass(frozen=True, slots=True, repr=False)
class Returned:
    """Helper HTTP/ordinary-IO comparison only, never C/A/W or close proof."""
    status: str
    reason: str | None
    first_failure_ns: int | None
    cleanup_end_ns: int
    control: dict = field(default_factory=controls.empty)

    def __post_init__(self):
        try:
            object.__setattr__(self, "control", controls.checked(self.control))
        except (ValueError, TypeError, UnicodeError, OverflowError):
            raise PrivateError() from None
        require(self.status != "ok" or self.control["reason"] == "none")
        require(type(self.cleanup_end_ns) is int and 0 < self.cleanup_end_ns < (1 << 63)
                and type(self.status) is str and (
            self.status == "ok" and self.reason is None
            or self.status == "refused" and type(self.reason) is str
                and self.reason in REMOTE_REASONS - {"cleanup-unknown"}
            or self.status == "unknown" and self.reason == "cleanup-unknown"))
        require(self.status == "ok" and self.first_failure_ns is None or self.status != "ok"
                and type(self.first_failure_ns) is int and 0 < self.first_failure_ns < self.cleanup_end_ns)


@dataclass(frozen=True, slots=True, repr=False)
class Binding:
    operation_id: str
    digest: str
    remote: str
    target: Target
    work_end_ns: int
    hard_end_ns: int
    nonce: bytes
    identity: tuple[int, int, int]

    def __post_init__(self):
        try:
            source._id(self.operation_id); source._hex(self.digest)
            require(type(self.remote) is str and _REMOTE.fullmatch(self.remote) is not None
                    and type(self.target) is Target and type(self.nonce) is bytes and len(self.nonce) == 16
                    and type(self.identity) is tuple and len(self.identity) == 3)
            source._integer(self.work_end_ns, 1, (1 << 63) - 1)
            source._integer(self.hard_end_ns, 1, (1 << 63) - 1)
            require(self.hard_end_ns - self.work_end_ns == 10_000_000_000)
            for item, maximum in zip(self.identity, ((1 << 32) - 1, (1 << 64) - 1, (1 << 64) - 1)):
                source._integer(item, 0, maximum)
        except (source.ProtocolError, ValueError, TypeError):
            raise PrivateError() from None

    def challenge(self):
        target = self.target
        return _encode({"protocol": PROTOCOL, "binding": {"id": self.operation_id, "digest": self.digest,
            "remote": self.remote, "repository": target.repository, "login": target.login,
            "accountId": target.account_id, "repositoryId": target.repository_id,
            "reference": target.selected.reference, "oid": target.selected.oid},
            "clock": {"workEndNs": self.work_end_ns, "hardEndNs": self.hard_end_ns},
            "nonce": self.nonce.hex(), "socket": list(self.identity)})

    def request(self, action="get"):
        require(action in ("get", "store", "erase"))
        return _encode({"protocol": PROTOCOL, "action": action, "id": self.operation_id, "digest": self.digest,
            "remote": self.remote, "repository": self.target.repository,
            "accountId": self.target.account_id, "login": self.target.login})

    def accept_request(self, raw):
        value = _keys(_decode(raw), ("protocol", "action", "id", "digest", "remote", "repository", "accountId", "login"))
        action = value["action"]
        require(type(action) is str and action in ("get", "store", "erase"))
        # Exact values, not case-folded account fallback or changed repository.
        require(raw == self.request(action))
        return action

    def grant(self, value):
        return _encode({"protocol": PROTOCOL, "digest": self.digest, "token": token(value)})

    def accept_grant(self, raw):
        value = _keys(_decode(raw), ("protocol", "digest", "token"))
        require(value["protocol"] == PROTOCOL and value["digest"] == self.digest)
        return token(value["token"])

    def returned(self, status, reason=None, *, first_failure_ns=None, cleanup_end_ns=None, control=None):
        value = Returned(status, reason, first_failure_ns, self.hard_end_ns if cleanup_end_ns is None else cleanup_end_ns,
                         controls.empty() if control is None else control)
        require(value.cleanup_end_ns == (self.hard_end_ns if value.first_failure_ns is None
                else min(self.hard_end_ns, value.first_failure_ns + 10_000_000_000)))
        require(value.first_failure_ns is None or max(1, self.work_end_ns - 45_000_000_000)
                <= value.first_failure_ns < self.hard_end_ns)
        raw = _encode({"protocol": PROTOCOL, "kind": "returned", "digest": self.digest,
                       "status": value.status, "reason": value.reason,
                       "firstFailureNs": value.first_failure_ns, "cleanupEndNs": value.cleanup_end_ns, "control": value.control})
        require(len(raw) <= RETURN_LIMIT)
        return raw

    def accept_message(self, raw):
        value = _decode(raw)
        if type(value) is dict and value.get("kind") == "returned":
            _keys(value, ("protocol", "kind", "digest", "status", "reason", "firstFailureNs", "cleanupEndNs", "control"))
            require(len(raw) <= RETURN_LIMIT and value["protocol"] == PROTOCOL and value["digest"] == self.digest)
            result = Returned(value["status"], value["reason"], value["firstFailureNs"], value["cleanupEndNs"], value["control"])
            require(raw == self.returned(result.status, result.reason,
                first_failure_ns=result.first_failure_ns, cleanup_end_ns=result.cleanup_end_ns, control=result.control))
            return result
        return self.accept_request(raw)


def challenge(raw):
    try:
        value = _keys(_decode(raw), ("protocol", "binding", "clock", "nonce", "socket"))
        require(value["protocol"] == PROTOCOL)
        row = _keys(value["binding"], ("id", "digest", "remote", "repository", "login", "accountId", "repositoryId", "reference", "oid"))
        clock = _keys(value["clock"], ("workEndNs", "hardEndNs"))
        require(type(value["nonce"]) is str and re.fullmatch(r"[a-f0-9]{32}", value["nonce"]) is not None
                and type(value["socket"]) is list)
        target = Target(row["repository"], row["login"], row["accountId"], row["repositoryId"],
                        Selection(row["reference"], row["oid"]))
        result = Binding(row["id"], row["digest"], row["remote"], target, clock["workEndNs"], clock["hardEndNs"],
                         bytes.fromhex(value["nonce"]), tuple(value["socket"]))
        require(result.challenge() == raw)
        return result
    except (source.ProtocolError, ValueError, TypeError, UnicodeError, OverflowError):
        raise PrivateError() from None
