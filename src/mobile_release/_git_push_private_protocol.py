"""Closed Push-only phases on the original map-v2 FD8, never a new channel.

The original pair/nonce, fixed helper and fixed hook own the dialogue. These
bounded values compare that custody; no digest/clock/return is a native grant,
HTTP permission, durable ACK or original C/A/W join. Fetch's ABI is unchanged.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import stat

from . import _git_remote_private_protocol as base
from . import _desktop_git_read_protocol as fields
from . import git_push_body as bodies
from . import git_push_wire as wire
from . import git_push_transport as transport
from . import git_remote_control as controls

PROTOCOL = "mrk-git-push-private/1"
FRAME_LIMIT = base.FRAME_LIMIT
RETURN_LIMIT = 1536  # Still inside the SAME aggregate 8KiB peer-input bound.
PrivateError, require = base.PrivateError, base.require
_encode, _decode, _keys, token = base._encode, base._decode, base._keys, base.token


def _hex(value):
    try:
        return fields._hex(value)
    except fields.ProtocolError:
        raise PrivateError() from None


def _number(value, maximum=(1 << 63) - 1, minimum=0):
    require(type(value) is int and minimum <= value <= maximum)
    return value


def _stamp(value):
    require(type(value) in (list, tuple) and len(value) == 9)
    result = tuple(_number(part, (1 << 64) - 1) for part in value)
    require(result[2] <= (1 << 32) - 1 and result[6] <= (1 << 32) - 1 and result[7] <= (1 << 32) - 1)
    return result


def body_value(value):
    require(type(value) is wire.BodyDigest)
    _number(value.body_bytes, wire.MAX_BODY, 33)
    _number(value.pack_bytes, value.body_bytes - 1, 32)
    require(value.body_bytes - value.pack_bytes <= wire.MAX_COMMAND)
    _number(value.advertised_objects, (1 << 32) - 1)
    _hex(value.body_sha256)
    require(wire._oid(value.pack_sha1))
    return {"bytes": value.body_bytes, "sha256": value.body_sha256, "packBytes": value.pack_bytes,
            "packSha1": value.pack_sha1, "objects": value.advertised_objects}


def parse_body(value):
    row = _keys(value, ("bytes", "sha256", "packBytes", "packSha1", "objects"))
    result = wire.BodyDigest(row["bytes"], row["sha256"], row["packBytes"], row["packSha1"], row["objects"])
    require(body_value(result) == row)
    return result


def status_value(value, selected):
    if value is None:
        return None
    require(type(value) is wire.Status and value.outcome in ("ok", "rejected")
            and (value.reference, value.old_oid, value.new_oid)
            == (selected.remote_ref, selected.old_oid, selected.new_oid))
    _hex(value.response_sha256)
    _number(value.response_bytes, wire.MAX_METADATA, 1)
    _number(value.progress_bytes, wire.MAX_PROGRESS)
    return {"outcome": value.outcome, "sha256": value.response_sha256,
            "bytes": value.response_bytes, "progressBytes": value.progress_bytes}


def parse_status(value, selected):
    if value is None:
        return None
    row = _keys(value, ("outcome", "sha256", "bytes", "progressBytes"))
    result = wire.Status(row["outcome"], selected.remote_ref, selected.old_oid, selected.new_oid,
                         row["sha256"], row["bytes"], row["progressBytes"])
    require(status_value(result, selected) == row)
    return result


@dataclass(frozen=True, slots=True, repr=False)
class Clock:
    """Native request's raw endpoints, not hook/helper-launch allowances."""
    digest: str
    work_end_ns: int
    hard_end_ns: int

    def __post_init__(self):
        _hex(self.digest)
        _number(self.work_end_ns, minimum=1); _number(self.hard_end_ns, minimum=1)
        require(self.hard_end_ns - self.work_end_ns == 10_000_000_000)

    @property
    def nonce(self):
        return bytes.fromhex(self.digest[:32])


@dataclass(frozen=True, slots=True, repr=False)
class Hook:
    clock: Clock
    mode: str
    review_digest: str
    remote: str
    url: str
    line: bytes

    def __post_init__(self):
        require(type(self.clock) is Clock and self.mode in ("review", "apply"))
        _hex(self.review_digest)
        require(type(self.remote) is type(self.url) is str and self.remote == self.url
                and self.url.startswith("mrk::https://github.com/") and self.url.endswith(".git")
                and self.url.isascii() and len(self.url) <= 256
                and type(self.line) is bytes and self.line.isascii() and 1 < len(self.line) <= 1024
                and self.line.endswith(b"\n") and self.line.count(b"\n") == 1 and b"\r" not in self.line)

    def request(self):
        return _encode({"protocol": PROTOCOL, "phase": "hook", "digest": self.clock.digest,
            "nonce": self.clock.nonce.hex(), "review": self.review_digest, "mode": self.mode,
            "remote": self.remote, "url": self.url, "line": self.line.decode("ascii")})

    def reply(self):
        return _encode({"protocol": PROTOCOL, "phase": "compared" if self.mode == "review" else "armed",
            "digest": self.clock.digest, "nonce": self.clock.nonce.hex(), "review": self.review_digest,
            "hook": hashlib.sha256(self.request()).hexdigest()})

    def accept_reply(self, raw):
        require(type(raw) is bytes and raw == self.reply())


@dataclass(frozen=True, slots=True, repr=False)
class Send:
    body: wire.BodyDigest
    stamp: tuple[int, ...]


@dataclass(frozen=True, slots=True, repr=False)
class Returned:
    status: str
    reason: str | None
    first_failure_ns: int | None
    cleanup_end_ns: int
    control: dict
    advertisement_sha256: str | None
    response: wire.Status | None
    after_sha256: str | None

    def __post_init__(self):
        # Reuse the closed old clock/control grammar. Push's one additional
        # refusal has a separate typed report-status record, never raw text.
        mapped = "response-invalid" if self.reason == "remote-rejected" else self.reason
        value = base.Returned(self.status, mapped, self.first_failure_ns, self.cleanup_end_ns, self.control)
        require(self.reason != "remote-rejected" or self.status == "refused")
        object.__setattr__(self, "control", value.control)
        for digest in (self.advertisement_sha256, self.after_sha256):
            if digest is not None:
                _hex(digest)


@dataclass(frozen=True, slots=True, repr=False)
class Binding:
    operation_id: str
    clock: Clock
    mode: str
    review_digest: str
    remote: str
    target: transport.Target
    identity: tuple[int, int, int]
    path: Path
    parent_stamp: tuple[int, ...]
    body_stamp: tuple[int, ...] | None

    def __post_init__(self):
        try:
            fields._id(self.operation_id)
            require(type(self.clock) is Clock and self.mode in ("review", "apply")
                    and type(self.target) is transport.Target and type(self.remote) is str
                    and base._REMOTE.fullmatch(self.remote) is not None)
            _hex(self.review_digest)
            require(type(self.identity) is tuple and len(self.identity) == 3)
            for item, maximum in zip(self.identity, ((1 << 32) - 1, (1 << 64) - 1, (1 << 64) - 1)):
                _number(item, maximum)
            require(type(self.path) is type(Path()) and self.path.is_absolute()
                    and 1 < len(os.fsencode(self.path)) <= 4096 and "\\" not in str(self.path)
                    and all(0 < len(os.fsencode(part)) <= 255 and part not in (".", "..")
                            and not any(ord(char) < 32 or ord(char) == 127 for char in part)
                            for part in self.path.parts[1:]))
            parent = _stamp(self.parent_stamp)
            require(stat.S_ISDIR(parent[2]) and stat.S_IMODE(parent[2]) == 0o700 and parent[6] == self.identity[0])
            if self.mode == "review":
                require(self.body_stamp is None)
            else:
                initial = _stamp(self.body_stamp)
                require(stat.S_ISREG(initial[2]) and stat.S_IMODE(initial[2]) == 0o600
                        and initial[3] == 0 and initial[6] == parent[6] and initial[8] == 1)
        except (fields.ProtocolError, ValueError, TypeError, UnicodeError, OverflowError):
            raise PrivateError() from None

    # Original common channel/clock code compares these same properties.
    digest = property(lambda self: self.clock.digest)
    work_end_ns = property(lambda self: self.clock.work_end_ns)
    hard_end_ns = property(lambda self: self.clock.hard_end_ns)
    nonce = property(lambda self: self.clock.nonce)

    def envelope(self, phase, **values):
        return {"protocol": PROTOCOL, "phase": phase, "digest": self.digest, "nonce": self.nonce.hex(), **values}

    def challenge(self):
        target, selected = self.target, self.target.selected
        return _encode(self.envelope("challenge", id=self.operation_id, mode=self.mode, review=self.review_digest,
            remote=self.remote, target={"repository": target.repository, "login": target.login,
                "accountId": target.account_id, "repositoryId": target.repository_id,
                "localRef": selected.local_ref, "remoteRef": selected.remote_ref,
                "oldOid": selected.old_oid, "newOid": selected.new_oid},
            clock={"workEndNs": self.work_end_ns, "hardEndNs": self.hard_end_ns}, socket=list(self.identity),
            path=str(self.path), parent=list(self.parent_stamp), body=None if self.body_stamp is None else list(self.body_stamp)))

    def request(self):
        return _encode(self.envelope("get"))

    def grant(self, value):
        return _encode(self.envelope("grant", token=token(value)))

    def accept_grant(self, raw):
        row = _keys(_decode(raw), ("protocol", "phase", "digest", "nonce", "token"))
        require(raw == self.grant(row["token"]))
        return token(row["token"])

    def hook(self):
        selected = self.target.selected
        url = "mrk::https://github.com/" + self.target.repository + ".git"
        line = (selected.local_ref + " " + selected.new_oid + " " + selected.remote_ref + " " + selected.old_oid + "\n").encode("ascii")
        return Hook(self.clock, self.mode, self.review_digest, url, url, line)

    def send(self, value, stamp):
        require(self.mode == "apply")
        stamp = _stamp(stamp)
        body = body_value(value)
        require(stamp[:3] == self.body_stamp[:3] and stamp[6:] == self.body_stamp[6:]
                and stamp[3] == value.body_bytes)
        return _encode(self.envelope("send", body=body, stamp=list(stamp)))

    def send_reply(self, value):
        require(self.mode == "apply")
        body_value(value)
        return _encode(self.envelope("send-armed", body=value.body_sha256))

    def returned(self, status, reason=None, *, first_failure_ns=None, cleanup_end_ns=None, control=None,
                 advertisement_sha256=None, response=None, after_sha256=None):
        value = Returned(status, reason, first_failure_ns, self.hard_end_ns if cleanup_end_ns is None else cleanup_end_ns,
            controls.empty() if control is None else control, advertisement_sha256, response, after_sha256)
        require(value.cleanup_end_ns == (self.hard_end_ns if value.first_failure_ns is None
            else min(self.hard_end_ns, value.first_failure_ns + 10_000_000_000)))
        require(value.first_failure_ns is None or max(1, self.work_end_ns - 45_000_000_000)
                <= value.first_failure_ns < self.hard_end_ns)
        report = status_value(response, self.target.selected)
        require(self.mode != "review" or response is after_sha256 is None)
        require(response is None or advertisement_sha256 is not None)
        require(after_sha256 is None or response is not None and response.outcome == "ok")
        if status == "ok":
            require(advertisement_sha256 is not None and (self.mode == "review" or
                    response is not None and response.outcome == "ok" and after_sha256 is not None))
        raw = _encode(self.envelope("returned", status=status, reason=reason, firstFailureNs=first_failure_ns,
            cleanupEndNs=value.cleanup_end_ns, control=value.control, advertisement=advertisement_sha256,
            response=report, after=after_sha256))
        require(len(raw) <= RETURN_LIMIT)
        return raw

    def accept_message(self, raw):
        row = _decode(raw)
        require(type(row) is dict and row.get("protocol") == PROTOCOL and row.get("digest") == self.digest
                and row.get("nonce") == self.nonce.hex())
        phase = row.get("phase")
        if phase == "get":
            require(raw == self.request())
            return "get"
        if phase == "hook":
            result = self.hook()
            require(raw == result.request())
            return result
        if phase == "send":
            _keys(row, ("protocol", "phase", "digest", "nonce", "body", "stamp"))
            value, stamp = parse_body(row["body"]), _stamp(row["stamp"])
            require(raw == self.send(value, stamp))
            return Send(value, stamp)
        require(phase == "returned" and len(raw) <= RETURN_LIMIT)
        _keys(row, ("protocol", "phase", "digest", "nonce", "status", "reason", "firstFailureNs", "cleanupEndNs",
                    "control", "advertisement", "response", "after"))
        report = parse_status(row["response"], self.target.selected)
        result = Returned(row["status"], row["reason"], row["firstFailureNs"], row["cleanupEndNs"], row["control"],
            row["advertisement"], report, row["after"])
        require(raw == self.returned(result.status, result.reason, first_failure_ns=result.first_failure_ns,
            cleanup_end_ns=result.cleanup_end_ns, control=result.control, advertisement_sha256=result.advertisement_sha256,
            response=result.response, after_sha256=result.after_sha256))
        return result


def challenge(raw):
    try:
        row = _keys(_decode(raw), ("protocol", "phase", "digest", "nonce", "id", "mode", "review", "remote",
                                  "target", "clock", "socket", "path", "parent", "body"))
        clock = _keys(row["clock"], ("workEndNs", "hardEndNs"))
        target = _keys(row["target"], ("repository", "login", "accountId", "repositoryId",
                                       "localRef", "remoteRef", "oldOid", "newOid"))
        selected = wire.Selection(target["localRef"], target["remoteRef"], target["oldOid"], target["newOid"])
        target = transport.Target(target["repository"], target["login"], target["accountId"], target["repositoryId"], selected)
        require(type(row["path"]) is str and type(row["socket"]) is list)
        result = Binding(row["id"], Clock(row["digest"], clock["workEndNs"], clock["hardEndNs"]),
            row["mode"], row["review"], row["remote"], target, tuple(row["socket"]), Path(row["path"]),
            _stamp(row["parent"]), None if row["body"] is None else _stamp(row["body"]))
        require(raw == result.challenge())
        return result
    except (fields.ProtocolError, ValueError, TypeError, UnicodeError, OverflowError):
        raise PrivateError() from None
