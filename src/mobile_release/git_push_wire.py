"""Closed receive-pack comparisons for one reviewed, non-deleting branch update.

No socket, process, credential, clock, durable ACK or permission is created here.
The pack is opaque: a bounded header/checksum is not object validation, remote
success, or proof that any original helper/HTTP/native owner has joined. Fetch's
protocol-v2 parser and its stateless-connect transcript are deliberately unchanged.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac

from . import git_remote_wire as framing
from .git_repository_read import _full_ref
from .git_service import _ref


READ_CHUNK = framing.READ_CHUNK
MAX_METADATA = 256 * 1024
MAX_COMMAND = 64 * 1024
MAX_BODY = 32 * 1024 * 1024  # The command envelope AND pack, not two allowances.
MAX_REFS = 1024
MAX_PROGRESS = 64 * 1024
WireError = framing.WireError
_need = framing._need
_BARE = frozenset({b"report-status", b"report-status-v2", b"delete-refs", b"side-band-64k",
                   b"quiet", b"atomic", b"ofs-delta", b"push-options", b"no-thin"})
_VALUED = frozenset({b"agent", b"session-id", b"object-format", b"push-cert", b"symref"})
_SERVICE = b"# service=git-receive-pack\n"


def _branch(value: object) -> bool:
    return (type(value) is str and value.isascii() and len(value) <= 255 and _ref(value))


def _oid(value: object) -> bool:
    return type(value) is str and value.isascii() and framing._oid(value.encode("ascii"))


@dataclass(frozen=True, slots=True, repr=False)
class Selection:
    """Exact comparison DATA; both OIDs are existing nonzero SHA-1 commits."""
    local_ref: str
    remote_ref: str
    old_oid: str
    new_oid: str

    def __post_init__(self):
        _need(_branch(self.local_ref) and _branch(self.remote_ref) and _oid(self.old_oid)
              and _oid(self.new_oid) and self.old_oid != self.new_oid)


@dataclass(frozen=True, slots=True, repr=False)
class Advertisement:
    raw: bytes
    prefix_bytes: int
    capabilities: tuple[bytes, ...]
    refs: tuple[tuple[str, str], ...]

    def git_bytes(self) -> bytes:
        # The HTTP service preamble is framing, not a Git capability. Nothing
        # in the actual receive-pack advertisement is removed or rewritten.
        return self.raw[self.prefix_bytes:]


def _packets(raw: bytes, maximum: int, count: int) -> tuple[int | bytes, ...]:
    _need(type(raw) is bytes and 0 < len(raw) <= maximum, "response-limit")
    decoder = framing._Packets(maximum, count)
    rows = []
    for offset in range(0, len(raw), READ_CHUNK):
        rows.extend(value for value, _ in decoder.feed(raw[offset:offset + READ_CHUNK]))
    decoder.finish()
    return tuple(rows)


def _capabilities(raw: bytes) -> tuple[bytes, ...]:
    _need(type(raw) is bytes and 0 < len(raw) <= 4096)
    values = tuple(raw.split(b" "))
    names = set()
    for value in values:
        _need(bool(value) and all(0x21 <= byte <= 0x7e for byte in value))
        name, equal, body = value.partition(b"=")
        _need(name not in names)
        names.add(name)
        if equal:
            _need(name in _VALUED and 0 < len(body) <= 512, "unsupported-protocol")
            if name == b"object-format":
                _need(body == b"sha1", "unsupported-protocol")
            elif name == b"symref":
                source, colon, target = body.partition(b":")
                _need(source == b"HEAD" and colon and _branch(target.decode("ascii")), "unsupported-protocol")
        else:
            _need(name in _BARE, "unsupported-protocol")
    _need(b"report-status" in names or b"report-status-v2" in names, "unsupported-protocol")
    return values


def _advertisement(raw: bytes) -> Advertisement:
    rows = _packets(raw, MAX_METADATA, MAX_REFS + 3)
    _need(len(rows) >= 4 and rows[0] == _SERVICE and rows[1] == 0 and rows[-1] == 0
          and all(type(row) is bytes for row in rows[2:-1]), "unsupported-protocol")
    refs, seen = [], set()
    caps = None
    for index, packet in enumerate(rows[2:-1]):
        _need(index < MAX_REFS, "response-limit")
        row = packet[:-1] if packet.endswith(b"\n") else packet
        if index == 0:
            row, zero, encoded = row.partition(b"\0")
            _need(zero == b"\0")
            caps = _capabilities(encoded)
        else:
            _need(b"\0" not in row)
        fields = framing._line(row, 2048).split(b" ")
        _need(len(fields) == 2 and framing._oid(fields[0]), "unsupported-protocol")
        reference = fields[1].decode("ascii")
        # No empty-repository capabilities^{}, .have, pseudo-ref, peel or
        # symbolic fallback can establish this existing-branch update.
        _need(_full_ref(reference) and reference not in seen, "unsupported-protocol")
        seen.add(reference)
        oid = fields[0].decode("ascii")
        refs.append((reference, oid))
    return Advertisement(raw, 4 + len(_SERVICE) + 4, caps, tuple(refs))


def advertisement(raw: bytes, selected: Selection) -> Advertisement:
    _need(type(selected) is Selection)
    value = _advertisement(raw)
    _need(dict(value.refs).get(selected.remote_ref) == selected.old_oid, "target-changed")
    return value


def after_advertisement(raw: bytes, selected: Selection) -> Advertisement:
    _need(type(selected) is Selection)
    value = _advertisement(raw)
    _need(dict(value.refs).get(selected.remote_ref) == selected.new_oid, "target-changed")
    return value


@dataclass(frozen=True, slots=True, repr=False)
class Reconciliation:
    state: str
    observed_oid: str | None
    response_sha256: str


def reconcile_advertisement(raw: bytes, selected: Selection) -> Reconciliation:
    """Historical GET comparison only; absence/another tip never grants retry."""
    _need(type(selected) is Selection)
    value = _advertisement(raw)
    oid = dict(value.refs).get(selected.remote_ref)
    state = ("matches-intended" if oid == selected.new_oid else "still-old" if oid == selected.old_oid
             else "not-returned" if oid is None else "other")
    return Reconciliation(state, oid, hashlib.sha256(raw).hexdigest())


def _original(offered: Advertisement, selected: Selection):
    _need(type(offered) is Advertisement and advertisement(offered.raw, selected) == offered)


@dataclass(frozen=True, slots=True, repr=False)
class Command:
    raw: bytes
    status_v2: bool
    sideband: bool


def command(raw: bytes, selected: Selection, offered: Advertisement) -> Command:
    _need(type(selected) is Selection)
    _original(offered, selected)
    rows = _packets(raw, MAX_COMMAND, 2)
    _need(len(rows) == 2 and type(rows[0]) is bytes and rows[1] == 0)
    update, zero, caps = rows[0].partition(b"\0")
    expected = (selected.old_oid + " " + selected.new_oid + " " + selected.remote_ref).encode("ascii")
    _need(update == expected and zero == b"\0", "target-changed")
    # Stock send-pack's cap_buf starts with one space. Accept that exact
    # spelling, not an arbitrary extra command/newline after the NUL.
    _need(caps.startswith(b" ") and len(caps) <= 4096)
    values = tuple(caps[1:].split(b" "))
    offered_names = {v.partition(b"=")[0] for v in offered.capabilities}
    seen = set()
    for value in values:
        _need(bool(value) and all(0x21 <= byte <= 0x7e for byte in value))
        name, equal, body = value.partition(b"=")
        _need(name not in seen and name in offered_names, "unsupported-protocol")
        seen.add(name)
        if equal:
            _need(name == b"object-format" and body == b"sha1"
                  or name == b"agent" and 0 < len(body) <= 512, "unsupported-protocol")
        else:
            _need(name in {b"report-status", b"report-status-v2", b"side-band-64k", b"quiet"},
                  "unsupported-protocol")
    reports = seen & {b"report-status", b"report-status-v2"}
    _need(len(reports) == 1, "unsupported-protocol")
    return Command(raw, b"report-status-v2" in reports, b"side-band-64k" in seen)


@dataclass(frozen=True, slots=True, repr=False)
class BodyDigest:
    body_bytes: int
    body_sha256: str
    pack_bytes: int
    pack_sha1: str
    advertised_objects: int


class PackStream:
    """Constant-sized opaque pack comparison, never a pack/object validator."""
    def __init__(self, request: Command, selected: Selection, offered: Advertisement):
        _need(type(request) is Command and command(request.raw, selected, offered) == request)
        self.request = request
        self.total = len(request.raw)
        self.pack_bytes = 0
        self.header, self.tail = b"", b""
        self.body_hash, self.pack_hash = hashlib.sha256(request.raw), hashlib.sha1()
        self.entered = self.finished = self.failed = False

    def feed(self, block: bytes):
        _need(not self.entered and not self.finished and not self.failed)
        self.entered = True
        try:
            _need(type(block) is bytes and 0 < len(block) <= READ_CHUNK)
            _need(len(block) <= MAX_BODY - self.total, "response-limit")
            self.total += len(block)
            self.pack_bytes += len(block)
            self.body_hash.update(block)
            # Hold only the SHA-1 trailer across chunk boundaries. This does
            # not parse compressed objects or imply the server accepts them.
            joined = self.tail + block
            if len(joined) > 20:
                data, self.tail = joined[:-20], joined[-20:]
                self.header += data[:12 - len(self.header)]
                self.pack_hash.update(data)
            else:
                self.tail = joined
        except BaseException:
            self.failed = True
            raise
        finally:
            self.entered = False

    def finish(self) -> BodyDigest:
        _need(not self.entered and not self.finished and not self.failed)
        self.finished = True
        try:
            _need(self.pack_bytes >= 32 and len(self.header) == 12 and self.header[:4] == b"PACK"
                  and int.from_bytes(self.header[4:8], "big") in (2, 3)
                  and hmac.compare_digest(self.pack_hash.digest(), self.tail))
            return BodyDigest(self.total, self.body_hash.hexdigest(), self.pack_bytes,
                              self.pack_hash.hexdigest(), int.from_bytes(self.header[8:12], "big"))
        except BaseException:
            self.failed = True
            raise


@dataclass(frozen=True, slots=True, repr=False)
class Status:
    outcome: str
    reference: str
    old_oid: str
    new_oid: str
    response_sha256: str
    response_bytes: int
    progress_bytes: int


def status_response(raw: bytes, selected: Selection, offered: Advertisement, request: Command) -> Status:
    _need(type(request) is Command and command(request.raw, selected, offered) == request)
    progress = 0
    if request.sideband:
        _need(type(raw) is bytes and 0 < len(raw) <= MAX_METADATA, "response-limit")
        decoder = framing._Packets(MAX_METADATA, MAX_METADATA // 5 + 1)
        inner = bytearray()
        ended = False
        # Do not retain a tuple for every tiny remote sideband packet. The
        # shared decoder has at most one READ_CHUNK's returned frame cells;
        # only the bounded inner status body survives the next iteration.
        for offset in range(0, len(raw), READ_CHUNK):
            for row, _ in decoder.feed(raw[offset:offset + READ_CHUNK]):
                _need(not ended)
                if row == 0:
                    ended = True
                    continue
                _need(type(row) is bytes and bool(row) and row[0] in (1, 2, 3))
                if row[0] == 1:
                    _need(len(row) - 1 <= MAX_METADATA - len(inner), "response-limit")
                    inner.extend(row[1:])
                elif row[0] == 2:
                    progress += len(row) - 1
                    _need(progress <= MAX_PROGRESS, "response-limit")
                else:
                    raise WireError()  # Never retain remote fatal text in an error.
        decoder.finish()
        _need(ended)
        rows = _packets(bytes(inner), MAX_METADATA, 6)
    else:
        rows = _packets(raw, MAX_METADATA, 6)
    _need(rows and rows[-1] == 0 and all(type(row) is bytes for row in rows[:-1]))
    _need(3 <= len(rows) <= (6 if request.status_v2 else 3))
    lines = tuple(framing._line(row, 4096) for row in rows[:-1])
    _need(lines[0].startswith(b"unpack ") and len(lines[0]) > len(b"unpack "))
    unpack_ok = lines[0] == b"unpack ok"
    reference = selected.remote_ref.encode("ascii")
    if lines[1] == b"ok " + reference:
        _need(unpack_ok)
        outcome = "ok"
    else:
        prefix = b"ng " + reference + b" "
        _need(lines[1].startswith(prefix) and len(lines[1]) > len(prefix))
        outcome = "rejected"
    options = {}
    for line in lines[2:]:
        _need(request.status_v2 and outcome == "ok" and line.startswith(b"option "))
        name, space, value = line[len(b"option "):].partition(b" ")
        _need(bool(space) and name not in options)
        expected = {b"refname": reference, b"old-oid": selected.old_oid.encode("ascii"),
                    b"new-oid": selected.new_oid.encode("ascii")}
        _need(name in expected and value == expected[name], "target-changed")
        options[name] = value
    return Status(outcome, selected.remote_ref, selected.old_oid, selected.new_oid,
                  hashlib.sha256(raw).hexdigest(), len(raw), progress)
