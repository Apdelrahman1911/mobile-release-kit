"""Finite Git protocol-v2 checks for MRK's stateless-connect-only helper.

No IO, HTTP client, credential, process, clock or publication authority lives
here. The real helper must stream through its SAME owned Git pipe and original
HTTP lifetime. In particular, finish() is not a TLS/pipe/process close receipt
and never emits the helper's response-end marker. Git, not this module, parses
and validates pack objects. These comparison objects cannot enable Fetch.
"""
from __future__ import annotations

from dataclasses import dataclass
import re

from .git_service import _ref

READ_CHUNK = 4096
MAX_PACKET = 65520  # Documented LARGE_PACKET_MAX, including four hex bytes.
MAX_REQUEST = 64 * 1024
MAX_METADATA = 256 * 1024
MAX_PACK_RESPONSE = 32 * 1024 * 1024
MAX_PROGRESS = 64 * 1024
MAX_PACKETS = 65536
MAX_REFS = 256
_HEX = frozenset(b"0123456789abcdefABCDEF")
_OID = re.compile(rb"[0-9a-f]{40}\Z", re.ASCII)
_FETCH_FEATURES = frozenset({b"shallow", b"wait-for-done", b"filter", b"ref-in-want",
                             b"sideband-all", b"packfile-uris"})


class WireError(ValueError):
    """Fixed redacted error; never retain upstream text in an exception."""
    def __init__(self, reason: str = "response-invalid") -> None:
        if reason not in {"response-invalid", "response-limit", "unsupported-protocol", "target-changed"}:
            reason = "response-invalid"
        self.reason = reason
        super().__init__("Git remote protocol refused: " + reason)


def _need(value: bool, reason: str = "response-invalid") -> None:
    if not value:
        raise WireError(reason)


def _oid(raw: bytes) -> bool:
    return _OID.fullmatch(raw) is not None and raw != b"0" * 40


def _line(raw: bytes, maximum: int = 4096) -> bytes:
    _need(type(raw) is bytes and 0 < len(raw) <= maximum)
    value = raw[:-1] if raw.endswith(b"\n") else raw
    _need(bool(value) and all(0x20 <= byte <= 0x7e for byte in value))
    return value


@dataclass(frozen=True, slots=True, repr=False)
class Selection:
    """Bounded comparison DATA, never account/ref consent or a native loan."""
    reference: str
    oid: str | None

    def __post_init__(self) -> None:
        _need(type(self.reference) is str and self.reference.isascii()
              and len(self.reference) <= 255 and _ref(self.reference))
        _need(self.oid is None or type(self.oid) is str and self.oid.isascii()
              and _oid(self.oid.encode("ascii")))


@dataclass(frozen=True, slots=True, repr=False)
class Advertisement:
    raw: bytes
    fetch_features: frozenset[bytes]
    unborn: bool
    agent: bool


@dataclass(frozen=True, slots=True, repr=False)
class FetchRequest:
    raw: bytes
    reference: str
    oid: str
    wants_ref: bool
    sideband_all: bool


class _Packets:
    """Incremental bounded framing; a failed/finished decoder is never reused."""
    def __init__(self, maximum: int, packet_count: int) -> None:
        self.maximum, self.packet_count = maximum, packet_count
        self.buffer = bytearray()
        self.size: int | None = None
        self.total = self.count = 0
        self.entered = self.finished = self.failed = False

    def feed(self, block: bytes) -> tuple[tuple[int | bytes, bytes], ...]:
        _need(not self.entered and not self.finished and not self.failed)
        self.entered = True
        try:
            _need(type(block) is bytes and 0 < len(block) <= READ_CHUNK)
            _need(len(block) <= self.maximum - self.total, "response-limit")
            self.total += len(block)
            result = []
            offset = 0
            while offset < len(block):
                need = (4 if self.size is None else self.size) - len(self.buffer)
                take = min(need, len(block) - offset)
                self.buffer.extend(block[offset:offset + take])
                offset += take
                if self.size is None and len(self.buffer) == 4:
                    _need(all(byte in _HEX for byte in self.buffer))
                    size = int(self.buffer, 16)
                    _need(size != 3 and size <= MAX_PACKET)
                    self.size = max(4, size)
                    if size > 4:
                        continue
                if self.size is None or len(self.buffer) != self.size:
                    continue
                self.count += 1
                _need(self.count <= self.packet_count, "response-limit")
                frame = bytes(self.buffer)
                size = int(frame[:4], 16)
                # Control2 is always refused by network consumers. Only the
                # original helper may add it after actual HTTP close succeeds.
                result.append((size if size < 4 else frame[4:], frame))
                self.buffer.clear()
                self.size = None
            return tuple(result)
        except BaseException:
            self.failed = True
            raise
        finally:
            self.entered = False

    def finish(self) -> None:
        _need(not self.entered and not self.finished and not self.failed)
        self.finished = True
        if self.buffer or self.size is not None:
            self.failed = True
            raise WireError()


def _metadata(raw: bytes, maximum: int = MAX_METADATA) -> list[int | bytes]:
    _need(type(raw) is bytes and 0 < len(raw) <= maximum, "response-limit")
    decoder = _Packets(maximum, 1024)
    result: list[int | bytes] = []
    for at in range(0, len(raw), READ_CHUNK):
        result.extend(item for item, _ in decoder.feed(raw[at:at + READ_CHUNK]))
    decoder.finish()
    _need(bool(result) and result[-1] == 0 and all(type(v) is bytes for v in result[:-1]))
    return result[:-1]


def advertisement(raw: bytes) -> Advertisement:
    rows = _metadata(raw)
    _need(2 <= len(rows) <= 17 and _line(rows[0]) == b"version 2", "unsupported-protocol")
    seen = set()
    features: frozenset[bytes] | None = None
    unborn = agent = False
    for raw_line in rows[1:]:
        value = _line(raw_line, 1024)
        name, equal, body = value.partition(b"=")
        _need(name not in seen)
        seen.add(name)
        if name == b"fetch":
            words = body.split(b" ") if equal else []
            _need(len(words) == len(set(words)) and all(v in _FETCH_FEATURES for v in words),
                  "unsupported-protocol")
            features = frozenset(words)
        elif name == b"ls-refs":
            _need(not equal or body == b"unborn", "unsupported-protocol")
            unborn = bool(equal)
        elif name == b"object-format":
            _need(equal == b"=" and body == b"sha1", "unsupported-protocol")
        elif name in {b"agent", b"session-id"}:
            _need(bool(equal and body) and len(body) <= 512 and b" " not in body)
            agent = agent or name == b"agent"
        else:
            _need(name == b"server-option" and not equal, "unsupported-protocol")
    _need(features is not None and b"ls-refs" in seen, "unsupported-protocol")
    return Advertisement(raw, features, unborn, agent)


def _request(raw: bytes, command: bytes, offered: Advertisement) -> list[bytes]:
    # Do not accept hand-constructed features as a substitute for actual bytes.
    _need(type(offered) is Advertisement and advertisement(offered.raw) == offered)
    _need(type(raw) is bytes and 0 < len(raw) <= MAX_REQUEST, "response-limit")
    decoder = _Packets(MAX_REQUEST, 64)
    packets: list[int | bytes] = []
    for at in range(0, len(raw), READ_CHUNK):
        packets.extend(v for v, _ in decoder.feed(raw[at:at + READ_CHUNK]))
    decoder.finish()
    _need(packets and packets[-1] == 0 and packets.count(1) == 1)
    split = packets.index(1)
    before, after = packets[:split], packets[split + 1:-1]
    _need(before and all(type(v) is bytes for v in before + after))
    headers = [_line(v, 1024) for v in before]
    _need(headers[0] == b"command=" + command)
    names = set()
    for value in headers[1:]:
        name, equal, body = value.partition(b"=")
        _need(bool(equal) and name not in names)
        names.add(name)
        _need(name == b"agent" and offered.agent and 0 < len(body) <= 512 and b" " not in body
              or name == b"object-format" and body == b"sha1", "unsupported-protocol")
    return [_line(v) for v in after]


def ls_refs_request(raw: bytes, selected: Selection, offered: Advertisement) -> None:
    _need(type(selected) is Selection)
    rows = _request(raw, b"ls-refs", offered)
    _need(len(rows) == len(set(rows)) and len(rows) <= 10)
    reference = selected.reference.encode("ascii")
    # Admit only these fixed full-name/DWIM prefixes, never a caller-supplied
    # broad prefix. The only wanted ref remains exact. Actual supported Git
    # invocation/expansion still needs its separate source/native nomination.
    prefixes = {reference, b"refs/" + reference, b"refs/tags/" + reference,
                b"refs/heads/" + reference, b"refs/remotes/" + reference,
                b"refs/remotes/" + reference + b"/HEAD"}
    found = set()
    for row in rows:
        if row.startswith(b"ref-prefix "):
            value = row[len(b"ref-prefix "):]
            _need(value in prefixes)
            found.add(value)
        else:
            _need(row in {b"peel", b"symrefs"} or row == b"unborn" and offered.unborn,
                  "unsupported-protocol")
    _need(reference in found)


def ls_refs_response(raw: bytes, selected: Selection) -> str:
    _need(type(selected) is Selection)
    rows = _metadata(raw)
    _need(len(rows) <= MAX_REFS, "response-limit")
    seen = set()
    found: str | None = None
    for row in rows:
        values = _line(row).split(b" ")
        _need(len(values) == 2 and _oid(values[0]), "unsupported-protocol")
        reference = values[1].decode("ascii")
        _need(_ref(reference) and reference not in seen)
        seen.add(reference)
        if reference == selected.reference:
            found = values[0].decode("ascii")
    _need(found is not None, "target-changed")
    _need(selected.oid is None or found == selected.oid, "target-changed")
    return found


def fetch_request(raw: bytes, selected: Selection, offered: Advertisement) -> FetchRequest:
    _need(type(selected) is Selection and selected.oid is not None)
    rows = _request(raw, b"fetch", offered)
    _need(rows and rows[-1] == b"done" and len(rows) == len(set(rows)))
    want = b"want " + selected.oid.encode("ascii")
    want_ref = b"want-ref " + selected.reference.encode("ascii")
    wants = [v for v in rows if v.startswith((b"want ", b"want-ref "))]
    _need(len(wants) == 1 and (wants[0] == want or wants[0] == want_ref
          and b"ref-in-want" in offered.fetch_features))
    flags = set(rows[:-1]) - {wants[0]}
    _need(flags <= {b"thin-pack", b"no-progress", b"ofs-delta", b"sideband-all"}, "unsupported-protocol")
    sideband = b"sideband-all" in flags
    _need(not sideband or b"sideband-all" in offered.fetch_features, "unsupported-protocol")
    return FetchRequest(raw, selected.reference, selected.oid, wants[0] == want_ref, sideband)


class FetchStream:
    """Bounded streaming comparison; returned frames go only to Git's pipe.

    The caller owns/joins its IO. No response-end marker, success grant or
    file/credential is minted here. A failing feed poisons this exact decoder,
    including BaseException, so a later chunk cannot repair a partial stream.
    """
    def __init__(self, selected: Selection, offered: Advertisement, request: bytes) -> None:
        self.request = fetch_request(request, selected, offered)
        self.decoder = _Packets(MAX_PACK_RESPONSE, MAX_PACKETS)
        self.phase = "wanted-header" if self.request.wants_ref else "pack-header"
        self.pack_bytes = self.progress_bytes = 0
        self.entered = self.finished = self.failed = False

    def feed(self, block: bytes) -> tuple[bytes, ...]:
        _need(not self.entered and not self.finished and not self.failed)
        self.entered = True
        try:
            frames = []
            for value, original in self.decoder.feed(block):
                _need(self.phase != "end")
                if type(value) is int:
                    if value == 1 and self.phase == "wanted-end":
                        self.phase = "pack-header"
                    elif value == 0 and self.phase == "pack" and self.pack_bytes:
                        self.phase = "end"
                    else:
                        raise WireError()
                    frames.append(original)
                    continue
                payload = value
                if self.request.sideband_all or self.phase == "pack":
                    _need(bool(payload) and payload[0] in (1, 2, 3))
                    band, payload = payload[0], payload[1:]
                    if band == 3:
                        raise WireError()  # Never echo the remote error text.
                    if band == 2:
                        self.progress_bytes += len(payload)
                        _need(self.progress_bytes <= MAX_PROGRESS, "response-limit")
                        frames.append(original)
                        continue
                if self.phase == "wanted-header":
                    _need(_line(payload) == b"wanted-refs", "unsupported-protocol")
                    self.phase = "wanted-row"
                elif self.phase == "wanted-row":
                    expected = (self.request.oid + " " + self.request.reference).encode("ascii")
                    _need(_line(payload) == expected, "target-changed")
                    self.phase = "wanted-end"
                elif self.phase == "pack-header":
                    _need(_line(payload) == b"packfile", "unsupported-protocol")
                    self.phase = "pack"
                elif self.phase == "pack":
                    _need(bool(payload))
                    self.pack_bytes += len(payload)
                else:
                    raise WireError()
                frames.append(original)
            return tuple(frames)
        except BaseException:
            self.failed = True
            raise
        finally:
            self.entered = False

    def finish(self) -> None:
        _need(not self.entered and not self.finished and not self.failed)
        self.finished = True
        try:
            self.decoder.finish()
            _need(self.phase == "end" and self.pack_bytes > 0)
        except BaseException:
            self.failed = True
            raise
