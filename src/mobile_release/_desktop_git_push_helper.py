"""One fixed connect/receive-pack transcript on the original helper pipes.

Not a bootstrap, native issuer, pipe adopter or credential entry. The existing
GitRemote entry must retain the body leases, fixed pre-push hook and SAME FD8
send-point exchange. Inert callback tests cannot establish that native custody.
There is no stateless-connect fallback, response-end marker or second reader.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib

from . import git_push_body as bodies
from . import git_push_transport as transport
from . import git_push_wire as wire


@dataclass(frozen=True, slots=True, repr=False)
class Transcript:
    local_ref: str
    remote_ref: str
    old_oid: str
    new_oid: str
    body: wire.BodyDigest
    response_sha256: str
    # Historical comparisons only. No child exit, TLS/pipe close, native
    # currentness, durable ACK or finality can be minted from this DATA.


class _Helper:
    def __init__(self, original: transport._PushTransport, io: bodies._BodyIO,
                 *, read, write, current, send_point):
        transport.require(type(original) is transport._PushTransport and original.mode == "apply"
                          and type(io) is bodies._BodyIO and io.current is current
                          and original.current is current and callable(read) and callable(write)
                          and callable(current) and callable(send_point))
        self.transport, self.io, self.read, self.write = original, io, read, write
        self.current, self.send_point = current, send_point
        self.body = self.request = None
        self.entered = self.finished = self.failed = False
        self.pack_eof = self.send_point_entered = self.send_point_returned = False

    def _read(self, maximum, *, eof=False):
        transport.require(type(maximum) is int and 1 <= maximum <= wire.READ_CHUNK)
        self.current(); self.transport.budget.remaining()
        block = self.read(maximum)
        self.current(); self.transport.budget.remaining()
        transport.require(type(block) is bytes and len(block) <= maximum and (eof or bool(block)))
        return block

    def _line(self):
        line = bytearray()
        for _ in range(128):
            line.extend(self._read(1))
            if line.endswith(b"\n"):
                return bytes(line)
        transport.require(False, "response-limit")

    def _emit(self, raw):
        transport.require(type(raw) is bytes and 0 < len(raw) <= wire.MAX_METADATA)
        for offset in range(0, len(raw), wire.READ_CHUNK):
            self.current(); self.transport.budget.remaining()
            # Only the original pipe knows its returned short writes. Never
            # replay a callback after a partial or otherwise uncertain result.
            transport.require(self.write(raw[offset:offset + wire.READ_CHUNK]) is None)
            self.current(); self.transport.budget.remaining()

    def _command(self):
        decoder = wire.framing._Packets(wire.MAX_COMMAND, 2)
        raw = bytearray()
        while True:
            # Do not consume any PACK bytes while parsing the one command.
            need = (4 if decoder.size is None else decoder.size) - len(decoder.buffer)
            transport.require(need > 0)
            block = self._read(min(wire.READ_CHUNK, need))
            transport.require(len(block) <= wire.MAX_COMMAND - len(raw), "response-limit")
            raw.extend(block)
            for value, _ in decoder.feed(block):
                transport.require(type(value) is bytes or value == 0)
                if value == 0:
                    decoder.finish()
                    return wire.command(bytes(raw), self.transport.target.selected, self.transport.offered)

    def run(self):
        transport.require(not self.entered and not self.failed and not self.finished)
        self.entered = True
        try:
            transport.require(self._line() == b"capabilities\n")
            self._emit(b"connect\n\n")
            transport.require(self._line() == b"connect git-receive-pack\n")
            self.transport.before()
            self.transport.advertisement()
            self._emit(b"\n")
            self._emit(self.transport.offered.git_bytes())
            self.request = self._command()
            # The actual parent retained both body leases before helper GO.
            # This child facet is installed before the first body write.
            self.body = bodies._PushBody(self.io, self.transport.target.selected, self.transport.offered)
            self.body.begin(self.request)
            while True:
                block = self._read(wire.READ_CHUNK, eof=True)
                if not block:
                    self.pack_eof = True
                    break
                self.body.append(block)
            digest = self.body.seal()
            # Stock send-pack has closed its pack input before waiting for the
            # response. The fixed pre-push hook already returned on the SAME
            # FD8; only now may the helper consume that candidate ACK once.
            self.send_point_entered = True
            transport.require(self.send_point(self.request, digest) is None)
            self.send_point_returned = True
            self.current(); self.transport.budget.remaining()
            response = self.transport.publish(self.body)
            self.transport.after()
            self._emit(response)
            self.current()
            transport.require(self.transport.finished and self.transport.phase == 7
                              and not self.transport.failed and self.body.phase == "sent")
            self.finished = True
            selected = self.transport.target.selected
            return Transcript(selected.local_ref, selected.remote_ref, selected.old_oid, selected.new_oid,
                              digest, self.transport.posted.value.response_sha256)
        except BaseException as error:
            self.failed = self.transport.failed = True
            self.transport.failure(getattr(error, "reason", "cleanup-unknown"))
            raise
        finally:
            self.entered = False


@dataclass(frozen=True, slots=True, repr=False)
class ReviewTranscript:
    local_ref: str
    remote_ref: str
    old_oid: str
    new_oid: str
    advertisement_sha256: str


class _ReviewHelper:
    """Original stock-Git dry-run: advertise, then exactly flush and EOF.

    The fixed pre-push hook still runs and compares the original tuple. Its
    parent separately retains that returned comparison, not a candidate ACK.
    This helper has no body lease, send point or POST branch. Its input EOF is
    protocol DATA, not closure of the original pipes/C-A-W or native finality.
    """
    _read, _line, _emit = _Helper._read, _Helper._line, _Helper._emit

    def __init__(self, original: transport._PushTransport, *, read, write, current):
        transport.require(type(original) is transport._PushTransport and original.mode == "review"
                          and original.current is current and callable(read) and callable(write)
                          and callable(current))
        self.transport, self.read, self.write, self.current = original, read, write, current
        self.entered = self.finished = self.failed = self.input_eof = False

    def run(self):
        transport.require(not self.entered and not self.failed and not self.finished)
        self.entered = True
        try:
            transport.require(self._line() == b"capabilities\n")
            self._emit(b"connect\n\n")
            transport.require(self._line() == b"connect git-receive-pack\n")
            self.transport.before()
            raw = self.transport.advertisement()
            self._emit(b"\n")
            self._emit(self.transport.offered.git_bytes())
            flush = bytearray()
            while len(flush) < 4:
                flush.extend(self._read(4 - len(flush)))
            transport.require(flush == b"0000")
            transport.require(self._read(1, eof=True) == b"")
            self.input_eof = True
            self.transport.finish_read()
            self.current(); self.transport.budget.remaining()
            transport.require(self.transport.finished and self.transport.phase == 5 and not self.transport.failed)
            self.finished = True
            selected = self.transport.target.selected
            return ReviewTranscript(selected.local_ref, selected.remote_ref, selected.old_oid,
                                    selected.new_oid, hashlib.sha256(raw).hexdigest())
        except BaseException as error:
            self.failed = self.transport.failed = True
            self.transport.failure(getattr(error, "reason", "cleanup-unknown"))
            raise
        finally:
            self.entered = False
