"""One stateless-connect Git transcript, using the SAME private Git pipe.

This is the fixed helper body, not an executable/credential/descriptor entry.
The native GitRemote input/FD8 issuer must still supply its actual held input,
output, transport and original clock/currentness owner. No bootstrap or public
route is installed by this supporting leaf. Fake callbacks test protocol only.
"""
from __future__ import annotations

from dataclasses import dataclass

from . import git_remote_wire as wire
from .git_remote_transport import _RemoteTransport, require


@dataclass(frozen=True, slots=True, repr=False)
class Transcript:
    reference: str
    oid: str
    # Only bounded comparison DATA. This never means C/A/W/native/IO close,
    # source POST, fsck/connectivity, candidate ACK or publication has settled.


class _Helper:
    def __init__(self, transport: _RemoteTransport, *, read, write, current) -> None:
        require(type(transport) is _RemoteTransport and callable(read) and callable(write)
                and callable(current) and transport.current is current
                and transport.target.selected.oid is not None)
        self.transport, self.read, self.write, self.current = transport, read, write, current
        self.entered = self.finished = self.failed = False

    def _read(self, maximum: int, *, eof: bool = False) -> bytes:
        require(type(maximum) is int and 1 <= maximum <= wire.READ_CHUNK)
        self.current(); self.transport.budget.remaining()
        block = self.read(maximum)
        self.current(); self.transport.budget.remaining()
        require(type(block) is bytes and len(block) <= maximum and (eof or bool(block)))
        return block

    def _line(self) -> bytes:
        line = bytearray()
        for _ in range(128):
            line.extend(self._read(1))
            if line.endswith(b"\n"):
                return bytes(line)
        require(False, "response-limit")

    def _emit(self, raw: bytes) -> None:
        require(type(raw) is bytes and 0 < len(raw) <= wire.MAX_METADATA)
        for start in range(0, len(raw), wire.READ_CHUNK):
            self.current(); self.transport.budget.remaining()
            # The ORIGINAL pipe writer owns actual short-write handling and
            # ambiguity. Never retry a callback that partially wrote or raised.
            require(self.write(raw[start:start + wire.READ_CHUNK]) is None)
            self.current(); self.transport.budget.remaining()

    def _request(self) -> bytes:
        decoder = wire._Packets(wire.MAX_REQUEST, 64)
        raw = bytearray()
        while True:
            # Do not over-read the following round. Reuse the wire decoder's
            # exact current frame, not a second parser or an unbounded readline.
            need = (4 if decoder.size is None else decoder.size) - len(decoder.buffer)
            require(need > 0)
            block = self._read(min(wire.READ_CHUNK, need))
            require(len(block) <= wire.MAX_REQUEST - len(raw), "response-limit")
            raw.extend(block)
            for value, _ in decoder.feed(block):
                require(value != 2)  # Only this helper emits response-end.
                if value == 0:
                    decoder.finish()
                    return bytes(raw)

    def run(self) -> Transcript:
        require(not self.entered and not self.failed and not self.finished)
        self.entered = True  # Before any original callback/IO or credential use.
        try:
            require(self._line() == b"capabilities\n")
            self._emit(b"stateless-connect\n\n")
            require(self._line() == b"stateless-connect git-upload-pack\n")
            self.transport.before()
            advertisement = self.transport.advertisement()
            # No fallback/capability rewriting. The original GET returned and
            # closed before acknowledging stateless-connect or relaying bytes.
            self._emit(b"\n")
            self._emit(advertisement)
            ls_refs = self._request()
            self._emit(self.transport.ls_refs(ls_refs))
            self._emit(b"0002")  # Only after that SAME HTTP exchange closed.
            fetch = self._request()
            self.transport.fetch(fetch, self._emit)
            self.transport.after()
            self._emit(b"0002")  # Includes exact post account/repository checks.
            require(self._read(1, eof=True) == b"")  # No third request/retry.
            self.current()
            require(self.transport.phase == 7 and not self.transport.failed)
            self.finished = True
            return Transcript(self.transport.selected.reference, self.transport.selected.oid)
        except BaseException:
            self.failed = self.transport.failed = True
            raise
        finally:
            self.entered = False
