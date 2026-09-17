"""The dedicated engine's sole main-thread unbuffered stdin/EOF owner.

No competing reader, signal-by-PID, inherited extra pipe, worker, callback, or
reconnect. Active work treats both prefetched leftovers and readable OS bytes
as STOP. Fixed cleanup calls poll() only, never a cancelled ordinary check().
"""
from __future__ import annotations

import os
import select
import stat
import threading
import time
from typing import TYPE_CHECKING

from ._desktop_edit_protocol import EditRequest, ProtocolError, PROTOCOL, WORKFLOW_PROTOCOL, REQUEST_LIMIT, parse_request

if TYPE_CHECKING:
    from .cancellation import DefaultCancellation


class EditInput:
    def __init__(self, started: float, *, protocol: str = PROTOCOL) -> None:
        if protocol not in {PROTOCOL, WORKFLOW_PROTOCOL}:
            raise ProtocolError("Invalid fixed edit domain")
        self.protocol = protocol
        self.pid = os.getpid()
        self.thread = threading.current_thread()
        self.started = started
        self.review_end = started + 900.0
        self.active_end: float | None = started + 30.0
        self.apply_active = False
        self.guard: DefaultCancellation | None = None
        self.fd: int | None = None
        self.identity: tuple[int, int, int] | None = None
        self.acquired = False
        self.close_claimed = False
        self.closed = False
        self.active = False
        self.stopped = False
        self.custody_unknown = False
        self.buffer = bytearray()
        self.frames = 0

    def _owner(self) -> None:
        if (self.pid != os.getpid() or self.thread is not threading.current_thread()
                or self.thread is not threading.main_thread()):
            raise ProtocolError("Edit input belongs to its original main thread")

    def acquire(self) -> None:
        self._owner()
        if self.acquired or self.fd is not None or self.close_claimed:
            raise ProtocolError("Edit input cannot be reacquired")
        # fd 0 is the bootstrap's fixed original stdin, not a renderer/discovered
        # descriptor. Claim it before the first fallible native inspection.
        self.fd = 0
        value = os.fstat(self.fd)
        if not stat.S_ISFIFO(value.st_mode):
            raise ProtocolError("Edit stdin must be the original pipe")
        self.identity = (value.st_dev, value.st_ino, value.st_mode)
        os.set_blocking(self.fd, False)
        self.acquired = True

    def bind(self, guard: DefaultCancellation) -> None:
        from .cancellation import DefaultCancellation
        self._owner()
        if type(guard) is not DefaultCancellation or self.guard is not None or not self.acquired:
            raise ProtocolError("Invalid edit input binding")
        guard._check_owner()
        self.guard = guard

    def _stop(self) -> None:
        self.stopped = True
        if self.guard is not None:
            self.guard.cancelled = True

    def poll(self, guard: DefaultCancellation) -> None:
        self._owner()
        if guard is not self.guard:
            raise ProtocolError("Invalid edit input owner")
        if self.stopped or self.close_claimed:
            if self.stopped:
                guard.cancelled = True
            return
        now = time.monotonic()
        if ((not self.apply_active and now >= self.review_end)
                or self.active_end is not None and now >= self.active_end):
            self._stop()
            return
        if self.active and self.buffer:
            self._stop()
            return
        try:
            if self.fd is None:
                raise ProtocolError("Edit input is not acquired")
            value = os.fstat(self.fd)
            if (value.st_dev, value.st_ino, value.st_mode) != self.identity:
                self.custody_unknown = True
                guard._abort(ProtocolError("Original edit input custody changed"))
                raise ProtocolError("Original edit input changed")
            limit = 1 if self.active else min(64 * 1024, REQUEST_LIMIT + 1 - len(self.buffer))
            if limit <= 0:
                raise ProtocolError("Edit input exceeded its bound")
            try:
                chunk = os.read(self.fd, limit)
            except BlockingIOError:
                return
            if not chunk or self.active:
                self._stop()
                return
            self.buffer.extend(chunk)
            if self.active_end is None:
                self.active_end = now + 30.0  # A partial request cannot hold review open.
            if len(self.buffer) > REQUEST_LIMIT:
                self._stop()
        except BaseException:
            # Read errors and identity uncertainty are STOP, never EOF/finality.
            self._stop()

    def request(self, sequence: int, session: str | None) -> EditRequest:
        self._owner()
        if self.guard is None or self.active or self.frames >= 3:
            raise ProtocolError("No next edit request is legal")
        while True:
            self.guard.check()
            position = self.buffer.find(b"\n")
            if position >= 0:
                raw = bytes(self.buffer[:position + 1])
                del self.buffer[:position + 1]
                # The sole reader becomes the exact active cancellation source
                # before parsing/acceptance. This catches prefetched frame 2 as
                # well as newly readable OS bytes/EOF before any native effect.
                self.active = True
                self.guard.check()
                request = parse_request(raw, sequence=sequence, session=session, protocol=self.protocol)
                self.guard.check()
                self.frames += 1
                self.apply_active = request.op == "apply"
                if sequence != 0:
                    self.active_end = time.monotonic() + 30.0
                return request
            if self.fd is None:
                raise ProtocolError("Original edit input is unavailable")
            try:
                select.select([self.fd], [], [], 0.2)
            except (OSError, ValueError):
                self._stop()

    def idle(self) -> None:
        self._owner()
        if self.guard is None or not self.active or self.apply_active:
            raise ProtocolError("No further idle phase is legal")
        self.guard.check()
        self.active = False
        self.active_end = None
        # Restore legal idle-input mode BEFORE publishing opened/prepared.
        self.guard.check()

    def close(self) -> None:
        self._owner()
        if self.close_claimed:
            if not self.closed:
                raise ProtocolError("Original edit input close is unknown")
            return
        self.close_claimed = True
        number, self.fd = self.fd, None
        try:
            if self.custody_unknown:
                # An observed reused/changed integer must never close a foreign
                # descriptor. Preserve uncertainty, not a numeric-close retry.
                raise ProtocolError("Original edit input custody is unknown")
            if number is not None:
                os.close(number)  # Once only; retired even on ambiguous error.
            self.closed = True
            if self.guard is not None:
                self.guard._remove_edit_source(self)
        except BaseException as error:
            if self.guard is not None:
                self.guard._abort(error)
            raise
