"""One fixed main-thread preflight request, then held-pipe EOF cancellation.

No multi-frame edit protocol, reconnect, generic callback or competing reader.
The child-local 1800-second endpoint cannot renew the earlier native T/W/H.
"""
from __future__ import annotations

import math
import os
import select
import stat
import threading
import time
from typing import TYPE_CHECKING

from ._desktop_preflight_protocol import (PreflightRequest, ProtocolError, REQUEST_LIMIT,
    WORK_SECONDS, parse_request, require)

if TYPE_CHECKING:
    from .cancellation import DefaultCancellation


class PreflightInput:
    def __init__(self, started: float) -> None:
        require(type(started) in {float, int} and math.isfinite(started) and started >= 0)
        self.pid = os.getpid()
        self.thread = threading.current_thread()
        self.work_end = started + WORK_SECONDS
        self.guard: DefaultCancellation | None = None
        self.fd: int | None = None
        self.identity: tuple[int, int, int] | None = None
        self.acquired = False
        self.close_claimed = False
        self.closed = False
        self.active = False
        self.stop_reason = "none"
        self.custody_unknown = False
        self.buffer = bytearray()
        self.request_returned = False
        self.budget = None
        self.first_failure: float | None = None

    def _owner(self) -> None:
        require(self.pid == os.getpid() and self.thread is threading.current_thread()
            and self.thread is threading.main_thread())

    def acquire(self) -> None:
        self._owner()
        require(not self.acquired and self.fd is None and not self.close_claimed)
        self.fd = 0  # Claim the fixed original standard pipe before inspection.
        value = os.fstat(0)
        require(stat.S_ISFIFO(value.st_mode))
        self.identity = (value.st_dev, value.st_ino, value.st_mode)
        os.set_blocking(0, False)
        self.acquired = True

    def bind(self, guard: DefaultCancellation) -> None:
        from .cancellation import DefaultCancellation
        self._owner()
        require(type(guard) is DefaultCancellation and self.guard is None and self.acquired)
        guard._check_owner()
        self.guard = guard

    def failure_observed(self) -> None:
        self._owner()
        if self.first_failure is None:
            self.first_failure = time.monotonic()

    def remaining_timeout(self, timeout: int) -> int:
        self._owner()
        require(self.guard is not None and type(timeout) is int and timeout > 0)
        self.guard.check()
        if self.budget is not None:
            self.budget.checkpoint()
        remaining = int(self.work_end - time.monotonic())
        if remaining < 1:
            self.stop("timed-out")
            self.guard.check()
        return min(timeout, remaining)

    def stop(self, reason: str = "cancelled") -> None:
        self._owner()
        require(type(reason) is str and reason in {"cancelled", "timed-out"})
        self.failure_observed()
        if self.stop_reason == "none":
            self.stop_reason = reason
        if self.guard is not None:
            self.guard.cancelled = True

    def poll(self, guard: DefaultCancellation) -> None:
        self._owner()
        require(guard is self.guard)
        if self.stop_reason != "none" or self.close_claimed:
            if self.stop_reason != "none":
                guard.cancelled = True
            return
        if time.monotonic() >= self.work_end:
            self.stop("timed-out")
            return
        if self.active and self.buffer:
            self.stop()
            return
        try:
            require(self.fd is not None)
            value = os.fstat(self.fd)
            if (value.st_dev, value.st_ino, value.st_mode) != self.identity:
                self.custody_unknown = True
                raise ProtocolError("Original preflight input changed")
            limit = 1 if self.active else min(64 * 1024, REQUEST_LIMIT + 1 - len(self.buffer))
            require(limit > 0)
            try:
                chunk = os.read(self.fd, limit)
            except BlockingIOError:
                return
            if not chunk or self.active:
                self.stop()
                return
            self.buffer.extend(chunk)
            if len(self.buffer) > REQUEST_LIMIT:
                self.stop()
        except BaseException as error:
            # A read/identity failure is not successful EOF or finality. Keep
            # it on the actual guard even if closing another resource works.
            self.stop()
            guard._abort(error)

    def request(self) -> PreflightRequest:
        self._owner()
        require(self.guard is not None and not self.active and not self.request_returned)
        while True:
            self.guard.check()
            position = self.buffer.find(b"\n")
            if position >= 0:
                raw = bytes(self.buffer[:position + 1])
                del self.buffer[:position + 1]
                self.active = True  # Leftovers and any further byte are STOP.
                self.guard.check()
                request = parse_request(raw)
                self.guard.check()
                self.request_returned = True
                return request
            require(self.fd is not None)
            try:
                select.select([self.fd], [], [], 0.05)
            except (OSError, ValueError) as error:
                self.stop()
                self.guard._abort(error)

    def close(self) -> None:
        self._owner()
        if self.close_claimed:
            require(self.closed)
            return
        self.close_claimed = True
        number, self.fd = self.fd, None
        try:
            require(not self.custody_unknown)
            if number is not None:
                value = os.fstat(number)
                # A pre-acquisition error has no validated original identity;
                # do not manufacture permission to close a possibly reused FD.
                require(self.identity is not None and (value.st_dev, value.st_ino, value.st_mode) == self.identity)
                os.close(number)  # Retired before the sole possibly consuming call.
            self.closed = True
            if self.guard is not None:
                self.guard._remove_preflight_source(self)
        except BaseException as error:
            if self.guard is not None:
                self.guard._abort(error)
            raise
