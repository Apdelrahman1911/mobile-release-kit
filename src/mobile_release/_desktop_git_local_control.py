"""One fixed GitLocal request/GO/candidate-ACK in the original held input.

Acquisition, consuming close, STOP identity and cancellation registration remain
the existing SavedCommandInput owner. No caller selects an input phase or sends
another command. A parsed ACK is comparison DATA, never durable/native authority.
"""
from __future__ import annotations

import math
import os
import select
import time

from . import _desktop_git_local_protocol as wire
from ._desktop_saved_command_control import SavedCommandDomain, _SavedCommandInput


class GitLocalInput(_SavedCommandInput):
    def __init__(self, started: float) -> None:
        super().__init__(started, domain=SavedCommandDomain.GitLocal)
        self.hard_end = started + wire.FINALITY_SECONDS
        self.initial = self.operation = None
        self.ready_sent = self.go_returned = False
        self.candidate_claimed = self.candidate_waiting = self.candidate_returned = False
        self.candidate = None
        self.ack_revision = None
        self.first_failure_ns = self.cleanup_end_ns = None

    def _frame(self, maximum: int) -> bytes:
        self._owner()
        wire.require(self.guard is not None and (not self.active or self.candidate_waiting)
                     and maximum in (wire.REQUEST_LIMIT, wire.READY_LIMIT))
        while True:
            self.guard.check()
            wire.require(len(self.buffer) <= maximum)
            if b"\n" in self.buffer:
                raw = bytes(self.buffer)
                wire.require(raw.endswith(b"\n") and raw.count(b"\n") == 1)
                self.buffer.clear()
                return raw
            wire.require(self.fd is not None)
            select.select([self.fd], [], [], min(0.05, max(0.0, self.work_end - time.monotonic())))

    def request(self) -> wire.Request:
        wire.require(self.initial is None and not self.request_returned)
        request = wire.parse_request(self._frame(wire.REQUEST_LIMIT))
        raw_clock = getattr(time, "CLOCK_UPTIME_RAW", None)
        wire.require(type(raw_clock) is int)
        before = time.monotonic()
        now = time.clock_gettime_ns(raw_clock)
        wire.require(type(now) is int and 0 <= now < request.work_end_ns < request.hard_end_ns)
        # Same lower-bound bridge as GitRead; no phase or command renews T/W/H.
        self.work_end = min(self.work_end, math.nextafter(before + (request.work_end_ns - now) / 1e9, -math.inf))
        self.hard_end = min(self.hard_end, math.nextafter(before + (request.hard_end_ns - now) / 1e9, -math.inf))
        self.cleanup_end_ns = request.hard_end_ns
        self.initial, self.request_returned = request, True
        self.guard.check()
        return request

    def failure_observed(self) -> None:
        self._owner()
        if self.first_failure is not None:
            return
        self.first_failure = time.monotonic()
        self.hard_end = min(self.hard_end, self.first_failure + 10)
        raw_clock = getattr(time, "CLOCK_UPTIME_RAW", None)
        raw = time.clock_gettime_ns(raw_clock) if type(raw_clock) is int else None
        after = time.monotonic()
        if type(raw) is int:
            raw -= math.ceil(max(0.0, after - self.first_failure) * 1_000_000_000)
        if self.initial is not None and type(raw) is int and 0 < raw < self.initial.hard_end_ns:
            self.first_failure_ns = raw
            self.cleanup_end_ns = min(self.initial.hard_end_ns, raw + 10_000_000_000)

    def poll(self, guard) -> None:
        """Same original cursor; the only added receiving phase is one ACK."""
        self._owner()
        wire.require(guard is self.guard)
        if self.stop_reason != "none" or self.close_claimed:
            if self.stop_reason != "none":
                guard.cancelled = True
            return
        if time.monotonic() >= self.work_end:
            self.stop("timed-out")
            return
        active = self.active and not self.candidate_waiting
        if active and self.buffer:
            self.stop()
            return
        try:
            wire.require(self.fd is not None)
            current = os.fstat(self.fd)
            if (current.st_dev, current.st_ino, current.st_mode) != self.identity:
                self.custody_unknown = True
                raise wire.ProtocolError("The original local Git input changed.")
            maximum = wire.READY_LIMIT if self.request_returned else wire.REQUEST_LIMIT
            limit = 1 if active else min(4096, maximum + 1 - len(self.buffer))
            wire.require(limit > 0)
            try:
                chunk = os.read(self.fd, limit)
            except BlockingIOError:
                return
            if not chunk or active:
                self.stop()
                return
            self.buffer.extend(chunk)
            if len(self.buffer) > maximum:
                self.stop()
        except BaseException as error:
            self.stop()
            guard._abort(error)

    def bind_operation(self, operation) -> None:
        from .desktop_git_local import GitLocalOperation
        self._owner()
        wire.require(type(operation) is GitLocalOperation and self.operation is None
                     and self.initial is operation.request and operation.source is self
                     and operation.guard is self.guard and self.guard is not None
                     and self.guard._saved_command_input() is self and self.request_returned and not self.ready_sent)
        self.operation = operation

    def require_operation(self):
        from .desktop_git_local import GitLocalOperation
        self._owner()
        wire.require(type(self.operation) is GitLocalOperation and self.operation.source is self
                     and self.operation.request is self.initial and self.operation.guard is self.guard)
        return self.operation

    def ready(self) -> bytes:
        self._owner()
        wire.require(not self.ready_sent and not self.active)
        self.require_operation().source_post(hash_files=True)
        self.guard.check()
        wire.require(not self.buffer)
        self.ready_sent = True
        return wire.ready(self.initial)

    def go(self) -> None:
        self._owner()
        wire.require(self.ready_sent and not self.go_returned)
        raw = self._frame(wire.READY_LIMIT)
        self.go_returned = self.active = True
        wire.require(raw == wire.go(self.initial))
        self.require_operation().source_post(hash_files=True)
        self.guard.check()

    def handoff(self, sent: wire.Candidate) -> None:
        """Entered before write. Missing/invalid/late return spends this handoff."""
        self._owner()
        operation = self.require_operation()
        wire.require(self.go_returned and self.active and not self.candidate_claimed and not self.buffer
                     and self.initial.phase == "apply" and operation.pending is None
                     and type(sent) is wire.Candidate and sent.request is self.initial)
        self.guard.check()
        self.candidate_claimed = self.candidate_waiting = True
        self.candidate = sent
        try:
            operation.write_candidate(sent)
            revision = wire.acknowledged(self.initial, sent, self._frame(wire.READY_LIMIT))
            self.candidate_waiting = False
            # The existing input owner polls STOP again after the native CAS
            # ACK. It remains active, so any extra bytes/EOF refuse publication.
            self.guard.check()
            operation.source_post(hash_files=True)
            self.ack_revision, self.candidate_returned = revision, True
        except BaseException:
            self.failure_observed()
            # Never clear claimed/replace the original candidate on failure.
            raise

    def remaining_timeout(self, timeout: int) -> int:
        self._owner()
        wire.require(type(timeout) is int and 0 < timeout <= wire.COMMAND_SECONDS)
        self.guard.check()
        remaining = int(self.work_end - time.monotonic())
        wire.require(remaining >= 1)
        return min(timeout, remaining)

    def command_limits(self, timeout: int, capture: bool, output_limit: int) -> tuple[int, int]:
        self._owner()
        operation = self.require_operation()
        pending = operation.pending
        wire.require(self.go_returned and self.active and not self.candidate_waiting
                     and operation.entered and pending is not None and pending.claimed
                     and capture is True and output_limit == pending.output_limit)
        return self.remaining_timeout(timeout), output_limit
