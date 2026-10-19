"""GitRead in the existing held-input/STOP lifecycle, with one original clock."""
from __future__ import annotations

import math
import select
import time

from . import _desktop_git_read_protocol as wire
from ._desktop_saved_command_control import SavedCommandDomain, _SavedCommandInput


class GitReadInput(_SavedCommandInput):
    def __init__(self, started: float) -> None:
        super().__init__(started, domain=SavedCommandDomain.GitRead)
        self.hard_end = started + wire.FINALITY_SECONDS
        self.initial = self.operation = None
        self.ready_sent = self.go_returned = False
        self.first_failure_ns: int | None = None
        self.cleanup_end_ns: int | None = None

    def _frame(self) -> bytes:
        self._owner()
        wire.require(self.guard is not None and not self.active)
        while True:
            self.guard.check()
            if b"\n" in self.buffer:
                raw = bytes(self.buffer)
                wire.require(len(raw) <= wire.REQUEST_LIMIT and raw.endswith(b"\n") and raw.count(b"\n") == 1)
                self.buffer.clear()
                return raw
            wire.require(self.fd is not None)
            select.select([self.fd], [], [], min(0.05, max(0.0, self.work_end - time.monotonic())))

    def request(self) -> wire.Request:
        wire.require(self.initial is None and not self.request_returned)
        request = wire.parse_request(self._frame())
        raw_clock = getattr(time, "CLOCK_UPTIME_RAW", None)
        wire.require(type(raw_clock) is int)
        before = time.monotonic()
        now = time.clock_gettime_ns(raw_clock)
        wire.require(type(now) is int and 0 <= now < request.work_end_ns < request.hard_end_ns)
        # These are lower bounds against the original native endpoints, not
        # fresh per-command/session budgets. The native T precedes admission.
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
        # Latch local F BEFORE a possibly interrupted native clock call. Its
        # entire bracket is subtracted to obtain an earlier native F; a lost
        # clock return never gets another call or a renewed cleanup endpoint.
        raw_clock = getattr(time, "CLOCK_UPTIME_RAW", None)
        raw = time.clock_gettime_ns(raw_clock) if type(raw_clock) is int else None
        after = time.monotonic()
        if type(raw) is int:
            raw -= math.ceil(max(0.0, after - self.first_failure) * 1_000_000_000)
        if self.initial is not None and type(raw) is int and 0 < raw < self.initial.hard_end_ns:
            self.first_failure_ns = raw
            self.cleanup_end_ns = min(self.initial.hard_end_ns, raw + 10_000_000_000)

    def bind_operation(self, operation) -> None:
        from .desktop_git_read import GitReadOperation
        self._owner()
        wire.require(type(operation) is GitReadOperation and self.operation is None and self.initial is operation.request
                     and operation.source is self and operation.guard is self.guard and self.guard is not None
                     and self.guard._saved_command_input() is self and self.request_returned and not self.ready_sent)
        self.operation = operation

    def require_operation(self):
        from .desktop_git_read import GitReadOperation
        self._owner()
        wire.require(type(self.operation) is GitReadOperation and self.operation.source is self
                     and self.operation.guard is self.guard)
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
        raw = self._frame()
        self.go_returned = self.active = True
        wire.require(raw == wire.go(self.initial))  # Bad GO is spent too.
        self.require_operation().source_post(hash_files=True)
        self.guard.check()

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
        wire.require(self.go_returned and self.active and operation.entered and pending is not None
                     and pending.claimed and capture is True and output_limit == pending.output_limit)
        return self.remaining_timeout(timeout), output_limit
