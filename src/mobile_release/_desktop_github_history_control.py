"""Exact two-frame History input, using the existing held-pipe lifecycle."""
from __future__ import annotations

import math
import select
import time

from ._desktop_saved_command_control import SavedCommandDomain, _SavedCommandInput
from . import _desktop_github_history_protocol as wire
from .github_history import HistoryBudget


class HistoryInput(_SavedCommandInput):
    def __init__(self, started: float) -> None:
        super().__init__(started, domain=SavedCommandDomain.GitHubHistory)
        self.started = started
        self.hard_end = started + wire.FINALITY_SECONDS
        self.budget = HistoryBudget()
        self.operation = None
        self.initial = None
        self.ready_sent = False
        self.go_returned = False
        self.raw_clock = self.raw_work_end = self.raw_hard_end = None

    def _read_frame(self, maximum: int) -> bytes:
        self._owner()
        wire.require(self.guard is not None and not self.active)
        while True:
            self.guard.check()
            if b"\n" in self.buffer:
                # Exact frame; a pre-sent second command/credential is refused.
                raw = bytes(self.buffer)
                wire.require(len(raw) <= maximum and raw.endswith(b"\n") and raw.count(b"\n") == 1)
                self.buffer.clear()
                return raw
            wire.require(len(self.buffer) <= maximum and self.fd is not None)
            select.select([self.fd], [], [], min(0.05, max(0.0, self.work_end - time.monotonic())))

    def request(self):
        wire.require(self.initial is None and not self.request_returned and not self.ready_sent)
        request = wire.parse_request(self._read_frame(wire.REQUEST_LIMIT), self.budget)
        clock = getattr(time, "CLOCK_UPTIME_RAW", None)
        wire.require(type(clock) is int)
        before = time.monotonic()
        raw = time.clock_gettime_ns(clock)
        work = int(request.native["clock"]["workEndNs"])
        hard = int(request.native["clock"]["hardEndNs"])
        wire.require(type(raw) is int and 0 <= raw < work <= hard)
        self.raw_clock, self.raw_work_end, self.raw_hard_end = clock, work, hard
        # The local sample precedes the raw sample; rounding can only tighten.
        self.work_end = min(self.work_end, math.nextafter(before + (work - raw) / 1e9, -math.inf))
        self.hard_end = min(self.hard_end, math.nextafter(before + (hard - raw) / 1e9, -math.inf))
        self.initial = request
        self.request_returned = True
        self.guard.check()
        return request

    def bind_operation(self, operation) -> None:
        from .desktop_github_history import HistoryOperation
        self._owner()
        wire.require(type(operation) is HistoryOperation and self.operation is None
                     and self.initial is operation.request and operation.source is self
                     and operation.guard is self.guard and self.request_returned and not self.ready_sent)
        self.operation = operation

    def require_operation(self):
        from .desktop_github_history import HistoryOperation
        self._owner()
        wire.require(type(self.operation) is HistoryOperation and self.operation.source is self)
        return self.operation

    def ready(self) -> bytes:
        self._owner()
        wire.require(self.initial is not None and not self.ready_sent and not self.active)
        self.require_operation().source_post()
        self.guard.check()
        wire.require(not self.buffer)
        self.ready_sent = True
        return wire.ready_frame(self.initial)

    def go(self) -> str:
        self._owner()
        wire.require(self.ready_sent and not self.go_returned and self.initial is not None)
        token = wire.parse_go(self._read_frame(wire.GO_LIMIT), self.initial, self.budget)
        self.active = True
        self.go_returned = True
        self.require_operation().source_post()
        self.guard.check()
        return token

    def remaining_timeout(self, timeout: int) -> int:
        self._owner()
        wire.require(type(timeout) is int and timeout > 0)
        self.require_operation().checkpoint()
        remaining = int(self.work_end - time.monotonic())
        wire.require(remaining >= 1)
        return min(timeout, remaining)

    def command_limits(self, timeout: int, capture: bool, output_limit: int):
        # Generic build/run_owned may not use this credentialed fixed origin.
        wire.require(False)
