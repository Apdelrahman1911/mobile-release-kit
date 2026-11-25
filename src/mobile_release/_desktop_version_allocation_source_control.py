"""One exact cancellation borrower of the existing allocation dialogue.

This is NOT an inherited-stdio owner. It never acquires, reads or closes fd0,
duplicates a descriptor, or owns another input buffer. The bootstrap alone
physically closes the original private descriptions after dialogue completion.
"""
from __future__ import annotations

import os
import math
import stat
import threading
import time

from . import _desktop_version_allocation_source_protocol as wire
from ._desktop_saved_command_control import SavedCommandDomain


class BorrowedAllocationInput:
    def __init__(self, dialogue, request: wire.SourceRequest) -> None:
        from ._desktop_version_allocation_runtime import _Dialogue
        wire.require(type(dialogue) is _Dialogue and type(request) is wire.SourceRequest)
        wire.require(wire.SourceRequest.parse(request.value()) == request)
        self.dialogue, self.request = dialogue, request
        self.pid, self.thread = os.getpid(), threading.current_thread()
        self.guard = self.operation = None
        self.identity = self.output_identity = None
        self.acquired = self.borrow_ended = self.unknown = False
        self.first_failure = None
        self.first_failure_raw = None
        self.failure_claimed = False
        self.failure_error = None

    @property
    def domain(self):
        return SavedCommandDomain.VersionAllocationSource

    @property
    def work_end(self):
        return self.dialogue.work_end

    @property
    def provider_selection(self):
        return self.dialogue.initial.provider

    def source_time(self):
        self.dialogue._time()

    def _owner(self):
        wire.require(self.pid == os.getpid() and self.thread is threading.current_thread()
                     and self.thread is threading.main_thread())

    def acquire_borrow(self):
        self._owner()
        wire.require(not self.acquired and self.identity is None and not self.borrow_ended and not self.unknown)
        self.unknown = True  # A lost initial observation cannot be reacquired.
        first, second = os.fstat(self.dialogue.control), os.fstat(self.dialogue.output)
        wire.require(stat.S_ISFIFO(first.st_mode) and stat.S_ISFIFO(second.st_mode))
        self.identity = (first.st_dev, first.st_ino, first.st_mode)
        self.output_identity = (second.st_dev, second.st_ino, second.st_mode)
        wire.require(self.identity != self.output_identity)
        self.acquired, self.unknown = True, False

    def bind(self, guard):
        from .cancellation import DefaultCancellation
        self._owner()
        wire.require(type(guard) is DefaultCancellation and self.guard is None and self.acquired
                     and not self.unknown and not self.borrow_ended)
        guard._check_owner()
        self.guard = guard

    def _identity(self):
        self._owner()
        wire.require(self.acquired and not self.unknown and not self.borrow_ended)
        self._descriptor_identity()

    def _descriptor_identity(self):
        first, second = os.fstat(self.dialogue.control), os.fstat(self.dialogue.output)
        wire.require((first.st_dev, first.st_ino, first.st_mode) == self.identity
                     and (second.st_dev, second.st_ino, second.st_mode) == self.output_identity)

    def failure_observed(self):
        self._owner()
        if self.failure_claimed:
            return
        self.failure_claimed = True  # A return-lost clock observation is not retryable.
        try:
            now = time.monotonic()
            raw = time.clock_gettime_ns(self.dialogue.raw_clock)
            wire.require(type(now) in (int, float) and math.isfinite(now)
                         and self.dialogue.last_time <= now and type(raw) is int
                         and self.dialogue.last_raw is not None and self.dialogue.last_raw <= raw
                         and 0 < raw < self.dialogue.raw_hard_end)
            self.first_failure, self.first_failure_raw = now, raw
            self.dialogue.last_time, self.dialogue.last_raw = now, raw
        except BaseException as error:
            self.unknown = True
            self.dialogue.poisoned = True
            self.failure_error = error
            if self.guard is not None:
                # The enclosing original CleanupScope has not remembered its
                # incoming primary yet. Latch fatal WITHOUT replacing it with
                # this diagnostic; no later work or FIN can pass this latch.
                self.guard.lifetime_ledger._abort()

    def poll(self, guard):
        self._owner()
        wire.require(guard is self.guard)
        try:
            self._identity()
            phase = self.dialogue.phase
            wire.require(phase in {"ready", "go", "active", "ack", "fin", "eof", "returned"})
            if phase == "active":
                self.dialogue.checkpoint()  # The sole original cursor checks EOF.
            else:
                # READY/GO/ACK/FIN have their own cursor. Do not prefetch even
                # one byte of an ACK while a state/C-A-W operation is pending.
                self.dialogue._time(finality=phase in {"fin", "eof", "returned"})
        except BaseException as error:
            self.unknown = True
            self.failure_observed()
            self.dialogue.poisoned = True
            guard._abort(error)

    def bind_operation(self, operation):
        from .version_allocation_source import AllocationSourceRun
        self._owner()
        wire.require(type(operation) is AllocationSourceRun and self.operation is None
            and operation.input is self and operation.request is self.request and operation.guard is self.guard
            and self.guard is not None and self.guard._saved_command_input() is self
            and self.dialogue.phase == "active" and not self.borrow_ended and not self.unknown)
        self.operation = operation

    def require_operation(self):
        from .version_allocation_source import AllocationSourceRun
        self._owner()
        wire.require(type(self.operation) is AllocationSourceRun and self.operation.input is self
                     and self.operation.guard is self.guard and self.operation.request is self.request)
        return self.operation

    def remaining_timeout(self, timeout):
        self._owner()
        wire.require(type(timeout) is int and 1 <= timeout <= 10)
        self.require_operation().checkpoint()
        remaining = int(self.work_end - time.monotonic())
        wire.require(remaining >= 1)
        return min(timeout, remaining)

    def command_limits(self, timeout, capture, output_limit):
        wire.require(capture is True)
        return self.require_operation().command_limits(self.remaining_timeout(timeout), output_limit)

    def originals_closed(self):
        self._owner()
        if self.operation is not None:
            return self.require_operation().originals_closed()
        # A refused GO can precede construction of the sole source operation.
        # No project/command can acquire through this input without that exact
        # operation. Releasing this unused borrow still says nothing about EOF.
        wire.require(self.guard is not None)
        facts = self.guard.lifetime_ledger.verdict()
        return (facts.complete and facts.cleanup_complete and facts.contained and not facts.fatal
                and facts.profile_calls == facts.commands == 0)

    def end_borrow(self):
        """Release only cancellation borrowing, NEVER claim inputClosed."""
        self._owner()
        wire.require(not self.borrow_ended and self.guard is not None and self.acquired and not self.unknown
                     and self.originals_closed())
        self._identity()
        self.borrow_ended = True
        self.guard._remove_saved_command_source(self)

    def terminal_bounds(self):
        """Actual SOURCE/Reserve closed originals; never caller-supplied grace."""
        from . import _desktop_version_allocation_protocol as reserve_wire
        self._owner()
        initial = self.dialogue.initial
        wire.require((type(initial) is wire.Initial or type(initial) is reserve_wire.Initial
                      and initial.provider is not None) and initial.source is self.request
                     and self.acquired and self.borrow_ended and not self.unknown
                     and self.guard is not None and self.guard.handler_state == "RESTORED"
                     and self.guard._saved_command_input() is None and self.originals_closed())
        self._descriptor_identity()  # These ORIGINAL bootstrap FDs are still open.
        wire.require(self.failure_claimed == (self.first_failure is not None)
                     and self.failure_claimed == (self.first_failure_raw is not None))
        end, raw_end = self.dialogue.hard_end, self.dialogue.raw_hard_end
        if self.first_failure is not None:
            end = min(end, self.first_failure + 10.0)
            raw_end = min(raw_end, self.first_failure_raw + 10_000_000_000)
        return end, raw_end
