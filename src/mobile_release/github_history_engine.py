"""Fixed native History handshake. No CLI, action family or caller HTTP API."""
from __future__ import annotations

import os
import select
import sys
import time
from datetime import datetime, timezone

from . import _desktop_github_history_protocol as wire
from ._desktop_github_history_control import HistoryInput
from ._desktop_saved_command_engine import _Output, _SavedCommandEngine
from .cancellation import CleanupScope, DefaultCancellation
from .desktop_github_history import HistoryOperation, HistoryRefused
from .github_history import ASSURANCE, UNAVAILABLE, parse_result
from .owned_process import ProcessCleanupError

_RETAINED = []


class _HistoryEngine:
    # Reuse the exact existing original-FD acquisition/consuming close methods.
    # This is the subordinate child framing owner, never another native process
    # supervisor or alternate gh spawn/wait implementation.
    _acquire_output = _SavedCommandEngine._acquire_output
    close_output = _SavedCommandEngine.close_output
    _require = staticmethod(wire.require)

    def __init__(self, started, runtime_dir):
        self.started, self.runtime_dir = started, runtime_dir
        self.guard = DefaultCancellation(ProcessCleanupError, "History original custody did not settle")
        self.input = HistoryInput(started)
        self.output, self.error_output = _Output(1), _Output(2)
        self.operation = self.request = None
        self.primary = None
        self.output_bytes = self.frames = 0
        self.terminal_claimed = False
        self.evidence = None

    def cleanup(self):
        first = None
        operation = self.operation if self.operation is not None else self.input.operation
        if operation is not None:
            try:
                operation.cleanup()
            except BaseException as error:
                first = error
                self.guard._abort(error)
        try:
            self.input.close()
        except BaseException as error:
            if first is None:
                first = error
            self.guard._abort(error)
        if first is not None:
            raise first

    def write(self, raw, *, terminal=False):
        wire.require(type(raw) is bytes and not self.terminal_claimed and self.frames == (1 if terminal else 0)
                     and self.output_bytes + len(raw) <= 65536)
        self.terminal_claimed = terminal
        self.frames += 1
        self.output_bytes += len(raw)
        view = memoryview(raw)
        while view:
            if not terminal:
                self.guard.check()
            end = self.input.hard_end if terminal else self.input.work_end
            if terminal and self.input.first_failure is not None:
                end = min(end, self.input.first_failure + 10)
            wire.require(time.monotonic() < end and self.output.owned and not self.output.close_claimed)
            observed = os.fstat(1)
            wire.require((observed.st_dev, observed.st_ino, observed.st_mode) == self.output.identity)
            try:
                count = os.write(1, view[:4096])
                wire.require(type(count) is int and 0 < count <= min(4096, len(view)))
                view = view[count:]
            except BlockingIOError:
                select.select([], [1], [], min(0.05, max(0.0, end - time.monotonic())))

    def run(self):
        self.guard.install()
        self.input.acquire()
        self.guard._install_github_history_source(self.input)
        self._acquire_output(self.output)
        self._acquire_output(self.error_output)
        self.guard.activate()
        self.request = self.input.request()
        self.operation = HistoryOperation(self.request, self.input, self.guard, self.runtime_dir)
        self.operation.admit()
        self.write(self.input.ready())
        token = self.input.go()
        try:
            self.evidence = self.operation.run(token)
        finally:
            token = None

    def terminal(self):
        operation = self.operation
        wire.require(self.request is not None and operation is not None and self.frames == 1)
        known = (operation.closed and not operation.unknown and not self.guard.lifetime_ledger.fatal
                 and self.input.closed and self.guard.handler_state == "RESTORED")
        stop = self.input.stop_reason != "none" or self.guard.cancelled
        reason, result = "none", None
        if not known:
            reason = "cleanup-unknown"
        elif stop:
            reason = "expired" if self.input.stop_reason == "timed-out" else "cancelled"
        elif self.primary is not None and not isinstance(self.primary, HistoryRefused):
            reason = "response-invalid"  # No inferred HTTP/auth/signature cause.
        elif not operation.identity_complete:
            reason = self.primary.reason if isinstance(self.primary, HistoryRefused) else "response-invalid"
        else:
            failure = self.primary.reason if isinstance(self.primary, HistoryRefused) else "none"
            value = {"schemaVersion": 1, "context": self.request.context.value(),
                     "observedAt": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
                     "verification": "verified" if failure == "none" else "unavailable" if failure in UNAVAILABLE else "refused",
                     "reason": failure, "evidence": self.evidence if failure == "none" else None,
                     "assurance": ASSURANCE}
            result = parse_result(value, self.request.context)
        life = {"complete": known, "fatal": not known, "contained": known,
                "commandDispatched": operation.dispatched if known else None,
                "commands": operation.budget._calls, "verifierCalls": operation.budget._verifiers,
                "inputClosed": self.input.closed, "handlersRestored": self.guard.handler_state == "RESTORED",
                "invocationClosed": operation.closed, "stopObserved": stop}
        self.write(wire.terminal_frame(self.request, result, reason, life), terminal=True)


def main(*, started, runtime_dir):
    engine = _HistoryEngine(started, runtime_dir)
    scope = CleanupScope(engine.guard, engine.cleanup, owns_cancellation=True, first_primary=True)
    status = 0
    try:
        try:
            with scope:
                try:
                    engine.run()
                except BaseException as error:
                    engine.input.failure_observed()  # F precedes any cleanup.
                    engine.primary = error
                    raise
        finally:
            scope.__exit__(*sys.exc_info())
    except BaseException as error:
        if engine.primary is None:
            engine.primary = error
        status = 70
    try:
        if engine.request is not None and engine.frames == 1:
            engine.terminal()
            if not engine.guard.lifetime_ledger.fatal and engine.input.closed and engine.operation.closed:
                status = 0
    except BaseException as error:
        engine.guard._abort(error)
        status = 74
    finally:
        try:
            engine.close_output()
        except BaseException:
            status = 74
        if (engine.guard.lifetime_ledger.fatal or not engine.input.closed
                or engine.operation is not None and not engine.operation.closed
                or any(row.owned and not row.closed for row in (engine.output, engine.error_output))):
            _RETAINED.append(engine)
    return status
