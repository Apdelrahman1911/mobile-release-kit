"""One private device exchange, inside the existing installed Supervisor child.

There is no polling loop, gh, subprocess, credential file, callback server or
alternative HTTP client. A new child is admitted only by the same native device
registration AFTER the preceding child/runtime/observer has actually retired.
"""
from __future__ import annotations

import math
import os
import select
import sys
import time

from . import github_device_protocol as wire
from ._desktop_saved_command_control import SavedCommandDomain, _SavedCommandInput
from ._desktop_saved_command_engine import _Output, _SavedCommandEngine
from .cancellation import CleanupScope, DefaultCancellation
from .owned_process import ProcessCleanupError

_RETAINED = []


class DeviceInput(_SavedCommandInput):
    def __init__(self, started: float) -> None:
        super().__init__(started, domain=SavedCommandDomain.GitHubDevice)
        self.hard_end = started + wire.FINALITY_SECONDS
        self.initial = self.operation = None
        self.ready_sent = self.go_returned = False
        self.first_raw_ns = None

    def failure_observed(self) -> None:
        # Original native uptime at first detection, BEFORE HTTP/input cleanup.
        # It is private and compared by the parent's retained original bracket.
        if self.first_failure is None:
            raw_clock = getattr(time, "CLOCK_UPTIME_RAW", None)
            if type(raw_clock) is int:
                self.first_raw_ns = time.clock_gettime_ns(raw_clock)
        super().failure_observed()

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
            select.select([self.fd], [], [], min(0.05, max(0.0, self.work_end-time.monotonic())))

    def request(self) -> wire.Request:
        wire.require(self.initial is None and not self.request_returned)
        request = wire.parse_request(self._frame())
        raw_clock = getattr(time, "CLOCK_UPTIME_RAW", None)
        wire.require(type(raw_clock) is int)
        before, now = time.monotonic(), time.clock_gettime_ns(raw_clock)
        wire.require(type(now) is int and 0 <= now < request.work_end_ns < request.hard_end_ns)
        self.work_end = min(self.work_end, math.nextafter(before+(request.work_end_ns-now)/1e9, -math.inf))
        self.hard_end = min(self.hard_end, math.nextafter(before+(request.hard_end_ns-now)/1e9, -math.inf))
        self.initial, self.request_returned = request, True
        self.guard.check()
        return request

    def ready(self) -> bytes:
        self._owner()
        wire.require(self.request_returned and not self.ready_sent and not self.active and not self.buffer
                     and type(self.operation) is DeviceOperation and self.operation.source is self)
        self.guard.check()
        self.ready_sent = True
        return wire.ready(self.initial)

    def go(self) -> None:
        wire.require(self.ready_sent and not self.go_returned)
        raw = self._frame()
        self.go_returned = self.active = True  # Wrong/lost GO is spent, never retried.
        wire.require(raw == wire.go(self.initial))
        self.guard.check()

    def command_limits(self, *args, **kwargs):
        wire.require(False)  # This profile admits NO child command/gh operation.


class DeviceOperation:
    def __init__(self, request: wire.Request, source: DeviceInput, guard: DefaultCancellation) -> None:
        wire.require(type(request) is wire.Request and type(source) is DeviceInput and type(guard) is DefaultCancellation
                     and source.initial is request and source.operation is None and source.guard is guard)
        self.request, self.source, self.guard = request, source, guard
        self.entered = self.returned = self.closed = self.unknown = False
        self.reply = self.budget = None
        source.operation = self  # Retain before any HTTP/trust/native entry.

    def checkpoint(self) -> None:
        self.source._owner()
        wire.require(self.source.operation is self and self.source.guard is self.guard
                     and self.guard._saved_command_input() is self.source and self.source.go_returned
                     and not self.closed and not self.unknown)
        self.guard.check()
        wire.require(time.monotonic() < self.source.work_end)

    def failure(self, reason: str) -> None:
        self.source.failure_observed()  # BEFORE the original HTTP close, never a renewed cleanup timer.
        self.unknown |= reason == "cleanup-unknown"

    def transport_binding(self, budget) -> None:
        from ._github_connection_transport import _Budget, _ExchangeProfile
        self.checkpoint()
        wire.require(self.entered and not self.returned and type(budget) is _Budget and self.budget is budget
                     and budget.profile is _ExchangeProfile.DEVICE and budget.end <= self.source.work_end
                     and budget.requests == 0)

    def run(self, runtime_dir: str) -> None:
        from ._github_connection_transport import _Budget, _ExchangeProfile, _ResponseRole, _make_live_exchange, ReadResult
        self.checkpoint()
        wire.require(not self.entered)
        self.entered = True
        started = time.monotonic()
        self.budget = _Budget(started, _profile=_ExchangeProfile.DEVICE)
        self.budget.end = min(self.budget.end, self.source.work_end)
        exchange = _make_live_exchange(None, started=started, runtime_dir=runtime_dir,
            api_version="2022-11-28", _profile=_ExchangeProfile.DEVICE, _setup_budget=self.budget, _device_owner=self)
        start = self.request.role == "start"
        result = exchange("POST", "/login/device/code" if start else "/login/oauth/access_token",
                          wire.form(self.request.role, self.request.client_id, self.request.device_code),
                          _role=_ResponseRole.DEVICE_START if start else _ResponseRole.DEVICE_POLL)
        # exchange returned only after its own response/connection close claims.
        self.returned = True
        self.checkpoint()
        wire.require(type(result) is ReadResult and result.control["reason"] == "none"
                     and result.observation["failure"] == "none" and result.observation["status"] in {200, 400})
        self.reply = wire.provider_reply(self.request.role, result.observation["body"])

    def cleanup(self) -> None:
        # There is no independent socket owner to reconstruct. A missing return
        # from the actual fixed exchange remains debt, not an empty result.
        if self.entered and not self.returned:
            self.unknown = True
        self.closed = not self.unknown


class _Engine:
    _acquire_output = _SavedCommandEngine._acquire_output
    close_output = _SavedCommandEngine.close_output
    _require = staticmethod(wire.require)

    def __init__(self, started: float, runtime_dir: str) -> None:
        self.guard = DefaultCancellation(ProcessCleanupError, "The original device connection did not settle")
        self.input = DeviceInput(started)
        self.output, self.error_output = _Output(1), _Output(2)
        self.runtime_dir = runtime_dir
        self.request = self.operation = self.primary = None
        self.frames = self.output_bytes = 0
        self.terminal_claimed = False

    def cleanup(self) -> None:
        first = None
        if self.operation is not None:
            try:
                self.operation.cleanup()
            except BaseException as error:
                first = error
                self.guard._abort(error)
        try:
            self.input.close()
        except BaseException as error:
            self.guard._abort(error)
            if first is None:
                first = error
        if first is not None:
            raise first

    def write(self, raw: bytes, *, terminal: bool = False) -> None:
        wire.require(type(raw) is bytes and not self.terminal_claimed and self.frames == int(terminal)
                     and self.output_bytes + len(raw) <= wire.RESPONSE_LIMIT)
        self.terminal_claimed = terminal
        self.frames += 1
        self.output_bytes += len(raw)
        view = memoryview(raw)
        while view:
            if not terminal:
                self.guard.check()
            end = self.input.hard_end if terminal else self.input.work_end
            if terminal and self.input.first_failure is not None:
                end = min(end, self.input.first_failure + 2)
            wire.require(time.monotonic() < end and self.output.owned and not self.output.close_claimed)
            value = os.fstat(1)
            wire.require((value.st_dev, value.st_ino, value.st_mode) == self.output.identity)
            try:
                count = os.write(1, view[:4096])
                wire.require(type(count) is int and 0 < count <= min(len(view), 4096))
                view = view[count:]
            except BlockingIOError:
                select.select([], [1], [], min(0.05, max(0.0, end-time.monotonic())))

    def run(self) -> None:
        self.guard.install()
        self.input.acquire()
        self.guard._install_saved_command_source(self.input)
        self._acquire_output(self.output)
        self._acquire_output(self.error_output)
        self.guard.activate()
        self.request = self.input.request()
        self.operation = DeviceOperation(self.request, self.input, self.guard)
        self.write(self.input.ready())
        self.input.go()
        self.operation.run(self.runtime_dir)

    def terminal(self) -> None:
        operation = self.operation
        wire.require(self.request is not None and operation is not None and self.frames == 1)
        known = (operation.closed and not operation.unknown and not self.guard.lifetime_ledger.fatal
                 and self.input.closed and self.guard.handler_state == "RESTORED")
        status, reply = "refused", None
        if not known:
            status = "cleanup-unknown"
        elif self.input.stop_reason != "none" or self.guard.cancelled:
            status = "timed-out" if self.input.stop_reason == "timed-out" else "cancelled"
        elif self.primary is None and self.input.first_failure is None and operation.entered and operation.returned and operation.reply is not None:
            status, reply = "ok", operation.reply
        self.write(wire.terminal(self.request, status, reply, self.input.first_raw_ns), terminal=True)
        operation.reply = None


def main(*, started: float, runtime_dir: str) -> int:
    engine = _Engine(started, runtime_dir)
    scope = CleanupScope(engine.guard, engine.cleanup, owns_cancellation=True, first_primary=True)
    status = 0
    try:
        try:
            with scope:
                try:
                    engine.run()
                except BaseException as error:
                    engine.input.failure_observed()
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
            if engine.operation.closed and engine.input.closed and not engine.guard.lifetime_ledger.fatal:
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
                or any(slot.owned and not slot.closed for slot in (engine.output, engine.error_output))):
            _RETAINED.append(engine)
    return status
