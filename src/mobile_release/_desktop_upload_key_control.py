"""One fixed GenerateUploadKey source in the existing held-input lifecycle."""
from __future__ import annotations

import math
import select
import time

from . import _desktop_upload_key_protocol as wire
from ._desktop_saved_command_control import SavedCommandDomain, _SavedCommandInput


class UploadKeyInput(_SavedCommandInput):
    def __init__(self, started: float) -> None:
        super().__init__(started, domain=SavedCommandDomain.GenerateUploadKey)
        self.hard_end = started + wire.FINALITY_SECONDS
        self.initial = self.operation = self.passwords = None
        self.ready_sent = self.go_claimed = self.go_returned = False
        self.material_pending = self.material_receiving = self.reading = False
        self.read_remaining = 0
        self.private_go = bytearray(wire.GO_LENGTH)  # Original backing before any read.

    def request(self) -> wire.Request:
        self._owner()
        wire.require(self.initial is None and not self.request_returned and not self.active)
        while True:
            self.guard.check()
            if b"\n" in self.buffer:
                wire.require(len(self.buffer) <= wire.REQUEST_LIMIT and self.buffer.endswith(b"\n")
                             and self.buffer.count(b"\n") == 1)
                raw = bytes(self.buffer)
                self.buffer.clear()
                break
            wire.require(self.fd is not None)
            select.select([self.fd], [], [], min(0.05, max(0.0, self.work_end - time.monotonic())))
        request = wire.parse_request(raw)
        raw_clock = getattr(time, "CLOCK_UPTIME_RAW", None)
        wire.require(type(raw_clock) is int)
        before = time.monotonic()
        now = time.clock_gettime_ns(raw_clock)
        wire.require(type(now) is int and 0 <= now < request.work_end_ns < request.hard_end_ns)
        # Native admitted T/W/H are the only authority. Child-local bounds may
        # only shorten them; generation/save/readback never renew a window.
        self.work_end = min(self.work_end, math.nextafter(before + (request.work_end_ns - now) / 1e9, -math.inf))
        self.hard_end = min(self.hard_end, math.nextafter(before + (request.hard_end_ns - now) / 1e9, -math.inf))
        self.initial, self.request_returned = request, True
        self.active = self.material_pending = True
        self.guard.check()
        return request

    def bind_operation(self, operation) -> None:
        from .desktop_upload_key import UploadKeyOperation
        self._owner()
        wire.require(type(operation) is UploadKeyOperation and self.operation is None
                     and self.initial is operation.request and operation.source is self
                     and operation.guard is self.guard and self.guard is not None
                     and self.guard._saved_command_input() is self and not self.ready_sent)
        self.operation = operation

    def require_operation(self):
        from .desktop_upload_key import UploadKeyOperation
        self._owner()
        wire.require(type(self.operation) is UploadKeyOperation and self.operation.source is self
                     and self.operation.guard is self.guard)
        return self.operation

    def ready(self) -> bytes:
        self._owner()
        wire.require(not self.ready_sent and self.material_pending and not self.material_receiving)
        self.require_operation().source_post()
        self.guard.check()
        wire.require(not self.buffer)
        self.ready_sent = True
        return wire.ready(self.initial)

    def go(self) -> None:
        self._owner()
        wire.require(self.ready_sent and not self.go_claimed and self.material_pending)
        self.go_claimed = self.material_receiving = self.reading = True  # One attempt even if malformed/interrupted.
        at = 0
        while at < wire.GO_LENGTH:
            self.read_remaining = wire.GO_LENGTH - at
            self.guard.check()
            if self.buffer:
                wire.require(len(self.buffer) <= self.read_remaining)
                size = len(self.buffer)
                self.private_go[at:at + size] = self.buffer
                self.buffer[:] = b"\0" * size
                self.buffer.clear()
                at += size
            else:
                wire.require(self.fd is not None)
                select.select([self.fd], [], [], min(0.05, max(0.0, self.work_end - time.monotonic())))
        self.reading = self.material_receiving = False
        # The original private_go stays on this source even if construction or
        # validation loses its return. No secret ever enters a public parser.
        self.passwords = wire.Passwords(self.private_go, self.initial)
        self.material_pending = False
        self.go_returned = True
        self.require_operation().source_post()
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
        wire.require(self.go_returned and self.active and not self.material_pending
                     and operation.pending in ("generate", "export") and operation.admitted == operation.pending
                     and capture is True and output_limit == wire.COMMAND_OUTPUT_LIMIT)
        maximum = wire.EXPORT_SECONDS if operation.pending == "export" else wire.COMMAND_SECONDS
        wire.require(type(timeout) is int and 0 < timeout <= maximum)
        return self.remaining_timeout(timeout), wire.COMMAND_OUTPUT_LIMIT

    def clear_private(self) -> None:
        if self.passwords is not None:
            self.passwords.close()
        self.private_go[:] = b"\0" * len(self.private_go)
        self.buffer[:] = b"\0" * len(self.buffer)
        self.buffer.clear()
