"""Dedicated original diagnostics child; ordinary owned commands may descend.

Neither passive Supervisor nor EditOwner may run this engine. Native admission
owns original T/W/H, document lifetime, request-writer STOP and all wait/IO/task
joins. A terminal frame is only provisional core DATA until those joins settle.
"""
from __future__ import annotations

import os
import select
import stat
import sys
import time
from dataclasses import dataclass

from ._desktop_environment_control import EnvironmentInput
from ._desktop_environment_protocol import (FINALITY_SECONDS, PROFILES, RESPONSE_LIMIT, WORK_SECONDS,
    EnvironmentRequest, ProtocolError, require, response)
from .cancellation import CleanupScope, DefaultCancellation
from .environment_diagnostics import DiagnosticsRun
from .owned_process import ProcessCleanupError

_RETAINED: list[_Engine] = []


@dataclass
class _Output:
    number: int
    owned: bool = False
    identity: tuple[int, int, int] | None = None
    close_claimed: bool = False
    closed: bool = False


class _Engine:
    def __init__(self, started: float) -> None:
        self.started = started
        self.guard = DefaultCancellation(ProcessCleanupError, "Environment diagnostics custody did not settle")
        self.input = EnvironmentInput(started)
        self.output, self.error_output = _Output(1), _Output(2)
        self.request: EnvironmentRequest | None = None
        self.service: DiagnosticsRun | None = None
        self.primary: BaseException | None = None
        self.frames = self.output_bytes = 0

    def _acquire_output(self, slot: _Output) -> None:
        require(not slot.owned and not slot.close_claimed)
        slot.owned = True  # Fixed inherited endpoint, registered before effects.
        value = os.fstat(slot.number)
        require(stat.S_ISFIFO(value.st_mode))
        slot.identity = (value.st_dev, value.st_ino, value.st_mode)
        os.set_blocking(slot.number, False)

    def remember(self, error: BaseException) -> None:
        if self.primary is None:
            self.primary = error
        if self.service is not None:
            self.service.remember(error)
        else:
            self.guard.lifetime_ledger._remember(error)

    def cleanup(self) -> None:
        first: BaseException | None = None
        # These are the only two original cleanup owners, not arbitrary hooks.
        if self.service is not None:
            try:
                self.service.close()
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

    def write(self, raw: bytes, *, terminal: bool = False) -> None:
        require(type(raw) is bytes and self.frames == (1 if terminal else 0)
            and self.output_bytes + len(raw) <= RESPONSE_LIMIT)
        self.frames += 1
        self.output_bytes += len(raw)
        remaining = memoryview(raw)
        while remaining:
            if not terminal:
                self.guard.check()
            require(time.monotonic() < self.started + (FINALITY_SECONDS if terminal else WORK_SECONDS))
            require(self.output.owned and not self.output.close_claimed)
            value = os.fstat(1)
            require((value.st_dev, value.st_ino, value.st_mode) == self.output.identity)
            try:
                count = os.write(1, remaining[:4096])
                require(type(count) is int and 0 < count <= min(4096, len(remaining)))
                remaining = remaining[count:]
            except BlockingIOError:
                select.select([], [1], [], 0.05)

    def run(self) -> None:
        self.guard.install()
        self.input.acquire()
        self.guard._install_environment_source(self.input)
        self._acquire_output(self.output)
        self._acquire_output(self.error_output)
        self.guard.activate()
        self.request = self.input.request()
        self.service = DiagnosticsRun(self.request, self.guard, self.input)
        self.write(response(self.request, "accepted", {"schemaVersion": 1, "context": dict(self.request.context),
            "hostPlatform": PROFILES[self.request.native["profile"]][0]}))
        self.service.run()

    def terminal(self) -> None:
        require(self.request is not None and self.service is not None)
        self.write(response(self.request, "terminal", self.service.terminal()), terminal=True)

    def close_output(self) -> None:
        first: BaseException | None = None
        for slot in (self.error_output, self.output):
            if not slot.owned or slot.close_claimed:
                continue
            slot.close_claimed = True
            try:
                value = os.fstat(slot.number)
                require(slot.identity is not None and (value.st_dev, value.st_ino, value.st_mode) == slot.identity)
                os.close(slot.number)  # One original attempt, never numeric retry.
                slot.closed = True
            except BaseException as error:
                self.guard._abort(error)
                if first is None:
                    first = error
        if first is not None:
            raise first

    def retain_unknown(self) -> None:
        if (self.guard.lifetime_ledger.fatal or not self.input.closed
                or self.service is not None and not self.service.lookup.closed
                or any(slot.owned and not slot.closed for slot in (self.output, self.error_output))):
            if self not in _RETAINED:
                _RETAINED.append(self)


def main(*, started: float) -> int:
    engine = _Engine(started)
    scope = CleanupScope(engine.guard, engine.cleanup, owns_cancellation=True, first_primary=True)
    try:
        try:
            try:
                with scope:
                    engine.run()
            finally:
                scope.__exit__(*sys.exc_info())  # Required even if with-exit dispatch loses its return.
        except BaseException as error:
            engine.remember(error)
        engine.terminal()
        engine.close_output()
        engine.retain_unknown()
        return 0  # Typed negative/unknown is not a successful whole native run.
    except BaseException:
        try:
            engine.close_output()
        except BaseException:
            pass  # No replay of an already claimed descriptor close.
        engine.retain_unknown()
        return 78
