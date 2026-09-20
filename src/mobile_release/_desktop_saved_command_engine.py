"""One original held-input/output engine for two fixed saved-command domains.

Native admission still owns original T/W/H, document lifetime, held request
STOP and every original wait/IO/task join. A terminal is provisional core DATA.
No generic service factory, supplied callback or command descriptor is accepted.
"""
from __future__ import annotations

import os
import select
import stat
import sys
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

from ._desktop_saved_command_control import SavedCommandDomain, _protocol, source_domain
from .cancellation import CleanupScope, DefaultCancellation
from .owned_process import ProcessCleanupError

if TYPE_CHECKING:
    from ._desktop_android_build_protocol import AndroidBuildRequest
    from ._desktop_preflight_protocol import PreflightRequest
    from .desktop_android_build import AndroidBuildRun
    from .desktop_preflight import OfflinePreflightRun

_RETAINED: list[_SavedCommandEngine] = []


@dataclass
class _Output:
    number: int
    owned: bool = False
    identity: tuple[int, int, int] | None = None
    close_claimed: bool = False
    closed: bool = False


class _SavedCommandEngine:
    def __init__(self, started: float, *, domain: SavedCommandDomain) -> None:
        _protocol(domain)  # Reject a third domain before constructing owners.
        self._domain = domain
        self.started = started
        message = ("Saved offline preflight custody did not settle"
                   if domain is SavedCommandDomain.OfflinePreflight else "Saved Android build custody did not settle")
        self.guard = DefaultCancellation(ProcessCleanupError, message)
        if domain is SavedCommandDomain.OfflinePreflight:
            from ._desktop_preflight_control import PreflightInput
            self.input = PreflightInput(started)
        else:
            from ._desktop_android_build_control import AndroidBuildInput
            self.input = AndroidBuildInput(started)
        self.output, self.error_output = _Output(1), _Output(2)
        self.request: PreflightRequest | AndroidBuildRequest | None = None
        self.service: OfflinePreflightRun | AndroidBuildRun | None = None
        self.primary: BaseException | None = None
        self.frames = self.output_bytes = 0
        self.terminal_claimed = False
        self._android_handoff_close_claimed = False
        self._android_frames = None
        if domain is SavedCommandDomain.AndroidBuild:
            self.input._bind_engine(self)

    @property
    def domain(self) -> SavedCommandDomain:
        return self._domain

    def _require(self, condition: bool) -> None:
        _protocol(self.domain).require(condition)

    def _acquire_output(self, slot: _Output) -> None:
        self._require(not slot.owned and not slot.close_claimed)
        slot.owned = True  # Fixed inherited endpoint, registered before effects.
        value = os.fstat(slot.number)
        self._require(stat.S_ISFIFO(value.st_mode))
        slot.identity = (value.st_dev, value.st_ino, value.st_mode)
        os.set_blocking(slot.number, False)

    def remember(self, error: BaseException) -> None:
        self.input.failure_observed()
        if self.primary is None:
            self.primary = error
        if self.service is not None:
            self.service.remember(error)
        else:
            self.guard.lifetime_ledger._remember(error)

    def cleanup(self) -> None:
        first: BaseException | None = None
        # These are fixed original cleanup owners, not arbitrary hooks. A
        # service constructor can bind the Android operation before losing its
        # return; settle that same operation before retiring its input source.
        if self.service is not None:
            try:
                self.service.close()
            except BaseException as error:
                first = error
                self.guard._abort(error)
        elif (self.domain is SavedCommandDomain.AndroidBuild and self.input.operation is not None
              and not self._android_handoff_close_claimed):
            self._android_handoff_close_claimed = True
            try:
                self.input.require_operation().close()
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
        wire = _protocol(self.domain)
        self._require(type(raw) is bytes and not self.terminal_claimed
                      and self.output_bytes + len(raw) <= wire.RESPONSE_LIMIT)
        if self.domain is SavedCommandDomain.OfflinePreflight:
            self._require(self.frames == (1 if terminal else 0))
        else:
            # Preserve a slot for the one terminal. The original Android DATA
            # encoder separately enforces accepted/stage/terminal sequencing.
            self._require(1 <= self.frames < wire.MAX_FRAMES if terminal else self.frames < wire.MAX_FRAMES - 1)
        self.terminal_claimed = terminal
        self.frames += 1
        self.output_bytes += len(raw)
        remaining = memoryview(raw)
        while remaining:
            if not terminal:
                self.guard.check()
            endpoint = self.started + (wire.FINALITY_SECONDS if terminal else wire.WORK_SECONDS)
            if terminal and self.input.first_failure is not None:
                endpoint = min(endpoint, self.input.first_failure + 10)
            self._require(time.monotonic() < endpoint)
            self._require(self.output.owned and not self.output.close_claimed)
            value = os.fstat(1)
            self._require((value.st_dev, value.st_ino, value.st_mode) == self.output.identity)
            try:
                count = os.write(1, remaining[:4096])
                self._require(type(count) is int and 0 < count <= min(4096, len(remaining)))
                remaining = remaining[count:]
            except BlockingIOError:
                select.select([], [1], [], 0.05)

    def _response(self, kind: str, payload: dict) -> bytes:
        wire = _protocol(self.domain)
        if self.domain is SavedCommandDomain.OfflinePreflight:
            return wire.response(self.request, kind, payload)
        self._require(type(self._android_frames) is wire.AndroidBuildFrames)
        return self._android_frames.response(kind, payload)

    def _progress(self, source, stage: str) -> None:
        self._require(self.domain is SavedCommandDomain.AndroidBuild)
        from .desktop_android_build import AndroidBuildRun
        self._require(source_domain(source) is SavedCommandDomain.AndroidBuild and self.input is source
                      and source._engine is self and self.guard._saved_command_input() is source
                      and self.request is not None and type(self.service) is AndroidBuildRun
                      and self.service.request is self.request and self.service.source is source
                      and self.service.guard is self.guard and self.service.operation is source.require_operation())
        self.write(self._response("progress", {"schemaVersion": 1, "stage": stage}))

    def run(self) -> None:
        self._require(source_domain(self.input) is self.domain)
        self.guard.install()
        self.input.acquire()
        if self.domain is SavedCommandDomain.OfflinePreflight:
            self.guard._install_preflight_source(self.input)
        else:
            self.guard._install_android_build_source(self.input)
        self._acquire_output(self.output)
        self._acquire_output(self.error_output)
        self.guard.activate()
        self.request = self.input.request()
        if self.domain is SavedCommandDomain.OfflinePreflight:
            from .desktop_preflight import OfflinePreflightRun
            self.service = OfflinePreflightRun(self.request, self.guard, self.input)
        else:
            from ._desktop_android_build_protocol import AndroidBuildFrames
            from .desktop_android_build import AndroidBuildRun
            self._require(self._android_frames is None)
            self._android_frames = AndroidBuildFrames(self.request)
            self.service = AndroidBuildRun(self.request, self.guard, self.input)
        self.write(self._response("accepted", {"schemaVersion": 1, "context": dict(self.request.context)}))
        self.service.run()

    def terminal(self) -> None:
        self._require(self.request is not None and self.service is not None)
        self.write(self._response("terminal", self.service.terminal()), terminal=True)

    def close_output(self) -> None:
        first: BaseException | None = None
        for slot in (self.error_output, self.output):
            if not slot.owned or slot.close_claimed:
                continue
            slot.close_claimed = True
            try:
                value = os.fstat(slot.number)
                self._require(slot.identity is not None
                              and (value.st_dev, value.st_ino, value.st_mode) == slot.identity)
                os.close(slot.number)  # One original attempt, never numeric retry.
                slot.closed = True
            except BaseException as error:
                self.input.failure_observed()  # Input may already be removed; F still belongs to this engine.
                self.guard._abort(error)
                if first is None:
                    first = error
        if first is not None:
            raise first

    def _service_resources_closed(self) -> bool:
        if self.domain is SavedCommandDomain.OfflinePreflight:
            return self.service is None or self.service.budget.closed
        if self.service is None and self.input.operation is None:
            # A constructor's lost handoff must not discard an already-bound
            # original operation, even though no terminal can then be emitted.
            return True
        operation = self.input.require_operation()
        self._require(self.service is None or self.service.operation is operation)
        closed = operation.closed()
        self._require(type(closed) is bool)
        return closed

    def retain_unknown(self) -> None:
        try:
            incomplete = (self.guard.lifetime_ledger.fatal or not self.input.closed
                          or not self._service_resources_closed()
                          or any(slot.owned and not slot.closed for slot in (self.output, self.error_output)))
        except BaseException as error:
            self.guard._abort(error)
            incomplete = True
        if incomplete and self not in _RETAINED:
            _RETAINED.append(self)


def run_engine(engine: _SavedCommandEngine) -> int:
    if engine.domain is SavedCommandDomain.OfflinePreflight:
        from ._desktop_preflight_engine import _Engine as ExpectedEngine
    elif engine.domain is SavedCommandDomain.AndroidBuild:
        from ._desktop_android_build_engine import _Engine as ExpectedEngine
    else:
        raise ValueError("Invalid original saved-command engine")
    if type(engine) is not ExpectedEngine:
        raise ValueError("Invalid original saved-command engine")
    scope = CleanupScope(engine.guard, engine.cleanup, owns_cancellation=True, first_primary=True)
    try:
        try:
            try:
                with scope:
                    try:
                        engine.run()
                    except BaseException as error:
                        try:
                            # Even a failure before source installation has an
                            # original F; service primary precedes its cleanup.
                            engine.remember(error)
                        except BaseException as diagnostic:
                            engine.guard._abort(diagnostic)
                        raise
            finally:
                scope.__exit__(*sys.exc_info())  # Required even if with-exit dispatch loses its return.
        except BaseException as error:
            engine.remember(error)
        engine.terminal()
        engine.close_output()
        engine.retain_unknown()
        return 0  # Typed negative/unknown is not a successful whole native run.
    except BaseException as error:
        try:
            engine.remember(error)  # F precedes even output-only cleanup.
        except BaseException as diagnostic:
            engine.guard._abort(diagnostic)
        try:
            engine.close_output()
        except BaseException:
            pass  # No replay of an already claimed descriptor close.
        engine.retain_unknown()
        return 78
