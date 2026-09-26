"""The one held-input lifecycle for two fixed saved-command domains.

Only the exact OfflinePreflight/AndroidBuild entry types may bind. This is not
a command descriptor, extensible cancellation source or caller callback API.
The child-local endpoints can only tighten the original native T/W/H.
"""
from __future__ import annotations

import math
import os
import select
import stat
import threading
import time
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ._desktop_android_build_protocol import AndroidBuildRequest
    from ._desktop_preflight_protocol import PreflightRequest
    from .cancellation import DefaultCancellation


class SavedCommandDomain(Enum):
    OfflinePreflight = "offline-preflight"
    AndroidBuild = "android-build"


def _protocol(domain: SavedCommandDomain):
    # Fixed imports, not a module name, factory or callback supplied by a caller.
    if domain is SavedCommandDomain.OfflinePreflight:
        from . import _desktop_preflight_protocol
        return _desktop_preflight_protocol
    if domain is SavedCommandDomain.AndroidBuild:
        from . import _desktop_android_build_protocol
        return _desktop_android_build_protocol
    raise ValueError("Invalid saved-command domain")


def source_domain(source: object) -> SavedCommandDomain:
    """A subclass/lookalike or changed domain is not an original source."""
    from ._desktop_preflight_control import PreflightInput
    if type(source) is PreflightInput and source.domain is SavedCommandDomain.OfflinePreflight:
        return SavedCommandDomain.OfflinePreflight
    from ._desktop_android_build_control import AndroidBuildInput
    if type(source) is AndroidBuildInput and source.domain is SavedCommandDomain.AndroidBuild:
        return SavedCommandDomain.AndroidBuild
    raise ValueError("Invalid original saved-command input")


class _SavedCommandInput:
    def __init__(self, started: float, *, domain: SavedCommandDomain) -> None:
        self._domain = domain
        wire = _protocol(domain)
        wire.require(type(started) in {float, int} and math.isfinite(started) and started >= 0)
        self.pid = os.getpid()
        self.thread = threading.current_thread()
        self.work_end = started + wire.WORK_SECONDS
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
        self.first_failure: float | None = None

    @property
    def domain(self) -> SavedCommandDomain:
        return self._domain

    def _require(self, condition: bool) -> None:
        _protocol(self.domain).require(condition)

    def _owner(self) -> None:
        source_domain(self)
        self._require(self.pid == os.getpid() and self.thread is threading.current_thread()
                      and self.thread is threading.main_thread())

    def acquire(self) -> None:
        self._owner()
        self._require(not self.acquired and self.fd is None and not self.close_claimed)
        self.fd = 0  # Claim the fixed original standard pipe before inspection.
        value = os.fstat(0)
        self._require(stat.S_ISFIFO(value.st_mode))
        self.identity = (value.st_dev, value.st_ino, value.st_mode)
        os.set_blocking(0, False)
        self.acquired = True

    def bind(self, guard: DefaultCancellation) -> None:
        from .cancellation import DefaultCancellation
        self._owner()
        self._require(type(guard) is DefaultCancellation and self.guard is None and self.acquired)
        guard._check_owner()
        self.guard = guard

    def failure_observed(self) -> None:
        self._owner()
        if self.first_failure is None:
            self.first_failure = time.monotonic()

    def remaining_timeout(self, timeout: int) -> int:
        self._owner()
        self._require(self.guard is not None and type(timeout) is int and timeout > 0)
        self.guard.check()
        if self.domain is SavedCommandDomain.OfflinePreflight:
            if self.budget is not None:
                self.budget.checkpoint()
        else:
            self.require_operation().checkpoint()
        remaining = int(self.work_end - time.monotonic())
        if remaining < 1:
            self.stop("timed-out")
            self.guard.check()
        return min(timeout, remaining)

    def command_limits(self, timeout: int, capture: bool, output_limit: int) -> tuple[int, int]:
        """Clamp only an original domain; no change to C/A/W command ownership."""
        timeout = self.remaining_timeout(timeout)
        if self.domain is SavedCommandDomain.OfflinePreflight:
            from ._desktop_preflight_budget import budget_for
            budget = budget_for(self.guard)
            if budget is None:
                raise ValueError("Offline preflight command has no original budget")
            if capture:
                output_limit = budget.capture(output_limit)
            return timeout, output_limit
        self._require(type(capture) is bool and type(output_limit) is int and output_limit > 0)
        operation = self.require_operation()
        # Independent Android-only affirmation of the four fixed roles. This
        # is not a larger generic capture budget, nor an OfflinePreflight change.
        role = operation._pending
        maxima = {"gradle": 2700, "bundletool": 60, "jarsigner": 120, "keytool": 30}
        self._require(role in maxima and capture is (role != "gradle"))
        selected = operation.command_limits(timeout, capture, output_limit)
        self._require(type(selected) is tuple and len(selected) == 2
                      and type(selected[0]) is int and 0 < selected[0] <= min(timeout, maxima[role])
                      and type(selected[1]) is int and 0 < selected[1] <= output_limit
                      and (not capture or selected[1] <= 2 * 1024 * 1024))
        return selected

    def stop(self, reason: str = "cancelled") -> None:
        self._owner()
        self._require(type(reason) is str and reason in {"cancelled", "timed-out"})
        self.failure_observed()
        if self.stop_reason == "none":
            self.stop_reason = reason
        if self.guard is not None:
            self.guard.cancelled = True

    def poll(self, guard: DefaultCancellation) -> None:
        self._owner()
        self._require(guard is self.guard)
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
            self._require(self.fd is not None)
            value = os.fstat(self.fd)
            if (value.st_dev, value.st_ino, value.st_mode) != self.identity:
                self.custody_unknown = True
                message = ("Original preflight input changed" if self.domain is SavedCommandDomain.OfflinePreflight
                           else "Original Android build input changed")
                raise _protocol(self.domain).ProtocolError(message)
            limit = 1 if self.active else min(64 * 1024, _protocol(self.domain).REQUEST_LIMIT + 1 - len(self.buffer))
            self._require(limit > 0)
            try:
                chunk = os.read(self.fd, limit)
            except BlockingIOError:
                return
            if not chunk or self.active:
                self.stop()
                return
            self.buffer.extend(chunk)
            if len(self.buffer) > _protocol(self.domain).REQUEST_LIMIT:
                self.stop()
        except BaseException as error:
            # A read/identity failure is not successful EOF or finality. Keep
            # it on the actual guard even if closing another resource works.
            self.stop()
            guard._abort(error)

    def request(self) -> PreflightRequest | AndroidBuildRequest:
        self._owner()
        self._require(self.guard is not None and not self.active and not self.request_returned)
        while True:
            self.guard.check()
            position = self.buffer.find(b"\n")
            if position >= 0:
                raw = bytes(self.buffer[:position + 1])
                del self.buffer[:position + 1]
                self.active = True  # Leftovers and any further byte are STOP.
                self.guard.check()
                request = _protocol(self.domain).parse_request(raw)
                self.guard.check()
                self.request_returned = True
                return request
            self._require(self.fd is not None)
            try:
                select.select([self.fd], [], [], 0.05)
            except (OSError, ValueError) as error:
                self.stop()
                self.guard._abort(error)

    def close(self) -> None:
        self._owner()
        if self.close_claimed:
            self._require(self.closed)
            return
        self.close_claimed = True
        number, self.fd = self.fd, None
        try:
            self._require(not self.custody_unknown)
            if number is not None:
                value = os.fstat(number)
                # A pre-acquisition error has no validated original identity;
                # do not manufacture permission to close a possibly reused FD.
                self._require(self.identity is not None
                              and (value.st_dev, value.st_ino, value.st_mode) == self.identity)
                os.close(number)  # Retired before the sole possibly consuming call.
            self.closed = True
            if self.guard is not None:
                self.guard._remove_saved_command_source(self)
        except BaseException as error:
            self.failure_observed()
            if self.guard is not None:
                self.guard._abort(error)
            raise
