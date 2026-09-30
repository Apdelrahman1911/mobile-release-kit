"""The dedicated engine's sole main-thread unbuffered stdin/EOF owner.

No competing reader, signal-by-PID, inherited extra pipe, worker, callback, or
reconnect. Active work treats both prefetched leftovers and readable OS bytes
as STOP. Fixed cleanup calls poll() only, never a cancelled ordinary check().
"""
from __future__ import annotations

import os
import select
import stat
import sys
import threading
import time
from typing import TYPE_CHECKING

from ._desktop_edit_protocol import (EditRequest, ProtocolError, PROTOCOL, WORKFLOW_PROTOCOL,
                                     METADATA_PROTOCOL, VERSION_PROTOCOL, IMAGES_PROTOCOL,
                                     VERSION_REQUEST_LIMIT, REQUEST_LIMIT, parse_request)

if TYPE_CHECKING:
    from .cancellation import DefaultCancellation


class EditInput:
    def __init__(self, started: float, *, protocol: str = PROTOCOL, _windows_stdio: object | None = None) -> None:
        if type(protocol) is not str or protocol not in {PROTOCOL, WORKFLOW_PROTOCOL, METADATA_PROTOCOL, VERSION_PROTOCOL, IMAGES_PROTOCOL}:
            raise ProtocolError("Invalid fixed edit domain")
        self.protocol = protocol
        self.request_limit = VERSION_REQUEST_LIMIT if protocol == VERSION_PROTOCOL else REQUEST_LIMIT
        if protocol == IMAGES_PROTOCOL:
            from ._desktop_images_protocol import request_limit
            self.request_limit = request_limit(0)
        self.pid = os.getpid()
        self.thread = threading.current_thread()
        self.started = started
        self.review_end = started + 900.0
        self.active_end: float | None = started + 30.0
        self.apply_active = False
        self.guard: DefaultCancellation | None = None
        self.fd: int | None = None
        self.identity: tuple[int, int, int] | None = None
        self.acquired = False
        self.close_claimed = False
        self.closed = False
        self.active = False
        self.stopped = False
        self.custody_unknown = False
        self.buffer = bytearray()
        self.frames = 0
        self._windows_stdio = _windows_stdio
        self._startup_guard: DefaultCancellation | None = None
        self.cleanup_start: float | None = None
        self.soft_end: float | None = None
        self.hard_end: float | None = None
        self._terminal_end: float | None = None
        if _windows_stdio is not None:
            if sys.platform != "win32" or protocol != IMAGES_PROTOCOL:
                raise ProtocolError("Only the original Windows image input has this transport")
            _windows_stdio._bind_input(self)

    def _owner(self) -> None:
        if (self.pid != os.getpid() or self.thread is not threading.current_thread()
                or self.thread is not threading.main_thread()):
            raise ProtocolError("Edit input belongs to its original main thread")

    def acquire(self) -> None:
        self._owner()
        if self.acquired or self.fd is not None or self.close_claimed:
            raise ProtocolError("Edit input cannot be reacquired")
        if self._windows_stdio is not None:
            # The bootstrap already retired the exact supplier wrappers and
            # claimed fixed native channels. This SAME Input owns the handoff.
            self.fd = 0  # fixed role marker, never passed to os.read/close here
            self._windows_stdio.handoff()
            self.acquired = True
            return
        # fd 0 is the bootstrap's fixed original stdin, not a renderer/discovered
        # descriptor. Claim it before the first fallible native inspection.
        self.fd = 0
        value = os.fstat(self.fd)
        if not stat.S_ISFIFO(value.st_mode):
            raise ProtocolError("Edit stdin must be the original pipe")
        self.identity = (value.st_dev, value.st_ino, value.st_mode)
        os.set_blocking(self.fd, False)
        self.acquired = True

    def bind(self, guard: DefaultCancellation) -> None:
        from .cancellation import DefaultCancellation
        self._owner()
        if type(guard) is not DefaultCancellation or self.guard is not None or not self.acquired:
            raise ProtocolError("Invalid edit input binding")
        guard._check_owner()
        if self._windows_stdio is not None and guard is not self._startup_guard:
            raise ProtocolError("The original image cancellation guard changed")
        self.guard = guard

    def _stop(self) -> None:
        if self._windows_stdio is not None:
            self._image_cleanup_started()
        self.stopped = True
        if self.guard is not None:
            self.guard.cancelled = True

    def poll(self, guard: DefaultCancellation) -> None:
        self._owner()
        if guard is not self.guard:
            raise ProtocolError("Invalid edit input owner")
        if self.stopped or self.close_claimed:
            if self.stopped:
                guard.cancelled = True
            return
        now = time.monotonic()
        if ((not self.apply_active and now >= self.review_end)
                or self.active_end is not None and now >= self.active_end):
            self._stop()
            return
        if self.active and self.buffer:
            self._stop()
            return
        try:
            if self.fd is None:
                raise ProtocolError("Edit input is not acquired")
            limit = 1 if self.active else min(64 * 1024, self.request_limit + 1 - len(self.buffer))
            if limit <= 0:
                raise ProtocolError("Edit input exceeded its bound")
            if self._windows_stdio is not None:
                chunk = self._windows_stdio.read_available(limit)
                if chunk is None:  # Pending OR successful zero-byte completion, not EOF.
                    return
            else:
                value = os.fstat(self.fd)
                if (value.st_dev, value.st_ino, value.st_mode) != self.identity:
                    self.custody_unknown = True
                    guard._abort(ProtocolError("Original edit input custody changed"))
                    raise ProtocolError("Original edit input changed")
                try:
                    chunk = os.read(self.fd, limit)
                except BlockingIOError:
                    return
            if not chunk or self.active:
                self._stop()
                return
            self.buffer.extend(chunk)
            if self.active_end is None:
                self.active_end = now + 30.0  # A partial request cannot hold review open.
            if len(self.buffer) > self.request_limit:
                self._stop()
        except BaseException as error:
            # Read errors and identity uncertainty are STOP, never EOF/finality.
            if self._windows_stdio is not None and self._windows_stdio._lost_custody():
                self.custody_unknown = True
                guard._abort(error)
            # A validated native per-operation Unknown remains sticky in the
            # SAME stdio owner. It STOPs producing; it does not invent a lost
            # Python/ABI custody fact that would strand unaffected siblings.
            self._stop()

    def request(self, sequence: int, session: str | None) -> EditRequest:
        self._owner()
        if self.guard is None or self.active or self.frames >= 3:
            raise ProtocolError("No next edit request is legal")
        while True:
            self.guard.check()
            position = self.buffer.find(b"\n")
            if position >= 0:
                # Copy just the admitted frame once, not a full bytearray slice
                # followed by bytes. Both views release before the sole buffer
                # is mutated; prefetched data keeps the same STOP semantics.
                with memoryview(self.buffer) as buffered:
                    with buffered[:position + 1] as frame:
                        raw = frame.tobytes()
                del self.buffer[:position + 1]
                # The sole reader becomes the exact active cancellation source
                # before parsing/acceptance. This catches prefetched frame 2 as
                # well as newly readable OS bytes/EOF before any native effect.
                self.active = True
                self.guard.check()
                request = parse_request(raw, sequence=sequence, session=session, protocol=self.protocol)
                self.guard.check()
                self.frames += 1
                if self.protocol == IMAGES_PROTOCOL:
                    from ._desktop_images_protocol import request_limit
                    self.request_limit = request_limit(self.frames)
                self.apply_active = request.op == "apply"
                if sequence != 0:
                    self.active_end = time.monotonic() + 30.0
                return request
            if self.fd is None:
                raise ProtocolError("Original edit input is unavailable")
            if self._windows_stdio is not None:
                self._windows_stdio._pause()
                continue
            try:
                select.select([self.fd], [], [], 0.2)
            except (OSError, ValueError):
                self._stop()

    def idle(self) -> None:
        self._owner()
        if self.guard is None or not self.active or self.apply_active:
            raise ProtocolError("No further idle phase is legal")
        self.guard.check()
        self.active = False
        self.active_end = None
        # Restore legal idle-input mode BEFORE publishing opened/prepared.
        self.guard.check()

    def close(self) -> None:
        self._owner()
        if self.close_claimed:
            if not self.closed:
                raise ProtocolError("Original edit input close is unknown")
            return
        self.close_claimed = True
        number, self.fd = self.fd, None
        try:
            if self.custody_unknown:
                # An observed reused/changed integer must never close a foreign
                # descriptor. Preserve uncertainty, not a numeric-close retry.
                raise ProtocolError("Original edit input custody is unknown")
            if self._windows_stdio is not None:
                self._image_cleanup_started()
                self._windows_stdio.close_role(0)
            elif number is not None:
                os.close(number)  # Once only; retired even on ambiguous error.
            self.closed = True
            if self.guard is not None:
                self.guard._remove_edit_source(self)
        except BaseException as error:
            if self._windows_stdio is not None:
                self._stop()
                if self._windows_stdio._lost_custody():
                    self.custody_unknown = True
            if self.guard is not None and (self._windows_stdio is None or self.custody_unknown):
                self.guard._abort(error)
            # The engine attempts independently rooted sibling stdio settlement
            # before generic CleanupScope records this original close failure.
            raise

    def _prepare_windows_owner(self, guard: DefaultCancellation) -> None:
        from .cancellation import DefaultCancellation
        self._owner()
        if (self._windows_stdio is None or type(guard) is not DefaultCancellation
                or self._startup_guard is not None or self.guard is not None or self.acquired):
            raise ProtocolError("The original image startup guard cannot be replaced")
        guard._check_owner()
        self._startup_guard = guard

    def _image_phase_endpoint(self) -> float:
        ends = ([self.review_end] if not self.apply_active else [])
        if self.active_end is not None:
            ends.append(self.active_end)
        if not ends:
            raise ProtocolError("The original image phase has no endpoint")
        return min(ends)

    def _image_cleanup_started(self) -> None:
        self._owner()
        if self.cleanup_start is None:
            now = time.monotonic()
            # If expiry is discovered late, spend the ORIGINAL endpoint, never
            # discovery time. STOP/failure/normal retirement cannot refresh it.
            self.cleanup_start = min(now, self._image_phase_endpoint())
            self.soft_end, self.hard_end = self.cleanup_start + 8.0, self.cleanup_start + 10.0

    def _image_endpoint(self) -> float:
        if self.hard_end is not None:
            return self.hard_end
        return self._image_phase_endpoint()

    def _image_native_boundary(self, *, settlement: bool = False, terminal: bool = False) -> None:
        self._owner()
        guard = self.guard if self.guard is not None else self._startup_guard
        if (self._windows_stdio is None or self._windows_stdio._input is not self or guard is None
                or self.custody_unknown or guard.lifetime_ledger.fatal
                or guard.handler_state not in (("ACTIVE", "RESTORED") if terminal else ("ACTIVE",))):
            raise ProtocolError("Original image guard/handler/custody is unresolved")
        guard._check_owner()
        now = time.monotonic()
        if self.cleanup_start is None and now >= self._image_phase_endpoint():
            self._stop()
        if now >= self._image_endpoint():
            raise ProtocolError("Original image hard endpoint expired")
        if not settlement and (self.cleanup_start is not None or self.stopped or self.close_claimed or guard.cancelled):
            self._stop()
            raise KeyboardInterrupt
        # No guard.check() recursion: this boundary is also used BY poll().
        # Native operations retain their return before the caller checks again.

    def _image_handoff_check(self) -> None:
        if self.guard is not None or self._startup_guard is None or self.acquired:
            raise ProtocolError("The original image handoff phase changed")
        self._startup_guard.check()  # Before source installation; no competing reader.
        self._image_native_boundary()

    def before_image_entry(self) -> None:
        if (self.guard is None or self.guard._edit_source is not self
                or not self.guard._activated or not self._windows_stdio._handoff_complete):
            raise ProtocolError("The original image producing binding is not active")
        self.guard.check()
        self._image_native_boundary()

    def before_image_settlement(self) -> None:
        if (self.guard is None or self.guard._edit_source is not self
                or not self.guard._activated or not self._windows_stdio._handoff_complete):
            raise ProtocolError("The original image settlement binding changed")
        self.guard._check_owner()
        self.guard._poll_edit_stop()  # Cooperative STOP allowed; NOT guard.check().
        self._image_native_boundary(settlement=True)

    def _image_terminal_started(self) -> None:
        if self._terminal_end is not None:
            raise ProtocolError("Original image terminal delivery cannot restart")
        self._image_cleanup_started()
        self._terminal_end = min(time.monotonic() + 2.0, self._image_endpoint())
        self._image_terminal_check()

    def _image_terminal_check(self) -> None:
        self._image_native_boundary(settlement=True, terminal=True)
        if (not self.closed or self.guard is None or self.guard.handler_state != "RESTORED"
                or self._terminal_end is None or time.monotonic() >= self._terminal_end):
            raise ProtocolError("Original image terminal delivery did not settle")
