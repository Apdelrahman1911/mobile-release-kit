"""Default-signal ownership for fixed, non-yielding resource cleanup.

This is not a public cancellation API or a global lifetime/concurrency lease.
Every caller must arm an unconditional outer finally around its CleanupScope:
normal with-exit dispatch can be interrupted before __exit__ has a frame.
"""
from __future__ import annotations

import signal
import threading
from collections.abc import Callable
from contextlib import contextmanager
from types import FrameType, TracebackType
from typing import Any


class DefaultCancellation:
    """Share nested deferral; leave custom handlers and worker threads alone."""

    def __init__(self, restore_error: type[Exception], restore_message: str) -> None:
        self.depth = 1
        self.cancelled = False
        self.previous: dict[int, Any] = {}
        self.restore_error = restore_error
        self.restore_message = restore_message

    def interrupt(self, signum: int, frame: FrameType | None) -> None:
        already_cancelled = self.cancelled
        self.cancelled = True
        if self.depth or already_cancelled:
            return
        # Only fixed executing cleanup code, never an entire setup/yield
        # generator: deferring at a late yield could enter a cancelled build.
        while frame is not None:
            if frame.f_code is CleanupScope.__exit__.__code__:
                return
            frame = frame.f_back
        raise KeyboardInterrupt

    def install(self) -> None:
        if threading.current_thread() is threading.main_thread():
            # Own catchable INT first, before acquiring resources. Its original
            # handler must also be restored LAST, after still-owned TERM.
            for signum, default in ((signal.SIGINT, signal.default_int_handler), (signal.SIGTERM, signal.SIG_DFL)):
                previous = signal.getsignal(signum)
                if previous == default:
                    self.previous[signum] = previous
                    signal.signal(signum, self.interrupt)

    def activate(self) -> None:
        self.depth -= 1
        self.check()

    def check(self) -> None:
        if self.cancelled:
            raise KeyboardInterrupt

    @contextmanager
    def deferred(self, *, check_on_exit: bool = True):
        self.depth += 1
        try:
            yield
        finally:
            self.depth -= 1
        # Do not mask an active error or end an enclosing acquisition's deferral.
        if check_on_exit and not self.depth:
            self.check()

    def restore(self) -> None:
        self.depth += 1
        failed = False
        for signum, previous in reversed(self.previous.items()):
            try:
                signal.signal(signum, previous)
            except (OSError, ValueError):
                failed = True
        if failed:
            raise self.restore_error(self.restore_message)


class CleanupScope:
    """Attempt registered cleanup once; a claimed attempt is NOT proof of success.

    Construct and enter before installing handlers or acquiring resources. In an
    unconditional outer finally call __exit__(*sys.exc_info()) again: this covers
    interrupted inner with-exit dispatch, without replaying ambiguous cleanup.
    """

    def __init__(
        self, cancellation: DefaultCancellation, cleanup: Callable[[], None], *, owns_cancellation: bool,
    ) -> None:
        self.cancellation = cancellation
        self.cleanup = cleanup
        self.owns_cancellation = owns_cancellation
        self.claimed = False

    def __enter__(self):
        return self

    def __exit__(
        self, exception_type: type[BaseException] | None, error: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool:
        if self.claimed:
            return False
        self.claimed = True
        try:
            with self.cancellation.deferred(check_on_exit=False):
                self.cleanup()
        finally:
            if self.owns_cancellation:
                self.cancellation.restore()
        # Restoration itself can record cancellation. Check AFTER it, only on
        # normal completion: original/cleanup/restore errors retain precedence.
        if self.owns_cancellation and exception_type is None:
            self.cancellation.check()
        return False
