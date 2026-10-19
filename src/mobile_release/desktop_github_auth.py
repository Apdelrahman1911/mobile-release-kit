"""Fixed private gh capture through EXISTING C/A/W descendant ownership.

Stock gh may leave its /usr/bin/security child running on a keyring timeout.
Do not replace run_owned with subprocess.run/gh wait/EOF or the History CLI.
All source names come from the original native registration, never a public
request. Child-side snapshots are additional checks, not native admission.
"""
from __future__ import annotations

import hashlib
import os
import select
import sys
import time
from dataclasses import dataclass

from . import _desktop_github_auth_protocol as wire
from ._desktop_github_auth_control import GhAuthInput
from ._desktop_saved_command_engine import _Output, _SavedCommandEngine
from .cancellation import CleanupScope, DefaultCancellation
from .owned_process import ProcessCleanupError, ProcessError, run_owned

_RETAINED = []


@dataclass(slots=True, repr=False)
class _Original:
    snapshot: wire.FileSnapshot
    fd: int | None = None
    entered: bool = False
    close_claimed: bool = False
    closed: bool = False
    unknown: bool = False


class GhAuthOperation:
    def __init__(self, request: wire.Request, source: GhAuthInput, guard: DefaultCancellation) -> None:
        wire.require(type(request) is wire.Request and type(source) is GhAuthInput and type(guard) is DefaultCancellation)
        self.request, self.source, self.guard = request, source, guard
        self.originals = [_Original(snapshot) for snapshot in (request.tool, *request.files)]
        self.entered = self.command_admitted = self.returned = self.closed = self.unknown = False
        self.output: bytes | None = None
        source.bind_operation(self)  # Before acquisition can lose its return.

    def checkpoint(self) -> None:
        self.source._owner()
        self.guard.check()
        wire.require(not self.closed and not self.unknown and time.monotonic() < self.source.work_end)
        wire.require((os.getuid(), os.geteuid(), os.getgid(), os.getegid()) ==
                     (self.request.uid, self.request.uid, self.request.gid, self.request.gid))

    def _check(self, original: _Original) -> None:
        self.checkpoint()
        wire.require(original.fd is not None and not original.close_claimed and not original.unknown)
        expected = original.snapshot
        wire.require(wire.identity(os.fstat(original.fd)) == expected.identity
                     and wire.identity(os.stat(expected.path, follow_symlinks=False)) == expected.identity)
        os.lseek(original.fd, 0, os.SEEK_SET)
        digest, count = hashlib.sha256(), 0
        while True:
            self.checkpoint()
            block = os.read(original.fd, min(32768, expected.identity[6] + 1 - count))
            if not block:
                break
            count += len(block)
            wire.require(count <= expected.identity[6])
            digest.update(block)
        wire.require(count == expected.identity[6] and digest.hexdigest() == expected.sha256
                     and wire.identity(os.fstat(original.fd)) == expected.identity
                     and wire.identity(os.stat(expected.path, follow_symlinks=False)) == expected.identity)
        self.checkpoint()

    def admit(self) -> None:
        self.checkpoint()
        for original in self.originals:
            wire.require(not original.entered)
            original.entered = True
            try:
                original.fd = os.open(original.snapshot.path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
            except OSError:
                original.closed = True  # Returned failed open owns no descriptor.
                raise wire.ProtocolError("The registered gh source could not be opened") from None
            except BaseException:
                original.unknown = self.unknown = True
                raise
            self._check(original)

    def source_post(self) -> None:
        self.checkpoint()
        for original in self.originals:
            self._check(original)

    def command_arguments(self, argv, *, environ, cwd, capture, text, output_limit, on_start,
                          cleanup, execution_scope, journal_binding, evidence) -> None:
        """Called by the original run_owned GhAuth seam before its C/A/W call."""
        self.checkpoint()
        wire.require(self.entered and not self.command_admitted and not self.returned and self.source.go_returned
                     and type(argv) in (tuple, list) and tuple(argv) == self.request.arguments()
                     and type(environ) is dict and environ == self.request.environment() and cwd == self.request.home
                     and capture is True and text is False and output_limit == wire.COMMAND_OUTPUT_LIMIT
                     and on_start is None and cleanup is False and execution_scope is None and journal_binding is None
                     and evidence is None)
        self.command_admitted = True  # Even a subsequent startup failure spends it.

    def run(self) -> None:
        self.source_post()
        wire.require(self.source.go_returned and not self.entered)
        self.entered = True
        try:
            result = run_owned(self.request.arguments(), environ=self.request.environment(), cwd=self.request.home,
                               timeout=self.source.remaining_timeout(wire.COMMAND_SECONDS), capture=True, text=False,
                               output_limit=wire.COMMAND_OUTPUT_LIMIT, cancellation=self.guard)
            # Unchanged run_owned returns ONLY after its actual C/A/W finality,
            # original group retirement and unconditional cleanup. Not gh EOF.
            self.returned = True
            wire.require(self.command_admitted and type(result.stdout) is bytes and type(result.stderr) is bytes
                         and result.returncode == 0 and not result.stderr)
            limit = 1024 if self.request.role == "version" else wire.TOKEN_LIMIT
            wire.require(0 < len(result.stdout) <= limit)
            self.source_post()
            self.output = result.stdout
        except ProcessError as error:
            self.unknown = self.unknown or error.fatal
            raise
        except BaseException:
            # Original cancellation ledger retains any lost/interrupted command.
            self.unknown = self.unknown or self.guard.lifetime_ledger.fatal
            raise

    def cleanup(self) -> None:
        first = None
        for original in reversed(self.originals):
            if original.close_claimed or not original.entered:
                continue
            original.close_claimed = True
            number, original.fd = original.fd, None  # Retire BEFORE sole close.
            if original.unknown:
                self.unknown = True
                continue
            if number is None:
                if not original.closed:
                    self.unknown = True
                continue
            try:
                os.close(number)
                original.closed = True
            except BaseException as error:
                original.unknown = self.unknown = True
                self.guard._abort(error)
                if first is None:
                    first = error
        self.closed = not self.unknown and all(not item.entered or item.closed for item in self.originals)
        if first is not None:
            raise first


class _Engine:
    # Same actual fixed inherited-FD acquisition and one-attempt close owners.
    _acquire_output = _SavedCommandEngine._acquire_output
    close_output = _SavedCommandEngine.close_output
    _require = staticmethod(wire.require)

    def __init__(self, started: float) -> None:
        self.guard = DefaultCancellation(ProcessCleanupError, "The original gh-auth capture did not settle")
        self.input = GhAuthInput(started)
        self.output, self.error_output = _Output(1), _Output(2)
        self.request = self.operation = self.primary = None
        self.frames = self.output_bytes = 0
        self.terminal_claimed = False

    def cleanup(self) -> None:
        first = None
        operation = self.operation or self.input.operation
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
                end = min(end, self.input.first_failure + wire.FINALITY_SECONDS - wire.WORK_SECONDS)
            wire.require(time.monotonic() < end and self.output.owned and not self.output.close_claimed)
            value = os.fstat(1)
            wire.require((value.st_dev, value.st_ino, value.st_mode) == self.output.identity)
            try:
                count = os.write(1, view[:4096])
                wire.require(type(count) is int and 0 < count <= min(len(view), 4096))
                view = view[count:]
            except BlockingIOError:
                select.select([], [1], [], min(0.05, max(0.0, end - time.monotonic())))

    def run(self) -> None:
        self.guard.install()
        self.input.acquire()
        self.guard._install_saved_command_source(self.input)
        self._acquire_output(self.output)
        self._acquire_output(self.error_output)
        self.guard.activate()
        self.request = self.input.request()
        self.operation = GhAuthOperation(self.request, self.input, self.guard)
        self.operation.admit()
        self.write(self.input.ready())
        self.input.go()
        self.operation.run()

    def terminal(self) -> None:
        operation = self.operation
        wire.require(self.request is not None and operation is not None and self.frames == 1)
        known = (operation.closed and not operation.unknown and not self.guard.lifetime_ledger.fatal
                 and self.input.closed and self.guard.handler_state == "RESTORED")
        status, output = "refused", b""
        if not known:
            status = "cleanup-unknown"
        elif self.input.stop_reason != "none" or self.guard.cancelled:
            status = "timed-out" if self.input.stop_reason == "timed-out" else "cancelled"
        elif self.primary is None and operation.entered and operation.command_admitted and operation.returned and operation.output is not None:
            status, output = "ok", operation.output
        self.write(wire.terminal(self.request, status, output), terminal=True)
        operation.output = None


def main(*, started: float) -> int:
    engine = _Engine(started)
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
