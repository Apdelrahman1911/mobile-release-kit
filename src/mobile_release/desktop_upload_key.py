"""Fixed upload-key generation through the EXISTING C/A/W process owner.

No application build/Store action, imported-key replacement, assignment,
certificate trust, native qualification or replay policy is created here.
Passwords enter only the two fixed keytool CHILD environments.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import select
import sys
import time

from . import _desktop_upload_key_jks as jks
from . import _desktop_upload_key_protocol as wire
from ._desktop_saved_command_engine import _Output, _SavedCommandEngine
from ._desktop_upload_key_control import UploadKeyInput
from ._desktop_upload_key_scratch import UploadKeyScratch
from ._desktop_upload_key_saved import UploadKeySaved
from .build_inputs import _Directory, _FD, _cleanup_failure
from .cancellation import CleanupScope, DefaultCancellation
from .owned_process import ProcessCleanupError, ProcessError, run_owned

_RETAINED = []


class UploadKeyOperation:
    def __init__(self, request: wire.Request, source: UploadKeyInput, guard: DefaultCancellation) -> None:
        wire.require(type(request) is wire.Request and type(source) is UploadKeyInput
                     and type(guard) is DefaultCancellation)
        self.request, self.source, self.guard = request, source, guard
        self.tool_parent = _Directory(request.tool.path.parent, guard)
        self.tool = _FD(guard)
        self.saved = UploadKeySaved(request.saved, guard)
        self.scratch = UploadKeyScratch(Path("/private/tmp"), request.id, guard)
        self.pending = self.admitted = None
        self.generated = self.exported = self.closed = self.unknown = False
        self.certificate = None
        self.command_result = None  # Private stdout/stderr retained, never errors/logs.
        source.bind_operation(self)

    def checkpoint(self) -> None:
        self.source._owner()
        self.guard.check()
        wire.require(sys.platform == "darwin" and not self.closed and not self.unknown
                     and time.monotonic() < self.source.work_end
                     and (os.getuid(), os.geteuid(), os.getgid(), os.getegid())
                     == (self.request.uid, self.request.uid, self.request.gid, self.request.gid))

    def _tool_check(self) -> None:
        self.checkpoint()
        self.tool_parent.check()
        wire.require(self.tool.number is not None and self.tool.close_state == "NOT_ATTEMPTED")
        expected = self.request.tool
        wire.require(wire.identity(os.fstat(self.tool.number)) == expected.identity
                     and wire.identity(os.stat(expected.path.name, dir_fd=self.tool_parent.fd,
                                               follow_symlinks=False)) == expected.identity)
        os.lseek(self.tool.number, 0, os.SEEK_SET)
        digest, count = hashlib.sha256(), 0
        while True:
            self.checkpoint()
            block = os.read(self.tool.number, min(32768, expected.identity[6] + 1 - count))
            if not block:
                break
            count += len(block)
            wire.require(count <= expected.identity[6])
            digest.update(block)
        wire.require(count == expected.identity[6] and digest.hexdigest() == expected.sha256
                     and wire.identity(os.fstat(self.tool.number)) == expected.identity
                     and wire.identity(os.stat(expected.path.name, dir_fd=self.tool_parent.fd,
                                               follow_symlinks=False)) == expected.identity)
        self.tool_parent.check()

    def admit(self) -> None:
        self.checkpoint()
        self.tool_parent.acquire()
        self.tool.open(self.request.tool.path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                       dir_fd=self.tool_parent.fd)
        self._tool_check()
        self.saved.acquire()
        self.scratch.acquire()

    def source_post(self) -> None:
        self.saved.check()
        self._tool_check()
        self.scratch.check()

    def command_arguments(self, argv, *, environ, cwd, capture, text, output_limit, on_start,
                          cleanup, execution_scope, journal_binding, evidence) -> None:
        """Only the exact original run_owned GenerateUploadKey seam calls this."""
        self.checkpoint()
        wire.require(self.source.go_returned and self.source.passwords is not None
                     and self.pending in ("generate", "export") and self.admitted is None
                     and self.scratch.file_identity is not None
                     and type(argv) in (tuple, list)
                     and tuple(argv) == self.request.arguments(self.scratch.path, export=self.pending == "export")
                     and type(environ) is dict and environ == self.source.passwords.environment(self.scratch.path)
                     and cwd == self.scratch.path and capture is True and text is False
                     and output_limit == wire.COMMAND_OUTPUT_LIMIT and on_start is None and cleanup is False
                     and execution_scope is None and journal_binding is None and evidence is None)
        wire.require((self.pending == "generate" and not self.generated and not self.exported)
                     or (self.pending == "export" and self.generated and not self.exported))
        self.source_post()
        self.admitted = self.pending  # Even a failed/unknown C/A/W startup spends this call.

    def _command(self, *, export: bool) -> None:
        self.checkpoint()
        wire.require(self.pending is None and self.admitted is None and self.source.passwords is not None)
        self.pending = "export" if export else "generate"
        try:
            self.command_result = run_owned(
                self.request.arguments(self.scratch.path, export=export),
                environ=self.source.passwords.environment(self.scratch.path), cwd=self.scratch.path,
                timeout=self.source.remaining_timeout(wire.EXPORT_SECONDS if export else wire.COMMAND_SECONDS),
                capture=True, text=False, output_limit=wire.COMMAND_OUTPUT_LIMIT, cancellation=self.guard)
            # This return is the unchanged C/A/W contract, not a bare keytool
            # exit or stdout EOF. The native M2/runtime tail is still retained.
            wire.require(self.admitted == self.pending and self.command_result.returncode == 0
                         and type(self.command_result.stdout) is bytes and type(self.command_result.stderr) is bytes)
            self.source_post()  # Replacing the precreated inode REFUSES, never adopts.
            if export:
                wire.require(0 < len(self.command_result.stdout) <= wire.CERTIFICATE_LIMIT)
                self.certificate = self.command_result.stdout
                self.exported = True
            else:
                self.generated = True
            self.pending = self.admitted = None
        except ProcessError as error:
            self.unknown = self.unknown or error.fatal
            raise
        except BaseException:
            self.unknown = self.unknown or self.guard.lifetime_ledger.fatal
            raise

    def run(self) -> None:
        self.source_post()
        wire.require(self.source.go_returned and self.source.passwords is not None)
        self.scratch.initialize(self.source.passwords.store())
        self._command(export=False)
        self._command(export=True)
        self.scratch.read_original()
        jks.generated_certificate(memoryview(self.scratch.raw)[:self.scratch.length],
                                  self.source.passwords.store(), self.certificate)
        self.source_post()

    def cleanup(self) -> None:
        first = None
        for close in (self.scratch.cleanup, self.saved.close, self.tool.close, self.tool_parent.close):
            try:
                close()
            except BaseException as error:
                self.unknown = True
                _cleanup_failure(self.guard, error)
                if first is None:
                    first = error
        self.closed = (not self.unknown and self.scratch.closed and self.saved.closed and self.tool.close_state == "CLOSED"
                       and all(slot.close_state == "CLOSED" for slot in self.tool_parent.slots))
        if first is not None:
            raise first


class _Engine:
    _acquire_output = _SavedCommandEngine._acquire_output
    close_output = _SavedCommandEngine.close_output
    _require = staticmethod(wire.require)

    def __init__(self, started: float) -> None:
        self.guard = DefaultCancellation(ProcessCleanupError, "The original upload-key operation did not settle")
        self.input = UploadKeyInput(started)
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

    def write(self, raw, *, terminal: bool = False) -> None:
        wire.require(type(raw) in (bytes, bytearray, memoryview) and self.frames == (2 if terminal else 1)
                     and self.output_bytes + len(raw) <= wire.RESPONSE_LIMIT)
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
        self.operation = UploadKeyOperation(self.request, self.input, self.guard)
        self.operation.admit()
        self.frames = 1
        self.write(self.input.ready())
        self.input.go()
        self.operation.run()

    def terminal(self) -> None:
        operation = self.operation
        wire.require(self.request is not None and operation is not None and self.frames == 1
                     and not self.terminal_claimed)
        self.terminal_claimed = True
        self.frames = 2
        known = (operation.closed and not operation.unknown and not self.guard.lifetime_ledger.fatal
                 and self.input.closed and self.guard.handler_state == "RESTORED")
        status = "refused"
        if not known:
            status = "cleanup-unknown"
        elif self.input.stop_reason != "none" or self.guard.cancelled:
            status = "timed-out" if self.input.stop_reason == "timed-out" else "cancelled"
        elif (self.primary is None and operation.generated and operation.exported
              and operation.certificate is not None and operation.scratch.length > 32):
            status = "ok"
        if status == "ok":
            self.write(wire.terminal_header(self.request, status, operation.scratch.length,
                                            len(operation.certificate)), terminal=True)
            self.write(memoryview(operation.scratch.raw)[:operation.scratch.length], terminal=True)
            self.write(operation.certificate, terminal=True)
        else:
            self.write(wire.terminal_header(self.request, status), terminal=True)


def main(*, started: float) -> int:
    engine = _Engine(started)
    scope = CleanupScope(engine.guard, engine.cleanup, owns_cancellation=True, first_primary=True)
    result = 0
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
        result = 70
    try:
        if engine.request is not None and engine.frames == 1:
            engine.terminal()
            if engine.operation.closed and engine.input.closed and not engine.guard.lifetime_ledger.fatal:
                result = 0
    except BaseException as error:
        engine.guard._abort(error)
        result = 74
    finally:
        try:
            engine.close_output()
        except BaseException:
            result = 74
        known = (not engine.guard.lifetime_ledger.fatal and engine.input.closed
                 and engine.guard.handler_state == "RESTORED"
                 and (engine.operation is None or engine.operation.closed)
                 and all(not slot.owned or slot.closed for slot in (engine.output, engine.error_output)))
        if not known:
            _RETAINED.append(engine)
            result = 74
        else:
            engine.input.clear_private()
            if engine.operation is not None:
                engine.operation.scratch.clear_result()
                engine.operation.saved.clear()
                engine.operation.certificate = engine.operation.command_result = None
    return result
