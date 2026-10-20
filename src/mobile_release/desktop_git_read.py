"""One closed repository read using the EXISTING run_owned C/A/W owner.

These child-side originals supplement, never replace, the retained native
Document/SourceBook/runtime admission. No arbitrary process, source path or
environment can be selected by the renderer. All errors and stderr stay private.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import select
import sys
import time

from . import _desktop_git_read_protocol as wire
from . import _desktop_git_branches as branch
from . import git_repository_read as read
from . import git_service as core
from ._desktop_git_read_control import GitReadInput
from ._desktop_saved_command_engine import _Output, _SavedCommandEngine
from .cancellation import CleanupScope, DefaultCancellation
from .owned_process import ProcessCleanupError, ProcessError, run_owned

_RETAINED = []


@dataclass(slots=True, repr=False)
class _Original:
    path: Path
    identity: tuple[int, ...]
    sha256: str | None
    fd: int | None = None
    entered: bool = False
    close_claimed: bool = False
    closed: bool = False
    unknown: bool = False


@dataclass(slots=True, repr=False)
class _Command:
    argv: tuple[str, ...]
    environ: dict[str, str]
    cwd: Path
    output_limit: int
    claimed: bool = False


class GitReadOperation:
    def __init__(self, request: wire.Request, source: GitReadInput, guard: DefaultCancellation) -> None:
        wire.require(type(request) is wire.Request and type(source) is GitReadInput and type(guard) is DefaultCancellation)
        self.request, self.source, self.guard = request, source, guard
        self.originals = [_Original(path, identity, None) for path, identity in request.directories]
        self.originals.extend(_Original(row.path, row.identity, row.sha256) for row in (request.tool, *request.files))
        self.entered = self.returned = self.closed = self.unknown = False
        self.calls = 0
        self.pending: _Command | None = None
        self.repository: read.GitReadRepository | None = None
        self.result: read.ReadObservation | core.Diff | read.History | branch.Branches | None = None
        source.bind_operation(self)  # Before any acquisition can lose its return.

    def checkpoint(self) -> None:
        self.source._owner()
        self.guard.check()
        wire.require(not self.closed and not self.unknown and time.monotonic() < self.source.work_end)
        wire.require((os.getuid(), os.geteuid(), os.getgid(), os.getegid()) ==
                     (self.request.uid, self.request.uid, self.request.gid, self.request.gid))

    def _check(self, original: _Original, hash_file: bool) -> None:
        self.checkpoint()
        wire.require(original.fd is not None and not original.close_claimed and not original.unknown)
        identity = wire.directory_identity if original.sha256 is None else wire.identity
        wire.require(identity(os.fstat(original.fd)) == original.identity
                     and identity(os.stat(original.path, follow_symlinks=False)) == original.identity)
        if hash_file and original.sha256 is not None:
            os.lseek(original.fd, 0, os.SEEK_SET)
            count, digest = 0, hashlib.sha256()
            while True:
                self.checkpoint()
                block = os.read(original.fd, min(32768, original.identity[6] + 1 - count))
                if not block:
                    break
                count += len(block)
                wire.require(count <= original.identity[6])
                digest.update(block)
            wire.require(count == original.identity[6] and digest.hexdigest() == original.sha256
                         and identity(os.fstat(original.fd)) == original.identity
                         and identity(os.stat(original.path, follow_symlinks=False)) == original.identity)
        self.checkpoint()

    def admit(self) -> None:
        self.checkpoint()
        for original in self.originals:
            wire.require(not original.entered)
            original.entered = True
            flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
            if original.sha256 is None:
                flags |= os.O_DIRECTORY
            try:
                original.fd = os.open(original.path, flags)
            except OSError:
                original.closed = True
                raise wire.ProtocolError("The original Git source could not be opened.") from None
            except BaseException:
                original.unknown = self.unknown = True
                raise
            self._check(original, True)
        self.source_post(hash_files=False)

    def source_post(self, *, hash_files: bool) -> None:
        self.checkpoint()
        for original in self.originals:
            self._check(original, hash_files)
        if self.request.index_absent:
            try:
                (self.request.root / ".git/index").lstat()
            except FileNotFoundError:
                pass
            else:
                raise core.GitError("stale-observation")

    def command_arguments(self, argv, *, environ, cwd, capture, text, output_limit,
                          on_start, cleanup, execution_scope, journal_binding, evidence) -> None:
        """Only the exact original run_owned GitRead branch calls this gate."""
        self.checkpoint()
        pending = self.pending
        wire.require(self.entered and self.source.go_returned and pending is not None and not pending.claimed
                     and type(argv) in (list, tuple) and tuple(argv) == pending.argv
                     and type(environ) is dict and environ == pending.environ and cwd == pending.cwd
                     and capture is True and text is False and output_limit == pending.output_limit
                     and on_start is None and cleanup is False and execution_scope is None
                     and journal_binding is None and evidence is None)
        self.source_post(hash_files=False)
        pending.claimed = True  # Startup failure spends this exact command too.

    def command(self, argv, *, cwd, environ, capture, text, timeout, output_limit, cancellation, execution_scope):
        self.checkpoint()
        wire.require(self.entered and not self.returned and self.pending is None and self.repository is not None
                     and cancellation is self.guard and execution_scope is None and capture is True and text is False
                     and type(output_limit) is int and 0 < output_limit <= core.MAX_GIT_BYTES
                     and type(timeout) is int and 0 < timeout <= wire.COMMAND_SECONDS)
        sessions = self.repository._active_sessions
        wire.require(len(sessions) == 1
                     and (branch.read_session(self, sessions[0]) if self.request.action.kind == "branches" else
                          type(sessions[0]) is read._ReadSession)
                     and sessions[0].repository is self.repository and sessions[0].frozen is not None)
        session = sessions[0]
        wire.require(type(argv) is list and all(type(arg) is str for arg in argv))
        marker = "--work-tree=" + str(self.request.root)
        wire.require(argv.count(marker) == 1)
        args = argv[argv.index(marker) + 1:]
        expected_argv, expected_env = session.command_spec(args)
        wire.require(argv == expected_argv and environ == expected_env and cwd == session.frozen.root
                     and session.root == self.request.root and session.repository.git_executable == wire.TOOL_PATH
                     and self.calls < core.MAX_CALLS)
        self.calls += 1
        pending = self.pending = _Command(tuple(argv), dict(environ), cwd, output_limit)
        try:
            result = run_owned(argv, cwd=cwd, environ=environ, capture=True, text=False, timeout=timeout,
                               output_limit=output_limit, cancellation=self.guard, execution_scope=None)
            # A CompletedProcess object cannot replace the actual shared ledger.
            # run_owned publishes only after its C/A/W group and cleanup return.
            verdict = self.guard.lifetime_ledger.verdict()
            wire.require(pending.claimed and verdict.cleanup_complete and verdict.contained
                         and verdict.commands == self.calls)
            self.source_post(hash_files=False)
            self.pending = None
            return result
        except BaseException:
            self.source.failure_observed()
            verdict = self.guard.lifetime_ledger.verdict()
            self.unknown = self.unknown or not verdict.cleanup_complete or not verdict.contained
            # An unresolved actual command stays on its original ledger. Never
            # turn this into a rerunnable command or forget its pending inputs.
            if not self.unknown:
                self.pending = None
            raise

    def run(self) -> None:
        self.source_post(hash_files=True)
        wire.require(self.source.go_returned and not self.entered)
        self.entered = True
        action = self.request.action
        repository_type = branch.GitBranchesRepository if action.kind == "branches" else read.GitReadRepository
        self.repository = repository_type(self.request.root, git_executable=wire.TOOL_PATH,
            work_end=self.source.work_end, cancellation=self.guard, _run=self.command)
        wire.require(self.repository.root == self.request.root)
        try:
            if action.kind == "observe":
                result = self.repository.observe()
            elif action.kind == "diff":
                result = self.repository.diff(action.paths, staged=action.staged, expected_revision=action.expected_revision)
            elif action.kind == "branches":
                result = self.repository.branches(expected_revision=action.expected_revision)
            else:
                wire.require(action.kind == "history")
                result = self.repository.history(expected_revision=action.expected_revision)
            wire.require(not self.repository._unknown and not self.repository._active_sessions
                         and not self.repository._retained_sessions and self.pending is None)
            self.source_post(hash_files=True)
            self.returned, self.result = True, result
        except ProcessError as error:
            self.unknown = self.unknown or error.fatal
            raise
        except BaseException:
            self.unknown = self.unknown or self.guard.lifetime_ledger.verdict().fatal
            raise

    def cleanup(self) -> None:
        first = None
        if self.repository is not None:
            self.unknown = self.unknown or self.repository._unknown or bool(
                self.repository._active_sessions or self.repository._retained_sessions)
        for original in reversed(self.originals):
            if original.close_claimed or not original.entered:
                continue
            original.close_claimed = True
            number, original.fd = original.fd, None
            if original.unknown:
                self.unknown = True
                continue
            if number is None:
                self.unknown = self.unknown or not original.closed
                continue
            try:
                os.close(number)
                original.closed = True
            except BaseException as error:
                original.unknown = self.unknown = True
                self.guard._abort(error)
                if first is None:
                    first = error
        self.closed = not self.unknown and all(not row.entered or row.closed for row in self.originals)
        if first is not None:
            raise first


class _Engine:
    _acquire_output = _SavedCommandEngine._acquire_output
    close_output = _SavedCommandEngine.close_output
    _require = staticmethod(wire.require)

    def __init__(self, started: float) -> None:
        self.guard = DefaultCancellation(ProcessCleanupError, "The original Git read did not settle.")
        self.input = GitReadInput(started)
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

    def write(self, raw: bytes, *, terminal=False) -> None:
        wire.require(type(raw) is bytes and not self.terminal_claimed and self.frames == int(terminal)
                     and self.output_bytes + len(raw) <= wire.RESPONSE_LIMIT)
        self.terminal_claimed = terminal
        self.frames += 1
        self.output_bytes += len(raw)
        remaining = memoryview(raw)
        while remaining:
            if not terminal:
                self.guard.check()
            end = self.input.hard_end if terminal else self.input.work_end
            wire.require(time.monotonic() < end and self.output.owned and not self.output.close_claimed)
            current = os.fstat(1)
            wire.require((current.st_dev, current.st_ino, current.st_mode) == self.output.identity)
            try:
                count = os.write(1, remaining[:4096])
                wire.require(type(count) is int and 0 < count <= min(len(remaining), 4096))
                remaining = remaining[count:]
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
        self.operation = GitReadOperation(self.request, self.input, self.guard)
        self.operation.admit()
        self.write(self.input.ready())
        self.input.go()
        self.operation.run()

    def terminal(self) -> None:
        operation = self.operation
        wire.require(self.request is not None and operation is not None and self.frames == 1)
        verdict = self.guard.lifetime_ledger.verdict()
        known = (operation.closed and not operation.unknown and verdict.cleanup_complete and verdict.contained
                 and self.input.closed and self.guard.handler_state == "RESTORED"
                 and (self.input.first_failure is None or self.input.first_failure_ns is not None))
        status, reason, result = "refused", "response-invalid", None
        if not known:
            status, reason = "cleanup-unknown", "unknown"
        elif self.input.stop_reason != "none" or self.guard.cancelled:
            status = "timed-out" if self.input.stop_reason == "timed-out" else "cancelled"
            reason = "deadline" if status == "timed-out" else "authorization"
        elif self.primary is None and operation.returned and operation.result is not None:
            status, reason, result = "ok", None, operation.result
        elif isinstance(self.primary, core.GitError):
            reason = self.primary.reason
        elif isinstance(self.primary, ProcessError):
            reason = "command-failed"
        self.write(wire.terminal(self.request, status, reason=reason, result=result,
            first_failure_ns=self.input.first_failure_ns,
            cleanup_end_ns=self.input.cleanup_end_ns or self.request.hard_end_ns), terminal=True)
        operation.result = None


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
            if engine.operation.closed and engine.input.closed and engine.guard.lifetime_ledger.verdict().cleanup_complete:
                status = 0
    except BaseException as error:
        engine.guard._abort(error)
        status = 74
    finally:
        try:
            engine.close_output()
        except BaseException:
            status = 74
        if (engine.guard.lifetime_ledger.verdict().fatal or not engine.input.closed
                or engine.operation is not None and not engine.operation.closed
                or any(slot.owned and not slot.closed for slot in (engine.output, engine.error_output))):
            _RETAINED.append(engine)
    return status
