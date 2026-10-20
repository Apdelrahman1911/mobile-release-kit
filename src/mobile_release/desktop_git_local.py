"""Closed local Git prepare/apply on the original saved C/A/W invocation.

The native owner supplies project/tool admission, publisher, consent and durable
Preparing/candidate ACKs. This child never opens the application Store or grants
itself authority from its request. Source/currentness checks supplement the
original native owner. No remote command, hook, credential or shell endpoint.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import select
import stat
import sys
import time

from . import _desktop_git_local_protocol as wire
from . import _desktop_git_branches as branch
from . import _desktop_git_read_protocol as source_fields
from . import git_repository_local as local
from . import git_service as core
from ._desktop_git_local_control import GitLocalInput
from ._desktop_saved_command_engine import _Output, _SavedCommandEngine
from .cancellation import CleanupScope, DefaultCancellation
from .desktop_git_read import GitReadOperation, _Command, _Original, _Engine as _ReadEngine
from .owned_process import ProcessCleanupError, ProcessError, run_owned

_RETAINED = []


class GitLocalOperation:
    # Reuse the original fixed file-descriptor acquisition/one-attempt close
    # primitives. There is no GitRead operation/domain/authorization here.
    checkpoint = GitReadOperation.checkpoint
    admit = GitReadOperation.admit
    cleanup = GitReadOperation.cleanup

    def __init__(self, request: wire.Request, source: GitLocalInput,
                 guard: DefaultCancellation, engine: _Engine) -> None:
        wire.require(type(request) is wire.Request and type(source) is GitLocalInput
                     and type(guard) is DefaultCancellation and type(engine) is _Engine
                     and engine.input is source and engine.guard is guard and engine.request is request)
        self.request, self.source, self.guard, self.engine = request, source, guard, engine
        self.operation_id = request.id
        self.originals = [_Original(path, identity, None) for path, identity in request.directories]
        self.originals.extend(_Original(row.path, row.identity, row.sha256) for row in (request.tool, *request.files))
        self.index_original = next((row for row in self.originals if row.path == request.root / ".git/index"), None)
        self.index_successor = None
        self.entered = self.returned = self.closed = self.unknown = False
        self.calls = 0
        self.pending = self.repository = self.review = self.diff = self.result = None
        source.bind_operation(self)

    def _publication(self):
        repository = self.repository
        transaction = None if repository is None else repository._transaction
        publication = None if transaction is None else transaction.index_publication
        if publication is None:
            return None
        # Only the actual transaction's positive return, never its early
        # published flag or a candidate-shaped frame, supplies this exception.
        wire.require(type(transaction) is local._LocalTransaction and transaction.session.repository is repository
                     and transaction.owner.original is self and type(publication) is local._IndexPublication
                     and self.source.candidate_returned and self.source.candidate is not None
                     and publication.intent is self.source.candidate.intent
                     and publication.intent.action in ("stage", "unstage")
                     and publication.original == self.review.plan._snapshot.index_stamp)
        return publication

    @staticmethod
    def _core_identity(identity):
        return (identity[0], identity[1], identity[2], identity[6], identity[7], identity[8])

    def _admit_index_successor(self, publication) -> None:
        wire.require(self.index_successor is None and publication is self._publication())
        self.checkpoint()
        path = self.request.root / ".git/index"
        identity = source_fields.identity(path.lstat())
        wire.require(self._core_identity(identity) == publication.successor.identity
                     and stat.S_ISREG(identity[2]) and not identity[2] & 0o7022
                     and identity[3] == self.request.uid and identity[5] == 1
                     and publication.successor.digest == publication.intent.candidate_index)
        successor = self.index_successor = _Original(path, identity, publication.successor.digest)
        self.originals.append(successor)  # Root the new FD route before open.
        successor.entered = True
        try:
            successor.fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
        except OSError:
            successor.closed = True
            raise core.GitError("recovery-required") from None
        except BaseException:
            successor.unknown = self.unknown = True
            raise
        GitReadOperation._check(self, successor, True)

    def _check(self, original: _Original, hash_file: bool) -> None:
        publication = self._publication()
        if original is not self.index_original or publication is None:
            GitReadOperation._check(self, original, hash_file)
            return
        self.checkpoint()
        wire.require(original.fd is not None and not original.close_claimed and not original.unknown
                     and self._core_identity(original.identity) == publication.original.identity
                     and original.sha256 == publication.original.digest and self.index_successor is not None)
        current = source_fields.identity(os.fstat(original.fd))
        # The OLD descriptor is never replaced by the successor. The original
        # inode/bytes/mode/owner/size/mtime remain exact. Only its own unlink's
        # nlink=0/ctime may differ after the proven rename+fsync return.
        unchanged = (0, 1, 2, 3, 4, 6, 7)
        wire.require(all(current[i] == original.identity[i] for i in unchanged) and current[5] == 0
                     and current[:2] != self.index_successor.identity[:2])
        if hash_file:
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
                         and source_fields.identity(os.fstat(original.fd)) == current)
        self.checkpoint()

    def source_post(self, *, hash_files: bool) -> None:
        self.checkpoint()
        publication = self._publication()
        if publication is not None and self.index_successor is None:
            self._admit_index_successor(publication)
        for original in self.originals:
            self._check(original, hash_files)
        if self.request.index_absent and publication is None:
            try:
                (self.request.root / ".git/index").lstat()
            except FileNotFoundError:
                pass
            else:
                raise core.GitError("stale-observation")

    def command_arguments(self, argv, *, environ, cwd, capture, text, output_limit,
                          on_start, cleanup, execution_scope, journal_binding, evidence) -> None:
        self.checkpoint()
        pending = self.pending
        wire.require(self.entered and self.source.go_returned and not self.source.candidate_waiting
                     and pending is not None and not pending.claimed and type(argv) in (list, tuple)
                     and tuple(argv) == pending.argv and type(environ) is dict and environ == pending.environ
                     and cwd == pending.cwd and capture is True and text is False and output_limit == pending.output_limit
                     and on_start is None and cleanup is False and execution_scope is None
                     and journal_binding is None and evidence is None)
        self.source_post(hash_files=False)
        pending.claimed = True

    def command(self, argv, *, cwd, environ, capture, text, timeout, output_limit, cancellation, execution_scope):
        self.checkpoint()
        wire.require(self.entered and not self.returned and self.pending is None and self.repository is not None
                     and cancellation is self.guard and execution_scope is None and capture is True and text is False
                     and type(output_limit) is int and 0 < output_limit <= core.MAX_GIT_BYTES
                     and type(timeout) is int and 0 < timeout <= wire.COMMAND_SECONDS)
        sessions = self.repository._active_sessions
        wire.require(len(sessions) == 1
                     and (branch.local_session(self, sessions[0]) if type(self.request.action) is branch.Action else
                          type(sessions[0]) is local._LocalSession)
                     and sessions[0].repository is self.repository and sessions[0].frozen is not None)
        session = sessions[0]
        wire.require(type(argv) is list and all(type(arg) is str for arg in argv) and type(environ) is dict)
        marker = "--work-tree=" + str(self.request.root)
        wire.require(argv.count(marker) == 1)
        args = argv[argv.index(marker) + 1:]
        selected_index = environ.get("GIT_INDEX_FILE")
        index = None if selected_index in (None, str(self.request.root / ".git/index")) else Path(selected_index)
        plan = self.repository._active_plan
        identity = plan._identity if args and args[0] == "commit-tree" and plan is not None else None
        expected_argv, expected_env = session.command_spec(args, index=index, identity=identity)
        wire.require(argv == expected_argv and environ == expected_env and cwd == session.frozen.root
                     and session.root == self.request.root and session.repository.git_executable == wire.TOOL_PATH
                     and self.calls < core.MAX_CALLS)
        self.calls += 1
        pending = self.pending = _Command(tuple(argv), dict(environ), cwd, output_limit)
        try:
            result = run_owned(argv, cwd=cwd, environ=environ, capture=True, text=False, timeout=timeout,
                               output_limit=output_limit, cancellation=self.guard, execution_scope=None)
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
            if not self.unknown:
                self.pending = None
            raise

    def check_current(self, root: Path, action: str, expected_revision: str) -> None:
        wire.require(self.request.phase == "apply" and self.entered and not self.returned
                     and self.source.go_returned and self.review is not None
                     and root == self.request.root and action == self.request.action.kind
                     and expected_revision == self.request.action.expected_revision)
        self.source_post(hash_files=False)

    def record_intent(self, intent: core.PublicationIntent) -> None:
        self.check_current(self.request.root, self.request.action.kind, self.request.action.expected_revision)
        sent = wire.candidate(self.request, self.review, intent)
        self.source.handoff(sent)
        self.check_current(self.request.root, self.request.action.kind, self.request.action.expected_revision)

    def write_candidate(self, sent: wire.Candidate) -> None:
        wire.require(self.source.candidate is sent and self.source.candidate_claimed
                     and self.source.candidate_waiting and self.engine.operation is self)
        self.engine.write(sent.raw, phase="candidate")

    def run(self) -> None:
        self.source_post(hash_files=True)
        wire.require(self.source.go_returned and not self.entered)
        self.entered = True
        action = self.request.action
        repository_type = branch.GitBranchesRepository if type(action) is branch.Action else local.GitLocalRepository
        self.repository = repository_type(self.request.root, git_executable=wire.TOOL_PATH,
            work_end=self.source.work_end, cancellation=self.guard, _run=self.command)
        try:
            # Apply performs a genuine fresh prepare from the retained exact
            # input, not reconstruction of a serialized/core plan capability.
            if type(action) is branch.Action:
                self.review = self.repository.prepare_branch(action.name, expected_revision=action.expected_revision,
                    expected_reference_revision=action.expected_reference_revision)
            else:
                self.review = self.repository.prepare_local(action.kind, expected_revision=action.expected_revision,
                    paths=action.paths, message=action.message, identity=action.identity)
            wire.matches_review(self.request, self.review)
            if self.request.phase == "prepare" and type(action) is not branch.Action:
                self.diff = self.repository.diff(self.review.plan.paths, staged=action.kind != "stage",
                                                expected_revision=action.expected_revision)
            elif self.request.phase == "apply":
                if type(action) is branch.Action:
                    self.result = self.repository.apply_branch(self.review, self, expected_digest=self.request.review_digest)
                else:
                    self.result = self.repository.apply_review(self.review, self, expected_digest=self.request.review_digest)
                if self.result.state != "succeeded":
                    self.source.failure_observed()
            wire.require(not self.repository._unknown and not self.repository._active_sessions
                         and not self.repository._retained_sessions and self.pending is None)
            self.source_post(hash_files=True)
            self.returned = True
        except ProcessError as error:
            self.unknown = self.unknown or error.fatal
            raise
        except BaseException:
            self.unknown = self.unknown or self.guard.lifetime_ledger.verdict().fatal
            raise

    def publication(self) -> str:
        if type(self.request.action) is branch.Action:
            return branch.publication(self)
        if self._publication() is not None:
            return "index-returned"
        transaction = None if self.repository is None else self.repository._transaction
        if transaction is not None and transaction.session.successor is not None:
            wire.require(transaction.owner.original is self and self.source.candidate_returned
                         and self.source.candidate is not None
                         and transaction.session.successor.oid == self.source.candidate.intent.candidate_commit)
            return "ref-returned"
        return "not-reported"


class _Engine:
    _acquire_output = _SavedCommandEngine._acquire_output
    close_output = _SavedCommandEngine.close_output
    cleanup = _ReadEngine.cleanup
    _require = staticmethod(wire.require)

    def __init__(self, started: float) -> None:
        self.guard = DefaultCancellation(ProcessCleanupError, "The original local Git operation did not settle.")
        self.input = GitLocalInput(started)
        self.output, self.error_output = _Output(1), _Output(2)
        self.request = self.operation = self.primary = None
        self.frames = self.output_bytes = 0
        self.candidate_written = self.terminal_claimed = False

    def write(self, raw: bytes, *, phase: str) -> None:
        wire.require(type(raw) is bytes and not self.terminal_claimed
                     and self.output_bytes + len(raw) <= wire.RESPONSE_LIMIT)
        if phase == "ready":
            wire.require(self.frames == 0 and len(raw) <= wire.READY_LIMIT)
        elif phase == "candidate":
            wire.require(self.frames == 1 and not self.candidate_written and len(raw) <= wire.CANDIDATE_LIMIT)
            self.candidate_written = True
        else:
            wire.require(phase == "terminal" and self.frames == 1 + int(self.candidate_written))
            self.terminal_claimed = True
        self.frames += 1
        self.output_bytes += len(raw)
        remaining = memoryview(raw)
        while remaining:
            if phase != "terminal":
                self.guard.check()
            end = self.input.hard_end if phase == "terminal" else self.input.work_end
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
        self.operation = GitLocalOperation(self.request, self.input, self.guard, self)
        self.operation.admit()
        self.write(self.input.ready(), phase="ready")
        self.input.go()
        self.operation.run()

    def terminal(self) -> None:
        operation = self.operation
        wire.require(self.request is not None and operation is not None
                     and self.frames == 1 + int(self.candidate_written))
        verdict = self.guard.lifetime_ledger.verdict()
        known = (operation.closed and not operation.unknown and verdict.cleanup_complete and verdict.contained
                 and self.input.closed and self.guard.handler_state == "RESTORED"
                 and (self.input.first_failure is None or self.input.first_failure_ns is not None))
        status, reason = "refused", "response-invalid"
        values = {}
        if not known:
            status, reason = "cleanup-unknown", "unknown"
        elif self.input.stop_reason != "none" or self.guard.cancelled:
            status = "timed-out" if self.input.stop_reason == "timed-out" else "cancelled"
            reason = "deadline" if status == "timed-out" else "authorization"
        elif self.primary is None and operation.returned:
            status, reason = "ok", None
            if self.request.phase == "prepare":
                values = {"review": operation.review, "diff": operation.diff}
            else:
                values = {"result": operation.result, "publication": operation.publication()}
        elif isinstance(self.primary, core.GitError):
            reason = self.primary.reason
        elif isinstance(self.primary, ProcessError):
            reason = "command-failed"
        self.write(wire.terminal(self.request, status, reason=reason, **values,
            first_failure_ns=self.input.first_failure_ns,
            cleanup_end_ns=self.input.cleanup_end_ns or self.request.hard_end_ns), phase="terminal")
        operation.result = operation.diff = operation.review = None


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
                    engine.primary = error
                    engine.input.failure_observed()
                    raise
        finally:
            scope.__exit__(*sys.exc_info())
    except BaseException as error:
        if engine.primary is None:
            engine.primary = error
        status = 70
    try:
        if engine.request is not None and engine.frames == 1 + int(engine.candidate_written):
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
