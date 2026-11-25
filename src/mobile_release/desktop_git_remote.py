"""One fixed Fetch worker on the ORIGINAL saved-command/C/A/W owners.

The actual native GitLocal owner still supplies its Publisher, Connection,
SourceBook, Preparing row and candidate/keep job. This child never reads the
Store or credentials from an ambient account, and accepts no command endpoint.
"""
from __future__ import annotations

from dataclasses import replace
import os
from pathlib import Path
import select
import sys
import time

from . import _desktop_git_remote_protocol as wire
from . import git_fetch_transaction as transaction
from . import git_repository_fetch as fetch
from . import git_service as core
from ._desktop_git_remote_control import GitRemoteInput
from ._git_remote_input_channel import OriginalInputChannel
from ._desktop_saved_command_engine import _Output, _SavedCommandEngine
from .cancellation import CleanupScope, DefaultCancellation
from .desktop_git_read import GitReadOperation, _Original, _Command, _Engine as _ReadEngine
from .owned_process import ProcessCleanupError, ProcessError, run_owned

_RETAINED = []


class GitRemoteOperation:
    # Same original source FD acquisition/check/one-attempt close. Fetch never
    # replaces HEAD/config/index or those old descriptors.
    checkpoint = GitReadOperation.checkpoint
    _check = GitReadOperation._check
    admit = GitReadOperation.admit
    source_post = GitReadOperation.source_post

    def __init__(self, request, source, guard, engine):
        wire.require(type(request) is wire.Request and type(source) is GitRemoteInput
                     and type(guard) is DefaultCancellation and type(engine) is _Engine
                     and engine.input is source and engine.guard is guard and engine.request is request)
        self.request, self.source, self.guard, self.engine = request, source, guard, engine
        self.operation_id = request.id
        self.originals = [_Original(path, identity, None) for path, identity in request.directories]
        self.originals.extend(_Original(row.path, row.identity, row.sha256) for row in (request.tool, *request.files))
        self.entered = self.returned = self.closed = self.unknown = False
        self.core_returned = False
        self.remote_entered = self.remote_returned = self.network_pending = False
        self.pending = self.repository = self.review = self.result = None
        self.calls = 0
        source.bind_operation(self)

    def _session(self):
        wire.require(self.repository is not None and type(self.repository) is fetch.GitFetchRepository)
        sessions = self.repository._active_sessions
        wire.require(len(sessions) == 1 and type(sessions[0]) is fetch._Session
                     and sessions[0].repository is self.repository and sessions[0].frozen is not None)
        return sessions[0]

    def _spec(self, argv, environ, cwd, *, network):
        session = self._session()
        wire.require(type(argv) is list and all(type(arg) is str for arg in argv) and type(environ) is dict
                     and session.root == self.request.root and self.repository.git_executable == wire.TOOL_PATH)
        marker = "--work-tree=" + str(self.request.root)
        if marker in argv:
            wire.require(not network and argv.count(marker) == 1)
            args = argv[argv.index(marker) + 1:]
            expected, environment = session.command_spec(args)
            wire.require(argv == expected and environ == environment and cwd == session.frozen.root)
            return
        tx = self.repository._transaction
        wire.require(type(tx) is transaction.FetchTransaction and tx.session is session and tx.view is not None
                     and tx.private_roles and tx.view.tx is tx)
        role = tx.private_roles[-1]
        wire.require((role in ("metadata", "fetch")) is network
                     and (not network or role == ("metadata" if self.request.phase == "prepare" else "fetch")))
        expected, environment = tx.view.command(role)
        wire.require(argv == expected and environ == environment and cwd == tx.view.root)
        tx.view.check()

    def command_arguments(self, argv, *, environ, cwd, capture, text, output_limit,
                          on_start, cleanup, execution_scope, journal_binding, evidence):
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

    def _pending(self, argv, *, cwd, environ, capture, text, timeout, output_limit,
                 cancellation, execution_scope, network):
        self.checkpoint()
        wire.require(self.entered and not self.returned and self.pending is None
                     and cancellation is self.guard and execution_scope is None and capture is True and text is False
                     and type(timeout) is int and 0 < timeout <= (45 if network else 10)
                     and type(output_limit) is int and 0 < output_limit <= (256 * 1024 if network else core.MAX_GIT_BYTES)
                     and self.calls < core.MAX_CALLS)
        self._spec(argv, environ, cwd, network=network)
        self.calls += 1
        self.network_pending = network
        self.pending = _Command(tuple(argv), dict(environ), cwd, output_limit)
        return self.pending

    def command(self, argv, **options):
        pending = self._pending(argv, **options, network=False)
        try:
            result = run_owned(argv, **options)
            verdict = self.guard.lifetime_ledger.verdict()
            wire.require(pending.claimed and verdict.cleanup_complete and verdict.contained and verdict.commands == self.calls)
            self.source_post(hash_files=False)
            self.pending = None
            return result
        except BaseException:
            self.source.failure_observed()
            verdict = self.guard.lifetime_ledger.verdict()
            self.unknown |= not verdict.cleanup_complete or not verdict.contained
            if not self.unknown:
                self.pending = None
            raise

    def remote_command(self, argv, **options):
        wire.require(not self.remote_entered and self.source.channel is None)
        self.remote_entered = True  # One command even when acquisition fails.
        pending = self._pending(argv, **options, network=True)
        channel_type = OriginalInputChannel
        if type(self) is not GitRemoteOperation:
            from .desktop_git_push import GitPushOperation
            from ._git_push_input_channel import PushInputChannel
            wire.require(type(self) is GitPushOperation)
            channel_type = PushInputChannel
        channel = self.source.channel = channel_type.__new__(channel_type)
        channel_type.__init__(channel, self.source)
        primary = result = None
        try:
            channel.acquire()
            from ._command_process import _run_git_remote_command
            result = _run_git_remote_command(channel.command, argv, environ=options["environ"], cwd=options["cwd"],
                timeout=options["timeout"], output_limit=options["output_limit"], text=False)
        except BaseException as error:
            primary = error
            self.source.failure_observed()
        verdict = self.guard.lifetime_ledger.verdict()
        self.unknown |= not verdict.cleanup_complete or not verdict.contained or verdict.fatal
        if channel.command is not None and channel.command._exported and verdict.commands != self.calls:
            self.unknown = True
        if not self.unknown:
            self.remote_returned = True  # Actual original C/A/W return, NOT HTTP success.
            try:
                closed = (channel.finish(self) if channel.command is not None and channel.command._exported
                          else channel.close_unused(self))
                self.unknown |= not closed
            except BaseException as error:
                self.unknown = True
                self.guard._abort(error)
                if primary is None:
                    primary = error
        if self.unknown:
            self.repository._unknown = True
            if primary is not None:
                raise primary
            raise ProcessCleanupError("The original private Git operation did not settle.", dispatched=True)
        self.pending = None
        self.network_pending = False
        if primary is not None:
            raise primary
        wire.require(pending.claimed and channel.closed)
        # This checks the separately reported actual helper outcome. Stock
        # Git's stateless disconnect can ignore a helper's exit status; Git0
        # and socket EOF alone must never become HTTP/IO success.
        channel.accept_return(self, result)
        self.source_post(hash_files=True)
        return result

    def credential_current(self, channel):
        self.checkpoint()
        wire.require(channel is self.source.channel and self.remote_entered and not self.remote_returned
                     and self.network_pending and self.pending is not None and self.pending.claimed
                     and channel.binding.target == self.request.target and self.source.go_returned
                     and self.source.stop_reason == "none")
        self.source_post(hash_files=False)

    def check_current(self, root, action, expected_revision):
        wire.require(self.request.phase == "apply" and self.entered and not self.returned
                     and self.source.go_returned and self.review is not None and root == self.request.root
                     and action == "fetch" and expected_revision == self.request.action.expected_revision)
        self.source_post(hash_files=False)

    def record_intent(self, intent):
        self.check_current(self.request.root, "fetch", self.request.action.expected_revision)
        sent = wire.candidate(self.request, self.review, intent)
        result = self.source.handoff(sent)
        self.check_current(self.request.root, "fetch", self.request.action.expected_revision)
        return result

    def write_candidate(self, sent):
        wire.require(self.source.candidate is sent and self.source.candidate_claimed and self.source.candidate_waiting
                     and self.engine.operation is self)
        self.engine.write(sent.raw, phase="candidate")

    def run(self):
        self.source_post(hash_files=True)
        wire.require(self.source.go_returned and not self.entered)
        self.entered = True
        selected = self.request.action
        self.repository = fetch.GitFetchRepository(self.request.root, git_executable=wire.TOOL_PATH,
            work_end=self.source.work_end, launch=self.engine.launch, cancellation=self.guard,
            _run=self.command, _remote=self.remote_command)
        try:
            if self.request.phase == "prepare":
                self.review = self.repository.prepare_remote(selected.remote, self.request.target,
                    expected_revision=selected.expected_revision, expected_reference_revision=selected.expected_reference_revision)
            else:
                # Reprepare genuinely from originals with the retained reviewed
                # OID. This stage does NOT repeat the earlier metadata request.
                self.review = self.repository.prepare_fetch(selected.remote, self.request.target,
                    expected_revision=selected.expected_revision, expected_reference_revision=selected.expected_reference_revision)
            wire.matches_review(self.request, self.review)
            if self.request.phase == "apply":
                self.result = self.repository.apply_fetch(self.review, self, expected_digest=self.request.review_digest)
                if self.result.state != "succeeded":
                    self.source.failure_observed()
            wire.require(not self.repository._unknown and not self.repository._active_sessions
                         and not self.repository._retained_sessions and self.pending is None)
            # A returned core result is distinct from the later source-current
            # check. Keep the former for joined recovery diagnostics if STOP
            # arrives after publication; it can never promote the latter.
            self.core_returned = True
            if not (self.result is not None and self.result.state != "succeeded" and self.source.stop_reason != "none"):
                self.source_post(hash_files=True)
            self.returned = True
        except ProcessError as error:
            self.unknown |= error.fatal
            raise
        except BaseException:
            self.unknown |= self.guard.lifetime_ledger.verdict().fatal
            raise

    def publication(self):
        tx = None if self.repository is None else self.repository._transaction
        receipt = None if tx is None else tx.publication
        if receipt is None:
            return None
        wire.require(type(tx) is transaction.FetchTransaction and tx.owner is self and tx.session.repository is self.repository
                     and type(receipt) is transaction.Publication and self.source.candidate_returned
                     and self.source.candidate is not None and receipt.intent is self.source.candidate.intent
                     and self.source.keep is receipt.keep and self.remote_returned and self.source.channel.closed)
        return receipt

    def diagnostics(self):
        tx = None if self.repository is None else self.repository._transaction
        return ("not-published", ()) if tx is None else tx.diagnostics()

    def cleanup(self):
        first = None
        channel = self.source.channel
        if channel is not None and not channel.closed:
            try:
                if self.unknown or channel.command is not None and channel.command._exported:
                    self.unknown = True  # Never substitute cleanup for a lost C/A/W return.
                elif not channel.close_unused(self):
                    self.unknown = True
            except BaseException as error:
                self.unknown = True
                first = error
                self.guard._abort(error)
        try:
            GitReadOperation.cleanup(self)
        except BaseException as error:
            if first is None:
                first = error
        if first is not None:
            raise first


class _Engine:
    _acquire_output = _SavedCommandEngine._acquire_output
    close_output = _SavedCommandEngine.close_output
    cleanup = _ReadEngine.cleanup
    _require = staticmethod(wire.require)

    def __init__(self, started, launch):
        wire.require(type(launch) is transaction.Launch)
        self.launch = launch
        self.guard = DefaultCancellation(ProcessCleanupError, "The original Git Fetch operation did not settle.")
        self.input = GitRemoteInput(started)
        self.output, self.error_output = _Output(1), _Output(2)
        self.request = self.operation = self.primary = None
        self.frames = self.output_bytes = 0
        self.candidate_written = self.terminal_claimed = False

    def write(self, raw, *, phase):
        wire.require(type(raw) is bytes and not self.terminal_claimed and self.output_bytes + len(raw) <= wire.RESPONSE_LIMIT)
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

    def run(self):
        self.guard.install()
        self.input.acquire()
        self.guard._install_saved_command_source(self.input)
        self._acquire_output(self.output)
        self._acquire_output(self.error_output)
        self.guard.activate()
        self.request = self.input.request()
        if type(self) is _Engine:
            self.operation = GitRemoteOperation(self.request, self.input, self.guard, self)
        else:
            from .desktop_git_push import GitPushOperation, _Engine as PushEngine
            wire.require(type(self) is PushEngine)
            self.operation = GitPushOperation(self.request, self.input, self.guard, self)
        self.operation.admit()
        self.write(self.input.ready(), phase="ready")
        self.input.go()
        self.operation.run()

    def terminal(self):
        operation = self.operation
        wire.require(self.request is not None and operation is not None and self.frames == 1 + int(self.candidate_written))
        verdict = self.guard.lifetime_ledger.verdict()
        known = (operation.closed and not operation.unknown and not verdict.fatal
            and verdict.cleanup_complete and verdict.contained
            and self.input.closed and self.guard.handler_state == "RESTORED"
            and (self.input.first_failure is None or self.input.first_failure_ns is not None))
        status, reason, values = "refused", "response-invalid", {}
        joined_result = (known and self.request.phase == "apply" and operation.core_returned
                         and type(operation.result) is core.MutationResult
                         and operation.result.settlement == "settled")
        if not known:
            status, reason = "cleanup-unknown", "unknown"
        elif joined_result:
            result = operation.result
            if result.state == "succeeded" and (self.primary is not None or not operation.returned
                    or self.input.first_failure is not None or self.input.stop_reason != "none" or self.guard.cancelled):
                # All original child/pipe/source closes remain required above.
                # A late STOP or failed source postcheck cannot become success,
                # nor erase the actual candidate/positive publication return.
                failure = ("deadline" if self.input.stop_reason == "timed-out" else
                           "authorization" if self.input.stop_reason != "none" or self.guard.cancelled else
                           self.primary.reason if isinstance(self.primary, core.GitError) else "response-invalid")
                wire.require(self.input.first_failure_ns is not None)
                result = replace(result, state="recovery-required", reason=failure)
            status, reason = "ok", None
            effect, paths = operation.diagnostics()
            values = {"result": result, "publication": operation.publication(),
                      "effect_phase": effect, "retained_paths": paths}
        elif self.input.stop_reason != "none" or self.guard.cancelled:
            status = "timed-out" if self.input.stop_reason == "timed-out" else "cancelled"
            reason = "deadline" if status == "timed-out" else "authorization"
        elif self.primary is None and operation.returned and self.input.first_failure is None:
            wire.require(self.request.phase == "prepare")
            status, reason, values = "ok", None, {"review": operation.review}
        elif isinstance(self.primary, core.GitError):
            reason = self.primary.reason
        elif isinstance(self.primary, ProcessError):
            reason = "command-failed"
        self.write(wire.terminal(self.request, status, reason=reason, **values,
            first_failure_ns=self.input.first_failure_ns,
            cleanup_end_ns=self.input.cleanup_end_ns or self.request.hard_end_ns,
            control=self.input.http_control), phase="terminal")
        operation.result = operation.review = None


def main(*, started, launch):
    return _run_engine(_Engine(started, launch))


def _run_engine(engine):
    if type(engine) is not _Engine:
        from .desktop_git_push import _Engine as PushEngine
        wire.require(type(engine) is PushEngine)
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
