"""Closed Push facet of the EXISTING GitRemote/GitLocal worker and engine.

The shared engine owns its input/output, cancellation and actual C/A/W. This
facet selects only the fixed Push core and hook handoff. No duplicated command
execution, token source, provider loop, journal store or native receipt issuer.
"""
from __future__ import annotations

from dataclasses import replace

from . import desktop_git_remote as original
from . import _desktop_git_push_protocol as wire
from . import _git_push_private_protocol as private
from . import git_push_transaction as transaction
from . import git_repository_push as push
from . import git_service as core
from ._desktop_git_push_control import GitPushInput
from ._desktop_saved_command_engine import _Output
from .cancellation import DefaultCancellation
from .desktop_git_read import _Original
from .owned_process import ProcessCleanupError, ProcessError


class GitPushOperation(original.GitRemoteOperation):
    def __init__(self, request, source, guard, engine):
        wire.require(type(request) is wire.Request and type(source) is GitPushInput
                     and type(guard) is DefaultCancellation and type(engine) is _Engine
                     and engine.input is source and engine.guard is guard and engine.request is request)
        self.request, self.source, self.guard, self.engine = request, source, guard, engine
        self.operation_id = request.id
        self.originals = [_Original(path, identity, None) for path, identity in request.directories]
        self.originals.extend(_Original(row.path, row.identity, row.sha256) for row in (request.tool, *request.files))
        self.entered = self.returned = self.closed = self.unknown = self.core_returned = False
        self.remote_entered = self.remote_returned = self.network_pending = False
        self.pending = self.repository = self.review = self.result = None
        self.calls = 0
        self.launch = replace(engine.launch, context=private.Clock(request.digest, request.work_end_ns, request.hard_end_ns))
        source.bind_operation(self)

    def _session(self):
        wire.require(type(self.repository) is push.GitPushRepository)
        sessions = self.repository._active_sessions
        wire.require(len(sessions) == 1 and type(sessions[0]) is push._Session
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
        wire.require(network and type(tx) is transaction.PushTransaction and tx.session is session and tx.view is not None
                     and tx.running and tx.entered and tx.view.tx is tx
                     and tx.mode == ("review" if self.request.phase == "prepare" else "apply"))
        expected, environment = tx.view.command()
        wire.require(argv == expected and environ == environment and cwd == tx.view.root)
        tx.view.check()

    def check_current(self, root, action, expected_revision):
        wire.require(self.request.phase == "apply" and self.entered and not self.returned
                     and self.source.go_returned and self.review is not None and root == self.request.root
                     and action == "push" and expected_revision == self.request.action.expected_revision)
        self.source_post(hash_files=False)

    def record_intent(self, intent):
        self.check_current(self.request.root, "push", self.request.action.expected_revision)
        sent = wire.candidate(self.request, self.review, intent)
        self.source.handoff(sent)
        self.check_current(self.request.root, "push", self.request.action.expected_revision)

    def run(self):
        self.source_post(hash_files=True)
        wire.require(self.source.go_returned and not self.entered)
        self.entered = True
        selected = self.request.action
        self.repository = push.GitPushRepository(self.request.root, git_executable=wire.TOOL_PATH,
            work_end=self.source.work_end, launch=self.launch, cancellation=self.guard,
            _run=self.command, _remote=self.remote_command)
        try:
            if self.request.phase == "prepare":
                self.review = self.repository.prepare_push(self.request.target,
                    expected_revision=selected.expected_revision, expected_reference_revision=selected.expected_reference_revision)
            else:
                self.review = self.repository.prepare_push_apply(self.request.target,
                    expected_revision=selected.expected_revision, expected_reference_revision=selected.expected_reference_revision,
                    expected_digest=self.request.review_digest)
            wire.matches_review(self.request, self.review)
            if self.request.phase == "apply":
                self.result = self.repository.apply_push(self.review, self, expected_digest=self.request.review_digest)
                if self.result.state != "succeeded":
                    self.source.failure_observed()
            wire.require(not self.repository._unknown and not self.repository._active_sessions
                         and not self.repository._retained_sessions and self.pending is None)
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

    def transmission(self):
        tx = None if self.repository is None else self.repository._transaction
        receipt = None if tx is None else tx.receipt
        if receipt is None:
            return None
        channel = self.source.channel
        wire.require(type(tx) is transaction.PushTransaction and tx.owner is self and tx.session.repository is self.repository
                     and type(receipt) is transaction.Returned and receipt.mode == "apply" and self.source.candidate_returned
                     and self.source.candidate is not None and tx.intent is self.source.candidate.intent
                     and self.remote_returned and channel.closed and channel.return_checked and channel.eof
                     and tx.send_consumed and receipt.body == tx.body_digest and receipt.status == tx.remote_status)
        return receipt

    def diagnostics(self):
        tx = None if self.repository is None else self.repository._transaction
        return ("not-sent", ()) if tx is None else tx.diagnostics()


class _Engine(original._Engine):
    _require = staticmethod(wire.require)

    def __init__(self, started, launch):
        wire.require(type(launch) is transaction.Launch and launch.context is None)
        self.launch = launch
        self.guard = DefaultCancellation(ProcessCleanupError, "The original Git Push operation did not settle.")
        self.input = GitPushInput(started)
        self.output, self.error_output = _Output(1), _Output(2)
        self.request = self.operation = self.primary = None
        self.frames = self.output_bytes = 0
        self.candidate_written = self.terminal_claimed = False

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
                         and type(operation.result) is core.MutationResult and operation.result.settlement == "settled")
        if not known:
            status, reason = "cleanup-unknown", "unknown"
        elif joined_result:
            result = operation.result
            if result.state == "succeeded" and (self.primary is not None or not operation.returned
                    or self.input.first_failure is not None or self.input.stop_reason != "none" or self.guard.cancelled):
                failure = ("deadline" if self.input.stop_reason == "timed-out" else
                           "authorization" if self.input.stop_reason != "none" or self.guard.cancelled else
                           self.primary.reason if isinstance(self.primary, core.GitError) else "response-invalid")
                wire.require(self.input.first_failure_ns is not None)
                result = replace(result, state="recovery-required", reason=failure)
            status, reason = "ok", None
            effect, paths = operation.diagnostics()
            values = {"result": result, "transmission": operation.transmission(),
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
    return original._run_engine(_Engine(started, launch))
