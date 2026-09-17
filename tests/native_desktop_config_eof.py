"""Fixed hosted-only transaction EOF instrumentation, never a test discovery target.

The private Rust fixture selects this bootstrap only after its original hosted,
root and compiled-source admission. It runs the genuine engine on its original
main thread and three pipes. No extra reader, cancellation setter, transaction,
thread, child, descriptor or rendezvous file is introduced. This is NOT ordinary
bootstrap-startup evidence or permission to enable production configuration Save.

The optional, exact github_workflows selector has a separate receipt prefix and
three fixed cases. Its conflict sibling is inserted by the original parent
fixture's file ledger, never by this shim. Configuration argv/records stay exact.
"""
from __future__ import annotations

import os
import select
import sys
import threading
import time

_WORKFLOW_CASES = ("precommit-eof", "postcommit-eof", "precommit-conflict-eof")


def _selection(arguments):
    """Closed DATA grammar; a selector is not hosted/root/source admission."""
    if type(arguments) is not list or any(type(item) is not str for item in arguments):
        return None
    if len(arguments) == 2 and arguments[1] in {"precommit-eof", "postcommit-eof"}:
        return False, arguments[1]
    if len(arguments) == 3 and arguments[1] == "github_workflows" and arguments[2] in _WORKFLOW_CASES:
        return True, arguments[2]
    return None


def _need(condition: bool) -> None:
    if not condition:
        raise RuntimeError("Fixed transaction EOF fixture observation failed")


class _Observation:
    def __init__(self, case, control, transaction, cancellation, descriptors, *, workflows=False):
        self.case = case
        self.workflows = workflows
        self.control = control
        self.transaction = transaction
        self.cancellation = cancellation
        self.descriptors = descriptors
        self.publish_original = transaction.InitWorkspace._publish_terminal
        self.workspace = None
        self.guard = None
        self.source = None
        self.ready_slot = None
        self.control_end = None
        self.marker_written = False
        self.resumed = False
        self.failed = False
        self.eof_reads = 0
        self.nonempty_reads = 0
        self.read_errors = 0
        self.checkpoint = "unexpected"
        self.committed_returns = 0
        self.rollback_returns = 0

    @property
    def precommit(self):
        return self.case == "precommit-eof" or self.workflows and self.case == "precommit-conflict-eof"

    @property
    def prefix(self):
        return "MRK_WORKFLOW_EOF_V1" if self.workflows else "MRK_CONFIG_EOF_V1"

    def retain_boundary(self, workspace, fd) -> None:
        guard = workspace._guard
        source = guard._edit_source if guard is not None else None
        scope = workspace._scope
        _need(self.workspace is None and type(workspace) is self.transaction.InitWorkspace
              and type(guard) is self.cancellation.DefaultCancellation
              and type(source) is self.control.EditInput and source.guard is guard
              and scope is not None and scope.workspace is workspace and scope.lease.guard is guard
              and not scope.claimed and not scope.closed
              and workspace._typed_claimed and workspace._install_started and workspace._installing
              and workspace._terminal_seen is None and not workspace._terminal_durable
              and not workspace._terminal_ambiguous and not workspace._recovery_claimed
              and not workspace._journal_clean and not workspace._cleanup_mode
              and workspace._handoff_depth == 0 and guard.depth == 0 and not guard.cancelled
              and not guard.lifetime_ledger.fatal and guard._edit_source_installed
              and not guard._edit_source_removed and source.acquired and source.fd == 0
              and source.identity is not None and not source.close_claimed and not source.closed
              and not source.stopped and not source.custody_unknown and source.active
              and source.apply_active and source.frames == 3 and not source.buffer
              and source.thread is threading.current_thread() is threading.main_thread()
              and source.active_end is not None and time.monotonic() < source.active_end - 0.25)
        if self.workflows:
            _need(workspace._typed_profile is self.transaction.TypedEditProfile.GITHUB_WORKFLOWS
                  and scope.lease.profile is self.transaction.TypedEditProfile.GITHUB_WORKFLOWS
                  and workspace._workflow_complete and workspace._workflow_header is not None
                  and workspace._workflow_plan is not None)
        slots = [slot for slot in workspace._slots if slot.number == fd]
        _need(len(slots) == 1 and type(slots[0]) is self.descriptors._FD
              and slots[0].guard is guard and slots[0].open_state == "OPEN"
              and slots[0].close_state == "NOT_ATTEMPTED")
        self.workspace, self.guard, self.source, self.ready_slot = workspace, guard, source, slots[0]
        # One absolute bound for BOTH records and the gate. It never renews an
        # original active/review/cleanup clock and is shorter than native +8.
        self.control_end = min(source.active_end - 0.25, time.monotonic() + 4.0)

    def write_record(self, raw: bytes) -> None:
        _need(type(raw) is bytes and 0 < len(raw) <= 512 and self.control_end is not None)
        remaining = memoryview(raw)
        while remaining:
            _need(time.monotonic() < self.control_end)
            try:
                count = os.write(2, remaining)
                _need(count > 0)
                remaining = remaining[count:]
            except BlockingIOError:
                select.select([], [2], [], min(0.05, max(0.0, self.control_end - time.monotonic())))

    def gate(self) -> None:
        _need(not self.marker_written and not self.resumed and not self.guard.cancelled
              and not self.source.stopped and not self.source.buffer)
        boundary = "before-COMMITTED" if self.precommit else "after-durable-COMMITTED"
        # Borrow only the original engine-owned stderr. Nonblocking writes make
        # the small observation bound real; the engine alone consumes its close.
        os.set_blocking(2, False)
        self.write_record(f"{self.prefix} {self.case} boundary={boundary}\n".encode("ascii"))
        self.marker_written = True
        while True:
            _need(time.monotonic() < self.control_end)
            ready, _, _ = select.select([self.source.fd], [], [],
                                        min(0.05, max(0.0, self.control_end - time.monotonic())))
            if ready == [self.source.fd]:
                self.resumed = True
                return  # NOT EOF evidence: the next ORIGINAL checkpoint reads.

    def publish(self, workspace, fd, plan, state):
        if state != "COMMITTED":
            result = self.publish_original(workspace, fd, plan, state)
            if state == "ROLLED_BACK" and workspace is self.workspace:
                self.rollback_returns = min(2, self.rollback_returns + 1)
            return result
        self.retain_boundary(workspace, fd)
        if self.precommit:
            self.gate()
        result = self.publish_original(workspace, fd, plan, state)
        self.committed_returns = min(2, self.committed_returns + 1)
        if self.case == "postcommit-eof":
            _need(workspace._terminal_seen == "COMMITTED" and workspace._terminal_durable
                  and not workspace._terminal_ambiguous and not workspace._recovery_claimed
                  and workspace._installing and workspace._handoff_depth == 0 and self.guard.depth == 0)
            self.gate()
        return result

    def record_read(self, fd, limit, result, error: bool) -> None:
        if not self.resumed:
            return
        # Instrumentation must preserve even the original native exception. No
        # observation failure may replace the real read result or set STOP.
        frame = None
        try:
            if error:
                self.read_errors = min(2, self.read_errors + 1)
            elif result == b"":
                self.eof_reads = min(2, self.eof_reads + 1)
            else:
                self.nonempty_reads = min(2, self.nonempty_reads + 1)
            source, guard, workspace = self.source, self.guard, self.workspace
            valid = (fd == source.fd == 0 and limit == 1 and source.active and source.apply_active
                     and source.frames == 3 and not source.buffer and not source.stopped
                     and not source.close_claimed and not guard.cancelled
                     and guard._edit_source is source and source.guard is guard
                     and time.monotonic() < source.active_end)
            # Fixed-depth ORIGINAL call-chain observation, not a replacement
            # poll/checkpoint. Do not retain frames or inspect caller payloads.
            frame = sys._getframe(2)  # record_read <- facade.read <- EditInput.poll
            for code, owner in ((self.control.EditInput.poll.__code__, source),
                                (self.cancellation.DefaultCancellation._poll_edit_stop.__code__, guard),
                                (self.cancellation.DefaultCancellation.check.__code__, guard)):
                valid = valid and frame is not None and frame.f_code is code and frame.f_locals.get("self") is owner
                frame = frame.f_back if frame is not None else None
            if self.precommit:
                valid = (valid and frame is not None
                         and frame.f_code is self.transaction.InitWorkspace._checkpoint.__code__
                         and frame.f_locals.get("self") is workspace and frame.f_back is not None
                         and frame.f_back.f_code is self.publish_original.__code__
                         and frame.f_back.f_locals.get("self") is workspace
                         and workspace._terminal_seen is None and workspace._installing
                         and not workspace._recovery_claimed and workspace._handoff_depth == 0)
                checkpoint = "publisher-entry"
            else:
                valid = (valid and frame is not None
                         and frame.f_code is self.descriptors._fd_cleanup.__wrapped__.__code__
                         and frame.f_locals.get("slot") is self.ready_slot
                         and self.ready_slot.number is None and self.ready_slot.close_state == "CLOSED"
                         and not workspace._installing and not workspace._recovery_claimed
                         and workspace._terminal_seen == "COMMITTED" and workspace._terminal_durable)
                checkpoint = "descriptor-close"
            self.checkpoint = checkpoint if valid and not error and result == b"" else "unexpected"
        except BaseException:
            self.failed = True
        finally:
            del frame

    def summary(self, engine) -> None:
        _need(self.marker_written and self.workspace is not None)
        workspace, source, guard = self.workspace, self.source, self.guard
        request, outcome = engine.last_request, engine.outcome
        applied = (not self.failed and self.resumed and engine.guard is guard and engine.input is source
                   and request is not None and request.seq == 2 and request.op == "apply"
                   and request.params.get("planToken") == engine.published_token
                   and engine.published_token is not None and source.frames == 3 and engine.frames == 2
                   and workspace._typed_claimed and workspace._install_started)
        if self.workflows:
            applied = applied and engine.workflows is True and source.protocol == self.control.WORKFLOW_PROTOCOL
        terminal = workspace._terminal_seen if workspace._terminal_seen in {"COMMITTED", "ROLLED_BACK"} else "UNKNOWN"
        durable = workspace._terminal_durable and not workspace._terminal_ambiguous
        recovery = workspace._recovery_claimed and not workspace._cleanup_mode
        clean = workspace._journal_clean and workspace._outcome.journal == "clean"
        settled = (source.closed and source.close_claimed and not source.custody_unknown
                   and engine.lease is workspace._scope.lease and engine.lease.closed and workspace._scope.closed
                   and guard._edit_source is None and guard._edit_source_removed
                   and guard.handler_state == "RESTORED" and not guard.lifetime_ledger.fatal
                   and outcome is not None and outcome.resources == "settled")
        cancelled = guard.cancelled and source.stopped and outcome is not None and outcome.reason == "cancelled"
        # A workflow precommit conflict is NOT rolled-back success. Original
        # _locations refuses the sibling before rollback moves: terminal UNKNOWN,
        # recovery-required, resources settled, cancelled. Rust validates that
        # distinct exact record and ends the original invocation after it.
        self.write_record((f"{self.prefix} {self.case} eof={self.eof_reads} nonempty={self.nonempty_reads} "
                           f"readErrors={self.read_errors} checkpoint={self.checkpoint} applied={int(applied)} "
                           f"committed={self.committed_returns} rolledBack={self.rollback_returns} terminal={terminal} "
                           f"durable={int(durable)} recovery={int(recovery)} clean={int(clean)} "
                           f"settled={int(settled)} cancelled={int(cancelled)}\n").encode("ascii"))


class _ControlOS:
    """Closed facade for control.os only; global os and all other IO are intact."""
    __slots__ = ("getpid", "fstat", "set_blocking", "close", "_read", "_observation")

    def __init__(self, original, observation):
        self.getpid, self.fstat = original.getpid, original.fstat
        self.set_blocking, self.close = original.set_blocking, original.close
        self._read, self._observation = original.read, observation

    def read(self, fd, limit):
        try:
            result = self._read(fd, limit)  # The one saved REAL call, exactly once.
        except BaseException:
            self._observation.record_read(fd, limit, None, True)
            raise
        self._observation.record_read(fd, limit, result, False)
        return result  # Preserve the exact bytes object; never manufacture EOF.


def main() -> int:
    started = time.monotonic()
    selected = _selection(sys.argv[1:])
    if (selected is None
            or not sys.flags.isolated or not sys.flags.no_site or not sys.dont_write_bytecode
            or not os.path.isabs(sys.argv[1]) or sys.version_info < (3, 11)
            or not (sys.platform.startswith("linux") or sys.platform == "darwin")
            or threading.current_thread() is not threading.main_thread()):
        return 78
    workflows, case = selected
    if workflows and (sys.platform != "linux" or os.uname().machine != "x86_64"):
        return 78
    sys.path.insert(0, sys.argv[1])
    from mobile_release import _desktop_edit_control as control
    from mobile_release import _desktop_edit_engine as engine
    from mobile_release import build_inputs, cancellation, init_transaction

    observation = _Observation(case, control, init_transaction, cancellation, build_inputs, workflows=workflows)
    original_os = control.os
    original_terminal = engine._Engine.terminal

    def publish(workspace, fd, plan, state):
        return observation.publish(workspace, fd, plan, state)

    def terminal(owner):
        try:
            observation.summary(owner)  # Original engine cleanup already ran.
        except BaseException:
            observation.failed = True  # Missing/partial record fails Rust admission.
        return original_terminal(owner)  # Never substitute outcome or skip checks.

    try:
        control.os = _ControlOS(original_os, observation)
        init_transaction.InitWorkspace._publish_terminal = publish
        engine._Engine.terminal = terminal
        return engine.main(started=started, workflows=True) if workflows else engine.main(started=started)
    finally:
        engine._Engine.terminal = original_terminal
        init_transaction.InitWorkspace._publish_terminal = observation.publish_original
        control.os = original_os


if __name__ == "__main__":
    try:
        code = main()
    except BaseException:
        code = 78  # No traceback, rejected input, project bytes or native paths.
    raise SystemExit(code)
