"""One fixed Store invocation's passive composite-lifetime record.

The checked terminal reader must hold its original registered binding and its
one-use observation. Decoded data, marker absence and exit status alone are not
authority. This private preparation is not an activated Store entrypoint.
No process, descriptor, handler, account or Store operation is acquired here.
"""
from __future__ import annotations

import os
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping

from ._command_process import CommandCallEvidence, OriginalCommandOutcome, _STORE_LANES
from . import _store_lane_contract as wire
from .cancellation import DefaultCancellation
from .owned_process import ProcessCleanupError, ProcessError, preserve_lifetime_error


_ROLES = frozenset(("runner", "tmp", "metadata", "ios-snapshot", "store-selection", "terminal"))
_ERROR = "Store lane original composite lifetime or binding is unconfirmed"


class StoreLaneEvidenceError(ProcessCleanupError):
    def __init__(self, *, attempted: bool = True) -> None:
        super().__init__(_ERROR, dispatched=attempted, contained=False)


@dataclass(frozen=True, slots=True, repr=False)
class StoreLaneResourceBinding:
    _record: object = field(repr=False)
    _owner: object = field(repr=False)
    _role: str


@dataclass(frozen=True, slots=True, repr=False)
class StoreLaneTerminal:
    """Typed decoded facts, usable only through the original reader binding.

    This value is not an original-command receipt or a cleanup capability.
    Only the actual original checked reader can publish it; callers must never
    accept a caller-constructed value or an arbitrary JSON file.
    """

    _binding: StoreLaneResourceBinding = field(repr=False)
    version: int
    nonce: bytes
    lane: str
    output: str
    launches_closed: bool
    adapter_settled: bool
    nested_settled: bool
    receipt_sha256: bytes | None


@dataclass(frozen=True, slots=True)
class StoreLaneVerdict:
    attempted: bool
    finished: bool
    failed: bool
    command_finality_confirmed: bool
    terminal_confirmed: bool
    dependents_settled: bool
    receipt_acceptable: bool


class StoreLaneCallEvidence:
    """One-use exact-origin evidence; no reset, adoption or cleanup methods."""

    def __init__(self, cancellation: DefaultCancellation, *, lane: str,
                 output: Path, nonce: bytes) -> None:
        self._pid, self._thread = os.getpid(), threading.current_thread()
        if (type(cancellation) is not DefaultCancellation or cancellation.pid != self._pid
                or cancellation.owner_thread is not self._thread):
            raise StoreLaneEvidenceError(attempted=False)
        if (type(lane) is not str or lane not in _STORE_LANES
                or not isinstance(output, Path) or not wire.absolute(str(output))
                or type(nonce) is not bytes or len(nonce) != 16):
            raise StoreLaneEvidenceError(attempted=False)
        self._guard, self._lane, self._output, self._nonce = cancellation, lane, str(output), nonce
        self._resources: dict[str, StoreLaneResourceBinding] = {}
        self._sealed = self._attempted = self._finished = self._failed = False
        self._terminal_attempted = False
        self._terminal: StoreLaneTerminal | None = None
        self._pending_attempt: object | None = None
        self._primary: BaseException | None = None
        self._secondary: list[BaseException] = []
        self._command = CommandCallEvidence(cancellation)
        self._command._reserve_store_lane(self, lane, output, nonce, cancellation)

    def _origin(self, cancellation: DefaultCancellation) -> None:
        # A copied/forked record must not call or mutate the parent's guard.
        if self._pid != os.getpid() or self._thread is not threading.current_thread():
            raise StoreLaneEvidenceError()
        if (cancellation is not self._guard or cancellation.pid != self._pid
                or cancellation.owner_thread is not self._thread):
            raise StoreLaneEvidenceError(attempted=self._attempted)

    def _remember(self, error: BaseException | None) -> None:
        if error is None:
            return
        if self._primary is None:
            self._primary = error
        elif error is not self._primary and len(self._secondary) < 8:
            if not any(item is error for item in self._secondary):
                self._secondary.append(error)

    def record_failure(self, error: BaseException) -> None:
        self._origin(self._guard)
        self._failed = True  # Failure precedes optional diagnostic collection.
        if not isinstance(error, BaseException):
            error = StoreLaneEvidenceError(attempted=self._attempted)
        self._remember(error)
        self._guard._abort(error)

    def _require(self, condition: bool) -> None:
        if not condition:
            error = StoreLaneEvidenceError(attempted=self._attempted)
            self.record_failure(error)
            raise error

    def bind_resource(self, role: str, owner: object, *,
                      cancellation: DefaultCancellation) -> StoreLaneResourceBinding:
        self._origin(cancellation)
        self._require(not self._sealed and not self._attempted and not self._finished and not self._failed
                      and type(role) is str and role in _ROLES and role not in self._resources
                      and owner is not None and not isinstance(owner, (str, bytes, int, float, Path)))
        binding = StoreLaneResourceBinding(self, owner, role)
        self._resources[role] = binding
        return binding

    def _resource(self, binding: StoreLaneResourceBinding, owner: object) -> None:
        self._require(type(binding) is StoreLaneResourceBinding and binding._record is self
                      and self._resources.get(binding._role) is binding and binding._owner is owner)

    def _files_owner(self):
        from ._store_lane_files import StoreLaneFiles

        binding = self._resources.get("terminal")
        self._require(type(binding) is StoreLaneResourceBinding
                      and type(binding._owner) is StoreLaneFiles)
        owner = binding._owner
        self._require(owner.record is self and owner.guard is self._guard
                      and all(role in self._resources
                              and self._resources[role] is owner.bindings.get(role)
                              and self._resources[role]._owner is owner
                              for role in ("runner", "tmp", "terminal")))
        return owner

    def _bind_attempt(self, owner: object, *, cancellation: DefaultCancellation) -> None:
        from ._store_lane_files import StoreLaneAttempt

        self._origin(cancellation)
        self._require(type(owner) is StoreLaneAttempt and owner.record is self
                      and owner.guard is cancellation and self._pending_attempt is None
                      and not self._sealed and not self._attempted and not self._finished
                      and not self._failed)
        self._pending_attempt = owner

    def _admit_command_owner(self, cwd: Path, environ: Mapping[str, str]):
        from ._store_lane_files import StoreLaneAttempt

        self._origin(self._guard)
        owner = self._files_owner()
        self._require(owner._matches_command(self, cwd, environ)
                      and type(self._pending_attempt) is StoreLaneAttempt
                      and self._pending_attempt._admitted_for(self, owner))
        return owner

    def _receipt_resources_closed(self) -> bool:
        # Read-only original state. Dependent settlement intentionally does not
        # require disposal yet: it is the gate that permits that disposal.
        from ._store_lane_files import StoreLaneAttempt, StoreLaneFiles

        binding = self._resources.get("terminal")
        owner = binding._owner if type(binding) is StoreLaneResourceBinding else None
        return (type(owner) is StoreLaneFiles and owner._receipt_closed_for(self)
                and type(self._pending_attempt) is StoreLaneAttempt
                and self._pending_attempt._receipt_closed_for(self))

    def seal_command(self, *, runner: Path, cwd: Path, environ: Mapping[str, str],
                     cancellation: DefaultCancellation) -> tuple[str, ...]:
        self._origin(cancellation)
        self._require(not self._sealed and not self._attempted and not self._finished
                      and not self._failed and "terminal" in self._resources)
        # Seal before optional matching/encoding: a failed seal cannot be retried.
        self._sealed = True
        try:
            return self._command.seal_store_lane(runner=runner, cwd=cwd, environ=environ)
        except BaseException as error:
            self.record_failure(error)
            raise

    def command_evidence(self, *, cancellation: DefaultCancellation) -> CommandCallEvidence:
        self._origin(cancellation)
        self._require(self._sealed and not self._attempted and not self._finished and not self._failed)
        return self._command

    def _command_attempted(self, command: CommandCallEvidence) -> None:
        """Called only by the original fixed sidecar before engine creation."""
        self._origin(self._guard)
        self._require(command is self._command and type(command) is CommandCallEvidence
                      and self._sealed and not self._attempted and not self._finished and not self._failed)
        self._attempted = True

    def _outcome(self) -> OriginalCommandOutcome | None:
        return self._command.settled_store_lane(
            owner=self, lane=self._lane, path=Path(self._output), cancellation=self._guard,
        )

    def publish_terminal(self, binding: StoreLaneResourceBinding, *, owner: object,
                         terminal: StoreLaneTerminal, cancellation: DefaultCancellation) -> None:
        """Single publication by the actual checked original terminal reader.

        Reading/validating its exclusive output, path/inode and FD finality is
        the reader's job. This passive slice never manufactures those facts.
        """
        self._origin(cancellation)
        try:
            from ._store_lane_files import StoreLaneFiles

            self._resource(binding, owner)
            self._require(type(owner) is StoreLaneFiles and owner is self._files_owner()
                          and binding._role == "terminal" and self._attempted and not self._finished
                          and not self._failed and not self._terminal_attempted)
            self._terminal_attempted = True
            outcome = self._outcome()
            self._require(outcome is not None and outcome.no_target is None
                          and outcome.result_integrity == "complete"
                          and outcome.termination == "normal-exit"
                          and type(outcome.returncode) is int
                          and outcome.returncode in (wire.SUCCESS, wire.SETTLED_FAILURE)
                          and type(terminal) is StoreLaneTerminal
                          and terminal._binding is binding
                          and type(terminal.version) is int and terminal.version == 1
                          and type(terminal.nonce) is bytes and terminal.nonce == self._nonce
                          and type(terminal.lane) is str and terminal.lane == self._lane
                          and type(terminal.output) is str and terminal.output == self._output
                          and terminal.launches_closed is True and terminal.adapter_settled is True
                          and terminal.nested_settled is True
                          and ((outcome.returncode == wire.SETTLED_FAILURE
                                and terminal.receipt_sha256 is None)
                               or (outcome.returncode == wire.SUCCESS
                                   and type(terminal.receipt_sha256) is bytes
                                   and len(terminal.receipt_sha256) == 32))
                          and owner._accepts_terminal(self, binding, terminal, outcome))
            self._terminal = terminal
        except BaseException as error:
            self.record_failure(error)
            raise

    def finish(self, *, cancellation: DefaultCancellation,
               primary: BaseException | None = None) -> StoreLaneVerdict:
        """Close admission once; missing evidence cannot be repaired afterward."""
        self._origin(cancellation)
        self._require(primary is None or isinstance(primary, BaseException))
        self._remember(primary)
        if not self._finished:
            self._finished = True
            try:
                outcome = self._outcome()
                self._require(not self._failed and (not self._attempted or outcome is not None
                              and (outcome.no_target is not None or self._terminal is not None)))
            except BaseException as error:
                self.record_failure(error)
        return self.verdict(cancellation=cancellation)

    def verdict(self, *, cancellation: DefaultCancellation) -> StoreLaneVerdict:
        self._origin(cancellation)
        try:
            outcome = self._outcome()
            facts = cancellation.lifetime_ledger.verdict()
            complete = (self._finished and (not self._attempted or outcome is not None
                        and (outcome.no_target is not None or self._terminal is not None)))
            idle = not self._failed and complete and facts.contained
            acceptable = (idle and self._finished and self._attempted and outcome is not None
                          and outcome.no_target is None and self._terminal is not None
                          and self._terminal.receipt_sha256 is not None
                          and outcome.result_integrity == "complete"
                          and outcome.termination == "normal-exit" and outcome.returncode == 0
                          and self._receipt_resources_closed()
                          and facts.cleanup_complete and self._primary is None
                          and not cancellation.cancelled and cancellation.handler_state != "UNKNOWN")
            return StoreLaneVerdict(self._attempted, self._finished, self._failed,
                                    outcome is not None, self._terminal is not None, idle, acceptable)
        except BaseException as error:
            self.record_failure(error)
            return StoreLaneVerdict(self._attempted, self._finished, True, False,
                                    self._terminal is not None, False, False)

    def dependents_settled_for(self, binding: StoreLaneResourceBinding, *, owner: object,
                              cancellation: DefaultCancellation) -> bool:
        self._origin(cancellation)
        self._resource(binding, owner)
        return self.verdict(cancellation=cancellation).dependents_settled

    def receipt_acceptable(self, *, lane: str, output: Path, sha256: bytes,
                           cancellation: DefaultCancellation) -> bool:
        self._origin(cancellation)
        self._require(type(lane) is str and lane == self._lane and isinstance(output, Path)
                      and str(output) == self._output and type(sha256) is bytes and len(sha256) == 32)
        verdict = self.verdict(cancellation=cancellation)
        return (verdict.receipt_acceptable and self._terminal is not None
                and self._terminal.receipt_sha256 == sha256)

    def require_receipt(self, *, lane: str, output: Path, sha256: bytes,
                        cancellation: DefaultCancellation) -> None:
        self._origin(cancellation)
        ledger = cancellation.lifetime_ledger
        if ledger.fatal:
            # Preserve an original guard interruption, not a later check()'s
            # freshly allocated diagnostic for the already-latched failure.
            self._remember(ledger._primary)
        try:
            acceptable = self.receipt_acceptable(lane=lane, output=output, sha256=sha256,
                                                  cancellation=cancellation)
            # Final active ownership/cancellation check AFTER the passive
            # receipt view. This creates no process or signal ownership.
            cancellation.check()
        except BaseException as error:
            # A cancelled/failed publication does not make settled consumers
            # live again. Retain the original error without record_failure().
            if ledger.fatal:
                self._remember(ledger._primary)
            self._remember(error)
            acceptable = False
        if acceptable:
            return
        if isinstance(self._primary, (KeyboardInterrupt, SystemExit)):
            raise self._primary
        settled = self.verdict(cancellation=cancellation).dependents_settled
        facts = ledger.verdict()
        error = ProcessError(_ERROR, dispatched=self._attempted,
                             contained=settled and facts.contained,
                             cleanup_complete=settled and facts.cleanup_complete)
        # These are bounded original diagnostics, not inferred exception text.
        # Merge typed chain facts without mutating the underlying true command
        # receipt or the independent dependent-resource settlement predicate.
        for previous in (self._primary, *self._secondary, ledger._primary,
                         *ledger._secondary, cancellation._diagnostic_error):
            preserve_lifetime_error(error, previous=previous)
        raise error from None
