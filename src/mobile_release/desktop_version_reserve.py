"""The fixed native Reserve call on the original SOURCE and HTTP owners.

No path/token discovery, state writer, candidate creation or second executor.
The native caller retains the already selected candidate and state jobs. This
call holds the actual source through Pending ACK / sole PUT / final source
check; only the bootstrap consumes its private FD closes. FIN is still DATA.
"""
from __future__ import annotations

import os
import sys

from . import _desktop_version_allocation_protocol as wire
from . import version_allocation as allocation
from ._desktop_version_allocation_runtime import _Dialogue, _StatePort, execute
from ._github_connection_transport import _control
from .cancellation import CleanupScope
from .version_allocation_source import AllocationSourceRun, _SourceCall, _RETAINED, _refusal_reason


class _ReserveCall(_SourceCall):
    def __init__(self, dialogue, initial, runtime_dir):
        wire.require(type(initial) is wire.Initial and initial.source is not None and initial.provider is not None)
        super().__init__(dialogue, initial)
        self.runtime_dir = runtime_dir
        self.go = self.port = self.outcome = None

    def run(self):
        self.guard.install()
        self.input.acquire_borrow()
        self.guard._install_saved_command_source(self.input)
        self.guard.activate()
        self.go = self.dialogue.go()
        self.guard.check()
        # Retain the exact GO snapshot/attempt custody before source acquisition
        # and before any native state dialogue. No failed return recreates it.
        self.port = _StatePort(self.dialogue, self.go)
        self.operation = AllocationSourceRun(self.initial.source, self.guard, self.input, selected=self.go.request)
        with self.operation.hold():
            outcome, port = execute(self.dialogue, self.go, runtime_dir=self.runtime_dir,
                                    source=self.operation, retained_port=self.port)
            wire.require(port is self.port)
            self.outcome = outcome  # Keep durable result DATA through post/close failure.
            if outcome.status != "reserved":
                self.input.failure_observed()  # Original returned failure, not later cleanup receipt time.


def _source_refused(call: _ReserveCall) -> allocation.AllocationOutcome:
    """Never renumber/recycle a reservation because its later source changed."""
    original = call.outcome
    claimed = original.write_claimed if original is not None else False
    acknowledged = original.write_acknowledged if original is not None else False
    retained = allocation.AllocationRequest.parse(call.go.request.value())
    wire.require(retained == call.go.request and call.port is not None and not call.port.poisoned)
    state = allocation_state(call)
    row = state.enrolled(call.initial.local_project_id, call.initial.authority)
    candidate = state.candidate(call.initial.local_project_id)
    wire.require(candidate is not None and candidate.request == retained)
    unresolved = row.pending is not None or candidate.reservation is not None or claimed
    return allocation.AllocationOutcome("recovery-required" if unresolved else "rejected", "source-changed",
        checkpoint=row.checkpoint, write_claimed=claimed, write_acknowledged=acknowledged,
        control=original.control if original is not None else _control())


def allocation_state(call):
    from .version_allocation_state import AllocationState
    return AllocationState.parse(call.port.snapshot.payload)


def finish_frame(call: _ReserveCall) -> bytes:
    """Only the actual closed borrower may extend the existing finite FIN."""
    wire.require(type(call) is _ReserveCall and call.go is not None and type(call.port) is _StatePort
                 and not call.port.poisoned and call.port.attempted is None
                 and type(call.operation) is AllocationSourceRun and call.operation.originals_closed())
    call.input.terminal_bounds()  # Includes actual readers/Invocation/C-A-W/RESTORED/FD identity.
    refused = call.primary is not None
    if refused:
        wire.require(_refusal_reason(call.primary, call.guard) is not None and not call.dialogue.poisoned
                     and call.input.first_failure is not None)
        outcome = _source_refused(call)
        source = None
    else:
        wire.require(call.outcome is not None and call.operation.binding is not None and not call.operation.failed)
        outcome, source = call.outcome, call.operation.binding
    facts = call.guard.lifetime_ledger.verdict()
    wire.require(facts.profile_calls == 0 and 0 <= facts.commands <= 8)
    if source is not None:
        wire.require(source == call.go.request.source and facts.commands == (8 if call.operation.pre_put_spent else 7))
    if outcome.status == "reserved":
        wire.require(source is not None and call.input.first_failure is None)
    else:
        wire.require(call.input.first_failure is not None)
    value = wire.frame(wire.finish_frame(call.initial, call.go.request, outcome,
        sequence=call.port.sequence, snapshot=call.port.snapshot), wire.FIN_LIMIT)
    value["finished"].update({"source": source.value() if source is not None else None,
        "firstFailureNs": str(call.input.first_failure_raw) if call.input.first_failure_raw is not None else None,
        "lifetime": {"originalsClosed": True, "borrowEnded": True, "handlersRestored": True,
                     "commands": facts.commands, "profileCalls": 0}})
    return wire.encoded(value, wire.FIN_LIMIT)


def run_owned(control: int, output: int, raw_initial: bytes, *, started: float, runtime_dir: str) -> None:
    wire.require(type(runtime_dir) is str and os.path.isabs(runtime_dir) and not _RETAINED)
    initial = wire.parse_initial(raw_initial)
    wire.require(initial.source is not None and initial.provider is not None)
    dialogue = _Dialogue(control, output, initial, started)
    dialogue.bind()
    call = _ReserveCall(dialogue, initial, runtime_dir)
    _RETAINED.append(call)
    scope = CleanupScope(call.guard, call.cleanup, owns_cancellation=True, first_primary=True)
    try:
        try:
            with scope:
                call.run()
        finally:
            scope.__exit__(*sys.exc_info())
    except BaseException as error:
        call.scope_error = error
        call.primary = call.guard.lifetime_ledger._primary or error
    if call.primary is not None and _refusal_reason(call.primary, call.guard) is None:
        raise call.scope_error  # Unknown ACK/EOF/clock/close never becomes a clean terminal.
    try:
        raw = finish_frame(call)
        dialogue.finish_source(raw, call.input)
    except BaseException as error:
        call.terminal_error = error
        call.input.unknown = True
        dialogue.poisoned = True
        call.guard._abort(error)
        if call.primary is not None:
            raise call.scope_error
        raise
