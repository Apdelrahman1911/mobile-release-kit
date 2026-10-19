"""Actual held source for optional allocation, reusing the original owners.

Source-only observations settle before candidate selection. An allocating call
must reacquire and match its full durable pre-edit source, hold this SAME scope
through HTTP, and check after Pending ACK immediately before the sole PUT.
Neither a SourceBinding nor this module enables a native allocation profile.
"""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import os
import re
import sys

from . import _desktop_version_allocation_source_protocol as wire
from . import version_policy as policy
from ._desktop_version_allocation_source_control import BorrowedAllocationInput
from .build_inputs import BuildInputRootChanged, InvocationCustody, invocation_custody
from .cancellation import CleanupScope, DefaultCancellation
from .checked_files import _Reader, _Policy, _directory_identity
from .config import MAX_CONFIG_BYTES, MAX_VERSION_BYTES, parse_config_text, validate_config_data
from .errors import ConfigurationError
from .local_release_source import LocalSourceError, LocalSourceObservation, _retain_source, source_descriptor_quote
from .owned_process import ProcessCleanupError, ProcessInterrupted, fatal_lifetime_error

_RETAINED = []


class SourceRefused(ValueError):
    """Only explicit saved-byte/policy comparisons, not generic protocol errors."""

    def __init__(self):
        super().__init__("The saved version source no longer matches")


def _saved_need(condition):
    if not condition:
        raise SourceRefused()


def _refusal_reason(error, guard):
    if type(error) in (SourceRefused, BuildInputRootChanged):
        return "source-refused"
    if type(error) is LocalSourceError and error.reason in {
            "path", "input", "repository", "configuration", "index", "source", "dirty", "changed", "budget"}:
        return "source-refused"
    if type(error) in (KeyboardInterrupt, ProcessInterrupted) and guard.cancelled:
        return "cancelled"
    return None  # In particular, an unclassified ProtocolError has no clean FIN.


class AllocationSourceRun:
    def __init__(self, request: wire.SourceRequest, guard: DefaultCancellation,
                 source: BorrowedAllocationInput, *, selected=None) -> None:
        from . import version_allocation as allocation
        from . import _desktop_version_allocation_protocol as dialogue_wire
        wire.require(type(request) is wire.SourceRequest and type(guard) is DefaultCancellation
                     and type(source) is BorrowedAllocationInput and source.request is request
                     and source.guard is guard and guard._version_allocation_source is source)
        if selected is None:
            wire.require(type(source.dialogue.initial) is wire.Initial and source.dialogue.initial.source is request)
            kind = "probe"
        else:
            wire.require(type(selected) is allocation.AllocationRequest
                         and type(source.dialogue.initial) is dialogue_wire.Initial and request.matches(selected.source))
            dialogue_wire.bound_request(source.dialogue.initial, selected)
            kind = source.dialogue.initial.kind
        self.request, self.guard, self.input, self.selected, self.kind = request, guard, source, selected, kind
        self.root = request.root
        self.invocation = self.observation = self.binding = None
        self.configuration_bytes = self.version_bytes = None
        self.readers, self.reader_closes, self.commands = [], [], []
        self.pending = None
        self.phase = "new"
        self.started = self.close_claimed = self.failed = self.pre_put_spent = False
        self.primary = None
        # Original operation retained before environment/root acquisition.
        source.bind_operation(self)

    def _owner(self):
        self.input._owner()
        wire.require(self.input.operation is self and self.input.request is self.request
                     and self.input.guard is self.guard)

    def checkpoint(self):
        self._owner()
        wire.require(not self.close_claimed and not self.failed and not self.input.borrow_ended)
        self.guard.check()
        self.input.dialogue._time()

    def remember(self, error):
        self._owner()
        self.failed = True
        if self.primary is None:
            self.primary = error
        try:
            self.input.failure_observed()
        except BaseException as diagnostic:
            self.guard._abort(diagnostic)  # Bad F is unknown; keep the original primary.
        self.guard.lifetime_ledger._remember(error)
        if fatal_lifetime_error(error, "Original allocation source cleanup did not settle") is not None:
            self.guard._abort(error)

    def bind_invocation(self, owner):
        self._owner()
        wire.require(type(owner) is InvocationCustody and self.invocation is None and self.started
                     and owner.mode == "allocation-read" and owner.cancellation is self.guard
                     and owner.root == self.root and owner.lane_evidence is None and owner.store_namespace is None)
        self.invocation = owner

    def _close_reader(self, index):
        if self.reader_closes[index]:
            return
        self.reader_closes[index] = True  # Sole close attempt, including return loss.
        self.readers[index].close()

    def _read_saved(self, relative, maximum, size, digest):
        self.checkpoint()
        wire.require(self.invocation is not None and self.invocation.project_owner is not None
                     and len(self.readers) < 2)
        path = self.root / relative
        # Only fixed config then its already-checked selected version path.
        wire.require(relative == ("release/mobile-release.json" if not self.readers else self.request.version_path)
                     and len(path.parts) <= 40)
        reader = _Reader(self.guard)
        index = len(self.readers)
        self.readers.append(reader)
        self.reader_closes.append(False)
        scope = CleanupScope(self.guard, lambda: self._close_reader(index), owns_cancellation=False,
                             fork_cleanup=reader.after_fork_child, first_primary=True)
        try:
            with scope:
                node = reader.acquire(path, _Policy(False, 1, maximum), None)
                wire.require(len(reader.descriptors) <= len(path.parts))
                _saved_need(node.observed.st_size == size and node.observed.st_uid == os.geteuid()
                            and node.observed.st_nlink == 1 and not node.observed.st_mode & 0o022)
                roots = [item for item in reader.nodes if item.canonical == self.root]
                wire.require(len(roots) == 1)
                _saved_need(_directory_identity(roots[0].observed) == self.request.identity
                            == _directory_identity(os.fstat(self.invocation.project_owner.fd)))
                raw = reader.read(node)
                # Retain bytes on the same run BEFORE postchecks/close may fail.
                if index == 0:
                    self.configuration_bytes = raw
                else:
                    self.version_bytes = raw
                _saved_need(len(raw) == size and hashlib.sha256(raw).hexdigest() == digest)
                reader.terminal()
        finally:
            scope.__exit__(*sys.exc_info())
        reader.assert_closed()
        self.checkpoint()

    def _saved(self):
        r = self.request
        self._read_saved("release/mobile-release.json", MAX_CONFIG_BYTES, r.configuration_size, r.configuration_sha256)
        try:
            config = parse_config_text(self.configuration_bytes.decode("utf-8"))
            validate_config_data(config)
        except (ConfigurationError, UnicodeError) as error:
            raise SourceRefused() from error
        _saved_need(config["version"]["source"] == r.version_path)
        self._read_saved(r.version_path, MAX_VERSION_BYTES, r.version_size, r.version_sha256)
        # No descriptor credit for a return-lost close. Both preliminary reads
        # must actually close before the continuous LocalSource scope opens.
        for reader in self.readers:
            reader.assert_closed()
        wire.require(source_descriptor_quote(self.root, r.version_path, r.ref[len("refs/heads/"):]) <= 96)

    def _arm_source(self, source, arguments, timeout, limit):
        self.checkpoint()
        wire.require(source is self.observation and source._composition is self and source.execution_source is None
                     and source.endpoint == self.input.work_end and self.pending is None
                     and len(self.commands) < wire.MAX_SOURCE_CALLS and type(timeout) is int and 1 <= timeout <= 10)
        index = len(self.commands)
        first = ((["config", "--local", "--no-includes", "--null", "--list"], 65536),
                 (["rev-parse", "--shared-index-path", "HEAD", "HEAD^{tree}"], 1024),
                 (["ls-files", "--stage", "-z"], 2 << 20), (["ls-files", "-v", "-z"], 2 << 20))
        if index < 4:
            wire.require(self.phase == "capture" and (arguments, limit) == first[index])
        elif index == 4:
            wire.require(self.phase == "capture" and len(arguments) == 5
                         and arguments[:4] == ["ls-tree", "-r", "-z", "--full-tree"]
                         and re.fullmatch(r"[0-9a-f]{40}", arguments[4]) is not None and limit == 2 << 20)
        else:
            wire.require(arguments == ["status", "--porcelain=v1", "-z", "--untracked-files=all", "--ignore-submodules=none"]
                         and limit == 2 << 20 and ((index == 5 and self.phase == "capture")
                         or (index == 6 and self.phase == "pre-put" and self.pre_put_spent)
                         or (index in {6, 7} and self.phase == "final")))
        facts = self.guard.lifetime_ledger.verdict()
        wire.require(facts.complete and facts.cleanup_complete and facts.contained and not facts.fatal
                     and facts.profile_calls == 0 and facts.commands == index and self.commands_settled())
        row = {"attempted": False, "settled": False, "slot": None, "command": None, "timeout": timeout, "limit": limit}
        self.commands.append(row)
        self.pending = row

    def _bind_source_command(self, source, argv, environment):
        self._owner()
        wire.require(source is self.observation and self.pending is not None and self.pending["command"] is None)
        self.pending["command"] = (tuple(argv), dict(environment))

    def command_arguments(self, argv, *, environ, cwd, capture, text, output_limit, on_start,
                          cleanup, execution_scope, journal_binding, evidence):
        self.checkpoint()
        row = self.pending
        wire.require(row is not None and row["command"] is not None and not row["attempted"]
                     and tuple(argv) == row["command"][0] and environ == row["command"][1] and cwd == self.root
                     and capture is True and text is False and output_limit == row["limit"] and cleanup is False
                     and on_start is execution_scope is journal_binding is evidence is None)
        self.observation._unchanged()
        row["attempted"] = True

    def command_limits(self, timeout, output_limit):
        row = self.pending
        wire.require(row is not None and row["attempted"] and row["slot"] is None
                     and 1 <= timeout <= row["timeout"] and output_limit == row["limit"])
        return timeout, output_limit

    def bind_command_slot(self, engine, slot):
        from ._command_process import CommandOutcomeSlot, _Outer
        self._owner()
        row = self.pending
        # Called by the ORIGINAL _Outer before its acquisition/cleanup scope.
        # Do not poll cancellation or introduce IO here.
        wire.require(row is not None and row["attempted"] and row["slot"] is None
            and type(engine) is _Outer and type(slot) is CommandOutcomeSlot
            and engine.guard is self.guard and engine.owns is False and engine.slot is slot
            and engine.scope is engine.binding is engine._store_timing is None
            and slot._engine is engine and slot._scope is None and slot._nonce == engine.nonce
            and slot.read() is None and self.guard.lifetime_ledger._command is slot)
        row["slot"] = slot

    def _outcome(self, row):
        # Pure existing check of the exact C/A/W original, not a signing loan.
        from ._desktop_ios_signed_operation import original_outcome
        return original_outcome(row["slot"], self.guard, None, None)

    def commands_settled(self):
        self._owner()
        return all(not row["attempted"] or row["settled"] and self._outcome(row) is not None for row in self.commands)

    def _source_returned(self, source, result):
        self._owner()
        row = self.pending
        wire.require(source is self.observation and row is not None and row["attempted"])
        actual, facts = self._outcome(row), self.guard.lifetime_ledger.verdict()
        wire.require(actual is not None and actual.result_integrity == "complete" and actual.termination == "normal-exit"
                     and actual.returncode == result.returncode and facts.complete and facts.cleanup_complete
                     and facts.contained and not facts.fatal and facts.commands == len(self.commands) and facts.profile_calls == 0)
        row["settled"] = True
        self.pending = None
        if result.returncode != 0:
            self.failed = True

    def _source_error(self, source, error):
        self._owner()
        wire.require(source is self.observation and self.pending is not None)
        row = self.pending
        facts = self.guard.lifetime_ledger.verdict()
        row["settled"] = bool(row["attempted"] and self._outcome(row) is not None and facts.complete
                              and facts.cleanup_complete and facts.contained and not facts.fatal)
        self.pending = None
        self.remember(error)

    def held_checkpoint(self):
        self.checkpoint()
        wire.require(self.phase == "holding" and self.observation is not None and self.binding is not None)
        self.observation._unchanged()  # No extra Git call for each HTTP exchange.

    def before_put(self, journal):
        from ._desktop_version_allocation_runtime import _Journal
        self.held_checkpoint()
        wire.require(self.kind == "reserve" and not self.pre_put_spent and type(journal) is _Journal
                     and journal._native.dialogue is self.input.dialogue and journal._native.active is None
                     and journal._native.attempted is None and not journal._native.poisoned)
        initial = self.input.dialogue.initial
        journal.admit_request(initial.authority, self.selected)
        pending = journal.pending_for(initial.authority, self.selected.candidate_id)
        wire.require(pending is not None and pending.reservation.request == self.selected)
        self.pre_put_spent = True  # Even a rejected/failed source recheck spends this call.
        self.phase = "pre-put"
        self.observation.check()  # AFTER actual durable Pending ACK, immediately before PUT.
        self.phase = "holding"
        self.held_checkpoint()

    @contextmanager
    def hold(self):
        self.checkpoint()
        wire.require(not self.started and self.invocation is None)
        self.started = True
        try:
            with invocation_custody(self.root, mode="allocation-read", cancellation=self.guard) as invocation:
                wire.require(invocation is self.invocation)
                with invocation.project(signing_lease=None):
                    self._saved()
                    self.observation = LocalSourceObservation(invocation, self.configuration_bytes, self.version_bytes,
                                                              self.input.work_end, None)
                    self.observation._composition = self
                    self.phase = "capture"
                    with _retain_source(self.observation):
                        observed = self.observation.observed
                        binding = policy.SourceBinding(observed.commit, observed.tree, observed.ref,
                            hashlib.sha256(self.configuration_bytes).hexdigest(), hashlib.sha256(self.version_bytes).hexdigest())
                        _saved_need(self.request.matches(binding) and (self.selected is None or self.selected.source == binding))
                        self.binding = binding
                        self.phase = "holding"
                        yield binding
                        self.phase = "final"
                    for reader in self.observation.readers:
                        reader.assert_closed()
            self.phase = "closed"
            wire.require(self.originals_closed())
        except BaseException as error:
            self.remember(error)
            raise

    def close(self):
        self._owner()
        if self.close_claimed:
            return
        self.close_claimed = True
        first = None
        if self.observation is not None and not self.observation.closed:
            try:
                self.observation._close()
            except BaseException as error:
                first = error
        for index in reversed(range(len(self.readers))):
            try:
                self._close_reader(index)
            except BaseException as error:
                if first is None:
                    first = error
        if self.invocation is not None and not self.invocation.claimed:
            try:
                self.invocation.cleanup()
            except BaseException as error:
                if first is None:
                    first = error
        if first is not None:
            self.remember(first)
            raise first

    def originals_closed(self):
        self._owner()
        for reader in [*self.readers, *(self.observation.readers if self.observation is not None else ())]:
            reader.assert_closed()  # LocalSource.closed alone is NOT close finality.
        facts = self.guard.lifetime_ledger.verdict()
        return (self.pending is None and self.commands_settled() and facts.complete and facts.cleanup_complete
                and facts.contained and not facts.fatal and facts.profile_calls == 0
                and facts.commands == sum(row["settled"] for row in self.commands)
                and (self.observation is None or self.observation.closed)
                and (not self.started if self.invocation is None else self.invocation._allocation_source_closed(self)))


class _SourceCall:
    def __init__(self, dialogue, initial):
        self.dialogue, self.initial = dialogue, initial
        self.guard = DefaultCancellation(ProcessCleanupError, "Original version source cleanup did not settle")
        self.input = BorrowedAllocationInput(dialogue, initial.source)
        self.operation = None
        self.primary = None
        self.scope_error = None
        self.terminal_error = None

    def cleanup(self):
        operation = self.operation or self.input.operation
        first = None
        if operation is not None:
            try:
                operation.close()
            except BaseException as error:
                first = error
                self.guard._abort(error)
        try:
            if self.input.acquired and self.input.guard is self.guard and not self.input.borrow_ended:
                self.input.end_borrow()
        except BaseException as error:
            if first is None:
                first = error
            self.guard._abort(error)
        if first is not None:
            raise first

    def run(self):
        self.guard.install()
        self.input.acquire_borrow()
        self.guard._install_saved_command_source(self.input)
        self.guard.activate()
        self.dialogue.phase = "go"
        try:
            self.dialogue._write(wire.ready_frame(self.initial))
            wire.parse_go(self.dialogue._read(wire.GO_LIMIT), self.initial)
            self.dialogue.phase = "active"
        except BaseException:
            self.dialogue.poisoned = True
            raise
        self.guard.check()
        self.operation = AllocationSourceRun(self.initial.source, self.guard, self.input)
        with self.operation.hold():
            pass  # Source-only: no journal, token, transport or candidate creation.


def run_owned(control: int, output: int, raw_initial: bytes, *, started: float, runtime_dir: str) -> None:
    from ._desktop_version_allocation_runtime import _Dialogue
    wire.require(type(runtime_dir) is str and os.path.isabs(runtime_dir) and not _RETAINED)
    initial = wire.parse_initial(raw_initial)
    dialogue = _Dialogue(control, output, initial, started)
    dialogue.bind()
    call = _SourceCall(dialogue, initial)
    _RETAINED.append(call)  # Original scope/run survives a lost acquire/return.
    scope = CleanupScope(call.guard, call.cleanup, owns_cancellation=True, first_primary=True)
    try:
        try:
            with scope:
                call.run()
        finally:
            scope.__exit__(*sys.exc_info())
    except BaseException as error:
        # InvocationCustody may return a typed fatal wrapper after cleanup.
        # Retain both originals: that wrapper cannot erase the same ledger's
        # first body error, and retaining a body error never clears fatal facts.
        call.scope_error = error
        call.primary = call.guard.lifetime_ledger._primary or error
    operation = call.operation or call.input.operation
    if call.primary is not None:
        reason = _refusal_reason(call.primary, call.guard)
        if reason is None:
            raise call.scope_error
        try:
            wire.require(type(operation) is AllocationSourceRun and not dialogue.poisoned
                         and call.input.first_failure is not None and operation.originals_closed())
            call.input.terminal_bounds()
        except BaseException as error:
            # A classified body refusal cannot erase unknown cleanup/clock facts.
            call.terminal_error = error
            call.input.unknown = True
            dialogue.poisoned = True
            call.guard._abort(error)
            raise call.scope_error
        binding = None
    else:
        reason = "none"
        wire.require(type(operation) is AllocationSourceRun and operation.binding is not None and not operation.failed
                     and operation.originals_closed() and call.input.first_failure is None)
        call.input.terminal_bounds()
        binding = operation.binding
    facts = call.guard.lifetime_ledger.verdict()
    try:
        raw = wire.finish_frame(initial, binding, reason=reason, commands=facts.commands,
                               first_failure_ns=call.input.first_failure_raw)
        dialogue.finish_source(raw, call.input)
    except BaseException as error:
        call.terminal_error = error
        call.guard._abort(error)
        if call.primary is not None:
            raise call.scope_error
        raise
