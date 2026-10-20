"""Fixed private duplex allocation worker, borrowing the original bootstrap FDs.

No new process/filesystem/token discovery owner. Native retains the real state
job and only releases its ACK after the actual CAS/close and original currentness
check. FIN remains DATA until the native reader/writer/child/runtime jobs join.
EOF is checked between HTTPS exchanges, not advertised as an interrupt of an
in-flight socket call; actual Supervisor STOP and joins own that settlement.
"""
from __future__ import annotations

import hashlib
import math
import os
import select
import time

from . import _desktop_version_allocation_protocol as wire
from . import version_allocation as allocation
from . import version_allocation_state as state
from . import version_policy as policy
from ._github_connection_transport import _check_control, _control
from .version_allocation_transport import _make_allocation_transport


class _Dialogue:
    """One borrowed input cursor and original output; no independent reader."""
    def __init__(self, control: int, output: int, initial: wire.Initial, started: float) -> None:
        wire.require(type(control) is int and control >= 3 and type(output) is int and output >= 3
                     and control != output and type(started) in (int, float) and math.isfinite(started))
        self.control, self.output, self.initial, self.started = control, output, initial, started
        self.work_end, self.hard_end = started + wire.WORK_SECONDS, started + wire.FINALITY_SECONDS
        self.raw_clock = self.raw_work_end = self.raw_hard_end = None
        self.last_time, self.last_raw = started, None
        self.phase = "new"
        self.buffer = bytearray()
        self.poisoned = False

    def _time(self, *, finality: bool = False) -> float:
        wire.require(not self.poisoned)
        now = time.monotonic()
        end = self.hard_end if finality else self.work_end
        valid = math.isfinite(now) and self.last_time <= now < end
        if valid and self.raw_clock is not None:
            raw = time.clock_gettime_ns(self.raw_clock)
            valid = type(raw) is int and self.last_raw <= raw < (self.raw_hard_end if finality else self.raw_work_end)
        if not valid:
            self.poisoned = True
            raise wire.ProtocolError("Original allocation deadline elapsed")
        self.last_time = now
        if self.raw_clock is not None:
            self.last_raw = raw
        return end - now

    def bind(self) -> None:
        wire.require(self.phase == "new")
        self.phase = "binding"
        clock = getattr(time, "CLOCK_UPTIME_RAW", None)
        wire.require(type(clock) is int)
        before = time.monotonic()
        wire.require(math.isfinite(before) and self.started <= before)
        raw = time.clock_gettime_ns(clock)
        work, hard = int(self.initial.clock["workEndNs"]), int(self.initial.clock["hardEndNs"])
        wire.require(type(raw) is int and 0 <= raw < work <= hard
                     and work - raw <= 60_000_000_000 and hard - raw <= 70_000_000_000)
        self.raw_clock, self.raw_work_end, self.raw_hard_end = clock, work, hard
        self.last_time, self.last_raw = before, raw
        self.work_end = min(self.work_end, math.nextafter(before + (work - raw) / 1e9, -math.inf))
        self.hard_end = min(self.hard_end, math.nextafter(before + (hard - raw) / 1e9, -math.inf))
        self._time()
        # The bootstrap alone owns consuming closes. These duplicated original
        # private descriptions have no other cursor and are not stdio anymore.
        os.set_blocking(self.control, False)
        os.set_blocking(self.output, False)
        self.phase = "ready"

    def _read(self, maximum: int) -> bytes:
        wire.require(not self.buffer)
        while True:
            remaining = self._time()
            ready, _, _ = select.select([self.control], [], [], min(0.05, remaining))
            if not ready:
                continue
            try:
                block = os.read(self.control, min(4096, maximum + 1 - len(self.buffer)))
            except BlockingIOError:
                continue
            self._time()
            if not block:
                raise wire.ProtocolError("Original allocation input closed early")
            self.buffer.extend(block)
            wire.require(len(self.buffer) <= maximum)
            if b"\n" in self.buffer:
                # Never split/covertly retain an eagerly supplied second frame.
                raw = bytes(self.buffer)
                wire.require(raw.endswith(b"\n") and raw.count(b"\n") == 1)
                self.buffer.clear()
                return raw

    def _write(self, raw: bytes, *, finality: bool = False) -> None:
        remaining = memoryview(raw)
        while remaining:
            timeout = self._time(finality=finality)
            _, ready, _ = select.select([], [self.output], [], min(0.05, timeout))
            if not ready:
                continue
            try:
                count = os.write(self.output, remaining[:4096])
            except BlockingIOError:
                continue
            wire.require(type(count) is int and 0 < count <= len(remaining))
            remaining = remaining[count:]
        self._time(finality=finality)

    def checkpoint(self) -> None:
        wire.require(self.phase == "active")
        try:
            self._time()
            ready, _, _ = select.select([self.control], [], [], 0)
            if ready:
                # EOF is loss of the original parent. Any unsolicited input is
                # also fatal; an ACK can be read only by its own state step.
                try:
                    os.read(self.control, 1)
                except BlockingIOError:
                    return
                raise wire.ProtocolError("Original allocation control changed")
        except BaseException:
            self.poisoned = True
            raise

    def go(self) -> wire.Go:
        wire.require(self.phase == "ready")
        self.phase = "go"
        try:
            self._write(wire.ready_frame(self.initial))
            result = wire.parse_go(self._read(wire.GO_LIMIT), self.initial)
            self.phase = "active"
            self.checkpoint()
            return result
        except BaseException:
            self.poisoned = True
            raise

    def change(self, raw: bytes, *, sequence: int, revision: int, digest: str) -> None:
        self.checkpoint()
        self.phase = "ack"
        try:
            self._write(raw)
            wire.parse_ack(self._read(wire.ACK_LIMIT), self.initial, sequence=sequence,
                           expected_revision=revision, payload_sha256=digest)
            self.phase = "active"
            self.checkpoint()  # STOP after CAS/ACK must veto the subsequent PUT.
        except BaseException:
            self.poisoned = True
            raise

    def finish(self, raw: bytes) -> None:
        self.checkpoint()
        self.phase = "fin"
        try:
            self._write(raw)
            self.phase = "eof"
            # FIN -> native stdin-close -> this original EOF -> bootstrap
            # consuming closes -> native stdout EOF/real child and IO joins.
            while True:
                remaining = self._time(finality=True)
                ready, _, _ = select.select([self.control], [], [], min(0.05, remaining))
                if not ready:
                    continue
                try:
                    block = os.read(self.control, 1)
                except BlockingIOError:
                    continue
                wire.require(block == b"")
                self._time(finality=True)
                self.phase = "returned"
                return
        except BaseException:
            self.poisoned = True
            raise

    def finish_source(self, raw: bytes, source) -> None:
        """Only the exact settled SOURCE borrower may use its original F tail.

        Allocation runtime finish/checkpoint behavior remains unchanged. This
        never clears poison, returns a second cursor, or renews an endpoint.
        """
        from ._desktop_version_allocation_source_control import BorrowedAllocationInput
        wire.require(type(source) is BorrowedAllocationInput and source.dialogue is self
                     and self.phase == "active" and not self.poisoned)
        end, raw_end = source.terminal_bounds()
        if source.first_failure is None:
            self.finish(raw)
            return
        try:
            self.hard_end = min(self.hard_end, end)
            self.raw_hard_end = min(self.raw_hard_end, raw_end)
            self._time(finality=True)
            ready, _, _ = select.select([self.control], [], [], 0)
            if ready:
                # Borrowing has ended, but EOF/unsolicited input still vetoes
                # a FIN. This is the SAME cursor, never an ACK/GO poll.
                try:
                    os.read(self.control, 1)
                except BlockingIOError:
                    pass
                else:
                    raise wire.ProtocolError("Original source control changed")
            self.phase = "fin"
            self._write(raw, finality=True)
            self.phase = "eof"
            while True:
                remaining = self._time(finality=True)
                ready, _, _ = select.select([self.control], [], [], min(0.05, remaining))
                if not ready:
                    continue
                try:
                    block = os.read(self.control, 1)
                except BlockingIOError:
                    continue
                wire.require(block == b"")
                self._time(finality=True)
                self.phase = "returned"
                return
        except BaseException:
            self.poisoned = True
            raise


class _StatePort:
    """Private native ACK adapter; GO is the actual native read's snapshot."""
    def __init__(self, dialogue: _Dialogue, go: wire.Go) -> None:
        self.dialogue, self.go = dialogue, go
        self.snapshot = go.snapshot
        self.read = False
        self.active = None
        self.attempted = None
        self.sequence = 0
        self.poisoned = False

    def read_version_allocations(self) -> state.NativeStateSnapshot:
        wire.require(not self.read and not self.poisoned)
        self.read = True
        return self.snapshot

    def replace_version_allocations(self, expected_revision: int, payload: bytes) -> state.NativeStateWriteAck:
        wire.require(self.read and not self.poisoned and self.active is not None
                     and type(expected_revision) is int and expected_revision == self.snapshot.revision)
        state.AllocationState.parse(payload)
        digest = hashlib.sha256(payload).hexdigest()
        raw = wire.state_frame(self.dialogue.initial, self.go.request, self.sequence + 1,
                               expected_revision, digest, self.active)
        # Latch AND retain input before sending. Missing/partial ACK cannot
        # produce an in-memory success or a second request/automatic retry.
        self.poisoned = True
        self.attempted = (expected_revision, payload, raw)
        self.sequence += 1
        self.dialogue.change(raw, sequence=self.sequence, revision=expected_revision, digest=digest)
        snapshot = state.NativeStateSnapshot(expected_revision + 1, payload)
        self.snapshot = snapshot
        self.attempted = None
        self.poisoned = False
        return state.NativeStateWriteAck(snapshot, "committed", "durable", "settled")


class _Journal(state.NativeAllocationJournal):
    """Bind each existing journal call to its one fixed native transition."""
    def __init__(self, port: _StatePort) -> None:
        self._native = port
        super().__init__(port, local_project_id=port.dialogue.initial.local_project_id)

    def _call(self, change: dict, method, *args) -> None:
        port = self._native
        wire.require(port.active is None and not port.poisoned)
        port.active = wire.transition(change, port.dialogue.initial, port.go.request)
        try:
            method(*args)
        finally:
            port.active = None  # The attempted bytes remain retained on failure.

    def enroll_authority(self, *args, **kwargs):
        raise wire.ProtocolError("Worker enrollment is forbidden")

    def select_candidate(self, *args, **kwargs):
        raise wire.ProtocolError("Worker candidate creation is forbidden")

    def record_checkpoint(self, authority, checkpoint):
        self._call({"kind": "checkpoint", "checkpoint": checkpoint.value()}, super().record_checkpoint, authority, checkpoint)

    def record_pending(self, pending):
        self._call({"kind": "pending", "pending": pending.value()}, super().record_pending, pending)

    def mark_rejected(self, pending):
        self._call({"kind": "rejected", "pending": pending.value()}, super().mark_rejected, pending)

    def mark_resolved(self, pending, checkpoint):
        self._call({"kind": "resolved", "pending": pending.value(), "checkpoint": checkpoint.value()}, super().mark_resolved, pending, checkpoint)

    def record_reused(self, authority, reservation, checkpoint):
        self._call({"kind": "reused", "reservation": reservation.value(), "checkpoint": checkpoint.value()},
                   super().record_reused, authority, reservation, checkpoint)


class _CheckedTransport:
    def __init__(self, original, dialogue: _Dialogue, source=None, journal=None) -> None:
        self.original, self.dialogue = original, dialogue
        self.source, self.journal = source, journal
        self.control = _control()

    def exchange(self, step, request):
        self.dialogue.checkpoint()
        if self.source is not None:
            self.source.held_checkpoint()
            if step == "write":
                # Only this fixed PUT boundary consumes the seventh source
                # command, AFTER the original Pending CAS/ACK returned.
                self.source.before_put(self.journal)
        result = self.original.exchange(step, request)
        self.control = dict(_check_control(result.control))
        self.dialogue.checkpoint()
        if self.source is not None:
            self.source.held_checkpoint()
        return result


def execute(dialogue: _Dialogue, go: wire.Go, *, runtime_dir: str, source=None,
            retained_port=None) -> tuple[allocation.AllocationOutcome, _StatePort]:
    dialogue.checkpoint()
    if source is not None:
        from .version_allocation_source import AllocationSourceRun
        wire.require(type(source) is AllocationSourceRun and source.input.dialogue is dialogue
                     and source.selected is go.request and source.provider is not None
                     and dialogue.initial.source is source.request and type(retained_port) is _StatePort
                     and retained_port.dialogue is dialogue and retained_port.go is go)
        source.held_checkpoint()
    else:
        wire.require(dialogue.initial.source is None and retained_port is None)
    port = _StatePort(dialogue, go) if retained_port is None else retained_port
    journal = _Journal(port)
    initial = dialogue.initial
    journal.admit_request(initial.authority, go.request)
    candidate = journal.selected_candidate(initial.authority)
    if initial.kind == "reserve" and candidate.reservation is None:
        # No unknown/partial inventory may even construct the live factory for
        # a new reservation. v2 is explicitly current-visible, never silently
        # promoted to v1's all-history scope. Reconciliation returns DATA only.
        try:
            if go.request.version_policy.schema_version in {2, 3}:
                allocation.current_inventory_policy(go.request).constraints(go.observations, go.request.enabled_platforms, go.request.identity_revision,
                            go.request.store_context_revision, go.request.version_policy,
                            now=math.floor(time.time()))
            else:
                policy.store_constraints(go.observations, go.request.enabled_platforms, go.request.identity_revision,
                                         go.request.version_policy, now=math.floor(time.time()))
        except policy.VersionPolicyError as error:
            return allocation.AllocationOutcome("rejected", error.reason, control=_control()), port
    # The native 60/70 began BEFORE its state/source stages. No fresh HTTP
    # minute is granted by the worker launch or by completion of source reads.
    started = dialogue.started if source is None else min(dialogue.started, dialogue.work_end - wire.WORK_SECONDS)
    original = _make_allocation_transport(go.token, started=started, runtime_dir=runtime_dir,
        selected=go.request, authority=initial.authority, checkpoint=journal.checkpoint(initial.authority),
        reconcile=initial.kind == "reconcile")
    transport = _CheckedTransport(original, dialogue, source, journal)
    result = allocation.allocate_version(go.request, initial.authority, transport, journal,
        observations=go.observations, clock=lambda: math.floor(time.time()))
    dialogue.checkpoint()
    wire.require(not port.poisoned and not journal._poisoned)
    return result, port


def run_owned(control: int, output: int, raw_initial: bytes, *, started: float, runtime_dir: str) -> None:
    """Borrow the existing bootstrap originals; it alone consumes their closes."""
    wire.require(type(runtime_dir) is str and os.path.isabs(runtime_dir))
    initial = wire.parse_initial(raw_initial)
    wire.require(initial.source is None)  # Native SOURCE/Reserve has its own closed composition.
    dialogue = _Dialogue(control, output, initial, started)
    dialogue.bind()
    go = dialogue.go()
    outcome, port = execute(dialogue, go, runtime_dir=runtime_dir)
    raw = wire.finish_frame(initial, go.request, outcome, sequence=port.sequence, snapshot=port.snapshot)
    dialogue.finish(raw)
