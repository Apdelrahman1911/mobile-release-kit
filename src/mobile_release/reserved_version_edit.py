"""Closed reserved-value borrower of the ORIGINAL typed edit and source owners.

The native Session, not this private wire DATA, owns the consume-once handoff,
publisher transitions, current credential and deadline. This child retains its
actual EditInput, two finite source scopes and the authentic RELEASE_VERSION
checkout/plan. It has no HTTP, allocator, replacement stdin cursor or writer.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import math
import os
import sys
import time

from . import _desktop_version_allocation_protocol as dialogue_wire
from . import _desktop_version_allocation_source_protocol as wire
from . import release_version_edit as edit
from . import version_allocation as allocation
from . import version_policy as policy
from ._desktop_version_allocation_source_provider import Provider
from .cancellation import CleanupScope
from .checked_files import _Reader, _Policy, _directory_identity, _file_identity
from .local_release_source import LocalSourceObservation, LocalSourceError


@dataclass(frozen=True, slots=True, repr=False)
class HandoffData:
    source: wire.SourceRequest
    provider: Provider
    reservation: allocation.Reservation
    authority: allocation.AuthorityRegistration
    checkpoint: allocation.Checkpoint
    observation: allocation.CurrentInventory
    clock: dict

    @classmethod
    def parse(cls, value):
        row = policy._object(value, {"schemaVersion", "source", "provider", "reservation", "authority",
                                     "checkpoint", "observation", "clock"})
        wire.require(type(row["schemaVersion"]) is int and row["schemaVersion"] == 1
                     and len(policy.canonical(row)) <= 12 * 1024)
        source = wire.SourceRequest.parse(row["source"])
        reservation = allocation.Reservation.parse(row["reservation"])
        request = reservation.request
        authority = allocation.AuthorityRegistration.parse(row["authority"])
        checkpoint = allocation.Checkpoint.parse(row["checkpoint"])
        observation = allocation.current_inventory_policy(request).CurrentInventory.parse(row["observation"])
        wire.require(request.version_policy.schema_version in {2, 3}
                     and source.matches(request.source) and authority.project_id == request.project_id
                     and authority.protected_branch and checkpoint.sequence >= reservation.sequence
                     and (checkpoint.sequence != reservation.sequence or checkpoint.head_sha256 == reservation.sha256)
                     and observation.identity_revision == request.identity_revision
                     and observation.context_revision == request.store_context_revision)
        return cls(source, Provider.parse(row["provider"], source), reservation, authority, checkpoint,
                   observation, dialogue_wire._clock(row["clock"]))

    def value(self):
        return {"schemaVersion": 1, "source": self.source.value(), "provider": self.provider.value(),
                "reservation": self.reservation.value(), "authority": self.authority.value(),
                "checkpoint": self.checkpoint.value(), "observation": self.observation.value(), "clock": self.clock}


class BorrowedReservedVersionInput:
    """No FD/read/close method: all STOP/input stays on the same EditInput."""
    def __init__(self, owner, phase):
        wire.require(type(owner) is ReservedVersionEdit and phase in {"prepare", "apply"})
        self.owner, self.phase = owner, phase
        self.guard, self.request = owner.guard, owner.data.source
        self.operation = None
        self.workspace = None
        self.borrow_ended = self.unknown = False

    @property
    def provider_selection(self):
        return self.owner.data.provider

    @property
    def work_end(self):
        return self.owner.work_end

    def _owner(self):
        self.owner.input._owner()
        wire.require(self.owner.input.reserved is self.owner and self in self.owner.borrowers
                     and self.owner.guard is self.guard)

    def admit_selected(self, request):
        self._owner()
        wire.require(request is self.owner.data.reservation.request and not self.borrow_ended
                     and self.owner.active is self and self.guard._version_allocation_source is self)

    def admits_provider(self, provider):
        self.admit_selected(self.owner.data.reservation.request)
        return provider is self.provider_selection

    def source_time(self):
        self._owner()
        self.owner.check_clock()

    def failure_observed(self):
        self._owner()
        self.owner.failure_observed()

    def bind_operation(self, operation):
        from .version_allocation_source import AllocationSourceRun
        self.admit_selected(self.owner.data.reservation.request)
        wire.require(type(operation) is AllocationSourceRun and self.operation is None
                     and operation.input is self and operation.guard is self.guard)
        self.operation = operation

    def require_operation(self):
        from .version_allocation_source import AllocationSourceRun
        self._owner()
        wire.require(type(self.operation) is AllocationSourceRun and self.operation.input is self)
        return self.operation

    def command_limits(self, timeout, capture, output_limit):
        wire.require(capture is True and type(timeout) is int and 1 <= timeout <= 10)
        self.require_operation().checkpoint()
        remaining = int(self.work_end - time.monotonic())
        wire.require(remaining >= 1)
        return self.require_operation().command_limits(min(timeout, remaining), output_limit)

    def closed_command_count(self, operation, count):
        self._owner()
        return (operation is self.operation and all(b.operation is not None for b in self.owner.borrowers)
                and count == sum(sum(bool(r["settled"]) for r in b.operation.commands) for b in self.owner.borrowers))

    def end_borrow(self):
        self._owner()
        wire.require(not self.borrow_ended and self.owner.active is self and not self.unknown
                     and self.require_operation().originals_closed())
        self.borrow_ended = True
        self.owner.active = None

    def borrow_workspace(self, scope):
        from .init_workspace_custody import LockedInitScope
        from .init_transaction import TypedEditProfile
        self.admit_selected(self.owner.data.reservation.request)
        operation = self.require_operation()
        wire.require(type(scope) is LockedInitScope and self.workspace is None and self.owner.lease is scope.lease
                     and scope.lease.profile is TypedEditProfile.RELEASE_VERSION and scope.lease._active is scope
                     and scope in scope.lease._scopes and not scope.locked and not scope.claimed
                     and self.phase in {"prepare", "apply"} and operation.phase == "holding"
                     and operation.invocation is not None and operation.invocation.project_owner is not None)
        self.workspace = scope  # Retain before checking another held descriptor.
        self.check_workspace(scope)

    def check_workspace(self, scope):
        operation = self.require_operation()
        wire.require(self.workspace is scope and self.owner.active is self and not self.borrow_ended
                     and scope.lease is self.owner.lease and scope.lease._active is scope
                     and operation.phase == "holding" and not operation.close_claimed
                     and operation.invocation is not None and operation.invocation.project_owner is not None)
        project = operation.invocation.project_owner
        wire.require(not project.claimed and project is operation.invocation._original_project
                     and scope.lock.number is not None and scope.lock.open_state == "OPEN"
                     and scope.lock.close_state == "NOT_ATTEMPTED")
        project.check()
        wire.require(_directory_identity(os.fstat(project.fd)) == self.request.identity
                     == _directory_identity(os.fstat(scope.lock.number))
                     == _directory_identity(os.fstat(scope.lease.directory.fd)))


class ReservedVersionSource(LocalSourceObservation):
    """Same Reader/slots. Only an actual committed writer permits one successor.

    Original version FD is retained and must show its own exact unlink. The new
    named file is a separate checked Reader, never reset/reused as the original.
    All other parent/control/file identities and missing controls remain exact.
    """
    def __init__(self, operation):
        from .version_allocation_source import AllocationSourceRun
        wire.require(type(operation) is AllocationSourceRun and type(operation.input) is BorrowedReservedVersionInput)
        super().__init__(operation.invocation, operation.configuration_bytes, operation.version_bytes,
                         operation.input.work_end, None)
        self.reserved = operation.input.owner
        self.successor = None
        self.successor_node = None
        self.version_node = None
        self.applied = False

    def _unchanged(self):
        if not self.applied:
            return super()._unchanged()
        self._owner()
        original = self.reserved
        wire.require(original.applied_source is self and original.plan is not None
                     and original.outcome is not None and original.outcome.effect == "committed"
                     and original.outcome.journal == "clean" and original.outcome.resources == "settled"
                     and original.outcome.reason == "none" and edit._authentic_plan(original.plan)
                     and original.plan._checkout._lease is original.lease)
        wire.require(self.version_node is not None and self.successor_node is not None and self.successor is not None)
        self.successor.terminal()
        for reader in self.readers:
            for node in reversed(reader.nodes):
                self.guard.check()
                if node is self.version_node:
                    actual, before = os.fstat(reader._number(node.slot)), node.observed
                    # Same old file, now unlinked by the successful original
                    # replacement. No mode/owner/data/mtime exemption.
                    wire.require(_directory_identity(actual) == _directory_identity(before)
                                 and actual.st_nlink == 0 and before.st_nlink == 1
                                 and actual.st_size == before.st_size and actual.st_mtime_ns == before.st_mtime_ns
                                 and actual.st_ctime_ns >= before.st_ctime_ns)
                    entry = reader._stat(node.parent, node.name)
                    wire.require(_file_identity(entry) == _file_identity(self.successor_node.observed))
                else:
                    entry = os.stat("/", follow_symlinks=False) if node.parent is None else reader._stat(node.parent, node.name)
                    identity = _directory_identity if node.directory else _file_identity
                    wire.require(identity(os.fstat(reader._number(node.slot))) == identity(node.observed) == identity(entry))
            wire.require(reader.root is not None)
            for alias in reader.aliases:
                wire.require(_file_identity(reader._stat(reader.root, alias.name)) == _file_identity(alias.observed)
                             and os.readlink(alias.name, dir_fd=reader._number(reader.root)) == alias.target)
        for parent, names in self.absent:
            for name in names:
                try:
                    os.stat(name, dir_fd=self.git_reader._number(parent.slot), follow_symlinks=False)
                except FileNotFoundError:
                    continue
                raise LocalSourceError("repository")

    def _clean(self):
        if not self.applied:
            return super()._clean()
        expected = b" M " + self.version_path.encode("utf-8") + b"\0"
        wire.require(self._git(["status", "--porcelain=v1", "-z", "--untracked-files=all", "--ignore-submodules=none"]) == expected)

    def accept_original_write(self):
        original = self.reserved
        wire.require(original.active is not None and original.active.phase == "apply"
                     and original.active.operation.observation is self and original.plan is not None
                     and edit._authentic_plan(original.plan) and original.applied_source is None
                     and original.outcome is not None and (original.outcome.effect, original.outcome.journal,
                         original.outcome.resources, original.outcome.reason) == ("committed", "clean", "settled", "none"))
        plan = original.plan
        wire.require(len(plan._payloads) == len(plan._checkout._files) == 1 and type(plan._payloads[0]) is bytes
                     and plan._checkout._files[0].path == self.version_path
                     and plan._checkout._files[0].data == self.version_bytes)
        matches = [node for _, node, raw in self.files if node.canonical == self.root / self.version_path and raw == self.version_bytes]
        wire.require(len(matches) == 1)
        self.version_node = matches[0]
        self.successor = _Reader(self.guard)  # Original retained before first open.
        original.applied_source = self
        self.successor_node = self.successor.acquire(self.root / self.version_path,
            _Policy(False, 1, wire.MAX_VERSION_BYTES), None)
        self.successor.terminal()
        node = self.successor_node
        wire.require(node.observed.st_mode == self.version_node.observed.st_mode
                     and node.observed.st_uid == self.version_node.observed.st_uid
                     and node.observed.st_gid == self.version_node.observed.st_gid
                     and node.observed.st_nlink == 1 and self.successor.read(node) == plan._payloads[0])
        wire.require(len(self.successor.descriptors) <= len((self.root / self.version_path).parts)
                     and self.held + len(self.successor.descriptors) + 7 <= 128)
        self.successor.terminal()
        self.applied = True
        self._unchanged()

    def _close(self):
        first = None
        if self.successor is not None:
            try:
                self.successor.close()
                self.successor.assert_closed()
            except BaseException as error:
                first = error
        try:
            super()._close()
        except BaseException as error:
            if first is None:
                first = error
        if first is not None:
            raise first

    def _fork_close(self):
        if self.successor is not None:
            self.successor.after_fork_child()
        super()._fork_close()


class ReservedVersionEdit:
    def __init__(self, engine, value):
        from ._desktop_edit_engine import _Engine
        wire.require(type(engine) is _Engine and engine.domain == "release_version" and not engine.saved_text_recovery
                     and engine.input.reserved is None and engine.input.guard is engine.guard
                     and engine.guard._edit_source is engine.input)
        self.engine, self.input, self.guard = engine, engine.input, engine.guard
        self.data = HandoffData.parse(value)
        self.borrowers, self.active = [], None
        self.lease = self.plan = self.outcome = self.applied_source = None
        self.failed = self.failure_claimed = False
        self.first_failure = self.first_raw = None
        self.clock = getattr(time, "CLOCK_UPTIME_RAW", None)
        wire.require(type(self.clock) is int)
        self.last_time, self.last_raw = time.monotonic(), time.clock_gettime_ns(self.clock)
        self.raw_work, self.raw_hard = int(self.data.clock["workEndNs"]), int(self.data.clock["hardEndNs"])
        wire.require(math.isfinite(self.last_time) and self.input.started <= self.last_time
                     and type(self.last_raw) is int and 0 <= self.last_raw < self.raw_work <= self.raw_hard
                     and self.raw_work - self.last_raw <= 60_000_000_000 and self.raw_hard - self.last_raw <= 70_000_000_000)
        self.work_end = math.nextafter(self.last_time + (self.raw_work - self.last_raw) / 1e9, -math.inf)
        self.hard_end = math.nextafter(self.last_time + (self.raw_hard - self.last_raw) / 1e9, -math.inf)
        self.input.reserved = self  # Same original, before lease/private source IO.
        self.input.review_end = min(self.input.review_end, self.work_end)
        self.input.active_end = min(self.input.active_end, self.work_end)

    def check_clock(self, *, terminal=False):
        self.input._owner()
        now, raw = time.monotonic(), time.clock_gettime_ns(self.clock)
        end = self.hard_end if terminal else self.work_end
        raw_end = self.raw_hard if terminal else self.raw_work
        if self.first_failure is not None:
            end, raw_end = min(end, self.first_failure + 10), min(raw_end, self.first_raw + 10_000_000_000)
        wire.require(not self.failed and math.isfinite(now) and self.last_time <= now < end
                     and type(raw) is int and self.last_raw <= raw < raw_end)
        self.last_time, self.last_raw = now, raw

    def failure_observed(self):
        if self.failure_claimed:
            return
        self.failure_claimed = True
        now, raw = time.monotonic(), time.clock_gettime_ns(self.clock)
        if not (math.isfinite(now) and self.last_time <= now and type(raw) is int
                and self.last_raw <= raw < self.raw_hard):
            self.failed = True
            self.guard._abort(wire.ProtocolError("Reserved edit original clock changed"))
            return
        self.first_failure, self.first_raw = now, raw
        self.last_time, self.last_raw = now, raw

    @contextmanager
    def source(self, phase):
        from .version_allocation_source import AllocationSourceRun
        wire.require(self.active is None and not self.failed and len(self.borrowers) == (0 if phase == "prepare" else 1)
                     and all(b.borrow_ended and b.operation.originals_closed() for b in self.borrowers))
        borrower = BorrowedReservedVersionInput(self, phase)
        self.borrowers.append(borrower)
        self.active = borrower
        operation = AllocationSourceRun(self.data.source, self.guard, borrower, selected=self.data.reservation.request)
        scope = CleanupScope(self.guard, lambda: self._close_borrow(borrower), owns_cancellation=False, first_primary=True)
        try:
            with scope:
                with operation.hold():
                    yield operation
        finally:
            scope.__exit__(*sys.exc_info())

    def _close_borrow(self, borrower):
        if borrower.operation is not None:
            borrower.operation.close()
            if isinstance(borrower.operation.observation, ReservedVersionSource):
                successor = borrower.operation.observation.successor
                if successor is not None:
                    successor.assert_closed()
        if not borrower.borrow_ended:
            borrower.end_borrow()

    def check_saved(self, checkout):
        self.check_clock()
        request = self.data.reservation.request
        wire.require(edit._authentic_checkout(checkout) and checkout._lease is self.engine.lease
                     and checkout.selection.source == self.data.source.version_path
                     and checkout.enabled_platforms == self.data.reservation.request.enabled_platforms
                     and checkout.baseline["savedConfig"]["sha256"] == request.source.configuration_sha256
                     and checkout.baseline["savedVersion"].get("sha256") == request.source.version_sha256)
        self.lease = self.engine.lease

    def prepare(self, checkout, params):
        self.check_saved(checkout)
        values = {"name": self.data.reservation.version.name, "build": str(self.data.reservation.version.build)}
        wire.require(self.plan is None and params["intent"] == "edit" and params["values"] == values)
        with self.source("prepare"):
            self.plan = allocation.prepare_reserved_version_edit(self.lease, checkout, params["revision"],
                params["expectedBaseline"], self.data.reservation, self.data.reservation.request,
                current_inventory=(self.data.observation,), now=int(time.time()))
        return self.plan

    def apply(self, plan):
        wire.require(plan is self.plan and edit._authentic_plan(plan) and self.outcome is None)
        allocation.current_inventory_policy(self.data.reservation.request).check_reserved(self.data.reservation.version, self.data.reservation.request.version_policy,
            enabled=self.data.reservation.request.enabled_platforms, identity_revision=self.data.reservation.request.identity_revision,
            context_revision=self.data.reservation.request.store_context_revision,
            observations=(self.data.observation,), now=int(time.time()))
        with self.source("apply") as source:
            self.outcome = edit.apply_release_version_edit(self.lease, plan)
            self.engine.outcome = self.outcome  # Preserve real effect BEFORE any source postcheck.
            wire.require((self.outcome.effect, self.outcome.journal, self.outcome.resources, self.outcome.reason)
                         == ("committed", "clean", "settled", "none"))
            source.observation.accept_original_write()
        return self.outcome

    def close(self):
        if self.active is not None:
            self._close_borrow(self.active)
        wire.require(all(b.borrow_ended and b.operation.originals_closed() for b in self.borrowers))

    def settled(self):
        self.close()
        self.check_clock(terminal=True)
        facts = self.guard.lifetime_ledger.verdict()
        return (self.active is None and facts.complete and facts.cleanup_complete and facts.contained
                and not facts.fatal and facts.profile_calls == 0 and facts.commands in {0, 7, 14})
