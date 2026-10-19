"""Closed allocation-state codec and adapter to the original native state owner.

The port is the service's private ``Namespace::VersionAllocations`` slot, never
a renderer-selected namespace, pathname or generic write command. Its native
``replace`` must finish file/parent sync, explicit closes and intent-fence
settlement before returning the success acknowledgement below. Python records
and an in-memory implementation cannot establish that durability.

This module performs no filesystem/process/network access and installs no live
route. The original native service owns admission, local exclusion, uncertain
write recovery and the lifetime of the port. A poisoned adapter cannot be used
again; constructing another adapter is NOT permission to reopen a poisoned
native store. The repository ledger, not this local state, allocates versions.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, Protocol

from . import version_allocation as allocation
from . import version_policy as policy
from ._desktop_github_engine import _decode_json

PROTOCOL = "mrk-version-allocation-state/1"
MAX_AUTHORITIES = 8
MAX_STATE_BYTES = 1024 * 1024
MAX_REVISION = (1 << 64) - 1


def _need(condition: bool) -> None:
    if not condition:
        raise allocation.VersionAllocationError("journal-unavailable")


@dataclass(frozen=True, slots=True)
class AuthorityState:
    authority: allocation.AuthorityRegistration
    checkpoint: allocation.Checkpoint
    pending: allocation.PendingAllocation | None = None

    def __post_init__(self) -> None:
        _need(type(self.authority) is allocation.AuthorityRegistration
              and self.authority.protected_branch
              and type(self.checkpoint) is allocation.Checkpoint)
        if self.checkpoint.sequence == 0:
            _need(self.checkpoint.head_sha256 == self.authority.genesis_sha256)
        if self.pending is not None:
            _need(type(self.pending) is allocation.PendingAllocation
                  and self.pending.authority == self.authority
                  and self.pending.checkpoint.sequence <= self.checkpoint.sequence)
            self.pending.to_bytes()
            if self.pending.checkpoint.sequence == self.checkpoint.sequence:
                _need(self.pending.checkpoint.head_sha256 == self.checkpoint.head_sha256)
            # A competing writer may win while this send remains uncertain.
            # Keep the original intent even when the current head is different.

    @classmethod
    def parse(cls, value: object) -> AuthorityState:
        row = policy._object(value, {"authority", "checkpoint", "pending"})
        pending = None if row["pending"] is None else allocation.PendingAllocation.parse(
            policy.canonical(row["pending"]) + b"\n")
        return cls(allocation.AuthorityRegistration.parse(row["authority"]),
                   allocation.Checkpoint.parse(row["checkpoint"]), pending)

    def value(self) -> dict[str, Any]:
        return {"authority": self.authority.value(), "checkpoint": self.checkpoint.value(),
                "pending": None if self.pending is None else self.pending.value()}


@dataclass(frozen=True, slots=True)
class AllocationState:
    authorities: tuple[AuthorityState, ...] = ()

    def __post_init__(self) -> None:
        _need(type(self.authorities) is tuple and len(self.authorities) <= MAX_AUTHORITIES
              and all(type(item) is AuthorityState for item in self.authorities))
        projects = tuple(item.authority.project_id for item in self.authorities)
        _need(projects == tuple(sorted(set(projects))))

    def value(self) -> dict[str, Any]:
        return {"schemaVersion": 1, "protocol": PROTOCOL,
                "authorities": [item.value() for item in self.authorities]}

    def to_bytes(self) -> bytes:
        raw = policy.canonical(self.value()) + b"\n"
        _need(len(raw) <= MAX_STATE_BYTES)
        return raw

    @classmethod
    def parse(cls, raw: bytes) -> AllocationState:
        try:
            _need(type(raw) is bytes and 0 < len(raw) <= MAX_STATE_BYTES
                  and raw.endswith(b"\n") and raw.count(b"\n") == 1)
            row = policy._object(_decode_json(raw[:-1], limit=MAX_STATE_BYTES - 1,
                nodes=20_000, depth=20, exact=True), {"schemaVersion", "protocol", "authorities"})
            _need(type(row["schemaVersion"]) is int and row["schemaVersion"] == 1
                  and row["protocol"] == PROTOCOL and type(row["authorities"]) is list
                  and len(row["authorities"]) <= MAX_AUTHORITIES)
            result = cls(tuple(AuthorityState.parse(item) for item in row["authorities"]))
            _need(result.to_bytes() == raw)
            return result
        except (ValueError, TypeError, KeyError, UnicodeError, RecursionError):
            raise allocation.VersionAllocationError("journal-unavailable") from None

    def selected(self, authority: allocation.AuthorityRegistration) -> AuthorityState:
        _need(type(authority) is allocation.AuthorityRegistration)
        for item in self.authorities:
            if item.authority.project_id == authority.project_id:
                _need(item.authority == authority)
                return item
        raise allocation.VersionAllocationError("journal-unavailable")

    def replacing(self, selected: AuthorityState) -> AllocationState:
        self.selected(selected.authority)  # Rebinding, removal and reset are not transitions.
        return AllocationState(tuple(selected if item.authority == selected.authority else item
                                     for item in self.authorities))


@dataclass(frozen=True, slots=True)
class NativeStateSnapshot:
    revision: int
    payload: bytes

    def __post_init__(self) -> None:
        _need(type(self.revision) is int and 0 <= self.revision <= MAX_REVISION
              and type(self.payload) is bytes and len(self.payload) <= MAX_STATE_BYTES)


@dataclass(frozen=True, slots=True)
class NativeStateWriteAck:
    snapshot: NativeStateSnapshot
    effect: str
    durability: str
    cleanup: str


class VersionAllocationsPort(Protocol):
    """Fixed internal adapter over PrivateStateDirectory, not a public DTO API.

    Native first-time initialization alone may return revision zero and empty
    bytes. Missing previously initialized state is an error, never that value.
    On native StateError, propagate failure and retain the ORIGINAL native owner
    and its effect/durability/cleanup facts; do not synthesize a success ack.
    """
    def read_version_allocations(self) -> NativeStateSnapshot: ...
    def replace_version_allocations(self, expected_revision: int, payload: bytes) -> NativeStateWriteAck: ...


class NativeAllocationJournal:
    """AllocationJournal with whole-slot native revision CAS and durable acks.

    Methods are controller-internal transitions, not new mutation/recovery
    permissions. In particular mark_rejected requires the controller's positive
    no-claim/conditional-rejection fact; absence during reconciliation cannot
    clear an intent. Opening reads only; enrollment is a separate explicit setup
    action after the original native owner verifies the approved remote genesis.
    """
    def __init__(self, port: VersionAllocationsPort) -> None:
        self._port = port
        self._poisoned = False
        try:
            snapshot = port.read_version_allocations()
            _need(type(snapshot) is NativeStateSnapshot)
            self._state = (AllocationState() if snapshot.revision == 0 and snapshot.payload == b""
                           else AllocationState.parse(snapshot.payload))
            self._snapshot = snapshot
        except Exception:
            self._poisoned = True
            raise allocation.VersionAllocationError("journal-unavailable") from None

    def _usable(self) -> None:
        _need(not self._poisoned)

    def _selected(self, authority: allocation.AuthorityRegistration) -> AuthorityState:
        self._usable()
        return self._state.selected(authority)

    def _store(self, state: AllocationState) -> None:
        self._usable()
        _need(self._snapshot.revision < MAX_REVISION)
        raw = state.to_bytes()
        try:
            ack = self._port.replace_version_allocations(self._snapshot.revision, raw)
            _need(type(ack) is NativeStateWriteAck and type(ack.snapshot) is NativeStateSnapshot
                  and ack.effect == "committed" and ack.durability == "durable" and ack.cleanup == "settled"
                  and ack.snapshot.revision == self._snapshot.revision + 1 and ack.snapshot.payload == raw)
        except Exception:
            # The write might have happened. Never retry, issue HTTP, erase an
            # intent or reconstruct a new native owner based on an exception.
            self._poisoned = True
            raise allocation.VersionAllocationError("journal-unavailable") from None
        self._state, self._snapshot = state, ack.snapshot

    def enroll_authority(self, authority: allocation.AuthorityRegistration,
                         checkpoint: allocation.Checkpoint) -> None:
        """Explicit local retention of VERIFIED genesis; no remote initialization."""
        self._usable()
        _need(type(authority) is allocation.AuthorityRegistration
              and type(checkpoint) is allocation.Checkpoint and checkpoint.sequence == 0
              and checkpoint.head_sha256 == authority.genesis_sha256
              and all(item.authority.project_id != authority.project_id for item in self._state.authorities))
        selected = AuthorityState(authority, checkpoint)
        self._store(AllocationState(tuple(sorted((*self._state.authorities, selected),
                                                key=lambda item: item.authority.project_id))))

    def checkpoint(self, authority: allocation.AuthorityRegistration) -> allocation.Checkpoint:
        return self._selected(authority).checkpoint

    def pending_for(self, authority: allocation.AuthorityRegistration,
                    candidate_id: str) -> allocation.PendingAllocation | None:
        allocation._uuid(candidate_id)
        pending = self._selected(authority).pending
        # One unresolved original sender blocks other candidates for this local
        # project; its private intent must not be hidden by a different lookup.
        _need(pending is None or pending.reservation.request.candidate_id == candidate_id)
        return pending

    def record_checkpoint(self, authority: allocation.AuthorityRegistration,
                          checkpoint: allocation.Checkpoint) -> None:
        selected = self._selected(authority)
        before = selected.checkpoint
        _need(type(checkpoint) is allocation.Checkpoint and checkpoint.sequence >= before.sequence)
        if checkpoint.sequence == before.sequence:
            _need(checkpoint.head_sha256 == before.head_sha256)
        if checkpoint.commit == before.commit:
            _need(checkpoint == before)
        if checkpoint != before:
            # Prefix and Git ancestry were checked by the closed controller;
            # numeric monotonicity alone is NOT evidence of repository history.
            self._store(self._state.replacing(replace(selected, checkpoint=checkpoint)))

    def record_pending(self, pending: allocation.PendingAllocation) -> None:
        _need(type(pending) is allocation.PendingAllocation)
        selected = self._selected(pending.authority)
        _need(selected.pending is None and pending.checkpoint == selected.checkpoint)
        self._store(self._state.replacing(replace(selected, pending=pending)))

    def mark_resolved(self, pending: allocation.PendingAllocation,
                      checkpoint: allocation.Checkpoint) -> None:
        _need(type(pending) is allocation.PendingAllocation)
        selected = self._selected(pending.authority)
        _need(selected.pending == pending and checkpoint == selected.checkpoint
              and checkpoint.sequence >= pending.reservation.sequence)
        if checkpoint.sequence == pending.reservation.sequence:
            _need(checkpoint.head_sha256 == pending.reservation.sha256)
        self._store(self._state.replacing(replace(selected, pending=None)))

    def mark_rejected(self, pending: allocation.PendingAllocation) -> None:
        _need(type(pending) is allocation.PendingAllocation)
        selected = self._selected(pending.authority)
        _need(selected.pending == pending)
        self._store(self._state.replacing(replace(selected, pending=None)))
