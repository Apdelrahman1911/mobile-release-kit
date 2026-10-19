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
MAX_ENROLLMENTS = 64
MAX_CANDIDATES = MAX_ENROLLMENTS
MAX_STATE_BYTES = 1024 * 1024
# Includes the full request in each of 64 selections and its optional reserved
# row, plus eight pending rows. The unchanged byte cap applies before decoding.
MAX_STATE_NODES = 50_000
MAX_REVISION = (1 << 64) - 1


def _need(condition: bool) -> None:
    if not condition:
        raise allocation.VersionAllocationError("journal-unavailable")


def _local_project_id(value: object) -> str:
    # This is the service's install-local preference identity, NOT the shared
    # ledger project ID. Equal strings/UUID bytes never infer an enrollment.
    _need(type(value) is str and len(value) == 32 and value != "0" * 32
          and all(char in "0123456789abcdef" for char in value))
    return value


@dataclass(frozen=True, slots=True)
class ProjectEnrollment:
    local_project_id: str
    authority_project_id: str

    def __post_init__(self) -> None:
        _local_project_id(self.local_project_id)
        allocation._project_id(self.authority_project_id)

    @classmethod
    def parse(cls, value: object) -> ProjectEnrollment:
        row = policy._object(value, {"localProjectId", "authorityProjectId"})
        return cls(row["localProjectId"], row["authorityProjectId"])

    def value(self) -> dict[str, str]:
        return {"localProjectId": self.local_project_id,
                "authorityProjectId": self.authority_project_id}


@dataclass(frozen=True, slots=True)
class SelectedCandidate:
    """Durable retry DATA for one explicit local enrollment, not an edit grant.

    The original native admission mints the UUID once. Reading or retrying this
    row must never mint one, infer an enrollment, or change its full request.
    """
    local_project_id: str
    request: allocation.AllocationRequest
    reservation: allocation.Reservation | None = None

    def __post_init__(self) -> None:
        _local_project_id(self.local_project_id)
        _need(type(self.request) is allocation.AllocationRequest
              and self.request.version_policy.mode == "automatic")
        _need(self.reservation is None or type(self.reservation) is allocation.Reservation
              and self.reservation.request == self.request)

    @classmethod
    def parse(cls, value: object) -> SelectedCandidate:
        row = policy._object(value, {"localProjectId", "request", "reservation"})
        return cls(row["localProjectId"], allocation.AllocationRequest.parse(row["request"]),
                   None if row["reservation"] is None else allocation.Reservation.parse(row["reservation"]))

    def value(self) -> dict[str, Any]:
        return {"localProjectId": self.local_project_id, "request": self.request.value(),
                "reservation": None if self.reservation is None else self.reservation.value()}


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
    enrollments: tuple[ProjectEnrollment, ...] = ()
    candidates: tuple[SelectedCandidate, ...] = ()

    def __post_init__(self) -> None:
        _need(type(self.authorities) is tuple and len(self.authorities) <= MAX_AUTHORITIES
              and all(type(item) is AuthorityState for item in self.authorities))
        projects = tuple(item.authority.project_id for item in self.authorities)
        _need(projects == tuple(sorted(set(projects))))
        _need(type(self.enrollments) is tuple and len(self.enrollments) <= MAX_ENROLLMENTS
              and all(type(item) is ProjectEnrollment for item in self.enrollments))
        local_projects = tuple(item.local_project_id for item in self.enrollments)
        _need(local_projects == tuple(sorted(set(local_projects)))
              and all(item.authority_project_id in projects for item in self.enrollments))
        _need(type(self.candidates) is tuple and len(self.candidates) <= MAX_CANDIDATES
              and all(type(item) is SelectedCandidate for item in self.candidates))
        candidate_locals = tuple(item.local_project_id for item in self.candidates)
        _need(candidate_locals == tuple(sorted(set(candidate_locals))))
        seen = set()
        for item in self.candidates:
            selected = self.enrolled(item.local_project_id, next(
                (row.authority for row in self.authorities
                 if row.authority.project_id == item.request.project_id), None))
            identity = (item.request.project_id, item.request.candidate_id)
            _need(identity not in seen)
            seen.add(identity)
            if item.reservation is not None:
                _need(item.reservation.sequence <= selected.checkpoint.sequence)
                if item.reservation.sequence == selected.checkpoint.sequence:
                    _need(item.reservation.sha256 == selected.checkpoint.head_sha256)
            pending = selected.pending
            if pending is not None and pending.reservation.request.candidate_id == item.request.candidate_id:
                _need(pending.reservation.request == item.request and item.reservation is None)

    def value(self) -> dict[str, Any]:
        return {"schemaVersion": 3, "protocol": PROTOCOL,
                "authorities": [item.value() for item in self.authorities],
                "enrollments": [item.value() for item in self.enrollments],
                "candidates": [item.value() for item in self.candidates]}

    def to_bytes(self) -> bytes:
        raw = policy.canonical(self.value()) + b"\n"
        _need(len(raw) <= MAX_STATE_BYTES)
        return raw

    @classmethod
    def parse(cls, raw: bytes) -> AllocationState:
        try:
            _need(type(raw) is bytes and 0 < len(raw) <= MAX_STATE_BYTES
                  and raw.endswith(b"\n") and raw.count(b"\n") == 1)
            decoded = _decode_json(raw[:-1], limit=MAX_STATE_BYTES - 1,
                                   nodes=MAX_STATE_NODES, depth=20, exact=True)
            _need(type(decoded) is dict and type(decoded.get("schemaVersion")) is int
                  and decoded["schemaVersion"] in {1, 2, 3})
            version = decoded["schemaVersion"]
            names = {"schemaVersion", "protocol", "authorities"}
            if version >= 2:
                names.add("enrollments")
            if version == 3:
                names.add("candidates")
            row = policy._object(decoded, names)
            _need(row["protocol"] == PROTOCOL
                  and type(row["authorities"]) is list
                  and len(row["authorities"]) <= MAX_AUTHORITIES)
            enrollments = [] if version == 1 else row["enrollments"]
            _need(type(enrollments) is list and len(enrollments) <= MAX_ENROLLMENTS)
            candidates = row["candidates"] if version == 3 else []
            _need(type(candidates) is list and len(candidates) <= MAX_CANDIDATES)
            result = cls(tuple(AuthorityState.parse(item) for item in row["authorities"]),
                         tuple(ProjectEnrollment.parse(item) for item in enrollments),
                         tuple(SelectedCandidate.parse(item) for item in candidates))
            canonical_row = result.value()
            if version < 3:
                canonical_row.pop("candidates")
            if version == 1:
                canonical_row.pop("enrollments")
            # Validate each legacy schema's OWN exact encoding. Constructor
            # reads never upgrade it or infer local/candidate ownership.
            canonical_row["schemaVersion"] = version
            _need(policy.canonical(canonical_row) + b"\n" == raw)
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
                                     for item in self.authorities), self.enrollments, self.candidates)

    def enrolled(self, local_project_id: str,
                 authority: allocation.AuthorityRegistration) -> AuthorityState:
        _local_project_id(local_project_id)
        _need(type(authority) is allocation.AuthorityRegistration
              and any(item.local_project_id == local_project_id
                      and item.authority_project_id == authority.project_id for item in self.enrollments))
        return self.selected(authority)

    def candidate(self, local_project_id: str) -> SelectedCandidate | None:
        _local_project_id(local_project_id)
        return next((item for item in self.candidates if item.local_project_id == local_project_id), None)

    def selecting(self, candidate: SelectedCandidate) -> AllocationState:
        _need(type(candidate) is SelectedCandidate)
        rows = tuple(item for item in self.candidates if item.local_project_id != candidate.local_project_id)
        return AllocationState(self.authorities, self.enrollments,
                               tuple(sorted((*rows, candidate), key=lambda item: item.local_project_id)))


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
    The native owner derives local_project_id from its original registered-root
    binding; accepting an ID here is DATA, not a substitute for that admission.
    Shared AllocationRequest.project_id always remains the authority's ID.
    """
    def __init__(self, port: VersionAllocationsPort, *, local_project_id: str) -> None:
        self._local_project_id = _local_project_id(local_project_id)
        self._port = port
        self._poisoned = False
        try:
            snapshot = port.read_version_allocations()
            _need(type(snapshot) is NativeStateSnapshot)
            self._state = (AllocationState() if snapshot.revision == 0 and snapshot.payload == b""
                           else AllocationState.parse(snapshot.payload))
            self._snapshot = snapshot
            selected = self._state.candidate(self._local_project_id)
            self._bound_request = None if selected is None else selected.request
        except Exception:
            self._poisoned = True
            raise allocation.VersionAllocationError("journal-unavailable") from None

    def _usable(self) -> None:
        _need(not self._poisoned)

    def _selected(self, authority: allocation.AuthorityRegistration) -> AuthorityState:
        self._usable()
        selected = self._state.enrolled(self._local_project_id, authority)
        candidate = self._state.candidate(self._local_project_id)
        _need(candidate is not None and candidate.request == self._bound_request
              and candidate.request.project_id == authority.project_id)
        return selected

    def admit_request(self, authority: allocation.AuthorityRegistration,
                      request: allocation.AllocationRequest) -> None:
        self._selected(authority)
        _need(type(request) is allocation.AllocationRequest and request == self._bound_request)

    def selected_candidate(self, authority: allocation.AuthorityRegistration) -> SelectedCandidate:
        self._selected(authority)
        candidate = self._state.candidate(self._local_project_id)
        _need(candidate is not None)
        return candidate

    def _store(self, state: AllocationState) -> None:
        self._usable()
        _need(self._snapshot.revision < MAX_REVISION)
        raw = state.to_bytes()
        # Latch BEFORE the original call. BaseException/cancellation and a
        # reentrant port callback must not leave another usable write path.
        self._poisoned = True
        try:
            ack = self._port.replace_version_allocations(self._snapshot.revision, raw)
            _need(type(ack) is NativeStateWriteAck and type(ack.snapshot) is NativeStateSnapshot
                  and ack.effect == "committed" and ack.durability == "durable" and ack.cleanup == "settled"
                  and ack.snapshot.revision == self._snapshot.revision + 1 and ack.snapshot.payload == raw)
            selected = state.candidate(self._local_project_id)
            self._state, self._snapshot, self._bound_request = (
                state, ack.snapshot, None if selected is None else selected.request)
        except Exception:
            # The write might have happened. Never retry, issue HTTP, erase an
            # intent or reconstruct a new native owner based on an exception.
            raise allocation.VersionAllocationError("journal-unavailable") from None
        self._poisoned = False  # Only the exact acknowledged state was adopted.

    def enroll_authority(self, authority: allocation.AuthorityRegistration,
                         checkpoint: allocation.Checkpoint) -> None:
        """Explicit native-approved local-to-shared enrollment; no remote IO.

        A new local project may select an already retained identical authority.
        Its supplied verified genesis NEVER replaces the current checkpoint or
        pending sender. Legacy schema1 upgrades only on this explicit action.
        Removing/rebinding a local enrollment needs a separate reviewed design.
        """
        self._usable()
        _need(type(authority) is allocation.AuthorityRegistration
              and authority.protected_branch
              and type(checkpoint) is allocation.Checkpoint and checkpoint.sequence == 0
              and checkpoint.head_sha256 == authority.genesis_sha256
              and all(item.local_project_id != self._local_project_id for item in self._state.enrollments))
        existing = next((item for item in self._state.authorities
                         if item.authority.project_id == authority.project_id), None)
        if existing is None:
            authorities = tuple(sorted((*self._state.authorities, AuthorityState(authority, checkpoint)),
                                       key=lambda item: item.authority.project_id))
        else:
            _need(existing.authority == authority)
            authorities = self._state.authorities
        enrollment = ProjectEnrollment(self._local_project_id, authority.project_id)
        enrollments = tuple(sorted((*self._state.enrollments, enrollment),
                                   key=lambda item: item.local_project_id))
        self._store(AllocationState(authorities, enrollments, self._state.candidates))

    def select_candidate(self, authority: allocation.AuthorityRegistration,
                         request: allocation.AllocationRequest, *,
                         previous_candidate_id: str | None = None,
                         reconcile_pending: bool = False) -> SelectedCandidate:
        """Explicit native selection, not a refresh/retry or UUID generator.

        Changing an existing selection requires a NEW native-minted UUID and
        the exact previous UUID from that original explicit action. Legacy
        pending data may only be adopted by explicit exact-request read-only
        reconciliation; a different local selection can never claim it.
        """
        self._usable()
        selected = self._state.enrolled(self._local_project_id, authority)
        _need(type(request) is allocation.AllocationRequest and request.project_id == authority.project_id
              and request.version_policy.mode == "automatic" and type(reconcile_pending) is bool)
        current = self._state.candidate(self._local_project_id)
        if current is not None and current.request == request:
            _need(previous_candidate_id is None)
            if reconcile_pending:
                _need(selected.pending is not None and selected.pending.reservation.request == request)
            return current  # A refresh neither writes nor remints.
        if current is None:
            _need(previous_candidate_id is None)
        else:
            _need(not reconcile_pending and previous_candidate_id == current.request.candidate_id
                  and request.candidate_id != current.request.candidate_id)
        pending = selected.pending
        if pending is not None:
            _need(current is None and reconcile_pending and pending.reservation.request == request)
        else:
            _need(not reconcile_pending)
        candidate = SelectedCandidate(self._local_project_id, request)
        self._store(self._state.selecting(candidate))
        return candidate

    def checkpoint(self, authority: allocation.AuthorityRegistration) -> allocation.Checkpoint:
        return self._selected(authority).checkpoint

    def pending_for(self, authority: allocation.AuthorityRegistration,
                    candidate_id: str) -> allocation.PendingAllocation | None:
        allocation._uuid(candidate_id)
        pending = self._selected(authority).pending
        _need(candidate_id == self._bound_request.candidate_id)
        # One unresolved original sender blocks other candidates for this shared
        # authority, including other enrolled local projects in the same host.
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
        candidate = self.selected_candidate(pending.authority)
        _need(selected.pending is None and pending.checkpoint == selected.checkpoint
              and pending.reservation.request == self._bound_request and candidate.reservation is None)
        self._store(self._state.replacing(replace(selected, pending=pending)))

    def mark_resolved(self, pending: allocation.PendingAllocation,
                      checkpoint: allocation.Checkpoint) -> None:
        _need(type(pending) is allocation.PendingAllocation)
        selected = self._selected(pending.authority)
        _need(selected.pending == pending and checkpoint == selected.checkpoint
              and checkpoint.sequence >= pending.reservation.sequence
              and pending.reservation.request == self._bound_request)
        if checkpoint.sequence == pending.reservation.sequence:
            _need(checkpoint.head_sha256 == pending.reservation.sha256)
        retained = replace(self.selected_candidate(pending.authority), reservation=pending.reservation)
        self._store(self._state.replacing(replace(selected, pending=None)).selecting(retained))

    def record_reused(self, authority: allocation.AuthorityRegistration,
                      reservation: allocation.Reservation, checkpoint: allocation.Checkpoint) -> None:
        selected = self._selected(authority)
        candidate = self.selected_candidate(authority)
        _need(type(reservation) is allocation.Reservation and reservation.request == self._bound_request
              and selected.pending is None and checkpoint == selected.checkpoint
              and checkpoint.sequence >= reservation.sequence
              and (candidate.reservation is None or candidate.reservation == reservation))
        if checkpoint.sequence == reservation.sequence:
            _need(checkpoint.head_sha256 == reservation.sha256)
        # Even identical already-stored bytes require a fresh native CAS ACK.
        # This is what detects a stale original adapter on the read/reuse path.
        self._store(self._state.selecting(replace(candidate, reservation=reservation)))

    def mark_rejected(self, pending: allocation.PendingAllocation) -> None:
        _need(type(pending) is allocation.PendingAllocation)
        selected = self._selected(pending.authority)
        _need(selected.pending == pending and pending.reservation.request == self._bound_request)
        self._store(self._state.replacing(replace(selected, pending=None)))
